#pragma once

#include <cstddef>
#include <cstdint>

// 单层补丁注册表（HookAPI Patch/Unpatch 后端）。
//
// 语义：
//  - 首次 Apply(target, bytes, len, owner)：保存该地址的原始字节并记录 owner；
//  - 重复 Apply 同一地址且长度相同：写入新字节，但保留最初存档（日志告警）；
//    长度不同或与其它补丁区间重叠时拒绝；
//  - RevertOwned(target, owner)：仅当记录属于该 owner 时恢复原始字节并移除记录；
//    无记录或 owner 不符返回 false。
//
// **Loader 不再替插件自动撤销补丁**（原 `RevertAllFor` 已删除，见 ARCHITECTURE §5.8）：
// 卸载/隔离路径不再回滚，补丁留在游戏里直到进程退出。插件要撤销就在自己还活着的时候
// 调 `Unpatch`（典型位置是 OnUnload）——那时它知道自己的状态，也知道补丁是否还在被调用。
//
// 线程安全：注册表以 CRITICAL_SECTION 保护（GameCore 重载循环在游戏线程、
// 主菜单开关 Mod 在 Loader 工作线程，两处都会触碰）。
namespace PatchRegistry {

// Apply：首次对 target 打补丁时保存原始字节并记录 owner；重复 Apply 同一地址且长度相同：
// 更新当前字节但保留最初存档（日志告警）。不同 target 的区间不可重叠，重复长度也不可改变。
// 返回 false 表示失败（参数无效/区间冲突/内存保护失败）。
bool Apply(void* target, const void* bytes, size_t len, const wchar_t* owner);

// 查询 [target, target+len) 是否与任何已登记的补丁区间重叠。
// 供 MinHook 装钩前做仲裁：同一段字节既被装钩又被打补丁时，两侧各自的"恢复原始字节"
// 会互相覆盖，最终恢复出第三种状态。调用方不得持注册表的锁（内部自己取）。
// 即使补丁不可撤销也保留：禁止两个插件往重叠区间打补丁，否则一方的补丁会不可逆地
// 踩坏另一方。
bool OverlapsRegistered(const void* target, size_t len);

// RevertOwned：仅当记录属于该 owner 时恢复原始字节并移除记录。
// 只由 HookAPI::Unpatch 调用（即插件主动撤销），Loader 自身不再自动调用。
bool RevertOwned(void* target, const wchar_t* owner);

}  // namespace PatchRegistry
