#pragma once

#include <cstddef>
#include <cstdint>

// 单层补丁注册表（v2 HookAPI Patch/Unpatch 后端）。
//
// 语义：
//  - 首次 Apply(target, bytes, len, owner)：保存该地址的原始字节并记录 owner；
//  - 重复 Apply 同一地址且长度相同：写入新字节，但保留最初存档（日志告警）；
//    长度不同或与其它补丁区间重叠时拒绝；
//  - RevertOwned(target, owner)：仅当记录属于该 owner 时恢复原始字节并移除记录；
//    无记录或 owner 不符返回 false；
//  - RevertAllFor(owner)：回滚某 owner 的全部未回滚补丁（插件卸载时调用）。
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
bool OverlapsRegistered(const void* target, size_t len);

// RevertOwned：仅当记录属于该 owner 时恢复原始字节并移除记录。
bool RevertOwned(void* target, const wchar_t* owner);

// RevertAllFor：回滚某 owner 的全部未回滚补丁（插件卸载时调用）。返回回滚条数。
size_t RevertAllFor(const wchar_t* owner);

}  // namespace PatchRegistry
