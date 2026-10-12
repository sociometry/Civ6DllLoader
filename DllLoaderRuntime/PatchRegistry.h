#pragma once

#include <cstddef>
#include <cstdint>

// 分层补丁注册表（HookAPI Patch/Unpatch 后端）。
//
// 语义（每个 target 上维护一个按应用顺序排列的 owner 栈）：
//  - Apply(target, bytes, len, owner)：把【写入前】该区间的当前字节存为本 owner 的存档，
//    压入栈顶，然后写入新字节。存档因此天然区分 owner：后打补丁者存的是"含下层补丁"的字节，
//    它 Unpatch 时还原下层补丁而不是原始字节；
//  - 同一 owner 对同一 target 重复 Apply 一律拒绝（补丁已生效，重打只会破坏存档语义）；
//  - 不同 owner 可以对同一 target 叠加补丁，各自持有一份存档；
//  - 与【其它 target】的补丁区间不得重叠（区间仲裁用各 target 的最大长度）；
//  - RevertOwned(target, owner)：只有该 owner 位于栈顶时才还原它自己的存档并出栈；
//    否则拒绝——写回旧字节会静默覆盖上层 owner 的补丁。全部出栈后 target 记录被摘除。
//
// **Loader 不替插件自动撤销补丁**（原 `RevertAllFor` 已删除，见 ARCHITECTURE §5.8）：
// 卸载/隔离路径不回滚，补丁留在游戏里直到进程退出。要撤销只能插件自己调 `Unpatch`。
//
// 线程安全：注册表以 CRITICAL_SECTION 保护（GameCore 重载循环在游戏线程、
// 主菜单开关 Mod 在 Loader 工作线程，两处都会触碰）。
namespace PatchRegistry {

// Apply：把写入前的当前字节存为本 owner 的存档并压栈，然后写入 bytes。
// 返回 false 表示失败（参数无效/该 owner 已打过这个 target/与其它 target 区间重叠/内存保护失败）。
bool Apply(void* target, const void* bytes, size_t len, const wchar_t* owner);

// 查询 [target, target+len) 是否与任何已登记的补丁区间重叠。
// 供 MinHook 装钩前做仲裁：同一段字节既被装钩又被打补丁时，两侧各自的"恢复原始字节"
// 会互相覆盖，最终恢复出第三种状态。调用方不得持注册表的锁（内部自己取）。
bool OverlapsRegistered(const void* target, size_t len);

// RevertOwned：仅当该 owner 位于 target 的栈顶时，还原它自己的存档并出栈。
// 只由 HookAPI::Unpatch 调用（即插件主动撤销），Loader 自身不调用。
bool RevertOwned(void* target, const wchar_t* owner);

}  // namespace PatchRegistry
