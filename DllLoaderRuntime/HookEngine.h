#pragma once
// HookEngine.h — 挂钩站点表 / JIT stub / capture / teardown 站点操作（阶段 5）。
//
// 本模块拥有（不导出）：
//   struct HookSite（含嵌套 CaptureOut）、g_hookSites、g_captureMutex、g_captureRuntime
// 若把 capture 划给别的文件，两边就得互相暴露最私密的数据结构 —— 故 B（站点）与
// E（capture）必须同文件。同理 teardown 的两个站点操作函数也归这里。
//
// 本头文件在阶段 4 就建好（ScriptBridge 要用 InstallLoaderDetourOnSite）；
// 阶段 5 抽出模块后补齐其余声明。

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include <Windows.h>

#include "../common/HookAPI.h"

namespace HookEngine {

// ================= 统一挂钩站点（Unified Hook Site） =================
// 对同一个 target，MinHook 只挂一次，挂到 Loader 自己 asmjit 生成的「中转 stub」。
// 一个站点把 Detour 槽、Capture 槽与 MinHook 侧合并到同一节点。
//
// 【为什么结构体在头文件里】：RemoveHookSiteRecordLocked 的签名收 HookSite&，
// 而它被母体（阶段 6 后是 PluginRegistry）调用 —— 故类型必须可见。
// 结构体本身【不导出变量】：g_hookSites 仍是 HookEngine.cpp 的文件级 static。
//
// 生命周期硬约束：日常「退役」只拔插槽（activeDetour=nullptr / hasCapture=false /
// captureOuts.clear()），绝不调用 MH_RemoveHook、绝不 JitRuntime::release、绝不
// g_hookSites.erase。理由：stub 先读 nextTarget 再尾跳，且没有可靠的计数能证明没有
// 调用者仍在 stub 内；随手释放 JIT 代码 / 节点 / trampoline 都是 UAF。节点只在进程
// 退出时随静态对象回收。
struct HookSite {
    struct CaptureOut {
        void** address = nullptr;
        std::wstring ownerId;
    };

    void* stubCode = nullptr;             // asmjit 中转 stub 入口（永不释放）
    void* minhookTrampoline = nullptr;    // MH_CreateHook 产出（尾跳回原函数）
    void* activeDetour = nullptr;         // 插件 detour；nullptr = 无
    void* nextTarget = nullptr;           // stub 实际尾跳目标 = activeDetour ?: minhookTrampoline
    std::wstring detourOwner;             // activeDetour 的 owner（空 = 无）
    bool hasCapture = false;              // stub 裸读的 POD 字节；true 才走慢路径
    bool hookInstalled = false;           // MinHook 已 Create+Enable（前导字节已被改写）
    bool retiring = false;                // g_captureMutex 保护；阻止新的捕获写入
    uint32_t captureParamIndex = 0;
    std::vector<CaptureOut> captureOuts;  // g_captureMutex 保护
    // MinHook 记录没能在 teardown 里摘掉的标记（目标映像已卸载 -> Disable/Remove 都失败）。
    // 下次在同一个地址取站时会据此强制重建记录，否则站点会一直以为钩还装着。
    bool recordStale = false;
    // 建 MinHook 记录时目标前导字节的副本：recordStale 重建前用它判断"这个地址现在还是不是
    // 当年那个函数"。不一致就绝不调用 MH_DisableHook / MH_RemoveHook —— 两者都会把旧记录的
    // 备份字节写回目标，旧映像已卸载时那就是在破坏当前映射的代码（跨映像/跨版本写坏函数）。
    static constexpr size_t kGuardBytes = 16;
    uint8_t prologueBackup[kGuardBytes] = {};
    bool prologueValid = false;
    // 前导字节对不上（或当时没读到）：本会话不再碰这个地址，绝不冒险写回旧字节（fail-closed）。
    bool poisoned = false;
};

// 地址前导窗口（字节数）：装钩前检查目标前导窗口是否与已登记补丁重叠，
// 打补丁前检查目标区间是否压住某个已装钩目标的前导窗口。
// 窗口取与"可读探测"同一口径（PluginBoundary::kMinHookTargetSpan，32 字节，保守）。
//
// 【为什么放头文件】：它同时被本模块与 PluginRegistry 的 HookPatch 使用（§6 跨模块常量）。
// 定义在 HookEngine.cpp，此处只声明 —— 避免每个 TU 各留一份（§7.0 的"静默分裂"）。
extern const size_t kHookPrologueWindow;

// 把一个 detour 装到统一站点表上（内部自己取 MinHook 锁）。
//   target   目标地址
//   detour   插件/Loader 的 detour
//   origSlot 出参：站点跳板（尾跳原函数）
//   why      日志用的调用方标识
// 返回 false 表示站点不可用 / 已被别人占用 / 目标不可读。
//
// 调用方【不得】持 Runtime::MinHookMutex()。
bool InstallLoaderDetourOnSite(void* target, void* detour, void** origSlot, const char* why);

// 退役某 owner 通过 HookAPI.InstallHook 注册的 detour 槽（只拔插槽，绝不物理脱钩）。
// 清空该 owner 的 activeDetour / detourOwner，nextTarget 回落到 minhookTrampoline。
// 返回被退役的站点数（调用方用于日志）。调用方须持 Runtime::MinHookMutex()。
size_t RetireHookSiteDetoursForOwnerLocked(const std::wstring& owner);

// 目标前导窗口 [target, target+len) 是否与已登记的补丁区间重叠（装钩前的仲裁）。
bool OverlapsHookPrologue(const void* target, size_t len);

// 摘除某 target 的 MinHook 记录（释放跳板），但**保留站点节点** ——
// stub 的机器码里用 imm64 永久内嵌了 &HookSite。
// 调用方须持 Runtime::MinHookMutex()。
bool RemoveHookSiteRecordLocked(void* target, HookSite& site);

// ---------------- 插件 ABI 入口 ----------------
// 母体的 g_hookApi 初始化表取它们地址（阶段 6 归门面），故不能是 static。
// 它们是插件可见的入口：先过 PluginDomain 的域门与归属校验，再落到 Core。

// HookAPI.InstallHook 的实现：装插件 detour。
bool InstallHookImpl(void* target, void* detour, void** original);

// HookAPI.RegisterGlobalCapture 的实现：注册参数捕获。
bool RegisterGlobalCaptureImpl(void* providerAddress, uint32_t paramIndex, void** out);

// HookAPI.UnregisterGlobalCapture 的实现：撤销本插件在该 provider 上的一个捕获订阅。
bool UnregisterGlobalCaptureImpl(void* providerAddress, void** out);

// ---------------- capture 订阅 ----------------
// 注册全局参数捕获（Loader 内部入口，不做插件域门）。
bool RegisterGlobalCaptureCore(void* providerAddress, uint32_t paramIndex, void** out,
    const std::wstring& ownerId);

// 撤销一个捕获订阅（Loader 内部入口，不做插件域门）：按 (provider, out, owner) 精确匹配。
// 只摘订阅、绝不物理摘钩；最后一个订阅移除后站点回到快路径。
bool UnregisterGlobalCaptureCore(void* providerAddress, void** out, const std::wstring& ownerId);

// 清理全部 capture 订阅（拔插槽 + 排空），保留站点与 detour。
void CleanupAllCaptureSites();

// 清理某 owner 的 capture 订阅（插件卸载/隔离路径）。
void CleanupCaptureSitesForOwner(const std::wstring& ownerId);

// ---------------- teardown（由 PluginRegistry::ResetForReload 编排） ----------------
// 第 1 步：趁旧映像仍映射，用一次 MH_ApplyQueued 批量还原全部 GameCore 域入口字节。
// 此后不再有新调用进入 stub / 插件 detour。
void DisableGameCoreDomainSites();

// 第 2 步：物理摘除 GameCore 域的站点记录（释放 MinHook 跳板），并复位共享钩状态。
//   lifecycleLock 由调用方持有，本函数内部会短暂 unlock 以排空在途 detour。
// 【顺序理由见实现处的长注释】：必须在 DisableGameCoreDomainSites 之后。
void RemoveGameCoreDomainSiteRecords(std::unique_lock<std::recursive_mutex>& lifecycleLock);

}  // namespace HookEngine
