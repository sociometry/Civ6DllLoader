// Civ6DLLHookLoader.cpp
#include "pch.h"
#include "Civ6DLLHookLoaderAPI.h"
#include <Windows.h>
#include <filesystem>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <string>
#include <map>
#include <functional>
#include "Civ6MessageBus.h"
#include "MinHook.h"
#include "Runtime.h"
#include "../common/Logger.h"
#include "../common/ModScan.h"
#include "ProxyTypes.h"
#include "Localization.h"
#include "HavokScript.h"
#include "PdataMatch.h"
#include "ImageAddress.h"
#include "PluginBoundary.h"
#include "PluginInFlight.h"

#include <cstdarg>
#include <cstdlib>
#include <cstring>   // memcmp（前导字节副本比对）
#include <cwchar>
#include <cwctype>
#include <atomic>
#include <condition_variable>
#include <intrin.h>
#include <optional>

#include "PatchRegistry.h"
#include "LoaderCore.h"
#include <asmjit/x86.h>

using namespace std;

static Civ6MessageBus g_bus;

// v2 插件跟踪项：路径 + 句柄 + 名字(stem，作 Patch owner / OnMessage 注册名) + 类别(Global/GameCore)。
enum class PluginState {
    Loading,
    Active,
    Deactivating,
    Quarantined,
};

struct PluginEntry {
    HMODULE handle = nullptr;
    std::wstring path;
    std::wstring name;
    std::wstring ownerId;
    LoaderCore::PluginCategory category = LoaderCore::PluginCategory::Global;
    PluginState state = PluginState::Active;
    // 类别 / ABI 版本在 OnLoad 之前就由插件的 Civ6PluginKind 导出判完（见 LoadPluginDllInternal），
    // 这里不再保存任何"插件自述"字段。
};
static vector<PluginEntry> g_plugins;

// 插件状态的唯一写入口：state 与 PluginInFlight 的放行镜像必须一起更新，
// 否则会出现"状态已停用、回调仍被放行"（或反之）的错位。
static void SetPluginState(PluginEntry& entry, PluginState state) {
    entry.state = state;
    PluginInFlight::SetAllowed(PluginInFlight::Resolve(entry.ownerId),
        state == PluginState::Loading || state == PluginState::Active);
}

// GameCore 插件的【待释放】句柄队列。
// 为什么不在插件卸载处直接 FreeLibrary：那一刻 GameCore 映像还映射着，它承载的 gamecore
// Lua 环境（gameplay / ui）要到引擎自己的 UnloadDLL 里才拆；而 Lua 表里可能仍持有指向插件
// 映像的 C 闭包（PushLuaMethods 推入的、以及插件自己在 RegisterScriptGlobals 里注册的）。
// 等引擎把 GameCore 连同那些 Lua 环境一起拆完（g_origUnloadDLL 返回之后）再 Free，「闭包被
// 调用」这件事就不再可能发生。只由游戏线程（Load/UnloadPluginsOf）入队，flush 由
// LoaderHooks 的两个 detour 在调到原函数之后调用。
static std::mutex g_pendingFreeMutex;
static std::vector<HMODULE> g_pendingFreeModules;

static void QueueGameCoreModuleForFree(HMODULE module) {
    if (!module) return;
    lock_guard<mutex> lock(g_pendingFreeMutex);
    g_pendingFreeModules.push_back(module);
}

// 插件生命周期互斥锁（递归：OnLoad/OnUnload 期间插件会再调用 HookAPI 注册入口，
// 需要重入）。保护 g_plugins、脚本全局注册表与 PushMethods 槽位的全部读写：
// 唯一写者是游戏线程（LoadDLL/UnloadDLL detour → Load/UnloadPluginsOf）。
// Runtime::MinHookMutex（MinHook 调用 + owner 表）与 PatchRegistry 的
// CRITICAL_SECTION 保持独立，锁序恒为 lifecycle → hook/patch。
// [声明位置] 必须在 FreePendingPluginModules 之前：它在 FreeLibrary 之后要用它清悬垂句柄。
static std::recursive_mutex g_pluginLifecycleMutex;

// 引擎卸完 GameCore 之后调用：真正 FreeLibrary 那些排队的插件模块。
// 不持任何 Loader 锁调用 FreeLibrary（插件 DllMain(DETACH) 可能反过来调 Loader）。
void LoaderCore::FreePendingPluginModules() {
    std::vector<HMODULE> modules;
    {
        lock_guard<mutex> lock(g_pendingFreeMutex);
        modules.swap(g_pendingFreeModules);
    }
    for (HMODULE module : modules) {
        FreeLibrary(module);
        Logger::Log("Plugin module freed after engine GameCore unload: %p", module);
        // 句柄已失效：把跟踪表里同句柄的条目置空，避免悬垂句柄被"同基址复用"的新模块误命中
        // （崩溃隔离的条目会一直留在表里，正是为了让 LoadSinglePlugin 的按路径去重拦住重试）。
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (auto& entry : g_plugins) {
            if (entry.handle == module) entry.handle = nullptr;
        }
    }
}

// GameCore 阶段切换互斥（InitializeGameCorePhase / ResetForReload 与插件加载/卸载互斥）：
// 保证 "attach -> 装钩 -> 加载 GameCore 插件" 与 "teardown -> 卸载" 两段不会交错。
static std::recursive_mutex g_gameCoreTransitionMutex;

// 插件回调的在途登记 / 排空全部走 PluginInFlight（见 PluginInFlight.h），只有一套实现：
//  - 状态门禁：写 PluginEntry::state 时经 SetPluginState 同步镜像到
//    PluginInFlight::SetAllowed（镜像的唯一写者）；
//  - 在途记账："加载器 -> 插件"入口（消息、ScriptGlobals / ScriptGlobalsUI、
//    GameEvent、PushMethods）进入时走 PluginInFlight::Enter；
//  - 排空：卸载/隔离与消息总线注销都调 PluginInFlight::WaitAll。

// OnLoad/OnUnload 的快速 owner 上下文。异步调用不依赖它，而由回调/调用方地址反查
// 所属插件模块，避免错误归为 Loader 导致插件停用后钩子仍生效。
static thread_local std::wstring g_activePluginOwner;
static thread_local HMODULE g_activePluginModule;

static void SetActivePluginContext(const std::wstring& owner, HMODULE module) {
    g_activePluginOwner = owner;
    g_activePluginModule = module;
}

static void ClearActivePluginContext() {
    g_activePluginOwner.clear();
    g_activePluginModule = nullptr;
}

// ================= 统一挂钩站点（Unified Hook Site） =================
// 对同一个 target，MinHook 只挂一次，挂到 Loader 自己 asmjit 生成的「中转 stub」。
// 一个站点把 Detour 槽、Capture 槽与 MinHook 侧合并到同一节点：
//   - Detour 槽：activeDetour/detourOwner —— InstallHook 的独占插件 detour；
//   - Capture 槽：hasCapture/captureParamIndex/captureOuts —— RegisterGlobalCapture 的
//     共享参数捕获订阅（同一 target 上 1 个 Detour + N 个 Capture 共存）；
//   - MinHook 侧：stubCode/minhookTrampoline/hookInstalled。
// stub 每次调用先读 hasCapture：无捕获直接尾跳 nextTarget（快路径，Detour-only 站点
// 几乎零开销）；有捕获才保存参数、调用 CaptureDispatch，再尾跳 nextTarget。
// nextTarget = activeDetour（有 Detour 时）或 minhookTrampoline（无 Detour 时）。
//
// 生命周期硬约束：日常「退役」只拔插槽（activeDetour=nullptr / hasCapture=false /
// captureOuts.clear()），绝不调用 MH_RemoveHook、绝不 JitRuntime::release、绝不
// g_hookSites.erase。理由：stub 先读 nextTarget 再尾跳，且没有可靠的计数能证明没有
// 调用者仍在 stub 内；随手释放 JIT 代码 / 节点 / trampoline 都是 UAF。节点只在进程
// 退出时随静态对象回收。
// 唯一的例外是 GameCore teardown：趁旧映像仍映射时先用一次 MH_ApplyQueued 批量还原
// 全部 GameCore 域入口字节（此后不再有新调用进入 stub / 插件 detour），再物理摘除
// MinHook 记录（释放跳板）。见 DisableGameCoreDomainSites / RemoveGameCoreDomainSiteRecords。
// 摘除失败的站点打 recordStale，下次在同一地址取站时强制重建（GetOrCreateHookSiteLocked）。
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

static std::map<void*, HookSite> g_hookSites;
// 站点锁复用 Runtime::MinHookMutex()（不要再引第三个锁）。锁序固定 MinHook -> capture：
// g_captureMutex 只保护派发侧数据（captureOuts / retiring / captureParamIndex）。
static std::mutex g_captureMutex;
static asmjit::JitRuntime g_captureRuntime;  // 统一 stub 的 JIT 分配器（永不 release）

extern "C" void CaptureDispatch(void* regs, uint32_t paramIndex, void* sitePtr);
static bool BuildHookHubStub(HookSite* site, void** outStub);
static HookSite* GetOrCreateHookSiteLocked(void* target, const char* why);

// 阶段 B 是否已完成（InitializeGameCorePhase 成功置 true；ResetForReload 复位）。
static bool g_gameCorePhaseReady = false;

// 插件身份用的路径规范化：小写 + '/'→'\\'。**故意只做词法处理**——它定义 ownerId、
// CategoryForPath 与"按路径去重"，都在热路径上（每次 owner 探针/取址都可能走到），
// 不能引入 I/O 或符号链接解析。需要"同一条路径的不同写法（8.3 短名/软链/大小写）"
// 归一的场景（扫描根授权、排除自身）用 EnabledMods::NormalizePath（weakly_canonical）。
static std::wstring NormalizePluginPath(const std::wstring& path) {
    std::wstring norm = path;
    for (wchar_t& ch : norm) {
        if (ch == L'/') {
            ch = L'\\';
        } else {
            ch = std::towlower(ch);
        }
    }
    return norm;
}

// 按路径含 \Plugins\Global\（大小写不敏感）判类别；其余视为 GameCore。
static LoaderCore::PluginCategory CategoryForPath(const std::wstring& path) {
    return NormalizePluginPath(path).find(L"\\plugins\\global\\") != std::wstring::npos
        ? LoaderCore::PluginCategory::Global
        : LoaderCore::PluginCategory::GameCore;
}

// Civ6PluginKind 导出低 32 位的 kind -> 插件类别。1=Global，2=GameCore；
// 3 预留给未来的 Frontend（未支持），其余一律未知 -> 拒载。
static bool KindToCategory(uint32_t kind, LoaderCore::PluginCategory& out) {
    if (kind == 1u) { out = LoaderCore::PluginCategory::Global; return true; }
    if (kind == 2u) { out = LoaderCore::PluginCategory::GameCore; return true; }
    return false;
}

// teardown 窗口：写侧是游戏线程（ResetForReload / 两个 detour），读侧还有插件线程
// （TargetInTearingDownGameCore），两个字段必须"成对生效"而不是各写各的裸变量。
// 写序固定：先 size 再 address(release)；清零点：先 address(release) 再 size。
// 读序固定：先 address(acquire)，非 0 才读 size。见 docs/ARCHITECTURE.md §2.1。
static std::atomic<uintptr_t> g_gameCoreTeardownAddress{ 0 };
static std::atomic<uint32_t> g_gameCoreTeardownSizeOfImage{ 0 };

static void SetGameCoreTeardownWindow(uintptr_t base, uint32_t sizeOfImage) {
    g_gameCoreTeardownSizeOfImage.store(sizeOfImage, std::memory_order_relaxed);
    g_gameCoreTeardownAddress.store(base, std::memory_order_release);
}

struct PushTargetConfig {
    PushMethodSigType signature = PushMethodSigType::NoManager;
    std::string symbolName;
};

// Loader 内置目标只读；插件自定义目标保存在自己的 owner 命名空间，
// 防止一个插件覆盖另一个插件的签名或符号。
static const unordered_map<string, PushTargetConfig> g_defaultPushTargetConfigs = {
    {"GameCore::Cache::Lua::IQuestsManager",
        { PushMethodSigType::WithManager, "GameCore::Cache::Lua::IQuestsManager::PushMethods" }},
    {"GameCore::Lua::IQuestsManager",
        { PushMethodSigType::NoManager, "GameCore::Lua::IQuestsManager::PushMethods" }},
};
static unordered_map<std::wstring, unordered_map<string, PushTargetConfig>>
    g_pluginPushTargetConfigs;

// Symbol RVAs live in Civ6DllLoader.symdb.bin (see PdataMatch.cpp).

static mutex g_scriptStateMutex;
static mutex g_pushStateMutex;
static atomic<uint32_t> g_activeSharedDetours{ 0 };
static mutex g_detourDrainMutex;
static condition_variable g_detourDrainCv;

class SharedDetourActivity {
public:
    SharedDetourActivity() {
        g_activeSharedDetours.fetch_add(1, std::memory_order_acq_rel);
    }
    ~SharedDetourActivity() {
        if (g_activeSharedDetours.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            lock_guard<mutex> lock(g_detourDrainMutex);
            g_detourDrainCv.notify_all();
        }
    }
};

namespace fs = std::filesystem;

// owner 归属查询的返回：ownerId + 该 owner 的插件类别（Global / GameCore）。
// 类别在同一次 g_plugins 遍历里带回，不额外加锁、不额外遍历。
struct CallerPluginInfo {
    std::wstring ownerId;
    LoaderCore::PluginCategory category = LoaderCore::PluginCategory::Global;
};

static std::optional<CallerPluginInfo> ResolvePluginOwnerForAddress(const void* codeAddress) {
    if (!codeAddress) return std::nullopt;

    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(codeAddress), &module)) {
        return std::nullopt;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    for (const auto& entry : g_plugins) {
        if (entry.handle != module) continue;
        if (!g_activePluginOwner.empty() && module == g_activePluginModule &&
                entry.ownerId == g_activePluginOwner &&
                entry.state != PluginState::Quarantined) {
            return CallerPluginInfo{ entry.ownerId, entry.category };
        }
        if ((entry.state == PluginState::Loading ||
                entry.state == PluginState::Active) &&
                entry.handle == module) {
            return CallerPluginInfo{ entry.ownerId, entry.category };
        }
    }
    return std::nullopt;
}

static std::optional<CallerPluginInfo> RequirePluginOwner(const void* codeAddress,
                                                           const char* apiName) {
    auto owner = ResolvePluginOwnerForAddress(codeAddress);
    if (!owner || owner->ownerId.empty()) {
        Logger::Log("%s rejected: caller/callback is not an active plugin", apiName);
        return std::nullopt;
    }
    return owner;
}

static bool TargetInCurrentGameCore(void* target) {
    const HookImageId image = ImageAddress::LoadedGameCore();
    return image != kHookImageInvalid && ImageAddress::Contains(image, target);
}

// CategoryNameForLog 的定义在本文件后部（LoaderCore 实现段），此处前向声明，
// 供下面的地址开放性日志使用。
static const char* CategoryNameForLog(LoaderCore::PluginCategory cat);

// GameCore 专属入口的运行期兜底门：编译期门禁（HookAPI.h 的宏重命名）之外的第二道门，
// 防的是不带 HookAPI.h、按结构体偏移直接调这些入口的插件。owner 缺失或不是 GameCore
// 类别一律拒绝，调用方按各自原失败值返回。
static bool RequireGameCoreOwner(const void* codeAddress, const char* apiName) {
    const auto owner = ResolvePluginOwnerForAddress(codeAddress);
    if (!owner || owner->category != LoaderCore::PluginCategory::GameCore) {
        Logger::Log("%s rejected: GameCore-only API called by %s", apiName,
            owner ? CategoryNameForLog(owner->category) : "unknown");
        return false;
    }
    return true;
}

// ================= 地址开放性门：调用方类别 × 目标地址域 =================
// 只对"取地址/给地址"的入口设门。域的划分依据：GameCore 映像是随对局重载的【短命域】，
// 常驻（Global）插件若跨代持有它的地址就会在重载后悬垂；反之 GameCore 插件只应在自己
// 这一代映像内活动。三类判定都只读，不改动任何状态、不抛异常；拒绝时按统一格式记日志
// （地址/映像对调用方不开放），调用方按其原本的失败值返回。
// 日志正文统一为：<ApiName> rejected: target|image|range <位点> is not open to caller (<Global|GameCore>)
//
// 规则是【正面】的（"允许落在哪里"），不是"不在 GameCore 里就算数"：
//   GameCore 类别：目标必须落在【当前 GameCore 映像】内（它唯一的合法域）；
//   Global  类别：目标必须落在【某个已加载的非 GameCore 模块】内 —— exe、常驻系统 dll
//                 （user32/dxgi…）、插件自己的模块都算；堆、VirtualAlloc 的 JIT 页、空闲
//                 地址、以及将来会被 GameCore 占用的地址一律拒绝。
// 旧的"与当前 GameCore 映像不相交就放行"为什么不行：GameCore 未加载时（阶段 A）它对任何
// 地址都放行，"Global 绝对不许动 GameCore dll"就只能靠"那块内存写不进去/不可执行"兜住，
// 而不是一条可判定、可解释的规则。

// 目标整段是否落在【同一个已加载模块】的映像内。
// 不解析 PE：两端各自的所属模块句柄相同即证明整段同属一个模块映像；堆 / VirtualAlloc 的
// JIT 页 / 空闲地址拿不到模块句柄（或两端不同），直接判否。
static bool RangeInsideOneLoadedModule(const void* target, size_t len) {
    if (!target || len == 0) return false;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(target);
    const uintptr_t end = begin + len;
    if (end < begin) return false;   // 回绕：判否
    HMODULE firstModule = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(target), &firstModule) || !firstModule) {
        return false;
    }
    HMODULE lastModule = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(end - 1), &lastModule) || !lastModule) {
        return false;
    }
    return firstModule == lastModule;
}

// 单个目标地址：GameCore 类别要求落在【当前 GameCore 映像】内；Global 类别要求落在某个
// 已加载的非 GameCore 模块内（见上面的规则）。
static bool IsTargetOpenToCaller(LoaderCore::PluginCategory caller, const void* target, const char* apiName) {
    const bool inGameCore = TargetInCurrentGameCore(const_cast<void*>(target));
    const bool ok = (caller == LoaderCore::PluginCategory::GameCore)
        ? inGameCore
        : (!inGameCore && RangeInsideOneLoadedModule(target, 1));
    if (!ok) {
        Logger::Log("%s rejected: target %p is not open to caller (%s)",
            apiName, target, CategoryNameForLog(caller));
    }
    return ok;
}

// 解析目标映像：GameCore 类别的 image 必须是 GameCore 系（kHookImageGameCoreBase/XP1/XP2）；
// Global 类别的 image 不得是 GameCore 系（exe / 其它常驻模块放行）。
// image 是否已加载不在这里判——交回 *Core（保持原失败路径与日志不变）。
static bool IsImageOpenToCaller(LoaderCore::PluginCategory caller, HookImageId image, const char* apiName) {
    const bool gameCoreFamily = image == kHookImageGameCoreBase ||
        image == kHookImageGameCoreXP1 || image == kHookImageGameCoreXP2;
    const bool ok = (caller == LoaderCore::PluginCategory::GameCore) ? gameCoreFamily : !gameCoreFamily;
    if (!ok) {
        Logger::Log("%s rejected: image %u is not open to caller (%s)",
            apiName, static_cast<unsigned>(image), CategoryNameForLog(caller));
    }
    return ok;
}

// 整段范围（Patch 用）：GameCore 类别要求 [target, target+len) 全落在当前 GameCore 映像内；
// Global 类别要求整段与当前 GameCore 映像不相交【且】整段落在同一个已加载的非 GameCore
// 模块内（正面规则，见上面的说明）。
// 区间算术一律用无溢出的差值比较（len <= PluginBoundary::kMaxPluginRawBytes，地址为实址）。
static bool IsRangeOpenToCaller(LoaderCore::PluginCategory caller, const void* target, size_t len, const char* apiName) {
    HookImageInfo gcInfo{ sizeof(HookImageInfo) };
    const HookImageId gcImage = ImageAddress::LoadedGameCore();
    const bool hasGameCore = gcImage != kHookImageInvalid &&
        ImageAddress::GetInfo(gcImage, &gcInfo) && gcInfo.imageSize != 0;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(target);
    bool ok = false;
    if (caller == LoaderCore::PluginCategory::GameCore) {
        ok = hasGameCore && begin >= gcInfo.base && len <= gcInfo.imageSize &&
            (begin - gcInfo.base) <= gcInfo.imageSize - len;
    } else {
        const bool disjoint = !hasGameCore ||
            (begin >= gcInfo.base ? (begin - gcInfo.base) >= gcInfo.imageSize
                                  : (gcInfo.base - begin) >= len);
        ok = disjoint && RangeInsideOneLoadedModule(target, len);
    }
    if (!ok) {
        Logger::Log("%s rejected: range %p len=%zu is not open to caller (%s)",
            apiName, target, len, CategoryNameForLog(caller));
    }
    return ok;
}

static bool TargetInTearingDownGameCore(void* target) {
    const uintptr_t base = g_gameCoreTeardownAddress.load(std::memory_order_acquire);
    if (base == 0) return false;   // 窗口未进入（或已清）：size 不必读
    const uint32_t sizeOfImage = g_gameCoreTeardownSizeOfImage.load(std::memory_order_relaxed);
    const uintptr_t p = reinterpret_cast<uintptr_t>(target);
    return p >= base && p - base < sizeOfImage;
}

// 生成统一中转 stub（裸 x64 机器码，Windows x64 调用约定）。
// 快路径（hasCapture == 0，Detour-only 站点的常态）：
//   mov r10, imm64(site)
//   cmp byte ptr [r10 + off(hasCapture)], 0
//   jne slow
//   mov rax, [r10 + off(nextTarget)]
//   jmp rax
// 慢路径（有 capture）：
//   sub rsp, 0x98
//   mov [rsp+20],rcx / [rsp+28],rdx / [rsp+30],r8 / [rsp+38],r9
//   movaps [rsp+40],xmm0 / [rsp+50],xmm1 / [rsp+60],xmm2 / [rsp+70],xmm3
//   lea rcx,[rsp+20] ; mov edx,[r10+off(captureParamIndex)] ; mov r8,r10
//   mov r10, imm64(&CaptureDispatch) ; call r10
//   恢复 rcx/rdx/r8/r9 + xmm0-3
//   add rsp, 0x98
//   mov r10, imm64(site)          ; C 调用会打掉 r10，必须重载
//   mov rax, [r10 + off(nextTarget)]
//   jmp rax
// rax/r10/r11 在函数入口是 volatile，且都不是参数寄存器，快路径只动 rax/r10。
// 栈对齐：入口 rsp ≡ 8 (mod 16)，sub 0x98（≡8）后 rsp ≡ 0 (mod 16)，[rsp+0..0x20)
// 恰好是 CaptureDispatch 的 shadow space，[rsp+0x20..0x80) 保存参数（movaps 目标全部
// 16 字节对齐）。慢路径不调用任何"进入/离开"计数（stub 与节点永不释放，计数不构成安全判据）：
// 计数不是安全判据（见 HookSite 注释）。
// stub 运行时从 site 字段读 nextTarget，因此 MinHook trampoline 可在 stub 生成之后由
// MH_CreateHook 回填，无需生成后回写任何可执行字节。
static bool BuildHookHubStub(HookSite* site, void** outStub) {
    using namespace asmjit;
    CodeHolder code;
    if (code.init(g_captureRuntime.environment(), g_captureRuntime.cpu_features()) != Error::kOk) {
        return false;
    }
    x86::Assembler a(&code);
    const Label slow = a.new_label();
    const int32_t offHasCapture = static_cast<int32_t>(offsetof(HookSite, hasCapture));
    const int32_t offNextTarget = static_cast<int32_t>(offsetof(HookSite, nextTarget));
    const int32_t offParamIndex = static_cast<int32_t>(offsetof(HookSite, captureParamIndex));

    // 快路径：无 capture -> 直接尾跳（不保存参数、不发生 C 调用）。
    a.mov(x86::r10, reinterpret_cast<uintptr_t>(site));
    a.cmp(x86::byte_ptr(x86::r10, offHasCapture), 0);
    a.jne(slow);
    a.mov(x86::rax, x86::ptr(x86::r10, offNextTarget));
    a.jmp(x86::rax);

    // 慢路径：保存参数 -> CaptureDispatch -> 恢复 -> 尾跳 nextTarget。
    a.bind(slow);
    a.sub(x86::rsp, 0x98);
    a.mov(x86::ptr(x86::rsp, 0x20), x86::rcx);
    a.mov(x86::ptr(x86::rsp, 0x28), x86::rdx);
    a.mov(x86::ptr(x86::rsp, 0x30), x86::r8);
    a.mov(x86::ptr(x86::rsp, 0x38), x86::r9);
    a.movaps(x86::ptr(x86::rsp, 0x40), x86::xmm0);
    a.movaps(x86::ptr(x86::rsp, 0x50), x86::xmm1);
    a.movaps(x86::ptr(x86::rsp, 0x60), x86::xmm2);
    a.movaps(x86::ptr(x86::rsp, 0x70), x86::xmm3);
    a.lea(x86::rcx, x86::ptr(x86::rsp, 0x20));
    a.mov(x86::edx, x86::dword_ptr(x86::r10, offParamIndex));
    a.mov(x86::r8, x86::r10);
    a.mov(x86::r10, reinterpret_cast<uintptr_t>(&CaptureDispatch));
    a.call(x86::r10);
    a.mov(x86::rcx, x86::ptr(x86::rsp, 0x20));
    a.mov(x86::rdx, x86::ptr(x86::rsp, 0x28));
    a.mov(x86::r8, x86::ptr(x86::rsp, 0x30));
    a.mov(x86::r9, x86::ptr(x86::rsp, 0x38));
    a.movaps(x86::xmm0, x86::ptr(x86::rsp, 0x40));
    a.movaps(x86::xmm1, x86::ptr(x86::rsp, 0x50));
    a.movaps(x86::xmm2, x86::ptr(x86::rsp, 0x60));
    a.movaps(x86::xmm3, x86::ptr(x86::rsp, 0x70));
    a.add(x86::rsp, 0x98);
    a.mov(x86::r10, reinterpret_cast<uintptr_t>(site));
    a.mov(x86::rax, x86::ptr(x86::r10, offNextTarget));
    a.jmp(x86::rax);

    void* stub = nullptr;
    if (g_captureRuntime.add(&stub, &code) != Error::kOk || !stub) {
        return false;
    }
    *outStub = stub;
    return true;
}

// 取/建 target 上的统一站点。调用方必须持有 Runtime::MinHookMutex()（站点锁）。
// 首次建站（或 recordStale 强制重建）才 MH_CreateHook + MH_EnableHook。
// 失败不抛异常：记日志并返回 nullptr；只有确认"这个节点刚建、还没被任何调用者看到"
// （created）时才 erase 它；erase 之后绝不再使用 site 引用。
static HookSite* GetOrCreateHookSiteLocked(void* target, const char* why) {
    if (!target) return nullptr;

    auto it = g_hookSites.find(target);
    const bool created = (it == g_hookSites.end());
    if (created) {
        it = g_hookSites.emplace(target, HookSite{}).first;
    }
    HookSite* site = &it->second;

    if (!created && site->poisoned) {
        Logger::Log("HookSite: target %p is poisoned (stale MinHook record from an unmapped image); "
                    "refusing (%s)", target, why ? why : "");
        return nullptr;
    }

    if (!created && !site->recordStale && site->hookInstalled) {
        return site;   // 既有、可用
    }

    if (!created && site->recordStale) {
        // recordStale：上一次 GameCore teardown 没能摘掉这条 MinHook 记录（目标映像当时
        // 已卸载 -> Disable/Remove 都失败）。此刻 target 是调用方刚解析出来的地址，可读。
        // 前置判据：当前字节必须与建记录时的副本一致（= 同一个函数），否则 MinHook 的
        // Disable/Remove 会把**旧映像备份的字节**写进当前映射的代码。
        bool samePrologue = false;
        if (site->prologueValid) {
            uint8_t current[HookSite::kGuardBytes] = {};
            if (PluginBoundary::TryReadRaw(target, current, HookSite::kGuardBytes,
                    HookSite::kGuardBytes)) {
                samePrologue = std::memcmp(current, site->prologueBackup,
                    HookSite::kGuardBytes) == 0;
            }
        }
        if (!samePrologue) {
            site->poisoned = true;
            Logger::Log("HookSite: recordStale target=%p 前导字节与建记录时不一致（旧映像已卸载/地址被复用）；"
                        "拒绝触碰它的 MinHook 记录 (fail-closed) (%s)", target, why ? why : "");
            return nullptr;
        }
        Logger::Log("HookSite: recordStale rebuild target=%p (%s)", target, why ? why : "");
        if (site->hookInstalled && Runtime::IsReadableSpan(target, 1)) {
            MH_DisableHook(target);
            const MH_STATUS st = MH_RemoveHook(target);
            if (st != MH_OK && st != MH_ERROR_NOT_CREATED) {
                Logger::Log("HookSite: stale hook remove failed target=%p status=%s",
                    target, MH_StatusToString(st));
            }
        }
        site->hookInstalled = false;
        site->minhookTrampoline = nullptr;
        site->activeDetour = nullptr;
        site->detourOwner.clear();
        // 绝不可置 nullptr：recordStale 只证明"入口字节已还原"，不能证明"没有调用者停在 stub 里"。
        // 指向 target = 让在途调用者直接执行原函数（与 RemoveHookSiteRecordLocked 的 b 步同理）。
        site->nextTarget = target;
        std::lock_guard<std::mutex> captureLock(g_captureMutex);
        site->hasCapture = false;
        site->retiring = false;
        site->captureOuts.clear();
        site->recordStale = false;
    }

    if (!site->stubCode && !BuildHookHubStub(site, &site->stubCode)) {
        Logger::Log("HookSite: stub build failed target=%p (%s)", target, why ? why : "");
        if (created) g_hookSites.erase(it);
        return nullptr;
    }

    MH_STATUS status = MH_CreateHook(target, site->stubCode, &site->minhookTrampoline);
    if (status == MH_ERROR_ALREADY_CREATED) {
        // 只有「本站节点已存在（!created）」**且当前字节与建记录时的副本一致**才可能是本站
        // 自己的残留记录（例如上一次 teardown 的 MH_RemoveHook 失败）。对全新站点、
        // 或字节对不上的地址，ALREADY_CREATED 只可能是别人的钩子；无条件摘除会释放对方的
        // trampoline（跳板指针悬垂、静默顶掉 Lua 脚本全局注册），并把旧字节写进当前映像。
        bool ownLeftover = false;
        if (!created && site->prologueValid) {
            uint8_t current[HookSite::kGuardBytes] = {};
            ownLeftover = PluginBoundary::TryReadRaw(target, current, HookSite::kGuardBytes,
                HookSite::kGuardBytes) &&
                std::memcmp(current, site->prologueBackup, HookSite::kGuardBytes) == 0;
        }
        if (ownLeftover) {
            MH_RemoveHook(target);
            status = MH_CreateHook(target, site->stubCode, &site->minhookTrampoline);
        } else {
            Logger::Log("HookSite: target %p already hooked by another owner; refusing to replace (%s)",
                target, why ? why : "");
            if (created) g_hookSites.erase(it);
            else site->poisoned = true;   // 不是我们的记录：别再碰这个地址
            return nullptr;
        }
    }
    if (status != MH_OK) {
        Logger::Log("HookSite: MH_CreateHook failed target=%p status=%s (%s)",
            target, MH_StatusToString(status), why ? why : "");
        if (created) g_hookSites.erase(it);
        return nullptr;
    }
    // 保存前导字节副本（供将来 recordStale 判断"同一函数"）。MH_CreateHook 不改入口字节，
    // 所以此刻读到的就是 MinHook 备份下来的那几字节。
    site->prologueValid = PluginBoundary::TryReadRaw(target, site->prologueBackup,
        HookSite::kGuardBytes, HookSite::kGuardBytes);
    if (!site->prologueValid) {
        Logger::Log("HookSite: target %p 前导字节不可读；本次仍建站，但 recordStale 只能 fail-closed (%s)",
            target, why ? why : "");
    }
    // 先把 stub 的尾跳目标置为新 trampoline，再 Enable：否则 Enable 之后、赋值之前进入
    // stub 的调用会 jmp 到 nullptr。
    site->nextTarget = site->minhookTrampoline;
    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("HookSite: MH_EnableHook failed target=%p status=%s (%s)",
            target, MH_StatusToString(status), why ? why : "");
        MH_RemoveHook(target);
        if (created) g_hookSites.erase(it);
        return nullptr;
    }
    site->hookInstalled = true;
    Logger::Log("HookSite: installed hub stub target=%p stub=%p trampoline=%p (%s)",
        target, site->stubCode, site->minhookTrampoline, why ? why : "");
    return site;
}

// 把 Loader 共享钩（ScriptData / ForUI / PushMethods）挂到 target 的统一站点上。
// 共享钩在站点里的表现：activeDetour = detour、detourOwner 恒为空、nextTarget = detour。
// 调用方不得持 Runtime::MinHookMutex()：内部自取（站点取/建要求持锁）。
// 幂等：同一 detour 已在站点上时直接返回当前跳板。
// 独占：站点已有别的 detour（插件或另一个共享钩）时拒绝，构成双向互斥。
//
// 【顺序约束】屏障是「nextTarget = detour 之前必须备好 origSlot」，不是 MH_EnableHook
// 之前——站点首次建立后 MinHook 侧已经 Enable，但此刻 nextTarget 只是 trampoline
// （纯透传）；detour 只有靠把 nextTarget 置为 detour 才被真正激活。因此必须先把
// origSlot 写成 trampoline，再发布 activeDetour/nextTarget，否则并发的首次调用会从
// stub 跳到 nullptr（只可能发生在站点刚建好、还没赋 nextTarget 的窗口，见
// GetOrCreateHookSiteLocked 里同一条约束）。
static bool InstallLoaderDetourOnSite(void* target, void* detour, void** origSlot, const char* why) {
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    HookSite* site = GetOrCreateHookSiteLocked(target, why);
    if (!site) {
        Logger::Log("InstallLoaderDetourOnSite: hook site unavailable target=%p (%s)",
            target, why ? why : "");
        return false;
    }
    if (site->activeDetour == detour) {
        if (origSlot) *origSlot = site->minhookTrampoline;
        return true;   // 幂等
    }
    if (site->activeDetour) {
        Logger::Log("InstallLoaderDetourOnSite: target %p already has detour=%p (owner=%ls) (%s)",
            target, site->activeDetour, site->detourOwner.c_str(), why ? why : "");
        return false;
    }
    if (origSlot) *origSlot = site->minhookTrampoline;
    site->activeDetour = detour;
    site->detourOwner.clear();
    site->nextTarget = detour;
    Logger::Log("InstallLoaderDetourOnSite: target=%p detour=%p trampoline=%p (%s)",
        target, detour, site->minhookTrampoline, why ? why : "");
    return true;
}

// 退役站点 detour 槽：只拔插槽，绝不 MH_RemoveHook / g_hookSites.erase。
// 调用方必须持有 Runtime::MinHookMutex()。
static size_t RetireHookSiteDetoursForOwnerLocked(const std::wstring& owner) {
    if (owner.empty()) return 0;
    size_t retired = 0;
    for (auto& [target, site] : g_hookSites) {
        if (site.activeDetour && site.detourOwner == owner) {
            site.activeDetour = nullptr;
            site.detourOwner.clear();
            site.nextTarget = site.minhookTrampoline;
            ++retired;
            Logger::Log("HookSite: retired detour slot %p (owner=%ls)", target, owner.c_str());
        }
    }
    return retired;
}

// 字节修改仲裁：MinHook 会改写目标函数的前导字节。同一个函数既被 InstallHook 装钩、
// 又被 Patch 打补丁时，两侧各自的"恢复原始字节"会互相覆盖，最终恢复出第三种字节状态
// （谁先卸载谁踩谁）。这里做双向检查：
//   - 装钩前：目标前导窗口是否与已登记补丁重叠 -> InstallHookImpl
//   - 打补丁前：目标区间是否压住某个已装钩目标的前导窗口 -> HookPatch
// 窗口取与"可读探测"同一口径（32 字节，保守）。
constexpr size_t kHookPrologueWindow = PluginBoundary::kMinHookTargetSpan;

// 调用方不得持 Runtime::MinHookMutex()（内部自己取）。只看统一的站点表：
// Loader 共享钩（ScriptData / ForUI / PushMethods）与插件 detour 都是站点，
// 只有站点的 MinHook 侧（hookInstalled）才改写过目标前导字节。
static bool OverlapsHookPrologue(const void* target, size_t len) {
    if (!target || len == 0) return false;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(target);
    const uintptr_t end = begin + len;
    if (end < begin) return true;   // 地址回绕：按冲突处理
    lock_guard<mutex> lock(Runtime::MinHookMutex());
    for (const auto& [siteTarget, site] : g_hookSites) {
        if (!site.hookInstalled) continue;   // 未 Enable 的站点尚未改写前导字节
        const uintptr_t hookBegin = reinterpret_cast<uintptr_t>(siteTarget);
        const uintptr_t hookEnd = hookBegin + kHookPrologueWindow;
        if (begin < hookEnd && hookBegin < end) return true;
    }
    return false;
}

// 插件 Detour 入口：不再直接 MH_CreateHook(target, detour)，而是把 detour 挂进
// target 的统一站点（MinHook 只挂一次，挂到站点 stub）。同一 target 已有 Detour 时
// 明确拒绝（Detour 槽独占）；Capture 槽可与之共存，挂载顺序无关。
bool InstallHookImpl(void* target, void* detour, void** original) {
    // target 是插件解析出来的【游戏代码地址】，original 是插件给自己的【输出槽】：
    // 两者都是调用方传入的指针值，有效性无法假定，必须在取锁【之前】用页属性探测拦掉坏地址。
    // 否则 MinHook 读目标前导字节时出错，会把 g_pluginLifecycleMutex 与
    // Runtime::MinHookMutex() 一起泄漏（/EHsc 下 lock_guard 不析构 -> 永久死锁）。
    // 注意：target 属于游戏模块，不是插件内存——判据是"这个指针值可不可信"，不是"它属于谁"。
    if (!PluginBoundary::IsReadable(target, PluginBoundary::kMinHookTargetSpan)) {
        Logger::Log("InstallHook rejected: target not readable %p (span=%zu)",
            target, PluginBoundary::kMinHookTargetSpan);
        return false;
    }
    if (original && !PluginBoundary::IsWritable(original, sizeof(void*))) {
        Logger::Log("InstallHook rejected: original out-param not writable %p", original);
        return false;
    }
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    if (PatchRegistry::OverlapsRegistered(target, kHookPrologueWindow)) {
        Logger::Log("InstallHook rejected: target %p overlaps a registered patch "
                    "(unpatch it first)", target);
        return false;
    }
    if (TargetInTearingDownGameCore(target)) {
        Logger::Log("InstallHook rejected: target %p belongs to tearing-down GameCore", target);
        return false;
    }
    auto owner = RequirePluginOwner(detour, "InstallHook");
    if (!owner) return false;
    // 地址开放性门：调用方类别 × 目标地址域。此门取代原先的"Global owner 必须先注册
    // GameCoreTeardown"门槛——域门之后 Global 已不可能指向当前 GameCore，那段判断
    // 永远不可达（HasGameCoreTeardownCallback 随之删除）。
    if (!IsTargetOpenToCaller(owner->category, target, "InstallHook")) return false;

    // 锁序 lifecycle -> MinHook -> capture：站点在 MinHook 站点锁下取/建。
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    HookSite* site = GetOrCreateHookSiteLocked(target, "InstallHook");
    if (!site) {
        Logger::Log("InstallHook: hook site unavailable target=%p", target);
        return false;
    }
    if (site->activeDetour) {
        Logger::Log("InstallHook rejected: target %p already has a detour (owner=%ls detour=%p)",
            target, site->detourOwner.c_str(), site->activeDetour);
        return false;
    }
    // 顺序不可交换（与 InstallLoaderDetourOnSite 同一理由，见 docs/ARCHITECTURE.md §5.5）：
    // 站点首建时 MinHook 侧已 enable，但那一刻 nextTarget 只是跳板（纯透传）——把 nextTarget
    // 置为 detour 才是"插件 detour 开始生效"的那一刻。必须先备好跳板（*original）再发布，
    // 否则另一线程可能在这两行之间进入 detour，读到的 original 还是插件侧的未初始化值。
    if (original) *original = site->minhookTrampoline;
    site->activeDetour = detour;
    site->detourOwner = owner->ownerId;
    site->nextTarget = detour;
    Logger::Log("InstallHook: target=%p detour=%p original=%p owner=%ls (hub stub=%p)",
        target, detour, original ? *original : nullptr, owner->ownerId.c_str(), site->stubCode);
    return true;
}

// 物理摘除某个站点自己的 MinHook 记录（释放跳板），并把站点还原为「未挂钩」。
// 调用方必须持有 Runtime::MinHookMutex()。
//
// a -> b -> c 的顺序不可交换：
//   a) MH_DisableHook(target)：先把目标入口字节还原回原函数（幂等；MH_ERROR_DISABLED
//      说明本来就已停用，按成功处理）。这一步失败就整体放弃：入口没还原时 b/c 都
//      不成立；
//   b) site.nextTarget = target：入口字节已还原，此刻仍在 stub 里的在途调用者改去
//      执行原函数——安全且语义正确，且此后不会再有人引用这块跳板；
//   c) MH_RemoveHook(target)：释放跳板。必须排在 b 之后，否则在途线程会从 stub 直接
//      跳进已释放的跳板（UAF）。
// 摘除失败时保留站点记账（hookInstalled 等不动）；teardown 路径会给该站点打
// recordStale，交给下次在同一地址取站时强制重建。
static bool RemoveHookSiteRecordLocked(void* target, HookSite& site) {
    if (!target) return false;
    const MH_STATUS disable = MH_DisableHook(target);
    if (disable != MH_OK && disable != MH_ERROR_DISABLED) {
        // 入口字节没能还原（例如映像已卸载 → MinHook 的 VirtualProtect 失败返回
        // MH_ERROR_MEMORY_PROTECT）：此时【绝不能】把 nextTarget 指向 target——入口
        // 仍跳本站 stub，stub 再跳 target 就成了死循环；记录与跳板原样保留，由调用方
        // 决定是否打 recordStale（teardown 路径）交给下次取站重建。
        Logger::Log("RemoveHookSiteRecord: MH_DisableHook(%p) -> %s; record retained",
            target, MH_StatusToString(disable));
        return false;
    }
    site.nextTarget = target;   // 入口已还原：在途调用走原函数，不再碰跳板
    const MH_STATUS remove = MH_RemoveHook(target);
    if (remove != MH_OK && remove != MH_ERROR_NOT_CREATED) {
        Logger::Log("RemoveHookSiteRecord: MH_RemoveHook(%p) -> %s", target, MH_StatusToString(remove));
        return false;
    }
    site.hookInstalled = false;
    site.minhookTrampoline = nullptr;
    site.activeDetour = nullptr;
    site.detourOwner.clear();
    Logger::Log("RemoveHookSiteRecord: removed MinHook record target=%p", target);
    return true;
}

void BroadcastMessageImpl(const char* topic, const void* data, size_t len) {
    g_bus.Broadcast(topic, data, len);
}

// 显式注册与 OnMessage 自动注册共用：消息地址只能来自 Loader 跟踪的插件名。
// 调用时不得持 lifecycle 锁；替换旧回调可能等待正在使用 HookAPI 的其它线程。
static bool RegisterPluginMessageHandler(const std::wstring& owner, MessageHandlerFn handler) {
    if (!handler) return false;
    std::string handlerName;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
            [&owner](const PluginEntry& entry) { return entry.ownerId == owner; });
        if (plugin == g_plugins.end() ||
            (plugin->state != PluginState::Loading && plugin->state != PluginState::Active)) {
            Logger::Log("RegisterMessageHandler rejected: plugin is not loading/active");
            return false;
        }
        const auto callbackOwner = ResolvePluginOwnerForAddress(reinterpret_cast<const void*>(handler));
        if (!callbackOwner || callbackOwner->ownerId != owner) {
            Logger::Log("RegisterMessageHandler rejected: callback does not belong to plugin");
            return false;
        }
        handlerName = ModScan::WideToNarrow(plugin->name);
        if (handlerName.empty() || handlerName == "Loader") {
            Logger::Log("RegisterMessageHandler rejected: empty or reserved plugin name");
            return false;
        }
    }
    // 总线锁 -> lifecycle 锁。若停用先发生则拒绝；若发布先发生，随后的
    // UnregisterOwner 必然能清除此登记，避免校验后停用又把 handler 注册回来。
    return g_bus.RegisterHandler(handlerName, handler, owner, [&owner] {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        const bool active = std::any_of(g_plugins.begin(), g_plugins.end(),
            [&owner](const PluginEntry& entry) {
                return entry.ownerId == owner &&
                    (entry.state == PluginState::Loading || entry.state == PluginState::Active);
            });
        if (!active) Logger::Log("RegisterMessageHandler rejected: plugin stopped before registration");
        return active;
    });
}

bool RegisterMessageHandlerImpl(MessageHandlerFn handler) {
    if (!handler) return false;
    // 与其它回调 API 一样按 handler 所属模块确定 owner；返回地址会因尾调用
    // 优化落在 Loader/引擎内，不能用来可靠识别插件。
    const auto owner = RequirePluginOwner(reinterpret_cast<const void*>(handler),
        "RegisterMessageHandler");
    return owner && RegisterPluginMessageHandler(owner->ownerId, handler);
}

void SendMessageToImpl(const char* pluginName, const char* topic, const void* data, size_t len) {
    // pluginName 是插件内存，而 SendTo 收 const std::string&：直接传进去会按 NUL 边界读它。
    // MSVC 的 basic_string(const char*) 不检查空指针（直接 traits::length），空指针/野指针
    // 都是一次裸 strlen。与其它字符串入口同一口径：锁外先抄进 Loader 自有存储。
    std::string nameCopy;
    if (!PluginBoundary::CopyCString(pluginName, nameCopy) || nameCopy.empty()) {
        Logger::Log("SendMessageTo rejected: pluginName pointer unreadable or empty");
        return;
    }
    g_bus.SendTo(nameCopy, topic, data, len);
}

bool IsImageLoadedImpl(HookImageId image) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    return ImageAddress::IsLoaded(image);
}

bool GetImageInfoImpl(HookImageId image, HookImageInfo* outInfo) {
    // outInfo 是插件内存：ImageAddress::GetInfo 会先【读】structSize 再【写】字段，
    // 而 GameCore 分支的写发生在 ImageAddress::g_mutex 内。坏地址在这里出错会泄漏
    // 那两把锁，所以进锁前先做读写探测（VirtualQuery 不会出错）。
    if (!PluginBoundary::IsReadableWritable(outInfo, sizeof(HookImageInfo))) {
        Logger::Log("GetImageInfo rejected: outInfo not readable+writable %p (need %zu bytes)",
            static_cast<const void*>(outInfo), sizeof(HookImageInfo));
        return false;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    return ImageAddress::GetInfo(image, outInfo);
}

// 按段名（.text/.idata/.rdata/.data；PE 段名为 8 字节非 NUL 终止数组）定位镜像内段的
// RVA 与大小（大小 = max(SizeOfRawData, VirtualSize)）。找不到段返回 false。
static bool ResolveSectionRva(HookImageId image, const char* sectionName,
    uintptr_t* outRva, size_t* outSize) {
    if (!sectionName || !outRva || !outSize) return false;
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(image, &info) || info.base == 0) return false;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(info.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(info.base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    // 段名比较：name 以 NUL 结束，逐字节对比至多 8 字节；name 提前结束即匹配成功
    // （PE 惯例段名 NUL/空格填充；name 更长时须 8 字节精确相等）。
    auto nameMatches = [](const IMAGE_SECTION_HEADER& sh, const char* name) -> bool {
        for (int i = 0; i < 8; ++i) {
            if (sh.Name[i] != static_cast<unsigned char>(name[i])) return false;
            if (name[i] == '\0') return true;
        }
        return true;
    };

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!nameMatches(*sec, sectionName)) continue;
        const size_t size = sec->Misc.VirtualSize > sec->SizeOfRawData
            ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        *outRva = sec->VirtualAddress;
        *outSize = size;
        return true;
    }
    return false;
}

// 内部分辨核心：不做插件边界校验、不加插件生命周期锁。
// Loader 自己（ResolveExeTarget / LoaderHooks / UiInject）走 Core；插件走下面的 *Impl。
// 这样游戏线程在 LoadDLL detour 里解析自家 hook 目标时，不会去拿那把可能被卡住的插件锁。
static void* ResolveByRvaCore(HookImageId image, uintptr_t rva, size_t span) {
    uintptr_t effectiveRva = rva;
    if (PdataMatch::HasContext(image)) {
        // 有该模块的 sidecar 上下文：插件传入的是旧映像坐标，先矫正到当前映像。
        // 版本一致时 CorrectRva 为恒等映射。
        const uintptr_t corrected = PdataMatch::CorrectRva(image, rva);
        if (corrected == 0) {
            Logger::Log("ResolveByRva: no pdata correction image=%u rva=0x%llX span=%zu",
                static_cast<unsigned>(image), static_cast<unsigned long long>(rva), span);
            return nullptr;
        }
        effectiveRva = corrected;
    }
    void* result = ImageAddress::ResolveByRva(image, effectiveRva, span);
    if (!result && ImageAddress::IsLoaded(image)) {
        Logger::Log("ResolveByRva: rejected image=%u rva=0x%llX span=%zu",
            static_cast<unsigned>(image),
            static_cast<unsigned long long>(effectiveRva), span);
    }
    return result;
}

// 插件入口：参数全是标量（没有需要锁外抄写的插件内存），只需加锁。
void* ResolveByRvaImpl(HookImageId image, uintptr_t rva, size_t span) {
    // 地址开放性门：调用方类别 × 解析目标映像域（本入口没有 loader 内部调用者，内部走 *Core）。
    auto caller = RequirePluginOwner(_ReturnAddress(), "ResolveByRva");
    if (!caller || !IsImageOpenToCaller(caller->category, image, "ResolveByRva")) return nullptr;
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    return ResolveByRvaCore(image, rva, span);
}

// 内部核心：name 由调用方保证可读（Loader 用字面量 / 插件先抄写）。
static void* ResolveByNameCore(HookImageId image, const char* nameSafe) {
    if (!ImageAddress::IsLoaded(image)) return nullptr;

    // 每个模块有各自 sidecar 上下文（容器：exe/GameCore 各自符号表）。
    if (!PdataMatch::HasContext(image)) {
        Logger::Log("ResolveByName: no symbol database for image=%u name=%s",
            static_cast<unsigned>(image), nameSafe);
        return nullptr;
    }

    // PdataMatch：sidecar 符号表存旧映像 RVA，按名矫正到当前映像后解析。
    const uintptr_t corrected = PdataMatch::CorrectByName(image, nameSafe);
    if (corrected == 0) {
        Logger::Log("ResolveByName: no symbol for image=%u name=%s",
            static_cast<unsigned>(image), nameSafe);
        return nullptr;
    }
    void* result = ImageAddress::ResolveByRva(image, corrected, 1);
    if (!result) {
        Logger::Log("ResolveByName: out-of-range RVA image=%u name=%s rva=0x%llX",
            static_cast<unsigned>(image), nameSafe,
            static_cast<unsigned long long>(corrected));
    }
    return result;
}

void* ResolveByNameImpl(HookImageId image, const char* name) {
    // 地址开放性门（RequirePluginOwner 只做模块归属查询，不解引用插件指针）。
    auto caller = RequirePluginOwner(_ReturnAddress(), "ResolveByName");
    if (!caller || !IsImageOpenToCaller(caller->category, image, "ResolveByName")) return nullptr;
    if (!name || !*name) return nullptr;

    // name 是插件内存：锁外先抄进 Loader 自有 string，锁内只碰副本
    // （PdataMatch 查表与日志都读它）。坏指针在这里失败，此时没有任何锁被持有。
    std::string nameCopy;
    if (!PluginBoundary::CopyCString(name, nameCopy) || nameCopy.empty()) {
        Logger::Log("ResolveByName rejected: name pointer unreadable");
        return nullptr;
    }

    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    return ResolveByNameCore(image, nameCopy.c_str());
}

void* ResolveByRvaExImpl(HookImageId image, uintptr_t rva, size_t span, HookImageSection section) {
    // 地址开放性门：调用方类别 × 解析目标映像域。
    auto caller = RequirePluginOwner(_ReturnAddress(), "ResolveByRvaEx");
    if (!caller || !IsImageOpenToCaller(caller->category, image, "ResolveByRvaEx")) return nullptr;
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (section == kSectionImage) {
        // 不修正：镜像相对 RVA 直接解析（供已按新映像坐标算好的调用方使用）。
        return ImageAddress::ResolveByRva(image, rva, span);
    }
    const char* sectionName = nullptr;
    switch (section) {
        case kSectionText:  sectionName = ".text";  break;
        case kSectionIdata: sectionName = ".idata"; break;
        case kSectionRdata: sectionName = ".rdata"; break;
        case kSectionData:  sectionName = ".data";  break;
        default: break;
    }
    if (!sectionName) {
        Logger::Log("ResolveByRvaEx: unknown section=%d image=%u rva=0x%llX span=%zu",
            static_cast<int>(section), static_cast<unsigned>(image),
            static_cast<unsigned long long>(rva), span);
        return nullptr;
    }
    uintptr_t sectionRva = 0;
    size_t sectionSize = 0;
    if (!ResolveSectionRva(image, sectionName, &sectionRva, &sectionSize)) {
        Logger::Log("ResolveByRvaEx: section %s not found image=%u",
            sectionName, static_cast<unsigned>(image));
        return nullptr;
    }
    return ImageAddress::ResolveByRva(image, sectionRva + rva, span);
}

// 内部核心：pattern 由调用方保证可读（Loader 用字面量 / 插件先抄写）。
static void* ResolveByPatternCore(HookImageId image, const char* pattern, HookImageSection section) {
    // 解析 AOB："48 8B ?? ?? 74 ?? E8"（?? 整字节通配，也支持单 nibble 如 4?）。
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> masks;
    const char* p = pattern;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == ',') ++p;
        if (!*p) break;
        uint8_t byte = 0, mask = 0;
        for (int nib = 0; nib < 2; ++nib) {
            // '?' 也占一个半字节；必须同样移位，否则 4? 会被解析成 ?4。
            byte = static_cast<uint8_t>(byte << 4);
            mask = static_cast<uint8_t>(mask << 4);
            const char c = *p;
            if (c == '?') {
                ++p;
            } else if (c >= '0' && c <= '9') {
                byte = static_cast<uint8_t>(byte | (c - '0'));
                mask = static_cast<uint8_t>(mask | 0xF);
                ++p;
            } else if (c >= 'a' && c <= 'f') {
                byte = static_cast<uint8_t>(byte | (c - 'a' + 10));
                mask = static_cast<uint8_t>(mask | 0xF);
                ++p;
            } else if (c >= 'A' && c <= 'F') {
                byte = static_cast<uint8_t>(byte | (c - 'A' + 10));
                mask = static_cast<uint8_t>(mask | 0xF);
                ++p;
            } else {
                Logger::Log("ResolveByPattern: invalid char '%c' in pattern \"%s\"", c, pattern);
                return nullptr;
            }
        }
        bytes.push_back(byte);
        masks.push_back(mask);
    }
    if (bytes.empty()) {
        Logger::Log("ResolveByPattern: empty pattern \"%s\"", pattern);
        return nullptr;
    }

    // 定位搜索范围（kSectionImage = 整个镜像；否则按段定位）。
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(image, &info) || info.base == 0) {
        Logger::Log("ResolveByPattern: image not loaded image=%u",
            static_cast<unsigned>(image));
        return nullptr;
    }
    uintptr_t searchBase = info.base;
    size_t searchSize = info.imageSize;
    if (section != kSectionImage) {
        const char* sectionName = nullptr;
        switch (section) {
            case kSectionText:  sectionName = ".text";  break;
            case kSectionIdata: sectionName = ".idata"; break;
            case kSectionRdata: sectionName = ".rdata"; break;
            case kSectionData:  sectionName = ".data";  break;
            default: break;
        }
        if (!sectionName) {
            Logger::Log("ResolveByPattern: unknown section=%d image=%u",
                static_cast<int>(section), static_cast<unsigned>(image));
            return nullptr;
        }
        uintptr_t sectionRva = 0;
        size_t sectionSize = 0;
        if (!ResolveSectionRva(image, sectionName, &sectionRva, &sectionSize)) {
            Logger::Log("ResolveByPattern: section %s not found image=%u",
                sectionName, static_cast<unsigned>(image));
            return nullptr;
        }
        const size_t avail = sectionRva < info.imageSize ? info.imageSize - sectionRva : 0;
        if (sectionSize > avail) sectionSize = avail;  // 防御：不越出映像映射
        searchBase = info.base + sectionRva;
        searchSize = sectionSize;
    }
    if (searchSize < bytes.size()) {
        Logger::Log("ResolveByPattern: pattern longer than region image=%u section=%d len=%zu",
            static_cast<unsigned>(image), static_cast<int>(section), bytes.size());
        return nullptr;
    }

    // PE 头声明的 SizeOfImage 不保证整段都已提交：声明值大于实际提交页时，线性扫描会读到
    // 未提交/守卫页，这里是裸指针访问且没有 SEH，一次访问违例就是整个游戏进程崩溃。
    // 扫描前对范围走一次 VirtualQuery（对任意地址都安全），不可读就拒绝（失败即关闭）。
    if (!Runtime::IsReadableSpan(reinterpret_cast<const void*>(searchBase), searchSize)) {
        Logger::Log("ResolveByPattern: region unreadable image=%u section=%d base=%p size=%zu",
            static_cast<unsigned>(image), static_cast<int>(section),
            reinterpret_cast<const void*>(searchBase), searchSize);
        return nullptr;
    }

    // 线性首命中搜索（mask 0 位 = 通配）。
    const uint8_t* basePtr = reinterpret_cast<const uint8_t*>(searchBase);
    const size_t limit = searchSize - bytes.size() + 1;
    for (size_t i = 0; i < limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if ((basePtr[i + j] & masks[j]) != bytes[j]) { match = false; break; }
        }
        if (match) {
            Logger::Log("ResolveByPattern: hit image=%u section=%d rva=0x%llX",
                static_cast<unsigned>(image), static_cast<int>(section),
                static_cast<unsigned long long>(i));
            return const_cast<uint8_t*>(basePtr + i);
        }
    }
    Logger::Log("ResolveByPattern: no hit image=%u section=%d pattern=\"%s\"",
        static_cast<unsigned>(image), static_cast<int>(section), pattern);
    return nullptr;
}

void* ResolveByPatternImpl(HookImageId image, const char* patternIn, HookImageSection section) {
    // 地址开放性门（RequirePluginOwner 只做模块归属查询，不解引用插件指针）。
    auto caller = RequirePluginOwner(_ReturnAddress(), "ResolveByPattern");
    if (!caller || !IsImageOpenToCaller(caller->category, image, "ResolveByPattern")) return nullptr;
    if (!patternIn || !*patternIn) {
        Logger::Log("ResolveByPattern: empty pattern");
        return nullptr;
    }
    // pattern 是插件内存：锁外抄写（原实现在锁内逐字节遍历它，一个没有结尾符的指针
    // 会一路读到出错 -> lock_guard 不析构 -> 锁永久泄漏），锁内只碰副本。
    std::string patternCopy;
    if (!PluginBoundary::CopyCString(patternIn, patternCopy) || patternCopy.empty()) {
        Logger::Log("ResolveByPattern rejected: pattern pointer unreadable");
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    return ResolveByPatternCore(image, patternCopy.c_str(), section);
}

// ---------------- RegisterGlobalCapture（全局参数捕获站） ----------------
// 站点结构 / stub 生成 / GetOrCreateHookSiteLocked 见文件前部「统一挂钩站点」。
// 本段只保留：派发器（CaptureDispatch）、注册入口、以及只拔插槽的退役路径。
// 语义：首个注册者在 target 上建统一站点（MinHook 挂到中转 stub）；后续同一站点的
// 注册只追加 out 槽。目标函数每次被调用时，stub 把第 captureParamIndex 个整数参数
// （rcx/rdx/r8/r9 之一）写入该站点的全部 out 槽。

// 叶子 shim：out 槽虽然在注册时已探过可写，但插件之后可能自行释放该地址或改页保护。
// 只有 POD 局部变量（MSVC C2712）；异常在这里被吃掉 —— 没有发生栈展开，调用方的
// lock_guard 照常析构，因此绝不会因这次写入失败而泄漏 g_captureMutex。
__declspec(noinline) static bool SafeWritePointer(void* dst, void* value) {
    __try {
        *reinterpret_cast<void**>(dst) = value;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// stub 慢路径调用的分发器：regs 指向 stub 栈帧保存的 4 个整数参数槽（rcx/rdx/r8/r9）。
// 锁序恒为 MinHook -> capture，因此这里【只】取 g_captureMutex。
// paramIndex 由 stub 传入，但一律以锁内站点字段为准（防止 stub 裸读到的陈旧值索引错
// 参数）；hasCapture/retiring/空 outs 任一不成立都直接返回（陈旧读到 1 的兜底）。
extern "C" void CaptureDispatch(void* regs, uint32_t paramIndex, void* sitePtr) {
    HookSite* site = static_cast<HookSite*>(sitePtr);
    if (!site || !regs) return;
    // paramIndex 只为 stub 的调用约定保留（它直接把站点字段读进 edx）；一律以锁内站点字段为准。
    (void)paramIndex;
    std::lock_guard<std::mutex> lock(g_captureMutex);
    if (!site->hasCapture || site->retiring) return;
    const uint32_t index = site->captureParamIndex;
    if (index > 3) return;
    if (site->captureOuts.empty()) return;
    const void* val = static_cast<void* const*>(regs)[index];
    for (const HookSite::CaptureOut& out : site->captureOuts) {
        if (!out.address) continue;
        if (!SafeWritePointer(out.address, const_cast<void*>(val))) {
            Logger::Log("CaptureDispatch: out slot not writable %p (plugin freed it?)",
                static_cast<const void*>(out.address));
        }
    }
}

// 捕获站点 stub 生成已合并到 BuildHookHubStub（见文件前部「统一挂钩站点」）。

// providerAddress 必须落在【可执行页】：它是函数入口，不是数据 —— 站点 stub 会尾跳进
// MinHook trampoline 去执行原函数前导，数据地址在这里没有意义。工程里没有现成的
// "可执行页"探测 helper（PluginBoundary::IsReadable/IsWritable 只探读/写，Runtime::
// IsReadableSpan 同源），因此按 LoaderCore::VerifyHookApiTableProtection 的写法走一次
// VirtualQuery：整段（kMinHookTargetSpan）逐区域要求 MEM_COMMIT、保护不含
// PAGE_NOACCESS/PAGE_GUARD，且含执行位。VirtualQuery 对任意地址都安全、不产生访问违例，
// 所以这个探测本身不需要 SEH，也不破坏 PluginBoundary 的"取锁前访存"不变量。
static bool IsExecutableTargetSpan(const void* p, size_t len) {
    if (!p || len == 0) return false;
    constexpr DWORD kExecMask = PAGE_EXECUTE | PAGE_EXECUTE_READ |
        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    const uint8_t* cur = static_cast<const uint8_t*>(p);
    size_t remain = len;
    while (remain > 0) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(cur, &mbi, sizeof(mbi)) == 0) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
        if ((mbi.Protect & kExecMask) == 0) return false;
        const size_t regionBytes = static_cast<size_t>(mbi.RegionSize)
            - static_cast<size_t>(cur - static_cast<const uint8_t*>(mbi.BaseAddress));
        if (regionBytes == 0) return false;   // 防御：RegionSize 解析异常，避免死循环
        const size_t consumed = regionBytes < remain ? regionBytes : remain;
        cur += consumed;
        remain -= consumed;
    }
    return true;
}

// RegisterGlobalCapture 内部核心（无插件 owner 校验）：从插件入口提取的公共核心，
// 供 RegisterGlobalCaptureImpl 复用。ownerId 空串 = Loader 归属（GameCore 重载时随
// CleanupAllCaptureSites 清理 GameCore 域站点；插件卸载清理按 owner 匹配，跳过空串）。
// providerAddress 是插件给的【绝对地址】，必须是可执行的函数入口：Loader 只探页属性
// （可读 + 落在可执行页），不做任何名字 / 符号 / 映像解析。
static bool RegisterGlobalCaptureCore(void* providerAddress, uint32_t paramIndex, void** out,
                                      const std::wstring& ownerId) {
    if (!providerAddress || !out || paramIndex > 3) {
        Logger::Log("RegisterGlobalCapture rejected: bad args provider=%p param=%u out=%p",
            providerAddress, static_cast<unsigned>(paramIndex), static_cast<void*>(out));
        return false;
    }
    // 页属性探测放在取生命周期锁【之前】（PluginBoundary 不变量）；探测本身是纯
    // VirtualQuery，不会产生访问违例。
    if (!PluginBoundary::IsReadable(providerAddress, PluginBoundary::kMinHookTargetSpan)) {
        Logger::Log("RegisterGlobalCapture rejected: provider not readable %p (span=%zu)",
            providerAddress, PluginBoundary::kMinHookTargetSpan);
        return false;
    }
    if (!IsExecutableTargetSpan(providerAddress, PluginBoundary::kMinHookTargetSpan)) {
        Logger::Log("RegisterGlobalCapture rejected: provider not in an executable page %p (span=%zu)",
            providerAddress, PluginBoundary::kMinHookTargetSpan);
        return false;
    }

    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (TargetInTearingDownGameCore(providerAddress)) {
        Logger::Log("RegisterGlobalCapture: target belongs to tearing-down GameCore provider=%p",
            providerAddress);
        return false;
    }

    // 锁序 lifecycle -> MinHook -> capture：先在站点锁下取/建站点（只有首次建站才挂
    // MinHook），再进 capture 锁登记订阅。同一 target 上的 Detour / 既有 Capture 都被复用。
    HookSite* site = nullptr;
    {
        lock_guard<std::mutex> hookLock(Runtime::MinHookMutex());
        site = GetOrCreateHookSiteLocked(providerAddress, "RegisterGlobalCapture");
    }
    if (!site) {
        Logger::Log("RegisterGlobalCapture: hook site unavailable provider=%p", providerAddress);
        return false;
    }

    size_t slotCount = 0;
    {
        lock_guard<std::mutex> captureLock(g_captureMutex);
        if (site->hasCapture && site->captureParamIndex != paramIndex) {
            Logger::Log("RegisterGlobalCapture: paramIndex conflict provider=%p have=%u want=%u",
                providerAddress, static_cast<unsigned>(site->captureParamIndex),
                static_cast<unsigned>(paramIndex));
            return false;
        }
        // 先追加 out 槽再置 hasCapture：stub 裸读到 hasCapture=1 时 outs 必已可见。
        site->captureParamIndex = paramIndex;
        site->captureOuts.push_back({ out, ownerId });
        site->retiring = false;
        site->hasCapture = true;
        slotCount = site->captureOuts.size();
    }
    Logger::Log("RegisterGlobalCapture: installed provider=%p param=%u owner=%ls "
                "(hub stub=%p outs=%zu)",
        providerAddress, static_cast<unsigned>(paramIndex), ownerId.c_str(),
        site->stubCode, slotCount);
    return true;
}

// 插件入口：owner 校验后走核心（out 槽须位于插件模块内）。
bool RegisterGlobalCaptureImpl(void* providerAddress, uint32_t paramIndex, void** out) {
    // out 是宿主【写】的目标（CaptureDispatch 会往它写），是插件内存 —— 处理放在取锁之前。
    // providerAddress 只探页属性（VirtualQuery，不解引用）。CaptureDispatch 侧另有叶子
    // SEH 兜底（防插件注册后自行释放该地址 / 改页保护）。
    if (!PluginBoundary::IsWritable(out, sizeof(void*))) {
        Logger::Log("RegisterGlobalCapture rejected: out slot not writable %p",
            static_cast<const void*>(out));
        return false;
    }

    // owner 查询与注册必须在同一生命周期锁内，防止查询后插件先被停用并完成清理。
    // 注意：owner 探针必须用插件自己的 out 指针（RequirePluginOwner 只做模块归属
    // 查询，不解引用），不能用 Loader 副本，否则会被判成 Loader 自身。
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(out), "RegisterGlobalCapture");
    if (!owner) return false;
    // 地址开放性门：capture 现在是"取地址型"入口（providerAddress 由插件自己解析后传入），
    // 因此统一按地址开放性口径判：GameCore 类别 -> 目标须在当前 GameCore 映像内；Global
    // 类别 -> 不得落在 GameCore 映像内（exe / 常驻模块放行）。原先"调用方类别必须是
    // GameCore"那道特例门随之删除：它要防的悬垂已由本门 + CleanupAllCaptureSites 的
    // GameCore 域过滤共同覆盖，而 Global 插件挂在常驻模块上的 capture 不再被误拒。
    if (!IsTargetOpenToCaller(owner->category, providerAddress, "RegisterGlobalCapture")) return false;
    return RegisterGlobalCaptureCore(providerAddress, paramIndex, out, owner->ownerId);
}

// 读 [vtable + index*8] 的槽函数指针。本函数无 C++ 对象（无展开要求），可用 SEH 兜底。
static void* ReadVTableSlotSafe(void* vtable, uint32_t index) {
    void* slotFunc = nullptr;
    __try {
        slotFunc = *reinterpret_cast<void**>(
            reinterpret_cast<uintptr_t>(vtable) + static_cast<uintptr_t>(index) * 8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    return slotFunc;
}

// ---------------- ResolveByVTable（按 vtable 符号 + 槽序号解析虚函数） ----------------
// 内部核心：vtableSymbol 由调用方保证可读。
static void* ResolveByVTableCore(HookImageId image, const char* vtableSymbol, uint32_t index) {
    uint32_t vtableRva = 0;
    uint32_t slotCount = 0;
    if (!PdataMatch::CorrectVTableByName(image, vtableSymbol, vtableRva, slotCount)) {
        Logger::Log("ResolveByVTable: no vtable for symbol=%s (not found / not vtable / not corrected)",
            vtableSymbol);
        return nullptr;
    }
    if (index >= slotCount) {
        Logger::Log("ResolveByVTable: index %u out of range for vtable=%s (slotCount=%u)",
            static_cast<unsigned>(index), vtableSymbol, static_cast<unsigned>(slotCount));
        return nullptr;
    }
    void* vtable = ImageAddress::ResolveByRva(image, vtableRva, 1);
    if (!vtable) {
        Logger::Log("ResolveByVTable: vtable address resolve failed symbol=%s rva=0x%X",
            vtableSymbol, static_cast<unsigned>(vtableRva));
        return nullptr;
    }
    // 读 [vtable + index*8] 的槽函数指针（SEH 兜底防坏地址）
    void* slotFunc = ReadVTableSlotSafe(vtable, index);
    if (!slotFunc) {
        Logger::Log("ResolveByVTable: slot read fault vtable=%s index=%u",
            vtableSymbol, static_cast<unsigned>(index));
    }
    return slotFunc;
}

void* ResolveByVTableImpl(HookImageId image, const char* vtableSymbolIn, uint32_t index) {
    // 地址开放性门（RequirePluginOwner 只做模块归属查询，不解引用插件指针）。
    auto caller = RequirePluginOwner(_ReturnAddress(), "ResolveByVTable");
    if (!caller || !IsImageOpenToCaller(caller->category, image, "ResolveByVTable")) return nullptr;
    if (!vtableSymbolIn || !*vtableSymbolIn) {
        Logger::Log("ResolveByVTable rejected: empty vtable symbol");
        return nullptr;
    }
    // vtableSymbol 是插件内存：锁外抄写（锁内会被 PdataMatch 查表与日志反复读取）。
    std::string symbolCopy;
    if (!PluginBoundary::CopyCString(vtableSymbolIn, symbolCopy) || symbolCopy.empty()) {
        Logger::Log("ResolveByVTable rejected: symbol pointer unreadable");
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    return ResolveByVTableCore(image, symbolCopy.c_str(), index);
}

// 只给 Loader 内部使用的"无锁取址表"：解析类入口指向不加插件锁的 Core，其余字段保持
// nullptr —— 这张表【绝不交给插件】。这样 common/HookAPI.h 里的 inline 取址工具
// （HookCurrentExeImage / ResolveByHookInfo / ResolveDataByAob / HookScanPatternNth /
//  HookFindSection）可以直接复用，既不经过插件表、也不加插件生命周期锁。
// 这些 inline 工具实际只用到下面这五个入口。
// 契约：只读。返回非 const 指针只是为了配合 header 里 HookAPI* 的签名。
static HookAPI* InternalToolApi() {
    static const HookAPI api = [] {
        HookAPI t{};
        t.apiVersion = CIV6_HOOK_API_VERSION;
        t.structSize = static_cast<uint32_t>(sizeof(HookAPI));
        t.GetImageInfo = &ImageAddress::GetInfo;
        t.ResolveByRva = &ResolveByRvaCore;
        t.ResolveByName = &ResolveByNameCore;
        t.ResolveByPattern = &ResolveByPatternCore;
        t.ResolveByVTable = &ResolveByVTableCore;
        return t;
    }();
    return const_cast<HookAPI*>(&api);
}

// 当前进程 exe 的映像 id：与 common/HookAPI.h 的 HookCurrentExeImage 同语义
// （GetImageInfo 是否有效），但直连 ImageAddress，不经过插件表/插件锁。
HookImageId LoaderCore::CurrentExeImage() {
    if (ImageAddress::IsLoaded(kHookImageExeDx11)) return kHookImageExeDx11;
    if (ImageAddress::IsLoaded(kHookImageExeDx12)) return kHookImageExeDx12;
    return kHookImageInvalid;
}

// Loader 内部解 exe 全局数据槽：算法与 common/HookAPI.h 的 ResolveDataByAob 完全相同，
// 只是走无锁内部表。供 LoaderHooks / UiInject 使用。
void* LoaderCore::ResolveDataByAobCore(HookImageId image, const char* aob, uint32_t index) {
    return ResolveDataByAob(InternalToolApi(), image, aob, index);
}

// ---------------- 站点捕获槽退役（只拔插槽，绝不物理脱钩） ----------------
// 两个失效场景：
//  1) GameCore 重载：目标位于旧 GameCore 映像内，重载后地址失效，清空落在当前 GameCore
//     映像内的捕获订阅（ResetForReload 调用 CleanupAllCaptureSites），等插件下次 OnLoad
//     自行重新注册；exe / 常驻模块域上的订阅与重载无关，保留；
//  2) 插件卸载：捕获槽的 out 指向插件内存，卸载后悬空（UnloadPluginByOwnerId 调用
//     CleanupCaptureSitesForOwner）。
// 硬约束：这里【只】清空 captureOuts / 翻转 hasCapture，绝不 MH_RemoveHook、绝不
// g_captureRuntime.release、绝不 g_hookSites.erase。站点 / stub / MinHook trampoline
// 全程存活，只在进程退出时随静态对象回收。本段只取 g_captureMutex（capture 侧），
// 不取 MinHook 锁，因此不会与「MinHook -> capture」的注册路径成环。
// CaptureDispatch 在同一把 g_captureMutex 下复查 hasCapture/retiring/空 outs：陈旧读到
// hasCapture=1 时因 outs 已清空而被兜住。

// 只清 GameCore 域：GameCore 映像随对局重载而换地址，它的站点订阅必须随代际重注册；
// exe / 其它常驻模块域上的站点（例如 Global 插件挂在 user32 上的 capture）永不失效，
// 必须保留 —— 这也正是原先「只允许 GameCore 插件注册 capture」那道特例门删除之后，
// Global 插件的常驻域订阅赖以存活的地方。
// ResetForReload 调用本函数时旧 GameCore 映像仍 attached（detach 更晚），因此
// ImageAddress::Contains(LoadedGameCore(), siteTarget) 的判定成立；GameCore 未加载
// （无效 id）时 Contains 恒 false，等于"无 GameCore 域可清"。
static void CleanupAllCaptureSites() {
    size_t sites = 0;
    size_t outs = 0;
    size_t kept = 0;
    {
        // 站点表结构由 MinHook 站点锁保护；capture 字段是它内层的派发侧数据。
        // 锁序恒为 MinHook -> capture，与注册路径一致，不成环。
        lock_guard<mutex> hookLock(Runtime::MinHookMutex());
        lock_guard<mutex> lock(g_captureMutex);
        const HookImageId gcImage = ImageAddress::LoadedGameCore();
        for (auto& entry : g_hookSites) {
            HookSite& site = entry.second;
            if (!site.hasCapture && site.captureOuts.empty()) continue;
            if (!ImageAddress::Contains(gcImage, entry.first)) {
                ++kept;   // 非当前 GameCore 域（exe / 常驻模块）：捕获订阅保留
                continue;
            }
            site.retiring = true;
            site.hasCapture = false;
            outs += site.captureOuts.size();
            site.captureOuts.clear();
            ++sites;
        }
    }
    Logger::Log("CleanupAllCaptureSites: unplugged capture on %zu site(s) / %zu out slot(s) "
                "inside the GameCore image (kept %zu site(s) outside by domain; no physical unhook)",
        sites, outs, kept);
}

// 插件卸载：只移除该 owner 的 out 槽；还有其它 owner 订阅时保留站点与 hasCapture。
static void CleanupCaptureSitesForOwner(const std::wstring& owner) {
    if (owner.empty()) return;
    size_t removed = 0;
    size_t emptied = 0;
    {
        // 同 CleanupAllCaptureSites：先站点锁再 capture 锁（MinHook -> capture）。
        lock_guard<mutex> hookLock(Runtime::MinHookMutex());
        lock_guard<mutex> lock(g_captureMutex);
        for (auto& entry : g_hookSites) {
            HookSite& site = entry.second;
            if (site.captureOuts.empty()) continue;
            const size_t oldSize = site.captureOuts.size();
            site.captureOuts.erase(std::remove_if(site.captureOuts.begin(), site.captureOuts.end(),
                [&owner](const HookSite::CaptureOut& out) {
                    return out.ownerId == owner;
                }), site.captureOuts.end());
            removed += oldSize - site.captureOuts.size();
            if (site.captureOuts.empty() && site.hasCapture) {
                site.retiring = true;
                site.hasCapture = false;
                ++emptied;
            }
        }
    }
    Logger::Log("CleanupCaptureSitesForOwner: owner=%ls removed=%zu out(s) emptied=%zu site(s) "
                "(no physical unhook)", owner.c_str(), removed, emptied);
}

// ================= GameEvents 桥接（RegisterGameEvent / TriggerGameEvent） =================
// GameEvents = 纯登记 + 插件端手动触发（不再挂游戏信号环，无每回合自动广播）：
//  - 登记：RegisterGameEvent(name, pushFn)——只在注册表记下名字与 Lua 参数打包回调（owner 生命周期保留）。
//  - 触发：TriggerGameEvent(name, payload)——插件主动触发 → GameEventInvokeLua → 内化到 Lua。
//  - 播放：内化路径（活跃 state 实时取 + 锁协议 + GameEvents[name].Call + 栈清理），
//        引擎桥旧路径（args 容器 + CallHook 桥）已删除，统一到 Lua 路径。

namespace {

// ---- GameEvent 引擎 ABI 常量 ----
// exe: ScriptSystem::CallHook 内的单例读取序列（mov rax,cs:singleton; mov rcx,[rax+10h]; jmp）
// ——AOB 自锚定，避免硬编码 RVA 的版本脆性。
constexpr const char* kLuaSingletonPattern =
    "48 8B 05 ?? ?? ?? ?? 48 8B 48 10 E9";
void* g_activeLuaStateHit = nullptr;   // AOB 命中缓存（Contains 校验，跨代自动重扫）
constexpr size_t   kGameEventNameMax           = 96;    // 事件名副本容量（注册表）

// ms_pkCurrentGame 定位 pattern（GameSignals::Subscribe 开头 mov rdi, cs:ms_pkCurrentGame
// 序列；读命中+3 的 disp32，目标槽 = 命中+7+disp32）。GetCurrentGameSlot 用它解析
// ms_pkCurrentGame 槽（GetEngineUtilityImpl 读 +0x18 取 EngineUtility）。
constexpr char kGameEventCurrentGamePattern[] =
    "48 8B 3D ?? ?? ?? ?? 48 85 FF 0F 84 ?? ?? ?? ?? 48 8B BF 80 02 00 00";
// GameSignals::Subscribe 内 "mov rdi, cs:ms_pkCurrentGame" 指令地址（按代缓存，重扫兜底）。
static void* g_gameEventContainerHit = nullptr;

constexpr int kMaxRegisteredGameEvents = 32;

// 每个注册的 GameEvent 一条记录：名字 + owner + Lua 参数打包回调。槽位判空用 name[0]。
struct RegisteredGameEvent {
    GameEventPushFn luaPushFn = nullptr;        // Lua 路径：压参数并返回个数
    std::wstring ownerId;                 // 注册者插件 owner（卸载/隔离按 owner 清理）
    char name[kGameEventNameMax] = {};    // 名字副本（对象末尾，长期存活；name[0]==0 即空槽）
    // 登记时解析一次并常驻：触发路径的守卫不再做宽字符串哈希。
    PluginInFlight::Owner* inFlight = nullptr;
};
static RegisteredGameEvent g_gameEvents[kMaxRegisteredGameEvents];

// ---- SEH 保护的内存读取 / 调用（无 C++ 对象，允许 __try） ----
static void* GameEventReadPtrSafe(const void* base, size_t offset) {
    void* value = nullptr;
    __try {
        value = *reinterpret_cast<void* const*>(static_cast<const char*>(base) + offset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    return value;
}

static int32_t GameEventReadInt32Safe(const void* addr) {
    int32_t value = 0;
    __try {
        value = *reinterpret_cast<const int32_t*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return value;
}

// ms_pkCurrentGame 的 .data 槽地址（命中地址按代缓存，重载后 Contains 失效自动重扫）。
static void* GetCurrentGameSlot() {
    if (!g_gameEventContainerHit ||
            !ImageAddress::Contains(kHookImageGameCoreXP2, g_gameEventContainerHit)) {
        g_gameEventContainerHit = ResolveByPatternCore(kHookImageGameCoreXP2,
            kGameEventCurrentGamePattern, kSectionText);
        if (!g_gameEventContainerHit) return nullptr;
    }
    const int32_t disp = GameEventReadInt32Safe(
        static_cast<const char*>(g_gameEventContainerHit) + 3);
    if (disp == 0) return nullptr;
    return static_cast<char*>(g_gameEventContainerHit) + 7 + disp;
}

// GameCore::EngineUtility 全局（ms_pkCurrentGame 槽 +0x18，与 scriptSystem +0x20 同族）。
// 锁协议（官方 Utility::CallHook 同款）。内部无门版本：Loader 自己的 Lua 锁协议路径
// （GameEventInvokeLuaImpl）必须能取到它 —— 那里 _ReturnAddress() 会落在 Loader 模块，
// 若走带门的 GetEngineUtilityImpl 会被 GameCore 门拒绝而误伤 TriggerGameEvent。
static void* GetEngineUtilityCore() {
    void* currentGameSlot = GetCurrentGameSlot();
    if (!currentGameSlot) return nullptr;
    return GameEventReadPtrSafe(static_cast<const char*>(currentGameSlot) + 0x18, 0);
}

// 插件可见入口：只对 GameCore 类别插件开放（调用方由返回地址反查）。
#pragma intrinsic(_ReturnAddress)
void* GetEngineUtilityImpl() {
    if (!RequireGameCoreOwner(_ReturnAddress(), "GetEngineUtility")) return nullptr;
    return GetEngineUtilityCore();
}

// 当前活跃游戏 Lua 状态——官方 GameCore::ScriptSystem::CallHook 同款（IDA 实证）：
//   mov rax, cs:?ms_apSingletonInstance@LuaScriptSystem@LuaSystem@@2PEAV12@EA   ; exe RVA 0x2D08F88
//   mov rcx, [rax+10h]                                                          ; 活跃 lua_State
// 每次实时读（引擎在对局/脚本切换时更新 +0x10），不缓存。
void* GetActiveLuaStateImpl() {
    // 定位 exe 的 ScriptSystem::CallHook 内的全局读取序列（IDA 实证）：
    //   48 8B 05 ?? ?? ?? ??   mov rax, cs:ms_apSingletonInstance
    //   48 8B 48 10            mov rcx, [rax+10h]      ← 活跃 lua_State
    //   E9 ?? ?? ?? ??         jmp GameEventLibrary::CallHook
    // AOB 自锚定（不依赖硬编码 RVA，游戏版本更新时该序列由编译器稳定生成）；
    // 命中地址按镜像缓存（Contains 校验，跨代/重载自动重扫）。
    static const HookImageId kCandidates[] = { kHookImageExeDx11, kHookImageExeDx12 };
    for (HookImageId image : kCandidates) {
        if (!ImageAddress::IsLoaded(image)) continue;
        // 缓存命中（地址仍属该镜像）直接用
        void* slot = nullptr;
        if (g_activeLuaStateHit && ImageAddress::Contains(image, g_activeLuaStateHit)) {
            const int32_t disp = GameEventReadInt32Safe(
                static_cast<const char*>(g_activeLuaStateHit) + 3);
            if (disp != 0) {
                slot = static_cast<char*>(g_activeLuaStateHit) + 7 + disp;
            }
        }
        if (!slot) {
            void* hit = ResolveByPatternCore(image, kLuaSingletonPattern, kSectionText);
            if (hit) {
                g_activeLuaStateHit = hit;
                const int32_t disp = GameEventReadInt32Safe(static_cast<const char*>(hit) + 3);
                if (disp != 0) slot = static_cast<char*>(hit) + 7 + disp;
            }
        }
        if (!slot) continue;
        void* singleton = GameEventReadPtrSafe(slot, 0);
        if (!singleton) continue;
        void* L = GameEventReadPtrSafe(static_cast<const char*>(singleton) + 0x10, 0);
        // 每个进程只打一次命中 RVA（预期 slot RVA=0x2D08F88）：确认 AOB 锚点落对位置，
        // 是"活跃 state 取不到"这类现场问题的第一手证据。
        static bool s_logged = false;
        if (!s_logged && L) {
            s_logged = true;
            HookImageInfo info{ sizeof(HookImageInfo) };
            if (ImageAddress::GetInfo(image, &info) && info.base) {
                Logger::Log("GetActiveLuaState: image=%u hitRva=0x%llX slotRva=0x%llX L=%p",
                    static_cast<unsigned>(image),
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(g_activeLuaStateHit) - info.base),
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(slot) - info.base), L);
            }
        }
        if (L) return L;
    }
    return nullptr;
}

// 插件卸载/隔离时清理其注册的 GameEvent：清槽位（name[0]='\0' + 字段清空 + ownerId.clear）。
// 调用方持 lifecycle 锁（RemovePluginOwnedRegistrations 内调用），本函数不再加锁。
static void CleanupGameEventsForOwner(const std::wstring& owner) {
    size_t cleaned = 0;
    for (auto& ev : g_gameEvents) {
        if (ev.name[0] == '\0' || ev.ownerId != owner) continue;
        ev.name[0] = '\0';
        ev.ownerId.clear();
        ev.inFlight = nullptr;
        ++cleaned;
    }
    if (cleaned == 0) return;
    Logger::Log("CleanupGameEventsForOwner: owner=%ls cleaned=%zu event(s)",
        owner.c_str(), cleaned);
}

}  // namespace

// Lua 表路径触发（内化）：官方 CallHook 同款机制全收进 runtime——
//   活跃 state 实时取 → 锁协议三步 → GameEvents[name].Call(table) → 栈清理。
// 插件 pushFn 只负责往栈顶空表塞字段（字符串键/嵌套/数组）。
// 栈清理兜底：独立 noinline SEH（/EHsc 下 __try 函数内不能带析构的 C++ 对象）。
// 关键：在 Lua 序列的 __try **之外**调用——即使插件 pushFn 崩溃，栈也能恢复到基线，
// 避免反复失败累积栈残留（远程引擎桥用 argsCreated 标志做等价兜底）。
static __declspec(noinline) void GameEventPopToBaseSeh(void* L, int base) {
    __try {
        auto* s = reinterpret_cast<hks::lua_State*>(L);
        const int top = hks::gettop(s);
        if (top > base) hks::pop(s, top - base);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// 插件参数回调的独立 SEH：让日志能分辨"插件回调崩"与"引擎/Lua 崩"（对齐远程粒度）。
static __declspec(noinline) bool GameEventPushArgsSeh(GameEventPushFn pushFn, void* L,
                                                      const void* payload, int* outNargs) {
    __try {
        *outNargs = pushFn(L, payload);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Lua 序列段（含插件回调）：只做 Lua 操作，栈清理交给调用者（保证崩溃路径也执行）。
// 只做 Lua 操作；栈清理由调用方（GameEventPopToBaseSeh）负责，所以这里不收 base。
static bool GameEventInvokeLuaSeh(const char* name, GameEventPushFn pushFn,
                                  const void* payload, void* L) {
    bool ok = false;
    __try {
        auto* s = reinterpret_cast<hks::lua_State*>(L);
        hks::getfield(s, hks::LUA_GLOBAL, "GameEvents");
        hks::getfield(s, -1, name);
        hks::getfield(s, -1, "Call");
        int nargs = 0;
        if (pushFn && !GameEventPushArgsSeh(pushFn, L, payload, &nargs)) {
            Logger::Log("GameEvent: InvokeLua pushFn failed name=%s", name);
            ok = false;   // 参数不完整，不继续调用
        } else {
            const int argc = (nargs < 0) ? 0 : nargs;
            ok = hks::pcall(s, argc, 0, 0) == 0; // Call(arg1, arg2, ...)
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("GameEvent: InvokeLua exception name=%s", name);
        ok = false;
    }
    return ok;
}

// EngineUtility 全局解析失败的限次告警：此时"GameCore 锁状态未知"，TriggerGameEvent
// 会直接拒绝执行——必须可诊断，但脚本可能高频触发，不能刷屏。
static void WarnEngineUtilityUnavailable(const char* name) {
    static std::atomic<int> s_warned{ 0 };
    const int seen = s_warned.fetch_add(1, std::memory_order_relaxed);
    if (seen < 10) {
        Logger::Log("GameEvent: TriggerGameEvent(\"%s\") refused: EngineUtility unavailable "
                    "(GameCore lock state unknown; AOB pattern mismatch or GameCore not ready)", name);
    } else if (seen == 10) {
        Logger::Log("GameEvent: EngineUtility still unavailable; further refusals are not logged");
    }
}

// 内层主体：Lua/插件段全部走 SEH 兜底；本函数【不声明 noexcept】。
// 原因（已用 MSVC 实测确认）：noexcept 函数里逃出的 C++ 异常会直接 std::terminate，
// 外层 GameEventInvokeLua 的 try/catch 永远看不到 —— 等于死代码。真实的 C++ 异常源是
// 插件回调 throw 与标准库分配失败；交给外层 catch 隔离，比带崩整个进程好。
static bool GameEventInvokeLuaImpl(const char* name, GameEventPushFn pushFn,
                                   const void* payload) {
    if (!name || !*name) return false;
    void* L = GetActiveLuaStateImpl();
    if (!L) {
        Logger::Log("GameEvent: InvokeLua no-active-state name=%s", name);
        return false;
    }
    if (!hks::getfield || !hks::setfield || !hks::createtable || !hks::pcall ||
        !hks::gettop || !hks::pop) {
        Logger::Log("GameEvent: InvokeLua hks-imports-missing name=%s", name);
        return false;
    }

    // 记录栈基线（清理兜底用）
    int base = 0;
    __try {
        base = hks::gettop(reinterpret_cast<hks::lua_State*>(L));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("GameEvent: InvokeLua gettop failed name=%s", name);
        return false;
    }

    // 锁协议（官方 Utility::CallHook 同款）：持锁则先释放，Lua 工作完成后恢复。
    // EngineUtility 解析失败 / 取放锁调用异常 = GameCore 锁状态未知：此时不进入 Lua
    //（带锁重入 Lua 可能自死锁或破坏 Lua 状态），本次触发直接拒绝并限次告警。
    void* eu = GetEngineUtilityCore();
    void** engineVtable = nullptr;   // 供 __finally 里取回锁使用（必须是 POD 局部）
    bool had = false;                // HasGameCoreLock 返回 true
    bool released = false;           // Release【正常返回】——只有这种情况才必须取回
    bool lockFaulted = false;        // 取放锁调用本身异常：锁状态未知
    if (eu) {
        __try {
            engineVtable = *reinterpret_cast<void***>(eu);
            had = reinterpret_cast<bool(__fastcall*)(void*)>(engineVtable[6])(eu); // HasGameCoreLock
            if (had) {
                reinterpret_cast<void(__fastcall*)(void*)>(engineVtable[7])(eu);   // Release
                released = true;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            const DWORD code = GetExceptionCode();
            if (had) {
                // HasGameCoreLock 已返回 true，Release 是否真的生效无法判定。这里不盲目取回
                // （在仍持锁时调 GetGameCoreLock 可能自死锁），但必须醒目留痕。
                Logger::Log("GameEvent: Release faulted code=0x%08X name=%s "
                            "- GameCore lock state UNKNOWN", code, name);
            } else {
                Logger::Log("GameEvent: lock protocol fault code=0x%08X name=%s", code, name);
            }
            lockFaulted = true;
            had = false;
            eu = nullptr;
        }
    }
    if (lockFaulted) {
        // 锁状态未知：不进入 Lua（以"可能仍持锁"的状态重入 Lua 会自死锁或破坏 Lua 状态）。
        return false;
    }
    if (!eu) {
        WarnEngineUtilityUnavailable(name);
        return false;
    }

    // ★ 一旦 released = true，无论以什么方式退出都必须把 GameCore 锁取回：
    //   __finally 在【正常返回 / C++ 异常展开 / 硬件异常展开】三种路径上都会执行。
    //   （/EHsc 下硬件异常不会执行 C++ 析构，但会执行 __finally —— 这正是这里要的语义。）
    //   本函数局部变量全是 POD，因此可以合法使用 __try/__finally（MSVC C2712）。
    bool ok = false;
    __try {
        ok = GameEventInvokeLuaSeh(name, pushFn, payload, L);
        GameEventPopToBaseSeh(L, base);   // 栈清理：崩溃路径同样执行（资源兜底）
    } __finally {
        if (released) {
            __try {
                reinterpret_cast<void(__fastcall*)(void*)>(engineVtable[8])(eu); // GetGameCoreLock
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // 已释放锁但取回失败：后续 Lua/游戏逻辑将在无锁状态下运行，必须留痕。
                Logger::Log("GameEvent: failed to re-acquire GameCore lock code=0x%08X name=%s",
                    GetExceptionCode(), name);
            }
        }
    }
    return ok;
}

// 外层：C++ 异常兜底（插件回调 throw / 标准库异常），与远程 Safe 层同款。
static bool GameEventInvokeLua(const char* name, GameEventPushFn pushFn,
                               const void* payload) noexcept {
    try {
        return GameEventInvokeLuaImpl(name, pushFn, payload);
    } catch (...) {
        Logger::Log("GameEvent: InvokeLua cxx-exception name=%s", name);
        return false;
    }
}

// 手动触发一次：查找注册记录，仅 Lua 路径（内化）。未注册或 luaPushFn 为 null → false。
// 查到记录后先取 owner 在途守卫（PluginInFlight::Enter）——插件卸载/隔离期间拒绝触发，
// 避免在途调用踩到已回滚的注册（与远程对引擎桥路径的加固同款）。
#pragma intrinsic(_ReturnAddress)

// 调用方归属校验（尽力而为）：
//   - 正常情况：插件经函数指针表调用本函数，_ReturnAddress() 落在该插件自己的模块里，
//     可精确判定；事件名若属于另一个插件则拒绝（挡住"抢注名字 + 用自己的 payload 触发
//     别人的 pushFn"这条跨插件路径）。
//   - 判定不出（尾调用 / 经第三方 wrapper 转发 / 调用方不是被跟踪插件）：只放行，保持旧行为。
//     与 Patch 用 _ReturnAddress() 的 caveat 相同 —— 所以这里必须 fail-open，不能 fail-closed。
__declspec(noinline)
bool TriggerGameEventImpl(const char* name, const void* payload) {
    if (!name || !*name) return false;
    const void* callerAddress = _ReturnAddress();
    if (!RequireGameCoreOwner(callerAddress, "TriggerGameEvent")) return false;

    // name 是插件内存：锁外抄写。原实现在锁内做 strcmp(ev.name, name)，一个悬垂的
    // 事件名指针就会在持锁状态下访存失败 -> lock_guard 不析构 -> 锁永久泄漏。
    std::string nameCopy;
    if (!PluginBoundary::CopyCString(name, nameCopy) || nameCopy.empty()) {
        Logger::Log("TriggerGameEvent rejected: name pointer unreadable");
        return false;
    }

    GameEventPushFn luaPushFn = nullptr;
    std::wstring owner;
    PluginInFlight::Owner* inFlight = nullptr;
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        PluginBoundary::LoaderLockScope pbLockScope;
        for (const auto& ev : g_gameEvents) {
            if (ev.name[0] && nameCopy == ev.name) {
                luaPushFn = ev.luaPushFn;
                owner = ev.ownerId;
                inFlight = ev.inFlight;
                break;
            }
        }
    }
    if (!luaPushFn) {
        Logger::Log("TriggerGameEvent: \"%s\" not registered (or non-Lua path)",
            nameCopy.c_str());
        return false;
    }
    // 事件名只归注册它的那个 owner；调用方（若能判定）必须是同一个 owner。
    if (const auto callerOwner = ResolvePluginOwnerForAddress(callerAddress)) {
        if (callerOwner->ownerId != owner) {
            Logger::Log("TriggerGameEvent rejected: \"%s\" is owned by %ls, triggered by %ls",
                nameCopy.c_str(), owner.c_str(), callerOwner->ownerId.c_str());
            return false;
        }
    }
    // 缓存指针为空（老数据 / 异常路径）时退化为按 owner 字符串解析一次。
    if (!inFlight) inFlight = PluginInFlight::Resolve(owner);
    auto callbackGuard = PluginInFlight::Enter(inFlight, PluginInFlight::Kind::GameEvent);
    if (!callbackGuard) {
        Logger::Log("TriggerGameEvent: rejected for inactive owner=%ls name=%s",
            owner.c_str(), nameCopy.c_str());
        return false;
    }
    return GameEventInvokeLua(nameCopy.c_str(), luaPushFn, payload);
}

// 注册 Lua 路径事件：owner/幂等/空槽登记（触发时走 GameEventInvokeLua 内化路径）。
bool RegisterGameEventImpl(const char* name, GameEventPushFn pushFn) {
    if (!name || !*name) return false;

    // name 是插件内存：锁外做有界抄写。原实现用裸 strlen 读它，而且下面还有锁内
    // 的 strcmp / memcpy —— 一个没有结尾符的指针会一路读到出错为止。
    std::string nameCopy;
    if (!PluginBoundary::CopyCString(name, nameCopy) || nameCopy.empty()) {
        Logger::Log("RegisterGameEvent rejected: name pointer unreadable");
        return false;
    }
    const size_t nameLength = nameCopy.size();
    if (nameLength >= kGameEventNameMax) {
        Logger::Log("RegisterGameEvent: name too long (%zu bytes, max %zu)",
            nameLength, kGameEventNameMax - 1);
        return false;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;

    // owner 探针：优先插件提供的 pushFn 地址；为空时退回插件的 name 指针。
    // 两者都只做模块归属查询（RequirePluginOwner 不解引用）。
    const void* ownerProbe = reinterpret_cast<const void*>(pushFn);
    if (!ownerProbe) ownerProbe = name;
    auto owner = RequirePluginOwner(ownerProbe, "RegisterGameEvent");
    if (!owner) {
        Logger::Log("RegisterGameEvent: no plugin owner");
        return false;
    }
    if (!RequireGameCoreOwner(ownerProbe, "RegisterGameEvent")) return false;
    // 键 = (owner, name)。同一插件重复注册幂等；**不同插件抢同名必须拒绝**。
    // 原实现不比较 owner 就 return true：调用方以为注册成功，实际它的 pushFn 被丢弃，
    // 之后它触发该名字时拿到的是【别人】的 pushFn，payload 布局不一致 -> 越界/类型混淆。
    for (const auto& ev : g_gameEvents) {
        if (!ev.name[0] || nameCopy != ev.name) continue;
        if (ev.ownerId == owner->ownerId) return true;       // 同 owner 重复注册：幂等
        Logger::Log("RegisterGameEvent rejected: name \"%s\" already owned by another plugin "
                    "(requested by %ls)", nameCopy.c_str(), owner->ownerId.c_str());
        return false;
    }
    RegisteredGameEvent* slot = nullptr;
    for (auto& ev : g_gameEvents) {
        if (!ev.name[0]) { slot = &ev; break; }
    }
    if (!slot) {
        Logger::Log("RegisterGameEvent: no free slot (max %d)", kMaxRegisteredGameEvents);
        return false;
    }
    slot->luaPushFn = pushFn;
    slot->ownerId = owner->ownerId;
    slot->inFlight = PluginInFlight::Resolve(owner->ownerId);
    memcpy(slot->name, nameCopy.c_str(), nameLength);
    slot->name[nameLength] = '\0';
    Logger::Log("GameEvent: registered Lua-event \"%s\" pushFn=%p", nameCopy.c_str(), pushFn);
    return true;
}

void* ResolveCurrentGameCoreByName(const char* name) {
    const HookImageId image = ImageAddress::LoadedGameCore();
    if (image == kHookImageInvalid) return nullptr;
    return ResolveByNameCore(image, name);
}

using PushMethodsNoFunc = void(__fastcall*)(hks::lua_State* L, int stackOffset);
using PushMethodsWithFunc = void(__fastcall*)(void*, hks::lua_State* L, int stackOffset);

static bool SameLuaMethod(const StoredLuaMethod& a, const StoredLuaMethod& b) {
    return a.owner == b.owner && a.luaMethodFunc == b.luaMethodFunc &&
        a.internalName == b.internalName && a.exposedName == b.exposedName;
}

// 对候选副本合并；调用方成功后才 swap 到正式表，冲突不会留下半批方法。
static bool MergeLuaMethod(vector<StoredLuaMethod>& candidate, const StoredLuaMethod& method) {
    if (!method.luaMethodFunc || method.internalName.empty() ||
            method.exposedName.empty() || method.owner.empty()) return false;
    const auto existing = std::find_if(candidate.begin(), candidate.end(),
        [&method](const StoredLuaMethod& item) {
            return item.exposedName == method.exposedName;
        });
    if (existing != candidate.end()) return SameLuaMethod(*existing, method);
    candidate.push_back(method);
    return true;
}

static bool MergeLuaMethods(vector<StoredLuaMethod>& candidate,
                             const vector<StoredLuaMethod>& methods) {
    for (const auto& method : methods) {
        if (!MergeLuaMethod(candidate, method)) return false;
    }
    return true;
}

HookApiPushMethodsResult PushLuaMethodsImpl(
        const char* name, const LuaMethodInfo* methods, uint32_t count) {
    if (!name || !*name || !methods || count == 0) return kHookApiPushMethodsFailed;
    if (count > PluginBoundary::kMaxLuaMethodsPerCall) {
        Logger::Log("PushLuaMethods rejected: count=%u over limit", count);
        return kHookApiPushMethodsFailed;
    }

    // ===== 阶段 1：不持任何 Loader 锁，先把插件内存抄进 Loader 自有存储 =====
    // name、methods 数组、每个 LuaMethodInfo 本身、以及它指向的两个字符串，全都是
    // 插件内存。任何一处是坏地址都在这里失败 —— 此刻没有锁被持有，失败是干净的。
    std::string targetName;
    if (!PluginBoundary::CopyCString(name, targetName) || targetName.empty()) {
        Logger::Log("PushLuaMethods rejected: name pointer unreadable");
        return kHookApiPushMethodsFailed;
    }
    std::vector<StoredLuaMethod> copies;
    copies.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        LuaMethodInfo raw{};                       // POD：结构体本身也是插件内存
        if (!PluginBoundary::CopyPod(&methods[i], raw)) {
            Logger::Log("PushLuaMethods rejected: LuaMethodInfo[%u] unreadable", i);
            return kHookApiPushMethodsFailed;
        }
        StoredLuaMethod method;
        method.luaMethodFunc = raw.luaMethodFunc;
        if (!PluginBoundary::CopyCString(raw.internalName, method.internalName) ||
            !PluginBoundary::CopyCString(raw.exposedName, method.exposedName)) {
            Logger::Log("PushLuaMethods rejected: method names[%u] unreadable", i);
            return kHookApiPushMethodsFailed;
        }
        copies.push_back(std::move(method));
    }

    // ===== 阶段 2：持锁，此后只碰 copies / targetName（Loader 自有） =====
    // owner 校验、候选合并和安装提交共用生命周期锁，停用不能插入中间。
    // owner 探针用插件提供的函数地址（值拷贝；RequirePluginOwner 只做模块归属查询，
    // 不解引用该地址）。
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    auto owner = RequirePluginOwner(
        reinterpret_cast<const void*>(copies[0].luaMethodFunc), "PushLuaMethods");
    if (!owner) return kHookApiPushMethodsFailed;
    if (!RequireGameCoreOwner(
            reinterpret_cast<const void*>(copies[0].luaMethodFunc), "PushLuaMethods")) {
        return kHookApiPushMethodsFailed;
    }
    const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&owner](const PluginEntry& entry) {
            return entry.ownerId == owner->ownerId &&
                (entry.state == PluginState::Loading || entry.state == PluginState::Active);
        });
    if (plugin == g_plugins.end()) return kHookApiPushMethodsFailed;

    // owner 回填：StoredLuaMethod::owner 为空会被 MergeLuaMethod 首行直接判非法，
    // 必须在合并之前补齐（否则整批 PushLuaMethods 都会失败）。
    for (auto& method : copies) method.owner = owner->ownerId;

    PushTargetConfig config;
    const auto ownerConfigs = g_pluginPushTargetConfigs.find(owner->ownerId);
    if (ownerConfigs != g_pluginPushTargetConfigs.end()) {
        const auto configured = ownerConfigs->second.find(targetName);
        if (configured != ownerConfigs->second.end()) config = configured->second;
    }
    if (config.symbolName.empty()) {
        const auto builtIn = g_defaultPushTargetConfigs.find(targetName);
        if (builtIn != g_defaultPushTargetConfigs.end()) config = builtIn->second;
    }
    if (config.symbolName.empty()) {
        Logger::Log("PushLuaMethods: unknown target %s", targetName.c_str());
        return kHookApiPushMethodsFailed;
    }

    // 同一批内的去重/冲突预检：整批验证通过后才安装。安装侧（InstallPushMethods*）会再
    // 与槽位上已有的定义合并一次，跨 owner 抢占同一 exposedName 在那里被整批拒绝。
    vector<StoredLuaMethod> batch;
    for (uint32_t i = 0; i < count; ++i) {
        // 每个方法都必须属于同一个插件（owner 一致）；名字为空由 MergeLuaMethod 判非法。
        auto methodOwner = RequirePluginOwner(
            reinterpret_cast<const void*>(copies[i].luaMethodFunc), "PushLuaMethods");
        if (!methodOwner || methodOwner->ownerId != owner->ownerId ||
                !MergeLuaMethod(batch, copies[i])) {
            Logger::Log("PushLuaMethods rejected: invalid or conflicting method for %s",
                targetName.c_str());
            return kHookApiPushMethodsFailed;
        }
    }

    // 登记只在当次安装内生效：Loader 不再为下一代 GameCore 保存登记表，因此 GameCore
    // 未就绪时无法延迟安装（Deferred 不再产生），直接失败。
    if (!g_gameCorePhaseReady) {
        Logger::Log("PushLuaMethods: GameCore not ready; cannot install %s "
                    "(no deferred registration)", targetName.c_str());
        return kHookApiPushMethodsFailed;
    }
    const std::string& symbolName = config.symbolName;
    void* target = ResolveCurrentGameCoreByName(symbolName.c_str());
    if (!target) {
        Logger::Log("PushLuaMethods: resolve failed: %s", symbolName.c_str());
        return kHookApiPushMethodsFailed;
    }
    void* base = config.signature == PushMethodSigType::NoManager
        ? InstallPushMethodsNoManager(target, batch, owner->ownerId)
        : InstallPushMethodsWithManager(target, batch, owner->ownerId);
    if (!base) {
        Logger::Log("PushLuaMethods: install failed: %s", symbolName.c_str());
        return kHookApiPushMethodsFailed;
    }
    return kHookApiPushMethodsInstalled;
}

namespace {

// 脚本全局注册项：owner = 注册时活跃插件名（空 = Loader 自身，插件卸载不撤销）。
// fn 指向插件映像内代码，插件卸载时必须移除，否则 RegisterScriptData detour
// 会调进已 FreeLibrary 的内存（与 OnMessage 悬空 handler 同类问题）。
struct ScriptGlobalsEntry {
    std::wstring owner;
    ScriptGlobalsFn fn;
    // 登记时解析一次并常驻：运行时守卫不再做宽字符串哈希。
    PluginInFlight::Owner* inFlight = nullptr;
};

std::vector<ScriptGlobalsEntry> g_scriptGlobals;
std::vector<ScriptGlobalsEntry> g_scriptGlobalsUI;
ProxyTypes::RegisterScriptData g_origRegisterScriptData = nullptr;
ProxyTypes::RegisterScriptDataForUI g_origRegisterScriptDataForUI = nullptr;
// 上述两个跳板由统一站点的 MH_CreateHook 回填（尾跳原函数），detour 用它们调原实现；
// 站点在 GameCore teardown 物理摘除（RemoveGameCoreDomainSiteRecords）时随记录一并清空。
// 是否已挂钩不再需要标志：
// 站点表本身就是唯一账本，重复安装幂等。

static void CallScriptGlobalsSafe(ScriptGlobalsFn fn, void* L) {
    if (!fn) return;
    __try {
        fn(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("ScriptGlobals callback crashed code=0x%08X", GetExceptionCode());
    }
}

// 拷贝快照后在锁外回调：注册表可能被 Loader 工作线程（插件卸载清理）并发修改。
static std::vector<ScriptGlobalsEntry> SnapshotScriptGlobals(std::vector<ScriptGlobalsEntry>& reg) {
    lock_guard<mutex> lock(g_scriptStateMutex);
    return reg;
}

void __cdecl Hook_RegisterScriptData(hks::lua_State* L) {
    SharedDetourActivity activity;
    const auto snapshot = SnapshotScriptGlobals(g_scriptGlobals);
    Logger::Log("RegisterScriptData: running %zu plugin global registrar(s)", snapshot.size());
    size_t i = 0;
    for (const auto& entry : snapshot) {
        Logger::Log("RegisterScriptData: registrar[%zu] begin", i);
        PluginInFlight::Owner* owner = entry.inFlight;
        if (!owner) owner = PluginInFlight::Resolve(entry.owner);
        auto callbackGuard =
            PluginInFlight::Enter(owner, PluginInFlight::Kind::ScriptGlobals);
        if (callbackGuard) {
            CallScriptGlobalsSafe(entry.fn, reinterpret_cast<void*>(L));
        } else {
            Logger::Log("RegisterScriptData: registrar[%zu] skipped for inactive owner=%ls",
                i, entry.owner.c_str());
        }
        Logger::Log("RegisterScriptData: registrar[%zu] end", i);
        ++i;
    }
    if (g_origRegisterScriptData) {
        Logger::Log("RegisterScriptData: calling original");
        g_origRegisterScriptData(L);
        Logger::Log("RegisterScriptData: original returned");
    }
}

void __cdecl Hook_RegisterScriptDataForUI(hks::lua_State* unused, hks::lua_State* L) {
    // 高频路径：游戏每建一个 UI context 就调一次（主菜单/对局切换均触发），
    // 逐次日志会刷屏——行为日志降噪，registrar 照常每次执行（新 context 需要重新挂全局）。
    SharedDetourActivity activity;
    const auto snapshot = SnapshotScriptGlobals(g_scriptGlobalsUI);
    for (const auto& entry : snapshot) {
        PluginInFlight::Owner* owner = entry.inFlight;
        if (!owner) owner = PluginInFlight::Resolve(entry.owner);
        auto callbackGuard =
            PluginInFlight::Enter(owner, PluginInFlight::Kind::ScriptGlobalsUI);
        if (callbackGuard) {
            CallScriptGlobalsSafe(entry.fn, reinterpret_cast<void*>(L));
        }
    }
    if (g_origRegisterScriptDataForUI) {
        g_origRegisterScriptDataForUI(unused, L);
    }
}

// 确保已注册回调对应的共享钩子已装上。两条调用路径：
//  1) 插件 RegisterScriptGlobals / RegisterScriptGlobalsForUI 注册时；
//  2) GameCore 重载后 InitializeGameCorePhase 再调。
// 共享钩的 MinHook 记录随旧 GameCore 映像在 ResetForReload 里被物理摘除，因此重载后
// 必须按【当次】仍存在的注册项重新装钩；不存在跨代保留的注册列表。
// 检查+安装整体持锁，消除并发首装的重复创建竞态。安装走统一站点表，天然幂等，
// 因此不需要「已装就早退」标志：重复调用只是复用同一站点、刷新 g_orig* 跳板。
static void EnsureScriptHooksInstalled() {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (!g_gameCorePhaseReady) return;

    if (!g_scriptGlobals.empty()) {
        void* target = ResolveCurrentGameCoreByName("GameCore::Lua::Utility::RegisterScriptData");
        if (!target) {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptData address missing");
        } else if (InstallLoaderDetourOnSite(target,
                       reinterpret_cast<void*>(&Hook_RegisterScriptData),
                       reinterpret_cast<void**>(&g_origRegisterScriptData), "ScriptData")) {
            Logger::Log("EnsureScriptHooksInstalled: hooked RegisterScriptData at %p", target);
        } else {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptData hook install failed "
                        "(target held by another detour?)");
        }
    }
    if (!g_scriptGlobalsUI.empty()) {
        void* target = ResolveCurrentGameCoreByName("GameCore::Lua::Utility::RegisterScriptDataForUI");
        if (!target) {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptDataForUI address missing");
        } else if (InstallLoaderDetourOnSite(target,
                       reinterpret_cast<void*>(&Hook_RegisterScriptDataForUI),
                       reinterpret_cast<void**>(&g_origRegisterScriptDataForUI), "ScriptDataForUI")) {
            Logger::Log("EnsureScriptHooksInstalled: hooked RegisterScriptDataForUI at %p", target);
        } else {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptDataForUI hook install failed "
                        "(target held by another detour?)");
        }
    }
}

}  // namespace

// 前置声明（定义于本文件后部）：OnLoad 失败时隔离该 owner 的全部注册。
// （未声明插件类别的模块在 OnLoad 之前就被拒载；消息回调崩溃由 Civ6MessageBus 的 SEH
// 兜住并只记日志——两者都不走隔离。）
static void QuarantinePluginByOwner(const std::wstring& ownerId);

void RegisterScriptGlobalsImpl(ScriptGlobalsFn fn) {
    if (!fn) return;
    // owner 校验与登记必须在同一把生命周期锁内完成。原实现先 RequirePluginOwner（内部取锁
    // 后释放）、再单独取锁 push_back：这中间若插件被停用并跑完 RemovePluginOwnedRegistrations，
    // 本次登记就永远清不掉（停用期间被守卫挡住，重新启用后又会多注册一份）。
    // RequirePluginOwner 内部取的是同一把递归锁，重入安全。
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn),
                                        "RegisterScriptGlobals");
        if (!owner) return;
        if (!RequireGameCoreOwner(reinterpret_cast<const void*>(fn), "RegisterScriptGlobals")) return;
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        g_scriptGlobals.push_back(
            ScriptGlobalsEntry{ owner->ownerId, fn, PluginInFlight::Resolve(owner->ownerId) });
    }
    EnsureScriptHooksInstalled();  // 内部自带生命周期锁（含并发首装与重载后重装）
}

void RegisterScriptGlobalsForUIImpl(ScriptGlobalsFn fn) {
    if (!fn) return;
    // 同 RegisterScriptGlobalsImpl：校验与登记同锁，避免"校验后、登记前"被卸载插入。
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn),
                                        "RegisterScriptGlobalsForUI");
        if (!owner) return;
        if (!RequireGameCoreOwner(reinterpret_cast<const void*>(fn),
                                  "RegisterScriptGlobalsForUI")) return;
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        g_scriptGlobalsUI.push_back(
            ScriptGlobalsEntry{ owner->ownerId, fn, PluginInFlight::Resolve(owner->ownerId) });
    }
    EnsureScriptHooksInstalled();
}

namespace {

constexpr int kMaxPushHooks = 16;

struct NoManagerHookSlot {
    void* target = nullptr;
    PushMethodsNoFunc base = nullptr;
    vector<StoredLuaMethod> methods;
    // 与 methods 平行的 owner 缓存：detour 热路径按索引取，不做宽字符串哈希。
    // 同一 target 的槽位可容纳多个 owner 的方法，所以必须是逐方法的表。
    vector<PluginInFlight::Owner*> methodOwners;
    bool used = false;
};

struct WithManagerHookSlot {
    void* target = nullptr;
    PushMethodsWithFunc base = nullptr;
    vector<StoredLuaMethod> methods;
    vector<PluginInFlight::Owner*> methodOwners;
    bool used = false;
};

NoManagerHookSlot g_noManagerSlots[kMaxPushHooks];
WithManagerHookSlot g_withManagerSlots[kMaxPushHooks];

// 合并后重建槽位的 owner 平行表：已存在的方法沿用旧指针（按 exposedName 匹配），
// 新方法解析一次。只在安装/重放这条冷路径上跑，detour 热路径零哈希。
template <typename Slot>
vector<PluginInFlight::Owner*> RebuildSlotOwners(
        const Slot& slot, const vector<StoredLuaMethod>& merged) {
    vector<PluginInFlight::Owner*> owners;
    owners.reserve(merged.size());
    for (const auto& method : merged) {
        PluginInFlight::Owner* cached = nullptr;
        for (size_t k = 0; k < slot.methods.size(); ++k) {
            if (slot.methods[k].exposedName == method.exposedName) {
                if (k < slot.methodOwners.size()) cached = slot.methodOwners[k];
                break;
            }
        }
        if (!cached) cached = PluginInFlight::Resolve(method.owner);
        owners.push_back(cached);
    }
    return owners;
}

// 槽位方法表与 owner 平行表必须锁步维护：这里按 owner 删除，两张表用同一套
// 索引压缩，避免错位。
template <typename Slot>
size_t RemoveOwnedSlotMethods(Slot& slot, const std::wstring& owner) {
    size_t removed = 0;
    size_t write = 0;
    for (size_t read = 0; read < slot.methods.size(); ++read) {
        if (slot.methods[read].owner == owner) {
            ++removed;
            continue;
        }
        if (write != read) {
            slot.methods[write] = std::move(slot.methods[read]);
            if (read < slot.methodOwners.size()) {
                slot.methodOwners[write] = slot.methodOwners[read];
            }
        }
        ++write;
    }
    slot.methods.resize(write);
    if (slot.methodOwners.size() > write) slot.methodOwners.resize(write);
    return removed;
}

// 注入一个插件登记的 Lua 方法：owner 已进入停用/隔离流程时跳过。
//
// 为什么必须加这道守卫：detour 先在 g_pushStateMutex 内快照 slot.methods，再在锁外逐个
// 注入。若快照之后该插件开始停用，RemovePluginOwnedRegistrations 会清空 slot，而本 detour
// 仍会把已快照的函数指针重新塞回 Lua 表（闭包一旦注册进 Lua 表就没有撤销路径）。
// 加上守卫后：停用流程里的 PluginInFlight::WaitAll 会等待在途注入结束，之后才清空登记；
// 之后的调用因 owner 的 allowed 镜像为 false 被拒绝，不会再有新注入。
// 边界：这只防"卸载后又被重新注入"。已进入 Lua 表的闭包仍然存在（backlog，未解决）。
static bool PushStoredMethodIfActive(hks::lua_State* L, const StoredLuaMethod& method,
                                     PluginInFlight::Owner* cachedOwner, int stackOffset) {
    if (!method.owner.empty()) {
        // 优先用安装时缓存的 owner 条目；为 null（老数据 / 异常路径）退化为按
        // owner 字符串解析一次，绝不解引用空指针。
        PluginInFlight::Owner* owner = cachedOwner;
        if (!owner) owner = PluginInFlight::Resolve(method.owner);
        auto guard = PluginInFlight::Enter(owner, PluginInFlight::Kind::PushMethods);
        if (!guard) return false;
    }
    PushLuaMethod(L, reinterpret_cast<hks::luaFunc>(method.luaMethodFunc),
        method.internalName.c_str(), stackOffset, method.exposedName.c_str());
    return true;
}

template<int I>
void __fastcall DetourPushNoManager(hks::lua_State* L, int stackOffset) {
    SharedDetourActivity activity;
    // 拷贝快照后在锁外回调：methods 可能被 Loader 工作线程（插件卸载清理）并发修改，
    // 快照同时把函数指针与 internalName/exposedName 字符串一并拷贝，锁外安全使用。
    std::vector<StoredLuaMethod> methods;
    std::vector<PluginInFlight::Owner*> methodOwners;
    PushMethodsNoFunc base = nullptr;
    {
        lock_guard<mutex> lock(g_pushStateMutex);
        methods = g_noManagerSlots[I].methods;
        methodOwners = g_noManagerSlots[I].methodOwners;
        base = g_noManagerSlots[I].base;
    }
    for (size_t i = 0; i < methods.size(); ++i) {
        PluginInFlight::Owner* owner = i < methodOwners.size() ? methodOwners[i] : nullptr;
        if (!PushStoredMethodIfActive(L, methods[i], owner, stackOffset)) {
            Logger::Log("DetourPushNoManager<%d>: skipped %s (owner=%ls inactive)",
                I, methods[i].exposedName.c_str(), methods[i].owner.c_str());
        }
    }
    if (base) {
        base(L, stackOffset);
    }
}

template<int I>
void __fastcall DetourPushWithManager(void* manager, hks::lua_State* L, int stackOffset) {
    SharedDetourActivity activity;
    std::vector<StoredLuaMethod> methods;
    std::vector<PluginInFlight::Owner*> methodOwners;
    PushMethodsWithFunc base = nullptr;
    {
        lock_guard<mutex> lock(g_pushStateMutex);
        methods = g_withManagerSlots[I].methods;
        methodOwners = g_withManagerSlots[I].methodOwners;
        base = g_withManagerSlots[I].base;
    }
    for (size_t i = 0; i < methods.size(); ++i) {
        PluginInFlight::Owner* owner = i < methodOwners.size() ? methodOwners[i] : nullptr;
        if (!PushStoredMethodIfActive(L, methods[i], owner, stackOffset)) {
            Logger::Log("DetourPushWithManager<%d>: skipped %s (owner=%ls inactive)",
                I, methods[i].exposedName.c_str(), methods[i].owner.c_str());
        }
    }
    if (base) {
        base(manager, L, stackOffset);
    }
}

void* NoManagerDetourTable[kMaxPushHooks] = {
    reinterpret_cast<void*>(&DetourPushNoManager<0>),
    reinterpret_cast<void*>(&DetourPushNoManager<1>),
    reinterpret_cast<void*>(&DetourPushNoManager<2>),
    reinterpret_cast<void*>(&DetourPushNoManager<3>),
    reinterpret_cast<void*>(&DetourPushNoManager<4>),
    reinterpret_cast<void*>(&DetourPushNoManager<5>),
    reinterpret_cast<void*>(&DetourPushNoManager<6>),
    reinterpret_cast<void*>(&DetourPushNoManager<7>),
    reinterpret_cast<void*>(&DetourPushNoManager<8>),
    reinterpret_cast<void*>(&DetourPushNoManager<9>),
    reinterpret_cast<void*>(&DetourPushNoManager<10>),
    reinterpret_cast<void*>(&DetourPushNoManager<11>),
    reinterpret_cast<void*>(&DetourPushNoManager<12>),
    reinterpret_cast<void*>(&DetourPushNoManager<13>),
    reinterpret_cast<void*>(&DetourPushNoManager<14>),
    reinterpret_cast<void*>(&DetourPushNoManager<15>),
};

void* WithManagerDetourTable[kMaxPushHooks] = {
    reinterpret_cast<void*>(&DetourPushWithManager<0>),
    reinterpret_cast<void*>(&DetourPushWithManager<1>),
    reinterpret_cast<void*>(&DetourPushWithManager<2>),
    reinterpret_cast<void*>(&DetourPushWithManager<3>),
    reinterpret_cast<void*>(&DetourPushWithManager<4>),
    reinterpret_cast<void*>(&DetourPushWithManager<5>),
    reinterpret_cast<void*>(&DetourPushWithManager<6>),
    reinterpret_cast<void*>(&DetourPushWithManager<7>),
    reinterpret_cast<void*>(&DetourPushWithManager<8>),
    reinterpret_cast<void*>(&DetourPushWithManager<9>),
    reinterpret_cast<void*>(&DetourPushWithManager<10>),
    reinterpret_cast<void*>(&DetourPushWithManager<11>),
    reinterpret_cast<void*>(&DetourPushWithManager<12>),
    reinterpret_cast<void*>(&DetourPushWithManager<13>),
    reinterpret_cast<void*>(&DetourPushWithManager<14>),
    reinterpret_cast<void*>(&DetourPushWithManager<15>),
};

int FindOrAllocNoManagerSlot(void* target) {
    for (int i = 0; i < kMaxPushHooks; ++i) {
        if (g_noManagerSlots[i].used && g_noManagerSlots[i].target == target) return i;
    }
    for (int i = 0; i < kMaxPushHooks; ++i) {
        if (!g_noManagerSlots[i].used) {
            g_noManagerSlots[i].used = true;
            g_noManagerSlots[i].target = target;
            return i;
        }
    }
    return -1;
}

int FindOrAllocWithManagerSlot(void* target) {
    for (int i = 0; i < kMaxPushHooks; ++i) {
        if (g_withManagerSlots[i].used && g_withManagerSlots[i].target == target) return i;
    }
    for (int i = 0; i < kMaxPushHooks; ++i) {
        if (!g_withManagerSlots[i].used) {
            g_withManagerSlots[i].used = true;
            g_withManagerSlots[i].target = target;
            return i;
        }
    }
    return -1;
}

}  // namespace

void* InstallPushMethodsNoManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                  const std::wstring& owner) {
    if (!target || methods.empty() || owner.empty() || std::any_of(methods.begin(), methods.end(),
            [&owner](const StoredLuaMethod& method) {
                return method.owner != owner;
            })) {
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    // 不持 MinHook 锁：InstallLoaderDetourOnSite 内部自己取。锁序因而是
    // lifecycle -> pushState -> MinHook（没有反向路径：无人持 MinHook 锁再取 pushState）。
    lock_guard<mutex> stateLock(g_pushStateMutex);
    const int slot = FindOrAllocNoManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsNoManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_noManagerSlots[slot];
    auto merged = state.methods;
    if (!MergeLuaMethods(merged, methods)) {
        if (!state.base) state = NoManagerHookSlot{};
        return nullptr;
    }
    // owner 平行表在 swap 之前按旧表重建（已存在的方法沿用旧指针，新方法解析一次）。
    auto mergedOwners = RebuildSlotOwners(state, merged);
    if (state.base) {
        // 相同方法重复安装/重放不会重复注入；整批验证成功后才发布。
        state.methods.swap(merged);
        state.methodOwners.swap(mergedOwners);
        return reinterpret_cast<void*>(state.base);
    }

    // 新槽：先把 detour 装上统一站点，成功后才登记方法；失败完整回滚槽位——否则
    // 半初始化槽位会让重试重复追加方法或返回失效跳板。共享钩不再自带 MinHook 记录：
    // 站点持有唯一记录，state.base = 站点跳板（origSlot）。
    if (!InstallLoaderDetourOnSite(target, NoManagerDetourTable[slot],
                                   reinterpret_cast<void**>(&state.base), "PushMethods")) {
        Logger::Log("InstallPushMethodsNoManager: install detour failed (target held by another owner?)");
        state = NoManagerHookSlot{};
        return nullptr;
    }
    state.methods.swap(merged);
    state.methodOwners.swap(mergedOwners);
    return reinterpret_cast<void*>(state.base);
}

void* InstallPushMethodsWithManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                    const std::wstring& owner) {
    if (!target || methods.empty() || owner.empty() || std::any_of(methods.begin(), methods.end(),
            [&owner](const StoredLuaMethod& method) {
                return method.owner != owner;
            })) {
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    // 不持 MinHook 锁：InstallLoaderDetourOnSite 内部自己取（同 NoManager 路径的锁序）。
    lock_guard<mutex> stateLock(g_pushStateMutex);
    const int slot = FindOrAllocWithManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsWithManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_withManagerSlots[slot];
    auto merged = state.methods;
    if (!MergeLuaMethods(merged, methods)) {
        if (!state.base) state = WithManagerHookSlot{};
        return nullptr;
    }
    // owner 平行表在 swap 之前按旧表重建（已存在的方法沿用旧指针，新方法解析一次）。
    auto mergedOwners = RebuildSlotOwners(state, merged);
    if (state.base) {
        state.methods.swap(merged);
        state.methodOwners.swap(mergedOwners);
        return reinterpret_cast<void*>(state.base);
    }

    // 同 NoManager：站点是唯一的 MinHook 账本，state.base = 站点跳板（origSlot）。
    if (!InstallLoaderDetourOnSite(target, WithManagerDetourTable[slot],
                                   reinterpret_cast<void**>(&state.base), "PushMethods")) {
        Logger::Log("InstallPushMethodsWithManager: install detour failed (target held by another owner?)");
        state = WithManagerHookSlot{};
        return nullptr;
    }
    state.methods.swap(merged);
    state.methodOwners.swap(mergedOwners);
    return reinterpret_cast<void*>(state.base);
}

// hks 导入缺失时的统一降级：安全默认值 + 限次日志（脚本可能高频调用，不能每次刷日志）。
// 导入缺失在 InitHavokScript 已整体告警并停用 GameCore 插件加载；此处是纵深防御
// （阶段 A 已加载的 Global 插件仍可能在调用这些包装）。
static void WarnHksImportMissing(const char* name) {
    static std::atomic<int> s_warned{ 0 };
    if (s_warned.fetch_add(1, std::memory_order_relaxed) < 10) {
        Logger::Log("HookAPI lua wrapper unavailable (HavokScript import missing): %s", name);
    }
}

static bool ValidateLuaState(void* L, const char* apiName) {
    if (L) return true;
    Logger::Log("%s rejected: lua_State is null", apiName ? apiName : "Lua API");
    return false;
}

static bool ValidateLuaCString(const char* value, const char* apiName) {
    if (value) return true;
    Logger::Log("%s rejected: string argument is null", apiName ? apiName : "Lua API");
    return false;
}

// 有返回值包装：状态指针无效/导入缺失 → 日志 + fallback。
#define HKS_GUARD_RET(fnPtr, fallback, L, ...) \
    do { \
        if (!ValidateLuaState((L), #fnPtr)) return (fallback); \
        if (!(fnPtr)) { WarnHksImportMissing(#fnPtr); return (fallback); } \
        return (fnPtr)(reinterpret_cast<hks::lua_State*>(L), __VA_ARGS__); \
    } while (0)

// void 包装：状态指针无效/导入缺失 → 日志 + 直接返回。
#define HKS_GUARD_VOID(fnPtr, L, ...) \
    do { \
        if (!ValidateLuaState((L), #fnPtr)) return; \
        if (!(fnPtr)) { WarnHksImportMissing(#fnPtr); return; } \
        return (fnPtr)(reinterpret_cast<hks::lua_State*>(L), __VA_ARGS__); \
    } while (0)

#define HKS_GUARD_RET0(fnPtr, fallback, L) \
    do { \
        if (!ValidateLuaState((L), #fnPtr)) return (fallback); \
        if (!(fnPtr)) { WarnHksImportMissing(#fnPtr); return (fallback); } \
        return (fnPtr)(reinterpret_cast<hks::lua_State*>(L)); \
    } while (0)

void LuaPushNamedCClosureImpl(void* L, void* func, int a, const char* name, int b) {
    if (!func || !ValidateLuaCString(name, "LuaPushNamedCClosure") || a < 0 || b < 0) return;
    HKS_GUARD_VOID(hks::pushnamedcclosure, L,
        reinterpret_cast<hks::luaFunc>(func), a, name, b);
}

int LuaCheckIntegerImpl(void* L, int index) {
    HKS_GUARD_RET(hks::checkinteger, 0, L, index);
}

double LuaCheckNumberImpl(void* L, int index) {
    HKS_GUARD_RET(hks::checknumber, 0.0, L, index);
}

void LuaPushNilImpl(void* L) {
    HKS_GUARD_VOID(hks::pushnil, reinterpret_cast<hks::lua_State*>(L));
}

void LuaSetFieldImpl(void* L, int stackOffset, const char* name) {
    if (!ValidateLuaCString(name, "LuaSetField")) return;
    HKS_GUARD_VOID(hks::setfield, L, stackOffset, name);
}

int LuaGetTopImpl(void* L) {
    HKS_GUARD_RET0(hks::gettop, 0, L);
}

int LuaDoStringImpl(void* L, const char* str) {
    if (!ValidateLuaCString(str, "LuaDoString")) return 0;
    HKS_GUARD_RET(hks::dostring, 0, L, str);
}

int LuaToBooleanImpl(void* L, int index) {
    HKS_GUARD_RET(hks::toboolean, 0, L, index);
}

void LuaPushNumberImpl(void* L, double num) {
    HKS_GUARD_VOID(hks::pushnumber, L, num);
}

void LuaPushIntegerImpl(void* L, int num) {
    // 语义对齐：API 承诺压整数，用 hksi_lua_pushinteger 压整数标记值
    // （此前走 pushnumber 是历史遗留，hks 开启 IntLiterals 时两者字节码可区分）。
    HKS_GUARD_VOID(hks::pushinteger, L, num);
}

static bool FormatLuaString(char* buffer, size_t capacity, const char* format, va_list args,
                            const char* apiName) {
    if (!ValidateLuaCString(format, apiName)) return false;
    const int result = _vsnprintf_s(buffer, capacity, _TRUNCATE, format, args);
    if (result < 0) {
        Logger::Log("%s rejected: invalid or oversized format result", apiName);
        return false;
    }
    return true;
}

void LuaErrorImpl(void* L, char const* str, ...) {
    if (!ValidateLuaState(L, "LuaError") || !hks::error) {
        if (!hks::error) WarnHksImportMissing("hks::error");
        return;
    }
    char buffer[1024];
    va_list args;
    va_start(args, str);
    const bool formatted = FormatLuaString(buffer, sizeof(buffer), str, args, "LuaError");
    va_end(args);
    if (!formatted) return;
    hks::error(reinterpret_cast<hks::lua_State*>(L), "%s", buffer);
}

char const* LuaPushFStringImpl(void* L, char const* str, ...) {
    if (!ValidateLuaState(L, "LuaPushFString") || !hks::pushfstring) {
        if (!hks::pushfstring) WarnHksImportMissing("hks::pushfstring");
        return nullptr;
    }
    char buffer[1024];
    va_list args;
    va_start(args, str);
    const bool formatted = FormatLuaString(buffer, sizeof(buffer), str, args, "LuaPushFString");
    va_end(args);
    if (!formatted) return nullptr;
    return hks::pushfstring(reinterpret_cast<hks::lua_State*>(L), "%s", buffer);
}

char const* LuaCheckLStringImpl(void* L, int index, unsigned __int64* a) {
    if (!a) return nullptr;
    HKS_GUARD_RET(hks::checklstring, nullptr, L, index, a);
}

void* LuaToUserDataImpl(void* L, int index) {
    HKS_GUARD_RET(hks::touserdata, nullptr, L, index);
}

void LuaGetFieldImpl(void* L, int a, char const* b) {
    if (!ValidateLuaCString(b, "LuaGetField")) return;
    HKS_GUARD_VOID(hks::getfield, L, a, b);
}

void LuaPopImpl(void* L, int a) {
    if (a < 0) return;
    HKS_GUARD_VOID(hks::pop, L, a);
}

void LuaCreateTableImpl(void* L, int a, int b) {
    if (a < 0 || b < 0) return;
    HKS_GUARD_VOID(hks::createtable, L, a, b);
}

void* LuaToCFunctionImpl(void* L, int index) {
    if (!ValidateLuaState(L, "LuaToCFunction")) return nullptr;
    if (!hks::tocfunction) {
        WarnHksImportMissing("hks::tocfunction");
        return nullptr;
    }
    return reinterpret_cast<void*>(hks::tocfunction(reinterpret_cast<hks::lua_State*>(L), index));
}

void LuaCheckTableImpl(void* L, int index) {
    HKS_GUARD_VOID(hks::checktable, L, index);
}

unsigned long long LuaObjLenImpl(void* L, int index) {
    HKS_GUARD_RET(hks::objlen, 0, L, index);
}

void LuaGetTableImpl(void* L, int index) {
    HKS_GUARD_VOID(hks::gettable, L, index);
}

int LuaCPcallImpl(void* L, LuaMethodFunc callback, void* userdata) {
    if (!L || !callback) {
        return kHookApiLuaCallInvalidArgument;
    }
    HKS_GUARD_RET(hks::cpcall, kHookApiLuaCallUnavailable,
        L,
        reinterpret_cast<hks::luaFunc>(callback), userdata);
}

int LuaRefImpl(void* L, int index) {
    HKS_GUARD_RET(hks::ref, 0, L, index);
}

int LuaPcallImpl(void* L, int a, int b, int c) {
    if (a < 0 || b < -1) return 0;
    HKS_GUARD_RET(hks::pcall, 0, L, a, b, c);
}

void LuaPushValueImpl(void* L, int value) {
    HKS_GUARD_VOID(hks::pushvalue, L, value);
}

void LuaRawGetIImpl(void* L, int a, int b) {
    HKS_GUARD_VOID(hks::rawgeti, L, a, b);
}

void LuaUnrefImpl(void* L, int a, int b) {
    HKS_GUARD_VOID(hks::unref, L, a, b);
}

void LuaSetTableImpl(void* L, int t) {
    HKS_GUARD_VOID(hks::settable, L, t);
}

int LuaIsNumberImpl(void* L, int num) {
    HKS_GUARD_RET(hks::isnumber, 0, L, num);
}

double LuaToNumberImpl(void* L, int num) {
    HKS_GUARD_RET(hks::tonumber, 0.0, L, num);
}

int LuaIsUserDataImpl(void* L, int num) {
    HKS_GUARD_RET(hks::isuserdata, 0, L, num);
}

int LuaOpenDebugImpl(void* L) {
    HKS_GUARD_RET0(hks::luaopen_debug, 0, L);
}

int LuaToIntegerImpl(void* L, int num) {
    HKS_GUARD_RET(hks::tointeger, 0, L, num);
}

int LuaTypeImpl(void* L, int num) {
    HKS_GUARD_RET(hks::type, 0, L, num);
}

int LuaOptIntegerImpl(void* L, int a, int b) {
    HKS_GUARD_RET(hks::optinteger, b, L, a, b);
}

int LuaSetHookImpl(void* L, void* a, int b, int c) {
    if (c < 0) return 0;
    HKS_GUARD_RET(hks::sethook, 0, L, a, b, c);
}

void* LuaGetHookImpl(void* L) {
    HKS_GUARD_RET0(hks::gethook, nullptr, L);
}

int LuaGetHookMaskImpl(void* L) {
    HKS_GUARD_RET0(hks::gethookmask, 0, L);
}

int LuaGetHookCountImpl(void* L) {
    HKS_GUARD_RET0(hks::gethookcount, 0, L);
}

int LuaCheckPlayerIdImpl(void* L, int index) {
    if (!ValidateLuaState(L, "LuaCheckPlayerId")) return -1;
    return hks::checkplayerid(reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaPushBooleanImpl(void* L, bool value) {
    if (!ValidateLuaState(L, "LuaPushBoolean")) return;
    hks::pushboolean(reinterpret_cast<hks::lua_State*>(L), value);
}

void LuaPushLightUserDataImpl(void* L, void* ptr) {
    if (!ValidateLuaState(L, "LuaPushLightUserData")) return;
    hks::pushlightuserdata(reinterpret_cast<hks::lua_State*>(L), ptr);
}

void* LocalizationLookupImpl(void* outStr, const char* key) {
    if (!outStr || !key || !Localization::LookupPtr) {
        Logger::Log("LocalizationLookup: invalid args or LookupPtr not ready");
        return nullptr;
    }
    auto* result = reinterpret_cast<Localization::String*>(outStr);
    auto* ans = Localization::LookupPtr(result, key);
    if (!ans) {
        Logger::Log("LocalizationLookup: failed for key=%s", key);
    }
    return reinterpret_cast<void*>(ans);
}

// ---------------- HookAPI v2 ----------------

void LogImpl(const char* format, ...) {
    if (!format) return;
    char buffer[2048];
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    Logger::Log("%s", buffer);
}

void LuaPushCFunctionFieldImpl(void* L, int tableIndex, const char* fieldName, void* fn, const char* internalName) {
    if (!ValidateLuaState(L, "LuaPushCFunctionField") ||
        !ValidateLuaCString(fieldName, "LuaPushCFunctionField") || !fn) return;
    if (!hks::pushnamedcclosure || !hks::setfield) {
        WarnHksImportMissing("hks::pushnamedcclosure/setfield");
        return;
    }
    const char* iname = internalName && *internalName ? internalName : fieldName;
    auto* state = reinterpret_cast<hks::lua_State*>(L);
    // pushnamedcclosure grows the stack by 1; relative negative indices must be
    // adjusted so they still refer to the table (e.g. -1 -> -2), matching
    // Example2's explicit LuaSetField(L, -2, ...).
    // 伪索引（hks 全局表 LUA_GLOBAL=-10002 等，<= -10000）不随栈增长漂移，透传。
    const bool isPseudoIndex = (tableIndex <= -10000);
    const int idx = (tableIndex < 0 && !isPseudoIndex) ? (tableIndex - 1) : tableIndex;
    hks::pushnamedcclosure(state, reinterpret_cast<hks::luaFunc>(fn), 0, iname, 0);
    hks::setfield(state, idx, fieldName);
}

void LuaNewGlobalTableImpl(void* L, const char* globalName, int narr, int nrec) {
    if (!ValidateLuaState(L, "LuaNewGlobalTable") ||
        !ValidateLuaCString(globalName, "LuaNewGlobalTable") || narr < 0 || nrec < 0) return;
    if (!hks::createtable || !hks::setfield || !hks::getfield) {
        WarnHksImportMissing("hks::createtable/setfield/getfield");
        return;
    }
    auto* state = reinterpret_cast<hks::lua_State*>(L);
    hks::createtable(state, narr, nrec);
    hks::setfield(state, hks::LUA_GLOBAL, globalName);
    hks::getfield(state, hks::LUA_GLOBAL, globalName);
}

uint32_t LocStringBytesImpl(void) {
    return CIV6_HOOK_API_LOC_STRING_BYTES;
}

void* LocCreateImpl(void) {
    void* mem = calloc(1, CIV6_HOOK_API_LOC_STRING_BYTES);
    return mem;
}

void LocDestroyImpl(void* loc) {
    if (!loc) return;
    if (Localization::DestructorPtr) {
        Localization::DestructorPtr(reinterpret_cast<Localization::String*>(loc));
    }
    free(loc);
}

void* LocLookupImpl(void* loc, const char* key) {
    if (!loc || !key || !Localization::LookupPtr) {
        Logger::Log("LocLookup: invalid args or LookupPtr not ready");
        return nullptr;
    }
    return Localization::LookupPtr(reinterpret_cast<Localization::String*>(loc), key);
}

int LocPushArgumentImpl(void* loc, const char* arg) {
    if (!loc || !arg || !Localization::PushArgumentPtr) return 0;
    return Localization::PushArgumentPtr(reinterpret_cast<Localization::String*>(loc), arg) ? 1 : 0;
}

const char* LocToUtf8Impl(void* loc) {
    if (!loc || !Localization::ToUTF8Ptr) return nullptr;
    return Localization::ToUTF8Ptr(reinterpret_cast<Localization::String*>(loc));
}

using EditPlayerFn = void*(__fastcall*)(int playerId);

static EditPlayerFn ResolveEditPlayer() {
    return reinterpret_cast<EditPlayerFn>(
        ResolveCurrentGameCoreByName("GameCore::Context::Globals::EditPlayer"));
}

void* EditPlayerImpl(int playerId) {
    if (!RequireGameCoreOwner(_ReturnAddress(), "EditPlayer")) return nullptr;
    auto fn = ResolveEditPlayer();
    if (!fn) {
        Logger::Log("EditPlayer: symbol missing");
        return nullptr;
    }
    // 对局开始前 ms_pkCurrentGame 尚未初始化，引擎 EditPlayer 会
    // 解引用 null 而 AV——SEH 兜底返回 nullptr（对局前调用本就没有意义，属调用方时序错误）。
    __try {
        return fn(playerId);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("EditPlayer: engine call failed (game not started?)");
        return nullptr;
    }
}

// Civ 风格字符串哈希：官方 GameCore::Utilities::MakeHash 的逐位等价实现（IDA 实证）。
//   官方：MakeHash(s) => Crypto::CRC::CalcString(&GameCore::Utilities::ms_Hasher, s, 0xFFFFFFFF)
//   循环体：v4 = a3 >> 8; v5 = m_table[(uint8_t)(a3 ^ *p)]; a3 = v4 ^ v5; 返回 a3（无最终异或）；
//   ms_Hasher->m_table 就是标准反射表（多项式 0xEDB88320，init 0xFFFFFFFF）。
// 官方写入里 `char i` 配合 (unsigned __int8)(a3 ^ i) 的截断，使 char 的符号扩展不生效，
// 所以这里用 uint8_t 与之逐位一致。内化后不再解析 GameCore 符号：对局前也能算，也不受重载影响。
// 单字节推进（8 轮反射多项式）：两个入口共用同一核，保证逐位一致。
constexpr uint32_t CivCrc32Byte(uint32_t h, uint8_t b) {
    h ^= b;
    for (int i = 0; i < 8; ++i) {
        h = (h & 1u) ? ((h >> 1) ^ 0xEDB88320u) : (h >> 1);
    }
    return h;
}
// NUL 结尾版（下面 static_assert 的编译期自检走这条）。
constexpr uint32_t CivCrc32Raw(const char* str) {
    uint32_t h = 0xFFFFFFFFu;
    for (const char* p = str; p && *p; ++p) {
        h = CivCrc32Byte(h, static_cast<uint8_t>(*p));
    }
    return h;
}
// 定长版：长度已由边界探针确定的路径走这条，不再做无界循环。
constexpr uint32_t CivCrc32RawLen(const char* str, size_t len) {
    uint32_t h = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        h = CivCrc32Byte(h, static_cast<uint8_t>(str[i]));
    }
    return h;
}
// 官方表核对（ConsoleApplication1.cpp:17-50 里还原出来的 crc32_table，共 258 项）：
//   前 256 项与标准反射表（多项式 0xEDB88320）【逐项一致】；尾部多出的 0xEDB88320 /
//   0xDEBB20E3 永远不会被索引（索引只取 (uint8_t)），故闭式实现与官方查表实现逐位等价。
// 编译期自检（向量取自官方实现/还原工程实测值，不是本实现的输出）：
//   raw("")                  = 0xFFFFFFFF   （init 原样返回）
//   raw("123456789")         = 0x340BC6D9   （标准 CRC32 0xCBF43926 去掉最终异或）
//   raw("a")                 = 0x174841BC   （标准 0xE8B7BE43）
//   raw("Hello")             = 0x082E767D   （标准 0xF7D18982）
//   raw("TERRA7")            = 0x16D22538
//   raw("NOTIFICATION_ADDED")= 0xF26F3ACF   （ConsoleApplication1 旧 exe 对照值）
static_assert(CivCrc32Raw("")                   == 0xFFFFFFFFu, "Civ CRC32 self-check: empty");
static_assert(CivCrc32Raw("123456789")          == 0x340BC6D9u, "Civ CRC32 self-check: 123456789");
static_assert(CivCrc32Raw("a")                  == 0x174841BCu, "Civ CRC32 self-check: a");
static_assert(CivCrc32Raw("Hello")              == 0x082E767Du, "Civ CRC32 self-check: Hello");
static_assert(CivCrc32Raw("TERRA7")             == 0x16D22538u, "Civ CRC32 self-check: TERRA7");
static_assert(CivCrc32Raw("NOTIFICATION_ADDED") == 0xF26F3ACFu, "Civ CRC32 self-check: NOTIFICATION_ADDED");

uint32_t MakeHashImpl(const char* str) {
    if (!str) return 0;   // 空指针返回 0（官方实现会直接解引用）
    // str 是插件内存：先按插件字符串的统一口径量长度（限长内找不到结尾符 = 坏数据），
    // 之后读的就只有探针已证明可读的那 len 个字节——野指针/未终止串不会把游戏带崩。
    size_t len = 0;
    if (!PluginBoundary::TryStrLenRaw(str, PluginBoundary::kMaxPluginString, len)) {
        Logger::Log("MakeHash rejected: string pointer unreadable or unterminated %p "
                    "(span limit=%zu)", str, PluginBoundary::kMaxPluginString);
        return 0;
    }
    return CivCrc32RawLen(str, len);
}

int RegisterPushMethodsTargetImpl(const char* name, int sigType, const char* pushMethodsSymbol) {
    if (!name || !*name) return 0;

    // name / pushMethodsSymbol 都是插件内存：锁外抄写（含早期日志读到的 name）。
    std::string nameCopy;
    if (!PluginBoundary::CopyCString(name, nameCopy) || nameCopy.empty()) {
        Logger::Log("RegisterPushMethodsTarget rejected: name pointer unreadable");
        return 0;
    }
    if (sigType != kHookApiPushNoManager && sigType != kHookApiPushWithManager) {
        Logger::Log("RegisterPushMethodsTarget: bad sigType %d for %s",
            sigType, nameCopy.c_str());
        return 0;
    }
    std::string symbolCopy;
    if (pushMethodsSymbol && *pushMethodsSymbol) {
        if (!PluginBoundary::CopyCString(pushMethodsSymbol, symbolCopy)) {
            Logger::Log("RegisterPushMethodsTarget rejected: pushMethodsSymbol unreadable");
            return 0;
        }
    }

    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    // owner 探针仍用插件自己的 name 指针：RequirePluginOwner 只做模块归属查询，
    // 不解引用；换成 Loader 副本会被判成 Loader 自身而全部拒绝。
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(name),
                                    "RegisterPushMethodsTarget");
    if (!owner) return 0;
    if (!RequireGameCoreOwner(reinterpret_cast<const void*>(name),
                              "RegisterPushMethodsTarget")) return 0;

    PushTargetConfig config{
        sigType == kHookApiPushWithManager
        ? PushMethodSigType::WithManager
        : PushMethodSigType::NoManager,
        !symbolCopy.empty() ? symbolCopy : (nameCopy + "::PushMethods")
    };

    auto& ownerConfigs = g_pluginPushTargetConfigs[owner->ownerId];
    const auto existing = ownerConfigs.find(nameCopy);
    if (existing != ownerConfigs.end()) {
        if (existing->second.signature != config.signature ||
                existing->second.symbolName != config.symbolName) {
            Logger::Log("RegisterPushMethodsTarget: conflicting redefinition owner=%ls target=%s",
                owner->ownerId.c_str(), nameCopy.c_str());
            return 0;
        }
        return 1;
    }
    ownerConfigs.emplace(nameCopy, config);
    Logger::Log("RegisterPushMethodsTarget: owner=%ls target=%s sig=%d sym=%s",
        owner->ownerId.c_str(), nameCopy.c_str(), sigType, config.symbolName.c_str());
    return 1;
}

// ---------------- Patch/Unpatch (v2) ----------------

#pragma intrinsic(_ReturnAddress)

__declspec(noinline) static bool HookPatch(void* target, const void* bytes, size_t len) {
    if (!target || !bytes || len == 0) return false;
    if (len > PluginBoundary::kMaxPluginRawBytes) {
        Logger::Log("Patch rejected: len=%zu over limit (%zu)",
            len, PluginBoundary::kMaxPluginRawBytes);
        return false;
    }
    // bytes 是插件内存，而 PatchRegistry::Apply 会在自己的临界区内 memcpy 读它。
    // 锁外先抄一份：坏指针在这里失败，此时生命周期锁与补丁临界区都没被持有。
    std::vector<uint8_t> bytesCopy(len);
    if (!PluginBoundary::CopyRawBytes(bytes, bytesCopy.data(), len,
            PluginBoundary::kMaxPluginRawBytes)) {
        Logger::Log("Patch rejected: bytes pointer unreadable %p", bytes);
        return false;
    }

    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    if (TargetInTearingDownGameCore(target)) return false;
    if (OverlapsHookPrologue(target, len)) {
        Logger::Log("Patch rejected: %p overlaps a hooked prologue window (%zu bytes); "
                    "InstallHook/Unpatch it first", target, kHookPrologueWindow);
        return false;
    }
    auto owner = RequirePluginOwner(_ReturnAddress(), "Patch");
    if (!owner) return false;
    // 地址开放性门（整段）：GameCore 类别要求 [target, target+len) 全落在当前 GameCore 映像内；
    // Global 类别要求整段与 GameCore 映像不相交。
    if (!IsRangeOpenToCaller(owner->category, target, len, "Patch")) return false;
    return PatchRegistry::Apply(target, bytesCopy.data(), len, owner->ownerId.c_str());
}

__declspec(noinline) static bool HookUnpatch(void* target) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    auto owner = RequirePluginOwner(_ReturnAddress(), "Unpatch");
    if (!owner) return false;
    // 地址开放性门：Patch 时已按整段校验过，这里只校验目标点
    // （PatchRegistry 没有现成的长度访问器，不为此改动别的文件）。
    if (!IsTargetOpenToCaller(owner->category, target, "Unpatch")) return false;
    return PatchRegistry::RevertOwned(target, owner->ownerId.c_str());
}

// 只读契约：Loader 初始化后从不写它（全是取地址/读取），插件也只该读。
// const 让它落到 .rdata（PAGE_READONLY）——插件写它会当场 AV，被 CallOnLoadSafe 接住。
static const HookAPI g_hookApi = {
    CIV6_HOOK_API_VERSION,
    static_cast<uint32_t>(sizeof(HookAPI)),

    &InstallHookImpl,
    &BroadcastMessageImpl,
    &RegisterMessageHandlerImpl,
    &SendMessageToImpl,

    &IsImageLoadedImpl,
    &GetImageInfoImpl,
    &ResolveByRvaImpl,
    &ResolveByNameImpl,
    &ResolveByRvaExImpl,
    &ResolveByPatternImpl,
    &RegisterGlobalCaptureImpl,
    &ResolveByVTableImpl,

    &PushLuaMethodsImpl,

    &RegisterScriptGlobalsImpl,
    &RegisterScriptGlobalsForUIImpl,

    &LuaPushNamedCClosureImpl,
    &LuaCheckIntegerImpl,
    &LuaCheckNumberImpl,
    &LuaSetFieldImpl,
    &LuaGetTopImpl,
    &LuaDoStringImpl,
    &LuaToBooleanImpl,
    &LuaPushNumberImpl,
    &LuaPushIntegerImpl,
    &LuaErrorImpl,
    &LuaPushFStringImpl,
    &LuaCheckLStringImpl,
    &LuaToUserDataImpl,
    &LuaGetFieldImpl,
    &LuaPopImpl,
    &LuaCreateTableImpl,
    &LuaToCFunctionImpl,
    &LuaCheckTableImpl,
    &LuaObjLenImpl,
    &LuaGetTableImpl,
    &LuaCPcallImpl,
    &LuaRefImpl,
    &LuaPcallImpl,
    &LuaPushValueImpl,
    &LuaRawGetIImpl,
    &LuaUnrefImpl,
    &LuaSetTableImpl,
    &LuaIsNumberImpl,
    &LuaToNumberImpl,
    &LuaIsUserDataImpl,
    &LuaOpenDebugImpl,
    &LuaToIntegerImpl,
    &LuaTypeImpl,
    &LuaOptIntegerImpl,
    &LuaSetHookImpl,
    &LuaGetHookImpl,
    &LuaGetHookMaskImpl,
    &LuaGetHookCountImpl,
    &LuaCheckPlayerIdImpl,
    &LuaPushBooleanImpl,
    &LuaPushLightUserDataImpl,

    &LogImpl,
    &LuaPushCFunctionFieldImpl,
    &LuaNewGlobalTableImpl,

    &LocalizationLookupImpl,

    &LocStringBytesImpl,
    &LocCreateImpl,
    &LocDestroyImpl,
    &LocLookupImpl,
    &LocPushArgumentImpl,
    &LocToUtf8Impl,

    &EditPlayerImpl,
    &MakeHashImpl,

    &RegisterPushMethodsTargetImpl,

    &HookPatch,
    &HookUnpatch,

    &RegisterGameEventImpl,
    &TriggerGameEventImpl,

    &GetEngineUtilityImpl,
    &GetActiveLuaStateImpl,
    &LuaPushNilImpl,
};

// 编译期守卫（配套 common/HookAPI.h 的 CIV6_HOOK_API_ENTRY_COUNT）：
//  1) sizeof 抓住"往 HookAPI 追加了字段，却没同步计数/初始化表"；
//  2) 末尾字段的偏移抓住"重排或删除字段"（冻结前缀只允许尾部追加）。
static_assert(sizeof(HookAPI) == sizeof(uint32_t) * 2 + CIV6_HOOK_API_ENTRY_COUNT * sizeof(void*),
    "HookAPI 字段数与 CIV6_HOOK_API_ENTRY_COUNT 不一致：追加字段后必须同步更新计数并补齐 g_hookApi");
static_assert(offsetof(HookAPI, LuaPushNil) ==
        sizeof(uint32_t) * 2 + (CIV6_HOOK_API_ENTRY_COUNT - 1) * sizeof(void*),
    "HookAPI 末尾字段位置变化：只允许在尾部追加，且必须同步 CIV6_HOOK_API_ENTRY_COUNT");

// loader 内部复用 common/HookAPI.h 的 HookInfo 取址工具时的入口（LoaderHooks/UiInject 用），
// 也是把这张表交给插件（OnLoad）的唯一出口。
// 契约：只读。const_cast 只是为了配合既有 HookAPI* 签名（common/HookAPI.h 里的 inline
// 工具函数都吃 HookAPI*）；任何调用方都不得写入。
HookAPI* LoaderCore::RuntimeHookApi() {
    return const_cast<HookAPI*>(&g_hookApi);
}

// 启动自检：确认这张表真的落在只读页，并且没有空项。MSVC 一般会把常量初始化的 const 对象
// 放进 .rdata，但那是实现细节而非语言保证 —— 一旦落到可写段，"插件改表"就不会被拦。
// 空项检查补的是编译器抓不到的那一半：追加字段、bump 了计数却漏填初始化的项，
// 聚合初始化只会静默零填，等到插件按表调用就是空指针调用 —— 这里在启动时 fail-loud。
// 前提由上面两条 static_assert 保证：入口字段从 offsetof(InstallHook) 起连续 8 字节一格。
void LoaderCore::VerifyHookApiTableProtection() {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(&g_hookApi, &mbi, sizeof(mbi)) == 0) {
        Logger::Log("[WARN] HookAPI 表: VirtualQuery 失败 err=%lu", GetLastError());
        return;
    }
    const DWORD protect = mbi.Protect;
    const bool writable = (protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    if (writable) {
        Logger::Log("[WARN] HookAPI 表落在可写页 (Protect=0x%lX base=%p)：插件写入不会被拦截，"
                    "请检查 const 与段归属", protect, static_cast<const void*>(&g_hookApi));
    } else {
        Logger::Log("HookAPI 表只读保护已验证 (Protect=0x%lX)", protect);
    }

    // 空项扫描：入口字段在结构体里连续排列（由 static_assert 保证），逐格读一遍。
    const uint8_t* slotBase = reinterpret_cast<const uint8_t*>(&g_hookApi) +
        offsetof(HookAPI, InstallHook);
    size_t nulls = 0;
    for (uint32_t i = 0; i < CIV6_HOOK_API_ENTRY_COUNT; ++i) {
        void* slot = nullptr;
        std::memcpy(&slot, slotBase + static_cast<size_t>(i) * sizeof(void*), sizeof(void*));
        if (!slot) {
            ++nulls;
            Logger::Log("[WARN] HookAPI 表第 %u 项为空（追加字段后忘了填 g_hookApi？）", i);
        }
    }
    if (nulls != 0) {
        Logger::Log("[WARN] HookAPI 表空项合计 %zu / %u：这些入口一旦被插件调用就是空指针调用",
            nulls, CIV6_HOOK_API_ENTRY_COUNT);
    }
}

// exe 版本锚（SizeOfImage + FileHeader.TimeDateStamp）：无符号库时判断"能否直接信任原始 RVA"。
// 由 tools/symdb.py aob 的同一份逆向数据得出；游戏更新后这里会失配 -> 只走 AOB 兜底。
namespace {
constexpr uint32_t kAnchorDx11SizeOfImage = 0x36D1000;
constexpr uint32_t kAnchorDx11TimeDate   = 0x667C6FC6;
constexpr uint32_t kAnchorDx12SizeOfImage = 0xFE22000;
constexpr uint32_t kAnchorDx12TimeDate   = 0x667C7363;
}

static bool ExeMatchesAnchor(HookImageId image) {
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(image, &info) || !info.base || !info.imageSize) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(info.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(info.base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const uint32_t sizeOfImage = nt->OptionalHeader.SizeOfImage;
    const uint32_t timeDate = nt->FileHeader.TimeDateStamp;
    if (image == kHookImageExeDx11) {
        return sizeOfImage == kAnchorDx11SizeOfImage && timeDate == kAnchorDx11TimeDate;
    }
    if (image == kHookImageExeDx12) {
        return sizeOfImage == kAnchorDx12SizeOfImage && timeDate == kAnchorDx12TimeDate;
    }
    return false;
}

void* LoaderCore::ResolveExeTarget(const HookInfoExe& info, size_t span) {
    // 走内部无锁表：游戏线程在 LoadDLL detour 里解析自家 hook 目标，不拿插件生命周期锁。
    const HookImageId image = CurrentExeImage();
    if (image == kHookImageInvalid) return nullptr;
    const HookInfo& entry = (image == kHookImageExeDx12) ? info.dx12 : info.dx11;
    const bool haveContext = PdataMatch::HasContext(image);
    if (haveContext || ExeMatchesAnchor(image)) {
        if (void* p = ResolveByHookInfo(InternalToolApi(), image, entry, span)) return p;
        Logger::Log("ResolveExeTarget: image=%u kind=%d unresolved (rva=0x%llX aob=%s)",
            static_cast<unsigned>(image), static_cast<int>(entry.kind),
            static_cast<unsigned long long>(entry.kind == kHookInfoRva ? entry.u.rva : 0),
            entry.aob ? "yes" : "no");
        return nullptr;
    }
    Logger::Log("ResolveExeTarget: [WARN] image=%u no symbol DB and PE identity != anchor; "
                "RVA path skipped, AOB fallback only", static_cast<unsigned>(image));
    if (entry.aob && *entry.aob) {
        return InternalToolApi()->ResolveByPattern(image, entry.aob, kSectionText);
    }
    return nullptr;
}

typedef void (*OnLoadFunc)(HookAPI*);
typedef void (*OnUnloadFunc)();
typedef void (*OnMessageFunc)(const char*, const void*, size_t);

static DWORD GetModuleSizeOfImage(HMODULE module) {
    if (!module) return 0;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

bool AttachGameCore(HMODULE gameCore) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    const DWORD sizeOfImage = GetModuleSizeOfImage(gameCore);
    const HookImageId image = ImageAddress::IdentifyGameCore(gameCore);
    if (sizeOfImage == 0 || image == kHookImageInvalid) {
        Logger::Log("GameCore rejected: invalid or unknown PE image");
        return false;
    }
    // XP2：先建 pdata 矫正表（sidecar 由 RuntimeEntry InitEarly 装载）。失败 = 无法矫正，
    // 拒绝注入（GameCore 本身照常运行）。
    if (PdataMatch::HasContext(image) && !PdataMatch::BuildNewTable(image, gameCore)) {
        Logger::Log("GameCore rejected: pdata table build failed");
        return false;
    }

    if (!ImageAddress::AttachGameCore(gameCore)) {
        Logger::Log("GameCore rejected: ImageAddress attach failed");
        return false;
    }
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(image, &info)) {
        ImageAddress::DetachGameCore();
        return false;
    }

    Logger::Log("GameCore attached image=%u base=0x%llX SizeOfImage=0x%08X",
        static_cast<unsigned>(image),
        static_cast<unsigned long long>(info.base), sizeOfImage);
    return true;
}

static bool CallOnLoadSafe(OnLoadFunc onLoad, const char* name) {
    __try {
        onLoad(LoaderCore::RuntimeHookApi());
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("OnLoad crashed in plugin %s code=0x%08X", name, GetExceptionCode());
        return false;
    }
}

static void CallOnUnloadSafe(OnUnloadFunc onUnload, const char* name) {
    __try {
        onUnload();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("OnUnload crashed in plugin %s code=0x%08X", name ? name : "?", GetExceptionCode());
    }
}

// Civ6PluginKind 的调用同样是"执行插件代码"（按契约只是返回常量，但不带任何强约束）。
// 独立 SEH 叶子：LoadPluginDllInternal 里全是需要展开的 C++ 对象，不能直接写 __try（C2712）。
__declspec(noinline) static bool CallPluginKindSafe(uint64_t(*fn)(), uint64_t* outKind, DWORD* outCode) {
    __try {
        *outKind = fn();
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (outCode) *outCode = GetExceptionCode();
        return false;
    }
}

// v2 统一插件加载流程：LoadLibraryExW + 类别/ABI 门禁(OnLoad 之前) + OnLoad(SEH) +
// OnMessage 自动注册 + 记录跟踪项。
// nameNarrow = 显示名（通常为文件名，内部取 stem 作 Patch owner / OnMessage 名）；已加载（同句柄）返回 false。
static bool LoadPluginDllInternal(const std::wstring& wpath, const std::string& nameNarrow,
    LoaderCore::PluginCategory category) {
    lock_guard<std::recursive_mutex> transitionLock(g_gameCoreTransitionMutex);
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);

    // 下面几步都会执行"别人的代码"：LoadLibraryExW 的 DllMain（及其依赖链）、插件的
    // Civ6PluginKind 导出。必须在**不持 lifecycle 锁**时做 —— 这把锁是最常被重入的
    // （插件回调、owner 探针都要它），持着它去跑第三方 DllMain/导出会把插件回调路径一起卡住，
    // 甚至自死锁。transition 锁仍罩全程：唯一的 teardown 入口 ResetForReload 拿的是同一把锁，
    // 而"往 g_plugins 加条目"只发生在本函数（加载是单线程串行的），所以放宽这几步是安全的。
    lifecycleLock.unlock();

    // 已驻留模块（更早的启用周期留下、未卸载）用 UNCHANGED_REFCOUNT 取回，"禁用→启用"
    // 循环不再累计引用计数；未映射才真正加载。ownsRef 标记引用是否归本调用所有，
    // 失败路径只释放自己拿到的引用（GetModuleHandleEx 取回的引用不属于我们）。
    bool ownsRef = false;
    HMODULE hPlugin = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            wpath.c_str(), &hPlugin)) {
        hPlugin = LoadLibraryExW(wpath.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        ownsRef = (hPlugin != nullptr);
    }
    if (!hPlugin) {
        Logger::Log("LoadPlugin failed: %s err=%lu", ModScan::WideToNarrow(wpath).c_str(), GetLastError());
        return false;
    }

    lifecycleLock.lock();
    for (const auto& entry : g_plugins) {
        if (entry.handle == hPlugin) {
            if (ownsRef) FreeLibrary(hPlugin);
            return false;
        }
    }
    lifecycleLock.unlock();

    // 类别门禁前置（OnLoad 之前）：插件头文件（common/HookAPI.h）自动发出 Civ6PluginKind 导出，
    // 低 32 位 = kind（高 32 位 = apiVersion，只进日志、不参与判断）。在这里拒载是安全的，
    // 但注意它不等于"插件没跑过代码"：LoadLibraryExW 已经跑过它的 DllMain/CRT 初始化，
    // 拒载安全的含义只是"没有任何经 Loader 账本的钩子/补丁/回调需要回滚"，
    // 因此可以直接释放本次自己 LoadLibraryExW 拿到的引用（ownsRef）——这是信任边界，
    // 不是安全保证。ABI 版本兼容性由插件侧 HookAPI_IsCompatible 判。
    using PluginKindFn = uint64_t(*)();
    auto kindFn = reinterpret_cast<PluginKindFn>(GetProcAddress(hPlugin, "Civ6PluginKind"));
    if (!kindFn) {
        Logger::Log("Plugin rejected: 缺 Civ6PluginKind 导出（必须用带类别门禁的 HookAPI.h 重编）: %s",
            ModScan::WideToNarrow(wpath).c_str());
        if (ownsRef) FreeLibrary(hPlugin);
        return false;
    }
    uint64_t kindInfo = 0;
    DWORD kindCrash = 0;
    if (!CallPluginKindSafe(kindFn, &kindInfo, &kindCrash)) {
        Logger::Log("Plugin rejected: Civ6PluginKind crashed code=0x%08X: %s",
            kindCrash, ModScan::WideToNarrow(wpath).c_str());
        if (ownsRef) FreeLibrary(hPlugin);
        return false;
    }
    const uint32_t declaredKind = static_cast<uint32_t>(kindInfo & 0xFFFFFFFFu);
    const uint32_t declaredApi = static_cast<uint32_t>(kindInfo >> 32);   // 仅日志/诊断
    LoaderCore::PluginCategory declaredCategory = LoaderCore::PluginCategory::Global;
    if (!KindToCategory(declaredKind, declaredCategory) || declaredCategory != category) {
        Logger::Log("Plugin rejected: 类别与安装路径不符 (kind=%u api=%u 路径类别=%s): %s",
            static_cast<unsigned>(declaredKind), static_cast<unsigned>(declaredApi),
            CategoryNameForLog(category), ModScan::WideToNarrow(wpath).c_str());
        if (ownsRef) FreeLibrary(hPlugin);
        return false;
    }

    auto onLoad = (OnLoadFunc)GetProcAddress(hPlugin, "OnLoad");
    if (!onLoad) {
        Logger::Log("Plugin has no OnLoad export: %s", ModScan::WideToNarrow(wpath).c_str());
        if (ownsRef) FreeLibrary(hPlugin);
        return false;
    }

    // 注册跟踪项（此后都在 lifecycle 锁内，直到需要调 OnLoad 时再放锁）。
    lifecycleLock.lock();
    const std::string narrow = ModScan::WideToNarrow(wpath);
    std::string pluginFileName = nameNarrow;
    if (pluginFileName.empty()) {
        const size_t slash = narrow.find_last_of("\\/");
        pluginFileName = slash == std::string::npos ? narrow : narrow.substr(slash + 1);
    }

    // stem 只用于消息寻址；ownerId 使用规范化完整路径，避免不同 Mod 的同名 DLL
    // 在卸载/隔离时互相清理。
    std::wstring pluginStem;
    {
        std::string stemName = pluginFileName;
        const size_t dot = stemName.find_last_of('.');
        if (dot != std::string::npos) stemName = stemName.substr(0, dot);
        pluginStem = ModScan::NarrowToWide(stemName);
    }
    Logger::Log("Loaded plugin %s (%s)", pluginFileName.c_str(), narrow.c_str());

    PluginEntry entry;
    entry.handle = hPlugin;
    entry.path = wpath;
    entry.name = pluginStem;
    entry.ownerId = NormalizePluginPath(wpath);
    entry.category = category;
    SetPluginState(entry, PluginState::Loading);
    const std::wstring ownerId = entry.ownerId;
    g_plugins.push_back(std::move(entry));

    // OnLoad 期间暴露"当前插件名"给 Patch 作 owner；SEH 由 CallOnLoadSafe 包裹，
    // 无论 OnLoad 正常返回还是崩溃，都要在返回后清空，防止污染后续插件。
    SetActivePluginContext(ownerId, hPlugin);
    lifecycleLock.unlock();
    const bool onLoadOk = CallOnLoadSafe(onLoad, pluginFileName.c_str());
    ClearActivePluginContext();
    lifecycleLock.lock();

    const auto trackedAfterLoad = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&ownerId](const PluginEntry& tracked) {
            return tracked.ownerId == ownerId;
        });
    if (!onLoadOk) {
        // 崩溃隔离：按 owner 回滚全部注册并标记隔离，防止半初始化状态持续生效、
        // 以及阶段 B 全量扫描反复重试崩溃的 OnLoad（条目留在 g_plugins，按路径去重拦住重试）。
        Logger::Log("Plugin quarantined after OnLoad failure: %s", narrow.c_str());
        lifecycleLock.unlock();
        // 此处必然还没被隔离：隔离的唯一调用点就是这一行（OnLoad 期间没有别的路径能先把
        // 本 owner 标成 Quarantined）。
        QuarantinePluginByOwner(ownerId);
        // 模块释放策略（崩溃 = OnLoad 已经跑过，插件可能留有待执行的 detour）：
        //   GameCore 类别：入队，等引擎卸完 GameCore（连同它的 Lua 环境）之后再 FreeLibrary；
        //                  Free 时 FreePendingPluginModules 会把这里的悬垂句柄置空。
        //   Global  类别：驻留——exe 域钩子被高频调用，MH_DisableHook 不等待所有在飞调用，
        //                  此刻 FreeLibrary 会把正在执行的插件代码变成 UAF。
        if (category == LoaderCore::PluginCategory::GameCore) {
            QueueGameCoreModuleForFree(hPlugin);
            Logger::Log("Plugin quarantined, module queued for free after engine GameCore unload: %s",
                ModScan::WideToNarrow(wpath).c_str());
        } else {
            Logger::Log("Plugin quarantined, module parked (kept mapped): %s",
                ModScan::WideToNarrow(wpath).c_str());
        }
        return false;
    }
    if (trackedAfterLoad == g_plugins.end()) {
        return false;
    }

    auto onMessage = (OnMessageFunc)GetProcAddress(hPlugin, "OnMessage");
    lifecycleLock.unlock();
    if (onMessage) {
        const bool registered = RegisterPluginMessageHandler(ownerId, onMessage);
        Logger::Log("OnMessage auto-registration %s for %s",
            registered ? "succeeded" : "rejected", pluginFileName.c_str());
    }
    lifecycleLock.lock();
    const auto activate = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&ownerId](const PluginEntry& tracked) {
            return tracked.ownerId == ownerId;
        });
    if (activate == g_plugins.end() || activate->state != PluginState::Loading) {
        lifecycleLock.unlock();
        g_bus.UnregisterOwner(ownerId);
        return false;
    }
    SetPluginState(*activate, PluginState::Active);
    return true;
}

// 说明（为什么这里什么都没有了）：v1 曾有一条"loader 消息入口"——任何插件都能
// BroadcastMessage/SendMessageTo("Loader", "load-plugin", <路径>)，让 Loader 去
// LoadLibrary 那个**任意路径**的 DLL 并以完整 HookAPI 调它的 OnLoad。它绕过了
// ModScan/EnabledMods 的启用集过滤（等于把"任意 native 代码执行"交给任何插件），
// 而且仓库里没有任何生产者。已连同 InitializeLoader（它唯一职责就是注册那个
// "Loader" 消息处理器）一并删除：插件只从"启用 Mod 的 Plugins\{Global,GameCore}"
// 目录、经 LoaderCore::LoadSinglePlugin 加载。

// ================= LoaderCore 实现（插件生命周期） =================

// 退役某插件通过 HookAPI.InstallHook 注册的 detour 槽（只拔插槽，绝不物理脱钩）：
// 清空该 owner 的 activeDetour / detourOwner，nextTarget 回落到 minhookTrampoline
// （stub 与 MinHook 钩保持存活，纯透传）。不这样做的话，插件卸载后再 OnLoad 会因
// 站点 activeDetour 非空而无法重新挂钩。
// 站点表是唯一的挂钩账本：Loader 共享钩的 detourOwner 恒为空，不会被这里命中。
// 在卸载插件的 FreeLibrary 之前调用；调用方传的是 ownerId（规范化小写的插件全路径）。
// Loader 自身共享钩的 detourOwner 是空串，不会被这里命中。
static void RemovePluginHooks(const wchar_t* owner) {
    if (!owner || !*owner) return;
    lock_guard<mutex> lock(Runtime::MinHookMutex());
    RetireHookSiteDetoursForOwnerLocked(std::wstring(owner));
}

// 撤销某插件注册的全部回调类条目（禁用/隔离时调用）：脚本全局、PushMethods
// 方法/目标配置、GameEvent 槽位。这些条目都持有指向插件映像的函数指针，
// 不清就会在对应 detour / 触发点里调进已释放内存（与 OnMessage 悬空 handler
// 同类问题）。槽位的 methods 清空后保留已装 hook（detour 只透传 base）。
static void RemovePluginOwnedRegistrations(const std::wstring& owner) {
    if (owner.empty()) return;
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);

    auto removeOwnedBy = [&owner](auto& vec) {
        size_t removed = 0;
        for (auto it = vec.begin(); it != vec.end(); ) {
            if (it->owner == owner) {
                it = vec.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        return removed;
    };

    size_t globals = 0;
    size_t globalsUi = 0;
    {
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        globals = removeOwnedBy(g_scriptGlobals);
        globalsUi = removeOwnedBy(g_scriptGlobalsUI);
    }

    size_t methods = 0;
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (auto& slot : g_noManagerSlots) {
            if (slot.used) methods += RemoveOwnedSlotMethods(slot, owner);
        }
        for (auto& slot : g_withManagerSlots) {
            if (slot.used) methods += RemoveOwnedSlotMethods(slot, owner);
        }
    }

    const size_t targetConfigsRemoved = g_pluginPushTargetConfigs.erase(owner);

    // GameEvent 槽位：清空该 owner 注册的事件表（name/luaPushFn/ownerId）。
    // Quarantine/Unload 都经本函数，无需在各自路径重复接线。
    CleanupGameEventsForOwner(owner);

    Logger::Log("RemovePluginOwnedRegistrations: owner=%ls globals=%zu globalsUI=%zu luaMethods=%zu targetConfigs=%zu",
        owner.c_str(), globals, globalsUi, methods, targetConfigsRemoved);
}

// 崩溃隔离（与 OnLoad 崩溃同构）：标记隔离 + 回滚该 owner 的全部注册
// （补丁/MinHook 钩/Lua 方法/脚本全局/GameEvent/OnMessage）。模块驻留不卸；
// 隔离后 reconcile 与阶段 B 全量扫描都不再重试。
static void QuarantinePluginByOwner(const std::wstring& ownerId) {
    if (ownerId.empty()) return;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (auto& entry : g_plugins) {
            if (entry.ownerId == ownerId) {
                SetPluginState(entry, PluginState::Quarantined);
                break;
            }
        }
    }
    // 先禁用并排空所有外部入口；等待期间不得持 lifecycle 锁。
    g_bus.UnregisterOwner(ownerId);
    PluginInFlight::WaitAll(PluginInFlight::Resolve(ownerId), ownerId.c_str());
    PatchRegistry::RevertAllFor(ownerId.c_str());
    RemovePluginHooks(ownerId.c_str());
    // 隔离路径也必须撤销参数捕获站点；否则站点仍会向插件的 out 槽写入数据。
    CleanupCaptureSitesForOwner(ownerId);
    RemovePluginOwnedRegistrations(ownerId);
    Logger::Log("Plugin quarantined by owner: %ls", ownerId.c_str());
}

// 按跟踪项卸载单个插件（调用方保证 index 有效）：
// OnUnload → PatchRegistry::RevertAllFor(name) → RemovePluginHooks(name) → 撤销 capture /
// 回调类注册 → 从 g_plugins 摘除 →（freeModule 时）句柄入队，等引擎卸完 GameCore 才 Free。
// freeModule 只由 GameCore 类别传 true：GameCore 插件随对局重载必须真正卸载，插件静态
// 状态才不会跨局残留；调用前 ResetForReload 已批量还原入口字节，不会再有人进入该插件的
// detour。Global 插件一律 false（只在启动时加载，禁用需要重启）；崩溃隔离路径根本不走
// 本函数，模块继续驻留。
static void UnloadPluginByOwnerId(const std::wstring& ownerId, bool freeModule) {
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    const auto initial = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&ownerId](const PluginEntry& entry) {
            return entry.ownerId == ownerId;
        });
    if (initial == g_plugins.end()) return;
    const size_t index = static_cast<size_t>(initial - g_plugins.begin());
    if (g_plugins[index].state != PluginState::Active) {
        Logger::Log("UnloadPluginEntryAt: quarantined plugin remains parked: %s",
                    ModScan::WideToNarrow(g_plugins[index].path).c_str());
        return;
    }

    SetPluginState(g_plugins[index], PluginState::Deactivating);
    PluginEntry entry = g_plugins[index];

    // 先阻止并排空消息回调，避免 OnUnload 释放插件状态时旧快照仍在执行。
    // 等待时必须释放 lifecycle 锁，否则 handler 若正在调用 HookAPI 会锁反转。
    lifecycleLock.unlock();
    g_bus.UnregisterOwner(entry.ownerId);
    // 脚本全局/GameEvent 入口使用快照并在锁外执行；先排空 owner 的在途调用，
    // 再进入 OnUnload，避免插件状态被释放后旧回调继续访问。
    PluginInFlight::WaitAll(PluginInFlight::Resolve(entry.ownerId), entry.ownerId.c_str());
    auto onUnload = (OnUnloadFunc)GetProcAddress(entry.handle, "OnUnload");
    SetActivePluginContext(entry.ownerId, entry.handle);
    if (onUnload) CallOnUnloadSafe(onUnload, nullptr);
    // 先 OnUnload 后回滚补丁：插件 OnUnload 可能仍依赖自己的补丁。
    // 必须在 FreeLibrary 之前回滚——补丁目标可能位于该插件自身映像内。
    PatchRegistry::RevertAllFor(entry.ownerId.c_str());
    // 撤销该插件的 MinHook 钩子：否则 GameCore 重载后重新 OnLoad 会撞 MH_ERROR_ALREADY_CREATED。
    RemovePluginHooks(entry.ownerId.c_str());
    // 撤销该插件的参数捕获订阅；其它 owner 仍在使用的共享站点继续工作。
    CleanupCaptureSitesForOwner(entry.ownerId);
    // 撤销该插件注册的回调类条目（见 RemovePluginOwnedRegistrations）。
    RemovePluginOwnedRegistrations(entry.ownerId);
    ClearActivePluginContext();
    lifecycleLock.lock();
    const auto tracked = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&entry](const PluginEntry& candidate) {
            return candidate.handle == entry.handle &&
                   candidate.ownerId == entry.ownerId;
        });
    if (tracked != g_plugins.end()) g_plugins.erase(tracked);
    // FreeLibrary 必须在生命周期锁【之外】调用：插件 DllMain(DLL_PROCESS_DETACH) 可能
    // 反过来调 Loader，持锁卸载会让行为不可控，而且 FreeLibrary 本身可能阻塞。
    // freeModule=false（Global）时继续驻留：游戏线程可能仍在该插件的 detour/回调内
    // 执行（MH_DisableHook 不等待所有类型的在飞调用），此刻卸下映像会把正在执行的
    // 代码变成 UAF。驻留后钩已摘、补丁已回滚、Lua 方法/回调/OnMessage 已注销，映像
    // 休眠不会再被调用；代价是重启用时静态状态跨周期保留，OnLoad 必须可重入。
    lifecycleLock.unlock();
    if (freeModule) {
        // 释放时机见 g_pendingFreeModules 的说明：等引擎卸完 GameCore（连同 gamecore 的
        // gameplay/ui Lua 环境）之后才 FreeLibrary。
        QueueGameCoreModuleForFree(entry.handle);
        Logger::Log("Plugin deactivated, module queued for free after engine GameCore unload: %s",
            ModScan::WideToNarrow(entry.path).c_str());
    } else {
        Logger::Log("Plugin deactivated, module parked (kept mapped): %s",
            ModScan::WideToNarrow(entry.path).c_str());
    }
}

static const char* CategoryNameForLog(LoaderCore::PluginCategory cat) {
    return cat == LoaderCore::PluginCategory::GameCore ? "GameCore" : "Global";
}

void LoaderCore::LoadPluginsOf(PluginCategory cat) {
    const HMODULE anchor = LoaderCore::RuntimeModuleHandle();
    // 扫描（文件系统/sqlite）在锁外做，避免长时间阻塞卸载/reconcile 路径；
    // 单个插件的加载由 LoadSinglePlugin 在锁内原子完成。
    const auto wpaths = (cat == PluginCategory::GameCore)
        ? ModScan::FindGameCorePluginCandidates(anchor)
        : ModScan::FindGlobalPluginCandidates(anchor);
    Logger::Log("LoadPluginsOf(%s): %zu candidate(s)", CategoryNameForLog(cat), wpaths.size());
    for (const auto& wpath : wpaths) {
        LoadSinglePlugin(wpath);
    }
}

void LoaderCore::UnloadPluginsOf(PluginCategory cat) {
    std::vector<std::wstring> owners;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (const auto& entry : g_plugins) {
            if (entry.category == cat && entry.state == PluginState::Active) {
                owners.push_back(entry.ownerId);
            }
        }
    }
    for (const auto& owner : owners) {
        // 只有 GameCore 类别真正卸映像（Global 插件只在启动时加载，禁用需要重启）。
        UnloadPluginByOwnerId(owner, cat == PluginCategory::GameCore);
    }
    size_t remaining = 0;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        // 只数本类别剩下的条目：Global / 被隔离的条目不属于这次卸载的口径，
        // 混在一起报会让"remaining"看起来永远不为 0。
        for (const auto& entry : g_plugins) {
            if (entry.category == cat) ++remaining;
        }
    }
    Logger::Log("UnloadPluginsOf(%s): unloaded=%zu remaining-in-category=%zu",
        CategoryNameForLog(cat), owners.size(), remaining);
}

bool LoaderCore::LoadSinglePlugin(const std::wstring& path) {
    if (path.empty()) return false;
    const std::wstring norm = NormalizePluginPath(path);
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (const auto& entry : g_plugins) {
            if (NormalizePluginPath(entry.path) == norm) {
                Logger::Log("LoadSinglePlugin: already loaded %s", ModScan::WideToNarrow(path).c_str());
                return false;
            }
        }
    }
    const std::wstring filename = fs::path(path).filename().wstring();
    return LoadPluginDllInternal(path, ModScan::WideToNarrow(filename), CategoryForPath(path));
}

bool LoaderCore::InitializeGameCorePhase() {
    lock_guard<std::recursive_mutex> transitionLock(g_gameCoreTransitionMutex);
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    HMODULE gm = GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll");
    if (!gm) {
        Logger::Log("InitializeGameCorePhase: GameCore_XP2_FinalRelease.dll not loaded");
        return false;
    }
    if (!AttachGameCore(gm)) {
        Logger::Log("InitializeGameCorePhase: AttachGameCore failed");
        return false;
    }
    // 阶段 B 固定顺序：AttachGameCore（映像登记 + pdata 表 + 作用域记账）→ HavokScript 导入 →
    // 本地化导入 → 共享脚本钩重装（EnsureScriptHooksInstalled，见本函数末尾）→ 加载 GameCore 插件。
    // （历史步骤 InitializeLoader 已删除，见文件上方说明。）
    // HavokScript 导入缺失 = Lua API 半可用，对插件是崩溃源：停用 GameCore 插件
    // 加载（本会话游戏本体照常运行）。
    if (!hks::InitHavokScript()) {
        Logger::Log("InitializeGameCorePhase: InitHavokScript incomplete; GameCore plugins disabled");
        ImageAddress::DetachGameCore();
        return false;
    }
    Localization::InitScript();
    g_gameCorePhaseReady = true;
    // 共享脚本钩的 MinHook 记录随旧映像在 ResetForReload 里被摘除，这里按【当次】仍存在的
    // 注册项重装。首次进入时若 Global 插件已在阶段 A 注册过脚本全局，也在此一并装钩。
    EnsureScriptHooksInstalled();
    Logger::Log("InitializeGameCorePhase: OK");
    return true;
}

bool LoaderCore::IsInitialized() {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    return g_gameCorePhaseReady;
}

// ================= GameCore teardown：批量停用 + 物理摘除 =================
// 早期实现：跨 GameCore 代际靠「域代际计数器」在注册路径重建站点，MinHook 记录与跳板
// 一直驻留到进程退出。现在改为在 teardown 里趁旧映像还活着【物理摘钩】：
//   1) DisableGameCoreDomainSites()：一次 MH_ApplyQueued 批量还原 GameCore 域全部入口字节；
//   2) （Teardown 回调 / capture 清理 / GameCore 插件卸载之后）
//      RemoveGameCoreDomainSiteRecords()：按地址物理摘除 MinHook 记录（释放跳板）。
// 为什么第 1 步必须先于 GameCore 插件 FreeLibrary：入口字节还原之后就不会再有新调用
// 进入插件 detour；反过来先 FreeLibrary 就会留下「入口仍跳向已释放插件代码」的窗口。
// 覆盖面：GameCore 域内【全部已挂钩站点】——Loader 共享钩（ScriptData / ForUI /
// PushMethods）与插件 detour 一视同仁，且不看 owner。不在此收掉的话，新映像未打补丁、
// 钩子永久失效，PushMethods 槽位还会按重载次数泄漏（上限 16 个）。
// exe / 常驻模块域站点不受影响。共享脚本钩由 EnsureScriptHooksInstalled 在新 GameCore
// attach 后按【当次】仍存在的注册项重新装钩。

// 第 1 步：把「GameCore 域（当前已加载映像 或 正在拆除的区间）+ 已挂钩」的站点批量停用。
// 用 MH_QueueDisableHook + 【一次】 MH_ApplyQueued，而不是逐个 MH_DisableHook：
//   * QueueDisable 只置 queueEnable=FALSE、不碰目标内存，因而可以边遍历站点表边调用；
//   * ApplyQueued 内部用一次 Freeze(ALL_HOOKS_POS) 把这批入口字节一起还原，是一个批处理
//     事务：入口一还原，就不会再有新调用进入 stub / 插件 detour。
// 但 ApplyQueued 的内部循环遇到第一个 EnableHookLL 失败就 break（后面的记录不会被停用），
// 所以排队前必须把不可读的目标剔除——否则一个已卸载映像的坏目标会挡住整批。
// 不可读候选（映像在 LoadDLL 重入兜底路径里已经卸载）无法排进本批：给它打 recordStale，
// 下次在同一地址取站时强制重建记录（否则站点会一直以为钩还装着，永不重新挂钩）。
// 无返回值：第 2 步自己重扫站点表（见 RemoveGameCoreDomainSiteRecords 的说明），因此本批
// 不带地址列表，也就不会漏掉 teardown 期间才装上的钩。
static void DisableGameCoreDomainSites() {
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    const HookImageId gcId = ImageAddress::LoadedGameCore();
    size_t candidates = 0;
    size_t readable = 0;
    size_t unreadable = 0;
    size_t queued = 0;
    for (auto& [target, site] : g_hookSites) {
        if (!site.hookInstalled) continue;
        if (!ImageAddress::Contains(gcId, target) && !TargetInTearingDownGameCore(target)) {
            continue;
        }
        ++candidates;
        if (!Runtime::IsReadableSpan(target, 1)) {
            // 本批不能包含不可读目标（ApplyQueued 首败即 break）；标脏，等下次取站重建。
            ++unreadable;
            site.recordStale = true;
            continue;
        }
        ++readable;
        const MH_STATUS status = MH_QueueDisableHook(target);
        if (status == MH_OK) {
            ++queued;
        } else {
            // 排队失败只记日志：这一步本来就不会改写目标内存，第 2 步还会按地址再尝试
            // 物理摘除，并据结果决定是否打 recordStale。
            Logger::Log("DisableGameCoreDomainSites: MH_QueueDisableHook(%p) -> %s",
                target, MH_StatusToString(status));
        }
    }
    // 一次 ApplyQueued = 这一批入口字节在同一个 Freeze 事务里还原。
    const MH_STATUS applied = MH_ApplyQueued();
    Logger::Log("DisableGameCoreDomainSites: candidates=%zu readable=%zu queued=%zu unreadable=%zu "
                "applyQueued=%s",
        candidates, readable, queued, unreadable, MH_StatusToString(applied));
}

// 第 2 步：物理摘除 GameCore 域的站点记录（释放 MinHook 跳板），并复位共享钩状态。
// 骨架沿用被本步替换掉的共享钩复位函数（该函数已删除）：
//   1) 进入 teardown 窗口 + ImageAddress::DetachGameCore()（此后 Contains 不再命中，
//      域过滤只剩 teardown 窗口），释放生命周期锁排空 g_activeSharedDetours（已进入共享
//      detour 的调用先退出），再重新持生命周期锁；
//   2) 重扫站点表而不是沿用第 1 步的地址列表：第 1 步与本步之间还跑过 capture 清理与
//      插件卸载，注销路径理论上仍可能往正在拆除的映像上装新钩；重扫能把它一并收掉，
//      否则这条新记录会跨代残留。摘除失败（映像已卸载
//      -> MH_DisableHook 的 VirtualProtect 失败）时给站点打 recordStale 并拔掉 detour 槽，
//      避免下次误判「已装」；
//   3) 复位 g_orig* 与全部 PushMethods 槽位（与旧实现完全一致）。
// 本函数不做 capture 的【订阅清理】（拔插槽 + 排空）——那是 ResetForReload 里更早的
// CleanupAllCaptureSites() 与插件卸载路径 CleanupCaptureSitesForOwner 的职责；这里只清
// 站点复位时必须一并清掉的 capture 数据字段（hasCapture / retiring / captureOuts）。
static void RemoveGameCoreDomainSiteRecords(
        unique_lock<std::recursive_mutex>& lifecycleLock) {
    // 禁止新的 GameCore API 解析后释放生命周期锁，让已经进入 detour 的插件回调
    // 能正常调用 HookAPI 并退出；不能在持 lifecycle/hook 锁时等待。
    HookImageInfo current{ sizeof(HookImageInfo) };
    const HookImageId currentId = ImageAddress::LoadedGameCore();
    if (ImageAddress::GetInfo(currentId, &current)) {
        SetGameCoreTeardownWindow(current.base, static_cast<uint32_t>(current.imageSize));
    }
    ImageAddress::DetachGameCore();
    lifecycleLock.unlock();
    {
        unique_lock<mutex> drainLock(g_detourDrainMutex);
        g_detourDrainCv.wait(drainLock, [] {
            return g_activeSharedDetours.load(std::memory_order_acquire) == 0;
        });
    }
    lifecycleLock.lock();

    // 排空后才真正摘除站点记录（释放跳板）；顺序理由见 RemoveHookSiteRecordLocked。
    // teardown 窗口此刻仍是旧映像区间（DetachGameCore 已让 ImageAddress 的 Contains 失效），
    // 它以唯一判据回答「这个站点属不属于本次拆除的映像」。
    size_t reset = 0;
    size_t stale = 0;
    {
        lock_guard<mutex> hookLock(Runtime::MinHookMutex());
        for (auto it = g_hookSites.begin(); it != g_hookSites.end(); ) {
            if (!it->second.hookInstalled || !TargetInTearingDownGameCore(it->first)) {
                ++it;
                continue;
            }
            if (RemoveHookSiteRecordLocked(it->first, it->second)) {
                // 记录已摘、入口已还原。**节点不删**：stub 的机器码里用 imm64 永久内嵌了
                // &HookSite（见 BuildHookHubStub），而"已经没有调用者停在 stub 内"无法证明
                // （见 HookSite 顶部的硬约束注释）——erase 会让仍在 stub 里的线程读到已释放的 map 节点。
                // 这里把站点复位成"未挂钩、可重建"：stub 保留并复用，下次在同一地址取站时走
                // MH_CreateHook + MH_EnableHook 的正常重建路径（还会重拍前导字节副本）。
                HookSite& site = it->second;
                site.hookInstalled = false;      // RemoveHookSiteRecordLocked 已置，写出来当不变量
                site.minhookTrampoline = nullptr;
                site.activeDetour = nullptr;
                site.detourOwner.clear();
                // 不能置 nullptr：RemoveHookSiteRecordLocked 的 b 步已把 nextTarget 设为 target，
                // 好让仍停在 stub 里的在途调用者走原函数；这里覆盖成 nullptr 会让它们 jmp 0，
                // 而"没有调用者停在 stub 内"无法证明（见 HookSite 顶部硬约束）。保持 target。
                site.nextTarget = it->first;
                {
                    // 锁序恒为 MinHook -> capture（本循环外层已持 MinHook 锁）。
                    lock_guard<mutex> captureLock(g_captureMutex);
                    site.hasCapture = false;
                    site.retiring = false;
                    site.captureOuts.clear();
                }
                ++reset;
                ++it;
                continue;
            }
            // 摘除失败（目标不可写/不可读）：入口字节没能还原，MinHook 记录与跳板还在。
            // 打 recordStale 让下次在同一地址取站时强制重建；同时先拔掉 detour 槽，
            // 免得下次误判「已装」而拒绝重新挂钩。
            ++stale;
            it->second.recordStale = true;
            it->second.activeDetour = nullptr;
            it->second.detourOwner.clear();
            it->second.nextTarget = it->second.minhookTrampoline;
            ++it;
        }
    }

    g_origRegisterScriptData = nullptr;
    g_origRegisterScriptDataForUI = nullptr;
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (int i = 0; i < kMaxPushHooks; ++i) {
            g_noManagerSlots[i] = NoManagerHookSlot{};
            g_withManagerSlots[i] = WithManagerHookSlot{};
        }
    }
    // teardown 窗口【不在这里清】：它以"旧映像区间"为唯一判据，必须活到引擎真正换掉映像
    // 那一步 —— LoaderHooks 的两个 detour 调完原函数后调 ClearGameCoreTeardownWindow()。
    // 提前清会让"仍映射着的旧映像"重新对 Global 插件变成可钩的已加载模块。
    Logger::Log("RemoveGameCoreDomainSiteRecords: reset %zu site(s) in place (MinHook record + "
                "trampoline released; node kept: stubs embed &HookSite), marked recordStale=%zu; "
                "script/UI detour sites + push slots reset",
        reset, stale);
}

// teardown 窗口的清零点：由 LoaderHooks 的两个 detour 在引擎原函数返回之后调用。
// 见 §2.3 第 9 步：窗口必须在引擎 LoadDLL/UnloadDLL 真正换映像之后才失效。
void LoaderCore::ClearGameCoreTeardownWindow() {
    g_gameCoreTeardownAddress.store(0, std::memory_order_release);   // 读者见 0 即短路
    g_gameCoreTeardownSizeOfImage.store(0, std::memory_order_relaxed);
}

void LoaderCore::ResetForReload() {
    lock_guard<std::recursive_mutex> transitionLock(g_gameCoreTransitionMutex);
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    g_gameCorePhaseReady = false;
    // 先进入 teardown 窗口（InstallHook/Patch 对旧映像的目标从此被拒绝）。
    HookImageInfo current{ sizeof(HookImageInfo) };
    const HookImageId currentId = ImageAddress::LoadedGameCore();
    if (ImageAddress::GetInfo(currentId, &current)) {
        SetGameCoreTeardownWindow(current.base, static_cast<uint32_t>(current.imageSize));
    } else {
        SetGameCoreTeardownWindow(0, 0);
    }
    lifecycleLock.unlock();

    // 第 1 步（必须在 UnloadPluginsOf 之前）：趁旧映像仍映射，用一次 ApplyQueued 批量
    // 还原 GameCore 域全部入口字节。入口不再指向 stub / 插件 detour 之后，后续
    // FreeLibrary 才不会有「入口跳向已释放插件代码」的窗口。
    DisableGameCoreDomainSites();

    // capture 站点的目标位于旧 GameCore 映像内，重载后地址失效，必须随重载清空落在
    // GameCore 域内的捕获订阅；exe / 常驻模块域上的订阅保留。本步只拔插槽，站点记录
    // 由后面的 RemoveGameCoreDomainSiteRecords 物理摘除。
    CleanupAllCaptureSites();

    // UnloadPluginsOf 自身不触碰初始化标志，天然无递归。GameCore 类别的插件模块【不】在这里
    // FreeLibrary：入口字节已在上一步还原，但 gamecore 的 Lua 环境要等引擎自己的 UnloadDLL
    // 才拆，所以只把句柄排队（见 UnloadPluginByOwnerId 与 FreePendingPluginModules）。
    UnloadPluginsOf(PluginCategory::GameCore);

    lifecycleLock.lock();
    // 这里【不需要】补丁清账：唯一的补丁来源是插件的 PatchImpl，它已经过正面域规则
    // （GameCore 插件只能落在当前 GameCore 映像内且卸载时按 owner 回滚；Global 插件只能
    // 落在已加载的非 GameCore 模块内），所以拆映像时不可能存在落在旧映像区间里的记录。
    // 第 2 步：重扫站点表物理摘除 GameCore 域的 MinHook 记录（释放跳板），并复位共享钩状态
    // （ScriptData/ForUI + PushMethods 槽位）。顺序理由见函数头注释。
    RemoveGameCoreDomainSiteRecords(lifecycleLock);
    // GameEvent 是 GameCore 专属入口（注册记录挂在插件 owner 上，随 GameCore 插件卸载
    // 一并清除）；这里无需为旧代槽位做任何保留或重挂。
    Logger::Log("ResetForReload: GameCore plugins unloaded (modules queued for free after engine unload), entry bytes restored in batch, MinHook records physically removed");
}
