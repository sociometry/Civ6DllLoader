#include "pch.h"
#include "LoaderCore.h"
#include "PluginTableAccess.h"

#include <Windows.h>
#include <algorithm>
#include <filesystem>
#include <cwctype>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "Civ6DLLHookLoaderAPI.h"
#include "Civ6MessageBus.h"
#include "HookEngine.h"
#include "ImageAddress.h"
#include "LoaderUpdate.h"
#include "ModScan.h"
#include "PatchRegistry.h"
#include "PdataMatch.h"
#include "PluginBoundary.h"
#include "PluginDomain.h"
#include "PluginInFlight.h"
#include "Runtime.h"
#include "ScriptBridge.h"
#include "TeardownWindow.h"
#include "../common/EnabledMods.h"
#include "../common/Logger.h"

// 从 Civ6DLLHookLoaderAPI.cpp 拆出（阶段 6）：插件生命周期编排 + 映像查询。
//
// 本模块拥有（不导出）：
//   g_plugins（插件表）、g_pendingFreeMutex/g_pendingFreeModules（待释放队列）、
//   g_pluginLifecycleMutex、g_gameCoreTransitionMutex、
//   g_activePluginOwner/g_activePluginModule（thread_local owner 上下文）、
//   PluginState / PluginEntry 两个类型。
// 对外的只读查询经 PluginTableAccess.h 的两个门面（ResolveOwnerByModule /
// IsOwnerActive），生命周期锁经 LoaderCore::LifecycleMutex() —— 都不外泄变量。

using namespace std;

namespace fs = std::filesystem;

// 前置声明：OnLoad 失败时隔离该 owner 的全部注册（定义在文件后部）。
static void QuarantinePluginByOwner(const std::wstring& ownerId);

// 插件跟踪项：路径 + 句柄 + 名字(stem，仅作 OnMessage 寻址名) + ownerId(规范化完整小写路径，
// 作 Patch / hook / capture 的 owner) + 类别(Global/GameCore)。
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
    // 本代（本次加载）的在途登记对象，由 PluginInFlight::BeginLifetime 在加载时新建。
    // 必须按代持有而不是每次 Resolve(ownerId)：同一个插件重载后是同一个 ownerId，
    // 若沿用旧对象，上一代未退出的回调会计进新一代的计数（WaitAll 等错对象）。
    // 旧对象由 BeginLifetime 停用但【不删除】——锁外快照可能还握着它。
    PluginInFlight::Owner* inFlight = nullptr;
    // 类别 / ABI 版本在 OnLoad 之前就由插件的 Civ6PluginKind 导出判完（见 LoadPluginDllInternal），
    // 这里不再保存任何"插件自述"字段。
};
static vector<PluginEntry> g_plugins;


// GameCore 插件的【待释放】句柄队列。
// 为什么不在插件卸载处直接 FreeLibrary：那一刻 GameCore 映像还映射着，它承载的 gamecore
// Lua 环境（gameplay / ui）要到引擎自己的 UnloadDLL 里才拆；而 Lua 表里可能仍持有指向插件
// 映像的 C 闭包（PushLuaMethods 推入的、以及插件自己在 RegisterScriptGlobals 里注册的）。
// 等引擎把 GameCore 连同那些 Lua 环境一起拆完（g_origUnloadDLL 返回之后）再 Free，「闭包被
// 调用」这件事就不再可能发生。只由游戏线程（Load/UnloadPluginsOf）入队，flush 由
// LoaderHooks 的两个 detour 在调到原函数之后调用。
static std::mutex g_pendingFreeMutex;
static std::vector<HMODULE> g_pendingFreeModules;


// 插件生命周期互斥锁（递归：OnLoad/OnUnload 期间插件会再调用 HookAPI 注册入口，
// 需要重入）。保护 g_plugins 的全部读写，以及脚本全局 / PushMethods 槽位的【写】；
// 唯一写者是游戏线程（LoadDLL/UnloadDLL detour → Load/UnloadPluginsOf）。
// 热路径的【读】不取这把锁 —— detour 用各自的细粒度互斥量取快照
// （脚本全局走 g_scriptStateMutex、PushMethods 走 g_pushStateMutex）。
// Runtime::MinHookMutex（MinHook 调用 + owner 表）与 PatchRegistry 的
// CRITICAL_SECTION 保持独立，锁序恒为 lifecycle → hook/patch。
// [声明位置] 必须在 FreePendingPluginModules 之前：它在 FreeLibrary 之后要用它清悬垂句柄。
static std::recursive_mutex g_pluginLifecycleMutex;


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


// g_gameCorePhaseReady 已移到 ScriptBridge（阶段 4），经 IsGameCorePhaseReady() 读写。

// 插件导出入口的类型（LoadPluginDllInternal 按名取这些导出）。
typedef void (*OnLoadFunc)(const HookContext*);
typedef void (*OnUnloadFunc)();
typedef void (*OnMessageFunc)(const char*, const void*, size_t);

// ================= 函数实现 =================

// ==== SetPluginState ====
// 插件状态的唯一写入口：state 与 PluginInFlight 的放行镜像必须一起更新，
// 否则会出现"状态已停用、回调仍被放行"（或反之）的错位。
// 用 entry.inFlight（本代对象）而不是 Resolve(ownerId)：后者会在加载路径抢先建出
// 一个非本代的对象，使代际隔离失效。调用方必须保证 inFlight 已赋值。
static void SetPluginState(PluginEntry& entry, PluginState state) {
    entry.state = state;
    PluginInFlight::SetAllowed(entry.inFlight,
        state == PluginState::Loading || state == PluginState::Active);
}

// ==== QueueGameCoreModuleForFree ====
static void QueueGameCoreModuleForFree(HMODULE module) {
    if (!module) return;
    lock_guard<mutex> lock(g_pendingFreeMutex);
    g_pendingFreeModules.push_back(module);
}

// ==== LifecycleMutex ====
// 共享访问器（声明见 LoaderCore.h）：其它 TU 经它拿同一把锁。
// g_pluginLifecycleMutex 保持文件级 static，不做 extern 变量（§5 原则）。
std::recursive_mutex& LoaderCore::LifecycleMutex() {
    return g_pluginLifecycleMutex;
}

// ==== FreePendingPluginModules ====
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

// ==== SetActivePluginContext ====
static void SetActivePluginContext(const std::wstring& owner, HMODULE module) {
    g_activePluginOwner = owner;
    g_activePluginModule = module;
}

// ==== ClearActivePluginContext ====
static void ClearActivePluginContext() {
    g_activePluginOwner.clear();
    g_activePluginModule = nullptr;
}

// ==== NormalizePluginPath ====
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

// ==== CategoryForPath ====
// 按路径含 \Plugins\Global\（大小写不敏感）判类别；其余视为 GameCore。
static LoaderCore::PluginCategory CategoryForPath(const std::wstring& path) {
    return NormalizePluginPath(path).find(L"\\plugins\\global\\") != std::wstring::npos
        ? LoaderCore::PluginCategory::Global
        : LoaderCore::PluginCategory::GameCore;
}

// ==== KindToCategory ====
// Civ6PluginKind 导出低 32 位的 kind -> 插件类别。1=Global，2=GameCore；
// 3 预留给未来的 Frontend（未支持），其余一律未知 -> 拒载。
static bool KindToCategory(uint32_t kind, LoaderCore::PluginCategory& out) {
    if (kind == 1u) { out = LoaderCore::PluginCategory::Global; return true; }
    if (kind == 2u) { out = LoaderCore::PluginCategory::GameCore; return true; }
    return false;
}


// ==== IsOwnerActive ====
// ResolvePluginOwnerForAddress 要查插件表，而插件表归本文件（阶段 6 后归
// PluginRegistry.cpp）。按 REFACTOR_PLAN.md §5.2 把"查表"整体收进这个只读门面，
// 这样 g_plugins / g_activePluginOwner / g_activePluginModule 三个变量都不必外泄，
// PluginDomain 也不必看见 PluginEntry / PluginState 两个类型。
// 对应拆分前 PushLuaMethodsImpl 里的 find_if：判断该 owner 是否还活着。
// 原代码拿到迭代器后只与 end() 比较、从不解引用，故返回 bool 是精确替换。
bool PluginRegistry::IsOwnerActive(const std::wstring& ownerId) {
    const auto it = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&ownerId](const PluginEntry& entry) {
            return entry.ownerId == ownerId &&
                (entry.state == PluginState::Loading || entry.state == PluginState::Active);
        });
    return it != g_plugins.end();
}

// ==== ResolveOwnerByModule ====
std::optional<PluginDomain::CallerPluginInfo> PluginRegistry::ResolveOwnerByModule(HMODULE module) {
    if (!module) return std::nullopt;
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    for (const auto& entry : g_plugins) {
        if (entry.handle != module) continue;
        // 规则 1：当前活跃插件优先（且排除已隔离）
        if (!g_activePluginOwner.empty() && module == g_activePluginModule &&
                entry.ownerId == g_activePluginOwner &&
                entry.state != PluginState::Quarantined) {
            return PluginDomain::CallerPluginInfo{ entry.ownerId, entry.category };
        }
        // 规则 2：任意 Loading/Active 的同模块插件
        if ((entry.state == PluginState::Loading ||
                entry.state == PluginState::Active) &&
                entry.handle == module) {
            return PluginDomain::CallerPluginInfo{ entry.ownerId, entry.category };
        }
    }
    return std::nullopt;
}

// ==== RegisterPluginMessageHandler ====
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
        const auto callbackOwner = PluginDomain::ResolvePluginOwnerForAddress(reinterpret_cast<const void*>(handler));
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
    return GlobalBus().RegisterHandler(handlerName, handler, owner, [&owner] {
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
namespace PluginRegistry {


// ==== RegisterMessageHandlerImpl ====
bool RegisterMessageHandlerImpl(MessageHandlerFn handler) {
    if (!handler) return false;
    // 与其它回调 API 一样按 handler 所属模块确定 owner；返回地址会因尾调用
    // 优化落在 Loader/引擎内，不能用来可靠识别插件。
    const auto owner = PluginDomain::RequirePluginOwner(reinterpret_cast<const void*>(handler),
        "RegisterMessageHandler");
    return owner && RegisterPluginMessageHandler(owner->ownerId, handler);
}

}  // namespace PluginRegistry

namespace PluginRegistry {


// ==== IsImageLoadedImpl ====
bool IsImageLoadedImpl(HookImageId image) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    return ImageAddress::IsLoaded(image);
}

}  // namespace PluginRegistry

namespace PluginRegistry {


// ==== GetImageInfoImpl ====
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

}  // namespace PluginRegistry

namespace PluginRegistry {


// ==== HookPatch ====
__declspec(noinline) bool HookPatch(void* target, const void* bytes, size_t len) {
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
    if (PluginDomain::TargetInTearingDownGameCore(target)) return false;
    if (HookEngine::OverlapsHookPrologue(target, len)) {
        Logger::Log("Patch rejected: %p overlaps a hooked prologue window (%zu bytes); "
                    "InstallHook/Unpatch it first", target, HookEngine::kHookPrologueWindow);
        return false;
    }
    auto owner = PluginDomain::RequirePluginOwner(_ReturnAddress(), "Patch");
    if (!owner) return false;
    // 地址开放性门（整段）：GameCore 类别要求 [target, target+len) 全落在当前 GameCore 映像内；
    // Global 类别要求整段与 GameCore 映像不相交【且】整段落在同一个已加载的非 GameCore 模块内
    // （正面规则，完整表述见 IsRangeOpenToCaller 的注释）。
    if (!PluginDomain::IsRangeOpenToCaller(owner->category, target, len, "Patch")) return false;
    return PatchRegistry::Apply(target, bytesCopy.data(), len, owner->ownerId.c_str());
}

}  // namespace PluginRegistry

namespace PluginRegistry {


// ==== HookUnpatch ====
__declspec(noinline) bool HookUnpatch(void* target) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    auto owner = PluginDomain::RequirePluginOwner(_ReturnAddress(), "Unpatch");
    if (!owner) return false;
    // 地址开放性门：Patch 时已按整段校验过，这里只校验目标点
    // （PatchRegistry 没有现成的长度访问器，不为此改动别的文件）。
    if (!PluginDomain::IsTargetOpenToCaller(owner->category, target, "Unpatch")) return false;
    return PatchRegistry::RevertOwned(target, owner->ownerId.c_str());
}

}  // namespace PluginRegistry


// ==== GetModuleSizeOfImage ====
static DWORD GetModuleSizeOfImage(HMODULE module) {
    if (!module) return 0;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

// ==== AttachGameCore ====
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

// ==== CallOnLoadSafe ====
static bool CallOnLoadSafe(OnLoadFunc onLoad, const char* name) {
    __try {
        onLoad(LoaderCore::RuntimeHookContext());
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("OnLoad crashed in plugin %s code=0x%08X", name, GetExceptionCode());
        return false;
    }
}

// ==== CallOnUnloadSafe ====
static void CallOnUnloadSafe(OnUnloadFunc onUnload, const char* name) {
    __try {
        onUnload();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("OnUnload crashed in plugin %s code=0x%08X", name ? name : "?", GetExceptionCode());
    }
}

// ==== CallPluginKindSafe ====
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

// ==== LoadPluginDllInternal ====
// 统一插件加载流程：LoadLibraryExW + 类别/ABI 门禁(OnLoad 之前) + 记录跟踪项(Loading)
// + OnLoad(SEH) + OnMessage 自动注册 + 激活(Active)。
// 注意"记录跟踪项"必须在 OnLoad【之前】：插件在 OnLoad 里就可能经 HookAPI 注册钩子，
// 那些入口要靠 owner 探针在 g_plugins 里找到本模块，条目缺席会把自己全部拒掉。
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
            PluginDomain::CategoryNameForLog(category), ModScan::WideToNarrow(wpath).c_str());
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
    // 先建本代登记对象，再置状态：SetPluginState 要写 entry.inFlight 的放行镜像，
    // 顺序反了会作用在 nullptr 上（静默失效）。
    entry.inFlight = PluginInFlight::BeginLifetime(entry.ownerId);
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
        GlobalBus().UnregisterOwner(ownerId);
        return false;
    }
    SetPluginState(*activate, PluginState::Active);
    return true;
}

// ==== RemovePluginHooks ====
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
    HookEngine::RetireHookSiteDetoursForOwnerLocked(std::wstring(owner));
}

// ==== RemovePluginOwnedRegistrations ====
// 撤销某插件注册的全部回调类条目（禁用/隔离时调用）：脚本全局、PushMethods
// 方法/目标配置、GameEvent 槽位。这些条目都持有指向插件映像的函数指针，
// 不清就会在对应 detour / 触发点里调进已释放内存（与 OnMessage 悬空 handler
// 同类问题）。槽位的 methods 清空后保留已装 hook（detour 只透传 base）。
//
// 具体清理动作已收进 ScriptBridge::RemovePluginRegistrations（阶段 4）：那些条目
// 归 ScriptBridge 所有，收进门面后脚本全局表、槽位数组、槽位类型都不必外泄。
//
// 【日志格式必须逐字保持】：这行在基线日志里出现过，拆分后要逐条比对，
// 改动措辞或字段顺序都会被判成行为差异。故门面返回全部四个计数。
static void RemovePluginOwnedRegistrations(const std::wstring& owner) {
    if (owner.empty()) return;
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    const ScriptBridge::RemovedCounts n = ScriptBridge::RemovePluginRegistrations(owner);
    Logger::Log("RemovePluginOwnedRegistrations: owner=%ls globals=%zu globalsUI=%zu luaMethods=%zu targetConfigs=%zu",
        owner.c_str(), n.globals, n.globalsUI, n.luaMethods, n.targetConfigs);
}

// ==== QuarantinePluginByOwner ====
// 崩溃隔离（与 OnLoad 崩溃同构）：标记隔离 + 回滚该 owner 的全部注册
// （MinHook 钩/Lua 方法/脚本全局/GameEvent/OnMessage）。模块驻留不卸；
// 隔离后阶段 B 全量扫描不再重试（项目没有 reconcile 通路：状态变化要重启才生效）。
// 【不回滚补丁】：隔离的语义是"模块驻留、代码仍在内存里"，此刻往可能正被执行的代码里
// 写还原字节、又没有 quiesce，风险高于收益；补丁按"进程生命周期内不可撤销"处理，
// 要撤销由插件在 OnUnload 里自己调 Unpatch。见 ARCHITECTURE §5.8。
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
    GlobalBus().UnregisterOwner(ownerId);
    PluginInFlight::WaitAll(PluginInFlight::Resolve(ownerId), ownerId.c_str());
    RemovePluginHooks(ownerId.c_str());
    // 隔离路径也必须撤销参数捕获站点；否则站点仍会向插件的 out 槽写入数据。
    HookEngine::CleanupCaptureSitesForOwner(ownerId);
    RemovePluginOwnedRegistrations(ownerId);
    Logger::Log("Plugin quarantined by owner: %ls", ownerId.c_str());
}

// ==== UnloadPluginByOwnerId ====
// 按 ownerId 卸载单个插件（索引在函数内部按 ownerId 查）：
// OnUnload → RemovePluginHooks（拔槽，绝不在插件卸载时物理摘 MinHook 记录）→ 撤销 capture /
// 回调类注册 → 从 g_plugins 摘除 →（freeModule 时）句柄入队，等引擎卸完 GameCore 才 Free。
// freeModule 只由 GameCore 类别传 true：GameCore 插件随对局重载必须真正卸载，插件静态
// 状态才不会跨局残留；调用前 ResetForReload 已批量还原入口字节，不会再有人进入该插件的
// detour。Global 插件一律 false（只在启动时加载，禁用需要重启）；崩溃隔离路径根本不走
// 本函数，模块继续驻留。
//
// 【不回滚补丁】：需要撤销的插件应在 OnUnload 里自己调 Unpatch（那时它知道自己状态）。
// Loader 侧不再自动还原，见 ARCHITECTURE §5.8。
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
    GlobalBus().UnregisterOwner(entry.ownerId);
    // 脚本全局/GameEvent 入口使用快照并在锁外执行；先排空 owner 的在途调用，
    // 再进入 OnUnload，避免插件状态被释放后旧回调继续访问。
    PluginInFlight::WaitAll(PluginInFlight::Resolve(entry.ownerId), entry.ownerId.c_str());
    auto onUnload = (OnUnloadFunc)GetProcAddress(entry.handle, "OnUnload");
    SetActivePluginContext(entry.ownerId, entry.handle);
    if (onUnload) CallOnUnloadSafe(onUnload, nullptr);
    // 撤销该插件的 MinHook 钩子：否则 GameCore 重载后重新 OnLoad 会撞 MH_ERROR_ALREADY_CREATED。
    RemovePluginHooks(entry.ownerId.c_str());
    // 撤销该插件的参数捕获订阅；其它 owner 仍在使用的共享站点继续工作。
    HookEngine::CleanupCaptureSitesForOwner(entry.ownerId);
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
    // 生命周期锁【之外】做入队/放行决策：入队只碰 g_pendingFreeModules 自己的锁，
    // 且此处已不再调用 FreeLibrary —— 真正的 FreeLibrary 在引擎卸完 GameCore 之后由
    // FreePendingPluginModules 执行（见 g_pendingFreeModules 的说明）。
    // freeModule=false（Global）时继续驻留：游戏线程可能仍在该插件的 detour/回调内
    // 执行（MH_DisableHook 不等待所有类型的在飞调用），此刻卸下映像会把正在执行的
    // 代码变成 UAF。驻留后钩已摘、Lua 方法/回调/OnMessage 已注销，映像
    // 休眠不会再被调用；代价是重启用时静态状态跨周期保留，OnLoad 必须可重入。
    // 补丁不在上面这条清理链里：Loader 不替插件回滚，要撤销由插件在 OnUnload 里自己调
    // Unpatch（见本函数上方的【不回滚补丁】与 ARCHITECTURE §5.8）。
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

// ==== LoadPluginsOf ====
void LoaderCore::LoadPluginsOf(PluginCategory cat) {
    // 扫描（文件系统/sqlite）在锁外做，避免长时间阻塞卸载路径；
    // 单个插件的加载由 LoadSinglePlugin 驱动：去重与跟踪项写入持锁，而加载与回调阶段
    // （LoadLibraryExW / Civ6PluginKind / OnLoad / OnMessage）会主动放锁以防自死锁，
    // 因此"加载全程在锁内原子完成"并不成立。
    const auto wpaths = (cat == PluginCategory::GameCore)
        ? ModScan::FindGameCorePluginCandidates()
        : ModScan::FindGlobalPluginCandidates();
    Logger::Log("LoadPluginsOf(%s): %zu candidate(s)", PluginDomain::CategoryNameForLog(cat), wpaths.size());
    for (const auto& wpath : wpaths) {
        LoadSinglePlugin(wpath);
    }
}

// ==== UnloadPluginsOf ====
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
        PluginDomain::CategoryNameForLog(cat), owners.size(), remaining);
}

// ==== LoadSinglePlugin ====
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

// ==== InitializeGameCorePhase ====
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
    // 阶段 B 固定顺序：AttachGameCore（映像登记 + pdata 表 + 作用域记账）→ 共享脚本钩重装
    // （EnsureScriptHooksInstalled，见本函数末尾）→ 加载 GameCore 插件。
    // （历史步骤 InitializeLoader 已删除，见文件上方说明。）
    // HKS / Localization 的导入不在这里做：它们是进程级静态导入，已在阶段 A
    // （WorkerMain）解析完成，缺失只降级各自的 API，不影响本阶段成败。
    ScriptBridge::SetGameCorePhaseReady(true);
    // 共享脚本钩的 MinHook 记录随旧映像在 ResetForReload 里被摘除，这里按【当次】仍存在的
    // 注册项重装。首次进入时若 Global 插件已在阶段 A 注册过脚本全局，也在此一并装钩。
    ScriptBridge::EnsureScriptHooksInstalled();
    Logger::Log("InitializeGameCorePhase: OK");
    return true;
}

// ==== IsInitialized ====
bool LoaderCore::IsInitialized() {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    return ScriptBridge::IsGameCorePhaseReady();
}


// ==== ResetForReload ====
void LoaderCore::ResetForReload() {
    lock_guard<std::recursive_mutex> transitionLock(g_gameCoreTransitionMutex);
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    ScriptBridge::SetGameCorePhaseReady(false);
    // 先进入 teardown 窗口（InstallHook/Patch 对旧映像的目标从此被拒绝）。
    HookImageInfo current{ sizeof(HookImageInfo) };
    const HookImageId currentId = ImageAddress::LoadedGameCore();
    if (ImageAddress::GetInfo(currentId, &current)) {
        LoaderCore::Teardown::SetWindow(current.base, static_cast<uint32_t>(current.imageSize));
    } else {
        LoaderCore::Teardown::SetWindow(0, 0);
    }
    lifecycleLock.unlock();

    // 第 1 步（必须在 UnloadPluginsOf 之前）：趁旧映像仍映射，用一次 ApplyQueued 批量
    // 还原 GameCore 域全部入口字节。入口不再指向 stub / 插件 detour 之后，后续
    // FreeLibrary 才不会有「入口跳向已释放插件代码」的窗口。
    HookEngine::DisableGameCoreDomainSites();

    // capture 站点的目标位于旧 GameCore 映像内，重载后地址失效，必须随重载清空落在
    // GameCore 域内的捕获订阅；exe / 常驻模块域上的订阅保留。本步只拔插槽，站点记录
    // 由后面的 HookEngine::RemoveGameCoreDomainSiteRecords 物理摘除。
    HookEngine::CleanupAllCaptureSites();

    // UnloadPluginsOf 自身不触碰初始化标志，天然无递归。GameCore 类别的插件模块【不】在这里
    // FreeLibrary：入口字节已在上一步还原，但 gamecore 的 Lua 环境要等引擎自己的 UnloadDLL
    // 才拆，所以只把句柄排队（见 UnloadPluginByOwnerId 与 FreePendingPluginModules）。
    UnloadPluginsOf(PluginCategory::GameCore);

    lifecycleLock.lock();
    // 这里【不做】补丁清账 —— 是设计决定而非"不可能有记录"：Loader 已删除补丁自动回滚
    // （见【不回滚补丁】与 ARCHITECTURE §5.8），补丁记录只在插件自己调 Unpatch 时才从
    // PatchRegistry 摘除。副作用是【未撤销的补丁记录会跨代存活】：GameCore 插件若没调
    // Unpatch，它那条落在旧映像区间里的记录会留到进程退出；新一代 GameCore 映射到同一基址
    // 时，这条陈旧记录仍会参与 OverlapsRegistered / OverlapsHookPrologue 的区间仲裁。
    // 第 2 步：重扫站点表物理摘除 GameCore 域的 MinHook 记录（释放跳板），并复位共享钩状态
    // （ScriptData/ForUI + PushMethods 槽位）。顺序理由见函数头注释。
    HookEngine::RemoveGameCoreDomainSiteRecords(lifecycleLock);
    // GameEvent 是 GameCore 专属入口（注册记录挂在插件 owner 上，随 GameCore 插件卸载
    // 一并清除）；这里无需为旧代槽位做任何保留或重挂。
    Logger::Log("ResetForReload: GameCore plugins unloaded (modules queued for free after engine unload), entry bytes restored in batch, MinHook records physically removed");
}


// ================= GameCore teardown：批量停用 + 物理摘除 =================
// 早期实现：跨 GameCore 代际靠「域代际计数器」在注册路径重建站点，MinHook 记录与跳板
// 一直驻留到进程退出。现在改为在 teardown 里趁旧映像还活着【物理摘钩】：
//   1) HookEngine::DisableGameCoreDomainSites()：一次 MH_ApplyQueued 批量还原 GameCore 域全部入口字节；
//   2) （capture 清理 / GameCore 插件卸载之后）
//      HookEngine::RemoveGameCoreDomainSiteRecords()：按地址物理摘除 MinHook 记录（释放跳板）。
// 为什么第 1 步必须先于 GameCore 插件 FreeLibrary：入口字节还原之后就不会再有新调用
// 进入插件 detour；反过来先 FreeLibrary 就会留下「入口仍跳向已释放插件代码」的窗口。
// 覆盖面：GameCore 域内【全部已挂钩站点】——Loader 共享钩（ScriptData / ForUI /
// PushMethods）与插件 detour 一视同仁，且不看 owner。不在此收掉的话，新映像未打补丁、
// 钩子永久失效，PushMethods 槽位还会按重载次数泄漏（上限 16 个）。
// exe / 常驻模块域站点不受影响。共享脚本钩由 EnsureScriptHooksInstalled 在新 GameCore
// attach 后按【当次】仍存在的注册项重新装钩。


// teardown 窗口的清零点：由 LoaderHooks 的两个 detour 在引擎原函数返回之后调用。
// 见 §2.3 第 9 步：窗口必须在引擎 LoadDLL/UnloadDLL 真正换映像之后才失效。

