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
#include "SymbolResolve.h"   // 阶段 1 拆出的地址解析（*Core / 符号库状态查询）
#include "TeardownWindow.h"  // 阶段 3a：teardown 窗口的共享存储（跨 TU 必须同一份）
#include "PluginDomain.h"      // 阶段 2：域规则 / 调用方鉴权
#include "PluginTableAccess.h" // 阶段 2：插件表只读门面（PluginRegistry::ResolveOwnerByModule）
namespace fs = std::filesystem;

#include "ScriptBridge.h"      // 阶段 4：Lua / GameEvent / 脚本注册 / PushMethods
#include "HookEngine.h"        // 阶段 4/5：InstallLoaderDetourOnSite

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

// 插件状态的唯一写入口：state 与 PluginInFlight 的放行镜像必须一起更新，
// 否则会出现"状态已停用、回调仍被放行"（或反之）的错位。
// 用 entry.inFlight（本代对象）而不是 Resolve(ownerId)：后者会在加载路径抢先建出
// 一个非本代的对象，使代际隔离失效。调用方必须保证 inFlight 已赋值。
static void SetPluginState(PluginEntry& entry, PluginState state) {
    entry.state = state;
    PluginInFlight::SetAllowed(entry.inFlight,
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
// 需要重入）。保护 g_plugins 的全部读写，以及脚本全局 / PushMethods 槽位的【写】；
// 唯一写者是游戏线程（LoadDLL/UnloadDLL detour → Load/UnloadPluginsOf）。
// 热路径的【读】不取这把锁 —— detour 用各自的细粒度互斥量取快照
// （脚本全局走 g_scriptStateMutex、PushMethods 走 g_pushStateMutex）。
// Runtime::MinHookMutex（MinHook 调用 + owner 表）与 PatchRegistry 的
// CRITICAL_SECTION 保持独立，锁序恒为 lifecycle → hook/patch。
// [声明位置] 必须在 FreePendingPluginModules 之前：它在 FreeLibrary 之后要用它清悬垂句柄。
static std::recursive_mutex g_pluginLifecycleMutex;

// 共享访问器（声明见 LoaderCore.h）：其它 TU 经它拿同一把锁。
// g_pluginLifecycleMutex 保持文件级 static，不做 extern 变量（§5 原则）。
std::recursive_mutex& LoaderCore::LifecycleMutex() {
    return g_pluginLifecycleMutex;
}

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
//
// 存储与两个 setter 已移到 TeardownWindow.h（阶段 3a）：HookEngine 与 PluginDomain
// 分属不同 TU，若各自留一份 static 就会静默失效。这里只保留母体内沿用的名字。
static void SetGameCoreTeardownWindow(uintptr_t base, uint32_t sizeOfImage) {
    LoaderCore::Teardown::SetWindow(base, sizeOfImage);
}

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


// 地址开放性门的规则说明见 PluginDomain.h（实现已迁至 PluginDomain.cpp）。


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
bool HookEngine::InstallLoaderDetourOnSite(void* target, void* detour, void** origSlot, const char* why) {
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
    if (PluginDomain::TargetInTearingDownGameCore(target)) {
        Logger::Log("InstallHook rejected: target %p belongs to tearing-down GameCore", target);
        return false;
    }
    auto owner = PluginDomain::RequirePluginOwner(detour, "InstallHook");
    if (!owner) return false;
    // 地址开放性门：调用方类别 × 目标地址域。此门取代原先那条"Global owner 必须先登记
    // GameCore teardown 回调"的门槛——域门之后 Global 已不可能指向当前 GameCore，那段判断
    // 永远不可达，相关登记机制随之整体删除。
    if (!PluginDomain::IsTargetOpenToCaller(owner->category, target, "InstallHook")) return false;

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

bool RegisterMessageHandlerImpl(MessageHandlerFn handler) {
    if (!handler) return false;
    // 与其它回调 API 一样按 handler 所属模块确定 owner；返回地址会因尾调用
    // 优化落在 Loader/引擎内，不能用来可靠识别插件。
    const auto owner = PluginDomain::RequirePluginOwner(reinterpret_cast<const void*>(handler),
        "RegisterMessageHandler");
    return owner && RegisterPluginMessageHandler(owner->ownerId, handler);
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


// 插件入口：参数全是标量（没有需要锁外抄写的插件内存），只需加锁。
void* ResolveByRvaImpl(HookImageId image, uintptr_t rva, size_t span) {
    // 地址开放性门：调用方类别 × 解析目标映像域（本入口没有 loader 内部调用者，内部走 *Core）。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByRva");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByRva")) return nullptr;
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    return SymbolResolve::ResolveByRvaCore(image, rva, span);
}


void* ResolveByNameImpl(HookImageId image, const char* name) {
    // 地址开放性门（RequirePluginOwner 只做模块归属查询，不解引用插件指针）。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByName");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByName")) return nullptr;
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
    return SymbolResolve::ResolveByNameCore(image, nameCopy.c_str());
}

void* ResolveByRvaExImpl(HookImageId image, uintptr_t rva, size_t span, HookImageSection section) {
    // 地址开放性门：调用方类别 × 解析目标映像域。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByRvaEx");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByRvaEx")) return nullptr;
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
    if (!SymbolResolve::ResolveSectionRva(image, sectionName, &sectionRva, &sectionSize)) {
        Logger::Log("ResolveByRvaEx: section %s not found image=%u",
            sectionName, static_cast<unsigned>(image));
        return nullptr;
    }
    return ImageAddress::ResolveByRva(image, sectionRva + rva, span);
}


void* ResolveByPatternImpl(HookImageId image, const char* patternIn, HookImageSection section,
    uint32_t index) {
    // 地址开放性门（RequirePluginOwner 只做模块归属查询，不解引用插件指针）。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByPattern");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByPattern")) return nullptr;
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
    return SymbolResolve::ResolveByPatternCore(image, patternCopy.c_str(), section, index);
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
    if (PluginDomain::TargetInTearingDownGameCore(providerAddress)) {
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
    auto owner = PluginDomain::RequirePluginOwner(reinterpret_cast<const void*>(out), "RegisterGlobalCapture");
    if (!owner) return false;
    // 地址开放性门：capture 现在是"取地址型"入口（providerAddress 由插件自己解析后传入），
    // 因此统一按地址开放性口径判：GameCore 类别 -> 目标须在当前 GameCore 映像内；Global
    // 类别 -> 目标须落在【某个已加载的非 GameCore 模块】内（正面规则，见 IsTargetOpenToCaller）。
    // 原先"调用方类别必须是 GameCore"那道特例门随之删除：它要防的悬垂已由本门 +
    // CleanupAllCaptureSites 的 GameCore 域过滤共同覆盖，而 Global 插件挂在常驻模块上的
    // capture 不再被误拒。
    if (!PluginDomain::IsTargetOpenToCaller(owner->category, providerAddress, "RegisterGlobalCapture")) return false;
    return RegisterGlobalCaptureCore(providerAddress, paramIndex, out, owner->ownerId);
}


void* ResolveByVTableImpl(HookImageId image, const char* vtableSymbolIn, uint32_t index) {
    // 地址开放性门（RequirePluginOwner 只做模块归属查询，不解引用插件指针）。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByVTable");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByVTable")) return nullptr;
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
    return SymbolResolve::ResolveByVTableCore(image, symbolCopy.c_str(), index);
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
// 全程存活，只在进程退出时随静态对象回收。本段锁序与注册路径一致（MinHook -> capture）：
// 站点表结构由 MinHook 站点锁保护，capture 字段是它内层的派发侧数据，两把锁都取、
// 顺序恒定，因此不会与注册路径成环。
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
// 插件可见入口：只对 GameCore 类别插件开放（调用方由返回地址反查）。
#pragma intrinsic(_ReturnAddress)


}  // namespace


// 手动触发一次：查找注册记录，仅 Lua 路径（内化）。未注册或 luaPushFn 为 null → false。
// 查到记录后先取 owner 在途守卫（PluginInFlight::Enter）——插件卸载/隔离期间拒绝触发，
// 避免在途调用踩到已回滚的注册（与远程对引擎桥路径的加固同款）。
#pragma intrinsic(_ReturnAddress)




namespace {

}  // namespace

// 前置声明（定义于本文件后部）：OnLoad 失败时隔离该 owner 的全部注册。
// （未声明插件类别的模块在 OnLoad 之前就被拒载；消息回调崩溃由 Civ6MessageBus 的 SEH
// 兜住并只记日志——两者都不走隔离。）
static void QuarantinePluginByOwner(const std::wstring& ownerId);


namespace {


}  // namespace




// ---------------- HookAPI v2 ----------------





// ---------------- 符号库状态查询（GetSymbolDbState / GetSymbolDbMatchRatio） ----------------
// 纯查询：不取插件生命周期锁，也不碰插件表——状态来自 PdataMatch 自己的快照锁。
// image 是标量，没有跨模块指针可解引用，因此不需要 RequirePluginOwner / 域门。


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
    if (PluginDomain::TargetInTearingDownGameCore(target)) return false;
    if (OverlapsHookPrologue(target, len)) {
        Logger::Log("Patch rejected: %p overlaps a hooked prologue window (%zu bytes); "
                    "InstallHook/Unpatch it first", target, kHookPrologueWindow);
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

__declspec(noinline) static bool HookUnpatch(void* target) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    PluginBoundary::LoaderLockScope pbLockScope;
    auto owner = PluginDomain::RequirePluginOwner(_ReturnAddress(), "Unpatch");
    if (!owner) return false;
    // 地址开放性门：Patch 时已按整段校验过，这里只校验目标点
    // （PatchRegistry 没有现成的长度访问器，不为此改动别的文件）。
    if (!PluginDomain::IsTargetOpenToCaller(owner->category, target, "Unpatch")) return false;
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

    &ScriptBridge::PushLuaMethodsImpl,

    &ScriptBridge::RegisterScriptGlobalsImpl,
    &ScriptBridge::RegisterScriptGlobalsForUIImpl,

    &ScriptBridge::LuaPushNamedCClosureImpl,
    &ScriptBridge::LuaCheckIntegerImpl,
    &ScriptBridge::LuaCheckNumberImpl,
    &ScriptBridge::LuaSetFieldImpl,
    &ScriptBridge::LuaGetTopImpl,
    &ScriptBridge::LuaDoStringImpl,
    &ScriptBridge::LuaToBooleanImpl,
    &ScriptBridge::LuaPushNumberImpl,
    &ScriptBridge::LuaPushIntegerImpl,
    &ScriptBridge::LuaErrorImpl,
    &ScriptBridge::LuaPushFStringImpl,
    &ScriptBridge::LuaCheckLStringImpl,
    &ScriptBridge::LuaToUserDataImpl,
    &ScriptBridge::LuaGetFieldImpl,
    &ScriptBridge::LuaPopImpl,
    &ScriptBridge::LuaCreateTableImpl,
    &ScriptBridge::LuaToCFunctionImpl,
    &ScriptBridge::LuaCheckTableImpl,
    &ScriptBridge::LuaObjLenImpl,
    &ScriptBridge::LuaGetTableImpl,
    &ScriptBridge::LuaCPcallImpl,
    &ScriptBridge::LuaRefImpl,
    &ScriptBridge::LuaPcallImpl,
    &ScriptBridge::LuaPushValueImpl,
    &ScriptBridge::LuaRawGetIImpl,
    &ScriptBridge::LuaUnrefImpl,
    &ScriptBridge::LuaSetTableImpl,
    &ScriptBridge::LuaIsNumberImpl,
    &ScriptBridge::LuaToNumberImpl,
    &ScriptBridge::LuaIsUserDataImpl,
    &ScriptBridge::LuaOpenDebugImpl,
    &ScriptBridge::LuaToIntegerImpl,
    &ScriptBridge::LuaTypeImpl,
    &ScriptBridge::LuaOptIntegerImpl,
    &ScriptBridge::LuaSetHookImpl,
    &ScriptBridge::LuaGetHookImpl,
    &ScriptBridge::LuaGetHookMaskImpl,
    &ScriptBridge::LuaGetHookCountImpl,
    &ScriptBridge::LuaCheckPlayerIdImpl,
    &ScriptBridge::LuaPushBooleanImpl,
    &ScriptBridge::LuaPushLightUserDataImpl,

    &ScriptBridge::LogImpl,
    &ScriptBridge::LuaPushCFunctionFieldImpl,
    &ScriptBridge::LuaNewGlobalTableImpl,

    &ScriptBridge::LocalizationLookupImpl,

    &ScriptBridge::LocStringBytesImpl,
    &ScriptBridge::LocCreateImpl,
    &ScriptBridge::LocDestroyImpl,
    &ScriptBridge::LocLookupImpl,
    &ScriptBridge::LocPushArgumentImpl,
    &ScriptBridge::LocToUtf8Impl,

    &ScriptBridge::EditPlayerImpl,
    &ScriptBridge::MakeHashImpl,

    &ScriptBridge::RegisterPushMethodsTargetImpl,

    &HookPatch,
    &HookUnpatch,

    &ScriptBridge::RegisterGameEventImpl,
    &ScriptBridge::TriggerGameEventImpl,

    &ScriptBridge::GetEngineUtilityImpl,
    &ScriptBridge::GetMainLuaStateImpl,
    &ScriptBridge::LuaPushNilImpl,
    &SymbolResolve::GetSymbolDbStateImpl,
    &SymbolResolve::GetSymbolDbMatchRatioImpl,
};

// 编译期守卫（配套 common/HookAPI.h 的 CIV6_HOOK_API_ENTRY_COUNT）：
//  1) sizeof 抓住"往 HookAPI 追加了字段，却没同步计数/初始化表"；
//  2) 末尾字段的偏移抓住"重排或删除字段"（冻结前缀只允许尾部追加）。
static_assert(sizeof(HookAPI) == sizeof(uint32_t) * 2 + CIV6_HOOK_API_ENTRY_COUNT * sizeof(void*),
    "HookAPI 字段数与 CIV6_HOOK_API_ENTRY_COUNT 不一致：追加字段后必须同步更新计数并补齐 g_hookApi");
static_assert(offsetof(HookAPI, GetSymbolDbMatchRatio) ==
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
    CleanupCaptureSitesForOwner(ownerId);
    RemovePluginOwnedRegistrations(ownerId);
    Logger::Log("Plugin quarantined by owner: %ls", ownerId.c_str());
}

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
    // 阶段 B 固定顺序：AttachGameCore（映像登记 + pdata 表 + 作用域记账）→ 共享脚本钩重装
    // （EnsureScriptHooksInstalled，见本函数末尾）→ 加载 GameCore 插件。
    // （历史步骤 InitializeLoader 已删除，见文件上方说明。）
    // HKS / Localization 的导入不在这里做：它们是进程级静态导入，已在阶段 A
    // （WorkerMain）解析完成，缺失只降级各自的 API，不影响本阶段成败。
    g_gameCorePhaseReady = true;
    // 共享脚本钩的 MinHook 记录随旧映像在 ResetForReload 里被摘除，这里按【当次】仍存在的
    // 注册项重装。首次进入时若 Global 插件已在阶段 A 注册过脚本全局，也在此一并装钩。
    ScriptBridge::EnsureScriptHooksInstalled();
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
//   2) （capture 清理 / GameCore 插件卸载之后）
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
        if (!ImageAddress::Contains(gcId, target) && !PluginDomain::TargetInTearingDownGameCore(target)) {
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
    // 排空在途共享 detour：计数与等待原语归 ScriptBridge 私有（阶段 4）。
    // 不能在持 lifecycle/hook 锁时等待 —— 已在此前 unlock。
    ScriptBridge::WaitForDetourDrain();
    lifecycleLock.lock();

    // 排空后才真正摘除站点记录（释放跳板）；顺序理由见 RemoveHookSiteRecordLocked。
    // teardown 窗口此刻仍是旧映像区间（DetachGameCore 已让 ImageAddress 的 Contains 失效），
    // 它以唯一判据回答「这个站点属不属于本次拆除的映像」。
    size_t reset = 0;
    size_t stale = 0;
    {
        lock_guard<mutex> hookLock(Runtime::MinHookMutex());
        for (auto it = g_hookSites.begin(); it != g_hookSites.end(); ) {
            if (!it->second.hookInstalled || !PluginDomain::TargetInTearingDownGameCore(it->first)) {
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

    // 共享钩状态复位（g_orig* ×2 + 全部 PushMethods 槽位）：这些对象归 ScriptBridge，
    // 收进门面后本文件不必看见槽位数组、槽位类型与那把锁（阶段 4）。
    ScriptBridge::ResetForTeardown();
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
    LoaderCore::Teardown::ClearWindow();
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
    // 这里【不做】补丁清账 —— 是设计决定而非"不可能有记录"：Loader 已删除补丁自动回滚
    // （见【不回滚补丁】与 ARCHITECTURE §5.8），补丁记录只在插件自己调 Unpatch 时才从
    // PatchRegistry 摘除。副作用是【未撤销的补丁记录会跨代存活】：GameCore 插件若没调
    // Unpatch，它那条落在旧映像区间里的记录会留到进程退出；新一代 GameCore 映射到同一基址
    // 时，这条陈旧记录仍会参与 OverlapsRegistered / OverlapsHookPrologue 的区间仲裁。
    // 第 2 步：重扫站点表物理摘除 GameCore 域的 MinHook 记录（释放跳板），并复位共享钩状态
    // （ScriptData/ForUI + PushMethods 槽位）。顺序理由见函数头注释。
    RemoveGameCoreDomainSiteRecords(lifecycleLock);
    // GameEvent 是 GameCore 专属入口（注册记录挂在插件 owner 上，随 GameCore 插件卸载
    // 一并清除）；这里无需为旧代槽位做任何保留或重挂。
    Logger::Log("ResetForReload: GameCore plugins unloaded (modules queued for free after engine unload), entry bytes restored in batch, MinHook records physically removed");
}
