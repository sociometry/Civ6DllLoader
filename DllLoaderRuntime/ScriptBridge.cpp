#include "pch.h"
#include "ScriptBridge.h"

#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdarg>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "Civ6DLLHookLoaderAPI.h"   // PushMethodSigType / PushMethods*Func / StoredLuaMethod
#include "Civ6MessageBus.h"
#include "HavokScript.h"
#include "ImageAddress.h"
#include "Localization.h"
#include "PatchRegistry.h"
#include "PdataMatch.h"
#include "PluginBoundary.h"
#include "PluginDomain.h"
#include "PluginInFlight.h"
#include "PluginTableAccess.h"
#include "ProxyTypes.h"
#include "Runtime.h"
#include "AddressResolve.h"
#include "TeardownWindow.h"
#include "HookEngine.h"        // InstallLoaderDetourOnSite
#include "../common/Logger.h"
#include "../common/ModScan.h"

// 从 Civ6DLLHookLoaderAPI.cpp 拆出（阶段 4）：Lua / GameEvent / 脚本注册 / PushMethods 槽位。
//
// 本文件里的状态（见下方各块）原属母体，现随模块私有化：
//   PushMethods 目标配置表、脚本/PushMethods 锁、detour 排空计数与等待原语、
//   GameEvent 常量与状态表、脚本全局注册表与两个跳板、PushMethods 槽位与 detour 表。
// 需要跨模块访问的部分（脚本全局表、槽位数组、g_orig*、排空计数）一律走
// ScriptBridge.h 里的门面，不再外泄变量。
//
// static 取舍：函数体中原来带 static 的 ABI 入口全部去掉 static（母体的 g_hookApi
// 取它们地址）；模块内部辅助保持 static。

using namespace std;

namespace ScriptBridge {

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

// ---- GameEvent 引擎 ABI 常量 ----
// exe: ScriptSystem::CallHook 内的单例读取序列（mov rax,cs:singleton; mov rcx,[rax+10h]; jmp）
// ——AOB 自锚定，避免硬编码 RVA 的版本脆性。
constexpr const char* kLuaSingletonPattern =
    "48 8B 05 ?? ?? ?? ?? 48 8B 48 10 E9";
void* g_mainLuaStateHit = nullptr;   // AOB 命中缓存（Contains 校验，跨代自动重扫）
constexpr size_t   kGameEventNameMax           = 96;    // 事件名副本容量（注册表）

// ms_pkCurrentGame 定位 pattern（GameSignals::Subscribe 开头 mov rdi, cs:ms_pkCurrentGame
// 序列；读命中+3 的 disp32，目标槽 = 命中+7+disp32）。GetCurrentGameSlot 用它解析
// ms_pkCurrentGame 槽（GetEngineUtilityCore 读 +0x18 取 EngineUtility）。
constexpr char kGameEventCurrentGamePattern[] =
    "48 8B 3D ?? ?? ?? ?? 48 85 FF 0F 84 ?? ?? ?? ?? 48 8B BF 80 02 00 00";
// GameSignals::Subscribe 内 "mov rdi, cs:ms_pkCurrentGame" 指令地址（按代缓存，重扫兜底）。
static void* g_gameEventContainerHit = nullptr;

// ---- 引擎侧"Modding"脚本库注册入口 ----
// AppLuaModdingLibrary::pRegister(lua_State*)：建一张新表 -> 57 个 hks 闭包逐个 setfield ->
// return 1（表留在栈上）。调用方 AppLuaUtils::ExposeLibraryToThread(L, thread, "Modding", pRegister)
// 负责把它挂成全局 "Modding"。IDA 实测：DX11 RVA 0x4D0D70、DX12 RVA 0x4D15F0，两版函数大小
// 都是 0xA9E；下面这条函数头签名在同批 Lua 库注册函数里各命中 12 处，pRegister 是第 10 个
// （两版顺序一致，已用两个 exe 的实际字节逐一核对）。
constexpr char kAob_ModdingRegister[] =
    "48 89 5C 24 08 57 48 83 EC 30 45 33 C0 33 D2 48 8B D9 E8 ?? ?? ?? ?? 33 FF 4C 8D 0D";
constexpr HookInfoExe kExeModdingRegister = {
    HookRva(0x4D0D70, kAob_ModdingRegister, 10),
    HookRva(0x4D15F0, kAob_ModdingRegister, 10)
};

typedef int64_t(__fastcall* ModdingRegisterFn)(void* L);
static ModdingRegisterFn g_origModdingRegister = nullptr;

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

// 脚本全局注册项：owner = 注册时活跃插件名（空 = Loader 自身，插件卸载不撤销）。
// fn 指向插件映像内代码，插件卸载时必须移除，否则 RegisterScriptData detour
// 会调进已 FreeLibrary 的内存（与 OnMessage 悬空 handler 同类问题）。
struct ScriptGlobalsEntry {
    std::wstring owner;
    ScriptGlobalsFn fn;
    // 登记时解析一次并常驻：运行时守卫不再做宽字符串哈希。
    PluginInFlight::Owner* inFlight = nullptr;
    // 全局脚本专用：该项已经跑到过哪个主 lua_State 上。同一个 state 只跑一次，
    // state 被重建（指针变化）后重新跑。GameCore 侧两个列表不使用这个字段。
    void* appliedFor = nullptr;
};

std::vector<ScriptGlobalsEntry> g_scriptGlobals;
std::vector<ScriptGlobalsEntry> g_scriptGlobalsUI;
// 引擎主 state（进程级）上的全局脚本登记。与上面两个列表的区别见 RegisterGlobalScriptImpl。
std::vector<ScriptGlobalsEntry> g_globalScriptGlobals;
ProxyTypes::RegisterScriptData g_origRegisterScriptData = nullptr;
ProxyTypes::RegisterScriptDataForUI g_origRegisterScriptDataForUI = nullptr;
// 上述两个跳板由统一站点的 MH_CreateHook 回填（尾跳原函数），detour 用它们调原实现；
// 站点在 GameCore teardown 物理摘除（RemoveGameCoreDomainSiteRecords）时随记录一并清空。
// 是否已挂钩不再需要标志：
// 站点表本身就是唯一账本，重复安装幂等。

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

// 阶段 B 就绪标志的前置声明（定义在文件末尾的门面段）。
bool IsGameCorePhaseReady();

// detour 模板的前置声明：两张函数指针表（紧随槽位数组）取它们的地址触发隐式实例化，
// 而模板定义在函数实现段（文件后部）。前置声明让表能先引用它们。
template<int I> void __fastcall DetourPushNoManager(hks::lua_State* L, int stackOffset);
template<int I> void __fastcall DetourPushWithManager(void* manager, hks::lua_State* L, int stackOffset);

// PushMethods detour 的两条函数指针类型（阶段 4 从母体迁入，与槽位结构体同处）。
using PushMethodsNoFunc = void(__fastcall*)(hks::lua_State* L, int stackOffset);
using PushMethodsWithFunc = void(__fastcall*)(void*, hks::lua_State* L, int stackOffset);

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

// ================= 函数实现 =================

// ==== GameEventReadPtrSafe ====
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

// ==== GameEventReadInt32Safe ====
static int32_t GameEventReadInt32Safe(const void* addr) {
    int32_t value = 0;
    __try {
        value = *reinterpret_cast<const int32_t*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return value;
}

// ==== GetCurrentGameSlot ====
// ms_pkCurrentGame 的 .data 槽地址（命中地址按代缓存，重载后 Contains 失效自动重扫）。
static void* GetCurrentGameSlot() {
    if (!g_gameEventContainerHit ||
            !ImageAddress::Contains(kHookImageGameCoreXP2, g_gameEventContainerHit)) {
        g_gameEventContainerHit = AddressResolve::ResolveByPatternCore(kHookImageGameCoreXP2,
            kGameEventCurrentGamePattern, kSectionText, 1);
        if (!g_gameEventContainerHit) return nullptr;
    }
    const int32_t disp = GameEventReadInt32Safe(
        static_cast<const char*>(g_gameEventContainerHit) + 3);
    if (disp == 0) return nullptr;
    return static_cast<char*>(g_gameEventContainerHit) + 7 + disp;
}

// ==== GetEngineUtilityCore ====
// GameCore::EngineUtility 全局（ms_pkCurrentGame 槽 +0x18，与 scriptSystem +0x20 同族）。
// 锁协议（官方 Utility::CallHook 同款）。**Loader 私有**，不导出为插件 ABI 入口：
// Loader 自己的 Lua 锁协议路径（GameEventInvokeLuaImpl）必须能取到它 —— 那里
// _ReturnAddress() 会落在 Loader 模块，任何按调用者身份设门的入口都会拒绝它。
static void* GetEngineUtilityCore() {
    void* currentGameSlot = GetCurrentGameSlot();
    if (!currentGameSlot) return nullptr;
    return GameEventReadPtrSafe(static_cast<const char*>(currentGameSlot) + 0x18, 0);
}

// ==== GetMainLuaStateImpl ====
// 引擎主 Lua VM（进程级，见 HookAPI.h 的 GetMainLuaState 说明）。
// **不限插件类别**：它是进程级 state，Global 插件持有它不会因换局悬垂，所以不需要
// 地址域门（域门防的是 GameCore 那种"随对局重载的短命域地址"）。Loader 内部
// GameEvent 路径（GameEventInvokeLuaImpl）也直接调它。
void* GetMainLuaStateImpl() {
    // 定位 exe 的 ScriptSystem::CallHook 内的全局读取序列（IDA 实证）：
    //   48 8B 05 ?? ?? ?? ??   mov rax, cs:ms_apSingletonInstance
    //   48 8B 48 10            mov rcx, [rax+10h]      ← 主 lua_State
    //   E9 ?? ?? ?? ??         jmp GameEventLibrary::CallHook
    // AOB 自锚定（不依赖硬编码 RVA，游戏版本更新时该序列由编译器稳定生成）；
    // 命中地址按镜像缓存（Contains 校验，跨代/重载自动重扫）。
    //
    // 注：该 pattern 在 PC exe 上命中 6 处（CallHook / CallAccumulator×2 / CallProcessor /
    // CallTestAll / CallTestAny），但 6 处的 disp32 全部指向同一个单例槽、且都是 mov rcx,[rax+10h]，
    // 所以取任一处结果等价，不需要唯一性。
    static const HookImageId kCandidates[] = { kHookImageExeDx11, kHookImageExeDx12 };
    for (HookImageId image : kCandidates) {
        if (!ImageAddress::IsLoaded(image)) continue;
        // 缓存命中（地址仍属该镜像）直接用
        void* slot = nullptr;
        if (g_mainLuaStateHit && ImageAddress::Contains(image, g_mainLuaStateHit)) {
            const int32_t disp = GameEventReadInt32Safe(
                static_cast<const char*>(g_mainLuaStateHit) + 3);
            if (disp != 0) {
                slot = static_cast<char*>(g_mainLuaStateHit) + 7 + disp;
            }
        }
        if (!slot) {
            void* hit = AddressResolve::ResolveByPatternCore(image, kLuaSingletonPattern, kSectionText, 1);
            if (hit) {
                g_mainLuaStateHit = hit;
                const int32_t disp = GameEventReadInt32Safe(static_cast<const char*>(hit) + 3);
                if (disp != 0) slot = static_cast<char*>(hit) + 7 + disp;
            }
        }
        if (!slot) continue;
        void* singleton = GameEventReadPtrSafe(slot, 0);
        if (!singleton) continue;
        void* L = GameEventReadPtrSafe(static_cast<const char*>(singleton) + 0x10, 0);
        // 每个进程只打一次命中 RVA（预期 slot RVA=0x2D08F88）：确认 AOB 锚点落对位置，
        // 是"主 state 取不到"这类现场问题的第一手证据。
        static bool s_logged = false;
        if (!s_logged && L) {
            s_logged = true;
            HookImageInfo info{ sizeof(HookImageInfo) };
            if (ImageAddress::GetInfo(image, &info) && info.base) {
                Logger::Log("GetMainLuaState: image=%u hitRva=0x%llX slotRva=0x%llX L=%p",
                    static_cast<unsigned>(image),
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(g_mainLuaStateHit) - info.base),
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(slot) - info.base), L);
            }
        }
        if (L) return L;
    }
    return nullptr;
}

// ==== CleanupGameEventsForOwner ====
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

// ==== GameEventPopToBaseSeh ====
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

// ==== GameEventPushArgsSeh ====
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

// ==== GameEventInvokeLuaSeh ====
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

// ==== WarnEngineUtilityUnavailable ====
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

// ==== GameEventInvokeLuaImpl ====
// 内层主体：Lua/插件段全部走 SEH 兜底；本函数【不声明 noexcept】。
// 原因（已用 MSVC 实测确认）：noexcept 函数里逃出的 C++ 异常会直接 std::terminate，
// 外层 GameEventInvokeLua 的 try/catch 永远看不到 —— 等于死代码。真实的 C++ 异常源是
// 插件回调 throw 与标准库分配失败；交给外层 catch 隔离，比带崩整个进程好。
static bool GameEventInvokeLuaImpl(const char* name, GameEventPushFn pushFn,
                                   const void* payload) {
    if (!name || !*name) return false;
    void* L = GetMainLuaStateImpl();
    if (!L) {
        Logger::Log("GameEvent: InvokeLua no-main-state name=%s", name);
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

// ==== GameEventInvokeLua ====
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

// ==== TriggerGameEventImpl ====
// 调用方归属校验（严格 fail-closed）：
//   正常情况：插件经函数指针表调用本函数，_ReturnAddress() 落在该插件自己的模块里，
//   可精确判定；事件名若属于另一个插件则拒绝（挡住"抢注名字 + 用自己的 payload 触发
//   别人的 pushFn"这条跨插件路径）。
//   判定不出（尾调用 / 经第三方 wrapper 转发 / 调用方不是被跟踪插件）同样拒：下面的
//   RequireGameCoreOwner 对 !owner 与"owner 不是 GameCore"一律 return false。
//   注意这与 Patch 用 _ReturnAddress() 的 caveat 不同 —— Patch 的探测在页属性层面，
//   失败可能只是探测不到；这里的 owner 查找失败就是"调用方身份不明"，没有放行理由。
__declspec(noinline)
bool TriggerGameEventImpl(const char* name, const void* payload) {
    if (!name || !*name) return false;
    const void* callerAddress = _ReturnAddress();
    if (!PluginDomain::RequireGameCoreOwner(callerAddress, "TriggerGameEvent")) return false;

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
        lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
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
    if (const auto callerOwner = PluginDomain::ResolvePluginOwnerForAddress(callerAddress)) {
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

// ==== RegisterGameEventImpl ====
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
    lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
    PluginBoundary::LoaderLockScope pbLockScope;

    // owner 探针：优先插件提供的 pushFn 地址；为空时退回插件的 name 指针。
    // 两者都只做模块归属查询（RequirePluginOwner 不解引用）。
    const void* ownerProbe = reinterpret_cast<const void*>(pushFn);
    if (!ownerProbe) ownerProbe = name;
    auto owner = PluginDomain::RequirePluginOwner(ownerProbe, "RegisterGameEvent");
    if (!owner) {
        Logger::Log("RegisterGameEvent: no plugin owner");
        return false;
    }
    if (!PluginDomain::RequireGameCoreOwner(ownerProbe, "RegisterGameEvent")) return false;
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

// ==== ResolveCurrentGameCoreByName ====
void* ResolveCurrentGameCoreByName(const char* name) {
    const HookImageId image = ImageAddress::LoadedGameCore();
    if (image == kHookImageInvalid) return nullptr;
    return AddressResolve::ResolveByNameCore(image, name);
}

// ==== SameLuaMethod ====
static bool SameLuaMethod(const StoredLuaMethod& a, const StoredLuaMethod& b) {
    return a.owner == b.owner && a.luaMethodFunc == b.luaMethodFunc &&
        a.internalName == b.internalName && a.exposedName == b.exposedName;
}

// ==== MergeLuaMethod ====
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

// ==== MergeLuaMethods ====
static bool MergeLuaMethods(vector<StoredLuaMethod>& candidate,
                             const vector<StoredLuaMethod>& methods) {
    for (const auto& method : methods) {
        if (!MergeLuaMethod(candidate, method)) return false;
    }
    return true;
}

// ==== PushLuaMethodsImpl ====
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
    lock_guard<std::recursive_mutex> lifecycleLock(LoaderCore::LifecycleMutex());
    PluginBoundary::LoaderLockScope pbLockScope;
    auto owner = PluginDomain::RequirePluginOwner(
        reinterpret_cast<const void*>(copies[0].luaMethodFunc), "PushLuaMethods");
    if (!owner) return kHookApiPushMethodsFailed;
    if (!PluginDomain::RequireGameCoreOwner(
            reinterpret_cast<const void*>(copies[0].luaMethodFunc), "PushLuaMethods")) {
        return kHookApiPushMethodsFailed;
    }
    // 插件表归 PluginRegistry，经只读门面查询（§5.2）——本模块不必看见
    // PluginEntry / PluginState 两个类型。
    if (!PluginRegistry::IsOwnerActive(owner->ownerId)) return kHookApiPushMethodsFailed;

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
        auto methodOwner = PluginDomain::RequirePluginOwner(
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
    if (!IsGameCorePhaseReady()) {
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

// ==== CallScriptGlobalsSafe ====
static void CallScriptGlobalsSafe(ScriptGlobalsFn fn, void* L) {
    if (!fn) return;
    __try {
        fn(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("ScriptGlobals callback crashed code=0x%08X", GetExceptionCode());
    }
}

// ==== SnapshotScriptGlobals ====
// 拷贝快照后在锁外回调：注册表可能被 Loader 工作线程（插件卸载清理）并发修改。
static std::vector<ScriptGlobalsEntry> SnapshotScriptGlobals(std::vector<ScriptGlobalsEntry>& reg) {
    lock_guard<mutex> lock(g_scriptStateMutex);
    return reg;
}

// ==== Hook_RegisterScriptData ====
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

// ==== Hook_RegisterScriptDataForUI ====
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

// ==== EnsureScriptHooksInstalled ====
// 确保已注册回调对应的共享钩子已装上。两条调用路径：
//  1) 插件 RegisterGameCoreScriptForGamePlay / RegisterGameCoreScriptForUI 注册时；
//  2) GameCore 重载后 InitializeGameCorePhase 再调。
// 共享钩的 MinHook 记录随旧 GameCore 映像在 ResetForReload 里被物理摘除，因此重载后
// 必须按【当次】仍存在的注册项重新装钩；不存在跨代保留的注册列表。
// 检查+安装整体持锁，消除并发首装的重复创建竞态。安装走统一站点表，天然幂等，
// 因此不需要「已装就早退」标志：重复调用只是复用同一站点、刷新 g_orig* 跳板。
void EnsureScriptHooksInstalled() {
    lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
    if (!IsGameCorePhaseReady()) return;

    if (!g_scriptGlobals.empty()) {
        void* target = ResolveCurrentGameCoreByName("GameCore::Lua::Utility::RegisterScriptData");
        if (!target) {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptData address missing");
        } else if (HookEngine::InstallLoaderDetourOnSite(target,
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
        } else if (HookEngine::InstallLoaderDetourOnSite(target,
                       reinterpret_cast<void*>(&Hook_RegisterScriptDataForUI),
                       reinterpret_cast<void**>(&g_origRegisterScriptDataForUI), "ScriptDataForUI")) {
            Logger::Log("EnsureScriptHooksInstalled: hooked RegisterScriptDataForUI at %p", target);
        } else {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptDataForUI hook install failed "
                        "(target held by another detour?)");
        }
    }
}

// ==== RegisterGameCoreScriptForGamePlayImpl ====
// 把插件的注册回调接进 GameCore 的 gameplay 脚本环境：由 Loader 挂住
// GameCore::Lua::Utility::RegisterScriptData，引擎每次调用它时顺带把已登记的插件回调
// 也跑一遍（原函数的语义保持不变）。
void RegisterGameCoreScriptForGamePlayImpl(ScriptGlobalsFn fn) {
    if (!fn) return;
    // owner 校验与登记必须在同一把生命周期锁内完成。原实现先 RequirePluginOwner（内部取锁
    // 后释放）、再单独取锁 push_back：这中间若插件被停用并跑完 RemovePluginOwnedRegistrations，
    // 本次登记就永远清不掉（停用期间被守卫挡住，重新启用后又会多注册一份）。
    // RequirePluginOwner 内部取的是同一把递归锁，重入安全。
    {
        lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
        auto owner = PluginDomain::RequirePluginOwner(reinterpret_cast<const void*>(fn),
                                        "RegisterGameCoreScriptForGamePlay");
        if (!owner) return;
        if (!PluginDomain::RequireGameCoreOwner(reinterpret_cast<const void*>(fn),
                                  "RegisterGameCoreScriptForGamePlay")) return;
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        g_scriptGlobals.push_back(
            ScriptGlobalsEntry{ owner->ownerId, fn, PluginInFlight::Resolve(owner->ownerId) });
    }
    EnsureScriptHooksInstalled();  // 内部自带生命周期锁（含并发首装与重载后重装）
}

// ==== RegisterGameCoreScriptForUIImpl ====
// 同上，但接进 GameCore 的 UI 脚本环境（GameCore::Lua::Utility::RegisterScriptDataForUI）。
// 两者的 lua_State 不同：gameplay 是每局那个，UI 是 GameCore 侧界面脚本用的那个。
void RegisterGameCoreScriptForUIImpl(ScriptGlobalsFn fn) {
    if (!fn) return;
    // 同 RegisterGameCoreScriptForGamePlayImpl：校验与登记同锁，避免"校验后、登记前"被卸载插入。
    {
        lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
        auto owner = PluginDomain::RequirePluginOwner(reinterpret_cast<const void*>(fn),
                                        "RegisterGameCoreScriptForUI");
        if (!owner) return;
        if (!PluginDomain::RequireGameCoreOwner(reinterpret_cast<const void*>(fn),
                                  "RegisterGameCoreScriptForUI")) return;
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        g_scriptGlobalsUI.push_back(
            ScriptGlobalsEntry{ owner->ownerId, fn, PluginInFlight::Resolve(owner->ownerId) });
    }
    EnsureScriptHooksInstalled();
}

static void EnsureGlobalScriptHooksInstalled();

// ==== RegisterGlobalScriptImpl ====
// 全局脚本注册：回调跑到【引擎主 lua_State】（进程级，见 GetMainLuaState）上。
// 与 GameCore 两个入口的区别：那两个挂的是 GameCore.dll 的 RegisterScriptData，state 每局
// 重建、注册跟着重建；这里挂的是 exe 的主 state，换局不失效，因此两类插件都能用。
// 登记本身不执行回调：主 state 要在 GUIInit 之后才存在，执行点见 RunGlobalScripts。
void RegisterGlobalScriptImpl(ScriptGlobalsFn fn) {
    if (!fn) return;
    {
        lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
        auto owner = PluginDomain::RequirePluginOwner(reinterpret_cast<const void*>(fn),
            "RegisterGlobalScript");
        if (!owner) return;
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        g_globalScriptGlobals.push_back(ScriptGlobalsEntry{
            owner->ownerId, fn, PluginInFlight::Resolve(owner->ownerId) });
    }
    Logger::Log("RegisterGlobalScript: queued for the engine main lua_State");
    // 尽早把引擎侧的 "Modding" 注册入口挂上：Global 插件在阶段 A 就注册，通常早于 GUIInit。
    EnsureGlobalScriptHooksInstalled();
}

// ==== Hook_ModdingRegister ====
// pRegister 的 detour：先跑插件登记的全局脚本，再走原函数。
// 放在原函数之前是有意的——原函数返回时栈顶留着刚建好的 "Modding" 表（返回 1），
// 那之后再调插件代码容易破坏调用方对栈的预期。
int64_t __fastcall Hook_ModdingRegister(void* L) {
    SharedDetourActivity activity;
    // 插件回调跑完把栈削回原高度：原函数接下来会在栈上建表（-2 索引指它），
    // 回调若留下多余的值，会让它填到错误的位置上。
    const int topBefore = L ? LuaGetTopImpl(L) : 0;
    RunGlobalScripts();
    if (L) {
        const int now = LuaGetTopImpl(L);
        if (now > topBefore) {
            LuaPopImpl(L, now - topBefore);
        }
    }
    if (g_origModdingRegister) {
        return g_origModdingRegister(L);
    }
    return 0;
}

// ==== EnsureGlobalScriptHooksInstalled ====
// 把 pRegister 挂进统一站点表（与 GameCore 的两个脚本钩同构，但目标是 exe 域）。
// 幂等：站点表本身就是账本，重复调用只是复用同一站点、刷新跳板。
static void EnsureGlobalScriptHooksInstalled() {
    {
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        if (g_globalScriptGlobals.empty()) return;
    }
    void* target = LoaderCore::ResolveExeTarget(kExeModdingRegister, 1);
    if (!target) {
        Logger::Log("EnsureGlobalScriptHooksInstalled: AppLuaModdingLibrary::pRegister not found");
        return;
    }
    if (HookEngine::InstallLoaderDetourOnSite(target,
            reinterpret_cast<void*>(&Hook_ModdingRegister),
            reinterpret_cast<void**>(&g_origModdingRegister), "GlobalScript")) {
        Logger::Log("EnsureGlobalScriptHooksInstalled: hooked Modding register at %p", target);
    } else {
        Logger::Log("EnsureGlobalScriptHooksInstalled: install failed at %p "
                    "(target held by another detour?)", target);
    }
}

// ==== RunGlobalScripts ====
// 把所有已登记的回调跑在引擎主 Lua state 上。调用点有两个约束：
//   1) 游戏线程（Lua 状态非线程安全）；
//   2) 主 state 已就绪（GUIInit 之后）。
// 当前由 UiInject 的 MainMenuState::LoadUI detour 触发——那时主菜单 UI 刚建好、主 state
// 必然存在，而且还没开始加载各 Mod 的 FrontEndUI Lua，插件注册的全局正好赶在前头。
// 每个登记项对同一个 state 只跑一次；state 被重建（指针变化）后再跑。
void RunGlobalScripts() {
    void* L = GetMainLuaStateImpl();
    if (!L) {
        Logger::Log("RunGlobalScripts: engine main lua_State not ready, skipped");
        return;
    }
    std::vector<ScriptGlobalsEntry> pending;
    {
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        for (auto& entry : g_globalScriptGlobals) {
            if (entry.appliedFor == L) continue;
            entry.appliedFor = L;
            pending.push_back(entry);
        }
    }
    if (pending.empty()) return;
    Logger::Log("RunGlobalScripts: running %zu registrar(s) on main lua_State %p",
        pending.size(), L);
    for (const auto& entry : pending) {
        PluginInFlight::Owner* owner = entry.inFlight;
        if (!owner) owner = PluginInFlight::Resolve(entry.owner);
        auto callbackGuard = PluginInFlight::Enter(owner, PluginInFlight::Kind::ScriptGlobals);
        if (callbackGuard) {
            CallScriptGlobalsSafe(entry.fn, L);
        } else {
            Logger::Log("RunGlobalScripts: skipped for inactive owner=%ls", entry.owner.c_str());
        }
    }
}

// ==== RebuildSlotOwners ====
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

// ==== RemoveOwnedSlotMethods ====
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

// ==== PushStoredMethodIfActive ====
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

// ==== DetourPushNoManager ====
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

// ==== DetourPushWithManager ====
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

// ==== FindOrAllocNoManagerSlot ====
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

// ==== FindOrAllocWithManagerSlot ====
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



// ==== WarnHksImportMissing ====
// hks 导入缺失时的统一降级：安全默认值 + 限次日志（脚本可能高频调用，不能每次刷日志）。
// 导入在阶段 A（WorkerMain）已整体告警；此处是纵深防御（防"告警漏了/新加导入没跟上"）。
// （阶段 A 已加载的 Global 插件仍可能在调用这些包装）。
static void WarnHksImportMissing(const char* name) {
    static std::atomic<int> s_warned{ 0 };
    if (s_warned.fetch_add(1, std::memory_order_relaxed) < 10) {
        Logger::Log("HookAPI lua wrapper unavailable (HavokScript import missing): %s", name);
    }
}

// ==== ValidateLuaState ====
static bool ValidateLuaState(void* L, const char* apiName) {
    if (L) return true;
    Logger::Log("%s rejected: lua_State is null", apiName ? apiName : "Lua API");
    return false;
}

// ==== ValidateLuaCString ====
static bool ValidateLuaCString(const char* value, const char* apiName) {
    if (value) return true;
    Logger::Log("%s rejected: string argument is null", apiName ? apiName : "Lua API");
    return false;
}

// ==== LuaPushNamedCClosureImpl ====
void LuaPushNamedCClosureImpl(void* L, void* func, int a, const char* name, int b) {
    if (!func || !ValidateLuaCString(name, "LuaPushNamedCClosure") || a < 0 || b < 0) return;
    HKS_GUARD_VOID(hks::pushnamedcclosure, L,
        reinterpret_cast<hks::luaFunc>(func), a, name, b);
}

// ==== LuaCheckIntegerImpl ====
int LuaCheckIntegerImpl(void* L, int index) {
    HKS_GUARD_RET(hks::checkinteger, 0, L, index);
}

// ==== LuaCheckNumberImpl ====
double LuaCheckNumberImpl(void* L, int index) {
    HKS_GUARD_RET(hks::checknumber, 0.0, L, index);
}

// ==== LuaPushNilImpl ====
void LuaPushNilImpl(void* L) {
    HKS_GUARD_VOID(hks::pushnil, reinterpret_cast<hks::lua_State*>(L));
}

// ==== LuaSetFieldImpl ====
void LuaSetFieldImpl(void* L, int stackOffset, const char* name) {
    if (!ValidateLuaCString(name, "LuaSetField")) return;
    HKS_GUARD_VOID(hks::setfield, L, stackOffset, name);
}

// ==== LuaGetTopImpl ====
int LuaGetTopImpl(void* L) {
    HKS_GUARD_RET0(hks::gettop, 0, L);
}

// ==== LuaDoStringImpl ====
int LuaDoStringImpl(void* L, const char* str) {
    if (!ValidateLuaCString(str, "LuaDoString")) return 0;
    HKS_GUARD_RET(hks::dostring, 0, L, str);
}

// ==== LuaToBooleanImpl ====
int LuaToBooleanImpl(void* L, int index) {
    HKS_GUARD_RET(hks::toboolean, 0, L, index);
}

// ==== LuaPushNumberImpl ====
void LuaPushNumberImpl(void* L, double num) {
    HKS_GUARD_VOID(hks::pushnumber, L, num);
}

// ==== LuaPushIntegerImpl ====
void LuaPushIntegerImpl(void* L, int num) {
    // 语义对齐：API 承诺压整数，用 hksi_lua_pushinteger 压整数标记值
    // （此前走 pushnumber 是历史遗留，hks 开启 IntLiterals 时两者字节码可区分）。
    HKS_GUARD_VOID(hks::pushinteger, L, num);
}

// ==== FormatLuaString ====
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

// ==== LuaErrorImpl ====
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

// ==== LuaPushFStringImpl ====
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

// ==== LuaCheckLStringImpl ====
char const* LuaCheckLStringImpl(void* L, int index, unsigned __int64* a) {
    if (!a) return nullptr;
    HKS_GUARD_RET(hks::checklstring, nullptr, L, index, a);
}

// ==== LuaToUserDataImpl ====
void* LuaToUserDataImpl(void* L, int index) {
    HKS_GUARD_RET(hks::touserdata, nullptr, L, index);
}

// ==== LuaGetFieldImpl ====
void LuaGetFieldImpl(void* L, int a, char const* b) {
    if (!ValidateLuaCString(b, "LuaGetField")) return;
    HKS_GUARD_VOID(hks::getfield, L, a, b);
}

// ==== LuaPopImpl ====
void LuaPopImpl(void* L, int a) {
    if (a < 0) return;
    HKS_GUARD_VOID(hks::pop, L, a);
}

// ==== LuaCreateTableImpl ====
void LuaCreateTableImpl(void* L, int a, int b) {
    if (a < 0 || b < 0) return;
    HKS_GUARD_VOID(hks::createtable, L, a, b);
}

// ==== LuaToCFunctionImpl ====
void* LuaToCFunctionImpl(void* L, int index) {
    if (!ValidateLuaState(L, "LuaToCFunction")) return nullptr;
    if (!hks::tocfunction) {
        WarnHksImportMissing("hks::tocfunction");
        return nullptr;
    }
    return reinterpret_cast<void*>(hks::tocfunction(reinterpret_cast<hks::lua_State*>(L), index));
}

// ==== LuaCheckTableImpl ====
void LuaCheckTableImpl(void* L, int index) {
    HKS_GUARD_VOID(hks::checktable, L, index);
}

// ==== LuaObjLenImpl ====
unsigned long long LuaObjLenImpl(void* L, int index) {
    HKS_GUARD_RET(hks::objlen, 0, L, index);
}

// ==== LuaGetTableImpl ====
void LuaGetTableImpl(void* L, int index) {
    HKS_GUARD_VOID(hks::gettable, L, index);
}

// ==== LuaCPcallImpl ====
int LuaCPcallImpl(void* L, LuaMethodFunc callback, void* userdata) {
    if (!L || !callback) {
        return kHookApiLuaCallInvalidArgument;
    }
    HKS_GUARD_RET(hks::cpcall, kHookApiLuaCallUnavailable,
        L,
        reinterpret_cast<hks::luaFunc>(callback), userdata);
}

// ==== LuaRefImpl ====
int LuaRefImpl(void* L, int index) {
    HKS_GUARD_RET(hks::ref, 0, L, index);
}

// ==== LuaPcallImpl ====
int LuaPcallImpl(void* L, int a, int b, int c) {
    if (a < 0 || b < -1) return 0;
    HKS_GUARD_RET(hks::pcall, 0, L, a, b, c);
}

// ==== LuaPushValueImpl ====
void LuaPushValueImpl(void* L, int value) {
    HKS_GUARD_VOID(hks::pushvalue, L, value);
}

// ==== LuaRawGetIImpl ====
void LuaRawGetIImpl(void* L, int a, int b) {
    HKS_GUARD_VOID(hks::rawgeti, L, a, b);
}

// ==== LuaUnrefImpl ====
void LuaUnrefImpl(void* L, int a, int b) {
    HKS_GUARD_VOID(hks::unref, L, a, b);
}

// ==== LuaSetTableImpl ====
void LuaSetTableImpl(void* L, int t) {
    HKS_GUARD_VOID(hks::settable, L, t);
}

// ==== LuaIsNumberImpl ====
int LuaIsNumberImpl(void* L, int num) {
    HKS_GUARD_RET(hks::isnumber, 0, L, num);
}

// ==== LuaToNumberImpl ====
double LuaToNumberImpl(void* L, int num) {
    HKS_GUARD_RET(hks::tonumber, 0.0, L, num);
}

// ==== LuaIsUserDataImpl ====
int LuaIsUserDataImpl(void* L, int num) {
    HKS_GUARD_RET(hks::isuserdata, 0, L, num);
}

// ==== LuaOpenDebugImpl ====
int LuaOpenDebugImpl(void* L) {
    HKS_GUARD_RET0(hks::luaopen_debug, 0, L);
}

// ==== LuaToIntegerImpl ====
int LuaToIntegerImpl(void* L, int num) {
    HKS_GUARD_RET(hks::tointeger, 0, L, num);
}

// ==== LuaTypeImpl ====
int LuaTypeImpl(void* L, int num) {
    HKS_GUARD_RET(hks::type, 0, L, num);
}

// ==== LuaOptIntegerImpl ====
int LuaOptIntegerImpl(void* L, int a, int b) {
    HKS_GUARD_RET(hks::optinteger, b, L, a, b);
}

// ==== LuaSetHookImpl ====
int LuaSetHookImpl(void* L, void* a, int b, int c) {
    if (c < 0) return 0;
    HKS_GUARD_RET(hks::sethook, 0, L, a, b, c);
}

// ==== LuaGetHookImpl ====
void* LuaGetHookImpl(void* L) {
    HKS_GUARD_RET0(hks::gethook, nullptr, L);
}

// ==== LuaGetHookMaskImpl ====
int LuaGetHookMaskImpl(void* L) {
    HKS_GUARD_RET0(hks::gethookmask, 0, L);
}

// ==== LuaGetHookCountImpl ====
int LuaGetHookCountImpl(void* L) {
    HKS_GUARD_RET0(hks::gethookcount, 0, L);
}

// ==== LuaCheckPlayerIdImpl ====
int LuaCheckPlayerIdImpl(void* L, int index) {
    if (!ValidateLuaState(L, "LuaCheckPlayerId")) return -1;
    return hks::checkplayerid(reinterpret_cast<hks::lua_State*>(L), index);
}

// ==== LuaPushBooleanImpl ====
void LuaPushBooleanImpl(void* L, bool value) {
    if (!ValidateLuaState(L, "LuaPushBoolean")) return;
    hks::pushboolean(reinterpret_cast<hks::lua_State*>(L), value);
}

// ==== LuaPushLightUserDataImpl ====
void LuaPushLightUserDataImpl(void* L, void* ptr) {
    if (!ValidateLuaState(L, "LuaPushLightUserData")) return;
    hks::pushlightuserdata(reinterpret_cast<hks::lua_State*>(L), ptr);
}

// ==== LocalizationLookupImpl ====
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

// ==== LogImpl ====
void LogImpl(const char* format, ...) {
    if (!format) return;
    char buffer[2048];
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    Logger::Log("%s", buffer);
}

// ==== LuaPushCFunctionFieldImpl ====
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

// ==== LuaNewGlobalTableImpl ====
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

// ==== LocStringBytesImpl ====
uint32_t LocStringBytesImpl(void) {
    return CIV6_HOOK_API_LOC_STRING_BYTES;
}

// ==== LocCreateImpl ====
void* LocCreateImpl(void) {
    void* mem = calloc(1, CIV6_HOOK_API_LOC_STRING_BYTES);
    return mem;
}

// ==== LocDestroyImpl ====
void LocDestroyImpl(void* loc) {
    if (!loc) return;
    if (Localization::DestructorPtr) {
        Localization::DestructorPtr(reinterpret_cast<Localization::String*>(loc));
    }
    free(loc);
}

// ==== LocLookupImpl ====
void* LocLookupImpl(void* loc, const char* key) {
    if (!loc || !key || !Localization::LookupPtr) {
        Logger::Log("LocLookup: invalid args or LookupPtr not ready");
        return nullptr;
    }
    return Localization::LookupPtr(reinterpret_cast<Localization::String*>(loc), key);
}

// ==== LocPushArgumentImpl ====
int LocPushArgumentImpl(void* loc, const char* arg) {
    if (!loc || !arg || !Localization::PushArgumentPtr) return 0;
    return Localization::PushArgumentPtr(reinterpret_cast<Localization::String*>(loc), arg) ? 1 : 0;
}

// ==== LocToUtf8Impl ====
const char* LocToUtf8Impl(void* loc) {
    if (!loc || !Localization::ToUTF8Ptr) return nullptr;
    return Localization::ToUTF8Ptr(reinterpret_cast<Localization::String*>(loc));
}

using EditPlayerFn = void*(__fastcall*)(int playerId);

// ==== ResolveEditPlayer ====
static EditPlayerFn ResolveEditPlayer() {
    return reinterpret_cast<EditPlayerFn>(
        ResolveCurrentGameCoreByName("GameCore::Context::Globals::EditPlayer"));
}

// ==== GetPlayerImpl ====
void* GetPlayerImpl(int playerId) {
    if (!PluginDomain::RequireGameCoreOwner(_ReturnAddress(), "GetPlayer")) return nullptr;
    auto fn = ResolveEditPlayer();
    if (!fn) {
        Logger::Log("GetPlayer: symbol missing");
        return nullptr;
    }
    // 对局开始前 ms_pkCurrentGame 尚未初始化，引擎 EditPlayer 会
    // 解引用 null 而 AV——SEH 兜底返回 nullptr（对局前调用本就没有意义，属调用方时序错误）。
    __try {
        return fn(playerId);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("GetPlayer: engine call failed (game not started?)");
        return nullptr;
    }
}

// ==== CivCrc32Byte ====
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

// ==== CivCrc32Raw ====
// NUL 结尾版（下面 static_assert 的编译期自检走这条）。
constexpr uint32_t CivCrc32Raw(const char* str) {
    uint32_t h = 0xFFFFFFFFu;
    for (const char* p = str; p && *p; ++p) {
        h = CivCrc32Byte(h, static_cast<uint8_t>(*p));
    }
    return h;
}

// ==== CivCrc32RawLen ====
// 定长版：长度已由边界探针确定的路径走这条，不再做无界循环。
constexpr uint32_t CivCrc32RawLen(const char* str, size_t len) {
    uint32_t h = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        h = CivCrc32Byte(h, static_cast<uint8_t>(str[i]));
    }
    return h;
}

// ==== MakeHashImpl ====
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

// ==== RegisterPushMethodsTargetImpl ====
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

    lock_guard<std::recursive_mutex> lifecycleLock(LoaderCore::LifecycleMutex());
    PluginBoundary::LoaderLockScope pbLockScope;
    // owner 探针仍用插件自己的 name 指针：RequirePluginOwner 只做模块归属查询，
    // 不解引用；换成 Loader 副本会被判成 Loader 自身而全部拒绝。
    auto owner = PluginDomain::RequirePluginOwner(reinterpret_cast<const void*>(name),
                                    "RegisterPushMethodsTarget");
    if (!owner) return 0;
    if (!PluginDomain::RequireGameCoreOwner(reinterpret_cast<const void*>(name),
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

void* InstallPushMethodsNoManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                  const std::wstring& owner) {
    if (!target || methods.empty() || owner.empty() || std::any_of(methods.begin(), methods.end(),
            [&owner](const StoredLuaMethod& method) {
                return method.owner != owner;
            })) {
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
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
    if (!HookEngine::InstallLoaderDetourOnSite(target, NoManagerDetourTable[slot],
                                   reinterpret_cast<void**>(&state.base), "PushMethods")) {
        Logger::Log("InstallPushMethodsNoManager: install detour failed (target held by another owner?)");
        state = NoManagerHookSlot{};
        return nullptr;
    }
    state.methods.swap(merged);
    state.methodOwners.swap(mergedOwners);
    return reinterpret_cast<void*>(state.base);
}

// ==== InstallPushMethodsWithManager ====
void* InstallPushMethodsWithManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                    const std::wstring& owner) {
    if (!target || methods.empty() || owner.empty() || std::any_of(methods.begin(), methods.end(),
            [&owner](const StoredLuaMethod& method) {
                return method.owner != owner;
            })) {
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
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
    if (!HookEngine::InstallLoaderDetourOnSite(target, WithManagerDetourTable[slot],
                                   reinterpret_cast<void**>(&state.base), "PushMethods")) {
        Logger::Log("InstallPushMethodsWithManager: install detour failed (target held by another owner?)");
        state = WithManagerHookSlot{};
        return nullptr;
    }
    state.methods.swap(merged);
    state.methodOwners.swap(mergedOwners);
    return reinterpret_cast<void*>(state.base);
}

}  // namespace ScriptBridge


// ================= 门面实现（声明见 ScriptBridge.h） =================

namespace ScriptBridge {

RemovedCounts RemovePluginRegistrations(const std::wstring& owner) {
    RemovedCounts n;
    // 脚本全局表：按 owner 摘除（原 RemovePluginOwnedRegistrations 的 removeOwnedBy）。
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
    {
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        n.globals = removeOwnedBy(g_scriptGlobals);
        n.globalsUI = removeOwnedBy(g_scriptGlobalsUI);
        removeOwnedBy(g_globalScriptGlobals);   // 全局脚本随 owner 一起摘，计数并进 globals
    }
    // PushMethods 槽位：逐槽摘掉该 owner 的方法。
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (auto& slot : g_noManagerSlots) {
            if (slot.used) n.luaMethods += RemoveOwnedSlotMethods(slot, owner);
        }
        for (auto& slot : g_withManagerSlots) {
            if (slot.used) n.luaMethods += RemoveOwnedSlotMethods(slot, owner);
        }
    }
    n.targetConfigs = g_pluginPushTargetConfigs.erase(owner);
    // GameEvent 槽位：清空该 owner 注册的事件表（name/luaPushFn/ownerId）。
    // Quarantine/Unload 都经本函数，无需在各自路径重复接线。
    CleanupGameEventsForOwner(owner);
    return n;
}

void ResetForTeardown() {
    // teardown 要的是"清空全部"，不是"按 owner 摘"——此刻也无法枚举 owner。
    // 覆盖 HookEngine 的 RemoveGameCoreDomainSiteRecords 原先直接操作的 6 个对象。
    g_origRegisterScriptData = nullptr;
    g_origRegisterScriptDataForUI = nullptr;
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (int i = 0; i < kMaxPushHooks; ++i) {
            g_noManagerSlots[i] = NoManagerHookSlot{};
            g_withManagerSlots[i] = WithManagerHookSlot{};
        }
    }
}

void WaitForDetourDrain() {
    unique_lock<mutex> drainLock(g_detourDrainMutex);
    g_detourDrainCv.wait(drainLock, [] {
        return g_activeSharedDetours.load(std::memory_order_acquire) == 0;
    });
}

// 阶段 B 就绪标志（原母体的 g_gameCorePhaseReady）。改原子后读侧无锁：
// 两个读点（PushLuaMethodsImpl / EnsureScriptHooksInstalled）本来就持 lifecycle 锁，
// 用 LoaderCore::IsInitialized() 会多取一次锁；写侧语义不变（那两处也持锁）。
namespace {
std::atomic<bool> g_gameCorePhaseReady{ false };
}

bool IsGameCorePhaseReady() {
    return g_gameCorePhaseReady.load(std::memory_order_acquire);
}

void SetGameCorePhaseReady(bool ready) {
    g_gameCorePhaseReady.store(ready, std::memory_order_release);
}

}  // namespace ScriptBridge


// ================= 公开 ABI 入口的转发 =================
// 声明在 Civ6DLLHookLoaderAPI.h（外部链接、不在任何 namespace 内），
// 实现体在 namespace ScriptBridge 内（要用槽位机制与那些私有状态）。
// 故在此提供两个薄转发 —— 这样既保持外部链接，又不必把内部类型暴露出去。
void* InstallPushMethodsNoManager(void* target, const std::vector<StoredLuaMethod>& methods,
    const std::wstring& owner) {
    return ScriptBridge::InstallPushMethodsNoManager(target, methods, owner);
}

void* InstallPushMethodsWithManager(void* target, const std::vector<StoredLuaMethod>& methods,
    const std::wstring& owner) {
    return ScriptBridge::InstallPushMethodsWithManager(target, methods, owner);
}
