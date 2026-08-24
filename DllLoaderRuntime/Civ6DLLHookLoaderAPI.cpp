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
#include "SymbolDb.h"

#include <cstdarg>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <atomic>
#include <unordered_set>

#include "PatchRegistry.h"
#include "LoaderCore.h"

using namespace std;

static Civ6MessageBus g_bus;

// v2 插件跟踪项：路径 + 句柄 + 名字(stem，作 Patch owner / OnMessage 注册名) + 类别(Global/GameCore)。
struct PluginEntry {
    HMODULE handle = nullptr;
    std::wstring path;
    std::wstring name;
    LoaderCore::PluginCategory category = LoaderCore::PluginCategory::Global;
};
static vector<PluginEntry> g_plugins;

// 插件生命周期互斥锁（递归：OnLoad/OnUnload 期间插件会再调用 HookAPI 注册入口，
// 需要重入）。保护 g_plugins、脚本全局注册表与 PushMethods 槽位的全部读写：
// 游戏线程（LoadDLL/UnloadDLL detour → Load/UnloadPluginsOf）与 Loader 工作线程
// （ReconcileGlobalPlugins）在此串行化。g_hookMutex（MinHook 调用 + owner 表）与
// PatchRegistry 的 CRITICAL_SECTION 保持独立，锁序恒为 lifecycle → hook/patch。
static std::recursive_mutex g_pluginLifecycleMutex;

// 当前正在加载/卸载的插件名（去扩展名的文件名 stem）。OnLoad/OnUnload 期间由
// SetActivePluginName 设置；HookPatch 与 InstallHookImpl 用它作 owner，使卸载时能对上号。
// 线程局部（G7）：OnLoad/OnUnload 永远运行在执行加载/卸载的线程上；他线程并发调用
// HookAPI（如插件在游戏线程 detour 里延迟装钩/打补丁）不会被误归属到正在加载的
// 插件——此时本线程 active 为空，owner 记为空串（Loader 所有，卸载不撤销）。
static thread_local wchar_t g_activePluginName[64];

static void SetActivePluginName(const wchar_t* name) {
    if (!name || !*name) {
        g_activePluginName[0] = L'\0';
        return;
    }
    wcsncpy_s(g_activePluginName, _countof(g_activePluginName), name, _TRUNCATE);
}

// 插件通过 HookAPI.InstallHook 注册的 MinHook 目标 → owner 插件名。
// owner 为空串 = Loader 自身（非插件）在加载阶段注册的钩子，插件卸载时不撤销。
// 插件卸载时据此精确 MH_DisableHook + MH_RemoveHook，避免 GameCore 重载后
// 同一 target 再次 MH_CreateHook 报 MH_ERROR_ALREADY_CREATED。
static std::unordered_map<void*, std::wstring> g_pluginHookOwners;

// 阶段 B 是否已完成（InitializeGameCorePhase 成功置 true；ResetForReload 复位）。
static bool g_gameCorePhaseReady = false;

// 规范化路径比较：小写 + '/'→'\\'（候选均为绝对路径，词法规范化即可）。
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

static uintptr_t g_GameCoreAddress;
static uint32_t g_GameCoreSizeOfImage;

static unordered_map<string, PushMethodSigType> g_MethodSignatureTable = {
    {"GameCore::Cache::Lua::IQuestsManager", PushMethodSigType::WithManager},
    {"GameCore::Lua::IQuestsManager", PushMethodSigType::NoManager},
};

// Symbol RVAs live in Civ6DllLoader.symbols.bin (see tools/pack_symbol_db.py).

mutex g_hookMutex;

namespace fs = std::filesystem;


// ---------------- HookAPI ??? ----------------
// InstallHookImpl 的内核：owner 显式传入。空串 = Loader 自身的共享 hook
// （如 RegisterScriptData），插件卸载时不撤销；插件名 = 该插件私有，卸载时撤销。
static bool InstallHookOwnedBy(void* target, void* detour, void** original, const wchar_t* owner) {
    lock_guard<mutex> lock(g_hookMutex);

    MH_STATUS status;
    if ((status = MH_CreateHook(target, detour, original)) != MH_OK) {
        Logger::Log("InstallHook: create failed %s", MH_StatusToString(status));
        return false;
    }

    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallHook: enable failed %s", MH_StatusToString(status));
        // 回滚残留的 MinHook 记录：否则该 target 永远 ALREADY_CREATED，再无重试机会。
        MH_RemoveHook(target);
        return false;
    }

    // 记录 target → owner（插件 OnLoad 期间 = 插件 stem；否则空串 = Loader 自身）。
    // 插件卸载时据此撤销，避免 GameCore 重载后同一 target 再次 CreateHook 报 ALREADY_CREATED。
    g_pluginHookOwners[target] = owner ? owner : L"";

    return true;
}

bool InstallHookImpl(void* target, void* detour, void** original) {
    return InstallHookOwnedBy(target, detour, original,
        g_activePluginName[0] ? g_activePluginName : L"");
}

// 摘除单个 MinHook 钩子；目标内存不可读（GameCore 映像已卸载，重载兜底路径会出现）
// 时跳过 RemoveHook——对未映射地址恢复原字节会失败甚至出错。残留的 MinHook 记录
// 由 InstallSharedHook 的 ALREADY_CREATED 恢复路径在新映像 attach 后清理复用。
static bool SafeRemoveHook(void* target) {
    if (!target) return false;
    if (!Runtime::IsReadableSpan(target, 1)) {
        Logger::Log("SafeRemoveHook: target %p unreadable (module unmapped); skip MinHook removal", target);
        return false;
    }
    MH_DisableHook(target);
    const MH_STATUS st = MH_RemoveHook(target);
    if (st != MH_OK) {
        Logger::Log("SafeRemoveHook: MH_RemoveHook(%p) -> %s", target, MH_StatusToString(st));
        return false;
    }
    return true;
}

void BroadcastMessageImpl(const char* topic, const void* data, size_t len) {
    g_bus.Broadcast(topic, data, len);
}

void RegisterMessageHandlerImpl(const char* pluginName, MessageHandlerFn handler) {
    g_bus.RegisterHandler(pluginName, handler);
}

void SendMessageToImpl(const char* pluginName, const char* topic, const void* data, size_t len) {
    g_bus.SendTo(pluginName, topic, data, len);
}

uintptr_t GetGameCoreAddressImpl() {
    return g_GameCoreAddress;
}

void* GetFunctionByNameImpl(const char* name) {
    if (!name || !*name || !g_GameCoreAddress) return nullptr;
    const uint32_t rva = SymbolDb::LookupRva(name);
    if (rva == 0 || rva >= g_GameCoreSizeOfImage) {
        if (rva != 0) {
            Logger::Log("GetFunctionByName: out-of-range RVA name=%s rva=0x%X image=0x%X",
                name, rva, g_GameCoreSizeOfImage);
        }
        return nullptr;
    }
    return reinterpret_cast<void*>(g_GameCoreAddress + rva);
}

void* GetFunctionByAddressImpl(uintptr_t address) {
    if (!g_GameCoreAddress || address == 0 || address >= g_GameCoreSizeOfImage) {
        Logger::Log("GetFunctionByAddress: rejected RVA=0x%llX image=0x%X",
            static_cast<unsigned long long>(address), g_GameCoreSizeOfImage);
        return nullptr;
    }
    return reinterpret_cast<void*>(g_GameCoreAddress + address);
}

using PushMethodsNoFunc = void(__fastcall*)(hks::lua_State* L, int stackOffset);
using PushMethodsWithFunc = void(__fastcall*)(void*, hks::lua_State* L, int stackOffset);

static vector<StoredLuaMethod> CopyLuaMethods(const LuaMethodInfo* methods, uint32_t count) {
    vector<StoredLuaMethod> out;
    if (!methods || count == 0) return out;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        StoredLuaMethod m;
        m.luaMethodFunc = methods[i].luaMethodFunc;
        m.internalName = methods[i].internalName ? methods[i].internalName : "";
        m.exposedName = methods[i].exposedName ? methods[i].exposedName : "";
        out.push_back(std::move(m));
    }
    return out;
}

void* PushLuaMethodsImpl(const char* name, const LuaMethodInfo* methods, uint32_t count) {
    if (!name) return nullptr;
    // M2: g_MethodSignatureTable 与 RegisterPushMethodsTargetImpl 的写入跨线程共享，
    // 读写都在生命周期锁内（后面 InstallPushMethods* 递归重入）。
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    auto name2 = string(name);
    auto sigIt = g_MethodSignatureTable.find(name2);
    if (sigIt == g_MethodSignatureTable.end()) {
        Logger::Log("PushLuaMethods: unknown target %s", name);
        return nullptr;
    }
    auto stored = CopyLuaMethods(methods, count);
    name2 += "::PushMethods";
    if (sigIt->second == PushMethodSigType::NoManager) {
        auto target = reinterpret_cast<PushMethodsNoFunc>(GetFunctionByNameImpl(name2.c_str()));
        if (!target) {
            Logger::Log("PushLuaMethods: missing %s", name2.c_str());
            return nullptr;
        }
        return InstallPushMethodsNoManager(target, stored);
    }
    auto target = reinterpret_cast<PushMethodsWithFunc>(GetFunctionByNameImpl(name2.c_str()));
    if (!target) {
        Logger::Log("PushLuaMethods: missing %s", name2.c_str());
        return nullptr;
    }
    return InstallPushMethodsWithManager(target, stored);
}

// 版本锁定偏移：当前回合 dword 位于 CurrentTurnStorage 解引用对象 +0xC0。
// 符号库/游戏版本错位时由下方可读探测兜住，返回 0 而不是读崩。
constexpr size_t kCurTurnDwordOffset = 0xC0;

unsigned int GetCurTurnImpl() {
    auto* slot = reinterpret_cast<uint64_t**>(
        GetFunctionByNameImpl("GameCore::Globals::CurrentTurnStorage"));
    if (!slot || !Runtime::IsReadableSpan(slot, sizeof(uint64_t*)) || !*slot) {
        Logger::Log("GetCurTurn: current-turn storage unavailable");
        return 0;
    }
    auto* storage = reinterpret_cast<const uint8_t*>(*slot);
    if (!Runtime::IsReadableSpan(storage, kCurTurnDwordOffset + sizeof(uint32_t))) {
        Logger::Log("GetCurTurn: storage readable-span check failed (version-locked offset?)");
        return 0;
    }
    return *reinterpret_cast<const uint32_t*>(storage + kCurTurnDwordOffset);
}

namespace {

// 脚本全局注册项：owner = 注册时活跃插件名（空 = Loader 自身，插件卸载不撤销）。
// fn 指向插件映像内代码，插件卸载时必须移除，否则 RegisterScriptData detour
// 会调进已 FreeLibrary 的内存（与 OnMessage 悬空 handler 同类问题）。
struct ScriptGlobalsEntry {
    std::wstring owner;
    ScriptGlobalsFn fn;
};

std::vector<ScriptGlobalsEntry> g_scriptGlobals;
std::vector<ScriptGlobalsEntry> g_scriptGlobalsUI;
ProxyTypes::RegisterScriptData g_origRegisterScriptData = nullptr;
ProxyTypes::RegisterScriptDataForUI g_origRegisterScriptDataForUI = nullptr;
bool g_scriptHookInstalled = false;
bool g_scriptUIHookInstalled = false;
// 共享钩子的目标地址（GameCore 域）：GameCore 重载时据此摘钩。
void* g_scriptHookTarget = nullptr;
void* g_scriptUIHookTarget = nullptr;

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
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    return reg;
}

void __cdecl Hook_RegisterScriptData(hks::lua_State* L) {
    const auto snapshot = SnapshotScriptGlobals(g_scriptGlobals);
    Logger::Log("RegisterScriptData: running %zu plugin global registrar(s)", snapshot.size());
    size_t i = 0;
    for (const auto& entry : snapshot) {
        Logger::Log("RegisterScriptData: registrar[%zu] begin", i);
        CallScriptGlobalsSafe(entry.fn, reinterpret_cast<void*>(L));
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
    const auto snapshot = SnapshotScriptGlobals(g_scriptGlobalsUI);
    Logger::Log("RegisterScriptDataForUI: running %zu plugin global registrar(s)", snapshot.size());
    size_t i = 0;
    for (const auto& entry : snapshot) {
        Logger::Log("RegisterScriptDataForUI: registrar[%zu] begin", i);
        CallScriptGlobalsSafe(entry.fn, reinterpret_cast<void*>(L));
        Logger::Log("RegisterScriptDataForUI: registrar[%zu] end", i);
        ++i;
    }
    if (g_origRegisterScriptDataForUI) {
        Logger::Log("RegisterScriptDataForUI: calling original");
        g_origRegisterScriptDataForUI(unused, L);
        Logger::Log("RegisterScriptDataForUI: original returned");
    }
}

// 装共享钩（owner 固定 = Loader）。ALREADY_CREATED = 旧 GameCore 映像残留的
// MinHook 记录（地址复用）：摘除后重装一次，强制按新映像重打补丁。
// g_*HookTarget 记录目标地址，供 GameCore 重载时摘钩。
static bool InstallSharedHook(void* target, void* detour, void** orig, void** targetSlot) {
    if (InstallHookOwnedBy(target, detour, orig, L"")) {
        *targetSlot = target;
        return true;
    }
    if (SafeRemoveHook(target) && InstallHookOwnedBy(target, detour, orig, L"")) {
        *targetSlot = target;
        return true;
    }
    return false;
}

// 确保已注册回调对应的共享钩子已装上。三条调用路径：
//  1) 插件 RegisterScriptGlobals 首次注册（原有路径）；
//  2) GameCore 重载后 InitializeGameCorePhase 再调（钩子已随 ResetForReload 摘除，
//     回调列表跨重载保留——Global 插件仍加载着，其注册项不丢）；
//  3) 阶段 B 首次进入时列表已非空（Global 插件在阶段 A 注册过）。
// 检查+安装整体持锁，消除并发首装的重复创建竞态。
static void EnsureScriptHooksInstalled() {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);

    if (!g_scriptHookInstalled && !g_scriptGlobals.empty()) {
        void* target = GetFunctionByNameImpl("GameCore::RegisterScriptData");
        if (!target) {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptData address missing");
        } else if (InstallSharedHook(target, reinterpret_cast<void*>(&Hook_RegisterScriptData),
                       reinterpret_cast<void**>(&g_origRegisterScriptData), &g_scriptHookTarget)) {
            g_scriptHookInstalled = true;
            Logger::Log("EnsureScriptHooksInstalled: hooked RegisterScriptData at %p", target);
        }
    }
    if (!g_scriptUIHookInstalled && !g_scriptGlobalsUI.empty()) {
        void* target = GetFunctionByNameImpl("GameCore::RegisterScriptDataForUI");
        if (!target) {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptDataForUI address missing");
        } else if (InstallSharedHook(target, reinterpret_cast<void*>(&Hook_RegisterScriptDataForUI),
                       reinterpret_cast<void**>(&g_origRegisterScriptDataForUI), &g_scriptUIHookTarget)) {
            g_scriptUIHookInstalled = true;
            Logger::Log("EnsureScriptHooksInstalled: hooked RegisterScriptDataForUI at %p", target);
        }
    }
}

}  // namespace

void RegisterScriptGlobalsImpl(ScriptGlobalsFn fn) {
    if (fn) {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        g_scriptGlobals.push_back(ScriptGlobalsEntry{ g_activePluginName, fn });
    }
    if (g_scriptHookInstalled) return;
    EnsureScriptHooksInstalled();  // 检查+安装整体在锁内（含并发首装与重载后重装）
}

void RegisterScriptGlobalsForUIImpl(ScriptGlobalsFn fn) {
    if (fn) {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        g_scriptGlobalsUI.push_back(ScriptGlobalsEntry{ g_activePluginName, fn });
    }
    if (g_scriptUIHookInstalled) return;
    EnsureScriptHooksInstalled();
}

namespace {

constexpr int kMaxPushHooks = 16;

struct NoManagerHookSlot {
    void* target = nullptr;
    PushMethodsNoFunc base = nullptr;
    vector<StoredLuaMethod> methods;
    bool used = false;
};

struct WithManagerHookSlot {
    void* target = nullptr;
    PushMethodsWithFunc base = nullptr;
    vector<StoredLuaMethod> methods;
    bool used = false;
};

NoManagerHookSlot g_noManagerSlots[kMaxPushHooks];
WithManagerHookSlot g_withManagerSlots[kMaxPushHooks];

template<int I>
void __fastcall DetourPushNoManager(hks::lua_State* L, int stackOffset) {
    // 拷贝快照后在锁外回调：methods 可能被 Loader 工作线程（插件卸载清理）并发修改，
    // 快照同时把函数指针与 internalName/exposedName 字符串一并拷贝，锁外安全使用。
    std::vector<StoredLuaMethod> methods;
    PushMethodsNoFunc base = nullptr;
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        methods = g_noManagerSlots[I].methods;
        base = g_noManagerSlots[I].base;
    }
    for (auto& method : methods) {
        PushLuaMethod(L, reinterpret_cast<hks::luaFunc>(method.luaMethodFunc),
            method.internalName.c_str(), stackOffset, method.exposedName.c_str());
    }
    if (base) {
        base(L, stackOffset);
    }
}

template<int I>
void __fastcall DetourPushWithManager(void* manager, hks::lua_State* L, int stackOffset) {
    std::vector<StoredLuaMethod> methods;
    PushMethodsWithFunc base = nullptr;
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        methods = g_withManagerSlots[I].methods;
        base = g_withManagerSlots[I].base;
    }
    for (auto& method : methods) {
        PushLuaMethod(L, reinterpret_cast<hks::luaFunc>(method.luaMethodFunc),
            method.internalName.c_str(), stackOffset, method.exposedName.c_str());
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

// 追加方法并登记 owner（OnLoad 期间 = 插件 stem），插件卸载时按此撤销。
static void AppendOwnedMethods(std::vector<StoredLuaMethod>& dst, const std::vector<StoredLuaMethod>& src) {
    std::vector<StoredLuaMethod> owned = src;
    const std::wstring owner = g_activePluginName[0] ? g_activePluginName : L"";
    for (auto& m : owned) {
        m.owner = owner;
    }
    dst.insert(dst.end(), owned.begin(), owned.end());
}

void* InstallPushMethodsNoManager(void* target, const std::vector<StoredLuaMethod>& methods) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    // G3: MinHook 调用统一串行在 g_hookMutex 上（与 InstallHookOwnedBy 一致），
    // 不依赖 MinHook 内部线程安全；锁序恒为 lifecycle → hook，单向无死锁。
    lock_guard<mutex> hookLock(g_hookMutex);
    const int slot = FindOrAllocNoManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsNoManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_noManagerSlots[slot];
    if (state.base) {
        // 已 hook 同一 target：只追加方法，返回既有 trampoline。
        AppendOwnedMethods(state.methods, methods);
        return reinterpret_cast<void*>(state.base);
    }

    // 新槽：先建钩启用，全部成功后才登记方法；任一步失败完整回滚槽位与
    // MinHook 记录——否则半初始化槽位会让重试重复追加方法或返回失效 trampoline。
    MH_STATUS status = MH_CreateHook(target, NoManagerDetourTable[slot], reinterpret_cast<void**>(&state.base));
    if (status != MH_OK) {
        Logger::Log("InstallPushMethodsNoManager: create hook failed %s", MH_StatusToString(status));
        state = NoManagerHookSlot{};
        return nullptr;
    }
    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallPushMethodsNoManager: enable hook failed %s", MH_StatusToString(status));
        MH_RemoveHook(target);
        state = NoManagerHookSlot{};
        return nullptr;
    }
    AppendOwnedMethods(state.methods, methods);
    return reinterpret_cast<void*>(state.base);
}

void* InstallPushMethodsWithManager(void* target, const std::vector<StoredLuaMethod>& methods) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    lock_guard<mutex> hookLock(g_hookMutex);  // G3: 同上，MinHook 调用统一串行
    const int slot = FindOrAllocWithManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsWithManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_withManagerSlots[slot];
    if (state.base) {
        AppendOwnedMethods(state.methods, methods);
        return reinterpret_cast<void*>(state.base);
    }

    MH_STATUS status = MH_CreateHook(target, WithManagerDetourTable[slot], reinterpret_cast<void**>(&state.base));
    if (status != MH_OK) {
        Logger::Log("InstallPushMethodsWithManager: create hook failed %s", MH_StatusToString(status));
        state = WithManagerHookSlot{};
        return nullptr;
    }
    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallPushMethodsWithManager: enable hook failed %s", MH_StatusToString(status));
        MH_RemoveHook(target);
        state = WithManagerHookSlot{};
        return nullptr;
    }
    AppendOwnedMethods(state.methods, methods);
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

// 有返回值包装：导入缺失 → 限次日志 + fallback。
#define HKS_GUARD_RET(fnPtr, fallback, ...) \
    do { \
        if (!(fnPtr)) { WarnHksImportMissing(#fnPtr); return (fallback); } \
        return (fnPtr)(__VA_ARGS__); \
    } while (0)

// void 包装：导入缺失 → 限次日志 + 直接返回。
#define HKS_GUARD_VOID(fnPtr, ...) \
    do { \
        if (!(fnPtr)) { WarnHksImportMissing(#fnPtr); return; } \
        return (fnPtr)(__VA_ARGS__); \
    } while (0)

void LuaPushNamedCClosureImpl(void* L, void* func, int a, const char* name, int b) {
    HKS_GUARD_VOID(hks::pushnamedcclosure, reinterpret_cast<hks::lua_State*>(L),
        reinterpret_cast<hks::luaFunc>(func), a, name, b);
}

int LuaCheckIntegerImpl(void* L, int index) {
    HKS_GUARD_RET(hks::checkinteger, 0, reinterpret_cast<hks::lua_State*>(L), index);
}

double LuaCheckNumberImpl(void* L, int index) {
    HKS_GUARD_RET(hks::checknumber, 0.0, reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaSetFieldImpl(void* L, int stackOffset, const char* name) {
    HKS_GUARD_VOID(hks::setfield, reinterpret_cast<hks::lua_State*>(L), stackOffset, name);
}

int LuaGetTopImpl(void* L) {
    HKS_GUARD_RET(hks::gettop, 0, reinterpret_cast<hks::lua_State*>(L));
}

int LuaDoStringImpl(void* L, const char* str) {
    HKS_GUARD_RET(hks::dostring, 0, reinterpret_cast<hks::lua_State*>(L), str);
}

int LuaToBooleanImpl(void* L, int index) {
    HKS_GUARD_RET(hks::toboolean, 0, reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaPushNumberImpl(void* L, double num) {
    HKS_GUARD_VOID(hks::pushnumber, reinterpret_cast<hks::lua_State*>(L), num);
}

void LuaPushIntegerImpl(void* L, int num) {
    // G12: 语义对齐——API 承诺压整数，用 hksi_lua_pushinteger 压整数标记值
    // （此前走 pushnumber 是历史遗留，hks 开启 IntLiterals 时两者字节码可区分）。
    HKS_GUARD_VOID(hks::pushinteger, reinterpret_cast<hks::lua_State*>(L), num);
}

void LuaErrorImpl(void* L, char const* str, ...) {
    if (!hks::error) {
        WarnHksImportMissing("hks::error");
        return;
    }
    char buffer[1024];
    va_list args;
    va_start(args, str);
    vsnprintf(buffer, sizeof(buffer), str, args);
    va_end(args);
    hks::error(reinterpret_cast<hks::lua_State*>(L), "%s", buffer);
}

char const* LuaPushFStringImpl(void* L, char const* str, ...) {
    if (!hks::pushfstring) {
        WarnHksImportMissing("hks::pushfstring");
        return nullptr;
    }
    char buffer[1024];
    va_list args;
    va_start(args, str);
    vsnprintf(buffer, sizeof(buffer), str, args);
    va_end(args);
    return hks::pushfstring(reinterpret_cast<hks::lua_State*>(L), "%s", buffer);
}

char const* LuaCheckLStringImpl(void* L, int index, unsigned __int64* a) {
    HKS_GUARD_RET(hks::checklstring, nullptr, reinterpret_cast<hks::lua_State*>(L), index, a);
}

void* LuaToUserDataImpl(void* L, int index) {
    HKS_GUARD_RET(hks::touserdata, nullptr, reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaGetFieldImpl(void* L, int a, char const* b) {
    HKS_GUARD_VOID(hks::getfield, reinterpret_cast<hks::lua_State*>(L), a, b);
}

void LuaPopImpl(void* L, int a) {
    HKS_GUARD_VOID(hks::pop, reinterpret_cast<hks::lua_State*>(L), a);
}

void LuaCreateTableImpl(void* L, int a, int b) {
    HKS_GUARD_VOID(hks::createtable, reinterpret_cast<hks::lua_State*>(L), a, b);
}

void* LuaToCFunctionImpl(void* L, int index) {
    if (!hks::tocfunction) {
        WarnHksImportMissing("hks::tocfunction");
        return nullptr;
    }
    return reinterpret_cast<void*>(hks::tocfunction(reinterpret_cast<hks::lua_State*>(L), index));
}

void LuaCheckTableImpl(void* L, int index) {
    HKS_GUARD_VOID(hks::checktable, reinterpret_cast<hks::lua_State*>(L), index);
}

unsigned long long LuaObjLenImpl(void* L, int index) {
    HKS_GUARD_RET(hks::objlen, 0, reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaGetTableImpl(void* L, int index) {
    HKS_GUARD_VOID(hks::gettable, reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaCPcallImpl(void* L, int a, void* func, int b) {
    HKS_GUARD_VOID(hks::cpcall, reinterpret_cast<hks::lua_State*>(L), a,
        reinterpret_cast<hks::luaFunc>(func), b);
}

int LuaRefImpl(void* L, int index) {
    HKS_GUARD_RET(hks::ref, 0, reinterpret_cast<hks::lua_State*>(L), index);
}

int LuaPcallImpl(void* L, int a, int b, int c) {
    HKS_GUARD_RET(hks::pcall, 0, reinterpret_cast<hks::lua_State*>(L), a, b, c);
}

void LuaPushValueImpl(void* L, int value) {
    HKS_GUARD_VOID(hks::pushvalue, reinterpret_cast<hks::lua_State*>(L), value);
}

void LuaRawGetIImpl(void* L, int a, int b) {
    HKS_GUARD_VOID(hks::rawgeti, reinterpret_cast<hks::lua_State*>(L), a, b);
}

void LuaUnrefImpl(void* L, int a, int b) {
    HKS_GUARD_VOID(hks::unref, reinterpret_cast<hks::lua_State*>(L), a, b);
}

void LuaSetTableImpl(void* L, int t) {
    HKS_GUARD_VOID(hks::settable, reinterpret_cast<hks::lua_State*>(L), t);
}

int LuaIsNumberImpl(void* L, int num) {
    HKS_GUARD_RET(hks::isnumber, 0, reinterpret_cast<hks::lua_State*>(L), num);
}

double LuaToNumberImpl(void* L, int num) {
    HKS_GUARD_RET(hks::tonumber, 0.0, reinterpret_cast<hks::lua_State*>(L), num);
}

int LuaIsUserDataImpl(void* L, int num) {
    HKS_GUARD_RET(hks::isuserdata, 0, reinterpret_cast<hks::lua_State*>(L), num);
}

int LuaOpenDebugImpl(void* L) {
    HKS_GUARD_RET(hks::luaopen_debug, 0, reinterpret_cast<hks::lua_State*>(L));
}

int LuaToIntegerImpl(void* L, int num) {
    HKS_GUARD_RET(hks::tointeger, 0, reinterpret_cast<hks::lua_State*>(L), num);
}

int LuaTypeImpl(void* L, int num) {
    HKS_GUARD_RET(hks::type, 0, reinterpret_cast<hks::lua_State*>(L), num);
}

int LuaOptIntegerImpl(void* L, int a, int b) {
    HKS_GUARD_RET(hks::optinteger, b, reinterpret_cast<hks::lua_State*>(L), a, b);
}

int LuaSetHookImpl(void* L, void* a, int b, int c) {
    HKS_GUARD_RET(hks::sethook, 0, reinterpret_cast<hks::lua_State*>(L), a, b, c);
}

void* LuaGetHookImpl(void* L) {
    HKS_GUARD_RET(hks::gethook, nullptr, reinterpret_cast<hks::lua_State*>(L));
}

int LuaGetHookMaskImpl(void* L) {
    HKS_GUARD_RET(hks::gethookmask, 0, reinterpret_cast<hks::lua_State*>(L));
}

int LuaGetHookCountImpl(void* L) {
    HKS_GUARD_RET(hks::gethookcount, 0, reinterpret_cast<hks::lua_State*>(L));
}

int LuaCheckPlayerIdImpl(void* L, int index) {
    return hks::checkplayerid(reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaPushBooleanImpl(void* L, bool value) {
    hks::pushboolean(reinterpret_cast<hks::lua_State*>(L), value);
}

void LuaPushLightUserDataImpl(void* L, void* ptr) {
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
    if (!L || !fieldName || !fn) return;
    if (!hks::pushnamedcclosure || !hks::setfield) {
        WarnHksImportMissing("hks::pushnamedcclosure/setfield");
        return;
    }
    const char* iname = internalName && *internalName ? internalName : fieldName;
    auto* state = reinterpret_cast<hks::lua_State*>(L);
    // pushnamedcclosure grows the stack by 1; relative negative indices must be
    // adjusted so they still refer to the table (e.g. -1 -> -2), matching
    // Example2's explicit LuaSetField(L, -2, ...).
    const int idx = (tableIndex < 0) ? (tableIndex - 1) : tableIndex;
    hks::pushnamedcclosure(state, reinterpret_cast<hks::luaFunc>(fn), 0, iname, 0);
    hks::setfield(state, idx, fieldName);
}

void LuaNewGlobalTableImpl(void* L, const char* globalName, int narr, int nrec) {
    if (!L || !globalName) return;
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

using SendGameEventFn = int64_t*(__fastcall*)(int64_t eventId, unsigned int a, unsigned int b);
using EditPlayerFn = void*(__fastcall*)(int playerId);
using GetCivDescFn = const char*(__fastcall*)(void* player);
using MakeHashFn = uint32_t(__fastcall*)(const char* str);

static SendGameEventFn ResolveSendGameEvent() {
    return reinterpret_cast<SendGameEventFn>(
        GetFunctionByNameImpl("GameCore::Reporting::Event::Send"));
}
static EditPlayerFn ResolveEditPlayer() {
    return reinterpret_cast<EditPlayerFn>(
        GetFunctionByNameImpl("GameCore::Context::Globals::EditPlayer"));
}
static GetCivDescFn ResolveGetCivDesc() {
    return reinterpret_cast<GetCivDescFn>(
        GetFunctionByNameImpl("GameCore::Player::Instance::GetCivilizationDescription"));
}
static MakeHashFn ResolveMakeHash() {
    return reinterpret_cast<MakeHashFn>(
        GetFunctionByNameImpl("GameCore::Utilities::MakeHash"));
}

int64_t SendGameEventImpl(int64_t eventId, unsigned int a, unsigned int b) {
    auto fn = ResolveSendGameEvent();
    if (!fn) {
        Logger::Log("SendGameEvent: symbol missing");
        return 0;
    }
    auto* r = fn(eventId, a, b);
    return reinterpret_cast<int64_t>(r);
}

void* EditPlayerImpl(int playerId) {
    auto fn = ResolveEditPlayer();
    if (!fn) {
        Logger::Log("EditPlayer: symbol missing");
        return nullptr;
    }
    return fn(playerId);
}

const char* GetCivilizationDescriptionImpl(void* player) {
    if (!player) return nullptr;
    auto fn = ResolveGetCivDesc();
    if (!fn) {
        Logger::Log("GetCivilizationDescription: symbol missing");
        return nullptr;
    }
    return fn(player);
}

uint32_t MakeHashImpl(const char* str) {
    auto fn = ResolveMakeHash();
    if (!fn || !str) return 0;
    return fn(str);
}

void* RequireFunctionImpl(const char* functionName) {
    void* p = GetFunctionByNameImpl(functionName);
    if (!p) {
        Logger::Log("RequireFunction: missing %s", functionName ? functionName : "(null)");
    }
    return p;
}

int ResolveSymbolImpl(const char* functionName, void** out) {
    if (!out) return 0;
    *out = GetFunctionByNameImpl(functionName);
    return *out ? 1 : 0;
}

int RegisterGameCoreRvaImpl(const char* name, uint32_t rva) {
    if (rva == 0 || rva >= g_GameCoreSizeOfImage) {
        Logger::Log("RegisterGameCoreRva: out-of-range name=%s rva=0x%X image=0x%X",
            name ? name : "(null)", rva, g_GameCoreSizeOfImage);
        return 0;
    }
    if (!SymbolDb::RegisterRva(name, rva)) {
        Logger::Log("RegisterGameCoreRva: rejected name=%s rva=0x%X",
            name ? name : "(null)", rva);
        return 0;
    }
    Logger::Log("RegisterGameCoreRva: %s -> 0x%X", name, rva);
    return 1;
}

int RegisterPushMethodsTargetImpl(const char* name, int sigType, const char* pushMethodsSymbol) {
    if (!name || !*name) return 0;
    if (sigType != kHookApiPushNoManager && sigType != kHookApiPushWithManager) {
        Logger::Log("RegisterPushMethodsTarget: bad sigType %d for %s", sigType, name);
        return 0;
    }
    // M2: 表写入与 PushLuaMethodsImpl 的读取跨线程共享，持锁修改。
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    g_MethodSignatureTable[name] = (sigType == kHookApiPushWithManager)
        ? PushMethodSigType::WithManager
        : PushMethodSigType::NoManager;

    std::string sym = pushMethodsSymbol && *pushMethodsSymbol
        ? pushMethodsSymbol
        : (std::string(name) + "::PushMethods");
    // Ensure GetFunctionByName can resolve the PushMethods symbol if only alias name differs.
    if (pushMethodsSymbol && *pushMethodsSymbol) {
        const uint32_t rva = SymbolDb::LookupRva(pushMethodsSymbol);
        if (rva != 0) {
            const std::string key = std::string(name) + "::PushMethods";
            SymbolDb::RegisterRva(key.c_str(), rva);
        }
    }
    Logger::Log("RegisterPushMethodsTarget: %s sig=%d sym=%s", name, sigType, sym.c_str());
    return 1;
}

// ---------------- Patch/Unpatch (v2) ----------------

static bool HookPatch(void* target, const void* bytes, size_t len) {
    return PatchRegistry::Apply(target, bytes, len,
        g_activePluginName[0] ? g_activePluginName : L"unknown");
}

static bool HookUnpatch(void* target) {
    return PatchRegistry::Revert(target);
}

static HookAPI g_hookApi = {
    CIV6_HOOK_API_VERSION,
    static_cast<uint32_t>(sizeof(HookAPI)),

    &InstallHookImpl,
    &BroadcastMessageImpl,
    &RegisterMessageHandlerImpl,
    &SendMessageToImpl,

    &GetGameCoreAddressImpl,
    &GetFunctionByNameImpl,
    &GetFunctionByAddressImpl,
    &PushLuaMethodsImpl,

    &GetCurTurnImpl,

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

    &LocalizationLookupImpl,

    &LogImpl,
    &LuaPushCFunctionFieldImpl,
    &LuaNewGlobalTableImpl,

    &LocStringBytesImpl,
    &LocCreateImpl,
    &LocDestroyImpl,
    &LocLookupImpl,
    &LocPushArgumentImpl,
    &LocToUtf8Impl,

    &SendGameEventImpl,
    &EditPlayerImpl,
    &GetCivilizationDescriptionImpl,
    &MakeHashImpl,

    &RequireFunctionImpl,
    &ResolveSymbolImpl,
    &RegisterGameCoreRvaImpl,
    &RegisterPushMethodsTargetImpl,

    &HookPatch,
    &HookUnpatch,
};

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
    const DWORD sizeOfImage = GetModuleSizeOfImage(gameCore);
    const uint32_t expected = SymbolDb::ExpectedSizeOfImage();
    if (sizeOfImage == 0) {
        Logger::Log("GameCore rejected: invalid PE image");
        return false;
    }
    if (expected != 0 && sizeOfImage != expected) {
        Logger::Log("GameCore rejected: SizeOfImage mismatch symbols=0x%08X actual=0x%08X",
            expected, sizeOfImage);
        return false;
    }

    g_GameCoreAddress = reinterpret_cast<uintptr_t>(gameCore);
    g_GameCoreSizeOfImage = sizeOfImage;

    Logger::Log("GameCore attached base=0x%llX SizeOfImage=0x%08X",
        static_cast<unsigned long long>(g_GameCoreAddress), sizeOfImage);
    return true;
}

static bool CallOnLoadSafe(OnLoadFunc onLoad, const char* name) {
    __try {
        onLoad(&g_hookApi);
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

// 前置声明：G2 崩溃隔离要用与卸载同一套 owner 清理（定义在本文件后部）。
static void RemovePluginHooks(const wchar_t* owner);
static void RemovePluginOwnedLuaEntries(const std::wstring& owner);

// v2 统一插件加载流程：LoadLibraryExW + OnLoad(SEH) + OnMessage 自动注册 + 记录跟踪项。
// nameNarrow = 显示名（通常为文件名，内部取 stem 作 Patch owner / OnMessage 名）；已加载（同句柄）返回 false。
static bool LoadPluginDllInternal(const std::wstring& wpath, const std::string& nameNarrow,
    LoaderCore::PluginCategory category) {
    // 全程持锁（含 OnLoad）：与卸载/reconcile 路径互斥，g_plugins 的查重与
    // push_back 原子化；OnLoad 内再调用 HookAPI 注册入口由递归锁重入。
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);

    // G5: 已驻留模块（禁用后未卸载）用 UNCHANGED_REFCOUNT 取回，"禁用→启用"循环
    // 不再累计引用计数；未映射才真正加载。ownsRef 标记引用是否归本调用所有，
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

    for (const auto& entry : g_plugins) {
        if (entry.handle == hPlugin) {
            if (ownsRef) FreeLibrary(hPlugin);
            return false;
        }
    }

    auto onLoad = (OnLoadFunc)GetProcAddress(hPlugin, "OnLoad");
    if (!onLoad) {
        Logger::Log("Plugin has no OnLoad export: %s", ModScan::WideToNarrow(wpath).c_str());
        if (ownsRef) FreeLibrary(hPlugin);
        return false;
    }

    const std::string narrow = ModScan::WideToNarrow(wpath);

    // 插件 stem（文件名去掉扩展名）作为 Patch owner；与 OnMessage 自动注册名一致。
    std::wstring pluginStem;
    {
        std::string stemName = nameNarrow.empty() ? narrow : nameNarrow;
        const size_t dot = stemName.find_last_of('.');
        if (dot != std::string::npos) stemName = stemName.substr(0, dot);
        pluginStem = ModScan::NarrowToWide(stemName);
    }
    Logger::Log("Loaded plugin %s (%s)", nameNarrow.c_str(), narrow.c_str());

    PluginEntry entry;
    entry.handle = hPlugin;
    entry.path = wpath;
    entry.name = pluginStem;
    entry.category = category;
    g_plugins.push_back(std::move(entry));

    // OnLoad 期间暴露"当前插件名"给 Patch 作 owner；SEH 由 CallOnLoadSafe 包裹，
    // 无论 OnLoad 正常返回还是崩溃，都要在返回后清空，防止污染后续插件。
    SetActivePluginName(pluginStem.c_str());
    const bool onLoadOk = CallOnLoadSafe(onLoad, nameNarrow.c_str());
    SetActivePluginName(nullptr);

    if (!onLoadOk) {
        // 崩溃隔离（G2）：仅驻留模块不够——半初始化插件已注册的补丁/钩子/Lua 方法/
        // OnMessage 可能仍生效。按 owner 执行与正常卸载同一套回滚（模块保持映射，
        // 驻留策略保证回滚后残留指针依然安全）。跟踪项保留在 g_plugins：
        // 一方面标记"已隔离"，另一方面防止阶段 B 全量扫描反复重试崩溃的 OnLoad。
        Logger::Log("Plugin quarantined after OnLoad failure: %s", narrow.c_str());
        PatchRegistry::RevertAllFor(pluginStem.c_str());
        RemovePluginHooks(pluginStem.c_str());
        RemovePluginOwnedLuaEntries(pluginStem);
        g_bus.UnregisterHandler(ModScan::WideToNarrow(pluginStem));
        return false;
    }

    auto onMessage = (OnMessageFunc)GetProcAddress(hPlugin, "OnMessage");
    if (onMessage) {
        // Register under filename stem so SendMessageTo("Example1", ...) works.
        string handlerName = nameNarrow.empty() ? narrow : nameNarrow;
        const size_t dot = handlerName.find_last_of('.');
        if (dot != string::npos) handlerName = handlerName.substr(0, dot);
        RegisterMessageHandlerImpl(handlerName.c_str(), onMessage);
        Logger::Log("Auto-registered OnMessage for %s", handlerName.c_str());
    }
    return true;
}

void LoadPluginDLL(const char* name, const string& path) {
    const std::wstring wpath = ModScan::NarrowToWide(path);
    LoadPluginDllInternal(wpath, name ? name : "", CategoryForPath(wpath));
}

void OnLoaderMessage(const char* topic, const void* data, size_t len) {
    Logger::Log("OnLoaderMessage %s", topic ? topic : "");
    if (topic && data && strcmp(topic, "load-plugin") == 0 && len > 0) {
        string path((const char*)data, len);
        LoadPluginDLL("loader", path);
    }
}

bool InitializeLoader(HMODULE hModule) {
    // v1 时代还记录模块句柄供 GetCurrentModuleDir 使用；该路径已随 v1 死代码清理
    // 删除，现在只注册 "Loader" 消息处理器（load-plugin 遗留入口，保持兼容）。
    (void)hModule;
    RegisterMessageHandlerImpl("Loader", OnLoaderMessage);
    return true;
}

// ================= LoaderCore 实现（S3c：插件生命周期 v2） =================

// 撤销某插件通过 HookAPI.InstallHook 注册的全部 MinHook 钩子（Disable + Remove）。
// 在卸载插件的 FreeLibrary 之前调用；owner 为插件 stem（空串代表 Loader 自身，不在此撤销）。
static void RemovePluginHooks(const wchar_t* owner) {
    if (!owner || !*owner) return;
    lock_guard<mutex> lock(g_hookMutex);
    for (auto it = g_pluginHookOwners.begin(); it != g_pluginHookOwners.end(); ) {
        if (it->second == owner) {
            void* target = it->first;
            // SafeRemoveHook：目标可能位于已卸载的旧 GameCore 映像（重载兜底路径），
            // 此时跳过 MinHook 移除，仅清簿记。
            SafeRemoveHook(target);
            it = g_pluginHookOwners.erase(it);
            Logger::Log("RemovePluginHooks: removed hook at %p (owner=%ls)", target, owner);
        } else {
            ++it;
        }
    }
}

// 撤销某插件注册的全部 Lua 方法与脚本全局回调（FreeLibrary 之前调用）：
// 这些条目持有指向插件映像的函数指针，不清就会在 PushMethods detour /
// RegisterScriptData detour 里调进已释放内存（与 OnMessage 悬空 handler 同类问题）。
// 槽位的 methods 清空后保留已装 hook（detour 只透传 base）：避免在游戏可能
// 正在执行 detour 时摘共享钩；后续同 target 再注册会复用该槽。
static void RemovePluginOwnedLuaEntries(const std::wstring& owner) {
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

    const size_t globals = removeOwnedBy(g_scriptGlobals);
    const size_t globalsUi = removeOwnedBy(g_scriptGlobalsUI);

    size_t methods = 0;
    for (auto& slot : g_noManagerSlots) {
        if (slot.used) methods += removeOwnedBy(slot.methods);
    }
    for (auto& slot : g_withManagerSlots) {
        if (slot.used) methods += removeOwnedBy(slot.methods);
    }

    Logger::Log("RemovePluginOwnedLuaEntries: owner=%ls globals=%zu globalsUI=%zu luaMethods=%zu",
        owner.c_str(), globals, globalsUi, methods);
}

// 按跟踪项卸载单个插件（调用方保证 index 有效）：
// OnUnload → PatchRegistry::RevertAllFor(name) → RemovePluginHooks(name) → FreeLibrary，语义与 S2a 接线一致。
static void UnloadPluginEntryAt(size_t index) {
    // 全程持锁（含 OnUnload）；上层 LoadPluginsOf/Reconcile 等入口也会先取锁，递归重入。
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);

    PluginEntry entry = std::move(g_plugins[index]);
    g_plugins.erase(g_plugins.begin() + index);

    auto onUnload = (OnUnloadFunc)GetProcAddress(entry.handle, "OnUnload");
    // 暴露当前插件名：OnUnload 期间若有 Patch 调用也归到该 owner。
    SetActivePluginName(entry.name.c_str());
    if (onUnload) CallOnUnloadSafe(onUnload, nullptr);
    // 先 OnUnload 后回滚补丁：插件 OnUnload 可能仍依赖自己的补丁。
    // 必须在 FreeLibrary 之前回滚——补丁目标可能位于该插件自身映像内。
    if (g_activePluginName[0]) {
        PatchRegistry::RevertAllFor(g_activePluginName);
    }
    // 撤销该插件的 MinHook 钩子：否则 GameCore 重载后重新 OnLoad 会撞 MH_ERROR_ALREADY_CREATED。
    RemovePluginHooks(g_activePluginName);
    // 撤销该插件注册的 Lua 方法与脚本全局回调（见 RemovePluginOwnedLuaEntries）。
    RemovePluginOwnedLuaEntries(entry.name);
    // 注销 OnMessage：否则 bus 里残留指向本映像的 handler，FreeLibrary 后广播/定向发送会跳进已释放内存。
    const std::string handlerName = ModScan::WideToNarrow(entry.name);
    if (!handlerName.empty()) {
        g_bus.UnregisterHandler(handlerName);
    }
    SetActivePluginName(nullptr);
    // 不 FreeLibrary：游戏线程可能仍在该插件的 detour/回调内执行（MH_DisableHook
    // 不等待在飞调用，RegisterScriptData 等回调也没有引用计数），此刻卸下映像会把
    // 正在执行的代码变成 UAF。改为驻留模块（hook 框架的标准做法）：映像保持映射
    // 但休眠——钩已摘、补丁已回滚、Lua 方法/回调/OnMessage 已注销，不会再被调用。
    // 代价是该插件重启用时静态状态跨周期保留，OnLoad 必须可重入（重新注册其
    // 钩子/回调）；这与全新加载路径对插件的要求一致。
    Logger::Log("Plugin deactivated, module parked (kept mapped): %s",
        ModScan::WideToNarrow(entry.path).c_str());
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
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    size_t unloaded = 0;
    for (size_t i = g_plugins.size(); i-- > 0; ) {
        if (g_plugins[i].category != cat) continue;
        UnloadPluginEntryAt(i);
        ++unloaded;
    }
    Logger::Log("UnloadPluginsOf(%s): unloaded=%zu remaining=%zu",
        CategoryNameForLog(cat), unloaded, g_plugins.size());
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

void LoaderCore::UnloadSinglePlugin(const std::wstring& path) {
    const std::wstring norm = NormalizePluginPath(path);
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    for (size_t i = 0; i < g_plugins.size(); ++i) {
        if (NormalizePluginPath(g_plugins[i].path) != norm) continue;
        UnloadPluginEntryAt(i);
        Logger::Log("UnloadSinglePlugin: %s", ModScan::WideToNarrow(path).c_str());
        return;
    }
    // 未加载：no-op
}

bool LoaderCore::InitializeGameCorePhase() {
    HMODULE gm = GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll");
    if (!gm) {
        Logger::Log("InitializeGameCorePhase: GameCore_XP2_FinalRelease.dll not loaded");
        return false;
    }
    if (!AttachGameCore(gm)) {
        Logger::Log("InitializeGameCorePhase: AttachGameCore failed");
        return false;
    }
    // v2 无薄壳：以当前进程 exe 模块作扫描锚。
    if (!InitializeLoader(GetModuleHandleW(nullptr))) {
        Logger::Log("InitializeGameCorePhase: InitializeLoader failed");
        return false;
    }
    // HavokScript 导入缺失 = Lua API 半可用，对插件是崩溃源：停用 GameCore 插件
    // 加载（本会话游戏本体照常运行）。
    if (!hks::InitHavokScript()) {
        Logger::Log("InitializeGameCorePhase: InitHavokScript incomplete; GameCore plugins disabled");
        return false;
    }
    Localization::InitScript();
    // GameCore 重载后重装共享脚本钩（ResetForReload 已摘除；回调列表跨重载保留）。
    // 首次进入时若 Global 插件已在阶段 A 注册过脚本全局，也在此一并装钩。
    EnsureScriptHooksInstalled();
    g_gameCorePhaseReady = true;
    Logger::Log("InitializeGameCorePhase: OK");
    return true;
}

void LoaderCore::ReconcileGlobalPlugins() {
    // 扫描（文件系统/sqlite）在锁外；下方对 g_plugins 的 diff 与加载/卸载整体持锁，
    // 与游戏线程的 LoadPluginsOf（LoadDLL detour 内）串行化。
    const auto expected = ModScan::FindGlobalPluginCandidates(LoaderCore::RuntimeModuleHandle());

    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);

    std::unordered_set<std::wstring> expectedNorm;
    expectedNorm.reserve(expected.size());
    for (const auto& wpath : expected) {
        expectedNorm.insert(NormalizePluginPath(wpath));
    }

    // 先卸载"当前有而期望无"的 Global 插件。
    std::vector<std::wstring> toUnload;
    for (const auto& entry : g_plugins) {
        if (entry.category != PluginCategory::Global) continue;
        if (expectedNorm.count(NormalizePluginPath(entry.path))) continue;
        toUnload.push_back(entry.path);
    }
    for (const auto& wpath : toUnload) {
        UnloadSinglePlugin(wpath);
    }

    // 再加载"期望有而当前无"的 Global 插件。
    std::unordered_set<std::wstring> currentNorm;
    currentNorm.reserve(g_plugins.size());
    for (const auto& entry : g_plugins) {
        if (entry.category == PluginCategory::Global) {
            currentNorm.insert(NormalizePluginPath(entry.path));
        }
    }
    size_t loaded = 0;
    for (const auto& wpath : expected) {
        if (currentNorm.count(NormalizePluginPath(wpath))) continue;
        if (LoadSinglePlugin(wpath)) ++loaded;
    }

    Logger::Log("ReconcileGlobalPlugins: unloaded=%zu loaded=%zu tracked=%zu",
        toUnload.size(), loaded, g_plugins.size());
}

bool LoaderCore::IsInitialized() {
    return g_gameCorePhaseReady;
}

// GameCore 重载时的共享钩子复位（G1）：RegisterScriptData/ForUI 共享钩与全部
// PushMethods 槽位钩的目标都在旧 GameCore 映像内——映像卸载后补丁字节随映射消失，
// 而 MinHook 记录、g_scriptHookInstalled 标志、trampoline 指针全部残留：
//  - 若不复位：重进游戏后 detour 不再被调用（新映像是未打补丁的原始字节），
//    且 g_scriptHookInstalled=true 让重注册早退 → Lua 注入本会话永久失效；
//  - PushMethods 槽位还会按重载次数泄漏（上限 16 个）。
// 在 UnloadDllDetour 路径调用时旧映像仍存活，可干净摘钩；在 LoadDllDetour 重入
// 兜底路径调用时映像可能已卸载，SafeRemoveHook 自动跳过（残留记录由
// InstallSharedHook 的 ALREADY_CREATED 恢复路径处理）。
// 已注册的 ScriptGlobals 回调列表跨重载保留（Global 插件仍加载着），
// 由 EnsureScriptHooksInstalled 在新 GameCore attach 后重新装钩。
static void ResetSharedGameCoreHooks() {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);

    if (g_scriptHookTarget) {
        SafeRemoveHook(g_scriptHookTarget);
        g_scriptHookTarget = nullptr;
        g_scriptHookInstalled = false;
        g_origRegisterScriptData = nullptr;
    }
    if (g_scriptUIHookTarget) {
        SafeRemoveHook(g_scriptUIHookTarget);
        g_scriptUIHookTarget = nullptr;
        g_scriptUIHookInstalled = false;
        g_origRegisterScriptDataForUI = nullptr;
    }

    for (int i = 0; i < kMaxPushHooks; ++i) {
        if (g_noManagerSlots[i].used) {
            SafeRemoveHook(g_noManagerSlots[i].target);
            g_noManagerSlots[i] = NoManagerHookSlot{};
        }
        if (g_withManagerSlots[i].used) {
            SafeRemoveHook(g_withManagerSlots[i].target);
            g_withManagerSlots[i] = WithManagerHookSlot{};
        }
    }
    Logger::Log("ResetSharedGameCoreHooks: script/UI hooks + push slots reset");
}

void LoaderCore::ResetForReload() {
    // UnloadPluginsOf 自身不触碰初始化标志，天然无递归。
    UnloadPluginsOf(PluginCategory::GameCore);
    // 共享钩子（ScriptData/ForUI + PushMethods 槽位）目标在旧 GameCore 映像内，
    // 必须随重载复位，否则 Lua 注入在新映像下永久失效（见函数头注释）。
    ResetSharedGameCoreHooks();
    g_gameCorePhaseReady = false;
    Logger::Log("ResetForReload: GameCore plugins unloaded, shared hooks reset, phase-B flag cleared");
}
