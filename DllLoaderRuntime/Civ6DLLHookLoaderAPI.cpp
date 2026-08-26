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
#include "ImageAddress.h"

#include <cstdarg>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <atomic>
#include <condition_variable>
#include <intrin.h>
#include <optional>
#include <unordered_set>

#include "PatchRegistry.h"
#include "LoaderCore.h"

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
};
static vector<PluginEntry> g_plugins;

// 插件生命周期互斥锁（递归：OnLoad/OnUnload 期间插件会再调用 HookAPI 注册入口，
// 需要重入）。保护 g_plugins、脚本全局注册表与 PushMethods 槽位的全部读写：
// 游戏线程（LoadDLL/UnloadDLL detour → Load/UnloadPluginsOf）与 Loader 工作线程
// （ReconcileGlobalPlugins）在此串行化。Runtime::MinHookMutex（MinHook 调用 + owner 表）与
// PatchRegistry 的 CRITICAL_SECTION 保持独立，锁序恒为 lifecycle → hook/patch。
static std::recursive_mutex g_pluginLifecycleMutex;

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

enum class HookKind {
    Plugin,
    SharedScript,
    PushMethods,
};

struct HookRecord {
    std::wstring owner;  // 空 = Loader 共享钩
    HookKind kind = HookKind::Plugin;
    uint64_t gameCoreGeneration = 0;
};

static std::unordered_map<void*, HookRecord> g_hookRecords;

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

static uintptr_t g_gameCoreTeardownAddress;
static uint32_t g_gameCoreTeardownSizeOfImage;

static unordered_map<string, PushMethodSigType> g_MethodSignatureTable = {
    {"GameCore::Cache::Lua::IQuestsManager", PushMethodSigType::WithManager},
    {"GameCore::Lua::IQuestsManager", PushMethodSigType::NoManager},
};

struct PushRegistration {
    std::string targetName;
    PushMethodSigType signature = PushMethodSigType::NoManager;
    std::vector<StoredLuaMethod> methods;
    std::wstring owner;
};
static std::vector<PushRegistration> g_pushRegistrations;

// Symbol RVAs live in Civ6DllLoader.symbols.bin (see tools/pack_symbol_db.py).

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

static std::optional<std::wstring> ResolvePluginOwnerForAddress(const void* codeAddress) {
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
            return entry.ownerId;
        }
        if ((entry.state == PluginState::Loading ||
                entry.state == PluginState::Active) &&
                entry.handle == module) {
            return entry.ownerId;
        }
    }
    return std::nullopt;
}

static std::optional<std::wstring> RequirePluginOwner(const void* codeAddress,
                                                       const char* apiName) {
    auto owner = ResolvePluginOwnerForAddress(codeAddress);
    if (!owner || owner->empty()) {
        Logger::Log("%s rejected: caller/callback is not an active plugin", apiName);
        return std::nullopt;
    }
    return owner;
}

static bool TargetInCurrentGameCore(void* target) {
    const HookImageId image = ImageAddress::LoadedGameCore();
    return image != kHookImageInvalid && ImageAddress::Contains(image, target);
}

static bool TargetInTearingDownGameCore(void* target) {
    const uintptr_t p = reinterpret_cast<uintptr_t>(target);
    return g_gameCoreTeardownAddress && p >= g_gameCoreTeardownAddress &&
        p - g_gameCoreTeardownAddress < g_gameCoreTeardownSizeOfImage;
}

static bool HasGameCoreTeardownCallback(const std::wstring& owner);

// ---------------- HookAPI ??? ----------------
static bool SafeRemoveHookLocked(void* target, bool eraseRecord);
// 调用方必须持有 Runtime::MinHookMutex()。
static MH_STATUS InstallHookOwnedByLocked(void* target, void* detour, void** original,
                                          const wchar_t* owner, HookKind kind) {
    MH_STATUS status = MH_CreateHook(target, detour, original);
    const auto existing = g_hookRecords.find(target);
    const bool recoverStalePlugin =
        status == MH_ERROR_ALREADY_CREATED &&
        kind == HookKind::Plugin &&
        existing != g_hookRecords.end() &&
        existing->second.kind == HookKind::Plugin &&
        existing->second.owner == (owner ? owner : L"") &&
        existing->second.gameCoreGeneration != 0 &&
        existing->second.gameCoreGeneration < ImageAddress::GameCoreGeneration() &&
        TargetInCurrentGameCore(target);
    if (recoverStalePlugin && SafeRemoveHookLocked(target, false)) {
        status = MH_CreateHook(target, detour, original);
    }
    if (status != MH_OK) {
        Logger::Log("InstallHook: create failed %s", MH_StatusToString(status));
        return status;
    }

    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallHook: enable failed %s", MH_StatusToString(status));
        // 回滚残留的 MinHook 记录：否则该 target 永远 ALREADY_CREATED，再无重试机会。
        MH_RemoveHook(target);
        return status;
    }

    g_hookRecords[target] = HookRecord{
        owner ? owner : L"",
        kind,
        TargetInCurrentGameCore(target) ? ImageAddress::GameCoreGeneration() : 0,
    };
    return MH_OK;
}

static bool InstallHookOwnedBy(void* target, void* detour, void** original,
                               const wchar_t* owner, HookKind kind = HookKind::Plugin) {
    lock_guard<mutex> lock(Runtime::MinHookMutex());
    return InstallHookOwnedByLocked(target, detour, original, owner, kind) == MH_OK;
}

bool InstallHookImpl(void* target, void* detour, void** original) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    if (TargetInTearingDownGameCore(target)) {
        Logger::Log("InstallHook rejected: target %p belongs to tearing-down GameCore", target);
        return false;
    }
    auto owner = RequirePluginOwner(detour, "InstallHook");
    if (owner && TargetInCurrentGameCore(target)) {
        const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
            [&owner](const PluginEntry& entry) {
                return entry.ownerId == *owner;
            });
        if (plugin != g_plugins.end() &&
                plugin->category == LoaderCore::PluginCategory::Global &&
                !HasGameCoreTeardownCallback(*owner)) {
            Logger::Log("InstallHook rejected: Global owner %ls must register GameCoreTeardown first",
                owner->c_str());
            return false;
        }
    }
    return owner && InstallHookOwnedBy(target, detour, original, owner->c_str());
}

// 摘除单个 MinHook 钩子；目标内存不可读（GameCore 映像已卸载，重载兜底路径会出现）
// 时跳过 RemoveHook——对未映射地址恢复原字节会失败甚至出错。残留的 MinHook 记录
// 由 InstallSharedHook 的 ALREADY_CREATED 恢复路径在新映像 attach 后清理复用。
// 调用方必须持有 Runtime::MinHookMutex()。
static bool SafeRemoveHookLocked(void* target, bool eraseRecord = true) {
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
    if (eraseRecord) g_hookRecords.erase(target);
    return true;
}

void BroadcastMessageImpl(const char* topic, const void* data, size_t len) {
    g_bus.Broadcast(topic, data, len);
}

void RegisterMessageHandlerImpl(const char* pluginName, MessageHandlerFn handler) {
    if (!pluginName || !*pluginName || !handler) return;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(handler),
                                    "RegisterMessageHandler");
    if (!owner) return;
    g_bus.RegisterHandler(pluginName, handler, *owner);
}

void SendMessageToImpl(const char* pluginName, const char* topic, const void* data, size_t len) {
    g_bus.SendTo(pluginName, topic, data, len);
}

bool IsImageLoadedImpl(HookImageId image) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    return ImageAddress::IsLoaded(image);
}

bool GetImageInfoImpl(HookImageId image, HookImageInfo* outInfo) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    return ImageAddress::GetInfo(image, outInfo);
}

void* ResolveByRvaImpl(HookImageId image, uintptr_t rva, size_t span) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    void* result = ImageAddress::ResolveByRva(image, rva, span);
    if (!result && ImageAddress::IsLoaded(image)) {
        Logger::Log("ResolveByRva: rejected image=%u rva=0x%llX span=%zu",
            static_cast<unsigned>(image),
            static_cast<unsigned long long>(rva), span);
    }
    return result;
}

void* ResolveByNameImpl(HookImageId image, const char* name) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (!name || !*name || !ImageAddress::IsLoaded(image)) return nullptr;

    // 当前符号包只对应 XP2 GameCore。exe/Base/XP1 暂无名字数据库；
    // 接口保留同一语义，后续可按 image 分发各自符号表。
    if (image != kHookImageGameCoreXP2) {
        Logger::Log("ResolveByName: no symbol database for image=%u name=%s",
            static_cast<unsigned>(image), name);
        return nullptr;
    }

    const uint32_t rva = SymbolDb::LookupRva(name);
    if (rva == 0) return nullptr;
    void* result = ImageAddress::ResolveByRva(image, rva, 1);
    if (!result) {
        Logger::Log("ResolveByName: out-of-range RVA image=%u name=%s rva=0x%X",
            static_cast<unsigned>(image), name, rva);
    }
    return result;
}

void* ResolveCurrentGameCoreByName(const char* name) {
    const HookImageId image = ImageAddress::LoadedGameCore();
    if (image == kHookImageInvalid) return nullptr;
    return ResolveByNameImpl(image, name);
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
    if (!name || !*name || !methods || count == 0) return nullptr;
    auto owner = RequirePluginOwner(
        reinterpret_cast<const void*>(methods[0].luaMethodFunc), "PushLuaMethods");
    if (!owner) return nullptr;
    for (uint32_t i = 0; i < count; ++i) {
        auto methodOwner = RequirePluginOwner(
            reinterpret_cast<const void*>(methods[i].luaMethodFunc), "PushLuaMethods");
        if (!methodOwner || *methodOwner != *owner) {
            Logger::Log("PushLuaMethods rejected: mixed or unowned callback modules");
            return nullptr;
        }
    }

    // M2: g_MethodSignatureTable 与 RegisterPushMethodsTargetImpl 的写入跨线程共享，
    // 读写都在生命周期锁内（后面 InstallPushMethods* 递归重入）。
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    const std::string targetName(name);
    auto sigIt = g_MethodSignatureTable.find(targetName);
    if (sigIt == g_MethodSignatureTable.end()) {
        Logger::Log("PushLuaMethods: unknown target %s", name);
        return nullptr;
    }
    auto stored = CopyLuaMethods(methods, count);
    for (auto& method : stored) method.owner = *owner;
    g_pushRegistrations.push_back(
        PushRegistration{ targetName, sigIt->second, stored, *owner });

    if (!g_gameCorePhaseReady) {
        Logger::Log("PushLuaMethods: deferred until GameCore phase is ready: %s",
                    targetName.c_str());
        return nullptr;
    }

    std::string symbolName = targetName + "::PushMethods";
    if (sigIt->second == PushMethodSigType::NoManager) {
        auto target = reinterpret_cast<PushMethodsNoFunc>(
            ResolveCurrentGameCoreByName(symbolName.c_str()));
        if (!target) {
            Logger::Log("PushLuaMethods: deferred until GameCore is ready: %s",
                        symbolName.c_str());
            return nullptr;
        }
        return InstallPushMethodsNoManager(target, stored, *owner);
    }
    auto target = reinterpret_cast<PushMethodsWithFunc>(
        ResolveCurrentGameCoreByName(symbolName.c_str()));
    if (!target) {
        Logger::Log("PushLuaMethods: deferred until GameCore is ready: %s",
                    symbolName.c_str());
        return nullptr;
    }
    return InstallPushMethodsWithManager(target, stored, *owner);
}

// 版本锁定偏移：当前回合 dword 位于 CurrentTurnStorage 解引用对象 +0xC0。
// 符号库/游戏版本错位时由下方可读探测兜住，返回 0 而不是读崩。
constexpr size_t kCurTurnDwordOffset = 0xC0;

unsigned int GetCurTurnImpl() {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    auto* slot = reinterpret_cast<uint64_t**>(
        ResolveCurrentGameCoreByName("GameCore::Globals::CurrentTurnStorage"));
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
    SharedDetourActivity activity;
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
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    MH_STATUS status = InstallHookOwnedByLocked(
        target, detour, orig, L"", HookKind::SharedScript);
    if (status == MH_OK) {
        *targetSlot = target;
        return true;
    }

    const auto it = g_hookRecords.find(target);
    const bool isOurStaleHook =
        status == MH_ERROR_ALREADY_CREATED &&
        it != g_hookRecords.end() &&
        it->second.owner.empty() &&
        it->second.gameCoreGeneration < ImageAddress::GameCoreGeneration() &&
        g_activeSharedDetours.load(std::memory_order_acquire) == 0;
    if (isOurStaleHook && SafeRemoveHookLocked(target) &&
        InstallHookOwnedByLocked(target, detour, orig, L"",
                                 HookKind::SharedScript) == MH_OK) {
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
    if (!g_gameCorePhaseReady) return;

    if (!g_scriptHookInstalled && !g_scriptGlobals.empty()) {
        void* target = ResolveCurrentGameCoreByName("GameCore::RegisterScriptData");
        if (!target) {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptData address missing");
        } else if (InstallSharedHook(target, reinterpret_cast<void*>(&Hook_RegisterScriptData),
                       reinterpret_cast<void**>(&g_origRegisterScriptData), &g_scriptHookTarget)) {
            g_scriptHookInstalled = true;
            Logger::Log("EnsureScriptHooksInstalled: hooked RegisterScriptData at %p", target);
        }
    }
    if (!g_scriptUIHookInstalled && !g_scriptGlobalsUI.empty()) {
        void* target = ResolveCurrentGameCoreByName("GameCore::RegisterScriptDataForUI");
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

// ---- GameCore 生命周期回调（Global 插件延迟挂钩，语义见 HookAPI.h 尾部文档）----

// 前置声明（定义于本文件后部）：回调崩溃时按 owner 隔离（与 OnLoad 崩溃同构）。
static void QuarantinePluginByOwner(const std::wstring& ownerId);

namespace {

struct GameCoreCallbackEntry {
    std::wstring owner;
    void (*fn)(void*) = nullptr;
    std::atomic<void*> context{ nullptr };
    std::atomic<bool> enabled{ true };
    std::atomic<uint32_t> activeCalls{ 0 };
    mutex drainMutex;
    condition_variable drainCv;
};

using GameCoreCallbackPtr = std::shared_ptr<GameCoreCallbackEntry>;
std::vector<GameCoreCallbackPtr> g_gameCoreReadyCallbacks;
std::vector<GameCoreCallbackPtr> g_gameCoreTeardownCallbacks;
mutex g_gameCoreCallbackMutex;
std::recursive_mutex g_gameCoreTransitionMutex;
thread_local GameCoreCallbackEntry* g_currentGameCoreCallback;

// 登记回调（同 owner + 同 fn 幂等：重复注册仅刷新 context）。
std::pair<GameCoreCallbackPtr, bool> AddGameCoreCallback(
        std::vector<GameCoreCallbackPtr>& reg, const std::wstring& owner,
        void (*fn)(void*), void* context, const char* apiName) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&owner](const PluginEntry& entry) {
            return entry.ownerId == owner &&
                (entry.state == PluginState::Loading ||
                 entry.state == PluginState::Active);
        });
    if (plugin == g_plugins.end()) {
        Logger::Log("%s rejected: owner is no longer active (%ls)",
            apiName, owner.c_str());
        return { nullptr, false };
    }
    lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
    for (auto& existing : reg) {
        if (existing->owner == owner && existing->fn == fn) {
            existing->context.store(context, std::memory_order_release);
            return { existing, false };
        }
    }
    auto entry = std::make_shared<GameCoreCallbackEntry>();
    entry->owner = owner;
    entry->fn = fn;
    entry->context.store(context, std::memory_order_release);
    Logger::Log("%s: registered owner=%ls", apiName, owner.c_str());
    reg.push_back(entry);
    return { entry, true };
}

__declspec(noinline) bool CallGameCoreCallbackSeh(
        const GameCoreCallbackPtr& entry, const char* phase) {
    __try {
        entry->fn(entry->context.load(std::memory_order_acquire));
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("%s: callback crashed owner=%ls code=0x%08X; quarantining",
            phase, entry->owner.c_str(), GetExceptionCode());
        return false;
    }
}

bool CallGameCoreCallbackSafe(const GameCoreCallbackPtr& entry, const char* phase) noexcept {
    try {
        return CallGameCoreCallbackSeh(entry, phase);
    } catch (...) {
        Logger::Log("%s: callback threw C++ exception owner=%ls; quarantining",
            phase, entry->owner.c_str());
        return false;
    }
}

bool AdmitGameCoreCallback(const GameCoreCallbackPtr& entry) {
    if (!entry || !entry->enabled.load(std::memory_order_acquire)) return false;
    entry->activeCalls.fetch_add(1, std::memory_order_acq_rel);
    if (entry->enabled.load(std::memory_order_acquire)) return true;
    if (entry->activeCalls.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        lock_guard<mutex> lock(entry->drainMutex);
        entry->drainCv.notify_all();
    }
    return false;
}

void InvokeAdmittedGameCoreCallback(const GameCoreCallbackPtr& entry,
                                    const char* phase) {
    Logger::Log("%s: begin owner=%ls", phase, entry->owner.c_str());
    auto* previous = g_currentGameCoreCallback;
    g_currentGameCoreCallback = entry.get();
    const bool succeeded = CallGameCoreCallbackSafe(entry, phase);
    g_currentGameCoreCallback = previous;
    if (succeeded) {
        Logger::Log("%s: end owner=%ls", phase, entry->owner.c_str());
    }
    if (entry->activeCalls.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        lock_guard<mutex> lock(entry->drainMutex);
        entry->drainCv.notify_all();
    }
    if (!succeeded) {
        QuarantinePluginByOwner(entry->owner);
    }
}

void DisableAndDrainGameCoreCallbacks(
        const std::vector<GameCoreCallbackPtr>& callbacks) {
    for (const auto& entry : callbacks) {
        entry->enabled.store(false, std::memory_order_release);
    }
    for (const auto& entry : callbacks) {
        if (entry.get() == g_currentGameCoreCallback) continue;
        unique_lock<mutex> lock(entry->drainMutex);
        entry->drainCv.wait(lock, [&entry] {
            return entry->activeCalls.load(std::memory_order_acquire) == 0;
        });
    }
}

void WaitForGameCoreCallbacks(const std::vector<GameCoreCallbackPtr>& registry) {
    std::vector<GameCoreCallbackPtr> snapshot;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
        snapshot = registry;
    }
    for (const auto& entry : snapshot) {
        if (entry.get() == g_currentGameCoreCallback) continue;
        unique_lock<mutex> lock(entry->drainMutex);
        entry->drainCv.wait(lock, [&entry] {
            return entry->activeCalls.load(std::memory_order_acquire) == 0;
        });
    }
}

void RemoveGameCoreCallbacksFor(const std::wstring& owner) {
    std::vector<GameCoreCallbackPtr> removed;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
        auto removeOwned = [&owner, &removed](auto& reg) {
            for (auto it = reg.begin(); it != reg.end(); ) {
                if ((*it)->owner == owner) {
                    removed.push_back(*it);
                    it = reg.erase(it);
                } else {
                    ++it;
                }
            }
        };
        removeOwned(g_gameCoreReadyCallbacks);
        removeOwned(g_gameCoreTeardownCallbacks);
    }
    DisableAndDrainGameCoreCallbacks(removed);
}

}  // namespace

static bool HasGameCoreTeardownCallback(const std::wstring& owner) {
    lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
    return std::any_of(g_gameCoreTeardownCallbacks.begin(),
        g_gameCoreTeardownCallbacks.end(),
        [&owner](const GameCoreCallbackPtr& entry) {
            return entry->owner == owner &&
                entry->enabled.load(std::memory_order_acquire);
        });
}

void RegisterGameCoreReadyImpl(GameCoreReadyFn fn, void* context) {
    if (!fn) return;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn), "RegisterGameCoreReady");
    if (!owner) return;
    auto [entry, inserted] = AddGameCoreCallback(
        g_gameCoreReadyCallbacks, *owner, fn, context, "RegisterGameCoreReady");
    if (!entry) return;
    // 注册即触发：GameCore 已就绪（如对局中 reconcile 新加载的插件）时立即补调，
    // 不必等下一次重载。
    bool admitted = false;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        admitted = inserted && g_gameCorePhaseReady &&
            g_currentGameCoreCallback != entry.get() &&
            AdmitGameCoreCallback(entry);
    }
    if (admitted) {
        InvokeAdmittedGameCoreCallback(entry, "GameCoreReady(immediate)");
    }
}

void RegisterGameCoreTeardownImpl(GameCoreTeardownFn fn, void* context) {
    if (!fn) return;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn), "RegisterGameCoreTeardown");
    if (!owner) return;
    AddGameCoreCallback(g_gameCoreTeardownCallbacks, *owner, fn, context,
                        "RegisterGameCoreTeardown");
}

static std::vector<GameCoreCallbackPtr> SnapshotGameCoreCallbacks(
        const std::vector<GameCoreCallbackPtr>& reg) {
    std::vector<GameCoreCallbackPtr> snapshot;
    lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
    snapshot = reg;
    return snapshot;
}

// 逐条准入、逐条执行：同 owner 的前一回调若崩溃并隔离，后续条目已被禁用，
// 不会因批量预先增加 activeCalls 而让隔离线程等待自己尚未执行的条目。
static void FireGameCoreCallbackSnapshot(
        const std::vector<GameCoreCallbackPtr>& snapshot, const char* phase) {
    for (const auto& entry : snapshot) {
        bool admitted = false;
        {
            lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
            admitted = AdmitGameCoreCallback(entry);
        }
        if (admitted) InvokeAdmittedGameCoreCallback(entry, phase);
    }
}

static void FireGameCoreCallbacks(std::vector<GameCoreCallbackPtr>& reg,
                                  const char* phase) {
    std::vector<GameCoreCallbackPtr> snapshot;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        snapshot = SnapshotGameCoreCallbacks(reg);
    }
    FireGameCoreCallbackSnapshot(snapshot, phase);
}

void RegisterScriptGlobalsImpl(ScriptGlobalsFn fn) {
    if (!fn) return;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn),
                                    "RegisterScriptGlobals");
    if (!owner) return;
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        g_scriptGlobals.push_back(ScriptGlobalsEntry{ *owner, fn });
    }
    EnsureScriptHooksInstalled();  // 检查+安装整体在锁内（含并发首装与重载后重装）
}

void RegisterScriptGlobalsForUIImpl(ScriptGlobalsFn fn) {
    if (!fn) return;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn),
                                    "RegisterScriptGlobalsForUI");
    if (!owner) return;
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        g_scriptGlobalsUI.push_back(ScriptGlobalsEntry{ *owner, fn });
    }
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
    SharedDetourActivity activity;
    // 拷贝快照后在锁外回调：methods 可能被 Loader 工作线程（插件卸载清理）并发修改，
    // 快照同时把函数指针与 internalName/exposedName 字符串一并拷贝，锁外安全使用。
    std::vector<StoredLuaMethod> methods;
    PushMethodsNoFunc base = nullptr;
    {
        lock_guard<mutex> lock(g_pushStateMutex);
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
    SharedDetourActivity activity;
    std::vector<StoredLuaMethod> methods;
    PushMethodsWithFunc base = nullptr;
    {
        lock_guard<mutex> lock(g_pushStateMutex);
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

static bool RecoverStalePushHookLocked(void* target, MH_STATUS status) {
    if (status != MH_ERROR_ALREADY_CREATED) return false;
    const auto it = g_hookRecords.find(target);
    if (it == g_hookRecords.end() ||
        it->second.kind != HookKind::PushMethods ||
        !it->second.owner.empty() ||
        it->second.gameCoreGeneration >= ImageAddress::GameCoreGeneration() ||
        g_activeSharedDetours.load(std::memory_order_acquire) != 0) {
        return false;
    }
    return SafeRemoveHookLocked(target);
}

void* InstallPushMethodsNoManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                  const std::wstring& owner) {
    if (owner.empty() || std::any_of(methods.begin(), methods.end(),
            [&owner](const StoredLuaMethod& method) {
                return method.owner != owner;
            })) {
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    lock_guard<mutex> stateLock(g_pushStateMutex);
    const int slot = FindOrAllocNoManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsNoManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_noManagerSlots[slot];
    if (state.base) {
        // 已 hook 同一 target：只追加方法，返回既有 trampoline。
        state.methods.insert(state.methods.end(), methods.begin(), methods.end());
        return reinterpret_cast<void*>(state.base);
    }

    // 新槽：先建钩启用，全部成功后才登记方法；任一步失败完整回滚槽位与
    // MinHook 记录——否则半初始化槽位会让重试重复追加方法或返回失效 trampoline。
    MH_STATUS status = MH_CreateHook(target, NoManagerDetourTable[slot], reinterpret_cast<void**>(&state.base));
    if (RecoverStalePushHookLocked(target, status)) {
        status = MH_CreateHook(target, NoManagerDetourTable[slot],
                               reinterpret_cast<void**>(&state.base));
    }
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
    g_hookRecords[target] = HookRecord{
        L"", HookKind::PushMethods, ImageAddress::GameCoreGeneration()
    };
    state.methods.insert(state.methods.end(), methods.begin(), methods.end());
    return reinterpret_cast<void*>(state.base);
}

void* InstallPushMethodsWithManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                    const std::wstring& owner) {
    if (owner.empty() || std::any_of(methods.begin(), methods.end(),
            [&owner](const StoredLuaMethod& method) {
                return method.owner != owner;
            })) {
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    lock_guard<mutex> stateLock(g_pushStateMutex);
    const int slot = FindOrAllocWithManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsWithManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_withManagerSlots[slot];
    if (state.base) {
        state.methods.insert(state.methods.end(), methods.begin(), methods.end());
        return reinterpret_cast<void*>(state.base);
    }

    MH_STATUS status = MH_CreateHook(target, WithManagerDetourTable[slot], reinterpret_cast<void**>(&state.base));
    if (RecoverStalePushHookLocked(target, status)) {
        status = MH_CreateHook(target, WithManagerDetourTable[slot],
                               reinterpret_cast<void**>(&state.base));
    }
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
    g_hookRecords[target] = HookRecord{
        L"", HookKind::PushMethods, ImageAddress::GameCoreGeneration()
    };
    state.methods.insert(state.methods.end(), methods.begin(), methods.end());
    return reinterpret_cast<void*>(state.base);
}

static void ReinstallPushRegistrations() {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    size_t installed = 0;
    for (const auto& registration : g_pushRegistrations) {
        const std::string symbolName = registration.targetName + "::PushMethods";
        void* target = ResolveCurrentGameCoreByName(symbolName.c_str());
        if (!target) {
            Logger::Log("ReinstallPushRegistrations: missing %s",
                        symbolName.c_str());
            continue;
        }
        void* base = registration.signature == PushMethodSigType::NoManager
            ? InstallPushMethodsNoManager(target, registration.methods,
                                          registration.owner)
            : InstallPushMethodsWithManager(target, registration.methods,
                                            registration.owner);
        if (base) ++installed;
    }
    Logger::Log("ReinstallPushRegistrations: installed=%zu registered=%zu",
                installed, g_pushRegistrations.size());
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
        ResolveCurrentGameCoreByName("GameCore::Reporting::Event::Send"));
}
static EditPlayerFn ResolveEditPlayer() {
    return reinterpret_cast<EditPlayerFn>(
        ResolveCurrentGameCoreByName("GameCore::Context::Globals::EditPlayer"));
}
static GetCivDescFn ResolveGetCivDesc() {
    return reinterpret_cast<GetCivDescFn>(
        ResolveCurrentGameCoreByName("GameCore::Player::Instance::GetCivilizationDescription"));
}
static MakeHashFn ResolveMakeHash() {
    return reinterpret_cast<MakeHashFn>(
        ResolveCurrentGameCoreByName("GameCore::Utilities::MakeHash"));
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
    // Ensure ResolveByName can resolve the PushMethods symbol if only alias name differs.
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

#pragma intrinsic(_ReturnAddress)

__declspec(noinline) static bool HookPatch(void* target, const void* bytes, size_t len) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    if (TargetInTearingDownGameCore(target)) return false;
    auto owner = RequirePluginOwner(_ReturnAddress(), "Patch");
    return owner && PatchRegistry::Apply(target, bytes, len, owner->c_str());
}

__declspec(noinline) static bool HookUnpatch(void* target) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    auto owner = RequirePluginOwner(_ReturnAddress(), "Unpatch");
    return owner && PatchRegistry::RevertOwned(target, owner->c_str());
}

static HookAPI g_hookApi = {
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

    &RegisterPushMethodsTargetImpl,

    &HookPatch,
    &HookUnpatch,

    &RegisterGameCoreReadyImpl,
    &RegisterGameCoreTeardownImpl,
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
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    const DWORD sizeOfImage = GetModuleSizeOfImage(gameCore);
    const HookImageId image = ImageAddress::IdentifyGameCore(gameCore);
    const uint32_t expected = SymbolDb::ExpectedSizeOfImage();
    if (sizeOfImage == 0 || image == kHookImageInvalid) {
        Logger::Log("GameCore rejected: invalid or unknown PE image");
        return false;
    }
    if (image == kHookImageGameCoreXP2 && expected != 0 && sizeOfImage != expected) {
        Logger::Log("GameCore rejected: SizeOfImage mismatch symbols=0x%08X actual=0x%08X",
            expected, sizeOfImage);
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

    Logger::Log("GameCore attached image=%u base=0x%llX SizeOfImage=0x%08X generation=%llu",
        static_cast<unsigned>(image),
        static_cast<unsigned long long>(info.base), sizeOfImage,
        static_cast<unsigned long long>(info.generation));
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

// v2 统一插件加载流程：LoadLibraryExW + OnLoad(SEH) + OnMessage 自动注册 + 记录跟踪项。
// nameNarrow = 显示名（通常为文件名，内部取 stem 作 Patch owner / OnMessage 名）；已加载（同句柄）返回 false。
static bool LoadPluginDllInternal(const std::wstring& wpath, const std::string& nameNarrow,
    LoaderCore::PluginCategory category) {
    lock_guard<std::recursive_mutex> transitionLock(g_gameCoreTransitionMutex);
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);

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
    entry.state = PluginState::Loading;
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
    const bool alreadyQuarantined =
        trackedAfterLoad != g_plugins.end() &&
        trackedAfterLoad->state == PluginState::Quarantined;

    if (!onLoadOk) {
        // 崩溃隔离（G2）：仅驻留模块不够——按 owner 回滚全部注册并标记隔离，
        // 防止半初始化状态持续生效、以及阶段 B 全量扫描反复重试崩溃的 OnLoad。
        Logger::Log("Plugin quarantined after OnLoad failure: %s", narrow.c_str());
        lifecycleLock.unlock();
        if (!alreadyQuarantined) QuarantinePluginByOwner(ownerId);
        return false;
    }
    if (alreadyQuarantined || trackedAfterLoad == g_plugins.end()) {
        return false;
    }

    auto onMessage = (OnMessageFunc)GetProcAddress(hPlugin, "OnMessage");
    lifecycleLock.unlock();
    if (onMessage) {
        // Register under filename stem so SendMessageTo("Example1", ...) works.
        string handlerName = pluginFileName;
        const size_t dot = handlerName.find_last_of('.');
        if (dot != string::npos) handlerName = handlerName.substr(0, dot);
        g_bus.RegisterHandler(handlerName, onMessage, ownerId);
        Logger::Log("Auto-registered OnMessage for %s", handlerName.c_str());
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
    activate->state = PluginState::Active;
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
        LoadPluginDLL(nullptr, path);
    }
}

bool InitializeLoader(HMODULE hModule) {
    // v1 时代还记录模块句柄供 GetCurrentModuleDir 使用；该路径已随 v1 死代码清理
    // 删除，现在只注册 "Loader" 消息处理器（load-plugin 遗留入口，保持兼容）。
    (void)hModule;
    static std::once_flag registerLoaderHandler;
    std::call_once(registerLoaderHandler, [] {
        g_bus.RegisterHandler("Loader", OnLoaderMessage);
    });
    return true;
}

// ================= LoaderCore 实现（S3c：插件生命周期 v2） =================

// 撤销某插件通过 HookAPI.InstallHook 注册的全部 MinHook 钩子（Disable + Remove）。
// 在卸载插件的 FreeLibrary 之前调用；owner 为插件 stem（空串代表 Loader 自身，不在此撤销）。
static void RemovePluginHooks(const wchar_t* owner) {
    if (!owner || !*owner) return;
    lock_guard<mutex> lock(Runtime::MinHookMutex());
    for (auto it = g_hookRecords.begin(); it != g_hookRecords.end(); ) {
        if (it->second.owner == owner) {
            void* target = it->first;
            if (SafeRemoveHookLocked(target, false)) {
                it = g_hookRecords.erase(it);
                Logger::Log("RemovePluginHooks: removed hook at %p (owner=%ls)",
                            target, owner);
            } else {
                Logger::Log("RemovePluginHooks: retained failed hook record at %p (owner=%ls)",
                            target, owner);
                ++it;
            }
        } else {
            ++it;
        }
    }
}

// 撤销某插件注册的全部回调类条目（禁用/隔离时调用）：脚本全局、PushMethods
// 方法/登记、GameCore 生命周期回调。这些条目都持有指向插件映像的函数指针，
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
            if (slot.used) methods += removeOwnedBy(slot.methods);
        }
        for (auto& slot : g_withManagerSlots) {
            if (slot.used) methods += removeOwnedBy(slot.methods);
        }
    }

    const size_t registrationsBefore = g_pushRegistrations.size();
    g_pushRegistrations.erase(
        std::remove_if(g_pushRegistrations.begin(), g_pushRegistrations.end(),
            [&owner](const PushRegistration& registration) {
                return registration.owner == owner;
            }),
        g_pushRegistrations.end());
    const size_t registrationsRemoved =
        registrationsBefore - g_pushRegistrations.size();

    Logger::Log("RemovePluginOwnedRegistrations: owner=%ls globals=%zu globalsUI=%zu luaMethods=%zu registrations=%zu",
        owner.c_str(), globals, globalsUi, methods, registrationsRemoved);
}

// 崩溃隔离（与 OnLoad 崩溃同构）：标记隔离 + 回滚该 owner 的全部注册
// （补丁/MinHook 钩/Lua 方法/生命周期回调/OnMessage）。模块驻留不卸；
// 隔离后 reconcile 与阶段 B 全量扫描都不再重试。
static void QuarantinePluginByOwner(const std::wstring& ownerId) {
    if (ownerId.empty()) return;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (auto& entry : g_plugins) {
            if (entry.ownerId == ownerId) {
                entry.state = PluginState::Quarantined;
                break;
            }
        }
    }
    // 先禁用并排空所有外部入口；等待期间不得持 lifecycle 锁。
    RemoveGameCoreCallbacksFor(ownerId);
    g_bus.UnregisterOwner(ownerId);
    PatchRegistry::RevertAllFor(ownerId.c_str());
    RemovePluginHooks(ownerId.c_str());
    RemovePluginOwnedRegistrations(ownerId);
    Logger::Log("Plugin quarantined by owner: %ls", ownerId.c_str());
}

// 按跟踪项卸载单个插件（调用方保证 index 有效）：
// OnUnload → PatchRegistry::RevertAllFor(name) → RemovePluginHooks(name) → FreeLibrary，语义与 S2a 接线一致。
static void UnloadPluginByOwnerId(const std::wstring& ownerId) {
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

    g_plugins[index].state = PluginState::Deactivating;
    PluginEntry entry = g_plugins[index];

    // 先阻止并排空消息回调，避免 OnUnload 释放插件状态时旧快照仍在执行。
    // 等待时必须释放 lifecycle 锁，否则 handler 若正在调用 HookAPI 会锁反转。
    lifecycleLock.unlock();
    RemoveGameCoreCallbacksFor(entry.ownerId);
    g_bus.UnregisterOwner(entry.ownerId);
    auto onUnload = (OnUnloadFunc)GetProcAddress(entry.handle, "OnUnload");
    SetActivePluginContext(entry.ownerId, entry.handle);
    if (onUnload) CallOnUnloadSafe(onUnload, nullptr);
    // 先 OnUnload 后回滚补丁：插件 OnUnload 可能仍依赖自己的补丁。
    // 必须在 FreeLibrary 之前回滚——补丁目标可能位于该插件自身映像内。
    PatchRegistry::RevertAllFor(entry.ownerId.c_str());
    // 撤销该插件的 MinHook 钩子：否则 GameCore 重载后重新 OnLoad 会撞 MH_ERROR_ALREADY_CREATED。
    RemovePluginHooks(entry.ownerId.c_str());
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
        UnloadPluginByOwnerId(owner);
    }
    size_t remaining = 0;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        remaining = g_plugins.size();
    }
    Logger::Log("UnloadPluginsOf(%s): unloaded=%zu remaining=%zu",
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

void LoaderCore::UnloadSinglePlugin(const std::wstring& path) {
    const std::wstring norm = NormalizePluginPath(path);
    std::wstring ownerId;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (const auto& entry : g_plugins) {
            if (NormalizePluginPath(entry.path) != norm) continue;
            if (entry.state != PluginState::Active) {
                Logger::Log("UnloadSinglePlugin: inactive plugin remains parked: %s",
                            ModScan::WideToNarrow(path).c_str());
                return;
            }
            ownerId = entry.ownerId;
            break;
        }
    }
    if (!ownerId.empty()) {
        UnloadPluginByOwnerId(ownerId);
        Logger::Log("UnloadSinglePlugin: %s", ModScan::WideToNarrow(path).c_str());
    }
    // 未加载：no-op
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
    // v2 无薄壳：以当前进程 exe 模块作扫描锚。
    if (!InitializeLoader(GetModuleHandleW(nullptr))) {
        Logger::Log("InitializeGameCorePhase: InitializeLoader failed");
        ImageAddress::DetachGameCore();
        return false;
    }
    // HavokScript 导入缺失 = Lua API 半可用，对插件是崩溃源：停用 GameCore 插件
    // 加载（本会话游戏本体照常运行）。
    if (!hks::InitHavokScript()) {
        Logger::Log("InitializeGameCorePhase: InitHavokScript incomplete; GameCore plugins disabled");
        ImageAddress::DetachGameCore();
        return false;
    }
    Localization::InitScript();
    g_gameCorePhaseReady = true;
    // GameCore 重载后重装共享脚本钩（ResetForReload 已摘除；回调列表跨重载保留）。
    // 首次进入时若 Global 插件已在阶段 A 注册过脚本全局，也在此一并装钩。
    EnsureScriptHooksInstalled();
    ReinstallPushRegistrations();
    // Global 插件的 Ready 回调：此刻新映像已 attach、符号可解析——插件在此
    // InstallHook/Patch/做一次性初始化；先于 GameCore 插件加载，保证顺序确定。
    const auto readySnapshot = SnapshotGameCoreCallbacks(g_gameCoreReadyCallbacks);
    lifecycleLock.unlock();
    FireGameCoreCallbackSnapshot(readySnapshot, "GameCoreReady");
    Logger::Log("InitializeGameCorePhase: OK");
    return true;
}

void LoaderCore::ReconcileGlobalPlugins() {
    // 扫描（文件系统/sqlite）在锁外；下方对 g_plugins 的 diff 与加载/卸载整体持锁，
    // 与游戏线程的 LoadPluginsOf（LoadDLL detour 内）串行化。
    const auto expected = ModScan::FindGlobalPluginCandidates(LoaderCore::RuntimeModuleHandle());

    std::unordered_set<std::wstring> expectedNorm;
    expectedNorm.reserve(expected.size());
    for (const auto& wpath : expected) {
        expectedNorm.insert(NormalizePluginPath(wpath));
    }

    // 先卸载"当前有而期望无"的 Global 插件。
    std::vector<std::wstring> toUnload;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (const auto& entry : g_plugins) {
            if (entry.category != PluginCategory::Global) continue;
            if (expectedNorm.count(NormalizePluginPath(entry.path))) continue;
            toUnload.push_back(entry.path);
        }
    }
    for (const auto& wpath : toUnload) {
        UnloadSinglePlugin(wpath);
    }

    // 再加载"期望有而当前无"的 Global 插件。
    std::unordered_set<std::wstring> currentNorm;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        currentNorm.reserve(g_plugins.size());
        for (const auto& entry : g_plugins) {
            if (entry.category == PluginCategory::Global) {
                currentNorm.insert(NormalizePluginPath(entry.path));
            }
        }
    }
    size_t loaded = 0;
    for (const auto& wpath : expected) {
        if (currentNorm.count(NormalizePluginPath(wpath))) continue;
        if (LoadSinglePlugin(wpath)) ++loaded;
    }

    size_t tracked = 0;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        tracked = g_plugins.size();
    }
    Logger::Log("ReconcileGlobalPlugins: unloaded=%zu loaded=%zu tracked=%zu",
        toUnload.size(), loaded, tracked);
}

bool LoaderCore::IsInitialized() {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
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
static void ResetSharedGameCoreHooks(
        unique_lock<std::recursive_mutex>& lifecycleLock) {
    std::vector<void*> pushTargets;
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (int i = 0; i < kMaxPushHooks; ++i) {
            if (g_noManagerSlots[i].used) {
                pushTargets.push_back(g_noManagerSlots[i].target);
            }
            if (g_withManagerSlots[i].used) {
                pushTargets.push_back(g_withManagerSlots[i].target);
            }
        }
    }

    {
        lock_guard<mutex> hookLock(Runtime::MinHookMutex());
        if (g_scriptHookTarget) MH_DisableHook(g_scriptHookTarget);
        if (g_scriptUIHookTarget) MH_DisableHook(g_scriptUIHookTarget);
        for (void* target : pushTargets) {
            if (target) MH_DisableHook(target);
        }
    }

    // 禁止新的 GameCore API 解析后释放生命周期锁，让已经进入 detour 的插件回调
    // 能正常调用 HookAPI 并退出；不能在持 lifecycle/hook 锁时等待。
    HookImageInfo current{ sizeof(HookImageInfo) };
    const HookImageId currentId = ImageAddress::LoadedGameCore();
    if (ImageAddress::GetInfo(currentId, &current)) {
        g_gameCoreTeardownAddress = current.base;
        g_gameCoreTeardownSizeOfImage = static_cast<uint32_t>(current.imageSize);
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

    {
        lock_guard<mutex> hookLock(Runtime::MinHookMutex());
        if (g_scriptHookTarget) SafeRemoveHookLocked(g_scriptHookTarget);
        if (g_scriptUIHookTarget) SafeRemoveHookLocked(g_scriptUIHookTarget);
        for (void* target : pushTargets) {
            if (target) SafeRemoveHookLocked(target);
        }
    }

    g_scriptHookTarget = nullptr;
    g_scriptUIHookTarget = nullptr;
    g_scriptHookInstalled = false;
    g_scriptUIHookInstalled = false;
    g_origRegisterScriptData = nullptr;
    g_origRegisterScriptDataForUI = nullptr;
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (int i = 0; i < kMaxPushHooks; ++i) {
            g_noManagerSlots[i] = NoManagerHookSlot{};
            g_withManagerSlots[i] = WithManagerHookSlot{};
        }
    }
    g_gameCoreTeardownAddress = 0;
    g_gameCoreTeardownSizeOfImage = 0;
    Logger::Log("ResetSharedGameCoreHooks: script/UI hooks + push slots reset");
}

// 按代际撤销所有 GameCore 域的插件钩（调用方持生命周期锁）。
// Global 插件在对局中经 Ready 回调装的 GameCore 域钩无人摘：同基址重载可靠
// recoverStalePlugin 自愈（前提插件重装），异基址重载则旧记录指向未映射内存
// 永远无法回收——统一在旧映像卸载前按 generation 清掉。exe 域钩
// （generation == 0）不受影响。
static void DisableGameCoreGenerationHooks(uint64_t generation) {
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    size_t disabled = 0;
    for (const auto& [target, record] : g_hookRecords) {
        if (record.gameCoreGeneration == generation &&
                record.kind == HookKind::Plugin &&
                !record.owner.empty()) {
            const MH_STATUS status = MH_DisableHook(target);
            if (status == MH_OK || status == MH_ERROR_DISABLED) {
                ++disabled;
            } else {
                Logger::Log("DisableGameCoreGenerationHooks: target=%p status=%s",
                    target, MH_StatusToString(status));
            }
        }
    }
    Logger::Log("DisableGameCoreGenerationHooks: disabled=%zu", disabled);
}

static void RemoveGameCoreGenerationHooks(uint64_t generation) {
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    size_t removed = 0;
    for (auto it = g_hookRecords.begin(); it != g_hookRecords.end(); ) {
        const HookRecord& record = it->second;
        const bool gameCoreDomainPluginHook =
            record.gameCoreGeneration == generation &&
            record.kind == HookKind::Plugin &&
            !record.owner.empty();
        if (gameCoreDomainPluginHook) {
            void* target = it->first;
            if (SafeRemoveHookLocked(target, false)) {
                it = g_hookRecords.erase(it);
                ++removed;
            } else {
                // 摘除失败（兜底路径映像已卸载等）：保留记录，待地址复用时由
                // recoverStalePlugin 路径或下次 teardown 处理。
                ++it;
            }
        } else {
            ++it;
        }
    }
    Logger::Log("RemoveGameCoreGenerationHooks: removed=%zu remainingRecords=%zu",
        removed, g_hookRecords.size());
}

void LoaderCore::ResetForReload() {
    lock_guard<std::recursive_mutex> transitionLock(g_gameCoreTransitionMutex);
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    g_gameCorePhaseReady = false;
    // 先进入 teardown 窗口（InstallHook/Patch 对旧映像的目标从此被拒绝），
    // ImageAddress 暂不 detach——teardown 回调内仍可解析符号读数据收尾。
    HookImageInfo current{ sizeof(HookImageInfo) };
    const HookImageId currentId = ImageAddress::LoadedGameCore();
    if (ImageAddress::GetInfo(currentId, &current)) {
        g_gameCoreTeardownAddress = current.base;
        g_gameCoreTeardownSizeOfImage = static_cast<uint32_t>(current.imageSize);
    } else {
        g_gameCoreTeardownAddress = 0;
        g_gameCoreTeardownSizeOfImage = 0;
    }
    const uint64_t teardownGeneration = ImageAddress::GameCoreGeneration();
    lifecycleLock.unlock();

    // phaseReady 已关闭，不会再有新的 Ready 准入；先等已准入回调结束，
    // 防止其与 Teardown/卸载交错。
    WaitForGameCoreCallbacks(g_gameCoreReadyCallbacks);

    // 先关闭该代插件钩入口，再运行 Teardown。回调返回即表示插件已排空自己
    // 的在途 detour；此后才会释放 original trampoline。
    DisableGameCoreGenerationHooks(teardownGeneration);

    // Global 插件收尾回调：置于 GameCore 插件卸载之前（它们可能依赖后者仍在
    // 钩上维护的数据）；旧映像此刻仍存活。
    FireGameCoreCallbacks(g_gameCoreTeardownCallbacks, "GameCoreTeardown");

    // UnloadPluginsOf 自身不触碰初始化标志，天然无递归。
    UnloadPluginsOf(PluginCategory::GameCore);

    lifecycleLock.lock();
    // 旧映像区间的补丁清账：GameCore 插件的补丁已随其卸载按 owner 回滚，
    // 这里收尾 Global 插件打在旧映像上的补丁（映像卸载前回滚字节，记录随之丢弃）。
    if (g_gameCoreTeardownAddress) {
        PatchRegistry::RevertAllInRange(
            g_gameCoreTeardownAddress, g_gameCoreTeardownSizeOfImage);
    }
    // 共享钩子（ScriptData/ForUI + PushMethods 槽位）目标在旧 GameCore 映像内，
    // 必须随重载复位，否则 Lua 注入在新映像下永久失效（见函数头注释）。
    ResetSharedGameCoreHooks(lifecycleLock);
    // 按代际清掉剩余的 GameCore 域插件钩（Global 插件的钩 + 各类漏网）。
    RemoveGameCoreGenerationHooks(teardownGeneration);
    Logger::Log("ResetForReload: teardown callbacks fired, GameCore plugins unloaded, shared hooks reset, generation hooks cleared");
}
