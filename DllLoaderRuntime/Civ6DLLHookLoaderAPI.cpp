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
#include <unordered_set>

#include "PatchRegistry.h"
#include "LoaderCore.h"

using namespace std;

static Civ6MessageBus g_bus;

static HMODULE g_loaderModule = NULL;

// v2 插件跟踪项：路径 + 句柄 + 名字(stem，作 Patch owner / OnMessage 注册名) + 类别(Global/GameCore)。
struct PluginEntry {
    HMODULE handle = nullptr;
    std::wstring path;
    std::wstring name;
    LoaderCore::PluginCategory category = LoaderCore::PluginCategory::Global;
};
static vector<PluginEntry> g_plugins;

// 当前正在加载/卸载的插件名（去扩展名的文件名 stem）。OnLoad/OnUnload 期间由
// SetActivePluginName 设置；HookPatch 与 InstallHookImpl 用它作 owner，使卸载时能对上号。
static wchar_t g_activePluginName[64];

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

static HMODULE g_GameCore;
static uintptr_t g_GameCoreAddress;
static uint32_t g_GameCoreSizeOfImage;

HMODULE GameCore;
uintptr_t GameCoreAddress;
DWORD GameProcessId;
HANDLE GameProcess;
uintptr_t BaseAddress;


static unordered_map<string, PushMethodSigType> g_MethodSignatureTable = {
    {"GameCore::Cache::Lua::IQuestsManager", PushMethodSigType::WithManager},
    {"GameCore::Lua::IQuestsManager", PushMethodSigType::NoManager},
};

// Symbol RVAs live in Civ6DllLoader.symbols.bin (see tools/pack_symbol_db.py).




//static vector<HookAPI::MessageHandler> g_handlers;
static mutex g_handlerMutex;
mutex g_hookMutex;

namespace fs = std::filesystem;


// ---------------- ???lua??????? ----------------
static unordered_map<string, void*> g_PushMethodAddresses;
static unordered_map<string, vector<LuaMethodInfo>> g_LuaMethodLists;

// ????detour????????????????
static unordered_map<string, void*> g_OriginalFunctions;


// ---------------- HookAPI ??? ----------------
bool InstallHookImpl(void* target, void* detour, void** original) {
    lock_guard<mutex> lock(g_hookMutex);

    MH_STATUS status;
    if ((status = MH_CreateHook(target, detour, original)) != MH_OK) {
        Logger::Log("InstallHook: create failed %s", MH_StatusToString(status));
        return false;
    }

    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallHook: enable failed %s", MH_StatusToString(status));
        return false;
    }

    // 记录 target → owner（插件 OnLoad 期间 = 插件 stem；否则空串 = Loader 自身）。
    // 插件卸载时据此撤销，避免 GameCore 重载后同一 target 再次 CreateHook 报 ALREADY_CREATED。
    g_pluginHookOwners[target] = g_activePluginName[0] ? g_activePluginName : L"";

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

unsigned int GetCurTurnImpl() {
    auto slot = reinterpret_cast<uint64_t*>(
        GetFunctionByNameImpl("GameCore::Globals::CurrentTurnStorage"));
    if (!slot || !*slot) {
        Logger::Log("GetCurTurn: current-turn storage unavailable");
        return 0;
    }
    uint32_t* base = reinterpret_cast<uint32_t*>(*slot);
    return base[48];
}

namespace {

std::vector<ScriptGlobalsFn> g_scriptGlobals;
std::vector<ScriptGlobalsFn> g_scriptGlobalsUI;
ProxyTypes::RegisterScriptData g_origRegisterScriptData = nullptr;
ProxyTypes::RegisterScriptDataForUI g_origRegisterScriptDataForUI = nullptr;
bool g_scriptHookInstalled = false;
bool g_scriptUIHookInstalled = false;

static void CallScriptGlobalsSafe(ScriptGlobalsFn fn, void* L) {
    if (!fn) return;
    __try {
        fn(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("ScriptGlobals callback crashed code=0x%08X", GetExceptionCode());
    }
}

void __cdecl Hook_RegisterScriptData(hks::lua_State* L) {
    Logger::Log("RegisterScriptData: running %zu plugin global registrar(s)", g_scriptGlobals.size());
    size_t i = 0;
    for (auto fn : g_scriptGlobals) {
        Logger::Log("RegisterScriptData: registrar[%zu] begin", i);
        CallScriptGlobalsSafe(fn, reinterpret_cast<void*>(L));
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
    Logger::Log("RegisterScriptDataForUI: running %zu plugin global registrar(s)", g_scriptGlobalsUI.size());
    size_t i = 0;
    for (auto fn : g_scriptGlobalsUI) {
        Logger::Log("RegisterScriptDataForUI: registrar[%zu] begin", i);
        CallScriptGlobalsSafe(fn, reinterpret_cast<void*>(L));
        Logger::Log("RegisterScriptDataForUI: registrar[%zu] end", i);
        ++i;
    }
    if (g_origRegisterScriptDataForUI) {
        Logger::Log("RegisterScriptDataForUI: calling original");
        g_origRegisterScriptDataForUI(unused, L);
        Logger::Log("RegisterScriptDataForUI: original returned");
    }
}

void ResetScriptHookState() {
    g_scriptGlobals.clear();
    g_scriptGlobalsUI.clear();
    g_scriptHookInstalled = false;
    g_scriptUIHookInstalled = false;
    g_origRegisterScriptData = nullptr;
    g_origRegisterScriptDataForUI = nullptr;
}

}  // namespace

void RegisterScriptGlobalsImpl(ScriptGlobalsFn fn) {
    if (fn) {
        g_scriptGlobals.push_back(fn);
    }
    if (g_scriptHookInstalled) return;

    void* target = GetFunctionByNameImpl("GameCore::RegisterScriptData");
    if (!target) {
        Logger::Log("RegisterScriptGlobals: RegisterScriptData address missing");
        return;
    }
    if (!InstallHookImpl(target, reinterpret_cast<void*>(&Hook_RegisterScriptData),
            reinterpret_cast<void**>(&g_origRegisterScriptData))) {
        Logger::Log("RegisterScriptGlobals: failed to hook RegisterScriptData");
        return;
    }
    g_scriptHookInstalled = true;
    Logger::Log("RegisterScriptGlobals: hooked RegisterScriptData");
}

void RegisterScriptGlobalsForUIImpl(ScriptGlobalsFn fn) {
    if (fn) {
        g_scriptGlobalsUI.push_back(fn);
    }
    if (g_scriptUIHookInstalled) return;

    void* target = GetFunctionByNameImpl("GameCore::RegisterScriptDataForUI");
    if (!target) {
        Logger::Log("RegisterScriptGlobalsForUI: address missing");
        return;
    }
    if (!InstallHookImpl(target, reinterpret_cast<void*>(&Hook_RegisterScriptDataForUI),
            reinterpret_cast<void**>(&g_origRegisterScriptDataForUI))) {
        Logger::Log("RegisterScriptGlobalsForUI: failed to hook");
        return;
    }
    g_scriptUIHookInstalled = true;
    Logger::Log("RegisterScriptGlobalsForUI: hooked RegisterScriptDataForUI");
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
    for (auto& method : g_noManagerSlots[I].methods) {
        PushLuaMethod(L, reinterpret_cast<hks::luaFunc>(method.luaMethodFunc),
            method.internalName.c_str(), stackOffset, method.exposedName.c_str());
    }
    if (g_noManagerSlots[I].base) {
        g_noManagerSlots[I].base(L, stackOffset);
    }
}

template<int I>
void __fastcall DetourPushWithManager(void* manager, hks::lua_State* L, int stackOffset) {
    for (auto& method : g_withManagerSlots[I].methods) {
        PushLuaMethod(L, reinterpret_cast<hks::luaFunc>(method.luaMethodFunc),
            method.internalName.c_str(), stackOffset, method.exposedName.c_str());
    }
    if (g_withManagerSlots[I].base) {
        g_withManagerSlots[I].base(manager, L, stackOffset);
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

void ResetPushHookSlots() {
    for (int i = 0; i < kMaxPushHooks; ++i) {
        g_noManagerSlots[i] = NoManagerHookSlot{};
        g_withManagerSlots[i] = WithManagerHookSlot{};
    }
}

}  // namespace

void* InstallPushMethodsNoManager(void* target, const std::vector<StoredLuaMethod>& methods) {
    const int slot = FindOrAllocNoManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsNoManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_noManagerSlots[slot];
    state.methods.insert(state.methods.end(), methods.begin(), methods.end());
    if (state.base) {
        return reinterpret_cast<void*>(state.base);
    }

    MH_STATUS status = MH_CreateHook(target, NoManagerDetourTable[slot], reinterpret_cast<void**>(&state.base));
    if (status != MH_OK) {
        Logger::Log("InstallPushMethodsNoManager: create hook failed %s", MH_StatusToString(status));
        return nullptr;
    }
    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallPushMethodsNoManager: enable hook failed %s", MH_StatusToString(status));
        return nullptr;
    }
    return reinterpret_cast<void*>(state.base);
}

void* InstallPushMethodsWithManager(void* target, const std::vector<StoredLuaMethod>& methods) {
    const int slot = FindOrAllocWithManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsWithManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_withManagerSlots[slot];
    state.methods.insert(state.methods.end(), methods.begin(), methods.end());
    if (state.base) {
        return reinterpret_cast<void*>(state.base);
    }

    MH_STATUS status = MH_CreateHook(target, WithManagerDetourTable[slot], reinterpret_cast<void**>(&state.base));
    if (status != MH_OK) {
        Logger::Log("InstallPushMethodsWithManager: create hook failed %s", MH_StatusToString(status));
        return nullptr;
    }
    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallPushMethodsWithManager: enable hook failed %s", MH_StatusToString(status));
        return nullptr;
    }
    return reinterpret_cast<void*>(state.base);
}


void LuaPushNamedCClosureImpl(void* L, void* func, int a, const char* name, int b) {
    hks::pushnamedcclosure(reinterpret_cast<hks::lua_State*>(L), reinterpret_cast<hks::luaFunc>(func), a, name, b);
}

int LuaCheckIntegerImpl(void* L, int index) {
    return hks::checkinteger(reinterpret_cast<hks::lua_State*>(L), index);
}

double LuaCheckNumberImpl(void* L, int index) {
    return hks::checknumber(reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaSetFieldImpl(void* L, int stackOffset, const char* name) {
    hks::setfield(reinterpret_cast<hks::lua_State*>(L), stackOffset, name);
}

int LuaGetTopImpl(void* L) {
    return hks::gettop(reinterpret_cast<hks::lua_State*>(L));
}

int LuaDoStringImpl(void* L, const char* str) {
    return hks::dostring(reinterpret_cast<hks::lua_State*>(L), str);
}

int LuaToBooleanImpl(void* L, int index) {
    return hks::toboolean(reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaPushNumberImpl(void* L, double num) {
    hks::pushnumber(reinterpret_cast<hks::lua_State*>(L), num);
}

void LuaPushIntegerImpl(void* L, int num) {
    hks::pushnumber(reinterpret_cast<hks::lua_State*>(L), num);
}

void LuaErrorImpl(void* L, char const* str, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, str);
    vsnprintf(buffer, sizeof(buffer), str, args);
    va_end(args);
    hks::error(reinterpret_cast<hks::lua_State*>(L), "%s", buffer);
}

char const* LuaPushFStringImpl(void* L, char const* str, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, str);
    vsnprintf(buffer, sizeof(buffer), str, args);
    va_end(args);
    return hks::pushfstring(reinterpret_cast<hks::lua_State*>(L), "%s", buffer);
}

char const* LuaCheckLStringImpl(void* L, int index, unsigned __int64* a) {
    return hks::checklstring(reinterpret_cast<hks::lua_State*>(L), index, a);
}

void* LuaToUserDataImpl(void* L, int index) {
    return hks::touserdata(reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaGetFieldImpl(void* L, int a, char const* b) {
    hks::getfield(reinterpret_cast<hks::lua_State*>(L), a, b);
}

void LuaPopImpl(void* L, int a) {
    hks::pop(reinterpret_cast<hks::lua_State*>(L), a);
}

void LuaCreateTableImpl(void* L, int a, int b) {
    hks::createtable(reinterpret_cast<hks::lua_State*>(L), a, b);
}

void* LuaToCFunctionImpl(void* L, int index) {
    return reinterpret_cast<void*>(hks::tocfunction(reinterpret_cast<hks::lua_State*>(L), index));
}

void LuaCheckTableImpl(void* L, int index) {
    hks::checktable(reinterpret_cast<hks::lua_State*>(L), index);
}

unsigned long long LuaObjLenImpl(void* L, int index) {
    return hks::objlen(reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaGetTableImpl(void* L, int index) {
    hks::gettable(reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaCPcallImpl(void* L, int a, void* func, int b) {
    hks::cpcall(reinterpret_cast<hks::lua_State*>(L), a, reinterpret_cast<hks::luaFunc>(func), b);
}

int LuaRefImpl(void* L, int index) {
    return hks::ref(reinterpret_cast<hks::lua_State*>(L), index);
}

int LuaPcallImpl(void* L, int a, int b, int c) {
    return hks::pcall(reinterpret_cast<hks::lua_State*>(L), a, b, c);
}

void LuaPushValueImpl(void* L, int value) {
    hks::pushvalue(reinterpret_cast<hks::lua_State*>(L), value);
}

void LuaRawGetIImpl(void* L, int a, int b) {
    hks::rawgeti(reinterpret_cast<hks::lua_State*>(L), a, b);
}

void LuaUnrefImpl(void* L, int a, int b) {
    hks::unref(reinterpret_cast<hks::lua_State*>(L), a, b);
}

void LuaSetTableImpl(void* L, int t) {
    hks::settable(reinterpret_cast<hks::lua_State*>(L), t);
}

int LuaIsNumberImpl(void* L, int num) {
    return hks::isnumber(reinterpret_cast<hks::lua_State*>(L), num);
}

double LuaToNumberImpl(void* L, int num) {
    return hks::tonumber(reinterpret_cast<hks::lua_State*>(L), num);
}

int LuaIsUserDataImpl(void* L, int num) {
    return hks::isuserdata(reinterpret_cast<hks::lua_State*>(L), num);
}

int LuaOpenDebugImpl(void* L) {
    return hks::luaopen_debug(reinterpret_cast<hks::lua_State*>(L));
}

int LuaToIntegerImpl(void* L, int num) {
    return hks::tointeger(reinterpret_cast<hks::lua_State*>(L), num);
}

int LuaTypeImpl(void* L, int num) {
    return hks::type(reinterpret_cast<hks::lua_State*>(L), num);
}

int LuaOptIntegerImpl(void* L, int a, int b) {
    return hks::optinteger(reinterpret_cast<hks::lua_State*>(L), a, b);
}

int LuaSetHookImpl(void* L, void* a, int b, int c) {
    return hks::sethook(reinterpret_cast<hks::lua_State*>(L), a, b, c);
}

void* LuaGetHookImpl(void* L) {
    return hks::gethook(reinterpret_cast<hks::lua_State*>(L));
}

int LuaGetHookMaskImpl(void* L) {
    return hks::gethookmask(reinterpret_cast<hks::lua_State*>(L));
}

int LuaGetHookCountImpl(void* L) {
    return hks::gethookcount(reinterpret_cast<hks::lua_State*>(L));
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

HMODULE Create() {
    g_GameCore = LoadLibrary(TEXT("../../../DLC/Expansion2/Binaries/Win64/GameCore_XP2_FinalRelease.dll"));
    if (!g_GameCore) {
        Logger::Log("Original GameCore failed to load err=%lu", GetLastError());
        return g_GameCore;
    }
    if (!AttachGameCore(g_GameCore)) {
        FreeLibrary(g_GameCore);
        g_GameCore = nullptr;
    }
    return g_GameCore;
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

    g_GameCore = gameCore;
    g_GameCoreAddress = reinterpret_cast<uintptr_t>(g_GameCore);
    g_GameCoreSizeOfImage = sizeOfImage;
    GameCoreAddress = g_GameCoreAddress;
    GameProcessId = GetCurrentProcessId();
    GameProcess = GetCurrentProcess();
    BaseAddress = (uintptr_t)GetModuleHandle(NULL);
    Runtime::Attach(gameCore);

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

// v2 统一插件加载流程：LoadLibraryExW + OnLoad(SEH) + OnMessage 自动注册 + 记录跟踪项。
// nameNarrow = 显示名（通常为文件名，内部取 stem 作 Patch owner / OnMessage 名）；已加载（同句柄）返回 false。
static bool LoadPluginDllInternal(const std::wstring& wpath, const std::string& nameNarrow,
    LoaderCore::PluginCategory category) {
    HMODULE hPlugin = LoadLibraryExW(wpath.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!hPlugin) {
        Logger::Log("LoadPlugin failed: %s err=%lu", ModScan::WideToNarrow(wpath).c_str(), GetLastError());
        return false;
    }

    for (const auto& entry : g_plugins) {
        if (entry.handle == hPlugin) {
            FreeLibrary(hPlugin);
            return false;
        }
    }

    auto onLoad = (OnLoadFunc)GetProcAddress(hPlugin, "OnLoad");
    if (!onLoad) {
        Logger::Log("Plugin has no OnLoad export: %s", ModScan::WideToNarrow(wpath).c_str());
        FreeLibrary(hPlugin);
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
        // Keep the module mapped: a partially initialized plugin may already
        // have registered callbacks or detours into its image. Unmapping it
        // here would turn those pointers into immediate use-after-free.
        Logger::Log("Plugin quarantined after OnLoad failure: %s", narrow.c_str());
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

void UnloadPlugins() {
    // v1 兼容入口：全量卸载（先 GameCore 后 Global，与加载次序相反）。
    LoaderCore::UnloadPluginsOf(LoaderCore::PluginCategory::GameCore);
    LoaderCore::UnloadPluginsOf(LoaderCore::PluginCategory::Global);
}

string GetCurrentModuleDir() {
    char path[MAX_PATH];
    GetModuleFileNameA(g_loaderModule, path, MAX_PATH);
    string fullPath = path;
    size_t pos = fullPath.find_last_of("\\/");
    return fullPath.substr(0, pos);
}

void OnLoaderMessage(const char* topic, const void* data, size_t len) {
    Logger::Log("OnLoaderMessage %s", topic ? topic : "");
    if (topic && data && strcmp(topic, "load-plugin") == 0 && len > 0) {
        string path((const char*)data, len);
        LoadPluginDLL("loader", path);
    }
}

bool InitializeLoader(HMODULE hModule) {
    g_loaderModule = hModule;
    RegisterMessageHandlerImpl("Loader", OnLoaderMessage);
    return true;
}

void CleanupLoader() {
    // Hooks may detour into plugin code — tear down MinHook before FreeLibrary.
    Runtime::Destroy();
    ResetScriptHookState();
    ResetPushHookSlots();
    g_bus.Clear();
    UnloadPlugins();
    g_loaderModule = nullptr;
    g_GameCore = nullptr;
    g_GameCoreAddress = 0;
    g_GameCoreSizeOfImage = 0;
}

void BroadcastLoaderMessage(const char* topic, const void* data, size_t len) {
    BroadcastMessageImpl(topic, data, len);
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
            MH_DisableHook(target);
            MH_RemoveHook(target);
            it = g_pluginHookOwners.erase(it);
            Logger::Log("RemovePluginHooks: removed hook at %p (owner=%ls)", target, owner);
        } else {
            ++it;
        }
    }
}

// 按跟踪项卸载单个插件（调用方保证 index 有效）：
// OnUnload → PatchRegistry::RevertAllFor(name) → RemovePluginHooks(name) → FreeLibrary，语义与 S2a 接线一致。
static void UnloadPluginEntryAt(size_t index) {
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
    // 注销 OnMessage：否则 bus 里残留指向本映像的 handler，FreeLibrary 后广播/定向发送会跳进已释放内存。
    const std::string handlerName = ModScan::WideToNarrow(entry.name);
    if (!handlerName.empty()) {
        g_bus.UnregisterHandler(handlerName);
    }
    SetActivePluginName(nullptr);
    FreeLibrary(entry.handle);
    Logger::Log("Unloaded plugin %s", ModScan::WideToNarrow(entry.path).c_str());
}

static const char* CategoryNameForLog(LoaderCore::PluginCategory cat) {
    return cat == LoaderCore::PluginCategory::GameCore ? "GameCore" : "Global";
}

void LoaderCore::LoadPluginsOf(PluginCategory cat) {
    const HMODULE anchor = LoaderCore::RuntimeModuleHandle();
    const auto wpaths = (cat == PluginCategory::GameCore)
        ? ModScan::FindGameCorePluginCandidates(anchor)
        : ModScan::FindGlobalPluginCandidates(anchor);
    Logger::Log("LoadPluginsOf(%s): %zu candidate(s)", CategoryNameForLog(cat), wpaths.size());
    for (const auto& wpath : wpaths) {
        LoadSinglePlugin(wpath);
    }
}

void LoaderCore::UnloadPluginsOf(PluginCategory cat) {
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
    for (const auto& entry : g_plugins) {
        if (NormalizePluginPath(entry.path) == norm) {
            Logger::Log("LoadSinglePlugin: already loaded %s", ModScan::WideToNarrow(path).c_str());
            return false;
        }
    }
    const std::wstring filename = fs::path(path).filename().wstring();
    return LoadPluginDllInternal(path, ModScan::WideToNarrow(filename), CategoryForPath(path));
}

void LoaderCore::UnloadSinglePlugin(const std::wstring& path) {
    const std::wstring norm = NormalizePluginPath(path);
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
    hks::InitHavokScript();
    Localization::InitScript();
    g_gameCorePhaseReady = true;
    Logger::Log("InitializeGameCorePhase: OK");
    return true;
}

void LoaderCore::ReconcileGlobalPlugins() {
    const auto expected = ModScan::FindGlobalPluginCandidates(LoaderCore::RuntimeModuleHandle());

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

void LoaderCore::ResetForReload() {
    // UnloadPluginsOf 自身不触碰初始化标志，天然无递归。
    UnloadPluginsOf(PluginCategory::GameCore);
    g_gameCorePhaseReady = false;
    Logger::Log("ResetForReload: GameCore plugins unloaded, phase-B flag cleared");
}
