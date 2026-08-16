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
#include "Logger.h"
#include "../common/ModScan.h"
#include "ProxyTypes.h"
#include "Localization.h"
#include "HavokScript.h"
#include "SymbolDb.h"

#include <cstdarg>
#include <cstdlib>

using namespace std;

static Civ6MessageBus g_bus;

static HMODULE g_loaderModule = NULL;
static vector<HMODULE> g_pluginHandles;

static HMODULE g_GameCore;
static uintptr_t g_GameCoreAddress;
static uint32_t g_GameCoreSizeOfImage;

HMODULE GameCore;
uintptr_t GameCoreAddress;
DWORD GameProcessId;
HANDLE GameProcess;
uintptr_t BaseAddress;


//static unordered_map<string, uintptr_t> g_PushMethodsAddresses = {
//    {"GameCore::Cache::Lua::IQuestsManager", 0x6B8750},
//    {"GameCore::Lua::IQuestsManager", 0x6FA1A0},
//};
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

//void InitLuaMethodHooks(HookAPI* api) {
//    for (const auto& [targetName, methodList] : g_LuaMethodLists) {
//        auto it = g_PushMethodAddresses.find(targetName);
//        if (it == g_PushMethodAddresses.end()) {
//            cerr << "[Hook] Target " << targetName << " not found.\n";
//            continue;
//        }
//
//        void* target = api->GetFunctionByName(targetName.c_str());
//        if (!target) {
//            cerr << "[Hook] Function " << targetName << " address is null.\n";
//            continue;
//        }
//
//        // ???? detour ????
//        auto detour = CreateLuaPushDetour(targetName);
//        if (!detour) {
//            cerr << "[Hook] Failed to create detour for " << targetName << "\n";
//            continue;
//        }
//
//        void* original = nullptr;
//        if (MH_CreateHook(target, detour, &original) != MH_OK ||
//            MH_EnableHook(target) != MH_OK) {
//            cerr << "[Hook] MH hook failed for " << targetName << "\n";
//            continue;
//        }
//
//        g_OriginalFunctions[targetName] = original;
//        cout << "[Hook] Hooked " << targetName << "\n";
//    }
//}

//void RegisterLuaMethods(const LuaMethodRegistration& registration) {
//    g_PushMethodAddresses[registration.name] = (void*)registration.pushMethodOffset;
//    g_LuaMethodLists[registration.name] = registration.methods;
//}

//void* CreateLuaPushDetour(const string& targetName) {
//    auto it = g_LuaMethodLists.find(targetName);
//    if (it == g_LuaMethodLists.end()) return nullptr;
//
//    const auto& methodList = it->second;
//    void* originalFunc = nullptr;
//
//    // lambda???????????????????detour
//    if (targetName.starts_with("Cache::")) {
//        // ????? Cache ????
//        return (void*)__fastcall + [](void* manager, hks::lua_State* L, int stackOffset) {
//            auto orig = reinterpret_cast<CachePushMethodFunc>(g_OriginalFunctions[targetName]);
//            for (auto& m : g_LuaMethodLists[targetName]) {
//                PushLuaMethod(L, m.luaMethodFunc, m.internalName.c_str(), stackOffset, m.exposedName.c_str());
//            }
//            orig(manager, L, stackOffset);
//            };
//    }
//    else {
//        return (void*)__fastcall + [](hks::lua_State* L, int stackOffset) {
//            auto orig = reinterpret_cast<PushMethodFunc>(g_OriginalFunctions[targetName]);
//            for (auto& m : g_LuaMethodLists[targetName]) {
//                PushLuaMethod(L, m.luaMethodFunc, m.internalName.c_str(), stackOffset, m.exposedName.c_str());
//            }
//            orig(L, stackOffset);
//            };
//    }
//}


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

//static std::vector<LuaMethodInfo> g_detourMethods_NoManager;
//static void(__fastcall* g_basePush_NoManager)(hks::lua_State*, int) = nullptr;
//
//static void __fastcall DetourPush_NoManager(hks::lua_State* L, int stackOffset) {
//    for (auto& method : g_detourMethods_NoManager) {
//        PushLuaMethod(L, method.luaMethodFunc, method.internalName.c_str(), stackOffset, method.exposedName.c_str());
//    }
//    if (g_basePush_NoManager) {
//        std::cout << "DetourPush_NoManager 1" << endl;
//        g_basePush_NoManager(L, stackOffset);
//    }
//        
//}
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

void LoadPluginDLL(const char* name, const string& path) {
    const std::wstring wpath = ModScan::NarrowToWide(path);
    HMODULE hPlugin = LoadLibraryExW(wpath.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!hPlugin) {
        Logger::Log("LoadPlugin failed: %s err=%lu", path.c_str(), GetLastError());
        return;
    }

    for (HMODULE existing : g_pluginHandles) {
        if (existing == hPlugin) {
            FreeLibrary(hPlugin);
            return;
        }
    }

    auto onLoad = (OnLoadFunc)GetProcAddress(hPlugin, "OnLoad");
    if (!onLoad) {
        Logger::Log("Plugin has no OnLoad export: %s", path.c_str());
        FreeLibrary(hPlugin);
        return;
    }

    Logger::Log("Loaded plugin %s (%s)", name, path.c_str());
    g_pluginHandles.push_back(hPlugin);
    if (!CallOnLoadSafe(onLoad, name)) {
        // Keep the module mapped: a partially initialized plugin may already
        // have registered callbacks or detours into its image. Unmapping it
        // here would turn those pointers into immediate use-after-free.
        Logger::Log("Plugin quarantined after OnLoad failure: %s", path.c_str());
        return;
    }

    auto onMessage = (OnMessageFunc)GetProcAddress(hPlugin, "OnMessage");
    if (onMessage) {
        // Register under filename stem so SendMessageTo("Example1", ...) works.
        string handlerName = name ? name : path;
        const size_t dot = handlerName.find_last_of('.');
        if (dot != string::npos) handlerName = handlerName.substr(0, dot);
        RegisterMessageHandlerImpl(handlerName.c_str(), onMessage);
        Logger::Log("Auto-registered OnMessage for %s", handlerName.c_str());
    }
}

void UnloadPlugins() {
    for (HMODULE h : g_pluginHandles) {
        auto onUnload = (OnUnloadFunc)GetProcAddress(h, "OnUnload");
        if (onUnload) CallOnUnloadSafe(onUnload, nullptr);
        FreeLibrary(h);
    }
    g_pluginHandles.clear();
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

void LoadPlugins() {
    if (!g_loaderModule) return;
    const auto plugins = ModScan::FindPluginCandidates(g_loaderModule);
    Logger::Log("Plugin candidates: %zu", plugins.size());
    for (const auto& wpath : plugins) {
        const string path = ModScan::WideToNarrow(wpath);
        LoadPluginDLL(fs::path(path).filename().string().c_str(), path);
    }
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
