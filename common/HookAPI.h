#pragma once

#include <Windows.h>
#include <stdint.h>
#include <stddef.h>

// Plugin <-> Runtime HookAPI ABI generation.
// Bump ONLY on breaking changes (reorder/remove/change existing fields or PushLuaMethods contract).
// Appending new fields at the end must NOT bump this - old plugins rely on structSize.
#ifndef CIV6_HOOK_API_VERSION
#define CIV6_HOOK_API_VERSION 1u
#endif

// Opaque Localization::String storage size for stack buffers (bytes). Prefer LocCreate/LocDestroy.
#ifndef CIV6_HOOK_API_LOC_STRING_BYTES
#define CIV6_HOOK_API_LOC_STRING_BYTES 256u
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int(__fastcall* LuaMethodFunc)(void* L);

typedef struct LuaMethodInfo {
    LuaMethodFunc luaMethodFunc;
    const char* internalName;
    const char* exposedName;
} LuaMethodInfo;

typedef void (*MessageHandlerFn)(const char* topic, const void* data, size_t len);
typedef void (*ScriptGlobalsFn)(void* L);

// Matches hks::LUA_GLOBAL - plugins can use this with LuaSetField.
enum { kHookApiLuaGlobal = -10002 };

// RegisterPushMethodsTarget sigType
enum {
    kHookApiPushNoManager = 0,
    kHookApiPushWithManager = 1
};

typedef struct HookAPI {
    uint32_t apiVersion;   // CIV6_HOOK_API_VERSION (generation; not bumped for appends)
    uint32_t structSize;   // sizeof(HookAPI) of the *runtime*; plugins compare against their sizeof

    bool (*InstallHook)(void* targetFunc, void* detour, void** original);
    void (*BroadcastMessage)(const char* topic, const void* data, size_t len);
    void (*RegisterMessageHandler)(const char* pluginName, MessageHandlerFn handler);
    void (*SendMessageTo)(const char* pluginName, const char* topic, const void* data, size_t len);

    uintptr_t (*GetGameCoreAddress)(void);
    void* (*GetFunctionByName)(const char* functionName);
    void* (*GetFunctionByAddress)(uintptr_t address);
    void* (*PushLuaMethods)(const char* name, const LuaMethodInfo* methods, uint32_t count);

    unsigned int (*GetCurTurn)(void);

    void (*RegisterScriptGlobals)(ScriptGlobalsFn fn);
    void (*RegisterScriptGlobalsForUI)(ScriptGlobalsFn fn);

    void (*LuaPushNamedCClosure)(void*, void*, int, const char*, int);
    int (*LuaCheckInteger)(void*, int);
    double (*LuaCheckNumber)(void*, int);
    void (*LuaSetField)(void*, int, const char*);
    int (*LuaGetTop)(void*);
    int (*LuaDoString)(void*, const char*);
    int (*LuaToBoolean)(void*, int);
    void (*LuaPushNumber)(void*, double);
    void (*LuaPushInteger)(void*, int);
    void (*LuaError)(void*, char const*, ...);
    char const* (*LuaPushFString)(void*, char const*, ...);
    char const* (*LuaCheckLString)(void*, int, unsigned __int64*);
    void* (*LuaToUserData)(void*, int);
    void (*LuaGetField)(void*, int, char const*);
    void (*LuaPop)(void*, int);
    void (*LuaCreateTable)(void*, int, int);
    void* (*LuaToCFunction)(void*, int);
    void (*LuaCheckTable)(void*, int);
    unsigned long long (*LuaObjLen)(void*, int);
    void (*LuaGetTable)(void*, int);
    void (*LuaCPcall)(void*, int, void*, int);
    int (*LuaRef)(void*, int);
    int (*LuaPcall)(void*, int, int, int);
    void (*LuaPushValue)(void*, int);
    void (*LuaRawGetI)(void*, int, int);
    void (*LuaUnref)(void*, int, int);
    void (*LuaSetTable)(void*, int);
    int (*LuaIsNumber)(void*, int);
    double (*LuaToNumber)(void*, int);
    int (*LuaIsUserData)(void*, int);
    int (*LuaOpenDebug)(void*);
    int (*LuaToInteger)(void*, int);
    int (*LuaType)(void*, int);
    int (*LuaOptInteger)(void*, int, int);
    int (*LuaSetHook)(void*, void*, int, int);
    void* (*LuaGetHook)(void*);
    int (*LuaGetHookMask)(void*);
    int (*LuaGetHookCount)(void*);
    int (*LuaCheckPlayerId)(void*, int);
    void (*LuaPushBoolean)(void* L, bool value);
    void (*LuaPushLightUserData)(void* L, void* ptr);

    void* (*LocalizationLookup)(void* outLocString, const char* key);

    // ---- Append-only extensions (do not bump CIV6_HOOK_API_VERSION) ----
    void (*Log)(const char* format, ...);
    void (*LuaPushCFunctionField)(void* L, int tableIndex, const char* fieldName, void* fn, const char* internalName);
    void (*LuaNewGlobalTable)(void* L, const char* globalName, int narr, int nrec);

    uint32_t (*LocStringBytes)(void);
    void* (*LocCreate)(void);
    void (*LocDestroy)(void* loc);
    void* (*LocLookup)(void* loc, const char* key);
    int (*LocPushArgument)(void* loc, const char* arg);
    const char* (*LocToUtf8)(void* loc);

    int64_t (*SendGameEvent)(int64_t eventId, unsigned int a, unsigned int b);
    void* (*EditPlayer)(int playerId);
    const char* (*GetCivilizationDescription)(void* player);
    uint32_t (*MakeHash)(const char* str);

    void* (*RequireFunction)(const char* functionName);
    int (*ResolveSymbol)(const char* functionName, void** out);
    int (*RegisterGameCoreRva)(const char* name, uint32_t rva);
    int (*RegisterPushMethodsTarget)(const char* name, int sigType, const char* pushMethodsSymbol);
} HookAPI;

// True if this runtime can serve a plugin built against the current header.
// - apiVersion must match the ABI generation (breaking-change counter).
// - structSize must be at least this plugin's sizeof(HookAPI) (runtime may be newer/larger).
static inline int HookAPI_IsCompatible(const HookAPI* api) {
    if (!api) return 0;
    if (api->apiVersion != CIV6_HOOK_API_VERSION) return 0;
    if (api->structSize < sizeof(HookAPI)) return 0;
    return 1;
}

// Optional: probe whether runtime exposes fields past minStructSize
// (pass sizeof(HookAPI) from a newer header copy if you dual-target).
static inline int HookAPI_HasMinSize(const HookAPI* api, uint32_t minStructSize) {
    if (!api) return 0;
    if (api->apiVersion != CIV6_HOOK_API_VERSION) return 0;
    return api->structSize >= minStructSize ? 1 : 0;
}

#ifdef __cplusplus
}  // extern "C"

template <typename T>
T GetFunctionByName(HookAPI* api, const char* functionName) {
    return reinterpret_cast<T>(api->GetFunctionByName(functionName));
}

template <typename T>
T GetFunctionByAddress(HookAPI* api, uintptr_t address) {
    return reinterpret_cast<T>(api->GetFunctionByAddress(address));
}

template <typename T>
void InstallHook(HookAPI* api, LPVOID pTarget, LPVOID pDetour, T** ppOriginal) {
    api->InstallHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
T RequireFunction(HookAPI* api, const char* functionName) {
    return reinterpret_cast<T>(api->RequireFunction(functionName));
}
#endif

// Recommended plugin exports (not required beyond OnLoad).
// extern "C" __declspec(dllexport) void OnLoad(HookAPI* api);
// extern "C" __declspec(dllexport) void OnUnload();
// extern "C" __declspec(dllexport) void OnMessage(const char* topic, const void* data, size_t len);
