#pragma once

#include <Windows.h>
#include <stdint.h>
#include <stddef.h>

// Plugin <-> Runtime HookAPI ABI generation.
// Bump ONLY on breaking changes (reorder/remove/change existing fields or PushLuaMethods contract).
// Appending new fields at the end must NOT bump this - old plugins rely on structSize.
#ifndef CIV6_HOOK_API_VERSION
#define CIV6_HOOK_API_VERSION 2u
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

// GameCore 生命周期回调（Global 插件延迟挂钩的标准姿势）。
// context 原样回传，插件可放自己的状态指针。
typedef void (*GameCoreReadyFn)(void* context);
typedef void (*GameCoreTeardownFn)(void* context);

// 可被插件寻址的具体 PE 映像。同一时刻一个 exe 与一个 GameCore 可以共存。
typedef enum HookImageId {
    kHookImageInvalid = 0,
    kHookImageExeDx11,
    kHookImageExeDx12,
    kHookImageGameCoreBase,
    kHookImageGameCoreXP1,
    kHookImageGameCoreXP2
} HookImageId;

// 段限定：ResolveByRvaEx / ResolveByPattern 用。kSectionImage = 整个镜像（镜像相对 RVA）。
typedef enum HookImageSection {
    kSectionImage = 0,   // 默认：整个镜像（不按段切）
    kSectionText,        // .text
    kSectionIdata,       // .idata
    kSectionRdata,       // .rdata
    kSectionData         // .data
} HookImageSection;

typedef struct HookImageInfo {
    uint32_t structSize;  // 调用前设为 sizeof(HookImageInfo)；0 视为当前头文件大小
    HookImageId image;
    uintptr_t base;
    size_t imageSize;
    uint64_t generation;  // exe 恒为 1；GameCore 每次 attach 递增
} HookImageInfo;

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

    bool (*IsImageLoaded)(HookImageId image);
    bool (*GetImageInfo)(HookImageId image, HookImageInfo* outInfo);
    void* (*ResolveByRva)(HookImageId image, uintptr_t rva, size_t span);
    void* (*ResolveByName)(HookImageId image, const char* name);
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

    int (*RegisterPushMethodsTarget)(const char* name, int sigType, const char* pushMethodsSymbol);

    // v2: 原始字节补丁（单层存档，见 patch registry）。由运行时在初始化时填表。
    bool (*Patch)(void* target, const void* bytes, size_t len);
    bool (*Unpatch)(void* target);

    // v2.1: GameCore 生命周期回调 —— Global 插件延迟挂钩的标准姿势：
    //   OnLoad → 先 RegisterGameCoreTeardown(teardown) → 再 RegisterGameCoreReady(ready)
    //   → ready 内 ResolveByName/ResolveByRva + InstallHook/Patch。
    // 语义要点：
    //  - Ready 回调在游戏线程、新 GameCore attach 后触发（早于 GameCore 插件加载）；
    //    注册时若 GameCore 已就绪（如对局中加载的插件），回调立即补调一次。
    //  - Teardown 回调在旧 GameCore 映像卸载前触发；该代插件钩已被禁用，仍可
    //    解析符号读数据收尾，但禁止再对旧映像装钩/打补丁（会被拒绝）。
    //    Global 插件若要 InstallHook 到 GameCore，必须先注册 Teardown，否则拒绝。
    //  - 每次重载为一"代"：teardown 后该代 GameCore 域的钩与补丁会被运行时统一
    //    撤销——插件须在 Teardown 返回前排空自身在途 detour 并置空 original
    //    trampoline；下一次 Ready 回调重新安装并取得新 trampoline。
    //  - 回调应保持短小（持运行时生命周期锁执行，重活自行开线程）；崩溃的回调
    //    会被 SEH 捕获，插件随之被隔离（其全部注册被回滚）。
    void (*RegisterGameCoreReady)(GameCoreReadyFn fn, void* context);
    void (*RegisterGameCoreTeardown)(GameCoreTeardownFn fn, void* context);

    // ---- Append-only extensions (do not bump CIV6_HOOK_API_VERSION) ----
    // 不修正 + 段限定：原始 RVA 直接解析（镜像相对或段相对），不走 pdata 矫正。
    void* (*ResolveByRvaEx)(HookImageId image, uintptr_t rva, size_t span, HookImageSection section);
    // AOB 特征搜索：pattern 形如 "48 8B ?? ?? 74 ?? E8"（?? 通配符），在指定段搜首个命中。
    void* (*ResolveByPattern)(HookImageId image, const char* pattern, HookImageSection section);
    // 注册全局变量捕获：hook providerFunction，运行时用机器码生成 stub 捕获其第 paramIndex 个
    // 参数（仅前 4 个寄存器参数，paramIndex 0-3），写入 out 指向的 void*。同一 providerFunction
    // 只 hook 一次，后续注册的 out 追加到列表，触发时统一赋值。返回 false = 注册失败（providerFunction 解析失败等）。
    bool (*RegisterGlobalCapture)(HookImageId image, const char* providerFunction, uint32_t paramIndex, void** out);
    // 按 vtable 符号名（demangled/mangled）解析第 index 个虚函数槽位（0 起）：
    // 定位 vtable 地址（版本一致恒等，跨版本走槽位结构匹配），读 [vtable + index*8] 的
    // 槽函数指针并返回。index 超出 vtable 槽位数时打日志并返回 nullptr。
    void* (*ResolveByVTable)(HookImageId image, const char* vtableSymbol, uint32_t index);
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
T ResolveByName(HookAPI* api, HookImageId image, const char* name) {
    return reinterpret_cast<T>(api->ResolveByName(image, name));
}

template <typename T>
void InstallHook(HookAPI* api, LPVOID pTarget, LPVOID pDetour, T** ppOriginal) {
    api->InstallHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
T ResolveByRva(HookAPI* api, HookImageId image, uintptr_t rva, size_t span = 1) {
    return reinterpret_cast<T>(api->ResolveByRva(image, rva, span));
}

template <typename T>
T ResolveByRvaEx(HookAPI* api, HookImageId image, uintptr_t rva, HookImageSection section = kSectionImage, size_t span = 1) {
    return reinterpret_cast<T>(api->ResolveByRvaEx(image, rva, span, section));
}

template <typename T>
T ResolveByPattern(HookAPI* api, HookImageId image, const char* pattern, HookImageSection section = kSectionImage) {
    return reinterpret_cast<T>(api->ResolveByPattern(image, pattern, section));
}

template <typename T>
T ResolveByVTable(HookAPI* api, HookImageId image, const char* vtableSymbol, uint32_t index) {
    return reinterpret_cast<T>(api->ResolveByVTable(image, vtableSymbol, index));
}
#endif

// Recommended plugin exports (not required beyond OnLoad).
// extern "C" __declspec(dllexport) void OnLoad(HookAPI* api);
// extern "C" __declspec(dllexport) void OnUnload();
// extern "C" __declspec(dllexport) void OnMessage(const char* topic, const void* data, size_t len);
