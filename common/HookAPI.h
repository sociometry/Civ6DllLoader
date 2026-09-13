#pragma once

#include <Windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Plugin <-> Runtime HookAPI ABI generation.
// This pre-release ABI is defined by the current field order; plugins must be rebuilt when it changes.
// Keep the generation at 1 for the unpublished 1.0.0 line.
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

// Lua 侧参数打包回调（RegisterGameEvent 用）：插件往 Lua 栈压**任意个任意类型**的参数，
// 返回压入个数（0 = 无参调用）。用法与 Lua C 函数一致：
//   标量：LuaPushInteger/… 逐个压，return 5 → Call(42, "smoke", 1.5, true, nil)
//   表：  LuaCreateTable + LuaSetField 填字段，return 1 → Call(info)（字符串键/嵌套/数组）
//   混合：随意组合。
// runtime 负责其余全部机制：活跃 state 获取、锁协议、GameEvents[name].Call、栈清理。
// 仅游戏线程调用；L 为当前活跃游戏 Lua 状态。
typedef int (*GameEventPushFn)(void* L, const void* payload);
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

// ---- 通用取址描述（不限映像；exe 域配 HookInfoExe 二选一）----
// 三种取址方式，各自可附带一条 AOB 兜底（仅主路径失败时使用；命中处即地址）：
//   kHookInfoRva    : rva（走 pdata 矫正，语义同 ResolveByRva）
//   kHookInfoVTable : vtableName + 槽序号（0,1,2...，同 ResolveByVTable）
//   kHookInfoName   : 符号名（demangled / mangled 均可，同 ResolveByName）
typedef enum HookInfoKind {
    kHookInfoRva = 0,
    kHookInfoVTable = 1,
    kHookInfoName = 2
} HookInfoKind;

typedef struct HookInfoVTableRef {
    const char* vtableName;
    uint32_t slotIndex;   // 槽函数序号（0 起；不是字节偏移）
} HookInfoVTableRef;

typedef struct HookInfo {
    HookInfoKind kind;
    const char*  aob;     // 可选：AOB（语法同 ResolveByPattern）
    uint32_t     index;   // AOB 多命中时选第几个（1 起；0 视为默认 1）
    union {
        uintptr_t         rva;
        HookInfoVTableRef vtable;
        const char*       name;
    } u;
} HookInfo;

// 按当前进程实际加载的 exe 二选一：CivilizationVI.exe -> dx11，CivilizationVI_DX12.exe -> dx12。
typedef struct HookInfoExe {
    HookInfo dx11;
    HookInfo dx12;
} HookInfoExe;

// Matches hks::LUA_GLOBAL - plugins can use this with LuaSetField.
enum { kHookApiLuaGlobal = -10002 };

// LuaCPcall: negative values are loader errors (Lua stack unchanged).
// Zero is success; positive values are the engine's Lua error status.
enum {
    kHookApiLuaCallUnavailable = -1,
    kHookApiLuaCallInvalidArgument = -2
};

// RegisterPushMethodsTarget sigType
enum {
    kHookApiPushNoManager = 0,
    kHookApiPushWithManager = 1
};

typedef enum HookApiPushMethodsResult {
    kHookApiPushMethodsFailed = 0,
    kHookApiPushMethodsDeferred = 1,
    kHookApiPushMethodsInstalled = 2
} HookApiPushMethodsResult;

typedef struct HookAPI {
    uint32_t apiVersion;   // CIV6_HOOK_API_VERSION (generation; not bumped for appends)
    uint32_t structSize;   // sizeof(HookAPI) of the *runtime*; plugins compare against their sizeof

    bool (*InstallHook)(void* targetFunc, void* detour, void** original);
    void (*BroadcastMessage)(const char* topic, const void* data, size_t len);
    // handler 必须位于 Loader 跟踪的插件模块中，以其所属插件作为注册 owner。
    // 地址固定为该插件的 DLL 文件名（去掉最后的扩展名，UTF-8、区分大小写），
    // 不接受自定义地址；同插件重复注册替换旧回调。
    // 空回调、未跟踪/已停用/已隔离的插件、保留名 "Loader" 或其它插件已占用的同名地址返回 false。
    // OnLoad 返回后，导出的 OnMessage 在同一地址自动登记并替换显式回调。
    // 预发布插件须用当前头文件重新编译。
    bool (*RegisterMessageHandler)(MessageHandlerFn handler);
    void (*SendMessageTo)(const char* pluginName, const char* topic, const void* data, size_t len);

    bool (*IsImageLoaded)(HookImageId image);
    bool (*GetImageInfo)(HookImageId image, HookImageInfo* outInfo);
    void* (*ResolveByRva)(HookImageId image, uintptr_t rva, size_t span);
    void* (*ResolveByName)(HookImageId image, const char* name);
    // ---- Image resolution extensions ----
    // 不修正 + 段限定：原始 RVA 直接解析（镜像相对或段相对），不走 pdata 矫正。
    void* (*ResolveByRvaEx)(HookImageId image, uintptr_t rva, size_t span, HookImageSection section);
    // AOB 特征搜索：pattern 形如 "48 8B ?? ?? 74 ?? E8"（?? 通配符），在指定段搜首个命中。
    // 每字节两字符：?? 整字节通配，4? / ?F 分别固定高/低半字节；十六进制字母大小写均可。
    // 字节间可用空格、Tab、逗号分隔或直接相连；格式错误或未命中返回 nullptr。
    void* (*ResolveByPattern)(HookImageId image, const char* pattern, HookImageSection section);
    // 注册全局变量捕获：hook providerFunction，运行时用机器码生成 stub 捕获其第 paramIndex 个
    // 参数（仅前 4 个寄存器参数，paramIndex 0-3），写入 out 指向的 void*。同一 providerFunction
    // 只 hook 一次，后续注册的 out 追加到列表，触发时统一赋值。返回 false = 注册失败（providerFunction 解析失败等）。
    // out 槽须位于注册插件的模块内；卸载/隔离只移除该插件的槽，保留其它插件的共享订阅。
    // 最后一个订阅移除后才摘钩；GameCore 重载会清除全部订阅，须在下一次 Ready 中重新注册。
    bool (*RegisterGlobalCapture)(HookImageId image, const char* providerFunction, uint32_t paramIndex, void** out);
    // 按 vtable 符号名（demangled/mangled）解析第 index 个虚函数槽位（0 起）：
    // 定位 vtable 地址（版本一致恒等，跨版本走槽位结构匹配），读 [vtable + index*8] 的
    // 槽函数指针并返回。index 超出 vtable 槽位数时打日志并返回 nullptr。
    void* (*ResolveByVTable)(HookImageId image, const char* vtableSymbol, uint32_t index);

    // Failed：本次没有新增登记/方法，先前已接受的登记保留。
    // Deferred：已接受登记，GameCore 就绪时自动尝试安装；Installed：本次已安装。
    // 同 owner + target + exposedName 的相同定义重复调用幂等；同 target 的同名
    // 不同定义（包括不同 owner）整批拒绝。函数和 internalName/exposedName 均须非空。
    // 参数由 Loader 复制，登记保留到插件停用；Global 插件跨 GameCore 重载自动重装。
    // 延迟安装失败会记日志并保留登记，可用相同参数重试。原 PushMethods 由 Loader
    // 自动调用，本接口不再返回其 trampoline；预发布插件须按当前头文件重新编译。
    HookApiPushMethodsResult (*PushLuaMethods)(const char* name, const LuaMethodInfo* methods, uint32_t count);

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
    // Correct protected C call: callback receives L; userdata is passed to the engine
    // as a full-width pointer. Returns 0 on success, the engine's positive Lua status
    // on error, or kHookApiLuaCall* for invalid arguments / missing imports.
    // Call on the thread owning L; L and callback must be non-null; userdata may be null.
    int (*LuaCPcall)(void* L, LuaMethodFunc callback, void* userdata);
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

    // ---- Utility and Lua convenience extensions ----
    void (*Log)(const char* format, ...);
    void (*LuaPushCFunctionField)(void* L, int tableIndex, const char* fieldName, void* fn, const char* internalName);
    void (*LuaNewGlobalTable)(void* L, const char* globalName, int narr, int nrec);

    void* (*LocalizationLookup)(void* outLocString, const char* key);

    uint32_t (*LocStringBytes)(void);
    void* (*LocCreate)(void);
    void (*LocDestroy)(void* loc);
    void* (*LocLookup)(void* loc, const char* key);
    int (*LocPushArgument)(void* loc, const char* arg);
    const char* (*LocToUtf8)(void* loc);

    void* (*EditPlayer)(int playerId);
    const char* (*GetCivilizationDescription)(void* player);
    uint32_t (*MakeHash)(const char* str);

    // 注册插件自己的 PushMethods 目标配置。pushMethodsSymbol 为空时使用 name + "::PushMethods"；
    // 非空时该完整符号名会同时用于首次解析和 GameCore 重载后的重装。
    // 配置按调用插件 owner 隔离，不能覆盖 Loader 内置目标或其他插件配置；同 owner 重复配置
    // 必须完全一致，已有该目标登记后也不能修改配置。name 指针必须来自调用插件模块。
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

    // GameEvents：纯登记 + 插件端手动触发。name 为 GameEvent 名（如 "MyCustomEvent"），
    // 最长 95 个字节（不含结尾 NUL）；超长名称直接返回 false，不会截断或占用槽位。
    // RegisterGameEvent：登记 Lua 侧构造参数事件（任意类型/个数，字符串键表/嵌套/数组）。
    //   pushFn 往 Lua 栈压参数并返回个数（0 = 无参调用），runtime 负责活跃 state 获取、
    //   锁协议、GameEvents[name].Call、栈清理（见 C++ 区 GameEventPushFn 说明）。
    //   返回 false = 注册失败（未就绪/无空槽/无 owner 等）。同名重复注册幂等返回 true。
    bool (*RegisterGameEvent)(const char* name, GameEventPushFn pushFn);
    // TriggerGameEvent：手动触发一次（必须先注册——回查注册记录拿 pushFn，未注册返回 false），
    //   payload 传给注册时的 pushFn（payload 同步解析，仅在本调用期间有效；pushFn 为 null = 无参调用）。
    //   插件回调与 Lua 调用的 SEH/C++ 异常由 Loader 截获并返回 false。
    //   GameCore 锁状态无法判定时（EngineUtility 解析失败或取/放锁调用异常）拒绝执行并返回 false：
    //   宁可漏触发，也不在持锁状态下重入 Lua（可能自死锁或破坏 Lua 状态）。
    //   必须在游戏线程调用——Lua 状态非线程安全。
    bool (*TriggerGameEvent)(const char* name, const void* payload);

    // GameCore::EngineUtility 全局对象指针（ms_pkCurrentGame 槽 +0x18，与 scriptSystem +0x20
    // 同族；IDA 实证 www.ms_pkEngineUtility）——锁协议用：
    //   had = eu->vtable[6](eu)  HasGameCoreLock（+0x30）
    //   if (had) eu->vtable[7](eu)  ReleaseGameCoreLock（+0x38）
    //   ... Lua 工作 ...
    //   if (had) eu->vtable[8](eu)  GetGameCoreLock（+0x40）
    // 与官方 Utility::CallHook 完全同款三步。GameCore 未就绪返回 nullptr。
    void* (*GetEngineUtility)(void);

    // 当前活跃游戏 Lua 状态——**官方 GameCore::ScriptSystem::CallHook 同款**：
    // 每次实时读 exe 全局 LuaSystem::LuaScriptSystem::ms_apSingletonInstance（RVA 0x2D08F88）
    // 的 +0x10 字段（引擎在对局/脚本切换时更新它）。
    // 【真机教训】不要缓存阶段 C 的 L：Civ6 多 lua_State 引擎，启动 state 与每局对局 state
    // 分离（全局表共享、API 栈不共享），旧 state 失效后 GetField 触发 hks 致命错误（80000003）。
    // 仅游戏线程调用；无对局/未就绪返回 nullptr。
    void* (*GetActiveLuaState)(void);

    // Lua nil 入栈（hks ?hksi_lua_pushnil 导出）。参数打包回调里构造 nil 参数用。
    void (*LuaPushNil)(void* L);
} HookAPI;

// True if this runtime can serve a plugin built against the current pre-release header.
// Plugins must be rebuilt after a field reorder; apiVersion remains 1 for the unpublished line.
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

// ---------------- HookInfo 取址工具（header-only，只组合 HookAPI 既有入口，不占 ABI 字段）----------------

static constexpr HookInfo HookRva(uintptr_t rva, const char* aob = nullptr,
    uint32_t index = 1) {
    HookInfo info{};
    info.kind = kHookInfoRva;
    info.aob = aob;
    info.index = index;
    info.u.rva = rva;
    return info;
}

static constexpr HookInfo HookVTable(const char* vtableName, uint32_t slotIndex,
    const char* aob = nullptr, uint32_t index = 1) {
    HookInfo info{};
    info.kind = kHookInfoVTable;
    info.aob = aob;
    info.index = index;
    info.u.vtable.vtableName = vtableName;
    info.u.vtable.slotIndex = slotIndex;
    return info;
}

static constexpr HookInfo HookName(const char* name, const char* aob = nullptr,
    uint32_t index = 1) {
    HookInfo info{};
    info.kind = kHookInfoName;
    info.aob = aob;
    info.index = index;
    info.u.name = name;
    return info;
}

// AOB 语法解析（与 HookAPI::ResolveByPattern 完全一致：?? 整字节通配、4?/?F 半字节、十六进制）。
static inline bool HookParsePattern(const char* pattern, uint8_t* values, uint8_t* masks,
    int maxTokens, int* outCount) {
    if (!pattern || !values || !masks || !outCount || maxTokens <= 0) return false;
    int count = 0;
    const char* p = pattern;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == '\n' || *p == '\r') ++p;
        if (!*p) break;
        if (count >= maxTokens) return false;
        uint8_t value = 0;
        uint8_t mask = 0;
        for (int nib = 0; nib < 2; ++nib) {
            value = static_cast<uint8_t>(value << 4);
            mask = static_cast<uint8_t>(mask << 4);
            const char c = *p;
            if (c == '?') {
                ++p;
            } else if (c >= '0' && c <= '9') {
                value = static_cast<uint8_t>(value | (c - '0'));
                mask = static_cast<uint8_t>(mask | 0xF);
                ++p;
            } else if (c >= 'a' && c <= 'f') {
                value = static_cast<uint8_t>(value | (c - 'a' + 10));
                mask = static_cast<uint8_t>(mask | 0xF);
                ++p;
            } else if (c >= 'A' && c <= 'F') {
                value = static_cast<uint8_t>(value | (c - 'A' + 10));
                mask = static_cast<uint8_t>(mask | 0xF);
                ++p;
            } else {
                return false;
            }
        }
        values[count] = value;
        masks[count] = mask;
        ++count;
    }
    *outCount = count;
    return count > 0;
}

// 定位映像里指定名字的段（PE 段表，语义同 runtime 内部 ResolveSectionRva；返回段起始指针）。
static inline const uint8_t* HookFindSection(HookAPI* api, HookImageId image, const char* name,
    size_t* outSize) {
    if (!api || !name) return nullptr;
    HookImageInfo info{};
    info.structSize = sizeof(HookImageInfo);
    if (!api->GetImageInfo(image, &info) || !info.base) return nullptr;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(info.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(info.base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        bool match = true;
        for (int k = 0; k < 8; ++k) {
            if (sec->Name[k] != static_cast<unsigned char>(name[k])) { match = false; break; }
            if (name[k] == '\0') break;
        }
        if (!match) continue;
        const size_t size = sec->Misc.VirtualSize > sec->SizeOfRawData
            ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (outSize) *outSize = size;
        return reinterpret_cast<const uint8_t*>(info.base) + sec->VirtualAddress;
    }
    return nullptr;
}

// AOB 第 index 个命中（1 起；0 视为 1）：index <= 1 直接走 HookAPI::ResolveByPattern（行为不变），
// index > 1 时在 .text 段内自行扫描取第 index 个（API 只给首命中，故无法纯组合实现）。
static inline void* HookScanPatternNth(HookAPI* api, HookImageId image, const char* pattern,
    uint32_t index) {
    if (!api || !pattern || !*pattern) return nullptr;
    if (index <= 1) return api->ResolveByPattern(image, pattern, kSectionText);
    constexpr int kMaxTokens = 512;
    uint8_t values[kMaxTokens];
    uint8_t masks[kMaxTokens];
    int count = 0;
    if (!HookParsePattern(pattern, values, masks, kMaxTokens, &count) || count == 0) return nullptr;
    size_t sectionSize = 0;
    const uint8_t* begin = HookFindSection(api, image, ".text", &sectionSize);
    if (!begin || sectionSize < static_cast<size_t>(count)) return nullptr;
    const size_t limit = sectionSize - static_cast<size_t>(count) + 1;
    uint32_t hits = 0;
    for (size_t i = 0; i < limit; ++i) {
        bool match = true;
        for (int j = 0; j < count; ++j) {
            if ((begin[i + j] & masks[j]) != values[j]) { match = false; break; }
        }
        if (match && ++hits == index) return const_cast<uint8_t*>(begin + i);
    }
    return nullptr;
}

// 解析一条 HookInfo：主路径（Rva / VTable / Name）失败时，若有 aob 则按 index 兜底定位。
static inline void* ResolveByHookInfo(HookAPI* api, HookImageId image, const HookInfo& info,
    size_t span = 1) {
    if (!api) return nullptr;
    void* result = nullptr;
    switch (info.kind) {
        case kHookInfoRva:
            if (info.u.rva != 0) result = api->ResolveByRva(image, info.u.rva, span);
            break;
        case kHookInfoVTable:
            if (info.u.vtable.vtableName && *info.u.vtable.vtableName)
                result = api->ResolveByVTable(image, info.u.vtable.vtableName, info.u.vtable.slotIndex);
            break;
        case kHookInfoName:
            if (info.u.name && *info.u.name) result = api->ResolveByName(image, info.u.name);
            break;
        default:
            break;
    }
    if (!result && info.aob && *info.aob)
        result = HookScanPatternNth(api, image, info.aob, info.index);
    return result;
}

// 当前进程 exe 的镜像 id（Dx11 / Dx12；未识别 = kHookImageInvalid）。内部细节，不写进文档。
static inline HookImageId HookCurrentExeImage(HookAPI* api) {
    if (!api) return kHookImageInvalid;
    HookImageInfo info{};
    info.structSize = sizeof(HookImageInfo);
    if (api->GetImageInfo(kHookImageExeDx11, &info)) return kHookImageExeDx11;
    info = HookImageInfo{};
    info.structSize = sizeof(HookImageInfo);
    if (api->GetImageInfo(kHookImageExeDx12, &info)) return kHookImageExeDx12;
    return kHookImageInvalid;
}

static inline void* ResolveByHookInfoExe(HookAPI* api, const HookInfoExe& info, size_t span = 1) {
    const HookImageId image = HookCurrentExeImage(api);
    if (image == kHookImageInvalid) return nullptr;
    return ResolveByHookInfo(api, image,
        image == kHookImageExeDx12 ? info.dx12 : info.dx11, span);
}

static inline bool HookAobIsHex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// AOB 相对寻址定位（不限映像；内部扫 .text）：
//   AOB 用 | 切分指令段；含 xx xx xx xx 的段 = 目标指令；段内恰好一组 xx（= disp32）。
//   命中 H、目标段起止字节偏移 S/E（| 不计入）、xx 组偏移 D  ->  目标 = H + E + i32[H + D]。
//   运行期 | 去掉、xx 换成 ??，交给 ResolveByPattern；命中不唯一/格式非法/目标越界 -> nullptr。
static inline void* ResolveDataByAob(HookAPI* api, HookImageId image, const char* aob,
    uint32_t index = 1) {
    if (!api || image == kHookImageInvalid || !aob || !*aob) return nullptr;
    constexpr int kMaxTokens = 256;
    char flat[kMaxTokens * 3 + 1];
    size_t flatLen = 0;
    int segIndex = 0;
    int byteOff = 0;
    int tokenSeg[kMaxTokens];
    int tokenByte[kMaxTokens];
    bool tokenXx[kMaxTokens];
    char tokenText[kMaxTokens][3];
    int tokenCount = 0;
    int xxFirst = -1;
    int xxCount = 0;

    const char* p = aob;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == '\n' || *p == '\r') ++p;
        if (!*p) break;
        if (*p == '|') { ++segIndex; ++p; continue; }
        const char c0 = p[0];
        const char c1 = p[1];
        if (!c0 || !c1) return nullptr;
        if (c1 == ' ' || c1 == '\t' || c1 == ',' || c1 == '|' || c1 == '\n' || c1 == '\r')
            return nullptr;   // 必须两位一组
        const bool isXx = (c0 == 'x' || c0 == 'X') && (c1 == 'x' || c1 == 'X');
        if (!isXx) {
            const bool wild0 = (c0 == '?');
            const bool wild1 = (c1 == '?');
            if (!wild0 && !HookAobIsHex(c0)) return nullptr;
            if (!wild1 && !HookAobIsHex(c1)) return nullptr;
        }
        if (tokenCount >= kMaxTokens || flatLen + 4 >= sizeof(flat)) return nullptr;
        tokenText[tokenCount][0] = c0;
        tokenText[tokenCount][1] = c1;
        tokenText[tokenCount][2] = '\0';
        tokenXx[tokenCount] = isXx;
        tokenSeg[tokenCount] = segIndex;
        tokenByte[tokenCount] = byteOff;
        if (isXx) {
            if (xxFirst < 0) xxFirst = tokenCount;
            ++xxCount;
            flat[flatLen++] = '?';
            flat[flatLen++] = '?';
        } else {
            flat[flatLen++] = c0;
            flat[flatLen++] = c1;
        }
        flat[flatLen++] = ' ';
        ++tokenCount;
        ++byteOff;
        p += 2;
    }
    flat[flatLen] = '\0';
    if (tokenCount == 0 || xxCount != 4 || xxFirst < 0) return nullptr;
    const int xxSeg = tokenSeg[xxFirst];
    for (int i = xxFirst; i < xxFirst + 4; ++i) {
        if (i >= tokenCount || !tokenXx[i] || tokenSeg[i] != xxSeg) return nullptr;
    }
    // 目标段结束偏移 E = 该段最后一个 token 的字节偏移 + 1
    int segEnd = -1;
    for (int i = tokenCount - 1; i >= 0; --i) {
        if (tokenSeg[i] == xxSeg) { segEnd = tokenByte[i] + 1; break; }
    }
    if (segEnd < 0) return nullptr;
    const int D = tokenByte[xxFirst];
    const int E = segEnd;
    if (D < 0 || D + 4 > E) return nullptr;

    void* hit = HookScanPatternNth(api, image, flat, index);
    if (!hit) return nullptr;
    int32_t disp = 0;
    memcpy(&disp, static_cast<const char*>(hit) + D, sizeof(disp));
    const intptr_t delta = static_cast<intptr_t>(E) + static_cast<intptr_t>(disp);
    const uintptr_t hitAddr = reinterpret_cast<uintptr_t>(hit);
    uintptr_t target = 0;
    if (delta >= 0) {
        target = hitAddr + static_cast<uintptr_t>(delta);
    } else {
        const uintptr_t back = static_cast<uintptr_t>(-delta);
        if (back > hitAddr) return nullptr;
        target = hitAddr - back;
    }
    HookImageInfo info{};
    info.structSize = sizeof(HookImageInfo);
    if (!api->GetImageInfo(image, &info) || !info.base || !info.imageSize) return nullptr;
    if (target < info.base || target - info.base >= info.imageSize) return nullptr;
    return reinterpret_cast<void*>(target);
}

#endif

// Recommended plugin exports (not required beyond OnLoad).
// extern "C" __declspec(dllexport) void OnLoad(HookAPI* api);
// extern "C" __declspec(dllexport) void OnUnload();
// extern "C" __declspec(dllexport) void OnMessage(const char* topic, const void* data, size_t len);
