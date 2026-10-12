#pragma once

#include <Windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Plugin <-> Runtime HookAPI ABI.
//
// 【预发布阶段：没有任何存量插件需要兼容】删改这个表不升版本号——从未对外发布过插件，
// 1 是 apiVersion 唯一出现过的值。首次对外发布之后若再破坏前缀，才需要递增版本号，
// 并把配套的兼容约定补回来。
//
// 拒载插件 ≠ "它的代码没跑过"：LoadLibraryExW 已经执行过插件的 DllMain 与 CRT 初始化，
// 所以被拒的模块可能已经持有线程或裸 OS 级钩子。这是一个信任边界，不是安全保证。
// 文件尾部的类别门禁让 GameCore 专属入口在 Global 插件里编译期就报错。
/* Loader 侧（非插件 TU）：DllLoaderRuntime 在 vcxproj 预处理宏里【显式】定义
   CIV6_HOOKAPI_BUILD_IMPL。没有它，Loader 那些包含 HookAPI.h 的 TU 会命中文件尾部的
   "必须声明插件类别" #error；插件工程不得定义它。（薄壳 DllLoader 不包含本头，也就不
   再定义该宏。） */

// 插件类别取值（1=Global，2=GameCore；3 预留给未来的 Frontend）。
// 这里先按插件宏定值：紧随其后的 Civ6PluginKind 导出要用它；文件尾部的门禁块再用 #ifndef
// 兜底定义同样的值（那里拿它重命名 GameCore 专属成员，让越界调用在编译期报错）。
// Loader 侧（CIV6_HOOKAPI_BUILD_IMPL）不定义该值。
#if defined(CIV6_PLUGIN_GLOBAL)
#define CIV6_PLUGIN_KIND_VALUE 1u
#elif defined(CIV6_PLUGIN_GAMECORE)
#define CIV6_PLUGIN_KIND_VALUE 2u
#endif


// 预发布阶段（从未对外发布过任何插件）：删改前缀不升版本号，1 是唯一出现过的值。
// 首次对外发布之后再破坏前缀，才按规则 3 递增。
#ifndef CIV6_HOOK_API_VERSION
#define CIV6_HOOK_API_VERSION 1u
#endif

// 插件类别导出（由本头文件自动发出，插件作者零改动）：
//   loader 在调 OnLoad 之前 GetProcAddress("Civ6PluginKind") 读它，用低 32 位 kind 与"安装路径
//   推出的类别"对账，不符 = OnLoad 之前就拒载（此刻插件没有任何钩子/补丁/回调，FreeLibrary 永远安全）。
//   高 32 位 apiVersion 只进日志/诊断，不参与拒载：ABI 兼容性仍由插件侧 HookAPI_IsCompatible 判。
//   inline 是必须的（同一头文件被多个 TU 包含）；返回值是纯常量，不碰游戏状态、不需要 static。
//   loader 侧（CIV6_HOOKAPI_BUILD_IMPL）不发出该导出。
#if defined(CIV6_PLUGIN_GLOBAL) || defined(CIV6_PLUGIN_GAMECORE)
#if !defined(CIV6_PLUGIN_KIND_VALUE)
#error "CIV6: 必须声明插件类别（CIV6_PLUGIN_KIND_VALUE = 1 Global / 2 GameCore）"
#endif
extern "C" __declspec(dllexport) inline uint64_t Civ6PluginKind(void) {
    return static_cast<uint64_t>(CIV6_PLUGIN_KIND_VALUE) |
        (static_cast<uint64_t>(CIV6_HOOK_API_VERSION) << 32);   // 低 32=kind，高 32=apiVersion
}
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
    kHookApiPushMethodsInstalled = 1
} HookApiPushMethodsResult;

// GetSymbolDbState 的返回值：内置符号库（sidecar）与目标映像的匹配状态。
// 用途：插件在依赖硬编码旧 RVA / 符号名之前，先判断矫正机制是否可用，
// 从而决定"照常用"还是"降级/关闭功能并提示用户更新 Loader"。
typedef enum HookApiSymbolDbState {
    // sidecar 里没有该映像的模块：完全没有符号数据，ResolveByRva/ResolveByName 必然失败。
    kHookApiDbNoContext = 0,
    // 有该映像的模块，但尚未建表（映像还没加载，或建表还没轮到）。稍后再查。
    kHookApiDbNotReady,
    // 建表失败：本次会话该映像不做矫正，旧 RVA 会解析失败（fail-closed，不回退原 RVA）。
    kHookApiDbBuildFailed,
    // 符号库与该映像**同一构建**：RVA 恒等，最可靠。此时 GetSymbolDbMatchRatio 返回 1.0。
    kHookApiDbIdentical,
    // 跨版本对齐成功：旧 RVA 会被矫正到当前映像。个别函数可能未匹配上，
    // 用 GetSymbolDbMatchRatio 看整体比例；单点是否可用仍以解析结果为准。
    kHookApiDbCrossVersion
} HookApiSymbolDbState;

typedef struct HookAPI {
    uint32_t apiVersion;   // 预发布阶段恒为 1；删改前缀不升版本号（见文件头说明）
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
    // AOB 特征搜索：pattern 形如 "48 8B ?? ?? 74 ?? E8"（?? 通配符），在指定段搜第 index 个命中。
    // 每字节两字符：?? 整字节通配，4? / ?F 分别固定高/低半字节；十六进制字母大小写均可。
    // 字节间可用空格、Tab、逗号分隔或直接相连；格式错误或未命中返回 nullptr。
    // index 从 1 起（0 视为 1），按地址升序计数；命中数不足 index 时返回 nullptr 并记日志。
    void* (*ResolveByPattern)(HookImageId image, const char* pattern, HookImageSection section,
        uint32_t index);
    // 注册全局变量捕获：hook providerAddress，运行时用机器码生成 stub 捕获其第 paramIndex 个
    // 参数（仅前 4 个寄存器参数，paramIndex 0-3），写入 out 指向的 void*。
    // providerAddress 是【绝对地址】（插件自行用 Resolve* 等入口取址后再传进来），且必须是
    // 可执行的函数入口：Loader 只探页属性（可读 + 落在可执行页），不做任何名字/符号/映像解析。
    // 同一 providerAddress 只 hook 一次，后续注册的 out 追加到列表，触发时统一赋值。
    // 返回 false = 注册失败（地址为空/不可读/不在可执行页、paramIndex > 3、out 槽不可写、
    // 目标属于正在拆除的 GameCore、或该地址对调用方不开放等）。
    // out 槽须位于注册插件的模块内；卸载/隔离只移除该插件的槽，保留其它插件的共享订阅。
    // 最后一个订阅移除后才摘钩；GameCore 重载只清除落在当前 GameCore 映像内的订阅
    // （exe/常驻模块域上的订阅保留），GameCore 域订阅须在下一次 GameCore 插件加载（OnLoad）时重新注册。
    bool (*RegisterGlobalCapture)(void* providerAddress, uint32_t paramIndex, void** out);
    // 按 vtable 符号名（demangled/mangled）解析第 index 个虚函数槽位（0 起）：
    // 定位 vtable 地址（版本一致恒等，跨版本走槽位结构匹配），读 [vtable + index*8] 的
    // 槽函数指针并返回。index 超出 vtable 槽位数时打日志并返回 nullptr。
    void* (*ResolveByVTable)(HookImageId image, const char* vtableSymbol, uint32_t index);

    // Failed：本次没有安装任何方法（GameCore 未就绪、符号解析失败，或与同一 target 上
    //   的既有定义冲突）；Installed：本次已安装。
    // 同 owner + target + exposedName 的相同定义重复调用幂等；同 target 的同名
    // 不同定义（包括不同 owner）整批拒绝。函数和 internalName/exposedName 均须非空。
    // 参数由 Loader 复制。原 PushMethods 由 Loader 自动调用，本接口不再返回其
    // trampoline；预发布插件须按当前头文件重新编译。
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
    // Lua 引用：把栈顶的值存进 t 指向的表，返回引用号（>=1），栈顶随之弹出。
    //   t 是【表在栈上的位置】，支持伪索引：-10000 = registry、-10001 = 环境、
    //   -10002 = globals（即 kHookApiLuaGlobal）；负数按栈顶算、正数按栈底算。
    //   ⚠ 传 -1 之类的"值的位置"是错的：引擎会把它当表去索引，内部再按指针解引用
    //   -> 访问违例（0xC0000005）。要用全局表就传 kHookApiLuaGlobal。
    //   语义来源：HavokScript_FinalRelease.dll 的 hksi_luaL_ref 反编译（非标准 Lua，
    //   但参数含义与 luaL_ref 一致，且额外支持上述伪索引）。
    int (*LuaRef)(void*, int);
    int (*LuaPcall)(void*, int, int, int);
    void (*LuaPushValue)(void*, int);
    void (*LuaRawGetI)(void*, int, int);
    // Lua 释放引用：参数顺序是 (t = 表位置, ref = 引用号)，与 luaL_unref 一致。
    // ref < 0 时忽略。t 用与 LuaRef 相同的伪索引（通常 kHookApiLuaGlobal）。
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
    // 字符串哈希：不再解析 GameCore 符号，改为 Loader 内部实现的原生 CRC32（raw，
    // 无最终异或，与官方 GameCore::Utilities::MakeHash 逐位一致）。对局前/重载后都能算。
    uint32_t (*MakeHash)(const char* str);

    // 注册插件自己的 PushMethods 目标配置。pushMethodsSymbol 为空时使用 name + "::PushMethods"；
    // 非空时该完整符号名用于解析本次安装的目标。
    // 配置按调用插件 owner 隔离，不能覆盖 Loader 内置目标或其他插件配置；同 owner 重复配置
    // 必须完全一致。name 指针必须来自调用插件模块。
    int (*RegisterPushMethodsTarget)(const char* name, int sigType, const char* pushMethodsSymbol);

    // 原始字节补丁（单层存档，见 patch registry）。两个槽在 Loader 的静态 HookAPI 表
    // （g_hookApi，编译期常量初始化）里一次性填好，运行期不再改表。
    bool (*Patch)(void* target, const void* bytes, size_t len);
    bool (*Unpatch)(void* target);

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

    // 引擎的**主 Lua VM**（exe 全局 LuaSystem::LuaScriptSystem 单例的 +0x10，RVA 0x2D08F88）。
    // 这是**进程级** state：由 lua_newstate() 在 Civ6App::GUIInit 时创建一次，只在
    // Civ6App::GUIShutdown 时 lua_close —— **换局不会让它失效，也不会被重写**
    // （全 exe 只有一处写 +0x10，就是 Setup 里 lua_newstate 之后那一次）。
    //
    // 名字来源于引擎自己：结构体成员就叫 m_pkMainLuaState，Tuner 注册时给的字符串名是
    // "Main State"。官方 GameCore::ScriptSystem::CallHook 也是读它：
    //   mov rax, cs:ms_apSingletonInstance ; mov rcx, [rax+10h] ; jmp GameEventLibrary::CallHook
    // 本接口按同款方式每次实时读单例槽再取 +0x10（槽会在 GUIShutdown 时被清零并 lua_close，
    // 所以绝不能缓存返回的指针）。
    //
    // 【别和"每局 thread state"混淆】Civ6 确实是多 lua_State 引擎，但那些是
    // lua_newthread(main_state) 派生出来的 coroutine：GameCore 每局用
    // IScriptSystem1::CreateLuaThread 建、结束时 FreeLuaThread 回收，**换局必失效**。
    // 本接口返回的不是它们。若插件持有的是某个 thread state，那才是会崩的场景。
    //
    // **Global 与 GameCore 两类插件都可调用，不限类别。** 这个 state 是进程级的，常驻插件
    // 持有它不会因换局而悬垂（这正是它与 §地址域门 所防的"GameCore 短命域地址"的根本区别）。
    // 之所以早先一度给它加类别门，是因为把"GameCore.dll 用 Lua::ms_CriticalSection、
    // exe 用 Lua::Details::LockAccess，是两个不同临界区实例"误当成了类别问题——那其实是
    // **线程**问题：约束是"仅游戏线程调用"，与插件类别无关，类别门拦不住跨线程调用。
    //
    // 仅游戏线程调用（Lua 状态非线程安全）。未就绪（GUIShutdown 之后 / 尚未 GUIInit）
    // 返回 nullptr。
    void* (*GetMainLuaState)(void);

    // Lua nil 入栈（hks ?hksi_lua_pushnil 导出）。参数打包回调里构造 nil 参数用。
    void (*LuaPushNil)(void* L);

    // ---- 符号库状态查询 ----
    // 内置符号库（sidecar）与指定映像的匹配状态，见 HookApiSymbolDbState 各值说明。
    // 返回 kHookApiDbNoContext = 该映像根本没有符号数据；kHookApiDbBuildFailed = 有数据但
    // 本次会话建表失败。两者都意味着该映像上的 ResolveByRva/ResolveByName 会返回 nullptr。
    // 纯查询，不加锁竞争、不改任何状态，可在任意线程调用。
    HookApiSymbolDbState (*GetSymbolDbState)(HookImageId image);

    // 跨版本对齐的匹配率（已匹配的 .pdata 条目数 / 总条目数），取值 [0.0, 1.0]。
    // 仅 kHookApiDbCrossVersion 状态下是"部分匹配"的度量；此时 1.0 表示全部对齐。
    // 非跨版本状态返回：Identical -> 1.0（恒等映射，无失配），其它 -> 0.0（无数据/不可用）。
    // 用于诊断与降级决策；单点能否解析仍以 ResolveByRva/ResolveByName 的返回值为准。
    double (*GetSymbolDbMatchRatio)(HookImageId image);

} HookAPI;

// True if this runtime can serve a plugin built from this header.
// Call it once at the top of OnLoad and abort if it returns 0: the second test is the
// append-only case (runtime table shorter than this plugin's header), the first is the
// breaking-change case. The plugin kind is NOT declared here - it travels in the
// Civ6PluginKind export emitted above, and the loader checks it before OnLoad.
static inline int HookAPI_IsCompatible(const HookAPI* api) {
    if (!api) return 0;
    if (api->apiVersion != CIV6_HOOK_API_VERSION) return 0;
    if (api->structSize < sizeof(HookAPI)) return 0;
    return 1;
}

#ifdef __cplusplus
}  // extern "C"

// HookAPI 里"入口"（函数指针）字段的数量。它是追加字段时唯一需要同步的计数：
// 追加字段 -> 改这个常量 -> Civ6DLLHookLoaderAPI.cpp 的 static_assert 会逼着你把
// g_hookApi 的位置初始化补齐（聚合初始化少写几项只会静默零填，运行时就是空指针调用）。
constexpr uint32_t CIV6_HOOK_API_ENTRY_COUNT = 77;

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
T ResolveByPattern(HookAPI* api, HookImageId image, const char* pattern,
    HookImageSection section = kSectionImage, uint32_t index = 1) {
    return reinterpret_cast<T>(api->ResolveByPattern(image, pattern, section, index));
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
        result = api->ResolveByPattern(image, info.aob, kSectionText, info.index);
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

    void* hit = api->ResolveByPattern(image, flat, kSectionText, index);
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
//
// ABI guard (do this first thing in OnLoad):
//   if (!HookAPI_IsCompatible(api)) {
//       if (api) api->Log("Civ6DllLoader is older than this plugin; please update the loader.");
//       return;
//   }
// This is how a plugin built from a newer header detects an older runtime instead of
// reading past the end of the table. The table itself is read-only - writing to it faults.
/* ---- 插件类别门禁（纯编译期语法门：不改结构体、不改布局） ----
   同一个 CIV6_PLUGIN_KIND_VALUE 驱动两件事：
     a) 本文件前段据此发出 Civ6PluginKind 导出（loader 在 OnLoad 之前判类别 + apiVersion）；
     b) 下面据此重命名 GameCore 专属成员名，越界调用在编译期就报错。 */
#if !defined(CIV6_PLUGIN_GLOBAL) && !defined(CIV6_PLUGIN_GAMECORE) && !defined(CIV6_HOOKAPI_BUILD_IMPL)
#error "CIV6: 必须声明插件类别：在工程预处理宏里定义 CIV6_PLUGIN_GLOBAL 或 CIV6_PLUGIN_GAMECORE"
#endif

#if defined(CIV6_PLUGIN_GLOBAL)
#ifndef CIV6_PLUGIN_KIND_VALUE
#define CIV6_PLUGIN_KIND_VALUE 1u
#endif
/* GameCore 专属入口：对象式宏重命名 -> 调用或取地址都在编译期报"不是 HookAPI 的成员"。
   结构体字段一个没少、偏移一个没变，只是这些名字在本 TU 里指向了不存在的成员。 */
#define EditPlayer                 CIV6_ERROR_EditPlayer_is_GameCoreOnly_rebuild_as_CIV6_PLUGIN_GAMECORE
#define RegisterGameEvent          CIV6_ERROR_RegisterGameEvent_is_GameCoreOnly_rebuild_as_CIV6_PLUGIN_GAMECORE
#define TriggerGameEvent           CIV6_ERROR_TriggerGameEvent_is_GameCoreOnly_rebuild_as_CIV6_PLUGIN_GAMECORE
#define RegisterScriptGlobals      CIV6_ERROR_RegisterScriptGlobals_is_GameCoreOnly_rebuild_as_CIV6_PLUGIN_GAMECORE
#define RegisterScriptGlobalsForUI CIV6_ERROR_RegisterScriptGlobalsForUI_is_GameCoreOnly_rebuild_as_CIV6_PLUGIN_GAMECORE
#define PushLuaMethods             CIV6_ERROR_PushLuaMethods_is_GameCoreOnly_rebuild_as_CIV6_PLUGIN_GAMECORE
#define RegisterPushMethodsTarget  CIV6_ERROR_RegisterPushMethodsTarget_is_GameCoreOnly_rebuild_as_CIV6_PLUGIN_GAMECORE
#elif defined(CIV6_PLUGIN_GAMECORE)
#ifndef CIV6_PLUGIN_KIND_VALUE
#define CIV6_PLUGIN_KIND_VALUE 2u
#endif
/* GameCore 类别：当前没有"只给 Global 用"的入口，无需重命名任何成员。 */
#endif

