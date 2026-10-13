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
//   高 32 位 apiVersion 只进日志/诊断，不参与拒载：ABI 兼容性仍由插件侧 HookContext_IsCompatible 判。
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

// ---------------- 插件 ABI 引导结构（唯一永久冻结的部分） ----------------
// loader 在 OnLoad 时把它传进来。这是 ABI 里唯一冻结的东西：
// 入口可以按名字增删，这里永远不动。插件的表由 HookAPI_Resolve 据此填满。
//
// 【字段顺序是刻意的】structSize 放偏移 0，它兼作"部署是否一致"的哨兵：
// 若插件与 loader 不是同一次构建（改了头文件却只重编了一边），两边对偏移的解释就不同，
// 此时新插件会把陈旧表的 apiVersion(=1) 读成 structSize，1 < sizeof(HookContext) 直接判否。
// 反过来旧插件把新表的 structSize(=16) 读成 apiVersion，不等于 1，同样判否。
// 两个方向都在调用任何函数指针之前退出，不会出现"把 InstallHook 当 Query 调用"。
typedef struct HookContext {
    uint32_t structSize;   // offset 0：loader 侧 sizeof(HookContext)；兼作部署一致性哨兵
    uint32_t apiVersion;   // 恒为 1；预发布阶段删改入口不递增
    // 名字 -> 函数地址；未知名字返回 nullptr。只认下面清单里的入口名，
    // 不暴露 loader 的任何其它函数（这是一道白名单）。
    void* (*Query)(const char* name);
} HookContext;

// ---------------- 入口清单（唯一来源） ----------------
// 每行四列，列名与下面各处 X 宏的参数名一致：
//
//   X(entryName, returnType, params, category)
//
//   entryName   入口名（如 InstallHook）。它同时是结构体成员名、Query 的查找键
//               （经 #entryName 字符串化得到），所以改名等于删一个入口。
//   returnType  返回类型。生成结构体时用；解析时不需要（decltype 能推出来）。
//   params      参数表，【含外层括号】（如 (int playerId)）。整块作为一个宏实参，
//               因此里面的逗号不会被切碎。
//   category    kCommon = Global 与 GameCore 两类插件都可用；
//               kGameCore = 仅 CIV6_PLUGIN_GAMECORE 生成成员，Global 编译期不可见。
//
// 【顺序即布局】loader 的 g_hookApi 用位置初始化，本清单顺序必须与它一致；
// 追加入口只可在末尾追加（docs/ARCHITECTURE.md §10.2）。
#define HOOK_API_LIST(X) \
    X(InstallHook, bool, (void* targetFunc, void* detour, void** original), kCommon) \
    X(BroadcastMessage, void, (const char* topic, const void* data, size_t len), kCommon) \
    /* handler 必须位于 Loader 跟踪的插件模块中，以其所属插件作为注册 owner。 \
       地址固定为该插件的 DLL 文件名（去掉最后的扩展名，UTF-8、区分大小写）， \
       不接受自定义地址；同插件重复注册替换旧回调。 \
       空回调、未跟踪/已停用/已隔离的插件、保留名 "Loader" 或其它插件已占用的同名地址返回 false。 \
       OnLoad 返回后，导出的 OnMessage 在同一地址自动登记并替换显式回调。 \
       预发布插件须用当前头文件重新编译。 */ \
    X(RegisterMessageHandler, bool, (MessageHandlerFn handler), kCommon) \
    X(SendMessageTo, void, (const char* pluginName, const char* topic, const void* data, size_t len), kCommon) \
    X(IsImageLoaded, bool, (HookImageId image), kCommon) \
    X(GetImageInfo, bool, (HookImageId image, HookImageInfo* outInfo), kCommon) \
    X(ResolveByRva, void*, (HookImageId image, uintptr_t rva, size_t span), kCommon) \
    X(ResolveByName, void*, (HookImageId image, const char* name), kCommon) \
    /* ---- Image resolution extensions ---- \
       不修正 + 段限定：原始 RVA 直接解析（镜像相对或段相对），不走 pdata 矫正。 */ \
    X(ResolveByRvaEx, void*, (HookImageId image, uintptr_t rva, size_t span, HookImageSection section), kCommon) \
    /* AOB 特征搜索：pattern 形如 "48 8B ?? ?? 74 ?? E8"（?? 通配符），在指定段搜第 index 个命中。 \
       每字节两字符：?? 整字节通配，4? / ?F 分别固定高/低半字节；十六进制字母大小写均可。 \
       字节间可用空格、Tab、逗号分隔或直接相连；格式错误或未命中返回 nullptr。 \
       index 从 1 起（0 视为 1），按地址升序计数；命中数不足 index 时返回 nullptr 并记日志。 */ \
    X(ResolveByPattern, void*, (HookImageId image, const char* pattern, HookImageSection section, uint32_t index), kCommon) \
    /* 注册全局变量捕获：hook providerAddress，运行时用机器码生成 stub 捕获其第 paramIndex 个 \
       参数（仅前 4 个寄存器参数，paramIndex 0-3），写入 out 指向的 void*。 \
       providerAddress 是【绝对地址】（插件自行用 Resolve* 等入口取址后再传进来），且必须是 \
       可执行的函数入口：Loader 只探页属性（可读 + 落在可执行页），不做任何名字/符号/映像解析。 \
       同一 providerAddress 只 hook 一次，后续注册的 out 追加到列表，触发时统一赋值。 \
       返回 false = 注册失败（地址为空/不可读/不在可执行页、paramIndex > 3、out 槽不可写、 \
       目标属于正在拆除的 GameCore、或该地址对调用方不开放等）。 \
       out 槽须位于注册插件的模块内；卸载/隔离只移除该插件的槽，保留其它插件的共享订阅。 \
       最后一个订阅移除后才摘钩；GameCore 重载只清除落在当前 GameCore 映像内的订阅 \
       （exe/常驻模块域上的订阅保留），GameCore 域订阅须在下一次 GameCore 插件加载（OnLoad）时重新注册。 */ \
    X(RegisterGlobalCapture, bool, (void* providerAddress, uint32_t paramIndex, void** out), kCommon) \
    /* 按 vtable 符号名（demangled/mangled）解析第 index 个虚函数槽位（0 起）： \
       定位 vtable 地址（版本一致恒等，跨版本走槽位结构匹配），读 [vtable + index*8] 的 \
       槽函数指针并返回。index 超出 vtable 槽位数时打日志并返回 nullptr。 */ \
    X(ResolveByVTable, void*, (HookImageId image, const char* vtableSymbol, uint32_t index), kCommon) \
    /* Failed：本次没有安装任何方法（GameCore 未就绪、符号解析失败，或与同一 target 上 \
       的既有定义冲突）；Installed：本次已安装。 \
       同 owner + target + exposedName 的相同定义重复调用幂等；同 target 的同名 \
       不同定义（包括不同 owner）整批拒绝。函数和 internalName/exposedName 均须非空。 \
       参数由 Loader 复制。原 PushMethods 由 Loader 自动调用，本接口不再返回其 \
       trampoline；预发布插件须按当前头文件重新编译。 */ \
    X(PushLuaMethods, HookApiPushMethodsResult, (const char* name, const LuaMethodInfo* methods, uint32_t count), kGameCore) \
    X(RegisterScriptGlobals, void, (ScriptGlobalsFn fn), kGameCore) \
    X(RegisterScriptGlobalsForUI, void, (ScriptGlobalsFn fn), kGameCore) \
    X(LuaPushNamedCClosure, void, (void*, void*, int, const char*, int), kCommon) \
    X(LuaCheckInteger, int, (void*, int), kCommon) \
    X(LuaCheckNumber, double, (void*, int), kCommon) \
    X(LuaSetField, void, (void*, int, const char*), kCommon) \
    X(LuaGetTop, int, (void*), kCommon) \
    X(LuaDoString, int, (void*, const char*), kCommon) \
    X(LuaToBoolean, int, (void*, int), kCommon) \
    X(LuaPushNumber, void, (void*, double), kCommon) \
    X(LuaPushInteger, void, (void*, int), kCommon) \
    X(LuaError, void, (void*, char const*, ...), kCommon) \
    X(LuaPushFString, char const*, (void*, char const*, ...), kCommon) \
    X(LuaCheckLString, char const*, (void*, int, unsigned __int64*), kCommon) \
    X(LuaToUserData, void*, (void*, int), kCommon) \
    X(LuaGetField, void, (void*, int, char const*), kCommon) \
    X(LuaPop, void, (void*, int), kCommon) \
    X(LuaCreateTable, void, (void*, int, int), kCommon) \
    X(LuaToCFunction, void*, (void*, int), kCommon) \
    X(LuaCheckTable, void, (void*, int), kCommon) \
    X(LuaObjLen, unsigned long long, (void*, int), kCommon) \
    X(LuaGetTable, void, (void*, int), kCommon) \
    /* Correct protected C call: callback receives L; userdata is passed to the engine \
       as a full-width pointer. Returns 0 on success, the engine's positive Lua status \
       on error, or kHookApiLuaCall* for invalid arguments / missing imports. \
       Call on the thread owning L; L and callback must be non-null; userdata may be null. */ \
    X(LuaCPcall, int, (void* L, LuaMethodFunc callback, void* userdata), kCommon) \
    /* Lua 引用：把栈顶的值存进 t 指向的表，返回引用号（>=1），栈顶随之弹出。 \
       t 是【表在栈上的位置】，支持伪索引：-10000 = registry、-10001 = 环境、 \
       -10002 = globals（即 kHookApiLuaGlobal）；负数按栈顶算、正数按栈底算。 \
       ⚠ 传 -1 之类的"值的位置"是错的：引擎会把它当表去索引，内部再按指针解引用 \
       -> 访问违例（0xC0000005）。要用全局表就传 kHookApiLuaGlobal。 \
       语义来源：HavokScript_FinalRelease.dll 的 hksi_luaL_ref 反编译（非标准 Lua， \
       但参数含义与 luaL_ref 一致，且额外支持上述伪索引）。 */ \
    X(LuaRef, int, (void*, int), kCommon) \
    X(LuaPcall, int, (void*, int, int, int), kCommon) \
    X(LuaPushValue, void, (void*, int), kCommon) \
    X(LuaRawGetI, void, (void*, int, int), kCommon) \
    /* Lua 释放引用：参数顺序是 (t = 表位置, ref = 引用号)，与 luaL_unref 一致。 \
       ref < 0 时忽略。t 用与 LuaRef 相同的伪索引（通常 kHookApiLuaGlobal）。 */ \
    X(LuaUnref, void, (void*, int, int), kCommon) \
    X(LuaSetTable, void, (void*, int), kCommon) \
    X(LuaIsNumber, int, (void*, int), kCommon) \
    X(LuaToNumber, double, (void*, int), kCommon) \
    X(LuaIsUserData, int, (void*, int), kCommon) \
    X(LuaOpenDebug, int, (void*), kCommon) \
    X(LuaToInteger, int, (void*, int), kCommon) \
    X(LuaType, int, (void*, int), kCommon) \
    X(LuaOptInteger, int, (void*, int, int), kCommon) \
    X(LuaSetHook, int, (void*, void*, int, int), kCommon) \
    X(LuaGetHook, void*, (void*), kCommon) \
    X(LuaGetHookMask, int, (void*), kCommon) \
    X(LuaGetHookCount, int, (void*), kCommon) \
    X(LuaCheckPlayerId, int, (void*, int), kCommon) \
    X(LuaPushBoolean, void, (void* L, bool value), kCommon) \
    X(LuaPushLightUserData, void, (void* L, void* ptr), kCommon) \
    /* ---- Utility and Lua convenience extensions ---- */ \
    X(Log, void, (const char* format, ...), kCommon) \
    X(LuaPushCFunctionField, void, (void* L, int tableIndex, const char* fieldName, void* fn, const char* internalName), kCommon) \
    X(LuaNewGlobalTable, void, (void* L, const char* globalName, int narr, int nrec), kCommon) \
    X(LocalizationLookup, void*, (void* outLocString, const char* key), kCommon) \
    X(LocStringBytes, uint32_t, (void), kCommon) \
    X(LocCreate, void*, (void), kCommon) \
    X(LocDestroy, void, (void* loc), kCommon) \
    X(LocLookup, void*, (void* loc, const char* key), kCommon) \
    X(LocPushArgument, int, (void* loc, const char* arg), kCommon) \
    X(LocToUtf8, const char*, (void* loc), kCommon) \
    X(GetPlayer, void*, (int playerId), kGameCore) \
    /* 字符串哈希：不再解析 GameCore 符号，改为 Loader 内部实现的原生 CRC32（raw， \
       无最终异或，与官方 GameCore::Utilities::MakeHash 逐位一致）。对局前/重载后都能算。 */ \
    X(MakeHash, uint32_t, (const char* str), kCommon) \
    /* 注册插件自己的 PushMethods 目标配置。pushMethodsSymbol 为空时使用 name + "::PushMethods"； \
       非空时该完整符号名用于解析本次安装的目标。 \
       配置按调用插件 owner 隔离，不能覆盖 Loader 内置目标或其他插件配置；同 owner 重复配置 \
       必须完全一致。name 指针必须来自调用插件模块。 */ \
    X(RegisterPushMethodsTarget, int, (const char* name, int sigType, const char* pushMethodsSymbol), kGameCore) \
    /* 原始字节补丁（单层存档，见 patch registry）。两个槽在 Loader 的静态 HookAPI 表 \
       （g_hookApi，编译期常量初始化）里一次性填好，运行期不再改表。 */ \
    X(Patch, bool, (void* target, const void* bytes, size_t len), kCommon) \
    X(Unpatch, bool, (void* target), kCommon) \
    /* GameEvents：纯登记 + 插件端手动触发。name 为 GameEvent 名（如 "MyCustomEvent"）， \
       最长 95 个字节（不含结尾 NUL）；超长名称直接返回 false，不会截断或占用槽位。 \
       RegisterGameEvent：登记 Lua 侧构造参数事件（任意类型/个数，字符串键表/嵌套/数组）。 \
       pushFn 往 Lua 栈压参数并返回个数（0 = 无参调用），runtime 负责活跃 state 获取、 \
       锁协议、GameEvents[name].Call、栈清理（见 C++ 区 GameEventPushFn 说明）。 \
       返回 false = 注册失败（未就绪/无空槽/无 owner 等）。同名重复注册幂等返回 true。 */ \
    X(RegisterGameEvent, bool, (const char* name, GameEventPushFn pushFn), kGameCore) \
    /* TriggerGameEvent：手动触发一次（必须先注册——回查注册记录拿 pushFn，未注册返回 false）， \
       payload 传给注册时的 pushFn（payload 同步解析，仅在本调用期间有效；pushFn 为 null = 无参调用）。 \
       插件回调与 Lua 调用的 SEH/C++ 异常由 Loader 截获并返回 false。 \
       GameCore 锁状态无法判定时（EngineUtility 解析失败或取/放锁调用异常）拒绝执行并返回 false： \
       宁可漏触发，也不在持锁状态下重入 Lua（可能自死锁或破坏 Lua 状态）。 \
       必须在游戏线程调用——Lua 状态非线程安全。 */ \
    X(TriggerGameEvent, bool, (const char* name, const void* payload), kGameCore) \
    /* 引擎的**主 Lua VM**（exe 全局 LuaSystem::LuaScriptSystem 单例的 +0x10，RVA 0x2D08F88）。 \
       这是**进程级** state：由 lua_newstate() 在 Civ6App::GUIInit 时创建一次，只在 \
       Civ6App::GUIShutdown 时 lua_close —— **换局不会让它失效，也不会被重写** \
       （全 exe 只有一处写 +0x10，就是 Setup 里 lua_newstate 之后那一次）。 \
        \
       名字来源于引擎自己：结构体成员就叫 m_pkMainLuaState，Tuner 注册时给的字符串名是 \
       "Main State"。官方 GameCore::ScriptSystem::CallHook 也是读它： \
       mov rax, cs:ms_apSingletonInstance ; mov rcx, [rax+10h] ; jmp GameEventLibrary::CallHook \
       本接口按同款方式每次实时读单例槽再取 +0x10（槽会在 GUIShutdown 时被清零并 lua_close， \
       所以绝不能缓存返回的指针）。 \
        \
       【别和"每局 thread state"混淆】Civ6 确实是多 lua_State 引擎，但那些是 \
       lua_newthread(main_state) 派生出来的 coroutine：GameCore 每局用 \
       IScriptSystem1::CreateLuaThread 建、结束时 FreeLuaThread 回收，**换局必失效**。 \
       本接口返回的不是它们。若插件持有的是某个 thread state，那才是会崩的场景。 \
        \
       **Global 与 GameCore 两类插件都可调用，不限类别。** 这个 state 是进程级的，常驻插件 \
       持有它不会因换局而悬垂（这正是它与 §地址域门 所防的"GameCore 短命域地址"的根本区别）。 \
       之所以早先一度给它加类别门，是因为把"GameCore.dll 用 Lua::ms_CriticalSection、 \
       exe 用 Lua::Details::LockAccess，是两个不同临界区实例"误当成了类别问题——那其实是 \
       **线程**问题：约束是"仅游戏线程调用"，与插件类别无关，类别门拦不住跨线程调用。 \
        \
       仅游戏线程调用（Lua 状态非线程安全）。未就绪（GUIShutdown 之后 / 尚未 GUIInit） \
       返回 nullptr。 */ \
    X(GetMainLuaState, void*, (void), kCommon) \
    /* Lua nil 入栈（hks ?hksi_lua_pushnil 导出）。参数打包回调里构造 nil 参数用。 */ \
    X(LuaPushNil, void, (void* L), kCommon) \
    /* ---- 符号库状态查询 ---- \
       内置符号库（sidecar）与指定映像的匹配状态，见 HookApiSymbolDbState 各值说明。 \
       返回 kHookApiDbNoContext = 该映像根本没有符号数据；kHookApiDbBuildFailed = 有数据但 \
       本次会话建表失败。两者都意味着该映像上的 ResolveByRva/ResolveByName 会返回 nullptr。 \
       纯查询，不加锁竞争、不改任何状态，可在任意线程调用。 */ \
    X(GetSymbolDbState, HookApiSymbolDbState, (HookImageId image), kCommon) \
    /* 跨版本对齐的匹配率（已匹配的 .pdata 条目数 / 总条目数），取值 [0.0, 1.0]。 \
       仅 kHookApiDbCrossVersion 状态下是"部分匹配"的度量；此时 1.0 表示全部对齐。 \
       非跨版本状态返回：Identical -> 1.0（恒等映射，无失配），其它 -> 0.0（无数据/不可用）。 \
       用于诊断与降级决策；单点能否解析仍以 ResolveByRva/ResolveByName 的返回值为准。 */ \
    X(GetSymbolDbMatchRatio, double, (HookImageId image), kCommon)

// ---------------- 插件类别声明（编译期强制） ----------------
// 成员生成依赖类别，所以这个检查必须出现在结构体【之前】。
#if !defined(CIV6_PLUGIN_GLOBAL) && !defined(CIV6_PLUGIN_GAMECORE) && !defined(CIV6_HOOKAPI_BUILD_IMPL)
#error "CIV6: 必须声明插件类别：在工程预处理宏里定义 CIV6_PLUGIN_GLOBAL 或 CIV6_PLUGIN_GAMECORE"
#endif

// ---------------- 类别门禁（编译期） ----------------
// Global 下 GameCore 专属成员【不生成】，于是 api->GetPlayer(...) 直接报
// C2039"不是 HookAPI 的成员"。与旧实现不同：旧实现靠文件末尾的 #define 重命名成员名
// （在使用点生效），新实现必须在结构体之前定值——成员集本身就依赖类别。
//
// 两个宏的参数名与清单列一一对应：
//   entryName   入口名（如 InstallHook）
//   returnType  返回类型
//   params      参数表，含外层括号（如 (int playerId)）
#define CIV6_HOOKAPI_MEMBER_kCommon(entryName, returnType, params) returnType (*entryName) params;
#if defined(CIV6_PLUGIN_GAMECORE) || defined(CIV6_HOOKAPI_BUILD_IMPL)
#define CIV6_HOOKAPI_MEMBER_kGameCore(entryName, returnType, params) returnType (*entryName) params;
#else
#define CIV6_HOOKAPI_MEMBER_kGameCore(entryName, returnType, params)
#endif

// ---------------- 插件侧表 ----------------
// 布局由本头文件决定，与 loader 内部怎么排无关。两类插件 sizeof 不同（GameCore 多 7 项），
// 没有问题：该结构体从不跨越模块边界，每个插件只用自己那一份。
// 头部两个标量保留，使 loader 的 g_hookApi 位置初始化可以原样复用。
typedef struct HookAPI {
    uint32_t apiVersion;
    uint32_t structSize;
#define X(entryName, returnType, params, category) \
    CIV6_HOOKAPI_MEMBER_##category(entryName, returnType, params)
    HOOK_API_LIST(X)
#undef X
} HookAPI;

// 本 runtime 能否服务用当前头文件编译出来的插件。OnLoad 开头调一次，返回 0 就中止。
// 这是跨两侧的有效比较：ctx 由 loader 填，structSize / apiVersion 是插件编译进去的值。
// structSize 在偏移 0，因此"两边不是同一次构建"时它读到的是对方的 apiVersion(=1) 或
// 别的值，必然小于 sizeof(HookContext)，当场拒绝——不会把函数指针当 Query 用。
// 插件类别不在这里判——它走上面的 Civ6PluginKind 导出，loader 在 OnLoad 之前就核对过。
static inline int HookContext_IsCompatible(const HookContext* ctx) {
    if (!ctx) return 0;
    if (ctx->structSize < sizeof(HookContext)) return 0;
    if (ctx->apiVersion != CIV6_HOOK_API_VERSION) return 0;
    return 1;
}

#ifdef __cplusplus
}  // extern "C"

// HookAPI 里"入口"（函数指针）字段的数量。由清单推导，不再手工维护；
// 它的作用只剩一个：loader 的 static_assert 用它校验 g_hookApi 的位置初始化补齐了
// （聚合初始化少写几项只会静默零填，运行时就是空指针调用）。

// ---------------- 以下为 C++ 专属（模板 / lambda），必须在 extern "C" 之外 ----------------

// 入口数：从同一份清单推导，不再手工同步。
inline constexpr uint32_t CIV6_HOOK_API_ENTRY_COUNT =
#define X(entryName, returnType, params, category) +1u
    HOOK_API_LIST(X)
#undef X
    ;

// 解析入口：把 ctx 里的 77 个名字逐个查回来，填满本模块私有的表，返回它。
// 查不到的名字置 nullptr（绝不会是野指针），插件用 HookAPI_RequireAll 声明真正依赖的项。
//
// 【不提供全局 api 指针】本可以在这里放一个 `inline HookAPI* api` 让插件连声明都省掉，
// 但那会与插件里普遍使用的形参名 `api`（`void Foo(HookAPI* api)`）冲突，产生一片 C4459。
// 表指针由插件自己声明 —— 与改造前 `static HookAPI* g_api = nullptr;` 的做法一致。
//
// 【为什么是立即执行 lambda】只有 static 的"初始化"受 C++ Magic Static 保护。
// 若写成 `static HookAPI t{};` 再逐行赋值，那 77 行是普通语句，每次调用都会重跑。
// 放进初始化表达式里，整块受一次性守卫保护，首次之后退化为 lea/ret。
#pragma warning(push)
#pragma warning(disable : 4996)   // 解析器给已废弃成员赋值会自触发 C4996
inline HookAPI* HookAPI_Resolve(const HookContext* ctx) {
    static HookAPI table = [ctx]() {
        HookAPI t{};
        t.apiVersion = CIV6_HOOK_API_VERSION;
        t.structSize = static_cast<uint32_t>(sizeof(HookAPI));
        // 查到的入口按名字填进去；返回类型由 decltype(t.<入口名>) 推出，不需要清单里的 returnType。
#define CIV6_HOOKAPI_RESOLVE_kCommon(entryName, returnType, params) \
        t.entryName = reinterpret_cast<decltype(t.entryName)>(ctx->Query(#entryName));
// Global 下这些成员根本不存在，解析也必须跳过，否则 t.GetPlayer = ... 编译不过。
#if defined(CIV6_PLUGIN_GAMECORE) || defined(CIV6_HOOKAPI_BUILD_IMPL)
#define CIV6_HOOKAPI_RESOLVE_kGameCore(entryName, returnType, params) \
        t.entryName = reinterpret_cast<decltype(t.entryName)>(ctx->Query(#entryName));
#else
#define CIV6_HOOKAPI_RESOLVE_kGameCore(entryName, returnType, params)
#endif
#define X(entryName, returnType, params, category) \
        CIV6_HOOKAPI_RESOLVE_##category(entryName, returnType, params)
        HOOK_API_LIST(X)
#undef X
#undef CIV6_HOOKAPI_RESOLVE_kGameCore
#undef CIV6_HOOKAPI_RESOLVE_kCommon
        return t;
    }();
    return &table;
}
#pragma warning(pop)

// 依赖声明：只列自己真正用到的入口，缺一个就返回 false（配合 OnLoad 里优雅退出）。
// 用成员指针而不是字符串，因此名字拼错是编译错误、IDE 能补全、重命名能跟随。
//   if (!HookAPI_RequireAll(api, &HookAPI::ResolveByName, &HookAPI::InstallHook)) return;
template <typename... M>
inline bool HookAPI_RequireAll(const HookAPI* apiTable, M... members) {
    return apiTable != nullptr && ((apiTable->*members != nullptr) && ...);
}


template <typename T>
T ResolveByName(HookAPI* apiTable, HookImageId image, const char* name) {
    return reinterpret_cast<T>(apiTable->ResolveByName(image, name));
}

template <typename T>
void InstallHook(HookAPI* apiTable, LPVOID pTarget, LPVOID pDetour, T** ppOriginal) {
    apiTable->InstallHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
T ResolveByRva(HookAPI* apiTable, HookImageId image, uintptr_t rva, size_t span = 1) {
    return reinterpret_cast<T>(apiTable->ResolveByRva(image, rva, span));
}

template <typename T>
T ResolveByRvaEx(HookAPI* apiTable, HookImageId image, uintptr_t rva, HookImageSection section = kSectionImage, size_t span = 1) {
    return reinterpret_cast<T>(apiTable->ResolveByRvaEx(image, rva, span, section));
}

template <typename T>
T ResolveByPattern(HookAPI* apiTable, HookImageId image, const char* pattern,
    HookImageSection section = kSectionImage, uint32_t index = 1) {
    return reinterpret_cast<T>(apiTable->ResolveByPattern(image, pattern, section, index));
}

template <typename T>
T ResolveByVTable(HookAPI* apiTable, HookImageId image, const char* vtableSymbol, uint32_t index) {
    return reinterpret_cast<T>(apiTable->ResolveByVTable(image, vtableSymbol, index));
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
static inline void* ResolveByHookInfo(HookAPI* apiTable, HookImageId image, const HookInfo& info,
    size_t span = 1) {
    if (!apiTable) return nullptr;
    void* result = nullptr;
    switch (info.kind) {
        case kHookInfoRva:
            if (info.u.rva != 0) result = apiTable->ResolveByRva(image, info.u.rva, span);
            break;
        case kHookInfoVTable:
            if (info.u.vtable.vtableName && *info.u.vtable.vtableName)
                result = apiTable->ResolveByVTable(image, info.u.vtable.vtableName, info.u.vtable.slotIndex);
            break;
        case kHookInfoName:
            if (info.u.name && *info.u.name) result = apiTable->ResolveByName(image, info.u.name);
            break;
        default:
            break;
    }
    if (!result && info.aob && *info.aob)
        result = apiTable->ResolveByPattern(image, info.aob, kSectionText, info.index);
    return result;
}

// 当前进程 exe 的镜像 id（Dx11 / Dx12；未识别 = kHookImageInvalid）。内部细节，不写进文档。
static inline HookImageId HookCurrentExeImage(HookAPI* apiTable) {
    if (!apiTable) return kHookImageInvalid;
    HookImageInfo info{};
    info.structSize = sizeof(HookImageInfo);
    if (apiTable->GetImageInfo(kHookImageExeDx11, &info)) return kHookImageExeDx11;
    info = HookImageInfo{};
    info.structSize = sizeof(HookImageInfo);
    if (apiTable->GetImageInfo(kHookImageExeDx12, &info)) return kHookImageExeDx12;
    return kHookImageInvalid;
}

static inline void* ResolveByHookInfoExe(HookAPI* apiTable, const HookInfoExe& info, size_t span = 1) {
    const HookImageId image = HookCurrentExeImage(apiTable);
    if (image == kHookImageInvalid) return nullptr;
    return ResolveByHookInfo(apiTable, image,
        image == kHookImageExeDx12 ? info.dx12 : info.dx11, span);
}

static inline bool HookAobIsHex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// AOB 相对寻址定位（不限映像；内部扫 .text）：
//   AOB 用 | 切分指令段；含 xx xx xx xx 的段 = 目标指令；段内恰好一组 xx（= disp32）。
//   命中 H、目标段起止字节偏移 S/E（| 不计入）、xx 组偏移 D  ->  目标 = H + E + i32[H + D]。
//   运行期 | 去掉、xx 换成 ??，交给 ResolveByPattern；命中不唯一/格式非法/目标越界 -> nullptr。
static inline void* ResolveDataByAob(HookAPI* apiTable, HookImageId image, const char* aob,
    uint32_t index = 1) {
    if (!apiTable || image == kHookImageInvalid || !aob || !*aob) return nullptr;
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

    void* hit = apiTable->ResolveByPattern(image, flat, kSectionText, index);
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
    if (!apiTable->GetImageInfo(image, &info) || !info.base || !info.imageSize) return nullptr;
    if (target < info.base || target - info.base >= info.imageSize) return nullptr;
    return reinterpret_cast<void*>(target);
}

#endif

// Recommended plugin exports (not required beyond OnLoad).
// extern "C" __declspec(dllexport) void OnLoad(HookContext* ctx);
// extern "C" __declspec(dllexport) void OnUnload();
// extern "C" __declspec(dllexport) void OnMessage(const char* topic, const void* data, size_t len);
//
// ABI guard (do this first thing in OnLoad):
//   if (!HookContext_IsCompatible(ctx)) return;
//   api = HookAPI_Resolve(ctx);
//   if (!HookAPI_RequireAll(api, &HookAPI::Log, &HookAPI::InstallHook)) return;
// This is how a plugin built from a newer header detects an older runtime instead of
// reading past the end of the table. The table itself is read-only - writing to it faults.

