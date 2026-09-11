#pragma once

#include <Windows.h>
#include <stdint.h>
#include <stddef.h>

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

// ---- GameEvent 参数容器（IScriptSystemArgs1）vtable 包装 ----
// 槽位布局 = 引擎 ms_pkScriptSystemArgs_vtbl（18 槽，exe IDA @0x140FC0588 逐槽反编译验证）。
// 本类是"指针直通"包装：ScriptSystemArgs* 直接就是引擎 args 对象指针（单指针
// 布局，static_assert 锁死），成员函数按槽位调用其 vtable。
// 用法：在引擎 args 对象指针上调用 Push*/Get* 成员填充/读取参数：
//
//   void MyPush(ScriptSystemArgs* args) {
//       args->PushInt(42);
//       args->PushString("hello", 5);
//   }
//
// 生命周期：args 仅在所属回调执行期间存活，不要在回调外缓存。回调整体在
// runtime 的 SEH 保护内执行。
class ScriptSystemArgs {
public:
    // ---- Push：追加参数（返回新参数的索引）----
    // 以下 5 槽调用约定经 exe IDA 反编译逐槽验证（Push_int(this, uint)、
    // Push_String(this, const void*, size_t) 等），也是引擎官方桥接 lambda
    // （CityBuilt 等）使用的全部参数形态。
    uint64_t PushFloat(float value)     { return call<uint64_t, 4>(value); }
    uint64_t PushInt(int value)         { return call<uint64_t, 5>(value); }
    uint64_t PushString(const char* s, uint64_t len) { return call<uint64_t, 6>(s, len); }
    uint64_t PushBool(bool value)       { return call<uint64_t, 7>(value); }
    uint64_t PushNull()                 { return call<uint64_t, 8>(); }
    // ---- Push：table 参数（引擎 Data::TypedVariantMap，官方 Events.Combat 同机制）----
    // 表对象经 GameEventTable 构造填充（见下）；引擎解包时该参数成为 Lua table。
    // PushTable 调 args vtable 槽2（Push_ContainerRvalue）——引擎按右值/移动语义接管
    // 表所有权（与 SetVariant 槽21 按值拷贝条目一致）；PushTable 后表析构变 no-op，
    // 禁止继续使用该表（尤其禁止再 SetXxx / 再次 PushTable）。
    // 约束：表对象须存活到 PushTable 调用结束（回调内栈对象天然满足）。
    uint64_t PushTable(const class GameEventTable& table);
    // 刻意不暴露的槽位（同样经反编译确认，见 docs）：
    //  - 槽[3] Push_UserData：把裸 8 字节指针塞进 Lua（userdata）——Lua 侧可长期持有，
    //    C++ 对象生存期无法约束，悬空即崩，不开放。
    //  - 槽[1] Push_Container(ConstRef)：借用语义，不开放。槽[2] Push_Container(Rvalue)
    //    由 PushTable 使用：参数是引擎 Data::TypedVariantMap 真对象指针（经 GameEventTable
    //    构造装真 vtable，非插件伪造的接口对象）。Lua 侧需要结构化数据时用 PushTable
    //    或 JSON 字符串自行约定。

    // ---- Get：按索引查询已 Push 的参数（索引从 0 起）----
    // 真实签名（exe IDA 反编译逐槽验证）：(this, index, T* out) → bool（成功标志），
    // 值写入 out；索引越界或类型不匹配返回 false 且不写 out。
    // GetType 返回引擎类型码（0=无效 1=bool 2=int 3=float? 4=int 5=string 6=user 7=table，
    // 精确含义见引擎 VariantType 枚举），Count 返回已 Push 参数个数。
    uint64_t    Count() const                        { return call<uint64_t, 9>(); }
    int         GetType(uint32_t index) const        { return call<int, 10>(index); }
    bool        GetBool(uint32_t index, bool* out) const          { return call<bool, 11>(index, out); }
    bool        GetInt(uint32_t index, int32_t* out) const        { return call<bool, 12>(index, out); }
    bool        GetFloat(uint32_t index, float* out) const        { return call<bool, 13>(index, out); }
    bool        GetString(uint32_t index, const char** out) const { return call<bool, 14>(index, out); }
    void*       GetParent() const                                { return call<void*, 17>(); }
    // 槽[15] GetTable / [16] GetUser 不暴露：容器与 userdata 是刻意不开放的
    // 参数形态（见 Push 段注释），对应的读回通道一并收口。

    // 裸指针（本类即指针直通包装，raw() 仅在需要喂给 void* 形参的引擎 API 时用）。
    void* raw() const { return reinterpret_cast<void*>(const_cast<ScriptSystemArgs*>(this)); }

private:
    // 槽 [0] 为析构相关（不暴露：args 生命周期由 runtime 的 DestroyArgs 管理）。
    template <typename Ret, size_t Slot, typename... A>
    Ret call(A... args) const {
        using Fn = Ret(__fastcall*)(const ScriptSystemArgs*, A...);
        const void* const* vt = *reinterpret_cast<const void* const* const*>(this);
        return reinterpret_cast<Fn>(vt[Slot])(this, args...);
    }
};
// 指针直通说明：本类无数据成员，ScriptSystemArgs* 的值即引擎 IScriptSystemArgs1
// 对象指针（call() 以 this 调用其 vtable 槽位）。sizeof 无意义（空类恒为 1），
// 禁止按值传递或存储本类——只用指针。

// ---- GameEvent table 参数（Data::TypedVariantMap 包装）----
// 引擎官方 Events.Combat 的 combatResult 同机制：88 字节堆对象 + 引擎真 vtable。
// 构造/析构经 HookAPI 新增的 AllocTypedVariantMap/FreeTypedVariantMap；键哈希用
// api->MakeHash("字段名")；SetXxx 全部虚槽直调（零额外 API 表面积）。
// 用法（Lua 路径内）：
//   GameEventTable t(api);                    // api = OnLoad 收到的 HookAPI*
//   t.SetInt   (api->MakeHash("playerId"), 42);
//   t.SetString(api->MakeHash("name"), "Caesar");
//   GameEventTable child(api);
//   child.SetUInt(api->MakeHash("hp"), 100);
//   t.SetChild (api->MakeHash("units"), child);   // 嵌套子表
//   args->PushTable(t);                        // 所有权移交引擎（t 析构变 no-op）
typedef struct HookAPI HookAPI;  // 前向声明（完整定义见下方 C 区）
class GameEventTable {
public:
    explicit GameEventTable(const HookAPI* api);   // AllocTypedVariantMap：分配 88 字节并调引擎构造
    ~GameEventTable();                             // 未 Push 过才 FreeTypedVariantMap；已 Push 则 no-op
    GameEventTable(const GameEventTable&) = delete;
    GameEventTable& operator=(const GameEventTable&) = delete;
    GameEventTable(GameEventTable&& other) noexcept;       // 移动：转移 m_map/m_pushed/m_api，源置空
    GameEventTable& operator=(GameEventTable&& other) noexcept;

    bool   valid() const { return m_map != nullptr; }
    void*  raw() const { return m_map; }
    // 键 = api->MakeHash("字段名")。全部经引擎 vtable 虚槽（构造时装的真表）。
    void SetInt   (uint32_t key, int32_t value);
    void SetUInt  (uint32_t key, uint32_t value);
    void SetFloat (uint32_t key, float value);
    void SetBool  (uint32_t key, bool value);
    void SetString(uint32_t key, const char* value);          // 空指针/空串 → 不写键（Lua 侧为 nil）
    void SetChild (uint32_t key, const GameEventTable& child); // child 保持独立（引擎按值拷贝条目）
    void Remove   (uint32_t key);

    // 内部：PushTable 调用后置位（引擎接管生存期，析构变 no-op）
    void markPushed() { m_pushed = true; }
private:
    // 引擎 vtable 虚槽直调（模式同 ScriptSystemArgs::call，this 为 m_map）
    template <typename Ret, size_t Slot, typename... A>
    Ret vtCall(A... args) const {
        using Fn = Ret(__fastcall*)(void*, A...);
        const void* const* vt = *reinterpret_cast<const void* const* const*>(m_map);
        return reinterpret_cast<Fn>(vt[Slot])(m_map, args...);
    }
    void* m_map = nullptr;
    mutable bool m_pushed = false;   // mutable：PushTable 以 const 引用置位（免 friend）
    const HookAPI* m_api = nullptr;  // 仅析构/移动需要（Set 全走虚槽）
};

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

    unsigned int (*GetCurTurn)(void);

    void* (*LocalizationLookup)(void* outLocString, const char* key);

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
    //   必须在游戏线程调用——Lua 状态非线程安全。
    bool (*TriggerGameEvent)(const char* name, const void* payload);

    // GameEvent table 参数支持（Data::TypedVariantMap 生命周期管理；SetXxx 在头文件类内联）。
    // Alloc：分配 88 字节并调引擎构造（返回引擎对象指针；失败 nullptr——GameCore 未就绪等）。
    // Free：调引擎 scalar deleting destructor 并释放（传 engineObj 指针；仅对未 Push 的表调用，
    //        PushTable 后所有权归引擎，禁止 Free）。
    void* (*AllocTypedVariantMap)(void);
    void  (*FreeTypedVariantMap)(void* engineObj);

    // 官方 ScriptSystem::PushDataVariantMap 直调（vtable 槽21，0x140FC06C0）：
    // 把 GameEventTable（TypedVariantKeyedContainer）压到 lua_State 栈顶，官方 ToLua 转换
    // （嵌套子表完整；键走 VariantManager::FindKey 反查——官方字段名→字符串键、
    // 未注册的自定义名→CRC32 数字键，见 exe sub_140DB5590）。
    // useKeyLookup=false 恒数字键。仅游戏线程、L 有效、tableObj 为未 Push 的
    // GameEventTable::raw() 时调用；GameCore 未就绪时无操作返回。
    void (*PushDataVariantMap)(void* L, const void* tableObj, bool useKeyLookup);

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

// ---- GameEventTable 实现 / ScriptSystemArgs::PushTable（此处 HookAPI 已完整定义）----

// vtable 槽位（rva_map vtable_xrefs 双向验证：槽号×8 = vtable 偏移）：
//   槽21 (+0xA8) SetVariant(uint, TypedVariantMap*)   嵌套子表
//   槽33 (+0x108) SetVariant(uint, const char*)       字符串
//   槽36 (+0x120) SetVariant(uint, float)
//   槽37 (+0x128) SetVariant(uint, uint)
//   槽38 (+0x130) SetVariant(uint, int)
//   槽39 (+0x138) SetVariant(uint, bool)
//   槽40 (+0x140) RemoveVariant(uint)
enum GameEventTableVtSlot : uint32_t {
    kGameEventTableVtSetChild  = 21,
    kGameEventTableVtSetString = 33,
    kGameEventTableVtSetFloat  = 36,
    kGameEventTableVtSetUInt   = 37,
    kGameEventTableVtSetInt    = 38,
    kGameEventTableVtSetBool   = 39,
    kGameEventTableVtRemove    = 40
};

inline GameEventTable::GameEventTable(const HookAPI* api)
    : m_map(api ? api->AllocTypedVariantMap() : nullptr), m_api(api) {}

inline GameEventTable::~GameEventTable() {
    // 已 Push（所有权移交引擎）或从未分配：no-op。未 Push：FreeTypedVariantMap 析构+释放。
    if (m_map && !m_pushed && m_api) {
        m_api->FreeTypedVariantMap(m_map);
    }
    m_map = nullptr;
}

inline GameEventTable::GameEventTable(GameEventTable&& other) noexcept
    : m_map(other.m_map), m_pushed(other.m_pushed), m_api(other.m_api) {
    other.m_map = nullptr;
    other.m_pushed = false;
    other.m_api = nullptr;
}

inline GameEventTable& GameEventTable::operator=(GameEventTable&& other) noexcept {
    if (this != &other) {
        if (m_map && !m_pushed && m_api) m_api->FreeTypedVariantMap(m_map);
        m_map = other.m_map;
        m_pushed = other.m_pushed;
        m_api = other.m_api;
        other.m_map = nullptr;
        other.m_pushed = false;
        other.m_api = nullptr;
    }
    return *this;
}

inline void GameEventTable::SetInt(uint32_t key, int32_t value) {
    if (m_map) vtCall<void*, kGameEventTableVtSetInt>(key, value);
}

inline void GameEventTable::SetUInt(uint32_t key, uint32_t value) {
    if (m_map) vtCall<void*, kGameEventTableVtSetUInt>(key, value);
}

inline void GameEventTable::SetFloat(uint32_t key, float value) {
    if (m_map) vtCall<void*, kGameEventTableVtSetFloat>(key, value);
}

inline void GameEventTable::SetBool(uint32_t key, bool value) {
    if (m_map) vtCall<void*, kGameEventTableVtSetBool>(key, value);
}

inline void GameEventTable::SetString(uint32_t key, const char* value) {
    if (!m_map) return;
    // 空指针/空串：不写键（Lua 侧读 nil），避免制造空串条目
    if (!value || !*value) return;
    vtCall<void*, kGameEventTableVtSetString>(key, value);
}

inline void GameEventTable::SetChild(uint32_t key, const GameEventTable& child) {
    if (!m_map || !child.valid()) return;
    vtCall<void*, kGameEventTableVtSetChild>(key, child.raw());
}

inline void GameEventTable::Remove(uint32_t key) {
    if (m_map) vtCall<void*, kGameEventTableVtRemove>(key);
}

inline uint64_t ScriptSystemArgs::PushTable(const GameEventTable& table) {
    if (!table.valid()) return 0;
    // args vtable 槽2 = Push_ContainerRvalue：引擎按右值/移动语义接管表对象
    //（与 SetVariant 槽21 按值拷贝条目一致；官方 Combat 链路同机制）。槽2 之后表
    // 所有权视为已移交：markPushed 使析构 no-op（若引擎实际为借用语义，表由引擎
    // 生命周期管理，同样安全——两种情况都要求 PushTable 后不再使用该表）。
    using Fn = uint64_t(__fastcall*)(const ScriptSystemArgs*, void*);
    const void* const* vt = *reinterpret_cast<const void* const* const*>(this);
    const uint64_t idx = reinterpret_cast<Fn>(vt[2])(this, table.raw());
    const_cast<GameEventTable&>(table).markPushed();
    return idx;
}
#endif

// Recommended plugin exports (not required beyond OnLoad).
// extern "C" __declspec(dllexport) void OnLoad(HookAPI* api);
// extern "C" __declspec(dllexport) void OnUnload();
// extern "C" __declspec(dllexport) void OnMessage(const char* topic, const void* data, size_t len);
