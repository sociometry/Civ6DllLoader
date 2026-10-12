#pragma once
// ScriptBridge.h — Lua / GameEvent / 脚本注册 / PushMethods 槽位（阶段 4）。
//
// 本模块是拆分里最大的一块（99 函数）。对外的接口分两类：
//   1. 插件 ABI 入口（*Impl 与 Lua/Loc 包装）—— 母体的 g_hookApi 表取它们的地址。
//      阶段 6 把 g_hookApi 迁到 HookLoaderApi.cpp 后，改由那个文件取地址。
//   2. 给 PluginRegistry / HookEngine 用的门面 —— 它们要复位本模块拥有的状态。
//
// 归属本模块的私有状态（不导出，见 REFACTOR_PLAN.md §5.1）：
//   g_defaultPushTargetConfigs / kLuaSingletonPattern / g_mainLuaStateHit
//   kGameEventNameMax / kGameEventCurrentGamePattern / g_gameEventContainerHit
//   kMaxRegisteredGameEvents / g_gameEvents
//   NoManagerDetourTable / WithManagerDetourTable / SharedDetourActivity
//   g_activeSharedDetours / g_detourDrainMutex / g_detourDrainCv
//
// 需要门面的跨模块状态（§5.2）：脚本全局表、PushMethods 槽位、detour 排空计数、
// g_gameCorePhaseReady。门面定义见下。

#include <cstddef>
#include <cstdint>
#include <string>

#include "../common/HookAPI.h"

namespace ScriptBridge {

// ================= 门面（给 PluginRegistry / HookEngine） =================

// 插件注册项的 owner 级摘除（PluginRegistry 的 RemovePluginOwnedRegistrations 用）。
// 原实现直接操作本模块 7 个变量；收进这一个函数后它们都不必外泄。
//
// 返回四个计数而不是一个总数：调用方的日志格式
//   "RemovePluginOwnedRegistrations: owner=%ls globals=%zu globalsUI=%zu
//    luaMethods=%zu targetConfigs=%zu"
// 在基线日志里出现过，拆分后要逐条比对，字段不能合并或改序。
struct RemovedCounts {
    size_t globals = 0;        // 脚本全局表（RegisterScriptData）
    size_t globalsUI = 0;      // 脚本全局表（ForUI）
    size_t luaMethods = 0;     // PushMethods 槽位里该 owner 的方法数
    size_t targetConfigs = 0;  // 该 owner 的 PushMethods 目标配置条数
};
RemovedCounts RemovePluginRegistrations(const std::wstring& owner);

// teardown 整体复位（HookEngine 的 RemoveGameCoreDomainSiteRecords 用）。
// 它一共碰 6 个本模块拥有的对象（g_orig* ×2、g_pushStateMutex、kMaxPushHooks、
// 两个槽位数组），全部收进这一个函数。
//
// 为什么不能复用 RemovePluginRegistrations：那个是"按 owner 摘"，teardown 要的是
// "清空全部"，且此刻无法枚举 owner。
void ResetForTeardown();

// 摘掉某 owner 登记的 Lua 事件（name / luaPushFn / ownerId）。PluginRegistry 用。
void CleanupGameEventsForOwner(const std::wstring& owner);

// 阶段 B（GameCore 就绪）时把 RegisterScriptData / ForUI 两个共享钩装到新映像上。
// PluginRegistry 的 InitializeGameCorePhase 用。
void EnsureScriptHooksInstalled();

// 等待所有在途的共享 detour 回调退出。HookEngine 在拆除站点前必须等它们退出，
// 否则会拆掉正在执行的跳板。计数与等待原语都归本模块私有。
void WaitForDetourDrain();

// 阶段 B 就绪标志。原来是个裸 bool（g_gameCorePhaseReady），读写两侧都持 lifecycle 锁；
// 现改为原子读写：读侧无锁（调用点本来就持锁，少一次重入），写侧语义不变。
//
// 实现放在 ScriptBridge.cpp（本模块的 EnsureScriptHooksInstalled 是主要读者）；
// 写方在 PluginRegistry 的 InitializeGameCorePhase / ResetForReload。
bool IsGameCorePhaseReady();
void SetGameCorePhaseReady(bool ready);

// ================= 插件 ABI 入口 =================
// 这些是 HookAPI 表里的函数指针目标。母体的 g_hookApi 初始化表取它们地址，
// 故不能是 static。签名与实现逐字一致（从源码自动提取，未手工改写）。

void* EditPlayerImpl(int playerId);
void* GetEngineUtilityImpl();
void* GetMainLuaStateImpl();
void* LocCreateImpl(void);
void LocDestroyImpl(void* loc);
void* LocLookupImpl(void* loc, const char* key);
int LocPushArgumentImpl(void* loc, const char* arg);
uint32_t LocStringBytesImpl(void);
const char* LocToUtf8Impl(void* loc);
void* LocalizationLookupImpl(void* outStr, const char* key);
void LogImpl(const char* format, ...);
int LuaCPcallImpl(void* L, LuaMethodFunc callback, void* userdata);
int LuaCheckIntegerImpl(void* L, int index);
char const* LuaCheckLStringImpl(void* L, int index, unsigned __int64* a);
double LuaCheckNumberImpl(void* L, int index);
int LuaCheckPlayerIdImpl(void* L, int index);
void LuaCheckTableImpl(void* L, int index);
void LuaCreateTableImpl(void* L, int a, int b);
int LuaDoStringImpl(void* L, const char* str);
void LuaErrorImpl(void* L, char const* str, ...);
void LuaGetFieldImpl(void* L, int a, char const* b);
int LuaGetHookCountImpl(void* L);
void* LuaGetHookImpl(void* L);
int LuaGetHookMaskImpl(void* L);
void LuaGetTableImpl(void* L, int index);
int LuaGetTopImpl(void* L);
int LuaIsNumberImpl(void* L, int num);
int LuaIsUserDataImpl(void* L, int num);
void LuaNewGlobalTableImpl(void* L, const char* globalName, int narr, int nrec);
unsigned long long LuaObjLenImpl(void* L, int index);
int LuaOpenDebugImpl(void* L);
int LuaOptIntegerImpl(void* L, int a, int b);
int LuaPcallImpl(void* L, int a, int b, int c);
void LuaPopImpl(void* L, int a);
void LuaPushBooleanImpl(void* L, bool value);
void LuaPushCFunctionFieldImpl(void* L, int tableIndex, const char* fieldName, void* fn, const char* internalName);
char const* LuaPushFStringImpl(void* L, char const* str, ...);
void LuaPushIntegerImpl(void* L, int num);
void LuaPushLightUserDataImpl(void* L, void* ptr);
void LuaPushNamedCClosureImpl(void* L, void* func, int a, const char* name, int b);
void LuaPushNilImpl(void* L);
void LuaPushNumberImpl(void* L, double num);
void LuaPushValueImpl(void* L, int value);
void LuaRawGetIImpl(void* L, int a, int b);
int LuaRefImpl(void* L, int index);
void LuaSetFieldImpl(void* L, int stackOffset, const char* name);
int LuaSetHookImpl(void* L, void* a, int b, int c);
void LuaSetTableImpl(void* L, int t);
int LuaToBooleanImpl(void* L, int index);
void* LuaToCFunctionImpl(void* L, int index);
int LuaToIntegerImpl(void* L, int num);
double LuaToNumberImpl(void* L, int num);
void* LuaToUserDataImpl(void* L, int index);
int LuaTypeImpl(void* L, int num);
void LuaUnrefImpl(void* L, int a, int b);
uint32_t MakeHashImpl(const char* str);
HookApiPushMethodsResult PushLuaMethodsImpl( const char* name, const LuaMethodInfo* methods, uint32_t count);
bool RegisterGameEventImpl(const char* name, GameEventPushFn pushFn);
int RegisterPushMethodsTargetImpl(const char* name, int sigType, const char* pushMethodsSymbol);
void RegisterScriptGlobalsForUIImpl(ScriptGlobalsFn fn);
void RegisterScriptGlobalsImpl(ScriptGlobalsFn fn);

// TriggerGameEventImpl 的 __declspec(noinline) 是【行为的一部分】，不是装饰：
// 它用 _ReturnAddress() 反查调用方是不是插件。被内联后取到的是 Loader 自身的栈帧，
// 鉴权会静默失效（不报错，只是认不出插件）。故单独列出，保留该限定符。
__declspec(noinline) bool TriggerGameEventImpl(const char* name, const void* payload);

}  // namespace ScriptBridge
