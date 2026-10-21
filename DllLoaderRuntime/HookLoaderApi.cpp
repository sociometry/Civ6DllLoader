#include "pch.h"
#include "Civ6DLLHookLoaderAPI.h"

#include <Windows.h>
#include <cstdint>

#include "Civ6MessageBus.h"
#include "HookEngine.h"
#include "LoaderCore.h"
#include "PluginBoundary.h"
#include "PluginRegistry.h"
#include "PluginTableAccess.h"
#include "ScriptBridge.h"
#include "AddressResolve.h"
#include "PluginDomain.h"
#include "../common/HookAPI.h"
#include "../common/Logger.h"

// 从 Civ6DLLHookLoaderAPI.cpp 拆出（阶段 6）：HookAPI 表本身。
//
// 这是整个拆分的【组装根 / ABI 汇聚点】：g_hookApi 的初始化表取各模块 *Impl 的地址，
// 因此它 include 全部子系统头文件，且没有任何下层模块反向 include 它。
//
// 只读契约：Loader 初始化后从不写它（全是取地址/读取），插件也只该读。
// const 让它落到 .rdata（PAGE_READONLY）——插件写它会当场 AV，被 CallOnLoadSafe 接住。

using namespace std;

// 只读契约：Loader 初始化后从不写它（全是取地址/读取），插件也只该读。
// const 让它落到 .rdata（PAGE_READONLY）——插件写它会当场 AV，被 CallOnLoadSafe 接住。
static const HookAPI g_hookApi = {
    CIV6_HOOK_API_VERSION,
    static_cast<uint32_t>(sizeof(HookAPI)),

    &HookEngine::InstallHookImpl,
    &BroadcastMessageImpl,
    &PluginRegistry::RegisterMessageHandlerImpl,
    &SendMessageToImpl,

    &PluginRegistry::IsImageLoadedImpl,
    &PluginRegistry::GetImageInfoImpl,
    &AddressResolve::ResolveByRvaImpl,
    &AddressResolve::ResolveByNameImpl,
    &AddressResolve::ResolveByRvaExImpl,
    &AddressResolve::ResolveByPatternImpl,
    &HookEngine::RegisterGlobalCaptureImpl,
    &AddressResolve::ResolveByVTableImpl,

    &ScriptBridge::PushLuaMethodsImpl,

    &ScriptBridge::RegisterGameCoreScriptForGamePlayImpl,
    &ScriptBridge::RegisterGameCoreScriptForUIImpl,

    &ScriptBridge::LuaPushNamedCClosureImpl,
    &ScriptBridge::LuaCheckIntegerImpl,
    &ScriptBridge::LuaCheckNumberImpl,
    &ScriptBridge::LuaSetFieldImpl,
    &ScriptBridge::LuaGetTopImpl,
    &ScriptBridge::LuaDoStringImpl,
    &ScriptBridge::LuaToBooleanImpl,
    &ScriptBridge::LuaPushNumberImpl,
    &ScriptBridge::LuaPushIntegerImpl,
    &ScriptBridge::LuaErrorImpl,
    &ScriptBridge::LuaPushFStringImpl,
    &ScriptBridge::LuaCheckLStringImpl,
    &ScriptBridge::LuaToUserDataImpl,
    &ScriptBridge::LuaGetFieldImpl,
    &ScriptBridge::LuaPopImpl,
    &ScriptBridge::LuaCreateTableImpl,
    &ScriptBridge::LuaToCFunctionImpl,
    &ScriptBridge::LuaCheckTableImpl,
    &ScriptBridge::LuaObjLenImpl,
    &ScriptBridge::LuaGetTableImpl,
    &ScriptBridge::LuaCPcallImpl,
    &ScriptBridge::LuaRefImpl,
    &ScriptBridge::LuaPcallImpl,
    &ScriptBridge::LuaPushValueImpl,
    &ScriptBridge::LuaRawGetIImpl,
    &ScriptBridge::LuaUnrefImpl,
    &ScriptBridge::LuaSetTableImpl,
    &ScriptBridge::LuaIsNumberImpl,
    &ScriptBridge::LuaToNumberImpl,
    &ScriptBridge::LuaIsUserDataImpl,
    &ScriptBridge::LuaOpenDebugImpl,
    &ScriptBridge::LuaToIntegerImpl,
    &ScriptBridge::LuaTypeImpl,
    &ScriptBridge::LuaOptIntegerImpl,
    &ScriptBridge::LuaSetHookImpl,
    &ScriptBridge::LuaGetHookImpl,
    &ScriptBridge::LuaGetHookMaskImpl,
    &ScriptBridge::LuaGetHookCountImpl,
    &ScriptBridge::LuaCheckPlayerIdImpl,
    &ScriptBridge::LuaPushBooleanImpl,
    &ScriptBridge::LuaPushLightUserDataImpl,

    &ScriptBridge::LogImpl,
    &ScriptBridge::LuaPushCFunctionFieldImpl,
    &ScriptBridge::LuaNewGlobalTableImpl,

    &ScriptBridge::LocalizationLookupImpl,

    &ScriptBridge::LocStringBytesImpl,
    &ScriptBridge::LocCreateImpl,
    &ScriptBridge::LocDestroyImpl,
    &ScriptBridge::LocLookupImpl,
    &ScriptBridge::LocPushArgumentImpl,
    &ScriptBridge::LocToUtf8Impl,

    &ScriptBridge::GetPlayerImpl,
    &ScriptBridge::MakeHashImpl,

    &PluginRegistry::HookPatch,
    &PluginRegistry::HookUnpatch,

    &ScriptBridge::RegisterGameEventImpl,
    &ScriptBridge::TriggerGameEventImpl,

    &ScriptBridge::GetMainLuaStateImpl,
    &ScriptBridge::LuaPushNilImpl,
    &AddressResolve::GetSymbolDbStateImpl,
    &AddressResolve::GetSymbolDbMatchRatioImpl,
    &HookEngine::UnregisterGlobalCaptureImpl,
    &ScriptBridge::RegisterGlobalScriptImpl,
    &ScriptBridge::LuaNextImpl,
};

// ==== RuntimeHookContext / HookApiQuery ====
// 插件不再拿到这张表：OnLoad 收到的是 HookContext（3 个字段，见 common/HookAPI.h），
// 里面只有一个 Query —— 插件在 OnLoad 里按名字把自己那张 HookAPI 表填满。
// 名字是白名单：只认 HOOK_API_LIST 里的 80 个入口，loader 的其它函数一律不暴露。
//
// g_hookApi 不删除，它现在的角色是【loader 内部实现地址表】：
// Query 按名字取其中的槽，其余用途（内部 header-only 工具）也照旧可用。
static void* HookApiQuery(const char* name) {
    if (!name || !*name) return nullptr;
    const uint8_t* base = reinterpret_cast<const uint8_t*>(&g_hookApi);
    void* slot = nullptr;
    // 按名字取 g_hookApi 里对应的那一格。名字由清单经 # 字符串化得到，不手写。
#define CIV6_HOOKAPI_QUERY(entryName)                                      \
    if (strcmp(name, #entryName) == 0) {                                   \
        std::memcpy(&slot, base + offsetof(HookAPI, entryName), sizeof(slot)); \
        return slot;                                                       \
    }
#define X(entryName, returnType, params, category) CIV6_HOOKAPI_QUERY(entryName)
    HOOK_API_LIST(X)
#undef X
#undef CIV6_HOOKAPI_QUERY
    return nullptr;
}

// 递给 OnLoad 的唯一出口。契约：只读，load 期间不变。
// 字段顺序见 common/HookAPI.h 的 HookContext 注释：structSize 在偏移 0，兼作部署一致性哨兵。
const HookContext* LoaderCore::RuntimeHookContext() {
    static const HookContext ctx = {
        static_cast<uint32_t>(sizeof(HookContext)),
        CIV6_HOOK_API_VERSION,
        &HookApiQuery,
    };
    return &ctx;
}

// ==== VerifyHookApiTableProtection ====
// 启动自检：确认这张表真的落在只读页，并且没有空项。MSVC 一般会把常量初始化的 const 对象
// 放进 .rdata，但那是实现细节而非语言保证 —— 一旦落到可写段，"插件改表"就不会被拦。
// 空项检查补的是编译器抓不到的那一半：追加字段、bump 了计数却漏填初始化的项，
// 聚合初始化只会静默零填，等到插件按表调用就是空指针调用 —— 这里在启动时 fail-loud。
// 前提由上面两条 static_assert 保证：入口字段从 offsetof(InstallHook) 起连续 8 字节一格。
void LoaderCore::VerifyHookApiTableProtection() {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(&g_hookApi, &mbi, sizeof(mbi)) == 0) {
        Logger::Log("[WARN] HookAPI 表: VirtualQuery 失败 err=%lu", GetLastError());
        return;
    }
    const DWORD protect = mbi.Protect;
    const bool writable = (protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    if (writable) {
        Logger::Log("[WARN] HookAPI 表落在可写页 (Protect=0x%lX base=%p)：插件写入不会被拦截，"
                    "请检查 const 与段归属", protect, static_cast<const void*>(&g_hookApi));
    } else {
        Logger::Log("HookAPI 表只读保护已验证 (Protect=0x%lX)", protect);
    }

    // 空项扫描：入口字段在结构体里连续排列（由 static_assert 保证），逐格读一遍。
    const uint8_t* slotBase = reinterpret_cast<const uint8_t*>(&g_hookApi) +
        offsetof(HookAPI, InstallHook);
    size_t nulls = 0;
    for (uint32_t i = 0; i < CIV6_HOOK_API_ENTRY_COUNT; ++i) {
        void* slot = nullptr;
        std::memcpy(&slot, slotBase + static_cast<size_t>(i) * sizeof(void*), sizeof(void*));
        if (!slot) {
            ++nulls;
            Logger::Log("[WARN] HookAPI 表第 %u 项为空（追加字段后忘了填 g_hookApi？）", i);
        }
    }
    if (nulls != 0) {
        Logger::Log("[WARN] HookAPI 表空项合计 %zu / %u：这些入口一旦被插件调用就是空指针调用",
            nulls, CIV6_HOOK_API_ENTRY_COUNT);
    }
}

// ABI 守卫：字段数 / 偏移一旦漂移，插件按旧布局调用就会踩错函数指针。
// 放在表定义之后，确保断言的是【实际发布的这张表】。
static_assert(sizeof(HookAPI) == sizeof(uint32_t) * 2 + CIV6_HOOK_API_ENTRY_COUNT * sizeof(void*),
    "HookAPI 布局与 CIV6_HOOK_API_ENTRY_COUNT 不一致：加字段后要同步这个常量");
static_assert(offsetof(HookAPI, LuaNext) == sizeof(uint32_t) * 2 +
    (CIV6_HOOK_API_ENTRY_COUNT - 1) * sizeof(void*),
    "HookAPI 末字段偏移不符：追加字段时顺序不能变（插件按偏移读）");
