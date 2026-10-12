#pragma once
// SymbolResolve.h — 地址解析：AOB 扫描 / 符号名 / RVA / vtable 槽 → 当前映像内的地址。
//
// 分层（见 docs/REFACTOR_PLAN.md §3.1）：
//   * 本文件只放【不校验插件边界、不加插件生命周期锁】的 Core 与 Loader 自用入口。
//   * 插件侧入口（ResolveByRvaImpl 等 5 个 *Impl）暂留母体，它们要调 PluginDomain
//     做归属校验；等 PluginDomain 抽出后再迁入（阶段 6）。
//
// 依赖：PdataMatch（符号库/pdata 矫正）、ImageAddress（映像登记与 RVA 换算）、
// Logger、PluginBoundary（只读探测）。不依赖 PluginDomain、不取 g_pluginLifecycleMutex。

#include "LoaderCore.h"        // LoaderCore::CurrentExeImage / ResolveDataByAobCore / ResolveExeTarget
#include "../common/HookAPI.h" // HookAPI / HookInfo / HookImageId / ResolveByHookInfo / ResolveDataByAob

namespace SymbolResolve {

// 按段名（.text/.idata/.rdata/.data）定位镜像内段的 RVA 与大小。
// 大小取 max(SizeOfRawData, VirtualSize)。找不到段返回 false。
//
// 【为什么它必须导出】：母体里的 ResolveByRvaExImpl（阶段 6 才迁走）调用它。
bool ResolveSectionRva(HookImageId image, const char* sectionName,
    uintptr_t* outRva, size_t* outSize);

// 以下三个 *Core 不做插件边界校验、不加插件生命周期锁：
//   * Loader 自身（ResolveExeTarget / LoaderHooks / UiInject）走它们；
//   * 插件走母体里的 *Impl（先校验归属，再加锁调这里）。
// 游戏线程在 LoadDLL detour 里解析自家 hook 目标时，不会去拿那把可能被卡住的插件锁。
//
// 【为什么它们必须导出】：母体里的 5 个 *Impl 调用它们。
void* ResolveByRvaCore(HookImageId image, uintptr_t rva, size_t span);
void* ResolveByNameCore(HookImageId image, const char* nameSafe);
void* ResolveByPatternCore(HookImageId image, const char* pattern, HookImageSection section,
    uint32_t index);

// 按 vtable 符号 + 槽序号解析虚函数地址。vtableSymbol 由调用方保证可读。
void* ResolveByVTableCore(HookImageId image, const char* vtableSymbol, uint32_t index);

// 符号库状态查询（转发 PdataMatch 的匹配状态/匹配率）。
// 【为什么必须导出】：g_hookApi 初始化表取这两个函数的地址。
HookApiSymbolDbState GetSymbolDbStateImpl(HookImageId image);
double GetSymbolDbMatchRatioImpl(HookImageId image);

// ---------------- 插件侧入口（阶段 6 从母体归位） ----------------
// 它们先过 PluginDomain 的归属/域门，再调上面的 *Core；是 HookAPI 表的目标。
// 签名与实现逐字一致（从源码提取）。
void* ResolveByRvaImpl(HookImageId image, uintptr_t rva, size_t span);
void* ResolveByNameImpl(HookImageId image, const char* name);
void* ResolveByRvaExImpl(HookImageId image, uintptr_t rva, size_t span, HookImageSection section);
void* ResolveByPatternImpl(HookImageId image, const char* patternIn, HookImageSection section,
    uint32_t index);
void* ResolveByVTableImpl(HookImageId image, const char* vtableSymbolIn, uint32_t index);

}  // namespace SymbolResolve
