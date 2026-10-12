#pragma once
// AddressResolve.h — 地址解析：AOB 扫描 / 符号名 / RVA / vtable 槽 → 当前映像内的地址。
//
// 【为什么叫 Address 而不是 Symbol】：本模块的【输出】一律是地址；符号名只是四条
// 输入路径之一（另外三条是 AOB 模式、RVA、vtable 槽序号）。符号库本身归 PdataMatch
// （它读 sidecar、做跨版本矫正），本模块只负责"给一个线索，换回一个地址"。
//
// 分层（见 docs/REFACTOR_PLAN.md §3.1）：
//   * *Core：不做插件边界校验、不加插件生命周期锁 —— Loader 自身走这条
//     （ResolveExeTarget / LoaderHooks / UiInject）。游戏线程在 LoadDLL detour 里
//     解析自家 hook 目标时，不会去拿那把可能被卡住的插件锁。
//   * *Impl：插件侧入口，先过 PluginDomain 的归属/域门，再调对应 *Core。
//
// 依赖：PdataMatch（符号库 / pdata 矫正）、ImageAddress（映像登记与 RVA 换算）、
// Logger、PluginBoundary（只读探测）、PluginDomain（仅 *Impl 用）。

#include "LoaderCore.h"        // LoaderCore::CurrentExeImage / ResolveDataByAobCore / ResolveExeTarget
#include "../common/HookAPI.h" // HookAPI / HookInfo / HookImageId / ResolveByHookInfo / ResolveDataByAob

namespace AddressResolve {

// 按段名（.text/.idata/.rdata/.data）定位镜像内段的 RVA 与大小。
// 大小取 max(SizeOfRawData, VirtualSize)。找不到段返回 false。
bool ResolveSectionRva(HookImageId image, const char* sectionName,
    uintptr_t* outRva, size_t* outSize);

// 三条内部核心（name / pattern 由调用方保证可读：Loader 用字面量、插件先抄写）。
void* ResolveByRvaCore(HookImageId image, uintptr_t rva, size_t span);
void* ResolveByNameCore(HookImageId image, const char* nameSafe);
void* ResolveByPatternCore(HookImageId image, const char* pattern, HookImageSection section,
    uint32_t index);

// 按 vtable 符号 + 槽序号解析虚函数地址。vtableSymbol 由调用方保证可读。
void* ResolveByVTableCore(HookImageId image, const char* vtableSymbol, uint32_t index);

// 符号库状态查询（转发 PdataMatch 的匹配状态/匹配率）。
// 名字带 SymbolDb 是因为它报的是【符号库】的匹配情况，不是本模块的名字来源。
HookApiSymbolDbState GetSymbolDbStateImpl(HookImageId image);
double GetSymbolDbMatchRatioImpl(HookImageId image);

// ---------------- 插件侧入口（HookAPI 表的目标） ----------------
// 先过 PluginDomain 的归属/域门，再调上面的 *Core。
void* ResolveByRvaImpl(HookImageId image, uintptr_t rva, size_t span);
void* ResolveByNameImpl(HookImageId image, const char* name);
void* ResolveByRvaExImpl(HookImageId image, uintptr_t rva, size_t span, HookImageSection section);
void* ResolveByPatternImpl(HookImageId image, const char* patternIn, HookImageSection section,
    uint32_t index);
void* ResolveByVTableImpl(HookImageId image, const char* vtableSymbolIn, uint32_t index);

}  // namespace AddressResolve
