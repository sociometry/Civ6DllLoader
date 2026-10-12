#pragma once
// PluginTableAccess.h — PluginDomain 读插件表所需的只读接口。
//
// 为什么单独一个头：插件表（g_plugins）与"当前活跃插件"（g_activePluginOwner/Module）
// 三个变量归 PluginRegistry 所有，而 PluginDomain 是它的下层。若让 PluginDomain 直接
// 看见这三个变量，就得把它们 extern 出去（违背 REFACTOR_PLAN.md §5 "不用 extern 全局
// 变量"原则），且 PluginDomain 会被迫 include 插件表的数据结构（PluginEntry / PluginState）。
//
// 所以按 §5.2 设计：把"查表"整体收进一个函数，调用方只拿结果。
//
// 实现归属：最终在 PluginRegistry.cpp。阶段 2 时插件表还在母体，故暂由母体实现，
// 阶段 6 随表一起搬走 —— 声明与调用方不变。

#include <optional>

#include <Windows.h>

#include "PluginDomain.h"      // PluginDomain::CallerPluginInfo

namespace PluginRegistry {

// 按 HMODULE 反查它属于哪个插件，返回 ownerId 与类别。
//
// 内部含两段优先级规则（与拆分前一致）：
//   规则 1：当前活跃插件优先（且排除已隔离）；
//   规则 2：任意 Loading/Active 的同模块插件。
//
// 【锁约定】调用方【不得】持有 g_pluginLifecycleMutex —— 本函数内部自己取。
// （该 mutex 是 recursive_mutex，重复获取不会死锁，但把锁语义显式化更清楚。）
//
// 地址不在任何已加载模块内、或模块不对应任何插件 -> nullopt。
std::optional<PluginDomain::CallerPluginInfo> ResolveOwnerByModule(HMODULE module);

}  // namespace PluginRegistry
