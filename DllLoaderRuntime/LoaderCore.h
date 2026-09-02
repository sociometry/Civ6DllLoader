#pragma once
// Civ6DllLoader v2 — Loader 核心接口（S3a 在 RuntimeEntry.cpp 实现早期初始化与事件循环，
// S3c 在 Civ6DLLHookLoaderAPI.cpp 实现插件生命周期，S4 在 LoaderHooks.cpp 实现 hook 与阶段 B/C 编排）。
#include <string>

namespace LoaderCore {

enum class PluginCategory {
    Global,   // Plugins\Global\*.dll：Loader 启动时加载（阶段 A）
    GameCore, // Plugins\GameCore\*.dll：GameCore::LoadDLL 成功后加载（阶段 B）
};

// 阶段 A 基础初始化（工作线程内调用）：Logger::Init(L"Civ6DllLoader_Loader.log")
// + PdataMatch::Init + Runtime::InitMinHook。实现于 RuntimeEntry.cpp（S3a）。
void InitEarly();

// Loader 自身模块句柄（version.dll）。实现于 RuntimeEntry.cpp（S3a）；供插件扫描作锚。
// 返回 0 表示尚未初始化（DllMain 休眠检测未通过，理论不会走到扫描）。
HMODULE RuntimeModuleHandle();

// 工作线程事件：EnableMod/DisableMod detour（S4）调用本函数置标志并唤醒工作线程，
// 工作线程随后执行 ReconcileGlobalPlugins。实现于 RuntimeEntry.cpp（S3a）。
void RequestReconcile();

// 扫描启用 Mod 并加载/卸载指定类别全部插件。实现于 Civ6DLLHookLoaderAPI.cpp（S3c）。
void LoadPluginsOf(PluginCategory cat);
void UnloadPluginsOf(PluginCategory cat);

// 单插件加载/卸载（阶段 C 增量 reconcile 用；按路径含 \Plugins\Global\ 或 \Plugins\GameCore\ 判定类别）。
// 实现于 Civ6DLLHookLoaderAPI.cpp（S3c）。
bool LoadSinglePlugin(const std::wstring& path);   // 已加载返回 false
void UnloadSinglePlugin(const std::wstring& path); // 未加载 no-op

// 阶段 B：官方 XP2 加载完成后（S4 detour 内调用）。实现于 Civ6DLLHookLoaderAPI.cpp（S3c）：
// AttachGameCore(GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll"))
// → InitializeLoader(GetModuleHandleW(nullptr)) → hks::InitHavokScript() → Localization::InitScript()。
// 返回 false 表示初始化失败（S4 据此跳过 GameCore 插件加载）。
bool InitializeGameCorePhase();

// 阶段 C：对比当前启用集与已加载 Global 插件清单，卸载被移除者、加载新增者。实现于 S3c。
void ReconcileGlobalPlugins();

// GameCore 重载循环：IsInitialized = 阶段 B 是否已完成；
// ResetForReload = 卸载全部 GameCore 插件 + 复位初始化标志（S4 在再次进入 LoadDLL detour 时调用）。
// 实现于 S3c。
bool IsInitialized();
void ResetForReload();

}  // namespace LoaderCore
