#pragma once
// Civ6DllLoader v2 — Loader 核心接口（S3a 在 RuntimeEntry.cpp 实现早期初始化与事件循环，
// S3c 在 Civ6DLLHookLoaderAPI.cpp 实现插件生命周期，S4 在 LoaderHooks.cpp 实现 hook 与阶段 B/C 编排）。
#include <string>

#include "../common/HookAPI.h"

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

// 进程内 HookAPI 实例（实现于 Civ6DLLHookLoaderAPI.cpp）。
// 用途只剩一个：把这张【只读表】交给插件（OnLoad）。Loader 自身的内部取址一律走下面的
// CurrentExeImage / ResolveDataByAobCore 与 Civ6DLLHookLoaderAPI.cpp 里的 *Core，
// 不经过插件 ABI、也不拿插件生命周期锁。
HookAPI* RuntimeHookApi();

// 当前进程 exe 的映像 id（DX11/DX12；未识别 = kHookImageInvalid）。
// 与 common/HookAPI.h 的 HookCurrentExeImage 同语义，但直连 ImageAddress。
HookImageId CurrentExeImage();

// Loader 内部解 exe 全局数据槽（AOB 相对寻址）。算法与 common/HookAPI.h 的
// ResolveDataByAob 相同，但走无锁内部表。失败返回 nullptr。
void* ResolveDataByAobCore(HookImageId image, const char* aob, uint32_t index = 1);

// 启动自检（实现于 Civ6DLLHookLoaderAPI.cpp）：确认 HookAPI 表位于只读页
// （.rdata）。不是只读就告警 —— 否则"插件写表"不会被拦截。
void VerifyHookApiTableProtection();

// exe 域目标解析（loader 自身 hook 用；实现于 Civ6DLLHookLoaderAPI.cpp）：
//  1) 变体由 CurrentExeImage 判定；未识别 -> nullptr；
//  2) 有该变体 PdataMatch 上下文，或 exe PE 身份与版本锚一致 -> 走 HookInfo 主路径
//     （RVA+pdata 矫正 / 名称 / vtable；AOB 兜底在 HookInfo 内部）；
//  3) 无上下文且身份与锚不一致 -> 跳过 RVA 路径，只用 AOB 兜底；再失败 -> nullptr。
//  全程走内部无锁工具表，不经过插件 HookAPI 表、不拿插件生命周期锁。
void* ResolveExeTarget(const HookInfoExe& info, size_t span = 1);

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
