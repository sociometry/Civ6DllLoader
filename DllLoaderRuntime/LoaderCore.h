#pragma once
// Civ6DllLoader v2 — Loader 核心接口。
// 实现分布：RuntimeEntry.cpp（早期初始化与一次性启动线程）、
// Civ6DLLHookLoaderAPI.cpp（插件生命周期）、LoaderHooks.cpp（exe 域 hook 与阶段 B 编排）。
#include <string>
#include <mutex>

#include "../common/HookAPI.h"

namespace LoaderCore {

// 插件生命周期锁（递归）。所有模块都用它把"插件表状态"与"插件回调执行"串起来，
// 故必须共享同一把：它被 4 个模块、34 个函数引用，是引用面最广的一个共享对象。
//
// 锁层级（详见 docs/ARCHITECTURE.md §2.5，实测 5 级）：
//   g_gameCoreTransitionMutex → LifecycleMutex() → g_pushStateMutex
//     → Runtime::MinHookMutex() → g_captureMutex
// 递归获取不会死锁，但不要在持 MinHook/capture 锁时反向取它（ABBA）。
//
// 实现仍在 Civ6DLLHookLoaderAPI.cpp（阶段 6 随插件表迁到 PluginRegistry.cpp），
// 声明与调用方不变。
std::recursive_mutex& LifecycleMutex();

enum class PluginCategory {
    Global,   // Plugins\Global\*.dll：Loader 启动时加载（阶段 A）
    GameCore, // Plugins\GameCore\*.dll：GameCore::LoadDLL 成功后加载（阶段 B）
};

// 阶段 A 基础初始化（工作线程内调用）：Logger::Init(L"Civ6DllLoader_Loader.log")
// + VerifyHookApiTableProtection + PdataMatch::Init（含给当前 exe 建 pdata 表）+ Runtime::InitMinHook。
// 实现于 RuntimeEntry.cpp。
void InitEarly();

// Loader 自身模块句柄（version.dll）。实现于 RuntimeEntry.cpp。
// 用途：读自身内嵌资源（`UiInject::ExtractResources`）。插件扫描已不再以它为锚
//（内容根与调用方无关，见 ModScan::CollectScanRoots）。
// 返回 0 表示尚未初始化（DllMain 休眠检测未通过，理论不会走到扫描）。
HMODULE RuntimeModuleHandle();

// 交给插件的引导结构（实现于 HookLoaderApi.cpp）。
// 插件在 OnLoad 里用它的 Query 按名字把本模块私有的 HookAPI 表填满，之后照旧 api->Xxx(...)。
// Loader 自身的内部取址一律走下面的 CurrentExeImage / ResolveDataByAobCore 与
// AddressResolve.cpp 里的 *Core / InternalToolApi()，不经过插件 ABI、也不拿插件生命周期锁。
const HookContext* RuntimeHookContext();

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

// 扫描启用 Mod 并加载/卸载指定类别全部插件。实现于 Civ6DLLHookLoaderAPI.cpp。
void LoadPluginsOf(PluginCategory cat);
void UnloadPluginsOf(PluginCategory cat);

// 仅在 UnloadDLL 原函数返回且确认引擎模块槽从非空变空后调用：真正
// FreeLibrary 那些在 ResetForReload 里排队的 GameCore 插件模块。见实现处的时机说明。
void FreePendingPluginModules();

// 单插件加载（按路径含 \Plugins\Global\ 或 \Plugins\GameCore\ 判定类别）。
// 实现于 Civ6DLLHookLoaderAPI.cpp。
bool LoadSinglePlugin(const std::wstring& path);   // 已加载返回 false

// 阶段 B：官方 XP2 加载完成后（LoadDLL detour 内调用）。实现于 Civ6DLLHookLoaderAPI.cpp：
// AttachGameCore(GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll"))
// → 重装共享脚本钩（EnsureScriptHooksInstalled，Loader 内部 static，不在本头文件暴露）。
// （HKS / Localization 的导入不在这里——它们是进程级静态导入，已在阶段 A 的 WorkerMain 解析。）
// 返回 false 表示初始化失败（detour 据此跳过 GameCore 插件加载）。
bool InitializeGameCorePhase();

// GameCore 重载循环：IsInitialized = 阶段 B 是否已完成；
// ResetForReload = 卸载全部 GameCore 插件 + 复位初始化标志（引擎 UnloadDLL 之前调用）。
bool IsInitialized();
void ResetForReload();

// teardown 窗口的清零点：UnloadDLL 原函数返回且确认模块槽从非空变空后调用。
// 不要在 ResetForReload 内部提前清：窗口是"旧映像区间"，必须活到引擎真正换映像那一步，
// 否则仍映射着的旧映像会重新对 Global 插件变成可钩的已加载模块。
void ClearGameCoreTeardownWindow();

}  // namespace LoaderCore
