#pragma once
#include <Windows.h>
#include <stddef.h>
#include <stdint.h>
#include "LoaderVersion.h"

// 只保留版本宏与文件名常量：安装器/自更新读的是候选 DLL 的 RCDATA 105，不执行它的导出。

#define CIV6_DLL_LOADER_MAKE_VERSION(major, minor, patch) \
    ((((uint32_t)(major)) << 16) | (((uint32_t)(minor)) << 8) | ((uint32_t)(patch)))

#define CIV6_DLL_LOADER_RUNTIME_FILENAMEW L"Civ6DllLoader.runtime.dll"

// ---- 代理文件名（安装目标 = 游戏 exe 目录里的这个名字）----
//
// 为什么是 winmm.dll 而不是 version.dll：
//   version.dll 是各注入工具共用的代理名，部分机器上（第三方启动器、安全软件、DLL 预加载
//   策略）会跳过 exe 目录里的这份、直接去 System32 取系统的那个 —— 表现为"loader 明明装了
//   却没生效"。winmm.dll 同样是 exe 静态导入表里的成员（导入序号 15），但它在那些机器上
//   能被正常解析，已实机验证。
//   附带收益：winmm 的导入序号晚于 Localization(10)/HavokScript(11)，Loader 因此晚于它们
//   载入，消除了 HavokScript/Localization 用 GetModuleHandle 取模块时的启动期竞态。
//
// 旧代理名只用于迁移与清理，新代码不再往这几个名字上安装任何东西。
#define CIV6_DLL_LOADER_PROXY_FILENAMEW L"winmm.dll"
#define CIV6_DLL_LOADER_PROXY_OLD_FILENAMEW L"winmm_Old.dll"
#define CIV6_DLL_LOADER_PROXY_TMP_FILENAMEW L"winmm.tmp"
#define CIV6_DLL_LOADER_LEGACY_PROXY_FILENAMEW L"version.dll"
#define CIV6_DLL_LOADER_LEGACY_PROXY_OLD_FILENAMEW L"version_Old.dll"

// 运行时版本号（1.1.0，安装器与自更新比较用）
constexpr uint32_t kLoaderRuntimeVersion = CIV6_DLL_LOADER_MAKE_VERSION(
    CIV6_DLL_LOADER_VERSION_MAJOR, CIV6_DLL_LOADER_VERSION_MINOR, CIV6_DLL_LOADER_VERSION_PATCH);
