#pragma once
#include <Windows.h>
#include <stddef.h>
#include <stdint.h>
#include "LoaderVersion.h"

// 只保留版本宏与文件名常量：安装器/自更新读的是候选 DLL 的 RCDATA 105，不执行它的导出。

#define CIV6_DLL_LOADER_MAKE_VERSION(major, minor, patch) \
    ((((uint32_t)(major)) << 16) | (((uint32_t)(minor)) << 8) | ((uint32_t)(patch)))

#define CIV6_DLL_LOADER_RUNTIME_FILENAMEW L"Civ6DllLoader.runtime.dll"

// 预发布 1.0.0 运行时版本号（安装器与自更新比较用）
constexpr uint32_t kLoaderRuntimeVersion = CIV6_DLL_LOADER_MAKE_VERSION(
    CIV6_DLL_LOADER_VERSION_MAJOR, CIV6_DLL_LOADER_VERSION_MINOR, CIV6_DLL_LOADER_VERSION_PATCH);
