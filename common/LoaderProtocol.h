#pragma once
#include <Windows.h>
#include <stddef.h>
#include <stdint.h>
#include "LoaderVersion.h"

// v2: LoaderHost/ABI 机制已随薄壳 Runtime 选举与启动移除（设计文档 §4.2/§4.3），
// 仅保留版本宏、文件名常量与导出函数指针类型。

#define CIV6_DLL_LOADER_MAKE_VERSION(major, minor, patch) \
    ((((uint32_t)(major)) << 16) | (((uint32_t)(minor)) << 8) | ((uint32_t)(patch)))

#define CIV6_DLL_LOADER_RUNTIME_FILENAMEA "Civ6DllLoader.runtime.dll"
#define CIV6_DLL_LOADER_RUNTIME_FILENAMEW L"Civ6DllLoader.runtime.dll"

#ifdef __cplusplus
extern "C" {
#endif

// Exported by Civ6DllLoader.runtime.dll
typedef uint32_t(__cdecl* GetLoaderVersionFn)(void);

#ifdef __cplusplus
}
#endif

// 预发布 1.0.0 运行时版本号（安装器与自更新比较用）
constexpr uint32_t kLoaderRuntimeVersion = CIV6_DLL_LOADER_MAKE_VERSION(
    CIV6_DLL_LOADER_VERSION_MAJOR, CIV6_DLL_LOADER_VERSION_MINOR, CIV6_DLL_LOADER_VERSION_PATCH);
