#pragma once
#include <Windows.h>
#include <stddef.h>
#include <stdint.h>

// Shell <-> Runtime ABI. structSize allows future fields to be appended
// without breaking runtimes that only require the stable prefix.
#ifndef CIV6_DLL_LOADER_HOST_ABI
#define CIV6_DLL_LOADER_HOST_ABI 1u
#endif

#define CIV6_DLL_LOADER_MAKE_VERSION(major, minor, patch) \
    ((((uint32_t)(major)) << 16) | (((uint32_t)(minor)) << 8) | ((uint32_t)(patch)))

#define CIV6_DLL_LOADER_RUNTIME_FILENAMEA "Civ6DllLoader.runtime.dll"
#define CIV6_DLL_LOADER_RUNTIME_FILENAMEW L"Civ6DllLoader.runtime.dll"

#ifdef __cplusplus
extern "C" {
#endif

typedef void* (__cdecl* DllCreateGameContextFn)(void);

typedef struct LoaderHost {
    uint32_t hostAbiVersion;          // CIV6_DLL_LOADER_HOST_ABI
    uint32_t structSize;              // sizeof(LoaderHost) supplied by the shell
    HMODULE shellModule;              // GameCore_XP2_Shell_FinalRelease.dll in-process
    HMODULE gameCoreModule;           // real GameCore_XP2_FinalRelease.dll
    DllCreateGameContextFn baseDllCreateGameContext;
} LoaderHost;

// Current runtime only requires fields through gameCoreModule. Keep this tied
// to the last mandatory field when optional fields are appended in the future.
#define CIV6_DLL_LOADER_HOST_REQUIRED_SIZE \
    (offsetof(LoaderHost, gameCoreModule) + sizeof(((LoaderHost*)0)->gameCoreModule))

// Exported by Civ6DllLoader.runtime.dll
typedef uint32_t(__cdecl* GetLoaderVersionFn)(void);
typedef int(__cdecl* LoaderStartFn)(const LoaderHost* host);
typedef void(__cdecl* LoaderShutdownFn)(void);

#ifdef __cplusplus
}
#endif
