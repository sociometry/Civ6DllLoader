#include "pch.h"
#include "../common/LoaderProtocol.h"
#include "Civ6DLLHookLoaderAPI.h"
#include "HavokScript.h"
#include "Localization.h"
#include "Logger.h"
#include "Runtime.h"
#include "SymbolDb.h"

// Bump when shipping loader fixes. Old mods keep old runtimes; election picks the newest.
static constexpr uint32_t kLoaderRuntimeVersion = CIV6_DLL_LOADER_MAKE_VERSION(1, 0, 0);

static HMODULE g_runtimeModule = nullptr;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        g_runtimeModule = hModule;
    } else if (reason == DLL_PROCESS_DETACH) {
        g_runtimeModule = nullptr;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) uint32_t __cdecl GetLoaderVersion(void) {
    return kLoaderRuntimeVersion;
}

extern "C" __declspec(dllexport) int __cdecl LoaderStart(const LoaderHost* host) {
    if (!host) return -1;
    if (host->hostAbiVersion != CIV6_DLL_LOADER_HOST_ABI) {
        Logger::Log("LoaderStart ABI mismatch: host=%u runtime=%u",
            host->hostAbiVersion, CIV6_DLL_LOADER_HOST_ABI);
        return -2;
    }
    if (host->structSize < CIV6_DLL_LOADER_HOST_REQUIRED_SIZE) {
        Logger::Log("LoaderStart host struct too small: host=%u required=%zu",
            host->structSize, static_cast<size_t>(CIV6_DLL_LOADER_HOST_REQUIRED_SIZE));
        return -3;
    }
    if (!host->shellModule || !host->gameCoreModule) {
        return -4;
    }

    Logger::Init(L"Civ6DllLoader_Runtime.log");
    Logger::Log("LoaderStart version=0x%08X", kLoaderRuntimeVersion);

    SymbolDb::Init(g_runtimeModule ? g_runtimeModule : host->shellModule);
    if (!AttachGameCore(host->gameCoreModule)) {
        SymbolDb::Shutdown();
        Logger::Shutdown();
        return -5;
    }
    // Use shell module path so ModScan finds sibling Workshop/Documents mods.
    InitializeLoader(host->shellModule);

    if (!Runtime::InitMinHook()) {
        CleanupLoader();
        SymbolDb::Shutdown();
        Logger::Shutdown();
        return -6;
    }
    hks::InitHavokScript();
    Localization::InitScript();
    LoadPlugins();

    Logger::Log("LoaderStart complete");
    return 0;
}

extern "C" __declspec(dllexport) void __cdecl LoaderShutdown(void) {
    Logger::Log("LoaderShutdown");
    CleanupLoader();
    SymbolDb::Shutdown();
    Logger::Shutdown();
}
