#include "ShellBootstrap.h"
#include "../common/LoaderProtocol.h"
#include "../common/ModScan.h"
#include "Logger.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace ShellBootstrap {

namespace {

HMODULE g_electedRuntime = nullptr;
LoaderShutdownFn g_loaderShutdown = nullptr;

struct RuntimeCandidate {
    std::wstring path;
    uint32_t version = 0;
};

HMODULE LoadModuleFromPath(const std::wstring& path) {
    return LoadLibraryExW(path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
}

bool BetterThan(const RuntimeCandidate& a, const RuntimeCandidate& b) {
    if (a.version != b.version) return a.version > b.version;
    // Stable tie-break: lexicographically smaller path wins.
    return a.path < b.path;
}

bool ProbeRuntimeVersion(const std::wstring& path, uint32_t& outVersion) {
    HMODULE mod = LoadModuleFromPath(path);
    if (!mod) {
        Logger::Log("Runtime probe failed: %ls (err=%lu)", path.c_str(), GetLastError());
        return false;
    }

    auto getVersion = reinterpret_cast<GetLoaderVersionFn>(GetProcAddress(mod, "GetLoaderVersion"));
    auto start = reinterpret_cast<LoaderStartFn>(GetProcAddress(mod, "LoaderStart"));
    const bool ok = getVersion && start;
    if (ok) {
        outVersion = getVersion();
    } else {
        Logger::Log("Runtime missing exports: %ls", path.c_str());
    }
    FreeLibrary(mod);
    return ok;
}

}  // namespace

HMODULE LoadRealGameCore() {
    // Prefer an already-mapped module (export forwarders often load it by basename).
    if (HMODULE existing = GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll")) {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(existing, path, MAX_PATH) > 0) {
            if (HMODULE bumped = LoadModuleFromPath(path)) {
                return bumped;
            }
        }
    }

    // Resolve from CivilizationVI.exe dir: Base\Binaries\Win64 -> DLC\Expansion2\...
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) > 0) {
        std::wstring dir(exePath);
        const size_t slash = dir.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            dir.resize(slash);
            const std::wstring candidate =
                dir + L"\\..\\..\\..\\DLC\\Expansion2\\Binaries\\Win64\\GameCore_XP2_FinalRelease.dll";
            wchar_t full[MAX_PATH];
            if (GetFullPathNameW(candidate.c_str(), MAX_PATH, full, nullptr) > 0) {
                if (HMODULE gameCore = LoadModuleFromPath(full)) {
                    return gameCore;
                }
                Logger::Log("LoadRealGameCore absolute failed: %ls (err=%lu)", full, GetLastError());
            }
        }
    }

    // Legacy CWD-relative fallback (works when cwd is game Win64).
    wchar_t legacyFull[MAX_PATH]{};
    HMODULE gameCore = nullptr;
    if (GetFullPathNameW(L"../../../DLC/Expansion2/Binaries/Win64/GameCore_XP2_FinalRelease.dll",
            MAX_PATH, legacyFull, nullptr) > 0) {
        gameCore = LoadModuleFromPath(legacyFull);
    }
    if (!gameCore) {
        Logger::Log("Failed to load real GameCore_XP2_FinalRelease.dll (err=%lu)", GetLastError());
    }
    return gameCore;
}

HMODULE ElectAndStartRuntime(HMODULE shellModule, HMODULE gameCoreModule, void* baseDllCreateGameContext) {
    if (g_electedRuntime) {
        return g_electedRuntime;
    }

    const auto paths = ModScan::FindRuntimeCandidates(shellModule);
    Logger::Log("Found %zu runtime candidate(s)", paths.size());

    std::vector<RuntimeCandidate> ranked;
    ranked.reserve(paths.size());
    for (const auto& path : paths) {
        uint32_t version = 0;
        if (!ProbeRuntimeVersion(path, version)) continue;
        Logger::Log("Candidate %ls version=0x%08X", path.c_str(), version);
        ranked.push_back(RuntimeCandidate{path, version});
    }

    if (ranked.empty()) {
        Logger::Log("No usable Civ6DllLoader.runtime.dll found");
        return nullptr;
    }

    // Ranked list already preferred highest version; try elected first, then fallbacks.
    std::sort(ranked.begin(), ranked.end(), BetterThan);

    LoaderHost host{};
    host.hostAbiVersion = CIV6_DLL_LOADER_HOST_ABI;
    host.structSize = static_cast<uint32_t>(sizeof(host));
    host.shellModule = shellModule;
    host.gameCoreModule = gameCoreModule;
    host.baseDllCreateGameContext = reinterpret_cast<DllCreateGameContextFn>(baseDllCreateGameContext);

    for (const auto& candidate : ranked) {
        HMODULE mod = LoadModuleFromPath(candidate.path);
        if (!mod) {
            Logger::Log("LoadLibrary failed for %ls (err=%lu)", candidate.path.c_str(), GetLastError());
            continue;
        }

        auto getVersion = reinterpret_cast<GetLoaderVersionFn>(GetProcAddress(mod, "GetLoaderVersion"));
        auto start = reinterpret_cast<LoaderStartFn>(GetProcAddress(mod, "LoaderStart"));
        auto shutdown = reinterpret_cast<LoaderShutdownFn>(GetProcAddress(mod, "LoaderShutdown"));
        if (!getVersion || !start) {
            Logger::Log("Runtime exports missing after load: %ls", candidate.path.c_str());
            FreeLibrary(mod);
            continue;
        }

        const int rc = start(&host);
        if (rc != 0) {
            Logger::Log("LoaderStart failed (%d) for %ls", rc, candidate.path.c_str());
            FreeLibrary(mod);
            continue;
        }

        g_electedRuntime = mod;
        g_loaderShutdown = shutdown;
        Logger::Log("Runtime started: %ls", candidate.path.c_str());
        return g_electedRuntime;
    }

    Logger::Log("All runtime candidates failed to start");
    return nullptr;
}

void ShutdownRuntime() {
    // Idempotent: normal teardown runs from DllDestroyGameContext.
    LoaderShutdownFn shutdown = g_loaderShutdown;
    g_loaderShutdown = nullptr;
    if (shutdown) {
        shutdown();
    }
    if (g_electedRuntime) {
        FreeLibrary(g_electedRuntime);
        g_electedRuntime = nullptr;
    }
}

}  // namespace ShellBootstrap
