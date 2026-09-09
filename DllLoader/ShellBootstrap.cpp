#include "pch.h"
#include "ShellBootstrap.h"
#include "../common/LoaderProtocol.h"
#include "../common/ModScan.h"
#include "../common/RestartGame.h"
#include "../common/RuntimePackage.h"
#include "../common/Logger.h"

#include <algorithm>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")

namespace ShellBootstrap {

namespace {

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

// Full path of the running process executable (e.g. ...\CivilizationVI.exe).
std::wstring GetProcessExePath() {
    wchar_t buf[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    return std::wstring(buf, n);
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

bool InstallLoaderIfMissing(HMODULE shellModule) {
    // Install at most once per process; the game may create/destroy game
    // contexts repeatedly within one session (reload cycles).
    static bool s_attempted = false;
    static bool s_installed = false;
    if (s_attempted) return s_installed;
    s_attempted = true;

    // a. Compute the exe directory from the current process image.
    const std::wstring exePath = GetProcessExePath();
    const size_t slash = exePath.find_last_of(L"\\/");
    if (exePath.empty() || slash == std::wstring::npos) {
        Logger::Log("InstallLoaderIfMissing: cannot resolve exe directory (path=%ls)", exePath.c_str());
        return false;
    }
    const std::wstring exeDir = exePath.substr(0, slash);
    const std::wstring versionDll = exeDir + L"\\version.dll";

    // b. Loader already installed -> zero action (no copy, no message box).
    const DWORD attr = GetFileAttributesW(versionDll.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        Logger::Log("InstallLoaderIfMissing: already installed: %ls", versionDll.c_str());
        s_installed = true;
        return s_installed;
    }

    // c. Collect candidates from enabled mods (ModScan applies the EnabledMods
    //    filter internally), probe versions, elect the highest
    //    (tie -> lexicographically smaller path).
    const auto paths = ModScan::FindRuntimeCandidates(shellModule);
    Logger::Log("InstallLoaderIfMissing: found %zu runtime candidate(s)", paths.size());

    std::vector<RuntimeCandidate> ranked;
    ranked.reserve(paths.size());
    for (const auto& path : paths) {
        uint32_t version = 0;
        if (!RuntimePackage::ProbeVersion(path, version)) continue;
        Logger::Log("InstallLoaderIfMissing: candidate %ls version=0x%08X", path.c_str(), version);
        ranked.push_back(RuntimeCandidate{path, version});
    }

    if (ranked.empty()) {
        // e. No usable candidate -> silent + log only (never a message box).
        Logger::Log("InstallLoaderIfMissing: no usable Civ6DllLoader.runtime.dll found; loader stays missing");
        return false;
    }
    std::sort(ranked.begin(), ranked.end(), BetterThan);
    const std::wstring& bestPath = ranked.front().path;
    Logger::Log("InstallLoaderIfMissing: elected %ls (version=0x%08X)", bestPath.c_str(), ranked.front().version);

    // d. Copy to exe-dir\version.tmp, atomic rename to version.dll, cleanup,
    //    then announce. Any failure below is silent + logged only.
    const std::wstring tmp = exeDir + L"\\version.tmp";
    if (!RuntimePackage::StageCandidate(bestPath, tmp, ranked.front().version)) {
        Logger::Log("InstallLoaderIfMissing: staging failed for %ls", bestPath.c_str());
        return false;
    }
    if (!RuntimePackage::PublishStaged(tmp, versionDll)) {
        return false;
    }
    // Best-effort stale-backup cleanup; failure is ignored.
    DeleteFileW((exeDir + L"\\version_Old.dll").c_str());

    MessageBoxW(nullptr,
        L"Civ6 DLL Loader 已安装，点击确定立即重启游戏。\nCiv6 DLL Loader installed. Click OK to restart the game now.",
        L"Civ6 DLL Loader",
        MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND);
    if (!RestartGame::LaunchAndExit()) {
        Logger::Log("InstallLoaderIfMissing: restart failed err=%lu; session continues", GetLastError());
    }

    s_installed = true;
    Logger::Log("InstallLoaderIfMissing: installed %ls -> %ls", bestPath.c_str(), versionDll.c_str());
    return s_installed;
}

}  // namespace ShellBootstrap
