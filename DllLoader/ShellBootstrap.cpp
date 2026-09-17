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

// ---- 路径辅助：按需增长缓冲，绝不把 MAX_PATH 截断当成成功 ----
// 这两个 API 的坑：GetModuleFileNameW 截断时返回缓冲区大小（不设 last error）；
// GetFullPathNameW 缓冲区不足时返回**所需长度**（> 0）。只判 "> 0" 就会把截断/残缺内容
// 当成功继续用（拼出的路径随即被 LoadLibraryExW 拿去加载）。这里统一改成"不够就翻倍重试"。
constexpr DWORD kMaxPathChars = 32768;   // 与长路径上限对齐，纯防御

bool GetModuleFileNameChecked(HMODULE module, std::wstring& out) {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(module, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0) return false;
        if (n < buf.size()) {
            buf.resize(n);
            out = std::move(buf);
            return true;
        }
        if (buf.size() >= kMaxPathChars) return false;
        buf.resize(buf.size() * 2, L'\0');
    }
}

bool GetFullPathChecked(const std::wstring& path, std::wstring& out) {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buf.size()),
            buf.data(), nullptr);
        if (n == 0) return false;
        if (n < buf.size()) {
            buf.resize(n);
            out = std::move(buf);
            return true;
        }
        if (buf.size() >= kMaxPathChars) return false;
        buf.resize(buf.size() * 2, L'\0');
    }
}

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
    std::wstring path;
    return GetModuleFileNameChecked(nullptr, path) ? path : std::wstring{};
}

}  // namespace

HMODULE LoadRealGameCore() {
    // Prefer an already-mapped module (export forwarders often load it by basename).
    if (HMODULE existing = GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll")) {
        std::wstring path;
        if (GetModuleFileNameChecked(existing, path)) {
            if (HMODULE bumped = LoadModuleFromPath(path)) {
                return bumped;
            }
        }
    }

    // Resolve from CivilizationVI.exe dir: Base\Binaries\Win64Steam (or Win64) -> DLC\Expansion2\...
    std::wstring exePath;
    if (GetModuleFileNameChecked(nullptr, exePath)) {
        const size_t slash = exePath.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            const std::wstring dir = exePath.substr(0, slash);
            const std::wstring candidate =
                dir + L"\\..\\..\\..\\DLC\\Expansion2\\Binaries\\Win64\\GameCore_XP2_FinalRelease.dll";
            std::wstring full;
            if (GetFullPathChecked(candidate, full)) {
                if (HMODULE gameCore = LoadModuleFromPath(full)) {
                    return gameCore;
                }
                Logger::Log("LoadRealGameCore absolute failed: %ls (err=%lu)", full.c_str(), GetLastError());
            }
        }
    }

    Logger::Log("Failed to load real GameCore_XP2_FinalRelease.dll (err=%lu)", GetLastError());
    return nullptr;
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

    // c. Collect candidates from the scan roots (game root / Documents Mods / Workshop) plus the
    //    loader's own directory. FindRuntimeCandidates deliberately does NOT filter by
    //    mod-enabled state - installation elects by version only (RCDATA 105), which is a
    //    separate path from "plugins load only from enabled mods". Probe versions, elect the
    //    highest (tie -> lexicographically smaller path).
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
