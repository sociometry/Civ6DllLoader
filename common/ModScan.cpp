#include "pch.h"
#include "ModScan.h"
#include "EnabledMods.h"
#include "LoaderProtocol.h"
#include "Logger.h"

#include <algorithm>
#include <set>
#include <shlobj.h>

#pragma comment(lib, "Shell32.lib")

namespace ModScan {

namespace {

constexpr const wchar_t* kCiv6SteamAppId = L"289070";

bool EqualsIgnoreCase(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (towlower(a[i]) != towlower(b[i])) return false;
    }
    return true;
}

void AddUnique(std::vector<std::wstring>& out, const std::wstring& path) {
    if (path.empty()) return;
    for (const auto& existing : out) {
        if (EqualsIgnoreCase(existing, path)) return;
    }
    out.push_back(path);
}

void AddUniqueNormalized(std::vector<std::wstring>& out, const fs::path& path) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return;
    AddUnique(out, path.wstring());
}

std::wstring GetDocumentsModsRoot() {
    wchar_t* docs = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &docs)) || !docs) {
        return {};
    }
    fs::path root = fs::path(docs) / L"My Games" / L"Sid Meier's Civilization VI" / L"Mods";
    CoTaskMemFree(docs);
    return root.wstring();
}

// Walk up from shell Win64 dir looking for steamapps/workshop/content/289070.
std::wstring FindWorkshopContentRoot(const std::wstring& binariesWin64Dir) {
    std::error_code ec;
    fs::path cur(binariesWin64Dir);
    for (int i = 0; i < 12 && !cur.empty(); ++i) {
        fs::path candidate = cur / L"steamapps" / L"workshop" / L"content" / kCiv6SteamAppId;
        if (fs::is_directory(candidate, ec)) {
            return candidate.wstring();
        }
        // Also accept if we are already inside .../workshop/content/289070/<mod>/...
        if (EqualsIgnoreCase(cur.filename().wstring(), kCiv6SteamAppId)) {
            const fs::path parent = cur.parent_path();
            if (EqualsIgnoreCase(parent.filename().wstring(), L"content")) {
                return cur.wstring();
            }
        }
        fs::path parent = cur.parent_path();
        if (parent == cur) break;
        cur = parent;
    }
    return {};
}

void CollectRuntimesUnderContentRoot(const fs::path& contentRoot, std::vector<std::wstring>& out) {
    std::error_code rootEc;
    if (!fs::is_directory(contentRoot, rootEc)) return;

    // Do not reuse error_code across exists/is_directory checks: a missing
    // Binaries tree must not abort iteration of sibling mod folders.
    std::error_code iterEc;
    for (fs::directory_iterator it(contentRoot, iterEc), end; !iterEc && it != end; it.increment(iterEc)) {
        std::error_code entryEc;
        if (!it->is_directory(entryEc)) continue;
        AddUniqueNormalized(out, it->path() / L"Binaries" / L"Win64" / CIV6_DLL_LOADER_RUNTIME_FILENAMEW);
    }
}

void DedupPluginsByFilename(std::vector<std::wstring>& paths) {
    std::set<std::wstring> seenNames;
    std::vector<std::wstring> filtered;
    filtered.reserve(paths.size());
    for (const auto& path : paths) {
        std::wstring name = fs::path(path).filename().wstring();
        for (auto& c : name) c = towlower(c);
        if (seenNames.count(name)) {
            const std::string narrow = WideToNarrow(path);
            Logger::Log("Skipping duplicate plugin basename (kept earlier path): %s", narrow.c_str());
            continue;
        }
        seenNames.insert(name);
        filtered.push_back(path);
    }
    paths.swap(filtered);
}

// Keep shell-local + Additional-Content-enabled mods only.
void FilterByEnabledMods(std::vector<std::wstring>& paths, HMODULE shellModule, const char* what) {
    if (paths.empty()) return;

    const std::wstring shellDir = GetModuleDirectory(shellModule);
    const std::wstring shellModRoot = EnabledMods::FindModRoot(shellDir);

    const EnabledMods::Snapshot snap = EnabledMods::Load();
    if (!snap.ok) {
        Logger::Log("WARN EnabledMods unavailable (%s); keeping only shell-local %s",
            snap.error.empty() ? "unknown" : snap.error.c_str(), what);
        std::vector<std::wstring> localOnly;
        localOnly.reserve(paths.size());
        for (const auto& path : paths) {
            const bool keep = (!shellModRoot.empty() && EnabledMods::PathIsUnderRoot(path, shellModRoot))
                || EnabledMods::PathIsUnderRoot(path, shellDir)
                || EqualsIgnoreCase(fs::path(path).parent_path().wstring(), shellDir)
                || EqualsIgnoreCase(fs::path(path).parent_path().parent_path().wstring(), shellDir);
            if (keep) {
                localOnly.push_back(path);
            } else {
                Logger::Log("Skipping %s (no EnabledMods DB): %s", what, WideToNarrow(path).c_str());
            }
        }
        paths.swap(localOnly);
        return;
    }

    Logger::Log("EnabledMods: %zu mod id(s), %zu root(s) for %s filter",
        snap.modIds.size(), snap.enabledModRoots.size(), what);

    std::vector<std::wstring> filtered;
    filtered.reserve(paths.size());
    for (const auto& path : paths) {
        const bool shellLocal = (!shellModRoot.empty() && EnabledMods::PathIsUnderRoot(path, shellModRoot))
            || EnabledMods::PathIsUnderRoot(path, shellDir);
        if (shellLocal || EnabledMods::AllowsPath(snap, path)) {
            filtered.push_back(path);
            continue;
        }
        Logger::Log("Skipping disabled/absent mod %s: %s", what, WideToNarrow(path).c_str());
    }
    paths.swap(filtered);
}

}  // namespace

namespace {

// v2: collect <mod>/Binaries/Win64/Plugins/<pluginSubdir>/*.dll candidates under one content root
// (Plugins\Global\ and Plugins\GameCore\ hierarchy one level deeper than the legacy flat Plugins\ scan).
void CollectPluginsUnderContentRootDir(const fs::path& contentRoot, const fs::path& pluginSubdir,
                                       std::vector<std::wstring>& out) {
    std::error_code rootEc;
    if (!fs::is_directory(contentRoot, rootEc)) return;

    std::error_code iterEc;
    for (fs::directory_iterator it(contentRoot, iterEc), end; !iterEc && it != end; it.increment(iterEc)) {
        std::error_code entryEc;
        if (!it->is_directory(entryEc)) continue;

        const fs::path pluginDir = it->path() / L"Binaries" / L"Win64" / L"Plugins" / pluginSubdir;
        std::error_code pluginEc;
        if (!fs::is_directory(pluginDir, pluginEc)) continue;

        std::error_code dllEc;
        for (fs::directory_iterator dit(pluginDir, dllEc), dend; !dllEc && dit != dend; dit.increment(dllEc)) {
            std::error_code fileEc;
            if (!dit->is_regular_file(fileEc)) continue;
            if (!ShouldSkipPluginFile(dit->path())) {
                AddUniqueNormalized(out, dit->path());
            }
        }
    }
}

// v2 shared pipeline: scan roots -> EnabledMods filter -> case-insensitive lexicographic sort ->
// basename dedup (order/filter/dedup mirrors the legacy flat Plugins scan).
std::vector<std::wstring> FindSubdirPluginCandidates(const fs::path& pluginSubdir, HMODULE anchor) {
    // 锚 = Loader 自身模块（version.dll）；由其目录收集扫描根，避免 exe 目录(Win64Steam)导致的根上溯偏差。
    std::vector<std::wstring> out;
    for (const auto& root : CollectScanRoots(anchor)) {
        CollectPluginsUnderContentRootDir(root, pluginSubdir, out);
    }
    FilterByEnabledMods(out, anchor, "plugin");

    std::sort(out.begin(), out.end(), [](const std::wstring& a, const std::wstring& b) {
        // Case-insensitive lexicographic order for stable load order (mirrors legacy flat scan).
        const size_t n = (std::min)(a.size(), b.size());
        for (size_t i = 0; i < n; ++i) {
            const wchar_t ca = towlower(a[i]);
            const wchar_t cb = towlower(b[i]);
            if (ca != cb) return ca < cb;
        }
        return a.size() < b.size();
    });

    DedupPluginsByFilename(out);
    return out;
}

}  // namespace

std::wstring GetModuleDirectory(HMODULE module) {
    wchar_t path[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(module, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    fs::path p(path);
    return p.parent_path().wstring();
}

std::wstring NarrowToWide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), n) != n) return {};
    out.pop_back();
    return out;
}

std::string WideToNarrow(const std::wstring& s) {
    if (s.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), n, nullptr, nullptr) != n) return {};
    out.pop_back();
    return out;
}

std::wstring FindContentRoot(const std::wstring& binariesWin64Dir) {
    fs::path win64(binariesWin64Dir);
    // 兼容 Win64 / Win64Steam 两种目录名（Steam 版 exe 与 Loader 在 Binaries\Win64Steam）。
    const std::wstring win64Name = win64.filename().wstring();
    if (win64Name.size() < 5 || !EqualsIgnoreCase(win64Name.substr(0, 5), L"Win64")) {
        return {};
    }
    fs::path binaries = win64.parent_path();
    if (!EqualsIgnoreCase(binaries.filename().wstring(), L"Binaries")) return {};
    fs::path modRoot = binaries.parent_path();
    if (modRoot.empty()) return {};
    return modRoot.parent_path().wstring();
}

std::vector<std::wstring> CollectScanRoots(HMODULE shellModule) {
    std::vector<std::wstring> roots;
    const std::wstring shellDir = GetModuleDirectory(shellModule);
    AddUnique(roots, FindContentRoot(shellDir));

    const std::wstring docsMods = GetDocumentsModsRoot();
    std::error_code ec;
    if (!docsMods.empty() && fs::is_directory(docsMods, ec)) {
        AddUnique(roots, docsMods);
    }

    const std::wstring workshop = FindWorkshopContentRoot(shellDir);
    if (!workshop.empty()) {
        AddUnique(roots, workshop);
    }

    return roots;
}

std::vector<std::wstring> FindRuntimeCandidates(HMODULE shellModule) {
    std::vector<std::wstring> out;
    const std::wstring shellDir = GetModuleDirectory(shellModule);
    AddUniqueNormalized(out, fs::path(shellDir) / CIV6_DLL_LOADER_RUNTIME_FILENAMEW);

    for (const auto& root : CollectScanRoots(shellModule)) {
        CollectRuntimesUnderContentRoot(root, out);
    }
    FilterByEnabledMods(out, shellModule, "runtime");
    return out;
}

std::vector<std::wstring> FindGlobalPluginCandidates(HMODULE anchor) {
    return FindSubdirPluginCandidates(L"Global", anchor);
}

std::vector<std::wstring> FindGameCorePluginCandidates(HMODULE anchor) {
    return FindSubdirPluginCandidates(L"GameCore", anchor);
}

bool ShouldSkipPluginFile(const fs::path& path) {
    const std::wstring name = path.filename().wstring();
    if (!EqualsIgnoreCase(path.extension().wstring(), L".dll")) return true;
    if (EqualsIgnoreCase(name, CIV6_DLL_LOADER_RUNTIME_FILENAMEW)) return true;
    if (EqualsIgnoreCase(name, L"GameCore_XP2_Shell_FinalRelease.dll")) return true;
    if (EqualsIgnoreCase(name, L"GameCore_XP2_CE_FinalRelease.dll")) return true;
    if (EqualsIgnoreCase(name, L"GameCore_XP2_FinalRelease.dll")) return true;
    return false;
}

}  // namespace ModScan
