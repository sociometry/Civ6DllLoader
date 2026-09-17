#include "pch.h"
#include "ModScan.h"
#include "EnabledMods.h"
#include "LoaderProtocol.h"
#include "Logger.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <set>
#include <shlobj.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")   // RegGetValueW（Steam 安装路径）

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

// ---- Steam 库发现（注册表 + libraryfolders.vdf）----
// 为什么需要它：FindWorkshopContentRoot 是从锚目录向上找 steamapps，只有锚在游戏安装目录
// 附近时才命中。薄壳的锚是 Mod 自己的 Binaries\Win64（Mod 常在 Documents\...\Mods），
// 从那里上溯永远碰不到 steamapps —— 于是"三个内容根"在首次补装时只剩两个。
// 这里改成问 Steam 自己：先读安装路径（HKCU\Software\Valve\Steam\SteamPath，退回
// HKLM WOW6432Node\...\InstallPath），再扫 <steam>\steamapps\libraryfolders.vdf 里的
// 每个库根，逐个拼 <lib>\steamapps\workshop\content\289070。
std::wstring ReadRegistryString(HKEY root, const wchar_t* subKey, const wchar_t* value) {
    wchar_t buf[1024] = {};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    if (RegGetValueW(root, subKey, value, RRF_RT_REG_SZ, &type, buf, &size) != ERROR_SUCCESS) {
        return {};
    }
    return std::wstring(buf);
}

std::wstring FindSteamInstallPath() {
    std::wstring path = ReadRegistryString(HKEY_CURRENT_USER, L"Software\\Valve\\Steam", L"SteamPath");
    if (!path.empty()) return path;
    path = ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Valve\\Steam", L"InstallPath");
    if (!path.empty()) return path;
    return ReadRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Valve\\Steam", L"InstallPath");
}

// <libraryRoot> 下的 Workshop 内容根（不存在或不是目录则返回空）。
std::wstring WorkshopRootUnder(const std::wstring& libraryRoot) {
    if (libraryRoot.empty()) return {};
    std::error_code ec;
    const fs::path candidate =
        fs::path(libraryRoot) / L"steamapps" / L"workshop" / L"content" / kCiv6SteamAppId;
    return fs::is_directory(candidate, ec) ? candidate.wstring() : std::wstring{};
}

// 从 <steam>\steamapps\libraryfolders.vdf 收集所有库根（只认 "path" 键；写入值里的
// 反斜杠是 vdf 转义，这里做最小反转义）。文本扫描，不引 JSON/vdf 依赖。
void CollectLibraryRootsFromVdf(const std::wstring& steamPath, std::vector<std::wstring>& out) {
    if (steamPath.empty()) return;
    std::ifstream in(fs::path(steamPath) / L"steamapps" / L"libraryfolders.vdf", std::ios::binary);
    if (!in) return;
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const std::string key = "\"path\"";
    size_t pos = 0;
    while ((pos = text.find(key, pos)) != std::string::npos) {
        pos += key.size();
        while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\t')) ++pos;
        if (pos >= text.size() || text[pos] != '"') continue;
        const size_t end = text.find('"', pos + 1);
        if (end == std::string::npos) break;
        std::string value;
        value.reserve(end - pos - 1);
        for (size_t i = pos + 1; i < end; ++i) {
            if (text[i] == '\\' && i + 1 < end) ++i;   // 反转义 \ 与 \"
            value.push_back(text[i]);
        }
        pos = end + 1;
        if (value.empty()) continue;
        const std::wstring wide = NarrowToWide(value);
        if (!wide.empty()) AddUnique(out, wide);
    }
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
            // 保留的是大小写不敏感字典序里的第一个（扫描结果在去重前已按该顺序排好）
            Logger::Log("Skipping duplicate plugin basename (kept the lexicographically first path): %s",
                narrow.c_str());
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
                || EnabledMods::PathIsUnderRoot(path, shellDir);
            if (keep) {
                localOnly.push_back(path);
            } else {
                Logger::Log("Skipping %s (no EnabledMods DB): %s", what, WideToNarrow(path).c_str());
            }
        }
        paths.swap(localOnly);
        return;
    }

    Logger::Log("EnabledMods: %zu root(s) for %s filter",
        snap.enabledModRoots.size(), what);

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
// (Plugins\Global\ and Plugins\GameCore\ are subdirectories of each mod's Plugins\ folder).
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
// basename dedup (stable order, case-insensitive sort, dedup by filename).
std::vector<std::wstring> FindSubdirPluginCandidates(const fs::path& pluginSubdir, HMODULE anchor) {
    // 锚 = Loader 自身模块（version.dll）；由其目录收集扫描根，避免 exe 目录(Win64Steam)导致的根上溯偏差。
    std::vector<std::wstring> out;
    for (const auto& root : CollectScanRoots(anchor)) {
        CollectPluginsUnderContentRootDir(root, pluginSubdir, out);
    }
    FilterByEnabledMods(out, anchor, "plugin");

    std::sort(out.begin(), out.end(), [](const std::wstring& a, const std::wstring& b) {
        // Case-insensitive lexicographic order for stable load order.
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

    // Workshop 内容根：① 从锚目录上溯（锚就在游戏安装树里时最快命中）；② 注册表拿 Steam
    // 安装路径 + libraryfolders.vdf 里的每个库根（锚在 Documents\Mods 时只有这条能命中，
    // 见 FindSteamInstallPath 的说明）。
    AddUnique(roots, FindWorkshopContentRoot(shellDir));
    const std::wstring steamPath = FindSteamInstallPath();
    if (!steamPath.empty()) {
        AddUnique(roots, WorkshopRootUnder(steamPath));
        std::vector<std::wstring> libraries;
        CollectLibraryRootsFromVdf(steamPath, libraries);
        for (const auto& library : libraries) {
            AddUnique(roots, WorkshopRootUnder(library));
        }
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
    // 故意【不】过 FilterByEnabledMods：安装/自更新 loader 只看版本（RC 资源 105），
    // 与"插件只从启用的 Mod 加载"是两条独立的通路，候选所在 Mod 是否启用不影响版本选举。
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
