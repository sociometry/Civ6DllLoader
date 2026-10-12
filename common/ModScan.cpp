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

// 定义在文件末尾（需要本文件的各种路径辅助）。static = 本文件内部链接；
// 声明与定义都在 ModScan 作用域，避免与匿名命名空间里的同名实体混淆。
static bool ShouldSkipPluginFile(const fs::path& path);
static std::vector<std::wstring> CollectScanRoots();

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

// 扫描根去重前必须先归一化：注册表 SteamPath 可能返回正斜杠（"d:/steam"），
// 而 libraryfolders.vdf 里写的是 "D:\\Steam" —— 同一目录两种写法，AddUnique 只做
// 大小写不敏感比较，会把它当成两个根、把同一棵树扫两遍。走项目统一的 NormalizePath
// （小写 + / -> \ + 去尾分隔符），不再另写一份"看起来一样"的实现。
void AddRootUnique(std::vector<std::wstring>& roots, const std::wstring& path) {
    const std::wstring norm = EnabledMods::NormalizePath(path);
    if (norm.empty()) return;
    AddUnique(roots, norm);
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

// Walk up from the exe dir looking for steamapps/workshop/content/289070.
std::wstring FindWorkshopContentRoot(const std::wstring& exeDir) {
    std::error_code ec;
    fs::path cur(exeDir);
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
// 为什么需要它：FindWorkshopContentRoot 是从 exe 目录向上找 steamapps，只有游戏装在
// 该库下时才命中。若游戏装在别的库、或上溯 12 层内碰不到 steamapps，就只剩这条路。
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

// Keep only mods recorded as enabled in Mods.sqlite.
// 授权判据只有一条：路径落在 Mods.sqlite 返回的某个精确 mod root 之下（AllowsPath）。
// 【没有】任何"锚本地豁免"：早先的 shellLocal 把"文件在不在锚模块目录下"当成了授权条件，
// 而插件的锚是 runtime 自己（装好即 version.dll，在游戏 exe 目录），等于无条件把整个
// 游戏 exe 目录加进白名单、与玩家启用了哪些 Mod 无关。见 ARCHITECTURE §3.1。
void FilterByEnabledMods(std::vector<std::wstring>& paths, const char* what) {
    if (paths.empty()) return;

    const EnabledMods::Snapshot snap = EnabledMods::Load();
    if (!snap.ok) {
        // 拿不到启用集 = 没有任何 Mod 被确认启用。失败即关闭：一个都不加载。
        Logger::Log("WARN EnabledMods unavailable (%s); loading no %s",
            snap.error.empty() ? "unknown" : snap.error.c_str(), what);
        paths.clear();
        return;
    }

    Logger::Log("EnabledMods: %zu root(s) for %s filter",
        snap.enabledModRoots.size(), what);

    std::vector<std::wstring> filtered;
    filtered.reserve(paths.size());
    for (const auto& path : paths) {
        if (EnabledMods::AllowsPath(snap, path)) {
            filtered.push_back(path);
            continue;
        }
        Logger::Log("Skipping disabled/absent mod %s: %s", what, WideToNarrow(path).c_str());
    }
    paths.swap(filtered);
}

}  // namespace

namespace {

// Collect <mod>/Binaries/Win64/Plugins/<pluginSubdir>/*.dll candidates under one content root
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

// Shared pipeline (FindGlobalPluginCandidates / FindGameCorePluginCandidates 共用这条):
// scan roots -> EnabledMods filter -> case-insensitive lexicographic sort ->
// basename dedup (stable order, case-insensitive sort, dedup by filename).
std::vector<std::wstring> FindSubdirPluginCandidates(const fs::path& pluginSubdir) {
    std::vector<std::wstring> out;
    for (const auto& root : CollectScanRoots()) {
        CollectPluginsUnderContentRootDir(root, pluginSubdir, out);
    }
    FilterByEnabledMods(out, "plugin");

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

// 仅本文件使用（FindRuntimeCandidates / FindSubdirPluginCandidates 调用）。
static std::vector<std::wstring> CollectScanRoots() {
    std::vector<std::wstring> roots;

    // Documents\My Games\...\Mods：玩家自装 Mod 的主位置。
    const std::wstring docsMods = GetDocumentsModsRoot();
    std::error_code ec;
    if (!docsMods.empty() && fs::is_directory(docsMods, ec)) {
        AddRootUnique(roots, docsMods);
    }

    // Workshop 内容根：① 从 exe 目录上溯（exe 在游戏安装树里，游戏装在哪个库就直接命中）；
    // ② 注册表拿 Steam 安装路径 + libraryfolders.vdf 里的每个库根（上溯碰不到 steamapps 时靠这条）。
    const std::wstring exeDir = GetModuleDirectory(nullptr);
    AddRootUnique(roots, FindWorkshopContentRoot(exeDir));
    const std::wstring steamPath = FindSteamInstallPath();
    if (!steamPath.empty()) {
        AddRootUnique(roots, WorkshopRootUnder(steamPath));
        std::vector<std::wstring> libraries;
        CollectLibraryRootsFromVdf(steamPath, libraries);
        for (const auto& library : libraries) {
            AddRootUnique(roots, WorkshopRootUnder(library));
        }
    }

    // 【不】加"游戏安装根"作为内容根：那不是模组容器。游戏自己
    // （Mods.sqlite 的 ScannedFiles）记录的安装内模组根是 <gameRoot>\DLC\<名> 与
    // <gameRoot>\Base\Assets\Scenarios\<名>，而 <gameRoot> 的直接子目录
    // （Base / CTP / DLC / Debug / LaunchPad）没有一个含 Binaries\Win64 —— 实测该根
    // 的候选取集恒为空。要覆盖官方 DLC 得用 <gameRoot>\DLC 当根；但那里是官方内容，
    // 不是 loader/插件的分发位置，故不扫。详见 ARCHITECTURE §3.1。
    return roots;
}

std::vector<std::wstring> FindRuntimeCandidates() {
    std::vector<std::wstring> out;
    // 不额外探测"自己旁边那一份"：薄壳只能在 <内容根>\<Mod>\Binaries\Win64\ 里被引擎加载，
    // 而那正是下面根扫描枚举的形状，所以自身探测恒为重复项（实测游戏 Mods.sqlite 记录的
    // 133 个 .modinfo 无一嵌套，全部是内容根的直接子目录）。
    for (const auto& root : CollectScanRoots()) {
        CollectRuntimesUnderContentRoot(root, out);
    }
    // 故意【不】过 FilterByEnabledMods：安装/自更新 loader 只看版本（RC 资源 105），
    // 与"插件只从启用的 Mod 加载"是两条独立的通路，候选所在 Mod 是否启用不影响版本选举。
    return out;
}

std::vector<std::wstring> FindGlobalPluginCandidates() {
    return FindSubdirPluginCandidates(L"Global");
}

std::vector<std::wstring> FindGameCorePluginCandidates() {
    return FindSubdirPluginCandidates(L"GameCore");
}

static bool ShouldSkipPluginFile(const fs::path& path) {
    const std::wstring name = path.filename().wstring();
    if (!EqualsIgnoreCase(path.extension().wstring(), L".dll")) return true;
    if (EqualsIgnoreCase(name, CIV6_DLL_LOADER_RUNTIME_FILENAMEW)) return true;
    if (EqualsIgnoreCase(name, L"GameCore_XP2_Shell_FinalRelease.dll")) return true;
    if (EqualsIgnoreCase(name, L"GameCore_XP2_CE_FinalRelease.dll")) return true;
    if (EqualsIgnoreCase(name, L"GameCore_XP2_FinalRelease.dll")) return true;
    return false;
}

}  // namespace ModScan
