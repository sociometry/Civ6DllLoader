#include "pch.h"
#include "LoaderUsage.h"

#include "Logger.h"

#include "../common/LoaderProtocol.h"
#include "../third_party/sqlite/sqlite3.h"

#include <algorithm>
#include <filesystem>
#include <shlobj.h>

#pragma comment(lib, "Shell32.lib")

namespace LoaderUsage {
namespace fs = std::filesystem;

namespace {

std::wstring Utf8ToWide(const char* utf8) {
    if (!utf8 || !*utf8) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out.data(), n) != n) return {};
    out.pop_back();
    return out;
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), n, nullptr, nullptr) != n) return {};
    out.pop_back();
    return out;
}

std::wstring ModsSqlitePath() {
    wchar_t* local = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local)) || !local) {
        return {};
    }
    fs::path p = fs::path(local) / L"Firaxis Games" / L"Sid Meier's Civilization VI" / L"Mods.sqlite";
    CoTaskMemFree(local);
    return p.wstring();
}

// 该目录下是否有"插件 DLL"：排除 loader/shell 那几个名字，其余 .dll 都算。
bool DirHasPluginDll(const fs::path& dir) {
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return false;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code fileEc;
        if (!it->is_regular_file(fileEc)) continue;
        const std::wstring name = it->path().filename().wstring();
        if (_wcsicmp(it->path().extension().c_str(), L".dll") != 0) continue;
        if (_wcsicmp(name.c_str(), CIV6_DLL_LOADER_RUNTIME_FILENAMEW) == 0) continue;
        if (_wcsicmp(name.c_str(), L"GameCore_XP2_Shell_FinalRelease.dll") == 0) continue;
        if (_wcsicmp(name.c_str(), L"GameCore_XP2_CE_FinalRelease.dll") == 0) continue;
        if (_wcsicmp(name.c_str(), L"GameCore_XP2_FinalRelease.dll") == 0) continue;
        return true;
    }
    return false;
}

bool UsesThisLoader(const fs::path& modRoot) {
    const fs::path win64 = modRoot / L"Binaries" / L"Win64";
    std::error_code ec;
    if (!fs::is_directory(win64, ec)) return false;
    if (fs::exists(win64 / L"GameCore_XP2_Shell_FinalRelease.dll", ec)) return true;
    if (fs::exists(win64 / CIV6_DLL_LOADER_RUNTIME_FILENAMEW, ec)) return true;
    return DirHasPluginDll(win64 / L"Plugins" / L"Global") ||
           DirHasPluginDll(win64 / L"Plugins" / L"GameCore");
}

bool GetModulePath(HMODULE module, std::wstring& out) {
    constexpr size_t kMaxPathChars = 32768;
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

}  // namespace

std::vector<UserMod> CollectUserMods(const std::wstring& language) {
    std::vector<UserMod> out;

    const std::wstring dbPath = ModsSqlitePath();
    if (dbPath.empty()) {
        Logger::Log("LoaderUsage: LocalAppData unavailable; mod list is empty");
        return out;
    }
    const std::string dbUtf8 = WideToUtf8(dbPath);
    if (dbUtf8.empty()) return out;

    sqlite3* db = nullptr;
    if (sqlite3_open_v2(dbUtf8.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK || !db) {
        Logger::Log("LoaderUsage: cannot open Mods.sqlite (%s)",
            db ? sqlite3_errmsg(db) : "open failed");
        if (db) sqlite3_close(db);
        return out;
    }
    sqlite3_busy_timeout(db, 500);

    // 不再过滤启用集：已禁用的 Mod 也要列出来（UI 标「已禁用」），enabled 由子查询判定。
    //
    // 名字解析：ModProperties.Name 是 .modinfo 的 <Name> 原值，可能就是一个 LOC_ 键。
    // 那个键**不在**运行期 Localization 表里（<LocalizedText> 块只进 Mods.sqlite），
    // 所以用同一张表里的 LocalizedText 自己解析：先当前语言，再退 en_US，最后才是原值。
    // 用相关子查询而不是 JOIN：同一 (ModRowId, Tag, Locale) 理论上有重复行，JOIN 会把
    // 一个 Mod 变成多行，子查询加 LIMIT 1 则不会。
    const char* sql =
        "SELECT sf.Path, mp.Value, "
        "  (SELECT lt.Text FROM LocalizedText lt WHERE lt.ModRowId = m.ModRowId "
        "     AND lt.Tag = mp.Value AND lt.Locale = ?1 LIMIT 1), "
        "  (SELECT lt.Text FROM LocalizedText lt WHERE lt.ModRowId = m.ModRowId "
        "     AND lt.Tag = mp.Value AND lt.Locale = 'en_US' LIMIT 1), "
        "  COALESCE((SELECT 1 FROM ModGroupItems g "
        "              JOIN ModGroups mg ON mg.ModGroupRowId = g.ModGroupRowId "
        "             WHERE mg.Selected = 1 AND g.ModRowId = m.ModRowId AND g.Disabled = 0 "
        "             LIMIT 1), 0) "
        "FROM Mods m "
        "JOIN ScannedFiles sf ON sf.ScannedFileRowId = m.ScannedFileRowId "
        "LEFT JOIN ModProperties mp ON mp.ModRowId = m.ModRowId AND mp.Name = 'Name' "
        "ORDER BY sf.Path;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        Logger::Log("LoaderUsage: query failed (%s)", sqlite3_errmsg(db));
        sqlite3_close(db);
        return out;
    }

    const std::string languageUtf8 = WideToUtf8(language);
    sqlite3_bind_text(stmt, 1, languageUtf8.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* pathUtf8 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (!pathUtf8 || !*pathUtf8) continue;
        const std::wstring modinfoPath = Utf8ToWide(pathUtf8);
        if (modinfoPath.empty()) continue;

        const fs::path modRoot = fs::path(modinfoPath).parent_path();
        if (!UsesThisLoader(modRoot)) continue;

        UserMod mod;
        const char* rawUtf8 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        const char* localizedUtf8 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        const char* englishUtf8 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        if (localizedUtf8 && *localizedUtf8) {
            mod.name = Utf8ToWide(localizedUtf8);
        } else if (englishUtf8 && *englishUtf8) {
            mod.name = Utf8ToWide(englishUtf8);
        } else if (rawUtf8 && *rawUtf8) {
            mod.name = Utf8ToWide(rawUtf8);   // 兜底：原值（可能是 LOC_ 键，Lua 侧还会再试一次）
        }
        mod.enabled = sqlite3_column_int(stmt, 4) != 0;   // 在选中的 ModGroup 里勾选 = 启用
        mod.folder = modRoot.filename().wstring();
        if (mod.name.empty()) mod.name = mod.folder;   // 没有 Name 属性：直接用目录名
        out.push_back(std::move(mod));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    size_t enabledCount = 0;
    for (const auto& mod : out) {
        if (mod.enabled) ++enabledCount;
    }
    Logger::Log("LoaderUsage: %zu mod(s) use this loader (%zu enabled, %zu disabled)",
        out.size(), enabledCount, out.size() - enabledCount);
    for (const auto& mod : out) {
        Logger::Log("LoaderUsage:   %ls (folder=%ls, %s)",
            mod.name.c_str(), mod.folder.c_str(), mod.enabled ? "enabled" : "disabled");
    }
    return out;
}

bool UninstallSelf(HMODULE self, DWORD& outError) {
    outError = 0;

    std::wstring selfPath;
    if (!GetModulePath(self, selfPath)) {
        outError = GetLastError();
        Logger::Log("LoaderUsage: GetModuleFileNameW failed err=%lu", outError);
        return false;
    }

    const fs::path path(selfPath);
    if (_wcsicmp(path.filename().c_str(), CIV6_DLL_LOADER_PROXY_FILENAMEW) != 0) {
        // 开发期直接从 x64\\Release 载入，或从别的名字加载：拒绝，避免把开发产物改名。
        Logger::Log("LoaderUsage: refusing to uninstall: own file is %ls, not %ls",
            path.filename().c_str(), CIV6_DLL_LOADER_PROXY_FILENAMEW);
        outError = 0;
        return false;
    }

    const fs::path oldPath = path.parent_path() / CIV6_DLL_LOADER_PROXY_OLD_FILENAMEW;
    // 残留的旧备份先清掉：它可能来自上次自更新/接管，删失败不阻断 —— 下面的 MoveFile
    // 会给出真正的失败原因（例如备份正被占用）。
    if (!DeleteFileW(oldPath.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
        Logger::Log("LoaderUsage: clearing stale %ls failed err=%lu (continuing)",
            oldPath.c_str(), GetLastError());
    }

    // 本模块正被自己映射着（映像以 FILE_SHARE_DELETE 打开），改名可行；
    // 不重启，本会话继续跑当前已映射的映像。
    if (!MoveFileW(path.c_str(), oldPath.c_str())) {
        outError = GetLastError();
        Logger::Log("LoaderUsage: MoveFileW(%ls -> %ls) failed err=%lu",
            path.c_str(), oldPath.c_str(), outError);
        return false;
    }

    Logger::Log("LoaderUsage: uninstalled %ls -> %ls (next start loads the system %ls)",
        path.c_str(), oldPath.c_str(), CIV6_DLL_LOADER_PROXY_FILENAMEW);
    return true;
}

}  // namespace LoaderUsage
