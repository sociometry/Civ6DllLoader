#include "pch.h"
#include "EnabledMods.h"
#include "Logger.h"
#include "../third_party/sqlite/sqlite3.h"

#include <algorithm>
#include <filesystem>
#include <shlobj.h>

#pragma comment(lib, "Shell32.lib")

namespace EnabledMods {
namespace fs = std::filesystem;

namespace {

std::string ToLowerAscii(std::string s) {
    for (auto& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::wstring Utf8ToWide(const char* utf8) {
    if (!utf8 || !*utf8) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out.data(), n) != n) return {};
    out.pop_back();
    return out;
}

std::wstring GetModsSqlitePath() {
    wchar_t* local = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local)) || !local) {
        return {};
    }
    fs::path p = fs::path(local) / L"Firaxis Games" / L"Sid Meier's Civilization VI" / L"Mods.sqlite";
    CoTaskMemFree(local);
    return p.wstring();
}

}  // namespace

std::wstring NormalizePath(const std::wstring& path) {
    if (path.empty()) return {};
    std::error_code ec;
    fs::path p(path);
    fs::path canon = fs::weakly_canonical(p, ec);
    if (!ec) p = canon;
    std::wstring s = p.wstring();
    for (auto& c : s) {
        if (c == L'/') c = L'\\';
        c = static_cast<wchar_t>(towlower(c));
    }
    // Strip trailing slashes
    while (s.size() > 3 && (s.back() == L'\\' || s.back() == L'/')) s.pop_back();
    return s;
}

bool PathIsUnderRoot(const std::wstring& path, const std::wstring& root) {
    const std::wstring p = NormalizePath(path);
    const std::wstring r = NormalizePath(root);
    if (p.empty() || r.empty()) return false;
    if (p == r) return true;
    if (p.size() <= r.size()) return false;
    if (p.compare(0, r.size(), r) != 0) return false;
    return p[r.size()] == L'\\';
}

std::wstring FindModRoot(const std::wstring& anyPathUnderMod) {
    std::error_code ec;
    fs::path cur = fs::path(anyPathUnderMod);
    if (fs::is_regular_file(cur, ec)) cur = cur.parent_path();

    for (int i = 0; i < 8 && !cur.empty(); ++i) {
        if (fs::is_directory(cur, ec)) {
            for (fs::directory_iterator it(cur, ec), end; !ec && it != end; it.increment(ec)) {
                std::error_code fileEc;
                if (!it->is_regular_file(fileEc)) continue;
                const auto ext = it->path().extension().wstring();
                if (_wcsicmp(ext.c_str(), L".modinfo") == 0) {
                    return NormalizePath(cur.wstring());
                }
            }
        }
        fs::path parent = cur.parent_path();
        if (parent == cur) break;
        cur = parent;
    }
    return {};
}

Snapshot Load() {
    Snapshot snap;
    const std::wstring dbPath = GetModsSqlitePath();
    if (dbPath.empty()) {
        snap.error = "LocalAppData path unavailable";
        return snap;
    }

    std::error_code ec;
    if (!fs::exists(dbPath, ec)) {
        snap.error = "Mods.sqlite not found";
        return snap;
    }

    // Read-only URI so we never take a write lock against the game.
    const int n = WideCharToMultiByte(CP_UTF8, 0, dbPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) {
        snap.error = "Mods.sqlite path UTF-8 conversion failed";
        return snap;
    }
    std::string utf8(static_cast<size_t>(n), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, dbPath.c_str(), -1, utf8.data(), n, nullptr, nullptr) != n) {
        snap.error = "Mods.sqlite path UTF-8 conversion failed";
        return snap;
    }
    utf8.pop_back();
    for (char& ch : utf8) {
        if (ch == '\\') ch = '/';
    }
    const std::string uri = std::string("file:") + utf8 + "?mode=ro";

    sqlite3* db = nullptr;
    const int openRc = sqlite3_open_v2(uri.c_str(), &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr);
    if (openRc != SQLITE_OK || !db) {
        snap.error = db ? sqlite3_errmsg(db) : "sqlite3_open_v2 failed";
        if (db) sqlite3_close(db);
        return snap;
    }

    // Avoid waiting long if the game has the DB locked for a moment.
    sqlite3_busy_timeout(db, 500);

    const char* sql =
        "SELECT m.ModId, sf.Path "
        "FROM ModGroupItems mgi "
        "JOIN ModGroups mg ON mg.ModGroupRowId = mgi.ModGroupRowId AND mg.Selected = 1 "
        "JOIN Mods m ON m.ModRowId = mgi.ModRowId "
        "JOIN ScannedFiles sf ON sf.ScannedFileRowId = m.ScannedFileRowId "
        "WHERE mgi.Disabled = 0;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        snap.error = sqlite3_errmsg(db);
        sqlite3_close(db);
        return snap;
    }

    int stepRc = SQLITE_OK;
    while ((stepRc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* modId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* pathUtf8 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (modId && *modId) {
            snap.modIds.insert(ToLowerAscii(modId));
        }
        if (pathUtf8 && *pathUtf8) {
            std::wstring modinfoPath = Utf8ToWide(pathUtf8);
            fs::path root = fs::path(modinfoPath).parent_path();
            const std::wstring norm = NormalizePath(root.wstring());
            if (!norm.empty()) {
                bool exists = false;
                for (const auto& existing : snap.enabledModRoots) {
                    if (existing == norm) { exists = true; break; }
                }
                if (!exists) snap.enabledModRoots.push_back(norm);
            }
        }
    }

    // 只有 SQLITE_DONE 表示完整读取成功。中途失败时不能把部分启用集
    // 当作有效快照；在 finalize/close 前保存错误，供扫描器走不可用分支。
    if (stepRc != SQLITE_DONE) {
        snap.error = "Mods.sqlite query failed (" + std::to_string(stepRc) + "): " +
            sqlite3_errmsg(db);
        snap.modIds.clear();
        snap.enabledModRoots.clear();
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    snap.ok = (stepRc == SQLITE_DONE);
    return snap;
}

bool AllowsPath(const Snapshot& snap, const std::wstring& path) {
    if (!snap.ok) return false;

    // 只认 Mods.sqlite 返回的精确 mod root，不沿路径向上找 .modinfo 再放宽：
    // 外层 mod 目录即使包着某个启用 root，其自身的其它文件也不因此获得授权。
    for (const auto& root : snap.enabledModRoots) {
        if (PathIsUnderRoot(path, root)) return true;
    }
    return false;
}

}  // namespace EnabledMods
