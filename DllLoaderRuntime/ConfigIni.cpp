#include "pch.h"
#include "ConfigIni.h"

#include "../common/Logger.h"
#include "../common/ModScan.h"   // GetModuleDirectory

#include <Windows.h>
#include <string>

namespace {

constexpr wchar_t kSubDir[]   = L"Civ6DllLoader";
constexpr wchar_t kFileName[] = L"config.ini";
constexpr wchar_t kSection[]  = L"Loader";
constexpr wchar_t kKeyGlobal[]   = L"ENABLE_GLOBAL";
constexpr wchar_t kKeyGameCore[] = L"ENABLE_GAMECORE";
constexpr wchar_t kKeyDebugLog[] = L"ENABLE_DEBUG_LOG";
constexpr wchar_t kKeyProfiler[] = L"ENABLE_PROFILER";

// 值解析：只认 true/false（大小写不敏感）与 1/0。
// 键缺失、空串、其它任何写法一律 false —— fail-closed：宁可插件不加载，
// 也不让一个写错的 ini 意外启用功能。
bool ParseFlagValue(const wchar_t* raw) {
    if (raw == nullptr || *raw == L'\0') return false;
    if (wcscmp(raw, L"1") == 0) return true;
    if (wcscmp(raw, L"0") == 0) return false;
    if (_wcsicmp(raw, L"true") == 0) return true;
    if (_wcsicmp(raw, L"false") == 0) return false;
    Logger::Log("ConfigIni: unrecognized flag value \"%ls\", treated as false", raw);
    return false;
}

// 读一个开关。GetPrivateProfileStringW 而非 GetPrivateProfileIntW：
// 后者的返回值是整数解析结果，"true" 会被读成 0，无法表达布尔。
bool ReadFlag(const wchar_t* key, const wchar_t* path) {
    if (path == nullptr || *path == L'\0') return false;
    wchar_t buf[32]{};
    const DWORD n = GetPrivateProfileStringW(kSection, key, L"", buf,
        static_cast<DWORD>(sizeof(buf) / sizeof(buf[0])), path);
    if (n == 0) return false;   // 段/键缺失
    return ParseFlagValue(buf);
}

bool WriteFlag(const wchar_t* key, bool enabled, const wchar_t* path) {
    if (path == nullptr || *path == L'\0') return false;
    const wchar_t* value = enabled ? L"true" : L"false";
    const BOOL ok = WritePrivateProfileStringW(kSection, key, value, path);
    if (!ok) {
        Logger::Log("ConfigIni: WritePrivateProfileStringW failed for %ls (err=%lu)",
            key, GetLastError());
    }
    return ok != FALSE;
}

// exe 目录在进程内恒定，缓存一次。
const std::wstring& CachedExeDir() {
    static const std::wstring dir = ModScan::GetModuleDirectory(nullptr);
    return dir;
}

const std::wstring& CachedPath() {
    static const std::wstring path = [] {
        const std::wstring& dir = CachedExeDir();
        if (dir.empty()) {
            Logger::Log("ConfigIni: GetModuleDirectory failed; config.ini unavailable");
            return std::wstring{};
        }
        return dir + L"\\" + kSubDir + L"\\" + kFileName;
    }();
    return path;
}

}  // namespace

namespace CfgIni {

std::wstring ConfigPath() {
    return CachedPath();
}

bool EnsureExists() {
    const std::wstring& path = CachedPath();
    if (path.empty()) return false;

    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        // 已存在：不动用户内容。缺失的键按 fail-closed 读成 false，
        // 这里【不】自动补齐 —— 补了就等于把"删掉键"这个动作静默解释成"启用"。
        // DEBUG_LOG 由 ReadDebugLogEnabled 缓存，这里直接调一次把值算出来，
        // 让首行日志就能看到它 —— 排查问题时"日志为什么这么少"往往就是它没开。
        const bool debugLog = ReadDebugLogEnabled();
        const bool profiler = ReadProfilerEnabled();
        Logger::Log("ConfigIni: existing %ls (ENABLE_GLOBAL=%d ENABLE_GAMECORE=%d "
            "ENABLE_DEBUG_LOG=%d ENABLE_PROFILER=%d)",
            path.c_str(), ReadGlobalEnabled() ? 1 : 0, ReadGameCoreEnabled() ? 1 : 0,
            debugLog ? 1 : 0, profiler ? 1 : 0);
        return true;
    }

    // 目录先于文件：ExtractResources 通常已建过，但 ini 可能被单独删掉。
    const std::wstring dir = CachedExeDir() + L"\\" + kSubDir;
    CreateDirectoryW(dir.c_str(), nullptr);   // 已存在 -> ERROR_ALREADY_EXISTS，忽略

    // 新建：两个键写 true（装好即启用）。之后若用户删掉某个键，
    // 再读就是 false（fail-closed），与"新建默认 true"并不矛盾：
    // 前者是文件缺失时的初始值，后者是键缺失时的判定规则。
    const bool okGlobal = WriteFlag(kKeyGlobal, true, path.c_str());
    const bool okGameCore = WriteFlag(kKeyGameCore, true, path.c_str());
    // ENABLE_DEBUG_LOG / ENABLE_PROFILER 默认 false，但照样写进新建的 ini：
    // 让它们作为"有这个键、可以改"的提示出现在文件里（默认关闭，不影响日志量与性能）。
    const bool okDebug = WriteFlag(kKeyDebugLog, false, path.c_str());
    const bool okProf = WriteFlag(kKeyProfiler, false, path.c_str());
    Logger::Log("ConfigIni: created %ls (ENABLE_GLOBAL=true, ENABLE_GAMECORE=true, "
        "ENABLE_DEBUG_LOG=false, ENABLE_PROFILER=false) write=%d/%d/%d/%d",
        path.c_str(), okGlobal ? 1 : 0, okGameCore ? 1 : 0, okDebug ? 1 : 0, okProf ? 1 : 0);
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool ReadGlobalEnabled() {
    return ReadFlag(kKeyGlobal, CachedPath().c_str());
}

bool ReadGameCoreEnabled() {
    return ReadFlag(kKeyGameCore, CachedPath().c_str());
}

bool WriteGlobalEnabled(bool enabled) {
    const bool ok = WriteFlag(kKeyGlobal, enabled, CachedPath().c_str());
    Logger::Log("ConfigIni: ENABLE_GLOBAL <- %s (%s)", enabled ? "true" : "false",
        ok ? "ok" : "FAILED");
    return ok;
}

bool WriteGameCoreEnabled(bool enabled) {
    const bool ok = WriteFlag(kKeyGameCore, enabled, CachedPath().c_str());
    Logger::Log("ConfigIni: ENABLE_GAMECORE <- %s (%s)", enabled ? "true" : "false",
        ok ? "ok" : "FAILED");
    return ok;
}

bool ReadDebugLogEnabled() {
    // 缓存一次：这个键只给人手改、改完要重启，不必每次打日志都读盘。
    // 而它的读点全在高频路径上（逐条日志的判断），读盘代价不能忽略。
    static const bool enabled = ReadFlag(kKeyDebugLog, CachedPath().c_str());
    return enabled;
}

bool ReadProfilerEnabled() {
    // 与 ReadDebugLogEnabled 同样的缓存理由：
    // Profiler::Begin 可能在每帧 / 每次回调里被调。
    static const bool enabled = ReadFlag(kKeyProfiler, CachedPath().c_str());
    return enabled;
}

}  // namespace CfgIni
