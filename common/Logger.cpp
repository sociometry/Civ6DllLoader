#include "pch.h"
#include "Logger.h"
#include <windows.h>
#include <shlobj.h>
#include <cstdio>
#include <cstdarg>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#pragma comment(lib, "Shell32.lib")

static FILE* gLogFile = nullptr;
static bool gUseDebugOutput = true;
static std::wstring gLogPath;

// gLogFile / gUseDebugOutput 的互斥：Log 可能来自游戏线程（detour）而 Init/Shutdown 来自
// Loader 工作线程或薄壳 DllMain。无锁时 Init/Shutdown 关掉文件与 Log 写文件会撞成 UAF。
// 函数内 static：避开跨 TU 的动态初始化顺序问题。
static std::mutex& LogMutex() {
    static std::mutex m;
    return m;
}

// Kernel object kept for process lifetime so GameCore unload/reload still sees "already truncated".
static HANDLE gLogSessionMarkers[4] = {};
static int gLogSessionMarkerCount = 0;

// True on the first Init of this log name in this Civ6 process; false on later frontend↔ingame reloads.
static bool ClaimFirstOpenThisProcess(const wchar_t* logFileName) {
    wchar_t safe[96]{};
    size_t o = 0;
    for (const wchar_t* p = logFileName; *p && o + 1 < 80; ++p) {
        const wchar_t c = *p;
        safe[o++] = ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
                     (c >= L'0' && c <= L'9'))
                        ? c
                        : L'_';
    }
    safe[o] = 0;

    wchar_t mapName[160]{};
    swprintf_s(mapName, L"Local\\Civ6DllLoaderLogOnce_%lu_%s", GetCurrentProcessId(), safe);

    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(DWORD), mapName);
    if (!mapping) {
        return true;  // fail-open: truncate rather than grow forever
    }
    const bool first = (GetLastError() != ERROR_ALREADY_EXISTS);
    // Do not CloseHandle — release would drop the marker while GameCore DLL is unloaded.
    if (gLogSessionMarkerCount < 4) {
        gLogSessionMarkers[gLogSessionMarkerCount++] = mapping;
    }
    return first;
}

static std::wstring ResolveLogPath(const wchar_t* logFileName) {
    if (!logFileName || !*logFileName) {
        logFileName = L"civ6_mod_log.txt";
    }
    if (wcschr(logFileName, L':') || (logFileName[0] == L'\\' && logFileName[1] == L'\\')) {
        return logFileName;
    }

    wchar_t* localAppData = nullptr;
    std::wstring dir;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppData)) &&
        localAppData) {
        dir = std::wstring(localAppData) +
            L"\\Firaxis Games\\Sid Meier's Civilization VI\\Logs";
        CoTaskMemFree(localAppData);
    }
    if (dir.empty()) {
        return logFileName;
    }

    SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    return dir + L"\\" + logFileName;
}

void Logger::Init(const wchar_t* logFileName, bool alsoOutputDebug) {
    {
        std::lock_guard<std::mutex> lock(LogMutex());
        if (gLogFile) {
            fclose(gLogFile);
            gLogFile = nullptr;
        }
        gUseDebugOutput = alsoOutputDebug;
    }

    gLogPath = ResolveLogPath(logFileName);
    // Truncate once per Civ6 process; append across frontend↔ingame / GameCore reloads.
    const bool truncate = ClaimFirstOpenThisProcess(logFileName);
    FILE* opened = _wfsopen(gLogPath.c_str(), truncate ? L"w" : L"a", _SH_DENYWR);
    if (opened) {
        setvbuf(opened, nullptr, _IONBF, 0);
        OutputDebugStringW((L"[DllLoader] log -> " + gLogPath + L"\n").c_str());
    } else {
        OutputDebugStringW((L"[DllLoader] failed to open log: " + gLogPath + L"\n").c_str());
    }
    {
        std::lock_guard<std::mutex> lock(LogMutex());
        gLogFile = opened;
    }
    if (opened) {
        Log("=== Logger initialized (pid=%lu mode=%s) ===",
            GetCurrentProcessId(), truncate ? "truncate" : "append");
    } else {
        Log("=== Logger initialized (open failed) ===");
    }
}

void Logger::Shutdown() {
    Log("=== Logger shutting down ===");
    std::lock_guard<std::mutex> lock(LogMutex());
    if (gLogFile) {
        fclose(gLogFile);
        gLogFile = nullptr;
    }
}

void Logger::Log(const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);

    std::ostringstream out;
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    tm local{};
    localtime_s(&local, &t);
    out << "[" << std::put_time(&local, "%H:%M:%S") << "] " << buffer << "\n";

    const std::string line = out.str();
    // 只有这一段碰共享状态：格式化与小字符串都在本线程自己的存储里。
    std::lock_guard<std::mutex> lock(LogMutex());
    if (gLogFile) {
        fputs(line.c_str(), gLogFile);
        fflush(gLogFile);
    }
    if (gUseDebugOutput) OutputDebugStringA(line.c_str());
}
