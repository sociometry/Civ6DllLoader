#include "Logger.h"
#include <windows.h>
#include <shlobj.h>
#include <cstdio>
#include <cstdarg>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Shell32.lib")

static FILE* gLogFile = nullptr;
static bool gUseDebugOutput = true;
static std::wstring gLogPath;
static LPTOP_LEVEL_EXCEPTION_FILTER gPreviousExceptionFilter = nullptr;
static bool gExceptionFilterInstalled = false;

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

void Logger::Init(const wchar_t* logFileName, bool alsoOutputDebug, bool enableConsole) {
    if (gLogFile) {
        fclose(gLogFile);
        gLogFile = nullptr;
    }

    gUseDebugOutput = alsoOutputDebug;
    if (enableConsole) {
        AllocConsole();
        freopen_s(&gLogFile, "CONOUT$", "w", stdout);
        freopen_s(&gLogFile, "CONOUT$", "w", stderr);
        gLogPath.clear();
    } else {
        gLogPath = ResolveLogPath(logFileName);
        // Truncate once per Civ6 process; append across frontend↔ingame / GameCore reloads.
        const bool truncate = ClaimFirstOpenThisProcess(logFileName);
        gLogFile = _wfsopen(gLogPath.c_str(), truncate ? L"w" : L"a", _SH_DENYWR);
        if (gLogFile) {
            setvbuf(gLogFile, nullptr, _IONBF, 0);
            OutputDebugStringW((L"[DllLoader] log -> " + gLogPath + L"\n").c_str());
            Log("=== Logger initialized (pid=%lu mode=%s) ===",
                GetCurrentProcessId(), truncate ? "truncate" : "append");
        } else {
            OutputDebugStringW((L"[DllLoader] failed to open log: " + gLogPath + L"\n").c_str());
            Log("=== Logger initialized (open failed) ===");
        }
        return;
    }
    Log("=== Logger initialized ===");
}

void Logger::Shutdown() {
    Log("=== Logger shutting down ===");
    if (gLogFile) {
        fclose(gLogFile);
        gLogFile = nullptr;
    }
    FreeConsole();
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
    if (gLogFile) {
        fputs(line.c_str(), gLogFile);
        fflush(gLogFile);
    }
    if (gUseDebugOutput) OutputDebugStringA(line.c_str());
}

void Logger::LogRaw(const char* msg) {
    if (gLogFile) {
        fputs(msg, gLogFile);
        fputc('\n', gLogFile);
        fflush(gLogFile);
    }
    if (gUseDebugOutput) OutputDebugStringA(msg);
}

LONG WINAPI GlobalCrashHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    Logger::Log("Unhandled exception occurred! Code: 0x%08X", ExceptionInfo->ExceptionRecord->ExceptionCode);
    Logger::Log("EIP/RIP: 0x%p", ExceptionInfo->ExceptionRecord->ExceptionAddress);

    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t filename[MAX_PATH]{};
    swprintf_s(filename, L"Civ6_Crash_%04d%02d%02d_%02d%02d%02d.dmp",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);

    const std::wstring dumpPath = ResolveLogPath(filename);
    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mdei = { GetCurrentThreadId(), ExceptionInfo, TRUE };
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &mdei, NULL, NULL);
        Logger::Log("Minidump written");
        CloseHandle(hFile);
    } else {
        Logger::Log("Failed to create dump file: %d", GetLastError());
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

void Logger::InstallGlobalExceptionHandler() {
    if (gExceptionFilterInstalled) return;
    gPreviousExceptionFilter = SetUnhandledExceptionFilter(GlobalCrashHandler);
    gExceptionFilterInstalled = true;
}

void Logger::RestoreGlobalExceptionHandler() {
    if (!gExceptionFilterInstalled) return;
    SetUnhandledExceptionFilter(gPreviousExceptionFilter);
    gPreviousExceptionFilter = nullptr;
    gExceptionFilterInstalled = false;
}

void Logger::LogCrash(const char* context) {
    Logger::Log("CRASH in context: %s", context ? context : "unknown");
}
