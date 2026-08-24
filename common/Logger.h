#pragma once
#include <string>

namespace Logger {
    void Init(const wchar_t* logFileName = L"civ6_mod_log.txt", bool alsoOutputDebug = true, bool enableConsole = false);
    void Shutdown();

    void Log(const char* format, ...);
    void LogRaw(const char* message);
    void LogCrash(const char* context = "Unknown crash");

    void InstallGlobalExceptionHandler();
    void RestoreGlobalExceptionHandler();
}
