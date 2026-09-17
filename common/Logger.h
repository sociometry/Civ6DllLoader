#pragma once
#include <string>

namespace Logger {
    // 日志仅记录诊断信息；进程级异常处理器和崩溃上报由宿主管理。
    void Init(const wchar_t* logFileName = L"civ6_mod_log.txt", bool alsoOutputDebug = true);
    void Shutdown();

    void Log(const char* format, ...);
}
