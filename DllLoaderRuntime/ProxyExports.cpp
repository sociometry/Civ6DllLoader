// ProxyExports.cpp — Civ6DllLoader v2 version.dll 代理导出。
//
// 来源：E:\WorkSpace\Civ6\version.cpp（用户提供的代理 DLL 代码）。
// 17 条 /EXPORT 转发 pragma 连同 MAKE_EXPORT 宏定义逐字搬入本文件，原注释风格一并保留。
// 与原文件不同：① 本项目只有 x64 配置，原文件里的 SysWOW64 分支已删除（见下方宏）；
// ② DllMain 不在此处（统一在 RuntimeEntry.cpp）。
//
// 作用（见 docs/ARCHITECTURE.md §1.1）：Loader 以 version.dll 名义安装在游戏 exe 目录时，
// 游戏对 version.dll 的静态导入（GetFileVersionInfoExW/SizeExW/W/SizeW 等 4 个 IAT 槽）
// 被转发到系统 System32/SysWOW64 真 version.dll，崩溃日志/版本上报功能原样工作；
// 其余 13 条转发保证对 version API 的间接调用同样落到系统 DLL。

#include "pch.h"

// 本项目只有 x64 配置（Win32 配置已移除）：转发目标固定 System32，
// 原文件里 SysWOW64 那一支不再保留。
#define MAKE_EXPORT(func) "/EXPORT:" func "=\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\version.dll." func
#pragma comment(linker, MAKE_EXPORT("GetFileVersionInfoA"))
#pragma comment(linker, MAKE_EXPORT("GetFileVersionInfoByHandle"))
#pragma comment(linker, MAKE_EXPORT("GetFileVersionInfoExA"))
#pragma comment(linker, MAKE_EXPORT("GetFileVersionInfoExW"))
#pragma comment(linker, MAKE_EXPORT("GetFileVersionInfoSizeA"))
#pragma comment(linker, MAKE_EXPORT("GetFileVersionInfoSizeExA"))
#pragma comment(linker, MAKE_EXPORT("GetFileVersionInfoSizeExW"))
#pragma comment(linker, MAKE_EXPORT("GetFileVersionInfoSizeW"))
#pragma comment(linker, MAKE_EXPORT("GetFileVersionInfoW"))
#pragma comment(linker, MAKE_EXPORT("VerFindFileA"))
#pragma comment(linker, MAKE_EXPORT("VerFindFileW"))
#pragma comment(linker, MAKE_EXPORT("VerInstallFileA"))
#pragma comment(linker, MAKE_EXPORT("VerInstallFileW"))
#pragma comment(linker, MAKE_EXPORT("VerLanguageNameA"))
#pragma comment(linker, MAKE_EXPORT("VerLanguageNameW"))
#pragma comment(linker, MAKE_EXPORT("VerQueryValueA"))
#pragma comment(linker, MAKE_EXPORT("VerQueryValueW"))