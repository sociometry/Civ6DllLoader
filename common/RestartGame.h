#pragma once
#include <Windows.h>
#include <shellapi.h>
#include <string>

// 共享的重启助手：拉起当前游戏 exe 并退出本进程。
// 头文件内联实现，两个工程（Shell / Loader）通过各自的 common include 路径直接包含，无需改动 vcxproj。
namespace RestartGame {

// 成功时不会返回（TerminateProcess）；失败返回 false（调用方记日志、继续本会话，玩家可手动重启）。
inline bool LaunchAndExit() {
    wchar_t exePath[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return false;
    }

    // 走 ShellExecuteW("open")：对 Steam 游戏，这等价于双击快捷方式，会经过 Steam 的启动协议
    // （建立 overlay、准备 steamclient 握手）。不能用 CreateProcessW 直接拉 exe——
    // 那样绕过了 Steam 启动链路，steam_api64.dll 的 SteamAPI_Init 会永久等待握手，游戏卡在
    // 启动早期（无窗口、无日志、CPU 忙等），就是我们观察到的"后台残留"假象。
    const HINSTANCE r = ShellExecuteW(nullptr, L"open", exePath, nullptr, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(r) <= 32) {
        return false;  // <=32 表示错误码
    }

    // 用 TerminateProcess 而非 ExitProcess：本调用发生在 Loader 工作线程、游戏仍在早期初始化，
    // 主线程可能持有 loader lock（仍在加载 DLL/跑 DllMain），或 steam_api64 等 DLL 的
    // DLL_PROCESS_DETACH 回调阻塞 → ExitProcess 会挂起、进程残留在后台。
    // TerminateProcess 直接终止，跳过 loader lock 与 DETACH 回调；此处无需要清理的用户状态。
    TerminateProcess(GetCurrentProcess(), 0);
    return true;  // 不可达
}

}  // namespace RestartGame
