#pragma once
#include <Windows.h>
#include <shellapi.h>
#include <string>

// 共享的重启助手：拉起当前游戏 exe 并退出本进程。
// 头文件内联实现，两个工程（Shell / Loader）通过各自的 common include 路径直接包含，无需改动 vcxproj。
namespace RestartGame {

// 当前命令行里 argv[0] 之后的部分（原样透传：保留 -dx11/-dx12、Steam 与玩家的自定义参数）。
// GetCommandLineW 的 argv[0] 可能带引号（路径含空格），也可能不带。
inline const wchar_t* CommandLineArguments() {
    const wchar_t* p = GetCommandLineW();
    if (!p) return L"";
    if (*p == L'"') {
        for (++p; *p && *p != L'"'; ++p) {
        }
        if (*p == L'"') ++p;
    } else {
        while (*p && *p != L' ' && *p != L'\t') ++p;
    }
    while (*p == L' ' || *p == L'\t') ++p;
    return p;
}

// 成功时不会返回（TerminateProcess）；失败返回 false（调用方记日志、继续本会话，玩家可手动重启）。
inline bool LaunchAndExit() {
    wchar_t exePath[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return false;
    }

    // ShellExecuteW("open") 只是"以 shell 的 open 动作执行这个 exe"，对 .exe 而言与
    // CreateProcessW 同类，并不经过 Steam 启动协议（steam://rungameid/... 才会）。
    // 它能工作的真实原因是**继承了本进程已有的 Steam 环境变量**（SteamAppId / SteamClientLaunch
    // 等，由当初拉起游戏的那次 Steam 启动设置），steam_api64 因此能完成握手；
    // CreateProcessW 同样继承这些变量，这里没有"必须走 shell"的硬要求。
    // lpParameters 必须带上原命令行 argv[0] 之后的部分：重启后的进程要和原来同参，
    // 否则 -dx11/-dx12、Steam 或玩家自定义参数会在重启时丢掉（等于换了一个会话）。
    const HINSTANCE r = ShellExecuteW(nullptr, L"open", exePath, CommandLineArguments(),
        nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<INT_PTR>(r) <= 32) {
        return false;  // <=32 表示错误码
    }

    // 用 TerminateProcess 而非 ExitProcess：两条调用路径都在别人的加载流程里——
    // LoaderUpdate 那条跑在阶段 A 的一次性工作线程、游戏仍在早期初始化；薄壳那条跑在引擎的
    // GameCore 加载线程（正处在 LoadLibrary 官方 GameCore 之后）。主线程可能仍持有 loader lock，
    // 或 steam_api64 等 DLL 的 DLL_PROCESS_DETACH 回调阻塞 → ExitProcess 会挂起、进程残留后台。
    // TerminateProcess 直接终止，跳过 loader lock 与 DETACH 回调；此处无需要清理的用户状态。
    TerminateProcess(GetCurrentProcess(), 0);
    return true;  // 不可达
}

}  // namespace RestartGame
