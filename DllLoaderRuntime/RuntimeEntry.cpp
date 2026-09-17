// RuntimeEntry.cpp — Civ6DllLoader v2 Loader 入口（DllLoaderRuntime 工程产物，
// 安装形态 = 游戏 exe 目录的 version.dll 代理）。
//
// v2 架构：
//   - DllMain：DisableThreadLibraryCalls → 休眠检测（自身父目录 == 游戏 exe 目录，且宿主进程是
//     CivilizationVI*.exe）通过才 spawn 工作线程；其它任何加载场合（别的进程加载了这份
//     version.dll、或开发中直接 LoadLibrary 本模块）→ 直接返回 TRUE，什么都不做。
//   - WorkerMain（阶段 A）：LoaderCore::InitEarly → LoaderHooks::InstallAll
//     → LoaderUpdate::CheckAndApplyUpdate → LoadPluginsOf(Global) → 线程退出。
//   - 阶段 B（LoadDLL detour）在游戏线程 detour 内同步执行（LoaderCore::InitializeGameCorePhase）。
//   - Global 插件仅启动时加载一次：运行期不再卸载/重装、也不再被 park；
//     主菜单开关 mod 需要重启才生效。

#include "pch.h"

#include <cwctype>
#include <string>

#include "../common/LoaderProtocol.h"
#include "LoaderCore.h"
#include "LoaderHooks.h"
#include "LoaderUpdate.h"
#include "../common/Logger.h"
#include "Runtime.h"
#include "PdataMatch.h"
#include "ImageAddress.h"
#include "UiInject.h"

namespace {

// ---- 工作线程共享状态（匿名命名空间，避免与 LoaderCore 命名空间符号冲突）----

HMODULE g_runtimeModule = nullptr;               // 本模块句柄（DllMain 休眠检测通过后设置）

// 取模块所在目录（去掉文件名部分）。失败返回空串。
std::wstring ModuleDirectory(HMODULE hModule) {
    std::wstring buf(512, L'\0');
    for (;;) {
        DWORD len = GetModuleFileNameW(hModule, buf.data(), static_cast<DWORD>(buf.size()));
        if (len == 0) return {};
        if (len < buf.size()) { buf.resize(len); break; }
        buf.resize(buf.size() * 2);
    }
    std::wstring::size_type slash = buf.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return {};
    buf.resize(slash);
    return buf;
}

// 规范化：统一小写、去尾部斜杠（休眠检测用，大小写不敏感比较）。
std::wstring NormalizeDir(std::wstring path) {
    for (wchar_t& ch : path) {
        ch = static_cast<wchar_t>(towlower(ch));
    }
    while (path.size() > 1 && (path.back() == L'\\' || path.back() == L'/')) {
        path.pop_back();
    }
    return path;
}

// 进程 exe 的文件名是否形如 CivilizationVI*.exe（DX11/DX12 两个变体都命中）。
// 用"前缀 + 后缀"而不是精确两名白名单，是为了兼容将来的 CivilizatonVI_*.exe 变体。
// DllMain 早调用：只用 kernel32 + 栈/小串，不分配内存、不读文件。
bool ProcessExeIsGame() {
    wchar_t path[MAX_PATH]{};
    const DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return false;
    std::wstring name(path, len);
    const std::wstring::size_type slash = name.find_last_of(L"\\/");
    if (slash != std::wstring::npos) name.erase(0, slash + 1);
    for (wchar_t& ch : name) ch = static_cast<wchar_t>(towlower(ch));

    const std::wstring prefix = L"civilizationvi";
    const std::wstring ext = L".exe";
    if (name.size() < prefix.size() + ext.size()) return false;
    if (name.compare(0, prefix.size(), prefix) != 0) return false;
    return name.compare(name.size() - ext.size(), ext.size(), ext) == 0;
}

// 休眠检测：**两个条件同时成立**才启动 Loader：
//   1) 自身父目录 == 进程 exe 父目录（version.dll 代理安装形态）；
//   2) 拉起本模块的进程就是游戏本体（CivilizationVI*.exe）。
// 只比目录的话，任何从游戏 exe 目录加载这个 version.dll 的进程（崩溃上报器、第三方工具、
// 覆盖层等）都会把 Loader 连同 Global 插件拉进自己的地址空间。
// whyOut 回填失败原因（静态字面量，休眠留痕用），成功时为 nullptr；不想知道就传 nullptr。
bool LoadedFromExeDirectory(HMODULE hModule, const wchar_t** whyOut) {
    if (NormalizeDir(ModuleDirectory(hModule)) != NormalizeDir(ModuleDirectory(nullptr))) {
        if (whyOut) *whyOut = L"module dir != host exe dir (not a version.dll proxy install)";
        return false;
    }
    if (!ProcessExeIsGame()) {
        if (whyOut) *whyOut = L"host exe is not CivilizationVI*.exe";
        return false;
    }
    if (whyOut) *whyOut = nullptr;
    return true;
}

// 阶段 A：跑完启动序列即返回的一次性工作线程（没有事件循环，之后一切由 detour 驱动）。
// Global 插件仅在此加载一次；之后主菜单开关 mod 只在下次启动生效。
DWORD WINAPI WorkerMain(LPVOID) {
    // 1) 基础初始化：Logger / PdataMatch / MinHook
    LoaderCore::InitEarly();

    // 1.5) 释放内嵌 FrontEnd UI 资源到 exe 目录的 Civ6DllLoader 子目录
    UiInject::ExtractResources();

    // 2) hook 安装（LoadDLL / UnloadDLL；失败静默降级）
    if (!LoaderHooks::InstallAll()) {
        Logger::Log("hook 安装降级");
    }

    // 2.5) FrontEnd UI 注入 hook（失败静默降级）
    if (!UiInject::Install()) {
        Logger::Log("FrontEnd UI 注入 hook 降级");
    }

    // 3) 自更新检查
    LoaderUpdate::CheckAndApplyUpdate();

    // 4) 阶段 A：加载启用 Mod 的 Global 插件（仅此一次；运行期不重查，开关 mod 重启生效）
    LoaderCore::LoadPluginsOf(LoaderCore::PluginCategory::Global);

    return 0;
}

}  // namespace

// ---- LoaderCore 阶段 A 基础初始化（本文件实现）----
HMODULE LoaderCore::RuntimeModuleHandle() {
    return g_runtimeModule;
}

void LoaderCore::InitEarly() {
    Logger::Init(L"Civ6DllLoader_Loader.log");
    Logger::Log("InitEarly: runtimeVersion=0x%08X", kLoaderRuntimeVersion);
    // HookAPI 表必须落在只读页：插件写它要当场 AV，而不是静默改掉 Loader 的行为。
    LoaderCore::VerifyHookApiTableProtection();
    if (!PdataMatch::Init(g_runtimeModule)) {
        Logger::Log("InitEarly: PdataMatch::Init 失败（sidecar 缺失，继续）");
    } else {
        // 当前 exe（DX11/DX12）若有对应模块，先建档，供插件按旧 exe RVA 矫正。
        // 缺模块 / 建档失败一律 fail-closed：该映像的 ResolveByRva/ResolveByName 返回 nullptr，
        // 不回退原 RVA（原 RVA 在更新后本就是错的）——所以这三种情况必须留下醒目日志。
        const HookImageId exeImage = ImageAddress::IdentifyExecutable();
        Logger::Log("InitEarly: exe variant=%s (image=%u)",
            exeImage == kHookImageExeDx11 ? "DX11" :
                (exeImage == kHookImageExeDx12 ? "DX12" : "unknown"),
            static_cast<unsigned>(exeImage));
        if (exeImage == kHookImageInvalid) {
            Logger::Log("InitEarly: [WARN] executable image not identified (DX11/DX12) - "
                        "exe-domain RVA correction disabled");
        } else if (!PdataMatch::HasContext(exeImage)) {
            Logger::Log("InitEarly: [WARN] sidecar has no module for exe image=%u - old exe RVAs "
                        "cannot be corrected (ResolveByRva/ResolveByName return nullptr)",
                static_cast<unsigned>(exeImage));
        } else {
            HMODULE exeModule = GetModuleHandleW(nullptr);
            if (exeModule && PdataMatch::BuildNewTable(exeImage, exeModule)) {
                Logger::Log("InitEarly: PdataMatch exe table ready image=%u",
                    static_cast<unsigned>(exeImage));
            } else {
                Logger::Log("InitEarly: [WARN] PdataMatch exe table build FAILED image=%u - "
                            "old exe RVAs cannot be corrected this session; "
                            "ResolveByRva/ResolveByName on this image will return nullptr "
                            "(no raw-RVA fallback)",
                    static_cast<unsigned>(exeImage));
            }
        }
    }
    if (!Runtime::InitMinHook()) {
        Logger::Log("InitEarly: Runtime::InitMinHook 失败（hook 功能不可用，继续）");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // 休眠检测：自身位于游戏 exe 目录、且宿主进程是 CivilizationVI*.exe 时才启动工作线程；
        // 其它任何加载场合（别的进程加载了这份 version.dll、开发中直接 LoadLibrary）都直接休眠。
        const wchar_t* sleepWhy = nullptr;
        if (!LoadedFromExeDirectory(hModule, &sleepWhy)) {
            // 此时 Logger 还没 Init（它由工作线程创建），写不了日志文件，只能靠 DebugView：
            // 排查"loader 明明装了却没生效"时，先在 DebugView 里搜 [Civ6DllLoader] sleeping。
            std::wstring msg = L"[Civ6DllLoader] sleeping: ";
            msg += sleepWhy;
            msg += L" | module=";
            msg += ModuleDirectory(hModule);
            OutputDebugStringW(msg.c_str());
            return TRUE;
        }
        g_runtimeModule = hModule;
        HANDLE hThread = CreateThread(nullptr, 0, WorkerMain, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);  // 不等待
    } else if (reason == DLL_PROCESS_DETACH) {
        g_runtimeModule = nullptr;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) uint32_t __cdecl GetLoaderVersion(void) {
    return kLoaderRuntimeVersion;
}

