// RuntimeEntry.cpp — Civ6DllLoader v2 Loader 入口（DllLoaderRuntime 工程产物，
// 安装形态 = 游戏 exe 目录的 version.dll 代理）。
//
// v2 架构（设计文档 §3.1 / §4.1）：
//   - DllMain：DisableThreadLibraryCalls → 休眠检测（自身父目录 == 游戏 exe 目录，
//     规范化比较）通过才 spawn 工作线程；检测失败（被旧薄壳从 Mod 目录 LoadLibrary
//     探测）→ 直接返回 TRUE，什么都不做。
//   - WorkerMain（阶段 A）：LoaderCore::InitEarly → LoaderHooks::InstallAll
//     → LoaderUpdate::CheckAndApplyUpdate → LoadPluginsOf(Global) → 事件循环。
//   - 阶段 B（LoadDLL detour）在游戏线程 detour 内同步执行（LoaderCore::InitializeGameCorePhase）；
//     阶段 C（EnableMod/DisableMod detour）经 LoaderCore::RequestReconcile 置标志 +
//     SetEvent 唤醒工作线程执行 ReconcileGlobalPlugins（本文件实现两者）。

#include "pch.h"

#include <atomic>
#include <cwctype>
#include <string>

#include "../common/LoaderProtocol.h"
#include "LoaderCore.h"
#include "LoaderHooks.h"
#include "LoaderUpdate.h"
#include "../common/Logger.h"
#include "Runtime.h"
#include "PdataMatch.h"
#include "UiInject.h"

namespace {

// ---- 工作线程共享状态（匿名命名空间，避免与 LoaderCore 命名空间符号冲突）----

HMODULE g_runtimeModule = nullptr;               // 本模块句柄（DllMain 休眠检测通过后设置）
HANDLE g_wakeEvent = nullptr;                    // 手动重置事件：RequestReconcile SetEvent；WorkerMain Wait 返回后 ResetEvent
std::atomic<bool> g_reconcileRequested{ false }; // 阶段 C 合并去抖标志

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

// 休眠检测：自身父目录 == 进程 exe 父目录（version.dll 代理安装形态）时为真。
bool LoadedFromExeDirectory(HMODULE hModule) {
    return NormalizeDir(ModuleDirectory(hModule)) == NormalizeDir(ModuleDirectory(nullptr));
}

// 阶段 A + 事件循环（§4.1）。步骤顺序即设计文档阶段 A 顺序。
DWORD WINAPI WorkerMain(LPVOID) {
    g_wakeEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);  // 手动重置事件

    // 1) 基础初始化：Logger / PdataMatch / MinHook
    LoaderCore::InitEarly();

    // 1.5) 释放内嵌 FrontEnd UI 资源到 exe 目录的 Civ6DllLoader 子目录
    UiInject::ExtractResources();

    // 2) hook 安装（LoadDLL / lEnableMod / lDisableMod；失败静默降级）
    if (!LoaderHooks::InstallAll()) {
        Logger::Log("hook 安装降级");
    }

    // 2.5) FrontEnd UI 注入 hook（失败静默降级）
    if (!UiInject::Install()) {
        Logger::Log("FrontEnd UI 注入 hook 降级");
    }

    // 3) 自更新检查
    LoaderUpdate::CheckAndApplyUpdate();

    // 4) 阶段 A：加载启用 Mod 的 Global 插件
    LoaderCore::LoadPluginsOf(LoaderCore::PluginCategory::Global);

    // 5) 事件循环：阶段 C（主菜单开关 Mod → RequestReconcile）合并去抖后重查启用集
    for (;;) {
        if (g_wakeEvent) {
            WaitForSingleObject(g_wakeEvent, INFINITE);
            ResetEvent(g_wakeEvent);
        } else {
            Sleep(200);  // 事件创建失败兜底，避免忙循环
        }
        if (g_reconcileRequested.exchange(false)) {
            LoaderCore::ReconcileGlobalPlugins();
        }
    }
    return 0;  // unreachable
}

}  // namespace

// ---- LoaderCore 阶段 A 基础初始化（S3a，本文件实现）----
HMODULE LoaderCore::RuntimeModuleHandle() {
    return g_runtimeModule;
}

void LoaderCore::InitEarly() {
    Logger::Init(L"Civ6DllLoader_Loader.log");
    Logger::Log("InitEarly: runtimeVersion=0x%08X", kLoaderRuntimeVersion);
    if (!PdataMatch::Init(g_runtimeModule)) {
        Logger::Log("InitEarly: PdataMatch::Init 失败（sidecar 缺失，继续）");
    }
    if (!Runtime::InitMinHook()) {
        Logger::Log("InitEarly: Runtime::InitMinHook 失败（hook 功能不可用，继续）");
    }
}

// ---- 阶段 C 唤醒请求（S3a，本文件实现；EnableMod/DisableMod detour 调用）----
void LoaderCore::RequestReconcile() {
    UiInject::RequestRefresh();
    g_reconcileRequested.store(true);
    if (g_wakeEvent) {
        SetEvent(g_wakeEvent);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // 休眠检测：仅当自身位于游戏 exe 目录（version.dll 代理安装形态）时启动工作线程；
        // 被旧薄壳从 Mod 目录 LoadLibrary 探测时直接休眠、什么都不做。
        if (!LoadedFromExeDirectory(hModule)) {
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

// v2: 兼容旧薄壳探测。立即失败，令旧薄壳自动回退到其他候选 runtime。
// 签名不再引用已删除的 LoaderHost：旧薄壳调用方传指针，stub 忽略即可（薄壳 ABI 兼容）。
extern "C" __declspec(dllexport) int __cdecl LoaderStart(const void* host) {
    (void)host;
    (void)GetLastError();  // 差异化指令：防 Release COMDAT 折叠把 stub 合并到无关符号
    return -1;
}

extern "C" __declspec(dllexport) void __cdecl LoaderShutdown(void) {
    // v2: 生命周期由工作线程与 detour 管理；保留导出仅为兼容旧薄壳。
    (void)GetLastError();  // 差异化指令：防 Release COMDAT 折叠把空 stub 合并到无关符号
}
