#include "pch.h"
#include "LoaderUpdate.h"
#include "../common/LoaderProtocol.h"
#include "../common/ModScan.h"
#include "../common/RestartGame.h"
#include "../common/Logger.h"

#include <algorithm>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")

namespace LoaderUpdate {

namespace {

struct RuntimeCandidate {
    std::wstring path;
    uint32_t version = 0;
};

// 自身模块句柄 + 全路径（即 exe 目录\version.dll），并推导 exe 目录。
// 异常场合（被旧薄壳从 Mod 目录 LoadLibrary 探测）→ 文件名不是 version.dll → 返回 false 直接退出。
bool GetSelfPath(std::wstring& outPath, std::wstring& outExeDir) {
    HMODULE hSelf = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&CheckAndApplyUpdate), &hSelf)) {
        Logger::Log("LoaderUpdate: GetModuleHandleExW failed err=%lu", GetLastError());
        return false;
    }

    wchar_t buf[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(hSelf, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        Logger::Log("LoaderUpdate: GetModuleFileNameW failed err=%lu", GetLastError());
        return false;
    }
    outPath.assign(buf, n);

    const size_t slash = outPath.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return false;
    }
    outExeDir = outPath.substr(0, slash);

    const std::wstring fileName = outPath.substr(slash + 1);
    return _wcsicmp(fileName.c_str(), L"version.dll") == 0;
}

// 规范化（lexically_normal + 小写）后做大小写不敏感比较。
std::wstring NormalizePath(const std::wstring& s) {
    std::wstring out = std::filesystem::path(s).lexically_normal().wstring();
    for (wchar_t& c : out) {
        c = static_cast<wchar_t>(towlower(c));
    }
    return out;
}

bool IsSamePath(const std::wstring& a, const std::wstring& b) {
    return NormalizePath(a) == NormalizePath(b);
}

// 选举：版本大者优先；同版本路径字典序小者优先。
bool BetterThan(const RuntimeCandidate& a, const RuntimeCandidate& b) {
    if (a.version != b.version) return a.version > b.version;
    return a.path < b.path;
}

// 探测候选版本：LoadLibraryW → GetProcAddress("GetLoaderVersion") → 读 uint32_t。失败跳过。
bool ProbeVersion(const std::wstring& path, uint32_t& outVersion) {
    HMODULE mod = LoadLibraryW(path.c_str());
    if (!mod) {
        Logger::Log("LoaderUpdate: probe LoadLibraryW failed: %ls err=%lu", path.c_str(), GetLastError());
        return false;
    }
    auto getVersion = reinterpret_cast<uint32_t(__cdecl*)(void)>(GetProcAddress(mod, "GetLoaderVersion"));
    const bool ok = getVersion != nullptr;
    if (ok) {
        outVersion = getVersion();
    } else {
        Logger::Log("LoaderUpdate: candidate missing GetLoaderVersion export: %ls", path.c_str());
    }
    FreeLibrary(mod);
    return ok;
}

}  // namespace

void CheckAndApplyUpdate() {
    // a. 自身路径与 exe 目录（文件名非 version.dll 的异常场合直接退出）
    std::wstring selfPath, exeDir;
    if (!GetSelfPath(selfPath, exeDir)) {
        return;
    }
    Logger::Log("LoaderUpdate: self=%ls", selfPath.c_str());

    const std::wstring oldPath = exeDir + L"\\version_Old.dll";
    const std::wstring tmpPath = exeDir + L"\\version.tmp";
    const std::wstring dllPath = exeDir + L"\\version.dll";

    // a2. 每次启动清理上一版残留；version_Old.dll 存在 = 本会话是自更新后的首次运行。
    //     仅清理 + 日志，不弹窗。
    const bool wasUpdated = GetFileAttributesW(oldPath.c_str()) != INVALID_FILE_ATTRIBUTES;
    if (wasUpdated) {
        if (!DeleteFileW(oldPath.c_str())) {
            Logger::Log("LoaderUpdate: delete version_Old.dll failed err=%lu, will retry next run", GetLastError());
        } else {
            Logger::Log("LoaderUpdate: removed stale version_Old.dll (post-update cleanup)");
        }
    }

    // b. 扫描启用 Mod 中的候选（FindRuntimeCandidates 内部已含 EnabledMods 过滤），排除自身
    const std::vector<std::wstring> candidates = ModScan::FindRuntimeCandidates(GetModuleHandleW(nullptr));
    std::vector<std::wstring> pool;
    pool.reserve(candidates.size());
    for (const auto& c : candidates) {
        if (!IsSamePath(c, selfPath)) {
            pool.push_back(c);
        }
    }
    Logger::Log("LoaderUpdate: candidates=%zu (self excluded=%zu)", pool.size(), candidates.size() - pool.size());

    // c. 探测版本并选举最高版本
    RuntimeCandidate best;
    size_t probed = 0;
    for (const auto& p : pool) {
        uint32_t v = 0;
        if (!ProbeVersion(p, v)) {
            continue;
        }
        ++probed;
        RuntimeCandidate cand{p, v};
        if (best.path.empty() || BetterThan(cand, best)) {
            best = cand;
        }
    }
    Logger::Log("LoaderUpdate: probed=%zu best=%ls v=0x%08X",
        probed, best.path.empty() ? L"(none)" : best.path.c_str(), best.version);

    // d. 当选版本 <= 当前运行版本 → 结束
    if (best.path.empty() || best.version <= kLoaderRuntimeVersion) {
        Logger::Log("LoaderUpdate: no newer runtime (best=0x%08X current=0x%08X)",
            best.path.empty() ? 0u : best.version, kLoaderRuntimeVersion);
        return;
    }

    // e. 更新舞蹈
    // 1) 残留清理：version_Old.dll 已在顶部清理过；此处防御性再删一次（不存在视为已干净）
    if (!DeleteFileW(oldPath.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
        Logger::Log("LoaderUpdate: delete version_Old.dll failed err=%lu, abort update", GetLastError());
        return;
    }
    // 2) 自身 → version_Old.dll（已加载 DLL 可改名，Windows 语义）
    if (!MoveFileW(selfPath.c_str(), oldPath.c_str())) {
        Logger::Log("LoaderUpdate: move self -> version_Old.dll failed err=%lu, abort update", GetLastError());
        return;
    }
    Logger::Log("LoaderUpdate: moved self to version_Old.dll");
    // 3) 当选候选 → version.tmp（失败时 _Old 已存在，下次启动薄壳安装器自愈）
    if (!CopyFileW(best.path.c_str(), tmpPath.c_str(), FALSE)) {
        Logger::Log("LoaderUpdate: copy candidate -> version.tmp failed err=%lu, abort update (shell self-heals next launch)", GetLastError());
        return;
    }
    // 4) 原子改名 version.tmp → version.dll（防截断 DLL 崩溃循环）
    if (!MoveFileExW(tmpPath.c_str(), dllPath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        Logger::Log("LoaderUpdate: move version.tmp -> version.dll failed err=%lu, abort update", GetLastError());
        DeleteFileW(tmpPath.c_str());
        return;
    }
    Logger::Log("LoaderUpdate: update applied new version=0x%08X (restart to take effect)", best.version);

    // 5) 双语提示弹窗（唯一允许弹窗的成功路径）——醒目样式 + 显示旧→新版本
    const uint32_t major = best.version >> 16;
    const uint32_t minor = (best.version >> 8) & 0xFF;
    const uint32_t patch = best.version & 0xFF;
    const uint32_t cmajor = kLoaderRuntimeVersion >> 16;
    const uint32_t cminor = (kLoaderRuntimeVersion >> 8) & 0xFF;
    const uint32_t cpatch = kLoaderRuntimeVersion & 0xFF;
    wchar_t msg[512];
    swprintf(msg, 512,
        L"★ Civ6 DLL Loader 已更新：v%u.%u.%u → v%u.%u.%u，点击确定立即重启游戏。★\n"
        L"★ Civ6 DLL Loader updated: v%u.%u.%u -> v%u.%u.%u. Click OK to restart the game now. ★",
        cmajor, cminor, cpatch, major, minor, patch,
        cmajor, cminor, cpatch, major, minor, patch);
    MessageBoxW(nullptr, msg, L"Civ6 DLL Loader — Update Ready",
        MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL | MB_TOPMOST | MB_SETFOREGROUND);
    if (!RestartGame::LaunchAndExit()) {
        Logger::Log("LoaderUpdate: restart failed err=%lu; session continues", GetLastError());
    }
}

}  // namespace LoaderUpdate