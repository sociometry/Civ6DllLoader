#include "pch.h"
#include "LoaderUpdate.h"
#include "../common/LoaderProtocol.h"
#include "../common/ModScan.h"
#include "../common/RestartGame.h"
#include "../common/RuntimePackage.h"
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
        if (!RuntimePackage::ProbeVersion(p, v)) {
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

    // e. 完成临时文件复制和静态校验后才改动当前安装；发布失败由共享流程恢复备份。
    if (!RuntimePackage::StageCandidate(best.path, tmpPath, best.version)) {
        Logger::Log("LoaderUpdate: staging failed; current installation unchanged");
        return;
    }
    if (!RuntimePackage::PublishStaged(tmpPath, dllPath, oldPath)) {
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
