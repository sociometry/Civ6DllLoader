#include "pch.h"
#include "ShellBootstrap.h"
#include "../common/LoaderProtocol.h"
#include "../common/ModScan.h"
#include "../common/RestartGame.h"
#include "../common/RuntimePackage.h"
#include "../common/Logger.h"

#include <algorithm>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")

namespace ShellBootstrap {

namespace {

struct RuntimeCandidate {
    std::wstring path;
    uint32_t version = 0;
};

// ---- 路径辅助：按需增长缓冲，绝不把 MAX_PATH 截断当成成功 ----
// 这两个 API 的坑：GetModuleFileNameW 截断时返回缓冲区大小（不设 last error）；
// GetFullPathNameW 缓冲区不足时返回**所需长度**（> 0）。只判 "> 0" 就会把截断/残缺内容
// 当成功继续用（拼出的路径随即被 LoadLibraryExW 拿去加载）。这里统一改成"不够就翻倍重试"。
constexpr DWORD kMaxPathChars = 32768;   // 与长路径上限对齐，纯防御

bool GetModuleFileNameChecked(HMODULE module, std::wstring& out) {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(module, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0) return false;
        if (n < buf.size()) {
            buf.resize(n);
            out = std::move(buf);
            return true;
        }
        if (buf.size() >= kMaxPathChars) return false;
        buf.resize(buf.size() * 2, L'\0');
    }
}

bool GetFullPathChecked(const std::wstring& path, std::wstring& out) {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buf.size()),
            buf.data(), nullptr);
        if (n == 0) return false;
        if (n < buf.size()) {
            buf.resize(n);
            out = std::move(buf);
            return true;
        }
        if (buf.size() >= kMaxPathChars) return false;
        buf.resize(buf.size() * 2, L'\0');
    }
}

HMODULE LoadModuleFromPath(const std::wstring& path) {
    return LoadLibraryExW(path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
}

bool BetterThan(const RuntimeCandidate& a, const RuntimeCandidate& b) {
    if (a.version != b.version) return a.version > b.version;
    // Stable tie-break: lexicographically smaller path wins.
    return a.path < b.path;
}

// Full path of the running process executable (e.g. ...\CivilizationVI.exe).
std::wstring GetProcessExePath() {
    std::wstring path;
    return GetModuleFileNameChecked(nullptr, path) ? path : std::wstring{};
}

}  // namespace

HMODULE LoadRealGameCore() {
    // Prefer an already-mapped module (export forwarders often load it by basename).
    if (HMODULE existing = GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll")) {
        std::wstring path;
        if (GetModuleFileNameChecked(existing, path)) {
            if (HMODULE bumped = LoadModuleFromPath(path)) {
                return bumped;
            }
        }
    }

    // Resolve from CivilizationVI.exe dir: Base\Binaries\Win64Steam (or Win64) -> DLC\Expansion2\...
    std::wstring exePath;
    if (GetModuleFileNameChecked(nullptr, exePath)) {
        const size_t slash = exePath.find_last_of(L"\\/");
        if (slash != std::wstring::npos) {
            const std::wstring dir = exePath.substr(0, slash);
            const std::wstring candidate =
                dir + L"\\..\\..\\..\\DLC\\Expansion2\\Binaries\\Win64\\GameCore_XP2_FinalRelease.dll";
            std::wstring full;
            if (GetFullPathChecked(candidate, full)) {
                if (HMODULE gameCore = LoadModuleFromPath(full)) {
                    return gameCore;
                }
                Logger::Log("LoadRealGameCore absolute failed: %ls (err=%lu)", full.c_str(), GetLastError());
            }
        }
    }

    Logger::Log("Failed to load real GameCore_XP2_FinalRelease.dll (err=%lu)", GetLastError());
    return nullptr;
}

bool InstallLoaderIfMissing() {
    // 只在【成功装好、或已确认我们的 loader 在位】时才记住结果并短路后续调用；
    // 任何失败都不置位，下次调用（同一会话内游戏可能重建 game context）还会重试。
    //
    // 原实现是"进入函数就置 s_attempted = true"，于是首次因 version.tmp 被占用之类
    // 的原因失败后，整个进程生命周期内再也不试，也再不去看磁盘状态 —— 无法自愈。
    static bool s_installed = false;
    if (s_installed) return true;

    // a. Compute the exe directory from the current process image.
    const std::wstring exePath = GetProcessExePath();
    const size_t slash = exePath.find_last_of(L"\\/");
    if (exePath.empty() || slash == std::wstring::npos) {
        Logger::Log("InstallLoaderIfMissing: cannot resolve exe directory (path=%ls)", exePath.c_str());
        return false;
    }
    const std::wstring exeDir = exePath.substr(0, slash);
    const std::wstring versionDll = exeDir + L"\\version.dll";

    // b. 已安装判定：判据不是"文件存在"，而是"那个文件是不是 Civ6DllLoader"。
    //    与下面 c 步筛选候选用的是同一套判据（x64 PE 校验 + RCDATA 105 的 magic/format）。
    //
    //    为什么不能只看 GetFileAttributesW：按 §1.1，我们的 Loader 在位时薄壳根本不会被加载
    //    （LoadDLL detour 把槽位改写成官方 DLL）。所以薄壳能跑到这里、又发现 version.dll 存在，
    //    那个文件几乎必然【不是】我们的 —— version.dll 是各注入工具共用的代理名。
    //    只看文件存在会把外来代理当成"已装好"而静默跳过，表现为"mod 不生效"且只留一行日志。
    //
    //    为什么用 IncludingLoaded 变体而不是 ProbeVersion：此处目标文件此时【必然已被代码映射】
    //    （游戏 exe 静态导入 version.dll），ProbeLocked 的 (module & 3) != 0 严格判据会因此不成立，
    //    从而把【我们自己的 loader】也误判成外来文件。放宽这一点后，真正区分"是不是我们的"
    //    落到资源本身：我们的 loader 有 RCDATA 105 且 magic/format 正确；外来代理（含 System32
    //    原生 version.dll）没有这个资源。已在真机上对四类情形逐一验证。
    const DWORD attr = GetFileAttributesW(versionDll.c_str());
    const bool exists = (attr != INVALID_FILE_ATTRIBUTES);
    const bool isDir = exists && (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;

    uint32_t installedVersion = 0;
    if (!isDir && exists && RuntimePackage::ProbeVersionIncludingLoaded(versionDll, installedVersion)) {
        // 是我们的 Loader -> 零动作（不复制、不弹窗）。版本落后由 runtime 侧自更新负责。
        Logger::Log("InstallLoaderIfMissing: our loader already installed v=0x%08X: %ls",
            installedVersion, versionDll.c_str());
        s_installed = true;
        return s_installed;
    }

    if (isDir) {
        Logger::Log("InstallLoaderIfMissing: %ls is a directory; cannot install", versionDll.c_str());
        return false;
    }

    // 存在但不是我们的 -> 接管（用与 runtime 侧自更新相同的原子替换流程），见下面 d 步。
    const bool foreignPresent = exists;
    if (foreignPresent) {
        Logger::Log("InstallLoaderIfMissing: [WARN] %ls exists but is not Civ6DllLoader "
                    "(foreign version.dll proxy or unrelated file); will back it up and take over",
            versionDll.c_str());
    }

    // c. Collect candidates from the scan roots (game root / Documents Mods / Workshop).
    //    FindRuntimeCandidates deliberately does NOT filter by
    //    mod-enabled state - installation elects by version only (RCDATA 105), which is a
    //    separate path from "plugins load only from enabled mods". Probe versions, elect the
    //    highest (tie -> lexicographically smaller path).
    const auto paths = ModScan::FindRuntimeCandidates();
    Logger::Log("InstallLoaderIfMissing: found %zu runtime candidate(s)", paths.size());

    std::vector<RuntimeCandidate> ranked;
    ranked.reserve(paths.size());
    for (const auto& path : paths) {
        uint32_t version = 0;
        if (!RuntimePackage::ProbeVersion(path, version)) continue;
        Logger::Log("InstallLoaderIfMissing: candidate %ls version=0x%08X", path.c_str(), version);
        ranked.push_back(RuntimeCandidate{path, version});
    }

    if (ranked.empty()) {
        // e. No usable candidate -> silent + log only (never a message box).
        Logger::Log("InstallLoaderIfMissing: no usable Civ6DllLoader.runtime.dll found; loader stays missing");
        return false;
    }
    std::sort(ranked.begin(), ranked.end(), BetterThan);
    const std::wstring& bestPath = ranked.front().path;
    Logger::Log("InstallLoaderIfMissing: elected %ls (version=0x%08X)", bestPath.c_str(), ranked.front().version);

    // d. 复制到 exe-dir\version.tmp，再原子替换成 version.dll，然后提示。
    //    替换的两种入口：
    //      - 首次安装（目录里没有 version.dll）：PublishStaged 用 MoveFileW，不覆盖已有文件；
    //      - 接管外来文件：走与 runtime 侧自更新【完全相同】的带备份原子替换
    //        （RuntimePackage::PublishStaged(..., backup) → ReplaceFileW，被拒时回退两步改名 + 回滚）。
    //
    //    为什么必须用 ReplaceFileW 而不是"先删再拷"：此时 version.dll 正被映像映射
    //    （游戏启动了它），DeleteFileW 会因共享冲突失败；ReplaceFileW 能把被替换文件
    //    重命名到备份名再让新文件顶上，被映射的文件也能改名 —— 这正是自更新选它的原因。
    //
    //    备份名沿用自更新那套 version_Old.dll，语义统一：它只是"被顶掉的旧文件"，
    //    进程内不会被任何人加载（游戏只静态导入 version.dll），需要时由用户自行取用。
    const std::wstring tmp = exeDir + L"\\version.tmp";
    const std::wstring oldPath = exeDir + L"\\version_Old.dll";
    if (!RuntimePackage::StageCandidate(bestPath, tmp, ranked.front().version)) {
        Logger::Log("InstallLoaderIfMissing: staging failed for %ls", bestPath.c_str());
        return false;
    }

    if (foreignPresent) {
        if (!RuntimePackage::PublishStaged(tmp, versionDll, oldPath)) {
            Logger::Log("InstallLoaderIfMissing: takeover of foreign version.dll failed; "
                        "original file left in place (or restored)");
            return false;
        }
        Logger::Log("InstallLoaderIfMissing: took over foreign version.dll "
                    "(previous file moved to %ls)", oldPath.c_str());
    } else {
        // 首次安装：目录里没有 version.dll，用不带备份的发布（MoveFileW，不覆盖已有文件）。
        if (!RuntimePackage::PublishStaged(tmp, versionDll)) {
            return false;
        }
        // 此时 version_Old.dll 只可能是上次自更新/接管的残留，且本次发布没用它 → 清掉。
        DeleteFileW(oldPath.c_str());
    }

    MessageBoxW(nullptr,
        L"Civ6 DLL Loader 已安装，点击确定立即重启游戏。\nCiv6 DLL Loader installed. Click OK to restart the game now.",
        L"Civ6 DLL Loader",
        MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND);
    if (!RestartGame::LaunchAndExit()) {
        Logger::Log("InstallLoaderIfMissing: restart failed err=%lu; session continues", GetLastError());
    }

    s_installed = true;
    Logger::Log("InstallLoaderIfMissing: installed %ls -> %ls", bestPath.c_str(), versionDll.c_str());
    return s_installed;
}

}  // namespace ShellBootstrap
