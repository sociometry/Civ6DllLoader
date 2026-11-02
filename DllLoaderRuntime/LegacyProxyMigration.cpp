#include "pch.h"
#include "LegacyProxyMigration.h"
#include "../common/LoaderProtocol.h"
#include "../common/Logger.h"
#include "../common/RuntimePackage.h"

#include <cwchar>
#include <string>

namespace LegacyProxyMigration {
namespace {

// 与 ShellBootstrap 同样的坑：GetModuleFileNameW 截断时返回缓冲区大小且不设 last error，
// 所以必须"不够就翻倍"，不能把返回值直接当成路径长度。
bool GetModulePath(HMODULE module, std::wstring& out) {
    constexpr size_t kMaxPathChars = 32768;
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

bool FileExists(const std::wstring& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

}  // namespace

void MigrateIfLegacyProxy(HMODULE self) {
    std::wstring selfPath;
    if (!GetModulePath(self, selfPath)) {
        Logger::Log("LegacyProxyMigration: GetModuleFileNameW failed err=%lu", GetLastError());
        return;
    }
    const size_t slash = selfPath.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return;

    const std::wstring exeDir = selfPath.substr(0, slash);
    const std::wstring fileName = selfPath.substr(slash + 1);

    // 已装在 winmm.dll 上（绝大多数会话），或开发中直接从别处 LoadLibrary → 什么都不做。
    if (_wcsicmp(fileName.c_str(), CIV6_DLL_LOADER_LEGACY_PROXY_FILENAMEW) != 0) return;

    Logger::Log("LegacyProxyMigration: running as legacy proxy %ls; migrating to %ls (self=%ls)",
        fileName.c_str(), CIV6_DLL_LOADER_PROXY_FILENAMEW, selfPath.c_str());

    // 1) 老 loader 的自更新/接管会在 exe 目录留下 version_Old.dll；它只是被顶掉的旧文件，
    //    删不掉也不影响迁移，留给下一次启动的清理段再试。
    const std::wstring legacyOld = exeDir + L"\\" CIV6_DLL_LOADER_LEGACY_PROXY_OLD_FILENAMEW;
    if (FileExists(legacyOld) && !DeleteFileW(legacyOld.c_str())) {
        Logger::Log("LegacyProxyMigration: delete %ls failed err=%lu (ignored)", legacyOld.c_str(),
            GetLastError());
    }

    const std::wstring target = exeDir + L"\\" CIV6_DLL_LOADER_PROXY_FILENAMEW;
    const std::wstring backup = exeDir + L"\\" CIV6_DLL_LOADER_PROXY_OLD_FILENAMEW;

    // 2) 目标名已被占用，分两种：
    //
    //    (a) 占位的【就是我们的 loader】：这台机器已经装好了 winmm，只是旧名字没退役干净
    //        （薄壳退役失败、上次迁移中断、用户手动复制过）。这时要做的不是顶掉它 ——
    //        那等于把可能更新的安装换成自己 —— 而是让位：把自身退役成 version_Old.dll，
    //        让下一次启动只加载 winmm 那一份，由它自己的自更新负责版本。
    //
    //    (b) 外来文件（别的工具的 winmm.dll 代理、系统 winmm.dll 被手工复制进来）：
    //        退到 winmm_Old.dll 再让自身顶上，与 LoaderUpdate 的接管流程同套路。
    const bool targetExists = FileExists(target);
    uint32_t targetVersion = 0;
    if (targetExists && RuntimePackage::ProbeVersionIncludingLoaded(target, targetVersion)) {
        Logger::Log("LegacyProxyMigration: %ls is already Civ6DllLoader v=0x%08X; "
                    "withdrawing legacy %ls instead of displacing it",
            CIV6_DLL_LOADER_PROXY_FILENAMEW, targetVersion, fileName.c_str());
        if (MoveFileW(selfPath.c_str(), legacyOld.c_str())) {
            Logger::Log("LegacyProxyMigration: retired %ls -> %ls (next start loads %ls only)",
                fileName.c_str(), CIV6_DLL_LOADER_LEGACY_PROXY_OLD_FILENAMEW,
                CIV6_DLL_LOADER_PROXY_FILENAMEW);
        } else {
            Logger::Log("LegacyProxyMigration: retire %ls failed err=%lu; both proxies stay installed "
                        "(next start they coexist)",
                fileName.c_str(), GetLastError());
        }
        return;
    }

    if (targetExists) {
        if (!DeleteFileW(backup.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND) {
            Logger::Log("LegacyProxyMigration: clear %ls failed err=%lu; keeping legacy install",
                backup.c_str(), GetLastError());
            return;
        }
        if (!MoveFileW(target.c_str(), backup.c_str())) {
            Logger::Log("LegacyProxyMigration: retire existing %ls failed err=%lu; keeping legacy install",
                CIV6_DLL_LOADER_PROXY_FILENAMEW, GetLastError());
            return;
        }
        Logger::Log("LegacyProxyMigration: existing %ls moved to %ls",
            CIV6_DLL_LOADER_PROXY_FILENAMEW, CIV6_DLL_LOADER_PROXY_OLD_FILENAMEW);
    }

    // 3) 一步改名。本模块的文件正被自己映射着（映像以 FILE_SHARE_DELETE 打开），
    //    重命名可行；不重启，本会话继续跑当前已映射的映像。
    if (MoveFileW(selfPath.c_str(), target.c_str())) {
        Logger::Log("LegacyProxyMigration: migrated %ls -> %ls (takes effect next start; "
                    "this session continues as %ls)",
            fileName.c_str(), CIV6_DLL_LOADER_PROXY_FILENAMEW, fileName.c_str());
        return;
    }

    const DWORD renameError = GetLastError();
    Logger::Log("LegacyProxyMigration: rename %ls -> %ls failed err=%lu; rolling back",
        fileName.c_str(), CIV6_DLL_LOADER_PROXY_FILENAMEW, renameError);
    if (targetExists) {
        if (MoveFileW(backup.c_str(), target.c_str())) {
            Logger::Log("LegacyProxyMigration: previous %ls restored; stays as %ls this session",
                CIV6_DLL_LOADER_PROXY_FILENAMEW, fileName.c_str());
        } else {
            // 回滚也失败：winmm.dll 此刻不存在，但 exe 会回退到 System32 的系统 winmm.dll，
            // 游戏照常启动；下一次启动 version.dll 仍是我们的 loader，会再试一次迁移。
            Logger::Log("LegacyProxyMigration: restore failed err=%lu; %ls is absent and preserved "
                        "at %ls (next start retries the migration)",
                GetLastError(), CIV6_DLL_LOADER_PROXY_FILENAMEW,
                CIV6_DLL_LOADER_PROXY_OLD_FILENAMEW);
        }
    }
}

}  // namespace LegacyProxyMigration
