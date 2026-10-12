#include "pch.h"
#include "RuntimePackage.h"
#include "LoaderProtocol.h"
#include "Logger.h"

#include <filesystem>
#include <cstring>

namespace RuntimePackage {
namespace {

class FileHandle {
public:
    explicit FileHandle(HANDLE handle) : handle_(handle) {}
    ~FileHandle() { if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    HANDLE get() const { return handle_; }
private:
    HANDLE handle_;
};

struct VersionResource {
    uint32_t magic;
    uint16_t format;
    uint16_t major;
    uint16_t minor;
    uint16_t patch;
};
static_assert(sizeof(VersionResource) == 12);

bool ReadAt(HANDLE file, LONGLONG offset, void* buffer, DWORD size) {
    LARGE_INTEGER pos{};
    pos.QuadPart = offset;
    if (!SetFilePointerEx(file, pos, nullptr, FILE_BEGIN)) return false;
    DWORD read = 0;
    return ReadFile(file, buffer, size, &read, nullptr) && read == size;
}

// 持有源文件只读句柄期间验证磁盘 PE；映射只用于资源 API。
// allowCodeMapped：见 ProbeVersion 的说明。默认 false = 只认"独立数据映射"，
// 避免从"同名但内容已被换掉的旧代码映射"读出错误的版本（staging/自更新路径需要这个严格性）。
bool ProbeLocked(HANDLE file, const std::wstring& path, uint32_t& outVersion,
                 bool allowCodeMapped) {
    LARGE_INTEGER size{};
    IMAGE_DOS_HEADER dos{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart < static_cast<LONGLONG>(sizeof(dos)) ||
        !ReadAt(file, 0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < static_cast<LONG>(sizeof(dos)) ||
        static_cast<LONGLONG>(dos.e_lfanew) > size.QuadPart - static_cast<LONGLONG>(sizeof(IMAGE_NT_HEADERS64))) {
        return false;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadAt(file, dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        !(nt.FileHeader.Characteristics & IMAGE_FILE_DLL) ||
        nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }

    HMODULE module = LoadLibraryExW(path.c_str(), nullptr,
        LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!module) return false;
    bool ok = false;
    // (module & 3) != 0 表示拿到的是【独立的数据映射】；为 0 表示 Windows 复用了进程里
    // 已有的【代码映射】。严格路径（候选筛选 / staging / 自更新）要求前者：
    // 后者的句柄属于进程里已加载的同名模块，它的资源可能来自另一个（已被替换的）文件内容。
    //
    // 但"已安装的是不是我们的 loader"这个判定必须放宽到 allowCodeMapped ——
    // 因为游戏 exe 静态导入 version.dll，薄壳运行时目标文件【必然】已被代码映射
    // （实测 LoadLibraryExW 直接返回该代码映射句柄，m&3==0）。若沿用严格判据，
    // 已装载的【我们自己的 loader】会被误判成"不是我们的"，进而被错误地接管覆盖。
    // 放宽后仍由下面的资源校验兜底：
    //   我们的 loader（无论是否已代码映射）-> 有 RCDATA 105 且 magic/format 正确 -> ok
    //   外来 version.dll（含 System32 原生）-> 没有该资源 -> false
    if (allowCodeMapped || (reinterpret_cast<uintptr_t>(module) & 3u) != 0) {
        HRSRC resource = FindResourceW(module,
            MAKEINTRESOURCEW(CIV6_DLL_LOADER_VERSION_RESOURCE_ID), RT_RCDATA);
        if (resource && SizeofResource(module, resource) == sizeof(VersionResource)) {
            HGLOBAL loaded = LoadResource(module, resource);
            const void* bytes = loaded ? LockResource(loaded) : nullptr;
            if (bytes) {
                VersionResource version{};
                std::memcpy(&version, bytes, sizeof(version));
                if (version.magic == CIV6_DLL_LOADER_VERSION_MAGIC &&
                    version.format == CIV6_DLL_LOADER_VERSION_FORMAT &&
                    version.minor <= 255 && version.patch <= 255) {
                    outVersion = CIV6_DLL_LOADER_MAKE_VERSION(version.major, version.minor, version.patch);
                    ok = outVersion != 0;
                }
            }
        }
    }
    FreeLibrary(module);
    return ok;
}

bool DeleteIfPresent(const std::wstring& path) {
    return DeleteFileW(path.c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND;
}

}  // namespace

bool ProbeVersion(const std::wstring& path, uint32_t& outVersion) {
    outVersion = 0;
    // 不允许搜索路径选择另一份同名文件。
    if (!std::filesystem::path(path).is_absolute()) return false;
    FileHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE || !ProbeLocked(file.get(), path, outVersion, false)) {
        Logger::Log("RuntimePackage: rejected candidate (x64 DLL/version resource required): %ls", path.c_str());
        return false;
    }
    return true;
}

// "已安装的是不是我们的 loader"专用：放宽 (module & 3) 判据，见 ProbeLocked 的说明。
// 与 ProbeVersion 的区别只在这一点；PE 校验与 RCDATA 105 校验完全相同。
bool ProbeVersionIncludingLoaded(const std::wstring& path, uint32_t& outVersion) {
    outVersion = 0;
    if (!std::filesystem::path(path).is_absolute()) return false;
    FileHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE || !ProbeLocked(file.get(), path, outVersion, true)) {
        return false;
    }
    return true;
}

bool StageCandidate(const std::wstring& source, const std::wstring& staged, uint32_t expectedVersion) {
    if (!std::filesystem::path(source).is_absolute() ||
        !std::filesystem::path(staged).is_absolute()) return false;
    // 禁止源文件在本次校验和复制之间被修改或换名。
    FileHandle input(CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    uint32_t actualVersion = 0;
    if (input.get() == INVALID_HANDLE_VALUE || !ProbeLocked(input.get(), source, actualVersion, false) ||
        actualVersion != expectedVersion) {
        Logger::Log("RuntimePackage: candidate changed or invalid before staging: %ls", source.c_str());
        return false;
    }
    if (!DeleteIfPresent(staged)) return false;
    bool copied = false;
    {
        // CREATE_NEW 避免跟随预先存在的临时文件/链接；复制期间独占写入。
        FileHandle output(CreateFileW(staged.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (output.get() == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER start{};
        if (SetFilePointerEx(input.get(), start, nullptr, FILE_BEGIN)) {
            char buffer[64 * 1024];
            for (;;) {
                DWORD read = 0, written = 0;
                if (!ReadFile(input.get(), buffer, sizeof(buffer), &read, nullptr)) break;
                if (read == 0) {
                    copied = FlushFileBuffers(output.get()) != FALSE;
                    break;
                }
                if (!WriteFile(output.get(), buffer, read, &written, nullptr) || written != read) break;
            }
        }
    }
    uint32_t stagedVersion = 0;
    if (!copied || !ProbeVersion(staged, stagedVersion) || stagedVersion != expectedVersion) {
        DeleteFileW(staged.c_str());
        Logger::Log("RuntimePackage: staging failed: %ls", staged.c_str());
        return false;
    }
    return true;
}

bool PublishStaged(const std::wstring& staged, const std::wstring& installed,
    const std::wstring& backup) {
    if (backup.empty()) {
        // 首次安装不覆盖扫描期间由其它安装者创建的 version.dll。
        if (MoveFileW(staged.c_str(), installed.c_str())) return true;
        Logger::Log("RuntimePackage: initial publish failed err=%lu", GetLastError());
        DeleteFileW(staged.c_str());
        return false;
    }
    // 首选：ReplaceFile 单次原子替换 —— 被替换文件被重命名到 backup，替换文件顶替它的名字。
    // 旧实现在 MoveFileW(installed -> backup) 与 MoveFileW(staged -> installed) 之间存在
    // "version.dll 不存在"的窗口：进程恰好在此被杀/断电，磁盘上就只剩 version_Old.dll，
    // 下次启动 exe 的静态导入只能回退到 System32 的系统 version.dll，loader 静默消失一个会话。
    if (!DeleteIfPresent(backup)) {
        Logger::Log("RuntimePackage: stale backup cleanup failed err=%lu", GetLastError());
        DeleteFileW(staged.c_str());
        return false;
    }
    if (ReplaceFileW(installed.c_str(), staged.c_str(), backup.c_str(),
            REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr)) {
        Logger::Log("RuntimePackage: published via ReplaceFile (atomic) -> %ls", installed.c_str());
        return true;
    }
    const DWORD replaceError = GetLastError();
    Logger::Log("RuntimePackage: ReplaceFileW failed err=%lu; falling back to rename dance", replaceError);

    // 回退路径：ReplaceFileW 在"被替换文件正被映射为映像"等场合会被拒
    //（ShellBootstrap 接管外来 version.dll 时确实会走到），此时退回两步改名：
    // 先把现役文件挪成 backup，再把 staged 改名到位。第二步失败就把 backup 改回原位；
    // 连恢复都失败时保留两份完整文件（见下），绝不删掉唯一的旧副本。
    // backup 已在上面清掉，不会撞名字。
    if (!MoveFileW(installed.c_str(), backup.c_str())) {
        Logger::Log("RuntimePackage: backup failed err=%lu", GetLastError());
        DeleteFileW(staged.c_str());
        return false;
    }
    if (MoveFileW(staged.c_str(), installed.c_str())) return true;
    const DWORD publishError = GetLastError();
    if (MoveFileW(backup.c_str(), installed.c_str())) {
        DeleteFileW(staged.c_str());
        Logger::Log("RuntimePackage: publish failed err=%lu; previous DLL restored", publishError);
    } else {
        // 恢复也失败时保留两份完整文件，供下次启动/人工恢复，绝不删掉唯一旧副本。
        Logger::Log("RuntimePackage: publish failed err=%lu; restore failed err=%lu; backup=%ls staged=%ls",
            publishError, GetLastError(), backup.c_str(), staged.c_str());
    }
    return false;
}

}  // namespace RuntimePackage
