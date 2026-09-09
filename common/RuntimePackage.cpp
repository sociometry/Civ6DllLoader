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
bool ProbeLocked(HANDLE file, const std::wstring& path, uint32_t& outVersion) {
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
    // 已作为代码加载的同名模块会被 Windows 复用；不从该旧映像读取版本。
    if ((reinterpret_cast<uintptr_t>(module) & 3u) != 0) {
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
    if (file.get() == INVALID_HANDLE_VALUE || !ProbeLocked(file.get(), path, outVersion)) {
        Logger::Log("RuntimePackage: rejected candidate (x64 DLL/version resource required): %ls", path.c_str());
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
    if (input.get() == INVALID_HANDLE_VALUE || !ProbeLocked(input.get(), source, actualVersion) ||
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
    if (!DeleteIfPresent(backup) || !MoveFileW(installed.c_str(), backup.c_str())) {
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
