#include "pch.h"
#include "SymbolDb.h"
#include "../common/Logger.h"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace SymbolDb {
namespace {

constexpr char kMagic[4] = { 'C', '6', 'S', 'B' };
constexpr uint32_t kVersion = 1;
constexpr uint32_t kResourceId = 101;
constexpr wchar_t kSidecarName[] = L"Civ6DllLoader.symbols.bin";

#pragma pack(push, 1)
struct Header {
    char magic[4];
    uint32_t version;
    uint32_t expectedSizeOfImage;
    uint32_t entryCount;
    uint32_t heapOffset;
    uint32_t heapSize;
    uint32_t entriesOffset;
};
struct Entry {
    uint32_t nameOffset;
    uint32_t rva;
};
#pragma pack(pop)

static_assert(sizeof(Header) == 28, "SymbolDb header size");

// 保护 g_map / g_expectedSizeOfImage / g_loaded 的跨线程访问：
// LookupRva 在游戏线程（GetFunctionByName 路径）被调，RegisterRva 可在 Loader
// 工作线程（Global 插件 OnLoad）被调，unordered_map 并发读写是 UB。
std::mutex g_stateMutex;

std::unordered_map<std::string, uint32_t> g_map;
uint32_t g_expectedSizeOfImage = 0;
bool g_loaded = false;
std::vector<uint8_t> g_blob;  // keep heap alive if we index into it (map copies strings)

bool ParseBlob(const uint8_t* data, size_t size, const char* sourceTag) {
    if (!data || size < sizeof(Header)) {
        Logger::Log("SymbolDb: %s too small", sourceTag);
        return false;
    }

    Header hdr{};
    std::memcpy(&hdr, data, sizeof(hdr));
    if (std::memcmp(hdr.magic, kMagic, 4) != 0) {
        Logger::Log("SymbolDb: %s bad magic", sourceTag);
        return false;
    }
    if (hdr.version != kVersion) {
        Logger::Log("SymbolDb: %s unsupported version %u", sourceTag, hdr.version);
        return false;
    }
    const uint64_t heapEnd =
        static_cast<uint64_t>(hdr.heapOffset) + static_cast<uint64_t>(hdr.heapSize);
    if (hdr.heapOffset > size || heapEnd > size || hdr.entriesOffset > size) {
        Logger::Log("SymbolDb: %s truncated header extents", sourceTag);
        return false;
    }
    const uint64_t entriesEnd =
        static_cast<uint64_t>(hdr.entriesOffset) + static_cast<uint64_t>(hdr.entryCount) * sizeof(Entry);
    if (entriesEnd > size) {
        Logger::Log("SymbolDb: %s truncated entries", sourceTag);
        return false;
    }

    if (hdr.entryCount > 4'000'000) {
        Logger::Log("SymbolDb: %s unreasonable entry count %u", sourceTag, hdr.entryCount);
        return false;
    }
    const uint8_t* heap = data + hdr.heapOffset;
    // 以下开始触碰共享状态（校验段只读局部变量，锁外完成）。
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_map.clear();
    g_map.reserve(hdr.entryCount);
    for (uint32_t i = 0; i < hdr.entryCount; ++i) {
        Entry e{};
        std::memcpy(&e, data + hdr.entriesOffset + i * sizeof(Entry), sizeof(e));
        if (e.nameOffset >= hdr.heapSize) continue;
        const char* name = reinterpret_cast<const char*>(heap + e.nameOffset);
        // Ensure NUL within heap
        const size_t maxLen = hdr.heapSize - e.nameOffset;
        const size_t len = strnlen(name, maxLen);
        if (len >= maxLen) continue;
        g_map.emplace(std::string(name, len), e.rva);
    }

    g_expectedSizeOfImage = hdr.expectedSizeOfImage;
    g_loaded = !g_map.empty();
    Logger::Log("SymbolDb: loaded %s entries=%zu expected_SizeOfImage=0x%08X",
        sourceTag, g_map.size(), g_expectedSizeOfImage);
    return g_loaded;
}

bool LoadSidecar(HMODULE runtimeModule) {
    wchar_t path[MAX_PATH]{};
    if (!runtimeModule || !GetModuleFileNameW(runtimeModule, path, MAX_PATH)) {
        return false;
    }
    std::wstring wpath(path);
    const size_t slash = wpath.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return false;
    wpath.resize(slash + 1);
    wpath += kSidecarName;

    HANDLE file = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(file, &li) || li.QuadPart <= 0 || li.QuadPart > 64 * 1024 * 1024) {
        CloseHandle(file);
        return false;
    }
    g_blob.resize(static_cast<size_t>(li.QuadPart));
    DWORD read = 0;
    const BOOL ok = ReadFile(file, g_blob.data(), static_cast<DWORD>(g_blob.size()), &read, nullptr);
    CloseHandle(file);
    if (!ok || read != g_blob.size()) {
        g_blob.clear();
        return false;
    }
    return ParseBlob(g_blob.data(), g_blob.size(), "sidecar");
}

bool LoadResource(HMODULE runtimeModule) {
    if (!runtimeModule) return false;
    HRSRC res = FindResourceW(runtimeModule, MAKEINTRESOURCEW(kResourceId), RT_RCDATA);
    if (!res) return false;
    HGLOBAL glob = LoadResource(runtimeModule, res);
    if (!glob) return false;
    const DWORD sz = SizeofResource(runtimeModule, res);
    const void* ptr = LockResource(glob);
    if (!ptr || sz == 0) return false;
    // Copy so we own the bytes (LockResource points into module image).
    g_blob.assign(static_cast<const uint8_t*>(ptr), static_cast<const uint8_t*>(ptr) + sz);
    return ParseBlob(g_blob.data(), g_blob.size(), "rcdata");
}

}  // namespace

bool Init(HMODULE runtimeModule) {
    Shutdown();
    if (LoadSidecar(runtimeModule)) {
        return true;
    }
    if (LoadResource(runtimeModule)) {
        return true;
    }
    Logger::Log("SymbolDb: no symbol database (sidecar or RCDATA) — GetFunctionByName limited");
    return false;
}

void Shutdown() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_map.clear();
    g_blob.clear();
    g_expectedSizeOfImage = 0;
    g_loaded = false;
}

uint32_t LookupRva(const char* name) {
    if (!name || !*name) return 0;
    std::lock_guard<std::mutex> lock(g_stateMutex);
    if (g_map.empty()) return 0;
    const auto it = g_map.find(name);
    if (it == g_map.end()) return 0;
    return it->second;
}

bool RegisterRva(const char* name, uint32_t rva) {
    if (!name || !*name || rva == 0) return false;
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_map[name] = rva;
    g_loaded = true;
    return true;
}

size_t EntryCount() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_map.size();
}

uint32_t ExpectedSizeOfImage() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_expectedSizeOfImage;
}

bool IsLoaded() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_loaded;
}

}  // namespace SymbolDb
