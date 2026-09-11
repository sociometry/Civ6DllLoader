// PdataMatch.cpp — pdata 匹配 RVA 矫正
//
// 游戏更新后 GameCore_XP2 的 RVA 变化：通过 PE 异常目录（.pdata）对函数做跨版本匹配，
// 把 old RVA（sidecar 签名表）矫正为 new RVA（当前加载的 GameCore 映像）。
//
// sidecar 二进制格式（Civ6DllLoader.symdb.bin，小端，pack(1)）：
//   Header(52B)  : "C6SD" + version=4 + baseSizeOfImage + baseTimeDateStamp
//                  + pdataCount + targetCount
//                  + pdataOffset + targetOffset + heapOffset + heapSize + vtableOffset(0=无)
//                  + aobOffset + aobSize
//   pdata 签名表  : pdataCount x 16B = begin_rva + size + unwind_hash（按 begin_rva 递增）
//   符号表        : targetCount x 32B = demangledNameOffset + mangledNameOffset + old_rva
//                  + kind(0=Function,1=vtable) + vtableSlotCount + reserved
//                  + normHeadHash + reserved2 + reserved3（nameOffset 相对堆）
//   vtable 槽位表 : 8B/条 = slotOffset + slotOldRva（按 vtable 符号出现顺序连续）
//   字符串堆      : NUL 结尾 UTF-8 名字连续存放
//
// 流程：Init（加载/解析 sidecar）→ BuildNewTable（解析 new .pdata + 算签名 + 版本指纹
//   + 磁盘缓存 + 全表序列对齐）→ CorrectRva / CorrectByName（查询 old->new 映射）。
// 对齐 = 窗口哈希锚点（唯一候选）+ LIS 锚点链（old 递增且 new 递增）
//   + 锚点间线性插值（插值处签名全等才接受）+ 头哈希校验（有 normHeadHash 的 Function）。

#include "pch.h"

#include "PdataMatch.h"
#include "NormHash.h"
#include "../common/Logger.h"

#include <Windows.h>
#include <compressapi.h>
#pragma comment(lib, "Cabinet.lib")

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace PdataMatch {
namespace {

// ---- sidecar（Civ6DllLoader.symdb.bin）----

constexpr char kSidecarMagic[4] = { 'C', '6', 'S', 'D' };
constexpr uint32_t kSidecarVersion = 4;      // v4：增加 PE TimeDateStamp；槽位仍为 8 字节
constexpr uint32_t kSidecarVersionMax = 4;
constexpr uint32_t kSidecarResourceId = 102;  // RCDATA 资源 id（旧资源 101 已随旧符号库退役，勿复用）
constexpr wchar_t kSidecarFileName[] = L"Civ6DllLoader.symdb.bin";

constexpr uint32_t kMaxPdataCount = 4'000'000;
constexpr uint32_t kMaxTargetCount = 4'000'000;
constexpr uint64_t kMaxHeapBytes = 256ull * 1024 * 1024;
constexpr uint32_t kMaxVtableSlots = 4'000'000;
constexpr uint32_t kUnmatched = UINT32_MAX;

// ---- 磁盘缓存（exe 目录 Civ6DllLoader\pdata_cache.bin）----

constexpr char kCacheMagic[4] = { 'C', '6', 'P', 'C' };
constexpr uint32_t kCacheVersion = 2;  // v2：新增 oldFingerprint（区分 sidecar 更新）
constexpr wchar_t kCacheDirName[] = L"Civ6DllLoader";
constexpr wchar_t kCacheFileName[] = L"pdata_cache.bin";

#pragma pack(push, 1)
struct SidecarHeader {           // 52 字节
    char magic[4];
    uint32_t version;
    uint32_t baseSizeOfImage;
    uint32_t pdataCount;
    uint32_t targetCount;
    uint32_t pdataOffset;
    uint32_t targetOffset;
    uint32_t heapOffset;
    uint32_t heapSize;
    uint32_t vtableOffset;       // 0 = 无
    uint32_t aobOffset;
    uint32_t aobSize;
    uint32_t baseTimeDateStamp;  // source GameCore PE FileHeader.TimeDateStamp
};
struct PdataSig {                // pdata 签名表条目（sidecar 里 16 字节；运行时 new 表 20 字节）
    uint32_t begin_rva;
    uint32_t size;
    uint64_t unwind_hash;
    uint32_t prologSize;          // SizeOfProlog（UNWIND_INFO offset 1）；sidecar 的 pdata 表无此字段，恒 0
};
struct SymbolEntry {             // 符号表条目，32 字节
    uint32_t demangledNameOffset;  // 相对堆，0 = 无
    uint32_t mangledNameOffset;    // 相对堆，0 = 无
    uint32_t old_rva;
    uint8_t kind;                  // 0=Function，1=vtable
    uint8_t vtableSlotCount;
    uint16_t reserved;
    uint64_t normHeadHash;
    uint32_t reserved2;
    uint32_t reserved3;
};
struct VtableSlot {              // vtable 槽位，8 字节
    uint32_t slotOffset;
    uint32_t slotOldRva;
};
struct CacheHeader {             // pdata_cache.bin 头，28 字节
    char magic[4];
    uint32_t version;
    uint64_t fingerprint;        // new pdata 指纹
    uint64_t oldFingerprint;     // old pdata 指纹（sidecar 内容）
    uint32_t entryCount;
};
#pragma pack(pop)

static_assert(sizeof(SidecarHeader) == 52, "SidecarHeader must be 52 bytes");
static_assert(sizeof(PdataSig) == 20, "PdataSig must be 20 bytes");
static_assert(sizeof(SymbolEntry) == 32, "SymbolEntry must be 32 bytes");
static_assert(sizeof(VtableSlot) == 8, "VtableSlot must be 8 bytes");
static_assert(sizeof(CacheHeader) == 28, "CacheHeader must be 28 bytes");
static_assert(sizeof(RUNTIME_FUNCTION) == 12, "RUNTIME_FUNCTION must be 12 bytes on x64");

// 符号表运行时形态
struct Symbol {
    std::string demangled;   // 空 = 无
    std::string mangled;
    uint32_t old_rva = 0;
    uint8_t kind = 0;        // 0=Function，1=vtable
    uint64_t normHeadHash = 0;
    std::vector<VtableSlot> slots;  // kind==1 时的槽位（解析期填充）
};

// ---- 状态（CorrectRva/CorrectByName 在游戏线程被调，Init/BuildNewTable 在加载线程，
//      用互斥锁保护共享表）----

std::mutex g_mutex;

// 前置声明（定义在 ParseNewPdata 之前）
uint64_t ComputeTableFingerprint(const std::vector<PdataSig>& table);

std::vector<PdataSig> g_oldPdata;                 // old 签名表（按 begin_rva 升序）
std::vector<Symbol> g_symbols;                    // 符号表
std::unordered_map<std::string, size_t> g_byDemangled;
std::unordered_map<std::string, size_t> g_byMangled;
std::unordered_map<uint32_t, uint64_t> g_headHashByRva;  // old_rva -> normHeadHash（Function 且有值）
struct AobInfo {                // 函数体 AOB 条目信息（v2 sidecar）
    uint32_t bodySize = 0;
    size_t dataOffset = 0;      // 在 g_aobData 里的偏移（body 起始，mask 紧随其后）
};
struct VtableInfo {              // vtable 符号信息（跨版本定位用）
    uint32_t old_rva = 0;        // vtable 地址（.rdata）
    std::vector<VtableSlot> slots;  // 槽位表（offset + funcRva，含叶子槽函数）
};
std::vector<uint8_t> g_aobData;                    // 函数体 AOB 表原始数据（v2）
std::unordered_map<uint32_t, AobInfo> g_aobByRva;  // old_rva -> AOB 信息
uint64_t g_oldFingerprint = 0;                 // old pdata 表指纹（sidecar 内容）
uint32_t g_baseSizeOfImage = 0;
uint32_t g_baseTimeDateStamp = 0;
bool g_loaded = false;
bool g_identical = false;  // 版本一致（恒等映射）：跳过一切 pdata 匹配，RVA 恒等解析
std::unordered_map<uint32_t, uint32_t> g_leafMap;  // 叶子符号 old_rva -> new_rva（跨版本 AOB 匹配结果）

std::vector<PdataSig> g_newPdata;                 // new 签名表（按 begin_rva 升序）
std::vector<uint32_t> g_map;                      // old_idx -> new_idx / kUnmatched
uint64_t g_fingerprint = 0;
bool g_tableReady = false;

// ---- 工具函数 ----

bool ReadWholeFile(const wchar_t* path, std::vector<uint8_t>& out) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    bool ok = false;
    do {
        LARGE_INTEGER li{};
        if (!GetFileSizeEx(file, &li) || li.QuadPart <= 0 ||
            li.QuadPart > static_cast<LONGLONG>(256 * 1024 * 1024)) break;
        out.resize(static_cast<size_t>(li.QuadPart));
        DWORD read = 0;
        if (!ReadFile(file, out.data(), static_cast<DWORD>(out.size()), &read, nullptr) ||
            read != out.size()) {
            out.clear();
            break;
        }
        ok = true;
    } while (false);
    CloseHandle(file);
    return ok;
}

// 解压 sidecar：格式 [uint32 original_size LE][XPRESS_HUFF data]（cabinet.dll 公共 API，
// 与 tools/compress_sidecar.py 对称）。未压缩文件以 "C6SD" 开头，调用方直接透传给 ParseSidecar。
bool DecompressSidecar(const std::vector<uint8_t>& packed, std::vector<uint8_t>& out) {
    if (packed.size() < 4) return false;
    uint32_t origSize = 0;
    std::memcpy(&origSize, packed.data(), 4);
    if (origSize == 0 || origSize > 512u * 1024 * 1024) return false;  // 安全上限

    const uint8_t* src = packed.data() + 4;
    const SIZE_T srcLen = static_cast<SIZE_T>(packed.size() - 4);

    DECOMPRESSOR_HANDLE dec = nullptr;
    if (!CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &dec)) {
        Logger::Log("PdataMatch: CreateDecompressor failed (gle=%lu)", GetLastError());
        return false;
    }
    out.resize(origSize);
    SIZE_T used = 0;
    const BOOL ok = Decompress(dec, src, srcLen, out.data(), origSize, &used);
    CloseDecompressor(dec);
    if (!ok || used != origSize) {
        Logger::Log("PdataMatch: Decompress failed ok=%d used=%zu want=%u (gle=%lu)",
            static_cast<int>(ok), static_cast<size_t>(used), origSize, GetLastError());
        out.clear();
        return false;
    }
    return true;
}

// 解析 sidecar（data 指向完整文件字节；所有字段拷贝进自有结构，不保留引用）
bool ParseSidecar(const uint8_t* data, size_t size, const char* sourceTag) {
    if (!data || size < sizeof(SidecarHeader)) {
        Logger::Log("PdataMatch: %s too small (%zu bytes)", sourceTag, size);
        return false;
    }
    SidecarHeader hdr{};
    std::memcpy(&hdr, data, sizeof(hdr));
    if (std::memcmp(hdr.magic, kSidecarMagic, 4) != 0) {
        Logger::Log("PdataMatch: %s bad magic", sourceTag);
        return false;
    }
    if (hdr.version < kSidecarVersion || hdr.version > kSidecarVersionMax) {
        Logger::Log("PdataMatch: %s unsupported version %u", sourceTag, hdr.version);
        return false;
    }
    if (size < sizeof(SidecarHeader)) {
        Logger::Log("PdataMatch: %s v4 header too small (%zu bytes)", sourceTag, size);
        return false;
    }
    const uint32_t aobOffset = hdr.aobOffset;
    uint32_t aobSize = hdr.aobSize;
    if (static_cast<uint64_t>(aobOffset) + aobSize > size) {
        Logger::Log("PdataMatch: %s AOB table out of range (off=%u size=%u)", sourceTag, aobOffset, aobSize);
        return false;
    }
    if (hdr.pdataCount > kMaxPdataCount || hdr.targetCount > kMaxTargetCount ||
        hdr.heapSize > kMaxHeapBytes || hdr.vtableOffset > size) {
        Logger::Log("PdataMatch: %s unreasonable counts (pdata=%u target=%u heap=%u vtable=0x%08X)",
            sourceTag, hdr.pdataCount, hdr.targetCount, hdr.heapSize, hdr.vtableOffset);
        return false;
    }
    const uint64_t pdataEnd = static_cast<uint64_t>(hdr.pdataOffset) +
        static_cast<uint64_t>(hdr.pdataCount) * 16;  // sidecar pdata 表固定 16 字节/条
    const uint64_t targetEnd = static_cast<uint64_t>(hdr.targetOffset) +
        static_cast<uint64_t>(hdr.targetCount) * sizeof(SymbolEntry);
    const uint64_t heapEnd = static_cast<uint64_t>(hdr.heapOffset) + hdr.heapSize;
    if (pdataEnd > size || targetEnd > size || heapEnd > size) {
        Logger::Log("PdataMatch: %s truncated extents", sourceTag);
        return false;
    }

    // pdata 签名表
    std::vector<PdataSig> oldPdata;
    oldPdata.reserve(hdr.pdataCount);
    for (uint32_t i = 0; i < hdr.pdataCount; ++i) {
        // sidecar 的 pdata 表固定 16 字节/条（begin_rva + size + unwind_hash），无 prologSize
        const uint8_t* p = data + hdr.pdataOffset + static_cast<uint64_t>(i) * 16;
        PdataSig e{};
        std::memcpy(&e.begin_rva, p, 4);
        std::memcpy(&e.size, p + 4, 4);
        std::memcpy(&e.unwind_hash, p + 8, 8);
        e.prologSize = 0;
        oldPdata.push_back(e);
    }
    if (oldPdata.empty()) {
        Logger::Log("PdataMatch: %s empty pdata table", sourceTag);
        return false;
    }
    // 对齐与二分都依赖 begin_rva 升序（sidecar 生成端保证，这里兜底）
    std::stable_sort(oldPdata.begin(), oldPdata.end(),
        [](const PdataSig& a, const PdataSig& b) { return a.begin_rva < b.begin_rva; });

    // 符号表 + vtable 槽位 + 字符串堆
    const uint8_t* heap = data + hdr.heapOffset;
    std::vector<Symbol> symbols;
    symbols.reserve(hdr.targetCount);
    std::unordered_map<std::string, size_t> byDemangled;
    std::unordered_map<std::string, size_t> byMangled;
    std::unordered_map<uint32_t, uint64_t> headHashByRva;
    std::vector<uint8_t> aobData;
    std::unordered_map<uint32_t, AobInfo> aobByRva;
    size_t aobCursor = aobOffset;   // AOB 表当前偏移
    uint32_t slotCursor = 0;
    size_t vtableSymbols = 0;

    for (uint32_t i = 0; i < hdr.targetCount; ++i) {
        SymbolEntry se{};
        std::memcpy(&se, data + hdr.targetOffset + static_cast<uint64_t>(i) * sizeof(SymbolEntry), sizeof(se));
        Symbol sym;
        sym.old_rva = se.old_rva;
        sym.kind = se.kind;
        sym.normHeadHash = se.normHeadHash;

        const auto readName = [&](uint32_t off) -> std::string {
            if (off == 0 || off >= hdr.heapSize) return {};
            const char* p = reinterpret_cast<const char*>(heap + off);
            const size_t maxLen = hdr.heapSize - off;
            const size_t len = strnlen(p, maxLen);
            if (len >= maxLen) return {};  // 堆内无 NUL，视为损坏
            return std::string(p, len);
        };
        sym.demangled = readName(se.demangledNameOffset);
        sym.mangled = readName(se.mangledNameOffset);

        if (sym.kind == 1 && se.vtableSlotCount != 0) {
            if (hdr.vtableOffset == 0 ||
                static_cast<uint64_t>(slotCursor) + se.vtableSlotCount > kMaxVtableSlots ||
                static_cast<uint64_t>(hdr.vtableOffset) +
                    (static_cast<uint64_t>(slotCursor) + se.vtableSlotCount) * sizeof(VtableSlot) > size) {
                Logger::Log("PdataMatch: %s vtable slot overflow at symbol %u", sourceTag, i);
                return false;
            }
            sym.slots.reserve(se.vtableSlotCount);
            for (uint8_t s = 0; s < se.vtableSlotCount; ++s) {
                VtableSlot vs{};
                std::memcpy(&vs, data + hdr.vtableOffset +
                    static_cast<uint64_t>(slotCursor + s) * sizeof(VtableSlot), sizeof(vs));
                sym.slots.push_back(vs);
            }
            slotCursor += se.vtableSlotCount;
            ++vtableSymbols;
        } else if (sym.kind == 0 && sym.normHeadHash != 0 && sym.old_rva != 0) {
            headHashByRva.emplace(sym.old_rva, sym.normHeadHash);
        }

        // v4：Function 符号读函数体 AOB（bodySize + body + mask）
        if (sym.kind == 0 && aobSize != 0) {
            if (aobCursor + 4 <= static_cast<uint64_t>(aobOffset) + aobSize) {
                uint32_t bodySize = 0;
                std::memcpy(&bodySize, data + aobCursor, 4);
                aobCursor += 4;
                const uint64_t span = static_cast<uint64_t>(bodySize) * 2;
                if (aobCursor + span <= static_cast<uint64_t>(aobOffset) + aobSize) {
                    const size_t off = aobData.size();
                    aobData.insert(aobData.end(), data + aobCursor, data + aobCursor + span);
                    aobByRva.emplace(sym.old_rva, AobInfo{ bodySize, off });
                    aobCursor += span;
                } else {
                    aobSize = 0;  // AOB 表截断，后续 Function 不再解析
                }
            } else {
                aobSize = 0;
            }
        }

        const size_t idx = symbols.size();
        symbols.push_back(std::move(sym));
        if (!symbols[idx].demangled.empty()) byDemangled.emplace(symbols[idx].demangled, idx);
        if (!symbols[idx].mangled.empty()) byMangled.emplace(symbols[idx].mangled, idx);
    }

    std::lock_guard<std::mutex> lock(g_mutex);
    g_oldPdata = std::move(oldPdata);
    g_oldFingerprint = ComputeTableFingerprint(g_oldPdata);
    g_symbols = std::move(symbols);
    g_byDemangled = std::move(byDemangled);
    g_byMangled = std::move(byMangled);
    g_headHashByRva = std::move(headHashByRva);
    g_aobData = std::move(aobData);
    g_aobByRva = std::move(aobByRva);
    g_baseSizeOfImage = hdr.baseSizeOfImage;
    g_baseTimeDateStamp = hdr.baseTimeDateStamp;
    g_loaded = true;
    Logger::Log("PdataMatch: %s loaded pdata=%zu symbols=%zu vtable_symbols=%zu vtable_slots=%u base=0x%08X timestamp=0x%08X",
        sourceTag, g_oldPdata.size(), g_symbols.size(), vtableSymbols, slotCursor,
        g_baseSizeOfImage, g_baseTimeDateStamp);
    return true;
}

bool LoadSidecar(HMODULE runtimeModule) {
    wchar_t path[MAX_PATH]{};
    if (!runtimeModule || !GetModuleFileNameW(runtimeModule, path, MAX_PATH)) return false;
    std::wstring wpath(path);
    const size_t slash = wpath.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return false;
    wpath.resize(slash + 1);
    wpath += kSidecarFileName;
    std::vector<uint8_t> blob;
    if (!ReadWholeFile(wpath.c_str(), blob)) return false;
    if (blob.size() >= 4 && std::memcmp(blob.data(), kSidecarMagic, 4) == 0) {
        return ParseSidecar(blob.data(), blob.size(), "sidecar");
    }
    std::vector<uint8_t> raw;
    if (!DecompressSidecar(blob, raw)) {
        Logger::Log("PdataMatch: sidecar file decompress failed (%zu bytes)", blob.size());
        return false;
    }
    return ParseSidecar(raw.data(), raw.size(), "sidecar");
}

bool LoadSidecarResource(HMODULE runtimeModule) {
    if (!runtimeModule) return false;
    HRSRC res = FindResourceW(runtimeModule, MAKEINTRESOURCEW(kSidecarResourceId), RT_RCDATA);
    if (!res) return false;
    HGLOBAL glob = LoadResource(runtimeModule, res);
    if (!glob) return false;
    const DWORD sz = SizeofResource(runtimeModule, res);
    const void* ptr = LockResource(glob);
    if (!ptr || sz == 0) return false;
    std::vector<uint8_t> blob(static_cast<const uint8_t*>(ptr),
        static_cast<const uint8_t*>(ptr) + sz);
    if (blob.size() >= 4 && std::memcmp(blob.data(), kSidecarMagic, 4) == 0) {
        return ParseSidecar(blob.data(), blob.size(), "rcdata");
    }
    std::vector<uint8_t> raw;
    if (!DecompressSidecar(blob, raw)) {
        Logger::Log("PdataMatch: rcdata sidecar decompress failed (%zu bytes)", blob.size());
        return false;
    }
    return ParseSidecar(raw.data(), raw.size(), "rcdata");
}

// 对 pdata 表算版本指纹：对 (size, unwind_hash) 全表字节做 FNV-1a64（每条 size(4) + unwind_hash(8)）
uint64_t ComputeTableFingerprint(const std::vector<PdataSig>& table) {
    std::vector<uint8_t> bytes;
    bytes.reserve(table.size() * 12);
    for (const PdataSig& e : table) {
        uint32_t size = e.size;
        uint64_t uh = e.unwind_hash;
        const uint8_t* sp = reinterpret_cast<const uint8_t*>(&size);
        const uint8_t* up = reinterpret_cast<const uint8_t*>(&uh);
        bytes.insert(bytes.end(), sp, sp + 4);
        bytes.insert(bytes.end(), up, up + 8);
    }
    return NormHash::Fnv1a64(bytes.data(), bytes.size());
}

// 解析 new GameCore 的 .pdata：RUNTIME_FUNCTION 数组 -> (begin_rva, size, unwind_hash) 签名表
bool ParseNewPdata(HMODULE gameCore, std::vector<PdataSig>& outTable,
    uint64_t& outFingerprint, uint32_t& outImageSize, uint32_t& outTimeDateStamp) {
    if (!gameCore) return false;
    const uint8_t* base = reinterpret_cast<const uint8_t*>(gameCore);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const uint32_t imageSize = nt->OptionalHeader.SizeOfImage;
    const uint32_t timeDateStamp = nt->FileHeader.TimeDateStamp;
    const IMAGE_DATA_DIRECTORY& exc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exc.VirtualAddress == 0 || exc.Size == 0) return false;
    if (static_cast<uint64_t>(exc.VirtualAddress) + exc.Size > imageSize) return false;

    const size_t count = exc.Size / sizeof(RUNTIME_FUNCTION);
    std::vector<PdataSig> table;
    table.reserve(count);
    size_t skipped = 0;
    for (size_t i = 0; i < count; ++i) {
        RUNTIME_FUNCTION rf{};
        std::memcpy(&rf, base + exc.VirtualAddress + i * sizeof(RUNTIME_FUNCTION), sizeof(rf));
        if (rf.BeginAddress == 0 || rf.EndAddress <= rf.BeginAddress ||
            rf.EndAddress > imageSize || rf.UnwindInfoAddress == 0) {
            ++skipped;
            continue;
        }
        // unwind_hash：UNWIND_INFO 前 len 字节；
        // len = 4 + 2*CountOfUnwindCodes + (CountOfUnwindCodes&1)*2（CountOfUnwindCodes 为第 3 字节）
        if (static_cast<uint64_t>(rf.UnwindInfoAddress) + 4 > imageSize) { ++skipped; continue; }
        const uint8_t* unwind = base + rf.UnwindInfoAddress;
        const uint8_t countOfCodes = unwind[2];
        const uint32_t len = 4u + 2u * countOfCodes + ((countOfCodes & 1u) ? 2u : 0u);
        if (static_cast<uint64_t>(rf.UnwindInfoAddress) + len > imageSize) { ++skipped; continue; }
        // unwind[1] = SizeOfProlog（UNWIND_INFO offset 1，1 字节），用于 head-hash 的 size 口径
        PdataSig e{ rf.BeginAddress, rf.EndAddress - rf.BeginAddress, NormHash::Fnv1a64(unwind, len), unwind[1] };
        table.push_back(e);
    }
    if (table.empty()) return false;
    std::stable_sort(table.begin(), table.end(),
        [](const PdataSig& a, const PdataSig& b) { return a.begin_rva < b.begin_rva; });

    outFingerprint = ComputeTableFingerprint(table);
    outTable = std::move(table);
    outImageSize = imageSize;
    outTimeDateStamp = timeDateStamp;
    if (skipped != 0) {
        Logger::Log("PdataMatch: new pdata skipped %zu invalid entries", skipped);
    }
    return true;
}

// 全表序列对齐：窗口哈希锚点 + LIS 锚点链 + 锚点间线性插值 + 头哈希校验
std::vector<uint32_t> AlignTables(
    const std::vector<PdataSig>& oldTable,
    const std::vector<PdataSig>& newTable,
    const std::unordered_map<uint32_t, uint64_t>& headHashByRva,
    const uint8_t* newBase,
    uint32_t newImageSize,
    size_t& outAnchors) {
    const size_t n = oldTable.size();
    const size_t m = newTable.size();
    std::vector<uint32_t> mapping(n, kUnmatched);
    outAnchors = 0;
    if (n == 0 || m == 0) return mapping;

    const auto keyOf = [](const PdataSig& e) -> uint64_t {
        return (static_cast<uint64_t>(e.size) << 32) ^ e.unwind_hash;
    };

    // new 表窗口索引：键 -> 索引列表
    std::unordered_map<uint64_t, std::vector<size_t>> newByKey;
    newByKey.reserve(m);
    for (size_t i = 0; i < m; ++i) newByKey[keyOf(newTable[i])].push_back(i);

    // 锚点选取：old 单条签名在 new 中候选唯一且未被占用
    struct Anchor { size_t oldIdx; size_t newIdx; };
    std::vector<Anchor> anchors;
    std::vector<uint8_t> newUsed(m, 0);
    for (size_t oi = 0; oi < n; ++oi) {
        const uint64_t key = keyOf(oldTable[oi]);
        const auto it = newByKey.find(key);
        if (it == newByKey.end() || it->second.size() != 1) continue;
        const size_t ni = it->second[0];
        if (newUsed[ni]) continue;
        newUsed[ni] = 1;
        anchors.push_back({ oi, ni });
    }
    std::stable_sort(anchors.begin(), anchors.end(),
        [](const Anchor& a, const Anchor& b) { return a.oldIdx < b.oldIdx; });

    // LIS：按 oldIdx 已升序，对 newIdx 求严格递增最长锚点链（贪心）
    std::vector<size_t> tails, tailIdx, prev(anchors.size(), SIZE_MAX);
    for (size_t i = 0; i < anchors.size(); ++i) {
        const size_t ni = anchors[i].newIdx;
        const auto it = std::lower_bound(tails.begin(), tails.end(), ni);
        const size_t pos = static_cast<size_t>(it - tails.begin());
        if (pos != 0) prev[i] = tailIdx[pos - 1];
        if (it == tails.end()) {
            tails.push_back(ni);
            tailIdx.push_back(i);
        } else {
            *it = ni;
            tailIdx[pos] = i;
        }
    }
    std::vector<Anchor> chain;
    if (!tailIdx.empty()) {
        size_t cur = tailIdx.back();
        while (cur != SIZE_MAX) {
            chain.push_back(anchors[cur]);
            cur = prev[cur];
        }
        std::reverse(chain.begin(), chain.end());
    }
    outAnchors = chain.size();
    for (const Anchor& a : chain) mapping[a.oldIdx] = static_cast<uint32_t>(a.newIdx);

    // 锚点之间线性插值：插值处 new 签名与 old 完全相等才接受，否则保持未匹配
    for (size_t k = 0; k + 1 < chain.size(); ++k) {
        const size_t oldA = chain[k].oldIdx;
        const size_t oldB = chain[k + 1].oldIdx;
        const size_t newA = chain[k].newIdx;
        const size_t newB = chain[k + 1].newIdx;
        const size_t span = oldB - oldA;
        if (span <= 1) continue;
        for (size_t d = 1; d < span; ++d) {
            const size_t oi = oldA + d;
            const size_t ni = newA + (newB - newA) * d / span;
            if (ni < m && newTable[ni].size == oldTable[oi].size &&
                newTable[ni].unwind_hash == oldTable[oi].unwind_hash) {
                mapping[oi] = static_cast<uint32_t>(ni);
            }
        }
    }

    // 首锚点之前 / 末锚点之后外推（与插值同一规则：签名完全相等才接受；
    // 覆盖首尾边界上签名重复的小函数，超出边界外推范围的自然保持未匹配）
    if (!chain.empty()) {
        const ptrdiff_t offFirst = static_cast<ptrdiff_t>(chain.front().newIdx) -
            static_cast<ptrdiff_t>(chain.front().oldIdx);
        const ptrdiff_t offLast = static_cast<ptrdiff_t>(chain.back().newIdx) -
            static_cast<ptrdiff_t>(chain.back().oldIdx);
        const size_t oldTail = oldTable.size() - 1;
        const size_t newTail = newTable.size() - 1;

        // 首锚点之前：ni = oi + offFirst，要求 0 <= ni < m
        if (chain.front().oldIdx > 0) {
            const size_t begin = (offFirst < 0)
                ? static_cast<size_t>(-offFirst)
                : 0;
            if (begin < chain.front().oldIdx) {
                for (size_t oi = begin; oi < chain.front().oldIdx; ++oi) {
                    const size_t ni = static_cast<size_t>(static_cast<ptrdiff_t>(oi) + offFirst);
                    if (ni < m && newTable[ni].size == oldTable[oi].size &&
                        newTable[ni].unwind_hash == oldTable[oi].unwind_hash) {
                        mapping[oi] = static_cast<uint32_t>(ni);
                    }
                }
            }
        }

        // 末锚点之后：ni = oi + offLast，要求 ni <= newTail
        if (chain.back().oldIdx < oldTail) {
            const size_t maxOi = (offLast >= 0 &&
                static_cast<ptrdiff_t>(newTail) - offLast < static_cast<ptrdiff_t>(oldTail))
                ? static_cast<size_t>(static_cast<ptrdiff_t>(newTail) - offLast)
                : oldTail;
            if (maxOi > chain.back().oldIdx) {
                for (size_t oi = chain.back().oldIdx + 1; oi <= maxOi; ++oi) {
                    const size_t ni = static_cast<size_t>(static_cast<ptrdiff_t>(oi) + offLast);
                    if (ni < m && newTable[ni].size == oldTable[oi].size &&
                        newTable[ni].unwind_hash == oldTable[oi].unwind_hash) {
                        mapping[oi] = static_cast<uint32_t>(ni);
                    }
                }
            }
        }
    }

    // 头哈希校验（提升置信度）：有 normHeadHash 的 Function，比对 new 函数头 min(SizeOfProlog,32) 字节
    if (!headHashByRva.empty() && newBase != nullptr) {
        size_t verified = 0;
        size_t rejected = 0;
        for (size_t oi = 0; oi < n; ++oi) {
            if (mapping[oi] == kUnmatched) continue;
            const auto hit = headHashByRva.find(oldTable[oi].begin_rva);
            if (hit == headHashByRva.end()) continue;  // 纯 pdata 无符号 -> 跳过
            const size_t ni = mapping[oi];
            const PdataSig& ne = newTable[ni];
            // headLen 用 SizeOfProlog（序言大小），与 sidecar 生成端 normHeadHash 口径一致。
            // 序言是函数身份最稳定的信号，两边都从各自 UNWIND_INFO 读 SizeOfProlog（unwind[1]）。
            const size_t headLen = ne.prologSize < 32 ? ne.prologSize : 32;
            if (headLen == 0 ||
                static_cast<uint64_t>(ne.begin_rva) + headLen > newImageSize) {
                continue;
            }
            const uint64_t actual = NormHash::NormalizedHeadHash(newBase + ne.begin_rva, headLen);
            if (actual == hit->second) {
                ++verified;
            } else {
                mapping[oi] = kUnmatched;
                ++rejected;
            }
        }
        if (rejected != 0) {
            Logger::Log("PdataMatch: head-hash rejected %zu matches, verified %zu", rejected, verified);
        }
    }

    // v9：未匹配项局部恢复（头 hash）
    // 对 v3 + head-hash 后仍 kUnmatched 且有序言头 hash 的 old 条目，在前后最近已匹配锚点
    // 划出的 new 区间内，用 SizeOfProlog 口径头 hash 做唯一匹配恢复（函数体变了但序言没变）。
    if (!headHashByRva.empty() && newBase != nullptr) {
        // 反向占用表：new 条目是否已被映射
        std::vector<uint8_t> newUsed(m, 0);
        for (size_t oi = 0; oi < n; ++oi) {
            if (mapping[oi] != kUnmatched && mapping[oi] < m) newUsed[mapping[oi]] = 1;
        }
        // 已匹配 old 索引（升序，仅 v3 锚点/插值，不含 v9 恢复的低置信项）
        std::vector<size_t> matchedOld;
        matchedOld.reserve(n);
        for (size_t oi = 0; oi < n; ++oi) {
            if (mapping[oi] != kUnmatched) matchedOld.push_back(oi);
        }
        size_t recovered = 0;
        for (size_t oi = 0; oi < n; ++oi) {
            if (mapping[oi] != kUnmatched) continue;
            const auto hit = headHashByRva.find(oldTable[oi].begin_rva);
            if (hit == headHashByRva.end()) continue;  // 无头 hash（非函数入口）-> 跳过
            // 前后最近已匹配锚点划定 new 区间
            auto itNext = std::upper_bound(matchedOld.begin(), matchedOld.end(), oi);
            size_t lo = 0;
            size_t hi = m;
            if (itNext != matchedOld.end()) hi = mapping[*itNext];
            if (itNext != matchedOld.begin()) lo = mapping[*(itNext - 1)] + 1;
            if (lo >= hi) continue;
            // 区间内搜索头 hash 唯一匹配
            size_t matchIdx = SIZE_MAX;
            size_t matchCount = 0;
            for (size_t nj = lo; nj < hi; ++nj) {
                if (newUsed[nj]) continue;
                const PdataSig& ne = newTable[nj];
                const size_t headLen = ne.prologSize < 32 ? ne.prologSize : 32;
                if (headLen == 0 ||
                    static_cast<uint64_t>(ne.begin_rva) + headLen > newImageSize) continue;
                const uint64_t h = NormHash::NormalizedHeadHash(newBase + ne.begin_rva, headLen);
                if (h == hit->second) {
                    matchIdx = nj;
                    ++matchCount;
                    if (matchCount > 1) break;  // 非唯一，放弃
                }
            }
            if (matchCount == 1) {
                mapping[oi] = static_cast<uint32_t>(matchIdx);
                newUsed[matchIdx] = 1;
                ++recovered;
            }
        }
        if (recovered != 0) {
            Logger::Log("PdataMatch: v9 local recovery matched %zu", recovered);
        }
    }

    // v10：归一化全函数体 AOB 恢复
    // 对 v9 后仍 kUnmatched 且有 AOB 的 old 条目，在前后已匹配锚点划定的 new RVA 区间内
    // 用归一化字节（body+mask）做唯一 AOB 搜索，命中后对齐到 new pdata 函数入口。
    if (!g_aobByRva.empty() && newBase != nullptr) {
        std::vector<uint8_t> newUsed(m, 0);
        for (size_t oi = 0; oi < n; ++oi) {
            if (mapping[oi] != kUnmatched && mapping[oi] < m) newUsed[mapping[oi]] = 1;
        }
        std::vector<size_t> matchedOld;
        matchedOld.reserve(n);
        for (size_t oi = 0; oi < n; ++oi) {
            if (mapping[oi] != kUnmatched) matchedOld.push_back(oi);
        }
        size_t recovered = 0;
        for (size_t oi = 0; oi < n; ++oi) {
            if (mapping[oi] != kUnmatched) continue;
            const auto it = g_aobByRva.find(oldTable[oi].begin_rva);
            if (it == g_aobByRva.end()) continue;
            const AobInfo& info = it->second;
            const size_t span = static_cast<size_t>(info.bodySize) * 2;
            if (info.bodySize == 0 || info.dataOffset + span > g_aobData.size()) continue;
            const uint8_t* body = g_aobData.data() + info.dataOffset;
            const uint8_t* mask = body + info.bodySize;
            // 前后最近已匹配锚点划定 new RVA 区间
            auto itNext = std::upper_bound(matchedOld.begin(), matchedOld.end(), oi);
            uint64_t loRva = 0;
            uint64_t hiRva = newImageSize;
            if (itNext != matchedOld.end()) hiRva = newTable[mapping[*itNext]].begin_rva;
            if (itNext != matchedOld.begin()) {
                const PdataSig& pe = newTable[mapping[*(itNext - 1)]];
                loRva = static_cast<uint64_t>(pe.begin_rva) + pe.size;
            }
            if (loRva >= hiRva || hiRva - loRva < info.bodySize) continue;
            // AOB 唯一搜索
            const uint8_t* lo = newBase + loRva;
            const uint8_t* hi = newBase + hiRva;
            const uint8_t* hitPtr = nullptr;
            size_t hitCount = 0;
            for (const uint8_t* p = lo; p + info.bodySize <= hi; ++p) {
                bool match = true;
                for (size_t k = 0; k < info.bodySize; ++k) {
                    if (mask[k] && p[k] != body[k]) { match = false; break; }
                }
                if (match) {
                    hitPtr = p;
                    ++hitCount;
                    if (hitCount > 1) break;
                }
            }
            if (hitCount != 1) continue;
            const uintptr_t hitRva = static_cast<uintptr_t>(hitPtr - newBase);
            // 命中位置对齐到 new pdata 函数入口（begin_rva）
            const auto found = std::lower_bound(newTable.begin(), newTable.end(), hitRva,
                [](const PdataSig& e, uintptr_t v) { return e.begin_rva < v; });
            if (found == newTable.end() || found->begin_rva != hitRva) continue;
            const size_t newIdx = static_cast<size_t>(found - newTable.begin());
            if (newUsed[newIdx]) continue;
            mapping[oi] = static_cast<uint32_t>(newIdx);
            newUsed[newIdx] = 1;
            ++recovered;
        }
        if (recovered != 0) {
            Logger::Log("PdataMatch: v10 AOB recovery matched %zu", recovered);
        }
    }
    return mapping;
}

// 叶子函数 AOB 匹配：对 old_rva 不在 pdata 里的叶子符号（gap），在前后最近已匹配 pdata
// 函数划定的 new RVA 区间内用归一化字节（body+mask）做唯一 AOB 搜索。
// 返回 old_rva -> new_rva 映射（命中为叶子函数入口 RVA）。
std::unordered_map<uint32_t, uint32_t> BuildLeafMap(
    const std::vector<PdataSig>& oldTable,
    const std::vector<uint32_t>& mapping,
    const std::vector<PdataSig>& newTable,
    const uint8_t* newBase,
    uint32_t newImageSize) {
    std::unordered_map<uint32_t, uint32_t> leafMap;
    const size_t n = oldTable.size();
    const size_t m = newTable.size();
    if (m == 0) return leafMap;

    // 已匹配 old 索引（oldTable 按 begin_rva 升序，故该列表也按 begin_rva 升序）
    std::vector<size_t> matchedOld;
    matchedOld.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        if (mapping[i] != kUnmatched) matchedOld.push_back(i);
    }

    size_t recovered = 0;
    for (const auto& kv : g_aobByRva) {
        const uint32_t rva = kv.first;
        const AobInfo& info = kv.second;
        const size_t span = static_cast<size_t>(info.bodySize) * 2;
        if (info.bodySize == 0 || info.dataOffset + span > g_aobData.size()) continue;
        // 包含判断：rva 在某个 pdata 条目内 = 非叶子，跳过
        bool inPdata = false;
        {
            size_t lo = 0, hi = n;
            while (lo < hi) {
                const size_t mid = lo + (hi - lo) / 2;
                if (oldTable[mid].begin_rva <= rva) lo = mid + 1;
                else hi = mid;
            }
            if (lo > 0) {
                size_t idx = lo - 1;
                size_t scanned = 0;
                for (;;) {
                    const PdataSig& oe = oldTable[idx];
                    if (rva < static_cast<uintptr_t>(oe.begin_rva) + oe.size) { inPdata = true; break; }
                    if (idx == 0 || scanned >= 64) break;
                    --idx;
                    ++scanned;
                }
            }
        }
        if (inPdata) continue;
        // 前后最近已匹配 pdata 函数划定 new RVA 区间
        auto itNext = std::lower_bound(matchedOld.begin(), matchedOld.end(), rva,
            [&](size_t idx, uint32_t v) { return oldTable[idx].begin_rva < v; });
        uint64_t loRva = 0;
        uint64_t hiRva = newImageSize;
        if (itNext != matchedOld.end()) hiRva = newTable[mapping[*itNext]].begin_rva;
        if (itNext != matchedOld.begin()) {
            const PdataSig& pe = newTable[mapping[*(itNext - 1)]];
            loRva = static_cast<uint64_t>(pe.begin_rva) + pe.size;
        }
        if (loRva >= hiRva || hiRva - loRva < info.bodySize) continue;
        // AOB 唯一搜索
        const uint8_t* body = g_aobData.data() + info.dataOffset;
        const uint8_t* mask = body + info.bodySize;
        const uint8_t* lo = newBase + loRva;
        const uint8_t* hi = newBase + hiRva;
        const uint8_t* hitPtr = nullptr;
        size_t hitCount = 0;
        for (const uint8_t* p = lo; p + info.bodySize <= hi; ++p) {
            bool match = true;
            for (size_t k = 0; k < info.bodySize; ++k) {
                if (mask[k] && p[k] != body[k]) { match = false; break; }
            }
            if (match) {
                hitPtr = p;
                ++hitCount;
                if (hitCount > 1) break;
            }
        }
        if (hitCount != 1) continue;
        const uint32_t hitRva = static_cast<uint32_t>(hitPtr - newBase);
        leafMap.emplace(rva, hitRva);
        ++recovered;
    }
    if (recovered != 0) {
        Logger::Log("PdataMatch: leaf AOB recovery matched %zu", recovered);
    }
    return leafMap;
}

// 矫正任意 old RVA（局部版本）：pdata 条目走 mapping，gap 走叶子 AOB 结果
uint32_t CorrectRvaLocal(uint32_t rva,
    const std::vector<PdataSig>& oldTable,
    const std::vector<uint32_t>& mapping,
    const std::vector<PdataSig>& newTable,
    const std::unordered_map<uint32_t, uint32_t>& leafMap) {
    const size_t n = oldTable.size();
    size_t lo = 0, hi = n;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (oldTable[mid].begin_rva <= rva) lo = mid + 1;
        else hi = mid;
    }
    if (lo > 0) {
        size_t idx = lo - 1;
        size_t scanned = 0;
        for (;;) {
            const PdataSig& oe = oldTable[idx];
            if (rva < static_cast<uintptr_t>(oe.begin_rva) + oe.size) {
                const uint32_t newIdx = mapping[idx];
                if (newIdx == kUnmatched || newIdx >= newTable.size()) return 0;
                const PdataSig& ne = newTable[newIdx];
                const uintptr_t offset = rva - oe.begin_rva;
                if (offset == 0) return ne.begin_rva;
                if (ne.size == oe.size) return ne.begin_rva + static_cast<uint32_t>(offset);
                return 0;
            }
            if (idx == 0 || scanned >= 64) break;
            --idx;
            ++scanned;
        }
    }
    const auto lit = leafMap.find(rva);
    return lit != leafMap.end() ? lit->second : 0;
}

// vtable 跨版本定位：矫正槽函数（pdata 或叶子）后，在 new 的 .rdata 段里搜
// 「槽函数绝对地址的指针序列」（vtable 里存的就是槽函数地址指针）。
// 优先级：单个 pdata 槽函数 → 连续 pdata 槽函数组合 → 单个叶子槽函数 → 连续叶子组合。
// 命中唯一则 vtable 新地址 = 命中位置 - 序列首槽 offset。
std::unordered_map<uint32_t, uint32_t> BuildVtableMap(
    const std::vector<VtableInfo>& vtables,
    const std::vector<PdataSig>& oldTable,
    const std::vector<uint32_t>& mapping,
    const std::vector<PdataSig>& newTable,
    const std::unordered_map<uint32_t, uint32_t>& leafMap,
    const uint8_t* newBase,
    uint32_t newImageSize) {
    std::unordered_map<uint32_t, uint32_t> vtableMap;
    if (!newBase || vtables.empty()) return vtableMap;

    // 解析 new 映像的 .rdata 段范围
    uintptr_t rdataVa = 0;
    size_t rdataSize = 0;
    {
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(newBase);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(newBase + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                const auto* sec = IMAGE_FIRST_SECTION(nt);
                for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
                    char name[9]{};
                    std::memcpy(name, sec->Name, 8);
                    if (std::strcmp(name, ".rdata") == 0) {
                        rdataVa = sec->VirtualAddress;
                        rdataSize = std::max<size_t>(sec->Misc.VirtualSize, sec->SizeOfRawData);
                        break;
                    }
                }
            }
        }
    }
    if (rdataVa == 0 || rdataSize < 8) return vtableMap;
    const uint8_t* rdataBegin = newBase + rdataVa;
    const uint8_t* rdataEnd = rdataBegin + rdataSize;
    const uint8_t* imgEnd = newBase + newImageSize;
    if (rdataEnd > imgEnd) rdataEnd = imgEnd;

    // 搜索辅助：在 .rdata 里搜一段 8 字节对齐的指针序列，唯一命中返回位置（否则 nullptr）
    const auto searchPtrs = [&](const std::vector<uint64_t>& absList) -> const uint8_t* {
        if (absList.empty()) return nullptr;
        std::vector<uint8_t> pat(absList.size() * 8);
        for (size_t i = 0; i < absList.size(); ++i) {
            std::memcpy(pat.data() + i * 8, &absList[i], 8);
        }
        const uint8_t* hit = nullptr;
        size_t count = 0;
        for (const uint8_t* p = rdataBegin; p + pat.size() <= rdataEnd; p += 8) {
            if (std::memcmp(p, pat.data(), pat.size()) == 0) {
                if (count == 0) hit = p;
                ++count;
                if (count > 1) return nullptr;  // 多命中，放弃
            }
        }
        return (count == 1) ? hit : nullptr;
    };

    size_t recovered = 0;
    for (const VtableInfo& vt : vtables) {
        // 矫正全部槽函数：收集 (offset, 绝对地址, 是否叶子)
        struct SlotC { uint32_t offset; uint64_t abs; bool leaf; };
        std::vector<SlotC> all;
        all.reserve(vt.slots.size());
        for (const VtableSlot& s : vt.slots) {
            const uint32_t f = CorrectRvaLocal(s.slotOldRva, oldTable, mapping, newTable, leafMap);
            if (f == 0) continue;
            const bool leaf = leafMap.find(s.slotOldRva) != leafMap.end();
            all.push_back(SlotC{ s.slotOffset,
                static_cast<uint64_t>(reinterpret_cast<uintptr_t>(newBase) + f), leaf });
        }
        if (all.empty()) continue;

        // 分 pdata 与叶子（slot 按 offset 升序，sidecar 生成端保证）
        std::vector<SlotC> pdataCs, leafCs;
        for (const SlotC& c : all) (c.leaf ? leafCs : pdataCs).push_back(c);

        const uint8_t* hit = nullptr;
        uint32_t hitOffset = 0;

        // 1) 单个 pdata 槽函数
        for (const SlotC& c : pdataCs) {
            const uint8_t* h = searchPtrs({ c.abs });
            if (h) { hit = h; hitOffset = c.offset; break; }
        }
        // 2) 连续 pdata 槽函数组合（2 个起）
        if (!hit && pdataCs.size() >= 2) {
            for (size_t i = 0; i < pdataCs.size() && !hit; ++i) {
                std::vector<uint64_t> seq;
                seq.push_back(pdataCs[i].abs);
                for (size_t j = i + 1; j < pdataCs.size(); ++j) {
                    if (pdataCs[j].offset != pdataCs[j - 1].offset + 8) break;  // 必须连续
                    seq.push_back(pdataCs[j].abs);
                    const uint8_t* h = searchPtrs(seq);
                    if (h) { hit = h; hitOffset = pdataCs[i].offset; break; }
                }
            }
        }
        // 3) 单个叶子槽函数
        if (!hit) {
            for (const SlotC& c : leafCs) {
                const uint8_t* h = searchPtrs({ c.abs });
                if (h) { hit = h; hitOffset = c.offset; break; }
            }
        }
        // 4) 连续叶子槽函数组合（2 个起）
        if (!hit && leafCs.size() >= 2) {
            for (size_t i = 0; i < leafCs.size() && !hit; ++i) {
                std::vector<uint64_t> seq;
                seq.push_back(leafCs[i].abs);
                for (size_t j = i + 1; j < leafCs.size(); ++j) {
                    if (leafCs[j].offset != leafCs[j - 1].offset + 8) break;
                    seq.push_back(leafCs[j].abs);
                    const uint8_t* h = searchPtrs(seq);
                    if (h) { hit = h; hitOffset = leafCs[i].offset; break; }
                }
            }
        }

        if (hit) {
            const uintptr_t hitRva = static_cast<uintptr_t>(hit - newBase);
            if (hitRva >= hitOffset) {
                vtableMap.emplace(vt.old_rva, static_cast<uint32_t>(hitRva - hitOffset));
                ++recovered;
            }
        }
    }
    if (recovered != 0) {
        Logger::Log("PdataMatch: vtable recovery matched %zu", recovered);
    }
    return vtableMap;
}

// exe 目录下 Civ6DllLoader\pdata_cache.bin（目录不存在则创建）
std::wstring CachePath() {
    wchar_t exePath[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return {};
    std::wstring dir(exePath);
    const size_t slash = dir.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return {};
    dir.resize(slash + 1);
    dir += kCacheDirName;
    CreateDirectoryW(dir.c_str(), nullptr);  // 已存在则忽略失败（后续写失败仅记日志）
    dir += L"\\";
    dir += kCacheFileName;
    return dir;
}

bool LoadCache(const std::wstring& path, uint64_t fingerprint, uint64_t oldFingerprint,
    size_t expectedCount, size_t newCount, std::vector<uint32_t>& outMap) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    bool ok = false;
    do {
        LARGE_INTEGER li{};
        if (!GetFileSizeEx(file, &li) || li.QuadPart < static_cast<LONGLONG>(sizeof(CacheHeader))) break;
        const size_t fileSize = static_cast<size_t>(li.QuadPart);
        std::vector<uint8_t> buf(fileSize);
        DWORD read = 0;
        if (!ReadFile(file, buf.data(), static_cast<DWORD>(buf.size()), &read, nullptr) ||
            read != buf.size()) break;
        CacheHeader hdr{};
        std::memcpy(&hdr, buf.data(), sizeof(hdr));
        if (std::memcmp(hdr.magic, kCacheMagic, 4) != 0 || hdr.version != kCacheVersion) break;
        if (hdr.fingerprint != fingerprint || hdr.oldFingerprint != oldFingerprint ||
            hdr.entryCount != expectedCount) break;
        if (sizeof(CacheHeader) + static_cast<uint64_t>(hdr.entryCount) * sizeof(uint32_t) > fileSize) break;
        outMap.resize(hdr.entryCount);
        std::memcpy(outMap.data(), buf.data() + sizeof(CacheHeader), outMap.size() * sizeof(uint32_t));
        bool valid = true;
        for (const uint32_t newIdx : outMap) {
            if (newIdx != kUnmatched && static_cast<size_t>(newIdx) >= newCount) {
                valid = false;
                break;
            }
        }
        if (!valid) {
            outMap.clear();
            break;
        }
        ok = true;
    } while (false);
    CloseHandle(file);
    return ok;
}

bool SaveCache(const std::wstring& path, uint64_t fingerprint, uint64_t oldFingerprint,
    const std::vector<uint32_t>& map) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    CacheHeader hdr{};
    std::memcpy(hdr.magic, kCacheMagic, 4);
    hdr.version = kCacheVersion;
    hdr.fingerprint = fingerprint;
    hdr.oldFingerprint = oldFingerprint;
    hdr.entryCount = static_cast<uint32_t>(map.size());
    bool ok = false;
    DWORD written = 0;
    do {
        if (!WriteFile(file, &hdr, sizeof(hdr), &written, nullptr) || written != sizeof(hdr)) break;
        if (map.empty()) { ok = true; break; }
        written = 0;
        const DWORD bytes = static_cast<DWORD>(map.size() * sizeof(uint32_t));
        if (!WriteFile(file, map.data(), bytes, &written, nullptr) || written != bytes) break;
        ok = true;
    } while (false);
    CloseHandle(file);
    return ok;
}

// 需持有 g_mutex 调用：在 old pdata 表二分查找包含 oldRva 的条目并矫正
uintptr_t CorrectRvaLocked(uintptr_t oldRva) {
    // 版本一致：跳过一切 pdata 匹配，直接恒等解析（gap 符号/vtable 的 RVA 也有效）
    if (g_identical) return oldRva;
    if (!g_tableReady || g_oldPdata.empty() || g_newPdata.empty() ||
        g_map.size() != g_oldPdata.size()) {
        return 0;
    }
    // 二分：最后一个 begin_rva <= oldRva 的条目（pdata 允许嵌套，先取最内层候选）
    size_t lo = 0;
    size_t hi = g_oldPdata.size();
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (g_oldPdata[mid].begin_rva <= oldRva) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) {
        // gap（第一个函数之前）：查叶子 AOB 匹配结果
        const auto lit = g_leafMap.find(static_cast<uint32_t>(oldRva));
        return lit != g_leafMap.end() ? lit->second : 0;
    }

    // 从最内层候选向前回扫找包含 oldRva 的条目（嵌套深度通常 <= 3，封顶防退化）
    constexpr size_t kMaxBackscan = 64;
    size_t idx = lo - 1;
    size_t scanned = 0;
    for (;;) {
        const PdataSig& oe = g_oldPdata[idx];
        if (oldRva < static_cast<uintptr_t>(oe.begin_rva) + oe.size) break;  // 包含
        if (idx == 0 || scanned >= kMaxBackscan) {
            // gap / 数据段：查叶子 AOB 匹配结果
            const auto lit = g_leafMap.find(static_cast<uint32_t>(oldRva));
            return lit != g_leafMap.end() ? lit->second : 0;
        }
        --idx;
        ++scanned;
    }

    const size_t oldIdx = idx;
    const PdataSig& oe = g_oldPdata[oldIdx];
    const uint32_t newIdx = g_map[oldIdx];
    if (newIdx == kUnmatched || newIdx >= g_newPdata.size()) return 0;
    const PdataSig& ne = g_newPdata[newIdx];
    const uintptr_t offset = oldRva - oe.begin_rva;
    if (offset == 0) return ne.begin_rva;                        // 函数开头
    if (ne.size == oe.size) return ne.begin_rva + offset;        // size 不变才允许内部偏移
    return 0;                                                    // deny
}

}  // namespace

bool Init(HMODULE runtimeModule) {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_oldPdata.clear();
        g_symbols.clear();
        g_byDemangled.clear();
        g_byMangled.clear();
        g_headHashByRva.clear();
        g_aobData.clear();
        g_aobByRva.clear();
        g_oldFingerprint = 0;
        g_identical = false;
        g_leafMap.clear();
        g_baseSizeOfImage = 0;
        g_baseTimeDateStamp = 0;
        g_loaded = false;
        g_newPdata.clear();
        g_map.clear();
        g_fingerprint = 0;
        g_tableReady = false;
    }
    if (LoadSidecar(runtimeModule)) return true;
    if (LoadSidecarResource(runtimeModule)) return true;
    Logger::Log("PdataMatch: no sidecar (Civ6DllLoader.symdb.bin or RCDATA 102) - pdata correction unavailable");
    return false;
}

bool BuildNewTable(HMODULE gameCore) {
    std::vector<PdataSig> oldTable;
    std::unordered_map<uint32_t, uint64_t> headHashByRva;
    std::vector<VtableInfo> vtables;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_loaded || g_oldPdata.empty()) {
            Logger::Log("PdataMatch: BuildNewTable without sidecar (Init failed)");
            return false;
        }
        oldTable = g_oldPdata;
        headHashByRva = g_headHashByRva;
        for (const Symbol& sym : g_symbols) {
            if (sym.kind == 1 && !sym.slots.empty()) {
                VtableInfo vi;
                vi.old_rva = sym.old_rva;
                vi.slots = sym.slots;
                vtables.push_back(std::move(vi));
            }
        }
    }

    std::vector<PdataSig> newTable;
    uint64_t fingerprint = 0;
    uint32_t imageSize = 0;
    uint32_t timeDateStamp = 0;
    if (!ParseNewPdata(gameCore, newTable, fingerprint, imageSize, timeDateStamp)) {
        Logger::Log("PdataMatch: BuildNewTable failed to parse new .pdata");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (imageSize != g_baseSizeOfImage || timeDateStamp != g_baseTimeDateStamp) {
            Logger::Log("PdataMatch: GameCore identity mismatch "
                        "(sidecar size=0x%08X timestamp=0x%08X; "
                        "loaded size=0x%08X timestamp=0x%08X)",
                g_baseSizeOfImage, g_baseTimeDateStamp, imageSize, timeDateStamp);
            return false;
        }
    }
    Logger::Log("PdataMatch: new pdata entries=%zu fingerprint=0x%016llX",
        newTable.size(), static_cast<unsigned long long>(fingerprint));

    std::vector<uint32_t> mapping;
    bool fromCache = false;
    size_t anchors = 0;

    // 恒等检查：old/new pdata 逐条完全一致 -> 版本未变，直接恒等映射（100% 覆盖、零回归）。
    // 版本一致时走这条路径，避免全表匹配漏配极小函数（如 19 字节的 MakeHash）导致
    // ResolveByRva 误返回 null。
    bool identical = oldTable.size() == newTable.size();
    if (identical) {
        for (size_t i = 0; i < oldTable.size(); ++i) {
            if (oldTable[i].begin_rva != newTable[i].begin_rva ||
                oldTable[i].size != newTable[i].size ||
                oldTable[i].unwind_hash != newTable[i].unwind_hash) {
                identical = false;
                break;
            }
        }
    }

    if (identical) {
        mapping.resize(oldTable.size());
        for (size_t i = 0; i < mapping.size(); ++i) mapping[i] = static_cast<uint32_t>(i);
        Logger::Log("PdataMatch: pdata identical (version unchanged) -> identity mapping entries=%zu",
            mapping.size());
    } else {
        const std::wstring cachePath = CachePath();
        if (!cachePath.empty() && LoadCache(cachePath, fingerprint, g_oldFingerprint,
                oldTable.size(), newTable.size(), mapping)) {
            fromCache = true;
            Logger::Log("PdataMatch: cache hit (fingerprint=0x%016llX, entries=%zu)",
                static_cast<unsigned long long>(fingerprint), mapping.size());
        } else {
            mapping = AlignTables(oldTable, newTable, headHashByRva,
                reinterpret_cast<const uint8_t*>(gameCore), imageSize, anchors);
            Logger::Log("PdataMatch: aligned old=%zu new=%zu anchors=%zu",
                oldTable.size(), newTable.size(), anchors);
            if (!cachePath.empty()) {
                if (SaveCache(cachePath, fingerprint, g_oldFingerprint, mapping)) {
                    Logger::Log("PdataMatch: cache saved");
                } else {
                    Logger::Log("PdataMatch: cache save failed (non-fatal)");
                }
            }
        }
    }

    // 叶子函数 AOB 匹配 + vtable 槽位反推（仅跨版本；版本一致时恒等解析，无需匹配）
    std::unordered_map<uint32_t, uint32_t> leafMap;
    if (!identical) {
        leafMap = BuildLeafMap(oldTable, mapping, newTable,
            reinterpret_cast<const uint8_t*>(gameCore), imageSize);
        // vtable 定位：矫正槽函数后在 .rdata 搜指针序列，结果并入 leafMap
        const auto vtableMap = BuildVtableMap(vtables, oldTable, mapping, newTable, leafMap,
            reinterpret_cast<const uint8_t*>(gameCore), imageSize);
        for (const auto& kv : vtableMap) leafMap.emplace(kv.first, kv.second);
    }

    size_t matched = 0;
    for (uint32_t v : mapping) if (v != kUnmatched) ++matched;
    if (matched == 0) {
        Logger::Log("PdataMatch: BuildNewTable: zero matches - correction unavailable");
        return false;
    }

    const size_t newCount = newTable.size();
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_newPdata = std::move(newTable);
        g_map = std::move(mapping);
        g_leafMap = std::move(leafMap);
        g_fingerprint = fingerprint;
        g_identical = identical;
        g_tableReady = true;
    }
    Logger::Log("PdataMatch: table ready old=%zu new=%zu matched=%zu%s",
        oldTable.size(), newCount, matched, fromCache ? " (from cache)" : "");
    return true;
}

uintptr_t CorrectRva(uintptr_t oldRva) {
    std::lock_guard<std::mutex> lock(g_mutex);
    return CorrectRvaLocked(oldRva);
}

uintptr_t CorrectByName(const char* name) {
    if (!name || !*name) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    // 两个 map 分别独立查找，避免跨容器迭代器比较（UB，Debug 下 _ITERATOR_DEBUG_LEVEL=2 会 assert）
    size_t symIdx = SIZE_MAX;  // SIZE_MAX 来自 <cstdint>（本文件已使用）
    const auto itD = g_byDemangled.find(name);
    if (itD != g_byDemangled.end()) {
        symIdx = itD->second;
    } else {
        const auto itM = g_byMangled.find(name);
        if (itM != g_byMangled.end()) symIdx = itM->second;
    }
    if (symIdx == SIZE_MAX || symIdx >= g_symbols.size()) return 0;
    const uint32_t oldRva = g_symbols[symIdx].old_rva;
    if (oldRva == 0) return 0;
    return CorrectRvaLocked(oldRva);  // 函数开头矫正（vtable 等非 pdata 符号自然返回 0）
}

uint64_t Fingerprint() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_fingerprint;
}

bool CorrectVTableByName(const char* name, uint32_t& outRva, uint32_t& outSlotCount) {
    if (!name || !*name) return false;
    std::lock_guard<std::mutex> lock(g_mutex);
    size_t symIdx = SIZE_MAX;
    const auto itD = g_byDemangled.find(name);
    if (itD != g_byDemangled.end()) {
        symIdx = itD->second;
    } else {
        const auto itM = g_byMangled.find(name);
        if (itM != g_byMangled.end()) symIdx = itM->second;
    }
    if (symIdx == SIZE_MAX || symIdx >= g_symbols.size()) return false;
    const Symbol& sym = g_symbols[symIdx];
    if (sym.kind != 1 || sym.slots.empty()) return false;  // 非 vtable
    // vtable RVA 矫正：版本一致恒等；跨版本查 g_leafMap（vtable 槽位结构匹配结果）
    const uintptr_t corrected = CorrectRvaLocked(sym.old_rva);
    if (corrected == 0) return false;
    outRva = static_cast<uint32_t>(corrected);
    outSlotCount = static_cast<uint32_t>(sym.slots.size());
    return true;
}

}  // namespace PdataMatch
