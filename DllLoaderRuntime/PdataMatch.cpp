// PdataMatch.cpp — pdata 匹配 RVA 矫正
//
// 游戏更新后 GameCore_XP2 的 RVA 变化：通过 PE 异常目录（.pdata）对函数做跨版本匹配，
// 把 old RVA（sidecar 签名表）矫正为 new RVA（当前加载的 GameCore 映像）。
//
// sidecar 二进制格式（Civ6DllLoader.symdb.bin，小端，pack(1)）——只有一种：多模块扁平容器。
//
// 多模块扁平容器（唯一格式；单模块符号库也是它，moduleCount=1）：
//   Header(32B)  : "C6SD" + version=1 + moduleCount + moduleTableOffset/moduleTableSize
//                  + dataOffset + flags + reserved
//   ModuleDesc   : 64B/模块 = imageId(1=ExeDx11,2=ExeDx12,5=GameCoreXP2)
//                  + baseSizeOfImage + baseTimeDateStamp
//                  + pdataOffset/pdataCount + symbolOffset/symbolCount
//                  + vtableOffset/vtableSlotCount + heapOffset/heapSize
//                  + aobOffset/aobSize + reserved[3]（offset 均为文件绝对偏移）
//   数据块        : 各模块 5 段依次排列（8B 对齐）：pdata / 符号 / vtable 槽位 / 字符串堆 / AOB
//
// 通用表结构：
//   pdata 签名表  : 16B/条 = begin_rva + size + unwind_hash（按 begin_rva 递增）
//   符号表        : 32B/条 = demangledNameOffset + mangledNameOffset + old_rva
//                  + kind(0=Function,1=vtable) + vtableSlotCount(u16) + reserved(u8)
//                  + normHeadHash + reserved2 + reserved3（nameOffset 相对堆）
//   vtable 槽位表 : 8B/条 = slotOffset + slotOldRva（按 vtable 符号出现顺序连续）
//   字符串堆      : NUL 结尾 UTF-8 名字连续存放
//   AOB 表        : 每条 Function = bodySize(u32) + body[n] + mask[n]（变长，n<=64）
//
// 压缩信封（Civ6DllLoader.symdb.bin.xp，RCDATA 102；只有侧载文件/资源用，裸 bin 不需要）：
//   "C6XC" + u32 algo(=1, LZMA1) + u32 original_size + payload（13B .lzma 头 + LZMA1 流）
//   未压缩 = 直接以 "C6SD" 开头（旁路文件 Civ6DllLoader.symdb.bin 的原样）
//
// 流程：Init（加载/解析 sidecar）→ BuildNewTable（身份判定 → 恒等 或 全表对齐 + 缓存）
//   → CorrectRva / CorrectByName（查询 old->new 映射）。
// BuildNewTable 身份判定顺序（与 sidecar 头记录比对）：
//   1) SizeOfImage + FileHeader.TimeDateStamp 一致 = 同一构建 → 恒等映射，不再比较 pdata；
//   2) 头身份不同 → 逐条比较 pdata 表，一致（纯重建、函数边界未变）→ 同样恒等映射；
//   3) 两者都不同 → 启动跨版本匹配（缓存 / 全表对齐 / 叶子 AOB / vtable）。
// 对齐 = 窗口哈希锚点（唯一候选）+ LIS 锚点链（old 递增且 new 递增）
//   + 锚点间线性插值（插值处签名全等才接受）+ 头哈希校验（有 normHeadHash 的 Function）。

#include "pch.h"

#include "PdataMatch.h"
#include "NormHash.h"
#include "../common/Logger.h"
#include "../third_party/lzma/LzmaDec.h"

#include <Windows.h>

#include <algorithm>
#include <cstdlib>
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
constexpr uint32_t kSidecarVersion = 1;      // 唯一版本：多模块扁平容器（单模块符号库 = moduleCount 1）
constexpr uint32_t kSidecarResourceId = 102;  // RCDATA 资源 id（旧资源 101 已随旧符号库退役，勿复用）
constexpr wchar_t kSidecarFileName[] = L"Civ6DllLoader.symdb.bin";

// ---- 压缩信封（RCDATA 102 / 旁路 .xp；裸 bin 以 "C6SD" 开头，不走这里）----
//
// 信封: "C6XC" + u32 algo + u32 originalSize + payload
//   algo 1 = LZMA1（唯一算法；LzmaDec，third_party/lzma；payload = .lzma 头 13B + LZMA1 流）
constexpr char kCompressedMagic[4] = { 'C', '6', 'X', 'C' };
constexpr uint32_t kCompressAlgoLzma = 1;         // LZMA1（自带解码器）
constexpr size_t kLzmaHeaderSize = 13;            // .lzma: 5B props(lc/lp/pb + dictSize) + 8B 原始大小

constexpr uint32_t kMaxPdataCount = 4'000'000;
constexpr uint32_t kMaxSymbolCount = 4'000'000;
constexpr uint64_t kMaxHeapBytes = 256ull * 1024 * 1024;
constexpr uint32_t kMaxVtableSlots = 4'000'000;
constexpr uint32_t kUnmatched = UINT32_MAX;

// ---- 磁盘缓存（exe 目录 Civ6DllLoader\pdata_cache.bin）----

constexpr char kCacheMagic[4] = { 'C', '6', 'P', 'C' };
constexpr uint32_t kCacheVersion = 1;
constexpr wchar_t kCacheDirName[] = L"Civ6DllLoader";
constexpr wchar_t kCacheFileName[] = L"pdata_cache.bin";

#pragma pack(push, 1)
struct ContainerHeader {         // 32 字节
    char magic[4];
    uint32_t version;            // kSidecarVersion
    uint32_t moduleCount;
    uint32_t moduleTableOffset;
    uint32_t moduleTableSize;
    uint32_t dataOffset;
    uint32_t flags;
    uint32_t reserved;
};
struct ModuleDesc {              // 64 字节/模块
    uint32_t imageId;            // 1=ExeDx11, 2=ExeDx12, 5=GameCoreXP2
    uint32_t baseSizeOfImage;
    uint32_t baseTimeDateStamp;  // 源 PE FileHeader.TimeDateStamp
    uint32_t pdataOffset;        // 以下 offset 均为文件绝对偏移
    uint32_t pdataCount;
    uint32_t symbolOffset;
    uint32_t symbolCount;
    uint32_t vtableOffset;
    uint32_t vtableSlotCount;
    uint32_t heapOffset;
    uint32_t heapSize;
    uint32_t aobOffset;
    uint32_t aobSize;
    uint32_t reserved[3];
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
    uint16_t vtableSlotCount;      // vtable 槽位数（16 位；pack(1) 占 +13..+14）
    uint8_t reserved;              // 保留（0）
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

static_assert(sizeof(ContainerHeader) == 32, "ContainerHeader must be 32 bytes");
static_assert(sizeof(ModuleDesc) == 64, "ModuleDesc must be 64 bytes");
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
struct AobInfo {                // 函数体 AOB 条目信息
    uint32_t bodySize = 0;
    size_t dataOffset = 0;      // 在 g_aobData 里的偏移（body 起始，mask 紧随其后）
};
struct VtableInfo {              // vtable 符号信息（跨版本定位用）
    uint32_t old_rva = 0;        // vtable 地址（.rdata）
    std::vector<VtableSlot> slots;  // 槽位表（offset + funcRva，含叶子槽函数）
};
std::vector<uint8_t> g_aobData;                    // 函数体 AOB 表原始数据
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

// ---- 多模块上下文（每个 HookImageId 一份）----
struct ContextState {
    uint32_t imageId = 0;
    uint32_t baseSizeOfImage = 0;
    uint32_t baseTimeDateStamp = 0;
    std::vector<PdataSig> oldPdata;
    std::vector<Symbol> symbols;
    std::unordered_map<std::string, size_t> byDemangled;
    std::unordered_map<std::string, size_t> byMangled;
    std::unordered_map<uint32_t, uint64_t> headHashByRva;
    std::vector<uint8_t> aobData;
    std::unordered_map<uint32_t, AobInfo> aobByRva;
    uint64_t oldFingerprint = 0;
    bool loaded = false;
    bool identical = false;
    std::unordered_map<uint32_t, uint32_t> leafMap;
    std::vector<PdataSig> newPdata;
    std::vector<uint32_t> map;
    uint64_t fingerprint = 0;
    bool tableReady = false;
};
static std::unordered_map<uint32_t, ContextState> g_contexts;  // imageId -> 上下文

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

// LZMA1 解码（third_party/lzma）。payload = .lzma 头（5B props + 8B 原始大小）+ LZMA1 流；
// LzmaDecode 把 dest 直接当字典用（dicSize 必须 <= destLen），一次解完，无需额外窗口内存。
bool LzmaDecodeRaw(const uint8_t* payload, size_t payloadLen, uint32_t origSize,
    std::vector<uint8_t>& out) {
    if (payloadLen <= kLzmaHeaderSize) {
        Logger::Log("PdataMatch: lzma payload too small (%zu)", payloadLen);
        return false;
    }
    // .lzma 头的 8 字节原始大小若已知（非 0xFF...）则必须与信封一致
    uint64_t declared = 0;
    for (int i = 0; i < 8; ++i) declared |= static_cast<uint64_t>(payload[5 + i]) << (8 * i);
    if (declared != UINT64_MAX && declared != origSize) {
        Logger::Log("PdataMatch: lzma size mismatch (header=%llu envelope=%u)",
            static_cast<unsigned long long>(declared), origSize);
        return false;
    }
    const uint8_t* stream = payload + kLzmaHeaderSize;
    const SizeT streamLen = static_cast<SizeT>(payloadLen - kLzmaHeaderSize);
    if (streamLen < LZMA_REQUIRED_INPUT_MAX) {
        Logger::Log("PdataMatch: lzma stream too small (%zu)", payloadLen - kLzmaHeaderSize);
        return false;
    }

    struct SzAllocator final : ISzAlloc {
        static void* AllocImpl(void* self, size_t size) { (void)self; return std::malloc(size); }
        static void FreeImpl(void* self, void* address) { (void)self; std::free(address); }
        SzAllocator() { Alloc = &AllocImpl; Free = &FreeImpl; }
    };
    SzAllocator alloc;

    out.resize(origSize);
    SizeT destLen = static_cast<SizeT>(origSize);
    SizeT srcLen = streamLen;
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
    const SRes res = LzmaDecode(out.data(), &destLen, stream, &srcLen,
        payload, LZMA_PROPS_SIZE, LZMA_FINISH_END, &status, &alloc);
    if (res != SZ_OK || destLen != origSize) {
        Logger::Log("PdataMatch: LzmaDecode failed res=%d destLen=%zu want=%u status=%d",
            static_cast<int>(res), static_cast<size_t>(destLen), origSize, static_cast<int>(status));
        out.clear();
        return false;
    }
    // LzmaDecode 会把 *srcLen 更新为实际消费字节数：必须整段用完（尾部多余 = 载荷被改过）。
    if (srcLen != streamLen) {
        Logger::Log("PdataMatch: lzma payload trailing bytes (consumed=%zu of %zu)",
            static_cast<size_t>(srcLen), static_cast<size_t>(streamLen));
        out.clear();
        return false;
    }
    return true;
}

// 解压 sidecar（自带 LZMA1 解码器，与 tools/compress_sidecar.py 对称）：
//   "C6XC" + u32 algo(=1) + u32 originalSize + payload（13B .lzma 头 + LZMA1 流）
// 未压缩文件以 "C6SD" 开头，调用方直接透传给 ParseContainer。
bool DecompressSidecar(const std::vector<uint8_t>& packed, std::vector<uint8_t>& out) {
    if (packed.size() < 12 || std::memcmp(packed.data(), kCompressedMagic, 4) != 0) {
        Logger::Log("PdataMatch: bad sidecar envelope (%zu bytes, no C6XC magic)", packed.size());
        return false;
    }
    uint32_t algoTag = 0;
    uint32_t origSize = 0;
    std::memcpy(&algoTag, packed.data() + 4, 4);
    std::memcpy(&origSize, packed.data() + 8, 4);
    if (algoTag != kCompressAlgoLzma) {
        Logger::Log("PdataMatch: unknown compress algo %u", algoTag);
        return false;
    }
    if (origSize == 0 || origSize > 512u * 1024 * 1024) return false;  // 安全上限

    const uint8_t* src = packed.data() + 12;
    const size_t srcLen = static_cast<size_t>(packed.size() - 12);
    if (!LzmaDecodeRaw(src, srcLen, origSize, out)) return false;
    Logger::Log("PdataMatch: sidecar decompressed algo=lzma %zu -> %u bytes", srcLen, origSize);
    return true;
}

// 解析容器内一个模块的数据段（data = 容器字节；各段偏移为文件绝对偏移，身份已由调用方校验）
bool ParseModuleData(const uint8_t* data, size_t size, const ModuleDesc& m, const char* sourceTag) {
    if (!data) return false;
    const uint32_t aobOffset = m.aobOffset;
    uint32_t aobSize = m.aobSize;
    if (m.pdataCount > kMaxPdataCount || m.symbolCount > kMaxSymbolCount ||
        m.heapSize > kMaxHeapBytes || m.vtableSlotCount > kMaxVtableSlots) {
        Logger::Log("PdataMatch: %s unreasonable counts (pdata=%u symbols=%u heap=%u slots=%u)",
            sourceTag, m.pdataCount, m.symbolCount, m.heapSize, m.vtableSlotCount);
        return false;
    }
    const uint64_t pdataEnd = static_cast<uint64_t>(m.pdataOffset) +
        static_cast<uint64_t>(m.pdataCount) * 16;  // sidecar pdata 表固定 16 字节/条
    const uint64_t symbolEnd = static_cast<uint64_t>(m.symbolOffset) +
        static_cast<uint64_t>(m.symbolCount) * sizeof(SymbolEntry);
    const uint64_t heapEnd = static_cast<uint64_t>(m.heapOffset) + m.heapSize;
    const uint64_t slotEnd = static_cast<uint64_t>(m.vtableOffset) +
        static_cast<uint64_t>(m.vtableSlotCount) * sizeof(VtableSlot);
    const uint64_t aobEnd = static_cast<uint64_t>(aobOffset) + aobSize;
    if (pdataEnd > size || symbolEnd > size || heapEnd > size || slotEnd > size || aobEnd > size) {
        Logger::Log("PdataMatch: %s module extents out of range (pdata=%llu symbols=%llu heap=%llu "
                    "slots=%llu aob=%llu size=%zu)", sourceTag, pdataEnd, symbolEnd, heapEnd,
            slotEnd, aobEnd, size);
        return false;
    }

    // pdata 签名表
    std::vector<PdataSig> oldPdata;
    oldPdata.reserve(m.pdataCount);
    for (uint32_t i = 0; i < m.pdataCount; ++i) {
        // sidecar 的 pdata 表固定 16 字节/条（begin_rva + size + unwind_hash），无 prologSize
        const uint8_t* p = data + m.pdataOffset + static_cast<uint64_t>(i) * 16;
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
    const uint8_t* heap = data + m.heapOffset;
    std::vector<Symbol> symbols;
    symbols.reserve(m.symbolCount);
    std::unordered_map<std::string, size_t> byDemangled;
    std::unordered_map<std::string, size_t> byMangled;
    std::unordered_map<uint32_t, uint64_t> headHashByRva;
    std::vector<uint8_t> aobData;
    std::unordered_map<uint32_t, AobInfo> aobByRva;
    size_t aobCursor = aobOffset;   // AOB 表当前偏移
    uint32_t slotCursor = 0;
    size_t vtableSymbols = 0;

    for (uint32_t i = 0; i < m.symbolCount; ++i) {
        SymbolEntry se{};
        std::memcpy(&se, data + m.symbolOffset + static_cast<uint64_t>(i) * sizeof(SymbolEntry), sizeof(se));
        Symbol sym;
        sym.old_rva = se.old_rva;
        sym.kind = se.kind;
        sym.normHeadHash = se.normHeadHash;

        const auto readName = [&](uint32_t off) -> std::string {
            if (off == 0 || off >= m.heapSize) return {};
            const char* p = reinterpret_cast<const char*>(heap + off);
            const size_t maxLen = m.heapSize - off;
            const size_t len = strnlen(p, maxLen);
            if (len >= maxLen) return {};  // 堆内无 NUL，视为损坏
            return std::string(p, len);
        };
        sym.demangled = readName(se.demangledNameOffset);
        sym.mangled = readName(se.mangledNameOffset);

        const uint32_t slotCount = se.vtableSlotCount;

        if (sym.kind == 1 && slotCount != 0) {
            if (m.vtableOffset == 0 ||
                static_cast<uint64_t>(slotCursor) + slotCount > kMaxVtableSlots ||
                static_cast<uint64_t>(m.vtableOffset) +
                    (static_cast<uint64_t>(slotCursor) + slotCount) * sizeof(VtableSlot) > size) {
                Logger::Log("PdataMatch: %s vtable slot overflow at symbol %u", sourceTag, i);
                return false;
            }
            sym.slots.reserve(slotCount);
            for (uint32_t s = 0; s < slotCount; ++s) {
                VtableSlot vs{};
                std::memcpy(&vs, data + m.vtableOffset +
                    static_cast<uint64_t>(slotCursor + s) * sizeof(VtableSlot), sizeof(vs));
                sym.slots.push_back(vs);
            }
            slotCursor += slotCount;
            ++vtableSymbols;
        } else if (sym.kind == 0 && sym.normHeadHash != 0 && sym.old_rva != 0) {
            headHashByRva.emplace(sym.old_rva, sym.normHeadHash);
        }

        // Function 符号读函数体 AOB（bodySize + body + mask）
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
    g_baseSizeOfImage = m.baseSizeOfImage;
    g_baseTimeDateStamp = m.baseTimeDateStamp;
    g_loaded = true;
    Logger::Log("PdataMatch: %s loaded pdata=%zu symbols=%zu vtable_symbols=%zu vtable_slots=%u base=0x%08X timestamp=0x%08X",
        sourceTag, g_oldPdata.size(), g_symbols.size(), vtableSymbols, slotCursor,
        g_baseSizeOfImage, g_baseTimeDateStamp);
    return true;
}


bool ParseModuleToContext(const uint8_t* data, size_t size, const ModuleDesc& m, const char* sourceTag) {
    if (!ParseModuleData(data, size, m, sourceTag)) return false;
    ContextState ctx;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        ctx.imageId = m.imageId;
        ctx.baseSizeOfImage = g_baseSizeOfImage;
        ctx.baseTimeDateStamp = g_baseTimeDateStamp;
        ctx.oldPdata = std::move(g_oldPdata);
        ctx.symbols = std::move(g_symbols);
        ctx.byDemangled = std::move(g_byDemangled);
        ctx.byMangled = std::move(g_byMangled);
        ctx.headHashByRva = std::move(g_headHashByRva);
        ctx.aobData = std::move(g_aobData);
        ctx.aobByRva = std::move(g_aobByRva);
        ctx.oldFingerprint = g_oldFingerprint;
        ctx.loaded = true;
        g_contexts[m.imageId] = std::move(ctx);
    }
    return true;
}

bool ParseContainer(const uint8_t* data, size_t size, const char* sourceTag) {
    if (size < sizeof(ContainerHeader)) {
        Logger::Log("PdataMatch: %s container too small (%zu bytes)", sourceTag, size);
        return false;
    }
    ContainerHeader h{};
    std::memcpy(&h, data, sizeof(h));
    if (std::memcmp(h.magic, kSidecarMagic, 4) != 0) {
        Logger::Log("PdataMatch: %s bad magic", sourceTag);
        return false;
    }
    if (h.version != kSidecarVersion) {
        Logger::Log("PdataMatch: %s unsupported version %u", sourceTag, h.version);
        return false;
    }
    if (h.moduleCount == 0 || h.moduleCount > 8) {
        Logger::Log("PdataMatch: %s bad moduleCount=%u (expect 1..8)", sourceTag, h.moduleCount);
        return false;
    }
    const uint64_t tableEnd = static_cast<uint64_t>(h.moduleTableOffset) + h.moduleTableSize;
    if (static_cast<uint64_t>(h.moduleTableOffset) > size || tableEnd > size ||
        h.moduleTableSize < static_cast<uint64_t>(h.moduleCount) * sizeof(ModuleDesc)) {
        Logger::Log("PdataMatch: %s bad module table", sourceTag);
        return false;
    }
    for (uint32_t i = 0; i < h.moduleCount; ++i) {
        ModuleDesc m{};
        std::memcpy(&m, data + h.moduleTableOffset + static_cast<uint64_t>(i) * sizeof(ModuleDesc), sizeof(m));
        // 容器只允许装 exe(DX11/DX12) 与 GameCoreXP2，且必须具备 PE 身份（否则无法做身份判定）。
        if (m.imageId != kHookImageExeDx11 && m.imageId != kHookImageExeDx12 &&
            m.imageId != kHookImageGameCoreXP2) {
            Logger::Log("PdataMatch: %s module %u has unsupported imageId=%u", sourceTag, i, m.imageId);
            return false;
        }
        if (m.baseSizeOfImage == 0 || m.baseTimeDateStamp == 0) {
            Logger::Log("PdataMatch: %s module %u (image=%u) missing PE identity",
                sourceTag, i, m.imageId);
            return false;
        }
        if (!ParseModuleToContext(data, size, m, sourceTag)) {
            Logger::Log("PdataMatch: %s module %u (image=%u) parse failed", sourceTag, i, m.imageId);
            return false;
        }
    }
    Logger::Log("PdataMatch: %s container modules=%u", sourceTag, h.moduleCount);
    return true;
}

// 单个来源的原始字节 -> 未压缩 sidecar 字节（"C6SD" 直通，否则按压缩信封解压）。
bool DecodeSidecarBlob(const std::vector<uint8_t>& blob, std::vector<uint8_t>& out, const char* tag) {
    if (blob.size() >= 4 && std::memcmp(blob.data(), kSidecarMagic, 4) == 0) {
        out = blob;
        return true;
    }
    if (DecompressSidecar(blob, out)) return true;
    Logger::Log("PdataMatch: %s sidecar decompress failed (%zu bytes)", tag, blob.size());
    return false;
}

// 来源 1：Loader 同目录旁路文件 Civ6DllLoader.symdb.bin（开发用覆盖：测新符号库无需重编）。
bool LoadSidecarFromFile(HMODULE runtimeModule, std::vector<uint8_t>& out) {
    if (!runtimeModule) return false;
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(runtimeModule, path, MAX_PATH)) return false;
    std::wstring wpath(path);
    const size_t slash = wpath.find_last_of(L"/\\");
    if (slash == std::wstring::npos) return false;
    wpath.resize(slash + 1);
    wpath += kSidecarFileName;
    std::vector<uint8_t> blob;
    if (!ReadWholeFile(wpath.c_str(), blob)) return false;
    return DecodeSidecarBlob(blob, out, "file");
}

// 来源 2：RCDATA 102（部署产物，多模块容器）。
bool LoadSidecarFromResource(HMODULE runtimeModule, std::vector<uint8_t>& out) {
    if (!runtimeModule) return false;
    HRSRC res = FindResourceW(runtimeModule, MAKEINTRESOURCEW(kSidecarResourceId), RT_RCDATA);
    if (!res) return false;
    HGLOBAL glob = LoadResource(runtimeModule, res);
    const DWORD sz = glob ? SizeofResource(runtimeModule, res) : 0;
    const void* ptr = glob ? LockResource(glob) : nullptr;
    if (!ptr || !sz) return false;
    std::vector<uint8_t> blob(static_cast<const uint8_t*>(ptr),
        static_cast<const uint8_t*>(ptr) + sz);
    return DecodeSidecarBlob(blob, out, "rcdata");
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
std::wstring CachePath(uint32_t imageId) {
    wchar_t exePath[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return {};
    std::wstring dir(exePath);
    const size_t slash = dir.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return {};
    dir.resize(slash + 1);
    dir += kCacheDirName;
    CreateDirectoryW(dir.c_str(), nullptr);  // 已存在则忽略失败（后续写失败仅记日志）
    dir += L"\\";
    if (imageId == kHookImageGameCoreXP2) {
        dir += kCacheFileName;               // GameCoreXP2 用固定名
    } else {
        dir += L"pdata_cache_";
        dir += std::to_wstring(imageId);
        dir += L".bin";
    }
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

// 在给定上下文中矫正 old_rva -> new_rva（需持有 g_mutex 调用）
uintptr_t CorrectRvaLocked(const ContextState& ctx, uintptr_t oldRva) {
    // 版本一致：跳过一切 pdata 匹配，直接恒等解析（gap 符号/vtable 的 RVA 也有效）
    if (ctx.identical) return oldRva;
    if (!ctx.tableReady || ctx.oldPdata.empty() || ctx.newPdata.empty() ||
        ctx.map.size() != ctx.oldPdata.size()) {
        return 0;
    }
    // 二分：最后一个 begin_rva <= oldRva 的条目（pdata 允许嵌套，先取最内层候选）
    size_t lo = 0;
    size_t hi = ctx.oldPdata.size();
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (ctx.oldPdata[mid].begin_rva <= oldRva) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) {
        // gap（第一个函数之前）：查叶子 AOB 匹配结果
        const auto lit = ctx.leafMap.find(static_cast<uint32_t>(oldRva));
        return lit != ctx.leafMap.end() ? lit->second : 0;
    }
    // 从最内层候选向前回扫找包含 oldRva 的条目（嵌套深度通常 <= 3，封顶防退化）
    constexpr size_t kMaxBackscan = 64;
    size_t idx = lo - 1;
    size_t scanned = 0;
    for (;;) {
        const PdataSig& oe = ctx.oldPdata[idx];
        if (oldRva < static_cast<uintptr_t>(oe.begin_rva) + oe.size) break;  // 包含
        if (idx == 0 || scanned >= kMaxBackscan) {
            const auto lit = ctx.leafMap.find(static_cast<uint32_t>(oldRva));
            return lit != ctx.leafMap.end() ? lit->second : 0;
        }
        --idx;
        ++scanned;
    }
    const size_t oldIdx = idx;
    const PdataSig& oe = ctx.oldPdata[oldIdx];
    const uint32_t newIdx = ctx.map[oldIdx];
    if (newIdx == kUnmatched || newIdx >= ctx.newPdata.size()) return 0;
    const PdataSig& ne = ctx.newPdata[newIdx];
    const uintptr_t offset = oldRva - oe.begin_rva;
    if (offset == 0) return ne.begin_rva;                        // 函数开头
    if (ne.size == oe.size) return ne.begin_rva + offset;        // size 不变才允许内部偏移
    return 0;                                                    // deny
}

// 清空全部解析状态（上下文 + 构建用临时 globals）：Init 起始与候选重试前调用。
void ResetAllParsedState() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_contexts.clear();
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

// 数据已搬进 g_contexts 后清掉构建用临时 globals。
void ClearTempGlobals() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_oldPdata.clear();
    g_symbols.clear();
    g_byDemangled.clear();
    g_byMangled.clear();
    g_headHashByRva.clear();
    g_aobData.clear();
    g_aobByRva.clear();
    g_leafMap.clear();
    g_newPdata.clear();
    g_map.clear();
    g_loaded = false;
    g_tableReady = false;
}
}  // namespace

bool Init(HMODULE runtimeModule) {
    // 候选来源与优先级：
    //  1) 旁路文件 Civ6DllLoader.symdb.bin（开发用覆盖：测新符号库无需重编）。
    //  2) RCDATA 102：部署产物。
    // 任一候选解析失败都继续尝试下一个：保住"旁路文件损坏/版本不认识时仍可用内嵌资源"的回退链。
    ResetAllParsedState();

    std::vector<uint8_t> fileBlob;
    const bool haveFile = LoadSidecarFromFile(runtimeModule, fileBlob);

    struct Candidate {
        const char* tag;
        bool isResource;
    };
    std::vector<Candidate> order;
    if (haveFile) order.push_back(Candidate{ "file", false });
    order.push_back(Candidate{ "rcdata", true });

    // RCDATA 按需加载：只有轮到它当候选时才解压（避免开发用旁路文件生效时白解 44MB）。
    std::vector<uint8_t> resourceBlob;
    bool resourceTried = false;
    for (const Candidate& candidate : order) {
        const std::vector<uint8_t>* bytes = &fileBlob;
        if (candidate.isResource) {
            if (!resourceTried) {
                resourceTried = true;
                if (!LoadSidecarFromResource(runtimeModule, resourceBlob)) {
                    Logger::Log("PdataMatch: sidecar source=rcdata unavailable");
                    continue;
                }
            }
            bytes = &resourceBlob;
        }
        ResetAllParsedState();   // 候选之间不留半解析的上下文
        if (ParseContainer(bytes->data(), bytes->size(), candidate.tag)) {
            Logger::Log("PdataMatch: sidecar source=%s (%zu bytes)", candidate.tag, bytes->size());
            ClearTempGlobals();
            return true;
        }
        Logger::Log("PdataMatch: sidecar source=%s parse failed; trying next source", candidate.tag);
    }
    Logger::Log("PdataMatch: no sidecar (Civ6DllLoader.symdb.bin or RCDATA 102) - pdata correction unavailable");
    return false;
}

static bool BuildNewTableImpl(uint32_t imageId, HMODULE gameCore) {
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
    Logger::Log("PdataMatch: new pdata entries=%zu fingerprint=0x%016llX",
        newTable.size(), static_cast<unsigned long long>(fingerprint));

    std::vector<uint32_t> mapping;
    bool fromCache = false;
    size_t anchors = 0;

    // 身份判定（与 sidecar 头记录的两项比对，顺序即优先级）：
    //  1) SizeOfImage + TimeDateStamp 相同 = 同一 GameCore 构建 -> 直接恒等映射，不再比较 pdata 表。
    //  2) 头身份不同 -> 逐条比较 pdata 表；完全一致（纯重建、函数边界未变）同样恒等映射。
    //  3) 头身份与 pdata 都不同 -> 才启动跨版本匹配（缓存 / AlignTables / 叶子 AOB / vtable）。
    bool headerIdentity = false;
    bool identical = false;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        headerIdentity = (imageSize == g_baseSizeOfImage && timeDateStamp == g_baseTimeDateStamp);
        if (headerIdentity && fingerprint != g_oldFingerprint) {
            // 头身份相同但 pdata 指纹不同：sidecar 的身份字段与表内容可能来自不同 DLL。
            Logger::Log("PdataMatch: header identity match but pdata fingerprint differs "
                        "(new=0x%016llX sidecar=0x%016llX); sidecar may be inconsistent",
                static_cast<unsigned long long>(fingerprint),
                static_cast<unsigned long long>(g_oldFingerprint));
        }
    }

    if (headerIdentity) {
        identical = true;
        Logger::Log("PdataMatch: identity by header (size=0x%08X ts=0x%08X) -> identity mapping",
            imageSize, timeDateStamp);
    } else {
        identical = oldTable.size() == newTable.size();
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
            Logger::Log("PdataMatch: header identity differs (size 0x%08X vs 0x%08X, ts 0x%08X vs 0x%08X) "
                        "but pdata tables identical -> identity mapping",
                imageSize, g_baseSizeOfImage, timeDateStamp, g_baseTimeDateStamp);
        } else {
            Logger::Log("PdataMatch: header identity and pdata both differ -> cross-version matching "
                        "(old=%zu new=%zu)", oldTable.size(), newTable.size());
        }
    }

    if (identical) {
        mapping.resize(oldTable.size());
        for (size_t i = 0; i < mapping.size(); ++i) mapping[i] = static_cast<uint32_t>(i);
        Logger::Log("PdataMatch: identity mapping entries=%zu",
            mapping.size());
    } else {
        const std::wstring cachePath = CachePath(imageId);
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

// 把构建用 globals 搬回对应上下文（构建正常结束或异常退出都必须执行——否则该模块的
// old pdata/符号表永久丢失）。按 imageId 重新查表，不跨放锁窗口持有裸指针。
static void RestoreContextFromGlobals(uint32_t imageId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_contexts.find(imageId);
    if (it != g_contexts.end()) {
        ContextState& ctx = it->second;
        ctx.oldPdata = std::move(g_oldPdata);
        ctx.symbols = std::move(g_symbols);
        ctx.byDemangled = std::move(g_byDemangled);
        ctx.byMangled = std::move(g_byMangled);
        ctx.headHashByRva = std::move(g_headHashByRva);
        ctx.aobData = std::move(g_aobData);
        ctx.aobByRva = std::move(g_aobByRva);
        ctx.oldFingerprint = g_oldFingerprint;
        ctx.baseSizeOfImage = g_baseSizeOfImage;
        ctx.baseTimeDateStamp = g_baseTimeDateStamp;
        ctx.leafMap = std::move(g_leafMap);
        ctx.newPdata = std::move(g_newPdata);
        ctx.map = std::move(g_map);
        ctx.fingerprint = g_fingerprint;
        ctx.identical = g_identical;
        ctx.tableReady = g_tableReady;
    }
    g_loaded = false;
}

bool BuildNewTable(uint32_t imageId, HMODULE target) {
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        const auto it = g_contexts.find(imageId);
        if (it == g_contexts.end() || !it->second.loaded) {
            Logger::Log("PdataMatch: BuildNewTable: no context for image=%u", imageId);
            return false;
        }
        ContextState& ctx = it->second;
        // 构建期间该上下文不可用：显式清掉"上次可用"的结论，避免并发 CorrectRva 在同一
        // imageId 上读到过期的恒等映射（铁律：拿不准就返回 0，不猜）。
        ctx.tableReady = false;
        ctx.identical = false;
        // 上下文 -> 构建用 globals（move，构建完再搬回）
        g_oldPdata = std::move(ctx.oldPdata);
        g_symbols = std::move(ctx.symbols);
        g_byDemangled = std::move(ctx.byDemangled);
        g_byMangled = std::move(ctx.byMangled);
        g_headHashByRva = std::move(ctx.headHashByRva);
        g_aobData = std::move(ctx.aobData);
        g_aobByRva = std::move(ctx.aobByRva);
        g_oldFingerprint = ctx.oldFingerprint;
        g_baseSizeOfImage = ctx.baseSizeOfImage;
        g_baseTimeDateStamp = ctx.baseTimeDateStamp;
        g_loaded = ctx.loaded;
        g_identical = false;
        g_leafMap.clear();
        g_newPdata.clear();
        g_map.clear();
        g_fingerprint = 0;
        g_tableReady = false;
    }

    // RAII：BuildNewTableImpl 中途抛异常（例如畸形 sidecar 触发大分配）也必须把数据搬回
    // 上下文，否则该模块的 old pdata/符号表永久丢失。
    struct RestoreGuard {
        uint32_t imageId;
        ~RestoreGuard() { RestoreContextFromGlobals(imageId); }
    } restoreGuard{ imageId };

    bool ok = false;
    try {
        ok = BuildNewTableImpl(imageId, target);
    } catch (...) {
        // 保持 fail-closed：解析/对齐抛异常 = 该映像不做矫正（调用方按未命中处理）。
        Logger::Log("PdataMatch: BuildNewTable exception; correction unavailable for image=%u",
            static_cast<unsigned>(imageId));
        ok = false;
    }
    return ok;
}

bool HasContext(uint32_t imageId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_contexts.find(imageId);
    return it != g_contexts.end() && it->second.loaded;
}

uintptr_t CorrectRva(uint32_t imageId, uintptr_t oldRva) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_contexts.find(imageId);
    if (it == g_contexts.end()) return 0;
    return CorrectRvaLocked(it->second, oldRva);
}

uintptr_t CorrectByName(uint32_t imageId, const char* name) {
    if (!name || !*name) return 0;
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_contexts.find(imageId);
    if (it == g_contexts.end()) return 0;
    const ContextState& ctx = it->second;
    size_t symIdx = SIZE_MAX;
    const auto itD = ctx.byDemangled.find(name);
    if (itD != ctx.byDemangled.end()) {
        symIdx = itD->second;
    } else {
        const auto itM = ctx.byMangled.find(name);
        if (itM != ctx.byMangled.end()) symIdx = itM->second;
    }
    if (symIdx == SIZE_MAX || symIdx >= ctx.symbols.size()) return 0;
    const uint32_t oldRva = ctx.symbols[symIdx].old_rva;
    if (oldRva == 0) return 0;
    return CorrectRvaLocked(ctx, oldRva);
}

uint64_t Fingerprint(uint32_t imageId) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_contexts.find(imageId);
    return it != g_contexts.end() ? it->second.fingerprint : 0;
}

bool CorrectVTableByName(uint32_t imageId, const char* name, uint32_t& outRva, uint32_t& outSlotCount) {
    if (!name || !*name) return false;
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto it = g_contexts.find(imageId);
    if (it == g_contexts.end()) return false;
    const ContextState& ctx = it->second;
    size_t symIdx = SIZE_MAX;
    const auto itD = ctx.byDemangled.find(name);
    if (itD != ctx.byDemangled.end()) {
        symIdx = itD->second;
    } else {
        const auto itM = ctx.byMangled.find(name);
        if (itM != ctx.byMangled.end()) symIdx = itM->second;
    }
    if (symIdx == SIZE_MAX || symIdx >= ctx.symbols.size()) return false;
    const Symbol& sym = ctx.symbols[symIdx];
    if (sym.kind != 1 || sym.slots.empty()) return false;  // 非 vtable
    const uintptr_t corrected = CorrectRvaLocked(ctx, sym.old_rva);
    if (corrected == 0) return false;
    outRva = static_cast<uint32_t>(corrected);
    outSlotCount = static_cast<uint32_t>(sym.slots.size());
    return true;
}
}  // namespace PdataMatch
