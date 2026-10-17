// PatchRegistry.cpp — 分层补丁注册表（HookAPI Patch/Unpatch 后端）。
// 域规则/补丁仲裁见 docs/ARCHITECTURE.md §4.1 与 §5.5。
#include "pch.h"
#include "PatchRegistry.h"

#include <Windows.h>

#include "../common/Logger.h"

#include <algorithm>
#include <limits>
#include <map>
#include <string>
#include <vector>

namespace PatchRegistry {

namespace {

// 一个 owner 在某个 target 上打的一层补丁。
struct Level {
    // 本层写入【之前】该区间的字节。后打补丁者存到的是"含下层补丁"的字节，
    // 因此它 Unpatch 时还原的是下层补丁而不是原始字节——这正是分层要的效果。
    std::vector<uint8_t> original;
    std::wstring owner;
};

struct Entry {
    // 按应用顺序排列，back() = 栈顶（最后一个打上去的补丁）。
    std::vector<Level> levels;

    // 本 target 上所有层覆盖的最大长度，用于与【其它 target】做区间仲裁。
    size_t Extent() const {
        size_t n = 0;
        for (const auto& lv : levels) n = (std::max)(n, lv.original.size());
        return n;
    }
};

std::map<void*, Entry>& Registry() {
    // 故意不释放：注册表存活于 Loader 整个进程生命周期，避免退出时的析构顺序问题。
    static std::map<void*, Entry>* reg = new std::map<void*, Entry>();
    return *reg;
}

CRITICAL_SECTION& Cs() {
    // 首次使用惰性初始化（C++11 magic static，线程安全）；进程退出时随进程回收。
    static CRITICAL_SECTION* cs = []() {
        CRITICAL_SECTION* p = new CRITICAL_SECTION();
        InitializeCriticalSection(p);
        return p;
    }();
    return *cs;
}

// 临界区 RAII 守卫。只兜 **C++ 异常**：临界区内还有 std::vector / std::map / std::wstring
// 分配，一次 bad_alloc 从裸 Enter/Leave 之间逃出去就会把补丁表的锁永久留在持有状态。
// 不兜硬件异常（AV）——/EHsc 下 SEH 不走析构，那类访存错误靠上游"取锁前先探页属性"的
// 纪律挡（见 PluginBoundary.h 的不变量）。
struct CsGuard {
    CsGuard() { EnterCriticalSection(&Cs()); }
    ~CsGuard() { LeaveCriticalSection(&Cs()); }
    CsGuard(const CsGuard&) = delete;
    CsGuard& operator=(const CsGuard&) = delete;
};

// 基本可写性检查（IsBadReadPtr 不可靠）：整段 [p, p+len) 必须落在
// MEM_COMMIT 且保护非 PAGE_NOACCESS/PAGE_GUARD 的区域内。
// 失败返回 false，调用方直接拒绝，不打补丁。
bool IsWritableCommitted(void* p, size_t len) {
    auto* cur = reinterpret_cast<uint8_t*>(p);
    size_t remain = len;
    while (remain > 0) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(cur, &mbi, sizeof(mbi)) == 0) {
            return false;
        }
        if (mbi.State != MEM_COMMIT) {
            return false;
        }
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) {
            return false;
        }
        const size_t regionBytes = static_cast<size_t>(mbi.RegionSize)
            - static_cast<size_t>(cur - static_cast<uint8_t*>(mbi.BaseAddress));
        if (regionBytes == 0) {
            return false;  // 防御：RegionSize 解析异常，避免死循环
        }
        const size_t consumed = (std::min)(regionBytes, remain);
        cur += consumed;
        remain -= consumed;
    }
    return true;
}

bool RangeEnd(uintptr_t begin, size_t len, uintptr_t& end) {
    if (len == 0 || begin > (std::numeric_limits<uintptr_t>::max)() - len) {
        return false;
    }
    end = begin + len;
    return end > begin;
}

bool RangesOverlap(uintptr_t aBegin, uintptr_t aEnd,
                   uintptr_t bBegin, uintptr_t bEnd) {
    return aBegin < bEnd && bBegin < aEnd;
}

// 单次补丁字节数上限。Apply 会按 len 分配原始字节存档并跨内存区域改保护属性，
// 没有上限时一个坏参数就能造成大分配/长时间改保护。口径与 HookAPI 层的
// PluginBoundary::kMaxPluginRawBytes 一致（1 MiB）。
constexpr size_t kMaxPatchBytes = 1u << 20;

// 逐区域保存的页保护属性。
struct SavedProtection {
    void* base;
    size_t size;
    DWORD protect;
};

// 由原始保护属性推导"带写权限"的等价属性。
// 不再一律用 PAGE_EXECUTE_READWRITE：那会把纯数据页临时变成可执行，破坏 W^X。
DWORD WritableVariant(DWORD protect) {
    switch (protect & 0xFFu) {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return PAGE_EXECUTE_READWRITE;
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
            return PAGE_READWRITE;
        default:
            // PAGE_NOACCESS / PAGE_GUARD / 未知属性没有"带写权限的等价属性"：返回 0 让
            // VirtualProtect 失败，调用方按既有失败路径拒绝这次补丁，绝不把不可访问页变成可写。
            return 0;
    }
}

// 按【内存区域】逐段改保护，并记录每段各自的旧属性。
// 为什么不能一次 VirtualProtect(target, len, ...)：跨页/跨区域时 oldProtect 只会返回
// 第一页的旧属性；用它恢复整个区间会把后续区域的保护属性写错（例如把 .rdata 的
// PAGE_READONLY 恢复成 .text 的 PAGE_EXECUTE_READ）。
bool MakeWritableRecording(void* target, size_t len, std::vector<SavedProtection>& saved) {
    auto* p = static_cast<uint8_t*>(target);
    size_t remain = len;
    while (remain > 0) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
        const auto* regionBase = static_cast<const uint8_t*>(mbi.BaseAddress);
        const size_t regionLeft = static_cast<size_t>(mbi.RegionSize)
            - static_cast<size_t>(p - regionBase);
        if (regionLeft == 0) return false;   // 防御：RegionSize 解析异常，避免死循环
        const size_t chunk = (std::min)(regionLeft, remain);
        DWORD old = 0;
        if (!VirtualProtect(p, chunk, WritableVariant(mbi.Protect), &old)) return false;
        saved.push_back(SavedProtection{ p, chunk, old });
        p += chunk;
        remain -= chunk;
    }
    return true;
}

// 恢复 MakeWritableRecording 记录的全部区域（尽力恢复，失败忽略）。
void RestoreProtections(const std::vector<SavedProtection>& saved) {
    for (const auto& s : saved) {
        DWORD ignored = 0;
        VirtualProtect(s.base, s.size, s.protect, &ignored);
    }
}

// 把 [target, target+len) 改写成 src（自动处理页保护与指令缓存）。
// src 必须已由调用方复制到自有缓冲（原字节存档目标、或插件字节的副本）。
bool WriteBytes(void* target, const void* src, size_t len) {
    std::vector<SavedProtection> saved;
    if (!MakeWritableRecording(target, len, saved)) {
        RestoreProtections(saved);         // 部分成功也要恢复，别留下可写/可执行的页
        Logger::Log("PatchRegistry: protect failed target=%p len=%zu err=%lu",
            target, len, GetLastError());
        return false;
    }
    memcpy(target, src, len);
    RestoreProtections(saved);             // 逐区域恢复各自的原保护属性
    FlushInstructionCache(GetCurrentProcess(), target, len);
    return true;
}

}  // namespace

bool Apply(void* target, const void* bytes, size_t len, const wchar_t* owner) {
    if (!target || !bytes || len == 0) {
        Logger::Log("PatchRegistry::Apply: invalid args target=%p len=%zu", target, len);
        return false;
    }
    if (len > kMaxPatchBytes) {
        Logger::Log("PatchRegistry::Apply: len=%zu over limit (%zu) target=%p",
            len, kMaxPatchBytes, target);
        return false;
    }
    const uintptr_t targetBegin = reinterpret_cast<uintptr_t>(target);
    uintptr_t targetEnd = 0;
    if (!RangeEnd(targetBegin, len, targetEnd)) {
        Logger::Log("PatchRegistry::Apply: address range overflow target=%p len=%zu", target, len);
        return false;
    }
    if (!IsWritableCommitted(target, len)) {
        Logger::Log("PatchRegistry::Apply: target not committed/writable target=%p len=%zu", target, len);
        return false;
    }
    if (!owner || !*owner) {
        owner = L"unknown";
    }

    CsGuard csGuard;
    auto it = Registry().find(target);
    // 需要与其它 target 仲裁的区间 = 本次写入里"本 target 尚未覆盖"的那部分。
    // 新 target 是全长；已存在的 target 只可能是扩长出来的尾部（缩回或等长的部分是
    // 它自己本来就占着的范围）。越过现有 extent 去压别的 target，撤销顺序会把对方的
    // 字节写坏 —— 所以扩长同样要过区间仲裁。
    uintptr_t claimBegin = targetBegin;
    if (it != Registry().end()) {
        // 同一 owner 重复 Apply 同一 target：拒绝。补丁已生效，再打一层只会让"哪层是谁的"
        // 彻底不可追踪；要改字节请先 Unpatch 再 Patch。
        for (const auto& lv : it->second.levels) {
            if (lv.owner == owner) {
                Logger::Log("PatchRegistry::Apply: owner already patched this target "
                            "target=%p len=%zu owner=%ls (unpatch first)",
                            target, len, owner);
                return false;
            }
        }
        uintptr_t coveredEnd = 0;
        if (RangeEnd(targetBegin, it->second.Extent(), coveredEnd) && coveredEnd < targetEnd) {
            claimBegin = coveredEnd;
        } else {
            claimBegin = targetEnd;   // 未越界：本次没有新增区间，不需要仲裁
        }
    }
    if (claimBegin < targetEnd) {
        for (const auto& kv : Registry()) {
            if (kv.first == target) continue;
            const uintptr_t otherBegin = reinterpret_cast<uintptr_t>(kv.first);
            uintptr_t otherEnd = 0;
            if (RangeEnd(otherBegin, kv.second.Extent(), otherEnd) &&
                    RangesOverlap(claimBegin, targetEnd, otherBegin, otherEnd)) {
                Logger::Log("PatchRegistry::Apply: range overlap target=%p len=%zu claimed=[%p,%p) existing=%p extent=%zu",
                    target, len, reinterpret_cast<void*>(claimBegin),
                    reinterpret_cast<void*>(targetEnd), kv.first, kv.second.Extent());
                return false;
            }
        }
    }

    // 存档必须在写入之前读取：存到的就是"本层写之前"的字节（含下层补丁的效果）。
    std::vector<uint8_t> original(len);
    memcpy(original.data(), target, len);
    if (!WriteBytes(target, bytes, len)) {
        return false;
    }

    Level level;
    level.original = std::move(original);
    level.owner = owner;
    Entry& entry = Registry()[target];
    entry.levels.push_back(std::move(level));
    Logger::Log("PatchRegistry::Apply: patched target=%p len=%zu owner=%ls depth=%zu",
        target, len, owner, entry.levels.size());
    return true;
}

bool OverlapsRegistered(const void* target, size_t len) {
    if (!target || len == 0) return false;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(target);
    const uintptr_t end = begin + len;
    if (end < begin) return true;   // 地址回绕：按冲突处理

    CsGuard csGuard;
    for (const auto& kv : Registry()) {
        const uintptr_t otherBegin = reinterpret_cast<uintptr_t>(kv.first);
        uintptr_t otherEnd = 0;
        if (RangeEnd(otherBegin, kv.second.Extent(), otherEnd) &&
                RangesOverlap(begin, end, otherBegin, otherEnd)) {
            return true;
        }
    }
    return false;
}

size_t DiscardOwned(const wchar_t* owner) {
    if (!owner || !*owner) return 0;
    CsGuard csGuard;
    size_t removed = 0;
    for (auto it = Registry().begin(); it != Registry().end(); ) {
        auto& levels = it->second.levels;
        const size_t before = levels.size();
        levels.erase(std::remove_if(levels.begin(), levels.end(),
            [owner](const Level& lv) { return lv.owner == owner; }), levels.end());
        removed += before - levels.size();
        if (levels.empty()) {
            it = Registry().erase(it);
        } else {
            ++it;
        }
    }
    if (removed != 0) {
        Logger::Log("PatchRegistry::DiscardOwned: owner=%ls dropped=%zu (no bytes written)",
                    owner, removed);
    }
    return removed;
}

bool RevertOwned(void* target, const wchar_t* owner) {
    if (!target || !owner || !*owner) return false;
    CsGuard csGuard;
    auto it = Registry().find(target);
    if (it == Registry().end()) {
        Logger::Log("PatchRegistry::RevertOwned: no patch record target=%p owner=%ls",
                    target, owner);
        return false;
    }
    if (it->second.levels.empty()) {
        Registry().erase(it);
        Logger::Log("PatchRegistry::RevertOwned: empty record dropped target=%p", target);
        return false;
    }
    // 只允许还原栈顶：下层存档记的是"上层写入之前"的字节，越过上层写回去会静默覆盖
    // 上层 owner 的补丁（而它自己仍以为补丁在生效）。上层先 Unpatch，下层才轮得到。
    if (it->second.levels.back().owner != owner) {
        Logger::Log("PatchRegistry::RevertOwned: not on top of stack target=%p owner=%ls top=%ls",
                    target, owner, it->second.levels.back().owner.c_str());
        return false;
    }

    // 先复制再写：下面 pop_back 会让 src 指向已释放的缓冲。
    std::vector<uint8_t> original = it->second.levels.back().original;
    if (!WriteBytes(target, original.data(), original.size())) {
        Logger::Log("PatchRegistry::RevertOwned: protect failed target=%p err=%lu",
                    target, GetLastError());
        return false;
    }
    const size_t restored = it->second.levels.back().original.size();
    it->second.levels.pop_back();
    if (it->second.levels.empty()) {
        Registry().erase(it);
    }
    Logger::Log("PatchRegistry::RevertOwned: restored target=%p len=%zu owner=%ls",
                target, restored, owner);
    return true;
}

}  // namespace PatchRegistry
