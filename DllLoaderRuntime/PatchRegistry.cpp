// PatchRegistry.cpp — v2 单层补丁注册表（HookAPI Patch/Unpatch 后端）。
// 设计见 docs/superpowers/specs/2026-08-17-civ6dllloader-v2-design.md §4.1 / §10 Q19。
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

struct Entry {
    std::vector<uint8_t> original;  // 首次 Patch 时的原始字节（单层存档）
    std::wstring owner;             // 所属插件（去扩展名的文件名 stem）
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
            return PAGE_READWRITE;
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

    EnterCriticalSection(&Cs());
    const auto existing = Registry().find(target);
    const bool isFirst = existing == Registry().end();
    if (isFirst) {
        for (const auto& kv : Registry()) {
            const uintptr_t otherBegin = reinterpret_cast<uintptr_t>(kv.first);
            uintptr_t otherEnd = 0;
            if (RangeEnd(otherBegin, kv.second.original.size(), otherEnd) &&
                    RangesOverlap(targetBegin, targetEnd, otherBegin, otherEnd)) {
                LeaveCriticalSection(&Cs());
                Logger::Log("PatchRegistry::Apply: range overlap target=%p len=%zu existing=%p len=%zu",
                    target, len, kv.first, kv.second.original.size());
                return false;
            }
        }
        Logger::Log("PatchRegistry::Apply: first patch target=%p len=%zu owner=%ls", target, len, owner);
    } else {
        if (existing->second.owner != owner) {
            const std::wstring currentOwner = existing->second.owner;
            LeaveCriticalSection(&Cs());
            Logger::Log("PatchRegistry::Apply: owner conflict target=%p current=%ls requested=%ls",
                        target, currentOwner.c_str(), owner);
            return false;
        }
        if (existing->second.original.size() != len) {
            const size_t currentLen = existing->second.original.size();
            LeaveCriticalSection(&Cs());
            Logger::Log("PatchRegistry::Apply: repeat length mismatch target=%p current=%zu requested=%zu owner=%ls",
                target, currentLen, len, owner);
            return false;
        }
        // 重复 Apply 同一地址：更新当前字节但保留最初存档（日志告警）。
        Logger::Log("PatchRegistry::Apply: repeat patch target=%p len=%zu owner=%ls (original archive kept)",
            target, len, owner);
    }

    std::vector<uint8_t> original(len);
    const auto* src = reinterpret_cast<const uint8_t*>(bytes);

    std::vector<SavedProtection> saved;
    if (!MakeWritableRecording(target, len, saved)) {
        RestoreProtections(saved);         // 部分成功也要恢复，别留下可写/可执行的页
        LeaveCriticalSection(&Cs());
        Logger::Log("PatchRegistry::Apply: protect failed target=%p len=%zu err=%lu",
            target, len, GetLastError());
        return false;
    }
    memcpy(original.data(), target, len);  // 存档原始字节（写入前读取）
    memcpy(target, src, len);              // 写入新字节
    RestoreProtections(saved);             // 逐区域恢复各自的原保护属性
    FlushInstructionCache(GetCurrentProcess(), target, len);

    if (isFirst) {
        Entry e;
        e.original = std::move(original);
        e.owner = owner;
        Registry().emplace(target, std::move(e));
    }
    LeaveCriticalSection(&Cs());
    return true;
}

bool OverlapsRegistered(const void* target, size_t len) {
    if (!target || len == 0) return false;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(target);
    const uintptr_t end = begin + len;
    if (end < begin) return true;   // 地址回绕：按冲突处理

    EnterCriticalSection(&Cs());
    for (const auto& kv : Registry()) {
        const uintptr_t otherBegin = reinterpret_cast<uintptr_t>(kv.first);
        uintptr_t otherEnd = 0;
        if (RangeEnd(otherBegin, kv.second.original.size(), otherEnd) &&
                RangesOverlap(begin, end, otherBegin, otherEnd)) {
            LeaveCriticalSection(&Cs());
            return true;
        }
    }
    LeaveCriticalSection(&Cs());
    return false;
}

bool Revert(void* target) {
    if (!target) {
        return false;
    }
    EnterCriticalSection(&Cs());
    const auto it = Registry().find(target);
    if (it == Registry().end()) {
        LeaveCriticalSection(&Cs());
        Logger::Log("PatchRegistry::Revert: no patch record for target=%p", target);
        return false;
    }

    const size_t origSize = it->second.original.size();
    const std::wstring owner = it->second.owner;
    std::vector<SavedProtection> saved;
    if (!MakeWritableRecording(target, origSize, saved)) {
        RestoreProtections(saved);
        LeaveCriticalSection(&Cs());
        Logger::Log("PatchRegistry::Revert: protect failed target=%p err=%lu", target, GetLastError());
        return false;
    }
    memcpy(target, it->second.original.data(), origSize);
    RestoreProtections(saved);
    FlushInstructionCache(GetCurrentProcess(), target, origSize);

    Registry().erase(it);
    LeaveCriticalSection(&Cs());
    Logger::Log("PatchRegistry::Revert: restored target=%p (%zu bytes) owner=%ls", target, origSize, owner.c_str());
    return true;
}

bool RevertOwned(void* target, const wchar_t* owner) {
    if (!target || !owner || !*owner) return false;
    EnterCriticalSection(&Cs());
    const auto it = Registry().find(target);
    if (it == Registry().end() || it->second.owner != owner) {
        LeaveCriticalSection(&Cs());
        Logger::Log("PatchRegistry::RevertOwned: owner mismatch target=%p owner=%ls",
                    target, owner);
        return false;
    }

    const size_t origSize = it->second.original.size();
    std::vector<SavedProtection> saved;
    if (!MakeWritableRecording(target, origSize, saved)) {
        RestoreProtections(saved);
        LeaveCriticalSection(&Cs());
        Logger::Log("PatchRegistry::RevertOwned: protect failed target=%p err=%lu",
                    target, GetLastError());
        return false;
    }
    memcpy(target, it->second.original.data(), origSize);
    RestoreProtections(saved);
    FlushInstructionCache(GetCurrentProcess(), target, origSize);
    Registry().erase(it);
    LeaveCriticalSection(&Cs());
    return true;
}

size_t RevertAllFor(const wchar_t* owner) {
    if (!owner || !*owner) {
        return 0;
    }
    EnterCriticalSection(&Cs());

    // 先收集目标再逐个回滚（回滚会擦除条目，避免迭代器失效）。
    std::vector<void*> targets;
    targets.reserve(Registry().size());
    for (const auto& kv : Registry()) {
        if (kv.second.owner == owner) {
            targets.push_back(kv.first);
        }
    }

    size_t reverted = 0;
    for (void* t : targets) {
        const auto it = Registry().find(t);
        if (it == Registry().end()) {
            continue;
        }
        const size_t origSize = it->second.original.size();
        std::vector<SavedProtection> saved;
        if (!MakeWritableRecording(t, origSize, saved)) {
            RestoreProtections(saved);
            Logger::Log("PatchRegistry::RevertAllFor: protect failed target=%p err=%lu", t, GetLastError());
            continue;
        }
        memcpy(t, it->second.original.data(), origSize);
        RestoreProtections(saved);
        FlushInstructionCache(GetCurrentProcess(), t, origSize);
        Registry().erase(it);
        ++reverted;
    }
    LeaveCriticalSection(&Cs());
    if (reverted > 0) {
        Logger::Log("PatchRegistry::RevertAllFor: rolled back %zu patch(es) for owner=%ls", reverted, owner);
    }
    return reverted;
}

size_t RevertAllInRange(uintptr_t base, uintptr_t size) {
    if (!base || !size) {
        return 0;
    }
    EnterCriticalSection(&Cs());

    std::vector<void*> targets;
    targets.reserve(Registry().size());
    for (const auto& kv : Registry()) {
        const uintptr_t p = reinterpret_cast<uintptr_t>(kv.first);
        uintptr_t patchEnd = 0;
        uintptr_t rangeEnd = 0;
        if (RangeEnd(p, kv.second.original.size(), patchEnd) &&
                RangeEnd(base, size, rangeEnd) &&
                RangesOverlap(p, patchEnd, base, rangeEnd)) {
            targets.push_back(kv.first);
        }
    }

    size_t reverted = 0;
    for (void* t : targets) {
        const auto it = Registry().find(t);
        if (it == Registry().end()) {
            continue;
        }
        const size_t origSize = it->second.original.size();
        std::vector<SavedProtection> saved;
        if (MakeWritableRecording(t, origSize, saved)) {
            memcpy(t, it->second.original.data(), origSize);
            RestoreProtections(saved);
            FlushInstructionCache(GetCurrentProcess(), t, origSize);
            ++reverted;
        } else {
            RestoreProtections(saved);
            // 回滚失败（如重载兜底路径映像已卸载）：字节随映射消失，同样丢弃。
            Logger::Log("PatchRegistry::RevertAllInRange: protect failed target=%p err=%lu (dropping record)",
                t, GetLastError());
        }
        Registry().erase(it);
    }
    LeaveCriticalSection(&Cs());
    if (!targets.empty()) {
        Logger::Log("PatchRegistry::RevertAllInRange: base=0x%llX size=0x%llX cleared=%zu reverted=%zu",
            static_cast<unsigned long long>(base),
            static_cast<unsigned long long>(size), targets.size(), reverted);
    }
    return reverted;
}

}  // namespace PatchRegistry
