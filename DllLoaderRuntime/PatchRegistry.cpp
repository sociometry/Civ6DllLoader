// PatchRegistry.cpp — v2 单层补丁注册表（HookAPI Patch/Unpatch 后端）。
// 设计见 docs/superpowers/specs/2026-08-17-civ6dllloader-v2-design.md §4.1 / §10 Q19。
#include "pch.h"
#include "PatchRegistry.h"

#include <Windows.h>

#include "../common/Logger.h"

#include <algorithm>
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

}  // namespace

bool Apply(void* target, const void* bytes, size_t len, const wchar_t* owner) {
    if (!target || !bytes || len == 0) {
        Logger::Log("PatchRegistry::Apply: invalid args target=%p len=%zu", target, len);
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
    const bool isFirst = Registry().find(target) == Registry().end();
    if (isFirst) {
        Logger::Log("PatchRegistry::Apply: first patch target=%p len=%zu owner=%ls", target, len, owner);
    } else {
        // 重复 Apply 同一地址：更新当前字节但保留最初存档（日志告警）。
        Logger::Log("PatchRegistry::Apply: repeat patch target=%p len=%zu owner=%ls (original archive kept)",
            target, len, owner);
    }

    std::vector<uint8_t> original(len);
    const auto* src = reinterpret_cast<const uint8_t*>(bytes);

    DWORD oldProtect = 0;
    if (!VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LeaveCriticalSection(&Cs());
        Logger::Log("PatchRegistry::Apply: VirtualProtect failed target=%p err=%lu", target, GetLastError());
        return false;
    }
    memcpy(original.data(), target, len);  // 存档原始字节（写入前读取）
    memcpy(target, src, len);              // 写入新字节
    VirtualProtect(target, len, oldProtect, &oldProtect);
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
    DWORD oldProtect = 0;
    if (!VirtualProtect(target, origSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LeaveCriticalSection(&Cs());
        Logger::Log("PatchRegistry::Revert: VirtualProtect failed target=%p err=%lu", target, GetLastError());
        return false;
    }
    memcpy(target, it->second.original.data(), origSize);
    VirtualProtect(target, origSize, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), target, origSize);

    Registry().erase(it);
    LeaveCriticalSection(&Cs());
    Logger::Log("PatchRegistry::Revert: restored target=%p (%zu bytes) owner=%ls", target, origSize, owner.c_str());
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
        DWORD oldProtect = 0;
        if (!VirtualProtect(t, origSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            Logger::Log("PatchRegistry::RevertAllFor: VirtualProtect failed target=%p err=%lu", t, GetLastError());
            continue;
        }
        memcpy(t, it->second.original.data(), origSize);
        VirtualProtect(t, origSize, oldProtect, &oldProtect);
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

}  // namespace PatchRegistry