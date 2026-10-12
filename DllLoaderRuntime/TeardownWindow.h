#pragma once
// TeardownWindow.h — GameCore teardown 窗口的共享状态（阶段 3a）。
//
// 为什么单独成头：这个窗口有两个模块在用，而它们分属不同 TU：
//   * 写侧：PluginRegistry（ResetForReload / ClearGameCoreTeardownWindow）
//          与 HookEngine（RemoveGameCoreDomainSiteRecords）
//   * 读侧：PluginDomain（TargetInTearingDownGameCore）、HookEngine（装钩前检查）
// 若各处各留一份 static，写方改的是自己那份、读方读的是另一份 —— 窗口静默失效，
// 且不报错（teardown 保护形同虚设）。所以必须共享同一份存储。
//
// 两个字段必须"成对生效"，不能各写各的裸变量：
//   写序固定：先 size 再 address(release)；清零点：先 address(release) 再 size。
//   读序固定：先 address(acquire)，非 0 才读 size。
// 见 docs/ARCHITECTURE.md §2.1。

#include <atomic>
#include <cstdint>

namespace LoaderCore::Teardown {

// 必须是 inline 变量（项目 LanguageStandard=stdcpp20），【绝不能】写成 static：
// static 会让每个 TU 得到独立副本，正是上面说的静默失效。
// std::atomic<uintptr_t>{0} 是常量初始化，不存在 static-init-order 问题。
inline std::atomic<uintptr_t> g_address{ 0 };
inline std::atomic<uint32_t>  g_sizeOfImage{ 0 };

inline void SetWindow(uintptr_t base, uint32_t sizeOfImage) {
    g_sizeOfImage.store(sizeOfImage, std::memory_order_relaxed);
    g_address.store(base, std::memory_order_release);
}

inline void ClearWindow() {
    g_address.store(0, std::memory_order_release);
    g_sizeOfImage.store(0, std::memory_order_relaxed);
}

// target 是否落在"正在拆除的旧映像"区间内。
// 注意：现有代码用的是 PluginDomain::TargetInTearingDownGameCore（它内联了同样的判断），
// 本函数是给 HookEngine 等新调用点用的统一入口；两者的判据必须保持一致。
inline bool IsTargetInWindow(const void* target) {
    const uintptr_t base = g_address.load(std::memory_order_acquire);
    if (base == 0) return false;
    const uint32_t size = g_sizeOfImage.load(std::memory_order_relaxed);
    const uintptr_t p = reinterpret_cast<uintptr_t>(target);
    return p >= base && (p - base) < size;
}

}  // namespace LoaderCore::Teardown
