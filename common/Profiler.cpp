#include "pch.h"
#include "Profiler.h"
#include "Logger.h"

#include <Windows.h>
#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <algorithm>

namespace {

// 频率只取一次。QueryPerformanceFrequency 恒定，进程内不会变。
int64_t QpcFrequency() {
    static const int64_t freq = [] {
        LARGE_INTEGER f{};
        QueryPerformanceFrequency(&f);
        return f.QuadPart > 0 ? f.QuadPart : 1;
    }();
    return freq;
}

int64_t QpcNow() {
    LARGE_INTEGER t{};
    QueryPerformanceCounter(&t);
    return t.QuadPart;
}

// 热路径上的唯一开销。默认 false（未注入前不测）。
std::atomic<bool> g_enabled{ false };

struct Agg {
    uint64_t count = 0;
    double totalMs = 0.0;
    double maxMs = 0.0;
};

// 聚合表。Begin/End 会在游戏线程与 Loader 工作线程上被调，
// 所以必须加锁；但只在启用时才进这里（未启用连这层都不过）。
std::mutex& AggMutex() {
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, Agg>& AggMap() {
    static std::unordered_map<std::string, Agg> m;
    return m;
}

}  // namespace

namespace Profiler {

void SetEnabled(bool enabled) {
    g_enabled.store(enabled, std::memory_order_relaxed);
}

bool Enabled() {
    return g_enabled.load(std::memory_order_relaxed);
}

int64_t Begin(const char* scope) {
    if (!Enabled() || !scope || !*scope) return 0;
    return QpcNow();
}

double TicksToMs(int64_t ticks) {
    if (ticks <= 0) return 0.0;
    return static_cast<double>(ticks) * 1000.0 / static_cast<double>(QpcFrequency());
}

void End(const char* scope, int64_t beginTick, const char* note) {
    if (beginTick == 0 || !scope || !*scope) return;
    const int64_t elapsed = QpcNow() - beginTick;
    const double ms = TicksToMs(elapsed);

    if (note && *note) {
        Logger::Log("[Prof] %s %.3f ms (%s)", scope, ms, note);
    } else {
        Logger::Log("[Prof] %s %.3f ms", scope, ms);
    }

    std::lock_guard<std::mutex> lock(AggMutex());
    Agg& a = AggMap()[std::string(scope)];
    a.count += 1;
    a.totalMs += ms;
    if (ms > a.maxMs) a.maxMs = ms;
}

void Reset() {
    std::lock_guard<std::mutex> lock(AggMutex());
    AggMap().clear();
}

void LogSummary(const char* tag) {
    if (!Enabled()) return;

    // 先拷出来再排序：锁内不做 IO（Logger 自己也有锁，这里保持"锁内不碰文件"）。
    std::vector<std::pair<std::string, Agg>> rows;
    {
        std::lock_guard<std::mutex> lock(AggMutex());
        rows.reserve(AggMap().size());
        for (const auto& kv : AggMap()) rows.emplace_back(kv.first, kv.second);
    }
    if (rows.empty()) {
        Logger::Log("[Prof] === summary(%s): no samples ===", tag ? tag : "");
        return;
    }
    std::sort(rows.begin(), rows.end(),
        [](const auto& a, const auto& b) { return a.second.totalMs > b.second.totalMs; });

    uint64_t totalCount = 0;
    double totalMs = 0.0;
    for (const auto& r : rows) {
        totalCount += r.second.count;
        totalMs += r.second.totalMs;
    }
    Logger::Log("[Prof] === summary(%s): %zu scope(s), %llu sample(s), %.3f ms total ===",
        tag ? tag : "", rows.size(), static_cast<unsigned long long>(totalCount), totalMs);
    for (const auto& r : rows) {
        Logger::Log("[Prof]   total=%10.3fms  count=%6llu  max=%9.3fms  avg=%9.3fms  %s",
            r.second.totalMs,
            static_cast<unsigned long long>(r.second.count),
            r.second.maxMs,
            r.second.count ? r.second.totalMs / static_cast<double>(r.second.count) : 0.0,
            r.first.c_str());
    }
}

}  // namespace Profiler
