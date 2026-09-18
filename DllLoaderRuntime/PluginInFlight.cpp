#include "pch.h"
#include "PluginInFlight.h"

#include "../common/Logger.h"

#include <chrono>
#include <cstdio>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace PluginInFlight {
namespace {

// 本线程在各 owner 上的嵌套层数。thread_local：只看自己这一条线程。
// 用 Owner* 做键线性扫描：插件数只有个位数，比宽字符串哈希快，且不产生分配。
thread_local std::vector<std::pair<const Owner*, uint32_t>> g_depth;

struct Registry {
    std::mutex mutex;
    std::unordered_map<std::wstring, Owner*> current;
};

Registry& Owners() {
    static Registry registry;
    return registry;
}

// 在本线程 depth 表里找该 owner 的槽位；没有返回 -1。
int FindDepthSlot(const Owner* o) {
    for (size_t i = 0; i < g_depth.size(); ++i) {
        if (g_depth[i].first == o) return static_cast<int>(i);
    }
    return -1;
}

// 进入一层回调：本线程在该 owner 上的嵌套层数 +1。
void DepthInc(const Owner* o) {
    const int slot = FindDepthSlot(o);
    if (slot >= 0) {
        ++g_depth[static_cast<size_t>(slot)].second;
        return;
    }
    g_depth.emplace_back(o, 1u);
}

// 退出一层回调：减到 0 就把槽位摘掉（与末尾交换后弹出），表只随嵌套深度增长。
void DepthDec(const Owner* o) {
    const int slot = FindDepthSlot(o);
    if (slot < 0) return;
    const size_t idx = static_cast<size_t>(slot);
    if (--g_depth[idx].second == 0) {
        g_depth[idx] = g_depth.back();
        g_depth.pop_back();
    }
}

// ---------------- 唯一的 decrement 出口 ----------------
// (a) 正常退出（Guard::Release）与“进入失败回退”（Enter 里 allowed==false）都
//     走这一个函数，不允许在别处再写一次 fetch_sub：两处各写一遍迟早漏掉一处
//     通知，结果就是 WaitAll 丢唤醒、永久挂住。
// (b) 为什么 fetch_sub 放在临界区外、只在“归零 或 正在排空”时才进临界区：
//     不在排空窗口（allowed==true）时根本没有等待者，没必要为一个 notify 去
//     抢锁；而一旦 allowed==false，则每次减计数都持锁 notify，与 WaitAll 的
//     “持锁判定谓词 + wait”配对，杜绝“通知早于入队”的丢失窗口。
void ReleaseCount(Owner* o, Kind kind) {
    if (!o) return;
    o->byKind[(uint32_t)kind].fetch_sub(1, std::memory_order_relaxed);
    const uint32_t prev = o->activeCalls.fetch_sub(1, std::memory_order_acq_rel);
    if (prev == 1 || !o->allowed.load(std::memory_order_acquire)) {  // 归零 或 正在排空
        std::lock_guard<std::mutex> lk(o->mtx);
        o->cv.notify_all();
    }
}

}  // namespace

// ---------------------------------------------------------------- 登记表

Owner* Resolve(const std::wstring& owner) {
    if (owner.empty()) return nullptr;
    auto& registry = Owners();
    std::lock_guard<std::mutex> lk(registry.mutex);
    auto it = registry.current.find(owner);
    if (it != registry.current.end()) return it->second;
    Owner* o = new Owner();
    registry.current.emplace(owner, o);
    return o;
}

Owner* BeginLifetime(const std::wstring& owner) {
    if (owner.empty()) return nullptr;
    auto& registry = Owners();
    std::lock_guard<std::mutex> lk(registry.mutex);
    Owner*& current = registry.current[owner];
    Owner* next = new Owner();
    next->allowed.store(false, std::memory_order_relaxed);
    if (current) SetAllowed(current, false);
    // 旧对象不能删除或重新放行：消息/注册表的锁外快照可能还握着它。
    current = next;
    return next;
}

void SetAllowed(Owner* o, bool allowed) {
    // 与 Enter 的加计数/读门禁及 WaitAll 的读计数建立同一个全序，避免双方都读到旧值。
    if (o) o->allowed.store(allowed, std::memory_order_seq_cst);
}

uint32_t LocalDepth(const Owner* o) {
    if (!o) return 0;
    const int slot = FindDepthSlot(o);
    return slot >= 0 ? g_depth[static_cast<size_t>(slot)].second : 0u;
}

std::string Describe(const Owner* o) {
    if (!o) return std::string("(null)");
    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "(在途=%u Message=%u GameEvent=%u ScriptGlobals=%u ScriptGlobalsUI=%u PushMethods=%u)",
                  o->activeCalls.load(std::memory_order_relaxed),
                  o->byKind[(uint32_t)Kind::Message].load(std::memory_order_relaxed),
                  o->byKind[(uint32_t)Kind::GameEvent].load(std::memory_order_relaxed),
                  o->byKind[(uint32_t)Kind::ScriptGlobals].load(std::memory_order_relaxed),
                  o->byKind[(uint32_t)Kind::ScriptGlobalsUI].load(std::memory_order_relaxed),
                  o->byKind[(uint32_t)Kind::PushMethods].load(std::memory_order_relaxed));
    return std::string(buf);
}

// ---------------------------------------------------------------- 排空等待

void WaitAll(Owner* o, const wchar_t* ownerName) {
    if (!o) return;
    // 本线程在该 owner 上的嵌套层数。等待条件是 activeCalls <= local：本线程
    // 自己的嵌套层不算“别人的在途”，于是“插件在自己的回调里触发自己的卸载”
    // 不会自等（自己等自己永远等不到）。
    const uint32_t local = LocalDepth(o);
    std::unique_lock<std::mutex> lk(o->mtx);
    auto ready = [&] { return o->activeCalls.load(std::memory_order_seq_cst) <= local; };
    int warns = 0;
    while (!o->cv.wait_for(lk, std::chrono::seconds(5), ready)) {
        if (warns == 0 || warns % 6 == 0) {
            Logger::Log("[InFlight] 等待插件回调排空超过 %d 秒：owner=%ls 本线程嵌套=%u %s",
                        (warns + 1) * 5, ownerName ? ownerName : L"(null)", local, Describe(o).c_str());
        }
        ++warns;
    }
    // 永不放弃：超时只记限流日志。放弃等待就等于把插件卸在正在运行的代码上
    // （UAF），比挂住更糟。
    //
    // 调用方不得持 g_pluginLifecycleMutex 调本函数（见头文件门禁纪律第 1 条）：
    // 持锁等待会与回调线程的 Enter 成环。
}

// ---------------------------------------------------------------- Guard

Guard::~Guard() {
    Release();
}

Guard::Guard(Guard&& other) noexcept
    : owner_(other.owner_), kind_(other.kind_), active_(other.active_) {
    other.owner_ = nullptr;
    other.active_ = false;
}

Guard& Guard::operator=(Guard&& other) noexcept {
    if (this != &other) {
        Release();               // 先释放自己已占用的在途，再接管对方的
        owner_ = other.owner_;
        kind_ = other.kind_;
        active_ = other.active_;
        other.owner_ = nullptr;
        other.active_ = false;
    }
    return *this;
}

void Guard::Release() {
    if (!active_) return;
    active_ = false;
    DepthDec(owner_);
    ReleaseCount(owner_, kind_);
    owner_ = nullptr;
}

// 进入一次“加载器 -> 插件”的回调。
// 顺序绝对不能反过来：先加计数、后判放行。反过来（先读 allowed 再自增）会在
// 无锁下重开“判定通过之后、自增之前插件正好被卸载”的窗口——那样 WaitAll
// 看不到这次在途，照样 UAF。
Guard Enter(Owner* o, Kind kind) {
    if (!o) return Guard();
    o->activeCalls.fetch_add(1, std::memory_order_seq_cst);
    o->byKind[(uint32_t)kind].fetch_add(1, std::memory_order_relaxed);
    if (!o->allowed.load(std::memory_order_seq_cst)) {
        ReleaseCount(o, kind);   // 回退；此时还没进 depth
        return Guard();
    }
    DepthInc(o);
    return Guard(o, kind);
}

}  // namespace PluginInFlight
