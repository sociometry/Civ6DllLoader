#pragma once
// Civ6DllLoader - 插件在途回调登记 / 卸载前排空。
//
// 用途：登记“加载器正在回调某个插件”的在途调用。卸载插件前先 SetAllowed(false)
// 再 WaitAll()，把该插件上的在途回调等干净，避免把插件 DLL 卸在正在运行的代码上
// （否则就是 UAF / 崩溃）。
//
// 覆盖范围：只覆盖“加载器主动去调插件”的回调类入口——
//     Message / GameEvent / ScriptGlobals / ScriptGlobalsUI / PushMethods（见 Kind）。
// 这些入口由加载器自己发起，可以在进出时记账。
// 不覆盖：钩子(detour) 与“交给 Lua 引擎的函数指针”——这两类不走这里，它们靠
//     加载顺序（先装钩子、后允许卸载）解决。
//
// ======================== 无锁门禁纪律（必读） ========================
// 1) Enter / Guard 绝不允许在持 g_pluginLifecycleMutex 的情况下调用。
//    卸载路径是：持 g_pluginLifecycleMutex -> SetAllowed(false) -> WaitAll()；
//    而 Enter 在无锁下自增计数并读 allowed。若回调线程持该锁再 Enter，就与
//    卸载线程成环（卸载线程持锁等排空，回调线程持锁等 Enter），死锁。
// 2) Enter 内部顺序固定：先加计数、后判放行、非法则回退。反过来会在无锁下
//    重开“判定通过之后才被卸载”的窗口。
// 3) Owner 条目在 Resolve 里常驻不删，指针终身稳定。
// =====================================================================

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>

namespace PluginInFlight {

enum class Kind : uint32_t { Message = 0, GameEvent, ScriptGlobals, ScriptGlobalsUI, PushMethods, Count };
constexpr uint32_t kKindCount = static_cast<uint32_t>(Kind::Count);

struct Owner {
    std::atomic<uint32_t> activeCalls{ 0 };      // 在途计数（含本线程自己的嵌套层）
    std::atomic<bool> allowed{ true };           // 状态镜像：只有 SetAllowed() 写
    std::atomic<uint32_t> byKind[kKindCount]{};  // 诊断用
    std::mutex mtx;
    std::condition_variable cv;
};

Owner* Resolve(const std::wstring& owner);       // 取/建；只在加载或初始化路径调用；返回指针常驻稳定
void SetAllowed(Owner* o, bool allowed);         // 状态镜像唯一写入口（store release）
uint32_t LocalDepth(const Owner* o);             // 本线程在该 owner 上的嵌套层数
std::string Describe(const Owner* o);            // 诊断串
void WaitAll(Owner* o, const wchar_t* ownerName); // 排空等待

class Guard {
public:
    Guard() = default;
    ~Guard();
    Guard(Guard&& other) noexcept;
    Guard& operator=(Guard&& other) noexcept;
    Guard(const Guard&) = delete;
    Guard& operator=(const Guard&) = delete;
    explicit operator bool() const { return active_; }
private:
    friend Guard Enter(Owner* o, Kind kind);
    Guard(Owner* o, Kind kind) : owner_(o), kind_(kind), active_(true) {}
    void Release();
    Owner* owner_ = nullptr;
    Kind kind_ = Kind::Message;
    bool active_ = false;
};

Guard Enter(Owner* o, Kind kind);
}  // namespace PluginInFlight
