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
// 不覆盖：钩子(detour) 与交给 Lua 引擎的函数指针。站点/跳板不提前回收；插件模块等
//     引擎卸载 Lua 环境后释放。插件自建线程仍须在 OnUnload 中停止。
//
// ======================== 无锁门禁纪律（必读） ========================
// 1) 回调在 lifecycle 锁外执行；卸载方持该锁 SetAllowed(false)，放锁后才 WaitAll。
//    若持 lifecycle 锁等待，会阻塞在途回调里的 HookAPI 调用并形成死锁。
// 2) Enter 内部顺序固定：先加计数、后判放行、非法则回退。反过来会在无锁下
//    重开“判定通过之后才被卸载”的窗口。
// 3) Owner 指针终身稳定；每次加载用 BeginLifetime 新建一份，旧快照永远停用。
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
Owner* BeginLifetime(const std::wstring& owner); // 加载新一代；调用方持插件生命周期锁
void SetAllowed(Owner* o, bool allowed);         // 状态镜像唯一写入口，与 Enter/WaitAll 全序同步
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
