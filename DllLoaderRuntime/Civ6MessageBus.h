#pragma once
//#include "pch.h"
#include <string>
#include <functional>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace PluginInFlight { struct Owner; }

class Civ6MessageBus {
public:
    using MessageHandler = std::function<void(const char* topic, const void* data, size_t len)>;

    // 生命周期边界（谁负责什么）：
    //   - 覆盖同名 handler【不阻塞】：旧 entry 标记为失效（active=false），派发路径据此
    //     跳过它；旧 entry 的内存由调用快照的 shared_ptr 保活到最后一个使用者退出。
    //   - 注销（UnregisterOwner）【会排空】：摘掉该 owner 的登记后等待其在途回调退出，
    //     返回时保证该 owner 不再有回调在执行。这是本类自身的承诺，不依赖调用方补等。
    //     插件生命周期管理（UnloadPluginByOwnerId / QuarantinePluginByOwner）在调
    //     OnUnload 与 FreeLibrary 之前也会 WaitAll，等的是同一个 Owner、计数已归零。
    // 本线程回调栈上的调用（含嵌套祖先与递归）继续到自然返回。
    // 回调内清理返回不代表自身调用链已经退出，不能立即释放该调用链仍依赖的外部状态。

    // 注册消息处理器（同 owner 同名覆盖；不同 owner 的同名注册返回 false）。
    // canRegister 在总线锁内、发布前执行，使生命周期校验与 UnregisterOwner 串行化；
    // 不得重入总线。调用者不得持有回调需要的锁。
    bool RegisterHandler(const std::string& name, MessageHandler handler,
                         const std::wstring& owner = {},
                         const std::function<bool()>& canRegister = {});

    void UnregisterOwner(const std::wstring& owner);

    // 广播消息给所有处理器
    void Broadcast(const char* topic, const void* data, size_t len);

    // 发送消息到指定处理器
    void SendTo(const std::string& targetName, const char* topic, const void* data, size_t len);

private:
    struct HandlerEntry {
        std::wstring owner;
        MessageHandler handler;
        // 在途记账 / 门禁统一走 PluginInFlight（注册时解析一次，见 .cpp）。
        PluginInFlight::Owner* inFlight = nullptr;
        // 本 entry 自身的有效性。覆盖同名 handler 时置 false，派发路径据此丢弃旧 handler。
        // 与 inFlight 的分工：inFlight 管"插件是否还允许被回调"（跨卸载/跨代），
        // active 只管"这一个 handler 是否已被替换掉"（同 owner 内的换实现）。
        // 用独立标记而不是复用 inFlight：覆盖时插件仍然活着，不能把 owner 级门禁关掉
        // （那会连带拒绝该 owner 的其它回调）。旧 entry 不删也不等——调用快照持有的
        // shared_ptr 会保活它到最后一个使用者退出。
        std::atomic<bool> active{ true };
    };

    using HandlerPtr = std::shared_ptr<HandlerEntry>;
    static void InvokeEntry(const HandlerPtr& entry, const char* topic,
                            const void* data, size_t len, const char* name);

    std::mutex mtx_;
    std::unordered_map<std::string, HandlerPtr> handlers_;
};

// 插件侧消息收发统一走 common/HookAPI.h（BroadcastMessage/SendMessageTo 函数指针），
// 由运行时的 g_bus 实现；不再提供平行的 C 导出接口。
//
// g_bus 本身定义在 Civ6MessageBus.cpp 内（文件级 static，不导出变量）。
// 需要它的其它模块（PluginRegistry 的加载/卸载/隔离路径要调 UnregisterOwner）
// 经这个访问器拿引用 —— 而不是把 g_bus 做成 extern 全局（各模块只持有自己那份私有状态）。
Civ6MessageBus& GlobalBus();

// 插件 ABI 转发层（实现在 Civ6MessageBus.cpp）：把 HookAPI 里的函数指针
// （BroadcastMessage / SendMessageTo）转成类方法调用。
// 声明在这里是因为母体的 g_hookApi 初始化表要取它们的地址。
void BroadcastMessageImpl(const char* topic, const void* data, size_t len);
void SendMessageToImpl(const char* pluginName, const char* topic, const void* data, size_t len);
