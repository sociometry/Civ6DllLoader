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

class Civ6MessageBus {
public:
    using MessageHandler = std::function<void(const char* topic, const void* data, size_t len)>;

    // 覆盖/注销会停止旧 entry 的新调用，并等待其它线程的在途调用退出。
    // 本线程回调栈上的调用（含嵌套祖先与递归）继续到自然返回，调用快照保活 entry。
    // 回调内清理返回不代表自身调用链已经退出，不能立即释放该调用链仍依赖的外部状态。

    // 注册消息处理器（同 owner 同名覆盖；不同 owner 的同名注册拒绝）
    void RegisterHandler(const std::string& name, MessageHandler handler,
                         const std::wstring& owner = {});

    // 注销消息处理器
    void UnregisterHandler(const std::string& name);
    void UnregisterOwner(const std::wstring& owner);

    // 注销全部处理器；排空语义与上面一致。
    void Clear();

    // 广播消息给所有处理器
    void Broadcast(const char* topic, const void* data, size_t len);

    // 发送消息到指定处理器
    void SendTo(const std::string& targetName, const char* topic, const void* data, size_t len);

private:
    struct HandlerEntry {
        std::wstring owner;
        MessageHandler handler;
        std::atomic<bool> enabled{ true };
        std::atomic<uint32_t> activeCalls{ 0 };
        std::mutex drainMutex;
        std::condition_variable drainCv;
    };

    using HandlerPtr = std::shared_ptr<HandlerEntry>;
    static void InvokeEntry(const HandlerPtr& entry, const char* topic,
                            const void* data, size_t len, const char* name);
    static void DisableAndDrain(const std::vector<HandlerPtr>& entries);

    std::mutex mtx_;
    std::unordered_map<std::string, HandlerPtr> handlers_;
};

// 插件侧消息收发统一走 common/HookAPI.h（BroadcastMessage/SendMessageTo 函数指针），
// 由运行时的 g_bus 实现；不再提供平行的 C 导出接口。
