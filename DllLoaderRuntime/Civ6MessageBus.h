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

    // 注册消息处理器（同名覆盖）
    void RegisterHandler(const std::string& name, MessageHandler handler,
                         const std::wstring& owner = {});

    // 注销消息处理器
    void UnregisterHandler(const std::string& name);
    void UnregisterOwner(const std::wstring& owner);

    // Drop all handlers (call before unloading plugins).
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
