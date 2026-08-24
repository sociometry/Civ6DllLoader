#pragma once
//#include "pch.h"
#include <string>
#include <functional>
#include <mutex>
#include <unordered_map>

class Civ6MessageBus {
public:
    using MessageHandler = std::function<void(const char* topic, const void* data, size_t len)>;

    // 注册消息处理器（同名覆盖）
    void RegisterHandler(const std::string& name, MessageHandler handler);

    // 注销消息处理器
    void UnregisterHandler(const std::string& name);

    // Drop all handlers (call before unloading plugins).
    void Clear();

    // 广播消息给所有处理器
    void Broadcast(const char* topic, const void* data, size_t len);

    // 发送消息到指定处理器
    void SendTo(const std::string& targetName, const char* topic, const void* data, size_t len);

private:
    std::mutex mtx_;
    std::unordered_map<std::string, MessageHandler> handlers_;
};

// 插件侧消息收发统一走 common/HookAPI.h（BroadcastMessage/SendMessageTo 函数指针），
// 由运行时的 g_bus 实现；不再提供平行的 C 导出接口。
