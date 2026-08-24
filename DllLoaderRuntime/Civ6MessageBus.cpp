#include "pch.h"
#include "Civ6MessageBus.h"
#include "../common/Logger.h"
#include <unordered_map>
#include <mutex>
#include <string>
#include <vector>

namespace {

// SEH thunk：__try 不能与带析构的局部对象同函数，独立成 noinline 函数。
// 工程以 /EHsc 编译，catch(...) 捕不住访问违例等硬件异常——插件 OnMessage
// 里的野指针必须在这里兜住，否则直接带崩游戏。
__declspec(noinline) void CallHandlerSeh(const Civ6MessageBus::MessageHandler& handler,
                                         const char* topic, const void* data, size_t len,
                                         const char* name) {
    __try {
        handler(topic, data, len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("Exception in message handler '%s' (SEH code=0x%08X)",
            name ? name : "?", GetExceptionCode());
    }
}

// 统一调用入口：SEH 兜硬件异常，C++ catch 兜 throw 的异常。
void InvokeHandler(const Civ6MessageBus::MessageHandler& handler, const char* topic,
                   const void* data, size_t len, const char* name) noexcept {
    try {
        CallHandlerSeh(handler, topic, data, len, name);
    } catch (...) {
        Logger::Log("Exception in message handler '%s' (C++)", name ? name : "?");
    }
}

}  // namespace

void Civ6MessageBus::RegisterHandler(const std::string& name, MessageHandler handler) {
    std::lock_guard<std::mutex> lock(mtx_);
    handlers_[name] = std::move(handler);
}

void Civ6MessageBus::UnregisterHandler(const std::string& name) {
    std::lock_guard<std::mutex> lock(mtx_);
    handlers_.erase(name);
}

void Civ6MessageBus::Clear() {
    std::lock_guard<std::mutex> lock(mtx_);
    handlers_.clear();
}

void Civ6MessageBus::Broadcast(const char* topic, const void* data, size_t len) {
    std::vector<std::pair<std::string, MessageHandler>> snapshot;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        snapshot.reserve(handlers_.size());
        for (const auto& entry : handlers_) {
            snapshot.push_back(entry);
        }
    }
    for (auto& [name, handler] : snapshot) {
        InvokeHandler(handler, topic, data, len, name.c_str());
    }
}

void Civ6MessageBus::SendTo(const std::string& targetName, const char* topic, const void* data, size_t len) {
    MessageHandler handler;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = handlers_.find(targetName);
        if (it == handlers_.end()) return;
        handler = it->second;
    }
    try {
        InvokeHandler(handler, topic, data, len, targetName.c_str());
    } catch (...) {
        Logger::Log("Exception in SendTo handler: %s", targetName.c_str());
    }
}
