#include "pch.h"
#include "Civ6MessageBus.h"
#include "PluginInFlight.h"
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

bool Civ6MessageBus::RegisterHandler(const std::string& name, MessageHandler handler,
                                     const std::wstring& owner,
                                     const std::function<bool()>& canRegister) {
    auto replacement = std::make_shared<HandlerEntry>();
    replacement->owner = owner;
    replacement->handler = std::move(handler);
    // 登记时解析一次：运行时的在途守卫按 owner 记账，不再做宽字符串哈希。
    replacement->inFlight = PluginInFlight::Resolve(owner);
    std::vector<HandlerPtr> replaced;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (canRegister && !canRegister()) return false;
        const auto existing = handlers_.find(name);
        if (existing != handlers_.end() && existing->second->owner != owner) {
            Logger::Log("Message handler name conflict rejected: %s", name.c_str());
            return false;
        }
        if (existing != handlers_.end()) {
            PluginInFlight::SetAllowed(&existing->second->calls, false);
            replaced.push_back(existing->second);
        }
        handlers_[name] = std::move(replacement);
    }
    DrainEntries(replaced);
    return true;
}

void Civ6MessageBus::UnregisterOwner(const std::wstring& owner) {
    if (owner.empty()) return;
    std::vector<HandlerPtr> removed;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto it = handlers_.begin(); it != handlers_.end(); ) {
            if (it->second->owner == owner) {
                PluginInFlight::SetAllowed(&it->second->calls, false);
                removed.push_back(it->second);
                it = handlers_.erase(it);
            } else {
                ++it;
            }
        }
    }
    DrainEntries(removed);
}

void Civ6MessageBus::DrainEntries(const std::vector<HandlerPtr>& entries) {
    // 不持总线锁或 lifecycle 锁等待。只排空被替换/移除的 entry，避免等待新 handler。
    for (const auto& entry : entries) {
        PluginInFlight::WaitAll(&entry->calls, entry->owner.c_str());
    }
}

void Civ6MessageBus::Broadcast(const char* topic, const void* data, size_t len) {
    std::vector<std::pair<std::string, HandlerPtr>> snapshot;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        snapshot.reserve(handlers_.size());
        for (const auto& entry : handlers_) {
            snapshot.emplace_back(entry.first, entry.second);
        }
    }
    for (auto& [name, entry] : snapshot) {
        InvokeEntry(entry, topic, data, len, name.c_str());
    }
}

void Civ6MessageBus::SendTo(const std::string& targetName, const char* topic, const void* data, size_t len) {
    HandlerPtr entry;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = handlers_.find(targetName);
        if (it == handlers_.end()) return;
        entry = it->second;
    }
    InvokeEntry(entry, topic, data, len, targetName.c_str());
}

void Civ6MessageBus::InvokeEntry(const HandlerPtr& entry, const char* topic,
                                 const void* data, size_t len, const char* name) {
    if (!entry) return;
    auto entryGuard = PluginInFlight::Enter(&entry->calls, PluginInFlight::Kind::Message);
    if (!entryGuard) return;
    auto guard = PluginInFlight::Enter(entry->inFlight, PluginInFlight::Kind::Message);
    // inFlight 只为"有 owner 的 handler"解析出来（注册路径只接受被跟踪的插件），
    // 判空是防御；门禁由 owner 的 allowed 镜像决定。
    if (entry->inFlight && !guard) return;
    InvokeHandler(entry->handler, topic, data, len, name);
}
