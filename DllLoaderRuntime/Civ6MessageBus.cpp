#include "pch.h"
#include "Civ6MessageBus.h"
#include "PluginInFlight.h"
#include "../common/Logger.h"
#include <algorithm>
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
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (canRegister && !canRegister()) return false;
        const auto existing = handlers_.find(name);
        if (existing != handlers_.end() && existing->second->owner != owner) {
            Logger::Log("Message handler name conflict rejected: %s", name.c_str());
            return false;
        }
        handlers_[name] = std::move(replacement);
    }
    // 覆盖旧 entry 不单独排空：异 owner 的覆盖已被拒绝，新旧 entry 同 owner，
    // 在途调用按 owner 记账，由 owner 级 WaitAll 统一等。
    return true;
}

void Civ6MessageBus::UnregisterHandler(const std::string& name) {
    std::wstring owner;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = handlers_.find(name);
        if (it == handlers_.end()) return;
        owner = it->second->owner;
        handlers_.erase(it);
    }
    // 先摘表项，再在总线锁外排空该 owner 的在途回调。
    PluginInFlight::WaitAll(PluginInFlight::Resolve(owner), owner.c_str());
}

void Civ6MessageBus::UnregisterOwner(const std::wstring& owner) {
    if (owner.empty()) return;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto it = handlers_.begin(); it != handlers_.end(); ) {
            if (it->second->owner == owner) {
                it = handlers_.erase(it);
            } else {
                ++it;
            }
        }
    }
    // 先摘表项，再在总线锁外排空该 owner 的在途回调：等待期间绝不能持 mtx_
    // （回调线程的 Enter / 注册路径都要进总线锁，持锁等待会成环）。
    // 调用方通常已经 SetAllowed(false)；此处只负责等干净。
    PluginInFlight::WaitAll(PluginInFlight::Resolve(owner), owner.c_str());
}

void Civ6MessageBus::Clear() {
    std::vector<HandlerPtr> removed;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (const auto& [name, entry] : handlers_) removed.push_back(entry);
        handlers_.clear();
    }
    // 摘表项（上面，持锁）与排空（下面，锁外）分开：WaitAll 绝不能在 mtx_ 内调用。
    std::vector<std::wstring> waited;
    for (const auto& entry : removed) {
        if (!entry) continue;
        const std::wstring& owner = entry->owner;
        if (std::find(waited.begin(), waited.end(), owner) != waited.end()) continue;
        waited.push_back(owner);
        PluginInFlight::WaitAll(PluginInFlight::Resolve(owner), owner.c_str());
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
    auto guard = PluginInFlight::Enter(entry->inFlight, PluginInFlight::Kind::Message);
    // inFlight 为空 = 没有插件 owner（Loader 自身的处理器）：它没有状态机、没有
    // 放行镜像，直接放行（这不是给 "Loader" 的特判）。非空时门禁由 allowed 镜像决定。
    if (entry->inFlight && !guard) return;
    InvokeHandler(entry->handler, topic, data, len, name);
}
