#include "pch.h"
#include "Civ6MessageBus.h"
#include "../common/Logger.h"
#include <unordered_map>
#include <mutex>
#include <string>
#include <vector>

namespace {
struct HandlerCallFrame;
thread_local const HandlerCallFrame* g_handlerCallStack = nullptr;

// 栈上链表记录整个同步回调链，不分配内存；嵌套/递归返回后自动恢复。
struct HandlerCallFrame {
    const void* entry;
    const HandlerCallFrame* previous;

    explicit HandlerCallFrame(const void* handlerEntry) noexcept
        : entry(handlerEntry), previous(g_handlerCallStack) {
        g_handlerCallStack = this;
    }
    ~HandlerCallFrame() { g_handlerCallStack = previous; }
    HandlerCallFrame(const HandlerCallFrame&) = delete;
    HandlerCallFrame& operator=(const HandlerCallFrame&) = delete;
};

size_t ActiveCallsOnThisThread(const void* entry) {
    size_t count = 0;
    for (const auto* frame = g_handlerCallStack; frame; frame = frame->previous) {
        if (frame->entry == entry) ++count;
    }
    return count;
}

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

void Civ6MessageBus::RegisterHandler(const std::string& name, MessageHandler handler,
                                     const std::wstring& owner) {
    auto replacement = std::make_shared<HandlerEntry>();
    replacement->owner = owner;
    replacement->handler = std::move(handler);
    std::vector<HandlerPtr> replaced;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        const auto existing = handlers_.find(name);
        if (existing != handlers_.end()) {
            if (existing->second->owner != owner) {
                Logger::Log("Message handler name conflict rejected: %s", name.c_str());
                return;
            }
            replaced.push_back(existing->second);
        }
        handlers_[name] = std::move(replacement);
    }
    DisableAndDrain(replaced);
}

void Civ6MessageBus::UnregisterHandler(const std::string& name) {
    std::vector<HandlerPtr> removed;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = handlers_.find(name);
        if (it != handlers_.end()) {
            removed.push_back(it->second);
            handlers_.erase(it);
        }
    }
    DisableAndDrain(removed);
}

void Civ6MessageBus::UnregisterOwner(const std::wstring& owner) {
    if (owner.empty()) return;
    std::vector<HandlerPtr> removed;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto it = handlers_.begin(); it != handlers_.end(); ) {
            if (it->second->owner == owner) {
                removed.push_back(it->second);
                it = handlers_.erase(it);
            } else {
                ++it;
            }
        }
    }
    DisableAndDrain(removed);
}

void Civ6MessageBus::Clear() {
    std::vector<HandlerPtr> removed;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (const auto& [name, entry] : handlers_) removed.push_back(entry);
        handlers_.clear();
    }
    DisableAndDrain(removed);
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
    if (!entry || !entry->enabled.load(std::memory_order_acquire)) return;
    entry->activeCalls.fetch_add(1, std::memory_order_acq_rel);
    if (entry->enabled.load(std::memory_order_acquire)) {
        const HandlerCallFrame frame(entry.get());
        InvokeHandler(entry->handler, topic, data, len, name);
    }
    {
        std::lock_guard<std::mutex> lock(entry->drainMutex);
        entry->activeCalls.fetch_sub(1, std::memory_order_acq_rel);
    }
    // 嵌套清理可能等的是“只剩本线程的 N 层”，因此每次退出都要通知。
    entry->drainCv.notify_all();
}

void Civ6MessageBus::DisableAndDrain(const std::vector<HandlerPtr>& entries) {
    for (const auto& entry : entries) {
        entry->enabled.store(false, std::memory_order_release);
    }
    for (const auto& entry : entries) {
        // 本线程整条回调链（含重复递归帧）必须自然返回，不能同步等待自己；
        // 其它线程的调用仍需排空。InvokeEntry 的 shared_ptr 快照保活旧 entry。
        const size_t localCalls = ActiveCallsOnThisThread(entry.get());
        std::unique_lock<std::mutex> lock(entry->drainMutex);
        entry->drainCv.wait(lock, [&entry, localCalls] {
            return entry->activeCalls.load(std::memory_order_acquire) <= localCalls;
        });
    }
}
