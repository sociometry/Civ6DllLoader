#include "pch.h"
#include "Civ6MessageBus.h"
#include "PluginBoundary.h"   // SendMessageToImpl 用 CopyCString 抄插件内存
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
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (canRegister && !canRegister()) return false;
        const auto existing = handlers_.find(name);
        if (existing != handlers_.end() && existing->second->owner != owner) {
            Logger::Log("Message handler name conflict rejected: %s", name.c_str());
            return false;
        }
        if (existing != handlers_.end()) {
            // 覆盖：给旧 handler 立一个"已失效"标记就走，不排空、不等待。
            // 旧 entry 的内存由调用快照的 shared_ptr 保活（见头文件生命周期说明）。
            existing->second->active.store(false, std::memory_order_release);
        }
        handlers_[name] = std::move(replacement);
    }
    // 覆盖旧 entry 不排空：异 owner 的覆盖已被拒绝，新旧 entry 同 owner、插件仍活着。
    // 旧 handler 至多被"已取出快照、尚未读 active"的那一次调用多跑一遍，随后被拦下。
    return true;
}

void Civ6MessageBus::UnregisterOwner(const std::wstring& owner) {
    if (owner.empty()) return;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto it = handlers_.begin(); it != handlers_.end(); ) {
            if (it->second->owner == owner) {
                // 标记失效后再摘表项：并发派发可能已从表里取到快照，靠 active 拦下它。
                it->second->active.store(false, std::memory_order_release);
                it = handlers_.erase(it);
            } else {
                ++it;
            }
        }
    }
    // 先摘表项（在总线锁外排空），再等该 owner 的在途回调退出。
    // 这是本类对外承诺的一部分：UnregisterOwner 返回后，该 owner 不会再有回调在执行。
    // 调用方（UnloadPluginByOwnerId / QuarantinePluginByOwner）在调 OnUnload 与
    // FreeLibrary 之前也会各自 WaitAll，但那时等的是同一个 Owner 对象、计数已归零，
    // 所以这里是零成本的；保留它换来的是"总线自身闭环"，不依赖调用方是否记得补一次。
    // 等待期间绝不能持 mtx_：回调线程的 Enter / 注册路径都要进总线锁，持锁等待会成环。
    PluginInFlight::WaitAll(PluginInFlight::Resolve(owner), owner.c_str());
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
    // 1) 本 entry 是否已被覆盖掉。快照可能在覆盖之前取出，靠这个标记把它拦下。
    //    只读一次原子量，不阻塞、不取锁。
    if (!entry->active.load(std::memory_order_acquire)) return;
    // 2) 插件级门禁：owner 已停用（卸载/隔离）时拒绝进入。
    //    inFlight 只为"有 owner 的 handler"解析出来（注册路径只接受被跟踪的插件），
    //    判空是防御；门禁由 owner 的 allowed 镜像决定。
    auto guard = PluginInFlight::Enter(entry->inFlight, PluginInFlight::Kind::Message);
    if (entry->inFlight && !guard) return;
    InvokeHandler(entry->handler, topic, data, len, name);
}


// ================= 消息总线实例与插件 ABI 转发层（阶段 3b 从母体迁入） =================
//
// g_bus 原来是 Civ6DLLHookLoaderAPI.cpp 的文件级 static；转发层（把 HookAPI 的函数指针
// 转成类方法调用）与类定义同文件最自然，故一起搬进来。其它模块要拿它经 GlobalBus()
// 访问器，而不是 extern 变量。

static Civ6MessageBus g_bus;

Civ6MessageBus& GlobalBus() {
    return g_bus;
}

void BroadcastMessageImpl(const char* topic, const void* data, size_t len) {
    g_bus.Broadcast(topic, data, len);
}

void SendMessageToImpl(const char* pluginName, const char* topic, const void* data, size_t len) {
    // pluginName 是插件内存，而 SendTo 收 const std::string&：直接传进去会按 NUL 边界读它。
    // MSVC 的 basic_string(const char*) 不检查空指针（直接 traits::length），空指针/野指针
    // 都是一次裸 strlen。与其它字符串入口同一口径：锁外先抄进 Loader 自有存储。
    std::string nameCopy;
    if (!PluginBoundary::CopyCString(pluginName, nameCopy) || nameCopy.empty()) {
        Logger::Log("SendMessageTo rejected: pluginName pointer unreadable or empty");
        return;
    }
    g_bus.SendTo(nameCopy, topic, data, len);
}
