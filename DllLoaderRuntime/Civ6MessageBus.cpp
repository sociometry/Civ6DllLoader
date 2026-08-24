#include "pch.h"
#include "Civ6MessageBus.h"
#include "../common/Logger.h"
#include <unordered_map>
#include <mutex>
#include <string>
#include <vector>

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
        try {
            handler(topic, data, len);
        } catch (...) {
            Logger::Log("Exception in Broadcast handler: %s", name.c_str());
        }
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
        handler(topic, data, len);
    } catch (...) {
        Logger::Log("Exception in SendTo handler: %s", targetName.c_str());
    }
}
