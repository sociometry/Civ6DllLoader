#pragma once
//#include "pch.h"
#include <string>
#include <functional>
#include <mutex>
#include <unordered_map>

class Civ6MessageBus {
public:
    using MessageHandler = std::function<void(const char* topic, const void* data, size_t len)>;

    // ע����Ϣ������������ͬ����
    void RegisterHandler(const std::string& name, MessageHandler handler);

    // ע����Ϣ������
    void UnregisterHandler(const std::string& name);

    // Drop all handlers (call before unloading plugins).
    void Clear();

    // �㲥��Ϣ�����д�����
    void Broadcast(const char* topic, const void* data, size_t len);

    // ������Ϣ��ָ��������
    void SendTo(const std::string& targetName, const char* topic, const void* data, size_t len);

private:
    std::mutex mtx_;
    std::unordered_map<std::string, MessageHandler> handlers_;
};

extern Civ6MessageBus g_messageBus;

// C���ӿڣ����㵼��DLL����
#ifdef __cplusplus
extern "C" {
#endif

    void RegisterMessageHandler(const char* name, void (*handler)(const char*, const void*, size_t));
    void UnregisterMessageHandler(const char* name);
    void BroadcastMessage(const char* topic, const void* data, size_t len);
    void SendMessageTo(const char* targetName, const char* topic, const void* data, size_t len);

#ifdef __cplusplus
}
#endif
