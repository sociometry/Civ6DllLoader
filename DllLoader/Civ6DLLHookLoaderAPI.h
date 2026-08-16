#pragma once

// Runtime-internal loader API. Plugins must include common/HookAPI.h only.
#include "../common/HookAPI.h"
#include <vector>
#include <string>

enum class PushMethodSigType {
    NoManager,
    WithManager
};

struct StoredLuaMethod {
    LuaMethodFunc luaMethodFunc = nullptr;
    std::string internalName;
    std::string exposedName;
};

void* InstallPushMethodsNoManager(void* target, const std::vector<StoredLuaMethod>& methods);
void* InstallPushMethodsWithManager(void* target, const std::vector<StoredLuaMethod>& methods);

bool InitializeLoader(HMODULE hModule);
HMODULE Create();
bool AttachGameCore(HMODULE gameCore);
void LoadPlugins();
void CleanupLoader();
void BroadcastLoaderMessage(const char* topic, const void* data, size_t len);
