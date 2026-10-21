#pragma once

// Runtime-internal loader API. Plugins must include common/HookAPI.h only.
#include "../common/HookAPI.h"
#include <vector>
#include <string>

struct StoredLuaMethod {
    LuaMethodFunc luaMethodFunc = nullptr;
    std::string internalName;
    std::string exposedName;
    std::wstring owner;  // 注册时活跃插件名（空 = Loader 自身；插件卸载时按此撤销）
};

void* InstallPushMethodsNoManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                  const std::wstring& owner);
void* InstallPushMethodsWithManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                    const std::wstring& owner);

bool AttachGameCore(HMODULE gameCore);
