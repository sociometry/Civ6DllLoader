#pragma once
// HookEngine.h — 挂钩站点表 / JIT stub / capture / teardown 站点操作（阶段 5）。
//
// 本头文件在阶段 4 就建好，因为 ScriptBridge 要用 InstallLoaderDetourOnSite
// （共享脚本钩的安装路径），而它属 HookEngine。阶段 5 抽出该模块后，
// 其余声明陆续补进来。

#include <cstddef>
#include <cstdint>

#include "../common/HookAPI.h"

namespace HookEngine {

// 把一个 detour 装到统一站点表上（内部自己取 MinHook 锁）。
//   target   目标地址
//   detour   插件/Loader 的 detour
//   origSlot 出参：站点跳板（尾跳原函数）
//   why      日志用的调用方标识
// 返回 false 表示站点不可用 / 已被别人占用 / 目标不可读。
//
// 调用方【不得】持 Runtime::MinHookMutex()。
bool InstallLoaderDetourOnSite(void* target, void* detour, void** origSlot, const char* why);

}  // namespace HookEngine
