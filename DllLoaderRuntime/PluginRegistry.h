#pragma once
// PluginRegistry.h — 插件生命周期编排 + 映像查询（阶段 6）。
//
// 本模块拥有插件表（g_plugins）与三把锁，对外的接口分两类：
//   1. LoaderCore.h 里的编排入口（LoadPluginsOf / ResetForReload / IsInitialized …）
//      —— 那些声明在 LoaderCore.h，不在本文件。
//   2. HookAPI 表里的 *Impl 入口 —— 由 HookLoaderApi.cpp 取地址，故声明在这里。
//
// 插件表的只读查询（ResolveOwnerByModule / IsOwnerActive）在 PluginTableAccess.h；
// 生命周期锁经 LoaderCore::LifecycleMutex()。

#include <cstdint>

#include "../common/HookAPI.h"

namespace PluginRegistry {

// ---------------- HookAPI 表里的 *Impl 入口 ----------------
// 这些是插件 ABI 的转发层：先做归属/域校验，再落到实现。

// HookAPI.RegisterMessageHandler：按 handler 所属模块确定 owner，再注册到消息总线。
// 【为什么归本模块而不归 Civ6MessageBus】：它 30/36 行在查插件表、校验插件状态、
// 调 PluginDomain 反查 owner —— 本质是插件身份校验，只在最后一行转给总线。
bool RegisterMessageHandlerImpl(MessageHandlerFn handler);

// HookAPI.IsImageLoaded / GetImageInfo：ImageAddress 的转发（映像查询）。
// 与总线无关；归这里是因为实现要取生命周期锁。
bool IsImageLoadedImpl(HookImageId image);
bool GetImageInfoImpl(HookImageId image, HookImageInfo* outInfo);

// HookAPI.Patch / Unpatch：字节补丁（走 PatchRegistry，带地址域门）。
// 两个都带 __declspec(noinline)：它们用 _ReturnAddress() 反查调用方插件身份，
// 被内联后取到的是 Loader 自己的栈帧，鉴权会静默失效。
__declspec(noinline) bool HookPatch(void* target, const void* bytes, size_t len);
__declspec(noinline) bool HookUnpatch(void* target);

}  // namespace PluginRegistry
