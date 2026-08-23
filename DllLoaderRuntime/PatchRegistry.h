#pragma once

#include <cstddef>

// 单层补丁注册表（v2 HookAPI Patch/Unpatch 后端）。
//
// 语义：
//  - 首次 Apply(target, bytes, len, owner)：保存该地址的原始字节并记录 owner；
//  - 重复 Apply 同一地址：写入新字节，但保留最初存档（日志告警）；
//  - Revert(target)：恢复原始字节并移除记录；无记录返回 false；
//  - RevertAllFor(owner)：回滚某 owner 的全部未回滚补丁（插件卸载时调用）。
//
// 线程安全：注册表以 CRITICAL_SECTION 保护（GameCore 重载循环在游戏线程、
// 主菜单开关 Mod 在 Loader 工作线程，两处都会触碰）。
namespace PatchRegistry {

// Apply：首次对 target 打补丁时保存原始字节并记录 owner；重复 Apply 同一地址：
// 更新当前字节但保留最初存档（日志告警）。返回 false 表示失败（参数无效/内存保护失败）。
bool Apply(void* target, const void* bytes, size_t len, const wchar_t* owner);

// Revert：恢复原始字节并移除记录；无记录返回 false。
bool Revert(void* target);

// RevertAllFor：回滚某 owner 的全部未回滚补丁（插件卸载时调用）。返回回滚条数。
size_t RevertAllFor(const wchar_t* owner);

}  // namespace PatchRegistry