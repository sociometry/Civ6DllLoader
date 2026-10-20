#pragma once
// PluginDomain.h — 插件域规则 / 调用方鉴权（阶段 2）。
//
// 这是所有子系统的公共下层：HookAPI 的每个插件入口都要先问"调用方是谁、这个地址
// 对它开放吗"。因此它必须独立成模块 —— 塞进任何业务文件都会逼所有模块 include 那个
// 业务头文件。
//
// 依赖方向：本模块【不依赖】PluginRegistry / HookEngine / ScriptBridge。
// 它读插件表要经 PluginRegistry::ResolveOwnerByModule（只读门面），
// 这样 g_plugins / g_activePluginOwner / g_activePluginModule 三个变量都不必外泄。

#include <optional>
#include <string>

#include <Windows.h>

#include "LoaderCore.h"        // LoaderCore::PluginCategory

namespace PluginDomain {

// owner 归属查询的返回：ownerId + 该 owner 的插件类别（Global / GameCore）。
// 类别在同一次 g_plugins 遍历里带回，不额外加锁、不额外遍历。
struct CallerPluginInfo {
    std::wstring ownerId;
    LoaderCore::PluginCategory category = LoaderCore::PluginCategory::Global;
};

// 按代码地址反查它属于哪个插件（先 GetModuleHandleExW 取模块，再查表）。
// 查表规则见 PluginRegistry::ResolveOwnerByModule 的实现（两段优先级）。
// 找不到 / 地址不在任何已加载模块内 -> nullopt。
std::optional<CallerPluginInfo> ResolvePluginOwnerForAddress(const void* codeAddress);

// 上者的"必须成功"版本：失败时按 apiName 记一行拒绝日志。
std::optional<CallerPluginInfo> RequirePluginOwner(const void* codeAddress, const char* apiName);

// GameCore 专属入口的运行期兜底门：owner 缺失或不是 GameCore -> false + 日志。
// 这是编译期门禁（HookAPI.h 的宏重命名）之外的第二道门，防的是不带 HookAPI.h、
// 按结构体偏移直接调这些入口的插件。
bool RequireGameCoreOwner(const void* codeAddress, const char* apiName);

// Global 专属入口的运行期兜底门：owner 缺失或不是 Global -> false + 日志。
// 与 RequireGameCoreOwner 对称，防的是绕过 HookAPI.h 直接按偏移调用的插件。
bool RequireGlobalOwner(const void* codeAddress, const char* apiName);

// target 是否落在【当前】GameCore 映像内。
bool TargetInCurrentGameCore(void* target);

// target 是否落在【正在拆除的旧 GameCore 映像】区间内（teardown 窗口）。
// 拆开的理由见 TeardownWindow.h：窗口是跨 TU 共享状态。
bool TargetInTearingDownGameCore(void* target);

// ================= 地址开放性门：调用方类别 × 目标地址域 =================
// 只对"取地址/给地址"的入口设门。域的划分依据：GameCore 映像是随对局重载的【短命域】，
// 常驻（Global）插件若跨代持有它的地址就会在重载后悬垂；反之 GameCore 插件只应在自己
// 这一代映像内活动。三类判定都只读，不改动任何状态、不抛异常；拒绝时按统一格式记日志
// （地址/映像对调用方不开放），调用方按其原本的失败值返回。
// 日志正文统一为：<ApiName> rejected: target|image|range <位点> is not open to caller (<Global|GameCore>)
//
// 规则是【正面】的（"允许落在哪里"），不是"不在 GameCore 里就算数"：
//   GameCore 类别：目标必须落在【当前 GameCore 映像】内（它唯一的合法域）；
//   Global  类别：目标必须落在【某个已加载的非 GameCore 模块】内 —— exe、常驻系统 dll
//                 （user32/dxgi…）、插件自己的模块都算；堆、VirtualAlloc 的 JIT 页、空闲
//                 地址、以及将来会被 GameCore 占用的地址一律拒绝。
// 旧的"与当前 GameCore 映像不相交就放行"为什么不行：GameCore 未加载时（阶段 A）它对任何
// 地址都放行，"Global 绝对不许动 GameCore dll"就只能靠"那块内存写不进去/不可执行"兜住，
// 而不是一条可判定、可解释的规则。

// 地址开放性门（正面规则）：判断 target 对某类别调用方是否可操作。
//   * Global 只能落在"已加载的非 GameCore 模块"内；
//   * GameCore 只能落在当前 GameCore 映像内。
bool IsTargetOpenToCaller(LoaderCore::PluginCategory caller, const void* target,
    const char* apiName);

// 同上，但判据是"整个映像"而非单个地址（Resolve* 的 image 参数）。
bool IsImageOpenToCaller(LoaderCore::PluginCategory caller, HookImageId image,
    const char* apiName);

// 区间版：Patch 的 [target, target+len) 必须完整落在允许的模块内，
// 且不得横跨两个模块。
bool IsRangeOpenToCaller(LoaderCore::PluginCategory caller, const void* target, size_t len,
    const char* apiName);

// 类别名（日志用）。定义在本模块，供全 Loader 的拒绝日志统一措辞。
const char* CategoryNameForLog(LoaderCore::PluginCategory cat);

}  // namespace PluginDomain
