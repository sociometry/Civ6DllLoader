#include "pch.h"
#include "PluginDomain.h"
#include "PluginTableAccess.h"

#include <Windows.h>

#include "ImageAddress.h"
#include "TeardownWindow.h"
#include "../common/Logger.h"

// 从 Civ6DLLHookLoaderAPI.cpp 拆出（阶段 2）。
//
// 本模块是全部子系统的公共下层，因此【不依赖】任何业务模块：
// 插件表查询经 PluginRegistry::ResolveOwnerByModule（只读门面），
// teardown 窗口经 LoaderCore::Teardown（共享头）。
//
// static 取舍：本文件只有 RangeInsideOneLoadedModule 保持 static（仅本 TU 调用）；
// 其余 9 个都有跨 TU 调用者，故去掉 static 并在 PluginDomain.h 声明。

namespace PluginDomain {

// 上者的"必须成功"版本：失败时按 apiName 记一行拒绝日志。
std::optional<CallerPluginInfo> RequirePluginOwner(const void* codeAddress,
                                                   const char* apiName) {
    auto owner = ResolvePluginOwnerForAddress(codeAddress);
    if (!owner || owner->ownerId.empty()) {
        Logger::Log("%s rejected: caller/callback is not an active plugin", apiName);
        return std::nullopt;
    }
    return owner;
}

bool TargetInCurrentGameCore(void* target) {
    const HookImageId image = ImageAddress::LoadedGameCore();
    return image != kHookImageInvalid && ImageAddress::Contains(image, target);
}

// GameCore 专属入口的运行期兜底门：编译期门禁（HookAPI.h 的宏重命名）之外的第二道门，
// 防的是不带 HookAPI.h、按结构体偏移直接调这些入口的插件。owner 缺失或不是 GameCore
// 类别一律拒绝，调用方按各自原失败值返回。
bool RequireGameCoreOwner(const void* codeAddress, const char* apiName) {
    const auto owner = ResolvePluginOwnerForAddress(codeAddress);
    if (!owner || owner->category != LoaderCore::PluginCategory::GameCore) {
        Logger::Log("%s rejected: GameCore-only API called by %s", apiName,
            owner ? CategoryNameForLog(owner->category) : "unknown");
        return false;
    }
    return true;
}

// Global 专属入口的运行期兜底门（与 RequireGameCoreOwner 对称）。
bool RequireGlobalOwner(const void* codeAddress, const char* apiName) {
    const auto owner = ResolvePluginOwnerForAddress(codeAddress);
    if (!owner || owner->category != LoaderCore::PluginCategory::Global) {
        Logger::Log("%s rejected: Global-only API called by %s", apiName,
            owner ? CategoryNameForLog(owner->category) : "unknown");
        return false;
    }
    return true;
}

// 目标整段是否落在【同一个已加载模块】的映像内。
// 不解析 PE：两端各自的所属模块句柄相同即证明整段同属一个模块映像；堆 / VirtualAlloc 的
// JIT 页 / 空闲地址拿不到模块句柄（或两端不同），直接判否。
static bool RangeInsideOneLoadedModule(const void* target, size_t len) {
    if (!target || len == 0) return false;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(target);
    const uintptr_t end = begin + len;
    if (end < begin) return false;   // 回绕：判否
    HMODULE firstModule = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(target), &firstModule) || !firstModule) {
        return false;
    }
    HMODULE lastModule = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(end - 1), &lastModule) || !lastModule) {
        return false;
    }
    return firstModule == lastModule;
}

// 单个目标地址：GameCore 类别要求落在【当前 GameCore 映像】内；Global 类别要求落在某个
// 已加载的非 GameCore 模块内（见上面的规则）。
bool IsTargetOpenToCaller(LoaderCore::PluginCategory caller, const void* target, const char* apiName) {
    const bool inGameCore = TargetInCurrentGameCore(const_cast<void*>(target));
    const bool ok = (caller == LoaderCore::PluginCategory::GameCore)
        ? inGameCore
        : (!inGameCore && RangeInsideOneLoadedModule(target, 1));
    if (!ok) {
        Logger::Log("%s rejected: target %p is not open to caller (%s)",
            apiName, target, CategoryNameForLog(caller));
    }
    return ok;
}

// 解析目标映像：GameCore 类别的 image 必须是 GameCore 系（kHookImageGameCoreBase/XP1/XP2）；
// Global 类别的 image 不得是 GameCore 系（exe / 其它常驻模块放行）。
// image 是否已加载不在这里判——交回 *Core（保持原失败路径与日志不变）。
bool IsImageOpenToCaller(LoaderCore::PluginCategory caller, HookImageId image, const char* apiName) {
    const bool gameCoreFamily = image == kHookImageGameCoreBase ||
        image == kHookImageGameCoreXP1 || image == kHookImageGameCoreXP2;
    const bool ok = (caller == LoaderCore::PluginCategory::GameCore) ? gameCoreFamily : !gameCoreFamily;
    if (!ok) {
        Logger::Log("%s rejected: image %u is not open to caller (%s)",
            apiName, static_cast<unsigned>(image), CategoryNameForLog(caller));
    }
    return ok;
}

// 整段范围（Patch 用）：GameCore 类别要求 [target, target+len) 全落在当前 GameCore 映像内；
// Global 类别要求整段与当前 GameCore 映像不相交【且】整段落在同一个已加载的非 GameCore
// 模块内（正面规则，见上面的说明）。
// 区间算术一律用无溢出的差值比较（len <= PluginBoundary::kMaxPluginRawBytes，地址为实址）。
bool IsRangeOpenToCaller(LoaderCore::PluginCategory caller, const void* target, size_t len, const char* apiName) {
    HookImageInfo gcInfo{ sizeof(HookImageInfo) };
    const HookImageId gcImage = ImageAddress::LoadedGameCore();
    const bool hasGameCore = gcImage != kHookImageInvalid &&
        ImageAddress::GetInfo(gcImage, &gcInfo) && gcInfo.imageSize != 0;
    const uintptr_t begin = reinterpret_cast<uintptr_t>(target);
    bool ok = false;
    if (caller == LoaderCore::PluginCategory::GameCore) {
        ok = hasGameCore && begin >= gcInfo.base && len <= gcInfo.imageSize &&
            (begin - gcInfo.base) <= gcInfo.imageSize - len;
    } else {
        const bool disjoint = !hasGameCore ||
            (begin >= gcInfo.base ? (begin - gcInfo.base) >= gcInfo.imageSize
                                  : (gcInfo.base - begin) >= len);
        ok = disjoint && RangeInsideOneLoadedModule(target, len);
    }
    if (!ok) {
        Logger::Log("%s rejected: range %p len=%zu is not open to caller (%s)",
            apiName, target, len, CategoryNameForLog(caller));
    }
    return ok;
}

bool TargetInTearingDownGameCore(void* target) {
    // 判据与窗口的读写序都在 TeardownWindow.h 里，保持单一来源。
    return LoaderCore::Teardown::IsTargetInWindow(target);
}

const char* CategoryNameForLog(LoaderCore::PluginCategory cat) {
    return cat == LoaderCore::PluginCategory::GameCore ? "GameCore" : "Global";
}

}  // namespace PluginDomain

// ResolvePluginOwnerForAddress 在 PluginDomain.h 里声明、在 PluginRegistry.cpp 里实现
// （阶段 2 时暂由母体实现，阶段 6 随插件表一起搬走）。这里只是把地址转成模块句柄。
std::optional<PluginDomain::CallerPluginInfo>
PluginDomain::ResolvePluginOwnerForAddress(const void* codeAddress) {
    if (!codeAddress) return std::nullopt;
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(codeAddress), &module)) {
        return std::nullopt;
    }
    return PluginRegistry::ResolveOwnerByModule(module);
}
