// Civ6DLLHookLoader.cpp
#include "pch.h"
#include "Civ6DLLHookLoaderAPI.h"
#include <Windows.h>
#include <filesystem>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <string>
#include <map>
#include <functional>
#include "Civ6MessageBus.h"
#include "MinHook.h"
#include "Runtime.h"
#include "../common/Logger.h"
#include "../common/ModScan.h"
#include "ProxyTypes.h"
#include "Localization.h"
#include "HavokScript.h"
#include "PdataMatch.h"
#include "ImageAddress.h"

#include <cstdarg>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <atomic>
#include <condition_variable>
#include <intrin.h>
#include <optional>
#include <unordered_set>

#include "PatchRegistry.h"
#include "LoaderCore.h"
#include <asmjit/x86.h>

using namespace std;

static Civ6MessageBus g_bus;

// v2 插件跟踪项：路径 + 句柄 + 名字(stem，作 Patch owner / OnMessage 注册名) + 类别(Global/GameCore)。
enum class PluginState {
    Loading,
    Active,
    Deactivating,
    Quarantined,
};

struct PluginEntry {
    HMODULE handle = nullptr;
    std::wstring path;
    std::wstring name;
    std::wstring ownerId;
    LoaderCore::PluginCategory category = LoaderCore::PluginCategory::Global;
    PluginState state = PluginState::Active;
};
static vector<PluginEntry> g_plugins;

// 插件生命周期互斥锁（递归：OnLoad/OnUnload 期间插件会再调用 HookAPI 注册入口，
// 需要重入）。保护 g_plugins、脚本全局注册表与 PushMethods 槽位的全部读写：
// 游戏线程（LoadDLL/UnloadDLL detour → Load/UnloadPluginsOf）与 Loader 工作线程
// （ReconcileGlobalPlugins）在此串行化。Runtime::MinHookMutex（MinHook 调用 + owner 表）与
// PatchRegistry 的 CRITICAL_SECTION 保持独立，锁序恒为 lifecycle → hook/patch。
static std::recursive_mutex g_pluginLifecycleMutex;

// 脚本全局 / GameEvent 的插件回调在快照锁外执行。按 owner 记录在途调用，
// 卸载先将插件切到 Deactivating/Quarantined，再等待计数归零，避免 OnUnload
// 释放插件状态后仍有旧快照进入插件代码。
struct PluginCallbackState {
    std::atomic<uint32_t> activeCalls{ 0 };
    std::mutex drainMutex;
    std::condition_variable drainCv;
};
static std::unordered_map<std::wstring, std::shared_ptr<PluginCallbackState>>
    g_pluginCallbackStates;

class PluginCallbackGuard {
public:
    PluginCallbackGuard() = default;
    explicit PluginCallbackGuard(std::shared_ptr<PluginCallbackState> state)
        : state_(std::move(state)) {}
    PluginCallbackGuard(const PluginCallbackGuard&) = delete;
    PluginCallbackGuard& operator=(const PluginCallbackGuard&) = delete;
    PluginCallbackGuard(PluginCallbackGuard&& other) noexcept
        : state_(std::move(other.state_)) {}
    PluginCallbackGuard& operator=(PluginCallbackGuard&& other) noexcept {
        if (this != &other) {
            Release();
            state_ = std::move(other.state_);
        }
        return *this;
    }
    ~PluginCallbackGuard() { Release(); }

    explicit operator bool() const { return state_ != nullptr; }

private:
    void Release() {
        if (!state_) return;
        if (state_->activeCalls.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            lock_guard<mutex> lock(state_->drainMutex);
            state_->drainCv.notify_all();
        }
        state_.reset();
    }

    std::shared_ptr<PluginCallbackState> state_;
};

static PluginCallbackGuard TryEnterPluginCallback(const std::wstring& owner) {
    if (owner.empty()) return {};
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&owner](const PluginEntry& entry) {
            return entry.ownerId == owner &&
                (entry.state == PluginState::Loading ||
                 entry.state == PluginState::Active);
        });
    if (plugin == g_plugins.end()) return {};

    auto& state = g_pluginCallbackStates[owner];
    if (!state) state = std::make_shared<PluginCallbackState>();
    state->activeCalls.fetch_add(1, std::memory_order_acq_rel);
    // 表项必须继续持有计数状态；守卫只复制 shared_ptr，不能把表项移空。
    return PluginCallbackGuard(state);
}

static void WaitForPluginCallbacks(const std::wstring& owner) {
    if (owner.empty()) return;
    std::shared_ptr<PluginCallbackState> state;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        const auto it = g_pluginCallbackStates.find(owner);
        if (it == g_pluginCallbackStates.end()) return;
        state = it->second;
    }
    unique_lock<mutex> drainLock(state->drainMutex);
    state->drainCv.wait(drainLock, [&state] {
        return state->activeCalls.load(std::memory_order_acquire) == 0;
    });
}

// OnLoad/OnUnload 的快速 owner 上下文。异步调用不依赖它，而由回调/调用方地址反查
// 所属插件模块，避免错误归为 Loader 导致插件停用后钩子仍生效。
static thread_local std::wstring g_activePluginOwner;
static thread_local HMODULE g_activePluginModule;

static void SetActivePluginContext(const std::wstring& owner, HMODULE module) {
    g_activePluginOwner = owner;
    g_activePluginModule = module;
}

static void ClearActivePluginContext() {
    g_activePluginOwner.clear();
    g_activePluginModule = nullptr;
}

enum class HookKind {
    Plugin,
    SharedScript,
    PushMethods,
};

struct HookRecord {
    std::wstring owner;  // 空 = Loader 共享钩
    HookKind kind = HookKind::Plugin;
    uint64_t gameCoreGeneration = 0;
};

static std::unordered_map<void*, HookRecord> g_hookRecords;

// 阶段 B 是否已完成（InitializeGameCorePhase 成功置 true；ResetForReload 复位）。
static bool g_gameCorePhaseReady = false;

// 规范化路径比较：小写 + '/'→'\\'（候选均为绝对路径，词法规范化即可）。
static std::wstring NormalizePluginPath(const std::wstring& path) {
    std::wstring norm = path;
    for (wchar_t& ch : norm) {
        if (ch == L'/') {
            ch = L'\\';
        } else {
            ch = std::towlower(ch);
        }
    }
    return norm;
}

// 按路径含 \Plugins\Global\（大小写不敏感）判类别；其余视为 GameCore。
static LoaderCore::PluginCategory CategoryForPath(const std::wstring& path) {
    return NormalizePluginPath(path).find(L"\\plugins\\global\\") != std::wstring::npos
        ? LoaderCore::PluginCategory::Global
        : LoaderCore::PluginCategory::GameCore;
}

static uintptr_t g_gameCoreTeardownAddress;
static uint32_t g_gameCoreTeardownSizeOfImage;

struct PushTargetConfig {
    PushMethodSigType signature = PushMethodSigType::NoManager;
    std::string symbolName;
};

// Loader 内置目标只读；插件自定义目标保存在自己的 owner 命名空间，
// 防止一个插件覆盖另一个插件的签名或符号。
static const unordered_map<string, PushTargetConfig> g_defaultPushTargetConfigs = {
    {"GameCore::Cache::Lua::IQuestsManager",
        { PushMethodSigType::WithManager, "GameCore::Cache::Lua::IQuestsManager::PushMethods" }},
    {"GameCore::Lua::IQuestsManager",
        { PushMethodSigType::NoManager, "GameCore::Lua::IQuestsManager::PushMethods" }},
};
static unordered_map<std::wstring, unordered_map<string, PushTargetConfig>>
    g_pluginPushTargetConfigs;

struct PushRegistration {
    std::string targetName;
    PushMethodSigType signature = PushMethodSigType::NoManager;
    std::vector<StoredLuaMethod> methods;
    std::wstring owner;
    std::string symbolName;
};
static std::vector<PushRegistration> g_pushRegistrations;

// Symbol RVAs live in Civ6DllLoader.symdb.bin (see PdataMatch.cpp).

static mutex g_scriptStateMutex;
static mutex g_pushStateMutex;
static atomic<uint32_t> g_activeSharedDetours{ 0 };
static mutex g_detourDrainMutex;
static condition_variable g_detourDrainCv;

class SharedDetourActivity {
public:
    SharedDetourActivity() {
        g_activeSharedDetours.fetch_add(1, std::memory_order_acq_rel);
    }
    ~SharedDetourActivity() {
        if (g_activeSharedDetours.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            lock_guard<mutex> lock(g_detourDrainMutex);
            g_detourDrainCv.notify_all();
        }
    }
};

namespace fs = std::filesystem;

static std::optional<std::wstring> ResolvePluginOwnerForAddress(const void* codeAddress) {
    if (!codeAddress) return std::nullopt;

    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(codeAddress), &module)) {
        return std::nullopt;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    for (const auto& entry : g_plugins) {
        if (entry.handle != module) continue;
        if (!g_activePluginOwner.empty() && module == g_activePluginModule &&
                entry.ownerId == g_activePluginOwner &&
                entry.state != PluginState::Quarantined) {
            return entry.ownerId;
        }
        if ((entry.state == PluginState::Loading ||
                entry.state == PluginState::Active) &&
                entry.handle == module) {
            return entry.ownerId;
        }
    }
    return std::nullopt;
}

static std::optional<std::wstring> RequirePluginOwner(const void* codeAddress,
                                                       const char* apiName) {
    auto owner = ResolvePluginOwnerForAddress(codeAddress);
    if (!owner || owner->empty()) {
        Logger::Log("%s rejected: caller/callback is not an active plugin", apiName);
        return std::nullopt;
    }
    return owner;
}

static bool TargetInCurrentGameCore(void* target) {
    const HookImageId image = ImageAddress::LoadedGameCore();
    return image != kHookImageInvalid && ImageAddress::Contains(image, target);
}

static bool TargetInTearingDownGameCore(void* target) {
    const uintptr_t p = reinterpret_cast<uintptr_t>(target);
    return g_gameCoreTeardownAddress && p >= g_gameCoreTeardownAddress &&
        p - g_gameCoreTeardownAddress < g_gameCoreTeardownSizeOfImage;
}

static bool HasGameCoreTeardownCallback(const std::wstring& owner);

// ---------------- HookAPI ??? ----------------
static bool SafeRemoveHookLocked(void* target, bool eraseRecord);
// 调用方必须持有 Runtime::MinHookMutex()。
static MH_STATUS InstallHookOwnedByLocked(void* target, void* detour, void** original,
                                          const wchar_t* owner, HookKind kind) {
    MH_STATUS status = MH_CreateHook(target, detour, original);
    const auto existing = g_hookRecords.find(target);
    const bool recoverStalePlugin =
        status == MH_ERROR_ALREADY_CREATED &&
        kind == HookKind::Plugin &&
        existing != g_hookRecords.end() &&
        existing->second.kind == HookKind::Plugin &&
        existing->second.owner == (owner ? owner : L"") &&
        existing->second.gameCoreGeneration != 0 &&
        existing->second.gameCoreGeneration < ImageAddress::GameCoreGeneration() &&
        TargetInCurrentGameCore(target);
    if (recoverStalePlugin && SafeRemoveHookLocked(target, false)) {
        status = MH_CreateHook(target, detour, original);
    }
    if (status != MH_OK) {
        Logger::Log("InstallHook: create failed %s", MH_StatusToString(status));
        return status;
    }

    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallHook: enable failed %s", MH_StatusToString(status));
        // 回滚残留的 MinHook 记录：否则该 target 永远 ALREADY_CREATED，再无重试机会。
        MH_RemoveHook(target);
        return status;
    }

    g_hookRecords[target] = HookRecord{
        owner ? owner : L"",
        kind,
        TargetInCurrentGameCore(target) ? ImageAddress::GameCoreGeneration() : 0,
    };
    return MH_OK;
}

static bool InstallHookOwnedBy(void* target, void* detour, void** original,
                               const wchar_t* owner, HookKind kind = HookKind::Plugin) {
    lock_guard<mutex> lock(Runtime::MinHookMutex());
    return InstallHookOwnedByLocked(target, detour, original, owner, kind) == MH_OK;
}

bool InstallHookImpl(void* target, void* detour, void** original) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    if (TargetInTearingDownGameCore(target)) {
        Logger::Log("InstallHook rejected: target %p belongs to tearing-down GameCore", target);
        return false;
    }
    auto owner = RequirePluginOwner(detour, "InstallHook");
    if (owner && TargetInCurrentGameCore(target)) {
        const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
            [&owner](const PluginEntry& entry) {
                return entry.ownerId == *owner;
            });
        if (plugin != g_plugins.end() &&
                plugin->category == LoaderCore::PluginCategory::Global &&
                !HasGameCoreTeardownCallback(*owner)) {
            Logger::Log("InstallHook rejected: Global owner %ls must register GameCoreTeardown first",
                owner->c_str());
            return false;
        }
    }
    return owner && InstallHookOwnedBy(target, detour, original, owner->c_str());
}

// 摘除单个 MinHook 钩子；目标内存不可读（GameCore 映像已卸载，重载兜底路径会出现）
// 时跳过 RemoveHook——对未映射地址恢复原字节会失败甚至出错。残留的 MinHook 记录
// 由 InstallSharedHook 的 ALREADY_CREATED 恢复路径在新映像 attach 后清理复用。
// 调用方必须持有 Runtime::MinHookMutex()。
static bool SafeRemoveHookLocked(void* target, bool eraseRecord = true) {
    if (!target) return false;
    if (!Runtime::IsReadableSpan(target, 1)) {
        Logger::Log("SafeRemoveHook: target %p unreadable (module unmapped); skip MinHook removal", target);
        return false;
    }
    MH_DisableHook(target);
    const MH_STATUS st = MH_RemoveHook(target);
    if (st != MH_OK) {
        Logger::Log("SafeRemoveHook: MH_RemoveHook(%p) -> %s", target, MH_StatusToString(st));
        return false;
    }
    if (eraseRecord) g_hookRecords.erase(target);
    return true;
}

void BroadcastMessageImpl(const char* topic, const void* data, size_t len) {
    g_bus.Broadcast(topic, data, len);
}

// 显式注册与 OnMessage 自动注册共用：消息地址只能来自 Loader 跟踪的插件名。
// 调用时不得持 lifecycle 锁；替换旧回调可能等待正在使用 HookAPI 的其它线程。
static bool RegisterPluginMessageHandler(const std::wstring& owner, MessageHandlerFn handler) {
    if (!handler) return false;
    std::string handlerName;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
            [&owner](const PluginEntry& entry) { return entry.ownerId == owner; });
        if (plugin == g_plugins.end() ||
            (plugin->state != PluginState::Loading && plugin->state != PluginState::Active)) {
            Logger::Log("RegisterMessageHandler rejected: plugin is not loading/active");
            return false;
        }
        const auto callbackOwner = ResolvePluginOwnerForAddress(reinterpret_cast<const void*>(handler));
        if (!callbackOwner || *callbackOwner != owner) {
            Logger::Log("RegisterMessageHandler rejected: callback does not belong to plugin");
            return false;
        }
        handlerName = ModScan::WideToNarrow(plugin->name);
        if (handlerName.empty() || handlerName == "Loader") {
            Logger::Log("RegisterMessageHandler rejected: empty or reserved plugin name");
            return false;
        }
    }
    // 总线锁 -> lifecycle 锁。若停用先发生则拒绝；若发布先发生，随后的
    // UnregisterOwner 必然能清除此登记，避免校验后停用又把 handler 注册回来。
    return g_bus.RegisterHandler(handlerName, handler, owner, [&owner] {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        const bool active = std::any_of(g_plugins.begin(), g_plugins.end(),
            [&owner](const PluginEntry& entry) {
                return entry.ownerId == owner &&
                    (entry.state == PluginState::Loading || entry.state == PluginState::Active);
            });
        if (!active) Logger::Log("RegisterMessageHandler rejected: plugin stopped before registration");
        return active;
    });
}

bool RegisterMessageHandlerImpl(MessageHandlerFn handler) {
    if (!handler) return false;
    // 与其它回调 API 一样按 handler 所属模块确定 owner；返回地址会因尾调用
    // 优化落在 Loader/引擎内，不能用来可靠识别插件。
    const auto owner = RequirePluginOwner(reinterpret_cast<const void*>(handler),
        "RegisterMessageHandler");
    return owner && RegisterPluginMessageHandler(*owner, handler);
}

void SendMessageToImpl(const char* pluginName, const char* topic, const void* data, size_t len) {
    g_bus.SendTo(pluginName, topic, data, len);
}

bool IsImageLoadedImpl(HookImageId image) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    return ImageAddress::IsLoaded(image);
}

bool GetImageInfoImpl(HookImageId image, HookImageInfo* outInfo) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    return ImageAddress::GetInfo(image, outInfo);
}

// 按段名（.text/.idata/.rdata/.data；PE 段名为 8 字节非 NUL 终止数组）定位镜像内段的
// RVA 与大小（大小 = max(SizeOfRawData, VirtualSize)）。找不到段返回 false。
static bool ResolveSectionRva(HookImageId image, const char* sectionName,
    uintptr_t* outRva, size_t* outSize) {
    if (!sectionName || !outRva || !outSize) return false;
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(image, &info) || info.base == 0) return false;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(info.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(info.base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    // 段名比较：name 以 NUL 结束，逐字节对比至多 8 字节；name 提前结束即匹配成功
    // （PE 惯例段名 NUL/空格填充；name 更长时须 8 字节精确相等）。
    auto nameMatches = [](const IMAGE_SECTION_HEADER& sh, const char* name) -> bool {
        for (int i = 0; i < 8; ++i) {
            if (sh.Name[i] != static_cast<unsigned char>(name[i])) return false;
            if (name[i] == '\0') return true;
        }
        return true;
    };

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!nameMatches(*sec, sectionName)) continue;
        const size_t size = sec->Misc.VirtualSize > sec->SizeOfRawData
            ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        *outRva = sec->VirtualAddress;
        *outSize = size;
        return true;
    }
    return false;
}

void* ResolveByRvaImpl(HookImageId image, uintptr_t rva, size_t span) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    uintptr_t effectiveRva = rva;
    if (PdataMatch::HasContext(image)) {
        // 有该模块的 sidecar 上下文：插件传入的是旧映像坐标，先矫正到当前映像。
        // 版本一致时 CorrectRva 为恒等映射。
        const uintptr_t corrected = PdataMatch::CorrectRva(image, rva);
        if (corrected == 0) {
            Logger::Log("ResolveByRva: no pdata correction image=%u rva=0x%llX span=%zu",
                static_cast<unsigned>(image), static_cast<unsigned long long>(rva), span);
            return nullptr;
        }
        effectiveRva = corrected;
    }
    void* result = ImageAddress::ResolveByRva(image, effectiveRva, span);
    if (!result && ImageAddress::IsLoaded(image)) {
        Logger::Log("ResolveByRva: rejected image=%u rva=0x%llX span=%zu",
            static_cast<unsigned>(image),
            static_cast<unsigned long long>(effectiveRva), span);
    }
    return result;
}

void* ResolveByNameImpl(HookImageId image, const char* name) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (!name || !*name || !ImageAddress::IsLoaded(image)) return nullptr;

    // 每个模块有各自 sidecar 上下文（容器：exe/GameCore 各自符号表）。
    if (!PdataMatch::HasContext(image)) {
        Logger::Log("ResolveByName: no symbol database for image=%u name=%s",
            static_cast<unsigned>(image), name);
        return nullptr;
    }

    // PdataMatch：sidecar 符号表存旧映像 RVA，按名矫正到当前映像后解析。
    const uintptr_t corrected = PdataMatch::CorrectByName(image, name);
    if (corrected == 0) {
        Logger::Log("ResolveByName: no symbol for image=%u name=%s",
            static_cast<unsigned>(image), name);
        return nullptr;
    }
    void* result = ImageAddress::ResolveByRva(image, corrected, 1);
    if (!result) {
        Logger::Log("ResolveByName: out-of-range RVA image=%u name=%s rva=0x%llX",
            static_cast<unsigned>(image), name,
            static_cast<unsigned long long>(corrected));
    }
    return result;
}

void* ResolveByRvaExImpl(HookImageId image, uintptr_t rva, size_t span, HookImageSection section) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (section == kSectionImage) {
        // 不修正：镜像相对 RVA 直接解析（供已按新映像坐标算好的调用方使用）。
        return ImageAddress::ResolveByRva(image, rva, span);
    }
    const char* sectionName = nullptr;
    switch (section) {
        case kSectionText:  sectionName = ".text";  break;
        case kSectionIdata: sectionName = ".idata"; break;
        case kSectionRdata: sectionName = ".rdata"; break;
        case kSectionData:  sectionName = ".data";  break;
        default: break;
    }
    if (!sectionName) {
        Logger::Log("ResolveByRvaEx: unknown section=%d image=%u rva=0x%llX span=%zu",
            static_cast<int>(section), static_cast<unsigned>(image),
            static_cast<unsigned long long>(rva), span);
        return nullptr;
    }
    uintptr_t sectionRva = 0;
    size_t sectionSize = 0;
    if (!ResolveSectionRva(image, sectionName, &sectionRva, &sectionSize)) {
        Logger::Log("ResolveByRvaEx: section %s not found image=%u",
            sectionName, static_cast<unsigned>(image));
        return nullptr;
    }
    return ImageAddress::ResolveByRva(image, sectionRva + rva, span);
}

void* ResolveByPatternImpl(HookImageId image, const char* pattern, HookImageSection section) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (!pattern || !*pattern) {
        Logger::Log("ResolveByPattern: empty pattern");
        return nullptr;
    }
    // 解析 AOB："48 8B ?? ?? 74 ?? E8"（?? 整字节通配，也支持单 nibble 如 4?）。
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> masks;
    const char* p = pattern;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == ',') ++p;
        if (!*p) break;
        uint8_t byte = 0, mask = 0;
        for (int nib = 0; nib < 2; ++nib) {
            // '?' 也占一个半字节；必须同样移位，否则 4? 会被解析成 ?4。
            byte = static_cast<uint8_t>(byte << 4);
            mask = static_cast<uint8_t>(mask << 4);
            const char c = *p;
            if (c == '?') {
                ++p;
            } else if (c >= '0' && c <= '9') {
                byte = static_cast<uint8_t>(byte | (c - '0'));
                mask = static_cast<uint8_t>(mask | 0xF);
                ++p;
            } else if (c >= 'a' && c <= 'f') {
                byte = static_cast<uint8_t>(byte | (c - 'a' + 10));
                mask = static_cast<uint8_t>(mask | 0xF);
                ++p;
            } else if (c >= 'A' && c <= 'F') {
                byte = static_cast<uint8_t>(byte | (c - 'A' + 10));
                mask = static_cast<uint8_t>(mask | 0xF);
                ++p;
            } else {
                Logger::Log("ResolveByPattern: invalid char '%c' in pattern \"%s\"", c, pattern);
                return nullptr;
            }
        }
        bytes.push_back(byte);
        masks.push_back(mask);
    }
    if (bytes.empty()) {
        Logger::Log("ResolveByPattern: empty pattern \"%s\"", pattern);
        return nullptr;
    }

    // 定位搜索范围（kSectionImage = 整个镜像；否则按段定位）。
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(image, &info) || info.base == 0) {
        Logger::Log("ResolveByPattern: image not loaded image=%u",
            static_cast<unsigned>(image));
        return nullptr;
    }
    uintptr_t searchBase = info.base;
    size_t searchSize = info.imageSize;
    if (section != kSectionImage) {
        const char* sectionName = nullptr;
        switch (section) {
            case kSectionText:  sectionName = ".text";  break;
            case kSectionIdata: sectionName = ".idata"; break;
            case kSectionRdata: sectionName = ".rdata"; break;
            case kSectionData:  sectionName = ".data";  break;
            default: break;
        }
        if (!sectionName) {
            Logger::Log("ResolveByPattern: unknown section=%d image=%u",
                static_cast<int>(section), static_cast<unsigned>(image));
            return nullptr;
        }
        uintptr_t sectionRva = 0;
        size_t sectionSize = 0;
        if (!ResolveSectionRva(image, sectionName, &sectionRva, &sectionSize)) {
            Logger::Log("ResolveByPattern: section %s not found image=%u",
                sectionName, static_cast<unsigned>(image));
            return nullptr;
        }
        const size_t avail = sectionRva < info.imageSize ? info.imageSize - sectionRva : 0;
        if (sectionSize > avail) sectionSize = avail;  // 防御：不越出映像映射
        searchBase = info.base + sectionRva;
        searchSize = sectionSize;
    }
    if (searchSize < bytes.size()) {
        Logger::Log("ResolveByPattern: pattern longer than region image=%u section=%d len=%zu",
            static_cast<unsigned>(image), static_cast<int>(section), bytes.size());
        return nullptr;
    }

    // 线性首命中搜索（mask 0 位 = 通配）。
    const uint8_t* basePtr = reinterpret_cast<const uint8_t*>(searchBase);
    const size_t limit = searchSize - bytes.size() + 1;
    for (size_t i = 0; i < limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if ((basePtr[i + j] & masks[j]) != bytes[j]) { match = false; break; }
        }
        if (match) {
            Logger::Log("ResolveByPattern: hit image=%u section=%d rva=0x%llX",
                static_cast<unsigned>(image), static_cast<int>(section),
                static_cast<unsigned long long>(i));
            return const_cast<uint8_t*>(basePtr + i);
        }
    }
    Logger::Log("ResolveByPattern: no hit image=%u section=%d pattern=\"%s\"",
        static_cast<unsigned>(image), static_cast<int>(section), pattern);
    return nullptr;
}

// ---------------- RegisterGlobalCapture（全局参数捕获站） ----------------
// 每个 providerFunction（经 pdata 矫正后的目标地址）对应一个捕获站点：首个注册者
// 生成裸机码 stub 并 MinHook 挂到目标函数入口；后续同一站点的注册只追加 out 槽。
// 目标函数每次被调用时，stub 把第 paramIndex 个整数参数（rcx/rdx/r8/r9 之一）写入
// 该站点注册的全部 out 槽。
struct CaptureSite {
    struct Out {
        void** address = nullptr;
        std::wstring ownerId;
    };

    void* original = nullptr;    // MH_CreateHook 产出的 trampoline（stub 尾跳目标）
    void* stubCode = nullptr;    // JitRuntime 分配的 stub 入口
    uint32_t paramIndex = 0;
    std::vector<Out> outs;
    std::atomic<uint32_t> activeCalls{ 0 };
    bool retiring = false;       // g_captureMutex 保护；阻止新 out 注册和捕获写入
};
static std::map<uintptr_t, CaptureSite> g_captureSites;
static std::mutex g_captureMutex;
static std::mutex g_captureRetireMutex; // 串行化各 owner / 整代清理，避免重复释放同一站点
static std::mutex g_captureDrainMutex;
static std::condition_variable g_captureDrainCv;
static asmjit::JitRuntime g_captureRuntime;
static bool RemoveCaptureHook(uintptr_t target);

extern "C" void CaptureEnter(CaptureSite* site) {
    if (site) site->activeCalls.fetch_add(1, std::memory_order_acq_rel);
}

extern "C" void CaptureLeave(CaptureSite* site) {
    if (!site) return;
    if (site->activeCalls.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        std::lock_guard<std::mutex> lock(g_captureDrainMutex);
        g_captureDrainCv.notify_all();
    }
}

// stub 调用的分发器：regs 指向 stub 栈帧里保存的 4 个整数参数槽（rcx/rdx/r8/r9），
// 取第 paramIndex 个值写入站点全部 out 槽。与注册路径共用 g_captureMutex。
extern "C" void CaptureDispatch(void* regs, uint32_t paramIndex, void* sitePtr) {
    CaptureSite* site = static_cast<CaptureSite*>(sitePtr);
    if (!site || !regs || paramIndex > 3) return;
    const void* val = static_cast<void* const*>(regs)[paramIndex];
    std::lock_guard<std::mutex> lock(g_captureMutex);
    if (site->retiring) return;
    for (const CaptureSite::Out& out : site->outs) {
        if (out.address) *out.address = const_cast<void*>(val);
    }
}

// 生成捕获站点 stub（裸 x64 机器码，Windows x64 调用约定）：
//   MinHook 跳入时：rcx/rdx/r8/r9 = 前 4 个整数参数，xmm0-3 = 前 4 个浮点参数，
//   [rsp] = 返回地址（此时 rsp ≡ 8 (mod 16)）。sub rsp, 0x98 后 rsp ≡ 0 (mod 16)：
//   [rsp+0x00..0x20) 恰好充当 CaptureEnter/CaptureDispatch/CaptureLeave 的 shadow space，
//   [rsp+0x20..0x80) 保存参数（movaps 目标全部 16 字节对齐）。
// original 回填方案（免写可执行内存、免扫描/免 reloc）：stub 尾部
//   mov rax, imm64(&site->original)  —— 生成时固化的 C++ 站点成员地址
//                                      （std::map 节点地址稳定，绝对寻址）
//   mov rax, [rax]                   —— 运行时读 trampoline 指针
//   jmp rax                          —— 尾跳 MinHook trampoline
// MH_CreateHook 在 MH_EnableHook 之前把 trampoline 写入 site->original，因此 stub
// 首次可执行时该值必已就绪，无需生成后回填任何 stub 字节。
static bool BuildCaptureStub(CaptureSite* site, void** outStub) {
    using namespace asmjit;
    CodeHolder code;
    if (code.init(g_captureRuntime.environment(), g_captureRuntime.cpu_features()) != Error::kOk) {
        return false;
    }
    x86::Assembler a(&code);
    a.sub(x86::rsp, 0x98);
    a.mov(x86::ptr(x86::rsp, 0x20), x86::rcx);
    a.mov(x86::ptr(x86::rsp, 0x28), x86::rdx);
    a.mov(x86::ptr(x86::rsp, 0x30), x86::r8);
    a.mov(x86::ptr(x86::rsp, 0x38), x86::r9);
    a.movaps(x86::ptr(x86::rsp, 0x40), x86::xmm0);
    a.movaps(x86::ptr(x86::rsp, 0x50), x86::xmm1);
    a.movaps(x86::ptr(x86::rsp, 0x60), x86::xmm2);
    a.movaps(x86::ptr(x86::rsp, 0x70), x86::xmm3);
    a.mov(x86::rcx, reinterpret_cast<uintptr_t>(site));
    a.mov(x86::r10, reinterpret_cast<uintptr_t>(&CaptureEnter));
    a.call(x86::r10);
    a.lea(x86::rcx, x86::ptr(x86::rsp, 0x20));
    a.mov(x86::edx, static_cast<uint32_t>(site->paramIndex));
    a.mov(x86::r8, reinterpret_cast<uintptr_t>(site));
    a.mov(x86::r10, reinterpret_cast<uintptr_t>(&CaptureDispatch));
    a.call(x86::r10);
    a.mov(x86::rcx, reinterpret_cast<uintptr_t>(site));
    a.mov(x86::r10, reinterpret_cast<uintptr_t>(&CaptureLeave));
    a.call(x86::r10);
    a.mov(x86::rcx, x86::ptr(x86::rsp, 0x20));
    a.mov(x86::rdx, x86::ptr(x86::rsp, 0x28));
    a.mov(x86::r8, x86::ptr(x86::rsp, 0x30));
    a.mov(x86::r9, x86::ptr(x86::rsp, 0x38));
    a.movaps(x86::xmm0, x86::ptr(x86::rsp, 0x40));
    a.movaps(x86::xmm1, x86::ptr(x86::rsp, 0x50));
    a.movaps(x86::xmm2, x86::ptr(x86::rsp, 0x60));
    a.movaps(x86::xmm3, x86::ptr(x86::rsp, 0x70));
    a.add(x86::rsp, 0x98);
    a.mov(x86::rax, reinterpret_cast<uintptr_t>(&site->original));
    a.mov(x86::rax, x86::ptr(x86::rax));
    a.jmp(x86::rax);

    void* stub = nullptr;
    if (g_captureRuntime.add(&stub, &code) != Error::kOk || !stub) {
        return false;
    }
    *outStub = stub;
    return true;
}

// RegisterGlobalCapture 内部核心（无插件 owner 校验）：从插件入口提取的公共核心，
// 供 RegisterGlobalCaptureImpl 复用。ownerId 空串 = Loader 归属（GameCore 重载
// 时随 CleanupAllCaptureSites 整站清理；插件卸载清理按 owner 匹配，跳过空串）。
static bool RegisterGlobalCaptureCore(HookImageId image, const char* providerFunction,
                                      uint32_t paramIndex, void** out,
                                      const std::wstring& ownerId) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (image != kHookImageGameCoreXP2 || !providerFunction || !*providerFunction ||
            paramIndex > 3 || !out) {
        Logger::Log("RegisterGlobalCapture rejected: bad args image=%u provider=%s param=%u",
            static_cast<unsigned>(image),
            providerFunction ? providerFunction : "(null)",
            static_cast<unsigned>(paramIndex));
        return false;
    }

    // CorrectByName 返回旧→新矫正后的 RVA（非地址），须经 ResolveByRva 换算为当前映像地址。
    const uintptr_t corrected = PdataMatch::CorrectByName(kHookImageGameCoreXP2, providerFunction);
    void* target = corrected ? ImageAddress::ResolveByRva(kHookImageGameCoreXP2, corrected, 1) : nullptr;
    if (!target) {
        Logger::Log("RegisterGlobalCapture: no pdata correction for provider=%s", providerFunction);
        return false;
    }
    if (TargetInTearingDownGameCore(target)) {
        Logger::Log("RegisterGlobalCapture: target belongs to tearing-down GameCore provider=%s",
            providerFunction);
        return false;
    }

    lock_guard<std::mutex> captureLock(g_captureMutex);
    CaptureSite& site = g_captureSites[reinterpret_cast<uintptr_t>(target)];
    if (site.stubCode) {
        if (site.retiring) {
            Logger::Log("RegisterGlobalCapture: target is being retired provider=%s", providerFunction);
            return false;
        }
        // 已存在站点：paramIndex 必须一致，仅追加 out 槽。
        if (site.paramIndex != paramIndex) {
            Logger::Log("RegisterGlobalCapture: paramIndex conflict provider=%s have=%u want=%u",
                providerFunction, static_cast<unsigned>(site.paramIndex),
                static_cast<unsigned>(paramIndex));
            return false;
        }
        site.outs.push_back({ out, ownerId });
        return true;
    }

    // 在生成/启用 hook 前准备订阅，避免启用成功后再分配 vector/string 时失败。
    // capture 锁保护整个安装过程，Dispatch 只会在安装成功并解锁后写入。
    site.paramIndex = paramIndex;
    site.outs.push_back({ out, ownerId });
    if (!BuildCaptureStub(&site, &site.stubCode)) {
        Logger::Log("RegisterGlobalCapture: stub build failed provider=%s", providerFunction);
        g_captureSites.erase(reinterpret_cast<uintptr_t>(target));
        return false;
    }
    MH_STATUS status;
    bool hookCreated = false;
    {
        lock_guard<std::mutex> mhLock(Runtime::MinHookMutex());
        status = MH_CreateHook(target, site.stubCode, &site.original);
        if (status == MH_OK) {
            hookCreated = true;
            status = MH_EnableHook(target);
        }
    }
    bool hookRemoved = true;
    if (status != MH_OK && hookCreated) {
        // Enable 失败后 MinHook 仍可能保留 CreateHook 记录；先完整摘除，
        // 否则重试会撞 ALREADY_CREATED，且 target 可能继续引用 stub。
        hookRemoved = RemoveCaptureHook(reinterpret_cast<uintptr_t>(target));
    }
    if (status != MH_OK) {
        Logger::Log("RegisterGlobalCapture: hook failed %s provider=%s",
            MH_StatusToString(status), providerFunction);
        void* failedStub = site.stubCode;
        if (hookRemoved) {
            g_captureSites.erase(reinterpret_cast<uintptr_t>(target));
            if (failedStub) g_captureRuntime.release(failedStub);
        } else {
            // 无法确认 target 已经脱离 stub 时宁可保留整站和代码，避免 UAF；
            // 标记 retiring，后续注册拒绝，重载清理会再次尝试摘钩。
            site.retiring = true;
            site.outs.clear(); // 注册已返回失败，不能再保留调用者的输出地址
            Logger::Log("RegisterGlobalCapture: rollback remove failed; site retained target=%p",
                target);
        }
        return false;
    }
    Logger::Log("RegisterGlobalCapture: installed provider=%s target=%p param=%u owner=%ls",
        providerFunction, target, static_cast<unsigned>(paramIndex), ownerId.c_str());
    return true;
}

// 插件入口：owner 校验后走核心（out 槽须位于插件模块内）。
bool RegisterGlobalCaptureImpl(HookImageId image, const char* providerFunction, uint32_t paramIndex, void** out) {
    // owner 查询与注册必须在同一生命周期锁内，防止查询后插件先被停用并完成清理。
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(out), "RegisterGlobalCapture");
    if (!owner) return false;
    return RegisterGlobalCaptureCore(image, providerFunction, paramIndex, out, *owner);
}

// 读 [vtable + index*8] 的槽函数指针。本函数无 C++ 对象（无展开要求），可用 SEH 兜底。
static void* ReadVTableSlotSafe(void* vtable, uint32_t index) {
    void* slotFunc = nullptr;
    __try {
        slotFunc = *reinterpret_cast<void**>(
            reinterpret_cast<uintptr_t>(vtable) + static_cast<uintptr_t>(index) * 8);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    return slotFunc;
}

// ---------------- ResolveByVTable（按 vtable 符号 + 槽序号解析虚函数） ----------------
void* ResolveByVTableImpl(HookImageId image, const char* vtableSymbol, uint32_t index) {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (!vtableSymbol || !*vtableSymbol) {
        Logger::Log("ResolveByVTable rejected: empty vtable symbol");
        return nullptr;
    }
    uint32_t vtableRva = 0;
    uint32_t slotCount = 0;
    if (!PdataMatch::CorrectVTableByName(image, vtableSymbol, vtableRva, slotCount)) {
        Logger::Log("ResolveByVTable: no vtable for symbol=%s (not found / not vtable / not corrected)",
            vtableSymbol);
        return nullptr;
    }
    if (index >= slotCount) {
        Logger::Log("ResolveByVTable: index %u out of range for vtable=%s (slotCount=%u)",
            static_cast<unsigned>(index), vtableSymbol, static_cast<unsigned>(slotCount));
        return nullptr;
    }
    void* vtable = ImageAddress::ResolveByRva(image, vtableRva, 1);
    if (!vtable) {
        Logger::Log("ResolveByVTable: vtable address resolve failed symbol=%s rva=0x%X",
            vtableSymbol, static_cast<unsigned>(vtableRva));
        return nullptr;
    }
    // 读 [vtable + index*8] 的槽函数指针（SEH 兜底防坏地址）
    void* slotFunc = ReadVTableSlotSafe(vtable, index);
    if (!slotFunc) {
        Logger::Log("ResolveByVTable: slot read fault vtable=%s index=%u",
            vtableSymbol, static_cast<unsigned>(index));
    }
    return slotFunc;
}

// ---------------- capture 站点生命周期清理 ----------------
// 两个失效场景：
//  1) GameCore 重载：providerFunction 位于旧 GameCore 映像内，重载后地址失效，必须
//     随重载清掉全部站点（ResetForReload 调用 CleanupAllCaptureSites），等下次
//     Ready 回调由插件重新注册；
//  2) 插件卸载：站点 out 槽指向插件内存，卸载后悬空（UnloadPluginByOwnerId 调用
//     CleanupCaptureSitesForOwner）。
// 锁序约定：g_captureMutex 只保护站点表与 out 槽（CaptureDispatch 也持它写槽）；
// 注册按 lifecycle→capture→mh 加锁，失败回滚沿用同一顺序。
// 清理由 g_captureRetireMutex 串行化：capture 锁内移除订阅并收集快照，
// 释放 capture 锁后才摘钩和等待在途调用，避免与 CaptureDispatch 互等。
// 摘钩后等待所有已进入 stub 的调用离开，再释放 stub 和站点对象，避免执行中的
// stub 访问已释放的 JIT 代码或 std::map 节点。CaptureEnter/Leave 由 stub 本身维护计数。
struct CaptureSiteSnapshot {
    uintptr_t target = 0;
    CaptureSite* site = nullptr;
    void* stub = nullptr;
};

static bool RemoveCaptureHook(uintptr_t target) {
    void* addr = reinterpret_cast<void*>(target);
    lock_guard<mutex> mhLock(Runtime::MinHookMutex());
    const MH_STATUS disableStatus = MH_DisableHook(addr);
    if (disableStatus != MH_OK && disableStatus != MH_ERROR_DISABLED &&
            disableStatus != MH_ERROR_NOT_CREATED) {
        Logger::Log("RemoveCaptureHook: disable failed target=%p status=%s",
            addr, MH_StatusToString(disableStatus));
        return false;
    }
    if (disableStatus == MH_ERROR_NOT_CREATED) return true;
    const MH_STATUS removeStatus = MH_RemoveHook(addr);
    if (removeStatus != MH_OK && removeStatus != MH_ERROR_NOT_CREATED) {
        Logger::Log("RemoveCaptureHook: remove failed target=%p status=%s",
            addr, MH_StatusToString(removeStatus));
        return false;
    }
    return true;
}

static void WaitForCaptureSiteDrain(CaptureSite* site) {
    if (!site) return;
    std::unique_lock<std::mutex> lock(g_captureDrainMutex);
    g_captureDrainCv.wait(lock, [site] {
        return site->activeCalls.load(std::memory_order_acquire) == 0;
    });
}

static void RetireCaptureSites(const vector<CaptureSiteSnapshot>& snapshot) {
    for (const auto& item : snapshot) {
        if (!RemoveCaptureHook(item.target)) {
            // 不能确认 target 已经不会再跳入 stub 时，保留 site/stub，优先避免 UAF。
            continue;
        }
        WaitForCaptureSiteDrain(item.site);
        {
            lock_guard<mutex> lock(g_captureMutex);
            const auto it = g_captureSites.find(item.target);
            if (it == g_captureSites.end() || &it->second != item.site ||
                    it->second.stubCode != item.stub) {
                continue;
            }
            if (item.stub) g_captureRuntime.release(item.stub);
            g_captureSites.erase(it);
        }
    }
}

static void CleanupAllCaptureSites() {
    lock_guard<mutex> retireLock(g_captureRetireMutex);
    vector<CaptureSiteSnapshot> snapshot;
    {
        lock_guard<mutex> lock(g_captureMutex);
        snapshot.reserve(g_captureSites.size());
        for (auto& [target, site] : g_captureSites) {
            site.retiring = true;
            snapshot.push_back({ target, &site, site.stubCode });
        }
    }
    RetireCaptureSites(snapshot);
}

// 插件卸载：只摘除该 owner 的 out 槽；还有其它 owner 订阅时保留站点和 hook。
static void CleanupCaptureSitesForOwner(const std::wstring& owner) {
    if (owner.empty()) return;
    lock_guard<mutex> retireLock(g_captureRetireMutex);
    vector<CaptureSiteSnapshot> snapshot;
    {
        lock_guard<mutex> lock(g_captureMutex);
        for (auto& [target, site] : g_captureSites) {
            const auto oldSize = site.outs.size();
            site.outs.erase(std::remove_if(site.outs.begin(), site.outs.end(),
                [&owner](const CaptureSite::Out& out) {
                    return out.ownerId == owner;
                }), site.outs.end());
            // 同时重试之前摘钩失败、已无订阅者的站点；不访问失败调用者的 out。
            if (site.outs.empty() && (oldSize != 0 || site.retiring)) {
                site.retiring = true;
                snapshot.push_back({ target, &site, site.stubCode });
            }
        }
    }
    if (snapshot.empty()) return;
    RetireCaptureSites(snapshot);
    Logger::Log("CleanupCaptureSitesForOwner: owner=%ls retired=%zu site(s)",
        owner.c_str(), snapshot.size());
}

// ================= GameEvents 桥接（RegisterGameEvent / TriggerGameEvent） =================
// GameEvents = 纯登记 + 插件端手动触发（不再挂游戏信号环，无每回合自动广播）：
//  - 登记：RegisterGameEvent(name, pushFn)——只在注册表记下名字与 Lua 参数打包回调（owner 生命周期保留）。
//  - 触发：TriggerGameEvent(name, payload)——插件主动触发 → GameEventInvokeLua → 内化到 Lua。
//  - 播放：内化路径（活跃 state 实时取 + 锁协议 + GameEvents[name].Call + 栈清理），
//        引擎桥旧路径（args 容器 + CallHook 桥）已删除，统一到 Lua 路径。

namespace {

// ---- GameEvent 引擎 ABI 常量 ----
// exe: ScriptSystem::CallHook 内的单例读取序列（mov rax,cs:singleton; mov rcx,[rax+10h]; jmp）
// ——AOB 自锚定，避免硬编码 RVA 的版本脆性。
constexpr const char* kLuaSingletonPattern =
    "48 8B 05 ?? ?? ?? ?? 48 8B 48 10 E9";
void* g_activeLuaStateHit = nullptr;   // AOB 命中缓存（Contains 校验，跨代自动重扫）
constexpr size_t   kGameEventNameMax           = 96;    // 事件名副本容量（注册表）

// ms_pkCurrentGame 定位 pattern（GameSignals::Subscribe 开头 mov rdi, cs:ms_pkCurrentGame
// 序列；读命中+3 的 disp32，目标槽 = 命中+7+disp32）。GetCurrentGameSlot 用它解析
// ms_pkCurrentGame 槽（GetEngineUtilityImpl 读 +0x18 取 EngineUtility）。
constexpr char kGameEventCurrentGamePattern[] =
    "48 8B 3D ?? ?? ?? ?? 48 85 FF 0F 84 ?? ?? ?? ?? 48 8B BF 80 02 00 00";
// GameSignals::Subscribe 内 "mov rdi, cs:ms_pkCurrentGame" 指令地址（按代缓存，重扫兜底）。
static void* g_gameEventContainerHit = nullptr;

constexpr int kMaxRegisteredGameEvents = 32;

// 每个注册的 GameEvent 一条记录：名字 + owner + Lua 参数打包回调。槽位判空用 name[0]。
struct RegisteredGameEvent {
    GameEventPushFn luaPushFn = nullptr;        // Lua 路径：压参数并返回个数
    std::wstring ownerId;                 // 注册者插件 owner（卸载/隔离按 owner 清理）
    char name[kGameEventNameMax] = {};    // 名字副本（对象末尾，长期存活；name[0]==0 即空槽）
};
static RegisteredGameEvent g_gameEvents[kMaxRegisteredGameEvents];

// ---- SEH 保护的内存读取 / 调用（无 C++ 对象，允许 __try） ----
static void* GameEventReadPtrSafe(const void* base, size_t offset) {
    void* value = nullptr;
    __try {
        value = *reinterpret_cast<void* const*>(static_cast<const char*>(base) + offset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    return value;
}

static int32_t GameEventReadInt32Safe(const void* addr) {
    int32_t value = 0;
    __try {
        value = *reinterpret_cast<const int32_t*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return value;
}

// ms_pkCurrentGame 的 .data 槽地址（命中地址按代缓存，重载后 Contains 失效自动重扫）。
static void* GetCurrentGameSlot() {
    if (!g_gameEventContainerHit ||
            !ImageAddress::Contains(kHookImageGameCoreXP2, g_gameEventContainerHit)) {
        g_gameEventContainerHit = ResolveByPatternImpl(kHookImageGameCoreXP2,
            kGameEventCurrentGamePattern, kSectionText);
        if (!g_gameEventContainerHit) return nullptr;
    }
    const int32_t disp = GameEventReadInt32Safe(
        static_cast<const char*>(g_gameEventContainerHit) + 3);
    if (disp == 0) return nullptr;
    return static_cast<char*>(g_gameEventContainerHit) + 7 + disp;
}

// GameCore::EngineUtility 全局（ms_pkCurrentGame 槽 +0x18，与 scriptSystem +0x20 同族）。
// 锁协议（官方 Utility::CallHook 同款）：插件在持锁上下文做 Lua 工作前调用。
void* GetEngineUtilityImpl() {
    void* currentGameSlot = GetCurrentGameSlot();
    if (!currentGameSlot) return nullptr;
    return GameEventReadPtrSafe(static_cast<const char*>(currentGameSlot) + 0x18, 0);
}

// 当前活跃游戏 Lua 状态——官方 GameCore::ScriptSystem::CallHook 同款（IDA 实证）：
//   mov rax, cs:?ms_apSingletonInstance@LuaScriptSystem@LuaSystem@@2PEAV12@EA   ; exe RVA 0x2D08F88
//   mov rcx, [rax+10h]                                                          ; 活跃 lua_State
// 每次实时读（引擎在对局/脚本切换时更新 +0x10），不缓存。
void* GetActiveLuaStateImpl() {
    // 定位 exe 的 ScriptSystem::CallHook 内的全局读取序列（IDA 实证）：
    //   48 8B 05 ?? ?? ?? ??   mov rax, cs:ms_apSingletonInstance
    //   48 8B 48 10            mov rcx, [rax+10h]      ← 活跃 lua_State
    //   E9 ?? ?? ?? ??         jmp GameEventLibrary::CallHook
    // AOB 自锚定（不依赖硬编码 RVA，游戏版本更新时该序列由编译器稳定生成）；
    // 命中地址按镜像缓存（Contains 校验，跨代/重载自动重扫）。
    static const HookImageId kCandidates[] = { kHookImageExeDx11, kHookImageExeDx12 };
    for (HookImageId image : kCandidates) {
        if (!ImageAddress::IsLoaded(image)) continue;
        // 缓存命中（地址仍属该镜像）直接用
        void* slot = nullptr;
        if (g_activeLuaStateHit && ImageAddress::Contains(image, g_activeLuaStateHit)) {
            const int32_t disp = GameEventReadInt32Safe(
                static_cast<const char*>(g_activeLuaStateHit) + 3);
            if (disp != 0) {
                slot = static_cast<char*>(g_activeLuaStateHit) + 7 + disp;
            }
        }
        if (!slot) {
            void* hit = ResolveByPatternImpl(image, kLuaSingletonPattern, kSectionText);
            if (hit) {
                g_activeLuaStateHit = hit;
                const int32_t disp = GameEventReadInt32Safe(static_cast<const char*>(hit) + 3);
                if (disp != 0) slot = static_cast<char*>(hit) + 7 + disp;
            }
        }
        if (!slot) continue;
        void* singleton = GameEventReadPtrSafe(slot, 0);
        if (!singleton) continue;
        void* L = GameEventReadPtrSafe(static_cast<const char*>(singleton) + 0x10, 0);
        // 【诊断】一次性打印命中 RVA（预期 slot RVA=0x2D08F88），验证 AOB 锚点正确性
        static bool s_logged = false;
        if (!s_logged && L) {
            s_logged = true;
            HookImageInfo info{ sizeof(HookImageInfo) };
            if (ImageAddress::GetInfo(image, &info) && info.base) {
                Logger::Log("GetActiveLuaState: image=%u hitRva=0x%llX slotRva=0x%llX L=%p",
                    static_cast<unsigned>(image),
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(g_activeLuaStateHit) - info.base),
                    static_cast<unsigned long long>(
                        reinterpret_cast<uintptr_t>(slot) - info.base), L);
            }
        }
        if (L) return L;
    }
    return nullptr;
}

// 插件卸载/隔离时清理其注册的 GameEvent：清槽位（name[0]='\0' + 字段清空 + ownerId.clear）。
// 调用方持 lifecycle 锁（RemovePluginOwnedRegistrations 内调用），本函数不再加锁。
static void CleanupGameEventsForOwner(const std::wstring& owner) {
    size_t cleaned = 0;
    for (auto& ev : g_gameEvents) {
        if (ev.name[0] == '\0' || ev.ownerId != owner) continue;
        ev.name[0] = '\0';
        ev.ownerId.clear();
        ++cleaned;
    }
    if (cleaned == 0) return;
    Logger::Log("CleanupGameEventsForOwner: owner=%ls cleaned=%zu event(s)",
        owner.c_str(), cleaned);
}

}  // namespace

// Lua 表路径触发（内化）：官方 CallHook 同款机制全收进 runtime——
//   活跃 state 实时取 → 锁协议三步 → GameEvents[name].Call(table) → 栈清理。
// 插件 pushFn 只负责往栈顶空表塞字段（字符串键/嵌套/数组）。
// 栈清理兜底：独立 noinline SEH（/EHsc 下 __try 函数内不能带析构的 C++ 对象）。
// 关键：在 Lua 序列的 __try **之外**调用——即使插件 pushFn 崩溃，栈也能恢复到基线，
// 避免反复失败累积栈残留（远程引擎桥用 argsCreated 标志做等价兜底）。
static __declspec(noinline) void GameEventPopToBaseSeh(void* L, int base) {
    __try {
        auto* s = reinterpret_cast<hks::lua_State*>(L);
        const int top = hks::gettop(s);
        if (top > base) hks::pop(s, top - base);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

// 插件参数回调的独立 SEH：让日志能分辨"插件回调崩"与"引擎/Lua 崩"（对齐远程粒度）。
static __declspec(noinline) bool GameEventPushArgsSeh(GameEventPushFn pushFn, void* L,
                                                      const void* payload, int* outNargs) {
    __try {
        *outNargs = pushFn(L, payload);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Lua 序列段（含插件回调）：只做 Lua 操作，栈清理交给调用者（保证崩溃路径也执行）。
static bool GameEventInvokeLuaSeh(const char* name, GameEventPushFn pushFn,
                                  const void* payload, void* L, int base) {
    bool ok = false;
    __try {
        auto* s = reinterpret_cast<hks::lua_State*>(L);
        hks::getfield(s, hks::LUA_GLOBAL, "GameEvents");
        hks::getfield(s, -1, name);
        hks::getfield(s, -1, "Call");
        int nargs = 0;
        if (pushFn && !GameEventPushArgsSeh(pushFn, L, payload, &nargs)) {
            Logger::Log("GameEvent: InvokeLua pushFn failed name=%s", name);
            ok = false;   // 参数不完整，不继续调用
        } else {
            const int argc = (nargs < 0) ? 0 : nargs;
            ok = hks::pcall(s, argc, 0, 0) == 0; // Call(arg1, arg2, ...)
        }
        (void)base;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("GameEvent: InvokeLua exception name=%s", name);
        ok = false;
    }
    return ok;
}

// EngineUtility 全局解析失败的限次告警：此时"GameCore 锁状态未知"，TriggerGameEvent
// 会直接拒绝执行——必须可诊断，但脚本可能高频触发，不能刷屏。
static void WarnEngineUtilityUnavailable(const char* name) {
    static std::atomic<int> s_warned{ 0 };
    const int seen = s_warned.fetch_add(1, std::memory_order_relaxed);
    if (seen < 10) {
        Logger::Log("GameEvent: TriggerGameEvent(\"%s\") refused: EngineUtility unavailable "
                    "(GameCore lock state unknown; AOB pattern mismatch or GameCore not ready)", name);
    } else if (seen == 10) {
        Logger::Log("GameEvent: EngineUtility still unavailable; further refusals are not logged");
    }
}

// 内层主体：无 C++ 异常语义（SEH 段 + 资源兜底）。
static bool GameEventInvokeLuaImpl(const char* name, GameEventPushFn pushFn,
                                   const void* payload) noexcept {
    if (!name || !*name) return false;
    void* L = GetActiveLuaStateImpl();
    if (!L) {
        Logger::Log("GameEvent: InvokeLua no-active-state name=%s", name);
        return false;
    }
    if (!hks::getfield || !hks::setfield || !hks::createtable || !hks::pcall ||
        !hks::gettop || !hks::pop) {
        Logger::Log("GameEvent: InvokeLua hks-imports-missing name=%s", name);
        return false;
    }

    // 记录栈基线（清理兜底用）
    int base = 0;
    __try {
        base = hks::gettop(reinterpret_cast<hks::lua_State*>(L));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("GameEvent: InvokeLua gettop failed name=%s", name);
        return false;
    }

    // 锁协议（官方 Utility::CallHook 同款）：持锁则先释放，Lua 工作完成后恢复。
    // EngineUtility 解析失败 / 取放锁调用异常 = GameCore 锁状态未知：此时不进入 Lua
    //（带锁重入 Lua 可能自死锁或破坏 Lua 状态），本次触发直接拒绝并限次告警。
    void* eu = GetEngineUtilityImpl();
    bool had = false;
    if (eu) {
        __try {
            void** vt = *reinterpret_cast<void***>(eu);
            had = reinterpret_cast<bool(__fastcall*)(void*)>(vt[6])(eu);  // HasGameCoreLock
            if (had) reinterpret_cast<void(__fastcall*)(void*)>(vt[7])(eu); // Release
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            Logger::Log("GameEvent: lock protocol fault code=0x%08X name=%s", GetExceptionCode(), name);
            had = false;
            eu = nullptr;
        }
    }
    if (!eu) {
        WarnEngineUtilityUnavailable(name);
        return false;
    }

    const bool ok = GameEventInvokeLuaSeh(name, pushFn, payload, L, base);

    // ★ 栈清理在 __try 之外——崩溃路径同样执行（资源兜底）
    GameEventPopToBaseSeh(L, base);

    if (had) {
        __try {
            void** vt = *reinterpret_cast<void***>(eu);
            reinterpret_cast<void(__fastcall*)(void*)>(vt[8])(eu);       // GetGameCoreLock
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // 已释放锁但取回失败：后续 Lua/游戏逻辑将在无锁状态下运行，必须留痕。
            Logger::Log("GameEvent: failed to re-acquire GameCore lock code=0x%08X name=%s",
                GetExceptionCode(), name);
        }
    }
    return ok;
}

// 外层：C++ 异常兜底（插件回调 throw / 标准库异常），与远程 Safe 层同款。
static bool GameEventInvokeLua(const char* name, GameEventPushFn pushFn,
                               const void* payload) noexcept {
    try {
        return GameEventInvokeLuaImpl(name, pushFn, payload);
    } catch (...) {
        Logger::Log("GameEvent: InvokeLua cxx-exception name=%s", name);
        return false;
    }
}

// 手动触发一次：查找注册记录，仅 Lua 路径（内化）。未注册或 luaPushFn 为 null → false。
// 查到记录后先取 owner 在途守卫（TryEnterPluginCallback）——插件卸载/隔离期间拒绝触发，
// 避免在途调用踩到已回滚的注册（与远程对引擎桥路径的加固同款）。
bool TriggerGameEventImpl(const char* name, const void* payload) {
    if (!name || !*name) return false;
    GameEventPushFn luaPushFn = nullptr;
    std::wstring owner;
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        for (const auto& ev : g_gameEvents) {
            if (ev.name[0] && strcmp(ev.name, name) == 0) {
                luaPushFn = ev.luaPushFn;
                owner = ev.ownerId;
                break;
            }
        }
    }
    if (!luaPushFn) {
        Logger::Log("TriggerGameEvent: \"%s\" not registered (or non-Lua path)", name);
        return false;
    }
    auto callbackGuard = TryEnterPluginCallback(owner);
    if (!callbackGuard) {
        Logger::Log("TriggerGameEvent: rejected for inactive owner=%ls name=%s",
            owner.c_str(), name);
        return false;
    }
    return GameEventInvokeLua(name, luaPushFn, payload);
}

// 注册 Lua 路径事件：owner/幂等/空槽登记（触发时走 GameEventInvokeLua 内化路径）。
bool RegisterGameEventImpl(const char* name, GameEventPushFn pushFn) {
    if (!name || !*name) return false;
    const size_t nameLength = strlen(name);
    if (nameLength >= kGameEventNameMax) {
        Logger::Log("RegisterGameEvent: name too long (%zu bytes, max %zu)",
            nameLength, kGameEventNameMax - 1);
        return false;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);

    const void* ownerProbe = reinterpret_cast<const void*>(pushFn);
    if (!ownerProbe) ownerProbe = name;
    auto owner = RequirePluginOwner(ownerProbe, "RegisterGameEvent");
    if (!owner) {
        Logger::Log("RegisterGameEvent: no plugin owner");
        return false;
    }
    for (const auto& ev : g_gameEvents) {
        if (ev.name[0] && strcmp(ev.name, name) == 0) return true;   // 同名幂等
    }
    RegisteredGameEvent* slot = nullptr;
    for (auto& ev : g_gameEvents) {
        if (!ev.name[0]) { slot = &ev; break; }
    }
    if (!slot) {
        Logger::Log("RegisterGameEvent: no free slot (max %d)", kMaxRegisteredGameEvents);
        return false;
    }
    slot->luaPushFn = pushFn;
    slot->ownerId = *owner;
    memcpy(slot->name, name, nameLength);
    slot->name[nameLength] = '\0';
    Logger::Log("GameEvent: registered Lua-event \"%s\" pushFn=%p", name, pushFn);
    return true;
}

void* ResolveCurrentGameCoreByName(const char* name) {
    const HookImageId image = ImageAddress::LoadedGameCore();
    if (image == kHookImageInvalid) return nullptr;
    return ResolveByNameImpl(image, name);
}

using PushMethodsNoFunc = void(__fastcall*)(hks::lua_State* L, int stackOffset);
using PushMethodsWithFunc = void(__fastcall*)(void*, hks::lua_State* L, int stackOffset);

static bool SameLuaMethod(const StoredLuaMethod& a, const StoredLuaMethod& b) {
    return a.owner == b.owner && a.luaMethodFunc == b.luaMethodFunc &&
        a.internalName == b.internalName && a.exposedName == b.exposedName;
}

// 对候选副本合并；调用方成功后才 swap 到正式表，冲突不会留下半批方法。
static bool MergeLuaMethod(vector<StoredLuaMethod>& candidate, const StoredLuaMethod& method) {
    if (!method.luaMethodFunc || method.internalName.empty() ||
            method.exposedName.empty() || method.owner.empty()) return false;
    const auto existing = std::find_if(candidate.begin(), candidate.end(),
        [&method](const StoredLuaMethod& item) {
            return item.exposedName == method.exposedName;
        });
    if (existing != candidate.end()) return SameLuaMethod(*existing, method);
    candidate.push_back(method);
    return true;
}

static bool MergeLuaMethods(vector<StoredLuaMethod>& candidate,
                             const vector<StoredLuaMethod>& methods) {
    for (const auto& method : methods) {
        if (!MergeLuaMethod(candidate, method)) return false;
    }
    return true;
}

HookApiPushMethodsResult PushLuaMethodsImpl(
        const char* name, const LuaMethodInfo* methods, uint32_t count) {
    if (!name || !*name || !methods || count == 0) return kHookApiPushMethodsFailed;
    // owner 校验、候选合并和安装提交共用生命周期锁，停用不能插入中间。
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    auto owner = RequirePluginOwner(
        reinterpret_cast<const void*>(methods[0].luaMethodFunc), "PushLuaMethods");
    if (!owner) return kHookApiPushMethodsFailed;
    const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&owner](const PluginEntry& entry) {
            return entry.ownerId == *owner &&
                (entry.state == PluginState::Loading || entry.state == PluginState::Active);
        });
    if (plugin == g_plugins.end()) return kHookApiPushMethodsFailed;

    const std::string targetName(name);
    PushTargetConfig config;
    const auto ownerConfigs = g_pluginPushTargetConfigs.find(*owner);
    if (ownerConfigs != g_pluginPushTargetConfigs.end()) {
        const auto configured = ownerConfigs->second.find(targetName);
        if (configured != ownerConfigs->second.end()) config = configured->second;
    }
    if (config.symbolName.empty()) {
        const auto builtIn = g_defaultPushTargetConfigs.find(targetName);
        if (builtIn != g_defaultPushTargetConfigs.end()) config = builtIn->second;
    }
    if (config.symbolName.empty()) {
        Logger::Log("PushLuaMethods: unknown target %s", name);
        return kHookApiPushMethodsFailed;
    }

    // 每个 owner/target 仅有一份登记；请求可以是重复、重排或部分重叠的批次。
    size_t registrationIndex = g_pushRegistrations.size();
    PushRegistration candidate{ targetName, config.signature, {}, *owner, config.symbolName };
    for (size_t i = 0; i < g_pushRegistrations.size(); ++i) {
        const auto& registration = g_pushRegistrations[i];
        if (registration.owner == *owner && registration.targetName == targetName) {
            if (registration.signature != candidate.signature ||
                    registration.symbolName != candidate.symbolName) {
                return kHookApiPushMethodsFailed;
            }
            candidate = registration;
            registrationIndex = i;
            break;
        }
    }
    for (uint32_t i = 0; i < count; ++i) {
        auto methodOwner = RequirePluginOwner(
            reinterpret_cast<const void*>(methods[i].luaMethodFunc), "PushLuaMethods");
        if (!methodOwner || *methodOwner != *owner || !methods[i].internalName ||
                !methods[i].exposedName || !MergeLuaMethod(candidate.methods, StoredLuaMethod{
                    methods[i].luaMethodFunc, methods[i].internalName, methods[i].exposedName, *owner })) {
            Logger::Log("PushLuaMethods rejected: invalid or conflicting method for %s", name);
            return kHookApiPushMethodsFailed;
        }
    }
    // 同一个 Lua 表的字段不允许被另一个 owner 的登记隐式覆盖，延迟阶段也校验。
    for (const auto& registration : g_pushRegistrations) {
        if (registration.targetName != targetName || registration.owner == *owner) continue;
        for (const auto& method : candidate.methods) {
            if (std::any_of(registration.methods.begin(), registration.methods.end(),
                    [&method](const StoredLuaMethod& existing) {
                        return existing.exposedName == method.exposedName;
                    })) {
                Logger::Log("PushLuaMethods rejected: field %s of %s belongs to another owner",
                    method.exposedName.c_str(), name);
                return kHookApiPushMethodsFailed;
            }
        }
    }

    // 安装前完成登记容器分配；成功后的发布只移动/交换已构造的数据。
    const bool isNew = registrationIndex == g_pushRegistrations.size();
    if (isNew) g_pushRegistrations.reserve(g_pushRegistrations.size() + 1);
    if (g_gameCorePhaseReady) {
        const std::string& symbolName = candidate.symbolName;
        void* target = ResolveCurrentGameCoreByName(symbolName.c_str());
        if (!target) {
            Logger::Log("PushLuaMethods: resolve failed: %s", symbolName.c_str());
            return kHookApiPushMethodsFailed;
        }
        void* base = candidate.signature == PushMethodSigType::NoManager
            ? InstallPushMethodsNoManager(target, candidate.methods, *owner)
            : InstallPushMethodsWithManager(target, candidate.methods, *owner);
        if (!base) {
            Logger::Log("PushLuaMethods: install failed: %s", symbolName.c_str());
            return kHookApiPushMethodsFailed;
        }
    }

    if (isNew) {
        g_pushRegistrations.push_back(std::move(candidate));
    } else {
        g_pushRegistrations[registrationIndex].methods.swap(candidate.methods);
    }
    return g_gameCorePhaseReady ? kHookApiPushMethodsInstalled : kHookApiPushMethodsDeferred;
}

namespace {

// 脚本全局注册项：owner = 注册时活跃插件名（空 = Loader 自身，插件卸载不撤销）。
// fn 指向插件映像内代码，插件卸载时必须移除，否则 RegisterScriptData detour
// 会调进已 FreeLibrary 的内存（与 OnMessage 悬空 handler 同类问题）。
struct ScriptGlobalsEntry {
    std::wstring owner;
    ScriptGlobalsFn fn;
};

std::vector<ScriptGlobalsEntry> g_scriptGlobals;
std::vector<ScriptGlobalsEntry> g_scriptGlobalsUI;
ProxyTypes::RegisterScriptData g_origRegisterScriptData = nullptr;
ProxyTypes::RegisterScriptDataForUI g_origRegisterScriptDataForUI = nullptr;
bool g_scriptHookInstalled = false;
bool g_scriptUIHookInstalled = false;
// 共享钩子的目标地址（GameCore 域）：GameCore 重载时据此摘钩。
void* g_scriptHookTarget = nullptr;
void* g_scriptUIHookTarget = nullptr;

static void CallScriptGlobalsSafe(ScriptGlobalsFn fn, void* L) {
    if (!fn) return;
    __try {
        fn(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("ScriptGlobals callback crashed code=0x%08X", GetExceptionCode());
    }
}

// 拷贝快照后在锁外回调：注册表可能被 Loader 工作线程（插件卸载清理）并发修改。
static std::vector<ScriptGlobalsEntry> SnapshotScriptGlobals(std::vector<ScriptGlobalsEntry>& reg) {
    lock_guard<mutex> lock(g_scriptStateMutex);
    return reg;
}

void __cdecl Hook_RegisterScriptData(hks::lua_State* L) {
    SharedDetourActivity activity;
    const auto snapshot = SnapshotScriptGlobals(g_scriptGlobals);
    Logger::Log("RegisterScriptData: running %zu plugin global registrar(s)", snapshot.size());
    size_t i = 0;
    for (const auto& entry : snapshot) {
        Logger::Log("RegisterScriptData: registrar[%zu] begin", i);
        auto callbackGuard = TryEnterPluginCallback(entry.owner);
        if (callbackGuard) {
            CallScriptGlobalsSafe(entry.fn, reinterpret_cast<void*>(L));
        } else {
            Logger::Log("RegisterScriptData: registrar[%zu] skipped for inactive owner=%ls",
                i, entry.owner.c_str());
        }
        Logger::Log("RegisterScriptData: registrar[%zu] end", i);
        ++i;
    }
    if (g_origRegisterScriptData) {
        Logger::Log("RegisterScriptData: calling original");
        g_origRegisterScriptData(L);
        Logger::Log("RegisterScriptData: original returned");
    }
}

void __cdecl Hook_RegisterScriptDataForUI(hks::lua_State* unused, hks::lua_State* L) {
    // 高频路径：游戏每建一个 UI context 就调一次（主菜单/对局切换均触发），
    // 逐次日志会刷屏——行为日志降噪，registrar 照常每次执行（新 context 需要重新挂全局）。
    SharedDetourActivity activity;
    const auto snapshot = SnapshotScriptGlobals(g_scriptGlobalsUI);
    for (const auto& entry : snapshot) {
        auto callbackGuard = TryEnterPluginCallback(entry.owner);
        if (callbackGuard) {
            CallScriptGlobalsSafe(entry.fn, reinterpret_cast<void*>(L));
        }
    }
    if (g_origRegisterScriptDataForUI) {
        g_origRegisterScriptDataForUI(unused, L);
    }
}

// 装共享钩（owner 固定 = Loader）。ALREADY_CREATED = 旧 GameCore 映像残留的
// MinHook 记录（地址复用）：摘除后重装一次，强制按新映像重打补丁。
// g_*HookTarget 记录目标地址，供 GameCore 重载时摘钩。
static bool InstallSharedHook(void* target, void* detour, void** orig, void** targetSlot) {
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    MH_STATUS status = InstallHookOwnedByLocked(
        target, detour, orig, L"", HookKind::SharedScript);
    if (status == MH_OK) {
        *targetSlot = target;
        return true;
    }

    const auto it = g_hookRecords.find(target);
    const bool isOurStaleHook =
        status == MH_ERROR_ALREADY_CREATED &&
        it != g_hookRecords.end() &&
        it->second.owner.empty() &&
        it->second.gameCoreGeneration < ImageAddress::GameCoreGeneration() &&
        g_activeSharedDetours.load(std::memory_order_acquire) == 0;
    if (isOurStaleHook && SafeRemoveHookLocked(target) &&
        InstallHookOwnedByLocked(target, detour, orig, L"",
                                 HookKind::SharedScript) == MH_OK) {
        *targetSlot = target;
        return true;
    }
    return false;
}

// 确保已注册回调对应的共享钩子已装上。三条调用路径：
//  1) 插件 RegisterScriptGlobals 首次注册（原有路径）；
//  2) GameCore 重载后 InitializeGameCorePhase 再调（钩子已随 ResetForReload 摘除，
//     回调列表跨重载保留——Global 插件仍加载着，其注册项不丢）；
//  3) 阶段 B 首次进入时列表已非空（Global 插件在阶段 A 注册过）。
// 检查+安装整体持锁，消除并发首装的重复创建竞态。
static void EnsureScriptHooksInstalled() {
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    if (!g_gameCorePhaseReady) return;

    if (!g_scriptHookInstalled && !g_scriptGlobals.empty()) {
        void* target = ResolveCurrentGameCoreByName("GameCore::Lua::Utility::RegisterScriptData");
        if (!target) {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptData address missing");
        } else if (InstallSharedHook(target, reinterpret_cast<void*>(&Hook_RegisterScriptData),
                       reinterpret_cast<void**>(&g_origRegisterScriptData), &g_scriptHookTarget)) {
            g_scriptHookInstalled = true;
            Logger::Log("EnsureScriptHooksInstalled: hooked RegisterScriptData at %p", target);
        }
    }
    if (!g_scriptUIHookInstalled && !g_scriptGlobalsUI.empty()) {
        void* target = ResolveCurrentGameCoreByName("GameCore::Lua::Utility::RegisterScriptDataForUI");
        if (!target) {
            Logger::Log("EnsureScriptHooksInstalled: RegisterScriptDataForUI address missing");
        } else if (InstallSharedHook(target, reinterpret_cast<void*>(&Hook_RegisterScriptDataForUI),
                       reinterpret_cast<void**>(&g_origRegisterScriptDataForUI), &g_scriptUIHookTarget)) {
            g_scriptUIHookInstalled = true;
            Logger::Log("EnsureScriptHooksInstalled: hooked RegisterScriptDataForUI at %p", target);
        }
    }
}

}  // namespace

// ---- GameCore 生命周期回调（Global 插件延迟挂钩，语义见 HookAPI.h 尾部文档）----

// 前置声明（定义于本文件后部）：回调崩溃时按 owner 隔离（与 OnLoad 崩溃同构）。
static void QuarantinePluginByOwner(const std::wstring& ownerId);

namespace {

struct GameCoreCallbackEntry {
    std::wstring owner;
    void (*fn)(void*) = nullptr;
    std::atomic<void*> context{ nullptr };
    std::atomic<bool> enabled{ true };
    std::atomic<uint32_t> activeCalls{ 0 };
    mutex drainMutex;
    condition_variable drainCv;
};

using GameCoreCallbackPtr = std::shared_ptr<GameCoreCallbackEntry>;
std::vector<GameCoreCallbackPtr> g_gameCoreReadyCallbacks;
std::vector<GameCoreCallbackPtr> g_gameCoreTeardownCallbacks;
mutex g_gameCoreCallbackMutex;
std::recursive_mutex g_gameCoreTransitionMutex;
thread_local GameCoreCallbackEntry* g_currentGameCoreCallback;

// 登记回调（同 owner + 同 fn 幂等：重复注册仅刷新 context）。
std::pair<GameCoreCallbackPtr, bool> AddGameCoreCallback(
        std::vector<GameCoreCallbackPtr>& reg, const std::wstring& owner,
        void (*fn)(void*), void* context, const char* apiName) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&owner](const PluginEntry& entry) {
            return entry.ownerId == owner &&
                (entry.state == PluginState::Loading ||
                 entry.state == PluginState::Active);
        });
    if (plugin == g_plugins.end()) {
        Logger::Log("%s rejected: owner is no longer active (%ls)",
            apiName, owner.c_str());
        return { nullptr, false };
    }
    lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
    for (auto& existing : reg) {
        if (existing->owner == owner && existing->fn == fn) {
            existing->context.store(context, std::memory_order_release);
            return { existing, false };
        }
    }
    auto entry = std::make_shared<GameCoreCallbackEntry>();
    entry->owner = owner;
    entry->fn = fn;
    entry->context.store(context, std::memory_order_release);
    Logger::Log("%s: registered owner=%ls", apiName, owner.c_str());
    reg.push_back(entry);
    return { entry, true };
}

__declspec(noinline) bool CallGameCoreCallbackSeh(
        const GameCoreCallbackPtr& entry, const char* phase) {
    __try {
        entry->fn(entry->context.load(std::memory_order_acquire));
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("%s: callback crashed owner=%ls code=0x%08X; quarantining",
            phase, entry->owner.c_str(), GetExceptionCode());
        return false;
    }
}

bool CallGameCoreCallbackSafe(const GameCoreCallbackPtr& entry, const char* phase) noexcept {
    try {
        return CallGameCoreCallbackSeh(entry, phase);
    } catch (...) {
        Logger::Log("%s: callback threw C++ exception owner=%ls; quarantining",
            phase, entry->owner.c_str());
        return false;
    }
}

bool AdmitGameCoreCallback(const GameCoreCallbackPtr& entry) {
    if (!entry || !entry->enabled.load(std::memory_order_acquire)) return false;
    entry->activeCalls.fetch_add(1, std::memory_order_acq_rel);
    if (entry->enabled.load(std::memory_order_acquire)) return true;
    if (entry->activeCalls.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        lock_guard<mutex> lock(entry->drainMutex);
        entry->drainCv.notify_all();
    }
    return false;
}

void InvokeAdmittedGameCoreCallback(const GameCoreCallbackPtr& entry,
                                    const char* phase) {
    Logger::Log("%s: begin owner=%ls", phase, entry->owner.c_str());
    auto* previous = g_currentGameCoreCallback;
    g_currentGameCoreCallback = entry.get();
    const bool succeeded = CallGameCoreCallbackSafe(entry, phase);
    g_currentGameCoreCallback = previous;
    if (succeeded) {
        Logger::Log("%s: end owner=%ls", phase, entry->owner.c_str());
    }
    if (entry->activeCalls.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        lock_guard<mutex> lock(entry->drainMutex);
        entry->drainCv.notify_all();
    }
    if (!succeeded) {
        QuarantinePluginByOwner(entry->owner);
    }
}

void DisableAndDrainGameCoreCallbacks(
        const std::vector<GameCoreCallbackPtr>& callbacks) {
    for (const auto& entry : callbacks) {
        entry->enabled.store(false, std::memory_order_release);
    }
    for (const auto& entry : callbacks) {
        if (entry.get() == g_currentGameCoreCallback) continue;
        unique_lock<mutex> lock(entry->drainMutex);
        entry->drainCv.wait(lock, [&entry] {
            return entry->activeCalls.load(std::memory_order_acquire) == 0;
        });
    }
}

void WaitForGameCoreCallbacks(const std::vector<GameCoreCallbackPtr>& registry) {
    std::vector<GameCoreCallbackPtr> snapshot;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
        snapshot = registry;
    }
    for (const auto& entry : snapshot) {
        if (entry.get() == g_currentGameCoreCallback) continue;
        unique_lock<mutex> lock(entry->drainMutex);
        entry->drainCv.wait(lock, [&entry] {
            return entry->activeCalls.load(std::memory_order_acquire) == 0;
        });
    }
}

void RemoveGameCoreCallbacksFor(const std::wstring& owner) {
    std::vector<GameCoreCallbackPtr> removed;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
        auto removeOwned = [&owner, &removed](auto& reg) {
            for (auto it = reg.begin(); it != reg.end(); ) {
                if ((*it)->owner == owner) {
                    removed.push_back(*it);
                    it = reg.erase(it);
                } else {
                    ++it;
                }
            }
        };
        removeOwned(g_gameCoreReadyCallbacks);
        removeOwned(g_gameCoreTeardownCallbacks);
    }
    DisableAndDrainGameCoreCallbacks(removed);
}

}  // namespace

static bool HasGameCoreTeardownCallback(const std::wstring& owner) {
    lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
    return std::any_of(g_gameCoreTeardownCallbacks.begin(),
        g_gameCoreTeardownCallbacks.end(),
        [&owner](const GameCoreCallbackPtr& entry) {
            return entry->owner == owner &&
                entry->enabled.load(std::memory_order_acquire);
        });
}

void RegisterGameCoreReadyImpl(GameCoreReadyFn fn, void* context) {
    if (!fn) return;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn), "RegisterGameCoreReady");
    if (!owner) return;
    auto [entry, inserted] = AddGameCoreCallback(
        g_gameCoreReadyCallbacks, *owner, fn, context, "RegisterGameCoreReady");
    if (!entry) return;
    // 注册即触发：GameCore 已就绪（如对局中 reconcile 新加载的插件）时立即补调，
    // 不必等下一次重载。
    bool admitted = false;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        admitted = inserted && g_gameCorePhaseReady &&
            g_currentGameCoreCallback != entry.get() &&
            AdmitGameCoreCallback(entry);
    }
    if (admitted) {
        InvokeAdmittedGameCoreCallback(entry, "GameCoreReady(immediate)");
    }
}

void RegisterGameCoreTeardownImpl(GameCoreTeardownFn fn, void* context) {
    if (!fn) return;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn), "RegisterGameCoreTeardown");
    if (!owner) return;
    AddGameCoreCallback(g_gameCoreTeardownCallbacks, *owner, fn, context,
                        "RegisterGameCoreTeardown");
}

static std::vector<GameCoreCallbackPtr> SnapshotGameCoreCallbacks(
        const std::vector<GameCoreCallbackPtr>& reg) {
    std::vector<GameCoreCallbackPtr> snapshot;
    lock_guard<mutex> cbLock(g_gameCoreCallbackMutex);
    snapshot = reg;
    return snapshot;
}

// 逐条准入、逐条执行：同 owner 的前一回调若崩溃并隔离，后续条目已被禁用，
// 不会因批量预先增加 activeCalls 而让隔离线程等待自己尚未执行的条目。
static void FireGameCoreCallbackSnapshot(
        const std::vector<GameCoreCallbackPtr>& snapshot, const char* phase) {
    for (const auto& entry : snapshot) {
        bool admitted = false;
        {
            lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
            admitted = AdmitGameCoreCallback(entry);
        }
        if (admitted) InvokeAdmittedGameCoreCallback(entry, phase);
    }
}

static void FireGameCoreCallbacks(std::vector<GameCoreCallbackPtr>& reg,
                                  const char* phase) {
    std::vector<GameCoreCallbackPtr> snapshot;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        snapshot = SnapshotGameCoreCallbacks(reg);
    }
    FireGameCoreCallbackSnapshot(snapshot, phase);
}

void RegisterScriptGlobalsImpl(ScriptGlobalsFn fn) {
    if (!fn) return;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn),
                                    "RegisterScriptGlobals");
    if (!owner) return;
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        g_scriptGlobals.push_back(ScriptGlobalsEntry{ *owner, fn });
    }
    EnsureScriptHooksInstalled();  // 检查+安装整体在锁内（含并发首装与重载后重装）
}

void RegisterScriptGlobalsForUIImpl(ScriptGlobalsFn fn) {
    if (!fn) return;
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(fn),
                                    "RegisterScriptGlobalsForUI");
    if (!owner) return;
    {
        lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        g_scriptGlobalsUI.push_back(ScriptGlobalsEntry{ *owner, fn });
    }
    EnsureScriptHooksInstalled();
}

namespace {

constexpr int kMaxPushHooks = 16;

struct NoManagerHookSlot {
    void* target = nullptr;
    PushMethodsNoFunc base = nullptr;
    vector<StoredLuaMethod> methods;
    bool used = false;
};

struct WithManagerHookSlot {
    void* target = nullptr;
    PushMethodsWithFunc base = nullptr;
    vector<StoredLuaMethod> methods;
    bool used = false;
};

NoManagerHookSlot g_noManagerSlots[kMaxPushHooks];
WithManagerHookSlot g_withManagerSlots[kMaxPushHooks];

template<int I>
void __fastcall DetourPushNoManager(hks::lua_State* L, int stackOffset) {
    SharedDetourActivity activity;
    // 拷贝快照后在锁外回调：methods 可能被 Loader 工作线程（插件卸载清理）并发修改，
    // 快照同时把函数指针与 internalName/exposedName 字符串一并拷贝，锁外安全使用。
    std::vector<StoredLuaMethod> methods;
    PushMethodsNoFunc base = nullptr;
    {
        lock_guard<mutex> lock(g_pushStateMutex);
        methods = g_noManagerSlots[I].methods;
        base = g_noManagerSlots[I].base;
    }
    for (auto& method : methods) {
        PushLuaMethod(L, reinterpret_cast<hks::luaFunc>(method.luaMethodFunc),
            method.internalName.c_str(), stackOffset, method.exposedName.c_str());
    }
    if (base) {
        base(L, stackOffset);
    }
}

template<int I>
void __fastcall DetourPushWithManager(void* manager, hks::lua_State* L, int stackOffset) {
    SharedDetourActivity activity;
    std::vector<StoredLuaMethod> methods;
    PushMethodsWithFunc base = nullptr;
    {
        lock_guard<mutex> lock(g_pushStateMutex);
        methods = g_withManagerSlots[I].methods;
        base = g_withManagerSlots[I].base;
    }
    for (auto& method : methods) {
        PushLuaMethod(L, reinterpret_cast<hks::luaFunc>(method.luaMethodFunc),
            method.internalName.c_str(), stackOffset, method.exposedName.c_str());
    }
    if (base) {
        base(manager, L, stackOffset);
    }
}

void* NoManagerDetourTable[kMaxPushHooks] = {
    reinterpret_cast<void*>(&DetourPushNoManager<0>),
    reinterpret_cast<void*>(&DetourPushNoManager<1>),
    reinterpret_cast<void*>(&DetourPushNoManager<2>),
    reinterpret_cast<void*>(&DetourPushNoManager<3>),
    reinterpret_cast<void*>(&DetourPushNoManager<4>),
    reinterpret_cast<void*>(&DetourPushNoManager<5>),
    reinterpret_cast<void*>(&DetourPushNoManager<6>),
    reinterpret_cast<void*>(&DetourPushNoManager<7>),
    reinterpret_cast<void*>(&DetourPushNoManager<8>),
    reinterpret_cast<void*>(&DetourPushNoManager<9>),
    reinterpret_cast<void*>(&DetourPushNoManager<10>),
    reinterpret_cast<void*>(&DetourPushNoManager<11>),
    reinterpret_cast<void*>(&DetourPushNoManager<12>),
    reinterpret_cast<void*>(&DetourPushNoManager<13>),
    reinterpret_cast<void*>(&DetourPushNoManager<14>),
    reinterpret_cast<void*>(&DetourPushNoManager<15>),
};

void* WithManagerDetourTable[kMaxPushHooks] = {
    reinterpret_cast<void*>(&DetourPushWithManager<0>),
    reinterpret_cast<void*>(&DetourPushWithManager<1>),
    reinterpret_cast<void*>(&DetourPushWithManager<2>),
    reinterpret_cast<void*>(&DetourPushWithManager<3>),
    reinterpret_cast<void*>(&DetourPushWithManager<4>),
    reinterpret_cast<void*>(&DetourPushWithManager<5>),
    reinterpret_cast<void*>(&DetourPushWithManager<6>),
    reinterpret_cast<void*>(&DetourPushWithManager<7>),
    reinterpret_cast<void*>(&DetourPushWithManager<8>),
    reinterpret_cast<void*>(&DetourPushWithManager<9>),
    reinterpret_cast<void*>(&DetourPushWithManager<10>),
    reinterpret_cast<void*>(&DetourPushWithManager<11>),
    reinterpret_cast<void*>(&DetourPushWithManager<12>),
    reinterpret_cast<void*>(&DetourPushWithManager<13>),
    reinterpret_cast<void*>(&DetourPushWithManager<14>),
    reinterpret_cast<void*>(&DetourPushWithManager<15>),
};

int FindOrAllocNoManagerSlot(void* target) {
    for (int i = 0; i < kMaxPushHooks; ++i) {
        if (g_noManagerSlots[i].used && g_noManagerSlots[i].target == target) return i;
    }
    for (int i = 0; i < kMaxPushHooks; ++i) {
        if (!g_noManagerSlots[i].used) {
            g_noManagerSlots[i].used = true;
            g_noManagerSlots[i].target = target;
            return i;
        }
    }
    return -1;
}

int FindOrAllocWithManagerSlot(void* target) {
    for (int i = 0; i < kMaxPushHooks; ++i) {
        if (g_withManagerSlots[i].used && g_withManagerSlots[i].target == target) return i;
    }
    for (int i = 0; i < kMaxPushHooks; ++i) {
        if (!g_withManagerSlots[i].used) {
            g_withManagerSlots[i].used = true;
            g_withManagerSlots[i].target = target;
            return i;
        }
    }
    return -1;
}

}  // namespace

static bool RecoverStalePushHookLocked(void* target, MH_STATUS status) {
    if (status != MH_ERROR_ALREADY_CREATED) return false;
    const auto it = g_hookRecords.find(target);
    if (it == g_hookRecords.end() ||
        it->second.kind != HookKind::PushMethods ||
        !it->second.owner.empty() ||
        it->second.gameCoreGeneration >= ImageAddress::GameCoreGeneration() ||
        g_activeSharedDetours.load(std::memory_order_acquire) != 0) {
        return false;
    }
    return SafeRemoveHookLocked(target);
}

void* InstallPushMethodsNoManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                  const std::wstring& owner) {
    if (!target || methods.empty() || owner.empty() || std::any_of(methods.begin(), methods.end(),
            [&owner](const StoredLuaMethod& method) {
                return method.owner != owner;
            })) {
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    lock_guard<mutex> stateLock(g_pushStateMutex);
    const int slot = FindOrAllocNoManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsNoManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_noManagerSlots[slot];
    auto merged = state.methods;
    if (!MergeLuaMethods(merged, methods)) {
        if (!state.base) state = NoManagerHookSlot{};
        return nullptr;
    }
    if (state.base) {
        // 相同方法重复安装/重放不会重复注入；整批验证成功后才发布。
        state.methods.swap(merged);
        return reinterpret_cast<void*>(state.base);
    }

    // 新槽：先建钩启用，全部成功后才登记方法；任一步失败完整回滚槽位与
    // MinHook 记录——否则半初始化槽位会让重试重复追加方法或返回失效 trampoline。
    MH_STATUS status = MH_CreateHook(target, NoManagerDetourTable[slot], reinterpret_cast<void**>(&state.base));
    if (RecoverStalePushHookLocked(target, status)) {
        status = MH_CreateHook(target, NoManagerDetourTable[slot],
                               reinterpret_cast<void**>(&state.base));
    }
    if (status != MH_OK) {
        Logger::Log("InstallPushMethodsNoManager: create hook failed %s", MH_StatusToString(status));
        state = NoManagerHookSlot{};
        return nullptr;
    }
    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallPushMethodsNoManager: enable hook failed %s", MH_StatusToString(status));
        MH_RemoveHook(target);
        state = NoManagerHookSlot{};
        return nullptr;
    }
    g_hookRecords[target] = HookRecord{
        L"", HookKind::PushMethods, ImageAddress::GameCoreGeneration()
    };
    state.methods.swap(merged);
    return reinterpret_cast<void*>(state.base);
}

void* InstallPushMethodsWithManager(void* target, const std::vector<StoredLuaMethod>& methods,
                                    const std::wstring& owner) {
    if (!target || methods.empty() || owner.empty() || std::any_of(methods.begin(), methods.end(),
            [&owner](const StoredLuaMethod& method) {
                return method.owner != owner;
            })) {
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    lock_guard<mutex> stateLock(g_pushStateMutex);
    const int slot = FindOrAllocWithManagerSlot(target);
    if (slot < 0) {
        Logger::Log("InstallPushMethodsWithManager: no free hook slot");
        return nullptr;
    }

    auto& state = g_withManagerSlots[slot];
    auto merged = state.methods;
    if (!MergeLuaMethods(merged, methods)) {
        if (!state.base) state = WithManagerHookSlot{};
        return nullptr;
    }
    if (state.base) {
        state.methods.swap(merged);
        return reinterpret_cast<void*>(state.base);
    }

    MH_STATUS status = MH_CreateHook(target, WithManagerDetourTable[slot], reinterpret_cast<void**>(&state.base));
    if (RecoverStalePushHookLocked(target, status)) {
        status = MH_CreateHook(target, WithManagerDetourTable[slot],
                               reinterpret_cast<void**>(&state.base));
    }
    if (status != MH_OK) {
        Logger::Log("InstallPushMethodsWithManager: create hook failed %s", MH_StatusToString(status));
        state = WithManagerHookSlot{};
        return nullptr;
    }
    if ((status = MH_EnableHook(target)) != MH_OK) {
        Logger::Log("InstallPushMethodsWithManager: enable hook failed %s", MH_StatusToString(status));
        MH_RemoveHook(target);
        state = WithManagerHookSlot{};
        return nullptr;
    }
    g_hookRecords[target] = HookRecord{
        L"", HookKind::PushMethods, ImageAddress::GameCoreGeneration()
    };
    state.methods.swap(merged);
    return reinterpret_cast<void*>(state.base);
}

static void ReinstallPushRegistrations() {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    if (!g_gameCorePhaseReady) return;
    size_t installed = 0;
    for (const auto& registration : g_pushRegistrations) {
        const auto plugin = std::find_if(g_plugins.begin(), g_plugins.end(),
            [&registration](const PluginEntry& entry) {
                return entry.ownerId == registration.owner &&
                    (entry.state == PluginState::Loading || entry.state == PluginState::Active);
            });
        if (plugin == g_plugins.end()) continue;
        const std::string& symbolName = registration.symbolName;
        void* target = ResolveCurrentGameCoreByName(symbolName.c_str());
        if (!target) {
            Logger::Log("ReinstallPushRegistrations: missing %s",
                        symbolName.c_str());
            continue;
        }
        void* base = registration.signature == PushMethodSigType::NoManager
            ? InstallPushMethodsNoManager(target, registration.methods,
                                          registration.owner)
            : InstallPushMethodsWithManager(target, registration.methods,
                                            registration.owner);
        if (base) {
            ++installed;
        } else {
            Logger::Log("ReinstallPushRegistrations: install failed, registration retained: %s owner=%ls",
                symbolName.c_str(), registration.owner.c_str());
        }
    }
    Logger::Log("ReinstallPushRegistrations: installed=%zu registered=%zu",
                installed, g_pushRegistrations.size());
}


// hks 导入缺失时的统一降级：安全默认值 + 限次日志（脚本可能高频调用，不能每次刷日志）。
// 导入缺失在 InitHavokScript 已整体告警并停用 GameCore 插件加载；此处是纵深防御
// （阶段 A 已加载的 Global 插件仍可能在调用这些包装）。
static void WarnHksImportMissing(const char* name) {
    static std::atomic<int> s_warned{ 0 };
    if (s_warned.fetch_add(1, std::memory_order_relaxed) < 10) {
        Logger::Log("HookAPI lua wrapper unavailable (HavokScript import missing): %s", name);
    }
}

static bool ValidateLuaState(void* L, const char* apiName) {
    if (L) return true;
    Logger::Log("%s rejected: lua_State is null", apiName ? apiName : "Lua API");
    return false;
}

static bool ValidateLuaCString(const char* value, const char* apiName) {
    if (value) return true;
    Logger::Log("%s rejected: string argument is null", apiName ? apiName : "Lua API");
    return false;
}

// 有返回值包装：状态指针无效/导入缺失 → 日志 + fallback。
#define HKS_GUARD_RET(fnPtr, fallback, L, ...) \
    do { \
        if (!ValidateLuaState((L), #fnPtr)) return (fallback); \
        if (!(fnPtr)) { WarnHksImportMissing(#fnPtr); return (fallback); } \
        return (fnPtr)(reinterpret_cast<hks::lua_State*>(L), __VA_ARGS__); \
    } while (0)

// void 包装：状态指针无效/导入缺失 → 日志 + 直接返回。
#define HKS_GUARD_VOID(fnPtr, L, ...) \
    do { \
        if (!ValidateLuaState((L), #fnPtr)) return; \
        if (!(fnPtr)) { WarnHksImportMissing(#fnPtr); return; } \
        return (fnPtr)(reinterpret_cast<hks::lua_State*>(L), __VA_ARGS__); \
    } while (0)

#define HKS_GUARD_RET0(fnPtr, fallback, L) \
    do { \
        if (!ValidateLuaState((L), #fnPtr)) return (fallback); \
        if (!(fnPtr)) { WarnHksImportMissing(#fnPtr); return (fallback); } \
        return (fnPtr)(reinterpret_cast<hks::lua_State*>(L)); \
    } while (0)

void LuaPushNamedCClosureImpl(void* L, void* func, int a, const char* name, int b) {
    if (!func || !ValidateLuaCString(name, "LuaPushNamedCClosure") || a < 0 || b < 0) return;
    HKS_GUARD_VOID(hks::pushnamedcclosure, L,
        reinterpret_cast<hks::luaFunc>(func), a, name, b);
}

int LuaCheckIntegerImpl(void* L, int index) {
    HKS_GUARD_RET(hks::checkinteger, 0, L, index);
}

double LuaCheckNumberImpl(void* L, int index) {
    HKS_GUARD_RET(hks::checknumber, 0.0, L, index);
}

void LuaPushNilImpl(void* L) {
    HKS_GUARD_VOID(hks::pushnil, reinterpret_cast<hks::lua_State*>(L));
}

void LuaSetFieldImpl(void* L, int stackOffset, const char* name) {
    if (!ValidateLuaCString(name, "LuaSetField")) return;
    HKS_GUARD_VOID(hks::setfield, L, stackOffset, name);
}

int LuaGetTopImpl(void* L) {
    HKS_GUARD_RET0(hks::gettop, 0, L);
}

int LuaDoStringImpl(void* L, const char* str) {
    if (!ValidateLuaCString(str, "LuaDoString")) return 0;
    HKS_GUARD_RET(hks::dostring, 0, L, str);
}

int LuaToBooleanImpl(void* L, int index) {
    HKS_GUARD_RET(hks::toboolean, 0, L, index);
}

void LuaPushNumberImpl(void* L, double num) {
    HKS_GUARD_VOID(hks::pushnumber, L, num);
}

void LuaPushIntegerImpl(void* L, int num) {
    // G12: 语义对齐——API 承诺压整数，用 hksi_lua_pushinteger 压整数标记值
    // （此前走 pushnumber 是历史遗留，hks 开启 IntLiterals 时两者字节码可区分）。
    HKS_GUARD_VOID(hks::pushinteger, L, num);
}

static bool FormatLuaString(char* buffer, size_t capacity, const char* format, va_list args,
                            const char* apiName) {
    if (!ValidateLuaCString(format, apiName)) return false;
    const int result = _vsnprintf_s(buffer, capacity, _TRUNCATE, format, args);
    if (result < 0) {
        Logger::Log("%s rejected: invalid or oversized format result", apiName);
        return false;
    }
    return true;
}

void LuaErrorImpl(void* L, char const* str, ...) {
    if (!ValidateLuaState(L, "LuaError") || !hks::error) {
        if (!hks::error) WarnHksImportMissing("hks::error");
        return;
    }
    char buffer[1024];
    va_list args;
    va_start(args, str);
    const bool formatted = FormatLuaString(buffer, sizeof(buffer), str, args, "LuaError");
    va_end(args);
    if (!formatted) return;
    hks::error(reinterpret_cast<hks::lua_State*>(L), "%s", buffer);
}

char const* LuaPushFStringImpl(void* L, char const* str, ...) {
    if (!ValidateLuaState(L, "LuaPushFString") || !hks::pushfstring) {
        if (!hks::pushfstring) WarnHksImportMissing("hks::pushfstring");
        return nullptr;
    }
    char buffer[1024];
    va_list args;
    va_start(args, str);
    const bool formatted = FormatLuaString(buffer, sizeof(buffer), str, args, "LuaPushFString");
    va_end(args);
    if (!formatted) return nullptr;
    return hks::pushfstring(reinterpret_cast<hks::lua_State*>(L), "%s", buffer);
}

char const* LuaCheckLStringImpl(void* L, int index, unsigned __int64* a) {
    if (!a) return nullptr;
    HKS_GUARD_RET(hks::checklstring, nullptr, L, index, a);
}

void* LuaToUserDataImpl(void* L, int index) {
    HKS_GUARD_RET(hks::touserdata, nullptr, L, index);
}

void LuaGetFieldImpl(void* L, int a, char const* b) {
    if (!ValidateLuaCString(b, "LuaGetField")) return;
    HKS_GUARD_VOID(hks::getfield, L, a, b);
}

void LuaPopImpl(void* L, int a) {
    if (a < 0) return;
    HKS_GUARD_VOID(hks::pop, L, a);
}

void LuaCreateTableImpl(void* L, int a, int b) {
    if (a < 0 || b < 0) return;
    HKS_GUARD_VOID(hks::createtable, L, a, b);
}

void* LuaToCFunctionImpl(void* L, int index) {
    if (!ValidateLuaState(L, "LuaToCFunction")) return nullptr;
    if (!hks::tocfunction) {
        WarnHksImportMissing("hks::tocfunction");
        return nullptr;
    }
    return reinterpret_cast<void*>(hks::tocfunction(reinterpret_cast<hks::lua_State*>(L), index));
}

void LuaCheckTableImpl(void* L, int index) {
    HKS_GUARD_VOID(hks::checktable, L, index);
}

unsigned long long LuaObjLenImpl(void* L, int index) {
    HKS_GUARD_RET(hks::objlen, 0, L, index);
}

void LuaGetTableImpl(void* L, int index) {
    HKS_GUARD_VOID(hks::gettable, L, index);
}

int LuaCPcallImpl(void* L, LuaMethodFunc callback, void* userdata) {
    if (!L || !callback) {
        return kHookApiLuaCallInvalidArgument;
    }
    HKS_GUARD_RET(hks::cpcall, kHookApiLuaCallUnavailable,
        L,
        reinterpret_cast<hks::luaFunc>(callback), userdata);
}

int LuaRefImpl(void* L, int index) {
    HKS_GUARD_RET(hks::ref, 0, L, index);
}

int LuaPcallImpl(void* L, int a, int b, int c) {
    if (a < 0 || b < -1) return 0;
    HKS_GUARD_RET(hks::pcall, 0, L, a, b, c);
}

void LuaPushValueImpl(void* L, int value) {
    HKS_GUARD_VOID(hks::pushvalue, L, value);
}

void LuaRawGetIImpl(void* L, int a, int b) {
    HKS_GUARD_VOID(hks::rawgeti, L, a, b);
}

void LuaUnrefImpl(void* L, int a, int b) {
    HKS_GUARD_VOID(hks::unref, L, a, b);
}

void LuaSetTableImpl(void* L, int t) {
    HKS_GUARD_VOID(hks::settable, L, t);
}

int LuaIsNumberImpl(void* L, int num) {
    HKS_GUARD_RET(hks::isnumber, 0, L, num);
}

double LuaToNumberImpl(void* L, int num) {
    HKS_GUARD_RET(hks::tonumber, 0.0, L, num);
}

int LuaIsUserDataImpl(void* L, int num) {
    HKS_GUARD_RET(hks::isuserdata, 0, L, num);
}

int LuaOpenDebugImpl(void* L) {
    HKS_GUARD_RET0(hks::luaopen_debug, 0, L);
}

int LuaToIntegerImpl(void* L, int num) {
    HKS_GUARD_RET(hks::tointeger, 0, L, num);
}

int LuaTypeImpl(void* L, int num) {
    HKS_GUARD_RET(hks::type, 0, L, num);
}

int LuaOptIntegerImpl(void* L, int a, int b) {
    HKS_GUARD_RET(hks::optinteger, b, L, a, b);
}

int LuaSetHookImpl(void* L, void* a, int b, int c) {
    if (c < 0) return 0;
    HKS_GUARD_RET(hks::sethook, 0, L, a, b, c);
}

void* LuaGetHookImpl(void* L) {
    HKS_GUARD_RET0(hks::gethook, nullptr, L);
}

int LuaGetHookMaskImpl(void* L) {
    HKS_GUARD_RET0(hks::gethookmask, 0, L);
}

int LuaGetHookCountImpl(void* L) {
    HKS_GUARD_RET0(hks::gethookcount, 0, L);
}

int LuaCheckPlayerIdImpl(void* L, int index) {
    if (!ValidateLuaState(L, "LuaCheckPlayerId")) return -1;
    return hks::checkplayerid(reinterpret_cast<hks::lua_State*>(L), index);
}

void LuaPushBooleanImpl(void* L, bool value) {
    if (!ValidateLuaState(L, "LuaPushBoolean")) return;
    hks::pushboolean(reinterpret_cast<hks::lua_State*>(L), value);
}

void LuaPushLightUserDataImpl(void* L, void* ptr) {
    if (!ValidateLuaState(L, "LuaPushLightUserData")) return;
    hks::pushlightuserdata(reinterpret_cast<hks::lua_State*>(L), ptr);
}

void* LocalizationLookupImpl(void* outStr, const char* key) {
    if (!outStr || !key || !Localization::LookupPtr) {
        Logger::Log("LocalizationLookup: invalid args or LookupPtr not ready");
        return nullptr;
    }
    auto* result = reinterpret_cast<Localization::String*>(outStr);
    auto* ans = Localization::LookupPtr(result, key);
    if (!ans) {
        Logger::Log("LocalizationLookup: failed for key=%s", key);
    }
    return reinterpret_cast<void*>(ans);
}

// ---------------- HookAPI v2 ----------------

void LogImpl(const char* format, ...) {
    if (!format) return;
    char buffer[2048];
    va_list args;
    va_start(args, format);
    _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    Logger::Log("%s", buffer);
}

void LuaPushCFunctionFieldImpl(void* L, int tableIndex, const char* fieldName, void* fn, const char* internalName) {
    if (!ValidateLuaState(L, "LuaPushCFunctionField") ||
        !ValidateLuaCString(fieldName, "LuaPushCFunctionField") || !fn) return;
    if (!hks::pushnamedcclosure || !hks::setfield) {
        WarnHksImportMissing("hks::pushnamedcclosure/setfield");
        return;
    }
    const char* iname = internalName && *internalName ? internalName : fieldName;
    auto* state = reinterpret_cast<hks::lua_State*>(L);
    // pushnamedcclosure grows the stack by 1; relative negative indices must be
    // adjusted so they still refer to the table (e.g. -1 -> -2), matching
    // Example2's explicit LuaSetField(L, -2, ...).
    // 伪索引（hks 全局表 LUA_GLOBAL=-10002 等，<= -10000）不随栈增长漂移，透传。
    const bool isPseudoIndex = (tableIndex <= -10000);
    const int idx = (tableIndex < 0 && !isPseudoIndex) ? (tableIndex - 1) : tableIndex;
    hks::pushnamedcclosure(state, reinterpret_cast<hks::luaFunc>(fn), 0, iname, 0);
    hks::setfield(state, idx, fieldName);
}

void LuaNewGlobalTableImpl(void* L, const char* globalName, int narr, int nrec) {
    if (!ValidateLuaState(L, "LuaNewGlobalTable") ||
        !ValidateLuaCString(globalName, "LuaNewGlobalTable") || narr < 0 || nrec < 0) return;
    if (!hks::createtable || !hks::setfield || !hks::getfield) {
        WarnHksImportMissing("hks::createtable/setfield/getfield");
        return;
    }
    auto* state = reinterpret_cast<hks::lua_State*>(L);
    hks::createtable(state, narr, nrec);
    hks::setfield(state, hks::LUA_GLOBAL, globalName);
    hks::getfield(state, hks::LUA_GLOBAL, globalName);
}

uint32_t LocStringBytesImpl(void) {
    return CIV6_HOOK_API_LOC_STRING_BYTES;
}

void* LocCreateImpl(void) {
    void* mem = calloc(1, CIV6_HOOK_API_LOC_STRING_BYTES);
    return mem;
}

void LocDestroyImpl(void* loc) {
    if (!loc) return;
    if (Localization::DestructorPtr) {
        Localization::DestructorPtr(reinterpret_cast<Localization::String*>(loc));
    }
    free(loc);
}

void* LocLookupImpl(void* loc, const char* key) {
    if (!loc || !key || !Localization::LookupPtr) {
        Logger::Log("LocLookup: invalid args or LookupPtr not ready");
        return nullptr;
    }
    return Localization::LookupPtr(reinterpret_cast<Localization::String*>(loc), key);
}

int LocPushArgumentImpl(void* loc, const char* arg) {
    if (!loc || !arg || !Localization::PushArgumentPtr) return 0;
    return Localization::PushArgumentPtr(reinterpret_cast<Localization::String*>(loc), arg) ? 1 : 0;
}

const char* LocToUtf8Impl(void* loc) {
    if (!loc || !Localization::ToUTF8Ptr) return nullptr;
    return Localization::ToUTF8Ptr(reinterpret_cast<Localization::String*>(loc));
}

using EditPlayerFn = void*(__fastcall*)(int playerId);
using GetCivDescFn = const char*(__fastcall*)(void* player);
using MakeHashFn = uint32_t(__fastcall*)(const char* str);

static EditPlayerFn ResolveEditPlayer() {
    return reinterpret_cast<EditPlayerFn>(
        ResolveCurrentGameCoreByName("GameCore::Context::Globals::EditPlayer"));
}
static GetCivDescFn ResolveGetCivDesc() {
    return reinterpret_cast<GetCivDescFn>(
        ResolveCurrentGameCoreByName("GameCore::Player::Instance::GetCivilizationDescription"));
}
static MakeHashFn ResolveMakeHash() {
    return reinterpret_cast<MakeHashFn>(
        ResolveCurrentGameCoreByName("GameCore::Utilities::MakeHash"));
}

void* EditPlayerImpl(int playerId) {
    auto fn = ResolveEditPlayer();
    if (!fn) {
        Logger::Log("EditPlayer: symbol missing");
        return nullptr;
    }
    // 对局开始前（Ready 回调时机）ms_pkCurrentGame 尚未初始化，引擎 EditPlayer 会
    // 解引用 null 而 AV——SEH 兜底返回 nullptr（对局前调用本就没有意义，属调用方时序错误）。
    __try {
        return fn(playerId);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("EditPlayer: engine call failed (game not started?)");
        return nullptr;
    }
}

const char* GetCivilizationDescriptionImpl(void* player) {
    if (!player) return nullptr;
    auto fn = ResolveGetCivDesc();
    if (!fn) {
        Logger::Log("GetCivilizationDescription: symbol missing");
        return nullptr;
    }
    __try {
        return fn(player);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("GetCivilizationDescription: engine call failed");
        return nullptr;
    }
}

uint32_t MakeHashImpl(const char* str) {
    auto fn = ResolveMakeHash();
    if (!fn || !str) return 0;
    return fn(str);
}

int RegisterPushMethodsTargetImpl(const char* name, int sigType, const char* pushMethodsSymbol) {
    if (!name || !*name) return 0;
    if (sigType != kHookApiPushNoManager && sigType != kHookApiPushWithManager) {
        Logger::Log("RegisterPushMethodsTarget: bad sigType %d for %s", sigType, name);
        return 0;
    }
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    auto owner = RequirePluginOwner(reinterpret_cast<const void*>(name),
                                    "RegisterPushMethodsTarget");
    if (!owner) return 0;

    PushTargetConfig config{
        sigType == kHookApiPushWithManager
        ? PushMethodSigType::WithManager
        : PushMethodSigType::NoManager,
        pushMethodsSymbol && *pushMethodsSymbol
        ? pushMethodsSymbol
        : (std::string(name) + "::PushMethods")
    };

    auto& ownerConfigs = g_pluginPushTargetConfigs[*owner];
    const auto existing = ownerConfigs.find(name);
    if (existing != ownerConfigs.end()) {
        if (existing->second.signature != config.signature ||
                existing->second.symbolName != config.symbolName) {
            Logger::Log("RegisterPushMethodsTarget: conflicting redefinition owner=%ls target=%s",
                owner->c_str(), name);
            return 0;
        }
        return 1;
    }
    const bool hasRegistration = std::any_of(g_pushRegistrations.begin(),
        g_pushRegistrations.end(), [&owner, name](const PushRegistration& registration) {
            return registration.owner == *owner && registration.targetName == name;
        });
    if (hasRegistration) {
        Logger::Log("RegisterPushMethodsTarget: cannot change config after registration owner=%ls target=%s",
            owner->c_str(), name);
        return 0;
    }
    ownerConfigs.emplace(name, config);
    Logger::Log("RegisterPushMethodsTarget: owner=%ls target=%s sig=%d sym=%s",
        owner->c_str(), name, sigType, config.symbolName.c_str());
    return 1;
}

// ---------------- Patch/Unpatch (v2) ----------------

#pragma intrinsic(_ReturnAddress)

__declspec(noinline) static bool HookPatch(void* target, const void* bytes, size_t len) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    if (TargetInTearingDownGameCore(target)) return false;
    auto owner = RequirePluginOwner(_ReturnAddress(), "Patch");
    return owner && PatchRegistry::Apply(target, bytes, len, owner->c_str());
}

__declspec(noinline) static bool HookUnpatch(void* target) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    auto owner = RequirePluginOwner(_ReturnAddress(), "Unpatch");
    return owner && PatchRegistry::RevertOwned(target, owner->c_str());
}

static HookAPI g_hookApi = {
    CIV6_HOOK_API_VERSION,
    static_cast<uint32_t>(sizeof(HookAPI)),

    &InstallHookImpl,
    &BroadcastMessageImpl,
    &RegisterMessageHandlerImpl,
    &SendMessageToImpl,

    &IsImageLoadedImpl,
    &GetImageInfoImpl,
    &ResolveByRvaImpl,
    &ResolveByNameImpl,
    &ResolveByRvaExImpl,
    &ResolveByPatternImpl,
    &RegisterGlobalCaptureImpl,
    &ResolveByVTableImpl,

    &PushLuaMethodsImpl,

    &RegisterScriptGlobalsImpl,
    &RegisterScriptGlobalsForUIImpl,

    &LuaPushNamedCClosureImpl,
    &LuaCheckIntegerImpl,
    &LuaCheckNumberImpl,
    &LuaSetFieldImpl,
    &LuaGetTopImpl,
    &LuaDoStringImpl,
    &LuaToBooleanImpl,
    &LuaPushNumberImpl,
    &LuaPushIntegerImpl,
    &LuaErrorImpl,
    &LuaPushFStringImpl,
    &LuaCheckLStringImpl,
    &LuaToUserDataImpl,
    &LuaGetFieldImpl,
    &LuaPopImpl,
    &LuaCreateTableImpl,
    &LuaToCFunctionImpl,
    &LuaCheckTableImpl,
    &LuaObjLenImpl,
    &LuaGetTableImpl,
    &LuaCPcallImpl,
    &LuaRefImpl,
    &LuaPcallImpl,
    &LuaPushValueImpl,
    &LuaRawGetIImpl,
    &LuaUnrefImpl,
    &LuaSetTableImpl,
    &LuaIsNumberImpl,
    &LuaToNumberImpl,
    &LuaIsUserDataImpl,
    &LuaOpenDebugImpl,
    &LuaToIntegerImpl,
    &LuaTypeImpl,
    &LuaOptIntegerImpl,
    &LuaSetHookImpl,
    &LuaGetHookImpl,
    &LuaGetHookMaskImpl,
    &LuaGetHookCountImpl,
    &LuaCheckPlayerIdImpl,
    &LuaPushBooleanImpl,
    &LuaPushLightUserDataImpl,

    &LogImpl,
    &LuaPushCFunctionFieldImpl,
    &LuaNewGlobalTableImpl,

    &LocalizationLookupImpl,

    &LocStringBytesImpl,
    &LocCreateImpl,
    &LocDestroyImpl,
    &LocLookupImpl,
    &LocPushArgumentImpl,
    &LocToUtf8Impl,

    &EditPlayerImpl,
    &GetCivilizationDescriptionImpl,
    &MakeHashImpl,

    &RegisterPushMethodsTargetImpl,

    &HookPatch,
    &HookUnpatch,

    &RegisterGameCoreReadyImpl,
    &RegisterGameCoreTeardownImpl,

    &RegisterGameEventImpl,
    &TriggerGameEventImpl,

    &GetEngineUtilityImpl,
    &GetActiveLuaStateImpl,
    &LuaPushNilImpl,
};

// loader 内部复用 common/HookAPI.h 的 HookInfo 取址工具时的入口（LoaderHooks/UiInject 用）。
HookAPI* LoaderCore::RuntimeHookApi() {
    return &g_hookApi;
}

// exe 版本锚（SizeOfImage + FileHeader.TimeDateStamp）：无符号库时判断"能否直接信任原始 RVA"。
// 由 tools/gen_exe_aobs.py 的同一份逆向数据得出；游戏更新后这里会失配 -> 只走 AOB 兜底。
namespace {
constexpr uint32_t kAnchorDx11SizeOfImage = 0x36D1000;
constexpr uint32_t kAnchorDx11TimeDate   = 0x667C6FC6;
constexpr uint32_t kAnchorDx12SizeOfImage = 0xFE22000;
constexpr uint32_t kAnchorDx12TimeDate   = 0x667C7363;
}

static bool ExeMatchesAnchor(HookImageId image) {
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(image, &info) || !info.base || !info.imageSize) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(info.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(info.base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const uint32_t sizeOfImage = nt->OptionalHeader.SizeOfImage;
    const uint32_t timeDate = nt->FileHeader.TimeDateStamp;
    if (image == kHookImageExeDx11) {
        return sizeOfImage == kAnchorDx11SizeOfImage && timeDate == kAnchorDx11TimeDate;
    }
    if (image == kHookImageExeDx12) {
        return sizeOfImage == kAnchorDx12SizeOfImage && timeDate == kAnchorDx12TimeDate;
    }
    return false;
}

void* LoaderCore::ResolveExeTarget(const HookInfoExe& info, size_t span) {
    const HookImageId image = HookCurrentExeImage(&g_hookApi);
    if (image == kHookImageInvalid) return nullptr;
    const HookInfo& entry = (image == kHookImageExeDx12) ? info.dx12 : info.dx11;
    const bool haveContext = PdataMatch::HasContext(image);
    if (haveContext || ExeMatchesAnchor(image)) {
        if (void* p = ResolveByHookInfo(&g_hookApi, image, entry, span)) return p;
        Logger::Log("ResolveExeTarget: image=%u kind=%d unresolved (rva=0x%llX aob=%s)",
            static_cast<unsigned>(image), static_cast<int>(entry.kind),
            static_cast<unsigned long long>(entry.kind == kHookInfoRva ? entry.u.rva : 0),
            entry.aob ? "yes" : "no");
        return nullptr;
    }
    Logger::Log("ResolveExeTarget: [WARN] image=%u no symbol DB and PE identity != anchor; "
                "RVA path skipped, AOB fallback only", static_cast<unsigned>(image));
    if (entry.aob && *entry.aob) {
        return g_hookApi.ResolveByPattern(image, entry.aob, kSectionText);
    }
    return nullptr;
}

typedef void (*OnLoadFunc)(HookAPI*);
typedef void (*OnUnloadFunc)();
typedef void (*OnMessageFunc)(const char*, const void*, size_t);

static DWORD GetModuleSizeOfImage(HMODULE module) {
    if (!module) return 0;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

bool AttachGameCore(HMODULE gameCore) {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    const DWORD sizeOfImage = GetModuleSizeOfImage(gameCore);
    const HookImageId image = ImageAddress::IdentifyGameCore(gameCore);
    if (sizeOfImage == 0 || image == kHookImageInvalid) {
        Logger::Log("GameCore rejected: invalid or unknown PE image");
        return false;
    }
    // XP2：先建 pdata 矫正表（sidecar 由 RuntimeEntry InitEarly 装载）。失败 = 无法矫正，
    // 拒绝注入（GameCore 本身照常运行）。
    if (PdataMatch::HasContext(image) && !PdataMatch::BuildNewTable(image, gameCore)) {
        Logger::Log("GameCore rejected: pdata table build failed");
        return false;
    }

    if (!ImageAddress::AttachGameCore(gameCore)) {
        Logger::Log("GameCore rejected: ImageAddress attach failed");
        return false;
    }
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(image, &info)) {
        ImageAddress::DetachGameCore();
        return false;
    }

    Logger::Log("GameCore attached image=%u base=0x%llX SizeOfImage=0x%08X generation=%llu",
        static_cast<unsigned>(image),
        static_cast<unsigned long long>(info.base), sizeOfImage,
        static_cast<unsigned long long>(info.generation));
    return true;
}

static bool CallOnLoadSafe(OnLoadFunc onLoad, const char* name) {
    __try {
        onLoad(&g_hookApi);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("OnLoad crashed in plugin %s code=0x%08X", name, GetExceptionCode());
        return false;
    }
}

static void CallOnUnloadSafe(OnUnloadFunc onUnload, const char* name) {
    __try {
        onUnload();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("OnUnload crashed in plugin %s code=0x%08X", name ? name : "?", GetExceptionCode());
    }
}

// v2 统一插件加载流程：LoadLibraryExW + OnLoad(SEH) + OnMessage 自动注册 + 记录跟踪项。
// nameNarrow = 显示名（通常为文件名，内部取 stem 作 Patch owner / OnMessage 名）；已加载（同句柄）返回 false。
static bool LoadPluginDllInternal(const std::wstring& wpath, const std::string& nameNarrow,
    LoaderCore::PluginCategory category) {
    lock_guard<std::recursive_mutex> transitionLock(g_gameCoreTransitionMutex);
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);

    // G5: 已驻留模块（禁用后未卸载）用 UNCHANGED_REFCOUNT 取回，"禁用→启用"循环
    // 不再累计引用计数；未映射才真正加载。ownsRef 标记引用是否归本调用所有，
    // 失败路径只释放自己拿到的引用（GetModuleHandleEx 取回的引用不属于我们）。
    bool ownsRef = false;
    HMODULE hPlugin = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            wpath.c_str(), &hPlugin)) {
        hPlugin = LoadLibraryExW(wpath.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        ownsRef = (hPlugin != nullptr);
    }
    if (!hPlugin) {
        Logger::Log("LoadPlugin failed: %s err=%lu", ModScan::WideToNarrow(wpath).c_str(), GetLastError());
        return false;
    }

    for (const auto& entry : g_plugins) {
        if (entry.handle == hPlugin) {
            if (ownsRef) FreeLibrary(hPlugin);
            return false;
        }
    }

    auto onLoad = (OnLoadFunc)GetProcAddress(hPlugin, "OnLoad");
    if (!onLoad) {
        Logger::Log("Plugin has no OnLoad export: %s", ModScan::WideToNarrow(wpath).c_str());
        if (ownsRef) FreeLibrary(hPlugin);
        return false;
    }

    const std::string narrow = ModScan::WideToNarrow(wpath);
    std::string pluginFileName = nameNarrow;
    if (pluginFileName.empty()) {
        const size_t slash = narrow.find_last_of("\\/");
        pluginFileName = slash == std::string::npos ? narrow : narrow.substr(slash + 1);
    }

    // stem 只用于消息寻址；ownerId 使用规范化完整路径，避免不同 Mod 的同名 DLL
    // 在卸载/隔离时互相清理。
    std::wstring pluginStem;
    {
        std::string stemName = pluginFileName;
        const size_t dot = stemName.find_last_of('.');
        if (dot != std::string::npos) stemName = stemName.substr(0, dot);
        pluginStem = ModScan::NarrowToWide(stemName);
    }
    Logger::Log("Loaded plugin %s (%s)", pluginFileName.c_str(), narrow.c_str());

    PluginEntry entry;
    entry.handle = hPlugin;
    entry.path = wpath;
    entry.name = pluginStem;
    entry.ownerId = NormalizePluginPath(wpath);
    entry.category = category;
    entry.state = PluginState::Loading;
    const std::wstring ownerId = entry.ownerId;
    g_plugins.push_back(std::move(entry));

    // OnLoad 期间暴露"当前插件名"给 Patch 作 owner；SEH 由 CallOnLoadSafe 包裹，
    // 无论 OnLoad 正常返回还是崩溃，都要在返回后清空，防止污染后续插件。
    SetActivePluginContext(ownerId, hPlugin);
    lifecycleLock.unlock();
    const bool onLoadOk = CallOnLoadSafe(onLoad, pluginFileName.c_str());
    ClearActivePluginContext();
    lifecycleLock.lock();

    const auto trackedAfterLoad = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&ownerId](const PluginEntry& tracked) {
            return tracked.ownerId == ownerId;
        });
    const bool alreadyQuarantined =
        trackedAfterLoad != g_plugins.end() &&
        trackedAfterLoad->state == PluginState::Quarantined;

    if (!onLoadOk) {
        // 崩溃隔离（G2）：仅驻留模块不够——按 owner 回滚全部注册并标记隔离，
        // 防止半初始化状态持续生效、以及阶段 B 全量扫描反复重试崩溃的 OnLoad。
        Logger::Log("Plugin quarantined after OnLoad failure: %s", narrow.c_str());
        lifecycleLock.unlock();
        if (!alreadyQuarantined) QuarantinePluginByOwner(ownerId);
        return false;
    }
    if (alreadyQuarantined || trackedAfterLoad == g_plugins.end()) {
        return false;
    }

    auto onMessage = (OnMessageFunc)GetProcAddress(hPlugin, "OnMessage");
    lifecycleLock.unlock();
    if (onMessage) {
        const bool registered = RegisterPluginMessageHandler(ownerId, onMessage);
        Logger::Log("OnMessage auto-registration %s for %s",
            registered ? "succeeded" : "rejected", pluginFileName.c_str());
    }
    lifecycleLock.lock();
    const auto activate = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&ownerId](const PluginEntry& tracked) {
            return tracked.ownerId == ownerId;
        });
    if (activate == g_plugins.end() || activate->state != PluginState::Loading) {
        lifecycleLock.unlock();
        g_bus.UnregisterOwner(ownerId);
        return false;
    }
    activate->state = PluginState::Active;
    return true;
}

void LoadPluginDLL(const char* name, const string& path) {
    const std::wstring wpath = ModScan::NarrowToWide(path);
    LoadPluginDllInternal(wpath, name ? name : "", CategoryForPath(wpath));
}

void OnLoaderMessage(const char* topic, const void* data, size_t len) {
    Logger::Log("OnLoaderMessage %s", topic ? topic : "");
    if (topic && data && strcmp(topic, "load-plugin") == 0 && len > 0) {
        string path((const char*)data, len);
        LoadPluginDLL(nullptr, path);
    }
}

bool InitializeLoader(HMODULE hModule) {
    // v1 时代还记录模块句柄供 GetCurrentModuleDir 使用；该路径已随 v1 死代码清理
    // 删除，现在只注册 "Loader" 消息处理器（load-plugin 遗留入口，保持兼容）。
    (void)hModule;
    static std::once_flag registerLoaderHandler;
    std::call_once(registerLoaderHandler, [] {
        g_bus.RegisterHandler("Loader", OnLoaderMessage);
    });
    return true;
}

// ================= LoaderCore 实现（S3c：插件生命周期 v2） =================

// 撤销某插件通过 HookAPI.InstallHook 注册的全部 MinHook 钩子（Disable + Remove）。
// 在卸载插件的 FreeLibrary 之前调用；owner 为插件 stem（空串代表 Loader 自身，不在此撤销）。
static void RemovePluginHooks(const wchar_t* owner) {
    if (!owner || !*owner) return;
    lock_guard<mutex> lock(Runtime::MinHookMutex());
    for (auto it = g_hookRecords.begin(); it != g_hookRecords.end(); ) {
        if (it->second.owner == owner) {
            void* target = it->first;
            if (SafeRemoveHookLocked(target, false)) {
                it = g_hookRecords.erase(it);
                Logger::Log("RemovePluginHooks: removed hook at %p (owner=%ls)",
                            target, owner);
            } else {
                Logger::Log("RemovePluginHooks: retained failed hook record at %p (owner=%ls)",
                            target, owner);
                ++it;
            }
        } else {
            ++it;
        }
    }
}

// 撤销某插件注册的全部回调类条目（禁用/隔离时调用）：脚本全局、PushMethods
// 方法/登记、GameCore 生命周期回调。这些条目都持有指向插件映像的函数指针，
// 不清就会在对应 detour / 触发点里调进已释放内存（与 OnMessage 悬空 handler
// 同类问题）。槽位的 methods 清空后保留已装 hook（detour 只透传 base）。
static void RemovePluginOwnedRegistrations(const std::wstring& owner) {
    if (owner.empty()) return;
    lock_guard<std::recursive_mutex> lock(g_pluginLifecycleMutex);

    auto removeOwnedBy = [&owner](auto& vec) {
        size_t removed = 0;
        for (auto it = vec.begin(); it != vec.end(); ) {
            if (it->owner == owner) {
                it = vec.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        return removed;
    };

    size_t globals = 0;
    size_t globalsUi = 0;
    {
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        globals = removeOwnedBy(g_scriptGlobals);
        globalsUi = removeOwnedBy(g_scriptGlobalsUI);
    }

    size_t methods = 0;
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (auto& slot : g_noManagerSlots) {
            if (slot.used) methods += removeOwnedBy(slot.methods);
        }
        for (auto& slot : g_withManagerSlots) {
            if (slot.used) methods += removeOwnedBy(slot.methods);
        }
    }

    const size_t registrationsBefore = g_pushRegistrations.size();
    g_pushRegistrations.erase(
        std::remove_if(g_pushRegistrations.begin(), g_pushRegistrations.end(),
            [&owner](const PushRegistration& registration) {
                return registration.owner == owner;
            }),
        g_pushRegistrations.end());
    const size_t registrationsRemoved =
        registrationsBefore - g_pushRegistrations.size();

    const size_t targetConfigsRemoved = g_pluginPushTargetConfigs.erase(owner);

    // GameEvent 槽位：清空该 owner 注册的事件表（name/luaPushFn/ownerId）。
    // Quarantine/Unload 都经本函数，无需在各自路径重复接线。
    CleanupGameEventsForOwner(owner);

    Logger::Log("RemovePluginOwnedRegistrations: owner=%ls globals=%zu globalsUI=%zu luaMethods=%zu registrations=%zu targetConfigs=%zu",
        owner.c_str(), globals, globalsUi, methods, registrationsRemoved, targetConfigsRemoved);
}

// 崩溃隔离（与 OnLoad 崩溃同构）：标记隔离 + 回滚该 owner 的全部注册
// （补丁/MinHook 钩/Lua 方法/生命周期回调/OnMessage）。模块驻留不卸；
// 隔离后 reconcile 与阶段 B 全量扫描都不再重试。
static void QuarantinePluginByOwner(const std::wstring& ownerId) {
    if (ownerId.empty()) return;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (auto& entry : g_plugins) {
            if (entry.ownerId == ownerId) {
                entry.state = PluginState::Quarantined;
                break;
            }
        }
    }
    // 先禁用并排空所有外部入口；等待期间不得持 lifecycle 锁。
    RemoveGameCoreCallbacksFor(ownerId);
    g_bus.UnregisterOwner(ownerId);
    WaitForPluginCallbacks(ownerId);
    PatchRegistry::RevertAllFor(ownerId.c_str());
    RemovePluginHooks(ownerId.c_str());
    // 隔离路径也必须撤销参数捕获站点；否则站点仍会向插件的 out 槽写入数据。
    CleanupCaptureSitesForOwner(ownerId);
    RemovePluginOwnedRegistrations(ownerId);
    Logger::Log("Plugin quarantined by owner: %ls", ownerId.c_str());
}

// 按跟踪项卸载单个插件（调用方保证 index 有效）：
// OnUnload → PatchRegistry::RevertAllFor(name) → RemovePluginHooks(name) → FreeLibrary，语义与 S2a 接线一致。
static void UnloadPluginByOwnerId(const std::wstring& ownerId) {
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    const auto initial = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&ownerId](const PluginEntry& entry) {
            return entry.ownerId == ownerId;
        });
    if (initial == g_plugins.end()) return;
    const size_t index = static_cast<size_t>(initial - g_plugins.begin());
    if (g_plugins[index].state != PluginState::Active) {
        Logger::Log("UnloadPluginEntryAt: quarantined plugin remains parked: %s",
                    ModScan::WideToNarrow(g_plugins[index].path).c_str());
        return;
    }

    g_plugins[index].state = PluginState::Deactivating;
    PluginEntry entry = g_plugins[index];

    // 先阻止并排空消息回调，避免 OnUnload 释放插件状态时旧快照仍在执行。
    // 等待时必须释放 lifecycle 锁，否则 handler 若正在调用 HookAPI 会锁反转。
    lifecycleLock.unlock();
    RemoveGameCoreCallbacksFor(entry.ownerId);
    g_bus.UnregisterOwner(entry.ownerId);
    // 脚本全局/GameEvent 入口使用快照并在锁外执行；先排空 owner 的在途调用，
    // 再进入 OnUnload，避免插件状态被释放后旧回调继续访问。
    WaitForPluginCallbacks(entry.ownerId);
    auto onUnload = (OnUnloadFunc)GetProcAddress(entry.handle, "OnUnload");
    SetActivePluginContext(entry.ownerId, entry.handle);
    if (onUnload) CallOnUnloadSafe(onUnload, nullptr);
    // 先 OnUnload 后回滚补丁：插件 OnUnload 可能仍依赖自己的补丁。
    // 必须在 FreeLibrary 之前回滚——补丁目标可能位于该插件自身映像内。
    PatchRegistry::RevertAllFor(entry.ownerId.c_str());
    // 撤销该插件的 MinHook 钩子：否则 GameCore 重载后重新 OnLoad 会撞 MH_ERROR_ALREADY_CREATED。
    RemovePluginHooks(entry.ownerId.c_str());
    // 撤销该插件的参数捕获订阅；其它 owner 仍在使用的共享站点继续工作。
    CleanupCaptureSitesForOwner(entry.ownerId);
    // 撤销该插件注册的回调类条目（见 RemovePluginOwnedRegistrations）。
    RemovePluginOwnedRegistrations(entry.ownerId);
    ClearActivePluginContext();
    lifecycleLock.lock();
    const auto tracked = std::find_if(g_plugins.begin(), g_plugins.end(),
        [&entry](const PluginEntry& candidate) {
            return candidate.handle == entry.handle &&
                   candidate.ownerId == entry.ownerId;
        });
    if (tracked != g_plugins.end()) g_plugins.erase(tracked);
    // 不 FreeLibrary：游戏线程可能仍在该插件的 detour/回调内执行（MH_DisableHook
    // 不等待所有类型的在飞调用），此刻卸下映像会把正在执行的代码变成 UAF。
    // 改为驻留模块（hook 框架的标准做法）：映像保持映射
    // 但休眠——钩已摘、补丁已回滚、Lua 方法/回调/OnMessage 已注销，不会再被调用。
    // 代价是该插件重启用时静态状态跨周期保留，OnLoad 必须可重入（重新注册其
    // 钩子/回调）；这与全新加载路径对插件的要求一致。
    Logger::Log("Plugin deactivated, module parked (kept mapped): %s",
        ModScan::WideToNarrow(entry.path).c_str());
}

static const char* CategoryNameForLog(LoaderCore::PluginCategory cat) {
    return cat == LoaderCore::PluginCategory::GameCore ? "GameCore" : "Global";
}

void LoaderCore::LoadPluginsOf(PluginCategory cat) {
    const HMODULE anchor = LoaderCore::RuntimeModuleHandle();
    // 扫描（文件系统/sqlite）在锁外做，避免长时间阻塞卸载/reconcile 路径；
    // 单个插件的加载由 LoadSinglePlugin 在锁内原子完成。
    const auto wpaths = (cat == PluginCategory::GameCore)
        ? ModScan::FindGameCorePluginCandidates(anchor)
        : ModScan::FindGlobalPluginCandidates(anchor);
    Logger::Log("LoadPluginsOf(%s): %zu candidate(s)", CategoryNameForLog(cat), wpaths.size());
    for (const auto& wpath : wpaths) {
        LoadSinglePlugin(wpath);
    }
}

void LoaderCore::UnloadPluginsOf(PluginCategory cat) {
    std::vector<std::wstring> owners;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (const auto& entry : g_plugins) {
            if (entry.category == cat && entry.state == PluginState::Active) {
                owners.push_back(entry.ownerId);
            }
        }
    }
    for (const auto& owner : owners) {
        UnloadPluginByOwnerId(owner);
    }
    size_t remaining = 0;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        remaining = g_plugins.size();
    }
    Logger::Log("UnloadPluginsOf(%s): unloaded=%zu remaining=%zu",
        CategoryNameForLog(cat), owners.size(), remaining);
}

bool LoaderCore::LoadSinglePlugin(const std::wstring& path) {
    if (path.empty()) return false;
    const std::wstring norm = NormalizePluginPath(path);
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (const auto& entry : g_plugins) {
            if (NormalizePluginPath(entry.path) == norm) {
                Logger::Log("LoadSinglePlugin: already loaded %s", ModScan::WideToNarrow(path).c_str());
                return false;
            }
        }
    }
    const std::wstring filename = fs::path(path).filename().wstring();
    return LoadPluginDllInternal(path, ModScan::WideToNarrow(filename), CategoryForPath(path));
}

void LoaderCore::UnloadSinglePlugin(const std::wstring& path) {
    const std::wstring norm = NormalizePluginPath(path);
    std::wstring ownerId;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (const auto& entry : g_plugins) {
            if (NormalizePluginPath(entry.path) != norm) continue;
            if (entry.state != PluginState::Active) {
                Logger::Log("UnloadSinglePlugin: inactive plugin remains parked: %s",
                            ModScan::WideToNarrow(path).c_str());
                return;
            }
            ownerId = entry.ownerId;
            break;
        }
    }
    if (!ownerId.empty()) {
        UnloadPluginByOwnerId(ownerId);
        Logger::Log("UnloadSinglePlugin: %s", ModScan::WideToNarrow(path).c_str());
    }
    // 未加载：no-op
}

bool LoaderCore::InitializeGameCorePhase() {
    lock_guard<std::recursive_mutex> transitionLock(g_gameCoreTransitionMutex);
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    HMODULE gm = GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll");
    if (!gm) {
        Logger::Log("InitializeGameCorePhase: GameCore_XP2_FinalRelease.dll not loaded");
        return false;
    }
    if (!AttachGameCore(gm)) {
        Logger::Log("InitializeGameCorePhase: AttachGameCore failed");
        return false;
    }
    // v2 无薄壳：以当前进程 exe 模块作扫描锚。
    if (!InitializeLoader(GetModuleHandleW(nullptr))) {
        Logger::Log("InitializeGameCorePhase: InitializeLoader failed");
        ImageAddress::DetachGameCore();
        return false;
    }
    // HavokScript 导入缺失 = Lua API 半可用，对插件是崩溃源：停用 GameCore 插件
    // 加载（本会话游戏本体照常运行）。
    if (!hks::InitHavokScript()) {
        Logger::Log("InitializeGameCorePhase: InitHavokScript incomplete; GameCore plugins disabled");
        ImageAddress::DetachGameCore();
        return false;
    }
    Localization::InitScript();
    g_gameCorePhaseReady = true;
    // GameCore 重载后重装共享脚本钩（ResetForReload 已摘除；回调列表跨重载保留）。
    // 首次进入时若 Global 插件已在阶段 A 注册过脚本全局，也在此一并装钩。
    EnsureScriptHooksInstalled();
    ReinstallPushRegistrations();
    // Global 插件的 Ready 回调：此刻新映像已 attach、符号可解析——插件在此
    // InstallHook/Patch/做一次性初始化；先于 GameCore 插件加载，保证顺序确定。
    const auto readySnapshot = SnapshotGameCoreCallbacks(g_gameCoreReadyCallbacks);
    lifecycleLock.unlock();
    FireGameCoreCallbackSnapshot(readySnapshot, "GameCoreReady");
    Logger::Log("InitializeGameCorePhase: OK");
    return true;
}

void LoaderCore::ReconcileGlobalPlugins() {
    // 扫描（文件系统/sqlite）在锁外；下方对 g_plugins 的 diff 与加载/卸载整体持锁，
    // 与游戏线程的 LoadPluginsOf（LoadDLL detour 内）串行化。
    const auto expected = ModScan::FindGlobalPluginCandidates(LoaderCore::RuntimeModuleHandle());

    std::unordered_set<std::wstring> expectedNorm;
    expectedNorm.reserve(expected.size());
    for (const auto& wpath : expected) {
        expectedNorm.insert(NormalizePluginPath(wpath));
    }

    // 先卸载"当前有而期望无"的 Global 插件。
    std::vector<std::wstring> toUnload;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        for (const auto& entry : g_plugins) {
            if (entry.category != PluginCategory::Global) continue;
            if (expectedNorm.count(NormalizePluginPath(entry.path))) continue;
            toUnload.push_back(entry.path);
        }
    }
    for (const auto& wpath : toUnload) {
        UnloadSinglePlugin(wpath);
    }

    // 再加载"期望有而当前无"的 Global 插件。
    std::unordered_set<std::wstring> currentNorm;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        currentNorm.reserve(g_plugins.size());
        for (const auto& entry : g_plugins) {
            if (entry.category == PluginCategory::Global) {
                currentNorm.insert(NormalizePluginPath(entry.path));
            }
        }
    }
    size_t loaded = 0;
    for (const auto& wpath : expected) {
        if (currentNorm.count(NormalizePluginPath(wpath))) continue;
        if (LoadSinglePlugin(wpath)) ++loaded;
    }

    size_t tracked = 0;
    {
        lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
        tracked = g_plugins.size();
    }
    Logger::Log("ReconcileGlobalPlugins: unloaded=%zu loaded=%zu tracked=%zu",
        toUnload.size(), loaded, tracked);
}

bool LoaderCore::IsInitialized() {
    lock_guard<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    return g_gameCorePhaseReady;
}

// GameCore 重载时的共享钩子复位（G1）：RegisterScriptData/ForUI 共享钩与全部
// PushMethods 槽位钩的目标都在旧 GameCore 映像内——映像卸载后补丁字节随映射消失，
// 而 MinHook 记录、g_scriptHookInstalled 标志、trampoline 指针全部残留：
//  - 若不复位：重进游戏后 detour 不再被调用（新映像是未打补丁的原始字节），
//    且 g_scriptHookInstalled=true 让重注册早退 → Lua 注入本会话永久失效；
//  - PushMethods 槽位还会按重载次数泄漏（上限 16 个）。
// 在 UnloadDllDetour 路径调用时旧映像仍存活，可干净摘钩；在 LoadDllDetour 重入
// 兜底路径调用时映像可能已卸载，SafeRemoveHook 自动跳过（残留记录由
// InstallSharedHook 的 ALREADY_CREATED 恢复路径处理）。
// 已注册的 ScriptGlobals 回调列表跨重载保留（Global 插件仍加载着），
// 由 EnsureScriptHooksInstalled 在新 GameCore attach 后重新装钩。
static void ResetSharedGameCoreHooks(
        unique_lock<std::recursive_mutex>& lifecycleLock) {
    std::vector<void*> pushTargets;
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (int i = 0; i < kMaxPushHooks; ++i) {
            if (g_noManagerSlots[i].used) {
                pushTargets.push_back(g_noManagerSlots[i].target);
            }
            if (g_withManagerSlots[i].used) {
                pushTargets.push_back(g_withManagerSlots[i].target);
            }
        }
    }

    {
        lock_guard<mutex> hookLock(Runtime::MinHookMutex());
        if (g_scriptHookTarget) MH_DisableHook(g_scriptHookTarget);
        if (g_scriptUIHookTarget) MH_DisableHook(g_scriptUIHookTarget);
        for (void* target : pushTargets) {
            if (target) MH_DisableHook(target);
        }
    }

    // 禁止新的 GameCore API 解析后释放生命周期锁，让已经进入 detour 的插件回调
    // 能正常调用 HookAPI 并退出；不能在持 lifecycle/hook 锁时等待。
    HookImageInfo current{ sizeof(HookImageInfo) };
    const HookImageId currentId = ImageAddress::LoadedGameCore();
    if (ImageAddress::GetInfo(currentId, &current)) {
        g_gameCoreTeardownAddress = current.base;
        g_gameCoreTeardownSizeOfImage = static_cast<uint32_t>(current.imageSize);
    }
    ImageAddress::DetachGameCore();
    lifecycleLock.unlock();
    {
        unique_lock<mutex> drainLock(g_detourDrainMutex);
        g_detourDrainCv.wait(drainLock, [] {
            return g_activeSharedDetours.load(std::memory_order_acquire) == 0;
        });
    }
    lifecycleLock.lock();

    {
        lock_guard<mutex> hookLock(Runtime::MinHookMutex());
        if (g_scriptHookTarget) SafeRemoveHookLocked(g_scriptHookTarget);
        if (g_scriptUIHookTarget) SafeRemoveHookLocked(g_scriptUIHookTarget);
        for (void* target : pushTargets) {
            if (target) SafeRemoveHookLocked(target);
        }
    }

    g_scriptHookTarget = nullptr;
    g_scriptUIHookTarget = nullptr;
    g_scriptHookInstalled = false;
    g_scriptUIHookInstalled = false;
    g_origRegisterScriptData = nullptr;
    g_origRegisterScriptDataForUI = nullptr;
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (int i = 0; i < kMaxPushHooks; ++i) {
            g_noManagerSlots[i] = NoManagerHookSlot{};
            g_withManagerSlots[i] = WithManagerHookSlot{};
        }
    }
    g_gameCoreTeardownAddress = 0;
    g_gameCoreTeardownSizeOfImage = 0;
    Logger::Log("ResetSharedGameCoreHooks: script/UI hooks + push slots reset");
}

// 按代际撤销所有 GameCore 域的插件钩（调用方持生命周期锁）。
// Global 插件在对局中经 Ready 回调装的 GameCore 域钩无人摘：同基址重载可靠
// recoverStalePlugin 自愈（前提插件重装），异基址重载则旧记录指向未映射内存
// 永远无法回收——统一在旧映像卸载前按 generation 清掉。exe 域钩
// （generation == 0）不受影响。
static void DisableGameCoreGenerationHooks(uint64_t generation) {
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    size_t disabled = 0;
    for (const auto& [target, record] : g_hookRecords) {
        if (record.gameCoreGeneration == generation &&
                record.kind == HookKind::Plugin &&
                !record.owner.empty()) {
            const MH_STATUS status = MH_DisableHook(target);
            if (status == MH_OK || status == MH_ERROR_DISABLED) {
                ++disabled;
            } else {
                Logger::Log("DisableGameCoreGenerationHooks: target=%p status=%s",
                    target, MH_StatusToString(status));
            }
        }
    }
    Logger::Log("DisableGameCoreGenerationHooks: disabled=%zu", disabled);
}

static void RemoveGameCoreGenerationHooks(uint64_t generation) {
    lock_guard<mutex> hookLock(Runtime::MinHookMutex());
    size_t removed = 0;
    for (auto it = g_hookRecords.begin(); it != g_hookRecords.end(); ) {
        const HookRecord& record = it->second;
        const bool gameCoreDomainPluginHook =
            record.gameCoreGeneration == generation &&
            record.kind == HookKind::Plugin &&
            !record.owner.empty();
        if (gameCoreDomainPluginHook) {
            void* target = it->first;
            if (SafeRemoveHookLocked(target, false)) {
                it = g_hookRecords.erase(it);
                ++removed;
            } else {
                // 摘除失败（兜底路径映像已卸载等）：保留记录，待地址复用时由
                // recoverStalePlugin 路径或下次 teardown 处理。
                ++it;
            }
        } else {
            ++it;
        }
    }
    Logger::Log("RemoveGameCoreGenerationHooks: removed=%zu remainingRecords=%zu",
        removed, g_hookRecords.size());
}

void LoaderCore::ResetForReload() {
    lock_guard<std::recursive_mutex> transitionLock(g_gameCoreTransitionMutex);
    unique_lock<std::recursive_mutex> lifecycleLock(g_pluginLifecycleMutex);
    g_gameCorePhaseReady = false;
    // 先进入 teardown 窗口（InstallHook/Patch 对旧映像的目标从此被拒绝），
    // ImageAddress 暂不 detach——teardown 回调内仍可解析符号读数据收尾。
    HookImageInfo current{ sizeof(HookImageInfo) };
    const HookImageId currentId = ImageAddress::LoadedGameCore();
    if (ImageAddress::GetInfo(currentId, &current)) {
        g_gameCoreTeardownAddress = current.base;
        g_gameCoreTeardownSizeOfImage = static_cast<uint32_t>(current.imageSize);
    } else {
        g_gameCoreTeardownAddress = 0;
        g_gameCoreTeardownSizeOfImage = 0;
    }
    const uint64_t teardownGeneration = ImageAddress::GameCoreGeneration();
    lifecycleLock.unlock();

    // phaseReady 已关闭，不会再有新的 Ready 准入；先等已准入回调结束，
    // 防止其与 Teardown/卸载交错。
    WaitForGameCoreCallbacks(g_gameCoreReadyCallbacks);

    // 先关闭该代插件钩入口，再运行 Teardown。回调返回即表示插件已排空自己
    // 的在途 detour；此后才会释放 original trampoline。
    DisableGameCoreGenerationHooks(teardownGeneration);

    // Global 插件收尾回调：置于 GameCore 插件卸载之前（它们可能依赖后者仍在
    // 钩上维护的数据）；旧映像此刻仍存活。
    FireGameCoreCallbacks(g_gameCoreTeardownCallbacks, "GameCoreTeardown");

    // capture 站点的 providerFunction 位于旧 GameCore 映像内，重载后地址失效，
    // 必须随重载清掉全部站点。此刻旧映像仍存活（尚未 detach），MH_RemoveHook
    // 能干净摘除；等下次 Ready 回调由插件重新注册。
    CleanupAllCaptureSites();

    // UnloadPluginsOf 自身不触碰初始化标志，天然无递归。
    UnloadPluginsOf(PluginCategory::GameCore);

    lifecycleLock.lock();
    // 旧映像区间的补丁清账：GameCore 插件的补丁已随其卸载按 owner 回滚，
    // 这里收尾 Global 插件打在旧映像上的补丁（映像卸载前回滚字节，记录随之丢弃）。
    if (g_gameCoreTeardownAddress) {
        PatchRegistry::RevertAllInRange(
            g_gameCoreTeardownAddress, g_gameCoreTeardownSizeOfImage);
    }
    // 共享钩子（ScriptData/ForUI + PushMethods 槽位）目标在旧 GameCore 映像内，
    // 必须随重载复位，否则 Lua 注入在新映像下永久失效（见函数头注释）。
    ResetSharedGameCoreHooks(lifecycleLock);
    // 按代际清掉剩余的 GameCore 域插件钩（Global 插件的钩 + 各类漏网）。
    RemoveGameCoreGenerationHooks(teardownGeneration);
    // GameCore 重载后 Global 插件注册的 GameEvent 槽位跨代保留：Register/Trigger 与
    // Lua 路径内化（GameEventInvokeLua）每次实时取活跃 state / scriptSystem（见
    // GetActiveLuaStateImpl），无需在此重挂任何信号环。
    Logger::Log("ResetForReload: teardown callbacks fired, GameCore plugins unloaded, shared hooks reset, generation hooks cleared");
}
