// LoaderHooks.cpp — Civ6DllLoader v2 游戏内 hook 安装。
//
// 安装 2 个 MinHook detour（编排见 docs/ARCHITECTURE.md §2.2）：
//   - GameCore::LoadDLL            （阶段 B：接管 GameCore 加载）
//   - GameCore::UnloadDLL          （阶段 B 收尾：卸 GameCore 前先卸插件）
// Global 插件仅启动时加载一次；主菜单开关 Mod 需重启才生效（不再挂 lEnableMod/lDisableMod 钩）。
// 一切失败仅日志 + 静默降级；安装按事务处理，任一步失败都会回滚本次已装 hook。
//
// exe 域取址：双版本 HookInfoExe（DX11 / DX12 各自的 RVA + 唯一 AOB），运行时按当前 exe
// 自动选取；RVA 走 pdata 矫正，AOB 作兜底（common/HookAPI.h 的 ResolveByHookInfoExe）。
// 数据槽（hModule）用 ResolveDataByAob 从 RIP 相对指令解出，不写数据地址。
// 入口特征码仍由本文件持有，作为"地址正确性"的硬门。

#include "pch.h"

#include "LoaderHooks.h"
#include "LoaderCore.h"
#include "ImageAddress.h"
#include "Runtime.h"
#include "ConfigIni.h"
#include "../common/Logger.h"
#include "../common/ModScan.h"
#include "MinHook.h"

#include <cwchar>
#include <wchar.h>
#include <string>
#include <cstring>
#include <vector>

namespace {

// ---- exe 域取址表（双版本）----
// 生成命令：python tools/symdb.py aob --emit-cpp（重建符号库/游戏更新后重新生成）。
// 说明：RVA 是各变体构建下的坐标（运行时会先走 pdata 矫正）；AOB 是该变体里唯一命中的兜底定位串。

// ---- 本块由 tools/symdb.py aob --emit-cpp 生成；重建符号库/游戏更新后重新生成 ----

constexpr char kAob_LoadDLL[] = "48 81 EC 48 02 00 00 48 83 3D ?? ?? ?? ?? 00 74 ?? 32 C0 48 81 C4 48 02 00 00 C3 48 8D 44 24 2C 48 89 AC 24 58 02 00 00 48 89 44 24 20 48 8D 54 24 2C 0F B7 05 ?? ?? ?? ?? 33 ED 41 B8 04 01 00";
constexpr char kAob_UnloadDLL_Dx11[] = "48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 74 ?? 48 89 5C 24 20 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? FF D0 48 8B 0D ?? ?? ?? ?? 33 DB 48 89 1D 4E D2";
constexpr char kAob_UnloadDLL_Dx12[] = "48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 74 ?? 48 89 5C 24 20 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? FF D0 48 8B 0D ?? ?? ?? ?? 33 DB 48 89 1D 8E 45";
constexpr char kAob_GetConfiguration[] = "48 83 EC 38 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 ?? E8 ?? ?? ?? ?? 8B D0 C7 44 24 28 00 00 00 00 41 B9 F4 07 00 00 C7 44 24 20 13 00 00 00 4C 8D 05 ?? ?? ?? ?? B9 08 13 00 00 E8 ?? ?? ?? ?? 48 85";

constexpr HookInfoExe kExeLoadDLL = { HookRva(0xF8510, kAob_LoadDLL), HookRva(0xF8850, kAob_LoadDLL) };
constexpr HookInfoExe kExeUnloadDLL = { HookRva(0xF8E30, kAob_UnloadDLL_Dx11), HookRva(0xF9170, kAob_UnloadDLL_Dx12) };
constexpr HookInfoExe kExeGetConfiguration = { HookRva(0x100390, kAob_GetConfiguration), HookRva(0x100CE0, kAob_GetConfiguration) };
// GetRuleSet：函数体（56 字节）内有 5 处机器码完全相同的兄弟函数（差异只在被通配的 disp32 上），
// 无法用内容唯一区分 -> 用 HookInfo.index 选升序命中表里的第 2 个（两版 exe 都是第 2 个）。
constexpr char kAob_GetRuleSet[] = "48 83 EC 28 48 8B 89 88 00 00 00 8B 15 ?? ?? ?? ?? 48 8B 01 FF 50 68 8B 48 14 C1 E9 1D F6 C1 01 74 ?? 66 83 38 05 75 ?? 48 8B 40 08 48 83 C4 28 C3 33 C0 48 83 C4 28 C3";
constexpr HookInfoExe kExeGetRuleSet = { HookRva(0x100F40, kAob_GetRuleSet, 2), HookRva(0x101890, kAob_GetRuleSet, 2) };

// 数据槽：| 分指令段，xx = disp32，用 ResolveDataByAob 解出全局地址
constexpr char kAob_hModule[] = "48 81 EC 48 02 00 00 | 48 83 3D xx xx xx xx 00 | 74 0A 32 C0 48 81 C4 48 02 00 00";

// 入口特征码（定义在后面；GetRuleSetName 先用到）
bool CheckGetConfigurationSignature(uintptr_t addr);
bool CheckGetRuleSetSignature(uintptr_t addr);

// 当前进程 exe 的镜像 id（未识别 = kHookImageInvalid）。
HookImageId ExeImage() {
    return LoaderCore::CurrentExeImage();
}

// ---- hook 目标函数签名（MinHook 与调用约定无关，x64 下 __fastcall 即默认约定）----
typedef char(__fastcall* LoadDllFn)(wchar_t* Path);       // GameCore::LoadDLL(wchar_t*)
typedef char(__fastcall* UnloadDllFn)();                  // GameCore::UnloadDLL()

// ---- 匿名命名空间状态 ----
LoadDllFn g_origLoadDLL = nullptr;
UnloadDllFn g_origUnloadDLL = nullptr;
HMODULE* g_engineModuleSlot = nullptr; // 在入口改写前解析，exe 生命周期内地址稳定
bool g_unloadIncomplete = false;      // 引擎尚未完成上一次卸载，不重启插件
wchar_t g_officialPath[260] = {};  // Loader 自有缓冲：官方 GameCore 绝对路径（不改调用者栈缓冲）

static bool ReadEngineModule(HMODULE& module) {
    module = nullptr;
    __try {
        if (!g_engineModuleSlot) return false;
        module = *g_engineModuleSlot;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 进程 exe 所在目录（去文件名段）。失败返回空串。
std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    std::wstring path(buf, n);
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return {};
    }
    path.resize(slash);
    return path;
}

// 官方 GameCore 绝对路径 = 游戏根（exe 目录上溯三级：Win64Steam→Binaries→Base→游戏根）
// + 传入的相对路径（rel 形如 DLC\Expansion2\Binaries\Win64\GameCore_XP2_FinalRelease.dll）。
// 写入自有静态缓冲 g_officialPath；目标文件不存在 → 返回 false（调用方透传原路径）。
bool BuildOfficialPath(const wchar_t* rel) {
    if (!rel) {
        return false;
    }
    std::wstring dir = GetExeDir();
    if (dir.empty()) {
        return false;
    }
    for (int i = 0; i < 3; ++i) {  // 去掉最后三个路径段（Win64Steam、Binaries、Base）
        const size_t slash = dir.find_last_of(L"\\/");
        if (slash == std::wstring::npos) {
            return false;
        }
        dir.resize(slash);
    }
    if (dir.size() + wcslen(rel) + 1 >= 260) {
        return false;
    }
    wcscpy_s(g_officialPath, 260, dir.c_str());
    wcscat_s(g_officialPath, 260, L"\\");
    wcscat_s(g_officialPath, 260, rel);
    return GetFileAttributesW(g_officialPath) != INVALID_FILE_ATTRIBUTES;
}

// ---- 规则集获取（权威来源，不猜路径）----
// GetRuleSet 返回当前规则集名字符串：0=还没进游戏；否则 "RULESET_STANDARD" /
// "RULESET_EXPANSION_1" / "RULESET_EXPANSION_2"（来自配置库 Rulesets 表）。
// SEH 兜底：配置单例的内部字段（GetRuleSet 读 +0x88）由后续配置库装载阶段填充，
// 装载前调用会解引用空指针——这里兜住并返回 nullptr（调用方按“未进游戏”透传）。
__declspec(noinline) const char* GetRuleSetName() {
    const uintptr_t cfgAddr = reinterpret_cast<uintptr_t>(
        LoaderCore::ResolveExeTarget(kExeGetConfiguration, 1));
    const uintptr_t rsAddr = reinterpret_cast<uintptr_t>(
        LoaderCore::ResolveExeTarget(kExeGetRuleSet, 1));
    if (!cfgAddr || !rsAddr ||
        !CheckGetConfigurationSignature(cfgAddr) || !CheckGetRuleSetSignature(rsAddr)) {
        return nullptr;
    }
    auto GetConfiguration = reinterpret_cast<void* (*)()>(cfgAddr);
    auto GetRuleSet = reinterpret_cast<const char* (__fastcall*)(void*)>(rsAddr);
    __try {
        void* cfg = GetConfiguration();
        if (!cfg) {
            return nullptr;
        }
        return GetRuleSet(cfg);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("GetRuleSetName: exception code=0x%08X (config not ready?), passthrough",
            GetExceptionCode());
        return nullptr;
    }
}

// 规则集名 → 官方 GameCore DLL 相对路径（相对游戏根 = exe 目录上溯三级）。
// 返回 nullptr = 未知（透传原路径兜底）。
// 本项目只支持 XP2：LoadDllDetour 已对非 EXPANSION_2 早退，所以这里只可能拿到 XP2 规则集。
const wchar_t* OfficialGameCoreRelPath(const char* ruleset) {
    if (ruleset && strstr(ruleset, "EXPANSION_2")) {
        return L"DLC\\Expansion2\\Binaries\\Win64\\GameCore_XP2_FinalRelease.dll";
    }
    return nullptr;
}

// ---- 特征码校验 ----
// 特征码读取前的统一前置检查：[addr, addr+span) 必须完整落在 exe 镜像内，
// 否则游戏更新导致 RVA 错位时，裸读入口字节本身就是访问违例。
bool SignatureSpanReadable(uintptr_t addr, size_t span) {
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(ExeImage(), &info)) return false;
    const uintptr_t base = info.base;
    const uintptr_t imageSize = info.imageSize;
    if (!addr || !base || !imageSize) {
        return false;
    }
    return addr >= base && addr - base + span <= imageSize;
}

// LoadDLL 入口：48 81 EC 48 02 00 00 | 48 83 3D | ?? ?? ?? ?? | 00 74 0A 32 C0
// （sub rsp,248h / cmp cs:hModule,0（4 字节 RIP 相对位移通配）/ imm 0 / jz +0Ah / xor al,al）
bool CheckLoadDllSignature(uintptr_t addr) {
    if (!SignatureSpanReadable(addr, 19)) {
        return false;
    }
    const unsigned char* p = reinterpret_cast<const unsigned char*>(addr);
    // 与通配位置一一对应的固定字节（顺序即为地址偏移 0..6、7..9、14..18）
    static const unsigned char kFixed[15] = {
        0x48, 0x81, 0xEC, 0x48, 0x02, 0x00, 0x00,  // [0..6]  sub rsp, 248h
        0x48, 0x83, 0x3D,                          // [7..9]  cmp cs:hModule, 0
        0x00, 0x74, 0x0A, 0x32, 0xC0               // [14..18] imm0 / jz +0Ah / xor al,al
    };
    static const int kOffsets[15] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 15, 16, 17, 18 };
    for (int i = 0; i < 15; ++i) {
        if (p[kOffsets[i]] != kFixed[i]) {
            return false;
        }
    }
    return true;
}

// UnloadDLL 入口：48 83 EC 28 | 48 83 3D ?? ?? ?? ?? 00 | 74 6E | 48 89
// （sub rsp,28h / cmp cs:hModule,0（4 字节 RIP 相对位移通配）/ imm 0 / jz +6Eh / mov [rsp+..],rbx）
bool CheckUnloadDllSignature(uintptr_t addr) {
    if (!SignatureSpanReadable(addr, 16)) {
        return false;
    }
    const unsigned char* p = reinterpret_cast<const unsigned char*>(addr);
    static const unsigned char kFixed[] = {
        0x48, 0x83, 0xEC, 0x28,                          // [0..3]  sub rsp, 28h
        0x48, 0x83, 0x3D,                                // [4..6]  cmp cs:hModule, 0
        0x00, 0x74, 0x6E, 0x48, 0x89                     // [11..15] imm0 / jz +6Eh / mov [rsp+..],rbx
    };
    static const int kOffsets[] = { 0, 1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15 };
    for (size_t i = 0; i < sizeof(kOffsets) / sizeof(kOffsets[0]); ++i) {
        if (p[kOffsets[i]] != kFixed[i]) {
            return false;
        }
    }
    return true;
}

// GetConfiguration 入口：48 83 EC 38 | 48 8B 05 ?? ?? ?? ?? | 48 85 C0 75 54
bool CheckGetConfigurationSignature(uintptr_t addr) {
    if (!SignatureSpanReadable(addr, 16)) {
        return false;
    }
    const unsigned char* p = reinterpret_cast<const unsigned char*>(addr);
    static const unsigned char kFixed[12] = {
        0x48, 0x83, 0xEC, 0x38,          // [0..3] sub rsp, 38h
        0x48, 0x8B, 0x05,                // [4..6] mov rax, [rip+disp32]
        0x48, 0x85, 0xC0, 0x75, 0x54     // [11..15] test rax,rax / jnz +54h
    };
    static const int kOffsets[12] = { 0, 1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15 };
    for (int i = 0; i < 12; ++i) {
        if (p[kOffsets[i]] != kFixed[i]) {
            return false;
        }
    }
    return true;
}

// GetRuleSet 入口：48 83 EC 28 | 48 8B 89 88 00 00 00 | 8B 15 ?? ?? ?? ??
bool CheckGetRuleSetSignature(uintptr_t addr) {
    if (!SignatureSpanReadable(addr, 17)) {
        return false;
    }
    const unsigned char* p = reinterpret_cast<const unsigned char*>(addr);
    static const unsigned char kFixed[13] = {
        0x48, 0x83, 0xEC, 0x28,                                 // [0..3] sub rsp, 28h
        0x48, 0x8B, 0x89, 0x88, 0x00, 0x00, 0x00,               // [4..10] mov rcx, [rcx+88h]
        0x8B, 0x15                                              // [11..12] mov edx, [rip+disp32]
    };
    static const int kOffsets[13] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    for (int i = 0; i < 13; ++i) {
        if (p[kOffsets[i]] != kFixed[i]) {
            return false;
        }
    }
    return true;
}

// ---- LoadDLL detour（阶段 B，游戏调用线程内同步执行；可重入 = GameCore 重载循环）----
static char __fastcall LoadDllDetour(wchar_t* Path) {
    // 权威判断：GetRuleSet 返回 0 = 还没进游戏（启动早期加载 Base 等），放行透传、不做任何事。
    const char* ruleset = GetRuleSetName();
    if (!ruleset) {
        Logger::Log("LoadDLL: ruleset=null (before game), passthrough");
        return g_origLoadDLL(Path);
    }
    Logger::Log("LoadDLL: ruleset=%s", ruleset);

    // 本项目只支持 XP2（风云变幻）：base / xp1 / 其他规则集一律透传原路径，
    // 不喂官方、不初始化、不加载 Mod DLL（避免 base/xp1 规则下误加载 Mod 插件）。
    if (!strstr(ruleset, "EXPANSION_2")) {
        Logger::Log("LoadDLL: non-XP2 ruleset (%s), passthrough (XP2 only)", ruleset);
        return g_origLoadDLL(Path);
    }

    // XP2 分支。两条前置条件任一不满足就不接管，原样透传引擎给的 Path：
    //   ① ENABLE_GAMECORE=false（用户在 config.ini 显式关掉）；
    //   ② 没有任何可用的 GameCore 插件候选（本框架在该 Mod 集里没装插件）。
    // 透传的意义：不强制喂官方 DLL，把加载权交还引擎原本的路径选择，
    // 从而与不走本框架的其它 GameCore DLL Mod 兼容。
    if (!CfgIni::ReadGameCoreEnabled()) {
        Logger::Log("LoadDLL: ENABLE_GAMECORE=false, passthrough (loader plugins disabled)");
        return g_origLoadDLL(Path);
    }

    // 扫描必须发生在原函数之前（要先决定路径），结果缓存给后面的 LoadPluginsOf 复用，
    // 避免一次进对局扫两遍（找 Steam 库、查 Mods.sqlite、逐个读 PE 版本资源）。
    std::vector<std::wstring> candidates = ModScan::FindGameCorePluginCandidates();
    if (candidates.empty()) {
        Logger::Log("LoadDLL: no GameCore plugin candidate, passthrough (non-loader mods unaffected)");
        return g_origLoadDLL(Path);
    }
    Logger::Log("LoadDLL: %zu GameCore plugin candidate(s), taking over", candidates.size());

    // 喂官方 GameCore DLL 绝对路径给原 LoadDLL（引擎槽位=官方）。
    const wchar_t* rel = OfficialGameCoreRelPath(ruleset);
    wchar_t* target = Path;
    if (rel && BuildOfficialPath(rel)) {
        target = g_officialPath;  // 官方 DLL（文件存在才改写；否则透传原路径）
    }

    // 非空 hModule 会让原函数直接返回 0；保留当前插件和 Lua 闭包。
    // 清理和释放只能由配套的 UnloadDLL detour 发起，LoadDLL 返回本身不是卸载屏障。
    const char result = g_origLoadDLL(target);
    if (LoaderCore::IsInitialized() || g_unloadIncomplete) return result;
    HMODULE loaded = nullptr;
    if (!ReadEngineModule(loaded) || !loaded) {
        Logger::Log("LoadDLL: no confirmed GameCore module; plugins not loaded");
        return result;
    }
    if (LoaderCore::InitializeGameCorePhase()) {
        // 用上面那份候选列表，不重扫。
        LoaderCore::LoadPluginsOf(LoaderCore::PluginCategory::GameCore, candidates);
    } else {
        Logger::Log("InitializeGameCorePhase failed; GameCore plugins not loaded");
    }
    return result;
}

// ---- UnloadDLL detour（阶段 B 收尾：原函数卸掉 GameCore 前先做清理）----
// UnloadDLL 的调用方：LoadDLL 失败路径、退游戏、LoadGameCore 重载、RollbackContent、
// UpdateContent。在调原函数【之前】清理：此时 GameCore 映像仍活着，插件 OnUnload 能
// 摘 MinHook 钩子（RemovePluginHooks）、撤销捕获与回调类注册（补丁由插件自己在
// OnUnload 里 Unpatch，Loader 不再自动回滚，见 ARCHITECTURE §5.8）。
// 但插件模块的 FreeLibrary 【不】在这里做：gamecore 的 gameplay/ui Lua 环境是这次调用
// 里才拆掉的，而 Lua 表里可能还留着指向插件映像的闭包 -> 排到原函数返回之后再 Free
// （见 LoaderCore::FreePendingPluginModules）。
static char __fastcall UnloadDllDetour() {
    HMODULE before = nullptr;
    const bool hadModule = ReadEngineModule(before) && before != nullptr;
    if (hadModule || LoaderCore::IsInitialized()) g_unloadIncomplete = true;
    if (LoaderCore::IsInitialized()) {
        Logger::Log("UnloadDLL: resetting GameCore phase (unloading plugins before core unload)");
        LoaderCore::ResetForReload();
    }
    const char result = g_origUnloadDLL();
    HMODULE after = nullptr;
    if (hadModule && ReadEngineModule(after) && !after) {
        // 必须观察到原卸载函数把非空槽清零；空操作/失败不能释放 Lua 仍可能引用的 DLL。
        LoaderCore::ClearGameCoreTeardownWindow();
        LoaderCore::FreePendingPluginModules();
        g_unloadIncomplete = false;
    }
    return result;
}

}  // namespace

bool LoaderHooks::InstallAll() {
    std::lock_guard<std::mutex> hookLock(Runtime::MinHookMutex());
    // MinHook 初始化：Runtime::InitMinHook 已在阶段 A 调用；此处防御性再初始化一次，
    // MH_ERROR_ALREADY_INITIALIZED 视为成功。
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        Logger::Log("InstallAll: MH_Initialize failed: %s", MH_StatusToString(st));
        return false;
    }
    Logger::Log("InstallAll: MinHook ready (status=%d)", static_cast<int>(st));

    const HookImageId exeImage = ExeImage();
    if (exeImage == kHookImageInvalid) {
        Logger::Log("InstallAll: [WARN] executable not identified (DX11/DX12); exe hooks skipped");
        return false;
    }
    Logger::Log("InstallAll: exe image=%u", static_cast<unsigned>(exeImage));

    // 只记录本次 MH_CreateHook 成功的目标。失败回滚时先禁用再移除，
    // 保证后续重试不会撞上半安装的残留记录，也不会留下指向本 DLL 的 detour。
    std::vector<LPVOID> createdHooks;
    createdHooks.reserve(4);
    const auto rollback = [&](const char* failedStep) {
        for (auto it = createdHooks.rbegin(); it != createdHooks.rend(); ++it) {
            const MH_STATUS disableStatus = MH_DisableHook(*it);
            if (disableStatus != MH_OK && disableStatus != MH_ERROR_DISABLED) {
                Logger::Log("InstallAll: rollback disable failed target=%p status=%s",
                    *it, MH_StatusToString(disableStatus));
            }
            const MH_STATUS removeStatus = MH_RemoveHook(*it);
            if (removeStatus != MH_OK && removeStatus != MH_ERROR_NOT_CREATED) {
                Logger::Log("InstallAll: rollback remove failed target=%p status=%s",
                    *it, MH_StatusToString(removeStatus));
            }
        }
        Logger::Log("InstallAll: %s; rolled back %zu hook(s)", failedStep, createdHooks.size());
        return false;
    };

    // ---- LoadDLL（RVA 0xF8510 / 0xF8850，AOB 兜底）----
    const uintptr_t loadDllAddr = reinterpret_cast<uintptr_t>(
        LoaderCore::ResolveExeTarget(kExeLoadDLL, 1));
    if (!loadDllAddr || !CheckLoadDllSignature(loadDllAddr)) {
        Logger::Log("LoadDLL signature mismatch; hook skipped (addr=0x%llX, err=%lu)",
            static_cast<unsigned long long>(loadDllAddr), GetLastError());
        return rollback("LoadDLL validation failed");
    }
    const uintptr_t unloadDllAddr = reinterpret_cast<uintptr_t>(
        LoaderCore::ResolveExeTarget(kExeUnloadDLL, 1));
    if (!unloadDllAddr || !CheckUnloadDllSignature(unloadDllAddr)) {
        return rollback("UnloadDLL validation failed (required for plugin lifetime)");
    }
    // 这个 AOB 包含 LoadDLL 的入口，必须在 MH_Enable/ApplyQueued 改写它之前解析。
    g_engineModuleSlot = static_cast<HMODULE*>(
        LoaderCore::ResolveDataByAobCore(exeImage, kAob_hModule));
    if (!Runtime::IsReadableSpan(g_engineModuleSlot, sizeof(HMODULE))) {
        g_engineModuleSlot = nullptr;
        return rollback("GameCore module slot unavailable");
    }
    if ((st = MH_CreateHook((LPVOID)loadDllAddr, &LoadDllDetour, (LPVOID*)&g_origLoadDLL))
            != MH_OK) {
        Logger::Log("LoadDLL MH_CreateHook failed: %s", MH_StatusToString(st));
        return rollback("LoadDLL create failed");
    }
    createdHooks.push_back((LPVOID)loadDllAddr);
    if ((st = MH_CreateHook((LPVOID)unloadDllAddr, &UnloadDllDetour,
            (LPVOID*)&g_origUnloadDLL)) != MH_OK) {
        return rollback("UnloadDLL create failed");
    }
    createdHooks.push_back((LPVOID)unloadDllAddr);
    // 两个 original 和 hModule 槽都备好后一次启用，避免只有加载钩工作的窗口。
    if (MH_QueueEnableHook((LPVOID)loadDllAddr) != MH_OK ||
        MH_QueueEnableHook((LPVOID)unloadDllAddr) != MH_OK || MH_ApplyQueued() != MH_OK) {
        return rollback("LoadDLL/UnloadDLL enable failed");
    }
    Logger::Log("InstallAll: LoadDLL + UnloadDLL installed; module slot=%p", g_engineModuleSlot);
    return true;
}
