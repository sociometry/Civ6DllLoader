// LoaderHooks.cpp — Civ6DllLoader v2 游戏内 hook 安装（S4）。
//
// 安装 4 个 MinHook detour（详见 docs/LoadDLL_analysis.md、docs/ModToggle_analysis.md 与
// 设计文档 §3.1 阶段 B/C、§4.1 阶段 B）：
//   - GameCore::LoadDLL            （阶段 B：接管 GameCore 加载）
//   - GameCore::UnloadDLL          （阶段 B 收尾：卸 GameCore 前先卸插件）
//   - AppLuaModdingLibrary::lEnableMod  （阶段 C：主菜单开关 Mod → RequestReconcile）
//   - AppLuaModdingLibrary::lDisableMod （阶段 C，同上）
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
#include "UiInject.h"
#include "../common/Logger.h"
#include "MinHook.h"

#include <cwchar>
#include <wchar.h>
#include <string>
#include <cstring>
#include <vector>

namespace {

// ---- exe 域取址表（双版本）----
// 生成命令：python tools/gen_exe_aobs.py --emit-cpp（重建符号库/游戏更新后重新生成）。
// 说明：RVA 是各变体构建下的坐标（运行时会先走 pdata 矫正）；AOB 是该变体里唯一命中的兜底定位串。

// ---- 本块由 tools/gen_exe_aobs.py --emit-cpp 生成；重建符号库/游戏更新后重新生成 ----

constexpr char kAob_LoadDLL[] = "48 81 EC 48 02 00 00 48 83 3D ?? ?? ?? ?? 00 74 ?? 32 C0 48 81 C4 48 02 00 00 C3 48 8D 44 24 2C 48 89 AC 24 58 02 00 00 48 89 44 24 20 48 8D 54 24 2C 0F B7 05 ?? ?? ?? ?? 33 ED 41 B8 04 01 00";
constexpr char kAob_UnloadDLL_Dx11[] = "48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 74 ?? 48 89 5C 24 20 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? FF D0 48 8B 0D ?? ?? ?? ?? 33 DB 48 89 1D 4E D2";
constexpr char kAob_UnloadDLL_Dx12[] = "48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 74 ?? 48 89 5C 24 20 E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? FF D0 48 8B 0D ?? ?? ?? ?? 33 DB 48 89 1D 8E 45";
constexpr char kAob_lEnableMod[] = "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 41 56 41 57 48 83 EC 40 48 8B 51 50 48 8B F9 45 33 FF 0F 57 C0 41 8B CF 4C 89 7C 24 30 F3 0F 7F 44 24 20 48 3B 57 48 48 0F 42 CA 0F 83 C6 00 00 00 8B 09 41 B8 06 00 00 00 83 E1 0F 8D 41 F7 83 F8 01 44 0F 47 C1 41 83 F8 03 0F 85 2B";
constexpr char kAob_lDisableMod[] = "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 41 56 41 57 48 83 EC 40 48 8B 51 50 48 8B F9 45 33 FF 0F 57 C0 41 8B CF 4C 89 7C 24 30 F3 0F 7F 44 24 20 48 3B 57 48 48 0F 42 CA 0F 83 C6 00 00 00 8B 09 41 B8 06 00 00 00 83 E1 0F 8D 41 F7 83 F8 01 44 0F 47 C1 41 83 F8 03 0F 85 15";
constexpr char kAob_GetConfiguration[] = "48 83 EC 38 48 8B 05 ?? ?? ?? ?? 48 85 C0 75 ?? E8 ?? ?? ?? ?? 8B D0 C7 44 24 28 00 00 00 00 41 B9 F4 07 00 00 C7 44 24 20 13 00 00 00 4C 8D 05 ?? ?? ?? ?? B9 08 13 00 00 E8 ?? ?? ?? ?? 48 85";

constexpr HookInfoExe kExeLoadDLL = { HookRva(0xF8510, kAob_LoadDLL), HookRva(0xF8850, kAob_LoadDLL) };
constexpr HookInfoExe kExeUnloadDLL = { HookRva(0xF8E30, kAob_UnloadDLL_Dx11), HookRva(0xF9170, kAob_UnloadDLL_Dx12) };
constexpr HookInfoExe kExelEnableMod = { HookRva(0x4CCFE0, kAob_lEnableMod), HookRva(0x4CD840, kAob_lEnableMod) };
constexpr HookInfoExe kExelDisableMod = { HookRva(0x4CCD50, kAob_lDisableMod), HookRva(0x4CD5B0, kAob_lDisableMod) };
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
typedef __int64(__fastcall* ModToggleFn)(void*);          // lEnableMod/lDisableMod(lua_State* L)
typedef char(__fastcall* UnloadDllFn)();                  // GameCore::UnloadDLL()

// ---- 匿名命名空间状态 ----
LoadDllFn g_origLoadDLL = nullptr;
ModToggleFn g_origEnableMod = nullptr;
ModToggleFn g_origDisableMod = nullptr;
UnloadDllFn g_origUnloadDLL = nullptr;
wchar_t g_officialPath[260] = {};  // Loader 自有缓冲：官方 GameCore 绝对路径（不改调用者栈缓冲）

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
const wchar_t* OfficialGameCoreRelPath(const char* ruleset) {
    if (!ruleset) {
        return nullptr;
    }
    if (strstr(ruleset, "EXPANSION_2")) {
        return L"DLC\\Expansion2\\Binaries\\Win64\\GameCore_XP2_FinalRelease.dll";
    }
    if (strstr(ruleset, "EXPANSION_1")) {
        return L"DLC\\Expansion1\\Binaries\\Win64\\GameCore_XP1_FinalRelease.dll";
    }
    if (strstr(ruleset, "STANDARD")) {
        return L"Base\\Binaries\\Win64Steam\\GameCore_Base_FinalRelease.dll";
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

// lEnableMod/lDisableMod 入口：48 89 5C 24 10 48 89 6C 24 18
// （mov [rsp+10h],rbx; mov [rsp+18h],rbp —— 两个函数同款入口序言）。
// 两者共用：入口相同即通过；不匹配 = 游戏 exe 已更新，RVA 集失效，整体跳过 hook。
bool CheckModToggleSignature(uintptr_t addr) {
    if (!SignatureSpanReadable(addr, 10)) {
        return false;
    }
    static const unsigned char kSig[10] = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18
    };
    return memcmp(reinterpret_cast<const void*>(addr), kSig, sizeof(kSig)) == 0;
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

    // XP2：喂官方 GameCore DLL 绝对路径给原 LoadDLL（引擎槽位=官方）。
    const wchar_t* rel = OfficialGameCoreRelPath(ruleset);
    wchar_t* target = Path;
    if (rel && BuildOfficialPath(rel)) {
        target = g_officialPath;  // 官方 DLL（文件存在才改写；否则透传原路径）
    }

    // 兜底：正常时序下 UnloadDLL detour 已在更早清场（映像卸载前）；此处防御
    // UnloadDLL hook 未安装/未生效的情况（IsInitialized 仍为 true 意味着没人清场）。
    if (LoaderCore::IsInitialized()) {
        Logger::Log("LoadDLL re-entry: resetting GameCore phase (UnloadDLL hook missed?)");
        LoaderCore::ResetForReload();
    }

    char result = g_origLoadDLL(target);  // 调原函数（已 hook 前 snapshot，MinHook trampoline）
    if (result != 0) {
        if (LoaderCore::InitializeGameCorePhase()) {
            LoaderCore::LoadPluginsOf(LoaderCore::PluginCategory::GameCore);
        } else {
            Logger::Log("InitializeGameCorePhase failed; GameCore plugins not loaded");
        }
    } else {
        // 区分幂等短路与真失败：读 exe 全局 hModule 槽（由 RIP 相对指令解出，不写数据地址）。
        const uintptr_t hModAddr = reinterpret_cast<uintptr_t>(
            LoaderCore::ResolveDataByAobCore(ExeImage(), kAob_hModule));
        HMODULE* hMod = reinterpret_cast<HMODULE*>(hModAddr);
        if (hMod && *hMod != nullptr) {
            Logger::Log("LoadDLL idempotent short-circuit; (re)initializing plugins against loaded module");
            if (LoaderCore::InitializeGameCorePhase()) {
                LoaderCore::LoadPluginsOf(LoaderCore::PluginCategory::GameCore);
            }
        } else {
            Logger::Log("LoadDLL failed to load GameCore (game will report its own error)");
        }
    }
    return result;
}

// ---- UnloadDLL detour（阶段 B 收尾：原函数卸掉 GameCore 前先卸 GameCore 插件）----
// UnloadDLL 的调用方：LoadDLL 失败路径、退游戏、LoadGameCore 重载、RollbackContent、
// UpdateContent。在调原函数【之前】清理：此时 GameCore 映像仍活着，插件 OnUnload 能
// 干净回滚补丁（PatchRegistry::RevertAllFor）/摘 MinHook 钩子（RemovePluginHooks）/
// FreeLibrary。等 LoadDLL 重入再清就晚了（映像已卸）。
static char __fastcall UnloadDllDetour() {
    if (LoaderCore::IsInitialized()) {
        Logger::Log("UnloadDLL: resetting GameCore phase (unloading plugins before core unload)");
        LoaderCore::ResetForReload();
    }
    return g_origUnloadDLL();
}

// ---- ModToggle detour（阶段 C：开关 Mod → 原函数执行 → 唤醒工作线程重查启用集）----
static __int64 __fastcall EnableModDetour(void* L) {
    __int64 r = g_origEnableMod(L);
    LoaderCore::RequestReconcile();
    UiInject::RefreshOnUiThread();
    return r;
}

static __int64 __fastcall DisableModDetour(void* L) {
    __int64 r = g_origDisableMod(L);
    LoaderCore::RequestReconcile();
    UiInject::RefreshOnUiThread();
    return r;
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

    // 可选 hook 的统一安装事务：失败只放弃这一个并记日志，**不连坐**已装好的钩子。
    // 关键点：一个可选 hook（lEnableMod / lDisableMod / UnloadDLL）的签名或启用失败，
    // 绝不该把核心的 LoadDLL 钩子一起回滚掉 —— 原实现在这里 return rollback(...)，
    // 等于"丢一个可选功能 = 丢全部功能"。
    const auto installOptional = [&](const char* name, uintptr_t addr,
                                     bool (*check)(uintptr_t), void* detour, void** original) {
        if (!addr || !check(addr)) {
            Logger::Log("%s signature mismatch; hook skipped (addr=0x%llX)", name,
                static_cast<unsigned long long>(addr));
            return;
        }
        MH_STATUS s = MH_CreateHook(reinterpret_cast<LPVOID>(addr), detour,
            reinterpret_cast<LPVOID*>(original));
        if (s != MH_OK) {
            Logger::Log("%s MH_CreateHook failed: %s", name, MH_StatusToString(s));
            return;
        }
        s = MH_EnableHook(reinterpret_cast<LPVOID>(addr));
        if (s != MH_OK) {
            Logger::Log("%s MH_EnableHook failed: %s", name, MH_StatusToString(s));
            MH_RemoveHook(reinterpret_cast<LPVOID>(addr));  // 摘掉半成品记录，避免下次 ALREADY_CREATED
            return;
        }
        createdHooks.push_back(reinterpret_cast<LPVOID>(addr));
        Logger::Log("%s hook installed at 0x%llX", name, static_cast<unsigned long long>(addr));
    };

    // ---- LoadDLL（RVA 0xF8510 / 0xF8850，AOB 兜底）----
    const uintptr_t loadDllAddr = reinterpret_cast<uintptr_t>(
        LoaderCore::ResolveExeTarget(kExeLoadDLL, 1));
    if (!loadDllAddr || !CheckLoadDllSignature(loadDllAddr)) {
        Logger::Log("LoadDLL signature mismatch; hook skipped (addr=0x%llX, err=%lu)",
            static_cast<unsigned long long>(loadDllAddr), GetLastError());
        return rollback("LoadDLL validation failed");
    }
    if ((st = MH_CreateHook((LPVOID)loadDllAddr, &LoadDllDetour, (LPVOID*)&g_origLoadDLL))
            != MH_OK) {
        Logger::Log("LoadDLL MH_CreateHook failed: %s", MH_StatusToString(st));
        return rollback("LoadDLL create failed");
    }
    createdHooks.push_back((LPVOID)loadDllAddr);
    if ((st = MH_EnableHook((LPVOID)loadDllAddr)) != MH_OK) {
        Logger::Log("LoadDLL MH_EnableHook failed: %s", MH_StatusToString(st));
        return rollback("LoadDLL enable failed");
    }
    Logger::Log("LoadDLL hook installed at 0x%llX",
        static_cast<unsigned long long>(loadDllAddr));

    // ---- lDisableMod（RVA 0x4CCD50 / 0x4CD5B0，AOB 兜底；可选）----
    installOptional("lDisableMod",
        reinterpret_cast<uintptr_t>(LoaderCore::ResolveExeTarget(kExelDisableMod, 1)),
        &CheckModToggleSignature, reinterpret_cast<void*>(&DisableModDetour),
        reinterpret_cast<void**>(&g_origDisableMod));

    // ---- lEnableMod（RVA 0x4CCFE0 / 0x4CD840，AOB 兜底；可选）----
    installOptional("lEnableMod",
        reinterpret_cast<uintptr_t>(LoaderCore::ResolveExeTarget(kExelEnableMod, 1)),
        &CheckModToggleSignature, reinterpret_cast<void*>(&EnableModDetour),
        reinterpret_cast<void**>(&g_origEnableMod));

    // ---- UnloadDLL（RVA 0xF8E30 / 0xF9170，AOB 兜底；可选）----
    installOptional("UnloadDLL",
        reinterpret_cast<uintptr_t>(LoaderCore::ResolveExeTarget(kExeUnloadDLL, 1)),
        &CheckUnloadDllSignature, reinterpret_cast<void*>(&UnloadDllDetour),
        reinterpret_cast<void**>(&g_origUnloadDLL));

    Logger::Log("InstallAll: %zu hook(s) installed (LoadDLL is the required one)", createdHooks.size());
    return true;
}
