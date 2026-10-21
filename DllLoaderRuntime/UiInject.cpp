// UiInject.cpp — Civ6DllLoader FrontEnd UI 注入。
//
// 两部分：
//  1) ExtractResources：把 RCDATA 内嵌的 Civ6DllLoader_FrontEndUI.{lua,xml} 释放到
//     <exe目录>\Civ6DllLoader\（文件已存在则跳过，用户可在磁盘编辑）。
//  2) Install：MinHook detour MainMenuState::LoadUI（RVA 0x8AB40）。主菜单 FrontEnd
//     context 就绪后：
//       a) 注入根容器 context（Civ6DllLoader/Civ6DllLoader_FrontEndUI，lua 留空），
//          挂到 FrontEnd 下（其 xml 的 Name = AdditionalFrontEndUI）；
//       b) 遍历已启用 Mod 的目录树，按文件名收集 FrontEndUI_*.xml（不读 .modinfo），
//          逐个用 AllocateControl<LuaContext> + ChangeParent + Initialize（虚表 +0x200）
//          加载，挂到根容器 context 下。
//
// 地址来源：CivilizationVI.exe（IDA base 0x140000000）逆向，全部特征码运行时校验，
// 错位则静默降级（不崩溃、不影响游戏）。

#include "pch.h"

#include "UiInject.h"
#include "ImageAddress.h"
#include "Runtime.h"
#include "LoaderCore.h"
#include "../common/Logger.h"
#include "../common/Profiler.h"
#include "../common/EnabledMods.h"
#include "ScriptBridge.h"
#include "MinHook.h"

#include <algorithm>
#include <atomic>
#include <cwchar>
#include <cwctype>
#include <cstring>
#include <filesystem>
#include <string>
#include <string.h>
#include <string_view>
#include <vector>

namespace {

// 当前进程 exe 的镜像 id（未识别 = kHookImageInvalid）。
HookImageId ExeImage() {
    return LoaderCore::CurrentExeImage();
}

// RCDATA 资源 id（103=lua / 104=xml；102 已被 sidecar 占用）
constexpr int kLuaResourceId = 103;
constexpr int kXmlResourceId = 104;

constexpr const wchar_t* kLuaFileName = L"Civ6DllLoader_FrontEndUI.lua";
constexpr const wchar_t* kXmlFileName = L"Civ6DllLoader_FrontEndUI.xml";
constexpr const wchar_t* kExtractDir = L"Civ6DllLoader";
// 传给 LuaContext::Initialize 的根容器 base name（不带 .xml；LoadXML 自动补 .xml + 同目录 .lua）
constexpr const wchar_t* kUiBaseName = L"Civ6DllLoader/Civ6DllLoader_FrontEndUI";

// ---- exe 域取址表（双版本）----
// 生成命令：python tools/symdb.py aob --emit-cpp（重建符号库/游戏更新后重新生成）。
constexpr char kAob_LoadUI_Dx11[] = "48 89 5C 24 08 57 48 83 EC 20 48 83 B9 30 02 00 00 00 48 8B F9 74 ?? E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 87 30 02 00 00 48 85 C0 74 ?? 48 8B 0D ?? ?? ?? ?? 48 8B D0 E8 DD";
constexpr char kAob_LoadUI_Dx12[] = "48 89 5C 24 08 57 48 83 EC 20 48 83 B9 30 02 00 00 00 48 8B F9 74 ?? E8 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 87 30 02 00 00 48 85 C0 74 ?? 48 8B 0D ?? ?? ?? ?? 48 8B D0 E8 4D";
constexpr char kAob_AllocLuaCtx_Dx11[] = "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 8B 05 ?? ?? ?? ?? 45 85 C0 74 ?? 48 8B 05 ?? ?? ?? ?? 41 FF C8 4A 8B 1C C0 FF 05 ?? ?? ?? ?? 44 89 05 4B";
constexpr char kAob_AllocLuaCtx_Dx12[] = "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 44 8B 05 ?? ?? ?? ?? 45 85 C0 74 ?? 48 8B 05 ?? ?? ?? ?? 41 FF C8 4A 8B 1C C0 FF 05 ?? ?? ?? ?? 44 89 05 9B";
constexpr char kAob_ChangeParent[] = "48 85 D2 74 ?? 48 89 5C 24 08 57 48 83 EC 20 48 8B D9 48 8B FA 48 8B 49 58 48 85 C9 74 ?? 48 8B 01 48 8B D3 FF 90 D0 00 00 00 48 8B 07 48 8B D3 48 8B CF FF 50 48 48 8B CF E8 ?? ?? ?? ?? 84 C0";
constexpr char kAob_DestroyChild[] = "40 57 48 83 EC 20 48 8B F9 48 8B 49 08 48 85 C9 74 ?? 48 8B 41 38 44 8B 41 48 48 89 5C 24 30 33 DB 48 89 74 24 38 8B 71 48 4E 8D 0C C0 49 3B C1 74 ?? 48 39 10 74 ?? FF C3 48 83 C0 08 49 3B C1";

constexpr HookInfoExe kExeLoadUI = { HookRva(0x8AB40, kAob_LoadUI_Dx11), HookRva(0x8B080, kAob_LoadUI_Dx12) };
constexpr HookInfoExe kExeAllocLuaCtx = { HookRva(0x7A500, kAob_AllocLuaCtx_Dx11), HookRva(0x7A9B0, kAob_AllocLuaCtx_Dx12) };
constexpr HookInfoExe kExeChangeParent = { HookRva(0x8707D0, kAob_ChangeParent), HookRva(0x872550, kAob_ChangeParent) };
constexpr HookInfoExe kExeDestroyChild = { HookRva(0x871410, kAob_DestroyChild), HookRva(0x873190, kAob_DestroyChild) };
// ForgeUI::UIManager 全局指针槽：| 分指令段，xx = disp32（ResolveDataByAob 解出实际地址）。
constexpr char kAob_UIManager[] = "48 8B 0D xx xx xx xx | E8 ?? ?? ?? ?? 48 89 87 30 02 00 00";

// LuaContext 虚表 Initialize 槽偏移（LoadUI 汇编：call [vftable+200h]）
constexpr uint32_t kVtInitSlot = 0x200;
// MainMenuState 的 FrontEnd context 指针字段（LoadUI 汇编：cmp [rcx+230h],0 / mov [rdi+230h],rax）
constexpr ptrdiff_t kOff_FrontEndContext = 0x230;

// ChangeParent 导出符号（exe 导出表 entry 93）
constexpr const char* kChangeParentExport =
    "?ChangeParent@ControlBase@ForgeUI@@QEAAXPEAV12@@Z";
// DestroyChild 导出符号（用于在 UI 重载前销毁 loader 自己的根 context）
constexpr const char* kDestroyChildExport =
    "?DestroyChild@ControlBase@ForgeUI@@UEAAXPEAV12@@Z";

// ---- 特征码（入口前 N 字节，全部固定，运行时校验）----
const uint8_t kSigLoadUI[] = {
    0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x20,0x48,0x83,0xB9,0x30,0x02,0x00,0x00,0x00
};
const uint8_t kSigAlloc[] = {
    0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x20,0x48,0x8B,0xF9
};
const uint8_t kSigChangeParent[] = {
    0x48,0x85,0xD2,0x74,0x6C,0x48,0x89,0x5C,0x24,0x08
};
const uint8_t kSigDestroyChild[] = {
    0x40,0x57,0x48,0x83,0xEC,0x20,0x48,0x8B,0xF9,0x48,0x8B,0x49,0x08
};

// ---- 类型 ----
typedef void* (__fastcall* AllocLuaContextFn)(void* uiManager);   // AllocateControl<LuaContext>(UIManager*)
typedef void  (__fastcall* ChangeParentFn)(void* child, void* parent);
typedef void  (__fastcall* DestroyChildFn)(void* parent, void* child);
typedef void  (__fastcall* LuaInitFn)(void* ctx, const wchar_t* name);
typedef void* (__fastcall* LoadUiFn)(void* state);

// ---- 状态 ----
// UI 对象只能在游戏/UI 线程操作；g_refreshRequested 初值为 true，注入失败时由失败路径重新
// 置位（下次 LoadUI 再试），成功后就保持 false；具体销毁与重建只在 LoadUI detour 里执行。
std::atomic<bool> g_refreshRequested{ true };
std::atomic<bool> g_injectionInProgress{ false };
void* g_frontEndContext = nullptr;
void* g_rootContext = nullptr;
LoadUiFn g_origLoadUI = nullptr;

// 进程 exe 所在目录（去文件名段）。失败返回空串。
std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    std::wstring path(buf, n);
    const size_t slash = path.find_last_of(L"/\\");
    if (slash == std::wstring::npos) return {};
    path.resize(slash);
    return path;
}

// 读 RCDATA 资源到 std::vector<uint8_t>。失败返回 false。
bool ReadResourceData(HMODULE module, int id, std::vector<uint8_t>& out) {
    HRSRC res = FindResourceW(module, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!res) return false;
    HGLOBAL glob = LoadResource(module, res);
    if (!glob) return false;
    const DWORD sz = SizeofResource(module, res);
    const void* ptr = LockResource(glob);
    if (!ptr || sz == 0) return false;
    out.assign(static_cast<const uint8_t*>(ptr), static_cast<const uint8_t*>(ptr) + sz);
    return true;
}

// 新建文件并整段写入（文件已存在则失败，**不覆盖**）。失败返回 false。
// CREATE_NEW：只在文件不存在时创建。调用方的语义本来就是"已存在则跳过"，
// 这样同时消掉 GetFileAttributesW -> CreateFileW 之间的 TOCTOU，也不会跟到 junction/symlink 目标。
bool WriteWholeFile(const std::wstring& path, const void* data, size_t len) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok = WriteFile(h, data, static_cast<DWORD>(len), &written, nullptr) != 0 &&
                    written == len;
    CloseHandle(h);
    return ok;
}

// ---- 资源版本标记 ----
// 两份 UI 资源各自在文件头带一行版本标记：
//   lua:  --@ui-version=N
//   xml:  <!--@ui-version=N-->
// 标记值 = 内嵌资源自身的版本；解压时与磁盘上那份的标记比较，决定覆盖与否。
// 这样"用户改过副本"和"Loader 升级了资源"两个需求不会互相踩：
//   · 磁盘版本 == 内嵌版本  -> 保留（用户可能改过）
//   · 磁盘版本 <  内嵌版本  -> 覆盖（Loader 升级过资源）
//   · 磁盘没有标记          -> 覆盖（旧版资源，或用户重写过）
constexpr int kUiResourceVersion = 1;
// 只扫文件头这么多字节：标记一定在最前面，避免整份读进来。
constexpr DWORD kVersionScanBytes = 256;

// 从打开的句柄里扫出 @ui-version=N。找不到或格式不对返回 0。
int ReadUiVersionFromHandle(HANDLE h) {
    char buf[kVersionScanBytes]{};
    DWORD got = 0;
    if (!ReadFile(h, buf, kVersionScanBytes, &got, nullptr) || got == 0) return 0;
    constexpr char kTag[] = "@ui-version=";
    constexpr size_t kTagLen = sizeof(kTag) - 1;
    for (size_t i = 0; i + kTagLen < got; ++i) {
        if (memcmp(buf + i, kTag, kTagLen) != 0) continue;
        size_t j = i + kTagLen;
        int value = 0;
        bool anyDigit = false;
        while (j < got && buf[j] >= '0' && buf[j] <= '9') {
            value = value * 10 + (buf[j] - '0');
            anyDigit = true;
            ++j;
            if (value > 1000000) return 0;  // 防御异常长数字
        }
        if (anyDigit) return value;
    }
    return 0;
}

// 读磁盘文件的版本标记；文件不存在 / 打不开 / 无标记都返回 0。
int ReadUiVersionFromDisk(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    const int v = ReadUiVersionFromHandle(h);
    CloseHandle(h);
    return v;
}

// 覆盖写：先写临时文件再原子替换，避免写到一半断电留下半个 UI。
bool ReplaceWholeFile(const std::wstring& path, const void* data, size_t len) {
    const std::wstring tmp = path + L".tmp";
    DeleteFileW(tmp.c_str());
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok = WriteFile(h, data, static_cast<DWORD>(len), &written, nullptr) != 0 &&
                    written == len;
    CloseHandle(h);
    if (!ok) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileW(tmp.c_str());
        return false;
    }
    return true;
}

// 释放单个资源到 <exe目录>\Civ6DllLoader\<fileName>。
// 是否覆盖由文件头版本标记决定，见上面 kUiResourceVersion 处的说明。
void ExtractOne(HMODULE module, int id, const wchar_t* fileName) {
    std::wstring dir = GetExeDir();
    if (dir.empty()) return;
    std::wstring subdir = dir + L"\\" + kExtractDir;
    std::wstring target = subdir + L"\\" + fileName;

    const bool exists = GetFileAttributesW(target.c_str()) != INVALID_FILE_ATTRIBUTES;
    if (exists) {
        const int diskVersion = ReadUiVersionFromDisk(target);
        if (diskVersion >= kUiResourceVersion) {
            Logger::Log("UiInject: %ls 保留 (disk=%d, embedded=%d)",
                        fileName, diskVersion, kUiResourceVersion);
            return;  // 磁盘已是最新（或更新），保留——用户可能改过
        }
        Logger::Log("UiInject: %ls 版本落后 (disk=%d, embedded=%d)，覆盖",
                    fileName, diskVersion, kUiResourceVersion);
    }

    std::vector<uint8_t> data;
    if (!ReadResourceData(module, id, data)) {
        Logger::Log("UiInject: RCDATA %d 读取失败", id);
        return;
    }
    if (!CreateDirectoryW(subdir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        Logger::Log("UiInject: 创建目录 %ls 失败 err=%lu", subdir.c_str(), GetLastError());
        return;
    }
    if (exists) {
        if (ReplaceWholeFile(target, data.data(), data.size())) {
            Logger::Log("UiInject: 覆盖 %ls (%zu bytes)", fileName, data.size());
        } else {
            Logger::Log("UiInject: 覆盖 %ls 失败 err=%lu", fileName, GetLastError());
        }
        return;
    }
    if (WriteWholeFile(target, data.data(), data.size())) {
        Logger::Log("UiInject: 释放 %ls (%zu bytes)", fileName, data.size());
    } else if (GetFileAttributesW(target.c_str()) != INVALID_FILE_ATTRIBUTES) {
        // 与前面那次存在性检查之间被别的进程抢先创建：语义上等同"已存在则跳过"。
    } else {
        Logger::Log("UiInject: 写 %ls 失败 err=%lu", fileName, GetLastError());
    }
}

// 特征码校验：确认 [addr, addr+len) 完整落在 exe 镜像内且字节匹配。
bool SignatureMatch(uintptr_t addr, const uint8_t* sig, size_t len) {
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(ExeImage(), &info)) return false;
    if (!addr || !info.base || !info.imageSize) return false;
    if (addr < info.base || addr - info.base + len > info.imageSize) return false;
    return memcmp(reinterpret_cast<const void*>(addr), sig, len) == 0;
}

// HookInfoExe + 特征码解析一个地址；失败返回 0。
uintptr_t ResolveChecked(const HookInfoExe& info, const uint8_t* sig, size_t sigLen, const char* tag) {
    void* p = LoaderCore::ResolveExeTarget(info, sigLen);
    if (!p || !SignatureMatch(reinterpret_cast<uintptr_t>(p), sig, sigLen)) {
        Logger::Log("UiInject: %s 特征码不匹配（游戏已更新？），跳过", tag);
        return 0;
    }
    return reinterpret_cast<uintptr_t>(p);
}

// Mod UI 文件名约定：FrontEndUI_*.xml（大小写不敏感）。
bool IsModUiFileName(const std::wstring& name) {
    constexpr size_t kPrefixLen = 11;  // "FrontEndUI_"
    if (name.size() <= kPrefixLen + 4) return false;
    if (_wcsnicmp(name.c_str(), L"FrontEndUI_", kPrefixLen) != 0) return false;
    return _wcsicmp(name.c_str() + name.size() - 4, L".xml") == 0;
}

// 遍历启用 Mod 的目录树，按文件名收集 FrontEndUI_*.xml 的 base name。
// base name 是相对 mod 根的 VFS 路径（去掉 .xml、分隔符统一成 '/'），正是
// LuaContext::Initialize 需要的形参；loader 不再读取 .modinfo。
std::vector<std::wstring> FindModUiFiles() {
    std::vector<std::wstring> out;
    const EnabledMods::Snapshot snap = EnabledMods::Load();
    if (!snap.ok) {
        Logger::Log("UiInject: EnabledMods 不可用（%s），跳过所有 Mod UI",
                    snap.error.empty() ? "unknown" : snap.error.c_str());
        return out;
    }

    // Mods.sqlite 已经给出实际启用的 mod 目录，只在这些根下按文件名找 UI 文件。
    // 递归遍历默认不跟随目录符号链接/junction，环不会无限展开；深度再兜一道上限，
    // 避免异常深的资源目录拖慢主菜单线程。
    constexpr int kMaxDepth = 8;
    for (const auto& enabledRoot : snap.enabledModRoots) {
        std::error_code ec;
        const std::filesystem::path modDir(enabledRoot);
        if (!std::filesystem::is_directory(modDir, ec)) continue;

        std::filesystem::recursive_directory_iterator it(
            modDir, std::filesystem::directory_options::skip_permission_denied, ec);
        const std::filesystem::recursive_directory_iterator end;
        for (; !ec && it != end; it.increment(ec)) {
            std::error_code fec;
            if (it->is_regular_file(fec) && IsModUiFileName(it->path().filename().wstring())) {
                std::error_code relEc;
                const std::filesystem::path rel = std::filesystem::relative(it->path(), modDir, relEc);
                if (!relEc && !rel.empty()) {
                    std::wstring base = rel.wstring();
                    if (base.size() > 4) {
                        base.resize(base.size() - 4);  // 去掉 ".xml"
                        std::replace(base.begin(), base.end(), L'\\', L'/');
                        out.push_back(std::move(base));
                    }
                }
            }
            if (it.depth() >= kMaxDepth) it.disable_recursion_pending();
        }
    }

    // 去重 + 大小写不敏感排序（稳定加载顺序）
    std::sort(out.begin(), out.end(), [](const std::wstring& a, const std::wstring& b) {
        const size_t n = (std::min)(a.size(), b.size());
        for (size_t i = 0; i < n; ++i) {
            const wchar_t ca = towlower(a[i]);
            const wchar_t cb = towlower(b[i]);
            if (ca != cb) return ca < cb;
        }
        return a.size() < b.size();
    });
    out.erase(std::unique(out.begin(), out.end(), [](const std::wstring& a, const std::wstring& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            if (towlower(a[i]) != towlower(b[i])) return false;
        }
        return true;
    }), out.end());
    return out;
}

// 注入链路解析后的函数指针集合。
struct UiApi {
    AllocLuaContextFn alloc = nullptr;
    ChangeParentFn changeParent = nullptr;
    DestroyChildFn destroyChild = nullptr;
};

// ForgeUI 的这些调用都跨越游戏内部 ABI；把 SEH 边界放在不含 C++ 对象的
// 小函数里，保证单个 context 失败时仍能回到调用方执行清理与重试。
__declspec(noinline) void* CallAllocateContextSafe(AllocLuaContextFn fn, void* mgr) {
    if (!fn) return nullptr;
    __try {
        return fn(mgr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("UiInject: AllocateControl 异常（已捕获）");
        return nullptr;
    }
}

__declspec(noinline) bool CallChangeParentSafe(ChangeParentFn fn, void* child, void* parent) {
    if (!fn || !child || !parent) return false;
    __try {
        fn(child, parent);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("UiInject: ChangeParent 异常（已捕获）");
        return false;
    }
}

__declspec(noinline) bool CallDestroyChildSafe(DestroyChildFn fn, void* parent, void* child) {
    if (!fn || !parent || !child) return false;
    __try {
        fn(parent, child);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("UiInject: DestroyChild 异常（已捕获），保留 context 等待重试");
        return false;
    }
}

__declspec(noinline) bool ReadPointerSafe(const void* address, void** value) {
    if (!address || !value) return false;
    __try {
        *value = *reinterpret_cast<void* const*>(address);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

__declspec(noinline) bool CallLuaInitSafe(LuaInitFn fn, void* ctx, const wchar_t* baseName) {
    if (!fn || !ctx || !baseName) return false;
    __try {
        fn(ctx, baseName);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Logger::Log("UiInject: LuaContext Initialize 异常（%ls，已捕获）", baseName);
        return false;
    }
}

// 创建 + 挂载 + 初始化一个 LuaContext（加载 baseName.xml + baseName.lua），挂到 parent 下。
// Initialize 走虚表 +0x200（不硬编码地址），xml 的 context 节点由 ForgeUI 正确绑定。
// outAllocated 始终保留尚未确认销毁的 context，供 root 路径登记并在下一次刷新重试。
void* InjectSingleContext(const UiApi& api, void* mgr, void* parent,
                          const wchar_t* baseName, void** outAllocated) {
    if (outAllocated) *outAllocated = nullptr;

    void* ctx = CallAllocateContextSafe(api.alloc, mgr);
    if (!ctx) {
        Logger::Log("UiInject: AllocateControl 返回空（%ls）", baseName);
        return nullptr;
    }
    if (outAllocated) *outAllocated = ctx;

    if (!CallChangeParentSafe(api.changeParent, ctx, parent)) {
        if (CallDestroyChildSafe(api.destroyChild, parent, ctx) && outAllocated) {
            *outAllocated = nullptr;
        }
        Logger::Log("UiInject: ChangeParent 失败（%ls）", baseName);
        return nullptr;
    }

    void* vt = nullptr;
    if (!ReadPointerSafe(ctx, &vt)) {
        Logger::Log("UiInject: LuaContext 虚表读取失败（%ls）", baseName);
        if (CallDestroyChildSafe(api.destroyChild, parent, ctx) && outAllocated) {
            *outAllocated = nullptr;
        }
        return nullptr;
    }
    if (!Runtime::IsReadableSpan(vt, kVtInitSlot + sizeof(void*))) {
        Logger::Log("UiInject: LuaContext 虚表不可读（%ls）", baseName);
        if (CallDestroyChildSafe(api.destroyChild, parent, ctx) && outAllocated) {
            *outAllocated = nullptr;
        }
        return nullptr;
    }
    void* initAddress = nullptr;
    if (!ReadPointerSafe(reinterpret_cast<uint8_t*>(vt) + kVtInitSlot, &initAddress) ||
        !CallLuaInitSafe(reinterpret_cast<LuaInitFn>(initAddress), ctx, baseName)) {
        if (CallDestroyChildSafe(api.destroyChild, parent, ctx) && outAllocated) {
            *outAllocated = nullptr;
        }
        return nullptr;
    }
    Logger::Log("UiInject: context 已加载 (%ls)", baseName);
    return ctx;
}

// 注入主体：在 LoadUI 原函数返回后调用。state = MainMenuState*。
void InjectFrontEndUi(void* state) {
    const bool refresh = g_refreshRequested.exchange(false, std::memory_order_acq_rel);

    // 1) 读 UIManager 全局 + FrontEnd context 指针
    void* mgr = nullptr;
    void* frontEnd = nullptr;
    {
        void* slot = LoaderCore::ResolveDataByAobCore(ExeImage(), kAob_UIManager);
        if (!slot || !Runtime::IsReadableSpan(slot, sizeof(void*))) {
            Logger::Log("UiInject: UIManager 全局不可读，放弃注入");
            if (refresh) g_refreshRequested.store(true, std::memory_order_release);
            return;
        }
        mgr = *reinterpret_cast<void**>(slot);
        frontEnd = *reinterpret_cast<void**>(
            reinterpret_cast<uint8_t*>(state) + kOff_FrontEndContext);
    }
    if (!mgr || !frontEnd) {
        Logger::Log("UiInject: mgr/frontEnd 为空（FrontEnd 未就绪），放弃");
        if (refresh) g_refreshRequested.store(true, std::memory_order_release);
        return;
    }

    const bool newFrontEnd = g_frontEndContext != frontEnd;
    if (!newFrontEnd && !refresh && g_rootContext) {
        return;  // 当前 FrontEnd 已经注入，且没有（失败路径置位的）重试请求
    }

    // LoadUI 重建时旧 FrontEnd 通常已经由游戏销毁；不能再访问旧指针。
    // 只有同一个 FrontEnd 收到刷新请求时，才使用游戏导出的 DestroyChild 安全销毁
    // 我们自己的根 context，然后在同一线程重新构建。
    if (newFrontEnd) {
        g_frontEndContext = frontEnd;
        g_rootContext = nullptr;
    }

    // 2) 解析注入链路函数指针
    UiApi api;
    uintptr_t allocAddr = ResolveChecked(kExeAllocLuaCtx, kSigAlloc, sizeof(kSigAlloc),
                                         "AllocateControl<LuaContext>");
    if (!allocAddr) {
        if (refresh) g_refreshRequested.store(true, std::memory_order_release);
        return;
    }
    api.alloc = reinterpret_cast<AllocLuaContextFn>(allocAddr);

    api.changeParent = reinterpret_cast<ChangeParentFn>(
        GetProcAddress(GetModuleHandleW(nullptr), kChangeParentExport));
    if (!api.changeParent) {
        uintptr_t cpAddr = ResolveChecked(kExeChangeParent, kSigChangeParent,
                                          sizeof(kSigChangeParent), "ChangeParent");
        api.changeParent = reinterpret_cast<ChangeParentFn>(cpAddr);
    }
    if (!api.changeParent) {
        if (refresh) g_refreshRequested.store(true, std::memory_order_release);
        return;
    }

    api.destroyChild = reinterpret_cast<DestroyChildFn>(
        GetProcAddress(GetModuleHandleW(nullptr), kDestroyChildExport));
    if (!api.destroyChild) {
        const uintptr_t destroyAddr = ResolveChecked(kExeDestroyChild, kSigDestroyChild,
                                                     sizeof(kSigDestroyChild), "DestroyChild");
        api.destroyChild = reinterpret_cast<DestroyChildFn>(destroyAddr);
    }
    if (!api.destroyChild) {
        Logger::Log("UiInject: DestroyChild 不可用，跳过注入并保留刷新请求");
        g_refreshRequested.store(true, std::memory_order_release);
        return;
    }

    if (!newFrontEnd && refresh && g_rootContext) {
        void* oldRoot = g_rootContext;
        if (!CallDestroyChildSafe(api.destroyChild, frontEnd, oldRoot)) {
            g_refreshRequested.store(true, std::memory_order_release);
            return;
        }
        g_rootContext = nullptr;
    }

    // 3) 注入根容器 context（lua 已留空），挂到 FrontEnd 下（其 Name = AdditionalFrontEndUI）
    void* rootAllocated = nullptr;
    void* rootCtx = InjectSingleContext(api, mgr, frontEnd, kUiBaseName, &rootAllocated);
    if (!rootCtx) {
        // DestroyChild 失败时保留这个已挂载的 root，让下次刷新继续回收。
        if (rootAllocated) g_rootContext = rootAllocated;
        g_refreshRequested.store(true, std::memory_order_release);
        return;
    }
    g_rootContext = rootCtx;

    // 4) 遍历启用 Mod 的目录树，加载 FrontEndUI_*.xml，挂到根容器下
    const std::vector<std::wstring> modUis = FindModUiFiles();
    Logger::Log("UiInject: 发现 %zu 个 Mod UI", modUis.size());
    for (const auto& base : modUis) {
        void* childAllocated = nullptr;
        InjectSingleContext(api, mgr, rootCtx, base.c_str(), &childAllocated);
        if (childAllocated) {
            // 子 context 仍挂在 root 下；下一次刷新销毁 root 时会一并回收。
            Logger::Log("UiInject: 子 context 回收延期至 root 销毁（%ls）", base.c_str());
        }
    }
}

void RunInjectionSafely(void* state) {
    if (g_injectionInProgress.exchange(true, std::memory_order_acq_rel)) {
        g_refreshRequested.store(true, std::memory_order_release);
        return;
    }
    __try {
        InjectFrontEndUi(state);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // 已登记的 root 会在下一次刷新通过 DestroyChild 回收；单个 context
        // 的分配、挂载、初始化异常则由各自的安全调用负责清理或保留登记。
        g_refreshRequested.store(true, std::memory_order_release);
        Logger::Log("UiInject: 注入异常（已捕获），降级");
    }
    g_injectionInProgress.store(false, std::memory_order_release);
}

// ---- MainMenuState::LoadUI detour ----
void* __fastcall LoadUiDetour(void* state) {
    void* result = g_origLoadUI(state);  // 先让原函数创建 FrontEnd + InvitePopup
    // 只在真的要注入时才计时（g_refreshRequested 为 false 时 RunInjectionSafely 是空转）。
    // 这个 detour 每次主菜单刷新都会进来，量全量就是纯浪费。
    const int64_t prof = Profiler::Begin("UiInject::RunInjection");
    RunInjectionSafely(state);
    Profiler::End("UiInject::RunInjection", prof);
    return result;
}

}  // namespace

void UiInject::ExtractResources() {
    HMODULE module = LoaderCore::RuntimeModuleHandle();
    if (!module) {
        Logger::Log("UiInject: runtime 模块句柄为空，跳过资源释放");
        return;
    }
    ExtractOne(module, kLuaResourceId, kLuaFileName);
    ExtractOne(module, kXmlResourceId, kXmlFileName);
}


bool UiInject::Install() {
    std::lock_guard<std::mutex> hookLock(Runtime::MinHookMutex());

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        Logger::Log("UiInject: MH_Initialize failed: %s", MH_StatusToString(st));
        return false;
    }

    const uintptr_t loadUiAddr = reinterpret_cast<uintptr_t>(
        LoaderCore::ResolveExeTarget(kExeLoadUI, 1));
    if (!loadUiAddr || !SignatureMatch(loadUiAddr, kSigLoadUI, sizeof(kSigLoadUI))) {
        Logger::Log("UiInject: MainMenuState::LoadUI 特征码不匹配；hook 跳过 (addr=0x%llX)",
                    static_cast<unsigned long long>(loadUiAddr));
        return false;
    }

    st = MH_CreateHook((LPVOID)loadUiAddr, &LoadUiDetour, (LPVOID*)&g_origLoadUI);
    if (st != MH_OK) {
        Logger::Log("UiInject: LoadUI MH_CreateHook failed: %s", MH_StatusToString(st));
        return false;
    }
    st = MH_EnableHook((LPVOID)loadUiAddr);
    if (st != MH_OK) {
        Logger::Log("UiInject: LoadUI MH_EnableHook failed: %s", MH_StatusToString(st));
        MH_RemoveHook((LPVOID)loadUiAddr);
        return false;
    }
    Logger::Log("UiInject: MainMenuState::LoadUI hook 已安装 (0x%llX)",
                static_cast<unsigned long long>(loadUiAddr));
    return true;
}
