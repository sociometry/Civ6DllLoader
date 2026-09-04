// UiInject.cpp — Civ6DllLoader FrontEnd UI 注入。
//
// 两部分：
//  1) ExtractResources：把 RCDATA 内嵌的 Civ6DllLoader_FrontEndUI.{lua,xml} 释放到
//     <exe目录>\Civ6DllLoader\（文件已存在则跳过，用户可在磁盘编辑）。
//  2) Install：MinHook detour MainMenuState::LoadUI（RVA 0x8AB40）。主菜单 FrontEnd
//     context 就绪后：
//       a) 注入根容器 context（Civ6DllLoader/Civ6DllLoader_FrontEndUI，lua 留空），
//          挂到 FrontEnd 下（其 xml 的 Name = AdditionalFrontEndUI）；
//       b) 遍历启用 Mod 的 .modinfo，从 ImportFiles 声明里收集 FrontEndUI_*.xml 的
//          base name（减少磁盘路径搜索），逐个用 AllocateControl<LuaContext> +
//          ChangeParent + Initialize（虚表 +0x200）加载，挂到根容器 context 下。
//
// 地址来源：CivilizationVI.exe（IDA base 0x140000000）逆向，全部特征码运行时校验，
// 错位则静默降级（不崩溃、不影响游戏）。

#include "pch.h"

#include "UiInject.h"
#include "ImageAddress.h"
#include "Runtime.h"
#include "LoaderCore.h"
#include "../common/Logger.h"
#include "../common/ModScan.h"
#include "../common/EnabledMods.h"
#include "MinHook.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string.h>
#include <string_view>
#include <vector>

namespace {

constexpr HookImageId kExeImage = kHookImageExeDx11;

// RCDATA 资源 id（103=lua / 104=xml；102 已被 sidecar 占用）
constexpr int kLuaResourceId = 103;
constexpr int kXmlResourceId = 104;

constexpr const wchar_t* kLuaFileName = L"Civ6DllLoader_FrontEndUI.lua";
constexpr const wchar_t* kXmlFileName = L"Civ6DllLoader_FrontEndUI.xml";
constexpr const wchar_t* kExtractDir = L"Civ6DllLoader";
// 传给 LuaContext::Initialize 的根容器 base name（不带 .xml；LoadXML 自动补 .xml + 同目录 .lua）
constexpr const wchar_t* kUiBaseName = L"Civ6DllLoader/Civ6DllLoader_FrontEndUI";

// Mod 内 UI 文件的约定前缀：loader 从 ImportFiles 声明里发现并加载所有 FrontEndUI_*.xml
constexpr const char* kModUiPrefix = "FrontEndUI_";

// exe 域 RVA（相对 GetModuleHandleW(nullptr) 基址）
constexpr uintptr_t kRva_LoadUI       = 0x8AB40;   // MainMenuState::LoadUI
constexpr uintptr_t kRva_AllocLuaCtx  = 0x7A500;   // AllocateControl<LuaContext>
constexpr uintptr_t kRva_ChangeParent = 0x8707D0;  // ControlBase::ChangeParent（导出兜底）
constexpr uintptr_t kRva_DestroyChild = 0x871410;  // ControlBase::DestroyChild（刷新时销毁根 context）
constexpr uintptr_t kRva_UIManager    = 0x235F7C8; // ForgeUI::UIManager 全局指针槽

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
// UI 对象只能在游戏/UI 线程操作；刷新请求由 Mod toggle detour 设置，
// 具体销毁与重建只在 LoadUI detour 或明确的 UI 线程刷新点执行。
std::atomic<bool> g_refreshRequested{ true };
std::atomic<bool> g_injectionInProgress{ false };
void* g_lastLoadUiState = nullptr;
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

// 写文件（覆盖）。失败返回 false。
bool WriteWholeFile(const std::wstring& path, const void* data, size_t len) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const bool ok = WriteFile(h, data, static_cast<DWORD>(len), &written, nullptr) != 0 &&
                    written == len;
    CloseHandle(h);
    return ok;
}

// 释放单个资源：目标 <exe目录>\Civ6DllLoader\<fileName> 已存在则跳过，否则写入。
void ExtractOne(HMODULE module, int id, const wchar_t* fileName) {
    std::wstring dir = GetExeDir();
    if (dir.empty()) return;
    std::wstring subdir = dir + L"\\" + kExtractDir;
    std::wstring target = subdir + L"\\" + fileName;
    if (GetFileAttributesW(target.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return;  // 已存在，不覆盖（用户可编辑）
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
    if (WriteWholeFile(target, data.data(), data.size())) {
        Logger::Log("UiInject: 释放 %ls (%zu bytes)", fileName, data.size());
    } else {
        Logger::Log("UiInject: 写 %ls 失败 err=%lu", fileName, GetLastError());
    }
}

// 特征码校验：确认 [addr, addr+len) 完整落在 exe 镜像内且字节匹配。
bool SignatureMatch(uintptr_t addr, const uint8_t* sig, size_t len) {
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(kExeImage, &info)) return false;
    if (!addr || !info.base || !info.imageSize) return false;
    if (addr < info.base || addr - info.base + len > info.imageSize) return false;
    return memcmp(reinterpret_cast<const void*>(addr), sig, len) == 0;
}

// RVA + 特征码解析一个地址；失败返回 0。
uintptr_t ResolveChecked(uintptr_t rva, const uint8_t* sig, size_t sigLen, const char* tag) {
    void* p = ImageAddress::ResolveByRva(kExeImage, rva, sigLen);
    if (!p || !SignatureMatch(reinterpret_cast<uintptr_t>(p), sig, sigLen)) {
        Logger::Log("UiInject: %s 特征码不匹配（游戏已更新？），跳过", tag);
        return 0;
    }
    return reinterpret_cast<uintptr_t>(p);
}

// 去首尾空白（isspace 判定）。
std::string TrimAscii(const std::string& s) {
    size_t a = 0;
    const size_t n = s.size();
    while (a < n && isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = n;
    while (b > a && isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

// 读 mod 目录里的第一个 .modinfo 文件内容（UTF-8，去 BOM）。失败返回空。
std::string ReadModinfo(const std::filesystem::path& modDir) {
    std::error_code ec;
    for (std::filesystem::directory_iterator it(modDir, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code fec;
        if (!it->is_regular_file(fec)) continue;
        if (_wcsicmp(it->path().extension().wstring().c_str(), L".modinfo") != 0) continue;
        std::ifstream f(it->path(), std::ios::binary);
        if (!f) return {};
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (content.size() >= 3 &&
            static_cast<unsigned char>(content[0]) == 0xEF &&
            static_cast<unsigned char>(content[1]) == 0xBB &&
            static_cast<unsigned char>(content[2]) == 0xBF) {
            content.erase(0, 3);
        }
        return content;
    }
    return {};
}

// XML 的最小词法辅助：只识别这里需要的元素，避免把注释、<FileName> 等相似文本
// 当成真实节点。modinfo 是游戏自己的 XML，完整 DOM 解析没有必要，但必须先去注释。
size_t FindTagEnd(std::string_view text, size_t start) {
    bool quoted = false;
    char quote = 0;
    for (size_t i = start; i < text.size(); ++i) {
        const char ch = text[i];
        if (quoted) {
            if (ch == quote) quoted = false;
        } else if (ch == '\"' || ch == '\'') {
            quoted = true;
            quote = ch;
        } else if (ch == '>') {
            return i;
        }
    }
    return std::string_view::npos;
}

bool IsXmlNameBoundary(char ch) {
    return ch == '>' || ch == '/' || std::isspace(static_cast<unsigned char>(ch)) != 0;
}

size_t FindOpeningTag(std::string_view text, std::string_view name, size_t from) {
    const std::string needle = "<" + std::string(name);
    size_t pos = from;
    while ((pos = text.find(needle, pos)) != std::string_view::npos) {
        const size_t after = pos + needle.size();
        if (after < text.size() && IsXmlNameBoundary(text[after])) return pos;
        pos = after;
    }
    return std::string_view::npos;
}

size_t FindClosingTag(std::string_view text, std::string_view name, size_t from) {
    const std::string needle = "</" + std::string(name);
    size_t pos = from;
    while ((pos = text.find(needle, pos)) != std::string_view::npos) {
        const size_t after = pos + needle.size();
        if (after < text.size() && IsXmlNameBoundary(text[after])) return pos;
        pos = after;
    }
    return std::string_view::npos;
}

std::string StripXmlComments(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    size_t pos = 0;
    while (pos < text.size()) {
        const size_t begin = text.find("<!--", pos);
        if (begin == std::string::npos) {
            out.append(text, pos, std::string::npos);
            break;
        }
        out.append(text, pos, begin - pos);
        const size_t end = text.find("-->", begin + 4);
        if (end == std::string::npos) break;
        pos = end + 3;
    }
    return out;
}

bool HasCriteriaAttribute(std::string_view tag) {
    size_t pos = 0;
    while ((pos = tag.find("criteria", pos)) != std::string_view::npos) {
        const bool nameStart = pos == 0 || std::isspace(static_cast<unsigned char>(tag[pos - 1])) != 0;
        size_t after = pos + 8;
        while (nameStart && after < tag.size() &&
               std::isspace(static_cast<unsigned char>(tag[after])) != 0) {
            ++after;
        }
        if (nameStart && after < tag.size() && tag[after] == '=') return true;
        pos += 8;
    }
    return false;
}

bool IsSelfClosingTag(std::string_view tag) {
    if (tag.empty()) return false;
    size_t end = tag.size();
    while (end > 0 && std::isspace(static_cast<unsigned char>(tag[end - 1])) != 0) --end;
    return end > 0 && tag[end - 1] == '/';
}

// 只接受无 Criteria 的 FrontEndActions/ImportFiles。条件表达式由游戏求值，
// loader 无法安全复现其语义；使用 loader 注入的 UI 应放在无条件 FrontEndActions 中。
std::vector<std::wstring> ParseModinfoUiFiles(const std::string& text) {
    std::vector<std::wstring> out;
    const std::string clean = StripXmlComments(text);
    size_t actionPos = 0;
    while ((actionPos = FindOpeningTag(clean, "FrontEndActions", actionPos)) != std::string_view::npos) {
        const size_t actionTagEnd = FindTagEnd(clean, actionPos);
        if (actionTagEnd == std::string_view::npos) break;
        const std::string_view actionTag(clean.data() + actionPos,
                                         actionTagEnd - actionPos + 1);
        if (IsSelfClosingTag(actionTag)) {
            actionPos = actionTagEnd + 1;
            continue;
        }
        const size_t actionEnd = FindClosingTag(clean, "FrontEndActions", actionTagEnd + 1);
        if (actionEnd == std::string_view::npos) break;
        const std::string_view action(clean.data() + actionTagEnd + 1,
                                      actionEnd - actionTagEnd - 1);

        size_t importPos = 0;
        while ((importPos = FindOpeningTag(action, "ImportFiles", importPos)) != std::string_view::npos) {
            const size_t importTagEnd = FindTagEnd(action, importPos);
            if (importTagEnd == std::string_view::npos) break;
            const std::string_view importTag(action.data() + importPos,
                                             importTagEnd - importPos + 1);
            if (IsSelfClosingTag(importTag)) {
                importPos = importTagEnd + 1;
                continue;
            }
            const size_t importEnd = FindClosingTag(action, "ImportFiles", importTagEnd + 1);
            if (importEnd == std::string_view::npos) break;
            const std::string_view block(action.data() + importTagEnd + 1,
                                         importEnd - importTagEnd - 1);
            const bool conditional = HasCriteriaAttribute(importTag) ||
                FindOpeningTag(block, "Criteria", 0) != std::string_view::npos;

            if (!conditional) {
                size_t filePos = 0;
                while ((filePos = FindOpeningTag(block, "File", filePos)) != std::string_view::npos) {
                    const size_t fileTagEnd = FindTagEnd(block, filePos);
                    if (fileTagEnd == std::string_view::npos) break;
                    const std::string_view fileTag(block.data() + filePos,
                                                   fileTagEnd - filePos + 1);
                    if (IsSelfClosingTag(fileTag)) {
                        filePos = fileTagEnd + 1;
                        continue;
                    }
                    const size_t fileEnd = FindClosingTag(block, "File", fileTagEnd + 1);
                    if (fileEnd == std::string_view::npos) break;
                    const std::string file = TrimAscii(std::string(
                        block.substr(fileTagEnd + 1, fileEnd - fileTagEnd - 1)));

                    size_t slash = file.find_last_of('/');
                    const size_t backslash = file.find_last_of('\\');
                    if (backslash != std::string::npos &&
                        (slash == std::string::npos || backslash > slash)) {
                        slash = backslash;
                    }
                    const std::string fname = (slash == std::string::npos) ? file : file.substr(slash + 1);

                    if (fname.size() > 11 &&
                        _strnicmp(fname.c_str(), kModUiPrefix, 11) == 0 &&
                        fname.size() >= 4 &&
                        _stricmp(fname.c_str() + fname.size() - 4, ".xml") == 0) {
                        const std::wstring wide = ModScan::NarrowToWide(
                            file.substr(0, file.size() - 4));
                        if (!wide.empty()) out.push_back(wide);
                    }
                    const size_t fileCloseEnd = FindTagEnd(block, fileEnd);
                    if (fileCloseEnd == std::string_view::npos) break;
                    filePos = fileCloseEnd + 1;
                }
            }
            const size_t importCloseEnd = FindTagEnd(action, importEnd);
            if (importCloseEnd == std::string_view::npos) break;
            importPos = importCloseEnd + 1;
        }
        const size_t actionCloseEnd = FindTagEnd(clean, actionEnd);
        if (actionCloseEnd == std::string_view::npos) break;
        actionPos = actionCloseEnd + 1;
    }
    return out;
}

// 遍历启用 Mod，解析各 .modinfo 的 FrontEndActions/ImportFiles，收集 FrontEndUI_*.xml base name。
std::vector<std::wstring> FindModUiFiles(HMODULE anchor) {
    std::vector<std::wstring> out;
    const EnabledMods::Snapshot snap = EnabledMods::Load();
    if (!snap.ok) {
        Logger::Log("UiInject: EnabledMods 不可用（%s），跳过所有 Mod UI",
                    snap.error.empty() ? "unknown" : snap.error.c_str());
        return out;
    }

    for (const auto& root : ModScan::CollectScanRoots(anchor)) {
        std::error_code ec;
        if (!std::filesystem::is_directory(root, ec)) continue;
        for (std::filesystem::directory_iterator it(root, ec), end;
             !ec && it != end; it.increment(ec)) {
            std::error_code de;
            if (!it->is_directory(de)) continue;
            const std::filesystem::path modDir = it->path();
            if (!EnabledMods::AllowsPath(snap, modDir.wstring())) continue;

            const std::string modinfo = ReadModinfo(modDir);
            if (modinfo.empty()) continue;
            const auto files = ParseModinfoUiFiles(modinfo);
            out.insert(out.end(), files.begin(), files.end());
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

// 创建 + 挂载 + 初始化一个 LuaContext（加载 baseName.xml + baseName.lua），挂到 parent 下。
// Initialize 走虚表 +0x200（不硬编码地址），xml 的 context 节点由 ForgeUI 正确绑定。
// 返回创建的 ctx（作为后续子 context 的 parent）；失败返回 nullptr。
void* InjectSingleContext(const UiApi& api, void* mgr, void* parent, const wchar_t* baseName) {
    void* ctx = api.alloc(mgr);
    if (!ctx) {
        Logger::Log("UiInject: AllocateControl 返回空（%ls）", baseName);
        return nullptr;
    }
    api.changeParent(ctx, parent);

    void* vt = *reinterpret_cast<void**>(ctx);
    if (!Runtime::IsReadableSpan(vt, kVtInitSlot + sizeof(void*))) {
        Logger::Log("UiInject: LuaContext 虚表不可读（%ls）", baseName);
        return nullptr;
    }
    LuaInitFn init = *reinterpret_cast<LuaInitFn*>(
        reinterpret_cast<uint8_t*>(vt) + kVtInitSlot);
    init(ctx, baseName);
    Logger::Log("UiInject: context 已加载 (%ls)", baseName);
    return ctx;
}

// 注入主体：在 LoadUI 原函数返回后调用。state = MainMenuState*。
void InjectFrontEndUi(void* state) {
    g_lastLoadUiState = state;
    const bool refresh = g_refreshRequested.exchange(false, std::memory_order_acq_rel);

    // 1) 读 UIManager 全局 + FrontEnd context 指针
    void* mgr = nullptr;
    void* frontEnd = nullptr;
    {
        void* slot = ImageAddress::ResolveByRva(kExeImage, kRva_UIManager, sizeof(void*));
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
        return;  // 当前 FrontEnd 已经注入，且没有 Mod toggle 请求
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
    uintptr_t allocAddr = ResolveChecked(kRva_AllocLuaCtx, kSigAlloc, sizeof(kSigAlloc),
                                         "AllocateControl<LuaContext>");
    if (!allocAddr) {
        if (refresh) g_refreshRequested.store(true, std::memory_order_release);
        return;
    }
    api.alloc = reinterpret_cast<AllocLuaContextFn>(allocAddr);

    api.changeParent = reinterpret_cast<ChangeParentFn>(
        GetProcAddress(GetModuleHandleW(nullptr), kChangeParentExport));
    if (!api.changeParent) {
        uintptr_t cpAddr = ResolveChecked(kRva_ChangeParent, kSigChangeParent,
                                          sizeof(kSigChangeParent), "ChangeParent");
        api.changeParent = reinterpret_cast<ChangeParentFn>(cpAddr);
    }
    if (!api.changeParent) {
        if (refresh) g_refreshRequested.store(true, std::memory_order_release);
        return;
    }

    if (!newFrontEnd && refresh && g_rootContext) {
        api.destroyChild = reinterpret_cast<DestroyChildFn>(
            GetProcAddress(GetModuleHandleW(nullptr), kDestroyChildExport));
        if (!api.destroyChild) {
            const uintptr_t destroyAddr = ResolveChecked(kRva_DestroyChild, kSigDestroyChild,
                                                         sizeof(kSigDestroyChild), "DestroyChild");
            api.destroyChild = reinterpret_cast<DestroyChildFn>(destroyAddr);
        }
        if (!api.destroyChild) {
            Logger::Log("UiInject: DestroyChild 不可用，保留当前 UI，跳过刷新");
            g_refreshRequested.store(true, std::memory_order_release);
            return;
        }

        void* oldRoot = g_rootContext;
        g_rootContext = nullptr;
        api.destroyChild(frontEnd, oldRoot);
    }

    // 3) 注入根容器 context（lua 已留空），挂到 FrontEnd 下（其 Name = AdditionalFrontEndUI）
    void* rootCtx = InjectSingleContext(api, mgr, frontEnd, kUiBaseName);
    if (!rootCtx) {
        g_refreshRequested.store(true, std::memory_order_release);
        return;
    }
    g_rootContext = rootCtx;

    // 4) 遍历启用 Mod 的 ImportFiles 声明，加载 FrontEndUI_*.xml，挂到根容器下
    HMODULE anchor = LoaderCore::RuntimeModuleHandle();
    const std::vector<std::wstring> modUis = FindModUiFiles(anchor);
    Logger::Log("UiInject: 发现 %zu 个 Mod UI", modUis.size());
    for (const auto& base : modUis) {
        InjectSingleContext(api, mgr, rootCtx, base.c_str());
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
        // 若异常发生在某个 Mod context 初始化之后，保留已登记的 root，
        // 让下一次刷新先通过 DestroyChild 回收，避免重复挂载。
        g_refreshRequested.store(true, std::memory_order_release);
        Logger::Log("UiInject: 注入异常（已捕获），降级");
    }
    g_injectionInProgress.store(false, std::memory_order_release);
}

// ---- MainMenuState::LoadUI detour ----
void* __fastcall LoadUiDetour(void* state) {
    void* result = g_origLoadUI(state);  // 先让原函数创建 FrontEnd + InvitePopup
    RunInjectionSafely(state);
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

void UiInject::RequestRefresh() {
    g_refreshRequested.store(true, std::memory_order_release);
}

void UiInject::RefreshOnUiThread() {
    if (!g_lastLoadUiState) return;
    RunInjectionSafely(g_lastLoadUiState);
}

bool UiInject::Install() {
    std::lock_guard<std::mutex> hookLock(Runtime::MinHookMutex());

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        Logger::Log("UiInject: MH_Initialize failed: %s", MH_StatusToString(st));
        return false;
    }

    const uintptr_t loadUiAddr = reinterpret_cast<uintptr_t>(
        ImageAddress::ResolveByRva(kExeImage, kRva_LoadUI, 1));
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
