// 本文件在 Loader 工程里按【不使用预编译头】编译（vcxproj 里对该文件设
// PrecompiledHeader=NotUsing），因为它不依赖任何工程私有头 —— 这样
// tools/plugin_version_selftest.cpp 的独立构建可以直接编它，不必伪造 pch.h。
#include "PluginVersion.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <vector>

// GetFileVersionInfo*/VerQueryValue 在 version.lib 里。用 pragma 而不是 vcxproj 的
// AdditionalDependencies：本文件按 NotUsing 预编译头独立编译，依赖应当跟着源码走。
#pragma comment(lib, "version.lib")

namespace PluginVersion {
namespace {

// 大小写不敏感的路径字典序。与 ModScan 的扫描排序必须用同一套规则，
// 否则会出现"排序认为 A 在前、选举却保留了 B"这种很难看出来的不一致。
bool LessIgnoreCase(const std::wstring& a, const std::wstring& b) {
    const size_t n = (std::min)(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        const wchar_t ca = static_cast<wchar_t>(towlower(a[i]));
        const wchar_t cb = static_cast<wchar_t>(towlower(b[i]));
        if (ca != cb) return ca < cb;
    }
    return a.size() < b.size();
}

// 分组键：小写 basename（含扩展名），与"同名插件"的既有语义一致。
std::wstring GroupKey(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    std::wstring name = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
    for (auto& c : name) c = static_cast<wchar_t>(towlower(c));
    return name;
}

constexpr DWORD kVsFixedFileInfoSignature = 0xFEEF04BDu;

// 从一块 VS_VERSIONINFO 数据里取出 VS_FIXEDFILEINFO（"\" 根块）。
bool ExtractFixed(const void* block, VS_FIXEDFILEINFO& out) {
    VS_FIXEDFILEINFO* fixed = nullptr;
    UINT fixedSize = 0;
    if (!VerQueryValueW(block, L"\\", reinterpret_cast<void**>(&fixed), &fixedSize)) return false;
    if (!fixed || fixedSize < sizeof(VS_FIXEDFILEINFO)) return false;
    if (fixed->dwSignature != kVsFixedFileInfoSignature) return false;
    out = *fixed;
    return true;
}

// 兜底：资源名不是数字 1 的 RT_VERSION。
//
// 为什么需要：GetFileVersionInfo* 只按 MAKEINTRESOURCE(1) 找 RT_VERSION。若 .rc 写成
// `VS_VERSION_INFO VERSIONINFO`（把关键字当资源名），资源本身完全合法、只是挂在字符串名下，
// 这几个 API 一律返回 0 —— 于是插件被版本门禁判成"没有版本"直接丢弃，现象是文件明明有
// VERSIONINFO 却加载不了。1.0 时代手写解析枚举资源名，所以不受影响；换用 Win32 API 后
// 这个差异才暴露出来，实机已在 Civ6BasePlugin / FourRing 上复现（三份 .rc 同名写法）。
//
// 只枚举、只读块数据，仍然不加载模块、不跑 DllMain（LOAD_LIBRARY_AS_DATAFILE 把文件当
// 数据映射，DllMain 不会执行）。
struct FirstVersionName {
    const void* name = nullptr;
    bool found = false;
};

BOOL CALLBACK FindFirstVersionName(HMODULE module, LPCWSTR /*type*/, LPWSTR name, LONG_PTR param) {
    auto* state = reinterpret_cast<FirstVersionName*>(param);
    if (!state || state->found) return FALSE;
    state->name = name;
    state->found = true;
    return FALSE;  // 只取第一个
}

bool ReadFixedFromAnyVersionResource(const std::wstring& path, VS_FIXEDFILEINFO& out) {
    HMODULE module = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
    if (!module) return false;

    FirstVersionName first;
    EnumResourceNamesW(module, MAKEINTRESOURCEW(16), FindFirstVersionName,
        reinterpret_cast<LONG_PTR>(&first));

    bool ok = false;
    if (first.found) {
        HRSRC resource = FindResourceW(module, static_cast<LPCWSTR>(first.name), MAKEINTRESOURCEW(16));
        if (resource) {
            const DWORD size = SizeofResource(module, resource);
            HGLOBAL loaded = LoadResource(module, resource);
            const void* data = loaded ? LockResource(loaded) : nullptr;
            if (data && size >= sizeof(VS_FIXEDFILEINFO)) {
                ok = ExtractFixed(data, out);
            }
        }
    }

    FreeLibrary(module);
    return ok;
}

// 用 Win32 版本 API 读 VS_FIXEDFILEINFO。
//
// 1.0 时代这里是手写解析 RT_VERSION 资源（LoadLibraryExW(AS_DATAFILE) + EnumResourceNamesW
// + 跳过 szKey、4 字节对齐、校验签名），原因写在当时的注释里：Loader 自己就以 version.dll
// 身份注入，导出 VERSION.dll 的函数会解析到自己（自引用），所以只能绕开这几个 API。
// 代理名改成 winmm.dll 之后（见 common/LoaderProtocol.h）这个理由消失了。
//
// **耦合警告**：这段代码从此依赖"Loader 不以 version.dll 为代理名"。若将来代理名回到
// VERSION.dll，这里必须改回资源解析，否则会解析到自己并大概率失败。
//
// 约束（PluginVersion.h:9）：不得加载候选模块、不得跑它的 DllMain。
// GetFileVersionInfoSizeW/GetFileVersionInfoW 只读文件、不执行代码，与原来的
// LoadLibraryExW(AS_DATAFILE) 语义一致；文件不存在或没有 VS_VERSIONINFO 时前者返回 0。
// 返回 0 时再走一次"任意资源名"的兜底，覆盖 .rc 把资源名写成字符串的插件。
bool ReadFixedFileInfo(const std::wstring& path, VS_FIXEDFILEINFO& out) {
    const DWORD size = GetFileVersionInfoSizeW(path.c_str(), nullptr);
    if (size == 0) return ReadFixedFromAnyVersionResource(path, out);

    std::vector<BYTE> buffer(size);
    if (!GetFileVersionInfoW(path.c_str(), 0, size, buffer.data())) {
        return ReadFixedFromAnyVersionResource(path, out);
    }

    if (ExtractFixed(buffer.data(), out)) return true;
    return ReadFixedFromAnyVersionResource(path, out);
}

}  // namespace

Version ReadFileVersion(const std::wstring& path) {
    if (path.empty()) return kNoVersion;

    VS_FIXEDFILEINFO fixed{};
    if (!ReadFixedFileInfo(path, fixed)) return kNoVersion;

    // VS_FIXEDFILEINFO 的布局：MS = (major << 16) | minor，LS = (patch << 16) | build。
    // 拆成四段再按 a.b.c.d 打包，使整数比较等价于版本字典序。
    const Version major = (static_cast<Version>(fixed.dwFileVersionMS) >> 16) & 0xFFFFu;
    const Version minor = static_cast<Version>(fixed.dwFileVersionMS) & 0xFFFFu;
    const Version patch = (static_cast<Version>(fixed.dwFileVersionLS) >> 16) & 0xFFFFu;
    const Version build = static_cast<Version>(fixed.dwFileVersionLS) & 0xFFFFu;
    return (major << 48) | (minor << 32) | (patch << 16) | build;
}

std::string Format(Version version) {
    char text[32];
    sprintf_s(text, "%u.%u.%u.%u",
        static_cast<unsigned>((version >> 48) & 0xFFFFu),
        static_cast<unsigned>((version >> 32) & 0xFFFFu),
        static_cast<unsigned>((version >> 16) & 0xFFFFu),
        static_cast<unsigned>(version & 0xFFFFu));
    return text;
}

std::vector<Decision> Select(std::vector<Candidate> candidates) {
    std::vector<Decision> decisions;
    decisions.reserve(candidates.size());

    struct Best {
        size_t candidateIndex = 0;
        size_t decisionIndex = 0;
        Version version = kNoVersion;
    };
    std::vector<std::pair<std::wstring, Best>> groups;

    for (size_t i = 0; i < candidates.size(); ++i) {
        const Candidate& cand = candidates[i];

        Decision decision;
        decision.path = cand.path;
        decision.version = cand.version;

        // (1) 强制门禁：没有版本号一律不加载。
        if (cand.version == kNoVersion) {
            decision.kind = DecisionKind::DroppedNoVersion;
            decisions.push_back(decision);
            continue;
        }

        const std::wstring key = GroupKey(cand.path);
        auto it = std::find_if(groups.begin(), groups.end(),
            [&key](const std::pair<std::wstring, Best>& g) { return g.first == key; });

        // (2) 该 basename 第一次出现：先假定它胜出。
        if (it == groups.end()) {
            decision.kind = DecisionKind::Kept;
            groups.emplace_back(key, Best{i, decisions.size(), cand.version});
            decisions.push_back(decision);
            continue;
        }

        Best& best = it->second;

        // (3) 新候选版本更高 -> 它成为新的胜出者，原胜出者降级为"被淘汰"。
        if (cand.version > best.version) {
            decision.kind = DecisionKind::Kept;
            decisions[best.decisionIndex].kind = DecisionKind::DroppedLowerVersion;
            decisions[best.decisionIndex].winner = cand.path;
            decisions[best.decisionIndex].winnerVersion = cand.version;
            best.candidateIndex = i;
            best.decisionIndex = decisions.size();
            best.version = cand.version;
            decisions.push_back(decision);
            continue;
        }

        // (4) 版本相同：保留字典序较小的路径。调用方按字典序排好输入，
        //     这里仍显式比较，避免依赖"输入已排序"这个隐含前提。
        const bool newcomerWins = (cand.version == best.version) &&
            LessIgnoreCase(cand.path, decisions[best.decisionIndex].path);

        if (!newcomerWins) {
            decision.kind = (cand.version == best.version) ? DecisionKind::DroppedSameVersion
                                                           : DecisionKind::DroppedLowerVersion;
            decision.winner = decisions[best.decisionIndex].path;
            decision.winnerVersion = best.version;
            decisions.push_back(decision);
            continue;
        }

        decision.kind = DecisionKind::Kept;
        decisions[best.decisionIndex].kind = DecisionKind::DroppedSameVersion;
        decisions[best.decisionIndex].winner = cand.path;
        decisions[best.decisionIndex].winnerVersion = cand.version;
        best.candidateIndex = i;
        best.decisionIndex = decisions.size();
        decisions.push_back(decision);
    }

    return decisions;
}

}  // namespace PluginVersion