// 本文件在 Loader 工程里按【不使用预编译头】编译（vcxproj 里对该文件设
// PrecompiledHeader=NotUsing），因为它不依赖任何工程私有头 —— 这样
// tools/plugin_version_selftest.cpp 的独立构建可以直接编它，不必伪造 pch.h。
#include "PluginVersion.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwctype>

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
// RT_VERSION 的整型 id。用 MAKEINTRESOURCE 而不是 RT_VERSION 宏：后者是
// MAKEINTRESOURCE(16)，在需要常量表达式的场合不通用。
constexpr WORD kVersionResourceType = 16;

// 从 RT_VERSION 资源块里取 VS_FIXEDFILEINFO 的 Value 字段。
//
// 资源布局（VS_VERSIONINFO）：
//   WORD wLength; WORD wValueLength; WORD wType; WCHAR szKey[]（"VS_VERSION_INFO\0"）
//   -> 4 字节对齐 -> VS_FIXEDFILEINFO Value（wValueLength 非 0 时存在）-> 子块
// 只想拿文件版本，所以不解析子块（StringFileInfo / VarFileInfo）。
bool ExtractFixedFileInfo(const BYTE* data, size_t size, VS_FIXEDFILEINFO& out) {
    if (!data || size < 6) return false;

    WORD valueLength = 0;
    std::memcpy(&valueLength, data + 2, sizeof(valueLength));

    // 跳过 szKey：以 WCHAR 0 结尾，起点固定为偏移 6。
    size_t cursor = 6;
    while (cursor + sizeof(WCHAR) <= size) {
        WCHAR ch = 0;
        std::memcpy(&ch, data + cursor, sizeof(ch));
        cursor += sizeof(WCHAR);
        if (ch == 0) break;
    }
    // 4 字节对齐
    cursor = (cursor + 3u) & ~static_cast<size_t>(3u);

    if (valueLength < sizeof(VS_FIXEDFILEINFO)) return false;
    if (cursor + sizeof(VS_FIXEDFILEINFO) > size) return false;

    std::memcpy(&out, data + cursor, sizeof(out));
    return out.dwSignature == kVsFixedFileInfoSignature;
}

// 只读文件、不加载模块：按数据映射打开，FindResource 取 RT_VERSION。
//
// 为什么不用 GetFileVersionInfo*/VerQueryValue：Loader 自身就是以 version.dll
// 身份注入的代理，导入 VERSION.dll 会解析到自己（自引用），能否工作取决于
// 转发导出是否恰好覆盖到那几个函数 —— 这是启动路径，不值得赌。这里只用
// kernel32，纪律与 RuntimePackage 读 RCDATA 105 完全一致。
bool ReadVersionResource(const std::wstring& path, VS_FIXEDFILEINFO& out) {
    const HMODULE module = LoadLibraryExW(path.c_str(), nullptr,
        LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!module) return false;

    // 枚举 RT_VERSION 下的所有块，取第一个能解析出 VS_FIXEDFILEINFO 的。
    // 不假设资源 id 一定是 1：VS 默认用 1，但手写 .rc 可以取别的值。
    struct EnumContext {
        HMODULE module = nullptr;
        VS_FIXEDFILEINFO* out = nullptr;
        bool found = false;
    } context{module, &out, false};

    EnumResourceNamesW(module, MAKEINTRESOURCEW(kVersionResourceType),
        [](HMODULE handle, LPCWSTR /*type*/, LPWSTR name, LONG_PTR param) -> BOOL {
            auto* ctx = reinterpret_cast<EnumContext*>(param);
            const HRSRC res = FindResourceW(handle, name, MAKEINTRESOURCEW(kVersionResourceType));
            if (!res) return TRUE;
            const DWORD size = SizeofResource(handle, res);
            const HGLOBAL loaded = LoadResource(handle, res);
            const void* bytes = loaded ? LockResource(loaded) : nullptr;
            if (bytes && size && ExtractFixedFileInfo(static_cast<const BYTE*>(bytes), size, *ctx->out)) {
                ctx->found = true;
                return FALSE;   // 已经拿到，停止枚举
            }
            return TRUE;
        },
        reinterpret_cast<LONG_PTR>(&context));

    const bool ok = context.found;
    FreeLibrary(module);
    return ok;
}

}  // namespace

Version ReadFileVersion(const std::wstring& path) {
    if (path.empty()) return kNoVersion;

    VS_FIXEDFILEINFO fixed{};
    if (!ReadVersionResource(path, fixed)) return kNoVersion;

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
