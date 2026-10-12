#include "pch.h"
#include "AddressResolve.h"

#include <Windows.h>
#include <vector>
#include <cstdint>
#include <mutex>

#include "ImageAddress.h"
#include "PdataMatch.h"
#include "PluginBoundary.h"
#include "PluginDomain.h"
#include "Runtime.h"
#include "../common/Logger.h"

// 从 Civ6DLLHookLoaderAPI.cpp 拆出（阶段 1；阶段 6 补入 5 个 *Impl）。
//
// 【命名】：本模块输出一律是地址，故叫 AddressResolve 而非 SymbolResolve。
// 符号名只是四条输入路径之一；符号库归 PdataMatch。详见 AddressResolve.h。
//
// static 的取舍（REFACTOR_PLAN.md §4.4）：
//   * ResolveSectionRva / *Core / *Impl / GetSymbolDb*Impl —— 外部链接
//     （HookAPI 表与其它模块要用）；
//   * ReadVTableSlotSafe / ExeMatchesAnchor / InternalToolApi —— 保持 static
//     （只被本 TU 调用；InternalToolApi 另外被同 TU 的 LoaderCore::* 调用）。

using namespace std;

namespace AddressResolve {

// 按段名（.text/.idata/.rdata/.data；PE 段名为 8 字节非 NUL 终止数组）定位镜像内段的
// RVA 与大小（大小 = max(SizeOfRawData, VirtualSize)）。找不到段返回 false。
bool ResolveSectionRva(HookImageId image, const char* sectionName,
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

// 内部分辨核心：不做插件边界校验、不加插件生命周期锁。
// Loader 自己（ResolveExeTarget / LoaderHooks / UiInject）走 Core；插件走母体的 *Impl。
// 这样游戏线程在 LoadDLL detour 里解析自家 hook 目标时，不会去拿那把可能被卡住的插件锁。
void* ResolveByRvaCore(HookImageId image, uintptr_t rva, size_t span) {
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

// 内部核心：name 由调用方保证可读（Loader 用字面量 / 插件先抄写）。
void* ResolveByNameCore(HookImageId image, const char* nameSafe) {
    if (!ImageAddress::IsLoaded(image)) return nullptr;

    // 每个模块有各自 sidecar 上下文（容器：exe/GameCore 各自符号表）。
    if (!PdataMatch::HasContext(image)) {
        Logger::Log("ResolveByName: no symbol database for image=%u name=%s",
            static_cast<unsigned>(image), nameSafe);
        return nullptr;
    }

    // PdataMatch：sidecar 符号表存旧映像 RVA，按名矫正到当前映像后解析。
    const uintptr_t corrected = PdataMatch::CorrectByName(image, nameSafe);
    if (corrected == 0) {
        Logger::Log("ResolveByName: no symbol for image=%u name=%s",
            static_cast<unsigned>(image), nameSafe);
        return nullptr;
    }
    void* result = ImageAddress::ResolveByRva(image, corrected, 1);
    if (!result) {
        Logger::Log("ResolveByName: out-of-range RVA image=%u name=%s rva=0x%llX",
            static_cast<unsigned>(image), nameSafe,
            static_cast<unsigned long long>(corrected));
    }
    return result;
}

// 内部核心：pattern 由调用方保证可读（Loader 用字面量 / 插件先抄写）。
void* ResolveByPatternCore(HookImageId image, const char* pattern, HookImageSection section,
    uint32_t index) {
    if (index == 0) index = 1;   // 0 视为默认首命中
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

    // PE 头声明的 SizeOfImage 不保证整段都已提交：声明值大于实际提交页时，线性扫描会读到
    // 未提交/守卫页，这里是裸指针访问且没有 SEH，一次访问违例就是整个游戏进程崩溃。
    // 扫描前对范围走一次 VirtualQuery（对任意地址都安全），不可读就拒绝（失败即关闭）。
    if (!Runtime::IsReadableSpan(reinterpret_cast<const void*>(searchBase), searchSize)) {
        Logger::Log("ResolveByPattern: region unreadable image=%u section=%d base=%p size=%zu",
            static_cast<unsigned>(image), static_cast<int>(section),
            reinterpret_cast<const void*>(searchBase), searchSize);
        return nullptr;
    }

    // 线性搜索第 index 个命中（mask 0 位 = 通配）。多命中场景由调用方用 index 消歧：
    // 例如 GetRuleSet 那种函数体完全相同的兄弟函数，只能靠升序命中表的位置区分。
    const uint8_t* basePtr = reinterpret_cast<const uint8_t*>(searchBase);
    const size_t limit = searchSize - bytes.size() + 1;
    uint32_t found = 0;
    for (size_t i = 0; i < limit; ++i) {
        bool match = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if ((basePtr[i + j] & masks[j]) != bytes[j]) { match = false; break; }
        }
        if (!match) continue;
        if (++found < index) continue;
        Logger::Log("ResolveByPattern: hit image=%u section=%d rva=0x%llX index=%u",
            static_cast<unsigned>(image), static_cast<int>(section),
            static_cast<unsigned long long>(i), index);
        return const_cast<uint8_t*>(basePtr + i);
    }
    Logger::Log("ResolveByPattern: no hit image=%u section=%d index=%u (found %u) pattern=\"%s\"",
        static_cast<unsigned>(image), static_cast<int>(section), index, found, pattern);
    return nullptr;
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
// 内部核心：vtableSymbol 由调用方保证可读。
void* ResolveByVTableCore(HookImageId image, const char* vtableSymbol, uint32_t index) {
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

// ---------------- 符号库状态查询（GetSymbolDbState / GetSymbolDbMatchRatio） ----------------
// 纯查询：不取插件生命周期锁，也不碰插件表——状态来自 PdataMatch 自己的快照锁。
// image 是标量，没有跨模块指针可解引用，因此不需要 RequirePluginOwner / 域门。
HookApiSymbolDbState GetSymbolDbStateImpl(HookImageId image) {
    switch (PdataMatch::GetMatchState(static_cast<uint32_t>(image))) {
        case PdataMatch::MatchState::NoContext:   return kHookApiDbNoContext;
        case PdataMatch::MatchState::NotBuilt:    return kHookApiDbNotReady;
        case PdataMatch::MatchState::BuildFailed: return kHookApiDbBuildFailed;
        case PdataMatch::MatchState::Identical:   return kHookApiDbIdentical;
        case PdataMatch::MatchState::CrossVersion:return kHookApiDbCrossVersion;
        default:                                  return kHookApiDbNoContext;
    }
}

double GetSymbolDbMatchRatioImpl(HookImageId image) {
    return PdataMatch::GetMatchRatio(static_cast<uint32_t>(image));
}

// exe 版本锚（SizeOfImage + FileHeader.TimeDateStamp）：无符号库时判断"能否直接信任原始 RVA"。
// 由 tools/symdb.py aob 的同一份逆向数据得出；游戏更新后这里会失配 -> 只走 AOB 兜底。
//
// SizeOfImage 必须用【去 DRM 视图】（PdataMatch::NormalizedSizeOfImage）：下面的常量取自
// 去 DRM 的 sidecar 数据，而 DRM 剥离只删末尾 .bind 段、TimeDateStamp 与 .pdata 逐字节不变。
// 实测同一构建的两版 exe：修改版 DX11 0x36D1000 / 原版 0x3704000，TDS 都是 0x667C6FC6 ——
// 直接比原始值会让跑原版 exe 的用户恒定失配，RVA 快路径失效。
namespace {
constexpr uint32_t kAnchorDx11SizeOfImage = 0x36D1000;
constexpr uint32_t kAnchorDx11TimeDate   = 0x667C6FC6;
constexpr uint32_t kAnchorDx12SizeOfImage = 0xFE22000;
constexpr uint32_t kAnchorDx12TimeDate   = 0x667C7363;
}

// 只被 ResolveExeTarget 使用，故保持 static（随本文件一起，不再跨 TU）。
static bool ExeMatchesAnchor(HookImageId image) {
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!ImageAddress::GetInfo(image, &info) || !info.base || !info.imageSize) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(info.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(info.base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const uint32_t sizeOfImage = PdataMatch::NormalizedSizeOfImage(nt);
    const uint32_t timeDate = nt->FileHeader.TimeDateStamp;
    if (image == kHookImageExeDx11) {
        return sizeOfImage == kAnchorDx11SizeOfImage && timeDate == kAnchorDx11TimeDate;
    }
    if (image == kHookImageExeDx12) {
        return sizeOfImage == kAnchorDx12SizeOfImage && timeDate == kAnchorDx12TimeDate;
    }
    return false;
}

// 只给 Loader 内部使用的"无锁取址表"：解析类入口指向不加插件锁的 Core，其余字段保持
// nullptr —— 这张表【绝不交给插件】。这样 common/HookAPI.h 里的 inline 取址工具
// （HookCurrentExeImage / ResolveByHookInfo / ResolveDataByAob）
// 可以直接复用，既不经过插件表、也不加插件生命周期锁。
// 这些 inline 工具实际只用到下面这五个入口。
// 契约：只读。返回非 const 指针只是为了配合 header 里 HookAPI* 的签名。
//
// 保持 static（只被本 TU 调用：ResolveDataByAobCore / ResolveExeTarget）。
// 命名空间内的 static 函数仍可用限定名在本 TU 内引用（AddressResolve::InternalToolApi）。
static HookAPI* InternalToolApi() {
    static const HookAPI api = [] {
        HookAPI t{};
        t.apiVersion = CIV6_HOOK_API_VERSION;
        t.structSize = static_cast<uint32_t>(sizeof(HookAPI));
        t.GetImageInfo = &ImageAddress::GetInfo;
        t.ResolveByRva = &ResolveByRvaCore;
        t.ResolveByName = &ResolveByNameCore;
        t.ResolveByPattern = &ResolveByPatternCore;
        t.ResolveByVTable = &ResolveByVTableCore;
        return t;
    }();
    return const_cast<HookAPI*>(&api);
}



// ================= 插件侧入口（阶段 6 从母体归位） =================
// 先过 PluginDomain 的归属/域门，再调上面的 *Core。

// ==== ResolveByRvaImpl ====
// 插件入口：参数全是标量（没有需要锁外抄写的插件内存），只需加锁。
void* ResolveByRvaImpl(HookImageId image, uintptr_t rva, size_t span) {
    // 地址开放性门：调用方类别 × 解析目标映像域（本入口没有 loader 内部调用者，内部走 *Core）。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByRva");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByRva")) return nullptr;
    lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
    PluginBoundary::LoaderLockScope pbLockScope;
    return AddressResolve::ResolveByRvaCore(image, rva, span);
}

// ==== ResolveByNameImpl ====
void* ResolveByNameImpl(HookImageId image, const char* name) {
    // 地址开放性门（RequirePluginOwner 只做模块归属查询，不解引用插件指针）。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByName");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByName")) return nullptr;
    if (!name || !*name) return nullptr;

    // name 是插件内存：锁外先抄进 Loader 自有 string，锁内只碰副本
    // （PdataMatch 查表与日志都读它）。坏指针在这里失败，此时没有任何锁被持有。
    std::string nameCopy;
    if (!PluginBoundary::CopyCString(name, nameCopy) || nameCopy.empty()) {
        Logger::Log("ResolveByName rejected: name pointer unreadable");
        return nullptr;
    }

    lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
    PluginBoundary::LoaderLockScope pbLockScope;
    return AddressResolve::ResolveByNameCore(image, nameCopy.c_str());
}

// ==== ResolveByRvaExImpl ====
void* ResolveByRvaExImpl(HookImageId image, uintptr_t rva, size_t span, HookImageSection section) {
    // 地址开放性门：调用方类别 × 解析目标映像域。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByRvaEx");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByRvaEx")) return nullptr;
    lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
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
    if (!AddressResolve::ResolveSectionRva(image, sectionName, &sectionRva, &sectionSize)) {
        Logger::Log("ResolveByRvaEx: section %s not found image=%u",
            sectionName, static_cast<unsigned>(image));
        return nullptr;
    }
    return ImageAddress::ResolveByRva(image, sectionRva + rva, span);
}

// ==== ResolveByPatternImpl ====
void* ResolveByPatternImpl(HookImageId image, const char* patternIn, HookImageSection section,
    uint32_t index) {
    // 地址开放性门（RequirePluginOwner 只做模块归属查询，不解引用插件指针）。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByPattern");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByPattern")) return nullptr;
    if (!patternIn || !*patternIn) {
        Logger::Log("ResolveByPattern: empty pattern");
        return nullptr;
    }
    // pattern 是插件内存：锁外抄写（原实现在锁内逐字节遍历它，一个没有结尾符的指针
    // 会一路读到出错 -> lock_guard 不析构 -> 锁永久泄漏），锁内只碰副本。
    std::string patternCopy;
    if (!PluginBoundary::CopyCString(patternIn, patternCopy) || patternCopy.empty()) {
        Logger::Log("ResolveByPattern rejected: pattern pointer unreadable");
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
    PluginBoundary::LoaderLockScope pbLockScope;
    return AddressResolve::ResolveByPatternCore(image, patternCopy.c_str(), section, index);
}

// ==== ResolveByVTableImpl ====
void* ResolveByVTableImpl(HookImageId image, const char* vtableSymbolIn, uint32_t index) {
    // 地址开放性门（RequirePluginOwner 只做模块归属查询，不解引用插件指针）。
    auto caller = PluginDomain::RequirePluginOwner(_ReturnAddress(), "ResolveByVTable");
    if (!caller || !PluginDomain::IsImageOpenToCaller(caller->category, image, "ResolveByVTable")) return nullptr;
    if (!vtableSymbolIn || !*vtableSymbolIn) {
        Logger::Log("ResolveByVTable rejected: empty vtable symbol");
        return nullptr;
    }
    // vtableSymbol 是插件内存：锁外抄写（锁内会被 PdataMatch 查表与日志反复读取）。
    std::string symbolCopy;
    if (!PluginBoundary::CopyCString(vtableSymbolIn, symbolCopy) || symbolCopy.empty()) {
        Logger::Log("ResolveByVTable rejected: symbol pointer unreadable");
        return nullptr;
    }
    lock_guard<std::recursive_mutex> lock(LoaderCore::LifecycleMutex());
    PluginBoundary::LoaderLockScope pbLockScope;
    return AddressResolve::ResolveByVTableCore(image, symbolCopy.c_str(), index);
}

}  // namespace AddressResolve

// ---------------- LoaderCore 入口（声明在 LoaderCore.h） ----------------
// 这三个是 Loader 自身用的入口，母体与其他 TU 都按 LoaderCore:: 调用。

// 当前进程 exe 的映像 id：与 common/HookAPI.h 的 HookCurrentExeImage 同语义
// （GetImageInfo 是否有效），但直连 ImageAddress，不经过插件表/插件锁。
HookImageId LoaderCore::CurrentExeImage() {
    if (ImageAddress::IsLoaded(kHookImageExeDx11)) return kHookImageExeDx11;
    if (ImageAddress::IsLoaded(kHookImageExeDx12)) return kHookImageExeDx12;
    return kHookImageInvalid;
}

// Loader 内部解 exe 全局数据槽：算法与 common/HookAPI.h 的 ResolveDataByAob 完全相同，
// 只是走无锁内部表。供 LoaderHooks / UiInject 使用。
void* LoaderCore::ResolveDataByAobCore(HookImageId image, const char* aob, uint32_t index) {
    return ResolveDataByAob(AddressResolve::InternalToolApi(), image, aob, index);
}

void* LoaderCore::ResolveExeTarget(const HookInfoExe& info, size_t span) {
    // 走内部无锁表：游戏线程在 LoadDLL detour 里解析自家 hook 目标，不拿插件生命周期锁。
    const HookImageId image = CurrentExeImage();
    if (image == kHookImageInvalid) return nullptr;
    const HookInfo& entry = (image == kHookImageExeDx12) ? info.dx12 : info.dx11;
    const bool haveContext = PdataMatch::HasContext(image);
    if (haveContext || AddressResolve::ExeMatchesAnchor(image)) {
        if (void* p = ResolveByHookInfo(AddressResolve::InternalToolApi(), image, entry, span)) return p;
        Logger::Log("ResolveExeTarget: image=%u kind=%d unresolved (rva=0x%llX aob=%s)",
            static_cast<unsigned>(image), static_cast<int>(entry.kind),
            static_cast<unsigned long long>(entry.kind == kHookInfoRva ? entry.u.rva : 0),
            entry.aob ? "yes" : "no");
        return nullptr;
    }
    Logger::Log("ResolveExeTarget: [WARN] image=%u no symbol DB and PE identity != anchor; "
                "RVA path skipped, AOB fallback only", static_cast<unsigned>(image));
    if (entry.aob && *entry.aob) {
        return AddressResolve::InternalToolApi()->ResolveByPattern(
            image, entry.aob, kSectionText, entry.index);
    }
    return nullptr;
}
