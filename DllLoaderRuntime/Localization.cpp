#include "pch.h"
#include "Localization.h"
#include "../common/Logger.h"
#include <Windows.h>
#include <cstring>

namespace Localization {

LookupFunc LookupPtr = nullptr;
PushArgumentFunc PushArgumentPtr = nullptr;
DestructorFunc DestructorPtr = nullptr;
ToUTF8Func ToUTF8Ptr = nullptr;

String::String() {
    std::memset(this, 0, sizeof(*this));
}

String::~String() {
    if (DestructorPtr)
        DestructorPtr(this);
}

bool String::PushArgument(const char* arg) {
    if (!PushArgumentPtr || !arg) return false;
    return PushArgumentPtr(this, arg);
}

const char* String::toUTF8() const {
    if (ToUTF8Ptr)
        return ToUTF8Ptr(this);
    return nullptr;
}

static void InitImports(HMODULE dll) {
    LookupPtr = reinterpret_cast<LookupFunc>(
        GetProcAddress(dll, "?Lookup@Localization@@YA?AVString@1@PEBD@Z"));
    PushArgumentPtr = reinterpret_cast<PushArgumentFunc>(
        GetProcAddress(dll, "?PushArgument@String@Localization@@QEAA_NPEBD@Z"));
    // 导出表实证（dumpbin /EXPORTS Localization_FinalRelease.dll）：
    //   ??1String@Localization@@UEAA@XZ  —— 虚析构（UEAA），非虚 QEAA 不存在
    //   ?toUTF8@String@Localization@@QEAAPEBDXZ —— 非 const 单参版（QEAA），
    //     const 版 QEBA 不存在；另有 ?toUTF8@...QEAAPEBDAEAIH@Z（输出缓冲三参版）
    DestructorPtr = reinterpret_cast<DestructorFunc>(
        GetProcAddress(dll, "??1String@Localization@@UEAA@XZ"));
    ToUTF8Ptr = reinterpret_cast<ToUTF8Func>(
        GetProcAddress(dll, "?toUTF8@String@Localization@@QEAAPEBDXZ"));
    if (!ToUTF8Ptr) {
        ToUTF8Ptr = reinterpret_cast<ToUTF8Func>(
            GetProcAddress(dll, "?toUTF8@String@Localization@@QEAAPEBDAEAIH@Z"));
    }

    // 聚合告警：Localization 各包装自带判空降级（返回空串/nullptr），这里把缺失
    // 的导出名列出来，方便对游戏版本差异定位。空的 ToUTF8 已尝试大小写变体。
    struct { const void* ptr; const char* name; } checks[] = {
        { reinterpret_cast<const void*>(LookupPtr), "Lookup" },
        { reinterpret_cast<const void*>(PushArgumentPtr), "PushArgument" },
        { reinterpret_cast<const void*>(DestructorPtr), "~String" },
        { reinterpret_cast<const void*>(ToUTF8Ptr), "toUTF8/ToUTF8" },
    };
    for (const auto& c : checks) {
        if (!c.ptr) {
            Logger::Log("Localization import missing: %s (loc wrappers degraded)", c.name);
        }
    }

    Logger::Log(
        "Localization Lookup=%p PushArg=%p Dtor=%p ToUTF8=%p",
        reinterpret_cast<void*>(LookupPtr),
        reinterpret_cast<void*>(PushArgumentPtr),
        reinterpret_cast<void*>(DestructorPtr),
        reinterpret_cast<void*>(ToUTF8Ptr));
}

void InitScript() {
    HMODULE dll = GetModuleHandle(TEXT("Localization_FinalRelease.dll"));
    if (!dll) {
        Logger::Log("Localization_FinalRelease.dll not loaded yet err=%lu", GetLastError());
        return;
    }
    InitImports(dll);
}

}  // namespace Localization
