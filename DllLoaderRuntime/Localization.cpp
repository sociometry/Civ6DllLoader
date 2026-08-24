#include "pch.h"
#include "Localization.h"
#include "../common/Logger.h"
#include <Windows.h>
#include <cstring>

namespace Localization {

GetArgumentCountFunc GetArgumentCountPtr = nullptr;
LookupFunc LookupPtr = nullptr;
PushArgumentFunc PushArgumentPtr = nullptr;
DestructorFunc DestructorPtr = nullptr;
ToUTF8Func ToUTF8Ptr = nullptr;

unsigned int String::GetArgumentCount() const {
    if (!GetArgumentCountPtr) return 0;
    return GetArgumentCountPtr(this);
}

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
    DestructorPtr = reinterpret_cast<DestructorFunc>(
        GetProcAddress(dll, "??1String@Localization@@QEAA@XZ"));
    ToUTF8Ptr = reinterpret_cast<ToUTF8Func>(
        GetProcAddress(dll, "?toUTF8@String@Localization@@QEBAPEBDXZ"));
    if (!ToUTF8Ptr) {
        ToUTF8Ptr = reinterpret_cast<ToUTF8Func>(
            GetProcAddress(dll, "?ToUTF8@String@Localization@@QEBAPEBDXZ"));
    }
    GetArgumentCountPtr = reinterpret_cast<GetArgumentCountFunc>(
        GetProcAddress(dll, "?GetArgumentCount@String@Localization@@QEBAIXZ"));

    // 聚合告警：Localization 各包装自带判空降级（返回空串/nullptr），这里把缺失
    // 的导出名列出来，方便对游戏版本差异定位。空的 ToUTF8 已尝试大小写变体。
    struct { const void* ptr; const char* name; } checks[] = {
        { reinterpret_cast<const void*>(LookupPtr), "Lookup" },
        { reinterpret_cast<const void*>(PushArgumentPtr), "PushArgument" },
        { reinterpret_cast<const void*>(DestructorPtr), "~String" },
        { reinterpret_cast<const void*>(ToUTF8Ptr), "toUTF8/ToUTF8" },
        { reinterpret_cast<const void*>(GetArgumentCountPtr), "GetArgumentCount" },
    };
    for (const auto& c : checks) {
        if (!c.ptr) {
            Logger::Log("Localization import missing: %s (loc wrappers degraded)", c.name);
        }
    }

    Logger::Log(
        "Localization Lookup=%p PushArg=%p Dtor=%p ToUTF8=%p ArgCount=%p",
        reinterpret_cast<void*>(LookupPtr),
        reinterpret_cast<void*>(PushArgumentPtr),
        reinterpret_cast<void*>(DestructorPtr),
        reinterpret_cast<void*>(ToUTF8Ptr),
        reinterpret_cast<void*>(GetArgumentCountPtr));
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
