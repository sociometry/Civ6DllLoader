#include "pch.h"
#include "Localization.h"
#include "Logger.h"
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

String Lookup(const char* key) {
    String result;
    if (LookupPtr && key)
        LookupPtr(&result, key);
    return result;
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
