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

static_assert(sizeof(String) == CIV6_HOOK_API_LOC_STRING_BYTES,
    "不透明 String 的尺寸必须与 ABI 头（LocStringBytes/LocCreate）一致");

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
    // 只有 0 参重载是 ToUTF8Func 的形状。另一个导出
    // ?toUTF8@String@Localization@@QEAAPEBDAEAIH@Z 是 (unsigned int&, int) 的重载，不能当
    // 单参函数调用（少传参数会让被调用方按引用解引用调用方的残留寄存器）。因此不设回退：
    // 主符号缺失就按"导入缺失"降级（LocToUtf8 返回 nullptr），由下面的聚合告警记录。
    ToUTF8Ptr = reinterpret_cast<ToUTF8Func>(
        GetProcAddress(dll, "?toUTF8@String@Localization@@QEAAPEBDXZ"));

    // 聚合告警：Localization 各包装自带判空降级（返回空串/nullptr），这里把缺失
    // 的导出名列出来，方便对游戏版本差异定位。
    struct { const void* ptr; const char* name; } checks[] = {
        { reinterpret_cast<const void*>(LookupPtr), "Lookup" },
        { reinterpret_cast<const void*>(PushArgumentPtr), "PushArgument" },
        { reinterpret_cast<const void*>(DestructorPtr), "~String" },
        { reinterpret_cast<const void*>(ToUTF8Ptr), "toUTF8" },
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
        // 不打 GetLastError：GetModuleHandle 失败不保证设置 last error。
        // 指针保留原值在这里安全：该模块是 exe 静态导入、进程内不会卸载，
        // "缺失"只可能发生在首次解析之前（此时四个指针都还是 nullptr）。
        Logger::Log("Localization_FinalRelease.dll not found; loc wrappers degraded");
        return;
    }
    InitImports(dll);
}

}  // namespace Localization
