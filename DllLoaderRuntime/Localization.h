#pragma once

#include "../common/HookAPI.h"   // CIV6_HOOK_API_LOC_STRING_BYTES：ABI 头里的唯一尺寸口径

namespace Localization {

// 不透明的 Firaxis 对象：Loader 只把它 reinterpret_cast 成 API 期望的指针，从不构造/析构
// （生命周期走 HookAPI 的 LocCreate/LocDestroy）。尺寸直接取 ABI 头，避免两处常量漂移。
class String {
public:
    String() = delete;
    ~String() = delete;
    String(const String&) = delete;
    String& operator=(const String&) = delete;

private:
    alignas(8) unsigned char storage_[CIV6_HOOK_API_LOC_STRING_BYTES];
};

using LookupFunc = String*(__cdecl*)(String* pThis, const char* key);
using PushArgumentFunc = bool(__fastcall*)(String* pThis, const char* arg);
using DestructorFunc = void(__fastcall*)(String* pThis);
using ToUTF8Func = const char*(__fastcall*)(const String* pThis);

extern LookupFunc LookupPtr;
extern PushArgumentFunc PushArgumentPtr;
extern DestructorFunc DestructorPtr;
extern ToUTF8Func ToUTF8Ptr;

void InitScript();

}  // namespace Localization
