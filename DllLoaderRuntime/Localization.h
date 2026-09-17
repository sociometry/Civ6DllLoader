#pragma once

#include <cstddef>

#ifndef LOCALIZATION_STRING_BYTES
#define LOCALIZATION_STRING_BYTES 256u
#endif

namespace Localization {

// Opaque storage matching Firaxis Localization::String layout size (over-allocated safely).
class String {
public:
    String();
    ~String();

    // opaque 游戏对象不能按字节复制或移动；只允许通过 out-param API 原地构造/使用。
    String(const String&) = delete;
    String& operator=(const String&) = delete;
    String(String&& other) = delete;
    String& operator=(String&& other) = delete;

    bool PushArgument(const char* arg);
    const char* toUTF8() const;

private:
    alignas(8) unsigned char storage_[LOCALIZATION_STRING_BYTES];
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
