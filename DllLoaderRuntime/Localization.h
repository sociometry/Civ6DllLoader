#pragma once

#include <cstddef>

#ifndef LOCALIZATION_STRING_BYTES
#define LOCALIZATION_STRING_BYTES 256u
#endif

namespace Localization {

class ParameterArgument;
class Language;

// Opaque storage matching Firaxis Localization::String layout size (over-allocated safely).
class String {
public:
    String();
    ~String();

    // 隐式拷贝是 storage 字节浅拷贝（内含游戏侧内部指针），两份对象析构会双重
    // 释放——删除拷贝（M3）。转移语义显式提供：字节搬移 + 源清零（清零态析构
    // 安全：与 LocCreate 的 calloc 语义一致）。
    String(const String&) = delete;
    String& operator=(const String&) = delete;
    String(String&& other) noexcept;
    String& operator=(String&& other) noexcept;

    bool PushArgument(const char* arg);
    const char* toUTF8() const;
    unsigned int GetArgumentCount() const;

private:
    alignas(8) unsigned char storage_[LOCALIZATION_STRING_BYTES];
};

String Lookup(const char* key);

using GetArgumentCountFunc = unsigned int(__fastcall*)(const String* pThis);
using LookupFunc = String*(__cdecl*)(String* pThis, const char* key);
using PushArgumentFunc = bool(__fastcall*)(String* pThis, const char* arg);
using DestructorFunc = void(__fastcall*)(String* pThis);
using ToUTF8Func = const char*(__fastcall*)(const String* pThis);

extern GetArgumentCountFunc GetArgumentCountPtr;
extern LookupFunc LookupPtr;
extern PushArgumentFunc PushArgumentPtr;
extern DestructorFunc DestructorPtr;
extern ToUTF8Func ToUTF8Ptr;

void InitScript();

}  // namespace Localization
