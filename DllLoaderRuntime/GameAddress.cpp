// GameAddress.cpp — 原始模块（CivilizationVI.exe）地址获取的最基础封装实现。
//
// 当前方案：RVA 相对 GetModuleHandleW(nullptr) 基址，Function/Global 均为 Base() + rva。
// 偏移值与特征码校验由调用方持有；未来换获取方案只改本文件。
#include "pch.h"

#include "GameAddress.h"

namespace GameAddress {

uintptr_t Base() {
    // 进程内恒定，缓存避免重复调用。
    static uintptr_t g_base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    return g_base;
}

uintptr_t Function(uintptr_t rva) {
    const uintptr_t base = Base();
    if (base == 0 || rva == 0) {
        return 0;
    }
    return base + rva;
}

uintptr_t GlobalVariable(uintptr_t rva) {
    const uintptr_t base = Base();
    if (base == 0 || rva == 0) {
        return 0;
    }
    return base + rva;
}

}  // namespace GameAddress
