#include "pch.h"

#include "GameAddress.h"

#include <Windows.h>

namespace GameAddress {

namespace {

struct ExeImageInfo {
    uintptr_t base = 0;
    uintptr_t sizeOfImage = 0;
};

// 进程内恒定，缓存只解析一次。exe 模块句柄在进程生命周期内始终有效，
// PE 头解析失败（理论上不可能）时 base/size 保持 0，所有换算随之降级。
ExeImageInfo LoadExeImageInfo() {
    const HMODULE exe = GetModuleHandleW(nullptr);
    if (!exe) {
        return {};
    }
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(exe);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return {};
    }
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(exe) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return {};
    }
    return { reinterpret_cast<uintptr_t>(exe), nt->OptionalHeader.SizeOfImage };
}

const ExeImageInfo& ExeInfo() {
    static ExeImageInfo info = LoadExeImageInfo();
    return info;
}

}  // namespace

uintptr_t Base() {
    return ExeInfo().base;
}

uintptr_t ImageSize() {
    return ExeInfo().sizeOfImage;
}

bool RvaSpanValid(uintptr_t rva, size_t span) {
    const ExeImageInfo& info = ExeInfo();
    if (info.base == 0 || info.sizeOfImage == 0 || rva == 0) {
        return false;
    }
    // 加法溢出防御：rva 与 span 都是外部输入。
    if (rva >= info.sizeOfImage || span > info.sizeOfImage - rva) {
        return false;
    }
    return true;
}

uintptr_t Function(uintptr_t rva) {
    if (!RvaSpanValid(rva, 1)) {
        return 0;
    }
    return Base() + rva;
}

uintptr_t GlobalVariable(uintptr_t rva) {
    if (!RvaSpanValid(rva, 1)) {
        return 0;
    }
    return Base() + rva;
}

}  // namespace GameAddress
