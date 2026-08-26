#include "pch.h"

#include "ImageAddress.h"

#include <Windows.h>

#include <cwchar>
#include <mutex>

namespace ImageAddress {
namespace {

struct ImageState {
    HookImageId id = kHookImageInvalid;
    uintptr_t base = 0;
    size_t sizeOfImage = 0;
    uint64_t generation = 0;
};

std::mutex g_mutex;
ImageState g_gameCore;
uint64_t g_gameCoreGeneration = 0;

size_t ModuleSizeOfImage(HMODULE module) {
    if (!module) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return nt->OptionalHeader.SizeOfImage;
}

const wchar_t* ModuleFilename(HMODULE module, wchar_t (&path)[MAX_PATH]) {
    const DWORD len = GetModuleFileNameW(module, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return nullptr;
    const wchar_t* slash = wcsrchr(path, L'\\');
    return slash ? slash + 1 : path;
}

ImageState LoadExecutable() {
    HMODULE module = GetModuleHandleW(nullptr);
    const HookImageId id = IdentifyExecutable();
    const size_t size = ModuleSizeOfImage(module);
    if (id == kHookImageInvalid || size == 0) return {};
    return { id, reinterpret_cast<uintptr_t>(module), size, 1 };
}

const ImageState& Executable() {
    static const ImageState state = LoadExecutable();
    return state;
}

bool CopyInfo(const ImageState& state, HookImageInfo* outInfo) {
    if (!outInfo || outInfo->structSize < sizeof(HookImageInfo) ||
        state.id == kHookImageInvalid || state.base == 0 || state.sizeOfImage == 0) {
        return false;
    }
    outInfo->image = state.id;
    outInfo->base = state.base;
    outInfo->imageSize = state.sizeOfImage;
    outInfo->generation = state.generation;
    return true;
}

bool IsExecutableId(HookImageId image) {
    return image == kHookImageExeDx11 || image == kHookImageExeDx12;
}

bool IsGameCoreId(HookImageId image) {
    return image == kHookImageGameCoreBase ||
        image == kHookImageGameCoreXP1 ||
        image == kHookImageGameCoreXP2;
}

}  // namespace

HookImageId IdentifyExecutable() {
    HMODULE module = GetModuleHandleW(nullptr);
    wchar_t path[MAX_PATH]{};
    const wchar_t* name = ModuleFilename(module, path);
    if (!name) return kHookImageInvalid;
    if (_wcsicmp(name, L"CivilizationVI.exe") == 0) return kHookImageExeDx11;
    if (_wcsicmp(name, L"CivilizationVI_DX12.exe") == 0) return kHookImageExeDx12;
    return kHookImageInvalid;
}

HookImageId IdentifyGameCore(HMODULE module) {
    wchar_t path[MAX_PATH]{};
    const wchar_t* name = ModuleFilename(module, path);
    if (!name) return kHookImageInvalid;
    if (_wcsicmp(name, L"GameCore_Base_FinalRelease.dll") == 0)
        return kHookImageGameCoreBase;
    if (_wcsicmp(name, L"GameCore_XP1_FinalRelease.dll") == 0)
        return kHookImageGameCoreXP1;
    if (_wcsicmp(name, L"GameCore_XP2_FinalRelease.dll") == 0)
        return kHookImageGameCoreXP2;
    return kHookImageInvalid;
}

bool AttachGameCore(HMODULE module) {
    const HookImageId id = IdentifyGameCore(module);
    const size_t size = ModuleSizeOfImage(module);
    if (!IsGameCoreId(id) || size == 0) return false;

    std::lock_guard<std::mutex> lock(g_mutex);
    ++g_gameCoreGeneration;
    g_gameCore = {
        id,
        reinterpret_cast<uintptr_t>(module),
        size,
        g_gameCoreGeneration
    };
    return true;
}

void DetachGameCore() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_gameCore = {};
}

HookImageId LoadedGameCore() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_gameCore.id;
}

uint64_t GameCoreGeneration() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_gameCoreGeneration;
}

bool IsLoaded(HookImageId image) {
    HookImageInfo info{ sizeof(HookImageInfo) };
    return GetInfo(image, &info);
}

bool GetInfo(HookImageId image, HookImageInfo* outInfo) {
    if (!outInfo) return false;
    if (outInfo->structSize == 0) {
        outInfo->structSize = sizeof(HookImageInfo);
    }
    if (IsExecutableId(image)) {
        const ImageState& exe = Executable();
        return exe.id == image && CopyInfo(exe, outInfo);
    }
    if (IsGameCoreId(image)) {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_gameCore.id == image && CopyInfo(g_gameCore, outInfo);
    }
    return false;
}

void* ResolveByRva(HookImageId image, uintptr_t rva, size_t span) {
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!GetInfo(image, &info) || rva == 0 || span == 0 ||
        rva >= info.imageSize || span > info.imageSize - rva) {
        return nullptr;
    }
    return reinterpret_cast<void*>(info.base + rva);
}

bool Contains(HookImageId image, const void* address) {
    HookImageInfo info{ sizeof(HookImageInfo) };
    if (!address || !GetInfo(image, &info)) return false;
    const uintptr_t p = reinterpret_cast<uintptr_t>(address);
    return p >= info.base && p - info.base < info.imageSize;
}

}  // namespace ImageAddress
