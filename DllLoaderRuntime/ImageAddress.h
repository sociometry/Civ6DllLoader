#pragma once

#include "../common/HookAPI.h"

#include <Windows.h>
#include <cstddef>
#include <cstdint>

// 进程内可寻址 PE 映像的统一注册与 RVA 换算。
//
// exe 在首次查询时自动识别；GameCore 由生命周期代码在 attach/detach 时登记。
// 这里不保存任何 RVA 或符号，调用方仍负责按具体 HookImageId 选择偏移。
namespace ImageAddress {

HookImageId IdentifyExecutable();
HookImageId IdentifyGameCore(HMODULE module);

// 成功 attach 后 GameCore 代际递增。失败不会改变当前登记。
bool AttachGameCore(HMODULE module);
void DetachGameCore();

HookImageId LoadedGameCore();
uint64_t GameCoreGeneration();

bool IsLoaded(HookImageId image);
bool GetInfo(HookImageId image, HookImageInfo* outInfo);
void* ResolveByRva(HookImageId image, uintptr_t rva, size_t span);

bool Contains(HookImageId image, const void* address);

}  // namespace ImageAddress
