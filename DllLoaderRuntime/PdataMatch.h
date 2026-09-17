#pragma once
#include <cstdint>
#include <Windows.h>

#include "../common/HookAPI.h"   // HookImageId

namespace PdataMatch {
    // 加载 sidecar：多模块容器 v1（Header + ModuleDesc[]，每个模块独立 pdata/符号/槽位/堆/AOB；
    // 单模块符号库也是它，moduleCount=1）。先读旁路文件 Civ6DllLoader.symdb.bin，再 RCDATA 资源 102。
    // 压缩信封 "C6XC"(algo 1=LZMA1) 可解；裸 "C6SD" 直接透传。
    // 返回 false = sidecar 缺失/损坏。注意调用方的处置不同：RuntimeEntry::InitEarly 只记日志继续
    // （缺 sidecar 时该映像不做 RVA 矫正，fail-closed 返回 0，不回退原 RVA）；
    // AttachGameCore 只在"有上下文但建表失败"时拒绝注入。
    bool Init(HMODULE runtimeModule);

    // 是否存在该映像的 sidecar 上下文（决定是否需要为它建档；没有就跳过）。
    bool HasContext(uint32_t imageId);

    // 解析目标映像的 .pdata + 算签名 + 身份判定 + 缓存 + 跨版本匹配，产出该模块 old->new 映射。
    // imageId 取 HookImageId（1=ExeDx11, 2=ExeDx12, 5=GameCoreXP2）。
    bool BuildNewTable(uint32_t imageId, HMODULE target);

    // 矫正 old_rva -> new_rva；无法矫正返回 0。
    uintptr_t CorrectRva(uint32_t imageId, uintptr_t oldRva);

    // 按名矫正（name 是 demangled 或 mangled 名）；无法矫正返回 0。
    uintptr_t CorrectByName(uint32_t imageId, const char* name);

    // 版本指纹（全表 (size,unwind_hash) 聚合 hash），供缓存键。
    uint64_t Fingerprint(uint32_t imageId);

    // 按 vtable 符号名（demangled/mangled）查矫正后的 vtable RVA 与槽位数。
    bool CorrectVTableByName(uint32_t imageId, const char* name, uint32_t& outRva, uint32_t& outSlotCount);
}
