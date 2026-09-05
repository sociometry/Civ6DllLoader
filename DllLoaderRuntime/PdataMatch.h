#pragma once
#include <cstdint>
#include <Windows.h>

namespace PdataMatch {
    // 加载 sidecar（先旁路文件 Civ6DllLoader.symdb.bin，再 RCDATA 资源），解析 old 签名表 + 符号表 + vtable 槽位。
    // 返回 false = sidecar 缺失/损坏（调用方应拒绝插件注入）。
    bool Init(HMODULE runtimeModule);

    // 解析 new GameCore 的 .pdata + 算签名 + 版本指纹比对 + 磁盘缓存 + 全表序列对齐，产出 old->new 映射。
    // 返回 false = 无法矫正（调用方应拒绝插件注入，但 GameCore 照常运行）。
    bool BuildNewTable(HMODULE gameCore);

    // 矫正 old_rva -> new_rva；无法矫正返回 0。
    uintptr_t CorrectRva(uintptr_t oldRva);

    // 按名矫正（name 是 demangled 或 mangled 名）；无法矫正返回 0。
    uintptr_t CorrectByName(const char* name);

    // 版本指纹（全表 (size,unwind_hash) 聚合 hash），供缓存键。
    uint64_t Fingerprint();

    // 按 vtable 符号名（demangled/mangled）查矫正后的 vtable RVA 与槽位数。
    // 返回 false = 符号不存在 / 非 vtable / 无法矫正。
    bool CorrectVTableByName(const char* name, uint32_t& outRva, uint32_t& outSlotCount);
}
