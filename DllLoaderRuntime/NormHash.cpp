// NormHash.cpp — 函数头归一化哈希（基于 HDE x64 反汇编）
//
// 归一化规则（跨版本函数匹配用）：
//   a. 位置相关 disp32 清零 4 字节：RIP-relative（mod==0 且 rm==5）或
//      绝对地址（SIB base==5 且 mod==0）。[rbp/rsp+disp] 等寄存器相对寻址不变。
//   b. rel32 分支（E8 call / E9 jmp / 0F 8x jcc）的 imm32 清零；
//      F_RELATIVE 保证只清分支目标，不碰 push imm32 / mov reg,imm32 等普通常量。
//   c. rel8 短跳（EB / 70-7F）的 imm8 清零。
// 偏移推导：x86-64 指令字节序为 [前缀][opcode][modrm][sib][disp][imm]，
//   disp 紧邻 imm 之前、均位于指令尾部 => immOff = len - immBytes，
//   dispOff = len - immBytes - dispBytes（与 hde64.c 的解析顺序一致）。

#include "pch.h"
#include "NormHash.h"
#include "../third_party/hde/hde64.h"

#include <cstring>

namespace NormHash {

uint64_t Fnv1a64(const uint8_t* data, size_t len) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

namespace {

constexpr size_t kMaxHeadBytes = 32;    // 解码窗口（调用方保证 codeLen <= 32，这里仍兜底）
constexpr size_t kHashBytes = 16;       // 归一化后取前 16 字节哈希
// HDE 在极端情况下（16 前缀 + REX + 0F + modrm + sib + disp32 + imm64）可从解码起点读到
// 约 32 字节；64 字节缓冲区保证指令横跨 codeLen 边界时也不越界（尾部零填充）。
constexpr size_t kDecodeBufferBytes = 64;

// 清零单条已解码指令中与位置相关的字段。buf 指向指令首字节，hs 为解码结果。
void NormalizeInstruction(uint8_t* buf, const hde64s& hs) {
    const size_t len = hs.len;
    if (len == 0 || len > 15) return;

    size_t immBytes = 0;
    if (hs.flags & F_IMM64) immBytes = 8;
    else if (hs.flags & F_IMM32) immBytes = 4;
    else if (hs.flags & F_IMM16) immBytes = 2;
    else if (hs.flags & F_IMM8) immBytes = 1;

    size_t dispBytes = 0;
    if (hs.flags & F_DISP32) dispBytes = 4;
    else if (hs.flags & F_DISP16) dispBytes = 2;
    else if (hs.flags & F_DISP8) dispBytes = 1;

    const size_t immOff = len - immBytes;
    const size_t dispOff = len - immBytes - dispBytes;

    // (a) 位置相关 disp32：RIP-relative（mod==0, rm==5）或绝对地址（SIB base==5, mod==0）
    bool posDisp32 = false;
    if (hs.flags & F_SIB) {
        posDisp32 = (hs.flags & F_DISP32) && hs.modrm_mod == 0 && hs.sib_base == 5;
    } else {
        posDisp32 = (hs.flags & F_DISP32) && hs.modrm_mod == 0 && hs.modrm_rm == 5;
    }
    if (posDisp32 && dispBytes == 4) {
        memset(buf + dispOff, 0, 4);
    }

    // (b)/(c) 相对分支目标清零；F_RELATIVE 仅对 rel8/rel16/rel32 分支置位，
    // 普通常量（push imm32 / mov reg,imm32 等）保持原样。
    if (hs.flags & F_RELATIVE) {
        if (immBytes == 4) memset(buf + immOff, 0, 4);       // rel32
        else if (immBytes == 1) memset(buf + immOff, 0, 1);  // rel8 短跳
        else if (immBytes == 2) memset(buf + immOff, 0, 2);  // 66 前缀 rel16
    }
}

} // namespace

uint64_t NormalizedHeadHash(const uint8_t* code, size_t codeLen) {
    uint8_t buf[kDecodeBufferBytes] = {};
    const size_t n = codeLen < kMaxHeadBytes ? codeLen : kMaxHeadBytes;
    if (code && n) {
        memcpy(buf, code, n);
    }

    size_t off = 0;
    while (off < n) {
        hde64s hs;
        const unsigned int len = hde64_disasm(buf + off, &hs);
        if (hs.flags & F_ERROR) break;                     // 解码失败 -> 停止
        if (len == 0 || len > 15 || hs.len != len) break;  // 防御：长度异常 -> 停止
        if (off + len > n) break;                          // 指令超界 -> 停止
        NormalizeInstruction(buf + off, hs);
        off += len;
    }

    const size_t hashLen = n < kHashBytes ? n : kHashBytes;
    return Fnv1a64(buf, hashLen);
}

} // namespace NormHash
