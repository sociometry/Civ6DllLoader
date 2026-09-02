#pragma once
#include <cstdint>
#include <cstddef>

namespace NormHash {
    // FNV-1a 64 位哈希
    // hash = 0xcbf29ce484222325; for each byte b: hash = (hash ^ b) * 0x100000001b3（64位回绕）
    uint64_t Fnv1a64(const uint8_t* data, size_t len);

    // 归一化函数头哈希：对函数头字节做 x86-64 归一化后取前 16 字节算 FNV-1a 64
    // code: 函数头字节指针；codeLen: 字节数（调用方保证 = min(size, 32)）
    uint64_t NormalizedHeadHash(const uint8_t* code, size_t codeLen);
}
