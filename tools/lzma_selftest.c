/* lzma_selftest.c — 用 runtime 同款解码器（third_party/lzma/LzmaDec.c）与同款压缩信封
 * 解开一个 .xp，写回原始 bin，用来独立验证"资源 → 信封 → LZMA1 → 容器"这条链路。
 *
 * 信封: "C6XC" + u32 algo + u32 originalSize + payload
 *   algo 1 = LZMA1：payload = .lzma 头（5B props + 8B size，size 常为 0xFF.. 未知）+ LZMA1 流
 *
 * build (x64 Native Tools 提示符，或 vcvars64 之后):
 *   cl /nologo /O2 /W3 lzma_selftest.c ..\third_party\lzma\LzmaDec.c ^
 *      /I..\third_party\lzma /Fe:lzma_selftest.exe
 * run:
 *   lzma_selftest.exe <in.xp> <out.bin>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../third_party/lzma/LzmaDec.h"

static void* SzAlloc(void* p, size_t size) { (void)p; return malloc(size); }
static void SzFree(void* p, void* address) { (void)p; free(address); }

static unsigned char* read_all(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    const long sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    rewind(f);
    unsigned char* buf = (unsigned char*)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

static unsigned rd32(const unsigned char* p) {
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <in.xp> <out.bin>\n", argv[0]);
        return 2;
    }
    size_t len = 0;
    unsigned char* data = read_all(argv[1], &len);
    if (!data) { fprintf(stderr, "read failed: %s\n", argv[1]); return 2; }

    if (len < 12 || memcmp(data, "C6XC", 4) != 0) {
        fprintf(stderr, "not a C6XC envelope\n");
        return 3;
    }
    const unsigned algo = rd32(data + 4);
    const unsigned orig_size = rd32(data + 8);
    if (algo != 1) {
        fprintf(stderr, "envelope algo=%u (expected 1 = LZMA1)\n", algo);
        return 3;
    }

    const unsigned char* payload = data + 12;
    const size_t payload_len = len - 12;
    if (payload_len <= 13) { fprintf(stderr, "payload too small\n"); return 3; }

    const unsigned char* props = payload;             /* 5 字节 */
    const unsigned char* stream = payload + 13;       /* 跳过 .lzma 13 字节头 */
    const size_t stream_len = payload_len - 13;

    unsigned char* out = (unsigned char*)malloc(orig_size);
    if (!out) { fprintf(stderr, "oom %u\n", orig_size); return 4; }

    ISzAlloc alloc;
    alloc.Alloc = &SzAlloc;
    alloc.Free = &SzFree;

    SizeT dest_len = (SizeT)orig_size;
    SizeT src_len = (SizeT)stream_len;
    ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
    const SRes res = LzmaDecode(out, &dest_len, stream, &src_len, props, LZMA_PROPS_SIZE,
                                LZMA_FINISH_END, &status, &alloc);
    if (res != SZ_OK || dest_len != (SizeT)orig_size) {
        fprintf(stderr, "LzmaDecode failed res=%d destLen=%llu/%u status=%d\n",
                (int)res, (unsigned long long)dest_len, orig_size, (int)status);
        return 4;
    }

    FILE* f = fopen(argv[2], "wb");
    if (!f) { fprintf(stderr, "write failed\n"); return 4; }
    const int ok = fwrite(out, 1, orig_size, f) == orig_size;
    fclose(f);
    free(out);
    free(data);
    if (!ok) { fprintf(stderr, "short write\n"); return 4; }

    printf("OK algo=1 lzma: %zu B envelope -> %u B raw, stream=%zu, consumed=%llu, status=%d\n",
           len, orig_size, stream_len, (unsigned long long)src_len, (int)status);
    return 0;
}
