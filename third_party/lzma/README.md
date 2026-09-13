# third_party/lzma —— LZMA SDK 解码器（LzmaDec）

## 来源与许可

- 文件：`LzmaDec.c` / `LzmaDec.h` / `7zTypes.h` / `Compiler.h` / `Precomp.h`
- 出处：Igor Pavlov 的 **LZMA SDK**（本副本取自 UABE 项目 `libCompression/` 的 vendored 拷贝，
  版本标记：LzmaDec.c 2016-05-16、LzmaDec.h 2013-01-18、7zTypes.h 2013-11-12、Compiler.h 2015-08-02）
- 许可：**Public domain**（各文件头部均带 `Igor Pavlov : Public domain`），无附加条件。

## 只用解码器

DllLoaderRuntime 只需要 **解码**：`PdataMatch.cpp` 加载 sidecar 时把 LZMA 压缩信封解开。
编码在构建期由 `tools/compress_sidecar.py` 用 python 标准库 `lzma`（liblzma）完成，所以
`LzmaEnc.c` / `LzFind*.c` / `Threads.c` **不引入**。

## 用法（一次性解压到整块输出缓冲）

`LzmaDecode()` 会把 `dest` 直接当作字典使用（`p.dic = dest; p.dicBufSize = outSize`），
所以对"已知输出大小、一次解完"的场景最省事：

```c
ISzAlloc alloc = { &MyAlloc, &MyFree };      /* malloc/free 包装 */
SizeT destLen = outSize, srcLen = payloadLen;
ELzmaStatus status;
SRes res = LzmaDecode(out, &destLen, payload, &srcLen,
                      props /* 5 字节 */, LZMA_PROPS_SIZE,
                      LZMA_FINISH_END, &status, &alloc);
/* res == SZ_OK && destLen == outSize 才算成功 */
```

约束：**编码端字典大小必须 ≤ 输出缓冲大小**（我们用 16MB 字典 / 44MB 输出，满足）。
