#!/usr/bin/env python3
"""Compress the sidecar container (*.pack.bin) into the runtime envelope.

Envelope (只有一种):
    b"C6XC" + uint32 algo(=1, LZMA1) + uint32 original_size + payload
    payload = .lzma 头（13B: 5B props + 8B 原始大小）+ LZMA1 流

Runtime 端 DllLoaderRuntime/PdataMatch.cpp 的 DecompressSidecar 用 third_party/lzma/LzmaDec
解同一条流；裸 blob（以 "C6SD" 开头）不需要信封。

LZMA1 参数必须与 runtime 一致：props 随 .lzma 头一起写，解码端直接读头。

Measured on the 44.3 MB container (3 modules), 9e dict 16MB: 3,991,784 B (9.0%).

Run:  python compress_sidecar.py [src] [dst]
"""
from __future__ import annotations

import argparse
import hashlib
import lzma
from pathlib import Path

TAG_LZMA = 1
MAGIC = b"C6XC"

# LZMA1 参数（dict 16MB 是 44MB 容器的拐点；再大只省 0.5%）
LZMA_DICT_SIZE = 16 << 20
LZMA_LC, LZMA_LP, LZMA_PB = 3, 0, 2
LZMA_FILTERS = [{
    "id": lzma.FILTER_LZMA1,
    "preset": 9 | lzma.PRESET_EXTREME,
    "dict_size": LZMA_DICT_SIZE,
    "lc": LZMA_LC, "lp": LZMA_LP, "pb": LZMA_PB,
}]


def compress(data: bytes) -> bytes:
    # FORMAT_ALONE = .lzma（13B 头：5B props + 8B 原始大小）+ LZMA1 流
    return lzma.compress(data, format=lzma.FORMAT_ALONE, filters=LZMA_FILTERS)


def decompress(payload: bytes) -> bytes:
    return lzma.decompress(payload, format=lzma.FORMAT_ALONE)


def parse_envelope(blob: bytes):
    """-> (orig_size, payload)"""
    if blob[:4] != MAGIC:
        raise RuntimeError("不是 C6XC 信封")
    tag = int.from_bytes(blob[4:8], "little")
    if tag != TAG_LZMA:
        raise RuntimeError(f"unknown algo tag {tag}")
    orig = int.from_bytes(blob[8:12], "little")
    return orig, blob[12:]


def main() -> int:
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="sidecar container -> C6XC/LZMA1 envelope")
    ap.add_argument("src", nargs="?", default=str(here / "Civ6DllLoader.symdb.pack.bin"))
    ap.add_argument("dst", nargs="?", default=str(here / "Civ6DllLoader.symdb.pack.bin.xp"))
    args = ap.parse_args()

    src, dst = Path(args.src), Path(args.dst)
    if not src.is_file():
        print(f"ERROR: source not found: {src}")
        return 1

    data = src.read_bytes()
    if data[:4] != b"C6SD":
        print(f"ERROR: {src.name} 不是 C6SD 容器")
        return 1
    orig = len(data)
    payload = compress(data)
    out = MAGIC + TAG_LZMA.to_bytes(4, "little") + orig.to_bytes(4, "little") + payload
    dst.write_bytes(out)
    print(f"compressed: {src.name} ({orig} B) -> {dst.name} "
          f"({len(out)} B, {100.0 * len(out) / orig:.1f}%)")

    # 回读校验：走与运行时同一条解析路径
    back_orig, back_payload = parse_envelope(out)
    if back_orig != orig:
        print(f"roundtrip FAIL: envelope orig_size={back_orig} != {orig}")
        return 2
    back = decompress(back_payload)
    if back != data:
        print("roundtrip FAIL: payload mismatch")
        return 2
    print(f"roundtrip OK: SHA256 {hashlib.sha256(back).hexdigest()[:16]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
