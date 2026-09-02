#!/usr/bin/env python3
"""Compress the sidecar (Civ6DllLoader.symdb.bin) with Windows XPRESS_HUFF.

Input:  Civ6DllLoader.symdb.bin  (uncompressed, starts with magic "C6SD")
Output: Civ6DllLoader.symdb.bin.xp (format: [uint32 original_size LE][XPRESS_HUFF data])

Uses cabinet.dll public Compression API (Windows 8+). Zero third-party deps.
The runtime (PdataMatch.cpp) decompresses with the symmetric Decompress path,
so both sides must stay on cabinet.dll XPRESS_HUFF.

Run:  python compress_sidecar.py [src] [dst]
"""
from __future__ import annotations

import ctypes
import hashlib
import sys
from ctypes import wintypes
from pathlib import Path

# COMPRESS_ALGORITHM_XPRESS_HUFF = 4
COMPRESS_ALGORITHM_XPRESS_HUFF = 4

cab = ctypes.windll.cabinet

# HRESULT CreateCompressor(COMPRESS_ALGORITHM, PCOMPRESS_ALLOCATION_ROUTINES, PCOMPRESSOR_HANDLE)
cab.CreateCompressor.argtypes = [
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
]
cab.CreateCompressor.restype = ctypes.c_long

# HRESULT Compress(COMPRESSOR_HANDLE, LPCVOID, SIZE_T, PVOID, SIZE_T, PSIZE_T)
cab.Compress.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
cab.Compress.restype = ctypes.c_long

# HRESULT CreateDecompressor(COMPRESS_ALGORITHM, PCOMPRESS_ALLOCATION_ROUTINES, PDECOMPRESSOR_HANDLE)
cab.CreateDecompressor.argtypes = [
    ctypes.c_uint32,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
]
cab.CreateDecompressor.restype = ctypes.c_long

# HRESULT Decompress(DECOMPRESSOR_HANDLE, LPCVOID, SIZE_T, PVOID, SIZE_T, PSIZE_T)
cab.Decompress.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
cab.Decompress.restype = ctypes.c_long

cab.CloseCompressor.argtypes = [ctypes.c_void_p]
cab.CloseDecompressor.argtypes = [ctypes.c_void_p]

S_OK = 0


def _ok(hr: int) -> bool:
    # S_OK == 0; S_FALSE == 1 (treated as success for these APIs when sizes are nonzero)
    return hr == S_OK or hr == 1


def compress_file(src_path: Path, dst_path: Path) -> None:
    data = src_path.read_bytes()
    orig_size = len(data)

    comp_handle = ctypes.c_void_p()
    hr = cab.CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, None,
                              ctypes.byref(comp_handle))
    if not _ok(hr):
        raise RuntimeError(f"CreateCompressor failed hr=0x{hr & 0xFFFFFFFF:08X}")

    # Worst-case buffer: XPRESS_HUFF may slightly exceed input for incompressible data.
    comp_cap = orig_size + (orig_size // 8) + 0x10000
    comp_buf = ctypes.create_string_buffer(comp_cap)
    comp_size = ctypes.c_size_t(0)

    src_ptr = ctypes.c_char_p(data)
    hr = cab.Compress(comp_handle, src_ptr, orig_size, comp_buf, comp_cap,
                      ctypes.byref(comp_size))
    if not _ok(hr) or comp_size.value == 0:
        cab.CloseCompressor(comp_handle)
        raise RuntimeError(f"Compress failed hr=0x{hr & 0xFFFFFFFF:08X} size={comp_size.value}")

    cab.CloseCompressor(comp_handle)

    # Assemble: [uint32 original_size LE][compressed data]
    out = bytearray(4 + comp_size.value)
    out[0:4] = orig_size.to_bytes(4, "little")
    out[4:] = ctypes.string_at(comp_buf, comp_size.value)
    dst_path.write_bytes(bytes(out))
    print(f"compressed: {src_path.name} ({orig_size} B) -> {dst_path.name} "
          f"({len(out)} B, {100.0 * len(out) / orig_size:.1f}%)")


def verify_roundtrip(src_path: Path, dst_path: Path) -> bool:
    """Decompress dst and compare SHA256 against src."""
    data = src_path.read_bytes()
    packed = dst_path.read_bytes()
    orig_size = int.from_bytes(packed[0:4], "little")
    if orig_size != len(data):
        print(f"roundtrip FAIL: header orig_size={orig_size} != src {len(data)}")
        return False

    dec_handle = ctypes.c_void_p()
    hr = cab.CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, None,
                                ctypes.byref(dec_handle))
    if not _ok(hr):
        print(f"roundtrip FAIL: CreateDecompressor hr=0x{hr & 0xFFFFFFFF:08X}")
        return False

    out_buf = ctypes.create_string_buffer(orig_size)
    used = ctypes.c_size_t(0)
    # IMPORTANT: src must skip the 4-byte header.
    src_body = packed[4:]
    hr = cab.Decompress(dec_handle, ctypes.c_char_p(bytes(src_body)), len(src_body),
                        out_buf, orig_size, ctypes.byref(used))
    cab.CloseDecompressor(dec_handle)

    if not _ok(hr):
        print(f"roundtrip FAIL: Decompress hr=0x{hr & 0xFFFFFFFF:08X} used={used.value}")
        return False
    if used.value != orig_size:
        print(f"roundtrip FAIL: used={used.value} != orig_size={orig_size}")
        return False

    h1 = hashlib.sha256(data).digest()
    h2 = hashlib.sha256(ctypes.string_at(out_buf, orig_size)).digest()
    ok = h1 == h2
    print(f"roundtrip {'OK' if ok else 'FAIL'}: SHA256 match")
    return ok


def main() -> int:
    here = Path(__file__).resolve().parent
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "Civ6DllLoader.symdb.bin"
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else here / "Civ6DllLoader.symdb.bin.xp"

    if not src.is_file():
        print(f"ERROR: source not found: {src}")
        return 1

    compress_file(src, dst)
    if not verify_roundtrip(src, dst):
        print("ERROR: roundtrip verification failed - do not use the output")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
