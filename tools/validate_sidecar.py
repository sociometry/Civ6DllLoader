#!/usr/bin/env python3
"""Validate a sidecar container the same way the runtime does (C6SD v1 + C6XC/LZMA1).

Usage:
  python validate_sidecar.py <file.bin|file.xp> [...]

Checks performed (mirrors DllLoaderRuntime/PdataMatch.cpp):
  * magic + version == 1
  * container header + module table bounds, per-module block extents
  * pdata 表 (16B/条): 范围、size != 0、按 begin_rva 升序
  * 符号表 (32B/条): 范围、kind in (0,1)、vtableSlotCount <= 65535、old_rva != 0
  * vtable 槽位表 (8B/条): 范围、被符号消费的总数 == 声明值
  * 字符串堆: 名字 NUL 结尾、offset 在范围内、不重复
  * AOB 表: 变长 (u32 bodySize <= 64 + body + mask) 走完且完全消费
  * 压缩信封: 只认 C6XC + algo 1 (LZMA1)
Exit code 0 = all files valid.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

MAGIC = b"C6SD"
VERSION = 1
MAX_AOB = 64
PDATA_ENTRY = 16
SYMBOL_ENTRY = 32
VTABLE_SLOT = 8
DESC = 64
CTR_HDR = 32

IMAGE_NAMES = {1: "ExeDx11", 2: "ExeDx12", 5: "GameCoreXP2"}


def decompress_xp(data: bytes) -> bytes:
    """C6XC + u32 algo(=1, LZMA1) + u32 original_size + payload -> 原始容器字节。"""
    import lzma

    if data[:4] != b"C6XC":
        raise RuntimeError("不是 C6XC 信封")
    tag = struct.unpack_from("<I", data, 4)[0]
    orig = struct.unpack_from("<I", data, 8)[0]
    if tag != 1:
        raise RuntimeError(f"unknown compress algo tag {tag}")
    out = lzma.decompress(data[12:], format=lzma.FORMAT_ALONE)
    if len(out) != orig:
        raise RuntimeError(f"size mismatch: {len(out)} != {orig}")
    return out


class Module:
    """一个模块的检查结果（已按容器范围校验）。"""

    def __init__(self, image_id, size_of_image, timestamp, pdata, symbols, slots,
                 heap, aob):
        self.image_id = image_id
        self.size_of_image = size_of_image
        self.timestamp = timestamp
        self.pdata = pdata          # list[(begin, size, unwind_hash)]
        self.symbols = symbols      # list[dict]
        self.slots = slots          # list[(slot_offset, slot_rva, name)]
        self.heap = heap            # bytes
        self.aob = aob              # list[(rva, body, mask)]


def _check_extents(name: str, off: int, count_bytes: int, size: int, errors: list) -> bool:
    if off + count_bytes > size:
        errors.append(f"{name}: extent [{off}, {off + count_bytes}) exceeds blob size {size}")
        return False
    return True


def parse_module(blob: bytes, f, errors: list, tag: str):
    """检查容器里的一个模块；返回 (Module, slots_used, aob_used) 或 None。"""
    (image_id, size_of_image, timestamp, pdata_off, pdata_count, sym_off, sym_count,
     vt_off, vt_slots, heap_off, heap_size, aob_off, aob_size) = f[:13]

    if not _check_extents("pdata", pdata_off, pdata_count * PDATA_ENTRY, len(blob), errors):
        return None
    if not _check_extents("symbols", sym_off, sym_count * SYMBOL_ENTRY, len(blob), errors):
        return None
    if not _check_extents("heap", heap_off, heap_size, len(blob), errors):
        return None
    if not _check_extents("vtable", vt_off, vt_slots * VTABLE_SLOT, len(blob), errors):
        return None
    if not _check_extents("aob", aob_off, aob_size, len(blob), errors):
        return None

    pdata = []
    for i in range(pdata_count):
        begin, size, unwind = struct.unpack_from("<IIQ", blob, pdata_off + i * PDATA_ENTRY)
        if size == 0:
            errors.append(f"{tag}: pdata[{i}]: zero size")
        pdata.append((begin, size, unwind))
    if pdata != sorted(pdata):
        errors.append(f"{tag}: pdata: not sorted by begin_rva")

    heap = blob[heap_off:heap_off + heap_size]

    def read_str(off: int) -> str:
        if off == 0 or off >= heap_size:
            return ""
        end = heap.find(b"\0", off)
        if end < 0:
            errors.append(f"{tag}: heap: name at {off} not NUL-terminated")
            return ""
        return heap[off:end].decode("utf-8", "replace")

    symbols = []
    symbols_seen = set()
    slots = []
    slot_cursor = 0
    aob_cursor = aob_off
    aob_entries = []
    aob_broken = False

    for i in range(sym_count):
        dem_off, man_off, old_rva, kind, slot_count, reserved, head_hash, r2, r3 = \
            struct.unpack_from("<IIIBHBQII", blob, sym_off + i * SYMBOL_ENTRY)
        if slot_count > 0xFFFF:
            errors.append(f"{tag}: symbol[{i}]: slotCount {slot_count} exceeds u16")
        name = read_str(dem_off) or read_str(man_off)
        if old_rva == 0 and name:
            errors.append(f"{tag}: symbol[{i}]: {name} has zero old_rva")
        if name and name in symbols_seen:
            errors.append(f"{tag}: symbol[{i}]: duplicate name {name}")
        symbols_seen.add(name)
        if kind not in (0, 1):
            errors.append(f"{tag}: symbol[{i}]: unknown kind {kind}")
        if kind == 1 and slot_count:
            for k in range(slot_count):
                if (slot_cursor + k) >= vt_slots:
                    errors.append(f"{tag}: symbol[{i}]: vtable slots overrun declared count")
                    break
                slot_off, slot_rva = struct.unpack_from(
                    "<II", blob, vt_off + (slot_cursor + k) * VTABLE_SLOT)
                slots.append((slot_off, slot_rva, name))
            slot_cursor += slot_count
        elif kind == 0 and aob_size and not aob_broken:
            if aob_cursor + 4 > aob_off + aob_size:
                errors.append(f"{tag}: aob: truncated bodySize for {name}")
                aob_broken = True
            else:
                body_size = struct.unpack_from("<I", blob, aob_cursor)[0]
                aob_cursor += 4
                span = body_size * 2
                if body_size > MAX_AOB:
                    errors.append(f"{tag}: aob[{name}]: bodySize {body_size} > {MAX_AOB}")
                if aob_cursor + span > aob_off + aob_size:
                    errors.append(f"{tag}: aob[{name}]: body out of range")
                    aob_broken = True
                else:
                    body = blob[aob_cursor:aob_cursor + body_size]
                    mask = blob[aob_cursor + body_size:aob_cursor + span]
                    aob_cursor += span
                    aob_entries.append((old_rva, body, mask))
        symbols.append(dict(index=i, name=name, old_rva=old_rva, kind=kind,
                            slot_count=slot_count, dem_off=dem_off, man_off=man_off,
                            head_hash=head_hash))
    if not aob_broken and aob_cursor != aob_off + aob_size:
        errors.append(f"{tag}: aob: table not fully consumed "
                      f"(cursor={aob_cursor} end={aob_off + aob_size})")

    return (Module(image_id, size_of_image, timestamp, pdata, symbols, slots,
                   heap, aob_entries), slot_cursor, aob_cursor - aob_off)


def parse_container(blob: bytes, errors: list, tag: str) -> list:
    if len(blob) < CTR_HDR:
        errors.append(f"{tag}: container too small")
        return []
    (magic, version, module_count, table_off, table_size, data_off, flags, reserved) = \
        struct.unpack_from("<4sIIIIIII", blob, 0)
    if magic != MAGIC:
        errors.append(f"{tag}: bad magic {magic!r}")
        return []
    if version != VERSION:
        errors.append(f"{tag}: unexpected version {version}")
        return []
    if not (1 <= module_count <= 8):
        errors.append(f"{tag}: bad moduleCount {module_count}")
        return []
    if table_size < module_count * DESC or table_off + table_size > len(blob):
        errors.append(f"{tag}: bad module table (off={table_off} size={table_size})")
        return []

    modules = []
    for i in range(module_count):
        f = struct.unpack_from("<16I", blob, table_off + i * DESC)
        image_id = f[0]
        name = IMAGE_NAMES.get(image_id, f"image{image_id}")
        print(f"  [{i}] {name}: SizeOfImage=0x{f[1]:X} TDS=0x{f[2]:08X} "
              f"pdata={f[4]} symbols={f[6]} vtableSlots={f[8]} "
              f"heap={f[10]} aob={f[12]}")
        if image_id not in IMAGE_NAMES:
            errors.append(f"{tag}: unknown imageId {image_id}")
        if f[1] == 0 or f[2] == 0:
            errors.append(f"{tag}/{name}: missing PE identity (SizeOfImage/TDS)")
        if f[13:] != (0, 0, 0):
            print(f"      note: reserved = {f[13:]} (expected 0)")
        res = parse_module(blob, f, errors, f"{tag}/{name}")
        if res is None:
            continue
        mod, slots_used, aob_used = res
        if slots_used != f[8]:
            errors.append(f"{tag}/{name}: slot array declared {f[8]} but symbols consume {slots_used}")
        if aob_used != f[12]:
            errors.append(f"{tag}/{name}: AOB declared {f[12]} but walked {aob_used}")
        modules.append((name, mod, slots_used, aob_used))
    return modules


def validate(path: Path) -> bool:
    raw = path.read_bytes()
    print(f"== {path.name} ({len(raw)} B)")
    errors: list = []
    blob = raw
    if not raw.startswith(MAGIC):
        try:
            blob = decompress_xp(raw)
            print(f"   C6XC/LZMA1 -> {len(blob)} B (magic {blob[:4]!r})")
        except Exception as exc:  # noqa: BLE001
            print(f"   FAIL: decompress: {exc}")
            return False
    if not blob.startswith(MAGIC):
        print("   FAIL: bad magic")
        return False

    modules = parse_container(blob, errors, path.name)
    for name, mod, slots, aob in modules:
        print(f"      {name}: pdata={len(mod.pdata)} symbols={len(mod.symbols)} "
              f"slots={slots} aob_entries={len(mod.aob)} heap={len(mod.heap)}")

    if errors:
        print(f"   FAIL ({len(errors)} problem(s)):")
        for e in errors[:40]:
            print(f"     - {e}")
        if len(errors) > 40:
            print(f"     ... and {len(errors) - 40} more")
        return False
    print("   OK")
    return True


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass
    args = sys.argv[1:]
    if not args:
        here = Path(__file__).resolve().parent
        args = [str(here / "Civ6DllLoader.symdb.pack.bin")]
    ok = True
    for a in args:
        path = Path(a)
        if not path.is_file():
            print(f"missing: {path}")
            ok = False
            continue
        ok = validate(path) and ok
    print("\nALL VALID" if ok else "\nVALIDATION FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
