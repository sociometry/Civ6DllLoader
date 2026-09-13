#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# build_sidecar.py - JSON + DLL -> sidecar 容器 bin（v1，moduleCount=1）
import argparse, json, os, struct, subprocess, sys, tempfile
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DLL = "E:/SteamLibrary/steamapps/common/Sid Meier's Civilization VI/DLC/Expansion2/Binaries/Win64/GameCore_XP2_FinalRelease.dll"
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3
MAX_AOB = 64  # 每个函数 AOB 最大存 64 字节

def fnv1a64(data):
    h = FNV_OFFSET
    for b in data:
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h

def parse_pdata(pe):
    exc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    n = exc.Size // 12
    raw = pe.get_data(exc.VirtualAddress, exc.Size)
    out = []
    for i in range(n):
        b, e, u = struct.unpack_from("<III", raw, i * 12)
        hdr = pe.get_data(u, 4)
        out.append((b, e - b, u, hdr[1]))
    return out

def unwind_hash(pe, unwind_rva):
    hdr = pe.get_data(unwind_rva, 4)
    cnt = hdr[2]
    ln = 4 + 2 * cnt + (cnt & 1) * 2
    return fnv1a64(pe.get_data(unwind_rva, ln))

def run_aob(helper, records):
    fd1, inp = tempfile.mkstemp(suffix=".bin"); os.close(fd1)
    fd2, outp = tempfile.mkstemp(suffix=".bin"); os.close(fd2)
    try:
        with open(inp, "wb") as f:
            for ln, b in records:
                f.write(struct.pack("<I", ln)); f.write(b)
        r = subprocess.run([helper, inp, outp, "--max", str(MAX_AOB)], capture_output=True, text=True, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError("aob_helper failed: " + r.stderr[:300])
        with open(outp, "rb") as f:
            return f.read()
    finally:
        for p in (inp, outp):
            try: os.unlink(p)
            except OSError: pass

def run_normhash(helper, records):
    fd1, inp = tempfile.mkstemp(suffix=".bin"); os.close(fd1)
    try:
        with open(inp, "wb") as f:
            for ln, b in records:
                f.write(struct.pack("<I", ln)); f.write(b)
        r = subprocess.run([helper, inp], capture_output=True, text=True, timeout=600)
        lines = [int(x, 16) for x in r.stdout.strip().splitlines()]
        if len(lines) != len(records):
            raise RuntimeError("normhash count mismatch")
        return lines
    finally:
        os.unlink(inp)

def main():
    ap = argparse.ArgumentParser(
        description="JSON + DLL -> sidecar 容器 bin (v1, moduleCount=1, with PE timestamp)")
    ap.add_argument("--dll", default=DEFAULT_DLL)
    ap.add_argument("--image-id", type=int, default=5,
                    help="模块身份：1=ExeDx11, 2=ExeDx12, 5=GameCoreXP2（默认 5）")
    ap.add_argument("--json", default=os.path.join(HERE, "Civ6DllLoader.symdb.json"))
    ap.add_argument("--bin", default=os.path.join(HERE, "Civ6DllLoader.symdb.bin"))
    ap.add_argument("--normhash", default=os.path.join(HERE, "normhash_helper.exe"))
    ap.add_argument("--aob", default=os.path.join(HERE, "aob_helper.exe"))
    args = ap.parse_args()

    print("[1/5] JSON ...")
    with open(args.json, "r", encoding="utf-8") as f:
        j = json.load(f)
    if int(j.get("version", 1)) != 1:
        raise SystemExit("JSON version 必须是 1（实际 {}）".format(j.get("version")))
    sizeimg = int(j["baseSizeOfImage"], 16)
    symbols = j["symbols"]
    func_syms = [s for s in symbols if s["kind"] == "function"]
    vt_syms = [s for s in symbols if s["kind"] == "vtable"]
    print("      {} symbols ({} func + {} vt)".format(len(symbols), len(func_syms), len(vt_syms)))

    print("[2/5] DLL pdata ...")
    pe = pefile.PE(args.dll)
    timestamp = pe.FILE_HEADER.TimeDateStamp
    pdata = parse_pdata(pe)
    pdata_begins = {b: (s, u, p) for (b, s, u, p) in pdata}
    print("      {} entries".format(len(pdata)))

    print("[3/5] normHeadHash ...")
    records, indices, placeholders = [], [], {}
    for idx, s in enumerate(func_syms):
        rva = int(s["rva"], 16)
        if rva in pdata_begins:
            ln = min(pdata_begins[rva][2], 32)
            if ln <= 0:
                placeholders[idx] = FNV_OFFSET
            else:
                records.append((ln, pe.get_data(rva, ln)))
                indices.append(idx)
        else:
            placeholders[idx] = FNV_OFFSET
    hashes = run_normhash(args.normhash, records)
    nhh = [0] * len(func_syms)
    for pos, idx in enumerate(indices):
        nhh[idx] = hashes[pos]
    for idx, h in placeholders.items():
        nhh[idx] = h
    print("      {} functions".format(len(func_syms)))

    print("[4/5] AOB ...")
    func_set = set(int(s["rva"], 16) for s in func_syms)
    func_by_rva = {int(s["rva"], 16): s for s in func_syms}

    def body_size_for(rva):
        lo, hi = 0, len(pdata) - 1
        i0 = None
        while lo <= hi:
            mid = (lo + hi) // 2
            b = pdata[mid][0]
            if b == rva:
                i0 = mid
                break
            elif b < rva:
                lo = mid + 1
            else:
                hi = mid - 1
        if i0 is None:
            return int(func_by_rva[rva]["size"])
        i1 = i0
        while i1 + 1 < len(pdata):
            if pdata[i1 + 1][0] in func_set:
                break
            i1 += 1
        return pdata[i1][0] + pdata[i1][1] - pdata[i0][0]

    aob_records = []
    for s in func_syms:
        rva = int(s["rva"], 16)
        bs = body_size_for(rva)
        aob_records.append((bs, pe.get_data(rva, bs)))
    aob_blob = run_aob(args.aob, aob_records)
    print("      AOB {} bytes".format(len(aob_blob)))

    print("[5/5] packing ...")
    pdata_rows = [(b, s, unwind_hash(pe, u)) for (b, s, u, p) in pdata]

    unique, off_map = [], {}
    def intern(s):
        if not s:
            return
        if s not in off_map:
            off_map[s] = None
            unique.append(s)
    for s in symbols:
        intern(s.get("demangled", ""))
        intern(s.get("mangled", ""))
    heap = bytearray(b"\x00")
    for s in unique:
        off_map[s] = len(heap)
        heap.extend(s.encode("utf-8") + b"\x00")
    heap_bytes = bytes(heap)

    slot_table = []
    for s in vt_syms:
        for sl in s.get("slots", []):
            off = int(sl["offset"])
            frva = int(sl["funcRva"], 16)
            slot_table.append((off, frva))
    slot_blob = struct.pack("<{}I".format(len(slot_table) * 2),
                           *[v for t in slot_table for v in t])

    # 容器布局：Header(32B) + ModuleDesc(64B) + 各段（8B 对齐，offset 均为文件绝对偏移）
    CTR_HDR, DESC = 32, 64
    data_off = CTR_HDR + DESC

    pdata_blob = bytearray()
    for b, s, u in pdata_rows:
        pdata_blob += struct.pack("<IIQ", b, s, u)

    symbol_blob = bytearray()
    func_idx = 0
    for s in symbols:
        d = off_map.get(s.get("demangled", ""), 0)
        m = off_map.get(s.get("mangled", ""), 0)
        rva = int(s["rva"], 16)
        if s["kind"] == "function":
            kind, slot_cnt, nh = 0, 0, nhh[func_idx]
            func_idx += 1
        else:
            kind, slot_cnt, nh = 1, s.get("slotCount", 0), 0
        symbol_blob += struct.pack("<II", d, m)
        symbol_blob += struct.pack("<I", rva)
        # vtableSlotCount 为 16 位（<BHB>: kind, u16 count, u8 reserved）
        assert slot_cnt <= 0xFFFF, "vtable slot count too large"
        symbol_blob += struct.pack("<BHB", kind, slot_cnt, 0)
        symbol_blob += struct.pack("<Q", nh)
        symbol_blob += struct.pack("<II", 0, 0)

    blocks = bytearray()

    def append_block(blk):
        off = data_off + len(blocks)
        blocks.extend(blk)
        blocks.extend(bytes((8 - (len(blocks) % 8)) % 8))
        return off

    pd_off = append_block(bytes(pdata_blob))
    sy_off = append_block(bytes(symbol_blob))
    vt_off = append_block(bytes(slot_blob))
    heap_off = append_block(bytes(heap_bytes))
    aob_off = append_block(bytes(aob_blob))

    out = bytearray()
    out += b"C6SD" + struct.pack("<IIIIIII", 1, 1, CTR_HDR, DESC, data_off, 0, 0)
    assert len(out) == CTR_HDR
    out += struct.pack("<16I", args.image_id, sizeimg, timestamp,
                       pd_off, len(pdata_rows), sy_off, len(symbols),
                       vt_off, len(slot_table), heap_off, len(heap_bytes),
                       aob_off, len(aob_blob), 0, 0, 0)
    assert len(out) == data_off
    out += blocks

    with open(args.bin, "wb") as f:
        f.write(out)
    print("      bin: {} bytes (container v1, image-id={})".format(len(out), args.image_id))
    print("      timestamp: 0x{:08X}".format(timestamp))
    print("      layout: data={} pd={} sy={} vt={} heap={} aob={}".format(
        data_off, pd_off, sy_off, vt_off, heap_off, aob_off))
    print("done.")

if __name__ == "__main__":
    main()
