#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""map_exe_by_disp.py v2 - 按「数据位移锚」把 DX11 站点重定位到 DX12。

两种 DX12 寻址形态都要覆盖：
  (a) 绝对形态：DX11 站点 disp = 数组 RVA（基址寄存器持 0x140000000）。
      DX12 若同样折叠，则 disp = Dx12BaseRVA + rel（rel = DX11 disp - Dx11BaseRVA）。
  (b) 对象形态：DX12 先把对象基址 lea 进寄存器，再 [reg + idx*8 + rel]，disp = rel（小的字段偏移）。
      判据：该指令所在函数里存在对某个候选基址 base 的 RIP 相对引用（lea base）。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from map_exe_sites import Exe, extract_sites, DEFAULT_EXE_DIR, DEFAULT_SRC  # noqa: E402
from capstone import CS_OP_REG, CS_OP_IMM, CS_OP_MEM  # noqa: E402

HERE = Path(__file__).resolve().parent

DX11_OBJS = {
    "m_IBList": 0x2B0A740,
    "m_VBList": 0x2B91200,
    "m_SPIList": 0x2AB9E40,
    "m_ComputeSPIList": 0x2822C80,
}
DX12_BASES = {
    "A": 0x14673D680,
    "B": 0x146C72040,
    "C": 0x146DB3840,
    "D": 0x14F2B50C0,
}
BASE = 0x140000000
BASE_RVA = {k: v - BASE for k, v in DX12_BASES.items()}


def insn_shape(ins):
    parts = [ins.mnemonic]
    for op in ins.operands:
        if op.type == CS_OP_REG:
            parts.append("r%d" % op.size)
        elif op.type == CS_OP_IMM:
            parts.append("i")
        elif op.type == CS_OP_MEM:
            b = ins.reg_name(op.mem.base) if op.mem.base else ""
            parts.append("rip%d" % op.size if b in ("rip", "eip")
                         else "m%d%s" % (op.size, ("+i" if op.mem.index else "")))
        else:
            parts.append("?")
    return "|".join(parts)


def insn_memsize(ins):
    parts = [ins.mnemonic]
    for op in ins.operands:
        if op.type == CS_OP_REG:
            parts.append("r%d" % op.size)
        elif op.type == CS_OP_IMM:
            parts.append("i")
        elif op.type == CS_OP_MEM:
            parts.append("m%d" % op.size)
        else:
            parts.append("?")
    return "|".join(parts)


def scan_insn(ins):
    """-> (abs_disps, rip_targets)"""
    absd, rip = [], []
    for op in ins.operands:
        if op.type == CS_OP_MEM:
            b = ins.reg_name(op.mem.base) if op.mem.base else ""
            if b in ("rip", "eip"):
                rip.append(ins.address + ins.size + op.mem.disp)
            else:
                absd.append(op.mem.disp)
    return absd, rip


def build_index(exe):
    idx, refs, n = {}, {}, 0
    for s, sz, nm in exe.funcs:
        rs = refs.setdefault(s, set())
        for ins in exe.disas(s, s + sz):
            n += 1
            absd, rip = scan_insn(ins)
            for t in rip:
                rs.add(t)
            for v in absd:
                idx.setdefault(v, []).append((s, ins.address, insn_shape(ins), insn_memsize(ins),
                                              ins.mnemonic + " " + ins.op_str))
    print("dx12 scan: %d instructions, %d abs-disp keys, %d funcs with refs" % (n, len(idx), len(refs)))
    return idx, refs


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ed = Path(DEFAULT_EXE_DIR)
    e11 = Exe(ed / "CivilizationVI.exe", HERE / "CivilizationVI.symdb.json", "Dx11")
    e12 = Exe(ed / "CivilizationVI_DX12.exe", HERE / "CivilizationVI_DX12.symdb.json", "Dx12")
    idx, refs = build_index(e12)
    sites = extract_sites(Path(DEFAULT_SRC))
    for rva, kind, label in sites:
        if kind == "data":
            continue
        fn = e11.func_of(rva)
        if fn is None:
            continue
        ins = None
        for x in e11.disas(fn[0], fn[1]):
            if x.address <= rva < x.address + x.size:
                ins = x
                break
        if ins is None:
            continue
        absd, _rip = scan_insn(ins)
        if not absd:
            continue
        sh, sh2 = insn_shape(ins), insn_memsize(ins)
        for dval in absd:
            obj = rel = None
            for on, orva in DX11_OBJS.items():
                if orva <= dval < orva + 0x40000:
                    obj, rel = on, dval - orva
                    break
            if obj is None:
                continue
            print("-- 0x%-7X %-44s disp=0x%-8X %s+0x%X   | %s" % (
                rva, label[:44], dval, obj, rel, ins.mnemonic + " " + ins.op_str))
            found = False
            # (b) 对象形态：disp == rel，且所在函数引用了候选基址
            for (fs, ia, s1, s2, txt) in idx.get(rel, []):
                if s1 != sh and s2 != sh2:
                    continue
                used = [bk for bk, bv in DX12_BASES.items() if bv in refs.get(fs, ())]
                if used:
                    found = True
                    print("     [OBJ %s] fn=0x%-7X insn=0x%-9X %-46s %s" % (
                        ",".join(used), fs, ia, txt, s1))
            # (a) 绝对形态
            for bk, brva in BASE_RVA.items():
                cand = brva + rel
                for (fs, ia, s1, s2, txt) in idx.get(cand, []):
                    if s1 != sh and s2 != sh2:
                        continue
                    found = True
                    print("     [ABS %s] cand=0x%-8X fn=0x%-7X insn=0x%-9X %s" % (bk, cand, fs, ia, txt))
            if not found:
                print("     (no hit)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
