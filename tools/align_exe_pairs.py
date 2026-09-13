#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""align_exe_pairs.py - 已知一对 DX11/DX12 函数时，把 DX11 的站点逐点对齐到 DX12。

用法:
  python tools/align_exe_pairs.py --dx11 0x940770 --dx12 0x940BE0 --sites 0x9408A1,0x9407CF
  python tools/align_exe_pairs.py --dx11 0x946A10 --dx12 0x944A50 --sites 0x946A37

输出：两函数形态序列相似度 + 每个站点所在指令在 DX12 的对齐指令（equal 视为可靠，replace/delete 标近似）。
函数表来自 tools/CivilizationVI[_DX12].symdb.json（IDA 导出）。
"""
from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import map_exe_sites as M  # noqa: E402

DEFAULT_EXE_DIR = M.DEFAULT_EXE_DIR


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe-dir", default=str(DEFAULT_EXE_DIR))
    ap.add_argument("--dx11", required=True, type=lambda v: int(v, 0), help="DX11 函数 RVA（含站点）")
    ap.add_argument("--dx12", required=True, type=lambda v: int(v, 0), help="DX12 对应函数 RVA")
    ap.add_argument("--sites", required=True, help="DX11 站点 RVA，逗号分隔")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ed = Path(args.exe_dir)
    e11 = M.Exe(ed / "CivilizationVI.exe", M.HERE / "CivilizationVI.symdb.json", "Dx11")
    e12 = M.Exe(ed / "CivilizationVI_DX12.exe", M.HERE / "CivilizationVI_DX12.symdb.json", "Dx12")

    f1 = e11.func_of(args.dx11)
    f2 = e12.func_of(args.dx12)
    if not f1 or not f2:
        print("函数未找到：dx11=%s dx12=%s" % (f1, f2))
        return 2
    sh1, ca1, ins1, st1 = M.analyze(e11, f1[0], f1[1])
    sh2, ca2, ins2, st2 = M.analyze(e12, f2[0], f2[1])
    ratio = difflib.SequenceMatcher(None, sh1, sh2, autojunk=False).ratio()
    print("DX11 0x%X (%s, %d 字节, %d 指令)  <->  DX12 0x%X (%s, %d 字节, %d 指令)   形态相似度 %.3f" % (
        f1[0], (f1[2] or "?")[:70], f1[1] - f1[0], len(ins1),
        f2[0], (f2[2] or "?")[:40], f2[1] - f2[0], len(ins2), ratio))
    ops = difflib.SequenceMatcher(None, sh1, sh2, autojunk=False).get_opcodes()
    sites = [int(x, 0) for x in args.sites.split(",") if x.strip()]
    for s in sites:
        ti = next((k for k, x in enumerate(ins1) if x.address <= s < x.address + x.size), None)
        if ti is None:
            print("  0x%-7X 不在该函数内" % s)
            continue
        src = ins1[ti].mnemonic + " " + ins1[ti].op_str
        mapped, how = None, "?"
        for o in ops:
            if o[1] <= ti < o[2]:
                mapped = (o[3] + (ti - o[1])) if o[0] == "equal" else o[3]
                how = o[0]
                break
        if mapped is not None and mapped < len(ins2):
            print("  0x%-7X %-46s -> DX12 0x%-9X %-46s [%s]" % (
                s, src[:46], ins2[mapped].address,
                (ins2[mapped].mnemonic + " " + ins2[mapped].op_str)[:46], how))
        else:
            print("  0x%-7X %-46s -> 无对齐" % (s, src[:46]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
