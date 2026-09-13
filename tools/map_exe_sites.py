#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""map_exe_sites.py (v2) - DX11 exe 站点 -> DX12 exe 语义重定位。

相比 v1 的改动：
  * 函数表改用 tools/CivilizationVI[_DX12].symdb.json（IDA 导出的 name+size），
    不再用 pdata（pdata 有缺口，且会把相邻函数并成一大块）。
  * 匹配指纹 = 指令形状序列（mnemonic + 操作数类别/宽度，寄存器身份抹掉），
    避免 DX11 内联 / DX12 outlined 带来的寄存器顺序差异。
  * 额外用「函数内引用的字符串字面量」做锚：DX11 侧有 Renderer.log 那类
    log 文本的函数，DX12 侧同样引用相同文本 -> 直接判定为同一函数。
  * 站点在其所在函数里的指令序号，用 difflib 对齐后映射到 DX12 指令。

用法:
  python map_exe_sites.py                      # 全量，写 docs/EXE_SITE_MAP.md + tools/exe_site_map.json
  python map_exe_sites.py --kind spi,ibvb
  python map_exe_sites.py --rva 0x95F88D       # 只看一个站点（打印 top 候选）
"""
from __future__ import annotations

import argparse
import bisect
import difflib
import json
import re
import struct
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_REG, CS_OP_IMM, CS_OP_MEM

HERE = Path(__file__).resolve().parent
DEFAULT_EXE_DIR = Path(r"E:\SteamLibrary\steamapps\common\Sid Meier's Civilization VI\Base\Binaries\Win64Steam")
DEFAULT_SRC = Path(r"E:\WorkSpace\Civ6\Civ6DllMods\recipes\Global\Civ6BasePlugin\dll\BugFix\UnlockModelLimit\UnlockModelLimit.cpp")
DEFAULT_OUT = HERE.parent / "docs" / "EXE_SITE_MAP.md"
DEFAULT_JSON = HERE / "exe_site_map.json"
MAX_INSNS = 400
WINDOW = 0x100000


class Exe:
    def __init__(self, path: Path, symdb: Path, name: str):
        self.name = name
        self.pe = pefile.PE(str(path), fast_load=True)
        self.pe.parse_data_directories()
        self.data = path.read_bytes()
        self.secs = [(s.Name.rstrip(b"\0").decode(errors="replace"), s.VirtualAddress,
                      s.Misc_VirtualSize, s.SizeOfRawData, s.PointerToRawData) for s in self.pe.sections]
        self.text = b""
        self.va = 0
        for nm, va, vsz, rawsz, praw in self.secs:
            if nm == ".text":
                self.text, self.va = self.data[praw:praw + rawsz], va
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage
        d = json.loads(symdb.read_text(encoding="utf-8"))
        fs = [x for x in d["symbols"] if x.get("kind") == "function" and int(x["size"]) > 0]
        self.funcs = sorted((int(x["rva"], 16), int(x["size"]), x.get("demangled", "")) for x in fs)
        self.starts = [f[0] for f in self.funcs]
        self._dis = Cs(CS_ARCH_X86, CS_MODE_64)
        self._dis.detail = True

    def ro(self, rva, n):
        for nm, va, vsz, rawsz, praw in self.secs:
            if va <= rva < va + max(vsz, rawsz):
                o = praw + (rva - va)
                if 0 <= o and o + n <= len(self.data):
                    return self.data[o:o + n]
        return None

    def section_of(self, rva):
        for nm, va, vsz, rawsz, praw in self.secs:
            if va <= rva < va + max(vsz, rawsz):
                return nm
        return None

    def func_of(self, rva):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i < 0:
            return None
        s, sz, nm = self.funcs[i]
        return (s, s + sz, nm) if rva < s + sz else None

    def disas(self, start, end):
        raw = self.ro(start, end - start)
        if not raw:
            return []
        return list(self._dis.disasm(raw, start))[:MAX_INSNS]

    def cstr(self, va, maxlen=160):
        if va < 0x1000:
            return None
        out = bytearray()
        for i in range(maxlen):
            b = self.ro(va + i, 1)
            if not b:
                return None
            c = b[0]
            if c == 0:
                break
            if not (32 <= c < 127):
                return None
            out.append(c)
        if len(out) < 6:
            return None
        return out.decode("ascii", "replace")


def analyze(exe: Exe, start: int, end: int):
    """-> (shape_tokens, canon_tokens, insns, strings(set))"""
    insns = exe.disas(start, end)
    order, shape, canon, strings = {}, [], [], set()
    for ins in insns:
        sp = [ins.mnemonic]
        cp = [ins.mnemonic]
        for op in ins.operands:
            if op.type == CS_OP_REG:
                sp.append("r%d" % op.size)
                nm = ins.reg_name(op.reg) or "?"
                order.setdefault(nm, "R%d" % len(order))
                cp.append("%s:w%d" % (order[nm], op.size))
            elif op.type == CS_OP_IMM:
                sp.append("i")
                cp.append("I")
            elif op.type == CS_OP_MEM:
                m = op.mem
                b = ins.reg_name(m.base) if m.base else ""
                i = ins.reg_name(m.index) if m.index else ""
                if b in ("rip", "eip"):
                    sp.append("rip%d" % op.size)
                    tgt = ins.address + ins.size + m.disp
                    s = exe.cstr(tgt)
                    if s:
                        strings.add(s)
                else:
                    sp.append("m%d%s" % (op.size, ("+i" if i else "")))
                if b:
                    order.setdefault(b, "R%d" % len(order))
                    b = order[b]
                if i:
                    order.setdefault(i, "R%d" % len(order))
                    i = order[i]
                cp.append("M[%s%s*%d]:w%d" % (b, ("+" + i) if i else "", m.scale or 1, op.size))
            else:
                sp.append("?")
                cp.append("?")
        shape.append("|".join(sp))
        canon.append("|".join(cp))
    return shape, canon, insns, strings


def bigrams(toks):
    return set(zip(toks, toks[1:])) if len(toks) > 1 else set()


def dice(a, b):
    return 0.0 if not a or not b else 2.0 * len(a & b) / (len(a) + len(b))


def jac(a, b):
    return 0.0 if not a or not b else len(a & b) / len(a | b)


def build(exe: Exe):
    out = []
    for s, sz, nm in exe.funcs:
        sh, ca, ins, st = analyze(exe, s, s + sz)
        if sh:
            out.append(dict(start=s, end=s + sz, name=nm, shape=sh, canon=ca, insns=ins,
                            strings=st, bg=bigrams(sh)))
    return out


def extract_sites(src: Path):
    lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    sites, last = [], ""
    pats = [("spi", re.compile(r"ApplySPIPatchSite\(\s*0x([0-9A-Fa-f]+)")),
            ("ibvb", re.compile(r"ApplyIBVBPatchSite\(\s*0x([0-9A-Fa-f]+)")),
            ("limit", re.compile(r"PatchLimitByte\(\s*0x([0-9A-Fa-f]+)")),
            ("resolve", re.compile(r"ResolveExe\(\s*0x([0-9A-Fa-f]+)\s*,\s*(\d+)"))]
    for ln in lines:
        st = ln.strip()
        if st.startswith("//"):
            last = st.lstrip("/ ").strip()
            continue
        if not st:
            continue
        for kind, rx in pats:
            m = rx.search(st)
            if not m:
                continue
            rva = int(m.group(1), 16)
            size = int(m.group(2)) if (kind == "resolve" and m.lastindex and m.lastindex >= 2) else None
            tail = st.split("//", 1)[1].strip() if "//" in st else ""
            sites.append((rva, kind if kind != "resolve" else ("hook" if size == 16 else "data"), tail or last))
            last = ""
            break
    seen, uniq = set(), []
    for s in sites:
        if (s[0], s[1]) in seen:
            continue
        seen.add((s[0], s[1]))
        uniq.append(s)
    return uniq


def rank_candidates(site_fn, dx11, dx12, rva):
    """-> [(score_tuple, cand, mapped_idx, tag)] 降序"""
    out = []
    lo, hi = rva - WINDOW, rva + WINDOW
    n11 = len(dx11["shape"])
    for c in dx12:
        if c["start"] < lo or c["start"] > hi:
            continue
        if not (0.3 <= len(c["shape"]) / max(1, n11) <= 3.0):
            continue
        d = dice(dx11["bg"], c["bg"])
        if d < 0.15:
            continue
        common = len(dx11["strings"] & c["strings"])
        out.append((d, common, c))
    out.sort(key=lambda x: (-x[1], -x[0]))
    res = []
    for d, common, c in out[:400]:
        r = difflib.SequenceMatcher(None, dx11["shape"], c["shape"], autojunk=False).ratio()
        sj = jac(dx11["strings"], c["strings"]) if dx11["strings"] else 0.0
        res.append(((common, sj, r), c, d))
    res.sort(key=lambda x: (-x[0][0], -x[0][1], -x[0][2]))
    return res


def align_index(a, b, i):
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if i1 <= i < i2:
            if tag == "equal":
                return j1 + (i - i1), ""
            return j1, "<>"
    return None, "?"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe-dir", default=str(DEFAULT_EXE_DIR))
    ap.add_argument("--src", default=str(DEFAULT_SRC))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--json", default=str(DEFAULT_JSON))
    ap.add_argument("--kind", default="")
    ap.add_argument("--rva", default="")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ed = Path(args.exe_dir)
    e11 = Exe(ed / "CivilizationVI.exe", HERE / "CivilizationVI.symdb.json", "Dx11")
    e12 = Exe(ed / "CivilizationVI_DX12.exe", HERE / "CivilizationVI_DX12.symdb.json", "Dx12")
    print("symdb funcs: dx11=%d dx12=%d" % (len(e11.funcs), len(e12.funcs)))
    sites = extract_sites(Path(args.src))
    kinds = set(k.strip() for k in args.kind.split(",") if k.strip())
    if args.rva:
        kinds = set()
        sites = [s for s in sites if s[0] == int(args.rva, 16)]
    else:
        sites = [s for s in sites if not kinds or s[1] in kinds]

    print("building dx12 index ...")
    d12 = build(e12)
    print("dx12 funcs indexed: %d" % len(d12))

    cache, rows = {}, []
    for rva, kind, label in sites:
        fn = e11.func_of(rva)
        if fn is None or e11.section_of(rva) != ".text":
            rows.append(dict(rva=rva, kind=kind, label=label, d11fn=None, d11name="", d11insn="",
                             d12rva=None, d12fn=None, d12name="", d12insn="", score=0.0,
                             note="数据槽（本次不自动映射）"))
            continue
        if fn[0] not in cache:
            cache[fn[0]] = analyze(e11, fn[0], fn[1])
        sh, ca, ins, st = cache[fn[0]]
        ti = next((k for k, x in enumerate(ins) if x.address <= rva < x.address + x.size), None)
        d11insn = "" if ti is None else "%s" % (ins[ti].mnemonic + " " + ins[ti].op_str)
        dx11 = dict(start=fn[0], end=fn[1], name=fn[2], shape=sh, canon=ca, insns=ins,
                    strings=st, bg=bigrams(sh))
        cands = rank_candidates(dx11, dx11, d12, rva)
        if args.rva:
            print("== DX11 0x%X  %s  fn=%s (0x%X, %d insns, %d strings)" % (
                rva, d11insn, fn[2][:80], fn[0], len(sh), len(st)))
            for (common, sj, r), c, d in cands[:8]:
                mi, ap = align_index(sh, c["shape"], ti) if ti is not None else (None, "")
                tgt = ("0x%X" % c["insns"][mi].address) if (mi is not None and mi < len(c["insns"])) else "-"
                print("   common=%d jac=%.2f ratio=%.3f dice=%.2f -> 0x%-7X..0x%-7X %s  mapped=%s" % (
                    common, sj, r, d, c["start"], c["end"], c["name"][:40], tgt))
        if not cands:
            rows.append(dict(rva=rva, kind=kind, label=label, d11fn=(fn[0], fn[1]), d11name=fn[2],
                             d11insn=d11insn, d12rva=None, d12fn=None, d12name="", d12insn="",
                             score=0.0, note="窗口内无候选"))
            continue
        (common, sj, r), c, d = cands[0]
        mi, ap = align_index(sh, c["shape"], ti) if ti is not None else (None, "?")
        d12rva = d12insn = None
        if mi is not None and 0 <= mi < len(c["insns"]):
            d12rva = c["insns"][mi].address
            d12insn = ap + c["insns"][mi].mnemonic + " " + c["insns"][mi].op_str
        if common >= 2 and sj >= 0.5:
            note = "字符串锚定"
        elif r >= 0.9 and not ap:
            note = "序列一致"
        elif r >= 0.7:
            note = "相似"
        else:
            note = "低置信"
        rows.append(dict(rva=rva, kind=kind, label=label, d11fn=(fn[0], fn[1]), d11name=fn[2],
                         d11insn=d11insn, d12rva=d12rva, d12fn=(c["start"], c["end"]),
                         d12name=c["name"], d12insn=d12insn or "", score=r, note=note,
                         alt=[dict(rva=x[1]["start"], name=x[1]["name"][:60], ratio=x[0][2],
                                   common=x[0][0], insn=(x[1]["insns"][align_index(sh, x[1]["shape"], ti)[0]].mnemonic + " " +
                                   x[1]["insns"][align_index(sh, x[1]["shape"], ti)[0]].op_str)
                                   if ti is not None and align_index(sh, x[1]["shape"], ti)[0] is not None
                                   and align_index(sh, x[1]["shape"], ti)[0] < len(x[1]["insns"]) else "")
                              for x in cands[1:4]]))
    Path(args.json).write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    md = ["# UnlockModelLimit sites: DX11 -> DX12 relocation", "",
          "tools/map_exe_sites.py v2 (symdb 函数表 + 指令形状序列 + 字符串锚).",
          "note: 字符串锚定 = 两函数引用同一批 log 字符串; 序列一致 = shape 序列 ratio>=0.9; 相似 >=0.7.", "",
          "| # | kind | label | DX11 RVA | DX11 fn | DX11 insn | DX12 RVA | DX12 insn | ratio | note |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        md.append("| %d | %s | %s | 0x%X | %s | %s | %s | %s | %.2f | %s |" % (
            i, r["kind"], r["label"].replace("|", "/")[:52], r["rva"],
            (r["d11name"] or "-")[:40].replace("|", "/"),
            r["d11insn"].replace("|", "/")[:44],
            ("0x%X" % r["d12rva"]) if r.get("d12rva") is not None else "-",
            (r["d12insn"] or "-").replace("|", "/")[:44], r["score"], r["note"]))
    Path(args.out).write_text("\n".join(md) + "\n", encoding="utf-8")
    from collections import Counter
    cnt = Counter(r["note"] for r in rows)
    print("rows %d: %s" % (len(rows), dict(cnt)))
    for r in rows:
        if r["note"] in ("低置信", "窗口内无候选") and r["kind"] != "data":
            print("  %-7s 0x%-7X %-46s -> %s  %s" % (
                r["kind"], r["rva"], (r["d11name"] or "")[:46],
                ("0x%X" % r["d12rva"]) if r.get("d12rva") is not None else "-", r["note"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
