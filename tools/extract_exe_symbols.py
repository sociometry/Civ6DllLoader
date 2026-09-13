#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_exe_symbols.py - 从 IDA 导出生成 EXE 版 symdb JSON（结构与 DLL 一致）

输入：
  --exe    当前(去DRM)的 EXE 文件       （读 SizeOfImage / pdataCount / vtable 槽位指针）
  --funcs  IDAPython 导出的 .funcs.txt  （raw, demangled, start, size, segment）
  --asm    IDA 导出的 .rdata 段 .asm    （vtable label + dq offset 展开）
  --out    输出 JSON
可选：
  --base   镜像基址（默认 0x140000000）
  --demumble demumble.exe（修复 IDA 去重后缀导致的 demangle 失败）

JSON 结构（与 Civ6DllLoader.symdb.json 一致）：
{
  "version": 1,
  "baseSizeOfImage": "0x...",
  "pdataCount": N,
  "symbols": [
     {"demangled": "...", "mangled": "...", "rva": "0x...", "kind": "function", "size": N},
     {"demangled": "...::vftable", "mangled": "??_7...6B@", "rva": "0x...",
      "kind": "vtable", "slotCount": N, "slots": [{"offset":0,"funcRva":"0x..."}, ...]}
  ]
}
"""

import argparse
import json
import os
import re
import struct
import subprocess

import pefile

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- 名字处理

OP_PROTECT = [
    ("operator()", "@OPP@"),
    ("operator[]", "@OPB@"),
    ("operator new[]", "@OPNEWA@"),
    ("operator delete[]", "@OPDELA@"),
    ("operator new", "@OPNEW@"),
    ("operator delete", "@OPDEL@"),
    ("operator ", "@OPSP@"),
]


def protect_ops(s):
    for k, v in OP_PROTECT:
        s = s.replace(k, v)
    return s


def restore_ops(s):
    for k, v in reversed(OP_PROTECT):
        s = s.replace(v, k)
    return s


def strip_params(name):
    """从后往前找第一对最外层平衡括号（参数表）去掉"""
    if not name:
        return name
    s = protect_ops(name)
    depth = 0
    start = -1
    i = len(s) - 1
    while i >= 0:
        c = s[i]
        if c == ")":
            depth += 1
        elif c == "(":
            depth -= 1
            if depth == 0:
                start = i
                break
        i -= 1
    out = s[:start].rstrip() if start != -1 else s
    return restore_ops(out)


def strip_ida_suffix(name):
    """去掉 IDA 为去重加的 _ / _N 后缀"""
    n = name
    while True:
        m = re.search(r"_\d+$", n)
        if m:
            n = n[:m.start()]
            continue
        if n.endswith("_"):
            n = n[:-1]
            continue
        break
    return n


# ---------------------------------------------------------------- funcs.txt

def parse_funcs(path, base):
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            raw = parts[0].strip()
            dem = parts[1].strip()
            seg = parts[4].strip()
            if seg != ".text":
                continue
            try:
                start = int(parts[2].strip(), 16)
                size = int(parts[3].strip(), 16)
            except ValueError:
                continue
            rows.append({"raw": raw, "dem": dem, "rva": start - base, "size": size})
    return rows


# ---------------------------------------------------------------- vtable asm

VT_LABEL_RE = re.compile(r"^([0-9A-Fa-f]{16})\s+(\?\?_7\S*?6B@)\s+dq offset")
# 槽位行：可能带地址前缀（如 "0000000140F9D8D0   dq offset ..."），也可能只有缩进
SLOT_LINE_RE = re.compile(r"^(?:[0-9A-Fa-f]{16}\s+)?dq offset")
COMMENT_LINE_RE = re.compile(r"^(?:[0-9A-Fa-f]{16}\s+)?;")


def vtable_demangle(label):
    s = label
    if s.startswith("??_7"):
        s = s[4:]
    if s.endswith("@@6B@"):
        s = s[:-5]
    parts = [p for p in s.split("@") if p]
    return "::".join(reversed(parts)) + "::vftable"


def parse_vtables(asm_path, exe_path, base):
    pe = pefile.PE(exe_path)
    data = open(exe_path, "rb").read()
    imgbase = pe.OPTIONAL_HEADER.ImageBase

    def read_qword(rva):
        off = pe.get_offset_from_rva(rva)
        if off is None or off + 8 > len(data):
            return 0
        return struct.unpack_from("<Q", data, off)[0]

    lines = open(asm_path, "r", encoding="utf-8", errors="ignore").read().splitlines()
    out = []
    i = 0
    n = len(lines)
    while i < n:
        m = VT_LABEL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        label = m.group(2)
        vrva = int(m.group(1), 16) - base
        cnt = 1  # label 行自带第一个槽
        j = i + 1
        while j < n:
            s = lines[j].strip()
            if not s or COMMENT_LINE_RE.match(s):
                j += 1
                continue
            if SLOT_LINE_RE.match(s):
                cnt += 1
                j += 1
                continue
            break
        slots = []
        for k in range(cnt):
            v = read_qword(vrva + k * 8)
            if imgbase <= v < imgbase + 0x20000000:
                frva = v - imgbase
            else:
                frva = v
            slots.append({"offset": k * 8, "funcRva": frva})
        out.append({"label": label, "rva": vrva, "slots": slots})
        i = j
    return out


# ---------------------------------------------------------------- main

def scan_runs(asm_path, exe_path, base):
    """扫描 .rdata asm，把所有连续的函数指针段找出来（未命名 vtable / 指针表）。

    返回 [{"rva": start_rva, "slots": [{"offset","func_rva"}], "first_name": str}, ...]
    """
    pe = pefile.PE(exe_path)
    data = open(exe_path, "rb").read()
    imgbase = pe.OPTIONAL_HEADER.ImageBase
    text = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"), None)
    if text is None:
        return []
    lo = imgbase + text.VirtualAddress
    hi = lo + text.Misc_VirtualSize

    def qword(rva):
        off = pe.get_offset_from_rva(rva)
        if off is None or off + 8 > len(data):
            return 0
        return struct.unpack_from("<Q", data, off)[0]

    ADDR = re.compile(r"^([0-9A-Fa-f]{16})\s*(.*)$")
    LABEL_DQ = re.compile(r"^\S+\s+dq offset\b")
    lines = open(asm_path, "r", encoding="utf-8", errors="ignore").read().splitlines()
    ptr_at = {}
    first_name = {}
    for ln in lines:
        m = ADDR.match(ln)
        if not m:
            continue
        ea = int(m.group(1), 16)
        ins = m.group(2).strip()
        tgt = None
        if ins.startswith("dq offset"):
            tgt = ins[len("dq offset"):].strip().split()[0]
        elif LABEL_DQ.match(ins):
            mm = re.search(r"\bdq offset\s+(\S+)", ins)
            if mm:
                tgt = mm.group(1)
        if tgt is None:
            continue
        v = qword(ea - imgbase)
        if lo <= v < hi:
            ptr_at[ea] = v
            first_name[ea] = tgt

    runs = []
    cur = None
    for ea in sorted(ptr_at):
        if cur is not None and ea == cur[1] + 8:
            cur[1] = ea
        else:
            if cur:
                runs.append(cur)
            cur = [ea, ea]
    if cur:
        runs.append(cur)

    out = []
    for a, b in runs:
        n = (b - a) // 8 + 1
        slots = []
        for k in range(n):
            ea = a + k * 8
            slots.append({"offset": k * 8, "func_rva": ptr_at[ea] - imgbase})
        out.append({"rva": a - imgbase, "slots": slots,
                    "first_name": first_name.get(a, "")})
    return out


def class_from_function_name(name):
    """从 mangled / demangled / IDA 函数名里取类名，失败返回 ""。"""
    if not name:
        return ""
    # 1) MSVC mangled: ?Method@Class@Scope@...@@  -> Scope::Class
    if name.startswith("?") and "@" in name:
        body = name[1:].split("@@")[0]
        parts = [x for x in body.split("@") if x]
        if len(parts) >= 2:
            cls_parts = [x for x in parts[1:] if not x.startswith("?$")]
            if cls_parts:
                return "::".join(reversed(cls_parts))
    # 2) demangled（含 ::）：GameCore::Foo::Bar(void) -> GameCore::Foo
    if "::" in name:
        n = strip_params(name)
        if "::" in n:
            return n.rsplit("::", 1)[0]
    return ""



def scan_candidate_vtables(asm_path, exe_path, base):
    """用 '; DATA XREF'（构造函数 lea 引用）+ 函数指针连续段，切出 vtable 起点。

    返回 [{"rva": start_rva, "slots": [{"offset","func_rva"}], "first_name": str}, ...]
    - 先找所有连续的函数指针段（run）
    - 段内被代码 DATA XREF 引用的地址 = 候选 vtable 起点
    - 在候选点切分 run；没有候选的 run 整体保留（可能是没被引用的 vtable）
    """
    pe = pefile.PE(exe_path)
    data = open(exe_path, "rb").read()
    imgbase = pe.OPTIONAL_HEADER.ImageBase
    text = next((s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text"), None)
    if text is None:
        return []
    lo = imgbase + text.VirtualAddress
    hi = lo + text.Misc_VirtualSize

    def qword(rva):
        off = pe.get_offset_from_rva(rva)
        if off is None or off + 8 > len(data):
            return 0
        return struct.unpack_from("<Q", data, off)[0]

    ADDR = re.compile(r"^([0-9A-Fa-f]{16})\s*(.*)$")
    LABEL_DQ = re.compile(r"^\S+\s+dq offset\b")
    lines = open(asm_path, "r", encoding="utf-8", errors="ignore").read().splitlines()

    ptr_at = {}
    name_at = {}
    label_at = {}
    xref = set()
    cur = None
    for ln in lines:
        m = ADDR.match(ln)
        if m:
            cur = int(m.group(1), 16)
            rest = m.group(2)
            if "DATA XREF:" in rest:
                xref.add(cur)
        else:
            if cur is not None and "DATA XREF:" in ln:
                xref.add(cur)

    for ln in lines:
        m = ADDR.match(ln)
        if not m:
            continue
        ea = int(m.group(1), 16)
        ins = m.group(2).strip()
        tgt = None
        if ins.startswith("dq offset"):
            tgt = ins[len("dq offset"):].strip().split()[0]
        elif LABEL_DQ.match(ins):
            mm = re.search(r"\bdq offset\s+(\S+)", ins)
            if mm:
                tgt = mm.group(1)
        if tgt is None:
            continue
        # 同行的 label（off_XXXX / ??_7...）
        lm = re.match(r"^(\S+)\s+dq offset(?:\s|$)", ins)
        if lm:
            label_at[ea] = lm.group(1)
        v = qword(ea - imgbase)
        if lo <= v < hi:
            ptr_at[ea] = v
            name_at[ea] = tgt

    runs = []
    c = None
    for ea in sorted(ptr_at):
        if c is not None and ea == c[1] + 8:
            c[1] = ea
        else:
            if c:
                runs.append(c)
            c = [ea, ea]
    if c:
        runs.append(c)

    cand = sorted(a for a in xref if a in ptr_at)
    cand_set = set(cand)

    out = []
    for a, b in runs:
        cs = sorted(x for x in cand if a <= x <= b)
        segs = []
        if cs:
            if cs[0] > a:
                segs.append((a, cs[0] - 8))     # 候选前的头部片段（无引用）
            for i, c0 in enumerate(cs):
                end = cs[i + 1] - 8 if i + 1 < len(cs) else b
                segs.append((c0, end))
        else:
            segs.append((a, b))
        for s0, e0 in segs:
            n = (e0 - s0) // 8 + 1
            slots = []
            for k in range(n):
                ea = s0 + k * 8
                slots.append({"offset": k * 8, "func_rva": ptr_at[ea] - imgbase})
            out.append({"rva": s0 - imgbase, "slots": slots,
                        "first_name": name_at.get(s0, ""),
                        "label": label_at.get(s0, "")})
    return out



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--funcs", required=True)
    ap.add_argument("--asm", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default="0x140000000")
    ap.add_argument("--demumble", default=os.path.join(HERE, "demumble.exe"))
    args = ap.parse_args()

    base = int(args.base, 16)
    pe = pefile.PE(args.exe)
    sizeimg = pe.OPTIONAL_HEADER.SizeOfImage
    pdata_count = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size // 12

    # ---- 函数 ----
    rows = parse_funcs(args.funcs, base)
    print("funcs(.text): %d" % len(rows))

    # 收集需要 demumble 修复的（第 2 列仍是 mangled）
    need_fix = []
    for r in rows:
        if r["dem"].startswith("?"):
            need_fix.append(strip_ida_suffix(r["dem"]))
    fixed_map = {}
    if need_fix:
        try:
            proc = subprocess.run([args.demumble], input="\n".join(need_fix),
                                  capture_output=True, text=True, timeout=600)
            outs = proc.stdout.splitlines()
            for src, out in zip(need_fix, outs):
                if out and out != src:
                    fixed_map[src] = out
            print("demumble 修复: %d / %d" % (len(fixed_map), len(need_fix)))
        except Exception as e:
            print("demumble 失败: %s" % e)

    symbols = []
    used = set()

    def uniq(d):
        if not d:
            return d
        if d not in used:
            used.add(d)
            return d
        k = 1
        while "%s_%d" % (d, k) in used:
            k += 1
        c = "%s_%d" % (d, k)
        used.add(c)
        return c

    for r in rows:
        dem = r["dem"]
        if dem.startswith("?"):
            base_name = strip_ida_suffix(dem)
            dem = fixed_map.get(base_name, "")
        dem = strip_params(dem)
        if not dem:
            dem = "sub_0x%X" % r["rva"]
        mangled = r["raw"] if r["raw"].startswith("?") else ""
        symbols.append({
            "demangled": uniq(dem),
            "mangled": mangled,
            "rva": "0x%X" % r["rva"],
            "kind": "function",
            "size": r["size"],
        })

    # ---- vtable：off_/DATA XREF 候选起点 + 指针段切分 ----
    func_name_by_rva = {r["rva"]: r["dem"] for r in rows}
    vts_labeled = parse_vtables(args.asm, args.exe, base)
    label_by_rva = {v["rva"]: v["label"] for v in vts_labeled}
    segs = scan_candidate_vtables(args.asm, args.exe, base)
    total_vt_slots = 0
    for seg in segs:
        lab = seg.get("label", "")
        if lab.startswith("??_7"):
            dem = vtable_demangle(lab)
            mang = lab
        elif lab.startswith("off_"):
            dem = lab          # IDA 给的未命名指针表名字
            mang = ""
        elif seg["rva"] in label_by_rva:
            dem = vtable_demangle(label_by_rva[seg["rva"]])
            mang = label_by_rva[seg["rva"]]
        else:
            cls = class_from_function_name(seg["first_name"])
            if not cls and seg["slots"]:
                fr = seg["slots"][0]["func_rva"]
                cls = class_from_function_name(func_name_by_rva.get(fr, ""))
            dem = (cls + "::vftable") if cls else ("vftable_0x%X" % seg["rva"])
            mang = ""
        slots = seg["slots"]
        symbols.append({
            "demangled": uniq(dem),
            "mangled": mang,
            "rva": "0x%X" % seg["rva"],
            "kind": "vtable",
            "slotCount": len(slots),
            "slots": [{"offset": sl["offset"], "funcRva": "0x%X" % sl["func_rva"]}
                      for sl in slots],
        })
        total_vt_slots += len(slots)
    print("vtables: %d (labeled %d), slots: %d" % (len(segs), len(vts_labeled), total_vt_slots))

    obj = {
        "version": 1,
        "baseSizeOfImage": "0x%X" % sizeimg,
        "pdataCount": pdata_count,
        "symbols": symbols,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

    mangled_left = sum(1 for s in symbols if s["kind"] == "function" and not s["demangled"])
    print("symbols: %d (function %d, vtable %d)" % (len(symbols), len(rows), sum(1 for x in symbols if x["kind"] == "vtable")))
    print("无 demangled 的函数: %d" % mangled_left)
    print("written: %s" % args.out)


if __name__ == "__main__":
    main()
