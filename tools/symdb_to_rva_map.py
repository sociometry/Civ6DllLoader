#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
symdb_to_rva_map.py

读取 Civ6DllLoader.symdb.json，生成以 rva 为键的符号映射：

{
  "0x1000": {
    "kind": "function",
    "demangled": "...",
    "mangled": "...",          # 非 mangled 函数为空字符串
    "vtable_xrefs": ["0x9D8890:0x0", "0x9D8890:0x8"]
  },
  "0x9D8890": {
    "kind": "vtable",
    "demangled": "...",
    "mangled": "...",
    "vtable_xrefs": []
  }
}

vtable_xrefs 格式： "vtable_rva:slotOffset"（均为 0x 十六进制）。
用法:
  python symdb_to_rva_map.py [input.json] [output.json]
"""

import json
import sys
import os

DEFAULT_INPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Civ6DllLoader.symdb.json")
DEFAULT_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rva_map.json")


def hexstr(rva: int) -> str:
    return f"0x{rva:X}"


def main():
    input_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_INPUT
    output_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUTPUT

    with open(input_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rva_map = {}

    # 第一遍：建立所有符号条目
    for sym in data["symbols"]:
        rva = int(sym["rva"], 16)
        kind = sym["kind"]
        rva_map[hexstr(rva)] = {
            "kind": kind,
            "demangled": sym.get("demangled", ""),
            "mangled": sym.get("mangled", ""),
            "vtable_xrefs": [],
        }

    # 第二遍：把 vtable 槽位引用（vtable_rva:slotOffset）加到被引用函数上
    for sym in data["symbols"]:
        if sym["kind"] != "vtable":
            continue

        vtable_rva = int(sym["rva"], 16)
        for slot in sym.get("slots", []):
            slot_offset = int(slot["offset"])
            func_rva = int(slot["funcRva"], 16)

            func_key = hexstr(func_rva)
            if func_key in rva_map:
                rva_map[func_key]["vtable_xrefs"].append(
                    f"{hexstr(vtable_rva)}:{hexstr(slot_offset)}"
                )

    # 去重并按 (vtable_rva, offset) 升序排列
    def xref_key(x: str):
        vt, off = x.split(":")
        return (int(vt, 16), int(off, 16))

    for key, entry in rva_map.items():
        entry["vtable_xrefs"] = sorted(set(entry["vtable_xrefs"]), key=xref_key)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(rva_map, f, ensure_ascii=False, indent=2)

    print(f"wrote {output_path}: {len(rva_map)} entries")


if __name__ == "__main__":
    main()
