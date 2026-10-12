#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_rva_map.py - 从三个 symdb JSON 生成 rva_to_symbol 的内嵌符号表

产物（默认写到 tools/rva_to_symbol/data/）：
    rva_map.gamecore.z   <- GameCore.symdb.json          (image 5)
    rva_map.dx11.z       <- CivilizationVI.symdb.json    (image 1)
    rva_map.dx12.z       <- CivilizationVI_DX12.symdb.json (image 2)

这三个文件由 rva_to_symbol 用 include_bytes! 在**编译期**嵌入 exe，运行时只解压 +
解析**选中的那一份**，因此：
    - 交付物是单个 exe，没有 sidecar 要跟着分发；
    - 查某个映像时不解压另外两个。

压缩格式选 zlib 而非 lzma：lzma 能再小 1 MB（1.7 MB vs 2.7 MB），但纯 Rust 的
lzma-rs 解压要 ~120 ms，而 zlib（miniz_oxide）只要 ~25 ms —— 对一个每次查表都要
走一遍启动路径的 cli 工具，速度比那 1 MB 值钱。

数据格式：{ "<rva>": {kind, demangled, mangled, vtable_xrefs[]}, ... }
键为 "0x<大写十六进制>"；工具侧做小写归一化后精确查表。

用法：
    python tools/gen_rva_map.py                 # 生成三个压缩包
    python tools/gen_rva_map.py --check         # 只核对已存在的产物是否需要更新
    python tools/gen_rva_map.py --image dx12    # 只生成一个

生成后需要重新编译 rva_to_symbol（见 tools/build_rva_to_symbol.bat）。
"""

import argparse
import json
import os
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "rva_to_symbol", "data")

# (flag 名, symdb JSON, 输出文件名, imageId, 显示名)
IMAGES = [
    ("gamecore", "GameCore.symdb.json", "rva_map.gamecore.z", 5, "GameCoreXP2"),
    ("dx11", "CivilizationVI.symdb.json", "rva_map.dx11.z", 1, "ExeDx11"),
    ("dx12", "CivilizationVI_DX12.symdb.json", "rva_map.dx12.z", 2, "ExeDx12"),
]


def hexstr(rva: int) -> str:
    return f"0x{rva:X}"


def build_map(symdb_path: str) -> dict:
    """与 symdb.py:build_rva_map 同源的构建逻辑（保持产物可比对）。"""
    with open(symdb_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rva_map = {}
    # 第一遍：所有符号条目
    for sym in data["symbols"]:
        rva = int(sym["rva"], 16)
        rva_map[hexstr(rva)] = {
            "kind": sym["kind"],
            "demangled": sym.get("demangled", ""),
            "mangled": sym.get("mangled", ""),
            "vtable_xrefs": [],
        }

    # 第二遍：vtable 槽位引用挂到被引用的函数上
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

    def xref_key(x: str):
        vt, off = x.split(":")
        return (int(vt, 16), int(off, 16))

    for entry in rva_map.values():
        entry["vtable_xrefs"] = sorted(set(entry["vtable_xrefs"]), key=xref_key)
    return rva_map


def gen_one(flag: str, json_name: str, out_name: str, image_id: int, label: str,
            check_only: bool) -> int:
    src = os.path.join(HERE, json_name)
    dst = os.path.join(DATA_DIR, out_name)
    if not os.path.isfile(src):
        print(f"[{flag}] 缺少输入 {src}", file=sys.stderr)
        return 1

    # 解析在两种模式下都需要：check 要重新算出内容才能比对
    rva_map = build_map(src)
    raw = json.dumps(rva_map, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # zlib level 9：体积接近 lzma 的 1.5 倍，但解压快 4-5 倍（见模块 docstring）。
    packed = zlib.compress(raw, 9)

    if check_only:
        if not os.path.isfile(dst):
            print(f"[{flag}] 产物缺失：{dst}")
            return 1
        with open(dst, "rb") as f:
            cur = f.read()
        if cur != packed:
            print(f"[{flag}] 产物已过期：{out_name}")
            return 1
        print(f"[{flag}] OK  image={image_id} ({label})  {len(rva_map)} entries, "
              f"{len(packed)/1048576:.2f} MB")
        return 0

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(dst, "wb") as f:
        f.write(packed)
    print(f"[{flag}] image={image_id} ({label})  entries={len(rva_map)}  "
          f"raw={len(raw)/1048576:.1f} MB -> {len(packed)/1048576:.2f} MB  {out_name}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="从 symdb JSON 生成 rva_to_symbol 的内嵌符号表（lzma 压缩）")
    ap.add_argument("--check", action="store_true",
                    help="只核对现有产物是否需要重新生成（不写文件）")
    ap.add_argument("--image", choices=[f for f, *_ in IMAGES], action="append",
                    help="只处理指定映像，可重复；省略=全部")
    args = ap.parse_args()

    want = set(args.image) if args.image else {f for f, *_ in IMAGES}
    rc = 0
    for flag, json_name, out_name, image_id, label in IMAGES:
        if flag not in want:
            continue
        rc |= gen_one(flag, json_name, out_name, image_id, label, args.check)
    if rc == 0 and not args.check:
        print("\n下一步：tools/build_rva_to_symbol.bat 重新编译（数据是编译期嵌入的）")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
