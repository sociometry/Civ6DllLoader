#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pack_multi_sidecar.py - 把多个 sidecar 容器合并成一个容器（唯一格式 v1）

容器格式（小端 pack(1)）:
  Header (32B):
    +0   char   magic[4]          = "C6SD"
    +4   uint32 version           = 1
    +8   uint32 moduleCount
    +12  uint32 moduleTableOffset = 32
    +16  uint32 moduleTableSize   = moduleCount * 64
    +20  uint32 dataOffset        (第一个模块数据的起始, 8 对齐)
    +24  uint32 flags
    +28  uint32 reserved
  ModuleDesc (64B * moduleCount, 紧跟 header):
    +0   uint32 imageId           (1=ExeDx11, 2=ExeDx12, 5=GameCoreXP2)
    +4   uint32 baseSizeOfImage
    +8   uint32 baseTimeDateStamp
    +12  uint32 pdataOffset       // 以下 offset 均为文件绝对偏移
    +16  uint32 pdataCount
    +20  uint32 symbolOffset
    +24  uint32 symbolCount
    +28  uint32 vtableOffset
    +32  uint32 vtableSlotCount
    +36  uint32 heapOffset
    +40  uint32 heapSize
    +44  uint32 aobOffset
    +48  uint32 aobSize
    +52  uint32 reserved[3]
  Data: 各模块的 5 个块依次排列（pdata / symbol / vtable slots / heap / aob，8B 对齐）

输入是 build_sidecar.py 产出的容器（每个 1..N 个模块），输出的模块表按输入顺序拼接。

Run:
  python pack_multi_sidecar.py --out Civ6DllLoader.symdb.pack.bin \
      --module Civ6DllLoader.symdb.bin --module CivilizationVI.symdb.bin \
      --module CivilizationVI_DX12.symdb.bin
  python pack_multi_sidecar.py --list Civ6DllLoader.symdb.pack.bin
"""

import argparse
import struct
import sys

MAGIC = b"C6SD"
VERSION = 1
HDR = 32
DESC = 64
IMAGE_NAMES = {1: "ExeDx11", 2: "ExeDx12", 3: "GameCoreBase", 4: "GameCoreXP1", 5: "GameCoreXP2"}


def align8(x):
    return x + ((8 - (x % 8)) % 8)


def read_modules(path):
    """读一个容器，返回其中的模块列表（每个模块含各段字节）。"""
    d = open(path, "rb").read()
    if d[:4] != MAGIC:
        raise ValueError(path + " 不是 C6SD")
    ver, count, moff, msize, doff, flags, res = struct.unpack_from("<IIIIIII", d, 4)
    if ver != VERSION:
        raise ValueError("%s version=%d（期望 %d）" % (path, ver, VERSION))
    if not (1 <= count <= 8):
        raise ValueError("%s moduleCount=%d（期望 1..8）" % (path, count))
    if moff + msize > len(d) or msize < count * DESC:
        raise ValueError("%s 模块表越界（off=%d size=%d）" % (path, moff, msize))

    mods = []
    for i in range(count):
        f = struct.unpack_from("<16I", d, moff + i * DESC)
        (iid, sizeimg, stamp, pdo, pdc, syo, syc, vto, vtc, ho, hs, ao, asz) = f[:13]

        def blk(off, n, what):
            if off + n > len(d):
                raise ValueError("%s[%d] %s 越界（off=%d n=%d）" % (path, i, what, off, n))
            return d[off:off + n]

        mods.append({
            "path": path,
            "imageId": iid,
            "baseSizeOfImage": sizeimg,
            "baseTimeDateStamp": stamp,
            "pdata": blk(pdo, pdc * 16, "pdata"),
            "pdataCount": pdc,
            "symbols": blk(syo, syc * 32, "symbols"),
            "symbolCount": syc,
            "slots": blk(vto, vtc * 8, "vtable slots"),
            "slotCount": vtc,
            "heap": blk(ho, hs, "heap"),
            "heapSize": hs,
            "aob": blk(ao, asz, "aob"),
            "aobSize": asz,
        })
    return mods


def pack(out_path, paths):
    mods = []
    for p in paths:
        mods.extend(read_modules(p))

    seen = set()
    for m in mods:
        if m["imageId"] in seen:
            raise ValueError("imageId %d 重复（%s）" % (m["imageId"], m["path"]))
        seen.add(m["imageId"])

    data_off = align8(HDR + DESC * len(mods))
    out = bytearray()
    out += MAGIC + struct.pack("<IIIIIII", VERSION, len(mods), HDR,
                               DESC * len(mods), data_off, 0, 0)
    assert len(out) == HDR

    table = bytearray()
    blocks = bytearray()

    def add_block(data):
        off = data_off + len(blocks)
        blocks.extend(data)
        blocks.extend(bytes((8 - (len(blocks) % 8)) % 8))
        return off

    for m in mods:
        m["pdataOffset"] = add_block(m["pdata"])
        m["symbolOffset"] = add_block(m["symbols"])
        m["vtableOffset"] = add_block(m["slots"])
        m["heapOffset"] = add_block(m["heap"])
        m["aobOffset"] = add_block(m["aob"])

    for m in mods:
        table += struct.pack(
            "<IIIIIIIIIIIIIIII",
            m["imageId"], m["baseSizeOfImage"], m["baseTimeDateStamp"],
            m["pdataOffset"], m["pdataCount"],
            m["symbolOffset"], m["symbolCount"],
            m["vtableOffset"], m["slotCount"],
            m["heapOffset"], m["heapSize"],
            m["aobOffset"], m["aobSize"],
            0, 0, 0)
    assert len(table) == DESC * len(mods)

    out += table
    assert len(out) == data_off
    out += blocks
    with open(out_path, "wb") as f:
        f.write(out)
    print("packed: %s (%d 字节, %d 模块)" % (out_path, len(out), len(mods)))
    for m in mods:
        print("   image %d (%-12s) sizeOfImage=0x%X stamp=0x%08X "
              "pdata=%d symbols=%d slots=%d heap=%d aob=%d [%s]"
              % (m["imageId"], IMAGE_NAMES.get(m["imageId"], "?"),
                 m["baseSizeOfImage"], m["baseTimeDateStamp"],
                 m["pdataCount"], m["symbolCount"], m["slotCount"],
                 m["heapSize"], m["aobSize"], m["path"]))


def list_pack(path):
    d = open(path, "rb").read()
    if d[:4] != MAGIC:
        print("不是 C6SD")
        return
    ver, count, moff, msize, doff, flags, res = struct.unpack_from("<IIIIIII", d, 4)
    print("C6SD version=%d modules=%d moduleTable=%d/%d dataOffset=%d flags=%d"
          % (ver, count, moff, msize, doff, flags))
    for i in range(count):
        o = moff + i * DESC
        (iid, sizeimg, stamp, pdo, pdc, syo, syc, vto, vtc, ho, hs, ao, asz,
         r1, r2, r3) = struct.unpack_from("<IIIIIIIIIIIIIIII", d, o)
        print("   [%d] image=%d (%-12s) sizeOfImage=0x%X stamp=0x%08X"
              % (i, iid, IMAGE_NAMES.get(iid, "?"), sizeimg, stamp))
        print("        pdata off=%d cnt=%d | symbol off=%d cnt=%d | vtable off=%d slots=%d | heap off=%d size=%d | aob off=%d size=%d"
              % (pdo, pdc, syo, syc, vto, vtc, ho, hs, ao, asz))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--module", action="append", default=[],
                    help="输入容器路径，可多次（模块身份来自容器自带的 imageId）")
    ap.add_argument("--list")
    args = ap.parse_args()
    if args.list:
        list_pack(args.list)
        return
    if not args.out or not args.module:
        print("需要 --out 和至少一个 --module")
        sys.exit(1)
    pack(args.out, args.module)


if __name__ == "__main__":
    main()
