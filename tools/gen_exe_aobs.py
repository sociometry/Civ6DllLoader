#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_exe_aobs.py - 生成/核对 exe 域 loader 目标的 AOB（供 HookInfo/HookInfoExe 使用）。

规则：
  * 函数目标：以容器里该变体模块的 mask 指纹（0xFF 必配 / 0x00 通配）为起点，
    命中不唯一就逐字节向函数体内扩，直到唯一。
    扩到整个函数仍不唯一（同码兄弟函数）时，用「第几个命中」来区分：
    HookInfo.index（1 起）——本工具会算出目标在升序命中表里的位置，
    两个变体位置一致才认为可用（否则上报）。
  * 数据槽：AOB 由人工用 | 分段、xx xx xx xx 标 disp32；
    本工具用 capstone 校验「每段正好是完整指令」「含 xx 的段内恰好一组 xx」
    「D+4<=E」，再扫 exe 确认目标命中，并打印解出的全局地址。

用法：
  python gen_exe_aobs.py                 # 生成/核对全部目标
  python gen_exe_aobs.py --emit-cpp      # 输出可粘贴进 LoaderHooks.cpp / UiInject.cpp 的常量块
  python gen_exe_aobs.py --exe-dir <dir> # 指定两个 exe 所在目录
退出码 0 = 全部可用；1 = 有需要人工处理的目标。
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

HERE = Path(__file__).resolve().parent
DEFAULT_PACK = HERE / "Civ6DllLoader.symdb.pack.bin"
DEFAULT_EXE_DIR = Path(r"E:\SteamLibrary\steamapps\common\Sid Meier's Civilization VI\Base\Binaries\Win64Steam")
IMAGE_NAMES = {1: "ExeDx11", 2: "ExeDx12"}

# 函数目标：(名字, dx11 RVA, dx12 RVA)
FUNC_TARGETS = [
    ("LoadDLL",          0xF8510,  0xF8850),
    ("UnloadDLL",        0xF8E30,  0xF9170),
    ("GetConfiguration", 0x100390, 0x100CE0),
    ("GetRuleSet",       0x100F40, 0x101890),
    ("LoadUI",           0x8AB40,  0x8B080),
    ("AllocLuaCtx",      0x7A500,  0x7A9B0),
    ("ChangeParent",     0x8707D0, 0x872550),
    ("DestroyChild",     0x871410, 0x873190),
]

# 数据槽：(名字, AOB) —— | 分段，xx 标 disp32
DATA_SLOTS = [
    ("hModule",
     "48 81 EC 48 02 00 00 | 48 83 3D xx xx xx xx 00 | 74 0A 32 C0 48 81 C4 48 02 00 00"),
    ("UIManager",
     "48 8B 0D xx xx xx xx | E8 ?? ?? ?? ?? 48 89 87 30 02 00 00"),
]


def load_pack(path: Path):
    d = path.read_bytes()
    if d[:4] != b"C6SD" or struct.unpack_from("<I", d, 4)[0] != 1:
        raise SystemExit(f"{path} 不是 C6SD v1 容器")
    count, moff = struct.unpack_from("<I", d, 8)[0], struct.unpack_from("<I", d, 12)[0]
    mods = {struct.unpack_from("<16I", d, moff + i * 64)[0]: struct.unpack_from("<16I", d, moff + i * 64)
            for i in range(count)}
    out = {}
    for img in (1, 2):
        f = mods[img]
        syo, syc, ao, aasz = f[5], f[6], f[11], f[12]
        order = []
        for i in range(syc):
            kind = struct.unpack_from("<IIIB", d, syo + i * 32)[3]
            if kind == 0:
                order.append(struct.unpack_from("<I", d, syo + i * 32 + 8)[0])
        cur, end, ent = ao, ao + aasz, {}
        for rva in order:
            if cur + 4 > end:
                break
            bs = struct.unpack_from("<I", d, cur)[0]
            cur += 4
            if bs == 0 or cur + 2 * bs > end:
                break
            ent[rva] = (d[cur:cur + bs], d[cur + bs:cur + 2 * bs])
            cur += 2 * bs
        out[img] = ent
    return out


class Exe:
    def __init__(self, path: Path):
        self.pe = pefile.PE(str(path), fast_load=True)
        self.pe.parse_data_directories()
        self.data = path.read_bytes()
        self.secs = [(s.Name.rstrip(b"\0").decode(), s.VirtualAddress, s.Misc_VirtualSize,
                      s.SizeOfRawData, s.PointerToRawData) for s in self.pe.sections]
        for nm, va, vsz, rawsz, praw in self.secs:
            if nm == ".text":
                self.text, self.va = self.data[praw:praw + rawsz], va
        self.size = self.pe.OPTIONAL_HEADER.SizeOfImage

    def ro(self, rva, n):
        for nm, va, vsz, rawsz, praw in self.secs:
            if va <= rva < va + max(vsz, rawsz):
                o = praw + (rva - va)
                if o + n <= len(self.data):
                    return self.data[o:o + n]
        return None

    def section_of(self, rva):
        for nm, va, vsz, rawsz, praw in self.secs:
            if va <= rva < va + max(vsz, rawsz):
                return nm
        return None

    def func_size(self, rva):
        exc = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        raw = self.ro(exc.VirtualAddress, exc.Size)
        for i in range(exc.Size // 12):
            b, e, u = struct.unpack_from("<III", raw, i * 12)
            if b == rva:
                return e - b
        return 0

    def count(self, body: bytes, mask: list) -> list:
        """全部命中（升序）。"""
        best = (0, 0)
        i = 0
        while i < len(mask):
            if mask[i]:
                j = i
                while j < len(mask) and mask[j]:
                    j += 1
                if j - i > best[0]:
                    best = (j - i, i)
                i = j
            else:
                i += 1
        if best[0] < 3:
            return []
        seed = body[best[1]:best[1] + best[0]]
        out, s = [], 0
        while True:
            k = self.text.find(seed, s)
            if k < 0:
                break
            p = k - best[1]
            if p >= 0 and p + len(mask) <= len(self.text):
                if all((not mask[t]) or self.text[p + t] == body[t] for t in range(len(mask))):
                    out.append(self.va + p)
            s = k + 1
            if len(out) > 4000:
                break
        return sorted(out)


def pat_str(body: bytes, mask: list) -> str:
    return " ".join("??" if mask[i] == 0 else "%02X" % body[i] for i in range(len(mask)))


def gen_func_aob(exe: Exe, rva: int, finger):
    """-> (pattern 或 None, 升序命中表, 说明)"""
    body, mask = bytearray(finger[0]), list(finger[1])
    if len(mask) == 0:
        return None, [], "容器无该 RVA 的指纹"
    fsz = exe.func_size(rva) or 4096
    hits = exe.count(bytes(body), mask)
    while len(hits) > 1 and len(mask) < min(fsz, 512):
        nb = exe.ro(rva + len(mask), 1)
        if nb is None:
            break
        body.append(nb[0])
        mask.append(0xFF)
        hits = exe.count(bytes(body), mask)
    if len(hits) == 1:
        return pat_str(bytes(body), mask), hits, "唯一"
    if rva in hits:
        pos = hits.index(rva) + 1
        return (pat_str(bytes(body), mask), hits,
                "扩到 %d 字节仍 %d 处命中（函数长 %d），目标为升序第 %d 个"
                % (len(mask), len(hits), fsz, pos))
    return None, hits, "目标不在命中表内（指纹与容器不一致？）"


def parse_marked(aob: str):
    """-> (flat_tokens, segs[(S,E,tokens)], D, S, E) 或抛 ValueError"""
    toks = aob.split()
    segs, cur, start, off = [], [], 0, 0
    for t in toks:
        if t == "|":
            segs.append((start, off, cur))
            start, cur = off, []
            continue
        if t not in ("??", "xx") and not all(c in "0123456789abcdefABCDEF" for c in t):
            raise ValueError(f"非法 token {t!r}")
        cur.append(t)
        off += 1
    segs.append((start, off, cur))
    xx_segs = [i for i, s in enumerate(segs) if "xx" in s[2]]
    if len(xx_segs) != 1:
        raise ValueError(f"含 xx 的段必须恰好一个（实际 {len(xx_segs)}）")
    si = xx_segs[0]
    S, E, segtoks = segs[si]
    groups = [i for i in range(len(segtoks) - 3) if segtoks[i:i + 4] == ["xx"] * 4]
    if len(groups) != 1:
        raise ValueError(f"目标段内 xx 组必须恰好一个（实际 {len(groups)}）")
    D = S + groups[0]
    if D + 4 > E:
        raise ValueError("xx 组越出目标段")
    flat = [t for t in toks if t != "|"]
    return flat, segs, D, S, E


def collect(pack, exes):
    """-> (entries, bad)：entries = [(name, r11, r12, {img: (pattern, hits, note, index)})]"""
    entries, bad = [], 0
    for name, r11, r12 in FUNC_TARGETS:
        per = {}
        for img, rva in ((1, r11), (2, r12)):
            finger = pack[img].get(rva)
            if finger is None:
                per[img] = (None, [], "容器无该 RVA 的指纹", 0)
                continue
            pat, hits, note = gen_func_aob(exes[img], rva, finger)
            index = 1
            if pat and len(hits) > 1:
                index = hits.index(rva) + 1 if rva in hits else 0
            per[img] = (pat, hits, note, index)
        entries.append((name, r11, r12, per))
    return entries


def verify(pack, exes) -> int:
    entries = collect(pack, exes)
    bad = 0
    print("== 函数目标（容器指纹起，扩到唯一；仍不唯一则用 index 选第几个命中）")
    for name, r11, r12, per in entries:
        idxs = [per[1][3], per[2][3]]
        usable = all(per[i][0] for i in (1, 2)) and all(per[i][3] > 0 for i in (1, 2))
        consistent = idxs[0] == idxs[1]
        if usable and consistent:
            mark = "OK "
        else:
            mark = "!! "
            bad += 1
        for img, rva in ((1, r11), (2, r12)):
            pat, hits, note, index = per[img]
            if not pat:
                print("  %s%-17s %-7s 0x%-8X %s" % (mark, name, IMAGE_NAMES[img], rva, note))
                continue
            extra = "" if index == 1 else "  -> index=%d" % index
            print("  %s%-17s %-7s 0x%-8X %s%s" % (mark, name, IMAGE_NAMES[img], rva, note, extra))
            if index != 1:
                print("        命中表: %s" % ["0x%X" % h for h in hits])
        if usable and not consistent:
            print("  !! %s 两变体的 index 不一致（%s）" % (name, idxs))

    print()
    print("== 数据槽（| 分段 + xx=disp32；capstone 校验段=完整指令）")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for name, aob in DATA_SLOTS:
        print("  %s" % name)
        try:
            flat, segs, D, S, E = parse_marked(aob)
        except ValueError as exc:
            print("     !! 格式非法：%s" % exc); bad += 1; continue
        print("     段: %s | 目标段 [%d,%d) 长 %d，D=%d" % ([(s[0], s[1]) for s in segs], S, E, E - S, D))
        for img, exe in exes.items():
            ok_seg = True
            for (sS, sE, stoks) in segs:
                raw = bytes(0x90 if t in ("??", "xx") else int(t, 16) for t in stoks)
                insns = list(md.disasm(raw, 0))
                if sum(i.size for i in insns) != sE - sS:
                    ok_seg = False
                    print("     !! %s 段 [%d,%d) 不是完整指令" % (IMAGE_NAMES[img], sS, sE))
            mask = [0 if t in ("??", "xx") else 0xFF for t in flat]
            body = bytes(0 if t in ("??", "xx") else int(t, 16) for t in flat)
            hits = exe.count(body, mask)
            if len(hits) != 1:
                print("     !! %s 命中 %d 处" % (IMAGE_NAMES[img], len(hits))); bad += 1; continue
            H = hits[0]
            disp = struct.unpack_from("<i", exe.text, H - exe.va + D)[0]
            tgt = H + E + disp
            sec = exe.section_of(tgt)
            ok = ok_seg and sec is not None
            if not ok:
                bad += 1
            print("     %s%s H=0x%-8X disp32=0x%08X -> 0x%X [%s]%s" % (
                "OK " if ok else "!! ", IMAGE_NAMES[img], H, disp & 0xFFFFFFFF, tgt, sec,
                "" if ok else "  （目标不在映像内/段非法）"))
    print()
    print("ALL OK" if bad == 0 else "有 %d 项需要人工处理" % bad)
    return 0 if bad == 0 else 1


def emit_cpp(pack, exes) -> int:
    entries = collect(pack, exes)
    lines = ["// ---- 本块由 tools/gen_exe_aobs.py --emit-cpp 生成；重建符号库/游戏更新后重新生成 ----", ""]
    emitted = {}

    def cname(name):
        return "kAob_" + name

    for name, r11, r12, per in entries:
        p1, p2 = per[1][0], per[2][0]
        if p1 and p2 and p1 == p2:
            key = cname(name)
            if key not in emitted:
                emitted[key] = p1
                lines.append('constexpr char %s[] = "%s";' % (key, p1))
        else:
            for img, suffix in ((1, "Dx11"), (2, "Dx12")):
                if per[img][0]:
                    key = "%s_%s" % (cname(name), suffix)
                    if key not in emitted:
                        emitted[key] = per[img][0]
                        lines.append('constexpr char %s[] = "%s";' % (key, per[img][0]))
    lines.append("")
    for name, r11, r12, per in entries:
        same = per[1][0] and per[2][0] and per[1][0] == per[2][0]

        def ref(img, suffix):
            if not per[img][0]:
                return None
            return cname(name) if same else "%s_%s" % (cname(name), suffix)

        def init(rva, img, suffix):
            r = ref(img, suffix)
            if not r:
                return "HookRva(0x%X)" % rva
            idx = per[img][3]
            return "HookRva(0x%X, %s%s)" % (rva, r, "" if idx <= 1 else ", %d" % idx)

        lines.append("constexpr HookInfoExe kExe%s = { %s, %s };" % (
            name, init(r11, 1, "Dx11"), init(r12, 2, "Dx12")))
    lines.append("")
    lines.append('// 数据槽：| 分指令段，xx = disp32，用 ResolveDataByAob 解出全局地址')
    for name, aob in DATA_SLOTS:
        lines.append('constexpr char kAob_%s[] = "%s";' % (name, aob))
    print("\n".join(lines))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", default=str(DEFAULT_PACK))
    ap.add_argument("--exe-dir", default=str(DEFAULT_EXE_DIR))
    ap.add_argument("--emit-cpp", action="store_true",
                    help="只输出可直接粘贴进 LoaderHooks.cpp / UiInject.cpp 的 constexpr 常量块")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    pack = load_pack(Path(args.pack))
    exe_dir = Path(args.exe_dir)
    exes = {1: Exe(exe_dir / "CivilizationVI.exe"), 2: Exe(exe_dir / "CivilizationVI_DX12.exe")}
    if args.emit_cpp:
        return emit_cpp(pack, exes)
    return verify(pack, exes)


if __name__ == "__main__":
    raise SystemExit(main())
