#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
symdb.py - Civ6 符号库（sidecar）流水线唯一入口

原先 tools/ 下的 7 个脚本合并成这一个带子命令的入口；每条老命令行只需把
脚本名换成 "python tools/symdb.py <子命令>"，参数名保持不变：

    json-exe   从 IDA 导出（.funcs.txt + .rdata .asm）+ 去 DRM exe 生成 exe 版 symdb JSON
    module     JSON + 对应 PE -> 单模块 sidecar 容器（依赖 aob_helper.exe / normhash_helper.exe）
    pack       多个单模块容器 -> Civ6DllLoader.symdb.pack.bin（--module 可多次；--list 只查）
    compress   pack.bin -> "C6XC"+LZMA1 信封 .xp（自带 SHA256 roundtrip 校验）
    validate   按运行时同款解析独立校验 .bin / .xp
    aob        从 pack.bin 的 mask 指纹生成/核对 loader 的 AOB 常量（--emit-cpp）
    all        一条命令跑完整条产线：module x3 -> pack -> compress -> 部署 -> validate -> 清理中间产物

（原先的 rva-map 子命令已迁到 tools/gen_rva_map.py：rva_to_symbol 现在把
 gamecore/dx11/dx12 三个映像的符号表压缩后编译期嵌入 exe，生成端要做三份 + 压缩。）

帮助：python tools/symdb.py <子命令> -h


================================================================================
可复现边界（2026-09-16 定）
================================================================================
  JSON -> .bin -> pack.bin -> .xp -> 部署/validate：**本脚本保证逐字节复现**
  （已验：module x3 / pack / compress 的 5 个产物 md5 与入库文件一致）。
  IDA 导出 -> JSON：**不在保证范围内**。JSON 是某一份 IDB 的快照：
    - 函数集合取决于 IDB 的分析状态（同一 PE 两次导出可差几十个函数）；
    - 名字全部来自 IDB，脚本只做 demangle/去重，不产生名字；
    - .rdata 段的 .asm 导出目前是 IDA 里的手工步骤（本仓库无脚本）；
    - JSON 的 "version" 只是历史标签；从未发布过，不做版本兼容分支，
      只接受 JSON_SCHEMA_VERSIONS 里列出的已知标签，未知值硬失败。


================================================================================
容器格式（小端，唯一 v1，"C6SD"）
================================================================================
  Header (32B, CTR_HDR):
    +0   char   magic[4]          = "C6SD"
    +4   uint32 version           = 1
    +8   uint32 moduleCount
    +12  uint32 moduleTableOffset = 32
    +16  uint32 moduleTableSize   = moduleCount * 64
    +20  uint32 dataOffset        (第一个模块数据的起始, 8 对齐)
    +24  uint32 flags
    +28  uint32 reserved
  ModuleDesc (64B, DESC, 紧跟 header):
    +0   uint32 imageId           (1=ExeDx11, 2=ExeDx12, 5=GameCoreXP2)
                                   ⚠️ 只支持这三个值。HookImageId 枚举里的 3=GameCoreBase /
                                   4=GameCoreXP1 是保留值，运行时 PdataMatch 遇到它们会
                                   直接判为 unsupported 并【拒载整个容器】，所以别打进去。
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
  Data: 每个模块的 5 个块依次排列（pdata / symbol / vtable slots / heap / aob，均 8B 对齐）

  pdata 表   16B/条 (PDATA_ENTRY):  <IIQ> begin_rva, size, unwind_hash(fnv1a64)
  符号表     32B/条 (SYMBOL_ENTRY): <III BHB Q II>
               dem_off, man_off, old_rva, kind(0=func / 1=vtable), u16 slotCount,
               u8 reserved, head_hash, r2, r3
               （vtableSlotCount 走 16 位 <BHB>，装载时再扩成 u32）
  vtable 槽  8B/条 (VTABLE_SLOT):  <II> slotOffset, funcRva
  heap       变长:  名字池，NUL 结尾，offset 0 保留
  aob        变长:  <I bodySize> + body[bodySize] + mask[bodySize]（bodySize <= MAX_AOB=64）

  各段在模块内按 [pdata, symbol, vtable, heap, aob] 顺序 8 字节对齐依次排列（padding8 补齐），
  所以"前一段末尾 == 后一段 offset"只在恰好对齐时成立，中间可能有填充字节。
  validate 实际检查的是【各段是否都落在容器 blob 范围内】（_check_extents），外加模块内
  符号/vtable/AOB 的游标消耗守恒；不检查上面的相邻等式。


================================================================================
压缩信封（只有一种，"C6XC" + LZMA1）
================================================================================
    b"C6XC" + uint32 algo(=1, LZMA1) + uint32 original_size + payload
    payload = .lzma 头（13B: 5B props + 8B 原始大小）+ LZMA1 流

  运行时 DllLoaderRuntime/PdataMatch.cpp 的 DecompressSidecar 用
  third_party/lzma/LzmaDec 解同一条流；裸 blob（以 "C6SD" 开头）不需要信封。
  LZMA1 参数必须与 runtime 一致：props 随 .lzma 头一起写，解码端直接读头。
    preset = 9 | PRESET_EXTREME, dict = 16MB, lc=3, lp=0, pb=2
  （dict 16MB 是 44MB 容器的拐点；再大只省 0.5%。）
  实测 44.3 MB 容器（3 模块）→ 3,991,784 B（9.0%）。

  compress 只保留 LZMA1 这一条路径（运行时也只认这一种信封，见上）。


================================================================================
JSON 结构（json-exe 产出，与 GameCore.symdb.json 一致）
================================================================================
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
  json-exe 的 vtable 枚举在该子命令内部完成：parse_vtables() 读 asm 里 ??_7.../off_ label；
  scan_candidate_vtables() 扫 .rdata 指针、按候选起点（构造函数的 DATA XREF）切连续函数
  指针段 → 每段一个 vtable。没有也不需要单独的 IDA vtable 导出脚本。

rva-map 产出（rva 为键，"vtable_rva:slotOffset" 为 vtable_xrefs）：
{
  "0x1000": {"kind":"function","demangled":"...","mangled":"...",
             "vtable_xrefs":["0x9D8890:0x0","0x9D8890:0x8"]},
  "0x9D8890": {"kind":"vtable","demangled":"...","mangled":"...","vtable_xrefs":[]}
}


================================================================================
aob 子命令规则（生成/核对 exe 域 loader 目标的 AOB，供 HookInfo/HookInfoExe 使用）
================================================================================
  * 函数目标：以容器里该变体模块的 mask 指纹（0xFF 必配 / 0x00 通配）为起点，
    命中不唯一就逐字节向函数体内扩，直到唯一。
    扩到整个函数仍不唯一（同码兄弟函数）时，用「第几个命中」来区分：
    HookInfo.index（1 起）——本工具会算出目标在升序命中表里的位置，
    两个变体位置一致才认为可用（否则上报）。
  * 数据槽：AOB 由人工用 | 分段、xx xx xx xx 标 disp32；
    本工具用 capstone 校验「每段正好是完整指令」「含 xx 的段内恰好一组 xx」
    「D+4<=E」，再扫 exe 确认目标命中，并打印解出的全局地址。
  退出码 0 = 全部可用；1 = 有需要人工处理的目标。


================================================================================
构建期工具链（Windows + python3 + pefile + capstone）
================================================================================
  ① IDA 里跑 dump_functions_idapython.py        → <idb>.funcs.txt
  ② symdb.py json-exe --exe <去DRM的exe> --funcs <idb>.funcs.txt --asm <idb>.asm
       --demumble demumble.exe --out CivilizationVI[_DX12].symdb.json
  ③ symdb.py module --json <json> --dll <对应PE> --bin <单模块.bin> --image-id <id>
  ④ symdb.py pack --module 5:...bin --module 1:...bin --module 2:...bin --out ...pack.bin
  ⑤ symdb.py compress <pack.bin> <pack.bin.xp>
  ⑥ symdb.py validate <bin|xp> [...]
  部署：把 ⑤ 的产物覆盖 DllLoaderRuntime/Civ6DllLoader.symdb.bin.xp
       （Sidecar.rc 里 102 RCDATA 指向它），重新编译即内嵌。
       "symdb.py all" 已把这一步自动化。

aob_helper.exe / normhash_helper.exe / demumble.exe 继续按原来的方式用 subprocess
调用，不重写。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pefile

# ============================================================================
# 默认路径 / 格式常量（容器与信封格式只在这里定义一次）
# ============================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

DEFAULT_GAME_DIR = "E:/SteamLibrary/steamapps/common/Sid Meier's Civilization VI"
DEFAULT_DLL = DEFAULT_GAME_DIR + "/DLC/Expansion2/Binaries/Win64/GameCore_XP2_FinalRelease.dll"
DEFAULT_EXE_DIR = "E:\\SteamLibrary\\steamapps\\common\\Sid Meier's Civilization VI\\Base\\Binaries\\Win64Steam"

DEFAULT_JSON = os.path.join(HERE, "GameCore.symdb.json")
DEFAULT_BIN = os.path.join(HERE, "Civ6DllLoader.symdb.bin")
DEFAULT_PACK = os.path.join(HERE, "Civ6DllLoader.symdb.pack.bin")
DEFAULT_AOB_HELPER = os.path.join(HERE, "aob_helper.exe")
DEFAULT_NORMHASH_HELPER = os.path.join(HERE, "normhash_helper.exe")
DEFAULT_DEMUMBLE = os.path.join(HERE, "demumble.exe")

# 去 DRM 的 exe 会删掉末节的 .bind 段（SecVR 遗留段），SizeOfImage 随之变小而 TDS/pdata 不变。
# sidecar 里的 baseSizeOfImage 统一记"剥掉它之后"的值，两端（此处与运行时的
# NormalizedSizeOfImage）用同一套规则。只认 .bind，避免误伤 GameCore 末尾的 .reloc。
DRM_SECTION = b".bind"
# 运行时内嵌资源（Sidecar.rc 的 102 RCDATA）
RUNTIME_XP = os.path.join(ROOT, "DllLoaderRuntime", "Civ6DllLoader.symdb.bin.xp")

# ---------------------------------------------------------------- 容器 ("C6SD")
MAGIC = b"C6SD"
VERSION = 1
CTR_HDR = 32            # 容器头
DESC = 64               # ModuleDesc
ALIGN = 8               # 所有段 8B 对齐
PDATA_ENTRY = 16        # <IIQ>
SYMBOL_ENTRY = 32       # <III BHB Q II>
VTABLE_SLOT = 8         # <II>
MAX_AOB = 64            # 每个函数 AOB 最大存 64 字节

IMAGE_NAMES = {1: "ExeDx11", 2: "ExeDx12", 3: "GameCoreBase",
               4: "GameCoreXP1", 5: "GameCoreXP2"}

# build_module 实际消费的 JSON 结构（symbols/vtables）。version 只是生产者标签：
# 仓库里的 GameCore.symdb.json = 2，两个 exe JSON = 4 —— 三者结构完全一致。
# 保留校验是为了挡住手改坏的输入；version 始终只是标签（项目从未发布过，不做版本兼容分支），
# 未知值硬失败。
JSON_SCHEMA_VERSIONS = (1, 2, 4)

# ---------------------------------------------------------------- 信封 ("C6XC")
XP_MAGIC = b"C6XC"
TAG_LZMA = 1
LZMA_DICT_SIZE = 16 << 20
LZMA_LC, LZMA_LP, LZMA_PB = 3, 0, 2
LZMA_FILTERS = [{
    "id": lzma.FILTER_LZMA1,
    "preset": 9 | lzma.PRESET_EXTREME,
    "dict_size": LZMA_DICT_SIZE,
    "lc": LZMA_LC, "lp": LZMA_LP, "pb": LZMA_PB,
}]


def align8(x: int) -> int:
    return x + ((ALIGN - (x % ALIGN)) % ALIGN)


def padding8(n: int) -> bytes:
    return bytes((ALIGN - (n % ALIGN)) % ALIGN)


def game_dll_path(game_dir: str) -> str:
    return os.path.join(game_dir, "DLC", "Expansion2", "Binaries", "Win64",
                        "GameCore_XP2_FinalRelease.dll")


def game_exe_dir(game_dir: str) -> str:
    return os.path.join(game_dir, "Base", "Binaries", "Win64Steam")


# ============================================================================
# 一、名字处理（json-exe 用）
# ============================================================================

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


# ============================================================================
# 二、json-exe：IDA 导出 + 去 DRM exe -> exe 版 symdb JSON
# ============================================================================

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


def normalized_size_of_image(pe) -> int:
    """SizeOfImage 的"去 DRM 视图"：剥掉末尾连续的 DRM 段后重算。

    去 DRM 的 exe 删掉了末节的 .bind 段（SecVR 遗留段），SizeOfImage 因此比原版小
    0x33000，而 TimeDateStamp 与 .pdata 表逐字节不变。若这里记原始 SizeOfImage，
    运行时（PdataMatch.cpp 的 NormalizedSizeOfImage，已剥掉 .bind 再比）就对不上，
    会退化成"逐条比 pdata 表"的慢路径。

    两端必须同一套规则。GameCore 没有 .bind（末节是 .reloc），返回原值。

    只认 .bind：不按"末节且非代码段"之类的启发式剥离，那会误伤 GameCore 的 .reloc。
    """
    original = pe.OPTIONAL_HEADER.SizeOfImage
    alignment = pe.OPTIONAL_HEADER.SectionAlignment
    if not alignment:
        return original
    secs = list(pe.sections)
    if not secs:
        return original

    def is_drm(s) -> bool:
        return bytes(s.Name).rstrip(b"\0") == DRM_SECTION

    keep = len(secs) - 1
    if keep < 0 or not is_drm(secs[keep]):
        return original                      # 末节不是 DRM 段
    while keep > 0 and is_drm(secs[keep]):
        keep -= 1                            # 跳过末节连续的 DRM 段，停在最后一个非 DRM 段
    # 循环停在 keep == 0 时，"只剩首段"与"全是 DRM 段"两种情形都成立，必须看 secs[keep]
    # 是不是 DRM 段才能区分（与 C++ 的 PdataMatch::NormalizedSizeOfImage 同规则）。
    if is_drm(secs[keep]):
        return original                      # 全是 DRM 段：布局异常，不采用

    last = secs[keep]
    vs = last.Misc_VirtualSize
    end = last.VirtualAddress + max(vs, last.SizeOfRawData)
    aligned = (end + alignment - 1) // alignment * alignment
    if aligned >= original:
        return original                      # 剥离后不该变大；变大说明解析有问题
    return aligned


def cmd_json_exe(args) -> int:
    base = int(args.base, 16)
    pe = pefile.PE(args.exe)
    sizeimg = normalized_size_of_image(pe)
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
    return 0


# ============================================================================
# 三、module：JSON + 对应 PE -> 单模块 sidecar 容器
# ============================================================================

def fnv1a64(data):
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
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
        r = subprocess.run([helper, inp, outp, "--max", str(MAX_AOB)],
                           capture_output=True, text=True, timeout=1800)
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


def build_module(image_id, json_path, pe_path, bin_path,
                 aob_helper=DEFAULT_AOB_HELPER, normhash_helper=DEFAULT_NORMHASH_HELPER):
    """JSON + PE -> 单模块容器（moduleCount=1，含 PE timestamp）。"""
    print("[1/5] JSON ...")
    with open(json_path, "r", encoding="utf-8") as f:
        j = json.load(f)
    jver = int(j.get("version", 1))
    if jver not in JSON_SCHEMA_VERSIONS:
        raise ValueError("JSON version {} 未知（已知兼容 {}）".format(
            j.get("version"), JSON_SCHEMA_VERSIONS))
    if jver != 1:
        print("      note: JSON version = {}（已知兼容，按同一结构解析）".format(j.get("version")))
    sizeimg = int(j["baseSizeOfImage"], 16)
    symbols = j["symbols"]
    func_syms = [s for s in symbols if s["kind"] == "function"]
    vt_syms = [s for s in symbols if s["kind"] == "vtable"]
    print("      {} symbols ({} func + {} vt)".format(len(symbols), len(func_syms), len(vt_syms)))

    print("[2/5] DLL pdata ...")
    pe = pefile.PE(pe_path)
    timestamp = pe.FILE_HEADER.TimeDateStamp
    pdata = parse_pdata(pe)
    pdata_begins = {b: (s, u, p) for (b, s, u, p) in pdata}
    print("      {} entries".format(len(pdata)))

    print("[3/5] normHeadHash ...")
    # normHeadHash = 0 表示"无头 hash"（非 pdata 函数，或 SizeOfProlog <= 0），运行时按 != 0
    # 判定。**必须写 0，不要写 FNV 初值之类占位常量**：Fnv1a64 至少哈希 1 个字节，取不到初值，
    # 所以非 0 的值在运行时一律被当作真实 hash；填错会让这些条目进入头 hash 校验并在
    # PdataMatch.cpp 的 mapping[oi] = kUnmatched 处抹掉本已正确的锚点。
    records, indices = [], []
    for idx, s in enumerate(func_syms):
        rva = int(s["rva"], 16)
        if rva in pdata_begins:
            ln = min(pdata_begins[rva][2], 32)
            if ln > 0:
                records.append((ln, pe.get_data(rva, ln)))
                indices.append(idx)
    hashes = run_normhash(normhash_helper, records)
    nhh = [0] * len(func_syms)
    for pos, idx in enumerate(indices):
        nhh[idx] = hashes[pos]
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
    aob_blob = run_aob(aob_helper, aob_records)
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

    # 容器布局：Header(CTR_HDR) + ModuleDesc(DESC) + 各段（ALIGN 对齐，offset 均为文件绝对偏移）
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
    assert len(symbol_blob) == len(symbols) * SYMBOL_ENTRY

    blocks = bytearray()

    def append_block(blk):
        off = data_off + len(blocks)
        blocks.extend(blk)
        blocks.extend(padding8(len(blocks)))
        return off

    pd_off = append_block(bytes(pdata_blob))
    sy_off = append_block(bytes(symbol_blob))
    vt_off = append_block(bytes(slot_blob))
    heap_off = append_block(bytes(heap_bytes))
    aob_off = append_block(bytes(aob_blob))

    out = bytearray()
    out += MAGIC + struct.pack("<IIIIIII", VERSION, 1, CTR_HDR, DESC, data_off, 0, 0)
    assert len(out) == CTR_HDR
    out += struct.pack("<16I", image_id, sizeimg, timestamp,
                       pd_off, len(pdata_rows), sy_off, len(symbols),
                       vt_off, len(slot_table), heap_off, len(heap_bytes),
                       aob_off, len(aob_blob), 0, 0, 0)
    assert len(out) == data_off
    out += blocks

    with open(bin_path, "wb") as f:
        f.write(out)
    print("      bin: {} bytes (container v1, image-id={})".format(len(out), image_id))
    print("      timestamp: 0x{:08X}".format(timestamp))
    print("      layout: data={} pd={} sy={} vt={} heap={} aob={}".format(
        data_off, pd_off, sy_off, vt_off, heap_off, aob_off))
    print("done.")
    return {"imageId": image_id, "size": len(out), "timestamp": timestamp,
            "symbols": len(symbols), "pdata": len(pdata_rows)}


def cmd_module(args) -> int:
    image_id = resolve_image_id(args)
    build_module(image_id, args.json, args.dll, args.bin, args.aob, args.normhash)
    return 0


def resolve_image_id(args) -> int:
    """module 同时接受位置参数 image-id 与老的 --image-id。"""
    pos = getattr(args, "image_id_pos", None)
    opt = getattr(args, "image_id", None)
    if pos is not None and opt is not None and pos != opt:
        raise SystemExit("image-id 冲突：位置参数 %d 与 --image-id %d" % (pos, opt))
    if pos is not None:
        return pos
    if opt is not None:
        return opt
    return 5


# ============================================================================
# 四、pack：多个单模块容器 -> 一个容器
# ============================================================================

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
            "pdata": blk(pdo, pdc * PDATA_ENTRY, "pdata"),
            "pdataCount": pdc,
            "symbols": blk(syo, syc * SYMBOL_ENTRY, "symbols"),
            "symbolCount": syc,
            "slots": blk(vto, vtc * VTABLE_SLOT, "vtable slots"),
            "slotCount": vtc,
            "heap": blk(ho, hs, "heap"),
            "heapSize": hs,
            "aob": blk(ao, asz, "aob"),
            "aobSize": asz,
        })
    return mods


def parse_module_spec(spec: str):
    """'--module [imageId:]path' -> (image_id|None, path)。

    只有 ':' 前是 1..2 位数字才当 imageId 前缀，避免吃掉 Windows 盘符（E:\...）。
    """
    head, sep, tail = spec.partition(":")
    if sep and 0 < len(head) <= 2 and head.isdigit():
        return int(head), tail
    return None, spec


def pack(out_path, module_specs):
    """module_specs: [(image_id|None, path), ...]，输出模块表按输入顺序拼接。"""
    mods = []
    for want, p in module_specs:
        got = read_modules(p)
        if want is not None:
            ids = [m["imageId"] for m in got]
            if want not in ids:
                raise ValueError("--module %d:%s 前缀与容器内的 imageId %s 不一致"
                                 % (want, p, ids))
        mods.extend(got)

    seen = set()
    for m in mods:
        if m["imageId"] in seen:
            raise ValueError("imageId %d 重复（%s）" % (m["imageId"], m["path"]))
        seen.add(m["imageId"])

    data_off = align8(CTR_HDR + DESC * len(mods))
    out = bytearray()
    out += MAGIC + struct.pack("<IIIIIII", VERSION, len(mods), CTR_HDR,
                               DESC * len(mods), data_off, 0, 0)
    assert len(out) == CTR_HDR

    table = bytearray()
    blocks = bytearray()

    def add_block(data):
        off = data_off + len(blocks)
        blocks.extend(data)
        blocks.extend(padding8(len(blocks)))
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
    return len(out)


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


def cmd_pack(args) -> int:
    if args.list:
        list_pack(args.list)
        return 0
    if not args.out or not args.module:
        print("需要 --out 和至少一个 --module")
        return 1
    pack(args.out, [parse_module_spec(s) for s in args.module])
    return 0


# ============================================================================
# 五、compress：容器 -> "C6XC" + LZMA1 信封
# ============================================================================

def compress(data: bytes) -> bytes:
    # FORMAT_ALONE = .lzma（13B 头：5B props + 8B 原始大小）+ LZMA1 流
    return lzma.compress(data, format=lzma.FORMAT_ALONE, filters=LZMA_FILTERS)


def decompress(payload: bytes) -> bytes:
    return lzma.decompress(payload, format=lzma.FORMAT_ALONE)


def parse_envelope(blob: bytes):
    """-> (orig_size, payload)"""
    if blob[:4] != XP_MAGIC:
        raise RuntimeError("不是 C6XC 信封")
    tag = int.from_bytes(blob[4:8], "little")
    if tag != TAG_LZMA:
        raise RuntimeError(f"unknown algo tag {tag}")
    orig = int.from_bytes(blob[8:12], "little")
    return orig, blob[12:]


def compress_file(src, dst) -> int:
    src, dst = Path(src), Path(dst)
    if not src.is_file():
        print(f"ERROR: source not found: {src}")
        return 1

    data = src.read_bytes()
    if data[:4] != MAGIC:
        print(f"ERROR: {src.name} 不是 C6SD 容器")
        return 1
    orig = len(data)
    payload = compress(data)
    out = XP_MAGIC + TAG_LZMA.to_bytes(4, "little") + orig.to_bytes(4, "little") + payload
    dst.write_bytes(out)
    print(f"compressed: {src.name} ({orig} B) -> {dst.name} "
          f"({len(out)} B, {100.0 * len(out) / orig:.1f}%)")

    # 回读校验：走与运行时同一条解析路径
    back_orig, back_payload = parse_envelope(out)
    if back_orig != orig:
        print(f"roundtrip FAIL: envelope orig_size={back_orig} != {orig}")
        return 2
    back = decompress(back_payload)
    if back != data:
        print("roundtrip FAIL: payload mismatch")
        return 2
    print(f"roundtrip OK: SHA256 {hashlib.sha256(back).hexdigest()[:16]}")
    return 0


def cmd_compress(args) -> int:
    return compress_file(args.src, args.dst)


# ============================================================================
# 六、validate：按运行时同款解析校验 .bin / .xp
# ============================================================================

def decompress_xp(data: bytes) -> bytes:
    """C6XC + u32 algo(=1, LZMA1) + u32 original_size + payload -> 原始容器字节。"""
    if data[:4] != XP_MAGIC:
        raise RuntimeError("不是 C6XC 信封")
    tag = struct.unpack_from("<I", data, 4)[0]
    orig = struct.unpack_from("<I", data, 8)[0]
    if tag != TAG_LZMA:
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


def validate_files(paths) -> bool:
    ok = True
    for a in paths:
        path = Path(a)
        if not path.is_file():
            print(f"missing: {path}")
            ok = False
            continue
        ok = validate(path) and ok
    print("\nALL VALID" if ok else "\nVALIDATION FAILED")
    return ok


def cmd_validate(args) -> int:
    files = args.files or [RUNTIME_XP]
    return 0 if validate_files(files) else 1


# ============================================================================
# 七、aob：从 pack.bin 的 mask 指纹生成/核对 loader 的 AOB 常量
# ============================================================================

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
    ("UIManager",
     "48 8B 0D xx xx xx xx | E8 ?? ?? ?? ?? 48 89 87 30 02 00 00"),
]

AOB_IMAGE_NAMES = {1: "ExeDx11", 2: "ExeDx12"}


def load_pack(path: Path):
    d = path.read_bytes()
    if d[:4] == XP_MAGIC:          # 允许直接喂部署后的 .xp（C6XC/LZMA1 信封）
        d = decompress_xp(d)
    if d[:4] != MAGIC or struct.unpack_from("<I", d, 4)[0] != VERSION:
        raise SystemExit(f"{path} 不是 C6SD v1 容器")
    count, moff = struct.unpack_from("<I", d, 8)[0], struct.unpack_from("<I", d, 12)[0]
    mods = {struct.unpack_from("<16I", d, moff + i * DESC)[0]:
            struct.unpack_from("<16I", d, moff + i * DESC) for i in range(count)}
    out = {}
    for img in (1, 2):
        f = mods[img]
        syo, syc, ao, aasz = f[5], f[6], f[11], f[12]
        order = []
        for i in range(syc):
            kind = struct.unpack_from("<IIIB", d, syo + i * SYMBOL_ENTRY)[3]
            if kind == 0:
                order.append(struct.unpack_from("<I", d, syo + i * SYMBOL_ENTRY + 8)[0])
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
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

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
                print("  %s%-17s %-7s 0x%-8X %s" % (mark, name, AOB_IMAGE_NAMES[img], rva, note))
                continue
            extra = "" if index == 1 else "  -> index=%d" % index
            print("  %s%-17s %-7s 0x%-8X %s%s" % (mark, name, AOB_IMAGE_NAMES[img], rva, note, extra))
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
                    print("     !! %s 段 [%d,%d) 不是完整指令" % (AOB_IMAGE_NAMES[img], sS, sE))
            mask = [0 if t in ("??", "xx") else 0xFF for t in flat]
            body = bytes(0 if t in ("??", "xx") else int(t, 16) for t in flat)
            hits = exe.count(body, mask)
            if len(hits) != 1:
                print("     !! %s 命中 %d 处" % (AOB_IMAGE_NAMES[img], len(hits))); bad += 1; continue
            H = hits[0]
            disp = struct.unpack_from("<i", exe.text, H - exe.va + D)[0]
            tgt = H + E + disp
            sec = exe.section_of(tgt)
            ok = ok_seg and sec is not None
            if not ok:
                bad += 1
            print("     %s%s H=0x%-8X disp32=0x%08X -> 0x%X [%s]%s" % (
                "OK " if ok else "!! ", AOB_IMAGE_NAMES[img], H, disp & 0xFFFFFFFF, tgt, sec,
                "" if ok else "  （目标不在映像内/段非法）"))
    print()
    print("ALL OK" if bad == 0 else "有 %d 项需要人工处理" % bad)
    return 0 if bad == 0 else 1


def emit_cpp(pack, exes) -> int:
    entries = collect(pack, exes)
    lines = ["// ---- 本块由 tools/symdb.py aob --emit-cpp 生成；重建符号库/游戏更新后重新生成 ----", ""]
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


def cmd_aob(args) -> int:
    pack_data = load_pack(Path(args.pack))
    exe_dir = Path(args.exe_dir)
    exes = {1: Exe(exe_dir / "CivilizationVI.exe"),
            2: Exe(exe_dir / "CivilizationVI_DX12.exe")}
    if args.emit_cpp:
        return emit_cpp(pack_data, exes)
    return verify(pack_data, exes)


# ============================================================================
# 八、rva-map
# ============================================================================
# 已迁出本文件：见 tools/gen_rva_map.py。
# rva_to_symbol 现在把三个映像（gamecore/dx11/dx12）的符号表 zlib 压缩后编译期
# 嵌入 exe，因此生成端要做"三份 + 压缩"，与这里原先的单份未压缩实现不同源。
# 保留两份实现只会造成漂移，故只留 gen_rva_map.py 一处。


# ============================================================================
# 九、all：一条命令跑完整条产线
# ============================================================================

# (imageId, 默认输入 PE, 默认输入 JSON, 默认输出 bin)
def all_module_jobs(game_dir):
    if game_dir:
        dll = game_dll_path(game_dir)
        exe_dir = game_exe_dir(game_dir)
    else:
        dll = DEFAULT_DLL
        exe_dir = DEFAULT_EXE_DIR
    return [
        (5, dll,
         os.path.join(HERE, "GameCore.symdb.json"),
         os.path.join(HERE, "GameCore.symdb.bin")),
        (1, os.path.join(exe_dir, "CivilizationVI.exe"),
         os.path.join(HERE, "CivilizationVI.symdb.json"),
         os.path.join(HERE, "CivilizationVI.symdb.bin")),
        (2, os.path.join(exe_dir, "CivilizationVI_DX12.exe"),
         os.path.join(HERE, "CivilizationVI_DX12.symdb.json"),
         os.path.join(HERE, "CivilizationVI_DX12.symdb.bin")),
    ]


def cmd_all(args) -> int:
    jobs = all_module_jobs(args.game_dir)
    pack_out = DEFAULT_PACK
    xp_out = pack_out + ".xp"
    # 中间产物：3 个单模块容器 + pack.bin + tools 侧的 .xp；交付物只有 RUNTIME_XP
    temps = [binp for _img, _pe, _js, binp in jobs] + [pack_out, xp_out]

    try:
        # ---- 1) module x3 ----
        print("== [1/5] module x3（JSON + PE -> 单模块容器）")
        for image_id, pe_path, json_path, bin_path in jobs:
            for label, p in (("PE", pe_path), ("JSON", json_path)):
                if not os.path.isfile(p):
                    raise RuntimeError("找不到 %s: %s" % (label, p))
            print("-- module image=%d (%s)" % (image_id, IMAGE_NAMES.get(image_id, "?")))
            print("   json: %s" % json_path)
            print("   pe  : %s" % pe_path)
            stats = build_module(image_id, json_path, pe_path, bin_path)
            print("[1/5] module %d -> %s (%d B, symbols=%d)"
                  % (image_id, bin_path, stats["size"], stats["symbols"]))

        # ---- 2) pack ----
        print("== [2/5] pack（3 个单模块容器 -> pack.bin）")
        n = pack(pack_out, [(img, binp) for img, _pe, _js, binp in jobs])
        print("[2/5] pack -> %s (%d B)" % (pack_out, n))

        # ---- 3) compress ----
        print("== [3/5] compress（pack.bin -> C6XC/LZMA1 信封）")
        rc = compress_file(pack_out, xp_out)
        if rc != 0:
            raise RuntimeError("compress 失败（exit %d）" % rc)
        print("[3/5] compress -> %s (%d B)" % (xp_out, os.path.getsize(xp_out)))

        # ---- 4) 部署到运行时 ----
        print("== [4/5] deploy -> %s" % RUNTIME_XP)
        os.makedirs(os.path.dirname(RUNTIME_XP), exist_ok=True)
        shutil.copyfile(xp_out, RUNTIME_XP)
        h1 = hashlib.sha256(open(xp_out, "rb").read()).hexdigest()
        h2 = hashlib.sha256(open(RUNTIME_XP, "rb").read()).hexdigest()
        if h1 != h2:
            raise RuntimeError("部署后内容不一致：%s != %s" % (h1, h2))
        print("[4/5] deploy -> %s (%d B, sha256=%s)"
              % (RUNTIME_XP, os.path.getsize(RUNTIME_XP), h1[:16]))

        # ---- 5) validate ----
        print("== [5/5] validate（pack.bin + .xp）")
        if not validate_files([pack_out, xp_out]):
            raise RuntimeError("validate 失败")
        print("[5/5] validate OK")

        # ---- 6) 清理中间产物（校验通过之后再删）----
        print("== 清理中间产物（tools/ 下的 .bin/.xp；交付物是 %s）" % RUNTIME_XP)
        for p in temps:
            try:
                os.unlink(p)
                print("   removed %s" % p)
            except FileNotFoundError:
                pass
            except OSError as exc:
                print("   WARN 删除失败 %s: %s" % (p, exc), file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1

    print("all done.")
    return 0


# ============================================================================
# 十、命令行入口
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="symdb.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Civ6 符号库（sidecar）流水线唯一入口：json-exe / module / pack / "
                    "compress / validate / aob / rva-map / all",
        epilog="例：\n"
               "  python tools/symdb.py all\n"
               "  python tools/symdb.py module 5 --json tools/GameCore.symdb.json "
               "--dll <游戏DLL> --bin /tmp/gc.bin\n"
               "  python tools/symdb.py pack --module 5:gc.bin --module 1:dx11.bin "
               "--module 2:dx12.bin --out out.bin\n"
               "  python tools/symdb.py pack --list tools/Civ6DllLoader.symdb.pack.bin\n"
               "  python tools/symdb.py compress pack.bin pack.bin.xp\n"
               "  python tools/symdb.py validate pack.bin pack.bin.xp\n")
    sub = ap.add_subparsers(dest="cmd", metavar="<子命令>")

    # ---- json-exe ----
    p = sub.add_parser("json-exe", help="IDA 导出 + 去DRM exe -> exe 版 symdb JSON",
                       description="从 IDA 导出（.funcs.txt + .rdata .asm）+ 去 DRM exe "
                                   "生成 exe 版 symdb JSON（结构与 DLL 一致）")
    p.add_argument("--exe", required=True, help="当前(去DRM)的 EXE 文件")
    p.add_argument("--funcs", required=True, help="IDAPython 导出的 .funcs.txt")
    p.add_argument("--asm", required=True, help="IDA 导出的 .rdata 段 .asm")
    p.add_argument("--out", required=True, help="输出 JSON")
    p.add_argument("--base", default="0x140000000", help="镜像基址（默认 0x140000000）")
    p.add_argument("--demumble", default=DEFAULT_DEMUMBLE, help="demumble.exe")
    p.set_defaults(func=cmd_json_exe)

    # ---- module ----
    p = sub.add_parser("module", help="JSON + 对应 PE -> 单模块 sidecar 容器",
                       description="JSON + DLL/EXE -> sidecar 容器 bin (v1, moduleCount=1, "
                                   "with PE timestamp)")
    p.add_argument("image_id_pos", nargs="?", type=int, metavar="image-id",
                   help="模块身份：1=ExeDx11, 2=ExeDx12, 5=GameCoreXP2（默认 5）")
    p.add_argument("--image-id", type=int, default=None,
                   help="同位置参数 image-id（老命令行兼容）")
    p.add_argument("--dll", default=DEFAULT_DLL, help="对应的 PE（DLL 或 EXE）")
    p.add_argument("--json", default=DEFAULT_JSON, help="输入 symdb JSON")
    p.add_argument("--bin", default=DEFAULT_BIN, help="输出单模块容器")
    p.add_argument("--normhash", default=DEFAULT_NORMHASH_HELPER, help="normhash_helper.exe")
    p.add_argument("--aob", default=DEFAULT_AOB_HELPER, help="aob_helper.exe")
    p.set_defaults(func=cmd_module)

    # ---- pack ----
    p = sub.add_parser("pack", help="多个单模块容器 -> Civ6DllLoader.symdb.pack.bin",
                       description="把多个 sidecar 容器合并成一个容器（唯一格式 v1）；"
                                   "--module 可用 [imageId:]path 形式，前缀只做一致性校验")
    p.add_argument("--out", help="输出 pack.bin")
    p.add_argument("--module", action="append", default=[],
                   help="输入容器路径 [imageId:]path，可多次（模块身份来自容器自带的 imageId）")
    p.add_argument("--list", help="只查：打印指定容器的模块表")
    p.set_defaults(func=cmd_pack)

    # ---- compress ----
    p = sub.add_parser("compress", help="pack.bin -> C6XC/LZMA1 信封 .xp",
                       description="sidecar container -> C6XC/LZMA1 envelope（自带 SHA256 "
                                   "roundtrip 校验）")
    p.add_argument("src", nargs="?", default=DEFAULT_PACK)
    p.add_argument("dst", nargs="?", default=DEFAULT_PACK + ".xp")
    p.set_defaults(func=cmd_compress)

    # ---- validate ----
    p = sub.add_parser("validate", help="按运行时同款解析校验 .bin / .xp",
                       description="Validate a sidecar container the same way the runtime "
                                   "does (C6SD v1 + C6XC/LZMA1)")
    p.add_argument("files", nargs="*", help="一个或多个 .bin / .xp（默认部署后的 DllLoaderRuntime/*.xp）")
    p.set_defaults(func=cmd_validate)

    # ---- aob ----
    p = sub.add_parser("aob", help="从 pack.bin 指纹生成/核对 loader 的 AOB 常量",
                       description="生成/核对 exe 域 loader 目标的 AOB（供 HookInfo/HookInfoExe "
                                   "使用）；退出码 0 = 全部可用，1 = 有需要人工处理的目标")
    p.add_argument("--pack", default=RUNTIME_XP, help="输入容器：pack.bin 或 C6XC 信封 .xp（默认部署后的 .xp）")
    p.add_argument("--exe-dir", default=DEFAULT_EXE_DIR, help="两个 exe 所在目录")
    p.add_argument("--emit-cpp", action="store_true",
                   help="只输出可直接粘贴进 LoaderHooks.cpp / UiInject.cpp 的 constexpr 常量块")
    p.set_defaults(func=cmd_aob)

    # ---- rva-map：已移到 tools/gen_rva_map.py ----
    # 旧实现只处理 GameCore 且产出单文件 rva_map.json；现在 rva_to_symbol 把三个映像
    # 的符号表压缩后**编译期嵌入** exe，生成逻辑（含 zlib 打包）统一由
    # tools/gen_rva_map.py 承担，这里不再保留第二份实现。
    # 重建：python tools/gen_rva_map.py 然后 tools/rva_to_symbol/build.bat

    # ---- all ----
    p = sub.add_parser("all", help="一条命令跑完整条产线",
                       description="module x3 -> pack -> compress -> 部署到 "
                                   "DllLoaderRuntime/Civ6DllLoader.symdb.bin.xp -> validate -> "
                                   "删掉 tools/ 下的 .bin/.xp 中间产物；任何一步失败立刻退出")
    p.add_argument("--game-dir", default=None,
                   help="游戏安装根目录，覆盖默认的 %s" % DEFAULT_GAME_DIR)
    p.set_defaults(func=cmd_all)

    return ap


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        pass
    ap = build_parser()
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    if not getattr(args, "cmd", None):
        ap.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
