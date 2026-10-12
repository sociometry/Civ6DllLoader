#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
log_fingerprint.py — 拆分验证用的日志指纹比对（REFACTOR_PLAN.md §8）。

拆分只搬代码、不改行为，所以拆分后的日志应当与基线逐条等价。
本脚本把两份日志归一化后比对，供每阶段收尾时执行。

归一化（抹掉每次运行必然不同的东西）：
  * 时间戳 [HH:MM:SS]  -> [TIME]
  * pid=NNNN           -> pid=<PID>
  * 16 位十六进制地址   -> <ADDR>   （MSVC %p 在 x64 下固定 16 位、无 0x 前缀）
  不做归一化：0x 前缀的显式值（sizeOfImage / timestamp / fingerprint / Protect）
  —— 它们是确定值，变了就说明跑的不是同一映像，必须报出来。

两种比对：
  1. 有序差异：逐行对齐。能发现顺序变化，但多线程交错会误报。
  2. 多重集差异：排序后比对。容忍交错，能发现任何增删改。
  两者都跑，任一有差异就非零退出。
  另附锚点顺序检查（§8 的 8 个锚点必须按基线顺序出现）。

用法：
    python tools/log_fingerprint.py --save-baseline <log>      # 归档基线
    python tools/log_fingerprint.py --compare <newlog>         # 与基线比对
    python tools/log_fingerprint.py --compare <newlog> --brief # 只报结论
"""

import argparse
import os
import re
import sys
from collections import Counter, OrderedDict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BASELINE = os.path.join(HERE, "baseline", "loader_baseline.norm.log")

# §8 列出的 8 个锚点（顺序即基线顺序）
ANCHORS = [
    "只读保护已验证",
    "installed hub stub",
    "RegisterGlobalCapture: installed",
    "RegisterScriptData: running",
    "DisableGameCoreDomainSites: candidates",
    "CleanupAllCaptureSites: unplugged",
    "RemoveGameCoreDomainSiteRecords: reset",
    "Plugin module freed after engine",
]

TS_RE = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]\s?")
PID_RE = re.compile(r"\bpid=\d+")
# %p：x64 下零填充的 16 位十六进制，且不带 0x 前缀。
# 用 (?<![\w]) 防止截断更长的十六进制串（如 fingerprint=0x8DDC... 已被 0x 规则排除）。
ADDR_RE = re.compile(r"(?<![\w])(?:0x)?(?=[0-9A-F]{16}(?![\w]))[0-9A-F]{16}")

# 【ASLR 基址】：DLL 每次加载的基址由系统决定，必然不同。
# 实测漏掉这条会让每次比对都误报 6 处（GameCore attached / ApiSmokeTest 的三行 ×2 轮）。
#
# 只抹【明确的基址字段】（base=0x...），不抹所有 0x 值 ——
# 0x 前缀的确定性值（sizeOfImage / timestamp / fingerprint / Protect）必须保留，
# 它们变了说明跑的不是同一映像，那是真差异。
BASE_RE = re.compile(r"\bbase=0x[0-9A-Fa-f]+")
# 插件/模块句柄同理（Plugin module freed 的 %p 已被 ADDR_RE 处理，
# 但显式 0x 形式出现在其它行时也要抹）。
MODULE_RE = re.compile(r"\bmodule=0x[0-9A-Fa-f]+")


def normalize_line(line: str) -> str:
    s = line.rstrip("\r\n")
    s = TS_RE.sub("[TIME] ", s)
    s = PID_RE.sub("pid=<PID>", s)
    s = BASE_RE.sub("base=<BASE>", s)
    s = MODULE_RE.sub("module=<MODULE>", s)
    # 只把【不带 0x 前缀】的 16 位十六进制当地址；
    # 带 0x 的是显式值（fingerprint 等），保留原样。
    s = ADDR_RE.sub(lambda m: m.group(0) if m.group(0).startswith("0x") else "<ADDR>", s)
    return s.rstrip()


def normalize(path: str):
    with open(path, encoding="utf-8", errors="replace") as fh:
        raw = fh.read().splitlines()
    return [normalize_line(x) for x in raw if x.strip()]


def load_baseline():
    if not os.path.exists(BASELINE):
        sys.stderr.write(f"缺少基线：{BASELINE}\n先跑 --save-baseline\n")
        sys.exit(2)
    with open(BASELINE, encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def cmd_save(log_path):
    lines = normalize(log_path)
    os.makedirs(os.path.dirname(BASELINE), exist_ok=True)
    with open(BASELINE, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"基线已归档：{BASELINE}")
    print(f"  原始 {len(lines)} 行（归一化后）")
    # 自检：8 个锚点都在
    joined = "\n".join(lines)
    missing = [a for a in ANCHORS if a not in joined]
    if missing:
        print(f"  ⚠ 基线缺少锚点：{missing}")
    else:
        print(f"  ✓ 8 个锚点齐全")
    # 统计归一化后仍存在的可变内容（16 位十六进制残留 = 归一化漏洞）
    LEFT = re.compile(r"(?<![\w])[0-9A-F]{16}(?![\w])")
    left = [x for x in lines if LEFT.search(x)]
    if left:
        print(f"  ⚠ 仍有 {len(left)} 行含未归一化的 16 位十六进制，例：")
        for x in left[:3]:
            print(f"      {x[:110]}")
    return 0


def diff_ordered(base, new):
    """逐行对齐，返回差异描述列表。"""
    out = []
    for i in range(max(len(base), len(new))):
        b = base[i] if i < len(base) else "<缺行>"
        n = new[i] if i < len(new) else "<缺行>"
        if b != n:
            out.append((i + 1, b, n))
    return out


def diff_multiset(base, new):
    """排序后比对，返回 (仅在基线, 仅在新日志, 计数差异)。"""
    cb, cn = Counter(base), Counter(new)
    only_base = sorted((cb - cn).elements())
    only_new = sorted((cn - cb).elements())
    return only_base, only_new


def check_anchor_order(lines):
    """锚点在日志里必须按基线顺序首次出现。返回 (ok, 详情)。"""
    pos, cur = [], 0
    for a in ANCHORS:
        found = None
        for i in range(cur, len(lines)):
            if a in lines[i]:
                found = i
                break
        if found is None:
            return False, f"锚点缺失或乱序：找不到「{a}」"
        pos.append((a, found))
        cur = found + 1
    return True, pos


def cmd_compare(new_path, brief=False, max_show=12):
    base = load_baseline()
    new = normalize(new_path)
    print(f"基线 {len(base)} 行  ←→  本次 {len(new)} 行")
    print()

    rc = 0

    # 1. 有序差异
    od = diff_ordered(base, new)
    if od:
        rc = 1
        print(f"✗ 有序差异 {len(od)} 处")
        if not brief:
            for ln, b, n in od[:max_show]:
                print(f"    L{ln}")
                print(f"      基线: {b[:120]}")
                print(f"      本次: {n[:120]}")
            if len(od) > max_show:
                print(f"    … 其余 {len(od) - max_show} 处")
    else:
        print("✓ 有序比对：逐行完全一致")

    # 2. 多重集差异（容忍线程交错）
    only_base, only_new = diff_multiset(base, new)
    if only_base or only_new:
        rc = 1
        print(f"✗ 内容差异：基线独有 {len(only_base)} 行，本次独有 {len(only_new)} 行")
        if not brief:
            for x in only_base[:max_show]:
                print(f"      - {x[:120]}")
            for x in only_new[:max_show]:
                print(f"      + {x[:120]}")
    else:
        print("✓ 多重集比对：内容集合完全一致（无增删改）")

    # 3. 锚点顺序
    ok, detail = check_anchor_order(new)
    if ok:
        print("✓ 锚点顺序：8 个锚点按基线顺序出现")
        if not brief:
            for a, i in detail:
                print(f"      L{i + 1:<5} {a}")
    else:
        rc = 1
        print(f"✗ 锚点顺序：{detail}")

    print()
    print("结论：" + ("通过" if rc == 0 else "不通过 —— 拆分引入了行为差异，需定位"))
    return rc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--save-baseline", metavar="LOG")
    ap.add_argument("--compare", metavar="LOG")
    ap.add_argument("--brief", action="store_true")
    args = ap.parse_args()

    if args.save_baseline:
        sys.exit(cmd_save(args.save_baseline))
    if args.compare:
        sys.exit(cmd_compare(args.compare, args.brief))
    ap.print_help()
    sys.exit(2)


if __name__ == "__main__":
    main()
