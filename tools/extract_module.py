#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_module.py — 把 REFACTOR_PLAN.md 里指定的函数从 Civ6DLLHookLoaderAPI.cpp
整块搬到目标文件，母体侧删除。用于 6 阶段拆分。

为什么不用手工剪切：
  * 行号会随每次编辑漂移，手工按行号剪容易错位；
  * 函数前面的注释块属于函数，手工剪切常把它留在母体；
  * 前面有独占一行的 template<> / __declspec 时，按签名行起算会丢掉它（§6）。
  本脚本按【函数体括号配对】定位（与 gen_refactor_facts.py 同一实现），
  并把紧邻上方的连续注释块一并带走。

不做的事：不改 static、不加声明、不动头文件 —— 那些是执行者的判断，
脚本只负责"把这段代码原样挪到那边并从这边删掉"。

用法：
    python tools/extract_module.py --list --phase 1          # 看待迁清单
    python tools/extract_module.py --phase 1 --dry-run        # 预演，打印将要做什么
    python tools/extract_module.py --phase 1                  # 实际执行（写文件）
"""

import argparse
import importlib.util
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SRC = os.path.join(REPO, "DllLoaderRuntime", "Civ6DLLHookLoaderAPI.cpp")

_spec = importlib.util.spec_from_file_location(
    "facts", os.path.join(HERE, "gen_refactor_facts.py"))
facts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(facts)

# 每阶段的待迁函数（按模块归属取自 gen_refactor_facts.py）
PHASE_MODULE = {
    1: "SymbolResolve",
    2: "PluginDomain",
    4: "ScriptBridge",
    5: "HookEngine",
    6: "PluginRegistry",
}

# 某些代码块不属于任何函数，但必须随指定函数一起走。
# 格式：模块 -> [(锚点函数名, 起始行, 结束行, 说明)]
# 健壮性由 _verify_extra() 保证：行内容与预期不符就报错而不是盲删。
EXTRA_BLOCKS = {
    "SymbolResolve": [
        ("ExeMatchesAnchor", 3353, 3365,
         "exe 版本锚常量（匿名 namespace）+ 其上方 7 行注释；"
         "这四个常量只被 ExeMatchesAnchor 使用"),
    ],
}


def _verify_extra(lines, start, end, expect_substrings):
    """确认 [start, end] 区间确实是我们以为的那段，防止行号漂移导致误删。"""
    seg = "\n".join(lines[start - 1:end])
    missing = [s for s in expect_substrings if s not in seg]
    if missing:
        raise SystemExit(
            f"EXTRA_BLOCKS 行号失配：L{start}-{end} 里找不到 {missing}。\n"
            f"（文件已改动？请重新核对区间后再跑）\n实际内容前 200 字符：\n{seg[:200]}")


# 已就地改造成门面实现、不再随模块搬走的函数
ALREADY_REFACTORED = {
    "ResolvePluginOwnerForAddress",   # -> PluginRegistry::ResolveOwnerByModule（阶段 2）
}


def functions_of(module):
    src = open(SRC, encoding="utf-8", errors="replace").read()
    clean = facts.strip_comments_and_strings(src)
    funcs = facts.find_functions(clean)
    out = []
    for name, s, e, cnt, q in funcs:
        if facts.module_of(name) == module and name not in ALREADY_REFACTORED:
            out.append((name, s, e, cnt))
    return out


def comment_start(lines, func_start):
    """向上找紧邻函数定义的连续注释块首行（1-based）。

    只在全是 // 行时上溯；遇到空行停下（空行是天然分隔，跨过去会把
    上一个函数的注释也带走 —— 实测每个待迁函数上方都是紧贴的 // 块）。
    """
    i = func_start - 1          # 0-based，指向函数定义行
    j = i - 1
    while j >= 0 and lines[j].lstrip().startswith("//"):
        j -= 1
    return j + 2                # 转回 1-based


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", type=int, required=True, choices=sorted(PHASE_MODULE))
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    module = PHASE_MODULE[args.phase]
    items = functions_of(module)
    src = open(SRC, encoding="utf-8", errors="replace").read()
    lines = src.split("\n")

    print(f"阶段 {args.phase}：{module} —— {len(items)} 个函数")
    print()
    total = 0
    blocks = []
    for name, s, e, cnt in sorted(items, key=lambda t: t[1]):
        cs = comment_start(lines, s)
        n = e - cs + 1
        total += n
        blocks.append((name, cs, e, n))
        extra = f"（含注释 {s - cs} 行）" if cs < s else ""
        print(f"  L{cs:<6}-{e:<6} {n:>4} 行  {name}{extra}")
    print()
    print(f"合计 {total} 行（函数体 {sum(c for _, _, _, c in items)} + 注释"
          f" {total - sum(c for _, _, _, c in items)}）")

    # ---------- 附加块（"不属于任何函数但必须随行"的代码）----------
    # 放在 --list / --dry-run 之前处理：这样预演也会校验行号，
    # 不至于"预演通过、实跑报错"。
    extras = EXTRA_BLOCKS.get(module, [])
    for anchor_fn, xs, xe, why in extras:
        expect = ["kAnchorDx11SizeOfImage", "kAnchorDx12TimeDate", "namespace {"]
        _verify_extra(lines, xs, xe, expect)
        fn = next((b for b in blocks if b[0] == anchor_fn), None)
        if not fn:
            raise SystemExit(f"EXTRA_BLOCKS 指向的 {anchor_fn} 不在本阶段清单里")
        if fn[1] != xe + 2:
            raise SystemExit(
                f"EXTRA_BLOCKS L{xe} 与 {anchor_fn}（L{fn[1]}）之间不是恰好 1 空行"
                f"（实为 {fn[1] - xe - 1} 行），拒绝自动合并")
        blocks.append((f"[extra] anchor 常量（随 {anchor_fn}）", xs, xe, xe - xs + 1))
        print()
        print(f"  + 附加块 L{xs}-{xe}（{xe - xs + 1} 行）：{why}")

    total = sum(b[3] for b in blocks)
    print()
    print(f"（含附加块）合计 {total} 行")

    # 重叠检查（必须先按起始行排序：附加块是 append 进来的，
    # 位置在 ExeMatchesAnchor 之后，不排序会误判成"重叠"）
    blocks.sort(key=lambda b: b[1])
    for i in range(1, len(blocks)):
        if blocks[i][1] <= blocks[i - 1][2]:
            raise SystemExit(
                f"块区间重叠：{blocks[i-1][0]}(L{blocks[i-1][1]}-{blocks[i-1][2]}) "
                f"与 {blocks[i][0]}(L{blocks[i][1]}-{blocks[i][2]})")

    if args.list:
        return 0

    if args.dry_run:
        print()
        print("（dry-run：未写文件）")
        return 0

    # ---------- 实际执行 ----------

    # 1. 逐个块从母体剪出（自下而上，避免行号漂移）
    grabbed = []          # [(name, [lines])]
    for name, cs, e, n in sorted(blocks, key=lambda t: -t[1]):
        chunk = lines[cs - 1:e]
        grabbed.append((name, chunk))
        del lines[cs - 1:e]
    grabbed.reverse()     # 恢复自上而下的顺序

    # 2. 母体侧不留空行堆积：把连续 3+ 空行压成 2
    text = "\n".join(lines)
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    if not args.dry_run:
        with open(SRC, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    # 3. 汇总抓到的东西（供调用方拼装目标文件）
    out_path = os.path.join(HERE, "extracted", f"phase{args.phase}_{module}.txt")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        for name, chunk in grabbed:
            fh.write(f"// ==== {name} ====\n")
            fh.write("\n".join(chunk) + "\n\n")

    print()
    print(f"✓ 已从母体剪出 {len(grabbed)} 个块，"
          f"母体现在 {len(text.splitlines())} 行")
    print(f"✓ 剪出的代码另存：{out_path}")
    print()
    print("接下来（需人工判断，脚本不做）：")
    print("  * 目标 .cpp/.h 的 include 与外部声明")
    print("  * 按 §4.4 决定哪些 static 要去掉")
    print("  * vcxproj 与 .vcxproj.filters 登记新文件")
    return 0


if __name__ == "__main__":
    sys.exit(main())
