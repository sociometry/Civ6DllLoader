#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simulate_split_verify.py — 机械验证 docs/REFACTOR_PLAN.md §4.3 的阶段顺序能否
"每阶段都编译通过"。只做计算，不引用计划里的计数。

三个镜头：
  1. 函数镜头（--phases）：每条跨 TU 引用按方向分为
       OUT-shim  抽出模块 → 仍留在母体的代码（母体目标多半是 static，必须去 static + 声明）
       IN-decl   母体 → 抽出模块（写模块自己的 .h 即可）
  2. 去 static 镜头（--destatic）：列出"模块固有但当前 static、且在某个阶段真的
     会被跨 TU 引用"的函数全集，并给出首次需要它的阶段与调用点。
  3. 状态镜头（--state）：文件级对象/类型被哪些模块的函数体引用；>=2 个模块即
     必须进内部头或走门面，并给出首次需要它的阶段。

用法：
    python tools/simulate_split_verify.py --phases
    python tools/simulate_split_verify.py --destatic
    python tools/simulate_split_verify.py --state
    python tools/simulate_split_verify.py --matrix
    python tools/simulate_split_verify.py --alt --phases
"""

import argparse
import importlib.util
import os
import re
import sys
from collections import defaultdict, OrderedDict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TARGET = os.path.join(REPO, "DllLoaderRuntime", "Civ6DLLHookLoaderAPI.cpp")

_spec = importlib.util.spec_from_file_location(
    "facts", os.path.join(HERE, "gen_refactor_facts.py"))
facts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(facts)

PARENT = "(母体)"

# 阶段 3 建 TeardownWindow.h，把 teardown 窗口的两个 atomic 与两个 setter 变成
# 头文件里的 inline 定义。inline 函数在每个 TU 内联展开，【不产生跨 TU 符号】，
# 因此 SetGameCoreTeardownWindow 从阶段 3 起不再是垫片。
#
# 【这里曾经算错】：只用"函数调用是否跨模块"判定的实现会把
# SetGameCoreTeardownWindow 记为阶段 5 的 1 个垫片（因为
# RemoveGameCoreDomainSiteRecords 在 L4004 调它、而 HookEngine 阶段 5 才抽出）。
# 正确口径是排除它 —— 它在阶段 3 已随窗口搬进共享头，与"某个模块的 .h 声明了它"
# 性质相同，都是【计划内已有的东西】，不是要临时提供的垫片。
# 与 simulate_split.py 的 SHARED_AT_PHASE3 保持同一口径。
ABSORBED_AT_PHASE3 = {
    "SetGameCoreTeardownWindow", "ClearGameCoreTeardownWindow",
    "g_gameCoreTeardownAddress", "g_gameCoreTeardownSizeOfImage",
}

# §4.3 的阶段表。阶段 3 含 TeardownWindow.h（计划如此安排，本脚本照抄以做对照）。
PHASES = [
    ("SymbolResolve",), ("PluginDomain",), ("Civ6MessageBus",), ("ScriptBridge",),
    ("HookEngine",), ("PluginRegistry", "HookLoaderApi"),
]
PHASES_ALT = [
    ("SymbolResolve",), ("PluginDomain",), ("Civ6MessageBus",), ("HookEngine",),
    ("ScriptBridge",), ("PluginRegistry", "HookLoaderApi"),
]

# "函数体之外"的引用逐行分类，避免把随模块搬走的对象误判成母体引用
TOPLEVEL_CLASSES = [
    ((206, 208), "fwd_decl", "前置声明，非引用"),
    ((2292, 2292), "fwd_decl", "QuarantinePluginByOwner 前置声明"),
    ((2473, 2508), "relocate", "Detour 表随模板进 ScriptBridge"),
    ((2654, 2675), "relocate", "HKS_GUARD_* 宏随 Lua*Impl 迁移"),
    ((3031, 3061), "relocate", "CivCrc32* + static_assert 同 TU 迁移"),
    ((3300, 3302), "relocate", "ABI static_assert 随 g_hookApi 进门面"),
    ((3201, 3298), "parent_use", "g_hookApi 初始化表：真·母体引用"),
]


class Model:
    def __init__(self):
        src = open(TARGET, encoding="utf-8", errors="replace").read()
        self.clean = facts.strip_comments_and_strings(src)
        self.lines = self.clean.split("\n")
        self.funcs = facts.find_functions(self.clean)
        self.by_name = {f[0]: f for f in self.funcs}
        self.deferred = set(facts.DEFERRED)
        self.owner_line = {}
        for name, s, e, c, q in self.funcs:
            for k in range(s, e + 1):
                self.owner_line[k] = name
        self.objs = facts.find_file_scope_objects(self.lines)
        self.types = facts.find_type_scopes(self.clean)
        # 哪些行属于"函数体内"
        self.in_func = set()
        for name, s, e, c, q in self.funcs:
            self.in_func.update(range(s, e + 1))

    def mod_of(self, name):
        if name in self.deferred:
            return PARENT
        return facts.module_of(name) or PARENT

    def tu_of(self, name, done):
        m = self.mod_of(name)
        return PARENT if m == PARENT else (m if m in done else PARENT)

    def is_static(self, name):
        f = self.by_name.get(name)
        return bool(f and re.match(r"^\s*static\b", self.lines[f[1] - 1]))

    def final_mod_of(self, name):
        """终态归属：缓迁 *Impl 最终进 SymbolResolve。"""
        if name in self.deferred:
            return "SymbolResolve"
        return facts.module_of(name) or PARENT

    def build_refs(self):
        names = sorted(self.by_name, key=len, reverse=True)
        alt = "|".join(re.escape(n) for n in names)
        pat = re.compile(r"(?<![\w:.>])(?:LoaderCore::)?(&?)(" + alt + r")\b")
        refs = []
        for i, ln in enumerate(self.lines, 1):
            for m in pat.finditer(ln):
                tgt = m.group(2)
                if self.by_name[tgt][1] == i:
                    continue
                caller = self.owner_line.get(i)
                if caller is None:
                    kind = classify_toplevel(i)
                    if kind in ("fwd_decl", "relocate"):
                        continue
                    caller = "(顶层)"
                refs.append((tgt, i, "addr" if m.group(1) == "&" else "call", caller))
        return refs


def classify_toplevel(line):
    for (a, b), kind, why in TOPLEVEL_CLASSES:
        if a <= line <= b:
            return kind
    return "parent_use"


def refs_at(M, refs, done):
    out = []
    for tgt, line, kind, caller in refs:
        ctu = PARENT if caller == "(顶层)" else M.tu_of(caller, done)
        ttu = M.tu_of(tgt, done)
        if ctu != ttu:
            out.append((ctu, caller, tgt, ttu, line, kind))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alt", action="store_true")
    for f in ("phases", "destatic", "state", "matrix"):
        ap.add_argument("--" + f, action="store_true")
    args = ap.parse_args()
    if not any(getattr(args, f) for f in ("phases", "destatic", "state", "matrix")):
        args.phases = args.destatic = args.state = True

    M = Model()
    refs = M.build_refs()

    # ---------------- 镜头 1：逐阶段跨 TU 引用 ----------------
    if args.phases:
        order = PHASES_ALT if args.alt else PHASES
        print(f"镜头 1  阶段顺序：{'备选(HookEngine 先)' if args.alt else '§4.3'}")
        print(f"        顶层函数 {len(M.funcs)}；文件级对象 {len(M.objs)}；类型 {len(M.types)}")
        done, prev = set(), set()
        for i, group in enumerate(order, 1):
            done2 = done | set(group)
            cur = refs_at(M, refs, done2)
            added = [e for e in cur if (e[1], e[2]) not in prev]
            outs, ins = OrderedDict(), OrderedDict()
            for ctu, caller, tgt, ttu, line, kind in added:
                # 阶段 3 之后，TeardownWindow.h 里的符号由共享头提供，不算垫片
                if i >= 3 and tgt in ABSORBED_AT_PHASE3:
                    continue
                (outs if (ctu != PARENT and ttu == PARENT) else ins).setdefault(
                    tgt, []).append((caller, line, kind))
            print(f"\n  ── 阶段 {i}：抽 {' + '.join(group)} ──")
            print(f"     OUT-shim {len(outs)} 个目标 / {sum(len(v) for v in outs.values())} 处")
            for tgt, uses in sorted(outs.items()):
                st = "  [原 static → 必须去 static]" if M.is_static(tgt) else ""
                print(f"        {tgt}{st}")
                for c, l, k in sorted(uses, key=lambda t: t[1]):
                    print(f"           L{l:<5} {c}  ({k})")
            print(f"     IN-decl  {len(ins)} 个目标 / {sum(len(v) for v in ins.values())} 处"
                  f"  ← 写模块 .h 即可")
            for tgt, uses in sorted(ins.items()):
                st = "  [原 static]" if M.is_static(tgt) else ""
                print(f"        {tgt:<40} {len(uses)} 处{st}  例 "
                      f"{uses[0][0]}@L{uses[0][1]}")
            prev = {(c, t) for _, c, t, _, _, _ in cur}
            done = done2

    # ---------------- 镜头 2：去 static 全集 ----------------
    if args.destatic:
        print("\n镜头 2  模块固有、当前 static、且终态会跨 TU 的函数（全部必须去 static）")
        seen = OrderedDict()
        allmods = {m for m in (M.mod_of(n) for n, s, e, c, q in M.funcs) if m != PARENT}
        # 终态：所有模块都抽走，缓迁 *Impl 也归入 SymbolResolve
        allmods2 = set(allmods) | {"SymbolResolve"}
        for tgt, line, kind, caller in refs:
            ctu = PARENT if caller == "(顶层)" else M.final_mod_of(caller)
            ttu = M.final_mod_of(tgt)
            if ctu == ttu:
                continue
            if not M.is_static(tgt) or tgt in seen:
                continue
            seen[tgt] = (M.final_mod_of(tgt), caller, line, kind, ctu)
        for tgt, (mod, caller, line, kind, ctu) in sorted(seen.items(), key=lambda kv: (kv[1][0], kv[0])):
            print(f"    {mod:<16} {tgt:<40} 例 {caller}({ctu})@L{line} ({kind})")
        print(f"    合计 {len(seen)} 个")
        never = [n for n, s, e, c, q in M.funcs
                 if M.is_static(n) and M.final_mod_of(n) != PARENT and n not in seen]
        print(f"    终态也从不跨 TU（可保持 static）：{len(never)} 个")
        for n in sorted(never, key=lambda n: (M.final_mod_of(n), n)):
            print(f"        {M.final_mod_of(n):<16} {n}")

    # ---------------- 镜头 3：状态 / 类型 ----------------
    if args.state:
        print("\n镜头 3  文件级对象与类型的引用者模块分布")
        print("        （>=2 个模块的函数体引用 ⇒ 必须进内部头或走门面）")
        targets = OrderedDict()
        for o, ln in sorted(M.objs.items(), key=lambda kv: kv[1]):
            targets[o] = ("对象", ln)
        # 函数体之外的裸声明（前置声明）不算引用
        pat_cache = {}
        rows = []
        for tname, (kind, dline) in targets.items():
            pat = pat_cache.setdefault(tname, re.compile(r"(?<![\w:.>])" + re.escape(tname) + r"\b"))
            users = defaultdict(list)
            for i, ln in enumerate(M.lines, 1):
                if i == dline or not pat.search(ln):
                    continue
                o = M.owner_line.get(i)
                if o is None:
                    if i in M.in_func:
                        continue
                    users["(顶层)"].append(i)
                else:
                    users[M.mod_of(o)].append(i)
            live = {k: v for k, v in users.items() if v}
            if len(live) < 2:
                continue
            rows.append((dline, tname, kind, live))
        for dline, tname, kind, live in rows:
            legs = ", ".join(f"{k}:{len(v)}({v[0]})" for k, v in sorted(
                live.items(), key=lambda kv: -len(kv[1])))
            print(f"        L{dline:<5} {tname:<32} {legs}")

        print("\n        ── 类型定义（struct/class/union）──")
        for tname, s, e in sorted(M.types, key=lambda t: t[1]):
            pat = re.compile(r"(?<![\w:.>])" + re.escape(tname) + r"\b")
            users = defaultdict(list)
            for i, ln in enumerate(M.lines, 1):
                if s <= i <= e or not pat.search(ln):
                    continue
                o = M.owner_line.get(i)
                if o is None:
                    if i in M.in_func:
                        continue
                    users["(顶层/声明行)"].append(i)
                else:
                    users[M.mod_of(o)].append(i)
            live = {k: v for k, v in users.items() if v}
            legs = ", ".join(f"{k}:{len(v)}" for k, v in sorted(live.items(), key=lambda kv: -len(kv[1])))
            print(f"        L{s:<5}-{e:<5} {tname:<28} {legs}")

    # ---------------- 镜头 4：模块边矩阵 ----------------
    if args.matrix:
        mat = defaultdict(set)
        for tgt, line, kind, caller in refs:
            a = "(顶层文件级)" if caller == "(顶层)" else M.mod_of(caller)
            b = M.mod_of(tgt)
            if a != b:
                mat[(a, b)].add((caller, tgt, line))
        print(f"\n镜头 4  模块间引用边 {len(mat)} 对")
        for (a, b), s in sorted(mat.items()):
            ls = sorted(x[2] for x in s)
            print(f"        {a:<14} → {b:<14} 边数{len(s):>4}  行号 {ls[:8]}"
                  f"{' ...' if len(ls) > 8 else ''}")
            print(f"            目标函数 {sorted({x[1] for x in s})}")


if __name__ == "__main__":
    main()
