#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simulate_split_destatic_phases.py — 算出"每个阶段新增必须去掉 static 的函数"。

与 §4.4 的争点：计划把 IsImageOpenToCaller / ResolveByRvaCore / ResolveByVTableCore /
ResolveSectionRva 归为"只在阶段 6 才需要"，理由是"调用方只有缓迁的 *Impl，
阶段 1–5 期间同处母体，不构成跨 TU"。本脚本检验这句话。

用法：python tools/simulate_split_destatic_phases.py
"""

import importlib.util
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(os.path.dirname(HERE), "DllLoaderRuntime", "Civ6DLLHookLoaderAPI.cpp")
_spec = importlib.util.spec_from_file_location("facts", os.path.join(HERE, "gen_refactor_facts.py"))
facts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(facts)

PHASES = [("SymbolResolve",), ("PluginDomain",), ("Civ6MessageBus",), ("ScriptBridge",),
          ("HookEngine",), ("PluginRegistry", "HookLoaderApi")]

src = open(TARGET, encoding="utf-8", errors="replace").read()
clean = facts.strip_comments_and_strings(src)
lines = clean.split("\n")
funcs = facts.find_functions(clean)
by = {f[0]: f for f in funcs}
defer = set(facts.DEFERRED)


def home(n):
    """缓迁 *Impl 在阶段 1–5 留在母体；其余按模块归属。"""
    if n in defer:
        return "(母体)"
    return facts.module_of(n) or "(母体)"


def is_static(n):
    return bool(re.match(r"^\s*static\b", lines[by[n][1] - 1]))


names = sorted(by, key=len, reverse=True)
pat = re.compile(r"(?<![\w:.>])(?:LoaderCore::)?&?(" + "|".join(map(re.escape, names)) + r")\b")

# 收集所有函数体内的引用（caller 函数 → callee 函数）
refs = []
for n, s, e, c, q in funcs:
    for i in range(s, e + 1):
        for m in pat.finditer(lines[i - 1]):
            if m.group(1) != n:
                refs.append((n, m.group(1), i))
# g_hookApi 初始化表（母体顶层）
for i in range(3201, 3299):
    for m in pat.finditer(lines[i - 1]):
        refs.append(("(顶层)", m.group(1), i))

done = set()
gfirst = {}
for ph, grp in enumerate(PHASES, 1):
    done2 = done | set(grp)

    def tu(n):
        h = home(n)
        return h if h in done2 else "(母体)"

    new = {}
    for caller, callee, i in refs:
        if caller == callee:
            continue
        ctu = "(母体)" if caller == "(顶层)" else tu(caller)
        if ctu != tu(callee) and is_static(callee):
            new.setdefault(callee, []).append((caller, i))
    for t in new:
        gfirst.setdefault(t, ph)
    print(f"\n阶段 {ph}：抽 {' + '.join(grp)}")
    print(f"  本阶段必须去 static 的函数：{len(new)} 个")
    for t, v in sorted(new.items()):
        print(f"     {t:<42} 归属={home(t):<16} 调用点 {[(c, l) for c, l in v][:3]}")
    done = done2

print("\n" + "=" * 90)
print("首次需要去 static 的阶段（全表）")
for t, ph in sorted(gfirst.items(), key=lambda kv: (kv[1], kv[0])):
    print(f"  阶段{ph}  {t}")
print(f"  合计 {len(gfirst)} 个")
