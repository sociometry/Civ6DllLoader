#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simulate_split.py — 机械模拟 REFACTOR_PLAN.md §4.3 的 6 阶段拆分，
逐阶段算出"哪些跨 TU 引用需要垫片"，据此判定每一步能否编译。

存在理由：§4.3 的"垫片数量比较"是计划里唯一没被机器验证的部分，
作者已经把它比反过一次（先说 HookEngine 先抽只需 2 个垫片，实际是
ScriptBridge 先抽只需 1 个）。靠人肉数调用点会重复出错，所以直接算。

判定口径：
  * 某阶段把函数集 M 移出母体后，凡"调用方与目标不在同一 TU"的引用
    都需要一条声明（原本 static 的还须去掉 static）。
  * 按【目标函数】去重 —— 同一个函数被调 3 次只需 1 条声明。
  * 取地址（&Foo）与调用（Foo(...)）同等对待：都是跨 TU 引用。
  * 母体本身也是一个 TU（"剩下没搬走的部分"）。

用法：
    python tools/simulate_split.py            # 按 §4.3 的顺序模拟
    python tools/simulate_split.py --alt      # 模拟"先 HookEngine"的备选顺序
"""

import argparse
import os
import re
import sys
from collections import defaultdict, OrderedDict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TARGET = os.path.join(REPO, "DllLoaderRuntime", "Civ6DLLHookLoaderAPI.cpp")

# 复用事实生成器的词法与函数提取，避免两套实现漂移
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "facts", os.path.join(HERE, "gen_refactor_facts.py"))
facts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(facts)

PARENT = "(母体)"

# 阶段 3 建 TeardownWindow.h（§5.3），把 teardown 窗口的 3 个符号搬进共享头。
# 搬进去之后，任何模块用它们都只需 include，不再算垫片 —— 这直接影响
# HookEngine 阶段的垫片计数（SetGameCoreTeardownWindow 原本是外向需求）。
SHARED_AT_PHASE3 = {"SetGameCoreTeardownWindow", "ClearGameCoreTeardownWindow",
                    "g_gameCoreTeardownAddress", "g_gameCoreTeardownSizeOfImage"}

# §4.3 的阶段顺序。注意阶段 6 同时抽 PluginRegistry 与 HookLoaderApi ——
# 它们是【同一个阶段】，必须一起建模。若拆成两阶段模拟，会凭空多出一条
# "CallOnLoadSafe(PluginRegistry) → RuntimeHookApi(HookLoaderApi)" 的垫片，
# 而实际执行时两者同阶段搬走，由 HookLoaderApi.h 直接解决。
# 每项：(阶段内要抽的模块列表, 该阶段新增行数)
PHASES = [
    (["SymbolResolve"], 304),
    (["PluginDomain"], 120),
    (["Civ6MessageBus"], 14),
    (["ScriptBridge"], 1213),
    (["HookEngine"], 624),
    (["PluginRegistry", "HookLoaderApi"], 655 + 36),
]

# 备选：HookEngine 先于 ScriptBridge
PHASES_ALT = [
    (["SymbolResolve"], 304),
    (["PluginDomain"], 120),
    (["Civ6MessageBus"], 14),
    (["HookEngine"], 624),
    (["ScriptBridge"], 1213),
    (["PluginRegistry", "HookLoaderApi"], 655 + 36),
]


def module_of_func(name, deferred):
    """函数归属。缓迁函数视为仍在母体（阶段 6 才归位）。"""
    if name in deferred:
        return PARENT
    return facts.module_of(name) or PARENT


def build():
    src = open(TARGET, encoding="utf-8", errors="replace").read()
    clean = facts.strip_comments_and_strings(src)
    lines = clean.split("\n")
    funcs = facts.find_functions(clean)
    return clean, lines, funcs


def is_static(lines, start):
    return bool(re.match(r"^\s*static\b", lines[start - 1]))


def cross_refs(lines, funcs, moved, deferred):
    """返回 {(caller, callee)}：caller 与 callee 在不同 TU 的引用。

    moved: 已移出母体的模块名集合
    """
    def tu_of(name):
        mod = module_of_func(name, deferred)
        if mod == PARENT:
            return PARENT
        return mod if mod in moved else PARENT

    by_name = {f[0]: f for f in funcs}
    names = sorted(by_name, key=len, reverse=True)

    in_func = set()
    for name, s, e, c, q in funcs:
        for k in range(s, e + 1):
            in_func.add(k)

    edges = set()
    for name, s, e, c, q in funcs:
        body = "\n".join(lines[s - 1:e])
        for tgt in names:
            if tgt == name:
                continue
            # 允许命名空间限定（`LoaderCore::RuntimeHookApi()`）—— 只用 (?<![\w])
            # 排除"更长标识符的后缀"（如 Foo vs MyFoo），不能用 (?<![\w:])，
            # 那会把合法限定调用整个漏掉（CallOnLoadSafe → LoaderCore::RuntimeHookApi）。
            if re.search(r"(?<![\w])&?(?:[\w:]*::)?" + re.escape(tgt)
                         + r"\s*[\(,;\)]", body):
                if tu_of(name) != tu_of(tgt):
                    edges.add((name, tgt))
    for i, ln in enumerate(lines, 1):
        if i in in_func:
            continue
        for tgt in names:
            if re.search(r"(?<![\w])&" + re.escape(tgt) + r"\b", ln):
                if tu_of(tgt) != PARENT:
                    edges.add((PARENT + f":L{i}", tgt))
    return edges


# 变量的归属：按声明位置推断所属模块（与 gen_refactor_facts 的变量表配合）
def var_module(var, decl_line, funcs, deferred, clean_lines):
    """变量所属模块 = 它被哪些模块的函数引用（多数派）。

    变量没有"定义在哪个模块"的天然答案 —— 迁移时它跟着使用方走。
    这里用【引用它的函数所属模块】的多数派近似，并在输出里标注分歧。
    """
    pat = re.compile(r"\b" + re.escape(var) + r"\b")
    votes = defaultdict(int)
    for name, s, e, c, q in funcs:
        body = "\n".join(clean_lines[s - 1:e])
        n = len(pat.findall(body))
        if n:
            votes[module_of_func(name, deferred)] += n
    if not votes:
        return PARENT, {}
    top = max(votes.items(), key=lambda kv: kv[1])[0]
    return top, dict(votes)


def var_outward_needs(clean_lines, funcs, vars_found, mod, moved, deferred):
    """新抽出的模块 mod 用到了哪些【别人拥有】的变量。

    【与阶段顺序无关】：不管对方抽没抽走，只要变量不归 mod，
    mod 就无权直接引用它 —— 要么对方公开（破坏封装），要么走门面。
    这正是"函数加个声明就行、变量不行"的区别所在。
    """
    out = defaultdict(set)
    for var in vars_found:
        owner, _ = var_module(var, vars_found[var], funcs, deferred, clean_lines)
        if owner == mod:
            continue
        pat = re.compile(r"\b" + re.escape(var) + r"\b")
        for name, s, e, c, q in funcs:
            if module_of_func(name, deferred) != mod:
                continue
            if pat.search("\n".join(clean_lines[s - 1:e])):
                out[var].add(name)
    return out


def var_cross_refs(clean_lines, funcs, vars_found, moved, deferred):
    """返回 {(caller_func, var)}：引用了【已移出模块所属变量】的母体/别模块函数。

    这类引用比函数引用更难处理：函数只要加声明，变量要么 extern（破坏封装）、
    要么做成门面（要写代码）。若变量是 static，连 extern 都不行。
    """
    out = defaultdict(set)
    for var, decl in vars_found.items():
        owner, votes = var_module(var, decl, funcs, deferred, clean_lines)
        if owner == PARENT or owner not in moved:
            continue
        pat = re.compile(r"\b" + re.escape(var) + r"\b")
        for name, s, e, c, q in funcs:
            tu = module_of_func(name, deferred)
            tu = tu if tu in moved else PARENT
            if tu == owner:
                continue
            body = "\n".join(clean_lines[s - 1:e])
            if pat.search(body):
                out[var].add(f"{name}({tu})")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alt", action="store_true",
                    help="模拟 HookEngine 先于 ScriptBridge 的顺序")
    args = ap.parse_args()

    clean, lines, funcs = build()
    deferred = facts.DEFERRED
    order = PHASES_ALT if args.alt else PHASES
    by_name = {f[0]: f for f in funcs}
    vars_found = facts.find_file_scope_objects(
        facts.strip_comments_and_strings(
            open(TARGET, encoding="utf-8", errors="replace").read(),
            keep_strings=True).splitlines())

    print(f"顺序：{'备选（HookEngine 先）' if args.alt else '§4.3（ScriptBridge 先）'}")
    print("=" * 78)
    print("""
判定口径 —— 只把【外向需求】算作垫片：
  * 外向需求：新抽出的模块 M 要用一个【还没抽出、仍在母体】的函数 F。
    M 自己的头文件没资格声明 F，所以必须临时找个地方声明它 = 垫片。
  * 内向需求：母体（或别的模块）要用 M 里已抽出的函数 F。
    这由 M 的头文件解决，是计划里本来就有的东西，不算垫片。
""")
    print("=" * 78)

    moved = set()
    shim_total = 0
    for i, (mods, size) in enumerate(order, 1):
        mod = mods[0] if len(mods) == 1 else "+".join(mods)
        moved.update(mods)
        edges = cross_refs(lines, funcs, moved, deferred)

        def tu_of(name):
            m = module_of_func(name, deferred)
            return m if m in moved else PARENT

        # 阶段 ≥3 之后，TeardownWindow.h 里的符号由共享头提供，不再是垫片
        shared = SHARED_AT_PHASE3 if i >= 3 else set()

        outward = defaultdict(set)   # 目标(仍在母体) -> {调用方}
        inward = defaultdict(set)
        for caller, callee in edges:
            if callee in shared:
                continue
            c_tu = (PARENT if caller.startswith(PARENT) else tu_of(caller))
            t_tu = tu_of(callee)
            if c_tu == mod and t_tu == PARENT:
                outward[callee].add(caller)
            elif t_tu == mod and c_tu == PARENT:
                inward[callee].add(caller)

        print(f"\n阶段 {i}：抽 {mod}（{size} 行）")
        if outward:
            print(f"   ★ 外向需求 {len(outward)} 个 —— 每个都是一条必须提供的垫片：")
            for t in sorted(outward):
                flag = "  [原 static → 须去 static]" if is_static(lines, by_name[t][1]) else ""
                print(f"       {t:<38} ← {', '.join(sorted(outward[t])[:3])}{flag}")
        else:
            print("   ★ 外向需求 0 个 —— 本阶段不需要垫片")
        print(f"     内向需求 {len(inward)} 个（由 {mod}.h 解决，不算垫片）")

        # 变量：比函数更麻烦。extern 会破坏封装，static 变量连 extern 都不行
        vout = var_outward_needs(lines, funcs, vars_found, mod, moved, deferred)
        vout = {v: c for v, c in vout.items() if v not in shared}
        if vout:
            print(f"   ☆ 外向变量需求 {len(vout)} 个 —— 本模块要用【仍在母体】的变量：")
            for v in sorted(vout):
                users = sorted(vout[v])
                print(f"       {v:<34} 被 {mod} 的：{', '.join(users[:3])}"
                      f"{' …' if len(users) > 3 else ''}")
        vcross = var_cross_refs(lines, funcs, vars_found, moved, deferred)
        mine = {v: c for v, c in vcross.items()
                if var_module(v, vars_found[v], funcs, deferred, lines)[0] == mod}
        if mine:
            print(f"   ☆ 被本模块「带走」但别处仍在用的变量 {len(mine)} 个：")
            for v in sorted(mine):
                users = sorted(mine[v])
                print(f"       {v:<34} 别处引用者：{', '.join(users[:3])}"
                      f"{' …' if len(users) > 3 else ''}")
        shim_total += len(outward)
    print()
    print("=" * 78)
    print(f"全程垫片总数（外向需求去重）：{shim_total}")


if __name__ == "__main__":
    main()
