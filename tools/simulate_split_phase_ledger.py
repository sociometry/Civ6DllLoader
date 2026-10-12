#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simulate_split_phase_ledger.py — 逐阶段算出"要编译通过，必须让哪些名字跨 TU 可见"。

判据（只用【函数体内的引用】，定义行不算引用 —— 定义行随对象一起搬）：

  对每个名字 E（函数 / 文件级对象 / 类型）：
      home(E)  = E 的最终模块（对象与类型按 §3/§5 的归属；尚未抽出的算母体）
      users(E) = 函数体内引用了 E 的函数的所属模块集合（尚未抽出的算母体）
  于是：
      OUT(E) = users(E) - {母体}     即"抽出模块要用它"
      IN(E)  = {母体} ∩ users(E)

  在阶段 N（已抽出集合 D）：
      若 home(E) 尚未抽出、而 users(E) 里有已抽出的模块
          → 该阶段必须给 E 一条【临时声明/垫片】才能编过
      若 home(E) 已抽出、而母体还要用它
          → 写 E 的模块 .h 即可（IN-decl，不算垫片）

用法：python tools/simulate_split_phase_ledger.py [--alt] [--all]
"""

import argparse
import importlib.util
import os
import re
import sys
from collections import defaultdict, OrderedDict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(os.path.dirname(HERE), "DllLoaderRuntime", "Civ6DLLHookLoaderAPI.cpp")
_spec = importlib.util.spec_from_file_location("facts", os.path.join(HERE, "gen_refactor_facts.py"))
facts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(facts)

ap = argparse.ArgumentParser()
ap.add_argument("--alt", action="store_true")
ap.add_argument("--all", action="store_true")
A = ap.parse_args()

PARENT = "(母体)"
PHASES = [("SymbolResolve",), ("PluginDomain",), ("Civ6MessageBus",), ("ScriptBridge",),
          ("HookEngine",), ("PluginRegistry", "HookLoaderApi")]
PHASES_ALT = [("SymbolResolve",), ("PluginDomain",), ("Civ6MessageBus",), ("HookEngine",),
              ("ScriptBridge",), ("PluginRegistry", "HookLoaderApi")]
ORDER = PHASES_ALT if A.alt else PHASES
DEFER_MOD = "SymbolResolve"          # §4.5：5 个缓迁 *Impl 最终归入 SymbolResolve

src = open(TARGET, encoding="utf-8", errors="replace").read()
clean = facts.strip_comments_and_strings(src)
lines = clean.split("\n")
funcs = facts.find_functions(clean)
by_name = {f[0]: f for f in funcs}
deferred = set(facts.DEFERRED)
owner_line = {}
for n, s, e, c, q in funcs:
    for k in range(s, e + 1):
        owner_line[k] = n
objs = facts.find_file_scope_objects(lines)
type_scopes = facts.find_type_scopes(clean)
types = {t[0]: (t[1], t[2]) for t in type_scopes}

# 文件级对象的归属（按 §3/§5 的实测归属表；未列出的按"使用者全在同一模块"判定）
OBJ_HOME = {
    "g_bus": "Civ6MessageBus",
    "g_plugins": "PluginRegistry", "g_activePluginOwner": "PluginRegistry",
    "g_activePluginModule": "PluginRegistry", "g_pluginLifecycleMutex": "PluginRegistry",
    "g_pendingFreeMutex": "PluginRegistry", "g_pendingFreeModules": "PluginRegistry",
    "g_gameCoreTransitionMutex": "PluginRegistry", "g_gameCorePhaseReady": "PluginRegistry",
    "g_scriptStateMutex": "ScriptBridge", "g_scriptGlobals": "ScriptBridge",
    "g_scriptGlobalsUI": "ScriptBridge", "g_origRegisterScriptData": "ScriptBridge",
    "g_origRegisterScriptDataForUI": "ScriptBridge", "g_pushStateMutex": "ScriptBridge",
    "g_noManagerSlots": "ScriptBridge", "g_withManagerSlots": "ScriptBridge",
    "g_pluginPushTargetConfigs": "ScriptBridge", "g_activeSharedDetours": "ScriptBridge",
    "g_detourDrainMutex": "ScriptBridge", "g_detourDrainCv": "ScriptBridge",
    "NoManagerDetourTable": "ScriptBridge", "WithManagerDetourTable": "ScriptBridge",
    "g_defaultPushTargetConfigs": "ScriptBridge", "g_gameEvents": "ScriptBridge",
    "g_gameEventContainerHit": "ScriptBridge", "g_mainLuaStateHit": "ScriptBridge",
    "kMaxPushHooks": "ScriptBridge", "kGameEventNameMax": "ScriptBridge",
    "kMaxRegisteredGameEvents": "ScriptBridge", "kGameEventCurrentGamePattern": "ScriptBridge",
    "kLuaSingletonPattern": "ScriptBridge",
    "g_hookSites": "HookEngine", "g_captureMutex": "HookEngine",
    "g_captureRuntime": "HookEngine", "kHookPrologueWindow": "HookEngine",
    "g_gameCoreTeardownAddress": "TeardownWindow", "g_gameCoreTeardownSizeOfImage": "TeardownWindow",
    "g_hookApi": "HookLoaderApi",
    "kAnchorDx11SizeOfImage": "SymbolResolve", "kAnchorDx11TimeDate": "SymbolResolve",
    "kAnchorDx12SizeOfImage": "SymbolResolve", "kAnchorDx12TimeDate": "SymbolResolve",
}
TYPE_HOME = {
    "PluginEntry": "PluginRegistry", "HookSite": "HookEngine", "CaptureOut": "HookEngine",
    "PushTargetConfig": "ScriptBridge", "SharedDetourActivity": "ScriptBridge",
    "CallerPluginInfo": "PluginDomain", "RegisteredGameEvent": "ScriptBridge",
    "ScriptGlobalsEntry": "ScriptBridge", "NoManagerHookSlot": "ScriptBridge",
    "WithManagerHookSlot": "ScriptBridge", "StoredLuaMethod": "ScriptBridge",
    "PluginState": "PluginRegistry",
}


def fn_mod(name):
    """缓迁的 5 个 *Impl 在阶段 1–5 期间仍留在母体（§4.5：阶段 6 才归位）。"""
    if name in deferred:
        return PARENT
    return facts.module_of(name) or PARENT


def fn_final_mod(name):
    return DEFER_MOD if name in deferred else (facts.module_of(name) or PARENT)


def obj_mod(o):
    return OBJ_HOME.get(o, PARENT)


def type_mod(t):
    return TYPE_HOME.get(t, PARENT)


def is_static_fn(name):
    f = by_name.get(name)
    return bool(f and re.match(r"^\s*static\b", lines[f[1] - 1]))


# 只收集【函数体内】的引用
names = sorted(by_name, key=len, reverse=True)
fn_pat = re.compile(r"(?<![\w:.>])(?:LoaderCore::)?&?(" + "|".join(map(re.escape, names)) + r")\b")
obj_pat = {o: re.compile(r"(?<![\w:.>])" + re.escape(o) + r"\b") for o in objs}
type_pat = {t: re.compile(r"(?<![\w:.>])" + re.escape(t) + r"\b") for t in types}

users_fn = defaultdict(set)
users_obj = defaultdict(set)
users_ty = defaultdict(set)
body_lines = []
for n, s, e, c, q in funcs:
    body_lines.append((n, s, e))

for n, s, e in body_lines:
    mod = fn_mod(n)
    body = "\n".join(lines[s - 1:e])
    for m in fn_pat.finditer(body):
        tgt = m.group(1)
        if by_name[tgt][1] >= s and by_name[tgt][2] <= e and by_name[tgt][0] == tgt and by_name[tgt][1] == s:
            continue
        if tgt != n:
            users_fn[tgt].add(mod)
    for o, p in obj_pat.items():
        if p.search(body):
            users_obj[o].add(mod)
    for t, p in type_pat.items():
        if p.search(body):
            users_ty[t].add(mod)

# 顶层文件级（g_hookApi 初始化表 / static_assert / detour 表）也算母体使用者
PARENT_LINES = [(3201, 3298, "g_hookApi 初始化表")]
for t, p in list(obj_pat.items()) + list(type_pat.items()):
    pass
for a, b, why in PARENT_LINES:
    chunk = "\n".join(lines[a - 1:b])
    for m in fn_pat.finditer(chunk):
        users_fn[m.group(1)].add(PARENT)
    for o, p in obj_pat.items():
        if p.search(chunk):
            users_obj[o].add(PARENT)
    for t, p in type_pat.items():
        if p.search(chunk):
            users_ty[t].add(PARENT)


def report(done, ph, group):
    print(f"\n{'='*100}\n阶段 {ph}：抽 {' + '.join(group)}   "
          f"（已抽出：{sorted(done) or '无'}）\n{'='*100}")
    out_fn, out_obj, out_ty = [], [], []
    for tgt, us in users_fn.items():
        home = fn_mod(tgt)
        if home in done or home in group:
            continue                       # 已抽出/本阶段抽出 → 走自己的 .h
        if us & (done | set(group)):
            out_fn.append((tgt, sorted(us)))
    for o, us in users_obj.items():
        home = obj_mod(o)
        if home in done or home in group:
            continue
        if us & (done | set(group)):
            out_obj.append((o, objs[o], sorted(us)))
    for t, us in users_ty.items():
        home = type_mod(t)
        if home in done or home in group:
            continue
        if us & (done | set(group)):
            out_ty.append((t, types[t][0], sorted(us)))

    print(f"  A. 函数垫片：本阶段抽出的模块要调的函数仍在母体（{len(out_fn)} 个）")
    for tgt, us in sorted(out_fn):
        st = "  [去 static]" if is_static_fn(tgt) else ""
        print(f"     {tgt:<42} 使用者 TU={us}  归属={fn_mod(tgt)}{st}")
    if not out_fn:
        print("     (无)")
    print(f"  B. 变量：本阶段抽出的模块要用的变量仍在母体/别模块（{len(out_obj)} 个）")
    for o, ln, us in sorted(out_obj, key=lambda x: x[1]):
        print(f"     L{ln:<5} {o:<32} 使用者 TU={us}  归属={obj_mod(o)}")
    if not out_obj:
        print("     (无)")
    print(f"  C. 类型：本阶段抽出的模块要用的类型仍在母体（{len(out_ty)} 个）")
    for t, ln, us in sorted(out_ty, key=lambda x: x[1]):
        print(f"     L{ln:<5} {t:<32} 使用者 TU={us}  归属={type_mod(t)}")
    if not out_ty:
        print("     (无)")

    # 反向：本阶段抽出的模块【必须导出】给母体的名字（母体还要用）
    exp_obj = [(o, objs[o], sorted(us)) for o, us in users_obj.items()
               if obj_mod(o) in set(group) and PARENT in us]
    exp_ty = [(t, types[t][0], sorted(us)) for t, us in users_ty.items()
              if type_mod(t) in set(group) and PARENT in us]
    exp_fn = [(t, sorted(us)) for t, us in users_fn.items()
              if fn_final_mod(t) in set(group) and PARENT in us]
    print(f"  D. 本阶段模块【必须导出】给母体的变量（母体还要用）：{len(exp_obj)} 个")
    for o, ln, us in sorted(exp_obj, key=lambda x: x[1]):
        print(f"     L{ln:<5} {o:<32} 使用者 TU={us}")
    if not exp_obj:
        print("     (无)")
    print(f"  E. 本阶段模块【必须导出】给母体的类型：{len(exp_ty)} 个")
    for t, ln, us in sorted(exp_ty, key=lambda x: x[1]):
        print(f"     L{ln:<5} {t:<32} 使用者 TU={us}")
    if not exp_ty:
        print("     (无)")
    print(f"  F. 本阶段模块【必须导出】给母体的函数（母体还要调用）：{len(exp_fn)} 个")
    for t, us in sorted(exp_fn):
        print(f"     {t:<42} 使用者 TU={us}")
    if not exp_fn:
        print("     (无)")


done = set()
for ph, group in enumerate(ORDER, 1):
    report(done, ph, group)
    done |= set(group)

if A.all:
    print(f"\n{'='*100}\n终态（全部抽出）\n{'='*100}")
    report(set(m for g in ORDER for m in g), 0, ())
