#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
assemble_scriptbridge.py — 阶段 4 专用：把 ScriptBridge 的私有状态声明从母体搬到
ScriptBridge.cpp。

为什么单独一个脚本：阶段 4 除了 99 个函数（由 extract_module.py 剪出），还要搬
20 多个状态声明。它们散落在母体的多个匿名 namespace 里，且与已抽走的函数交错，
不能整段搬 —— 必须按【精确子区间】搬，且每段带内容校验（失配即报错）。

用法：
    python tools/assemble_scriptbridge.py --dry-run
    python tools/assemble_scriptbridge.py
"""

import argparse
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PARENT = os.path.join(REPO, "DllLoaderRuntime", "Civ6DLLHookLoaderAPI.cpp")

# (起始行, 结束行, 必须出现的子串, 说明)
# 行号以【当前母体】为准；脚本先核对内容，不符即报错而不是盲删。
STATE_BLOCKS = [
    (257, 274, ["struct PushTargetConfig", "g_defaultPushTargetConfigs",
                "g_pluginPushTargetConfigs", "PushMethodSigType::WithManager"],
     "PushTargetConfig 结构 + PushMethods 目标配置表"),
    (276, 296, ["g_scriptStateMutex", "g_pushStateMutex", "g_activeSharedDetours",
                "g_detourDrainMutex", "g_detourDrainCv", "class SharedDetourActivity"],
     "脚本/PushMethods 锁 + detour 排空计数与等待原语 + RAII 计数类"),
    # GameEvent 段：匿名 namespace 起，到 g_gameEvents 定义止
    #（其后紧跟的 SEH 读取函数已由 extract_module.py 抽走）
    (1147, 1177, ["namespace {", "kLuaSingletonPattern", "g_mainLuaStateHit",
                  "kGameEventNameMax", "kGameEventCurrentGamePattern",
                  "g_gameEventContainerHit", "kMaxRegisteredGameEvents",
                  "struct RegisteredGameEvent", "g_gameEvents[kMaxRegisteredGameEvents]"],
     "GameEvent 引擎 ABI 常量 + 注册表状态（含匿名 namespace 开头）"),
    # 脚本全局注册表段：匿名 namespace 起，到两个跳板定义止
    (1195, 1215, ["namespace {", "struct ScriptGlobalsEntry", "g_scriptGlobals",
                  "g_scriptGlobalsUI", "g_origRegisterScriptData",
                  "g_origRegisterScriptDataForUI"],
     "脚本全局注册表 + 两个原函数跳板"),
    # PushMethods 槽位段：匿名 namespace 起，到两个槽位数组止
    (1225, 1248, ["namespace {", "kMaxPushHooks", "struct NoManagerHookSlot",
                  "struct WithManagerHookSlot", "g_noManagerSlots",
                  "g_withManagerSlots"],
     "PushMethods 槽位常量 + 两个槽位类型 + 两个槽位数组"),
]

# 被搬走 namespace 开头的三段，母体里会留下孤立的 "}  // namespace"。
# 处理办法：不搬 "namespace {" 行，只搬其后的内容 —— 这样母体的 namespace
# 仍然配平，且搬出的内容在目标文件里由统一的匿名 namespace 包裹。
# 见 _split_namespace_open()。


def _split_namespace_open(seg):
    """把块首的 'namespace {' 行摘出来单独返回。

    返回 (namespace_line_or_None, rest)。这样调用方可以把 namespace 行留在母体、
    只搬内容，避免括号不配对。"""
    lines = seg.split("\n")
    if lines and lines[0].strip() == "namespace {":
        return "namespace {", "\n".join(lines[1:])
    return None, seg


def _find_slot_tables(lines):
    """两张 detour 函数指针表（在槽位数组之后，长度随 kMaxPushHooks 变）。"""
    start = None
    for i, ln in enumerate(lines, 1):
        if re.match(r"^void\* NoManagerDetourTable\[", ln):
            start = i
            break
    if start is None:
        raise SystemExit("找不到 NoManagerDetourTable 定义")
    closes = 0
    end = None
    for i in range(start, len(lines) + 1):
        if lines[i - 1].rstrip() == "};":
            closes += 1
            if closes == 2:
                end = i
                break
    if end is None:
        raise SystemExit("找不到两张 detour 表的结束行")
    return start, end


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    lines = open(PARENT, encoding="utf-8", errors="replace").read().split("\n")
    print(f"母体当前 {len(lines)} 行")

    ts, te = _find_slot_tables(lines)
    blocks = list(STATE_BLOCKS) + [
        (ts, te, ["NoManagerDetourTable", "WithManagerDetourTable",
                  "DetourPushNoManager<0>", "DetourPushWithManager<0>"],
         "两张 detour 函数指针表（隐式实例化 DetourPushNoManager<0..15>）"),
    ]
    blocks.sort(key=lambda t: t[0])

    for i in range(1, len(blocks)):
        if blocks[i][0] <= blocks[i - 1][1]:
            raise SystemExit(f"区间重叠：L{blocks[i-1][0]}-{blocks[i-1][1]} 与 "
                             f"L{blocks[i][0]}-{blocks[i][1]}")

    # 校验 + 决定实际删除区间（含 namespace 开头的段，只删 namespace 行【之后】的内容）
    plan = []
    for s, e, expect, why in blocks:
        seg = "\n".join(lines[s - 1:e])
        missing = [x for x in expect if x not in seg]
        if missing:
            raise SystemExit(f"区间 L{s}-{e} 校验失败，缺少 {missing}：\n{seg[:400]}")
        ns, rest = _split_namespace_open(seg)
        del_from = s + 1 if ns else s          # 有 namespace 行则保留它
        plan.append((del_from, e, rest, why, ns is not None))
        note = "（保留 namespace 行）" if ns else ""
        print(f"  ✓ L{del_from:<5}-{e:<5} {why}{note}")

    if args.dry_run:
        print("\n（dry-run：未写文件）")
        return 0

    for del_from, e, _rest, _why, _ns in sorted(plan, key=lambda t: -t[0]):
        del lines[del_from - 1:e]
    out = re.sub(r"\n{4,}", "\n\n\n", "\n".join(lines))
    with open(PARENT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(out)
    print(f"\n母体现在 {len(out.splitlines())} 行")

    dest = os.path.join(HERE, "extracted", "phase4_state_blocks.txt")
    with open(dest, "w", encoding="utf-8", newline="\n") as fh:
        for del_from, e, rest, why, _ns in plan:
            fh.write(f"// ==== {why} ====\n{rest.strip(chr(10))}\n\n")
    print(f"状态块另存：{dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
