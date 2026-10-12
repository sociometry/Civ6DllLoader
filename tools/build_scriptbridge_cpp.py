#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_scriptbridge_cpp.py — 阶段 4 专用：把三份中间产物拼成 ScriptBridge.cpp。

输入（都在 tools/extracted/）：
    phase4_state_blocks.txt   6 个状态块（含匿名 namespace 开闭与少量上下文残留）
    phase4_ScriptBridge.txt   99 个函数体（含各自上方注释）

输出：
    DllLoaderRuntime/ScriptBridge.cpp

拼装规则：
  * 去掉状态块开头的游离 "};"（剪区间时带上了上一个结构的收尾）。
  * 状态块之间的匿名 namespace 开闭要合并：源文件里它们是【同一个】匿名 namespace
    的三段，剪开后各自带 namespace { ... }，直接拼接会得到多个匿名 namespace。
    多个匿名 namespace 在 C++ 里合法且等价于一个，故保留原样 —— 不做合并，
    减少改动面。
  * 函数体按提取顺序排列（与源文件同序）。
"""

import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
EX = os.path.join(HERE, "extracted")
OUT = os.path.join(REPO, "DllLoaderRuntime", "ScriptBridge.cpp")

HEADER = '''#include "pch.h"
#include "ScriptBridge.h"

#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdarg>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "Civ6MessageBus.h"
#include "HavokScript.h"
#include "ImageAddress.h"
#include "Localization.h"
#include "PatchRegistry.h"
#include "PdataMatch.h"
#include "PluginBoundary.h"
#include "PluginDomain.h"
#include "PluginInFlight.h"
#include "PluginTableAccess.h"
#include "ProxyTypes.h"
#include "Runtime.h"
#include "TeardownWindow.h"
#include "HookEngine.h"        // InstallLoaderDetourOnSite
#include "../common/Logger.h"
#include "../common/ModScan.h"

// 从 Civ6DLLHookLoaderAPI.cpp 拆出（阶段 4）：Lua / GameEvent / 脚本注册 / PushMethods 槽位。
//
// 本文件里的状态（见下方各块）原属母体，现随模块私有化：
//   PushMethods 目标配置表、脚本/PushMethods 锁、detour 排空计数与等待原语、
//   GameEvent 常量与状态表、脚本全局注册表与两个跳板、PushMethods 槽位与 detour 表。
// 需要跨模块访问的部分（脚本全局表、槽位数组、g_orig*、排空计数）一律走
// ScriptBridge.h 里的门面，不再外泄变量。
//
// static 取舍：函数体中原来带 static 的 ABI 入口全部去掉 static（母体的 g_hookApi
// 取它们地址）；模块内部辅助保持 static。

using namespace std;

namespace {

'''

FOOTER = '''

}  // namespace

// ================= 门面实现（声明见 ScriptBridge.h） =================

namespace ScriptBridge {

RemovedCounts RemovePluginRegistrations(const std::wstring& owner) {
    RemovedCounts n;
    // 脚本全局表：按 owner 摘除（原 RemovePluginOwnedRegistrations 的 removeOwnedBy）。
    auto removeOwnedBy = [&owner](auto& vec) {
        size_t removed = 0;
        for (auto it = vec.begin(); it != vec.end(); ) {
            if (it->owner == owner) {
                it = vec.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        return removed;
    };
    {
        lock_guard<mutex> stateLock(g_scriptStateMutex);
        n.globals = removeOwnedBy(g_scriptGlobals);
        n.globalsUI = removeOwnedBy(g_scriptGlobalsUI);
    }
    // PushMethods 槽位：逐槽摘掉该 owner 的方法。
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (auto& slot : g_noManagerSlots) {
            if (slot.used) n.luaMethods += RemoveOwnedSlotMethods(slot, owner);
        }
        for (auto& slot : g_withManagerSlots) {
            if (slot.used) n.luaMethods += RemoveOwnedSlotMethods(slot, owner);
        }
    }
    n.targetConfigs = g_pluginPushTargetConfigs.erase(owner);
    // GameEvent 槽位：清空该 owner 注册的事件表（name/luaPushFn/ownerId）。
    // Quarantine/Unload 都经本函数，无需在各自路径重复接线。
    CleanupGameEventsForOwner(owner);
    return n;
}

void ResetForTeardown() {
    // teardown 要的是"清空全部"，不是"按 owner 摘"——此刻也无法枚举 owner。
    // 覆盖 HookEngine 的 RemoveGameCoreDomainSiteRecords 原先直接操作的 6 个对象。
    g_origRegisterScriptData = nullptr;
    g_origRegisterScriptDataForUI = nullptr;
    {
        lock_guard<mutex> stateLock(g_pushStateMutex);
        for (int i = 0; i < kMaxPushHooks; ++i) {
            g_noManagerSlots[i] = NoManagerHookSlot{};
            g_withManagerSlots[i] = WithManagerHookSlot{};
        }
    }
}

void WaitForDetourDrain() {
    unique_lock<mutex> drainLock(g_detourDrainMutex);
    g_detourDrainCv.wait(drainLock, [] {
        return g_activeSharedDetours.load(std::memory_order_acquire) == 0;
    });
}

// 阶段 B 就绪标志（原母体的 g_gameCorePhaseReady）。改原子后读侧无锁：
// 两个读点（PushLuaMethodsImpl / EnsureScriptHooksInstalled）本来就持 lifecycle 锁，
// 用 LoaderCore::IsInitialized() 会多取一次锁；写侧语义不变（那两处也持锁）。
namespace {
std::atomic<bool> g_gameCorePhaseReady{ false };
}

bool IsGameCorePhaseReady() {
    return g_gameCorePhaseReady.load(std::memory_order_acquire);
}

void SetGameCorePhaseReady(bool ready) {
    g_gameCorePhaseReady.store(ready, std::memory_order_release);
}

}  // namespace ScriptBridge
'''


def strip_leading_closer(seg: str) -> str:
    """去掉块开头游离的 "};"（剪区间时带上了上一个结构的收尾）。"""
    lines = seg.split("\n")
    while lines and lines[0].strip() in ("};", "}", ""):
        lines.pop(0)
    return "\n".join(lines)


def main():
    state = open(os.path.join(EX, "phase4_state_blocks.txt"),
                 encoding="utf-8").read()
    funcs = open(os.path.join(EX, "phase4_ScriptBridge.txt"),
                 encoding="utf-8").read()

    # 状态块：按 "// ==== ... ====" 切分
    parts = re.split(r"^// ==== .*? ====$", state, flags=re.M)
    blocks = [strip_leading_closer(p).strip("\n") for p in parts if p.strip()]
    print(f"状态块 {len(blocks)} 个")

    # 函数块：同样切分，但保留 "// ==== 函数名 ====" 标记作为分节注释
    fparts = re.split(r"^(// ==== .*? ====)$", funcs, flags=re.M)
    fblocks = []
    for i in range(1, len(fparts), 2):
        marker, body = fparts[i], fparts[i + 1].strip("\n")
        fblocks.append(f"{marker}\n{body}")
    print(f"函数块 {len(fblocks)} 个")

    body = "\n\n".join(blocks) + "\n\n// ================= 函数实现 =================\n\n"
    body += "\n\n".join(fblocks)

    # 函数体里对 g_gameCorePhaseReady 的读取改走门面（定义在下面的门面段里）。
    # 原代码直接读裸 bool；改原子后统一经 IsGameCorePhaseReady()，
    # 这样"谁在读、谁在写"只有一处定义，也避免将来有人漏改某一处。
    n_read = body.count("if (!g_gameCorePhaseReady)")
    body = body.replace("if (!g_gameCorePhaseReady) {", "if (!IsGameCorePhaseReady()) {")
    body = body.replace("if (!g_gameCorePhaseReady) return;", "if (!IsGameCorePhaseReady()) return;")
    print(f"g_gameCorePhaseReady 读取改门面：{n_read} 处")

    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(HEADER + body + FOOTER)
    print(f"已写 {OUT}：{len((HEADER + body + FOOTER).splitlines())} 行")
    return 0


if __name__ == "__main__":
    sys.exit(main())
