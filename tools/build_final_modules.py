#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_final_modules.py — 阶段 6 专用：把母体剩下的东西分成两块，并拼出
PluginRegistry.cpp 与 HookLoaderApi.cpp。

母体（Civ6DLLHookLoaderAPI.cpp）在阶段 6 结束后应当只剩：
    * PluginRegistry 的 32 个函数 + 插件表状态（g_plugins / 三把锁 / 两个 thread_local）
    * HookLoaderApi 的 2 个函数 + g_hookApi 表
    * 三个 typedef（OnLoadFunc / OnUnloadFunc / OnMessageFunc）
    以及它们之间的注释。

本脚本只做【状态块搬运 + 文件拼装】；函数体由 extract_module.py 剪出。

输入（tools/extracted/）：
    phase6_PluginRegistry.txt   32 个函数
    phase8_HookLoaderApi.txt    2 个函数
    pr_state_blocks.txt         母体剩余的状态声明块

输出：
    DllLoaderRuntime/PluginRegistry.cpp
    DllLoaderRuntime/HookLoaderApi.cpp
"""

import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
EX = os.path.join(HERE, "extracted")
RT = os.path.join(REPO, "DllLoaderRuntime")

PR_HEADER = '''#include "pch.h"
#include "LoaderCore.h"
#include "PluginTableAccess.h"

#include <Windows.h>
#include <algorithm>
#include <filesystem>
#include <cwctype>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "Civ6DLLHookLoaderAPI.h"
#include "Civ6MessageBus.h"
#include "HookEngine.h"
#include "ImageAddress.h"
#include "LoaderUpdate.h"
#include "ModScan.h"
#include "PatchRegistry.h"
#include "PdataMatch.h"
#include "PluginBoundary.h"
#include "PluginDomain.h"
#include "PluginInFlight.h"
#include "Runtime.h"
#include "ScriptBridge.h"
#include "TeardownWindow.h"
#include "../common/EnabledMods.h"
#include "../common/Logger.h"

// 从 Civ6DLLHookLoaderAPI.cpp 拆出（阶段 6）：插件生命周期编排 + 映像查询。
//
// 本模块拥有（不导出）：
//   g_plugins（插件表）、g_pendingFreeMutex/g_pendingFreeModules（待释放队列）、
//   g_pluginLifecycleMutex、g_gameCoreTransitionMutex、
//   g_activePluginOwner/g_activePluginModule（thread_local owner 上下文）、
//   PluginState / PluginEntry 两个类型。
// 对外的只读查询经 PluginTableAccess.h 的两个门面（ResolveOwnerByModule /
// IsOwnerActive），生命周期锁经 LoaderCore::LifecycleMutex() —— 都不外泄变量。

using namespace std;

namespace fs = std::filesystem;

// 前置声明：OnLoad 失败时隔离该 owner 的全部注册（定义在文件后部）。
static void QuarantinePluginByOwner(const std::wstring& ownerId);

'''

PR_FOOTER = '''
'''

HLA_HEADER = '''#include "pch.h"
#include "Civ6DLLHookLoaderAPI.h"

#include <Windows.h>
#include <cstdint>

#include "Civ6MessageBus.h"
#include "HookEngine.h"
#include "LoaderCore.h"
#include "PluginBoundary.h"
#include "PluginRegistry.h"
#include "PluginTableAccess.h"
#include "ScriptBridge.h"
#include "SymbolResolve.h"
#include "PluginDomain.h"
#include "../common/HookAPI.h"
#include "../common/Logger.h"

// 从 Civ6DLLHookLoaderAPI.cpp 拆出（阶段 6）：HookAPI 表本身。
//
// 这是整个拆分的【组装根 / ABI 汇聚点】：g_hookApi 的初始化表取各模块 *Impl 的地址，
// 因此它 include 全部子系统头文件，且没有任何下层模块反向 include 它。
//
// 只读契约：Loader 初始化后从不写它（全是取地址/读取），插件也只该读。
// const 让它落到 .rdata（PAGE_READONLY）——插件写它会当场 AV，被 CallOnLoadSafe 接住。

using namespace std;

'''

HLA_FOOTER = '''

// ABI 守卫：字段数 / 偏移一旦漂移，插件按旧布局调用就会踩错函数指针。
// 放在表定义之后，确保断言的是【实际发布的这张表】。
static_assert(sizeof(HookAPI) == sizeof(uint32_t) * 2 + CIV6_HOOK_API_ENTRY_COUNT * sizeof(void*),
    "HookAPI 布局与 CIV6_HOOK_API_ENTRY_COUNT 不一致：加字段后要同步这个常量");
static_assert(offsetof(HookAPI, GetSymbolDbMatchRatio) == sizeof(uint32_t) * 2 +
    (CIV6_HOOK_API_ENTRY_COUNT - 1) * sizeof(void*),
    "HookAPI 末字段偏移不符：追加字段时顺序不能变（插件按偏移读）");
'''


def split_funcs(path):
    txt = open(path, encoding="utf-8").read()
    parts = re.split(r"^(// ==== .*? ====)$", txt, flags=re.M)
    out = []
    for i in range(1, len(parts), 2):
        out.append(f"{parts[i]}\n{parts[i+1].strip(chr(10))}")
    return out


def main():
    pr_funcs = split_funcs(os.path.join(EX, "phase6_PluginRegistry.txt"))
    hla_funcs = split_funcs(os.path.join(EX, "phase8_HookLoaderApi.txt"))
    state = open(os.path.join(EX, "pr_state_blocks.txt"), encoding="utf-8").read()
    print(f"PluginRegistry 函数 {len(pr_funcs)} 个；HookLoaderApi 函数 {len(hla_funcs)} 个")

    # HookLoaderApi.cpp：g_hookApi 表 + 2 个函数
    hla_state = open(os.path.join(EX, "hla_state_blocks.txt"), encoding="utf-8").read()
    hla_body = hla_state.strip("\n") + "\n\n" + "\n\n".join(hla_funcs)
    with open(os.path.join(RT, "HookLoaderApi.cpp"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write(HLA_HEADER + hla_body + HLA_FOOTER)
    print("已写 HookLoaderApi.cpp")

    # PluginRegistry.cpp：状态块 + 32 个函数
    pr_body = state.strip("\n") + "\n\n// ================= 函数实现 =================\n\n"
    pr_body += "\n\n".join(pr_funcs)
    # g_gameCorePhaseReady 归 ScriptBridge（阶段 4）：读写都改走门面。
    # 用 re.sub 而不是 str.replace —— 原文的缩进/上下文变体较多，
    # 逐字匹配容易因为一处空格差异而静默失效（实测踩过）。
    pr_body = re.sub(r"g_gameCorePhaseReady = true;",
                     "ScriptBridge::SetGameCorePhaseReady(true);", pr_body)
    pr_body = re.sub(r"g_gameCorePhaseReady = false;",
                     "ScriptBridge::SetGameCorePhaseReady(false);", pr_body)
    pr_body = re.sub(r"return g_gameCorePhaseReady;",
                     "return ScriptBridge::IsGameCorePhaseReady();", pr_body)
    with open(os.path.join(RT, "PluginRegistry.cpp"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write(PR_HEADER + pr_body + PR_FOOTER)
    print("已写 PluginRegistry.cpp")
    return 0


if __name__ == "__main__":
    sys.exit(main())
