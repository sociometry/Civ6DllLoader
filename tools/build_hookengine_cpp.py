#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_hookengine_cpp.py — 阶段 5 专用：把 HookEngine 的状态块与 16 个函数体拼成
DllLoaderRuntime/HookEngine.cpp。

输入（tools/extracted/）：
    he_chunk1.txt          统一挂钩站点 banner + HookSite 结构 + 4 个文件级变量
    he_chunk2.txt          kHookPrologueWindow（跨模块常量，也进 HookEngine.h）
    he_chunk3.txt          三条前置声明（CaptureDispatch / BuildHookHubStub /
                           GetOrCreateHookSiteLocked）
    phase5_HookEngine.txt  16 个函数体（extract_module.py 剪出）

输出：
    DllLoaderRuntime/HookEngine.cpp
"""

import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
EX = os.path.join(HERE, "extracted")
OUT = os.path.join(REPO, "DllLoaderRuntime", "HookEngine.cpp")

HEADER = '''#include "pch.h"
#include "HookEngine.h"

#include <Windows.h>
#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <asmjit/x86.h>

#include "MinHook.h"
#include "ImageAddress.h"
#include "PatchRegistry.h"
#include "PluginBoundary.h"
#include "PluginDomain.h"
#include "Runtime.h"
#include "ScriptBridge.h"      // WaitForDetourDrain / ResetForTeardown
#include "SymbolResolve.h"
#include "TeardownWindow.h"
#include "../common/Logger.h"

// 从 Civ6DLLHookLoaderAPI.cpp 拆出（阶段 5）：挂钩站点表 / JIT stub / capture /
// teardown 站点操作。
//
// 本模块拥有（不导出，见 REFACTOR_PLAN.md §5.1）：
//   struct HookSite（含嵌套 CaptureOut）、g_hookSites、g_captureMutex、g_captureRuntime
// 跨模块常量 kHookPrologueWindow 放 HookEngine.h（PluginRegistry 的 HookPatch 也要用）。
//
// static 取舍：InstallLoaderDetourOnSite 等被 ScriptBridge / PluginRegistry 调用的
// 函数去掉 static；纯本 TU 辅助保持 static。

using namespace std;

namespace HookEngine {

'''

FOOTER = '''

}  // namespace HookEngine
'''


def main():
    chunks = {}
    for name in ("he_chunk1", "he_chunk2", "he_chunk3"):
        p = os.path.join(EX, name + ".txt")
        chunks[name] = open(p, encoding="utf-8").read().rstrip("\n")
        print(f"  {name}: {len(chunks[name].splitlines())} 行")

    funcs = open(os.path.join(EX, "phase5_HookEngine.txt"),
                 encoding="utf-8").read()
    fparts = re.split(r"^(// ==== .*? ====)$", funcs, flags=re.M)
    fblocks = []
    for i in range(1, len(fparts), 2):
        marker, body = fparts[i], fparts[i + 1].strip("\n")
        fblocks.append(f"{marker}\n{body}")
    print(f"  函数块: {len(fblocks)} 个")

    body = []
    body.append("// ---------------- 站点状态（随本模块私有） ----------------\n")
    body.append(chunks["he_chunk1"])
    body.append("\n\n// ---------------- 跨模块常量 ----------------\n")
    # chunk2 里的 kHookPrologueWindow 同时进 HookEngine.h（PluginRegistry 也要用），
    # 这里保留定义（头文件里只放 extern 声明），故注释说明一下。
    body.append(chunks["he_chunk2"])
    body.append("\n\n// ---------------- 前置声明 ----------------\n")
    body.append(chunks["he_chunk3"])
    body.append("\n\n// ---------------- 函数实现 ----------------\n")
    body.extend(fblocks)

    text = HEADER + "\n\n".join(body) + FOOTER
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"已写 {OUT}：{len(text.splitlines())} 行")
    return 0


if __name__ == "__main__":
    sys.exit(main())
