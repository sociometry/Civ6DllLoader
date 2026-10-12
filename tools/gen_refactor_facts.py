#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_refactor_facts.py — 为 docs/REFACTOR_PLAN.md 生成全部实测数据。

存在理由：该文档前三版的行数/行号/计数/归属数据由手工统计得出，被两轮独立
审查（docs/REFACTOR_PLAN_REVIEW_R2.md 与 _R3_A/_R3_B.md）查出 20 余处错误：
HookEngine 行数虚报 60%（文档写 ~1000、实测 624）、两个日志锚点行号互换
（差 2666 行）、依赖计数把别的模块算进来（称合并会拖入 PluginBoundary 14 次，
实测阶段 1 要迁的 10 个函数体内是 0 次）。手工统计不可复现，本脚本让每个
数字都有单一来源。

关键设计（针对上述错误的成因）：
  * 行数按【函数体括号配对】算，不按行号区间截取 —— 后者会把夹在中间的其他
    模块函数一并计入（这正是 "PluginBoundary 14 次" 的来源，实测该区间内属于
    Core 函数的是 0 次）。
  * 依赖统计只在【该函数体内】搜模块名，不跨区间。
  * 所有计数先剥离注释与字符串字面量，避免注释里的字样被算进去（"__try 15/16/21"
    三方分歧的成因）。
  * 未归入任何模块的函数会被显式列出，不靠"另有 N 个"含糊带过。

用法：
    python tools/gen_refactor_facts.py                 # 全部报表
    python tools/gen_refactor_facts.py --section 3     # 只出某一节
    python tools/gen_refactor_facts.py --check         # 只校验文档与实测是否一致
"""

import argparse
import contextlib
import importlib.util
import io
import os
import re
import sys
from collections import defaultdict, OrderedDict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TARGET = os.path.join(REPO, "DllLoaderRuntime", "Civ6DLLHookLoaderAPI.cpp")


# ---------------------------------------------------------------- 词法预处理

def strip_comments_and_strings(src: str, keep_strings: bool = False):
    """返回与 src 等长的文本，注释与字符串字面量的内容被替换为空格。

    保留换行与长度，使行号、列号仍与原文件对应 —— 这样后续既能按行号定位，
    又不会把注释里的 "__try" / "PluginBoundary" 当成真实代码。

    keep_strings=True 时只抹注释、保留字符串内容。用于【跨行声明拼接】：
    声明可能跨行（`constexpr const char* k =` 换行 `"...";`），若把字符串也抹空，
    续行会变成空行，拼接逻辑就断在那里，声明被漏扫。
    """
    out = list(src)
    n = len(src)
    i = 0
    while i < n:
        c = src[i]
        # 行注释
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        # 块注释
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
            continue
        # 字符串 / 字符字面量（含 raw 的简化处理）
        if c == '"' or c == "'":
            if keep_strings:
                i += 1
                while i < n:
                    if src[i] == "\\" and i + 1 < n:
                        i += 2
                        continue
                    if src[i] == quote_of(c):
                        i += 1
                        break
                    i += 1
                continue
            quote = c
            out[i] = " "
            i += 1
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    if src[i] != "\n":
                        out[i] = " "
                    if src[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if src[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def quote_of(c):
    return c


# ---------------------------------------------------------------- 函数提取

# 函数定义的形态：行首（可有 static / extern "C" / __declspec(...) 前缀）
# 以标识符 + '(' 结尾，且该行不以 ';' 结尾（排除声明）、不是控制流关键字。
CTRL_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "return", "sizeof", "do", "else",
    "case", "default", "static_assert", "typedef", "using", "namespace", "struct",
    "class", "enum", "union", "template", "extern", "define", "ifdef", "ifndef",
    "endif", "pragma", "include", "undef", "elif",
}

PREFIX_RE = re.compile(
    r"^(?:static\s+|extern\s+\"C\"\s+|inline\s+|__declspec\s*\([^)]*\)\s+"
    r"|__cdecl\s+|__fastcall\s+|__stdcall\s+|constexpr\s+|virtual\s+)*"
)


def find_functions(clean: str):
    """返回 [(name, start_line, end_line, body_line_count, qualified)]。

    start_line 是含签名的首行；end_line 是函数体闭合大括号所在行。
    body_line_count = end - start + 1（闭区间，与文档口径一致）。

    算法：从每个"看起来像函数定义"的起始行出发，先跨行配对参数列表的圆括号，
    再找函数体的 '{' 并配对花括号。跨行签名（如 InstallPushMethodsNoManager）
    也能处理。
    """
    lines = clean.split("\n")
    funcs = []
    i = 0
    n = len(lines)
    # 这些"前置行"属于函数定义的一部分，必须计入 start_line —— 否则机械按行
    # 截取会丢掉它们，造成真实的编译/行为破坏：
    #   * `template <typename Slot>` 独占一行 -> 丢失后 Slot 未定义（C2065）
    #   * `__declspec(noinline)` 独占一行    -> 丢失后函数可能被内联，
    #     _ReturnAddress() 取到错误的栈帧，插件鉴权静默失效
    LEADING_RE = re.compile(
        r"^\s*(?:template\s*<.*>\s*$|__declspec\s*\([^)]*\)\s*$"
        r"|__forceinline\s*$|inline\s*$|static\s*$|extern\s+\"C\"\s*$)")
    while i < n:
        raw = lines[i]
        if not raw or raw[0] in " \t":
            i += 1
            continue
        if raw.lstrip().startswith("#"):
            i += 1
            continue
        if raw.startswith(("}", "//", "/*", "*")):
            i += 1
            continue

        # 回看：若上一行是 template<> / __declspec(...) 之类的前置行，start 提前
        start = i
        while start - 1 >= 0 and LEADING_RE.match(lines[start - 1]):
            start -= 1
            if i - start > 4:
                break

        # 去掉前缀限定符后应形如 "返回类型 名字("
        stripped = PREFIX_RE.sub("", raw).strip()
        if "(" not in stripped:
            i += 1
            continue
        # 排除纯声明（行尾 ';'）
        if stripped.rstrip().endswith(";"):
            i += 1
            continue
        # 函数名是 '(' 之前的那一段里的最后一个标识符（前面是返回类型与限定符）
        head = stripped[:stripped.index("(")].strip()
        if not head:
            i += 1
            continue
        # 允许模板参数，取最后一个由字母/数字/下划线/:: 组成的段
        cands = re.findall(r"[A-Za-z_~][\w:]*", head)
        if not cands:
            i += 1
            continue
        name = cands[-1]
        base = name.split("::")[-1]
        if base in CTRL_KEYWORDS:
            i += 1
            continue
        # 返回类型位置必须非空（排除宏调用等）
        if len(cands) < 2 and "::" not in name:
            i += 1
            continue

        # 从首个 '(' 起配对圆括号；闭合后继续找函数体的 '{'
        depth = 0
        seen_open = False
        body_start = None
        j = i
        while j < n:
            line = lines[j]
            k = 0
            while k < len(line):
                ch = line[k]
                if ch == "(":
                    depth += 1
                    seen_open = True
                elif ch == ")":
                    depth -= 1
                elif ch == "{" and seen_open and depth == 0:
                    body_start = j
                    break
                elif ch == ";" and seen_open and depth == 0:
                    break  # 声明而非定义
                k += 1
            if body_start is not None:
                break
            if seen_open and depth == 0 and ";" in line:
                break
            j += 1
        if body_start is None:
            i += 1
            continue

        # 从 body_start 的 '{' 开始配对花括号
        d = 0
        end_line = None
        for k in range(body_start, n):
            for ch in lines[k]:
                if ch == "{":
                    d += 1
                elif ch == "}":
                    d -= 1
                    if d == 0:
                        end_line = k
                        break
            if end_line is not None:
                break
        if end_line is None:
            i += 1
            continue
        funcs.append((base, start + 1, end_line + 1, end_line - start + 1, name))
        i = end_line + 1
    return funcs


# ---------------------------------------------------------------- 模块归属

# 按函数名精确指派（不靠行号区间 —— 那正是此前错误的来源）
MODULE_OF = {}


def _assign(module, names):
    for nm in names.split():
        MODULE_OF[nm] = module


_assign("SymbolResolve", """
ResolveSectionRva ResolveByRvaCore ResolveByNameCore ResolveByPatternCore
ResolveByVTableCore ReadVTableSlotSafe ResolveDataByAobCore InternalToolApi
ExeMatchesAnchor CurrentExeImage ResolveExeTarget
GetSymbolDbStateImpl GetSymbolDbMatchRatioImpl
""")

_assign("PluginDomain", """
ResolvePluginOwnerForAddress RequirePluginOwner TargetInCurrentGameCore
RequireGameCoreOwner RangeInsideOneLoadedModule IsTargetOpenToCaller
IsImageOpenToCaller IsRangeOpenToCaller TargetInTearingDownGameCore
CategoryNameForLog
""")

_assign("HookEngine", """
GetOrCreateHookSiteLocked RemoveGameCoreDomainSiteRecords DisableGameCoreDomainSites
RegisterGlobalCaptureCore InstallHookImpl BuildHookHubStub
CleanupAllCaptureSites CleanupCaptureSitesForOwner RegisterGlobalCaptureImpl
InstallLoaderDetourOnSite RemoveHookSiteRecordLocked IsExecutableTargetSpan
CaptureDispatch RetireHookSiteDetoursForOwnerLocked OverlapsHookPrologue
SafeWritePointer
""")

_assign("PluginRegistry", """
SetPluginState QueueGameCoreModuleForFree FreePendingPluginModules
SetActivePluginContext ClearActivePluginContext NormalizePluginPath KindToCategory
SetGameCoreTeardownWindow RegisterPluginMessageHandler RegisterMessageHandlerImpl
IsImageLoadedImpl GetImageInfoImpl HookPatch HookUnpatch AttachGameCore
CallOnLoadSafe CallOnUnloadSafe CallPluginKindSafe LoadPluginDllInternal
RemovePluginHooks RemovePluginOwnedRegistrations QuarantinePluginByOwner
UnloadPluginByOwnerId LoadPluginsOf UnloadPluginsOf LoadSinglePlugin
InitializeGameCorePhase IsInitialized ClearGameCoreTeardownWindow ResetForReload
CategoryForPath GetModuleSizeOfImage
""")

_assign("Civ6MessageBus", """
BroadcastMessageImpl SendMessageToImpl
""")

# 阶段 2/4 新增的门面实现：归 PluginRegistry
_assign("PluginRegistry", """
LifecycleMutex IsOwnerActive ResolveOwnerByModule
""")

# §4.5：5 个缓迁 *Impl 在阶段 6 归入 SymbolResolve（此前留在母体避开 C 依赖）
_assign("SymbolResolve", """
ResolveByRvaImpl ResolveByNameImpl ResolveByRvaExImpl ResolveByPatternImpl ResolveByVTableImpl
""")

_assign("HookLoaderApi", """
VerifyHookApiTableProtection RuntimeHookApi
""")

# ScriptBridge：显式列 + 模式匹配
_assign("ScriptBridge", """
GetCurrentGameSlot GetEngineUtilityCore GetEngineUtilityImpl GetMainLuaStateImpl
GameEventReadPtrSafe GameEventReadInt32Safe GameEventPopToBaseSeh
GameEventPushArgsSeh GameEventInvokeLuaSeh GameEventInvokeLuaImpl
GameEventInvokeLua WarnEngineUtilityUnavailable TriggerGameEventImpl
RegisterGameEventImpl CleanupGameEventsForOwner ResolveCurrentGameCoreByName
SameLuaMethod MergeLuaMethod MergeLuaMethods CallScriptGlobalsSafe
SnapshotScriptGlobals Hook_RegisterScriptData Hook_RegisterScriptDataForUI
EnsureScriptHooksInstalled RegisterScriptGlobalsImpl RegisterScriptGlobalsForUIImpl
RemoveOwnedSlotMethods RebuildSlotOwners PushStoredMethodIfActive
DetourPushNoManager DetourPushWithManager FindOrAllocNoManagerSlot
FindOrAllocWithManagerSlot InstallPushMethodsNoManager InstallPushMethodsWithManager
WarnHksImportMissing ValidateLuaState ValidateLuaCString FormatLuaString
EditPlayerImpl MakeHashImpl RegisterPushMethodsTargetImpl
CivCrc32Raw CivCrc32Byte CivCrc32RawLen ResolveEditPlayer PushLuaMethodsImpl
""")

# 本阶段【有意缓迁】到母体的函数：它们调用 PluginDomain（C），而 C 要到阶段 3 才拆。
# 与"未归属"不同 —— 这是计划内的中间态，必须单独列出，否则会被误读成漏划。
DEFERRED = {
    "ResolveByRvaImpl", "ResolveByNameImpl", "ResolveByRvaExImpl",
    "ResolveByPatternImpl", "ResolveByVTableImpl",
}

SCRIPTBRIDGE_PATTERNS = [
    re.compile(r"^Lua\w*Impl$"),
    re.compile(r"^Loc\w*Impl$"),
    re.compile(r"^LogImpl$"),
    re.compile(r"^Hook_\w+$"),
    re.compile(r"^Detour\w+$"),
]


def find_type_scopes(clean: str):
    """返回 [(name, start_line, end_line)]，用于判断某个 static 属于哪个类型。

    必须支持【嵌套类型】：HookSite::CaptureOut(L172)、NoManagerHookSlot(L2334)、
    WithManagerHookSlot(L2344)、RegisteredGameEvent(L1595)、ScriptGlobalsEntry(L2171)
    都在另一个 struct 内。只认深度 0 会漏掉这 5 个，导致 §6 的类型成员归属判错。

    做法：用一个栈跟踪"当前这个花括号层是不是类型体"，而不是只看全局深度。
    """
    lines = clean.split("\n")
    scopes = []
    # 栈元素：类型名（None 表示这层不是类型体）
    stack = []
    pending = None
    for i, ln in enumerate(lines, 1):
        # enum / enum class 也算类型：PluginState 是 enum class，跨 TU 时
        # 与 struct 同样需要进内部头（`entry.state == PluginState::Loading`
        # 这种比较必须在声明可见的 TU 里编译）。漏掉它会让"哪些类型要搬"
        # 的清单不完整。
        m = re.match(r"^\s*(?:typedef\s+)?(struct|class|union|enum(?:\s+class)?)"
                     r"\s+(\w+)?", ln)
        if m and ";" not in ln:
            pending = m.group(2) or "(匿名)"
        for ch in ln:
            if ch == "{":
                stack.append(pending)
                if pending:
                    scopes.append([pending, i, None])
                pending = None
            elif ch == "}":
                if stack:
                    closed = stack.pop()
                    if closed:
                        # 找到该类型名最近一个未记 end 的条目
                        for sc in reversed(scopes):
                            if sc[0] == closed and sc[2] is None:
                                sc[2] = i
                                break
    return [tuple(s) for s in scopes if s[2] is not None]


def type_scope_of(scopes, line_no):
    for name, s, e in scopes:
        if s <= line_no <= e:
            return name
    return None


def module_of(name, qualified=""):
    if name in MODULE_OF:
        return MODULE_OF[name]
    for pat in SCRIPTBRIDGE_PATTERNS:
        if pat.match(name):
            return "ScriptBridge"
    return None


# ---------------------------------------------------------------- 报表

MODULES = ["SymbolResolve", "PluginDomain", "HookEngine", "ScriptBridge",
           "Civ6MessageBus", "PluginRegistry", "HookLoaderApi"]

# 模块依赖的候选模块名（用于函数体内的依赖探测）
DEP_TOKENS = OrderedDict([
    ("ImageAddress", r"\bImageAddress::"),
    ("PdataMatch", r"\bPdataMatch::"),
    ("PluginBoundary", r"\bPluginBoundary::"),
    ("Runtime", r"\bRuntime::"),
    ("Logger", r"\bLogger::"),
    ("PluginInFlight", r"\bPluginInFlight::"),
    ("PatchRegistry", r"\bPatchRegistry::"),
    ("Civ6MessageBus", r"\bg_bus\b"),
    ("HookAPI_common", r"\bResolveDataByAob\b|\bResolveByHookInfo\b"),
])


def find_file_scope_objects(clines):
    """返回 OrderedDict{名字: 行号}：函数/类型之外的对象定义（含匿名 namespace 成员）。

    单一定义点 —— 报表与 --check 共用，避免两处实现漂移。

    判定要点：
      * 匿名 namespace 不算一层（成员是文件级对象）
      * 按花括号深度而非列位置
      * 不限于 g_ 前缀：常量（kMaxPushHooks）、函数指针表（NoManagerDetourTable）、
        anchor 常量同样是有状态的迁移单元
      * 【必须处理跨行声明】：声明符可能在续行上，例如
            static unordered_map<...>
                g_pluginPushTargetConfigs;
            constexpr const char* kLuaSingletonPattern =
                "48 8B 05 ...";
        逐行匹配会漏掉这两个（实测漏扫导致 g_ 变量少计 1 个、常量少计 1 个）。
        做法：把"看起来是声明开头但本行未结束"的行与后续行拼起来再匹配，
        并记录起始行号。
    """
    vars_found = OrderedDict()
    depth = 0
    scope_kind = []
    i = 0
    n = len(clines)
    while i < n:
        stripped = clines[i].strip()
        eff = depth - sum(1 for k in scope_kind if k == "anon")
        if eff == 0 and stripped and not stripped.startswith("#") \
                and not re.match(r"^\}\s*;?\s*$", stripped) \
                and not re.match(r"^(using|typedef|namespace|struct|class|enum|"
                                 r"union|template|static_assert|extern\s+\"C\")\b",
                                 stripped):
            # 拼接续行：直到本行以【终结】定界符结束，或最多再吃 3 行。
            # 注意 '=' 单独结尾【不是】终结 —— `constexpr const char* k =`
            # 换行接字符串是常见写法（kLuaSingletonPattern L1579-1580）。
            joined = stripped
            j = i
            while j + 1 < n and (j - i) < 3:
                if re.search(r"[;{[]\s*$", joined) or joined.endswith(")") \
                        or re.search(r"=\s*\S", joined):
                    break
                j += 1
                joined += " " + clines[j].strip()
            m = re.match(r"^(?:static\s+|inline\s+|constexpr\s+|const\s+)*"
                         r"[A-Za-z_][\w:<>,\s\*&]*?[\s\*&](\w+)\s*"
                         r"(\[[^\]]*\]|=[^=]|\{|;)", joined)
            if m and "(" not in joined[:m.start(1)]:
                vars_found.setdefault(m.group(1), i + 1)
        # 深度更新：只按【本行】算，不涉续行（续行不含花括号定界）
        opener = "anon" if re.match(r"^\s*namespace\s*\{", stripped) else "other"
        for ch in stripped:
            if ch == "{":
                scope_kind.append(opener)
                opener = "other"
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
                if scope_kind:
                    scope_kind.pop()
        i += 1
    return vars_found


def check_document(clean, clines, funcs, raw_lines=None, klines=None):
    """核对 docs/REFACTOR_PLAN.md 里引用的数字是否与源码实测一致。

    存在理由：前两轮审查各算各的，分歧无法收敛。让审查者跑同一条命令，
    文档里每个可机检的数字（模块行数/函数数、变量总数、SEH 处数、
    日志锚点行号、未归属函数数）都能当场判定对错。

    raw_lines 是未剥离注释/字符串的原始行 —— 日志锚点的文本在字符串字面量里，
    在 clines 中已被抹成空格，必须用原始行匹配。
    """
    if raw_lines is None:
        raw_lines = clines
    doc_path = os.path.join(REPO, "docs", "REFACTOR_PLAN.md")
    if not os.path.exists(doc_path):
        print(f"找不到 {doc_path}")
        return 1
    doc = open(doc_path, encoding="utf-8").read()

    def owner_of(line_no):
        for name, s, e, cnt, q in funcs:
            if s <= line_no <= e:
                return name
        return "(顶层)"

    failures = []

    by_module = defaultdict(list)
    for name, s, e, cnt, q in funcs:
        mod = module_of(name, q)
        if mod:
            by_module[mod].append((name, s, e, cnt))

    def expect(label, actual, pattern):
        m = re.search(pattern, doc)
        if not m:
            failures.append(f"{label}: 文档里找不到该数字（实测 {actual}）")
            return
        if str(actual) != m.group(1):
            failures.append(f"{label}: 文档写 {m.group(1)}，实测 {actual}")

    # §2 汇总表：| `Mod.cpp` | 304 | 13 | 内容 |
    for mod in MODULES:
        items = by_module.get(mod, [])
        m = re.search(rf"\|\s*`{mod}\.cpp`[^|]*\|\s*(\d+)[^|]*\|\s*(\d+)\s*\|", doc)
        if not m:
            failures.append(f"{mod}: §2 汇总表里找不到该行（实测 {len(items)} 函数）")
            continue
        if int(m.group(1)) != sum(t[3] for t in items):
            failures.append(
                f"{mod} 行数: §2 表写 {m.group(1)}，实测 {sum(t[3] for t in items)}")
        if int(m.group(2)) != len(items):
            failures.append(f"{mod} 函数数: §2 表写 {m.group(2)}，实测 {len(items)}")

    # §3 逐模块清单标题：### 3.1 `Mod.cpp` — 13 函数 / 304 行
    for mod in MODULES:
        items = by_module.get(mod, [])
        m = re.search(rf"###\s*[\d.]*\s*`?{mod}\.cpp`?\s*[—-]+\s*(\d+) 函数 / (\d+) 行", doc)
        if not m:
            continue
        if int(m.group(1)) != len(items):
            failures.append(f"{mod}: §3 标题写 {m.group(1)} 函数，实测 {len(items)}")
        if int(m.group(2)) != sum(t[3] for t in items):
            failures.append(
                f"{mod}: §3 标题写 {m.group(2)} 行，实测 {sum(t[3] for t in items)}")

    # 变量总数：与报表共用同一个实现，避免两处口径漂移。
    # 【找不到锚点文本要报错，不能静默跳过】—— 否则文档改了措辞（"变量"→"对象"）
    # 就会让这条断言悄悄失效，check 反而变成假阳性。
    nvars = len(find_file_scope_objects(klines if klines is not None else clines))
    m = re.search(r"实测文件级(?:变量|对象)共 \*\*(\d+) 个\*\*", doc)
    if not m:
        failures.append(f"文件级变量总数: 文档里找不到统计句（实测 {nvars}）")
    elif int(m.group(1)) != nvars:
        failures.append(f"文件级变量总数: 文档写 {m.group(1)}，实测 {nvars}")

    # SEH：找不到锚点要报错（静默跳过 = 假阳性）
    for kw in ("__try", "__except", "__finally"):
        n = sum(1 for ln in clines if re.search(r"\b" + kw + r"\b", ln))
        m = re.search(rf"`{kw}`\s*\*{{0,2}}(\d+)", doc)
        if not m:
            failures.append(f"`{kw}`: 文档里找不到处数（实测 {n}）")
        elif int(m.group(1)) != n:
            failures.append(f"`{kw}`: 文档写 {m.group(1)}，实测 {n}")

    # 日志锚点：在【原始行】里找，clines 已把字符串字面量抹空。
    # 匹配用同一段子串（源码里找得到、文档里也照抄），避免"文档改个措辞就静默跳过"。
    # 必须覆盖文档 §8 列出的【全部】锚点 —— 少列一个，那条就永远不会被检出。
    for anchor in ("只读保护已验证", "installed hub stub",
                   "RegisterGlobalCapture: installed",
                   "RegisterScriptData: running",
                   "DisableGameCoreDomainSites: candidates",
                   "CleanupAllCaptureSites: unplugged",
                   "RemoveGameCoreDomainSiteRecords: reset",
                   "Plugin module freed after engine"):
        actual = None
        for i, ln in enumerate(raw_lines, 1):
            if anchor in ln:
                actual = i
                break
        if actual is None:
            failures.append(f"锚点 {anchor!r}: 源码里找不到该日志（脚本自身需更新）")
            continue
        m = re.search(rf"L(\d+)\s+[^\n]*{re.escape(anchor)}", doc)
        if not m:
            failures.append(f"锚点 {anchor!r}: 文档里找不到（实测 L{actual}）")
        elif int(m.group(1)) != actual:
            failures.append(f"锚点 {anchor!r}: 文档写 L{m.group(1)}，实测 L{actual}")

    # 全局陈旧数字扫描：模块行数一旦写进正文（阶段表、工作量表、结论段），
    # 就不止一处。定点断言只钉住了表格与标题，正文里的同一数字会漂移
    # （实测：ScriptBridge 1208→1213 时，§4/§10/§11 里另有 3 处没跟着改）。
    #
    # 只在"模块名紧跟 N 行"这种表述上判定（中间最多一个括号），避免把
    # "HookEngine 行数虚报 60%、日志锚点行号互换差 2666 行" 这类无关数字误判。
    # 对已存在的文件（Civ6MessageBus.cpp）比对其真实行数，其余比对分配行数。
    # §3 各模块表里的【每个函数】的行数与行号。
    # 这是最容易漂移的地方：函数一多，改一处口径（如把 template 前置行纳入 start）
    # 就会让整表的行数与行号集体失效，而定点断言只钉住了表头的合计。
    by_name = {f[0]: f for f in funcs}
    for m in re.finditer(r"\|\s*(\d+)\s*\|\s*`(\w+)`[^|]*\|\s*L(\d+)-(\d+)\s*\|", doc):
        cnt, name = int(m.group(1)), m.group(2)
        s, e = int(m.group(3)), int(m.group(4))
        f = by_name.get(name)
        if not f:
            failures.append(f"§3 表: 函数 {name} 在源码中不存在")
            continue
        if f[1] != s or f[2] != e:
            failures.append(f"§3 表 {name}: 文档写 L{s}-{e}，实测 L{f[1]}-{f[2]}")
        if f[3] != cnt:
            failures.append(f"§3 表 {name}: 文档写 {cnt} 行，实测 {f[3]}")

    # §4.1 跨模块调用图：文档那张表声称的边数必须与实测一致。
    # 这张表是 §4.2 环分析、§4.3 阶段顺序的依据 —— 边数错了，后面全错。
    # （实测踩过：PluginRegistry → HookLoaderApi 因正则不匹配限定调用而漏掉。）
    try:
        spec = importlib.util.spec_from_file_location(
            "sim", os.path.join(HERE, "simulate_split.py"))
        sim = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sim)
        all_moved = set(m for mods, _ in sim.PHASES for m in mods)
        edges = sim.cross_refs(clines, funcs, all_moved, DEFERRED)
        agg = defaultdict(set)
        for c, t in edges:
            ctu = (sim.PARENT if c.startswith(sim.PARENT)
                   else module_of(c) or sim.PARENT)
            ttu = module_of(t) or sim.PARENT
            if ctu != ttu and ctu != sim.PARENT and ttu != sim.PARENT:
                agg[(ctu, ttu)].add((c, t))
        for m in re.finditer(r"\|\s*(\w+)\s*→\s*(\w+)\s*\|\s*(\d+)\s*\|", doc):
            a, b, claimed = m.group(1), m.group(2), int(m.group(3))
            actual = len(agg.get((a, b), ()))
            if actual != claimed:
                line_no = doc[:m.start()].count("\n") + 1
                failures.append(
                    f"§4.1 边 {a}→{b}: 文档 L{line_no} 写 {claimed}，实测 {actual}")
    except Exception as e:                                  # noqa: BLE001
        failures.append(f"§4.1 边校验未能执行（模拟器不可用）：{e}")

    # §4.3 阶段表声称的"函数垫片"数。
    # 这是全计划唯一无法靠读代码判断的量（要靠模拟），也是最容易写反的
    # —— 作者已经比反过一次（把 ScriptBridge 先抽说成 2 个垫片）。
    try:
        spec = importlib.util.spec_from_file_location(
            "sim2", os.path.join(HERE, "simulate_split.py"))
        sim2 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sim2)
        moved = set()
        shims_by_phase = []
        for phase_no, (mods, _size) in enumerate(sim2.PHASES, 1):
            moved.update(mods)
            e2 = sim2.cross_refs(clines, funcs, moved, DEFERRED)
            # 阶段 3 起 TeardownWindow.h 已提供这些符号，不再是垫片
            # （与 simulate_split.py 的 SHARED_AT_PHASE3 保持同一口径）
            shared = sim2.SHARED_AT_PHASE3 if phase_no >= 3 else set()

            def tu(n, _m=frozenset(moved)):
                mm = module_of(n)
                return mm if mm in _m else sim2.PARENT

            out = set()
            for c, t in e2:
                if t in shared:
                    continue
                ctu = sim2.PARENT if c.startswith(sim2.PARENT) else tu(c)
                if ctu in mods and tu(t) == sim2.PARENT:
                    out.add(t)
            shims_by_phase.append(len(out))
        total_shims = sum(shims_by_phase)

        # 逐行校验 §4.3 表的"函数垫片"列。只校验总数不够 —— 总数对而某一行
        # 写错（例如把阶段 4 的 1 写到阶段 5、阶段 4 写 0）时总数仍可能是 1。
        #
        # 【必须先切出 §4.3 这一节再匹配】：文件里有多张以数字开头的五列表
        # （§3 的"行数 | 函数 | 行号"、§10 的工作量表），不限定范围会误报一片。
        sec = re.search(r"### 4\.3(.*?)\n### 4\.4", doc, re.S)
        if not sec:
            failures.append("§4.3: 找不到该节（无法校验逐阶段垫片列）")
        else:
            sec_start = doc[:sec.start(1)].count("\n") + 1
            for m in re.finditer(
                    r"^\|\s*(\d+)[ab]?\s*\|([^|]*)\|([^|]*)\|([^|]*)\|"
                    r"\s*\*{0,2}(\d+)\*{0,2}\s*\|",
                    sec.group(1), re.M):
                phase_no, claimed = int(m.group(1)), int(m.group(5))
                if not 1 <= phase_no <= len(shims_by_phase):
                    continue
                actual = shims_by_phase[phase_no - 1]
                if claimed != actual:
                    line_no = sec_start + sec.group(1)[:m.start()].count("\n")
                    failures.append(
                        f"§4.3 L{line_no} 阶段 {m.group(1)} 函数垫片: "
                        f"文档写 {claimed}，实测 {actual}")

        m = re.search(r"函数垫片全程只有\s*\*{0,2}(\d+)\*{0,2}\s*个", doc)
        if not m:
            failures.append(f"§4.3: 找不到\"函数垫片全程只有 N 个\"（实测 {total_shims}）")
        elif int(m.group(1)) != total_shims:
            failures.append(
                f"§4.3 函数垫片总数: 文档写 {m.group(1)}，实测 {total_shims}")
        # 备选顺序的垫片数（文档在对比表里给了这个数）
        moved = set()
        alt_shims = []
        for phase_no, (mods, _size) in enumerate(sim2.PHASES_ALT, 1):
            moved.update(mods)
            e2 = sim2.cross_refs(clines, funcs, moved, DEFERRED)
            shared = sim2.SHARED_AT_PHASE3 if phase_no >= 3 else set()

            def tu2(n, _m=frozenset(moved)):
                mm = module_of(n)
                return mm if mm in _m else sim2.PARENT

            out = set()
            for c, t in e2:
                if t in shared:
                    continue
                ctu = sim2.PARENT if c.startswith(sim2.PARENT) else tu2(c)
                if ctu in mods and tu2(t) == sim2.PARENT:
                    out.add(t)
            alt_shims.append(len(out))
        m = re.search(r"备选（`HookEngine` 先）\s*\|\s*\*\*(\d+)\*\*", doc)
        if m and int(m.group(1)) != sum(alt_shims):
            failures.append(
                f"§4.3 备选顺序垫片: 文档写 {m.group(1)}，实测 {sum(alt_shims)}")
    except Exception as e:                                  # noqa: BLE001
        failures.append(f"§4.3 垫片校验未能执行：{e!r}")

    # §4.4 的 static 清单：文档把"必须去掉 static"的函数分组列出，
    # 并在标题里给了总数。这个数靠人肉分组数出来极易错（缓迁 *Impl 的
    # 调用方算不算、限定调用算不算，都会左右结果）。
    # 按【阶段】算"每个 static 函数首次必须去 static 的时点"。
    #
    # 【这里曾经写错过】：旧实现把"调用方全是缓迁 *Impl"的函数归为"阶段 6 专属"，
    # 理由是"阶段 1-5 期间同处母体"。这个推理是错的 —— 缓迁指的是【被调方搬走了、
    # 而调用方（*Impl）留在母体】，两者从阶段 1 起就在不同 TU。
    # 例：ResolveByRvaImpl(母体) 调 ResolveByRvaCore(阶段1 进 SymbolResolve.cpp)
    #     → 阶段 1 就需要 ResolveByRvaCore 去 static。
    # 正确判据只看：被调方此刻是否已被移出母体、而调用方仍在母体。
    try:
        spec = importlib.util.spec_from_file_location(
            "sim3", os.path.join(HERE, "simulate_split.py"))
        sim3 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sim3)
        by = {f[0]: f for f in funcs}

        def is_static_fn(n):
            return bool(re.match(r"^\s*static\b", clines[by[n][1] - 1]))

        # 阶段 3 的 TeardownWindow.h 把 SetGameCoreTeardownWindow 搬进共享头。
        # 它不是"被别的模块调用后跨 TU"，而是【随窗口一起搬走并内联进头文件】——
        # 性质不同，单列一个阶段 3 条目（见下），故从逐阶段循环里排除。
        absorbed = set(sim3.SHARED_AT_PHASE3) - {"SetGameCoreTeardownWindow"}
        first_need = {}                      # 函数 -> 首次需要去 static 的阶段
        moved = set()
        for phase_no, (mods, _size) in enumerate(sim3.PHASES, 1):
            moved.update(mods)
            e3 = sim3.cross_refs(clines, funcs, moved, DEFERRED)
            for c, t in e3:
                if t in absorbed or t not in by or not is_static_fn(t):
                    continue
                ctu = (sim3.PARENT if c.startswith(sim3.PARENT)
                       else module_of(c) or sim3.PARENT)
                ttu = module_of(t) or sim3.PARENT
                if ctu != ttu:
                    first_need.setdefault(t, phase_no)
        # SetGameCoreTeardownWindow 在阶段 3 随 TeardownWindow.h 一起处理
        if is_static_fn("SetGameCoreTeardownWindow"):
            first_need["SetGameCoreTeardownWindow"] = 3

        # 文档 §4.4 的"按阶段去掉 static"表：逐行校验每阶段的函数个数与名单。
        for m in re.finditer(
                r"\|\s*(\d+)（[^）]*）\s*\|\s*([^|]+?)\s*\|\s*(\d+)\s*\|", doc):
            phase_no, names_cell, cnt = int(m.group(1)), m.group(2), int(m.group(3))
            if "`" not in names_cell:
                continue                     # 不是函数清单行（如表头/合计）
            names = set(re.findall(r"`(\w+)`", names_cell))
            actual = {t for t, p in first_need.items() if p == phase_no}
            if names != actual:
                miss = actual - names
                extra = names - actual
                detail = []
                if miss:
                    detail.append(f"漏 {sorted(miss)}")
                if extra:
                    detail.append(f"多 {sorted(extra)}")
                failures.append(
                    f"§4.4 阶段 {phase_no} 去 static 清单不符：{'；'.join(detail)}")
            if cnt != len(actual):
                failures.append(
                    f"§4.4 阶段 {phase_no} 数量: 文档写 {cnt}，实测 {len(actual)}")

        # 总数（文档写"合计 23"）
        m = re.search(r"\|\s*\|\s*\*\*合计\*\*\s*\|\s*\*\*(\d+)\*\*\s*\|", doc)
        if m and int(m.group(1)) != len(first_need):
            failures.append(
                f"§4.4 去 static 总数: 文档写 {m.group(1)}，实测 {len(first_need)}")
    except Exception as e:                                  # noqa: BLE001
        failures.append(f"§4.4 static 校验未能执行：{e!r}")

    # §4.1 表格里的"对数 / 调用点"两列。
    # 这两个数不同（一个 (调用方,被调) 对可能有多个调用点），必须分别校验 ——
    # 独立实现者用调用点口径算出 4，本文档用对数口径写 3，两者都对；
    # 不写清口径就会被认为是错的。
    try:
        spec = importlib.util.spec_from_file_location(
            "sim5", os.path.join(HERE, "simulate_split.py"))
        sim5 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sim5)
        all_moved = set(m for mods, _ in sim5.PHASES for m in mods)
        e5 = sim5.cross_refs(clines, funcs, all_moved, DEFERRED)
        pair_cnt = defaultdict(set)      # (a,b) -> {(caller,callee)}
        site_cnt = defaultdict(int)      # (a,b) -> 调用点数
        for c, t in e5:
            ctu = (sim5.PARENT if c.startswith(sim5.PARENT)
                   else module_of(c) or sim5.PARENT)
            ttu = module_of(t) or sim5.PARENT
            if ctu == ttu or ctu == sim5.PARENT or ttu == sim5.PARENT:
                continue
            pair_cnt[(ctu, ttu)].add((c, t))
        # 调用点数：重新逐函数体数匹配次数（cross_refs 已去重，这里另算）
        for name, s, e, _c, _q in funcs:
            body = "\n".join(clines[s - 1:e])
            ctu = module_of(name) or sim5.PARENT
            for tgt in {tt for _, tt in e5}:
                ttu = module_of(tgt) or sim5.PARENT
                if ctu == ttu or ctu == sim5.PARENT or ttu == sim5.PARENT:
                    continue
                n = len(re.findall(
                    r"(?<![\w])&?(?:[\w:]*::)?" + re.escape(tgt)
                    + r"\s*[\(,;\)]", body))
                if n:
                    site_cnt[(ctu, ttu)] += n
        for m in re.finditer(
                r"\|\s*(\w+)\s*→\s*(\w+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", doc):
            a, b = m.group(1), m.group(2)
            pc, sc = int(m.group(3)), int(m.group(4))
            line_no = doc[:m.start()].count("\n") + 1
            ap = len(pair_cnt.get((a, b), ()))
            asc = site_cnt.get((a, b), 0)
            if ap != pc:
                failures.append(
                    f"§4.1 L{line_no} {a}→{b} 对数: 文档写 {pc}，实测 {ap}")
            if asc != sc:
                failures.append(
                    f"§4.1 L{line_no} {a}→{b} 调用点: 文档写 {sc}，实测 {asc}")
    except Exception as e:                                  # noqa: BLE001
        failures.append(f"§4.1 对数/调用点校验未能执行：{e!r}")

    # §6 表里的几个"被 N 个函数使用"计数。它们散在正文里、没有表格锚点，
    # 人工核对时最容易想当然（实测 HKS_GUARD 是 36 个 Lua*Impl 用，不是 44）。
    lua_pat = re.compile(r"^Lua\w*Impl$")
    all_lua = [f[0] for f in funcs if lua_pat.match(f[0])]
    guard_users = [n for n, s, e, _c, _q in funcs
                   if re.search(r"HKS_GUARD", "\n".join(clines[s - 1:e]))]
    m = re.search(r"实测被 \*\*(\d+) 个\*\* `Lua\*Impl` 使用", doc)
    if m and int(m.group(1)) != len(guard_users):
        failures.append(
            f"§6 HKS_GUARD 使用数: 文档写 {m.group(1)}，实测 {len(guard_users)}")
    m = re.search(r"全文件共 (\d+) 个 `Lua\*Impl`", doc)
    if m and int(m.group(1)) != len(all_lua):
        failures.append(
            f"§6 Lua*Impl 总数: 文档写 {m.group(1)}，实测 {len(all_lua)}")

    # §4.3 的变量交互数：方向 A（外向）与方向 B（被带走）。
    # 前一版只统计了方向 A，把工作量低估了近一半 —— 故两个方向都钉住。
    try:
        spec = importlib.util.spec_from_file_location(
            "sim4", os.path.join(HERE, "simulate_split.py"))
        sim4 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sim4)
        vf = find_file_scope_objects(klines if klines is not None else clines)
        moved = set()
        a_total = b_total = 0
        for mods, _size in sim4.PHASES:
            moved.update(mods)
            a_total += len(sim4.var_outward_needs(
                clines, funcs, vf, mods[0], moved, DEFERRED))
            cr = sim4.var_cross_refs(clines, funcs, vf, moved, DEFERRED)
            b_total += len({v for v in cr
                            if sim4.var_module(v, vf[v], funcs, DEFERRED,
                                               clines)[0] in mods})
        for pat, actual, label in (
                (r"方向 A[^\n]*合计 \*\*(\d+)\*\*", a_total, "方向 A（外向）"),
                (r"方向 B[^\n]*合计 \*\*(\d+)\*\*", b_total, "方向 B（被带走）"),
                (r"合计 \d+ \+ \d+ = (\d+) 处变量交互", a_total + b_total,
                 "变量交互总数")):
            m = re.search(pat, doc)
            if not m:
                failures.append(f"§4.3: 找不到{label}（实测 {actual}）")
            elif int(m.group(1)) != actual:
                failures.append(f"§4.3 {label}: 文档写 {m.group(1)}，实测 {actual}")
    except Exception as e:                                  # noqa: BLE001
        failures.append(f"§4.3 变量交互校验未能执行：{e!r}")

    # 缓迁与未归属：文档 §2 表必须钉住这两个数。
    # 【不能只在报表里打印】—— 报表是给人看的，没人核对就等于没检查。
    deferred = [f for f in funcs if f[0] in DEFERRED]
    unassigned = [f for f in funcs
                  if not module_of(f[0]) and f[0] not in DEFERRED]
    # 锚点用较宽松的 "计划内缓迁" + 表行格式，不写死小节号 ——
    # 否则改一次交叉引用（§4 -> §4.5）就让断言失效。
    m = re.search(r"计划内缓迁[^|\n]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", doc)
    if not m:
        failures.append(f"计划内缓迁: 文档 §2 表里找不到该行（实测 "
                        f"{len(deferred)} 函数 / {sum(t[3] for t in deferred)} 行）")
    else:
        if int(m.group(1)) != sum(t[3] for t in deferred):
            failures.append(f"缓迁行数: 文档写 {m.group(1)}，实测 "
                            f"{sum(t[3] for t in deferred)}")
        if int(m.group(2)) != len(deferred):
            failures.append(f"缓迁函数数: 文档写 {m.group(2)}，实测 {len(deferred)}")
    # "未归属 0 个"是本次拆分最重要的健康指标（说明每个函数都定了去处）
    m = re.search(r"未归属（需人工裁定）\s*\|\s*(\d+)\s*\|", doc)
    if not m:
        failures.append(f"未归属函数数: 文档 §2 表里找不到该行（实测 {len(unassigned)}）")
    elif int(m.group(1)) != len(unassigned):
        failures.append(f"未归属函数数: 文档写 {m.group(1)}，实测 {len(unassigned)}")

    if failures:
        print(f"✗ 文档与源码不一致（{len(failures)} 处）：")
        for f in failures:
            print(f"    {f}")
        return 1
    print("✓ 文档引用的数字与源码实测一致")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--section", default=None,
                    help="只输出指定小节（如 3 = §3 模块清单、8 = §8 日志锚点）。"
                         "本参数此前【只被解析、从未生效】—— 文档曾把它写成核对 §3 的"
                         "方法，实际输出与不带参数逐字节相同。现按标题里的小节号过滤。")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    src = open(TARGET, encoding="utf-8", errors="replace").read()
    clean = strip_comments_and_strings(src)
    lines = src.split("\n")
    clines = clean.split("\n")
    # 文件级对象检测专用：保留字符串内容。否则跨行声明里以字符串开头的续行
    # 会被抹成空行，声明拼接断在那里（kLuaSingletonPattern L1579-1580 就是这样漏的）。
    klines = strip_comments_and_strings(src, keep_strings=True).split("\n")

    funcs = find_functions(clean)

    if args.check:
        # 【--check 只对"拆分前"的原文件成立】：它校验的是 REFACTOR_PLAN.md §3/§4
        # 里按原文件行号记录的数据。一旦开始拆分，函数被搬走、行号全部平移，
        # 这些断言必然失败 —— 那是预期噪声，不是回归。
        # 拆分期间判断"搬得对不对"要用别的判据（函数体逐字节比对 + 编译 + 日志指纹）。
        # 若原文件已被拆分，先说明再跑，避免把噪声当信号。
        if not os.path.exists(os.path.join(HERE, "baseline",
                                           "Civ6DLLHookLoaderAPI.original.cpp")):
            sys.stderr.write(
                "注意：--check 校验的是【拆分前原文件】的行号数据。\n"
                "      当前母体若已被拆分，行号已平移，本命令的失败是预期噪声。\n"
                "      拆分期间请用别的判据：函数体逐字节比对 + 编译 + 日志指纹。\n\n")
        sys.exit(check_document(clean, clines, funcs, lines, klines))

    # --section N：把报表输出捕获下来，只保留匹配小节号的那几段。
    # 报表由 48 处 print 拼成，逐个加条件易漏；这里统一在出口过滤。
    # 段落以 "===...===" 后的 "§N 标题" 行为界，取到下一个界为止。
    if args.section is not None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            report(clean, clines, klines, lines, funcs)
        text = buf.getvalue()
        want = str(args.section)
        out, keep = [], False
        for ln in text.split("\n"):
            m = re.match(r"^§(\d+)\b", ln)
            if m:
                keep = (m.group(1) == want)
            if keep:
                out.append(ln)
        sys.stdout.write("\n".join(out) + "\n")
        if not out:
            sys.stderr.write(f"--section {want}：报表里没有该小节\n")
            sys.exit(1)
        sys.exit(0)

    report(clean, clines, klines, lines, funcs)


def report(clean, clines, klines, lines, funcs):
    print(f"文件: {TARGET}")
    print(f"总行数: {len(lines)}   顶层函数定义: {len(funcs)}")
    print()

    # ---- 模块归属与行数 ----
    by_module = defaultdict(list)
    unassigned = []
    deferred = []
    for name, s, e, cnt, q in funcs:
        mod = module_of(name, q)
        if mod:
            by_module[mod].append((name, s, e, cnt))
        elif name in DEFERRED:
            deferred.append((name, s, e, cnt))
        else:
            unassigned.append((name, s, e, cnt))

    print("=" * 96)
    print("§3 各模块函数清单（行数 = 闭区间 end-start+1，按函数体括号配对实测）")
    print("=" * 96)
    total_assigned = 0
    for mod in MODULES:
        items = sorted(by_module.get(mod, []), key=lambda t: -t[3])
        ssum = sum(t[3] for t in items)
        total_assigned += ssum
        print(f"\n### {mod}  —  {len(items)} 个函数, {ssum} 行")
        for name, s, e, cnt in items:
            print(f"    {cnt:>4}  L{s}-{e}  {name}")
    print()
    print(f"已归属合计: {total_assigned} 行")
    dsum = sum(t[3] for t in deferred)
    print(f"计划内缓迁（调 C，待阶段 3 后归位）: {len(deferred)} 个函数, {dsum} 行")
    for name, s, e, cnt in sorted(deferred, key=lambda t: -t[3]):
        print(f"    {cnt:>4}  L{s}-{e}  {name}")
    print(f"未归属（需人工裁定）: {len(unassigned)} 个函数")
    for name, s, e, cnt in sorted(unassigned, key=lambda t: -t[3]):
        print(f"    {cnt:>4}  L{s}-{e}  {name}")
    print()

    # ---- 文件级变量 ----
    # 判定逻辑见 find_file_scope_objects()（与 --check 共用同一实现）。
    print("=" * 96)
    print("§5 文件级对象（函数/类型外，含匿名 namespace 成员）")
    print("=" * 96)
    vars_found = find_file_scope_objects(klines)
    gvars = [v for v in vars_found if v.startswith("g_")]
    print(f"共 {len(vars_found)} 个（g_ 前缀 {len(gvars)} 个，其余为常量/表）：")
    for name, ln in vars_found.items():
        print(f"    L{ln:<5} {name}")
    print()

    # ---- 每个变量的引用者（用于归属判断）----
    print("=" * 96)
    print("§5 变量引用分布（按所属函数，剥离注释后统计）")
    print("=" * 96)
    def owner_of(line_no):
        for name, s, e, cnt, q in funcs:
            if s <= line_no <= e:
                return name
        return "(顶层)"

    for v in vars_found:
        pat = re.compile(r"\b" + v + r"\b")
        refs = [i for i, ln in enumerate(clines, 1) if pat.search(ln)]
        owners = defaultdict(int)
        for r in refs:
            owners[owner_of(r)] += 1
        mods = defaultdict(int)
        for o, c in owners.items():
            # 缓迁函数【不是"未归属"】：它们已定去处（阶段 3 后进 SymbolResolve），
            # 只是暂时留在母体。混进"未归属"会虚高跨模块依赖数，干扰判断
            # （例如 g_pluginLifecycleMutex 的 6 处"未归属"里 5 处其实来自它们）。
            if o in DEFERRED:
                mods["SymbolResolve(缓迁)"] += c
            else:
                mods[module_of(o) or "(未归属)"] += c
        tag = "  <== 跨模块" if len([m for m in mods if m != "(未归属)"]) > 1 else ""
        print(f"  {v}  ({len(refs)} 处){tag}")
        for m, c in sorted(mods.items(), key=lambda t: -t[1]):
            print(f"      {c:>3}x  {m}")
    print()

    # ---- __try / __except / __finally ----
    print("=" * 96)
    print("§7 SEH 原语（剥离注释后统计）")
    print("=" * 96)
    for kw in ("__try", "__except", "__finally"):
        pat = re.compile(r"\b" + kw + r"\b")
        hits = [i for i, ln in enumerate(clines, 1) if pat.search(ln)]
        print(f"  {kw}: {len(hits)} 处")
        if kw == "__try":
            # 逐条列出，不合并同一函数内的多个 __try —— 文档要的是完整清单
            for h in hits:
                print(f"      L{h:<5} {owner_of(h)}")
    print()

    # ---- static 声明 ----
    # 必须区分【函数内 static】（拆分时误分两份会改变日志指纹，是真正的隐藏耦合）
    # 与【结构体成员的 static constexpr】（随结构体一起搬，拆分无影响）。
    # 首版脚本把 struct HookSite::kGuardBytes 也列成"函数内 static"，是错的。
    # 只列函数内 static 与类型成员 static —— 文件级 static 全局已由 §5 变量表覆盖。
    print("=" * 96)
    print("§6 static 声明（仅列函数内 static 与类型成员）")
    print("=" * 96)
    types_found = find_type_scopes(clean)
    for i, ln in enumerate(clines, 1):
        if not re.search(r"\bstatic\b", ln):
            continue
        m = re.search(r"\bstatic\s+(?:constexpr\s+)?[\w:<>, ]*?\b(\w+)\s*(?:=|;|\[|\{)", ln)
        if not m:
            continue
        nm = m.group(1)
        fn = owner_of(i)
        if fn != "(顶层)":
            print(f"  L{i:<5} {nm:<14} 【函数内 static】 in {fn}")
        else:
            ty = type_scope_of(types_found, i)
            if ty:
                print(f"  L{i:<5} {nm:<14} 【类型成员】 in struct {ty}")
    print()

    # ---- 匿名 namespace ----
    # 用花括号深度配对，而不是匹配 "}  // namespace" 注释 —— 后者会漏掉
    # 没有注释收尾的那个（L3360-3365 的 anchor 常量块，收尾就是裸 '}'）。
    print("=" * 96)
    print("§6 匿名 namespace（花括号配对，非注释匹配）")
    print("=" * 96)
    depth = 0
    open_at = None
    for i, ln in enumerate(clines, 1):
        if depth == 0 and re.match(r"^\s*namespace\s*\{", ln):
            open_at = i
        for ch in ln:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and open_at is not None:
                    body = "\n".join(clines[open_at:i])
                    members = re.findall(r"\b(g_\w+|\w+)\s*(?:=|;|\[)", body)
                    print(f"  L{open_at}-{i}  ({i - open_at + 1} 行)")
                    open_at = None
    print()

    # ---- _ReturnAddress 使用点 ----
    print("=" * 96)
    print("§6 _ReturnAddress 与 pragma intrinsic（鉴权敏感点）")
    print("=" * 96)
    for i, ln in enumerate(clines, 1):
        if "_ReturnAddress" in ln:
            kind = "pragma" if "pragma" in ln else "使用"
            print(f"  L{i:<5} [{kind}] in {owner_of(i)}")
    print()

    # ---- 日志锚点 ----
    print("=" * 96)
    print("§8 日志锚点（原文与行号，供文档直接引用）")
    print("=" * 96)
    anchors = [
        "只读保护已验证",
        "installed hub stub",
        "RegisterGlobalCapture: installed",
        "RegisterScriptData: running",
        "DisableGameCoreDomainSites: candidates",
        "CleanupAllCaptureSites: unplugged",
        "RemoveGameCoreDomainSiteRecords: reset",
        "Plugin module freed after engine",
    ]
    for a in anchors:
        for i, ln in enumerate(lines, 1):
            if a in ln:
                print(f"  L{i:<5} {ln.strip()[:96]}")
                break
        else:
            print(f"  ?????  未找到: {a}")
    print()

    # ---- 依赖矩阵 ----
    print("=" * 96)
    print("§5 各模块的外部依赖（只统计归属到该模块的函数体内）")
    print("=" * 96)
    for mod in MODULES:
        items = by_module.get(mod, [])
        agg = defaultdict(int)
        for name, s, e, cnt in items:
            body = "\n".join(clines[s - 1:e])
            for dep, pat in DEP_TOKENS.items():
                agg[dep] += len(re.findall(pat, body))
        live = {k: v for k, v in agg.items() if v}
        print(f"  {mod:<18} " + (", ".join(f"{k}:{v}" for k, v in
              sorted(live.items(), key=lambda t: -t[1])) or "(无)"))
    print()

    # ---- 常量跨模块使用 ----
    # 只报【真的跨模块】的：定义处若在顶层（母体），它本来就不属于任何模块，
    # 拆分时随使用方一起搬即可，不是耦合。首版把定义处也算成 "(未归属)" 模块，
    # 导致每个常量都被误标成"跨模块"。
    print("=" * 96)
    print("§6 常量使用范围（跨 2 个以上模块才需进内部头）")
    print("=" * 96)
    for cname in ("kHookPrologueWindow", "kMaxPushHooks", "kMinHookTargetSpan",
                  "kGuardBytes", "kAnchorDx11SizeOfImage"):
        pat = re.compile(r"\b" + cname + r"\b")
        hits = [i for i, ln in enumerate(clines, 1) if pat.search(ln)]
        if not hits:
            print(f"  {cname}: 本文件未出现")
            continue
        defs = [h for h in hits if owner_of(h) == "(顶层)"]
        uses = [h for h in hits if owner_of(h) != "(顶层)"]
        mods = sorted({module_of(owner_of(h)) or "(未归属)" for h in uses})
        where = f"定义 L{defs[0]}" if defs else "定义在别处"
        tag = "  <== 跨模块" if len(mods) > 1 else ""
        print(f"  {cname}: {where}, 使用 {len(uses)} 处, 模块={mods}{tag}")


if __name__ == "__main__":
    main()
