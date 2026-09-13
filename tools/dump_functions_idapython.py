#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# dump_functions_idapython.py
#
# 在 IDA 里运行（File -> Script file...），导出全部函数：
#   raw_name <TAB> demangled <TAB> start_hex <TAB> size_hex <TAB> segment
#
# - raw_name  : IDB 里存的名字（C++ 就是 mangled ?...，sub_/自动名就是原名）
# - demangled : IDA 自己的 demangler（和函数窗口显示一致）
#               IDA 为去重加的后缀 _ / _N 会让 demangler 失败，
#               脚本会自动去掉后缀重试；解不出来就保留 raw
# - start/size: 十六进制
#
# 输出：<idb_path>.funcs.txt

import re
import idautils
import idc
import ida_name
import idaapi

try:
    _get_inf_attr = idaapi.get_inf_attr
    _INF_SHORT_DN = idaapi.INF_SHORT_DN
except Exception:
    _get_inf_attr = None
    _INF_SHORT_DN = None


def _short_flag():
    if _get_inf_attr is not None and _INF_SHORT_DN is not None:
        try:
            return _get_inf_attr(_INF_SHORT_DN)
        except Exception:
            return 0
    return 0


def _try_demangle(name):
    short = _short_flag()
    dem = None
    try:
        dem = ida_name.demangle_name(name, short)
    except Exception:
        dem = None
    if not dem:
        try:
            dem = idc.demangle_name(name, short)
        except Exception:
            dem = None
    return dem


def demangle(name):
    dem = _try_demangle(name)
    if dem and dem != name:
        return dem
    # IDA 去重后缀 _ / _N 会导致 demangle 失败，去掉后重试
    if name.startswith("?"):
        base = name
        while True:
            m = re.search(r"_\d+$", base)
            if m:
                base = base[:m.start()]
            elif base.endswith("_"):
                base = base[:-1]
            else:
                break
            dem = _try_demangle(base)
            if dem and dem != base:
                return dem
    return name


def main():
    idb = idc.get_idb_path()
    out_path = idb + ".funcs.txt"

    lines = []
    for ea in idautils.Functions():
        raw = idc.get_func_name(ea)
        if not raw:
            continue
        dem = demangle(raw)
        try:
            end = idc.get_func_attr(ea, idc.FUNCATTR_END)
        except Exception:
            end = ea
        size = end - ea if end and end > ea else 0
        seg = idc.get_segm_name(ea)
        lines.append("%s\t%s\t%X\t%X\t%s" % (raw, dem, ea, size, seg))

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("functions: %d" % len(lines))
    print("written: %s" % out_path)


if __name__ == "__main__":
    main()
