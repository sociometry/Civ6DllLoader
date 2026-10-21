#!/usr/bin/env python3
"""package_release.py - 打包 Civ6DllLoader 的 Release 发布物。

为什么放在项目根目录并纳入版本控制：发布包的内容清单本身就是需要被评审、
被追溯的东西。散在本地的一次性脚本过两周就没人记得该带哪几个文件了。

用法（在仓库根目录执行）：
    python package_release.py                  # 打当前版本
    python package_release.py --version 1.0.1  # 覆盖版本号
    python package_release.py --no-build       # 跳过构建，直接用现有产物

交付物（与 docs/ARCHITECTURE.md §8 的工程清单一致）：
    Shell      GameCore_XP2_Shell_FinalRelease.dll   首次安装用的薄壳
    Runtime    Civ6DllLoader.runtime.dll             真正的 Loader
    SDK        common/HookAPI.h                      插件 ABI 头
    Tool       tools/rva_to_symbol.exe               RVA -> 符号名
    docs       docs/ARCHITECTURE.md

产物落在 dist/ 下：Civ6DllLoader-<ver>.zip
Mods 侧有自己独立的打包脚本（Civ6DllMods/package_release.py）。

设计取舍：
  * 默认先构建：直接拿 x64/Release 里的旧产物去打包，最容易发生"代码改了、
    包里还是上一版"。--no-build 只在明确知道产物是最新时用。
  * 缺文件直接失败，不跳过：发布包少一个 DLL 是最难在事后发现的问题
    （用户装完才发现某个功能没了）。宁可构建阶段就报错。
  * zip 里不带 pdb：pdb 十几 MB 且是调试用。需要排查崩溃时另加 --with-pdb。
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

# Windows 控制台默认可能是 GBK；脚本输出里有中文，统一成 UTF-8 避免乱码。
# errors=replace 兜底：老终端不支持 UTF-8 时宁可显示问号，也不要抛异常中断打包。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

LOADER_SLN = "DllLoader.sln"

# msbuild 的位置不写死：优先 PATH，其次常见 VS 安装目录。--msbuild 可覆盖。
MSBUILD_CANDIDATES = [
    "msbuild",
    r"E:\VisualStudio\Products\MSBuild\Current\Bin\MSBuild.exe",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe",
]


def find_msbuild(explicit):
    if explicit:
        return explicit if Path(explicit).is_file() or shutil.which(explicit) else None
    for cand in MSBUILD_CANDIDATES:
        if Path(cand).is_file():
            return cand
        found = shutil.which(cand)
        if found:
            return found
    return None


def run_build(repo, msbuild):
    """跑一次 Release|x64 构建。True = 成功。"""
    if msbuild is None:
        print("[错误] 找不到 msbuild，无法构建。")
        print("       用 --msbuild <路径> 指定，或加 --no-build 直接打包现有产物。")
        return False
    sln = repo / LOADER_SLN
    if not sln.is_file():
        print("[错误] 找不到 " + str(sln))
        return False
    cmd = [msbuild, str(sln), "/t:Build",
           "/p:Configuration=Release", "/p:Platform=x64",
           "/v:minimal", "/nologo"]
    print("[构建] " + str(sln))
    rc = subprocess.run(cmd, cwd=str(repo)).returncode
    if rc != 0:
        print("[错误] 构建失败, exit=" + str(rc))
        return False
    return True


def collect(repo, with_pdb):
    out = repo / "x64" / "Release"
    items = [
        (out / "GameCore_XP2_Shell_FinalRelease.dll",
         "Binaries/Win64/GameCore_XP2_Shell_FinalRelease.dll"),
        (out / "Civ6DllLoader.runtime.dll",
         "Binaries/Win64/Civ6DllLoader.runtime.dll"),
        (repo / "common" / "HookAPI.h", "SDK/HookAPI.h"),
        (repo / "tools" / "rva_to_symbol.exe", "Tools/rva_to_symbol.exe"),
        (repo / "docs" / "ARCHITECTURE.md", "docs/ARCHITECTURE.md"),
    ]
    if with_pdb:
        items.append((out / "GameCore_XP2_Shell_FinalRelease.pdb",
                      "Binaries/Win64/GameCore_XP2_Shell_FinalRelease.pdb"))
        items.append((out / "Civ6DllLoader.runtime.pdb",
                      "Binaries/Win64/Civ6DllLoader.runtime.pdb"))
    return items


def check(items):
    """逐个确认源文件存在。缺一个就整体失败。"""
    missing = [(s, d) for s, d in items if not s.is_file()]
    if not missing:
        return True
    print("[错误] 缺少以下产物：")
    for s, d in missing:
        print("       " + str(s) + "   -> " + d)
    return False


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_zip(zip_path, items, extra_text=None):
    """打 zip 并写 SHA256SUMS.txt。返回包内文件数。"""
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for src, arc in items:
            zf.write(src, arc)
            lines.append(sha256(src) + "  " + arc)
        for arc, text in (extra_text or {}).items():
            data = text.encode("utf-8")
            zf.writestr(arc, data)
            lines.append(hashlib.sha256(data).hexdigest() + "  " + arc)
        zf.writestr("SHA256SUMS.txt", "\n".join(lines) + "\n")
    return len(lines)


README = """# Civ6DllLoader {version}

Civ6 的 DLL 插件加载器。以 version.dll 代理的形态注入游戏进程，按
Global / GameCore 两个阶段加载插件，并提供主菜单设置面板。

## 目录

    Binaries/Win64/GameCore_XP2_Shell_FinalRelease.dll   首次安装用的薄壳
    Binaries/Win64/Civ6DllLoader.runtime.dll             真正的 Loader
    SDK/HookAPI.h                                        插件 ABI 头（必须用这份）
    Tools/rva_to_symbol.exe                              RVA -> 符号名查表
    docs/ARCHITECTURE.md                                 架构与实现细节

## 安装

把这两个 DLL 放到 Mod 的 Binaries/Win64/ 下，并让 Mod 的 Config.sql 把
DllPrefix 改写为 GameCore_XP2_Shell。薄壳会在 Loader 缺席时自动完成
version.dll 的补装，装完提示重启。细节见 docs/ARCHITECTURE.md。

## 注意

- 改完设置要重启：ENABLE_GLOBAL 只影响下次启动，ENABLE_GAMECORE 影响下一局。
- 设置面板在主菜单右上角齿轮里，开关存在 <exe目录>/Civ6DllLoader/config.ini。
- config.ini 里缺失的键会在启动时按默认值自动补上，已有键的值不会被改动。

## 插件开发

用 SDK/HookAPI.h 编写插件，产物放进 Mod 的 Binaries/Win64/Plugins/ 下的
完整规范见 Civ6DllMods 仓库的 docs/PLUGIN_GUIDE.md。
"""


def main():
    ap = argparse.ArgumentParser(description="打包 Civ6DllLoader 发布物")
    ap.add_argument("--version", default="1.0", help="版本号，默认 1.0")
    ap.add_argument("--no-build", action="store_true", help="跳过构建")
    ap.add_argument("--with-pdb", action="store_true", help="把 pdb 也打进包")
    ap.add_argument("--msbuild", default=None, help="msbuild 路径（默认自动探测）")
    ap.add_argument("--outdir", default="dist", help="输出目录，默认 dist/")
    args = ap.parse_args()

    repo = Path(__file__).resolve().parent
    outdir = (repo / args.outdir).resolve()
    version = args.version

    print("版本  : " + version)
    print("仓库  : " + str(repo))
    print("输出  : " + str(outdir))
    print()

    if not args.no_build:
        if not run_build(repo, find_msbuild(args.msbuild)):
            return 1
        print()

    items = collect(repo, args.with_pdb)
    if not check(items):
        return 1

    zip_path = outdir / ("Civ6DllLoader-" + version + ".zip")
    n = write_zip(zip_path, items, {"README.md": README.format(version=version)})
    print("[完成] " + zip_path.name + "  " + str(n) + " 项, " +
          format(zip_path.stat().st_size, ",") + " 字节")
    print()
    print("下一步：打 tag 并上传这个 zip 到 Release。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
