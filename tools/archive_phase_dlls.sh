#!/usr/bin/env bash
# archive_phase_dlls.sh — 为每个拆分阶段构建并归档 DLL，供出问题时二分定位。
#
# 为什么需要：拆分是 6 个阶段 7 次提交，最后一次性验证。若实机出问题，
# 需要能单独部署某个中间态来缩小范围 —— 这要求每个中间态都有一份构建产物。
#
# 做法：git stash 当前改动 -> 逐个 checkout 阶段提交 -> 构建 -> 拷贝产物 -> 回到 HEAD。
# 每个产物存为 tools/baseline/dlls/<序号>_<阶段名>_<commit>.dll。
#
# 用法：bash tools/archive_phase_dlls.sh
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="$PWD"
OUT="$REPO/tools/baseline/dlls"
MSBUILD="/e/VisualStudio/Products/MSBuild/Current/Bin/MSBuild.exe"
mkdir -p "$OUT"

# 阶段提交（按时间顺序）
PHASES=(
  "00_基线_03b6a0a"
  "01_SymbolResolve_e468e04"
  "02_PluginDomain_4e311b6"
  "03a_TeardownWindow_8d6e00e"
  "03b_MessageBus_e7c02b7"
  "04_ScriptBridge_065a77a"
  "05_HookEngine_dce1d9b"
  "06_PluginRegistry_ed31892"
)

START=$(git rev-parse --abbrev-ref HEAD)
echo "起始分支：$START"
echo "当前工作区是否干净：$(git status --porcelain | wc -l) 个改动"

for entry in "${PHASES[@]}"; do
  name="${entry%_*}"
  sha="${entry##*_}"
  echo
  echo "=== $name ($sha) ==="
  git checkout -q "$sha" -- . 2>/dev/null || git checkout -q "$sha"
  "$MSBUILD" DllLoader.sln -p:Configuration=Release -p:Platform=x64 \
      -m -v:q -nologo -t:Rebuild > "/tmp/build_$name.log" 2>&1 || {
    echo "  ✗ 构建失败，见 /tmp/build_$name.log"; continue; }
  cp "$REPO/x64/Release/Civ6DllLoader.runtime.dll" "$OUT/${name}.dll"
  echo "  ✓ $(stat -c%s "$OUT/${name}.dll") 字节  md5=$(md5sum "$OUT/${name}.dll" | cut -c1-12)"
done

echo
echo "回到 $START"
git checkout -q "$START"
echo "归档完成："
ls -la "$OUT"
