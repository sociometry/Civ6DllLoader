# Civ6DllLoader

Civilization VI DLL hook loader: thin GameCore shell + versioned runtime + HookAPI.

This repository contains **loader infrastructure only**. Plugin examples live in a separate repo (`Civ6DllLoader-Examples`).

## 代码阅读与审查

- [代码阅读指南](docs/CODE_READING_GUIDE.md)：按启动、生命周期、Hook、地址解析和发布流程精读，附源码导航与所有权说明。
- [2026-09-18 代码审查报告](docs/CODE_REVIEW_2026-09-18.md)：已复现缺陷、静态发现、旧文档差异、构建结果和待验证清单。
- [既有架构文档](docs/ARCHITECTURE.md)：保留作背景参考；与当前实现不一致的部分已在审查报告中列出。

审查针对该日期的工作区快照（含当时的暂存修改），不表示后续版本已修复所列问题。

## Layout

```text
common/              HookAPI, ModScan, LoaderProtocol
DllLoader/           Thin shell (GameCore_XP2_Shell_FinalRelease.dll)
DllLoaderRuntime/    Runtime + HookAPI implementation
third_party/sqlite/  Bundled SQLite used by shell/runtime
tools/               Symbol DB packing and maintained aliases
DllLoader.sln        Shell + Runtime projects only
```

## Build

Open `DllLoader.sln` in Visual Studio (x64 | Release).

Outputs (typical):

- `x64\Release\GameCore_XP2_Shell_FinalRelease.dll`
- `x64\Release\Civ6DllLoader.runtime.dll`

Copy both into a Workshop mod under `Binaries\Win64\`.

Runtime candidates carry static version metadata (RCDATA 105). Installation and
updates read this resource without executing candidate DLL entry points or exports.
Rebuild both shell and runtime after this change: older runtimes without the
resource are skipped. Version numbers remain defined in `common/LoaderVersion.h`.

Candidates come from the scan roots (game root, Documents Mods, Workshop) and the
loader's own directory. The installer/updater does **not** filter by mod-enabled state
(plugin loading still does). The metadata identifies the package format; it is not a
publisher signature, and `ProbeVersion` only checks PE + RC 105 - so only distribute
runtime DLLs from sources you trust.
