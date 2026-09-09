# Civ6DllLoader

Civilization VI DLL hook loader: thin GameCore shell + versioned runtime + HookAPI.

This repository contains **loader infrastructure only**. Plugin examples live in a separate repo (`Civ6DllLoader-Examples`).

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

Candidates still come from enabled mods and the loader's local scan locations.
The metadata identifies the package format; it is not a publisher signature.
Only distribute runtime DLLs from sources you trust.
