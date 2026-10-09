# Civ6DllLoader

Civilization VI DLL hook loader: thin GameCore shell + versioned runtime + HookAPI.

This repository contains **loader infrastructure only**. Plugin examples live in a separate repo (`Civ6DllLoader-Examples`).

## Layout

```text
common/              HookAPI, ModScan, LoaderProtocol
DllLoader/           Thin shell (GameCore_XP2_Shell_FinalRelease.dll)
DllLoaderRuntime/    Runtime + HookAPI implementation
third_party/sqlite/  Bundled SQLite for the enabled-mod filter (runtime; the shell
                     just links the same TU via ModScan)
tools/               Symbol DB packing and maintained aliases
DllLoader.sln        Shell + Runtime projects only
```

## Build

Open `DllLoader.sln` in Visual Studio (x64 | Release).

Outputs (typical):

- `x64\Release\GameCore_XP2_Shell_FinalRelease.dll`
- `x64\Release\Civ6DllLoader.runtime.dll`

Copy both into a Workshop mod under `Binaries\Win64\`. On the first launch the shell elects the
highest-version runtime, copies it to `<game exe dir>\version.dll` and asks to restart; after that
restart the proxy DLL is what pulls the loader in. Once the loader is in place the shell is never
loaded at all — the `LoadDLL` detour redirects the Expansion2 slot straight to the stock GameCore
DLL, vanilla sessions included (see `docs/ARCHITECTURE.md` §1.1).

Runtime candidates carry static version metadata (RCDATA 105). Installation and
updates read this resource without executing candidate DLL entry points or exports.
Rebuild both shell and runtime after this change: older runtimes without the
resource are skipped. Version numbers remain defined in `common/LoaderVersion.h`.

Candidates come from the scan roots (Documents Mods and the Steam Workshop content
roots); the game install root is not a mod container and is not scanned. The installer/updater does **not** filter by mod-enabled state
(plugin loading still does). The metadata identifies the package format; it is not a
publisher signature, and `ProbeVersion` only checks PE + RC 105 - so only distribute
runtime DLLs from sources you trust.
