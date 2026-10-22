# Civ6DllLoader

> English | [中文](README.md)

A native C++ plugin loader for Civilization VI: a thin shell (first-run installer) + a versioned runtime + a read-only HookAPI.

This repository contains **loader infrastructure only**. Plugin examples live in a separate repo (`Civ6DllLoader-Examples`).

## How it works

In one sentence: it disguises itself as `version.dll` to get into the process, takes over the ruleset-DLL load slot, and then mounts any number of third-party DLL plugins onto the game's lifecycle.

1. **Injection** — the game EXE has `version.dll` in its static import table, and the Windows loader resolves it from the EXE directory first. We deploy `Civ6DllLoader.runtime.dll` as `<exe dir>\version.dll`, so it loads at the earliest stage of process initialization; it forwards the system `version.dll` exports one by one, so version queries behave exactly as before.
2. **Self-check, then start** — `DllMain` first verifies that "its own directory == the process exe directory" and that "the host exe name looks like `CivilizationVI*.exe`"; otherwise it goes dormant silently (no thread, no file I/O, no hooks). Once it passes, it spawns a **one-shot** worker thread to finish initialization — avoiding the loader lock, and the main loader thread never blocks waiting on it.
3. **Take over the slot** — the worker thread resolves the symbol DB, initializes MinHook, installs detours on `LoadDLL` / `UnloadDLL` (`LoadUI` is installed separately by the UI-injection module), and then loads Global plugins. From that point on, when the engine asks to load `GameCore_XP2_FinalRelease.dll`, the detour rewrites the path back to the **stock** DLL — so the shell is **never loaded** in the installed state, and vanilla sessions run untouched.
4. **Load plugins** — once GameCore is mapped, phase B begins: scan the Documents `Mods` root and the Steam Workshop content roots, accept only `Binaries/Win64/Plugins/{Global,GameCore}/*.dll` under **enabled mods**, read each DLL's `VERSIONINFO`, keep only the highest version per basename, then load by category and call its `OnLoad`.
5. **Deliver the interface** — `OnLoad(const HookContext*)` receives an entry table that is looked up **by name** (`ctx->Query("InstallHook")`), not a struct with a frozen layout; the plugin-side `HookAPI.h` fills it into a module-private table and code keeps calling `api->Xxx(...)`. Category is reconciled both ways between the auto-emitted `Civ6PluginKind` export and the install path; a mismatch rejects the plugin.
6. **Resolve addresses** — plugins locate in-game addresses by symbol name / RVA / AOB / vtable slot. Symbol names and old RVAs come from the embedded sidecar symbol DB; across game updates `PdataMatch` corrects them onto the current image using the PE exception unwind tables (`.pdata`), with AOB as fallback and verification.
7. **Teardown** — when the engine calls `UnloadDLL`, the detour first runs a full reverse-order teardown (restore entry bytes → notify plugins → call the original function to unload GameCore and its Lua environments → release plugin modules), then lets the original call through.

The very first run (no `version.dll` in the EXE directory yet) takes another path: a mod shipping the shell rewrites the ruleset `DllPrefix` to `GameCore_XP2_Shell` via the stock `Config.sql`, so the engine loads the shell; the shell installs no hooks — it only scans runtime candidates, elects the highest version by static version resource (RCDATA 105), copies it to `exe\version.dll` and asks for a restart. After the restart the steady-state path above takes over and the shell no longer participates.

For the full mechanism see [docs/ARCHITECTURE.en.md](docs/ARCHITECTURE.en.md).

## Core features

- **Whole-process reach**: plugins are not confined to GameCore — they can hook the main EXE and resident system libraries, and can inject into the front-end (ForgeUI) main menu. That is out of reach for the classic "replace the ruleset DLL" approach.
- **Many plugins side by side**: the loader pins the ruleset slot to the stock DLL and routes plugins through their own directory and scan pipeline, so several independent DLLs that touch the same logic can be active at once — **no more `LoadOrder` race**, and no source-level merging.
- **Resilient to game updates**: `PdataMatch` corrects cross-version RVAs using `.pdata` sliding anchors + interpolation + prologue hashes + AOB inference, and a disk cache short-circuits repeat work; the symbol DB rebuilds with a single `tools/symdb.py` command, and plugins resolve by "symbol name first, AOB as fallback".
- **Two-domain lifecycle isolation**: `Global` (process lifetime, never unloaded, may touch exe/system libraries) and `GameCore` (loaded per match, truly unloaded on exit, restricted to the current GameCore image) are enforced three ways: compile-time member pruning, load-time category reconciliation, and runtime address-domain checks.
- **Unified hook sites and shared hooks**: one MinHook instance per target address for the whole process, always jumping into a loader-generated stub; N subscribers (detour + parameter captures) share a single site, install/uninstall never trample each other, and the hot path is a handful of instructions.
- **Name-delivered ABI**: the entry list is a single X-macro source of truth, so adding, removing or reordering entries does not break already-compiled plugins; `structSize` doubles as a "same build on both sides" sentinel, and `HookAPI_RequireAll` makes missing entries fail gracefully inside `OnLoad`.
- **Crash quarantine and safe unload ordering**: a plugin that crashes in `OnLoad` or returns 0 is quarantined with its registrations rolled back and is never retried; match exit follows a strict reverse-order teardown, avoiding dangling calls into unloaded plugin code after the engine drops its Lua environments.
- **Front-end UI without compiling**: drop `UI/FrontEnd/FrontEndUI_*.xml` + `.lua` into a mod directory and they are mounted into the main menu — no DLL required.
- **Operable by design**: `config.ini` exposes `ENABLE_GLOBAL` / `ENABLE_GAMECORE` / `ENABLE_DEBUG_LOG` / `ENABLE_PROFILER`; symbol-DB match state, timing profiles and structured logs are all inspectable; `tools/rva_to_symbol.exe` is a single-file RVA → symbol lookup.

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
DLL, vanilla sessions included (see `docs/ARCHITECTURE.en.md` §1.1).

Runtime candidates carry static version metadata (RCDATA 105). Installation and
updates read this resource without executing candidate DLL entry points or exports.
Rebuild both shell and runtime after this change: older runtimes without the
resource are skipped. Version numbers remain defined in `common/LoaderVersion.h`.

Candidates come from the scan roots (Documents Mods and the Steam Workshop content
roots); the game install root is not a mod container and is not scanned. The installer/updater does **not** filter by mod-enabled state
(plugin loading still does). The metadata identifies the package format; it is not a
publisher signature, and `ProbeVersion` only checks PE + RC 105 — so only distribute
runtime DLLs from sources you trust.
