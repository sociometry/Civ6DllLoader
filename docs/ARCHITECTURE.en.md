# Civ6DllLoader Architecture Overview

> English | [中文](ARCHITECTURE.md)

- Applicable version: pre-release `1.0.0` (`common/LoaderVersion.h`), plugin ABI `CIV6_HOOK_API_VERSION = 1`.
- This document is the **sole authoritative architecture description**.
- Convention: this document locates things by `file` / `file:function name` and avoids hard-coding line numbers wherever possible (line numbers drift as the code changes).
- **⚠️ marker = key caveats and design constraints**: covers lifecycle boundaries, cross-platform struct layout differences, and hard constraints on cross-thread calls.

---

## 0. One-Minute Overview

### 0.1 Host Background and System Positioning
Civilization VI uses a two-layer execution model: the main process (`CivilizationVI.exe`) is resident throughout and handles the front-end UI and engine rendering, while the core game match logic (`GameCore_XP2_FinalRelease.dll`) is a dynamic module that the engine loads when a match begins (`LoadDLL`) and unloads when the match ends (`UnloadDLL`).

**Civ6DllLoader** is a native C++ plugin extension platform built for Civilization VI:
1. **Injection bootstrap**: loaded at the earliest stage of process initialization through a `version.dll` proxy in the game directory (a copy of `Civ6DllLoader.runtime.dll`), assisted by a dedicated "thin shell installer" that takes its place automatically on first use;
2. **Hooking infrastructure**: intercepts key lifecycle functions (`LoadDLL` / `UnloadDLL` / `LoadUI`) and maintains a unified "hook site registry (HookSite Registry)", managing native hooks and parameter capture with unified stubs and trampolines;
3. **Plugin extension surface**: through a read-only function pointer table (`HookAPI`), provides third-party plugins with module address resolution, hook installation, memory patches, and engine event callbacks.

### 0.2 Community Solutions Compared and Design Motivation

The vast majority of DLL mods in the community rely on the officially provided ruleset override mechanism (updating the `DllPrefix` of the `GameCores` table in the database via `Config.sql`, replacing the official ruleset with a custom-compiled DLL).

**Pain points of the traditional approach**:
1. **Functional scope limited by GameCore**: it can only be loaded as a ruleset DLL and cannot intervene in the main program EXE, system libraries, or the front-end UI (ForgeUI);
2. **Single-instance exclusivity and LoadOrder contention**: the engine allows only one DLL to be mounted per ruleset (e.g. `Expansion2`). Multiple DLL mods cannot coexist unless they are merged at the source level, and they must compete over `LoadOrder` priority to win the right to take effect.

**Core advantages of Civ6DllLoader**:
1. **Breaking out of the GameCore limits (whole-domain extension)**: entering the process through an EXE import table proxy (`version.dll`) frees plugin capability from the GameCore scope, making it possible to intercept the main program EXE, inject into the front-end UI, and keep a resident monitor;
2. **Fully taking over the load logic, eliminating LoadOrder contention**: intercepts `GameCore::LoadDLL` inside the EXE, redirects the ruleset slot back to the official vanilla DLL, and takes over the plugin scan and load pipeline at the same time. Multiple conforming independent DLL plugins can be loaded in parallel and coexist safely, eliminating contention for the ruleset `LoadOrder` between mods;
3. **Comprehensive cross-version function auto-matching (strong resistance to updates)**: built-in cross-version auto-correction mechanism (`PdataMatch`) based on the PE exception unwind table (`.pdata`), combined with sliding-window anchor chains, linear interpolation/extrapolation, normalized function header hashing, and vtable back-inference, which can effectively cope with future game version updates and greatly reduces the maintenance and adaptation cost of Mod symbols going stale after a game update.
   > The match ratio has **no built-in statistics**: `PdataMatch` only emits a per-entry `matched %zu` count log,
   > and `GetMatchRatio` returns a real match ratio only for CrossVersion. When an assessment is needed, rely on the on-machine logs
   > and do not quote any percentage from this document (§7.3).

**Known limitations and trade-offs**:
1. **Strict specification constraints**: the Loader will not load arbitrary DLLs that do not follow the configured rules; plugins must integrate with this project's specification (follow the directory structure layout, export `Civ6PluginKind` to declare the category, interact via `HookAPI`);
2. **First install still depends on the official mechanism**: in the initial state where `version.dll` has not yet been generated in the EXE directory, the thin shell installer still needs to enter once through the official `GameCores` override mechanism to complete election and deployment; therefore the first install still requires a game restart to take effect, and the thin shell itself still has to take part in the official `LoadOrder` contention on its first entry.
3. **Currently only the Steam version is supported**

### 0.3 The Three Core Architecture Principles

1. **Lifecycle dual-domain isolation (Category × Domain)**:
   - **Global plugins**: loaded when the main process starts, never unloaded for the lifetime of the process, and their operation scope is strictly limited to resident modules (the EXE and system libraries).
   - **GameCore plugins**: loaded and unloaded with the dynamic match lifecycle, with the operation scope strictly limited to the GameCore memory mapping range of the current match (GameCore plugins apply only to the Expansion2 (Gathering Storm) ruleset).
   - This isolation is guaranteed by three things: compile-time symbol renaming, load-time path reconciliation, and runtime address boundary checks (§3.5, §4).
2. **Unified hook site accounting (Unified Hook Site)**:
   At most one MinHook instance is ever created per target address globally, uniformly redirecting to the dispatch stub generated by the Loader. When a plugin retires, only the dispatch slot is unbound; the entry bytes are physically restored only during GameCore unload cleanup (Teardown) (§5). Site nodes and stubs stay resident for the lifetime of the process and are reused in place.
3. **Strict reverse-order destruction (Safe Teardown Sequencing)**:
   When leaving a match, a fixed sequence is followed: **restore the entry bytes → plugin unload notification (OnUnload/unregister callbacks) → call the original UnloadDll function to unload GameCore and its Lua environment → free the plugin DLL modules** (§2.4). This order avoids dangling pointer crashes caused by callbacks into already-unloaded plugin code after the engine's Lua environment has been released.
   ⚠️ Patches are not rolled back automatically by the Loader: patches are resident in the process by default, and if revocation is needed the plugin must call `Unpatch` itself (§5.8).

What is in the process (see §1.1 for details):

| Module | Role |
|---|---|
| `CivilizationVI.exe` | The game proper; the Loader's hook targets (LoadDLL / UnloadDLL / LoadUI…) |
| `version.dll` | **The Loader itself** (a copy of `Civ6DllLoader.runtime.dll` placed in the exe directory): the exe statically imports it, and it forwards the system `version.dll` exports one by one, so system version query behavior is unchanged |
| `GameCore_XP2_Shell_FinalRelease.dll` | **The Loader installer on first use of this kind of Mod** (zero hooks, does not start the runtime): it is loaded by the engine only when the Loader is absent; when the Loader is in place it never enters the process (see below) |
| `GameCore_XP2_FinalRelease.dll` | The game's match logic (the "short-lived domain", swapped out on every match entry) |
| `Localization_FinalRelease.dll` / `HavokScript_FinalRelease.dll` | Localization / Lua VM (resident, resolved by export name) |

Key file index (the entry point for reading the code):

| File | Responsibility |
|---|---|
| `common/HookAPI.h` | Plugin ABI: entry list `HOOK_API_LIST`, `HookContext`, generative `HookAPI`, `HookAPI_Resolve`, category gate |
| `DllLoaderRuntime/HookLoaderApi.cpp` | **ABI convergence point**: the `g_hookApi` table itself + name-based `Query` delivery + read-only verification; it takes the addresses of each module's `*Impl` and is not depended on in reverse |
| `DllLoaderRuntime/PluginRegistry.cpp` | Plugin lifecycle: `PluginEntry` table, load/unload/quarantine, category determination, `ResetForReload`, queued release |
| `DllLoaderRuntime/ScriptBridge.cpp` | Lua / GameEvent / script registration / PushMethods slots (the largest module) |
| `DllLoaderRuntime/HookEngine.cpp` | Site table, stub generation, capture, hook installation and physical hook removal |
| `DllLoaderRuntime/PluginDomain.cpp` | Domain gate (`IsTargetOpenToCaller` etc.) and caller identity authentication |
| `DllLoaderRuntime/AddressResolve.cpp` | Address resolution implementation (RVA / name / pattern / vtable) |
| `DllLoaderRuntime/LoaderHooks.cpp` | Installation and detour orchestration of the exe-domain hooks (LoadDLL / UnloadDLL) |
| `DllLoaderRuntime/RuntimeEntry.cpp` | DllMain, dormancy detection, one-shot startup thread |
| `DllLoaderRuntime/UiInject.cpp` | Main menu UI injection (LoadUI detour + LuaContext) |
| `DllLoaderRuntime/ImageAddress.cpp` | PE image registration and RVA conversion |
| `DllLoaderRuntime/PdataMatch.cpp` | sidecar parsing + pdata matching + RVA correction |
| `DllLoaderRuntime/PatchRegistry.cpp` | Patch ledger (stores original bytes by address); **the Loader does not roll back automatically**, see §5.8 |
| `DllLoaderRuntime/PluginInFlight.*` | In-flight registration and draining of plugin callbacks (**isolated by load generation**, see §6.1) |
| `DllLoaderRuntime/Civ6MessageBus.*` | Inter-plugin messages; the bus's global instance and the plugin ABI forwarding layer live here too |
| `DllLoaderRuntime/TeardownWindow.h` | Shared state of the teardown window (writer side PluginRegistry/HookEngine, reader side PluginDomain) |
| `DllLoaderRuntime/PluginTableAccess.h` | Read-only facade of the plugin table (for ScriptBridge / HookLoaderApi queries, without exposing the table itself) |
| `common/ModScan.cpp` / `common/EnabledMods.*` | Plugin scanning and "enabled Mod" filtering (**applies to plugins only**; the candidates for installing/self-updating the loader do not consult the enabled set) |
| `DllLoader/ShellBootstrap.cpp` | Shell-side re-installation (first install; the runtime self-update lives in `LoaderUpdate.cpp`) |
| `tools/symdb.py` | Symbol DB pipeline (the only entry point, including AOB generation/verification) |

> Suggested source reading order: `HookLoaderApi.cpp` (see who owns each of the 80 pointers in the ABI table) → `PluginRegistry.cpp` (lifecycle)
> → `HookEngine.cpp` (hooking) → `ScriptBridge.cpp` (script surface). For each module's ownership state and facades, read the top
> comments of the respective headers (the former `docs/REFACTOR_PLAN.md` has been merged into this document and no longer exists separately).

---

## 1. Deployment Form and Boot Chain

### 1.1 Modules and Roles in the Process

There are two mutually independent entry paths in the process:

#### 1. Loader injection path (based on import table hijacking)
The EXE's static import table contains `version.dll`, and the Windows loader resolves that dependency from the EXE directory first.
- We deploy `Civ6DllLoader.runtime.dll` as `version.dll` in the EXE directory, so that the Loader is loaded automatically at the earliest stage of process initialization (`DllLoaderRuntime/ProxyExports.cpp`);
- That module forwards the native `version.dll` exports one by one to the real system library, with no impact at all on the operating system's version query behavior.

#### 2. Thin shell load path (based on mod configuration redirection)
The thin shell (`GameCore_XP2_Shell_FinalRelease.dll`) steps in on demand through the official mod mechanism:
1. **Official default load**: officially registered in `DLC/Expansion2/Config/Expansion2_Config.xml` as `GameCores(GameCore='Expansion2', PackageId=..., DllPrefix='GameCore_XP2')`, and the engine concatenates and loads `Binaries/Win64/GameCore_XP2_FinalRelease.dll` accordingly;
2. **Mod configuration redirection**: the mod rewrites the `DllPrefix` in the database to `GameCore_XP2_Shell` via `Config.sql`, making the engine request the thin shell DLL in the mod directory instead;
3. **Dual-state load branch**:
   - **Normal state (Loader already in place)**: the Loader's `LoadDLL` detour intercepts the call and directly rewrites the request path back to the absolute path of the official GameCore. Therefore **the thin shell is never loaded into memory**;
   - **First install (Loader absent)**: with no detour interception, the engine loads the thin shell normally. The thin shell exports interfaces such as `DllCreateGameContext` itself and forwards them to the official GameCore to keep the game running, while carrying out the `version.dll` installation logic in the background (§1.3).

The thin shell does **not** start the runtime on its own — the runtime is already resident in the process under the identity of `version.dll`. The thin shell's only duty is to complete the election and copy when `version.dll` is missing, and to prompt for a restart to take effect. As long as `version.dll` already exists in the EXE directory, the thin shell takes no part in any operation for the entire session.

- runtime: `Civ6DllLoader.runtime.dll` (artifacts under `x64\Release\`); all hook / sidecar / plugin logic lives here;
- thin shell: `GameCore_XP2_Shell_FinalRelease.dll` (also under `x64\Release\`), installer only (scan Mods + version
  election + re-install `version.dll` + prompt restart), **zero hooks**, does not start the runtime; not loaded when the Loader is in place.

### 1.2 version.dll Dormancy Detection

`RuntimeEntry.cpp`'s DllMain performs a self-check first, and starts the Loader **only when both conditions hold**:

1. **Its own parent directory == the process exe's parent directory** (`Base\Binaries\Win64Steam\` or `Win64\`);
2. **The host process's exe name looks like `CivilizationVI*.exe`** (case-insensitive prefix + `.exe` suffix,
   both the DX11 and DX12 variants match).

If either does not hold, it "sleeps" — no thread creation, no file reads, no hooks — avoiding leaking Loader logic into unrelated processes.
Comparing the directory alone is not enough: any process that loads this `version.dll` from the game exe directory (crash reporters, third-party tools,
overlays) is blocked by ②. While dormant the Logger is not initialized yet (it is Init'ed only in the worker thread), so only a single line
with the reason is left in `OutputDebugString`, visible with DebugView; when investigating "the loader did not take effect", look here first.
**Note**: if you launch the game with a renamed exe or a third-party launcher, the Loader will silently sleep — a direct consequence of ②.

### 1.3 Installer and Self-Update

Two mutually independent installation and maintenance paths:

**① Shell-side "re-installation and takeover" (`DllLoader/ShellBootstrap.cpp`)** — executed only once, when the thin shell is loaded by the engine:

1. **Version probing and readiness determination (`RuntimePackage::ProbeVersionIncludingLoaded`)**:
   - Normally, if the Loader is properly in place and the hook installation succeeds, the `LoadDLL` detour redirects it to the official GameCore, and **the thin shell is never loaded at all**;
   - Once the thin shell is loaded, it means no redirection interception has happened. At that point `exe\version.dll` is checked:
     - If the file does not exist: judged as not yet installed, and the first-install flow is entered;
     - If the file exists and contains a compliant RC 105 resource (it is our Loader): it means the Loader is in place but its `LoadDLL` hook failed to take effect (e.g. the process slept and skipped it, hook installation failed, etc.), so the status quo is kept with zero action (no need to copy again or show a dialog, just pass through to the official GameCore);
     - If the file exists but **is not our Loader** (missing the compliant RC 105 resource): it means the current `version.dll` is a foreign proxy or an unrelated conflicting file, and the **takeover flow** is triggered (overwrite install with backup);
2. **Candidate collection and version election**:
   - Collect `Civ6DllLoader.runtime.dll` candidates (`ModScan::FindRuntimeCandidates()`, no parameters);
   - Validate each PE and read RC resource 105, electing the highest version (on a version tie, take the one with the smaller path lexicographic order; candidates are not filtered by the Mod enabled set);
3. **Split atomic publication (publishing to `version.dll`)**:
   - **First install** (original file does not exist): copy to `version.tmp`, then atomically rename into place directly, and clean up any leftover `version_Old.dll`;
   - **Takeover of a foreign file** (original file exists and is currently mapped by the system): copy to `version.tmp`, then call `ReplaceFileW` for an atomic replacement with backup, safely moving the original file to `version_Old.dll` before writing over it;
4. **Prompt for restart**: show a dialog "Installed. Click OK to restart the game immediately" and try to start a new process to restart;
5. **Silent fallback**: if any step fails, it **only logs, shows no dialog, and does not block game startup**; this session simply passes through to the official GameCore and completes normally.

**② Runtime-side self-update (`LoaderUpdate::CheckAndApplyUpdate`)** — the copy already running in the process replaces the one on disk:

- Precondition: its own file name must be `version.dll` (otherwise it is treated as a direct load during development and the self-update is skipped);
- At startup, if `version_Old.dll` is found to exist, it means **the previous session has just completed a self-update**, so it is deleted directly (self-healing);
- Candidates go through the same `ModScan::FindRuntimeCandidates()`; after excluding itself (normalized path comparison),
  a newer version is selected → **first backed up as `version_Old.dll`, then atomically replaced** (`ReplaceFileW`: the replaced file is renamed to the backup name and
  the replacement file takes over its name, so there is no intermediate state on disk where "`version.dll` does not exist"; if `ReplaceFileW` is rejected, it falls back to
  the old two-step rename + rollback on failure) → on failure it rolls back and the current installation stays unchanged;
- After the swap, this session **still uses the old version in memory**, and a restart is required for it to take effect (the log writes `update applied ... (restart to take effect)`).

Version numbers and protocol constants are in `common/LoaderProtocol.h` + `common/LoaderVersion.h` (`1.0.0`, RC resource id 105).
The candidate version number obtained by the thin shell also comes from the same RC resource — **the installer does not execute the candidate DLL's `DllMain`/TLS/exports**, it only reads the resource.

Candidates are **not filtered by the Mod enabled set** (`FilterByEnabledMods` is not called in `ModScan::FindRuntimeCandidates`):
installing and self-updating the Loader elects solely by the RC 105 version number, which is a separate path from "plugins are loaded only from enabled Mods".

The candidate discovery rules are as follows:
1. **Scan scope**: candidates are collected only from two content roots:
   - User documents directory: `Documents\My Games\Sid Meier's Civilization VI\Mods`
   - Steam Workshop content directories (auto-discovered by walking up from the EXE directory, or by querying the registry `SteamPath` and parsing `libraryfolders.vdf`)
2. **Exclude the game install root**: the game installation directory itself is not a mod container (its subdirectories `Base`, `DLC`, etc. do not contain the `Binaries\Win64` distribution structure), so it is not used as a scan root;
3. **Security boundary**: `RuntimePackage::ProbeVersion` only parses the PE structure and the RC 105 resource, and does not include publisher digital signature verification; any Runtime DLL located in the above mod directories with a compliant structure takes part in the version election.

The plugin-side enabled-set filtering mechanism (`FilterByEnabledMods` + `EnabledMods::AllowsPath`) is detailed in §3.1.

### 1.4 One-Shot Startup Thread (Stage A)

After `RuntimeEntry.cpp`'s DllMain passes dormancy detection, it creates a **one-shot** thread (`WorkerMain`), with 7 steps as follows.
**The numbering corresponds one-to-one with the comments in `WorkerMain`** (the code writes `1) / 1.2) / 1.5) / 2) / 2.5) / 3) / 4)` —
the ones with decimals are steps inserted later, so the sequence is not contiguous; this is a trace of the historical order, not a typo):

**1)** `LoaderCore::InitEarly()`: `Logger::Init` + `VerifyHookApiTableProtection` (the HookAPI table must reside in read-only pages)
   + `PdataMatch::Init` (load the sidecar) + **create a profile for the current exe variant** + `Runtime::InitMinHook`.
   This profiling step (the branches of `IdentifyExecutable()` in `RuntimeEntry.cpp`) is easy to miss: a successful `PdataMatch::Init`
   only makes the sidecar available; you still have to build an exe symbol table for **whether the current process is actually DX11 or DX12**, so that plugins can perform
   cross-version correction against the old exe RVA. A missing module or a failed profile build is always fail-closed: `ResolveByRva`/`ResolveByName`
   for that image return `nullptr` and **do not fall back to the original RVA** (the original RVA is simply wrong after an update), so both cases leave a prominent log line;
**1.2)** `hks::InitHavokScript()` + `Localization::InitScript()`: the two **process-level static imports** are resolved once
   (a miss only degrades their respective APIs and does not affect plugin loading; why this stage, see §1.5);
**1.5)** `UiInject::ExtractResources()`: release the embedded FrontEnd UI resources into the `<exe directory>\Civ6DllLoader\` subdirectory;
**2)** `LoaderHooks::InstallAll()`: exe-domain hooks. **Both are mandatory**: if either `LoadDLL` or `UnloadDLL`
   fails validation, all hooks created in this run are rolled back. `UnloadDLL` is mandatory because the release timing of plugin modules hangs on it
   (§2.4) — with only the load hook installed, GameCore plugins would never reach their release point.
   Only after both `MH_CreateHook` calls succeed and the engine module slot address is available is a single
   `MH_QueueEnableHook ×2 + MH_ApplyQueued` used to enable them simultaneously: avoiding a window where "only the load hook is in effect".
**2.5)** `UiInject::Install()`: main menu UI injection hook, silently degrading on failure;
**3)** `LoaderUpdate::CheckAndApplyUpdate()`: runtime-level self-update check (the second line of defense besides the thin shell);
**4)** `LoaderCore::LoadPluginsOf(PluginCategory::Global)`: scan and load **Global plugins**.

This thread **is not resident**: no event loop, no reconcile (see §3.3). Everything afterwards is driven by detours on the game thread.

> **Design consideration: on the safety of creating an initialization thread inside `DllMain` (Loader Lock)**
> 
> The Windows loader lock (Loader Lock) strictly forbids executing `LoadLibraryExW`, file I/O, and complex cross-module synchronization inside the `DllMain` call stack. For this reason, the Runtime uses an asynchronous worker thread to complete Stage A initialization:
> 
> * **Lightweight dispatch**: `DllMain` only performs `DisableThreadLibraryCalls` and the module path check, calls `CreateThread` to create an independent worker thread, then immediately closes the handle via `CloseHandle` and returns;
> * **Avoiding circular waits**: the main loading thread **never blocks waiting** for that worker thread (no `WaitForSingleObject` call), thus completely eliminating the possibility of a circular deadlock with the system loader lock;
> * **Thin shell comparison**: the thin shell defers all logic to the engine callback `DllCreateGameContext`, completely bypassing `DllMain`; the Runtime achieves the same safety guarantee through a non-blocking worker thread.

### 1.5 Stage A / Stage B

- **Stage A (before entering the main menu)**: the thread above. At this stage GameCore is not loaded yet, and Global plugins' `OnLoad` runs here;
  the address resolution/hooking they can do only involves the exe and resident modules.
  This stage also resolves two **process-level static imports**: `hks::InitHavokScript()` (Lua VM) and `Localization::InitScript()`.
  Both are loaded along with the exe and are unrelated to the match cycle, so they must be resolved in Stage A and **must not be deferred to Stage B**.
  Defensive rationale: if they were placed in Stage B and a resolution failure caused an early exit, the GameCore image would already have been loaded and mapped by the operating system,
  while the Loader has not yet begun attach-tracking it and has not established the teardown protection window; this would let Global plugins
  legitimately hook into that unmanaged image, which then could not be cleaned up when retiring for a match switch.
  When resolved in Stage A, a missing import only **degrades** the respective API (safe default value per entry + rate-limited logging) and
  **does not affect plugin loading** — plugins may not use Lua or localization at all.
- **Stage B (on entering a match)**: the engine calls `LoadDLL` → our detour (`LoaderHooks.cpp`) rewrites the path and calls the original function,
  and on success `LoaderCore::InitializeGameCorePhase()`: `AttachGameCore` →
  `EnsureScriptHooksInstalled` → load **GameCore plugins**.
  (`hks::InitHavokScript` / `Localization::InitScript` are **not** here — see the Stage A explanation.)
- **Leaving a match**: the engine calls `UnloadDLL` → our detour first calls `ResetForReload()` (see §2.3) and then the original function.

Both `LoaderHooks::InstallAll()` and `UiInject::Install()` install hooks in Stage A (inside that one-shot thread).
The `LoadUI` hook is managed by `UiInject::Install()`, a separate transaction from `LoadDLL`/`UnloadDLL`.

> **On the log order of self-update and hook installation**: `InstallAll()` is scheduled before the self-update check, so the log shows
> `InstallAll: LoadDLL + UnloadDLL installed; module slot=...` first, and only afterwards the self-update check output.
> A successfully updated DLL will take effect with the system load on the next startup.

---

## 2. Lifecycle and teardown

### 2.1 Stage State

- Whether Stage B is ready: `ScriptBridge::SetGameCorePhaseReady` / `IsGameCorePhaseReady`
  (`std::atomic<bool>`, defined in `ScriptBridge.cpp`). `InitializeGameCorePhase()`
  sets it `true` and `ResetForReload()` sets it `false`; `LoaderCore::IsInitialized()` answers only this one question.
  Rationale for using an atomic: both read points already hold the lifecycle lock, and a lock-free read side saves one re-entry; the write side still holds the lock, so the semantics are unchanged.
- `g_gameCoreTransitionMutex` (recursive): strings "phase switching" and "plugin load/unload" together, ensuring that
  "attach → install hooks → load GameCore plugins" and "teardown → unload" do not interleave. All three entries take it first:
  `LoadPluginDllInternal` / `InitializeGameCorePhase` / `ResetForReload`.
- **teardown window** (`LoaderCore::Teardown::g_address` / `g_sizeOfImage`, defined in `TeardownWindow.h`):
  inside the window `TargetInTearingDownGameCore(target)` is true and `InstallHook` rejects directly; the window is also the sole criterion in the latter half of teardown
  for "which sites belong to the image being torn down this time" (because by then `ImageAddress` has already detached).
  These two fields are read and written by 4 modules (PluginRegistry / HookEngine / PluginDomain + the header itself), so they must
  **share the same storage across TUs**: writing them as separate `static` variables per TU would make the window fail silently without any error.
  Both fields are `std::atomic`, and taking effect as a pair has a fixed order: the write side does size first, then address(release); the clearing side does
  address(release) first, then size; the read side does address(acquire) first and reads size only when it is non-zero. The write side is the game thread, while the read side also includes
  plugin threads (`TargetInTearingDownGameCore`).

### 2.2 Orchestration of LoadDLL / UnloadDLL (`LoaderHooks.cpp`)

Both detours share one exe-side engine module slot, `g_engineModuleSlot` (resolved in `InstallAll` by `kAob_hModule`;
**it must be addressed before MH_Enable/ApplyQueued rewrites the LoadDLL entry** — that AOB covers the LoadDLL entry). Read it via
`ReadEngineModule()` (wrapped in `__try`; if the slot is unreadable it is treated as "unavailable" rather than crashing).

`LoadDllDetour`:

1. `GetRuleSetName()` returns empty → not in the game yet (loading Base etc. early in startup), pass through as-is; not `EXPANSION_2` → pass through (only XP2 is supported);
1.5 **Switch and candidate gate (inside the XP2 branch)**: `config.ini`'s `ENABLE_GAMECORE=false`, or
   `ModScan::FindGameCorePluginCandidates()` finds no candidates at all → **pass the engine-provided Path through as-is**,
   without feeding the official DLL, without initializing Stage B, and without loading plugins. Thus, when this framework has no GameCore plugins,
   the engine still loads according to its own rules, remaining compatible with other GameCore DLL Mods that do not go through this framework.
   The candidate list is scanned and cached at this point for reuse in step 6 (avoiding scanning twice in a single match entry).
2. Rewrite the input parameter (the **thin shell** path requested by the engine after the Mod overrode `GameCores`) **into the absolute path of the official GameCore**
   (`OfficialGameCoreRelPath` gives the official relative path, `BuildOfficialPath` concatenates it under the game root; only when the official file does not exist is
   the original path passed through). Redirection rule: **the engine slot = official**; the thin shell is loaded only when the Loader is absent and this detour does not exist;
3. **Call the original function first**, `g_origLoadDLL(target)`, and return its return value as-is;
4. `IsInitialized() || g_unloadIncomplete` → return directly. Both cases mean "this match should not be re-initialized":
   Stage B is already ready, or the engine's previous unload has not finished (set by `UnloadDllDetour`; if no module slot clearing is observed after the original function returns,
   it is not cleared);
5. Read `g_engineModuleSlot`: unavailable or `nullptr` → log and return, **do not** initialize (without a confirmed image there is no mappable domain);
6. `InitializeGameCorePhase()` succeeds → `LoadPluginsOf(GameCore)`; fails → log only.

> **Why the return value of `LoadDLL` is ignored**: the decompilation (`docs/analysis/LoadDLL_analysis.md` lines 15–16,
> `0x1400F851F`) is `if (hModule != nullptr) return 0;` — the engine's `LoadDLL` has **three paths** returning 0:
> the module is already loaded (idempotent short circuit), `LoadLibraryW` failed, missing `Dll*` exports. Only a return of 1 definitely means "this load succeeded".
> The only caller, `AppModdingFramework::LoadGameCore`, calls `UnloadDLL` before calling it, but that cannot guarantee the module slot
> is definitely cleared (failure paths). Reading the module slot is the only criterion that can distinguish "whether the image is in place".

`UnloadDllDetour`:

1. Read the module slot to get `before`; `before` is non-null **or** Stage B is ready → set `g_unloadIncomplete = true`
   ("the engine's unload has not finished yet");
2. `IsInitialized()` → `ResetForReload()` (cleanup + **enqueue** the GameCore plugin modules);
3. Call the original function `g_origUnloadDLL()` — **the engine unloads the GameCore image together with its gameplay/ui Lua environments here**;
4. **Only when the slot is observed changing from non-null to null** (`hadModule && ReadEngineModule(after) && !after`) are
   `ClearGameCoreTeardownWindow()` + `FreePendingPluginModules()` called, and `g_unloadIncomplete` cleared.
   A no-op or failure of the engine must not trigger the release: at that point the Lua environment may still reference closures inside the plugin images.
   This is also the other half of "LoadDLL returning 0 is not an unload barrier" — the unload barrier is **the slot being cleared**, not the function returning.

### 2.2.1 Process-level Switches: `Civ6DllLoader\config.ini`

`<exe directory>\Civ6DllLoader\config.ini` (the same directory as the FrontEnd UI resources):

```ini
[Loader]
ENABLE_GLOBAL=true
ENABLE_GAMECORE=true
ENABLE_DEBUG_LOG=false
ENABLE_PROFILER=false
```

| Key | Effective point | Scope of effect |
|---|---|---|
| `ENABLE_GLOBAL` | Stage A's `WorkerMain` step 4 | Only decides whether to `LoadPluginsOf(Global)`. The Loader's hooks, UI injection, and self-update **execute as usual** |
| `ENABLE_GAMECORE` | The XP2 branch of `LoadDllDetour` | When false, the original Path is passed through, the load is not taken over, and GameCore plugins are not loaded |
| `ENABLE_DEBUG_LOG` | Plugin-side self-check | Developer switch, default false. **Read-only, can only be edited by hand**, there is no Writer / UI / Lua interface. Lets plugins decide whether "per-line/per-frame" level diagnostic logs are emitted |
| `ENABLE_PROFILER` | `Profiler::SetEnabled` at the start of `WorkerMain` | Developer switch, default false. Likewise read-only and hand-edit only. When enabled, the Loader emits timing analysis (see below) |

**Three independent reading rules, do not confuse them**:

- **File does not exist** → create it, writing the four keys with their respective defaults (feature keys `true`, developer keys `false`);
- **File exists but a key is missing** → **write back that key's default value** at startup, leaving the values of existing keys untouched.
  This way keys added after an upgrade (`ENABLE_DEBUG_LOG` / `ENABLE_PROFILER`) appear automatically in an old user's
  ini, instead of "documented but not found in the file". `WritePrivateProfileStringW` itself only adds a key when
  it does not exist, so values the user edited by hand are not trampled; and when a feature key's default is already `false`,
  writing it back or not behaves the same;
- **Key exists but the value is invalid** → the key is read as `false` (fail-closed: better that the plugin is not loaded
  than that a mistyped ini accidentally enables a feature).

Both developer switches are **cached once** per process (hand edits take effect after a restart): their read points are on high-frequency paths
(the per-line log decision / every `Begin`), so they cannot read the disk every time.

#### Performance Profiling (`ENABLE_PROFILER`)

`common/Profiler.h` provides the `PROFILE_SCOPE("name")` RAII macro, which finishes up automatically at the end of the scope.
**When the switch is off, both `Begin`/`End` are no-ops** — only one extra atomic bool read, no time sampling, no allocation,
no logging, so instrumentation can be left on hot paths.

Timing uses `QueryPerformanceCounter` (monotonic, unaffected by system clock adjustments), with the frequency cached once.
One line is emitted per scope, and a summary is emitted at the end of a stage (sorted by total descending):

```
[Prof] InitEarly 12.345 ms
[Prof] Plugin(LoadLibraryExW) 3.210 ms (MyPlugin.dll)
[Prof] === summary(stage A): 14 scope(s), 21 sample(s), 456.789 ms total ===
[Prof]   total=   210.123ms  count=     1  max=  210.123ms  avg=  210.123ms  WorkerMain(total)
[Prof]   total=   102.456ms  count=     1  max=  102.456ms  avg=  102.456ms  LoadPluginsOf(Global)
...
```

Instrumentation coverage: the steps of the startup sequence (`InitEarly` / dependency imports / resource extraction / each hook installation / self-update /
Lua interface registration), plugin loading (`LoadLibraryExW` including DllMain and the dependency chain, `OnLoad`, the whole batch),
Stage B (`InitializeGameCorePhase`), UI injection (the
`LoadUiDetour` entered on every main menu refresh).

**Unrelated to `ENABLE_DEBUG_LOG`**: the two are independent switches. `ENABLE_DEBUG_LOG` governs fine-grained logging
(exposed to plugins via HookAPI's `IsDebugLogEnabled`), `ENABLE_PROFILER` governs timing,
and is **not exposed externally** — the profiler only measures the Loader's own instrumentation, and plugins have no need to query it.

Only `true` / `false` (case-insensitive) and `1` / `0` are accepted as values; anything else is logged and treated as `false`.
The implementation uses `GetPrivateProfileStringW` instead of `GetPrivateProfileIntW` — the latter's integer parsing would read
`true` as 0 and cannot express a boolean.

**When it takes effect**: `ENABLE_GLOBAL` / `ENABLE_GAMECORE` only affect the load decision of "the very next time".
By the time the main menu appears Global has already finished loading, so changing `ENABLE_GLOBAL` only takes effect on the next startup; GameCore is loaded only when entering a match,
so changing it in the main menu affects the next match entry. At runtime it **will not** unload already-loaded plugins because of this.
The two developer switches (`ENABLE_DEBUG_LOG` / `ENABLE_PROFILER`) are cached within the process and also require a restart after being changed.

**Lua interface**: the `DllLoader` table is provided by the Loader itself (independent of any plugin) and is mounted on every thread environment:

```lua
DllLoader.GetGlobalState()        --> boolean
DllLoader.SetGlobalState(true)    --> boolean (whether the disk write succeeded)
DllLoader.GetGameCoreState()      --> boolean
DllLoader.SetGameCoreState(false) --> boolean
```

This path is separate from the `RegisterGlobalScript` used by plugins: the latter uses `RequirePluginOwner` to
look up the plugin module in reverse by callback address, whereas the Loader itself is not a plugin and cannot pass that check, so `ScriptBridge` provides
`ExposeLoaderLuaGlobals` separately, invoked first in each thread environment by `RunGlobalScriptsFor`.

### 2.3 The Complete Order of ResetForReload (every step's position has a reason)

1. Take `g_gameCoreTransitionMutex` + `LoaderCore::LifecycleMutex()`;
2. Set the Stage B ready flag to `false` (`ScriptBridge::SetGameCorePhaseReady(false)`; from then on `EnsureScriptHooksInstalled`
   and other entries bail out early by themselves);
3. Enter the teardown window (`LoaderCore::Teardown::SetWindow(base, sizeOfImage)`; `ImageAddress` is still attached;
   when image information cannot be obtained, explicitly set `SetWindow(0, 0)`, see §9.1 item 1);
4. Release the lifecycle lock (below we need to wait for callbacks and load/unload plugins; holding the lock while waiting causes lock inversion);
5. `DisableGameCoreDomainSites()`: while the old image is still mapped, take **all hooked sites** of the GameCore domain,
   queue them with `MH_QueueDisableHook` and call **a single** `MH_ApplyQueued` → all entry bytes are restored and no one can enter a stub or a plugin detour anymore.
   Unreadable targets (the fallback path when the image is already gone) are not queued and get `recordStale` instead;
6. `CleanupAllCaptureSites()`: clear only capture subscriptions **that fall inside the GameCore domain**; those on the exe / resident module domains are kept;
7. `UnloadPluginsOf(PluginCategory::GameCore)`: unload plugins one by one (§3.3), and the GameCore module handles are **only enqueued**;
8. Re-acquire the lifecycle lock;
9. `RemoveGameCoreDomainSiteRecords()` performs site cleanup and unbinding:
   - **Set the window and unbind**: enter the teardown window (with internal protection) and execute `ImageAddress::DetachGameCore()`;
   - **Drain in-flight calls**: temporarily release the lifecycle lock and wait for `g_activeSharedDetours` to reach zero so as to drain in-flight shared detours;
   - **Re-lock and rescan to reset**: re-acquire the lifecycle lock and rescan the site table for physical hook removal. On success, `MH_RemoveHook` and **reset the site in place** (keep and reuse the node and stub, clear the capture slots; **never erase**, because the stub machine code hard-codes `&HookSite`); on failure, mark `recordStale` and retire the detour slot;
   - **Reset shared entries**: reset `g_origRegisterScriptData(/ForUI)` and the 16 PushMethods slots;
   - **Window persistence**: **the teardown window is not cleared here**; it must persist until the engine truly finishes unloading — `UnloadDllDetour`
     calls `ClearGameCoreTeardownWindow()` after the original function returns **and** the module slot is confirmed to have gone from non-null to null (see §2.2 step 4);
10. Back in `UnloadDllDetour`: call `g_origUnloadDLL()` → if the slot has been cleared, `ClearGameCoreTeardownWindow()` →
    `FreePendingPluginModules()` (see §2.2, §2.4);

Why this order:

- **Step 5 must precede step 7**: only after the entry bytes are restored can we even talk about "Freeing a plugin will not leave a window where an entry jumps to freed code";
- **Step 9 rescans instead of reusing step 5's address list**: plugin unloading also ran between steps 5 and 9, and registration entries such as `PushLuaMethods`
  by design do not pass the domain gate, so they could theoretically still install hooks onto the image being torn down — a rescan collects them all at once;
- **Patch records must be cleared here, but the bytes are not written back**: the old image is about to be remapped, so writing bytes back to the old addresses is both meaningless and possibly
  lands on the new image; keeping the records is even worse — when the next-generation GameCore maps to the same base address, stale records make later callers hit "this owner has already
  patched" or overlapping ranges, and from then on **patches can never be applied again**. Therefore teardown calls `PatchRegistry::DiscardOwned` for all GameCore-category plugins:
  it only removes the bookkeeping and does not touch memory. Quarantined/parked plugins are cleared too (they do not go through
  `UnloadPluginByOwnerId`). Global plugins are resident and not unloaded, their records are kept, and they can still `Unpatch` themselves (see §5.8).

### 2.4 Release Timing of Plugin Modules

- `UnloadPluginByOwnerId` (GameCore category) **only enqueues the handle** (`g_pendingFreeModules`, protected by `g_pendingFreeMutex`).
  Refused loads due to category/ABI mismatch do not go through this path: that kind of refusal happens before `OnLoad` and the reference is released directly (§3.3);
- `LoaderCore::FreePendingPluginModules()` is called in **exactly one place**: after `UnloadDllDetour`'s `g_origUnloadDLL()`
  returns, **and** when "the original function really did clear a non-null module slot to null" holds. `LoadDllDetour` no longer calls it —
  LoadDLL returning by itself is not an unload barrier (the engine also returns 0 when the module is already loaded, see the note in §2.2);
- The condition is "the slot has been cleared" rather than "the function returned": the engine's `UnloadDLL` may do nothing (no-op) or fail midway,
  in which case the Lua environment may still reference closures inside the plugin image, and freeing the module would be a UAF;
- Consequently the premise "the plugin image has been freed while its Lua closures can still be called" does not exist: the GameCore gameplay/ui Lua environments
  are torn down as part of the engine unload, so the state hosting the closures is already gone;
- Cost and boundary: a GameCore module quarantined after an `OnLoad` crash stays mapped until the next Load/Unload; Global plugins are never unloaded anyway.

### 2.5 Locks and Lock Order

| Lock | Protects | Notes |
|---|---|---|
| `g_gameCoreTransitionMutex` (recursive) | Serializes phase switching | Outermost; file-level static in `PluginRegistry.cpp` |
| `LoaderCore::LifecycleMutex()` (recursive) | `g_plugins`, the various registries, slot tables, owner probes | Most frequently re-entered. Implemented as the file-level static `g_pluginLifecycleMutex` in `PluginRegistry.cpp`, **the variable is not exported**; other modules obtain the same lock through this accessor |
| `g_pushStateMutex` | The 16 PushMethods slots | Inner to lifecycle; file-level static in `ScriptBridge.cpp` |
| `Runtime::MinHookMutex()` | The site table + all `MH_*` calls | Inner to pushState |
| `g_captureMutex` | Capture dispatch data on sites (`captureOuts`/`retiring`/`captureParamIndex`) | Innermost |
| `ImageAddress::g_mutex` | Image registration (base/size/id) | Leaf |
| `g_scriptStateMutex` | The two registries of ScriptGlobals | Leaf (no other lock is taken while holding it); like `pushState` it is a lower layer of lifecycle, and the two **never nest in each other** (see `ScriptBridge::RemovePluginRegistrations`) |
| `Civ6MessageBus::mtx_` | The handler table of the message bus | `Enter`/draining happens after the lock is released (bus → lifecycle) |
| `PluginInFlight::Owner::mtx` | The condition variable wait in `WaitAll` | Only this lock is held while waiting |
| `g_pendingFreeMutex` | The pending-free handle queue | Leaf; `FreeLibrary` is always done outside the lock (a plugin's `DllMain(DETACH)` may call back into the loader) |
| `g_detourDrainMutex` + `g_detourDrainCv` | Waiting for `g_activeSharedDetours` to reach zero | The lifecycle / MinHook / capture locks have already been released before waiting (**must not** wait while holding lifecycle); the outermost `g_gameCoreTransitionMutex` is still held — it only serializes phase switching and takes no part in in-flight callback locking |

Fixed order: `transition → lifecycle →{ pushState | scriptState }→ MinHook → capture/ImageAddress`
(the message bus forms a layer of its own: `mtx_ → lifecycle`, but it never nests with the site locks).
Anywhere "plugin code may be called" (`OnLoad`/`OnUnload`/callbacks/`WaitAll`) the lifecycle lock must **be released first**.

Cross-module state always goes through accessors rather than extern variables (`LifecycleMutex()` / `GlobalBus()` /
`ScriptBridge::IsGameCorePhaseReady()` etc.). This is the established principle of the split: extern variables need cross-module visibility,
while file-level statics naturally cannot provide it, and neither can guarantee "only one copy".

> **Note that "lock order" only applies to nested holding.** Two disjoint critical sections (for example
> the block in `RemoveGameCoreDomainSiteRecords` that takes MinHook first and the block that takes pushState later,
> with the former already released in between) **do not constitute any lock-order relationship**, regardless of their physical order.
> When verifying lock order you must look at the brace scopes, not just the order of line numbers.

### 2.6 Logging

- Loader: `Logger::Init` → `%LocalAppData%\Firaxis Games\Sid Meier's Civilization VI\Logs\Civ6DllLoader_Loader.log`;
  in the process it is **truncated on the first open and appended afterwards** (using a `Local\` named mapping to record a marker, and deliberately never calling `CloseHandle` —
  otherwise the marker would be gone when GameCore is unloaded), so a single log can show both generations before and after a reload;
  the thin shell has its own `Civ6DllLoader_Shell.log`;
- The lines to look at first when troubleshooting: `LoadDLL: ruleset=...`, `InstallAll: exe image=...`,
  `GameCore attached image=.. base=.. SizeOfImage=..`, `HookSite: installed hub stub ...`,
  `ResetForReload: ...`, `RemoveGameCoreDomainSiteRecords: reset N site(s) in place (MinHook record + trampoline released; node kept: stubs embed &HookSite), marked recordStale=M; ...`,
  `Plugin deactivated, module queued for free after engine GameCore unload`,
  `Plugin module freed after engine GameCore unload: <handle>`, `Plugin deactivated, module parked (kept mapped)`.

When troubleshooting "the plugin was not loaded", check in this order: `LoadDLL: no confirmed GameCore module; plugins not loaded`
(the engine module slot is unavailable or empty → initialization was never entered), `InitializeGameCorePhase failed` (Stage B initialization failed).
Note that `g_unloadIncomplete` writes no log: it only makes the next `LoadDllDetour` return early, so when "LoadDLL logged the
ruleset but not a single plugin was loaded", first confirm that it was not blocked by this flag.

---

## 3. Plugin Model

### 3.1 Directory and Category Determination

Scanning (`common/ModScan.cpp`): content roots = `Documents\My Games\...\Mods` / Workshop,
under each root it looks for `<mod>\Binaries\Win64\Plugins\<Global|GameCore>\*.dll` (the plugin directory is fixed at `Binaries\Win64`;
`Win64Steam` only affects the shape of the exe directory, and plugin scanning does not recognize it). The pipeline runs in this order:

1. **Enabled-set filtering** (`common/EnabledMods.*`, reads `Mods.sqlite`): **the path must fall under the root of an enabled mod**,
   and only the exact mod root returned by the SQL counts (`AllowsPath` does not walk up the path looking for a `.modinfo` and then relax:
   an outer mod directory does not thereby gain authorization even if it wraps an enabled root). Comparing GUIDs alone is not enough: the same GUID may have several installed copies.
   **There is no "anchor-local exemption" whatsoever**: the only authorization criterion is `AllowsPath`. When `Mods.sqlite` cannot be read, **not a single one is loaded**
   (fail closed). `CollectScanRoots()` takes no anchor-module parameter: content-root discovery is entirely independent of the caller
   (`SHGetKnownFolderPath` for Documents, registry + `libraryfolders.vdf` for Steam/Workshop,
   walking up from the exe directory for Workshop).
2. **File version gate (mandatory)**: for each candidate, read the PE `VERSIONINFO` file version; **if it cannot be read, the whole thing is not loaded**,
   and the log keeps `Rejected plugin (no VERSIONINFO file version resource)`. Note that `0.0.0.0` and "no resource"
   are equivalent here, both count as having no version.
3. **Case-insensitive lexicographic sort**.
4. **Deduplicate by basename, take the highest version within a group**; when versions are equal, take the lexicographically smallest path
   (the same rule as `BetterThan` in the §1.3 runtime election). `Global` / `GameCore` each go through it once, and same-named candidates across categories each keep one copy.

> Version reading goes through `common/PluginVersion.*`, using `GetFileVersionInfoSizeW` / `GetFileVersionInfoW` /
> `VerQueryValueW` to read `VS_FIXEDFILEINFO` — **pure file reading, no module loading**, it does not execute the candidate's
> `DllMain`/TLS/exports, the same set of discipline as reading the runtime's `RCDATA 105`.
> The election logic is a pure function (`PluginVersion::Select`): input is a list of `{path, version}`, output is the keep/eliminate decision,
> it touches no filesystem and writes no log, so the rules can be verified directly outside the game.
>
> ⚠️ **Breaking requirement**: a plugin DLL must carry a `VERSIONINFO` file version, otherwise it will not be loaded. The way to add a version is to give the project
> a `.rc` (VS resource view → Add Resource → Version), not to add `RCDATA`.

**The game install root is not a content root**: it is not a mod container (none of the direct subdirectories `Base`/`CTP`/`DLC`/`Debug`/`LaunchPad`
contain `Binaries\Win64`, and the measured candidate set is always empty). The in-install mod roots recorded by `ScannedFiles` in the game's own `Mods.sqlite`
are `<gameRoot>\DLC\<name>` and `<gameRoot>\Base\Assets\Scenarios\<name>`; among the official DLCs only
`DLC\Expansion1` / `DLC\Expansion2` carry `Binaries\Win64`, and that is official content, not a distribution location for the loader/plugins.


Category determination (`PluginRegistry.cpp:CategoryForPath`): after normalizing the path (all lowercase, `/`→`\`), if it contains
`\plugins\global\` → `Global`, **everything else is always `GameCore`**. Note the default direction: anything placed outside the expected location is treated as
GameCore (truly unloaded every match + may only touch the GameCore image).

The category decides three things: load timing (Stage A / Stage B), lifetime (resident / truly unloaded), and the domain gate (which half of the address space is available).

### 3.2 Load Flow (`LoadPluginDllInternal`)

1. Acquire the `g_gameCoreTransitionMutex` + the lifecycle lock;
2. `GetModuleHandleExW(UNCHANGED_REFCOUNT, path)` first checks whether the module is already resident; if not, `LoadLibraryExW`,
   with `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`. `ownsRef` marks whether the reference belongs to this call.
   This step (and the `Civ6PluginKind` call immediately after it) is done **without holding the lifecycle lock**: they execute
   third-party `DllMain`/plugin exports, and that lock is the most frequently re-entered one (plugin callbacks and owner probes all need it); running someone else's code while holding it
   would stall the plugin callback path as well, or even self-deadlock; `g_gameCoreTransitionMutex` still covers the whole load process, so teardown cannot interleave;
3. Duplicate handle (the same module is already in the tracking table) → release the reference it obtained itself and return false;
4. **Category gate (before OnLoad)**: read the plugin's `Civ6PluginKind` export (low 32 = kind; high 32 = apiVersion
   goes into the log only, emitted automatically by `common/HookAPI.h`). A missing export (a plugin built from an old header) or a kind that does not match "the category
   derived from the install path" → log + release the reference this call itself obtained (`ownsRef`) and then reject the load; apiVersion **does not participate** in this
   decision, ABI compatibility is decided on the plugin side by `HookContext_IsCompatible` (`structSize` + `apiVersion`).
   **All rejections happen before OnLoad**: at that point there is no hook/patch/callback **entered through the Loader ledger** that needs rollback, and `FreeLibrary`
   only releases the reference this call itself obtained. Note that this is not the same as "not a single line of plugin code has ever run" — `LoadLibraryExW` has already executed its
   `DllMain`/CRT initialization, and the `Civ6PluginKind` call also executes inside the SEH leaf; that is a trust boundary, not a security guarantee;
5. Find the initialization export `OnLoad`; missing → reject the load (release the reference). The signature is
   `int OnLoad(const HookContext*)`: **returning 0 = initialization failure** (for example `HookAPI_RequireAll` is missing an interface),
   non-zero = success. The return value is the only failure channel, and the loader no longer treats "it did not crash" as success;
6. Assemble the `PluginEntry` (handle / path / stem name / `ownerId` = normalized full path / category /
   `inFlight` = the `PluginInFlight::Owner*` of **this load generation**),
   `SetPluginState(Loading)` (synchronously updates the admission mirror) and push it into `g_plugins`.
   **The order must not be reversed**: `SetPluginState` has to write the admission mirror of `entry.inFlight`; setting the state first would make it act on `nullptr`
   and silently fail; `inFlight` must be newly created by `BeginLifetime` (not `Resolve`), otherwise generation isolation is void (§6.1);
7. `SetActivePluginContext(ownerId, handle)` → release the lock → `CallOnLoadSafe` (wrapped in SEH) → clear the context → re-acquire the lock;
8. Initialization failure → `QuarantinePluginByOwner` (§3.3) + **module release policy** (end of §3.3), return false.
   Both sources travel the same rollback chain, only the logging is separate: **crash** (an exception during execution) and **`OnLoad` returning 0** (the plugin
   explicitly refusing). On failure it does **not register `OnMessage` and does not enter `Active`**, and the entry stays in `g_plugins` as `Quarantined`
   to block retries;
9. Has an `OnMessage` export → automatically register the message handler;
10. `SetPluginState(Active)`, load complete.

### 3.3 Unload / Quarantine / Residency

**Crash quarantine `QuarantinePluginByOwner`** (mark + roll back all registrations except patches):
`SetPluginState(Quarantined)` → deregister messages → `PluginInFlight::WaitAll` →
`RemovePluginHooks` (retire the detour slot) → `CleanupCaptureSitesForOwner` → `RemovePluginOwnedRegistrations`.
After quarantine, Stage B will never retry it: the entry stays in `g_plugins` (its state is not `Active`), and the by-path deduplication in `LoadSinglePlugin` blocks it.

**Module release policy after a crash** (`OnLoad` has already run, the plugin may have left pending detours):
- **GameCore category → enqueue** (`QueueGameCoreModuleForFree`): wait until the engine has finished unloading GameCore (together with its gameplay/ui
  Lua environments) and only then `FreeLibrary`; when freeing, `FreePendingPluginModules` nulls the handle of entries with the same handle in the tracking table,
  preventing a dangling handle from being mistakenly matched by a new module that "reuses the same base address";
- **Global category → resident**: exe-domain hooks are called at high frequency, `MH_DisableHook` does not wait for all in-flight calls, so calling `FreeLibrary` at this moment
  would turn the executing plugin code into a UAF (the cost: one image mapped until process exit);
- **Plugins with a category/ABI mismatch do not go through here**: that kind of rejection happens before OnLoad (§3.2 step 4), and the reference is released directly.

**Normal unload `UnloadPluginByOwnerId(ownerId, freeModule)`**:
`SetPluginState(Deactivating)` → release the lock → deregister messages → `WaitAll` → `OnUnload` (SEH) →
`RemovePluginHooks` (retire the slot, never physically remove the MinHook record while a plugin is unloading) → `CleanupCaptureSitesForOwner` →
`RemovePluginOwnedRegistrations` → re-lock → remove from `g_plugins` → release the lock → when `freeModule`, **enqueue for release**,
otherwise log "module parked" (resident).

> **Patches are not in the chain above**: the Loader no longer rolls back automatically (§5.8). A plugin that needs to revert should call
> `Unpatch` itself inside `OnUnload` — at that point the GameCore image is still alive and the plugin still knows its own state.

- **Global is always resident** (including after an OnLoad crash quarantine, see the release policy above): it is loaded only at startup (disabling the mod requires a restart),
  and the game thread may still be sitting in one of its exe-domain detours; the cost of residency is that plugin static state persists across sessions, so `OnLoad`
  must be re-entrant (re-register its hooks/callbacks).
  ⚠️ **Quarantine (`QuarantinePluginByOwner`) does not call `OnUnload`**, so patches made by the plugin at quarantine time are neither reverted by the plugin itself
  nor rolled back automatically by the Loader (§5.8) — **the patches stay in the game until the process exits**.
- **GameCore truly unloads**: its hooks/patches may only land inside the current GameCore image (§4.1), plus the full teardown on reload,
  so static state does not survive across matches.

### 3.4 Plugin ABI: Interfaces Delivered by Name and Version Rules

**The contract carrier is the "entry name", not a field offset.** The Loader delivers entries by name through `HookContext::Query`,
the plugin fills its module-private `HookAPI` table in `OnLoad`, and afterwards calls `api->Xxx(...)` as before.
Therefore entries may be deleted, reordered, or moved to a different domain without rejecting any plugin — as long as the name is still there, existing plugins keep working.

Three components:

- **`HookContext`** (`common/HookAPI.h`) — the only frozen structure in the ABI, the only argument of `OnLoad`:

  | Field | Offset | Purpose |
  |---|---|---|
  | `structSize` | 0 | Loader-side `sizeof(HookContext)`; **also serves as the sentinel for "are both sides the same build"** |
  | `apiVersion` | 4 | always 1; during pre-release, deleting or changing entries does not increment it |
  | `Query` | 8 | name → function address; an unknown name returns `nullptr` |

- **`HookAPI`** — the plugin-side table, its layout decided by `common/HookAPI.h`, unrelated to how the Loader orders it internally.
  This structure never crosses a module boundary, each plugin uses only its own copy; the `sizeof` of the two plugin kinds differs
  (GameCore has 7 more members), which is not a problem.

- **`HOOK_API_LIST`** (`common/HookAPI.h`) — the single source of the 80 entries, in X-macro form,
  columns = `X(entryName, returnType, params, category)`. It generates: struct members, the entry count
  `CIV6_HOOK_API_ENTRY_COUNT`, the Loader-side name lookup, and the plugin-side resolution code. Adding an entry = adding one line to the list.

**Why `structSize` is at offset 0**: it is the criterion for deployment consistency. If the plugin and the Loader are not the same build
(the header was changed but only one side was recompiled), the two sides interpret the offsets differently: a new plugin would read the stale table's `apiVersion` (=1)
as `structSize`, and `1 < sizeof(HookContext)` immediately rejects; the reverse direction likewise. Both directions exit before calling any function
pointer.

**The Loader-side `g_hookApi`** is a `const HookAPI` (`.rdata`, read-only), position-initialized with 80 items,
used inside the Loader and serving as the address source for `Query`. Its shape is nailed down by two `static_assert`s
(`sizeof(HookAPI)` and the offset of the last member must agree with `CIV6_HOOK_API_ENTRY_COUNT`),
and at startup `VerifyHookApiTableProtection` scans once more for empty items (omitting an item in aggregate initialization only silently zero-fills it,
which cannot be caught at compile time).

**Currently `CIV6_HOOK_API_VERSION = 1`, and during pre-release, deleting or changing entries does not bump the version number** — no plugin has ever been released publicly,
`1` is the only value it has ever had. **During pre-release, plugins must be recompiled with the current header**;
the version number only needs to be incremented after the first public release, see §10.3 for the rules.

**Category goes through a path independent of the table**: `common/HookAPI.h` automatically emits a `Civ6PluginKind` export for plugins
(`extern "C" __declspec(dllexport) inline`, low 32 = kind, high 32 = `CIV6_HOOK_API_VERSION`),
and the Loader reads it with `GetProcAddress` **before** `OnLoad`, **judging only the category** (the high 32 bits go into the log only).
The plugin author does not have to write a single line.

**`HookContext_IsCompatible(ctx)`** is the self-check a plugin performs before entering its main logic, comparing `structSize` and `apiVersion`:

- `ctx` is the copy compiled into the Loader (the static object returned by `LoaderCore::RuntimeHookContext()`),
  while `CIV6_HOOK_API_VERSION` and `sizeof(HookContext)` are the values compiled into the plugin — this is a valid comparison spanning both sides;
- what it cannot guard against is "the plugin never calls it at all". What really enforces the gate before `OnLoad` is the `Civ6PluginKind` export above.

**`HookAPI_RequireAll(api, &HookAPI::Xxx, ...)`** lets the plugin declare the entries it truly depends on.
`HookAPI_Resolve` always fills every cell, putting `nullptr` in the ones that cannot be found (never a wild pointer, the worst case is a null-pointer call),
so when something is missing the plugin reports the name in `OnLoad` and exits gracefully, instead of crashing at some call site.
The arguments are member pointers rather than strings, so a misspelled name is a compile error, the IDE can autocomplete, and renames are followed.

> **Threading contract note**: except for the interfaces explicitly marked "game thread only" (such as the Lua primitives and some GameCore-specific entries), most of the remaining entries are internally protected by a dedicated mutex. For concurrent access and lock ordering requirements, see the §2.5 lock table.

### 3.5 The Category Gate in Three Layers

1. **Compile time** (`common/HookAPI.h`): the plugin defines `CIV6_PLUGIN_GLOBAL` or
   `CIV6_PLUGIN_GAMECORE` in the project macros. The struct members are generated from the list via `CIV6_HOOKAPI_MEMBER_<category>`,
   under Global the 7 GameCore-specific members are **not generated**, so `api->GetPlayer(...)` directly reports
   `C2039: "GetPlayer": is not a member of "HookAPI"`. The category declaration and the struct definition live in the same header,
   and the check comes before the struct — the member set itself depends on the category.
   With neither macro defined and not being the loader → `#error`; the loader side escapes via `CIV6_HOOKAPI_BUILD_IMPL` in the vcxproj
   (under that macro the GameCore members are generated as usual, because the Loader internally needs the full table).
2. **Load time** (`LoadPluginDllInternal`, before `OnLoad`): `GetProcAddress(plugin, "Civ6PluginKind")`
   reads the "plugin-declared kind" and reconciles it with "the category derived from the install path" (`CategoryForPath`); a mismatch rejects the load — at this point the plugin has not run
   any code yet (apiVersion is also in the export, but it only goes into the log and does not participate in rejection).
3. **Run time** (`RequireGameCoreOwner`): each of the 7 GameCore-specific entries has a fallback of its own, against plugins that "do not include the header and directly
   hand-write `ctx->Query("GetPlayer")` to grab it by force"; the probe address prefers the function address supplied by the plugin, and uses
   `_ReturnAddress()` when there is none.

These three layers only cover **the interface surface and identity**; "whether the target address is open" is another layer (§4.1).

---

## 4. Plugin Interfaces (Full HookAPI Table)

80 entries, divided into four categories by "who can use them and what restrictions apply". The list is `HOOK_API_LIST` in `common/HookAPI.h`,
and both the struct and the counts are generated from it.

> Count check: **9** (address-resolution/byte-modification entries gated by target address domain) + **7** (GameCore-specific)
> + **45** (Lua primitives) + **18** (others, among which `RegisterGlobalScript` is visible only to Global) = **80**.
> Of these 80, 1 (`RegisterGlobalScript`) has its visibility noted separately only inside §4.4, and does not form a category of its own.

### 4.1 Common to Both Domains, but Gated by "Target Address Domain" (9)

| Entry | Gate |
|---|---|
| `InstallHook(target, detour, original)` | target address |
| `Patch(target, bytes, len)` / `Unpatch(target)` | range / target address |
| `RegisterGlobalCapture(providerAddress, paramIndex, out)` | target address (must be an executable function entry) |
| `ResolveByRva` / `ResolveByName` / `ResolveByRvaEx` / `ResolveByPattern` / `ResolveByVTable` | `image` parameter |

Rules (based on positive allow-list authorization, not a simple non-GameCore exclusion):

- `GameCore` category: the target must fall inside the **current GameCore image** (its only legitimate operating domain);
- `Global` category: the target must fall inside **some loaded non-GameCore module** — the exe, resident system dlls (user32/dxgi…),
  and the plugin's own module all count; **the heap, `VirtualAlloc` JIT pages, free addresses, and addresses that will later be occupied by GameCore are all rejected**.

Implementation (`PluginDomain.cpp`): `IsTargetOpenToCaller` (single point) / `IsRangeOpenToCaller` (whole range) /
`IsImageOpenToCaller` (image parameter); module determination uses `RangeInsideOneLoadedModule` — the same module handle returned by
`GetModuleHandleExW(FROM_ADDRESS)` at each end proves that the whole range belongs to one loaded module (without parsing PE).

`GetModuleHandleExW(FROM_ADDRESS)` **determines ownership strictly by that module's `SizeOfImage`** (measured:
`kernel32` base `+SizeOfImage-1` hits, while `+SizeOfImage` immediately returns FALSE / `ERROR_MOD_NOT_FOUND`=126).
So "`!hasGameCore` makes the first conjunct always true" does not constitute admission — the criterion is carried independently by the second conjunct
`RangeInsideOneLoadedModule`, and heap pages, JIT pages, free addresses and the alignment slack outside an image cannot obtain a module handle.


Other arbitrations **parallel** to the domain gate (order in §5.5): page attribute pre-check (`PluginBoundary`), patch range arbitration
(`PatchRegistry::OverlapsRegistered`), hook installation prologue window arbitration (`OverlapsHookPrologue`), teardown window
(`TargetInTearingDownGameCore`).

### 4.2 GameCore-Specific (6, three-layer restriction of compile time + load time + run time)

`GetPlayer`, `RegisterGameEvent`, `TriggerGameEvent`, `RegisterGameCoreScriptForGamePlay`,
`RegisterGameCoreScriptForUI`, `PushLuaMethods`.

Why specific: `GetPlayer` resolves the `GameCore::Context::Globals::EditPlayer` symbol (the function name on the engine side is
`EditPlayer`, and the interface name only expresses "get the player object"); the other six operate on
**gamecore's script environment** (putting closures into Lua tables, registering script globals, events). It makes no sense for Global plugins to use them:
before a match there is no object to get, and during a match they should not hold references into the GameCore domain either.

### 4.3 Lua Primitives (45) — Not GameCore-Specific

The vast majority are thin wrappers over exports of `HavokScript_FinalRelease.dll` (registered in bulk in `HavokScript.cpp` by an import table + macros,
plus `checkplayerid`). **The exception is `LuaPushBoolean`**: that DLL does not export any of `pushboolean` / `hksi_lua_pushboolean` /
`lua_pushboolean` (proven by the export table), so the only option is a raw stack write — using the hard-coded offset of `lua_State::top`,
`kLuaStateTopSlotOffset = 0x48`, to construct a TValue directly and advance the stack top (see the comment in `HavokScript.cpp`).
This is **the only `lua_State` struct layout dependency** in the whole ABI, and it must be re-verified when the game version changes; there is a writability probe before the write,
which can only stop "cannot write", it cannot stop "the offset changed and it still writes into other writable memory".

The entries themselves are **unrelated to GameCore**: what they act on is the
`lua_State*` **passed in by the caller**, so both plugin kinds are open to them. The import is resolved once in **Stage A** (that DLL is a static import of the exe and is resident);
when missing, each entry degrades to a safe default value + rate-limited logging, **without affecting plugin loading**.

Table traversal relies on `LuaNext` (`hksi_lua_next`): `LuaObjLen` only gives the sequence length and cannot get string keys, while
`LuaNext` fully implements the stack contract of Lua 5.1 `lua_next` (pushes nil on the first round, pops the value itself each round, and the key is popped once traversal ends).
It lets plugin-side C++ traverse hash tables directly, without borrowing a round-trip through a piece of Lua code.

### 4.4 Others (18, among which `RegisterGlobalScript` is visible only to Global)

- Messaging: `BroadcastMessage` / `RegisterMessageHandler` / `SendMessageTo` (§6.2);
- `Log`, image metadata `IsImageLoaded` / `GetImageInfo`;
- Symbol DB state: `GetSymbolDbState` / `GetSymbolDbMatchRatio` — the argument is an `image` scalar, there is no cross-module
  pointer to dereference, so they **do not pass the domain gate and do not take the plugin lock**, they only read `PdataMatch`'s own snapshot (§7.3).
- Localization: `LocalizationLookup` / `LocStringBytes` / `LocCreate` / `LocDestroy` / `LocLookup` /
  `LocPushArgument` / `LocToUtf8` — they go through the exports of the separate module `Localization_FinalRelease.dll`;
- Developer switch query: `IsDebugLogEnabled` — purely reads the cached value of `config.ini`, does not pass the domain gate and does not take the plugin lock.
  Plugins use it to decide whether their "per-item/per-frame" logging is emitted. `ENABLE_PROFILER` is not exposed externally:
  it only controls the Loader's own `PROFILE_SCOPE` instrumentation, and plugins have no need to query it;
- `MakeHash`: **internalized** as the loader's own native CRC32 (raw, no final XOR, bit-for-bit identical to the official `GameCore::Utilities::MakeHash`,
  and there is a compile-time self-check vector); it no longer resolves any GameCore symbol and can be computed at any time;
- Script registration: `RegisterGlobalScript` (**Global category only**, registered into every Lua environment of the engine, §6.3)
  and `UnregisterGlobalCapture` (cancels one of its own parameter capture subscriptions, §5.3) — neither is gated by the target address domain:
  the former only registers a callback, the latter can only remove a slot under its own name;
- `GetMainLuaState`: reads the exe global `LuaSystem::LuaScriptSystem::ms_apSingletonInstance` (measured RVA on DX11
  `0x2D08F88`) and the `+0x10` after dereferencing → **the engine main Lua VM** (`m_pkMainLuaState`). ★ This is a **process-level** state:
  `lua_newstate()` is created once in `Civ6App::GUIInit` and only `lua_close`d in `Civ6App::GUIShutdown`
  — **it does not become invalid and is not rewritten on a match change** (only one place in the whole exe writes `+0x10`). Returns null when not ready.
  **Both Global and GameCore plugins may call it, with no category restriction** — it is a process-level state, a resident plugin holding it
  will not dangle on a match change, so it is not in the same class as `GetPlayer`-style "short-lived GameCore domain" entries, and is not restricted by the address domain gate.

  ⚠️ **Do not confuse it with the "per-match thread state"**: Civ6 is indeed a multi-`lua_State` engine, but what GameCore creates each match with
  `IScriptSystem1::CreateLuaThread` is a coroutine derived from `lua_newthread(main_state)`,
  which is always reclaimed by `FreeLuaThread` on a match change. What this interface returns is **not** those; if what the plugin holds is some thread state,
  that is the scenario where it crashes.
  ⚠️ **Game thread only** (the Lua state is not thread-safe). Note that this is a **thread** constraint, not a category constraint:
  GameCore.dll uses `Lua::ms_CriticalSection`, while the exe side uses `Lua::Details::LockAccess`,
  which are two different instances, so calling from a non-game thread lacks the lock — the category gate cannot stop this case.

---

## 5. Hook Subsystem

### 5.1 Sites (HookSite) and the site table

`std::map<void*, HookSite> g_hookSites`: **key = the absolute address of the target function**; one address gets exactly one MinHook hook,
attached to a stub that the Loader generates itself. A single site carries three things at once:

- **plugin detour slot**: `activeDetour` + `detourOwner` (exclusive);
- **capture slot**: `hasCapture` / `captureParamIndex` / `captureOuts` (1 detour + N capture subscriptions coexist at the same address);
- **MinHook side**: `stubCode` / `minhookTrampoline` / `hookInstalled`.

`nextTarget` is the stub's tail-jump target (= the detour when one exists, otherwise = the trampoline); `recordStale` means "the previous
teardown failed to remove this MinHook record" (the next time a site is taken at the same address it is forcibly rebuilt).

### 5.2 stub (relay code generated by the loader)

`BuildHookHubStub` (asmjit generates raw x64 machine code):

- fast path: `push r10` → `mov r10, site` → `cmp [r10+hasCapture], 0` → `jne slow` →
  `mov r10, [r10+nextTarget]` → `xchg r10, [rsp]` → `ret`;
- slow path (with capture): `push rax` / `push r11` → `sub rsp, 0xE0` → save rcx/rdx/r8/r9
  and **xmm0-3** → `CaptureDispatch(regs, paramIndex, site)` → restore the parameters and xmm → restore the three cells →
  `ret` to `nextTarget`.

The fast path writes no "original values" to the stack at all: `xchg` swaps r10's original value back while putting `nextTarget` on top of
the stack, and `ret` pops straight to it — this is a **tail jump**, not a `call`, because the caller's return address is already on the
stack. The hot path touches nothing but r10 the whole way; rax/r11 are not touched by a single instruction. The reason the slow path still
has to preserve r11: a stub's hook point can land in the middle of a function, where r11 may be a live value the caller is using (for
example being used as a frame pointer, with the epilogue `mov rsp,r11` restoring the stack directly). rax/r10/r11 are indeed volatile at a
function entry, but the fact that "the hook point may land in the middle of a function" forces them to be treated as live values.

**The slow path must save xmm0-3.** The slow path actively `call`s `CaptureDispatch`, and under the Win64 calling convention it is the
**caller** at that moment, obliged to preserve the volatile registers itself; xmm0-3 are also the incoming locations of the first four
floating-point parameters. If the hooked function has a signature like `double Target(void*, double, double, double)`, not saving them lets
the original function receive garbage values overwritten by `CaptureDispatch` (and by calls inside it, such as `vsnprintf` in logging) —
in measured runs the target function simply computed 0 instead of the expected result.

Saving only xmm0-3 rather than xmm0-15: these four cells are the **incoming locations of the first four floating-point parameters**, and they
are the only thing the stub must preserve on behalf of the hooked function — provided the hook point sits at the **function entry**.

> ⚠️ **This premise is currently not enforced**. `RegisterGlobalCapture` only verifies that the provider address lands in an executable page
> (`IsTargetOpenToCaller` + page attribute probing); **it does not require it to be a function entry**; and the text above just said that
> "the hook point may land in the middle of a function", which is exactly why `r11` must be saved. Together the two mean: **if the provider
> lands in the middle of a function, xmm4-15 may be live, while the slow path only preserves xmm0-3**.
>
> All currently known callers pass function-entry addresses obtained from `ResolveByName` / `ResolveByRva`, so in practice this does not
> trip; but that is a **convention**, not a **check**. Either write "the provider must be a function entry" into the docs/headers as a hard
> contract, or add validation in `RegisterGlobalCaptureImpl`, or widen the saved range to xmm0-15 (8 `movaps` become 32).

The cost is negligible: 8 `movaps` (4 stores, 4 loads); measured (1 million iterations × 8 rounds, timed with `rdtscp`) it comes out at
**−0.004 cycles/iter** versus baseline, fully absorbed by out-of-order execution; by comparison the slow path already has a `lock_guard`
atomic operation and a `CaptureDispatch` call, which is on the order of tens of cycles.

Stack alignment: at the entry `rsp ≡ 8 (mod 16)`; after pushing the three cells it is ≡ 0, so the slow-path frame takes `0xE0` (≡ 0) — that
way rsp is still 16-byte aligned at the `call`. [rsp+0..0x20) is the shadow space, [rsp+0x20..0x40) holds the four integer parameters,
[rsp+0x40..0x80) holds xmm0-3 (16-byte aligned starting at 0x40, so `movaps` is legal), and the exit `add rsp, 0xF0` pops the frame together
with the three cells.

Two design points: `nextTarget` is read from the site field **at runtime**, so the trampoline can be filled in by `MH_CreateHook` after the
stub is generated, and retiring the detour slot does not require rewriting any executable bytes; once generated, a stub is **never released**.

**Field offsets are nailed down at compile time**: the stub accesses `HookSite` through byte offsets written into the instructions (the three
`offsetof` sites for `hasCapture` / `nextTarget` / `captureParamIndex`), and a stub is never rebuilt — so after changing the `HookSite`
layout, stubs generated with the old layout and stubs generated with the new layout may coexist in the same process. A wrong offset does not
fail compilation, raises no runtime error, and only shows up as capture silently ceasing to work or as a jump to a garbage address. What
`HookEngine.cpp` pins with `static_assert` before `BuildHookHubStub` are the **invariants the stub actually relies on**, not the measured
numbers of some configuration: `hasCapture` is exactly one byte (the stub uses `cmp byte ptr` to read just that cell), `nextTarget` is
naturally aligned (the stub reads it as a qword), and the three offsets plus `sizeof(HookSite)` all fall within `int32` (the asmjit
displacement width). The offsets themselves are computed on the fly from this TU's `offsetof`, and they hold for both Release and Debug even
though their STL layouts differ (the iterator debug layer pads the containers) — hard-coding Release's numbers would only make Debug fail to
compile (which is exactly why the Debug build once failed).

These four only guard against layout drift **within a single build**. Stub reuse across binaries is not guaranteed by them — but that premise
holds in this project: what the stub embeds is this process's `&HookSite`, and a `version.dll` self-update restarts the process, so no old
stub exists in the new process.

**Residency principle for stubs and HookSite nodes (never released)**:
1. **Immediate pointer embedded**: the stub machine code hard-codes the site node address with the immediate `mov r10, imm64(&HookSite)`; if
   the node were released, the execution flow would dereference a dangling pointer;
2. **No lock-free quiescence test**: the system cannot prove "no thread is currently stopped inside the stub execution flow or the trampoline"
   (there is no reliable atomic reference count), so freeing the memory carries a use-after-free (UAF) hazard;
3. **Allocator lifetime constraints**: AsmJit uses a block memory allocation model in which multiple stubs share the underlying memory pages, so
   freeing cannot be done at the granularity of a single stub.

Therefore, during GameCore unload cleanup (Teardown) the system only performs an **in-place state reset** on the `HookSite` so it can be
reused, keeping the underlying stub machine code and the node itself.


### 5.3 capture (parameter capture)

`RegisterGlobalCapture(providerAddress, paramIndex, out)`: address domain gate → precheck that the address is readable and lands in an
executable page → take/create the site → `hasCapture = true`, append `out` to `captureOuts` (with owner accounting). Afterwards, on every
call to the target function, the stub's slow path writes the `paramIndex`-th **integer** register parameter (rcx/rdx/r8/r9, i.e. paramIndex
0-3) into all `out`s.

**Capturing is transparent to the target function**: the slow path fully saves and restores the integer parameter registers and xmm0-3 around
`CaptureDispatch` (see §5.2), so whether or not a capture exists, and whatever `CaptureDispatch` does internally (locking, writing slots,
logging on failure), the hooked function receives exactly the same parameters as it would without the hook. This is part of the interface
contract, not luck about "the current providers happen to have no floating-point parameters".

**Floating-point parameters are outside the capture scope**: paramIndex indexes integer parameter registers only. Fetching some `double`
parameter is impossible — it lives in xmm0-3, while `CaptureDispatch`'s `regs` holds only the four integer slots. This is a deliberate
scope limit, not a defect.

Cleanup only retires the slots: `CleanupAllCaptureSites()` (clears only the subscriptions that fall inside the **current GameCore image**;
exe/resident domains are kept) and `CleanupCaptureSitesForOwner()` (withdraws by owner). **Never** is a physical unhook done for this.

### 5.4 MinHook's real semantics and this project's conventions

| API | What it actually does |
|---|---|
| `MH_CreateHook` | allocates the trampoline (a relocated copy of the original function's prologue bytes + `jmp` back into the original function), saves the backup bytes, creates a record; **does not touch the entry** |
| `MH_EnableHook` | freezes threads (moving any IP that landed at the target entry into the trampoline) → rewrites the first 5 bytes of the entry to `jmp` (or a relay) |
| `MH_DisableHook` | freezes threads (moving any IP inside the trampoline back to the target) → writes the backup bytes back to the entry (idempotent) |
| `MH_QueueDisableHook` + `MH_ApplyQueued` | batch: only sets queued flags; `ApplyQueued` restores the whole batch of entries with a **single** `Freeze` |
| `MH_RemoveHook` | if the record is enabled, runs a disable pass first; then `FreeBuffer` (frees the trampoline) + deletes the record. **When already disabled it does not touch the target memory at all** |

Convention: every `MH_*` call happens inside `Runtime::MinHookMutex()`; hook targets and `Patch` ranges are mutually exclusive in both
directions (neither side's "restore the original bytes" may step on the other).

### 5.5 Installing hooks (InstallHook) and shared hooks

The order of `InstallHookImpl` (each step blocks one class of error):

1. `PluginBoundary::IsReadable(target, 32)` / `IsWritable(original)`: bad addresses must be rejected **before taking the locks**;
   otherwise a failure by MinHook to read the target's prologue bytes leaks both locks at once;
2. take the lifecycle lock → `PatchRegistry::OverlapsRegistered` (does it conflict with a patch range?) → teardown window?;
3. owner probe (`ResolvePluginOwnerForAddress(detour)`);
4. **address domain gate** (§4.1);
5. take the MinHook lock → take/create the site (`MH_CreateHook` + `MH_EnableHook` when necessary) → exclusivity check;
6. write the slots, in this order: prepare `*original` first (= the trampoline) → `activeDetour`/`detourOwner` → **last** `nextTarget`.
   Rationale for the order: after a site is first created the MinHook side is already enabled, but at that moment `nextTarget` is only the
   trampoline (pure pass-through); a detour is only activated by "setting nextTarget to the detour", so the trampoline has to be handed to the
   plugin before publication.

`InstallLoaderDetourOnSite` is the same entry point used for the Loader's own shared hooks (`RegisterScriptData(/ForUI)`, the PushMethods
slot): detourOwner is always empty, the same detour is idempotent, and it is mutually exclusive in both directions with plugin detours.
The Loader's own **exe domain** hooks (`LoadDLL` / `UnloadDLL` / `LoadUI`) do not go through the site table and call `MH_CreateHook`
directly.

**Ownership determination for `MH_ERROR_ALREADY_CREATED`** (`GetOrCreateHookSiteLocked`): MinHook returns this status for a target that
already has a record. It has two possible sources, and they are handled in opposite ways:

- this site's node already exists (it was not created by this call) **and** the current prologue bytes match this site's `prologueBackup` →
  the leftover record is **ours** (the previous teardown's `MH_RemoveHook` failed), so `MH_RemoveHook` followed by a rebuild is allowed;
- every other case (a brand-new site, or the bytes do not match) → it can only be **someone else's** hook (a plugin's or another
  mechanism's). **Unconditionally removing it would free the other party's trampoline** (dangling trampoline pointer, and it may silently
  knock out the Lua script global registration), and would also write old bytes into the current image.
  In this case site creation at that address is refused: a newly created node is `erase`d, and an existing node is marked `poisoned` and
  permanently blacklisted.

### 5.6 Retirement, removal and teardown

- **Retire the detour slot** (plugin unload): `RetireHookSiteDetoursForOwnerLocked(owner)` — only clears `activeDetour` and lets `nextTarget` fall
  back to the trampoline. The plugin code is about to be `FreeLibrary`ed, so the stub must first stop pointing at it;
- **Remove the record** (GameCore teardown): `RemoveHookSiteRecordLocked`'s a→b→c:
  a) `MH_DisableHook` (**on failure, give up entirely** — at that point the entry bytes are not restored, and if nextTarget were pointed at
  target, the entry would still jump to the stub while the stub jumps to target, spinning in circles); b) `nextTarget = target` (in-flight
  calls are rerouted to the original function); c) `MH_RemoveHook` (frees the trampoline); then clear the site accounting;
- **Two-phase teardown** (§2.3 steps 5 and 9): first "batch disable" (a single `ApplyQueued` restores all entry bytes), then drain the
  in-flight shared detours, then rescan the site table to "remove records + reset sites in place" (**do not erase nodes**: `&HookSite` is
  permanently embedded in the stub machine code, and "no caller is stopped inside the stub" cannot be proven); anything that cannot be
  removed is marked `recordStale` and forcibly rebuilt the next time a site is taken at the same address.

### 5.7 Invariants and known leftovers

| Item | Current state | Notes |
|---|---|---|
| Sites / stubs are never released | **Hard constraint** | teardown only removes the MinHook record + resets the site in place; the node and stub are kept and reused (the stub embeds `&HookSite`, and erase would let in-flight threads read an already-freed map node) |
| stub's JIT memory | **Not reclaimable** | asmjit can only release as a whole, and multiple stubs share blocks. After site reuse the accumulation from "a new stub per generation" **is gone** (at most one stub block per address); fully reclaiming it would require switching to a self-managed `VirtualAlloc`/`VirtualFree` (which would incidentally drop the asmjit dependency) — **not done** |
| `recordStale` rebuild | Kept + guarded | before rebuilding, the target's current prologue bytes are compared against the copy taken when the record was created (`HookSite::prologueBackup`): **any mismatch poisons that site and refuses to touch the MinHook record** (fail-closed), avoiding writing bytes of an old image into the current image; only on a match are `MH_DisableHook`/`MH_RemoveHook` called |
| Reload at a different base address | Site reuse | teardown resets the site in place (`hookInstalled=false`, the stub and `prologueBackup` are kept for rebuilding); only leftovers that "cannot be removed" stay behind as `recordStale` (or poisoned) |

### 5.8 Undoing patches (`PatchRegistry`) — **the Loader does not roll back automatically**

`Patch` / `Unpatch` are a plugin's **raw byte modification** of game memory. The ledger is an **owner stack layered per target**: each
target keeps a chain of `Level`s (in application order), and each level records "the bytes of that range **before** that level wrote them"
plus the owner.

**The Loader does not roll back automatically on a plugin's behalf**. Reasons:

- **Where automatic rollback is possible it is superfluous anyway**: GameCore plugin patches are only allowed to land inside the current
  GameCore image (§4.1), and they vanish along with the mapping when the image is torn down;
- **Where rollback is genuinely needed is precisely where it is most dangerous**: the semantics of crash quarantine (§3.3) are "the module
  stays resident and its code is still in memory" — writing restore bytes into code that **may be executing right now**, with no quiesce of
  any kind (the project does have MinHook's thread freeze, but this path does not use it), is riskier than it is worth;
- **Restoring is itself a change to page protection**, and the return value of the protection restore is ignored, so a single failure leaves
  the page permanently writable (breaking W^X).

**Layering semantics**:

- **Repeated `Apply` of the same target by the same owner → refused.** The patch is already in effect, and stacking another layer only makes
  "which layer belongs to whom" untrackable; to change bytes, `Unpatch` and then `Patch`;
- **Different owners may stack patches.** Each layer stores the bytes **before that layer's write**, so when a later patcher `Unpatch`es, what
  it restores is the **lower layer's patch**, not the original bytes — every layer lands where it belongs;
- **`RevertOwned` only allows restoring the top of the stack.** A lower layer's archive records "the bytes before the layer above wrote", so
  writing it back past the layer above silently overwrites the upper patch (while that owner still believes it is in effect). To withdraw a
  lower layer, withdraw the upper one first;
- **Range arbitration uses the target's longest layer** (`Entry::Extent()`). Stacked layers on the same target overlap by construction, so no
  arbitration is needed there; arbitration only concerns **different targets**, preventing two plugins from patching interleaved ranges and
  stepping on each other.

**Bidirectional mutual exclusion with MinHook** (if two mechanisms each keep their own copy of "the original bytes" for the same stretch of
prologue bytes, they overwrite each other):

- before installing a hook: `InstallHookImpl` checks `PatchRegistry::OverlapsRegistered(target, kHookPrologueWindow)`;
- before patching: `HookPatch` checks `OverlapsHookPrologue(target, len)` — it **only considers sites with `hookInstalled == true`**
  (sites that were never Enabled have not rewritten their prologue bytes yet). Therefore **a point that is already hooked can never be
  patched**, and vice versa. The window is `PluginBoundary::kMinHookTargetSpan` (32 bytes, the same measure used for readability probing).

**Conventions**:

- `Unpatch(target)` is kept (backed by `PatchRegistry::RevertOwned`), for a plugin to withdraw **while it is still alive**. At that point the
  plugin knows its own state and knows whether its patch is still being called;
- **The Loader never withdraws a plugin's patches for it**. Patches left behind after quarantine/unload stay in the game until the process
  exits;
- `DiscardOwned(owner)` is the only "settle the books" entry the Loader calls: **it only removes records and never writes bytes back**, and is
  used at the end of a GameCore lifetime (match change / GameCore-category plugin unload). The criterion is "the target image is about to be
  remapped, so writing the old bytes back is both meaningless and may land at a new address", but the records must be removed, because after
  address reuse the residual records would block subsequent `Apply` and `OverlapsRegistered`. When a layer in the middle of the stack is
  removed, the upper layer's archive is kept as is (it recorded the bytes "including that layer" in the first place) with no
  re-arrangement.

**Both adding a range and growing it require arbitration**: a new target is compared against other targets by its full length; when an
existing target appends a longer layer, only **the part that goes beyond its current `Extent()`** is taken for comparison (a part that
shrinks or stays the same is the extent it already occupied, so there is no need to compare it again). Without this, patching the same target
with 4 bytes and then with 12 bytes could quietly cover another target 8 bytes in, and undoing it would scramble that party's bytes.

---

## 6. Plugin callbacks, Lua and the UI data flow

### 6.1 PluginInFlight (in-flight registration and draining)

`PluginInFlight::Owner`: the owner's admission mirror + in-flight counter + per-kind counters. The admission mirror has only one write entry,
`SetAllowed`, and `SetAllowed` has **two** callers: `SetPluginState` (admits when setting `Loading`/`Active`, closes for all other states)
and `BeginLifetime` (closes the previous generation when a new one is established, see below). Guarded entries use `Enter(owner, kind)`
(increment first, then check; roll back on failure) and `ReleaseCount`; unload/quarantine uses `WaitAll(owner, name)`: the predicate is
"this owner's in-flight count ≤ this thread's own depth", and if it is not satisfied within 5 seconds it logs a bounded number of times but
**keeps waiting** (never gives up).

Entries it guards: message handlers, `RegisterGameCoreScriptForGamePlay` / `RegisterGameCoreScriptForUI`, `GameEvent` triggering,
`PushLuaMethods` pushing. What it does **not** guard: plugin detours (guaranteed by teardown ordering), and Lua function pointers already
handed to the engine.

#### Isolation per load generation (`BeginLifetime`)

`Resolve(ownerId)` is "take/create", and the same ownerId always returns the **same** `Owner*`. For GameCore plugins this is wrong:
they reload every match, so the same ownerId reuses the same object across generations, and **callbacks from the previous generation that have
not yet exited get counted into the new generation**, so `WaitAll` waits on the wrong object — and reloading every match is inevitable, not
an edge case.

Therefore the load path does not go through `Resolve` but through `BeginLifetime(ownerId)`:

- **a new `Owner` is created** on every load, made the current generation, and set to `allowed = false`;
- the previous generation is **set to `allowed = false` but never deleted and never re-admitted** — out-of-lock snapshots (the message bus's
  handler snapshot, the script registry's snapshot) may still hold that pointer, so deleting it is a UAF and re-admitting it would let the
  previous generation's callbacks come back in;
- `PluginEntry::inFlight` stores **this generation's** pointer, and `SetPluginState` uses it.
  ⚠️ **But the three drain points (`QuarantinePluginByOwner` / `UnloadPluginByOwnerId` /
  `Civ6MessageBus::UnregisterOwner`) still go through `Resolve(ownerId)`**, which yields "the current generation" rather than "this
  generation" — the opposite of this section's design intent. Today this is masked by "plugin loads are serialized on the game thread" and is
  a known defect (§9.1 #4); the fix: thread `PluginEntry::inFlight` all the way down (`HandlerEntry` already stores inFlight);
- `Owner*` itself is stable for life, and `Owner` objects are never reclaimed. The old generation's counters drop to zero naturally, but
  nobody waits on it any more.

The memory ordering is not "all seq_cst" but three tiers by responsibility:

- the write of `allowed` (`SetAllowed`), the read of `activeCalls` in `WaitAll`'s predicate, and the `activeCalls` increment plus the
  `allowed` read in `Enter` — these **four** places are `seq_cst`: they must live in the same total order, otherwise the unloading side and
  the callback side may each read a stale value, creating a window where "the unloader thinks it has drained, while the callback side thinks
  the gate is still open";
- the `fetch_sub` of `activeCalls` in `ReleaseCount` is `acq_rel` (it must see all prior writes by the callbacks);
- the per-kind counters `byKind[*]` are only used by `Describe()`'s diagnostic log, are all `relaxed`, and carry no synchronization
  semantics.

Before changing the atomic orderings here, read the comment at the top of `PluginInFlight.cpp` about "the only decrement exit".

### 6.2 Message bus (`Civ6MessageBus`)

Owner-based handler registration, `Broadcast`, `SendTo`, `UnregisterOwner`; handler invocation goes through `PluginInFlight::Enter` (skipped
outright if the owner is already disabled); unregistration `WaitAll`s outside the lock.
The bus has **no** handlers of the Loader's own, and no entry point to "unregister a single handler by name": v1's `load-plugin` message entry
(any plugin could make the Loader `LoadLibrary` an arbitrary path and call its `OnLoad`, bypassing the enabled-set filtering) has been
deleted along with `InitializeLoader`, and plugins can only be loaded through `LoaderCore::LoadSinglePlugin`'s scan path.

Every `HandlerEntry` carries its own `std::atomic<bool> active`, which divides the work with the owner-level `inFlight`:

- `inFlight` governs "may this plugin still be called back" (across unload / across generations);
- `active` governs only "has this one handler been replaced" (implementation swaps within the same owner).

When a same-named handler is overridden (must be the same owner; a same-named registration from a different owner is rejected outright), the
system **only sets the old entry's `active` to false and neither drains nor waits**: at override time the plugin is still alive, and closing
the owner-level gate would also reject that owner's other callbacks. The old entry is not deleted — concurrent dispatches that already took a
snapshot still hold the `shared_ptr`, which keeps it alive until the last user exits. The cost is that an old handler may run at most one
extra time, for the call that "already took the snapshot but has not yet read active", after which it is blocked.

`UnregisterOwner`, by contrast, **does drain**: after removing that owner's table entries it `WaitAll`s outside the bus lock, and on return
it guarantees no callback of that owner is still executing. This is the bus's own outward promise and does not rely on the caller waiting
additionally — the callers (`UnloadPluginByOwnerId` / `QuarantinePluginByOwner`) also each wait once before `OnUnload` and `FreeLibrary`,
but by then they are waiting on the same `Owner` with counters already at zero, so the cost of the duplicate wait is zero.

### 6.3 Script global registration (three entries)

**GameCore domain (GameCore only)**: `RegisterGameCoreScriptForGamePlay(fn)` / `RegisterGameCoreScriptForUI(fn)`
→ registered into `g_scriptGlobals` / `g_scriptGlobalsUI` → `EnsureScriptHooksInstalled()` installs a shared hook on
`GameCore::Lua::Utility::RegisterScriptData(ForUI)` → when the game initializes scripts, the detour calls each
`fn(L)` in turn (SEH isolation + `PluginInFlight` guard), and finally calls the original function (the trampoline). The two states are
different: gameplay is rebuilt every match, while the UI one is the one used by GameCore-side interface scripts.

**Process level (Global only)**: `RegisterGlobalScript(fn)` → registered into `g_globalScriptGlobals`, and the callback runs on **a
lua_State that the engine has already set up for some script environment**. The key point is that there is **more than one** such state.

The main execution point is a shared hook on `LuaSystem::LuaExposureLibrary::Register(lua_State*)`
(`EnsureGlobalScriptHooksInstalled`); the callback runs on **the L of the thread passed into the hook**.

**Why "one registration per thread"**:

HavokScript maintains **a separate environment table** for each `LuaThread` (`LuaSystem::LuaUtils::PushThreadAndEnvironment` walks
`_G.Threads` matching thread objects one by one), and the measured result is: an interface hung on the main VM is **inaccessible** from
other states. So `RegisterGlobalScript` cannot just write one copy into the main VM; it must register once for every new
`lua_State*` it encounters. **No deduplication per state**: both engine-side call sites call it exactly once right after creating a new
thread, so the same L would not come twice anyway, and an extra layer of bookkeeping would only silently swallow the callback on a real
duplicate; callback idempotency is the plugin's own responsibility.

**Why hook `LuaExposureLibrary::Register`**:

- it is one of the very few functions **every thread passes through**: `LuaScriptSystem::RegisterThreadLibraries`
  (the UI / ForgeUI context chain) and `GameCore::ScriptSystem::CreateLuaThread` (the GamePlay chain)
  both call it directly, so both chains are covered rather than only the UI;
- it is only 5 instructions (`48 8B 0D …` reads the singleton → `E9` tail-jumps to `CCallWithErrorHandling`), and its incoming argument
  is exactly that thread's `lua_State*`;
- address resolution: `HookInfoExe` dual version (DX11 RVA `0x974CC0` / DX12 RVA `0x982AE0`; both versions' function size is
  `0x1A`), with AOB fallback taking the 3rd hit among the same batch of targets (the order is the same in both versions).

**Two pitfalls already hit (conclusions on record)**:

- hooking `AppLuaLocaleLibrary::pRegister` does not work: `ExposeLibraryToThread`'s trampoline first calls
  `hksi_lua_getglobal(L, "Locale")`, and **only when the result is nil** does it `lua_call` into `pRegister`.
  The main-menu generation has already created `Locale`, so subsequent threads skip it and `pRegister` never executes at all;
- hooking `AppLuaLocaleLibrary::Register` does not work either: its first parameter is **`mainState`**
  (`RegisterThreadLibraries` and `CreateLuaThread` both pass the main VM), so the thread's L is unobtainable,
  and it keeps running against the same state, which looks like "it stops taking effect once you enter a match".

The detour runs plugin callbacks **before** the original function, and afterwards trims that thread's Lua stack back to its original height:
the registration flow that follows does `getglobal` / `pushclosure` / `setfield` on the stack, and leftover values would make it fill in
the wrong positions.

**There is no catch-up point**: this chain is the only entry. By the time each thread environment is created the hook has necessarily
already been installed (Global plugins install it when registering in phase A, before any thread), so there is no case of "missing some
environment". There used to be a catch-up point in each of `LoadPluginsOf(GameCore)` and `UiInject`'s LoadUI, and they were later removed:
they all wrote to the **main VM**, while each thread has its own environment table, so writing to the main VM cannot reach the gameplay /
FrontEnd threads — meaning they neither solved the problem nor did anything except execute once more on the main VM.

### 6.4 PushLuaMethods

`PushLuaMethods(pushMethodsSymbol, sigType, methods[], count)` (GameCore only): the first parameter is the
**full symbol name** (e.g. `GameCore::Lua::IUnit::PushMethods`), passed verbatim to symbol resolution with no concatenation of any kind →
resolve the address → merge/dedupe/conflict precheck → install on the site (16 slots, the loader's own detour) → when the game calls that
target function, the detour writes the plugins' C closures into the table the game provides, keyed by `exposedName`; each method goes
through `PluginInFlight::Enter` before being pushed.

`sigType` (`kHookApiPushNoManager` / `kHookApiPushWithManager`) specifies the signature shape of that PushMethods and decides whether
`NoManagerDetourTable` or `WithManagerDetourTable` is used; getting it wrong produces no error at all, but the parameters are shifted
wholesale.

**There is no "deferred registration"**: when GameCore is not ready it simply fails.
**Methods must be re-registered by the plugin each match**: `ResetForTeardown` clears all slots.
**The symbol name is the plugin's responsibility**: the Loader neither infers nor concatenates, and a single wrong character is a
`resolve failed`.

### 6.5 GameEvent

`RegisterGameEvent(name, pushFn)` / `TriggerGameEvent(name, payload)` (GameCore only): registration only writes the loader's own table
(owner + name + pushFn); triggering takes the "internalized" path — take the active Lua state → `GameEvents[name].Call(...)`, with the
arguments **pushed on the spot** by the plugin's `pushFn` (the loader is the one calling it, so it can be guarded by `PluginInFlight`).

### 6.6 Lua environment partition and HavokScript

- the game **does not have just one Lua**, but **the layers must be kept straight** (both kinds of thing are called `lua_State*`, and their
  lifetimes are completely different):

  | | What it is | Lifetime |
  |---|---|---|
  | **Main VM** | the exe global `LuaScriptSystem` singleton's `+0x10` (`m_pkMainLuaState`), created by `lua_newstate()` | **process level**, `GUIInit` → `GUIShutdown` |
  | **thread / coroutine** | derived by `IScriptSystem1::CreateLuaThread` → `lua_newthread(main VM)` | **per match**, reclaimed by `FreeLuaThread` |

  `CallAccumulator<float>` / `CallProcessor` / `CallTestAll` / `CallTestAny` are all 3-instruction thunks,
  and they all read the **main VM**; GameCore's `ScriptSystem` itself **holds no `lua_State` at all**.
  `GetMainLuaState` reads the main VM. **The UI (ForgeUI) may have its own separate VM** — unverified, do not assume it is the same one;
- the Lua VM implementation is in `HavokScript_FinalRelease.dll` (a separate module), and all of the loader's `Lua*` primitives go through
  its exports. **GameCore.dll does not contain the VM**: it imports 49 lua symbols from the same DLL, but **not** `lua_newstate` /
  `lua_close` / `lua_newthread` — it can only **consume** states, not create or destroy them;
- who puts "plugin stuff" into Lua: only two ways — `PushLuaMethods` (the loader stuffs plugin closures into the game's method tables), and
  the globals/closures the plugin itself registers inside its `RegisterGlobalScript` / `RegisterGameCoreScriptForGamePlay` callbacks.
  `GameEvent`'s `pushFn` is not in any Lua table (the loader calls it fresh each time);
- therefore "plugin addresses left in Lua tables" is not a problem under the GameCore-only scope plus §2.4's release ordering: by the time the
  plugin module is released, those states are already gone along with GameCore;
- **Not supported**: PushMethods on the frontend side (`kind=3` is now explicitly rejected). Doing it in the future would need a
  "loader dispatcher"-style adapter, otherwise plugin closures could outlive GameCore.

#### 6.6.1 Struct reference (IDA-verified; read this before changing code in this area)

> Source: SO (ARM64, full symbols, **struct types are the most trustworthy**) + PC exe + GameCore.dll, three-way cross-validated.
> ⚠️ **The two platforms have different layouts**, do not mix them. Everything below is a **measured value**.

**`LuaSystem::LuaScriptSystem`** (the object `ms_apSingletonInstance` points to; the derived class
`AppLuaScriptSystem` **adds no members**):

| Offset | PC (x64) | SO (ARM64) | Member |
|---|---|---|---|
| 0x00 | 8 | 8 | `__vftable` |
| 0x08 / 0x0C | 4 / 4 | 4 / 4 | `m_iLogLevel` / `m_uiLogTypes` |
| **0x10** | 8 | 8 | **`m_pkMainLuaState`** ← the only `lua_State` |
| 0x18 | 5×**0x10** | 5×**0x18** | 5 Tuner `FastDelegate`s (Remove/Add/Update/Message/Close) |
| 0x68 / 0x90 | 0x90 | 0x90 | `HksStateSettings` |
| **Total** | **0xF8 (248)** | **0x120 (288)** | |

**The two platform sizes differ, and the entire difference comes from `FastDelegate`**: SO 24 bytes, PC 16 bytes × 5.
(This is directly confirmed by `operator new(0x120)` / `aligned_malloc_wrp(248)` in `AppLuaScriptSystem::Create`.)

**`lua_State`** (`m_apistack` is **`+0x48` on both platforms** — this is what
`HavokScript.cpp`'s `kLuaStateTopSlotOffset` is based on):

| Offset | Member | Notes |
|---|---|---|
| 0x00 | `hks::ChunkHeader` (16B) | |
| 0x10 | `m_global` (`hks::HksGlobal*`) | |
| 0x18 | `m_callStack` (`hks::CallStack`, 48B) | |
| **0x48** | **`m_apistack` (`hks::ApiStack`, 32B)** | `top` is at its `+0x00` → `[L+0x48]` is the API stack top |
| 0x68 | `pending` | |
| 0x70 | `globals` (`HksObject`) | |
| 0xB0 / 0xB8 (SO) · 0x98 / 0xA0 (PC) | `m_next` / `m_nextStateStack` | **the thread chain** — the substance of "multiple lua_State"s |

**`HksObject` (a Lua stack element, 16B)** — the basis for `RawPushTValue`'s hand-written layout:

| Offset | Size | Member |
|---|---|---|
| 0x00 | 4 | `t` (type tag) |
| 0x04 | 4 | hole |
| 0x08 | 8 | `v` (the `HksValue` union: pointer / double / uint64) |

`ApiStack` = `{ top, base, alloc_top, bottom }` (8B each), with `top` at `+0x00`.

> Before changing the Lua-related offsets in `HavokScript.cpp` / `PdataMatch`, verify against the tables above. Any game version change requires re-verification.

---

### 6.7 UI injection (`UiInject`)

The main menu's frontend UI does not go through the plugin ABI: it is the loader itself hanging a context into the game's ForgeUI tree.

1. **Resources**: `UiInject::ExtractResources()` (phase A, see §1.4) extracts the
   `Civ6DllLoader_FrontEndUI.{lua,xml}` of RCDATA 103/104 into `<exe directory>\Civ6DllLoader\`; it skips if the target file already
   exists (users may edit it on disk), writes with `CREATE_NEW`, and treats "someone else already put it there" as a benign race;
2. **Hook**: `UiInject::Install()` detours `MainMenuState::LoadUI` (an independent exe-domain hook, unrelated to the site table,
   see §5.5). The detour calls the original function first (FrontEnd and InvitePopup are created by the game itself), then
   `RunInjectionSafely`;
3. **Injection** (`InjectFrontEndUi`, executed only on the game/UI thread; on re-entry it sets `g_refreshRequested` and defers to the next
   `LoadUI`): AOB resolves the `ForgeUI::UIManager` global slot → take the FrontEnd
   context from `MainMenuState + 0x230` → `AllocateControl<LuaContext>(mgr)` to create the root context → `ChangeParent` to attach it under
   FrontEnd → take vtable `+0x200` and call `Initialize(baseName)` (a virtual slot, no hard-coded address) to load
   `Civ6DllLoader/Civ6DllLoader_FrontEndUI` (the xml's `Name = AdditionalFrontEndUI`);
4. **Mod UI**: walk the **directory tree of enabled mods**, find `FrontEndUI_*.xml` by file name (both the prefix and the `.xml`
   extension are case-insensitive), and **do not read `.modinfo`** — so mod authors do not need to register it in `ImportFiles`, they just
   need to name the file `FrontEndUI_<anything>.xml` and put it at any level of the mod directory. The base name is taken from the file's
   VFS path relative to the mod root (separators normalized to `/`, `.xml` stripped), which is exactly the parameter `Initialize` wants.
   Recursive traversal does not follow directory symlinks by default, plus there is an 8-level depth cap, to avoid an abnormal directory
   slowing down the main-menu thread; enabled or not is recognized only via the exact mod root returned by `Mods.sqlite` (§3.1), and mods
   that are not enabled are never scanned;
5. **Refresh and reclamation**: rebuild when `g_frontEndContext` changes (FrontEnd replaced); when the same FrontEnd receives
   `g_refreshRequested` (the previous injection failed), first destroy the loader's own root context with the exe-exported `DestroyChild`
   and then rebuild. When destruction fails or a child-context injection fails, the pointer is registered in `g_rootContext` / `outAllocated`
   and handed to the next refresh for reclamation, so it is neither destroyed twice nor does a reference get lost;
6. **Known leftover**: deciding "is this a new FrontEnd" uses **pointer identity comparison**; if the game frees the old object and the new one
   happens to land at the same address (ABA), that refresh is judged "the same object" and returns early, and the Mod UI only comes back the
   next time the FrontEnd address changes. Changing the criterion would need a game-side object generation counter, which the loader cannot
   obtain.

---

## 7. Image Resolution and Symbol DB

### 7.1 ImageAddress (image registry)

`ImageAddress` is the single entry point for "which PE images in the process are available + how to turn an RVA into an effective address":

- `HookImageId`: `1=ExeDx11`, `2=ExeDx12`, `3=GameCoreBase`, `4=GameCoreXP1`, `5=GameCoreXP2`
  (3/4 are only values in the ABI and are unreachable at runtime. **What really prevents them from taking effect is two places**: ① the sidecar container only accepts 1/2/5;
  ② `InitializeGameCorePhase` hard-codes `GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll")`,
  and it is the only place in the whole project that calls `AttachGameCore`; even though `ImageAddress::IdentifyGameCore` itself contains
  Base/XP1 rules, they are never triggered at runtime);
- the exe is auto-identified by file name on first query (`CivilizationVI.exe` / `CivilizationVI_DX12.exe`);
- GameCore is registered explicitly by the lifetime code: `AttachGameCore(HMODULE)` / `DetachGameCore()` / `LoadedGameCore()`;
- `Contains(image, addr)` / `GetInfo(image, out)` (id/base/sizeOfImage) / `ResolveByRva(image, rva, span)`.

"GameCore is a short-lived domain" is the foundation of the whole design: it is attached when a match starts and detached when the match ends
(the engine's `UnloadDLL`), so addresses may change at any time; whereas addresses of the exe / resident modules are stable for the process lifetime.

### 7.2 sidecar (symbol DB container)

Artifact: `DllLoaderRuntime/Civ6DllLoader.symdb.bin.xp` (~3.9 MB, three modules: ExeDx11 / ExeDx12 / GameCoreXP2),
compiled via `Sidecar.rc` into **RCDATA 102** and embedded into the runtime. Load order: first look for the side-load file in the same directory,
`Civ6DllLoader.symdb.bin` (hot replacement during development), then fall back to the resource.

Two layers of wrapping (details and invariants are in the document at the top of `tools/symdb.py`):

- **container `C6SD` (only v1, no v2/v3/v4 branches)**: 32B header + `ModuleDesc[]` (64B per entry, carrying imageId/baseSizeOfImage/baseTimeDateStamp
  and the offsets of each block) + 5 data blocks per module (pdata / symbol table / vtable slots / name heap / AOB), all 8B aligned;
- **compression envelope `C6XC`**: `b"C6XC" + algo(=1, LZMA1) + originalSize + .lzma header + stream`; a bare `C6SD` is passed through directly.
  The LZMA1 parameters (preset 9|EXTREME, dict 16MB, lc3/lp0/pb2) are fixed by the generator side; the runtime only hands the 5 bytes of
  props from the `.lzma` header to `LzmaDecode` as-is (`dest` is the dictionary, the dictionary never overflows), but **validates before decoding**: props/dictionary valid,
  envelope `originalSize` in a reasonable ratio to the compressed stream length, 512MB hard cap — a malformed sidecar never triggers a large allocation,
  and `Init` additionally has a `try/catch` fallback.

### 7.3 PdataMatch (cross-version RVA correction)

After a game update GameCore's RVAs change, while the symbol DB stores **old RVAs** (matching the old pdata signature). `PdataMatch` is responsible for correcting
`old_rva` to the `new_rva` in the current image:

- `Init(runtimeModule)`: read the sidecar (file → resource) → unwrap the envelope → build a context per module. The whole thing has a `try/catch` fallback:
  allocation/parse exceptions triggered by a malformed sidecar only fail this load, and never escape the worker thread;
- `BuildNewTable(imageId, target)`: parse the `.pdata` (exception directory) of the target PE image, compute the feature signature `(begin_rva, size, unwind_hash)` for each record
  (`unwind_hash` is a FNV-1a64 hash), and perform the matching decisions in order:
  1. **fast path identity mapping**:
     - if the DRM-stripped normalized `SizeOfImage` and `TimeDateStamp` match exactly, judge it to be the same build and establish the identity mapping directly;
     - if the timestamps differ, but all entries of the whole table agree item by item on `(begin_rva, size, unwind_hash)` (pure binary recompile), also take the identity mapping;
  2. **cross-version heuristic matching pipeline**:
     - **disk cache**: try to load the cache file by `(new table fingerprint, sidecar fingerprint)` (`LoadCache`/`SaveCache`), and take effect directly after a sampling validation passes;
     - **anchor extraction and interpolation**: search for stable anchors via window hashing, extract a monotonic anchor chain via the longest increasing subsequence (LIS), interpolate linearly between anchors,
       and extrapolate outward at both ends;
     - **prologue and AOB validation completion**: compute the new function prologue hash and compare it with `normHeadHash` to drop mismatches; then perform head-hash local recovery and function-body AOB recovery,
       finally merging the leaf-function AOB and vtable-slot back-inference results (into `leafMap`).
  
  *Supplementary note on the DRM-stripped view*: the `SizeOfImage` used in the build decisions above is all normalized by `NormalizedSizeOfImage`
  (strip the consecutive trailing `.bind` sections backwards from the last section, then recompute with section alignment). The original EXE carries a `.bind` section, and its raw `SizeOfImage`
  is 0x33000 larger than that of the DRM-stripped modified version, yet the code and `.pdata` of the two are byte-for-byte identical. Therefore, in any decision about "whether this image is the same build"
  (such as `BuildNewTable`, `ExeMatchesAnchor`), both sides must compare using the normalized size; whereas all memory out-of-bounds and buffer boundary checks
  must use the raw PE size (`OptionalHeader.SizeOfImage`).
- after a cache hit, one sampling self-validation is done using the head/tail + at most 64 evenly spaced entries (`ValidateCachedMap`). It only guarantees "structurally like
  the output of this match" (indices in range, at least one of signature/head hash/AOB holds), **not a guarantee of cache trustworthiness**: the cache file
  lives in the same game directory as the sidecar with the same permissions, and whoever can rewrite it could just as well replace the runtime directly;
- `CorrectRva` / `CorrectByName` / `CorrectVTableByName` only look up tables; build time (vtable back-inference) and runtime queries share
  the same `CorrectRvaInTables` semantics (binary search + capped 64-entry back-scan; in-function offsets are only allowed when `size` is unchanged;
  gap / back-scan exhaustion falls back to `leafMap`);
- returning 0 / nullptr = correction failed (callers handle it on their own failure paths);
- **state query** (`GetMatchState` / `GetMatchRatio`, the backends of `HookAPI::GetSymbolDbState` /
  `GetSymbolDbMatchRatio`): expose the results of the criteria above to plugins, so that they can judge whether correction is available before relying on
  hard-coded old RVAs. `GetMatchState` distinguishes five states — `NoContext` (the sidecar has no module for that image) /
  `NotBuilt` (module present but no table built) / `BuildFailed` (table build failed; not correctable in this session) / `Identical`
  (same build, RVA identity) / `CrossVersion` (cross-version alignment succeeded). The two flags `buildAttempted` and `tableReady`
  together separate "not yet reached" from "tried but failed" — `tableReady=false` alone cannot distinguish the two.
  `GetMatchRatio` returns a real match ratio only for `CrossVersion` (the proportion of non-`kUnmatched` in `map`),
  returns 1.0 for `Identical`, and 0.0 otherwise. Both are pure snapshot reads, used only for diagnostics/degradation decisions — **whether a single point can be resolved
  is always determined by the return value of `CorrectRva` / `CorrectByName`**.

### 7.4 Address resolution entry points and fallback order

- **plugin-visible** (`HookAPI`, all of them must pass the `image` domain gate): `ResolveByRva` / `ResolveByRvaEx` (explicit section) /
  `ResolveByName` / `ResolveByPattern` (AOB text, with `index` taking the N-th hit in ascending order within the section) / `ResolveByVTable`;
- **symbol DB state query** (does not pass the domain gate, does not take the plugin lock): `GetSymbolDbState(image)` /
  `GetSymbolDbMatchRatio(image)` — the parameter is the `image` scalar, with no cross-module pointers, so it only needs to read
  `PdataMatch`'s own snapshot;
- **section-relative RVA (`ResolveByRvaEx` + non-`kSectionImage`)**: the section coordinates found must pass three
  checks before they may be converted to an address — zero-length rejection (same convention as `ResolveByRva`), `rva < sectionSize`,
  `span <= sectionSize - rva` (subtraction comparison, avoiding underflow of `sectionSize - rva`), and finally the addition overflow of
  `sectionRva + rva`. The whole-image range check of `ImageAddress::ResolveByRva` alone **cannot replace**
  the section range check: an address beyond the section end is still inside the image and would silently resolve to a valid pointer;
- **Loader internal** (not through the plugin ABI, and not taking the plugin lock): `LoaderCore::ResolveExeTarget(HookInfoExe)` and
  `ResolveDataByAobCore(image, aob, index)`;
- **exe domain dual versions**: `HookInfoExe` = each variant (DX11/DX12) gets one set of "RVA + unique AOB", and at runtime one set is selected according to the current exe:
  RVA first (corrected via pdata), AOB as fallback/validation. Examples: `kExeLoadDLL` / `kExeUnloadDLL` /
  `kExeGetRuleSet` (with `index` to disambiguate sibling functions with identical code);
- **data slots**: also an AOB of "instruction by instruction + `disp32` wildcard", resolving a RIP-relative global address (`UIManager`,
  `ms_apSingletonInstance`, `ms_pkCurrentGame`, etc., see `kAob_UIManager` in `UiInject.cpp`).
  AOB generation/verification is handled by `tools/symdb.py aob`.

### 7.5 External modules

- `Localization_FinalRelease.dll`: resolve `Lookup` / `PushArgument` / `String` destructor / `toUTF8` etc. by **export name**;
  a missing one only degrades the corresponding wrapper (returns empty string/nullptr) and does not affect other functionality;
- `HavokScript_FinalRelease.dll`: resolves about 40 `hksi_lua*` / `hks*` exports, as the implementation of the vast majority of `Lua*` primitives;
  **resolved once in phase A** (this module is statically imported by the exe and resident, so the import addresses are constant, and there is no reason to "re-resolve");
  missing imports → every Lua API entry degrades to a safe default + rate-limited logging, **without affecting plugin loading**. The only exception is `LuaPushBoolean`: that DLL does not export any `pushboolean`,
  so the implementation is a raw stack write that hard-codes `lua_State + 0x48` (`RawPushTValue`), and that offset must be re-verified on every game version change.

### 7.6 Toolchain: `tools/symdb.py` (the only entry point)

The symbol DB production line is consolidated into one entry point with subcommands:

| Subcommand | Purpose |
|---|---|
| `json-exe` | from IDA exports (`.funcs.txt` + `.rdata .asm`) + DRM-stripped exe → exe-version symdb JSON |
| `module` | JSON + corresponding PE → single-module `C6SD` container (depends on `aob_helper.exe` / `normhash_helper.exe`) |
| `pack` | multiple single-module containers → `Civ6DllLoader.symdb.pack.bin` (`--module` may be repeated, `--list` only queries) |
| `compress` | `pack.bin` → `C6XC` + LZMA1 envelope `.xp` (with SHA256 roundtrip verification) |
| `validate` | independently validate `.bin` / `.xp` using the same parsing as the runtime |
| `aob` | generate/verify the loader's AOB constants from the mask fingerprints in the container (`--emit-cpp` emits a paste-ready constant block) |
| `all` | run the whole production line in one command: `module` ×3 → `pack` → `compress` → `validate` → deploy to `DllLoaderRuntime/` → clean the intermediate artifacts |

**Deployment order is part of the production line**: first `validate` the candidates (`.pack.bin` and `.xp`), and only publish after they pass; publishing goes through
"temporary file inside the target directory → verify the copy → `os.replace` atomic rename", and if any step fails the deliverable stays as it was (it is neither
overwritten by a half-written file, nor replaced by a bad candidate when validation fails). When validation fails the candidate is kept in `tools/` for diagnosis.

`rva_to_symbol` (RVA → symbol) covers **the three images gamecore / dx11 / dx12**: each image's symbol table is compressed into one
zlib blob, and the Rust side `include_bytes!` embeds it into the exe at **compile time** — the deliverable is still a single file, and a query only decompresses
the selected one. Rebuild: `python tools/gen_rva_map.py` then `tools/rva_to_symbol/build.bat` (one shot, including build and install).

**Reproducibility boundary** (a settled conclusion in the tool docs): `JSON → .bin → pack.bin → .xp → deploy/validate` guarantees **byte-for-byte reproduction**;
`IDA → JSON` **does not** (the JSON is a snapshot of one particular IDB, the function set depends on IDA's analysis state; all names come from the IDB).

---

## 8. Projects, Build and Deployment

### 8.1 The two projects (`DllLoader.sln`)

| Project | Output `TargetName` | Responsibility |
|---|---|---|
| `DllLoader/DllLoader.vcxproj` | `GameCore_XP2_Shell_FinalRelease` (shell) | Loader installer for the first use of this class of mod (scan mods + version election + install `version.dll` + prompt restart); zero hooks, does not start the runtime, does no runtime self-update |
| `DllLoaderRuntime/DllLoaderRuntime.vcxproj` | `Civ6DllLoader.runtime` (the Loader proper) | all hooks / sidecar / HookAPI / plugin lifecycle |

Both projects are x64, C++20 (`/std:c++20`), `/utf-8`. Key preprocessor macros:

- `DllLoaderRuntime`: `ASMJIT_STATIC` (link asmjit statically) + **`CIV6_HOOKAPI_BUILD_IMPL`** (declares "I am the loader side",
  so that the category gate in `common/HookAPI.h` neither `#error`s nor renames member names);
- both have `_CRT_SECURE_NO_WARNINGS` / `_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS`;
- Release for both projects uses the static CRT (`MultiThreaded` = /MT), Debug uses `MultiThreadedDebugDLL` (/MDd).
  Therefore HookAPI only allows PODs/pointers to be passed: **no `std::` containers or heap memory beyond "whoever allocates frees" may cross the module boundary**
  (paired interfaces such as `LocCreate`/`LocDestroy` are designed under this constraint);
- the Debug configuration has pre-existing `LNK4075` / `LNK4098` warnings; that is normal.

### 8.2 third_party and link dependencies

| Component | Use | Files actually compiled in |
|---|---|---|
| `third_party/asmjit_src` (+ `asmjit_build` / `asmjit_build_dbg`) | generate site stubs (the only use; **not** used anywhere else) | referenced via include path; links the prebuilt `libAsmJit.x64.lib` / `libAsmJit.x64.debug.lib` |
| `third_party/hde` | MinHook's length disassembler | `hde64.c` (`NormHash.cpp` also uses it directly) |
| `third_party/lzma` (LzmaDec) | decode the sidecar's `C6XC` LZMA1 stream | `LzmaDec.c` + `LzmaDec.h` |
| `third_party/sqlite` | runtime-side reading of `Mods.sqlite` (enabled mod filtering) | `sqlite3.c` + `sqlite3.h` |
| prebuilt MinHook | the actual hooking implementation for sites and exe-domain hooks | `DllLoader/resources/libMinHook.x64.lib` (**the repo contains only headers + the lib, no `hook.c`**) |

> Note: MinHook's behavior (`MH_EnableHook`'s thread-freeze semantics, trampoline construction, "do not touch target memory when already disabled")
> **cannot be verified** within this repo — only the prebuilt library and headers exist. That table in §5.4 is a description of the library's behavior,
> not a conclusion drawn from this repo's sources.

### 8.3 Build

```bat
call "E:\VisualStudio\Products\VC\Auxiliary\Build\vcvarsall.bat" x64
"E:\VisualStudio\Products\MSBuild\Current\Bin\amd64\MSBuild.exe" DllLoaderRuntime\DllLoaderRuntime.vcxproj /nologo /m /v:m /p:Configuration=Release /p:Platform=x64
```

`Configuration` takes `Debug` / `Release`; the same holds for the shell project. After changing `common/HookAPI.h` you **must rebuild both configurations**
(it is the plugin ABI, and the payload lives in the runtime).

### 8.4 Artifacts and deployment locations

| Artifact | Target location |
|---|---|
| `x64\<cfg>\Civ6DllLoader.runtime.dll` (renamed `version.dll`) | the game exe directory (`Base\Binaries\Win64Steam\` or `Win64\`) |
| `x64\<cfg>\GameCore_XP2_Shell_FinalRelease.dll` + `Civ6DllLoader.runtime.dll` | `Binaries\Win64\` of the enabled mod |
| `DllLoaderRuntime\Civ6DllLoader.symdb.bin.xp` | deployed directly by `symdb.py all` (compiled into the runtime's RCDATA 102) |
| `DllLoaderRuntime\Resources\Civ6DllLoader_FrontEndUI.{lua,xml}` | RCDATA 103/104, extracted by `UiInject::ExtractResources` into `<exe directory>\Civ6DllLoader\` |
| version resource of `x64\<cfg>\Civ6DllLoader.runtime.dll` | RCDATA **105** (`CIV6_DLL_LOADER_VERSION_RESOURCE_ID`): install/self-update only reads it, never running the candidate DLL's `DllMain`/TLS/exports |

---

## 9. Known Trade-offs and Residual Risks

The following are design constraints and known trade-offs that the system architecture explicitly accepts after weighing (not unhandled defects):

| # | Symptom | Cause / mechanism | Impact | Status |
|---|---|---|---|---|
| 1 | the JIT memory of site stubs is never reclaimed | **root cause**: `imm64` in the stub machine code embeds `&HookSite` permanently, and "no caller is stopped inside the stub" cannot be proven (no reliable count), so releasing it means UAF. asmjit can only release whole blocks, and sharing one block among multiple stubs is the second, compounding cause | within the process lifetime there is one more block only per new **distinct target address**; the same address reuses the same block and does not accumulate across reinstalls | accepted (hard constraint). If the site count explodes in the future, stubs could become "one `VirtualAlloc`/`VirtualFree` per site" combined with caller counting, which would also drop the asmjit dependency |
| 2 | the **old image byte write-back** risk when `recordStale` rebuilds | the old MinHook record only holds a copy of the leading bytes taken when the record was created, with no version information | before rebuilding, compare the current leading bytes with the copy (`HookSite::prologueBackup`): on mismatch, poison that site and refuse to touch the record (fail-closed) | guard rail added (§5.7) |
| 3 | Global plugins are never unloaded | domain model: Global hooks the resident exe | plugin static state survives across matches and across save loads | convention: the `OnLoad` of a Global plugin must be idempotent and must not assume "it runs only once" |
| 4 | plugin-owned threads / front-end Lua closures are not protected by the loader | these are outside HookAPI's coverage | concurrent calls at the instant of unload may cause dangling accesses or crashes | documented; without "thread registration" it cannot be fixed at the root |
| 5 | domain gates are installed only on entries of the "change address / give address" kind | the design principle is **authorizing by target address**, not restricting plugin behavior | registration and callback entries have no gate | intentional: the boundary holds through "GameCore-exclusive entries + domain rules" together |
| 6 | teardown relies on the design assumption "any in-flight GameCore call is treated as unrecoverable" | the engine's own `UnloadDLL` also unmaps that memory | absolute safety is unattainable | accepted: equivalent to the engine's native behavior |
| 7 | sites in the exe domain are never unhooked | the exe is resident, and unhooking would introduce extra state | the hooks live until process exit | intentional |
| 8 | toggling a mod does not take effect; a restart is required | there is no reconcile path | user experience | intentional: state consistency takes priority over convenience |
| 9 | UI injection depends on signatures, and a match failure degrades silently | a game update changed the target code | the panel does not appear (there is a log record), everything else works normally | accepted |
| 10 | data slot location depends on the AOB fallback instruction sequence | compiler / game updates | a location failure returns 0 and the corresponding feature degrades | accepted (logged) |
| 11 | sleep detection requires the host exe name to look like `CivilizationVI*.exe` | prevents "another process loading this `version.dll` from the exe directory" from pulling the Loader + Global plugins in | in sessions using a renamed exe / a third-party launcher, the Loader sleeps silently (installs no hooks); `OutputDebugString` leaves a trace | intentional (strict first) |
| 12 | patches applied by plugins are **not rolled back automatically by the Loader** | automatic rollback would have to write restore bytes into possibly executing code at the moment "the plugin has already crashed", with no quiesce; and the saved bytes may be someone else's trampoline bytes | after quarantine/unload the patch stays in the game until process exit; plugins must manage the `Unpatch` timing themselves | intentional (§5.8) |

### 9.1 Known unhandled issues (implementation defects, to be fixed)

The table above is "accepted trade-offs". The ones below are **not design outcomes but defects of the current implementation**; when making changes, do not mistake them for intentional:

| # | Issue | Location | Description |
|---|---|---|---|
| 1 | the teardown window is cleared to empty when image information cannot be obtained | `ResetForReload` (the `LoaderCore::Teardown::SetWindow(0, 0)` branch) | when `base == 0` the protection check returns false outright, which amounts to switching the protection gate off at the most uncertain moment; yet `RemoveGameCoreDomainSiteRecords` in `HookEngine.cpp` **deliberately does not clear** in the same situation (it only calls `SetWindow` when `GetInfo` succeeds) — the two contradict each other |
| 2 | status code `3` (reserved Frontend) and several empty slots | `common/HookAPI.h` | these belong to unimplemented functionality and should not be kept long-term in the core ABI enum definition |
| 3 | `ShouldSkipPluginFile` uses a filename blacklist rather than a whitelist | `common/ModScan.cpp` | a latent hazard: if the official build later adds a DLL in that directory, it may be mistakenly loaded as a third-party plugin |
| 4 | draining waits on the "current generation" instead of the "this generation" `PluginInFlight::Owner` | `QuarantinePluginByOwner` / `UnloadPluginByOwnerId` in `PluginRegistry.cpp`, and `UnregisterOwner` in `Civ6MessageBus.cpp` | all three go through `Resolve(ownerId)`, the opposite of the per-generation design of `PluginEntry::inFlight` (§6.1). When the same ownerId is loaded concurrently, the old generation's in-flight callbacks never get drained → the old generation module is released → UAF. Currently masked by "loading is serialized on the game thread" |
| 5 | **GameCore plugin detours have no in-flight counting** | `PluginInFlight.h` (self-declares that it does not cover detours), `WaitForDetourDrain` in `HookEngine.cpp` | draining only waits for the Loader's own 5 shared detours. Restoring the entry bytes excludes only **new** calls, not **in-flight** ones; afterwards `FreeLibrary` may unload onto a thread still inside the plugin detour. Global avoids this with "park, never unload", GameCore has no compensation (§9 table #4 describes the same class of risk) |
| 6 | `PdataMatch` still judges identity when "the header identity matches but the pdata fingerprints differ" | `BuildNewTableImpl` in `PdataMatch.cpp` | after detecting the inconsistency it only logs and still sets `identical = true`; `CorrectRvaLocked` therefore returns the old RVA directly and skips all mapping validation (fail-open). It should go through `AlignTables` instead, and let `BuildNewTable` return false on zero match |
| 7 | the release queue for GameCore plugin modules has a single outlet and is blocked by a condition | `UnloadDllDetour` in `LoaderHooks.cpp` | only after confirming that the engine cleared the hModule slot does it clear the window + flush the queue + reset `g_unloadIncomplete`, **with no else branch**. Once that condition does not hold: modules linger and leak, the teardown window is never cleaned (`Patch` then permanently refuses the old range), and `g_unloadIncomplete` stays true so the whole session loads no further GameCore plugins |
| 8 | the `recordStale` branch of `HookEngine` does not clear the capture fields | `RemoveGameCoreDomainSiteRecords` in `HookEngine.cpp` | the success branch clears `hasCapture`/`retiring`/`captureOuts`, the failure branch only pulls the detour slot. At that point the entry still jumps to this site's stub and `hasCapture` is still true, while the plugin memory that `captureOuts` points to may already be freed → write-side UAF |

---

## 10. Appendix

### 10.1 Glossary

| Term | Meaning |
|---|---|
| shell | `GameCore_XP2_Shell_FinalRelease.dll`: the Loader installer for the first use of this class of mod; zero hooks, loaded by the engine only when the Loader is absent |
| Loader / runtime | `Civ6DllLoader.runtime.dll`: the module that actually does the work; `version.dll` is its copy |
| site | a record keyed by the **target absolute address**, the shared carrier for the three things hook / capture / record |
| detour slot | the position inside a site for "at most one plugin detour", exclusive, taken over by a later arrival |
| capture | the slot inside a site for "read some parameter / write some parameter", several of them can be shared |
| shared hook | when multiple plugins (or multiple internal needs) land on the same address, only one `MH_CreateHook` is installed and the site dispatches centrally |
| stub | machine code generated by asmjit: after entering from the MinHook trampoline it looks up the site, runs the dispatch logic, then forwards to the original function |
| trampoline | the copied instruction block MinHook prepares for "calling the original function" |
| record | the target bytes a site backs up before installation, used to restore when unloading |
| domain gate | a dual check of caller domain and target address on "change address / give address" entries |
| kind | plugin category (Global / GameCore), determines which block of memory it may hook |
| sidecar | symbol DB container (`C6SD` v1, optionally wrapped in a `C6XC` + LZMA1 envelope) |
| pdata correction | mapping old RVAs to the current image's RVAs using `.pdata` exception table signatures |
| fingerprint | the pdata-set hash of an image, used to decide "whether the version is the same" and as a cache key |

### 10.2 How to extend

#### Adding a HookAPI entry

1. Append one line `X(entryName, returnType, params, category)` at the **end** of `HOOK_API_LIST` in `common/HookAPI.h`.
   The struct member, `CIV6_HOOK_API_ENTRY_COUNT`, the loader-side name lookup and the plugin-side resolution code are all generated from this one line; nothing else needs changing;
2. `entryName` is a contract from then on: it is both the struct member name and the lookup key of `Query` (stringified via `#entryName`
   in the manifest), so renaming equals deleting an entry and adding another. Append at the end so that the positional initialization of
   the loader-side `g_hookApi` only needs one item added at the corresponding position;
3. when `category` is filled in as `kGameCore` (only meaningful for GameCore), the implementation must call `RequireGameCoreOwner`
   as a runtime fallback;
4. if it is of the "change address / give address" kind: the implementation must pass `IsTargetOpenToCaller` / `IsRangeOpenToCaller`;
5. implement the corresponding `*Impl` in the **owning module** (address resolution → `AddressResolve.cpp`; script/Lua/GameEvent/PushMethods →
   `ScriptBridge.cpp`; plugin lifecycle → `PluginRegistry.cpp`; hook installation/capture → `HookEngine.cpp`),
   then fill in its address **in manifest order** in the `g_hookApi` positional initialization table of `HookLoaderApi.cpp`.
   The two `static_assert`s above `g_hookApi` (`sizeof` + last-field offset) catch "added a manifest item but forgot the initializer",
   and `VerifyHookApiTableProtection` also scans for empty items at startup — a missing item shows up as that name returning
   `nullptr` through `Query`, which the plugin side catches via `HookAPI_RequireAll`;
   > the table is `const` and the `*Impl` functions must not be `static` (`g_hookApi` takes their addresses);
   > conversely `HookLoaderApi.cpp` includes all subsystem headers, and no lower module includes it back —
   > it is the composition root and takes no part in the implementation.
6. building the loader side requires `CIV6_HOOKAPI_BUILD_IMPL` (already defined in the project);
7. do **not** touch the order of existing rows (`g_hookApi` is positionally initialized), and do not change `apiVersion` (see 10.3).

#### Adding an internal hook (for the loader's own use)

- exe / resident modules: just `MH_CreateHook` + `MH_EnableHook` (the domain is stable, no site model needed);
- GameCore: go through the site model (`InstallLoaderDetourOnSite` and the like), so that teardown can remove them uniformly;
- need to read parameters / write return values: use capture slots, do not write a second mechanism of your own.

#### Adding a plugin category

1. `common/HookAPI.h`: `CIV6_PLUGIN_KIND_VALUE` is not a hand-filled constant but **derived from the plugin macro**
   (`#if defined(CIV6_PLUGIN_GLOBAL) -> 1u / #elif defined(CIV6_PLUGIN_GAMECORE) -> 2u`).
   So adding a new category = adding a new `CIV6_PLUGIN_<X>` macro + one `#elif` branch for the value (3 and up are reserved bits;
   3 is already reserved for a future Frontend in the header comment); there is also an `#ifndef` fallback block at the end of the file that must be kept in sync;
2. load-time mapping: `KindToCategory` + the directory-name decision of `CategoryForPath` (both in `PluginRegistry.cpp`);
3. domain rules: add a **positive** rule in `IsTargetOpenToCaller` for "which block of memory this category may touch";
4. teardown policy: work out when its module may be `FreeLibrary`ed (currently only the GameCore category queues for release).

### 10.3 Rules for changing the ABI

- **entries evolve by name and do not occupy offsets**: adding an entry = adding one manifest line (`apiVersion` unchanged); deleting an entry =
  deleting that line (a plugin using it gets `nullptr` at `HookAPI_RequireAll` and exits gracefully);
  reordering manifest lines only affects the initialization order of the loader-internal `g_hookApi` and is irrelevant to plugins;
- **a signature change = add `XxxEx`, keep the old entry**: name lookup can prove "the name exists", it cannot prove "the parameters match".
  When `GetPlayer(int)` needs another parameter, add `GetPlayerEx(int, bool)` and have the old entry forward to it inside the Loader;
  mark the old entry with `[[deprecated("use GetPlayerEx")]]` so that plugins get `C4996` and the replacement suggestion at compile time.
  Precedents: `CreateWindow`/`CreateWindowEx`, `VirtualAlloc`/`VirtualAllocExNuma`.
  **Do not change a signature in place** — that is register/stack misalignment, not a compile error, and manifests as random runtime crashes;
- **`HookContext` only grows**: it is the only frozen struct, its field order must not move (`structSize` must stay at offset 0,
  it doubles as the deployment consistency sentinel);
- **no version bump during pre-release (now)**: no plugin has ever been released externally, so delete and change entries directly,
  with `CIV6_HOOK_API_VERSION` staying at `1` (the only value that has ever appeared); plugins must be recompiled against the current header;
- **after public release, bump the version only when the `HookContext` prefix is broken**, so that old plugins are rejected rather than crash;
- **the category gate is outside `HookContext`**: the `Civ6PluginKind` export is responsible for fast rejection by category "before OnLoad"
  (a plugin built from an old header lacks this export → it is rejected before OnLoad);
  ABI compatibility is judged by `structSize` + `apiVersion` (plugin side `HookContext_IsCompatible`);
- **deleting enum values does not affect the ABI**;
- after the change you must: rebuild both configurations + run a real-machine test pass to verify.

### 10.4 Documentation maintenance conventions

- this file is **the single overall architecture document**; "why it is designed this way" is written here;
- "why it is not written this way" comments in code should point at the corresponding section of this file rather than restating it.
