# Civ6DllLoader Feature Catalog (API + UI Injection)

> English | [中文](FEATURE_CATALOG.md)

Everything the loader exposes, on one page: the **plugin API** (80 `HookAPI` entries) and **UI injection** (main-menu screens).

- Authoritative source: the entry list is `HOOK_API_LIST` in [`common/HookAPI.h`](../common/HookAPI.h) (X-macro, single source of truth).
- Usage and examples: plugin authors should follow the [Plugin Development Guide](https://github.com/sociometry/Civ6DllMods/blob/main/docs/PLUGIN_GUIDE.md) (§6 covers the API, §7 covers UI injection).
- Architecture and internals: [ARCHITECTURE.en.md](ARCHITECTURE.en.md).

---

## 0. At a glance

| Capability | Count | Plugin domain | Purpose |
| --- | --- | --- | --- |
| Address resolution and image queries | 9 | both | Turn symbol names / RVAs / AOBs / vtable slots into callable addresses |
| Hooking and patching | 3 | both | Install detours, write bytes, revert patches |
| Inter-plugin messaging | 3 | both | Topic broadcast and direct send |
| Lua primitives | 45 | both | Operate on `lua_State` directly: tables, calls, references |
| Script-environment registration and object extension | 4 | per domain | Mount globals into gameplay / UI / engine environments; attach methods to engine Lua objects |
| Event bus | 2 | GameCore | Register and fire custom GameEvents |
| Localization | 7 | both | Resolve LOC keys, push arguments, convert to UTF-8 |
| Utilities and diagnostics | 7 | both | Logging, hashing, symbol-DB state, debug switch, player object |
| **Total** | **80** | | |
| **UI injection** | 1 mechanism | no plugin needed | `FrontEndUI_*.xml` + `.lua` mounted into the main menu without compiling |

> Domain legend: **both** = `kCommon`, available to Global and GameCore alike; **GameCore** = only visible when compiling with `CIV6_PLUGIN_GAMECORE`; **Global** = only with `CIV6_PLUGIN_GLOBAL`.

---

## 1. Address resolution and image queries (9)

Locating functions and data inside the game is the prerequisite for every hook and patch.

| Entry | Signature | Domain | Notes |
| --- | --- | --- | --- |
| `IsImageLoaded` | `bool(HookImageId image)` | both | Whether the target image is loaded |
| `GetImageInfo` | `bool(HookImageId image, HookImageInfo* outInfo)` | both | Base address and image size |
| `ResolveByRva` | `void*(HookImageId image, uintptr_t rva, size_t span)` | both | RVA lookup with `PdataMatch` cross-version correction |
| `ResolveByRvaEx` | `void*(image, rva, span, HookImageSection section)` | both | Same, section-scoped; does **not** apply pdata correction |
| `ResolveByName` | `void*(HookImageId image, const char* name)` | both | Symbol-name lookup (demangled or mangled) |
| `ResolveByPattern` | `void*(image, const char* pattern, HookImageSection section, uint32_t index)` | both | AOB signature search, `??` wildcards, `index` is 1-based |
| `ResolveByVTable` | `void*(image, const char* vtableSymbol, uint32_t index)` | both | Virtual function by vtable name + slot index (0-based) |
| `RegisterGlobalCapture` | `bool(void* providerAddress, uint32_t paramIndex, void** out)` | both | Capture the Nth **integer** argument (rcx/rdx/r8/r9) of a function |
| `UnregisterGlobalCapture` | `bool(void* providerAddress, void** out)` | both | Cancel that subscription (removes the subscription, not the hook) |

`HookImageId` values usable at runtime: `kHookImageExeDx11` / `kHookImageExeDx12` / `kHookImageGameCoreXP2`.

**Typical chain**: `ResolveByName` to get the function address → `InstallHook` to hook it; for data slots use `ResolveByPattern` + `Dispatch` or `RegisterGlobalCapture`.

---

## 2. Hooking and patching (3)

| Entry | Signature | Domain | Notes |
| --- | --- | --- | --- |
| `InstallHook` | `bool(void* targetFunc, void* detour, void** original)` | both | Install a MinHook detour; `original` receives the trampoline for calling through |
| `Patch` | `bool(void* target, const void* bytes, size_t len)` | both | Write raw bytes (owner stack layered per target) |
| `Unpatch` | `bool(void* target)` | both | Revert **your own** patch (top of the stack only) |

**Hard constraints**:

- The same address **cannot be both hooked and patched**; either direction is rejected (MinHook and the patch registry would each keep their own copy of the "original bytes" and overwrite each other).
- The loader **does not roll patches back automatically**: after quarantine or unload the patch stays in the game until the process exits. Call `Unpatch` yourself from `OnUnload` if you need it gone.
- Before hooking, make sure no one else has a hook or patch inside the target's 32-byte window.

---

## 3. Inter-plugin messaging (3)

| Entry | Signature | Domain | Notes |
| --- | --- | --- | --- |
| `BroadcastMessage` | `void(const char* topic, const void* data, size_t len)` | both | Topic broadcast |
| `RegisterMessageHandler` | `bool(MessageHandlerFn handler)` | both | Register a handler; the owner is the plugin module containing the handler |
| `SendMessageTo` | `void(const char* pluginName, const char* topic, const void* data, size_t len)` | both | Send to one named plugin |

Messages are dispatched on the **game thread**; the handler address must live inside a plugin module tracked by the loader.
---

## 4. Lua primitives (45)

Direct manipulation of `lua_State`. Most are thin wrappers over exports of `HavokScript_FinalRelease.dll` and are **unrelated to GameCore**, so both plugin domains can use them; the `void* L` parameter is the state the caller passes in.

### 4.1 Stack and types (18)

| Entry | Notes |
| --- | --- |
| `LuaGetTop` / `LuaSetField` / `LuaGetField` | Stack-top index; write/read table fields |
| `LuaPop` / `LuaPushValue` / `LuaPushNil` | Stack operations |
| `LuaType` / `LuaIsNumber` / `LuaIsUserData` | Type checks |
| `LuaToNumber` / `LuaToInteger` / `LuaToBoolean` / `LuaToCFunction` / `LuaToUserData` | Value conversion |
| `LuaPushInteger` / `LuaPushNumber` / `LuaPushBoolean` / `LuaPushLightUserData` | Push scalars |

### 4.2 Table operations (7)

| Entry | Notes |
| --- | --- |
| `LuaCreateTable` / `LuaNewGlobalTable` | Create a table / a global table |
| `LuaGetTable` / `LuaSetTable` | Read/write by a key on the stack |
| `LuaRawGetI` | Read an array element by integer index |
| `LuaObjLen` | Sequence length (no string keys) |
| `LuaNext` | Iterate a hash table (`lua_next` semantics; the caller must pop the value) |

### 4.3 Calls and errors (4)

| Entry | Notes |
| --- | --- |
| `LuaCPcall` | Protected C call, returns a status code |
| `LuaPcall` | Protected Lua call |
| `LuaDoString` | Execute a chunk of Lua source |
| `LuaError` | `luaL_error`: **raises and does not return** (longjmp); never call it inside a loader callback frame |

### 4.4 References and C closures (5)

| Entry | Notes |
| --- | --- |
| `LuaRef` / `LuaUnref` | Register and release a reference (supports registry / environment / globals pseudo-indices) |
| `LuaPushNamedCClosure` / `LuaPushCFunctionField` | Push a C closure / attach a C function field to a table |
| `LuaCheckPlayerId` | Validate and normalise a playerId argument |

### 4.5 Argument checking and formatting (6)

| Entry | Notes |
| --- | --- |
| `LuaCheckInteger` / `LuaCheckNumber` / `LuaCheckLString` / `LuaCheckTable` | Argument checks (raise on type mismatch) |
| `LuaOptInteger` | Optional integer with a default |
| `LuaPushFString` | Push a formatted string |

### 4.6 Debug hooks (5)

| Entry | Notes |
| --- | --- |
| `LuaSetHook` / `LuaGetHook` / `LuaGetHookMask` / `LuaGetHookCount` | Wrappers around the `debug.sethook` family |
| `LuaOpenDebug` | Open the debug library |

> **Thread constraint**: Lua state is not thread-safe, so every Lua primitive **must be called on the game thread**.
> `LuaError` / `LuaCheck*` raise on a type mismatch, which skips C++ destructors — do not use them inside registration-style callback frames.

---

## 5. Script-environment registration and Lua object extension (4)

The first three entries mount global modules into different Lua environments and differ only in "which environment" and "when it runs"; `PushLuaMethods` instead attaches methods to an existing engine Lua object.

| Entry | Signature | Domain | Mounts into | Lifetime |
| --- | --- | --- | --- | --- |
| `RegisterGlobalScript` | `void(ScriptGlobalsFn fn)` | **Global only** | **Every** script environment of the exe (main menu / options / match …) | Runs once per environment; runs again after an environment is rebuilt |
| `RegisterGameCoreScriptForGamePlay` | `void(ScriptGlobalsFn fn)` | **GameCore only** | GameCore's gameplay Lua | Rebuilt per match; gone when the match ends |
| `RegisterGameCoreScriptForUI` | `void(ScriptGlobalsFn fn)` | **GameCore only** | GameCore's UI-script Lua | Same as above (a different state from gameplay) |
| `PushLuaMethods` | `HookApiPushMethodsResult(const char* pushMethodsSymbol, int sigType, const LuaMethodInfo* methods, uint32_t count)` | **GameCore only** | Batch-attach methods to engine C++ Lua objects such as `IUnit` or `IQuestsManager` | Rebuilt per match; re-attach in each match's `OnLoad` |

**Choosing**: use `RegisterGlobalScript` for resident features; use the GameCore entries for anything that only makes sense inside a match. In the callback, **always mount into the `L` you were given** — never cache the first `L`.

---

## 6. Event bus (2, GameCore only)

| Entry | Signature | Notes |
| --- | --- | --- |
| `RegisterGameEvent` | `bool(const char* name, GameEventPushFn pushFn)` | Register a custom event that Lua can receive; `pushFn` pushes the arguments |
| `TriggerGameEvent` | `bool(const char* name, const void* payload)` | Fire the event; `payload` is handed to the registered `pushFn` |

Event names are limited to 95 bytes. Inside `pushFn` you can push any number of arguments of any type using the primitives from 4.1–4.2.

**Game thread only**; the loader handles the lock protocol, `GameEvents[name].Call`, and stack cleanup.
---

## 7. Localization (7)

```c
void* loc = api->LocCreate();
api->LocLookup(loc, "LOC_TECH_POTTERY_NAME");
api->LocPushArgument(loc, "42");
const char* text = api->LocToUtf8(loc);
api->LocDestroy(loc);
```

| Entry | Notes |
| --- | --- |
| `LocalizationLookup` | One-shot key lookup into an output buffer |
| `LocCreate` / `LocDestroy` | Create / release a lookup context |
| `LocLookup` | Look up a key within the context |
| `LocPushArgument` | Append a formatting argument |
| `LocToUtf8` | Get the UTF-8 result |
| `LocStringBytes` | Byte-capacity constant of a single LocString |

---

## 8. Utilities and diagnostics (7)

| Entry | Signature | Domain | Notes |
| --- | --- | --- | --- |
| `Log` | `void(const char* format, ...)` | both | Write to the loader log (shared with every plugin) |
| `IsDebugLogEnabled` | `bool(void)` | both | `ENABLE_DEBUG_LOG` from `config.ini`; gates hot-path logging |
| `MakeHash` | `uint32_t(const char* str)` | both | CRC32 bit-identical to the engine's `GameCore::Utilities::MakeHash` |
| `GetSymbolDbState` | `HookApiSymbolDbState(HookImageId image)` | both | Match state of the symbol DB for that image (5 states) |
| `GetSymbolDbMatchRatio` | `double(HookImageId image)` | both | Cross-version match ratio; meaningful only under `CrossVersion` |
| `GetMainLuaState` | `void*(void)` | both | The engine's **process-level** main Lua VM; survives match changes |
| `GetPlayer` | `void*(int playerId)` | **GameCore only** | Player object (inside a match) |

`GetSymbolDbState` returns one of: `NoContext` / `NotReady` / `BuildFailed` / `Identical` / `CrossVersion`.
**Recommendation**: check this state before relying on hardcoded old RVAs; on `BuildFailed`, disable the feature as a whole rather than running half-broken.

---

## 9. UI injection: main-menu screens (no DLL required)

Besides C++ plugins, the loader offers a **file-only** UI extension path: add panels, buttons and popups to the main menu.

### 9.1 Minimal layout

```text
MyAwesomeMod/
  MyAwesomeMod.modinfo
  UI/FrontEnd/
    FrontEndUI_MyMod.xml     <- screen definition
    FrontEndUI_MyMod.lua     <- logic; same name, same directory as the xml
  Binaries/Win64/
    GameCore_XP2_Shell_FinalRelease.dll
    Civ6DllLoader.runtime.dll
```

Just drop it into the mod directory: **no compilation, no `OnLoad`, no `CIV6_PLUGIN_*` macro**.

### 9.2 Naming and recognition rules

| Rule | Notes |
| --- | --- |
| The prefix must be `FrontEndUI_` | The loader's recognition marker; case-insensitive |
| The extension must be `.xml` | A same-named `.lua` in the same directory is loaded with it |
| At least one character must follow the prefix | `FrontEndUI_.xml` is invalid |
| It must live under an **enabled** mod's directory tree | Recursion up to 8 levels; unreadable subdirectories are skipped |
| The relative path must be unique | If two mods use the same relative path, only one screen is loaded |

### 9.3 Relationship to native game mechanisms

- You do **not** need `<ImportFiles>` in `.modinfo`; the loader scans by file name, so writing it has no effect either way.
- **Conditional loading is not supported**: `criteria` in `.modinfo` plays no part. If a screen must be conditional, always inject it and hide it from `.lua` with `SetHide(true)`.
- **Main menu only**. In-match screens still go through the game's native `AddUserInterfaces` + `ReplaceUIScript`.

### 9.4 Troubleshooting

After reaching the main menu, open `Civ6DllLoader_Loader.log` and search for `UiInject:`:

```text
UiInject: 发现 2 个 Mod UI
UiInject: context 已加载 (FrontEndUI_MyMod)
```

| Symptom | Cause |
| --- | --- |
| No `发现 N 个 Mod UI` line | The mod is not considered enabled, or the scan failed outright |
| A count appears but your file is missing | Prefix/extension invalid, or the file sits in a disabled mod |
| `context 已加载` appears but nothing shows | The screen itself (XML layout, or Lua never shows it) |

The guide's chapter 7 has the full detail.

---

## 10. Boundaries (read this first — it saves time)

| Not possible | Why |
| --- | --- |
| Changing game rule values | That is the database layer; the loader is not needed |
| Calling Lua from an arbitrary thread | All Lua primitives are game-thread only |
| Automatic patch rollback | The loader does not roll back; plugins call `Unpatch` from `OnUnload` |
| Injecting into in-match UI | Main menu only; use the native UI mechanisms in a match |
| Loading a plugin without a version resource | Plugin DLLs must carry `VERSIONINFO`, otherwise they are rejected |
| Using Global and GameCore-only entries in one module | Invisible at compile time; split the module by domain |

---

## 11. Related documents

| Document | Content |
| --- | --- |
| [ARCHITECTURE.en.md](ARCHITECTURE.en.md) | Architecture overview: boot chain, lifecycle, plugin model, hook subsystem |
| [PLUGIN_GUIDE](https://github.com/sociometry/Civ6DllMods/blob/main/docs/PLUGIN_GUIDE.en.md) | Plugin development guide: project setup, address model, API usage, UI injection, FAQ |
| [`common/HookAPI.h`](../common/HookAPI.h) | Single source of truth for the entry list and all type definitions |
| [README](../README.en.md) | How it works and core features |
