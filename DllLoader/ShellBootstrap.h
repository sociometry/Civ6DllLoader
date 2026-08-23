#pragma once
#include <Windows.h>

namespace ShellBootstrap {

// Load real Expansion2 GameCore relative to the current working/module layout.
HMODULE LoadRealGameCore();

// v2 installer (at most once per process): if <exe dir>\version.dll is missing,
// elect the highest-version Civ6DllLoader.runtime.dll from enabled mods and
// install it as exe-dir\version.dll (copy to version.tmp, then atomic rename).
// Returns true when the Loader is present afterwards, false when it remains
// missing. Already-installed counts as true. Any failure is silent + logged
// only (never a message box); the success dialog appears exactly once.
bool InstallLoaderIfMissing(HMODULE shellModule);

}  // namespace ShellBootstrap