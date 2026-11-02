#pragma once
#include <Windows.h>

namespace ShellBootstrap {

// Load real Expansion2 GameCore relative to the current working/module layout.
HMODULE LoadRealGameCore();

// v2 installer (at most once per process, retried after failure): if <exe dir>\winmm.dll
// is not our loader, elect the highest-version Civ6DllLoader.runtime.dll found under the
// scan roots (deliberately NOT filtered by mod-enabled state) and install it as
// exe-dir\winmm.dll (copy to winmm.tmp, then atomic rename; a foreign winmm.dll is
// backed up to winmm_Old.dll first). A legacy loader still installed as version.dll is
// retired to version_Old.dll afterwards, so the next session loads exactly one copy.
// Returns true when the Loader is present afterwards, false when it remains
// missing. Already-installed counts as true. Any failure is silent + logged
// only (never a message box); the success dialog appears exactly once.
bool InstallLoaderIfMissing();

}  // namespace ShellBootstrap