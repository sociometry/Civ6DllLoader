#pragma once
#include <Windows.h>

namespace ShellBootstrap {

// Load real Expansion2 GameCore relative to the current working/module layout.
HMODULE LoadRealGameCore();

// Scan for Civ6DllLoader.runtime.dll, pick highest GetLoaderVersion(), call LoaderStart.
// Returns the elected runtime module (keep loaded), or nullptr on failure.
HMODULE ElectAndStartRuntime(HMODULE shellModule, HMODULE gameCoreModule, void* baseDllCreateGameContext);

void ShutdownRuntime();

}  // namespace ShellBootstrap
