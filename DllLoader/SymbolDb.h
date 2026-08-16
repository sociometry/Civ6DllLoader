#pragma once

#include <Windows.h>
#include <stdint.h>

namespace SymbolDb {

// Load Civ6DllLoader.symbols.bin (sidecar next to runtime, else RCDATA).
// Returns true if a table was loaded.
bool Init(HMODULE runtimeModule);

void Shutdown();

// Lookup RVA by mangled name, friendly name, or alias. 0 if missing.
uint32_t LookupRva(const char* name);

// Plugin/runtime override; creates map if empty. Returns false on bad args.
bool RegisterRva(const char* name, uint32_t rva);

size_t EntryCount();
uint32_t ExpectedSizeOfImage();
bool IsLoaded();

}  // namespace SymbolDb
