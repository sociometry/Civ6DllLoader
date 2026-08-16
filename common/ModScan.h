#pragma once
#include <Windows.h>
#include <filesystem>
#include <string>
#include <vector>

namespace ModScan {

namespace fs = std::filesystem;

std::wstring GetModuleDirectory(HMODULE module);
std::wstring NarrowToWide(const std::string& s);
std::string WideToNarrow(const std::wstring& s);

// From .../SomeMod/Binaries/Win64 -> parent of SomeMod (Mods or workshop content folder).
// Returns empty if layout is unexpected; caller should still scan the Win64 folder itself.
std::wstring FindContentRoot(const std::wstring& binariesWin64Dir);

// Unique roots to enumerate sibling mods from (Documents Mods, workshop content, etc.).
std::vector<std::wstring> CollectScanRoots(HMODULE shellModule);

// All Civ6DllLoader.runtime.dll candidates under scan roots + next to the shell.
std::vector<std::wstring> FindRuntimeCandidates(HMODULE shellModule);

// All plugin DLL paths: <mod>/Binaries/Win64/Plugins/*.dll across scan roots,
// plus Plugins next to the shell module.
std::vector<std::wstring> FindPluginCandidates(HMODULE shellModule);

bool ShouldSkipPluginFile(const fs::path& path);

}  // namespace ModScan
