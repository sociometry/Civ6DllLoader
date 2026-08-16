#pragma once
#include <Windows.h>
#include <string>
#include <unordered_set>
#include <vector>

namespace EnabledMods {

struct Snapshot {
    bool ok = false;
    std::string error;
    std::unordered_set<std::string> modIds;          // lowercase GUID from .modinfo
    std::vector<std::wstring> enabledModRoots;       // normalized absolute mod roots
};

// Read selected ModGroup from Mods.sqlite (Additional Content enable list).
Snapshot Load();

// Walk up from a file/dir path to the folder that contains a *.modinfo.
std::wstring FindModRoot(const std::wstring& anyPathUnderMod);

// Parse id="..." from the first .modinfo under modRoot (lowercase).
std::string ReadModId(const std::wstring& modRoot);

std::wstring NormalizePath(const std::wstring& path);
bool PathIsUnderRoot(const std::wstring& path, const std::wstring& root);

// True if path belongs to an enabled mod (by ModId or enabled root prefix).
bool AllowsPath(const Snapshot& snap, const std::wstring& path);

}  // namespace EnabledMods
