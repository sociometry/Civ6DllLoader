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

bool ShouldSkipPluginFile(const fs::path& path);

// v2: 各启用 Mod 的 Binaries\Win64\Plugins\Global\*.dll 候选（顺序/过滤/去重语义同旧扁平 Plugins 扫描）
// v2 运行时无 shell 模块句柄可传：以当前进程可执行模块（GetModuleHandleW(nullptr)）为锚收集扫描根。
std::vector<std::wstring> FindGlobalPluginCandidates();
// v2: 各启用 Mod 的 Binaries\Win64\Plugins\GameCore\*.dll 候选（同上）
std::vector<std::wstring> FindGameCorePluginCandidates();

}  // namespace ModScan
