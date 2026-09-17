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
// 安装/自更新 loader 用：只看版本，【不】按 Mod 启用集过滤（插件扫描才过滤）。
std::vector<std::wstring> FindRuntimeCandidates(HMODULE shellModule);

bool ShouldSkipPluginFile(const fs::path& path);

// v2: 各启用 Mod 的 Binaries\Win64\Plugins\Global\*.dll 候选（稳定的顺序/大小写不敏感排序/按文件名去重语义）
// anchor = 锚模块（Loader 自身 version.dll）；以其目录收集扫描根。
std::vector<std::wstring> FindGlobalPluginCandidates(HMODULE anchor);
// v2: 各启用 Mod 的 Binaries\Win64\Plugins\GameCore\*.dll 候选（同上）
std::vector<std::wstring> FindGameCorePluginCandidates(HMODULE anchor);

}  // namespace ModScan
