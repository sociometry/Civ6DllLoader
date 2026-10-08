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

// Unique roots to enumerate sibling mods from (game root, Documents Mods, workshop content).
// 内容根一律由【进程 exe 目录】推导，不接受调用方传锚模块：游戏只从
// <内容根>\<Mod>\Binaries\Win64\ 加载薄壳，而内容根由 exe 目录上溯得到，
// 所以"谁在调用"不改变结果（传别的模块只会少拿根，见 ARCHITECTURE §3.1）。
std::vector<std::wstring> CollectScanRoots();

// All Civ6DllLoader.runtime.dll candidates under the scan roots.
// 安装/自更新 loader 用：只看版本，【不】按 Mod 启用集过滤（插件扫描才过滤）。
std::vector<std::wstring> FindRuntimeCandidates();

bool ShouldSkipPluginFile(const fs::path& path);

// v2: 各启用 Mod 的 Binaries\Win64\Plugins\Global\*.dll 候选（稳定的顺序/大小写不敏感排序/按文件名去重语义）
std::vector<std::wstring> FindGlobalPluginCandidates();
// v2: 各启用 Mod 的 Binaries\Win64\Plugins\GameCore\*.dll 候选（同上）
std::vector<std::wstring> FindGameCorePluginCandidates();

}  // namespace ModScan
