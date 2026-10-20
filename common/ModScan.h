#pragma once
#include <Windows.h>
#include <filesystem>
#include <string>
#include <vector>

namespace ModScan {

namespace fs = std::filesystem;

// 模块所在目录（传 nullptr = 当前进程 exe 的目录）。空串表示取不到。
std::wstring GetModuleDirectory(HMODULE module);
std::wstring NarrowToWide(const std::string& s);
std::string WideToNarrow(const std::wstring& s);

// All Civ6DllLoader.runtime.dll candidates under the scan roots.
// 安装/自更新 loader 用：只看版本，【不】按 Mod 启用集过滤（插件扫描才过滤）。
std::vector<std::wstring> FindRuntimeCandidates();

// 各启用 Mod 的 Binaries\Win64\Plugins\Global\*.dll 候选。
// 管线：启用集过滤 -> 文件版本门禁（没有 VERSIONINFO 文件版本的一律剔除）
//       -> 大小写不敏感字典序排序 -> 按 basename 去重并留版本最高者（同版本取字典序最小）。
// 返回顺序即加载顺序（稳定、可复现）。
std::vector<std::wstring> FindGlobalPluginCandidates();
// 各启用 Mod 的 Binaries\Win64\Plugins\GameCore\*.dll 候选（同上，与 Global 各自独立去重）
std::vector<std::wstring> FindGameCorePluginCandidates();

}  // namespace ModScan
