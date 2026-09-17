#pragma once
#include <Windows.h>
#include <string>
#include <unordered_set>
#include <vector>

namespace EnabledMods {

struct Snapshot {
    bool ok = false;
    std::string error;
    std::unordered_set<std::string> modIds;          // lowercase ModId from Mods.sqlite
    std::vector<std::wstring> enabledModRoots;       // normalized absolute mod roots
};

// Read selected ModGroup from Mods.sqlite (Additional Content enable list).
// 查询必须完整结束才返回 ok=true；失败返回错误和空集合，不暴露部分启用集。
Snapshot Load();

// Walk up from a file/dir path to the folder that contains a *.modinfo.
std::wstring FindModRoot(const std::wstring& anyPathUnderMod);

std::wstring NormalizePath(const std::wstring& path);
bool PathIsUnderRoot(const std::wstring& path, const std::wstring& root);

// True if path belongs to an enabled mod root recorded by Mods.sqlite.
// 授权必须绑定 SQL 返回的精确 mod root；嵌套/重叠目录不得隐式授权。
// 只比较 ModId(GUID) 不够，因为同一个 GUID 可能有多份安装副本。
bool AllowsPath(const Snapshot& snap, const std::wstring& path);

}  // namespace EnabledMods
