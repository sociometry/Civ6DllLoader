#pragma once
#include <Windows.h>
#include <string>
#include <vector>

namespace EnabledMods {

struct Snapshot {
    bool ok = false;
    std::string error;
    std::vector<std::wstring> enabledModRoots;       // normalized absolute mod roots
};

// Read selected ModGroup from Mods.sqlite (Additional Content enable list).
// 查询必须完整结束才返回 ok=true；失败返回错误和空集合，不暴露部分启用集。
Snapshot Load();

// 路径规范化：全小写、'/'\''->\、去尾分隔符。规范化失败（weakly_canonical 置
// error_code）返回空串 —— 授权判定必须失败即关闭，不能拿未解析链接的原始串当规范路径。
std::wstring NormalizePath(const std::wstring& path);
bool PathIsUnderRoot(const std::wstring& path, const std::wstring& root);

// True if path belongs to an enabled mod root recorded by Mods.sqlite.
// 授权必须绑定 SQL 返回的精确 mod root；嵌套/重叠目录不得隐式授权。
// 只比较 ModId(GUID) 不够，因为同一个 GUID 可能有多份安装副本。
bool AllowsPath(const Snapshot& snap, const std::wstring& path);

}  // namespace EnabledMods
