#pragma once
// ConfigIni — Loader 的进程级开关文件。
//
// 位置：<exe目录>\Civ6DllLoader\config.ini（与 UI 资源同目录）
// 格式：
//   [Loader]
//   ENABLE_GLOBAL=true
//   ENABLE_GAMECORE=true
//
// 两条独立规则，别混淆：
//   * 文件不存在 -> 新建，两个键都写 true（装好即启用）；
//   * 文件在但某个键缺失 / 值非法 -> 该键读作 false（fail-closed：
//     宁可插件不加载，也不让写错的 ini 意外启用功能）。
//   只认 true/false（大小写不敏感）与 1/0；其它写法记一行日志后按 false。
#include <string>

namespace CfgIni {

// 配置文件绝对路径（<exe目录>\Civ6DllLoader\config.ini）。
// 解析失败（拿不到 exe 路径）返回空串，调用方据此跳过所有读写。
std::wstring ConfigPath();

// 确保配置文件存在：目录缺失则建目录；文件缺失则以两个 true 初始化。
// 已存在则不动内容（保留用户编辑）。返回 true = 文件最终可用。
bool EnsureExists();

// 读取一个开关（缺失或值非法 -> false）。
bool ReadGlobalEnabled();
bool ReadGameCoreEnabled();

// 写入一个开关并落盘。返回 true = 写成功。
// 只改 [Loader] 段里对应的那个键，保留文件里其它内容。
bool WriteGlobalEnabled(bool enabled);
bool WriteGameCoreEnabled(bool enabled);

}  // namespace CfgIni
