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
// 注意：ENABLE_DEBUG_LOG 没有对应的 Writer —— 它只给开发者手改，
// 运行期（含 UI）不该把它打开，否则一次误点就会让日志暴涨。
bool WriteGlobalEnabled(bool enabled);
bool WriteGameCoreEnabled(bool enabled);

// ==== ENABLE_DEBUG_LOG ====
// 开发者开关，**只读、只能手改 ini**：没有 Writer，也没有 UI 入口 / Lua 接口。
// 默认 false（键缺失也读作 false，与其它键的 fail-closed 一致）。
// 用途：控制运行期"逐条/每帧"级别的诊断日志；常驻的量少日志不受它影响，
// 否则真出问题时反而看不到上下文。
//
// 结果在进程内缓存一次：这个键是给人手改的，改完要重启游戏才生效，
// 没必要每次打日志都去读一次磁盘（那些日志本身就在高频路径上）。
bool ReadDebugLogEnabled();

// ==== ENABLE_PROFILER ====
// 性能分析开关。同样**只读、只能手改 ini**，没有 Writer / UI / Lua 接口，默认 false。
// 与 ENABLE_DEBUG_LOG **互不相关**：DEBUG_LOG 管细颗粒度诊断日志，
// PROFILER 管耗时统计。分析器本身（Profiler 模块）也只听这个开关 ——
// 关着的时候 Begin/End 是空操作，不取时间、不分配、不打日志。
//
// 同样进程内缓存一次（手改 + 重启生效）。
bool ReadProfilerEnabled();

}  // namespace CfgIni
