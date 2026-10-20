#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

// 插件 DLL 的静态版本号：从 PE 的 VERSIONINFO 资源里读"文件版本"。
//
// 关键约束：**不加载模块**。GetFileVersionInfo* 按文件路径读资源，
// 不执行候选的 DllMain / TLS / 导出，与 RuntimePackage::ProbeVersion
// 读 RCDATA 105 是同一套纪律。
//
// 为什么插件要版本号：多个 Mod 可能各带一份同名插件，扫描时按 basename
// 去重只能留一份。旧规则是"路径字典序第一"（与版本无关，纯属偶然），
// 现在改为"版本最高者胜"。
namespace PluginVersion {

// (major<<48) | (minor<<32) | (patch<<16) | build
// 这样 64 位整数的大小顺序恰好等于 "a.b.c.d" 的字典序（高位先比）。
using Version = uint64_t;

// 0 = 没有可用的版本号。来源有三种，加载策略上等价（一律不加载）：
//   ① 没有 VERSIONINFO 资源；② 资源读不出来/格式不对；③ 填的就是 0.0.0.0。
// 也就是说 0.0.0.0 不是"最低版本"，而是"没有版本"。
constexpr Version kNoVersion = 0;

// path 必须是绝对路径。不加载模块，可在扫描阶段安全调用。
Version ReadFileVersion(const std::wstring& path);

// "1.2.3.4"，供日志用。
std::string Format(Version version);

struct Candidate {
    std::wstring path;
    Version version = kNoVersion;
};

enum class DecisionKind {
    Kept,                   // 该 basename 组的胜出者
    DroppedLowerVersion,    // 同组里有更高版本
    DroppedSameVersion,     // 版本相同，按路径字典序裁决
    DroppedNoVersion,       // 读不到版本号（强制门禁）
};

struct Decision {
    std::wstring path;
    Version version = kNoVersion;
    DecisionKind kind = DecisionKind::Kept;
    // 仅 Dropped 时有意义：与之竞争的胜出者（组内最终保留的那一份）。
    std::wstring winner;
    Version winnerVersion = kNoVersion;
};

// 先按版本门禁剔除，再按 basename（大小写不敏感）分组、组内留版本最高者；
// 版本相同时留路径字典序最小者（与 Loader 自身 runtime 选举同规则）。
//
// 输入顺序即输出顺序的依据：返回值的 Kept 项保持输入中的相对次序，
// 不重新排序 —— 加载顺序对插件可见，不能因为选举而改变。
//
// 纯函数：不读日志、不碰文件系统（候选的 version 由调用方预先填好）。
std::vector<Decision> Select(std::vector<Candidate> candidates);

}  // namespace PluginVersion
