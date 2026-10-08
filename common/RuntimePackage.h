#pragma once
#include <cstdint>
#include <string>

namespace RuntimePackage {

// 只读 x64 DLL 的静态版本资源；没有资源的旧候选拒绝，不回退到执行导出。
// 资源用于识别格式和排序；候选来源由 ModScan 的扫描根（游戏根 / Documents Mods /
// Workshop 库）与 loader 自身目录决定——**不经启用集过滤**（启用集只约束插件加载）。
//
// 严格版：只认【独立数据映射】。用于候选筛选 / staging / 自更新——那些路径要靠
// "文件此刻的字节"判断版本，若 Windows 复用了进程里已存在的同名代码映射，读到的
// 资源可能属于被替换前的旧内容。
bool ProbeVersion(const std::wstring& path, uint32_t& outVersion);

// 放宽版：允许复用进程里已存在的代码映射。**只用于"已安装的这个文件是不是我们的
// loader"** 这一判定 —— 因为游戏 exe 静态导入 version.dll，薄壳运行时该文件必然
// 已被代码映射，严格版会把我们自己的 loader 误判成外来文件（详见 .cpp 内说明）。
// PE 校验与 RCDATA 105 + magic/format 校验与严格版完全一致。
bool ProbeVersionIncludingLoaded(const std::wstring& path, uint32_t& outVersion);

// 从禁止写入/替换的源文件复制并校验临时文件；失败不改动已安装的 DLL。
bool StageCandidate(const std::wstring& source, const std::wstring& staged, uint32_t expectedVersion);

// backup 为空为首次安装（不覆盖已有文件）；否则先备份，再发布，失败尝试恢复。
bool PublishStaged(const std::wstring& staged, const std::wstring& installed,
    const std::wstring& backup = {});

}  // namespace RuntimePackage
