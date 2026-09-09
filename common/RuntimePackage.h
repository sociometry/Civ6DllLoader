#pragma once
#include <cstdint>
#include <string>

namespace RuntimePackage {

// 只读 x64 DLL 的静态版本资源；没有资源的旧候选拒绝，不回退到执行导出。
// 资源用于识别格式和排序；候选来源的信任仍由 ModScan 的启用集/本地规则决定。
bool ProbeVersion(const std::wstring& path, uint32_t& outVersion);

// 从禁止写入/替换的源文件复制并校验临时文件；失败不改动已安装的 DLL。
bool StageCandidate(const std::wstring& source, const std::wstring& staged, uint32_t expectedVersion);

// backup 为空为首次安装（不覆盖已有文件）；否则先备份，再发布，失败尝试恢复。
bool PublishStaged(const std::wstring& staged, const std::wstring& installed,
    const std::wstring& backup = {});

}  // namespace RuntimePackage
