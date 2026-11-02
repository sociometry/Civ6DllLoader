#pragma once
#include <Windows.h>

// 通道②：把"以历史代理名 version.dll 安装的 loader"搬到自己名下（winmm.dll）。
//
// 为什么需要它：v1.0.x 及更早的 build 把 runtime 装成 exe 目录的 version.dll。那些机器升级
// 之后不会再有别的东西去动 version.dll —— 薄壳只在 LoadDLL detour 缺失时进场，而老 loader
// 在位时它的 detour 是好的，薄壳根本不会被加载。所以这条自迁移是老用户唯一的自动通道。
namespace LegacyProxyMigration {

// 阶段 A 早期调用一次（Logger 已 Init）。仅当自身文件名是 version.dll 时动作：
//   1) 清掉 version_Old.dll 残留（老 loader 自更新/接管留下的备份）；
//   2) exe 目录里没有 winmm.dll      → 一步改名：version.dll -> winmm.dll；
//      已存在（不论是谁的、什么版本） → 先把它退成 winmm_Old.dll，再把自己的文件改名上去；
//                                       第二步失败就把 winmm_Old.dll 改回 winmm.dll。
// 成功后**不重启**：磁盘上从此只有 winmm.dll，但本会话继续以 version.dll 身份跑完
// （映像已映射，改名不影响正在执行的代码）。下次启动 exe 加载的就是 winmm.dll。
//
// 与版本号无关：迁移只是"换个文件名继续用同一份二进制"。若目标位上原本是更新版本，
// 这里会把它顶到 winmm_Old.dll —— 极小概率的降级，由下一次 runtime 自更新纠正
//（自更新只认 winmm.dll 这个名字，做完会重启），代价是多一次重启。
//
// 全部失败静默（只写日志）：最坏情形是这台机器继续停在旧代理名上，行为与本版本之前完全一致。
void MigrateIfLegacyProxy(HMODULE self);

}  // namespace LegacyProxyMigration
