#pragma once
namespace LoaderUpdate {
// 阶段 A 由 Loader 工作线程调用一次：扫描各内容根里的 Civ6DllLoader.runtime.dll 候选
// （不按 Mod 启用集过滤），
// 若发现版本高于当前运行版本则执行自更新舞蹈并在成功后弹双语提示窗。
// 全程失败静默（只写日志，不弹窗）。
void CheckAndApplyUpdate();
}