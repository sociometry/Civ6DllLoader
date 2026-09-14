#pragma once
// Civ6DllLoader — FrontEnd UI 注入。
// 把内嵌的 Civ6DllLoader_FrontEndUI.{lua,xml} 释放到 <exe目录>\Civ6DllLoader\，
// 并在主菜单 FrontEnd 就绪后（MainMenuState::LoadUI detour）创建并挂载我们的 LuaContext。

namespace UiInject {

// 释放内嵌 UI 资源（RCDATA 103=lua / 104=xml）到 <exe目录>\Civ6DllLoader\。
// 目标文件已存在则跳过（不覆盖，允许用户在磁盘编辑副本）。
void ExtractResources();

// 安装 MainMenuState::LoadUI detour：FrontEnd context 就绪后注入我们的 UI context。
// 返回 false = hook 未安装（特征码不匹配 / 游戏已更新），静默降级。
bool Install();

// 请求重建注入树（只设置标志，不在调用线程直接操作 ForgeUI 对象）。
// 当前无进程内调用者：Global 插件仅启动时加载，Mod 开关不再触发运行期重注入。
void RequestRefresh();

}  // namespace UiInject
