#pragma once
// Civ6DllLoader v2 — 游戏内 hook 安装接口（实现在 LoaderHooks.cpp）。
namespace LoaderHooks {

// 安装 GameCore::LoadDLL 入口 detour（RVA 0xF8510，特征码 48 81 EC 48 02 00 00 48 83 3D ?? ?? ?? ?? 00 74 0A 32 C0
// 定位，MinHook）与 GameCore::UnloadDLL 入口 detour。
// Global 插件仅启动时加载一次；主菜单开关 Mod 需重启才生效（不再挂 lEnableMod/lDisableMod 钩）。
// LoadDLL 是必需项：它失败会回滚本次已创建的全部 hook 并返回 false。UnloadDLL 是可选
// （特征码不符/启用失败只放弃它一个，函数照常返回 true）——别把 true 读成"两个都装上了"。
bool InstallAll();

}  // namespace LoaderHooks
