#pragma once
// Civ6DllLoader v2 — 游戏内 hook 安装接口（S4 实现 LoaderHooks.cpp）。
namespace LoaderHooks {

// 安装 GameCore::LoadDLL 入口 detour（RVA 0xF8510，特征码 48 81 EC 48 02 00 00 48 83 3D ?? ?? ?? ?? 00 74 0A 32 C0
// 定位，MinHook）与 AppLuaModdingLibrary::lEnableMod/lDisableMod 入口 detour（RVA 0x4CCFE0 / 0x4CCD50）。
// 返回 false 表示至少一个 hook 安装失败（已记日志；其余 hook 照常工作，静默降级）。
bool InstallAll();

}  // namespace LoaderHooks
