#pragma once
#include <Windows.h>
#include <string>
#include <vector>

// LoaderUsage —— "哪些已启用的 Mod 在用本加载器"与"卸载自己"。
//
// 用途：主菜单设置面板里的【卸载加载器】按钮。
//   1) 面板打开时调 CollectUserMods()，把列表交给 Lua；
//   2) 用户确认后调 UninstallSelf()，把本模块文件改名成 winmm_Old.dll。
//
// 判据（review 后与需求方确认过：薄壳与 runtime 是配套的，自带代理的情况忽略）：
//   <mod>\Binaries\Win64 下满足任一即算"使用本加载器"——
//     · GameCore_XP2_Shell_FinalRelease.dll（薄壳：进对局时会补装 winmm.dll）
//     · Civ6DllLoader.runtime.dll（自带 runtime）
//     · Plugins\Global 或 Plugins\GameCore 下有插件 DLL（没有 loader 就没人加载它们）
//   已启用和已禁用的都会列出（禁用的在 UI 上标红「已禁用」）：禁用的虽然不会把加载器
//   装回来，但用户需要看到它同样依赖加载器，免得下次启用后又装回来。
namespace LoaderUsage {

struct UserMod {
    // 已按当前语言解析过的显示名（C++ 从 Mods.sqlite.LocalizedText 取）；
    // 所有语言都没有时退回 ModProperties.Name 原值（可能是 LOC_ 键，Lua 侧再兜一次）。
    std::wstring name;
    // Mod 目录名。名字为空时 Lua 拿它兜底显示。
    std::wstring folder;
    // 是否在当前选中的 ModGroup 里被勾选。禁用的也要列出来（UI 上标「已禁用」），
    // 因为用户需要知道「这个 Mod 也依赖加载器，只是暂时关掉了」。
    bool enabled = true;
};

// 带上述标记的 Mod（**含已禁用的**，用 enabled 字段区分）。顺序按 .modinfo 路径字典序。
//
// language：游戏当前语言的 Locale 串（zh_Hans_CN / en_US / ...），用于解析 Mod 显示名。
// 为什么不能靠 Locale.Lookup：.modinfo 里的 <LocalizedText> 块只会被 Mod 扫描器写进
// Mods.sqlite 的 LocalizedText 表（供模组管理器显示），**不会**被当作 UpdateText 插进运行期
// 的 Localization 表；Lua 侧 Locale.Lookup(该 tag) 因此只会拿回 key 本身（在 FrontEnd 自己的
// context 里也一样，日志已验证）。这里直接查 Mods.sqlite 的同一份数据：按当前语言取，退回 en_US。
std::vector<UserMod> CollectUserMods(const std::wstring& language);

// 把 self 指向的模块文件改名为同目录的 winmm_Old.dll：
// 本次会话继续用已映射的映像，下次启动不再注入（= 卸载）。
// 只接受文件名本来就是 winmm.dll 的情况；开发期从别处 LoadLibrary 时直接拒绝（outError = 0）。
// 失败时 outError 是 Win32 错误码，供调用方显示。
bool UninstallSelf(HMODULE self, DWORD& outError);

}  // namespace LoaderUsage
