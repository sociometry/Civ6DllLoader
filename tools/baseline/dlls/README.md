# 各阶段构建产物（二分定位用）

拆分是 6 个阶段 7 次提交，最后一次性验证。若实机出问题，用这里的产物逐个部署
来缩小范围 —— 每个中间态都能编译，所以都能单独跑。

| 文件 | 提交 | 状态 |
|---|---|---|
| `00_基线_03b6a0a.dll` | `03b6a0a` | 基线，已知通过 |
| `01_SymbolResolve_e468e04.dll` | `e468e04` | |
| `02_PluginDomain_4e311b6.dll` | `4e311b6` | |
| `03a_TeardownWindow_8d6e00e.dll` | `8d6e00e` | |
| `03b_MessageBus_e7c02b7.dll` | `e7c02b7` | |
| `04_ScriptBridge_065a77a.dll` | `065a77a` | |
| `05_HookEngine_dce1d9b.dll` | `dce1d9b` | |
| `06_PluginRegistry_final_ed31892.dll` | `ed31892` | 最终版，当前已部署 |

生成全部产物：`bash tools/archive_phase_dlls.sh`（逐个 checkout + Rebuild，耗时较长）。
也可以直接从对应提交重建：`git checkout <sha> && msbuild ... -t:Rebuild`。

部署方式（与平时一致）：

    cp <某个>.dll "E:/SteamLibrary/.../Win64Steam/version.dll"
    cp <某个>.dll "E:/Sumcam/Documents/My Games/.../FourRing/Binaries/Win64/Civ6DllLoader.runtime.dll"
