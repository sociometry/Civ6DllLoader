# Civ6DllLoader

> 中文 | [English](README.en.md)

《文明VI》的原生 C++ 插件加载器：薄壳（首次安装器）+ 带版本号的 runtime + 只读 HookAPI。

本仓库只包含 **loader 基础设施**。插件示例在独立仓库（`Civ6DllLoader-Examples`）。

## 基本运作原理

一句话：把自己伪装成 `version.dll` 进进程，接管规则集 DLL 的加载槽位，再把多个第三方 DLL 插件按生命周期挂进去。

1. **注入** —— 游戏 EXE 的静态导入表里有 `version.dll`，Windows 加载器优先从 EXE 目录解析它。
   我们把 `Civ6DllLoader.runtime.dll` 部署成 `<exe 目录>\version.dll`，于是它在进程初始化最早阶段自动载入；
   它同时把系统 `version.dll` 的导出逐条转发出去，操作系统的版本查询行为不变。
2. **自检后启动** —— `DllMain` 先确认「自身目录 == 进程 exe 目录」且「宿主 exe 名形如 `CivilizationVI*.exe`」，
   否则静默休眠（不建线程、不读文件、不挂钩）。通过后建一条**一次性**工作线程完成初始化——
   避开 Loader Lock，主加载线程绝不阻塞等它。
3. **接管槽位** —— 工作线程解析符号库与 MinHook、装 `LoadDLL` / `UnloadDLL` 两个 detour（`LoadUI` 由 UI 注入模块单独安装），
   然后加载 Global 插件。此后引擎请求加载 `GameCore_XP2_FinalRelease.dll` 时，
   detour 直接把路径改回**官方原版** DLL —— 所以薄壳在已安装状态下**永远不被加载**，原版对局照常运行。
4. **加载插件** —— GameCore 映射完成后进入阶段 B：扫描「我的文档 Mods」与 Steam Workshop 内容根，
   只认**已启用 Mod** 下的 `Binaries/Win64/Plugins/{Global,GameCore}/*.dll`，读 DLL 的 `VERSIONINFO` 版本，
   同名插件只留版本最高的一份，然后按类别加载并调用其 `OnLoad`。
5. **交付接口** —— `OnLoad(const HookContext*)` 拿到的是**按名字取函数**的入口表（`ctx->Query("InstallHook")`），
   而不是固定布局的结构体；插件侧 `HookAPI.h` 把它填成本模块私有的一张表，之后照常调用。
   类别由插件自动导出的 `Civ6PluginKind` 与安装路径双向对账，不符即拒载。
6. **取址** —— 插件用符号名 / RVA / AOB / 虚表槽取游戏内地址。符号名与旧 RVA 由内置 sidecar 符号库提供，
   跨版本时由 `PdataMatch` 按 PE 异常展开表（`.pdata`）矫正到当前映像，AOB 作为兜底与校验。
7. **退场** —— 引擎调 `UnloadDLL` 时，detour 先做一次完整的逆序 teardown
   （还原入口字节 → 通知插件 → 调原函数卸 GameCore 及其 Lua 环境 → 释放插件模块），再放行原调用。

首次使用（EXE 目录里还没有 `version.dll`）时走另一条路：带薄壳的 Mod 通过官方 `Config.sql`
把规则集 `DllPrefix` 改写成 `GameCore_XP2_Shell`，引擎因此加载薄壳；薄壳不做任何 hook，
只扫描候选 runtime、按静态版本资源（RCDATA 105）选举最高版本、复制为 `exe\version.dll` 并提示重启。
重启后即进入上面的稳态路径，薄壳不再参与。

完整机制见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 核心特性

- **全域扩展**：插件的作用面是**整个进程**，不只是 GameCore —— 可拦截主程序 EXE、常驻系统库，
  也可注入前端（ForgeUI）主菜单。这是「只能替换规则集 DLL」的传统方案做不到的。
- **多插件并行共存**：Loader 把规则集槽位永久指回官方 DLL，插件走自己的目录与扫描流水线，
  因此多个改同一块逻辑的独立 DLL 可以同时生效，**不再争抢 `LoadOrder`**，也不需要源码级合并。
- **抗游戏更新**：`PdataMatch` 基于 `.pdata` 的滑动锚点 + 插值 + 序言哈希 + AOB 反推做跨版本 RVA 矫正，
  磁盘缓存命中后直接生效；符号库用 `tools/symdb.py` 一条命令重建，插件侧以「符号名主路径 + AOB 兜底」定位。
- **双域生命周期隔离**：`Global`（随进程、永不卸载、可动 exe/系统库）与 `GameCore`（随对局加载、
  退局真卸载、只能动当前 GameCore 映像）由编译期成员裁剪、加载期类别对账、运行期地址域检查三重保证。
- **统一挂钩站点与共享钩**：同一目标地址全进程只建一个 MinHook 实例，统一跳进 Loader 生成的 stub；
  N 个订阅者（detour + 参数捕获）共享一个站点，装卸互不踩踏，热路径只有几条指令。
- **按名字交付的 ABI**：入口清单是 X-macro 的单一来源，增删/重排入口不破坏已编译插件；
  `structSize` 兼作「两边是否同一次构建」的哨兵，`HookAPI_RequireAll` 让缺接口在 `OnLoad` 里优雅失败。
- **崩溃隔离与安全卸载时序**：插件在 `OnLoad` 崩溃或返回 0 会被隔离并回滚注册，同一条路径不会重试；
  退局严格逆序析构，避免引擎 Lua 环境释放后回调已卸载插件导致的悬垂崩溃。
- **免编译的前端 UI**：`UI/FrontEnd/FrontEndUI_*.xml` + `.lua` 放进 Mod 目录即被挂进主菜单，不需要编译任何 DLL。
- **可运维性**：`config.ini` 提供 `ENABLE_GLOBAL` / `ENABLE_GAMECORE` / `ENABLE_DEBUG_LOG` / `ENABLE_PROFILER`
  四个开关；符号库匹配状态、耗时分析、结构化日志都直接可查；`tools/rva_to_symbol.exe` 单文件反查符号名。

## 目录结构

```text
common/              HookAPI、ModScan、LoaderProtocol
DllLoader/           薄壳（GameCore_XP2_Shell_FinalRelease.dll）
DllLoaderRuntime/    runtime + HookAPI 实现
third_party/sqlite/  「启用 Mod」过滤用的内置 SQLite（在 runtime 侧；薄壳只是
                     通过 ModScan 链接同一份 TU）
tools/               符号库打包与维护脚本
DllLoader.sln        只含薄壳 + runtime 两个工程
```

## 构建与部署

用 Visual Studio 打开 `DllLoader.sln`（x64 | Release）。

典型产物：

- `x64\Release\GameCore_XP2_Shell_FinalRelease.dll`
- `x64\Release\Civ6DllLoader.runtime.dll`

两个都复制进 Workshop mod 的 `Binaries\Win64\`。首次启动时薄壳会选举版本最高的 runtime，
复制成 `<游戏 exe 目录>\version.dll` 并提示重启；重启之后就是那个代理 DLL 把 loader 拉进进程。
loader 在位时薄壳根本不会被加载 —— `LoadDLL` 的 detour 会把 Expansion2 槽位直接指回官方
GameCore DLL，原版对局也一样（见 `docs/ARCHITECTURE.md` §1.1）。

runtime 候选带静态版本元数据（RCDATA 105）。安装与更新只读这份资源，**不执行**候选 DLL 的
入口点或导出。改动之后薄壳与 runtime 都要重新构建：没有该资源的旧 runtime 会被跳过。
版本号仍然定义在 `common/LoaderVersion.h`。

候选来自扫描根（我的文档 Mods 与 Steam Workshop 内容根）；游戏安装根不是模组容器，不参与扫描。
安装器 / 自更新**不**按 Mod 启用状态过滤（插件加载仍然会）。这份元数据只标识包格式，
不是发布者签名，且 `ProbeVersion` 只校验 PE + RC 105 —— 所以**只从你信任的来源分发 runtime DLL**。
