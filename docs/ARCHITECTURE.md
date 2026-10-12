# Civ6DllLoader 架构总览

- 适用版本：预发布 `1.0.0`（`common/LoaderVersion.h`），插件 ABI `CIV6_HOOK_API_VERSION = 1`。
- 这份文档是**唯一权威的架构说明**。
- 约定：本文用 `file` / `file:函数名` 定位，尽量不写死行号（行号会随改动漂移）。
- **⚠️ 标记 = 关键注意事项与设计约束**：包含生命周期边界、跨平台结构体布局差异以及跨线程调用的硬性约束。

---

## 0. 一分钟速览

### 0.1 宿主背景与系统定位
《文明VI》采用双层执行模型：主进程（`CivilizationVI.exe`）常驻运行，负责前端界面与引擎渲染；而核心游戏对局逻辑（`GameCore_XP2_FinalRelease.dll`）则作为动态模块，随对局开始由引擎加载（`LoadDLL`）、随对局结束卸载（`UnloadDLL`）。

**Civ6DllLoader** 是为《文明VI》构建的原生 C++ 插件扩展平台：
1. **注入引导**：在游戏目录下通过 `version.dll` 代理（`Civ6DllLoader.runtime.dll` 的副本）在进程初始化最早阶段载入，辅以专用的“薄壳安装器”在首次使用时自动就位；
2. **挂钩基础设施**：拦截关键生命周期函数（`LoadDLL` / `UnloadDLL` / `LoadUI`），维护统一的“挂钩站点表（HookSite Registry）”，以统一的 Stub 和跳板管理原生钩子与参数捕获；
3. **插件扩展面**：通过只读的函数指针表（`HookAPI`），向第三方插件提供模块取址、Hook 安装、内存补丁及引擎事件回调能力。

### 0.2 社区方案对比与设计动机

社区中绝大多数 DLL 模组依赖官方提供的规则集覆盖机制（通过 `Config.sql` 更新数据库 `GameCores` 表的 `DllPrefix`，将官方规则集替换为自定义编译的 DLL）。

**传统方案的痛点**：
1. **功能范围受限于 GameCore**：只能作为规则集 DLL 载入，无法介入主程序 EXE、系统库或前端 UI（ForgeUI）；
2. **单实例排他与 LoadOrder 争抢**：引擎同一规则集（如 `Expansion2`）只能挂载一个 DLL。多个 DLL 模组如果不做源码级合并就无法共存，必须竞争 `LoadOrder` 优先级以争夺生效权。

**Civ6DllLoader 的核心优势**：
1. **突破 GameCore 局限（全域扩展）**：通过 EXE 导入表代理（`version.dll`）进入进程，使插件能力不再局限于 GameCore 范畴，能够拦截主程序 EXE、注入前端界面以及常驻监听；
2. **完全接管加载逻辑，消除 LoadOrder 竞争**：拦截 EXE 内部的 `GameCore::LoadDLL`，将规则集槽位重定向回官方原版 DLL，同时接管插件扫描与加载流水线。多个符合规范的独立 DLL 插件可以并行加载、安全共存，消除了模组间对规则集 `LoadOrder` 的争抢；
3. **完善的跨版本函数自动匹配（抗更新能力强）**：内置基于 PE 异常展开表（`.pdata`）的跨版本自动矫正机制（`PdataMatch`），结合滑动窗口锚点链、线性插值/外推、函数序言哈希校验及虚表反推，能够有效应对游戏未来的版本更新。跨版本函数匹配成功率高达 80%，大幅降低了游戏更新导致 Mod 符号失效的维护与适配成本（§7.3）。

**已知局限与权衡**：
1. **强规范约束**：Loader 不会加载不符合设定规则的随意 DLL，插件必须接入本项目的规范（遵循目录结构划分、导出 `Civ6PluginKind` 声明类别、基于 `HookAPI` 交互）；
2. **首次安装仍依赖官方机制**：在 EXE 目录下尚未生成 `version.dll` 的初始状态下，薄壳安装器仍需借助官方 `GameCores` 覆盖机制进场一次以完成选举与部署，因此首次安装仍需重启游戏生效，且薄壳自身在首次进场时仍需参与官方 `LoadOrder` 竞争。
3. **目前只支持Steam版本**

### 0.3 三大核心架构原则

1. **生命周期双域隔离（Category × Domain）**：
   - **Global 插件**：随主进程启动加载，进程生命周期内永不卸载，操作范围严格限制为常驻模块（EXE 及系统库）。
   - **GameCore 插件**：随对局动态生命周期加载与卸载，操作范围严格限制在当前对局的 GameCore 内存映射区间（GameCore插件只适用于Expansion2（风云变幻）规则集）。
   - 该隔离由编译期符号重命名、加载期路径对账、运行期地址边界检查三重保证（§3.5、§4）。
2. **统一的挂钩站点记账（Unified Hook Site）**：
   同一目标地址在全局至多创建一次 MinHook 实例，统一重定向至 Loader 生成的分发 Stub。插件退役仅解绑分发插槽；仅在 GameCore 卸载清理（Teardown）时才物理还原入口字节（§5）。站点节点与 Stub 在进程生命周期内常驻保留并原地复用。
3. **严格的逆序析构（Safe Teardown Sequencing）**：
   退出对局时遵循固定时序：**还原入口字节 → 插件卸载通知（OnUnload/注销回调） → 调用原始UnloadDll函数卸载 GameCore 及其 Lua 环境 → 释放插件 DLL 模块**（§2.4）。该顺序避免了引擎 Lua 环境释放后回调已卸载插件代码引发的悬垂指针崩溃。
   ⚠️ 补丁不由 Loader 自动回滚：补丁在进程内默认常驻，若需撤销由插件自行调用 `Unpatch`（§5.8）。

进程里有哪些东西（详见 §1.1）：

| 模块 | 角色 |
|---|---|
| `CivilizationVI.exe` | 游戏本体；Loader 的钩子目标（LoadDLL / UnloadDLL / LoadUI…） |
| `version.dll` | **Loader 本体**（就是 `Civ6DllLoader.runtime.dll` 的副本，被放进 exe 目录）：exe 静态导入它，
|  |  同时它把系统 `version.dll` 的导出逐条转发出去，所以系统版本查询行为不变 |
| `GameCore_XP2_Shell_FinalRelease.dll` | **首次使用该类 Mod 时的 Loader 安装器**（零 hook、不启动 runtime）：
|  |  只有 Loader 缺席时才会被引擎加载；Loader 在位时它不进进程（见下） |
| `GameCore_XP2_FinalRelease.dll` | 游戏的对局逻辑（"短命域"，每次进对局都换） |
| `Localization_FinalRelease.dll` / `HavokScript_FinalRelease.dll` | 本地化 / Lua VM（常驻，按导出名解析） |

关键文件索引（读代码的入口）：

| 文件 | 职责 |
|---|---|
| `common/HookAPI.h` | 插件 ABI：HookAPI 表、类型、类别门禁、`HookAPI_IsCompatible` |
| `DllLoaderRuntime/HookLoaderApi.cpp` | **ABI 汇聚点**：`g_hookApi` 表本身 + 只读性校验；它取各模块 `*Impl` 的地址，不反向被依赖 |
| `DllLoaderRuntime/PluginRegistry.cpp` | 插件生命周期：`PluginEntry` 表、加载/卸载/隔离、类别判定、`ResetForReload`、排队释放 |
| `DllLoaderRuntime/ScriptBridge.cpp` | Lua / GameEvent / 脚本注册 / PushMethods 槽位（最大的一个模块） |
| `DllLoaderRuntime/HookEngine.cpp` | 站点表、stub 生成、capture、装钩与物理摘钩 |
| `DllLoaderRuntime/PluginDomain.cpp` | 域门（`IsTargetOpenToCaller` 等）与调用者身份认证 |
| `DllLoaderRuntime/AddressResolve.cpp` | 取址实现（RVA / 名称 / pattern / 虚表） |
| `DllLoaderRuntime/LoaderHooks.cpp` | exe 域钩子（LoadDLL / UnloadDLL）的安装与 detour 编排 |
| `DllLoaderRuntime/RuntimeEntry.cpp` | DllMain、休眠检测、一次性启动线程 |
| `DllLoaderRuntime/UiInject.cpp` | 主菜单 UI 注入（LoadUI detour + LuaContext） |
| `DllLoaderRuntime/ImageAddress.cpp` | PE 映像注册与 RVA 换算 |
| `DllLoaderRuntime/PdataMatch.cpp` | sidecar 解析 + pdata 匹配 + RVA 矫正 |
| `DllLoaderRuntime/PatchRegistry.cpp` | 补丁账本（按地址存原始字节）；**Loader 不自动回滚**，见 §5.8 |
| `DllLoaderRuntime/PluginInFlight.*` | 插件回调的在途登记与排空（**按加载代隔离**，见 §6.1） |
| `DllLoaderRuntime/Civ6MessageBus.*` | 插件间消息；总线的全局实例与插件 ABI 转发层也在此 |
| `DllLoaderRuntime/TeardownWindow.h` | teardown 窗口的共享状态（写侧 PluginRegistry/HookEngine，读侧 PluginDomain） |
| `DllLoaderRuntime/PluginTableAccess.h` | 插件表的只读门面（供 ScriptBridge / HookLoaderApi 查询，不暴露表本身） |
| `common/ModScan.cpp` / `common/EnabledMods.*` | 插件扫描与"启用 Mod"过滤（**只作用于插件**；安装/自更新 loader 的候选不看启用集） |
| `DllLoader/ShellBootstrap.cpp` | 薄壳侧的补装（首次安装；运行时自更新在 `LoaderUpdate.cpp`） |
| `tools/symdb.py` | 符号库流水线（唯一入口，含 AOB 生成/核对） |

> 读源码的顺序建议：`HookLoaderApi.cpp`（看 ABI 表的 78 个指针各归谁）→ `PluginRegistry.cpp`（生命周期）
> → `HookEngine.cpp`（挂钩）→ `ScriptBridge.cpp`（脚本面）。各模块的归属状态与门面见
> `docs/REFACTOR_PLAN.md` §3/§5。

---

## 1. 部署形态与启动链

### 1.1 进程里的模块与角色

进程里存在两条相互独立的进入路径：

#### 1. Loader 注入路径（基于导入表劫持）
EXE 的静态导入表中包含 `version.dll`，Windows 加载器优先从 EXE 目录解析该依赖。
- 我们将 `Civ6DllLoader.runtime.dll` 部署为 EXE 目录下的 `version.dll`，使 Loader 在进程初始化最早阶段自动载入（`DllLoaderRuntime/ProxyExports.cpp`）；
- 该模块将原生 `version.dll` 的导出函数逐条转发至系统真实库，完全不影响操作系统的版本查询行为。

#### 2. 薄壳载入路径（基于模组配置重定向）
薄壳（`GameCore_XP2_Shell_FinalRelease.dll`）依靠官方模组机制按需介入：
1. **官方默认加载**：官方在 `DLC/Expansion2/Config/Expansion2_Config.xml` 中登记 `GameCores(GameCore='Expansion2', PackageId=..., DllPrefix='GameCore_XP2')`，引擎据此拼接并加载 `Binaries/Win64/GameCore_XP2_FinalRelease.dll`；
2. **模组配置重定向**：模组通过 `Config.sql` 将数据库中的 `DllPrefix` 改写为 `GameCore_XP2_Shell`，使引擎转向请求加载模组目录下的薄壳 DLL；
3. **双态加载分支**：
   - **常规状态（Loader 已在位）**：Loader 的 `LoadDLL` Detour 拦截该调用，直接将请求路径改写回官方 GameCore 的绝对路径。因此**薄壳完全不会被载入内存**；
   - **首次安装（Loader 缺席）**：由于没有 Detour 拦截，引擎正常载入薄壳。薄壳自行导出 `DllCreateGameContext` 等接口转发给官方 GameCore 保证游戏正常运行，同时在后台执行 `version.dll` 的安装逻辑（§1.3）。

薄壳**不会**主动启动 runtime——runtime 已经以 `version.dll` 的身份驻留于进程中。薄壳唯一的职责是在缺少 `version.dll` 时完成选举与复制，并提示重启生效。只要 EXE 目录已存在 `version.dll`，薄壳在整个会话中均不参与任何操作。

- runtime：`Civ6DllLoader.runtime.dll`（产物在 `x64\Release\`），所有 hook / sidecar / 插件逻辑都在这里；
- 薄壳：`GameCore_XP2_Shell_FinalRelease.dll`（同样在 `x64\Release\`），只有安装器（扫描 Mod + 版本
  选举 + 补装 `version.dll` + 提示重启），**零 hook**、不启动 runtime；Loader 在位时不被加载。

### 1.2 version.dll 的休眠检测

`RuntimeEntry.cpp` 的 DllMain 先做一次自检，**两个条件同时成立**才启动 Loader：

1. **自身父目录 == 进程 exe 父目录**（`Base\Binaries\Win64Steam\` 或 `Win64\`）；
2. **宿主进程的 exe 名形如 `CivilizationVI*.exe`**（大小写不敏感的前缀 + `.exe` 后缀，
   DX11/DX12 两个变体都命中）。

任一不成立就"休眠"——不建线程、不读文件、不挂钩，避免把 Loader 逻辑泄漏到无关进程。
只比目录不够：任何从游戏 exe 目录加载这份 `version.dll` 的进程（崩溃上报器、第三方工具、
覆盖层）都会被 ② 挡住。休眠时 Logger 还没初始化（它在工作线程里才 Init），所以只往
`OutputDebugString` 留一行原因，用 DebugView 能看到；排查"loader 没生效"先看这里。
**注意**：如果你用改名过的 exe 或第三方启动器拉起游戏，Loader 会静默休眠——这是 ② 的直接后果。

### 1.3 安装器与自更新

两条相互独立的安装与维护通路：

**① 薄壳侧的“补装与接管”（`DllLoader/ShellBootstrap.cpp`）**——仅在薄壳被引擎加载时执行一次：

1. **版本探测与就绪判断（`RuntimePackage::ProbeVersionIncludingLoaded`）**：
   - 正常情况下，若 Loader 正常就位并成功装钩，`LoadDLL` Detour 会将其重定向至官方 GameCore，**薄壳根本不会被加载**；
   - 薄壳一旦被加载，说明当前并没有发生重定向拦截。此时检查 `exe\version.dll`：
     - 若文件不存在：判定为尚未安装，进入首次安装流程；
     - 若文件存在且包含合规的 RC 105 资源（属于我们的 Loader）：说明 Loader 虽然已在位，但其 `LoadDLL` 钩子未能生效（如进程休眠跳过、Hook 安装失败等），因此保持现状，零动作（无需重复复制或弹窗，直接透传官方 GameCore）；
     - 若文件存在但**不是我们的 Loader**（缺少合规的 RC 105 资源）：说明当前 `version.dll` 为外来代理或无关冲突文件，触发**接管流程**（带备份覆盖安装）；
2. **收集候选与版本选举**：
   - 收集 `Civ6DllLoader.runtime.dll` 候选（`ModScan::FindRuntimeCandidates()`，无参数）；
   - 逐个校验 PE 并读取 RC 资源 105，选举版本最高者（版本相同时取路径字典序较小者，候选不按 Mod 启用集过滤）；
3. **分流原子发布（发布到 `version.dll`）**：
   - **首次安装**（原文件不存在）：复制到 `version.tmp` 后直接原子重命名到位，并清理残留的 `version_Old.dll`；
   - **接管外来文件**（原文件存在且正被系统映射）：复制到 `version.tmp` 后调用 `ReplaceFileW` 进行带备份原子替换，将原文件安全移至 `version_Old.dll` 后覆盖写入；
4. **提示重启**：弹窗提示“已安装，点击确定立即重启游戏”并尝试启动新进程重启；
5. **静默兜底**：任何一步失败均**只记日志、不弹窗、不阻塞游戏启动**，本次会话直接透传官方 GameCore 正常完成。

**② runtime 侧的自更新（`LoaderUpdate::CheckAndApplyUpdate`）**——已在进程里跑的那份去换磁盘上的：

- 前提：自己的文件名必须是 `version.dll`（否则视为开发中的直接加载，跳过自更新）；
- 启动时若发现 `version_Old.dll` 存在，说明**上一会话刚做完一次自更新**，直接删掉它（自愈）；
- 候选走同一个 `ModScan::FindRuntimeCandidates()`；排除自己（规范化路径比较）后
  选更新的版本 → **先备份成 `version_Old.dll` 再原子替换**（`ReplaceFileW`：被替换文件被重命名到备份名、
  替换文件顶替它的名字，磁盘上不会出现 "`version.dll` 不存在" 的中间态；`ReplaceFileW` 被拒时退回
  旧的两步改名 + 失败回滚）→ 失败则回滚，当前安装保持不变；
- 换完这一会话**仍在用内存里的旧版本**，必须重启才生效（日志写 `update applied ... (restart to take effect)`）。

版本号与协议常量在 `common/LoaderProtocol.h` + `common/LoaderVersion.h`（`1.0.0`、RC 资源 id 105）。
薄壳拿到的候选版本号也来自同一份 RC 资源——**安装器不执行候选 DLL 的 `DllMain`/TLS/导出**，只读资源。

候选**不按 Mod 启用集过滤**（`ModScan::FindRuntimeCandidates` 中不调用 `FilterByEnabledMods`）：
安装与自更新 Loader 仅依据 RC 105 的版本号进行选举，这与“插件仅从启用的 Mod 中加载”属于两条独立通路。

候选发现规则如下：
1. **扫描范围**：候选仅收集自两个内容根目录：
   - 用户文档目录：`Documents\My Games\Sid Meier's Civilization VI\Mods`
   - Steam Workshop 内容目录（通过从 EXE 目录上溯，或查询注册表 `SteamPath` 并解析 `libraryfolders.vdf` 自动发现）
2. **排除游戏安装根**：游戏安装目录本身不是模组容器（其子目录 `Base`、`DLC` 等均不包含 `Binaries\Win64` 分发结构），因此不作为扫描根目录；
3. **安全边界**：`RuntimePackage::ProbeVersion` 仅解析 PE 结构与 RC 105 资源，不包含发行者数字签名验证；任何位于上述模组目录且结构合规的 Runtime DLL 均会参与版本选举。

插件侧的启用集过滤机制（`FilterByEnabledMods` + `EnabledMods::AllowsPath`）详见 §3.1。

### 1.4 一次性启动线程（阶段 A）

`RuntimeEntry.cpp` 的 DllMain 通过休眠检测后建一个**一次性**线程（`WorkerMain`），步骤是固定的
（下文编号与 `WorkerMain` 里的注释编号一一对应：1 / 1.2 / 1.5 / 2 / 2.5 / 3 / 4）：

1. `LoaderCore::InitEarly()`：`Logger::Init` + `VerifyHookApiTableProtection`（HookAPI 表必须落在只读页）
   + `PdataMatch::Init`（加载 sidecar）+ **为当前 exe 变体建档** + `Runtime::InitMinHook`。
   建档这一步（`RuntimeEntry.cpp` 的 `IdentifyExecutable()` 分支）容易被漏掉：`PdataMatch::Init` 成功
   只是让 sidecar 可用，还要为**当前进程实际是 DX11 还是 DX12** 建一份 exe 符号表，供插件按旧 exe
   RVA 作跨版本矫正。缺模块或建档失败一律 fail-closed：该映像的 `ResolveByRva`/`ResolveByName`
   返回 `nullptr`，**不回退原 RVA**（原 RVA 在更新后本就是错的），所以这两种情况都会留醒目日志；
2. `hks::InitHavokScript()` + `Localization::InitScript()`：两个**进程级静态导入**解析一次
   （缺失只降级各自的 API，不影响插件加载；为什么放这一阶段见 §1.5）；
3. `UiInject::ExtractResources()`：把内嵌的 FrontEnd UI 资源释放到 `<exe 目录>\Civ6DllLoader\` 子目录；
4. `LoaderHooks::InstallAll()`：exe 域钩子。**两个都是必需项**：`LoadDLL` 或 `UnloadDLL` 任一
   校验失败都会把本次已建的钩子全部回滚。`UnloadDLL` 必需是因为插件模块的释放时机挂在它上面
   （§2.4）——只装加载钩的话 GameCore 插件永远等不到释放点。
   两个 `MH_CreateHook` 都成功、且引擎模块槽取址可用之后，才用一次
   `MH_QueueEnableHook ×2 + MH_ApplyQueued` 同时启用：避免出现"只有加载钩生效"的窗口。
5. `UiInject::Install()`：主菜单 UI 注入钩，失败静默降级；
6. `LoaderUpdate::CheckAndApplyUpdate()`：runtime 级自更新检查（薄壳之外的第二道）；
7. `LoaderCore::LoadPluginsOf(PluginCategory::Global)`：扫描并加载 **Global 插件**。

这条线程**不常驻**：没有事件循环、没有 reconcile（见 §3.3）。此后一切都在游戏线程上由 detour 驱动。

> **设计考量：关于在 `DllMain` 中创建初始化线程的安全性（Loader Lock）**
> 
> Windows 加载器锁（Loader Lock）严格禁止在 `DllMain` 调用栈内执行 `LoadLibraryExW`、文件 I/O 以及跨模块复杂同步。为此，Runtime 采用异步工作线程完成阶段 A 初始化：
> 
> * **轻量化派发**：`DllMain` 仅执行 `DisableThreadLibraryCalls` 与模块路径校验，调用 `CreateThread` 创建独立工作线程后，立即通过 `CloseHandle` 关闭句柄并返回；
> * **避免循环等待**：主加载线程**绝不阻塞等待**该工作线程（无 `WaitForSingleObject` 调用），因此彻底消除了与系统加载器锁成环死锁的可能；
> * **薄壳对比**：薄壳通过将所有逻辑延迟至引擎回调 `DllCreateGameContext` 执行，完全避开了 `DllMain`；Runtime 则通过非阻塞的工作线程达成相同安全保证。

### 1.5 阶段 A / 阶段 B

- **阶段 A（进主菜单前）**：上面那条线程。此阶段 GameCore 还没加载，Global 插件的 `OnLoad` 在这里跑；
  它们能做的取址/挂钩只涉及 exe 与常驻模块。
  该阶段还解析两个**进程级静态导入**：`hks::InitHavokScript()`（Lua VM）与 `Localization::InitScript()`。
  两者随 exe 装载、与对局周期无关，必须在阶段 A 解析，**不能推迟到阶段 B**。
  防御理由：若放在阶段 B 且解析失败提前退出，此时 GameCore 映像已被操作系统加载映射，
  但 Loader 尚未将其 attach 跟踪、且没有建立 teardown 保护窗口；这会导致 Global 插件能够
  合法钩入这一处于脱管状态的映像，而换局退役时又无法被清理。
  在阶段 A 解析时，导入缺失仅**降级**各自的 API（逐入口返回安全默认值 + 限次日志），
  **不影响插件加载**——插件可能完全不使用 Lua 或本地化。
- **阶段 B（进对局时）**：引擎调用 `LoadDLL` → 我们的 detour（`LoaderHooks.cpp`）改写路径并调原函数，
  成功后 `LoaderCore::InitializeGameCorePhase()`：`AttachGameCore` →
  `EnsureScriptHooksInstalled` → 加载 **GameCore 插件**。
  （`hks::InitHavokScript` / `Localization::InitScript` **不在**这里——见阶段 A 的说明。）
- **退对局**：引擎调用 `UnloadDLL` → 我们的 detour 先 `ResetForReload()`（见 §2.3）再调原函数。

`LoaderHooks::InstallAll()` 与 `UiInject::Install()` 都在阶段 A（那条一次性线程里）装钩子。
`LoadUI` 的钩子归 `UiInject::Install()` 管，和 `LoadDLL`/`UnloadDLL` 是两套独立的事务。

> **关于自更新与装钩日志顺序**：`InstallAll()` 排在自更新检查之前，因此日志中先出现
> `InstallAll: LoadDLL + UnloadDLL installed; module slot=...`，随后才出现自更新检查输出。
> 更新成功的 DLL 将在下一次启动时随系统加载生效。

---

## 2. 生命周期与 teardown

### 2.1 阶段状态

- 阶段 B 是否就绪：`ScriptBridge::SetGameCorePhaseReady` / `IsGameCorePhaseReady`
  （`std::atomic<bool>`，定义在 `ScriptBridge.cpp`）。`InitializeGameCorePhase()`
  置 `true`，`ResetForReload()` 置 `false`；`LoaderCore::IsInitialized()` 只回答这一件事。
  用原子的理由：两个读点本来就持 lifecycle 锁，读侧无锁后少一次重入；写侧仍持锁，语义不变。
- `g_gameCoreTransitionMutex`（递归）：把"阶段切换"与"插件加载/卸载"串起来，保证
  「attach → 装钩 → 加载 GameCore 插件」与「teardown → 卸载」不交错。三个入口都先拿它：
  `LoadPluginDllInternal` / `InitializeGameCorePhase` / `ResetForReload`。
- **teardown 窗口**（`LoaderCore::Teardown::g_address` / `g_sizeOfImage`，定义在 `TeardownWindow.h`）：
  窗口内 `TargetInTearingDownGameCore(target)` 为真，`InstallHook` 直接拒绝；窗口也是 teardown 后半段
  "哪些站点属于本次要拆的映像"的唯一判据（因为那时 `ImageAddress` 已经 detach）。
  这两个字段被 4 个模块读写（PluginRegistry / HookEngine / PluginDomain + 头文件本身），因此必须
  **跨 TU 共享同一份存储**：写成各 TU 独立的 `static` 会让窗口静默失效且不报错。
  两个字段是 `std::atomic`，成对生效有固定次序：写侧先 size 再 address(release)，清零点先
  address(release) 再 size；读侧先 address(acquire)，非 0 才读 size。写侧是游戏线程，读侧还有
  插件线程（`TargetInTearingDownGameCore`）。

### 2.2 LoadDLL / UnloadDLL 的编排（`LoaderHooks.cpp`）

两个 detour 共用一份 exe 侧的引擎模块槽 `g_engineModuleSlot`（在 `InstallAll` 里由 `kAob_hModule` 解析，
**必须在 MH_Enable/ApplyQueued 改写 LoadDLL 入口之前**取址——该 AOB 覆盖 LoadDLL 入口）。读它用
`ReadEngineModule()`（`__try` 包裹，槽不可读就当作"拿不到"而不是崩）。

`LoadDllDetour`：

1. `GetRuleSetName()` 返回空 → 还没进游戏（启动早期加载 Base 等），原样透传；非 `EXPANSION_2` → 透传（只支持 XP2）；
2. 把入参（Mod 顶替 `GameCores` 后引擎请求的**薄壳**路径）**改写成官方 GameCore 的绝对路径**
   （`OfficialGameCoreRelPath` 给官方相对路径、`BuildOfficialPath` 拼到游戏根下；官方文件不存在才
   透传原路径）。重定向规则：**引擎槽位=官方**，薄壳只在 Loader 缺席、没有这个 detour 时才被加载；
3. **先调原函数** `g_origLoadDLL(target)`，把返回值原样带回；
4. `IsInitialized() || g_unloadIncomplete` → 直接返回。两种情形都表示"当前这一局不该重新初始化"：
   阶段 B 已经就绪，或引擎上一次的卸载还没走完（`UnloadDllDetour` 置位、原函数返回后若没观察到
   模块槽清零就不清）；
5. 读 `g_engineModuleSlot`：拿不到或为 `nullptr` → 记日志返回，**不**初始化（没有确认的映像就没有可挂的域）；
6. `InitializeGameCorePhase()` 成功 → `LoadPluginsOf(GameCore)`；失败 → 只记日志。

> **为什么不看 `LoadDLL` 的返回值**：反编译（`docs/analysis/LoadDLL_analysis.md` 第 15–16 行，
> `0x1400F851F`）是 `if (hModule != nullptr) return 0;` —— 引擎的 `LoadDLL` 有**三条路径**返回 0：
> 模块已加载（幂等短路）、`LoadLibraryW` 失败、缺 `Dll*` 导出。只有返回 1 才确定是"这次新加载成功"。
> 唯一调用者 `AppModdingFramework::LoadGameCore` 会在调用前先 `UnloadDLL`，但那只保证不了模块槽
> 一定被清空（失败路径）。读模块槽是唯一能区分"映像在不在位"的判据。

`UnloadDllDetour`：

1. 读模块槽得到 `before`；`before` 非空**或**阶段 B 已就绪 → 置 `g_unloadIncomplete = true`
   （"引擎的卸载还没完成"）；
2. `IsInitialized()` → `ResetForReload()`（清理 + 把 GameCore 插件模块**入队**）；
3. 调原函数 `g_origUnloadDLL()`——**引擎在这里卸掉 GameCore 映像连同它的 gameplay/ui Lua 环境**；
4. **只有观察到槽从非空变成空**（`hadModule && ReadEngineModule(after) && !after`）才
   `ClearGameCoreTeardownWindow()` + `FreePendingPluginModules()`，并清 `g_unloadIncomplete`。
   引擎的空操作或失败不能触发释放：此时 Lua 环境可能还在引用插件映像里的闭包。
   这也是"LoadDLL 返回 0 不算卸载屏障"的另一半——卸载屏障是**槽被清零**，不是函数返回。

### 2.3 ResetForReload 的完整顺序（每一步的位置都有理由）

1. 拿 `g_gameCoreTransitionMutex` + `LoaderCore::LifecycleMutex()`；
2. 阶段 B 就绪标志置 `false`（`ScriptBridge::SetGameCorePhaseReady(false)`；此后 `EnsureScriptHooksInstalled`
   等入口会自行早退）；
3. 进入 teardown 窗口（`LoaderCore::Teardown::SetWindow(base, sizeOfImage)`；`ImageAddress` 仍 attach；
   取不到映像信息时显式设 `SetWindow(0, 0)`，见 §9.1 第 1 条）；
4. 放掉 lifecycle 锁（下面要等回调、要加载/卸载插件，持锁等会锁反转）；
5. `DisableGameCoreDomainSites()`：趁旧映像仍映射，把 GameCore 域**全部已挂钩站点**
   `MH_QueueDisableHook` 后**一次** `MH_ApplyQueued` → 所有入口字节还原、不会再有人进入 stub 或插件 detour。
   不可读的目标（映像已经没了的兜底路径）不排队，改打 `recordStale`；
6. `CleanupAllCaptureSites()`：只清**落在 GameCore 域内**的捕获订阅，exe / 常驻模块域上的保留；
7. `UnloadPluginsOf(PluginCategory::GameCore)`：逐个插件走卸载流程（§3.3），GameCore 的模块句柄**只入队**；
8. 重新拿 lifecycle 锁；
9. `RemoveGameCoreDomainSiteRecords()` 执行站点清理与解绑：
   - **设置窗口与解绑**：进入 teardown 窗口（内部设防）并执行 `ImageAddress::DetachGameCore()`；
   - **排空在途调用**：临时释放 lifecycle 锁，等待 `g_activeSharedDetours` 归零以排空在途共享 detour；
   - **重锁并扫表复位**：重新获取 lifecycle 锁，重新扫描站点表以物理摘钩。成功则 `MH_RemoveHook` 并**原地复位站点**（保留并复用节点及 stub，清空 capture 槽；**绝不 erase**，因为 stub 机器码硬编码了 `&HookSite`）；失败则标记 `recordStale` 并拔除 detour 槽；
   - **复位共享入口**：复位 `g_origRegisterScriptData(/ForUI)` 与 16 个 PushMethods 槽位；
   - **窗口存续**：**teardown 窗口不在此处清除**，必须维持到引擎真正完成卸载——由 `UnloadDllDetour`
     在原函数返回**且**确认模块槽从非空变空后调 `ClearGameCoreTeardownWindow()`（见 §2.2 第 4 步）；
10. 回到 `UnloadDllDetour`：调 `g_origUnloadDLL()` → 若槽已清零则 `ClearGameCoreTeardownWindow()` →
    `FreePendingPluginModules()`（见 §2.2、§2.4）；

为什么是这个顺序：

- **第 5 步必须在第 7 步之前**：入口字节还原之后才谈得上"Free 插件不会留下入口跳向已释放代码的窗口"；
- **第 9 步重扫而不是沿用第 5 步的地址列表**：第 5～9 步之间还跑过插件卸载，而 `PushLuaMethods` 这类
  注册入口按设计不过域门，理论上仍可能往正在拆除的映像上装钩——重扫能一并收掉；
- **这里【不做】补丁区间清账，是设计决定**：Loader 不替插件回滚补丁（§5.8），补丁记录只在插件
  自己调 `Unpatch` 时才从 `PatchRegistry` 摘除。副作用是**未撤销的补丁记录会跨代存活** —— GameCore
  插件若没调 `Unpatch`，它那条落在旧映像区间里的记录会留到进程退出；新一代 GameCore 映射到同一基址时，
  这条陈旧记录仍会参与 `OverlapsRegistered` / `OverlapsHookPrologue` 的区间仲裁（见 §5.8）。

### 2.4 插件模块的释放时机

- `UnloadPluginByOwnerId`（GameCore 类别）**只把句柄入队**（`g_pendingFreeModules`，由 `g_pendingFreeMutex`
  保护）。类别/ABI 不符的拒载不走这条：那种拒载发生在 `OnLoad` 之前，直接释放引用（§3.3）；
- `LoaderCore::FreePendingPluginModules()` 在**唯一一处**被调用：`UnloadDllDetour` 的 `g_origUnloadDLL()`
  返回之后，**且**满足"原函数确实把非空模块槽清成了空"。`LoadDllDetour` 不再调它——
  LoadDLL 返回本身不是卸载屏障（引擎在模块已加载时也返回 0，见 §2.2 的说明）；
- 条件是"槽已清零"而不是"函数返回了"：引擎的 `UnloadDLL` 可能什么都没做（空操作）或中途失败，
  此时 Lua 环境还可能引用插件映像里的闭包，释放模块就是 UAF；
- 于是"插件映像已释放、而它的 Lua 闭包还能被调用"这个前提不存在：gamecore 的 gameplay/ui Lua 环境
  是引擎卸载里拆的，闭包所在的 state 已经没了；
- 代价与边界：`OnLoad` 崩溃被隔离的 GameCore 模块会一直映射到下一次 Load/Unload；Global 插件本来就永不卸载。

### 2.5 锁与锁序

| 锁 | 保护 | 备注 |
|---|---|---|
| `g_gameCoreTransitionMutex`（递归） | 阶段切换串行化 | 最外层；文件级 static，在 `PluginRegistry.cpp` |
| `LoaderCore::LifecycleMutex()`（递归） | `g_plugins`、各类注册表、槽位表、owner 探针 | 最常被重入。实现是 `PluginRegistry.cpp` 里的文件级 static `g_pluginLifecycleMutex`，**不导出变量**，其它模块经这个访问器拿同一把锁 |
| `g_pushStateMutex` | PushMethods 的 16 个槽位 | 在 lifecycle 内层；文件级 static，在 `ScriptBridge.cpp` |
| `Runtime::MinHookMutex()` | 站点表 + 所有 `MH_*` 调用 | 在 pushState 内层 |
| `g_captureMutex` | 站点上的捕获派发数据（`captureOuts`/`retiring`/`captureParamIndex`） | 最内层 |
| `ImageAddress::g_mutex` | 映像登记（base/size/id） | 叶子 |
| `g_scriptStateMutex` | ScriptGlobals 的两个注册表 | 叶子（持有它时不再取别的锁）；与 `pushState` 同为 lifecycle 的下层，两者**从不互相嵌套**（见 `ScriptBridge::RemovePluginRegistrations`） |
| `Civ6MessageBus::mtx_` | 消息总线的 handler 表 | 出锁后才 `Enter`/排空（总线 → lifecycle） |
| `PluginInFlight::Owner::mtx` | `WaitAll` 的条件变量等待 | 等待时只持这一把 |
| `g_pendingFreeMutex` | 待释放句柄队列 | 叶子；`FreeLibrary` 一律在锁外做（插件 `DllMain(DETACH)` 可能回调 loader） |
| `g_detourDrainMutex` + `g_detourDrainCv` | 等 `g_activeSharedDetours` 归零 | 等待前已放掉 lifecycle / MinHook / capture 锁（**不得**持 lifecycle 等）；仍持最外层 `g_gameCoreTransitionMutex`——它只串行化阶段切换，不参与在途回调取锁 |

固定顺序：`transition → lifecycle →{ pushState | scriptState }→ MinHook → capture/ImageAddress`
（消息总线自成一层：`mtx_ → lifecycle`，但它从不与站点锁嵌套）。
凡是"插件代码可能被调用"的地方（`OnLoad`/`OnUnload`/回调/`WaitAll`）都必须**先放掉 lifecycle 锁**。

跨模块状态一律走访问器而不是 extern 变量（`LifecycleMutex()` / `GlobalBus()` /
`ScriptBridge::IsGameCorePhaseReady()` 等）。这是拆分的既定原则：extern 变量需要跨模块可见，
文件级 static 则天然做不到，两者都不能保证"只有一份"。

> **注意"锁序"只对嵌套持有成立。** 两个不相交的临界区（例如
> `RemoveGameCoreDomainSiteRecords` 里先取 MinHook 的块与后取 pushState 的块，
> 中间已释放前者）**不构成任何锁序关系**，无论它们的物理先后。
> 核对锁序时必须看大括号作用域，不能只看行号先后。

### 2.6 日志

- Loader：`Logger::Init` → `%LocalAppData%\Firaxis Games\Sid Meier's Civilization VI\Logs\Civ6DllLoader_Loader.log`；
  进程内**首次打开截断、之后追加**（用 `Local\` 命名 mapping 记标记，且故意不 `CloseHandle`——
  否则 GameCore 被卸载时标记就没了），所以一份日志里能同时看到重载前后两代；
  薄壳另有 `Civ6DllLoader_Shell.log`；
- 排查时优先看的几行：`LoadDLL: ruleset=...`、`InstallAll: exe image=...`、
  `GameCore attached image=.. base=.. SizeOfImage=..`、`HookSite: installed hub stub ...`、
  `ResetForReload: ...`、`RemoveGameCoreDomainSiteRecords: reset N site(s) in place (MinHook record + trampoline released; node kept: stubs embed &HookSite), marked recordStale=M; ...`、
  `Plugin deactivated, module queued for free after engine GameCore unload`、
  `Plugin module freed after engine GameCore unload: <handle>`、`Plugin deactivated, module parked (kept mapped)`。

排查"插件没加载"时按这个顺序看：`LoadDLL: no confirmed GameCore module; plugins not loaded`
（引擎模块槽拿不到或为空 → 根本没进初始化）、`InitializeGameCorePhase failed`（阶段 B 初始化失败）。
注意 `g_unloadIncomplete` 不写日志：它只让下一次 `LoadDllDetour` 提前返回，所以"LoadDLL 打了
ruleset 日志但插件一条没加载"时，要先确认不是被这个标志挡下的。

---

## 3. 插件模型

### 3.1 目录与类别判定

扫描（`common/ModScan.cpp`）：内容根 = `Documents\My Games\...\Mods` / Workshop，
每个根下找 `<mod>\Binaries\Win64\Plugins\<Global|GameCore>\*.dll`（插件目录固定是 `Binaries\Win64`；
`Win64Steam` 只影响 exe 目录的形状，插件扫描不认它），
按文件名去重，再用 `common/EnabledMods.*`（读 `Mods.sqlite` 的启用集）过滤：**路径必须落在某个启用 Mod
的根下**，且**只认 SQL 返回的那个精确 mod root**（`AllowsPath` 不沿路径向上找 `.modinfo` 再放宽：
外层 mod 目录即使包着某个启用 root，也不因此获得授权）。只比 GUID 不够：同一 GUID 可能有多份安装副本。
**没有任何"锚本地豁免"**：授权判据只有 `AllowsPath` 一条。`Mods.sqlite` 读不到时**一个都不加载**
（失败即关闭）。`CollectScanRoots()` 不接受锚模块参数：内容根的发现全部与调用方无关
（`SHGetKnownFolderPath` 拿 Documents、注册表 + `libraryfolders.vdf` 拿 Steam/Workshop、
exe 目录上溯拿 Workshop）。

**游戏安装根不是内容根**：它不是模组容器（直接子目录 `Base`/`CTP`/`DLC`/`Debug`/`LaunchPad`
都不含 `Binaries\Win64`，实测候选取集恒为空）。游戏自己 `Mods.sqlite` 的 `ScannedFiles` 记录的
安装内模组根是 `<gameRoot>\DLC\<名>` 与 `<gameRoot>\Base\Assets\Scenarios\<名>`；官方 DLC 里只有
`DLC\Expansion1` / `DLC\Expansion2` 带 `Binaries\Win64`，而那是官方内容、不是 loader/插件的分发位置。


类别判定（`PluginRegistry.cpp:CategoryForPath`）：把路径规范化（全小写、`/`→`\`）后含
`\plugins\global\` → `Global`，**其余一律 `GameCore`**。注意默认方向：放到预期之外的位置会被当成
GameCore（每局真卸载 + 只能动 GameCore 映像）。

类别决定三件事：加载时机（阶段 A / 阶段 B）、生命周期（驻留 / 真卸载）、域门（哪半边地址空间可用）。

### 3.2 加载流程（`LoadPluginDllInternal`）

1. 拿 `g_gameCoreTransitionMutex` + lifecycle 锁；
2. `GetModuleHandleExW(UNCHANGED_REFCOUNT, path)` 先看模块是否已驻留；没有再 `LoadLibraryExW`,
   用 `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`。`ownsRef` 标记引用是否归本次调用。
   这一步（以及紧接着的 `Civ6PluginKind` 调用）都在**不持 lifecycle 锁**时做：它们会执行
   第三方 `DllMain`/插件导出，而那把锁是最常被重入的（插件回调、owner 探针都要它），持着它跑别人的代码
   会把插件回调路径一起卡住甚至自死锁；`g_gameCoreTransitionMutex` 仍罩整个加载过程，所以不会被 teardown 穿插；
3. 句柄重复（同一模块已在跟踪表里）→ 释放自己拿到的引用并返回 false；
4. **类别门禁（在 OnLoad 之前）**：读插件的 `Civ6PluginKind` 导出（低 32 = kind；高 32 = apiVersion
   只进日志，由 `common/HookAPI.h` 自动发出）。缺导出（旧头文件编出来的插件）或 kind 与"安装路径
   推出的类别"不符 → 记日志 + 释放本次自己拿到的引用（`ownsRef`）后拒载；apiVersion **不参与**这里的
   判断，ABI 兼容性由插件侧 `HookAPI_IsCompatible`（版本 + `structSize`）决定。
   **所有拒载都发生在 OnLoad 之前**：此时没有任何**经 Loader 账本**的钩子/补丁/回调需要回滚，`FreeLibrary`
   只释放本次自己拿到的引用。注意这不等于「插件一行代码都没跑过」——`LoadLibraryExW` 已经执行过它的
   `DllMain`/CRT 初始化，`Civ6PluginKind` 的调用也在 SEH 叶子里执行；那是信任边界，不是安全保证；
5. 找 `OnLoad` 导出；缺失 → 拒载（释放引用）；
6. 组装 `PluginEntry`（handle / path / stem 名 / `ownerId` = 规范化全路径 / category /
   `inFlight` = **本次加载代**的 `PluginInFlight::Owner*`），
   `SetPluginState(Loading)`（同步放行镜像）并 push 进 `g_plugins`。
   **顺序不能反**：`SetPluginState` 要写 `entry.inFlight` 的放行镜像，先置状态会让它作用在 `nullptr` 上
   而静默失效；`inFlight` 必须由 `BeginLifetime` 新建（不是 `Resolve`），否则代际隔离失效（§6.1）；7. `SetActivePluginContext(ownerId, handle)` → 放锁 → `CallOnLoadSafe(onLoad)`（SEH 包住）→ 清上下文 → 重新拿锁；
8. `OnLoad` 崩溃 → `QuarantinePluginByOwner`（§3.3）+ **模块释放策略**（§3.3 末），返回 false；
9. 有 `OnMessage` 导出 → 自动注册消息处理器；
10. `SetPluginState(Active)`，加载完成。

### 3.3 卸载 / 隔离 / 驻留

**崩溃隔离 `QuarantinePluginByOwner`**（标记 + 回滚除补丁外的全部注册）：
`SetPluginState(Quarantined)` → 注销消息 → `PluginInFlight::WaitAll` →
`RemovePluginHooks`（拔 detour 槽）→ `CleanupCaptureSitesForOwner` → `RemovePluginOwnedRegistrations`。
隔离后阶段 B 不会再重试它：条目留在 `g_plugins`（状态不是 `Active`），`LoadSinglePlugin` 的按路径去重会拦住。

**崩溃后的模块释放策略**（`OnLoad` 已经跑过，插件可能留有待执行的 detour）：
- **GameCore 类别 → 入队**（`QueueGameCoreModuleForFree`）：等引擎卸完 GameCore（连同它的 gameplay/ui
  Lua 环境）之后才 `FreeLibrary`；Free 时 `FreePendingPluginModules` 会把跟踪表里同句柄的条目句柄置空，
  防止悬垂句柄被"同基址复用"的新模块误命中；
- **Global 类别 → 驻留**：exe 域钩子被高频调用，`MH_DisableHook` 不等待所有在飞调用，此刻 `FreeLibrary`
  会把正在执行的插件代码变成 UAF（代价：一份映像映射到进程退出）；
- **类别/ABI 不匹配的插件不走这里**：那种拒载发生在 OnLoad 之前（§3.2 第 4 步），直接释放引用。

**正常卸载 `UnloadPluginByOwnerId(ownerId, freeModule)`**：
`SetPluginState(Deactivating)` → 放锁 → 注销消息 → `WaitAll` → `OnUnload`（SEH）→
`RemovePluginHooks`（拔槽，绝不在插件卸载时物理摘 MinHook 记录）→ `CleanupCaptureSitesForOwner` →
`RemovePluginOwnedRegistrations` → 重锁 → 从 `g_plugins` 摘除 → 放锁 → `freeModule` 时**入队待释放**，
否则记"module parked"（驻留）。

> **补丁不在上面这条链里**：Loader 不再自动回滚（§5.8）。要撤销的插件应在 `OnUnload` 里自己调
> `Unpatch` —— 那时 GameCore 映像还活着、插件也知道自己的状态。

- **Global 永远驻留**（含 OnLoad 崩溃隔离之后，见上面的释放策略）：只在启动时加载（禁用 Mod 需要重启），
  且游戏线程可能仍停在它某个 exe 域 detour 里；驻留的代价是插件静态状态跨会话保留，所以 `OnLoad`
  必须可重入（重新注册它的钩/回调）。
  ⚠️ **隔离（`QuarantinePluginByOwner`）不调 `OnUnload`**，所以隔离时插件打的补丁既不会被它自己
  撤销、Loader 也不自动回滚（§5.8）——**补丁会留在游戏里直到进程退出**。
- **GameCore 真卸载**：它的钩/补丁只允许落在当前 GameCore 映像内（§4.1），加上重载时整套 teardown，
  所以静态状态不会跨局残留。

### 3.4 插件 ABI：HookAPI 表与版本规则

- 表是 `const HookAPI g_hookApi`（`.rdata`，只读——插件写它会当场 AV，被 `CallOnLoadSafe` 接住）；
- **表的形状由两条 `static_assert` + 一个计数常量钉死**：`CIV6_HOOK_API_ENTRY_COUNT`（当前 77）
  必须与 `sizeof(HookAPI)` 和末尾成员偏移同时吻合，否则编译失败；启动时 `VerifyHookApiTableProtection`
  再扫一遍空项（聚合初始化漏写一项只会静默零填，编译期抓不到）；
- **当前 `CIV6_HOOK_API_VERSION = 1`，且预发布阶段删改前缀不升版本号** —— 从未对外发布过插件，
  `1` 是它唯一出现过的值。
  此后只在**尾部追加**过入口（`GetSymbolDbState` / `GetSymbolDbMatchRatio`）——
  追加不破坏旧偏移，旧插件不读新字段即可继续工作，`HookAPI_IsCompatible` 的 `structSize` 比较会
  放过这种情形。
  **在预发布阶段，插件必须用当前头文件重新编译**；首次对外发布之后才需要递增版本号；
- **类别走一条独立于表的通路**：`common/HookAPI.h` 为插件自动发出 `Civ6PluginKind` 导出
  （`extern "C" __declspec(dllexport) inline`，低 32 = kind、高 32 = `CIV6_HOOK_API_VERSION`），
  loader 在 `OnLoad` **之前** `GetProcAddress` 读它、**只判类别**（高 32 位只进日志）。插件作者一行都不用写；
- `HookAPI_IsCompatible(api)` 对比 `apiVersion` 与 `structSize`，**这是一个跨两边的有效比较**：
  `api` 是 Loader 通过 `OnLoad` 传进来的 `LoaderCore::RuntimeHookApi()`（= `&g_hookApi`，
  Loader 编译进去的那份表），`CIV6_HOOK_API_VERSION` 与 `sizeof(HookAPI)` 才是插件编译进去的值。
  因此它能同时检出两种失配：**破坏性改动**（Loader 侧 `apiVersion` 变了而插件头没跟上，或反之）
  与 **append-only 场景**（Loader 表更大时 `structSize` 不等式成立，正是 `common/HookAPI.h` 里
  `HookAPI_IsCompatible` 上方注释承诺的语义；Loader 侧 `structSize` 另有 static_assert 钉死）。
  它守不住的是"插件根本没调它"——
  真正在 `OnLoad` 之前硬把关的仍然是上一条的 `Civ6PluginKind` 导出：
- 两个门的分工：`Civ6PluginKind` 决定"要不要跑 `OnLoad`"（Loader 侧强制），
  `HookAPI_IsCompatible` 是插件进入主逻辑前的自检（插件侧自愿，但比较内容有效）。

> **线程调用契约说明**：除明确标注“仅游戏线程调用”的接口（如 Lua 原语与部分 GameCore 专属入口）外，其余大部分入口内部均通过专用互斥锁保护。关于并发访问与锁序要求，详见 §2.5 锁表。

### 3.5 类别门禁三层

1. **编译期**（`common/HookAPI.h` 底部）：插件在工程宏里定义 `CIV6_PLUGIN_GLOBAL` 或
   `CIV6_PLUGIN_GAMECORE`。Global 下把 8 个 GameCore 专属**成员名**重命名成自带解释的符号，
   于是"调用或取地址"都在编译期报「不是 HookAPI 的成员」；结构体字段一个没少、偏移一个没变。
   两个宏都没定义且不是 loader → `#error`；loader 侧靠 vcxproj 里的 `CIV6_HOOKAPI_BUILD_IMPL` 逃逸。
2. **加载期**（`LoadPluginDllInternal`，在 `OnLoad` 之前）：`GetProcAddress(plugin, "Civ6PluginKind")`
   读"插件自述 kind"，与"安装路径推出的类别"（`CategoryForPath`）对账，不符就拒载——此时插件还没跑过
   任何代码（apiVersion 也在导出里，但只记日志，不参与拒载）。
3. **运行期**（`RequireGameCoreOwner`）：8 个 GameCore 专属入口各有一道兜底，防"不带头文件、按结构体
   偏移硬调"的插件；探针地址优先用插件提供的函数地址，没有则用 `_ReturnAddress()`。

这三层只管**接口面与身份**；"目标地址是否开放"是另一层（§4.1）。

---

## 4. 插件接口（HookAPI 全表）

表共 79 个字段 = 2 个头（`apiVersion` / `structSize`）+ 77 个入口。按"谁能用、受什么限制"分四类。

### 4.1 双域通用，但按"目标地址域"设门（9 个）

| 入口 | 门 |
|---|---|
| `InstallHook(target, detour, original)` | 目标地址 |
| `Patch(target, bytes, len)` / `Unpatch(target)` | 区间 / 目标地址 |
| `RegisterGlobalCapture(providerAddress, paramIndex, out)` | 目标地址（必须是可执行函数入口） |
| `ResolveByRva` / `ResolveByName` / `ResolveByRvaEx` / `ResolveByPattern` / `ResolveByVTable` | `image` 参数 |

规则（基于正面白名单授权，而非简单的非 GameCore 排除）：

- `GameCore` 类别：目标必须落在**当前 GameCore 映像**内（其唯一合法操作域）；
- `Global` 类别：目标必须落在**某个已加载的非 GameCore 模块**内 —— exe、常驻系统 dll（user32/dxgi…）、
  插件自己的模块都算；**堆、`VirtualAlloc` 的 JIT 页、空闲地址、将来会被 GameCore 占用的地址一律拒绝**。

实现（`PluginDomain.cpp`）：`IsTargetOpenToCaller`（单点）/ `IsRangeOpenToCaller`（整段）/
`IsImageOpenToCaller`（image 参数）；模块判定用 `RangeInsideOneLoadedModule`——两端各自的
`GetModuleHandleExW(FROM_ADDRESS)` 返回同一模块句柄，即证明整段同属一个已加载模块（不解析 PE）。

`GetModuleHandleExW(FROM_ADDRESS)` **严格按该模块的 `SizeOfImage` 判定归属**（实测：
`kernel32` 基址 `+SizeOfImage-1` 命中，`+SizeOfImage` 即返回 FALSE / `ERROR_MOD_NOT_FOUND`=126）。
所以"`!hasGameCore` 让第一个合取项恒真"并不构成放行——判据由第二个合取项
`RangeInsideOneLoadedModule` 独立承担，堆页、JIT 页、空闲地址及映像外的对齐余量均无法取得模块句柄。


与域门**并列**的其它仲裁（顺序见 §5.5）：页属性预检（`PluginBoundary`）、补丁区间仲裁
（`PatchRegistry::OverlapsRegistered`）、装钩前导窗口仲裁（`OverlapsHookPrologue`）、teardown 窗口
（`TargetInTearingDownGameCore`）。

### 4.2 GameCore 专属（7 个，编译期 + 加载期 + 运行期三层限制）

`EditPlayer`、`RegisterGameEvent`、`TriggerGameEvent`、`RegisterScriptGlobals`、
`RegisterScriptGlobalsForUI`、`PushLuaMethods`、`RegisterPushMethodsTarget`。

为什么专属：`EditPlayer` 解析 `GameCore::Context::Globals::EditPlayer` 符号；其余六个操作
**gamecore 的脚本环境**（往 Lua 表里放闭包、注册脚本全局、事件）。Global 插件用它们没有意义：
对局前拿不到对象，对局中也不该持有 GameCore 域的引用。

### 4.3 Lua 原语（44 个）——不是 GameCore 专属

全部是 `HavokScript_FinalRelease.dll` 导出的薄封装（`HavokScript.cpp` 里由一张导入表 + 宏批量登记，
加 `checkplayerid` + 极端情况下的原始栈兜底）。入口本身**与 GameCore 无关**：作用对象是**调用方传进来的**
`lua_State*`，所以两类插件都开放。导入在**阶段 A** 解析一次（该 DLL 是 exe 静态导入、常驻）；
缺失时逐个入口降级为安全默认值 + 限次日志，**不影响插件加载**。

### 4.4 其它（17 个）

- 消息：`BroadcastMessage` / `RegisterMessageHandler` / `SendMessageTo`（§6.2）；
- `Log`、映像元数据 `IsImageLoaded` / `GetImageInfo`；
- 符号库状态：`GetSymbolDbState` / `GetSymbolDbMatchRatio`——参数是 `image` 标量，没有跨模块
  指针可解引用，因此**不过域门、不取插件锁**，只读 `PdataMatch` 自己的快照（§7.3）。
- 本地化：`LocalizationLookup` / `LocStringBytes` / `LocCreate` / `LocDestroy` / `LocLookup` /
  `LocPushArgument` / `LocToUtf8`——走独立模块 `Localization_FinalRelease.dll` 的导出；
- `MakeHash`：**已内化**为 loader 自己的原生 CRC32（raw，无最终异或，与官方 `GameCore::Utilities::MakeHash`
  逐位一致，并有编译期自检向量）；不再解析任何 GameCore 符号，任何时刻可算；
- `GetMainLuaState`：读 exe 全局 `LuaSystem::LuaScriptSystem::ms_apSingletonInstance`（DX11 实测 RVA
  `0x2D08F88`）解引用后的 `+0x10` → **引擎主 Lua VM**（`m_pkMainLuaState`）。★ 这是**进程级** state：
  `lua_newstate()` 在 `Civ6App::GUIInit` 建一次，只在 `Civ6App::GUIShutdown` `lua_close`
  ——**换局不会失效、也不会被重写**（全 exe 仅一处写 `+0x10`）。未就绪返回 null。
  **Global 与 GameCore 两类插件都可调用，不限类别**——它是进程级 state，常驻插件持有它
  不会因换局悬垂，所以与 `EditPlayer` 那类"GameCore 短命域"入口不同类，不受地址域门限制。

  ⚠️ **别和"每局 thread state"混淆**：Civ6 确实是多 `lua_State` 引擎，但 GameCore 每局用
  `IScriptSystem1::CreateLuaThread` 建的是 `lua_newthread(main_state)` 派生的 coroutine，
  换局必被 `FreeLuaThread` 回收。本接口返回的**不是**它们；若插件持有的是某个 thread state，
  那才是会崩的场景。
  ⚠️ **仅游戏线程调用**（Lua 状态非线程安全）。注意这是**线程**约束而非类别约束：
  GameCore.dll 用 `Lua::ms_CriticalSection`、exe 侧用 `Lua::Details::LockAccess`，
  是两个不同实例，所以从非游戏线程调用会缺锁——类别门拦不住这种情况。

---

## 5. 挂钩子系统

### 5.1 站点（HookSite）与站点表

`std::map<void*, HookSite> g_hookSites`：**键 = 目标函数的绝对地址**，同一地址只挂一次 MinHook，
挂到 Loader 自己生成的 stub。一个站点同时承载三样东西：

- **插件 detour 槽**：`activeDetour` + `detourOwner`（独占）；
- **capture 槽**：`hasCapture` / `captureParamIndex` / `captureOuts`（同一地址 1 个 detour + N 个捕获订阅共存）；
- **MinHook 侧**：`stubCode` / `minhookTrampoline` / `hookInstalled`。

`nextTarget` 是 stub 的尾跳目标（有 detour 时=detour，否则=跳板）；`recordStale` 表示"上一次 teardown
没能摘掉这条 MinHook 记录"（下次同地址取站时强制重建）。

### 5.2 stub（loader 生成的中转代码）

`BuildHookHubStub`（asmjit 生成裸 x64 机器码）：

- 快路径：`mov r10, site` → `cmp [r10+hasCapture], 0` → `jne slow` → `mov rax, [r10+nextTarget]` → `jmp rax`；
- 慢路径（有 capture）：保存 rcx/rdx/r8/r9 与 xmm0-3 → `CaptureDispatch(regs, paramIndex, site)` → 恢复
  → 重新加载 site → 尾跳 `nextTarget`（栈对齐到调用约定）。

两个设计点：`nextTarget` **运行时**从站点字段读，所以跳板可以在 stub 生成之后由 `MH_CreateHook` 回填、
拔槽也不需要改写任何可执行字节；stub 一经生成**永不释放**。

**字段偏移是编译期钉死的**：stub 访问 `HookSite` 靠写进指令里的字节偏移（`hasCapture` /
`nextTarget` / `captureParamIndex` 三处 `offsetof`），而 stub 永不重建——改 `HookSite` 布局后，
同进程里可能同时存在按旧布局生成的旧 stub 与按新布局生成的新 stub。偏移错了不编译失败、
不运行时报错，只表现为 capture 静默失效或跳到垃圾地址。`HookEngine.cpp` 在
`BuildHookHubStub` 之前有四条 `static_assert` 钉住这三个偏移与 `sizeof(HookSite)`
（实测 x64 Release：`hasCapture` 0x40 / `nextTarget` 0x18 / `captureParamIndex` 0x44 /
`sizeof` 0x78），改布局会在编译期失败并提示同步 `BuildHookHubStub`。

这四条只挡**同一次构建内**的布局漂移。跨二进制的 stub 复用不由它们保证——但该前提在本项目成立：
stub 里嵌的是本进程的 `&HookSite`，而 `version.dll` 自更新会重启进程，新进程里不存在旧 stub。

**Stub 与 HookSite 节点的常驻原则（永不释放）**：
1. **立即数指针内嵌**：Stub 机器码使用立即数 `mov r10, imm64(&HookSite)` 硬编码了站点节点地址；若释放节点，执行流将直接访问悬垂指针；
2. **缺乏无锁静默判定机制**：系统无法证明“当前已无任何线程正停留在 Stub 执行流或跳板内”（缺少可靠的原子引用计数），释放内存会产生释放后使用（UAF）隐患；
3. **分配器生命周期限制**：AsmJit 采用块状内存分配模型，多组 Stub 共享底层内存页，无法进行单条 Stub 粒度的释放归还。

因此，在 GameCore 卸载清理（Teardown）时，系统仅对 `HookSite` 执行**原地状态复位**以供复用，保留底层 Stub 机器码与节点本身。


### 5.3 capture（参数捕获）

`RegisterGlobalCapture(providerAddress, paramIndex, out)`：地址域门 → 可读 + 落在可执行页的预检 →
取/建站点 → `hasCapture = true`、把 `out` 追加进 `captureOuts`（带 owner 记账）。之后每次调用目标函数，
stub 的慢路径把第 `paramIndex` 个寄存器参数写到所有 `out`。

清理只拔插槽：`CleanupAllCaptureSites()`（只清落在**当前 GameCore 映像**内的订阅，exe/常驻域保留）与
`CleanupCaptureSitesForOwner()`（按 owner 撤）。**绝不**为此物理脱钩。

### 5.4 MinHook 的真实语义与本项目约定

| API | 它到底做了什么 |
|---|---|
| `MH_CreateHook` | 分配跳板（原函数前导字节的重定位副本 + `jmp` 回原函数）、保存备份字节、建记录；**不改入口** |
| `MH_EnableHook` | 冻结线程（把 IP 落在目标入口的搬进跳板）→ 把入口前 5 字节改成 `jmp`（或 relay） |
| `MH_DisableHook` | 冻结线程（把 IP 落在跳板里的搬回目标）→ 把备份字节写回入口（幂等） |
| `MH_QueueDisableHook` + `MH_ApplyQueued` | 批量：只置排队标记，`ApplyQueued` 用**一次** `Freeze` 把整批入口一起还原 |
| `MH_RemoveHook` | 若记录 enabled 先走一遍 disable；然后 `FreeBuffer`（释放跳板）+ 删记录。**已 disabled 时完全不碰目标内存** |

约定：所有 `MH_*` 调用都在 `Runtime::MinHookMutex()` 内；hook 目标与 `Patch` 区间双向互斥（谁的
"还原原始字节"都不许踩对方）。

### 5.5 装钩（InstallHook）与共享钩

`InstallHookImpl` 的顺序（每一步都在挡一类错误）：

1. `PluginBoundary::IsReadable(target, 32)` / `IsWritable(original)`：坏地址必须在**取锁之前**拒掉，
   否则 MinHook 读目标前导字节失败会把两把锁一起泄漏；
2. 取 lifecycle 锁 → `PatchRegistry::OverlapsRegistered`（与补丁区间冲突？）→ teardown 窗口？；
3. owner 探针（`ResolvePluginOwnerForAddress(detour)`）；
4. **地址域门**（§4.1）；
5. 取 MinHook 锁 → 站点取/建（必要时 `MH_CreateHook` + `MH_EnableHook`）→ 独占性检查；
6. 写槽，顺序：先备 `*original`（=跳板）→ `activeDetour`/`detourOwner` → **最后** `nextTarget`。
   顺序理由：站点首建后 MinHook 侧已 enable，但那一刻 `nextTarget` 只是跳板（纯透传）；detour 只有靠
   "把 nextTarget 置为 detour"才被激活，所以必须先把跳板交给插件再发布。

`InstallLoaderDetourOnSite` 是 Loader 给自己的共享钩（`RegisterScriptData(/ForUI)`、PushMethods 槽）
用的同一入口：detourOwner 恒空、同一 detour 幂等、与插件 detour 双向互斥。
Loader 自己的 **exe 域**钩（`LoadDLL` / `UnloadDLL` / `LoadUI`）不经过站点表，直接 `MH_CreateHook`。

**`MH_ERROR_ALREADY_CREATED` 的归属判定**（`GetOrCreateHookSiteLocked`）：MinHook 对已建过记录的
target 返回这个状态。它有两种可能来源，处理方式相反：

- 本站节点已存在（不是本次新建）**且**当前前导字节与本站 `prologueBackup` 一致 → 是**自己**的残留记录
  （上次 teardown 的 `MH_RemoveHook` 失败），可以先 `MH_RemoveHook` 再重建；
- 其余情况（全新站点，或字节对不上）→ 只能是**别人**（插件或其它机制）的钩子。**无条件摘除会释放对方的
  trampoline**（跳板指针悬垂，且可能静默顶掉 Lua 脚本全局注册），还会把旧字节写进当前映像。
  此时拒绝对该地址建站：新建的节点 `erase` 掉，已存在的节点打 `poisoned` 永久拉黑。

### 5.6 退役、摘除与 teardown

- **拔槽**（插件卸载）：`RetireHookSiteDetoursForOwnerLocked(owner)`——只把 `activeDetour` 清空、
  `nextTarget` 回落到跳板。插件代码马上要被 `FreeLibrary`，所以必须先让 stub 不再指向它；
- **摘除**（GameCore teardown）：`RemoveHookSiteRecordLocked` 的 a→b→c：
  a) `MH_DisableHook`（**失败就整体放弃**——此时入口字节没还原，若把 nextTarget 指向 target，
  入口仍跳 stub、stub 又跳 target，会打转）；b) `nextTarget = target`（在途调用改走原函数）；
  c) `MH_RemoveHook`（释放跳板）；然后清站点记账；
- **teardown 两阶段**（§2.3 第 5、9 步）：先"批量停用"（一次 `ApplyQueued` 还原全部入口字节），
  排空在途共享 detour，再重扫站点表"摘记录 + 原地复位站点"（**不 erase 节点**：stub 的机器码里
  永久内嵌 `&HookSite`，而"没有调用者停在 stub 内"无法证明）；摘不掉的打 `recordStale`，
  下次同地址取站强制重建。

### 5.7 不变量与已知残留

| 项 | 现状 | 说明 |
|---|---|---|
| 站点 / stub 一律不释放 | **硬约束** | teardown 只摘 MinHook 记录 + 原地复位站点；节点与 stub 保留并复用（stub 内嵌 `&HookSite`，erase 会让在途线程读到已释放 map 节点） |
| stub 的 JIT 内存 | **回收不了** | asmjit 只能整体 release，且多 stub 共用块。站点复用后"每代新建 stub"的累积**已消失**（每个地址最多一块 stub）；要彻底回收需改成自建 `VirtualAlloc`/`VirtualFree`（顺带可去掉 asmjit 依赖）——**未做** |
| `recordStale` 重建 | 保留 + 已加护栏 | 重建前先比对目标当前前导字节与建记录时的副本（`HookSite::prologueBackup`）：**不一致就 poison 该站点、拒绝触碰 MinHook 记录**（fail-closed），避免把旧映像的字节写进当前映像；一致时才 `MH_DisableHook`/`MH_RemoveHook` |
| 换基址重载 | 站点复用 | teardown 原地复位站点（`hookInstalled=false`，stub 与 `prologueBackup` 保留待重建）；只有"摘不掉"的残留会留下 `recordStale`（或 poison） |

### 5.8 补丁的撤销（`PatchRegistry`）—— **Loader 不自动回滚**

`Patch` / `Unpatch` 是插件对游戏内存的**原始字节修改**。账本是**按 target 分层的 owner 栈**：
每个 target 维护一串 `Level`（按应用顺序），每层记「该层写入**之前**该区间的字节」+ owner。

**Loader 不替插件自动回滚**。理由：

- **能自动回滚的场合回滚本就多余**：GameCore 插件的补丁只允许落在当前 GameCore 映像内（§4.1），
  拆映像时随映射一起消失；
- **真正需要回滚的场合恰恰最危险**：崩溃隔离（§3.3）的语义是"模块驻留不卸、代码仍在内存里"——
  此时往**可能正被执行**的代码里写还原字节、又不做任何 quiesce（项目自己有 MinHook 的线程冻结机制，
  但这条路径没用），风险高于收益；
- **还原本身也在改页保护**，而恢复保护属性的返回值被忽略，一次失败就会把页永久留在可写状态（破坏 W^X）。

**分层语义**：

- **同 owner 重复 `Apply` 同一 target → 拒绝。** 补丁已生效，再叠一层只会让"哪层是谁的"不可追踪；
  要改字节就 `Unpatch` 再 `Patch`；
- **不同 owner 可以叠加补丁。** 每层存的是**本层写入前**的字节，
  所以后打补丁者 `Unpatch` 时还原的是**下层补丁**而非原始字节——各层各归其位；
- **`RevertOwned` 只允许还原栈顶。** 下层存档记的是"上层写入之前"的字节，越过上层写回去会静默
  覆盖上层的补丁（而那个 owner 仍以为自己在生效）。要撤下层就先撤上层；
- **区间仲裁按 target 的最大层长**（`Entry::Extent()`）。同一 target 上的叠加层区间本就重合，
  无需仲裁；仲裁只针对**不同 target**，防止两个插件往交错区间打补丁互相踩。

**与 MinHook 的双向互斥**（同一段前导字节被两套机制各存一份"原始字节"会互相覆盖）：

- 装钩前：`InstallHookImpl` 查 `PatchRegistry::OverlapsRegistered(target, kHookPrologueWindow)`；
- 打补丁前：`HookPatch` 查 `OverlapsHookPrologue(target, len)`——**只看 `hookInstalled == true`
  的站点**（未 Enable 的站点尚未改写前导字节）。因此**已被挂钩的点位不可能再打上补丁**，
  反之亦然。窗口取 `PluginBoundary::kMinHookTargetSpan`（32 字节，与可读探测同口径）。

**约定**：

- `Unpatch(target)` 保留（底层 `PatchRegistry::RevertOwned`），供插件在**自己还活着的时候**
  主动撤销。这时插件知道自己的状态，也知道自己的补丁是否还被调用；
- **Loader 不替插件自动撤销补丁**。隔离/卸载后的补丁留在游戏里，直到进程退出。

> 副作用（已知且接受）：未 `Unpatch` 的层会留到进程退出；GameCore 插件若未撤销，其落在旧映像
> 区间里的记录会跨代存活，并继续参与 `OverlapsRegistered` / `OverlapsHookPrologue` 的区间仲裁
> （见 §2.3 第 9 步）。

---

## 6. 插件回调、Lua 与 UI 数据流

### 6.1 PluginInFlight（在途登记与排空）

`PluginInFlight::Owner`：owner 的放行镜像 + 在途计数 + 每类计数；`SetAllowed` 是镜像的**唯一写者**
（只由 `SetPluginState` 调用）。守卫入口用 `Enter(owner, kind)`（先增量再检查、失败回退）与
`ReleaseCount`；卸载/隔离用 `WaitAll(owner, name)`：谓词是「本 owner 的在途计数 ≤ 本线程自己的深度」，
5 秒未满足就限次记日志但**继续等**（不放弃）。

被它守卫的入口：消息 handler、`RegisterScriptGlobals`（含 UI）、`GameEvent` 触发、`PushLuaMethods` 推送。
**不**被它守卫的：插件 detour（靠 teardown 顺序保证）、以及已经交给引擎的 Lua 函数指针。

#### 按加载代隔离（`BeginLifetime`）

`Resolve(ownerId)` 是"取/建"，同一 ownerId 永远返回**同一个** `Owner*`。对 GameCore 插件这是错的：
它们每局重载，同一个 ownerId 会跨代复用同一个对象，于是**上一代尚未退出的回调会计进新一代的计数**，
`WaitAll` 等错对象——而每局重载是必然发生的，不是边缘情形。

因此加载路径不走 `Resolve`，走 `BeginLifetime(ownerId)`：

- 每次加载**新建一个 `Owner`**，把它设为当前代，并置 `allowed = false`；
- 上一代**置 `allowed = false` 但绝不删除、也绝不重新放行**——锁外的快照（消息总线的 handler 快照、
  脚本注册表的快照）可能还握着那个指针，删了是 UAF，重新放行等于让上一代的回调又进来；
- `PluginEntry::inFlight` 存的是**本代**那个指针，`SetPluginState` / `WaitAll` 都用它，不再按
  ownerId 反查（反查会拿到当前代，从而失去代际隔离）；
- `Owner*` 本身终身稳定，`Owner` 对象不回收。旧代的计数自然归零，但没人再等它。

`SetAllowed`、`WaitAll` 的谓词、`Enter` 的加计数，三处的内存序统一为 `seq_cst`：这三者必须处在
同一个全序里，否则卸载方与回调方可能各读到旧值，形成"卸载方以为排空了、回调方以为门还开着"的窗口。

### 6.2 消息总线（`Civ6MessageBus`）

按 owner 注册 handler、`Broadcast`、`SendTo`、`UnregisterOwner`；handler 调用走
`PluginInFlight::Enter`（owner 已停用则直接跳过）；注销在锁外 `WaitAll`。
总线**没有** Loader 自己的处理器，也没有"按名字注销单个 handler"的入口：v1 的 `load-plugin`
消息入口（任何插件都能让 Loader 去 `LoadLibrary` 任意路径并调其 `OnLoad`，绕过启用集过滤）
已连同 `InitializeLoader` 一起删除，插件只能经 `LoaderCore::LoadSinglePlugin` 的扫描路径加载。

每个 `HandlerEntry` 带一个独立的 `std::atomic<bool> active`，与 owner 级的 `inFlight` 分工：

- `inFlight` 管"这个插件还允许被回调吗"（跨卸载 / 跨代）；
- `active` 只管"这一个 handler 已被替换掉吗"（同 owner 内的换实现）。

覆盖同名 handler（必须同 owner，异 owner 的同名注册直接拒绝）时**只把旧 entry 的 `active` 置 false、
不排空不等待**：覆盖发生时插件仍然活着，把 owner 级门禁关掉会连带拒绝该 owner 的其它回调。旧 entry
不删——已取出快照的并发派发还持有 `shared_ptr`，由它保活到最后一个使用者退出。代价是旧 handler
至多被"已取出快照、尚未读 active"的那一次调用多跑一遍，随后被拦下。

`UnregisterOwner` 则**会排空**：摘掉该 owner 的表项后，在总线锁外 `WaitAll`，返回时保证该 owner
不再有回调在执行。这是总线自身的对外承诺，不依赖调用方补等——调用方
（`UnloadPluginByOwnerId` / `QuarantinePluginByOwner`）在 `OnUnload` 与 `FreeLibrary` 之前也会各等一次，
但那时等的是同一个 `Owner`、计数已归零，重复等待的成本是零。

### 6.3 ScriptGlobals（+ ForUI）

`RegisterScriptGlobals(fn)`（GameCore 专属）：登记进 `g_scriptGlobals`（UI 版本进 `g_scriptGlobalsUI`）→
`EnsureScriptHooksInstalled()` 在 `GameCore::Lua::Utility::RegisterScriptData(ForUI)` 上装共享钩 →
游戏初始化脚本时，detour 依次调用每个 `fn(L)`（SEH 隔离 + `PluginInFlight` 守卫），最后调原函数（跳板）。

### 6.4 PushLuaMethods

`RegisterPushMethodsTarget(name, sigType, symbol)` + `PushLuaMethods(name, methods[], count)`
（都是 GameCore 专属）：把目标名解析成游戏符号（如 `GameCore::Lua::IUnit::PushMethods`）→ 合并/去重/
冲突预检 → 装到站点（16 个槽位，loader 自己的 detour）→ 游戏调用该目标函数时，detour 把插件的 C 闭包
按 `exposedName` 写进游戏给的那张表；每个方法推送前走 `PluginInFlight::Enter`。
**没有"延迟登记"**：GameCore 未就绪时直接失败。
**注意两个层次的处理不同**：`PushLuaMethods` 的**方法**确实要插件在新一局自己重新注册；
但 `RegisterPushMethodsTarget` 登记的**目标配置**（`g_pluginPushTargetConfigs`，按 owner 隔离）
是**跨 `ResetForReload` 存活**的，只在插件被卸载或隔离时才随 `RemovePluginOwnedRegistrations` 清除。

### 6.5 GameEvent

`RegisterGameEvent(name, pushFn)` / `TriggerGameEvent(name, payload)`（GameCore 专属）：注册只写 loader
自己的表（owner + name + pushFn）；触发走"内化"路径——取活跃 Lua state → `GameEvents[name].Call(...)`，
参数由插件的 `pushFn` **现压**（是 loader 在调它，所以能被 `PluginInFlight` 守卫）。

### 6.6 Lua 环境划分与 HavokScript

- 游戏里**不是只有一个 Lua**，但**层次要分清**（两类东西都叫 `lua_State*`，生命周期完全不同）：

  | | 是什么 | 生命周期 |
  |---|---|---|
  | **主 VM** | exe 全局 `LuaScriptSystem` 单例的 `+0x10`（`m_pkMainLuaState`），`lua_newstate()` 建 | **进程级**，`GUIInit` → `GUIShutdown` |
  | **thread / coroutine** | `IScriptSystem1::CreateLuaThread` → `lua_newthread(主VM)` 派生 | **每局**，`FreeLuaThread` 回收 |

  `CallAccumulator<float>` / `CallProcessor` / `CallTestAll` / `CallTestAny` 都是 3 指令 thunk，
  读的都是**主 VM**；GameCore 的 `ScriptSystem` 本身**不持有任何 `lua_State`**。
  `GetMainLuaState` 读的是主 VM。**UI（ForgeUI）可能有自己独立的 VM**——未查证，别假设是同一个；
- Lua VM 实现在 `HavokScript_FinalRelease.dll`（独立模块），loader 的所有 `Lua*` 原语都经它的导出。
  **GameCore.dll 不含 VM**：它从同一个 DLL 导入 49 个 lua 符号，但**没有** `lua_newstate` /
  `lua_close` / `lua_newthread`——它只能**消费** state，不能创建或销毁；
- 谁把"插件的东西"放进 Lua：只有两条——`PushLuaMethods`（loader 把插件闭包塞进游戏的方法表）、插件自己
  在 `RegisterScriptGlobals` 回调里注册的全局/闭包。`GameEvent` 的 `pushFn` 不在 Lua 表里（loader 每次现调）；
- 因此"插件地址留在 Lua 表里"这件事，在 GameCore 专属 + §2.4 的释放顺序下不成问题：插件模块被释放时，
  那些 state 已经随 GameCore 一起没了；
- **未支持**：frontend 侧的 PushMethods（`kind=3` 现在被显式拒绝）。将来要做，需要"loader 派发器"式的 adapter，
  否则插件闭包可能活过 GameCore。

#### 6.6.1 结构体参考（IDA 实证，改动本区代码前先读）

> 来源：SO（ARM64，符号全，**结构体类型最可信**）+ PC exe + GameCore.dll 三方交叉验证。
> ⚠️ **两个平台布局不同**，别互套。下面给出的都是**实测值**。

**`LuaSystem::LuaScriptSystem`**（`ms_apSingletonInstance` 指向的对象；派生类
`AppLuaScriptSystem` **不新增任何成员**）：

| 偏移 | PC (x64) | SO (ARM64) | 成员 |
|---|---|---|---|
| 0x00 | 8 | 8 | `__vftable` |
| 0x08 / 0x0C | 4 / 4 | 4 / 4 | `m_iLogLevel` / `m_uiLogTypes` |
| **0x10** | 8 | 8 | **`m_pkMainLuaState`** ← 唯一的 `lua_State` |
| 0x18 | 5×**0x10** | 5×**0x18** | 5 个 Tuner `FastDelegate`（Remove/Add/Update/Message/Close） |
| 0x68 / 0x90 | 0x90 | 0x90 | `HksStateSettings` |
| **总计** | **0xF8 (248)** | **0x120 (288)** | |

**两平台大小不同，差异全部来自 `FastDelegate`**：SO 24 字节、PC 16 字节 × 5。
（`AppLuaScriptSystem::Create` 里 `operator new(0x120)` / `aligned_malloc_wrp(248)` 可直接印证。）

**`lua_State`**（`m_apistack` 在两个平台**都是 `+0x48`** —— 这是
`HavokScript.cpp` 的 `kLuaStateTopSlotOffset` 的依据）：

| 偏移 | 成员 | 备注 |
|---|---|---|
| 0x00 | `hks::ChunkHeader` (16B) | |
| 0x10 | `m_global` (`hks::HksGlobal*`) | |
| 0x18 | `m_callStack` (`hks::CallStack`, 48B) | |
| **0x48** | **`m_apistack` (`hks::ApiStack`, 32B)** | `top` 在其 `+0x00` → `[L+0x48]` 即 API 栈顶 |
| 0x68 | `pending` | |
| 0x70 | `globals` (`HksObject`) | |
| 0xB0 / 0xB8 (SO) · 0x98 / 0xA0 (PC) | `m_next` / `m_nextStateStack` | **thread 链**——"多 lua_State"的实体 |

**`HksObject`（Lua 栈元素，16B）** —— `RawPushTValue` 的手写布局依据：

| 偏移 | 大小 | 成员 |
|---|---|---|
| 0x00 | 4 | `t`（类型标签） |
| 0x04 | 4 | 空洞 |
| 0x08 | 8 | `v`（`HksValue` 联合：指针 / double / uint64） |

`ApiStack` = `{ top, base, alloc_top, bottom }`（各 8B），`top` 在 `+0x00`。

> 改动 `HavokScript.cpp` / `PdataMatch` 的 Lua 相关偏移前，先按上表核对。换游戏版本必须重验。

---

### 6.7 UI 注入（`UiInject`）

主菜单的前端 UI 不走插件 ABI：它是 loader 自己往游戏的 ForgeUI 树里挂 context。

1. **资源**：`UiInject::ExtractResources()`（阶段 A，见 §1.4）把 RCDATA 103/104 的
   `Civ6DllLoader_FrontEndUI.{lua,xml}` 释放到 `<exe 目录>\Civ6DllLoader\`；目标文件已存在就跳过
   （用户可以在磁盘上改），写入用 `CREATE_NEW`，"已被别人放好"按良性竞态处理；
2. **钩子**：`UiInject::Install()` detour `MainMenuState::LoadUI`（exe 域独立钩，与站点表无关，
   见 §5.5）。detour 先调原函数（FrontEnd 与 InvitePopup 由游戏自己建），再 `RunInjectionSafely`；
3. **注入**（`InjectFrontEndUi`，只在游戏/UI 线程执行；重入时置 `g_refreshRequested` 留到下次
   `LoadUI`）：AOB 解出 `ForgeUI::UIManager` 全局槽 → 从 `MainMenuState + 0x230` 取 FrontEnd
   context → `AllocateControl<LuaContext>(mgr)` 造根 context → `ChangeParent` 挂到 FrontEnd 下 →
   取虚表 `+0x200` 调 `Initialize(baseName)`（虚拟槽位，不硬编码地址）加载
   `Civ6DllLoader/Civ6DllLoader_FrontEndUI`（xml 的 `Name = AdditionalFrontEndUI`）；
4. **Mod UI**：遍历启用 Mod 的 `.modinfo`，从 `<FrontEndActions><ImportFiles>` 收集
   `FrontEndUI_*.xml` 的 base name，逐个同样注入到根 context 下。文件名有路径安全校验（相对路径、
   无盘符、逐段非空/非 `.`/`..`、前缀必须是 `FrontEndUI_`、扩展名 `.xml`）；带条件的声明不加载，
   但**条件是按 XML 出现顺序记的**：`<Criteria>` 必须排在 `<File>` 之前才生效；
5. **刷新与回收**：`g_frontEndContext` 变化（换了 FrontEnd）时重建；同一个 FrontEnd 收到
   `g_refreshRequested`（上次注入失败）时先用 exe 导出的 `DestroyChild` 销毁 loader 自己的根
   context 再重建。销毁失败或子 context 注入失败时，指针登记在 `g_rootContext` / `outAllocated`
   里交给下次刷新回收，不重复销毁、也不丢引用；
6. **已知残留**：判"是不是新 FrontEnd"用的是**指针身份比较**；若游戏释放旧对象后新对象恰好落在同一
   地址（ABA），这次刷新会被判成"同一对象"而早退，Mod UI 只会在下一次 FrontEnd 地址变化时回来。
   改判据需要游戏侧的对象代次，loader 拿不到。

---

## 7. 映像解析与符号库

### 7.1 ImageAddress（映像登记）

`ImageAddress` 是"进程里哪些 PE 映像可用 + 怎么把 RVA 换成实址"的唯一入口：

- `HookImageId`：`1=ExeDx11`、`2=ExeDx12`、`3=GameCoreBase`、`4=GameCoreXP1`、`5=GameCoreXP2`
  （3/4 只是 ABI 里的取值，运行期不可达。**真正限制它们生效的是两处**：① sidecar 容器只接受 1/2/5；
  ② `InitializeGameCorePhase` 里硬编码了 `GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll")`，
  而它是全项目唯一调用 `AttachGameCore` 的地方；`ImageAddress::IdentifyGameCore` 本身即使包含
  Base/XP1 规则，运行期也不会被触发）；
- exe 在首次查询时按文件名自动识别（`CivilizationVI.exe` / `CivilizationVI_DX12.exe`）；
- GameCore 由生命周期代码显式登记：`AttachGameCore(HMODULE)` / `DetachGameCore()` / `LoadedGameCore()`；
- `Contains(image, addr)` / `GetInfo(image, out)`（id/base/sizeOfImage）/ `ResolveByRva(image, rva, span)`。

"GameCore 是短命域"是整套设计的地基：它对局开始 attach、结束（引擎 `UnloadDLL`）就 detach，
地址随时可能变；而 exe / 常驻模块的地址在进程生命周期内稳定。

### 7.2 sidecar（符号库容器）

产物：`DllLoaderRuntime/Civ6DllLoader.symdb.bin.xp`（约 3.9 MB，三模块：ExeDx11 / ExeDx12 / GameCoreXP2），
经 `Sidecar.rc` 编成 **RCDATA 102** 嵌进 runtime。加载顺序：先找同目录的旁路文件
`Civ6DllLoader.symdb.bin`（开发时热替换），再退回资源。

两层封装（细节与不变式见 `tools/symdb.py` 顶部文档）：

- **容器 `C6SD`（只有 v1 一种，没有 v2/v3/v4 分支）**：32B 头 + `ModuleDesc[]`（64B/条，含 imageId/baseSizeOfImage/baseTimeDateStamp
  与各块偏移）+ 每模块 5 个数据块（pdata / 符号表 / vtable 槽 / 名字堆 / AOB），全部 8B 对齐；
- **压缩信封 `C6XC`**：`b"C6XC" + algo(=1, LZMA1) + originalSize + .lzma 头 + 流`；裸 `C6SD` 直接透传。
  LZMA1 参数（preset 9|EXTREME、dict 16MB、lc3/lp0/pb2）由生成端固定；runtime 只把 `.lzma` 头的 5 字节
  props 原样交给 `LzmaDecode`（`dest` 即字典，字典不会越界），但**解码前先校验**：props/字典合法、
  信封 `originalSize` 与压缩流长度成合理比例、512MB 硬上限——畸形 sidecar 不会触发大分配，
  `Init` 另有 `try/catch` 兜底。

### 7.3 PdataMatch（跨版本 RVA 矫正）

游戏更新后 GameCore 的 RVA 会变，而符号库里存的是**旧 RVA**（配旧 pdata 签名）。`PdataMatch` 负责把
`old_rva` 矫正成当前映像里的 `new_rva`：

- `Init(runtimeModule)`：读 sidecar（文件 → 资源）→ 解信封 → 逐模块建上下文。整段有 `try/catch` 兜底：
  畸形 sidecar 触发的分配/解析异常只让本次加载失败，绝不逃出工作线程；
- `BuildNewTable(imageId, target)`：解析目标 PE 映像的 `.pdata`（异常目录），为每条记录计算特征签名 `(begin_rva, size, unwind_hash)`（`unwind_hash` 为 FNV-1a64 哈希），依次执行匹配判断：
  1. **快路径恒等映射**：
     - 若去 DRM 归一化后的 `SizeOfImage` 与 `TimeDateStamp` 完全一致，判定为同一构建，直接建立恒等映射；
     - 若时间戳不同，但整表所有项的 `(begin_rva, size, unwind_hash)` 逐项一致（纯二进制重编译），同样走恒等映射；
  2. **跨版本启发式匹配管线**：
     - **磁盘缓存**：尝试按 `(新表指纹, sidecar指纹)` 加载缓存文件（`LoadCache`/`SaveCache`），抽样校验通过后直接生效；
     - **锚点提取与插值**：通过窗口哈希搜寻稳定锚点，经最长递增子序列（LIS）提取单调锚点链，在锚点之间进行线性插值，并在首尾两端向外推导；
     - **序言与 AOB 校验补全**：计算新函数序言哈希，比对 `normHeadHash` 剔除失配项；随后执行头哈希局部恢复、函数体 AOB 恢复，最终合并叶子函数 AOB 与虚表槽位反推结果（并入 `leafMap`）。
  
  *关于去 DRM 视图的补充说明*：上述构建判定使用的 `SizeOfImage` 均经过 `NormalizedSizeOfImage` 归一化处理（从末节向前剥离连续的 `.bind` 段后按节对齐重算）。原版 EXE 携带 `.bind` 段，其原始 `SizeOfImage` 比去 DRM 修改版大 0x33000，但两者的代码与 `.pdata` 逐字节相同。因此，凡涉及“该映像是否为同一构建”的判定（如 `BuildNewTable`、`ExeMatchesAnchor`），两端必须统一使用归一化尺寸进行比对；而所有内存越界与缓冲区边界检查，则必须使用 PE 原始尺寸（`OptionalHeader.SizeOfImage`）。
- 缓存命中后按头/尾 + 最多 64 个等距条目做一次抽样自校验（`ValidateCachedMap`）。它只保证「结构上像
  本次匹配的产出」（索引不越界、签名/头 hash/AOB 至少一条成立），**不是对缓存可信度的保证**：缓存文件
  与 sidecar 同在游戏目录、权限相同，能改写它的人也能直接换掉 runtime；
- `CorrectRva` / `CorrectByName` / `CorrectVTableByName` 只查表；构建期（vtable 反推）与运行期查询共用
  同一份 `CorrectRvaInTables` 口径（二分 + 封顶 64 条回扫；只有 `size` 不变时才允许函数内偏移；
  gap / 回扫耗尽退回 `leafMap`）；
- 返回 0 / nullptr = 矫正失败（调用方按各自失败路径处理）；
- **状态查询**（`GetMatchState` / `GetMatchRatio`，`HookAPI::GetSymbolDbState` /
  `GetSymbolDbMatchRatio` 的后端）：把上面的判据结果暴露给插件，让它能在依赖硬编码旧 RVA
  之前先判断矫正是否可用。`GetMatchState` 区分五态——`NoContext`（sidecar 无该映像模块）/
  `NotBuilt`（有模块但未建表）/ `BuildFailed`（建表失败，本次会话不可矫正）/ `Identical`
  （同一构建，RVA 恒等）/ `CrossVersion`（跨版本对齐成功）。`buildAttempted` 与 `tableReady`
  两个标志一起把"还没轮到"和"试过但失败"分开——单看 `tableReady=false` 无法区分这两者。
  `GetMatchRatio` 仅对 `CrossVersion` 返回真实匹配率（`map` 中非 `kUnmatched` 的比例），
  `Identical` 返回 1.0，其余返回 0.0。两者都是纯读快照，只作诊断/降级依据——**单点能否解析
  始终以 `CorrectRva` / `CorrectByName` 的返回值为准**。

### 7.4 取址入口与回退顺序

- **插件可见**（`HookAPI`，全部要过 `image` 域门）：`ResolveByRva` / `ResolveByRvaEx`（指定段）/
  `ResolveByName` / `ResolveByPattern`（AOB 文本，带 `index` 取段内升序第 N 个命中）/ `ResolveByVTable`；
- **符号库状态查询**（不过域门、不取插件锁）：`GetSymbolDbState(image)` /
  `GetSymbolDbMatchRatio(image)`——参数是 `image` 标量，没有跨模块指针，因此只需读
  `PdataMatch` 自己的快照；
- **Loader 内部**（不经过插件 ABI，也不拿插件锁）：`LoaderCore::ResolveExeTarget(HookInfoExe)` 与
  `ResolveDataByAobCore(image, aob, index)`；
- **exe 域双版本**：`HookInfoExe` = 每个变体（DX11/DX12）各一组「RVA + 唯一 AOB」，运行时按当前 exe
  选一组：先 RVA（经 pdata 矫正），AOB 作为兜底/校验。例：`kExeLoadDLL` / `kExeUnloadDLL` /
  `kExeGetRuleSet`（带 `index` 解决同码兄弟函数）；
- **数据槽**：同样是"逐段指令 + `disp32` 通配"的 AOB，解出 RIP 相对的全局地址（`UIManager`、
  `ms_apSingletonInstance`、`ms_pkCurrentGame` 等，见 `UiInject.cpp` 的 `kAob_UIManager`）。
  AOB 的生成/核对由 `tools/symdb.py aob` 负责。

### 7.5 外部模块

- `Localization_FinalRelease.dll`：按**导出名**解析 `Lookup` / `PushArgument` / `String` 析构 / `toUTF8` 等；
  缺任何一个只降级对应包装（返回空串/nullptr），不影响其它功能；
- `HavokScript_FinalRelease.dll`：解析约 40 个 `hksi_lua*` / `hks*` 导出，作为绝大多数 `Lua*` 原语的实现；
  **在阶段 A 解析一次**（该模块是 exe 静态导入、常驻，导入地址恒定，没有"需要重新解析"的理由）；
  缺导入 → Lua API 逐个入口降级为安全默认值 + 限次日志，**不影响插件加载**。唯一的例外是 `LuaPushBoolean`：该 DLL 不导出任何 `pushboolean`，
  实现是硬编码 `lua_State + 0x48` 的原始栈写入（`RawPushTValue`），换游戏版本必须重验该偏移。

### 7.6 工具链：`tools/symdb.py`（唯一入口）

符号库产线收在一个带子命令的入口里：

| 子命令 | 作用 |
|---|---|
| `json-exe` | 从 IDA 导出（`.funcs.txt` + `.rdata .asm`）+ 去 DRM 的 exe → exe 版 symdb JSON |
| `module` | JSON + 对应 PE → 单模块 `C6SD` 容器（依赖 `aob_helper.exe` / `normhash_helper.exe`） |
| `pack` | 多个单模块容器 → `Civ6DllLoader.symdb.pack.bin`（`--module` 可多次，`--list` 只查） |
| `compress` | `pack.bin` → `C6XC` + LZMA1 信封 `.xp`（带 SHA256 roundtrip 校验） |
| `validate` | 按运行时同款解析独立校验 `.bin` / `.xp` |
| `aob` | 从容器里的 mask 指纹生成/核对 loader 的 AOB 常量（`--emit-cpp` 直接出可粘贴的常量块） |
| `all` | 一条命令跑完产线：`module` ×3 → `pack` → `compress` → 部署到 `DllLoaderRuntime/` → `validate` → 清理中间产物 |

`rva_to_symbol`（RVA → 符号）覆盖 **gamecore / dx11 / dx12 三个映像**：每个映像的符号表各压成一份
zlib 数据，由 Rust 侧 `include_bytes!` 在**编译期嵌入** exe —— 交付物仍是单个文件，查询时只解压选中的
那一份。
重建：`python tools/gen_rva_map.py` 然后 `tools/rva_to_symbol/build.bat`（一键，含编译与安装）。

**可复现边界**（工具文档里的定论）：`JSON → .bin → pack.bin → .xp → 部署/validate` 保证**逐字节复现**；
`IDA → JSON` **不保证**（JSON 是某一份 IDB 的快照，函数集合取决于 IDA 的分析状态；名字全部来自 IDB）。

---

## 8. 工程、构建与部署

### 8.1 两个工程（`DllLoader.sln`）

| 工程 | 产物 `TargetName` | 职责 |
|---|---|---|
| `DllLoader/DllLoader.vcxproj` | `GameCore_XP2_Shell_FinalRelease`（薄壳） | 首次使用该类 Mod 时的 Loader 安装器（扫描 Mod + 版本选举 + 补装 `version.dll` + 提示重启）；零 hook、不启动 runtime、不做运行时自更新 |
| `DllLoaderRuntime/DllLoaderRuntime.vcxproj` | `Civ6DllLoader.runtime`（Loader 本体） | 一切 hook / sidecar / HookAPI / 插件生命周期 |

两个工程都是 x64、C++20（`/std:c++20`）、`/utf-8`。关键预处理宏：

- `DllLoaderRuntime`：`ASMJIT_STATIC`（静态链接 asmjit）+ **`CIV6_HOOKAPI_BUILD_IMPL`**（声明"我是 loader 侧"，
  这样 `common/HookAPI.h` 的类别门禁不会 `#error`、也不会把成员名重命名）；
- 两者都有 `_CRT_SECURE_NO_WARNINGS` / `_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS`；
- 两个工程的 Release 都用静态 CRT（`MultiThreaded` = /MT），Debug 用 `MultiThreadedDebugDLL`（/MDd）。
  因此 HookAPI 只允许传 POD/指针：**不能跨模块传 `std::` 容器或"谁分配谁释放"以外的堆内存**
  （`LocCreate`/LocDestroy 这类成对接口就是按这条约束设计的）；
- Debug 配置下会有既存的 `LNK4075` / `LNK4098` 警告，属正常。

### 8.2 third_party 与链接依赖

| 组件 | 用途 | 实际编入的文件 |
|---|---|---|
| `third_party/asmjit_src`（+ `asmjit_build` / `asmjit_build_dbg`） | 生成站点 stub（唯一用途；**未**用在别处） | 以 include 路径引用；链接预编译的 `libAsmJit.x64.lib` / `libAsmJit.x64.debug.lib` |
| `third_party/hde` | MinHook 的长度反汇编器 | `hde64.c`（`NormHash.cpp` 也直接用它） |
| `third_party/lzma`（LzmaDec） | 解 sidecar 的 `C6XC` LZMA1 流 | `LzmaDec.c` + `LzmaDec.h` |
| `third_party/sqlite` | runtime 侧读 `Mods.sqlite`（启用 Mod 过滤） | `sqlite3.c` + `sqlite3.h` |
| 预编译 MinHook | 站点与 exe 域钩子的实际挂钩实现 | `DllLoader/resources/libMinHook.x64.lib`（**仓库里只有头文件 + lib，没有 `hook.c`**） |

> 注：MinHook 的行为（`MH_EnableHook` 的线程冻结语义、跳板构造、"已 disabled 时不碰目标内存"）
> 在本仓库内**无法验证** —— 只有预编译库和头文件。§5.4 那张表是对该库行为的描述，
> 不是从本仓库源码得出的结论。

### 8.3 构建

```bat
call "E:\VisualStudio\Products\VC\Auxiliary\Build\vcvarsall.bat" x64
"E:\VisualStudio\Products\MSBuild\Current\Bin\amd64\MSBuild.exe" DllLoaderRuntime\DllLoaderRuntime.vcxproj /nologo /m /v:m /p:Configuration=Release /p:Platform=x64
```

`Configuration` 取 `Debug` / `Release`；薄壳工程同理。改 `common/HookAPI.h` 后**必须两个配置都重编**
（它是插件 ABI，载荷在 runtime 里）。

### 8.4 产物与部署位置

| 产物 | 目标位置 |
|---|---|
| `x64\<cfg>\Civ6DllLoader.runtime.dll`（改名 `version.dll`） | 游戏 exe 目录（`Base\Binaries\Win64Steam\` 或 `Win64\`） |
| `x64\<cfg>\GameCore_XP2_Shell_FinalRelease.dll` + `Civ6DllLoader.runtime.dll` | 启用 Mod 的 `Binaries\Win64\` |
| `DllLoaderRuntime\Civ6DllLoader.symdb.bin.xp` | 由 `symdb.py all` 直接部署（编进 runtime 的 RCDATA 102） |
| `DllLoaderRuntime\Resources\Civ6DllLoader_FrontEndUI.{lua,xml}` | RCDATA 103/104，由 `UiInject::ExtractResources` 释放到 `<exe 目录>\Civ6DllLoader\` |
| `x64\<cfg>\Civ6DllLoader.runtime.dll` 的版本资源 | RCDATA **105**（`CIV6_DLL_LOADER_VERSION_RESOURCE_ID`）：安装/自更新只读它，不执行候选 DLL 的 `DllMain`/TLS/导出 |

---

## 9. 已知取舍与残留风险

以下为系统架构在权衡后明确接受的设计约束与已知折衷（非未捕获缺陷）：

| # | 现象 | 原因 / 机制 | 影响 | 状态 |
|---|---|---|---|---|
| 1 | 站点 stub 的 JIT 内存永不回收 | **根本原因**：stub 机器码里 `imm64` 永久内嵌 `&HookSite`，而"没有调用者停在 stub 内"无法证明（无可靠计数），释放即 UAF。asmjit 只能整块 release、多 stub 共用一块是叠加的第二原因 | 进程生命周期内每新增一个**不同目标地址**才多一块 stub；同地址复用同一块，不随 reinstall 累积 | 接受（硬约束）。若将来站点数量爆炸，可把 stub 改成"每站点 `VirtualAlloc`/`VirtualFree`"配合调用者计数，顺带去 asmjit 依赖 |
| 2 | `recordStale` 重建时的**旧映像字节写回**风险 | 旧 MinHook 记录里只有建记录时的前导字节副本，不含版本信息 | 重建前先比对当前前导字节与副本（`HookSite::prologueBackup`）：不一致就 poison 该站点、拒绝触碰记录（fail-closed） | 已加护栏（§5.7） |
| 3 | Global 插件永不卸载 | 域模型：Global 钩的是常驻 exe | 插件静态状态跨对局、跨读档存活 | 约定：Global 插件的 `OnLoad` 必须幂等，不得假设"只执行一次" |
| 4 | 插件自建线程 / 前端 Lua 闭包不受 loader 保护 | 这些不在 HookAPI 覆盖范围内 | 卸载瞬间的并发调用可能引发悬垂访问或崩溃 | 文档告知；不做"线程登记"就无法根治 |
| 5 | 域门只装在"换地址 / 给地址"这类入口 | 设计原则是**按目标地址授权**，不是限制插件行为 | 注册、回调类入口不设门 | 有意：边界靠"GameCore 专属入口 + 域规则"共同成立 |
| 6 | teardown 依赖"有在途 GameCore 调用即视为不可恢复"的设计假设 | 引擎自己 `UnloadDLL` 同样会 unmap 那块内存 | 做不到绝对安全 | 接受：与引擎原生行为等价 |
| 7 | exe 域的站点永不摘钩 | exe 常驻，摘了反而引入额外状态 | 钩子活到进程退出 | 有意 |
| 8 | 开关 Mod 不生效，必须重启 | 没有 reconcile 通路 | 操作体验 | 有意：状态一致性优先于便利 |
| 9 | UI 注入依赖特征码，匹配失败静默降级 | 游戏更新改了目标代码 | 面板不出现（日志有记录），其余功能正常 | 接受 |
| 10 | 数据槽定位依赖 AOB 兜底指令序列 | 编译器 / 游戏更新 | 定位失败返回 0，对应功能降级 | 接受（有日志） |
| 11 | 休眠检测要求宿主 exe 名形如 `CivilizationVI*.exe` | 防止"别的进程从 exe 目录加载这份 version.dll"时把 Loader + Global 插件拉进去 | 用改名 exe / 第三方启动器的会话里 Loader 静默休眠（不装钩）；`OutputDebugString` 有留痕 | 有意（严格优先） |
| 12 | 插件打的补丁**不由 Loader 自动回滚** | 自动回滚要在"插件已崩"的时刻往可能正执行的代码里写还原字节，且无 quiesce；存档还可能是别人的跳板字节 | 隔离/卸载后补丁留在游戏里直到进程退出；插件需自己管 `Unpatch` 时机 | 有意（§5.8） |

### 9.1 已知未处理的问题（实现缺陷，待修复）

上面那张表是"已接受的取舍"。下面这些**不是设计结果，而是当前实现的缺陷**，改动时不要误以为是有意的：

| # | 问题 | 位置 | 说明 |
|---|---|---|---|
| 1 | teardown 窗口在取不到映像信息时被清成空 | `ResetForReload`（`LoaderCore::Teardown::SetWindow(0, 0)` 分支） | 当 `base == 0` 时保护判定直接返回 false，等于在最不确定时关掉了保护门；而 `HookEngine.cpp` 的 `RemoveGameCoreDomainSiteRecords` 在同样情形下**刻意不清**（只在 `GetInfo` 成功时才 `SetWindow`），两者矛盾 |
| 2 | 状态码 `3`（预留 Frontend）与若干空槽 | `common/HookAPI.h` | 属于未实现功能，不应长期保留在核心 ABI 枚举定义中 |
| 3 | `ShouldSkipPluginFile` 用文件名黑名单而非白名单 | `common/ModScan.cpp` | 存在隐患：若官方将来在目录下新增 DLL，可能会被误当成第三方插件加载 |

---

## 10. 附录

### 10.1 术语表

| 术语 | 含义 |
|---|---|
| 薄壳（shell） | `GameCore_XP2_Shell_FinalRelease.dll`：首次使用该类 Mod 时的 Loader 安装器；零 hook，只有 Loader 缺席时才会被引擎加载 |
| Loader / runtime | `Civ6DllLoader.runtime.dll`：真正干活的模块，`version.dll` 是它的副本 |
| 站点（site） | 以**目标绝对地址**为键的一条记录，是钩子/捕获/记录三件事的共用载体 |
| 插件插槽（detour slot） | 站点里"至多一个插件 detour"的位置，独占，后来者接管 |
| 捕获（capture） | 站点里"读取某参数 / 写出参数"的插槽，可多个共享 |
| 共享钩 | 多个插件（或多个内部需求）落到同一地址时，只装一个 `MH_CreateHook`，由站点统一派发 |
| stub | asmjit 生成的机器码：从 MinHook 跳板进来后查站点、走派发逻辑，再转发到原函数 |
| 跳板（trampoline） | MinHook 为"调用原函数"准备的复制指令块 |
| 记录（record） | 站点在安装前备份的目标字节，卸载时用于还原 |
| 域门（domain gate） | 对"换地址 / 给地址"入口做调用者域与目标地址的双重检查 |
| kind | 插件类别（Global / GameCore），决定它能钩哪块内存 |
| sidecar | 符号库容器（`C6SD` v1，可套 `C6XC` + LZMA1 信封） |
| pdata 矫正 | 用 `.pdata` 异常表签名把旧 RVA 映射到当前映像的 RVA |
| 指纹 | 一个映像的 pdata 集合哈希，用来判断"版本是否相同"和做缓存键 |

### 10.2 如何扩展

#### 加一个 HookAPI 入口

1. 在 `common/HookAPI.h` 的 `HookAPI` 结构**尾部**追加函数指针；
2. 若它只对 GameCore 有意义：加进文件底部"类别门禁"块的对象式重命名列表（7 个之一的位置），
   并在实现里调用 `RequireGameCoreOwner`；
3. 若它是"换地址 / 给地址"类：实现必须过 `IsTargetOpenToCaller` / `IsRangeOpenToCaller`；
4. 在**归属模块**里实现对应的 `*Impl`（取址类 → `AddressResolve.cpp`；脚本/Lua/GameEvent/PushMethods 类 →
   `ScriptBridge.cpp`；插件生命周期类 → `PluginRegistry.cpp`；装钩/捕获 → `HookEngine.cpp`），
   然后在 `HookLoaderApi.cpp` 的 `g_hookApi` 位置初始化表里**按顺序**填上它的地址。
   追加入口还必须同步 `common/HookAPI.h` 的 `CIV6_HOOK_API_ENTRY_COUNT`：`g_hookApi` 上方的两条
   `static_assert`（`sizeof` + 末尾字段偏移）挡住「加了字段却没改计数/没补初始化」，
   `VerifyHookApiTableProtection` 启动时还会扫描空项；
   > 表是 `const` 的且 `*Impl` 不能是 `static`（`g_hookApi` 取的是它们的地址）；
   > 反过来 `HookLoaderApi.cpp` include 全部子系统头文件，且没有任何下层模块反向 include 它——
   > 它是组装根，不参与实现。
5. 编译 loader 侧需要 `CIV6_HOOKAPI_BUILD_IMPL`（工程里已定义）；
6. **不要**动已有字段的顺序，也不要改 `apiVersion`（见 10.3）。

#### 加一个内部钩（loader 自己用）

- exe / 常驻模块：直接 `MH_CreateHook` + `MH_EnableHook`（域稳定，无需站点模型）；
- GameCore：走站点模型（`InstallLoaderDetourOnSite` 之类），这样 teardown 能统一摘掉；
- 需要读参数 / 写返回值：用捕获插槽，不要自己写第二套。

#### 加一个插件类别

1. `common/HookAPI.h` 的 `CIV6_PLUGIN_KIND_VALUE` 加值（3 起是保留位）+ 头文件里的
   `CIV6_PLUGIN_KIND_VALUE` 取值分支（新宏 → 新 kind）；
2. 加载期映射：`KindToCategory` + `CategoryForPath` 的目录名判断（都在 `PluginRegistry.cpp`）；
3. 域规则：`IsTargetOpenToCaller` 里加一条"该类别能碰哪块内存"的**正向**规则；
4. teardown 策略：想清楚它的模块什么时候能 `FreeLibrary`（现在只有 GameCore 类别会排队释放）。

### 10.3 改 ABI 的规则

- **预发布阶段（当前）不升版本号**：从未对外发布过插件，删字段 / 改顺序 / 改语义直接做，
  `CIV6_HOOK_API_VERSION` 停在 `1`（唯一出现过的值）；插件必须用当前头文件重新编译；
- **对外发布之后**：只追加（新增函数追加到尾部，`apiVersion` 不动）；破坏前缀才提升版本号，
  旧插件会被拒而不是崩；
- **类别门在表外**：`Civ6PluginKind` 导出负责"OnLoad 之前"按类别快速拒绝（旧头文件编出来的插件没有这个
  导出 → 在 OnLoad 之前就被拒）；ABI 版本兼容仍由表内的 `apiVersion` + `structSize`（插件侧
  `HookAPI_IsCompatible`）判；
- **删除枚举值不算前缀破坏**：不需要再升版本；
- 改完必须：两个配置都重编 + 跑一遍真机测试验证。

### 10.4 文档维护约定

- 本文件是**唯一的总架构文档**，"为什么这样设计"写在这里；
- 代码里的"为什么不这样写"注释应指向本文件对应小节，而不是复述一遍。



