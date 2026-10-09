# Civ6DllLoader 架构总览

- 状态：**当前有效**（对齐 HEAD 的历次重构之后：kind 门禁、域门正面规则、teardown 物理摘挂钩记录、
  站点原地复位、插件释放延后、tools 单入口化）。最后校订：2026-10-02
  （本轮为一次全面代码复审后的修订：修正若干与代码不符的表述，并新增 §9.1「已知未处理的问题」）。
- 适用版本：预发布 `1.0.0`（`common/LoaderVersion.h`），插件 ABI `CIV6_HOOK_API_VERSION = 1`。
- 这份文档是**唯一权威的架构说明**；逆向取证类材料（原始反汇编/字节/映射表）在 `docs/analysis/`，
  本文在需要处引用它们。历史设计文档已删除。
- 约定：本文用 `file` / `file:函数名` 定位，尽量不写死行号（行号会随改动漂移）。
- **⚠️ 标记 = 该处"文档所述的目标状态"与"当前代码"不一致**：可能是已知缺陷（另见 §9.1），
  也可能是已决定但尚未实施的改动。改代码前以代码为准。

---

## 0. 一分钟速览

一句话：**在游戏进程里用 `version.dll` 代理（`Civ6DllLoader.runtime.dll` 的副本）把 Loader 塞进
进程；薄壳只在"Loader 还没装"时出场一次（安装器）；runtime 挂少数几个钩（LoadDLL / UnloadDLL / LoadUI），
维护一个按地址索引的"挂钩站点表"，并通过一张只读函数指针表（HookAPI）把"取址 / 装钩 / 打补丁 /
注册回调"的能力交给插件。**

三个必须记住的不变量（后面各节都会回到它们）：

1. **类别 × 域**：插件分 `Global`（只启动时加载、永不卸载、只许动**已加载的非 GameCore 模块**）
   与 `GameCore`（随对局加载/卸载、只许动**当前 GameCore 映像**）。这条同时由编译期、加载期、
   运行期三层保证（§3.5、§4）。
2. **站点表是唯一的挂钩账本**：同一个目标地址只挂一次 MinHook，挂到 Loader 自己生成的 stub；
   站点、stub、capture 订阅都记账在 `g_hookSites` 里。日常退役只"拔插槽"，**只有 GameCore teardown
   才会物理摘除 MinHook 记录/跳板**（§5）；**站点节点与 stub 一律不释放**（stub 的机器码里内嵌了
   `&HookSite`，teardown 只把节点原地复位以便下次复用）。
3. **释放顺序**：摘钩（还原入口字节）→ 卸载插件（OnUnload / 注销回调）→ 交给引擎
   `UnloadDLL` 卸掉 GameCore（连同它的 Lua 环境）→ **之后**才 `FreeLibrary` 插件模块（§2.4）。
   ⚠️ 补丁**不由 Loader 自动回滚**：语义是"补丁进程内不可撤销，由插件自己在 `OnUnload` 里
   `Unpatch`"，见 §5.8。

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
| `DllLoaderRuntime/Civ6DLLHookLoaderAPI.cpp` | 一切的核心：站点表、capture、插件生命周期、
|  |  HookAPI 实现、域门、teardown |
| `DllLoaderRuntime/LoaderHooks.cpp` | exe 域钩子（LoadDLL / UnloadDLL）的安装与 detour 编排 |
| `DllLoaderRuntime/RuntimeEntry.cpp` | DllMain、休眠检测、一次性启动线程 |
| `DllLoaderRuntime/UiInject.cpp` | 主菜单 UI 注入（LoadUI detour + LuaContext） |
| `DllLoaderRuntime/ImageAddress.cpp` | PE 映像注册与 RVA 换算 |
| `DllLoaderRuntime/PdataMatch.cpp` | sidecar 解析 + pdata 匹配 + RVA 矫正 |
| `DllLoaderRuntime/PatchRegistry.cpp` | 补丁账本（按地址存原始字节）；**Loader 不自动回滚**，见 §5.8 |
| `DllLoaderRuntime/PluginInFlight.*` | 插件回调的在途登记与排空 |
| `DllLoaderRuntime/Civ6MessageBus.*` | 插件间消息 |
| `common/ModScan.cpp` / `common/EnabledMods.*` | 插件扫描与"启用 Mod"过滤（**只作用于插件**；安装/自更新 loader 的候选不看启用集） |
| `DllLoader/ShellBootstrap.cpp` | 薄壳侧的补装（首次安装；运行时自更新在 `LoaderUpdate.cpp`） |
| `tools/symdb.py` | 符号库流水线（唯一入口，含 AOB 生成/核对） |

---

## 1. 部署形态与启动链

### 1.1 进程里的模块与角色

进程里有**两条独立的进入路径**，别把它们混起来：

1. **Loader 靠静态导入进进程**：exe 的导入表里有 `version.dll`，Windows 会从 exe 目录解析它——
   我们把 `Civ6DllLoader.runtime.dll` 复制成 exe 目录的 `version.dll`，于是 Loader 在进程启动**最早**
   阶段就进来了（`DllLoaderRuntime/ProxyExports.cpp`）。这份 `version.dll` 的导出表逐条转给系统真正的
   `version.dll`，所以"查文件版本"这类系统行为不受影响。
2. **薄壳靠游戏自己的加载器进进程**：官方在 `DLC/Expansion2/Config/Expansion2_Config.xml` 里登记
   `GameCores(GameCore='Expansion2', PackageId=<Expansion2 的 GUID>, DllPrefix='GameCore_XP2')`，
   引擎据此加载 `Binaries/Win64/GameCore_XP2_FinalRelease.dll`（`DllPrefix` + 引擎自己拼的
   `_FinalRelease.dll`）。Mod 用 `FrontEndActions/UpdateDatabase` 顶掉这一行
   （`Data/Config.sql`：`UPDATE GameCores SET PackageId=<该 Mod 的 GUID>, DllPrefix='GameCore_XP2_Shell'
   WHERE GameCore='Expansion2'`），于是引擎用 `GameCore::LoadDLL(wchar_t const*)` 请求的就变成
   **`<该 Mod>\Binaries\Win64\GameCore_XP2_Shell_FinalRelease.dll`**。**Loader 在位时**，
   `LoadDLL` detour 把入参改写成**官方 DLL 的绝对路径**
   （`LoaderHooks.cpp` 的 `OfficialGameCoreRelPath` + `BuildOfficialPath`；官方文件不存在才透传原路径）
   → 引擎槽位=官方，**薄壳根本不进进程**。
   **只有 Loader 缺席时**（没有 detour）引擎才会真的加载薄壳：它自己实现 `DllCreateGameContext` /
   `DllDestroyGameContext`、懒加载真正的官方 GameCore（`ShellBootstrap::LoadRealGameCore`）让规则集照常
   运行，并执行下面那条"补装"。

薄壳**不会**去启动 runtime——runtime 早就以 `version.dll` 的身份在进程里了。它唯一和 Loader 相关的
职责是：发现 exe 目录没有 `version.dll` 时，收集 `Civ6DllLoader.runtime.dll` 候选、选版本最高的一份
装上去，并提示"请重启游戏生效"（安装器细节见 §1.3）。**只要 exe 目录已有 `version.dll`，薄壳这一会话
不做任何事。**

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

两条**互相独立**的通路，别当成一件事：

**① 薄壳侧的"补装"（`DllLoader/ShellBootstrap.cpp`）**——只在 Loader 完全没装时用，进程内只跑一次：

1. 算 exe 目录，看 `exe\version.dll` 在不在：**在 → 零动作**（不复制、不弹窗，正常路径就走这里）；
2. 不在 → 收集 `Civ6DllLoader.runtime.dll` 候选（`ModScan::FindRuntimeCandidates()`，无参数）→
   逐个探测版本（读 RC 资源 105）→ 选版本最高的一份（同版本比路径字典序）。
   候选**不按 Mod 启用集过滤**（见下面的说明）；
3. 复制到 `version.tmp` 再原子改名成 `version.dll`（顺带尽力清理 `version_Old.dll`）；
4. 弹一次双语提示"已安装，点击确定立即重启游戏"并尝试重启；
5. 任何一步失败都**只记日志、不弹窗、不阻塞**——本次会话就以官方 GameCore 透传跑完（Loader 缺席，
   也就不会有任何插件被加载）。

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

候选**不按 Mod 启用集过滤**（`ModScan::FindRuntimeCandidates` 故意不调 `FilterByEnabledMods`）：
安装/自更新 loader 只看版本（RC 资源 105），与"插件只从启用的 Mod 加载"是两条独立通路。
代价与前提：候选来自两个内容根（`Documents\...\Mods` / Steam Workshop）下的
`<mod>\Binaries\Win64\Civ6DllLoader.runtime.dll`。**游戏安装根不是内容根**（它不是模组容器，
其直接子目录 `Base`/`CTP`/`DLC`/`Debug`/`LaunchPad` 都不含 `Binaries\Win64`；官方 DLC 的模组根是
`<gameRoot>\DLC\<名>`，不是 loader 的分发位置），所以不扫它。Workshop 根有两条发现方式：从 exe 目录
上溯（exe 在游戏安装树里时直接命中），以及"问 Steam 自己"（注册表
`HKCU\Software\Valve\Steam\SteamPath`，退回 `HKLM\...\Valve\Steam\InstallPath`；
再扫 `<steam>\steamapps\libraryfolders.vdf` 里的每个库根）。而 `RuntimePackage::ProbeVersion` 只验 PE + RC 105、
**没有发行者签名**——能装成 `version.dll` 的候选就是这些目录里任意名字对得上的 runtime DLL。
插件侧的启用集过滤（`FilterByEnabledMods` + `EnabledMods::AllowsPath`）见 §3.1。

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
4. `LoaderHooks::InstallAll()`：exe 域钩子。**`LoadDLL` 是必需项**（它失败会把本次已建的钩子全部回滚），
   `UnloadDLL` 是**可选项**（失败只放弃它一个，`LoadDLL` 照常留着——丢一个可选功能不等于丢全部）；
5. `UiInject::Install()`：主菜单 UI 注入钩，失败静默降级；
6. `LoaderUpdate::CheckAndApplyUpdate()`：runtime 级自更新检查（薄壳之外的第二道）；
7. `LoaderCore::LoadPluginsOf(PluginCategory::Global)`：扫描并加载 **Global 插件**。

这条线程**不常驻**：没有事件循环、没有 reconcile（见 §3.3）。此后一切都在游戏线程上由 detour 驱动。

> **关于"在 `DllMain` 里 `CreateThread`"**：这是有意为之，不是遗漏。
> 新线程做的第一件事（`Logger::Init`、`MH_Initialize`、`PdataMatch::Init`、`LoadLibraryExW`）
> 都属于"不该在加载器锁下做"的事，所以必须挪出 `DllMain` 的调用栈。
> `DllMain` 本身只做三件轻活（`DisableThreadLibraryCalls`、两次字符串比较、一次赋值），
> 且**不等待**新线程（用 `CloseHandle` 而非 `WaitForSingleObject`），因此不会与加载器锁成环。
>
> **改动时必须保留"不等待"这一条。** `DllLoader/dllmain.cpp` 那句注释
> （*"Load real GameCore here (not in DllMain/CreateThread) so unload/reload cannot deadlock
> on the loader lock waiting for a worker thread"*）针对的正是这个反例：
> 若把加载放进工作线程、又由持有加载器锁的一方去等它，就会循环等待。
> 薄壳的规避方式是**不在 `DllMain` 做事**（全部推迟到 `DllCreateGameContext` 这个引擎回调里）；
> runtime 的规避方式是**在 `DllMain` 只起线程、绝不等待**。
> 两条路径不同，但各自都避开了同一个坑。

### 1.5 阶段 A / 阶段 B

- **阶段 A（进主菜单前）**：上面那条线程。此阶段 GameCore 还没加载，Global 插件的 `OnLoad` 在这里跑；
  它们能做的取址/挂钩只涉及 exe 与常驻模块。
  该阶段还解析两个**进程级静态导入**：`hks::InitHavokScript()`（Lua VM）与 `Localization::InitScript()`。
  两者随 exe 装载、与对局周期无关，故放这里而不是阶段 B（放阶段 B 会把"进程级依赖"误表达成
  "每局重建的能力"）。导入缺失只**降级**各自的 API（逐入口返回安全默认值 + 限次日志），
  **不影响插件加载**——插件可能压根不用 Lua 或本地化。
- **阶段 B（进对局时）**：引擎调用 `LoadDLL` → 我们的 detour（`LoaderHooks.cpp`）改写路径并调原函数，
  成功后 `LoaderCore::InitializeGameCorePhase()`：`AttachGameCore` →
  `EnsureScriptHooksInstalled` → 加载 **GameCore 插件**。
  （`hks::InitHavokScript` / `Localization::InitScript` **不在**这里——见阶段 A 的说明。）
- **退对局**：引擎调用 `UnloadDLL` → 我们的 detour 先 `ResetForReload()`（见 §2.3）再调原函数。

`LoaderHooks::InstallAll()` 与 `UiInject::Install()` 都在阶段 A（那条一次性线程里）装钩子；两者失败都只
记日志。`LoadUI` 的钩子归 `UiInject::Install()` 管，和 `LoadDLL`/`UnloadDLL` 是两套独立的事务。

> 顺序上的一个细节：`InstallAll()` 排在自更新检查**之前**，所以日志里会先看到 "LoadDLL hook installed"，
> 再看到 "LoaderUpdate: ..."。**不要**按这个顺序推断成"自更新只在下一次启动才装钩子"。

---

## 2. 生命周期与 teardown

### 2.1 阶段状态

- `g_gameCorePhaseReady`：阶段 B 是否就绪。`InitializeGameCorePhase()` 成功置 `true`，`ResetForReload()` 置 `false`；
  `LoaderCore::IsInitialized()` 只回答这一件事。
- `g_gameCoreTransitionMutex`（递归）：把"阶段切换"与"插件加载/卸载"串起来，保证
  「attach → 装钩 → 加载 GameCore 插件」与「teardown → 卸载」不交错。三个入口都先拿它：
  `LoadPluginDllInternal` / `InitializeGameCorePhase` / `ResetForReload`。
- `g_gameCoreTeardownAddress` / `g_gameCoreTeardownSizeOfImage`：**teardown 窗口**。窗口内
  `TargetInTearingDownGameCore(target)` 为真，`InstallHook` 直接拒绝；窗口也是 teardown 后半段
  "哪些站点属于本次要拆的映像"的唯一判据（因为那时 `ImageAddress` 已经 detach）。
  两个字段是 `std::atomic`，成对生效有固定次序：写侧先 size 再 address(release)，清零点先
  address(release) 再 size；读侧先 address(acquire)，非 0 才读 size。写侧是游戏线程，读侧还有
  插件线程（`TargetInTearingDownGameCore`）。

### 2.2 LoadDLL / UnloadDLL 的编排（`LoaderHooks.cpp`）

`LoadDllDetour`：

1. `GetRuleSetName()` 为空 → 还没进游戏，原样透传；非 `EXPANSION_2` → 透传（只支持 XP2）；
2. 把入参（Mod 顶替 `GameCores` 后引擎请求的**薄壳**路径）**改写成官方 GameCore 的绝对路径**
   （`OfficialGameCoreRelPath` 给官方相对路径、`BuildOfficialPath` 拼到游戏根下；官方文件不存在才
   透传原路径）。方向别记反：**引擎槽位=官方**，薄壳只在 Loader 缺席、没有这个 detour 时才被加载；
3. 若 `IsInitialized()` 仍为真（说明 `UnloadDLL` 钩子没生效 / 没清场）→ 先 `ResetForReload()` 兜底；
4. 调原函数 `g_origLoadDLL(target)`；
5. `ClearGameCoreTeardownWindow()`：**引擎这一步才真正换映像**，旧的 teardown 窗口（旧映像区间）
   到此失效——提前清会让仍映射着的旧映像重新对 Global 插件变成"可钩的已加载模块"（§2.3 第 9 步）。
   清窗发生在判返回值**之前**：`result == 0` 的幂等短路路径里映像仍是同一个（随后按"已加载
   模块"重新初始化插件，见本节第 7 点），失败路径同样不该把旧区间留在保护态；
6. `FreePendingPluginModules()`：这次调用可能顺带卸掉了旧的 GameCore，排队中的插件模块此刻才释放；
7. 成功 → `InitializeGameCorePhase()` + `LoadPluginsOf(GameCore)`；失败 → 区分"幂等短路"（读 exe 的
   `hModule` 槽判断模块是否已加载）与真失败，只记日志。

`UnloadDllDetour`：

1. `IsInitialized()` → `ResetForReload()`（清理 + 把 GameCore 插件模块**入队**）；
2. 调原函数 `g_origUnloadDLL()`——**引擎在这里卸掉 GameCore 映像连同它的 gameplay/ui Lua 环境**；
3. `ClearGameCoreTeardownWindow()`：映像已经没了，teardown 窗口可以清（§2.3 第 9 步）；
4. `FreePendingPluginModules()`：真正 `FreeLibrary` 那些插件模块。

### 2.3 ResetForReload 的完整顺序（每一步的位置都有理由）

1. 拿 `g_gameCoreTransitionMutex` + `g_pluginLifecycleMutex`；
2. `g_gameCorePhaseReady = false`（此后 `EnsureScriptHooksInstalled` 等入口会自行早退）；
3. 进入 teardown 窗口（写 `g_gameCoreTeardownAddress/SizeOfImage`；`ImageAddress` 仍 attach）；
4. 放掉 lifecycle 锁（下面要等回调、要加载/卸载插件，持锁等会锁反转）；
5. `DisableGameCoreDomainSites()`：趁旧映像仍映射，把 GameCore 域**全部已挂钩站点**
   `MH_QueueDisableHook` 后**一次** `MH_ApplyQueued` → 所有入口字节还原、不会再有人进入 stub 或插件 detour。
   不可读的目标（映像已经没了的兜底路径）不排队，改打 `recordStale`；
6. `CleanupAllCaptureSites()`：只清**落在 GameCore 域内**的捕获订阅，exe / 常驻模块域上的保留；
7. `UnloadPluginsOf(PluginCategory::GameCore)`：逐个插件走卸载流程（§3.3），GameCore 的模块句柄**只入队**；
8. 重新拿 lifecycle 锁；
9. `RemoveGameCoreDomainSiteRecords()`：进 teardown 窗口（在 `RemoveGameCoreDomainSiteRecords` 内部，
   此时 `ResetForReload` 第 3 步已经写过一次）+ `ImageAddress::DetachGameCore()` → 放锁
   **排空在途共享 detour**（`g_activeSharedDetours` 归零）→ 重锁，**重扫站点表**摘记录：
   成功即 `MH_RemoveHook` + **把站点原地复位**（节点/stub 保留并复用，**绝不 erase**——stub 内嵌
   `&HookSite`；复位包括清空 capture 槽）；失败则打 `recordStale` 并拔掉 detour 槽。最后复位
   `g_origRegisterScriptData(/ForUI)`、16 个 PushMethods 槽位。**teardown 窗口不在这里清**：
   它要活到引擎真正换映像那一步（两个 detour 调完原函数再 `ClearGameCoreTeardownWindow()`）；
10. 回到 detour，调 `g_origUnloadDLL()` → `ClearGameCoreTeardownWindow()` →
    `FreePendingPluginModules()`（见 §2.4）；

为什么是这个顺序：

- **第 5 步必须在第 7 步之前**：入口字节还原之后才谈得上"Free 插件不会留下入口跳向已释放代码的窗口"；
- **第 9 步重扫而不是沿用第 5 步的地址列表**：第 5～9 步之间还跑过插件卸载，而 `PushLuaMethods` 这类
  注册入口按设计不过域门，理论上仍可能往正在拆除的映像上装钩——重扫能一并收掉；
- **这里【不做】补丁区间清账，是设计决定**：Loader 已删除补丁自动回滚（§5.8），补丁记录只在插件
  自己调 `Unpatch` 时才从 `PatchRegistry` 摘除。副作用是**未撤销的补丁记录会跨代存活** —— GameCore
  插件若没调 `Unpatch`，它那条落在旧映像区间里的记录会留到进程退出；新一代 GameCore 映射到同一基址时，
  这条陈旧记录仍会参与 `OverlapsRegistered` / `OverlapsHookPrologue` 的区间仲裁（见 §5.8）。

### 2.4 插件模块的释放时机

- `UnloadPluginByOwnerId`（GameCore 类别）**只把句柄入队**（`g_pendingFreeModules`，由 `g_pendingFreeMutex`
  保护）。类别/ABI 不符的拒载不走这条：那种拒载发生在 `OnLoad` 之前，直接释放引用（§3.3）；
- `LoaderCore::FreePendingPluginModules()` 在两个 detour 里调用：`UnloadDllDetour` 的
  `g_origUnloadDLL()` **之后**、`LoadDllDetour` 的 `g_origLoadDLL()` **之后**；
- 于是"插件映像已释放、而它的 Lua 闭包还能被调用"这个前提不存在：gamecore 的 gameplay/ui Lua 环境
  是引擎卸载里拆的，闭包所在的 state 已经没了；
- 代价与边界：`OnLoad` 崩溃被隔离的 GameCore 模块会一直映射到下一次 Load/Unload；Global 插件本来就永不卸载。

### 2.5 锁与锁序

| 锁 | 保护 | 备注 |
|---|---|---|
| `g_gameCoreTransitionMutex`（递归） | 阶段切换串行化 | 最外层 |
| `g_pluginLifecycleMutex`（递归） | `g_plugins`、各类注册表、槽位表、owner 探针 | 最常被重入 |
| `g_pushStateMutex` | PushMethods 的 16 个槽位 | 在 lifecycle 内层 |
| `Runtime::MinHookMutex()` | 站点表 + 所有 `MH_*` 调用 | 在 pushState 内层 |
| `g_captureMutex` | 站点上的捕获派发数据（`captureOuts`/`retiring`/`captureParamIndex`） | 最内层 |
| `ImageAddress::g_mutex` | 映像登记（base/size/id） | 叶子 |
| `g_scriptStateMutex` | ScriptGlobals 的两个注册表 | 叶子（持有它时不再取别的锁）；与 `pushState` 同为 lifecycle 的下层，两者**从不互相嵌套**（见 `RemovePluginOwnedRegistrations`） |
| `Civ6MessageBus::mtx_` | 消息总线的 handler 表 | 出锁后才 `Enter`/排空（总线 → lifecycle） |
| `PluginInFlight::Owner::mtx` | `WaitAll` 的条件变量等待 | 等待时只持这一把 |
| `g_pendingFreeMutex` | 待释放句柄队列 | 叶子；`FreeLibrary` 一律在锁外做（插件 `DllMain(DETACH)` 可能回调 loader） |
| `g_detourDrainMutex` + `g_detourDrainCv` | 等 `g_activeSharedDetours` 归零 | 等待前已放掉 lifecycle / MinHook / capture 锁（**不得**持 lifecycle 等）；仍持最外层 `g_gameCoreTransitionMutex`——它只串行化阶段切换，不参与在途回调取锁 |

固定顺序：`transition → lifecycle →{ pushState | scriptState }→ MinHook → capture/ImageAddress`
（消息总线自成一层：`mtx_ → lifecycle`，但它从不与站点锁嵌套）。
凡是"插件代码可能被调用"的地方（`OnLoad`/`OnUnload`/回调/`WaitAll`）都必须**先放掉 lifecycle 锁**。

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

> 历史坑：这两处参数曾叫 `shellModule` / `shellDir`，但实际有三个调用方分别传 runtime 自己、
> exe 模块、薄壳，语义混在一个名字里，`FilterByEnabledMods` 因此被误当成"薄壳的目录"而写出
> 一条绕过白名单的例外（装成 `version.dll` 后它就是游戏 exe 目录）。现在参数已删除。
> 扫描根去重也必须先归一化：注册表 `SteamPath` 返回 `d:/steam` 而 vdf 里是 `D:\Steam`，
> 同一目录两种写法，只做大小写不敏感比较会把它当成两个根、扫两遍。

类别判定（`Civ6DLLHookLoaderAPI.cpp:CategoryForPath`）：把路径规范化（全小写、`/`→`\`）后含
`\plugins\global\` → `Global`，**其余一律 `GameCore`**。注意默认方向：放到预期之外的位置会被当成
GameCore（每局真卸载 + 只能动 GameCore 映像）。

类别决定三件事：加载时机（阶段 A / 阶段 B）、生命周期（驻留 / 真卸载）、域门（哪半边地址空间可用）。

### 3.2 加载流程（`LoadPluginDllInternal`）

1. 拿 `g_gameCoreTransitionMutex` + `g_pluginLifecycleMutex`；
2. `GetModuleHandleExW(UNCHANGED_REFCOUNT, path)` 先看模块是否已驻留；没有再 `LoadLibraryExW`,
   用 `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`。`ownsRef` 标记引用是否归本次调用。
   这一步（以及紧接着的 `Civ6PluginKind` 调用）都在**不持 `g_pluginLifecycleMutex`** 时做：它们会执行
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
6. 组装 `PluginEntry`（handle / path / stem 名 / `ownerId` = 规范化全路径 / category），
   `SetPluginState(Loading)`（同步 `PluginInFlight` 放行镜像）并 push 进 `g_plugins`；
7. `SetActivePluginContext(ownerId, handle)` → 放锁 → `CallOnLoadSafe(onLoad)`（SEH 包住）→ 清上下文 → 重新拿锁；
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
- **表的形状由两条 `static_assert` + 一个计数常量钉死**：`CIV6_HOOK_API_ENTRY_COUNT`（当前 76）
  必须与 `sizeof(HookAPI)` 和末尾成员偏移同时吻合，否则编译失败；启动时 `VerifyHookApiTableProtection`
  再扫一遍空项；
- **当前 `CIV6_HOOK_API_VERSION = 1`，且预发布阶段删改前缀不升版本号** —— 从未对外发布过插件，
  `1` 是它唯一出现过的值。已发生过两次破坏前缀都没 bump（① 删掉
  `GetCivilizationDescription` / `RegisterGameCoreReady` / `RegisterGameCoreTeardown`；
  ② 类别声明从表尾字段 `DeclarePluginKind` 改成插件自带导出 `Civ6PluginKind`，79 字段变 78）。
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

> **缺失：HookAPI 没有线程契约。** 头文件只在三个 Lua 相关入口上写了"仅游戏线程调用"，
> 其余 70 多个入口对调用线程没有任何约定，而实现里大量状态是靠互斥锁而非"单线程"假设保护的。
> 应当补一条全局契约（哪些入口只允许游戏线程 / Loader 一次性启动线程调用），
> 详见 §2.5 的锁表与 `common/HookAPI.h` 的三处现有标注。

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

表共 78 个字段 = 2 个头（`apiVersion` / `structSize`）+ 76 个入口。按"谁能用、受什么限制"分四类。

### 4.1 双域通用，但按"目标地址域"设门（9 个）

| 入口 | 门 |
|---|---|
| `InstallHook(target, detour, original)` | 目标地址 |
| `Patch(target, bytes, len)` / `Unpatch(target)` | 区间 / 目标地址 |
| `RegisterGlobalCapture(providerAddress, paramIndex, out)` | 目标地址（必须是可执行函数入口） |
| `ResolveByRva` / `ResolveByName` / `ResolveByRvaEx` / `ResolveByPattern` / `ResolveByVTable` | `image` 参数 |

规则（**应该是**正面规则，不是"不在 GameCore 里就算数"）：

- `GameCore` 类别：目标必须落在**当前 GameCore 映像**内（它唯一的合法域）—— **这条已正确实现**；
- `Global` 类别：目标必须落在**某个已加载的非 GameCore 模块**内 —— exe、常驻系统 dll（user32/dxgi…）、
  插件自己的模块都算；**堆、`VirtualAlloc` 的 JIT 页、空闲地址、将来会被 GameCore 占用的地址一律拒绝**。

实现（`Civ6DLLHookLoaderAPI.cpp`）：`IsTargetOpenToCaller`（单点）/ `IsRangeOpenToCaller`（整段）/
`IsImageOpenToCaller`（image 参数）；模块判定用 `RangeInsideOneLoadedModule`——两端各自的
`GetModuleHandleExW(FROM_ADDRESS)` 返回同一模块句柄，即证明整段同属一个已加载模块（不解析 PE）。

`GetModuleHandleExW(FROM_ADDRESS)` **严格按该模块的 `SizeOfImage` 判定归属**（本机实测：
`kernel32` 基址 `+SizeOfImage-1` 命中，`+SizeOfImage` 即返回 FALSE / `ERROR_MOD_NOT_FOUND`=126）。
所以"`!hasGameCore` 让第一个合取项恒真"并不构成放行——判据由第二个合取项
`RangeInsideOneLoadedModule` 独立承担，堆页 / JIT 页 / 空闲地址 / 映像外的对齐余量都拿不到模块句柄。
（曾有"模块映像之后的保留/对齐区仍会通过"的说法，已实测证伪并删除。）


与域门**并列**的其它仲裁（顺序见 §5.5）：页属性预检（`PluginBoundary`）、补丁区间仲裁
（`PatchRegistry::OverlapsRegistered`）、装钩前导窗口仲裁（`OverlapsHookPrologue`）、teardown 窗口
（`TargetInTearingDownGameCore`）。

### 4.2 GameCore 专属（8 个，编译期 + 加载期 + 运行期三层限制）

`GetEngineUtility`、`EditPlayer`、`RegisterGameEvent`、`TriggerGameEvent`、`RegisterScriptGlobals`、
`RegisterScriptGlobalsForUI`、`PushLuaMethods`、`RegisterPushMethodsTarget`。

为什么专属：`GetEngineUtility` 的定位 pattern 直接扫 **GameCore XP2**（读 `ms_pkCurrentGame + 0x18`），
`EditPlayer` 解析 `GameCore::Context::Globals::EditPlayer` 符号；其余六个操作 **gamecore 的脚本环境**
（往 Lua 表里放闭包、注册脚本全局、事件）。Global 插件用它们没有意义：对局前拿不到对象，对局中也不该
持有 GameCore 域的引用。

### 4.3 Lua 原语（44 个）——不是 GameCore 专属

全部是 `HavokScript_FinalRelease.dll` 导出的薄封装（`HavokScript.cpp`：约 40 个 `GetProcAddress` +
`checkplayerid` + 极端情况下的原始栈兜底）。入口本身**与 GameCore 无关**：作用对象是**调用方传进来的**
`lua_State*`，所以两类插件都开放。导入在**阶段 A** 解析一次（该 DLL 是 exe 静态导入、常驻）；
缺失时逐个入口降级为安全默认值 + 限次日志，**不影响插件加载**。

### 4.4 其它

- 消息：`BroadcastMessage` / `RegisterMessageHandler` / `SendMessageTo`（§6.2）；
- `Log`、映像元数据 `IsImageLoaded` / `GetImageInfo`；
- 本地化：`LocalizationLookup` / `LocStringBytes` / `LocCreate` / `LocDestroy` / `LocLookup` /
  `LocPushArgument` / `LocToUtf8`——走独立模块 `Localization_FinalRelease.dll` 的导出；
- `MakeHash`：**已内化**为 loader 自己的原生 CRC32（raw，无最终异或，与官方 `GameCore::Utilities::MakeHash`
  逐位一致，并有编译期自检向量）；不再解析任何 GameCore 符号，任何时刻可算；
- `GetMainLuaState`：读 exe 全局 `LuaSystem::LuaScriptSystem::ms_apSingletonInstance`（DX11 实测 RVA
  `0x2D08F88`）解引用后的 `+0x10` → **引擎主 Lua VM**（`m_pkMainLuaState`）。★ 这是**进程级** state：
  `lua_newstate()` 在 `Civ6App::GUIInit` 建一次，只在 `Civ6App::GUIShutdown` `lua_close`
  ——**换局不会失效、也不会被重写**（全 exe 仅一处写 `+0x10`）。未就绪返回 null。
  **Global 与 GameCore 两类插件都可调用，不限类别**——它是进程级 state，常驻插件持有它
  不会因换局悬垂，所以与 `GetEngineUtility` 那类"GameCore 短命域"入口不同类，不受地址域门限制。

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

**为什么永不释放**（这一点很容易记错，§9 表格第 1 行曾把它归因为 asmjit 的限制，实际不是）：
stub 的机器码里用 `imm64` **永久内嵌了 `&HookSite`**（见上面的 `mov r10, imm64(site)`），
而"已经没有任何调用者停在 stub 内部"这件事**无法证明** —— 没有可靠的计数。
所以释放 stub、节点或跳板都会是 UAF；节点只在进程退出时随静态对象回收。
asmjit 只能整块 release、多个 stub 共用一块，是**叠加**在这个硬约束之上的第二个原因，
不是根本原因。


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

`Patch` / `Unpatch` 是插件对游戏内存的**原始字节修改**，账本按地址存"第一次 Apply 之前的字节"。

**已实施：删除 Loader 侧的自动回滚**（`RevertAllFor` 及其两个调用点
`UnloadPluginByOwnerId` / `QuarantinePluginByOwner` 里的还原步骤），理由：

- **两个调用点里只有一个有意义，而那个恰好最危险。** `UnloadPluginByOwnerId` 那条针对 GameCore 插件，
  其补丁本来就只能落在当前 GameCore 映像内（§4.1），拆映像时随映射一起消失，回滚纯属多余；
  真正会用到它的是**崩溃隔离**（§3.3），而隔离的语义是"模块驻留不卸、代码仍在内存里"——
  此时往**可能正被执行**的代码里写还原字节、又不做任何 quiesce（项目自己有 MinHook 的线程冻结机制，
  但这条路径没用），风险高于收益；
- **存档未必是"真原始"。** 它存的是"调用 `Apply` 那一刻"的字节；若那一刻该函数已被 MinHook 挂钩，
  存下来的就是跳板字节，日后写回等于把别的机制的跳板又塞回去；
- **还原本身也在改页保护**，而恢复保护属性的返回值被忽略，一次失败就会把页永久留在可写状态（破坏 W^X）。

**约定**：

- `Unpatch(target)` **保留**（底层 `PatchRegistry::RevertOwned`），供插件在**自己还活着的时候**
  主动撤销（典型位置是 `OnUnload`）。这时插件知道自己的状态，也知道自己的补丁是否还被调用；
- **Loader 不再替插件自动撤销补丁**。隔离/卸载后的补丁留在游戏里，直到进程退出——
  插件作者应把 `Patch` 视为"进程生命周期内不可撤销"的默认语义，需要可撤销就自己管好 `Unpatch` 时机；
- `PatchRegistry::OverlapsRegistered` **保留**：即使补丁不可撤销，也必须禁止两个插件往**重叠**区间
  打补丁（否则一方的补丁会不可逆地踩坏另一方）。`InstallHook` 的前导窗口仲裁 `OverlapsHookPrologue`
  同理保留。

> 副作用（已知且接受）：`PatchRegistry` 的记录只增不减（`Apply` 加、`RevertOwned` 减），
> 隔离或未调 `Unpatch` 的插件会让记录在其后驻留到进程退出。

---

## 6. 插件回调、Lua 与 UI 数据流

### 6.1 PluginInFlight（在途登记与排空）

`PluginInFlight::Owner`：owner 的放行镜像 + 在途计数；`SetAllowed` 是镜像的**唯一写者**（只由
`SetPluginState` 调用）。守卫入口用 `Enter(owner, kind)`（先增量再检查、失败回滚）与 `ReleaseCount`；
卸载/隔离用 `WaitAll(owner, name)`：谓词是「本 owner 的在途计数 ≤ 本线程自己的深度」，5 秒未满足就
限次记日志但**继续等**（不放弃）。

被它守卫的入口：消息 handler、`RegisterScriptGlobals`（含 UI）、`GameEvent` 触发、`PushLuaMethods` 推送。
**不**被它守卫的：插件 detour（靠 teardown 顺序保证）、以及已经交给引擎的 Lua 函数指针。

### 6.2 消息总线（`Civ6MessageBus`）

按 owner 注册 handler、`Broadcast`、`SendMessageTo`、`UnregisterOwner`；handler 调用走
`PluginInFlight::Enter`（owner 已停用则直接跳过）；注销在锁外 `WaitAll`。
总线**没有** Loader 自己的处理器，也没有"按名字注销单个 handler"的入口：v1 的 `load-plugin`
消息入口（任何插件都能让 Loader 去 `LoadLibrary` 任意路径并调其 `OnLoad`，绕过启用集过滤）
已连同 `InitializeLoader` 一起删除，插件只能经 `LoaderCore::LoadSinglePlugin` 的扫描路径加载。

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
参数由插件的 `pushFn` **现压**（是 loader 在调它，所以能被 `PluginInFlight` 守卫）。引擎信号环桥接的旧
路径已删除。

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
  （3/4 只是 ABI 里的取值，运行期不可达。**真正堵死它们的是两处**：① sidecar 容器只接受 1/2/5；
  ② `InitializeGameCorePhase` 里硬编码了 `GetModuleHandleW(L"GameCore_XP2_FinalRelease.dll")`，
  而它是全项目唯一调用 `AttachGameCore` 的地方。`ImageAddress::IdentifyGameCore` 本身是接受
  Base/XP1 的，所以别以为靠枚举值就能挡住）；
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
- `BuildNewTable(imageId, target)`：解析目标映像的 `.pdata`（PE 异常目录），对每条算签名
  （`(begin_rva, size, unwind_hash)`，`unwind_hash` 是 FNV-1a64），再按顺序判定：
  ① **去 DRM `SizeOfImage`** + `TimeDateStamp` 相同 = 同一构建 → 恒等映射；
  ② 否则整表逐条 `(begin_rva, size, unwind_hash)` 相等（纯重建）→ 同样恒等映射；
  ③ 两者都不同 → 跨版本匹配：磁盘缓存（`LoadCache` / `SaveCache`，键 =
  新表指纹 + sidecar 指纹；两者都是各自 pdata 表 `(size, unwind_hash)` 序列的 FNV-1a64，**不含**
  `begin_rva`、符号名与 AOB 数据）→ 窗口哈希锚点 + LIS 锚点链 + 锚点间插值 + **首尾锚点外推** →
  **头 hash 校验**（sidecar 里带 `normHeadHash` 的 old 条目，按新映像同一函数的序言字节重算，
  不等即剔除）→ 头 hash 局部恢复（`normHeadHash`，生成端「无 hash」一律写 0）→ 函数体 AOB 恢复 →
  叶子 AOB 匹配 + vtable 槽位反推（结果并入同一张 `leafMap`）；
  ① 里的 `SizeOfImage` 是**去 DRM 视图**（`NormalizedSizeOfImage`：从末节往前剥掉连续的
  `.bind` 段后重算，只认 `.bind` 这一个名字）。去 DRM 的 exe 删掉了末尾的 `.bind` 段，
  `SizeOfImage` 因此比原版小 0x33000，而 `TimeDateStamp` 与 `.pdata` 表逐字节不变 ——
  sidecar 的 `baseSizeOfImage` 与运行时两边用同一套规则（`symdb.py:normalized_size_of_image`
  与 `PdataMatch.cpp:NormalizedSizeOfImage`），故去 DRM 版与原版都能命中快路径。
  GameCore 没有 `.bind`（末节是 `.reloc`），原样返回。
  **注意两种 `SizeOfImage` 用途不同**：身份判定用归一值，所有越界/边界检查一律用 PE 原始值
  （`nt->OptionalHeader.SizeOfImage`），不能用 sidecar 里的历史值去约束当前映像。
  **凡是"这个映像是不是我认识的那个构建"的比较，两边都必须走归一口径** —— 目前共三处：
  `BuildNewTable` 的 `headerIdentity`、exe 版本锚 `ExeMatchesAnchor`（`Civ6DLLHookLoaderAPI.cpp`，
  无符号库时判断能否直接信任原始 RVA）、以及 `PdataMatch` 的那条"header 不同但 pdata 相同"日志
  （早期只改了前两处，第三处会打出两种口径的假差异）；
- 缓存命中后按头/尾 + 最多 64 个等距条目做一次抽样自校验（`ValidateCachedMap`）。它只保证「结构上像
  本次匹配的产出」（索引不越界、签名/头 hash/AOB 至少一条成立），**不是对缓存可信度的保证**：缓存文件
  与 sidecar 同在游戏目录、权限相同，能改写它的人也能直接换掉 runtime；
- `CorrectRva` / `CorrectByName` / `CorrectVTableByName` 只查表；构建期（vtable 反推）与运行期查询共用
  同一份 `CorrectRvaInTables` 口径（二分 + 封顶 64 条回扫；只有 `size` 不变时才允许函数内偏移；
  gap / 回扫耗尽退回 `leafMap`）；
- 返回 0 / nullptr = 矫正失败（调用方按各自失败路径处理）。

### 7.4 取址入口与回退顺序

- **插件可见**（`HookAPI`，全部要过 `image` 域门）：`ResolveByRva` / `ResolveByRvaEx`（指定段）/
  `ResolveByName` / `ResolveByPattern`（AOB 文本）/ `ResolveByVTable`；
- **Loader 内部**（不经过插件 ABI，也不拿插件锁）：`LoaderCore::ResolveExeTarget(HookInfoExe)` 与
  `ResolveDataByAobCore(image, aob, index)`；
- **exe 域双版本**：`HookInfoExe` = 每个变体（DX11/DX12）各一组「RVA + 唯一 AOB」，运行时按当前 exe
  选一组：先 RVA（经 pdata 矫正），AOB 作为兜底/校验。例：`kExeLoadDLL` / `kExeUnloadDLL` /
  `kExeGetRuleSet`（带 `index` 解决同码兄弟函数）；
- **数据槽**：同样是"逐段指令 + `disp32` 通配"的 AOB，解出 RIP 相对的全局地址（`hModule`、`UIManager`、
  `ms_apSingletonInstance`、`ms_pkCurrentGame` 等）。AOB 的生成/核对由 `tools/symdb.py aob` 负责。

### 7.5 外部模块

- `Localization_FinalRelease.dll`：按**导出名**解析 `Lookup` / `PushArgument` / `String` 析构 / `toUTF8` 等；
  缺任何一个只降级对应包装（返回空串/nullptr），不影响其它功能；
- `HavokScript_FinalRelease.dll`：解析约 40 个 `hksi_lua*` / `hks*` 导出，作为绝大多数 `Lua*` 原语的实现；
  **在阶段 A 解析一次**（该模块是 exe 静态导入、常驻，导入地址恒定，没有"需要重新解析"的理由）；
  缺导入 → Lua API 逐个入口降级为安全默认值 + 限次日志，**不影响插件加载**。唯一的例外是 `LuaPushBoolean`：该 DLL 不导出任何 `pushboolean`，
  实现是硬编码 `lua_State + 0x48` 的原始栈写入（`RawPushTValue`），换游戏版本必须重验该偏移。

### 7.6 工具链：`tools/symdb.py`（唯一入口）

原先 7 个脚本已合并为一个带子命令的入口，每条老命令行只需把脚本名换成 `python tools/symdb.py <子命令>`：

| 子命令 | 作用 |
|---|---|
| `json-exe` | 从 IDA 导出（`.funcs.txt` + `.rdata .asm`）+ 去 DRM 的 exe → exe 版 symdb JSON |
| `module` | JSON + 对应 PE → 单模块 `C6SD` 容器（依赖 `aob_helper.exe` / `normhash_helper.exe`） |
| `pack` | 多个单模块容器 → `Civ6DllLoader.symdb.pack.bin`（`--module` 可多次，`--list` 只查） |
| `compress` | `pack.bin` → `C6XC` + LZMA1 信封 `.xp`（带 SHA256 roundtrip 校验） |
| `validate` | 按运行时同款解析独立校验 `.bin` / `.xp` |
| `aob` | 从容器里的 mask 指纹生成/核对 loader 的 AOB 常量（`--emit-cpp` 直接出可粘贴的常量块） |
| `rva-map` | `GameCore.symdb.json` → `rva_map.json`（喂 `rva_to_symbol.exe` 做地址→符号） |
| `all` | 一条命令跑完产线：`module` ×3 → `pack` → `compress` → 部署到 `DllLoaderRuntime/` → `validate` → 清理中间产物 |

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

以下都是**有意识地接受**的取舍（不是遗漏）。做改动前先看这一节：很多"看起来是 bug"的行为是设计结果。

| # | 现象 | 原因 / 机制 | 影响 | 状态 |
|---|---|---|---|---|
| 1 | 站点 stub 的 JIT 内存永不回收 | **根本原因**：stub 机器码里 `imm64` 永久内嵌 `&HookSite`，而"没有调用者停在 stub 内"无法证明（无可靠计数），释放即 UAF。asmjit 只能整块 release、多 stub 共用一块是叠加的第二原因 | 进程生命周期内每新增一个**不同目标地址**才多一块 stub；同地址复用同一块，不随 reinstall 累积 | 接受（硬约束）。若将来站点数量爆炸，可把 stub 改成"每站点 `VirtualAlloc`/`VirtualFree`"配合调用者计数，顺带去 asmjit 依赖 |
| 2 | `recordStale` 重建时的**旧映像字节写回**风险 | 旧 MinHook 记录里只有建记录时的前导字节副本，不含版本信息 | 重建前先比对当前前导字节与副本（`HookSite::prologueBackup`）：不一致就 poison 该站点、拒绝触碰记录（fail-closed） | 已加护栏（§5.7） |
| 3 | Global 插件永不卸载 | 域模型：Global 钩的是常驻 exe | 插件静态状态跨对局、跨读档存活 | 约定：Global 插件的 `OnLoad` 必须幂等，不得假设"只执行一次" |
| 4 | 插件自建线程 / 前端 Lua 闭包不受 loader 保护 | 这些不在 HookAPI 覆盖范围内 | 卸载瞬间的并发调用会踩空 | 文档告知；不做"线程登记"就无法根治 |
| 5 | 域门只装在"换地址 / 给地址"这类入口 | 设计原则是**按目标地址授权**，不是限制插件行为 | 注册、回调类入口不设门 | 有意：边界靠"GameCore 专属入口 + 域规则"共同成立 |
| 6 | teardown 依赖"有在途 GameCore 调用就已经完蛋"这个弱假设 | 引擎自己 `UnloadDLL` 同样会 unmap 那块内存 | 做不到绝对安全 | 接受：与引擎原生行为等价 |
| 7 | exe 域的站点永不摘钩 | exe 常驻，摘了反而引入额外状态 | 钩子活到进程退出 | 有意 |
| 8 | 开关 Mod 不生效，必须重启 | 没有 reconcile 通路 | 操作体验 | 有意：状态一致性优先于便利 |
| 9 | UI 注入依赖特征码，匹配失败静默降级 | 游戏更新改了目标代码 | 面板不出现（日志有记录），其余功能正常 | 接受 |
| 10 | 数据槽定位依赖 AOB 兜底指令序列 | 编译器 / 游戏更新 | 定位失败返回 0，对应功能降级 | 接受（有日志） |
| 11 | 休眠检测要求宿主 exe 名形如 `CivilizationVI*.exe` | 防止"别的进程从 exe 目录加载这份 version.dll"时把 Loader + Global 插件拉进去 | 用改名 exe / 第三方启动器的会话里 Loader 静默休眠（不装钩）；`OutputDebugString` 有留痕 | 有意（严格优先） |
| 12 | 插件打的补丁**不再自动回滚** | 自动回滚要在"插件已崩"的时刻往可能正执行的代码里写还原字节，且无 quiesce；存档还可能是别人的跳板字节 | 隔离/卸载后补丁留在游戏里直到进程退出；插件需自己管 `Unpatch` 时机 | 有意（§5.8，已实施） |

### 9.1 已知未处理的问题（不是取舍，是待修）

上面那张表是"已接受的取舍"。下面这些**不是设计结果，而是当前实现的缺陷**，改动时不要误以为是有意的：

| # | 问题 | 位置 | 说明 |
|---|---|---|---|
| B | ~~`GetActiveLuaState` 没有类别限制~~ ❌ **已撤回：无需设防** | `HookAPI.h`（§4.4 / §6.6） | 主 state 是**进程级**的、换局<u>不会</u>失效（原以为"每局 state"是错的，见 §6.6），所以它**不该**受地址域门限制——与 `GetEngineUtility` 等 GameCore 专属入口不同类。一度据"GameCore.dll 用 `Lua::ms_CriticalSection`、与 exe 侧是不同临界区实例"加过门，但那**是线程问题不是类别问题**，类别门拦不住跨线程调用；约束是"**仅游戏线程调用**"。门已移除。保留的有效产出：接口改名 `GetMainLuaState`（对齐引擎的 `m_pkMainLuaState` / Tuner 的 `"Main State"`）+ 错误注释修正 |
| H | ~~GameCore 已映射但未 attach 时 Global 能钩进去~~ ✅ **已解决** | `InitializeGameCorePhase` | 根因是**进程级依赖的导入（HKS / Localization）被错放在每局阶段**：`InitHavokScript` 失败会走一条"detach 了却不设 teardown 窗口、标志仍为 false"的路径，导致 Global 插件能钩进一个 Loader 不再跟踪的映像而无人清理。已把两个导入移到阶段 A（`WorkerMain`），该失败路径整体消失。见 `AUDIT_REPORT.md` §35 |
| C | teardown 窗口在取不到映像信息时被清成空 | `ResetForReload`（`SetGameCoreTeardownWindow(0,0)` 分支） | 而 `base == 0` 时保护判定直接返回 false，等于在最不确定时把门关掉；同文件 `RemoveGameCoreDomainSiteRecords` 在同样情形下**刻意不清**，两者矛盾 |
| E | 状态码 `3`（预留 Frontend）与若干空槽 | `common/HookAPI.h` | 未实现的功能不应留在核心枚举里 |
| F | `ShouldSkipPluginFile` 用文件名黑名单而非白名单 | `common/ModScan.cpp` | 会把将来新增的官方 DLL 当插件加载（`FindContentRoot` 那条已于本次提交删除：它接受任意 `Win64*` 前缀，且唯一的调用点会引入"游戏安装根"这个恒空的内容根） |

> **A、D 两行已撤回**（独立复核证伪，详见 `AUDIT_REPORT.md` §9 / §14）：
> - A：`!hasGameCore` 只让第一个合取项恒真，判据由第二个合取项 `RangeInsideOneLoadedModule` 承担；
>   且 `GetModuleHandleExW(FROM_ADDRESS)` 严格按 `SizeOfImage` 判定（实测证伪"对齐余量能过"）。
> - D：`MakeHashImpl` **确有** SEH 探针（`TryStrLenRaw`），且 `LocLookupImpl` 等多处严格更弱。

> 曾经的 G（"补丁自动回滚尚未按 §5.8 删除"）**已解决**：Loader 侧自动回滚已删除，
> 见 §5.8 与 §9 表第 12 行。

---

## 10. 附录

### 10.1 证据文档索引（`docs/analysis/`）

架构结论都是逆出来的，原始证据保留在这里，改代码前先对照：

| 文档 | 覆盖内容 |
|---|---|
| `LoadDLL_analysis.md` | `LoadDLL` / `UnloadDLL` 的反编译与参数、规则集判断、官方路径改写 |
| `GameEvents_链路.md` | 游戏事件系统（`RegisterGameEvent` / `TriggerGameEvent`）整条链路与调用时机 |
| `EXE_SITE_MAP.md` | exe 域全部站点的 RVA / AOB / 语义清单 |
| `HookInfo_取址模型.md` | 取址模型（image/RVA/pdata 矫正/AOB 兜底）与各入口的取舍 |
| `GameSignals_Subscribe_decompiled.txt` | 信号订阅相关反编译原文 |
| `Units_Create_decompiled.txt` | 单位创建相关反编译原文 |
| `真机测试清单.md` | 需要实机验证的场景清单（每次改 ABI / 生命周期都要过一遍） |

### 10.2 术语表

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

### 10.3 如何扩展

#### 加一个 HookAPI 入口

1. 在 `common/HookAPI.h` 的 `HookAPI` 结构**尾部**追加函数指针；
2. 若它只对 GameCore 有意义：加进文件底部"类别门禁"块的对象式重命名列表（8 个之一的位置），
   并在实现里调用 `RequireGameCoreOwner`；
3. 若它是"换地址 / 给地址"类：实现必须过 `IsTargetOpenToCaller` / `IsRangeOpenToCaller`；
4. 在 `Civ6DLLHookLoaderAPI.cpp` 的 `Impl` 里实现，并**按顺序**填进 `g_hookApi` 的位置初始化表；
   追加入口还必须同步 `common/HookAPI.h` 的 `CIV6_HOOK_API_ENTRY_COUNT`：`g_hookApi` 上方的两条
   `static_assert`（`sizeof` + 末尾字段偏移）挡住「加了字段却没改计数/没补初始化」，
   `VerifyHookApiTableProtection` 启动时还会扫描空项；
5. 编译 loader 侧需要 `CIV6_HOOKAPI_BUILD_IMPL`（工程里已定义）；
6. **不要**动已有字段的顺序，也不要改 `apiVersion`（见 10.4）。

#### 加一个内部钩（loader 自己用）

- exe / 常驻模块：直接 `MH_CreateHook` + `MH_EnableHook`（域稳定，无需站点模型）；
- GameCore：走站点模型（`InstallLoaderDetourOnSite` 之类），这样 teardown 能统一摘掉；
- 需要读参数 / 写返回值：用捕获插槽，不要自己写第二套。

#### 加一个插件类别

1. `common/HookAPI.h` 的 `CIV6_PLUGIN_KIND_VALUE` 加值（3 起是保留位）+ 头文件里的
   `CIV6_PLUGIN_KIND_VALUE` 取值分支（新宏 → 新 kind）；
2. 加载期映射：`KindToCategory`（API cpp 内）+ `CategoryForPath` 的目录名判断；
3. 域规则：`IsTargetOpenToCaller` 里加一条"该类别能碰哪块内存"的**正向**规则；
4. teardown 策略：想清楚它的模块什么时候能 `FreeLibrary`（现在只有 GameCore 类别会排队释放）。

### 10.4 改 ABI 的规则

- **预发布阶段（当前）不升版本号**：从未对外发布过插件，删字段 / 改顺序 / 改语义直接做，
  `CIV6_HOOK_API_VERSION` 停在 `1`（唯一出现过的值）；插件必须用当前头文件重新编译。
  已发生的两次破坏前缀见 §3.4；
- **对外发布之后**：只追加（新增函数追加到尾部，`apiVersion` 不动）；破坏前缀才提升版本号，
  旧插件会被拒而不是崩；
- **类别门在表外**：`Civ6PluginKind` 导出负责"OnLoad 之前"按类别快速拒绝（旧头文件编出来的插件没有这个
  导出 → 在 OnLoad 之前就被拒）；ABI 版本兼容仍由表内的 `apiVersion` + `structSize`（插件侧
  `HookAPI_IsCompatible`）判；
- **删除枚举值不算前缀破坏**：不需要再升版本；
- 改完必须：两个配置都重编 + 跑一遍 `真机测试清单.md`。

### 10.5 文档维护约定

- 本文件是**唯一的总架构文档**，"为什么这样设计"写在这里；
- 反编译原文、站点地图、测试清单放 `docs/analysis/`，只增不改语义；
- 代码里的"为什么不这样写"注释应指向本文件对应小节，而不是复述一遍。



