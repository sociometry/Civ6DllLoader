# Civ6DllLoader 架构总览

- 状态：**当前有效**（对齐 HEAD 的 S1–S5 重构之后：kind 门禁、域门正面规则、teardown 物理摘钩、
  插件释放延后、tools 单入口化）。最后校订：2026-09-16。
- 适用版本：预发布 `1.0.0`（`common/LoaderVersion.h`），插件 ABI `CIV6_HOOK_API_VERSION = 1`。
- 这份文档是**唯一权威的架构说明**；逆向取证类材料（原始反汇编/字节/映射表）在 `docs/analysis/`，
  本文在需要处引用它们。历史设计文档已删除。
- 约定：本文用 `file` / `file:函数名` 定位，尽量不写死行号（行号会随改动漂移）。

---

## 0. 一分钟速览

一句话：**在游戏进程里用 `version.dll` 代理 + 薄壳宿主，把 `Civ6DllLoader.runtime.dll` 塞进
进程；runtime 挂少数几个钩（LoadDLL / UnloadDLL / LoadUI），维护一个按地址索引的"挂钩站点表"，
并通过一张只读函数指针表（HookAPI）把"取址 / 装钩 / 打补丁 / 注册回调"的能力交给插件。**

三个必须记住的不变量（后面各节都会回到它们）：

1. **类别 × 域**：插件分 `Global`（只启动时加载、永不卸载、只许动**已加载的非 GameCore 模块**）
   与 `GameCore`（随对局加载/卸载、只许动**当前 GameCore 映像**）。这条同时由编译期、加载期、
   运行期三层保证（§3.5、§4）。
2. **站点表是唯一的挂钩账本**：同一个目标地址只挂一次 MinHook，挂到 Loader 自己生成的 stub；
   站点、stub、capture 订阅都记账在 `g_hookSites` 里。日常退役只"拔插槽"，**只有 GameCore teardown
   才会物理摘除**（§5）。
3. **释放顺序**：摘钩（还原入口字节）→ 卸载插件（OnUnload / 回滚补丁 / 注销回调）→ 交给引擎
   `UnloadDLL` 卸掉 GameCore（连同它的 Lua 环境）→ **之后**才 `FreeLibrary` 插件模块（§2.4）。

进程里有哪些东西（详见 §1.1）：

| 模块 | 角色 |
|---|---|
| `CivilizationVI.exe` | 游戏本体；Loader 的钩子目标（LoadDLL / UnloadDLL / LoadUI…） |
| `version.dll` | **Loader 本体**（就是 `Civ6DllLoader.runtime.dll` 的副本，被放进 exe 目录）：exe 静态导入它，
|  |  同时它把系统 `version.dll` 的导出逐条转发出去，所以系统版本查询行为不变 |
| `GameCore_XP2_Shell_FinalRelease.dll` | 官方 GameCore 的**替身壳**（由 Mod 框架按规则集加载）：懒加载真正的官方
|  |  GameCore 并转发导出；**自己不启动 runtime**，只在 Loader 缺失时安装一次并提示重启 |
| `GameCore_XP2_FinalRelease.dll` | 游戏的对局逻辑（"短命域"，每次进对局都换） |
| `Localization_FinalRelease.dll` / `HavokScript_FinalRelease.dll` | 本地化 / Lua VM（常驻，按导出名解析） |

关键文件索引（读代码的入口）：

| 文件 | 职责 |
|---|---|
| `common/HookAPI.h` | 插件 ABI：HookAPI 表、类型、冻结前缀规则、类别门禁、`HookAPI_IsCompatible` |
| `DllLoaderRuntime/Civ6DLLHookLoaderAPI.cpp` | 一切的核心：站点表、capture、插件生命周期、
|  |  HookAPI 实现、域门、teardown |
| `DllLoaderRuntime/LoaderHooks.cpp` | exe 域钩子（LoadDLL / UnloadDLL）的安装与 detour 编排 |
| `DllLoaderRuntime/RuntimeEntry.cpp` | DllMain、休眠检测、一次性启动线程 |
| `DllLoaderRuntime/UiInject.cpp` | 主菜单 UI 注入（LoadUI detour + LuaContext） |
| `DllLoaderRuntime/ImageAddress.cpp` | PE 映像注册与 RVA 换算 |
| `DllLoaderRuntime/PdataMatch.cpp` | sidecar 解析 + pdata 匹配 + RVA 矫正 |
| `DllLoaderRuntime/PatchRegistry.cpp` | 补丁账本（按地址存原始字节） |
| `DllLoaderRuntime/PluginInFlight.*` | 插件回调的在途登记与排空 |
| `DllLoaderRuntime/Civ6MessageBus.*` | 插件间消息 |
| `common/ModScan.cpp` / `common/EnabledMods.*` | 插件扫描与"启用 Mod"过滤 |
| `DllLoader/ShellBootstrap.cpp` | 薄壳侧的安装/自更新 |
| `tools/symdb.py` | 符号库流水线（唯一入口，含 AOB 生成/核对） |

---

## 1. 部署形态与启动链

### 1.1 进程里的模块与角色

进程里有**两条独立的进入路径**，别把它们混起来：

1. **Loader 靠静态导入进进程**：exe 的导入表里有 `version.dll`，Windows 会从 exe 目录解析它——
   我们把 `Civ6DllLoader.runtime.dll` 复制成 exe 目录的 `version.dll`，于是 Loader 在进程启动**最早**
   阶段就进来了（`DllLoader/ProxyExports.cpp`）。这份 `version.dll` 的导出表逐条转给系统真正的
   `version.dll`，所以"查文件版本"这类系统行为不受影响。
2. **薄壳靠游戏自己的加载器进进程**：进对局时引擎用 `GameCore::LoadDLL(wchar_t const*)` 按规则集
   加载 GameCore DLL；我们的 `LoadDLL` detour 把官方路径（`DLC\Expansion2\...\GameCore_XP2_FinalRelease.dll`）
   **改写成 Mod 目录里的薄壳** `GameCore_XP2_Shell_FinalRelease.dll`。薄壳在引擎调它的
   `DllCreateGameContext` 时才懒加载真正的官方 GameCore，并把 155 条导出转发过去（另 2 条自己实现）。

薄壳**不会**去启动 runtime——runtime 早就以 `version.dll` 的身份在进程里了。它唯一和 Loader 相关的
职责是：发现 exe 目录没有 `version.dll` 时，从启用 Mod 的 runtime 里挑版本最高的一份装上去，并提示
"请重启游戏生效"（安装器细节见 §1.3）。

- runtime：`Civ6DllLoader.runtime.dll`（产物在 `x64\Release\`），所有 hook / sidecar / 插件逻辑都在这里；
- 薄壳：`GameCore_XP2_Shell_FinalRelease.dll`（同样在 `x64\Release\`），只有导出转发 + 安装器，**零 hook**。

### 1.2 version.dll 的休眠检测

`RuntimeEntry.cpp` 的 DllMain 先做一次自检：**自己所在目录必须是游戏 exe 目录**
（`Base\Binaries\Win64Steam\` 或 `Win64\`）。不在就说明这个 `version.dll` 是被别的程序（浏览器、
编辑器）加载的，直接"休眠"——不建线程、不读文件、不挂钩，避免把 Loader 逻辑泄漏到无关进程。

### 1.3 安装器与自更新

两条**互相独立**的通路，别当成一件事：

**① 薄壳侧的"补装"（`DllLoader/ShellBootstrap.cpp`）**——只在 Loader 完全没装时用，进程内只跑一次：

1. 算 exe 目录，看 `exe\version.dll` 在不在：**在 → 零动作**（不复制、不弹窗，正常路径就走这里）；
2. 不在 → 从启用 Mod 里收集 `Civ6DllLoader.runtime.dll` 候选（`ModScan` 已做启用过滤）→ 逐个探测版本
   （读 RC 资源 105）→ 选版本最高的一份（同版本比路径字典序）；
3. 复制到 `version.tmp` 再原子改名成 `version.dll`（顺带尽力清理 `version_Old.dll`）；
4. 弹一次双语提示"已安装，点击确定立即重启游戏"并尝试重启；
5. 任何一步失败都**只记日志、不弹窗、不阻塞**——本次会话就以官方 GameCore 透传跑完（Loader 缺席，
   也就不会有任何插件被加载）。

**② runtime 侧的自更新（`LoaderUpdate::CheckAndApplyUpdate`）**——已在进程里跑的那份去换磁盘上的：

- 前提：自己的文件名必须是 `version.dll`（否则视为开发中的直接加载，跳过自更新）；
- 启动时若发现 `version_Old.dll` 存在，说明**上一会话刚做完一次自更新**，直接删掉它（自愈）；
- 从启用 Mod 的候选里排除自己，选更新的版本 → 备份成 `version_Old.dll` → 替换；失败则回滚，
  当前安装保持不变；
- 换完这一会话**仍在用内存里的旧版本**，必须重启才生效（日志写 `update applied ... (restart to take effect)`）。

版本号与协议常量在 `common/LoaderProtocol.h` + `common/LoaderVersion.h`（`1.0.0`、RC 资源 id 105）。
薄壳拿到的候选版本号也来自同一份 RC 资源——**安装器不执行候选 DLL 的 `DllMain`/TLS/导出**，只读资源。

### 1.4 一次性启动线程（阶段 A）

`RuntimeEntry.cpp` 的 DllMain 通过休眠检测后建一个**一次性**线程（`WorkerMain`），步骤是固定的：

1. `LoaderCore::InitEarly()`：`Logger::Init` + `VerifyHookApiTableProtection`（HookAPI 表必须落在只读页）
   + `PdataMatch::Init`（加载 sidecar）+ `Runtime::InitMinHook`；
2. `UiInject::ExtractResources()`：把内嵌的 FrontEnd UI 资源释放到 exe 目录；
3. `LoaderHooks::InstallAll()`：exe 域钩子。**`LoadDLL` 是必需项**（它失败会把本次已建的钩子全部回滚），
   `UnloadDLL` 是**可选项**（失败只放弃它一个，`LoadDLL` 照常留着——丢一个可选功能不等于丢全部）；
4. `UiInject::Install()`：主菜单 UI 注入钩，失败静默降级；
5. `LoaderUpdate::CheckAndApplyUpdate()`：runtime 级自更新检查（薄壳之外的第二道）；
6. `LoaderCore::LoadPluginsOf(PluginCategory::Global)`：扫描并加载 **Global 插件**。

这条线程**不常驻**：没有事件循环、没有 reconcile（见 §3.3）。此后一切都在游戏线程上由 detour 驱动。

### 1.5 阶段 A / 阶段 B

- **阶段 A（进主菜单前）**：上面那条线程。此阶段 GameCore 还没加载，Global 插件的 `OnLoad` 在这里跑；
  它们能做的取址/挂钩只涉及 exe 与常驻模块。
- **阶段 B（进对局时）**：引擎调用 `LoadDLL` → 我们的 detour（`LoaderHooks.cpp`）改写路径并调原函数，
  成功后 `LoaderCore::InitializeGameCorePhase()`：`AttachGameCore` → `InitializeLoader` →
  `hks::InitHavokScript` → `Localization::InitScript` → `EnsureScriptHooksInstalled` →
  加载 **GameCore 插件**。
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

### 2.2 LoadDLL / UnloadDLL 的编排（`LoaderHooks.cpp`）

`LoadDllDetour`：

1. `GetRuleSetName()` 为空 → 还没进游戏，原样透传；非 `EXPANSION_2` → 透传（只支持 XP2）；
2. 把官方 GameCore 的路径改写成我们 Mod 里的薄壳路径（`OfficialGameCoreRelPath` + `BuildOfficialPath`，
   薄壳文件不存在就透传原路径）；
3. 若 `IsInitialized()` 仍为真（说明 `UnloadDLL` 钩子没生效 / 没清场）→ 先 `ResetForReload()` 兜底；
4. 调原函数 `g_origLoadDLL(target)`；
5. `FreePendingPluginModules()`：这次调用可能顺带卸掉了旧的 GameCore，排队中的插件模块此刻才释放；
6. 成功 → `InitializeGameCorePhase()` + `LoadPluginsOf(GameCore)`；失败 → 区分"幂等短路"（读 exe 的
   `hModule` 槽判断模块是否已加载）与真失败，只记日志。

`UnloadDllDetour`：

1. `IsInitialized()` → `ResetForReload()`（清理 + 把 GameCore 插件模块**入队**）；
2. 调原函数 `g_origUnloadDLL()`——**引擎在这里卸掉 GameCore 映像连同它的 gameplay/ui Lua 环境**；
3. `FreePendingPluginModules()`：真正 `FreeLibrary` 那些插件模块。

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
9. `RemoveGameCoreDomainSiteRecords()`：写 teardown 窗口 + `ImageAddress::DetachGameCore()` → 放锁
   **排空在途共享 detour**（`g_activeSharedDetours` 归零）→ 重锁，**重扫站点表**摘记录：
   成功即 `MH_RemoveHook` + **erase 节点**；失败则打 `recordStale` 并拔掉 detour 槽。最后复位
   `g_origRegisterScriptData(/ForUI)`、16 个 PushMethods 槽位、清空 teardown 窗口；
10. 回到 detour，调 `g_origUnloadDLL()`，然后 `FreePendingPluginModules()`（见 §2.4）。

为什么是这个顺序：

- **第 5 步必须在第 7 步之前**：入口字节还原之后才谈得上"Free 插件不会留下入口跳向已释放代码的窗口"；
- **第 9 步重扫而不是沿用第 5 步的地址列表**：第 5～9 步之间还跑过插件卸载，而 `PushLuaMethods` 这类
  注册入口按设计不过域门，理论上仍可能往正在拆除的映像上装钩——重扫能一并收掉；
- **不再需要"补丁区间清账"**：唯一的补丁来源是插件的 `PatchImpl`，它已过正面域规则（§4.1），
  拆映像时不可能存在落在旧映像区间里的记录。

### 2.4 插件模块的释放时机

- `UnloadPluginByOwnerId` 与"未声明类别"的拒载路径都**只把句柄入队**（`g_pendingFreeModules`，
  由 `g_pendingFreeMutex` 保护）；
- `LoaderCore::FreePendingPluginModules()` 在两个 detour 里调用：`UnloadDllDetour` 的
  `g_origUnloadDLL()` **之后**、`LoadDllDetour` 的 `g_origLoadDLL()` **之后**；
- 于是"插件映像已释放、而它的 Lua 闭包还能被调用"这个前提不存在：gamecore 的 gameplay/ui Lua 环境
  是引擎卸载里拆的，闭包所在的 state 已经没了；
- 代价与边界：拒载的 GameCore 模块会一直映射到下一次 Load/Unload；Global 插件本来就永不卸载。

### 2.5 锁与锁序

| 锁 | 保护 | 备注 |
|---|---|---|
| `g_gameCoreTransitionMutex`（递归） | 阶段切换串行化 | 最外层 |
| `g_pluginLifecycleMutex`（递归） | `g_plugins`、各类注册表、槽位表、owner 探针 | 最常被重入 |
| `g_pushStateMutex` | PushMethods 的 16 个槽位 | 在 lifecycle 内层 |
| `Runtime::MinHookMutex()` | 站点表 + 所有 `MH_*` 调用 | 在 pushState 内层 |
| `g_captureMutex` | 站点上的捕获派发数据（`captureOuts`/`retiring`/`captureParamIndex`） | 最内层 |
| `ImageAddress::g_mutex` | 映像登记（base/size/id） | 叶子 |
| `g_scriptStateMutex` | ScriptGlobals 的两个注册表 | 叶子 |
| `g_pendingFreeMutex` | 待释放句柄队列 | 叶子 |
| `g_detourDrainMutex` + `g_detourDrainCv` | 等 `g_activeSharedDetours` 归零 | **等待时不持任何其它锁** |

固定顺序：`transition → lifecycle → pushState → MinHook → capture/ImageAddress`。
凡是"插件代码可能被调用"的地方（`OnLoad`/`OnUnload`/回调/`WaitAll`）都必须**先放掉 lifecycle 锁**。

### 2.6 日志

- Loader：`Logger::Init` → `%LocalAppData%\Firaxis Games\Sid Meier's Civilization VI\Logs\Civ6DllLoader_Loader.log`；
  进程内**首次打开截断、之后追加**（用 `Local\` 命名 mapping 记标记，且故意不 `CloseHandle`——
  否则 GameCore 被卸载时标记就没了），所以一份日志里能同时看到重载前后两代；
  薄壳另有 `Civ6DllLoader_Shell.log`；
- 排查时优先看的几行：`LoadDLL: ruleset=...`、`InstallAll: exe image=...`、
  `GameCore attached image=.. base=.. SizeOfImage=..`、`HookSite: installed hub stub ...`、
  `ResetForReload: ...`、`RemoveGameCoreDomainSiteRecords: erased N site node(s), marked recordStale=M`、
  `Plugin deactivated, module queued for free after engine GameCore unload`、
  `Plugin module freed after engine GameCore unload: <handle>`、`Plugin deactivated, module parked (kept mapped)`。

---

## 3. 插件模型

### 3.1 目录与类别判定

扫描（`common/ModScan.cpp`）：内容根 = 游戏目录 / `Documents\My Games\...\Mods` / Workshop，
每个根下找 `<mod>\Binaries\Win64\Plugins\<Global|GameCore>\*.dll`（`Win64Steam` 也兼容），
按文件名去重，再用 `common/EnabledMods.*`（读 `Mods.sqlite` 的启用集）过滤：**路径必须落在某个启用 Mod
的根下**（只比 GUID 不够，同一 GUID 可能有多份安装副本）。

类别判定（`Civ6DLLHookLoaderAPI.cpp:CategoryForPath`）：把路径规范化（全小写、`/`→`\`）后含
`\plugins\global\` → `Global`，**其余一律 `GameCore`**。注意默认方向：放到预期之外的位置会被当成
GameCore（每局真卸载 + 只能动 GameCore 映像）。

类别决定三件事：加载时机（阶段 A / 阶段 B）、生命周期（驻留 / 真卸载）、域门（哪半边地址空间可用）。

### 3.2 加载流程（`LoadPluginDllInternal`）

1. 拿 `g_gameCoreTransitionMutex` + `g_pluginLifecycleMutex`；
2. `GetModuleHandleExW(UNCHANGED_REFCOUNT, path)` 先看模块是否已驻留；没有再 `LoadLibraryExW`,
   用 `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`。`ownsRef` 标记引用是否归本次调用；
3. 句柄重复（同一模块已在跟踪表里）→ 释放自己拿到的引用并返回 false；
4. 找 `OnLoad` 导出；缺失 → 拒载（释放引用）；
5. 组装 `PluginEntry`（handle / path / stem 名 / `ownerId` = 规范化全路径 / category），
   `SetPluginState(Loading)`（同步 `PluginInFlight` 放行镜像）并 push 进 `g_plugins`；
6. `SetActivePluginContext(ownerId, handle)` → 放锁 → `CallOnLoadSafe(onLoad)`（SEH 包住）→ 清上下文 → 重新拿锁；
7. `OnLoad` 崩溃 → `QuarantinePluginByOwner`（§3.3），返回 false；
8. **类别声明强制**：`entry.kindDeclared` 为 false（没调 `HookAPI_IsCompatible` 的旧头文件插件）→ 记日志
   + 隔离回滚 + 摘表 +（GameCore 类别则入队待释放 / Global 则按 `ownsRef` 释放）+ 返回 false；
9. 有 `OnMessage` 导出 → 自动注册消息处理器；
10. `SetPluginState(Active)`，加载完成。

### 3.3 卸载 / 隔离 / 驻留

**崩溃隔离 `QuarantinePluginByOwner`**（只标记 + 回滚，**模块驻留不卸**）：
`SetPluginState(Quarantined)` → 注销消息 → `PluginInFlight::WaitAll` → `PatchRegistry::RevertAllFor` →
`RemovePluginHooks`（拔 detour 槽）→ `CleanupCaptureSitesForOwner` → `RemovePluginOwnedRegistrations`。
隔离后阶段 B 不会再重试它（状态不是 `Active`）。

**正常卸载 `UnloadPluginByOwnerId(ownerId, freeModule)`**：
`SetPluginState(Deactivating)` → 放锁 → 注销消息 → `WaitAll` → `OnUnload`（SEH）→
`PatchRegistry::RevertAllFor`（先 OnUnload 后回滚：OnUnload 可能还依赖自己的补丁）→
`RemovePluginHooks`（拔槽，绝不在插件卸载时物理摘 MinHook 记录）→ `CleanupCaptureSitesForOwner` →
`RemovePluginOwnedRegistrations` → 重锁 → 从 `g_plugins` 摘除 → 放锁 → `freeModule` 时**入队待释放**，
否则记"module parked"（驻留）。

- **Global 永远驻留**：只在启动时加载（禁用 Mod 需要重启），且游戏线程可能仍停在它某个 exe 域 detour 里；
  驻留的代价是插件静态状态跨会话保留，所以 `OnLoad` 必须可重入（重新注册它的钩/回调）。
- **GameCore 真卸载**：它的钩/补丁只允许落在当前 GameCore 映像内（§4.1），加上重载时整套 teardown，
  所以静态状态不会跨局残留。

### 3.4 插件 ABI：HookAPI 表与冻结前缀

- 表是 `const HookAPI g_hookApi`（`.rdata`，只读——插件写它会当场 AV，被 `CallOnLoadSafe` 接住）；
- **冻结前缀规则**（`common/HookAPI.h` 顶部）：只许在末尾 append；append **不** bump 版本；
  破坏前缀（删除/重排/改语义）必须 bump；兼容性最终由 `structSize` 判定；
- 当前 `CIV6_HOOK_API_VERSION = 1`：**预发布阶段**还没对外发过任何插件，所以删掉那 3 个入口
  （`GetCivilizationDescription` / `RegisterGameCoreReady` / `RegisterGameCoreTeardown`）时**没有**升版本号，
  1 是唯一出现过的值。首次对外发布之后再破坏前缀，才按规则递增；
- `HookAPI_IsCompatible(api)`：插件侧先调 `DeclarePluginKind`（先按 `structSize` 判断表够不够长），
  再做原有的版本/大小检查；loader 侧只保留版本/大小检查；
- 由此：**每个插件都必须在 `OnLoad` 开头调 `HookAPI_IsCompatible`**——它既是版本门，也是类别声明
  （不调 = 加载期拒载）。

### 3.5 类别门禁三层

1. **编译期**（`common/HookAPI.h` 底部）：插件在工程宏里定义 `CIV6_PLUGIN_GLOBAL` 或
   `CIV6_PLUGIN_GAMECORE`。Global 下把 8 个 GameCore 专属**成员名**重命名成自带解释的符号，
   于是"调用或取地址"都在编译期报「不是 HookAPI 的成员」；结构体字段一个没少、偏移一个没变。
   两个宏都没定义且不是 loader → `#error`；loader 侧靠 vcxproj 里的 `CIV6_HOOKAPI_BUILD_IMPL` 逃逸。
2. **加载期**（`DeclarePluginKindImpl` + `LoadPluginDllInternal`）：用 `g_activePluginModule`
   （取不到就返回地址 + `GetModuleHandleExW`）确定调用模块，比对"自述 kind vs 安装路径推出的类别"
   与 `apiVersion`，记账；`OnLoad` 返回后强制要求"已声明且一致"。
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

规则（**正面**规则，不是"不在 GameCore 里就算数"）：

- `GameCore` 类别：目标必须落在**当前 GameCore 映像**内（它唯一的合法域）；
- `Global` 类别：目标必须落在**某个已加载的非 GameCore 模块**内 —— exe、常驻系统 dll（user32/dxgi…）、
  插件自己的模块都算；**堆、`VirtualAlloc` 的 JIT 页、空闲地址、将来会被 GameCore 占用的地址一律拒绝**。

实现（`Civ6DLLHookLoaderAPI.cpp`）：`IsTargetOpenToCaller`（单点）/ `IsRangeOpenToCaller`（整段）/
`IsImageOpenToCaller`（image 参数）；模块判定用 `RangeInsideOneLoadedModule`——两端各自的
`GetModuleHandleExW(FROM_ADDRESS)` 返回同一模块句柄，即证明整段同属一个已加载模块（不解析 PE）。

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
`lua_State*`，所以两类插件都开放。导入在每次阶段 B 重新解析；缺失时 Lua API 降级，并停用 GameCore
插件加载（半可用的 Lua 对插件是崩溃源）。

### 4.4 其它

- 消息：`BroadcastMessage` / `RegisterMessageHandler` / `SendMessageTo`（§6.2）；
- `Log`、映像元数据 `IsImageLoaded` / `GetImageInfo`；
- 本地化：`LocalizationLookup` / `LocStringBytes` / `LocCreate` / `LocDestroy` / `LocLookup` /
  `LocPushArgument` / `LocToUtf8`——走独立模块 `Localization_FinalRelease.dll` 的导出；
- `MakeHash`：**已内化**为 loader 自己的原生 CRC32（raw，无最终异或，与官方 `GameCore::Utilities::MakeHash`
  逐位一致，并有编译期自检向量）；不再解析任何 GameCore 符号，任何时刻可算；
- `GetActiveLuaState`：读 exe 里脚本系统单例槽 → 活跃的 gamecore `lua_State`；对局前返回 null。

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
拔槽也不需要改写任何可执行字节；stub 一经生成**永不释放**（asmjit 的 JIT 分配器只能整体 release，
而且多个 stub 共用同一块）。

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
  排空在途共享 detour，再重扫站点表"摘记录 + erase 节点"；摘不掉的打 `recordStale`，下次同地址取站
  强制重建。

### 5.7 不变量与已知残留

| 项 | 现状 | 说明 |
|---|---|---|
| 站点 / stub 日常不释放 | 保持 | 日常"退役"只拔插槽；**只有 teardown 会 erase 节点**（依据：入口已还原 → stub 不可达） |
| stub 的 JIT 内存 | **回收不了** | asmjit 只能整体 release，且多 stub 共用块。要回收需改成自建 `VirtualAlloc`/`VirtualFree`（顺带可去掉 asmjit 依赖）——**未做** |
| `recordStale` 重建 | 保留 | 会把旧映像备份的 5 字节写进新映像同地址函数头；同 build 字节相同，换 GameCore 版本才有风险 |
| 换基址重载 | 现在会清 | teardown 会 erase 节点，所以只有"摘不掉"的残留会留下 |

---

## 6. 插件回调与 Lua / 事件数据流

### 6.1 PluginInFlight（在途登记与排空）

`PluginInFlight::Owner`：owner 的放行镜像 + 在途计数；`SetAllowed` 是镜像的**唯一写者**（只由
`SetPluginState` 调用）。守卫入口用 `Enter(owner, kind)`（先增量再检查、失败回滚）与 `ReleaseCount`；
卸载/隔离用 `WaitAll(owner, name)`：谓词是「本 owner 的在途计数 ≤ 本线程自己的深度」，5 秒未满足就
限次记日志但**继续等**（不放弃）。

被它守卫的入口：消息 handler、`RegisterScriptGlobals`（含 UI）、`GameEvent` 触发、`PushLuaMethods` 推送。
**不**被它守卫的：插件 detour（靠 teardown 顺序保证）、以及已经交给引擎的 Lua 函数指针。

### 6.2 消息总线（`Civ6MessageBus`）

按 owner 注册 handler、`Broadcast`、`SendMessageTo`、`UnregisterOwner`、`Clear`；handler 调用走
`PluginInFlight::Enter`（owner 已停用则直接跳过）；注销/清空在锁外 `WaitAll`。Loader 自己也注册了一个
`Loader` 处理器（`load-plugin` 遗留入口，保持兼容）。

### 6.3 ScriptGlobals（+ ForUI）

`RegisterScriptGlobals(fn)`（GameCore 专属）：登记进 `g_scriptGlobals`（UI 版本进 `g_scriptGlobalsUI`）→
`EnsureScriptHooksInstalled()` 在 `GameCore::Lua::Utility::RegisterScriptData(ForUI)` 上装共享钩 →
游戏初始化脚本时，detour 依次调用每个 `fn(L)`（SEH 隔离 + `PluginInFlight` 守卫），最后调原函数（跳板）。

### 6.4 PushLuaMethods

`RegisterPushMethodsTarget(name, sigType, symbol)` + `PushLuaMethods(name, methods[], count)`
（都是 GameCore 专属）：把目标名解析成游戏符号（如 `GameCore::Lua::IUnit::PushMethods`）→ 合并/去重/
冲突预检 → 装到站点（16 个槽位，loader 自己的 detour）→ 游戏调用该目标函数时，detour 把插件的 C 闭包
按 `exposedName` 写进游戏给的那张表；每个方法推送前走 `PluginInFlight::Enter`。
**没有"延迟登记"**：GameCore 未就绪时直接失败（跨代重装由插件在新一局自己重新注册）。

### 6.5 GameEvent

`RegisterGameEvent(name, pushFn)` / `TriggerGameEvent(name, payload)`（GameCore 专属）：注册只写 loader
自己的表（owner + name + pushFn）；触发走"内化"路径——取活跃 Lua state → `GameEvents[name].Call(...)`，
参数由插件的 `pushFn` **现压**（是 loader 在调它，所以能被 `PluginInFlight` 守卫）。引擎信号环桥接的旧
路径已删除。

### 6.6 Lua 环境划分与 HavokScript

- 游戏里**不是只有一个 Lua**：`frontend`（主菜单）与 `gamecore`（对局；内部再分 gameplay / ui）是不同
  的 `lua_State`。Loader 只碰 gamecore 侧：`GetActiveLuaState` 读的是 exe 里脚本系统单例槽指向的活跃 state；
- Lua VM 在 `HavokScript_FinalRelease.dll`（独立模块），loader 的所有 `Lua*` 原语都经它的导出；
- 谁把"插件的东西"放进 Lua：只有两条——`PushLuaMethods`（loader 把插件闭包塞进游戏的方法表）、插件自己
  在 `RegisterScriptGlobals` 回调里注册的全局/闭包。`GameEvent` 的 `pushFn` 不在 Lua 表里（loader 每次现调）；
- 因此"插件地址留在 Lua 表里"这件事，在 GameCore 专属 + §2.4 的释放顺序下不成问题：插件模块被释放时，
  那些 state 已经随 GameCore 一起没了；
- **未支持**：frontend 侧的 PushMethods（`kind=3` 现在被显式拒绝）。将来要做，需要"loader 派发器"式的 adapter，
  否则插件闭包可能活过 GameCore。

---

## 7. 映像解析与符号库

### 7.1 ImageAddress（映像登记）

`ImageAddress` 是"进程里哪些 PE 映像可用 + 怎么把 RVA 换成实址"的唯一入口：

- `HookImageId`：`1=ExeDx11`、`2=ExeDx12`、`3=GameCoreBase`、`4=GameCoreXP1`、`5=GameCoreXP2`；
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
  LZMA1 参数（preset 9|EXTREME、dict 16MB、lc3/lp0/pb2）必须与 runtime 的解码端一致。

### 7.3 PdataMatch（跨版本 RVA 矫正）

游戏更新后 GameCore 的 RVA 会变，而符号库里存的是**旧 RVA**（配旧 pdata 签名）。`PdataMatch` 负责把
`old_rva` 矫正成当前映像里的 `new_rva`：

- `Init(runtimeModule)`：读 sidecar（文件 → 资源）→ 解信封 → 逐模块建上下文；
- `BuildNewTable(imageId, target)`：解析目标映像的 `.pdata`（PE 异常目录），对每条算签名
  （`(begin_rva, size, unwind_hash)`，`unwind_hash` 是 FNV-1a64）→ 与 sidecar 里的旧表比对：
  **指纹一致 = 版本相同 → 恒等映射短路**（不做匹配）；否则走跨版本匹配；
- 结果可按 `CorrectRva` / `CorrectByName` / `CorrectVTableByName` 查询；`Fingerprint(imageId)` 作为缓存键，
  缓存在磁盘上（`LoadCache` / `SaveCache`），命中就省掉一次全量匹配；
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
- `HavokScript_FinalRelease.dll`：解析约 40 个 `hksi_lua*` / `hks*` 导出，作为所有 `Lua*` 原语的实现；
  **每次阶段 B 重新解析**（它跟着 GameCore 一起装卸）；缺导入 → Lua API 降级 + 停用 GameCore 插件加载。

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
| `DllLoader/DllLoader.vcxproj` | `GameCore_XP2_Shell_FinalRelease`（薄壳） | 转发导出 + 安装/自更新 + 拉起 runtime |
| `DllLoaderRuntime/DllLoaderRuntime.vcxproj` | `Civ6DllLoader.runtime`（Loader 本体） | 一切 hook / sidecar / HookAPI / 插件生命周期 |

两个工程都是 x64、C++20（`/std:c++20`）、`/utf-8`。关键预处理宏：

- `DllLoaderRuntime`：`ASMJIT_STATIC`（静态链接 asmjit）+ **`CIV6_HOOKAPI_BUILD_IMPL`**（声明"我是 loader 侧"，
  这样 `common/HookAPI.h` 的类别门禁不会 `#error`、也不会把成员名重命名）；
- 两者都有 `_CRT_SECURE_NO_WARNINGS` / `_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS`；
- Debug 配置下会有既存的 `LNK4075` / `LNK4098` 警告，属正常。

### 8.2 third_party 与链接依赖

| 组件 | 用途 |
|---|---|
| `third_party/asmjit_src`（+ `asmjit_build` / `asmjit_build_dbg`） | 生成站点 stub（唯一用途；**未**用在别处） |
| `third_party/hde` | MinHook 的长度反汇编器 |
| `third_party/lzma`（LzmaDec） | 解 sidecar 的 `C6XC` LZMA1 流 |
| `third_party/sqlite` | runtime 侧读 `Mods.sqlite`（启用 Mod 过滤） |
| 预编译 MinHook | `libMinHook.x64.lib`（在 `DllLoader/resources`） |

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
| `DllLoaderRuntime\Resources\Civ6DllLoader_FrontEndUI.{lua,xml}` | RCDATA 103/104，由 `UiInject::ExtractResources` 释放到 exe 目录 |
| `x64\<cfg>\Civ6DllLoader.runtime.dll` 的版本资源 | RCDATA **105**（`CIV6_DLL_LOADER_VERSION_RESOURCE_ID`）：安装/自更新只读它，不执行候选 DLL 的 `DllMain`/TLS/导出 |

---

## 9. 已知取舍与残留风险

以下都是**有意识地接受**的取舍（不是遗漏）。做改动前先看这一节：很多"看起来是 bug"的行为是设计结果。

| # | 现象 | 原因 / 机制 | 影响 | 状态 |
|---|---|---|---|---|
| 1 | 站点 stub 的 JIT 内存永不回收 | asmjit 的 `CodeHolder` 只能整块释放，做不到逐站点回收 | 每次 reinstall 累积几十字节虚拟内存，量级可忽略 | 接受。若将来站点数量爆炸，可把 stub 改成"每站点 `VirtualAlloc`/`VirtualFree`"，顺带去 asmjit 依赖 |
| 2 | `recordStale` 重建时，可能把**旧映像**备份下来的字节写进**新映像**的同地址 | 旧记录只有 5 字节原始字节，不含版本信息 | 同版本 GameCore 完全一致；跨版本才可能写坏 | 接受（同一次游戏版本内 GameCore 布局稳定） |
| 3 | Global 插件永不卸载 | 域模型：Global 钩的是常驻 exe | 插件静态状态跨对局、跨读档存活 | 约定：Global 插件的 `OnLoad` 必须幂等，不得假设"只执行一次" |
| 4 | 插件自建线程 / 前端 Lua 闭包不受 loader 保护 | 这些不在 HookAPI 覆盖范围内 | 卸载瞬间的并发调用会踩空 | 文档告知；不做"线程登记"就无法根治 |
| 5 | 域门只装在"换地址 / 给地址"这类入口 | 设计原则是**按目标地址授权**，不是限制插件行为 | 注册、回调类入口不设门 | 有意：边界靠"GameCore 专属入口 + 域规则"共同成立 |
| 6 | teardown 依赖"有在途 GameCore 调用就已经完蛋"这个弱假设 | 引擎自己 `UnloadDLL` 同样会 unmap 那块内存 | 做不到绝对安全 | 接受：与引擎原生行为等价 |
| 7 | exe 域的站点永不摘钩 | exe 常驻，摘了反而引入额外状态 | 钩子活到进程退出 | 有意 |
| 8 | 开关 Mod 不生效，必须重启 | 没有 reconcile 通路 | 操作体验 | 有意：状态一致性优先于便利 |
| 9 | UI 注入依赖特征码，匹配失败静默降级 | 游戏更新改了目标代码 | 面板不出现（日志有记录），其余功能正常 | 接受 |
| 10 | 数据槽定位依赖 AOB 兜底指令序列 | 编译器 / 游戏更新 | 定位失败返回 0，对应功能降级 | 接受（有日志） |

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
| 薄壳（shell） | `GameCore_XP2_Shell_FinalRelease.dll`：只做转发 + 安装/自更新 + 拉起 runtime |
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
5. 编译 loader 侧需要 `CIV6_HOOKAPI_BUILD_IMPL`（工程里已定义）；
6. **不要**动已有字段的顺序，也不要改 `apiVersion`（见 10.4）。

#### 加一个内部钩（loader 自己用）

- exe / 常驻模块：直接 `MH_CreateHook` + `MH_EnableHook`（域稳定，无需站点模型）；
- GameCore：走站点模型（`InstallLoaderDetourOnSite` 之类），这样 teardown 能统一摘掉；
- 需要读参数 / 写返回值：用捕获插槽，不要自己写第二套。

#### 加一个插件类别

1. `common/HookAPI.h` 的 `CIV6_PLUGIN_KIND_VALUE_*` 加值（3 起是保留位）；
2. 加载期映射：`DeclarePluginKind` 表 + `CategoryForPath` 的目录名判断；
3. 域规则：`IsTargetOpenToCaller` 里加一条"该类别能碰哪块内存"的**正向**规则；
4. teardown 策略：想清楚它的模块什么时候能 `FreeLibrary`（现在只有 GameCore 类别会排队释放）。

### 10.4 改 ABI 的规则

- **只追加**：`HookAPI` 是"冻结前缀"。新增函数只能追加到尾部，旧插件凭 `structSize` 继续工作，`apiVersion` 不动；
- **破坏前缀就要升版本**：删字段 / 改顺序 / 改语义 → 提升 `CIV6_HOOK_API_VERSION`，旧插件会被拒（而不是崩）。
  例外只有一个：**首次对外发布之前**不递增（现在就是这种情况，值停在 `1`）；
- **删除枚举值不算前缀破坏**：不需要再升版本；
- 改完必须：两个配置都重编 + 跑一遍 `真机测试清单.md`。

### 10.5 文档维护约定

- 本文件是**唯一的总架构文档**，"为什么这样设计"写在这里；
- 反编译原文、站点地图、测试清单放 `docs/analysis/`，只增不改语义；
- 代码里的"为什么不这样写"注释应指向本文件对应小节，而不是复述一遍。



