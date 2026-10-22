# Civ6DllLoader 功能目录（API + UI 注入）

> 中文 | [English](FEATURE_CATALOG.en.md)

一页看清 loader 对外提供哪些能力：**插件 API**（`HookAPI` 的 80 个入口）与 **UI 注入**（主菜单界面）。

- 权威来源：入口清单在 [`common/HookAPI.h`](../common/HookAPI.h) 的 `HOOK_API_LIST`（X-macro，唯一来源）。
- 用法与示例：插件侧请对照 [Plugin Development Guide](https://github.com/sociometry/Civ6DllMods/blob/main/docs/PLUGIN_GUIDE.md)（§6 讲 API、§7 讲 UI 注入）。
- 架构与实现细节：[ARCHITECTURE.md](ARCHITECTURE.md)。

---

## 0. 一分钟速览

| 能力面 | 数量 | 适用插件 | 用途 |
| --- | --- | --- | --- |
| 取址与映像查询 | 9 | 两者 | 把符号名 / RVA / AOB / 虚表槽变成可调用地址 |
| 挂钩与补丁 | 3 | 两者 | 装 detour、改字节、撤销补丁 |
| 插件间消息 | 3 | 两者 | 主题式广播与定向发送 |
| Lua 原语 | 45 | 两者 | 直接操作 `lua_State`，读写表、调用、引用管理 |
| 脚本环境注册与对象扩展 | 4 | 分域 | 往 gameplay / UI / 引擎各环境挂全局，给引擎 Lua 对象挂方法 |
| 事件总线 | 2 | GameCore | 注册并触发自定义 GameEvent |
| 本地化 | 7 | 两者 | 查 LOC key、拼参数、转 UTF-8 |
| 工具与诊断 | 7 | 两者 | 日志、哈希、符号库状态、调试开关、玩家对象 |
| **合计** | **80** | | |
| **UI 注入** | 1 套机制 | 无需插件 | `FrontEndUI_*.xml` + `.lua` 免编译挂主菜单 |

> 类别说明：**两者** = `kCommon`，Global 与 GameCore 都可用；**GameCore** = 仅 `CIV6_PLUGIN_GAMECORE` 编译可见；**Global** = 仅 `CIV6_PLUGIN_GLOBAL` 编译可见。

---

## 1. 取址与映像查询（9）

把游戏里的函数 / 数据定位出来，是所有 hook 与 patch 的前置步骤。

| 入口 | 签名 | 类别 | 说明 |
| --- | --- | --- | --- |
| `IsImageLoaded` | `bool(HookImageId image)` | 两者 | 目标映像是否已加载 |
| `GetImageInfo` | `bool(HookImageId image, HookImageInfo* outInfo)` | 两者 | 取基址 / 映像大小 |
| `ResolveByRva` | `void*(HookImageId image, uintptr_t rva, size_t span)` | 两者 | RVA 解析，走 `PdataMatch` 跨版本矫正 |
| `ResolveByRvaEx` | `void*(image, rva, span, HookImageSection section)` | 两者 | 同上，可限定段；**不**做 pdata 矫正 |
| `ResolveByName` | `void*(HookImageId image, const char* name)` | 两者 | 按符号名（demangled / mangled 均可）解析 |
| `ResolveByPattern` | `void*(image, const char* pattern, HookImageSection section, uint32_t index)` | 两者 | AOB 特征码搜索，`??` 通配，`index` 从 1 起 |
| `ResolveByVTable` | `void*(image, const char* vtableSymbol, uint32_t index)` | 两者 | 按 vtable 名 + 槽序号（0 起）取虚函数 |
| `RegisterGlobalCapture` | `bool(void* providerAddress, uint32_t paramIndex, void** out)` | 两者 | 捕获某函数第 N 个**整数**参数（rcx/rdx/r8/r9） |
| `UnregisterGlobalCapture` | `bool(void* providerAddress, void** out)` | 两者 | 撤销上面那条订阅（只摘订阅，不摘钩） |

`HookImageId` 运行期实际可用：`kHookImageExeDx11` / `kHookImageExeDx12` / `kHookImageGameCoreXP2`。

**典型链路**：`ResolveByName` 拿函数地址 → `InstallHook` 装钩；数据槽则用 `ResolveByPattern` + `Dispatch` 或 `RegisterGlobalCapture` 取。

---

## 2. 挂钩与补丁（3）

| 入口 | 签名 | 类别 | 说明 |
| --- | --- | --- | --- |
| `InstallHook` | `bool(void* targetFunc, void* detour, void** original)` | 两者 | 装 MinHook detour，`original` 拿跳板用于调原函数 |
| `Patch` | `bool(void* target, const void* bytes, size_t len)` | 两者 | 写原始字节（按 target 分层的 owner 栈） |
| `Unpatch` | `bool(void* target)` | 两者 | 撤销**自己**的补丁（只允许撤栈顶） |

**硬约束**：

- 同一个地址**不能既装钩又打补丁**，两个方向都会被拒绝（MinHook 与补丁各存一份「原始字节」会互相覆盖）。
- Loader **不自动回滚补丁**：隔离 / 卸载后补丁会留在游戏里，需要撤销请在 `OnUnload` 里自己调 `Unpatch`。
- 装钩前请确认目标 32 字节窗口内没有别人的钩子或补丁。

---

## 3. 插件间消息（3）

| 入口 | 签名 | 类别 | 说明 |
| --- | --- | --- | --- |
| `BroadcastMessage` | `void(const char* topic, const void* data, size_t len)` | 两者 | 主题广播 |
| `RegisterMessageHandler` | `bool(MessageHandlerFn handler)` | 两者 | 注册处理器，owner 取 handler 所在插件模块 |
| `SendMessageTo` | `void(const char* pluginName, const char* topic, const void* data, size_t len)` | 两者 | 定向发给某个插件 |

消息在**游戏线程**派发；handler 地址必须落在 Loader 跟踪的插件模块内。

---

## 4. Lua 原语（45）

直接操作 `lua_State`。绝大多数是 `HavokScript_FinalRelease.dll` 导出的薄封装，**与 GameCore 无关**，两类插件都可用；参数里的 `void* L` 就是调用方自己传进来的 state。

### 4.1 栈与类型（18）

| 入口 | 说明 |
| --- | --- |
| `LuaGetTop` / `LuaSetField` / `LuaGetField` | 栈顶下标、写/读表字段 |
| `LuaPop` / `LuaPushValue` / `LuaPushNil` | 栈操作 |
| `LuaType` / `LuaIsNumber` / `LuaIsUserData` | 类型判断 |
| `LuaToNumber` / `LuaToInteger` / `LuaToBoolean` / `LuaToCFunction` / `LuaToUserData` | 取值转换 |
| `LuaPushInteger` / `LuaPushNumber` / `LuaPushBoolean` / `LuaPushLightUserData` | 压入标量 |

### 4.2 表操作（7）

| 入口 | 说明 |
| --- | --- |
| `LuaCreateTable` / `LuaNewGlobalTable` | 建表 / 建全局表 |
| `LuaGetTable` / `LuaSetTable` | 按栈上 key 读写 |
| `LuaRawGetI` | 按整数下标读数组元素 |
| `LuaObjLen` | 序列长度（拿不到字符串键） |
| `LuaNext` | 遍历哈希表（`lua_next` 语义，value 需调用方自己弹） |

### 4.3 调用与异常（4）

| 入口 | 说明 |
| --- | --- |
| `LuaCPcall` | 受保护的 C 调用，返回状态码 |
| `LuaPcall` | 受保护的 Lua 调用 |
| `LuaDoString` | 执行一段 Lua 源码 |
| `LuaError` | `luaL_error`：**raise 且不返回**（长跳转），不要在 Loader 的回调帧里调用 |

### 4.4 引用与 C 闭包（5）

| 入口 | 说明 |
| --- | --- |
| `LuaRef` / `LuaUnref` | 引用注册与释放（支持 registry / 环境 / globals 伪索引） |
| `LuaPushNamedCClosure` / `LuaPushCFunctionField` | 挂 C 闭包 / 给表挂 C 函数字段 |
| `LuaCheckPlayerId` | 校验并规整 playerId 参数 |

### 4.5 参数校验与格式化（6）

| 入口 | 说明 |
| --- | --- |
| `LuaCheckInteger` / `LuaCheckNumber` / `LuaCheckLString` / `LuaCheckTable` | 参数检查（类型不符会 raise） |
| `LuaOptInteger` | 带默认值的可选整数 |
| `LuaPushFString` | 格式化字符串入栈 |

### 4.6 调试钩子（5）

| 入口 | 说明 |
| --- | --- |
| `LuaSetHook` / `LuaGetHook` / `LuaGetHookMask` / `LuaGetHookCount` | `debug.sethook` 系列封装 |
| `LuaOpenDebug` | 打开 debug 库 |

> **线程约束**：Lua 状态非线程安全，全部 Lua 原语**只能在游戏线程调用**。
> `LuaError` / `LuaCheck*` 在类型不符时会 raise，会跳过 C++ 析构 —— 不要在登记类回调帧里用。

---

## 5. 脚本环境注册与 Lua 对象扩展（4）

前三个入口往不同 Lua 环境注入全局模块，只差「挂到哪个环境、何时执行」；`PushLuaMethods` 则是给引擎已有的 Lua 对象挂方法。

| 入口 | 签名 | 类别 | 挂到哪 | 生命周期 |
| --- | --- | --- | --- | --- |
| `RegisterGlobalScript` | `void(ScriptGlobalsFn fn)` | **Global 专属** | exe 的**每一个**脚本环境（主菜单 / 选项 / 对局…） | 每个环境各跑一次，环境重建后重跑 |
| `RegisterGameCoreScriptForGamePlay` | `void(ScriptGlobalsFn fn)` | **GameCore 专属** | GameCore 的 gameplay Lua | 每局重建，退局失效 |
| `RegisterGameCoreScriptForUI` | `void(ScriptGlobalsFn fn)` | **GameCore 专属** | GameCore 的 UI 脚本 Lua | 同上（与 gameplay 不是同一个 state） |
| `PushLuaMethods` | `HookApiPushMethodsResult(const char* pushMethodsSymbol, int sigType, const LuaMethodInfo* methods, uint32_t count)` | **GameCore 专属** | 给引擎已有的 C++ Lua 对象批量挂方法（如 `IUnit`、`IQuestsManager`） | 随对局重建，需在每局的 `OnLoad` 重新挂 |

**选型**：常驻功能用 `RegisterGlobalScript`；只在对局内生效的功能用 GameCore 那几个。回调里请**每次往传入的 L 挂**，不要缓存第一次的 `L`。

---

## 6. 事件总线（2，GameCore 专属）

| 入口 | 签名 | 说明 |
| --- | --- | --- |
| `RegisterGameEvent` | `bool(const char* name, GameEventPushFn pushFn)` | 登记一个可被 Lua 侧接收的自定义事件；`pushFn` 负责把参数压栈 |
| `TriggerGameEvent` | `bool(const char* name, const void* payload)` | 触发事件，`payload` 原样交给注册时的 `pushFn` |

事件名最长 95 字节。`pushFn` 里可以用 4.1–4.2 的原语压任意类型、任意个数的参数。

**仅游戏线程可调用**；Loader 内部负责锁协议、`GameEvents[name].Call` 与栈清理。

---

## 7. 本地化（7）

```c
void* loc = api->LocCreate();
api->LocLookup(loc, "LOC_TECH_POTTERY_NAME");
api->LocPushArgument(loc, "42");
const char* text = api->LocToUtf8(loc);
api->LocDestroy(loc);
```

| 入口 | 说明 |
| --- | --- |
| `LocalizationLookup` | 一次性查 key 到输出缓冲 |
| `LocCreate` / `LocDestroy` | 创建 / 释放查询上下文 |
| `LocLookup` | 在上下文里查 key |
| `LocPushArgument` | 追加格式化参数 |
| `LocToUtf8` | 取 UTF-8 结果 |
| `LocStringBytes` | 单个 LocString 的字节容量常量 |

---

## 8. 工具与诊断（7）

| 入口 | 签名 | 类别 | 说明 |
| --- | --- | --- | --- |
| `Log` | `void(const char* format, ...)` | 两者 | 写 loader 日志（与所有插件共用同一文件） |
| `IsDebugLogEnabled` | `bool(void)` | 两者 | `config.ini` 的 `ENABLE_DEBUG_LOG`，给热路径日志上闸 |
| `MakeHash` | `uint32_t(const char* str)` | 两者 | 与官方 `GameCore::Utilities::MakeHash` 逐位一致的 CRC32 |
| `GetSymbolDbState` | `HookApiSymbolDbState(HookImageId image)` | 两者 | 符号库对该映像的匹配状态（5 态） |
| `GetSymbolDbMatchRatio` | `double(HookImageId image)` | 两者 | 跨版本匹配率，仅 `CrossVersion` 下有意义 |
| `GetMainLuaState` | `void*(void)` | 两者 | 引擎**进程级**主 Lua VM，换局不失效 |
| `GetPlayer` | `void*(int playerId)` | **GameCore 专属** | 取玩家对象（对局内） |

`GetSymbolDbState` 的五个取值：`NoContext` / `NotReady` / `BuildFailed` / `Identical` / `CrossVersion`。
**建议**：依赖硬编码旧 RVA 之前先查这个状态，`BuildFailed` 时整体降级而不是半残运行。

---

## 9. UI 注入：主菜单界面（无需编译 DLL）

除了 C++ 插件，loader 还提供一条**纯文件**的 UI 扩展路径：给主菜单加面板、按钮、弹窗。

### 9.1 最小用法

```text
MyAwesomeMod/
  MyAwesomeMod.modinfo
  UI/FrontEnd/
    FrontEndUI_MyMod.xml     ← 界面定义
    FrontEndUI_MyMod.lua     ← 逻辑，与 xml 同名同目录
  Binaries/Win64/
    GameCore_XP2_Shell_FinalRelease.dll
    Civ6DllLoader.runtime.dll
```

放进 Mod 目录即可，**不用编译、不用 `OnLoad`、不用 `CIV6_PLUGIN_*` 宏**。

### 9.2 命名与识别规则

| 规则 | 说明 |
| --- | --- |
| 前缀必须是 `FrontEndUI_` | Loader 的识别标志，大小写不敏感 |
| 扩展名必须是 `.xml` | 同目录同名的 `.lua` 会自动一起加载 |
| 前缀后至少还要有一个字符 | `FrontEndUI_.xml` 不合法 |
| 必须在**已启用** Mod 的目录树里 | 递归最多 8 层，无权限的子目录跳过 |
| 相对路径唯一 | 两个 Mod 里相对路径相同的界面只加载一份 |

### 9.3 与游戏原生机制的关系

- **不需要**在 `.modinfo` 里写 `<ImportFiles>`；Loader 只按文件名扫描，写了也不生效、不碍事。
- **不支持条件加载**：`.modinfo` 里的 `criteria` 不参与判断。需要条件显示就让它总是注入，在 `.lua` 里 `SetHide(true)`。
- **只覆盖主菜单**。对局内界面仍走游戏原生的 `AddUserInterfaces` + `ReplaceUIScript`。

### 9.4 排查

进主菜单后看 `Civ6DllLoader_Loader.log`，搜 `UiInject:`：

```text
UiInject: 发现 2 个 Mod UI
UiInject: context 已加载 (FrontEndUI_MyMod)
```

| 现象 | 原因 |
| --- | --- |
| 没有 `发现 N 个 Mod UI` | Mod 未被判为启用，或扫描整体失败 |
| 有计数但没有自己的文件 | 前缀 / 扩展名不合规，或放在未启用的 Mod 里 |
| 有 `context 已加载` 但不显示 | 界面自身（XML 布局或 Lua 没显示它） |

更细的说明见 Plugin Development Guide 第 7 章。

---

## 10. 能力边界（先看这里，能省很多时间）

| 做不到 | 说明 |
| --- | --- |
| 改游戏规则数值 | 那是数据库层的事，不需要 loader |
| 在任意线程调 Lua | 全部 Lua 原语仅限游戏线程 |
| 自动回滚补丁 | Loader 不回滚，需插件自己在 `OnUnload` 撤销 |
| 给对局内 UI 注入 | 只支持主菜单，对局内用原生 UI 机制 |
| 加载无版本资源的插件 | 插件 DLL 必须带 `VERSIONINFO`，否则拒载 |
| 同时用 Global 与 GameCore 专属入口 | 编译期就不可见，需按域拆分模块 |

---

## 11. 相关文档

| 文档 | 内容 |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 架构总览：启动链、生命周期、插件模型、挂钩子系统 |
| [PLUGIN_GUIDE](https://github.com/sociometry/Civ6DllMods/blob/main/docs/PLUGIN_GUIDE.md) | 插件开发指南：工程配置、取址模型、API 用法、UI 注入、FAQ |
| [`common/HookAPI.h`](../common/HookAPI.h) | 入口清单与全部类型定义的唯一来源 |
| [README](../README.md) | 基本运作原理与核心特性 |

