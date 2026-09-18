# Civ6DllLoader 代码审查报告

审查日期：2026-09-18。配套文档：[代码阅读指南](CODE_READING_GUIDE.md)。

## 1. 结论与边界

**目前不能得出“代码没有大问题”的结论。** 本次整理出 9 项需要处理的发现，其中 6 项用调用当前生产实现的最小探针复现。优先处理地址解析失去保护、Hook/Patch 仲裁遗漏、插件模块引用所有权、更新失败恢复这四类问题，再验证真实游戏内的卸载时序。

同时，现有代码已经包含有价值的保护：owner 按加载代隔离、消息旧快照门禁、回调锁外执行与排空、安装 detour 前发布 original、GameCore 入口停用和延迟释放插件 DLL、静态探测运行时候选等。生命周期自测已通过。这些证据支持各自覆盖的局部性质，不能替代整条卸载链的正确性证明。

### 快照与审查范围

- HEAD：`7d80611`。实际依据是**工作区源码**，包含用户已有的暂存修改，并非只审查 HEAD。
- 开始时已有 10 个暂存文件：API 实现、消息总线 `.cpp/.h`、`LoaderCore.h`、`LoaderHooks.cpp`、`PluginInFlight.cpp/.h`、`ARCHITECTURE.md`、生命周期自测及运行脚本。本次保留这些修改。
- 重点追踪两个工程的自有运行时代码：入口、安装更新、插件发现、生命周期、Hook/capture/Patch、消息、Lua/事件/UI、映像及 sidecar 解析；对照 ABI、资源和项目配置。
- 工具部分阅读 IDA 导出脚本、Rust 查询工具，并重点检查 `symdb.py` 的格式、生成、校验和部署路径；没有跑完整符号生产线。
- 未执行游戏、未安装到游戏目录、未验证具体游戏版本、未逐项反编译 160 个薄壳转发目标、未审计预编译库及辅助 EXE 的二进制实现。第三方 SQLite/LZMA/hde/asmjit 不属于本轮完整源码审计范围。
- 本轮新增两份文档，并修改 README 入口与文档忽略规则；未创建 Git 提交，运行时修复建议尚未实施。临时探针和构建产物放在被忽略的 `tools/out/code-review-20260918/`。

作为快照校验，`DllLoaderRuntime/Civ6DLLHookLoaderAPI.cpp` 的 SHA-256 为：

```text
0545BB3D47FB212632269B697A959213EC7ED03D637351BAF6DB354EB2F8AD16
```

下文行号对应这次快照；代码更新后请以函数名定位。

## 2. 发现一览

“高”表示在所述触发条件下可能错误修改/调用代码、提前卸载模块，或破坏可用安装；不表示日常流程必然触发。“中”表示边界或失败路径存在明确缺口。“实测”是复现不期望行为，**不是安全测试通过**。

| 编号 | 优先级 | 发现 | 证据 |
| --- | --- | --- | --- |
| F1 | 高 | 无符号上下文时，旧 RVA 解析静默退回原始地址 | 实测 + 静态调用链 |
| F2 | 高 | Hook/Patch 冲突检查没有覆盖 capture、内部钩和全部修改范围 | capture 路径实测，其余静态 |
| F3 | 高 | 借用的插件模块句柄失去引用所有权信息，后续会被释放 | 静态调用链 + Win32 契约 |
| F4 | 高 | `ReplaceFileW` 部分失败后仍假定旧文件在原路径 | 静态调用链 + Win32 失败语义；未注入实测 |
| F5 | 中 | EXE 无上下文回退忽略 AOB 的第 N 个命中参数 | 实测 |
| F6 | 中 | 段相对 RVA 没有检查段内跨度和加法溢出 | 段越界实测；溢出分支静态 |
| F7 | 中 | sidecar 虚表槽读取只限制到文件末尾，未限制到声明的槽表末尾 | 畸形模块描述实测 |
| F8 | 中 | 补丁回滚遇到页保护失败就丢弃记录，可能遗留无法恢复的补丁 | 实测 |
| F9 | 中 | 符号工具 `all` 在校验前覆盖交付资源 | 静态控制流 |

## 3. 各项发现与建议

### F1：没有上下文时把旧 RVA 当作当前 RVA

位置：[Civ6DLLHookLoaderAPI.cpp](../DllLoaderRuntime/Civ6DLLHookLoaderAPI.cpp) `ResolveByRvaCore`，853–872；`AttachGameCore`，3228 起。另见 [RuntimeEntry.cpp](../DllLoaderRuntime/RuntimeEntry.cpp) `InitEarly` 对 fail-closed 的说明。

`effectiveRva` 初始等于输入 `rva`。只有 `HasContext(image)` 为真才调用 `CorrectRva`；否则直接进入 `ImageAddress::ResolveByRva`。没有上下文与“有上下文但矫正失败”因此具有不同安全行为。GameCore 挂接也不以该模块必须有符号上下文为前提。

**触发：** sidecar 缺失、解析失败或合法容器缺少目标模块，而插件继续使用基准版本旧 RVA。游戏更新后，这个数仍可能落在映像范围内，却指向另一个函数或数据。

**复现：** 在没有初始化 sidecar 的测试 EXE 中，调用真实 `ResolveByRvaImpl(image, 0x1000, 1)`，结果等于当前模块 `base + 0x1000`，没有拒绝。fixture 将 EXE 登记为有效 Global owner，仅用于满足入口的身份检查。

**建议：** 将“旧坐标需要矫正”和“已知当前坐标的原始解析”分开；前者无上下文时返回失败，后者保留显式入口。Loader 自身已知 PE 锚点的特例应在内部表达，避免外溢为所有插件的默认行为。

**修复验收：** 分别覆盖 sidecar 缺失、模块缺失、建表失败、有效 identity、成功矫正五种情况；前两项不得再返回看似可用的旧地址。

### F2：字节修改仲裁不完整

位置：[Civ6DLLHookLoaderAPI.cpp](../DllLoaderRuntime/Civ6DLLHookLoaderAPI.cpp) `InstallHookImpl` 682、`InstallLoaderDetourOnSite` 610、`RegisterGlobalCaptureCore` 1166、`OverlapsHookPrologue` 664、`HookPatch` 2970；[LoaderHooks.cpp](../DllLoaderRuntime/LoaderHooks.cpp)、[UiInject.cpp](../DllLoaderRuntime/UiInject.cpp) 的直接 MinHook 安装路径。

`InstallHookImpl` 会拒绝与补丁账本重叠的入口；capture 与 Loader 共享站点安装没有同等前置检查。反向的 `HookPatch` 只遍历 `g_hookSites` 中启用的站点，不能覆盖通过其它路径直接创建的 LoadDLL/UnloadDLL/UI 钩子。另外，仲裁窗口从 `target` 开始，未包含可能由 MinHook 使用的入口前 hotpatch 区域。

**复现：** 先用真实 `HookPatch` 在 fixture 函数入口登记 1 字节补丁，再调用 `RegisterGlobalCaptureImpl`。两次调用都成功。为避免执行损坏入口，探针写入的值与原字节相同，且装钩后不调用该目标；冲突账本与接受行为已经足以证明遗漏。

**影响：** 若补丁实际改变内容，MinHook 可能将已补丁的字节当成原始内容；先 Unpatch 又可能覆盖仍启用的跳转。随后卸载顺序会决定最终留下哪一种错误字节状态。

**建议：** 在统一的站点/修改入口集中仲裁，把所有直接 MinHook 入口纳入登记。仲裁范围应覆盖实际可能改写的字节，包含入口前区域，并保持检查与安装处于同一事务。

**修复验收：** 对普通 detour、capture、Loader 共享钩、三个 EXE 直接钩，分别测试“先 Patch 后 Hook”和相反顺序；额外测 hotpatch 区重叠、停用后重用及撤销顺序。

### F3：模块句柄的借用与拥有混在一起

位置：[Civ6DLLHookLoaderAPI.cpp](../DllLoaderRuntime/Civ6DLLHookLoaderAPI.cpp) `PluginEntry` 51、`LoadPluginDllInternal` 3304–3313 / 3389–3398、失败隔离 3427–3430、`UnloadPluginAt` 3619–3623、`FreePendingPluginModules` 98–105。

加载函数先用 `GetModuleHandleExW(UNCHANGED_REFCOUNT, path, ...)` 取已驻留模块。成功时 `ownsRef=false`，但正式加入 `PluginEntry` 后没有保存该标志。GameCore 正常卸载及部分 OnLoad 失败路径均把句柄排队，最终无条件 `FreeLibrary`。

**触发：** 某 DLL 已由另一个模块或依赖关系加载，但尚未由本 Loader 记录。Loader 接纳这个借用句柄；卸载 GameCore 时却减少别人的引用。反过来，Global 插件若只借用句柄，外部拥有者释放后，Loader 保存的回调也没有自己的引用保证其继续映射。

`UNCHANGED_REFCOUNT` 不增加引用，Microsoft 明确要求不要把这种借用句柄交给 `FreeLibrary`，否则可能过早解除映射。依据：[GetModuleHandleExW 文档](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)。

**建议：** 每个被接纳的插件都应有清楚的自有模块引用；若要复用 Loader 自己保留的驻留引用，须显式转移所有权并区分它和外部预加载模块。重复记录检查、失败回滚、park 与待释放队列应共用同一规则。

**修复验收：** 测试外部预加载、首次加载、重复候选、Global 驻留复用、GameCore 重载以及 OnLoad 失败；每次释放只能抵消 Loader 自己取得的引用。本项尚未制作真实预加载插件集成测试。

### F4：更新失败后的文件位置假设不成立

位置：[RuntimePackage.cpp](../common/RuntimePackage.cpp) `PublishStaged`，147–190，尤其 165–178。

代码先尝试 `ReplaceFileW(installed, staged, backup, ...)`。失败后统一执行 `MoveFileW(installed, backup)`，并注释假定 backup 仍不存在。

但 `ERROR_UNABLE_TO_MOVE_REPLACEMENT_2`（1177）允许出现以下状态：旧 installed 已移动到 backup，replacement 仍位于原 staged 路径。此时 fallback 第一步失败，代码删除 staged 后返回，未尝试将 backup 恢复为 installed。下一次启动可能没有预期的运行时代理。依据：[ReplaceFileW 文档的失败状态](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew)。

此外，即便进入传统两步改名路径时初态正确，两次改名之间仍有 installed 不存在的中断窗口。因此不能把整个实现概括为始终原子发布。

**建议：** 根据错误码及实际文件状态恢复，恢复完成前保留可用 staged/backup；为“installed 缺失、backup 存在”建立明确处理策略。不要在全部 `ReplaceFileW` 错误后使用相同的文件位置假设。

**修复验收：** 注入成功、1175/1176/1177、文件占用、访问拒绝、第二次改名失败和恢复失败；检查每个步骤后 installed/staged/backup 的组合。应在独立临时目录与测试 DLL 上做，不需要真实安装游戏。

### F5：AOB 回退丢失命中序号

位置：[Civ6DLLHookLoaderAPI.cpp](../DllLoaderRuntime/Civ6DLLHookLoaderAPI.cpp) `ResolveExeTarget`，3193–3212；[LoaderHooks.cpp](../DllLoaderRuntime/LoaderHooks.cpp) `kExeGetRuleSet`，49；[HookAPI.h](../common/HookAPI.h) `HookScanPatternNth`。

有符号上下文或匹配锚点时使用 `ResolveByHookInfo`，会处理 `entry.index`。无上下文且 PE 不匹配时直接调用 `ResolveByPattern`，只取首个结果。

**复现：** fixture 中构造重复模式，令 `index=2`，分别确定第一、第二个不同命中。真实 `ResolveExeTarget` 返回第一个。生产 `kExeGetRuleSet` 明确设置了 `index=2`，故这个参数不是未使用的接口装饰；选错相似 getter 可能使规则集判断错误。

**建议与验收：** 所有回退路径保持相同的 Nth 语义，最好同时检查预期命中数与目标特征。覆盖 0、1、多命中及序号超出范围；不能只测试默认 `index=1`。

### F6：段内偏移可以越过指定段

位置：[Civ6DLLHookLoaderAPI.cpp](../DllLoaderRuntime/Civ6DLLHookLoaderAPI.cpp) `ResolveByRvaExImpl`，931–961。

函数取出 `sectionRva` 和 `sectionSize`，但最后只将 `sectionRva + rva` 交给全映像边界检查，未使用 `sectionSize`。加法本身也没有溢出检查。

**复现：** 查询 fixture 的 `.text` 大小，再传 `rva=sectionSize, span=1, kSectionText`，仍得到非空地址，即指定段末尾后的第一个字节被接受。

**建议与验收：** 先用减法式边界检查保证 `rva` 和 `span` 完整位于段内，再做受检加法。测试最后一个字节、跨段跨度、等于段大小、接近 `UINTPTR_MAX`、空段以及 `span=0` 的明确契约。

### F7：虚表槽越过声明的逻辑表边界

位置：[PdataMatch.cpp](../DllLoaderRuntime/PdataMatch.cpp) `ParseModuleData`，366–525，尤其 381–384 / 444–461。

解析器计算了描述符声明的 `slotEnd`，但每个 vtable 符号消费槽位时，只检查累计数量是否超过全局上限、读取是否超过整个文件，不检查累计数量是否超过 `m.vtableSlotCount`，也不限制在 `slotEnd` 内。

**复现输入：** 64 字节缓冲；pdata 在偏移 0，1 条有效记录；symbol 在偏移 16，1 条 `kind=1, vtableSlotCount=1` 记录；描述符的 vtable 起点为 48、**声明槽数为 0**；heap 同样从 48 开始，长 16。直接调用生产 `ParseModuleData` 返回 true。

这证明解析器会把文件内其它逻辑区的数据当成虚表槽，**不是已证明越过整个分配缓冲区的内存读取**。损坏的旁路文件可能因被接受而阻止内嵌资源回退，继续生成错误地址信息。

Python 侧 `parse_module` 已检查声明槽数，`parse_container` 还校验实际消费量一致，C++ 运行时没有同等约束，两者并非完全相同的验证器。

**建议与验收：** 以声明槽表为边界，验证消费总量及内部区段关系，拒绝不支持的符号 kind/重复模块等歧义输入。加入零槽但有消费、恰好用完、超出一槽、多个虚表累计超出、槽表与 heap 重叠的反例。

### F8：回滚失败抹掉唯一的恢复记录

位置：[PatchRegistry.cpp](../DllLoaderRuntime/PatchRegistry.cpp) `RevertAllFor`，283–325，尤其 306–314。

`MakeWritableRecording` 失败时，代码把情况解释为“映像已卸载”，随后删除该补丁记录。保护失败也可能只是仍在映射的页面暂时为 `PAGE_NOACCESS`，并不等于原始字节已经随映射消失。

**复现：** fixture 使用页对齐的模块内静态缓冲，先由真实 `HookPatch` 将 `0x11` 改为 `0x22`，再把该页设为 `PAGE_NOACCESS`。执行 `RevertAllFor` 返回 0；`VirtualQuery` 仍报告 `MEM_COMMIT`，账本却已无记录。恢复读写保护后，内容仍是 `0x22`。

**影响：** 之后页面重新可访问，补丁仍在，但原字节档案和冲突占位都丢了。其它修改可能在此基础上继续叠加，卸载清理也无法重试。

**建议：** 区分“确认映射已经消失”和“映射仍在但暂时无法写入”；后者保留失败记录，明确上报并安排重试/阻止危险释放。还应检查恢复页保护的失败报告，以及显式 critical section 在分配异常下的退出保证。

**修复验收：** 将本次保护变化序列加入正式测试；追加已解除映射、跨页中途失败、保护恢复失败。失败不能伪装成已经清理完成。

### F9：符号产线在验证前发布

位置：[symdb.py](../tools/symdb.py) `cmd_all`，1739–1810，复制资源在 1775，validate 在 1785。

`all` 先将生成的 `.xp` 复制到 `DllLoaderRuntime/Civ6DllLoader.symdb.bin.xp`，再验证 pack 与 xp。若验证发现无效符号/数据，命令会失败，但已覆盖的交付资源不会自动恢复。之后普通构建可能把失败产物嵌入 DLL。

**建议与验收：** 先对临时生成物完成全部验证，再发布交付资源。通过故意生成校验失败的输入，验证旧资源 hash 完全不变；成功路径才允许改变交付文件。当前只是静态确认，未为了复现而覆盖仓库资源。

## 4. 尚未闭合的风险与假设

以下项目需要更多证据。不要将它们写成已经复现的游戏崩溃，也不要因未复现而当作已安全。

### R1：插件代码的真实停止点

`PluginInFlight` 只覆盖 Message、GameEvent、ScriptGlobals、ScriptGlobalsUI、PushMethods 这些 Loader 发起的受控回调。普通插件 detour、注入 Lua 后日后执行的闭包、插件自建线程并不在 owner 计数内。

现在延迟到原始 GameCore 卸载返回、模块句柄清空后才释放 DLL，前提是引擎此时已经销毁所有可能调用插件的 Lua 状态，并且没有其它线程仍在插件 detour。`OnUnload` 更早执行，插件状态也可能先于代码解除映射而被释放。需要证明引擎串行性/静止点，或增加完整的调用寿命机制。

共享 detour 的计数也从进入 C++ detour 后开始。应专门考虑“线程已从 stub 取到旧 nextTarget，但尚未增加共享计数”的窗口，核对 MinHook 停用、槽位复用与原函数复位之间是否有充分保证。

### R2：阶段 A 与阶段 B 没有整体完成屏障

工作线程先安装游戏线程的钩子，再检查更新、加载 Global。transition 锁保护若干转换函数，但不覆盖整段扫描、全部阶段 A、以及所有引擎原始 Load/Unload 调用。

需在快速进入对局、慢磁盘、更新弹窗、Global OnLoad 较慢时记录线程与时序，确认 Global 是否允许晚于 GameCore 插件加载、HavokScript 导入与使用是否跨线程并发。源码中“唯一写者是游戏线程”等注释不足以证明事实。

### R3：地址矫正与缓存的置信度

`PdataMatch` 的 PE identity、相同 pdata 快速路径、基于 size/unwind 的指纹与抽样缓存检查，都不是整个二进制的语义证明。代码改变但函数大小/unwind 不变、仅修改 sidecar 的 AOB/名字/虚表、或数据布局变化时，缓存与恒等映射是否仍正确，需要特制样本验证。

建议保存解析结果的来源与置信依据，对真正要调用/改写的关键站点补充唯一性、完整指令/调用约定和对象布局验证，避免只因范围合法就进入原生调用。

### R4：JIT 非叶函数的展开信息

生成 stub 的 capture 慢路径会调整 `rsp` 并调用 `CaptureDispatch`。本次在项目及所用 asmjit 路径中未找到对应的动态 unwind 表登记。Microsoft 对动态生成的 x64 非叶代码要求适当的函数表支持，否则异常处理/回溯不可靠。依据：[x64 异常处理](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)、[RtlAddFunctionTable](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtladdfunctiontable)。

受控 SEH 叶子减少了常见异常逃逸，但 `CaptureDispatch` 中日志、锁及分配路径仍需分析。建议为生成代码提供正确展开信息，或提供可验证的“不允许异常越过该帧”边界，并实测栈回溯与异常路径。本轮没有注入该类异常。

### R5：边界保护与原生并发写入的限度

页属性预检与稍后的访问之间仍可能发生卸载/改保护；`/EHsc` 下 SEH 穿过持锁 C++ 栈帧也不等价于普通异常清理。Patch 的普通 `memcpy` 不提供对正在执行其它线程的原子指令修改保证。

Global 的域判断依赖已登记的 GameCore 映像；在尚未 Attach、Attach 失败或已 Detach 的窗口，需要核查是否可能把一个实际短寿命游戏模块误作可长期使用目标。函数指针按模块归属识别、`_ReturnAddress()` 与编译器尾调用的组合，也值得用真实插件的 Release 包装函数验证。

### R6：UI 与游戏 ABI 的版本依赖

固定对象偏移、虚表偏移、Lua 栈布局和短函数前导签名可能在更新后部分仍匹配但整体语义已变。UI 解析器只实现 XML 子集；条件节点出现在 File 之后、部分子 context 初始化失败、根对象销毁后同地址复用等场景，应做专门测试。

未找到仓库中实际的 `docs/analysis/` 取证材料，无法复核旧文档引用的逆向证据。需要将具体二进制身份和反汇编证据纳入版本管理，才能将这些假设变成可追溯契约。

## 5. 旧文档和注释的差异

本轮保留已经暂存的 [ARCHITECTURE.md](ARCHITECTURE.md)，未用新文档覆盖它。下面是阅读时应立即修正的理解。

| 旧表述/位置 | 当前源码事实 |
| --- | --- |
| `InitEarly` 注释及架构对缺少上下文的 fail-closed 描述 | `ResolveByRvaCore` 在完全没有上下文时仍走原始 RVA；见 F1 |
| 架构 §3.1：按文件名去重后再过滤启用 Mod | 实现为先过滤，再排序、去重 |
| `HookAPI.h` capture 注释：最后一个订阅移除后才摘钩 | 站点/跳板通常保留，退出 capture 变为透传；域级停用另有处理 |
| 架构术语表：detour 独占，“后来者接管” | `InstallHookImpl` 遇到已占 detour 会拒绝 |
| 类别门禁被理解为拒绝发生在任何插件代码执行之前 | 类别检查晚于 `LoadLibraryExW`，DllMain/TLS/依赖初始化可能已执行 |
| `RuntimePackage.h`：候选信任由启用集/本地规则决定 | 运行时候选不使用启用 Mod 过滤，README 已有正确说明 |
| 架构 §2.5：共享 detour 等待时不持任何其它锁 | 释放 lifecycle 后，外层 transition 锁仍在 |
| 生命周期字段注释：唯一写者是游戏线程 | Global 加载来自工作线程；阶段 B 来自游戏线程，依靠同步约束而非天然单线程 |
| 更新整体被概括为原子替换 | fallback 是两步改名，部分 `ReplaceFileW` 失败状态尚未正确恢复；见 F4 |
| `symdb.py` validator 与运行时“同款解析”的理解 | Python 对声明槽数和消费总量更严格；见 F7 |
| 架构中的 `docs/analysis/` 证据索引 | 本工作区中没有对应材料，不能当作已核验依据 |

建议后续修代码时同步修对应注释；仅改文档不能消除 F1–F9。

## 6. 已执行的验证

### 6.1 构建与生命周期自测

环境：Windows x64，Visual Studio 2026 Community 18.10.1，MSVC 工具目录 `14.51.36231`，可用平台工具集 v145。项目声明 v143；本机当前 MSBuild 的平台工具集注册没有 v143，故本次通过命令行覆盖为 v145。没有改 `.vcxproj`。

| 项目/测试 | 结果 | 限定 |
| --- | --- | --- |
| Shell，Release x64 | 构建成功，0 error / 0 warning | v145，并非默认 v143 验证 |
| Runtime，Release x64 | 构建成功，0 error / 0 warning | 同上 |
| Shell，Debug x64 | 构建成功，0 error / 0 warning | 同上 |
| Runtime，Debug x64 | 构建成功，0 error / 68 条 warning | LNK4075 × 1、LNK4098 × 1、LNK4099 × 66 |
| `runtime_lifetime_selftest` | `PASS: runtime lifetime regression tests` | 不包含真实 Hook/GameCore/Lua 集成 |
| 当前内嵌 sidecar 的生产解码与解析 | PASS，3 个模块上下文 | 不证明对应游戏版本中的地址语义正确 |

Debug Runtime 的警告分别涉及编辑继续与链接优化选项、默认 CRT 库冲突，以及 asmjit 调试符号缺失。尤其 CRT 冲突应核对预编译库配置，不能因为成功链接就视为运行时兼容性已验证。

生命周期自测覆盖：

1. 同 owner 重新加载生成新生命周期，旧 gate 不会被重新开放。
2. 移动后的 Guard 仍正确持有并释放在途计数。
3. 广播旧快照遇到替换，在同代与重载两种情况下都不误调用旧处理器。
4. 注销等待外部在途 handler，回调自注销不等待自己。
5. 替换只等待旧 entry，不被替换后新 entry 的在途回调拖住。

### 6.2 构建复查方法

在已初始化 x64 C++ 工具链的 PowerShell 中，可按下面方式生成隔离产物。工具集按实际安装选择；本次为 v145。

```powershell
$reviewRoot = Join-Path (Get-Location) 'tools/out/code-review-20260918'
foreach ($configuration in @('Release', 'Debug')) {
    foreach ($project in @('DllLoader', 'DllLoaderRuntime')) {
        $outputDir = "$reviewRoot/bin/$configuration/"
        $intermediateDir = "$reviewRoot/obj/$project/$configuration/"
        New-Item -ItemType Directory -Force -Path $reviewRoot | Out-Null
        & MSBuild.exe "$project/$project.vcxproj" /nologo /t:Rebuild /v:minimal `
            "/p:Configuration=$configuration" /p:Platform=x64 /p:PlatformToolset=v145 `
            "/p:OutDir=$outputDir" "/p:IntDir=$intermediateDir" `
            *> "$reviewRoot/build-$configuration-$project.log"
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $project $configuration" }
    }
}
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/run_runtime_lifetime_selftest.ps1
```

本机直接启动脚本曾遇到执行策略及 DevShell 中 `Path`/`PATH` 重复问题；实际先经 `vcvarsall.bat x64` 初始化环境，并只在构建子进程内归一化重复 PATH 项。沙箱下 MSBuild FileTracker 曾遇到访问拒绝，经执行权限批准后完成上述四次构建。早期失败不等于最终构建失败；最终日志是 `build-<配置>-<工程>.log`。

### 6.3 缺陷探针的结果与重建条件

本地证据目录：[tools/out/code-review-20260918](../tools/out/code-review-20260918/)。该目录被 Git 忽略，**不是项目正式测试套件，也不会随仓库提交**；以下输入和结果摘要保留在本报告中供重新构造测试。

- `audit_probe.cpp` 直接编译当前 API 实现，链接本轮 Debug 依赖对象、MinHook 与 asmjit；不链接 `RuntimeEntry.cpp`，不启动游戏 Worker。fixture EXE 名为 `CivilizationVI.exe`，以满足生产映像识别，并将自身模块登记为测试 Global owner。
- 探针分别调用真实 RVA 入口、段解析、EXE AOB 回退、`HookPatch` 与 capture、补丁回滚。Hook 只作用于探针进程自己的函数；登记后不执行这个目标。PAGE_NOACCESS 用例使用探针自身独占的页对齐静态缓冲。
- `pdata_probe.cpp` 直接编译当前 `PdataMatch.cpp`，先解码并解析仓库真实资源，再按 F7 的 64 字节输入调用生产内部模块解析函数。正常输入与畸形输入的结果分别报告。
- `run-probes.cmd`、`audit.rsp`、构建日志与下列结果文件保留在本地。缺陷探针在发现预期缺陷时返回 0；不能将它的退出码解释为代码已修复。

`audit-results.txt`：

```text
RVA without sidecar returns raw address: REPRODUCED
section-relative RVA accepts first byte past section: REPRODUCED
no-context EXE fallback ignores index=2: REPRODUCED
capture hook accepts registered patch overlap: REPRODUCED
committed protected page loses rollback record: REPRODUCED
Observed 5/5 review findings. This is a defect probe, not a passing safety test.
```

`pdata-results.txt`：

```text
current sidecar production decode/parse: PASS (3966172 -> 44318600 bytes; contexts=3)
vtable slot read past declared block: REPRODUCED
```

真实资源 `DllLoaderRuntime/Civ6DllLoader.symdb.bin.xp` 的 SHA-256：

```text
830B95E206496886C8AE76C8AE58D0A36EB4D1C553272AA1D1382E17531A9291
```

## 7. 下一轮验证清单

先把 F1–F9 的触发条件转换为正式回归测试，再按以下矩阵做游戏内验证。所有项目目前均为**待做**，不因本轮构建成功而自动通过。

| 场景 | 需要观察的证据 |
| --- | --- |
| DX11 与 DX12 冷启动、首次安装后重启 | 正确代理/系统导出、符号身份、Load/Unload 钩安装，Global 只加载一次 |
| XP2 进入对局 → 返回菜单 → 再进入，循环至少 20 次 | 插件 OnLoad/OnUnload 次数、owner 代际、待释放队列清空、站点复用与内存增长 |
| 基础版/XP1 规则集 | 不误进入 XP2 阶段，不使用错误 GameCore ABI |
| 同地址与不同地址的 GameCore 重载 | 原入口字节正确，旧 original/共享槽未被新实例误用 |
| 慢 Global OnLoad，同时快速进入对局 | 阶段 A/B 顺序、锁等待和 hks 读写线程符合契约 |
| 插件回调内发送消息、替换 handler、自注销 | 无死锁；旧 entry/owner 不再被调用 |
| 正在执行 detour/Lua 闭包时退出对局 | OnUnload 不提前释放被访问状态，模块解除映射前无旧调用者 |
| OnLoad/事件/消息/OnUnload 各处故障 | 隔离范围、补丁回滚、队列、锁均可恢复，日志不宣称未完成的成功 |
| 启用 Mod 变化、SQLite 忙/坏文件、同名 DLL | 过滤、排序、去重符合预期；Global 重启生效，GameCore 下次加载生效 |
| sidecar 缺失、损坏、模块缺失及旧缓存 | 明确拒绝危险地址；内嵌回退与缓存失效有日志证据 |
| Hook/Patch 双向冲突、capture 混用、hotpatch | 所有入口同样拒绝重叠，撤销后字节与最初完全一致 |
| 更新时文件占用、访问拒绝、部分改名失败 | 任一步失败后有可启动安装或明确可恢复状态，不丢唯一恢复材料 |
| UI context 重建、同址复用、条件/坏 XML、子项失败 | 不重复挂接、不误加载条件文件，失败可重试，不残留悬空指针 |
| 用工程原声明的 v143 构建 Release/Debug | 工具集及预编译依赖一致，ABI 与 CRT 警告得到解释或解决 |

每次游戏测试保存：EXE/GameCore 文件 hash 与版本、运行时版本、启用 Mod 集合、线程/生命周期日志、预期和实测结果、崩溃 dump（若发生）。只有这些记录与对应源码版本一起保留，后续才能判断“这次修改修了什么、还没有证明什么”。
