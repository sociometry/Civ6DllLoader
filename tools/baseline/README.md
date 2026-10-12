# 拆分验证基线

`loader_baseline.norm.log` —— 拆分开始前（commit 7eeda3a）实机跑完 §8 流程的
Loader 日志，已归一化（时间戳 / pid / `%p` 地址替换为占位符）。

- 采集时间：2026-10-12 00:34–00:37
- 部署产物 md5：39801e709edc0f962a7a220c5505a40c
- 覆盖路径：启动 → 主菜单 → 两次「进对局 → 退回主菜单」重载循环
- **未覆盖**：Global 插件路径（当时 `Plugins/Global/` 为空，日志记 `0 candidate(s)`）
- 367 行，8 个锚点齐全

比对方式：

    python tools/log_fingerprint.py --compare "<新的 Loader 日志>"

每次改动后重跑同一套实机流程，再执行上面这条命令。不一致即说明改动改变了行为。
