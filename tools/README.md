# Runtime 符号库

`pack_symbol_db.py` 将 [`symbol_aliases.json`](symbol_aliases.json) 打包为
runtime 使用的 `Civ6DllLoader.symbols.bin`。

```powershell
python tools/pack_symbol_db.py --check
```

产出：`tools/out/Civ6DllLoader.symbols.bin`。

- `symbol_aliases.json` 保存经确认的插件友好名称、RVA 和目标
  GameCore `SizeOfImage`。
- 如果本地存在 `tools/out/map_new_rva_unique.jsonl`，打包器也会合并其中的
  修饰名、可解析友好名和 IDA 风格名称；该文件属于可选的本地逆向产物，
  不进入仓库。
- Runtime 优先加载同目录旁路文件，否则读取 DLL 内嵌的 RCDATA。
- 构建 `DllLoaderRuntime` 时会自动运行打包器，无需手工执行。
