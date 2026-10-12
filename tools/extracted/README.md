# 抽取中间产物

`extract_module.py` 把待迁代码从母体剪出后，原始文本落在这里，供拼装目标文件时对照。
母体侧已删除，这里是唯一副本 —— 拼装完并编译通过后即可丢弃。

- `phase1_SymbolResolve.txt` —— 13 个函数 + anchor 常量块（337 行）
