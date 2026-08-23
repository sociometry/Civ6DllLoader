#pragma once
// GameAddress.h — 原始模块（CivilizationVI.exe）地址获取的最基础封装。
//
// 只封装「由 RVA 换算为绝对地址」这一动作；偏移值（RVA）与特征码校验仍由调用方持有，
// 本模块不内置任何偏移/特征码/目标清单。以后换获取方案（特征码扫描、符号表等）时，
// 本模块是唯一改动点，调用方的传参语义随方案演进。
#include <cstdint>

namespace GameAddress {

// exe 模块基址（GetModuleHandleW(nullptr)，进程内恒定，缓存只取一次）。失败返回 0。
uintptr_t Base();

// 函数绝对地址 = Base() + rva。rva 为 0 或基址不可用返回 0。
uintptr_t Function(uintptr_t rva);

// 全局变量（数据）绝对地址 = Base() + rva。rva 为 0 或基址不可用返回 0。
uintptr_t GlobalVariable(uintptr_t rva);

}  // namespace GameAddress
