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

// exe 模块 PE 头的 SizeOfImage（进程内恒定，缓存只取一次）。失败返回 0。
// 游戏更新后镜像大小变化 = RVA 集已失效，调用方应据此整体降级。
uintptr_t ImageSize();

// [Base()+rva, Base()+rva+span) 是否完整落在 exe 镜像内（含 span 字节余量，
// 供特征码读取前判定可读）。rva=0 或镜像信息不可用返回 false。
bool RvaSpanValid(uintptr_t rva, size_t span);

// 函数绝对地址 = Base() + rva。rva 为 0、基址不可用或 rva 越出镜像返回 0。
uintptr_t Function(uintptr_t rva);

// 全局变量（数据）绝对地址 = Base() + rva。rva 为 0、基址不可用或 rva 越出镜像返回 0。
uintptr_t GlobalVariable(uintptr_t rva);

}  // namespace GameAddress
