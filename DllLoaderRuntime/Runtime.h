#pragma once
#include "MinHook.h"
#include "ProxyTypes.h"
#include "../common/Logger.h"
#include <mutex>

namespace Runtime {
	std::mutex& MinHookMutex();

	// MinHook 初始化（进程内一次）。本函数只认 MH_OK，重复初始化会失败并返回 false；
	// 对 MH_ERROR_ALREADY_INITIALIZED 的容错在 LoaderHooks::InstallAll / UiInject::Install 各自的 MH_Initialize 判断里。
	bool InitMinHook();

	// [p, p+len) 全部落在 MEM_COMMIT 且非 PAGE_NOACCESS/PAGE_GUARD 的页内。
	// 供版本锁定偏移解引用前探测（符号库/游戏版本错位时降级而不是访问违例）。
	bool IsReadableSpan(const void* p, size_t len);

	// 同上，且保护属性含写权限（heap/RW 数据段）。供原始内存写入前探测。
	bool IsWritableSpan(const void* p, size_t len);
};
