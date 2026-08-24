#include "pch.h"
#include "Runtime.h"
#include "MinHook.h"
#include "../common/Logger.h"
#include "HavokScript.h"

#include <algorithm>

#pragma comment(lib, "libMinHook.x64.lib")

namespace Runtime {
	bool InitMinHook() {
		if (MH_Initialize() != MH_OK) {
			Logger::Log("MinHook failed to init");
			return false;
		}
		Logger::Log("MinHook initialized");
		return true;
	}

	// VirtualQuery 逐区域走查（IsBadReadPtr 不可靠）：整段必须落在 MEM_COMMIT
	// 且保护不含 PAGE_NOACCESS/PAGE_GUARD 的区域内；needWrite 再要求写权限位。
	static bool SpanPageCheck(const void* p, size_t len, bool needWrite) {
		auto* cur = reinterpret_cast<const uint8_t*>(p);
		size_t remain = len;
		while (remain > 0) {
			MEMORY_BASIC_INFORMATION mbi{};
			if (VirtualQuery(cur, &mbi, sizeof(mbi)) == 0) {
				return false;
			}
			if (mbi.State != MEM_COMMIT) {
				return false;
			}
			if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) {
				return false;
			}
			if (needWrite && !(mbi.Protect &
			        (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
				return false;
			}
			const size_t regionBytes = static_cast<size_t>(mbi.RegionSize)
			    - static_cast<size_t>(cur - static_cast<const uint8_t*>(mbi.BaseAddress));
			if (regionBytes == 0) {
				return false;  // 防御：RegionSize 解析异常，避免死循环
			}
			const size_t consumed = (std::min)(regionBytes, remain);
			cur += consumed;
			remain -= consumed;
		}
		return true;
	}

	bool IsReadableSpan(const void* p, size_t len) {
		if (!p || len == 0) return false;
		return SpanPageCheck(p, len, false);
	}

	bool IsWritableSpan(const void* p, size_t len) {
		if (!p || len == 0) return false;
		return SpanPageCheck(p, len, true);
	}
}
