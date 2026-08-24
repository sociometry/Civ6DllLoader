#pragma once
#include "MinHook.h"
#include "ProxyTypes.h"
#include "../common/Logger.h"
typedef unsigned char byte;

namespace Runtime {
	extern HMODULE GameCore;
	extern uintptr_t GameCoreAddress;
	extern DWORD GameProcessId;
	extern uintptr_t BaseAddress;

	using _EnterLuaCriticalSection = void(*)(void);
	extern _EnterLuaCriticalSection EnterLuaCriticalSection;

	using _LeaveLuaCriticalSection = void(*)(void);
	extern _LeaveLuaCriticalSection LeaveLuaCriticalSection;

extern void Attach(HMODULE gameCore);

extern void Destroy();

bool InitMinHook();

// [p, p+len) 全部落在 MEM_COMMIT 且非 PAGE_NOACCESS/PAGE_GUARD 的页内。
// 供版本锁定偏移解引用前探测（符号库/游戏版本错位时降级而不是访问违例）。
bool IsReadableSpan(const void* p, size_t len);

// 同上，且保护属性含写权限（heap/RW 数据段）。供原始内存写入前探测。
bool IsWritableSpan(const void* p, size_t len);

	template <typename T>
	T GetGameCoreGlobalAt(uintptr_t address) {
		return reinterpret_cast<T>(GameCoreAddress + address);
	}

	template <typename T>
	T GetGlobalAt(uintptr_t address) {
		return reinterpret_cast<T>(BaseAddress + address);
	}

	template <typename T>
	void CreateHook(LPVOID pTarget, LPVOID pDetour, T** ppOriginal) {
		MH_STATUS status;
		if ((status = MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal))) != MH_OK) {
			Logger::Log("CreateHook failed: %s", MH_StatusToString(status));
		}
		if ((status = MH_EnableHook(pTarget)) != MH_OK) {
			Logger::Log("EnableHook failed: %s", MH_StatusToString(status));
		}
	}

	extern BOOL WriteCodeToGameCore(uintptr_t address, byte* bytes, size_t sizeOfBytes);
	extern BOOL WriteCodeToProcess(uintptr_t address, byte* bytes, size_t sizeOfBytes);
};
