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
