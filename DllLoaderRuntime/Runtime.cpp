#include "pch.h"
#include "Runtime.h"
#include "MinHook.h"
#include "../common/Logger.h"
#include "HavokScript.h"

#pragma comment(lib, "libMinHook.x64.lib")

namespace Runtime {
	HMODULE GameCore;
	uintptr_t GameCoreAddress;
	DWORD GameProcessId;
	HANDLE GameProcess;
	uintptr_t BaseAddress;

	_EnterLuaCriticalSection EnterLuaCriticalSection;
	_LeaveLuaCriticalSection LeaveLuaCriticalSection;

	void Attach(HMODULE gameCore) {
		GameCore = gameCore;
		GameCoreAddress = reinterpret_cast<uintptr_t>(GameCore);
		GameProcessId = GetCurrentProcessId();
		GameProcess = GetCurrentProcess();
		BaseAddress = (uintptr_t)GetModuleHandle(NULL);
		// These helpers are not currently present in the versioned symbol DB.
		// Never bind the historical executable-relative RVAs on an unknown build.
		EnterLuaCriticalSection = nullptr;
		LeaveLuaCriticalSection = nullptr;
	}

	bool InitMinHook() {
		if (MH_Initialize() != MH_OK) {
			Logger::Log("MinHook failed to init");
			return false;
		}
		Logger::Log("MinHook initialized");
		return true;
	}

	// Tear down MinHook before any FreeLibrary of plugins/runtime.
	// Does not FreeLibrary(GameCore); the shell owns that module.
	void Destroy() {
		MH_DisableHook(MH_ALL_HOOKS);
		MH_Uninitialize();
		GameCore = NULL;
		GameCoreAddress = 0x0;
		EnterLuaCriticalSection = nullptr;
		LeaveLuaCriticalSection = nullptr;
	}

	BOOL WriteCodeToProcess(uintptr_t address, byte* bytes, size_t sizeOfBytes) {
		DWORD oldProtect;
		LPVOID lpBaseAddress = reinterpret_cast<LPVOID>(address);

		if (!VirtualProtectEx(GameProcess, lpBaseAddress, sizeOfBytes, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			Logger::Log("VirtualProtectEx failed err=%lu", GetLastError());
			return FALSE;
		}

		SIZE_T numberOfBytesWritten;
		BOOL result = WriteProcessMemory(GameProcess, lpBaseAddress, bytes, sizeOfBytes, &numberOfBytesWritten);

		if (!result || numberOfBytesWritten != sizeOfBytes) {
			Logger::Log("WriteProcessMemory failed err=%lu", GetLastError());
			VirtualProtectEx(GameProcess, lpBaseAddress, sizeOfBytes, oldProtect, &oldProtect);
			return FALSE;
		}

		VirtualProtectEx(GameProcess, lpBaseAddress, sizeOfBytes, oldProtect, &oldProtect);
		return TRUE;
	}

	BOOL WriteCodeToGameCore(uintptr_t address, byte* bytes, size_t sizeOfBytes) {
		return WriteCodeToProcess(address + GameCoreAddress, bytes, sizeOfBytes);
	}
}
