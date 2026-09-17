#include "pch.h"
#include <Windows.h>
#include <string>
#include <vector>
#include "HavokScript.h"
#include "Runtime.h"
#include "../common/Logger.h"

namespace hks {
	hks_pushnamedcclosureType pushnamedcclosure;
	luaL_checkintegerType checkinteger;
	luaL_checknumberType checknumber;
	hksi_lua_setfieldType setfield;
	GetTopType gettop;
	DoStringType dostring;
	hksi_lua_tobooleanType toboolean;
	hksi_lua_pushnumberType pushnumber;
	hksi_lua_pushintegerType pushinteger;
	hksi_lua_pushnilType pushnil;
	hksi_luaL_errorType error;
	hksi_lua_pushfstringType pushfstring;
	CheckLStringType checklstring;
	hksi_lua_touserdataType touserdata;
	hksi_lua_getfieldType getfield;
	PopType pop;
	hksi_lua_createtableType createtable;
	lua_tocfunctionType tocfunction;
	hksL_checktableType checktable;
	hks_lua_objlenType objlen;
	hks_lua_gettableType gettable;
	hksi_lua_cpcallType cpcall;
	hski_lua_pushvalueType pushvalue;
	RefType ref;
	hksi_lua_pcallType pcall;
	hksi_lua_rawgetiType rawgeti;
	hksi_lua_unrefType unref;
	hksi_lua_isnumberType isnumber;
	hksi_lua_tonumberType tonumber;
	hksi_lua_isuserdataType isuserdata;
	hksi_lua_settableType settable;
	luaopen_debugType luaopen_debug;
	hksi_lua_tointegerType tointeger;
	hksi_lua_typeType type;
	luaL_optintegerType optinteger;
	hksi_lua_sethookType sethook;
	hksi_lua_gethookType gethook;
	hksi_lua_gethookmaskType gethookmask;
	hksi_lua_gethookcountType gethookcount;

	// 官方导出优先（存在时无 lua_State 布局依赖）；仅当全部候选都缺失才走原始栈写入兜底。
	hksi_lua_pushbooleanType pushbooleanReal = nullptr;
	hksi_lua_pushlightuserdataType pushlightuserdataReal = nullptr;

	// 本次 Init 缺失的导入名清单（含重复解析失败）；InitHavokScript 据此判定整体失败。
	std::vector<std::string> g_missingImports;

	// 解析并登记：缺失的导入名记录在案，InitHavokScript 汇总告警并返回 false
	// （GameCore 插件随之停用——半可用的 Lua API 对插件是崩溃源，宁可不加载）。
#define RESOLVE_IMPORT(var, mangled) \
    do { \
        (var) = reinterpret_cast<decltype(var)>(GetProcAddress(hksDll, (mangled))); \
        if (!(var)) g_missingImports.push_back((mangled)); \
    } while (0)

	// 候选型解析：按顺序尝试多个 mangling，第一个命中的生效；全缺失不算失败（有兜底路径）。
	template <typename FnT>
	FnT ResolveFirst(HMODULE hksDll, const char* const* candidates, size_t count) {
		for (size_t i = 0; i < count; ++i) {
			if (auto fn = reinterpret_cast<FnT>(GetProcAddress(hksDll, candidates[i]))) {
				return fn;
			}
		}
		return nullptr;
	}

	static void InitHavokScriptImports(HMODULE hksDll) {
		g_missingImports.clear();

		RESOLVE_IMPORT(pushnamedcclosure, "?hks_pushnamedcclosure@@YAXPEAUlua_State@@P6AH0@ZHPEBDH@Z");
		RESOLVE_IMPORT(setfield, "?hksi_lua_setfield@@YAXPEAUlua_State@@HPEBD@Z");
		RESOLVE_IMPORT(checkinteger, "?luaL_checkinteger@@YAHPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(gettop, "?GetTop@LuaState@LuaPlus@@QEBAHXZ");
		RESOLVE_IMPORT(dostring, "?DoString@LuaState@LuaPlus@@QEAAHPEBD@Z");
		RESOLVE_IMPORT(toboolean, "?hksi_lua_toboolean@@YAHPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(pushinteger, "?hksi_lua_pushinteger@@YAXPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(pushnumber, "?hksi_lua_pushnumber@@YAXPEAUlua_State@@N@Z");
		RESOLVE_IMPORT(error, "?hksi_luaL_error@@YAHPEAUlua_State@@PEBDZZ");
		RESOLVE_IMPORT(checknumber, "?luaL_checknumber@@YANPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(pushfstring, "?hksi_lua_pushfstring@@YAPEBDPEAUlua_State@@PEBDZZ");
		RESOLVE_IMPORT(checklstring, "?hksi_luaL_checklstring@@YAPEBDPEAUlua_State@@HPEA_K@Z");
		RESOLVE_IMPORT(pop, "?Pop@LuaState@LuaPlus@@QEAAXH@Z");
		RESOLVE_IMPORT(touserdata, "?hksi_lua_touserdata@@YAPEAXPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(getfield, "?hksi_lua_getfield@@YAXPEAUlua_State@@HPEBD@Z");
		RESOLVE_IMPORT(createtable, "?lua_createtable@@YAXPEAUlua_State@@HH@Z");
		RESOLVE_IMPORT(tocfunction, "?lua_tocfunction@@YAP6AHPEAUlua_State@@@Z0H@Z");
		RESOLVE_IMPORT(checktable, "?hksL_checktable@@YAXPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(objlen, "?hksi_lua_objlen@@YA_KPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(gettable, "?hksi_lua_gettable@@YAXPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(cpcall, "?hksi_lua_cpcall@@YAHPEAUlua_State@@P6AH0@ZPEAX@Z");
		RESOLVE_IMPORT(ref, "?luaL_ref@@YAHPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(pcall, "?hksi_lua_pcall@@YAHPEAUlua_State@@HHH@Z");
		RESOLVE_IMPORT(pushvalue, "?hksi_lua_pushvalue@@YAXPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(pushnil, "?hksi_lua_pushnil@@YAXPEAUlua_State@@@Z");
		RESOLVE_IMPORT(rawgeti, "?hksi_lua_rawgeti@@YAXPEAUlua_State@@HH@Z");
		RESOLVE_IMPORT(unref, "?hksi_luaL_unref@@YAXPEAUlua_State@@HH@Z");
		RESOLVE_IMPORT(settable, "?SetTable@LuaState@LuaPlus@@QEAAXH@Z");
		RESOLVE_IMPORT(isnumber, "?hksi_lua_isnumber@@YAHPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(tonumber, "?hksi_lua_tonumber@@YANPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(isuserdata, "?hksi_lua_isuserdata@@YAHPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(luaopen_debug, "?luaopen_debug@@YAHPEAUlua_State@@@Z");
		RESOLVE_IMPORT(tointeger, "?hksi_lua_tointeger@@YAHPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(type, "?hksi_lua_type@@YAHPEAUlua_State@@H@Z");
		RESOLVE_IMPORT(optinteger, "?luaL_optinteger@@YAHPEAUlua_State@@HH@Z");
		RESOLVE_IMPORT(sethook, "?hksi_lua_sethook@@YAHPEAUlua_State@@P6AX0PEAUlua_Debug@@@ZHH@Z");
		RESOLVE_IMPORT(gethook, "?hksi_lua_gethook@@YAP6AXPEAUlua_State@@PEAUlua_Debug@@@Z0@Z");
		RESOLVE_IMPORT(gethookmask, "?hksi_lua_gethookmask@@YAHPEAUlua_State@@@Z");
		RESOLVE_IMPORT(gethookcount, "?hksi_lua_gethookcount@@YAHPEAUlua_State@@@Z");

		// pushboolean / pushlightuserdata：尝试官方导出（精确 mangling 匹配，不存在即返回空）。
		static const char* kPushBooleanCandidates[] = {
			"?hksi_lua_pushboolean@@YAXPEAUlua_State@@_N@Z",
			"?hksi_lua_pushboolean@@YAXPEAUlua_State@@H@Z",
			"?lua_pushboolean@@YAXPEAUlua_State@@H@Z",
		};
		static const char* kPushLightUserDataCandidates[] = {
			"?hksi_lua_pushlightuserdata@@YAXPEAUlua_State@@PEAX@Z",
			"?lua_pushlightuserdata@@YAXPEAUlua_State@@PEAX@Z",
		};
		pushbooleanReal = ResolveFirst<hksi_lua_pushbooleanType>(
			hksDll, kPushBooleanCandidates, _countof(kPushBooleanCandidates));
		pushlightuserdataReal = ResolveFirst<hksi_lua_pushlightuserdataType>(
			hksDll, kPushLightUserDataCandidates, _countof(kPushLightUserDataCandidates));
		if (!pushbooleanReal) {
			Logger::Log("InitHavokScript: no pushboolean export; raw-stack fallback (offset-locked)");
		}
		if (!pushlightuserdataReal) {
			Logger::Log("InitHavokScript: no pushlightuserdata export; raw-stack fallback (offset-locked)");
		}
	}

	int checkplayerid(lua_State* L, int position) {
		if (!checkinteger) {
			if (error) error(L, "checkplayerid unavailable (HavokScript import missing)");
			return -1;
		}
		int playerId = hks::checkinteger(L, position);
		if (0 <= playerId && playerId < 64) {
			return playerId;
		}

		// 非法 ID 也走判空：checkinteger 与 error 是两个独立导入，可能一有一无。
		if (error) {
			std::string errorMessage = "Invalid playerId: ";
			hks::error(L, errorMessage.append(std::to_string(playerId)).c_str());
		}
		return -1;
	}

	// ---- 原始栈写入兜底（仅当 HavokScript 未导出对应 push 函数时使用）----
	// lua_State::top 指针槽偏移：版本锁定值（对当前 GameCore 布局硬编码）。官方导出
	// 可用时本路径不会执行；一旦 lua_State 布局变动，这个偏移就不再指向 top 槽，
	// pushboolean / pushlightuserdata 会【静默丢值】——下面的可写探测只挡得住“写不
	// 进去”的情形（所以不会崩），挡不住“写到别处可写内存”，故换游戏版本必须重验此值。
	constexpr uintptr_t kLuaStateTopSlotOffset = 0x48;

	// 写入一个 16 字节 TValue（tt(4)+pad(4)+value(8)）并把 top 指针推进一个槽位。
	static bool RawPushTValue(lua_State* L, int typeTag, uintptr_t valueBits) {
		if (!L) return false;
		int** topSlotPtr = reinterpret_cast<int**>(reinterpret_cast<uintptr_t>(L) + kLuaStateTopSlotOffset);
		// top 槽既要读（取栈顶）也要写（推进栈顶），按可写检查。
		if (!Runtime::IsWritableSpan(topSlotPtr, sizeof(int*))) return false;
		int* stackTop = *topSlotPtr;
		if (!Runtime::IsWritableSpan(stackTop, 16)) return false;
		stackTop[0] = typeTag;                                    // tt
		*reinterpret_cast<uintptr_t*>(stackTop + 2) = valueBits;  // value（+8）
		*topSlotPtr = stackTop + 4;                               // top += sizeof(TValue)
		return true;
	}

	void pushboolean(lua_State* L, bool value) {
		if (pushbooleanReal) {
			pushbooleanReal(L, value ? 1 : 0);
			return;
		}
		RawPushTValue(L, 1, value ? 1u : 0u);  // LUA_TBOOLEAN
	}

	void pushlightuserdata(lua_State* L, void* ptr) {
		if (pushlightuserdataReal) {
			pushlightuserdataReal(L, ptr);
			return;
		}
		RawPushTValue(L, 2, reinterpret_cast<uintptr_t>(ptr));  // LUA_TLIGHTUSERDATA
	}

	// Should only ever be called once. 返回 false = 有导入缺失，
	// 调用方（InitializeGameCorePhase）据此停用 GameCore 插件加载（宁缺毋崩）。
	bool InitHavokScript() {
		HMODULE hksDll = GetModuleHandle(TEXT("HavokScript_FinalRelease.dll"));
		if (hksDll == NULL) {
			Logger::Log("Failed to load HavokScript err=%lu", GetLastError());
			return false;
		}
		InitHavokScriptImports(hksDll);
		if (!g_missingImports.empty()) {
			for (const auto& name : g_missingImports) {
				Logger::Log("HavokScript missing import: %s", name.c_str());
			}
			Logger::Log("InitHavokScript: %zu import(s) missing; lua API degraded",
				g_missingImports.size());
			return false;
		}
		return true;
	}
}
