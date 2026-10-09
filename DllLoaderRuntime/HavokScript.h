#pragma once
#include <iostream>
#include <Windows.h>

// 推送前检查导入指针：HavokScript 导出缺失时静默跳过（InitHavokScript 已整体告警），
// 不再把空指针调用放进游戏线程。
#define PushLuaMethod(L, func, cclosurename, stackOffset, name) \
    do { \
        if (hks::pushnamedcclosure && hks::setfield) { \
            hks::pushnamedcclosure(L, func, 0, cclosurename, 0); \
            hks::setfield(L, stackOffset, name); \
        } \
    } while (0)

namespace hks {
	constexpr int LUA_GLOBAL = -10002;

	typedef struct lua_State lua_State;

	typedef int(__cdecl* luaFunc)(lua_State*);

	typedef void(__cdecl* hks_pushnamedcclosureType)(lua_State*, luaFunc, int, const char*, int);
	extern hks_pushnamedcclosureType pushnamedcclosure;
	typedef int(__cdecl* luaL_checkintegerType)(lua_State*, int);
	extern luaL_checkintegerType checkinteger;
	typedef double(__cdecl* luaL_checknumberType)(lua_State*, int);
	extern luaL_checknumberType checknumber;
	typedef void(__cdecl* hksi_lua_setfieldType)(lua_State*, int, const char*);
	extern hksi_lua_setfieldType setfield;
	typedef int(__thiscall* GetTopType)(lua_State*);
	extern GetTopType gettop;
	typedef int(__thiscall* DoStringType)(lua_State*, const char*);
	extern DoStringType dostring;
	typedef int(__cdecl* hksi_lua_tobooleanType)(lua_State*, int);
	extern hksi_lua_tobooleanType toboolean;
	typedef void(__cdecl* hksi_lua_pushnumberType)(lua_State*, double);
	extern hksi_lua_pushnumberType pushnumber;
	typedef void(__cdecl* hksi_lua_pushintegerType)(lua_State*, int);
	extern hksi_lua_pushintegerType pushinteger;
	typedef void(__cdecl* hksi_lua_pushnilType)(lua_State*);
	extern hksi_lua_pushnilType pushnil;
	typedef void(__cdecl* hksi_luaL_errorType)(lua_State*, char const*, ...);
	extern hksi_luaL_errorType error;
	typedef char const* (__cdecl* hksi_lua_pushfstringType)(lua_State*, char const*, ...);
	extern hksi_lua_pushfstringType pushfstring;
	typedef char const* (__cdecl* CheckLStringType)(lua_State*, int, unsigned __int64*);
	extern CheckLStringType checklstring;
	typedef void* (__cdecl* hksi_lua_touserdataType)(lua_State*, int);
	extern hksi_lua_touserdataType touserdata;
	typedef void(__cdecl* hksi_lua_getfieldType)(lua_State*, int, char const*);
	extern hksi_lua_getfieldType getfield;
	typedef void(__thiscall* PopType)(lua_State*, int);
	extern PopType pop;
	typedef void(__cdecl* hksi_lua_createtableType)(lua_State*, int, int);
	extern hksi_lua_createtableType createtable;
	typedef luaFunc(__cdecl* lua_tocfunctionType)(lua_State*, int);
	extern lua_tocfunctionType tocfunction;
	typedef void(__cdecl* hksL_checktableType)(lua_State*, int);
	extern hksL_checktableType checktable;
	typedef unsigned long long(__cdecl* hks_lua_objlenType)(lua_State*, int);
	extern hks_lua_objlenType objlen;
	typedef void(__cdecl* hks_lua_gettableType)(lua_State*, int);
	extern hks_lua_gettableType gettable;
	// ?hksi_lua_cpcall@@YAHPEAUlua_State@@P6AH0@ZPEAX@Z
	// int __cdecl hksi_lua_cpcall(lua_State*, luaFunc, void*)
	typedef int(__cdecl* hksi_lua_cpcallType)(lua_State*, luaFunc, void*);
	extern hksi_lua_cpcallType cpcall;
	typedef int(__cdecl* RefType)(lua_State*, int);
	extern RefType ref;
	typedef int(__cdecl* hksi_lua_pcallType)(lua_State*, int, int, int);
	extern hksi_lua_pcallType pcall;
	typedef void(__cdecl* hski_lua_pushvalueType)(lua_State*, int);
	extern hski_lua_pushvalueType pushvalue;
	typedef void(__cdecl* hksi_lua_rawgetiType)(lua_State*, int, int);
	extern hksi_lua_rawgetiType rawgeti;
	typedef void(__cdecl* hksi_lua_unrefType)(hks::lua_State*, int, int);
	extern hksi_lua_unrefType unref;
	typedef void(__cdecl* hksi_lua_settableType)(hks::lua_State*, int);
	extern hksi_lua_settableType settable;
	typedef int(__cdecl* hksi_lua_isnumberType)(hks::lua_State*, int);
	extern hksi_lua_isnumberType isnumber;
	typedef double(__cdecl* hksi_lua_tonumberType)(hks::lua_State*, int);
	extern hksi_lua_tonumberType tonumber;
	typedef int(__cdecl* hksi_lua_isuserdataType)(hks::lua_State*, int);
	extern hksi_lua_isuserdataType isuserdata;
	typedef int(__cdecl* luaopen_debugType)(hks::lua_State*);
	extern luaopen_debugType luaopen_debug;
	typedef int(__cdecl* hksi_lua_tointegerType)(hks::lua_State*, int);
	extern hksi_lua_tointegerType tointeger;
	typedef int(__cdecl* hksi_lua_typeType)(lua_State*, int);
	extern hksi_lua_typeType type;
	typedef int(__cdecl* luaL_optintegerType)(lua_State*, int, int);
	extern luaL_optintegerType optinteger;
	typedef int(__cdecl* hksi_lua_sethookType)(lua_State*, void*, int, int);
	extern hksi_lua_sethookType sethook;
	typedef void* (__cdecl* hksi_lua_gethookType)(lua_State*);
	extern hksi_lua_gethookType gethook;
	typedef int(__cdecl* hksi_lua_gethookmaskType)(lua_State*);
	extern hksi_lua_gethookmaskType gethookmask;
	typedef int(__cdecl* hksi_lua_gethookcountType)(lua_State*);
	extern hksi_lua_gethookcountType gethookcount;

	// pushlightuserdata：官方导出优先，缺失时 HavokScript.cpp 内部走带防护的原始栈写入兜底。
	// pushboolean：该 DLL 没有对应导出，唯一实现就是原始栈写入（细节见 HavokScript.cpp）。
	typedef void(__cdecl* hksi_lua_pushlightuserdataType)(lua_State*, void*);

	extern int checkplayerid(lua_State*, int);
	extern void pushboolean(lua_State* L, bool value);
	extern void pushlightuserdata(lua_State* L, void* ptr);

	// 阶段 A（WorkerMain）解析一次即可：HavokScript_FinalRelease.dll 是 **exe 的静态导入**，
	// 随进程装载、进程内不会卸载，所以 GetProcAddress 的结果恒定，没有"需要重新解析"的理由。
	// 返回 false = 模块缺失或任一导入未解析；调用方按**降级**处理（Lua API 逐入口
	// 返回安全默认值），不要据此拒载插件。
	extern bool InitHavokScript();
}
