#pragma once
// 只保留 loader 真正用到的类型别名。
#include "HavokScript.h"

namespace ProxyTypes {
	typedef void(__cdecl* RegisterScriptDataForUI)(hks::lua_State* _, hks::lua_State* L);
	typedef void(__cdecl* RegisterScriptData)(hks::lua_State*);
	typedef void* (__cdecl* DllCreateGameContext)(void);
	typedef void(__cdecl* DllDestroyGameContext)(void* context);
}
