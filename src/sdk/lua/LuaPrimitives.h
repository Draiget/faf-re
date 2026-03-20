#pragma once

#if defined(__has_include)
#if __has_include(<lua.h>)
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#elif __has_include(<lua-lang/include/lua.h>)
#include <lua-lang/include/lua.h>
#include <lua-lang/include/lauxlib.h>
#include <lua-lang/include/lualib.h>
#elif __has_include("../../../dependencies/lua-lang/include/lua.h")
#include "../../../dependencies/lua-lang/include/lua.h"
#include "../../../dependencies/lua-lang/include/lauxlib.h"
#include "../../../dependencies/lua-lang/include/lualib.h"
#else
#error "Lua headers not found. Add dependencies/lua-lang/include to include paths."
#endif
#else
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#endif

#include <cstdint>

#include "legacy/containers/String.h"

#ifndef LUA_MULTRET
#define LUA_MULTRET (-1)
#endif

#ifndef LUA_REGISTRYINDEX
#define LUA_REGISTRYINDEX (-10000)
#endif

#ifndef LUA_GLOBALSINDEX
#define LUA_GLOBALSINDEX (-10001)
#endif

#ifndef lua_upvalueindex
#define lua_upvalueindex(i) (LUA_GLOBALSINDEX - (i))
#endif

#ifndef LUA_OK
#define LUA_OK 0
#define LUA_ERRRUN 1
#define LUA_ERRFILE 2
#define LUA_ERRSYNTAX 3
#define LUA_ERRMEM 4
#define LUA_ERRERR 5
#endif

#ifndef LUA_TNONE
#define LUA_TNONE (-1)
#define LUA_TNIL 0
#define LUA_TBOOLEAN 1
#define LUA_TLIGHTUSERDATA 2
#define LUA_TNUMBER 3
#define LUA_TSTRING 4
#define LUA_TTABLE 5
#endif

// LuaPlus 5.0 in this game build keeps separate tags for C functions/proto/upvalue.
#ifdef LUA_CFUNCTION
#undef LUA_CFUNCTION
#endif
#ifdef LUA_TFUNCTION
#undef LUA_TFUNCTION
#endif
#ifdef LUA_TUSERDATA
#undef LUA_TUSERDATA
#endif
#ifdef LUA_TTHREAD
#undef LUA_TTHREAD
#endif
#ifdef LUA_TPROTO
#undef LUA_TPROTO
#endif
#ifdef LUA_TUPVALUE
#undef LUA_TUPVALUE
#endif
#define LUA_CFUNCTION 6
#define LUA_TFUNCTION 7
#define LUA_TUSERDATA 8
#define LUA_TTHREAD 9
#define LUA_TPROTO 10
#define LUA_TUPVALUE 11

#define LUA_HOOKCALL 0
#define LUA_HOOKRET 1
#define LUA_HOOKLINE 2
#define LUA_HOOKCOUNT 3
#define LUA_HOOKTAILRET 4

#define LUA_MASKCALL (1 << LUA_HOOKCALL)
#define LUA_MASKRET (1 << LUA_HOOKRET)
#define LUA_MASKLINE (1 << LUA_HOOKLINE)
#define LUA_MASKCOUNT (1 << LUA_HOOKCOUNT)

#define LUA_NOREF (-2)
#define LUA_REFNIL (-1)

namespace gpg
{
	class Stream;
	class BinaryReader;
	class RType;
	class RRef;
}

struct global_State;
union GCObject;
struct lua_State;

namespace moho
{
	class CMessageStream;
	class Sim;
	class CLuaTask;
}

namespace LuaPlus
{
	class LuaState;
	class LuaStackObject;
	class LuaObject;

	// Keep 4-byte alignment to mirror MSVC x86-era binary layout.
#pragma pack(push, 4)
	union Value
	{
		void* p;
		float n;
		int b;
	};

	// lua.org/source/5.0/lobject.h.html#TObject
	struct TObject
	{
		int tt;
		Value value;

		TObject(int number) : tt{ LUA_TNUMBER } { value.n = static_cast<float>(number); }
		TObject(float number) : tt{ LUA_TNUMBER } { value.n = number; }
		TObject(bool boolean) : tt{ LUA_TBOOLEAN } { value.b = boolean ? 1 : 0; }
		TObject() : tt{ LUA_TNIL } { value.p = nullptr; }
	};

	using StkId = TObject*;
#pragma pack(pop)
}
