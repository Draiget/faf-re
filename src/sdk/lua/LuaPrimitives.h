#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(__has_include)
#if __has_include(<lua.h>)
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#elif __has_include(<LuaPlus_Build1081/Src/LuaPlus/include/lua.h>)
#include <LuaPlus_Build1081/Src/LuaPlus/include/lua.h>
#include <LuaPlus_Build1081/Src/LuaPlus/include/lauxlib.h>
#include <LuaPlus_Build1081/Src/LuaPlus/include/lualib.h>
#elif __has_include("../../../dependencies/LuaPlus_Build1081/Src/LuaPlus/include/lua.h")
#include "../../../dependencies/LuaPlus_Build1081/Src/LuaPlus/include/lua.h"
#include "../../../dependencies/LuaPlus_Build1081/Src/LuaPlus/include/lauxlib.h"
#include "../../../dependencies/LuaPlus_Build1081/Src/LuaPlus/include/lualib.h"
#else
#error "Lua headers not found. Add dependencies/LuaPlus_Build1081/Src/LuaPlus/include to include paths."
#endif
#else
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#endif

#ifdef __cplusplus
}
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

#ifndef LUA_ENVIRONINDEX
#define LUA_ENVIRONINDEX LUA_GLOBALSINDEX
#endif

#ifndef lua_upvalueindex
#define lua_upvalueindex(i) (LUA_GLOBALSINDEX - (i))
#endif

// `lua_getn` is a real function in this fork (0x0090AD30), not vanilla Lua's
// alias for luaL_getn (0x0090E870). The two differ: luaL_getn consults the
// "sizes" weak table and then counts up from 1, whereas lua_getn goes straight
// at the table's array and hash parts. Aliasing them made every lua_getn call
// site reach the wrong body.
#ifdef lua_getn
#undef lua_getn
#endif
#ifdef __cplusplus
extern "C"
{
#endif
int lua_getn(lua_State* L, int index);
#ifdef __cplusplus
}
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
	class WriteArchive;
	class ReadArchive;
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

void* lua_getglobaluserdata(lua_State* state);

/**
 * Address: 0x0090DD40 (FUN_0090DD40, luaL_getmetafield)
 *
 * What it does:
 * Looks up one named metafield on the object's metatable, leaving the
 * metatable stack slot consumed on success and restoring the stack on miss.
 */
int luaL_getmetafield(lua_State* L, int obj, const char* event);

/**
 * Address: 0x0091A8D0 (FUN_0091A8D0, luaO_pushfstring)
 *
 * What it does:
 * Starts one varargs lane for `format`, forwards to `luaO_pushvfstring`, and
 * returns the pushed string pointer from that worker.
 */
#ifdef __cplusplus
extern "C"
{
#endif
const char* luaO_pushfstring(lua_State* L, const char* format, ...);
#ifdef __cplusplus
}
#endif

inline moho::Sim* lua_getglobaluserdata_typed(lua_State* state)
{
	return static_cast<moho::Sim*>(::lua_getglobaluserdata(state));
}

// Preserve typed SDK call sites while matching LuaPlus API signature.
#define lua_getglobaluserdata lua_getglobaluserdata_typed

/**
 * Address: 0x0090D430 (FUN_0090D430, lua_call)
 *
 * This fork contains no lua_pcall, no luaD_pcall and no
 * luaD_rawrunprotected - the setjmp machinery was removed and lua_call took
 * over the job. It wraps luaD_call in a C++ try with two handlers: the one at
 * 0x0090D48D returns the caught lua::lua_Error's `code` (read at +0x28, which
 * the constructor at 0x0090DA40 pins with `mov [esi+28h], edx`), and the one
 * at 0x0090D4B0 returns 1 for anything else. So lua_call *is* the protected
 * call here, and it returns a status where vanilla LuaPlus 1081 declares void.
 *
 * The macro is how every call site gets to see the real signature without
 * editing the vendored lua.h, the same shape lua_getglobaluserdata uses above.
 */
/**
 * Address: 0x0090D400 (FUN_0090D400, lua_call)
 * Mangled: ?lua_call@@YAXPAUlua_State@@HH@Z
 *
 * IDA signature:
 * void __cdecl lua_call(lua_State *L, int nargs, int nresults);
 *
 * What it does:
 * The other half of the pair, and the one the LuaPlus surface exports: a bare
 * luaD_call with no handler at all, so an error keeps unwinding to whatever
 * protected boundary the caller sits inside. Engine code that wants a script
 * error to reach the caller - `doscript` above all - calls this one; only the
 * sites that genuinely want to inspect a status code call the protected form.
 */
#ifdef __cplusplus
extern "C"
{
#endif
int LuaCallProtected(lua_State* L, int nargs, int nresults);
void LuaCallUnprotected(lua_State* L, int nargs, int nresults);
#ifdef __cplusplus
}
#endif
#define lua_call LuaCallProtected

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

		/**
		 * Address: 0x009216D0 (FUN_009216D0, TObject::MemberSerialize)
		 *
		 * What it does:
		 * Serializes one tagged Lua value lane into write-archive format,
		 * including named-object indirection and type-specific payload dispatch.
		 */
		static void MemberSerialize(gpg::WriteArchive* archive, TObject* object, int version, gpg::RRef* ownerRef);

		/**
		 * Address: 0x009226F0 (FUN_009226F0, TObject::MemberDeserialize)
		 *
		 * What it does:
		 * Deserializes one tagged Lua value lane from read-archive format,
		 * including named-object lookup and type-specific payload dispatch.
		 */
		static void MemberDeserialize(gpg::ReadArchive* archive, TObject* object, int version, gpg::RRef* ownerRef);
	};

	// `traverseproto` (0x009154A0) walks a Proto's constant array as
	// `[ecx+eax*8]`, so a TObject is 8 bytes; `newkey` (0x00927970) reads the
	// tag as `*(_DWORD *)&mp->i_val.tt` at the start of the object, so `tt`
	// leads. Both are load-bearing for Node's 20-byte stride.
	static_assert(offsetof(TObject, tt) == 0x00, "TObject::tt must be at +0x00");
	static_assert(offsetof(TObject, value) == 0x04, "TObject::value must be at +0x04");
	static_assert(sizeof(TObject) == 0x08, "TObject size must be 0x08");

	using StkId = TObject*;
#pragma pack(pop)
}
