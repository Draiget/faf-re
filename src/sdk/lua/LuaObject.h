#pragma once

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "legacy/containers/String.h"

#define LUA_MULTRET (-1)

#define LUA_REGISTRYINDEX (-10000)
#define LUA_GLOBALSINDEX (-10001)
#define lua_upvalueindex(i) (LUA_GLOBALSINDEX - (i))

#define LUA_OK 0
#define LUA_ERRRUN 1
#define LUA_ERRFILE 2
#define LUA_ERRSYNTAX 3
#define LUA_ERRMEM 4
#define LUA_ERRERR 5

#define LUA_TNONE (-1)
#define LUA_TNIL 0
#define LUA_TBOOLEAN 1
#define LUA_TLIGHTUSERDATA 2
#define LUA_TNUMBER 3
#define LUA_TSTRING 4
#define LUA_TTABLE 5
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
	class BinaryReader;
}

struct global_State;
union GCObject;

namespace moho
{
	class CMessageStream;
	class Sim;
	class CLuaTask;
}

struct lua_State;

namespace LuaPlus
{
	class LuaState;

	// Keep 4-byte alignment to mirror MSVC x86 layout
#pragma pack(push, 4)

	typedef union {
		void* p;
		float n;
		int b;
	} Value;

	// lua.org/source/5.0/lobject.h.html#TObject
	struct TObject {
		int tt;
		Value value;

		TObject(int value) : tt{ LUA_TNUMBER } { this->value.n = value; }
		TObject(float value) : tt{ LUA_TNUMBER } { this->value.n = value; }
		TObject(bool value) : tt{ LUA_TBOOLEAN } { this->value.b = value; }
		TObject() : tt{ LUA_TNIL } {}
	};

	typedef TObject* StkId;

	class LuaObject
	{
	public:
		class MiniLuaObject
		{
		public:
			LuaObject* m_next;
			LuaObject* m_prev;
		};

		LuaObject() :
			m_next(nullptr),
			m_prev(nullptr),
			m_state(nullptr)
		{
		}

		/**
		 * Address: 0x00908A40
		 * @param other 
		 */
		explicit LuaObject(LuaObject* other) :
			m_next(nullptr),
			m_prev(nullptr),
			m_object(other)
		{
			m_object.tt = LUA_TNIL;
			m_state = other->m_state;
			if (m_state != nullptr) {
				AddToUsedObjectList(m_state, &other->m_object);
			}
		}

		/**
		 * Address: 0x009072B0
		 * @return 
		 */
		LuaState* GetActiveState();

		/**
		 * Address: 0x009088E0
		 * @param state 
		 * @param obj 
		 */
		void AddToUsedObjectList(LuaState* state, TObject* obj);

		/**
		 * Address: 0x00908890
		 *
		 * @param state 
		 */
		void AddToUsedList(LuaState* state);

		/**
		 * Address: 0x009072B0
		 *
		 * Rules:
		 * - false if no state (m_state == nullptr)
		 * - false if type is NIL (tt == 0)
		 * - if type is BOOLEAN, return underlying boolean value
		 * - true for any other non-NIL type
		 */
		explicit operator bool() const noexcept;

		/**
		 * Address: 0x00907D10
		 *
		 * Push this object's value onto the given lua_State stack and return the slot used.
		 * Preconditions:
		 * - Both states must share the same global state (state->l_G == m_state->m_state->l_G).
		 * Behavior:
		 * - Writes m_object into *state->top, returns the address of that slot (old top),
		 *   ensures at least one extra slot (lua_checkstack) if top reached ci->top,
		 *   then increments state->top.
		 */
		StkId PushStack(lua_State* state);

		/**
		 * Address: 0x00909940
		 *
		 * @param state 
		 * @param nArray 
		 * @param lnHash 
		 */
		void AssignNewTable(LuaState* state, int32_t nArray, uint32_t lnHash);

		/**
		 * Address: 0x009096A0
		 *
		 * @param state 
		 * @param number 
		 */
		void AssignNumber(LuaState* state, double number);

		/**
		 * Address: 0x009084E0
		 *
		 * @param index 
		 * @param value 
		 */
		void SetString(int32_t index, const char* value);

		/**
		 * Address: 0x00908450
		 *
		 * @param name 
		 * @param value 
		 */
		void SetString(const char* name, const char* value);

		/**
		 * Address: 0x004D2A40
		 *
		 * @param state 
		 * @param reader 
		 * @return 
		 */
		void SCR_FromByteStream(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader);

	public:
		LuaObject* m_next;
		LuaObject* m_prev;
		LuaState* m_state;
		TObject m_object;
	};
	static_assert(sizeof(LuaObject) == 0x14, "LuaObject must be 0x14");

	class LuaState
	{
	public:
		// Returns raw lua_State* (C API).
		virtual lua_State* GetCState() const = 0;

		// Optional: human-readable typename for diagnostics.
		virtual const char* TypeName() const = 0;

		virtual ~LuaState() = default;

		// Fields are unknown; actual layout is not inferred yet.
		// Keep interface-only wrapper until offsets are proven at runtime.
	public:
		lua_State* m_state;
		moho::CLuaTask* luatask;
		bool m_ownState;
		LuaObject m_threadObj;
		LuaState* m_rootState;
		LuaObject::MiniLuaObject m_headObject;
		LuaObject::MiniLuaObject m_tailObject;
	};


	template <typename T>
	class LuaFunction :
		public LuaObject
	{
	public:
		/**
		 * Address: 0041F910
		 * @param obj
		 */
		LuaFunction(LuaObject obj) :
			LuaObject(obj)
		{
		}

		void operator()(const LuaObject& obj, const char* s, const char* a4, const char* a5) {
			Call(obj, s, a4, a5);
		}
		void operator()(const LuaObject& obj, const char* s, const char* a4, const char* a5) const {
			const_cast<LuaFunction<T>*>(this)->Call(const_cast<LuaObject&>(obj), s, a4, a5);
		}

		void operator()(const LuaObject& obj,
			const msvc8::string& s,
			const msvc8::string& a4,
			const msvc8::string& a5) {
			Call(obj, s.c_str(), a4.c_str(), a5.c_str());
		}
		void operator()(const LuaObject& obj,
			const msvc8::string& s,
			const msvc8::string& a4,
			const msvc8::string& a5) const {
			const_cast<LuaFunction<T>*>(this)->Call(obj, s.c_str(), a4.c_str(), a5.c_str());
		}

		/**
		 * Address: 0x007CC980
		 */
		void Call(LuaObject& obj, const char* s, const char* a4, const char* a5) {
			const LuaState* st = const_cast<LuaFunction<T>*>(this)->GetActiveState();
			if (!st) {
				return;
			}
			lua_State* l = st->GetCState();
			const int savedTop = lua_gettop(l);

			// Push callee and args: [func=this][obj][s][a4][a5]
			PushStack(l);
			obj.PushStack(l);
			lua_pushstring(l, s);
			lua_pushstring(l, a4);
			lua_pushstring(l, a5);

			lua_call(l, 4, 1); // one return value (discarded)
			lua_settop(l, savedTop);
		}

		/**
		 * Address: 0x005FDAB0
		 */
		void Call(LuaObject& obj, const char* arg0) {
			const LuaState* st = const_cast<LuaFunction<T>*>(this)->GetActiveState();
			if (!st) {
				return;
			}
			lua_State* l = st->GetCState();
			const int savedTop = lua_gettop(l);

			PushStack(l);
			obj.PushStack(l);
			lua_pushstring(l, arg0);

			lua_call(l, 2, 1); // one return value (discarded)
			lua_settop(l, savedTop);
		}
	};

	inline LuaState*& g_ConsoleLuaState()
	{
		// Base image has no ASLR in this build.
		static auto** pp = reinterpret_cast<LuaState**>(0x010A6478);
		return *pp;
	}
#pragma pack(pop)
}


typedef unsigned __int8 lu_byte;
typedef int ls_nstr;
typedef size_t lu_mem;
typedef unsigned int lu_hash;
typedef int ls_hash;
typedef unsigned int Instruction;
typedef __int64 type_ptrdiff_t;
typedef int(__cdecl* CFunction)(lua_State* L);
typedef void(__cdecl* Hook)(lua_State* L, void* ar);

typedef void* (__cdecl* ReallocFunction)(void* ptr, int oldsize, int size, void* data, const char* allocName, unsigned int flags);
typedef void(__cdecl* FreeFunction)(void* ptr, int oldsize, void* data);
typedef int(__cdecl* CFunction)(lua_State* L);

struct GCheader
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
};

struct __declspec(align(4)) TString
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	int32_t reserved;
	lu_hash hash;
	size_t len;
	char str[1];
};

struct Node
{
	LuaPlus::TObject i_key;
	LuaPlus::TObject i_val;
	Node* next;
};

struct Table
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	int32_t gap;
	int8_t flags;
	lu_byte lsizenode;
	Table* metatable;
	LuaPlus::TObject* array;
	Node* node;
	Node* firstfree;
	GCObject* gclist;
	int sizearray;
};

struct Udata
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	Table* metatable;
	size_t len;
};

struct CClosure
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	int8_t gap1[2];
	lu_byte nupvalues;
	lu_byte isC;
	GCObject* gclist;
	CFunction f;
	lu_byte gap2[36];
	LuaPlus::TObject upvalue_m1[1];
	LuaPlus::TObject upvalue[1];
};

struct LocVar
{
	TString* varname;
	int startpc;
	int endpc;
};

struct __declspec(align(4)) Proto
{
  GCObject * next;
  lu_byte tt;
  lu_byte marked;
  __declspec(align(4)) LuaPlus::TObject* k;
  Instruction* code;
  Proto** p;
  int* lineinfo;
  LocVar* locvars;
  TString** upvalues;
  TString* source;
  int sizeupvalues;
  int sizek;
  int sizecode;
  int sizelineinfo;
  int sizep;
  int sizelocvars;
  int lineDefined;
  GCObject* gclist;
  lu_byte nups;
  lu_byte numparams;
  lu_byte is_vararg;
  lu_byte maxstacksize;
  int32_t v0;
  int32_t v1;
  int32_t v2;
  int32_t v3;
  int32_t v4;
  int32_t v5;
  int32_t v6;
  int32_t v7;
  int64_t v8;
};

struct UpVal
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	LuaPlus::TObject* v;
	LuaPlus::TObject value;
};

struct LClosure
{
	GCObject* next;
	int32_t tt;
	int32_t marked;
	lu_byte nupvalues;
	int8_t gap1;
	int32_t isC;
	GCObject* gclist;
	LuaPlus::TObject g;
	Proto* p;
	UpVal* upvals[3];
};

union Closure
{
	CClosure c;
	LClosure l;
};

struct CallInfo
{
	LuaPlus::StkId base;
	LuaPlus::StkId top;
	int state;
	const Instruction* savedpc;
	const Instruction** pc;
	int32_t v0;
	int32_t v1;
	int32_t v2;
	int tailcalls;
	int32_t v3;
};

struct Mbuffer
{
	char* buffer;
	size_t buffsize;
};

struct stringtable
{
	GCObject** hash;
	ls_nstr nuse;
	int size;
};

struct GCState
{
	GCObject* tmark;
	GCObject* wk;
	GCObject* wv;
	GCObject* wkv;
	global_State* g;
	lua_State* L;
};

struct global_State
{
	stringtable strt;
	GCObject* rootgc;
	GCObject* rootgc1;
	GCObject* rootudata;
	GCObject* tmudata;
	Mbuffer buff;
	lu_mem GCthreshold;
	CFunction panic;
	int32_t nblocks;
	LuaPlus::TObject _registry;
	LuaPlus::TObject _defaultmeta;
	lua_State* mainthread;
	lua_State* lstate;
	Node dummynode[1];
	TString* tmname[15];
	LuaPlus::TObject _defaultmetatypes[11];
	int32_t gap3;
	int32_t gapF4;
	int32_t gapF8;
	int32_t gapFC;
	int32_t gap100;
	int32_t gap104;
	int32_t gap108;
	int32_t gap10C;
	int32_t gap110;
	int32_t gap114;
	int32_t gap118;
	int8_t gap11C[24];
	void (*fatalErrorFunc)(void);
	void* memData;
	ReallocFunction reallocFunc;
	FreeFunction freeFunc;
	int minimumstrings;
	moho::Sim* globalUserData;
	void(__cdecl* userGCFunction)(GCState*);
	int8_t gap4[1];
	lu_byte hookmask;
	lu_byte allowhook;
	int8_t gap5[1];
	int32_t basehookcount;
	int32_t hookcount;
	Hook hook;
	int8_t gapend[88];
};

struct __declspec(align(8)) lua_State
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	LuaPlus::TObject* top;
	LuaPlus::StkId base;
	global_State* l_G;
	CallInfo* ci;
	LuaPlus::StkId stack_last;
	LuaPlus::StkId stack;
	int stacksize;
	CallInfo* end_ci;
	CallInfo* base_ci;
	unsigned __int16 size_ci;
	unsigned __int16 nCcalls;
	LuaPlus::TObject _gt;
	GCObject* openupval;
	GCObject* gclist;
	unsigned int allocFlags;
	LuaPlus::LuaState* stateUserData;
	int32_t gap2[2];
	struct type_lua_longjmp* errorJmp;
	type_ptrdiff_t errfunc;
	const char* allocName;
	int hookcount;
	int32_t gap3;
};

union GCObject
{
	GCheader gch;
	TString ts;
	Udata u;
	Closure cl;
	Table h;
	Proto p;
	UpVal uv;
	lua_State th;
};