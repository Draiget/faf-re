#pragma once

#include <cstddef>

#include "lua/LuaPrimitives.h"

typedef unsigned __int8 lu_byte;
typedef int ls_nstr;
typedef size_t lu_mem;
typedef unsigned int lu_hash;
typedef int ls_hash;
typedef unsigned int Instruction;
typedef __int64 type_ptrdiff_t;
typedef int(__cdecl* CFunction)(lua_State* L);
typedef void(__cdecl* Hook)(lua_State* L, lua_Debug* ar);
typedef void* (__cdecl* ReallocFunction)(void* ptr, int oldsize, int size, void* data, const char* allocName, unsigned int flags);
typedef void(__cdecl* FreeFunction)(void* ptr, int oldsize, void* data);

struct type_lua_longjmp;

struct GCheader
{
	GCObject* next;      // Intrusive GC list link.
	lu_byte tt;          // Type tag.
	lu_byte marked;      // GC mark/color flags.
};

struct __declspec(align(4)) TString
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	int32_t reserved;    // Header padding / reserved flags in this build.
	lu_hash hash;        // Cached hash for string table lookup.
	size_t len;          // String length in bytes.
	char str[1];         // Flexible array tail.
};

struct Node
{
	LuaPlus::TObject i_key; // Hash key.
	LuaPlus::TObject i_val; // Hash value.
	Node* next;             // Collision chain link.
};

struct Table
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	int32_t reservedAfterHeader;
	int8_t flags;           // Cached "missing TM" bitset.
	lu_byte lsizenode;      // log2(node array size).
	Table* metatable;
	LuaPlus::TObject* array; // Dense integer-key part.
	Node* node;              // Hash node array.
	Node* firstfree;         // First free hash node.
	GCObject* gclist;        // GC gray list link.
	int sizearray;           // Dense array slot count.
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
	int8_t reservedHeader[2];
	lu_byte nupvalues;
	lu_byte isC;
	GCObject* gclist;
	CFunction f;
	lu_byte reservedTail[36]; // Build-specific expansion before upvalue tail.
	LuaPlus::TObject upvalue_m1[1];
	LuaPlus::TObject upvalue[1];
};

struct LocVar
{
	TString* varname;
	int startpc;
	int endpc;
};

// Proto's `int64_t reserved8` forces a natural 8-byte alignment, so any
// `align(4)` here would be silently ignored (C4359). Don't add an alignment
// specifier — the natural alignment is correct and matches the binary layout.
struct Proto
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	LuaPlus::TObject* k; // Constant table.
	Instruction* code;   // Bytecode stream.
	Proto** p;           // Nested function prototypes.
	int* lineinfo;       // PC -> source line map.
	LocVar* locvars;     // Local debug names/ranges.
	TString** upvalues;  // Upvalue names.
	TString* source;     // Defining chunk name.
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
	int32_t reserved0;
	int32_t reserved1;
	int32_t reserved2;
	int32_t reserved3;
	int32_t reserved4;
	int32_t reserved5;
	int32_t reserved6;
	int32_t reserved7;
	int64_t reserved8;
};

struct UpVal
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	LuaPlus::TObject* v; // Points to stack slot when open.
	LuaPlus::TObject value; // Closed value storage.
};

struct LClosure
{
	GCObject* next;
	int32_t tt;
	int32_t marked;
	lu_byte nupvalues;
	int8_t reservedHeader;
	int32_t isC;
	GCObject* gclist;
	LuaPlus::TObject g; // Closure environment/global table.
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
	LuaPlus::StkId base;    // Base stack slot for this frame.
	LuaPlus::StkId top;     // Stack limit for this frame.
	int state;              // CI_* state flags.
	const Instruction* savedpc;
	const Instruction** pc; // Live interpreter PC pointer.
	int32_t reserved0;
	int32_t reserved1;
	int32_t reserved2;
	int tailcalls;          // Number of collapsed tail calls.
	int32_t reserved3;
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
	stringtable strt;            // Interned string table.
	GCObject* rootgc;            // Main GC root list.
	GCObject* rootgc1;           // Secondary GC root list lane (debug traversal).
	GCObject* rootudata;         // Userdata root list.
	Mbuffer buff;                // Scratch concat buffer.
	lu_mem GCthreshold;          // Next GC trigger threshold.
	CFunction panic;             // Panic callback.
	int32_t gcTraversalLockDepth; // GC traversal lock counter used by debug helpers.
	LuaPlus::TObject _registry;  // Registry table.
	LuaPlus::TObject _defaultmeta; // Default table/userdata metatable.
	lua_State* mainthread;       // Main thread.
	lua_State* lstate;           // Currently active thread.
	Node dummynode[1];           // Shared empty-table node.
	TString* tmname[15];         // Interned TM names.
	LuaPlus::TObject _defaultmetatypes[11]; // Default metatable per type tag.
	void* lockDataOrReserved;    // Matches LuaPlus MT support slot (if enabled).
	void* lockFuncOrReserved;    // Matches LuaPlus MT support slot (if enabled).
	void* unlockFuncOrReserved;  // Matches LuaPlus MT support slot (if enabled).
	int32_t unknownFC;
	int32_t unknown100;
	int32_t unknown104;
	int32_t unknown108;
	int32_t unknown10C;
	int32_t unknown110;
	int32_t unknown114;
	int32_t unknown118;
	int8_t unknown11C[24];
	void (*fatalErrorFunc)(void);   // Fatal VM error sink.
	void* memData;                  // Allocator user context.
	ReallocFunction reallocFunc;    // Custom realloc callback.
	FreeFunction freeFunc;          // Custom free callback.
	int minimumstrings;             // String table floor.
	int32_t unknown144;             // Preserves x86 hook-function slot alignment block.
	moho::Sim* globalUserData;      // Engine-owned Lua global userdata.
	void(__cdecl* userGCFunction)(GCState*); // Engine GC callback hook.
	int8_t unknown150;
	lu_byte hookmask;               // Hook event mask (CALL/RET/LINE/COUNT).
	lu_byte allowhook;              // Hook enable gate.
	int8_t unknown153;
	int32_t basehookcount;          // Hook countdown reset value.
	int32_t hookcount;              // Current hook countdown.
	Hook hook;                      // Active debug hook callback.
	int8_t unknown160[88];
};

struct __declspec(align(8)) lua_State
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	LuaPlus::TObject* top;        // First free stack slot.
	LuaPlus::StkId base;          // Base of current function frame.
	global_State* l_G;            // Shared global VM state.
	CallInfo* ci;                 // Current call frame.
	LuaPlus::StkId stack_last;    // Last valid stack slot.
	LuaPlus::StkId stack;         // Stack base.
	int stacksize;                // Allocated stack slots.
	CallInfo* end_ci;             // End of callinfo array.
	CallInfo* base_ci;            // Callinfo array start.
	unsigned __int16 size_ci;     // Number of CallInfo entries.
	unsigned __int16 nCcalls;     // Nested C-call depth.
	LuaPlus::TObject _gt;         // Thread global table reference.
	GCObject* openupval;          // Open upvalue list head.
	GCObject* gclist;             // Thread GC list link.
	unsigned int allocFlags;      // Allocator behavior flags.
	LuaPlus::LuaState* stateUserData; // C++ LuaState wrapper back-pointer.
	// Stock LuaPlus_1081 ends at +0x44. Remaining slots are kept for the
	// engine-linked build variant until each one is proven in gpgcore/moho.
	int32_t unknown48;
	int32_t unknown4C;
	type_lua_longjmp* errorJmp;   // Inferred from legacy Lua 5.0; not re-proven in game binary yet.
	type_ptrdiff_t errfunc;       // Inferred protected-call error handler index.
	const char* allocName;        // Inferred debug allocation tag.
	int32_t unknown5C;
	int32_t unknown60;
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

#if INTPTR_MAX == INT32_MAX
static_assert(offsetof(lua_State, l_G) == 0x10, "lua_State::l_G must be at +0x10 (x86)");
static_assert(offsetof(lua_State, _gt) == 0x30, "lua_State::_gt must be at +0x30 (x86)");
static_assert(offsetof(lua_State, stateUserData) == 0x44, "lua_State::stateUserData must be at +0x44 (x86)");
static_assert(sizeof(CallInfo) == 0x28, "CallInfo must be 0x28 bytes (x86)");

static_assert(offsetof(global_State, rootgc) == 0x0C, "global_State::rootgc must be at +0x0C (x86)");
static_assert(offsetof(global_State, rootgc1) == 0x10, "global_State::rootgc1 must be at +0x10 (x86)");
static_assert(offsetof(global_State, rootudata) == 0x14, "global_State::rootudata must be at +0x14 (x86)");
static_assert(
	offsetof(global_State, gcTraversalLockDepth) == 0x28,
	"global_State::gcTraversalLockDepth must be at +0x28 (x86)"
);
static_assert(offsetof(global_State, lstate) == 0x40, "global_State::lstate must be at +0x40 (x86)");
static_assert(offsetof(global_State, userGCFunction) == 0x14C, "global_State::userGCFunction must be at +0x14C (x86)");
static_assert(offsetof(global_State, hookmask) == 0x151, "global_State::hookmask must be at +0x151 (x86)");
static_assert(offsetof(global_State, basehookcount) == 0x154, "global_State::basehookcount must be at +0x154 (x86)");
static_assert(offsetof(global_State, hookcount) == 0x158, "global_State::hookcount must be at +0x158 (x86)");
static_assert(offsetof(global_State, hook) == 0x15C, "global_State::hook must be at +0x15C (x86)");
#endif
