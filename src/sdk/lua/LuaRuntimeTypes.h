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
	lu_byte commonHeaderPad[2]; // +0x06 CommonHeader tail padding in this fork.

	/**
	 * Reserved-word index, one-based, or 0 for an ordinary string.
	 *
	 * A SINGLE BYTE, and it must stay one. `newlstr` (0x00924860) clears it
	 * with `mov byte ptr [esi+8], 0` and `luaX_init` (0x009180D0) sets it with
	 * `*((_BYTE *)v2 + 8) = i` - neither ever touches +0x09..+0x0B, so those
	 * three bytes hold whatever the allocator left. Widening this field to an
	 * int32 reads that garbage: it made ordinary identifiers come back with a
	 * non-zero `reserved`, so the lexer returned `reserved + FIRST_RESERVED-1`
	 * instead of TK_NAME and every `local <name>` after one could fail.
	 */
	lu_byte reserved;
	lu_byte reservedPad[3];     // +0x09 never written by the binary.

	lu_hash hash;        // Cached hash for string table lookup.
	size_t len;          // String length in bytes.
	char str[1];         // Flexible array tail.
};
static_assert(offsetof(TString, tt) == 0x04, "TString::tt must be at +0x04");
static_assert(offsetof(TString, marked) == 0x05, "TString::marked must be at +0x05");
static_assert(offsetof(TString, reserved) == 0x08, "TString::reserved must be at +0x08");
static_assert(offsetof(TString, hash) == 0x0C, "TString::hash must be at +0x0C");
static_assert(offsetof(TString, len) == 0x10, "TString::len must be at +0x10");
// `newlstr` allocates `len + 0x15`: a 20-byte header plus the NUL terminator.
static_assert(offsetof(TString, str) == 0x14, "TString::str must be at +0x14");

struct Node
{
	LuaPlus::TObject i_key; // Hash key.
	LuaPlus::TObject i_val; // Hash value.
	Node* next;             // Collision chain link.
};

struct Table
{
	GCObject* next;          // +0x00
	lu_byte tt;              // +0x04
	lu_byte marked;          // +0x05
	lu_byte reservedAfterHeader[2]; // +0x06 CommonHeader tail padding in this fork.
	int8_t flags;            // +0x08 Cached "missing TM" bitset.
	lu_byte lsizenode;       // +0x09 log2(node array size).
	// +0x0A..0x0B implicit padding before the pointer lanes.
	Table* metatable;        // +0x0C
	LuaPlus::TObject* array; // +0x10 Dense integer-key part.
	Node* node;              // +0x14 Hash node array.
	Node* firstfree;         // +0x18 First free hash node.
	GCObject* gclist;        // +0x1C GC gray list link.
	int sizearray;           // +0x20 Dense array slot count.

	/**
	 * Address: 0x00920530 (FUN_00920530, Table::MemberSerialize)
	 *
	 * What it does:
	 * Serializes one table metatable pointer lane, dense array payload lanes,
	 * and non-empty hash key/value lanes using the archive owner context.
	 */
	static void MemberSerialize(gpg::WriteArchive* archive, Table* object, int version, const gpg::RRef* ownerRef);

	/**
	 * Address: 0x00922950 (FUN_00922950, Table::MemberDeserialize)
	 *
	 * What it does:
	 * Deserializes one Lua table metatable pointer lane, dense array payload
	 * lanes, and hashed key/value lanes under owner GC traversal lock.
	 */
	static void MemberDeserialize(gpg::ReadArchive* archive, Table* object, int version, const gpg::RRef& ownerRef);

	static gpg::RType* sType;
};

// Layout confirmed from the binary, not inferred: luaH_new (FUN_00927320)
// stores metatable/array/node/sizearray/lsizenode at these displacements and
// allocates the object with luaM_realloc(L, 0, 0, 0x24), and luaH_getnum
// (FUN_00927450) reads [esi+20h] for sizearray, [esi+10h] for array,
// [esi+14h] for node and [esi+9] for lsizenode. flags is the
// "mov byte ptr [esi+8], 0FFh" (t->flags = -1) at 0x00927350.
static_assert(offsetof(Table, flags) == 0x08, "Table::flags must be at +0x08");
static_assert(offsetof(Table, lsizenode) == 0x09, "Table::lsizenode must be at +0x09");
static_assert(offsetof(Table, metatable) == 0x0C, "Table::metatable must be at +0x0C");
static_assert(offsetof(Table, array) == 0x10, "Table::array must be at +0x10");
static_assert(offsetof(Table, node) == 0x14, "Table::node must be at +0x14");
static_assert(offsetof(Table, firstfree) == 0x18, "Table::firstfree must be at +0x18");
static_assert(offsetof(Table, gclist) == 0x1C, "Table::gclist must be at +0x1C");
static_assert(offsetof(Table, sizearray) == 0x20, "Table::sizearray must be at +0x20");
static_assert(sizeof(Table) == 0x24, "Table size must be 0x24 (luaH_new allocates 0x24)");

struct Udata
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	Table* metatable;
	/// Reused by this fork to carry the object's `gpg::RType*` rather than a
	/// byte count - see LuaObject::GetUserData (0x00907BC0), which reads it
	/// from +0x0C and takes the payload from +0x10.
	size_t len;

	/**
	 * Address: 0x009207E0 (FUN_009207E0, Udata::MemberSerialize)
	 *
	 * What it does:
	 * Serializes userdata metatable pointer lane and typed payload bytes using
	 * one owning Lua thread reference as archive owner context.
	 */
	static void MemberSerialize(gpg::WriteArchive* archive, Udata* object, int version, gpg::RRef* ownerRef);

	/**
	 * Address: 0x00923170 (FUN_00923170, Udata::MemberDeserialize)
	 *
	 * What it does:
	 * Deserializes userdata metatable pointer lane and payload bytes under one
	 * owning Lua thread traversal lock context.
	 */
	static void MemberDeserialize(gpg::ReadArchive* archive, Udata* object, int version, const gpg::RRef& ownerRef);
};
static_assert(offsetof(Udata, metatable) == 0x08, "Udata::metatable offset must be 0x08");
static_assert(offsetof(Udata, len) == 0x0C, "Udata::len offset must be 0x0C");
static_assert(sizeof(Udata) == 0x10, "Udata size must be 0x10");

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

	/**
	 * Address: 0x00920E40 (FUN_00920E40, Proto::MemberSerialize)
	 *
	 * What it does:
	 * Serializes proto scalar metadata, constants/code/nested-proto lanes, and
	 * debug name/source pointer lanes under the owning thread archive context.
	 */
	static void MemberSerialize(gpg::WriteArchive* archive, Proto* object, int version, gpg::RRef* ownerRef);

	/**
	 * Address: 0x00922B20 (FUN_00922B20, Proto::MemberDeserialize)
	 *
	 * What it does:
	 * Deserializes proto scalar metadata, constants/code/nested-proto lanes,
	 * and debug name/source pointer lanes, then validates bytecode consistency.
	 */
	static void MemberDeserialize(gpg::ReadArchive* archive, Proto* object, int version, gpg::RRef* ownerRef);

	static gpg::RType* sType;
};

struct UpVal
{
	GCObject* next;
	lu_byte tt;
	lu_byte marked;
	LuaPlus::TObject* v; // Points to stack slot when open.
	LuaPlus::TObject value; // Closed value storage.
};

// Shares its header with CClosure: tt/marked are single bytes like every other
// collectable, and nupvalues/isC sit at +0x08/+0x09. The previous model made
// tt and marked int32, which pushed p to +0x20 and the upvalue array to +0x24 -
// every `cl.l.p` read was landing on the wrong field.
struct LClosure
{
	GCObject* next;                  // +0x00
	lu_byte tt;                      // +0x04
	lu_byte marked;                  // +0x05
	lu_byte reservedAfterHeader[2];  // +0x06 CommonHeader tail padding.
	lu_byte nupvalues;               // +0x08
	lu_byte isC;                     // +0x09
	lu_byte reservedAfterCounts[2];  // +0x0A
	GCObject* gclist;                // +0x0C
	LuaPlus::TObject g;              // +0x10 Closure environment/global table.
	Proto* p;                        // +0x18
	UpVal* upvals[1];                // +0x1C Flexible tail, one pointer each.

	/**
	 * Address: 0x00920DA0 (FUN_00920DA0, LClosure::MemberSerialize)
	 *
	 * What it does:
	 * Serializes one closure's proto pointer, global-object lane, and upvalue
	 * pointer array lanes under the owning thread archive context.
	 */
	static void MemberSerialize(gpg::WriteArchive* archive, LClosure* object, int version, const gpg::RRef* ownerRef);

	/**
	 * Address: 0x00922AB0 (FUN_00922AB0, LClosure::MemberDeserialize)
	 *
	 * What it does:
	 * Deserializes prototype/global-object/upvalue pointer lanes for one
	 * Lua closure object.
	 */
	static void MemberDeserialize(gpg::ReadArchive* archive, LClosure* object, int version, const gpg::RRef& ownerRef);
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

// Every offset below is pinned by a concrete instruction in the shipped
// binary; see the static_assert block after lua_State for the citations. The
// struct previously modelled the head region four bytes short (no `tmudata`
// lane), which pushed `buff` through `_defaultmetatypes` onto the wrong slots
// and made `_registry`/`_defaultmeta` alias each other's halves.
struct global_State
{
	stringtable strt;            // +0x00 Interned string table.
	GCObject* rootgc;            // +0x0C Main GC root list.
	GCObject* rootgc1;           // +0x10 Secondary GC root list lane (debug traversal).
	GCObject* rootudata;         // +0x14 Userdata root list.
	GCObject* tmudata;           // +0x18 Userdata queued for finalization.
	Mbuffer buff;                // +0x1C Scratch concat buffer.
	lu_mem GCthreshold;          // +0x24 Next GC trigger threshold.
	int32_t gcTraversalLockDepth; // +0x28 GC traversal lock counter used by debug helpers.
	lu_mem nblocks;              // +0x2C Bytes currently allocated.
	LuaPlus::TObject _registry;  // +0x30 Registry table.
	LuaPlus::TObject _defaultmeta; // +0x38 Default table/userdata metatable.
	lua_State* mainthread;       // +0x40 Main thread.
	lua_State* lstate;           // +0x44 Currently active thread.
	Node dummynode[1];           // +0x48 Shared empty-table node.
	TString* tmname[18];         // +0x5C Interned tag-method names.
	TString* typenames[12];      // +0xA4 Interned type-name strings, indexed by tag.
	LuaPlus::TObject _defaultmetatypes[12]; // +0xD4 Default metatable per type tag.
	void (*fatalErrorFunc)(void);   // +0x134 Fatal VM error sink.
	void* memData;                  // +0x138 Allocator user context.
	ReallocFunction reallocFunc;    // +0x13C Custom realloc callback.
	FreeFunction freeFunc;          // +0x140 Custom free callback.
	int minimumstrings;             // +0x144 String table floor.
	moho::Sim* globalUserData;      // +0x148 Engine-owned Lua global userdata.
	void(__cdecl* userGCFunction)(GCState*); // +0x14C Engine GC callback hook.
	lu_byte allocationTrackingEnabled; // +0x150 Debug allocation-tracking gate.
	lu_byte hookmask;               // +0x151 Hook event mask (CALL/RET/LINE/COUNT).
	lu_byte allowhook;              // +0x152 Hook enable gate.
	lu_byte reservedAfterAllowHook; // +0x153 Padding to the hook-count block.
	int32_t basehookcount;          // +0x154 Hook countdown reset value.
	int32_t hookcount;              // +0x158 Current hook countdown.
	Hook hook;                      // +0x15C Active debug hook callback.
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

	/**
	 * Address: 0x00921050 (FUN_00921050, lua_State::MemberSerialize)
	 *
	 * What it does:
	 * Serializes raw VM stack/callframe/global/upvalue lanes for one
	 * `lua_State` runtime object.
	 */
	static void MemberSerialize(
		gpg::WriteArchive* archive,
		lua_State* state,
		int version,
		const gpg::RRef* ownerRef
	);

	/**
	 * Address: 0x00922DD0 (FUN_00922DD0, lua_State::MemberDeserialize)
	 *
	 * What it does:
	 * Restores one Lua thread stack/callframe/global/upvalue lane set from a
	 * serialized archive payload.
	 */
	static void MemberDeserialize(
		gpg::ReadArchive* archive,
		lua_State* state,
		int version,
		gpg::RRef* ownerRef
	);

	// The object ends at +0x48: lua_open (FUN_009246D0) allocates it with
	// "push 48h" -> luaM_realloc, and f_luaopen stores
	// sizeof(lua_State) + sizeof(global_State) into nblocks as 0x1A8, which
	// leaves exactly 0x1A8 - 0x160 = 0x48 for this struct. It used to carry
	// 0x20 bytes of unproven trailing slots (errorJmp/errfunc/allocName and
	// filler), so any write through them landed past the real allocation.
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
static_assert(sizeof(lua_State) == 0x48, "lua_State must be 0x48 bytes (lua_open allocates 0x48)");
static_assert(sizeof(CallInfo) == 0x28, "CallInfo must be 0x28 bytes (x86)");

// LClosure. luaF_newLclosure (FUN_00914EF0) allocates "lea eax, ds:1Ch[ebx*4]"
// - 0x1C plus four bytes per upvalue - so the upvalue array starts at 0x1C. It
// then writes nupvalues with "mov [esi+8], bl" and the environment TObject with
// "mov [esi+10h], ecx" / "mov [esi+14h], edx". p at 0x18 is confirmed twice
// over: luaD_precall reads "mov edx,[ebp+4]" / "mov edi,[edx+18h]", and
// luaF_getlocalname reads "mov ebx,[ecx+18h]".
static_assert(offsetof(LClosure, nupvalues) == 0x08, "LClosure::nupvalues must be at +0x08 (x86)");
static_assert(offsetof(LClosure, gclist) == 0x0C, "LClosure::gclist must be at +0x0C (x86)");
static_assert(offsetof(LClosure, g) == 0x10, "LClosure::g must be at +0x10 (x86)");
static_assert(offsetof(LClosure, p) == 0x18, "LClosure::p must be at +0x18 (x86)");
static_assert(offsetof(LClosure, upvals) == 0x1C, "LClosure::upvals must be at +0x1C (x86)");

// global_State head region. Each offset below is taken from a single named
// instruction rather than inferred from neighbouring fields.
//   strt.nuse/.size   checkSizes  (FUN_00915AA0) "mov eax,[ecx+8]" / "cmp [ecx+4],eax"
//   rootgc/rootgc1/rootudata/tmudata
//                     f_luaopen   (FUN_00924470) zeroes +0x0C/+0x10/+0x14/+0x18
//   buff              checkSizes  "mov edx,[eax+1Ch]" (buffer) / "cmp [ecx+20h],40h" (buffsize)
//   GCthreshold       lua_getgcthreshold (FUN_0090D650) "mov eax,[ecx+24h]; shr eax,0Ah"
//   gcTraversalLock   FUN_009136F0 "add dword ptr [edi+28h],1" / "...,0FFFFFFFFh"
//   nblocks           lua_getgccount (FUN_0090D660) "mov eax,[ecx+2Ch]; shr eax,0Ah"
//   _registry         negindex    (FUN_0090C340) LUA_REGISTRYINDEX returns
//                     "mov eax,[eax+10h]; add eax,30h", and the
//                     registry-by-integer lane reads the table out of
//                     "mov eax,[edx+34h]" - so tt is 0x30, value 0x34
//   _defaultmeta      lua_setmetatable (FUN_0090D340) falls back to
//                     "mov ecx,[esi+10h]; add ecx,38h" when the pushed value
//                     is nil, which is stock Lua's defaultmeta(L)
//   mainthread        markroot    "mov edi,[ecx+40h]" -> traversestack
//   lstate            f_luaopen   "mov [ebp+44h],esi" (the second thread slot)
//   dummynode         f_luaopen   zeroes +0x48/+0x50/+0x58 = i_key.tt / i_val.tt / next
//   tmname[18]        luaT_init   (FUN_009283C0) esi = 0x5C, step 4, "cmp esi,0A4h; jl"
//   typenames[12]     luaB_type   (FUN_0090F270) "mov ecx,[edx+ecx*4+0A4h]"
//   _defaultmetatypes[12]
//                     luaT_gettmbyobj (FUN_00928450) "lea eax,[ecx+eax*8+0D4h]";
//                     markroot loops esi = 0xD8..0x138 step 8 over the value halves
static_assert(offsetof(global_State, rootgc) == 0x0C, "global_State::rootgc must be at +0x0C (x86)");
static_assert(offsetof(global_State, rootgc1) == 0x10, "global_State::rootgc1 must be at +0x10 (x86)");
static_assert(offsetof(global_State, rootudata) == 0x14, "global_State::rootudata must be at +0x14 (x86)");
static_assert(offsetof(global_State, tmudata) == 0x18, "global_State::tmudata must be at +0x18 (x86)");
static_assert(offsetof(global_State, buff) == 0x1C, "global_State::buff must be at +0x1C (x86)");
static_assert(offsetof(global_State, GCthreshold) == 0x24, "global_State::GCthreshold must be at +0x24 (x86)");
static_assert(
	offsetof(global_State, gcTraversalLockDepth) == 0x28,
	"global_State::gcTraversalLockDepth must be at +0x28 (x86)"
);
static_assert(offsetof(global_State, nblocks) == 0x2C, "global_State::nblocks must be at +0x2C (x86)");
static_assert(offsetof(global_State, _registry) == 0x30, "global_State::_registry must be at +0x30 (x86)");
static_assert(offsetof(global_State, _defaultmeta) == 0x38, "global_State::_defaultmeta must be at +0x38 (x86)");
static_assert(offsetof(global_State, mainthread) == 0x40, "global_State::mainthread must be at +0x40 (x86)");
static_assert(offsetof(global_State, lstate) == 0x44, "global_State::lstate must be at +0x44 (x86)");
static_assert(offsetof(global_State, dummynode) == 0x48, "global_State::dummynode must be at +0x48 (x86)");
static_assert(offsetof(global_State, tmname) == 0x5C, "global_State::tmname must be at +0x5C (x86)");
static_assert(offsetof(global_State, typenames) == 0xA4, "global_State::typenames must be at +0xA4 (x86)");
static_assert(
	offsetof(global_State, _defaultmetatypes) == 0xD4,
	"global_State::_defaultmetatypes must be at +0xD4 (x86)"
);
static_assert(offsetof(global_State, fatalErrorFunc) == 0x134, "global_State::fatalErrorFunc must be at +0x134 (x86)");
static_assert(offsetof(global_State, memData) == 0x138, "global_State::memData must be at +0x138 (x86)");
static_assert(offsetof(global_State, reallocFunc) == 0x13C, "global_State::reallocFunc must be at +0x13C (x86)");
static_assert(offsetof(global_State, freeFunc) == 0x140, "global_State::freeFunc must be at +0x140 (x86)");
static_assert(offsetof(global_State, minimumstrings) == 0x144, "global_State::minimumstrings must be at +0x144 (x86)");
static_assert(offsetof(global_State, globalUserData) == 0x148, "global_State::globalUserData must be at +0x148 (x86)");
static_assert(offsetof(global_State, userGCFunction) == 0x14C, "global_State::userGCFunction must be at +0x14C (x86)");
static_assert(
	offsetof(global_State, allocationTrackingEnabled) == 0x150,
	"global_State::allocationTrackingEnabled must be at +0x150 (x86)"
);
static_assert(offsetof(global_State, hookmask) == 0x151, "global_State::hookmask must be at +0x151 (x86)");
static_assert(offsetof(global_State, allowhook) == 0x152, "global_State::allowhook must be at +0x152 (x86)");
static_assert(offsetof(global_State, basehookcount) == 0x154, "global_State::basehookcount must be at +0x154 (x86)");
static_assert(offsetof(global_State, hookcount) == 0x158, "global_State::hookcount must be at +0x158 (x86)");
static_assert(offsetof(global_State, hook) == 0x15C, "global_State::hook must be at +0x15C (x86)");
// f_luaopen (FUN_00924470) allocates the object with
// luaM_realloc(&thread, 0, 0, 0x160u), and its last field write is
// "mov [ebp+15Ch], ebx" (hook). The struct therefore ends at 0x160. The same
// function then stores sizeof(lua_State) + sizeof(global_State) into nblocks
// as the literal 0x1A8, which cross-checks 0x160 against lua_State's 0x48.
static_assert(sizeof(global_State) == 0x160, "global_State must be 0x160 bytes (f_luaopen allocates 0x160)");
#endif
