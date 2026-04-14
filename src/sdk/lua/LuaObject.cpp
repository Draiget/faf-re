#include "LuaObject.h"

#include <cerrno>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <io.h>
#include <limits>
#include <new>
#include <sstream>
#include <string>
#include <stdexcept>

#include "LuaAssertion.h"
#include "LuaTableIterator.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"

using namespace LuaPlus;

extern "C" void __cdecl _free_crt(void* ptr);

/**
 * Address: 0x00923F20 (FUN_00923F20, luaHelper_ReallocFunction)
 *
 * What it does:
 * Reallocates one Lua helper buffer lane through CRT `realloc`.
 */
[[nodiscard]] void* luaHelper_ReallocFunction(LuaPlus::LuaState* const ptr, const int, const unsigned int size)
{
	return std::realloc(ptr, static_cast<std::size_t>(size));
}

/**
 * Address: 0x00923F40 (FUN_00923F40, luaHelper_FreeFunction)
 *
 * What it does:
 * Releases one Lua helper allocation lane through CRT `_free_crt`.
 */
void luaHelper_FreeFunction(void* const ptr)
{
	_free_crt(ptr);
}

class TableSerializer
{
public:
	/**
	 * Address: 0x009233B0 (FUN_009233B0, init_TableSerializer)
	 *
	 * What it does:
	 * Initializes one table serializer helper runtime object by wiring intrusive
	 * helper links and binding table deserialize/serialize callback lanes.
	 */
	static TableSerializer* Initialize(TableSerializer* serializer);

	/**
	 * Address: 0x009233A0 (FUN_009233A0, TableSerializer::Deserialize)
	 *
	 * What it does:
	 * Forwards one serialized table payload into `Table::MemberDeserialize`
	 * using caller-provided owner reference lane.
	 */
	static void Deserialize(gpg::ReadArchive* archive, Table* object, int version, gpg::RRef* ownerRef);

	/**
	 * Address: 0x00920A50 (FUN_00920A50, TableSerializer::Serialize)
	 *
	 * What it does:
	 * Forwards one table serialization payload into `Table::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, Table* object, int version, gpg::RRef* ownerRef);

	virtual void RegisterSerializeFunctions();

	gpg::SerHelperBase* mHelperNext;
	gpg::SerHelperBase* mHelperPrev;
	gpg::RType::load_func_t mDeserialize;
	gpg::RType::save_func_t mSerialize;
};

static_assert(offsetof(TableSerializer, mHelperNext) == 0x04, "TableSerializer::mHelperNext offset must be 0x04");
static_assert(offsetof(TableSerializer, mHelperPrev) == 0x08, "TableSerializer::mHelperPrev offset must be 0x08");
static_assert(offsetof(TableSerializer, mDeserialize) == 0x0C, "TableSerializer::mDeserialize offset must be 0x0C");
static_assert(offsetof(TableSerializer, mSerialize) == 0x10, "TableSerializer::mSerialize offset must be 0x10");
static_assert(sizeof(TableSerializer) == 0x14, "TableSerializer size must be 0x14");

/**
 * Address: 0x009233B0 (FUN_009233B0, init_TableSerializer)
 *
 * What it does:
 * Initializes one table serializer helper runtime object by wiring intrusive
 * helper links and binding table deserialize/serialize callback lanes.
 */
TableSerializer* TableSerializer::Initialize(TableSerializer* serializer)
{
	if (serializer == nullptr) {
		return nullptr;
	}
	serializer = new (serializer) TableSerializer();

	auto* const self = reinterpret_cast<gpg::SerHelperBase*>(&serializer->mHelperNext);
	serializer->mHelperNext = self;
	serializer->mHelperPrev = self;
	serializer->mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&TableSerializer::Deserialize);
	serializer->mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&TableSerializer::Serialize);
	return serializer;
}

void TableSerializer::RegisterSerializeFunctions() {}

/**
 * Address: 0x009233A0 (FUN_009233A0, TableSerializer::Deserialize)
 *
 * What it does:
 * Forwards one serialized table payload into `Table::MemberDeserialize`.
 */
void TableSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	Table* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	Table::MemberDeserialize(archive, object, version, *ownerRef);
}

/**
 * Address: 0x00920A50 (FUN_00920A50, TableSerializer::Serialize)
 *
 * What it does:
 * Forwards one table serialization payload into `Table::MemberSerialize`.
 */
void TableSerializer::Serialize(
	gpg::WriteArchive* const archive,
	Table* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	Table::MemberSerialize(archive, object, version, ownerRef);
}

class LClosureSerializer
{
public:
	/**
	 * Address: 0x00921370 (FUN_00921370, LClosureSerializer::Serialize)
	 *
	 * What it does:
	 * Forwards one closure save lane into `LClosure::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, LClosure* object, int version, const gpg::RRef* ownerRef);

	/**
	 * Address: 0x00923430 (FUN_00923430, LClosureSerializer::Deserialize)
	 *
	 * What it does:
	 * Forwards one serialized closure payload into `LClosure::MemberDeserialize`
	 * using the provided archive owner reference lane.
	 */
	static void Deserialize(gpg::ReadArchive* archive, LClosure* object, int version, gpg::RRef* ownerRef);
};

class ProtoSerializer
{
public:
	/**
	 * Address: 0x009213C0 (FUN_009213C0, ProtoSerializer::Serialize)
	 *
	 * What it does:
	 * Forwards one proto save lane into `Proto::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, Proto* object, int version, gpg::RRef* ownerRef);
};

class lua_StateSerializer
{
public:
	/**
	 * Address: 0x009213F0 (FUN_009213F0, lua_StateSerializer::Serialize)
	 *
	 * What it does:
	 * Forwards one Lua thread save lane into `lua_State::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, lua_State* state, int version, const gpg::RRef* ownerRef);
};

class TObjectSerializer
{
public:
	/**
	 * Address: 0x00921FC0 (FUN_00921FC0, TObjectSerializer::Serialize)
	 *
	 * What it does:
	 * Forwards one tagged Lua value save lane into `TObject::MemberSerialize`.
	 */
	static void Serialize(gpg::WriteArchive* archive, TObject* object, int version, gpg::RRef* ownerRef);

	/**
	 * Address: 0x00923250 (FUN_00923250, TObjectSerializer::Deserialize)
	 *
	 * What it does:
	 * Forwards one tagged Lua value load lane into `TObject::MemberDeserialize`.
	 */
	static void Deserialize(gpg::ReadArchive* archive, TObject* object, int version, gpg::RRef* ownerRef);
};

/**
 * Address: 0x00921370 (FUN_00921370, LClosureSerializer::Serialize)
 *
 * What it does:
 * Forwards one closure save lane into `LClosure::MemberSerialize`.
 */
void LClosureSerializer::Serialize(
	gpg::WriteArchive* const archive,
	LClosure* const object,
	const int version,
	const gpg::RRef* const ownerRef
)
{
	LClosure::MemberSerialize(archive, object, version, ownerRef);
}

void LClosureSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	LClosure* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	const gpg::RRef nullOwner{};
	LClosure::MemberDeserialize(archive, object, version, ownerRef != nullptr ? *ownerRef : nullOwner);
}

/**
 * Address: 0x009213C0 (FUN_009213C0, ProtoSerializer::Serialize)
 *
 * What it does:
 * Forwards one proto save lane into `Proto::MemberSerialize`.
 */
void ProtoSerializer::Serialize(
	gpg::WriteArchive* const archive,
	Proto* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	Proto::MemberSerialize(archive, object, version, ownerRef);
}

/**
 * Address: 0x009213F0 (FUN_009213F0, lua_StateSerializer::Serialize)
 *
 * What it does:
 * Forwards one Lua thread save lane into `lua_State::MemberSerialize`.
 */
void lua_StateSerializer::Serialize(
	gpg::WriteArchive* const archive,
	lua_State* const state,
	const int version,
	const gpg::RRef* const ownerRef
)
{
	lua_State::MemberSerialize(archive, state, version, ownerRef);
}

/**
 * Address: 0x00921FC0 (FUN_00921FC0, TObjectSerializer::Serialize)
 *
 * What it does:
 * Forwards one tagged Lua value save lane into `TObject::MemberSerialize`.
 */
void TObjectSerializer::Serialize(
	gpg::WriteArchive* const archive,
	TObject* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	TObject::MemberSerialize(archive, object, version, ownerRef);
}

/**
 * Address: 0x00923250 (FUN_00923250, TObjectSerializer::Deserialize)
 *
 * What it does:
 * Forwards one tagged Lua value load lane into `TObject::MemberDeserialize`.
 */
void TObjectSerializer::Deserialize(
	gpg::ReadArchive* const archive,
	TObject* const object,
	const int version,
	gpg::RRef* const ownerRef
)
{
	TObject::MemberDeserialize(archive, object, version, ownerRef);
}

namespace
{
	struct LuaGlobalStateGcRuntimeView
	{
		std::uint8_t reserved00[0x24];
		std::uint32_t gcThreshold;
		void* panicFunction;
		std::uint32_t allocatedBytes;
	};

	static_assert(
		offsetof(LuaGlobalStateGcRuntimeView, gcThreshold) == 0x24,
		"LuaGlobalStateGcRuntimeView::gcThreshold offset must be 0x24"
	);
	static_assert(
		offsetof(LuaGlobalStateGcRuntimeView, panicFunction) == 0x28,
		"LuaGlobalStateGcRuntimeView::panicFunction offset must be 0x28"
	);
	static_assert(
		offsetof(LuaGlobalStateGcRuntimeView, allocatedBytes) == 0x2C,
		"LuaGlobalStateGcRuntimeView::allocatedBytes offset must be 0x2C"
	);

	struct LuaGlobalStateUserdataRuntimeView
	{
		std::uint8_t reserved00[0x14];
		GCObject* rootUserdata;
		std::uint8_t reserved18To117[0x100];
		Table* userdataMetatable;
	};
	static_assert(
		offsetof(LuaGlobalStateUserdataRuntimeView, rootUserdata) == 0x14,
		"LuaGlobalStateUserdataRuntimeView::rootUserdata offset must be 0x14"
	);
	static_assert(
		offsetof(LuaGlobalStateUserdataRuntimeView, userdataMetatable) == 0x118,
		"LuaGlobalStateUserdataRuntimeView::userdataMetatable offset must be 0x118"
	);

	struct LuaFuncStateCodegenRuntimeView
	{
		Proto* functionProto;
		std::uint8_t reserved04To0B[0x08];
		void* lexState;
		std::uint8_t reserved10To23[0x14];
		int freeRegister;
	};

	static_assert(
		offsetof(LuaFuncStateCodegenRuntimeView, functionProto) == 0x00,
		"LuaFuncStateCodegenRuntimeView::functionProto offset must be 0x00"
	);
	static_assert(
		offsetof(LuaFuncStateCodegenRuntimeView, lexState) == 0x0C,
		"LuaFuncStateCodegenRuntimeView::lexState offset must be 0x0C"
	);
	static_assert(
		offsetof(LuaFuncStateCodegenRuntimeView, freeRegister) == 0x24,
		"LuaFuncStateCodegenRuntimeView::freeRegister offset must be 0x24"
	);

	struct LuaFuncStateConstantRuntimeView
	{
		Proto* functionProto;      // +0x00
		Table* constantLookupTable; // +0x04
		std::uint8_t reserved08To0F[0x08];
		lua_State* state;          // +0x10
		std::uint8_t reserved14To27[0x14];
		int constantCount;         // +0x28
	};

	static_assert(
		offsetof(LuaFuncStateConstantRuntimeView, functionProto) == 0x00,
		"LuaFuncStateConstantRuntimeView::functionProto offset must be 0x00"
	);
	static_assert(
		offsetof(LuaFuncStateConstantRuntimeView, constantLookupTable) == 0x04,
		"LuaFuncStateConstantRuntimeView::constantLookupTable offset must be 0x04"
	);
	static_assert(
		offsetof(LuaFuncStateConstantRuntimeView, state) == 0x10,
		"LuaFuncStateConstantRuntimeView::state offset must be 0x10"
	);
	static_assert(
		offsetof(LuaFuncStateConstantRuntimeView, constantCount) == 0x28,
		"LuaFuncStateConstantRuntimeView::constantCount offset must be 0x28"
	);

	struct LuaExpDescCodegenRuntimeView
	{
		int kind;
		int info;
		int aux;
		int t;
		int f;
	};

	static_assert(offsetof(LuaExpDescCodegenRuntimeView, kind) == 0x00, "LuaExpDescCodegenRuntimeView::kind offset must be 0x00");
	static_assert(offsetof(LuaExpDescCodegenRuntimeView, info) == 0x04, "LuaExpDescCodegenRuntimeView::info offset must be 0x04");
	static_assert(offsetof(LuaExpDescCodegenRuntimeView, aux) == 0x08, "LuaExpDescCodegenRuntimeView::aux offset must be 0x08");
	static_assert(offsetof(LuaExpDescCodegenRuntimeView, t) == 0x0C, "LuaExpDescCodegenRuntimeView::t offset must be 0x0C");
	static_assert(offsetof(LuaExpDescCodegenRuntimeView, f) == 0x10, "LuaExpDescCodegenRuntimeView::f offset must be 0x10");

	struct LuaFuncStateUpvalueRuntimeView
	{
		Proto* functionProto;
		std::uint8_t reserved04To0B[0x08];
		void* lexState;
		lua_State* state;
		std::uint8_t reserved14To37[0x24];
		LuaExpDescCodegenRuntimeView upvalues[0x20];
	};

	static_assert(
		offsetof(LuaFuncStateUpvalueRuntimeView, functionProto) == 0x00,
		"LuaFuncStateUpvalueRuntimeView::functionProto offset must be 0x00"
	);
	static_assert(
		offsetof(LuaFuncStateUpvalueRuntimeView, lexState) == 0x0C,
		"LuaFuncStateUpvalueRuntimeView::lexState offset must be 0x0C"
	);
	static_assert(
		offsetof(LuaFuncStateUpvalueRuntimeView, state) == 0x10,
		"LuaFuncStateUpvalueRuntimeView::state offset must be 0x10"
	);
	static_assert(
		offsetof(LuaFuncStateUpvalueRuntimeView, upvalues) == 0x38,
		"LuaFuncStateUpvalueRuntimeView::upvalues offset must be 0x38"
	);

#if INTPTR_MAX == INT32_MAX
	static_assert(offsetof(Table, lsizenode) == 0x0D, "Table::lsizenode offset must be 0x0D (x86)");
	static_assert(offsetof(Table, array) == 0x14, "Table::array offset must be 0x14 (x86)");
	static_assert(offsetof(Table, node) == 0x18, "Table::node offset must be 0x18 (x86)");
	static_assert(offsetof(Table, sizearray) == 0x24, "Table::sizearray offset must be 0x24 (x86)");
	static_assert(sizeof(Node) == 0x14, "Node size must be 0x14 (x86)");
#endif

	[[nodiscard]] constexpr std::uint32_t LuaHashMask(const Table* const table)
	{
		return (1u << table->lsizenode) - 1u;
	}

	[[nodiscard]] constexpr std::uint32_t LuaHashOddModulus(const Table* const table)
	{
		return LuaHashMask(table) | 1u;
	}

	[[nodiscard]] std::uint32_t LuaFloatBitPattern(const float value)
	{
		std::uint32_t bits = 0u;
		std::memcpy(&bits, &value, sizeof(bits));
		return bits;
	}

	[[nodiscard]] constexpr int LuaInstructionSignedOffset(const Instruction instruction)
	{
		return static_cast<int>((instruction >> 6) & 0x3FFFFu) - 0x1FFFF;
	}

	struct LuaGlobalStateTableAllocRuntimeView
	{
		std::uint8_t reserved00[0x100];
		Table* defaultTableMetatable;
		std::uint8_t reserved104To14F[0x4C];
		std::uint8_t allocationTrackingEnabled;
	};
#if INTPTR_MAX == INT32_MAX
	static_assert(
		offsetof(LuaGlobalStateTableAllocRuntimeView, defaultTableMetatable) == 0x100,
		"LuaGlobalStateTableAllocRuntimeView::defaultTableMetatable offset must be 0x100 (x86)"
	);
	static_assert(
		offsetof(LuaGlobalStateTableAllocRuntimeView, allocationTrackingEnabled) == 0x150,
		"LuaGlobalStateTableAllocRuntimeView::allocationTrackingEnabled offset must be 0x150 (x86)"
	);
#endif

	[[maybe_unused]] Table* LuaDebugGetSizesTable(lua_State* const state);
}

struct FuncState;
struct expdesc;

extern "C"
{
	void luaC_collectgarbage(lua_State* L);
	void luaC_link(lua_State* L, GCObject* object, int typeTag);
	Closure* luaF_newCclosure(lua_State* L, int nelems);
	lua_State* luaE_newthread(lua_State* L);
	void luaD_growstack(lua_State* L, int n);
	void* luaM_realloc(lua_State* L, void* oldblock, lu_mem oldsize, lu_mem size);
	void* luaM_growaux(lua_State* L, void* block, int* size, int sizeElem, int limit, const char* what);
	const char* luaO_pushvfstring(lua_State* L, const char* fmt, va_list argp);
	int _errorfb(lua_State* L, int level);
	void luaG_runerror(lua_State* L, const char* format, ...);
	void luaV_concat(lua_State* L, int total, int last);
	int luaV_tostring(lua_State* L, TObject* obj);
	void discharge2reg(expdesc* e, int reg, FuncState* fs);
	int luaK_code(FuncState* fs, Instruction i, int line);
	int luaK_codeABC(FuncState* fs, int o, int a, int b, int c);
	void luaK_dischargevars(FuncState* fs, expdesc* e);
	void luaK_nil(FuncState* fs, int from, int n);
	void luaX_checklimit(void* ls, int v, int l, const char* what);
	void luaX_syntaxerror(void* ls, const char* msg);
	TString* luaS_newlstr(lua_State* L, const char* str, size_t len);
	extern const TObject luaO_nilobject;
	int luaO_rawequalObj(const TObject* t1, const TObject* t2);
	Node* luaH_mainposition(const Table* t, const TObject* key);
	const TObject* luaH_getany(const TObject* key, Table* t);
	const TObject* luaH_get(Table* t, const TObject* key);
	const TObject* luaH_getstr(Table* t, TString* key);
	const TObject* luaH_getnum(Table* t, int key);
	int luaO_log2(unsigned int x);
	const TObject* luaT_gettm(Table* events, int event, TString* ename);
	void luaD_reallocstack(lua_State* L, int newsize);
	TObject* newkey(lua_State* L, Table* t, const TObject* key);
	void luaK_fixjump(int to, int from, FuncState* fs);
	TObject* luaH_set(lua_State* L, Table* t, const TObject* key);
	TObject* luaH_setnum(lua_State* L, Table* t, int key);
	TObject* negindex(lua_State* L, int idx);

	/**
	 * Address: 0x009240C0 (FUN_009240C0, lua_stack_init)
	 *
	 * What it does:
	 * Allocates one fresh Lua thread stack and call-info array, initializes the
	 * first call frame, and seeds default stack/base/top lanes for execution.
	 */
	[[maybe_unused]] static void lua_stack_init(lua_State* const allocatorState, lua_State* const threadState)
	{
		constexpr int kInitialStackSlots = 45;
		constexpr int kStackGuardTailSlots = 6;
		constexpr int kInitialCallInfoSlots = 8;
		constexpr int kInitialCallFrameTopSpan = 20;

		TObject* const stackBase = static_cast<TObject*>(luaM_realloc(
			allocatorState,
			nullptr,
			0u,
			static_cast<lu_mem>(sizeof(TObject) * kInitialStackSlots)
		));
		threadState->stack = stackBase;
		threadState->top = stackBase;
		threadState->stacksize = kInitialStackSlots;
		threadState->stack_last = stackBase + (kInitialStackSlots - kStackGuardTailSlots);

		CallInfo* const callInfoBase = static_cast<CallInfo*>(luaM_realloc(
			allocatorState,
			nullptr,
			0u,
			static_cast<lu_mem>(sizeof(CallInfo) * kInitialCallInfoSlots)
		));
		threadState->ci = callInfoBase;
		threadState->base_ci = callInfoBase;
		callInfoBase->state = 5;
		callInfoBase->savedpc = nullptr;
		callInfoBase->tailcalls = 0;
		callInfoBase->pc = nullptr;
		callInfoBase->reserved0 = 0;
		callInfoBase->reserved1 = 0;
		callInfoBase->reserved2 = 0;

		threadState->top->tt = LUA_TNIL;
		CallInfo* const ci = threadState->ci;
		ci->base = ++threadState->top;
		threadState->base = ci->base;
		ci->top = threadState->top + kInitialCallFrameTopSpan;
		threadState->size_ci = static_cast<std::uint16_t>(kInitialCallInfoSlots);
		threadState->end_ci = threadState->base_ci + kInitialCallInfoSlots;
	}

	/**
	 * Address: 0x00924080 (FUN_00924080, lua_setusergcfunction)
	 *
	 * What it does:
	 * Stores one engine GC callback pointer in the shared global-state lane.
	 */
	void lua_setusergcfunction(lua_State* const state, void(__cdecl* userGCFunction)(void*))
	{
		state->l_G->userGCFunction = reinterpret_cast<void(__cdecl*)(GCState*)>(userGCFunction);
	}

	/**
	 * Address: 0x009240B0 (FUN_009240B0, lua_setstateuserdata)
	 *
	 * What it does:
	 * Stores one LuaPlus wrapper pointer in `lua_State::stateUserData`.
	 */
	void lua_setstateuserdata(lua_State* const state, void* const stateUserData)
	{
		state->stateUserData = static_cast<LuaState*>(stateUserData);
	}

	/**
	 * Address: 0x00924060 (FUN_00924060, lua_setglobaluserdata)
	 *
	 * What it does:
	 * Stores engine global userdata pointer into `global_State::globalUserData`.
	 */
	void lua_setglobaluserdata(lua_State* const state, void* const globalUserData)
	{
		state->l_G->globalUserData = static_cast<moho::Sim*>(globalUserData);
	}

	/**
	 * Address: 0x009240A0 (FUN_009240A0, lua_getstateuserdata)
	 *
	 * What it does:
	 * Returns LuaPlus state wrapper pointer stored in `lua_State::stateUserData`.
	 */
	void* lua_getstateuserdata(lua_State* const state)
	{
		return state->stateUserData;
	}

	/**
	 * Address: 0x0090C530 (FUN_0090C530, lua_newthread)
	 *
	 * What it does:
	 * Runs the Lua GC-threshold gate, creates one new coroutine state, pushes
	 * that thread object to stack top, and preserves Lua stack growth guard.
	 */
	lua_State* lua_newthread(lua_State* const state)
	{
		auto* const globalStateRuntime = reinterpret_cast<LuaGlobalStateGcRuntimeView*>(state->l_G);
		if (globalStateRuntime->allocatedBytes >= globalStateRuntime->gcThreshold
			&& globalStateRuntime->panicFunction == nullptr) {
			luaC_collectgarbage(state);
		}

		lua_State* const newThread = luaE_newthread(state);
		auto* const threadObject = reinterpret_cast<GCObject*>(newThread);
		TObject* const top = state->top;
		top->tt = static_cast<int>(threadObject->gch.tt);
		top->value.p = threadObject;

		if (top >= state->ci->top && state->stack_last - top <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;
		return newThread;
	}

	/**
	 * Address: 0x0090C3D0 (FUN_0090C3D0, luaA_index)
	 *
	 * What it does:
	 * Resolves one Lua stack index to its `TObject*` slot. Positive indices are
	 * relative to the current call's base; non-positive indices route through
	 * `negindex` (registry, globals, upvalues, or negative stack offsets).
	 */
	TObject* luaA_index(lua_State* const state, const int stackIndex)
	{
		if (stackIndex > 0) {
			return &state->base[stackIndex - 1];
		}
		return negindex(state, stackIndex);
	}

	/**
	 * Address: 0x0090C420 (FUN_0090C420, luaA_pushobject)
	 *
	 * What it does:
	 * Copies one `TObject` lane to stack top, grows stack when the guard lane
	 * reaches one slot, then advances top.
	 */
	void luaA_pushobject(lua_State* const state, const TObject* const object)
	{
		*state->top = *object;
		if ((state->stack_last - state->top) <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;
	}

	/**
	 * Address: 0x0090CED0 (FUN_0090CED0, lua_pushcclosure)
	 *
	 * What it does:
	 * Allocates one C closure with `n` upvalues from stack top, runs the
	 * GC-threshold check lane, then pushes closure object back onto the stack.
	 */
	void lua_pushcclosure(lua_State* const state, lua_CFunction fn, int n)
	{
		auto* const globalStateRuntime = reinterpret_cast<LuaGlobalStateGcRuntimeView*>(state->l_G);
		if (globalStateRuntime->allocatedBytes >= globalStateRuntime->gcThreshold
			&& globalStateRuntime->panicFunction == nullptr) {
			luaC_collectgarbage(state);
		}

		Closure* const closure = luaF_newCclosure(state, n);
		closure->c.f = fn;
		state->top -= n;

		for (int upvalueIndex = n - 1; upvalueIndex >= 0; --upvalueIndex) {
			closure->c.upvalue[upvalueIndex] = state->top[upvalueIndex];
		}

		TObject* const top = state->top;
		top->tt = static_cast<int>(closure->c.tt);
		top->value.p = closure;

		if (top >= state->ci->top && state->stack_last - top <= 1) {
			luaD_growstack(state, 1);
		}

		state->top += 1;
	}

	/**
	 * Address: 0x0090AD00 (FUN_0090AD00, lua_setdefaultmetatable)
	 *
	 * What it does:
	 * Pops one value from stack top and, when that value is a table, writes it
	 * into the default-metatable slot for `type + 7`.
	 */
	void lua_setdefaultmetatable(lua_State* const state, const int type)
	{
		TObject* const topValue = state->top - 1;
		if (topValue->tt == LUA_TTABLE) {
			state->l_G->_defaultmetatypes[type + 7] = *topValue;
		}
		--state->top;
	}

	/**
	 * Address: 0x0090D650 (FUN_0090D650, lua_getgcthreshold)
	 *
	 * What it does:
	 * Returns the current GC threshold in KiB units.
	 */
	int lua_getgcthreshold(lua_State* const state)
	{
		return static_cast<int>(static_cast<std::uint32_t>(state->l_G->GCthreshold) >> 10);
	}

	/**
	 * Address: 0x0090D660 (FUN_0090D660, lua_getgccount)
	 *
	 * What it does:
	 * Returns the current allocated-block count in KiB units.
	 */
	int lua_getgccount(lua_State* const state)
	{
		return static_cast<int>(static_cast<std::uint32_t>(state->l_G->unknown10C) >> 10);
	}

	/**
	 * Address: 0x0090D670 (FUN_0090D670, lua_setgcthreshold)
	 *
	 * What it does:
	 * Sets the GC threshold in KiB units (saturating to max on overflow) and
	 * runs one GC cycle when allocated bytes already cross the new limit.
	 */
	void lua_setgcthreshold(lua_State* const state, const int newThreshold)
	{
		auto* const globalStateRuntime = reinterpret_cast<LuaGlobalStateGcRuntimeView*>(state->l_G);
		if (static_cast<std::uint32_t>(newThreshold) <= 0x3FFFFFu) {
			globalStateRuntime->gcThreshold = static_cast<std::uint32_t>(newThreshold) << 10;
		} else {
			globalStateRuntime->gcThreshold = 0xFFFFFFFFu;
		}

		if (globalStateRuntime->allocatedBytes >= globalStateRuntime->gcThreshold
			&& globalStateRuntime->panicFunction == nullptr) {
			luaC_collectgarbage(state);
		}
	}

	/**
	 * Address: 0x0090D740 (FUN_0090D740, lua_concat)
	 *
	 * What it does:
	 * Concatenates `n` values at stack top through VM concat, pushes empty
	 * string when `n == 0`, and preserves Lua stack-growth guard behavior.
	 */
	void lua_concat(lua_State* const state, const int n)
	{
		auto* const globalStateRuntime = reinterpret_cast<LuaGlobalStateGcRuntimeView*>(state->l_G);
		if (globalStateRuntime->allocatedBytes >= globalStateRuntime->gcThreshold
			&& globalStateRuntime->panicFunction == nullptr) {
			luaC_collectgarbage(state);
		}

		if (n >= 2) {
			const int last = static_cast<int>(state->top - state->base) - 1;
			luaV_concat(state, n, last);
			state->top += 1 - n;
			return;
		}

		if (n == 0) {
			TObject* const top = state->top;
			TString* const emptyString = luaS_newlstr(state, nullptr, 0u);
			top->tt = static_cast<int>(emptyString->tt);
			top->value.p = emptyString;

			if (top >= state->ci->top && state->stack_last - top <= 1) {
				luaD_growstack(state, 1);
			}

			state->top += 1;
		}
	}

	/**
	 * Address: 0x0090D940 (FUN_0090D940, aux_upvalue)
	 *
	 * What it does:
	 * Resolves one upvalue pointer/name pair for either C closures
	 * (`upvalue_m1[n]`) or Lua closures (`upvals[n-1]` + `proto->upvalues[n-1]`)
	 * and returns null on type/index mismatch.
	 */
	[[maybe_unused]] const char* aux_upvalue(
		lua_State* const state,
		const int functionIndex,
		TObject** const outValueSlot,
		const int upvalueIndex
	)
	{
		TObject* functionObject = nullptr;
		if (functionIndex <= 0) {
			functionObject = negindex(state, functionIndex);
		} else {
			functionObject = &state->base[functionIndex - 1];
		}

		if (functionObject->tt == LUA_CFUNCTION) {
			auto* const cClosure = static_cast<CClosure*>(functionObject->value.p);
			if (upvalueIndex <= static_cast<int>(cClosure->nupvalues)) {
				*outValueSlot = &cClosure->upvalue_m1[upvalueIndex];
				return "";
			}
			return nullptr;
		}

		if (functionObject->tt == LUA_TFUNCTION) {
			auto* const lClosure = static_cast<LClosure*>(functionObject->value.p);
			Proto* const prototype = lClosure->p;
			if (upvalueIndex <= prototype->sizeupvalues) {
				*outValueSlot = lClosure->upvals[upvalueIndex - 1]->v;
				return prototype->upvalues[upvalueIndex - 1]->str;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x0090E330 (FUN_0090E330, luaL_pushresult)
	 *
	 * What it does:
	 * Flushes pending buffer bytes as one Lua string lane, then concatenates
	 * all buffered segments and resets buffer nesting level to one.
	 */
	void luaL_pushresult(luaL_Buffer* const buffer)
	{
		const auto bufferedLength = buffer->p - buffer->buffer;
		if (bufferedLength != 0) {
			lua_pushlstring(buffer->L, buffer->buffer, static_cast<size_t>(bufferedLength));
			++buffer->lvl;
			buffer->p = buffer->buffer;
		}

		lua_concat(buffer->L, buffer->lvl);
		buffer->lvl = 1;
	}

	/**
	 * Address: 0x0090CB10 (FUN_0090CB10, lua_strlen)
	 *
	 * What it does:
	 * Resolves one stack lane by positive or negative index, converts it to a
	 * string when needed, and returns the resulting byte length.
	 */
	[[nodiscard]] size_t lua_strlen(lua_State* const state, const int idx)
	{
		TObject* object = nullptr;
		if (idx <= 0) {
			object = state->top + idx;
			if (object < state->base) {
				return 0;
			}
		} else {
			object = &state->base[idx - 1];
			if (object >= state->top) {
				return 0;
			}
		}

		if (object == nullptr) {
			return 0;
		}

		if (object->tt == LUA_TSTRING) {
			return static_cast<TString*>(object->value.p)->len;
		}

		if (luaV_tostring(state, object) == 0) {
			return 0;
		}

		return static_cast<TString*>(object->value.p)->len;
	}

	/**
	 * Address: 0x0090CC10 (FUN_0090CC10, lua_tolightuserdata)
	 *
	 * What it does:
	 * Returns light-userdata pointer for one stack index (`nullptr` for
	 * out-of-range/non-lightuserdata lanes).
	 */
	[[nodiscard]] void* lua_tolightuserdata(lua_State* const state, const int idx)
	{
		TObject* object = nullptr;
		if (idx <= 0) {
			object = negindex(state, idx);
		} else {
			object = &state->base[idx - 1];
			if (object >= state->top) {
				return nullptr;
			}
		}

		if (object == nullptr || object->tt != LUA_TLIGHTUSERDATA) {
			return nullptr;
		}

		return object->value.p;
	}

	/**
	 * Address: 0x0090E1E0 (FUN_0090E1E0, adjuststack)
	 *
	 * What it does:
	 * Chooses one suffix of stacked Lua string fragments to concatenate,
	 * balancing total top-fragment length against fragment count.
	 */
	void adjuststack(luaL_Buffer* const buffer)
	{
		int fragmentsToConcat = 1;
		if (buffer->lvl <= 1) {
			return;
		}

		lua_State* const state = buffer->L;
		size_t topLength = lua_strlen(state, -1);
		int relativeIndex = -2;

		while (fragmentsToConcat < buffer->lvl) {
			const size_t currentLength = lua_strlen(state, relativeIndex);
			const int remainingFragments = buffer->lvl - fragmentsToConcat + 1;
			if (remainingFragments < 10 && topLength <= currentLength) {
				break;
			}

			topLength += currentLength;
			++fragmentsToConcat;
			--relativeIndex;
		}

		lua_concat(state, fragmentsToConcat);
		buffer->lvl += 1 - fragmentsToConcat;
	}

	/**
	 * Address: 0x00926170 (FUN_00926170, luaI_addquoted)
	 *
	 * What it does:
	 * Writes one quoted Lua string literal into the buffer, escaping embedded
	 * NUL, newline, quote, and backslash bytes with the legacy Lua escape lane.
	 */
	[[maybe_unused]] void luaI_addquoted(lua_State* const state, const int argumentIndex, luaL_Buffer* const buffer)
	{
		char* const bufferEnd = reinterpret_cast<char*>(&buffer[1]);
		size_t remainingLength = 0;
		const char* source = luaL_checklstring(state, argumentIndex, &remainingLength);

		if (buffer->p >= bufferEnd) {
			luaL_prepbuffer(buffer);
		}

		*buffer->p++ = '"';
		for (; remainingLength != 0; ++source) {
			--remainingLength;

			switch (*source) {
			case '\0':
				luaL_addlstring(buffer, "\\000", 4u);
				break;

			case '\n':
			case '"':
			case '\\':
				if (buffer->p >= bufferEnd) {
					luaL_prepbuffer(buffer);
				}

				*buffer->p++ = '\\';
				if (buffer->p >= bufferEnd) {
					luaL_prepbuffer(buffer);
				}

				*buffer->p = *source;
				++buffer->p;
				break;

			default:
				if (buffer->p >= bufferEnd) {
					luaL_prepbuffer(buffer);
				}

				*buffer->p = *source;
				++buffer->p;
				break;
			}
		}

		--remainingLength;
		if (buffer->p >= bufferEnd) {
			luaL_prepbuffer(buffer);
		}

		*buffer->p++ = '"';
	}

	/**
	 * Address: 0x0091A570 (FUN_0091A570, luaO_rawequalObj)
	 *
	 * What it does:
	 * Compares two tagged Lua values with raw-equality semantics (no
	 * metamethod dispatch), including exact-number and pointer-lane equality.
	 */
	int luaO_rawequalObj(const TObject* const t1, const TObject* const t2)
	{
		if (t1->tt != t2->tt) {
			return 0;
		}

		switch (t1->tt) {
		case LUA_TNIL:
			return 1;
		case LUA_TNUMBER:
			return (t1->value.n == t2->value.n) ? 1 : 0;
		default:
			return (t1->value.p == t2->value.p) ? 1 : 0;
		}
	}

	/**
	 * Address: 0x0091A8D0 (FUN_0091A8D0, luaO_pushfstring)
	 *
	 * What it does:
	 * Starts one varargs lane for `format`, forwards to `luaO_pushvfstring`,
	 * then returns that pushed Lua string pointer.
	 */
	const char* luaO_pushfstring(lua_State* const state, const char* const format, ...)
	{
		va_list argp;
		va_start(argp, format);
		const char* const pushedString = luaO_pushvfstring(state, format, argp);
		va_end(argp);
		return pushedString;
	}

	/**
	 * Address: 0x0091A640 (FUN_0091A640, pushstr)
	 *
	 * What it does:
	 * Interns one Lua string, writes the tagged string object into the current
	 * stack slot, and grows the stack if only one slot of headroom remains.
	 */
	[[maybe_unused]] TString* pushstr(lua_State* const state, const char* const source)
	{
		TObject* const top = state->top;
		TString* const stringObject = luaS_newlstr(state, source, std::strlen(source));
		top->tt = stringObject->tt;
		top->value.p = stringObject;

		if (state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;
		return stringObject;
	}

	/**
	 * Address: 0x009247C0 (FUN_009247C0, luaS_resize)
	 *
	 * What it does:
	 * Rebuilds the Lua interned-string hash table to `newsize`, rehashing all
	 * existing `TString` nodes and releasing the previous bucket array.
	 */
	void luaS_resize(lua_State* const state, const int newsize)
	{
		GCObject** const newHash = static_cast<GCObject**>(
			luaM_realloc(state, nullptr, 0u, static_cast<lu_mem>(sizeof(GCObject*) * newsize))
		);
		global_State* const globalState = state->l_G;
		if (newsize > 0) {
			std::memset(newHash, 0, static_cast<std::size_t>(sizeof(GCObject*) * newsize));
		}

		for (int bucketIndex = 0; bucketIndex < globalState->strt.size; ++bucketIndex) {
			GCObject* node = globalState->strt.hash[bucketIndex];
			while (node != nullptr) {
				GCObject* const next = node->gch.next;
				const int newBucket = static_cast<int>(node->ts.hash & static_cast<lu_hash>(newsize - 1));
				node->gch.next = newHash[newBucket];
				newHash[newBucket] = node;
				node = next;
			}
		}

		luaM_realloc(
			state,
			globalState->strt.hash,
			static_cast<lu_mem>(sizeof(GCObject*) * globalState->strt.size),
			0u
		);
		globalState->strt.hash = newHash;
		globalState->strt.size = newsize;
	}

	/**
	 * Address: 0x00924860 (FUN_00924860, newlstr)
	 *
	 * What it does:
	 * Allocates one `TString`, copies payload bytes plus terminating NUL, links
	 * it into the string-table bucket chain, and triggers table growth when
	 * string usage exceeds bucket count.
	 */
	[[nodiscard]] static TString* newlstr(
		const lu_hash hashValue,
		lua_State* const state,
		const char* const source,
		const std::size_t length
	)
	{
		constexpr std::size_t kTStringHeaderWithTerminator = offsetof(TString, str) + 1u;
		constexpr int kLuaStringTableMaxGrowth = 0x3FFFFFFE;

		GCObject* const object = static_cast<GCObject*>(
			luaM_realloc(state, nullptr, 0u, static_cast<lu_mem>(length + kTStringHeaderWithTerminator))
		);
		TString* const stringObject = &object->ts;
		stringObject->len = length;
		stringObject->hash = hashValue;
		stringObject->marked = 0u;
		stringObject->tt = LUA_TSTRING;
		stringObject->reserved = 0;

		if (length != 0 && source != nullptr) {
			std::memcpy(stringObject->str, source, length);
		}
		stringObject->str[length] = '\0';

		global_State* const globalState = state->l_G;
		const int bucket = static_cast<int>(hashValue & static_cast<lu_hash>(globalState->strt.size - 1));
		object->gch.next = globalState->strt.hash[bucket];
		globalState->strt.hash[bucket] = object;

		const int stringUseCount = ++globalState->strt.nuse;
		const int bucketCount = globalState->strt.size;
		if (stringUseCount > bucketCount && bucketCount <= kLuaStringTableMaxGrowth) {
			luaS_resize(state, bucketCount * 2);
		}

		return stringObject;
	}

	/**
	 * Address: 0x009248E0 (FUN_009248E0, luaS_newlstr)
	 *
	 * What it does:
	 * Computes Lua string hash, probes interned-string bucket chain for an exact
	 * byte match, and returns existing interned object or allocates a new one.
	 */
	TString* luaS_newlstr(lua_State* const state, const char* const source, const std::size_t length)
	{
		const std::size_t hashStep = (length >> 5u) + 1u;
		lu_hash hashValue = static_cast<lu_hash>(length);
		for (std::size_t probeIndex = length; probeIndex >= hashStep; probeIndex -= hashStep) {
			const lu_hash byteValue = static_cast<unsigned char>(source[probeIndex - 1u]);
			hashValue ^= (hashValue << 5u) + (hashValue >> 2u) + byteValue;
		}

		global_State* const globalState = state->l_G;
		const int bucket = static_cast<int>(hashValue & static_cast<lu_hash>(globalState->strt.size - 1));
		for (GCObject* object = globalState->strt.hash[bucket]; object != nullptr; object = object->gch.next) {
			TString* const candidate = &object->ts;
			if (candidate->tt == LUA_TSTRING && candidate->len == length) {
				if (length == 0u || (source != nullptr && std::memcmp(source, candidate->str, length) == 0)) {
					return candidate;
				}
			}
		}

		return newlstr(hashValue, state, source, length);
	}

	/**
	 * Address: 0x00925A20 (FUN_00925A20, push_onecapture)
	 *
	 * What it does:
	 * Pushes one pattern-capture result to Lua stack (error for unfinished
	 * capture, numeric position for position captures, or captured substring).
	 */
	struct CaptureRuntimeView
	{
		const char* init;
		int len;
	};
	struct MatchStateRuntimeView
	{
		const char* srcInit;
		const char* srcEnd;
		lua_State* state;
		int level;
		CaptureRuntimeView captures[32];
	};
	static_assert(offsetof(CaptureRuntimeView, init) == 0x0, "CaptureRuntimeView::init offset must be 0x0");
	static_assert(offsetof(CaptureRuntimeView, len) == 0x4, "CaptureRuntimeView::len offset must be 0x4");
	static_assert(sizeof(CaptureRuntimeView) == 0x8, "CaptureRuntimeView size must be 0x8");
	static_assert(offsetof(MatchStateRuntimeView, srcInit) == 0x0, "MatchStateRuntimeView::srcInit offset must be 0x0");
	static_assert(offsetof(MatchStateRuntimeView, srcEnd) == 0x4, "MatchStateRuntimeView::srcEnd offset must be 0x4");
	static_assert(offsetof(MatchStateRuntimeView, state) == 0x8, "MatchStateRuntimeView::state offset must be 0x8");
	static_assert(offsetof(MatchStateRuntimeView, level) == 0xC, "MatchStateRuntimeView::level offset must be 0xC");
	static_assert(
		offsetof(MatchStateRuntimeView, captures) == 0x10,
		"MatchStateRuntimeView::captures offset must be 0x10"
	);
	static_assert(sizeof(MatchStateRuntimeView) == 0x110, "MatchStateRuntimeView size must be 0x110");

	[[nodiscard]] const char* luaI_classend(const char* p, MatchStateRuntimeView* ms);
	[[nodiscard]] int match_class(int c1, int cl1);
	[[nodiscard]] int matchbracketclass(const char* p, int c, const char* ec);
	[[nodiscard]] int luaI_singlematch(int c, const char* p, const char* ep);
	[[nodiscard]] const char* matchbalance(const char* p, const char* s, MatchStateRuntimeView* ms);
	[[nodiscard]] const char* match_capture(int l, MatchStateRuntimeView* ms, const char* s);
	[[nodiscard]] const char* max_expand(MatchStateRuntimeView* ms, const char* s, const char* p, const char* ep);
	[[nodiscard]] const char* min_expand(const char* s, MatchStateRuntimeView* ms, const char* p, const char* ep);
	[[nodiscard]] const char* start_capture(const char* s, MatchStateRuntimeView* ms, const char* p, int what);
	[[nodiscard]] const char* end_capture(const char* s, MatchStateRuntimeView* ms, const char* p);
	[[nodiscard]] const char* match(MatchStateRuntimeView* ms, const char* s, const char* p);

	/**
	 * Address: 0x00925920 (FUN_00925920, lmemfind)
	 *
	 * What it does:
	 * Searches one bounded source span for the first occurrence of a bounded
	 * pattern span and returns the match pointer or null when not found.
	 */
	[[nodiscard]] const char* lmemfind(
		const size_t patternLength,
		const char* const sourceText,
		const size_t sourceLength,
		const char* const patternText
	)
	{
		if (patternLength == 0u) {
			return sourceText;
		}

		if (patternLength > sourceLength) {
			return nullptr;
		}

		const size_t tailLength = patternLength - 1u;
		size_t remainingSearch = sourceLength - tailLength;
		if (remainingSearch == 0u) {
			return nullptr;
		}

		const char firstPatternByte = patternText[0];
		const char* searchCursor = sourceText;
		while (true) {
			const void* const found = std::memchr(searchCursor, firstPatternByte, remainingSearch);
			if (found == nullptr) {
				return nullptr;
			}

			const char* const candidate = static_cast<const char*>(found);
			if (tailLength == 0u
				|| std::memcmp(candidate + 1, patternText + 1, tailLength) == 0) {
				return candidate;
			}

			const char* const nextCursor = candidate + 1;
			if (nextCursor <= searchCursor) {
				return nullptr;
			}

			const size_t consumed = static_cast<size_t>(nextCursor - searchCursor);
			if (consumed >= remainingSearch) {
				return nullptr;
			}

			searchCursor = nextCursor;
			remainingSearch -= consumed;
		}
	}

	void push_onecapture(const int captureIndex, MatchStateRuntimeView* const matchState)
	{
		CaptureRuntimeView& capture = matchState->captures[captureIndex];
		const int captureLength = capture.len;
		if (captureLength == -1) {
			luaL_error(matchState->state, "unfinished capture");
			return;
		}

		if (captureLength == -2) {
			const int capturePosition = static_cast<int>(capture.init - matchState->srcInit + 1);
			lua_pushnumber(matchState->state, static_cast<float>(capturePosition));
			return;
		}

		lua_pushlstring(matchState->state, capture.init, static_cast<size_t>(captureLength));
	}

	/**
	 * Address: 0x00925A80 (FUN_00925A80, push_captures)
	 *
	 * What it does:
	 * Pushes all current pattern captures to Lua stack (or the full match slice
	 * when there are no captures) and returns pushed value count.
	 */
	[[nodiscard]] int push_captures(const char* const sourceStart, const char* const sourceEnd, MatchStateRuntimeView* const ms)
	{
		luaL_checkstack(ms->state, ms->level, "too many captures");
		if (ms->level == 0 && sourceStart != nullptr) {
			lua_pushlstring(ms->state, sourceStart, static_cast<size_t>(sourceEnd - sourceStart));
			return 1;
		}

		for (int captureIndex = 0; captureIndex < ms->level; ++captureIndex) {
			push_onecapture(captureIndex, ms);
		}

		return ms->level;
	}

	/**
	 * Address: 0x009250B0 (FUN_009250B0, luaI_classend)
	 *
	 * What it does:
	 * Advances a pattern pointer to the end of the current class/range token,
	 * raising Lua pattern syntax errors for truncated `%` or `[...]` forms.
	 */
	[[nodiscard]] const char* luaI_classend(const char* p, MatchStateRuntimeView* const ms)
	{
		const char token = *p++;
		if (token == '%') {
			if (*p == '\0') {
				luaL_error(ms->state, "malformed pattern (ends with `%%')");
				return nullptr;
			}
			return p + 1;
		}

		if (token == '[') {
			if (*p == '^') {
				++p;
			}

			do {
				if (*p == '\0') {
					luaL_error(ms->state, "malformed pattern (missing `]')");
					return nullptr;
				}

				const char next = *p++;
				if (next == '%' && *p != '\0') {
					++p;
				}
			} while (*p != ']');

			return p + 1;
		}

		return p;
	}

	/**
	 * Address: 0x00925120 (FUN_00925120, match_class)
	 *
	 * What it does:
	 * Evaluates one Lua character class against `c1`, honoring the legacy
	 * uppercase-negation convention for class letters.
	 */
	[[nodiscard]] int match_class(const int c1, const int cl1)
	{
		const unsigned char ch = static_cast<unsigned char>(c1);
		const unsigned char classChar = static_cast<unsigned char>(cl1);
		int result = 0;

		switch (std::tolower(classChar)) {
		case 'a':
			result = std::isalpha(ch) != 0;
			break;
		case 'c':
			result = std::iscntrl(ch) != 0;
			break;
		case 'd':
			result = std::isdigit(ch) != 0;
			break;
		case 'l':
			result = std::islower(ch) != 0;
			break;
		case 'p':
			result = std::ispunct(ch) != 0;
			break;
		case 's':
			result = std::isspace(ch) != 0;
			break;
		case 'u':
			result = std::isupper(ch) != 0;
			break;
		case 'w':
			result = std::isalnum(ch) != 0;
			break;
		case 'x':
			result = std::isxdigit(ch) != 0;
			break;
		case 'z':
			result = (ch == 0);
			break;
		default:
			return c1 == cl1;
		}

		if (std::islower(classChar) == 0) {
			result = (result == 0);
		}

		return result;
	}

	/**
	 * Address: 0x00925230 (FUN_00925230, matchbracketclass)
	 *
	 * What it does:
	 * Evaluates a bracket class or range list against one character and honors
	 * `^` negation, character ranges, and embedded `%` class escapes.
	 */
	[[nodiscard]] int matchbracketclass(const char* p, const int c, const char* ec)
	{
		int positive = 1;
		if (p[1] == '^') {
			positive = 0;
			++p;
		}

		++p;
		if (p < ec) {
			const char* cursor = p + 2;
			do {
				if (*p == '%') {
					const int classChar = static_cast<unsigned char>(*++p);
					++cursor;
					if (match_class(c, classChar)) {
						return positive;
					}
				} else if (p[1] == '-' && cursor < ec) {
					const int first = static_cast<unsigned char>(*p);
					p += 2;
					cursor += 2;
					if (first <= c && c <= static_cast<unsigned char>(*p)) {
						return positive;
					}
				} else if (static_cast<unsigned char>(*p) == c) {
					return positive;
				}

				++p;
				++cursor;
			} while (p < ec);
		}

		return positive == 0;
	}

	/**
	 * Address: 0x009252D0 (FUN_009252D0, luaI_singlematch)
	 *
	 * What it does:
	 * Performs one pattern atom test at a single character position.
	 */
	[[nodiscard]] int luaI_singlematch(const int c, const char* const p, const char* const ep)
	{
		const unsigned char patternChar = static_cast<unsigned char>(*p);
		if (patternChar == '%') {
			return match_class(c, p[1]);
		}

		if (patternChar == '.') {
			return 1;
		}

		if (patternChar == '[') {
			return matchbracketclass(p, c, ep - 1);
		}

		return patternChar == c;
	}

	/**
	 * Address: 0x00925320 (FUN_00925320, matchbalance)
	 *
	 * What it does:
	 * Matches one balanced-pair pattern lane and advances to the matching
	 * closing delimiter when nesting depth returns to zero.
	 */
	[[nodiscard]] const char* matchbalance(const char* p, const char* s, MatchStateRuntimeView* const ms)
	{
		if (*p == '\0' || p[1] == '\0') {
			luaL_error(ms->state, "unbalanced pattern");
			return nullptr;
		}

		const char openChar = *p;
		if (*s != openChar) {
			return nullptr;
		}

		const char* const srcEnd = ms->srcEnd;
		const char closeChar = p[1];
		int depth = 1;
		++s;
		for (const int openValue = openChar; s < srcEnd; ++s) {
			const int current = static_cast<unsigned char>(*s);
			if (current == closeChar) {
				if (--depth == 0) {
					return s + 1;
				}
			} else if (current == openValue) {
				++depth;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x00925390 (FUN_00925390, max_expand)
	 *
	 * What it does:
	 * Greedily consumes the largest possible prefix matching the current
	 * pattern atom, then backtracks until the tail pattern succeeds.
	 */
	[[nodiscard]] const char* max_expand(
		MatchStateRuntimeView* const ms,
		const char* s,
		const char* p,
		const char* ep
	)
	{
		const char* current = s;
		int matchedCount = 0;

		if (s < ms->srcEnd) {
			while (true) {
				const unsigned char patternChar = static_cast<unsigned char>(*p);
				const unsigned char currentChar = static_cast<unsigned char>(*current);

				bool matched = false;
				if (patternChar == '%') {
					matched = match_class(currentChar, p[1]) != 0;
				} else if (patternChar == '.') {
					matched = true;
				} else if (patternChar == '[') {
					matched = matchbracketclass(p, currentChar, ep - 1) != 0;
				} else {
					matched = patternChar == currentChar;
				}

				if (matched == false) {
					break;
				}

				++current;
				++matchedCount;
				if (current >= ms->srcEnd) {
					break;
				}
			}
		}

		while (true) {
			const char* const result = match(ms, s + matchedCount, ep + 1);
			if (result != nullptr) {
				return result;
			}

			--matchedCount;
			if (matchedCount < 0) {
				return nullptr;
			}
		}
	}

	/**
	 * Address: 0x00925430 (FUN_00925430, min_expand)
	 *
	 * What it does:
	 * Tries the tail pattern at the current source position first and only
	 * advances while the current atom still matches.
	 */
	[[nodiscard]] const char* min_expand(
		const char* s,
		MatchStateRuntimeView* const ms,
		const char* p,
		const char* ep
	)
	{
		const char* current = s;
		while (true) {
			const char* const result = match(ms, current, ep + 1);
			if (result != nullptr) {
				return result;
			}

			if (current >= ms->srcEnd) {
				return nullptr;
			}

			const unsigned char patternChar = static_cast<unsigned char>(*p);
			const unsigned char sourceChar = static_cast<unsigned char>(*current);
			const bool matched =
				(patternChar == '%')
					? (match_class(sourceChar, p[1]) != 0)
					: (patternChar == '.'
						? true
						: (patternChar == '[' ? (matchbracketclass(p, sourceChar, ep - 1) != 0)
											   : (patternChar == sourceChar)));
			if (matched == false) {
				return nullptr;
			}

			++current;
		}
	}

	/**
	 * Address: 0x00925580 (FUN_00925580, match_capture)
	 *
	 * What it does:
	 * Compares a captured substring lane against the current source lane and
	 * advances when they match byte-for-byte.
	 */
	[[nodiscard]] const char* match_capture(const int l, MatchStateRuntimeView* const ms, const char* const s)
	{
		const int captureIndex = l - '1';
		if (captureIndex < 0 || captureIndex >= ms->level || ms->captures[captureIndex].len == -1) {
			luaL_error(ms->state, "invalid capture index");
			return nullptr;
		}

		const int captureLength = ms->captures[captureIndex].len;
		if (ms->srcEnd - s < captureLength) {
			return nullptr;
		}

		if (std::memcmp(ms->captures[captureIndex].init, s, static_cast<size_t>(captureLength)) != 0) {
			return nullptr;
		}

		return s + captureLength;
	}

	/**
	 * Address: 0x009254D0 (FUN_009254D0, start_capture)
	 *
	 * What it does:
	 * Starts one new capture lane, advances nested pattern matching, and rolls
	 * back the capture depth when the tail pattern fails.
	 */
	[[nodiscard]] const char* start_capture(
		const char* s,
		MatchStateRuntimeView* const ms,
		const char* p,
		const int what
	)
	{
		const int level = ms->level;
		if (level >= 32) {
			luaL_error(ms->state, "too many captures");
			return nullptr;
		}

		ms->captures[level].init = s;
		ms->captures[level].len = what;
		ms->level = level + 1;
		const char* const result = match(ms, s, p);
		if (result == nullptr) {
			--ms->level;
		}
		return result;
	}

	/**
	 * Address: 0x00925520 (FUN_00925520, end_capture)
	 *
	 * What it does:
	 * Completes the most recent open capture lane, then re-enters matching and
	 * rolls the capture back open if the tail fails.
	 */
	[[nodiscard]] const char* end_capture(const char* s, MatchStateRuntimeView* const ms, const char* p)
	{
		int level = ms->level - 1;
		if (level < 0) {
			luaL_error(ms->state, "invalid pattern capture");
			return nullptr;
		}

		while (ms->captures[level].len != -1) {
			--level;
			if (level < 0) {
				luaL_error(ms->state, "invalid pattern capture");
				return nullptr;
			}
		}

		ms->captures[level].len = static_cast<int>(s - ms->captures[level].init);
		const char* const result = match(ms, s, p);
		if (result == nullptr) {
			ms->captures[level].len = -1;
		}
		return result;
	}

	/**
	 * Address: 0x00925650 (FUN_00925650, match)
	 *
	 * What it does:
	 * Evaluates one Lua pattern atom against the current source lane, handling
	 * anchors, captures, frontier checks, balanced pairs, and quantifiers.
	 */
	[[nodiscard]] const char* match(MatchStateRuntimeView* const ms, const char* s, const char* p)
	{
		while (true) {
			switch (*p) {
			case '\0':
				return s;

			case '$':
				if (p[1] != '\0') {
					goto default_case;
				}
				return s != ms->srcEnd ? nullptr : s;

			case '%': {
				const unsigned char p1 = static_cast<unsigned char>(p[1]);
				if (p1 == 'b') {
					s = matchbalance(p + 2, s, ms);
					if (s == nullptr) {
						return nullptr;
					}
					p += 4;
					continue;
				}
				if (p1 != 'f') {
					if (std::isdigit(p1) == 0) {
						goto default_case;
					}
					s = match_capture(p1, ms, s);
					if (s == nullptr) {
						return nullptr;
					}
					p += 2;
					continue;
				}

				p += 2;
				if (*p != '[') {
					luaL_error(ms->state, "missing `[' after `%%f' in pattern");
					return nullptr;
				}

				const char* const classEnd = luaI_classend(p, ms);
				const char* const classEndMinusOne = classEnd - 1;
				const unsigned char previous = (s == ms->srcInit) ? 0 : static_cast<unsigned char>(*(s - 1));
				if (!matchbracketclass(p, previous, classEndMinusOne)
					&& matchbracketclass(p, static_cast<unsigned char>(*s), classEndMinusOne)) {
					p = classEnd;
					continue;
				}
				return nullptr;
			}

			case '(':
				if (p[1] == ')') {
					return start_capture(s, ms, p + 2, -2);
				}
				return start_capture(s, ms, p + 1, -1);

			case ')':
				return end_capture(s, ms, p + 1);

			default:
			default_case:
				break;
			}

			const char* const ep = luaI_classend(p, ms);
			int matched = 0;
			if (s < ms->srcEnd) {
				const unsigned char patternChar = static_cast<unsigned char>(*p);
				const unsigned char sourceChar = static_cast<unsigned char>(*s);
				if (patternChar == '%') {
					matched = match_class(sourceChar, p[1]);
				} else if (patternChar == '.') {
					matched = 1;
				} else if (patternChar == '[') {
					matched = matchbracketclass(p, sourceChar, ep - 1);
				} else {
					matched = patternChar == sourceChar;
				}
			}

			switch (*ep) {
			case '*':
				return max_expand(ms, s, p, ep);

			case '+':
				if (matched == 0) {
					return nullptr;
				}
				return max_expand(ms, s + 1, p, ep);

			case '-':
				return min_expand(s, ms, p, ep);

			case '?':
				if (matched != 0) {
					const char* const result = match(ms, s + 1, ep + 1);
					if (result != nullptr) {
						return result;
					}
				}
				p = ep + 1;
				continue;

			default:
				if (matched == 0) {
					return nullptr;
				}
				++s;
				p = ep;
				continue;
			}
		}
	}

	/**
	 * Address: 0x00926F70 (FUN_00926F70, luaH_mainposition)
	 *
	 * What it does:
	 * Computes the canonical main hash-bucket node for one table key by key
	 * tag (boolean/lightuserdata/number/string/default pointer lane).
	 */
	Node* luaH_mainposition(const Table* const t, const TObject* const key)
	{
		const std::uint32_t hashMask = LuaHashMask(t);
		const std::uint32_t oddModulus = LuaHashOddModulus(t);

		switch (key->tt) {
		case LUA_TBOOLEAN:
			return &t->node[static_cast<std::uint32_t>(key->value.b) & hashMask];
		case LUA_TLIGHTUSERDATA: {
			const std::uint32_t raw = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(key->value.p));
			return &t->node[raw % oddModulus];
		}
		case LUA_TNUMBER: {
			const std::uint32_t hash = LuaFloatBitPattern(key->value.n + 1.0f);
			return &t->node[hash % oddModulus];
		}
		case LUA_TSTRING: {
			auto* const stringKey = static_cast<TString*>(key->value.p);
			return &t->node[stringKey->hash & hashMask];
		}
		default: {
			const std::uint32_t raw = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(key->value.p));
			return &t->node[raw % oddModulus];
		}
		}
	}

	/**
	 * Address: 0x00927400 (FUN_00927400, luaH_getany)
	 *
	 * What it does:
	 * Performs hash-table lookup for arbitrary key tags and returns the slot
	 * value lane or `luaO_nilobject` when the key is not present.
	 */
	const TObject* luaH_getany(const TObject* const key, Table* const t)
	{
		if (key->tt == LUA_TNIL) {
			return &luaO_nilobject;
		}

		Node* node = luaH_mainposition(t, key);
		while (luaO_rawequalObj(&node->i_key, key) == 0) {
			node = node->next;
			if (node == nullptr) {
				return &luaO_nilobject;
			}
		}

		return &node->i_val;
	}

	/**
	 * Address: 0x00927450 (FUN_00927450, luaH_getnum)
	 *
	 * What it does:
	 * Looks up one integer key in table array-part first, then in hash chains
	 * using Lua's numeric-key hash lane and nilobject-on-miss semantics.
	 */
	const TObject* luaH_getnum(Table* const t, const int key)
	{
		if (key >= 1 && key <= t->sizearray) {
			return &t->array[key - 1];
		}

		const float floatKey = static_cast<float>(key);
		const std::uint32_t bucket = LuaFloatBitPattern(floatKey + 1.0f) % LuaHashOddModulus(t);
		Node* node = &t->node[bucket];
		while (node->i_key.tt != LUA_TNUMBER || node->i_key.value.n != floatKey) {
			node = node->next;
			if (node == nullptr) {
				return &luaO_nilobject;
			}
		}

		return &node->i_val;
	}

	/**
	 * Address: 0x009274D0 (FUN_009274D0, luaH_getstr)
	 *
	 * What it does:
	 * Looks up one interned string key in table hash chains and returns either
	 * the value lane or the shared Lua nil object on miss.
	 */
	const TObject* luaH_getstr(Table* const t, TString* const key)
	{
		Node* node = &t->node[key->hash & LuaHashMask(t)];
		while (node->i_key.tt != LUA_TSTRING || static_cast<TString*>(node->i_key.value.p) != key) {
			node = node->next;
			if (node == nullptr) {
				return &luaO_nilobject;
			}
		}

		return &node->i_val;
	}

	/**
	 * Address: 0x00927510 (FUN_00927510, luaH_get)
	 *
	 * What it does:
	 * Dispatches table get by key tag, including integer-fast-path for number
	 * keys and string-fast-path for interned string keys.
	 */
	const TObject* luaH_get(Table* const t, const TObject* const key)
	{
		if (key->tt == LUA_TNUMBER) {
			const float numericKey = key->value.n;
			const int integerKey = static_cast<int>(numericKey);
			if (static_cast<float>(integerKey) == numericKey) {
				return luaH_getnum(t, integerKey);
			}
		} else if (key->tt == LUA_TSTRING) {
			return luaH_getstr(t, static_cast<TString*>(key->value.p));
		}

		return luaH_getany(key, t);
	}

	/**
	 * Address: 0x00927610 (FUN_00927610, luaH_index)
	 *
	 * What it does:
	 * Resolves the linear iteration index used by `next`, validating incoming
	 * key shape and mapping hash-node value-lane pointers back to node indices.
	 */
	int luaH_index(lua_State* const state, Table* const table, const TObject* const key)
	{
		if (key->tt == LUA_TNIL) {
			return -1;
		}

		if (key->tt == LUA_TNUMBER) {
			const float numericKey = key->value.n;
			const int integerKey = static_cast<int>(numericKey);
			if (static_cast<float>(integerKey) == numericKey && integerKey >= 1) {
				const int zeroBased = integerKey - 1;
				if ((zeroBased & 0xFF000000) == 0 && integerKey <= table->sizearray) {
					return zeroBased;
				}
			}
		}

		const TObject* const slot = luaH_get(table, key);
		if (slot == &luaO_nilobject) {
			luaG_runerror(state, "invalid key for `next'");
		}

		const auto nodeBase = reinterpret_cast<std::uintptr_t>(table->node);
		const auto slotAddress = reinterpret_cast<std::uintptr_t>(slot);
		const std::uintptr_t valueLaneOffset = offsetof(Node, i_val);
		const int nodeIndex =
			static_cast<int>((slotAddress - nodeBase - valueLaneOffset) / static_cast<std::uintptr_t>(sizeof(Node)));
		return table->sizearray + nodeIndex;
	}

	/**
	 * Address: 0x009276A0 (FUN_009276A0, luaH_next)
	 *
	 * What it does:
	 * Advances Lua table iteration from `key` to the next occupied array/hash
	 * slot and writes both next-key and next-value lanes into caller storage.
	 */
	int luaH_next(lua_State* const state, Table* const table, TObject* const key)
	{
		int index = luaH_index(state, table, key) + 1;
		const int sizearray = table->sizearray;
		if (index < sizearray) {
			TObject* arraySlot = &table->array[index];
			while (arraySlot->tt == LUA_TNIL) {
				++index;
				++arraySlot;
				if (index >= sizearray) {
					break;
				}
			}

			if (index < sizearray) {
				key->tt = LUA_TNUMBER;
				key->value.n = static_cast<float>(index + 1);
				key[1] = table->array[index];
				return 1;
			}
		}

		int nodeIndex = index - sizearray;
		const int nodeCount = 1 << table->lsizenode;
		if (nodeIndex >= nodeCount) {
			return 0;
		}

		Node* const nodeBase = table->node;
		TObject* valueSlot = &nodeBase[nodeIndex].i_val;
		while (valueSlot->tt == LUA_TNIL) {
			++nodeIndex;
			valueSlot = reinterpret_cast<TObject*>(reinterpret_cast<std::uint8_t*>(valueSlot) + sizeof(Node));
			if (nodeIndex >= nodeCount) {
				return 0;
			}
		}

		key[0] = nodeBase[nodeIndex].i_key;
		key[1] = nodeBase[nodeIndex].i_val;
		return 1;
	}

	/**
	 * Address: 0x0090A6B0 (FUN_0090A6B0, LuaPlusH_next)
	 *
	 * What it does:
	 * Advances Lua table iteration using LuaPlus object wrappers, returning the
	 * next key/value pair in `key` and `value` and `0` when exhausted.
	 */
	extern "C" int LuaPlusH_next(
		LuaState* const state,
		LuaObject* const table,
		LuaObject* const key,
		LuaObject* const value
	)
	{
		if (state == nullptr || state->m_state == nullptr || table == nullptr || key == nullptr || value == nullptr) {
			return 0;
		}

		auto* const tableObject = static_cast<Table*>(table->m_object.value.p);
		if (tableObject == nullptr) {
			return 0;
		}

		int nextIndex = luaH_index(state->m_state, tableObject, &key->m_object) + 1;
		const int arraySize = tableObject->sizearray;

		if (nextIndex < arraySize) {
			TObject* arrayValue = &tableObject->array[nextIndex];
			while (arrayValue->tt == LUA_TNIL) {
				++nextIndex;
				++arrayValue;
				if (nextIndex >= arraySize) {
					break;
				}
			}

			if (nextIndex < arraySize) {
				key->AssignInteger(state, nextIndex + 1);
				value->AssignTObject(state, arrayValue);
				return 1;
			}
		}

		int nodeIndex = nextIndex - arraySize;
		const int nodeCount = 1 << tableObject->lsizenode;
		if (nodeIndex >= nodeCount) {
			return 0;
		}

		Node* const nodeBase = tableObject->node;
		TObject* valueSlot = &nodeBase[nodeIndex].i_val;
		while (valueSlot->tt == LUA_TNIL) {
			++nodeIndex;
			if (nodeIndex >= nodeCount) {
				return 0;
			}
			valueSlot = &nodeBase[nodeIndex].i_val;
		}

		key->AssignTObject(state, &nodeBase[nodeIndex].i_key);
		value->AssignTObject(state, &nodeBase[nodeIndex].i_val);
		return 1;
	}

	/**
	 * Address: 0x009102F0 (FUN_009102F0, luaK_concat)
	 *
	 * What it does:
	 * Concatenates two jump lists for Lua codegen: appends `l2` to `*l1`,
	 * walking terminal jump links in generated bytecode before patching.
	 */
	void luaK_concat(FuncState* const fs, int* const l1, const int l2)
	{
		if (l2 == LUA_MULTRET) {
			return;
		}

		int list = *l1;
		if (list == LUA_MULTRET) {
			*l1 = l2;
			return;
		}

		const auto* const fsRuntime = reinterpret_cast<const LuaFuncStateCodegenRuntimeView*>(fs);
		const Instruction* const code = fsRuntime->functionProto->code;
		while (true) {
			const int signedOffset = LuaInstructionSignedOffset(code[list]);
			if (signedOffset == LUA_MULTRET) {
				break;
			}

			const int next = list + signedOffset + 1;
			if (next == LUA_MULTRET) {
				break;
			}

			list = next;
		}

		luaK_fixjump(l2, list, fs);
	}

	/**
	 * Address: 0x00910400 (FUN_00910400, addk)
	 *
	 * What it does:
	 * Interns one constant value/key pair into `FuncState` constant tracking
	 * (`h` + `Proto::k`) and returns the resulting constant index.
	 */
	int addk(TObject* const valueObject, FuncState* const functionState, TObject* const keyObject)
	{
		auto* const fsRuntime = reinterpret_cast<LuaFuncStateConstantRuntimeView*>(functionState);
		const TObject* const lookupSlot = luaH_get(fsRuntime->constantLookupTable, keyObject);
		if (lookupSlot->tt == LUA_TNUMBER) {
			return static_cast<int>(lookupSlot->value.n);
		}

		Proto* const functionProto = fsRuntime->functionProto;
		if (fsRuntime->constantCount + 1 > functionProto->sizek) {
			functionProto->k = static_cast<TObject*>(luaM_growaux(
				fsRuntime->state,
				functionProto->k,
				&functionProto->sizek,
				static_cast<int>(sizeof(TObject)),
				0x3FFFF,
				"constant table overflow"
			));
		}

		functionProto->k[fsRuntime->constantCount] = *valueObject;

		TObject* const insertedSlot = luaH_set(fsRuntime->state, fsRuntime->constantLookupTable, keyObject);
		insertedSlot->value.n = static_cast<float>(fsRuntime->constantCount);
		insertedSlot->tt = LUA_TNUMBER;

		const int constantIndex = fsRuntime->constantCount;
		fsRuntime->constantCount = constantIndex + 1;
		return constantIndex;
	}

	/**
	 * Address: 0x00910500 (FUN_00910500, nil_constant)
	 *
	 * What it does:
	 * Interns one shared nil constant key lane (using `FuncState::h` table
	 * identity as key) and returns its constant-table index.
	 */
	int nil_constant(FuncState* const functionState)
	{
		auto* const fsRuntime = reinterpret_cast<LuaFuncStateConstantRuntimeView*>(functionState);

		TObject nilValue{};
		nilValue.tt = LUA_TNIL;

		TObject keyObject{};
		keyObject.value.p = fsRuntime->constantLookupTable;
		keyObject.tt = static_cast<int>(fsRuntime->constantLookupTable->tt);

		return addk(&nilValue, functionState, &keyObject);
	}

	struct LuaDischargeExpdescRuntimeView
	{
		int k;
		int info;
		int aux;
		int t;
		int f;
	};

	struct LuaDischargeLexStateRuntimeView
	{
		int current;
		int linenumber;
		int lastline;
	};

	static_assert(offsetof(LuaDischargeExpdescRuntimeView, k) == 0x00, "LuaDischargeExpdescRuntimeView::k offset must be 0x00");
	static_assert(offsetof(LuaDischargeExpdescRuntimeView, info) == 0x04, "LuaDischargeExpdescRuntimeView::info offset must be 0x04");
	static_assert(offsetof(LuaDischargeExpdescRuntimeView, aux) == 0x08, "LuaDischargeExpdescRuntimeView::aux offset must be 0x08");
	static_assert(offsetof(LuaDischargeExpdescRuntimeView, t) == 0x0C, "LuaDischargeExpdescRuntimeView::t offset must be 0x0C");
	static_assert(offsetof(LuaDischargeExpdescRuntimeView, f) == 0x10, "LuaDischargeExpdescRuntimeView::f offset must be 0x10");
	static_assert(sizeof(LuaDischargeExpdescRuntimeView) == 0x14, "LuaDischargeExpdescRuntimeView size must be 0x14");
	static_assert(offsetof(LuaDischargeLexStateRuntimeView, current) == 0x00, "LuaDischargeLexStateRuntimeView::current offset must be 0x00");
	static_assert(offsetof(LuaDischargeLexStateRuntimeView, linenumber) == 0x04, "LuaDischargeLexStateRuntimeView::linenumber offset must be 0x04");
	static_assert(offsetof(LuaDischargeLexStateRuntimeView, lastline) == 0x08, "LuaDischargeLexStateRuntimeView::lastline offset must be 0x08");
	static_assert(sizeof(LuaDischargeLexStateRuntimeView) == 0x0C, "LuaDischargeLexStateRuntimeView size must be 0x0C");

	/**
	 * Address: 0x00910970 (FUN_00910970, discharge2reg)
	 *
	 * What it does:
	 * Forces one expression into a destination register, rewriting the
	 * expression lane or emitting a move/load opcode as needed.
	 */
	extern "C" void discharge2reg(expdesc* const e, const int reg, FuncState* const fs)
	{
		constexpr int kExpKindNil = 1;
		constexpr int kExpKindTrue = 2;
		constexpr int kExpKindFalse = 3;
		constexpr int kExpKindConstant = 4;
		constexpr int kExpKindRelocatable = 10;
		constexpr int kExpKindNonReloc = 11;
		constexpr int kLuaOpMove = 0;
		constexpr int kLuaOpLoadBool = 2;

		auto* const expr = reinterpret_cast<LuaDischargeExpdescRuntimeView*>(e);
		auto* const fsRuntime = reinterpret_cast<LuaFuncStateCodegenRuntimeView*>(fs);

		luaK_dischargevars(fs, e);

		switch (expr->k) {
		case kExpKindNil:
			luaK_nil(fs, reg, 1);
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;

		case kExpKindTrue:
		case kExpKindFalse:
			luaK_codeABC(fs, kLuaOpLoadBool, reg, expr->k == kExpKindTrue ? 1 : 0, 0);
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;

		case kExpKindConstant:
			luaK_code(
				fs,
				static_cast<Instruction>(((expr->info | (reg << 18)) << 6) | 1),
				static_cast<int>(reinterpret_cast<LuaDischargeLexStateRuntimeView*>(fsRuntime->lexState)->lastline)
			);
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;

		case kExpKindRelocatable:
			fsRuntime->functionProto->code[expr->info] =
				(reg << 24) | (static_cast<unsigned int>(fsRuntime->functionProto->code[expr->info]) & 0x00FFFFFFu);
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;

		case kExpKindNonReloc: {
			const int info = expr->info;
			if (reg != info) {
				luaK_codeABC(fs, kLuaOpMove, reg, info, 0);
			}
			expr->info = reg;
			expr->k = kExpKindNonReloc;
			break;
		}

		default:
			return;
		}
	}

	/**
	 * Address: 0x0090DB80 (FUN_0090DB80, luaL_where)
	 *
	 * What it does:
	 * Pushes one `source(line): ` prefix when a valid debug frame exists;
	 * otherwise pushes an empty prefix string.
	 */
	void luaL_where(lua_State* const state, const int level)
	{
		lua_Debug activationRecord{};
		if (lua_getstack(state, level, &activationRecord) != 0) {
			lua_getinfo(state, "Snl", &activationRecord);
			if (activationRecord.currentline > 0) {
				lua_pushfstring(state, "%s(%d): ", activationRecord.short_src, activationRecord.currentline);
				return;
			}
		}

	lua_pushlstring(state, "", 0u);
	}

	/**
	 * Address: 0x0090DD40 (FUN_0090DD40, luaL_getmetafield)
	 *
	 * What it does:
	 * Looks up one named metafield on the object's metatable, leaving the
	 * metatable stack slot consumed on success and restoring the stack on miss.
	 */
	int luaL_getmetafield(lua_State* const state, const int obj, const char* const event)
	{
		if (lua_getmetatable(state, obj) == 0) {
			return 0;
		}

		lua_pushstring(state, event);
		lua_rawget(state, -2);
		if (lua_type(state, -1) == LUA_TNIL) {
			lua_settop(state, -3);
			return 0;
		}

		lua_remove(state, -2);
		return 1;
	}

	/**
	 * Address: 0x0090DE00 (FUN_0090DE00, luaL_openlib)
	 *
	 * What it does:
	 * Opens/creates one globals table slot for `libname`, binds every
	 * `luaL_reg` entry as a closure capturing `nup` upvalues, and restores
	 * stack height by dropping the upvalue copies and destination table.
	 */
	void luaL_openlib(lua_State* const state, const char* const libname, const luaL_reg* registration, const int nup)
	{
		if (libname != nullptr) {
			lua_pushstring(state, libname);
			lua_gettable(state, LUA_GLOBALSINDEX);
			if (lua_type(state, -1) == LUA_TNIL) {
				lua_settop(state, -2);
				lua_newtable(state);
				lua_pushstring(state, libname);
				lua_pushvalue(state, -2);
				lua_settable(state, LUA_GLOBALSINDEX);
			}
			lua_insert(state, -1 - nup);
		}

		const int destinationTableIndex = -3 - nup;
		while (registration != nullptr && registration->name != nullptr) {
			lua_pushstring(state, registration->name);
			for (int upvalueIndex = 0; upvalueIndex < nup; ++upvalueIndex) {
				lua_pushvalue(state, -1 - nup);
			}
			lua_pushcclosure(state, registration->func, nup);
			lua_settable(state, destinationTableIndex);
			++registration;
		}

		lua_settop(state, -1 - nup);
	}

	/**
	 * Address: 0x0090EBF0 (FUN_0090EBF0, luaL_optnumber)
	 *
	 * What it does:
	 * Returns `luaL_checknumber` for present non-nil argument lanes, otherwise
	 * returns caller-provided default numeric value.
	 */
	lua_Number luaL_optnumber(lua_State* const state, const int index, const lua_Number defaultValue)
	{
		if (lua_type(state, index) > LUA_TNIL) {
			return luaL_checknumber(state, index);
		}

		return defaultValue;
	}

	/**
	 * Address: 0x00927090 (FUN_00927090, computesizes)
	 *
	 * What it does:
	 * Chooses optimal array/hash split from bucketed integer-key usage counts
	 * and writes resulting dense-array size plus hash-entry count.
	 */
	void computesizes(
		const int totalUsedEntries,
		int* const narray,
		int* const nhash,
		const int* const nums
	)
	{
		int accumulatedArrayUse = nums[0];
		int bestLog = (accumulatedArrayUse != 0) ? 0 : -1;
		int bestArrayUse = accumulatedArrayUse;
		if (accumulatedArrayUse < *narray) {
			int log = 0;
			const int* numsLane = nums + 1;
			while (accumulatedArrayUse < *narray) {
				const int bucketUpperBound = 1 << log;
				if (*narray < bucketUpperBound) {
					break;
				}

				if (*numsLane > 0) {
					accumulatedArrayUse += *numsLane;
					if (accumulatedArrayUse >= bucketUpperBound) {
						bestLog = log + 1;
						bestArrayUse = accumulatedArrayUse;
					}
				}

				++numsLane;
				++log;
			}
		}

		*nhash = totalUsedEntries - bestArrayUse;
		*narray = (bestLog == -1) ? 0 : (1 << bestLog);
	}

	/**
	 * Address: 0x00927110 (FUN_00927110, numuse)
	 *
	 * What it does:
	 * Counts live Lua table entries by dense-array power-of-two buckets and
	 * hash-node lanes, then derives resize targets for array/hash partitions.
	 */
	void numuse(Table* const table, int* const narray, int* const nhash)
	{
		constexpr int kLuaTableMaxBits = 0x18;
		constexpr int kLuaBucketCount = kLuaTableMaxBits + 1;

		int totalUse = 0;
		int nums[kLuaBucketCount]{};

		int i = 0;
		int lg = 0;
		const int sizearray = table->sizearray;
		while (lg <= kLuaTableMaxBits) {
			int bucketEnd = 1 << lg;
			if (bucketEnd > sizearray) {
				bucketEnd = sizearray;
				if (i >= sizearray) {
					break;
				}
			}

			nums[lg] = 0;
			while (i < bucketEnd) {
				if (table->array[i].tt != LUA_TNIL) {
					++nums[lg];
					++totalUse;
				}
				++i;
			}

			++lg;
		}

		for (; lg < kLuaBucketCount; ++lg) {
			nums[lg] = 0;
		}

		*narray = totalUse;
		const int nodeCount = 1 << table->lsizenode;
		for (int index = nodeCount - 1; index >= 0; --index) {
			const Node& node = table->node[index];
			if (node.i_val.tt == LUA_TNIL) {
				continue;
			}

			if (node.i_key.tt == LUA_TNUMBER) {
				const float numericKey = node.i_key.value.n;
				const int integerKey = static_cast<int>(numericKey);
				if (static_cast<float>(integerKey) == numericKey && integerKey >= 1
					&& ((integerKey - 1) & 0xFF000000) == 0) {
					const int logIndex = luaO_log2(static_cast<unsigned int>(integerKey - 1));
					++nums[logIndex + 1];
					++(*narray);
				}
			}

			++totalUse;
		}

		computesizes(totalUse, narray, nhash, nums);
	}

	/**
	 * Address: 0x00927240 (FUN_00927240, setarrayvector)
	 *
	 * What it does:
	 * Resizes one table dense-array lane, nil-tags newly exposed slots, and
	 * updates `Table::sizearray`.
	 */
	int setarrayvector(const int size, Table* const table, lua_State* const state)
	{
		const lu_mem oldBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(table->sizearray);
		const lu_mem newBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(size);
		table->array = static_cast<TObject*>(luaM_realloc(state, table->array, oldBytes, newBytes));

		int index = table->sizearray;
		while (index < size) {
			table->array[index].tt = LUA_TNIL;
			++index;
		}

		table->sizearray = size;
		return index;
	}

	/**
	 * Address: 0x00927290 (FUN_00927290, setnodevector)
	 *
	 * What it does:
	 * Allocates or binds one table hash-node lane, nil-tags every hash slot key
	 * and value tag, then refreshes `lsizenode` and `firstfree`.
	 */
	Node* setnodevector(lua_State* const state, Table* const table, const int lsize)
	{
		constexpr int kLuaTableMaxHashBits = 0x18;
		if (lsize > kLuaTableMaxHashBits) {
			luaG_runerror(state, "table overflow");
		}

		const int size = 1 << lsize;
		if (lsize != 0) {
			const lu_mem nodeBytes = static_cast<lu_mem>(sizeof(Node)) * static_cast<lu_mem>(size);
			table->node = static_cast<Node*>(luaM_realloc(state, nullptr, 0u, nodeBytes));

			for (int index = 0; index < size; ++index) {
				Node& node = table->node[index];
				node.next = nullptr;
				node.i_key.tt = LUA_TNIL;
				node.i_val.tt = LUA_TNIL;
			}
		} else {
			table->node = state->l_G->dummynode;
		}

		table->lsizenode = static_cast<lu_byte>(lsize);
		Node* const firstFree = &table->node[size - 1];
		table->firstfree = firstFree;
		return firstFree;
	}

	/**
	 * Address: 0x009136F0 (FUN_009136F0, sub_9136F0)
	 *
	 * What it does:
	 * Records one newly-created table type entry in Lua debug allocation-size
	 * map while temporarily disabling recursive allocation tracking.
	 */
	void LuaDebugTrackNewTableAllocation(lua_State* const state, Table* const table)
	{
		global_State* const globalState = state->l_G;
		++globalState->gcTraversalLockDepth;
		globalState->unknown150 = 0;

		TObject* const top = state->top;
		top->tt = static_cast<int>(table->tt);
		top->value.p = table;
		state->top = top + 1;

		Table* const sizesTable = LuaDebugGetSizesTable(state);
		TObject* const destination = luaH_set(state, sizesTable, state->top - 1);

		lua_pushstring(state, lua_typename(state, table->tt));
		(void)_errorfb(state, 0);

		*destination = *(state->top - 1);
		state->top -= 2;

		globalState->unknown150 = 1;
		--globalState->gcTraversalLockDepth;
	}

	/**
	 * Address: 0x00927320 (FUN_00927320, luaH_new)
	 *
	 * What it does:
	 * Allocates and initializes one Lua table object, links it into GC lists,
	 * allocates array/hash lanes, and applies debug allocation tracking hook.
	 */
	Table* luaH_new(lua_State* const state, const int narray, const int lnhash)
	{
		Table* const table = static_cast<Table*>(luaM_realloc(state, nullptr, 0u, sizeof(Table)));
		luaC_link(state, reinterpret_cast<GCObject*>(table), LUA_TTABLE);

		auto* const globalStateView = reinterpret_cast<LuaGlobalStateTableAllocRuntimeView*>(state->l_G);
		table->metatable = globalStateView->defaultTableMetatable;
		table->flags = static_cast<std::int8_t>(-1);
		table->array = nullptr;
		table->sizearray = 0;
		table->lsizenode = 0;
		table->node = nullptr;

		(void)setarrayvector(narray, table, state);
		(void)setnodevector(state, table, lnhash);

		if (globalStateView->allocationTrackingEnabled != 0) {
			LuaDebugTrackNewTableAllocation(state, table);
		}

		return table;
	}

	/**
	 * Address: 0x009273A0 (FUN_009273A0, luaH_free)
	 *
	 * What it does:
	 * Releases one Lua table's hash-node and array storage, then frees the
	 * table object itself through Lua allocator callbacks.
	 */
	void luaH_free(lua_State* const state, Table* const table)
	{
		if (table->lsizenode != 0) {
			const lu_mem nodeBytes = static_cast<lu_mem>(sizeof(Node)) * static_cast<lu_mem>(1u << table->lsizenode);
			(void)luaM_realloc(state, table->node, nodeBytes, 0u);
		}

		const lu_mem arrayBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(table->sizearray);
		(void)luaM_realloc(state, table->array, arrayBytes, 0u);
		(void)luaM_realloc(state, table, static_cast<lu_mem>(sizeof(Table)), 0u);
	}

	/**
	 * Address: 0x00927780 (FUN_00927780, resize)
	 *
	 * What it does:
	 * Rebuilds one Lua table's array/hash storage to new capacities, migrates
	 * live entries across resized lanes, and frees old hash storage when
	 * applicable.
	 */
	int resize(Table* const table, const int newArraySize, lua_State* const state, const int newHashBits)
	{
		const int oldArraySize = table->sizearray;
		const int oldHashBits = table->lsizenode;
		Node* oldNodeArray = table->node;

		Node copiedDummyNode{};
		if (oldHashBits == 0) {
			copiedDummyNode = *oldNodeArray;
			oldNodeArray = &copiedDummyNode;
			state->l_G->dummynode[0].i_key.tt = LUA_TNIL;
			state->l_G->dummynode[0].i_val.tt = LUA_TNIL;
		}

		if (newArraySize > oldArraySize) {
			setarrayvector(newArraySize, table, state);
		}
		setnodevector(state, table, newHashBits);

		if (newArraySize < oldArraySize) {
			table->sizearray = newArraySize;
			for (int index = newArraySize; index < oldArraySize; ++index) {
				TObject* const arraySlot = &table->array[index];
				if (arraySlot->tt == LUA_TNIL) {
					continue;
				}

				const int oneBasedKey = index + 1;
				TObject* destinationSlot = const_cast<TObject*>(luaH_getnum(table, oneBasedKey));
				if (destinationSlot->tt == LUA_TNIL) {
					destinationSlot = luaH_setnum(state, table, oneBasedKey);
				}
				*destinationSlot = *arraySlot;
			}

			const lu_mem oldArrayBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(oldArraySize);
			const lu_mem newArrayBytes = static_cast<lu_mem>(sizeof(TObject)) * static_cast<lu_mem>(newArraySize);
			table->array = static_cast<TObject*>(luaM_realloc(state, table->array, oldArrayBytes, newArrayBytes));
		}

		const int oldNodeCount = 1 << oldHashBits;
		for (int index = oldNodeCount - 1; index >= 0; --index) {
			const Node& oldNode = oldNodeArray[index];
			if (oldNode.i_val.tt == LUA_TNIL) {
				continue;
			}

			TObject* const destinationSlot = luaH_set(state, table, &oldNode.i_key);
			*destinationSlot = oldNode.i_val;
		}

		if (oldHashBits != 0) {
			const lu_mem oldNodeBytes = static_cast<lu_mem>(sizeof(Node)) * static_cast<lu_mem>(oldNodeCount);
			return static_cast<int>(reinterpret_cast<std::uintptr_t>(luaM_realloc(state, oldNodeArray, oldNodeBytes, 0u)));
		}

		return oldNodeCount;
	}

	/**
	 * Address: 0x00927930 (FUN_00927930, sub_927930)
	 *
	 * What it does:
	 * Recomputes Lua table array/hash resize targets from current occupancy and
	 * applies one resize pass with the derived hash-bit count.
	 */
	int RehashTableFromUsage(Table* const table, lua_State* const state)
	{
		int narray = 0;
		int nhash = 0;
		numuse(table, &narray, &nhash);
		const int hashBits = luaO_log2(static_cast<unsigned int>(nhash)) + 1;
		return resize(table, narray, state, hashBits);
	}

	/**
	 * Address: 0x00927970 (FUN_00927970, newkey)
	 *
	 * What it does:
	 * Inserts one missing key into Lua table storage, relocating collided nodes
	 * through `firstfree` chains and triggering table resize when hash lanes
	 * are exhausted.
	 */
	TObject* newkey(lua_State* const state, Table* const table, const TObject* const key)
	{
		Node* mainPosition = luaH_mainposition(table, key);
		if (mainPosition->i_val.tt != LUA_TNIL) {
			Node* const collidingMainPosition = luaH_mainposition(table, &mainPosition->i_key);
			Node* const firstFree = table->firstfree;
			if (collidingMainPosition == mainPosition) {
				firstFree->next = mainPosition->next;
				mainPosition->next = firstFree;
				mainPosition = firstFree;
			} else {
				Node* collisionPrev = collidingMainPosition;
				while (collisionPrev->next != mainPosition) {
					collisionPrev = collisionPrev->next;
				}

				collisionPrev->next = firstFree;
				firstFree->i_key = mainPosition->i_key;
				firstFree->i_val = mainPosition->i_val;
				firstFree->next = mainPosition->next;
				mainPosition->next = nullptr;
				mainPosition->i_val.tt = LUA_TNIL;
			}
		}

		mainPosition->i_key = *key;
		if (table->firstfree->i_key.tt == LUA_TNIL) {
			return &mainPosition->i_val;
		}

		const Node* const nodeStart = table->node;
		for (;;) {
			Node* const currentFirstFree = table->firstfree;
			if (currentFirstFree == nodeStart) {
				break;
			}

			Node* const previousNode = currentFirstFree - 1;
			table->firstfree = previousNode;
			if (previousNode->i_key.tt == LUA_TNIL) {
				return &mainPosition->i_val;
			}
		}

		mainPosition->i_val.tt = LUA_TBOOLEAN;
		mainPosition->i_val.value.b = 0;
		(void)RehashTableFromUsage(table, state);

		TObject* valueSlot = nullptr;
		if (key->tt == LUA_TNUMBER) {
			const float numericKey = key->value.n;
			const int integerKey = static_cast<int>(numericKey);
			if (static_cast<float>(integerKey) == numericKey) {
				valueSlot = const_cast<TObject*>(luaH_getnum(table, integerKey));
			}
		} else if (key->tt == LUA_TSTRING) {
			valueSlot = const_cast<TObject*>(luaH_getstr(table, static_cast<TString*>(key->value.p)));
		}

		if (valueSlot == nullptr) {
			valueSlot = const_cast<TObject*>(luaH_getany(key, table));
		}

		valueSlot->tt = LUA_TNIL;
		return valueSlot;
	}

	/**
	 * Address: 0x00927560 (FUN_00927560, luaH_set)
	 *
	 * What it does:
	 * Resolves mutable slot for one table key (with integer/string fast-paths),
	 * resets table metamethod-cache flags, and inserts missing keys via `newkey`.
	 */
	TObject* luaH_set(lua_State* const state, Table* const table, const TObject* const key)
	{
		const TObject* slot = nullptr;
		if (key->tt == LUA_TNUMBER) {
			const float numericKey = key->value.n;
			const int integerKey = static_cast<int>(numericKey);
			if (static_cast<float>(integerKey) == numericKey) {
				slot = luaH_getnum(table, integerKey);
			}
		} else if (key->tt == LUA_TSTRING) {
			slot = luaH_getstr(table, static_cast<TString*>(key->value.p));
		}

		if (slot == nullptr) {
			slot = luaH_getany(key, table);
		}

		table->flags = 0;
		if (slot == &luaO_nilobject) {
			if (key->tt == LUA_TNIL) {
				luaG_runerror(state, "table index is nil");
			} else if (key->tt == LUA_TNUMBER) {
				const float numericKey = key->value.n;
				if (numericKey != numericKey) {
					luaG_runerror(state, "table index is NaN");
				}
			}

			return newkey(state, table, key);
		}

		return const_cast<TObject*>(slot);
	}

	/**
	 * Address: 0x00927AC0 (FUN_00927AC0, luaH_setnum)
	 *
	 * What it does:
	 * Resolves or inserts one integer-key table slot and returns the mutable
	 * value lane for callers to assign payload data.
	 */
	TObject* luaH_setnum(lua_State* const state, Table* const table, const int key)
	{
		const TObject* slot = luaH_getnum(table, key);
		if (slot == &luaO_nilobject) {
			TObject numericKey{};
			numericKey.tt = LUA_TNUMBER;
			numericKey.value.n = static_cast<float>(key);
			return newkey(state, table, &numericKey);
		}

		return const_cast<TObject*>(slot);
	}

	/**
	 * Address: 0x00927EF0 (FUN_00927EF0, sub_927EF0)
	 *
	 * What it does:
	 * Compares two stack lanes for table-sort partitioning, using custom
	 * comparator at stack index 2 when present and falling back to
	 * `lua_lessthan` when comparator is absent.
	 */
	[[nodiscard]] int LuaSortLessThanWithOptionalComparator(
		const int leftStackIndex,
		const int rightStackIndex,
		lua_State* const state
	)
	{
		if (lua_type(state, 2) == LUA_TNONE) {
			return lua_lessthan(state, rightStackIndex, leftStackIndex);
		}

		lua_pushvalue(state, 2);
		lua_pushvalue(state, rightStackIndex - 1);
		lua_pushvalue(state, leftStackIndex - 2);
		lua_call(state, 2, 1);
		const int lessThan = lua_toboolean(state, -1);
		lua_settop(state, -2);
		return lessThan;
	}

	/**
	 * Address: 0x00910A70 (FUN_00910A70, discharge2anyreg)
	 *
	 * What it does:
	 * Ensures one expression is materialized in a register lane, grows
	 * `Proto::maxstacksize` when needed, and throws parser syntax errors when
	 * register usage exceeds Lua's function complexity cap.
	 */
	void discharge2anyreg(FuncState* const fs, expdesc* const e)
	{
		constexpr int kExpKindNonReloc = 0x0B;
		constexpr int kLuaMaxFunctionRegisterSlots = 0xFA;

		auto* const fsView = reinterpret_cast<LuaFuncStateCodegenRuntimeView*>(fs);
		const auto* const expView = reinterpret_cast<const LuaExpDescCodegenRuntimeView*>(e);
		if (expView->kind == kExpKindNonReloc) {
			return;
		}

		const int requiredRegisterCount = fsView->freeRegister + 1;
		if (requiredRegisterCount > static_cast<int>(fsView->functionProto->maxstacksize)) {
			if (requiredRegisterCount >= kLuaMaxFunctionRegisterSlots) {
				luaX_syntaxerror(fsView->lexState, "function or expression too complex");
			}
			fsView->functionProto->maxstacksize = static_cast<lu_byte>(requiredRegisterCount);
		}

		discharge2reg(e, fsView->freeRegister++, fs);
	}

	/**
	 * Address: 0x0091AE90 (FUN_0091AE90, indexupvalue)
	 *
	 * What it does:
	 * Finds or appends one parser upvalue entry matching expression
	 * kind/info lanes, grows proto upvalue-name storage when needed, and
	 * returns resolved upvalue index.
	 */
	int indexupvalue(FuncState* const fs, expdesc* const value, TString* const name)
	{
		constexpr int kLuaMaxUpvalues = 0x20;
		constexpr int kLuaIntMaxMinusTwo = 0x7FFFFFFD;
		constexpr int kUpvalueNameEntrySizeBytes = 4;

		auto* const fsView = reinterpret_cast<LuaFuncStateUpvalueRuntimeView*>(fs);
		Proto* const proto = fsView->functionProto;
		const auto* const valueView = reinterpret_cast<const LuaExpDescCodegenRuntimeView*>(value);

		int index = 0;
		const int existingUpvalueCount = static_cast<int>(proto->nups);
		while (index < existingUpvalueCount) {
			const LuaExpDescCodegenRuntimeView& slot = fsView->upvalues[index];
			if (slot.kind == valueView->kind && slot.info == valueView->info) {
				return index;
			}
			++index;
		}

		luaX_checklimit(fsView->lexState, existingUpvalueCount + 1, kLuaMaxUpvalues, "upvalues");
		int& upvalueCapacity = proto->sizeupvalues;
		if (existingUpvalueCount + 1 > upvalueCapacity) {
			proto->upvalues = static_cast<TString**>(
				luaM_growaux(
					fsView->state,
					proto->upvalues,
					&upvalueCapacity,
					kUpvalueNameEntrySizeBytes,
					kLuaIntMaxMinusTwo,
					"upvalues"
				)
			);
		}

		proto->upvalues[existingUpvalueCount] = name;
		fsView->upvalues[existingUpvalueCount] = *valueView;
		proto->nups = static_cast<lu_byte>(existingUpvalueCount + 1);
		return existingUpvalueCount;
	}

} // extern "C"

namespace
{
	struct LuaZioRuntimeView;

	extern "C"
	{
		const TObject* luaH_get(Table* t, const TObject* key);
		const TObject* luaH_getnum(Table* t, int key);
		const TObject* luaH_getstr(Table* t, TString* key);
		TObject* luaH_set(lua_State* L, Table* t, const TObject* key);
		TObject* luaH_setnum(lua_State* L, Table* t, int key);
		TObject* luaA_index(lua_State* L, int index);
		Table* luaH_new(lua_State* L, int narray, int nhash);
		TString* luaS_newlstr(lua_State* L, const char* str, size_t len);
		const char* luaF_getlocalname(const Proto* func, int local_number, int pc);
		Table* luaT_getmetatable(lua_State* L, const TObject* o);
		int luaO_log2(unsigned int x);
		const TObject* luaV_gettable(lua_State* L, const TObject* t, const TObject* key, StkId val);
		void luaV_settable(lua_State* L, const TObject* t, TObject* key, StkId val);
		int luaV_tonumber(const TObject* obj, TObject* outNumber);
		int luaV_tostring(lua_State* L, TObject* obj);
		const char* getobjname(int stackPos, CallInfo* callInfo, const char** nameOut);
		void luaG_runerror(lua_State* L, const char* format, ...);
		int luaZ_fill(LuaZioRuntimeView* stream);
		int luaZ_read(LuaZioRuntimeView* stream, void* buffer, size_t size);
		std::FILE* __cdecl __iob_func(void);
		void luaO_chunkid(char* out, const char* source, size_t bufflen);
		void luaA_pushobject(lua_State* L, const TObject* o);
		int luaopen_serialize(lua_State* L);
		void reallymarkobject(GCState* gcState, GCObject* object);
		int luaD_call(lua_State* L, StkId func, int nResults);
		int luaD_precall(lua_State* L, StkId func);
		void luaD_callhook(lua_State* L, int event, int line);
		int luaD_poscall(lua_State* L, int wanted, StkId firstResult);
		void luaD_reallocCI(lua_State* L, int newsize);
		void luaD_growstack(lua_State* L, int n);
		StkId luaV_execute(lua_State* L);
		void* luaM_realloc(lua_State* L, void* oldblock, lu_mem oldsize, lu_mem size);
		void correctstack(lua_State* L, TObject* oldstack);
		extern const char* luaT_typenames[];
	}
	constexpr std::uint16_t kLuaMaxCallInfoFrames = 0x1000u;

	[[nodiscard]] gpg::RRef* lua_newuserdata_ref(
		const gpg::RRef* const sourceRef,
		lua_State* const state,
		gpg::RType* const fallbackType
	)
	{
		void* const storage = lua_newuserdata(state, sizeof(gpg::RRef));
		if (storage == nullptr) {
			return nullptr;
		}

		auto* const outRef = static_cast<gpg::RRef*>(storage);
		if (sourceRef != nullptr) {
			*outRef = *sourceRef;
		} else {
			outRef->mObj = nullptr;
			outRef->mType = nullptr;
		}

		if (outRef->mType == nullptr) {
			outRef->mType = fallbackType;
		}
		return outRef;
	}

	/**
	 * Address: 0x00924A10 (FUN_00924A10, luaS_newudata)
	 *
	 * What it does:
	 * Allocates one reflected userdata payload for `type`, default-constructs
	 * the payload through the registered `ctorRefFunc_`, and links userdata into
	 * the root userdata list.
	 */
	[[nodiscard]] Udata* CreateDefaultConstructedUserdata(lua_State* const state, gpg::RType* const type)
	{
		if (type->ctorRefFunc_ == nullptr) {
			luaG_runerror(state, "type %s is not default constructible", type->GetName());
		}

		const std::size_t userdataSize = sizeof(Udata) + static_cast<std::size_t>(type->size_);
		Udata* const userdata = static_cast<Udata*>(luaM_realloc(state, nullptr, 0u, userdataSize));

		try {
			void* const payload = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
			(void)type->ctorRefFunc_(payload);
		} catch (...) {
			(void)luaM_realloc(state, userdata, userdataSize, 0u);
			throw;
		}

		userdata->len = reinterpret_cast<std::size_t>(type);
		userdata->tt = LUA_TUSERDATA;
		userdata->marked = (type->dtrFunc_ != nullptr) ? 2u : 0u;

		auto* const globalStateRuntime = reinterpret_cast<LuaGlobalStateUserdataRuntimeView*>(state->l_G);
		userdata->metatable = globalStateRuntime->userdataMetatable;
		userdata->next = globalStateRuntime->rootUserdata;
		globalStateRuntime->rootUserdata = reinterpret_cast<GCObject*>(userdata);
		return userdata;
	}

	/**
	 * Address: 0x00924AF0 (FUN_00924AF0, luaS_newudata2)
	 *
	 * What it does:
	 * Allocates one reflected userdata payload for `sourceRef`, move-constructs
	 * it through the source type handler, and links it into root userdata lanes.
	 */
	[[nodiscard]] Udata* CreateRefUserdata(lua_State* const state, gpg::RRef* const sourceRef)
	{
		gpg::RType* const sourceType = sourceRef->mType;
		if (sourceType->movRefFunc_ == nullptr) {
			luaG_runerror(state, "type %s is not copy constructible", sourceType->GetName());
		}

		const std::size_t userdataSize = sizeof(Udata) + static_cast<std::size_t>(sourceType->size_);
		Udata* const userdata = static_cast<Udata*>(luaM_realloc(state, nullptr, 0u, userdataSize));

		try {
			void* const payload = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
			(void)sourceType->movRefFunc_(payload, sourceRef);
		} catch (...) {
			(void)luaM_realloc(state, userdata, userdataSize, 0u);
			throw;
		}

		userdata->len = reinterpret_cast<std::size_t>(sourceType);
		userdata->tt = LUA_TUSERDATA;
		userdata->marked = (sourceType->dtrFunc_ != nullptr) ? 2u : 0u;

		auto* const globalStateRuntime = reinterpret_cast<LuaGlobalStateUserdataRuntimeView*>(state->l_G);
		userdata->metatable = globalStateRuntime->userdataMetatable;
		userdata->next = globalStateRuntime->rootUserdata;
		globalStateRuntime->rootUserdata = reinterpret_cast<GCObject*>(userdata);
		return userdata;
	}

	[[nodiscard]] gpg::RRef BuildRefFromUserdata(Udata* const userdata)
	{
		gpg::RRef out{};
		out.mObj = reinterpret_cast<std::uint8_t*>(userdata) + sizeof(Udata);
		out.mType = reinterpret_cast<gpg::RType*>(userdata->len);
		return out;
	}

	/**
	 * Address: 0x00912D30 (FUN_00912D30, kname)
	 *
	 * What it does:
	 * Resolves one proto constant-table slot name from a stack/register index
	 * by subtracting `MAXSTACK`; returns `"?"` when slot is out of range or not
	 * a Lua string constant.
	 */
	[[maybe_unused]] const char* kname(const int stackSlotIndex, const Proto* const proto)
	{
		constexpr int kLuaParserMaxStackSlots = 0xFA;
		constexpr const char* kUnknownName = "?";

		const int constantIndex = stackSlotIndex - kLuaParserMaxStackSlots;
		if (constantIndex < 0 || proto == nullptr || proto->k == nullptr) {
			return kUnknownName;
		}

		const LuaPlus::TObject& constant = proto->k[constantIndex];
		if (constant.tt != LUA_TSTRING || constant.value.p == nullptr) {
			return kUnknownName;
		}

		return static_cast<const TString*>(constant.value.p)->str;
	}

	/**
	 * Address: 0x009127F0 (FUN_009127F0, travglobals)
	 *
	 * What it does:
	 * Scans the global table hash nodes for a value equal to `object` and
	 * returns the associated string-key name when found.
	 */
	[[maybe_unused]] const char* travglobals(lua_State* const state, const TObject* const object)
	{
		auto* const globalsTable = static_cast<Table*>(state->_gt.value.p);
		int remaining = 1 << globalsTable->lsizenode;
		if (remaining == 0) {
			return nullptr;
		}

		int nodeIndex = remaining;
		while (remaining > 0) {
			Node* const node = &globalsTable->node[--nodeIndex];
			--remaining;

			if (luaO_rawequalObj(object, &node->i_val) != 0 && node->i_key.tt == LUA_TSTRING) {
				return static_cast<const TString*>(node->i_key.value.p)->str;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x009128D0 (FUN_009128D0, checkopenop)
	 *
	 * What it does:
	 * Checks whether instruction `pc + 1` is an "open" opcode lane for
	 * symbolic execution (`OP_CALL`..`OP_RETURN` with open-result flag cleared,
	 * or `OP_SETLIST`).
	 */
	[[maybe_unused]] bool checkopenop(const Proto* const proto, const int pc)
	{
		constexpr unsigned int kLuaOpcodeMask = 0x3Fu;
		constexpr unsigned int kLuaOpenOperandMask = 0x00FF8000u;
		constexpr unsigned int kOpCall = 0x1Du;
		constexpr unsigned int kOpReturn = 0x1Fu;
		constexpr unsigned int kOpSetList = 0x24u;

		const Instruction instruction = proto->code[pc + 1];
		const unsigned int opcode = static_cast<unsigned int>(instruction) & kLuaOpcodeMask;
		if (opcode >= kOpCall) {
			if (opcode <= kOpReturn) {
				return (static_cast<unsigned int>(instruction) & kLuaOpenOperandMask) == 0u;
			}

			if (opcode == kOpSetList) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Address: 0x00912530 (FUN_00912530, currentline)
	 *
	 * What it does:
	 * Returns one active source line for the current frame when `savedpc` maps
	 * into Lua bytecode; returns `-1` for non-Lua frames and `0` when lineinfo
	 * is absent.
	 */
	[[maybe_unused]] int currentline(CallInfo* const ci)
	{
		constexpr int kCiSavedPc = 3;
		if (ci->state >= kCiSavedPc) {
			return -1;
		}

		const auto* const closure = static_cast<const Closure*>(ci->base[-1].value.p);
		const Proto* const proto = closure->l.p;
		const int instructionIndex = static_cast<int>(ci->savedpc - proto->code);
		if (instructionIndex < 0) {
			return -1;
		}

		if (proto->lineinfo != nullptr) {
			return proto->lineinfo[instructionIndex];
		}

		return 0;
	}

	/**
	 * Address: 0x00912910 (FUN_00912910, checkRK)
	 *
	 * What it does:
	 * Validates one RK operand lane against either register space
	 * (`< maxstacksize`) or constant-table space (`MAXSTACK + k`).
	 */
	[[maybe_unused]] bool checkRK(const int rkIndex, const Proto* const proto)
	{
		constexpr int kLuaParserMaxStackSlots = 0xFA;
		return rkIndex < static_cast<int>(proto->maxstacksize)
			|| (rkIndex >= kLuaParserMaxStackSlots
				&& (rkIndex - kLuaParserMaxStackSlots) < proto->sizek);
	}

	/**
	 * Address: 0x00912E90 (FUN_00912E90, getfuncname)
	 *
	 * What it does:
	 * Resolves callee object-name metadata for call/tailcall opcodes in the
	 * previous Lua frame and returns the object-class string from `getobjname`.
	 */
	[[maybe_unused]] const char* getfuncname(const char** const nameOut, CallInfo* const ci)
	{
		constexpr int kCiSavedPc = 3;
		constexpr int kOpCall = 29;
		constexpr int kOpTailCall = 30;

		if ((ci->state < kCiSavedPc && ci->tailcalls > 0) || (ci - 1)->state >= kCiSavedPc) {
			return nullptr;
		}

		CallInfo* const callerFrame = ci - 1;
		const auto* const callerClosure = static_cast<const Closure*>(callerFrame->base[-1].value.p);
		const Proto* const callerProto = callerClosure->l.p;

		int instructionIndex = -1;
		if (callerFrame->state < kCiSavedPc) {
			instructionIndex = static_cast<int>(callerFrame->savedpc - callerProto->code);
		}

		const Instruction instruction = callerProto->code[instructionIndex];
		const int opcode = static_cast<int>(instruction & 0x3Fu);
		if (opcode != kOpCall && opcode != kOpTailCall) {
			return nullptr;
		}

		return getobjname(static_cast<int>(instruction >> 24u), callerFrame, nameOut);
	}

	/**
	 * Address: 0x00912F30 (FUN_00912F30, addinfo)
	 *
	 * What it does:
	 * Prefixes one Lua error message with `chunk(line): ` when the active call
	 * frame is a Lua function and returns the formatted string lane.
	 */
	[[maybe_unused]] const char* addinfo(lua_State* const state, const char* const msg)
	{
		char buff[60]{};
		CallInfo* const ci = state->ci;
		if (ci->state < 3) {
			const auto* const closure = static_cast<const Closure*>(ci->base[-1].value.p);
			const Proto* const proto = closure->l.p;
			const int line = currentline(ci);
			luaO_chunkid(buff, proto->source->str, sizeof(buff));
			return luaO_pushfstring(state, "%s(%d): %s", buff, line, msg);
		}

		return msg;
	}

	/**
	 * Address: 0x009133A0 (FUN_009133A0, luaG_typeerror)
	 *
	 * What it does:
	 * Resolves Lua operand provenance/name when possible and raises a typed
	 * operation error matching Lua's runtime wording.
	 */
	void luaG_typeerror(lua_State* const state, const TObject* const object, const char* const operation)
	{
		const char* const valueType = luaT_typenames[object->tt];
		CallInfo* const callInfo = state->ci;
		const char* objectName = nullptr;
		TObject* stackSlot = callInfo->base;
		const TObject* const stackTop = callInfo->top;

		while (stackSlot < stackTop) {
			if (stackSlot == object) {
				const int stackIndex = static_cast<int>(object - state->base);
				const char* const objectClass = getobjname(stackIndex, callInfo, &objectName);
				if (objectClass != nullptr) {
					luaG_runerror(
						state, "attempt to %s %s `%s' (a %s value)", operation, objectClass, objectName, valueType
					);
				}
				break;
			}
			++stackSlot;
		}

		luaG_runerror(state, "%s expected but got %s", operation, valueType);
	}

	/**
	 * Address: 0x00913420 (FUN_00913420, luaV_concat type-error helper)
	 *
	 * What it does:
	 * Selects the non-string operand lane from two concat candidates and raises
	 * `luaG_typeerror(..., "concatenate")`.
	 */
	[[maybe_unused]] [[noreturn]] void luaV_concat_raise_typeerror(
		lua_State* const state,
		TObject* const leftCandidate,
		TObject* const rightCandidate
	)
	{
		TObject* errorOperand = leftCandidate;
		if (leftCandidate != nullptr && leftCandidate->tt == LUA_TSTRING) {
			errorOperand = rightCandidate;
		}

		luaG_typeerror(state, errorOperand, "concatenate");
		std::abort();
	}

	/**
	 * Address: 0x00914240 (FUN_00914240, luaD_growCI)
	 *
	 * What it does:
	 * Doubles call-info capacity and raises runtime overflow errors for
	 * recursive error handling and post-growth stack-limit overrun.
	 */
	[[maybe_unused]] void luaD_growCI(lua_State* const state)
	{
		const std::uint16_t currentFrameCapacity = state->size_ci;
		if (currentFrameCapacity > kLuaMaxCallInfoFrames) {
			luaG_runerror(state, "error in Lua error handling");
		}

		luaD_reallocCI(state, static_cast<int>(currentFrameCapacity) * 2);
		if (state->size_ci > kLuaMaxCallInfoFrames) {
			luaG_runerror(state, "stack overflow");
		}
	}

	/**
	 * Address: 0x00913850 (FUN_00913850, correctstack)
	 *
	 * What it does:
	 * Rebases stack-relative `top/base/callinfo/open-upvalue` pointers after one
	 * Lua stack reallocation from `oldStackBase` to `state->stack`.
	 */
	extern "C" void correctstack(lua_State* const state, TObject* const oldStackBase)
	{
		TObject* const newStackBase = state->stack;
		state->top = &newStackBase[state->top - oldStackBase];

		for (GCObject* openUpvalue = state->openupval; openUpvalue != nullptr; openUpvalue = openUpvalue->gch.next) {
			UpVal* const upvalue = &openUpvalue->uv;
			upvalue->v = &newStackBase[upvalue->v - oldStackBase];
		}

		for (CallInfo* frame = state->base_ci; frame <= state->ci; ++frame) {
			frame->top = &newStackBase[frame->top - oldStackBase];
			frame->base = &newStackBase[frame->base - oldStackBase];
		}

		state->base = state->ci->base;
	}

	/**
	 * Address: 0x00913990 (FUN_00913990, luaD_growstack)
	 *
	 * What it does:
	 * Reallocates Lua stack storage, grows by either `2x` or `n + EXTRA_STACK`,
	 * then rewrites stack-relative pointers through `correctstack`.
	 */
	extern "C" void luaD_growstack(lua_State* const state, const int n)
	{
		constexpr int kLuaExtraStackSlots = 5;
		const int currentStackSize = state->stacksize;
		TObject* const oldStackBase = state->stack;
		const int newStackSize =
			(n > currentStackSize) ? (currentStackSize + n + kLuaExtraStackSlots) : (currentStackSize * 2);
		TObject* const newStackBase = static_cast<TObject*>(luaM_realloc(
			state,
			oldStackBase,
			static_cast<lu_mem>(sizeof(TObject) * currentStackSize),
			static_cast<lu_mem>(sizeof(TObject) * newStackSize)
		));
		state->stack = newStackBase;
		state->stacksize = newStackSize;
		state->stack_last = &newStackBase[newStackSize - 6];
		correctstack(state, oldStackBase);
	}

	/**
	 * Address: 0x009292F0 (FUN_009292F0, callTM)
	 *
	 * What it does:
	 * Pushes one metamethod + three operands, performs a no-result Lua call,
	 * and preserves stack-growth behavior.
	 */
	[[maybe_unused]] void callTM(
		const TObject* const firstOperand,
		const TObject* const secondOperand,
		const TObject* const thirdOperand,
		lua_State* const state,
		const TObject* const metamethodFunction
	)
	{
		TObject* const top = state->top;
		top[0] = *metamethodFunction;
		top[1] = *firstOperand;
		top[2] = *secondOperand;
		top[3] = *thirdOperand;

		if (reinterpret_cast<const char*>(state->stack_last) - reinterpret_cast<const char*>(state->top) <= 32) {
			luaD_growstack(state, 4);
		}

		state->top += 4;
		(void)luaD_call(state, state->top - 4, 0);
	}

	/**
	 * Address: 0x009295A0 (FUN_009295A0, get_compTM)
	 *
	 * What it does:
	 * Resolves one comparison metamethod from both metatables and returns it
	 * only when both sides expose the same metamethod function.
	 */
	[[maybe_unused]] const TObject* get_compTM(
		Table* const leftMetatable,
		const int event,
		lua_State* const state,
		Table* const rightMetatable
	)
	{
		const lu_byte eventMask = static_cast<lu_byte>(1u << static_cast<unsigned int>(event));
		if ((leftMetatable->flags & eventMask) != 0u) {
			return nullptr;
		}

		const TObject* const leftTagMethod = luaT_gettm(leftMetatable, event, state->l_G->tmname[event]);
		if (leftTagMethod == nullptr) {
			return nullptr;
		}

		if (leftMetatable == rightMetatable) {
			return leftTagMethod;
		}

		if ((rightMetatable->flags & eventMask) != 0u) {
			return nullptr;
		}

		const TObject* const rightTagMethod = luaT_gettm(rightMetatable, event, state->l_G->tmname[event]);
		if (rightTagMethod == nullptr) {
			return nullptr;
		}

		return (luaO_rawequalObj(leftTagMethod, rightTagMethod) != 0) ? leftTagMethod : nullptr;
	}

	/**
	 * Address: 0x00929280 (FUN_00929280, callTMres)
	 *
	 * What it does:
	 * Pushes one metamethod function + two operands, executes one Lua call with
	 * a single expected result, then pops that result slot from the Lua stack.
	 */
	[[maybe_unused]] int callTMres(
		const TObject* const metamethodFunction,
		const TObject* const leftOperand,
		const TObject* const rightOperand,
		lua_State* const state
	)
	{
		TObject* const top = state->top;
		top[0] = *metamethodFunction;
		top[1] = *leftOperand;
		top[2] = *rightOperand;

		if (reinterpret_cast<const char*>(state->stack_last) - reinterpret_cast<const char*>(state->top) <= 24) {
			luaD_growstack(state, 3);
		}

		state->top += 3;
		const int callResult = luaD_call(state, state->top - 3, 1);
		--state->top;
		return callResult;
	}

	[[nodiscard]] static const TObject*
	LookupTagMethodByObject(lua_State* const state, const TObject* const object, const int event)
	{
		Table* const metatable = luaT_getmetatable(state, object);
		if (metatable == nullptr) {
			return &luaO_nilobject;
		}

		return luaT_gettm(metatable, event, state->l_G->tmname[event]);
	}

	/**
	 * Address: 0x00929610 (FUN_00929610, call_orderTM)
	 *
	 * What it does:
	 * Resolves order metamethod on both operands, executes one shared metamethod
	 * call when both sides match, and returns Lua-truthiness of result.
	 */
	[[maybe_unused]] int call_orderTM(
		lua_State* const state,
		const TObject* const leftOperand,
		const TObject* const rightOperand,
		const int event
	)
	{
		const TObject* const rightMetamethod = LookupTagMethodByObject(state, rightOperand, event);
		if (rightMetamethod->tt == LUA_TNIL) {
			return -1;
		}

		const TObject* const leftMetamethod = LookupTagMethodByObject(state, leftOperand, event);
		if (luaO_rawequalObj(rightMetamethod, leftMetamethod) == 0) {
			return -1;
		}

		(void)callTMres(rightMetamethod, leftOperand, rightOperand, state);
		const TObject* const result = state->top;
		return (result->tt != LUA_TNIL && (result->tt != LUA_TBOOLEAN || result->value.b != 0)) ? 1 : 0;
	}

	/**
	 * Address: 0x00913AD0 (FUN_00913AD0, adjust_varargs)
	 *
	 * What it does:
	 * Pads missing fixed args with nil, collects extra args into one vararg
	 * table (`1..n` plus string key `"n"`), and pushes that table.
	 */
	[[maybe_unused]] void adjust_varargs(lua_State* const state, int fixedArgCount, StkId base)
	{
		int actualArgCount = static_cast<int>(state->top - base);
		if (actualArgCount < fixedArgCount) {
			int missingArgCount = fixedArgCount - actualArgCount;
			if ((state->stack_last - state->top) <= missingArgCount) {
				luaD_growstack(state, missingArgCount);
			}

			actualArgCount = fixedArgCount;
			while (missingArgCount-- > 0) {
				state->top->tt = LUA_TNIL;
				++state->top;
			}
		}

		actualArgCount -= fixedArgCount;
		Table* const varargTable = luaH_new(state, actualArgCount, 1);
		for (int index = 0; index < actualArgCount; ++index) {
			const TObject* const sourceSlot = state->top - actualArgCount + index;
			*luaH_setnum(state, varargTable, index + 1) = *sourceSlot;
		}

		TString* const internedCountKey = luaS_newlstr(state, "n", 1u);
		TObject keyN{};
		keyN.tt = static_cast<int>(internedCountKey->tt);
		keyN.value.p = internedCountKey;

		TObject* const countSlot = luaH_set(state, varargTable, &keyN);
		countSlot->tt = LUA_TNUMBER;
		countSlot->value.n = static_cast<float>(actualArgCount);

		state->top -= actualArgCount;
		state->top->tt = static_cast<int>(varargTable->tt);
		state->top->value.p = varargTable;

		if ((state->stack_last - state->top) <= 1) {
			const int currentStackSize = state->stacksize;
			TObject* const oldStackBase = state->stack;
			int newStackSize = currentStackSize * 2;
			if (currentStackSize < 1) {
				newStackSize = currentStackSize + 6;
			}

			TObject* const newStackBase = static_cast<TObject*>(luaM_realloc(
				state,
				oldStackBase,
				static_cast<lu_mem>(sizeof(TObject) * currentStackSize),
				static_cast<lu_mem>(sizeof(TObject) * newStackSize)
			));
			state->stack = newStackBase;
			state->stack_last = &newStackBase[newStackSize - 6];
			state->stacksize = newStackSize;
			correctstack(state, oldStackBase);
		}

		++state->top;
	}

	[[noreturn]] void LuaAssertFail(const char* message)
	{
		throw std::runtime_error(message ? message : "Lua assertion failed");
	}

	void Ensure(bool cond, const char* message)
	{
		if (!cond) {
			LuaAssertFail(message);
		}
	}

	/**
	 * Address: 0x00924020 (FUN_00924020, defaultFatalErrorFunc)
	 *
	 * What it does:
	 * Handles unrecoverable Lua VM fatal-error fallback by terminating the
	 * process with exit code `1`.
	 */
	[[noreturn]] void defaultFatalErrorFunc()
	{
		std::exit(1);
	}

	template <class TObjectType>
	[[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
	{
		if (slot == nullptr) {
			slot = gpg::LookupRType(typeid(TObjectType));
		}
		return slot;
	}

	gpg::RType* gLuaTObjectType = nullptr;
	gpg::RType* gWrapFileType = nullptr;

	struct WrapFile
	{
		std::FILE* stream;
		std::uint8_t closeEnabled;
		std::uint8_t reserved[3];
	};
	static_assert(sizeof(WrapFile) == 0x8, "WrapFile size must be 0x8");
	static_assert(offsetof(WrapFile, stream) == 0x0, "WrapFile::stream offset must be 0x0");
	static_assert(offsetof(WrapFile, closeEnabled) == 0x4, "WrapFile::closeEnabled offset must be 0x4");

	struct WrapFileRuntimeView
	{
		std::FILE* stream;
		std::uint8_t closeEnabled;
		std::uint8_t reserved[3];
	};
	static_assert(offsetof(WrapFileRuntimeView, closeEnabled) == 0x4, "WrapFileRuntimeView::closeEnabled offset must be 0x4");
	static_assert(sizeof(WrapFileRuntimeView) == sizeof(WrapFile), "WrapFileRuntimeView size must match WrapFile");

	class WrapFileTypeInfo final : public gpg::RType
	{
	public:
		[[nodiscard]] const char* GetName() const override;

		/**
		 * Address: 0x00917FE0 (FUN_00917FE0, WrapFileTypeInfo::Init)
		 *
		 * What it does:
		 * Initializes WrapFile reflection size/callback lanes and finalizes the
		 * descriptor.
		 */
		void Init() override;
	};

	class TObjectTypeInfo final : public gpg::RType
	{
	public:
		[[nodiscard]] const char* GetName() const override;

		/**
		 * Address: 0x00921F50 (FUN_00921F50, TObjectTypeInfo::Init)
		 *
		 * What it does:
		 * Initializes TObject reflection size lane and finalizes the descriptor.
		 */
		void Init() override;
	};

	struct LuaZioRuntimeView
	{
		int remainingBytes;
		const char* cursor;
	};
	static_assert(offsetof(LuaZioRuntimeView, remainingBytes) == 0x0, "LuaZioRuntimeView::remainingBytes offset must be 0x0");
	static_assert(offsetof(LuaZioRuntimeView, cursor) == 0x4, "LuaZioRuntimeView::cursor offset must be 0x4");

	struct LuaLoadStateRuntimeView
	{
		lua_State* state;
		LuaZioRuntimeView* stream;
		void* reserved08;
		int swapBytes;
		const char* chunkName;
	};
	static_assert(offsetof(LuaLoadStateRuntimeView, state) == 0x0, "LuaLoadStateRuntimeView::state offset must be 0x0");
	static_assert(offsetof(LuaLoadStateRuntimeView, stream) == 0x4, "LuaLoadStateRuntimeView::stream offset must be 0x4");
	static_assert(offsetof(LuaLoadStateRuntimeView, swapBytes) == 0xC, "LuaLoadStateRuntimeView::swapBytes offset must be 0xC");
	static_assert(offsetof(LuaLoadStateRuntimeView, chunkName) == 0x10, "LuaLoadStateRuntimeView::chunkName offset must be 0x10");

	constexpr int kLuaRefUserdataTypeTag = LUA_TUSERDATA;
	constexpr int kLuaIoUpvalueEnvIndex = lua_upvalueindex(1);
	constexpr int kLuaIoReadlineFileUpvalueIndex = lua_upvalueindex(1);
	constexpr int kLuaIoReadlineCloseOnEofUpvalueIndex = lua_upvalueindex(2);
	constexpr std::size_t kLuaIoReadChunkSize = 0x200;
	constexpr const char* kLuaDebugHookRegistryKey = "h";
	constexpr const char* kLuaDebugExternalHookLabel = "external hook";
	constexpr const char* kLuaDebugPrompt = "lua_debug> ";
	constexpr const char* kLuaDebugContinueToken = "cont\n";
	constexpr int kLuaDebugInputBufferSize = 0xFC;
	constexpr int kLuaDebugReadLineLimit = 0xFA;
	constexpr int kLuaRegistryAllocationSizesKey = 3;
	constexpr const char* const kLuaDebugHookEventNames[] = {
		"call",
		"return",
		"line",
		"count",
		"tail return"
	};
	static_assert(
		(sizeof(kLuaDebugHookEventNames) / sizeof(kLuaDebugHookEventNames[0])) == 5,
		"kLuaDebugHookEventNames must match Lua hook event count"
	);

	/**
	 * Address: 0x0090CBB0 (FUN_0090CBB0, func_GetRRefFromUserdata)
	 *
	 * What it does:
	 * Reads one userdata stack lane, then materializes `{payload, rtype}` into
	 * a reflected `gpg::RRef`; non-userdata/out-of-range lanes return null ref.
	 */
	void GetRRefFromUserdata(gpg::RRef* const out, lua_State* const state, const int index)
	{
		if (out == nullptr) {
			return;
		}

		out->mObj = nullptr;
		out->mType = nullptr;
		if (state == nullptr || lua_type(state, index) != kLuaRefUserdataTypeTag) {
			return;
		}

		// Lua userdata payload starts at +0x10 from GCObject; rtype lane is at +0x0C.
		std::uint8_t* const payload = static_cast<std::uint8_t*>(lua_touserdata(state, index));
		if (payload == nullptr) {
			return;
		}

		out->mObj = payload;
		out->mType = *reinterpret_cast<gpg::RType* const*>(payload - sizeof(void*));
	}

	bool IsWrapFileTypeName(const char* const typeName)
	{
		return typeName != nullptr && std::strstr(typeName, "WrapFile") != nullptr;
	}

	/**
	 * Address: 0x00917060 (FUN_00917060, gpg::RRef::TryUpcast_WrapFile)
	 *
	 * What it does:
	 * Validates reflected userdata carries one WrapFile-compatible type lane,
	 * then returns the wrapped file payload pointer; throws `BadRefCast` on
	 * mismatch to match runtime cast-failure behavior.
	 */
	WrapFileRuntimeView* TryUpcastWrapFile(gpg::RRef* const reference)
	{
		const char* sourceTypeName = "null";
		if (reference != nullptr && reference->mType != nullptr) {
			const char* const runtimeTypeName = reference->mType->GetName();
			sourceTypeName = runtimeTypeName != nullptr ? runtimeTypeName : "null";
		}

		if (reference == nullptr || reference->mObj == nullptr || !IsWrapFileTypeName(sourceTypeName)) {
			throw gpg::BadRefCast(nullptr, sourceTypeName, "WrapFile");
		}

		return static_cast<WrapFileRuntimeView*>(reference->mObj);
	}

	/**
	 * Address: 0x00917240 (FUN_00917240, aux_close)
	 *
	 * What it does:
	 * Closes one wrapped FILE lane only when close-enabled; prefers `_pclose`
	 * and falls back through `fclose` error path exactly as original control
	 * flow, then nulls the stored stream pointer.
	 */
	int AuxClose(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, 1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		if (wrapFile->closeEnabled == 0 || wrapFile->stream == nullptr) {
			return 0;
		}

		if (::_pclose(wrapFile->stream) == -1 && std::fclose(wrapFile->stream) != 0) {
			wrapFile->stream = nullptr;
			return 0;
		}

		wrapFile->stream = nullptr;
		return 1;
	}

	/**
	 * Address: 0x009172B0 (FUN_009172B0, lua::io_close)
	 *
	 * What it does:
	 * Resolves default `_output` file handle from io upvalue when arg-1 is
	 * missing, attempts wrapped close, and pushes Lua `(true)` or
	 * `(nil, strerror(errno), errno-number)` result lanes.
	 */
	[[maybe_unused]] int LuaIoClose(lua_State* const state)
	{
		if (lua_type(state, 1) == LUA_TNONE && lua_type(state, kLuaIoUpvalueEnvIndex) == LUA_TTABLE) {
			lua_pushstring(state, "_output");
			lua_rawget(state, kLuaIoUpvalueEnvIndex);
		}

		if (AuxClose(state)) {
			lua_pushboolean(state, 1);
			return 1;
		}

		lua_pushnil(state);
		const int errorCode = *_errno();
		lua_pushfstring(state, "%s", std::strerror(errorCode));
		lua_pushnumber(state, static_cast<lua_Number>(errorCode));
		return 3;
	}

	/**
	 * Address: 0x00917B10 (FUN_00917B10, lua::f_flush)
	 *
	 * What it does:
	 * Flushes one reflected wrapped FILE handle, raising Lua closed-file error
	 * for null stream lane and returning standard io-library `(true)` or
	 * `(nil, strerror(errno), errno-number)` result tuples.
	 */
	[[maybe_unused]] int LuaFileFlush(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, 1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		if (std::fflush(wrapFile->stream) == 0) {
			lua_pushboolean(state, 1);
			return 1;
		}

		lua_pushnil(state);
		const int errorCode = *_errno();
		lua_pushfstring(state, "%s", std::strerror(errorCode));
		lua_pushnumber(state, static_cast<lua_Number>(errorCode));
		return 3;
	}

	/**
	 * Address: 0x00915F60 (FUN_00915F60, lua::io_dir)
	 *
	 * What it does:
	 * Expands one wildcard expression through CRT find-first/find-next and
	 * returns one Lua table of 1-based filename entries.
	 */
	[[maybe_unused]] int LuaIoDir(lua_State* const state)
	{
		const char* const wildcard = lua_tostring(state, 1);
		lua_newtable(state);

		__finddata64_t findData{};
		const intptr_t findHandle = ::_findfirst64(wildcard, &findData);
		if (findHandle != -1) {
			int index = 1;
			lua_pushnumber(state, static_cast<lua_Number>(index));
			lua_pushstring(state, findData.name);
			lua_settable(state, -3);

			while (::_findnext64(findHandle, &findData) == 0) {
				++index;
				lua_pushnumber(state, static_cast<lua_Number>(index));
				lua_pushstring(state, findData.name);
				lua_settable(state, -3);
			}

			(void)::_findclose(findHandle);
		}

		return 1;
	}

	bool ReadLine(std::FILE* const stream, lua_State* const state);
	gpg::RRef* BuildWrapFileRef(gpg::RRef* const out, WrapFileRuntimeView* const wrapFile);

	/**
	 * Address: 0x00916020 (FUN_00916020, read_number)
	 *
	 * What it does:
	 * Reads one floating-point value from `FILE*` and pushes it as Lua number;
	 * returns zero on scan failure.
	 */
	[[maybe_unused]] int ReadNumberFromFile(std::FILE* const stream, lua_State* const state)
	{
		double value = 0.0;
		if (std::fscanf(stream, "%lf", &value) != 1) {
			return 0;
		}

		lua_pushnumber(state, static_cast<lua_Number>(value));
		return 1;
	}

	/**
	 * Address: 0x00916160 (FUN_00916160, read_chars)
	 *
	 * What it does:
	 * Reads up to `count` bytes from `FILE*` into one Lua buffer string and
	 * returns success when full count was read or at least one byte was pushed.
	 */
	[[maybe_unused]] bool ReadCharsFromFile(std::size_t count, std::FILE* const stream, lua_State* const state)
	{
		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);

		std::size_t chunkSize = kLuaIoReadChunkSize;
		std::size_t readCount = 0u;
		do {
			char* const writeBuffer = luaL_prepbuffer(&buffer);
			if (chunkSize > count) {
				chunkSize = count;
			}

			readCount = std::fread(writeBuffer, 1u, chunkSize, stream);
			buffer.p += readCount;
			count -= readCount;
		} while (count != 0u && readCount == chunkSize);

		luaL_pushresult(&buffer);
		return count == 0u || lua_strlen(state, -1) > 0u;
	}

	/**
	 * Address: 0x009161F0 (FUN_009161F0, g_read)
	 *
	 * What it does:
	 * Implements Lua IO read options (`number`, `*l`, `*n`, `*a`) over one
	 * wrapped `FILE*`, preserving nil-on-failure stack/result semantics.
	 */
	[[maybe_unused]] int LuaReadFromFile(
		std::FILE* const stream,
		lua_State* const state,
		const int firstArgumentIndex
	)
	{
		int argumentIndex = firstArgumentIndex;
		int readSucceeded = 1;
		int remainingOptions = lua_gettop(state) - 1;

		if (remainingOptions == 0) {
			readSucceeded = ReadLine(stream, state) ? 1 : 0;
			argumentIndex = firstArgumentIndex + 1;
		} else {
			luaL_checkstack(state, remainingOptions + 20, "too many arguments");
			while (remainingOptions > 0) {
				--remainingOptions;
				if (readSucceeded == 0) {
					break;
				}

				if (lua_type(state, argumentIndex) == LUA_TNUMBER) {
					const int requestedCount = static_cast<int>(lua_tonumber(state, argumentIndex));
					if (requestedCount != 0) {
						readSucceeded = ReadCharsFromFile(
							static_cast<std::size_t>(static_cast<unsigned int>(requestedCount)), stream, state
						)
							? 1
							: 0;
					} else {
						const int nextChar = std::getc(stream);
						std::ungetc(nextChar, stream);
						lua_pushlstring(state, nullptr, 0u);
						readSucceeded = nextChar != EOF ? 1 : 0;
					}
				} else if (lua_type(state, argumentIndex) == LUA_TSTRING) {
					const char* const option = lua_tostring(state, argumentIndex);
					if (option == nullptr || option[0] != '*') {
						luaL_argerror(state, argumentIndex, "invalid option");
					}

					switch (option[1]) {
					case 'a':
						(void)ReadCharsFromFile(
							static_cast<std::size_t>(std::numeric_limits<unsigned int>::max()), stream, state
						);
						readSucceeded = 1;
						break;
					case 'l':
						readSucceeded = ReadLine(stream, state) ? 1 : 0;
						break;
					case 'n':
						readSucceeded = ReadNumberFromFile(stream, state);
						break;
					case 'w':
						luaL_error(state, "obsolete option `*w' to 'read'");
						break;
					default:
						luaL_argerror(state, argumentIndex, "invalid format");
						break;
					}
				}

				++argumentIndex;
			}
		}

		if (readSucceeded == 0) {
			lua_settop(state, -2);
			lua_pushnil(state);
		}

		return argumentIndex - firstArgumentIndex;
	}

	/**
	 * Address: 0x00916090 (FUN_00916090, read_line)
	 *
	 * What it does:
	 * Reads one text line from a wrapped `FILE*`, strips the trailing newline
	 * when present, pushes the line as Lua string, and returns non-empty status.
	 */
	bool ReadLine(std::FILE* const stream, lua_State* const state)
	{
		std::string line{};
		char chunk[512]{};

		while (std::fgets(chunk, static_cast<int>(sizeof(chunk)), stream) != nullptr) {
			const size_t chunkLength = std::strlen(chunk);
			if (chunkLength == 0) {
				continue;
			}

			if (chunk[chunkLength - 1] == '\n') {
				line.append(chunk, chunkLength - 1);
				lua_pushlstring(state, line.c_str(), line.size());
				return true;
			}

			line.append(chunk, chunkLength);
		}

		lua_pushlstring(state, line.c_str(), line.size());
		return !line.empty();
	}

	/**
	 * Address: 0x009177E0 (FUN_009177E0, io_readline)
	 *
	 * What it does:
	 * Reads one line from the wrapped file upvalue, optionally auto-closes on
	 * EOF depending on the boolean close-flag upvalue, and returns Lua iterator
	 * success status (`1` for value pushed, `0` for EOF).
	 */
	[[maybe_unused]] int LuaIoReadline(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, kLuaIoReadlineFileUpvalueIndex);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		std::FILE* const stream = wrapFile->stream;
		if (stream == nullptr) {
			luaL_error(state, "file is already closed");
		}

		if (ReadLine(stream, state)) {
			return 1;
		}

		if (lua_toboolean(state, kLuaIoReadlineCloseOnEofUpvalueIndex) != 0) {
			lua_settop(state, 0);
			lua_pushvalue(state, kLuaIoReadlineFileUpvalueIndex);
			(void)AuxClose(state);
		}

		return 0;
	}

	/**
	 * Address: 0x00917DC0 (FUN_00917DC0, lua::aux_lines)
	 *
	 * What it does:
	 * Creates one line-iterator closure for a wrapped file handle with
	 * upvalues `{FILE* metatable, file userdata, closeOnEof=false}`.
	 */
	[[maybe_unused]] int LuaAuxLines(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, 1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);
		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		lua_pushlstring(state, "FILE*", 5u);
		lua_rawget(state, LUA_REGISTRYINDEX);
		lua_pushvalue(state, 1);
		lua_pushboolean(state, 0);
		lua_pushcclosure(state, LuaIoReadline, 3);
		return 1;
	}

	/**
	 * Address: 0x00917190 (FUN_00917190, newfile)
	 *
	 * What it does:
	 * Allocates one WrapFile userdata lane, binds `FILE*` metatable, and sets
	 * the close-enabled byte according to caller intent.
	 */
	WrapFileRuntimeView* NewFileUserdata(lua_State* const state, const bool closeEnabled)
	{
		gpg::RRef reference{};
		lua_newuserdata_ref(&reference, state, CachedType<WrapFile>(gWrapFileType));
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		luaL_getmetatable(state, "FILE*");
		lua_setmetatable(state, -2);
		wrapFile->closeEnabled = closeEnabled ? 1u : 0u;
		return wrapFile;
	}

	/**
	 * Address: 0x00917000 (FUN_00917000, sub_917000)
	 *
	 * What it does:
	 * Destroys one heap-allocated WrapFile storage lane, conditionally closing
	 * the stream when close-enabled, then frees the payload block.
	 */
	[[maybe_unused]] void DestroyWrapFileStorage(WrapFileRuntimeView* const wrapFile)
	{
		if (wrapFile == nullptr) {
			return;
		}

		if (wrapFile->stream != nullptr && wrapFile->closeEnabled != 0u) {
			std::fclose(wrapFile->stream);
		}

		wrapFile->stream = nullptr;
		::operator delete(wrapFile);
	}

	/**
	 * Address: 0x00917030 (FUN_00917030, sub_917030)
	 *
	 * What it does:
	 * Performs WrapFile close-on-destruct semantics in-place and clears the
	 * stream lane, returning the raw x86 `EAX` result payload.
	 */
	[[maybe_unused]] std::intptr_t FinalizeWrapFileStorage(WrapFileRuntimeView* const wrapFile)
	{
		std::intptr_t result = reinterpret_cast<std::intptr_t>(wrapFile->stream);
		if (wrapFile->stream != nullptr && wrapFile->closeEnabled != 0u) {
			result = static_cast<std::intptr_t>(std::fclose(wrapFile->stream));
		}

		wrapFile->stream = nullptr;
		return result;
	}

	/**
	 * Address: 0x00917D00 (FUN_00917D00, sub_917D00)
	 *
	 * What it does:
	 * Allocates one heap WrapFile storage payload and returns it as reflected
	 * `gpg::RRef` with close-enabled default state.
	 */
	[[maybe_unused]] gpg::RRef* NewWrapFileStorageRef(gpg::RRef* const out)
	{
		auto* const wrapFile = static_cast<WrapFileRuntimeView*>(::operator new(sizeof(WrapFileRuntimeView), std::nothrow));
		if (wrapFile != nullptr) {
			wrapFile->stream = nullptr;
			wrapFile->closeEnabled = 1u;
		}

		return BuildWrapFileRef(out, wrapFile);
	}

	/**
	 * Address: 0x00917D40 (FUN_00917D40, sub_917D40)
	 *
	 * What it does:
	 * Initializes caller-owned WrapFile storage and returns the reflected
	 * `gpg::RRef` view of that payload.
	 */
	[[maybe_unused]] gpg::RRef* ConstructWrapFileStorageRef(
		gpg::RRef* const out,
		WrapFileRuntimeView* const wrapFile
	)
	{
		if (wrapFile != nullptr) {
			wrapFile->stream = nullptr;
			wrapFile->closeEnabled = 1u;
		}

		return BuildWrapFileRef(out, wrapFile);
	}

	const char* WrapFileTypeInfo::GetName() const
	{
		return "WrapFile";
	}

	/**
	 * Address: 0x00917FE0 (FUN_00917FE0, WrapFileTypeInfo::Init)
	 *
	 * What it does:
	 * Initializes WrapFile reflection size/callback lanes and finalizes the
	 * descriptor.
	 */
	void WrapFileTypeInfo::Init()
	{
		size_ = sizeof(WrapFile);
		gpg::RType::Init();
		newRefFunc_ = reinterpret_cast<gpg::RType::new_ref_func_t>(&NewWrapFileStorageRef);
		ctorRefFunc_ = reinterpret_cast<gpg::RType::ctor_ref_func_t>(&ConstructWrapFileStorageRef);
		deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(&FinalizeWrapFileStorage);
		Finish();
	}

	const char* TObjectTypeInfo::GetName() const
	{
		return "TObject";
	}

	/**
	 * Address: 0x00921F50 (FUN_00921F50, TObjectTypeInfo::Init)
	 *
	 * What it does:
	 * Initializes TObject reflection size lane and finalizes the descriptor.
	 */
	void TObjectTypeInfo::Init()
	{
		size_ = sizeof(TObject);
		gpg::RType::Init();
		Finish();
	}

	/**
	 * Address: 0x00917CE0 (FUN_00917CE0, sub_917CE0)
	 *
	 * What it does:
	 * Binds WrapFile cleanup callbacks (`delete`, `destruct`) onto one
	 * reflection type descriptor lane.
	 */
	[[maybe_unused]] gpg::RType* ConfigureWrapFileCleanupCallbacks(gpg::RType* const type)
	{
		type->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		type->dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(&FinalizeWrapFileStorage);
		return type;
	}

	/**
	 * Address: 0x00917F10 (FUN_00917F10, sub_917F10)
	 *
	 * What it does:
	 * Binds WrapFile `new-ref` and `construct-ref` callbacks onto one
	 * reflection type descriptor lane.
	 */
	[[maybe_unused]] gpg::RType* ConfigureWrapFileRefCallbacks(gpg::RType* const type)
	{
		type->newRefFunc_ = reinterpret_cast<gpg::RType::new_ref_func_t>(&NewWrapFileStorageRef);
		type->ctorRefFunc_ = reinterpret_cast<gpg::RType::ctor_ref_func_t>(&ConstructWrapFileStorageRef);
		return type;
	}

	/**
	 * Address: 0x00917F30 (FUN_00917F30, sub_917F30)
	 *
	 * What it does:
	 * Binds full WrapFile callback suite (`new/construct/delete/destruct`) onto
	 * one reflection type descriptor lane.
	 */
	[[maybe_unused]] gpg::RType* ConfigureWrapFileAllCallbacks(gpg::RType* const type)
	{
		type->newRefFunc_ = reinterpret_cast<gpg::RType::new_ref_func_t>(&NewWrapFileStorageRef);
		type->ctorRefFunc_ = reinterpret_cast<gpg::RType::ctor_ref_func_t>(&ConstructWrapFileStorageRef);
		type->deleteFunc_ = reinterpret_cast<gpg::RType::delete_func_t>(&DestroyWrapFileStorage);
		type->dtrFunc_ = reinterpret_cast<gpg::RType::dtr_func_t>(&FinalizeWrapFileStorage);
		return type;
	}

	/**
	 * Address: 0x00917100 (FUN_00917100, sub_917100)
	 *
	 * What it does:
	 * Builds one reflected `gpg::RRef` lane for a WrapFile runtime payload.
	 */
	[[maybe_unused]] gpg::RRef* BuildWrapFileRef(gpg::RRef* const out, WrapFileRuntimeView* const wrapFile)
	{
		out->mObj = wrapFile;
		out->mType = CachedType<WrapFile>(gWrapFileType);
		return out;
	}

	/**
	 * Address: 0x00917130 (FUN_00917130, sub_917130)
	 *
	 * What it does:
	 * Validates that one userdata stack lane resolves to a WrapFile payload.
	 */
	[[maybe_unused]] void ValidateWrapFileUserdataAt(lua_State* const state, const int index)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, index);
		(void)TryUpcastWrapFile(&reference);
	}

	/**
	 * Address: 0x00917150 (FUN_00917150, tofile)
	 *
	 * What it does:
	 * Resolves one wrapped file userdata and returns `FILE*`, raising Lua's
	 * closed-file error when stream lane is null.
	 */
	[[maybe_unused]] std::FILE* ToFile(lua_State* const state, const int index)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, index);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);
		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		return wrapFile->stream;
	}

	/**
	 * Address: 0x009175B0 (FUN_009175B0, sub_9175B0)
	 *
	 * What it does:
	 * Looks up global io handle by key (`_input`/`_output`) and returns wrapped
	 * `FILE*`, raising Lua closed-file error when stream lane is null.
	 */
	[[maybe_unused]] std::FILE* GetIoFileFromGlobal(lua_State* const state, const char* const globalKey)
	{
		lua_pushstring(state, globalKey);
		lua_rawget(state, LUA_GLOBALSINDEX);

		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, -1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);
		if (wrapFile->stream == nullptr) {
			luaL_error(state, "attempt to use a closed file");
		}

		return wrapFile->stream;
	}

	/**
	 * Address: 0x00917540 (FUN_00917540, lua::io_tmpfile)
	 *
	 * What it does:
	 * Creates one temporary `FILE*` wrapped userdata and returns either the
	 * handle or standard Lua io `(nil, strerror(errno), errno)` error tuple.
	 */
	[[maybe_unused]] int LuaIoTmpFile(lua_State* const state)
	{
		WrapFileRuntimeView* const wrapFile = NewFileUserdata(state, true);
		wrapFile->stream = std::tmpfile();
		if (wrapFile->stream != nullptr) {
			return 1;
		}

		lua_pushnil(state);
		const int errorCode = *_errno();
		lua_pushfstring(state, "%s", std::strerror(errorCode));
		lua_pushnumber(state, static_cast<lua_Number>(errorCode));
		return 3;
	}

	/**
	 * Address: 0x00916C80 (FUN_00916C80, io_difftime)
	 *
	 * What it does:
	 * Converts the first two numeric arguments to a time span and pushes the
	 * `difftime` result as one Lua number.
	 */
	[[maybe_unused]] int io_difftime(lua_State* const state)
	{
		const std::time_t right = static_cast<std::time_t>(luaL_optnumber(state, 2, 0.0f));
		const std::time_t left = static_cast<std::time_t>(luaL_checknumber(state, 1));
		lua_pushnumber(state, static_cast<lua_Number>(std::difftime(left, right)));
		return 1;
	}

	/**
	 * Address: 0x00917350 (FUN_00917350, lua::io_tostring)
	 *
	 * What it does:
	 * Formats one wrapped file userdata lane as `file (%p)` when open, or
	 * `file (closed)` when the underlying stream lane is null.
	 */
	[[maybe_unused]] int LuaIoToString(lua_State* const state)
	{
		gpg::RRef reference{};
		GetRRefFromUserdata(&reference, state, 1);
		WrapFileRuntimeView* const wrapFile = TryUpcastWrapFile(&reference);

		char description[128]{};
		if (wrapFile->stream != nullptr) {
			std::sprintf(description, "%p", static_cast<void*>(wrapFile));
		} else {
			std::strcpy(description, "closed");
		}

		lua_pushfstring(state, "file (%s)", description);
		return 1;
	}

	int PushIoOpenFailure(lua_State* const state, const char* const path)
	{
		lua_pushnil(state);
		const int errorCode = *_errno();
		const char* const errorText = std::strerror(errorCode);
		if (path != nullptr) {
			lua_pushfstring(state, "%s: %s", path, errorText);
		} else {
			lua_pushfstring(state, "%s", errorText);
		}
		lua_pushnumber(state, static_cast<lua_Number>(*_errno()));
		return 3;
	}

	int pushresult(const char* const path, lua_State* const state, const bool success)
	{
		if (success) {
			lua_pushboolean(state, 1);
			return 1;
		}

		return PushIoOpenFailure(state, path);
	}

	/**
	 * Address: 0x009173E0 (FUN_009173E0, lua::io_open)
	 *
	 * What it does:
	 * Opens one file path with optional mode and returns either wrapped file
	 * userdata or the standard Lua io error tuple.
	 */
	[[maybe_unused]] int LuaIoOpen(lua_State* const state)
	{
		const char* const filePath = luaL_checklstring(state, 1, nullptr);
		const char* const mode = luaL_optlstring(state, 2, "r", nullptr);

		WrapFileRuntimeView* const wrapFile = NewFileUserdata(state, true);
		wrapFile->stream = std::fopen(filePath, mode);
		if (wrapFile->stream != nullptr) {
			return 1;
		}

		return PushIoOpenFailure(state, filePath);
	}

	/**
	 * Address: 0x00917490 (FUN_00917490, lua::io_popen)
	 *
	 * What it does:
	 * Opens one process pipe with optional mode and returns either wrapped file
	 * userdata or the standard Lua io error tuple.
	 */
	[[maybe_unused]] int LuaIoPopen(lua_State* const state)
	{
		const char* const command = luaL_checklstring(state, 1, nullptr);
		const char* const mode = luaL_optlstring(state, 2, "r", nullptr);

		WrapFileRuntimeView* const wrapFile = NewFileUserdata(state, true);
		wrapFile->stream = ::_popen(command, mode);
		if (wrapFile->stream != nullptr) {
			return 1;
		}

		return PushIoOpenFailure(state, command);
	}

	/**
	 * Address: 0x00916500 (FUN_00916500, io_execute)
	 *
	 * What it does:
	 * Executes one shell command from arg-1 and returns process exit code as a
	 * single Lua numeric result.
	 */
	[[maybe_unused]] int io_execute(lua_State* const state)
	{
		const char* const command = luaL_checklstring(state, 1, nullptr);
		const int resultCode = std::system(command);
		lua_pushnumber(state, static_cast<lua_Number>(resultCode));
		return 1;
	}

	/**
	 * Address: 0x00916540 (FUN_00916540, io_remove)
	 *
	 * What it does:
	 * Removes one filesystem path from Lua arg-1 and returns standard
	 * io-library success/error tuple via `pushresult`.
	 */
	[[maybe_unused]] int io_remove(lua_State* const state)
	{
		const char* const path = luaL_checklstring(state, 1, nullptr);
		const int removeResult = std::remove(path);
		return pushresult(path, state, removeResult == 0);
	}

	/**
	 * Address: 0x00916570 (FUN_00916570, io_rename)
	 *
	 * What it does:
	 * Renames one filesystem path pair from Lua args 1/2 and returns standard
	 * io-library success/error tuple via `pushresult`.
	 */
	[[maybe_unused]] int io_rename(lua_State* const state)
	{
		const char* const sourcePath = luaL_checklstring(state, 1, nullptr);
		const char* const destinationPath = luaL_checklstring(state, 2, nullptr);
		const int renameResult = std::rename(sourcePath, destinationPath);
		return pushresult(sourcePath, state, renameResult == 0);
	}

	/**
	 * Address: 0x009165B0 (FUN_009165B0, io_tmpname)
	 *
	 * What it does:
	 * Produces one temporary filename string through `tmpnam`; raises Lua error
	 * when the CRT cannot provide a unique path.
	 */
	[[maybe_unused]] int io_tmpname(lua_State* const state)
	{
		char tempName[16]{};
		if (std::tmpnam(tempName) != tempName) {
			return luaL_error(state, "unable to generate a unique filename in `tmpname'");
		}

		lua_pushstring(state, tempName);
		return 1;
	}

	/**
	 * Address: 0x00916600 (FUN_00916600, io_getenv)
	 *
	 * What it does:
	 * Reads one environment-variable name from arg-1, pushes its value as Lua
	 * string (or nil when not found), and returns one result.
	 */
	[[maybe_unused]] int io_getenv(lua_State* const state)
	{
		const char* const variableName = luaL_checklstring(state, 1, nullptr);
		const char* const variableValue = std::getenv(variableName);
		lua_pushstring(state, variableValue);
		return 1;
	}

	/**
	 * Address: 0x00916630 (FUN_00916630, io_clock)
	 *
	 * What it does:
	 * Samples CRT `clock()` ticks and returns elapsed seconds as one Lua number.
	 */
	[[maybe_unused]] int io_clock(lua_State* const state)
	{
		const int tickCount = std::clock();
		lua_pushnumber(state, static_cast<lua_Number>(static_cast<float>(tickCount) * 0.001f));
		return 1;
	}

	/**
	 * Address: 0x00916D60 (FUN_00916D60, io_exit)
	 *
	 * What it does:
	 * Reads one optional numeric exit code from arg-1 (default zero), converts
	 * it to process exit status, and terminates the host process.
	 */
	[[maybe_unused]] [[noreturn]] int io_exit(lua_State* const state)
	{
		const int exitCode = static_cast<int>(luaL_optnumber(state, 1, 0.0f));
		std::exit(exitCode);
	}

	/**
	 * Address: 0x009163C0 (FUN_009163C0, g_write)
	 *
	 * What it does:
	 * Writes Lua string/number arguments to one `FILE*` lane and returns
	 * standard io-library success or `(nil, strerror(errno), errno)` tuple.
	 */
	[[maybe_unused]] int LuaWriteToFile(
		int firstArgumentIndex,
		lua_State* const state,
		std::FILE* const stream
	)
	{
		int remainingArguments = lua_gettop(state) - 1;
		int writeSucceeded = 1;
		if (remainingArguments == 0) {
			lua_pushboolean(state, 1);
			return 1;
		}

		do {
			--remainingArguments;
			if (lua_type(state, firstArgumentIndex) == LUA_TNUMBER) {
				if (writeSucceeded != 0) {
					const double value = lua_tonumber(state, firstArgumentIndex);
					writeSucceeded = std::fprintf(stream, "%.14g", value) > 0 ? 1 : 0;
				}
			} else if (lua_type(state, firstArgumentIndex) == LUA_TSTRING) {
				std::size_t elementCount = 0u;
				const char* const text = luaL_checklstring(state, firstArgumentIndex, &elementCount);
				if (writeSucceeded == 0 || std::fwrite(text, 1u, elementCount, stream) != elementCount) {
					writeSucceeded = 0;
				} else {
					writeSucceeded = 1;
				}
			}

			++firstArgumentIndex;
		} while (remainingArguments != 0);

		if (writeSucceeded != 0) {
			lua_pushboolean(state, 1);
			return 1;
		}

		lua_pushnil(state);
		const int errorCode = *_errno();
		lua_pushfstring(state, "%s", std::strerror(errorCode));
		lua_pushnumber(state, static_cast<lua_Number>(*_errno()));
		return 3;
	}

	/**
	 * Address: 0x00917600 (FUN_00917600, g_iofile)
	 *
	 * What it does:
	 * Updates global io default handle (`_input`/`_output`) from path-or-file
	 * arg-1 and returns the resolved current default handle.
	 */
	[[maybe_unused]] int LuaIoFile(lua_State* const state, const char* const globalKey, const char* const mode)
	{
		if (lua_type(state, 1) > LUA_TNONE) {
			const char* const argument = lua_tostring(state, 1);
			lua_pushstring(state, globalKey);

			if (argument != nullptr) {
				WrapFileRuntimeView* const wrapFile = NewFileUserdata(state, true);
				wrapFile->stream = std::fopen(argument, mode);
				if (wrapFile->stream == nullptr) {
					const int errorCode = *_errno();
					lua_pushfstring(state, "%s: %s", argument, std::strerror(errorCode));
					luaL_argerror(state, 1, lua_tostring(state, -1));
				}
			} else {
				(void)ToFile(state, 1);
				lua_pushvalue(state, 1);
			}

			lua_rawset(state, LUA_ENVIRONINDEX);
		}

		lua_pushstring(state, globalKey);
		lua_rawget(state, LUA_ENVIRONINDEX);
		return 1;
	}

	/**
	 * Address: 0x009176F0 (FUN_009176F0, lua::io_input)
	 *
	 * What it does:
	 * Gets/sets Lua io default `_input` handle lane via `g_iofile`.
	 */
	[[maybe_unused]] int LuaIoInput(lua_State* const state)
	{
		return LuaIoFile(state, "_input", "r");
	}

	/**
	 * Address: 0x00917710 (FUN_00917710, lua::io_output)
	 *
	 * What it does:
	 * Gets/sets Lua io default `_output` handle lane via `g_iofile`.
	 */
	[[maybe_unused]] int LuaIoOutput(lua_State* const state)
	{
		return LuaIoFile(state, "_output", "w");
	}

	/**
	 * Address: 0x00917730 (FUN_00917730, lua::io_read)
	 *
	 * What it does:
	 * Reads from global `_input` file handle using Lua io option semantics.
	 */
	[[maybe_unused]] int LuaIoRead(lua_State* const state)
	{
		std::FILE* const stream = GetIoFileFromGlobal(state, "_input");
		return LuaReadFromFile(stream, state, 1);
	}

	/**
	 * Address: 0x00917790 (FUN_00917790, lua::f_read)
	 *
	 * What it does:
	 * Reads from userdata-bound file handle using Lua io option semantics.
	 */
	[[maybe_unused]] int LuaFileRead(lua_State* const state)
	{
		return LuaReadFromFile(ToFile(state, 1), state, 2);
	}

	/**
	 * Address: 0x00917880 (FUN_00917880, lua::io_write)
	 *
	 * What it does:
	 * Writes Lua args to global `_output` file handle with io tuple semantics.
	 */
	[[maybe_unused]] int LuaIoWrite(lua_State* const state)
	{
		std::FILE* const stream = GetIoFileFromGlobal(state, "_output");
		return LuaWriteToFile(1, state, stream);
	}

	/**
	 * Address: 0x009178F0 (FUN_009178F0, lua::f_write)
	 *
	 * What it does:
	 * Writes Lua args to userdata-bound file handle with io tuple semantics.
	 */
	[[maybe_unused]] int LuaFileWrite(lua_State* const state)
	{
		return LuaWriteToFile(2, state, ToFile(state, 1));
	}

	int ReadZioByte(LuaZioRuntimeView* const stream)
	{
		const int available = stream->remainingBytes;
		stream->remainingBytes = available - 1;
		if (available <= 0) {
			return luaZ_fill(stream);
		}

		const unsigned char value = static_cast<unsigned char>(*stream->cursor);
		++stream->cursor;
		return static_cast<int>(value);
	}

	/**
	 * Address: 0x009285C0 (FUN_009285C0, LoadBlock)
	 *
	 * What it does:
	 * Loads one raw byte block from Lua chunk stream; when byte-swap mode is
	 * enabled it reads byte-by-byte in reverse order, otherwise bulk-reads.
	 */
	[[maybe_unused]] void LuaLoadBlock(
		const size_t size,
		void* const destination,
		LuaLoadStateRuntimeView* const loadState
	)
	{
		if (loadState->swapBytes != 0) {
			auto* writeCursor = static_cast<std::uint8_t*>(destination) + size;
			for (size_t index = 0; index < size; ++index) {
				--writeCursor;
				const int byteValue = ReadZioByte(loadState->stream);
				if (byteValue == -1) {
					luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
				}
				*writeCursor = static_cast<std::uint8_t>(byteValue);
			}
			return;
		}

		if (luaZ_read(loadState->stream, destination, size) != 0) {
			luaG_runerror(loadState->state, "unexpected end of file in %s", loadState->chunkName);
		}
	}

	/**
	 * Address: 0x0090A780 (FUN_0090A780, LuaPlusGCFunction)
	 *
	 * What it does:
	 * Marks root-state live LuaObject payload GC nodes during Lua GC callback,
	 * skipping already-marked or non-GC-tag payload lanes.
	 */
	void LuaPlusGCFunction(GCState* const gcState)
	{
		if (gcState == nullptr || gcState->L == nullptr) {
			return;
		}

		auto* const state = static_cast<LuaState*>(gcState->L->stateUserData);
		if (state == nullptr || state != state->m_rootState) {
			return;
		}

		LuaObject* node = state->m_headObject.m_next;
		LuaObject* const tail = reinterpret_cast<LuaObject*>(&state->m_tailObject);
		while (node != tail) {
			if (node->m_object.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(node->m_object.value.p);
				if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(gcState, object);
				}
			}
			node = node->m_next;
		}
	}

	/**
	 * Address: 0x009151E0 (FUN_009151E0, reallymarkobject)
	 *
	 * What it does:
	 * Marks one collectable GC object and links it into the appropriate gray
	 * propagation lane.
	 */
	extern "C" void reallymarkobject(GCState* const st, GCObject* const object)
	{
		GCObject* current = object;
		current->gch.marked |= 1u;

		while (true) {
			switch (static_cast<unsigned int>(current->gch.tt - LUA_TTABLE)) {
			case 0:
				current->h.gclist = st->tmark;
				st->tmark = current;
				return;

			case 1:
			case 2:
				current->cl.c.gclist = st->tmark;
				st->tmark = current;
				return;

			case 3:
				current = reinterpret_cast<GCObject*>(current->u.metatable);
				if (current != nullptr && (current->gch.marked & 0x11u) == 0u) {
					current->gch.marked |= 1u;
					if (static_cast<unsigned int>(current->gch.tt - LUA_TTABLE) <= 5u) {
						continue;
					}
				}
				return;

			case 4:
				current->th.gclist = st->tmark;
				st->tmark = current;
				return;

			case 5:
				current->p.gclist = st->tmark;
				st->tmark = current;
				return;

			default:
				return;
			}
		}
	}

	/**
	 * Address: 0x00915320 (FUN_00915320, traversetable)
	 *
	 * What it does:
	 * Marks the metatable, resolves weak-table mode, and traverses array/hash
	 * lanes while preserving weak key/value semantics.
	 */
	extern "C" void traversetable(GCState* const st, Table* const h)
	{
		constexpr int kLuaTagMethodMode = 3;

		auto markCollectable = [st](TObject& slot) {
			if (slot.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(slot.value.p);
				if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, object);
				}
			}
		};

		auto condMarkCollectable = [&markCollectable](TObject& slot, const bool shouldMark) {
			if (shouldMark) {
				markCollectable(slot);
			}
		};

		Table* const metatable = h->metatable;
		bool weakkey = false;
		bool weakvalue = false;
		if ((metatable->marked & 0x11u) == 0u) {
			reallymarkobject(st, reinterpret_cast<GCObject*>(metatable));
		}

		if ((metatable->flags & 4) == 0) {
			const TObject* const mode = luaT_gettm(metatable, kLuaTagMethodMode, st->g->tmname[kLuaTagMethodMode]);
			if (mode != nullptr && mode->tt == LUA_TSTRING) {
				const char* const modeText = static_cast<TString*>(mode->value.p)->str;
				weakkey = std::strchr(modeText, 'k') != nullptr;
				weakvalue = std::strchr(modeText, 'v') != nullptr;
			}
		}

		if (weakkey || weakvalue) {
			h->marked &= static_cast<lu_byte>(~0x6u);
			if (weakkey) {
				h->marked |= 0x2u;
			}
			if (weakvalue) {
				h->marked |= 0x4u;
			}

			GCObject** const weaklist = weakkey ? (weakvalue ? &st->wkv : &st->wk) : &st->wv;
			h->gclist = *weaklist;
			*weaklist = reinterpret_cast<GCObject*>(h);
		}

		if (!weakvalue) {
			for (int index = h->sizearray; index != 0; --index) {
				markCollectable(h->array[index - 1]);
			}
		}

		for (int index = 1 << h->lsizenode; index != 0; --index) {
			Node* const node = &h->node[index - 1];
			if (node->i_val.tt != LUA_TNIL) {
				condMarkCollectable(node->i_key, !weakkey);
				condMarkCollectable(node->i_val, !weakvalue);
			}
		}
	}

	/**
	 * Address: 0x009154A0 (FUN_009154A0, traverseproto)
	 *
	 * What it does:
	 * Marks one prototype's strings, upvalue names, nested protos, and local
	 * variable names.
	 */
	extern "C" void traverseproto(GCState* const st, Proto* const f)
	{
		f->source->marked |= 1u;
		for (int index = 0; index < f->sizek; ++index) {
			TObject& constant = f->k[index];
			if (constant.tt == LUA_TSTRING) {
				static_cast<TString*>(constant.value.p)->marked |= 1u;
			}
		}

		for (int index = 0; index < f->sizeupvalues; ++index) {
			f->upvalues[index]->marked |= 1u;
		}

		for (int index = 0; index < f->sizep; ++index) {
			Proto* const nested = f->p[index];
			if ((nested->marked & 0x11u) == 0u) {
				reallymarkobject(st, reinterpret_cast<GCObject*>(nested));
			}
		}

		for (int index = 0; index < f->sizelocvars; ++index) {
			f->locvars[index].varname->marked |= 1u;
		}
	}

	/**
	 * Address: 0x00915540 (FUN_00915540, traversecclosure)
	 *
	 * What it does:
	 * Marks one C closure's collectable upvalue lanes.
	 */
	extern "C" void traversecclosure(GCState* const st, CClosure* const cl)
	{
		for (int index = 0; index < cl->nupvalues; ++index) {
			TObject& upvalue = cl->upvalue[index];
			if (upvalue.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(upvalue.value.p);
				if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, object);
				}
			}
		}
	}

	/**
	 * Address: 0x00915580 (FUN_00915580, traverselclosure)
	 *
	 * What it does:
	 * Marks one Lua closure's environment, prototype, and nested upvalues.
	 */
	extern "C" void traverselclosure(GCState* const st, LClosure* const cl)
	{
		if (cl->g.tt >= LUA_TSTRING) {
			auto* const object = static_cast<GCObject*>(cl->g.value.p);
			if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, object);
			}
		}

		if (cl->p != nullptr && (cl->p->marked & 0x11u) == 0u) {
			reallymarkobject(st, reinterpret_cast<GCObject*>(cl->p));
		}

		for (int index = 0; index < cl->nupvalues; ++index) {
			UpVal* const upvalue = cl->upvals[index];
			if (upvalue != nullptr && upvalue->marked == 0) {
				if (upvalue->value.tt >= LUA_TSTRING) {
					auto* const object = static_cast<GCObject*>(upvalue->value.value.p);
					if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
						reallymarkobject(st, object);
					}
				}
				upvalue->marked = 1u;
			}
		}
	}

	/**
	 * Address: 0x00915670 (FUN_00915670, traversestack)
	 *
	 * What it does:
	 * Marks the thread global table and live stack lanes, clears the unused tail
	 * to nil, then trims overgrown stack and call-info allocations.
	 */
	extern "C" void traversestack(lua_State* const L1, GCState* const st)
	{
		if (L1->_gt.tt >= LUA_TSTRING) {
			auto* const object = static_cast<GCObject*>(L1->_gt.value.p);
			if (object != nullptr && (object->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, object);
			}
		}

		CallInfo* const baseCi = L1->base_ci;
		CallInfo* const currentCi = L1->ci;
		TObject* lim = L1->top;
		for (CallInfo* ci = baseCi; ci <= currentCi; ++ci) {
			if (lim < ci->top) {
				lim = ci->top;
			}
		}

		for (TObject* object = L1->stack; object < L1->top; ++object) {
			if (object->tt >= LUA_TSTRING) {
				auto* const gcObject = static_cast<GCObject*>(object->value.p);
				if (gcObject != nullptr && (gcObject->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, gcObject);
				}
			}
		}

		for (TObject* object = L1->top; object <= lim; ++object) {
			object->tt = LUA_TNIL;
			object->value.p = nullptr;
		}

		if ((4 * (L1->ci - L1->base_ci) < L1->size_ci) && L1->size_ci > 0x10u) {
			luaD_reallocCI(L1, L1->size_ci >> 1);
		}

		if ((4 * (lim - L1->stack) < L1->stacksize) && L1->stacksize > 90) {
			luaD_reallocstack(L1, L1->stacksize / 2);
		}
	}

	/**
	 * Address: 0x00915840 (FUN_00915840, cleartablekeys)
	 *
	 * What it does:
	 * Walks weak-key tables and clears hash nodes whose keys are collectable
	 * but were not marked alive in the current propagation pass.
	 */
	extern "C" void cleartablekeys(GCObject* tableList)
	{
		auto markStringKey = [](LuaPlus::TObject& keySlot) {
			if (keySlot.tt == LUA_TSTRING && keySlot.value.p != nullptr) {
				static_cast<TString*>(keySlot.value.p)->marked |= 1u;
			}
		};

		for (Table* table = reinterpret_cast<Table*>(tableList); table != nullptr;
			 table = reinterpret_cast<Table*>(table->gclist)) {
			const int nodeCount = 1 << table->lsizenode;
			for (int nodeIndex = nodeCount; nodeIndex != 0; --nodeIndex) {
				Node& node = table->node[nodeIndex - 1];
				LuaPlus::TObject& keySlot = node.i_key;
				markStringKey(keySlot);

				if (keySlot.tt >= LUA_TSTRING) {
					auto* const keyObject = static_cast<GCObject*>(keySlot.value.p);
					if (keyObject != nullptr && (keyObject->gch.marked & 1u) == 0u) {
						node.i_val.tt = LUA_TNIL;
						keySlot.tt = LUA_TNONE;
					}
				}
			}
		}
	}

	/**
	 * Address: 0x009158A0 (FUN_009158A0, cleartablevalues)
	 *
	 * What it does:
	 * Walks weak-value tables and clears array/hash value lanes whose
	 * collectable payloads were not marked alive in the current GC pass.
	 */
	extern "C" void cleartablevalues(GCObject* tableList)
	{
		auto markStringValue = [](LuaPlus::TObject& valueSlot) {
			if (valueSlot.tt == LUA_TSTRING && valueSlot.value.p != nullptr) {
				static_cast<TString*>(valueSlot.value.p)->marked |= 1u;
			}
		};

		for (Table* table = reinterpret_cast<Table*>(tableList); table != nullptr;
			 table = reinterpret_cast<Table*>(table->gclist)) {
			for (int arrayIndex = table->sizearray; arrayIndex != 0; --arrayIndex) {
				LuaPlus::TObject& valueSlot = table->array[arrayIndex - 1];
				markStringValue(valueSlot);
				if (valueSlot.tt >= LUA_TSTRING) {
					auto* const valueObject = static_cast<GCObject*>(valueSlot.value.p);
					if (valueObject != nullptr && (valueObject->gch.marked & 1u) == 0u) {
						valueSlot.tt = LUA_TNIL;
					}
				}
			}

			const int nodeCount = 1 << table->lsizenode;
			for (int nodeIndex = nodeCount; nodeIndex != 0; --nodeIndex) {
				Node& node = table->node[nodeIndex - 1];
				LuaPlus::TObject& valueSlot = node.i_val;
				markStringValue(valueSlot);

				if (valueSlot.tt >= LUA_TSTRING) {
					auto* const valueObject = static_cast<GCObject*>(valueSlot.value.p);
					if (valueObject != nullptr && (valueObject->gch.marked & 1u) == 0u) {
						const bool hasCollectableKey = node.i_key.tt >= LUA_TSTRING;
						valueSlot.tt = LUA_TNIL;
						if (hasCollectableKey) {
							node.i_key.tt = LUA_TNONE;
						}
					}
				}
			}
		}
	}

	extern "C" void freeobj(GCObject* object, lua_State* state);

	/**
	 * Address: 0x00915A00 (FUN_00915A00, sweeplist)
	 *
	 * What it does:
	 * Walks one intrusive GC list lane until `tail`, keeping live nodes in-place
	 * (while clearing their dead-white bit) and unlinking/freeing dead nodes up
	 * to `limit`, returning the reclaimed object count.
	 */
	extern "C" int sweeplist(
		GCObject** const listHeadLink,
		GCObject* const tail,
		lua_State* const state,
		const int limit
	)
	{
		GCObject** currentLink = listHeadLink;
		GCObject* current = *currentLink;
		int reclaimedCount = 0;

		while (current != tail) {
			const lu_byte markByte = current->gch.marked;
			const int colorClass = static_cast<int>(markByte & 0xF9u);

			if (colorClass > limit) {
				current->gch.marked = static_cast<lu_byte>(markByte & 0xFEu);
				currentLink = &current->gch.next;
			} else {
				*currentLink = current->gch.next;
				++reclaimedCount;
				freeobj(current, state);
			}

			current = *currentLink;
		}

		return reclaimedCount;
	}

	/**
	 * Address: 0x00915A50 (FUN_00915A50, sweepstrings)
	 *
	 * What it does:
	 * Sweeps every string-table bucket and decrements `nuse` by each bucket's
	 * reclaimed string count.
	 */
	[[maybe_unused]] void sweepstrings(lua_State* const state, const int all)
	{
		global_State* const globalState = state->l_G;
		for (int index = 0; index < globalState->strt.size; ++index) {
			globalState->strt.nuse -= sweeplist(&globalState->strt.hash[index], nullptr, state, all);
		}
	}

	/**
	 * Address: 0x00915AA0 (FUN_00915AA0, checkSizes)
	 *
	 * What it does:
	 * Shrinks oversized string/hash scratch storage and recomputes the next GC
	 * threshold after the current mark/sweep dead-memory estimate.
	 */
	[[maybe_unused]] void checkSizes(lua_State* const state, const size_t deadmem)
	{
		global_State* const globalState = state->l_G;
		if (globalState->strt.nuse < globalState->strt.size / 4) {
			const int stringTableSize = globalState->strt.size;
			if (stringTableSize > 64) {
				luaS_resize(state, stringTableSize / 2);
			}
		}

		if (globalState->buff.buffsize > 64u) {
			const lu_mem oldBufferSize = globalState->buff.buffsize;
			const lu_mem newBufferSize = oldBufferSize >> 1;
			globalState->buff.buffer =
				static_cast<char*>(luaM_realloc(state, globalState->buff.buffer, oldBufferSize, newBufferSize));
			globalState->buff.buffsize = newBufferSize;
		}

		const int nblocks = globalState->unknown10C;
		int thresholdBase = nblocks + nblocks;
		if (nblocks >= 0x40000000) {
			thresholdBase = nblocks + 0x10000000;
		}

		const std::uint32_t adjustedThreshold =
			static_cast<std::uint32_t>(thresholdBase) - static_cast<std::uint32_t>(deadmem);
		globalState->GCthreshold = static_cast<lu_mem>(adjustedThreshold);
	}

	/**
	 * Address: 0x00915BF0 (FUN_00915BF0, markroot)
	 *
	 * What it does:
	 * Marks Lua GC roots for default metatable lanes, registry, and thread
	 * roots, then dispatches the optional engine GC callback hook.
	 */
	[[maybe_unused]] void markroot(GCState* const st, lua_State* const state)
	{
		global_State* const globalState = state->l_G;
		global_State* const gcGlobals = st->g;

		if (globalState->_defaultmeta.tt >= LUA_TSTRING) {
			auto* const defaultMetaObject = static_cast<GCObject*>(globalState->_defaultmeta.value.p);
			if ((defaultMetaObject->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, defaultMetaObject);
			}
		}

		for (TObject& slot : globalState->_defaultmetatypes) {
			if (slot.tt >= LUA_TSTRING) {
				auto* const object = static_cast<GCObject*>(slot.value.p);
				if ((object->gch.marked & 0x11u) == 0u) {
					reallymarkobject(st, object);
				}
			}
		}

		if (globalState->_registry.tt >= LUA_TSTRING) {
			auto* const registryObject = static_cast<GCObject*>(globalState->_registry.value.p);
			if ((registryObject->gch.marked & 0x11u) == 0u) {
				reallymarkobject(st, registryObject);
			}
		}

		traversestack(gcGlobals->mainthread, st);
		if (state != gcGlobals->mainthread && (state->marked & 0x11u) == 0u) {
			reallymarkobject(st, reinterpret_cast<GCObject*>(state));
		}

		if (globalState->userGCFunction != nullptr) {
			st->L = gcGlobals->mainthread;
			globalState->userGCFunction(st);
		}
	}

	/**
	 * Address: 0x00915750 (FUN_00915750, propagatemarks)
	 *
	 * What it does:
	 * Drains the gray list by dispatching tables, closures, threads, and proto
	 * nodes through their specialized traversal lanes.
	 */
	extern "C" void propagatemarks(GCState* const st)
	{
		while (st->tmark != nullptr) {
			GCObject* const current = st->tmark;
			switch (current->gch.tt) {
			case LUA_TTABLE:
				st->tmark = current->h.gclist;
				traversetable(st, &current->h);
				break;

			case LUA_CFUNCTION:
				st->tmark = current->cl.c.gclist;
				traversecclosure(st, &current->cl.c);
				break;

			case LUA_TFUNCTION:
				st->tmark = current->cl.c.gclist;
				traverselclosure(st, &current->cl.l);
				break;

			case LUA_TTHREAD:
				st->tmark = current->th.gclist;
				traversestack(&current->th, st);
				if (current->th.l_G->userGCFunction != nullptr) {
					st->L = &current->th;
					current->th.l_G->userGCFunction(st);
				}
				break;

			case LUA_TPROTO:
				st->tmark = current->p.gclist;
				traverseproto(st, &current->p);
				break;

			default:
				break;
			}
		}
	}

	constexpr unsigned int kLuaOpcodeMask = 0x3Fu;
	constexpr unsigned int kLuaOpcodeModeMask = 0x3u;
	constexpr unsigned int kLuaInstructionAFieldShift = 24u;
	constexpr unsigned int kLuaInstructionBFieldShift = 15u;
	constexpr unsigned int kLuaInstructionCFieldShift = 6u;
	constexpr unsigned int kLuaInstructionABxMask = 0x3FFFFu;
	constexpr unsigned int kLuaInstructionBOrCMask = 0x1FFu;
	constexpr int kLuaInstructionSignedBxBias = 0x1FFFF;

	constexpr unsigned char kLuaOpcodeModes[] = {
		0, 1, 0, 0, 0, 1, 0, 1, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
		0, 0, 2, 0, 2, 1, 1, 0, 1
	};

	constexpr const char* const kLuaOpcodeNames[] = {
		"MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL",
		"GETGLOBAL", "GETTABLE", "SETGLOBAL", "SETUPVAL", "SETTABLE",
		"NEWTABLE", "SELF", "ADD", "SUB", "MUL",
		"DIV", "BAND", "BOR", "BSHL", "BSHR",
		"XOR", "UNM", "NOT", "CONCAT", "JMP",
		"EQ", "LT", "LE", "TEST", "CALL",
		"TAILCALL", "RETURN", "FORLOOP", "TFORLOOP", "TFORPREP",
		"SETLIST", "SETLISTO", "CLOSE", "CLOSURE"
	};
	static_assert(
		(sizeof(kLuaOpcodeModes) / sizeof(kLuaOpcodeModes[0]))
		== (sizeof(kLuaOpcodeNames) / sizeof(kLuaOpcodeNames[0])),
		"Lua opcode mode/name table sizes must match"
	);
	constexpr const char* kLuaDebugLevelOutOfRange = "level out of range";
	constexpr const char* kLuaDebugFunctionOrLevelExpected = "function or level expected";
	constexpr const char* kLuaDebugInvalidOption = "invalid option";

	/**
	 * Address: 0x009116B0 (FUN_009116B0, getinfo)
	 *
	 * What it does:
	 * Resolves debug info for either stack level arg-1 or function arg-1 and
	 * returns one table populated by requested option mask (`flnSu` by default).
	 */
	[[maybe_unused]] int LuaDebugGetInfo(lua_State* const state)
	{
		const char* optionMask = luaL_optlstring(state, 2, "flnSu", nullptr);
		::lua_Debug activationRecord{};

		if (lua_isnumber(state, 1) != 0) {
			const int level = static_cast<int>(lua_tonumber(state, 1));
			if (lua_getstack(state, level, &activationRecord) == 0) {
				lua_pushnil(state);
				return 1;
			}
		} else {
			const int firstArgumentType = lua_type(state, 1);
			if ((firstArgumentType | 1) != LUA_TFUNCTION) {
				luaL_argerror(state, 1, kLuaDebugFunctionOrLevelExpected);
			}

			lua_pushfstring(state, ">%s", optionMask);
			optionMask = lua_tostring(state, -1);
			lua_pushvalue(state, 1);
		}

		if (lua_getinfo(state, optionMask, &activationRecord) == 0) {
			return luaL_argerror(state, 2, kLuaDebugInvalidOption);
		}

		lua_newtable(state);
		for (const char* option = optionMask; *option != '\0'; ++option) {
			switch (*option) {
				case 'S':
					lua_pushstring(state, "source");
					lua_pushstring(state, activationRecord.source);
					lua_rawset(state, -3);

					lua_pushstring(state, "short_src");
					lua_pushstring(state, activationRecord.short_src);
					lua_rawset(state, -3);

					lua_pushstring(state, "linedefined");
					lua_pushnumber(state, static_cast<lua_Number>(activationRecord.linedefined));
					lua_rawset(state, -3);

					lua_pushstring(state, "what");
					lua_pushstring(state, activationRecord.what);
					lua_rawset(state, -3);
					break;

				case 'f':
					lua_pushlstring(state, "func", 4);
					lua_pushvalue(state, -3);
					lua_rawset(state, -3);
					break;

				case 'l':
					lua_pushstring(state, "currentline");
					lua_pushnumber(state, static_cast<lua_Number>(activationRecord.currentline));
					lua_rawset(state, -3);
					break;

				case 'n':
					lua_pushstring(state, "name");
					lua_pushstring(state, activationRecord.name);
					lua_rawset(state, -3);

					lua_pushstring(state, "namewhat");
					lua_pushstring(state, activationRecord.namewhat);
					lua_rawset(state, -3);
					break;

				case 'u':
					lua_pushstring(state, "nups");
					lua_pushnumber(state, static_cast<lua_Number>(activationRecord.nups));
					lua_rawset(state, -3);
					break;

				default:
					break;
			}
		}

		return 1;
	}

	/**
	 * Address: 0x00911940 (FUN_00911940, getlocal)
	 *
	 * What it does:
	 * Returns local variable name/value pair for stack level arg-1 and local
	 * index arg-2; returns `nil` when local index is unavailable.
	 */
	[[maybe_unused]] int LuaDebugGetLocal(lua_State* const state)
	{
		const int level = static_cast<int>(luaL_checknumber(state, 1));
		::lua_Debug activationRecord{};
		if (lua_getstack(state, level, &activationRecord) == 0) {
			return luaL_argerror(state, 1, kLuaDebugLevelOutOfRange);
		}

		const int localIndex = static_cast<int>(luaL_checknumber(state, 2));
		const char* const localName = lua_getlocal(state, &activationRecord, localIndex);
		if (localName != nullptr) {
			lua_pushstring(state, localName);
			lua_pushvalue(state, -2);
			return 2;
		}

		lua_pushnil(state);
		return 1;
	}

	/**
	 * Address: 0x009119D0 (FUN_009119D0, setlocal)
	 *
	 * What it does:
	 * Sets one local variable for stack level arg-1/local index arg-2 using
	 * stack arg-3 and returns assigned local name (or nil).
	 */
	[[maybe_unused]] int LuaDebugSetLocal(lua_State* const state)
	{
		const int level = static_cast<int>(luaL_checknumber(state, 1));
		::lua_Debug activationRecord{};
		if (lua_getstack(state, level, &activationRecord) == 0) {
			return luaL_argerror(state, 1, kLuaDebugLevelOutOfRange);
		}

		luaL_checkany(state, 3);
		const int localIndex = static_cast<int>(luaL_checknumber(state, 2));
		lua_pushstring(state, lua_setlocal(state, &activationRecord, localIndex));
		return 1;
	}

	/**
	 * Address: 0x00911AB0 (FUN_00911AB0, getupvalue)
	 *
	 * What it does:
	 * Returns upvalue name+value for function arg-1 and upvalue index arg-2;
	 * returns 0 when index is out of range.
	 */
	[[maybe_unused]] int LuaDebugGetUpvalue(lua_State* const state)
	{
		const int upvalueIndex = static_cast<int>(luaL_checknumber(state, 2));
		luaL_checktype(state, 1, LUA_TFUNCTION);

		const char* const upvalueName = lua_getupvalue(state, 1, upvalueIndex);
		if (upvalueName != nullptr) {
			lua_pushstring(state, upvalueName);
			lua_insert(state, -2);
			return 2;
		}

		return 0;
	}

	/**
	 * Address: 0x00911B00 (FUN_00911B00, setupvalue)
	 *
	 * What it does:
	 * Writes function upvalue from stack arg-3 for function arg-1/index arg-2
	 * and returns upvalue name when the write succeeds.
	 */
	[[maybe_unused]] int LuaDebugSetUpvalue(lua_State* const state)
	{
		luaL_checkany(state, 3);
		const int upvalueIndex = static_cast<int>(luaL_checknumber(state, 2));
		luaL_checktype(state, 1, LUA_TFUNCTION);

		const char* const upvalueName = lua_setupvalue(state, 1, upvalueIndex);
		if (upvalueName != nullptr) {
			lua_pushstring(state, upvalueName);
			lua_insert(state, -1);
			return 1;
		}

		return 0;
	}

	/**
	 * Address: 0x00911B60 (FUN_00911B60, hookf)
	 *
	 * What it does:
	 * Dispatches one debug-hook event to the registry-stored `h` callback,
	 * passing event-name + current line (`nil` when line < 0).
	 */
	[[maybe_unused]] void LuaDebugHookCallback(lua_State* const state, ::lua_Debug* const activationRecord)
	{
		lua_pushlightuserdata(state, const_cast<char*>(kLuaDebugHookRegistryKey));
		lua_rawget(state, LUA_REGISTRYINDEX);
		if ((lua_type(state, -1) | 1) == LUA_TFUNCTION) {
			lua_pushstring(state, kLuaDebugHookEventNames[activationRecord->event]);

			const int currentLine = activationRecord->currentline;
			if (currentLine < 0) {
				lua_pushnil(state);
			} else {
				lua_pushnumber(state, static_cast<lua_Number>(currentLine));
			}

			lua_call(state, 2, 0);
		} else {
			lua_settop(state, -2);
		}
	}

	/**
	 * Address: 0x00911C00 (FUN_00911C00, makemask)
	 *
	 * What it does:
	 * Parses textual hook mask (`c`,`r`,`l`) plus count gate and returns packed
	 * Lua hook mask bits.
	 */
	[[maybe_unused]] int LuaDebugBuildHookMask(const char* const maskSpec, const int count)
	{
		int mask = (std::strchr(maskSpec, 'c') != nullptr) ? LUA_MASKCALL : 0;
		if (std::strchr(maskSpec, 'r') != nullptr) {
			mask |= LUA_MASKRET;
		}
		if (std::strchr(maskSpec, 'l') != nullptr) {
			mask |= LUA_MASKLINE;
		}
		if (count > 0) {
			mask |= LUA_MASKCOUNT;
		}
		return mask;
	}

	/**
	 * Address: 0x00911C80 (FUN_00911C80, sethook)
	 *
	 * What it does:
	 * Sets or clears the active debug hook based on arg-1 (`nil` clears),
	 * then stores callback object in registry key `h`.
	 */
	[[maybe_unused]] int LuaDebugSetHook(lua_State* const state)
	{
		if (lua_type(state, 1) > LUA_TNIL) {
			const char* const maskSpec = luaL_checklstring(state, 2, nullptr);
			const int count = static_cast<int>(luaL_optnumber(state, 3, 0.0));
			const int mask = LuaDebugBuildHookMask(maskSpec, count);
			lua_sethook(state, &LuaDebugHookCallback, mask, count);
		} else {
			lua_settop(state, 1);
			lua_sethook(state, nullptr, 0, 0);
		}

		lua_pushlightuserdata(state, const_cast<char*>(kLuaDebugHookRegistryKey));
		lua_pushvalue(state, 1);
		lua_rawset(state, LUA_REGISTRYINDEX);
		return 0;
	}

	/**
	 * Address: 0x00911D20 (FUN_00911D20, gethook)
	 *
	 * What it does:
	 * Returns the current hook callback object (`h` or `"external hook"`),
	 * active hook mask string, and hook count.
	 */
	[[maybe_unused]] int LuaDebugGetHook(lua_State* const state)
	{
		const int mask = lua_gethookmask(state);
		const auto hook = lua_gethook(state);
		const auto localHook = &LuaDebugHookCallback;
		if (hook == nullptr || hook == localHook) {
			lua_pushlightuserdata(state, const_cast<char*>(kLuaDebugHookRegistryKey));
			lua_rawget(state, LUA_REGISTRYINDEX);
		} else {
			lua_pushlstring(state, kLuaDebugExternalHookLabel, std::strlen(kLuaDebugExternalHookLabel));
		}

		char maskString[8]{};
		int writeIndex = 0;
		if ((mask & LUA_MASKCALL) != 0) {
			maskString[writeIndex++] = 'c';
		}
		if ((mask & LUA_MASKRET) != 0) {
			maskString[writeIndex++] = 'r';
		}
		if ((mask & LUA_MASKLINE) != 0) {
			maskString[writeIndex++] = 'l';
		}

		maskString[writeIndex] = '\0';
		lua_pushstring(state, maskString);
		lua_pushnumber(state, static_cast<lua_Number>(lua_gethookcount(state)));
		return 3;
	}

	/**
	 * Address: 0x00911DE0 (FUN_00911DE0, luaD_debug)
	 *
	 * What it does:
	 * Runs one interactive debug REPL on stdin/stderr until EOF or `cont\\n`,
	 * executing each entered line with `lua_dostring`.
	 */
	[[maybe_unused]] int LuaDebugConsole(lua_State* const state)
	{
		char inputBuffer[kLuaDebugInputBufferSize]{};

		std::FILE* ioBase = __iob_func();
		std::fputs(kLuaDebugPrompt, &ioBase[2]);

		ioBase = __iob_func();
		if (std::fgets(inputBuffer, kLuaDebugReadLineLimit, &ioBase[0]) == nullptr) {
			return 0;
		}

		do {
			if (std::strcmp(inputBuffer, kLuaDebugContinueToken) == 0) {
				break;
			}

			lua_dostring(state, inputBuffer);
			lua_settop(state, 0);

			ioBase = __iob_func();
			std::fputs(kLuaDebugPrompt, &ioBase[2]);
			ioBase = __iob_func();
		} while (std::fgets(inputBuffer, kLuaDebugReadLineLimit, &ioBase[0]) != nullptr);

		return 0;
	}

	/**
	 * Address: 0x00912780 (FUN_00912780, funcinfo)
	 *
	 * What it does:
	 * Populates one `lua_Debug` function-source lane from function object type:
	 * C closure (`=[C]`) or Lua prototype-backed closure info.
	 */
	[[maybe_unused]] void LuaDebugPopulateFuncInfo(
		::lua_Debug* const activationRecord,
		TObject* const functionObject
	)
	{
		if (functionObject->tt == LUA_CFUNCTION) {
			activationRecord->source = "=[C]";
			activationRecord->linedefined = -1;
			activationRecord->what = "C";
			luaO_chunkid(activationRecord->short_src, activationRecord->source, LUA_IDSIZE);
			return;
		}

		const auto* const closure = static_cast<const Closure*>(functionObject->value.p);
		const Proto* const proto = closure->l.p;
		activationRecord->source = proto->source->str;
		activationRecord->linedefined = proto->lineDefined;
		activationRecord->what = (proto->lineDefined == 0) ? "main" : "Lua";
		luaO_chunkid(activationRecord->short_src, activationRecord->source, LUA_IDSIZE);
	}

	/**
	 * Address: 0x00911EC0 (FUN_00911EC0, listcode_buildop)
	 *
	 * What it does:
	 * Formats one Lua bytecode instruction into a debug line with source line,
	 * instruction index, opcode mnemonic, and decoded operand lane values.
	 */
	[[maybe_unused]] const char* LuaDebugBuildOpcodeText(
		const Proto* const proto,
		const int instructionIndex,
		char* const outputBuffer
	)
	{
		const Instruction instruction = proto->code[instructionIndex];
		const auto opcode = static_cast<unsigned int>(instruction) & kLuaOpcodeMask;
		const int sourceLine = proto->lineinfo != nullptr ? proto->lineinfo[instructionIndex] : 0;
		std::sprintf(outputBuffer, "(%4d) %4d - ", sourceLine, instructionIndex);

		char* const writeCursor = outputBuffer + std::strlen(outputBuffer);
		const auto mode = kLuaOpcodeModes[opcode] & kLuaOpcodeModeMask;
		const auto registerA = static_cast<unsigned int>(instruction) >> kLuaInstructionAFieldShift;

		if (mode == 0) {
			std::sprintf(
				writeCursor,
				"%-12s%4u %4u %4u",
				kLuaOpcodeNames[opcode],
				registerA,
				(static_cast<unsigned int>(instruction) >> kLuaInstructionBFieldShift) & kLuaInstructionBOrCMask,
				(static_cast<unsigned int>(instruction) >> kLuaInstructionCFieldShift) & kLuaInstructionBOrCMask
			);
		} else if (mode == 1) {
			std::sprintf(
				writeCursor,
				"%-12s%4u %4u",
				kLuaOpcodeNames[opcode],
				registerA,
				(static_cast<unsigned int>(instruction) >> kLuaInstructionCFieldShift) & kLuaInstructionABxMask
			);
		} else if (mode == 2) {
			std::sprintf(
				writeCursor,
				"%-12s%4u %4d",
				kLuaOpcodeNames[opcode],
				registerA,
				static_cast<int>(
					((static_cast<unsigned int>(instruction) >> kLuaInstructionCFieldShift) & kLuaInstructionABxMask)
				) - kLuaInstructionSignedBxBias
			);
		}

		return outputBuffer;
	}

	/**
	 * Address: 0x00911FC0 (FUN_00911FC0, debug_listcode)
	 *
	 * What it does:
	 * Builds one Lua table describing function bytecode: fixed fields
	 * (`maxstack`, `numparams`) plus formatted per-instruction listing lines.
	 */
	[[maybe_unused]] int LuaDebugListCode(lua_State* const state)
	{
		if (lua_type(state, 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		auto* const stackValueObject = static_cast<GCObject*>(state->ci->base->value.p);
		Proto* const proto = stackValueObject->cl.l.p;

		lua_newtable(state);

		lua_pushstring(state, "maxstack");
		lua_pushnumber(state, static_cast<lua_Number>(proto->maxstacksize));
		lua_rawset(state, -3);

		lua_pushstring(state, "numparams");
		lua_pushnumber(state, static_cast<lua_Number>(proto->numparams));
		lua_rawset(state, -3);

		char opcodeText[100]{};
		for (int instructionIndex = 0; instructionIndex < proto->sizecode; ++instructionIndex) {
			lua_pushnumber(state, static_cast<lua_Number>(instructionIndex + 1));
			lua_pushstring(state, LuaDebugBuildOpcodeText(proto, instructionIndex, opcodeText));
			lua_settable(state, -3);
		}

		return 1;
	}

	/**
	 * Address: 0x009120B0 (FUN_009120B0, func_listk)
	 *
	 * What it does:
	 * Returns one table containing function constant slots (`proto->k`) indexed
	 * from 1..sizek for Lua function arg-1.
	 */
	[[maybe_unused]] int LuaDebugListConstants(lua_State* const state)
	{
		if (lua_type(state, 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		auto* const closureObject = static_cast<GCObject*>(state->ci->base->value.p);
		Proto* const proto = closureObject->cl.l.p;

		lua_newtable(state);
		for (int constantIndex = 0; constantIndex < proto->sizek; ++constantIndex) {
			lua_pushnumber(state, static_cast<lua_Number>(constantIndex + 1));
			luaA_pushobject(state, &proto->k[constantIndex]);
			lua_settable(state, -3);
		}
		return 1;
	}

	/**
	 * Address: 0x00912130 (FUN_00912130, func_listlocals)
	 *
	 * What it does:
	 * Pushes all local variable names visible at the requested pc lane (arg-2)
	 * for function arg-1 and returns pushed name count.
	 */
	[[maybe_unused]] int LuaDebugListLocals(lua_State* const state)
	{
		const int pc = static_cast<int>(luaL_checknumber(state, 2)) - 1;

		const int functionType = lua_type(state, 1);
		if ((functionType | 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		auto* const closureObject = static_cast<GCObject*>(state->ci->base->value.p);
		const Proto* const proto = closureObject->cl.l.p;

		int localNumber = 1;
		for (const char* localName = luaF_getlocalname(proto, 1, pc);
			localName != nullptr;
			localName = luaF_getlocalname(proto, localNumber, pc)) {
			lua_pushstring(state, localName);
			++localNumber;
		}
		return localNumber - 1;
	}

	[[nodiscard]] std::size_t AlignSizeToEight(const std::size_t value)
	{
		return (value + 7u) & ~static_cast<std::size_t>(7u);
	}

	struct LuaTableSizeRuntimeView
	{
		std::uint8_t reserved00[0x9];
		lu_byte lsizenode;
		std::uint8_t reserved0A[0x16];
		int32_t sizearray;
	};
	static_assert(
		offsetof(LuaTableSizeRuntimeView, lsizenode) == 0x9,
		"LuaTableSizeRuntimeView::lsizenode offset must be 0x9"
	);
	static_assert(
		offsetof(LuaTableSizeRuntimeView, sizearray) == 0x20,
		"LuaTableSizeRuntimeView::sizearray offset must be 0x20"
	);

	struct LuaThreadSizeRuntimeView
	{
		std::uint8_t reserved00[0x20];
		std::uint32_t lane20;
		std::uint32_t lane24;
		std::uint32_t lane28;
	};
	static_assert(
		offsetof(LuaThreadSizeRuntimeView, lane20) == 0x20,
		"LuaThreadSizeRuntimeView::lane20 offset must be 0x20"
	);
	static_assert(
		offsetof(LuaThreadSizeRuntimeView, lane24) == 0x24,
		"LuaThreadSizeRuntimeView::lane24 offset must be 0x24"
	);
	static_assert(
		offsetof(LuaThreadSizeRuntimeView, lane28) == 0x28,
		"LuaThreadSizeRuntimeView::lane28 offset must be 0x28"
	);

	void LuaDebugAppendGcObject(lua_State* const state, Table* const outputTable, int& nextIndex, GCObject* const object)
	{
		TObject* const slot = luaH_setnum(state, outputTable, ++nextIndex);
		slot->tt = static_cast<int>(object->gch.tt);
		slot->value.p = object;
	}

	void LuaDebugAppendNumber(
		lua_State* const state,
		Table* const outputTable,
		int& nextIndex,
		const float number
	)
	{
		TObject* const slot = luaH_setnum(state, outputTable, ++nextIndex);
		slot->tt = LUA_TNUMBER;
		slot->value.n = number;
	}

	/**
	 * Address: 0x00912FA0 (FUN_00912FA0, lua::getsizes)
	 *
	 * What it does:
	 * Returns (and lazily initializes) the registry weak-key table at numeric
	 * key `3` used by Lua debug allocation-size bookkeeping.
	 */
	[[maybe_unused]] Table* LuaDebugGetSizesTable(lua_State* const state)
	{
		Table* const registryTable = static_cast<Table*>(state->l_G->_registry.value.p);
		TObject* const sizesSlot = luaH_setnum(state, registryTable, kLuaRegistryAllocationSizesKey);
		if (sizesSlot->tt != LUA_TTABLE) {
			lua_newtable(state);
			lua_newtable(state);
			lua_pushlstring(state, "__mode", 6u);
			lua_pushlstring(state, "k", 1u);
			lua_rawset(state, -3);
			lua_setmetatable(state, -2);
			*sizesSlot = *(state->top - 1);
			--state->top;
		}

		return static_cast<Table*>(sizesSlot->value.p);
	}

	/**
	 * Address: 0x009121C0 (FUN_009121C0, func_allobjects)
	 *
	 * What it does:
	 * Builds and returns a flat debug table with every tracked GC object from
	 * root GC lists and interned-string buckets.
	 */
	[[maybe_unused]] int LuaDebugAllObjects(lua_State* const state)
	{
		lua_newtable(state);
		auto* const outputTable = static_cast<Table*>((state->top - 1)->value.p);
		int objectIndex = 0;
		lua_setgcthreshold(state, 0);

		global_State* const globalState = state->l_G;
		++globalState->gcTraversalLockDepth;

		for (GCObject* object = globalState->rootgc; object != nullptr; object = object->gch.next) {
			if (object != reinterpret_cast<GCObject*>(outputTable)) {
				LuaDebugAppendGcObject(state, outputTable, objectIndex, object);
			}
		}

		for (GCObject* object = globalState->rootgc1; object != nullptr; object = object->gch.next) {
			LuaDebugAppendGcObject(state, outputTable, objectIndex, object);
		}

		for (GCObject* object = globalState->rootudata; object != nullptr; object = object->gch.next) {
			LuaDebugAppendGcObject(state, outputTable, objectIndex, object);
		}

		const stringtable& stringTable = globalState->strt;
		if (stringTable.hash != nullptr) {
			for (int bucketWalk = 0; bucketWalk < stringTable.size; ++bucketWalk) {
				for (GCObject* object = stringTable.hash[bucketWalk]; object != nullptr; object = object->gch.next) {
					LuaDebugAppendGcObject(state, outputTable, objectIndex, object);
				}
			}
		}

		--globalState->gcTraversalLockDepth;
		return 1;
	}

	/**
	 * Address: 0x009122F0 (FUN_009122F0, func_allocinfo)
	 *
	 * What it does:
	 * Pushes the debug allocation-info table returned by `lua::getsizes` onto
	 * the Lua stack as a raw internal `TObject`.
	 */
	[[maybe_unused]] int LuaDebugAllocInfo(lua_State* const state)
	{
		lua_setgcthreshold(state, 0);
		Table* const sizesTable = LuaDebugGetSizesTable(state);

		TObject* const top = state->top;
		top->tt = static_cast<int>(sizesTable->tt);
		top->value.p = sizesTable;
		state->top = top + 1;
		return 1;
	}

	/**
	 * Address: 0x00912320 (FUN_00912320, func_trackallocations)
	 *
	 * What it does:
	 * Toggles global allocation tracking gate from boolean arg-1.
	 */
	[[maybe_unused]] int LuaDebugTrackAllocations(lua_State* const state)
	{
		if (lua_type(state, 1) != LUA_TBOOLEAN) {
			luaL_argerror(state, 1, "boolean expected");
		}

		state->l_G->unknown150 = static_cast<std::int8_t>(lua_toboolean(state, 1));
		return 0;
	}

	struct LuaClosureHeaderRuntimeView
	{
		std::uint8_t reserved00[0x8];
		std::uint8_t upvalueCount;
	};
	static_assert(
		offsetof(LuaClosureHeaderRuntimeView, upvalueCount) == 0x8,
		"LuaClosureHeaderRuntimeView::upvalueCount offset must be 0x8"
	);

	struct LuaUserdataTypeInfoRuntimeView
	{
		std::uint8_t reserved00[0x8];
		std::uint32_t payloadSize;
	};
	static_assert(
		offsetof(LuaUserdataTypeInfoRuntimeView, payloadSize) == 0x8,
		"LuaUserdataTypeInfoRuntimeView::payloadSize offset must be 0x8"
	);

	struct LuaUserdataRuntimeView
	{
		std::uint8_t reserved00[0x0C];
		LuaUserdataTypeInfoRuntimeView* typeInfo;
	};
	static_assert(
		offsetof(LuaUserdataRuntimeView, typeInfo) == 0x0C,
		"LuaUserdataRuntimeView::typeInfo offset must be 0x0C"
	);

	/**
	 * Address: 0x00912360 (FUN_00912360, func_GetTObjectSize)
	 *
	 * What it does:
	 * Returns aligned byte size for one Lua `TObject` payload by exact runtime
	 * type tag rules used by debug allocation helpers.
	 */
	[[maybe_unused]] std::size_t LuaDebugGetTObjectSize(const TObject* const object)
	{
		if (object == nullptr) {
			return 0;
		}

		switch (object->tt) {
		case LUA_TSTRING: {
			const auto* const stringObject = static_cast<const TString*>(object->value.p);
			if (stringObject == nullptr) {
				return 0;
			}
			return AlignSizeToEight(stringObject->len + 0x15u);
		}
		case LUA_TTABLE: {
			const auto* const tableObject = static_cast<const LuaTableSizeRuntimeView*>(object->value.p);
			if (tableObject == nullptr) {
				return 0;
			}

			const std::size_t hashBytes
				= tableObject->lsizenode != 0u ? (static_cast<std::size_t>(20u) << tableObject->lsizenode) : 0u;
			const std::size_t arrayBytes = static_cast<std::size_t>(tableObject->sizearray) * sizeof(TObject);
			return AlignSizeToEight(hashBytes + arrayBytes + 0x24u);
		}
		case LUA_CFUNCTION: {
			const auto* const closureHeader = static_cast<const LuaClosureHeaderRuntimeView*>(object->value.p);
			if (closureHeader == nullptr) {
				return 0;
			}
			return AlignSizeToEight(static_cast<std::size_t>(0x40u + (8u * closureHeader->upvalueCount)));
		}
		case LUA_TFUNCTION: {
			const auto* const closureHeader = static_cast<const LuaClosureHeaderRuntimeView*>(object->value.p);
			if (closureHeader == nullptr) {
				return 0;
			}
			return AlignSizeToEight(static_cast<std::size_t>(0x1Cu + (4u * closureHeader->upvalueCount)));
		}
		case LUA_TUSERDATA: {
			const auto* const userData = static_cast<const LuaUserdataRuntimeView*>(object->value.p);
			if (userData == nullptr || userData->typeInfo == nullptr) {
				return 0;
			}

			return AlignSizeToEight(static_cast<std::size_t>(userData->typeInfo->payloadSize + 0x10u));
		}
		case LUA_TTHREAD: {
			const auto* const threadState = static_cast<const LuaThreadSizeRuntimeView*>(object->value.p);
			if (threadState == nullptr) {
				return 0;
			}

			// Keep x86 lane arithmetic shape from FUN_00912360 exactly.
			std::uint32_t rawSize = 0x48u + (threadState->lane20 * 8u);
			rawSize -= threadState->lane28;
			rawSize += threadState->lane24;
			return AlignSizeToEight(static_cast<std::size_t>(rawSize));
		}
		case LUA_TPROTO: {
			const auto* const proto = static_cast<const Proto*>(object->value.p);
			if (proto == nullptr) {
				return 0;
			}

			const std::size_t scalarCount = static_cast<std::size_t>(
				proto->sizeupvalues
				+ proto->sizecode
				+ proto->sizelineinfo
				+ proto->sizep
				+ (proto->sizelocvars * 3)
				+ (proto->sizek * 2)
				+ 28
			);
			return AlignSizeToEight(scalarCount * sizeof(std::int32_t));
		}
		case LUA_TUPVALUE:
			return AlignSizeToEight(0x14u);
		default:
			return 0;
		}
	}

	/**
	 * Address: 0x00912470 (FUN_00912470, func_allocatedsize)
	 *
	 * What it does:
	 * Replaces each stack argument with a number containing its aligned object
	 * allocation size and returns the converted argument count.
	 */
	[[maybe_unused]] int LuaDebugAllocatedSize(lua_State* const state)
	{
		const int argumentCount = lua_gettop(state);
		for (int argumentIndex = 0; argumentIndex < argumentCount; ++argumentIndex) {
			TObject* const object = &state->base[argumentIndex];
			object->value.n = static_cast<float>(LuaDebugGetTObjectSize(object));
			object->tt = LUA_TNUMBER;
		}
		return argumentCount;
	}

	struct LuaProfileCountersRuntimeView
	{
		std::uint32_t sampleCount;
		std::uint32_t sampleCountAux;
		std::uint8_t reserved08[0x18];
		std::int64_t totalBytes;
	};
	static_assert(
		offsetof(LuaProfileCountersRuntimeView, totalBytes) == 0x20,
		"LuaProfileCountersRuntimeView::totalBytes offset must be 0x20"
	);

	[[nodiscard]] const LuaProfileCountersRuntimeView* LuaDebugGetProfileCounters(const GCObject* const object)
	{
		if (object->gch.tt == LUA_CFUNCTION) {
			return reinterpret_cast<const LuaProfileCountersRuntimeView*>(
				reinterpret_cast<const std::uint8_t*>(object) + 0x18u
			);
		}
		if (object->gch.tt == LUA_TPROTO) {
			return reinterpret_cast<const LuaProfileCountersRuntimeView*>(
				reinterpret_cast<const std::uint8_t*>(object) + 0x48u
			);
		}

		return nullptr;
	}

	/**
	 * Address: 0x0091E080 (FUN_0091E080, func_profiledata)
	 *
	 * What it does:
	 * Builds a flat profile table for GC proto/C-closure nodes that carry
	 * allocation counters, emitting per-node tuple lanes with total byte tally.
	 */
	[[maybe_unused]] int LuaDebugProfileData(lua_State* const state)
	{
		lua_newtable(state);
		auto* const outputTable = static_cast<Table*>((state->top - 1)->value.p);

		global_State* const globalState = state->l_G;
		++globalState->gcTraversalLockDepth;

		for (GCObject* secondary = globalState->rootgc1; secondary != nullptr; secondary = secondary->gch.next) {
		}

		int outputIndex = 0;
		for (GCObject* object = globalState->rootgc; object != nullptr; object = object->gch.next) {
			const LuaProfileCountersRuntimeView* const counters = LuaDebugGetProfileCounters(object);
			if (counters == nullptr || (counters->sampleCount | counters->sampleCountAux) == 0u) {
				continue;
			}

			LuaDebugAppendGcObject(state, outputTable, outputIndex, object);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, static_cast<float>(counters->totalBytes));
		}

		--globalState->gcTraversalLockDepth;
		return 1;
	}

	/**
	 * Address: 0x0090E790 (FUN_0090E790, callalert)
	 *
	 * What it does:
	 * Handles Lua chunk-call failures by dispatching to global `_ALERT` when it
	 * is callable, otherwise prints the pending Lua error text to stderr and
	 * drops helper/error stack lanes.
	 */
	[[maybe_unused]] void LuaCallAlert(lua_State* const state, const int status)
	{
		if (status == 0) {
			return;
		}

		lua_pushstring(state, "_ALERT");
		lua_gettable(state, LUA_GLOBALSINDEX);

		const int alertType = lua_type(state, -1);
		if ((alertType | 1) == LUA_TFUNCTION) {
			lua_insert(state, -2);
			lua_call(state, 1, 0);
			return;
		}

		const char* const alertText = lua_tostring(state, -2);
		std::fprintf(stderr, "%s\n", alertText);
		lua_settop(state, -3);
	}

	/**
	 * Address: 0x0090E830 (FUN_0090E830, lua_dofile)
	 *
	 * What it does:
	 * Loads one Lua chunk from `filename`, executes it when load succeeds,
	 * then routes any error status through `callalert`.
	 */
	extern "C" int lua_dofile(lua_State* const state, const char* const filename)
	{
		int status = ::luaL_loadfile(state, filename);
		if (status == 0) {
			status = ::lua_pcall(state, 0, LUA_MULTRET, 0);
		}

		LuaCallAlert(state, status);
		return status;
	}

	/**
	 * Address: 0x0090E870 (FUN_0090E870, lua_dobuffer)
	 *
	 * What it does:
	 * Loads one source buffer as a Lua chunk, executes it when load succeeds,
	 * then routes any error status through `callalert`.
	 */
	[[maybe_unused]] int lua_dobuffer(
		lua_State* const state,
		const char* const buffer,
		const int size,
		const char* const name
	)
	{
		int status = ::luaL_loadbuffer(state, buffer, static_cast<size_t>(size), name);
		if (status == 0) {
			status = ::lua_pcall(state, 0, LUA_MULTRET, 0);
		}

		LuaCallAlert(state, status);
		return status;
	}

	/**
	 * Address: 0x0090E8D0 (FUN_0090E8D0, lua_dostring)
	 *
	 * What it does:
	 * Executes one null-terminated source string by forwarding to `lua_dobuffer`.
	 */
	[[maybe_unused]] int lua_dostring(lua_State* const state, const char* const source)
	{
		return lua_dobuffer(state, source, static_cast<int>(std::strlen(source)), source);
	}

	/**
	 * Address: 0x0090D6B0 (FUN_0090D6B0, lua_version)
	 *
	 * What it does:
	 * Returns the embedded Lua runtime version string literal.
	 */
	extern "C" const char* lua_version()
	{
		return "Lua 5.0.1";
	}

	/**
	 * Address: 0x00924BE0 (FUN_00924BE0, str_len)
	 *
	 * What it does:
	 * Returns the byte length of arg-1 string as one Lua number result.
	 */
	[[maybe_unused]] int str_len(lua_State* const state)
	{
		size_t textLength = 0u;
		(void)luaL_checklstring(state, 1, &textLength);
		lua_pushnumber(state, static_cast<float>(textLength));
		return 1;
	}

	/**
	 * Address: 0x00924CE0 (FUN_00924CE0, str_lower)
	 *
	 * What it does:
	 * Lowercases each byte from the first Lua string argument and pushes the
	 * transformed buffer result.
	 */
	[[maybe_unused]] int str_lower(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);
		char* const bufferEnd = reinterpret_cast<char*>(&buffer) + sizeof(buffer);
		for (size_t index = 0; index < textLength; ++index) {
			if (buffer.p >= bufferEnd) {
				luaL_prepbuffer(&buffer);
			}
			*buffer.p++ = static_cast<char>(std::tolower(static_cast<unsigned char>(text[index])));
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x00924C30 (FUN_00924C30, str_sub)
	 *
	 * What it does:
	 * Returns the substring slice selected by arg-2 and arg-3, honoring Lua's
	 * 1-based negative-index conventions and empty-slice behavior.
	 */
	[[maybe_unused]] int str_sub(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);

		int start = static_cast<int>(luaL_checknumber(state, 2));
		if (start < 0) {
			start += static_cast<int>(textLength) + 1;
		}

		int end = static_cast<int>(luaL_optnumber(state, 3, -1.0f));
		if (end < 0) {
			end += static_cast<int>(textLength) + 1;
		}

		if (start < 1) {
			start = 1;
		}
		if (end > static_cast<int>(textLength)) {
			end = static_cast<int>(textLength);
		}

		if (start > end) {
			lua_pushlstring(state, "", 0u);
		} else {
			lua_pushlstring(state, text + (start - 1), static_cast<size_t>(end - start + 1));
		}
		return 1;
	}

	/**
	 * Address: 0x00924D80 (FUN_00924D80, str_upper)
	 *
	 * What it does:
	 * Uppercases each byte from the first Lua string argument and pushes the
	 * transformed buffer result.
	 */
	[[maybe_unused]] int str_upper(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);
		char* const bufferEnd = reinterpret_cast<char*>(&buffer) + sizeof(buffer);
		for (size_t index = 0; index < textLength; ++index) {
			if (buffer.p >= bufferEnd) {
				luaL_prepbuffer(&buffer);
			}
			*buffer.p++ = static_cast<char>(std::toupper(static_cast<unsigned char>(text[index])));
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x00924E20 (FUN_00924E20, str_rep)
	 *
	 * What it does:
	 * Repeats arg-1 string arg-2 times and pushes the concatenated result.
	 */
	[[maybe_unused]] int str_rep(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);
		const int repeatCount = static_cast<int>(luaL_checknumber(state, 2));

		luaL_Buffer buffer{};
		luaL_buffinit(state, &buffer);
		for (int repeatIndex = 0; repeatIndex < repeatCount; ++repeatIndex) {
			luaL_addlstring(&buffer, text, textLength);
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Address: 0x00924FB0 (FUN_00924FB0, writer)
	 *
	 * What it does:
	 * Appends one Lua bytecode dump chunk into a `luaL_Buffer` sink and returns
	 * success (`1`) to the dump producer.
	 */
	[[maybe_unused]] int writer(
		lua_State* const,
		const char* const chunk,
		const size_t chunkSize,
		luaL_Buffer* const buffer
	)
	{
		luaL_addlstring(buffer, chunk, chunkSize);
		return 1;
	}

	/**
	 * Address: 0x00924EA0 (FUN_00924EA0, str_byte)
	 *
	 * What it does:
	 * Returns one byte value from arg-1 at optional arg-2 position, honoring
	 * Lua's negative-index adjustment and out-of-range empty-result behavior.
	 */
	[[maybe_unused]] int str_byte(lua_State* const state)
	{
		size_t textLength = 0u;
		const char* const text = luaL_checklstring(state, 1, &textLength);

		int position = static_cast<int>(luaL_optnumber(state, 2, 1.0f));
		if (position < 0) {
			position += static_cast<int>(textLength) + 1;
		}

		if (position <= 0 || static_cast<size_t>(position) > textLength) {
			return 0;
		}

		lua_pushnumber(state, static_cast<float>(static_cast<unsigned char>(text[position - 1])));
		return 1;
	}

	/**
	 * Address: 0x00925B30 (FUN_00925B30, str_find)
	 *
	 * What it does:
	 * Finds one pattern in source text with optional plain/anchored modes and
	 * returns `(start,end,captures...)` or `nil` when no match exists.
	 */
	[[maybe_unused]] int str_find(lua_State* const state)
	{
		size_t sourceLength = 0u;
		const char* const sourceText = luaL_checklstring(state, 1, &sourceLength);
		size_t patternLength = 0u;
		const char* pattern = luaL_checklstring(state, 2, &patternLength);

		int startIndex = static_cast<int>(luaL_optnumber(state, 3, 1.0f));
		if (startIndex < 0) {
			startIndex += static_cast<int>(sourceLength) + 1;
		}

		std::size_t init = 0u;
		if (startIndex - 1 >= 0) {
			init = static_cast<std::size_t>(startIndex - 1);
			if (init > sourceLength) {
				init = sourceLength;
			}
		}

		if (lua_toboolean(state, 4) != 0 || std::strpbrk(pattern, "^$*+?.([%-") == nullptr) {
			const char* const found = lmemfind(patternLength, sourceText + init, sourceLength - init, pattern);
			if (found != nullptr) {
				const std::size_t matchStart = static_cast<std::size_t>(found - sourceText);
				lua_pushnumber(state, static_cast<float>(matchStart + 1u));
				lua_pushnumber(state, static_cast<float>(matchStart + patternLength));
				return 2;
			}

			lua_pushnil(state);
			return 1;
		}

		int anchor = 0;
		if (*pattern == '^') {
			++pattern;
			anchor = 1;
		}

		const char* searchCursor = sourceText + init;
		MatchStateRuntimeView matchState{};
		matchState.state = state;
		matchState.srcInit = sourceText;
		matchState.srcEnd = sourceText + sourceLength;

		while (true) {
			matchState.level = 0;
			const char* const matchEnd = match(&matchState, searchCursor, pattern);
			if (matchEnd != nullptr) {
				lua_pushnumber(state, static_cast<float>(searchCursor - sourceText + 1));
				lua_pushnumber(state, static_cast<float>(matchEnd - sourceText));
				return push_captures(nullptr, nullptr, &matchState) + 2;
			}

			const char* const priorCursor = searchCursor++;
			if (priorCursor >= matchState.srcEnd || anchor != 0) {
				lua_pushnil(state);
				return 1;
			}
		}
	}

	/**
	 * Address: 0x00925D00 (FUN_00925D00, gfind_aux)
	 *
	 * What it does:
	 * Advances legacy `%gfind` iterator state over source/pattern upvalues and
	 * returns next capture tuple while updating closure start offset.
	 */
	[[maybe_unused]] int gfind_aux(lua_State* const state)
	{
		const char* const sourceText = lua_tostring(state, lua_upvalueindex(1));
		const size_t sourceLength = lua_strlen(state, lua_upvalueindex(1));
		const char* const pattern = lua_tostring(state, lua_upvalueindex(2));

		MatchStateRuntimeView matchState{};
		matchState.state = state;
		matchState.srcInit = sourceText;
		matchState.srcEnd = sourceText + sourceLength;

		const int startOffset = static_cast<int>(lua_tonumber(state, lua_upvalueindex(3)));
		const char* sourceCursor = sourceText + startOffset;
		if (sourceCursor > matchState.srcEnd) {
			return 0;
		}

		const char* matchEnd = nullptr;
		while (true) {
			matchState.level = 0;
			matchEnd = match(&matchState, sourceCursor, pattern);
			if (matchEnd != nullptr) {
				break;
			}

			++sourceCursor;
			if (sourceCursor > matchState.srcEnd) {
				return 0;
			}
		}

		int newStart = static_cast<int>(matchEnd - sourceText);
		if (matchEnd == sourceCursor) {
			++newStart;
		}

		lua_pushnumber(state, static_cast<float>(newStart));
		lua_replace(state, lua_upvalueindex(3));
		return push_captures(sourceCursor, matchEnd, &matchState);
	}

	/**
	 * Address: 0x00925E00 (FUN_00925E00, gfind)
	 *
	 * What it does:
	 * Validates source/pattern string arguments and returns one closure iterator
	 * with `(source, pattern, startIndex)` captured upvalues.
	 */
	[[maybe_unused]] int gfind(lua_State* const state)
	{
		luaL_checklstring(state, 1, nullptr);
		luaL_checklstring(state, 2, nullptr);
		lua_settop(state, 2);
		lua_pushnumber(state, 0.0f);
		lua_pushcclosure(state, gfind_aux, 3);
		return 1;
	}

	/**
	 * Address: 0x00925E50 (FUN_00925E50, add_s)
	 *
	 * What it does:
	 * Builds one replacement segment for `%gsub`: either expands replacement
	 * string capture escapes (`%1`..`%9`) or calls replacement function/value.
	 */
	[[maybe_unused]] void add_s(
		MatchStateRuntimeView* const matchState,
		luaL_Buffer* const buffer,
		const char* const sourceStart,
		const char* const sourceEnd
	)
	{
		lua_State* const state = matchState->state;
		if (lua_isstring(state, 3) != 0) {
			const char* const replacement = lua_tostring(state, 3);
			const size_t replacementLength = lua_strlen(state, 3);
			for (size_t replacementIndex = 0; replacementIndex < replacementLength; ++replacementIndex) {
				if (replacement[replacementIndex] == '%') {
					const unsigned char replacementChar =
						static_cast<unsigned char>(replacement[++replacementIndex]);
					if (std::isdigit(replacementChar) != 0) {
						const int captureIndex = static_cast<int>(replacement[replacementIndex] - '1');
						if (captureIndex < 0 || captureIndex >= matchState->level
							|| matchState->captures[captureIndex].len == -1) {
							luaL_error(matchState->state, "invalid capture index");
						}

						push_onecapture(captureIndex, matchState);
						luaL_addvalue(buffer);
					} else {
						if (buffer->p >= reinterpret_cast<char*>(&buffer[1])) {
							luaL_prepbuffer(buffer);
						}
						*buffer->p++ = replacement[replacementIndex];
					}
				} else {
					if (buffer->p >= reinterpret_cast<char*>(&buffer[1])) {
						luaL_prepbuffer(buffer);
					}
					*buffer->p++ = replacement[replacementIndex];
				}
			}
			return;
		}

		lua_pushvalue(state, 3);
		const int captureCount = push_captures(sourceStart, sourceEnd, matchState);
		lua_call(state, captureCount, 1);
		if (lua_isstring(state, -1) != 0) {
			luaL_addvalue(buffer);
			return;
		}

		lua_settop(state, -2);
	}

	/**
	 * Address: 0x00919A50 (FUN_00919A50, math_abs)
	 *
	 * What it does:
	 * Computes `abs(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	[[maybe_unused]] int math_abs(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::fabs(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919A80 (FUN_00919A80, math_sin)
	 *
	 * What it does:
	 * Computes `sin(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	[[maybe_unused]] int math_sin(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::sin(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919AB0 (FUN_00919AB0, math_cos)
	 *
	 * What it does:
	 * Computes `cos(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	[[maybe_unused]] int math_cos(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::cos(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919AE0 (FUN_00919AE0, math_tan)
	 *
	 * What it does:
	 * Computes `tan(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	[[maybe_unused]] int math_tan(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::tan(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919B40 (FUN_00919B40, math_acos)
	 *
	 * What it does:
	 * Computes `acos(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	[[maybe_unused]] int math_acos(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::acos(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919B70 (FUN_00919B70, math_atan)
	 *
	 * What it does:
	 * Computes `atan(arg1)` (x87 `fpatan` lane with denominator `1.0`) and
	 * pushes one Lua numeric result.
	 */
	[[maybe_unused]] int math_atan(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(
			state,
			static_cast<lua_Number>(std::atan2(static_cast<double>(value), 1.0))
		);
		return 1;
	}

	/**
	 * Address: 0x00919BA0 (FUN_00919BA0, math_atan2)
	 *
	 * What it does:
	 * Computes `atan2(arg1, arg2)` with Lua numeric argument validation and
	 * pushes one Lua numeric result.
	 */
	[[maybe_unused]] int math_atan2(lua_State* const state)
	{
		const lua_Number numerator = luaL_checknumber(state, 1);
		const lua_Number denominator = luaL_checknumber(state, 2);
		lua_pushnumber(
			state,
			static_cast<lua_Number>(std::atan2(static_cast<double>(numerator), static_cast<double>(denominator)))
		);
		return 1;
	}

	/**
	 * Address: 0x00919BE0 (FUN_00919BE0, math_ceil)
	 *
	 * What it does:
	 * Computes `ceil(arg1)` with Lua numeric argument validation and pushes one
	 * resulting Lua number.
	 */
	[[maybe_unused]] int math_ceil(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::ceil(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919C10 (FUN_00919C10, math_floor)
	 *
	 * What it does:
	 * Computes `floor(arg1)` with Lua numeric argument validation and pushes
	 * one resulting Lua number.
	 */
	[[maybe_unused]] int math_floor(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::floor(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919C40 (FUN_00919C40, math_mod)
	 *
	 * What it does:
	 * Computes `fmod(arg1, arg2)` with Lua numeric argument checks and pushes
	 * one Lua numeric result.
	 */
	[[maybe_unused]] int math_mod(lua_State* const state)
	{
		const lua_Number left = luaL_checknumber(state, 1);
		const lua_Number right = luaL_checknumber(state, 2);
		lua_pushnumber(
			state,
			static_cast<lua_Number>(std::fmod(static_cast<double>(left), static_cast<double>(right)))
		);
		return 1;
	}

	/**
	 * Address: 0x00919C80 (FUN_00919C80, math_sqrt)
	 *
	 * What it does:
	 * Computes `sqrt(arg1)` with Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	[[maybe_unused]] int math_sqrt(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::sqrt(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919CB0 (FUN_00919CB0, math_pow)
	 *
	 * What it does:
	 * Computes `pow(arg1, arg2)` with Lua numeric argument checks and pushes
	 * one Lua numeric result.
	 */
	[[maybe_unused]] int math_pow(lua_State* const state)
	{
		const lua_Number base = luaL_checknumber(state, 1);
		const lua_Number exponent = luaL_checknumber(state, 2);
		lua_pushnumber(
			state,
			static_cast<lua_Number>(std::pow(static_cast<double>(base), static_cast<double>(exponent)))
		);
		return 1;
	}

	/**
	 * Address: 0x00919CF0 (FUN_00919CF0, math_log)
	 *
	 * What it does:
	 * Computes natural logarithm for arg-1 (`ln`) and pushes one Lua numeric
	 * result.
	 */
	[[maybe_unused]] int math_log(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::log(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919D20 (FUN_00919D20, math_log10)
	 *
	 * What it does:
	 * Computes base-10 logarithm for arg-1 and pushes one Lua numeric result.
	 */
	[[maybe_unused]] int math_log10(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::log10(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919D50 (FUN_00919D50, math_exp)
	 *
	 * What it does:
	 * Computes exponential (`e^arg1`) and pushes one Lua numeric result.
	 */
	[[maybe_unused]] int math_exp(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::exp(static_cast<double>(value))));
		return 1;
	}

	/**
	 * Address: 0x00919D90 (FUN_00919D90, math_deg)
	 *
	 * What it does:
	 * Converts radians (arg-1) to degrees and pushes one Lua numeric result.
	 */
	[[maybe_unused]] int math_deg(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, value * static_cast<lua_Number>(57.29578f));
		return 1;
	}

	/**
	 * Address: 0x00919DC0 (FUN_00919DC0, math_rad)
	 *
	 * What it does:
	 * Converts degrees (arg-1) to radians and pushes one Lua numeric result.
	 */
	[[maybe_unused]] int math_rad(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, value * static_cast<lua_Number>(0.017453292f));
		return 1;
	}

	/**
	 * Address: 0x00919DF0 (FUN_00919DF0, math_frexp)
	 *
	 * What it does:
	 * Computes `frexp(arg1, &exp)` and pushes both mantissa and exponent as Lua
	 * numeric results.
	 */
	[[maybe_unused]] int math_frexp(lua_State* const state)
	{
		int exponent = 0;
		const lua_Number value = luaL_checknumber(state, 1);
		const lua_Number mantissa = static_cast<lua_Number>(std::frexp(static_cast<double>(value), &exponent));
		lua_pushnumber(state, mantissa);
		lua_pushnumber(state, static_cast<lua_Number>(exponent));
		return 2;
	}

	/**
	 * Address: 0x00919E40 (FUN_00919E40, math_ldexp)
	 *
	 * What it does:
	 * Computes `ldexp(arg1, int(arg2))` with Lua numeric argument checks and
	 * returns the result as one Lua number.
	 */
	[[maybe_unused]] int math_ldexp(lua_State* const state)
	{
		const int exponent = static_cast<int>(luaL_checknumber(state, 2));
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(std::ldexp(static_cast<double>(value), exponent)));
		return 1;
	}

	/**
	 * Address: 0x00919E90 (FUN_00919E90, math_min)
	 *
	 * What it does:
	 * Returns the minimum numeric value across all Lua arguments.
	 */
	[[maybe_unused]] int math_min(lua_State* const state)
	{
		const int valueCount = lua_gettop(state);
		lua_Number currentMinimum = luaL_checknumber(state, 1);

		for (int index = 2; index <= valueCount; ++index) {
			const lua_Number value = luaL_checknumber(state, index);
			if (currentMinimum > value) {
				currentMinimum = value;
			}
		}

		lua_pushnumber(state, currentMinimum);
		return 1;
	}

	/**
	 * Address: 0x00919F10 (FUN_00919F10, math_max)
	 *
	 * What it does:
	 * Returns the maximum numeric value across all Lua arguments.
	 */
	[[maybe_unused]] int math_max(lua_State* const state)
	{
		const int valueCount = lua_gettop(state);
		lua_Number currentMaximum = luaL_checknumber(state, 1);

		for (int index = 2; index <= valueCount; ++index) {
			const lua_Number value = luaL_checknumber(state, index);
			if (value > currentMaximum) {
				currentMaximum = value;
			}
		}

		lua_pushnumber(state, currentMaximum);
		return 1;
	}

	/**
	 * Address: 0x0091A0D0 (FUN_0091A0D0, math_randomseed)
	 *
	 * What it does:
	 * Reads one numeric seed argument, truncates it to integer seed lane, and
	 * re-seeds the C runtime RNG.
	 */
	[[maybe_unused]] int math_randomseed(lua_State* const state)
	{
		const auto seed = static_cast<unsigned int>(luaL_checknumber(state, 1));
		std::srand(seed);
		return 0;
	}

	/**
	 * Address: 0x0090EE20 (FUN_0090EE20, luaB_error)
	 *
	 * What it does:
	 * Raises a Lua error from arg-1 and optionally prefixes source/line
	 * context using arg-2 stack level.
	 */
	[[maybe_unused]] int luaB_error(lua_State* const state)
	{
		const int level = static_cast<int>(luaL_optnumber(state, 2, 1.0f));
		luaL_checkany(state, 1);
		if (lua_isstring(state, 1) != 0 && level != 0) {
			luaL_where(state, level);
			lua_pushvalue(state, 1);
			lua_concat(state, 2);
			return lua_error(state);
		}

		lua_pushvalue(state, 1);
		return lua_error(state);
	}

	/**
	 * Address: 0x0090EEA0 (FUN_0090EEA0, luaB_getmetatable)
	 *
	 * What it does:
	 * Returns arg-1 metatable when present; if protected `__metatable` exists,
	 * returns that field instead.
	 */
	[[maybe_unused]] int luaB_getmetatable(lua_State* const state)
	{
		luaL_checkany(state, 1);
		if (lua_getmetatable(state, 1) == 0) {
			lua_pushnil(state);
			return 1;
		}

		(void)luaL_getmetafield(state, 1, "__metatable");
		return 1;
	}

	[[maybe_unused]] void getfunc(lua_State* const state)
	{
		if (lua_isfunction(state, 1) != 0) {
			lua_pushvalue(state, 1);
			return;
		}

		::lua_Debug activationRecord{};
		const int level = static_cast<int>(luaL_optnumber(state, 1, 1.0f));
		if (level < 0) {
			luaL_argerror(state, 1, "level must be non-negative");
		}
		if (lua_getstack(state, level, &activationRecord) == 0) {
			luaL_argerror(state, 1, "invalid level");
		}

		lua_getinfo(state, "f", &activationRecord);
		if (lua_isnil(state, -1) != 0) {
			luaL_error(state, "no function environment for tail call at level %d", level);
		}
	}

	/**
	 * Address: 0x0090F050 (FUN_0090F050, luaB_getfenv)
	 *
	 * What it does:
	 * Resolves target function (object or stack level), then returns its
	 * effective environment (`__fenv` override when present).
	 */
	[[maybe_unused]] int luaB_getfenv(lua_State* const state)
	{
		getfunc(state);
		lua_getfenv(state, -1);
		lua_pushlstring(state, "__fenv", 6u);
		lua_rawget(state, -2);
		if (lua_type(state, -1) == LUA_TNIL) {
			lua_settop(state, -2);
		}
		return 1;
	}

	/**
	 * Address: 0x0090F160 (FUN_0090F160, luaB_rawequal)
	 *
	 * What it does:
	 * Requires two arguments, compares them with raw-equality semantics, and
	 * pushes one boolean result.
	 */
	[[maybe_unused]] int luaB_rawequal(lua_State* const state)
	{
		luaL_checkany(state, 1);
		luaL_checkany(state, 2);
		lua_pushboolean(state, lua_rawequal(state, 1, 2));
		return 1;
	}

	/**
	 * Address: 0x0090F190 (FUN_0090F190, luaB_rawget)
	 *
	 * What it does:
	 * Requires table + key arguments, performs one raw table lookup, and
	 * returns the retrieved value.
	 */
	[[maybe_unused]] int luaB_rawget(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		luaL_checkany(state, 2);
		lua_rawget(state, 1);
		return 1;
	}

	/**
	 * Address: 0x0090F1C0 (FUN_0090F1C0, luaB_rawset)
	 *
	 * What it does:
	 * Requires table/key/value arguments, performs one raw table write, and
	 * returns the table lane.
	 */
	[[maybe_unused]] int luaB_rawset(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		luaL_checkany(state, 2);
		luaL_checkany(state, 3);
		lua_rawset(state, 1);
		return 1;
	}

	/**
	 * Address: 0x0090F200 (FUN_0090F200, luaB_gcinfo)
	 *
	 * What it does:
	 * Pushes current GC count and threshold as numeric values.
	 */
	[[maybe_unused]] int luaB_gcinfo(lua_State* const state)
	{
		lua_pushnumber(state, static_cast<lua_Number>(lua_getgccount(state)));
		lua_pushnumber(state, static_cast<lua_Number>(lua_getgcthreshold(state)));
		return 2;
	}

	/**
	 * Address: 0x0090F240 (FUN_0090F240, luaB_collectgarbage)
	 *
	 * What it does:
	 * Optionally sets GC threshold from arg-1 and returns no values.
	 */
	[[maybe_unused]] int luaB_collectgarbage(lua_State* const state)
	{
		const lua_Number threshold = luaL_optnumber(state, 1, 0.0f);
		lua_setgcthreshold(state, static_cast<int>(threshold));
		return 0;
	}

	/**
	 * Address: 0x0090F270 (FUN_0090F270, luaB_type)
	 *
	 * What it does:
	 * Replaces arg-1 with the interned type-name string lane from
	 * `global_State::_defaultmetatypes` and returns it.
	 */
	[[maybe_unused]] int luaB_type(lua_State* const state)
	{
		luaL_checkany(state, 1);

		TObject* const top = state->top;
		const int valueTypeTag = (top - 1)->tt;
		TString* const typeName = static_cast<TString*>(state->l_G->_defaultmetatypes[valueTypeTag].value.p);
		(top - 1)->tt = static_cast<int>(typeName->tt);
		(top - 1)->value.p = typeName;
		return 1;
	}

	/**
	 * Address: 0x0090F2B0 (FUN_0090F2B0, luaB_next)
	 *
	 * What it does:
	 * Iterates one table lane with `lua_next`; returns key/value pair when
	 * available, otherwise pushes nil and returns one value.
	 */
	[[maybe_unused]] int luaB_next(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		lua_settop(state, 2);
		if (lua_next(state, 1) != 0) {
			return 2;
		}

		lua_pushnil(state);
		return 1;
	}

	/**
	 * Address: 0x0090F2F0 (FUN_0090F2F0, luaB_pairs)
	 *
	 * What it does:
	 * Returns the canonical Lua `pairs` iterator triple:
	 * (`next`, table, nil).
	 */
	[[maybe_unused]] int luaB_pairs(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		lua_pushlstring(state, "next", 4u);
		lua_rawget(state, LUA_GLOBALSINDEX);
		lua_pushvalue(state, 1);
		lua_pushnil(state);
		return 3;
	}

	/**
	 * Address: 0x0090F330 (FUN_0090F330, luaB_ipairs)
	 *
	 * What it does:
	 * Implements the legacy Lua `ipairs` iterator lane: bootstrap call returns
	 * (`ipairs`, table, 0), subsequent calls increment numeric index and fetch
	 * array slot with `lua_rawgeti`.
	 */
	[[maybe_unused]] int luaB_ipairs(lua_State* const state)
	{
		const float indexValue = lua_tonumber(state, 2);
		luaL_checktype(state, 1, LUA_TTABLE);

		if (indexValue == 0.0f && lua_type(state, 2) == LUA_TNONE) {
			lua_pushlstring(state, "ipairs", 6u);
			lua_rawget(state, LUA_GLOBALSINDEX);
			lua_pushvalue(state, 1);
			lua_pushnumber(state, 0.0f);
			return 3;
		}

		const float nextIndex = indexValue + 1.0f;
		lua_pushnumber(state, nextIndex);
		lua_rawgeti(state, 1, static_cast<int>(nextIndex));
		return lua_type(state, -1) != LUA_TNIL ? 2 : 0;
	}

	/**
	 * Address: 0x0090F420 (FUN_0090F420, luaB_loadstring)
	 *
	 * What it does:
	 * Loads one Lua chunk from string input and returns either compiled
	 * function (success) or `(nil, error)` on failure.
	 */
	[[maybe_unused]] int luaB_loadstring(lua_State* const state)
	{
		size_t chunkLength = 0u;
		const char* const chunkText = luaL_checklstring(state, 1, &chunkLength);
		const char* const chunkName = luaL_optlstring(state, 2, chunkText, nullptr);
		if (::luaL_loadbuffer(state, chunkText, chunkLength, chunkName) == 0) {
			return 1;
		}

		lua_pushnil(state);
		lua_insert(state, -2);
		return 2;
	}

	/**
	 * Address: 0x0090F480 (FUN_0090F480, luaB_loadfile)
	 *
	 * What it does:
	 * Loads one Lua chunk from optional file path and returns either compiled
	 * function (success) or `(nil, error)` on failure.
	 */
	[[maybe_unused]] int luaB_loadfile(lua_State* const state)
	{
		const char* const fileName = luaL_optlstring(state, 1, nullptr, nullptr);
		if (luaL_loadfile(state, fileName) == 0) {
			return 1;
		}

		lua_pushnil(state);
		lua_insert(state, -2);
		return 2;
	}

	/**
	 * Address: 0x0090F4C0 (FUN_0090F4C0, luaB_dofile)
	 *
	 * What it does:
	 * Loads an optional file path, executes the chunk, and returns all chunk
	 * results currently on stack.
	 */
	[[maybe_unused]] int luaB_dofile(lua_State* const state)
	{
		const char* const fileName = luaL_optlstring(state, 1, nullptr, nullptr);
		const int baseTop = lua_gettop(state);
		if (luaL_loadfile(state, fileName) != 0) {
			lua_error(state);
		}

		lua_call(state, 0, LUA_MULTRET);
		return lua_gettop(state) - baseTop;
	}

	/**
	 * Address: 0x0090F560 (FUN_0090F560, luaB_unpack)
	 *
	 * What it does:
	 * Expands table arg-1 array part into multiple return values.
	 */
	[[maybe_unused]] int luaB_unpack(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		const int elementCount = luaL_getn(state, 1);
		luaL_checkstack(state, elementCount, "table too big to unpack");
		for (int index = 1; index <= elementCount; ++index) {
			lua_rawgeti(state, 1, index);
		}
		return elementCount;
	}

	/**
	 * Address: 0x0090F5B0 (FUN_0090F5B0, luaB_pcall)
	 *
	 * What it does:
	 * Executes protected call on arg-1 function using remaining stack args, then
	 * prepends boolean success flag to returned value lanes.
	 */
	[[maybe_unused]] int luaB_pcall(lua_State* const state)
	{
		luaL_checkany(state, 1);
		const int status = lua_pcall(state, lua_gettop(state) - 1, LUA_MULTRET, 0);
		lua_pushboolean(state, status == 0 ? 1 : 0);
		lua_insert(state, 1);
		return lua_gettop(state);
	}

	/**
	 * Address: 0x0090F780 (FUN_0090F780, pushcomposename)
	 *
	 * What it does:
	 * Expands each '?' placeholder in the module path component using arg-1,
	 * then concatenates all generated fragments into one composed name.
	 */
	[[maybe_unused]] void pushcomposename(lua_State* const state)
	{
		const char* path = lua_tostring(state, -1);
		int segmentCount = 1;
		const char* wildcard = std::strchr(path, '?');
		while (wildcard != nullptr) {
			luaL_checkstack(state, 3, "too many marks in a path component");
			lua_pushlstring(state, path, static_cast<size_t>(wildcard - path));
			lua_pushvalue(state, 1);
			path = wildcard + 1;
			segmentCount += 2;
			wildcard = std::strchr(path, '?');
		}

		lua_pushstring(state, path);
		lua_concat(state, segmentCount);
	}

	/**
	 * Address: 0x0090FB60 (FUN_0090FB60, luaB_cocreate)
	 *
	 * What it does:
	 * Creates one new coroutine thread and moves arg-1 Lua function onto the
	 * new thread stack as its entry lane.
	 */
	[[maybe_unused]] int luaB_cocreate(lua_State* const state)
	{
		lua_State* const newThread = lua_newthread(state);
		if (lua_type(state, 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		lua_pushvalue(state, 1);
		lua_xmove(state, newThread, 1);
		return 1;
	}

	/**
	 * Address: 0x0090FC10 (FUN_0090FC10, luaB_yield)
	 *
	 * What it does:
	 * Yields current coroutine with all values currently present on stack.
	 */
	[[maybe_unused]] int luaB_yield(lua_State* const state)
	{
		return lua_yield(state, lua_gettop(state));
	}

	/**
	 * Address: 0x00914580 (FUN_00914580, resume)
	 *
	 * What it does:
	 * Applies one coroutine resume step: restores pending frame state when
	 * resuming after yield, executes VM, then finalizes any immediate return.
	 */
	[[maybe_unused]] void resume(int* const userData, lua_State* const state)
	{
		const int argumentCount = *userData;
		CallInfo* const currentFrame = state->ci;

		if (currentFrame == state->base_ci) {
			(void)luaD_precall(state, &state->top[-argumentCount - 1]);
		} else if (currentFrame->state == 4) {
			CallInfo* const previousFrame = currentFrame - 1;
			const std::uint32_t instruction = static_cast<std::uint32_t>(*(previousFrame->savedpc - 1));
			previousFrame->state = 0;

			const int wantedResults = static_cast<int>((instruction >> 6u) & 0x1FFu) - 1;
			(void)luaD_poscall(state, wantedResults, &state->top[-argumentCount]);
			if (wantedResults >= 0) {
				state->top = state->ci->top;
			}
		} else {
			currentFrame->state = 0;
		}

		StkId firstResult = luaV_execute(state);
		if (firstResult != nullptr) {
			(void)luaD_poscall(state, -1, firstResult);
		}
	}

	/**
	 * Address: 0x00913CF0 (FUN_00913CF0, callrethooks)
	 *
	 * What it does:
	 * Emits return and tail-return debug hook events for one completed frame and
	 * remaps `firstResult` to the current stack base after hook side effects.
	 */
	[[maybe_unused]] StkId callrethooks(StkId firstResult, lua_State* const state)
	{
		constexpr int kCiSavedPc = 3;

		const std::ptrdiff_t resultOffset = firstResult - state->stack;
		luaD_callhook(state, LUA_HOOKRET, -1);

		CallInfo* const currentFrame = state->ci;
		if (currentFrame->state < kCiSavedPc) {
			if (currentFrame->tailcalls != 0) {
				do {
					--state->ci->tailcalls;
					luaD_callhook(state, LUA_HOOKTAILRET, -1);
				} while (state->ci->tailcalls != 0);
			}
			--state->ci->tailcalls;
		}

		return state->stack + resultOffset;
	}

	/**
	 * Address: 0x00913DC0 (FUN_00913DC0, resume_error)
	 *
	 * What it does:
	 * Pushes one interned error string into the coroutine base slot, grows the
	 * stack when needed, and returns a single Lua result lane.
	 */
	[[maybe_unused]] int resume_error(lua_State* const state, const char* const message)
	{
		TObject* const base = state->ci->base;
		state->top = base;

		TString* const errorString = luaS_newlstr(state, message, std::strlen(message));
		base->tt = errorString->tt;
		base->value.p = errorString;

		if (state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;
		return 1;
	}

	/**
	 * Address: 0x0090FA00 (FUN_0090FA00, auxresume)
	 *
	 * What it does:
	 * Moves resume arguments into target coroutine, executes one resume, then
	 * moves either one error object or all yielded/returned values back.
	 */
	[[maybe_unused]] int auxresume(const int argumentCount, lua_State* const callerState, lua_State* const coroutineState)
	{
		if (lua_checkstack(coroutineState, argumentCount) == 0) {
			luaL_error(callerState, "too many arguments to resume");
		}

		lua_xmove(callerState, coroutineState, argumentCount);
		if (lua_resume(coroutineState, argumentCount) != 0) {
			lua_xmove(coroutineState, callerState, 1);
			return -1;
		}

		const int resultCount = lua_gettop(coroutineState);
		if (lua_checkstack(callerState, resultCount) == 0) {
			luaL_error(callerState, "too many results to resume");
		}

		lua_xmove(coroutineState, callerState, resultCount);
		return resultCount;
	}

	/**
	 * Address: 0x0090FA80 (FUN_0090FA80, luaB_coresume)
	 *
	 * What it does:
	 * Resumes coroutine from arg-1 using remaining args, returning status boolean
	 * plus coroutine results (or status false + error object).
	 */
	[[maybe_unused]] int luaB_coresume(lua_State* const state)
	{
		lua_State* const coroutineState = lua_tothread(state, 1);
		if (coroutineState == nullptr) {
			luaL_argerror(state, 1, "coroutine expected");
		}

		const int resumeResultCount = auxresume(lua_gettop(state) - 1, state, coroutineState);
		if (resumeResultCount >= 0) {
			lua_pushboolean(state, 1);
			lua_insert(state, -1 - resumeResultCount);
			return resumeResultCount + 1;
		}

		lua_pushboolean(state, 0);
		lua_insert(state, -2);
		return 2;
	}

	/**
	 * Address: 0x0090FB00 (FUN_0090FB00, luaB_auxwrap)
	 *
	 * What it does:
	 * Upvalue-bound coroutine wrapper: resumes coroutine with call args and
	 * propagates errors with traceback context.
	 */
	[[maybe_unused]] int luaB_auxwrap(lua_State* const state)
	{
		lua_State* const coroutineState = lua_tothread(state, lua_upvalueindex(1));
		const int resultCount = auxresume(lua_gettop(state), state, coroutineState);
		if (resultCount < 0) {
			if (lua_isstring(state, -1) != 0) {
				luaL_where(state, 1);
				lua_insert(state, -2);
				lua_concat(state, 2);
			}
			lua_error(state);
		}
		return resultCount;
	}

	/**
	 * Address: 0x0090FBB0 (FUN_0090FBB0, luaB_cowrap)
	 *
	 * What it does:
	 * Creates one coroutine from arg-1 Lua function and returns one closure that
	 * resumes it through `luaB_auxwrap`.
	 */
	[[maybe_unused]] int luaB_cowrap(lua_State* const state)
	{
		lua_State* const newThread = lua_newthread(state);
		if (lua_type(state, 1) != LUA_TFUNCTION) {
			luaL_argerror(state, 1, "Lua function expected");
		}

		lua_pushvalue(state, 1);
		lua_xmove(state, newThread, 1);
		lua_pushcclosure(state, luaB_auxwrap, 1);
		return 1;
	}

	/**
	 * Address: 0x0090F510 (FUN_0090F510, luaB_assert)
	 *
	 * What it does:
	 * Validates arg-1 presence/truthiness, raises Lua assertion error with
	 * optional arg-2 message, and returns arg-1 as the only result on success.
	 */
	[[maybe_unused]] int luaB_assert(lua_State* const state)
	{
		luaL_checkany(state, 1);
		if (lua_toboolean(state, 1) == 0) {
			const char* const message = luaL_optlstring(state, 2, "assertion failed!", nullptr);
			luaL_error(state, "%s", message);
		}

		lua_settop(state, 1);
		return 1;
	}

	/**
	 * Address: 0x0090EEF0 (FUN_0090EEF0, luaB_setmetatable)
	 *
	 * What it does:
	 * Sets one table metatable after validating arg-2 type (`nil|table`) and
	 * rejecting protected `__metatable` lanes.
	 */
	[[maybe_unused]] int luaB_setmetatable(lua_State* const state)
	{
		const int metatableType = lua_type(state, 2);
		luaL_checktype(state, 1, LUA_TTABLE);

		if (metatableType != LUA_TNIL && metatableType != LUA_TTABLE) {
			luaL_argerror(state, 2, "nil or table expected");
		}

		if (luaL_getmetafield(state, 1, "__metatable") != 0) {
			luaL_error(state, "cannot change a protected metatable");
		}

		lua_settop(state, 2);
		lua_setmetatable(state, 1);
		return 1;
	}

	/**
	 * Address: 0x0090F600 (FUN_0090F600, luaB_newproxy)
	 *
	 * What it does:
	 * Creates one proxy userdata lane and optionally binds/validates its
	 * metatable against the base-lib proxy registry upvalue.
	 */
	[[maybe_unused]] int luaB_newproxy(lua_State* const state)
	{
		lua_settop(state, 1);

		gpg::RRef proxyRef{};
		(void)lua_newuserdata_ref(&proxyRef, state, nullptr);

		if (lua_toboolean(state, 1) == 0) {
			return 1;
		}

		if (lua_type(state, 1) == LUA_TBOOLEAN) {
			lua_newtable(state);
			lua_pushvalue(state, -1);
			lua_pushboolean(state, 1);
			lua_rawset(state, lua_upvalueindex(1));
		} else {
			const bool hasMetaTable = (lua_getmetatable(state, 1) != 0);
			bool isKnownProxy = false;
			if (hasMetaTable) {
				lua_rawget(state, lua_upvalueindex(1));
				isKnownProxy = (lua_toboolean(state, -1) != 0);
				lua_settop(state, -2);
			}

			if (!hasMetaTable || !isKnownProxy) {
				luaL_argerror(state, 1, "boolean or proxy expected");
			}

			(void)lua_getmetatable(state, 1);
		}

		lua_setmetatable(state, 2);
		return 1;
	}

	/**
	 * Address: 0x0090A8C0 (FUN_0090A8C0, LS_LOG)
	 *
	 * What it does:
	 * Implements Lua `LOG`/`_ALERT` by applying `tostring` to each argument,
	 * joining with tab separators, and forwarding the final text to gpg logging.
	 */
	[[maybe_unused]] int LS_LOG(lua_State* const state)
	{
		Ensure(state != nullptr, "state");

		const int argumentCount = lua_gettop(state);
		lua_pushstring(state, "tostring");
		lua_gettable(state, LUA_GLOBALSINDEX);

		std::ostringstream messageBuilder{};
		for (int argumentIndex = 1; argumentIndex <= argumentCount; ++argumentIndex) {
			lua_pushvalue(state, -1);
			lua_pushvalue(state, argumentIndex);
			lua_call(state, 1, 1);

			const char* const convertedText = lua_tostring(state, -1);
			if (convertedText == nullptr) {
				luaL_error(state, "`tostring' must return a string to `print'");
				return 0;
			}

			if (argumentIndex > 1) {
				messageBuilder << '\t';
			}
			messageBuilder << convertedText;

			lua_settop(state, -2);
		}

		msvc8::string message{};
		message.assign_owned(messageBuilder.str());
		gpg::LogMessage(gpg::LogSeverity::Info, message);
		return 0;
	}

	/**
	 * Address: 0x0090AF50 (FUN_0090AF50)
	 *
	 * What it does:
	 * Writes one dumped Lua chunk block into an output FILE stream and reports
	 * boolean success expected by this build's `lua_dump` path.
	 */
	[[maybe_unused]] int LS_dump_FileChunkWriter(
		lua_State* const,
		const void* const buffer,
		const size_t elementSize,
		void* const streamUserData
	)
	{
		std::FILE* const output = static_cast<std::FILE*>(streamUserData);
		return (output != nullptr && std::fwrite(buffer, elementSize, 1u, output) == 1u) ? 1 : 0;
	}

	/**
	 * Address: 0x0090AF80 (FUN_0090AF80, LS_import)
	 *
	 * What it does:
	 * Implements legacy `import` fallback for this runtime lane by returning
	 * false on the Lua stack.
	 */
	[[maybe_unused]] int LS_import(lua_State* const state)
	{
		Ensure(state != nullptr, "state");
		Ensure(state->stateUserData != nullptr, "state->stateUserData");

		lua_State* const cstate = state->stateUserData->m_state;
		lua_pushboolean(cstate, 0);
		(void)lua_gettop(cstate);
		return 1;
	}

	/**
	 * Address: 0x0090AFB0 (FUN_0090AFB0, LS_dump)
	 *
	 * What it does:
	 * Loads one Lua source file, dumps the compiled chunk to output file path,
	 * and returns success/failure boolean on the Lua stack.
	 */
	[[maybe_unused]] int LS_dump(lua_State* const state)
	{
		Ensure(state != nullptr, "state");
		Ensure(state->stateUserData != nullptr, "state->stateUserData");

		LuaState* const luaState = state->stateUserData;
		lua_State* const cstate = luaState->m_state;

		LuaStackObject sourcePathArg(luaState, 1);
		const char* const sourcePath = lua_tostring(cstate, 1);
		if (sourcePath == nullptr) {
			LuaStackObject::TypeError(&sourcePathArg, "string");
		}

		LuaStackObject outputPathArg(luaState, 2);
		const char* const outputPath = lua_tostring(cstate, 2);
		if (outputPath == nullptr) {
			LuaStackObject::TypeError(&outputPathArg, "string");
		}

		if (luaL_loadfile(cstate, sourcePath) != 0) {
			lua_pushboolean(cstate, 0);
			(void)lua_gettop(cstate);
			return 1;
		}

		std::FILE* const output = std::fopen(outputPath, "wb");
		if (output != nullptr) {
			(void)lua_dump(cstate, LS_dump_FileChunkWriter, output);
			std::fclose(output);
			lua_pushboolean(cstate, 1);
			(void)lua_gettop(cstate);
		} else {
			lua_pushboolean(cstate, 0);
			(void)lua_gettop(cstate);
		}
		return 1;
	}

	/**
	 * Address: 0x0090B0D0 (FUN_0090B0D0, ScriptFunctionsRegister)
	 *
	 * What it does:
	 * Registers script-global helper lanes (`import`, `LuaDumpBinary`) on the
	 * active Lua globals table.
	 */
	[[maybe_unused]] void ScriptFunctionsRegister(LuaState* const state)
	{
		Ensure(state != nullptr, "state");
		LuaObject globals = state->GetGlobals();
		globals.Register("import", LS_import, 0);
		globals.Register("LuaDumpBinary", LS_dump, 0);
	}

	unsigned int HashLuaString(const char* key, const unsigned int length)
	{
		unsigned int hash = length;
		const unsigned int step = (hash >> 5U) + 1U;
		for (unsigned int i = length; i >= step; i -= step) {
			hash ^= (hash >> 2U) + (hash << 5U) + static_cast<unsigned char>(key[i - 1U]);
		}
		return hash;
	}

	const TString* FindInternedString(lua_State* state, const char* key)
	{
		Ensure(state != nullptr && state->l_G != nullptr, "state != nullptr && state->l_G != nullptr");
		Ensure(key != nullptr, "key");

		const stringtable& strings = state->l_G->strt;
		if (strings.hash == nullptr || strings.size <= 0) {
			return nullptr;
		}

		const unsigned int keyLength = static_cast<unsigned int>(std::strlen(key));
		const unsigned int hash = HashLuaString(key, keyLength);
		GCObject* current = strings.hash[hash & static_cast<unsigned int>(strings.size - 1)];
		while (current != nullptr) {
			if (current->gch.tt == LUA_TSTRING) {
				const auto* candidate = reinterpret_cast<const TString*>(current);
				if (candidate->len == static_cast<size_t>(keyLength)
					&& std::memcmp(candidate->str, key, static_cast<size_t>(keyLength)) == 0) {
					return candidate;
				}
			}
			current = current->gch.next;
		}

		return nullptr;
	}

	TObject CaptureStackValue(lua_State* state, const int index)
	{
		lua_pushvalue(state, index);
		const TObject value = *(state->top - 1);
		lua_pop(state, 1);
		return value;
	}

	void PushTObject(lua_State* state, const TObject& object)
	{
		switch (object.tt) {
			case LUA_TNIL:
				lua_pushnil(state);
				return;
			case LUA_TBOOLEAN:
				lua_pushboolean(state, object.value.b ? 1 : 0);
				return;
			case LUA_TNUMBER:
				lua_pushnumber(state, object.value.n);
				return;
			case LUA_TSTRING: {
				const auto* str = static_cast<const TString*>(object.value.p);
				lua_pushstring(state, str ? str->str : "");
				return;
			}
			default:
				break;
		}

		*state->top = object;
		if (state->top >= state->ci->top) {
			lua_checkstack(state, 1);
		}
		state->top += 1;
	}

	void RebindToState(LuaObject& object, LuaState* state)
	{
		Ensure(state != nullptr, "state");
		const LuaState* root = state->m_rootState ? state->m_rootState : state;
		if (root == object.m_state) {
			return;
		}

		if (object.m_state) {
			*object.m_prev = object.m_next;
			object.m_next->m_prev = object.m_prev;
			object.m_object.tt = LUA_TNIL;
		}

		object.AddToUsedList(state);
	}
}

extern "C"
{
	/**
	 * Address: 0x0090D260 (FUN_0090D260, lua_settable)
	 *
	 * What it does:
	 * Resolves one Lua API table target at `idx`, performs one table write
	 * using top-2 key/value stack lanes, then pops those two lanes.
	 */
	void lua_settable(lua_State* const state, const int idx)
	{
		TObject* object = nullptr;
		if (idx <= 0) {
			object = luaA_index(state, idx);
		} else {
			object = &state->base[idx - 1];
		}

		luaV_settable(state, object, state->top - 2, state->top - 1);
		state->top -= 2;
	}
}

extern "C"
{
	int _errorfb(lua_State* L, int level);
}

/**
 * Address: 0x00911E90 (FUN_00911E90, errorfb)
 *
 * What it does:
 * Calls core traceback formatter with default skip level 1.
 */
extern "C" int errorfb(lua_State* const state)
{
	return _errorfb(state, 1);
}

/**
 * Address: 0x00911EA0 (FUN_00911EA0, lua_traceback)
 *
 * What it does:
 * Pushes message text and then runs core traceback formatter at given level.
 */
extern "C" int lua_traceback(lua_State* const state, const char* const message, const int level)
{
	lua_pushstring(state, message);
	return _errorfb(state, level);
}

namespace
{
	const luaL_reg kLuaDebugLibrary[] = {
		{"getinfo", &LuaDebugGetInfo},
		{"getlocal", &LuaDebugGetLocal},
		{"setlocal", &LuaDebugSetLocal},
		{"getupvalue", &LuaDebugGetUpvalue},
		{"setupvalue", &LuaDebugSetUpvalue},
		{"sethook", &LuaDebugSetHook},
		{"gethook", &LuaDebugGetHook},
		{"debug", &LuaDebugConsole},
		{"traceback", &errorfb},
		{"listcode", &LuaDebugListCode},
		{"listk", &LuaDebugListConstants},
		{"listlocals", &LuaDebugListLocals},
		{"allobjects", &LuaDebugAllObjects},
		{"allocinfo", &LuaDebugAllocInfo},
		{"trackallocations", &LuaDebugTrackAllocations},
		{"allocatedsize", &LuaDebugAllocatedSize},
		{"profiledata", &LuaDebugProfileData},
		{nullptr, nullptr}
	};
}

/**
 * Address: 0x009124C0 (FUN_009124C0, luaopen_debug)
 *
 * What it does:
 * Opens the Lua debug library table, installs `_TRACEBACK` in globals, and
 * binds it to the recovered `errorfb` traceback helper.
 */
int luaopen_debug(lua_State* const state)
{
	luaL_openlib(state, "debug", kLuaDebugLibrary, 0);
	lua_pushlstring(state, "_TRACEBACK", 10u);
	lua_pushcclosure(state, errorfb, 0);
	lua_settable(state, LUA_GLOBALSINDEX);
	return 1;
}

/**
 * Address: 0x00912560 (FUN_00912560, lua_sethook)
 *
 * What it does:
 * Installs or clears VM debug hook callback/mask/count lanes in `global_State`.
 */
int lua_sethook(lua_State* const state, lua_Hook hook, int mask, const int count)
{
	if (hook == nullptr || mask == 0) {
		mask = 0;
		hook = nullptr;
	}

	global_State* const globalState = state->l_G;
	globalState->hook = hook;
	globalState->basehookcount = count;
	globalState->hookcount = globalState->basehookcount;
	globalState->hookmask = static_cast<lu_byte>(mask);
	return 1;
}

/**
 * Address: 0x009125B0 (FUN_009125B0, lua_gethook)
 *
 * What it does:
 * Returns currently installed VM debug hook callback pointer.
 */
lua_Hook lua_gethook(lua_State* const state)
{
	return state->l_G->hook;
}

/**
 * Address: 0x009125C0 (FUN_009125C0, lua_gethookmask)
 *
 * What it does:
 * Returns active VM debug hook mask bitfield.
 */
int lua_gethookmask(lua_State* const state)
{
	return state->l_G->hookmask;
}

/**
 * Address: 0x009125D0 (FUN_009125D0, lua_gethookcount)
 *
 * What it does:
 * Returns base hook countdown reload value.
 */
int lua_gethookcount(lua_State* const state)
{
	return state->l_G->basehookcount;
}

/**
 * Address: 0x009072A0 (FUN_009072A0, LuaPlus::LuaObject::LuaObject)
 *
 * What it does:
 * Initializes an empty LuaObject with null list links/state and NIL payload.
 */
LuaObject::LuaObject()
	: m_next(nullptr),
	  m_prev(nullptr),
	  m_state(nullptr),
	  m_object()
{
}

/**
 * Address: 0x005280D0 (FUN_005280D0, ??0LuaObject@LuaPlus@@QAE@@Z)
 *
 * What it does:
 * Casts one raw C Lua state pointer to the owning `LuaState` wrapper and
 * forwards construction to the stack-lane constructor with index `-1`.
 */
LuaObject::LuaObject(lua_State* const state)
	: LuaObject(LuaState::CastState(state), -1)
{
}

LuaObject::LuaObject(LuaState* state)
	: LuaObject()
{
	AddToUsedList(state);
	m_object.tt = LUA_TNIL;
}

LuaObject::LuaObject(LuaState* state, const int32_t stackIndex)
	: LuaObject()
{
	Ensure(state != nullptr, "state");
	const TObject stackObject = CaptureStackValue(state->GetCState(), stackIndex);
	AddToUsedObjectList(state, const_cast<TObject*>(&stackObject));
}

/**
 * Address: 0x009089F0 (FUN_009089F0, LuaPlus::LuaObject::LuaObject)
 *
 * What it does:
 * Binds this object to one caller-provided raw `TObject` lane and inserts it
 * into the owning root-state used-object list.
 */
LuaObject::LuaObject(LuaState* state, TObject* obj)
	: LuaObject()
{
	Ensure(obj != nullptr, "obj");
	AddToUsedObjectList(state, obj);
}

/**
 * Address: 0x00908A70 (FUN_00908A70, ??0LuaObject@LuaPlus@@QAE@ABVLuaStackObject@1@@Z)
 *
 * What it does:
 * Initializes this object from one stack slot and links it into the root
 * used-object list of the source stack-object state.
 */
LuaObject::LuaObject(const LuaStackObject& stackObject)
{
	m_object.tt = LUA_TNIL;
	TObject* const stackValue = luaA_index(stackObject.m_state->m_state, stackObject.m_stackIndex);
	AddToUsedObjectList(stackObject.m_state, stackValue);
}

/**
 * Address: 0x00908A40 (FUN_00908A40, LuaPlus::LuaObject::LuaObject)
 *
 * What it does:
 * Initializes an empty object, then mirrors the source LuaObject by
 * linking into the same root-state used-object list when bound.
 */
LuaObject::LuaObject(const LuaObject& other)
	: LuaObject()
{
	if (other.m_state) {
		AddToUsedObjectList(other.m_state, const_cast<TObject*>(&other.m_object));
	}
}

/**
 * Address: 0x00908AB0 (FUN_00908AB0, LuaPlus::LuaObject::operator=)
 *
 * What it does:
 * Unlinks current state-list ownership (when bound), then binds to `other`
 * by re-inserting this object into the source state's used-object list.
 */
LuaObject& LuaObject::operator=(const LuaObject& other)
{
	if (this == &other) {
		return *this;
	}

	if (m_state) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
		m_object.tt = LUA_TNIL;
	}

	if (other.m_state) {
		AddToUsedObjectList(other.m_state, const_cast<TObject*>(&other.m_object));
	} else {
		m_state = nullptr;
		m_next = nullptr;
		m_prev = nullptr;
	}
	return *this;
}

/**
 * Address: 0x00908B00 (FUN_00908B00, LuaPlus::LuaObject::operator=)
 *
 * What it does:
 * Unlinks current state-list ownership (when bound), resolves one stack slot
 * TValue lane from `stackObject`, then re-links this object into that state's
 * used-object list.
 */
LuaObject& LuaObject::operator=(const LuaStackObject& stackObject)
{
	if (m_state) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
		m_object.tt = LUA_TNIL;
	}

	TObject* const stackValue = luaA_index(stackObject.m_state->m_state, stackObject.m_stackIndex);
	AddToUsedObjectList(stackObject.m_state, stackValue);
	return *this;
}

/**
 * Address: 0x009075D0 (FUN_009075D0, LuaPlus::LuaObject::~LuaObject)
 * Address: 0x005D0A90 (FUN_005D0A90, LuaObject::j_Dtr_6 thunk)
 * Address: 0x00624120 (FUN_00624120, LuaObject::j_Dtr_7 thunk)
 * Address: 0x00BA2E8B (FUN_00BA2E8B, LuaObject::j_Dtr_9 thunk)
 *
 * What it does:
 * Unlinks this object from the owning state's intrusive used-object list
 * when bound and clears the tagged value to nil.
 */
LuaObject::~LuaObject()
{
	if (m_state) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
		m_object.tt = LUA_TNIL;
	}
}

/**
 * Address: 0x005D0A90 (FUN_005D0A90, LuaObject::j_Dtr_6 thunk)
 *
 * What it does:
 * Forwards one non-deleting thunk lane to `LuaObject::~LuaObject`.
 */
[[maybe_unused]] void LuaObjectDtrThunk6(LuaObject* const object)
{
	object->~LuaObject();
}

/**
 * Address: 0x00624120 (FUN_00624120, LuaObject::j_Dtr_7 thunk)
 *
 * What it does:
 * Forwards one non-deleting thunk lane to `LuaObject::~LuaObject`.
 */
[[maybe_unused]] void LuaObjectDtrThunk7(LuaObject* const object)
{
	object->~LuaObject();
}

/**
 * Address: 0x0090AC10 (FUN_0090AC10, LuaPlus::LuaState::LuaState)
 *
 * What it does:
 * Initializes root-state ownership lanes, creates a fresh C `lua_State`,
 * binds userdata/GC callbacks, and runs standard-library init.
 */
LuaState::LuaState(const StandardLibraries initStandardLibrary)
	: m_state(nullptr),
	  m_luaTask(nullptr),
	  m_ownState(0),
	  m_pad9{0, 0, 0},
	  m_threadObj(),
	  m_rootState(this),
	  m_headObject{nullptr, nullptr},
	  m_tailObject{nullptr, nullptr}
{
	m_state = lua_open();
	m_ownState = 1;
	lua_setusergcfunction(m_state, reinterpret_cast<void(__cdecl*)(void*)>(&LuaPlusGCFunction));
	lua_setstateuserdata(m_state, this);

	m_headObject.m_next = reinterpret_cast<LuaObject*>(&m_tailObject);
	m_tailObject.m_prev = reinterpret_cast<LuaObject**>(&m_headObject.m_next);
	m_headObject.m_prev = nullptr;
	m_tailObject.m_next = nullptr;
	m_luaTask = nullptr;

	Init(initStandardLibrary);
}

/**
 * Address: 0x0090AAD0 (FUN_0090AAD0, LuaPlus::LuaState::Init)
 *
 * What it does:
 * Initializes selected standard libraries and script helper globals, then
 * always registers `LOG` and `_ALERT` on the global table.
 */
void LuaState::Init(const StandardLibraries initStandardLibrary)
{
	if (initStandardLibrary != LIB_NONE) {
		lua_State* const state = m_state;
		const int previousTop = lua_gettop(state);

		luaopen_base(state);
		luaopen_table(state);
		if (initStandardLibrary == LIB_OSIO) {
			luaopen_io(state);
		}
		luaopen_serialize(state);
		luaopen_string(state);
		luaopen_math(state);
		luaopen_debug(state);
		if (initStandardLibrary == LIB_OSIO) {
			luaopen_loadlib(state);
		}

		ScriptFunctionsRegister(this);
		lua_settop(state, previousTop);
	}

	LuaObject globals = GetGlobals();
	globals.Register("LOG", LS_LOG, 0);

	LuaObject alertGlobals = GetGlobals();
	alertGlobals.Register("_ALERT", LS_LOG, 0);
}

/**
 * Address: 0x0090A520 (FUN_0090A520, LuaPlus::LuaState::LuaState)
 *
 * What it does:
 * Creates one coroutine thread state under the provided root wrapper, captures
 * the pushed thread object into `m_threadObj`, then binds `stateUserData`.
 */
LuaState::LuaState(LuaState* const parentState)
	: m_state(nullptr),
	  m_luaTask(nullptr),
	  m_ownState(0),
	  m_pad9{0, 0, 0},
	  m_threadObj(),
	  m_rootState(parentState ? parentState->m_rootState : nullptr),
	  m_headObject{nullptr, nullptr},
	  m_tailObject{nullptr, nullptr}
{
	Ensure(parentState != nullptr, "parentState");
	Ensure(m_rootState != nullptr, "parentState->m_rootState");
	Ensure(m_rootState->m_state != nullptr, "parentState->m_rootState->m_state");

	m_state = lua_newthread(m_rootState->m_state);
	Ensure(m_state != nullptr, "lua_newthread");

	const LuaStackObject threadStackObject(m_rootState, lua_gettop(m_rootState->m_state));
	m_threadObj = LuaObject(threadStackObject);
	lua_settop(m_rootState->m_state, -2);

	m_state->stateUserData = this;
}

/**
 * Address: 0x0090A600 (FUN_0090A600, LuaPlus::LuaState::~LuaState)
 *
 * What it does:
 * Clears root-owned live objects, detaches Lua state userdata, closes owned
 * C-state when required, then lets member destructors run.
 */
LuaState::~LuaState()
{
	if (m_rootState == this) {
		const auto* const tail = reinterpret_cast<const LuaObject*>(&m_tailObject);
		while (m_headObject.m_next != tail) {
			LuaObject* const live = m_headObject.m_next;
			Ensure(live != nullptr, "live");
			live->Reset();
		}
	}

	if (m_state != nullptr) {
		m_state->stateUserData = nullptr;
		if (m_ownState != 0) {
			lua_close(m_state);
		}
	}
}

/**
 * Address: 0x004C99B0 (FUN_004C99B0, LuaState scalar deleting destructor thunk)
 *
 * What it does:
 * Runs `LuaState` non-deleting destruction, then conditionally releases the
 * object storage when the scalar-delete flag bit is set.
 */
[[maybe_unused]] LuaState* DestroyLuaStateWithDeleteFlag(LuaState* const state, const std::uint8_t deleteFlag)
{
	state->~LuaState();
	if ((deleteFlag & 1u) != 0u) {
		::operator delete(state);
	}
	return state;
}

/**
 * Address: 0x0090A7D0 (FUN_0090A7D0, LuaPlus::LuaState::SetState)
 *
 * What it does:
 * Binds this wrapper to an existing C `lua_State`, sets root thread/sentinel
 * ownership for main-thread lanes, and updates `stateUserData`.
 */
void LuaState::SetState(lua_State* const state)
{
	if (m_state != nullptr || m_rootState != nullptr) {
		throw LuaAssertion("m_state==NULL && m_rootState==NULL");
	}

	if (state->stateUserData != nullptr) {
		throw LuaAssertion("L->stateUserData == NULL");
	}

	lua_State* const mainThread = state->l_G->mainthread;
	if (mainThread == state) {
		m_rootState = this;
		m_state = state;
		m_ownState = 1;
		m_headObject.m_prev = nullptr;
		m_headObject.m_next = reinterpret_cast<LuaObject*>(&m_tailObject);
		m_tailObject.m_prev = reinterpret_cast<LuaObject**>(&m_headObject.m_next);
		m_tailObject.m_next = nullptr;
		m_state->l_G->userGCFunction = &LuaPlusGCFunction;
		m_state->stateUserData = this;
		return;
	}

	m_rootState = mainThread->stateUserData;
	if (m_rootState == nullptr) {
		throw LuaAssertion("m_rootState");
	}

	m_state = state;
	m_threadObj.AssignThread(this);
	m_state->stateUserData = this;
}

/**
 * Address: 0x00921050 (FUN_00921050, lua_State::MemberSerialize)
 *
 * What it does:
 * Serializes raw lua_State stack/callframe/global/upvalue lanes for archive
 * persistence.
 */
/**
 * Address: 0x00921480 (FUN_00921480, func_SerializeNameLuaObject)
 *
 * What it does:
 * Resolves optional object-name indirection from global table
 * `"__serialize_name_for_object"` and returns a TString pointer when present.
 */
[[nodiscard]] const TObject* ResolveSerializedObjectNameEntry(lua_State* state, TString* key);

[[nodiscard]] TString* ResolveSerializedNameForLuaObject(lua_State* const state, const Value value)
{
	TString* const serializeMapName = luaS_newlstr(state, "__serialize_name_for_object", 0x1Bu);
	const TObject* const serializeMapObject = luaH_getstr(static_cast<Table*>(state->_gt.value.p), serializeMapName);
	if (serializeMapObject->tt != LUA_TTABLE) {
		return nullptr;
	}

	const auto* const gcObject = static_cast<const GCObject*>(value.p);
	if (gcObject == nullptr) {
		return nullptr;
	}

	TObject lookupKey{};
	lookupKey.tt = static_cast<int>(gcObject->gch.tt);
	lookupKey.value = value;

	const TObject* const lookupResult = luaH_get(static_cast<Table*>(serializeMapObject->value.p), &lookupKey);
	if (lookupResult->tt == LUA_TNIL) {
		return nullptr;
	}

	if (lookupResult->tt != LUA_TSTRING) {
		throw gpg::SerializationError("__serialize_name_for_object table must contain only string values");
	}

	return static_cast<TString*>(lookupResult->value.p);
}

/**
 * Address: 0x009216D0 (FUN_009216D0, TObject::MemberSerialize)
 *
 * What it does:
 * Serializes one tagged Lua value lane with optional named-object indirection
 * and type-specific payload dispatch.
 */
void TObject::MemberSerialize(
	gpg::WriteArchive* const archive,
	TObject* const object,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");
	Ensure(ownerRef != nullptr, "ownerRef");

	if (object->tt > LUA_TSTRING) {
		lua_State* const ownerState = ownerRef->TryUpcastLuaThreadState();
		if (TString* const serializedName = ResolveSerializedNameForLuaObject(ownerState, object->value);
			serializedName != nullptr) {
			archive->WriteInt(-2);
			archive->WriteTString(serializedName, *ownerRef);
			return;
		}
	}

	archive->WriteInt(object->tt);
	switch (object->tt) {
	case LUA_TBOOLEAN:
		archive->WriteInt(object->value.b);
		return;
	case LUA_TLIGHTUSERDATA:
		throw gpg::SerializationError("light userdata cannot be serialized");
	case LUA_TNUMBER:
		archive->WriteValue(&object->value, 0);
		return;
	case LUA_TSTRING:
		archive->WriteTString(static_cast<TString*>(object->value.p), *ownerRef);
		return;
	case LUA_TTABLE:
		archive->WriteTTable(static_cast<Table*>(object->value.p), *ownerRef);
		return;
	case LUA_CFUNCTION:
		archive->WriteCFunction(static_cast<CClosure*>(object->value.p), *ownerRef);
		return;
	case LUA_TFUNCTION:
		archive->WriteFunction(static_cast<LClosure*>(object->value.p), *ownerRef);
		return;
	case LUA_TUSERDATA:
		archive->WriteUserdata(static_cast<Udata*>(object->value.p), *ownerRef);
		return;
	case LUA_TTHREAD:
		archive->WriteTThread(static_cast<lua_State*>(object->value.p), *ownerRef);
		return;
	default:
		return;
	}
}

/**
 * Address: 0x009226F0 (FUN_009226F0, TObject::MemberDeserialize)
 *
 * What it does:
 * Deserializes one tagged Lua value lane with named-object lookup support and
 * type-specific payload dispatch.
 */
void TObject::MemberDeserialize(
	gpg::ReadArchive* const archive,
	TObject* const object,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");
	Ensure(ownerRef != nullptr, "ownerRef");

	int typeCode = LUA_TNIL;
	archive->ReadInt(&typeCode);
	switch (typeCode) {
	case -2: {
		lua_State* const ownerState = ownerRef->TryUpcastLuaThreadState();
		TString* serializedName = nullptr;
		(void)archive->ReadPointer_TString(&serializedName, ownerRef);

		const TObject* const resolvedObject = ResolveSerializedObjectNameEntry(ownerState, serializedName);
		if (resolvedObject->tt == LUA_TNIL) {
			throw gpg::SerializationError("Named script object not found");
		}

		*object = *resolvedObject;
		return;
	}

	case LUA_TNONE:
	case LUA_TNIL:
		object->tt = typeCode;
		object->value.p = nullptr;
		return;

	case LUA_TBOOLEAN: {
		int boolValue = 0;
		archive->ReadInt(&boolValue);
		object->tt = LUA_TBOOLEAN;
		object->value.b = boolValue;
		return;
	}

	case LUA_TLIGHTUSERDATA:
		throw gpg::SerializationError("light userdata cannot be serialized");

	case LUA_TNUMBER: {
		float numberValue = 0.0f;
		archive->ReadFloat(&numberValue);
		object->tt = LUA_TNUMBER;
		object->value.n = numberValue;
		return;
	}

	case LUA_TSTRING: {
		TString* stringValue = nullptr;
		(void)archive->ReadPointer_TString(&stringValue, ownerRef);
		object->tt = LUA_TSTRING;
		object->value.p = stringValue;
		return;
	}

	case LUA_TTABLE: {
		Table* tableValue = nullptr;
		(void)archive->ReadPointer_Table(&tableValue, ownerRef);
		object->tt = LUA_TTABLE;
		object->value.p = tableValue;
		return;
	}

	case LUA_CFUNCTION:
		throw gpg::SerializationError("C functions must be saved by name, not value");

	case LUA_TFUNCTION: {
		LClosure* functionValue = nullptr;
		(void)archive->ReadPointer_LClosure(&functionValue, ownerRef);
		object->tt = LUA_TFUNCTION;
		object->value.p = functionValue;
		return;
	}

	case LUA_TUSERDATA: {
		Udata* userdataValue = nullptr;
		(void)archive->ReadPointer_Udata(&userdataValue, ownerRef);
		object->tt = LUA_TUSERDATA;
		object->value.p = userdataValue;
		return;
	}

	case LUA_TTHREAD: {
		lua_State* threadValue = nullptr;
		(void)archive->ReadPointer_lua_State(&threadValue, ownerRef);
		object->tt = LUA_TTHREAD;
		object->value.p = threadValue;
		return;
	}

	default:
		throw gpg::SerializationError("Unknown type code for lua value");
	}
}

/**
 * Address: 0x00920DA0 (FUN_00920DA0, LClosure::MemberSerialize)
 *
 * What it does:
 * Serializes one closure's proto pointer, global-object lane, and upvalue
 * pointer array lanes.
 */
void LClosure::MemberSerialize(
	gpg::WriteArchive* const archive,
	LClosure* const object,
	const int,
	const gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	const gpg::RRef nullOwner{};
	const gpg::RRef& owner = ownerRef != nullptr ? *ownerRef : nullOwner;

	gpg::RRef protoRef{};
	(void)gpg::RRef_Proto(&protoRef, object->p);
	gpg::WriteRawPointer(archive, protoRef, gpg::TrackedPointerState::Unowned, owner);

	archive->Write(CachedType<TObject>(gLuaTObjectType), &object->g, owner);

	for (std::uint8_t upvalueIndex = 0; upvalueIndex < object->nupvalues; ++upvalueIndex) {
		gpg::RRef upvalueRef{};
		(void)gpg::RRef_UpVal(&upvalueRef, object->upvals[upvalueIndex]);
		gpg::WriteRawPointer(archive, upvalueRef, gpg::TrackedPointerState::Unowned, owner);
	}
}

/**
 * Address: 0x00920E40 (FUN_00920E40, Proto::MemberSerialize)
 *
 * What it does:
 * Serializes proto scalar metadata, constants/code/nested-proto lanes, and
 * debug name/source pointer lanes.
 */
void Proto::MemberSerialize(
	gpg::WriteArchive* const archive,
	Proto* const object,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	const gpg::RRef nullOwner{};
	const gpg::RRef& owner = ownerRef != nullptr ? *ownerRef : nullOwner;

	archive->WriteInt(object->sizeupvalues);
	archive->WriteInt(object->sizek);
	archive->WriteInt(object->sizecode);
	archive->WriteInt(object->sizelineinfo);
	archive->WriteInt(object->sizep);
	archive->WriteInt(object->sizelocvars);
	archive->WriteInt(object->lineDefined);
	archive->WriteUByte(object->nups);
	archive->WriteUByte(object->numparams);
	archive->WriteUByte(object->is_vararg);
	archive->WriteUByte(object->maxstacksize);

	for (int index = 0; index < object->sizek; ++index) {
		archive->Write(CachedType<TObject>(gLuaTObjectType), &object->k[index], owner);
	}

	archive->WriteBytes(reinterpret_cast<char*>(object->code), sizeof(Instruction) * static_cast<std::size_t>(object->sizecode));

	for (int index = 0; index < object->sizep; ++index) {
		gpg::RRef protoRef{};
		(void)gpg::RRef_Proto(&protoRef, object->p[index]);
		gpg::WriteRawPointer(archive, protoRef, gpg::TrackedPointerState::Unowned, owner);
	}

	for (int index = 0; index < object->sizelineinfo; ++index) {
		archive->WriteInt(object->lineinfo[index]);
	}

	for (int index = 0; index < object->sizelocvars; ++index) {
		gpg::RRef localNameRef{};
		(void)gpg::RRef_TString(&localNameRef, object->locvars[index].varname);
		gpg::WriteRawPointer(archive, localNameRef, gpg::TrackedPointerState::Unowned, owner);
		archive->WriteInt(object->locvars[index].startpc);
		archive->WriteInt(object->locvars[index].endpc);
	}

	for (int index = 0; index < object->nups; ++index) {
		gpg::RRef upvalueNameRef{};
		(void)gpg::RRef_TString(&upvalueNameRef, object->upvalues[index]);
		gpg::WriteRawPointer(archive, upvalueNameRef, gpg::TrackedPointerState::Unowned, owner);
	}

	gpg::RRef sourceRef{};
	(void)gpg::RRef_TString(&sourceRef, object->source);
	gpg::WriteRawPointer(archive, sourceRef, gpg::TrackedPointerState::Unowned, owner);
}

/**
 * Address: 0x00920530 (FUN_00920530, Table::MemberSerialize)
 *
 * What it does:
 * Serializes table metatable pointer lane, dense array payload lanes, and
 * non-empty hash key/value lanes.
 */
void Table::MemberSerialize(
	gpg::WriteArchive* const archive,
	Table* const object,
	const int,
	const gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");
	Ensure(ownerRef != nullptr, "ownerRef");

	gpg::RRef metatableRef{};
	(void)gpg::RRef_Table(&metatableRef, object->metatable);
	gpg::WriteRawPointer(archive, metatableRef, gpg::TrackedPointerState::Unowned, *ownerRef);

	const int hashNodeCount = 1 << object->lsizenode;
	int nonEmptyHashCount = 0;
	for (int hashIndex = 0; hashIndex < hashNodeCount; ++hashIndex) {
		if (object->node[hashIndex].i_val.tt != LUA_TNIL) {
			++nonEmptyHashCount;
		}
	}
	archive->WriteInt(nonEmptyHashCount);

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	for (int arrayIndex = 0; arrayIndex < object->sizearray; ++arrayIndex) {
		archive->Write(tObjectType, &object->array[arrayIndex], *ownerRef);
	}

	for (int hashIndex = 0; hashIndex < hashNodeCount; ++hashIndex) {
		Node* const node = &object->node[hashIndex];
		if (node->i_val.tt == LUA_TNIL) {
			continue;
		}

		archive->Write(tObjectType, &node->i_key, *ownerRef);
		archive->Write(tObjectType, &node->i_val, *ownerRef);
	}
}

/**
 * Address: 0x00922950 (FUN_00922950, Table::MemberDeserialize)
 *
 * What it does:
 * Deserializes table metatable pointer lane, dense-array element lanes, and
 * hashed key/value lanes under owner GC traversal lock.
 */
void Table::MemberDeserialize(
	gpg::ReadArchive* const archive,
	Table* const object,
	const int,
	const gpg::RRef& ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");
	Ensure(ownerState->l_G != nullptr, "ownerState->l_G");

	struct GlobalStateLockGuard
	{
		global_State* state;
		explicit GlobalStateLockGuard(global_State* const inState) : state(inState)
		{
			++state->gcTraversalLockDepth;
		}
		~GlobalStateLockGuard()
		{
			--state->gcTraversalLockDepth;
		}
	} lockGuard(ownerState->l_G);

	(void)archive->ReadPointer_Table(&object->metatable, &ownerRef);

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	int hashEntryCount = 0;
	archive->ReadInt(&hashEntryCount);

	for (int arrayIndex = 1; arrayIndex <= object->sizearray; ++arrayIndex) {
		TObject* const destinationSlot = luaH_setnum(ownerState, object, arrayIndex);
		archive->Read(tObjectType, destinationSlot, ownerRef);
	}

	for (int hashIndex = 0; hashIndex < hashEntryCount; ++hashIndex) {
		TObject key{};
		archive->Read(tObjectType, &key, ownerRef);
		TObject* const destinationSlot = luaH_set(ownerState, object, &key);
		archive->Read(tObjectType, destinationSlot, ownerRef);
	}
}

/**
 * Address: 0x009207E0 (FUN_009207E0, Udata::MemberSerialize)
 *
 * What it does:
 * Uses the owner Lua-thread lane as serialization context, writes userdata
 * metatable pointer as unowned tracked reference, then serializes userdata
 * payload through the stored runtime `RType`.
 */
void Udata::MemberSerialize(
	gpg::WriteArchive* const archive,
	Udata* const object,
	const int,
	gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");
	Ensure(ownerRef != nullptr, "ownerRef");

	lua_State* const ownerState = ownerRef->TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");
	Ensure(ownerState->l_G != nullptr, "ownerState->l_G");

	struct GlobalStateLockGuard
	{
		global_State* state;
		explicit GlobalStateLockGuard(global_State* const inState) : state(inState)
		{
			++state->gcTraversalLockDepth;
		}
		~GlobalStateLockGuard()
		{
			--state->gcTraversalLockDepth;
		}
	} lockGuard(ownerState->l_G);

	gpg::RRef metatableRef{};
	(void)gpg::RRef_Table(&metatableRef, object->metatable);
	gpg::WriteRawPointer(archive, metatableRef, gpg::TrackedPointerState::Unowned, *ownerRef);

	gpg::RType* const payloadType = reinterpret_cast<gpg::RType*>(object->len);
	const void* const payload = reinterpret_cast<const std::uint8_t*>(object) + sizeof(Udata);
	archive->Write(payloadType, payload, *ownerRef);
}

/**
 * Address: 0x00923170 (FUN_00923170, Udata::MemberDeserialize)
 *
 * What it does:
 * Deserializes userdata metatable pointer lane and typed payload bytes using
 * one owning Lua thread traversal lock lane from `ownerRef`.
 */
void Udata::MemberDeserialize(
	gpg::ReadArchive* const archive,
	Udata* const object,
	const int,
	const gpg::RRef& ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	lua_State* const ownerState = ownerRef.TryUpcastLuaThreadState();
	Ensure(ownerState != nullptr, "ownerState");
	Ensure(ownerState->l_G != nullptr, "ownerState->l_G");

	struct GlobalStateLockGuard
	{
		global_State* state;
		explicit GlobalStateLockGuard(global_State* const inState) : state(inState)
		{
			++state->gcTraversalLockDepth;
		}
		~GlobalStateLockGuard()
		{
			--state->gcTraversalLockDepth;
		}
	} lockGuard(ownerState->l_G);

	(void)archive->ReadPointer_Table(&object->metatable, &ownerRef);
	gpg::RType* const payloadType = reinterpret_cast<gpg::RType*>(object->len);
	void* const payload = reinterpret_cast<std::uint8_t*>(object) + sizeof(Udata);
	archive->Read(payloadType, payload, ownerRef);
}

/**
 * Address: 0x00922AB0 (FUN_00922AB0, LClosure::MemberDeserialize)
 *
 * What it does:
 * Deserializes prototype/global-object/upvalue pointer lanes for one Lua
 * closure object.
 */
void LClosure::MemberDeserialize(
	gpg::ReadArchive* const archive,
	LClosure* const object,
	const int,
	const gpg::RRef& ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	archive->ReadPointer_Proto(&object->p, &ownerRef);
	archive->Read(CachedType<TObject>(gLuaTObjectType), &object->g, ownerRef);

	UpVal** upvalueLane = object->upvals;
	for (std::uint8_t upvalueIndex = 0; upvalueIndex < object->nupvalues; ++upvalueIndex, ++upvalueLane) {
		archive->ReadPointer_UpVal(upvalueLane, &ownerRef);
	}
}

void lua_State::MemberSerialize(
	gpg::WriteArchive* const archive,
	lua_State* const state,
	const int,
	const gpg::RRef* const ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(state != nullptr, "state");

	const gpg::RRef nullOwner{};
	const gpg::RRef& owner = ownerRef != nullptr ? *ownerRef : nullOwner;

	TObject* const stackBase = state->stack;
	const int baseIndex = static_cast<int>(state->base - stackBase);
	const int topIndex = static_cast<int>(state->top - stackBase);

	archive->WriteInt(state->stacksize);
	archive->WriteInt(baseIndex);
	archive->WriteInt(topIndex);

	gpg::RType* const tObjectType = CachedType<TObject>(gLuaTObjectType);
	for (int index = 0; index < topIndex; ++index) {
		archive->Write(tObjectType, &stackBase[index], owner);
	}

	archive->WriteUShort(state->size_ci);
	const std::uint16_t currentCallInfoIndex = static_cast<std::uint16_t>(state->ci - state->base_ci);
	archive->WriteUShort(currentCallInfoIndex);

	for (std::uint16_t callInfoIndex = 0; callInfoIndex <= currentCallInfoIndex; ++callInfoIndex) {
		CallInfo* const callInfo = state->base_ci + callInfoIndex;

		archive->WriteInt(static_cast<int>(callInfo->base - stackBase));
		archive->WriteInt(static_cast<int>(callInfo->top - stackBase));
		archive->WriteInt(callInfo->state);
		archive->WriteInt(callInfo->tailcalls);

		if (callInfo->state < 3) {
			const TObject* const functionSlot = callInfo->base - 1;
			const auto* const closure = static_cast<const Closure*>(functionSlot->value.p);
			const Instruction* const codeBase = closure->l.p->code;
			archive->WriteInt(static_cast<int>(callInfo->savedpc - codeBase));
		}
	}

	archive->Write(tObjectType, &state->_gt, owner);

	for (GCObject* openUpval = state->openupval; openUpval != nullptr; openUpval = openUpval->gch.next) {
		UpVal* const upvalue = &openUpval->uv;
		archive->WriteInt(static_cast<int>(upvalue->v - stackBase));

		gpg::RRef upvalueRef{};
		(void)gpg::RRef_UpVal(&upvalueRef, upvalue);
		gpg::WriteRawPointer(archive, upvalueRef, gpg::TrackedPointerState::Unowned, owner);
	}

	archive->WriteInt(-1);
}

/**
 * Address: 0x0090B8F0 (FUN_0090B8F0, LuaPlus::LuaState::MemberSerialize)
 *
 * What it does:
 * Serializes root/current LuaState pointer lanes for archive ownership
 * restoration.
 */
void LuaState::MemberSerialize(gpg::WriteArchive* const archive, LuaState* const state)
{
	Ensure(archive != nullptr, "archive");
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState != nullptr, "state->m_rootState");

	gpg::RRef rootStateRef{};
	(void)gpg::RRef_LuaState(&rootStateRef, state->m_rootState);
	gpg::WriteRawPointer(archive, rootStateRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

	gpg::RRef currentStateRef{};
	(void)gpg::RRef_lua_State(&currentStateRef, state->m_state);
	gpg::WriteRawPointer(archive, currentStateRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
}

LuaState* LuaState::GetActiveState()
{
	if (!m_state || !m_state->l_G || !m_state->l_G->lstate) {
		return nullptr;
	}
	return m_state->l_G->lstate->stateUserData;
}

lua_State* LuaState::GetActiveCState()
{
	if (!m_state || !m_state->l_G) {
		return nullptr;
	}
	return m_state->l_G->lstate;
}

lua_State* LuaState::GetCState() const
{
	return m_state;
}

/**
 * Address: 0x1000A4A0 (?GetGlobals@LuaState@LuaPlus@@QAE?AVLuaObject@2@XZ)
 */
LuaObject LuaState::GetGlobals()
{
	if (!m_state) {
		return {};
	}

	return LuaObject(this, LUA_GLOBALSINDEX);
}

/**
 * Address: 0x0090A510 (FUN_0090A510, LuaPlus::LuaState::CastState)
 *
 * What it does:
 * Returns the C++ wrapper pointer stored in `lua_State::stateUserData`.
 */
LuaState* LuaState::CastState(lua_State* const state)
{
	return state->stateUserData;
}

/**
 * Address: 0x10008F20 (?GetGlobal@LuaState@LuaPlus@@QAE?AVLuaObject@2@PBD@Z)
 */
LuaObject LuaState::GetGlobal(const char* name)
{
	LuaObject globals = GetGlobals();
	return globals[name ? name : ""];
}

LuaState* LuaState::GetRootState()
{
	return m_rootState;
}

const LuaState* LuaState::GetRootState() const
{
	return m_rootState;
}

const LuaObject* LuaState::GetThreadObject() const
{
	return &m_threadObj;
}

/**
 * Address: 0x004CCA10 (FUN_004CCA10, LuaPlus::LuaState::PushNil)
 *
 * What it does:
 * Pushes nil to this state's Lua stack and returns a stack-object view for
 * the pushed value.
 */
LuaStackObject LuaState::PushNil()
{
	lua_pushnil(m_state);
	return LuaStackObject(this, lua_gettop(m_state));
}

/**
 * Address: 0x004CCA30 (FUN_004CCA30, LuaPlus::LuaState::PushNumber)
 *
 * What it does:
 * Pushes one numeric value to this state's Lua stack and returns a stack view
 * for the pushed value.
 */
LuaStackObject LuaState::PushNumber(const float n)
{
	lua_pushnumber(m_state, n);
	return LuaStackObject(this, lua_gettop(m_state));
}

LuaStackObject LuaState::Stack(const int32_t index)
{
	return LuaStackObject(this, index);
}

/**
 * Address: 0x0090BFB0 (FUN_0090BFB0, LuaPlus::LuaState::CheckString)
 *
 * What it does:
 * Validates stack slot `index` as string/coercible and returns Lua's internal
 * string pointer + optional byte length.
 */
const char* LuaState::CheckString(const int32_t index, size_t* const lengthOut)
{
	return luaL_checklstring(m_state, index, lengthOut);
}

/**
 * Address: 0x0090C170 (FUN_0090C170, LuaPlus::LuaState::CheckAny)
 *
 * What it does:
 * Raises a Lua argument error when stack slot `index` is missing.
 */
void LuaState::CheckAny(const int32_t index)
{
	luaL_checkany(m_state, index);
}

int32_t LuaState::GetTop() const
{
	return m_state ? lua_gettop(m_state) : 0;
}

bool LuaState::IsRootState() const
{
	return m_rootState == this;
}

bool LuaState::IsSuspended() const
{
	// lua_suspended() is not surfaced in this SDK build yet.
	return false;
}

/**
 * Address: 0x0090C1D0 (FUN_0090C1D0, ?Error@LuaState@LuaPlus@@QAAHPBDZZ)
 *
 * What it does:
 * Formats one varargs error string on the Lua stack and raises `lua_error`.
 */
void LuaState::Error(LuaState* const state, const char* const format, ...)
{
	va_list args;
	va_start(args, format);
	lua_pushvfstring(state->m_state, format, args);
	va_end(args);
	lua_error(state->m_state);
}

/**
 * Address: 0x00415490 (FUN_00415490, LuaPlus::LuaStackObject::LuaStackObject)
 */
LuaStackObject::LuaStackObject(LuaState* state, const int32_t stackIndex)
	: m_state(state),
	  m_stackIndex(stackIndex)
{
}

/**
 * Address: 0x00456AE0 (FUN_00456AE0, sub_456AE0)
 *
 * LuaState *,char const *
 *
 * What it does:
 * Pushes one C-string onto the Lua state stack and returns a stack-object
 * view for the pushed slot.
 */
LuaStackObject LuaPlus::PushStringAndCaptureStackObject(LuaState* const state, const char* const value)
{
	lua_pushstring(state->m_state, value);
	return LuaStackObject(state, lua_gettop(state->m_state));
}

bool LuaStackObject::IsNil() const
{
	return !m_state || !m_state->GetCState() || lua_type(m_state->GetCState(), m_stackIndex) == LUA_TNIL;
}

/**
 * Address: 0x004154B0 (FUN_004154B0, LuaPlus::LuaStackObject::TypeError)
 *
 * What it does:
 * Raises the standard Lua bad-argument error for the current stack slot.
 */
void LuaStackObject::TypeError(const char* const expectedType) const
{
	luaL_argerror(m_state->GetCState(), m_stackIndex, expectedType ? expectedType : "value");
}

void LuaStackObject::TypeError(const char* const expectedType, const int32_t) const
{
	TypeError(expectedType);
}

void LuaStackObject::TypeError(LuaStackObject* const self, const char* const expectedType)
{
	if (self != nullptr) {
		self->TypeError(expectedType);
	}
}

/**
 * Address: 0x00415530 (FUN_00415530, LuaPlus::LuaStackObject::GetString)
 *
 * What it does:
 * Returns the string view for the current stack slot, coercing via Lua and
 * raising a type error when conversion fails.
 */
const char* LuaStackObject::GetString() const
{
	const char* const str = lua_tostring(m_state->GetCState(), m_stackIndex);
	if (!str) {
		TypeError("string");
	}
	return str;
}

/**
 * Address: 0x0041B520 (FUN_0041B520, LuaPlus::LuaStackObject::GetInteger)
 *
 * What it does:
 * Reads one integer lane from the current Lua stack slot and raises a type
 * error when the slot is not numeric.
 */
int32_t LuaStackObject::GetInteger() const
{
	lua_State* const cState = m_state->GetCState();
	if (lua_type(cState, m_stackIndex) != LUA_TNUMBER) {
		TypeError("integer");
	}
	return static_cast<int32_t>(lua_tonumber(cState, m_stackIndex));
}

/**
 * Address: 0x004CCB00 (FUN_004CCB00, LuaPlus::LuaStackObject::ToNumber)
 *
 * What it does:
 * Validates that the current stack lane is numeric and returns one Lua number
 * payload; raises `TypeError(\"number\")` for non-numeric values.
 */
double LuaStackObject::ToNumber() const
{
	lua_State* const cState = m_state->GetCState();
	if (lua_type(cState, m_stackIndex) != LUA_TNUMBER) {
		TypeError("number");
	}
	return lua_tonumber(cState, m_stackIndex);
}

/**
 * Address: 0x00415560 (FUN_00415560, LuaPlus::LuaStackObject::GetBoolean)
 *
 * What it does:
 * Reads the current stack slot as a Lua boolean, allowing nil as false and
 * raising a type error for other non-boolean values.
 */
bool LuaStackObject::GetBoolean() const
{
	const int type = lua_type(m_state->GetCState(), m_stackIndex);
	if (type != LUA_TBOOLEAN && type != LUA_TNIL) {
		TypeError("boolean");
	}
	return lua_toboolean(m_state->GetCState(), m_stackIndex) != 0;
}

/**
 * Address: 0x00528140 (FUN_00528140, LuaPlus::LuaStackObject::GetByName)
 *
 * What it does:
 * Pushes `name`, performs one raw lookup against this stack slot, and returns
 * a stack-object view of the lookup result.
 */
LuaStackObject LuaStackObject::GetByName(const char* const name) const
{
	lua_State* const cState = m_state->GetCState();
	lua_pushstring(cState, name);
	lua_rawget(cState, m_stackIndex);
	return LuaStackObject(m_state, lua_gettop(cState));
}

/**
 * Address: 0x009072B0 (FUN_009072B0, LuaPlus::LuaObject::GetActiveState)
 *
 * What it does:
 * Returns the active Lua wrapper state (`stateUserData`) from this object's
 * bound root C-state lane.
 */
LuaState* LuaObject::GetActiveState() const
{
	return m_state->m_state->l_G->lstate->stateUserData;
}

/**
 * Address: 0x009072C0 (FUN_009072C0, LuaPlus::LuaObject::GetActiveCState)
 *
 * What it does:
 * Returns the active C-state pointer through this object's bound root
 * wrapper lane.
 */
lua_State* LuaObject::GetActiveCState() const
{
	return m_state->m_state->l_G->lstate;
}

/**
 * Address: 0x0091E200 (FUN_0091E200, func_SerializeLuaObjectName)
 *
 * What it does:
 * Resolves one serialized-name lookup lane from globals key
 * `"__serialize_object_for_name"` and returns the matching table entry for
 * `key`, or Lua's canonical nil object lane when the globals slot is not a
 * table.
 */
[[maybe_unused, nodiscard]] const TObject* ResolveSerializedObjectNameEntry(lua_State* const state, TString* const key)
{
	TString* const serializeMapName = luaS_newlstr(state, "__serialize_object_for_name", 0x1Bu);
	const TObject* const serializeMapObject = luaH_getstr(static_cast<Table*>(state->_gt.value.p), serializeMapName);
	if (serializeMapObject->tt == LUA_TTABLE) {
		return luaH_getstr(static_cast<Table*>(serializeMapObject->value.p), key);
	}

	return &luaO_nilobject;
}

/**
 * Address: 0x0090B990 (FUN_0090B990, LuaPlus::LuaObject::MemberSerialize)
 *
 * What it does:
 * Serializes LuaObject state ownership lane and TObject payload.
 */
void LuaObject::MemberSerialize(gpg::WriteArchive* const archive, LuaObject* const object)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	gpg::RRef stateRef{};
	(void)gpg::RRef_LuaState(&stateRef, object->m_state);
	gpg::WriteRawPointer(archive, stateRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

	if (object->m_state != nullptr) {
		gpg::RRef ownerRef{};
		(void)gpg::RRef_lua_State(&ownerRef, object->m_state->m_state);
		archive->Write(CachedType<TObject>(gLuaTObjectType), &object->m_object, ownerRef);
	}
}

/**
 * Address: 0x0090BDD0 (FUN_0090BDD0, LuaPlus::LuaObject::MemberDeserialize)
 *
 * What it does:
 * Deserializes LuaObject state ownership lane and TObject payload.
 */
void LuaObject::MemberDeserialize(
	gpg::ReadArchive* const archive,
	LuaObject* const object,
	const int,
	const gpg::RRef& ownerRef
)
{
	Ensure(archive != nullptr, "archive");
	Ensure(object != nullptr, "object");

	LuaState* state = nullptr;
	(void)archive->ReadPointer_LuaState(&state, &ownerRef);
	if (state != nullptr) {
		object->AssignNil(state);

		gpg::RRef stateOwner{};
		(void)gpg::RRef_lua_State(&stateOwner, object->m_state->m_state);
		archive->Read(CachedType<TObject>(gLuaTObjectType), &object->m_object, stateOwner);
		return;
	}

	*object = LuaObject{};
}

/**
 * Address: 0x009088E0 (FUN_009088E0, LuaPlus::LuaObject::AddToUsedObjectList)
 *
 * What it does:
 * Binds this object to the root used-object intrusive list from `state` and
 * copies the caller-provided raw payload into `m_object`.
 */
void LuaObject::AddToUsedObjectList(LuaState* state, TObject* object)
{
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState != nullptr, "state->m_rootState");
	Ensure(object != nullptr, "obj");

	LuaState* const root = state->m_rootState;
	m_state = root;
	m_next = root->m_headObject.m_next;
	root->m_headObject.m_next = this;
	m_next->m_prev = reinterpret_cast<LuaObject**>(this);
	m_prev = reinterpret_cast<LuaObject**>(&root->m_headObject.m_next);
	m_object = *object;
}

/**
 * Address: 0x009099B0 (FUN_009099B0, LuaPlus::LuaObject::AssignTObject)
 *
 * What it does:
 * Rebinds this object to the target root list only when the owner root
 * changes, then copies one caller-provided raw `TObject` payload.
 */
void LuaObject::AssignTObject(LuaState* state, TObject* object)
{
	Ensure(state != nullptr, "state");
	Ensure(object != nullptr, "obj");

	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			*reinterpret_cast<std::uint32_t*>(&m_object.tt) = 0u;
		}
		AddToUsedList(state);
	}

	m_object = *object;
}

/**
 * Address: 0x00908890 (FUN_00908890, LuaPlus::LuaObject::AddToUsedList)
 *
 * What it does:
 * Binds this object to the root used-object intrusive list from `state`,
 * preserving the current payload lane.
 */
void LuaObject::AddToUsedList(LuaState* state)
{
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState != nullptr, "state->m_rootState");

	LuaState* const root = state->m_rootState;
	m_state = root;
	m_next = root->m_headObject.m_next;
	root->m_headObject.m_next = this;
	m_next->m_prev = reinterpret_cast<LuaObject**>(this);
	m_prev = reinterpret_cast<LuaObject**>(&root->m_headObject.m_next);
}

/**
 * Address: 0x009096F0 (FUN_009096F0, LuaPlus::LuaObject::AssignThread)
 *
 * What it does:
 * Rebinds this object to one thread `lua_State` payload and enforces root
 * ownership transition semantics for the intrusive used-object list.
 */
void LuaObject::AssignThread(LuaState* const state)
{
	if (state->m_rootState == state) {
		LuaState* const activeState = state->GetActiveState();
		luaG_runerror(activeState->m_state, "attempt to use main lua state as a thread");
	}

	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			m_object.tt = LUA_TNIL;
		}
		AddToUsedList(state);
	}

	m_object.value.p = state->m_state;
	m_object.tt = state->m_state->tt;
}

/**
 * Address: 0x009075F0 (FUN_009075F0, LuaPlus::LuaObject::Reset)
 *
 * What it does:
 * Unlinks this object from the owning state intrusive list (when bound),
 * resets the tagged value to nil, and clears state ownership.
 */
void LuaObject::Reset()
{
	if (!m_state) {
		return;
	}

	if (m_prev && m_next) {
		*m_prev = m_next;
		m_next->m_prev = m_prev;
	}
	m_object.tt = LUA_TNIL;
	m_state = nullptr;
	m_next = nullptr;
	m_prev = nullptr;
}

/**
 * Address: 0x00907440 (FUN_00907440, LuaPlus::LuaObject::operator bool)
 *
 * What it does:
 * Applies Lua truthiness rules for this bound object:
 * nil is false, booleans return stored value, everything else is true.
 */
LuaObject::operator bool() const noexcept
{
	if (!m_state) {
		return false;
	}

	if (m_object.tt == LUA_TNIL) {
		return false;
	}

	if (m_object.tt == LUA_TBOOLEAN) {
		return m_object.value.b != 0;
	}

	return true;
}

/**
 * Address: 0x009072F0 (FUN_009072F0, LuaPlus::LuaObject::IsNil)
 *
 * What it does:
 * Returns true only for state-bound objects tagged as nil.
 */
bool LuaObject::IsNil() const noexcept
{
	return m_state != nullptr && m_object.tt == LUA_TNIL;
}

/**
 * Address: 0x009078D0 (FUN_009078D0, LuaPlus::LuaObject::IsBoolean)
 *
 * What it does:
 * Asserts state binding and returns whether this value is a boolean tag.
 */
bool LuaObject::IsBoolean() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TBOOLEAN;
}

/**
 * Address: 0x00907350 (FUN_00907350, LuaPlus::LuaObject::IsNumber)
 *
 * What it does:
 * Returns whether this value carries a numeric Lua tag.
 */
bool LuaObject::IsNumber() const noexcept
{
	return m_object.tt == LUA_TNUMBER;
}

/**
 * Address: 0x00907370 (FUN_00907370, LuaPlus::LuaObject::IsString)
 *
 * What it does:
 * Returns whether this value carries a string Lua tag.
 */
bool LuaObject::IsString() const noexcept
{
	return m_object.tt == LUA_TSTRING;
}

/**
 * Address: 0x00907320 (FUN_00907320, LuaPlus::LuaObject::IsUserData)
 *
 * What it does:
 * Returns true for both full userdata and light userdata tags.
 */
bool LuaObject::IsUserData() const noexcept
{
	return m_object.tt == LUA_TUSERDATA || m_object.tt == LUA_TLIGHTUSERDATA;
}

/**
 * Address: 0x00907810 (FUN_00907810, LuaPlus::LuaObject::IsFunction)
 *
 * What it does:
 * Validates state ownership, then treats both Lua closure and C-function
 * tags as callable by checking `(tt | 1) == LUA_TFUNCTION`.
 */
bool LuaObject::IsFunction() const
{
	if (m_state == nullptr) {
		throw LuaAssertion("m_state");
	}

	return (m_object.tt | 1) == LUA_TFUNCTION;
}

/**
 * Address: 0x009077C0 (FUN_009077C0, LuaPlus::LuaObject::IsConvertibleToString)
 *
 * What it does:
 * Returns true when this value is already string or numeric.
 */
bool LuaObject::IsConvertibleToString() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt == LUA_TSTRING || m_object.tt == LUA_TNUMBER;
}

/**
 * Address: 0x009072D0 (FUN_009072D0, LuaPlus::LuaObject::TypeError)
 *
 * What it does:
 * Raises one Lua-object operation type error for the current tagged value.
 */
void LuaObject::TypeError(const char* const operation) const
{
	lua_State* const cState = GetActiveCState();
	const char* const valueType = cState != nullptr ? lua_typename(cState, m_object.tt) : "unknown";
	const char* const opText = operation != nullptr ? operation : "operate on";

	std::string message("attempt to ");
	message += opText;
	message += " a ";
	message += valueType != nullptr ? valueType : "unknown";
	message += " value";
	throw std::runtime_error(message);
}

/**
 * Address: 0x009076D0 (FUN_009076D0, LuaPlus::LuaObject::Type)
 *
 * What it does:
 * Returns this object's raw Lua type tag.
 */
int LuaObject::Type() const
{
	Ensure(m_state != nullptr, "m_state");
	return m_object.tt;
}

/**
 * Address: 0x00908B50 (FUN_00908B50, LuaPlus::LuaObject::TypeName)
 *
 * What it does:
 * Returns `"no value"` for `LUA_TNONE`; otherwise returns Lua's typename for
 * this object's current type tag.
 */
const char* LuaObject::TypeName() const
{
	Ensure(m_state != nullptr, "m_state");

	const int type = m_object.tt;
	if (type == LUA_TNONE) {
		return "no value";
	}
	return luaT_typenames[type];
}

void LuaObject::SetTableHelper(const char* key, TObject* object)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");
	Ensure(object != nullptr, "obj");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	lua_pushstring(lstate, key);
	PushTObject(lstate, *object);
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);
}

void LuaObject::SetTableHelper(const int32_t index, TObject* object)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(object != nullptr, "obj");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	lua_pushnumber(lstate, static_cast<lua_Number>(index));
	PushTObject(lstate, *object);
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00907ED0 (FUN_00907ED0, LuaPlus::LuaObject::SetN)
 *
 * What it does:
 * Writes Lua array-length metadata (`n`) for this table object.
 */
void LuaObject::SetN(const int32_t n)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	luaL_setn(lstate, -1, n);
	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00907D10 (FUN_00907D10)
 * Mangled: ?PushStack@LuaObject@LuaPlus@@QBEXPAUlua_State@@@Z
 *
 * What it does:
 * Validates that both objects share the same Lua global-state root, pushes this
 * object's raw `TObject` payload onto `state->top`, extends stack space when
 * needed, then advances the stack top by one slot.
 */
StkId LuaObject::PushStack(lua_State* state) const
{
	if (state == nullptr || m_state == nullptr || m_state->m_state == nullptr) {
		throw LuaAssertion("state->l_G == m_state->m_state->l_G");
	}
	if (state->l_G != m_state->m_state->l_G) {
		throw LuaAssertion("state->l_G == m_state->m_state->l_G");
	}

	StkId const slot = state->top;
	*slot = m_object;

	if (slot >= state->ci->top) {
		lua_checkstack(state, 1);
	}
	state->top = slot + 1;
	return slot;
}

StkId LuaObject::PushStack(LuaState* state) const
{
	Ensure(state != nullptr, "state");
	Ensure(state->m_rootState == m_state, "state->m_rootState == m_state");
	return PushStack(state->GetCState());
}

void LuaObject::AssignNewTable(LuaState* state, const int32_t nArray, const uint32_t lnHash)
{
	RebindToState(*this, state);

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	// Address: 0x00909940 (FUN_00909940)
	// Binary path creates a table directly via luaH_new using requested array/hash sizing.
	const int hashBits = luaO_log2(lnHash);
	Table* const table = luaH_new(lstate, nArray, hashBits + 1);
	Ensure(table != nullptr, "luaH_new returned null");
	m_object.tt = table->tt;
	m_object.value.p = table;
}

/**
 * Address: 0x00909650 (FUN_00909650, LuaPlus::LuaObject::AssignInteger)
 *
 * What it does:
 * Rebinds this object to `state` root ownership lane when needed, then stores
 * one integer payload converted to Lua number format.
 */
void LuaObject::AssignInteger(LuaState* state, const int32_t value)
{
	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			m_object.tt = LUA_TNIL;
		}
		AddToUsedList(state);
	}

	m_object.value.n = static_cast<float>(value);
	m_object.tt = LUA_TNUMBER;
}

/**
 * Address: 0x009096A0 (FUN_009096A0, LuaPlus::LuaObject::AssignNumber)
 *
 * What it does:
 * Rebinds this object to `state` root ownership (when needed) and stores one
 * numeric payload lane.
 */
void LuaObject::AssignNumber(LuaState* state, const double number)
{
	RebindToState(*this, state);
	m_object.value.n = static_cast<float>(number);
	m_object.tt = LUA_TNUMBER;
}

void LuaObject::AssignNil(LuaState* state)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TNIL;
	m_object.value.p = nullptr;
}

/**
 * Address: 0x00909600 (FUN_00909600, LuaPlus::LuaObject::AssignBoolean)
 *
 * What it does:
 * Rebinds this object to one state-root lane when needed, then stores one
 * boolean payload lane (`LUA_TBOOLEAN`).
 */
void LuaObject::AssignBoolean(LuaState* state, const bool value)
{
	if (state->m_rootState != m_state) {
		if (m_state != nullptr) {
			*m_prev = m_next;
			m_next->m_prev = m_prev;
			*reinterpret_cast<std::uint32_t*>(&m_object.tt) = 0u;
		}
		AddToUsedList(state);
	}

	m_object.value.b = value ? 1u : 0u;
	*reinterpret_cast<std::uint32_t*>(&m_object.tt) = LUA_TBOOLEAN;
}

/**
 * Address: 0x00909750 (FUN_00909750, LuaPlus::LuaObject::AssignString)
 *
 * What it does:
 * Rebinds this object to one state-root lane when needed, then stores one
 * interned string payload or marks this object as `LUA_TNIL` for null input.
 */
void LuaObject::AssignString(LuaState* state, const char* value)
{
	RebindToState(*this, state);
	if (value == nullptr) {
		m_object.tt = LUA_TNIL;
		return;
	}

	Ensure(state != nullptr, "state");
	lua_State* const lstate = state->m_state;
	Ensure(lstate != nullptr, "state->m_state");

	TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
	m_object.tt = interned->tt;
	m_object.value.p = interned;
}

void LuaObject::AssignLightUserData(LuaState* state, void* value)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TLIGHTUSERDATA;
	m_object.value.p = value;
}

/**
 * Address: 0x009097D0 (FUN_009097D0, LuaPlus::LuaObject::AssignNewUserData)
 *
 * What it does:
 * Rebinds this object to `state` root ownership, allocates one default-
 * constructed userdata payload for `type`, and stores it as object payload.
 */
gpg::RRef LuaObject::AssignNewUserData(LuaState* state, const gpg::RType* type)
{
	RebindToState(*this, state);
	Ensure(state != nullptr, "state");
	Ensure(type != nullptr, "type");

	lua_State* const lstate = state->m_state;
	Ensure(lstate != nullptr, "state->m_state");

	Udata* const userdata = CreateDefaultConstructedUserdata(lstate, const_cast<gpg::RType*>(type));
	m_object.tt = static_cast<int>(userdata->tt);
	m_object.value.p = userdata;
	return BuildRefFromUserdata(userdata);
}

/**
 * Address: 0x00909840 (FUN_00909840, LuaPlus::LuaObject::AssignNewUserData)
 *
 * What it does:
 * Rebinds this object to `state` root ownership, then materializes one
 * reflected userdata lane from `value` and stores it as object payload.
 */
gpg::RRef LuaObject::AssignNewUserData(LuaState* state, const gpg::RRef& value)
{
	RebindToState(*this, state);
	Ensure(state != nullptr, "state");
	lua_State* const lstate = state->m_state;
	Ensure(lstate != nullptr, "state->m_state");

	Udata* const userdata = CreateRefUserdata(lstate, const_cast<gpg::RRef*>(&value));
	m_object.tt = static_cast<int>(userdata->tt);
	m_object.value.p = userdata;
	return BuildRefFromUserdata(userdata);
}

/**
 * Address: 0x009084E0 (FUN_009084E0, LuaPlus::LuaObject::SetString)
 *
 * What it does:
 * Writes one table entry by integer index using a string-or-nil payload.
 */
void LuaObject::SetString(const int32_t index, const char* value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject valueObject{};
	if (value != nullptr) {
		TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
		valueObject.tt = interned->tt;
		valueObject.value.p = interned;
	} else {
		valueObject.tt = LUA_TNIL;
		valueObject.value.p = nullptr;
	}

	TObject keyObject{};
	keyObject.value.n = static_cast<float>(index);
	keyObject.tt = LUA_TNUMBER;
	luaV_settable(lstate, &m_object, &keyObject, &valueObject);
}

/**
 * Address: 0x00908450 (FUN_00908450, LuaPlus::LuaObject::SetString)
 *
 * What it does:
 * Writes one table entry by string key using a string-or-nil payload.
 */
void LuaObject::SetString(const char* key, const char* value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject valueObject{};
	if (value != nullptr) {
		TString* const interned = luaS_newlstr(lstate, value, std::strlen(value));
		valueObject.tt = interned->tt;
		valueObject.value.p = interned;
	} else {
		valueObject.tt = LUA_TNIL;
		valueObject.value.p = nullptr;
	}

	SetTableHelper(key, &valueObject);
}

/**
 * Address: 0x00907FF0 (FUN_00907FF0, LuaPlus::LuaObject::SetNil)
 *
 * What it does:
 * Writes a nil payload to one table entry addressed by string key.
 */
void LuaObject::SetNil(const char* const key)
{
	Ensure(m_state != nullptr, "m_state");

	TObject nilObject{};
	nilObject.tt = LUA_TNIL;
	nilObject.value.p = nullptr;
	SetTableHelper(key, &nilObject);
}

/**
 * Address: 0x00907FA0 (FUN_00907FA0, LuaPlus::LuaObject::SetNil)
 *
 * What it does:
 * Writes a nil payload to one table entry addressed by integer key.
 */
void LuaObject::SetNil(const int32_t index)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject keyObject{};
	keyObject.tt = LUA_TNUMBER;
	keyObject.value.n = static_cast<float>(index);

	TObject nilObject{};
	nilObject.tt = LUA_TNIL;
	nilObject.value.p = nullptr;

	luaV_settable(lstate, &m_object, &keyObject, &nilObject);
}

/**
 * Address: 0x00908320 (FUN_00908320, LuaPlus::LuaObject::SetNumber)
 *
 * What it does:
 * Writes one table entry by string key using a numeric payload.
 */
void LuaObject::SetNumber(const char* key, const float value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object;
	object.tt = LUA_TNUMBER;
	object.value.n = value;
	SetTableHelper(key, &object);
}

/**
 * Address: 0x00908370 (FUN_00908370, LuaPlus::LuaObject::SetNumber)
 *
 * What it does:
 * Writes one table entry by integer key using a numeric payload.
 */
void LuaObject::SetNumber(const int32_t index, const float value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = value;

	TObject key{};
	key.tt = LUA_TNUMBER;
	key.value.n = static_cast<float>(index);

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x00908240 (FUN_00908240, ?SetInteger@LuaObject@LuaPlus@@QBEXHH@Z)
 *
 * What it does:
 * Writes one table entry by integer key using an integer payload.
 */
void LuaObject::SetInteger(const int32_t index, const int32_t value)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	TObject val{};
	val.tt = LUA_TNUMBER;
	val.value.n = static_cast<float>(value);

	TObject key{};
	key.tt = LUA_TNUMBER;
	key.value.n = static_cast<float>(index);

	luaV_settable(lstate, &m_object, &key, &val);
}

/**
 * Address: 0x009081F0 (FUN_009081F0, ?SetInteger@LuaObject@LuaPlus@@QBEXPBDH@Z)
 *
 * What it does:
 * Writes one table entry by string key using an integer payload lane.
 */
void LuaObject::SetInteger(const char* key, const int32_t value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object{};
	object.tt = LUA_TNUMBER;
	object.value.n = static_cast<float>(value);
	SetTableHelper(key, &object);
}

/**
 * Address: 0x009080C0 (FUN_009080C0, LuaPlus::LuaObject::SetBoolean)
 *
 * What it does:
 * Writes one boolean payload into this table by string key.
 */
void LuaObject::SetBoolean(const char* key, const bool value)
{
	Ensure(m_state != nullptr, "m_state");

	TObject object{};
	object.tt = LUA_TBOOLEAN;
	object.value.b = value ? 1 : 0;
	SetTableHelper(key, &object);
}

/**
 * Address: 0x00908760 (FUN_00908760, LuaPlus::LuaObject::SetObject)
 *
 * What it does:
 * Writes one table field by string key after enforcing shared-state ownership
 * with the source Lua object value.
 */
void LuaObject::SetObject(const char* key, const LuaObject& value)
{
	Ensure(m_state == value.m_state, "m_state == value.m_state");
	SetTableHelper(key, const_cast<TObject*>(&value.m_object));
}

void LuaObject::SetObject(const char* key, LuaObject* value)
{
	if (value) {
		SetObject(key, *value);
		return;
	}

	TObject nilValue;
	SetTableHelper(key, &nilValue);
}

/**
 * Address: 0x00908810 (FUN_00908810, LuaPlus::LuaObject::SetObject)
 *
 * What it does:
 * Writes one table entry by LuaObject key/value lanes after validating shared
 * state ownership.
 */
void LuaObject::SetObject(const LuaObject& key, const LuaObject& value)
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");
	Ensure(m_state == value.m_state, "m_state == value.m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	luaV_settable(
		lstate,
		&m_object,
		const_cast<TObject*>(&key.m_object),
		const_cast<TObject*>(&value.m_object)
	);
}

/**
 * Address: 0x009087A0 (FUN_009087A0, LuaPlus::LuaObject::SetObject)
 *
 * What it does:
 * Writes one object value into this table by integer key after enforcing
 * shared Lua-state ownership with `value`.
 */
void LuaObject::SetObject(const int32_t index, const LuaObject& value)
{
	Ensure(m_state == value.m_state, "m_state == value.m_state");
	SetTableHelper(index, const_cast<TObject*>(&value.m_object));
}

void LuaObject::SetObject(const int32_t index, LuaObject* value)
{
	if (value) {
		SetObject(index, *value);
		return;
	}

	TObject nilValue;
	SetTableHelper(index, &nilValue);
}

/**
 * Address: 0x00907E00 (FUN_00907E00, LuaPlus::LuaObject::SetMetaTable)
 *
 * What it does:
 * Validates that both objects share one Lua state and applies `valueObj` as
 * this object's runtime metatable.
 */
void LuaObject::SetMetaTable(const LuaObject& valueObj)
{
	Ensure(m_state && m_state == valueObj.m_state, "m_state && m_state == valueObj.m_state");

	lua_State* lstate = m_state->GetCState();
	Ensure(lstate != nullptr, "m_state->GetCState() != nullptr");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	const_cast<LuaObject&>(valueObj).PushStack(lstate);
	lua_setmetatable(lstate, -2);
	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x00908BA0 (FUN_00908BA0, LuaPlus::LuaObject::GetMetaTable)
 *
 * What it does:
 * Fetches this object's runtime metatable and returns it as a bound LuaObject.
 */
LuaObject LuaObject::GetMetaTable() const
{
	Ensure(m_state != nullptr, "m_state");

	Table* const metatable = luaT_getmetatable(m_state->m_state, &m_object);

	LuaObject out(m_state);
	out.m_object.value.p = metatable;
	out.m_object.tt = metatable->tt;
	return out;
}

/**
 * Address: 0x00908C10 (FUN_00908C10, LuaPlus::LuaObject::CreateTable)
 *
 * What it does:
 * Creates one new Lua table and stores it in this table at string key `key`.
 */
LuaObject LuaObject::CreateTable(const char* const key, const int32_t narray, const int32_t lnhash)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	LuaObject out(m_state);
	Table* const table = luaH_new(lstate, narray, lnhash);
	out.m_object.value.p = table;
	out.m_object.tt = table->tt;
	SetTableHelper(key, &out.m_object);
	return out;
}

/**
 * Address: 0x00908CA0 (FUN_00908CA0, LuaPlus::LuaObject::CreateTable_Array)
 *
 * What it does:
 * Creates one new Lua table and stores it in this table at integer key
 * `index`.
 */
LuaObject LuaObject::CreateTable(const int32_t index, const int32_t narray, const int32_t lnhash)
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	LuaObject out(m_state);
	Table* const table = luaH_new(lstate, narray, lnhash);
	out.m_object.value.p = table;
	out.m_object.tt = table->tt;

	TObject keyObject{};
	keyObject.tt = LUA_TNUMBER;
	keyObject.value.n = static_cast<float>(index);
	luaV_settable(lstate, &m_object, &keyObject, &out.m_object);
	return out;
}

/**
 * Address: 0x00909CE0 (FUN_00909CE0, LuaPlus::LuaObject::Insert)
 *
 * What it does:
 * Calls `table.insert(this, key, obj)` in the active Lua state and restores
 * the original stack top after the call.
 */
void LuaObject::Insert(const int32_t key, const LuaObject& obj) const
{
	if (m_state != obj.m_state) {
		throw LuaAssertion("m_state == obj.m_state");
	}

	LuaState* const activeState = m_state->GetActiveState();
	lua_State* const lstate = activeState->m_state;
	const int oldTop = lua_gettop(lstate);

	{
		LuaObject tableObject = activeState->GetGlobal("table");
		LuaObject insertFunction = tableObject["insert"];
		insertFunction.PushStack(activeState);

		const_cast<LuaObject*>(this)->PushStack(activeState);
		lua_pushnumber(lstate, static_cast<lua_Number>(key));
		const_cast<LuaObject&>(obj).PushStack(activeState);
		lua_call(lstate, 3, LUA_MULTRET);
	}

	lua_settop(lstate, oldTop);
}

/**
 * Address: 0x10007360 (?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
 * Address: 0x00908DF0 (FUN_00908DF0, __imp_?GetByIndex@LuaObject@LuaPlus@@QBE?AV12@H@Z)
 *
 * What it does:
 * Reads one table slot by numeric index and returns the value as a bound
 * `LuaObject` while restoring the caller stack top.
 */
LuaObject LuaObject::GetByIndex(const int32_t index) const
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	const_cast<LuaObject*>(this)->PushStack(lstate);
	lua_pushnumber(lstate, static_cast<lua_Number>(index));
	lua_gettable(lstate, -2);
	LuaObject value{ LuaStackObject(m_state, -1) };
	lua_settop(lstate, oldTop);
	return value;
}

/**
 * Address: 0x00908E70 (FUN_00908E70, LuaPlus::LuaObject::GetByObject)
 *
 * What it does:
 * Looks up this table using a LuaObject key and returns the raw slot value.
 */
LuaObject LuaObject::GetByObject(const LuaObject& key) const
{
	Ensure(m_state == key.m_state, "m_state == key.m_state");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const TObject* const rawValue = luaV_gettable(lstate, &m_object, &key.m_object, nullptr);
	LuaObject out;
	out.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return out;
}

LuaObject LuaObject::GetByName(const char* name) const
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(name != nullptr, "name");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	const_cast<LuaObject*>(this)->PushStack(lstate);
	lua_pushstring(lstate, name);
	lua_gettable(lstate, -2);
	LuaObject value{LuaStackObject(m_state, -1)};
	lua_settop(lstate, oldTop);
	return value;
}

/**
 * Address: 0x00908F60 (FUN_00908F60, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates table indexing, resolves an already-interned string key from the
 * VM string table, and returns the raw table slot value.
 */
LuaObject LuaObject::operator[](const char* const name) const
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(name != nullptr, "name");

	lua_State* const lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
	}

	const TString* const internedKey = FindInternedString(lstate, name);
	if (internedKey == nullptr) {
		LuaObject nilValue;
		nilValue.AddToUsedList(m_state);
		nilValue.m_object.tt = LUA_TNIL;
		return nilValue;
	}

	TObject keyObject;
	keyObject.tt = internedKey->tt;
	keyObject.value.p = const_cast<TString*>(internedKey);

	const TObject* const rawValue = luaH_get(reinterpret_cast<Table*>(m_object.value.p), &keyObject);
	Ensure(rawValue != nullptr, "obj");

	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x009091E0 (FUN_009091E0, LuaPlus::LuaObject::operator[])
 *
 * What it does:
 * Validates state + table type for integer indexing, then fetches the raw
 * numeric-key slot directly from Lua's table storage.
 */
LuaObject LuaObject::operator[](const int32_t index) const
{
	if (!m_state) {
		throw LuaAssertion("m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TTABLE) {
		luaG_typeerror(lstate, &m_object, "index");
		if (m_object.tt != LUA_TTABLE) {
			throw LuaAssertion("(((o)->tt) == LUA_TTABLE)");
		}
	}

	const TObject* const rawValue = luaH_getnum(reinterpret_cast<Table*>(m_object.value.p), index);
	LuaObject result;
	result.AddToUsedObjectList(m_state, const_cast<TObject*>(rawValue));
	return result;
}

/**
 * Address: 0x009093B0 (FUN_009093B0, LuaPlus::LuaObject::Lookup)
 *
 * What it does:
 * Traverses a dotted path and alternates string-key vs numeric-index lookup
 * based on each segment's parse result.
 */
LuaObject LuaObject::Lookup(const char* const path) const
{
	if (path == nullptr || *path == '\0') {
		return *this;
	}

	auto tryParseIndex = [](const char* const text, int32_t* const outIndex) -> bool
	{
		if (text == nullptr || *text == '\0' || outIndex == nullptr) {
			return false;
		}

		char* parseEnd = nullptr;
		const double parsedValue = std::strtod(text, &parseEnd);
		if (parseEnd == text || parseEnd == nullptr || *parseEnd != '\0') {
			return false;
		}

		const double minValue = static_cast<double>(std::numeric_limits<int32_t>::min());
		const double maxValue = static_cast<double>(std::numeric_limits<int32_t>::max());
		if (parsedValue < minValue || parsedValue > maxValue) {
			return false;
		}

		*outIndex = static_cast<int32_t>(parsedValue);
		return true;
	};

	LuaObject current = *this;
	std::string mutablePath(path);
	char* segment = mutablePath.data();
	char* dot = std::strchr(segment, '.');

	while (dot != nullptr) {
		*dot = '\0';
		if (*segment == '\0') {
			return {};
		}

		int32_t numericIndex = 0;
		current = tryParseIndex(segment, &numericIndex) ? current[numericIndex] : current[segment];
		if (current.IsNil()) {
			return current;
		}

		segment = dot + 1;
		dot = std::strchr(segment, '.');
	}

	if (*segment == '\0') {
		return {};
	}

	int32_t numericIndex = 0;
	return tryParseIndex(segment, &numericIndex) ? current[numericIndex] : current[segment];
}

int32_t LuaObject::GetN() const
{
	Ensure(m_state != nullptr, "m_state");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	const_cast<LuaObject*>(this)->PushStack(lstate);
#if defined(lua_rawlen)
	const int32_t count = static_cast<int32_t>(lua_rawlen(lstate, -1));
#elif defined(lua_objlen)
	const int32_t count = static_cast<int32_t>(lua_objlen(lstate, -1));
#else
	const int32_t count = luaL_getn(lstate, -1);
#endif
	lua_settop(lstate, oldTop);
	return count;
}

/**
 * Address: 0x00907F50 (FUN_00907F50, LuaPlus::LuaObject::GetCount)
 *
 * What it does:
 * Pushes this object to the active Lua stack, reads Lua table length via
 * `lua_getn`, then restores stack top and returns that element count.
 */
int32_t LuaObject::GetCount() const
{
	Ensure(m_state != nullptr, "m_state");

	LuaState* const activeState = GetActiveState();
	Ensure(activeState != nullptr, "active state");
	Ensure(activeState->m_state != nullptr, "active lua state");

	const int oldTop = lua_gettop(activeState->m_state);
	const_cast<LuaObject*>(this)->PushStack(activeState);
	const int stackIndex = lua_gettop(activeState->m_state);
	const int32_t count = static_cast<int32_t>(lua_getn(activeState->m_state, stackIndex));
	lua_settop(activeState->m_state, oldTop);
	return count;
}

/**
 * Address: 0x0090A410 (FUN_0090A410, LuaPlus::LuaObject::GetTableCount)
 *
 * What it does:
 * Iterates all table entries and returns the number of key/value pairs.
 */
int32_t LuaObject::GetTableCount() const
{
	int32_t count = 0;
	LuaTableIterator iter(*this, 1);
	while (!iter.m_isDone) {
		++count;
		iter.Next();
	}
	return count;
}

/**
 * Address: 0x00907630 (FUN_00907630, LuaPlus::LuaObject::Register)
 *
 * What it does:
 * Creates one C closure with `tagMethod` upvalues from the Lua root-state
 * stack, then assigns it into this table object under `key`.
 */
void LuaObject::Register(const char* const key, CFunction const value, const int32_t tagMethod)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(m_state->m_state != nullptr, "lua state");
	Ensure(m_state->m_state->l_G != nullptr, "lua global state");
	Ensure(key != nullptr, "key");
	Ensure(value != nullptr, "value");

	lua_State* const closureState = m_state->m_state->l_G->lstate;
	Ensure(closureState != nullptr, "closure state");

	Closure* const closure = luaF_newCclosure(closureState, tagMethod);
	closure->c.f = value;
	closureState->top -= tagMethod;

	for (int upvalueIndex = tagMethod - 1; upvalueIndex >= 0; --upvalueIndex) {
		closure->c.upvalue[upvalueIndex] = closureState->top[upvalueIndex];
		closureState->top[upvalueIndex].tt = 0;
	}

	TObject closureObject{};
	closureObject.value.p = closure;
	closureObject.tt = static_cast<int>(closure->c.tt);
	SetTableHelper(key, &closureObject);
}

/**
 * Address: 0x004D2A40 (FUN_004D2A40, Moho::SCR_FromByteStream)
 *
 * What it does:
 * Deserializes one tagged Lua payload from a binary stream and recursively
 * rebuilds nested table key/value pairs.
 */
void LuaObject::SCR_FromByteStream(LuaObject& out, LuaState* state, const gpg::BinaryReader* reader)
{
	Ensure(state != nullptr, "state");
	Ensure(reader != nullptr, "reader");

	LuaObject result;
	int8_t luaType = 0;
	reader->ReadExact(luaType);

	switch (luaType) {
		case 0: {
			float number = 0.0f;
			reader->ReadExact(number);
			result.AssignNumber(state, number);
			break;
		}
		case 1: {
			msvc8::string string;
			reader->ReadString(&string);
			result.AssignString(state, string.c_str());
			break;
		}
		case 2:
			result.AssignNil(state);
			break;
		case 3: {
			int8_t byteValue = 0;
			reader->ReadExact(byteValue);
			result.AssignBoolean(state, byteValue != 0);
			break;
		}
		case 4: {
			result.AssignNewTable(state, 0, 0);
			gpg::Stream* stream = const_cast<gpg::Stream*>(reader->stream());
			if (!stream) {
				gpg::Warnf("Error deserializing lua table: no stream.");
				result.AssignNil(state);
				break;
			}

			while (true) {
				const int8_t nextType = stream->GetByte();
				if (nextType == -1) {
					gpg::Warnf("Error deserializing lua table: unexpected EOF.");
					result.AssignNil(state);
					break;
				}

				stream->VirtUnGetByte(nextType);
				if (nextType == 5) {
					(void)stream->GetByte();
					break;
				}

				LuaObject key;
				SCR_FromByteStream(key, state, reader);
				if (key.IsNil()) {
					gpg::Die("Deserialized nil table key.");
				}

				LuaObject value;
				SCR_FromByteStream(value, state, reader);
				if (value.IsNil()) {
					gpg::Die("Deserialized nil table value.");
				}

				result.SetObject(key, value);
			}
			break;
		}
		case 5:
			gpg::Warnf("Error deseralizing lua object: unexpected end-of-table marker encountered.");
			result.AssignNil(state);
			break;
		default:
			gpg::Warnf("Attempt to deserialize unknown lua data.");
			result.AssignNil(state);
			break;
	}

	out = result;
}

/**
 * Address: 0x00907C90 (FUN_00907C90, LuaPlus::LuaObject::GetBoolean)
 *
 * What it does:
 * Validates this object has a bound state, raises Lua's type-error lane for
 * non-nil/non-boolean values, and returns Lua truthiness for boolean lanes.
 */
bool LuaObject::GetBoolean() const
{
	if (!m_state) {
		throw LuaAssertion("m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TNIL && m_object.tt != LUA_TBOOLEAN) {
		luaG_typeerror(lstate, &m_object, "get as boolean");
	}

	return m_object.tt != LUA_TNIL && (m_object.tt != LUA_TBOOLEAN || m_object.value.b != 0);
}

/**
 * Address: 0x00907A90 (FUN_00907A90, LuaPlus::LuaObject::GetString)
 *
 * What it does:
 * Validates this object has a bound state, raises Lua's type-error lane for
 * non-string values, and returns the underlying interned string buffer.
 */
const char* LuaObject::GetString() const
{
	if (!m_state) {
		throw LuaAssertion("m_state");
	}

	lua_State* const lstate = GetActiveCState();
	if (m_object.tt != LUA_TSTRING) {
		luaG_typeerror(lstate, &m_object, "get as string");
	}

	const auto* ts = static_cast<const TString*>(m_object.value.p);
	return ts->str;
}

/**
 * Address: 0x00907410 (FUN_00907410, LuaPlus::LuaObject::ToStrLen)
 *
 * What it does:
 * Returns current string length when already string, otherwise tries Lua's
 * number-to-string conversion and returns resulting length on success.
 */
int32_t LuaObject::ToStrLen()
{
	if (m_object.tt == LUA_TSTRING) {
		const auto* const text = static_cast<const TString*>(m_object.value.p);
		return static_cast<int32_t>(text->len);
	}

	if (luaV_tostring(m_state->m_state, &m_object) != 0) {
		const auto* const text = static_cast<const TString*>(m_object.value.p);
		return static_cast<int32_t>(text->len);
	}

	return 0;
}

/**
 * Address: 0x009073B0 (FUN_009073B0, LuaPlus::LuaObject::ToNumber)
 *
 * What it does:
 * Returns numeric payload when already numeric, otherwise attempts Lua numeric
 * coercion and returns `0` on conversion failure.
 */
double LuaObject::ToNumber() const
{
	TObject numericValue{};
	if (m_object.tt == LUA_TNUMBER || luaV_tonumber(&m_object, &numericValue) != 0) {
		return static_cast<double>(m_object.value.n);
	}
	return 0.0;
}

/**
 * Address: 0x009073E0 (FUN_009073E0, LuaPlus::LuaObject::ToString)
 *
 * What it does:
 * Returns the current interned string buffer when this object is already a
 * string, otherwise attempts in-place Lua coercion via `luaV_tostring` and
 * returns `nullptr` when conversion fails.
 */
const char* LuaObject::ToString() const
{
	if (m_object.tt == LUA_TSTRING) {
		return static_cast<const GCObject*>(m_object.value.p)->ts.str;
	}

	TObject* const object = const_cast<TObject*>(&m_object);
	if (luaV_tostring(m_state->m_state, object) != 0) {
		return static_cast<const GCObject*>(object->value.p)->ts.str;
	}

	return nullptr;
}

/**
 * Address: 0x00907970 (FUN_00907970, LuaPlus::LuaObject::GetNumber)
 *
 * What it does:
 * Asserts state binding, enforces numeric type, and returns numeric payload.
 */
double LuaObject::GetNumber() const
{
	Ensure(m_state != nullptr, "m_state");
	if (m_object.tt != LUA_TNUMBER) {
		luaG_typeerror(m_state->m_state->l_G->lstate, &m_object, "get as number");
	}
	return static_cast<double>(m_object.value.n);
}

/**
 * Address: 0x00907910 (FUN_00907910, LuaPlus::LuaObject::GetInteger)
 *
 * What it does:
 * Asserts state binding, enforces numeric type, and returns int-truncated payload.
 */
int32_t LuaObject::GetInteger() const
{
	Ensure(m_state != nullptr, "m_state");
	if (m_object.tt != LUA_TNUMBER) {
		luaG_typeerror(m_state->m_state->l_G->lstate, &m_object, "get as int");
	}
	return static_cast<int32_t>(m_object.value.n);
}

/**
 * Address: 0x004D2C80 (FUN_004D2C80, ?SCR_ToByteStream@Moho@@YA_NABVLuaObject@LuaPlus@@AAVStream@gpg@@@Z)
 *
 * What it does:
 * Encodes one LuaObject value into the SCR tagged stream format and recursively
 * serializes table keys/values while warning on userdata/unsupported lanes.
 */
bool LuaObject::ToByteStream(gpg::Stream& stream)
{
	char typeTag;
	bool success = true;

	if (!m_state || IsNil()) {
		typeTag = 2;
		if (stream.mWriteEnd != stream.mWriteHead) {
			*stream.mWriteHead = typeTag;
			++stream.mWriteHead;
		} else {
			stream.VirtWrite(&typeTag, 1);
		}
		return true;
	}

	if (IsBoolean()) {
		typeTag = 3;
		if (stream.mWriteEnd != stream.mWriteHead) {
			*stream.mWriteHead = typeTag;
			++stream.mWriteHead;
		} else {
			stream.VirtWrite(&typeTag, 1);
		}

		const bool boolValue = GetBoolean();
		typeTag = boolValue ? 1 : 0;
		if (stream.mWriteEnd != stream.mWriteHead) {
			*stream.mWriteHead = typeTag;
			++stream.mWriteHead;
		} else {
			stream.VirtWrite(&typeTag, 1);
		}
		return true;
	}

	if (IsNumber()) {
		typeTag = 0;
		stream.Write(typeTag);
		const float number = static_cast<float>(GetNumber());
		stream.Write(number);
		return true;
	}

	if (IsString()) {
		typeTag = 1;
		stream.Write(typeTag);
		const char* str = GetString();
		stream.Write(str ? str : "");
		return true;
	}

	if (IsTable()) {
		typeTag = 4;
		stream.Write(typeTag);

		LuaTableIterator iter(*this, 1);
		while (!iter.m_isDone) {
			LuaObject key = iter.GetKey();
			if (!key.ToByteStream(stream)) {
				success = false;
			}

			LuaObject value = iter.GetValue();
			if (!value.ToByteStream(stream)) {
				success = false;
			}

			iter.Next();
		}

		typeTag = 5;
		stream.Write(typeTag);
		return success;
	}

	if (IsUserData()) {
		gpg::Warnf("Attempt to serialize lua user data.");
		typeTag = 2;
		stream.Write(typeTag);
		return false;
	}

	gpg::Warnf("Attempt to serialize unsupported lua value.");
	typeTag = 2;
	stream.Write(typeTag);
	return false;
}

namespace LuaPlus
{
	/**
	 * Address: 0x004C7C70 (FUN_004C7C70, gpg::fastvector_LuaObject::clear)
	 *
	 * IDA signature:
	 * LuaPlus::LuaObject *__usercall std::vector_LuaObject::clear@<eax>(
	 *   gpg::fastvector_LuaObject *this@<edi>);
	 *
	 * What it does:
	 * Destroys every live `LuaPlus::LuaObject` element in one
	 * fastvector runtime view, then either keeps inline storage (when
	 * the active buffer matches the saved inline-origin pointer) or
	 * frees the active heap buffer and rebinds the view back to its
	 * inline lane, reading the saved inline-capacity sentinel from the
	 * first pointer slot of the inline buffer.
	 */
	void ClearAndResetLuaObjectFastVector(gpg::fastvector_runtime_view<LuaPlus::LuaObject>& view) noexcept
	{
		for (LuaPlus::LuaObject* it = view.begin; it != view.end; ++it) {
			it->~LuaObject();
		}

		gpg::FastVectorRuntimeResetToInline(view);
	}
}
