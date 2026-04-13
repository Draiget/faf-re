#include "LuaObject.h"

#include <cerrno>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <io.h>
#include <limits>
#include <new>
#include <sstream>
#include <string>
#include <stdexcept>

#include "LuaAssertion.h"
#include "LuaTableIterator.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Logging.h"

using namespace LuaPlus;

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
}

struct FuncState;
struct expdesc;

extern "C"
{
	void luaC_collectgarbage(lua_State* L);
	Closure* luaF_newCclosure(lua_State* L, int nelems);
	void luaD_growstack(lua_State* L, int n);
	void* luaM_realloc(lua_State* L, void* oldblock, lu_mem oldsize, lu_mem size);
	void* luaM_growaux(lua_State* L, void* block, int* size, int sizeElem, int limit, const char* what);
	void luaG_runerror(lua_State* L, const char* format, ...);
	void discharge2reg(expdesc* e, int reg, FuncState* fs);
	void luaX_checklimit(void* ls, int v, int l, const char* what);
	void luaX_syntaxerror(void* ls, const char* msg);
	const TObject* luaH_getnum(Table* t, int key);
	TObject* luaH_set(lua_State* L, Table* t, const TObject* key);
	TObject* luaH_setnum(lua_State* L, Table* t, int key);

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
		void luaD_reallocCI(lua_State* L, int newsize);
		void luaD_growstack(lua_State* L, int n);
		void* luaM_realloc(lua_State* L, void* oldblock, lu_mem oldsize, lu_mem size);
		void correctstack(lua_State* L, TObject* oldstack);
		extern const char* luaT_typenames[];
		extern const TObject luaO_nilobject;
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
		if (luaL_loadbuffer(state, chunkText, chunkLength, chunkName) == 0) {
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
 * Address: 0x009075D0 (FUN_009075D0, LuaPlus::LuaObject::~LuaObject)
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
 * Address: 0x00907360 (FUN_00907360, LuaPlus::LuaObject::IsNumber)
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

void LuaObject::AssignBoolean(LuaState* state, const bool value)
{
	RebindToState(*this, state);
	m_object.tt = LUA_TBOOLEAN;
	m_object.value.b = value ? 1 : 0;
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

void LuaObject::Register(const char* key, CFunction value, const int32_t tagMethod)
{
	Ensure(m_state != nullptr, "m_state");
	Ensure(key != nullptr, "key");
	Ensure(value != nullptr, "value");

	lua_State* lstate = GetActiveCState();
	Ensure(lstate != nullptr, "active lua state");

	const int oldTop = lua_gettop(lstate);
	PushStack(lstate);
	lua_pushstring(lstate, key);
	lua_pushcfunction(lstate, value);
	lua_settable(lstate, -3);
	lua_settop(lstate, oldTop);

	(void)tagMethod;
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

const char* LuaObject::ToString() const
{
	if (IsString()) {
		return GetString();
	}

	if (IsNil()) {
		return "nil";
	}

	if (IsBoolean()) {
		return GetBoolean() ? "true" : "false";
	}

	thread_local std::string scratch;
	if (IsNumber()) {
		scratch = std::to_string(GetNumber());
		return scratch.c_str();
	}

	lua_State* const state = GetActiveCState();
	return state ? lua_typename(state, m_object.tt) : "unknown";
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
