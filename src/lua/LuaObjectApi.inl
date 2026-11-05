// Part of LuaObject.cpp, included there: the C API (lapi).

	/**
	 * Address: 0x0090C900 (FUN_0090C900, lua_equal)
	 *
	 * What it does:
	 * Resolves two Lua API stack indices, validates same-type operands, then
	 * performs one Lua semantic equality test via `luaV_equalval`.
	 */
	int lua_equal(lua_State* const state, const int leftIndex, const int rightIndex)
	{
		TObject* leftObject = nullptr;
		if (leftIndex > 0) {
			TObject* const candidate = state->base + leftIndex - 1;
			if (candidate < state->top) {
				leftObject = candidate;
			}
		} else {
			leftObject = negindex(state, leftIndex);
		}

		TObject* rightObject = nullptr;
		if (rightIndex > 0) {
			TObject* const candidate = state->base + rightIndex - 1;
			if (candidate < state->top) {
				rightObject = candidate;
			}
		} else {
			rightObject = negindex(state, rightIndex);
		}

		return leftObject != nullptr
			&& rightObject != nullptr
			&& leftObject->tt == rightObject->tt
			&& luaV_equalval(state, leftObject, rightObject) != 0;
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
	 * What it does:
	 * Resolves one stack index the way every read-only lua_* accessor does:
	 * like `luaA_index`, except a positive index past the top yields nothing
	 * instead of a slot nobody pushed. The binary open-codes this three-line
	 * test at the head of each accessor rather than calling a helper.
	 */
	[[nodiscard]] TObject* luaA_indexAcceptable(lua_State* const state, const int stackIndex)
	{
		if (stackIndex <= 0) {
			return negindex(state, stackIndex);
		}

		TObject* const candidate = &state->base[stackIndex - 1];
		return candidate < state->top ? candidate : nullptr;
	}

	/**
	 * Address: 0x0090C340 (FUN_0090C340, negindex)
	 *
	 * IDA signature:
	 * TObject *__usercall negindex@<eax>(lua_State *L, int idx);
	 *
	 * What it does:
	 * Resolves a non-positive stack index to its slot. Ordinary negative
	 * indices count back from the top; below those sit the pseudo-indices -
	 * this fork adds a registry-by-integer range beneath the usual
	 * globals/registry pair, and anything lower still is an upvalue of the
	 * running C closure (null when the closure has no such upvalue).
	 *
	 * The thresholds are the literals in the disassembly, not the decompiler's
	 * symbol substitution:
	 *   0x0090C344  cmp edx, 0FFFFD8F0h   -10000  LUA_REGISTRYINDEX
	 *   0x0090C357  cmp edx, 0FFFF63C0h   -40000  kRegistryIntegerIndexBase
	 *   0x0090C37D  cmp edx, 0FFFFD8EFh   -10001  LUA_GLOBALSINDEX
	 */
	TObject* negindex(lua_State* const L, const int idx)
	{
		// Registry slots addressed by integer, a LuaPlus extension below the
		// stock pseudo-index pair.
		constexpr int kRegistryIntegerIndexBase = -40000;

		if (idx > LUA_REGISTRYINDEX) {
			return &L->top[idx];
		}

		if (idx < kRegistryIntegerIndexBase) {
			auto* const registry = static_cast<Table*>(L->l_G->_registry.value.p);
			return const_cast<TObject*>(luaH_getnum(registry, kRegistryIntegerIndexBase - idx));
		}

		if (idx == LUA_GLOBALSINDEX) {
			return &L->_gt;
		}

		if (idx == LUA_REGISTRYINDEX) {
			return &L->l_G->_registry;
		}

		// Upvalue of the running C closure, counted down from the globals
		// pseudo-index. `upvalue_m1` is the one-before-first lane the binary
		// indexes, so the subscript is used directly.
		GCObject* const closure = static_cast<GCObject*>(L->base[-1].value.p);
		const int upvalueIndex = LUA_GLOBALSINDEX - idx;
		if (upvalueIndex > closure->cl.c.nupvalues) {
			return nullptr;
		}

		return &closure->cl.c.upvalue_m1[upvalueIndex];
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
	 * Address: 0x0090C740 (FUN_0090C740, lua_type)
	 *
	 * IDA signature:
	 * int __cdecl lua_type(lua_State *L, int idx);
	 *
	 * What it does:
	 * Returns the type tag at `idx`, or LUA_TNONE for an index that addresses
	 * nothing: past the live top for a positive index, or a pseudo-index with
	 * no slot (an upvalue the running closure does not have).
	 */
	int lua_type(lua_State* const state, const int idx)
	{
		const TObject* slot = nullptr;
		if (idx > 0) {
			slot = &state->base[idx - 1];
			if (slot >= state->top) {
				return LUA_TNONE;
			}
		} else {
			slot = negindex(state, idx);
			if (slot == nullptr) {
				return LUA_TNONE;
			}
		}

		return slot->tt;
	}

	/**
	 * Address: 0x0090C780 (FUN_0090C780, lua_typename)
	 *
	 * IDA signature:
	 * const char *__cdecl lua_typename(lua_State *L, int t);
	 *
	 * What it does:
	 * Names one type tag. The state argument is unused - the table is global.
	 */
	const char* lua_typename([[maybe_unused]] lua_State* const state, const int t)
	{
		if (t == LUA_TNONE) {
			return "no value";
		}

		return luaT_typenames[t];
	}

	/**
	 * Address: 0x0090C6E0 (FUN_0090C6E0, lua_pushvalue)
	 *
	 * IDA signature:
	 * void __cdecl lua_pushvalue(lua_State *L, int idx);
	 *
	 * What it does:
	 * Copies the value at `idx` onto the top of the stack.
	 */
	void lua_pushvalue(lua_State* const state, const int idx)
	{
		*state->top = *luaA_index(state, idx);
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090C5F0 (FUN_0090C5F0, lua_remove)
	 *
	 * IDA signature:
	 * void __cdecl lua_remove(lua_State *L, int idx);
	 *
	 * What it does:
	 * Deletes the value at `idx`, shifting everything above it down one slot.
	 */
	void lua_remove(lua_State* const state, const int idx)
	{
		TObject* slot = luaA_index(state, idx);
		for (++slot; slot < state->top; ++slot) {
			slot[-1] = *slot;
		}

		--state->top;
	}

	/**
	 * Address: 0x0090C640 (FUN_0090C640, lua_insert)
	 *
	 * IDA signature:
	 * void __cdecl lua_insert(lua_State *L, int idx);
	 *
	 * What it does:
	 * Moves the top value down to `idx`, shifting everything from `idx` up one
	 * slot to make room. The stack height is unchanged.
	 */
	void lua_insert(lua_State* const state, const int idx)
	{
		TObject* const destination = luaA_index(state, idx);
		for (TObject* slot = state->top; slot > destination; --slot) {
			*slot = slot[-1];
		}

		*destination = *state->top;
	}

	/**
	 * Address: 0x0090C690 (FUN_0090C690, lua_replace)
	 *
	 * IDA signature:
	 * void __cdecl lua_replace(lua_State *L, int idx);
	 *
	 * What it does:
	 * Pops the top value and stores it into `idx`.
	 */
	void lua_replace(lua_State* const state, const int idx)
	{
		const TObject* const source = state->top - 1;
		*luaA_index(state, idx) = *source;
		--state->top;
	}

	/**
	 * Address: 0x0090CD80 (FUN_0090CD80, lua_pushlstring)
	 *
	 * IDA signature:
	 * void __cdecl lua_pushlstring(lua_State *L, const char *s, size_t len);
	 *
	 * What it does:
	 * Interns `len` bytes as a Lua string and pushes it, running the GC gate
	 * first because the intern may allocate.
	 */
	void lua_pushlstring(lua_State* const state, const char* const s, const size_t len)
	{
		luaC_checkGC(state);

		TString* const interned = luaS_newlstr(state, s, len);
		TObject* const top = state->top;
		top->tt = static_cast<int>(interned->tt);
		top->value.p = interned;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090D110 (FUN_0090D110, lua_newtable)
	 *
	 * IDA signature:
	 * void __cdecl lua_newtable(lua_State *L);
	 *
	 * What it does:
	 * Creates one empty table and pushes it, running the GC gate first because
	 * the table allocates.
	 */
	void lua_newtable(lua_State* const state)
	{
		luaC_checkGC(state);

		Table* const table = luaH_new(state, 0, 0);
		TObject* const top = state->top;
		top->tt = static_cast<int>(table->tt);
		top->value.p = table;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090C590 (FUN_0090C590, lua_gettop)
	 * Mangled: ?lua_gettop@@YAHPAUlua_State@@@Z
	 *
	 * IDA signature:
	 * int __cdecl lua_gettop(lua_State *L);
	 *
	 * What it does:
	 * Returns the number of values on the current frame's stack.
	 */
	int lua_gettop(lua_State* const state)
	{
		return static_cast<int>(state->top - state->base);
	}

	/**
	 * Address: 0x0090C5A0 (FUN_0090C5A0, lua_settop)
	 * Mangled: ?lua_settop@@YAXPAUlua_State@@H@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_settop(lua_State *L, int idx);
	 *
	 * What it does:
	 * Sets the stack height. A non-negative `idx` is an absolute height, and
	 * any slots opened up by growing are niled - only the tag is written, the
	 * value half is left as it was. A negative `idx` is relative to the
	 * current top, so -1 leaves the stack unchanged.
	 */
	void lua_settop(lua_State* const state, const int idx)
	{
		if (idx >= 0) {
			TObject* const target = state->base + idx;
			for (; state->top < target; ++state->top) {
				state->top->tt = LUA_TNIL;
			}

			state->top = target;
		} else {
			state->top += idx + 1;
		}
	}

	/**
	 * Address: 0x0090CD00 (FUN_0090CD00, lua_pushnil)
	 * Mangled: ?lua_pushnil@@YAXPAUlua_State@@@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_pushnil(lua_State *L);
	 *
	 * What it does:
	 * Pushes nil. Only the tag is written - the value half keeps whatever the
	 * slot held before.
	 */
	void lua_pushnil(lua_State* const state)
	{
		state->top->tt = LUA_TNIL;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090CD40 (FUN_0090CD40, lua_pushnumber)
	 * Mangled: ?lua_pushnumber@@YAXPAUlua_State@@M@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_pushnumber(lua_State *L, float n);
	 *
	 * What it does:
	 * Pushes a number. The binary takes a 4-byte float ("movss xmm0,[esp+n]")
	 * because this fork's Value::n is float - that is what makes TObject 8
	 * bytes instead of 12. The parameter is lua_Number, which the build
	 * defines as float (LUA_NUMBER=float in src/CMakeLists.txt), as the
	 * shipped engine was built.
	 */
	void lua_pushnumber(lua_State* const state, const lua_Number n)
	{
		TObject* const top = state->top;
		top->value.n = static_cast<float>(n);
		top->tt = LUA_TNUMBER;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090CF80 (FUN_0090CF80, lua_pushboolean)
	 *
	 * IDA signature:
	 * void __cdecl lua_pushboolean(lua_State *L, int b);
	 *
	 * What it does:
	 * Pushes a boolean, normalising any non-zero input to 1.
	 */
	void lua_pushboolean(lua_State* const state, const int b)
	{
		TObject* const top = state->top;
		top->tt = LUA_TBOOLEAN;
		top->value.b = (b != 0) ? 1 : 0;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090CFC0 (FUN_0090CFC0, lua_pushlightuserdata)
	 *
	 * IDA signature:
	 * void __cdecl lua_pushlightuserdata(lua_State *L, void *p);
	 *
	 * What it does:
	 * Pushes a raw pointer the collector does not own.
	 */
	void lua_pushlightuserdata(lua_State* const state, void* const p)
	{
		TObject* const top = state->top;
		top->tt = LUA_TLIGHTUSERDATA;
		SetLightPointer(top->value, p);
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090CDF0 (FUN_0090CDF0, lua_pushstring)
	 * Mangled: ?lua_pushstring@@YAXPAUlua_State@@PBD@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_pushstring(lua_State *L, const char *s);
	 *
	 * What it does:
	 * Pushes a NUL-terminated string, or nil when `s` is null.
	 */
	void lua_pushstring(lua_State* const state, const char* const s)
	{
		if (s == nullptr) {
			state->top->tt = LUA_TNIL;
			api_incr_top(state);
			return;
		}

		lua_pushlstring(state, s, std::strlen(s));
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
		luaC_checkGC(state);

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
	 * IDA signature:
	 * void __cdecl lua_setdefaultmetatable(lua_State *L, int type);
	 *
	 * What it does:
	 * Pops one value from stack top and, when that value is a table, writes it
	 * into the default-metatable slot for `type`.
	 */
	void lua_setdefaultmetatable(lua_State* const state, const int type)
	{
		TObject* const topValue = state->top - 1;
		if (topValue->tt == LUA_TTABLE) {
			state->l_G->_defaultmetatypes[type] = *topValue;
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
		return static_cast<int>(static_cast<std::uint32_t>(state->l_G->nblocks) >> 10);
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
		global_State* const globalState = state->l_G;
		if (static_cast<std::uint32_t>(newThreshold) <= 0x3FFFFFu) {
			globalState->GCthreshold = static_cast<std::uint32_t>(newThreshold) << 10;
		} else {
			globalState->GCthreshold = 0xFFFFFFFFu;
		}

		luaC_checkGC(state);
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
		luaC_checkGC(state);

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
	 * Address: 0x0090D8E0 (FUN_0090D8E0, lua_pushupvalues)
	 *
	 * What it does:
	 * Pushes all upvalue lanes from the current closure (`base[-1]`) onto the
	 * Lua stack, preserving the original growth guard (`nup + 20` slots).
	 */
	extern "C" int lua_pushupvalues(lua_State* const state)
	{
		const auto* const closure = static_cast<const Closure*>(state->base[-1].value.p);
		const int upvalueCount = static_cast<int>(closure->c.nupvalues);
		const int requiredStackSlots = upvalueCount + 20;

		if ((state->stack_last - state->top) <= requiredStackSlots) {
			luaD_growstack(state, requiredStackSlots);
		}

		const TObject* sourceUpvalue = &closure->c.upvalue[0];
		for (int upvalueIndex = 0; upvalueIndex < upvalueCount; ++upvalueIndex, ++sourceUpvalue) {
			TObject* const stackTop = state->top;
			*stackTop = *sourceUpvalue;
			state->top = stackTop + 1;
		}

		return upvalueCount;
	}

	/**
	 * Address: 0x0090D940 (FUN_0090D940, aux_upvalue)
	 *
	 * What it does:
	 * Resolves one upvalue pointer/name pair for either C closures
	 * (`upvalue_m1[n]`) or Lua closures (`upvals[n-1]` + `proto->upvalues[n-1]`)
	 * and returns null on type/index mismatch.
	 */
	const char* aux_upvalue(
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
	 * Address: 0x0090D9A0 (FUN_0090D9A0, lua_getupvalue)
	 *
	 * IDA signature:
	 * const char *__cdecl lua_getupvalue(lua_State *L, int funcindex, int n);
	 *
	 * What it does:
	 * Resolves upvalue `n` of the closure at `funcindex` through `aux_upvalue`
	 * and, when it exists, pushes its value onto the stack and returns its name.
	 *
	 * The push is `api_incr_top` open-coded, and this fork's version carries a
	 * stack check the stock one does not: at 0x0090D9D2 it compares the new top
	 * against `L->ci->top` and, only when the top has reached or passed it, also
	 * checks `L->stack_last - L->top` and grows by one slot when eight bytes or
	 * fewer remain. One TObject is eight bytes here, so that is "no room for the
	 * value we just wrote".
	 */
	extern "C" const char* lua_getupvalue(lua_State* const state, const int functionIndex, const int upvalueIndex)
	{
		TObject* valueSlot = nullptr;
		const char* const upvalueName = aux_upvalue(state, functionIndex, &valueSlot, upvalueIndex);
		if (upvalueName == nullptr) {
			return nullptr;
		}

		*state->top = *valueSlot;

		if (state->top >= state->ci->top && state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}
		++state->top;

		return upvalueName;
	}

	/**
	 * Address: 0x0090DA00 (FUN_0090DA00, lua_setupvalue)
	 *
	 * IDA signature:
	 * const char *__cdecl lua_setupvalue(lua_State *L, int funcindex, int n);
	 *
	 * What it does:
	 * Resolves upvalue `n` of the closure at `funcindex` through `aux_upvalue`
	 * and, when it exists, pops the stack top into it and returns its name.
	 *
	 * Note the asymmetry with `lua_getupvalue` above: the pop happens only on
	 * the success path (0x0090DA1F sits after the `test eax, eax` at 0x0090DA1B),
	 * so a failed lookup leaves the stack untouched.
	 */
	extern "C" const char* lua_setupvalue(lua_State* const state, const int functionIndex, const int upvalueIndex)
	{
		TObject* valueSlot = nullptr;
		const char* const upvalueName = aux_upvalue(state, functionIndex, &valueSlot, upvalueIndex);
		if (upvalueName == nullptr) {
			return nullptr;
		}

		--state->top;
		*valueSlot = *state->top;

		return upvalueName;
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
			// `negindex`, not `top + idx` (0x0090CB31 calls it). Anything at or
			// below LUA_REGISTRYINDEX is a pseudo-index - the registry, the globals
			// table, or a C closure upvalue - and top-relative arithmetic sends
			// those far below the stack base, where the guard below answers 0.
			// `string.gfind` measures its subject through `lua_upvalueindex(1)`, so
			// every iterator built by it saw a zero-length subject, matched
			// nothing, and yielded no words at all: `WrapText` returned no lines
			// and every wrapped string in the UI - dialog bodies, tooltips - came
			// out blank.
			object = negindex(state, idx);
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
	 * Address: 0x0090E9E0 (FUN_0090E9E0, tag_error)
	 *
	 * What it does:
	 * Formats one Lua type-mismatch message (`"%s expected, got %s"`) and raises
	 * argument error for the offending stack index.
	 */
	static int tag_error(const int expectedTag, const int argumentIndex, lua_State* const state)
	{
		const char* const expectedName = lua_typename(state, expectedTag);
		const int gotTag = lua_type(state, argumentIndex);
		const char* const gotName = lua_typename(state, gotTag);
		const char* const message = lua_pushfstring(state, "%s expected, got %s", expectedName, gotName);
		return luaL_argerror(state, argumentIndex, message);
	}

	// ---------------------------------------------------------------------
	// Public C API accessors that were still resolving to the prebuilt
	// LuaPlus library.
	//
	// Every one of these reads the lua_State and global_State this tree
	// builds, and the library's copies read them at stock offsets - so each
	// was a live fault waiting for the first script that touched it.
	// lua_getmetatable was the one that fired: tostring(ClientVersion) in
	// init_faf.lua reached luaL_callmeta, and the library's copy compared
	// against a defaultmeta it found at the wrong place and pushed a table
	// that was not one.
	// ---------------------------------------------------------------------

	/**
	 * Address: 0x0090D180 (FUN_0090D180, lua_getmetatable)
	 *
	 * IDA signature:
	 * int __cdecl lua_getmetatable(lua_State *L, int objindex);
	 *
	 * What it does:
	 * Pushes the metatable governing one value and always reports success.
	 * That is a fork change: stock Lua returns 0 and pushes nothing when the
	 * value has no metatable of its own, whereas here every type has one -
	 * tables and userdata carry theirs, everything else shares the per-type
	 * default - so `luaT_getmetatable` always has something to hand back.
	 */
	int lua_getmetatable(lua_State* const state, const int objindex)
	{
		const TObject* const object = luaA_indexAcceptable(state, objindex);
		Table* const metatable = luaT_getmetatable(state, object);

		state->top->tt = static_cast<int>(metatable->tt);
		state->top->value.p = metatable;
		api_incr_top(state);
		return 1;
	}

	/**
	 * What it does:
	 * Returns the raw pointer behind a userdata slot: the payload for a full
	 * userdata, the stored pointer for a light one.
	 *
	 * The shipped binary has no lua_touserdata - every site that wants this
	 * open-codes it, as func_GetRRefFromUserdata does at 0x0090CBB0 - but this
	 * tree calls it from eight places, so it needs a body here. Without one it
	 * resolved to the prebuilt LuaPlus copy, which tests stock's LUA_TUSERDATA
	 * of 7; this fork numbers cfunction 6, function 7, full userdata 8. Every
	 * one of those eight calls was therefore answering null.
	 */
	void* lua_touserdata(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		if (object == nullptr) {
			return nullptr;
		}

		switch (object->tt) {
			case LUA_TUSERDATA:
				return static_cast<std::uint8_t*>(object->value.p) + sizeof(Udata);
			case LUA_TLIGHTUSERDATA:
				return LightPointer(object->value);
			default:
				return nullptr;
		}
	}

	/**
	 * Address: 0x0090C9F0 (FUN_0090C9F0, lua_tonumber)
	 *
	 * What it does:
	 * Reads one stack slot as a number, parsing a numeric string on the way
	 * through a scratch slot. Anything else reads as zero.
	 */
	lua_Number lua_tonumber(lua_State* const state, const int idx)
	{
		const TObject* object = luaA_indexAcceptable(state, idx);
		if (object == nullptr) {
			return 0.0f;
		}

		TObject scratch{};
		if (object->tt != LUA_TNUMBER) {
			object = luaV_tonumber(object, &scratch);
			if (object == nullptr) {
				return 0.0f;
			}
		}

		return object->value.n;
	}

	/**
	 * Address: 0x0090C7A0 (FUN_0090C7A0, lua_isnumber)
	 *
	 * What it does:
	 * Reports whether one stack slot is a number or a string that parses as
	 * one.
	 */
	int lua_isnumber(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		if (object == nullptr) {
			return 0;
		}

		TObject scratch{};
		return (object->tt == LUA_TNUMBER || luaV_tonumber(object, &scratch) != nullptr) ? 1 : 0;
	}

	/**
	 * Address: 0x0090C800 (FUN_0090C800, lua_isstring)
	 *
	 * What it does:
	 * Reports whether one stack slot holds a string. Note this fork does not
	 * accept a number here the way stock Lua does - the tag test is exact.
	 */
	int lua_isstring(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		return (object != nullptr && object->tt == LUA_TSTRING) ? 1 : 0;
	}

	/**
	 * Address: 0x0090C890 (FUN_0090C890, lua_rawequal)
	 *
	 * What it does:
	 * Compares two stack slots by identity, without consulting `__eq`.
	 */
	int lua_rawequal(lua_State* const state, const int index1, const int index2)
	{
		const TObject* const left = luaA_indexAcceptable(state, index1);
		const TObject* const right = luaA_indexAcceptable(state, index2);
		return (left != nullptr && right != nullptr && luaO_rawequalObj(left, right) != 0) ? 1 : 0;
	}

	/**
	 * Address: 0x0090C980 (FUN_0090C980, lua_lessthan)
	 *
	 * What it does:
	 * Orders two stack slots with full `__lt` semantics.
	 */
	int lua_lessthan(lua_State* const state, const int index1, const int index2)
	{
		const TObject* const left = luaA_indexAcceptable(state, index1);
		const TObject* const right = luaA_indexAcceptable(state, index2);
		if (left == nullptr || right == nullptr) {
			return 0;
		}

		return luaV_lessthan(state, left, right);
	}

	/**
	 * Address: 0x0090CA40 (FUN_0090CA40, lua_toboolean)
	 *
	 * What it does:
	 * Reads one stack slot and reports whether it is "truthy" - anything
	 * except nil and the boolean `false` counts as true. An out-of-range
	 * positive index (at or past the stack top) short-circuits to false
	 * without consulting the tag at all.
	 */
	int lua_toboolean(lua_State* const state, const int idx)
	{
		TObject* object = nullptr;
		if (idx <= 0) {
			object = negindex(state, idx);
		} else {
			object = &state->base[idx - 1];
			if (object >= state->top) {
				return 0;
			}
		}

		return (object != nullptr && object->tt != LUA_TNIL &&
			(object->tt != LUA_TBOOLEAN || object->value.b != 0)) ? 1 : 0;
	}

	/** Engine addition (the binary has no use for it): the function a C function value calls. */
	lua_CFunction lua_tocfunction(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		if (object == nullptr || object->tt != LUA_CFUNCTION) {
			return nullptr;
		}
		return static_cast<const Closure*>(object->value.p)->c.f;
	}

	/**
	 * Address: 0x0090CC90 (FUN_0090CC90, lua_topointer)
	 *
	 * What it does:
	 * Returns an identity pointer for the collectable value at one index -
	 * the payload itself for userdata, the object for everything else, and
	 * nothing for values that are not collectable.
	 */
	const void* lua_topointer(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		if (object == nullptr) {
			return nullptr;
		}

		switch (object->tt) {
			case LUA_TLIGHTUSERDATA:
				return LightPointer(object->value);
			case LUA_TTABLE:
			case LUA_CFUNCTION:
			case LUA_TFUNCTION:
			case LUA_TTHREAD:
				return object->value.p;
			case LUA_TUSERDATA:
				// Full userdata identifies by its payload, which starts one
				// header past the object - `add eax, 10h`.
				return static_cast<const std::uint8_t*>(object->value.p) + sizeof(Udata);
			default:
				return nullptr;
		}
	}

	/**
	 * Address: 0x0090CC50 (FUN_0090CC50, lua_tothread)
	 *
	 * What it does:
	 * Returns the coroutine at one index, or nothing when the slot holds
	 * something else.
	 */
	lua_State* lua_tothread(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_indexAcceptable(state, idx);
		if (object == nullptr || object->tt != LUA_TTHREAD) {
			return nullptr;
		}

		return static_cast<lua_State*>(object->value.p);
	}

	/**
	 * Address: 0x0090C4C0 (FUN_0090C4C0, lua_xmove)
	 *
	 * What it does:
	 * Moves `n` values off one thread's stack and onto another's, in order.
	 * Both threads share a global_State, so the values are copied as they are.
	 *
	 * `add [ebx+8], eax` with eax = -n*8 is the source pop; the loop then reads
	 * `[ecx+edi*8]` and its +4 half, which is one 8-byte TObject per step.
	 */
	void lua_xmove(lua_State* const from, lua_State* const to, const int n)
	{
		from->top -= n;
		for (int index = 0; index < n; ++index) {
			*to->top = from->top[index];
			api_incr_top(to);
		}
	}

	/**
	 * Address: 0x0090C460 (FUN_0090C460, lua_checkstack)
	 *
	 * What it does:
	 * Makes room for `size` more slots, growing the stack and widening the
	 * current frame's ceiling if that is what it takes. Reports failure only
	 * when the request would push the frame past the API stack limit.
	 */
	int lua_checkstack(lua_State* const state, const int size)
	{
		constexpr int kMaxApiStackSlots = 0x800; // "cmp edx, 800h" at 0x0090C476

		if (size + (state->top - state->base) > kMaxApiStackSlots) {
			return 0;
		}

		if (state->stack_last - state->top <= size) {
			luaD_growstack(state, size);
		}

		StkId const requiredTop = state->top + size;
		if (state->ci->top < requiredTop) {
			state->ci->top = requiredTop;
		}

		return 1;
	}

	/**
	 * Address: 0x0090EA70 (FUN_0090EA70, luaL_checkany)
	 *
	 * What it does:
	 * Requires that an argument slot exists at all. The decompile shows it
	 * returning lua_type's result, but that is just the value left in EAX by
	 * the tail call - the declared shape is void, as in stock Lua.
	 */
	void luaL_checkany(lua_State* const state, const int narg)
	{
		if (lua_type(state, narg) == LUA_TNONE) {
			(void)luaL_argerror(state, narg, "value expected");
		}
	}

	/**
	 * Address: 0x0090EA20 (FUN_0090EA20, luaL_checktype)
	 *
	 * What it does:
	 * Requires that an argument slot holds exactly type `t`.
	 */
	void luaL_checktype(lua_State* const state, const int narg, const int t)
	{
		if (lua_type(state, narg) != t) {
			(void)tag_error(t, narg, state);
		}
	}

	/**
	 * Address: 0x0090EAA0 (FUN_0090EAA0, luaL_checklstring)
	 *
	 * What it does:
	 * Requires that an argument slot reads as a string, optionally reporting
	 * its length.
	 */
	const char* luaL_checklstring(lua_State* const state, const int narg, size_t* const len)
	{
		const char* const text = lua_tostring(state, narg);
		if (text == nullptr) {
			(void)tag_error(LUA_TSTRING, narg, state);
		}

		if (len != nullptr) {
			*len = lua_strlen(state, narg);
		}

		return text;
	}

	/**
	 * Address: 0x0090EB10 (FUN_0090EB10, luaL_optlstring)
	 *
	 * What it does:
	 * Same as `luaL_checklstring`, except an absent or nil argument yields
	 * the caller's default.
	 */
	const char* luaL_optlstring(
		lua_State* const state,
		const int narg,
		const char* const def,
		size_t* const len
	)
	{
		if (lua_type(state, narg) > LUA_TNIL) {
			return luaL_checklstring(state, narg, len);
		}

		if (len != nullptr) {
			*len = (def != nullptr) ? std::strlen(def) : 0u;
		}

		return def;
	}

	/**
	 * Address: 0x0090EB70 (FUN_0090EB70, luaL_checknumber)
	 *
	 * What it does:
	 * Requires that an argument slot reads as a number. Zero is ambiguous -
	 * lua_tonumber returns it both for the number zero and for anything
	 * unconvertible - so that one case is re-tested with lua_isnumber.
	 */
	lua_Number luaL_checknumber(lua_State* const state, const int narg)
	{
		const lua_Number value = lua_tonumber(state, narg);
		if (value == 0.0f && lua_isnumber(state, narg) == 0) {
			(void)tag_error(LUA_TNUMBER, narg, state);
		}

		return value;
	}

	/**
	 * Address: 0x0090D6D0 (FUN_0090D6D0, lua_next)
	 *
	 * What it does:
	 * Advances one table traversal: takes the key on top, replaces it with the
	 * next key and pushes that key's value. On reaching the end it pops the key
	 * and reports 0.
	 *
	 * Note the index resolution here is `luaA_index`, not the acceptable-index
	 * form the read-only accessors use - a positive index past the top is not
	 * defended against, because a caller that has no table there is already
	 * wrong.
	 */
	int lua_next(lua_State* const state, const int idx)
	{
		const TObject* const table = luaA_index(state, idx);
		const int hasMore = luaH_next(state, static_cast<Table*>(table->value.p), state->top - 1);

		if (hasMore == 0) {
			--state->top; // traversal finished: drop the key
			return 0;
		}

		api_incr_top(state); // key was replaced in place; publish its value
		return hasMore;
	}

	/**
	 * Address: 0x0090D0A0 (FUN_0090D0A0, lua_rawgeti)
	 *
	 * What it does:
	 * Pushes `t[n]` for an integer key without consulting `__index`.
	 */
	void lua_rawgeti(lua_State* const state, const int idx, const int n)
	{
		const TObject* const table = luaA_index(state, idx);
		*state->top = *luaH_getnum(static_cast<Table*>(table->value.p), n);
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090D6C0 (FUN_0090D6C0, lua_error)
	 *
	 * What it does:
	 * Raises the value on top of the stack as an error. The binary's body is a
	 * bare tail call to luaG_errormsg with no return value, because this fork
	 * throws rather than longjmps and control never comes back; the int here is
	 * only what the API declaration asks for.
	 */
	int lua_error(lua_State* const state)
	{
		luaG_errormsg(state);
		return 0; // unreachable
	}

	/**
	 * Address: 0x0090D1F0 (FUN_0090D1F0, lua_getfenv)
	 *
	 * What it does:
	 * Pushes the environment of the function at `idx`; anything that is not a
	 * Lua closure answers with the running thread's globals.
	 */
	void lua_getfenv(lua_State* const state, const int idx)
	{
		const TObject* const object = luaA_index(state, idx);
		const TObject* const environment = (object->tt == LUA_TFUNCTION)
			? &static_cast<GCObject*>(object->value.p)->cl.l.g
			: &state->_gt;

		*state->top = *environment;
		api_incr_top(state);
	}

	/**
	 * Address: 0x0090D3B0 (FUN_0090D3B0, lua_setfenv)
	 *
	 * What it does:
	 * Pops a value and installs it as the environment of the Lua closure at
	 * `idx`. The value is consumed either way; only the assignment is
	 * conditional.
	 */
	int lua_setfenv(lua_State* const state, const int idx)
	{
		TObject* const object = luaA_index(state, idx);
		--state->top;

		if (object->tt != LUA_TFUNCTION) {
			return 0;
		}

		static_cast<GCObject*>(object->value.p)->cl.l.g = *state->top;
		return 1;
	}

	/**
	 * Address: 0x0090AD30 (FUN_0090AD30, lua_getn)
	 *
	 * What it does:
	 * Answers a table's length the way this fork defines it: an `n` field wins
	 * outright; otherwise it is the larger of the array part's last non-nil
	 * index and the largest numeric key in the hash part.
	 */
	int lua_getn(lua_State* const state, const int index)
	{
		const TObject* const object = luaA_index(state, index);
		Table* const table = static_cast<Table*>(object->value.p);

		TString* const nField = luaS_newlstr(state, "n", 1u);
		const TObject* const recorded = luaH_getstr(table, nField);
		if (recorded->tt == LUA_TNUMBER) {
			return static_cast<int>(recorded->value.n);
		}

		// Walk the array part back to its last non-nil slot. An empty or
		// all-nil array leaves the index at -1, so the count comes out zero.
		int lastArrayIndex = table->sizearray - 1;
		for (; lastArrayIndex >= 0; --lastArrayIndex) {
			if (table->array[lastArrayIndex].tt != LUA_TNIL) {
				break;
			}
		}

		auto largest = static_cast<float>(lastArrayIndex + 1);

		const Node* node = table->node;
		for (int remaining = 1 << table->lsizenode; remaining != 0; --remaining, ++node) {
			if (node->KeyIs(LUA_TNUMBER) && node->i_val.tt != LUA_TNIL && node->KeyValue().n > largest) {
				largest = node->KeyValue().n;
			}
		}

		return static_cast<int>(largest);
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

		return LightPointer(object->value);
	}

	/**
	 * Address: 0x0090ADE0 (FUN_0090ADE0)
	 *
	 * What it does:
	 * Loads one light-userdata function pointer from pseudo-index `-10002` and
	 * invokes that callback with the current Lua state.
	 */
	int lua_calllightuserdata(lua_State* const state)
	{
		using LuaRegistryStdCall = int(__stdcall*)(lua_State*);
		auto* const callback = reinterpret_cast<LuaRegistryStdCall>(lua_tolightuserdata(state, -10002));
		return callback(state);
	}

	/**
	 * Address: 0x0090AE30 (FUN_0090AE30)
	 *
	 * What it does:
	 * Copies one Lua string value (including trailing `\0`) from stack index
	 * `idx` into caller-provided destination storage.
	 */
	char* lua_copystring_to_buffer(lua_State* const state, const int idx, void* const destination)
	{
		char* const source = const_cast<char*>(lua_tostring(state, idx));
		const size_t length = lua_strlen(state, idx);
		// Raw Lua string blob copy including the trailing NUL.
		std::copy_n(source, length + 1u, static_cast<char*>(destination));
		return static_cast<char*>(destination);
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
	void luaI_addquoted(lua_State* const state, const int argumentIndex, luaL_Buffer* const buffer)
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
		case LUA_TBOOLEAN:
			// 0x0091A5A8 compares the 4-byte value word. Booleans are written
			// through `b`, which on x64 leaves the upper half of `p` holding
			// whatever the slot held before, so compare `b`.
			return (t1->value.b == t2->value.b) ? 1 : 0;
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
	 * Address: 0x00913810 (FUN_00913810)
	 *
	 * What it does:
	 * Interns one C-string, writes that tagged string object into caller-chosen
	 * stack slot `slot`, and moves `L->top` to one-past that slot.
	 */
	TString* PushLuaStringAtStackSlot(
		lua_State* const L,
		TObject* const slot,
		const char* const source
	)
	{
		TString* const stringObject = luaS_newlstr(L, source, std::strlen(source));
		slot->tt = stringObject->tt;
		slot->value.p = stringObject;
		L->top = slot + 1;
		return stringObject;
	}

	/**
	 * Address: 0x0091A640 (FUN_0091A640, pushstr)
	 *
	 * What it does:
	 * Interns one Lua string, writes the tagged string object into the current
	 * stack slot, and grows the stack if only one slot of headroom remains.
	 */
	TString* pushstr(lua_State* const state, const char* const source)
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
		GCObject** const newHash = luaM_newvector<GCObject*>(state, static_cast<lu_mem>(newsize));
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

		luaM_freearray<GCObject*>(state, globalState->strt.hash, static_cast<lu_mem>(globalState->strt.size));
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
		constexpr int kLuaStringTableMaxGrowth = 0x3FFFFFFE;

		GCObject* const object = static_cast<GCObject*>(luaM_reallocblock(state, nullptr, {0u, 0u}, sizestring(length)));
		TString* const stringObject = &object->ts;
		stringObject->len = length;
		stringObject->hash = hashValue;
		stringObject->marked = 0u;
		stringObject->tt = LUA_TSTRING;
		stringObject->reserved = 0;

		if (length != 0 && source != nullptr) {
			// Raw char blob copy into Lua string storage.
			std::copy_n(source, length, stringObject->str);
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
