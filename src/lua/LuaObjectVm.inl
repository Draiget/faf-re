// Part of LuaObject.cpp, included there: closures, the VM and state setup (lfunc, lvm, lstate).

	/**
	 * Address: 0x00914F40 (FUN_00914F40, luaF_newupval)
	 *
	 * What it does:
	 * Allocates an upvalue, links it for collection and points `v` at its own
	 * `value`, making it a closed upvalue. The value itself is left for the
	 * caller: the only one is the archive load, which reads it next.
	 */
	UpVal* luaF_newupval(lua_State* const state)
	{
		auto* const upvalue = luaM_new<UpVal>(state);
		upvalue->v = &upvalue->value;
		luaC_link(state, reinterpret_cast<GCObject*>(upvalue), LUA_TUPVALUE);
		return upvalue;
	}

	/**
	 * Address: 0x009138D0 (FUN_009138D0, luaD_reallocstack)
	 *
	 * IDA signature:
	 * void __cdecl luaD_reallocstack(lua_State *L, int newsize);
	 *
	 * What it does:
	 * Resizes the value stack and re-points everything that held a slot into
	 * the old block. `stack_last` is kept six slots short of the end, which is
	 * the headroom the API relies on for pushes that do not check first.
	 */
	void luaD_reallocstack(lua_State* const state, const int newsize)
	{
		constexpr int kStackHeadroom = 6;

		StkId const oldStack = state->stack;
		auto* const newStack = luaM_reallocvector<TObject>(
			state, oldStack, static_cast<lu_mem>(state->stacksize), static_cast<lu_mem>(newsize)
		);

		state->stack_last = &newStack[newsize - kStackHeadroom];
		state->stack = newStack;
		state->stacksize = newsize;
		correctstack(state, oldStack);
	}

	/**
	 * Address: 0x00913920 (FUN_00913920, luaD_reallocCI)
	 *
	 * IDA signature:
	 * CallInfo *__cdecl luaD_reallocCI(lua_State *L, int newsize);
	 *
	 * What it does:
	 * Resizes the call-info array, rebasing the current frame pointer onto the
	 * new block. Note the frame count is truncated to 16 bits when end_ci is
	 * computed, matching size_ci's width.
	 */
	void luaD_reallocCI(lua_State* const state, const int newsize)
	{
		CallInfo* const oldBase = state->base_ci;
		const ptrdiff_t activeFrame = state->ci - oldBase;

		auto* const newBase = luaM_reallocvector<CallInfo>(
			state, oldBase, static_cast<lu_mem>(state->size_ci), static_cast<lu_mem>(newsize)
		);

		state->ci = &newBase[activeFrame];
		state->size_ci = static_cast<std::uint16_t>(newsize);
		state->base_ci = newBase;
		state->end_ci = &newBase[static_cast<std::uint16_t>(newsize)];
	}

	/**
	 * Address: 0x0090DF30 (FUN_0090DF30, getsizes)
	 *
	 * IDA signature:
	 * void __usercall getsizes(lua_State *L@<esi>);
	 *
	 * What it does:
	 * Pushes the registry's weak-keyed table of array sizes, creating it on
	 * first use. Weak keys mean a table recorded here does not keep itself
	 * alive just by having had its length cached.
	 */
	static void getsizes(lua_State* const state)
	{
		constexpr int kRegistrySizesKey = 2;

		lua_rawgeti(state, LUA_REGISTRYINDEX, kRegistrySizesKey);
		if (lua_type(state, -1) != LUA_TNIL) {
			return;
		}

		lua_settop(state, -2);
		lua_newtable(state);
		lua_pushvalue(state, -1);
		(void)lua_setmetatable(state, -2);
		lua_pushlstring(state, "__mode", 6u);
		lua_pushlstring(state, "k", 1u);
		lua_rawset(state, -3);
		lua_pushvalue(state, -1);
		lua_rawseti(state, LUA_REGISTRYINDEX, kRegistrySizesKey);
	}

	/**
	 * Address: 0x0090DFB0 (FUN_0090DFB0, luaL_setn)
	 *
	 * IDA signature:
	 * void __cdecl luaL_setn(lua_State *L, int t, int n);
	 *
	 * What it does:
	 * Records a table's length. A table that already carries an `n` field keeps
	 * using it; otherwise the size goes in the weak side table, so the table
	 * itself is left unmodified.
	 */
	void luaL_setn(lua_State* const state, int t, const int n)
	{
		if (static_cast<unsigned int>(t) >= 0xFFFFD8F1u || t == 0) {
			t += lua_gettop(state) + 1;
		}

		lua_pushlstring(state, "n", 1u);
		lua_rawget(state, t);

		int recorded = static_cast<int>(lua_tonumber(state, -1));
		if (recorded == 0 && lua_isnumber(state, -1) == 0) {
			recorded = -1;
		}

		lua_settop(state, -2);

		if (recorded < 0) {
			getsizes(state);
			lua_pushvalue(state, t);
			lua_pushnumber(state, static_cast<lua_Number>(n));
			lua_rawset(state, -3);
			lua_settop(state, -2);
			return;
		}

		lua_pushlstring(state, "n", 1u);
		lua_pushnumber(state, static_cast<lua_Number>(n));
		lua_rawset(state, t);
	}

	/**
	 * Address: 0x0090E090 (FUN_0090E090, luaL_getn)
	 *
	 * IDA signature:
	 * int __cdecl luaL_getn(lua_State *L, int t);
	 *
	 * What it does:
	 * Reports a table's length, in the order the `n` field, then the weak side
	 * table, then an actual count from index 1 up to the first nil.
	 */
	int luaL_getn(lua_State* const state, int t)
	{
		if (static_cast<unsigned int>(t) >= 0xFFFFD8F1u || t == 0) {
			t += lua_gettop(state) + 1;
		}

		lua_pushlstring(state, "n", 1u);
		lua_rawget(state, t);

		int recorded = static_cast<int>(lua_tonumber(state, -1));
		if (recorded == 0 && lua_isnumber(state, -1) == 0) {
			recorded = -1;
		}

		lua_settop(state, -2);
		if (recorded >= 0) {
			return recorded;
		}

		getsizes(state);
		lua_pushvalue(state, t);
		lua_rawget(state, -2);

		recorded = static_cast<int>(lua_tonumber(state, -1));
		if (recorded == 0 && lua_isnumber(state, -1) == 0) {
			recorded = -1;
		}

		lua_settop(state, -3);
		if (recorded >= 0) {
			return recorded;
		}

		int index = 1;
		lua_rawgeti(state, t, index);
		while (lua_type(state, -1) != LUA_TNIL) {
			lua_settop(state, -2);
			lua_rawgeti(state, t, ++index);
		}

		lua_settop(state, -2);
		return index - 1;
	}

	/**
	 * Address: 0x00915090 (FUN_00915090, luaF_freeproto)
	 *
	 * IDA signature:
	 * void __cdecl luaF_freeproto(lua_State *L, Proto *f);
	 *
	 * What it does:
	 * Releases a prototype and every array hanging off it, the prototype
	 * itself last.
	 */
	void luaF_freeproto(lua_State* const state, Proto* const proto)
	{
		luaM_freearray<Instruction>(state, proto->code, static_cast<lu_mem>(proto->sizecode));
		luaM_freearray<Proto*>(state, proto->p, static_cast<lu_mem>(proto->sizep));
		luaM_freearray<TObject>(state, proto->k, static_cast<lu_mem>(proto->sizek));
		luaM_freearray<int>(state, proto->lineinfo, static_cast<lu_mem>(proto->sizelineinfo));
		luaM_freearray<LocVar>(state, proto->locvars, static_cast<lu_mem>(proto->sizelocvars));
		luaM_freearray<TString*>(state, proto->upvalues, static_cast<lu_mem>(proto->sizeupvalues));
		luaM_freelem<Proto>(state, proto);
	}

	/**
	 * Address: 0x00929680 (FUN_00929680, luaV_strcmp)
	 *
	 * IDA signature:
	 * int __usercall luaV_strcmp(const TString *ls@<ecx>, const TString *rs@<eax>);
	 *
	 * What it does:
	 * Orders two Lua strings by locale. They may contain embedded NULs, so a
	 * single strcoll is not enough: when the compared runs tie, whichever
	 * string ends at that NUL sorts first, and if neither does the comparison
	 * resumes past it.
	 */
	static int luaV_strcmp(const TString* const ls, const TString* const rs)
	{
		const char* left = ls->str;
		const char* right = rs->str;
		size_t leftRemaining = ls->len;
		size_t rightRemaining = rs->len;

		for (;;) {
			const int ordering = std::strcoll(left, right);
			if (ordering != 0) {
				return ordering;
			}

			// Equal up to a NUL: whoever ran out is the smaller string.
			const size_t run = std::strlen(left);
			if (run == rightRemaining) {
				return (run == leftRemaining) ? 0 : 1;
			}

			if (run == leftRemaining) {
				return -1;
			}

			const size_t consumed = run + 1u;
			left += consumed;
			right += consumed;
			leftRemaining -= consumed;
			rightRemaining -= consumed;
		}
	}

	/**
	 * Address: 0x00913460 (FUN_00913460, luaG_ordererror)
	 *
	 * IDA signature:
	 * void __cdecl luaG_ordererror(lua_State *L, const TObject *p1, const TObject *p2);
	 *
	 * What it does:
	 * Reports two values that cannot be ordered. The binary distinguishes
	 * "two %s values" from "%s with %s" by comparing the third character of
	 * the two type names, which is enough to separate every pair in
	 * luaT_typenames.
	 */
	void luaG_ordererror(lua_State* const state, const TObject* const left, const TObject* const right)
	{
		const char* const leftName = luaT_typenames[left->tt];
		const char* const rightName = luaT_typenames[right->tt];

		if (leftName[2] == rightName[2]) {
			luaG_runerror(state, "attempt to compare two %s values", leftName);
		}

		luaG_runerror(state, "attempt to compare %s with %s", leftName, rightName);
	}

	/**
	 * Address: 0x009296F0 (FUN_009296F0, luaV_lessthan)
	 *
	 * IDA signature:
	 * int __cdecl luaV_lessthan(lua_State *L, const TObject *l, const TObject *r);
	 *
	 * What it does:
	 * Evaluates `l < r`. Values of different tags order by tag alone; numbers
	 * and strings compare directly; anything else goes to `__lt`.
	 */
	int luaV_lessthan(lua_State* const state, const TObject* const left, const TObject* const right)
	{
		constexpr int kTagMethodLess = 14;

		if (left->tt != right->tt) {
			return left->tt < right->tt;
		}

		if (left->tt == LUA_TNUMBER) {
			return right->value.n > left->value.n;
		}

		if (left->tt == LUA_TSTRING) {
			return luaV_strcmp(
				static_cast<const TString*>(left->value.p),
				static_cast<const TString*>(right->value.p)
			) < 0;
		}

		const int viaTagMethod = call_orderTM(state, left, right, kTagMethodLess);
		if (viaTagMethod == -1) {
			luaG_ordererror(state, left, right);
		}

		return viaTagMethod;
	}

	/**
	 * Address: 0x00929770 (FUN_00929770, luaV_lessequal)
	 *
	 * IDA signature:
	 * int __usercall luaV_lessequal(const TObject *l@<edi>, const TObject *r@<esi>, lua_State *L);
	 *
	 * What it does:
	 * Evaluates `l <= r`. With no `__le` it falls back to `not (r < l)`, which
	 * is what makes a type that only defines `__lt` still usable with `<=`.
	 */
	int luaV_lessequal(lua_State* const state, const TObject* const left, const TObject* const right)
	{
		constexpr int kTagMethodLess = 14;
		constexpr int kTagMethodLessEqual = 15;

		if (left->tt != right->tt) {
			return left->tt < right->tt;
		}

		if (left->tt == LUA_TNUMBER) {
			return right->value.n >= left->value.n;
		}

		if (left->tt == LUA_TSTRING) {
			return luaV_strcmp(
				static_cast<const TString*>(left->value.p),
				static_cast<const TString*>(right->value.p)
			) <= 0;
		}

		const int viaLessEqual = call_orderTM(state, left, right, kTagMethodLessEqual);
		if (viaLessEqual != -1) {
			return viaLessEqual;
		}

		const int viaLess = call_orderTM(state, right, left, kTagMethodLess);
		if (viaLess == -1) {
			luaG_ordererror(state, left, right);
		}

		return viaLess == 0;
	}

	/**
	 * Address: 0x00929810 (FUN_00929810, luaV_equalval)
	 *
	 * IDA signature:
	 * int __cdecl luaV_equalval(lua_State *L, const TObject *l, const TObject *r);
	 *
	 * What it does:
	 * Compares two values already known to share a tag. Primitives compare by
	 * payload; tables and userdata are equal when they are the same object, and
	 * otherwise consult `__eq` - which only applies when both sides carry the
	 * same handler.
	 */
	int luaV_equalval(lua_State* const state, const TObject* const left, const TObject* const right)
	{
		constexpr int kTagMethodEqual = 3;

		Table* leftMetatable = nullptr;
		Table* rightMetatable = nullptr;

		switch (left->tt) {
			case LUA_TNIL:
				return 1;
			case LUA_TBOOLEAN:
				return left->value.b == right->value.b;
			case LUA_TNUMBER:
				return left->value.n == right->value.n;
			case LUA_TTABLE: {
				auto* const leftTable = static_cast<Table*>(left->value.p);
				auto* const rightTable = static_cast<Table*>(right->value.p);
				if (leftTable == rightTable) {
					return 1;
				}
				leftMetatable = leftTable->metatable;
				rightMetatable = rightTable->metatable;
				break;
			}
			case LUA_TUSERDATA: {
				auto* const leftUdata = static_cast<Udata*>(left->value.p);
				auto* const rightUdata = static_cast<Udata*>(right->value.p);
				if (leftUdata == rightUdata) {
					return 1;
				}
				leftMetatable = leftUdata->metatable;
				rightMetatable = rightUdata->metatable;
				break;
			}
			default:
				// Every other tag holds a pointer (string, function, light
				// userdata, thread): 0x009298D2 compares the whole value word,
				// which on x64 is `p`, not the low half `b`.
				return left->value.p == right->value.p;
		}

		const TObject* const handler = get_compTM(leftMetatable, kTagMethodEqual, state, rightMetatable);
		if (handler == nullptr) {
			return 0;
		}

		(void)callTMres(handler, left, right, state);

		const TObject* const result = state->top;
		if (result->tt == LUA_TNIL) {
			return 0;
		}

		if (result->tt != LUA_TBOOLEAN) {
			return 1;
		}

		return result->value.b != 0;
	}

	/**
	 * Address: 0x00915010 (FUN_00915010, luaF_newproto)
	 *
	 * IDA signature:
	 * Proto *__cdecl luaF_newproto(lua_State *L);
	 *
	 * What it does:
	 * Allocates an empty function prototype and links it for collection. Every
	 * lane is cleared except gclist, which luaC_link has just written.
	 */
	Proto* luaF_newproto(lua_State* const state)
	{
		auto* const proto = luaM_new<Proto>(state);
		luaC_link(state, reinterpret_cast<GCObject*>(proto), LUA_TPROTO);

		proto->k = nullptr;
		proto->code = nullptr;
		proto->p = nullptr;
		proto->lineinfo = nullptr;
		proto->locvars = nullptr;
		proto->upvalues = nullptr;
		proto->source = nullptr;
		proto->sizeupvalues = 0;
		proto->sizek = 0;
		proto->sizecode = 0;
		proto->sizelineinfo = 0;
		proto->sizep = 0;
		proto->sizelocvars = 0;
		proto->lineDefined = 0;
		proto->nups = 0;
		proto->numparams = 0;
		proto->is_vararg = 0;
		proto->maxstacksize = 0;
		proto->reserved0 = 0;
		proto->reserved1 = 0;
		proto->reserved2 = 0;
		proto->reserved3 = 0;
		proto->reserved4 = 0;
		proto->reserved5 = 0;
		proto->reserved6 = 0;
		proto->reserved7 = 0;
		proto->reserved8 = 0;
		return proto;
	}

	/**
	 * Address: 0x00915160 (FUN_00915160, luaF_freeclosure)
	 *
	 * IDA signature:
	 * void __cdecl luaF_freeclosure(lua_State *L, Closure *c);
	 *
	 * What it does:
	 * Releases a closure. The size is computed from the upvalue count with the
	 * Lua-closure formula, which is what the binary does for either kind.
	 */
	void luaF_freeclosure(lua_State* const state, Closure* const closure)
	{
		// The real size only reaches the free hook, which ignores it; the
		// counter is charged the binary's Lua-closure formula
		// (kLuaX86LClosureHeader = 28, 4 per upvalue) for either kind.
		const LuaBlockSize lClosureSize = sizeLclosure(closure->c.nupvalues);
		(void)luaM_realloc(state, closure, lClosureSize.real, 0u, lClosureSize.accounted, 0u);
	}

	/**
	 * Address: 0x00914F70 (FUN_00914F70, luaF_findupval)
	 *
	 * IDA signature:
	 * UpVal *__usercall luaF_findupval(lua_State *L, StkId level);
	 *
	 * What it does:
	 * Returns the upvalue already pointing at `level`, or makes one and splices
	 * it into the thread's open list. The list runs from higher stack slots
	 * down, so the walk stops as soon as it passes the target.
	 */
	UpVal* luaF_findupval(lua_State* const state, StkId const level)
	{
		GCObject** link = &state->openupval;

		for (GCObject* candidate = state->openupval; candidate != nullptr; candidate = candidate->gch.next) {
			TObject* const referenced = candidate->uv.v;
			if (referenced < level) {
				break;
			}

			if (referenced == level) {
				if (moho::lua_IncrementalGC && moho::lua_incremental::IsUiState(state->l_G)) {
					if (auto* const incremental = moho::lua_incremental::Find(state->l_G);
						incremental != nullptr && incremental->initialized &&
						moho::lua_incremental::IsDead(*incremental, candidate)) {
						candidate->gch.marked ^= moho::lua_incremental::kWhiteBits;
					}
				}
				return &candidate->uv;
			}

			link = &candidate->gch.next;
		}

		auto* const upvalue = luaM_new<UpVal>(state);
		upvalue->tt = LUA_TUPVALUE;
		if (moho::lua_IncrementalGC && moho::lua_incremental::IsUiState(state->l_G)) {
			const auto* const incremental = moho::lua_incremental::Find(state->l_G);
			upvalue->marked = (incremental != nullptr && incremental->initialized)
				? moho::lua_incremental::White(*incremental)
				: moho::lua_incremental::kWhite0Bit;
		} else {
			upvalue->marked = 1;
		}
		upvalue->v = level;
		upvalue->next = *link;
		*link = reinterpret_cast<GCObject*>(upvalue);
		return upvalue;
	}

	/**
	 * Address: 0x009139F0 (FUN_009139F0, luaD_callhook)
	 *
	 * IDA signature:
	 * void __cdecl luaD_callhook(lua_State *L, int event, int line);
	 *
	 * What it does:
	 * Invokes the installed debug hook for one event. Stack positions are
	 * saved as offsets rather than pointers because the hook may grow the
	 * stack and move it, and the hook is disabled for its own duration so it
	 * cannot re-enter. A tail return has no frame of its own, so it reports
	 * i_ci 0.
	 */
	void luaD_callhook(lua_State* const state, const int event, const int line)
	{
		constexpr int kMinCStackSlots = 20;

		global_State* const globalState = state->l_G;
		const Hook hook = globalState->hook;
		if (hook == nullptr || globalState->allowhook == 0) {
			return;
		}

		const ptrdiff_t savedTop = state->top - state->stack;
		const ptrdiff_t savedFrameTop = state->ci->top - state->stack;

		lua_Debug ar{};
		ar.event = event;
		ar.currentline = line;
		ar.i_ci = (event == LUA_HOOKTAILRET) ? 0 : static_cast<int>(state->ci - state->base_ci);

		if (state->stack_last - state->top <= kMinCStackSlots) {
			luaD_growstack(state, kMinCStackSlots);
		}

		state->ci->top = state->top + kMinCStackSlots;
		state->l_G->allowhook = 0;
		hook(state, &ar);
		state->l_G->allowhook = 1;

		state->ci->top = state->stack + savedFrameTop;
		state->top = state->stack + savedTop;
	}

	/**
	 * Address: 0x009131B0 (FUN_009131B0, luaG_errormsg)
	 *
	 * IDA signature:
	 * void __cdecl luaG_errormsg(lua_State *L);
	 *
	 * What it does:
	 * Delivers a pending error. If the globals table defines `_TRACEBACK`, it
	 * is called with the message and whatever it returns replaces it - that is
	 * how a stack trace gets attached. Either way the result is thrown as a
	 * lua_RuntimeError carrying the top-of-stack string.
	 */
	void luaG_errormsg(lua_State* const state)
	{
		// FADeepProbe request smuggling (deviation, documented): mods request
		// watches/probes with pcall(error, "FADeepProbe watchaddr ..."), and
		// the request is readable right here - the error object is on the
		// stack and pcall has not swallowed it yet. Arming is a side effect;
		// the error itself still raises normally, so mod-visible behaviour is
		// unchanged.
		if (state->top > state->stack && state->top[-1].tt == LUA_TSTRING) {
			const TString* const request = static_cast<const TString*>(state->top[-1].value.p);
			if (request != nullptr && request->len >= 18
				&& std::strncmp(request->str, "FADeepProbe ", 12) == 0) {
				char text[128] = {};
				const std::size_t bytes = (request->len < sizeof(text) - 1) ? request->len : sizeof(text) - 1;
				std::memcpy(text, request->str, bytes);
				(void)gpg::diag::ParseFadepProbeRequest(text);
			}
		}

		TString* const key = luaS_newlstr(state, "_TRACEBACK", 10u);
		state->top->tt = static_cast<int>(key->tt);
		state->top->value.p = key;
		api_incr_top(state);

		const TObject* const handler = luaV_gettable(state, &state->_gt, state->top - 1, 0);
		if (IsCallableTag(handler->tt)) {
			// Stack holds [message, "_TRACEBACK"]; turn it into
			// [handler, message] and call it.
			state->top[-1] = state->top[-2];
			state->top[-2] = *handler;
			(void)luaD_call(state, state->top - 2, 1);
		} else {
			--state->top;
		}

		throw lua_RuntimeError(lua::lua_Error(state, LUA_ERRRUN));
	}

	/**
	 * Address: 0x00929150 (FUN_00929150, luaV_tonumber)
	 *
	 * IDA signature:
	 * const TObject *__usercall luaV_tonumber@<eax>(const TObject *obj, TObject *n);
	 *
	 * What it does:
	 * Views a value as a number. Numbers are returned as they are; a string is
	 * parsed into the caller's scratch slot and that is returned instead.
	 * Anything else - or a string that does not parse - gives null, which is
	 * what makes arithmetic on it fall through to a tag method.
	 */
	const TObject* luaV_tonumber(const TObject* const obj, TObject* const n)
	{
		if (obj->tt == LUA_TNUMBER) {
			return obj;
		}

		if (obj->tt == LUA_TSTRING) {
			float parsed = 0.0f;
			if (luaO_str2d(static_cast<const TString*>(obj->value.p)->str, &parsed) != 0) {
				n->value.n = parsed;
				n->tt = LUA_TNUMBER;
				return n;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x009291A0 (FUN_009291A0, luaV_tostring)
	 *
	 * IDA signature:
	 * int __cdecl luaV_tostring(lua_State *L, TObject *obj);
	 *
	 * What it does:
	 * Converts a number in place to its string form, leaving anything else
	 * alone. Returns whether the slot now holds a string.
	 */
	int luaV_tostring(lua_State* const state, TObject* const object)
	{
		if (object->tt != LUA_TNUMBER) {
			return 0;
		}

		char rendered[32];
		// Plan WPL.17: the Windows CRT's NaN text (LuaNumberText.h).
		(void)lua::FormatNumberLikeWindowsCrt(rendered, "%.14g", static_cast<double>(object->value.n));

		TString* const interned = luaS_newlstr(state, rendered, std::strlen(rendered));
		object->value.p = interned;
		object->tt = static_cast<int>(interned->tt);
		return 1;
	}

	/**
	 * Address: 0x00929910 (FUN_00929910, luaV_concat)
	 *
	 * IDA signature:
	 * void __cdecl luaV_concat(lua_State *L, int total, int last);
	 *
	 * What it does:
	 * Folds `total` stack values ending at `last` into one string. Each pass
	 * takes the longest run of strings and numbers it can reach and joins them
	 * through the shared scratch buffer in a single allocation, so `a..b..c`
	 * does not build an intermediate. A pair that is not concatenable falls
	 * back to `__concat`, which handles one pair at a time - hence the outer
	 * loop.
	 */
	// Lua's own `tostring` macro, and the shape the binary open-codes at each of
	// the three sites below: `if (slot->tt != LUA_TSTRING) { convert or fail }`.
	//
	// `luaV_tostring` alone is NOT this test - it reports 0 for a value that is
	// already a string, because its job is only the number-to-string conversion.
	// Calling it bare on the right-hand operand made every string-to-string
	// concatenation take the __concat path and raise "concatenate expected but
	// got string". Since luaO_pushvfstring builds every Lua error message with
	// exactly that concatenation, each error raised a fresh error while
	// formatting itself, and the first one to occur overflowed the stack.
	[[nodiscard]] static bool CoerceToStringInPlace(lua_State* const state, StkId const slot)
	{
		return slot->tt == LUA_TSTRING || luaV_tostring(state, slot) != 0;
	}

	void luaV_concat(lua_State* const state, int total, int last)
	{
		constexpr int kTagMethodConcat = 16;
		constexpr size_t kMaxStringSize = 0xFFFFFFFDu;

		do {
			StkId const top = state->base + last + 1;
			int handled = 2;

			if (!CoerceToStringInPlace(state, top - 2) || !CoerceToStringInPlace(state, top - 1)) {
				const TObject* handler = luaT_gettmbyobj(state, top - 2, kTagMethodConcat);
				if (handler->tt == LUA_TNIL) {
					handler = luaT_gettmbyobj(state, top - 1, kTagMethodConcat);
				}

				if (!IsCallableTag(handler->tt)) {
					luaV_concat_raise_typeerror(state, top - 2, top - 1);
				}

				const ptrdiff_t resultOffset =
					reinterpret_cast<char*>(top - 2) - reinterpret_cast<char*>(state->stack);
				(void)callTMres(handler, top - 2, top - 1, state);
				*reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + resultOffset) = *state->top;
			} else if (static_cast<TString*>(top[-1].value.p)->len > 0u) {
				// Two strings at least. Reach back over as many more as are
				// convertible so the whole run costs one allocation.
				size_t joinedLength = static_cast<TString*>(top[-1].value.p)->len
					+ static_cast<TString*>(top[-2].value.p)->len;

				while (handled < total && CoerceToStringInPlace(state, top - handled - 1)) {
					joinedLength += static_cast<TString*>(top[-handled - 1].value.p)->len;
					++handled;
				}

				if (joinedLength > kMaxStringSize) {
					luaG_runerror(state, "string size overflow");
				}

				char* const buffer = luaZ_openspace(state, &state->l_G->buff, joinedLength);

				size_t written = 0;
				for (int index = handled; index > 0; --index) {
					const TString* const piece = static_cast<TString*>(top[-index].value.p);
					// Raw concat lane: string pieces appended byte-wise into one buffer.
					std::copy_n(piece->str, piece->len, buffer + written);
					written += piece->len;
				}

				TString* const joined = luaS_newlstr(state, buffer, written);
				top[-handled].tt = static_cast<int>(joined->tt);
				top[-handled].value.p = joined;
			}

			total -= handled - 1;
			last -= handled - 1;
		} while (total > 1);
	}
	// -----------------------------------------------------------------------
	// lvm.c - the interpreter loop.
	// -----------------------------------------------------------------------

	// Instruction field positions. The operand range limits and MAXSTACK
	// already sit above with the symbolic executor's tables; only the field
	// offsets are new here.
	constexpr int kLuaSizeOp = 6;
	constexpr int kLuaSizeC = 9;
	constexpr int kLuaSizeB = 9;
	constexpr int kLuaPosC = kLuaSizeOp;
	constexpr int kLuaPosBx = kLuaPosC;
	constexpr int kLuaPosB = kLuaPosC + kLuaSizeC;
	constexpr int kLuaPosA = kLuaPosB + kLuaSizeB;



	// Opcodes. Stock Lua 5.0.2 with this fork's four extra bit operators
	// spliced in after OP_DIV, which shifts everything from there up by four.
	enum LuaOpcode : int
	{
		kOpMove = 0, kOpLoadK, kOpLoadBool, kOpLoadNil, kOpGetUpval,
		kOpGetGlobal, kOpGetTable, kOpSetGlobal, kOpSetUpval, kOpSetTable,
		kOpNewTable, kOpSelf,
		kOpAdd, kOpSub, kOpMul, kOpDiv,
		kOpBAnd, kOpBOr, kOpBShl, kOpBShr, kOpBXor,
		kOpUnm, kOpNot, kOpConcat,
		kOpJmp, kOpEq, kOpLt, kOpLe, kOpTest,
		kOpCall, kOpTailCall, kOpReturn,
		kOpForLoop, kOpTForLoop, kOpTForPrep,
		kOpSetList, kOpSetListO, kOpClose, kOpClosure
	};

	// Tag-method slots. This fork has no TM_MODE and adds one per bit
	// operator, so TM_EQ lands at 3 and the arithmetic block runs 4..13 -
	// which is what global_State::tmname[18] is sized for.
	enum LuaTagMethod : int
	{
		kTmIndex = 0, kTmNewIndex, kTmGc, kTmEq,
		kTmAdd, kTmSub, kTmMul, kTmDiv,
		kTmBAnd, kTmBOr, kTmBShl, kTmBShr, kTmBXor,
		kTmUnm, kTmLt, kTmLe, kTmConcat, kTmCall
	};

	// CallInfo::state. Not the bit flags stock Lua uses - this fork stores a
	// small enumeration, read back from how luaV_execute and luaD_precall
	// write it.
	constexpr int kFrameRunning = 0;   // a Lua frame executing here
	constexpr int kFrameCalling = 1;   // its callee's frame sits on top
	constexpr int kFrameSuspended = 2; // unwind out to the C caller

	// Hook masks and event codes.
	constexpr int kHookMaskCall = 1;
	constexpr int kHookMaskLine = 4;
	constexpr int kHookMaskCount = 8;
	constexpr int kHookEventCall = 0;
	constexpr int kHookEventLine = 2;
	constexpr int kHookEventCount = 3;

	[[nodiscard]] static constexpr int LuaGetOpcode(const Instruction i) noexcept
	{
		return static_cast<int>(i & ((1u << kLuaSizeOp) - 1u));
	}

	[[nodiscard]] static constexpr int LuaGetArgA(const Instruction i) noexcept
	{
		return static_cast<int>((i >> kLuaPosA) & 0xFFu);
	}

	[[nodiscard]] static constexpr int LuaGetArgB(const Instruction i) noexcept
	{
		return static_cast<int>((i >> kLuaPosB) & 0x1FFu);
	}

	[[nodiscard]] static constexpr int LuaGetArgC(const Instruction i) noexcept
	{
		return static_cast<int>((i >> kLuaPosC) & 0x1FFu);
	}

	[[nodiscard]] static constexpr int LuaGetArgBx(const Instruction i) noexcept
	{
		return static_cast<int>((i >> kLuaPosBx) & kLuaMaxArgBx);
	}

	[[nodiscard]] static constexpr int LuaGetArgSBx(const Instruction i) noexcept
	{
		return LuaGetArgBx(i) - kLuaMaxArgSBx;
	}

	[[nodiscard]] static constexpr bool LuaIsFalse(const TObject* const o) noexcept
	{
		return o->tt == LUA_TNIL || (o->tt == LUA_TBOOLEAN && o->value.b == 0);
	}

	// The bit operators work on the 32-bit truncation of their operands and
	// hand the result back as a number. A negative result is re-read as
	// unsigned first, so `-1 >> 0` is 4294967295 rather than -1 - the binary
	// adds 2^32 (the constant at 0x00E4F710) whenever the sign bit is set.
	//
	// 0x0092A897..0x0092A8A9: `fild` loads the integer exactly, the `fadd`
	// rounds once under `_PC_24`, and `fstp dword` is then exact - one rounding
	// of the exact unsigned value. Rounding the int32 to float first and then
	// adding 2^32 rounds twice and lands one float (256) away for operands such
	// as -2147307649 (2147659520 in the binary, 2147659776 when double-rounded).
	[[nodiscard]] static inline float LuaBitwiseResult(const std::int32_t value) noexcept
	{
		const std::uint32_t unsignedValue = static_cast<std::uint32_t>(value);
		return static_cast<float>(static_cast<double>(unsignedValue)); // exact widen, one rounding
	}

	// 0x0092A847..0x0092A864: `fistp qword` under round-toward-zero, keeping the
	// low dword. Results of the operators above are unsigned and reach 2^32, so
	// operands at or past 2^31 are the normal case: the binary wraps them
	// (4294967040 -> 0xFFFFFF00), where a direct float-to-int32 cast yields the
	// 0x80000000 "integer indefinite" instead.
	[[nodiscard]] static inline std::int32_t LuaToBitwiseOperand(const float value) noexcept
	{
		return static_cast<std::int32_t>(static_cast<std::int64_t>(value));
	}

	/**
	 * Engine addition (lua_ThreadedDispatch): the array-part slot `key` names in `table`, or null -
	 * what luaH_get and luaH_set reach through luaH_getnum for a whole number from 1 to the array's
	 * size, without their general lookup. Null for anything else, which they then look up as before.
	 */
	[[nodiscard]] static inline TObject* LuaArraySlot(Table* const table, const TObject* const key) noexcept
	{
		if (key->tt != LUA_TNUMBER) {
			return nullptr;
		}
		const float number = key->value.n;
		const int size = table->sizearray;
		if (!(number >= 1.0f && number <= static_cast<float>(size))) {
			return nullptr;
		}
		const int index = static_cast<int>(number);
		if (static_cast<float>(index) != number || index > size) {
			return nullptr;
		}
		return &table->array[index - 1];
	}

	namespace
	{
		inline void RunLuaCallGate(moho::LuaCFunctionPtr function); // below, with luaD_precall
	} // namespace

	/**
	 * Engine addition (lua_ThreadedDispatch): what luaH_next does from the slot after `index`
	 * (luaH_index's answer for the current key), writing the next key and value at `key`. 0 at the end.
	 */
	[[nodiscard]] static int LuaNextFrom(Table* const table, int index, TObject* const key) noexcept
	{
		++index;
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
		while (nodeBase[nodeIndex].i_val.tt == LUA_TNIL) {
			if (++nodeIndex >= nodeCount) {
				return 0;
			}
		}
		key[0] = nodeBase[nodeIndex].Key();
		key[1] = nodeBase[nodeIndex].i_val;
		return 1;
	}

	/**
	 * Engine addition (lua_ThreadedDispatch): OP_TFORLOOP's call of the built-in `next` (luaB_next)
	 * over a table, done in place: what luaD_call, luaD_precall, luaB_next, lua_next and luaD_poscall
	 * do, in the same order and to the same stack slots - the C-call depth, the closure's invocation
	 * count, the call gate, the next key and value where luaH_next leaves them, the results moved down
	 * and padded with nils to `nvar`, the top, then the collection check luaD_call ends with - without
	 * the frame. False, having done nothing, whenever the call could do more than that: another
	 * function, a call or return hook, a C-function hook, a depth at the limit, a call-info array or a
	 * stack that would have to grow, or a key luaH_index refuses (the call raises that error itself).
	 */
	[[nodiscard]] static bool LuaInlineNextCall(lua_State* const L, StkId const callBase, const int nvar)
	{
		constexpr unsigned int kMaxCCalls = 200;
		constexpr int kMinCStackSlots = 20;
		constexpr int kHookMaskCallOrReturn = (1 << 0) | (1 << 1);

		if (callBase[0].tt != LUA_TFUNCTION || callBase[1].tt != LUA_TTABLE) {
			return false;
		}
		Closure* const closure = &static_cast<GCObject*>(callBase[0].value.p)->cl;
		if (closure->c.isC == 0 || closure->c.f != &luaB_next || (L->l_G->hookmask & kHookMaskCallOrReturn) != 0 ||
		    gLuaCFunctionCallHook != nullptr || static_cast<unsigned int>(L->nCcalls) + 1u >= kMaxCCalls ||
		    &L->ci[1] == L->end_ci || L->stack_last - L->top <= kMinCStackSlots) {
			return false;
		}

		// luaH_index, without its error.
		Table* const table = static_cast<Table*>(callBase[1].value.p);
		TObject* const key = &callBase[2];
		int index = -1;
		if (key->tt != LUA_TNIL) {
			bool inArray = false;
			if (key->tt == LUA_TNUMBER) {
				const float numericKey = key->value.n;
				const int integerKey = fa::TruncateToInt(numericKey);
				if (static_cast<float>(integerKey) == numericKey && integerKey >= 1) {
					const int zeroBased = integerKey - 1;
					if ((zeroBased & 0xFF000000) == 0 && integerKey <= table->sizearray) {
						index = zeroBased;
						inArray = true;
					}
				}
			}
			if (!inArray) {
				const TObject* const slot = luaH_get(table, key);
				if (slot == &luaO_nilobject) {
					return false;
				}
				const auto nodeBase = reinterpret_cast<std::uintptr_t>(static_cast<Node*>(table->node));
				const auto slotAddress = reinterpret_cast<std::uintptr_t>(slot);
				index = table->sizearray +
					static_cast<int>((slotAddress - nodeBase - offsetof(Node, i_val)) / static_cast<std::uintptr_t>(sizeof(Node)));
			}
		}

		// luaD_call and luaD_precall up to the C function.
		++L->nCcalls;
		std::uint32_t& invocationsLow = reinterpret_cast<std::uint32_t&>(closure->c.upvalue_m1[0].tt);
		std::uint32_t& invocationsHigh = reinterpret_cast<std::uint32_t&>(closure->c.upvalue_m1[0].value.b);
		const std::uint32_t previousLow = invocationsLow++;
		if (invocationsLow < previousLow) {
			++invocationsHigh;
		}
		RunLuaCallGate(closure->c.f);

		// luaB_next: lua_next over (state, control), then the nil it pushes at the end.
		int produced = 2;
		if (LuaNextFrom(table, index, key) == 0) {
			key->tt = LUA_TNIL;
			produced = 1;
		}

		// luaD_poscall.
		StkId result = callBase;
		StkId firstResult = callBase + 2;
		StkId const top = firstResult + produced;
		int wanted = nvar;
		for (; wanted != 0 && firstResult < top; --wanted) {
			*result++ = *firstResult++;
		}
		for (; wanted > 0; --wanted) {
			(result++)->tt = LUA_TNIL;
		}
		L->top = result;

		--L->nCcalls;
		luaC_checkGC(L);
		return true;
	}

	extern "C++"
	{
	/**
	 * Engine addition (lua_ThreadedDispatch): the body of luaV_execute, once for each way of reaching an
	 * instruction's handler. `kThreaded` jumps to it through a table of label addresses (computed goto)
	 * at the fetch, with no range check, and the fast paths below that it guards; otherwise the
	 * binary's `switch`. Handlers `break` back to the one fetch either way, and are the same handlers.
	 */
	template <bool kThreaded>
	TObject* LuaExecute(lua_State* L)
	{
		global_State* const G = L->l_G;
		lua_State* const previousActiveThread = G->lstate;

		// The binary restores `lstate` at each of its returns (FUN_00929C60
		// saves it at +0x44 on entry and writes it back before every exit). It
		// has no way to restore on the error path because errors there are a
		// longjmp; ours are C++ exceptions, and an unwind past this frame would
		// leave `lstate` pointing at the thread that raised - typically a
		// coroutine, whose `stateUserData` is null by construction
		// (`luaE_newthread`). Every later `LuaObject::GetActiveState()` then
		// hands back null, and the first UI event to build a Lua event table
		// dies on it. A guard keeps the binary's intent on all exits.
		struct ActiveThreadGuard
		{
			global_State* g;
			lua_State* previous;
			~ActiveThreadGuard() { g->lstate = previous; }
		} const activeThreadGuard{G, previousActiveThread};

		G->lstate = L;

		LClosure* cl = nullptr;
		const Instruction* pc = nullptr;
		TObject* k = nullptr;
		int oldline = -1;

	callentry: // a fresh call: the call hook sees it before the first instruction
		if ((G->hookmask & kHookMaskCall) != 0) {
			luaD_callhook(L, kHookEventCall, -1);
		}

	retentry: // resuming: the frame is already set up
		cl = &static_cast<GCObject*>(L->base[-1].value.p)->cl.l;
		pc = L->ci->savedpc;
		k = cl->p->k;
		oldline = -1;

		// Live-pc publication (deviation, documented): keep `ci->pc` pointing
		// at the address of the interpreter's `pc` variable so a crash handler
		// can read the *current* instruction of the running frame. savedpc is
		// stale between calls (it is only written at calls and hooks), and the
		// alternative - refreshing savedpc on every back-edge - costs a store
		// per loop iteration. One store per dispatch entry; `pc` itself lives
		// in this frame for the whole interpreter loop, so the pointer is
		// stable between refreshes.
		L->ci->pc = &pc;

		for (;;) {
			const Instruction i = *pc++;

			if ((G->hookmask & (kHookMaskLine | kHookMaskCount)) != 0) {
				--G->hookcount;
				if (G->hookcount == 0 || (G->hookmask & kHookMaskLine) != 0) {
					L->ci->savedpc = pc - 1;

					if ((G->hookmask & kHookMaskCount) != 0 && G->hookcount == 0) {
						G->hookcount = G->basehookcount;
						luaD_callhook(L, kHookEventCount, -1);
					} else if ((G->hookmask & kHookMaskLine) != 0) {
						// Only report a line once, however many instructions it
						// covers.
						const CallInfo* const ci = L->ci;
						const Proto* const p = static_cast<GCObject*>(ci->base[-1].value.p)->cl.l.p;
						const int line = (p->lineinfo != nullptr)
							? p->lineinfo[ci->savedpc - p->code]
							: 0;
						if (line != oldline) {
							oldline = line;
							luaD_callhook(L, kHookEventLine, line);
						}
					}

					if (L->ci->state == kFrameSuspended) { // did the hook yield?
						G->lstate = previousActiveThread;
						return nullptr;
					}
				}
			}

			StkId const base = L->base;
			StkId const ra = base + LuaGetArgA(i);

			// Operand accessors. RKB/RKC pick a constant instead of a register
			// once the index passes MAXSTACK.
			const auto rb = [&]() -> StkId { return base + LuaGetArgB(i); };
			const auto rkb = [&]() -> TObject* {
				const int index = LuaGetArgB(i);
				return (index >= kLuaMaxStack) ? &k[index - kLuaMaxStack] : &base[index];
			};
			const auto rkc = [&]() -> TObject* {
				const int index = LuaGetArgC(i);
				return (index >= kLuaMaxStack) ? &k[index - kLuaMaxStack] : &base[index];
			};

			if constexpr (kThreaded) {
				static_assert(kOpClosure + 1 == 39 && kLuaSizeOp == 6);
				static void* const kTargets[64] = {
					&&op_Move, &&op_LoadK, &&op_LoadBool, &&op_LoadNil, &&op_GetUpval, &&op_GetGlobal,
					&&op_GetTable, &&op_SetGlobal, &&op_SetUpval, &&op_SetTable, &&op_NewTable, &&op_Self,
					&&op_Add, &&op_Sub, &&op_Mul, &&op_Div, &&op_BAnd, &&op_BOr,
					&&op_BShl, &&op_BShr, &&op_BXor, &&op_Unm, &&op_Not, &&op_Concat,
					&&op_Jmp, &&op_Eq, &&op_Lt, &&op_Le, &&op_Test, &&op_Call,
					&&op_TailCall, &&op_Return, &&op_ForLoop, &&op_TForLoop, &&op_TForPrep, &&op_SetList,
					&&op_SetListO, &&op_Close, &&op_Closure,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
					&&op_Default,
				};
				goto* kTargets[LuaGetOpcode(i)];
			}

			switch (LuaGetOpcode(i)) {
			case kOpMove: op_Move:
				*ra = *rb();
				break;

			case kOpLoadK: op_LoadK:
				*ra = k[LuaGetArgBx(i)];
				break;

			case kOpLoadBool: op_LoadBool:
				ra->value.b = LuaGetArgB(i);
				ra->tt = LUA_TBOOLEAN;
				if (LuaGetArgC(i) != 0) {
					++pc; // C says skip the next instruction
				}
				break;

			case kOpLoadNil: op_LoadNil: {
				StkId slot = rb();
				do {
					slot->tt = LUA_TNIL;
					--slot;
				} while (slot >= ra);
				break;
			}

			case kOpGetUpval: op_GetUpval: {
				const int upIndex = LuaGetArgB(i);
				if (upIndex >= static_cast<int>(cl->nupvalues) || cl->upvals[upIndex] == nullptr) {
					static int sGetUpvalBudget = 0;
					if (sGetUpvalBudget < 20) {
						++sGetUpvalBudget;
						const Proto* const proto = cl->p;
						const char* const source =
							(proto != nullptr && proto->source != nullptr) ? proto->source->str : "<no source>";
						const int line = (proto != nullptr && proto->lineinfo != nullptr && proto->code != nullptr)
							? proto->lineinfo[(pc - 1) - proto->code]
							: -1;
						char probe[288];
						sprintf_s(probe, sizeof(probe),
						          "[LUAUPVAL] GETUPVAL bad: cl=%p nups=%d B=%d src=%.150s line=%d\n",
						          static_cast<const void*>(cl),
						          static_cast<int>(cl->nupvalues), upIndex, source, line);
						::OutputDebugStringA(probe);
					}
					ra->tt = LUA_TNIL;
					break;
				}
				*ra = *cl->upvals[upIndex]->v;
				break;
			}

			case kOpGetGlobal: op_GetGlobal: {
				const TObject* const key = &k[LuaGetArgBx(i)];
				const TObject* value = luaH_getstr(
					static_cast<Table*>(cl->g.value.p),
					static_cast<TString*>(key->value.p)
				);
				if (value->tt == LUA_TNIL) {
					value = luaV_index(L, &cl->g, key, 0);
				}
				*(L->base + LuaGetArgA(i)) = *value;
				break;
			}

			case kOpGetTable: op_GetTable: {
				StkId const table = rb();
				const TObject* const key = rkc();
				const TObject* value = nullptr;
				if constexpr (kThreaded) {
					// The slot luaH_get would find for a string or an array key, when it holds a value.
					if (table->tt == LUA_TTABLE) {
						Table* const h = static_cast<Table*>(table->value.p);
						const TObject* const found = (key->tt == LUA_TSTRING)
							? luaH_getstr(h, static_cast<TString*>(key->value.p))
							: LuaArraySlot(h, key);
						if (found != nullptr && found->tt != LUA_TNIL) {
							*ra = *found;
							break;
						}
					}
				}
				if (table->tt == LUA_TTABLE) {
					value = luaH_get(static_cast<Table*>(table->value.p), key);
					if (value->tt == LUA_TNIL) {
						value = luaV_index(L, table, key, 0);
					}
				} else {
					value = luaV_getnotable(L, table, key, 0);
				}
				*(L->base + LuaGetArgA(i)) = *value;
				break;
			}

			case kOpSetGlobal: op_SetGlobal:
				luaV_settable(L, &cl->g, &k[LuaGetArgBx(i)], ra);
				break;

			case kOpSetUpval: op_SetUpval: {
				const int upIndex = LuaGetArgB(i);
				if (upIndex >= static_cast<int>(cl->nupvalues) || cl->upvals[upIndex] == nullptr) {
					static int sSetUpvalBudget = 0;
					if (sSetUpvalBudget < 20) {
						++sSetUpvalBudget;
						const Proto* const proto = cl->p;
						const char* const source =
							(proto != nullptr && proto->source != nullptr) ? proto->source->str : "<no source>";
						const int line = (proto != nullptr && proto->lineinfo != nullptr && proto->code != nullptr)
							? proto->lineinfo[(pc - 1) - proto->code]
							: -1;
						char probe[288];
						sprintf_s(probe, sizeof(probe),
						          "[LUAUPVAL] SETUPVAL bad: cl=%p nups=%d B=%d slot=%p src=%.150s line=%d\n",
						          static_cast<const void*>(cl),
						          static_cast<int>(cl->nupvalues), upIndex,
						          static_cast<const void*>(
							          upIndex < static_cast<int>(cl->nupvalues) ? cl->upvals[upIndex] : nullptr),
						          source, line);
						::OutputDebugStringA(probe);
					}
					break;
				}
				*cl->upvals[upIndex]->v = *ra;
				faf_lua51_gc_barrier_value(
					L,
					reinterpret_cast<GCObject*>(cl->upvals[upIndex]),
					ra
				); // Lua 5.1.5 lvm.c: OP_SETUPVAL
				break;
			}

			case kOpSetTable: op_SetTable:
				if constexpr (kThreaded) {
					// A string or an array key whose slot holds a value: what luaV_settable does with it
					// (luaH_set's flags reset, then the store), as no __newindex applies to a set slot.
					if (ra->tt == LUA_TTABLE) {
						Table* const h = static_cast<Table*>(ra->value.p);
						const TObject* const key = rkb();
						TObject* const slot = (key->tt == LUA_TSTRING)
							? const_cast<TObject*>(luaH_getstr(h, static_cast<TString*>(key->value.p)))
							: LuaArraySlot(h, key);
						if (slot != nullptr && slot->tt != LUA_TNIL) {
							h->flags = 0;
							*slot = *rkc();
							// The store above is luaV_settable's common case, and it carries that
							// function's write barrier: without it the incremental collector cannot
							// see the new reference and can free the value while the table still
							// holds it.
							faf_lua51_gc_barrier_back(L, h);
							break;
						}
					}
				}
				luaV_settable(L, ra, rkb(), rkc());
				break;

			case kOpNewTable: op_NewTable: {
				// B is a floating byte: three mantissa bits and an exponent, as
				// packed by luaO_int2fb.
				const int sizeHint = LuaGetArgB(i);
				Table* const table = luaH_new(L, (sizeHint & 7) << (sizeHint >> 3), LuaGetArgC(i));
				ra->tt = static_cast<int>(table->tt);
				ra->value.p = table;
				luaC_checkGC(L);
				break;
			}

			case kOpSelf: op_Self: {
				StkId const object = rb();
				const TObject* const key = rkc();
				if (key->tt != LUA_TSTRING) {
					// The code generator only ever emits OP_SELF with a string
					// key; a chunk that says otherwise is not one this
					// interpreter can run.
					G->lstate = previousActiveThread;
					return nullptr;
				}

				ra[1] = *object;
				const TObject* value = nullptr;
				if (object->tt == LUA_TTABLE) {
					value = luaH_getstr(
						static_cast<Table*>(object->value.p),
						static_cast<TString*>(key->value.p)
					);
					if (value->tt != LUA_TNIL) {
						*ra = *value;
						break;
					}
					value = luaV_index(L, object, key, 0);
				} else {
					value = luaV_getnotable(L, object, key, 0);
				}
				*(L->base + LuaGetArgA(i)) = *value;
				break;
			}

			case kOpAdd: op_Add: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					ra->value.n = c->value.n + b->value.n;
					ra->tt = LUA_TNUMBER;
				} else {
					// Note there is no string coercion here: unlike stock Lua,
					// this fork goes straight to the tag method.
					(void)CallBinTmOrRaiseArithmeticTypeError(
						kTmAdd, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpSub: op_Sub: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					ra->value.n = b->value.n - c->value.n;
					ra->tt = LUA_TNUMBER;
				} else {
					(void)CallBinTmOrRaiseArithmeticTypeError(
						kTmSub, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpMul: op_Mul: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					ra->value.n = c->value.n * b->value.n;
					ra->tt = LUA_TNUMBER;
				} else {
					(void)CallBinTmOrRaiseArithmeticTypeError(
						kTmMul, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpDiv: op_Div: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					ra->value.n = b->value.n / c->value.n;
					ra->tt = LUA_TNUMBER;
				} else {
					(void)CallBinTmOrRaiseArithmeticTypeError(
						kTmDiv, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpBAnd: op_BAnd:
			case kOpBOr: op_BOr:
			case kOpBShl: op_BShl:
			case kOpBShr: op_BShr:
			case kOpBXor: op_BXor: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				if (b->tt == LUA_TNUMBER && c->tt == LUA_TNUMBER) {
					const std::int32_t left = LuaToBitwiseOperand(b->value.n);
					const std::int32_t right = LuaToBitwiseOperand(c->value.n);
					std::int32_t result = 0;
					switch (LuaGetOpcode(i)) {
					case kOpBAnd: result = left & right; break;
					case kOpBOr:  result = left | right; break;
					case kOpBShl: result = left << right; break;
					case kOpBShr: result = static_cast<std::int32_t>(
						static_cast<std::uint32_t>(left) >> right); break;
					default:      result = left ^ right; break; // kOpBXor
					}
					ra->value.n = LuaBitwiseResult(result);
					ra->tt = LUA_TNUMBER;
				} else {
					const int event = kTmBAnd + (LuaGetOpcode(i) - kOpBAnd);
					(void)CallBinTmOrRaiseArithmeticTypeError(
						event, const_cast<TObject*>(b), L, const_cast<TObject*>(c), ra);
				}
				break;
			}

			case kOpUnm: op_Unm: {
				const TObject* operand = rb();
				TObject coerced{};
				if (operand->tt != LUA_TNUMBER) {
					float parsed = 0.0f;
					if (operand->tt == LUA_TSTRING
						&& luaO_str2d(static_cast<const TString*>(operand->value.p)->str, &parsed) != 0) {
						// Unary minus is the one arithmetic operator here that
						// still coerces a numeric string.
						coerced.value.n = parsed;
						coerced.tt = LUA_TNUMBER;
						operand = &coerced;
					} else {
						TObject secondOperand{};
						secondOperand.tt = LUA_TNIL;
						(void)CallBinTmOrRaiseArithmeticTypeError(
							kTmUnm, const_cast<TObject*>(operand), L, &secondOperand, ra);
						break;
					}
				}
				ra->value.n = -0.0f - operand->value.n;
				ra->tt = LUA_TNUMBER;
				break;
			}

			case kOpNot: op_Not:
				ra->value.b = LuaIsFalse(rb()) ? 1 : 0;
				ra->tt = LUA_TBOOLEAN;
				break;

			case kOpConcat: op_Concat: {
				const int b = LuaGetArgB(i);
				const int c = LuaGetArgC(i);
				luaV_concat(L, c - b + 1, c); // may change the stack
				*(L->base + LuaGetArgA(i)) = *(L->base + b);
				luaC_checkGC(L);
				break;
			}

			case kOpJmp: op_Jmp:
				pc += LuaGetArgSBx(i);
				break;

			case kOpEq: op_Eq: {
				const TObject* const b = rkb();
				const TObject* const c = rkc();
				int equal = 0;
				if (b->tt == c->tt) {
					// luaV_equalval's answer for the tags that never reach __eq (lua_ThreadedDispatch).
					const int tag = b->tt;
					if (kThreaded && tag == LUA_TNUMBER) {
						equal = (b->value.n == c->value.n) ? 1 : 0;
					} else if (kThreaded && (tag == LUA_TNIL)) {
						equal = 1;
					} else if (kThreaded && tag == LUA_TBOOLEAN) {
						equal = (b->value.b == c->value.b) ? 1 : 0;
					} else if (kThreaded && tag == LUA_TSTRING) {
						equal = (b->value.p == c->value.p) ? 1 : 0;
					} else {
						equal = luaV_equalval(L, rkb(), rkc()) ? 1 : 0;
					}
				}
				if (equal == LuaGetArgA(i)) {
					pc += LuaGetArgSBx(*pc) + 1;
				} else {
					++pc; // skip the jump that follows
				}
				break;
			}

			case kOpLt: op_Lt:
				if ((kThreaded && rkb()->tt == LUA_TNUMBER && rkc()->tt == LUA_TNUMBER
				       ? (rkc()->value.n > rkb()->value.n ? 1 : 0) // luaV_lessthan's number case (lua_ThreadedDispatch)
				       : luaV_lessthan(L, rkb(), rkc())) == LuaGetArgA(i)) {
					pc += LuaGetArgSBx(*pc) + 1;
				} else {
					++pc;
				}
				break;

			case kOpLe: op_Le:
				if ((kThreaded && rkb()->tt == LUA_TNUMBER && rkc()->tt == LUA_TNUMBER
				       ? (rkc()->value.n >= rkb()->value.n ? 1 : 0) // luaV_lessequal's number case (lua_ThreadedDispatch)
				       : luaV_lessequal(L, rkb(), rkc())) == LuaGetArgA(i)) {
					pc += LuaGetArgSBx(*pc) + 1;
				} else {
					++pc;
				}
				break;

			case kOpTest: op_Test: {
				StkId const value = rb();
				if ((LuaIsFalse(value) ? 1 : 0) == LuaGetArgC(i)) {
					++pc;
				} else {
					*ra = *value;
					pc += LuaGetArgSBx(*pc) + 1;
				}
				break;
			}

			case kOpCall: op_Call:
			case kOpTailCall: op_TailCall: {
				if (LuaGetArgB(i) != 0) {
					L->top = ra + LuaGetArgB(i);
				}
				const int nresults = LuaGetArgC(i) - 1;

				StkId const firstResult = luaD_precall(L, ra);
				if (firstResult == nullptr) { // a Lua function: run it here
					if (LuaGetOpcode(i) == kOpCall) {
						L->ci[-1].state = kFrameCalling;
						L->ci[-1].savedpc = pc - 1; // points at this OP_CALL
					} else {
						// Tail call: slide the new frame down over the caller's,
						// so the two share one stack level.
						StkId const callerBase = L->ci[-1].base;
						StkId const source = callerBase + LuaGetArgA(i);
						if (L->openupval != nullptr) {
							luaF_close(L, callerBase);
						}

						int moved = 0;
						while (source + moved < L->top) {
							callerBase[moved - 1] = source[moved];
							++moved;
						}

						L->top = callerBase + moved;
						L->ci[-1].top = L->top;
						L->ci[-1].savedpc = L->ci->savedpc;
						++L->ci[-1].tailcalls; // one more call lost to the trace
						--L->ci;
						L->base = L->ci->base;
					}
					goto callentry;
				}

				if (firstResult > L->top) { // the C function yielded
					L->ci[-1].state = kFrameSuspended;
					L->ci[-1].savedpc = pc;
					G->lstate = previousActiveThread;
					return nullptr;
				}

				luaD_poscall(L, nresults, firstResult);
				if (nresults >= 0) {
					L->top = L->ci->top;
				}
				break;
			}

			case kOpReturn: op_Return: {
				CallInfo* const caller = &L->ci[-1];
				const int b = LuaGetArgB(i);
				if (b != 0) {
					L->top = ra + b - 1;
				}
				if (L->openupval != nullptr) {
					luaF_close(L, base);
				}
				L->ci->savedpc = pc;

				if (caller->state != kFrameCalling) {
					// Whoever called in was C code, so hand the results back.
					G->lstate = previousActiveThread;
					return ra;
				}

				// The caller is Lua and is waiting at its OP_CALL: finish the
				// call and resume it without leaving this function.
				const int nresults = LuaGetArgC(*caller->savedpc) - 1;
				luaD_poscall(L, nresults, ra);
				if (nresults >= 0) {
					L->top = L->ci->top;
				}
				L->ci->state = kFrameRunning;
				++L->ci->savedpc; // step past the OP_CALL
				goto retentry;
			}

			case kOpForLoop: op_ForLoop: {
				if (ra->tt != LUA_TNUMBER) {
					luaG_runerror(L, "`for' initial value must be a number");
				}
				if (ra[1].tt != LUA_TNUMBER) {
					float parsed = 0.0f;
					if (ra[1].tt != LUA_TSTRING
						|| luaO_str2d(static_cast<const TString*>(ra[1].value.p)->str, &parsed) == 0) {
						luaG_runerror(L, "`for' limit must be a number");
					}
					ra[1].value.n = parsed;
					ra[1].tt = LUA_TNUMBER;
				}
				if (ra[2].tt != LUA_TNUMBER) {
					float parsed = 0.0f;
					if (ra[2].tt != LUA_TSTRING
						|| luaO_str2d(static_cast<const TString*>(ra[2].value.p)->str, &parsed) == 0) {
						luaG_runerror(L, "`for' step must be a number");
					}
					ra[2].value.n = parsed;
					ra[2].tt = LUA_TNUMBER;
				}

				const float step = ra[2].value.n;
				const float limit = ra[1].value.n;
				const float index = ra->value.n + step;
				if ((step > 0.0f) ? (index <= limit) : (index >= limit)) {
					pc += LuaGetArgSBx(i); // jump back to the body
					ra->value.n = index;
				}
				break;
			}

			case kOpTForLoop: op_TForLoop: {
				const int nvar = LuaGetArgC(i) + 1;
				StkId callBase = ra + nvar + 2;
				callBase[0] = ra[0];
				callBase[1] = ra[1];
				callBase[2] = ra[2];
				L->top = callBase + 3; // iterator + state + control
				bool calledInPlace = false;
				if constexpr (kThreaded) {
					calledInPlace = LuaInlineNextCall(L, callBase, nvar);
				}
				if (!calledInPlace) {
					(void)luaD_call(L, callBase, nvar);
				}

				L->top = L->ci->top;
				// the call may have moved the stack, so find the slots again
				callBase = L->base + LuaGetArgA(i) + 2;
				for (int slot = nvar - 1; slot >= 0; --slot) {
					callBase[slot] = callBase[slot + nvar];
				}

				if (callBase->tt != LUA_TNIL) {
					pc += LuaGetArgSBx(*pc) + 1; // go round again
				} else {
					++pc; // control variable is nil: leave the loop
				}
				break;
			}

			case kOpTForPrep: op_TForPrep: {
				if (ra->tt == LUA_TTABLE) {
					// `for x in t' is shorthand for `for x in next, t'.
					ra[1].tt = LUA_TTABLE;
					ra[1].value.p = ra->value.p;
					TString* const nextName = luaS_newlstr(L, "next", 4u);
					*ra = *luaH_getstr(static_cast<Table*>(L->_gt.value.p), nextName);
				} else if (!IsCallableTag(ra->tt)) {
					L->ci->savedpc = pc - 1;
					luaG_typeerror(L, ra, "loop over");
				}
				pc += LuaGetArgSBx(i);
				break;
			}

			case kOpSetList: op_SetList:
			case kOpSetListO: op_SetListO: {
				if (ra->tt != LUA_TTABLE) {
					// Only a table constructor emits these, so a chunk that
					// reaches here with anything else is not runnable.
					G->lstate = previousActiveThread;
					return nullptr;
				}

				Table* const table = static_cast<Table*>(ra->value.p);
				const int bc = LuaGetArgBx(i);
				int n = 0;
				if (LuaGetOpcode(i) == kOpSetList) {
					n = (bc & static_cast<int>(kLuaFieldsPerFlushM1)) + 1;
				} else {
					n = static_cast<int>(L->top - ra) - 1; // the open call's results
					L->top = L->ci->top;
				}

				const int batchBase = bc & ~static_cast<int>(kLuaFieldsPerFlushM1);
				for (; n > 0; --n) {
					*luaH_setnum(L, table, batchBase + n) = ra[n];
					faf_lua51_gc_barrier_back(L, table); // Lua 5.1.5 lvm.c: OP_SETLIST
				}
				break;
			}

			case kOpClose: op_Close:
				luaF_close(L, ra);
				break;

			case kOpClosure: op_Closure: {
				Proto* const proto = cl->p->p[LuaGetArgBx(i)];
				const int nups = proto->nups;
				Closure* const closure = luaF_newLclosure(L, nups, &cl->g);
				closure->l.p = proto;

				// Each upvalue is described by one pseudo-instruction following
				// the OP_CLOSURE: either GETUPVAL to share the enclosing
				// closure's, or MOVE to capture a local.
				for (int up = 0; up < nups; ++up, ++pc) {
					const int index = LuaGetArgB(*pc);
					closure->l.upvals[up] = (LuaGetOpcode(*pc) == kOpGetUpval)
						? cl->upvals[index]
						: luaF_findupval(L, base + index);
					faf_lua51_gc_barrier_f(
						L,
						reinterpret_cast<GCObject*>(closure),
						reinterpret_cast<GCObject*>(closure->l.upvals[up])
					); // Lua 5.1.5 lvm.c: OP_CLOSURE
				}

				ra->tt = static_cast<int>(closure->l.tt);
				ra->value.p = closure;
				luaC_checkGC(L);
				break;
			}

			default: op_Default:
				break;
			}

			L->ci->savedpc = pc;
		}
	}
	} // extern "C++"

	/**
	 * Address: 0x00929C60 (FUN_00929C60, luaV_execute)
	 *
	 * IDA signature:
	 * TObject *__cdecl luaV_execute(lua_State *L);
	 *
	 * What it does:
	 * Runs Lua bytecode. Returns the first result of the frame that finished
	 * when control has to go back to whatever C code called in, or null when the
	 * interpreter was unwound by a yield.
	 *
	 * The loop is entered twice over: `callentry` for a fresh call, which fires
	 * the call hook first, and `retentry` for resuming a caller whose callee has
	 * just returned. A Lua-to-Lua call therefore never recurses into this
	 * function - OP_CALL jumps back to the top with the new frame in place, and
	 * OP_RETURN jumps back with the old one restored.
	 */
	TObject* luaV_execute(lua_State* L)
	{
		return moho::lua_ThreadedDispatch ? LuaExecute<true>(L) : LuaExecute<false>(L);
	}


	/**
	 * Address: 0x0091A690 (FUN_0091A690, luaO_pushvfstring)
	 *
	 * IDA signature:
	 * const char *__cdecl luaO_pushvfstring(lua_State *L, const char *fmt, va_list argp);
	 *
	 * What it does:
	 * Formats a message onto the Lua stack. Each literal run and each
	 * conversion is pushed as its own value and the lot is concatenated at the
	 * end, which is how the result becomes a collectable Lua string rather
	 * than something the caller has to free. Only %%, %c, %d, %f and %s are
	 * understood - anything else is dropped, as in the binary.
	 */
	void luaG_errormsg(lua_State* L);

	const char* luaO_pushvfstring(lua_State* const state, const char* fmt, va_list argp)
	{
		int pushed = 1;
		pushstr(state, "");

		const char* conversion = std::strchr(fmt, '%');
		while (conversion != nullptr) {
			TString* const literal = luaS_newlstr(state, fmt, static_cast<size_t>(conversion - fmt));
			TObject* top = state->top;
			top->tt = static_cast<int>(literal->tt);
			top->value.p = literal;
			api_incr_top(state);

			top = state->top;
			switch (conversion[1]) {
				case '%':
					pushstr(state, "%");
					break;
				case 'c': {
					char one[2];
					one[0] = static_cast<char>(va_arg(argp, int));
					one[1] = '\0';
					pushstr(state, one);
					break;
				}
				case 'd':
					top->value.n = static_cast<float>(va_arg(argp, int));
					top->tt = LUA_TNUMBER;
					api_incr_top(state);
					break;
				case 'f':
					top->value.n = static_cast<float>(va_arg(argp, double));
					top->tt = LUA_TNUMBER;
					api_incr_top(state);
					break;
				case 's':
					pushstr(state, va_arg(argp, const char*));
					break;
				default:
					break;
			}

			pushed += 2;
			fmt = conversion + 2;
			conversion = std::strchr(fmt, '%');
		}

		pushstr(state, fmt);
		luaV_concat(state, pushed + 1, static_cast<int>(state->top - state->base) - 1);
		state->top -= pushed;
		return static_cast<TString*>(state->top[-1].value.p)->str;
	}

	/**
	 * Address: 0x00913270 (FUN_00913270, luaG_runerror)
	 *
	 * IDA signature:
	 * void __cdecl luaG_runerror(lua_State *L, const char *fmt, ...);
	 *
	 * What it does:
	 * Raises a runtime error: formats the message onto the stack, tags it with
	 * the chunk and line it came from, and hands it to the error machinery.
	 * Never returns.
	 */
	void luaG_runerror(lua_State* const state, const char* const format, ...)
	{
		va_list arguments;
		va_start(arguments, format);
		const char* const message = luaO_pushvfstring(state, format, arguments);
		va_end(arguments);

		addinfo(state, message);
		luaG_errormsg(state);
	}

	/**
	 * Address: 0x0091A510 (FUN_0091A510, luaO_log2)
	 *
	 * IDA signature:
	 * int __cdecl luaO_log2(unsigned int x);
	 *
	 * What it does:
	 * Returns floor(log2(x)), or -1 for zero. Works a byte at a time off a
	 * 256-entry lookup table, so the answer costs one table read plus a
	 * constant.
	 */
	int luaO_log2(const unsigned int x)
	{
		// The binary carries this as 256 literal bytes at 0x00D46407; every
		// entry from 1 up is floor(log2(i)), which is cheaper to state than to
		// transcribe. Entry 0 is 0 there and unreachable here either way.
		static constexpr auto kLog2Byte = [] {
			std::array<unsigned char, 256> table{};
			for (unsigned int i = 2; i < 256; ++i) {
				table[i] = static_cast<unsigned char>(table[i / 2] + 1);
			}
			return table;
		}();

		if (x >= 0x10000u) {
			return (x >= 0x1000000u)
				? kLog2Byte[x >> 24] + 24
				: kLog2Byte[(x >> 16) & 0xFFu] + 16;
		}
		if (x >= 0x100u) {
			return kLog2Byte[(x >> 8) & 0xFFu] + 8;
		}
		return (x != 0u) ? kLog2Byte[x] : -1;
	}

	/**
	 * Address: 0x0091A5D0 (FUN_0091A5D0, luaO_str2d)
	 *
	 * IDA signature:
	 * int __usercall luaO_str2d@<eax>(const char *s, Number *result);
	 *
	 * What it does:
	 * Converts a numeric literal, accepting it only when the whole string is
	 * consumed apart from trailing space. Returns 0 on anything else, which is
	 * what makes `tonumber("1x")` nil.
	 */
	int luaO_str2d(const char* const s, float* const result)
	{
		char* end = nullptr;
		// Plan WPL.17: the Windows CRT's NaN spellings (LuaNumberText.h).
		const float value = static_cast<float>(lua::ParseNumberLikeWindowsCrt(s, &end));
		if (end == s) {
			return 0; // nothing converted
		}

		while (std::isspace(static_cast<unsigned char>(*end)) != 0) {
			++end; // trailing space is fine
		}
		if (*end != '\0') {
			return 0; // but nothing else is
		}

		*result = value;
		return 1;
	}

	/**
	 * Address: 0x0091A4E0 (FUN_0091A4E0, luaO_int2fb)
	 *
	 * IDA signature:
	 * unsigned int __cdecl luaO_int2fb(unsigned int x);
	 *
	 * What it does:
	 * Packs a size into Lua's "floating byte" form - three mantissa bits and an
	 * exponent - so that a table's array-part hint fits one instruction field.
	 * Values under 8 pass through unchanged.
	 */
	unsigned int luaO_int2fb(const unsigned int x)
	{
		unsigned int mantissa = x;
		int exponent = 0;
		while (mantissa >= 8u) {
			mantissa = (mantissa + 1u) >> 1;
			++exponent;
		}
		return mantissa | (static_cast<unsigned int>(exponent) << 3);
	}

	/**
	 * Address: 0x0091A8F0 (FUN_0091A8F0, luaO_chunkid)
	 *
	 * IDA signature:
	 * void __cdecl luaO_chunkid(char *out, const char *source, int bufflen);
	 *
	 * What it does:
	 * Renders a chunk name for an error message, in the three forms Lua's
	 * loader tags sources with. `=name` is used verbatim, `@file` is a file
	 * path shown from the tail with a leading ellipsis when it does not fit,
	 * and anything else is source text quoted as `[string "..."]`, truncated
	 * at the first newline or at the buffer limit.
	 */
	void luaO_chunkid(char* const out, const char* const source, const int bufflen)
	{
		if (*source == '=') {
			std::strncpy(out, source + 1, static_cast<size_t>(bufflen));
			out[bufflen - 1] = '\0';
			return;
		}

		if (*source == '@') {
			// File name: keep the tail, which is the part that identifies it.
			constexpr int kEllipsisReserve = 8;

			const char* path = source + 1;
			const int length = static_cast<int>(std::strlen(path));
			*out = '\0';

			if (length > bufflen - kEllipsisReserve) {
				path += length - (bufflen - kEllipsisReserve);
				std::strcat(out, "...");
			}

			std::strcat(out, path);
			return;
		}

		// Source text: show the first line, quoted.
		constexpr int kQuotingReserve = 17;

		int length = static_cast<int>(std::strcspn(source, "\n"));
		if (length > bufflen - kQuotingReserve) {
			length = bufflen - kQuotingReserve;
		}

		std::strcpy(out, "[string \"");
		if (source[length] != '\0') {
			std::strncat(out, source, static_cast<size_t>(length));
			std::strcat(out, "...");
		} else {
			std::strcat(out, source);
		}

		std::strcat(out, "\"]");
	}

	/**
	 * Address: 0x00912F30 (FUN_00912F30, addinfo)
	 *
	 * IDA signature:
	 * const char *__usercall addinfo(lua_State *L@<edi>, const char *msg);
	 *
	 * What it does:
	 * Prefixes an error message with the chunk name and line it came from,
	 * turning "attempt to call a nil value" into
	 * "script.lua(42): attempt to call a nil value". Only frames still running
	 * Lua bytecode carry that position, so a C frame is left unannotated.
	 */
	[[maybe_unused]] static void addinfo(lua_State* const state, const char* const msg)
	{
		constexpr int kChunkIdBufferSize = 60;
		constexpr int kCallInfoStateRunningLua = 3;

		CallInfo* const ci = state->ci;
		if (ci->state >= kCallInfoStateRunningLua) {
			return;
		}

		const Proto* const proto = static_cast<GCObject*>(ci->base[-1].value.p)->cl.l.p;
		const ptrdiff_t pc = ci->savedpc - proto->code;

		int line = -1;
		if (pc >= 0) {
			line = (proto->lineinfo != nullptr) ? proto->lineinfo[pc] : 0;
		}

		char chunkId[kChunkIdBufferSize];
		luaO_chunkid(chunkId, proto->source->str, kChunkIdBufferSize);
		(void)luaO_pushfstring(state, "%s(%d): %s", chunkId, line, msg);
	}

	/**
	 * Address: 0x0090D430 (FUN_0090D430, lua_call)
	 *
	 * IDA signature:
	 * int __cdecl lua_call(lua_State *L, int nargs, int nresults);
	 *
	 * What it does:
	 * Calls the function sitting `nargs` slots below the top, leaving
	 * `nresults` values in its place, and reports whether it got there: 0 on
	 * success, the raised lua::lua_Error's own code otherwise, or LUA_ERRRUN
	 * for anything else that escapes.
	 *
	 * This is the fork's only protected-call entry point - it has no
	 * lua_pcall, no luaD_pcall and no luaD_rawrunprotected, because the C++
	 * exceptions it raises need a try rather than a setjmp. The body is one EH
	 * region around luaD_call with two handlers, at 0x0090D48D (reads `code`
	 * from the error at +0x28 and returns it) and 0x0090D4B0 (returns 1).
	 *
	 * It used to be recovered as a void passthrough on the assumption that
	 * "lua_pcall catches them", so callers reached for the prebuilt LuaPlus
	 * lua_pcall instead - which walks this state at stock offsets, writes an
	 * errfunc field past the end of our 0x48-byte lua_State, and cannot catch a
	 * C++ throw through its setjmp anyway. A script error consequently unwound
	 * past every protected boundary and out of WinMain.
	 */
	int LuaCallProtected(lua_State* const state, const int nargs, const int nresults)
	{
		StkId const func = state->top - (nargs + 1);
		try {
			(void)luaD_call(state, func, nresults);
		} catch (const lua::lua_Error& error) {
			return error.code;
		} catch (...) {
			return LUA_ERRRUN;
		}
		return 0;
	}

	/**
	 * Address: 0x0090D400 (FUN_0090D400, lua_call)
	 * Mangled: ?lua_call@@YAXPAUlua_State@@HH@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_call(lua_State *L, int nargs, int nresults);
	 *
	 * What it does:
	 * Calls with no handler, so an error unwinds to the caller's own protected
	 * boundary instead of being turned into a status nobody reads.
	 */
	void LuaCallUnprotected(lua_State* const state, const int nargs, const int nresults)
	{
		(void)luaD_call(state, state->top - (nargs + 1), nresults);
	}

	/**
	 * Address: 0x00913C30 (FUN_00913C30, tryFuncTM)
	 *
	 * IDA signature:
	 * StkId __usercall tryFuncTM(TObject *func@<eax>, lua_State *L@<esi>);
	 *
	 * What it does:
	 * Handles a call on something that is not a function. The value's `__call`
	 * tag method becomes the callee and the original value is shifted up to
	 * become its first argument, so `t(x)` turns into `mt.__call(t, x)`.
	 */
	static StkId tryFuncTM(StkId func, lua_State* const state)
	{
		constexpr int kTagMethodCall = 17;

		const TObject* const handler = luaT_gettmbyobj(state, func, kTagMethodCall);
		const ptrdiff_t funcOffset = reinterpret_cast<char*>(func) - reinterpret_cast<char*>(state->stack);

		if (!IsCallableTag(handler->tt)) {
			luaG_typeerror(state, func, "call");
		}

		// Open a slot at `func` by sliding everything above it up one.
		for (StkId slot = state->top; slot > func; --slot) {
			slot[0] = slot[-1];
		}

		if (state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}

		++state->top;

		StkId const target = reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + funcOffset);
		target->tt = handler->tt;
		target->value.p = handler->value.p;
		return target;
	}

	/**
	 * Address: 0x00913D40 (FUN_00913D40, luaD_poscall)
	 *
	 * IDA signature:
	 * void __cdecl luaD_poscall(lua_State *L, int wanted, StkId firstResult);
	 *
	 * What it does:
	 * Tears the finished frame down: pops the CallInfo, restores `base`, then
	 * slides the results down over the callee and its arguments, padding with
	 * nil when fewer were produced than the caller asked for.
	 */
	void luaD_poscall(lua_State* const state, int wanted, StkId firstResult)
	{
		constexpr lu_byte kHookMaskReturn = 1 << 1;

		if ((state->l_G->hookmask & kHookMaskReturn) != 0) {
			firstResult = callrethooks(firstResult, state);
		}

		--state->ci;
		StkId result = state->base - 1;
		state->base = state->ci->base;

		for (; wanted != 0 && firstResult < state->top; --wanted) {
			*result++ = *firstResult++;
		}

		for (; wanted > 0; --wanted) {
			(result++)->tt = LUA_TNIL;
		}

		state->top = result;
	}

	namespace
	{
		// Engine addition (LuaCallGate.h): this thread's gate, and how many threads have one, so the
		// C-call path reads one shared word and reaches thread-local storage only while a gate is set.
		thread_local moho::LuaCallGate tLuaCallGate = nullptr;
		std::atomic<int> sLuaCallGateCount{0};

		inline void RunLuaCallGate(const moho::LuaCFunctionPtr function)
		{
			if (sLuaCallGateCount.load(std::memory_order_relaxed) != 0) {
				if (const moho::LuaCallGate gate = tLuaCallGate; gate != nullptr) {
					gate(function);
				}
			}
		}
	} // namespace

	/**
	 * Address: 0x009142A0 (FUN_009142A0, luaD_precall)
	 *
	 * IDA signature:
	 * StkId __cdecl luaD_precall(lua_State *L, StkId func);
	 *
	 * What it does:
	 * Opens a call frame. A Lua closure gets its stack reserved and returns
	 * null, telling the caller to run the interpreter; a C closure is invoked
	 * here and its first result returned. Anything else is routed through
	 * `__call` first.
	 */
	LuaCFunctionCallHook gLuaCFunctionCallHook = nullptr;

	StkId luaD_precall(lua_State* const state, StkId func)
	{
		constexpr int kMinCStackSlots = 20;
		constexpr lu_byte kHookMaskCall = 1 << 0;

		// This fork's CallInfo::state is a small enum, not stock Lua's bitmask:
		// 0 is a Lua frame running here, 1 is a frame whose callee sits on top,
		// 2 is one unwinding out to its C caller, and 3 is a C function's own
		// frame - `mov dword ptr [eax+8], 3` at 0x009143D3.
		//
		// Writing 1 here instead marked every C frame "calling", so when a
		// chunk invoked from C returned, OP_RETURN took the resume path and
		// dereferenced the null savedpc that belongs to a C frame. Any script
		// loaded through dofile faulted the moment it finished.
		constexpr int kFrameCFunction = 3;

		const ptrdiff_t funcOffset = reinterpret_cast<char*>(func) - reinterpret_cast<char*>(state->stack);

		if (!IsCallableTag(func->tt)) {
			func = tryFuncTM(func, state);
		}

		if (&state->ci[1] == state->end_ci) {
			luaD_growCI(state);
		}

		if (func->tt == LUA_TFUNCTION) {
			// Lua closure: reserve its registers and hand back to the caller,
			// which runs luaV_execute over the frame we just opened.
			Proto* const proto = static_cast<GCObject*>(func->value.p)->cl.l.p;

			if (proto->is_vararg != 0) {
				adjust_varargs(state, proto->numparams, func + 1);
			}

			if (state->stack_last - state->top <= proto->maxstacksize) {
				luaD_growstack(state, proto->maxstacksize);
			}

			CallInfo* const ci = ++state->ci;
			ci->base = reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + funcOffset) + 1;
			state->base = ci->base;
			ci->top = state->base + proto->maxstacksize;
			ci->savedpc = proto->code;
			ci->tailcalls = 0;
			ci->state = 0;
			ci->pc = nullptr;
			ci->reserved0 = 0;
			ci->reserved1 = 0;
			ci->reserved2 = 0;

			for (; state->top < ci->top; ++state->top) {
				state->top->tt = LUA_TNIL;
			}

			state->top = ci->top;
			// Per-proto invocation counter at Proto+0x68 (reserved8). The binary
			// bumps only the low dword - "add dword ptr [edi+68h], 1" with no
			// carry - so this is a 32-bit increment, not a 64-bit one.
			reinterpret_cast<std::uint32_t&>(proto->reserved8) += 1u;
			return nullptr;
		}

		if (state->stack_last - state->top <= kMinCStackSlots) {
			luaD_growstack(state, kMinCStackSlots);
		}

		CallInfo* const ci = ++state->ci;
		ci->base = reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + funcOffset) + 1;
		state->base = ci->base;
		ci->top = state->top + kMinCStackSlots;
		ci->state = kFrameCFunction;
		ci->savedpc = nullptr;
		ci->tailcalls = 0;
		ci->pc = nullptr;
		ci->reserved0 = 0;
		ci->reserved1 = 0;
		ci->reserved2 = 0;

		if ((state->l_G->hookmask & kHookMaskCall) != 0) {
			luaD_callhook(state, LUA_HOOKCALL, -1);
		}

		Closure* const closure = static_cast<Closure*>(state->base[-1].value.p);

		// The two words at upvalue_m1[0] are one 64-bit invocation counter this
		// fork keeps per C closure - the binary increments the low half and
		// carries into the high half. It is the same field `func_profiledata`
		// reports as LuaProfileRecord::invocationCount, reaching it as
		// CClosure+0x18+0x20 instead; an assert there ties the two views of it
		// together.
		std::uint32_t& invocationsLow = reinterpret_cast<std::uint32_t&>(closure->c.upvalue_m1[0].tt);
		std::uint32_t& invocationsHigh = reinterpret_cast<std::uint32_t&>(closure->c.upvalue_m1[0].value.b);
		const std::uint32_t previousLow = invocationsLow++;
		if (invocationsLow < previousLow) {
			++invocationsHigh;
		}

#if defined(TRACY_ENABLE)
		// Profile builds: one zone per engine function Lua calls, named by its binder.
		FAF_PROFILE_ZONE_TRANSIENT(gpg::profiling::LuaCFunctionName(reinterpret_cast<const void*>(closure->c.f)));
#endif
		RunLuaCallGate(closure->c.f); // engine addition, LuaCallGate.h
		if (const LuaCFunctionCallHook hook = gLuaCFunctionCallHook; hook != nullptr) {
			hook(closure->c.f);
		}

		const int produced = closure->c.f(state);
		return state->top - produced;
	}

	/**
	 * Address: 0x00914430 (FUN_00914430, luaD_call)
	 *
	 * IDA signature:
	 * void __cdecl luaD_call(lua_State *L, StkId func, int nResults);
	 *
	 * What it does:
	 * Calls `func` and leaves `nResults` values behind it. Guards the C stack
	 * against runaway recursion, and on any error unwinds this frame back to
	 * the depth it started at - closing upvalues, planting the message where
	 * the caller expects it, and restoring the hook gate - before letting the
	 * error continue outward.
	 */
	int luaD_call(lua_State* const state, StkId func, const int nResults)
	{
		constexpr unsigned int kMaxCCalls = 200;
		constexpr unsigned int kMaxCCallsHandling = kMaxCCalls + (kMaxCCalls >> 3);

		const ptrdiff_t frameOffset =
			reinterpret_cast<char*>(state->ci) - reinterpret_cast<char*>(state->base_ci);
		const std::uint16_t savedNestedCalls = state->nCcalls;
		const lu_byte savedAllowHook = state->l_G->allowhook;
		const ptrdiff_t funcOffset = reinterpret_cast<char*>(func) - reinterpret_cast<char*>(state->stack);

		++state->nCcalls;

		// Unwind this frame back to the depth it started at, planting the
		// message where the caller expects it, then let the error continue
		// outward. Shared by the two handlers below.
		const auto unwindFrameForError = [&](const char* const message) {
			StkId const errorSlot =
				reinterpret_cast<StkId>(reinterpret_cast<char*>(state->stack) + funcOffset);
			luaF_close(state, errorSlot);
			(void)PushLuaStringAtStackSlot(state, errorSlot, message);

			state->ci = reinterpret_cast<CallInfo*>(
				reinterpret_cast<char*>(state->base_ci) + frameOffset
			);
			state->base = state->ci->base;
			state->nCcalls = savedNestedCalls;
			state->l_G->allowhook = savedAllowHook;
			(void)luaD_refreshstacklimit(state);
		};

		try {
			// 0x00914488 opens the try scope before the depth test at 0x0091447B,
			// so both overflow errors unwind through this frame's handler, which
			// puts nCcalls back. Raised outside it, every "C stack overflow"
			// caught by a script callback left the count one high, and the limit
			// stopped firing once the count had stepped past 200.
			if (state->nCcalls >= kMaxCCalls) {
				if (state->nCcalls == kMaxCCalls) {
					luaG_runerror(state, "C stack overflow");
				} else if (state->nCcalls >= kMaxCCallsHandling) {
					throw lua_ErrorError(lua::lua_Error(state, LUA_ERRERR, "error in Lua error handling"));
				}
			}

			StkId firstResult = luaD_precall(state, func);
			if (firstResult == nullptr) {
				firstResult = luaV_execute(state);
			}

			luaD_poscall(state, nResults, firstResult);
		} catch (const fa::exception& error) {
			// Every lua_Error arrives here: fa::exception is what MSVC8's
			// std::exception was, and the original caught exactly that.
			unwindFrameForError(error.what());
			throw;
		} catch (const std::exception& error) {
			// Still needed while the rest of the tree sits on the modern
			// hierarchy - CRT bad_alloc, gpg's own exception types.
			unwindFrameForError(error.what());
			throw;
		}

		--state->nCcalls;
		luaC_checkGC(state);
		return 0;
	}

	/**
	 * Address: 0x00915290 (FUN_00915290, luaC_separateudata)
	 *
	 * IDA signature:
	 * size_t __usercall luaC_separateudata(lua_State *L);
	 *
	 * What it does:
	 * Moves every unreachable userdata that still wants finalising off the
	 * live list and onto `tmudata`, returning the total bytes they occupy so
	 * the collector can charge them against the allocation counter before the
	 * finalisers have actually run.
	 */
	static size_t luaC_separateudata(lua_State* const state)
	{
		constexpr lu_byte kReachableMask = 0x11;
		constexpr lu_byte kWantsFinaliserMask = 0x02;

		global_State* const globalState = state->l_G;
		GCObject** survivor = &globalState->rootudata;
		GCObject* collected = nullptr;
		GCObject** lastCollected = &collected;
		size_t deadmem = 0;

		for (GCObject* current = *survivor; current != nullptr; current = *survivor) {
			const lu_byte marked = current->gch.marked;
			if ((marked & kReachableMask) != 0 || (marked & kWantsFinaliserMask) == 0) {
				survivor = &current->gch.next;
				continue;
			}

			// The payload's x86 size: deadmem is charged against nblocks (x64 port, LuaMemAccounting.h).
			deadmem += static_cast<size_t>(LuaX86PayloadSize(reinterpret_cast<gpg::RType*>(current->u.len)));
			*survivor = current->gch.next;
			current->gch.next = nullptr;
			*lastCollected = current;
			lastCollected = &current->gch.next;
		}

		*lastCollected = state->l_G->tmudata;
		state->l_G->tmudata = collected;
		return deadmem;
	}

	/**
	 * Address: 0x00915B20 (FUN_00915B20, luaC_callGCTM)
	 *
	 * IDA signature:
	 * void __cdecl luaC_callGCTM(lua_State *L);
	 *
	 * What it does:
	 * Runs the finaliser for every userdata `luaC_separateudata` set aside,
	 * returning each one to the live list first so a finaliser that resurrects
	 * its object finds it intact. Hooks stay disabled for the duration. Unlike
	 * stock Lua this does not look up a `__gc` metamethod - the fork calls the
	 * reflected destructor recorded on the userdata's RType instead, which is
	 * why the payload pointer rather than a Lua value is what gets passed.
	 */
	static void luaC_callGCTM(lua_State* const state)
	{
		constexpr lu_byte kClearFinaliserBits = 0xFC;

		global_State* const globalState = state->l_G;
		const lu_byte savedAllowHook = globalState->allowhook;
		globalState->allowhook = 0;

		// One reserved slot holds the userdata across the finaliser call.
		++state->top;

		while (state->l_G->tmudata != nullptr) {
			GCObject* const udata = state->l_G->tmudata;

			state->l_G->tmudata = udata->gch.next;
			udata->gch.next = state->l_G->rootudata;
			state->l_G->rootudata = udata;
			sweep_boundaries::NoteLinked(state->l_G, sweep_boundaries::kListUserdata, udata); // engine addition: lua_ParallelSweep

			TObject* const slot = state->top - 1;
			slot->value.p = udata;
			slot->tt = static_cast<int>(udata->gch.tt);

			udata->gch.marked &= kClearFinaliserBits;

			auto* const type = reinterpret_cast<gpg::RType*>(udata->u.len);
			type->dtrFunc_(static_cast<void*>(&udata->u + 1));
		}

		--state->top;
		state->l_G->allowhook = savedAllowHook;
	}

	/**
	 * Engine fix, not in the binary: `t[k] = nil` leaves k in its node with a nil value, and the binary keeps
	 * the pointer after k is freed. A new string or object at the same address then matches that node if its
	 * chain passes there, so it is stored outside its own chain. The next insert that moves the chain away
	 * strands it: `next` fails with "invalid key" and `newkey` walks off the chain's end through a null node
	 * (replay 26841630; retail crashes on the same read, 0x009279A6).
	 *
	 * So a removed key that this collection frees becomes a dead key, as a weak table's cleared key does.
	 * Only those: a key still alive may be set again or be `next`'s position, and keeps its node as in the
	 * binary. No node moves and nothing allocates from Lua, so table order and nblocks stay the same. Called
	 * after the last mark, while every node listed still belongs to a live table.
	 */
	static void ForgetDeadRemovedKeys(std::vector<Node*>& nodes) noexcept
	{
		for (Node* const node : nodes) {
			const LuaPlus::TObject key = node->Key();
			if (key.tt >= LUA_TSTRING && (static_cast<GCObject*>(key.value.p)->gch.marked & 0x11u) == 0u) {
				node->SetKeyTag(LUA_TNONE);
			}
		}
		nodes.clear();
	}

	/**
	 * Address: 0x00915CC0 (FUN_00915CC0, mark)
	 *
	 * IDA signature:
	 * size_t __usercall mark(lua_State *L@<eax>);
	 *
	 * What it does:
	 * The mark half of one collection cycle. Roots are marked and propagated,
	 * then weak-valued tables are cleared before userdata pending finalisation
	 * are separated out and re-marked - they and anything they reach have to
	 * survive long enough for their finalisers to run. A second propagation
	 * covers that resurrection, after which the weak tables are cleared for
	 * real. Returns the bytes owed by the separated userdata.
	 */
	static size_t mark(lua_State* const state)
	{
		constexpr lu_byte kMarkedBit = 0x01;

		GCState st{};
		st.g = state->l_G;
		st.L = state;

		// Engine change (lua_ParallelMark): decided once, so a switch flipped mid-collection
		// cannot mix the paths.
		const bool parallel = parallel_mark::Enabled();
		// This collection's weak tables, local to it: the user VM collects on the main thread while
		// the sim VM marks, so the two cannot share one set (see parallel_mark::WeakSets).
		parallel_mark::WeakSets weakSets;

		GcDetailLaps lap; // FAF_LUAGC_TIMING only

		// Engine addition (lua_GcVerify, debug only): the serial reference of the first propagation.
		const bool verify = parallel && gc_verify::Enabled();
		const std::size_t noWeakBefore[3] = {0u, 0u, 0u};
		if (verify) {
			gc_verify::sCollection.fetch_add(1);
			gc_verify::CheckLuaObjectList(st.g);
			gc_verify::TakeReference(st.g, 1, [state](GCState& reference) {
				reference.g = state->l_G;
				reference.L = state;
				markroot(&reference, state);
			});
		}

		LuaState* const rootObjects = MarkRootForCollection(&st, state, parallel); // engine change: lua_ParallelMark
		lap("root");
		PropagateMarksForCollection(&st, parallel, weakSets, rootObjects); // engine change: lua_ParallelMark, see there
		lap("propagate");
		if (verify) {
			gc_verify::CompareReference(weakSets.tables, noWeakBefore);
			if (gc_verify::sCollection.load() % 100 == 1) {
				gpg::Logf("[GCVERIFY-OK] collection %ld verified, %zu objects", gc_verify::sCollection.load(), gc_verify::sReference.objects.size());
			}
		}

		std::vector<Table*> weakKeyValueVector; // engine change: lua_ParallelMark (the wkv tables of the first pass)
		if (parallel) {
			using namespace parallel_weak;
			Clear({{&weakSets.tables[parallel_mark::kWeakBoth], kValues}, {&weakSets.tables[parallel_mark::kWeakValues], kValues}});
			weakKeyValueVector = std::move(weakSets.tables[parallel_mark::kWeakBoth]);
			weakSets.tables[parallel_mark::kWeakBoth].clear();
			weakSets.tables[parallel_mark::kWeakValues].clear();
		} else {
			cleartablevalues(st.wkv);
			cleartablevalues(st.wv);
		}

		GCObject* const weakKeyValueTables = st.wkv;
		st.wkv = nullptr;
		st.wv = nullptr;
		lap("weak");

		size_t deadmem = 0;
		if (!parallel || !parallel_sweep::SeparateUserdata(state, deadmem)) { // engine change: lua_ParallelMark
			deadmem = luaC_separateudata(state);
		}
		lap("separate");

		for (GCObject* udata = st.g->tmudata; udata != nullptr; udata = udata->gch.next) {
			udata->gch.marked &= static_cast<lu_byte>(~kMarkedBit);
			reallymarkobject(&st, udata);
		}

		// lua_GcVerify: the serial reference of the second propagation, from the same gray chain
		// (rebuilt afterwards, since the reference consumed it).
		const std::size_t weakBefore[3] = {weakSets.tables[0].size(), weakSets.tables[1].size(), weakSets.tables[2].size()};
		if (verify) {
			std::vector<GCObject*> chain;
			for (GCObject* object = st.tmark; object != nullptr; object = parallel_mark::NextGray(object)) {
				chain.push_back(object);
			}
			gc_verify::TakeReference(st.g, 2, [&st](GCState& reference) {
				reference.g = st.g;
				reference.L = st.L;
				reference.tmark = st.tmark;
			});
			for (std::size_t index = 0; index < chain.size(); ++index) {
				GCObject* const object = chain[index];
				GCObject* const next = index + 1u < chain.size() ? chain[index + 1u] : nullptr;
				switch (object->gch.tt) {
				case LUA_TTABLE: object->h.gclist = next; break;
				case LUA_CFUNCTION:
				case LUA_TFUNCTION: object->cl.c.gclist = next; break;
				case LUA_TTHREAD: object->th.gclist = next; break;
				case LUA_TPROTO: object->p.gclist = next; break;
				default: break;
				}
			}
		}

		PropagateMarksForCollection(&st, parallel, weakSets); // engine change: lua_ParallelMark, see there
		lap("propagate");
		if (verify) {
			gc_verify::CompareReference(weakSets.tables, weakBefore);
		}

		if (parallel) { // engine change: lua_ParallelMark
			using namespace parallel_weak;
			Clear({
				{&weakKeyValueVector, kKeys},
				{&weakSets.tables[parallel_mark::kWeakKeys], kKeys},
				{&weakSets.tables[parallel_mark::kWeakValues], kValues},
				{&weakSets.tables[parallel_mark::kWeakBoth], kKeys | kValues},
			});
		} else {
			cleartablekeys(weakKeyValueTables);
			cleartablekeys(st.wk);
			cleartablevalues(st.wv);
			cleartablekeys(st.wkv);
			cleartablevalues(st.wkv);
		}
		lap("weak");
		if (verify) { // lua_GcVerify
			gc_verify::CheckWeakInvariant(st.g);
			gc_verify::CheckDeadThreadUpvalues(st.g);
		}

		ForgetDeadRemovedKeys(weakSets.removedKeys);
		ForgetDeadRemovedKeys(tRemovedKeyNodes);

		return deadmem;
	}

	/**
	 * Address: 0x00915D90 (FUN_00915D90, luaC_collectgarbage)
	 *
	 * IDA signature:
	 * void __cdecl luaC_collectgarbage(lua_State *L);
	 *
	 * What it does:
	 * One full stop-the-world cycle: mark, sweep the four collectable lanes,
	 * resize the string table and recompute the threshold, then run the
	 * finalisers that the mark phase deferred.
	 */
	void luaC_collectgarbage(lua_State* const state)
	{
		if (moho::lua_IncrementalGC && moho::lua_incremental::IsUiState(state->l_G)) {
			const moho::lua_incremental::SState* const incremental =
				moho::lua_incremental::Find(state->l_G);
			if (incremental != nullptr && incremental->frameDriven) {
				return;
			}
			faf_lua51_gc_step(state); // Lua 5.1.5 lgc.c: luaC_step()
			return;
		}
		RunLuaCallGate(nullptr); // engine addition, LuaCallGate.h: finalizers may reach the engine
		FAF_PROFILE_ZONE_TRANSIENT(moho::IsSimThread() ? "Sim::LuaGC" : "UI::LuaGC");

		// x64 port test mode (plan 4.1a), not in the binary: FAF_LUAGC_LOG.
		lua::GcEventLogCollection(state->l_G, state->l_G->nblocks, state->l_G->GCthreshold);

		lua::GcTimer timer(state->l_G, state->l_G->nblocks); // engine addition: FAF_LUAGC_TIMING
		const size_t deadmem = mark(state);
		timer.Lap(lua::GcTimer::kMark);

		SweepForCollection(state); // engine change: lua_ParallelSweep, see there
		timer.Lap(lua::GcTimer::kSweep);

		checkSizes(state, deadmem);
		luaC_callGCTM(state);
		timer.Lap(lua::GcTimer::kFinalize);
	}

	/**
	 * Engine addition (replay keyframes): one full collection that treats weak tables as strong.
	 * After a keyframe's load it frees what the session's start built and the keyframe replaced, and
	 * nothing the keyframe holds, however weakly, since the game had not collected that yet.
	 */
	extern "C" void lua_collectkeepingweaktables(lua_State* const state)
	{
		sKeepWeakTablesOf.store(state->l_G, std::memory_order_relaxed);
		luaC_collectgarbage(state);
		sKeepWeakTablesOf.store(nullptr, std::memory_order_relaxed);
	}

	/**
	 * Address: 0x009284A0 (FUN_009284A0, luaT_getmetatable)
	 *
	 * IDA signature:
	 * Table *__cdecl luaT_getmetatable(lua_State *L, const TObject *o);
	 *
	 * What it does:
	 * Returns the metatable governing one value: tables and userdata carry
	 * their own, everything else shares the per-type default.
	 */
	Table* luaT_getmetatable(lua_State* const state, const TObject* const object)
	{
		switch (object->tt) {
			case LUA_TTABLE:
				return static_cast<Table*>(object->value.p)->metatable;
			case LUA_TUSERDATA:
				return static_cast<Udata*>(object->value.p)->metatable;
			default:
				return static_cast<Table*>(state->l_G->_defaultmetatypes[object->tt].value.p);
		}
	}

	/**
	 * Address: 0x009293E0 (FUN_009293E0, luaV_gettable)
	 *
	 * IDA signature:
	 * const TObject *__cdecl luaV_gettable(lua_State *L, const TObject *t, const TObject *key, int loop);
	 *
	 * What it does:
	 * Reads `t[key]` with full `__index` semantics. A raw hit on a real table
	 * returns immediately; a miss, or a non-table subject, continues down the
	 * metatable chain. `loop` counts the hops taken so far and trips the
	 * "loop in gettable" error past 100.
	 */
	const TObject* luaV_gettable(
		lua_State* const state,
		const TObject* const t,
		const TObject* const key,
		const int loop
	)
	{
		constexpr int kMaxTagMethodChain = 100;

		if (loop > kMaxTagMethodChain) {
			luaG_runerror(state, "loop in gettable");
		}

		if (t->tt != LUA_TTABLE) {
			return luaV_getnotable(state, t, key, loop + 1);
		}

		const TObject* const value = luaH_get(static_cast<Table*>(t->value.p), key);
		if (value->tt != LUA_TNIL) {
			return value;
		}

		return luaV_index(state, t, key, loop + 1);
	}

	/**
	 * Address: 0x00929BF0 (FUN_00929BF0, luaV_index)
	 *
	 * IDA signature:
	 * const TObject *__cdecl luaV_index(lua_State *L, const TObject *t, const TObject *key, int loop);
	 *
	 * What it does:
	 * Handles a raw miss on a real table. The metatable's cached "no __index
	 * here" flag short-circuits to nil without touching the table at all;
	 * otherwise a callable handler is invoked and anything else is re-indexed.
	 */
	const TObject* luaV_index(
		lua_State* const state,
		const TObject* const t,
		const TObject* const key,
		const int loop
	)
	{
		constexpr int kTagMethodIndex = 0;
		constexpr int kNoIndexTagMethodFlag = 1 << kTagMethodIndex;

		Table* const metatable = static_cast<Table*>(t->value.p)->metatable;
		if ((metatable->flags & kNoIndexTagMethodFlag) != 0) {
			return &luaO_nilobject;
		}

		const TObject* const handler =
			luaT_gettm(metatable, kTagMethodIndex, state->l_G->tmname[kTagMethodIndex]);
		if (handler == nullptr) {
			return &luaO_nilobject;
		}

		if (IsCallableTag(handler->tt)) {
			(void)callTMres(handler, t, key, state);
			return state->top;
		}

		return luaV_gettable(state, handler, key, loop);
	}

	/**
	 * Address: 0x00929370 (FUN_00929370, luaV_getnotable)
	 *
	 * IDA signature:
	 * const TObject *__usercall luaV_getnotable(lua_State *L@<eax>, const TObject *t@<edi>,
	 *     const TObject *key@<ebx>, int loop);
	 *
	 * What it does:
	 * Handles indexing a value that is not a table. The per-type `__index` tag
	 * method wins if there is one; failing that the value's whole metatable
	 * stands in as the handler, so `("x").upper` resolves through the string
	 * metatable.
	 */
	const TObject* luaV_getnotable(
		lua_State* const state,
		const TObject* const t,
		const TObject* const key,
		const int loop
	)
	{
		constexpr int kTagMethodIndex = 0;

		const TObject* handler = luaT_gettmbyobj(state, t, kTagMethodIndex);

		TObject metatableAsHandler{};
		if (handler->tt == LUA_TNIL) {
			Table* const metatable = luaT_getmetatable(state, t);
			metatableAsHandler.tt = static_cast<int>(metatable->tt);
			metatableAsHandler.value.p = metatable;
			handler = &metatableAsHandler;
		}

		if (IsCallableTag(handler->tt)) {
			(void)callTMres(handler, t, key, state);
			return state->top;
		}

		return luaV_gettable(state, handler, key, loop);
	}

	/**
	 * Address: 0x0090D000 (FUN_0090D000, lua_gettable)
	 * Mangled: ?lua_gettable@@YAXPAUlua_State@@H@Z
	 *
	 * IDA signature:
	 * void __cdecl lua_gettable(lua_State *L, int idx);
	 *
	 * What it does:
	 * Replaces the key on top of the stack with `t[key]`, honouring metatables.
	 */
	void lua_gettable(lua_State* const state, const int idx)
	{
		const TObject* const table = luaA_index(state, idx);
		TObject* const key = state->top - 1;
		*key = *luaV_gettable(state, table, key, 0);
	}

	/**
	 * Address: 0x0090D050 (FUN_0090D050, lua_rawget)
	 *
	 * IDA signature:
	 * void __cdecl lua_rawget(lua_State *L, int idx);
	 *
	 * What it does:
	 * Replaces the key on top of the stack with `t[key]`, without consulting
	 * any metatable.
	 */
	void lua_rawget(lua_State* const state, const int idx)
	{
		const TObject* const table = luaA_index(state, idx);
		TObject* const key = state->top - 1;
		*key = *luaH_get(static_cast<Table*>(table->value.p), key);
	}

	/**
	 * Address: 0x0090D2A0 (FUN_0090D2A0, lua_rawset)
	 *
	 * IDA signature:
	 * void __cdecl lua_rawset(lua_State *L, int idx);
	 *
	 * What it does:
	 * Stores `t[key] = value` from the top two stack slots and pops both,
	 * bypassing metatables.
	 */
	void lua_rawset(lua_State* const state, const int idx)
	{
		const TObject* const table = luaA_index(state, idx);
		TObject* const key = state->top - 2;
		*luaH_set(state, static_cast<Table*>(table->value.p), key) = *(state->top - 1);
		faf_lua51_gc_barrier_back(state, static_cast<Table*>(table->value.p)); // Lua 5.1.5 lapi.c: lua_rawset()
		state->top -= 2;
	}

	/**
	 * Address: 0x0090D2F0 (FUN_0090D2F0, lua_rawseti)
	 *
	 * IDA signature:
	 * void __cdecl lua_rawseti(lua_State *L, int idx, int n);
	 *
	 * What it does:
	 * Stores `t[n] = value` from the top stack slot and pops it, bypassing
	 * metatables.
	 */
	void lua_rawseti(lua_State* const state, const int idx, const int n)
	{
		const TObject* const table = luaA_index(state, idx);
		*luaH_setnum(state, static_cast<Table*>(table->value.p), n) = *(state->top - 1);
		faf_lua51_gc_barrier_back(state, static_cast<Table*>(table->value.p)); // Lua 5.1.5 lapi.c: lua_rawseti()
		--state->top;
	}

	/**
	 * Address: 0x0090D340 (FUN_0090D340, lua_setmetatable)
	 *
	 * IDA signature:
	 * int __cdecl lua_setmetatable(lua_State *L, int objindex);
	 *
	 * What it does:
	 * Pops a metatable off the stack and installs it on the value at
	 * `objindex`. A nil on top means "no metatable of its own", which this
	 * fork expresses by installing the shared default metatable rather than a
	 * null pointer - so a table's metatable lane is never empty. Returns 1
	 * when the target can carry one, 0 for tags that cannot.
	 */
	int lua_setmetatable(lua_State* const state, const int objindex)
	{
		const TObject* const object = luaA_index(state, objindex);

		const TObject* metatable = state->top - 1;
		if (metatable->tt == LUA_TNIL) {
			metatable = &state->l_G->_defaultmeta;
		}

		int applied = 1;
		switch (object->tt) {
			case LUA_TTABLE: {
				Table* const target = static_cast<Table*>(object->value.p);
				target->metatable = static_cast<Table*>(metatable->value.p);
				faf_lua51_gc_barrier_back(state, target); // Lua 5.1.5 lapi.c: lua_setmetatable()
				break;
			}
			case LUA_TUSERDATA:
				static_cast<Udata*>(object->value.p)->metatable = static_cast<Table*>(metatable->value.p);
				faf_lua51_gc_barrier_value(
					state,
					static_cast<GCObject*>(object->value.p),
					metatable
				); // Lua 5.1.5 lapi.c: lua_setmetatable()
				break;
			default:
				applied = 0;
				break;
		}

		--state->top;
		return applied;
	}

	/**
	 * Address: 0x00915DF0 (FUN_00915DF0, luaC_link)
	 *
	 * IDA signature:
	 * void __cdecl luaC_link(lua_State *L, GCObject *o, lu_byte tt);
	 *
	 * What it does:
	 * Pushes one fresh collectable onto the head of the main GC root list and
	 * stamps its tag, clearing the mark bits so the next sweep sees it white.
	 */
	void luaC_link(lua_State* const state, GCObject* const object, const int typeTag)
	{
		if (moho::lua_IncrementalGC && moho::lua_incremental::IsUiState(state->l_G)) {
			faf_lua51_gc_link(state, object, typeTag); // Lua 5.1.5 lgc.c: luaC_link()
			return;
		}
		global_State* const globalState = state->l_G;
		object->gch.next = globalState->rootgc;
		globalState->rootgc = object;
		object->gch.marked = 0;
		object->gch.tt = static_cast<lu_byte>(typeTag);
		sweep_boundaries::NoteLinked(globalState, sweep_boundaries::kListObjects, object); // engine addition: lua_ParallelSweep
	}

	/**
	 * Address: 0x00914E90 (FUN_00914E90, luaF_newCclosure)
	 *
	 * IDA signature:
	 * Closure *__cdecl luaF_newCclosure(lua_State *L, int nelems);
	 *
	 * What it does:
	 * Allocates a C closure sized for `nelems` upvalues, links it for
	 * collection, and records the upvalue count. The function pointer itself
	 * is filled in by the caller.
	 */
	Closure* luaF_newCclosure(lua_State* const state, const int nelems)
	{
		auto* const closure = static_cast<Closure*>(luaM_reallocblock(state, nullptr, {0u, 0u}, sizeCclosure(nelems)));

		luaC_link(state, reinterpret_cast<GCObject*>(closure), LUA_CFUNCTION);

		// The binary clears 0x18 through 0x40 - the tail of the reserved span
		// whose fields are not named yet, plus the one-before-first upvalue
		// lane - and deliberately leaves the dword at 0x14 as the allocator
		// returned it.
		constexpr std::size_t kUnclearedReservedPrefix = 4;
		std::memset(
			&closure->c.reservedTail[kUnclearedReservedPrefix],
			0,
			sizeof(closure->c.reservedTail) - kUnclearedReservedPrefix
		);
		closure->c.upvalue_m1[0].tt = LUA_TNIL;
		closure->c.upvalue_m1[0].value.p = nullptr;

		closure->c.nupvalues = static_cast<lu_byte>(nelems);
		return closure;
	}

	/**
	 * Address: 0x0092BAD0 (FUN_0092BAD0, luaZ_openspace)
	 *
	 * IDA signature:
	 * char *__cdecl luaZ_openspace(lua_State *L, Mbuffer *buff, size_t n);
	 *
	 * What it does:
	 * Grows the shared scratch buffer to at least `n` bytes, never below the
	 * 32-byte floor. The allocator flag lane is forced to 1 across the resize
	 * and restored afterwards, which is how this build tags scratch growth
	 * apart from ordinary VM allocation.
	 */
	char* luaZ_openspace(lua_State* const state, Mbuffer* const buff, const size_t n)
	{
		constexpr size_t kMinBuffer = 32u;

		if (n > buff->buffsize) {
			const size_t newSize = n < kMinBuffer ? kMinBuffer : n;

			const unsigned int savedAllocFlags = state->allocFlags;
			state->allocFlags = 1u;
			buff->buffer = luaM_reallocvector<char>(
				state, buff->buffer, static_cast<lu_mem>(buff->buffsize), static_cast<lu_mem>(newSize)
			);
			state->allocFlags = savedAllocFlags;

			buff->buffsize = newSize;
		}

		return buff->buffer;
	}

	/**
	 * Address: 0x00D47508 (luaT_eventname)
	 *
	 * What it does:
	 * Source text for the tag-method names `luaT_init` interns into
	 * `global_State::tmname`. Eighteen entries, read out of the shipped image;
	 * the array ends where unrelated data begins, and the count matches
	 * luaT_init's own loop bound (esi = 0x5C stepping 4 while below 0xA4).
	 */
	const char* luaT_eventname[]{
		"__index",    // 0
		"__newindex", // 1
		"__mode",     // 2
		"__eq",       // 3
		"__add",      // 4
		"__sub",      // 5
		"__mul",      // 6
		"__div",      // 7
		"__band",     // 8
		"__bor",      // 9
		"__bshl",     // 10
		"__bshr",     // 11
		"__pow",      // 12
		"__unm",      // 13
		"__lt",       // 14
		"__le",       // 15
		"__concat",   // 16
		"__call",     // 17
	};

	/**
	 * Address: 0x00D46010 (token2string)
	 *
	 * What it does:
	 * The reserved words, in token order. `luaX_init` interns these and stamps
	 * each one's `reserved` lane with its index + 1, which is how the lexer
	 * recognises a keyword by pointer identity instead of strcmp. Entry 22 in
	 * the image starts the non-reserved token names, so the reserved run is
	 * exactly the 22 below - matching luaX_init's "cmp ebx, 16h".
	 */
	const char* token2string[]{
		"and",   "break", "continue", "do",   "else", "elseif",
		"end",   "false", "for",      "function", "if", "in",
		"local", "nil",   "not",      "or",   "repeat", "return",
		"then",  "true",  "until",    "while",
	};

	/**
	 * Address: 0x009241A0 (FUN_009241A0, luaC_init)
	 *
	 * IDA signature:
	 * void __usercall luaC_init(lua_State *L@<edi>);
	 *
	 * What it does:
	 * Despite the luaC_ prefix this is not GC setup - it interns the twelve
	 * type names into `global_State::typenames` and pins each against
	 * collection. The loop walks g+0xA4 through g+0xD4 in four-byte steps,
	 * which is where that array lives.
	 */
	void luaC_init(lua_State* const state)
	{
		for (int typeTag = 0; typeTag < kLuaTypeTagCount; ++typeTag) {
			const char* const name = luaT_typenames[typeTag];
			TString* const interned = luaS_newlstr(state, name, std::strlen(name));
			state->l_G->typenames[typeTag] = interned;
			state->l_G->typenames[typeTag]->marked |= kLuaFixedStringMark;
		}
	}

	/**
	 * Address: 0x009283C0 (FUN_009283C0, luaT_init)
	 *
	 * IDA signature:
	 * void __cdecl luaT_init(lua_State *L);
	 *
	 * What it does:
	 * Interns the tag-method names into `global_State::tmname` and pins each
	 * against collection, so `luaT_gettm` can look a metamethod up by
	 * pre-interned key.
	 */
	void luaT_init(lua_State* const state)
	{
		for (int event = 0; event < kLuaTagMethodCount; ++event) {
			const char* const name = luaT_eventname[event];
			TString* const interned = luaS_newlstr(state, name, std::strlen(name));
			state->l_G->tmname[event] = interned;
			state->l_G->tmname[event]->marked |= kLuaFixedStringMark;
		}
	}

	/**
	 * Address: 0x009180D0 (FUN_009180D0, luaX_init)
	 *
	 * IDA signature:
	 * void __cdecl luaX_init(lua_State *L);
	 *
	 * What it does:
	 * Interns the reserved words, pins them, and stamps each with its token
	 * index + 1. The binary writes only the low byte of the `reserved` lane
	 * ("mov [eax+8], cl"); the indices are all under 256, so storing the whole
	 * field is equivalent for a freshly interned string.
	 */
	void luaX_init(lua_State* const state)
	{
		for (int token = 0; token < kLuaReservedWordCount; ++token) {
			const char* const word = token2string[token];
			TString* const interned = luaS_newlstr(state, word, std::strlen(word));
			interned->marked |= kLuaFixedStringMark;
			interned->reserved = token + 1;
		}
	}

	/**
	 * Address: 0x009247A0 (FUN_009247A0, luaS_freeall)
	 *
	 * IDA signature:
	 * void __cdecl luaS_freeall(lua_State *L);
	 *
	 * What it does:
	 * Releases the string table's bucket array. The strings themselves are
	 * already gone by this point - close_state sweeps before calling here.
	 */
	void luaS_freeall(lua_State* const state)
	{
		global_State* const globalState = state->l_G;
		luaM_freearray<GCObject*>(state, globalState->strt.hash, static_cast<lu_mem>(globalState->strt.size));
	}

	/**
	 * Address: 0x00915BA0 (FUN_00915BA0, luaC_sweep)
	 *
	 * IDA signature:
	 * int __cdecl luaC_sweep(lua_State *L, int all);
	 *
	 * What it does:
	 * Sweeps the four collectable lanes in the order userdata, strings,
	 * secondary root list, main root list. `all` selects the mark limit: 0
	 * keeps anything reachable, 0x100 is above every real mark bit and so
	 * collects everything, which is what close_state passes.
	 */
	int luaC_sweep(lua_State* const state, const int all)
	{
		constexpr int kSweepEverythingLimit = 0x100;

		const int limit = all != 0 ? kSweepEverythingLimit : 0;

		sweep_boundaries::Forget(state->l_G); // engine addition: this frees lua_ParallelSweep boundaries
		(void)sweeplist(&state->l_G->rootudata, nullptr, state, limit);
		sweepstrings(state, limit);
		(void)sweeplist(&state->l_G->rootgc1, nullptr, state, limit);
		return sweeplist(&state->l_G->rootgc, nullptr, state, limit);
	}

	/**
	 * Address: 0x00914FC0 (FUN_00914FC0, luaF_close)
	 *
	 * IDA signature:
	 * void __cdecl luaF_close(lua_State *L, StkId level);
	 *
	 * What it does:
	 * Closes every open upvalue at or above `level`: the referenced stack slot
	 * is copied into the upvalue's own storage, the pointer is retargeted at
	 * that copy, and the object moves off the thread's open list onto the GC
	 * list. Open upvalues are ordered by descending stack slot, so the walk
	 * stops at the first one below `level`.
	 */
	void luaF_close(lua_State* const state, const StkId level)
	{
		for (GCObject* upvalObject = state->openupval; upvalObject != nullptr;
			 upvalObject = state->openupval) {
			UpVal* const upval = &upvalObject->uv;
			if (upval->v < level) {
				return;
			}

			if (moho::lua_IncrementalGC && moho::lua_incremental::IsUiState(state->l_G)) {
				upval->value = *upval->v;
				upval->v = &upval->value;
				state->openupval = upvalObject->gch.next;
				faf_lua51_gc_link_upval(state, upval);
				continue;
			}

			upval->value = *upval->v;
			upval->v = &upval->value;
			state->openupval = upvalObject->gch.next;
			luaC_link(state, upvalObject, LUA_TUPVALUE);
		}
	}

	/**
	 * Address: 0x00924470 (FUN_00924470, f_luaopen)
	 *
	 * IDA signature:
	 * void __usercall f_luaopen(lua_State *L@<eax>);
	 *
	 * What it does:
	 * Builds the shared global_State for a brand-new thread. The chicken-and-
	 * egg problem - the allocator lives in the global_State being allocated -
	 * is solved with a throwaway lua_State/global_State pair on the stack
	 * carrying just the allocator hooks, which is what the real object is
	 * allocated through. After that it seeds the string table, the registry
	 * (whose metatable is itself), a default metatable per type tag, the
	 * thread's globals table, the interned name tables, and the scratch
	 * buffer.
	 */
	void f_luaopen(lua_State* const state)
	{
		// The binary leaves this bootstrap pair uninitialised apart from the
		// five fields below, so luaM_realloc reads whatever the stack held for
		// allocFlags. Value-initialising is the one deliberate deviation here:
		// reading indeterminate storage is undefined behaviour in C++, and
		// zero is the flag value every other caller uses (luaZ_openspace saves
		// and restores it precisely because 1 is the exception).
		lua_State bootstrapState{};
		global_State bootstrapGlobals{};
		bootstrapState.l_G = &bootstrapGlobals;
		bootstrapGlobals.reallocFunc = luaHelper_Realloc;
		bootstrapGlobals.freeFunc = luaHelper_Free;
		bootstrapGlobals.memData = luaHelper_memData;
		bootstrapGlobals.nblocks = kLuaX86Size<lua_State> + kLuaX86Size<global_State>;

		auto* const globalState = luaM_new<global_State>(&bootstrapState);
		if (globalState == nullptr) {
			throw lua_MemError(lua::lua_Error(state, LUA_ERRMEM, "out of memory"));
		}

		state->l_G = globalState;
		// x64 port test mode (plan 4.1a), not in the binary: FAF_LUAGC_LOG.
		lua::GcEventLogRegisterState(globalState);

		globalState->strt.hash = nullptr;
		globalState->strt.nuse = 0;
		globalState->strt.size = 0;
		globalState->rootgc = nullptr;
		globalState->rootgc1 = nullptr;
		globalState->rootudata = nullptr;
		globalState->tmudata = nullptr;
		globalState->buff.buffer = nullptr;
		globalState->buff.buffsize = 0u;
		globalState->GCthreshold = 0u;
		globalState->gcTraversalLockDepth = 0;
		globalState->nblocks = kLuaX86Size<lua_State> + kLuaX86Size<global_State>;
		globalState->_defaultmeta.tt = LUA_TNIL;
		globalState->_registry.tt = LUA_TNIL;
		globalState->mainthread = state;
		globalState->lstate = state;
		globalState->dummynode[0].SetKeyTag(LUA_TNIL);
		globalState->dummynode[0].i_val.tt = LUA_TNIL;
		globalState->dummynode[0].SetNext(nullptr);
		globalState->fatalErrorFunc = &defaultFatalErrorFunc;
		globalState->memData = luaHelper_memData;
		globalState->reallocFunc = luaHelper_Realloc;
		globalState->freeFunc = luaHelper_Free;
		globalState->globalUserData = nullptr;
		globalState->userGCFunction = nullptr;
		globalState->allocationTrackingEnabled = 0;
		globalState->hookmask = 0;
		globalState->allowhook = 1;
		globalState->basehookcount = 0;
		globalState->hookcount = 0;
		globalState->hook = nullptr;

		lua_stack_init(state, state);

		for (TObject& slot : globalState->_defaultmetatypes) {
			slot.value.p = nullptr;
		}

		// The slot starts life as the number 0 before being replaced by its
		// table - the binary really does write LUA_TNUMBER here first.
		globalState->_defaultmeta.tt = LUA_TNUMBER;
		globalState->_defaultmeta.value.p = nullptr;

		// The shared default metatable is its own metatable, which is what
		// terminates metatable chains for values that have none of their own.
		Table* const defaultMeta = luaH_new(state, 0, 0);
		globalState->_defaultmeta.tt = static_cast<int>(defaultMeta->tt);
		globalState->_defaultmeta.value.p = defaultMeta;
		static_cast<Table*>(globalState->_defaultmeta.value.p)->metatable =
			static_cast<Table*>(globalState->_defaultmeta.value.p);

		for (TObject& slot : globalState->_defaultmetatypes) {
			Table* const typeMeta = luaH_new(state, 0, 0);
			slot.tt = static_cast<int>(typeMeta->tt);
			slot.value.p = typeMeta;
			static_cast<Table*>(slot.value.p)->metatable =
				static_cast<Table*>(globalState->_defaultmeta.value.p);
		}

		Table* const globals = luaH_new(state, 0, 4);
		state->_gt.tt = static_cast<int>(globals->tt);
		state->_gt.value.p = globals;

		Table* const registry = luaH_new(state, 4, 4);
		globalState->_registry.value.p = registry;
		globalState->_registry.tt = static_cast<int>(registry->tt);
		globalState->minimumstrings = lua_minimumnumstrings;

		luaS_resize(state, kLuaInitialStringTableSize);
		luaC_init(state);
		luaT_init(state);
		luaX_init(state);

		TString* const outOfMemory = luaS_newlstr(state, "not enough memory", 17u);
		outOfMemory->marked |= kLuaFixedStringMark;

		globalState->GCthreshold = 4u * globalState->nblocks;
		(void)luaZ_openspace(state, &globalState->buff, static_cast<size_t>(lua_minimumauxspace));
	}

	/**
	 * Address: 0x009246D0 (FUN_009246D0, lua_open)
	 * Mangled: ?lua_open@@YAPAUlua_State@@XZ
	 *
	 * IDA signature:
	 * lua_State *__cdecl lua_open(void);
	 *
	 * What it does:
	 * Allocates the main thread through the same throwaway allocator state
	 * f_luaopen uses, blanks it, and hands it to f_luaopen to acquire the
	 * shared global_State. If that throws part-way the half-built state is
	 * closed before the exception continues out - the binary expresses this
	 * with an SEH frame around the f_luaopen call.
	 */
	lua_State* lua_open(void)
	{
		lua_State bootstrapState{};
		global_State bootstrapGlobals{};
		bootstrapState.l_G = &bootstrapGlobals;
		bootstrapGlobals.reallocFunc = luaHelper_Realloc;
		bootstrapGlobals.freeFunc = luaHelper_Free;
		bootstrapGlobals.memData = luaHelper_memData;
		bootstrapGlobals.nblocks = kLuaX86Size<lua_State> + kLuaX86Size<global_State>;

		auto* const state = luaM_new<lua_State>(&bootstrapState);
		if (state == nullptr) {
			return nullptr;
		}

		state->next = nullptr;
		state->tt = LUA_TTHREAD;
		state->marked = 0;
		state->l_G = nullptr;
		state->ci = nullptr;
		state->stack = nullptr;
		state->stacksize = 0;
		state->base_ci = nullptr;
		state->size_ci = 0;
		state->nCcalls = 0;
		state->_gt.tt = LUA_TNIL;
		state->openupval = nullptr;
		state->gclist = nullptr;
		state->stateUserData = nullptr;
		// Not written by the binary, which leaves the freshly allocated bytes
		// in place and lets luaM_realloc read them. Zeroed here for the same
		// reason as the bootstrap pair above: the allocator hook ignores the
		// flag lane, so the observable behaviour is identical without the
		// indeterminate read.
		state->allocFlags = 0u;

		try {
			f_luaopen(state);
		} catch (...) {
			close_state(state);
			throw;
		}

		// Crash-report registry (deviation, documented): every live VM is
		// registered so the crash handler can dump its frames. See
		// LuaCrashDump.cpp; the registry is append-only and never touched on
		// any hot path.
		lua::RegisterLuaVm(state);

		return state;
	}

	/**
	 * Address: 0x009243E0 (FUN_009243E0, lua_close)
	 *
	 * IDA signature:
	 * void __cdecl lua_close(lua_State *L);
	 *
	 * What it does:
	 * Tears the whole VM down through its main thread: open upvalues are closed,
	 * every userdata still owing a finaliser is moved onto `tmudata`, and those
	 * finalisers then run on a stack rewound to the base frame. A finaliser that
	 * throws only costs itself - `luaC_callGCTM` unlinks each userdata before
	 * calling it - so the rewind-and-run is simply repeated until one pass gets
	 * through. That retry is how the binary spells stock Lua's
	 * `do { ... } while (luaD_rawrunprotected(L, callallgcTM, NULL) != 0)`: the
	 * fork raises C++ exceptions, so the loop is an EH region whose handler at
	 * 0x00924463 reloads the main thread and jumps back to the rewind at
	 * 0x00924420. `close_state` then releases the arrays and both state objects.
	 *
	 * Recovered because the prebuilt LuaPlus copy reads this state at stock
	 * offsets and so walked garbage from its very first line:
	 * `global_State::mainthread` is at +0x40 here, and `rootudata`/`tmudata` sit
	 * at +0x14/+0x18 rather than the stock +0x10/+0x14 because the fork carries
	 * a second GC lane.
	 */
	void lua_close(lua_State* const state)
	{
		faf_lua51_gc_release(state->l_G); // drop any incremental state before 5.0 teardown
		lua_State* const mainThread = state->l_G->mainthread;

		luaF_close(mainThread, mainThread->stack);
		(void)luaC_separateudata(mainThread);

		for (bool finalisersFinished = false; !finalisersFinished;) {
			mainThread->ci = mainThread->base_ci;
			mainThread->top = mainThread->base_ci->base;
			mainThread->base = mainThread->top;
			mainThread->nCcalls = 0u;

			try {
				luaC_callGCTM(mainThread);
				finalisersFinished = true;
			} catch (...) {
				// Whatever threw is already off `tmudata`; rewind and run the
				// rest, which is all the binary's catch funclet does.
			}
		}

		close_state(mainThread);
	}
}
#pragma warning(pop)

void moho::LUA_SetCallGate(const LuaCallGate gate) noexcept
{
	const LuaCallGate previous = tLuaCallGate;
	tLuaCallGate = gate;
	if (previous == nullptr && gate != nullptr) {
		sLuaCallGateCount.fetch_add(1, std::memory_order_relaxed);
	} else if (previous != nullptr && gate == nullptr) {
		sLuaCallGateCount.fetch_sub(1, std::memory_order_relaxed);
	}
}

bool moho::LUA_IsLibraryCFunction(const LuaCFunctionPtr function) noexcept
{
	static const std::vector<LuaCFunctionPtr> sLibraryFunctions = [] {
		std::vector<LuaCFunctionPtr> functions;
		for (const luaL_reg* const library :
		     {base_funcs, co_funcs, kLuaStringLibrary, kLuaTableLibrary, kFafTableLibraryExtensions, kLuaMathLib}) {
			for (const luaL_reg* entry = library; entry->name != nullptr; ++entry) {
				functions.push_back(entry->func);
			}
		}
		std::sort(functions.begin(), functions.end(), std::less<>{});
		return functions;
	}();
	return std::binary_search(sLibraryFunctions.begin(), sLibraryFunctions.end(), function, std::less<>{});
}

extern "C"
{
	int _errorfb(lua_State* L, int level);
}

/**
 * Address: 0x009134B0 (FUN_009134B0, _errorfb)
 *
 * What it does:
 * Walks the active Lua call stack starting at `level`, pushing one
 * `"stack traceback:"` header followed by a `\n\t<chunk>(<line>): in
 * function <name>` line for each frame. Compresses the middle of very deep
 * stacks with a single ellipsis (`LEVELS1=12`, `LEVELS2=10`). Concatenates
 * the result into one string at top-of-stack and returns 1. Recovered as a
 * free function here because callers (e.g. `errorfb`, `lua_traceback`) live
 * in our recovered LuaObject.cpp.
 */
extern "C" int _errorfb(lua_State* const state, int level)
{
	constexpr int kLevels1 = 12;
	constexpr int kLevels2 = 10;
	int firstpart = 1;
	lua_Debug ar;
	int base = 0; // what stays below the message: only the text gets joined

	if (lua_gettop(state) == 0) {
		lua_pushlstring(state, "", 0);
	} else if (!lua_isstring(state, -1)) {
		return 1;
	} else {
		base = lua_gettop(state) - 1;
		lua_pushlstring(state, "\n", 1);
	}

	lua_pushlstring(state, "stack traceback:", 16);
	while (lua_getstack(state, level++, &ar)) {
		if (level > kLevels1 && firstpart) {
			if (!lua_getstack(state, level + kLevels2, &ar)) {
				--level;
			} else {
				lua_pushlstring(state, "\n\t...", 5);
				while (lua_getstack(state, level + kLevels2, &ar)) {
					++level;
				}
			}
			firstpart = 0;
			continue;
		}

		lua_pushlstring(state, "\n\t", 2);
		lua_getinfo(state, "Snl", &ar);
		lua_pushstring(state, ar.short_src);
		if (ar.currentline > 0) {
			lua_pushfstring(state, "(%d)", ar.currentline);
		}
		lua_pushlstring(state, ":", 1);

		switch (*ar.namewhat) {
			case 'g':
			case 'l':
			case 'f':
			case 'm':
				lua_pushfstring(state, " in function `%s'", ar.name);
				break;
			default:
				if (*ar.what == 'm') {
					lua_pushfstring(state, " in main chunk");
				} else if (*ar.what == 'C' || *ar.what == 't') {
					lua_pushlstring(state, " ?", 2);
				} else {
					lua_pushfstring(state, " in function <%s:%d>", ar.short_src, ar.linedefined);
				}
		}

		lua_concat(state, lua_gettop(state) - base);
	}

	lua_concat(state, lua_gettop(state) - base);
	return 1;
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
 * Address: 0x00923690 (FUN_00923690, luaopen_serialize)
 *
 * What it does:
 * Opens the LuaPlus `serialize` library table with the two functions the
 * binary registers through `serializelib` at 0x00D47068. Table contents read
 * out of the shipped image:
 *   0x00D47068 -> "tostring"   / 0x00D4706C -> 0x00923AC0 LuaSerializeToString
 *   0x00D47070 -> "fromstring" / 0x00D47074 -> 0x00923D20 LuaSerializeFromString
 *   0x00D47078 -> { nullptr, nullptr } sentinel
 * Both bodies live in `gpg/core/containers/ArchiveSerialization.cpp`; naming
 * them here is what keeps them in the link, and what makes runtime
 * `serialize.tostring` / `serialize.fromstring` resolve instead of returning
 * nil.
 */
extern "C" int luaopen_serialize(lua_State* const state)
{
	static const luaL_reg kSerializeLibrary[] = {
		{"tostring", &LuaSerializeToString},
		{"fromstring", &LuaSerializeFromString},
		{nullptr, nullptr}
	};
	luaL_openlib(state, "serialize", kSerializeLibrary, 0);
	return 1;
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
		MOHO_ASSERT_NOT_SIM_WORKER("LuaObject used-object list");
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
		MOHO_ASSERT_NOT_SIM_WORKER("LuaObject used-object list");
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
 * Address: 0x005790D0 (FUN_005790D0, LuaObject::j_Dtr_3 thunk)
 * Address: 0x005791A0 (FUN_005791A0, LuaObject::j_Dtr_4 thunk)
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
		MOHO_ASSERT_NOT_SIM_WORKER("LuaObject used-object list");
		*m_prev = m_next;
		m_next->m_prev = m_prev;
		m_object.tt = LUA_TNIL;
	}
}

/**
  * Alias of FUN_005790D0 (non-canonical helper lane).
 *
 * What it does:
 * Forwards one import-thunk lane to `LuaObject::~LuaObject`.
 */
void LuaObjectDtrThunk3(LuaObject* const object)
{
	object->~LuaObject();
}

/**
  * Alias of FUN_005791A0 (non-canonical helper lane).
 *
 * What it does:
 * Forwards one non-deleting thunk lane to `LuaObject::~LuaObject`.
 */
void LuaObjectDtrThunk4(LuaObject* const object)
{
	object->~LuaObject();
}

/**
  * Alias of FUN_005D0A90 (non-canonical helper lane).
 *
 * What it does:
 * Forwards one non-deleting thunk lane to `LuaObject::~LuaObject`.
 */
void LuaObjectDtrThunk6(LuaObject* const object)
{
	object->~LuaObject();
}

/**
  * Alias of FUN_00624120 (non-canonical helper lane).
 *
 * What it does:
 * Forwards one non-deleting thunk lane to `LuaObject::~LuaObject`.
 */
void LuaObjectDtrThunk7(LuaObject* const object)
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
	: LuaState(initStandardLibrary, static_cast<int>(moho::lua_incremental::ELuaVmRole::Baseline))
{
}

LuaState::LuaState(const StandardLibraries initStandardLibrary, const int collectorRole)
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

	if (collectorRole != static_cast<int>(moho::lua_incremental::ELuaVmRole::Baseline)) {
		faf_lua51_gc_register_vm(m_state, collectorRole);
	}

	m_headObject.m_next = reinterpret_cast<LuaObject*>(&m_tailObject);
	m_tailObject.m_prev = reinterpret_cast<LuaObject**>(&m_headObject.m_next);
	m_headObject.m_prev = nullptr;
	m_tailObject.m_next = nullptr;
	m_luaTask = nullptr;

	Init(initStandardLibrary);
}
