// Part of LuaObject.cpp, included there: the base library and coroutines (lbaselib).

	/**
	 * Address: 0x0090F240 (FUN_0090F240, luaB_collectgarbage)
	 *
	 * What it does:
	 * Optionally sets GC threshold from arg-1 and returns no values.
	 */
	int luaB_collectgarbage(lua_State* const state)
	{
		const lua_Number threshold = luaL_optnumber(state, 1, 0.0f);
		lua_setgcthreshold(state, static_cast<int>(threshold));
		// Engine addition (lua_IncrementalGC, #278): a frame-driven UI state skips the collection
		// lua_setgcthreshold asks for, so a script's own request runs the incremental collector's full
		// cycle, as the binary's collection does when the heap has reached the threshold.
		global_State* const globalState = state->l_G;
		if (moho::lua_IncrementalGC && moho::lua_incremental::IsUiState(globalState) &&
		    globalState->nblocks >= globalState->GCthreshold) {
			faf_lua51_gc_full(state);
		}
		return 0;
	}

	/**
	 * Address: 0x0090F270 (FUN_0090F270, luaB_type)
	 *
	 * What it does:
	 * Replaces arg-1 with the interned type-name string lane from
	 * `global_State::typenames` and returns it.
	 */
	int luaB_type(lua_State* const state)
	{
		luaL_checkany(state, 1);

		TObject* const top = state->top;
		const int valueTypeTag = (top - 1)->tt;
		TString* const typeName = state->l_G->typenames[valueTypeTag];
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
	int luaB_next(lua_State* const state)
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
	int luaB_pairs(lua_State* const state)
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
	int luaB_ipairs(lua_State* const state)
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
	int luaB_loadstring(lua_State* const state)
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
	int luaB_loadfile(lua_State* const state)
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
	int luaB_dofile(lua_State* const state)
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
	 * Engine addition: loads `path` from the mounted file system, as `doscript`
	 * and `import` find scripts, and pushes the chunk or the error message.
	 * Returns `lua_load`'s status.
	 */
	int LoadMountedFile(lua_State* const state, const char* const path)
	{
		fa::string diskPath{};
		moho::FILE_EnsureWaitHandleSet();
		moho::FWaitHandleSet* const files = moho::FILE_GetWaitHandleSet();
		if (files != nullptr && files->mHandle != nullptr) {
			(void)files->mHandle->FindFile(&diskPath, path, nullptr);
		}
		if (diskPath.empty()) {
			lua_pushfstring(state, "cannot find %s in the game's files", path);
			return LUA_ERRFILE;
		}

		const gpg::MemBuffer<const char> contents = moho::DISK_MemoryMapFile(diskPath.c_str());
		if (contents.mBegin == nullptr) {
			lua_pushfstring(state, "cannot read %s", path);
			return LUA_ERRFILE;
		}
		const fa::string chunkName = gpg::STR_Printf("@%s", path);
		return ::luaL_loadbuffer(
			state, contents.mBegin, static_cast<size_t>(contents.mEnd - contents.mBegin), chunkName.c_str()
		);
	}

	/**
	 * Engine addition: `loadfile` in states opened without `io` - every game
	 * state (sim, user interface, blueprints, session). Stock `loadfile` hands
	 * the path to fopen, so a lobby's map or mod could read any file on a
	 * joiner's disk; this one looks only in the game's mounted files.
	 */
	int luaB_loadfile_mounted(lua_State* const state)
	{
		const char* const fileName = luaL_checklstring(state, 1, nullptr);
		if (LoadMountedFile(state, fileName) == 0) {
			return 1;
		}

		lua_pushnil(state);
		lua_insert(state, -2);
		return 2;
	}

	/** Engine addition: `dofile` beside `luaB_loadfile_mounted`. */
	int luaB_dofile_mounted(lua_State* const state)
	{
		const char* const fileName = luaL_checklstring(state, 1, nullptr);
		const int baseTop = lua_gettop(state);
		if (LoadMountedFile(state, fileName) != 0) {
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
	int luaB_unpack(lua_State* const state)
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
	int luaB_pcall(lua_State* const state)
	{
		luaL_checkany(state, 1);
		const int status = LuaCallProtected(state, lua_gettop(state) - 1, LUA_MULTRET);
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
	void pushcomposename(lua_State* const state)
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
	int luaB_cocreate(lua_State* const state)
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
	int luaB_yield(lua_State* const state)
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
	StkId callrethooks(StkId firstResult, lua_State* const state)
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
	int resume_error(lua_State* const state, const char* const message)
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
	 * A `CallInfo::state` of 4 marks a frame that yielded; 2 marks one that is
	 * still inside a C function. Only those two can be resumed.
	 */
	constexpr int kCallInfoStateYielded = 4;
	constexpr int kCallInfoStateInC = 2;

	/**
	 * The threshold `lua_yield` tests: a frame at 3 or above is running Lua code
	 * and yields for real, anything below has not started and is only marked as
	 * being in C.
	 */
	constexpr int kCallInfoStateRunningLuaFrame = 3;

	/** Argument C of an instruction: bits 6..14. */
	[[nodiscard]] constexpr int GetInstructionArgC(const Instruction instruction)
	{
		return static_cast<int>((instruction >> 6) & 0x1FFu);
	}

	/**
	 * Address: 0x00914580 (FUN_00914580, resume)
	 *
	 * IDA signature:
	 * void __usercall resume(int *ud@<eax>, lua_State *L@<edi>);
	 *
	 * What it does:
	 * The body `lua_resume` runs inside its protected region. Either starts the
	 * coroutine's function, or picks the suspended frame back up - a frame that
	 * yielded finishes the call that yielded first, using the result count of
	 * the instruction that issued it - and then runs the interpreter.
	 */
	void resume(lua_State* const state, const int nargs)
	{
		CallInfo* const ci = state->ci;

		if (ci == state->base_ci) {
			// First resume: start the coroutine body itself.
			luaD_precall(state, state->top - (nargs + 1));
		} else if (ci->state == kCallInfoStateYielded) {
			// Finish the call that yielded. Its result count comes from argument
			// C of the CALL instruction that issued it, which sits one word
			// behind the saved program counter of the caller's frame.
			const int nresults = GetInstructionArgC(ci[-1].savedpc[-1]) - 1;
			ci[-1].state = 0;

			luaD_poscall(state, nresults, state->top - nargs);
			if (nresults >= 0) {
				state->top = state->ci->top;
			}
		} else {
			ci->state = 0;
		}

		StkId const firstResult = luaV_execute(state);
		if (firstResult != nullptr) {
			luaD_poscall(state, -1, firstResult);
		}
	}

	/**
	 * Unwinds a coroutine back to its base frame after `resume` threw, leaving
	 * the error text as the single value on its stack.
	 */
	void RestoreCoroutineAfterError(
		lua_State* const state, const char* const errorText, const lu_byte savedAllowHook
	)
	{
		state->ci = state->base_ci;
		state->base = state->ci->base;
		state->nCcalls = 0;

		luaF_close(state, state->base);
		(void)PushLuaStringAtStackSlot(state, state->base, errorText);

		state->l_G->allowhook = savedAllowHook;
		(void)luaD_refreshstacklimit(state);
	}

	/**
	 * Address: 0x00913E40 (FUN_00913E40, lua_yield)
	 *
	 * IDA signature:
	 * int __cdecl lua_yield(lua_State *L, int nresults);
	 *
	 * What it does:
	 * Suspends the running coroutine. A frame that has not started executing Lua
	 * yet (`state < 3`) is only marked as sitting in C; a live Lua frame first
	 * refuses to yield across a C function, then slides its `nresults` return
	 * values down to the frame base, trims the stack to them, and marks itself
	 * yielded. Always returns -1, which `luaD_precall` reads as "this frame did
	 * not produce results here".
	 *
	 * The two state values are the whole point, and the binary spells them out:
	 *
	 *   0x00913EF0: mov dword ptr [edi+8], 2   ; state < 3  -> in-C
	 *   0x00913EE2: mov dword ptr [edi+8], 4   ; otherwise  -> yielded
	 *
	 * which are exactly the two values `lua_resume` accepts. Until this was
	 * recovered the call resolved to the prebuilt LuaPlus library instead, and
	 * that build writes stock Lua 5.0 `CI_*` bitmask flags into the same field.
	 * Our `lua_resume` then compared them against this fork's enum, found
	 * neither 4 nor 2, and rejected every resume with "cannot resume
	 * non-suspended coroutine" - which killed the script driving the intro
	 * movies.
	 */
	extern "C" int lua_yield(lua_State* const state, const int nresults)
	{
		CallInfo* const ci = state->ci;

		if (state->nCcalls != 0) {
			luaG_runerror(state, "attempt to yield across metamethod/C-call boundary");
		}

		if (ci->state < kCallInfoStateRunningLuaFrame) {
			ci->state = kCallInfoStateInC;
			return -1;
		}

		if (ci[-1].state != 0) {
			luaG_runerror(state, "cannot yield a C function");
		}

		// Only move anything when the results are not already sitting at the
		// frame base; the binary guards the whole block on this comparison.
		if (&state->top[-nresults] > state->base) {
			for (int i = 0; i < nresults; ++i) {
				state->base[i] = state->top[i - nresults];
			}
			state->top = &state->base[nresults];
		}

		ci->state = kCallInfoStateYielded;
		return -1;
	}

	/**
	 * Address: 0x00914610 (FUN_00914610, lua_resume)
	 *
	 * IDA signature:
	 * int __cdecl lua_resume(lua_State *L, int nargs);
	 *
	 * What it does:
	 * Resumes a coroutine: rejects one that is dead or not suspended, then runs
	 * `resume` protected. On the way out of an error it rewinds to the base
	 * frame, closes pending upvalues, replaces the stack with the error text
	 * and restores the hook flag, returning the raised lua::lua_Error's own
	 * code (or LUA_ERRRUN for anything else that escapes).
	 *
	 * Like lua_call this fork protects with a C++ try rather than a setjmp, so
	 * the two handlers at 0x009146BF and 0x00914728 are the EH funclets the
	 * decompiler elides - `luaD_rawrunprotected` does not exist here.
	 *
	 * Recovering this matters beyond fidelity: while it resolved to the
	 * prebuilt LuaPlus library, resume walked our coroutine at stock Lua
	 * offsets and wrote 12-byte TObjects onto an 8-byte stack, so every script
	 * error came back as a garbage value - "<non-string lua error>".
	 */
	extern "C" int lua_resume(lua_State* const state, const int nargs)
	{
		CallInfo* const ci = state->ci;

		if (ci == state->base_ci) {
			if (nargs >= state->top - state->base) {
				return resume_error(state, "cannot resume dead coroutine");
			}
		} else if (ci->state != kCallInfoStateYielded && ci->state != kCallInfoStateInC) {
			return resume_error(state, "cannot resume non-suspended coroutine");
		}

		const lu_byte savedAllowHook = state->l_G->allowhook;

		try {
			resume(state, nargs);
		} catch (const lua::lua_Error& error) {
			RestoreCoroutineAfterError(state, error.what(), savedAllowHook);
			return error.code;
		} catch (const std::exception& error) {
			RestoreCoroutineAfterError(state, error.what(), savedAllowHook);
			return LUA_ERRRUN;
		}

		return 0;
	}

	/**
	 * Engine addition, not in the binary: a coroutine gets its LuaState wrapper on its first
	 * resume. The binary leaves `stateUserData` null on a coroutine, so an engine function
	 * called inside one crashes on that null. A coroutine loaded from a save has no wrapper
	 * either and gets it here too. The thread object is reset at once because LuaPlus treats
	 * every bound LuaObject as a GC root, and `luaE_freethread` deletes the wrapper. Nothing here
	 * allocates from Lua, so the collector runs when it does in retail.
	 */
	void BindCoroutineState(lua_State* const coroutineState)
	{
		if (coroutineState->stateUserData != nullptr || coroutineState->l_G->mainthread->stateUserData == nullptr) {
			return;
		}

		auto* const wrapper = new LuaPlus::LuaState(LuaPlus::LuaState::UNBOUND);
		wrapper->SetState(coroutineState);
		wrapper->m_threadObj.Reset();
	}

	/**
	 * Address: 0x0090FA00 (FUN_0090FA00, auxresume)
	 *
	 * What it does:
	 * Moves resume arguments into target coroutine, executes one resume, then
	 * moves either one error object or all yielded/returned values back.
	 */
	int auxresume(const int argumentCount, lua_State* const callerState, lua_State* const coroutineState)
	{
		BindCoroutineState(coroutineState); // engine addition
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
	int luaB_coresume(lua_State* const state)
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
	int luaB_auxwrap(lua_State* const state)
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
	int luaB_cowrap(lua_State* const state)
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
	int luaB_assert(lua_State* const state)
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
	int luaB_setmetatable(lua_State* const state)
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
	int luaB_newproxy(lua_State* const state)
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
	int LS_LOG(lua_State* const state)
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

		fa::string message{};
		message.assign_owned(messageBuilder.str());
		gpg::LogMessage(gpg::LogSeverity::Info, message);
		return 0;
	}

	/**
	 * Address: 0x0090AF80 (FUN_0090AF80, LS_import)
	 *
	 * What it does:
	 * Implements legacy `import` fallback for this runtime lane by returning
	 * false on the Lua stack.
	 */
	int LS_import(lua_State* const state)
	{
		Ensure(state != nullptr, "state");
		Ensure(state->stateUserData != nullptr, "state->stateUserData");

		lua_State* const cstate = state->stateUserData->m_state;
		lua_pushboolean(cstate, 0);
		(void)lua_gettop(cstate);
		return 1;
	}

	/**
	 * Address: 0x0090B0D0 (FUN_0090B0D0, ScriptFunctionsRegister)
	 *
	 * What it does:
	 * Registers the script-global `import` fallback on the active Lua globals
	 * table.
	 *
	 * The binary also registers `LuaDumpBinary` here (`LS_dump`, 0x0090AFB0):
	 * compile any file on disk and write the chunk to any path, with raw
	 * fopen. Every state got it, including the blueprint state that runs
	 * host-chosen mods' .bp files before FAF's globalInit.lua (which sets it to
	 * nil) could, so a lobby's mod could write files anywhere on every
	 * joiner's disk. The engine leaves it out; nothing in FAF calls it.
	 */
	void ScriptFunctionsRegister(LuaState* const state)
	{
		Ensure(state != nullptr, "state");
		LuaObject globals = state->GetGlobals();
		globals.Register("import", LS_import, 0);
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

	/**
	 * One prepared call to a Lua function - LuaPlus's own `LuaCall`, whose
	 * declaration in LuaObject.h is these four members in this order:
	 *
	 *     LuaState* m_state;  LuaObject m_functionObj;
	 *     int m_numArgs;      int m_startResults;
	 *
	 * and whose constructor is the same sequence the body below recovers:
	 * copy the callable, zero the argument count, resolve the state from the
	 * object, check it really is a function, record GetTop() + 1, push it.
	 *
	 * This fork's version is the stock one minus the _ALERT handler: LuaPlus
	 * pushes _ALERT in the constructor and calls through PCall with it as the
	 * error handler, where 0x00909A00 pushes nothing extra and 0x00907270
	 * calls plain lua_call. Nothing here should be back-filled from the
	 * vendored .inl on the strength of the layout matching.
	 */
	struct LuaCall
	{
		LuaState* m_state = nullptr;  // +0x00 thread the call is staged on
		LuaObject m_functionObj{};    // +0x04 the callable, tracked on the live list
		int m_numArgs = 0;            // +0x18 arguments pushed so far
		int m_startResults = 0;       // +0x1C stack index the first result lands at
	};
	static_assert(offsetof(LuaCall, m_state) == 0x00, "LuaCall::m_state offset must be 0x00");
	static_assert(offsetof(LuaCall, m_functionObj) == 0x04, "LuaCall::m_functionObj offset must be 0x04");
	static_assert(offsetof(LuaCall, m_numArgs) == 0x18, "LuaCall::m_numArgs offset must be 0x18");
	static_assert(offsetof(LuaCall, m_startResults) == 0x1C, "LuaCall::m_startResults offset must be 0x1C");
	static_assert(sizeof(LuaCall) == 0x20, "LuaCall size must be 0x20");

	/**
	 * Address: 0x00909A00 (FUN_00909A00)
	 *
	 * IDA signature:
	 * int __thiscall sub_909A00(LuaCall *this@<ecx>, const LuaObject *functionObject);
	 *
	 * What it does:
	 * Constructs one Lua call-frame view from a caller-supplied function
	 * `LuaObject`: default-initializes the embedded function lane, links it
	 * onto the source object's root-state live-object intrusive list with the
	 * same tagged value via `AddToUsedObjectList`, captures the CURRENTLY
	 * RUNNING thread's `LuaPlus::LuaState*` wrapper into `state`, asserts the
	 * function slot is bound (`m_state` non-null), raises a Lua type error
	 * when the payload is not callable (`tt | 1 != 7` ⇒ not `LUA_TFUNCTION`),
	 * and records that thread's current stack top `+ 1` as `nextTopIndex`
	 * while pushing the function onto that stack as the first call-frame slot.
	 *
	 * The frame's thread is `l_G->lstate` (+0x44), not `l_G->mainthread`
	 * (+0x40): the binary reads `[[[m_state]+0x10]+0x44]+0x44` at both the
	 * `state` capture and the `luaG_typeerror` call. The two coincide only
	 * while the main thread is the one running. Every UI/sim callback that
	 * runs inside a coroutine (`ForkThread`) has `lstate != mainthread`, and
	 * building the frame on the main thread there pushes the callable and its
	 * arguments onto a stack `lua_call` is not run against, so the call
	 * silently does nothing -- which is how `LuaObject::Insert` stopped
	 * filling the table `EntityCategoryGetUnitList` returns.
	 */
	LuaCall* ConstructLuaCallFrame(
		LuaCall* const frame,
		LuaObject* const functionObject
	)
	{
		frame->m_functionObj.m_next = nullptr;
		frame->m_functionObj.m_prev = nullptr;
		frame->m_functionObj.m_state = nullptr;
		frame->m_functionObj.m_object.tt = 0;
		frame->m_functionObj.m_object.value.p = nullptr;

		LuaState* const sourceState = functionObject->m_state;
		if (sourceState != nullptr) {
			frame->m_functionObj.AddToUsedObjectList(sourceState, &functionObject->m_object);
		}

		frame->m_numArgs = 0;
		LuaState* const boundState = frame->m_functionObj.m_state;
		frame->m_state = boundState->m_state->l_G->lstate->stateUserData;

		if (frame->m_functionObj.m_state == nullptr) {
			throw LuaAssertion("m_state");
		}

		constexpr std::uint32_t kFunctionTagMask = 1u;
		if ((static_cast<std::uint32_t>(frame->m_functionObj.m_object.tt) | kFunctionTagMask) != 7u) {
			luaG_typeerror(
				frame->m_functionObj.m_state->m_state->l_G->lstate,
				&frame->m_functionObj.m_object,
				"call"
			);
		}

		lua_State* const rootLuaState = frame->m_state->m_state;
		const int currentTop = lua_gettop(rootLuaState);
		frame->m_startResults = currentTop + 1;

		(void)frame->m_functionObj.PushStack(frame->m_state);
		return frame;
	}

	/**
	 * Address: 0x00907270 (FUN_00907270)
	 *
	 * What it does:
	 * Runs one prepared Lua call frame using retained argument-count lanes, then
	 * materializes one stack-object view for the top result slot.
	 */
	LuaStackObject* InvokeLuaCallFrame(
		LuaCall* const frame,
		LuaStackObject* const outResult,
		const int* const resultCount
	)
	{
		lua_call(frame->m_state->m_state, frame->m_numArgs, *resultCount);
		outResult->m_state = frame->m_state;
		outResult->m_stackIndex = frame->m_startResults - 1;
		return outResult;
	}

	/**
	 * Address: 0x00907480 (FUN_00907480)
	 *
	 * What it does:
	 * Copies one tagged Lua value to `state->top`, grows stack when needed, and
	 * advances top by one slot.
	 */
	StkId PushRawLuaObjectToStack(const TObject* const object, lua_State* const state)
	{
		StkId const top = state->top;
		*top = *object;
		if (top >= state->ci->top) {
			(void)lua_checkstack(state, 1);
		}

		state->top = top + 1;
		return top;
	}

	/**
	 * Address: 0x00908940 (FUN_00908940)
	 *
	 * What it does:
	 * Pushes one LuaObject argument onto a prepared Lua call frame and bumps the
	 * retained argument-count lane.
	 */
	LuaCall* PushLuaObjectArgumentToCallFrame(
		LuaCall* const frame,
		LuaObject* const argument
	)
	{
		const StkId pushed = argument->PushStack(frame->m_state);
		(void)pushed;
		++frame->m_numArgs;
		return frame;
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

/**
 * Address: 0x009125E0 (FUN_009125E0, lua_getstack)
 *
 * What it does:
 * Walks `level` frames down from the current one and records which
 * CallInfo that landed on, so `lua_getinfo` can describe it. Tail calls
 * collapsed into a Lua frame each count as a level of their own, which is
 * why a frame's `tailcalls` comes off the counter. Reports failure once the
 * walk reaches the base frame with levels still to go.
 */
int lua_getstack(lua_State* const state, const int level, ::lua_Debug* const activationRecord)
{
	constexpr int kFrameCFunction = 3;

	int remaining = level;
	CallInfo* ci = state->ci;

	if (level > 0) {
		bool landed = false;
		while (ci > state->base_ci) {
			--remaining;
			if (ci->state < kFrameCFunction) {
				remaining -= ci->tailcalls;
			}
			// Step down first, then check: level 1 has to end up on the
			// caller of the running function, not on the running function
			// itself. Testing before the step made every level report one
			// frame too shallow, so debug.getinfo(1) described the C
			// function it was called from instead of the Lua one that
			// called it.
			--ci;
			if (remaining <= 0) {
				landed = true;
				break;
			}
		}

		if (!landed && remaining > 0) {
			return 0;
		}
	}

	if (ci == state->base_ci) {
		return 0;
	}

	// A negative remainder means the level landed inside a run of tail
	// calls rather than on a real frame; i_ci = 0 marks that for
	// lua_getinfo, which then answers from info_tailcall.
	activationRecord->i_ci = (remaining >= 0) ? static_cast<int>(ci - state->base_ci) : 0;
	return 1;
}

/**
 * Address: 0x009132F0 (FUN_009132F0, lua_getinfo)
 *
 * What it does:
 * Describes either the function on top of the stack (`what` starting with
 * '>') or the frame `lua_getstack` recorded. When the option string asks
 * for 'f', the function object auxgetinfo parked at the top is published.
 */
int lua_getinfo(lua_State* const state, const char* what, ::lua_Debug* const activationRecord)
{
	int status = 1;

	if (*what == '>') {
		StkId const functionSlot = state->top - 1;
		// `or eax, 1 / cmp eax, 7` - the two function tags differ only in the
		// low bit, so this is one test for "callable".
		if ((functionSlot->tt | 1) != LUA_TFUNCTION) {
			luaG_runerror(state, "value for `lua_getinfo' is not a function");
		}

		status = auxgetinfo(what + 1, functionSlot, activationRecord, state, nullptr);
		--state->top; // the function was an argument; consume it
	} else if (activationRecord->i_ci != 0) {
		CallInfo* const ci = state->base_ci + activationRecord->i_ci;
		status = auxgetinfo(what, ci->base - 1, activationRecord, state, ci);
	} else {
		info_tailcall(activationRecord, state);
	}

	if (std::strchr(what, 'f') != nullptr) {
		if (state->stack_last - state->top <= 1) {
			luaD_growstack(state, 1);
		}
		++state->top;
	}

	return status;
}

namespace LuaPlus
{
	/**
	 * Address: 0x00928DD0 (FUN_00928DD0, LoadSignature)
	 * IDA signature:
	 * void __usercall LoadSignature(LoadState *S@<esi>);
	 *
	 * What it does:
	 * Reads and validates the `"\x1BLua"` chunk signature byte-by-byte from the
	 * load stream; raises "unexpected end of file" on EOF and "bad signature" on
	 * the first mismatching byte.
	 */
	void LuaLoadSignature(LoadState* const loadState)
	{
		const char* expected = "\x1BLua";
		for (;;) {
			const int byteValue = LuaReadChunkByteOrThrow(loadState);
			if (byteValue != static_cast<unsigned char>(*expected)) {
				break;
			}
			if (*++expected == '\0') {
				return;
			}
		}

		if (*expected != '\0') {
			luaG_runerror(loadState->state, "bad signature in %s", loadState->chunkName);
		}
	}

	/**
	 * Address: 0x00928E50 (FUN_00928E50, TestSize)
	 * IDA signature:
	 * void __usercall TestSize(int s@<edi>, LoadState *S@<esi>, const char *tname);
	 *
	 * What it does:
	 * Reads one size byte from the load stream and verifies it equals the
	 * expected `sizeof(<tname>)`; raises "virtual machine mismatch" on a size
	 * disagreement (and "unexpected end of file" on EOF).
	 */
	void LuaTestTypeSize(const int expectedSize, LoadState* const loadState, const char* const typeName)
	{
		const int readSize = LuaReadChunkByteOrThrow(loadState);
		if (static_cast<unsigned char>(readSize) != expectedSize) {
			luaG_runerror(
				loadState->state,
				"virtual machine mismatch in %s: size of %s is %d but read %d",
				loadState->chunkName,
				typeName,
				expectedSize,
				static_cast<unsigned char>(readSize)
			);
		}
	}

	/**
	 * Address: 0x00928EC0 (FUN_00928EC0, luaU_endianness)
	 *
	 * IDA signature:
	 * int __cdecl luaU_endianness(void);
	 *
	 * What it does:
	 * Reports the native byte order for the chunk header - 1 little-endian,
	 * 0 big. Upstream writes `int x = 1; return *(char*)&x;`, which on this
	 * 32-bit x86 target the compiler folds to the two instructions actually
	 * present: `mov eax, 1` / `ret`.
	 *
	 * It sits at 0x00928EC0, directly between `LuaTestTypeSize` (0x00928E50)
	 * and `LuaLoadChunkHeader` (0x00928ED0), which is exactly where
	 * `lundump.c` defines it - and the reason it belongs here rather than in
	 * the import-thunk file a PE-wide byte scan once put it in. Its only caller
	 * is `LuaDumpChunkHeader` in LuaDump.cpp, which calls it at 0x00914D3B.
	 *
	 * Byte-identical bodies live at twelve other addresses in this image.
	 * They are separate functions belonging to separate translation units, not
	 * folded twins of this one; this address is the loader's.
	 */
	int luaU_endianness()
	{
		const int probe = 1;
		return *reinterpret_cast<const char*>(&probe);
	}

	/**
	 * Address: 0x00928ED0 (FUN_00928ED0, LoadChunk)
	 * IDA signature:
	 * void __usercall LoadChunk(LoadState *S@<eax>);
	 *
	 * What it does:
	 * Validates the full binary chunk header: signature, combined
	 * version/format word (must equal 0x0501), endianness/byte-swap flag, the
	 * eight type-size bytes (int/size_t/Instruction/OP/A/B/C/number), and the
	 * `lua_Number` self-test value (must truncate to 31415926).
	 */
	void LuaLoadChunkHeader(LoadState* const loadState)
	{
		LuaLoadSignature(loadState);

		const int versionByte = LuaReadChunkByteOrThrow(loadState);
		const int formatByte = LuaReadChunkByteOrThrow(loadState);
		const int versionWord = static_cast<unsigned char>(formatByte)
			| (static_cast<unsigned char>(versionByte) << 8);
		if (versionWord > 0x0501) {
			luaG_runerror(
				loadState->state,
				"%s too new: read version %d.%d; expected at most %d.%d",
				loadState->chunkName,
				versionWord / 16,
				versionWord & 0xF,
				80,
				1
			);
		}
		if (versionWord < 0x0501) {
			luaG_runerror(
				loadState->state,
				"%s too old: read version %d.%d; expected at least %d.%d",
				loadState->chunkName,
				versionWord / 16,
				versionWord % 16,
				80,
				1
			);
		}

		const int endiannessByte = LuaReadChunkByteOrThrow(loadState);
		loadState->swapBytes = (static_cast<std::uint8_t>(endiannessByte) != 1) ? 1 : 0;

		LuaTestTypeSize(4, loadState, "int");
		LuaTestTypeSize(4, loadState, "size_t");
		LuaTestTypeSize(4, loadState, "Instruction");
		LuaTestTypeSize(6, loadState, "OP");
		LuaTestTypeSize(8, loadState, "A");
		LuaTestTypeSize(9, loadState, "B");
		LuaTestTypeSize(9, loadState, "C");
		LuaTestTypeSize(4, loadState, "number");

		float numberFormat = 0.0f;
		LuaLoadBlock(4u, &numberFormat, loadState);
		if (static_cast<int>(numberFormat) != 31415926) {
			luaG_runerror(loadState->state, "unknown number format in %s", loadState->chunkName);
		}
	}

	/**
	 * Address: 0x00928C10 (FUN_00928C10, LoadFunction)
	 * IDA signature:
	 * Proto *__cdecl LoadFunction(LoadState *S, TString *parentSource);
	 *
	 * What it does:
	 * Recursively reads one `Proto` from the chunk stream: source string (falling
	 * back to the parent chunk name), line-defined, upvalue/param counts,
	 * vararg/stack-size flags, then the line-info, local-variable, upvalue-name,
	 * constant + nested-proto, and bytecode lanes via the sub-loaders. Validates
	 * decoded bytecode with `luaG_checkcode`.
	 */
	Proto* LuaLoadProtoObject(LoadState* const loadState, TString* const fallbackSource)
	{
		Proto* const proto = luaF_newproto(loadState->state);

		TString* const loadedSource = LuaLoadTString(loadState);
		proto->source = (loadedSource != nullptr) ? loadedSource : fallbackSource;
		faf_lua51_gc_barrier_f(
			loadState->state,
			reinterpret_cast<GCObject*>(proto),
			reinterpret_cast<GCObject*>(proto->source)
		); // Lua 5.1.5 lparser.c: Proto source barrier

		int lineDefined = 0;
		LuaLoadBlock(4u, &lineDefined, loadState);
		if (lineDefined < 0) {
			luaG_runerror(loadState->state, "bad integer in %s", loadState->chunkName);
		}
		proto->lineDefined = lineDefined;

		proto->nups = static_cast<lu_byte>(LuaReadChunkByteOrThrow(loadState));
		proto->numparams = static_cast<lu_byte>(LuaReadChunkByteOrThrow(loadState));
		proto->is_vararg = static_cast<lu_byte>(LuaReadChunkByteOrThrow(loadState));
		proto->maxstacksize = static_cast<lu_byte>(LuaReadChunkByteOrThrow(loadState));

		LuaLoadProtoLineInfo(loadState, proto);
		LuaLoadProtoLocalVariableDebugInfo(loadState, proto);
		LuaLoadProtoUpvalueNames(loadState, proto);
		LuaLoadProtoConstantsAndNestedProtos(loadState, proto);
		LuaLoadProtoCode(loadState, proto);

		if (luaG_checkcode(proto) == 0) {
			luaG_runerror(loadState->state, "bad code in %s", loadState->chunkName);
		}

		return proto;
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

namespace
{
	// LUA_CFUNCTION (6) and LUA_TFUNCTION (7) are adjacent tags differing only
	// in the low bit, which is how the binary tests "is this callable" in one
	// instruction pair: `or eax, 1` / `cmp eax, 7`.
	[[nodiscard]] constexpr bool IsCallableTag(const int tag) noexcept
	{
		return (tag | 1) == LUA_TFUNCTION;
	}
}

/**
 * Address: 0x00929450 (FUN_00929450, luaV_settable)
 *
 * IDA signature:
 * void __cdecl luaV_settable(lua_State *L, const TObject *t, TObject *key, StkId val);
 *
 * What it does:
 * Performs one `t[key] = val` with full `__newindex` semantics. The raw table
 * store wins in three cases: the slot already holds a non-nil value, the
 * metatable carries the cached "no __newindex here" flag, or the metatable
 * genuinely has no `__newindex`. Otherwise the handler is invoked when it is
 * callable, and re-indexed into when it is another container - bounded to 100
 * hops before raising "loop in settable".
 *
 * Defined with C linkage at namespace scope on purpose: the prebuilt
 * LuaPlus lib carries its own `_luaV_settable` built against a different
 * TObject/Table layout, and letting that one win is what corrupted every
 * table written through `luaL_openlib` during startup.
 *
 * FAF hot-patch: 0x00929450 jumps to 0x0128C4F4 in .exxt, a full replacement
 * body. Against the 2007 body it differs in three ways, all modelled here:
 *  - only LUA_TFUNCTION (7) is invoked; the 2007 `(tt | 1) == 7` test also
 *    called a LUA_CFUNCTION (6) handler, which the patch re-indexes into
 *    instead (and the inlined callTM stores the tag as 7);
 *  - the handler is copied into a frame temporary before re-indexing, so
 *    later hops read that copy rather than the handler's slot;
 *  - the hop budget is a `dec ebx`/`jne` count from 100, i.e. 100 lookups,
 *    where the 2007 `++loop <= 100` allowed 101.
 */
extern "C" void luaV_settable(
	lua_State* const state,
	const TObject* target,
	TObject* const key,
	TObject* const val
)
{
	constexpr int kTagMethodNewIndex = 1;
	constexpr int kNoNewIndexTagMethodFlag = 1 << kTagMethodNewIndex;
	constexpr int kMaxTagMethodChain = 100;

	TObject chainedHandler{};
	for (int hopsLeft = kMaxTagMethodChain; hopsLeft != 0; --hopsLeft) {
		const TObject* handler = nullptr;

		if (target->tt == LUA_TTABLE) {
			auto* const table = static_cast<Table*>(target->value.p);
			TObject* const slot = luaH_set(state, table, key);

			if (slot->tt != LUA_TNIL) {
				*slot = *val;
				faf_lua51_gc_barrier_back(state, table); // Lua 5.1.5 lvm.c: luaV_settable()
				return;
			}

			Table* const metatable = table->metatable;
			if ((metatable->flags & kNoNewIndexTagMethodFlag) != 0) {
				*slot = *val;
				faf_lua51_gc_barrier_back(state, table); // Lua 5.1.5 lvm.c: luaV_settable()
				return;
			}

			handler = luaT_gettm(metatable, kTagMethodNewIndex, state->l_G->tmname[kTagMethodNewIndex]);
			if (handler == nullptr) {
				*slot = *val;
				faf_lua51_gc_barrier_back(state, table); // Lua 5.1.5 lvm.c: luaV_settable()
				return;
			}
		} else {
			handler = luaT_gettmbyobj(state, target, kTagMethodNewIndex);
			if (handler->tt == LUA_TNIL) {
				luaG_typeerror(state, target, "index");
			}
		}

		if (handler->tt == LUA_TFUNCTION) {
			callTM(target, key, val, state, handler);
			return;
		}

		chainedHandler = *handler;
		target = &chainedHandler;
	}

	luaG_runerror(state, "loop in settable");
}

namespace moho
{
	static UserGcDispatcher sUserGcDispatcher{};

	void RegisterUserGcDispatcher(const UserGcDispatcher& dispatcher) noexcept
	{
		sUserGcDispatcher = dispatcher;
	}

	/**
	 * Engine addition: `lua_AllowPrecompiledChunks`. Off, `lua_load` (and so
	 * `doscript`, `import`, `loadstring`, `dofile`) refuses compiled Lua chunks
	 * and takes source only. A crafted chunk can get past `luaG_checkcode` and
	 * run native code, and a lobby's map or mod would run it on every joiner.
	 * On by default for now, so mods and maps that ship compiled chunks can move
	 * to source; each compiled chunk loaded is named in the log (`f_parser`).
	 */
	bool lua_AllowPrecompiledChunks = true;
	thread_local bool lua_LoadingCachedChunk = false;

	TConVar<bool> gTConVar_lua_AllowPrecompiledChunks(
		"lua_AllowPrecompiledChunks",
		"Load compiled Lua chunks as well as source (off: a map or mod could run native code through one).",
		&lua_AllowPrecompiledChunks
	);

	/**
	 * Engine addition: `lua_ThreadedDispatch`. On, the interpreter reaches each instruction's handler
	 * through a table of label addresses and takes its fast paths (LuaExecute); off, the binary's switch.
	 */
	bool lua_ThreadedDispatch = true;

	TConVar<bool> gTConVar_lua_ThreadedDispatch(
		"lua_ThreadedDispatch",
		"Reach each Lua instruction's handler through a table of label addresses, with fast paths for table "
		"slots, comparisons and next() loops (1, the default), or through the binary's switch (0). The same "
		"results either way; Lua runs faster with 1.",
		&lua_ThreadedDispatch
	);

	/**
	 * Engine addition: `lua_ParallelMark`, a user-side switch. When set, the mark phase of a sim
	 * Lua collection runs on the sim worker pool: propagation (`PropagateMarksForCollection`), the
	 * LuaPlus root objects (`MarkRootForCollection`), weak-table clearing (`parallel_weak`) and the
	 * userdata separation (`parallel_sweep::SeparateUserdata`). On by default; it only acts while
	 * `sim_Workers` > 0.
	 */
	bool lua_ParallelMark = true;

	// Off until the game's startup copies the convar in (CaptureIncrementalGcStartupSetting, from
	// CScApp::Init). Headless, the server and the tools never do, so their session states keep the
	// shipped collector and their sim paths skip the incremental checks.
	bool lua_IncrementalGC = false;
	bool lua_IncrementalGCSetting = true;

	TConVar<bool> gTConVar_lua_IncrementalGC(
		"lua_IncrementalGC",
		"Use the Lua 5.1-style incremental collector (default on); 0 keeps the shipped full stop-the-world collector.",
		&lua_IncrementalGCSetting
	);

	TConVar<bool> gTConVar_lua_ParallelMark(
		"lua_ParallelMark",
		"Mark the sim Lua heap on the sim worker threads during a collection (same results).",
		&lua_ParallelMark
	);

	/**
	 * Engine addition: `lua_ParallelSweep`, a user-side switch. When set, the sweep of a sim Lua
	 * collection classifies the heap on the sim worker pool (see `SweepForCollection`); the frees
	 * stay on the sim thread, in list order. On by default; it only acts while `sim_Workers` > 0.
	 */
	bool lua_ParallelSweep = true;

	TConVar<bool> gTConVar_lua_ParallelSweep(
		"lua_ParallelSweep",
		"Sort live from dead objects of the sim Lua heap on the sim worker threads during a sweep (same results).",
		&lua_ParallelSweep
	);

	/**
	 * Engine addition, debugging aid: `lua_GcVerify`, a user-side switch, default off. Checks every
	 * parallel sim collection against a serial one (see `gc_verify`). Slow; for soak and debug runs.
	 */
	bool lua_GcVerify = false;

	TConVar<bool> gTConVar_lua_GcVerify(
		"lua_GcVerify",
		"Debug: check each parallel sim Lua collection against a serial mark and sweep, logging [GCVERIFY] lines.",
		&lua_GcVerify
	);
} // namespace moho

/**
 * Engine addition, debugging aid: `lua_GcVerify` (default off). At every sim collection that runs
 * the parallel collector, the mark is first run serially into a reference (then the mark bytes are
 * put back), and the parallel mark is compared with it: mark bytes and weak-table lists after both
 * propagations. After the mark it checks that no marked weak table still refers to an unmarked
 * object, that no live closure keeps an open upvalue into a dead thread's stack, and that the root
 * LuaObject list is intact; the parallel sweep's classification is compared with a serial walk.
 * Findings are logged as `[GCVERIFY]` warnings (at most 400 per process), and every 100th verified
 * collection as `[GCVERIFY-OK]`. The serial reference shrinks thread stacks as a serial mark would,
 * so a verified run can collect at slightly different points than an unverified one.
 */
namespace
{
	enum class EGcPoolKind
	{
		None,
		Sim,
		User
	};

	struct GcWorkerPoolInfo
	{
		EGcPoolKind kind{EGcPoolKind::None};
		unsigned int workerCount{0};

		[[nodiscard]] bool IsParallel() const noexcept {
			return kind != EGcPoolKind::None && workerCount > 0u;
		}

		template <class Body>
		void ParallelFor(std::size_t count, std::size_t grain, Body&& body) const
		{
			if (kind == EGcPoolKind::Sim) {
				moho::CSimWorkerPool::Get().ParallelFor(count, grain, std::forward<Body>(body));
			} else if (kind == EGcPoolKind::User) {
				using BodyType = std::remove_reference_t<Body>;
				moho::sUserGcDispatcher.parallelFor(
					count,
					grain,
					[](void* context, std::size_t begin, std::size_t end) {
						(*static_cast<BodyType*>(context))(begin, end);
					},
					const_cast<void*>(static_cast<const void*>(std::addressof(body)))
				);
			} else {
				for (std::size_t begin = 0; begin < count; begin += grain) {
					body(begin, std::min(count, begin + grain));
				}
			}
		}
	};

	namespace gc_verify
	{
		[[nodiscard]] bool Enabled() noexcept
		{
			return moho::lua_GcVerify;
		}

		std::atomic<long> sCollection{0};
		long sReported = 0;
		constexpr long kReportBudget = 400;

		[[nodiscard]] bool Report() noexcept
		{
			return ++sReported <= kReportBudget;
		}

		void CollectObjects(global_State* const g, std::vector<GCObject*>& out)
		{
			out.clear();
			const auto addList = [&out](GCObject* object) {
				for (; object != nullptr; object = object->gch.next) {
					out.push_back(object);
				}
			};
			const auto addOpen = [&out](lua_State* const thread) {
				for (GCObject* upvalue = thread->openupval; upvalue != nullptr; upvalue = upvalue->gch.next) {
					out.push_back(upvalue);
				}
			};
			addList(g->rootgc);
			addList(g->rootgc1);
			addList(g->rootudata);
			addList(g->tmudata);
			for (int bucket = 0; bucket < g->strt.size; ++bucket) {
				addList(g->strt.hash[bucket]);
			}
			out.push_back(reinterpret_cast<GCObject*>(g->mainthread));
			addOpen(g->mainthread);
			for (GCObject* thread = g->rootgc1; thread != nullptr; thread = thread->gch.next) {
				if (thread->gch.tt == LUA_TTHREAD) {
					addOpen(&thread->th);
				}
			}
		}

		void ReadMarks(const std::vector<GCObject*>& objects, std::vector<lu_byte>& out)
		{
			out.resize(objects.size());
			for (std::size_t index = 0; index < objects.size(); ++index) {
				out[index] = objects[index]->gch.marked;
			}
		}

		void WriteMarks(const std::vector<GCObject*>& objects, const std::vector<lu_byte>& marks)
		{
			for (std::size_t index = 0; index < objects.size(); ++index) {
				objects[index]->gch.marked = marks[index];
			}
		}

		void ListToVector(GCObject* list, std::vector<GCObject*>& out)
		{
			out.clear();
			for (; list != nullptr; list = list->h.gclist) {
				out.push_back(list);
			}
			std::sort(out.begin(), out.end());
		}

		[[nodiscard]] const char* TypeName(const int tt) noexcept
		{
			switch (tt) {
			case LUA_TSTRING: return "string";
			case LUA_TTABLE: return "table";
			case LUA_CFUNCTION: return "cfunction";
			case LUA_TFUNCTION: return "function";
			case LUA_TUSERDATA: return "userdata";
			case LUA_TTHREAD: return "thread";
			case LUA_TPROTO: return "proto";
			case LUA_TUPVALUE: return "upvalue";
			default: return "?";
			}
		}

		/// The serial reference of one propagation, taken before the parallel one runs.
		struct MarkReference
		{
			std::vector<GCObject*> objects;
			std::vector<lu_byte> before;
			std::vector<lu_byte> serial;
			std::vector<GCObject*> weak[3]; // wk, wv, wkv after the serial propagation, sorted
			long collection = 0;
			int pass = 0;
		};

		MarkReference sReference;
