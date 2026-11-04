// Part of LuaObject.cpp, included there: the debug library (ldblib).

	/**
	 * Address: 0x00911940 (FUN_00911940, getlocal)
	 *
	 * What it does:
	 * Returns local variable name/value pair for stack level arg-1 and local
	 * index arg-2; returns `nil` when local index is unavailable.
	 */
	int LuaDebugGetLocal(lua_State* const state)
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
	int LuaDebugSetLocal(lua_State* const state)
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
	int LuaDebugGetUpvalue(lua_State* const state)
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
	int LuaDebugSetUpvalue(lua_State* const state)
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
	void LuaDebugHookCallback(lua_State* const state, ::lua_Debug* const activationRecord)
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
	int LuaDebugBuildHookMask(const char* const maskSpec, const int count)
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
	int LuaDebugSetHook(lua_State* const state)
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
	int LuaDebugGetHook(lua_State* const state)
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
	int LuaDebugConsole(lua_State* const state)
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
	void LuaDebugPopulateFuncInfo(
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
	 * Address: 0x00912850 (FUN_00912850, info_tailcall)
	 *
	 * What it does:
	 * Fills one activation record for a frame that only exists as a tail call,
	 * where there is no function object left to describe, and pushes a nil in
	 * place of the function `lua_getinfo` would otherwise have left behind.
	 */
	void info_tailcall(::lua_Debug* const activationRecord, lua_State* const state)
	{
		activationRecord->namewhat = "";
		activationRecord->name = "";
		activationRecord->currentline = -1;
		activationRecord->linedefined = -1;
		activationRecord->what = "tail";
		activationRecord->source = "=(tail call)";
		luaO_chunkid(activationRecord->short_src, activationRecord->source, LUA_IDSIZE);
		activationRecord->nups = 0;
		state->top->tt = LUA_TNIL;
	}

	/**
	 * Address: 0x00913020 (FUN_00913020, auxgetinfo)
	 *
	 * IDA signature:
	 * int __usercall auxgetinfo(const char *what@<eax>, TObject *f@<edi>,
	 *     lua_Debug *ar@<esi>, lua_State *L, CallInfo *ci);
	 *
	 * What it does:
	 * Fills the activation record for one frame, a field per option letter.
	 * An unrecognised letter leaves the record alone and makes the whole call
	 * report failure, but the rest of the string is still processed.
	 */
	int auxgetinfo(
		const char* what,
		TObject* const functionObject,
		::lua_Debug* const activationRecord,
		lua_State* const state,
		CallInfo* const ci
	)
	{
		int status = 1;

		for (; *what != '\0'; ++what) {
			switch (*what) {
				case 'S':
					LuaDebugPopulateFuncInfo(activationRecord, functionObject);
					break;

				case 'f':
					// Parked at the top for lua_getinfo to publish once it has
					// seen an 'f' in the option string.
					*state->top = *functionObject;
					break;

				case 'l':
					activationRecord->currentline = (ci != nullptr) ? currentline(ci) : -1;
					break;

				case 'n': {
					const char* nameWhat = (ci != nullptr) ? getfuncname(&activationRecord->name, ci) : nullptr;
					activationRecord->namewhat = nameWhat;
					if (nameWhat == nullptr) {
						// Not resolvable from the call site, so fall back to
						// whatever global happens to hold this function.
						const char* const globalName = travglobals(state, functionObject);
						activationRecord->name = globalName;
						activationRecord->namewhat = (globalName != nullptr) ? "global" : "";
					}
					break;
				}

				case 'u':
					activationRecord->nups = static_cast<const Closure*>(functionObject->value.p)->c.nupvalues;
					break;

				default:
					status = 0;
					break;
			}
		}

		return status;
	}

	/**
	 * Address: 0x00911EC0 (FUN_00911EC0, listcode_buildop)
	 *
	 * What it does:
	 * Formats one Lua bytecode instruction into a debug line with source line,
	 * instruction index, opcode mnemonic, and decoded operand lane values.
	 */
	const char* LuaDebugBuildOpcodeText(
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
	int LuaDebugListCode(lua_State* const state)
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
	int LuaDebugListConstants(lua_State* const state)
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
	int LuaDebugListLocals(lua_State* const state)
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
	Table* LuaDebugGetSizesTable(lua_State* const state)
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
	int LuaDebugAllObjects(lua_State* const state)
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
	int LuaDebugAllocInfo(lua_State* const state)
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
	int LuaDebugTrackAllocations(lua_State* const state)
	{
		if (lua_type(state, 1) != LUA_TBOOLEAN) {
			luaL_argerror(state, 1, "boolean expected");
		}

		state->l_G->allocationTrackingEnabled = static_cast<lu_byte>(lua_toboolean(state, 1));
		return 0;
	}

	// The per-tag byte costs FUN_00912360 folds in. Each is the fixed header
	// of the object, with the variable tail added separately below.
	constexpr std::size_t kLuaTableFixedBytes = 0x24;     // sizeof(Table)
	constexpr std::size_t kLuaCClosureFixedBytes = 0x40;  // CClosure, TObject upvalues
	constexpr std::size_t kLuaLClosureFixedBytes = 0x1C;  // LClosure, UpVal* upvalues
	constexpr std::size_t kLuaUdataFixedBytes = 0x10;     // sizeof(Udata)
	constexpr std::size_t kLuaThreadFixedBytes = 0x48;    // sizeof(lua_State)

	static_assert(sizeof(Table) == kLuaTableFixedBytes, "Table size must be 0x24");
	static_assert(sizeof(Udata) == kLuaUdataFixedBytes, "Udata size must be 0x10");
	static_assert(sizeof(lua_State) == kLuaThreadFixedBytes, "lua_State size must be 0x48");
	static_assert(offsetof(CClosure, nupvalues) == 0x08, "CClosure::nupvalues must be at +0x08");
	static_assert(offsetof(LClosure, nupvalues) == 0x08, "LClosure::nupvalues must be at +0x08");
	static_assert(offsetof(LClosure, upvals) == kLuaLClosureFixedBytes, "LClosure::upvals must be at +0x1C");
	static_assert(offsetof(lua_State, stacksize) == 0x20, "lua_State::stacksize must be at +0x20");
	static_assert(offsetof(lua_State, end_ci) == 0x24, "lua_State::end_ci must be at +0x24");
	static_assert(offsetof(lua_State, base_ci) == 0x28, "lua_State::base_ci must be at +0x28");

	/**
	 * Address: 0x00912360 (FUN_00912360, func_GetTObjectSize)
	 *
	 * What it does:
	 * Returns aligned byte size for one Lua `TObject` payload by exact runtime
	 * type tag rules used by debug allocation helpers.
	 */
	std::size_t LuaDebugGetTObjectSize(const TObject* const object)
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
			const auto* const tableObject = static_cast<const Table*>(object->value.p);
			if (tableObject == nullptr) {
				return 0;
			}

			// An empty table shares the global dummy node and owns no hash part.
			const std::size_t hashBytes
				= tableObject->lsizenode != 0u ? (sizeof(Node) << tableObject->lsizenode) : 0u;
			const std::size_t arrayBytes = static_cast<std::size_t>(tableObject->sizearray) * sizeof(TObject);
			return AlignSizeToEight(hashBytes + arrayBytes + kLuaTableFixedBytes);
		}
		case LUA_CFUNCTION: {
			const auto* const closure = static_cast<const CClosure*>(object->value.p);
			if (closure == nullptr) {
				return 0;
			}
			// A C closure stores its upvalues inline as TObjects.
			return AlignSizeToEight(kLuaCClosureFixedBytes + sizeof(TObject) * closure->nupvalues);
		}
		case LUA_TFUNCTION: {
			const auto* const closure = static_cast<const LClosure*>(object->value.p);
			if (closure == nullptr) {
				return 0;
			}
			// A Lua closure stores pointers to shared UpVals instead.
			return AlignSizeToEight(kLuaLClosureFixedBytes + sizeof(UpVal*) * closure->nupvalues);
		}
		case LUA_TUSERDATA: {
			const auto* const userData = static_cast<const Udata*>(object->value.p);
			if (userData == nullptr) {
				return 0;
			}

			// This fork keeps the payload's RType in `len` rather than a byte
			// count, so the size comes from the descriptor.
			const auto* const payloadType = reinterpret_cast<const gpg::RType*>(userData->len);
			if (payloadType == nullptr) {
				return 0;
			}

			return AlignSizeToEight(static_cast<std::size_t>(payloadType->size_) + kLuaUdataFixedBytes);
		}
		case LUA_TTHREAD: {
			const auto* const threadState = static_cast<const lua_State*>(object->value.p);
			if (threadState == nullptr) {
				return 0;
			}

			// The CallInfo array is measured as the span between its ends
			// rather than from size_ci, which is what FUN_00912360 does:
			// 0x48 + stacksize*8, minus base_ci, plus end_ci.
			const std::size_t stackBytes = static_cast<std::size_t>(threadState->stacksize) * sizeof(TObject);
			const std::size_t callInfoBytes = static_cast<std::size_t>(
				reinterpret_cast<const char*>(threadState->end_ci)
				- reinterpret_cast<const char*>(threadState->base_ci)
			);
			return AlignSizeToEight(kLuaThreadFixedBytes + stackBytes + callInfoBytes);
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
	int LuaDebugAllocatedSize(lua_State* const state)
	{
		const int argumentCount = lua_gettop(state);
		for (int argumentIndex = 0; argumentIndex < argumentCount; ++argumentIndex) {
			TObject* const object = &state->base[argumentIndex];
			object->value.n = static_cast<float>(LuaDebugGetTObjectSize(object));
			object->tt = LUA_TNUMBER;
		}
		return argumentCount;
	}

	/**
	 * The per-callable profiling record this fork embeds in both kinds of
	 * callable object: at +0x18 inside a `CClosure` and at +0x48 inside a
	 * `Proto`. `func_profiledata` (0x0091E080) selects between the two on the
	 * GC tag - `lea eax, [ebp+48h]` for LUA_TPROTO, `lea ecx, [ebp+18h]` for
	 * LUA_CFUNCTION - then skips any record whose first two words are both
	 * zero (`mov ecx, [eax]` / `or ecx, [eax+4]`).
	 *
	 * `invocationCount` is one 64-bit counter, loaded whole by
	 * `fild qword ptr [ecx+20h]` at 0x0091E1B7. It is the same counter
	 * `luaD_precall` bumps on every C-closure call, which reaches it from the
	 * other direction as `CClosure::upvalue_m1[0]` - the slot one before the
	 * upvalue array, which is not an upvalue. The assert below is what keeps
	 * those two descriptions of one field agreeing.
	 */
	struct LuaProfileRecord
	{
		std::uint32_t sampleCount;      // +0x00
		std::uint32_t sampleCountAux;   // +0x04
		std::uint8_t reserved08[0x18];  // +0x08 timing lanes; emitted as zero
		std::int64_t invocationCount;   // +0x20
	};
	static_assert(
		offsetof(LuaProfileRecord, invocationCount) == 0x20,
		"LuaProfileRecord::invocationCount offset must be 0x20"
	);

	/// Where the record sits inside each of the two callable objects.
	constexpr std::size_t kCClosureProfileOffset = 0x18;
	constexpr std::size_t kProtoProfileOffset = 0x48;

	static_assert(
		offsetof(Proto, reserved0) == kProtoProfileOffset,
		"Proto's profile record must start at +0x48"
	);
	static_assert(
		offsetof(CClosure, upvalue_m1)
			== kCClosureProfileOffset + offsetof(LuaProfileRecord, invocationCount),
		"CClosure::upvalue_m1[0] must be the profile record's invocation counter"
	);

	[[nodiscard]] const LuaProfileRecord* LuaDebugGetProfileRecord(const GCObject* const object)
	{
		if (object->gch.tt == LUA_CFUNCTION) {
			return reinterpret_cast<const LuaProfileRecord*>(
				reinterpret_cast<const std::uint8_t*>(object) + kCClosureProfileOffset
			);
		}
		if (object->gch.tt == LUA_TPROTO) {
			return reinterpret_cast<const LuaProfileRecord*>(
				reinterpret_cast<const std::uint8_t*>(object) + kProtoProfileOffset
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
	int LuaDebugProfileData(lua_State* const state)
	{
		lua_newtable(state);
		auto* const outputTable = static_cast<Table*>((state->top - 1)->value.p);

		global_State* const globalState = state->l_G;
		++globalState->gcTraversalLockDepth;

		for (GCObject* secondary = globalState->rootgc1; secondary != nullptr; secondary = secondary->gch.next) {
		}

		int outputIndex = 0;
		for (GCObject* object = globalState->rootgc; object != nullptr; object = object->gch.next) {
			const LuaProfileRecord* const counters = LuaDebugGetProfileRecord(object);
			if (counters == nullptr || (counters->sampleCount | counters->sampleCountAux) == 0u) {
				continue;
			}

			LuaDebugAppendGcObject(state, outputTable, outputIndex, object);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, 0.0f);
			LuaDebugAppendNumber(state, outputTable, outputIndex, static_cast<float>(counters->invocationCount));
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
	void LuaCallAlert(lua_State* const state, const int status)
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
			status = LuaCallProtected(state, 0, LUA_MULTRET);
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
	int lua_dobuffer(
		lua_State* const state,
		const char* const buffer,
		const int size,
		const char* const name
	)
	{
		int status = ::luaL_loadbuffer(state, buffer, static_cast<size_t>(size), name);
		if (status == 0) {
			status = LuaCallProtected(state, 0, LUA_MULTRET);
		}

		LuaCallAlert(state, status);
		return status;
	}

	/**
	 * Address: 0x0090E8D0 (FUN_0090E8D0, lua_dostring)
	 *
	 * IDA signature:
	 * int __cdecl lua_dostring(lua_State *L, const char *s);
	 *
	 * What it does:
	 * Executes one null-terminated source string by forwarding to `lua_dobuffer`.
	 *
	 * `extern "C"` is load-bearing, not decoration. Without it this body carries
	 * C++ linkage, the `_lua_dostring` every caller emits stays unresolved, and
	 * the prebuilt LuaPlus library answers instead - with a `lua_State` laid out
	 * differently from this tree's. The same trap is why `lua_version` below
	 * carries it.
	 */
	extern "C" int lua_dostring(lua_State* const state, const char* const source)
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
	int str_len(lua_State* const state)
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
	int str_lower(lua_State* const state)
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
	int str_sub(lua_State* const state)
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
	int str_upper(lua_State* const state)
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
