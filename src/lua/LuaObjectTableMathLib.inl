// Part of LuaObject.cpp, included there: the table and math libraries (ltablib, lmathlib).

	/**
	 * Address: 0x00927DD0 (FUN_00927DD0, str_concat)
	 *
	 * IDA signature:
	 * int __cdecl str_concat(lua_State *L);
	 *
	 * What it does:
	 * table.concat(t, sep, i, j) - joins t[i..j] with sep, defaulting to the
	 * whole array part and an empty separator.
	 */
	int LuaTableConcat(lua_State* const state)
	{
		std::size_t separatorLength = 0;
		const char* const separator = luaL_optlstring(state, 2, "", &separatorLength);
		int first = static_cast<int>(luaL_optnumber(state, 3, 1.0));
		int last = static_cast<int>(luaL_optnumber(state, 4, 0.0));

		luaL_checktype(state, 1, LUA_TTABLE);
		if (last == 0) {
			last = luaL_getn(state, 1);
		}

		luaL_Buffer buffer;
		luaL_buffinit(state, &buffer);
		for (; first <= last; ++first) {
			lua_rawgeti(state, 1, first);
			if (lua_isstring(state, -1) == 0) {
				luaL_argerror(state, 1, "table contains non-strings");
			}
			luaL_addvalue(&buffer);
			if (first != last) {
				luaL_addlstring(&buffer, separator, separatorLength);
			}
		}

		luaL_pushresult(&buffer);
		return 1;
	}

	/**
	 * Compares two stack slots the way the sort was asked to: through the
	 * comparator parked at index 2 when there is one, and with lua_lessthan when
	 * index 2 is nil. The comparator path pushes the function first, so the two
	 * operand indices shift by one and two respectively.
	 */
	[[nodiscard]] bool LuaSortCompare(lua_State* const state, const int leftIndex, const int rightIndex)
	{
		if (lua_type(state, 2) == LUA_TNIL) {
			return lua_lessthan(state, leftIndex, rightIndex) != 0;
		}

		lua_pushvalue(state, 2);
		lua_pushvalue(state, leftIndex < 0 ? leftIndex - 1 : leftIndex);
		lua_pushvalue(state, rightIndex < 0 ? rightIndex - 2 : rightIndex);
		LuaCallUnprotected(state, 2, 1);
		const bool result = lua_toboolean(state, -1) != 0;
		lua_settop(state, -2);
		return result;
	}

	/**
	 * Writes the two values on top of the stack into t[i] and t[j].
	 */
	void LuaSortSet2(lua_State* const state, const int i, const int j)
	{
		lua_rawseti(state, 1, i);
		lua_rawseti(state, 1, j);
	}

	/**
	 * Address: 0x00927F60 (FUN_00927F60, auxsort)
	 *
	 * IDA signature:
	 * void __cdecl auxsort(lua_State *L, int l, int u);
	 *
	 * What it does:
	 * Quicksort over t[l..u]: orders the ends, medians the middle into u-1 as the
	 * pivot, partitions around it, then recurses into the smaller half and loops
	 * on the larger one. A comparator that never settles walks an index off the
	 * range, which is the "invalid order function for sorting" case.
	 */
	void LuaTableAuxSort(lua_State* const state, int lower, int upper)
	{
		while (lower < upper) {
			lua_rawgeti(state, 1, lower);
			lua_rawgeti(state, 1, upper);
			if (LuaSortCompare(state, -1, -2)) {
				LuaSortSet2(state, lower, upper);
			} else {
				lua_settop(state, -3);
			}

			if (upper - lower == 1) {
				break;
			}

			const int middle = (lower + upper) / 2;
			lua_rawgeti(state, 1, middle);
			lua_rawgeti(state, 1, lower);
			if (LuaSortCompare(state, -2, -1)) {
				LuaSortSet2(state, middle, lower);
			} else {
				lua_settop(state, -2);
				lua_rawgeti(state, 1, upper);
				if (LuaSortCompare(state, -1, -2)) {
					LuaSortSet2(state, middle, upper);
				} else {
					lua_settop(state, -3);
				}
			}

			if (upper - lower == 2) {
				break;
			}

			lua_rawgeti(state, 1, middle);
			lua_pushvalue(state, -1);
			const int pivotSlot = upper - 1;
			lua_rawgeti(state, 1, pivotSlot);
			LuaSortSet2(state, middle, pivotSlot);

			int i = lower;
			int j = pivotSlot;
			for (;;) {
				lua_rawgeti(state, 1, ++i);
				while (LuaSortCompare(state, -1, -2)) {
					if (i > upper) {
						luaL_error(state, "invalid order function for sorting");
					}
					lua_settop(state, -2);
					lua_rawgeti(state, 1, ++i);
				}

				lua_rawgeti(state, 1, --j);
				while (LuaSortCompare(state, -3, -1)) {
					if (j < lower) {
						luaL_error(state, "invalid order function for sorting");
					}
					lua_settop(state, -2);
					lua_rawgeti(state, 1, --j);
				}

				if (j < i) {
					break;
				}
				LuaSortSet2(state, i, j);
			}

			lua_settop(state, -4);
			lua_rawgeti(state, 1, pivotSlot);
			lua_rawgeti(state, 1, i);
			LuaSortSet2(state, pivotSlot, i);

			int recurseLower = 0;
			int recurseUpper = 0;
			if (i - lower >= upper - i) {
				recurseLower = i + 1;
				recurseUpper = upper;
				upper = i - 1;
			} else {
				recurseLower = lower;
				recurseUpper = i - 1;
				lower = i + 1;
			}
			LuaTableAuxSort(state, recurseLower, recurseUpper);
		}
	}

	/**
	 * Address: 0x00928360 (FUN_00928360, luaB_sort)
	 *
	 * IDA signature:
	 * int __cdecl luaB_sort(lua_State *L);
	 *
	 * What it does:
	 * table.sort(t [, comp]). Note there is no type check on the comparator: the
	 * fork accepts any callable and LuaSortCompare only asks whether index 2 is
	 * nil. Stock ltablib checks it against LUA_TFUNCTION, which is 6 in stock
	 * numbering but the *C* function tag in this fork, so the vendored copy of
	 * this function rejects every Lua comparator with "cfunction expected, got
	 * function".
	 */
	int LuaTableSort(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		const int count = luaL_getn(state, 1);
		luaL_checkstack(state, 40, "");
		lua_settop(state, 2);
		LuaTableAuxSort(state, 1, count);
		return 0;
	}

	/**
	 * Address: 0x00D47418 (tab_funcs)
	 *
	 * The "table" library registration array, read out of the shipped image:
	 * eight rows in this order, terminated by the null row. This table is the
	 * source-level invocation for every function in it.
	 */
	const luaL_reg kLuaTableLibrary[] = {
		{"concat", &LuaTableConcat},
		{"foreach", &LuaTableForEach},
		{"foreachi", &LuaTableForEachIndexed},
		{"getn", &LuaTableGetN},
		{"setn", &LuaTableSetN},
		{"sort", &LuaTableSort},
		{"insert", &LuaTableInsert},
		{"remove", &LuaTableRemove},
		{nullptr, nullptr}
	};

	/**
	 * Address: 0x0128BF5A (.exxt, FAF hot-patch; no FUN_ token in the IDA export)
	 *
	 * What it does:
	 * table.getsize(t): counts the non-nil values in the array part and in the
	 * hash part, pushed as a number; 0 when argument 1 is missing or not a
	 * table. The hash part is only walked when `lsizenode != 0`, so a table
	 * whose single hash node holds the only entry reports 0.
	 */
	int LuaTableGetSize(lua_State* const state)
	{
		lua_Number size = 0.0f;
		const TObject* const argument = state->base;
		if (argument < state->top && argument->tt == LUA_TTABLE) {
			const Table* const table = static_cast<const Table*>(argument->value.p);
			const auto isPresent = [](const TObject& value) { return value.tt != LUA_TNIL; };

			int count = 0;
			if (table->lsizenode != 0) {
				const Node* const nodes = table->node;
				count += static_cast<int>(std::count_if(
					nodes, nodes + (1 << table->lsizenode), [&](const Node& node) { return isPresent(node.i_val); }
				));
			}
			count += static_cast<int>(std::count_if(static_cast<TObject*>(table->array), table->array + table->sizearray, isPresent));
			size = static_cast<lua_Number>(count);
		}

		lua_pushnumber(state, size);
		return 1;
	}

	/**
	 * Address: 0x0128BFD1 (.exxt, FAF hot-patch; no FUN_ token in the IDA export)
	 *
	 * What it does:
	 * table.empty(t): true unless the hash part (walked only when
	 * `lsizenode != 0`) or the array part holds a non-nil value; also true when
	 * argument 1 is missing or not a table.
	 */
	int LuaTableEmpty(lua_State* const state)
	{
		bool isEmpty = true;
		const TObject* const argument = state->base;
		if (argument < state->top && argument->tt == LUA_TTABLE) {
			const Table* const table = static_cast<const Table*>(argument->value.p);
			const auto isPresent = [](const TObject& value) { return value.tt != LUA_TNIL; };

			if (table->lsizenode != 0) {
				const Node* const nodes = table->node;
				isEmpty = std::none_of(
					nodes, nodes + (1 << table->lsizenode), [&](const Node& node) { return isPresent(node.i_val); }
				);
			}
			if (isEmpty) {
				isEmpty = std::none_of(static_cast<TObject*>(table->array), table->array + table->sizearray, isPresent);
			}
		}

		lua_pushboolean(state, isEmpty ? 1 : 0);
		return 1;
	}

	/**
	 * Address: 0x0128C055 (.exxt, FAF hot-patch; no FUN_ token in the IDA export)
	 *
	 * What it does:
	 * table.unpack(t [, i [, j]]): pushes t[i]..t[j] raw, i defaulting to 1 and
	 * j to lua_getn(t) (both truncated from lua_Number), and returns the count;
	 * nothing when i > j.
	 */
	int LuaTableUnpack(lua_State* const state)
	{
		luaL_checktype(state, 1, LUA_TTABLE);
		const int length = lua_getn(state, 1);
		int index = static_cast<int>(luaL_optnumber(state, 2, 1.0f));
		const int last = static_cast<int>(luaL_optnumber(state, 3, static_cast<lua_Number>(length)));
		if (last < index) {
			return 0;
		}

		const int count = last - index + 1;
		luaL_checkstack(state, count, "too many results to unpack");
		for (; index <= last; ++index) {
			lua_rawgeti(state, 1, index);
		}
		return count;
	}

	/**
	 * Address: 0x0128B4DA (.exxt, FAF hot-patch; no FUN_ token in the IDA export)
	 *
	 * What it does:
	 * Builds a new table presized to `source`'s array size and `1 << lsizenode`,
	 * records it in `visited` under `source`, then copies every entry in
	 * iteration order. Keys are shared; a value already in `visited` reuses its
	 * copy, a table value is copied recursively, anything else is shared. The
	 * metatable is not copied.
	 */
	LuaObject DeepCopyLuaTable(const LuaObject& source, LuaObject& visited)
	{
		Ensure(source.m_state != nullptr, "m_state");
		Ensure(source.IsTable(), "IsTable()");

		const Table* const sourceTable = static_cast<const Table*>(source.m_object.value.p);
		LuaObject copy;
		copy.AssignNewTable(
			source.m_state, sourceTable->sizearray, static_cast<std::uint32_t>(1u << sourceTable->lsizenode)
		);
		visited.SetObject(source, copy);

		for (LuaTableIterator it(source, 1); it; it.Next()) {
			const LuaObject key = it.GetKey();
			const LuaObject value = it.GetValue();

			const LuaObject alreadyCopied = visited.GetByObject(value);
			if (!alreadyCopied.IsNil()) {
				copy.SetObject(key, alreadyCopied);
				continue;
			}

			Ensure(value.m_state != nullptr, "m_state");
			const LuaObject copiedValue = value.IsTable() ? DeepCopyLuaTable(value, visited) : LuaObject(value);
			copy.SetObject(key, copiedValue);
		}

		return copy;
	}

	/**
	 * Address: 0x0128B402 (.exxt, FAF hot-patch; no FUN_ token in the IDA export)
	 *
	 * What it does:
	 * Deep-copies a table through a fresh `visited` table (so shared and cyclic
	 * sub-tables keep their topology); any other value is returned as is.
	 */
	LuaObject DeepCopyLuaObject(const LuaObject& source)
	{
		Ensure(source.m_state != nullptr, "m_state");
		if (!source.IsTable()) {
			return source;
		}

		LuaObject visited;
		visited.AssignNewTable(source.m_state, 0, 0u);
		return DeepCopyLuaTable(source, visited);
	}

	/**
	 * Address: 0x0128C0F1 (.exxt, FAF hot-patch; no FUN_ token in the IDA export)
	 *
	 * What it does:
	 * table.clone(v): pushes a deep copy of argument 1.
	 */
	int LuaTableClone(lua_State* const state)
	{
		const LuaObject source(state->stateUserData, 1);
		const LuaObject copy = DeepCopyLuaObject(source);
		copy.PushStack(state);
		return 1;
	}

	/**
	 * Address: 0x0129366C (.exxt, FAF hot-patch registration array)
	 *
	 * The four rows FAF adds to the "table" library, in image order.
	 */
	const luaL_reg kFafTableLibraryExtensions[] = {
		{"getsize", &LuaTableGetSize},
		{"empty", &LuaTableEmpty},
		{"unpack", &LuaTableUnpack},
		{"clone", &LuaTableClone},
		{nullptr, nullptr}
	};

	/**
	 * Address: 0x009283A0 (FUN_009283A0, luaopen_table)
	 * Address: 0x0128C1DE (.exxt, FAF replacement opener)
	 *
	 * IDA signature:
	 * int __cdecl luaopen_table(lua_State *L);
	 *
	 * What it does:
	 * Opens the "table" library.
	 *
	 * FAF hot-patch: LuaState::Init's `call luaopen_table` at 0x0090AB1F now
	 * calls 0x0128C1DE in .exxt, which opens "table" from the original rows
	 * (0x00D47418) and then a second time from the FAF rows (0x0129366C),
	 * returning 1. 0x009283A0 itself is left unreferenced in the shipped image.
	 *
	 * Named apart from the binary's symbol for the same reason LuaOpenString is:
	 * `lualib.h` declares `luaopen_table` inside `extern "C"`, and the rename
	 * keeps this body from having to answer to that C symbol. The vendored
	 * library did export its own copy, compiled against stock tag numbering -
	 * it is no longer linked as of 2026-09-23, but the rename stands on the
	 * linkage argument alone.
	 */
	int LuaOpenTable(lua_State* const state)
	{
		luaL_openlib(state, "table", kLuaTableLibrary, 0);
		luaL_openlib(state, "table", kFafTableLibraryExtensions, 0);
		return 1;
	}

	/**
	 * Address: 0x00926EF0 (FUN_00926EF0, luaopen_string)
	 *
	 * IDA signature:
	 * int __cdecl luaopen_string(lua_State *L);
	 *
	 * What it does:
	 * Opens the "string" library and then makes that same table the default
	 * metatable for every string value, which is what lets `("x"):upper()` and
	 * `s:sub(1,2)` resolve without a per-string metatable.
	 *
	 * The type argument to `lua_setdefaultmetatable` is 4 - LUA_TSTRING in this
	 * fork's tag numbering.
	 *
	 * Named apart from the binary's symbol for the same reason `LuaOpenIo` is:
	 * the vendored `lualib.h` declares `luaopen_string` inside `extern "C"`, so
	 * a definition under that name would have to be `extern "C"` too or leave
	 * `_luaopen_string` for whatever else supplies it. The rename sidesteps the
	 * question entirely, and the one caller (`LuaOpenString(state)`, below in
	 * this file) names this body directly.
	 *
	 * An older version of this note said the prebuilt LuaPlus library's copy was
	 * "what currently answers", and blamed `string.gsub` rejecting every
	 * replacement on it. That was never true after the rename: a symbol scan of
	 * all 1,037 objects found `_luaopen_string` neither defined nor referenced
	 * anywhere in `src`, so the library's member was never pulled in to
	 * begin with. Since 2026-09-23 the library is not linked at all. If the
	 * `gsub` symptom is still reproducible, it has some other cause and the
	 * search should start over.
	 */
	int LuaOpenString(lua_State* const state)
	{
		luaL_openlib(state, "string", kLuaStringLibrary, 0);
		lua_pushstring(state, "string");
		lua_gettable(state, LUA_GLOBALSINDEX);
		lua_setdefaultmetatable(state, LUA_TSTRING);
		return 1;
	}

	/**
	 * Address: 0x00919930 (FUN_00919930)
	 *
	 * What it does:
	 * Bridges one Lua numeric value into `frexp` mantissa/exponent extraction
	 * and returns the mantissa lane as `double`.
	 *
	 * The binary's frexp is the MSVC8 CRT's (0x00A8DA05), which answers -0
	 * with +0 where the current CRT keeps -0 (difffuzz `lua_frexp`), so this
	 * goes through `fa::frexp`.
	 */
	double LuaFrexpMantissaBridgeA(const lua_Number value, int* const exponentOut)
	{
		if (exponentOut == nullptr) {
			errno = EINVAL;
			return 0.0;
		}

		return fa::frexp(static_cast<double>(value), exponentOut);
	}

	/**
	 * Address: 0x00919950 (FUN_00919950)
	 *
	 * What it does:
	 * Bridges one Lua numeric value plus exponent lane into `ldexp`.
	 */
	double LuaLdexpBridgeA(const lua_Number value, const int exponent)
	{
		return std::ldexp(static_cast<double>(value), exponent);
	}

	/**
	 * Address: 0x009199F0 (FUN_009199F0)
	 *
	 * What it does:
	 * Secondary dispatch lane into the Lua `frexp` bridge helper.
	 */
	double LuaFrexpMantissaBridgeB(const lua_Number value, int* const exponentOut)
	{
		return LuaFrexpMantissaBridgeA(value, exponentOut);
	}

	/**
	 * Address: 0x00919A10 (FUN_00919A10)
	 *
	 * What it does:
	 * Secondary dispatch lane into the Lua `ldexp` bridge helper.
	 */
	double LuaLdexpBridgeB(const lua_Number value, const int exponent)
	{
		return LuaLdexpBridgeA(value, exponent);
	}

	/**
	 * Address: 0x009199B0 (FUN_009199B0)
	 *
	 * What it does:
	 * Promotes one Lua numeric value to `double`, applies `ceil`, and returns
	 * the x87-compatible double-precision result lane.
	 */
	double LuaCeilBridge(const lua_Number value)
	{
		return std::ceil(static_cast<double>(value));
	}

	/**
	 * Address: 0x00919A50 (FUN_00919A50, math_abs)
	 *
	 * What it does:
	 * Computes `abs(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_abs(lua_State* const state)
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
	 *
	 * DETERMINISM NOTE, covering this whole trig cluster (`math_sin`,
	 * `math_cos`, `math_tan`, `math_asin`, `math_acos`, `math_atan`,
	 * `math_atan2`): the binary reaches these through the x87 transcendental
	 * instructions, whose low-order bits are implementation defined rather than
	 * IEEE-specified, and which differ between AMD and Intel. This is the widest
	 * exposure of that hazard in the engine, because sim scripts call
	 * `math.sin`/`math.cos` far more often than the engine's own aiming math
	 * does.
	 *
	 * It was measured, and it is NOT a live desync vector: under the engine's
	 * `_PC_24`, x87 `fsin`/`fcos` match the correctly-rounded result to zero ulp
	 * over ~1.4M distinct floats, the near-pi region included. Method and
	 * numbers are on `CalculateFiringDirection` in
	 * `moho/ai/CAimManipulator.cpp`. Recorded because the hazard looks real and
	 * gets re-proposed; the 24-bit precision control is what neutralises it.
	 *
	 * sin/cos/tan/atan/atan2 run those same x87 instructions through
	 * `fa::sinf` and friends (legacy/math/X87Math.h). The CRT's software
	 * routines would be vendor independent, but they are not the binary's, and
	 * the x86 and x64 CRTs disagree with each other in the last bit, which would
	 * split an x86 client from an x64 one. exp/log/log10 are inline x87
	 * expansions in the binary too (`fa::IntrinsicExp` and friends; exp's
	 * fmul/fadd steps round at 24 bits, so a correctly rounded exp differs).
	 * asin/acos/pow/mod go through the MSVC8 CRT's `_CI*` entries. The game
	 * calls _set_SSE2_enable(0), so those take their x87 bodies, whose
	 * arithmetic rounds under the simulation's _PC_24 and is not correctly
	 * rounded; `fa::asin`/`acos`/`pow`/`fmod` reproduce them. Every
	 * `math.*` entry has a difffuzz row (`--filter lua_`).
	 */
	int math_sin(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(fa::sinf(value)));
		return 1;
	}

	/**
	 * Address: 0x00919AB0 (FUN_00919AB0, math_cos)
	 *
	 * What it does:
	 * Computes `cos(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_cos(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(fa::cosf(value)));
		return 1;
	}

	/**
	 * Address: 0x00919AE0 (FUN_00919AE0, math_tan)
	 *
	 * What it does:
	 * Computes `tan(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_tan(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(fa::tanf(value)));
		return 1;
	}

	/**
	 * Address: 0x00919B40 (FUN_00919B40, math_acos)
	 *
	 * What it does:
	 * Computes `acos(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_acos(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(fa::acos(static_cast<double>(value)))); // _CIacos lane dispatch
		return 1;
	}

	/**
	 * Address: 0x00919B70 (FUN_00919B70, math_atan)
	 *
	 * What it does:
	 * Computes `atan(arg1)` (x87 `fpatan` lane with denominator `1.0`) and
	 * pushes one Lua numeric result.
	 */
	int math_atan(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(fa::atanf(value)));
		return 1;
	}

	/**
	 * Address: 0x00919BA0 (FUN_00919BA0, math_atan2)
	 *
	 * What it does:
	 * Computes `atan2(arg1, arg2)` with Lua numeric argument validation and
	 * pushes one Lua numeric result.
	 */
	int math_atan2(lua_State* const state)
	{
		const lua_Number numerator = luaL_checknumber(state, 1);
		const lua_Number denominator = luaL_checknumber(state, 2);
		lua_pushnumber(state, static_cast<lua_Number>(fa::atan2f(numerator, denominator)));
		return 1;
	}

	/**
	 * Address: 0x00919BE0 (FUN_00919BE0, math_ceil)
	 *
	 * What it does:
	 * Computes `ceil(arg1)` with Lua numeric argument validation and pushes one
	 * resulting Lua number.
	 */
	int math_ceil(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(LuaCeilBridge(value)));
		return 1;
	}

	/**
	 * Address: 0x00919C10 (FUN_00919C10, math_floor)
	 *
	 * What it does:
	 * Computes `floor(arg1)` with Lua numeric argument validation and pushes
	 * one resulting Lua number.
	 */
	int math_floor(lua_State* const state)
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
	int math_mod(lua_State* const state)
	{
		const lua_Number left = luaL_checknumber(state, 1);
		const lua_Number right = luaL_checknumber(state, 2);
		// 0x00919C63: the MSVC8 CRT `fmod` (0x00A8E06A), which returns +0 for a
		// -0 dividend where the current CRT keeps -0.
		lua_pushnumber(
			state,
			static_cast<lua_Number>(fa::fmod(static_cast<double>(left), static_cast<double>(right)))
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
	int math_sqrt(lua_State* const state)
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
	int math_pow(lua_State* const state)
	{
		const lua_Number base = luaL_checknumber(state, 1);
		const lua_Number exponent = luaL_checknumber(state, 2);
		lua_pushnumber(
			state,
			static_cast<lua_Number>(fa::pow(static_cast<double>(base), static_cast<double>(exponent)))
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
	int math_log(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(fa::IntrinsicLn(value))); // fldln2; fyl2x
		return 1;
	}

	/**
	 * Address: 0x00919D20 (FUN_00919D20, math_log10)
	 *
	 * What it does:
	 * Computes base-10 logarithm for arg-1 and pushes one Lua numeric result.
	 */
	int math_log10(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(fa::IntrinsicLog10(value))); // fldlg2; fyl2x
		return 1;
	}

	/**
	 * Address: 0x00919D50 (FUN_00919D50, math_exp)
	 *
	 * What it does:
	 * Computes exponential (`e^arg1`) and pushes one Lua numeric result.
	 */
	int math_exp(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(fa::IntrinsicExp(value))); // f2xm1/fscale expansion
		return 1;
	}

	/**
	 * Address: 0x00919D90 (FUN_00919D90, math_deg)
	 *
	 * What it does:
	 * Converts radians (arg-1) to degrees and pushes one Lua numeric result.
	 */
	int math_deg(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		// 0x00919D9D `fmul dword ptr [0x00D46340]` on the x87 stack: a product in
		// the denormal range rounds twice, unlike one SSE multiply.
		lua_pushnumber(state, fa::MultiplyX87(value, 57.29578f));
		return 1;
	}

	/**
	 * Address: 0x00919DC0 (FUN_00919DC0, math_rad)
	 *
	 * What it does:
	 * Converts degrees (arg-1) to radians and pushes one Lua numeric result.
	 */
	int math_rad(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		// 0x00919DCD `fmul dword ptr [0x00D46344]`, as in math_deg.
		lua_pushnumber(state, fa::MultiplyX87(value, 0.017453292f));
		return 1;
	}

	/**
	 * Address: 0x00919DF0 (FUN_00919DF0, math_frexp)
	 *
	 * What it does:
	 * Computes `frexp(arg1, &exp)` and pushes both mantissa and exponent as Lua
	 * numeric results.
	 */
	int math_frexp(lua_State* const state)
	{
		int exponent = 0;
		const lua_Number value = luaL_checknumber(state, 1);
		const lua_Number mantissa = static_cast<lua_Number>(LuaFrexpMantissaBridgeB(value, &exponent));
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
	int math_ldexp(lua_State* const state)
	{
		const int exponent = static_cast<int>(luaL_checknumber(state, 2));
		const lua_Number value = luaL_checknumber(state, 1);
		lua_pushnumber(state, static_cast<lua_Number>(LuaLdexpBridgeB(value, exponent)));
		return 1;
	}

	/**
	 * Address: 0x00919E90 (FUN_00919E90, math_min)
	 *
	 * What it does:
	 * Returns the minimum numeric value across all Lua arguments.
	 */
	int math_min(lua_State* const state)
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
	int math_max(lua_State* const state)
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
	int math_randomseed(lua_State* const state)
	{
		// 0x0091A0F5: `fistp qword` (truncating), low dword kept - so negative and
		// >= 2^32 seeds wrap modulo 2^32 rather than hitting a float-to-unsigned
		// conversion that is undefined for them, and NaN, infinities and values
		// beyond int64 seed 0 (the integer indefinite's low dword).
		const auto seed = static_cast<unsigned int>(fa::TruncateToInt64(luaL_checknumber(state, 1)));
		std::srand(seed);
		return 0;
	}

	/**
	 * Address: 0x00919B10 (FUN_00919B10, math_asin)
	 *
	 * What it does:
	 * Computes `asin(arg1)` after Lua numeric argument validation and pushes
	 * one Lua numeric result.
	 */
	int math_asin(lua_State* const state)
	{
		const lua_Number value = luaL_checknumber(state, 1);
		// 0x00919B20: `_CIasin` (0x00A8DE20) with the float on the x87 stack.
		lua_pushnumber(state, static_cast<lua_Number>(fa::asin(static_cast<double>(value))));
		return 1;
	}

	/**
	 * The scale the engine applies to `rand()` to reach [0,1).
	 *
	 * This is 0x38000100, which is NOT 1/32768 (that would be 0x38000000) - the
	 * fork's constant is a hair larger. Kept bit-exact rather than "corrected",
	 * because `math.random` feeds simulation code and any drift here desyncs.
	 */
	constexpr float kLuaRandomScale = 3.0518509447574615e-05f;

	/**
	 * Address: 0x00919F90 (FUN_00919F90, math_random)
	 *
	 * IDA signature:
	 * int __usercall math_random@<eax>(__m128i a1@<xmm0>, lua_State *L);
	 *
	 * What it does:
	 * Lua's three-form `math.random`: no argument yields the raw [0,1) sample,
	 * one argument `u` yields an integer in [1,u], and two arguments `l,u` yield
	 * an integer in [l,u]. The sample is drawn once up front, before the
	 * argument count is even read, so the RNG advances on every call regardless
	 * of form.
	 *
	 * The range forms scale on the x87 (0x0091A089 `fild upper; fmul dword
	 * sample`, 0x0091A02E likewise for `upper - lower + 1`), and the sim runs
	 * under `_PC_24`, so the product is rounded to single precision BEFORE
	 * `floor` sees it. Flooring the unrounded double product instead returns
	 * one less whenever the exact product sits just under an integer that the
	 * float rounding reaches. A 24-bit sample times a 31-bit span needs up to
	 * 55 bits, so a double multiply can round first and hand the float
	 * conversion a false tie (spans above 2^29); `fa::MultiplyIntegerX87`
	 * rounds the exact product once. The trailing `fadd 1.0f` /
	 * `fiadd lower` is one more single-rounded op. The span
	 * `upper - lower + 1` is the binary's wrapping `sub esi, ebx; add esi, 1`.
	 */
	int math_random(lua_State* const state)
	{
		const float sample = static_cast<float>(std::rand() % 0x7FFF) * kLuaRandomScale;

		const int argumentCount = lua_gettop(state);
		if (argumentCount == 0) {
			lua_pushnumber(state, sample);
			return 1;
		}

		if (argumentCount == 1) {
			const int upper = static_cast<int>(luaL_checknumber(state, 1));
			if (upper < 1) {
				luaL_argerror(state, 1, "interval is empty");
			}
			const float scaled = fa::MultiplyIntegerX87(upper, sample);
			const float picked = std::floor(scaled);
			lua_pushnumber(state, picked + 1.0f);
			return 1;
		}

		if (argumentCount != 2) {
			luaL_error(state, "wrong number of arguments");
		}

		const int lower = static_cast<int>(luaL_checknumber(state, 1));
		const int upper = static_cast<int>(luaL_checknumber(state, 2));
		if (lower > upper) {
			luaL_argerror(state, 2, "interval is empty");
		}
		const auto span =
			static_cast<std::int32_t>(static_cast<std::uint32_t>(upper) - static_cast<std::uint32_t>(lower) + 1u);
		const float scaled = fa::MultiplyIntegerX87(span, sample);
		const float picked = std::floor(scaled);
		// `fiadd lower` adds the exact integer and rounds once to single.
		lua_pushnumber(state, static_cast<float>(static_cast<double>(picked) + static_cast<double>(lower)));
		return 1;
	}

	/**
	 * The `math` library registration table at 0x00D46278.
	 *
	 * Order is taken from the binary's .rdata, not from stock Lua 5.0: this fork
	 * lists `pow` between `deg` and `rad` rather than after `randomseed`.
	 */
	const luaL_reg kLuaMathLib[] = {
		{"abs", math_abs},          {"sin", math_sin},     {"cos", math_cos},
		{"tan", math_tan},          {"asin", math_asin},   {"acos", math_acos},
		{"atan", math_atan},        {"atan2", math_atan2}, {"ceil", math_ceil},
		{"floor", math_floor},      {"mod", math_mod},     {"frexp", math_frexp},
		{"ldexp", math_ldexp},      {"sqrt", math_sqrt},   {"min", math_min},
		{"max", math_max},          {"log", math_log},     {"log10", math_log10},
		{"exp", math_exp},          {"deg", math_deg},     {"pow", math_pow},
		{"rad", math_rad},          {"random", math_random},
		{"randomseed", math_randomseed},
		{nullptr, nullptr},
	};

	/**
	 * Address: 0x0091A110 (FUN_0091A110, luaopen_math)
	 *
	 * What it does:
	 * Registers the `math` library, then adds two entries the registration table
	 * cannot express: the `pi` constant, and `__pow` installed into the *globals*
	 * table rather than into `math`, which is what makes the `^` operator work.
	 *
	 * The `__pow` write targets pseudo-index -10001 (LUA_GLOBALSINDEX); only the
	 * `pi` write lands on the `math` table left on the stack by luaL_openlib.
	 */
	int LuaOpenMath(lua_State* const state)
	{
		luaL_openlib(state, "math", kLuaMathLib, 0);

		lua_pushlstring(state, "pi", 2u);
		lua_pushnumber(state, 3.1415927410125732f);
		lua_settable(state, -3);

		lua_pushlstring(state, "__pow", 5u);
		lua_pushcclosure(state, math_pow, 0);
		lua_settable(state, LUA_GLOBALSINDEX);
		return 1;
	}

	/**
	 * Address: 0x0090EE20 (FUN_0090EE20, luaB_error)
	 *
	 * What it does:
	 * Raises a Lua error from arg-1 and optionally prefixes source/line
	 * context using arg-2 stack level.
	 */
	int luaB_error(lua_State* const state)
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
	 * Address: 0x0091A3B0 (FUN_0091A3B0, sub_91A3B0)
	 *
	 * What it does:
	 * Pushes the last Win32 error as a Lua string. Falls back to a formatted
	 * numeric message when FormatMessage itself fails, so the caller always ends
	 * up with exactly one string on the stack.
	 */
	void PushLastSystemError(lua_State* const state)
	{
		const DWORD lastError = ::GetLastError();
		CHAR buffer[128];
		if (::FormatMessageA(
				FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, lastError, 0, buffer,
				static_cast<DWORD>(sizeof(buffer)), nullptr
			) != 0) {
			lua_pushstring(state, buffer);
		} else {
			lua_pushfstring(state, "system error %d\n", lastError);
		}
	}

	/**
	 * Address: 0x0091A410 (FUN_0091A410, loadlib)
	 *
	 * What it does:
	 * `loadlib(path, symbol)` - loads a DLL and wraps the named export as a Lua
	 * C closure carrying the module handle as its one upvalue, so the module
	 * stays alive as long as the closure does.
	 *
	 * On failure it returns three values (nil, message, "open"/"init") rather
	 * than raising, and it frees the library when the load succeeded but the
	 * symbol did not resolve.
	 */
	int LuaLoadLib(lua_State* const state)
	{
		const char* const path = luaL_checklstring(state, 1, nullptr);
		const char* const symbol = luaL_checklstring(state, 2, nullptr);

		const HMODULE module = ::LoadLibraryA(path);
		if (module != nullptr) {
			if (auto* const entry =
					reinterpret_cast<lua_CFunction>(::GetProcAddress(module, symbol));
				entry != nullptr) {
				lua_pushlightuserdata(state, module);
				lua_pushcclosure(state, entry, 1);
				return 1;
			}
		}

		lua_pushnil(state);
		PushLastSystemError(state);
		lua_pushstring(state, (module != nullptr) ? "init" : "open");
		if (module != nullptr) {
			::FreeLibrary(module);
		}
		return 3;
	}

	/**
	 * Address: 0x0091A4B0 (FUN_0091A4B0, luaopen_loadlib)
	 *
	 * What it does:
	 * Installs `loadlib` straight into the globals table. Unlike the other
	 * openers there is no library table and no return value - it pushes nothing
	 * and reports zero results.
	 */
	int LuaOpenLoadLib(lua_State* const state)
	{
		lua_pushstring(state, "loadlib");
		lua_pushcclosure(state, LuaLoadLib, 0);
		lua_settable(state, LUA_GLOBALSINDEX);
		return 0;
	}

	/**
	 * Address: 0x0090EEA0 (FUN_0090EEA0, luaB_getmetatable)
	 *
	 * What it does:
	 * Returns arg-1 metatable when present; if protected `__metatable` exists,
	 * returns that field instead.
	 */
	int luaB_getmetatable(lua_State* const state)
	{
		luaL_checkany(state, 1);
		if (lua_getmetatable(state, 1) == 0) {
			lua_pushnil(state);
			return 1;
		}

		(void)luaL_getmetafield(state, 1, "__metatable");
		return 1;
	}

	void getfunc(lua_State* const state)
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
	int luaB_getfenv(lua_State* const state)
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
	int luaB_rawequal(lua_State* const state)
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
	int luaB_rawget(lua_State* const state)
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
	int luaB_rawset(lua_State* const state)
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
	int luaB_gcinfo(lua_State* const state)
	{
		lua_pushnumber(state, static_cast<lua_Number>(lua_getgccount(state)));
		lua_pushnumber(state, static_cast<lua_Number>(lua_getgcthreshold(state)));
		return 2;
	}
