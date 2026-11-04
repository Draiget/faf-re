// Part of LuaObject.cpp, included there: library opening and the auxiliary library (lauxlib).

	/**
	 * Address: 0x0090FC30 (FUN_0090FC30, luaB_costatus)
	 *
	 * IDA signature:
	 * int __cdecl luaB_costatus(lua_State *L);
	 *
	 * What it does:
	 * Reports a coroutine as "running" when it is the calling thread,
	 * "suspended" while it still has a frame or stack to resume into, and
	 * "dead" once it has neither.
	 */
	int luaB_costatus(lua_State* const state)
	{
		lua_State* const coroutine = lua_tothread(state, 1);
		if (coroutine == nullptr) {
			luaL_argerror(state, 1, "coroutine expected");
		}

		if (state == coroutine) {
			lua_pushlstring(state, "running", 7u);
			return 1;
		}

		lua_Debug frame{};
		if (lua_getstack(coroutine, 0, &frame) != 0 || lua_gettop(coroutine) != 0) {
			lua_pushlstring(state, "suspended", 9u);
			return 1;
		}

		lua_pushlstring(state, "dead", 4u);
		return 1;
	}

	/**
	 * Address: 0x0090ECF0 (FUN_0090ECF0, luaB_tonumber)
	 *
	 * IDA signature:
	 * int __cdecl luaB_tonumber(lua_State *L);
	 *
	 * What it does:
	 * Converts argument 1 to a number. Base 10 accepts anything Lua already
	 * considers numeric; any other base parses a string with `strtoul` and
	 * requires the whole remainder to be blank. Returns nil on failure.
	 */
	int luaB_tonumber(lua_State* const state)
	{
		constexpr int kDecimalBase = 10;
		constexpr int kMinBase = 2;
		constexpr int kMaxBase = 36;

		const int base = static_cast<int>(luaL_optnumber(state, 2, static_cast<lua_Number>(kDecimalBase)));

		if (base == kDecimalBase) {
			luaL_checkany(state, 1);
			if (lua_isnumber(state, 1) != 0) {
				lua_pushnumber(state, lua_tonumber(state, 1));
				return 1;
			}
		} else {
			const char* const text = luaL_checklstring(state, 1, nullptr);
			if (base < kMinBase || base > kMaxBase) {
				luaL_argerror(state, 2, "base out of range");
			}

			char* end = nullptr;
			const unsigned long value = std::strtoul(text, &end, base);
			if (text != end) {
				while (std::isspace(static_cast<unsigned char>(*end)) != 0) {
					++end;
				}

				if (*end == '\0') {
					lua_pushnumber(state, static_cast<lua_Number>(value));
					return 1;
				}
			}
		}

		lua_pushnil(state);
		return 1;
	}

	/**
	 * Address: 0x0090F6D0 (FUN_0090F6D0, lua::getpath)
	 *
	 * IDA signature:
	 * const char *__usercall lua::getpath(lua_State *L@<esi>);
	 *
	 * What it does:
	 * Resolves the package search path: the global `LUA_PATH` wins, then the
	 * environment variable of the same name, and failing both a built-in
	 * "current directory" pattern.
	 */
	static const char* getpath(lua_State* const state)
	{
		lua_pushstring(state, "LUA_PATH");
		lua_gettable(state, LUA_GLOBALSINDEX);
		const char* const scriptPath = lua_tostring(state, -1);
		lua_settop(state, -2);

		if (scriptPath != nullptr) {
			return scriptPath;
		}

		const char* const environmentPath = std::getenv("LUA_PATH");
		if (environmentPath == nullptr) {
			return "?;?.lua";
		}

		return environmentPath;
	}

	/**
	 * Address: 0x0090F0A0 (FUN_0090F0A0, luaB_setfenv)
	 *
	 * IDA signature:
	 * int __cdecl luaB_setfenv(lua_State *L);
	 *
	 * What it does:
	 * Installs a new environment table on a function. A `__fenv` key in the
	 * current environment marks it protected and refuses the change. Level 0
	 * targets the running thread's own globals rather than a function.
	 */
	int luaB_setfenv(lua_State* const state)
	{
		luaL_checktype(state, 2, LUA_TTABLE);
		getfunc(state);

		lua_getfenv(state, -1);
		lua_pushlstring(state, "__fenv", 6u);
		lua_rawget(state, -2);
		if (lua_type(state, -1) != LUA_TNIL) {
			luaL_error(state, "`setfenv' cannot change a protected environment");
		}

		lua_settop(state, -3);
		lua_pushvalue(state, 2);

		if (lua_isnumber(state, 1) != 0 && lua_tonumber(state, 1) == 0.0) {
			lua_replace(state, LUA_GLOBALSINDEX);
			return 0;
		}

		if (lua_setfenv(state, -2) == 0) {
			luaL_error(state, "`setfenv' cannot change environment of given function");
		}

		return 0;
	}

	/**
	 * Address: 0x0090FDE0 (FUN_0090FDE0, luaB_tostring)
	 *
	 * IDA signature:
	 * int __cdecl luaB_tostring(lua_State *L);
	 *
	 * What it does:
	 * Renders argument 1 as a string. A `__tostring` metamethod wins outright;
	 * otherwise each tag gets its own form, and userdata is described through
	 * the reflection system - type name, address and lexical value - which is
	 * this fork's departure from stock Lua's bare "userdata: %p".
	 */
	int luaB_tostring(lua_State* const state)
	{
		constexpr std::size_t kRenderBufferSize = 512;

		luaL_checkany(state, 1);
		if (luaL_callmeta(state, 1, "__tostring") != 0) {
			return 1;
		}

		char rendered[kRenderBufferSize];

		switch (lua_type(state, 1)) {
			case LUA_TNIL:
				lua_pushlstring(state, "nil", 3u);
				return 1;
			case LUA_TBOOLEAN:
				lua_pushstring(state, lua_toboolean(state, 1) ? "true" : "false");
				return 1;
			case LUA_TNUMBER:
				lua_pushstring(state, lua_tostring(state, 1));
				return 1;
			case LUA_TSTRING:
				lua_pushvalue(state, 1);
				return 1;
			case LUA_TUPVALUE:
				lua_pushlstring(state, "upval", 5u);
				return 1;
			case LUA_TLIGHTUSERDATA:
				std::sprintf(rendered, "pointer: %p", lua_tolightuserdata(state, 1));
				break;
			case LUA_TTABLE:
				std::sprintf(rendered, "table: %p", lua_topointer(state, 1));
				break;
			case LUA_CFUNCTION:
				std::sprintf(rendered, "cfunction: %p", lua_topointer(state, 1));
				break;
			case LUA_TFUNCTION:
				std::sprintf(rendered, "function: %p", lua_topointer(state, 1));
				break;
			case LUA_TTHREAD:
				std::sprintf(rendered, "thread: %p", static_cast<void*>(lua_tothread(state, 1)));
				break;
			case LUA_TUSERDATA: {
				gpg::RRef reference{};
				GetRRefFromUserdata(&reference, state, 1);
				const msvc8::string lexical = reference.GetLexical();
				std::sprintf(
					rendered,
					"userdata: %.80s at %p = %.80s",
					reference.GetName(),
					reference.mObj,
					lexical.c_str()
				);
				break;
			}
			case LUA_TPROTO: {
				const Proto* const proto = static_cast<const Proto*>(state->base->value.p);
				std::sprintf(rendered, "code: %.200s(%d)", proto->source->str, proto->lineDefined);
				break;
			}
			default:
				rendered[0] = '\0';
				break;
		}

		lua_pushstring(state, rendered);
		return 1;
	}

	/**
	 * Address: 0x0090F7F0 (FUN_0090F7F0, luaB_require)
	 *
	 * IDA signature:
	 * int __cdecl luaB_require(lua_State *L);
	 *
	 * What it does:
	 * Loads a package once. Already-loaded names come straight back out of
	 * `_LOADED`; otherwise each ';'-separated template in the search path is
	 * tried in turn until one loads. The chunk runs with `_REQUIREDNAME` set to
	 * the requested name, and whatever it returns - or `true` if it returns
	 * nothing - is cached under that name.
	 */
	int luaB_require(lua_State* const state)
	{
		constexpr int kFileNotFound = 2;

		int status = kFileNotFound;

		luaL_checklstring(state, 1, nullptr);
		lua_settop(state, 1);
		lua_pushstring(state, "_LOADED");
		lua_gettable(state, LUA_GLOBALSINDEX);
		if (lua_type(state, 2) != LUA_TTABLE) {
			luaL_error(state, "`_LOADED' is not a table");
		}

		const char* path = getpath(state);
		lua_pushvalue(state, 1);
		lua_rawget(state, 2);

		if (!lua_toboolean(state, -1)) {
			while (status == kFileNotFound) {
				lua_settop(state, 3);
				if (*path == '\0') {
					break;
				}

				const char* component = path;
				if (*component == ';') {
					++component;
				}

				const char* end = std::strchr(component, ';');
				if (end == nullptr) {
					end = component + std::strlen(component);
				}

				lua_pushlstring(state, component, static_cast<size_t>(end - component));
				if (end == nullptr) {
					break;
				}

				path = end;
				pushcomposename(state);
				status = luaL_loadfile(state, lua_tostring(state, -1));
			}

			if (status != 0) {
				if (status != kFileNotFound) {
					const char* const reason = lua_tostring(state, -1);
					luaL_error(state, "error loading package `%s' (%s)", lua_tostring(state, 1), reason);
				}

				const char* const searched = getpath(state);
				luaL_error(state, "could not load package `%s' from path `%s'", lua_tostring(state, 1), searched);
			}

			lua_pushstring(state, "_REQUIREDNAME");
			lua_gettable(state, LUA_GLOBALSINDEX);
			lua_insert(state, -2);
			lua_pushvalue(state, 1);
			lua_pushstring(state, "_REQUIREDNAME");
			lua_insert(state, -2);
			lua_settable(state, LUA_GLOBALSINDEX);

			lua_call(state, 0, 1);

			lua_insert(state, -2);
			lua_pushstring(state, "_REQUIREDNAME");
			lua_insert(state, -2);
			lua_settable(state, LUA_GLOBALSINDEX);

			if (lua_type(state, -1) == LUA_TNIL) {
				lua_pushboolean(state, 1);
				lua_replace(state, -2);
			}

			lua_pushvalue(state, 1);
			lua_pushvalue(state, -2);
			lua_rawset(state, 2);
		}

		return 1;
	}

	/**
	 * Address: 0x00D45170 (base_funcs)
	 *
	 * What it does:
	 * The global functions `base_open` registers straight into the globals
	 * table. Read out of the shipped image in this exact order.
	 */
	const luaL_reg base_funcs[]{
		{"error", luaB_error},
		{"getmetatable", luaB_getmetatable},
		{"setmetatable", luaB_setmetatable},
		{"getfenv", luaB_getfenv},
		{"setfenv", luaB_setfenv},
		{"next", luaB_next},
		{"ipairs", luaB_ipairs},
		{"pairs", luaB_pairs},
		{"print", luaB_print},
		{"tonumber", luaB_tonumber},
		{"tostring", luaB_tostring},
		{"type", luaB_type},
		{"assert", luaB_assert},
		{"unpack", luaB_unpack},
		{"rawequal", luaB_rawequal},
		{"rawget", luaB_rawget},
		{"rawset", luaB_rawset},
		{"pcall", luaB_pcall},
		{"collectgarbage", luaB_collectgarbage},
		{"gcinfo", luaB_gcinfo},
		{"loadfile", luaB_loadfile},
		{"dofile", luaB_dofile},
		{"loadstring", luaB_loadstring},
		{"require", luaB_require},
		{nullptr, nullptr},
	};

	/**
	 * Address: 0x00D45238 (co_funcs)
	 *
	 * What it does:
	 * The `coroutine` table's contents.
	 */
	const luaL_reg co_funcs[]{
		{"create", luaB_cocreate},
		{"wrap", luaB_cowrap},
		{"resume", luaB_coresume},
		{"yield", luaB_yield},
		{"status", luaB_costatus},
		{nullptr, nullptr},
	};

	/**
	 * Address: 0x0090FCD0 (FUN_0090FCD0, base_open)
	 *
	 * IDA signature:
	 * void __usercall base_open(lua_State *L@<esi>);
	 *
	 * What it does:
	 * Opens the base library into the globals table itself - `_G` names it,
	 * `_VERSION` records the dialect - and installs `newproxy`, whose upvalue
	 * is a weak-keyed table remembering which proxies it created.
	 */
	static void base_open(lua_State* const state)
	{
		lua_pushlstring(state, "_G", 2u);
		lua_pushvalue(state, LUA_GLOBALSINDEX);
		luaL_openlib(state, nullptr, base_funcs, 0);

		lua_pushlstring(state, "_VERSION", 8u);
		lua_pushlstring(state, "Lua 5.0.1", 9u);
		lua_rawset(state, -3);

		lua_pushlstring(state, "newproxy", 8u);
		lua_newtable(state);
		lua_pushvalue(state, -1);
		lua_setmetatable(state, -2);
		lua_pushlstring(state, "__mode", 6u);
		lua_pushlstring(state, "k", 1u);
		lua_rawset(state, -3);
		lua_pushcclosure(state, luaB_newproxy, 1);
		lua_rawset(state, -3);

		lua_rawset(state, -1);
	}

	/**
	 * Address: 0x0090FD90 (FUN_0090FD90, luaopen_base)
	 *
	 * IDA signature:
	 * int __cdecl luaopen_base(lua_State *L);
	 *
	 * What it does:
	 * Opens the base library and the `coroutine` table, then seeds `_LOADED`.
	 * Note what it does *not* do: the prebuilt LuaPlus asks for a default
	 * metatable here through lua_getdefaultmetatable, a function the shipped
	 * binary does not contain at all - which is why the lib's copy of this
	 * function asserted against our global_State.
	 */
	int luaopen_base(lua_State* const state)
	{
		base_open(state);
		luaL_openlib(state, "coroutine", co_funcs, 0);

		lua_newtable(state);
		lua_pushstring(state, "_LOADED");
		lua_insert(state, -2);
		lua_settable(state, LUA_REGISTRYINDEX);
		return 0;
	}

	// luaV_gettable and the two paths below are mutually recursive: a metatable
	// whose __index is itself a table sends the lookup back around.
	const TObject* luaV_getnotable(lua_State* state, const TObject* t, const TObject* key, int loop);
	const TObject* luaV_index(lua_State* state, const TObject* t, const TObject* key, int loop);

	/**
	 * Address: 0x0090E400 (FUN_0090E400, luaL_buffinit)
	 *
	 * IDA signature:
	 * void __cdecl luaL_buffinit(lua_State *L, luaL_Buffer *B);
	 *
	 * What it does:
	 * Starts an empty string buffer. `lvl` counts the partial strings parked
	 * on the Lua stack, which is how the buffer grows past its fixed array.
	 */
	void luaL_buffinit(lua_State* const state, luaL_Buffer* const buffer)
	{
		buffer->L = state;
		buffer->p = buffer->buffer;
		buffer->lvl = 0;
	}

	/**
	 * Address: 0x0090E260 (FUN_0090E260, luaL_prepbuffer)
	 *
	 * IDA signature:
	 * char *__usercall luaL_prepbuffer(luaL_Buffer *B);
	 *
	 * What it does:
	 * Flushes whatever the array holds onto the Lua stack and hands it back
	 * empty. An already-empty buffer is left alone, so no zero-length string
	 * is pushed.
	 */
	char* luaL_prepbuffer(luaL_Buffer* const buffer)
	{
		if (buffer->p != buffer->buffer) {
			lua_pushlstring(buffer->L, buffer->buffer, static_cast<size_t>(buffer->p - buffer->buffer));
			++buffer->lvl;
			buffer->p = buffer->buffer;
			adjuststack(buffer);
		}

		return buffer->buffer;
	}

	/**
	 * Address: 0x0090E2A0 (FUN_0090E2A0, luaL_addlstring)
	 *
	 * IDA signature:
	 * void __cdecl luaL_addlstring(luaL_Buffer *B, const char *s, size_t l);
	 *
	 * What it does:
	 * Appends `l` bytes, flushing whenever the array fills. The binary tests
	 * and copies one byte at a time rather than in runs, which matters for a
	 * source string that overlaps the buffer.
	 */
	void luaL_addlstring(luaL_Buffer* const buffer, const char* s, size_t l)
	{
		for (; l != 0u; --l, ++s) {
			if (buffer->p >= reinterpret_cast<char*>(buffer + 1) && buffer->p != buffer->buffer) {
				lua_pushlstring(buffer->L, buffer->buffer, static_cast<size_t>(buffer->p - buffer->buffer));
				++buffer->lvl;
				buffer->p = buffer->buffer;
				adjuststack(buffer);
			}

			*buffer->p++ = *s;
		}
	}

	/**
	 * Address: 0x0090E300 (FUN_0090E300, luaL_addstring)
	 *
	 * IDA signature:
	 * void __cdecl luaL_addstring(luaL_Buffer *B, const char *s);
	 *
	 * What it does:
	 * Appends a NUL-terminated string.
	 */
	void luaL_addstring(luaL_Buffer* const buffer, const char* const s)
	{
		luaL_addlstring(buffer, s, std::strlen(s));
	}

	/**
	 * Address: 0x0090E370 (FUN_0090E370, luaL_addvalue)
	 *
	 * IDA signature:
	 * void __cdecl luaL_addvalue(luaL_Buffer *B);
	 *
	 * What it does:
	 * Appends the value on top of the Lua stack. One that fits is copied into
	 * the array; one that does not is left on the stack as its own level, with
	 * any pending array contents pushed underneath it first so the pieces stay
	 * in order.
	 */
	void luaL_addvalue(luaL_Buffer* const buffer)
	{
		lua_State* const state = buffer->L;
		const size_t valueLength = lua_strlen(state, -1);
		const size_t freeSpace = sizeof(buffer->buffer) - static_cast<size_t>(buffer->p - buffer->buffer);

		if (valueLength > freeSpace) {
			if (buffer->p != buffer->buffer) {
				lua_pushlstring(buffer->L, buffer->buffer, static_cast<size_t>(buffer->p - buffer->buffer));
				++buffer->lvl;
				buffer->p = buffer->buffer;
				// Slide the flushed piece below the value being added.
				lua_insert(state, -2);
			}

			++buffer->lvl;
			adjuststack(buffer);
			return;
		}

		// Raw blob append of a Lua string into the growable marshal buffer.
		std::copy_n(lua_tostring(state, -1), valueLength, buffer->p);
		buffer->p += valueLength;
		lua_settop(state, -2);
	}

	/**
	 * Address: 0x0090DC20 (FUN_0090DC20, luaL_findstring)
	 *
	 * IDA signature:
	 * int __cdecl luaL_findstring(const char *name, const char *const *list);
	 *
	 * What it does:
	 * Returns the index of `name` in a NULL-terminated list, or -1.
	 */
	int luaL_findstring(const char* const name, const char* const* const list)
	{
		for (int index = 0; list[index] != nullptr; ++index) {
			if (std::strcmp(list[index], name) == 0) {
				return index;
			}
		}

		return -1;
	}

	/**
	 * Address: 0x0090DC70 (FUN_0090DC70, luaL_newmetatable)
	 *
	 * IDA signature:
	 * int __cdecl luaL_newmetatable(lua_State *L, const char *tname);
	 *
	 * What it does:
	 * Creates a metatable registered under `tname` and leaves it on the stack,
	 * or returns 0 with the existing one if the name is taken. The registry
	 * gets both directions - name to table and table to name - so a userdata's
	 * type can be recovered from its metatable.
	 */
	int luaL_newmetatable(lua_State* const state, const char* const tname)
	{
		lua_pushstring(state, tname);
		lua_rawget(state, LUA_REGISTRYINDEX);
		if (lua_type(state, -1) != LUA_TNIL) {
			return 0;
		}

		lua_settop(state, -2);
		lua_newtable(state);

		lua_pushstring(state, tname);
		lua_pushvalue(state, -2);
		lua_rawset(state, LUA_REGISTRYINDEX);

		lua_pushvalue(state, -1);
		lua_pushstring(state, tname);
		lua_rawset(state, LUA_REGISTRYINDEX);
		return 1;
	}

	/**
	 * Address: 0x0090DDA0 (FUN_0090DDA0, luaL_callmeta)
	 *
	 * IDA signature:
	 * int __cdecl luaL_callmeta(lua_State *L, int obj, const char *event);
	 *
	 * What it does:
	 * Calls a metamethod with the object as its only argument, leaving the one
	 * result. Returns 0 untouched when there is no such metamethod.
	 */
	int luaL_callmeta(lua_State* const state, int obj, const char* const event)
	{
		if (static_cast<unsigned int>(obj) >= 0xFFFFD8F1u || obj == 0) {
			obj += lua_gettop(state) + 1;
		}

		const int found = luaL_getmetafield(state, obj, event);
		if (found == 0) {
			return found;
		}

		lua_pushvalue(state, obj);
		lua_call(state, 1, 1);
		return 1;
	}

	/**
	 * Address: 0x0090E900 (FUN_0090E900, luaL_argerror)
	 *
	 * IDA signature:
	 * int __usercall luaL_argerror(lua_State *L, int narg, const char *extramsg);
	 *
	 * What it does:
	 * Raises a bad-argument error naming the offending position and function.
	 * A method call shifts the numbering, because `self` is argument one - so
	 * a complaint about it is reported as bad self rather than argument 0.
	 */
	int luaL_argerror(lua_State* const state, int narg, const char* const extramsg)
	{
		lua_Debug ar{};
		(void)lua_getstack(state, 0, &ar);
		(void)lua_getinfo(state, "n", &ar);

		if (std::strcmp(ar.namewhat, "method") == 0 && --narg == 0) {
			luaL_error(state, "calling `%s' on bad self (%s)", ar.name, extramsg);
		}

		if (ar.name == nullptr) {
			ar.name = "?";
		}

		return luaL_error(state, "bad argument #%d to `%s' (%s)", narg, ar.name, extramsg);
	}

	/**
	 * Address: 0x0090E9A0 (FUN_0090E9A0, luaL_typerror)
	 *
	 * IDA signature:
	 * int __cdecl luaL_typerror(lua_State *L, int narg, const char *tname);
	 *
	 * What it does:
	 * Raises "expected X, got Y" for an argument of the wrong type.
	 */
	int luaL_typerror(lua_State* const state, const int narg, const char* const tname)
	{
		const char* const actual = lua_typename(state, lua_type(state, narg));
		const char* const message = lua_pushfstring(state, "%s expected, got %s", tname, actual);
		return luaL_argerror(state, narg, message);
	}

	/**
	 * Address: 0x0090E420 (FUN_0090E420, luaL_ref)
	 *
	 * IDA signature:
	 * int __cdecl luaL_ref(lua_State *L, int t);
	 *
	 * What it does:
	 * Stores the value on top of the stack in table `t` and returns an integer
	 * key for it. Slot 1 heads a free list threaded through the table itself,
	 * so released references are reused before the table grows. A nil value
	 * consumes nothing and returns -1.
	 */
	int luaL_ref(lua_State* const state, int t)
	{
		constexpr int kFreeListSlot = 1;
		constexpr int kFirstReference = 3;
		constexpr int kRefNil = -1;

		if (static_cast<unsigned int>(t) >= 0xFFFFD8F1u || t == 0) {
			t += lua_gettop(state) + 1;
		}

		if (lua_type(state, -1) == LUA_TNIL) {
			lua_settop(state, -2);
			return kRefNil;
		}

		lua_rawgeti(state, t, kFreeListSlot);
		const int recycled = static_cast<int>(lua_tonumber(state, -1));
		lua_settop(state, -2);

		if (recycled != 0) {
			// Pop the head of the free list and re-point slot 1 at its successor.
			lua_rawgeti(state, t, recycled);
			lua_rawseti(state, t, kFreeListSlot);
			lua_rawseti(state, t, recycled);
			return recycled;
		}

		int next = luaL_getn(state, t);
		if (next < kFirstReference) {
			next = kFirstReference;
		}

		++next;
		luaL_setn(state, t, next);
		lua_rawseti(state, t, next);
		return next;
	}

	/**
	 * Address: 0x0090E4F0 (FUN_0090E4F0, luaL_unref)
	 *
	 * IDA signature:
	 * void __cdecl luaL_unref(lua_State *L, int t, int ref);
	 *
	 * What it does:
	 * Releases a reference by pushing its slot onto the free list headed at
	 * slot 1. Negative references - LUA_REFNIL and LUA_NOREF - are ignored.
	 */
	void luaL_unref(lua_State* const state, int t, const int ref)
	{
		constexpr int kFreeListSlot = 1;

		if (ref < 0) {
			return;
		}

		if (static_cast<unsigned int>(t) >= 0xFFFFD8F1u || t == 0) {
			t += lua_gettop(state) + 1;
		}

		lua_rawgeti(state, t, kFreeListSlot);
		lua_rawseti(state, t, ref);
		lua_pushnumber(state, static_cast<lua_Number>(ref));
		lua_rawseti(state, t, kFreeListSlot);
	}

	/**
	 * Address: 0x00915190 (FUN_00915190, luaF_getlocalname)
	 *
	 * IDA signature:
	 * const char *__cdecl luaF_getlocalname(const Proto *f, int local_number, int pc);
	 *
	 * What it does:
	 * Names the `local_number`-th local that is live at `pc`. Locals are stored
	 * in the order they come into scope, so the walk stops as soon as one
	 * starts after `pc`.
	 */
	const char* luaF_getlocalname(const Proto* const proto, int local_number, const int pc)
	{
		for (int index = 0; index < proto->sizelocvars; ++index) {
			const LocVar& local = proto->locvars[index];
			if (local.startpc > pc) {
				break;
			}

			if (pc < local.endpc && --local_number == 0) {
				return local.varname->str;
			}
		}

		return nullptr;
	}

	/**
	 * Address: 0x00924300 (FUN_00924300, luaE_newthread)
	 *
	 * IDA signature:
	 * lua_State *__usercall luaE_newthread(lua_State *L);
	 *
	 * What it does:
	 * Creates a coroutine sharing the parent's global state and globals table,
	 * with its own stack. It goes on the secondary GC root list, not the main
	 * one.
	 */
	lua_State* luaE_newthread(lua_State* const state)
	{
		auto* const thread = luaM_new<lua_State>(state);

		thread->next = state->l_G->rootgc1;
		state->l_G->rootgc1 = reinterpret_cast<GCObject*>(thread);
		sweep_boundaries::NoteLinked(state->l_G, sweep_boundaries::kListThreads, reinterpret_cast<GCObject*>(thread)); // engine addition: lua_ParallelSweep

		thread->marked = 0;
		thread->stack = nullptr;
		thread->stacksize = 0;
		thread->openupval = nullptr;
		thread->size_ci = 0;
		thread->nCcalls = 0;
		thread->ci = nullptr;
		thread->base_ci = nullptr;
		thread->stateUserData = nullptr;
		thread->_gt.tt = LUA_TNIL;
		thread->tt = LUA_TTHREAD;
		thread->l_G = state->l_G;

		lua_stack_init(state, thread);
		thread->_gt = state->_gt;
		return thread;
	}

	/**
	 * Address: 0x00924370 (FUN_00924370, luaE_freethread)
	 *
	 * IDA signature:
	 * void __usercall luaE_freethread(lua_State *L, lua_State *L1);
	 *
	 * What it does:
	 * Destroys a coroutine: closes its upvalues, then releases its call-info
	 * array, its stack, and the thread object, all charged to the parent.
	 */
	void luaE_freethread(lua_State* const state, lua_State* const thread)
	{
		// `lstate` names the currently-executing thread and is only ever the
		// main thread or one that is live: `luaV_execute` sets it on entry and
		// puts the previous one back on exit. Collecting the thread it happens
		// to name breaks that, and every later `GetActiveCState()` then hands
		// out a freed `lua_State` whose `top` points into whatever the
		// allocator did with the block - the observed fault was a push through
		// a `top` sitting in the uncommitted tail of a heap segment. The binary
		// does not need this because it cannot reach here with `lstate` stale;
		// dropping back to the main thread restores its invariant.
		global_State* const globalState = state->l_G;
		if (globalState != nullptr && globalState->lstate == thread) {
			globalState->lstate = globalState->mainthread;
		}

		// Engine addition: a coroutine's wrapper (`BindCoroutineState`) has no other owner. A ForkThread
		// state belongs to its task and clears `stateUserData` when it dies.
		if (thread->stateUserData != nullptr) {
			if (thread->stateUserData->m_luaTask == nullptr) {
				delete thread->stateUserData;
				thread->stateUserData = nullptr;
			}
		}

		luaF_close(thread, thread->stack);
		luaM_freearray<CallInfo>(state, thread->base_ci, static_cast<lu_mem>(thread->size_ci));
		luaM_freearray<TObject>(state, thread->stack, static_cast<lu_mem>(thread->stacksize));
		luaM_freelem<lua_State>(state, thread);
	}

	/**
	 * Address: 0x0092BA10 (FUN_0092BA10, luaZ_init)
	 *
	 * IDA signature:
	 * void __cdecl luaZ_init(ZIO *z, lua_Chunkreader reader, void *data, const char *name);
	 *
	 * What it does:
	 * Binds a stream to its reader. The buffer starts empty, so the first read
	 * pulls a block.
	 */
	void luaZ_init(ZIO* const stream, const lua_Chunkreader reader, void* const data, const char* const name)
	{
		stream->reader = reader;
		stream->readerData = data;
		stream->chunkName = name;
		stream->remainingBytes = 0;
		stream->cursor = nullptr;
	}

	/**
	 * Address: 0x0092B970 (FUN_0092B970, luaZ_fill)
	 *
	 * IDA signature:
	 * int __cdecl luaZ_fill(ZIO *z);
	 *
	 * What it does:
	 * Pulls the next block from the reader and returns its first byte, already
	 * consumed. An empty or absent block is end of stream.
	 */
	int luaZ_fill(ZIO* const stream)
	{
		size_t available = 0;
		const char* const block = reinterpret_cast<const char*>(
			stream->reader(nullptr, stream->readerData, &available)
		);

		if (block == nullptr || available == 0u) {
			return kLuaEndOfStream;
		}

		stream->remainingBytes = available - 1u;
		stream->cursor = block + 1;
		return static_cast<unsigned char>(*block);
	}

	/**
	 * Address: 0x0092B9B0 (FUN_0092B9B0, luaZ_lookahead)
	 *
	 * IDA signature:
	 * int __cdecl luaZ_lookahead(ZIO *z);
	 *
	 * What it does:
	 * Peeks the next byte without consuming it. Refilling consumes one, so it
	 * is pushed back - the binary inlines luaZ_fill here and open-codes that
	 * same adjustment.
	 */
	int luaZ_lookahead(ZIO* const stream)
	{
		if (stream->remainingBytes == 0) {
			if (luaZ_fill(stream) == kLuaEndOfStream) {
				return kLuaEndOfStream;
			}

			++stream->remainingBytes;
			--stream->cursor;
		}

		return static_cast<unsigned char>(*stream->cursor);
	}
	/**
	 * Address: 0x0090CE50 (FUN_0090CE50, lua_pushvfstring)
	 *
	 * What it does:
	 * Formats a string onto the Lua stack. The API entry gives the collector a
	 * chance to run first, which the internal luaO_pushvfstring does not.
	 */
	const char* lua_pushvfstring(lua_State* const state, const char* const fmt, va_list argp)
	{
		luaC_checkGC(state);
		return luaO_pushvfstring(state, fmt, argp);
	}

	/**
	 * Address: 0x0090CE90 (FUN_0090CE90, lua_pushfstring)
	 *
	 * What it does:
	 * The varargs form of lua_pushvfstring.
	 */
	const char* lua_pushfstring(lua_State* const state, const char* const fmt, ...)
	{
		va_list argp;
		va_start(argp, fmt);
		luaC_checkGC(state);
		const char* const result = luaO_pushvfstring(state, fmt, argp);
		va_end(argp);
		return result;
	}

	/**
	 * Address: 0x0090CA90 (FUN_0090CA90, lua_tostring)
	 *
	 * IDA signature:
	 * const char *__usercall lua_tostring@<eax>(lua_State *L, int idx);
	 *
	 * What it does:
	 * Reads a stack slot as a string, converting a number in place if that is
	 * what is there. The conversion allocates, so the collector gets a chance
	 * to run before returning - which is also why the returned pointer is only
	 * good until the slot changes.
	 */
	const char* lua_tostring(lua_State* const state, const int idx)
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

		if (object == nullptr) {
			return nullptr;
		}

		if (object->tt == LUA_TSTRING) {
			return static_cast<const TString*>(object->value.p)->str;
		}

		const char* result = nullptr;
		if (luaV_tostring(state, object) != 0) {
			result = static_cast<const TString*>(object->value.p)->str;
		}

		luaC_checkGC(state);
		return result;
	}

	// Defined in LuaParser.cpp, alongside f_parser and SParser.
	int luaD_protectedparser(lua_State* L, ZIO* z, int bin);

	/**
	 * Address: 0x0090D5C0 (FUN_0090D5C0, lua_load)
	 *
	 * IDA signature:
	 * int __cdecl lua_load(lua_State *L, lua_Chunkreader reader, void *data, const char *chunkname);
	 *
	 * What it does:
	 * Compiles a chunk pulled from `reader`. One byte of lookahead decides
	 * whether it is precompiled - a leading ESC marks a binary chunk - so
	 * source and bytecode load through the same entry point.
	 */
	int lua_load(lua_State* const state, const lua_Chunkreader reader, void* const data, const char* chunkname)
	{
		constexpr int kLuaSignatureFirstByte = 0x1B; // ESC, the binary-chunk marker

		if (chunkname == nullptr) {
			chunkname = "?";
		}

		ZIO stream;
		luaZ_init(&stream, reader, data, chunkname);
		const int first = luaZ_lookahead(&stream);
		return luaD_protectedparser(state, &stream, first == kLuaSignatureFirstByte);
	}

	/**
	 * Address: 0x0090D610 (FUN_0090D610, lua_dump)
	 *
	 * IDA signature:
	 * int __cdecl lua_dump(lua_State *L, lua_Chunkwriter writer, void *data);
	 *
	 * What it does:
	 * The other direction from `lua_load`: takes the function on top of the
	 * stack and writes its compiled form out through `writer`. Reports 1 when
	 * it dumped something and 0 when the value on top was not a dumpable
	 * function - it is a boolean, not a status code, so 0 is the failure.
	 *
	 * Two things disqualify a value, and the binary tests them in this order.
	 * `cmp dword ptr [eax], 7` at 0x0090D61A wants a Lua closure: this fork
	 * gives C functions their own tag (`LUA_CFUNCTION`, 6), so the tag check
	 * alone is upstream's whole `isLfunction`, with no `isC` test needed after
	 * it. `cmp byte ptr [eax+8], 0` at 0x0090D622 then wants
	 * `nupvalues == 0`, because a closure that captured anything cannot be
	 * reconstructed from bytecode alone.
	 *
	 * `extern "C"` comes from the enclosing block and is load-bearing, not
	 * decoration: the vendored `lua.h` declares this inside `extern "C"`, so a
	 * C++-mangled definition here would leave every caller's `_lua_dump`
	 * unresolved and let the prebuilt LuaPlus library answer instead - with a
	 * `lua_State` it lays out differently.
	 */
	int lua_dump(lua_State* const state, const lua_Chunkwriter writer, void* const data)
	{
		const TObject* const function = state->top - 1;
		if (function->tt != LUA_TFUNCTION) {
			return 0;
		}

		const Closure* const closure = static_cast<const Closure*>(function->value.p);
		if (closure->l.nupvalues != 0) {
			return 0;
		}

		LuaPlus::luaU_dump(state, closure->l.p, writer, data);
		return 1;
	}

	// One block of a file being loaded. luaL_loadfile keeps this on its own
	// stack and hands it to lua_load as the reader's state.
	struct LuaLoadFileState
	{
		FILE* f;
		char buff[512];
	};

	// The whole of a string being loaded, handed over in one go.
	struct LuaLoadStringState
	{
		const char* s;
		size_t size;
	};

	/**
	 * Address: 0x0090E550 (FUN_0090E550, getWF)
	 *
	 * What it does:
	 * Reader for luaL_loadfile: hands over one buffer's worth at a time.
	 */
	const char* getWF(lua_State* const state, void* const data, size_t* const size)
	{
		(void)state;
		auto* const lf = static_cast<LuaLoadFileState*>(data);
		if (std::feof(lf->f) != 0) {
			return nullptr;
		}

		*size = std::fread(lf->buff, 1u, sizeof(lf->buff), lf->f);
		return (*size > 0u) ? lf->buff : nullptr;
	}

	/**
	 * Address: 0x0090E740 (FUN_0090E740, getS)
	 *
	 * What it does:
	 * Reader for luaL_loadbuffer: the whole string once, then end of stream.
	 */
	const char* getS(lua_State* const state, void* const data, size_t* const size)
	{
		(void)state;
		auto* const ls = static_cast<LuaLoadStringState*>(data);
		if (ls->size == 0u) {
			return nullptr;
		}

		*size = ls->size;
		ls->size = 0u;
		return ls->s;
	}

	/**
	 * Address: 0x0090E590 (FUN_0090E590, errfile)
	 *
	 * IDA signature:
	 * int __usercall errfile@<eax>(int fnameindex@<ebx>, lua_State *L@<edi>);
	 *
	 * What it does:
	 * Replaces the pushed chunk name with "cannot read <file>: <reason>" and
	 * reports it as a file error. The name is skipped past its `@` marker.
	 */
	int errfile(lua_State* const state, const int fnameindex)
	{
		const char* const filename = lua_tostring(state, fnameindex) + 1;
		lua_pushfstring(state, "cannot read %s: %s", filename, std::strerror(errno));
		lua_remove(state, fnameindex);
		return LUA_ERRFILE;
	}

	/**
	 * Address: 0x0090E5D0 (FUN_0090E5D0, luaL_loadfile)
	 *
	 * IDA signature:
	 * int __cdecl luaL_loadfile(lua_State *L, const char *filename);
	 *
	 * What it does:
	 * Loads a chunk from a file, or from stdin when `filename` is null. The
	 * chunk name is pushed first so an error can name the file even if opening
	 * it failed. If the first byte is neither printable nor whitespace the file
	 * is reopened in binary mode, which is how a precompiled chunk survives the
	 * text-mode line-ending translation.
	 */
	int luaL_loadfile(lua_State* const state, const char* const filename)
	{
		const int fnameindex = lua_gettop(state) + 1; // where the chunk name lands

		LuaLoadFileState lf;
		if (filename != nullptr) {
			lua_pushfstring(state, "@%s", filename);
			lf.f = std::fopen(filename, "r");
		} else {
			lua_pushlstring(state, "=stdin", 6u);
			lf.f = stdin;
		}

		if (lf.f == nullptr) {
			return errfile(state, fnameindex);
		}

		const int first = std::getc(lf.f);
		/**
		 * Address: 0x00A868BB (FUN_00A868BB, `ungetc` -- IDA FLIRT-identified
		 * by its real CRT symbol name, not `FUN_`/`sub_` prefixed)
		 * Address: 0x00A8679D (FUN_00A8679D, `_ungetc_nolock`-equivalent
		 * internal body `ungetc` calls into)
		 *
		 * `std::ungetc(first, lf.f)` below compiles to these two out-of-line
		 * MSVC8 CRT stdio bodies. Confirmed against 0x00A8679D's own `.c`:
		 * text-mode `ioinfo`/`_badioinfo` validation via `_fileno`, then
		 * direct `FILE::_flag`/`_base`/`_ptr`/`_cnt` manipulation and
		 * `getbuf`/`_invalid_parameter` calls -- textbook MSVC CRT
		 * `ungetc`/`_ungetc_nolock`, not engine code. Reached from this call
		 * site (the classic `luaL_loadfile` shebang-line peek: read one
		 * byte, push it back, then decide text- vs binary-mode reopen) and
		 * from the `io.read(0)`-style peek at `LuaObject.cpp` ~line 6112.
		 */
		std::ungetc(first, lf.f);
		if (std::isspace(first) == 0 && std::isprint(first) == 0 && lf.f != stdin) {
			std::fclose(lf.f);
			lf.f = std::fopen(filename, "rb");
			if (lf.f == nullptr) {
				return errfile(state, fnameindex);
			}
		}

		const int status =
			lua_load(state, reinterpret_cast<lua_Chunkreader>(getWF), &lf, lua_tostring(state, -1));

		const int readstatus = std::ferror(lf.f);
		if (lf.f != stdin) {
			std::fclose(lf.f);
		}
		if (readstatus != 0) {
			lua_settop(state, fnameindex); // drop whatever the load left behind
			return errfile(state, fnameindex);
		}

		lua_remove(state, fnameindex);
		return status;
	}

	/**
	 * Address: 0x0090E760 (FUN_0090E760, luaL_loadbuffer)
	 *
	 * What it does:
	 * Loads a chunk from memory.
	 */
	int luaL_loadbuffer(
		lua_State* const state,
		const char* const buff,
		const size_t size,
		const char* const name
	)
	{
		LuaLoadStringState ls;
		ls.s = buff;
		ls.size = size;
		return lua_load(state, reinterpret_cast<lua_Chunkreader>(getS), &ls, name);
	}


	/**
	 * Address: 0x0092BA40 (FUN_0092BA40, luaZ_read)
	 *
	 * IDA signature:
	 * size_t __cdecl luaZ_read(ZIO *z, void *b, size_t n);
	 *
	 * What it does:
	 * Copies `n` bytes out of the stream, pulling blocks as needed. Returns 0
	 * on success, or how many bytes were still wanted when the stream ended -
	 * so a non-zero result is a short read, not a count.
	 */
	size_t luaZ_read(ZIO* const stream, void* buffer, size_t n)
	{
		while (n != 0u) {
			if (stream->remainingBytes == 0) {
				if (luaZ_fill(stream) == kLuaEndOfStream) {
					return n;
				}

				++stream->remainingBytes;
				--stream->cursor;
			}

			// Unsigned, as the binary's `cmp ebx, edi` / `ja` at 0x0092BA9D is.
			const size_t chunk = (n <= stream->remainingBytes) ? n : stream->remainingBytes;
			// Byte-stream chunk copy from the reader cursor.
			std::copy_n(static_cast<const char*>(stream->cursor), chunk, static_cast<char*>(buffer));

			stream->remainingBytes -= chunk;
			stream->cursor += chunk;
			buffer = static_cast<char*>(buffer) + chunk;
			n -= chunk;
		}

		return 0u;
	}

	/**
	 * Address: 0x0090DD10 (FUN_0090DD10, luaL_checkstack)
	 *
	 * IDA signature:
	 * void __cdecl luaL_checkstack(lua_State *L, int space, const char *mes);
	 *
	 * What it does:
	 * Reserves stack room or raises "stack overflow", naming what wanted it.
	 */
	void luaL_checkstack(lua_State* const state, const int space, const char* const message)
	{
		if (lua_checkstack(state, space) == 0) {
			luaL_error(state, "stack overflow (%s)", message);
		}
	}

	/**
	 * Address: 0x0090DCF0 (FUN_0090DCF0, luaL_getmetatable)
	 *
	 * IDA signature:
	 * void __cdecl luaL_getmetatable(lua_State *L, const char *tname);
	 *
	 * What it does:
	 * Pushes the registry entry a named metatable was registered under.
	 */
	void luaL_getmetatable(lua_State* const state, const char* const tname)
	{
		lua_pushstring(state, tname);
		lua_rawget(state, LUA_REGISTRYINDEX);
	}

	/**
	 * Address: 0x00914EF0 (FUN_00914EF0, luaF_newLclosure)
	 *
	 * IDA signature:
	 * Closure *__usercall luaF_newLclosure(lua_State *L, int nelems, TObject *e);
	 *
	 * What it does:
	 * Allocates a Lua closure sized for `nelems` upvalues, links it for
	 * collection, and captures the environment it was created in. The
	 * prototype and the upvalue array are filled in by the caller.
	 */
	Closure* luaF_newLclosure(lua_State* const state, const int nelems, const TObject* const environment)
	{
		auto* const closure = static_cast<Closure*>(luaM_reallocblock(state, nullptr, {0u, 0u}, sizeLclosure(nelems)));

		luaC_link(state, reinterpret_cast<GCObject*>(closure), LUA_TFUNCTION);

		closure->l.g = *environment;
		closure->l.nupvalues = static_cast<lu_byte>(nelems);
		return closure;
	}
