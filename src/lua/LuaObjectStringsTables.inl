// Part of LuaObject.cpp, included there: interned strings, pattern helpers and tables (lstring, ltable).

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
	/// Captures one pattern may hold open at once (upstream `MAXCAPTURES`).
	/// `start_capture` raises "too many captures" on the 33rd.
	constexpr int MAXCAPTURES = 32;

	/// A capture that has been opened by `(` but not yet closed by `)`.
	constexpr int CAP_UNFINISHED = -1;

	/// A position capture, `()`, which yields an index rather than a slice.
	constexpr int CAP_POSITION = -2;

	/// The pattern matcher's working state, threaded through every `match*`
	/// helper below - upstream's `MatchState` from lstrlib.c.
	struct MatchState
	{
		/// Where one capture began, and how long it is - or one of the two
		/// sentinels above, which is why `len` is signed.
		struct Capture
		{
			const char* init; // +0x00
			int len;          // +0x04
		};

		const char* srcInit;            // +0x00 start of the subject string
		const char* srcEnd;             // +0x04 its terminating NUL
		lua_State* state;               // +0x08
		int level;                      // +0x0C captures open or finished
		Capture captures[MAXCAPTURES];  // +0x10
	};
	static_assert(offsetof(MatchState::Capture, init) == 0x0, "MatchState::Capture::init offset must be 0x0");
	static_assert(offsetof(MatchState::Capture, len) == 0x4, "MatchState::Capture::len offset must be 0x4");
	static_assert(sizeof(MatchState::Capture) == 0x8, "MatchState::Capture size must be 0x8");
	static_assert(offsetof(MatchState, srcInit) == 0x0, "MatchState::srcInit offset must be 0x0");
	static_assert(offsetof(MatchState, srcEnd) == 0x4, "MatchState::srcEnd offset must be 0x4");
	static_assert(offsetof(MatchState, state) == 0x8, "MatchState::state offset must be 0x8");
	static_assert(offsetof(MatchState, level) == 0xC, "MatchState::level offset must be 0xC");
	static_assert(offsetof(MatchState, captures) == 0x10, "MatchState::captures offset must be 0x10");
	static_assert(sizeof(MatchState) == 0x110, "MatchState size must be 0x110");

	[[nodiscard]] const char* luaI_classend(const char* p, MatchState* ms);
	[[nodiscard]] int match_class(int c1, int cl1);
	[[nodiscard]] int matchbracketclass(const char* p, int c, const char* ec);
	[[nodiscard]] int luaI_singlematch(int c, const char* p, const char* ep);
	[[nodiscard]] const char* matchbalance(const char* p, const char* s, MatchState* ms);
	[[nodiscard]] const char* match_capture(int l, MatchState* ms, const char* s);
	[[nodiscard]] const char* max_expand(MatchState* ms, const char* s, const char* p, const char* ep);
	[[nodiscard]] const char* min_expand(const char* s, MatchState* ms, const char* p, const char* ep);
	[[nodiscard]] const char* start_capture(const char* s, MatchState* ms, const char* p, int what);
	[[nodiscard]] const char* end_capture(const char* s, MatchState* ms, const char* p);
	[[nodiscard]] const char* match(MatchState* ms, const char* s, const char* p);

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

	void push_onecapture(const int captureIndex, MatchState* const matchState)
	{
		MatchState::Capture& capture = matchState->captures[captureIndex];
		const int captureLength = capture.len;
		if (captureLength == CAP_UNFINISHED) {
			luaL_error(matchState->state, "unfinished capture");
			return;
		}

		if (captureLength == CAP_POSITION) {
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
	[[nodiscard]] int push_captures(const char* const sourceStart, const char* const sourceEnd, MatchState* const ms)
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
	[[nodiscard]] const char* luaI_classend(const char* p, MatchState* const ms)
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
	[[nodiscard]] const char* matchbalance(const char* p, const char* s, MatchState* const ms)
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
		MatchState* const ms,
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
		MatchState* const ms,
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
	[[nodiscard]] const char* match_capture(const int l, MatchState* const ms, const char* const s)
	{
		const int captureIndex = l - '1';
		if (captureIndex < 0 || captureIndex >= ms->level || ms->captures[captureIndex].len == CAP_UNFINISHED) {
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
		MatchState* const ms,
		const char* p,
		const int what
	)
	{
		const int level = ms->level;
		if (level >= MAXCAPTURES) {
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
	[[nodiscard]] const char* end_capture(const char* s, MatchState* const ms, const char* p)
	{
		int level = ms->level - 1;
		if (level < 0) {
			luaL_error(ms->state, "invalid pattern capture");
			return nullptr;
		}

		while (ms->captures[level].len != CAP_UNFINISHED) {
			--level;
			if (level < 0) {
				luaL_error(ms->state, "invalid pattern capture");
				return nullptr;
			}
		}

		ms->captures[level].len = static_cast<int>(s - ms->captures[level].init);
		const char* const result = match(ms, s, p);
		if (result == nullptr) {
			ms->captures[level].len = CAP_UNFINISHED;
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
	[[nodiscard]] const char* match(MatchState* const ms, const char* s, const char* p)
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
			const std::uint32_t raw = ValuePointerBits(key->value);
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
			const std::uint32_t raw = ValuePointerBits(key->value);
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
		for (;;) {
			const TObject nodeKey = node->Key();
			if (luaO_rawequalObj(&nodeKey, key) != 0) {
				break;
			}
			node = node->Next();
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
		while (!node->KeyIs(LUA_TNUMBER) || node->KeyValue().n != floatKey) {
			node = node->Next();
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
		while (!node->KeyIs(LUA_TSTRING) || static_cast<TString*>(node->KeyValue().p) != key) {
			node = node->Next();
			if (node == nullptr) {
				return &luaO_nilobject;
			}
		}

		return &node->i_val;
	}

	/**
	 * Address: 0x00928420 (FUN_00928420, luaT_gettm)
	 *
	 * IDA signature:
	 * const TObject *__cdecl luaT_gettm(Table *events, char event, TString *ename);
	 *
	 * What it does:
	 * Fetches one tag method from a metatable by name. On a miss it records the
	 * absence in the metatable's `flags` cache - setting bit `event` so later
	 * lookups for the same event can skip the table entirely - and returns null
	 * rather than the shared nil object, which is what lets callers distinguish
	 * "no such tag method" from "a tag method whose value is nil".
	 */
	const TObject* luaT_gettm(Table* const events, const int event, TString* const ename)
	{
		const TObject* const tagMethod = luaH_getstr(events, ename);
		if (tagMethod->tt == LUA_TNIL) {
			events->flags |= static_cast<int8_t>(1 << event);
			return nullptr;
		}

		return tagMethod;
	}

	/**
	 * Address: 0x00928450 (FUN_00928450, luaT_gettmbyobj)
	 *
	 * IDA signature:
	 * const TObject *__cdecl luaT_gettmbyobj(lua_State *L, const TObject *o, int event);
	 *
	 * What it does:
	 * Resolves one tag method for an arbitrary value. Tables and userdata each
	 * carry their own metatable, so the event name is looked up there. Every
	 * other tag shares the per-type default metatable this fork keeps in
	 * `global_State::_defaultmetatypes` - unlike stock Lua 5.0, which returns
	 * the nil sentinel for those tags - so the slot is handed back directly and
	 * the caller sees nil only when no default has been installed for the type.
	 */
	const TObject* luaT_gettmbyobj(lua_State* const state, const TObject* const object, const int event)
	{
		global_State* const globalState = state->l_G;
		TString* const eventName = globalState->tmname[event];

		switch (object->tt) {
			case LUA_TTABLE:
				return luaH_getstr(static_cast<Table*>(object->value.p)->metatable, eventName);
			case LUA_TUSERDATA:
				return luaH_getstr(static_cast<Udata*>(object->value.p)->metatable, eventName);
			default:
				return &globalState->_defaultmetatypes[object->tt];
		}
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
			const int integerKey = fa::TruncateToInt(numericKey); // the binary's cvttss2si
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
			const int integerKey = fa::TruncateToInt(numericKey); // the binary's cvttss2si
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

		const auto nodeBase = reinterpret_cast<std::uintptr_t>(static_cast<Node*>(table->node));
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

		key[0] = nodeBase[nodeIndex].Key();
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

		TObject nodeKey = nodeBase[nodeIndex].Key();
		key->AssignTObject(state, &nodeKey);
		value->AssignTObject(state, &nodeBase[nodeIndex].i_val);
		return 1;
	}
