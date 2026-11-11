// Part of LuaObject.cpp, included there: the string library (lstrlib).

/**
 * Address: 0x00924E20 (FUN_00924E20, str_rep)
 *
 * What it does:
 * Repeats arg-1 string arg-2 times and pushes the concatenated result.
 */
int str_rep(
  lua_State* const state
)
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
 *
 * Signature is `lua_Chunkwriter`'s, which is how `str_dump` hands it to
 * `lua_dump`; the sink arrives as the opaque user-data lane.
 */
int writer(
  lua_State* const,
  const void* const chunk,
  const size_t chunkSize,
  void* const sink
)
{
  luaL_addlstring(static_cast<luaL_Buffer*>(sink), static_cast<const char*>(chunk), chunkSize);
  return 1;
}

/**
 * Address: 0x00924EA0 (FUN_00924EA0, str_byte)
 *
 * What it does:
 * Returns one byte value from arg-1 at optional arg-2 position, honoring
 * Lua's negative-index adjustment and out-of-range empty-result behavior.
 */
int str_byte(
  lua_State* const state
)
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
int str_find(
  lua_State* const state
)
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
  MatchState matchState{};
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
int gfind_aux(
  lua_State* const state
)
{
  const char* const sourceText = lua_tostring(state, lua_upvalueindex(1));
  const size_t sourceLength = lua_strlen(state, lua_upvalueindex(1));
  const char* const pattern = lua_tostring(state, lua_upvalueindex(2));

  MatchState matchState{};
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
int gfind(
  lua_State* const state
)
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
void add_s(
  MatchState* const matchState,
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
        const unsigned char replacementChar = static_cast<unsigned char>(replacement[++replacementIndex]);
        if (std::isdigit(replacementChar) != 0) {
          const int captureIndex = static_cast<int>(replacement[replacementIndex] - '1');
          if (
            captureIndex < 0 || captureIndex >= matchState->level ||
            matchState->captures[captureIndex].len == CAP_UNFINISHED
          ) {
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
 * Address: 0x00925FA0 (FUN_00925FA0, str_gsub)
 *
 * IDA signature:
 * int __cdecl str_gsub(lua_State *L);
 *
 * What it does:
 * Replaces up to `n` matches of a pattern in the subject, driving `add_s`
 * for each one, and returns the rebuilt string plus the substitution count.
 *
 * The arg-3 check is the one that surfaces as
 * "bad argument #3 to `gsub' (string or function expected)": it accepts a
 * string, or a value whose tag `(t | 1)` is LUA_TFUNCTION - this fork keeps
 * C and Lua functions on adjacent tags 6 and 7, so that single test covers
 * both.
 */
int str_gsub(
  lua_State* const state
)
{
  size_t sourceLength = 0u;
  const char* sourceCursor = luaL_checklstring(state, 1, &sourceLength);
  const char* pattern = luaL_checklstring(state, 2, nullptr);

  const int maxSubstitutions = static_cast<int>(luaL_optnumber(state, 4, static_cast<lua_Number>(sourceLength + 1u)));

  int anchor = 0;
  if (*pattern == '^') {
    ++pattern;
    anchor = 1;
  }

  int substitutionCount = 0;
  if (lua_gettop(state) < 3 || (lua_isstring(state, 3) == 0 && (lua_type(state, 3) | 1) != LUA_TFUNCTION)) {
    luaL_argerror(state, 3, "string or function expected");
  }

  luaL_Buffer buffer{};
  luaL_buffinit(state, &buffer);

  MatchState matchState{};
  matchState.state = state;
  matchState.srcInit = sourceCursor;
  matchState.srcEnd = sourceCursor + sourceLength;

  if (maxSubstitutions > 0) {
    do {
      matchState.level = 0;
      const char* const matchEnd = match(&matchState, sourceCursor, pattern);
      if (matchEnd != nullptr) {
        ++substitutionCount;
        add_s(&matchState, &buffer, sourceCursor, matchEnd);
      }

      if (matchEnd != nullptr && matchEnd > sourceCursor) {
        sourceCursor = matchEnd;
      } else {
        // An empty match, or none: copy one byte across and step
        // past it, so the scan cannot stall on a zero-width hit.
        if (sourceCursor >= matchState.srcEnd) {
          break;
        }

        if (buffer.p >= reinterpret_cast<char*>(&buffer + 1)) {
          luaL_prepbuffer(&buffer);
        }

        *buffer.p++ = *sourceCursor++;
      }
    } while (anchor == 0 && substitutionCount < maxSubstitutions);
  }

  luaL_addlstring(&buffer, sourceCursor, static_cast<size_t>(matchState.srcEnd - sourceCursor));
  luaL_pushresult(&buffer);
  lua_pushnumber(state, static_cast<lua_Number>(substitutionCount));
  return 2;
}

/**
 * Address: 0x00924F10 (FUN_00924F10, str_char)
 *
 * IDA signature:
 * int __cdecl str_char(lua_State *L);
 *
 * What it does:
 * Builds a string from its numeric arguments, one byte each, rejecting any
 * value that does not survive a round trip through `unsigned char`.
 */
int str_char(
  lua_State* const state
)
{
  const int argumentCount = lua_gettop(state);

  luaL_Buffer buffer{};
  luaL_buffinit(state, &buffer);

  for (int argumentIndex = 1; argumentIndex <= argumentCount; ++argumentIndex) {
    const int value = static_cast<int>(luaL_checknumber(state, argumentIndex));
    if (static_cast<int>(static_cast<unsigned char>(value)) != value) {
      luaL_argerror(state, argumentIndex, "invalid value");
    }

    if (buffer.p >= reinterpret_cast<char*>(&buffer + 1)) {
      luaL_prepbuffer(&buffer);
    }

    *buffer.p++ = static_cast<char>(value);
  }

  luaL_pushresult(&buffer);
  return 1;
}

/**
 * Address: 0x00924FD0 (FUN_00924FD0, str_dump)
 *
 * IDA signature:
 * int __cdecl str_dump(lua_State *L);
 *
 * What it does:
 * Serializes a Lua function to a bytecode string by driving `lua_dump`
 * through `writer`, which appends each chunk into the buffer.
 */
int str_dump(
  lua_State* const state
)
{
  luaL_checktype(state, 1, LUA_TFUNCTION);

  luaL_Buffer buffer{};
  luaL_buffinit(state, &buffer);
  if (lua_dump(state, writer, &buffer) == 0) {
    luaL_error(state, "unable to dump given function");
  }

  luaL_pushresult(&buffer);
  return 1;
}

/**
 * Address: 0x009262C0 (FUN_009262C0, luaI_addquotedbinary)
 *
 * IDA signature:
 * void __usercall luaI_addquotedbinary(lua_State *L@<edx>, int arg@<ecx>,
 *                                      luaL_Buffer *b@<esi>);
 *
 * What it does:
 * The `%Q` quoter - this engine's addition next to stock `%q`. Where `%q`
 * emits `\000`-style decimal escapes and passes every other byte through,
 * this one uses the named C escapes for the seven control characters that
 * have them and `\xNN` for anything else `isprint` rejects, so the result
 * survives a round trip through a byte-exact source reader.
 */
void luaI_addquotedbinary(
  lua_State* const state,
  const int argumentIndex,
  luaL_Buffer* const buffer
)
{
  char* const bufferEnd = reinterpret_cast<char*>(&buffer[1]);
  size_t remainingLength = 0u;
  const char* source = luaL_checklstring(state, argumentIndex, &remainingLength);

  if (buffer->p >= bufferEnd) {
    luaL_prepbuffer(buffer);
  }

  *buffer->p++ = '"';

  // Emits one backslash plus `escaped`, prepping the buffer before each
  // byte exactly as the binary does - the two-step check is what keeps a
  // pair from straddling a buffer boundary.
  const auto addEscapePair = [buffer, bufferEnd](const char escaped) {
    if (buffer->p >= bufferEnd) {
      luaL_prepbuffer(buffer);
    }

    *buffer->p++ = '\\';
    if (buffer->p >= bufferEnd) {
      luaL_prepbuffer(buffer);
    }

    *buffer->p++ = escaped;
  };

  for (; remainingLength != 0u; ++source) {
    --remainingLength;

    switch (*source) {
    case '\a':
      addEscapePair('a');
      break;
    case '\b':
      addEscapePair('b');
      break;
    case '\t':
      addEscapePair('t');
      break;
    case '\n':
      addEscapePair('n');
      break;
    case '\v':
      addEscapePair('v');
      break;
    case '\f':
      addEscapePair('f');
      break;
    case '\r':
      addEscapePair('r');
      break;

    case '"':
    case '\\':
      addEscapePair(*source);
      break;

    default:
      if (std::isprint(static_cast<unsigned char>(*source)) != 0) {
        if (buffer->p >= bufferEnd) {
          luaL_prepbuffer(buffer);
        }

        *buffer->p++ = *source;
      } else {
        char hexEscape[12]{};
        std::sprintf(hexEscape, "\\x%02x", static_cast<unsigned char>(*source));
        luaL_addstring(buffer, hexEscape);
      }
      break;
    }
  }

  if (buffer->p >= bufferEnd) {
    luaL_prepbuffer(buffer);
  }

  *buffer->p++ = '"';
}

/// Longest `%`-directive this build will assemble, including the leading
/// `%` and the trailing NUL: `scanformat`'s own bound at 0x009265F9.
constexpr int kMaxFormatSpecifier = 20;

/// Largest single formatted item `str_format_helper` will `sprintf`, taken
/// from its 0x200-byte scratch buffer at 0x00926690.
constexpr int kMaxFormatItem = 512;

/**
 * Address: 0x00926590 (FUN_00926590, scanformat)
 *
 * IDA signature:
 * const char *__usercall scanformat@<eax>(const char *strfrmt@<ebx>,
 *     lua_State *L, char *form, int *hasprecision);
 *
 * What it does:
 * Consumes one `%`-directive's flags, width and precision, copies them into
 * `form` with the `%` restored, and returns the cursor left on the
 * conversion character. Width and precision are capped at two digits each,
 * which is what makes the total fit `kMaxFormatSpecifier`.
 */
const char* scanformat(
  const char* const specifier,
  lua_State* const state,
  char* const form,
  int* const hasPrecision
)
{
  static constexpr const char* kFormatFlags = "-+ #0";

  const char* cursor = specifier;
  if (std::strchr(kFormatFlags, *cursor) != nullptr) {
    do {
      ++cursor;
    } while (std::strchr(kFormatFlags, *cursor) != nullptr);
  }

  if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
    ++cursor;
  }

  if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
    ++cursor;
  }

  if (*cursor == '.') {
    ++cursor;
    *hasPrecision = 1;
    if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
      ++cursor;
    }

    if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
      ++cursor;
    }
  }

  if (std::isdigit(static_cast<unsigned char>(*cursor)) != 0) {
    luaL_error(state, "invalid format (width or precision too long)");
  }

  const int scannedLength = static_cast<int>(cursor - specifier);
  if (scannedLength + 2 > kMaxFormatSpecifier) {
    luaL_error(state, "invalid format (too long)");
  }

  form[0] = '%';
  std::strncpy(form + 1, specifier, static_cast<size_t>(scannedLength) + 1u);
  form[scannedLength + 2] = '\0';
  return cursor;
}

/**
 * Address: 0x00926690 (FUN_00926690, str_format_helper)
 *
 * IDA signature:
 * int __cdecl str_format_helper(luaL_Buffer *b, lua_State *L, int arg);
 *
 * What it does:
 * The body of `string.format`, split out so callers can supply their own
 * buffer and first-argument index.
 *
 * Beyond stock Lua 5.0 this build adds two conversions:
 *   - `%Q`, the binary-safe quoter above, and
 *   - `%b<T>`, which appends the argument as raw little-endian bytes with
 *     `T` picking the width: `F` double (8), `f` float (4), `d` int32 (4),
 *     `w` int16 (2), `b` byte (1). An unrecognized `T` appends nothing.
 *     The pack path writes into the scratch buffer and then clears its
 *     first byte, so the shared `strlen`-based tail contributes nothing on
 *     top of the exact-width append it already made.
 */
int str_format_helper(
  luaL_Buffer* const buffer,
  lua_State* const state,
  int argumentIndex
)
{
  size_t specifierLength = 0u;
  const char* specifier = luaL_checklstring(state, argumentIndex, &specifierLength);
  const char* const specifierEnd = specifier + specifierLength;

  luaL_buffinit(state, buffer);
  while (specifier < specifierEnd) {
    if (*specifier != '%') {
      if (buffer->p >= reinterpret_cast<char*>(&buffer[1])) {
        luaL_prepbuffer(buffer);
      }

      *buffer->p++ = *specifier++;
      continue;
    }

    ++specifier;
    if (*specifier == '%') {
      if (buffer->p >= reinterpret_cast<char*>(&buffer[1])) {
        luaL_prepbuffer(buffer);
      }

      *buffer->p++ = *specifier++;
      continue;
    }

    int hasPrecision = 0;
    if (std::isdigit(static_cast<unsigned char>(*specifier)) != 0 && specifier[1] == '$') {
      luaL_error(state, "obsolete option (d$) to `format'");
    }

    ++argumentIndex;

    char form[kMaxFormatSpecifier]{};
    char item[kMaxFormatItem]{};
    specifier = scanformat(specifier, state, form, &hasPrecision);

    const char conversion = *specifier++;
    switch (conversion) {
    case 'c':
    case 'd':
    case 'i':
      std::sprintf(item, form, static_cast<int>(luaL_checknumber(state, argumentIndex)));
      break;

    case 'o':
    case 'u':
    case 'x':
    case 'X':
      std::sprintf(
        item, form, static_cast<unsigned int>(static_cast<std::int64_t>(luaL_checknumber(state, argumentIndex)))
      );
      break;

    case 'e':
    case 'E':
    case 'f':
    case 'g':
    case 'G':
      // Plan WPL.17: the Windows CRT's NaN text (LuaNumberText.h).
      (void)lua::FormatNumberLikeWindowsCrt(item, form, static_cast<double>(luaL_checknumber(state, argumentIndex)));
      break;

    case 'q':
      luaI_addquoted(state, argumentIndex, buffer);
      continue;

    case 'Q':
      luaI_addquotedbinary(state, argumentIndex, buffer);
      continue;

    case 'b': {
      // The pack scratch: eight bytes cleared up front, the widest
      // operand written over them, then item[0] zeroed by the shared
      // tail so `strlen` adds nothing more.
      std::memset(item + 1, 0, 8u);

      const char packWidth = *specifier++;
      // Pack lanes: scalar bits written into the byte scratch item for
      // luaL_addlstring — raw buffer IO by design.
      switch (packWidth) {
      case 'F': {
        const double packed = static_cast<double>(luaL_checknumber(state, argumentIndex));
        // Pack lane: scalar bits written into the byte scratch item for luaL_addlstring.
        std::memcpy(item, &packed, sizeof(packed));
        luaL_addlstring(buffer, item, sizeof(packed));
        break;
      }

      case 'f': {
        const float packed = static_cast<float>(luaL_checknumber(state, argumentIndex));
        // Pack lane: scalar bits written into the byte scratch item for luaL_addlstring.
        std::memcpy(item, &packed, sizeof(packed));
        luaL_addlstring(buffer, item, sizeof(packed));
        break;
      }

      case 'd': {
        const std::int32_t packed =
          static_cast<std::int32_t>(static_cast<std::int64_t>(luaL_checknumber(state, argumentIndex)));
        // Pack lane: scalar bits written into the byte scratch item for luaL_addlstring.
        std::memcpy(item, &packed, sizeof(packed));
        luaL_addlstring(buffer, item, sizeof(packed));
        break;
      }

      case 'w': {
        const std::int16_t packed = static_cast<std::int16_t>(static_cast<int>(luaL_checknumber(state, argumentIndex)));
        // Pack lane: scalar bits written into the byte scratch item for luaL_addlstring.
        std::memcpy(item, &packed, sizeof(packed));
        luaL_addlstring(buffer, item, sizeof(packed));
        break;
      }

      case 'b': {
        const char packed = static_cast<char>(static_cast<int>(luaL_checknumber(state, argumentIndex)));
        item[0] = packed;
        luaL_addlstring(buffer, item, 1u);
        break;
      }

      default:
        break;
      }

      item[0] = '\0';
      break;
    }

    case 's': {
      size_t textLength = 0u;
      const char* const text = luaL_checklstring(state, argumentIndex, &textLength);
      if (hasPrecision == 0 && textLength >= 100u) {
        // Too long to survive the scratch buffer, and with no
        // precision to trim it there is nothing to format: push the
        // value itself instead.
        lua_pushvalue(state, argumentIndex);
        luaL_addvalue(buffer);
        continue;
      }

      std::sprintf(item, form, text);
      break;
    }

    default:
      luaL_error(state, "invalid option to `format'");
      return 0;
    }

    luaL_addlstring(buffer, item, std::strlen(item));
  }

  return 1;
}

/**
 * Address: 0x00926EB0 (FUN_00926EB0, str_format)
 *
 * IDA signature:
 * int __cdecl str_format(lua_State *L);
 *
 * What it does:
 * `string.format`: runs the shared helper over a local buffer starting at
 * argument 1 and pushes the result.
 */
int str_format(
  lua_State* const state
)
{
  luaL_Buffer buffer{};
  const int status = str_format_helper(&buffer, state, 1);
  if (status == 0) {
    return status;
  }

  luaL_pushresult(&buffer);
  return 1;
}

/**
 * Address: 0x00926AE0 (FUN_00926AE0, str_lualex)
 *
 * IDA signature:
 * int __cdecl str_lualex(lua_State *L);
 *
 * What it does:
 * `string.lualex`, this engine's own entry: resolves the backslash escapes
 * a Lua source lexer would, so a string that arrived with its escapes still
 * literal (from a data file, say) can be turned into the bytes it denotes.
 *
 * Two deviations from the lexer it imitates are the binary's, kept as-is:
 *   - `\xNN` appends *two* bytes, the accumulator's low byte and its second
 *     byte, rather than the one byte a lexer would emit; and
 *   - the hex digits are accumulated from the *start of the subject*
 *     (index 0) instead of from just past the `x`, so the value only comes
 *     out right for an escape at the very beginning of the string.
 * Both are reproduced deliberately - see the reconstruction note.
 */
int str_lualex(
  lua_State* const state
)
{
  size_t sourceLength = 0u;
  const char* const source = luaL_checklstring(state, 1, &sourceLength);

  luaL_Buffer buffer{};
  luaL_buffinit(state, &buffer);

  char* const bufferEnd = reinterpret_cast<char*>(&buffer + 1);
  const auto prepIfFull = [&buffer, bufferEnd]() {
    if (buffer.p >= bufferEnd) {
      luaL_prepbuffer(&buffer);
    }
  };

  for (size_t index = 0u; index < sourceLength; ++index) {
    if (source[index] != '\\') {
      prepIfFull();
      *buffer.p++ = source[index];
      continue;
    }

    switch (source[++index]) {
    case 'a':
      prepIfFull();
      *buffer.p++ = '\a';
      break;
    case 'b':
      prepIfFull();
      *buffer.p++ = '\b';
      break;
    case 'f':
      prepIfFull();
      *buffer.p++ = '\f';
      break;
    case 'n':
      prepIfFull();
      *buffer.p++ = '\n';
      break;
    case 'r':
      prepIfFull();
      *buffer.p++ = '\r';
      break;
    case 't':
      prepIfFull();
      *buffer.p++ = '\t';
      break;
    case 'v':
      prepIfFull();
      *buffer.p++ = '\v';
      break;

    case 'x': {
      const int firstHex = std::tolower(static_cast<unsigned char>(source[++index]));
      if (std::isdigit(firstHex) == 0 && (firstHex < 'a' || firstHex > 'f')) {
        // Not an escape after all: back up and pass the `x` through.
        --index;
        prepIfFull();
        *buffer.p++ = 'x';
        break;
      }

      int hexValue = 0;
      int hexCursor = 0;
      int lookahead = 0;
      do {
        const int digit = std::tolower(static_cast<unsigned char>(source[hexCursor]));
        if (std::isdigit(digit) != 0) {
          hexValue = 16 * hexValue + (digit - '0');
        } else if (static_cast<unsigned int>(digit - 'a') <= 5u) {
          hexValue = 16 * hexValue + (digit - 'a' + 10);
        }

        lookahead = std::tolower(static_cast<unsigned char>(source[hexCursor + 1]));
        hexCursor += 2;
      } while ((hexCursor < 2 && std::isdigit(lookahead) != 0) || (lookahead >= 'a' && lookahead <= 'f'));

      prepIfFull();
      *buffer.p++ = static_cast<char>(hexValue);
      prepIfFull();
      *buffer.p++ = static_cast<char>(hexValue >> 8);
      break;
    }

    default:
      if (std::isdigit(static_cast<unsigned char>(source[index])) != 0) {
        int decimalValue = 0;
        int digitCount = 0;
        do {
          decimalValue = 10 * decimalValue + (source[index] - '0');
          ++digitCount;
          ++index;
        } while (digitCount < 3 && std::isdigit(static_cast<unsigned char>(source[index])) != 0);

        prepIfFull();
        *buffer.p++ = static_cast<char>(decimalValue);
      } else {
        prepIfFull();
        *buffer.p++ = source[index];
      }
      break;
    }
  }

  luaL_pushresult(&buffer);
  return 1;
}

/**
 * Address: 0x00D47158 (`strlib` registration table)
 *
 * What it does:
 * The `lstrlib` registration table, read out of the image at 0x00D47158:
 * thirteen entries whose name pointers run down through 0x00D47150 and
 * whose function lanes are the addresses recovered above, terminated by the
 * null row at 0x00D471C0.
 *
 * Twelve are stock Lua 5.0; `lualex` is this engine's, and sits last.
 * `gmatch` is absent, as it should be for 5.0.
 *
 * This table is the source-level invocation for every function in it -
 * `luaopen_string` hands it to `luaL_openlib`, which installs them by
 * address.
 */
const luaL_reg kLuaStringLibrary[] = {
  {"len", &str_len},
  {"sub", &str_sub},
  {"lower", &str_lower},
  {"upper", &str_upper},
  {"char", &str_char},
  {"rep", &str_rep},
  {"byte", &str_byte},
  {"format", &str_format},
  {"dump", &str_dump},
  {"find", &str_find},
  {"gfind", &gfind},
  {"gsub", &str_gsub},
  {"lualex", &str_lualex},
  {nullptr, nullptr}
};

/**
 * Address: 0x00927B10 (FUN_00927B10, luaB_foreachi)
 *
 * IDA signature:
 * int __cdecl luaB_foreachi(lua_State *L);
 *
 * What it does:
 * Calls f(i, t[i]) for 1..getn(t), stopping at and returning the first
 * non-nil result.
 */
int LuaTableForEachIndexed(
  lua_State* const state
)
{
  luaL_checktype(state, 1, LUA_TTABLE);
  const int count = luaL_getn(state, 1);

  for (int index = 1; index <= count; ++index) {
    lua_pushvalue(state, 2);
    lua_pushnumber(state, static_cast<lua_Number>(index));
    lua_rawgeti(state, 1, index);
    LuaCallUnprotected(state, 2, 1);
    if (lua_type(state, -1) != LUA_TNIL) {
      return 1;
    }
    lua_settop(state, -2);
  }

  return 0;
}

/**
 * Address: 0x00927BA0 (FUN_00927BA0, luaB_foreach)
 *
 * IDA signature:
 * int __cdecl luaB_foreach(lua_State *L);
 *
 * What it does:
 * Calls f(k, v) for every pair, stopping at and returning the first non-nil
 * result.
 */
int LuaTableForEach(
  lua_State* const state
)
{
  luaL_checktype(state, 1, LUA_TTABLE);

  lua_pushnil(state);
  while (lua_next(state, 1) != 0) {
    lua_pushvalue(state, 2);
    lua_pushvalue(state, -3);
    lua_pushvalue(state, -3);
    LuaCallUnprotected(state, 2, 1);
    if (lua_type(state, -1) != LUA_TNIL) {
      return 1;
    }
    lua_settop(state, -3);
  }

  return 0;
}

/**
 * Address: 0x00927C20 (FUN_00927C20, luaB_getn)
 *
 * IDA signature:
 * int __cdecl luaB_getn(lua_State *L);
 */
int LuaTableGetN(
  lua_State* const state
)
{
  luaL_checktype(state, 1, LUA_TTABLE);
  lua_pushnumber(state, static_cast<lua_Number>(luaL_getn(state, 1)));
  return 1;
}

/**
 * Address: 0x00927C60 (FUN_00927C60, luaB_setn)
 *
 * IDA signature:
 * int __cdecl luaB_setn(lua_State *L);
 */
int LuaTableSetN(
  lua_State* const state
)
{
  luaL_checktype(state, 1, LUA_TTABLE);
  const auto count = static_cast<int>(luaL_checknumber(state, 2));
  luaL_setn(state, 1, count);
  return 0;
}

/**
 * Address: 0x00927C90 (FUN_00927C90, luaB_tinsert)
 *
 * IDA signature:
 * int __cdecl luaB_tinsert(lua_State *L);
 *
 * What it does:
 * table.insert(t, v) appends; table.insert(t, pos, v) shifts everything from
 * pos up one and writes v there. Inserting past the end grows n to the given
 * position.
 */
int LuaTableInsert(
  lua_State* const state
)
{
  int valueIndex = lua_gettop(state);
  luaL_checktype(state, 1, LUA_TTABLE);

  const int currentCount = luaL_getn(state, 1);
  int newCount = currentCount + 1;
  int position = 0;

  if (valueIndex == 2) {
    position = currentCount + 1;
  } else {
    position = static_cast<int>(luaL_checknumber(state, 2));
    if (position > newCount) {
      newCount = position;
    }
    valueIndex = 3;
  }

  luaL_setn(state, 1, newCount);
  for (int slot = newCount - 1; slot >= position; --slot) {
    lua_rawgeti(state, 1, slot);
    lua_rawseti(state, 1, slot + 1);
  }

  lua_pushvalue(state, valueIndex);
  lua_rawseti(state, 1, position);
  return 0;
}

/**
 * Address: 0x00927D30 (FUN_00927D30, luaB_tremove)
 *
 * IDA signature:
 * int __cdecl luaB_tremove(lua_State *L);
 *
 * What it does:
 * Removes t[pos] (default n), shifts the tail down, and returns the removed
 * value. An empty table returns nothing at all.
 */
int LuaTableRemove(
  lua_State* const state
)
{
  luaL_checktype(state, 1, LUA_TTABLE);

  const int count = luaL_getn(state, 1);
  const auto position = static_cast<int>(luaL_optnumber(state, 2, static_cast<lua_Number>(count)));
  if (count <= 0) {
    return 0;
  }

  luaL_setn(state, 1, count - 1);
  lua_rawgeti(state, 1, position);
  for (int slot = position; slot < count; ++slot) {
    lua_rawgeti(state, 1, slot + 1);
    lua_rawseti(state, 1, slot);
  }

  lua_pushnil(state);
  lua_rawseti(state, 1, count);
  return 1;
}
