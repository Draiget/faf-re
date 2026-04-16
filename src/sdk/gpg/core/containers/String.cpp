#include "String.h"

#include <cstdarg>
#include <string_view>
using namespace gpg;

msvc8::string gpg::sWhitespaceChars{" \n\t\r"};

/**
 * Address: 0x009380A0 (FUN_009380A0, gpg::STR_Utf8ByteOffset)
 *
 * What it does:
 * Advances `pos` UTF-8 codepoints (or to end-of-string) and returns the
 * resulting byte offset from the original string start.
 */
int gpg::STR_Utf8ByteOffset(
  const StrArg str,
  const int pos
)
{
  const char* itr = str;
  int i;
  for (i = 0; *itr; ++i) {
    if (i >= pos) {
      break;
    }
    itr = STR_NextUtf8Char(itr);
  }
  return itr - str;
}

// 0x00938070
int gpg::STR_Utf8Len(
  char const* str
)
{
  int i;
  for (i = 0; *str; ++i) {
    str = STR_NextUtf8Char(str);
  }
  return i;
}

/**
 * Address: 0x00938040 (FUN_00938040, gpg::STR_NextUtf8Char)
 *
 * What it does:
 * Advances to the next UTF-8 codepoint boundary, stopping at NUL.
 */
const char* gpg::STR_NextUtf8Char(
  const char* str
)
{
  if (*str) {
    char c;
    do {
      c = *++str;
    } while (c && (c & 0xC0) == 0x80);
  }
  return str;
}

/**
 * Address: 0x00938020 (FUN_00938020, gpg::STR_PreviousUtf8Char)
 *
 * What it does:
 * Walks backward to the previous UTF-8 codepoint boundary, bounded by
 * `start` when non-null.
 */
const char* gpg::STR_PreviousUtf8Char(
  const char* str,
  const char* start
)
{
  char c;
  do {
    if (start != nullptr && str <= start) {
      break;
    }
    c = *--str;
  } while ((c & 0xC0) == 0x80);
  return str;
}

/**
 * Address: 0x009387D0 (FUN_009387D0, gpg::STR_Utf8SubString)
 *
 * What it does:
 * Walks UTF-8 codepoint boundaries to extract one `[pos, pos+len)` codepoint
 * range; throws `std::out_of_range` when `pos` is past end-of-string.
 */
msvc8::string gpg::STR_Utf8SubString(
  StrArg str,
  const int pos,
  const int len
)
{
  const char* start = nullptr;
  for (int i = 0;; ++i) {
    if (i == pos) {
      start = str;
    }
    if (i == pos + len) {
      if (str != nullptr) {
        return msvc8::string{start, static_cast<std::size_t>(str - start)};
      }
      break;
    }
    if (!*str) {
      break;
    }
    str = STR_NextUtf8Char(str);
  }
  if (start == nullptr) {
    throw std::out_of_range{msvc8::string{"offset past end of string"}.to_std()};
  }
  return msvc8::string{start, static_cast<std::size_t>(str - start)};
}

/**
 * Address: 0x00937F90 (FUN_00937F90, gpg::STR_EncodeUtf8Char)
 *
 * What it does:
 * Encodes one wide character to UTF-8 (1-3 bytes) when `limit` permits and
 * returns the next write position; otherwise returns the original `dest`.
 */
char* gpg::STR_EncodeUtf8Char(
  char* dest,
  const wchar_t chr,
  const char* limit
)
{
  if (chr >= 0x80) {
    if (chr >= 0x800) {
      if (!limit || dest + 3 <= limit) {
        dest[0] = (chr >> 12) | 0xE0;
        dest[1] = (chr >> 6) & 0x3F | 0x80;
        dest[2] = chr & 0x3F | 0x80;
        return dest + 3;
      }
    } else if (!limit || dest + 2 <= limit) {
      dest[0] = (chr >> 6) | 0xC0;
      dest[1] = chr & 0x3F | 0x80;
      return dest + 2;
    }
  } else if (!limit || dest + 1 <= limit) {
    dest[0] = chr;
    return dest + 1;
  }
  return dest;
}

/**
 * Address: 0x00937EF0 (FUN_00937EF0, gpg::STR_DecodeUtf8Char)
 *
 * What it does:
 * Decodes one UTF-8 sequence and returns the pointer advanced past consumed
 * bytes, preserving binary continuation-byte validation behavior.
 */
const char* gpg::STR_DecodeUtf8Char(
  const char* str,
  wchar_t& dest
)
{
  const char* cursor = str + 1;
  const signed char leadSigned = static_cast<signed char>(*str);
  const unsigned char lead = static_cast<unsigned char>(*str);

  wchar_t codepoint = static_cast<wchar_t>(leadSigned);
  if ((lead & 0x80u) != 0u) {
    if ((lead & 0xE0u) == 0xC0u) {
      codepoint = static_cast<wchar_t>((lead & 0x1Fu) << 6);
    } else {
      if ((lead & 0xF0u) == 0xE0u) {
        codepoint = static_cast<wchar_t>((lead & 0x0Fu) << 12);
      } else {
        if ((lead & 0xF8u) != 0xF0u) {
          dest = codepoint;
          return cursor;
        }

        codepoint = 0;
        const unsigned char c2 = static_cast<unsigned char>(*cursor);
        if ((c2 & 0xC0u) != 0x80u) {
          dest = codepoint;
          return cursor;
        }

        codepoint = static_cast<wchar_t>((c2 & 0x3Fu) << 12);
        cursor = str + 2;
      }

      const unsigned char c3 = static_cast<unsigned char>(*cursor);
      if ((c3 & 0xC0u) != 0x80u) {
        dest = codepoint;
        return cursor;
      }

      codepoint = static_cast<wchar_t>(codepoint | ((c3 & 0x3Fu) << 6));
      ++cursor;
    }

    const unsigned char c4 = static_cast<unsigned char>(*cursor);
    if ((c4 & 0xC0u) == 0x80u) {
      codepoint = static_cast<wchar_t>(codepoint | (c4 & 0x3Fu));
      ++cursor;
    }
  }

  dest = codepoint;
  return cursor;
}

// 0x00938680
msvc8::string gpg::STR_WideToUtf8(
  const wchar_t* str
)
{
  msvc8::string builder{};
  if (str != nullptr) {
    char buff[4];
    for (wchar_t c = *str; c; c = *++str) {
      const char* end = STR_EncodeUtf8Char(buff, c, &buff[sizeof(buff)]);
      builder.append(buff, end - buff);
    }
  }
  return builder;
}

// 0x00938720
std::wstring gpg::STR_Utf8ToWide(
  StrArg str
)
{
  std::wstring builder{};
  if (str == nullptr) {
    return builder;
  }
  wchar_t c;
  for (str = STR_DecodeUtf8Char(str, c); c; str = STR_DecodeUtf8Char(str, c)) {
    builder.append(1, c);
  }
  return builder;
}

// 0x00938CB0
bool gpg::STR_GetToken(
  StrArg& find,
  const char* str,
  msvc8::string& dest
)
{
  int c = *find;
  while (c && strchr(str, c) != nullptr) {
    c = *++find;
  }
  if (c) {
    const char* start = find;
    c = *++find;
    while (c && strchr(str, c) != nullptr) {
      c = *++find;
    }
    dest = msvc8::string{start, find};
    if (c) {
      ++find;
    }
    return true;
  }
  dest.clear();
  find = nullptr;
  return false;
}

/**
 * Address: 0x00938F40 (FUN_00938F40, gpg::STR_GetTokens)
 *
 * What it does:
 * Reads tokens from one mutable scan pointer and appends each token to the
 * output vector.
 */
void gpg::STR_GetTokens(
  StrArg find,
  const char* str,
  msvc8::vector<msvc8::string>& vec
)
{
  msvc8::string token{};
  const char* const delimiters = str;
  if (STR_GetToken(find, delimiters, token)) {
    do {
      vec.push_back(token);
    } while (STR_GetToken(find, delimiters, token));
  }
}

/**
 * Address: 0x009384A0 (FUN_009384A0, gpg::STR_GetWordStartIndex)
 *
 * What it does:
 * Walks backward across UTF-8 codepoint boundaries from `pos` and returns the
 * start index of the current/previous word boundary.
 */
int gpg::STR_GetWordStartIndex(
  msvc8::string& str,
  const int pos
)
{
  if (STR_Utf8Len(str.data()) <= 1) {
    return 0;
  }

  const char* const begin = str.data();
  const char* cursor = begin + STR_Utf8ByteOffset(begin, pos);
  int index = pos;
  bool boundary = false;

  while (cursor > begin) {
    cursor = STR_PreviousUtf8Char(cursor, begin);
    const char c = *cursor;
    const auto whitespacePos = sWhitespaceChars.find(&c, 0, 1);

    if (boundary) {
      if (whitespacePos != msvc8::string::npos) {
        return index;
      }
    } else {
      boundary = whitespacePos == msvc8::string::npos;
    }

    --index;
  }

  return index;
}

/**
 * Address: 0x00938570 (FUN_00938570, gpg::STR_GetNextWordStartIndex)
 *
 * msvc8::string &, int
 *
 * IDA signature:
 * int __cdecl gpg::STR_GetNextWordStartIndex(std::string *str, int pos);
 *
 * What it does:
 * Scans forward from `pos` and returns the first non-whitespace codepoint
 * after the next whitespace separator; returns UTF-8 length when none exists.
 */
int gpg::STR_GetNextWordStartIndex(
  msvc8::string& str,
  int pos
)
{
  const char* const begin = str.data();
  const int len = STR_Utf8Len(begin);
  if (len == 0 || pos >= len) {
    return len;
  }

  const char* cursor = begin + STR_Utf8ByteOffset(begin, pos);
  int index = pos;
  bool seenWhitespace = false;

  while (*cursor != '\0') {
    const char c = *cursor;
    const bool isWhitespace = (sWhitespaceChars.find(&c, 0, 1) != msvc8::string::npos);

    if (seenWhitespace) {
      if (!isWhitespace) {
        return index;
      }
    } else {
      seenWhitespace = isWhitespace;
    }

    ++index;
    cursor = STR_NextUtf8Char(cursor);
  }

  return index;
}

/**
 * Address: 0x00938190 (FUN_00938190, gpg::STR_EndsWith)
 *
 * What it does:
 * Returns whether `str` has suffix `end`, requiring `str` to be strictly
 * longer than `end`.
 */
bool gpg::STR_EndsWith(
  const StrArg str,
  const StrArg end
)
{
  const unsigned int strLen = strlen(str);
  const unsigned int endLen = strlen(end);
  return strLen > endLen && !strcmp(&str[strLen - endLen], end);
}

/**
 * Address: 0x00938210 (FUN_00938210, gpg::STR_StartsWith)
 *
 * What it does:
 * Returns whether `str` begins with `start`.
 */
bool gpg::STR_StartsWith(
  const StrArg str,
  const StrArg start
)
{
  return strncmp(str, start, strlen(start)) == 0;
}

/**
 * Address: 0x00938250 (FUN_00938250, gpg::STR_EndsWithNoCase)
 *
 * What it does:
 * Returns whether `str` ends with `end` using ASCII case-insensitive
 * comparison.
 */
bool gpg::STR_EndsWithNoCase(
  const StrArg str,
  const StrArg end
)
{
  const unsigned int strLen = strlen(str);
  const unsigned int endLen = strlen(end);
  return strLen > endLen && !_stricmp(&str[strLen - endLen], end);
}

/**
 * Address: 0x009382B0 (FUN_009382B0, gpg::STR_StartsWithNoCase)
 *
 * What it does:
 * Returns whether `str` begins with `start` using ASCII case-insensitive
 * comparison.
 */
bool gpg::STR_StartsWithNoCase(
  const StrArg str,
  const StrArg start
)
{
  return _strnicmp(str, start, strlen(start)) == 0;
}

bool gpg::STR_EqualsNoCaseN(
  const StrArg lhs,
  const StrArg rhs,
  const std::size_t count
)
{
  if (count == 0u) {
    return true;
  }
  if (lhs == nullptr || rhs == nullptr) {
    return false;
  }

  for (std::size_t i = 0; i < count; ++i) {
    unsigned char a = static_cast<unsigned char>(lhs[i]);
    unsigned char b = static_cast<unsigned char>(rhs[i]);
    if (a == '\0' || b == '\0') {
      return a == b;
    }

    if (a >= 'A' && a <= 'Z') {
      a = static_cast<unsigned char>(a + ('a' - 'A'));
    }
    if (b >= 'A' && b <= 'Z') {
      b = static_cast<unsigned char>(b + ('a' - 'A'));
    }
    if (a != b) {
      return false;
    }
  }

  return true;
}

int gpg::STR_CompareNoCase(
  const StrArg lhs,
  const StrArg rhs
)
{
  if (lhs == rhs) {
    return 0;
  }
  if (lhs == nullptr) {
    return -1;
  }
  if (rhs == nullptr) {
    return 1;
  }
  return _stricmp(lhs, rhs);
}

bool gpg::STR_ContainsNoCase(
  const StrArg str,
  const StrArg needle
)
{
  if (needle == nullptr || needle[0] == '\0') {
    return true;
  }
  if (str == nullptr) {
    return false;
  }

  const msvc8::string haystackLower = STR_ToLower(str);
  const msvc8::string needleLower = STR_ToLower(needle);
  return haystackLower.find(needleLower.data(), 0, needleLower.size()) != msvc8::string::npos;
}

bool gpg::STR_EqualsNoCase(
  const StrArg lhs,
  const StrArg rhs
)
{
  if (lhs == nullptr || rhs == nullptr) {
    return lhs == rhs;
  }
  return _stricmp(lhs, rhs) == 0;
}

/**
 * Address: 0x009382F0 (FUN_009382F0, gpg::STR_IsIdent)
 *
 * What it does:
 * Validates one identifier token using ASCII `[A-Za-z_]` start and
 * `[A-Za-z0-9_]*` tail rules.
 */
bool gpg::STR_IsIdent(
  StrArg str
)
{
  char c = *str++;
  if (c == '\0' || (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && c != '_') {
    return false;
  }
  c = *str++;
  while (c) {
    if ((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_') {
      return false;
    }
    c = *str++;
  }
  return true;
}

/**
 * Address: 0x00938B40 (FUN_00938B40, gpg::STR_Replace)
 *
 * What it does:
 * Replaces every occurrence of `what` in `str` with `with` while `unk` is
 * non-zero, returning the number of replacements performed.
 */
int gpg::STR_Replace(
  msvc8::string& str,
  const StrArg what,
  const StrArg with,
  const unsigned int unk
)
{
  const std::size_t whatLength = std::strlen(what);
  const std::size_t withLength = std::strlen(with);

  int replaceCount = 0;
  if (unk != 0u) {
    std::size_t searchPos = 0u;
    while ((searchPos = str.find(what, searchPos, whatLength)) != msvc8::string::npos) {
      str.replace(searchPos, whatLength, std::string_view{with, withLength});
      searchPos += withLength;
      ++replaceCount;
    }
  }
  return replaceCount;
}

// 0x00938150
int gpg::STR_ParseUInt32(
  const StrArg str
)
{
  if (str == nullptr) {
    return 0;
  }
  if (_strnicmp(str, "0x", 2) == 0) {
    return STR_Xtoi(&str[2]);
  }
  return atoi(str);
}

// 0x009380F0
int gpg::STR_Xtoi(
  StrArg str
)
{
  int res = 0;
  if (str != nullptr) {
    for (char c = *str; c != NULL; c = *++str) {
      res *= 16;
      if (c - '0' <= 9) {
        res += c - '0';
      } else if (c - 'A' <= 5) {
        res += 10 + c - 'A';
      } else if (c - 'a' <= 5) {
        res += 10 + c - 'a';
      } else {
        return res;
      }
    }
  }
  return res;
}

bool gpg::STR_IsAsciiWhitespace(
  const char ch
)
{
  switch (ch) {
  case ' ':
  case '\t':
  case '\n':
  case '\r':
  case '\f':
  case '\v':
    return true;
  default:
    return false;
  }
}

namespace
{
  enum class WildcardMatchStepResult : int
  {
    Mismatch = 0,
    Match = 1,
    Star = 2,
    PrefixExhausted = 3,
    PatternExhausted = 4
  };

  char FoldWildcardChar(
    const char c,
    const bool caseSensitive
  )
  {
    if (caseSensitive) {
      return c;
    }
    if (c >= 'A' && c <= 'Z') {
      return static_cast<char>(c + ('a' - 'A'));
    }
    return c;
  }

  /**
   * Address: 0x00938350 (FUN_00938350)
   *
   * What it does:
   * Advances one wildcard match lane across literal/`?`/`*` tokens and reports
   * the state-machine transition result.
   */
  [[nodiscard]] WildcardMatchStepResult AdvanceWildcardLiteralLane(
    const char*& text,
    const char*& pattern
  ) noexcept
  {
    const char* textCursor = text;
    const char* patternCursor = pattern;
    char patternChar = *patternCursor;
    if (patternChar == '\0') {
      return (*textCursor != '\0') ? WildcardMatchStepResult::PatternExhausted : WildcardMatchStepResult::Match;
    }

    while (true) {
      ++patternCursor;
      if (patternChar == '?') {
        const char textChar = *textCursor++;
        if (textChar == '\0') {
          return WildcardMatchStepResult::PrefixExhausted;
        }

        if (static_cast<signed char>(textChar) < 0 && ((*textCursor & 0xC0) == 0x80)) {
          char continuationByte = 0;
          do {
            continuationByte = *++textCursor;
          } while ((continuationByte & 0xC0) == 0x80);
        }
      } else if (patternChar == '*') {
        text = textCursor;
        pattern = patternCursor;
        return WildcardMatchStepResult::Star;
      } else {
        const char textChar = *textCursor++;
        if (textChar != patternChar) {
          return (textChar != '\0') ? WildcardMatchStepResult::Mismatch : WildcardMatchStepResult::PrefixExhausted;
        }
      }

      patternChar = *patternCursor;
      if (patternChar == '\0') {
        return (*textCursor != '\0') ? WildcardMatchStepResult::PatternExhausted : WildcardMatchStepResult::Match;
      }
    }
  }

  /**
   * Address: 0x009383D0 (FUN_009383D0, wildcard core matcher lane)
   *
   * What it does:
   * Executes the binary wildcard state machine used by
   * `gpg::STR_MatchWildcard`/`gpg::STR_WildcardValidPrefix`, including UTF-8
   * aware `?` handling and `*` backtracking semantics.
   */
  [[nodiscard]] int MatchWildcardPatternLane(
    const char* text,
    const char* pattern
  ) noexcept
  {
    WildcardMatchStepResult result = AdvanceWildcardLiteralLane(text, pattern);
    if (result != WildcardMatchStepResult::Star) {
      return static_cast<int>(result);
    }

    while (true) {
      for (const char* scan = text;; scan = ++text) {
        const char patternChar = *pattern;
        char scanChar = '\0';
        if (patternChar != '*' && patternChar != '?') {
          scanChar = *scan;
          if (scanChar != patternChar) {
            while (scanChar != '\0') {
              scanChar = *++scan;
              text = scan;
              if (scanChar == patternChar) {
                break;
              }
            }
            if (scanChar == '\0') {
              return static_cast<int>(WildcardMatchStepResult::PrefixExhausted);
            }
          }
        }

        result = AdvanceWildcardLiteralLane(text, pattern);
        if (result != WildcardMatchStepResult::Mismatch) {
          if (result == WildcardMatchStepResult::Star) {
            break;
          }
          if (result != WildcardMatchStepResult::PatternExhausted) {
            return static_cast<int>(result);
          }
        }
      }
    }
  }
} // namespace

/**
 * Address: 0x00938450 (FUN_00938450, gpg::STR_MatchWildcard)
 *
 * What it does:
 * Calls the wildcard matcher in default case-sensitive mode.
 */
bool gpg::STR_MatchWildcard(
  StrArg text,
  StrArg pattern
)
{
  return STR_MatchWildcard(text, pattern, true);
}

bool gpg::STR_MatchWildcard(
  StrArg text,
  StrArg pattern,
  const bool caseSensitive
)
{
  if (text == nullptr || pattern == nullptr) {
    return false;
  }

  if (caseSensitive) {
    return MatchWildcardPatternLane(text, pattern) == static_cast<int>(WildcardMatchStepResult::Match);
  }

  const char* starPattern = nullptr;
  const char* starText = nullptr;

  while (*text != '\0') {
    if (*pattern == '*') {
      starPattern = pattern++;
      starText = text;
      continue;
    }

    const bool charsMatch =
      (*pattern == '?') || (FoldWildcardChar(*pattern, caseSensitive) == FoldWildcardChar(*text, caseSensitive));
    if (charsMatch) {
      ++pattern;
      ++text;
      continue;
    }

    if (starPattern == nullptr) {
      return false;
    }

    pattern = starPattern + 1;
    text = ++starText;
  }

  while (*pattern == '*') {
    ++pattern;
  }

  return *pattern == '\0';
}

/**
 * Address: 0x00938470 (FUN_00938470, gpg::STR_WildcardValidPrefix)
 *
 * What it does:
 * Calls wildcard-prefix validation in default case-sensitive mode.
 */
bool gpg::STR_WildcardValidPrefix(
  StrArg prefix,
  StrArg pattern
)
{
  return STR_WildcardValidPrefix(prefix, pattern, true);
}

bool gpg::STR_WildcardValidPrefix(
  StrArg prefix,
  StrArg pattern,
  const bool caseSensitive
)
{
  if (prefix == nullptr || pattern == nullptr) {
    return false;
  }

  if (caseSensitive) {
    const int result = MatchWildcardPatternLane(prefix, pattern);
    return result == static_cast<int>(WildcardMatchStepResult::Match)
      || result == static_cast<int>(WildcardMatchStepResult::PrefixExhausted);
  }

  const char* starPattern = nullptr;
  const char* starPrefix = nullptr;

  while (*prefix != '\0') {
    if (*pattern == '*') {
      starPattern = pattern++;
      starPrefix = prefix;
      continue;
    }

    const bool charsMatch =
      (*pattern == '?') || (FoldWildcardChar(*pattern, caseSensitive) == FoldWildcardChar(*prefix, caseSensitive));
    if (charsMatch) {
      ++pattern;
      ++prefix;
      continue;
    }

    if (starPattern == nullptr) {
      return false;
    }

    pattern = starPattern + 1;
    prefix = ++starPrefix;
  }

  return true;
}

// 0x00938C80
msvc8::string gpg::STR_GetWhitespaceCharacters()
{
  return msvc8::string{sWhitespaceChars};
}

/**
 * Address: 0x00938BF0 (FUN_00938BF0, gpg::STR_Chop)
 *
 * What it does:
 * Returns `str` without its trailing `chr` delimiter (or without the last
 * character when `chr==0`).
 */
msvc8::string gpg::STR_Chop(
  const StrArg str,
  const char chr
)
{
  if (str && *str) {
    int size = strlen(str);
    if (!chr || str[size - 1] == chr) {
      --size;
    }
    return msvc8::string{str, &str[size]};
  } else {
    return msvc8::string{""};
  }
}

// 0x00938A80
msvc8::string gpg::STR_ToLower(
  StrArg str
)
{
  msvc8::string builder{};
  builder.reserve(strlen(str));
  for (char c = *str; c != NULL; c = *++str) {
    if (c - 'A' <= 25) {
      c += 'a' - 'A';
    }
    builder.append(1, c);
  }
  return builder;
}

/**
 * Address: 0x009389C0 (FUN_009389C0, gpg::STR_ToUpper)
 *
 * What it does:
 * Produces one uppercase ASCII copy of the input string.
 */
msvc8::string gpg::STR_ToUpper(
  StrArg str
)
{
  msvc8::string builder{};
  builder.reserve(strlen(str));
  for (char c = *str; c != NULL; c = *++str) {
    if (c - 'a' <= 25) {
      c -= 'a' - 'A';
    }
    builder.append(1, c);
  }
  return builder;
}

void gpg::STR_NormalizeFilenameLowerSlash(
  msvc8::string& inOut
)
{
  for (std::size_t i = 0; i < inOut.size(); ++i) {
    char ch = inOut[i];
    if (ch >= 'A' && ch <= 'Z') {
      ch = static_cast<char>(ch + ('a' - 'A'));
    }
    if (ch == '\\') {
      ch = '/';
    }
    inOut[i] = ch;
  }
}

void gpg::STR_NormalizeFilenameLowerSlash(
  std::string& inOut
)
{
  for (std::size_t i = 0; i < inOut.size(); ++i) {
    char ch = inOut[i];
    if (ch >= 'A' && ch <= 'Z') {
      ch = static_cast<char>(ch + ('a' - 'A'));
    }
    if (ch == '\\') {
      ch = '/';
    }
    inOut[i] = ch;
  }
}

/**
 * Address: 0x0051E2E0 (FUN_0051E2E0, func_StringInitFilename)
 *
 * What it does:
 * Initializes destination string into empty SSO state, then canonicalizes one
 * filename/path token to lowercase backslash form.
 */
msvc8::string* gpg::STR_InitFilename(
  msvc8::string* const out,
  const StrArg in
)
{
  if (out == nullptr) {
    return nullptr;
  }

  out->tidy(false, 0U);
  STR_CanonizeFilename(out, in);
  return out;
}

msvc8::string* gpg::STR_SetFilename(
  msvc8::string* const out,
  const StrArg in
)
{
  return STR_InitFilename(out, in);
}

/**
 * Address: 0x0050E460 (FUN_0050E460, gpg::STR_CopyFilename)
 *
 * What it does:
 * Routes one source filename string through `STR_SetFilename` into `out`.
 */
msvc8::string* gpg::STR_CopyFilename(
  msvc8::string* const out,
  const msvc8::string* const filename
)
{
  return STR_SetFilename(out, filename->raw_data_unsafe());
}

/**
 * Address: 0x00458450 (FUN_00458450, gpg::STR_CanonizeFilename)
 *
 * What it does:
 * Lowercases one path and normalizes `/` separators to `\\`.
 */
void gpg::STR_CanonizeFilename(
  msvc8::string* const out,
  const StrArg in
)
{
  if (out == nullptr) {
    return;
  }

  out->assign_owned(STR_ToLower(in ? in : "").view());
  for (std::size_t i = 0; i < out->size(); ++i) {
    if ((*out)[i] == '/') {
      (*out)[i] = '\\';
    }
  }
}

/**
 * Address: 0x009388C0 (FUN_009388C0, gpg::STR_TrimWhitespace)
 *
 * What it does:
 * Skips leading ASCII whitespace bytes, copies the remaining text, then trims
 * trailing ASCII whitespace bytes from the copied buffer.
 */
msvc8::string gpg::STR_TrimWhitespace(
  StrArg str
)
{
  msvc8::string builder{};
  if (str != nullptr) {
    const char* cursor = str;
    while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
      ++cursor;
    }
    builder = cursor;

    std::size_t trimmedSize = builder.size();
    while (trimmedSize != 0) {
      const char c = builder[trimmedSize - 1];
      if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
        break;
      }
      --trimmedSize;
    }
    builder.resize(trimmedSize);
  }
  return builder;
}

/**
 * Address: 0x00938F10 (FUN_00938F10)
 * Mangled: ?STR_Printf@gpg@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PBDZZ
 *
 * What it does:
 * Starts one varargs lane at `fmt` and forwards formatting through `STR_Va`.
 */
msvc8::string gpg::STR_Printf(
  const char* fmt,
  ...
)
{
  va_list va;
  va_start(va, fmt);
  const char* forwardedFormat = fmt;
  const msvc8::string ret = STR_Va(forwardedFormat, va);
  va_end(va);
  return ret;
}

/**
 * Address: 0x00938E00 (FUN_00938E00)
 * Mangled: ?STR_Va@gpg@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAPBD@Z
 *
 * What it does:
 * Formats one vararg message into a 256-byte stack buffer first, then retries
 * in a growable heap buffer until `_vsnprintf` returns a concrete length.
 */
msvc8::string gpg::STR_Va(
  const char*& fmt,
  const va_list va
)
{
  msvc8::string builder{};
  char stackBuffer[256]{};
  int formattedLength = std::vsnprintf(stackBuffer, sizeof(stackBuffer), fmt, va);
  if (formattedLength == -1) {
    msvc8::vector<char> dynamicBuffer{};
    std::size_t capacity = sizeof(stackBuffer);
    do {
      capacity *= 2;
      dynamicBuffer.resize(capacity, 0);
      formattedLength = std::vsnprintf(dynamicBuffer.data(), capacity, fmt, va);
    } while (formattedLength == -1);

    builder.append(dynamicBuffer.data(), formattedLength);
    return builder;
  }

  builder.append(stackBuffer, formattedLength);
  return builder;
}
