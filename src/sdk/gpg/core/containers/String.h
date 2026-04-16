#pragma once

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
  using StrArg = const char*;
  using WStrArg = const wchar_t*;

  extern msvc8::string sWhitespaceChars; // 0x00F32308

  /**
   * Address: 0x009380A0 (FUN_009380A0, gpg::STR_Utf8ByteOffset)
   *
   * What it does:
   * Returns the byte offset that corresponds to `pos` UTF-8 codepoints into
   * `str`, clamping at the NUL terminator.
   */
  int STR_Utf8ByteOffset(StrArg str, int pos);
  int STR_Utf8Len(char const*);                                         // 0x00938070
  /**
   * Address: 0x00938040 (FUN_00938040, gpg::STR_NextUtf8Char)
   *
   * What it does:
   * Advances to the next UTF-8 codepoint boundary (or keeps `str` at the
   * NUL terminator when already at string end).
   */
  const char* STR_NextUtf8Char(const char* str);
  /**
   * Address: 0x00938020 (FUN_00938020, gpg::STR_PreviousUtf8Char)
   *
   * What it does:
   * Walks backward from `str` to the previous UTF-8 codepoint boundary,
   * stopping at `start` when provided.
   */
  const char* STR_PreviousUtf8Char(const char* str, const char* start);
  /**
   * Address: 0x009387D0 (FUN_009387D0, gpg::STR_Utf8SubString)
   *
   * What it does:
   * Returns one UTF-8 codepoint-range substring; throws `std::out_of_range`
   * when `pos` starts past the end of the source string.
  */
  msvc8::string STR_Utf8SubString(StrArg str, int pos, int len);
  /**
   * Address: 0x00937F90 (FUN_00937F90, gpg::STR_EncodeUtf8Char)
   *
   * What it does:
   * Encodes one wide character into UTF-8 at `dest`, returning the first
   * byte after written output or the original `dest` when `limit` blocks
   * the write.
   */
  char* STR_EncodeUtf8Char(char* dest, wchar_t chr, const char* limit);
  /**
   * Address: 0x00937EF0 (FUN_00937EF0, gpg::STR_DecodeUtf8Char)
   *
   * What it does:
   * Decodes one UTF-8 sequence from `str` into `dest` and returns a pointer to
   * the first byte after the consumed sequence.
   */
  const char* STR_DecodeUtf8Char(const char*, wchar_t&);
  msvc8::string STR_WideToUtf8(const wchar_t*);                         // 0x00938680
  std::wstring STR_Utf8ToWide(StrArg str);                              // 0x00938720

  bool STR_GetToken(const char*& find, const char* str, msvc8::string& dest);           // 0x00938CB0
  /**
   * Address: 0x00938F40 (FUN_00938F40, gpg::STR_GetTokens)
   *
   * What it does:
   * Repeatedly tokenizes one source string via `STR_GetToken` and appends each
   * produced token to `dest`.
   */
  void STR_GetTokens(StrArg find, const char* str, msvc8::vector<msvc8::string>& dest);
  int STR_GetWordStartIndex(msvc8::string& str, int pos);                               // 0x009384A0
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
  int STR_GetNextWordStartIndex(msvc8::string& str, int pos);
  /**
   * Address: 0x00938190 (FUN_00938190, gpg::STR_EndsWith)
   *
   * What it does:
   * Returns whether `str` ends with `end` when `str` is strictly longer than
   * `end`, matching the original binary comparison lane.
   */
  bool STR_EndsWith(StrArg str, StrArg end);
  /**
   * Address: 0x00938210 (FUN_00938210, gpg::STR_StartsWith)
   *
   * What it does:
   * Returns whether `str` begins with `start`.
   */
  bool STR_StartsWith(StrArg str, StrArg start);
  /**
   * Address: 0x00938250 (FUN_00938250, gpg::STR_EndsWithNoCase)
   *
   * What it does:
   * Returns whether `str` ends with `end` using ASCII case-insensitive
   * comparison.
   */
  bool STR_EndsWithNoCase(StrArg str, StrArg end);
  /**
   * Address: 0x009382B0 (FUN_009382B0, gpg::STR_StartsWithNoCase)
   *
   * What it does:
   * Returns whether `str` begins with `start` using ASCII case-insensitive
   * comparison.
   */
  bool STR_StartsWithNoCase(StrArg str, StrArg start);
  bool STR_EqualsNoCaseN(StrArg lhs, StrArg rhs, std::size_t count);
  int STR_CompareNoCase(StrArg lhs, StrArg rhs);
  bool STR_ContainsNoCase(StrArg str, StrArg needle);
  bool STR_EqualsNoCase(StrArg lhs, StrArg rhs);
  /**
   * Address: 0x009382F0 (FUN_009382F0, gpg::STR_IsIdent)
   *
   * What it does:
   * Returns whether `str` matches Lua/C identifier rules:
   * first char `[A-Za-z_]`, remaining chars `[A-Za-z0-9_]*`.
   */
  bool STR_IsIdent(StrArg str);
  /**
   * Address: 0x00938B40 (FUN_00938B40, gpg::STR_Replace)
   *
   * What it does:
   * Replaces every occurrence of `what` in `str` with `with` while `unk` is
   * non-zero, returning the number of replacements performed.
   */
  int STR_Replace(msvc8::string& str, StrArg what, StrArg with, unsigned int unk);
  int STR_ParseUInt32(StrArg str);                                                 // 0x00938150
  int STR_Xtoi(StrArg str);                                                        // 0x009380F0
  bool STR_IsAsciiWhitespace(char ch);
  /**
   * Address: 0x00938450 (FUN_00938450, gpg::STR_MatchWildcard)
   *
   * What it does:
   * Evaluates wildcard matching in case-sensitive mode.
   */
  bool STR_MatchWildcard(StrArg, StrArg);
  bool STR_MatchWildcard(StrArg, StrArg, bool caseSensitive);
  /**
   * Address: 0x00938470 (FUN_00938470, gpg::STR_WildcardValidPrefix)
   *
   * What it does:
   * Evaluates wildcard-prefix validity in default case-sensitive mode.
   */
  bool STR_WildcardValidPrefix(StrArg prefix, StrArg pattern);
  bool STR_WildcardValidPrefix(StrArg, StrArg, bool caseSensitive);

  msvc8::string STR_GetWhitespaceCharacters();  // 0x00938C80
  /**
   * Address: 0x00938BF0 (FUN_00938BF0, gpg::STR_Chop)
   *
   * What it does:
   * Returns `str` without its trailing `chr` delimiter (or without the last
   * character when `chr==0`).
   */
  msvc8::string STR_Chop(StrArg str, char chr);
  msvc8::string STR_ToLower(StrArg str);        // 0x00938A80
  /**
   * Address: 0x009389C0 (FUN_009389C0, gpg::STR_ToUpper)
   *
   * What it does:
   * Returns one uppercase ASCII copy of `str`.
   */
  msvc8::string STR_ToUpper(StrArg str);
  void STR_NormalizeFilenameLowerSlash(msvc8::string& inOut);
  void STR_NormalizeFilenameLowerSlash(std::string& inOut);

  /**
   * Address: 0x0051E2E0 (FUN_0051E2E0, func_StringInitFilename)
   *
   * What it does:
   * Initializes destination string storage and canonicalizes one filename/path
   * (lowercase + separator normalization).
   */
  msvc8::string* STR_InitFilename(msvc8::string* out, StrArg in);
  msvc8::string* STR_SetFilename(msvc8::string* out, StrArg in);

  /**
   * Address: 0x0050E460 (FUN_0050E460, gpg::STR_CopyFilename)
   *
   * What it does:
   * Copies one filename string through the filename canonicalization lane.
   */
  msvc8::string* STR_CopyFilename(msvc8::string* out, const msvc8::string* filename);

  /**
   * Address: 0x00458450 (FUN_00458450, gpg::STR_CanonizeFilename)
   *
   * What it does:
   * Lowercases one path and normalizes `/` separators to `\\`.
   */
  void STR_CanonizeFilename(msvc8::string* out, StrArg in);
  /**
   * Address: 0x009388C0 (FUN_009388C0, gpg::STR_TrimWhitespace)
   *
   * What it does:
   * Trims leading/trailing ASCII whitespace (`' '`, `'\t'`, `'\r'`, `'\n'`)
   * from one input C-string and returns the trimmed copy.
   */
  msvc8::string STR_TrimWhitespace(StrArg str);

  /**
   * Address: 0x00938F10 (FUN_00938F10)
   * Mangled: ?STR_Printf@gpg@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PBDZZ
   *
   * What it does:
   * Starts one varargs lane at `fmt` and forwards formatting through `STR_Va`.
   */
  msvc8::string STR_Printf(const char* fmt, ...);

  /**
   * Address: 0x00938E00 (FUN_00938E00)
   * Mangled: ?STR_Va@gpg@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@AAPBD@Z
   *
   * What it does:
   * Formats one vararg message into stack buffer first, then grows a dynamic
   * buffer until `_vsnprintf` succeeds.
   */
  msvc8::string STR_Va(const char*& fmt, va_list va);
} // namespace gpg
