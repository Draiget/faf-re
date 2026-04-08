#pragma once

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
  using StrArg = const char*;
  using WStrArg = const wchar_t*;

  extern msvc8::string sWhitespaceChars; // 0x00F32308

  int STR_Utf8ByteOffset(StrArg str, int pos);                          // 0x009380A0
  int STR_Utf8Len(char const*);                                         // 0x00938070
  const char* STR_NextUtf8Char(const char* str);                        // 0x00938040
  const char* STR_PreviousUtf8Char(const char* str, const char* start); // 0x00938020
  /**
   * Address: 0x009387D0 (FUN_009387D0, gpg::STR_Utf8SubString)
   *
   * What it does:
   * Returns one UTF-8 codepoint-range substring; throws `std::out_of_range`
   * when `pos` starts past the end of the source string.
   */
  msvc8::string STR_Utf8SubString(StrArg str, int pos, int len);
  char* STR_EncodeUtf8Char(char*, wchar_t, const char*);                // 0x00937F90
  const char* STR_DecodeUtf8Char(const char*, wchar_t&);                // 0x00937EF0
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
  int STR_GetNextWordStartIndex(msvc8::string& str, int pos);                           // 0x00938570
  bool STR_EndsWith(StrArg str, StrArg end);                                            // 0x00938190
  bool STR_StartsWith(StrArg str, StrArg start);                                        // 0x00938210
  bool STR_EndsWithNoCase(StrArg str, StrArg end);                                      // 0x00938250
  bool STR_StartsWithNoCase(StrArg str, StrArg start);                                  // 0x009382B0
  bool STR_EqualsNoCaseN(StrArg lhs, StrArg rhs, std::size_t count);
  int STR_CompareNoCase(StrArg lhs, StrArg rhs);
  bool STR_ContainsNoCase(StrArg str, StrArg needle);
  bool STR_EqualsNoCase(StrArg lhs, StrArg rhs);
  bool STR_IsIdent(StrArg str);                                                    // 0x009382F0
  int STR_Replace(msvc8::string& str, StrArg what, StrArg with, unsigned int unk); // 0x00938B40
  int STR_ParseUInt32(StrArg str);                                                 // 0x00938150
  int STR_Xtoi(StrArg str);                                                        // 0x009380F0
  bool STR_IsAsciiWhitespace(char ch);
  bool STR_MatchWildcard(StrArg, StrArg); // 0x00938450
  bool STR_MatchWildcard(StrArg, StrArg, bool caseSensitive);
  bool STR_WildcardValidPrefix(StrArg, StrArg); // 0x00938470
  bool STR_WildcardValidPrefix(StrArg, StrArg, bool caseSensitive);

  msvc8::string STR_GetWhitespaceCharacters();  // 0x00938C80
  msvc8::string STR_Chop(StrArg str, char chr); // 0x00938BF0
  msvc8::string STR_ToLower(StrArg str);        // 0x00938A80
  msvc8::string STR_ToUpper(StrArg str);        // 0x009389C0
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
  msvc8::string STR_TrimWhitespace(StrArg str); // 0x009388C0

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
