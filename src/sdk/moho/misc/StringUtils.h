#pragma once

#include <locale>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"

namespace msvc8
{
  struct string;
}

namespace moho
{
  /**
   * Trim leading/trailing ASCII spaces; returns [outBegin,outEnd).
   */
  inline void TrimRange(const char* s, size_t n, const char*& outBegin, const char*& outEnd);

  /**
   * Split by commas, trim tokens, skip empty.
   * Writes into out (appends).
   */
  inline void SplitByComma(const msvc8::string& src, msvc8::vector<msvc8::string>& out);

  /**
   * Join strings with a separator.
   */
  inline msvc8::string Join(const msvc8::vector<msvc8::string>& items, const char* sep);

  /**
   * Check exact, case-sensitive membership in comma-separated list.
   * Returns true if 'name' equals any trimmed token in 'ignoreList'.
   */
  inline bool IsNameIgnored(const msvc8::string& ignoreList, const char* name);

  /**
   * Address: 0x0050E010 (FUN_0050E010, ?BP_ShortId@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV23@@Z)
   *
   * What it does:
   * Returns the substring between the slash and dot lookup lanes used by
   * binary BP id canonicalization.
   */
  msvc8::string BP_ShortId(const msvc8::string& idText);

  /**
   * Address: 0x0048E0C0 (FUN_0048E0C0, Moho::URI_Split)
   *
   * gpg::StrArg,std::basic_string<char,std::char_traits<char>,std::allocator<char>> &,...
   *
   * What it does:
   * Splits one URI into `scheme`, `authority`, `path`, `query`, and `fragment`
   * lanes using the original URI parser rules.
   */
  bool URI_Split(
    gpg::StrArg uri,
    msvc8::string* scheme,
    msvc8::string* authority,
    msvc8::string* path,
    msvc8::string* query,
    msvc8::string* fragment
  );
} // namespace moho
