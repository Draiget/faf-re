#pragma once

#include <locale>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/Vector.h"

namespace fa
{
  struct string;
}

namespace moho
{
  /**
   * Trim leading/trailing ASCII spaces; returns [outBegin,outEnd).
   */
  void TrimRange(const char* s, size_t n, const char*& outBegin, const char*& outEnd);

  /**
   * Split by commas, trim tokens, skip empty.
   * Writes into out (appends).
   */
  void SplitByComma(const fa::string& src, fa::vector<fa::string>& out);

  /**
   * Join strings with a separator.
   */
  fa::string Join(const fa::vector<fa::string>& items, const char* sep);

  /**
   * Check exact, case-sensitive membership in comma-separated list.
   * Returns true if 'name' equals any trimmed token in 'ignoreList'.
   */
  bool IsNameIgnored(const fa::string& ignoreList, const char* name);

  /**
   * Address: 0x0050E010 (FUN_0050E010, ?BP_ShortId@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV23@@Z)
   *
   * What it does:
   * Returns the substring between the slash and dot lookup lanes used by
   * binary BP id canonicalization.
   */
  fa::string BP_ShortId(const fa::string& idText);

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
    fa::string* scheme,
    fa::string* authority,
    fa::string* path,
    fa::string* query,
    fa::string* fragment
  );
} // namespace moho
