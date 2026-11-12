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
   * Join strings with a separator.
   */
  fa::string Join(const fa::vector<fa::string>& items, const char* sep);

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
