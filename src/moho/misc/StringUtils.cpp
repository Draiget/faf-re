#include "StringUtils.h"

#include <cctype>
#include <string>

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
using namespace moho;

void moho::TrimRange(
  const char* s,
  const size_t n,
  const char*& outBegin,
  const char*& outEnd
)
{
  const char* b = s;
  const char* e = s + n;
  while (b < e && gpg::STR_IsAsciiWhitespace(*b)) {
    ++b;
  }
  while (e > b && gpg::STR_IsAsciiWhitespace(e[-1])) {
    --e;
  }
  outBegin = b;
  outEnd = e;
}

void moho::SplitByComma(
  const fa::string& src,
  fa::vector<fa::string>& out
)
{
  const char* s = src.c_str();
  const size_t n = src.size();
  size_t i = 0;
  while (i < n) {
    // skip delimiters and spaces
    while (i < n && (s[i] == ',' || gpg::STR_IsAsciiWhitespace(s[i]))) {
      ++i;
    }
    if (i >= n) {
      break;
    }

    // read token till next comma
    size_t j = i;
    while (j < n && s[j] != ',')
      ++j;

    // trim [i, j)
    const char* tb;
    const char* te;
    TrimRange(s + i, j - i, tb, te);
    if (te > tb) {
      out.push_back(fa::string(tb, static_cast<size_t>(te - tb)));
    }
    i = (j < n ? j + 1 : j);
  }
}

fa::string moho::Join(
  const fa::vector<fa::string>& items,
  const char* sep
)
{
  fa::string out;
  if (items.empty()) {
    return out;
  }

  const size_t sepLen = std::strlen(sep);
  // Compute total size to reduce reallocations (optional; MSVC8 string has SSO=15)
  size_t total = 0;
  for (const auto& item : items) {
    total += item.size();
  }
  total += sepLen * (!items.empty() ? (items.size() - 1) : 0);
  out.reserve(total);

  for (size_t i = 0; i < items.size(); ++i) {
    if (i)
      out.append(sep);
    out.append(items[i].c_str(), items[i].size());
  }
  return out;
}

/**
 * Address: 0x0048E0C0 (FUN_0048E0C0, Moho::URI_Split)
 *
 * gpg::StrArg,std::basic_string<char,std::char_traits<char>,std::allocator<char>> &,...
 *
 * What it does:
 * Splits one URI into `scheme`, `authority`, `path`, `query`, and `fragment`
 * lanes using the original URI parser rules.
 */
bool moho::URI_Split(
  const gpg::StrArg uri,
  fa::string* const scheme,
  fa::string* const authority,
  fa::string* const path,
  fa::string* const query,
  fa::string* const fragment
)
{
  if (scheme == nullptr || authority == nullptr || path == nullptr || query == nullptr || fragment == nullptr) {
    return false;
  }

  scheme->clear();
  authority->clear();
  path->clear();
  query->clear();
  fragment->clear();

  if (uri == nullptr || uri[0] == '\0') {
    return false;
  }

  auto assignOutputs = [&](
                         const std::string& schemeValue,
                         const std::string& authorityValue,
                         const std::string& pathValue,
                         const std::string& queryValue,
                         const std::string& fragmentValue
                       ) {
    scheme->assign_owned(schemeValue);
    authority->assign_owned(authorityValue);
    path->assign_owned(pathValue);
    query->assign_owned(queryValue);
    fragment->assign_owned(fragmentValue);
  };

  const char* cursor = uri;
  char current = *cursor;
  if (!std::isalpha(static_cast<unsigned char>(current))) {
    return false;
  }

  std::string schemeValue{};
  schemeValue.push_back(current);

  ++cursor;
  current = *cursor;
  while (current != ':') {
    const unsigned char symbol = static_cast<unsigned char>(current);
    if (!std::isalnum(symbol) && current != '+' && current != '-' && current != '.') {
      return false;
    }

    schemeValue.push_back(current);
    ++cursor;
    current = *cursor;
  }

  schemeValue.push_back(current);
  ++cursor;

  std::string authorityValue{};
  std::string pathValue{};
  std::string queryValue{};
  std::string fragmentValue{};

  current = *cursor;
  if (current == '/' && cursor[1] == '/') {
    authorityValue = "//";
    current = cursor[2];
    cursor += 2;

    if (current != '/') {
      do {
        ++cursor;
        if (current == '?') {
          goto parse_query;
        }
        if (current == '#' || current == '\0') {
          goto parse_path;
        }

        authorityValue.push_back(current);
        current = *cursor;
      } while (current != '/');
    }
  }

  current = *cursor;
  ++cursor;

parse_path:
  if (current == '?') {
    goto parse_query;
  }

  while (true) {
    if (current == '#') {
      do {
        fragmentValue.push_back(current);
        current = *cursor;
        ++cursor;
      } while (current != '\0');

      assignOutputs(schemeValue, authorityValue, pathValue, queryValue, fragmentValue);
      return true;
    }

    if (current == '\0') {
      break;
    }

    pathValue.push_back(current);
    current = *cursor;
    ++cursor;
    if (current == '?') {
      break;
    }
  }

parse_query:
  while (current != '\0') {
    queryValue.push_back(current);
    current = *cursor;
    ++cursor;

    if (current == '#') {
      do {
        fragmentValue.push_back(current);
        current = *cursor;
        ++cursor;
      } while (current != '\0');
      break;
    }
  }

  assignOutputs(schemeValue, authorityValue, pathValue, queryValue, fragmentValue);
  return true;
}
