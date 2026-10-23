#include "StringUtils.h"

#include <cctype>
#include <string>

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
using namespace moho;

void moho::TrimRange(const char* s, const size_t n, const char*& outBegin, const char*& outEnd)
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

void moho::SplitByComma(const msvc8::string& src, msvc8::vector<msvc8::string>& out)
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
      out.push_back(msvc8::string(tb, static_cast<size_t>(te - tb)));
    }
    i = (j < n ? j + 1 : j);
  }
}

msvc8::string moho::Join(const msvc8::vector<msvc8::string>& items, const char* sep)
{
  msvc8::string out;
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

bool moho::IsNameIgnored(const msvc8::string& ignoreList, const char* name)
{
  if (!name || ignoreList.empty()) {
    return false;
  }

  msvc8::vector<msvc8::string> tokens;
  tokens.reserve(8); // small, avoids reallocs
  SplitByComma(ignoreList, tokens);

  const size_t len = std::strlen(name);
  for (const auto& t : tokens) {
    if (t.size() == len && std::memcmp(t.c_str(), name, len) == 0) {
      return true;
    }
  }
  return false;
}

/**
 * Address: 0x0050E010 (FUN_0050E010, ?BP_ShortId@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV23@@Z)
 *
 * What it does:
 * Returns the path stem lane delimited by slash/dot markers using the same
 * index math as the original binary helper.
 */
msvc8::string moho::BP_ShortId(const msvc8::string& idText)
{
  const std::string_view text = idText.view();
  const std::size_t slash = text.find_last_of('/');
  const std::size_t start = (slash == std::string_view::npos) ? 0u : (slash + 1u);
  const std::size_t dot = text.find_last_of('.');
  const std::size_t end = (dot == std::string_view::npos || dot < start) ? text.size() : dot;
  return idText.substr(start, end - start);
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
  msvc8::string* const scheme,
  msvc8::string* const authority,
  msvc8::string* const path,
  msvc8::string* const query,
  msvc8::string* const fragment
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

  auto assignOutputs = [&](const std::string& schemeValue,
                           const std::string& authorityValue,
                           const std::string& pathValue,
                           const std::string& queryValue,
                           const std::string& fragmentValue) {
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
