// The gpg string helpers (src/gpg/core/containers/String.h, String.cpp): UTF-8 walking and
// coding, tokens, word starts, prefix and case tests, wildcards, filenames, printf.

#include <gtest/gtest.h>

#include <cstddef>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "gpg/core/containers/String.h"

namespace
{
  // "a", "é" (2 bytes), "€" (3 bytes), U+1F600 (4 bytes).
  constexpr const char kMixed[] = "a\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80";

  [[nodiscard]] char Fold(const char c)
  {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  }

  /** '*' matches any run, '?' one character. */
  [[nodiscard]] bool ReferenceMatch(const char* const t, const char* const p, const bool fold)
  {
    if (*p == '*') {
      return ReferenceMatch(t, p + 1, fold) || (*t != '\0' && ReferenceMatch(t + 1, p, fold));
    }
    if (*t == '\0') {
      return *p == '\0';
    }
    if (*p == '?' || (fold ? Fold(*p) == Fold(*t) : *p == *t)) {
      return ReferenceMatch(t + 1, p + 1, fold);
    }
    return false;
  }

  /**
   * The case-sensitive matcher of the binary (0x009383D0): the classic last-star backtracking,
   * except that a star that ends the pattern matches only an empty rest (CScrLuaObjectFactory
   * relies on it: "STR_MatchWildcard never matches a pattern that ends in `*`").
   */
  [[nodiscard]] bool ReferenceMatchCaseSensitive(const char* t, const char* p)
  {
    const char* starPattern = nullptr;
    const char* starText = nullptr;
    for (;;) {
      if (*p == '*') {
        ++p;
        if (*p == '\0') {
          return *t == '\0';
        }
        starPattern = p;
        starText = t;
        continue;
      }
      if (*t == '\0') {
        return *p == '\0';
      }
      if (*p == '?' || *p == *t) {
        ++p;
        ++t;
        continue;
      }
      if (starPattern == nullptr) {
        return false;
      }
      p = starPattern;
      t = ++starText;
    }
  }

  /** Some continuation of `t` matches `p`. */
  [[nodiscard]] bool ReferenceValidPrefix(const char* const t, const char* const p, const bool fold)
  {
    if (*t == '\0') {
      return true;
    }
    if (*p == '*') {
      return ReferenceValidPrefix(t, p + 1, fold) || ReferenceValidPrefix(t + 1, p, fold);
    }
    if (*p == '\0') {
      return false;
    }
    if (*p == '?' || (fold ? Fold(*p) == Fold(*t) : *p == *t)) {
      return ReferenceValidPrefix(t + 1, p + 1, fold);
    }
    return false;
  }

  [[nodiscard]] std::string RandomOf(std::mt19937& rng, const char* const alphabet, const std::size_t alphabetSize, const std::size_t maxLength)
  {
    std::string out;
    for (std::size_t n = rng() % (maxLength + 1); n > 0; --n) {
      out.push_back(alphabet[rng() % alphabetSize]);
    }
    return out;
  }
} // namespace

TEST(GpgString, Utf8LengthsAndOffsets)
{
  EXPECT_EQ(gpg::STR_Utf8Len(kMixed), 4);
  EXPECT_EQ(gpg::STR_Utf8Len(""), 0);
  EXPECT_EQ(gpg::STR_Utf8ByteOffset(kMixed, 0), 0);
  EXPECT_EQ(gpg::STR_Utf8ByteOffset(kMixed, 1), 1);
  EXPECT_EQ(gpg::STR_Utf8ByteOffset(kMixed, 2), 3);
  EXPECT_EQ(gpg::STR_Utf8ByteOffset(kMixed, 3), 6);
  EXPECT_EQ(gpg::STR_Utf8ByteOffset(kMixed, 4), 10);
  EXPECT_EQ(gpg::STR_Utf8ByteOffset(kMixed, 9), 10);

  const char* p = kMixed;
  std::vector<std::ptrdiff_t> forward;
  while (*p != '\0') {
    p = gpg::STR_NextUtf8Char(p);
    forward.push_back(p - kMixed);
  }
  EXPECT_EQ(forward, (std::vector<std::ptrdiff_t>{1, 3, 6, 10}));
  EXPECT_EQ(gpg::STR_NextUtf8Char(p), p);

  std::vector<std::ptrdiff_t> backward;
  while (p != kMixed) {
    p = gpg::STR_PreviousUtf8Char(p, kMixed);
    backward.push_back(p - kMixed);
  }
  EXPECT_EQ(backward, (std::vector<std::ptrdiff_t>{6, 3, 1, 0}));
  EXPECT_EQ(gpg::STR_PreviousUtf8Char(kMixed, kMixed), kMixed);
}

TEST(GpgString, Utf8SubString)
{
  EXPECT_EQ(gpg::STR_Utf8SubString(kMixed, 1, 2).view(), "\xC3\xA9\xE2\x82\xAC");
  EXPECT_EQ(gpg::STR_Utf8SubString("abc", 1, 5).view(), "bc");
  EXPECT_EQ(gpg::STR_Utf8SubString("abc", 3, 1).view(), "");
  EXPECT_EQ(gpg::STR_Utf8SubString("abc", 0, 0).view(), "");
  EXPECT_THROW((void)gpg::STR_Utf8SubString("abc", 4, 1), std::out_of_range);
}

TEST(GpgString, EncodeDecodeRoundTripsEveryBmpUnit)
{
  for (unsigned int code = 1; code <= 0xFFFFu; ++code) {
    const wchar_t c = static_cast<wchar_t>(code);
    char buffer[4]{};
    char* const end = gpg::STR_EncodeUtf8Char(buffer, c, buffer + sizeof(buffer));
    const std::ptrdiff_t length = end - buffer;
    ASSERT_EQ(length, code < 0x80u ? 1 : (code < 0x800u ? 2 : 3)) << code;
    wchar_t decoded = 0;
    const char* const next = gpg::STR_DecodeUtf8Char(buffer, decoded);
    ASSERT_EQ(static_cast<unsigned int>(decoded), code);
    ASSERT_EQ(next, end) << code;
  }
}

TEST(GpgString, EncodeStopsAtTheLimit)
{
  char buffer[3]{};
  EXPECT_EQ(gpg::STR_EncodeUtf8Char(buffer, L'\x20AC', buffer + 2), buffer);
  EXPECT_EQ(gpg::STR_EncodeUtf8Char(buffer, L'\xE9', buffer + 1), buffer);
  EXPECT_EQ(gpg::STR_EncodeUtf8Char(buffer, L'a', buffer), buffer);
  EXPECT_EQ(gpg::STR_EncodeUtf8Char(buffer, L'a', nullptr), buffer + 1);
}

TEST(GpgString, DecodeStopsAtATruncatedSequence)
{
  wchar_t c = 0;
  const char truncated[] = "\xC3";
  EXPECT_EQ(gpg::STR_DecodeUtf8Char(truncated, c), truncated + 1);
  const char fourBytes[] = "\xF0\x9F\x98\x80";
  EXPECT_EQ(gpg::STR_DecodeUtf8Char(fourBytes, c), fourBytes + 4);
  const char plain[] = "z";
  EXPECT_EQ(gpg::STR_DecodeUtf8Char(plain, c), plain + 1);
  EXPECT_EQ(c, L'z');
}

TEST(GpgString, WideAndUtf8Conversions)
{
  const std::wstring wide = L"abc \x00E9\x20AC\x0416\xFFFD";
  const fa::string utf8 = gpg::STR_WideToUtf8(wide.c_str());
  EXPECT_EQ(utf8.view(), "abc \xC3\xA9\xE2\x82\xAC\xD0\x96\xEF\xBF\xBD");
  EXPECT_EQ(gpg::STR_Utf8ToWide(utf8.c_str()), wide);
  EXPECT_TRUE(gpg::STR_WideToUtf8(nullptr).empty());
  EXPECT_TRUE(gpg::STR_Utf8ToWide(nullptr).empty());
}

TEST(GpgString, Tokens)
{
  const char* find = "  a,b,,c ";
  fa::string token;
  ASSERT_TRUE(gpg::STR_GetToken(find, " ,", token));
  EXPECT_EQ(token.view(), "a");
  ASSERT_TRUE(gpg::STR_GetToken(find, " ,", token));
  EXPECT_EQ(token.view(), "b");
  ASSERT_TRUE(gpg::STR_GetToken(find, " ,", token));
  EXPECT_EQ(token.view(), "c");
  EXPECT_FALSE(gpg::STR_GetToken(find, " ,", token));
  EXPECT_EQ(find, nullptr);
  EXPECT_TRUE(token.empty());

  fa::vector<fa::string> tokens;
  gpg::STR_GetTokens("/maps/SCMP_001//scenario.lua", "/", tokens);
  ASSERT_EQ(tokens.size(), 3u);
  EXPECT_EQ(tokens[0].view(), "maps");
  EXPECT_EQ(tokens[1].view(), "SCMP_001");
  EXPECT_EQ(tokens[2].view(), "scenario.lua");
  fa::vector<fa::string> none;
  gpg::STR_GetTokens("///", "/", none);
  EXPECT_TRUE(none.empty());
}

TEST(GpgString, WordStarts)
{
  fa::string text("hello brave world");
  EXPECT_EQ(gpg::STR_GetNextWordStartIndex(text, 0), 6);
  EXPECT_EQ(gpg::STR_GetNextWordStartIndex(text, 6), 12);
  EXPECT_EQ(gpg::STR_GetNextWordStartIndex(text, 12), 17);
  EXPECT_EQ(gpg::STR_GetNextWordStartIndex(text, 40), 17);
  EXPECT_EQ(gpg::STR_GetWordStartIndex(text, 8), 6);
  EXPECT_EQ(gpg::STR_GetWordStartIndex(text, 6), 0);
  EXPECT_EQ(gpg::STR_GetWordStartIndex(text, 12), 6);
  EXPECT_EQ(gpg::STR_GetWordStartIndex(text, 17), 12);
  fa::string single("x");
  EXPECT_EQ(gpg::STR_GetWordStartIndex(single, 1), 0);
  fa::string empty;
  EXPECT_EQ(gpg::STR_GetNextWordStartIndex(empty, 0), 0);
}

TEST(GpgString, PrefixesAndSuffixes)
{
  EXPECT_TRUE(gpg::STR_EndsWith("abc", "bc"));
  // A string never ends with itself (retail 0x00938190: strlen(str) > strlen(end)).
  EXPECT_FALSE(gpg::STR_EndsWith("abc", "abc"));
  EXPECT_TRUE(gpg::STR_EndsWith("abc", ""));
  EXPECT_FALSE(gpg::STR_EndsWith("", ""));
  EXPECT_FALSE(gpg::STR_EndsWith("abc", "xbc"));
  EXPECT_TRUE(gpg::STR_EndsWithNoCase("file.LUA", ".lua"));
  EXPECT_FALSE(gpg::STR_EndsWithNoCase(".lua", ".LUA"));
  EXPECT_TRUE(gpg::STR_StartsWith("abc", "ab"));
  EXPECT_TRUE(gpg::STR_StartsWith("abc", ""));
  EXPECT_TRUE(gpg::STR_StartsWith("abc", "abc"));
  EXPECT_FALSE(gpg::STR_StartsWith("ab", "abc"));
  EXPECT_TRUE(gpg::STR_StartsWithNoCase("/LUA/x", "/lua/"));
  EXPECT_FALSE(gpg::STR_StartsWithNoCase("/lux", "/lua"));
}

TEST(GpgString, CaseInsensitiveComparisons)
{
  EXPECT_TRUE(gpg::STR_EqualsNoCaseN("ABCdef", "abcXYZ", 3));
  EXPECT_FALSE(gpg::STR_EqualsNoCaseN("ABCdef", "abcXYZ", 4));
  EXPECT_TRUE(gpg::STR_EqualsNoCaseN(nullptr, nullptr, 0));
  EXPECT_FALSE(gpg::STR_EqualsNoCaseN(nullptr, "a", 1));
  EXPECT_TRUE(gpg::STR_EqualsNoCaseN("ab", "AB", 5));
  EXPECT_FALSE(gpg::STR_EqualsNoCaseN("ab", "abc", 5));

  EXPECT_EQ(gpg::STR_CompareNoCase("abc", "ABC"), 0);
  EXPECT_LT(gpg::STR_CompareNoCase("abc", "ABD"), 0);
  EXPECT_GT(gpg::STR_CompareNoCase("b", "A"), 0);
  EXPECT_EQ(gpg::STR_CompareNoCase(nullptr, nullptr), 0);
  EXPECT_EQ(gpg::STR_CompareNoCase(nullptr, "a"), -1);
  EXPECT_EQ(gpg::STR_CompareNoCase("a", nullptr), 1);

  EXPECT_TRUE(gpg::STR_EqualsNoCase("Hello", "hELLO"));
  EXPECT_FALSE(gpg::STR_EqualsNoCase("Hello", "Hell"));
  EXPECT_TRUE(gpg::STR_EqualsNoCase(nullptr, nullptr));
  EXPECT_FALSE(gpg::STR_EqualsNoCase("a", nullptr));

  EXPECT_TRUE(gpg::STR_ContainsNoCase("Hello World", "O wO"));
  EXPECT_FALSE(gpg::STR_ContainsNoCase("Hello World", "xyz"));
  EXPECT_TRUE(gpg::STR_ContainsNoCase("abc", ""));
  EXPECT_TRUE(gpg::STR_ContainsNoCase(nullptr, nullptr));
  EXPECT_FALSE(gpg::STR_ContainsNoCase(nullptr, "a"));
}

TEST(GpgString, FileNameOrderIsCaseInsensitiveWithACaseTieBreak)
{
  EXPECT_TRUE(gpg::STR_FileNameOrderLess("abc", "ABD"));
  EXPECT_FALSE(gpg::STR_FileNameOrderLess("ABD", "abc"));
  EXPECT_TRUE(gpg::STR_FileNameOrderLess("ABC", "abc"));
  EXPECT_FALSE(gpg::STR_FileNameOrderLess("abc", "ABC"));
  EXPECT_FALSE(gpg::STR_FileNameOrderLess("abc", "abc"));
  EXPECT_TRUE(gpg::STR_FileNameOrderLess("ab", "abc"));
  // Letters compare as upper case, so '_' (0x5F) sorts after them.
  EXPECT_TRUE(gpg::STR_FileNameOrderLess("a_", "a_b"));
  EXPECT_TRUE(gpg::STR_FileNameOrderLess("az", "a_"));
  std::mt19937 rng(9);
  const char alphabet[] = {'a', 'B', 'b', '_', 'A'};
  for (int i = 0; i < 5000; ++i) {
    const std::string a = RandomOf(rng, alphabet, sizeof(alphabet), 4);
    const std::string b = RandomOf(rng, alphabet, sizeof(alphabet), 4);
    const bool less = gpg::STR_FileNameOrderLess(a.c_str(), b.c_str());
    const bool greater = gpg::STR_FileNameOrderLess(b.c_str(), a.c_str());
    ASSERT_FALSE(less && greater) << a << " " << b;
    ASSERT_EQ(!less && !greater, a == b) << a << " " << b;
  }
}

TEST(GpgString, IdentifiersAndNumbers)
{
  EXPECT_TRUE(gpg::STR_IsIdent("_a1"));
  EXPECT_TRUE(gpg::STR_IsIdent("Z"));
  EXPECT_FALSE(gpg::STR_IsIdent(""));
  EXPECT_FALSE(gpg::STR_IsIdent("1a"));
  EXPECT_FALSE(gpg::STR_IsIdent("a-b"));

  EXPECT_EQ(gpg::STR_ParseUInt32("123"), 123);
  EXPECT_EQ(gpg::STR_ParseUInt32("0x1F"), 31);
  EXPECT_EQ(gpg::STR_ParseUInt32("0X1f"), 31);
  EXPECT_EQ(gpg::STR_ParseUInt32("12abc"), 12);
  EXPECT_EQ(gpg::STR_ParseUInt32(nullptr), 0);
  EXPECT_EQ(gpg::STR_Xtoi("ff"), 255);
  EXPECT_EQ(gpg::STR_Xtoi("7fffFFFF"), 0x7FFFFFFF);
  // The digit loop shifts before it looks at the character, as retail 0x009380F0 does
  // (`shl eax, 4` ahead of the range checks).
  EXPECT_EQ(gpg::STR_Xtoi("1g"), 16);
  EXPECT_EQ(gpg::STR_Xtoi(""), 0);
  EXPECT_EQ(gpg::STR_Xtoi(nullptr), 0);

  for (const char c : {' ', '\t', '\n', '\r', '\f', '\v'}) {
    EXPECT_TRUE(gpg::STR_IsAsciiWhitespace(c)) << static_cast<int>(c);
  }
  EXPECT_FALSE(gpg::STR_IsAsciiWhitespace('a'));
  EXPECT_FALSE(gpg::STR_IsAsciiWhitespace('\0'));
  EXPECT_EQ(gpg::STR_GetWhitespaceCharacters().view(), " \n\t\r");
}

TEST(GpgString, WildcardTargetedCases)
{
  EXPECT_TRUE(gpg::STR_MatchWildcard("abc", "abc"));
  EXPECT_FALSE(gpg::STR_MatchWildcard("abc", "abd"));
  EXPECT_TRUE(gpg::STR_MatchWildcard("abc", "a?c"));
  EXPECT_TRUE(gpg::STR_MatchWildcard("units.lua", "*.lua"));
  EXPECT_TRUE(gpg::STR_MatchWildcard("abc", "a*c"));
  EXPECT_FALSE(gpg::STR_MatchWildcard("ABC", "abc"));
  // A pattern that ends in '*' matches only when nothing is left for the star (the binary's
  // behaviour; CScrLuaObjectFactory.cpp builds its listings around it).
  EXPECT_FALSE(gpg::STR_MatchWildcard("abc", "*"));
  EXPECT_FALSE(gpg::STR_MatchWildcard("abc", "a*"));
  EXPECT_TRUE(gpg::STR_MatchWildcard("a", "a*"));
  EXPECT_TRUE(gpg::STR_MatchWildcard("", "*"));
  // '?' takes a whole UTF-8 character in the case-sensitive matcher.
  EXPECT_TRUE(gpg::STR_MatchWildcard("\xC3\xA9", "?"));
  EXPECT_TRUE(gpg::STR_MatchWildcard("x\xE2\x82\xACy", "x?y"));
  EXPECT_FALSE(gpg::STR_MatchWildcard(nullptr, "*"));
  EXPECT_FALSE(gpg::STR_MatchWildcard("a", nullptr));

  // The case-insensitive matcher lets a trailing star take the rest.
  EXPECT_TRUE(gpg::STR_MatchWildcard("ABC", "a*", false));
  EXPECT_TRUE(gpg::STR_MatchWildcard("Units.LUA", "*.lua", false));
  EXPECT_FALSE(gpg::STR_MatchWildcard("Units.LUA", "*.lux", false));

  EXPECT_TRUE(gpg::STR_WildcardValidPrefix("ab", "abc"));
  EXPECT_FALSE(gpg::STR_WildcardValidPrefix("abd", "abc"));
  EXPECT_TRUE(gpg::STR_WildcardValidPrefix("abc", "*x"));
  EXPECT_TRUE(gpg::STR_WildcardValidPrefix("", "abc"));
  EXPECT_TRUE(gpg::STR_WildcardValidPrefix("AB", "abc", false));
  EXPECT_FALSE(gpg::STR_WildcardValidPrefix(nullptr, "a"));
}

TEST(GpgString, CaseSensitiveWildcardMatchesItsReference)
{
  std::mt19937 rng(10);
  const char textAlphabet[] = {'a', 'b', 'A'};
  const char patternAlphabet[] = {'a', 'b', 'A', '?', '*'};
  for (int i = 0; i < 30000; ++i) {
    const std::string text = RandomOf(rng, textAlphabet, sizeof(textAlphabet), 6);
    const std::string pattern = RandomOf(rng, patternAlphabet, sizeof(patternAlphabet), 5);
    ASSERT_EQ(gpg::STR_MatchWildcard(text.c_str(), pattern.c_str()), ReferenceMatchCaseSensitive(text.c_str(), pattern.c_str()))
      << "'" << text << "' against '" << pattern << "'";
    if (pattern.empty() || pattern.back() != '*') {
      ASSERT_EQ(gpg::STR_MatchWildcard(text.c_str(), pattern.c_str()), ReferenceMatch(text.c_str(), pattern.c_str(), false))
        << "'" << text << "' against '" << pattern << "'";
    }
  }
}

TEST(GpgString, CaseInsensitiveWildcardMatchesItsReference)
{
  std::mt19937 rng(11);
  const char textAlphabet[] = {'a', 'b', 'A'};
  const char patternAlphabet[] = {'a', 'b', 'B', '?', '*'};
  for (int i = 0; i < 30000; ++i) {
    const std::string text = RandomOf(rng, textAlphabet, sizeof(textAlphabet), 6);
    const std::string pattern = RandomOf(rng, patternAlphabet, sizeof(patternAlphabet), 5);
    ASSERT_EQ(gpg::STR_MatchWildcard(text.c_str(), pattern.c_str(), false), ReferenceMatch(text.c_str(), pattern.c_str(), true))
      << "'" << text << "' against '" << pattern << "'";
    ASSERT_EQ(gpg::STR_WildcardValidPrefix(text.c_str(), pattern.c_str(), false), ReferenceValidPrefix(text.c_str(), pattern.c_str(), true))
      << "prefix '" << text << "' of '" << pattern << "'";
  }
}

TEST(GpgString, ReplaceWithinTheCapacity)
{
  fa::string path("a\\b\\c");
  EXPECT_EQ(gpg::STR_Replace(path, "\\", "/", 1u), 2);
  EXPECT_EQ(path.view(), "a/b/c");
  fa::string unchanged("a\\b");
  EXPECT_EQ(gpg::STR_Replace(unchanged, "\\", "/", 0u), 0);
  EXPECT_EQ(unchanged.view(), "a\\b");
  fa::string stamp("12:34:56");
  EXPECT_EQ(gpg::STR_Replace(stamp, ":", "", 1u), 2);
  EXPECT_EQ(stamp.view(), "123456");
  fa::string grown("aaa");
  EXPECT_EQ(gpg::STR_Replace(grown, "a", "aa", 1u), 3);
  EXPECT_EQ(grown.view(), "aaaaaa");
  fa::string none("abc");
  EXPECT_EQ(gpg::STR_Replace(none, "x", "y", 1u), 0);
}

// Bug: STR_Replace (retail 0x00938B40) calls a string replace that grows the buffer (0x00480DF0,
// through _Grow 0x00405C20). fa::string::replace returns false instead when the result does not
// fit the current capacity, and STR_Replace ignores that: the text stays and the count still
// goes up. Minimal input: "xx" with "x" -> "yyyyyyyyyy" gives "yyyyyyyyyyx" and 2.
TEST(GpgString, DISABLED_ReplaceGrowsPastTheCapacity)
{
  fa::string s("xx");
  EXPECT_EQ(gpg::STR_Replace(s, "x", "yyyyyyyyyy", 1u), 2);
  EXPECT_EQ(s.view(), std::string(20, 'y'));
}

TEST(GpgString, ChopTrimAndCase)
{
  EXPECT_EQ(gpg::STR_Chop("abc", 'c').view(), "ab");
  EXPECT_EQ(gpg::STR_Chop("abc", 'x').view(), "abc");
  EXPECT_EQ(gpg::STR_Chop("abc", '\0').view(), "ab");
  EXPECT_EQ(gpg::STR_Chop("", 'c').view(), "");
  EXPECT_EQ(gpg::STR_Chop(nullptr, 'c').view(), "");

  EXPECT_EQ(gpg::STR_TrimWhitespace("  \t a b \r\n").view(), "a b");
  EXPECT_EQ(gpg::STR_TrimWhitespace(" \t\r\n ").view(), "");
  EXPECT_EQ(gpg::STR_TrimWhitespace("x").view(), "x");
  EXPECT_TRUE(gpg::STR_TrimWhitespace(nullptr).empty());

  const bool lowerInPlace = gpg::str_LowerInPlace;
  for (const bool inPlace : {true, false}) {
    gpg::str_LowerInPlace = inPlace;
    EXPECT_EQ(gpg::STR_ToLower("MiXeD Case 123 \xC4").view(), "mixed case 123 \xC4") << inPlace;
    EXPECT_EQ(gpg::STR_ToLower("A Much Longer Text Than Fifteen").view(), "a much longer text than fifteen") << inPlace;
  }
  gpg::str_LowerInPlace = lowerInPlace;
  EXPECT_EQ(gpg::STR_ToUpper("MiXeD case 123").view(), "MIXED CASE 123");
}

TEST(GpgString, FilenameHelpers)
{
  fa::string mixed("Maps\\Foo/BAR.Scmap");
  gpg::STR_NormalizeFilenameLowerSlash(mixed);
  EXPECT_EQ(mixed.view(), "maps/foo/bar.scmap");
  std::string stdMixed("Maps\\Foo/BAR.Scmap");
  gpg::STR_NormalizeFilenameLowerSlash(stdMixed);
  EXPECT_EQ(stdMixed, "maps/foo/bar.scmap");

  const bool lowerInPlace = gpg::str_LowerInPlace;
  for (const bool inPlace : {true, false}) {
    gpg::str_LowerInPlace = inPlace;
    fa::string canon;
    gpg::STR_CanonizeFilename(&canon, "Maps/Foo\\Bar.SCMAP");
    EXPECT_EQ(canon.view(), "maps\\foo\\bar.scmap") << inPlace;
    gpg::STR_CanonizeFilename(&canon, nullptr);
    EXPECT_TRUE(canon.empty()) << inPlace;
  }
  gpg::str_LowerInPlace = lowerInPlace;

  // A source inside the string itself: the whole text, then a tail of it.
  fa::string self("Some/Long/Path/Name.LUA");
  gpg::STR_CanonizeFilename(&self, self.c_str());
  EXPECT_EQ(self.view(), "some\\long\\path\\name.lua");
  gpg::STR_CanonizeFilename(&self, self.c_str() + 10);
  EXPECT_EQ(self.view(), "path\\name.lua");
  gpg::STR_CanonizeFilename(nullptr, "x");

  fa::string init;
  EXPECT_EQ(gpg::STR_InitFilename(&init, "A/B"), &init);
  EXPECT_EQ(init.view(), "a\\b");
  fa::string set;
  EXPECT_EQ(gpg::STR_SetFilename(&set, "C/D"), &set);
  EXPECT_EQ(set.view(), "c\\d");
  fa::string copy;
  EXPECT_EQ(gpg::STR_CopyFilename(&copy, &init), &copy);
  EXPECT_EQ(copy.view(), "a\\b");
  EXPECT_EQ(gpg::STR_InitFilename(nullptr, "x"), nullptr);
}

TEST(GpgString, PrintfAtAndPastTheStackBuffer)
{
  EXPECT_EQ(gpg::STR_Printf("%d-%s", 42, "x").view(), "42-x");
  EXPECT_EQ(gpg::STR_Printf("").view(), "");
  const fa::string exact = gpg::STR_Printf("%0255d", 7);
  EXPECT_EQ(exact.size(), 255u);
  const fa::string past = gpg::STR_Printf("%0256d", 7);
  EXPECT_EQ(past.size(), 256u);
  const fa::string long1000 = gpg::STR_Printf("%01000d", 5);
  ASSERT_EQ(long1000.size(), 1000u);
  EXPECT_EQ(long1000.view(), std::string(999, '0') + "5");
}
