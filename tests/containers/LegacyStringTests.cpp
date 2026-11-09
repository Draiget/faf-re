// fa::string and fa::scoped_string (src/legacy/containers/String.h, String.cpp) against
// std::string.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "legacy/containers/String.h"

namespace
{
  [[nodiscard]] std::string Text(const std::size_t n, const char first = 'a')
  {
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
      out.push_back(static_cast<char>(first + static_cast<char>(i % 26u)));
    }
    return out;
  }

  /** The invariants every fa::string keeps, whatever its contents. */
  [[nodiscard]] ::testing::AssertionResult IsWellFormed(const fa::string& s)
  {
    if (!s.basic_sanity()) {
      return ::testing::AssertionFailure() << "basic_sanity() is false";
    }
    if (s.capacity() < 15u) {
      return ::testing::AssertionFailure() << "capacity " << s.capacity() << " below the inline 15";
    }
    if (s.is_sso() != (s.capacity() == 15u)) {
      return ::testing::AssertionFailure() << "is_sso() disagrees with capacity " << s.capacity();
    }
    if (s.c_str()[s.size()] != '\0') {
      return ::testing::AssertionFailure() << "no terminator at size " << s.size();
    }
    if (s.data() != s.c_str()) {
      return ::testing::AssertionFailure() << "data() and c_str() differ";
    }
    return ::testing::AssertionSuccess();
  }

  [[nodiscard]] std::size_t Pick(std::mt19937& rng, const std::size_t maxInclusive)
  {
    return std::uniform_int_distribution<std::size_t>(0, maxInclusive)(rng);
  }
} // namespace

TEST(FaString, DefaultIsEmptyAndInline)
{
  const fa::string s;
  EXPECT_TRUE(s.empty());
  EXPECT_EQ(s.size(), 0u);
  EXPECT_EQ(s.capacity(), 15u);
  EXPECT_TRUE(s.is_sso());
  EXPECT_STREQ(s.c_str(), "");
  EXPECT_TRUE(IsWellFormed(s));
}

TEST(FaString, ConstructorsAtTheInlineBoundary)
{
  for (const std::size_t n : {0u, 1u, 14u, 15u, 16u, 17u, 100u}) {
    SCOPED_TRACE(n);
    const std::string text = Text(n);
    const fa::string fromChars(text.c_str());
    const fa::string fromView(std::string_view{text});
    const fa::string fromPointerAndSize(text.data(), n);
    const fa::string fromRange(text.data(), text.data() + n);
    for (const fa::string* s : {&fromChars, &fromView, &fromPointerAndSize, &fromRange}) {
      EXPECT_EQ(s->view(), text);
      EXPECT_TRUE(IsWellFormed(*s));
      // Up to 15 characters inline; past that, the heap block is exactly the size.
      EXPECT_EQ(s->capacity(), n <= 15u ? 15u : n);
    }
  }
  const fa::string fromNull(static_cast<const char*>(nullptr));
  EXPECT_TRUE(fromNull.empty());
  const fa::string fromNullRange(nullptr, static_cast<std::size_t>(5));
  EXPECT_TRUE(fromNullRange.empty());
  const char* const text = "abc";
  const fa::string backwards(text + 2, text);
  EXPECT_TRUE(backwards.empty());
}

TEST(FaString, CopyAndAssignBetweenInlineAndHeap)
{
  const fa::string shortText("short");
  const fa::string longText(Text(40));
  for (const fa::string* source : {&shortText, &longText}) {
    for (const fa::string* start : {&shortText, &longText}) {
      fa::string target(*start);
      EXPECT_EQ(target.view(), start->view());
      target = *source;
      EXPECT_EQ(target.view(), source->view());
      EXPECT_TRUE(IsWellFormed(target));
      if (!source->is_sso()) {
        EXPECT_NE(target.c_str(), source->c_str());
      }
    }
  }
  fa::string self(Text(30));
  const fa::string& alias = self;
  self = alias;
  EXPECT_EQ(self.view(), Text(30));
  fa::string& mutableAlias = self;
  self = std::move(mutableAlias);
  EXPECT_EQ(self.view(), Text(30));
}

TEST(FaString, MoveLeavesTheSourceEmptyAndInline)
{
  fa::string heap(Text(50));
  const char* const storage = heap.c_str();
  fa::string moved(std::move(heap));
  EXPECT_EQ(moved.c_str(), storage);
  EXPECT_TRUE(heap.empty());
  EXPECT_TRUE(heap.is_sso());
  EXPECT_TRUE(IsWellFormed(heap));

  fa::string target("x");
  target = std::move(moved);
  EXPECT_EQ(target.c_str(), storage);
  EXPECT_TRUE(moved.empty());
  heap = "reused";
  EXPECT_EQ(heap.view(), "reused");
}

TEST(FaString, GrowthFollowsMsvc8)
{
  // MSVC8's _Grow: the new capacity is need | 15, or capacity + capacity / 2 when need | 15
  // is less than half again the old capacity.
  fa::string s;
  std::vector<std::size_t> capacities{s.capacity()};
  for (int i = 0; i < 200; ++i) {
    ASSERT_TRUE(s.push_back('x'));
    if (capacities.back() != s.capacity()) {
      capacities.push_back(s.capacity());
    }
  }
  EXPECT_EQ(capacities, (std::vector<std::size_t>{15, 31, 47, 70, 105, 157, 235}));
  EXPECT_EQ(s.size(), 200u);
}

TEST(FaString, SelfAppendAcrossTheInlineBoundary)
{
  fa::string s("abcdefghij");
  s += s;
  EXPECT_EQ(s.view(), "abcdefghijabcdefghij");
  s.append(s.c_str() + 5, 10);
  EXPECT_EQ(s.view(), "abcdefghijabcdefghijfghijabcde");
  s += s;
  EXPECT_EQ(s.size(), 60u);
  EXPECT_EQ(s.view().substr(30), "abcdefghijabcdefghijfghijabcde");
  EXPECT_TRUE(IsWellFormed(s));
}

TEST(FaString, RandomOpsMatchStdString)
{
  for (unsigned seed = 1; seed <= 6; ++seed) {
    std::mt19937 rng(seed);
    fa::string s;
    std::string ref;
    for (int step = 0; step < 3000; ++step) {
      const unsigned op = rng() % 20u;
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op);
      const std::string piece = Text(Pick(rng, 20), static_cast<char>('A' + rng() % 26u));
      switch (op) {
      case 0:
        ASSERT_TRUE(s.append(piece.data(), piece.size()));
        ref += piece;
        break;
      case 1:
        ASSERT_TRUE(s.append(std::string_view{piece}));
        ref += piece;
        break;
      case 2: {
        const std::size_t count = Pick(rng, 20);
        ASSERT_TRUE(s.append(count, '#'));
        ref.append(count, '#');
        break;
      }
      case 3:
        ASSERT_TRUE(s.push_back('z'));
        ref.push_back('z');
        break;
      case 4:
        s += piece.c_str();
        ref += piece;
        break;
      case 5: {
        const fa::string other(piece.c_str());
        s += other;
        ref += piece;
        break;
      }
      case 6: {
        const std::size_t pos = Pick(rng, ref.size() + 2);
        const std::size_t count = (rng() & 1u) != 0u ? fa::string::npos : Pick(rng, 10);
        s.erase(pos, count);
        if (pos < ref.size()) {
          ref.erase(pos, count);
        }
        break;
      }
      case 7: {
        const std::size_t n = Pick(rng, ref.size() + 30);
        ASSERT_TRUE(s.resize(n, '-'));
        ref.resize(n, '-');
        break;
      }
      case 8:
        if (rng() % 4u == 0u) {
          s.clear();
          ref.clear();
        }
        break;
      case 9: {
        const std::size_t n = Pick(rng, 200);
        s.reserve(n);
        ASSERT_GE(s.capacity(), std::min<std::size_t>(n, fa::string::maxCapGuard));
        break;
      }
      case 10: {
        // replace never grows: it reports false and leaves the text when the result doesn't fit.
        const std::size_t pos = Pick(rng, ref.size());
        const std::size_t count = Pick(rng, 8);
        const std::size_t removed = std::min(count, ref.size() - pos);
        const bool fits = ref.size() - removed + piece.size() <= s.capacity();
        ASSERT_EQ(s.replace(pos, count, piece), fits);
        if (fits) {
          ref.replace(pos, count, piece);
        }
        break;
      }
      case 11: {
        const std::size_t count = Pick(rng, 25);
        s.assign(count, '*');
        ref.assign(count, '*');
        break;
      }
      case 12:
        s.assign(piece.data(), piece.size());
        ref = piece;
        break;
      case 13: {
        const fa::string source(piece.c_str());
        const std::size_t pos = Pick(rng, piece.size());
        const std::size_t count = (rng() & 1u) != 0u ? fa::string::npos : Pick(rng, 10);
        s.assign(source, pos, count);
        ref = piece.substr(pos, count);
        break;
      }
      case 14:
        s = piece.c_str();
        ref = piece;
        break;
      case 15:
        s.reverse();
        std::reverse(ref.begin(), ref.end());
        break;
      case 16: {
        const std::size_t from = Pick(rng, ref.size() + 2);
        const std::size_t length = (rng() & 1u) != 0u ? fa::string::npos : Pick(rng, 12);
        const fa::string sub = s.substr(from, length);
        ASSERT_EQ(sub.view(), from < ref.size() ? ref.substr(from, length) : std::string());
        ASSERT_TRUE(IsWellFormed(sub));
        break;
      }
      case 17:
        s += s;
        ref += ref;
        if (ref.size() > 2000) {
          s.clear();
          ref.clear();
        }
        break;
      case 18: {
        const fa::string copy(s);
        s = copy + piece.c_str();
        ref += piece;
        break;
      }
      default: {
        const fa::string other(piece.c_str());
        s = other + std::string_view{"|"} + s;
        ref = piece + "|" + ref;
        if (ref.size() > 2000) {
          s.clear();
          ref.clear();
        }
        break;
      }
      }
      ASSERT_EQ(s.view(), ref);
      ASSERT_EQ(s.to_std(), ref);
      ASSERT_EQ(s.size(), ref.size());
      ASSERT_EQ(s.empty(), ref.empty());
      ASSERT_TRUE(IsWellFormed(s));
    }
  }
}

TEST(FaString, FindMatchesStdString)
{
  std::mt19937 rng(77);
  for (int step = 0; step < 3000; ++step) {
    std::string text;
    const std::size_t length = Pick(rng, 40);
    for (std::size_t i = 0; i < length; ++i) {
      text.push_back(static_cast<char>('a' + rng() % 3u));
    }
    std::string needle;
    const std::size_t needleLength = Pick(rng, 4);
    for (std::size_t i = 0; i < needleLength; ++i) {
      needle.push_back(static_cast<char>('a' + rng() % 3u));
    }
    const std::size_t pos = Pick(rng, length + 2);
    const fa::string s(text.c_str());
    SCOPED_TRACE(::testing::Message() << "'" << text << "' find '" << needle << "' from " << pos);
    ASSERT_EQ(s.find(std::string_view{needle}, pos), text.find(needle, pos));
    ASSERT_EQ(s.find(needle.data(), pos, needle.size()), text.find(needle.data(), pos, needle.size()));
    if (pos <= length) {
      ASSERT_EQ(s.find(needle.empty() ? 'a' : needle[0], pos), text.find(needle.empty() ? 'a' : needle[0], pos));
    }
  }
  const fa::string s("abc");
  EXPECT_EQ(s.find('a', 4), fa::string::npos);
  EXPECT_EQ(s.find(nullptr, 0, 2), fa::string::npos);
  EXPECT_EQ(s.find(nullptr, 1, 0), 1u);
}

TEST(FaString, CompareAndEquality)
{
  std::mt19937 rng(5);
  for (int step = 0; step < 2000; ++step) {
    const std::string a = Text(Pick(rng, 5), static_cast<char>('a' + rng() % 2u));
    const std::string b = Text(Pick(rng, 5), static_cast<char>('a' + rng() % 2u));
    const fa::string lhs(a.c_str());
    const fa::string rhs(b.c_str());
    const int expected = a.compare(b);
    const auto sign = [](const int v) { return (v > 0) - (v < 0); };
    ASSERT_EQ(sign(lhs.compare(std::string_view{b})), sign(expected)) << a << " vs " << b;
    ASSERT_EQ(sign(lhs.compare(b.c_str())), sign(expected));
    ASSERT_EQ(lhs < rhs, a < b);
    ASSERT_EQ(lhs == rhs, a == b);
    ASSERT_EQ(lhs == std::string_view{b}, a == b);
    ASSERT_EQ(std::string_view{b} == lhs, a == b);
    ASSERT_EQ(lhs == b.c_str(), a == b);
    ASSERT_EQ(b.c_str() == lhs, a == b);
    const std::size_t pos = Pick(rng, a.size() + 1);
    const std::size_t count = (rng() & 1u) != 0u ? fa::string::npos : Pick(rng, 4);
    if (pos <= a.size()) {
      ASSERT_EQ(sign(lhs.compare(pos, count, std::string_view{b})), sign(a.compare(pos, count, b)));
      ASSERT_EQ(sign(lhs.compare(pos, count, b.data(), b.size())), sign(a.compare(pos, count, b)));
    }
  }
  const fa::string empty;
  EXPECT_TRUE(empty == static_cast<const char*>(nullptr));
  EXPECT_EQ(empty.compare(static_cast<const char*>(nullptr)), 0);
  EXPECT_EQ(fa::string("ab").compare(0, 2, nullptr, 3), 1);
}

TEST(FaString, EqualsNoCaseFoldsAsciiOnly)
{
  const fa::string s("Hello World");
  EXPECT_TRUE(s.equals_no_case("hello world"));
  EXPECT_TRUE(s.equals_no_case(std::string_view{"HELLO WORLD"}));
  EXPECT_FALSE(s.equals_no_case("hello worl"));
  EXPECT_FALSE(s.equals_no_case(static_cast<const char*>(nullptr)));
  EXPECT_TRUE(fa::string().equals_no_case(static_cast<const char*>(nullptr)));
  EXPECT_FALSE(fa::string("\xC4").equals_no_case("\xE4"));
}

TEST(FaString, AssignWithAPositionPastTheEndThrows)
{
  const fa::string source("abc");
  fa::string target("keep");
  EXPECT_THROW(target.assign(source, 4), std::out_of_range);
  target.assign(source, 3);
  EXPECT_TRUE(target.empty());
  target.assign(source, 1, 1);
  EXPECT_EQ(target.view(), "b");
}

TEST(FaString, AssignFromItselfWithAnOffset)
{
  fa::string s(Text(30));
  s.assign(s, 10, 5);
  EXPECT_EQ(s.view(), Text(30).substr(10, 5));
  s.assign(s, 1);
  EXPECT_EQ(s.view(), Text(30).substr(11, 4));
  s.assign(s, 4);
  EXPECT_TRUE(s.empty());
}

TEST(FaString, ResetAndAssignReleasesTheOldBuffer)
{
  fa::string s(Text(40));
  const fa::string source("tiny");
  s.reset_and_assign(source);
  EXPECT_EQ(s.view(), "tiny");
  EXPECT_TRUE(s.is_sso());
  fa::string& alias = s;
  s.reset_and_assign(alias);
  EXPECT_EQ(s.view(), "tiny");
}

TEST(FaString, AssignInplaceOnlyWithinTheCapacity)
{
  fa::string s("abc");
  EXPECT_TRUE(s.assign_inplace("0123456789ABCDE"));
  EXPECT_EQ(s.view(), "0123456789ABCDE");
  EXPECT_FALSE(s.assign_inplace("0123456789ABCDEF"));
  EXPECT_EQ(s.view(), "0123456789ABCDE");
}

TEST(FaString, OwnedAssignmentsGiveExactCapacities)
{
  fa::string s("abc");
  s.assign_owned(std::string_view{Text(20)});
  EXPECT_EQ(s.view(), Text(20));
  EXPECT_EQ(s.capacity(), 20u);
  s.assign_owned("x");
  EXPECT_EQ(s.view(), "x");
  EXPECT_TRUE(s.is_sso());
  s.assign_owned_strong(std::string_view{Text(33)});
  EXPECT_EQ(s.capacity(), 33u);
  s.assign_owned_strong(s.view().substr(3, 4));  // a view of itself, copied before the swap
  EXPECT_EQ(s.view(), Text(33).substr(3, 4));
  s.assign_owned_strong(static_cast<const char*>(nullptr));
  EXPECT_TRUE(s.empty());
  EXPECT_TRUE(IsWellFormed(s));
}

TEST(FaString, TidyKeepsAPrefixInline)
{
  fa::string s(Text(30));
  s.tidy(true, 5u);
  EXPECT_EQ(s.view(), Text(5));
  EXPECT_TRUE(s.is_sso());
  s.eos(2u);
  EXPECT_EQ(s.view(), Text(2));
  s.eos(100u);
  EXPECT_EQ(s.size(), 15u);
}

TEST(FaString, ConcatenationOperators)
{
  const fa::string a("abc");
  const fa::string b(Text(20));
  EXPECT_EQ((a + b).view(), "abc" + Text(20));
  EXPECT_EQ((a + std::string_view{"de"}).view(), "abcde");
  EXPECT_EQ((a + "xy").view(), "abcxy");
  EXPECT_EQ((a + static_cast<const char*>(nullptr)).view(), "abc");
  fa::string c;
  c += 'q';
  c += static_cast<const char*>(nullptr);
  EXPECT_EQ(c.view(), "q");
  EXPECT_EQ(static_cast<std::string_view>(c), "q");
  EXPECT_EQ(fa::string("ab")[1], 'b');
}

TEST(FaString, ScopedStringOwnsItsCopy)
{
  const fa::scoped_string fromChars("hello");
  EXPECT_EQ(fromChars.view(), "hello");
  const fa::scoped_string fromView(std::string_view{Text(25)});
  EXPECT_EQ(fromView.view(), Text(25));
  const fa::string plain(Text(18));
  fa::scoped_string fromString(plain);
  EXPECT_EQ(fromString.view(), Text(18));
  EXPECT_NE(fromString.c_str(), plain.c_str());
  fa::scoped_string copy(fromString);
  EXPECT_EQ(copy.view(), Text(18));

  const char* const storage = copy.c_str();
  fa::scoped_string moved(std::move(copy));
  EXPECT_EQ(moved.c_str(), storage);
  EXPECT_TRUE(copy.empty());

  copy = fromChars;
  EXPECT_EQ(copy.view(), "hello");
  copy = plain;
  EXPECT_EQ(copy.view(), Text(18));
  const fa::scoped_string& alias = copy;
  copy = alias;
  EXPECT_EQ(copy.view(), Text(18));
  copy = std::move(moved);
  EXPECT_EQ(copy.c_str(), storage);
  EXPECT_TRUE(moved.empty());
}
