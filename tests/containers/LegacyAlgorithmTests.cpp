// fa::sort and its pieces (src/legacy/algorithms/Sort.h), fa::remove and fa::remove_if
// (Remove.h), against the std:: algorithms.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <functional>
#include <iterator>
#include <list>
#include <numeric>
#include <random>
#include <utility>
#include <vector>

#include "legacy/algorithms/Remove.h"
#include "legacy/algorithms/Sort.h"
#include "legacy/containers/List.h"

namespace
{
  struct Keyed
  {
    int key;
    int payload;
  };

  [[nodiscard]] bool KeyLess(const Keyed& a, const Keyed& b)
  {
    return a.key < b.key;
  }

  enum class Pattern
  {
    Random,
    FewDistinct,
    Sorted,
    Reversed,
    AllEqual,
    OrganPipe,
    Sawtooth,
  };

  [[nodiscard]] std::vector<int> Make(const Pattern pattern, const std::size_t n, std::mt19937& rng)
  {
    std::vector<int> v(n);
    for (std::size_t i = 0; i < n; ++i) {
      const int index = static_cast<int>(i);
      switch (pattern) {
      case Pattern::Random:
        v[i] = static_cast<int>(rng() % 100000u);
        break;
      case Pattern::FewDistinct:
        v[i] = static_cast<int>(rng() % 4u);
        break;
      case Pattern::Sorted:
        v[i] = index;
        break;
      case Pattern::Reversed:
        v[i] = static_cast<int>(n) - index;
        break;
      case Pattern::AllEqual:
        v[i] = 7;
        break;
      case Pattern::OrganPipe:
        v[i] = std::min(index, static_cast<int>(n) - index);
        break;
      case Pattern::Sawtooth:
        v[i] = index % 17;
        break;
      }
    }
    return v;
  }

  constexpr Pattern kPatterns[] = {
    Pattern::Random,
    Pattern::FewDistinct,
    Pattern::Sorted,
    Pattern::Reversed,
    Pattern::AllEqual,
    Pattern::OrganPipe,
    Pattern::Sawtooth,
  };

  constexpr std::size_t kSizes[] = {0, 1, 2, 3, 4, 31, 32, 33, 40, 41, 42, 100, 257, 1000, 20000};
} // namespace

TEST(FaSort, MatchesStdSortOnEveryPattern)
{
  std::mt19937 rng(1);
  for (const Pattern pattern : kPatterns) {
    for (const std::size_t n : kSizes) {
      SCOPED_TRACE(::testing::Message() << "pattern " << static_cast<int>(pattern) << " n " << n);
      std::vector<int> v = Make(pattern, n, rng);
      std::vector<int> expected = v;
      std::sort(expected.begin(), expected.end());
      fa::sort(v.data(), v.data() + v.size(), std::less<int>{});
      ASSERT_EQ(v, expected);
    }
  }
}

TEST(FaSort, CustomComparator)
{
  std::mt19937 rng(2);
  for (const std::size_t n : kSizes) {
    std::vector<int> v = Make(Pattern::Random, n, rng);
    std::vector<int> expected = v;
    std::sort(expected.begin(), expected.end(), std::greater<int>{});
    fa::sort(v.data(), v.data() + v.size(), std::greater<int>{});
    ASSERT_EQ(v, expected) << n;
  }
}

TEST(FaSort, KeyedSortIsAPermutationInKeyOrder)
{
  std::mt19937 rng(3);
  for (const std::size_t n : kSizes) {
    std::vector<Keyed> v(n);
    for (std::size_t i = 0; i < n; ++i) {
      v[i] = Keyed{static_cast<int>(rng() % 10u), static_cast<int>(i)};
    }
    const std::vector<Keyed> original = v;
    fa::sort(v.data(), v.data() + v.size(), KeyLess);
    ASSERT_TRUE(std::is_sorted(v.begin(), v.end(), KeyLess)) << n;
    std::vector<int> payloads;
    for (const Keyed& k : v) {
      payloads.push_back(k.payload);
    }
    std::sort(payloads.begin(), payloads.end());
    std::vector<int> all(n);
    std::iota(all.begin(), all.end(), 0);
    ASSERT_EQ(payloads, all) << n;
    for (const Keyed& k : v) {
      ASSERT_EQ(original[static_cast<std::size_t>(k.payload)].key, k.key);
    }
  }
}

TEST(FaSort, HeapFallbackSortsWhenTheDepthBudgetIsSpent)
{
  std::mt19937 rng(4);
  for (const std::ptrdiff_t budget : {0, 1, 2}) {
    for (const std::size_t n : {33u, 100u, 1000u}) {
      std::vector<int> v = Make(Pattern::Random, n, rng);
      std::vector<int> expected = v;
      std::sort(expected.begin(), expected.end());
      fa::detail::sort_impl(v.data(), v.data() + v.size(), budget, std::less<int>{});
      ASSERT_EQ(v, expected) << "budget " << budget << " n " << n;
    }
  }
}

TEST(FaSort, MakeHeapAndSortHeap)
{
  std::mt19937 rng(5);
  for (std::size_t n = 0; n < 200; ++n) {
    std::vector<int> v = Make(n % 2 == 0 ? Pattern::Random : Pattern::FewDistinct, n, rng);
    fa::detail::make_heap(v.data(), v.data() + v.size(), std::less<int>{});
    ASSERT_TRUE(std::is_heap(v.begin(), v.end())) << n;
    std::vector<int> expected = v;
    std::sort(expected.begin(), expected.end());
    fa::detail::sort_heap(v.data(), v.data() + v.size(), std::less<int>{});
    ASSERT_EQ(v, expected) << n;
  }
}

TEST(FaSort, PartitionSplitsAroundThePivot)
{
  std::mt19937 rng(6);
  for (int round = 0; round < 2000; ++round) {
    const std::size_t n = 33 + rng() % 300u;
    std::vector<int> v = Make(round % 3 == 0 ? Pattern::FewDistinct : Pattern::Random, n, rng);
    std::vector<int> sortedBefore = v;
    std::sort(sortedBefore.begin(), sortedBefore.end());
    const std::pair<int*, int*> equal = fa::detail::unguarded_partition(v.data(), v.data() + v.size(), std::less<int>{});
    ASSERT_LT(equal.first, equal.second);
    const int pivot = *equal.first;
    for (const int* p = v.data(); p != equal.first; ++p) {
      ASSERT_LT(*p, pivot) << "round " << round;
    }
    for (const int* p = equal.first; p != equal.second; ++p) {
      ASSERT_EQ(*p, pivot) << "round " << round;
    }
    for (const int* p = equal.second; p != v.data() + v.size(); ++p) {
      ASSERT_GT(*p, pivot) << "round " << round;
    }
    std::sort(v.begin(), v.end());
    ASSERT_EQ(v, sortedBefore) << "round " << round;
  }
}

TEST(FaSort, InsertionSortIsStable)
{
  // MSVC8's _Insertion_sort shifts each element past the greater ones only, so equal keys keep
  // their order.
  std::mt19937 rng(7);
  for (std::size_t n = 0; n <= 40; ++n) {
    std::vector<Keyed> v(n);
    for (std::size_t i = 0; i < n; ++i) {
      v[i] = Keyed{static_cast<int>(rng() % 4u), static_cast<int>(i)};
    }
    std::vector<Keyed> expected = v;
    std::stable_sort(expected.begin(), expected.end(), KeyLess);
    fa::detail::insertion_sort(v.data(), v.data() + v.size(), KeyLess);
    for (std::size_t i = 0; i < n; ++i) {
      ASSERT_EQ(v[i].key, expected[i].key) << n;
      ASSERT_EQ(v[i].payload, expected[i].payload) << n;
    }
  }
}

TEST(FaSort, RotateMatchesStdRotate)
{
  for (std::size_t n = 0; n <= 14; ++n) {
    for (std::size_t middle = 0; middle <= n; ++middle) {
      std::vector<int> v(n);
      std::iota(v.begin(), v.end(), 0);
      std::vector<int> expected = v;
      std::rotate(expected.begin(), expected.begin() + static_cast<std::ptrdiff_t>(middle), expected.end());
      fa::detail::rotate(v.data(), v.data() + middle, v.data() + n);
      ASSERT_EQ(v, expected) << "n " << n << " middle " << middle;
    }
  }
}

TEST(FaSort, Median3OrdersThree)
{
  std::vector<int> v{1, 2, 3};
  do {
    std::vector<int> w = v;
    fa::detail::median3(&w[0], &w[1], &w[2], std::less<int>{});
    ASSERT_EQ(w, (std::vector<int>{1, 2, 3}));
  } while (std::next_permutation(v.begin(), v.end()));
  std::vector<int> twins{2, 1, 2};
  fa::detail::median3(&twins[0], &twins[1], &twins[2], std::less<int>{});
  EXPECT_EQ(twins, (std::vector<int>{1, 2, 2}));
}

// --- remove ------------------------------------------------------------------------------------

TEST(FaRemove, MatchesStdRemove)
{
  std::mt19937 rng(8);
  for (int round = 0; round < 3000; ++round) {
    std::vector<int> v(rng() % 30u);
    for (int& x : v) {
      x = static_cast<int>(rng() % 4u);
    }
    const int value = static_cast<int>(rng() % 4u);
    std::vector<int> expected = v;
    const auto expectedEnd = std::remove(expected.begin(), expected.end(), value);
    int* const end = fa::remove(v.data(), v.data() + v.size(), value);
    ASSERT_EQ(end - v.data(), expectedEnd - expected.begin()) << "round " << round;
    ASSERT_TRUE(std::equal(v.data(), end, expected.begin())) << "round " << round;
  }
}

TEST(FaRemove, RemoveIfMatchesStdRemoveIf)
{
  std::mt19937 rng(9);
  const auto odd = [](const int x) { return (x & 1) != 0; };
  for (int round = 0; round < 3000; ++round) {
    std::vector<int> v(rng() % 30u);
    for (int& x : v) {
      x = static_cast<int>(rng() % 10u);
    }
    std::vector<int> expected = v;
    const auto expectedEnd = std::remove_if(expected.begin(), expected.end(), odd);
    int* const end = fa::remove_if(v.data(), v.data() + v.size(), odd);
    ASSERT_EQ(end - v.data(), expectedEnd - expected.begin()) << "round " << round;
    ASSERT_TRUE(std::equal(v.data(), end, expected.begin())) << "round " << round;
  }
}

TEST(FaRemove, NothingAndEverything)
{
  std::vector<int> v{1, 2, 3};
  EXPECT_EQ(fa::remove(v.data(), v.data() + 3, 9), v.data() + 3);
  EXPECT_EQ(v, (std::vector<int>{1, 2, 3}));
  std::vector<int> same{4, 4, 4};
  EXPECT_EQ(fa::remove(same.data(), same.data() + 3, 4), same.data());
  int* const none = nullptr;
  EXPECT_EQ(fa::remove(none, none, 1), none);
  EXPECT_EQ(fa::remove_if(none, none, [](int) { return true; }), none);
}

TEST(FaRemove, WorksOnListIterators)
{
  fa::list<int> list;
  std::list<int> ref;
  for (const int x : {1, 2, 1, 3, 1, 4}) {
    list.push_back(x);
    ref.push_back(x);
  }
  const auto end = fa::remove(list.begin(), list.end(), 1);
  const auto refEnd = std::remove(ref.begin(), ref.end(), 1);
  std::vector<int> got;
  for (auto it = list.begin(); it != end; ++it) {
    got.push_back(*it);
  }
  EXPECT_EQ(got, std::vector<int>(ref.begin(), refEnd));
}
