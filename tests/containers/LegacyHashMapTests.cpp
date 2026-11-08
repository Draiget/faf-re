// fa::hash_map and fa::hash_set (src/legacy/containers/HashMap.h) against std::unordered_map
// and std::unordered_set, across many bucket splits.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <random>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "legacy/containers/HashMap.h"

namespace
{
  template <class HashMap>
  [[nodiscard]] std::vector<std::pair<int, int>> SortedPairs(HashMap& m)
  {
    std::vector<std::pair<int, int>> out;
    for (auto it = m.begin(); it != m.end(); ++it) {
      out.emplace_back(it->first, it->second);
    }
    std::sort(out.begin(), out.end());
    return out;
  }

  /** Every element of the table is found at its own node, and the reference agrees. */
  [[nodiscard]] ::testing::AssertionResult LookupsAgree(
    fa::hash_map<int, int>& m, const std::unordered_map<int, int>& ref, const int keyRange)
  {
    if (m.size() != ref.size()) {
      return ::testing::AssertionFailure() << "size " << m.size() << " vs " << ref.size();
    }
    for (auto it = m.begin(); it != m.end(); ++it) {
      const auto found = m.find(it->first);
      if (found == m.end() || &*found != &*it) {
        return ::testing::AssertionFailure() << "key " << it->first << " is not found at its own node";
      }
    }
    for (int key = -2; key < keyRange + 2; ++key) {
      const auto found = m.find(key);
      const auto expected = ref.find(key);
      if ((found == m.end()) != (expected == ref.end())) {
        return ::testing::AssertionFailure() << "key " << key << " found " << (found != m.end());
      }
      if (found != m.end() && found->second != expected->second) {
        return ::testing::AssertionFailure() << "key " << key << " maps to " << found->second;
      }
      const auto range = m.equal_range(key);
      const auto distance = std::distance(range.first, range.second);
      if (distance != (expected == ref.end() ? 0 : 1)) {
        return ::testing::AssertionFailure() << "key " << key << " has an equal range of " << distance;
      }
      if (distance == 0 && (range.first != m.end() || range.second != m.end())) {
        return ::testing::AssertionFailure() << "key " << key << ": an empty range that is not (end, end)";
      }
      if (m.count(key) != ref.count(key)) {
        return ::testing::AssertionFailure() << "key " << key << " counted " << m.count(key);
      }
    }
    return ::testing::AssertionSuccess();
  }

  void RunHashMapRandomOps(const unsigned seed, const int steps, const int keyRange)
  {
    std::mt19937 rng(seed);
    fa::hash_map<int, int> m;
    std::unordered_map<int, int> ref;
    for (int step = 0; step < steps; ++step) {
      const unsigned op = rng() % 10u;
      const int key = static_cast<int>(rng() % static_cast<unsigned>(keyRange));
      const int value = static_cast<int>(rng() % 1000u);
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op << " key " << key);
      switch (op) {
      case 0:
      case 1:
      case 2: {
        const auto result = m.insert({key, value});
        const auto expected = ref.insert({key, value});
        ASSERT_EQ(result.second, expected.second);
        ASSERT_EQ(result.first->first, key);
        ASSERT_EQ(result.first->second, expected.first->second);
        break;
      }
      case 3:
        m[key] += value;
        ref[key] += value;
        break;
      case 4:
        ASSERT_EQ(m.erase(key), ref.erase(key));
        break;
      case 5: {
        const auto it = m.find(key);
        if (it != m.end()) {
          m.erase(it);
          ref.erase(key);
        }
        break;
      }
      case 6: {
        // Erase a run of the list: the bucket starts must follow.
        auto first = m.begin();
        std::advance(first, static_cast<std::ptrdiff_t>(rng() % (m.size() + 1)));
        auto last = first;
        for (unsigned n = rng() % 5u; n > 0 && last != m.end(); --n) {
          ++last;
        }
        for (auto it = first; it != last; ++it) {
          ref.erase(it->first);
        }
        m.erase(first, last);
        break;
      }
      case 7:
        if (rng() % 50u == 0u) {
          m.clear();
          ref.clear();
        }
        break;
      default:
        if (!ref.empty()) {
          const auto it = m.find(key);
          if (it != m.end()) {
            it->second = value;
            ref[key] = value;
          }
        }
        break;
      }
      ASSERT_EQ(m.size(), ref.size());
      ASSERT_EQ(m.empty(), ref.empty());
      if (step % 25 == 0 || step == steps - 1) {
        ASSERT_TRUE(LookupsAgree(m, ref, keyRange));
        ASSERT_EQ(SortedPairs(m), SortedPairs(ref));
      }
    }
  }
} // namespace

TEST(FaHashValue, IsTheParkMillerStep)
{
  // Schrage's method for 16807 * key mod (2^31 - 1).
  EXPECT_EQ(fa::hash_value(0L), 0u);
  EXPECT_EQ(fa::hash_value(1L), 16807u);
  std::mt19937 rng(1);
  for (int i = 0; i < 10000; ++i) {
    const long key = static_cast<long>(rng() % 2147483647u);
    const auto expected = static_cast<std::size_t>((16807LL * key) % 2147483647LL);
    ASSERT_EQ(fa::hash_value(key), expected) << key;
  }
}

TEST(FaHashValue, CompareHashesIntegersAndPointersWithTheSeed)
{
  const fa::hash_compare<unsigned int> ints;
  EXPECT_EQ(ints(5u), fa::hash_value(static_cast<long>(static_cast<std::size_t>(5u) ^ fa::hash_seed)));
  int object = 0;
  const fa::hash_compare<int*> pointers;
  EXPECT_EQ(
    pointers(&object), fa::hash_value(static_cast<long>(reinterpret_cast<std::uintptr_t>(&object) ^ fa::hash_seed)));
  EXPECT_TRUE(ints(1u, 2u));
  EXPECT_FALSE(ints(2u, 1u));
  EXPECT_EQ(fa::hash_compare<int>::bucket_size, 4u);
  EXPECT_EQ(fa::hash_compare<int>::min_buckets, 8u);
}

TEST(FaHashMap, EmptyMap)
{
  fa::hash_map<int, int> m;
  EXPECT_TRUE(m.empty());
  EXPECT_EQ(m.size(), 0u);
  EXPECT_EQ(m.begin(), m.end());
  EXPECT_EQ(m.find(3), m.end());
  EXPECT_EQ(m.count(3), 0u);
  EXPECT_EQ(m.erase(3), 0u);
}

TEST(FaHashMap, RandomOpsMatchUnorderedMapFewKeys)
{
  for (unsigned seed = 1; seed <= 3; ++seed) {
    RunHashMapRandomOps(seed, 3000, 50);
  }
}

TEST(FaHashMap, RandomOpsMatchUnorderedMapManyKeys)
{
  for (unsigned seed = 11; seed <= 12; ++seed) {
    RunHashMapRandomOps(seed, 6000, 3000);
  }
}

TEST(FaHashMap, GrowsThroughManySplits)
{
  fa::hash_map<int, int> m;
  std::unordered_map<int, int> ref;
  for (int i = 0; i < 5000; ++i) {
    const int key = i * 7919 % 10007;
    ASSERT_TRUE(m.insert({key, i}).second);
    ref.emplace(key, i);
  }
  ASSERT_TRUE(LookupsAgree(m, ref, 10007));
  for (int i = 0; i < 5000; i += 3) {
    const int key = i * 7919 % 10007;
    ASSERT_EQ(m.erase(key), 1u);
    ref.erase(key);
  }
  ASSERT_TRUE(LookupsAgree(m, ref, 10007));
}

TEST(FaHashMap, EraseOfEverythingClearsAndCanBeReused)
{
  fa::hash_map<int, int> m;
  for (int i = 0; i < 300; ++i) {
    m[i] = i;
  }
  const auto next = m.erase(m.begin(), m.end());
  EXPECT_EQ(next, m.end());
  EXPECT_TRUE(m.empty());
  for (int i = 0; i < 300; ++i) {
    m[i] = -i;
  }
  std::unordered_map<int, int> ref;
  for (int i = 0; i < 300; ++i) {
    ref[i] = -i;
  }
  EXPECT_TRUE(LookupsAgree(m, ref, 300));
}

TEST(FaHashMap, SubscriptInsertsAValueInitialisedEntry)
{
  fa::hash_map<int, int> m;
  EXPECT_EQ(m[7], 0);
  m[7] = 3;
  EXPECT_EQ(m[7], 3);
  EXPECT_EQ(m.size(), 1u);
}

TEST(FaHashMap, MoveKeepsTheBuckets)
{
  fa::hash_map<int, int> m;
  std::unordered_map<int, int> ref;
  for (int i = 0; i < 500; ++i) {
    m[i * 3] = i;
    ref[i * 3] = i;
  }
  fa::hash_map<int, int> moved(std::move(m));
  EXPECT_TRUE(LookupsAgree(moved, ref, 1500));
  m.clear();
  m[1] = 1;
  EXPECT_EQ(m.size(), 1u);
  EXPECT_NE(m.find(1), m.end());
}

// Bug: hash_table has no copy constructor of its own, so a copy copies the bucket vector of
// list iterators as it is: they still point into the source's list, and the copy's lookups walk
// the source's nodes (a dangling walk once the source is gone). MSVC8's _Hash copy rebuilds the
// buckets (_Copy). Minimal input: a hash_map {1: 1}; copy.find(1) returns the source's node.
TEST(FaHashMap, DISABLED_CopyFindsItsOwnElements)
{
  fa::hash_map<int, int> m;
  for (int i = 0; i < 20; ++i) {
    m[i] = i;
  }
  fa::hash_map<int, int> copy(m);
  std::set<const void*> own;
  for (auto it = copy.begin(); it != copy.end(); ++it) {
    own.insert(&*it);
  }
  for (int i = 0; i < 20; ++i) {
    const auto found = copy.find(i);
    ASSERT_NE(found, copy.end()) << i;
    EXPECT_EQ(own.count(&*found), 1u) << i;
  }
}

TEST(FaHashSet, RandomOpsWithPointerKeys)
{
  std::vector<int> objects(400);
  std::mt19937 rng(5);
  fa::hash_set<int*> s;
  std::unordered_set<int*> ref;
  for (int step = 0; step < 5000; ++step) {
    int* const key = &objects[rng() % objects.size()];
    SCOPED_TRACE(::testing::Message() << "step " << step);
    switch (rng() % 3u) {
    case 0:
    case 1: {
      const auto result = s.insert(key);
      ASSERT_EQ(result.second, ref.insert(key).second);
      ASSERT_EQ(*result.first, key);
      break;
    }
    default:
      ASSERT_EQ(s.erase(key), ref.erase(key));
      break;
    }
    ASSERT_EQ(s.size(), ref.size());
    if (step % 50 == 0) {
      for (int& object : objects) {
        ASSERT_EQ(s.find(&object) != s.end(), ref.count(&object) == 1u);
      }
      std::vector<int*> got(s.begin(), s.end());
      std::vector<int*> expected(ref.begin(), ref.end());
      std::sort(got.begin(), got.end());
      std::sort(expected.begin(), expected.end());
      ASSERT_EQ(got, expected);
    }
  }
}

TEST(FaHashSet, UnsignedKeys)
{
  fa::hash_set<std::uintptr_t> s;
  for (std::uintptr_t i = 0; i < 1000; ++i) {
    ASSERT_TRUE(s.insert(i * 0x1000u).second);
  }
  for (std::uintptr_t i = 0; i < 1000; ++i) {
    ASSERT_FALSE(s.insert(i * 0x1000u).second);
    ASSERT_NE(s.find(i * 0x1000u), s.end());
    ASSERT_EQ(s.find(i * 0x1000u + 1u), s.end());
  }
  EXPECT_EQ(s.size(), 1000u);
}
