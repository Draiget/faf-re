// fa::set, fa::multiset, fa::map, fa::multimap (src/legacy/containers/Set.h, Map.h, RbTree.h)
// against their std:: counterparts, with the red-black invariants checked after every step,
// and the sentinel-tree helpers of Tree.h.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <functional>
#include <iterator>
#include <map>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "ContainerTestTypes.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/Tree.h"

namespace
{
  using faf_container_tests::Values;

  template <class V>
  using RbNode = fa::detail::rb_node<V>;

  struct SetKey
  {
    [[nodiscard]] const int& operator()(const int& v) const noexcept
    {
      return v;
    }
  };

  struct MapKey
  {
    template <class Pair>
    [[nodiscard]] const int& operator()(const Pair& v) const noexcept
    {
      return v.first;
    }
  };

  template <class V, class KeyOf, class Less>
  struct RbWalk
  {
    const RbNode<V>* head;
    KeyOf keyOf;
    Less less;
    std::size_t count = 0;
    int blackHeight = -1;
    const RbNode<V>* first = nullptr;
    const RbNode<V>* previous = nullptr;
    std::string error;

    RbWalk(const RbNode<V>* const h, const KeyOf k, const Less l)
      : head(h)
      , keyOf(k)
      , less(l)
    {}

    void Walk(const RbNode<V>* const n, const int blacks)
    {
      if (!error.empty()) {
        return;
      }
      if (n == head) {
        if (blackHeight < 0) {
          blackHeight = blacks;
        } else if (blackHeight != blacks) {
          error = "two paths with different black counts";
        }
        return;
      }
      if (n->isNil != 0) {
        error = "a nil node that is not the head";
        return;
      }
      if (n->left != head && n->left->parent != n) {
        error = "a left child whose parent link is wrong";
        return;
      }
      if (n->right != head && n->right->parent != n) {
        error = "a right child whose parent link is wrong";
        return;
      }
      if (n->color == fa::detail::kRbRed && (n->left->color == fa::detail::kRbRed || n->right->color == fa::detail::kRbRed)) {
        error = "a red node with a red child";
        return;
      }
      const int below = blacks + (n->color == fa::detail::kRbBlack ? 1 : 0);
      Walk(n->left, below);
      if (previous != nullptr && less(keyOf(n->value), keyOf(previous->value))) {
        error = "keys out of order";
        return;
      }
      if (first == nullptr) {
        first = n;
      }
      previous = n;
      ++count;
      Walk(n->right, below);
    }
  };

  /** The red-black and header invariants of an fa tree whose head is `head`. */
  template <class V, class KeyOf, class Less = std::less<int>>
  [[nodiscard]] ::testing::AssertionResult IsValidRbTree(
    const RbNode<V>* const head, const std::size_t size, const KeyOf keyOf, const Less less = Less{})
  {
    if (head == nullptr || head->isNil == 0) {
      return ::testing::AssertionFailure() << "the head is not the nil node";
    }
    if (head->color != fa::detail::kRbBlack) {
      return ::testing::AssertionFailure() << "the head is not black";
    }
    const RbNode<V>* const root = head->parent;
    if (size == 0) {
      if (root != head || head->left != head || head->right != head) {
        return ::testing::AssertionFailure() << "an empty tree's head does not point at itself";
      }
      return ::testing::AssertionSuccess();
    }
    if (root == head || root->parent != head) {
      return ::testing::AssertionFailure() << "the root's parent is not the head";
    }
    if (root->color != fa::detail::kRbBlack) {
      return ::testing::AssertionFailure() << "the root is red";
    }
    RbWalk<V, KeyOf, Less> walk{head, keyOf, less};
    walk.Walk(root, 0);
    if (!walk.error.empty()) {
      return ::testing::AssertionFailure() << walk.error;
    }
    if (walk.count != size) {
      return ::testing::AssertionFailure() << walk.count << " nodes for size " << size;
    }
    if (head->left != walk.first || head->right != walk.previous) {
      return ::testing::AssertionFailure() << "the head's leftmost or rightmost link is stale";
    }
    return ::testing::AssertionSuccess();
  }

  template <class Map>
  [[nodiscard]] std::vector<std::pair<int, int>> Pairs(const Map& m)
  {
    std::vector<std::pair<int, int>> out;
    for (auto it = m.begin(); it != m.end(); ++it) {
      out.emplace_back(it->first, it->second);
    }
    return out;
  }

  template <class Set>
  [[nodiscard]] std::vector<int> StdValues(const Set& s)
  {
    return std::vector<int>(s.begin(), s.end());
  }

  [[nodiscard]] std::size_t Pick(std::mt19937& rng, const std::size_t maxInclusive)
  {
    return std::uniform_int_distribution<std::size_t>(0, maxInclusive)(rng);
  }

  /** The position of `it` from `begin`, or -1 for `end`. */
  template <class It>
  [[nodiscard]] std::ptrdiff_t Offset(It begin, const It it, const It end)
  {
    return it == end ? -1 : std::distance(begin, it);
  }

  void RunSetRandomOps(const unsigned seed, const int steps, const unsigned keyRange)
  {
    std::mt19937 rng(seed);
    fa::set<int> s;
    fa::set<int> other;
    std::set<int> ref;
    std::set<int> otherRef;
    for (int step = 0; step < steps; ++step) {
      const unsigned op = rng() % 13u;
      const int key = static_cast<int>(rng() % keyRange);
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op << " key " << key);
      switch (op) {
      case 0:
      case 1: {
        const auto result = s.insert(key);
        const auto expected = ref.insert(key);
        ASSERT_EQ(result.second, expected.second);
        ASSERT_EQ(*result.first, key);
        break;
      }
      case 2: {
        const auto result = s.insert(key + 0);
        ASSERT_EQ(result.second, ref.insert(key).second);
        ASSERT_EQ(*result.first, key);
        break;
      }
      case 3: {
        const auto result = s.emplace(key);
        ASSERT_EQ(result.second, ref.insert(key).second);
        ASSERT_EQ(*result.first, key);
        break;
      }
      case 4:
        ASSERT_EQ(static_cast<std::size_t>(s.erase(key)), ref.erase(key));
        break;
      case 5: {
        const auto it = s.find(key);
        ASSERT_EQ(it == s.end(), ref.find(key) == ref.end());
        if (it != s.end()) {
          const auto next = s.erase(it);
          const auto refNext = ref.erase(ref.find(key));
          ASSERT_EQ(Offset(s.begin(), next, s.end()), Offset(ref.begin(), refNext, ref.end()));
        }
        break;
      }
      case 6: {
        const int a = static_cast<int>(rng() % keyRange);
        const int lo = std::min(a, key);
        const int hi = std::max(a, key);
        const auto next = s.erase(s.lower_bound(lo), s.lower_bound(hi));
        ref.erase(ref.lower_bound(lo), ref.lower_bound(hi));
        ASSERT_TRUE(next == s.lower_bound(hi));
        break;
      }
      case 7: {
        ASSERT_EQ(static_cast<std::size_t>(s.count(key)), ref.count(key));
        ASSERT_EQ(Offset(s.begin(), s.find(key), s.end()), Offset(ref.begin(), ref.find(key), ref.end()));
        ASSERT_EQ(Offset(s.begin(), s.lower_bound(key), s.end()), Offset(ref.begin(), ref.lower_bound(key), ref.end()));
        ASSERT_EQ(Offset(s.begin(), s.upper_bound(key), s.end()), Offset(ref.begin(), ref.upper_bound(key), ref.end()));
        const auto range = s.equal_range(key);
        const auto refRange = ref.equal_range(key);
        ASSERT_EQ(Offset(s.begin(), range.first, s.end()), Offset(ref.begin(), refRange.first, ref.end()));
        ASSERT_EQ(Offset(s.begin(), range.second, s.end()), Offset(ref.begin(), refRange.second, ref.end()));
        break;
      }
      case 8: {
        std::vector<int> keys;
        for (std::size_t i = Pick(rng, 6); i > 0; --i) {
          keys.push_back(static_cast<int>(rng() % keyRange));
        }
        s.insert(keys.begin(), keys.end());
        ref.insert(keys.begin(), keys.end());
        break;
      }
      case 9:
        if (rng() % 10u == 0u) {
          s.clear();
          ref.clear();
        }
        break;
      case 10:
        other = s;
        otherRef = ref;
        break;
      case 11:
        s.swap(other);
        std::swap(ref, otherRef);
        break;
      default:
        s = std::move(other);
        ref = otherRef;
        otherRef.clear();
        ASSERT_TRUE(other.empty());
        break;
      }
      ASSERT_EQ(Values(s), StdValues(ref));
      ASSERT_EQ(Values(other), StdValues(otherRef));
      ASSERT_EQ(static_cast<std::size_t>(s.size()), ref.size());
      ASSERT_EQ(s.empty(), ref.empty());
      ASSERT_TRUE(IsValidRbTree(s.end().node(), s.size(), SetKey{}));
      ASSERT_TRUE(IsValidRbTree(other.end().node(), other.size(), SetKey{}));
    }
  }
} // namespace

TEST(FaSet, EmptySet)
{
  const fa::set<int> s;
  EXPECT_TRUE(s.empty());
  EXPECT_EQ(s.size(), 0u);
  EXPECT_TRUE(s.begin() == s.end());
  EXPECT_TRUE(s.find(1) == s.end());
  EXPECT_TRUE(s.lower_bound(1) == s.end());
  EXPECT_EQ(s.count(1), 0u);
  EXPECT_TRUE(IsValidRbTree(s.end().node(), 0, SetKey{}));
}

TEST(FaSet, RandomOpsMatchStdSetSmallKeyRange)
{
  for (unsigned seed = 1; seed <= 3; ++seed) {
    RunSetRandomOps(seed, 3000, 40u);
  }
}

TEST(FaSet, RandomOpsMatchStdSetLargeKeyRange)
{
  for (unsigned seed = 11; seed <= 12; ++seed) {
    RunSetRandomOps(seed, 3000, 100000u);
  }
}

TEST(FaSet, SequentialInsertAndEraseKeepTheTreeBalanced)
{
  fa::set<int> s;
  for (int i = 0; i < 2000; ++i) {
    ASSERT_TRUE(s.insert(i).second);
  }
  ASSERT_TRUE(IsValidRbTree(s.end().node(), s.size(), SetKey{}));
  for (int i = 2999; i >= 2000; --i) {
    ASSERT_TRUE(s.insert(i).second);
  }
  ASSERT_TRUE(IsValidRbTree(s.end().node(), s.size(), SetKey{}));
  for (int i = 0; i < 3000; i += 2) {
    ASSERT_EQ(s.erase(i), 1u);
  }
  ASSERT_TRUE(IsValidRbTree(s.end().node(), s.size(), SetKey{}));
  EXPECT_EQ(s.size(), 1500u);
  EXPECT_EQ(*s.begin(), 1);
  auto last = s.end();
  --last;
  EXPECT_EQ(*last, 2999);
}

TEST(FaSet, IteratorsStayValidAcrossOtherInsertsAndErases)
{
  fa::set<int> s;
  for (int i = 0; i < 200; ++i) {
    s.insert(i);
  }
  std::vector<const int*> addresses;
  for (int i = 1; i < 200; i += 2) {
    addresses.push_back(&*s.find(i));
  }
  for (int i = 0; i < 200; i += 2) {
    s.erase(i);
  }
  for (int i = 1000; i < 2000; ++i) {
    s.insert(i);
  }
  std::size_t index = 0;
  for (int i = 1; i < 200; i += 2, ++index) {
    ASSERT_EQ(&*s.find(i), addresses[index]) << i;
  }
}

TEST(FaSet, IterationBothWays)
{
  fa::set<int> s;
  for (const int k : {5, 3, 9, 1, 7}) {
    s.insert(k);
  }
  std::vector<int> backwards;
  auto it = s.end();
  while (it != s.begin()) {
    --it;
    backwards.push_back(*it);
  }
  EXPECT_EQ(backwards, (std::vector<int>{9, 7, 5, 3, 1}));
  auto post = s.begin();
  EXPECT_EQ(*post++, 1);
  EXPECT_EQ(*post--, 3);
  EXPECT_EQ(*post, 1);
}

TEST(FaSet, EraseOfTheEndThrows)
{
  fa::set<int> s;
  s.insert(1);
  EXPECT_THROW(s.erase(s.end()), std::out_of_range);
  EXPECT_EQ(s.size(), 1u);
}

TEST(FaSet, EraseOfEverythingClearsAndCanBeReused)
{
  fa::set<int> s;
  for (int i = 0; i < 50; ++i) {
    s.insert(i);
  }
  EXPECT_TRUE(s.erase(s.begin(), s.end()) == s.end());
  EXPECT_TRUE(s.empty());
  EXPECT_TRUE(IsValidRbTree(s.end().node(), 0, SetKey{}));
  s.insert(4);
  EXPECT_EQ(Values(s), std::vector<int>{4});
}

TEST(FaSet, CopyMoveSwapAndSelfAssignment)
{
  const std::vector<int> keys{4, 8, 15, 16, 23, 42};
  fa::set<int> a(keys.begin(), keys.end());
  const fa::set<int> copy(a);
  EXPECT_EQ(Values(copy), keys);
  EXPECT_TRUE(IsValidRbTree(copy.end().node(), copy.size(), SetKey{}));

  const fa::set<int>& alias = a;
  a = alias;
  EXPECT_EQ(Values(a), keys);

  fa::set<int> moved(std::move(a));
  EXPECT_EQ(Values(moved), keys);
  EXPECT_TRUE(a.empty());
  EXPECT_TRUE(IsValidRbTree(a.end().node(), 0, SetKey{}));
  a.insert(1);

  moved.swap(a);
  EXPECT_EQ(Values(moved), std::vector<int>{1});
  EXPECT_EQ(Values(a), keys);
  fa::set<int>& mutableAlias = a;
  a = std::move(mutableAlias);
  EXPECT_EQ(Values(a), keys);
}

TEST(FaSet, CustomComparator)
{
  fa::set<int, std::greater<int>> s;
  for (const int k : {3, 1, 2}) {
    s.insert(k);
  }
  EXPECT_EQ(Values(s), (std::vector<int>{3, 2, 1}));
  EXPECT_TRUE(IsValidRbTree(s.end().node(), s.size(), SetKey{}, std::greater<int>{}));
  EXPECT_EQ(*s.lower_bound(2), 2);
  EXPECT_EQ(*s.upper_bound(2), 1);
}

// --- multiset ----------------------------------------------------------------------------------

TEST(FaMultiset, RandomOpsMatchStdMultiset)
{
  for (unsigned seed = 1; seed <= 3; ++seed) {
    std::mt19937 rng(seed);
    fa::multiset<int> s;
    std::multiset<int> ref;
    for (int step = 0; step < 3000; ++step) {
      const unsigned op = rng() % 7u;
      const int key = static_cast<int>(rng() % 30u);
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op);
      switch (op) {
      case 0:
      case 1: {
        const auto it = s.insert(key);
        ASSERT_EQ(*it, key);
        ref.insert(key);
        break;
      }
      case 2: {
        // A hint anywhere: the insert must still land in order.
        auto hint = s.begin();
        std::advance(hint, static_cast<std::ptrdiff_t>(Pick(rng, ref.size())));
        const auto it = s.insert(hint, key);
        ASSERT_EQ(*it, key);
        ref.insert(key);
        break;
      }
      case 3:
        if (!ref.empty()) {
          const std::size_t index = Pick(rng, ref.size() - 1);
          auto it = s.begin();
          std::advance(it, static_cast<std::ptrdiff_t>(index));
          auto refIt = ref.begin();
          std::advance(refIt, static_cast<std::ptrdiff_t>(index));
          ASSERT_EQ(*it, *refIt);
          const auto next = s.erase(it);
          const auto refNext = ref.erase(refIt);
          ASSERT_EQ(Offset(s.begin(), next, s.end()), Offset(ref.begin(), refNext, ref.end()));
        }
        break;
      case 4: {
        const std::size_t first = Pick(rng, ref.size());
        const std::size_t last = first + Pick(rng, ref.size() - first);
        auto a = s.begin();
        std::advance(a, static_cast<std::ptrdiff_t>(first));
        auto b = s.begin();
        std::advance(b, static_cast<std::ptrdiff_t>(last));
        auto ra = ref.begin();
        std::advance(ra, static_cast<std::ptrdiff_t>(first));
        auto rb = ref.begin();
        std::advance(rb, static_cast<std::ptrdiff_t>(last));
        s.erase(a, b);
        ref.erase(ra, rb);
        break;
      }
      case 5:
        if (rng() % 10u == 0u) {
          s.clear();
          ref.clear();
        }
        break;
      default: {
        fa::multiset<int> moved(std::move(s));
        ASSERT_TRUE(s.empty());
        s.swap(moved);
        break;
      }
      }
      ASSERT_EQ(Values(s), StdValues(ref));
      ASSERT_EQ(static_cast<std::size_t>(s.size()), ref.size());
      ASSERT_TRUE(IsValidRbTree(s.end().node(), s.size(), SetKey{}));
    }
  }
}

// Bug: rb_tree's copy constructor and copy assignment re-insert the source with insert_unique
// (copy_from in RbTree.h), so a copied multiset or multimap loses every duplicate key. MSVC8's
// _Tree copies the structure (_Copy) and keeps them, as std:: does. Minimal input: a multiset
// {1, 1}; its copy is {1}.
TEST(FaMultiset, DISABLED_CopyKeepsDuplicates)
{
  fa::multiset<int> s;
  s.insert(1);
  s.insert(1);
  const fa::multiset<int> copy(s);
  EXPECT_EQ(Values(copy), (std::vector<int>{1, 1}));
  fa::multiset<int> assigned;
  assigned = s;
  EXPECT_EQ(Values(assigned), (std::vector<int>{1, 1}));
}

// --- map ---------------------------------------------------------------------------------------

TEST(FaMap, RandomOpsMatchStdMap)
{
  for (unsigned seed = 1; seed <= 4; ++seed) {
    std::mt19937 rng(seed);
    fa::map<int, int> m;
    fa::map<int, int> other;
    std::map<int, int> ref;
    std::map<int, int> otherRef;
    for (int step = 0; step < 3000; ++step) {
      const unsigned op = rng() % 16u;
      const int key = static_cast<int>(rng() % 60u);
      const int value = static_cast<int>(rng() % 1000u);
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op << " key " << key);
      switch (op) {
      case 0:
        m[key] += value;
        ref[key] += value;
        break;
      case 1: {
        const auto result = m.insert({key, value});
        const auto expected = ref.insert({key, value});
        ASSERT_EQ(result.second, expected.second);
        ASSERT_EQ(result.first->first, key);
        ASSERT_EQ(result.first->second, expected.first->second);
        break;
      }
      case 2: {
        auto hint = m.begin();
        std::advance(hint, static_cast<std::ptrdiff_t>(Pick(rng, ref.size())));
        const auto it = m.insert(hint, {key, value});
        ASSERT_EQ(it->first, key);
        ref.insert({key, value});
        ASSERT_EQ(it->second, ref[key]);
        break;
      }
      case 3: {
        // A hint at the right place: lower_bound and the end.
        const auto hint = (rng() & 1u) != 0u ? m.lower_bound(key) : m.end();
        const auto it = m.insert(hint, {key, value});
        ASSERT_EQ(it->first, key);
        ref.insert({key, value});
        break;
      }
      case 4: {
        const auto result = m.emplace(key, value);
        ASSERT_EQ(result.second, ref.emplace(key, value).second);
        break;
      }
      case 5:
        ASSERT_EQ(m.erase(key), ref.erase(key));
        break;
      case 6: {
        const auto it = m.find(key);
        ASSERT_EQ(it == m.end(), ref.find(key) == ref.end());
        if (it != m.end()) {
          const auto next = m.erase(it);
          const auto refNext = ref.erase(ref.find(key));
          ASSERT_EQ(Offset(m.begin(), next, m.end()), Offset(ref.begin(), refNext, ref.end()));
        }
        break;
      }
      case 7: {
        const int a = static_cast<int>(rng() % 60u);
        const int lo = std::min(a, key);
        const int hi = std::max(a, key);
        m.erase(m.lower_bound(lo), m.upper_bound(hi));
        ref.erase(ref.lower_bound(lo), ref.upper_bound(hi));
        break;
      }
      case 8: {
        const auto found = ref.find(key);
        int* const got = m.try_get(key);
        ASSERT_EQ(got == nullptr, found == ref.end());
        if (got != nullptr) {
          ASSERT_EQ(*got, found->second);
          ASSERT_EQ(m.at(key), found->second);
          m.at(key) = value;
          found->second = value;
        }
        const fa::map<int, int>& constMap = m;
        ASSERT_EQ(constMap.try_get(key) == nullptr, found == ref.end());
        break;
      }
      case 9: {
        const fa::map<int, int>& constMap = m;
        const std::map<int, int>& constRef = ref;
        ASSERT_EQ(m.count(key), ref.count(key));
        ASSERT_EQ(Offset(constMap.begin(), constMap.find(key), constMap.end()), Offset(constRef.begin(), constRef.find(key), constRef.end()));
        ASSERT_EQ(Offset(m.begin(), m.lower_bound(key), m.end()), Offset(ref.begin(), ref.lower_bound(key), ref.end()));
        ASSERT_EQ(Offset(m.begin(), m.upper_bound(key), m.end()), Offset(ref.begin(), ref.upper_bound(key), ref.end()));
        const auto range = constMap.equal_range(key);
        const auto refRange = ref.equal_range(key);
        ASSERT_EQ(Offset(constMap.begin(), range.first, constMap.end()), Offset(ref.begin(), refRange.first, ref.end()));
        ASSERT_EQ(Offset(constMap.begin(), range.second, constMap.end()), Offset(ref.begin(), refRange.second, ref.end()));
        break;
      }
      case 10:
        if (rng() % 10u == 0u) {
          m.clear();
          ref.clear();
        }
        break;
      case 11:
        other = m;
        otherRef = ref;
        break;
      case 12:
        m.swap(other);
        std::swap(ref, otherRef);
        break;
      case 13:
        m = std::move(other);
        ref = otherRef;
        otherRef.clear();
        ASSERT_TRUE(other.empty());
        break;
      default:
        for (auto it = m.begin(); it != m.end(); ++it) {
          it->second += 1;
        }
        for (auto& entry : ref) {
          entry.second += 1;
        }
        break;
      }
      ASSERT_EQ(Pairs(m), Pairs(ref));
      ASSERT_EQ(Pairs(other), Pairs(otherRef));
      ASSERT_EQ(m.size(), ref.size());
      ASSERT_TRUE(m.basic_sanity());
      ASSERT_TRUE(IsValidRbTree(m.end().node(), m.size(), MapKey{}));
      ASSERT_TRUE(IsValidRbTree(other.end().node(), other.size(), MapKey{}));
    }
  }
}

TEST(FaMap, SubscriptInsertsAValueInitialisedEntry)
{
  fa::map<int, int> m;
  EXPECT_EQ(m[5], 0);
  EXPECT_EQ(m.size(), 1u);
  m[5] = 9;
  EXPECT_EQ(m[5], 9);
  EXPECT_EQ(m.size(), 1u);
  EXPECT_NE(m.header_ptr(), nullptr);
}

TEST(FaMap, CopyIsDeepAndEqual)
{
  fa::map<int, int> m;
  for (int i = 0; i < 100; ++i) {
    m[i * 3 % 101] = i;
  }
  fa::map<int, int> copy(m);
  EXPECT_EQ(Pairs(copy), Pairs(m));
  copy[1000] = 1;
  EXPECT_EQ(m.count(1000), 0u);
  const fa::map<int, int>& alias = copy;
  copy = alias;
  EXPECT_EQ(copy.size(), 101u);
  EXPECT_TRUE(IsValidRbTree(copy.end().node(), copy.size(), MapKey{}));
}

// --- multimap ----------------------------------------------------------------------------------

TEST(FaMultimap, RandomOpsMatchStdMultimap)
{
  for (unsigned seed = 1; seed <= 3; ++seed) {
    std::mt19937 rng(seed);
    fa::multimap<int, int> m;
    std::multimap<int, int> ref;
    for (int step = 0; step < 3000; ++step) {
      const unsigned op = rng() % 8u;
      const int key = static_cast<int>(rng() % 25u);
      const int value = step;
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op << " key " << key);
      switch (op) {
      case 0:
      case 1:
      case 2: {
        // Without a hint an equal key goes after the ones already there, as in std::.
        const auto it = m.insert({key, value});
        ASSERT_EQ(it->second, value);
        ref.insert({key, value});
        break;
      }
      case 3:
        ASSERT_EQ(m.erase(key), ref.erase(key));
        break;
      case 4: {
        const auto it = m.find(key);
        ASSERT_EQ(it == m.end(), ref.find(key) == ref.end());
        if (it != m.end()) {
          ASSERT_EQ(it->first, key);
          ASSERT_EQ(Offset(m.begin(), it, m.end()), Offset(ref.begin(), ref.lower_bound(key), ref.end()));
          const auto next = m.erase(it);
          const auto refNext = ref.erase(ref.lower_bound(key));
          ASSERT_EQ(Offset(m.begin(), next, m.end()), Offset(ref.begin(), refNext, ref.end()));
        }
        break;
      }
      case 5: {
        ASSERT_EQ(m.count(key), ref.count(key));
        const auto range = m.equal_range(key);
        const auto refRange = ref.equal_range(key);
        ASSERT_EQ(Offset(m.begin(), range.first, m.end()), Offset(ref.begin(), refRange.first, ref.end()));
        ASSERT_EQ(Offset(m.begin(), range.second, m.end()), Offset(ref.begin(), refRange.second, ref.end()));
        ASSERT_EQ(Offset(m.begin(), m.upper_bound(key), m.end()), Offset(ref.begin(), ref.upper_bound(key), ref.end()));
        break;
      }
      case 6:
        m.erase(m.lower_bound(key), m.upper_bound(key + 3));
        ref.erase(ref.lower_bound(key), ref.upper_bound(key + 3));
        break;
      default:
        if (rng() % 10u == 0u) {
          m.clear();
          ref.clear();
        }
        break;
      }
      ASSERT_EQ(Pairs(m), Pairs(ref));
      ASSERT_EQ(m.size(), ref.size());
      ASSERT_TRUE(IsValidRbTree(m.end().node(), m.size(), MapKey{}));
    }
  }
}

TEST(FaMultimap, HintedInsertsKeepTheKeysInOrder)
{
  std::mt19937 rng(17);
  fa::multimap<int, int> m;
  std::multimap<int, int> ref;
  for (int step = 0; step < 3000; ++step) {
    const int key = static_cast<int>(rng() % 20u);
    auto hint = m.begin();
    std::advance(hint, static_cast<std::ptrdiff_t>(Pick(rng, ref.size())));
    const auto it = m.insert(hint, {key, step});
    ASSERT_EQ(it->first, key);
    ASSERT_EQ(it->second, step);
    ref.insert({key, step});
    ASSERT_TRUE(IsValidRbTree(m.end().node(), m.size(), MapKey{})) << "step " << step;
  }
  std::vector<std::pair<int, int>> got = Pairs(m);
  std::vector<std::pair<int, int>> expected = Pairs(ref);
  std::sort(got.begin(), got.end());
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(got, expected);
}

TEST(FaMultimap, MoveAndSwap)
{
  fa::multimap<int, int> a;
  a.insert({1, 1});
  a.insert({1, 2});
  fa::multimap<int, int> b(std::move(a));
  EXPECT_TRUE(a.empty());
  EXPECT_EQ(Pairs(b), (std::vector<std::pair<int, int>>{{1, 1}, {1, 2}}));
  a.insert({2, 0});
  a.swap(b);
  EXPECT_EQ(a.size(), 2u);
  EXPECT_EQ(b.size(), 1u);
  b = std::move(a);
  EXPECT_EQ(b.size(), 2u);
  EXPECT_TRUE(a.empty());
}

// Bug: the copy re-inserts with insert_unique (see FaMultiset.DISABLED_CopyKeepsDuplicates).
// Minimal input: {1: 1, 1: 2}; its copy is {1: 1}.
TEST(FaMultimap, DISABLED_CopyKeepsDuplicates)
{
  fa::multimap<int, int> m;
  m.insert({1, 1});
  m.insert({1, 2});
  const fa::multimap<int, int> copy(m);
  EXPECT_EQ(Pairs(copy), (std::vector<std::pair<int, int>>{{1, 1}, {1, 2}}));
}

// --- Tree.h ------------------------------------------------------------------------------------

namespace
{
  struct KeyNode : fa::NodeBase
  {
    int key = 0;
  };

  /** An unbalanced search tree on `head` in the layout Tree.h walks: null children. */
  void BuildSearchTree(fa::Head& head, const std::vector<int>& keys)
  {
    fa::reset_empty(&head);
    for (const int key : keys) {
      auto* const node = new KeyNode();
      node->key = key;
      node->left = nullptr;
      node->right = nullptr;
      if (head.parent == &head) {
        node->parent = &head;
        head.parent = node;
        head.left = node;
        head.right = node;
        continue;
      }
      fa::NodeBase* cur = head.parent;
      for (;;) {
        fa::NodeBase*& child = key < static_cast<KeyNode*>(cur)->key ? cur->left : cur->right;
        if (child == nullptr) {
          child = node;
          node->parent = cur;
          break;
        }
        cur = child;
      }
      if (key < static_cast<KeyNode*>(head.left)->key) {
        head.left = node;
      }
      if (key >= static_cast<KeyNode*>(head.right)->key) {
        head.right = node;
      }
    }
  }

  [[nodiscard]] std::vector<int> WalkKeys(fa::Head& head)
  {
    std::vector<int> keys;
    for (fa::NodeBase* n = fa::leftmost(&head); n != fa::end(&head); n = fa::next(n, &head)) {
      keys.push_back(static_cast<KeyNode*>(n)->key);
    }
    return keys;
  }

  /** Frees a tree built by BuildSearchTree, children first. */
  void FreeSubtree(fa::NodeBase* const n)
  {
    if (n == nullptr) {
      return;
    }
    FreeSubtree(n->left);
    FreeSubtree(n->right);
    delete static_cast<KeyNode*>(n);
  }

  void FreeSearchTree(fa::Head& head)
  {
    if (head.parent != &head) {
      FreeSubtree(head.parent);
    }
    fa::reset_empty(&head);
  }

  /** Records the nodes it is handed and frees them only when it is told to. */
  struct RecordingDeleter
  {
    static inline std::vector<fa::NodeBase*> handed;
    void operator()(fa::NodeBase* const n) const
    {
      handed.push_back(n);
    }
    static void FreeAll()
    {
      for (fa::NodeBase* const n : handed) {
        delete static_cast<KeyNode*>(n);
      }
      handed.clear();
    }
  };

  struct FreeingDeleter
  {
    void operator()(fa::NodeBase* const n) const noexcept
    {
      delete static_cast<KeyNode*>(n);
    }
  };
} // namespace

TEST(FaTree, NextWalksASearchTreeInOrder)
{
  std::mt19937 rng(3);
  for (int round = 0; round < 300; ++round) {
    std::vector<int> keys;
    for (std::size_t i = Pick(rng, 40); i > 0; --i) {
      keys.push_back(static_cast<int>(rng() % 100u));
    }
    fa::Head head{};
    BuildSearchTree(head, keys);
    std::vector<int> sorted = keys;
    std::stable_sort(sorted.begin(), sorted.end());
    ASSERT_EQ(WalkKeys(head), sorted) << "round " << round;

    // clear_all hands every node over once and empties the head. The nodes are freed after the
    // walk (see DISABLED_ClearAllWithAFreeingDeleter).
    std::vector<int> visited;
    std::vector<fa::NodeBase*> nodes;
    fa::clear_all(&head, [&visited, &nodes](fa::NodeBase* const n) {
      visited.push_back(static_cast<KeyNode*>(n)->key);
      nodes.push_back(n);
    });
    ASSERT_EQ(visited, sorted);
    ASSERT_EQ(fa::root(&head), &head);
    ASSERT_EQ(fa::leftmost(&head), &head);
    ASSERT_EQ(fa::rightmost(&head), &head);
    for (fa::NodeBase* const n : nodes) {
      delete static_cast<KeyNode*>(n);
    }
  }
}

TEST(FaTree, EraseRangeVisitsEachNodeOfTheRange)
{
  fa::Head head{};
  BuildSearchTree(head, {50, 20, 70, 10, 30, 60, 80});
  fa::NodeBase* first = fa::leftmost(&head);
  first = fa::next(first, &head);  // 20
  fa::NodeBase* last = first;
  for (int i = 0; i < 3; ++i) {
    last = fa::next(last, &head);  // 30, 50, 60
  }
  std::vector<int> visited;
  fa::erase_range(&head, first, last, [&visited](fa::NodeBase* const n) { visited.push_back(static_cast<KeyNode*>(n)->key); });
  EXPECT_EQ(visited, (std::vector<int>{20, 30, 50}));
  FreeSearchTree(head);
  fa::clear_all(static_cast<fa::Head*>(nullptr), [](fa::NodeBase*) {});
}

TEST(FaTree, EmbeddedTreeHandsEveryNodeToItsDeleter)
{
  RecordingDeleter::handed.clear();
  {
    fa::EmbeddedTree<RecordingDeleter> tree;
    EXPECT_EQ(fa::leftmost(tree.head()), tree.head());
    BuildSearchTree(*tree.head(), {5, 2, 8, 1, 9, 3});
    EXPECT_EQ(WalkKeys(*tree.head()), (std::vector<int>{1, 2, 3, 5, 8, 9}));
    tree.clear();
    EXPECT_EQ(RecordingDeleter::handed.size(), 6u);
    EXPECT_EQ(fa::root(tree.head()), tree.head());
    BuildSearchTree(*tree.head(), {4, 6});
  }
  EXPECT_EQ(RecordingDeleter::handed.size(), 8u);
  RecordingDeleter::FreeAll();
}

// Bug (no callers in src/): erase_range, clear_all and EmbeddedTree::clear walk the tree in order
// and destroy each node right after taking its successor, but next() climbs through the parents
// of a node without a right child, and in order those parents were destroyed already. With a
// deleter that frees, the walk reads freed nodes. Minimal input: root 50 with right child 70;
// after 50 is freed, next(70) reads 50->right. MSVC8's _Erase frees children first.
TEST(FaTree, DISABLED_ClearAllWithAFreeingDeleter)
{
  fa::EmbeddedTree<FreeingDeleter> tree;
  BuildSearchTree(*tree.head(), {50, 70, 60, 80, 20});
  tree.clear();
  EXPECT_EQ(fa::root(tree.head()), tree.head());
}

TEST(FaTree, SentinelLowerBoundMatchesTheSet)
{
  using Node = RbNode<int>;
  std::mt19937 rng(23);
  for (int round = 0; round < 50; ++round) {
    fa::set<int> s;
    for (std::size_t i = Pick(rng, 60); i > 0; --i) {
      s.insert(static_cast<int>(rng() % 200u));
    }
    Node* const head = s.end().node();
    const auto nodeLess = [](const Node& n, const int key) { return n.value < key; };
    for (int key = -1; key <= 201; ++key) {
      ASSERT_EQ((fa::lower_bound_node<Node, &Node::isNil>(head, key, nodeLess)), s.lower_bound(key).node()) << key;
      // With only a node-less-than-key test it cannot reject a greater node: it is lower_bound
      // (see DISABLED_FindEqualOrHeadGivesTheHeadForAnAbsentKey).
      ASSERT_EQ((fa::find_equal_or_head_node<Node, &Node::isNil>(head, key, nodeLess)), s.lower_bound(key).node()) << key;
      ASSERT_EQ((fa::lower_bound_node<Node, &Node::parent, &Node::left, &Node::right, &Node::isNil>(head, key, nodeLess)),
                s.lower_bound(key).node());
    }
  }
  const fa::MemberSentinelTree<Node, &Node::parent, &Node::left, &Node::right, &Node::isNil> none{nullptr};
  EXPECT_FALSE(none.valid());
  EXPECT_EQ(none.lower_bound(1, [](const Node&, int) { return false; }), nullptr);
  EXPECT_EQ(none.find_equal_or_head(1, [](const Node&, int) { return false; }), nullptr);
}

// Bug (no callers in src/): find_equal_or_head returns the lower bound even when its key is
// greater than the one searched, because the only test it has is node < key, and its final
// `nodeLessThanKey(*candidate, key)` is always false for a lower bound. Minimal input: a set {5}
// and key 3: it returns the node of 5, not the head.
TEST(FaTree, DISABLED_FindEqualOrHeadGivesTheHeadForAnAbsentKey)
{
  using Node = RbNode<int>;
  fa::set<int> s;
  s.insert(5);
  Node* const head = s.end().node();
  const auto nodeLess = [](const Node& n, const int key) { return n.value < key; };
  EXPECT_EQ((fa::find_equal_or_head_node<Node, &Node::isNil>(head, 3, nodeLess)), head);
}
