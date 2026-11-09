// fa::list (src/legacy/containers/Vector.h, List.h) and fa::queue (Queue.h) against std::list
// and std::queue.

#include <gtest/gtest.h>

#include <cstddef>
#include <iterator>
#include <list>
#include <queue>
#include <random>
#include <type_traits>
#include <utility>
#include <vector>

#include "ContainerTestTypes.h"
#include "legacy/containers/Deque.h"
#include "legacy/containers/List.h"
#include "legacy/containers/Queue.h"

namespace
{
  using faf_container_tests::Tracked;
  using faf_container_tests::Values;

  template <class List>
  [[nodiscard]] std::vector<int> ReverseValues(const List& list)
  {
    return Values(list.rbegin(), list.rend());
  }

  template <class List>
  [[nodiscard]] typename List::iterator At(List& list, const std::size_t index)
  {
    auto it = list.begin();
    std::advance(it, static_cast<std::ptrdiff_t>(index));
    return it;
  }

  [[nodiscard]] std::size_t Pick(std::mt19937& rng, const std::size_t maxInclusive)
  {
    return std::uniform_int_distribution<std::size_t>(0, maxInclusive)(rng);
  }

  [[nodiscard]] std::vector<int> ToVector(const std::list<int>& list)
  {
    return std::vector<int>(list.begin(), list.end());
  }

  [[nodiscard]] std::vector<int> ToReverseVector(const std::list<int>& list)
  {
    return std::vector<int>(list.rbegin(), list.rend());
  }

  template <class E>
  [[nodiscard]] E Make(const int v)
  {
    if constexpr (std::is_same_v<E, int>) {
      return v;
    } else {
      return E(v);
    }
  }

  template <class E>
  void RunListRandomOps(const unsigned seed, const int steps)
  {
    using List = fa::list<E>;
    std::mt19937 rng(seed);
    List a;
    List b;
    std::list<int> refA;
    std::list<int> refB;
    for (int step = 0; step < steps; ++step) {
      const unsigned op = rng() % 18u;
      const int value = static_cast<int>(rng() % 1000u);
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op);
      switch (op) {
      case 0:
        a.push_back(Make<E>(value));
        refA.push_back(value);
        break;
      case 1:
        a.push_front(Make<E>(value));
        refA.push_front(value);
        break;
      case 2:
        if (!refA.empty()) {
          a.pop_back();
          refA.pop_back();
        }
        break;
      case 3:
        if (!refA.empty()) {
          a.pop_front();
          refA.pop_front();
        }
        break;
      case 4: {
        const std::size_t pos = Pick(rng, refA.size());
        const auto it = a.insert(At(a, pos), Make<E>(value));
        ASSERT_EQ(Values(it, std::next(it)), std::vector<int>{value});
        refA.insert(At(refA, pos), value);
        break;
      }
      case 5: {
        const std::size_t pos = Pick(rng, refA.size());
        const std::size_t count = Pick(rng, 5);
        std::vector<E> source;
        std::vector<int> sourceValues;
        for (std::size_t i = 0; i < count; ++i) {
          source.push_back(Make<E>(value + static_cast<int>(i)));
          sourceValues.push_back(value + static_cast<int>(i));
        }
        const auto where = At(a, pos);
        const auto it = a.insert(where, source.begin(), source.end());
        ASSERT_EQ(it, count == 0 ? where : std::prev(where, static_cast<std::ptrdiff_t>(count)));
        refA.insert(At(refA, pos), sourceValues.begin(), sourceValues.end());
        break;
      }
      case 6:
        if (!refA.empty()) {
          const std::size_t pos = Pick(rng, refA.size() - 1);
          const auto next = a.erase(At(a, pos));
          const auto refNext = refA.erase(At(refA, pos));
          ASSERT_EQ(next == a.end(), refNext == refA.end());
        }
        break;
      case 7: {
        const std::size_t first = Pick(rng, refA.size());
        const std::size_t last = first + Pick(rng, refA.size() - first);
        const auto it = a.erase(At(a, first), At(a, last));
        ASSERT_EQ(std::distance(a.begin(), it), static_cast<std::ptrdiff_t>(first));
        refA.erase(At(refA, first), At(refA, last));
        break;
      }
      case 8: {
        // Move a range of b in front of a position of a.
        const std::size_t first = Pick(rng, refB.size());
        const std::size_t last = first + Pick(rng, refB.size() - first);
        const std::size_t where = Pick(rng, refA.size());
        a.splice(At(a, where), b, At(b, first), At(b, last));
        refA.splice(At(refA, where), refB, At(refB, first), At(refB, last));
        break;
      }
      case 9: {
        // Move a range of a within a, to a position outside it (and not its end; see
        // DISABLED_SpliceBeforeTheRangeEndIsANoOp).
        if (refA.size() < 3) {
          break;
        }
        const std::size_t first = 1 + Pick(rng, refA.size() - 2);
        const std::size_t last = first + 1 + Pick(rng, refA.size() - first - 1);
        const std::size_t where = (rng() & 1u) != 0u || last == refA.size() ? Pick(rng, first - 1) : last + 1 + Pick(rng, refA.size() - last - 1);
        if (where == last) {
          break;
        }
        a.splice(At(a, where), a, At(a, first), At(a, last));
        refA.splice(At(refA, where), refA, At(refA, first), At(refA, last));
        break;
      }
      case 10:
        if (rng() % 6u == 0u) {
          a.clear();
          refA.clear();
        }
        break;
      case 11:
        b = a;
        refB = refA;
        break;
      case 12:
        a.swap(b);
        std::swap(refA, refB);
        break;
      case 13:
        a = std::move(b);
        refA = refB;
        refB.clear();
        ASSERT_TRUE(b.empty());
        break;
      case 14: {
        List moved(std::move(a));
        a = std::move(moved);
        break;
      }
      case 15:
        if constexpr (std::is_same_v<E, int>) {
          ASSERT_EQ(a.emplace_back(value), value);
        } else {
          ASSERT_EQ(a.emplace_back(value).value, value);
        }
        refA.push_back(value);
        break;
      default:
        b.push_back(Make<E>(value));
        refB.push_back(value);
        break;
      }
      ASSERT_EQ(Values(a), ToVector(refA));
      ASSERT_EQ(ReverseValues(a), ToReverseVector(refA));
      ASSERT_EQ(Values(b), ToVector(refB));
      ASSERT_EQ(a.size(), refA.size());
      ASSERT_EQ(b.size(), refB.size());
      ASSERT_EQ(a.empty(), refA.empty());
      if (!refA.empty()) {
        if constexpr (std::is_same_v<E, int>) {
          ASSERT_EQ(a.front(), refA.front());
          ASSERT_EQ(a.back(), refA.back());
        } else {
          ASSERT_EQ(a.front().value, refA.front());
          ASSERT_EQ(a.back().value, refA.back());
        }
      }
    }
  }
} // namespace

TEST(FaList, EmptyList)
{
  const fa::list<int> list;
  EXPECT_TRUE(list.empty());
  EXPECT_EQ(list.size(), 0u);
  EXPECT_EQ(list.begin(), list.end());
  EXPECT_EQ(list.rbegin(), list.rend());
}

TEST(FaList, IteratorsStayValidAcrossInsertAndErase)
{
  fa::list<int> list;
  list.push_back(1);
  const auto two = list.insert(list.end(), 2);
  list.push_back(3);
  int* const twoAddress = &*two;
  for (int i = 0; i < 100; ++i) {
    list.push_front(-i);
    list.push_back(100 + i);
  }
  list.erase(list.begin());
  list.pop_back();
  EXPECT_EQ(&*two, twoAddress);
  EXPECT_EQ(*two, 2);
  auto next = two;
  ++next;
  EXPECT_EQ(*next, 3);
  auto prev = two;
  --prev;
  EXPECT_EQ(*prev, 1);
}

TEST(FaList, EraseOfTheEndDoesNothing)
{
  fa::list<int> list;
  list.push_back(1);
  EXPECT_EQ(list.erase(list.end()), list.begin());
  EXPECT_EQ(list.size(), 1u);
}

TEST(FaList, EraseOfEverythingClears)
{
  fa::list<int> list;
  for (int i = 0; i < 10; ++i) {
    list.push_back(i);
  }
  EXPECT_EQ(list.erase(list.begin(), list.end()), list.end());
  EXPECT_TRUE(list.empty());
  list.push_back(5);
  EXPECT_EQ(Values(list), std::vector<int>{5});
}

TEST(FaList, SpliceFromAnotherListMovesNodesAndCounts)
{
  fa::list<int> a;
  fa::list<int> b;
  for (int i = 0; i < 5; ++i) {
    a.push_back(i);
    b.push_back(10 + i);
  }
  auto first = b.begin();
  ++first;
  int* const moved = &*first;
  auto last = first;
  std::advance(last, 3);
  auto where = a.begin();
  std::advance(where, 2);
  a.splice(where, b, first, last);
  EXPECT_EQ(Values(a), (std::vector<int>{0, 1, 11, 12, 13, 2, 3, 4}));
  EXPECT_EQ(Values(b), (std::vector<int>{10, 14}));
  EXPECT_EQ(a.size(), 8u);
  EXPECT_EQ(b.size(), 2u);
  auto check = a.begin();
  std::advance(check, 2);
  EXPECT_EQ(&*check, moved);
  a.splice(a.end(), b, b.begin(), b.begin());
  EXPECT_EQ(b.size(), 2u);
}

// Bug: splice(where, *this, first, last) with where == last links the range into a cycle that
// is no longer reachable from the head; std::list (and MSVC8's, which skips the splice when
// `_Where == _Last`) leave the list as it is. The guard in fa::list::splice tests
// `whereNode == firstNode` instead. Minimal input: {1, 2, 3}, splice(it(3), self, it(1), it(3))
// leaves begin..end = {3} with size() 3.
TEST(FaList, DISABLED_SpliceBeforeTheRangeEndIsANoOp)
{
  fa::list<int> list;
  list.push_back(1);
  list.push_back(2);
  list.push_back(3);
  auto last = list.begin();
  std::advance(last, 2);
  list.splice(last, list, list.begin(), last);
  EXPECT_EQ(Values(list), (std::vector<int>{1, 2, 3}));
  EXPECT_EQ(list.size(), 3u);
}

TEST(FaList, SpliceBeforeTheRangeStartIsANoOp)
{
  fa::list<int> list;
  list.push_back(1);
  list.push_back(2);
  list.push_back(3);
  auto first = list.begin();
  ++first;
  auto last = list.end();
  list.splice(first, list, first, last);
  EXPECT_EQ(Values(list), (std::vector<int>{1, 2, 3}));
}

TEST(FaList, CopyMoveSwapAndSelfAssignment)
{
  fa::list<int> a;
  for (int i = 0; i < 6; ++i) {
    a.push_back(i);
  }
  fa::list<int> copy(a);
  EXPECT_EQ(Values(copy), Values(a));
  const fa::list<int>& alias = a;
  a = alias;
  EXPECT_EQ(Values(a), (std::vector<int>{0, 1, 2, 3, 4, 5}));

  fa::list<int> moved(std::move(copy));
  EXPECT_TRUE(copy.empty());
  EXPECT_EQ(copy.begin(), copy.end());
  copy.push_back(42);
  EXPECT_EQ(Values(copy), std::vector<int>{42});

  moved.swap(copy);
  EXPECT_EQ(Values(moved), std::vector<int>{42});
  EXPECT_EQ(Values(copy), (std::vector<int>{0, 1, 2, 3, 4, 5}));

  fa::list<int>& mutableAlias = moved;
  moved = std::move(mutableAlias);
  EXPECT_EQ(Values(moved), std::vector<int>{42});
}

TEST(FaList, DestroysEveryElement)
{
  Tracked::ResetCounters();
  {
    fa::list<Tracked> list;
    const long heads = Tracked::live;  // the head node holds a value too
    for (int i = 0; i < 30; ++i) {
      list.push_back(Tracked(i));
    }
    EXPECT_EQ(Tracked::live, heads + 30);
    auto first = list.begin();
    std::advance(first, 5);
    auto last = first;
    std::advance(last, 10);
    list.erase(first, last);
    EXPECT_EQ(Tracked::live, heads + 20);
    list.clear();
    EXPECT_EQ(Tracked::live, heads);
  }
  EXPECT_EQ(Tracked::live, 0);
  EXPECT_EQ(Tracked::badAccesses, 0);
}

TEST(FaList, RandomOpsMatchStdList)
{
  for (unsigned seed = 1; seed <= 3; ++seed) {
    RunListRandomOps<int>(seed, 2500);
  }
}

TEST(FaList, RandomOpsMatchStdListTrackedElement)
{
  Tracked::ResetCounters();
  for (unsigned seed = 11; seed <= 12; ++seed) {
    RunListRandomOps<Tracked>(seed, 2500);
  }
  EXPECT_EQ(Tracked::live, 0);
  EXPECT_EQ(Tracked::badAccesses, 0);
}

TEST(FaList, LinkedListLayout)
{
  EXPECT_EQ(sizeof(fa::linked_list<int>), 2 * sizeof(void*));
}

// --- fa::queue --------------------------------------------------------------------------------

namespace
{
  template <class Queue>
  void RunQueueRandomOps(const unsigned seed)
  {
    std::mt19937 rng(seed);
    Queue q;
    std::queue<int> ref;
    for (int step = 0; step < 3000; ++step) {
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step);
      if (rng() % 3u != 0u || ref.empty()) {
        const int value = static_cast<int>(rng() % 1000u);
        if ((rng() & 1u) != 0u) {
          q.push(value);
        } else {
          q.push(value + 0);  // the rvalue overload
        }
        ref.push(value);
      } else {
        q.pop();
        ref.pop();
      }
      ASSERT_EQ(q.size(), ref.size());
      ASSERT_EQ(q.empty(), ref.empty());
      if (!ref.empty()) {
        ASSERT_EQ(q.front(), ref.front());
        ASSERT_EQ(q.back(), ref.back());
        const Queue& constQueue = q;
        ASSERT_EQ(constQueue.front(), ref.front());
        ASSERT_EQ(constQueue.back(), ref.back());
      }
    }
  }
} // namespace

TEST(FaQueue, RandomOpsOverListMatchStdQueue)
{
  RunQueueRandomOps<fa::queue<int>>(5);
}

TEST(FaQueue, RandomOpsOverDequeMatchStdQueue)
{
  RunQueueRandomOps<fa::queue<int, fa::deque<int>>>(6);
}

TEST(FaQueue, CopyMoveAndSwap)
{
  fa::queue<int> a;
  for (int i = 0; i < 5; ++i) {
    a.push(i);
  }
  fa::queue<int> copy(a);
  EXPECT_EQ(Values(copy._Get_container()), (std::vector<int>{0, 1, 2, 3, 4}));
  fa::queue<int> moved(std::move(copy));
  EXPECT_TRUE(copy.empty());
  EXPECT_EQ(moved.size(), 5u);

  fa::queue<int> other;
  other.push(9);
  fa::swap(moved, other);
  EXPECT_EQ(moved.size(), 1u);
  EXPECT_EQ(moved.front(), 9);
  EXPECT_EQ(other.front(), 0);

  const fa::queue<int>& alias = other;
  other = alias;
  EXPECT_EQ(other.size(), 5u);
  copy = other;
  copy.pop();
  EXPECT_EQ(copy.front(), 1);
  EXPECT_EQ(other.front(), 0);

  fa::list<int> seed;
  seed.push_back(7);
  seed.push_back(8);
  const fa::queue<int> fromContainer(seed);
  EXPECT_EQ(fromContainer.front(), 7);
  EXPECT_EQ(fromContainer.back(), 8);
}
