// fa::vector (src/legacy/containers/Vector.h) against std::vector, and the vector<bool> word
// helpers in fa::detail that the terrain edit buffer and the animation manipulators use.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <list>
#include <new>
#include <random>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "ContainerTestTypes.h"
#include "legacy/containers/Vector.h"

namespace
{
  using faf_container_tests::Tracked;
  using faf_container_tests::TrackedCopyRelocated;
  using faf_container_tests::Values;

  /** A trivially copyable element wider than one word, for the memmove paths. */
  struct Pod12
  {
    int value;
    int twice;
    int negated;
  };

  template <class Vec>
  using ElemOf = std::remove_pointer_t<typename Vec::iterator>;

  template <class E>
  [[nodiscard]] E Make(const int v)
  {
    if constexpr (std::is_same_v<E, int>) {
      return v;
    } else if constexpr (std::is_same_v<E, Pod12>) {
      return Pod12{v, 2 * v, -v};
    } else {
      return E(v);
    }
  }

  template <class E>
  [[nodiscard]] long LiveCount()
  {
    if constexpr (requires { E::live; }) {
      return E::live;
    } else {
      return 0;
    }
  }

  template <class E>
  [[nodiscard]] long BadAccesses()
  {
    if constexpr (requires { E::badAccesses; }) {
      return E::badAccesses;
    } else {
      return 0;
    }
  }

  template <class E>
  void ResetCounters()
  {
    if constexpr (requires { E::ResetCounters(); }) {
      E::ResetCounters();
    }
  }

  template <class E>
  [[nodiscard]] bool CountsLiveObjects()
  {
    return requires { E::live; };
  }

  [[nodiscard]] std::size_t Pick(std::mt19937& rng, const std::size_t maxInclusive)
  {
    return std::uniform_int_distribution<std::size_t>(0, maxInclusive)(rng);
  }

  /**
   * Drives `Vec` and a std::vector<int> of the element values with the same seeded operations
   * and compares them after every step. A second vector takes part through copy, move and swap.
   */
  template <class Vec>
  void RunRandomOps(const unsigned seed, const int steps)
  {
    using E = ElemOf<Vec>;
    ResetCounters<E>();
    {
      std::mt19937 rng(seed);
      Vec v;
      Vec other;
      std::vector<int> ref;
      std::vector<int> otherRef;
      for (int step = 0; step < steps; ++step) {
        const unsigned op = rng() % 22u;
        const int value = static_cast<int>(rng() % 1000u);
        SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op);
        switch (op) {
        case 0: {
          const E e = Make<E>(value);
          v.push_back(e);
          ref.push_back(value);
          break;
        }
        case 1:
          v.push_back(Make<E>(value));
          ref.push_back(value);
          break;
        case 2:
          if constexpr (std::is_same_v<E, Pod12>) {
            v.emplace_back(Make<E>(value));
          } else {
            v.emplace_back(value);
          }
          ref.push_back(value);
          break;
        case 3:
          // pop_back on an empty fa::vector does nothing.
          v.pop_back();
          if (!ref.empty()) {
            ref.pop_back();
          }
          break;
        case 4: {
          const std::size_t pos = Pick(rng, ref.size());
          const auto it = v.insert(v.begin() + pos, Make<E>(value));
          ASSERT_EQ(it, v.begin() + pos);
          ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), value);
          break;
        }
        case 5: {
          const std::size_t pos = Pick(rng, ref.size());
          const std::size_t count = Pick(rng, 5);
          const auto it = v.insert(v.begin() + pos, count, Make<E>(value));
          ASSERT_EQ(it, v.begin() + pos);
          ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), count, value);
          break;
        }
        case 6: {
          const std::size_t pos = Pick(rng, ref.size());
          const std::size_t count = Pick(rng, 6);
          std::vector<E> source;
          std::vector<int> sourceValues;
          for (std::size_t i = 0; i < count; ++i) {
            source.push_back(Make<E>(value + static_cast<int>(i)));
            sourceValues.push_back(value + static_cast<int>(i));
          }
          const E* const first = source.data();
          const auto it = v.insert(v.begin() + pos, first, first + count);
          ASSERT_EQ(it, v.begin() + pos);
          ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), sourceValues.begin(), sourceValues.end());
          break;
        }
        case 7:
          if (!ref.empty()) {
            const std::size_t pos = Pick(rng, ref.size() - 1);
            const auto it = v.erase(v.begin() + pos);
            ASSERT_EQ(it, v.begin() + pos);
            ref.erase(ref.begin() + static_cast<std::ptrdiff_t>(pos));
          }
          break;
        case 8: {
          const std::size_t first = Pick(rng, ref.size());
          const std::size_t last = first + Pick(rng, ref.size() - first);
          const auto it = v.erase(v.begin() + first, v.begin() + last);
          ASSERT_EQ(it, v.begin() + first);
          ref.erase(ref.begin() + static_cast<std::ptrdiff_t>(first), ref.begin() + static_cast<std::ptrdiff_t>(last));
          break;
        }
        case 9: {
          const std::size_t n = Pick(rng, ref.size() + 8);
          v.resize(n);
          ref.resize(n, 0);
          break;
        }
        case 10: {
          const std::size_t n = Pick(rng, ref.size() + 8);
          v.resize(n, Make<E>(value));
          ref.resize(n, value);
          break;
        }
        case 11:
          if (rng() % 8u == 0u) {
            const std::size_t capacity = v.capacity();
            v.clear();
            ref.clear();
            ASSERT_EQ(v.capacity(), capacity);
          }
          break;
        case 12: {
          const std::size_t n = Pick(rng, ref.size() + 40);
          v.reserve(n);
          ASSERT_GE(v.capacity(), n);
          break;
        }
        case 13: {
          const std::size_t count = Pick(rng, ref.size() + 6);
          std::vector<E> source;
          std::vector<int> sourceValues;
          for (std::size_t i = 0; i < count; ++i) {
            source.push_back(Make<E>(value - static_cast<int>(i)));
            sourceValues.push_back(value - static_cast<int>(i));
          }
          v.assign(source.data(), count);
          ref = sourceValues;
          break;
        }
        case 14: {
          const std::size_t count = Pick(rng, 10);
          v.assign(count, Make<E>(value));
          ref.assign(count, value);
          break;
        }
        case 15:
          other = v;
          otherRef = ref;
          break;
        case 16:
          v.swap(other);
          std::swap(ref, otherRef);
          break;
        case 17:
          v = std::move(other);
          ref = otherRef;
          otherRef.clear();
          ASSERT_TRUE(other.empty());
          ASSERT_EQ(other.capacity(), 0u);
          break;
        case 18:
          if (!ref.empty()) {
            // The value refers into the vector itself; insert copies it first.
            const std::size_t pos = Pick(rng, ref.size());
            const std::size_t from = Pick(rng, ref.size() - 1);
            const int expected = ref[from];
            v.insert(v.begin() + pos, v[from]);
            ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), expected);
          }
          break;
        case 19:
          if (!ref.empty()) {
            const std::size_t from = Pick(rng, ref.size() - 1);
            const int expected = ref[from];
            v.push_back(v[from]);
            ref.push_back(expected);
          }
          break;
        case 20: {
          const std::size_t pos = Pick(rng, ref.size());
          const std::size_t count = Pick(rng, 3);
          if (!ref.empty() && count != 0u) {
            const std::size_t from = Pick(rng, ref.size() - 1);
            const int expected = ref[from];
            v.insert(v.begin() + pos, count, v[from]);
            ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), count, expected);
          }
          break;
        }
        default:
          if (!ref.empty()) {
            ASSERT_EQ(Values(&v.front(), &v.front() + 1), std::vector<int>{ref.front()});
            ASSERT_EQ(Values(&v.back(), &v.back() + 1), std::vector<int>{ref.back()});
          }
          break;
        }
        ASSERT_EQ(Values(v), ref);
        ASSERT_EQ(Values(other), otherRef);
        ASSERT_EQ(v.size(), ref.size());
        ASSERT_EQ(v.empty(), ref.empty());
        ASSERT_LE(v.size(), v.capacity());
        if (CountsLiveObjects<E>()) {
          ASSERT_EQ(LiveCount<E>(), static_cast<long>(v.size() + other.size()));
        }
        ASSERT_EQ(BadAccesses<E>(), 0);
      }
    }
    EXPECT_EQ(LiveCount<E>(), 0);
    EXPECT_EQ(BadAccesses<E>(), 0);
  }

  template <class Vec>
  [[nodiscard]] std::vector<std::size_t> CapacitiesWhilePushing(const int count, const bool emplace)
  {
    Vec v;
    std::vector<std::size_t> capacities;
    for (int i = 0; i < count; ++i) {
      if (emplace) {
        v.emplace_back(i);
      } else {
        const int value = i;
        v.push_back(value);
      }
      if (capacities.empty() || capacities.back() != v.capacity()) {
        capacities.push_back(v.capacity());
      }
    }
    return capacities;
  }
} // namespace

TEST(FaVector, EmptyVectorHasNoStorage)
{
  const fa::vector<int> v;
  EXPECT_TRUE(v.empty());
  EXPECT_EQ(v.size(), 0u);
  EXPECT_EQ(v.capacity(), 0u);
  EXPECT_EQ(v.data(), nullptr);
  EXPECT_EQ(v.begin(), v.end());
}

TEST(FaVector, LayoutWithAndWithoutTheDebugProxy)
{
  EXPECT_EQ(sizeof(fa::vector<int, false>), 3 * sizeof(void*));
  EXPECT_EQ(sizeof(fa::vector<int, true>), 4 * sizeof(void*));
}

TEST(FaVector, GrowthAddsHalfTheCapacity)
{
  // MSVC8's growth: the new capacity is cap + cap / 2, or the size needed when that is more.
  const std::vector<std::size_t> expected{1, 2, 3, 4, 6, 9, 13, 19, 28, 42};
  EXPECT_EQ(CapacitiesWhilePushing<fa::vector<int>>(30, false), expected);
  EXPECT_EQ(CapacitiesWhilePushing<fa::vector<int>>(30, true), expected);
  EXPECT_EQ((CapacitiesWhilePushing<fa::vector<int, false>>(30, false)), expected);
}

TEST(FaVector, InsertGrowsToTheLargerOfHalfAndNeed)
{
  fa::vector<int> v;
  v.insert(v.end(), 10u, 1);
  EXPECT_EQ(v.capacity(), 10u);
  v.insert(v.end(), 1u, 2);
  EXPECT_EQ(v.capacity(), 15u);
  v.insert(v.begin(), 20u, 3);
  EXPECT_EQ(v.capacity(), 31u);
  EXPECT_EQ(v.size(), 31u);
}

TEST(FaVector, Constructors)
{
  const fa::vector<int> sized(3);
  EXPECT_EQ(Values(sized), (std::vector<int>{0, 0, 0}));
  EXPECT_EQ(sized.capacity(), 3u);

  const fa::vector<int> filled(4, 7);
  EXPECT_EQ(Values(filled), (std::vector<int>{7, 7, 7, 7}));

  const std::list<int> source{5, 6, 7};
  const fa::vector<int> ranged(source.begin(), source.end());
  EXPECT_EQ(Values(ranged), (std::vector<int>{5, 6, 7}));

  const std::vector<int> stdSource{1, 2, 3, 4, 5};
  const fa::vector<int> converted(stdSource);
  EXPECT_EQ(Values(converted), stdSource);
  EXPECT_EQ(converted.to_std(), stdSource);

  const fa::vector<int> empty(0, 1);
  EXPECT_EQ(empty.data(), nullptr);
  EXPECT_EQ(empty.capacity(), 0u);

  fa::vector<int> copied(filled);
  EXPECT_EQ(Values(copied), Values(filled));
  EXPECT_NE(copied.data(), filled.data());

  int* const storage = copied.data();
  fa::vector<int> moved(std::move(copied));
  EXPECT_EQ(moved.data(), storage);
  EXPECT_EQ(copied.data(), nullptr);
  EXPECT_EQ(copied.capacity(), 0u);
  EXPECT_EQ(Values(moved), (std::vector<int>{7, 7, 7, 7}));
}

TEST(FaVector, CopyAssignmentCoversEveryCapacityCase)
{
  fa::vector<int> target;
  const fa::vector<int> small(2, 1);
  const fa::vector<int> big(9, 2);
  const fa::vector<int> none;

  target = big;  // grows from nothing
  EXPECT_EQ(Values(target), Values(big));
  const std::size_t capacity = target.capacity();

  target = small;  // shrinks in place
  EXPECT_EQ(Values(target), Values(small));
  EXPECT_EQ(target.capacity(), capacity);

  target = big;  // grows within the capacity
  EXPECT_EQ(Values(target), Values(big));
  EXPECT_EQ(target.capacity(), capacity);

  target = none;  // empties and keeps the capacity
  EXPECT_TRUE(target.empty());
  EXPECT_EQ(target.capacity(), capacity);
}

TEST(FaVector, SelfAssignmentKeepsTheContents)
{
  fa::vector<Tracked> v;
  for (int i = 0; i < 5; ++i) {
    v.emplace_back(i);
  }
  const fa::vector<Tracked>& alias = v;
  v = alias;
  EXPECT_EQ(Values(v), (std::vector<int>{0, 1, 2, 3, 4}));
  fa::vector<Tracked>& mutableAlias = v;
  v = std::move(mutableAlias);
  EXPECT_EQ(Values(v), (std::vector<int>{0, 1, 2, 3, 4}));
  EXPECT_EQ(Tracked::badAccesses, 0);
}

TEST(FaVector, EraseReturnsTheNextPosition)
{
  fa::vector<int> v;
  for (int i = 0; i < 8; ++i) {
    v.push_back(i);
  }
  // The erase runs in its own statement: end() moves with it.
  int* next = v.erase(v.begin());
  EXPECT_EQ(next, v.begin());
  EXPECT_EQ(Values(v), (std::vector<int>{1, 2, 3, 4, 5, 6, 7}));
  next = v.erase(v.end() - 1);
  EXPECT_EQ(next, v.end());
  EXPECT_EQ(Values(v), (std::vector<int>{1, 2, 3, 4, 5, 6}));
  next = v.erase(v.begin() + 2, v.begin() + 4);
  EXPECT_EQ(next, v.begin() + 2);
  EXPECT_EQ(Values(v), (std::vector<int>{1, 2, 5, 6}));
  next = v.erase(v.begin() + 1, v.begin() + 1);
  EXPECT_EQ(next, v.begin() + 1);
  EXPECT_EQ(Values(v), (std::vector<int>{1, 2, 5, 6}));
  next = v.erase(v.begin(), v.end());
  EXPECT_EQ(next, v.end());
  EXPECT_TRUE(v.empty());
}

TEST(FaVector, InsertWithinAndPastTheCapacity)
{
  fa::vector<int> v;
  v.reserve(10);
  for (int i = 0; i < 4; ++i) {
    v.push_back(i);
  }
  const int* const storage = v.data();
  // Fewer new elements than the tail behind the position, then more.
  v.insert(v.begin() + 1, 2u, 9);
  EXPECT_EQ(Values(v), (std::vector<int>{0, 9, 9, 1, 2, 3}));
  v.insert(v.begin() + 5, 3u, 8);
  EXPECT_EQ(Values(v), (std::vector<int>{0, 9, 9, 1, 2, 8, 8, 8, 3}));
  EXPECT_EQ(v.data(), storage);

  const int extra[] = {40, 41, 42};
  v.insert(v.begin() + 2, extra, extra + 3);
  EXPECT_EQ(Values(v), (std::vector<int>{0, 9, 40, 41, 42, 9, 1, 2, 8, 8, 8, 3}));
  EXPECT_NE(v.data(), storage);
  EXPECT_EQ(v.insert(v.begin() + 3, extra, extra), v.begin() + 3);
  EXPECT_EQ(v.insert(v.begin() + 3, 0u, 5), v.begin() + 3);
  EXPECT_EQ(v.size(), 12u);
}

TEST(FaVector, DestroysEachElementOnce)
{
  Tracked::ResetCounters();
  {
    fa::vector<Tracked> v;
    for (int i = 0; i < 20; ++i) {
      v.emplace_back(i);
    }
    EXPECT_EQ(Tracked::live, 20);
    v.erase(v.begin() + 3, v.begin() + 8);
    EXPECT_EQ(Tracked::live, 15);
    v.resize(4);
    EXPECT_EQ(Tracked::live, 4);
    v.resize(10, Tracked(5));
    EXPECT_EQ(Tracked::live, 10);
    v.pop_back();
    EXPECT_EQ(Tracked::live, 9);
    v.clear();
    EXPECT_EQ(Tracked::live, 0);
    for (int i = 0; i < 6; ++i) {
      v.emplace_back(i);
    }
    EXPECT_EQ(Values(v), (std::vector<int>{0, 1, 2, 3, 4, 5}));
  }
  EXPECT_EQ(Tracked::live, 0);
  EXPECT_EQ(Tracked::badAccesses, 0);
}

TEST(FaVector, TidyFreesAndReleaseHandsTheStorageOver)
{
  fa::vector<int> v(5, 3);
  v.tidy();
  EXPECT_EQ(v.capacity(), 0u);
  EXPECT_EQ(v.data(), nullptr);

  v.assign(3u, 4);
  int* const storage = v.data();
  v.release_storage_without_free();
  EXPECT_EQ(v.data(), nullptr);
  EXPECT_EQ(v.size(), 0u);
  EXPECT_EQ(storage[0], 4);
  ::operator delete(storage);
}

TEST(FaVector, UncheckedPushAndPopMoveOnlyTheEnd)
{
  fa::vector<int> v;
  v.reserve(4);
  v.push_back(1);
  v.push_back(2);
  v.push_back(3);
  v.pop_back_no_destroy();
  EXPECT_EQ(v.size(), 2u);
  v.push_back_no_construct();
  EXPECT_EQ(v.size(), 3u);
  EXPECT_EQ(v[2], 3);
  EXPECT_EQ(v.ptr_at(1), v.data() + 1);
}

TEST(FaVector, TooLongRequestsThrow)
{
  fa::vector<int> v(2, 1);
  EXPECT_THROW(v.reserve(fa::vector<int>::max_size() + 1), std::length_error);
  EXPECT_THROW(v.insert(v.begin(), fa::vector<int>::max_size(), 0), std::length_error);
  EXPECT_EQ(Values(v), (std::vector<int>{1, 1}));
  EXPECT_THROW((void)fa::detail::allocate_checked<int>(0x40000000u), std::bad_alloc);
  EXPECT_EQ(fa::vector<int>::max_size(), 0xFFFFFFFFu / sizeof(int));
}

TEST(FaVector, ConversionsToAndFromStd)
{
  fa::vector<int> v;
  v.from_std(std::vector<int>{3, 1, 4, 1, 5});
  EXPECT_EQ(v.to_std(), (std::vector<int>{3, 1, 4, 1, 5}));
  v.assign(std::vector<int>{9});
  EXPECT_EQ(v.to_std(), (std::vector<int>{9}));
}

TEST(FaVector, PushBackOfAnOwnElementAtCapacity)
{
  Tracked::ResetCounters();
  {
    fa::vector<Tracked> v;
    for (int i = 0; i < 4; ++i) {
      v.emplace_back(10 + i);
    }
    ASSERT_EQ(v.size(), v.capacity());
    v.push_back(v[1]);
    EXPECT_EQ(Values(v), (std::vector<int>{10, 11, 12, 13, 11}));
  }
  EXPECT_EQ(Tracked::badAccesses, 0);
}

// Bug: emplace_back (an engine addition; MSVC8 had none) grows the storage before it constructs
// the new element, so an argument that refers into the vector is read after it was destroyed
// and freed. std::vector supports this. Minimal input: a full vector<Tracked> {10, 11, 12, 13}
// and emplace_back(v[1]); the copy reads a destroyed Tracked.
TEST(FaVector, DISABLED_EmplaceBackOfAnOwnElementAtCapacity)
{
  Tracked::ResetCounters();
  {
    fa::vector<Tracked> v;
    for (int i = 0; i < 4; ++i) {
      v.emplace_back(10 + i);
    }
    ASSERT_EQ(v.size(), v.capacity());
    v.emplace_back(v[1]);
    EXPECT_EQ(Values(v), (std::vector<int>{10, 11, 12, 13, 11}));
  }
  EXPECT_EQ(Tracked::badAccesses, 0);
}

TEST(FaVector, RandomOpsMatchStdVectorInt)
{
  for (unsigned seed = 1; seed <= 4; ++seed) {
    RunRandomOps<fa::vector<int>>(seed, 2500);
  }
}

TEST(FaVector, RandomOpsMatchStdVectorWithoutProxy)
{
  RunRandomOps<fa::vector<int, false>>(11, 2500);
  RunRandomOps<fa::vector<Tracked, false>>(12, 2500);
}

TEST(FaVector, RandomOpsMatchStdVectorWideTrivialElement)
{
  for (unsigned seed = 21; seed <= 23; ++seed) {
    RunRandomOps<fa::vector<Pod12>>(seed, 2500);
  }
}

TEST(FaVector, RandomOpsMatchStdVectorTrackedElement)
{
  for (unsigned seed = 31; seed <= 34; ++seed) {
    RunRandomOps<fa::vector<Tracked>>(seed, 2500);
  }
}

TEST(FaVector, RandomOpsMatchStdVectorCopyRelocatedElement)
{
  for (unsigned seed = 41; seed <= 43; ++seed) {
    RunRandomOps<fa::vector<TrackedCopyRelocated>>(seed, 2500);
  }
}

// --- vector<bool> word helpers ------------------------------------------------------------------

namespace
{
  using Cursor = fa::detail::vector_bool_word_cursor;
  using WordStorage = fa::detail::vector_bool_storage;

  [[nodiscard]] long GlobalBit(const std::uint32_t* const base, const Cursor& c)
  {
    return static_cast<long>(c.word - base) * 32 + static_cast<long>(c.bit);
  }

  [[nodiscard]] Cursor CursorAt(std::uint32_t* const base, const long bit)
  {
    return Cursor{base + bit / 32, static_cast<std::uint32_t>(bit % 32)};
  }

  [[nodiscard]] bool BitAt(const std::uint32_t* const base, const long bit)
  {
    return ((base[bit / 32] >> (bit % 32)) & 1u) != 0u;
  }

  [[nodiscard]] std::vector<bool> Bits(const std::vector<std::uint32_t>& words)
  {
    std::vector<bool> bits;
    for (std::size_t i = 0; i < words.size() * 32; ++i) {
      bits.push_back(BitAt(words.data(), static_cast<long>(i)));
    }
    return bits;
  }

  [[nodiscard]] void* AllocateWords(const unsigned int count)
  {
    return ::operator new(static_cast<std::size_t>(count) * sizeof(std::uint32_t));
  }

  [[nodiscard]] std::vector<std::uint32_t> WordsOf(const WordStorage& storage)
  {
    return std::vector<std::uint32_t>(storage.begin, storage.end);
  }

  void EraseWords(WordStorage* const storage, std::uint32_t* const first, std::uint32_t* const last)
  {
    std::uint32_t* end = storage->end;
    std::uint32_t* out = nullptr;
    (void)fa::detail::EraseWordRangeAndStoreDestination(&out, end, first, last);
    storage->end = end;
  }
} // namespace

TEST(FaVectorBool, CursorStepsCarryAcrossWords)
{
  std::uint32_t words[4]{};
  Cursor c{words, 0};
  for (long i = 0; i < 4 * 32; ++i) {
    ASSERT_EQ(GlobalBit(words, c), i);
    c.Increment();
  }
  EXPECT_EQ(c.word, words + 4);
  EXPECT_EQ(c.bit, 0u);
  for (long i = 4 * 32; i > 0; --i) {
    c.Decrement();
    ASSERT_EQ(GlobalBit(words, c), i - 1);
  }
  c.AdvanceWord();
  EXPECT_EQ(c.word, words + 1);
}

TEST(FaVectorBool, AdvanceAndDistanceMatchBitIndices)
{
  std::uint32_t words[8]{};
  std::mt19937 rng(7);
  for (int step = 0; step < 5000; ++step) {
    const long from = static_cast<long>(rng() % 257u);
    const long to = static_cast<long>(rng() % 257u);
    SCOPED_TRACE(::testing::Message() << "from " << from << " to " << to);
    Cursor c = CursorAt(words, from);
    (void)fa::detail::AdvanceCursorBits(&c, static_cast<int>(to - from));
    ASSERT_EQ(GlobalBit(words, c), to);
    ASSERT_LT(c.bit, 32u);
    ASSERT_EQ(fa::detail::CursorBitDistance(CursorAt(words, from), CursorAt(words, to)), static_cast<int>(to - from));

    Cursor copy{};
    (void)fa::detail::CopyCursorAndAdvance(&copy, CursorAt(words, from), static_cast<int>(to - from));
    ASSERT_EQ(GlobalBit(words, copy), to);

    std::uint32_t* const base = words;
    Cursor fromSlot{};
    (void)fa::detail::SetCursorFromWordSlotAndAdvanceBits(&fromSlot, &base, static_cast<int>(to));
    ASSERT_EQ(GlobalBit(words, fromSlot), to);
  }
  EXPECT_TRUE(fa::detail::CursorEqual(CursorAt(words, 40), CursorAt(words, 40)));
  EXPECT_TRUE(fa::detail::CursorNotEqual(CursorAt(words, 40), CursorAt(words, 41)));
}

TEST(FaVectorBool, ForwardCopyMatchesStdCopy)
{
  std::mt19937 rng(9);
  for (int step = 0; step < 2000; ++step) {
    std::vector<std::uint32_t> source(6);
    std::vector<std::uint32_t> dest(6);
    for (auto& w : source) {
      w = static_cast<std::uint32_t>(rng());
    }
    for (auto& w : dest) {
      w = static_cast<std::uint32_t>(rng());
    }
    const long first = static_cast<long>(rng() % 192u);
    const long last = first + static_cast<long>(rng() % static_cast<unsigned>(193 - first));
    const long out = static_cast<long>(rng() % static_cast<unsigned>(193 - (last - first)));
    SCOPED_TRACE(::testing::Message() << "step " << step << " [" << first << ", " << last << ") -> " << out);

    std::vector<bool> expected = Bits(dest);
    const std::vector<bool> sourceBits = Bits(source);
    std::copy(sourceBits.begin() + first, sourceBits.begin() + last, expected.begin() + out);

    Cursor end{};
    (void)fa::detail::CopyBitCursorRangeForward(
      &end, CursorAt(source.data(), first), CursorAt(source.data(), last), CursorAt(dest.data(), out));
    ASSERT_EQ(Bits(dest), expected);
    ASSERT_EQ(GlobalBit(dest.data(), end), out + (last - first));
  }
}

TEST(FaVectorBool, BackwardCopyShiftsAnOverlappingRangeRight)
{
  std::mt19937 rng(10);
  for (int step = 0; step < 2000; ++step) {
    std::vector<std::uint32_t> words(6);
    for (auto& w : words) {
      w = static_cast<std::uint32_t>(rng());
    }
    const long first = static_cast<long>(rng() % 150u);
    const long last = first + static_cast<long>(rng() % static_cast<unsigned>(151 - first));
    const long shift = static_cast<long>(rng() % static_cast<unsigned>(193 - last));
    SCOPED_TRACE(::testing::Message() << "step " << step << " [" << first << ", " << last << ") + " << shift);

    std::vector<bool> expected = Bits(words);
    std::copy_backward(expected.begin() + first, expected.begin() + last, expected.begin() + last + shift);

    Cursor begin{};
    (void)fa::detail::CopyBitCursorRangeBackward(
      &begin, CursorAt(words.data(), first), CursorAt(words.data(), last), CursorAt(words.data(), last + shift));
    ASSERT_EQ(Bits(words), expected);
    ASSERT_EQ(GlobalBit(words.data(), begin), first + shift);
  }
}

TEST(FaVectorBool, FillSetsOrClearsARange)
{
  std::mt19937 rng(11);
  for (int step = 0; step < 2000; ++step) {
    std::vector<std::uint32_t> words(5);
    for (auto& w : words) {
      w = static_cast<std::uint32_t>(rng());
    }
    const long first = static_cast<long>(rng() % 160u);
    const long last = first + static_cast<long>(rng() % static_cast<unsigned>(161 - first));
    const bool value = (rng() & 1u) != 0u;
    std::vector<bool> expected = Bits(words);
    std::fill(expected.begin() + first, expected.begin() + last, value);
    (void)fa::detail::FillBitCursorRangeFromBooleanSlot(
      &value, CursorAt(words.data(), first), CursorAt(words.data(), last));
    ASSERT_EQ(Bits(words), expected) << "step " << step;
  }
}

TEST(FaVectorBool, CopyBitAtCursor)
{
  std::uint32_t source = 0x00000004u;
  std::uint32_t dest = 0xFFFFFFFFu;
  Cursor destination{&dest, 5};
  (void)fa::detail::CopyBitAtCursor(&destination, Cursor{&source, 1});
  EXPECT_EQ(dest, 0xFFFFFFDFu);
  (void)fa::detail::CopyBitAtCursor(&destination, Cursor{&source, 2});
  EXPECT_EQ(dest, 0xFFFFFFFFu);
}

TEST(FaVectorBool, InsertFillWordsMatchesStdInsert)
{
  const auto throwTooLong = [] { fa::detail::ThrowVectorBoolTooLong(); };
  std::mt19937 rng(12);
  WordStorage storage{};
  ASSERT_TRUE(fa::detail::InitializeWordStorage(&storage, 0u, throwTooLong, AllocateWords));
  std::vector<std::uint32_t> ref;
  for (int step = 0; step < 3000; ++step) {
    const std::size_t pos = Pick(rng, ref.size());
    const std::size_t count = Pick(rng, 4);
    const std::uint32_t fill = static_cast<std::uint32_t>(rng());
    SCOPED_TRACE(::testing::Message() << "step " << step << " pos " << pos << " count " << count);
    const std::size_t capacityBefore = static_cast<std::size_t>(storage.capacityEnd - storage.begin);
    std::uint32_t* const at = fa::detail::InsertFillWords(
      &storage, storage.begin + pos, count, fill, throwTooLong, AllocateWords);
    ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), count, fill);
    ASSERT_EQ(at, storage.begin + pos);
    ASSERT_EQ(WordsOf(storage), ref);
    const std::size_t capacity = static_cast<std::size_t>(storage.capacityEnd - storage.begin);
    if (capacityBefore < ref.size()) {
      ASSERT_EQ(capacity, std::max(capacityBefore + capacityBefore / 2, ref.size()));
    } else {
      ASSERT_EQ(capacity, capacityBefore);
    }
    if (ref.size() > 200) {
      const std::size_t first = Pick(rng, ref.size());
      EraseWords(&storage, storage.begin + first, storage.end);
      ref.resize(first);
      ASSERT_EQ(WordsOf(storage), ref);
    }
  }
  ::operator delete(storage.begin);
}

TEST(FaVectorBool, ResizeWordStorageGrowsWithFillAndErasesTheTail)
{
  const auto throwTooLong = [] { fa::detail::ThrowVectorBoolTooLong(); };
  const auto growWords = [&throwTooLong](
                           WordStorage* const s, std::uint32_t* const at, const std::size_t count, const std::uint32_t fill) {
    (void)fa::detail::InsertFillWords(s, at, count, fill, throwTooLong, AllocateWords);
  };
  WordStorage storage{};
  ASSERT_TRUE(fa::detail::InitializeWordStorage(&storage, 2u, throwTooLong, AllocateWords));
  EXPECT_EQ(storage.end, storage.begin);
  EXPECT_EQ(storage.capacityEnd - storage.begin, 2);

  EXPECT_EQ(fa::detail::ResizeWordStorage(&storage, 3u, 0xABu, growWords, EraseWords), 3u);
  EXPECT_EQ(WordsOf(storage), (std::vector<std::uint32_t>{0xAB, 0xAB, 0xAB}));
  EXPECT_EQ(fa::detail::ResizeWordStorage(&storage, 5u, 0x11u, growWords, EraseWords), 5u);
  EXPECT_EQ(WordsOf(storage), (std::vector<std::uint32_t>{0xAB, 0xAB, 0xAB, 0x11, 0x11}));
  EXPECT_EQ(fa::detail::ResizeWordStorage(&storage, 1u, 0x22u, growWords, EraseWords), 1u);
  EXPECT_EQ(WordsOf(storage), (std::vector<std::uint32_t>{0xAB}));
  EXPECT_EQ(fa::detail::ResizeWordStorage(&storage, 1u, 0x22u, growWords, EraseWords), 1u);
  EXPECT_EQ(WordsOf(storage), (std::vector<std::uint32_t>{0xAB}));
  ::operator delete(storage.begin);
}

TEST(FaVectorBool, InitializeRejectsTooManyWords)
{
  const auto throwTooLong = [] { fa::detail::ThrowVectorBoolTooLong(); };
  WordStorage storage{};
  EXPECT_THROW((void)fa::detail::InitializeWordStorage(&storage, 0x40000000u, throwTooLong, AllocateWords), std::length_error);
  EXPECT_EQ(storage.begin, nullptr);
}

TEST(FaVectorBool, NormalizeTrimsWordsAndMasksTheLastOne)
{
  const auto throwTooLong = [] { fa::detail::ThrowVectorBoolTooLong(); };
  WordStorage storage{};
  ASSERT_TRUE(fa::detail::InitializeWordStorage(&storage, 4u, throwTooLong, AllocateWords));
  (void)fa::detail::InsertFillWords(&storage, storage.end, 4u, 0xFFFFFFFFu, throwTooLong, AllocateWords);

  EXPECT_EQ(fa::detail::NormalizeBitCountAndTrimTail(&storage, 70u, EraseWords), 70u);
  EXPECT_EQ(storage.prefix, 70u);
  EXPECT_EQ(WordsOf(storage), (std::vector<std::uint32_t>{0xFFFFFFFFu, 0xFFFFFFFFu, 0x3Fu}));

  EXPECT_EQ(fa::detail::NormalizeBitCountAndTrimTail(&storage, 64u, EraseWords), 64u);
  EXPECT_EQ(WordsOf(storage), (std::vector<std::uint32_t>{0xFFFFFFFFu, 0xFFFFFFFFu}));

  EXPECT_EQ(fa::detail::NormalizeBitCountAndTrimTail(&storage, 0u, EraseWords), 0u);
  EXPECT_TRUE(WordsOf(storage).empty());
  ::operator delete(storage.begin);
}

TEST(FaVectorBool, SmallWordHelpers)
{
  EXPECT_EQ(fa::detail::BitCountToWordCount(0u), 0u);
  EXPECT_EQ(fa::detail::BitCountToWordCount(1u), 1u);
  EXPECT_EQ(fa::detail::BitCountToWordCount(32u), 1u);
  EXPECT_EQ(fa::detail::BitCountToWordCount(33u), 2u);
  EXPECT_EQ(fa::detail::HighestSetBitIndex(1u), 0);
  EXPECT_EQ(fa::detail::HighestSetBitIndex(0x80000000u), 31);
  EXPECT_EQ(fa::detail::HighestSetBitIndex(0x00012345u), 16);
  EXPECT_TRUE(fa::detail::IsSingleBitSetNonZero(0x400u));
  EXPECT_FALSE(fa::detail::IsSingleBitSetNonZero(0u));
  EXPECT_FALSE(fa::detail::IsSingleBitSetNonZero(0x401u));
  EXPECT_EQ(fa::detail::HighByteOfWord(0x1234ABCDu), 0xABu);
  EXPECT_EQ(fa::detail::WordSpanCountFromOptionalBegin(nullptr, nullptr), 0u);

  std::uint32_t a = 1u;
  std::uint32_t b = 2u;
  (void)fa::detail::SwapWords(&a, &b);
  EXPECT_EQ(a, 2u);
  EXPECT_EQ(b, 1u);

  std::uint32_t words[5] = {1, 2, 3, 4, 5};
  std::uint32_t* end = words + 5;
  std::uint32_t* out = nullptr;
  (void)fa::detail::EraseWordRangeAndStoreDestination(&out, end, words + 1, words + 3);
  EXPECT_EQ(out, words + 1);
  EXPECT_EQ(end, words + 3);
  EXPECT_EQ((std::vector<std::uint32_t>(words, end)), (std::vector<std::uint32_t>{1, 4, 5}));
}
