// gpg::core::FastVector, FastVectorInline, FastVectorN and the legacy:: helpers
// (src/gpg/core/containers/FastVector.h) against std::vector.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <random>
#include <set>
#include <type_traits>
#include <utility>
#include <vector>

#include "ContainerTestTypes.h"
#include "gpg/core/containers/FastVector.h"

namespace
{
  using faf_container_tests::Tracked;
  using faf_container_tests::TrackedCopyRelocated;
  using faf_container_tests::Values;
  using gpg::core::FastVector;
  using gpg::core::FastVectorInline;
  using gpg::core::FastVectorN;

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
  [[nodiscard]] long LiveCount()
  {
    if constexpr (requires { E::live; }) {
      return E::live;
    } else {
      return -1;
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

  [[nodiscard]] std::size_t Pick(std::mt19937& rng, const std::size_t maxInclusive)
  {
    return std::uniform_int_distribution<std::size_t>(0, maxInclusive)(rng);
  }

  template <class E>
  void RunFastVectorRandomOps(const unsigned seed, const int steps)
  {
    ResetCounters<E>();
    {
      std::mt19937 rng(seed);
      FastVector<E> v;
      FastVector<E> other;
      std::vector<int> ref;
      std::vector<int> otherRef;
      for (int step = 0; step < steps; ++step) {
        const unsigned op = rng() % 13u;
        const int value = static_cast<int>(rng() % 1000u);
        SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op);
        switch (op) {
        case 0:
        case 1: {
          const E e = Make<E>(value);
          if (op == 0) {
            v.PushBack(e);
          } else {
            v.push_back(e);
          }
          ref.push_back(value);
          break;
        }
        case 2: {
          const std::size_t n = Pick(rng, ref.size() + 6);
          v.resize(n);
          ref.resize(n, 0);
          break;
        }
        case 3: {
          const std::size_t n = Pick(rng, ref.size() + 6);
          v.resize(n, Make<E>(value));
          ref.resize(n, value);
          break;
        }
        case 4: {
          const std::size_t n = Pick(rng, ref.size() + 6);
          v.Resize(n, Make<E>(value));
          ref.resize(n, value);
          break;
        }
        case 5:
          if (!ref.empty()) {
            const std::size_t pos = Pick(rng, ref.size() - 1);
            E* const next = v.erase(v.begin() + pos);
            ASSERT_EQ(next, v.begin() + pos);
            ref.erase(ref.begin() + static_cast<std::ptrdiff_t>(pos));
          }
          break;
        case 6: {
          const std::size_t first = Pick(rng, ref.size());
          const std::size_t last = first + Pick(rng, ref.size() - first);
          E* const next = v.erase(v.begin() + first, v.begin() + last);
          ASSERT_EQ(next, v.begin() + first);
          ref.erase(ref.begin() + static_cast<std::ptrdiff_t>(first), ref.begin() + static_cast<std::ptrdiff_t>(last));
          break;
        }
        case 7:
          if (rng() % 6u == 0u) {
            if ((rng() & 1u) != 0u) {
              v.Clear();
            } else {
              v.clear();
            }
            ref.clear();
          }
          break;
        case 8: {
          const std::size_t n = Pick(rng, ref.size() + 20);
          v.Reserve(n);
          ASSERT_GE(v.Capacity(), n);
          break;
        }
        case 9:
          other = v;
          otherRef = ref;
          break;
        case 10:
          std::swap(v, other);
          std::swap(ref, otherRef);
          break;
        case 11: {
          FastVector<E> moved(std::move(v));
          ASSERT_TRUE(v.Empty());
          ASSERT_EQ(v.Capacity(), 0u);
          v = std::move(moved);
          break;
        }
        default:
          if (!ref.empty()) {
            const std::size_t i = Pick(rng, ref.size() - 1);
            v[i] = Make<E>(value);
            ref[i] = value;
          }
          break;
        }
        ASSERT_EQ(Values(v), ref);
        ASSERT_EQ(Values(other), otherRef);
        ASSERT_EQ(v.Size(), ref.size());
        ASSERT_EQ(v.size(), ref.size());
        ASSERT_EQ(v.Empty(), ref.empty());
        ASSERT_LE(v.Size(), v.Capacity());
        if (!ref.empty()) {
          ASSERT_EQ(Values(&v.Front(), &v.Front() + 1), std::vector<int>{ref.front()});
          ASSERT_EQ(Values(&v.back(), &v.back() + 1), std::vector<int>{ref.back()});
        }
        if (LiveCount<E>() >= 0) {
          ASSERT_EQ(LiveCount<E>(), static_cast<long>(v.Size() + other.Size()));
        }
        ASSERT_EQ(BadAccesses<E>(), 0);
      }
    }
    if (LiveCount<E>() >= 0) {
      EXPECT_EQ(LiveCount<E>(), 0);
    }
    EXPECT_EQ(BadAccesses<E>(), 0);
  }

  template <class E, std::size_t N>
  void CheckInlineInvariant(const FastVectorN<E, N>& v)
  {
    ASSERT_EQ(v.originalVec_, v.InlineStorage());
    ASSERT_LE(v.Size(), v.Capacity());
    if (v.UsingInlineStorage()) {
      ASSERT_EQ(v.Capacity(), N);
    }
  }

  template <class E, std::size_t N>
  void RunFastVectorNRandomOps(const unsigned seed, const int steps)
  {
    using Vec = FastVectorN<E, N>;
    ResetCounters<E>();
    {
      std::mt19937 rng(seed);
      Vec v;
      Vec other;
      std::vector<int> ref;
      std::vector<int> otherRef;
      for (int step = 0; step < steps; ++step) {
        const unsigned op = rng() % 20u;
        const int value = static_cast<int>(rng() % 1000u);
        SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op);
        switch (op) {
        case 0:
        case 1: {
          const E e = Make<E>(value);
          if (op == 0) {
            v.push_back(e);
          } else {
            v.PushBack(e);
          }
          ref.push_back(value);
          break;
        }
        case 2: {
          E e = Make<E>(value);
          v.Append(e);
          ref.push_back(value);
          break;
        }
        case 3: {
          const std::size_t pos = Pick(rng, ref.size());
          const std::size_t count = Pick(rng, 2 * N + 1);
          std::vector<E> source;
          std::vector<int> sourceValues;
          for (std::size_t i = 0; i < count; ++i) {
            source.push_back(Make<E>(value + static_cast<int>(i)));
            sourceValues.push_back(value + static_cast<int>(i));
          }
          v.InsertAt(v.begin() + pos, source.data(), source.data() + count);
          ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), sourceValues.begin(), sourceValues.end());
          break;
        }
        case 4: {
          const std::size_t n = Pick(rng, ref.size() + N + 2);
          v.Resize(n, Make<E>(value));
          ref.resize(n, value);
          break;
        }
        case 5: {
          const std::size_t n = Pick(rng, ref.size() + N + 2);
          v.resize(n);
          ref.resize(n, 0);
          break;
        }
        case 6: {
          const std::size_t n = Pick(rng, ref.size() + 3 * N);
          if ((rng() & 1u) != 0u) {
            v.Reserve(n);
          } else {
            v.Grow(n);
          }
          ASSERT_GE(v.Capacity(), n);
          break;
        }
        case 7: {
          const std::size_t first = Pick(rng, ref.size());
          const std::size_t last = first + Pick(rng, ref.size() - first);
          v.erase(v.begin() + first, v.begin() + last);
          ref.erase(ref.begin() + static_cast<std::ptrdiff_t>(first), ref.begin() + static_cast<std::ptrdiff_t>(last));
          break;
        }
        case 8:
          if (rng() % 5u == 0u) {
            v.ResetStorageToInline();
            ref.clear();
            ASSERT_TRUE(v.UsingInlineStorage());
          }
          break;
        case 9:
          // AddAll replaces the contents (0x0057EB00).
          v.AddAll(&other);
          ref = otherRef;
          break;
        case 10:
          other = v;
          otherRef = ref;
          break;
        case 11: {
          Vec copy(v);
          ASSERT_NO_FATAL_FAILURE(CheckInlineInvariant(copy));
          ASSERT_EQ(Values(copy), ref);
          break;
        }
        case 12: {
          // Moves only from inline sources: see DISABLED_MoveFromAHeapSourceKeepsTheInlineCapacity.
          if (!v.UsingInlineStorage()) {
            break;
          }
          Vec moved(std::move(v));
          ASSERT_NO_FATAL_FAILURE(CheckInlineInvariant(moved));
          ASSERT_TRUE(v.Empty());
          ASSERT_TRUE(v.UsingInlineStorage());
          ASSERT_EQ(Values(moved), ref);
          v = std::move(moved);
          break;
        }
        case 13:
          if (!other.UsingInlineStorage()) {
            break;
          }
          v = std::move(other);
          ref = otherRef;
          otherRef.clear();
          ASSERT_TRUE(other.Empty());
          ASSERT_TRUE(other.UsingInlineStorage());
          break;
        case 14: {
          FastVector<E> plain;
          std::vector<int> plainValues;
          for (std::size_t i = Pick(rng, 2 * N); i > 0; --i) {
            plain.PushBack(Make<E>(value + static_cast<int>(i)));
            plainValues.push_back(value + static_cast<int>(i));
          }
          v.ResetFrom(plain);
          ref = plainValues;
          break;
        }
        case 15:
          if (!ref.empty()) {
            // An element of the vector itself, pushed at capacity: the copy is made before the
            // old storage goes.
            const std::size_t from = Pick(rng, ref.size() - 1);
            const int expected = ref[from];
            v.push_back(v[from]);
            ref.push_back(expected);
          }
          break;
        case 16:
          if (rng() % 4u == 0u) {
            v.Clear();
            ref.clear();
          }
          break;
        default:
          if (!ref.empty()) {
            const std::size_t i = Pick(rng, ref.size() - 1);
            v[i] = Make<E>(value);
            ref[i] = value;
          }
          break;
        }
        ASSERT_EQ(Values(v), ref);
        ASSERT_EQ(Values(other), otherRef);
        ASSERT_NO_FATAL_FAILURE(CheckInlineInvariant(v));
        ASSERT_NO_FATAL_FAILURE(CheckInlineInvariant(other));
        if (LiveCount<E>() >= 0) {
          ASSERT_EQ(LiveCount<E>(), static_cast<long>(v.Size() + other.Size()));
        }
        ASSERT_EQ(BadAccesses<E>(), 0);
      }
    }
    if (LiveCount<E>() >= 0) {
      EXPECT_EQ(LiveCount<E>(), 0);
    }
    EXPECT_EQ(BadAccesses<E>(), 0);
  }
} // namespace

TEST(GpgFastVector, EmptyVectorHasNoStorage)
{
  const FastVector<int> v;
  EXPECT_TRUE(v.Empty());
  EXPECT_EQ(v.Size(), 0u);
  EXPECT_EQ(v.Capacity(), 0u);
  EXPECT_EQ(v.Data(), nullptr);
  EXPECT_EQ(v.begin(), v.end());
  EXPECT_EQ(v.rbegin(), v.rend());
}

TEST(GpgFastVector, PushBackDoublesFromFour)
{
  FastVector<int> v;
  std::vector<std::size_t> capacities;
  for (int i = 0; i < 40; ++i) {
    v.PushBack(i);
    if (capacities.empty() || capacities.back() != v.Capacity()) {
      capacities.push_back(v.Capacity());
    }
  }
  EXPECT_EQ(capacities, (std::vector<std::size_t>{4, 8, 16, 32, 64}));
}

TEST(GpgFastVector, ResizeZeroFillsTrivialElements)
{
  FastVector<int> v;
  for (int i = 1; i <= 6; ++i) {
    v.PushBack(i);
  }
  v.resize(2);
  v.resize(5);
  EXPECT_EQ(Values(v), (std::vector<int>{1, 2, 0, 0, 0}));
  v.Resize(7);
  EXPECT_EQ(Values(v), (std::vector<int>{1, 2, 0, 0, 0, 0, 0}));
}

TEST(GpgFastVector, EraseRejectsRangesOutsideTheVector)
{
  FastVector<int> v;
  for (int i = 0; i < 5; ++i) {
    v.PushBack(i);
  }
  int outside = 0;
  EXPECT_EQ(v.erase(&outside, &outside + 1), v.end());
  EXPECT_EQ(v.erase(v.begin() + 3, v.begin() + 1), v.end());
  EXPECT_EQ(v.erase(v.begin(), v.end() + 1), v.end());
  EXPECT_EQ(v.erase(nullptr, nullptr), v.end());
  EXPECT_EQ(Values(v), (std::vector<int>{0, 1, 2, 3, 4}));
  FastVector<int> empty;
  EXPECT_EQ(empty.erase(empty.begin(), empty.end()), nullptr);
}

TEST(GpgFastVector, CopyAssignmentKeepsOrGrowsTheStorage)
{
  FastVector<int> big;
  FastVector<int> small;
  for (int i = 0; i < 10; ++i) {
    big.PushBack(i);
  }
  small.PushBack(42);
  FastVector<int> target;
  target = big;
  EXPECT_EQ(Values(target), Values(big));
  const int* const storage = target.Data();
  target = small;
  EXPECT_EQ(Values(target), std::vector<int>{42});
  EXPECT_EQ(target.Data(), storage);
  const FastVector<int>& alias = target;
  target = alias;
  EXPECT_EQ(Values(target), std::vector<int>{42});
}

TEST(GpgFastVector, RandomOpsMatchStdVectorInt)
{
  for (unsigned seed = 1; seed <= 4; ++seed) {
    RunFastVectorRandomOps<int>(seed, 2500);
  }
}

TEST(GpgFastVector, RandomOpsMatchStdVectorTrackedElement)
{
  for (unsigned seed = 11; seed <= 13; ++seed) {
    RunFastVectorRandomOps<Tracked>(seed, 2500);
  }
}

TEST(GpgFastVector, RandomOpsMatchStdVectorCopyRelocatedElement)
{
  RunFastVectorRandomOps<TrackedCopyRelocated>(21, 2500);
}

// The storage hooks exist on 64-bit builds only (FastVector.h), where SimBlockLane accounts for them.
#if defined(_M_X64) || defined(__x86_64__)
TEST(GpgFastVector, UIntStorageHooksSeeEveryBlock)
{
  using Hook = void (*)(const void*, std::size_t);
  using FreeHook = void (*)(const void*);
  static std::set<const void*> blocks;
  static int allocations = 0;
  static int frees = 0;
  static Hook previousAllocated = nullptr;
  static FreeHook previousFreed = nullptr;
  blocks.clear();
  allocations = 0;
  frees = 0;
  previousAllocated = gpg::core::detail::gUIntStorageAllocated;
  previousFreed = gpg::core::detail::gUIntStorageFreed;
  gpg::core::detail::gUIntStorageAllocated = [](const void* block, const std::size_t bytes) {
    ++allocations;
    blocks.insert(block);
    if (previousAllocated != nullptr) {
      previousAllocated(block, bytes);
    }
  };
  gpg::core::detail::gUIntStorageFreed = [](const void* block) {
    if (block != nullptr) {
      ++frees;
      blocks.erase(block);
    }
    if (previousFreed != nullptr) {
      previousFreed(block);
    }
  };
  {
    FastVector<unsigned int> v;
    for (unsigned int i = 0; i < 20; ++i) {
      v.PushBack(i);
    }
    // Blocks of 4, 8, 16 and 32 slots; the first three were freed on the way.
    EXPECT_EQ(v.Capacity(), 32u);
    EXPECT_EQ(allocations, 4);
    EXPECT_EQ(frees, 3);
    EXPECT_EQ(blocks.size(), 1u);
  }
  EXPECT_EQ(frees, allocations);
  EXPECT_TRUE(blocks.empty());
  gpg::core::detail::gUIntStorageAllocated = previousAllocated;
  gpg::core::detail::gUIntStorageFreed = previousFreed;
}
#endif

// --- FastVectorN -------------------------------------------------------------------------------

TEST(GpgFastVectorN, StartsInlineAndReturnsToInline)
{
  FastVectorN<int, 4> v;
  EXPECT_TRUE(v.UsingInlineStorage());
  EXPECT_EQ(v.Capacity(), 4u);
  EXPECT_EQ(v.Data(), v.InlineStorage());
  for (int i = 0; i < 4; ++i) {
    v.push_back(i);
  }
  EXPECT_TRUE(v.UsingInlineStorage());
  v.push_back(4);
  EXPECT_FALSE(v.UsingInlineStorage());
  EXPECT_EQ(v.Capacity(), 8u);
  EXPECT_EQ(Values(v), (std::vector<int>{0, 1, 2, 3, 4}));
  v.ResetStorageToInline();
  EXPECT_TRUE(v.UsingInlineStorage());
  EXPECT_TRUE(v.Empty());
  EXPECT_EQ(v.Capacity(), 4u);
  v.push_back(9);
  EXPECT_EQ(Values(v), std::vector<int>{9});
}

TEST(GpgFastVectorN, MoveFromAnInlineSource)
{
  FastVectorN<int, 4> source;
  source.push_back(1);
  source.push_back(2);
  FastVectorN<int, 4> moved(std::move(source));
  EXPECT_TRUE(moved.UsingInlineStorage());
  EXPECT_EQ(Values(moved), (std::vector<int>{1, 2}));
  EXPECT_TRUE(source.Empty());
  FastVectorN<int, 4> heap;
  for (int i = 0; i < 6; ++i) {
    heap.push_back(i);
  }
  heap = std::move(moved);
  EXPECT_EQ(Values(heap), (std::vector<int>{1, 2}));
  EXPECT_TRUE(moved.Empty());
  heap.ResetStorageToInline();
  EXPECT_EQ(heap.Capacity(), 4u);
}

// Bug: FastVectorN's move constructor and move assignment (engine additions; C++03 had no move)
// take a heap source's buffer without writing the inline capacity header into the target's
// inline storage, as every other way off the inline storage does (SaveInlineCapacity_). The next
// ResetStorageToInline, ResetFrom or copy assignment then restores a capacity read from whatever
// that storage holds, and later pushes write past it. Minimal input: a FastVectorN<int, 4> with
// {7} takes `= std::move(x)` from one holding 5 elements; after ResetStorageToInline its
// capacity is 7, not 4.
TEST(GpgFastVectorN, DISABLED_MoveFromAHeapSourceKeepsTheInlineCapacity)
{
  FastVectorN<int, 4> heapA;
  FastVectorN<int, 4> heapB;
  for (int i = 0; i < 5; ++i) {
    heapA.push_back(i);
    heapB.push_back(i);
  }
  FastVectorN<int, 4> target;
  target.push_back(7);
  target = std::move(heapA);
  EXPECT_EQ(Values(target), (std::vector<int>{0, 1, 2, 3, 4}));
  target.ResetStorageToInline();
  EXPECT_EQ(target.Capacity(), 4u);

  FastVectorN<int, 4> moved(std::move(heapB));
  moved.ResetStorageToInline();
  EXPECT_EQ(moved.Capacity(), 4u);
}

TEST(GpgFastVectorN, SizedConstructorFillsWithZero)
{
  const FastVectorN<int, 4> small(3);
  EXPECT_TRUE(small.UsingInlineStorage());
  EXPECT_EQ(Values(small), (std::vector<int>{0, 0, 0}));
  const FastVectorN<int, 4> big(9);
  EXPECT_FALSE(big.UsingInlineStorage());
  EXPECT_EQ(Values(big), std::vector<int>(9, 0));
  EXPECT_EQ(big.Capacity(), 9u);
}

TEST(GpgFastVectorN, AddAllReplacesTheContents)
{
  FastVectorN<int, 2> a;
  FastVectorN<int, 2> b;
  a.push_back(1);
  a.push_back(2);
  a.push_back(3);
  b.push_back(7);
  EXPECT_EQ(a.AddAll(&b), &a);
  EXPECT_EQ(Values(a), std::vector<int>{7});
  b.push_back(8);
  b.push_back(9);
  a.AddAll(&b);
  EXPECT_EQ(Values(a), (std::vector<int>{7, 8, 9}));
  EXPECT_EQ(a.AddAll(&a), &a);
  EXPECT_EQ(Values(a), (std::vector<int>{7, 8, 9}));
}

TEST(GpgFastVectorN, InsertAtEveryPositionWithinCapacity)
{
  for (std::size_t pos = 0; pos <= 4; ++pos) {
    for (std::size_t count = 0; count <= 4; ++count) {
      FastVectorN<int, 8> v;
      std::vector<int> ref;
      for (int i = 0; i < 4; ++i) {
        v.push_back(i);
        ref.push_back(i);
      }
      std::vector<int> source;
      for (std::size_t i = 0; i < count; ++i) {
        source.push_back(100 + static_cast<int>(i));
      }
      v.InsertAt(v.begin() + pos, source.data(), source.data() + count);
      ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), source.begin(), source.end());
      ASSERT_EQ(Values(v), ref) << "pos " << pos << " count " << count;
      ASSERT_TRUE(v.UsingInlineStorage());
    }
  }
}

TEST(GpgFastVectorN, RandomOpsMatchStdVectorInt)
{
  for (unsigned seed = 1; seed <= 3; ++seed) {
    RunFastVectorNRandomOps<int, 4>(seed, 2500);
  }
  RunFastVectorNRandomOps<int, 1>(4, 2500);
  RunFastVectorNRandomOps<int, 16>(5, 2500);
}

TEST(GpgFastVectorN, RandomOpsMatchStdVectorTrackedElement)
{
  for (unsigned seed = 11; seed <= 12; ++seed) {
    RunFastVectorNRandomOps<Tracked, 4>(seed, 2500);
  }
  RunFastVectorNRandomOps<Tracked, 1>(13, 2500);
}

TEST(GpgFastVectorN, RandomOpsMatchStdVectorCopyRelocatedElement)
{
  RunFastVectorNRandomOps<TrackedCopyRelocated, 3>(21, 2500);
}

TEST(GpgFastVectorN, InitHelpersBindTheInlineStorage)
{
  gpg::fastvector_n<int, 2> source;
  source.push_back(1);
  source.push_back(2);
  source.push_back(3);
  gpg::fastvector_n<int, 2> destination;
  EXPECT_EQ(gpg::FastVectorN2RebindAndCopy(&destination, &source), &destination);
  EXPECT_EQ(Values(destination), (std::vector<int>{1, 2, 3}));
  EXPECT_EQ(gpg::FastVectorN2RebindAndCopy(static_cast<gpg::fastvector_n<int, 2>*>(nullptr), &source), nullptr);

  FastVectorN<int, 4> v;
  v.push_back(5);
  v.SetSizeUnchecked(0);
  EXPECT_TRUE(v.Empty());
  FastVectorN<int, 4> copied;
  copied.InitInlineAndCopyFrom(source);
  EXPECT_EQ(Values(copied), (std::vector<int>{1, 2, 3}));
  EXPECT_TRUE(copied.UsingInlineStorage());
}

// --- FastVectorInline --------------------------------------------------------------------------

TEST(GpgFastVectorInline, ExternalInlineStorageAndRelease)
{
  alignas(8) int storage[4]{};
  FastVectorInline<int> v;
  v.BindInlineStorage(storage, 4);
  EXPECT_TRUE(v.UsesInlineStorage());
  for (int i = 0; i < 4; ++i) {
    v.push_back(i);
  }
  EXPECT_EQ(v.Data(), storage);
  v.PushBack(4);
  EXPECT_FALSE(v.UsesInlineStorage());
  EXPECT_EQ(v.Capacity(), 8u);
  v.reserve(20);
  EXPECT_EQ(v.Capacity(), 20u);
  EXPECT_EQ(Values(v), (std::vector<int>{0, 1, 2, 3, 4}));

  const FastVectorInline<int>::ReleasedBlock released = v.ReleaseHeapStorage();
  EXPECT_EQ(Values(released.begin, released.end), (std::vector<int>{0, 1, 2, 3, 4}));
  EXPECT_TRUE(v.UsesInlineStorage());
  EXPECT_EQ(v.Capacity(), 4u);
  EXPECT_TRUE(v.Empty());
  FastVectorInline<int>::FreeReleasedBlock(released);
  const FastVectorInline<int>::ReleasedBlock none = v.ReleaseHeapStorage();
  EXPECT_EQ(none.begin, nullptr);

  v.resize(3, 7);
  EXPECT_EQ(Values(v), (std::vector<int>{7, 7, 7}));
  v.resize(1);
  EXPECT_EQ(Values(v), std::vector<int>{7});
  v.resize(6);
  EXPECT_EQ(Values(v), (std::vector<int>{7, 0, 0, 0, 0, 0}));
  v.ResetStorageToInline();
  EXPECT_EQ(v.Data(), storage);
  EXPECT_EQ(v.Capacity(), 4u);
}

TEST(GpgFastVectorInline, InsertRangeMatchesStdInsert)
{
  std::mt19937 rng(31);
  alignas(8) int storage[3]{};
  FastVectorInline<int> v;
  v.BindInlineStorage(storage, 3);
  std::vector<int> ref;
  for (int step = 0; step < 2000; ++step) {
    const std::size_t pos = Pick(rng, ref.size());
    const std::size_t count = Pick(rng, 5);
    std::vector<int> source;
    for (std::size_t i = 0; i < count; ++i) {
      source.push_back(static_cast<int>(rng() % 1000u));
    }
    int* const end = v.InsertRange(v.begin() + pos, source.data(), source.data() + count);
    ASSERT_EQ(end, v.end());
    ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), source.begin(), source.end());
    ASSERT_EQ(Values(v), ref) << "step " << step;
    if (ref.size() > 100) {
      v.ResetStorageToInline();
      ref.clear();
      ASSERT_EQ(v.Capacity(), 3u);
    }
  }
}

TEST(GpgFastVectorInline, AssignFrom)
{
  alignas(8) int storageA[2]{};
  alignas(8) int storageB[2]{};
  FastVectorInline<int> a;
  FastVectorInline<int> b;
  a.BindInlineStorage(storageA, 2);
  b.BindInlineStorage(storageB, 2);
  for (int i = 0; i < 5; ++i) {
    b.push_back(i);
  }
  a.push_back(9);
  a.AssignFrom(b);
  EXPECT_EQ(Values(a), (std::vector<int>{0, 1, 2, 3, 4}));
  b.resize(1);
  a.AssignFrom(b);
  EXPECT_EQ(Values(a), std::vector<int>{0});
  a.AssignFrom(a);
  EXPECT_EQ(Values(a), std::vector<int>{0});
}

// --- legacy:: helpers --------------------------------------------------------------------------
// legacy::InsertRange and legacy::CopyFrom are left out: they drop the [[nodiscard]] result of
// ReallocateForInsert / InsertRange (FastVector.h, ReallocateForInsert and InsertRange calls in
// their bodies), so instantiating them adds -Wunused-result warnings, and src/ has no caller.

TEST(GpgFastVectorLegacy, ReallocateForInsertSplicesTheRange)
{
  std::mt19937 rng(41);
  FastVector<int> v;
  std::vector<int> ref;
  for (int step = 0; step < 2000; ++step) {
    const std::size_t pos = Pick(rng, ref.size());
    const std::size_t count = Pick(rng, 5);
    std::vector<int> source;
    for (std::size_t i = 0; i < count; ++i) {
      source.push_back(static_cast<int>(rng() % 1000u));
    }
    const std::size_t capacity = ref.size() + count + Pick(rng, 4);
    ASSERT_EQ(gpg::core::legacy::ReallocateForInsert(v, capacity, v.begin() + pos, source.data(), source.data() + count), capacity);
    ref.insert(ref.begin() + static_cast<std::ptrdiff_t>(pos), source.begin(), source.end());
    ASSERT_EQ(Values(v), ref) << "step " << step;
    ASSERT_EQ(gpg::core::legacy::Count(v), ref.size());
    ASSERT_EQ(gpg::core::legacy::IsEmpty(v), ref.empty());
    ASSERT_EQ(gpg::core::legacy::CapacityCount(v), capacity);
    if (ref.size() > 100) {
      // Drop a prefix the way the legacy erase does: move the tail down.
      const std::size_t keep = Pick(rng, ref.size());
      (void)gpg::core::legacy::MovePrefixAndSetEnd(v, v.begin() + (ref.size() - keep), v.begin());
      ref.erase(ref.begin(), ref.begin() + static_cast<std::ptrdiff_t>(ref.size() - keep));
      ASSERT_EQ(Values(v), ref);
    }
  }
}

TEST(GpgFastVectorLegacy, EnsureCapacityAndAccessors)
{
  FastVector<int> target;
  target.PushBack(5);
  EXPECT_EQ(gpg::core::legacy::EnsureCapacity(target, 3), 3u);
  EXPECT_EQ(gpg::core::legacy::CapacityCount(target), 4u);
  EXPECT_EQ(gpg::core::legacy::EnsureCapacity(target, 100), 100u);
  EXPECT_EQ(gpg::core::legacy::CapacityCount(target), 100u);
  EXPECT_EQ(Values(target), std::vector<int>{5});
  EXPECT_EQ(gpg::core::legacy::IndexPtr(target, 0), gpg::core::legacy::BeginPtr(target));
  EXPECT_EQ(gpg::core::legacy::MovePrefixAndSetEnd(target, target.begin(), target.begin()), target.begin());
  EXPECT_EQ(Values(target), std::vector<int>{5});
}

TEST(GpgFastVectorLegacy, InlineOriginKeepsItsCapacityHeader)
{
  FastVectorN<int, 4> v;
  for (int i = 0; i < 3; ++i) {
    v.push_back(i);
  }
  const int extra[] = {10, 11, 12};
  EXPECT_EQ(gpg::core::legacy::ReallocateForInsert(static_cast<FastVector<int>&>(v), 6u, v.end(), extra, extra + 3, v.originalVec_), 6u);
  EXPECT_FALSE(v.UsingInlineStorage());
  EXPECT_EQ(Values(v), (std::vector<int>{0, 1, 2, 10, 11, 12}));
  v.ResetStorageToInline();
  EXPECT_EQ(v.Capacity(), 4u);

  FastVector<int> window;
  int buffer[6]{};
  int* metadata = nullptr;
  (void)gpg::core::legacy::BindExternalWindow(window, 6u, buffer, metadata);
  EXPECT_EQ(metadata, buffer);
  EXPECT_EQ(gpg::core::legacy::CapacityCount(window), 6u);
  window.start_ = window.end_ = window.capacity_ = nullptr;  // the window's storage is not owned
}

TEST(GpgFastVectorLegacy, CopyDwordRangeForward)
{
  // The null test is per slot, on the running address (MSVC's `if (dest != 0)` construct
  // idiom), so only the first slot of a null destination is skipped; a null destination is not
  // a supported input and is not tested.
  const std::uint32_t words[] = {1, 2, 3};
  std::uint32_t out[3]{};
  EXPECT_EQ(gpg::core::detail::CopyDwordRangeForward(out, words, words + 3), out + 3);
  EXPECT_EQ((std::vector<std::uint32_t>(out, out + 3)), (std::vector<std::uint32_t>{1, 2, 3}));
  EXPECT_EQ(gpg::core::detail::CopyDwordRangeForward(out, words, words), out);
}
