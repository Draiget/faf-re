// fa::deque (src/legacy/containers/Deque.h) against std::deque for every block size it picks,
// and fa::auto_ptr (AutoPtr.h).

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <random>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "ContainerTestTypes.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/Deque.h"

namespace
{
  using faf_container_tests::Tracked;

  /** 16 bytes: the deque keeps one element per block. */
  struct Wide
  {
    double value;
    double negated;
  };

  template <class E>
  [[nodiscard]] E Make(const int v)
  {
    if constexpr (std::is_same_v<E, Wide>) {
      return Wide{static_cast<double>(v), -static_cast<double>(v)};
    } else if constexpr (std::is_same_v<E, Tracked>) {
      return Tracked(v);
    } else {
      return static_cast<E>(v);
    }
  }

  template <class E>
  [[nodiscard]] int ValueOf(const E& e)
  {
    if constexpr (std::is_same_v<E, Wide>) {
      return static_cast<int>(e.value);
    } else if constexpr (std::is_same_v<E, Tracked>) {
      return e.value;
    } else {
      return static_cast<int>(e);
    }
  }

  template <class E>
  [[nodiscard]] std::vector<int> Contents(fa::deque<E>& d)
  {
    std::vector<int> out;
    for (auto it = d.begin(); it != d.end(); ++it) {
      out.push_back(ValueOf(*it));
    }
    std::vector<int> indexed;
    for (std::size_t i = 0; i < d.size(); ++i) {
      indexed.push_back(ValueOf(d[i]));
    }
    EXPECT_EQ(out, indexed);
    return out;
  }

  [[nodiscard]] std::vector<int> Contents(const std::deque<int>& d)
  {
    return std::vector<int>(d.begin(), d.end());
  }

  template <class E>
  void RunDequeRandomOps(const unsigned seed, const int steps)
  {
    std::mt19937 rng(seed);
    fa::deque<E> d;
    fa::deque<E> other;
    std::deque<int> ref;
    std::deque<int> otherRef;
    for (int step = 0; step < steps; ++step) {
      const unsigned op = rng() % 9u;
      // Values stay small so that every element type holds them exactly.
      const int value = static_cast<int>(rng() % 100u);
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op);
      switch (op) {
      case 0:
      case 1:
        d.push_back(Make<E>(value));
        ref.push_back(value);
        break;
      case 2:
      case 3:
        d.push_front(Make<E>(value));
        ref.push_front(value);
        break;
      case 4:
        if (!ref.empty()) {
          d.pop_back();
          ref.pop_back();
        }
        break;
      case 5:
        if (!ref.empty()) {
          d.pop_front();
          ref.pop_front();
        }
        break;
      case 6:
        if (rng() % 16u == 0u) {
          d.clear();
          ref.clear();
          ASSERT_EQ(d.capacity(), 0u);
        }
        break;
      case 7:
        d.swap(other);
        std::swap(ref, otherRef);
        break;
      default:
        if (!ref.empty()) {
          const std::size_t i = rng() % ref.size();
          ASSERT_EQ(ValueOf(d.at(i)), ref.at(i));
          d[i] = Make<E>(value);
          ref[i] = value;
        }
        break;
      }
      ASSERT_EQ(d.size(), ref.size());
      ASSERT_EQ(d.empty(), ref.empty());
      ASSERT_LE(d.size(), d.capacity());
      ASSERT_EQ(Contents(d), Contents(ref));
      ASSERT_EQ(other.size(), otherRef.size());
      if (!ref.empty()) {
        ASSERT_EQ(ValueOf(d.front()), ref.front());
        ASSERT_EQ(ValueOf(d.back()), ref.back());
        const fa::deque<E>& constDeque = d;
        ASSERT_EQ(ValueOf(constDeque.front()), ref.front());
        ASSERT_EQ(ValueOf(constDeque.back()), ref.back());
        ASSERT_EQ(ValueOf(constDeque[ref.size() - 1]), ref.back());
        ASSERT_EQ(ValueOf(constDeque.at(0)), ref.front());
      }
      if constexpr (std::is_same_v<E, Tracked>) {
        ASSERT_EQ(Tracked::live, static_cast<long>(d.size() + other.size()));
        ASSERT_EQ(Tracked::badAccesses, 0);
      }
    }
    ASSERT_EQ(Contents(other), Contents(otherRef));
  }
} // namespace

TEST(FaDeque, BlockSizeFollowsTheElementSize)
{
  EXPECT_EQ(fa::deque<char>::kBlockSize, 16u);
  EXPECT_EQ(fa::deque<std::int16_t>::kBlockSize, 8u);
  EXPECT_EQ(fa::deque<std::int32_t>::kBlockSize, 4u);
  EXPECT_EQ(fa::deque<double>::kBlockSize, 2u);
  EXPECT_EQ(fa::deque<Wide>::kBlockSize, 1u);
}

TEST(FaDeque, EmptyDequeHasNoMap)
{
  fa::deque<int> d;
  EXPECT_TRUE(d.empty());
  EXPECT_EQ(d.capacity(), 0u);
  EXPECT_EQ(d.begin(), d.end());
  EXPECT_THROW((void)d.at(0), std::out_of_range);
}

TEST(FaDeque, TheFirstPushAllocatesEightBlocks)
{
  fa::deque<int> back;
  back.push_back(1);
  EXPECT_EQ(back.capacity(), 8u * fa::deque<int>::kBlockSize);
  fa::deque<int> front;
  front.push_front(1);
  EXPECT_EQ(front.capacity(), 8u * fa::deque<int>::kBlockSize);
  EXPECT_EQ(front.front(), 1);
}

TEST(FaDeque, IteratorArithmetic)
{
  fa::deque<int> d;
  for (int i = 0; i < 10; ++i) {
    d.push_back(i);
  }
  auto it = d.begin();
  it += 4;
  EXPECT_EQ(*it, 4);
  EXPECT_EQ(*(it + 3), 7);
  EXPECT_EQ(*(2 + it), 6);
  EXPECT_EQ(*(it - 2), 2);
  EXPECT_EQ(d.end() - d.begin(), 10);
  EXPECT_LT(d.begin(), it);
  EXPECT_GE(d.end(), it);
  it -= 4;
  EXPECT_EQ(it, d.begin());
  EXPECT_EQ(*it++, 0);
  EXPECT_EQ(*it--, 1);
  EXPECT_EQ(*it, 0);
}

TEST(FaDeque, ClearAndReleaseThenReuse)
{
  fa::deque<int> d;
  for (int i = 0; i < 50; ++i) {
    d.push_front(i);
  }
  d.clear_and_release();
  EXPECT_TRUE(d.empty());
  EXPECT_EQ(d.capacity(), 0u);
  d.push_back(3);
  d.push_front(2);
  EXPECT_EQ(Contents(d), (std::vector<int>{2, 3}));
}

TEST(FaDeque, RandomOpsMatchStdDequeChar)
{
  RunDequeRandomOps<char>(1, 4000);
}

TEST(FaDeque, RandomOpsMatchStdDequeShort)
{
  RunDequeRandomOps<std::int16_t>(2, 4000);
}

TEST(FaDeque, RandomOpsMatchStdDequeInt)
{
  RunDequeRandomOps<int>(3, 4000);
  RunDequeRandomOps<int>(4, 4000);
}

TEST(FaDeque, RandomOpsMatchStdDequeDouble)
{
  RunDequeRandomOps<double>(5, 4000);
}

TEST(FaDeque, RandomOpsMatchStdDequeWideElement)
{
  RunDequeRandomOps<Wide>(6, 4000);
}

TEST(FaDeque, RandomOpsMatchStdDequeTrackedElement)
{
  Tracked::ResetCounters();
  RunDequeRandomOps<Tracked>(7, 4000);
  EXPECT_EQ(Tracked::live, 0);
  EXPECT_EQ(Tracked::badAccesses, 0);
}

TEST(FaDeque, GrowsTheMapWhileWrappedAround)
{
  // pop_front moves the offset forward, so the next pushes at the back wrap around the map
  // before it grows; the growth must keep the logical order.
  fa::deque<int> d;
  std::deque<int> ref;
  int next = 0;
  for (int round = 0; round < 40; ++round) {
    for (int i = 0; i < 7; ++i) {
      d.push_back(next);
      ref.push_back(next);
      ++next;
    }
    for (int i = 0; i < 5; ++i) {
      d.pop_front();
      ref.pop_front();
    }
    d.push_front(-round);
    ref.push_front(-round);
    ASSERT_EQ(Contents(d), Contents(ref)) << "round " << round;
  }
}

// --- fa::auto_ptr ------------------------------------------------------------------------------

namespace
{
  struct Base
  {
    static inline int destroyed = 0;
    int value = 0;
    explicit Base(const int v)
      : value(v)
    {}
    virtual ~Base()
    {
      ++destroyed;
    }
  };

  struct Derived : Base
  {
    explicit Derived(const int v)
      : Base(v)
    {}
  };

  [[nodiscard]] fa::auto_ptr<Derived> MakeDerived(const int v)
  {
    return fa::auto_ptr<Derived>(new Derived(v));
  }
} // namespace

TEST(FaAutoPtr, OwnershipMovesOnCopyAndAssignment)
{
  Base::destroyed = 0;
  {
    fa::auto_ptr<Base> a(new Base(1));
    EXPECT_TRUE(static_cast<bool>(a));
    fa::auto_ptr<Base> b(a);
    EXPECT_EQ(a.get(), nullptr);
    EXPECT_FALSE(static_cast<bool>(a));
    EXPECT_TRUE(!a);
    EXPECT_EQ(b->value, 1);
    EXPECT_EQ((*b).value, 1);

    fa::auto_ptr<Base> c;
    c = b;
    EXPECT_EQ(b.get(), nullptr);
    EXPECT_EQ(c->value, 1);
    EXPECT_EQ(Base::destroyed, 0);

    fa::auto_ptr<Base>& alias = c;
    c = alias;
    EXPECT_EQ(c->value, 1);
    EXPECT_EQ(Base::destroyed, 0);
  }
  EXPECT_EQ(Base::destroyed, 1);
}

TEST(FaAutoPtr, ResetReleaseAndSwap)
{
  Base::destroyed = 0;
  fa::auto_ptr<Base> a(new Base(1));
  Base* const same = a.get();
  a.reset(same);
  EXPECT_EQ(Base::destroyed, 0);
  a.reset(new Base(2));
  EXPECT_EQ(Base::destroyed, 1);
  EXPECT_EQ(a->value, 2);

  Base* const released = a.release();
  EXPECT_EQ(a.get(), nullptr);
  EXPECT_EQ(released->value, 2);
  delete released;
  EXPECT_EQ(Base::destroyed, 2);

  a = new Base(3);
  fa::auto_ptr<Base> b(new Base(4));
  a.swap(b);
  EXPECT_EQ(a->value, 4);
  EXPECT_EQ(b->value, 3);
  fa::swap(a, b);
  EXPECT_EQ(a->value, 3);
  a.reset();
  EXPECT_EQ(Base::destroyed, 3);
  EXPECT_TRUE(a == nullptr);
  EXPECT_TRUE(nullptr == a);
  EXPECT_TRUE(b != nullptr);
  EXPECT_TRUE(b == b.get());
  EXPECT_FALSE(a == b);
}

TEST(FaAutoPtr, ConvertsFromDerivedThroughTheRef)
{
  Base::destroyed = 0;
  {
    fa::auto_ptr<Derived> d(new Derived(5));
    fa::auto_ptr<Base> b(d);
    EXPECT_EQ(d.get(), nullptr);
    EXPECT_EQ(b->value, 5);

    fa::auto_ptr<Base> fromTemporary(MakeDerived(6));
    EXPECT_EQ(fromTemporary->value, 6);

    fa::auto_ptr<Base> assigned;
    assigned = MakeDerived(7);
    EXPECT_EQ(assigned->value, 7);

    fa::auto_ptr<Derived> source(new Derived(8));
    assigned = source;
    EXPECT_EQ(assigned->value, 8);
    EXPECT_EQ(Base::destroyed, 1);
  }
  EXPECT_EQ(Base::destroyed, 4);
}
