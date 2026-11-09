#pragma once

// Element types and helpers shared by the container suites (tests/containers).

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <vector>

namespace faf_container_tests
{
  /**
   * An element that counts its live instances and carries a magic word its destructor clears.
   * A copy or move that reads a destroyed object, or an assignment onto one, counts as a bad
   * access, so a container that reads an element after it freed or destroyed it shows up in
   * `badAccesses`. A moved-from object keeps its magic but takes `kMovedFrom` as its value, so a
   * moved-from element that stays visible shows up in the contents.
   *
   * `NothrowMove` picks which of the containers' relocation paths runs: a nothrow move, or the
   * copy path a container takes when the move may throw.
   */
  template <bool NothrowMove>
  struct BasicTracked
  {
    static constexpr std::uint32_t kAlive = 0xA11CE5EDu;
    static constexpr std::uint32_t kDead = 0xDEADDEADu;
    static constexpr int kMovedFrom = -77777;

    static inline long live = 0;
    static inline long badAccesses = 0;

    int value = 0;
    std::uint32_t magic = kAlive;

    static void ResetCounters() noexcept
    {
      live = 0;
      badAccesses = 0;
    }

    BasicTracked() noexcept
    {
      ++live;
    }

    explicit BasicTracked(const int v) noexcept
      : value(v)
    {
      ++live;
    }

    BasicTracked(const BasicTracked& other) noexcept
      : value(other.value)
    {
      Check(other);
      ++live;
    }

    BasicTracked(BasicTracked&& other) noexcept(NothrowMove)
      : value(other.value)
    {
      Check(other);
      other.value = kMovedFrom;
      ++live;
    }

    BasicTracked& operator=(const BasicTracked& other) noexcept
    {
      Check(other);
      Check(*this);
      value = other.value;
      return *this;
    }

    BasicTracked& operator=(BasicTracked&& other) noexcept(NothrowMove)
    {
      Check(other);
      Check(*this);
      value = other.value;
      if (&other != this) {
        other.value = kMovedFrom;
      }
      return *this;
    }

    ~BasicTracked()
    {
      Check(*this);
      magic = kDead;
      --live;
    }

    friend bool operator==(const BasicTracked& a, const BasicTracked& b) noexcept
    {
      return a.value == b.value;
    }

    friend bool operator<(const BasicTracked& a, const BasicTracked& b) noexcept
    {
      return a.value < b.value;
    }

    friend std::ostream& operator<<(std::ostream& out, const BasicTracked& t)
    {
      return out << "Tracked(" << t.value << ")";
    }

  private:
    static void Check(const BasicTracked& t) noexcept
    {
      if (t.magic != kAlive) {
        ++badAccesses;
      }
    }
  };

  using Tracked = BasicTracked<true>;
  using TrackedCopyRelocated = BasicTracked<false>;

  /** The `value`s of a range of `BasicTracked`, or the range itself for plain ints. */
  template <class It>
  [[nodiscard]] std::vector<int> Values(It first, It last)
  {
    std::vector<int> out;
    for (; first != last; ++first) {
      if constexpr (requires { (*first).value; }) {
        out.push_back((*first).value);
      } else {
        out.push_back(static_cast<int>(*first));
      }
    }
    return out;
  }

  template <class Container>
  [[nodiscard]] std::vector<int> Values(const Container& c)
  {
    return Values(c.begin(), c.end());
  }
} // namespace faf_container_tests
