#pragma once

// Engine addition (dedicated-server plan WPL.5, WPL.6): the operand type of the MSVC
// interlocked intrinsics (_InterlockedExchangeAdd, _InterlockedIncrement, ...). They work
// on Windows' 32-bit `long`. clang provides the same intrinsics on Linux (-fms-extensions)
// on a 32-bit `int` there, since `long` is 64-bit (LP64). Code that casts a 32-bit field
// for them casts to this type. New code uses the helpers below, which need no cast.

#include <atomic>
#include <bit>
#include <cstdint>

namespace platform
{
#if defined(_WIN32)
  using InterlockedLong = long;
#else
  using InterlockedLong = int;
#endif
  static_assert(sizeof(InterlockedLong) == 4, "the interlocked intrinsics operate on 32-bit values");

  // Atomic operations on a 32-bit field that isn't a std::atomic, because a recovered layout or
  // lock-free counter fixes its type. All sequentially consistent, as the intrinsics' full barriers.
  [[nodiscard]] inline std::atomic_ref<std::int32_t> AtomicField(volatile std::int32_t* const slot) noexcept
  {
    return std::atomic_ref<std::int32_t>(const_cast<std::int32_t&>(*slot));
  }

  [[nodiscard]] inline std::int32_t AtomicLoad(volatile std::int32_t* const slot) noexcept
  {
    return AtomicField(slot).load();
  }

  // Each of these returns the value before the operation.
  inline std::int32_t AtomicExchange(volatile std::int32_t* const slot, const std::int32_t value) noexcept
  {
    return AtomicField(slot).exchange(value);
  }

  inline std::int32_t AtomicAdd(volatile std::int32_t* const slot, const std::int32_t delta) noexcept
  {
    return AtomicField(slot).fetch_add(delta);
  }

  inline std::int32_t AtomicCompareExchange(
    volatile std::int32_t* const slot, const std::int32_t desired, const std::int32_t expected
  ) noexcept
  {
    std::int32_t previous = expected;
    (void)AtomicField(slot).compare_exchange_strong(previous, desired);
    return previous;
  }

  // Adds to a float stored as its bits. The sum's operand order matters for NaNs: current + delta.
  inline std::int32_t AtomicAddFloat(volatile std::int32_t* const slot, const float delta) noexcept
  {
    for (;;) {
      const std::int32_t observed = AtomicLoad(slot);
      const float next = std::bit_cast<float>(observed) + delta;
      if (AtomicCompareExchange(slot, std::bit_cast<std::int32_t>(next), observed) == observed) {
        return observed;
      }
    }
  }
} // namespace platform
