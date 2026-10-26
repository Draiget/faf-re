#pragma once

// Engine addition (dedicated-server plan WPL.5): std::atomic_ref for the Linux build. The
// shared code uses std::atomic_ref (C++20) on bytes and ints of engine structures; libc++ 18,
// the pinned Linux toolchain's library, does not ship it yet (__cpp_lib_atomic_ref unset).
// This is the subset the engine uses, on the compiler's __atomic builtins, with the
// standard's semantics. platform/PosixCompat.h includes it on Linux only; the Windows builds
// use the MSVC STL's own std::atomic_ref.

#include <atomic>
#include <type_traits>

#if !defined(__cpp_lib_atomic_ref)

namespace std
{
  template <class T>
  class atomic_ref
  {
    static_assert(std::is_trivially_copyable_v<T>, "atomic_ref needs a trivially copyable type");

  public:
    using value_type = T;

    explicit atomic_ref(T& object) noexcept
      : mObject(&object)
    {}

    atomic_ref(const atomic_ref&) noexcept = default;
    atomic_ref& operator=(const atomic_ref&) = delete;

    [[nodiscard]] T load(const memory_order order = memory_order_seq_cst) const noexcept
    {
      return __atomic_load_n(mObject, ToBuiltin(order));
    }

    void store(const T value, const memory_order order = memory_order_seq_cst) const noexcept
    {
      __atomic_store_n(mObject, value, ToBuiltin(order));
    }

    operator T() const noexcept
    {
      return load();
    }

    T exchange(const T value, const memory_order order = memory_order_seq_cst) const noexcept
    {
      return __atomic_exchange_n(mObject, value, ToBuiltin(order));
    }

    bool compare_exchange_weak(
      T& expected, const T desired, const memory_order success, const memory_order failure
    ) const noexcept
    {
      return __atomic_compare_exchange_n(mObject, &expected, desired, true, ToBuiltin(success), ToBuiltin(failure));
    }

    bool compare_exchange_weak(T& expected, const T desired, const memory_order order = memory_order_seq_cst)
      const noexcept
    {
      return compare_exchange_weak(expected, desired, order, FailureOrder(order));
    }

    bool compare_exchange_strong(
      T& expected, const T desired, const memory_order success, const memory_order failure
    ) const noexcept
    {
      return __atomic_compare_exchange_n(mObject, &expected, desired, false, ToBuiltin(success), ToBuiltin(failure));
    }

    bool compare_exchange_strong(T& expected, const T desired, const memory_order order = memory_order_seq_cst)
      const noexcept
    {
      return compare_exchange_strong(expected, desired, order, FailureOrder(order));
    }

    T fetch_add(const T value, const memory_order order = memory_order_seq_cst) const noexcept
    {
      return __atomic_fetch_add(mObject, value, ToBuiltin(order));
    }

    T fetch_sub(const T value, const memory_order order = memory_order_seq_cst) const noexcept
    {
      return __atomic_fetch_sub(mObject, value, ToBuiltin(order));
    }

    T fetch_and(const T value, const memory_order order = memory_order_seq_cst) const noexcept
    {
      return __atomic_fetch_and(mObject, value, ToBuiltin(order));
    }

    T fetch_or(const T value, const memory_order order = memory_order_seq_cst) const noexcept
    {
      return __atomic_fetch_or(mObject, value, ToBuiltin(order));
    }

    T fetch_xor(const T value, const memory_order order = memory_order_seq_cst) const noexcept
    {
      return __atomic_fetch_xor(mObject, value, ToBuiltin(order));
    }

  private:
    [[nodiscard]] static constexpr int ToBuiltin(const memory_order order) noexcept
    {
      switch (order) {
      case memory_order_relaxed:
        return __ATOMIC_RELAXED;
      case memory_order_consume:
        return __ATOMIC_CONSUME;
      case memory_order_acquire:
        return __ATOMIC_ACQUIRE;
      case memory_order_release:
        return __ATOMIC_RELEASE;
      case memory_order_acq_rel:
        return __ATOMIC_ACQ_REL;
      default:
        return __ATOMIC_SEQ_CST;
      }
    }

    [[nodiscard]] static constexpr memory_order FailureOrder(const memory_order order) noexcept
    {
      return order == memory_order_acq_rel ? memory_order_acquire
           : order == memory_order_release ? memory_order_relaxed
                                           : order;
    }

    T* mObject;
  };
} // namespace std

#endif // !defined(__cpp_lib_atomic_ref)
