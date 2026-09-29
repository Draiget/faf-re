#pragma once

#include <algorithm>
#include <cstddef>
#include <type_traits>

namespace platform
{
  /**
   * Bytes to allocate for an object whose size is known from the x86 binary
   * (an `operator new(0x198)` at the allocation site) rather than from a
   * complete recovered class.
   *
   * On x86 it is exactly the binary's size. On x64 every pointer, vtable
   * pointer and size_t doubles, so the object is at most twice as large as on
   * x86 (every member's size and alignment at most double); the result is the
   * larger of that bound and `sizeof(T)`.
   */
  template <class T = void>
  [[nodiscard]] constexpr std::size_t BinaryObjectBytes(const std::size_t x86Bytes) noexcept
  {
#if defined(_M_IX86)
    return x86Bytes;
#else
    if constexpr (std::is_void_v<T>) {
      return 2u * x86Bytes;
    } else {
      return (std::max)(sizeof(T), 2u * x86Bytes);
    }
#endif
  }
} // namespace platform
