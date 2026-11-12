#pragma once

#include <cstddef>

namespace moho_detail
{

  // "Require equality": defined only for Actual == Expected.
  template <std::size_t Actual, std::size_t Expected>
  struct require_size_equal; // primary template is incomplete (error when the values differ)

  template <std::size_t N>
  struct require_size_equal<N, N>
  {}; // specialization for equality: an empty type (OK)

  template <std::size_t Actual, std::size_t Expected>
  struct require_offset_equal; // the same for field offsets

  template <std::size_t N>
  struct require_offset_equal<N, N>
  {};
} // namespace moho_detail

// Token pasting for unique names
#define MOHO_CONCAT2(a, b) a##b
#define MOHO_CONCAT(a, b) MOHO_CONCAT2(a, b)

// Checks the size of a type. On a mismatch MSVC prints:
// "use of undefined type 'moho_detail::require_size_equal<8,4>'"
#define EXPECT_SIZE(T, EXPECTED)                                                                                       \
  typedef moho_detail::require_size_equal<sizeof(T), (EXPECTED)> MOHO_CONCAT(_expect_size_line_, __LINE__)

// Checks the offset of a field
#define EXPECT_OFFSET(T, FIELD, EXPECTED)                                                                              \
  typedef moho_detail::require_offset_equal<offsetof(T, FIELD), (EXPECTED)> MOHO_CONCAT(_expect_offs_line_, __LINE__)
