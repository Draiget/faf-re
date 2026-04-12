#pragma once

#include <cstddef>

namespace gpg::gal
{
  /**
   * Address: 0x00408450 (FUN_00408450, gpg::gal::STR_Compare)
   *
   * What it does:
   * Length-bounded byte comparison of two strings, like `memcmp` but normalized
   * to `-1`/`0`/`+1` instead of negative/zero/positive. The binary uses an
   * inlined 4-byte word comparison loop followed by per-byte fallback for
   * tail bytes; this implementation matches that observable behavior.
   */
  [[nodiscard]] int STR_Compare(const char* lhs, const char* rhs, std::size_t length) noexcept;
} // namespace gpg::gal
