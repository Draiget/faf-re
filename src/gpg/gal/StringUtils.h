#pragma once

#include <cstddef>

#include "legacy/containers/String.h"

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

  /**
   * Address: 0x008EA3B0 (FUN_008EA3B0, gpg::gal::STR_FindInRange)
   *
   * What it does:
   * Scans a contiguous `msvc8::string` range and returns the first entry that
   * exactly matches `*search`; returns `end` when not found.
   */
  [[nodiscard]] msvc8::string* STR_FindInRange(
    msvc8::string* start, msvc8::string* end, const char* const* search
  ) noexcept;
} // namespace gpg::gal
