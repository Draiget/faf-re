#include "gpg/gal/StringUtils.h"

#include <cstdint>

namespace gpg::gal
{
  /**
   * Address: 0x00408450 (FUN_00408450, gpg::gal::STR_Compare)
   *
   * What it does:
   * Length-bounded byte comparison normalized to -1 / 0 / +1.
   *
   * The binary uses an aggressive 4-byte word compare loop while at least
   * 4 bytes remain, then drops to per-byte comparison for the tail. We
   * mirror that exact loop structure to preserve identical behavior on
   * misaligned reads and short tails.
   */
  int STR_Compare(const char* lhs, const char* rhs, const std::size_t length) noexcept
  {
    std::size_t remaining = length;

    // 4-byte word comparison while at least 4 bytes remain.
    if (remaining >= 4u) {
      while (*reinterpret_cast<const std::uint32_t*>(lhs) == *reinterpret_cast<const std::uint32_t*>(rhs)) {
        remaining -= 4u;
        rhs += 4;
        lhs += 4;
        if (remaining < 4u) {
          break;
        }
      }
    }

    if (remaining == 0u) {
      return 0;
    }

    // Per-byte fallback (manually unrolled to match the binary control flow).
    int diff = static_cast<int>(static_cast<unsigned char>(*lhs)) - static_cast<int>(static_cast<unsigned char>(*rhs));
    if (diff == 0) {
      remaining -= 1u;
      ++lhs;
      ++rhs;
      if (remaining == 0u) {
        return 0;
      }
      diff = static_cast<int>(static_cast<unsigned char>(*lhs)) - static_cast<int>(static_cast<unsigned char>(*rhs));
      if (diff == 0) {
        remaining -= 1u;
        ++lhs;
        ++rhs;
        if (remaining == 0u) {
          return 0;
        }
        diff = static_cast<int>(static_cast<unsigned char>(*lhs)) - static_cast<int>(static_cast<unsigned char>(*rhs));
        if (diff == 0) {
          ++lhs;
          ++rhs;
          if (remaining == 1u) {
            return 0;
          }
          diff = static_cast<int>(static_cast<unsigned char>(*lhs)) - static_cast<int>(static_cast<unsigned char>(*rhs));
          if (diff == 0) {
            return 0;
          }
        }
      }
    }

    if (diff <= 0) {
      return -1;
    }
    return 1;
  }
} // namespace gpg::gal
