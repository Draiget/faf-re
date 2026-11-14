#include "gpg/gal/StringUtils.h"

#include <cstdint>
#include <cstring>

namespace gpg::gal
{
  /**
   * Address: 0x00408450 (FUN_00408450, gpg::gal::STR_Compare)
   *
   * What it does:
   * Length-bounded byte comparison normalized to -1 / 0 / +1.
   *
   * The binary's word-then-byte loop is MSVC's inline expansion of memcmp:
   * it returns the sign of the first differing byte.
   */
  int STR_Compare(
    const char* lhs,
    const char* rhs,
    const std::size_t length
  ) noexcept
  {
    const int result = std::memcmp(lhs, rhs, length);
    return result < 0 ? -1 : (result > 0 ? 1 : 0);
  }

  /**
   * Address: 0x008EA3B0 (FUN_008EA3B0, gpg::gal::STR_FindInRange)
   *
   * What it does:
   * Iterates `[start, end)` and returns the first string that exactly matches
   * `*search`; returns `end` when no exact match is present.
   */
  fa::string* STR_FindInRange(
    fa::string* start,
    fa::string* end,
    const char* const* search
  ) noexcept
  {
    fa::string* iter = start;
    if (iter == end) {
      return iter;
    }

    const char* const needle = *search;
    do {
      const std::size_t needleLength = std::strlen(needle);
      const std::size_t candidateLength = iter->size();
      const std::size_t compareLength = (candidateLength < needleLength) ? candidateLength : needleLength;

      const int compareResult = STR_Compare(iter->raw_data_unsafe(), needle, compareLength);
      if (compareResult == 0 && candidateLength >= needleLength) {
        if (candidateLength == needleLength) {
          break;
        }
      }

      ++iter;
    } while (iter != end);

    return iter;
  }
} // namespace gpg::gal
