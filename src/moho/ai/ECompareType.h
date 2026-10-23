#pragma once

#include <cstdint>

namespace moho
{
  enum ECompareType : std::int32_t
  {
    COMPARE_Closest = 0,
    COMPARE_Furthest = 1,
    COMPARE_HighestValue = 2,
    COMPARE_LeastDefended = 4,
  };

  static_assert(sizeof(ECompareType) == 0x04, "ECompareType size must be 0x04");
} // namespace moho

