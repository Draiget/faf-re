#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x00770E90 (FUN_00770E90)
   *
   * What it does:
   * Runtime trail effect scalar parameter lanes.
   */
  enum ETrailParam : std::int32_t
  {
    TRAIL_POSITION = 0,
    TRAIL_POSITION_X = 0,
    TRAIL_POSITION_Y = 1,
    TRAIL_POSITION_Z = 2,
    TRAIL_LIFETIME = 3,
    TRAIL_LENGTH = 4,
    TRAIL_SCALE = 5,
    TRAIL_LASTPARAM = 6,
  };

  static_assert(sizeof(ETrailParam) == 0x4, "ETrailParam size must be 4 bytes");
} // namespace moho
