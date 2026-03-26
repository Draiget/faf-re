#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x007705A0 (FUN_007705A0)
   *
   * What it does:
   * Emitter curve lanes used by particle emitters.
   */
  enum EEmitterCurve : std::int32_t
  {
    EMITTER_XDIR_CURVE = 0,
    EMITTER_YDIR_CURVE = 1,
    EMITTER_ZDIR_CURVE = 2,
    EMITTER_EMITRATE_CURVE = 3,
    EMITTER_LIFETIME_CURVE = 4,
    EMITTER_VELOCITY_CURVE = 5,
    EMITTER_X_ACCEL_CURVE = 6,
    EMITTER_Y_ACCEL_CURVE = 7,
    EMITTER_Z_ACCEL_CURVE = 8,
    EMITTER_RESISTANCE_CURVE = 9,
    EMITTER_SIZE_CURVE = 10,
    EMITTER_X_POSITION_CURVE = 11,
    EMITTER_Y_POSITION_CURVE = 12,
    EMITTER_Z_POSITION_CURVE = 13,
    EMITTER_BEGINSIZE_CURVE = 14,
    EMITTER_ENDSIZE_CURVE = 15,
    EMITTER_ROTATION_CURVE = 16,
    EMITTER_ROTATION_RATE_CURVE = 17,
    EMITTER_FRAMERATE_CURVE = 18,
    EMITTER_TEXTURESELECTION_CURVE = 19,
    EMITTER_RAMPSELECTION_CURVE = 20,
    EMITTER_LAST_CURVE = 21,
  };

  static_assert(sizeof(EEmitterCurve) == 0x4, "EEmitterCurve size must be 4 bytes");
} // namespace moho
