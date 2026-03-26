#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x00770850 (FUN_00770850)
   *
   * What it does:
   * Scalar parameter lanes consumed by runtime particle emitters.
   */
  enum EEmitterParam : std::int32_t
  {
    EFFECT_POSITION = 0,
    EFFECT_POSITION_X = 0,
    EFFECT_POSITION_Y = 1,
    EFFECT_POSITION_Z = 2,
    EFFECT_TICKCOUNT = 3,
    EFFECT_LIFETIME = 4,
    EFFECT_REPEATTIME = 5,
    EFFECT_TICKINCREMENT = 6,
    EFFECT_BLENDMODE = 7,
    EFFECT_FRAMECOUNT = 8,
    EFFECT_USE_LOCAL_VELOCITY = 9,
    EFFECT_USE_LOCAL_ACCELERATION = 10,
    EFFECT_USE_GRAVITY = 11,
    EFFECT_ALIGN_ROTATION = 12,
    EFFECT_INTERPOLATE_EMISSION = 13,
    EFFECT_TEXTURE_STRIPCOUNT = 14,
    EFFECT_ALIGN_TO_BONE = 15,
    EFFECT_SORTORDER = 16,
    EFFECT_FLAT = 17,
    EFFECT_SCALE = 18,
    EFFECT_LODCUTOFF = 19,
    EFFECT_EMITIFVISIBLE = 20,
    EFFECT_CATCHUPEMIT = 21,
    EFFECT_CREATEIFVISIBLE = 22,
    EFFECT_SNAPTOWATERLINE = 23,
    EFFECT_ONLYEMITONWATER = 24,
    EFFECT_PARTICLERESISTANCE = 25,
    EFFECT_LASTPARAM = 26,
  };

  static_assert(sizeof(EEmitterParam) == 0x4, "EEmitterParam size must be 4 bytes");
} // namespace moho
