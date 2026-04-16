#pragma once

#include "Wm3Vector3.h"

namespace moho
{
  struct SPhysConstants
  {
    /**
     * Address: 0x00699A90 (FUN_00699A90, Moho::SPhysConstants::SPhysConstants)
     *
     * What it does:
     * Initializes gravity constants to `(0.0f, -4.9f, 0.0f)`.
     */
    SPhysConstants() noexcept;

    Wm3::Vec3f mGravity;
  };

  static_assert(sizeof(SPhysConstants) == 0x0C, "SPhysConstants size must be 0x0C");
} // namespace moho
