#pragma once

#include "wm3/Vector3.h"
#include "wm3/Quaternion.h"

namespace moho
{
  using Vector3f = Wm3::Vector3f;

  /**
   * Address: 0x00570750 (FUN_00570750, Moho::EulerRollToQuat)
   *
   * What it does:
   * Builds one quaternion from axis + roll radians (`axis * sin(roll/2)`,
   * `w = cos(roll/2)`).
   */
  Wm3::Quatf* EulerRollToQuat(const Wm3::Vector3f* axis, Wm3::Quatf* outQuaternion, float roll);

  static_assert(sizeof(Vector3f) == 0x0C, "moho::Vector3f size must be 0x0C");
} // namespace moho
