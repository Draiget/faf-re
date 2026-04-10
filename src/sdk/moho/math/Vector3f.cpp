#include "Vector3f.h"

#include <cmath>

namespace moho
{
  /**
   * Address: 0x00570750 (FUN_00570750, Moho::EulerRollToQuat)
   *
   * What it does:
   * Converts one axis+roll pair into quaternion lanes.
   */
  Wm3::Quatf* EulerRollToQuat(const Wm3::Vector3f* const axis, Wm3::Quatf* const outQuaternion, const float roll)
  {
    const float halfRoll = roll * 0.5f;
    const float sinHalfRoll = std::sinf(halfRoll);
    outQuaternion->w = std::cosf(halfRoll);
    outQuaternion->x = axis->x * sinHalfRoll;
    outQuaternion->y = axis->y * sinHalfRoll;
    outQuaternion->z = axis->z * sinHalfRoll;
    return outQuaternion;
  }
} // namespace moho
