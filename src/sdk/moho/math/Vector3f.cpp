#include "Vector3f.h"

#include <cmath>
#include <limits>

namespace moho
{
  /**
   * Address: 0x004EBEC0 (FUN_004EBEC0, Moho::Zeroed<Wm3::Quaternion<float>>)
   *
   * What it does:
   * Lazily initializes one process-static quaternion lane with all components
   * set to `0.0f`, then returns it by reference.
   */
  template <>
  const Wm3::Quaternionf& Zeroed<Wm3::Quaternionf>()
  {
    static Wm3::Quaternionf zeroQuaternion{};
    static bool initialized = false;
    if (!initialized) {
      zeroQuaternion.x = 0.0f;
      zeroQuaternion.y = 0.0f;
      zeroQuaternion.z = 0.0f;
      zeroQuaternion.w = 0.0f;
      initialized = true;
    }

    return zeroQuaternion;
  }

  /**
   * Address: 0x004EAD40 (FUN_004EAD40, Moho::Invalid<Wm3::Vector3<float>>)
   *
   * What it does:
   * Lazily initializes one process-static invalid vector with NaN lanes and
   * returns it by reference.
   */
  template <>
  const Wm3::Vector3f& Invalid<Wm3::Vector3f>()
  {
    static Wm3::Vector3f invalidVector{};
    static bool initialized = false;
    if (!initialized) {
      const float nanValue = std::numeric_limits<float>::quiet_NaN();
      invalidVector.x = nanValue;
      invalidVector.y = nanValue;
      invalidVector.z = nanValue;
      initialized = true;
    }

    return invalidVector;
  }

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
