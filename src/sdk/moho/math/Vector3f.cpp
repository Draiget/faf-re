#include "Vector3f.h"

#include <cmath>
#include <limits>

namespace moho
{
  /**
   * Address: 0x005657F0 (FUN_005657F0, Moho::IsValid_Vector3f)
   *
   * What it does:
   * Checks each Vector3f lane for NaN. Binary uses a chain of `isnan(x/y/z)`
   * calls; mirrored here as `!std::isnan(...)` to preserve the exact
   * "reject NaN, accept infinities" semantic of the original.
   */
  [[nodiscard]] bool IsValidVector3f(const Wm3::Vector3f& value) noexcept
  {
    return !std::isnan(value.x) && !std::isnan(value.y) && !std::isnan(value.z);
  }

  /**
   * Address: 0x004CC960 (FUN_004CC960)
   *
   * What it does:
   * Returns squared Euclidean 3D distance between two Vector3f points.
   */
  float DistanceSquared3D(const Wm3::Vector3f& from, const Wm3::Vector3f& to) noexcept
  {
    const float dx = to.x - from.x;
    const float dy = to.y - from.y;
    const float dz = to.z - from.z;
    return (dx * dx) + (dy * dy) + (dz * dz);
  }

  /**
   * Address: 0x005382E0 (FUN_005382E0, Moho::VEC_LargestAxis)
   *
   * What it does:
   * Returns the axis index (`0=x`, `1=y`, `2=z`) of the component
   * with greatest absolute magnitude.
   */
  int VEC_LargestAxis(const Wm3::Vector3f& value) noexcept
  {
    const bool yDominatesX = std::fabs(value.y) > std::fabs(value.x);
    const int dominantAxis = yDominatesX ? 1 : 0;
    const float* const lanes = &value.x;
    if (std::fabs(value.z) <= std::fabs(lanes[dominantAxis])) {
      return dominantAxis;
    }

    return 2;
  }

  /**
   * Address: 0x005B1C90 (FUN_005B1C90, func_VecSetLengthS)
   *
   * What it does:
   * Normalizes the input vector and then rescales it to the requested target
   * length. Returns false when the source vector has no positive squared
   * length.
   */
  [[nodiscard]] bool VecSetLength(Wm3::Vector3f* const vector, const float targetLength)
  {
    const float x = vector->x;
    const float lengthSq = (x * x) + (vector->y * vector->y) + (vector->z * vector->z);
    if (lengthSq <= 0.0f) {
      return false;
    }

    const float scale = targetLength / std::sqrtf(lengthSq);
    vector->x = x * scale;
    vector->y *= scale;
    vector->z *= scale;
    return true;
  }

  /**
   * Address: 0x0069A360 (FUN_0069A360, func_VecSetLengthTo)
   *
   * What it does:
   * Scales `sourceVector` to match the length of `targetLengthVector` and
   * stores the result in `destination`; falls back to copying
   * `targetLengthVector` when `sourceVector` has zero squared length.
   */
  Wm3::Vector3f* VecSetLengthTo(
    Wm3::Vector3f* const destination,
    const Wm3::Vector3f* const targetLengthVector,
    const Wm3::Vector3f* const sourceVector
  ) noexcept
  {
    const float sourceX = sourceVector->x;
    const float sourceLengthSq =
      (sourceX * sourceX) + (sourceVector->y * sourceVector->y) + (sourceVector->z * sourceVector->z);
    if (sourceLengthSq <= 0.0f) {
      *destination = *targetLengthVector;
      return destination;
    }

    const float targetLengthSq =
      (targetLengthVector->x * targetLengthVector->x) + (targetLengthVector->y * targetLengthVector->y) +
      (targetLengthVector->z * targetLengthVector->z);
    const float scale = std::sqrtf(targetLengthSq / sourceLengthSq);
    destination->x = sourceX * scale;
    destination->y = sourceVector->y * scale;
    destination->z = sourceVector->z * scale;
    return destination;
  }

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
