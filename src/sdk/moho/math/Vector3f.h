#pragma once

#include "Wm3Vector3.h"
#include "Wm3Quaternion.h"

namespace moho
{
  using Vector3f = Wm3::Vector3f;

  template <class T>
  [[nodiscard]] const T& Zeroed();

  template <class T>
  [[nodiscard]] const T& Invalid();

  /**
   * Address: 0x005B1C90 (FUN_005B1C90, func_VecSetLengthS)
   *
   * What it does:
   * Scales a 3D vector in place so its length matches the requested target
   * length.
   */
  [[nodiscard]] bool VecSetLength(Wm3::Vector3f* vector, float targetLength);

  /**
   * Address: 0x00570750 (FUN_00570750, Moho::EulerRollToQuat)
   *
   * What it does:
   * Builds one quaternion from axis + roll radians (`axis * sin(roll/2)`,
   * `w = cos(roll/2)`).
   */
  Wm3::Quatf* EulerRollToQuat(const Wm3::Vector3f* axis, Wm3::Quatf* outQuaternion, float roll);

  /**
   * Address: 0x004EAD40 (FUN_004EAD40, Moho::Invalid<Wm3::Vector3<float>>)
   *
   * What it does:
   * Returns process-lifetime singleton invalid Vector3f (all lanes set to NaN).
   */
  template <>
  [[nodiscard]] const Wm3::Vector3f& Invalid<Wm3::Vector3f>();

  /**
   * Address: 0x004EBEC0 (FUN_004EBEC0, Moho::Zeroed<Wm3::Quaternion<float>>)
   *
   * What it does:
   * Returns process-lifetime singleton zero Quaternionf
   * (`x=y=z=w=0.0f`).
   */
  template <>
  [[nodiscard]] const Wm3::Quaternionf& Zeroed<Wm3::Quaternionf>();

  static_assert(sizeof(Vector3f) == 0x0C, "moho::Vector3f size must be 0x0C");
} // namespace moho
