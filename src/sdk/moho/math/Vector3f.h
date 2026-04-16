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
   * Address: 0x004ED810 (FUN_004ED810)
   *
   * What it does:
   * Scales one vector in place by `1/divisor`; when `divisor == 0`, writes
   * `FLT_MAX` into all three lanes.
   */
  [[nodiscard]] Wm3::Vector3f* VecScaleByReciprocalOrSetMax(
    Wm3::Vector3f* vector,
    float divisor
  ) noexcept;

  /**
   * Address: 0x0069A360 (FUN_0069A360, func_VecSetLengthTo)
   *
   * What it does:
   * Writes `sourceVector` scaled to the magnitude of `targetLengthVector`
   * into `destination`; if `sourceVector` is zero-length, copies
   * `targetLengthVector` directly.
   */
  [[nodiscard]] Wm3::Vector3f* VecSetLengthTo(
    Wm3::Vector3f* destination,
    const Wm3::Vector3f* targetLengthVector,
    const Wm3::Vector3f* sourceVector
  ) noexcept;

  /**
   * Address: 0x0069A230 (FUN_0069A230)
   *
   * What it does:
   * Reflects `incident` about `normal` (`incident - 2*dot(incident,normal)*normal`)
   * and writes the result into `destination`.
   */
  [[nodiscard]] Wm3::Vector3f* ReflectVector3fAcrossNormal(
    Wm3::Vector3f* destination,
    const Wm3::Vector3f* incident,
    const Wm3::Vector3f* normal
  ) noexcept;

  /**
   * Address: 0x005657F0 (FUN_005657F0, Moho::IsValid_Vector3f)
   *
   * What it does:
   * Returns true when all three lanes of the input vector are non-NaN. Shared
   * validator with 54+ callsites across unit motion, tasks, and command lanes.
   */
  [[nodiscard]] bool IsValidVector3f(const Wm3::Vector3f& value) noexcept;

  /**
   * Address: 0x0069A1D0 (FUN_0069A1D0, sub_69A1D0)
   *
   * What it does:
   * Returns true when the vector squared-length is within `0.001f` of unit
   * length.
   */
  [[nodiscard]] bool IsUnitLengthVector3f(const Wm3::Vector3f& value) noexcept;

  /**
   * Address: 0x004CC960 (FUN_004CC960)
   *
   * What it does:
   * Returns squared Euclidean 3D distance between two Vector3f points.
   */
  [[nodiscard]] float DistanceSquared3D(const Wm3::Vector3f& from, const Wm3::Vector3f& to) noexcept;

  /**
   * Address: 0x005382E0 (FUN_005382E0, Moho::VEC_LargestAxis)
   *
   * What it does:
   * Returns index of the axis with the largest absolute component
   * (`0=x`, `1=y`, `2=z`).
   */
  [[nodiscard]] int VEC_LargestAxis(const Wm3::Vector3f& value) noexcept;

  /**
   * Address: 0x00565A10 (FUN_00565A10)
   *
   * What it does:
   * Returns the planar heading angle in radians from one vector lane using
   * `atan2(x, z)`.
   */
  [[nodiscard]] float VEC_HeadingFromXZ(const Wm3::Vector3f* value) noexcept;

  /**
   * Address: 0x00570750 (FUN_00570750, Moho::EulerRollToQuat)
   *
   * What it does:
   * Builds one quaternion from axis + roll radians (`axis * sin(roll/2)`,
   * `w = cos(roll/2)`).
   */
  Wm3::Quatf* EulerRollToQuat(const Wm3::Vector3f* axis, Wm3::Quatf* outQuaternion, float roll);

  /**
   * Address: 0x004EAD30 (FUN_004EAD30, Moho::Zeroed<Wm3::Vector3<float>>)
   *
   * What it does:
   * Returns process-lifetime singleton zero Vector3f (`x=y=z=0.0f`).
   */
  template <>
  [[nodiscard]] const Wm3::Vector3f& Zeroed<Wm3::Vector3f>();

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
