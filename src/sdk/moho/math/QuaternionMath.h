#pragma once

#include "wm3/Quaternion.h"
#include "wm3/Vector3.h"

namespace moho
{
  /**
   * Address: 0x004EB740 (FUN_004EB740, fun_RotateQuat)
   *
   * IDA signature:
   * char __usercall fun_RotateQuat@<al>(float *quat@<esi>, float rads);
   *
   * What it does:
   * Modifies a quaternion in-place to represent a partial rotation around its own
   * axis by the given angle (radians). Returns false and leaves the quaternion
   * unchanged if the half-angle exceeds pi/2 or the axis component is too short.
   */
  bool RotateQuatByAngle(Wm3::Quaternionf* quat, float rads);

  /**
   * Address: 0x004EDED0 (FUN_004EDED0, func_QuatsNearEqual)
   *
   * IDA signature:
   * BOOL __usercall func_QuatsNearEqual@<eax>(Wm3::Quaternionf *a1@<edi>, Wm3::Quaternionf *a2@<esi>);
   *
   * What it does:
   * Returns true when every quaternion lane differs by at most 1e-6 from the
   * corresponding lane in `rhs`. Used by SLERP to short-circuit interpolation
   * when the endpoints are already coincident.
   */
  [[nodiscard]] bool QuatsNearEqual(const Wm3::Quaternionf& lhs, const Wm3::Quaternionf& rhs) noexcept;

  /**
   * Address: 0x004EDAA0 (FUN_004EDAA0, func_NormalizeQuatInPlace)
   *
   * IDA signature:
   * void __usercall func_NormalizeQuatInPlace(Wm3::Quaternionf *a1@<esi>);
   *
   * What it does:
   * Renormalizes a quaternion in place. If the magnitude is below 1e-6, all
   * lanes are zeroed (rather than reset to identity) to match the binary's
   * degenerate-input behavior.
   */
  void NormalizeQuatInPlace(Wm3::Quaternionf* quat) noexcept;

  /**
   * Address: 0x004EBC00 (FUN_004EBC00, Moho::SLERP)
   *
   * IDA signature:
   * Wm3::Quaternionf *__usercall Moho::SLERP@<eax>(
   *     Wm3::Quaternionf *q2@<eax>,
   *     Wm3::Quaternionf *q1@<ecx>,
   *     Wm3::Quaternionf *out@<ebx>,
   *     double t@<st0>,
   *     float t);
   *
   * What it does:
   * Spherical linear interpolation between unit quaternions `q1` and `q2`
   * with parameter `t` clamped to `[0, 1]`. Picks the shortest arc, falls
   * back to a normalized linear blend when the angle is small or the sin
   * is non-finite, and short-circuits to a copy of `q1` when both inputs
   * are already coincident. Writes the result into `*out` and returns it.
   */
  Wm3::Quaternionf* SLERP(
      const Wm3::Quaternionf* q2,
      const Wm3::Quaternionf* q1,
      Wm3::Quaternionf* out,
      float t) noexcept;

  /**
   * Address: 0x0069AA50 (FUN_0069AA50, func_QuatFromVecRot)
   *
   * IDA signature:
   * void callcnv_F3 sub_69AA50(Wm3::Quaternionf *a1, Wm3::Vector3f *a2@<ecx>, float rads);
   *
   * What it does:
   * Extracts the forward-axis column from a quaternion's rotation matrix, builds
   * a cross-add delta quaternion between that forward axis and a reference vector,
   * applies a partial rotation via RotateQuatByAngle, then multiplies the result
   * back into the source quaternion in-place.
   * Used by Moho::Projectile::MotionTick and UpdateTracking.
   */
  void QuatFromVecRot(Wm3::Quaternionf* quat, const Wm3::Vector3f* refAxis, float rads);

} // namespace moho
