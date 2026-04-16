#pragma once

#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace moho
{
  /**
   * Address: 0x0062FB50 (FUN_0062FB50, func_NormalizeAngle)
   *
   * What it does:
   * Wraps an angle in radians into the signed range `[-pi, pi]` using a
   * modulo by `2*pi`, then applies one corrective wrap when needed.
   */
  [[nodiscard]] float NormalizeAngleSignedRadians(float angleRadians) noexcept;

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
   * Address: 0x004EB3F0 (FUN_004EB3F0, func_MatrixToQuat)
   *
   * IDA signature:
   * Wm3::Quaternionf *callcnv_F3 func_MatrixToQuat@<eax>(
   *   Moho::VMatrix3 *a1@<eax>, Wm3::Quaternionf *dest@<esi>);
   *
   * What it does:
   * Converts one 3x3 basis matrix (three row vectors) into a quaternion using
   * the binary trace/max-diagonal branch logic.
   */
  Wm3::Quaternionf* MatrixToQuat(const Wm3::Vector3f* matrixRows, Wm3::Quaternionf* out) noexcept;

  /**
   * Address: 0x004F0CB0 (FUN_004F0CB0, sub_4F0CB0)
   *
   * What it does:
   * Converts one 3x3 basis matrix (row lanes) into quaternion output using the
   * canonical trace/dominant-axis branch with scalar lane sign matching Lua
   * HPR/prop creation paths.
   */
  Wm3::Quaternionf* MatrixRowsToQuatCanonical(const Wm3::Vector3f* matrixRows, Wm3::Quaternionf* out) noexcept;

  /**
   * Address: 0x004F0AE0 (FUN_004F0AE0, func_MatrixToQuat_0)
   *
   * What it does:
   * Transposes one 3x3 matrix from column lanes into row lanes, then forwards
   * to `MatrixRowsToQuatCanonical`.
   */
  Wm3::Quaternionf* MatrixColumnsToQuatCanonical(const Wm3::Vector3f* matrixColumns, Wm3::Quaternionf* out) noexcept;

  /**
   * Address: 0x004EBA80 (FUN_004EBA80, func_QuatLERP)
   *
   * IDA signature:
   * Wm3::Quaternionf *__usercall func_QuatLERP@<eax>(
   *   Wm3::Quaternionf *q1@<eax>,
   *   Wm3::Quaternionf *q2@<ecx>,
   *   Wm3::Quaternionf *dest@<ebx>,
   *   float amt);
   *
   * What it does:
   * Clamps `amount` to `[0,1]`, flips one endpoint when needed for shortest
   * hemisphere, performs normalized linear interpolation, and writes into
   * `out`.
   */
  Wm3::Quaternionf* QuatLERP(
    const Wm3::Quaternionf* q1,
    const Wm3::Quaternionf* q2,
    Wm3::Quaternionf* out,
    float amount
  ) noexcept;

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

  /**
   * Address: 0x006C1070 (FUN_006C1070)
   *
   * What it does:
   * Extracts one axis-angle representation from a quaternion, returning the
   * normalized axis in `axisOut` and angle (radians) in `angleRadiansOut`.
   */
  void QuatToAxisAndAngle(
    const Wm3::Quaternionf& quaternion,
    Wm3::Vector3f* axisOut,
    float* angleRadiansOut
  ) noexcept;

  /**
   * Address: 0x00697360 (FUN_00697360, func_VecToQuatB)
   *
   * What it does:
   * Converts one axis-angle vector into a quaternion by normalizing the vector,
   * treating its length as the angle, and writing `sin(angle/2)` into the xyz
   * lanes with `cos(angle/2)` in w.
   */
  Wm3::Quaternionf* QuatFromAxisAngleVector(Wm3::Quaternionf* quat, Wm3::Vector3f axisAngle) noexcept;

} // namespace moho
