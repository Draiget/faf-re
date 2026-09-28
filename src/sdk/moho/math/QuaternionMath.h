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

  /**
   * Address: 0x004EB830 (FUN_004EB830)
   *
   * IDA signature:
   * float *__usercall sub_4EB830@<eax>(
   *   float *currentOrientation@<ebx>, float *outOrientation@<edi>,
   *   float *targetOrientation, float turnStepRadians, char *outNoStep);
   *
   * What it does:
   * Performs one axis-angle interpolation step from `currentOrientation` toward
   * `targetOrientation` by at most `turnStepRadians`. Computes the relative
   * `delta = currentOrientation * conjugate(targetOrientation)`, clamps `delta`
   * via `RotateQuatByAngle`, and writes `outOrientation = targetOrientation *
   * clampedDelta`. If `RotateQuatByAngle` rejects the input (half-angle exceeds
   * pi/2 or the axis lanes are too short), copies `currentOrientation` into
   * `outOrientation` and sets `*outNoStep = 1`; otherwise sets `*outNoStep = 0`.
   * Used by `CSlaveManipulator::ManipulatorUpdate` and
   * `CThrustManipulator::MoveManipulator` for max-rate-limited reorientation.
   */
  Wm3::Quaternionf* BlendOrientationDeltaByMaxAngle(
    const Wm3::Quaternionf& currentOrientation,
    const Wm3::Quaternionf& targetOrientation,
    float turnStepRadians,
    bool* outNoStep,
    Wm3::Quaternionf* outOrientation
  ) noexcept;

  /**
   * Address: 0x006D2680 (FUN_006D2680, sub_6D2680)
   *
   * Multiplies two row-major 3x3 matrices (`result = a * b`), each three
   * consecutive `Wm3::Vector3f` rows. `result` must not alias `a`/`b`.
   */
  Wm3::Vector3f* Multiply3x3RowMatrices(
    Wm3::Vector3f* result, const Wm3::Vector3f* a, const Wm3::Vector3f* b
  ) noexcept;

  /**
   * Address: 0x006D1E30 (FUN_006D1E30, sub_6D1E30)
   *
   * Builds a row-major 3x3 rotation matrix (three `Wm3::Vector3f` rows) from
   * heading/pitch/roll Euler angles in radians (`headingY * pitchX * rollZ`).
   */
  Wm3::Vector3f* BuildRotationMatrixFromEulerHPR(
    Wm3::Vector3f* outMatrix, float heading, float pitch, float roll
  ) noexcept;

  /**
   * Address: 0x00452FD0 (FUN_00452FD0, func_QuatToMatrix)
   *
   * Expands a unit quaternion (engine scalar-first storage: `.w` scalar,
   * `.x/.y/.z` imaginary) into a row-major 3x3 rotation matrix, written as three
   * consecutive `Wm3::Vector3f` rows. Returns `outMatrix`.
   */
  Wm3::Vector3f* QuatToMatrix(const Wm3::Quaternionf* quat, Wm3::Vector3f* outMatrix) noexcept;

  /**
   * Address: 0x00452D40 (FUN_00452D40, Moho::MultQuadVec)
   *
   * What it does:
   * Expands `quat` into a row-major rotation matrix and multiplies `vec` by
   * its three rows, storing the rotated vector in `dest`.
   */
  Wm3::Vector3f* MultQuadVec(
    Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat
  );

  /**
   * Ordinary scalar-first Hamilton product: `.w` is the scalar, `(.x,.y,.z)`
   * the imaginary lanes, `a` the left operand and `b` the right one.
   *
   * This is the engine's real convention. `QuatToMatrix` (0x00452FD0) and
   * `VMatrix4::Set` (0x004EE980) both compute no `ww` term at all, which fixes
   * `.w` as their scalar lane; `VTransform::Inverse` (0x0046FBF0) conjugates by
   * keeping lane 0 and negating lanes 1-3; the product inlined into
   * `HardwareMeshBatch::FillBatch` (0x007E7EA0) and the one inlined into
   * `CAniPoseBone::Rotate` (0x0054BC00) both form their scalar term as
   * `a0*b0 - a1*b1 - a2*b2 - a3*b3`, positive in lane 0.
   *
   * Mind the operand order at each site: `CAniPoseBone::Rotate` composes as
   * `orient_ * rotation` (the existing orientation on the LEFT), which is the
   * reverse of how that call used to be written. The two orders differ by the
   * sign of the cross-product term, so they are not interchangeable.
   */
  Wm3::Quaternionf MultiplyQuat(const Wm3::Quaternionf& a, const Wm3::Quaternionf& b) noexcept;

  /**
   * Address: 0x0050CB50 (FUN_0050CB50, sub_50CB50)
   *
   * What it does:
   * Builds the shortest-arc delta that rotates `currentUp` onto
   * `targetNormal`, including the anti-parallel fallback axis selection: when
   * the two are exactly opposed the half-vector degenerates, so the axis is
   * taken perpendicular to whichever of `currentUp`'s x/y lanes is smaller.
   *
   * This writes a genuine `.w`-scalar quaternion -- the dot-product term goes
   * to offset 0 and the three cross-product/fallback lanes to 4/8/12 -- unlike
   * the scalar-first convention every *engine orientation* quaternion in this
   * binary uses. Getting that backwards relabels a correct value set onto the
   * wrong fields, which is exactly what the copy in `CThrustManipulator.cpp`
   * did before it was folded into this one.
   *
   * Callers: `COORDS_Tilt` (0x0050B820) and `cfunc_EntityPushOver`'s tilt lane
   * in `Entity.cpp`, and both of `CThrustManipulator`'s seeding sites -- its
   * constructor (0x0064A71D) and `ManipulatorUpdate` (0x0064AAD3).
   */
  Wm3::Quaternionf* BuildTiltShortestArcDelta(
    const Wm3::Vector3f& targetNormal, Wm3::Quaternionf* outDelta, const Wm3::Vector3f& currentUp
  ) noexcept;

  /**
   * Ordinary scalar-first conjugate: keeps `.w`, negates `.x`/`.y`/`.z`.
   * Transcribed from `VTransform::Inverse` (0x0046FBF0), which copies
   * `[eax+0]` verbatim and negates `[eax+4]`/`[eax+8]`/`[eax+0Ch]`.
   */
  Wm3::Quaternionf ConjugateQuat(const Wm3::Quaternionf& q) noexcept;
  /**
   * Header-scope yaw rotations about +Y. Like the float limits in gpg core,
   * these are `static const` objects in a header, so every including
   * translation unit owns a copy with its own dynamic initializer: WildMagic's
   * axis-angle constructor calls `sin` then `cos` of the half angle and
   * multiplies the sine by the axis, so lanes x and z come out as `0 * sin`
   * and lane y as `sin` (the `1 *` folds). The exe has 40 copies of each
   * (39 of the +45 one). The original header is not named anywhere in the
   * binary; every recovered reader (CAiSteeringImpl, CUnitMotion,
   * CUnitPatrolTask) includes this one.
   */

  /**
   * kQuatYawNeg90: a quarter turn clockwise (seen from above) (half angle -pi/4).
   *
   * Address: 0x00BCAED0 (FUN_00BCAED0, dynamic initializer of the copy at 0x010AD488)
   * Address: 0x00BCB540 (FUN_00BCB540, dynamic initializer of the copy at 0x010AD7BC)
   * Address: 0x00BCBBD0 (FUN_00BCBBD0, dynamic initializer of the copy at 0x010AE1CC)
   * Address: 0x00BCBFB0 (FUN_00BCBFB0, dynamic initializer of the copy at 0x010AE438)
   * Address: 0x00BCC460 (FUN_00BCC460, dynamic initializer of the copy at 0x010AE6DC)
   * Address: 0x00BCCA70 (FUN_00BCCA70, dynamic initializer of the copy at 0x010AEC44)
   * Address: 0x00BCCE40 (FUN_00BCCE40, dynamic initializer of the copy at 0x010AEE10)
   * Address: 0x00BCD0F0 (FUN_00BCD0F0, dynamic initializer of the copy at 0x010AEF64)
   * Address: 0x00BCD420 (FUN_00BCD420, dynamic initializer of the copy at 0x010AF144)
   * Address: 0x00BCD9F0 (FUN_00BCD9F0, dynamic initializer of the copy at 0x010AF788)
   * Address: 0x00BCE220 (FUN_00BCE220, dynamic initializer of the copy at 0x010AFDC0)
   * Address: 0x00BCE550 (FUN_00BCE550, dynamic initializer of the copy at 0x010AFF40)
   * Address: 0x00BCF0D0 (FUN_00BCF0D0, dynamic initializer of the copy at 0x010B0964)
   * Address: 0x00BCF320 (FUN_00BCF320, dynamic initializer of the copy at 0x010B09C8)
   * Address: 0x00BCF590 (FUN_00BCF590, dynamic initializer of the copy at 0x010B0AB8)
   * Address: 0x00BCFAC0 (FUN_00BCFAC0, dynamic initializer of the copy at 0x010B0E40)
   * Address: 0x00BCFE30 (FUN_00BCFE30, dynamic initializer of the copy at 0x010B105C)
   * Address: 0x00BD0080 (FUN_00BD0080, dynamic initializer of the copy at 0x010B1124)
   * Address: 0x00BD0390 (FUN_00BD0390, dynamic initializer of the copy at 0x010B1354)
   * Address: 0x00BD0760 (FUN_00BD0760, dynamic initializer of the copy at 0x010B159C)
   * Address: 0x00BD0A10 (FUN_00BD0A10, dynamic initializer of the copy at 0x010B16DC)
   * Address: 0x00BD0C60 (FUN_00BD0C60, dynamic initializer of the copy at 0x010B17A4)
   * Address: 0x00BD0EB0 (FUN_00BD0EB0, dynamic initializer of the copy at 0x010B186C)
   * Address: 0x00BD1160 (FUN_00BD1160, dynamic initializer of the copy at 0x010B19AC)
   * Address: 0x00BD13F0 (FUN_00BD13F0, dynamic initializer of the copy at 0x010B1A88)
   * Address: 0x00BD1640 (FUN_00BD1640, dynamic initializer of the copy at 0x010B1B50)
   * Address: 0x00BD1AB0 (FUN_00BD1AB0, dynamic initializer of the copy at 0x010B1E94)
   * Address: 0x00BD1DE0 (FUN_00BD1DE0, dynamic initializer of the copy at 0x010B1F70)
   * Address: 0x00BD2840 (FUN_00BD2840, dynamic initializer of the copy at 0x010B2614)
   * Address: 0x00BD32E0 (FUN_00BD32E0, dynamic initializer of the copy at 0x010B2E70)
   * Address: 0x00BD4A20 (FUN_00BD4A20, dynamic initializer of the copy at 0x010B4194)
   * Address: 0x00BD6170 (FUN_00BD6170, dynamic initializer of the copy at 0x010B5504)
   * Address: 0x00BD6870 (FUN_00BD6870, dynamic initializer of the copy at 0x010B5AD8)
   * Address: 0x00BD6DE0 (FUN_00BD6DE0, dynamic initializer of the copy at 0x010B5DE8)
   * Address: 0x00BD7330 (FUN_00BD7330, dynamic initializer of the copy at 0x010B6158)
   * Address: 0x00BD75A0 (FUN_00BD75A0, dynamic initializer of the copy at 0x010B61E4)
   * Address: 0x00BD7790 (FUN_00BD7790, dynamic initializer of the copy at 0x010B6244)
   * Address: 0x00BD8590 (FUN_00BD8590, dynamic initializer of the copy at 0x010B76D4)
   * Address: 0x00BD90E0 (FUN_00BD90E0, dynamic initializer of the copy at 0x010B7FD8)
   * Address: 0x00BD9680 (FUN_00BD9680, dynamic initializer of the copy at 0x010B86EC)
   */
  static const Wm3::Quaternionf kQuatYawNeg90(Wm3::Vector3f(0.0f, 1.0f, 0.0f), -1.5707964f);

  /**
   * kQuatYawPos90: a quarter turn counter-clockwise (half angle pi/4).
   *
   * Address: 0x00BCAF30 (FUN_00BCAF30, dynamic initializer of the copy at 0x010AD5C0)
   * Address: 0x00BCB5A0 (FUN_00BCB5A0, dynamic initializer of the copy at 0x010AE018)
   * Address: 0x00BCBC30 (FUN_00BCBC30, dynamic initializer of the copy at 0x010AE278)
   * Address: 0x00BCC010 (FUN_00BCC010, dynamic initializer of the copy at 0x010AE458)
   * Address: 0x00BCC4C0 (FUN_00BCC4C0, dynamic initializer of the copy at 0x010AE7B0)
   * Address: 0x00BCCAD0 (FUN_00BCCAD0, dynamic initializer of the copy at 0x010AED90)
   * Address: 0x00BCCEA0 (FUN_00BCCEA0, dynamic initializer of the copy at 0x010AEEC0)
   * Address: 0x00BCD150 (FUN_00BCD150, dynamic initializer of the copy at 0x010AF088)
   * Address: 0x00BCD480 (FUN_00BCD480, dynamic initializer of the copy at 0x010AF18C)
   * Address: 0x00BCDA50 (FUN_00BCDA50, dynamic initializer of the copy at 0x010AF8D0)
   * Address: 0x00BCE280 (FUN_00BCE280, dynamic initializer of the copy at 0x010AFDF4)
   * Address: 0x00BCE5B0 (FUN_00BCE5B0, dynamic initializer of the copy at 0x010B026C)
   * Address: 0x00BCF130 (FUN_00BCF130, dynamic initializer of the copy at 0x010B0998)
   * Address: 0x00BCF380 (FUN_00BCF380, dynamic initializer of the copy at 0x010B09FC)
   * Address: 0x00BCF5F0 (FUN_00BCF5F0, dynamic initializer of the copy at 0x010B0BDC)
   * Address: 0x00BCFB20 (FUN_00BCFB20, dynamic initializer of the copy at 0x010B0EC4)
   * Address: 0x00BCFE90 (FUN_00BCFE90, dynamic initializer of the copy at 0x010B1090)
   * Address: 0x00BD00E0 (FUN_00BD00E0, dynamic initializer of the copy at 0x010B11BC)
   * Address: 0x00BD03F0 (FUN_00BD03F0, dynamic initializer of the copy at 0x010B13B0)
   * Address: 0x00BD07C0 (FUN_00BD07C0, dynamic initializer of the copy at 0x010B1624)
   * Address: 0x00BD0A70 (FUN_00BD0A70, dynamic initializer of the copy at 0x010B1774)
   * Address: 0x00BD0CC0 (FUN_00BD0CC0, dynamic initializer of the copy at 0x010B183C)
   * Address: 0x00BD0F10 (FUN_00BD0F10, dynamic initializer of the copy at 0x010B197C)
   * Address: 0x00BD11C0 (FUN_00BD11C0, dynamic initializer of the copy at 0x010B1A44)
   * Address: 0x00BD1450 (FUN_00BD1450, dynamic initializer of the copy at 0x010B1AA8)
   * Address: 0x00BD16A0 (FUN_00BD16A0, dynamic initializer of the copy at 0x010B1BD4)
   * Address: 0x00BD1B10 (FUN_00BD1B10, dynamic initializer of the copy at 0x010B1F2C)
   * Address: 0x00BD1E40 (FUN_00BD1E40, dynamic initializer of the copy at 0x010B1FF4)
   * Address: 0x00BD28A0 (FUN_00BD28A0, dynamic initializer of the copy at 0x010B26BC)
   * Address: 0x00BD3340 (FUN_00BD3340, dynamic initializer of the copy at 0x010B2F68)
   * Address: 0x00BD4A80 (FUN_00BD4A80, dynamic initializer of the copy at 0x010B4250)
   * Address: 0x00BD61D0 (FUN_00BD61D0, dynamic initializer of the copy at 0x010B559C)
   * Address: 0x00BD68D0 (FUN_00BD68D0, dynamic initializer of the copy at 0x010B5B94)
   * Address: 0x00BD6E40 (FUN_00BD6E40, dynamic initializer of the copy at 0x010B5EBC)
   * Address: 0x00BD7390 (FUN_00BD7390, dynamic initializer of the copy at 0x010B6178)
   * Address: 0x00BD7600 (FUN_00BD7600, dynamic initializer of the copy at 0x010B6204)
   * Address: 0x00BD77F0 (FUN_00BD77F0, dynamic initializer of the copy at 0x010B727C)
   * Address: 0x00BD85F0 (FUN_00BD85F0, dynamic initializer of the copy at 0x010B7BD8)
   * Address: 0x00BD9140 (FUN_00BD9140, dynamic initializer of the copy at 0x010B85E8)
   * Address: 0x00BD96E0 (FUN_00BD96E0, dynamic initializer of the copy at 0x010B8734)
   */
  static const Wm3::Quaternionf kQuatYawPos90(Wm3::Vector3f(0.0f, 1.0f, 0.0f), 1.5707964f);

  /**
   * kQuatYawNeg45: an eighth turn clockwise (half angle -pi/8).
   *
   * Address: 0x00BCAF90 (FUN_00BCAF90, dynamic initializer of the copy at 0x010AD560)
   * Address: 0x00BCB600 (FUN_00BCB600, dynamic initializer of the copy at 0x010ADFF4)
   * Address: 0x00BCBC90 (FUN_00BCBC90, dynamic initializer of the copy at 0x010AE1DC)
   * Address: 0x00BCC070 (FUN_00BCC070, dynamic initializer of the copy at 0x010AE448)
   * Address: 0x00BCC520 (FUN_00BCC520, dynamic initializer of the copy at 0x010AE764)
   * Address: 0x00BCCB30 (FUN_00BCCB30, dynamic initializer of the copy at 0x010AECCC)
   * Address: 0x00BCCF00 (FUN_00BCCF00, dynamic initializer of the copy at 0x010AEEB0)
   * Address: 0x00BCD1B0 (FUN_00BCD1B0, dynamic initializer of the copy at 0x010AF078)
   * Address: 0x00BCD4E0 (FUN_00BCD4E0, dynamic initializer of the copy at 0x010AF17C)
   * Address: 0x00BCDAB0 (FUN_00BCDAB0, dynamic initializer of the copy at 0x010AF8B0)
   * Address: 0x00BCE2E0 (FUN_00BCE2E0, dynamic initializer of the copy at 0x010AFDE4)
   * Address: 0x00BCE610 (FUN_00BCE610, dynamic initializer of the copy at 0x010B01F8)
   * Address: 0x00BCF190 (FUN_00BCF190, dynamic initializer of the copy at 0x010B0974)
   * Address: 0x00BCF3E0 (FUN_00BCF3E0, dynamic initializer of the copy at 0x010B09D8)
   * Address: 0x00BCF650 (FUN_00BCF650, dynamic initializer of the copy at 0x010B0B54)
   * Address: 0x00BCFB80 (FUN_00BCFB80, dynamic initializer of the copy at 0x010B0EB4)
   * Address: 0x00BCFEF0 (FUN_00BCFEF0, dynamic initializer of the copy at 0x010B1080)
   * Address: 0x00BD0140 (FUN_00BD0140, dynamic initializer of the copy at 0x010B11AC)
   * Address: 0x00BD0450 (FUN_00BD0450, dynamic initializer of the copy at 0x010B138C)
   * Address: 0x00BD0820 (FUN_00BD0820, dynamic initializer of the copy at 0x010B15AC)
   * Address: 0x00BD0AD0 (FUN_00BD0AD0, dynamic initializer of the copy at 0x010B1764)
   * Address: 0x00BD0D20 (FUN_00BD0D20, dynamic initializer of the copy at 0x010B182C)
   * Address: 0x00BD0F70 (FUN_00BD0F70, dynamic initializer of the copy at 0x010B18F4)
   * Address: 0x00BD1220 (FUN_00BD1220, dynamic initializer of the copy at 0x010B1A34)
   * Address: 0x00BD14B0 (FUN_00BD14B0, dynamic initializer of the copy at 0x010B1A98)
   * Address: 0x00BD1700 (FUN_00BD1700, dynamic initializer of the copy at 0x010B1BC4)
   * Address: 0x00BD1B70 (FUN_00BD1B70, dynamic initializer of the copy at 0x010B1F1C)
   * Address: 0x00BD1EA0 (FUN_00BD1EA0, dynamic initializer of the copy at 0x010B1FA8)
   * Address: 0x00BD2900 (FUN_00BD2900, dynamic initializer of the copy at 0x010B26AC)
   * Address: 0x00BD33A0 (FUN_00BD33A0, dynamic initializer of the copy at 0x010B2F58)
   * Address: 0x00BD4AE0 (FUN_00BD4AE0, dynamic initializer of the copy at 0x010B4230)
   * Address: 0x00BD6230 (FUN_00BD6230, dynamic initializer of the copy at 0x010B5514)
   * Address: 0x00BD6930 (FUN_00BD6930, dynamic initializer of the copy at 0x010B5B70)
   * Address: 0x00BD6EA0 (FUN_00BD6EA0, dynamic initializer of the copy at 0x010B5E98)
   * Address: 0x00BD73F0 (FUN_00BD73F0, dynamic initializer of the copy at 0x010B6168)
   * Address: 0x00BD7660 (FUN_00BD7660, dynamic initializer of the copy at 0x010B61F4)
   * Address: 0x00BD7850 (FUN_00BD7850, dynamic initializer of the copy at 0x010B721C)
   * Address: 0x00BD8650 (FUN_00BD8650, dynamic initializer of the copy at 0x010B7784)
   * Address: 0x00BD91A0 (FUN_00BD91A0, dynamic initializer of the copy at 0x010B85D8)
   * Address: 0x00BD9740 (FUN_00BD9740, dynamic initializer of the copy at 0x010B8724)
   */
  static const Wm3::Quaternionf kQuatYawNeg45(Wm3::Vector3f(0.0f, 1.0f, 0.0f), -0.78539819f);

  /**
   * kQuatYawPos45: an eighth turn counter-clockwise (half angle pi/8).
   *
   * Address: 0x00BCAFF0 (FUN_00BCAFF0, dynamic initializer of the copy at 0x010AD60C)
   * Address: 0x00BCB660 (FUN_00BCB660, dynamic initializer of the copy at 0x010AE028)
   * Address: 0x00BCBCF0 (FUN_00BCBCF0, dynamic initializer of the copy at 0x010AE288)
   * Address: 0x00BCC0D0 (FUN_00BCC0D0, dynamic initializer of the copy at 0x010AE468)
   * Address: 0x00BCC580 (FUN_00BCC580, dynamic initializer of the copy at 0x010AE838)
   * Address: 0x00BCCB90 (FUN_00BCCB90, dynamic initializer of the copy at 0x010AEDA0)
   * Address: 0x00BCCF60 (FUN_00BCCF60, dynamic initializer of the copy at 0x010AEED0)
   * Address: 0x00BCD210 (FUN_00BCD210, dynamic initializer of the copy at 0x010AF114)
   * Address: 0x00BCD540 (FUN_00BCD540, dynamic initializer of the copy at 0x010AF19C)
   * Address: 0x00BCDB10 (FUN_00BCDB10, dynamic initializer of the copy at 0x010AFA68)
   * Address: 0x00BCE340 (FUN_00BCE340, dynamic initializer of the copy at 0x010AFE04)
   * Address: 0x00BCE670 (FUN_00BCE670, dynamic initializer of the copy at 0x010B027C)
   * Address: 0x00BCF1F0 (FUN_00BCF1F0, dynamic initializer of the copy at 0x010B09A8)
   * Address: 0x00BCF440 (FUN_00BCF440, dynamic initializer of the copy at 0x010B0A0C)
   * Address: 0x00BCF6B0 (FUN_00BCF6B0, dynamic initializer of the copy at 0x010B0BEC)
   * Address: 0x00BCFBE0 (FUN_00BCFBE0, dynamic initializer of the copy at 0x010B0EE8)
   * Address: 0x00BCFF50 (FUN_00BCFF50, dynamic initializer of the copy at 0x010B10A0)
   * Address: 0x00BD01A0 (FUN_00BD01A0, dynamic initializer of the copy at 0x010B11E0)
   * Address: 0x00BD04B0 (FUN_00BD04B0, dynamic initializer of the copy at 0x010B1424)
   * Address: 0x00BD0880 (FUN_00BD0880, dynamic initializer of the copy at 0x010B1634)
   * Address: 0x00BD0B30 (FUN_00BD0B30, dynamic initializer of the copy at 0x010B1784)
   * Address: 0x00BD0D80 (FUN_00BD0D80, dynamic initializer of the copy at 0x010B184C)
   * Address: 0x00BD0FD0 (FUN_00BD0FD0, dynamic initializer of the copy at 0x010B198C)
   * Address: 0x00BD1280 (FUN_00BD1280, dynamic initializer of the copy at 0x010B1A54)
   * Address: 0x00BD1510 (FUN_00BD1510, dynamic initializer of the copy at 0x010B1AB8)
   * Address: 0x00BD1760 (FUN_00BD1760, dynamic initializer of the copy at 0x010B1BE4)
   * Address: 0x00BD1BD0 (FUN_00BD1BD0, dynamic initializer of the copy at 0x010B1F3C)
   * Address: 0x00BD1F00 (FUN_00BD1F00, dynamic initializer of the copy at 0x010B2004)
   * Address: 0x00BD2960 (FUN_00BD2960, dynamic initializer of the copy at 0x010B26CC)
   * Address: 0x00BD3400 (FUN_00BD3400, dynamic initializer of the copy at 0x010B2FDC)
   * Address: 0x00BD6290 (FUN_00BD6290, dynamic initializer of the copy at 0x010B55C0)
   * Address: 0x00BD6990 (FUN_00BD6990, dynamic initializer of the copy at 0x010B5BA4)
   * Address: 0x00BD6F00 (FUN_00BD6F00, dynamic initializer of the copy at 0x010B5EE0)
   * Address: 0x00BD7450 (FUN_00BD7450, dynamic initializer of the copy at 0x010B61B0)
   * Address: 0x00BD76C0 (FUN_00BD76C0, dynamic initializer of the copy at 0x010B6214)
   * Address: 0x00BD78B0 (FUN_00BD78B0, dynamic initializer of the copy at 0x010B729C)
   * Address: 0x00BD86B0 (FUN_00BD86B0, dynamic initializer of the copy at 0x010B7BE8)
   * Address: 0x00BD9200 (FUN_00BD9200, dynamic initializer of the copy at 0x010B8608)
   * Address: 0x00BD97A0 (FUN_00BD97A0, dynamic initializer of the copy at 0x010B8744)
   */
  static const Wm3::Quaternionf kQuatYawPos45(Wm3::Vector3f(0.0f, 1.0f, 0.0f), 0.78539819f);
} // namespace moho
