#include "QuaternionMath.h"

#include <cmath>

// Forward declaration of QuatCrossAdd (defined in Sim.cpp at global scope)
Wm3::Quaternionf* QuatCrossAdd(Wm3::Quaternionf* dest, Wm3::Vector3f v1, Wm3::Vector3f v2);

namespace moho
{
  /**
   * Address: 0x0062FB50 (FUN_0062FB50, func_NormalizeAngle)
   *
   * What it does:
   * Wraps an angle in radians into the signed range `[-pi, pi]`.
   */
  float NormalizeAngleSignedRadians(const float angleRadians) noexcept
  {
    constexpr float kPi = 3.1415927f;
    constexpr float kTwoPi = 6.2831855f;

    const float wrapped = static_cast<float>(std::fmod(angleRadians, static_cast<double>(kTwoPi)));
    if (wrapped < -kPi) {
      return wrapped + kTwoPi;
    }
    if (wrapped > kPi) {
      return wrapped - kTwoPi;
    }
    return wrapped;
  }

  /**
   * Address: 0x004EDED0 (FUN_004EDED0, func_QuatsNearEqual)
   *
   * IDA signature:
   * BOOL __usercall func_QuatsNearEqual@<eax>(Wm3::Quaternionf *a1@<edi>, Wm3::Quaternionf *a2@<esi>);
   *
   * What it does:
   * Returns true when every quaternion lane differs by at most 1e-6 from the
   * corresponding lane in rhs.
   */
  bool QuatsNearEqual(const Wm3::Quaternionf& lhs, const Wm3::Quaternionf& rhs) noexcept
  {
    constexpr float kEps = 1.0e-6f;
    return std::fabs(lhs.x - rhs.x) <= kEps
        && std::fabs(lhs.y - rhs.y) <= kEps
        && std::fabs(lhs.z - rhs.z) <= kEps
        && std::fabs(lhs.w - rhs.w) <= kEps;
  }

  /**
   * Address: 0x004EDAA0 (FUN_004EDAA0, func_NormalizeQuatInPlace)
   *
   * IDA signature:
   * void __usercall func_NormalizeQuatInPlace(Wm3::Quaternionf *a1@<esi>);
   *
   * What it does:
   * Renormalizes a quaternion in place; on degenerate input (length below
   * 1e-6) every lane is zeroed instead of being reset to identity, matching
   * the binary precisely.
   */
  void NormalizeQuatInPlace(Wm3::Quaternionf* const quat) noexcept
  {
    constexpr float kEps = 1.0e-6f;

    const float length = std::sqrt(
        (quat->x * quat->x) + (quat->y * quat->y) + (quat->z * quat->z) + (quat->w * quat->w));

    if (length <= kEps) {
      quat->x = 0.0f;
      quat->y = 0.0f;
      quat->z = 0.0f;
      quat->w = 0.0f;
      return;
    }

    const float invLength = 1.0f / length;
    quat->x *= invLength;
    quat->y *= invLength;
    quat->z *= invLength;
    quat->w *= invLength;
  }

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
   * Spherical linear interpolation between two unit quaternions. Clamps t to
   * [0, 1], picks the shortest arc by negating q2 when the dot product is
   * negative, and falls back to a normalized linear blend when the angle is
   * small or the sin is non-finite. Coincident inputs short-circuit to a copy
   * of q1 into the output. Writes the result into *out and returns it.
   */
  Wm3::Quaternionf* SLERP(
      const Wm3::Quaternionf* const q2,
      const Wm3::Quaternionf* const q1,
      Wm3::Quaternionf* const out,
      const float t) noexcept
  {
    // Coincident endpoints: copy the first input lane-for-lane and exit.
    if (QuatsNearEqual(*q1, *q2)) {
      out->x = q1->x;
      out->y = q1->y;
      out->z = q1->z;
      out->w = q1->w;
      return out;
    }

    // Clamp t into [0, 1] (binary order: clamp high then low).
    float tClamped = t;
    if (tClamped >= 1.0f) {
      tClamped = 1.0f;
    }
    if (tClamped < 0.0f) {
      tClamped = 0.0f;
    }

    Wm3::Quaternionf rhs{q2->w, q2->x, q2->y, q2->z};
    float dot = (q1->x * q2->x) + (q1->y * q2->y) + (q1->z * q2->z) + (q1->w * q2->w);

    // Take the shortest arc.
    if (dot < 0.0f) {
      dot = -dot;
      rhs.x = -rhs.x;
      rhs.y = -rhs.y;
      rhs.z = -rhs.z;
      rhs.w = -rhs.w;
    }

    const float oneMinusT = 1.0f - tClamped;

    // Use the spherical formula only when the endpoints are sufficiently apart
    // and the resulting sin is finite; otherwise fall through to the lerp+normalize path.
    if ((1.0f - dot) > 0.001f) {
      const float angle = std::acos(dot);
      constexpr float kPi = 3.1415927f;
      if ((kPi - angle) >= 0.001f) {
        const float sinAngle = std::sin(angle);
        if (std::isfinite(sinAngle) && sinAngle != 0.0f) {
          const float invSin = 1.0f / sinAngle;
          const float w1 = std::sin(oneMinusT * angle) * invSin;
          const float w2 = std::sin(tClamped * angle) * invSin;
          out->x = (q1->x * w1) + (rhs.x * w2);
          out->y = (q1->y * w1) + (rhs.y * w2);
          out->z = (q1->z * w1) + (rhs.z * w2);
          out->w = (q1->w * w1) + (rhs.w * w2);
          return out;
        }
      }
    }

    // Linear blend + normalize fallback (small angle or non-finite sin).
    Wm3::Quaternionf blended{
      (q1->w * oneMinusT) + (rhs.w * tClamped),
      (q1->x * oneMinusT) + (rhs.x * tClamped),
      (q1->y * oneMinusT) + (rhs.y * tClamped),
      (q1->z * oneMinusT) + (rhs.z * tClamped),
    };
    NormalizeQuatInPlace(&blended);
    *out = blended;
    return out;
  }


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
  bool RotateQuatByAngle(Wm3::Quaternionf* quat, float rads)
  {
    constexpr float kHalfPi = 1.5707964f;

    const float halfAngle = std::fabs(rads * 0.5f);
    if (halfAngle >= kHalfPi) {
      return false;
    }

    const float qx = quat->x;
    const float qy = quat->y;
    const float qz = quat->z;

    float sinHalf = std::sinf(halfAngle);
    const float axisLenSq = (qz * qz) + (qx * qx) + (qy * qy);
    if (axisLenSq <= (sinHalf * sinHalf)) {
      return false;
    }

    // Flip sin if the w component is negative to preserve hemisphere consistency
    if (quat->w < 0.0f) {
      sinHalf = -0.0f - sinHalf;
    }

    // Normalize the axis portion
    Wm3::Vector3f axis{qx, qy, qz};
    Wm3::Vector3f::Normalize(&axis);

    // Apply the partial rotation
    quat->x = axis.x * sinHalf;
    quat->y = axis.y * sinHalf;
    quat->z = axis.z * sinHalf;
    quat->w = std::cosf(halfAngle);

    return true;
  }

  /**
   * Address: 0x0069AA50 (FUN_0069AA50, func_QuatFromVecRot)
   *
   * IDA signature:
   * void callcnv_F3 sub_69AA50(Wm3::Quaternionf *a1, Wm3::Vector3f *a2@<ecx>, float rads);
   *
   * What it does:
   * Extracts the forward-axis column (z-column of the rotation matrix) from a
   * quaternion, builds a cross-add delta quaternion between that forward axis and
   * a reference vector, applies a partial rotation via RotateQuatByAngle, then
   * pre-multiplies the delta into the source quaternion in-place.
   * Used by Moho::Projectile::MotionTick and UpdateTracking.
   */
  void QuatFromVecRot(Wm3::Quaternionf* quat, const Wm3::Vector3f* refAxis, float rads)
  {
    const Wm3::Vector3f refVec{refAxis->x, refAxis->y, refAxis->z};

    // Extract the z-axis column of the rotation matrix from the quaternion.
    // For quaternion q = (w, x, y, z):
    //   col2.x = 2*(x*z + w*y)
    //   col2.y = 2*(y*z - w*x)
    //   col2.z = 1 - 2*(x*x + y*y)
    const float qx = quat->x;
    const float qy = quat->y;
    const float qz = quat->z;
    const float qw = quat->w;

    Wm3::Vector3f forwardAxis;
    forwardAxis.x = ((qx * qz) + (qw * qy)) * 2.0f;
    forwardAxis.y = ((qy * qz) - (qw * qx)) * 2.0f;
    forwardAxis.z = 1.0f - ((qx * qx) + (qy * qy)) * 2.0f;

    // Build a delta quaternion that rotates forwardAxis toward refVec
    Wm3::Quaternionf delta;
    ::QuatCrossAdd(&delta, forwardAxis, refVec);

    // Apply partial rotation to the delta quaternion
    RotateQuatByAngle(&delta, rads);

    // Pre-multiply: quat_new = delta * quat (Hamilton product)
    const float dw = delta.w;
    const float dx = delta.x;
    const float dy = delta.y;
    const float dz = delta.z;

    const float ow = quat->w;
    const float ox = quat->x;
    const float oy = quat->y;
    const float oz = quat->z;

    quat->w = (ow * dw) - (ox * dx) - (oy * dy) - (oz * dz);
    quat->x = (dw * ox) + (dx * ow) + (dy * oz) - (dz * oy);
    quat->y = (dw * oy) - (dx * oz) + (dy * ow) + (dz * ox);
    quat->z = (dw * oz) + (dx * oy) - (dy * ox) + (dz * ow);
  }
} // namespace moho
