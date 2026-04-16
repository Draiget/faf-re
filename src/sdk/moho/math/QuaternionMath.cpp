#include "QuaternionMath.h"

#include <cmath>

// Forward declaration of QuatCrossAdd (defined in Sim.cpp at global scope)
Wm3::Quaternionf* QuatCrossAdd(Wm3::Quaternionf* dest, Wm3::Vector3f v1, Wm3::Vector3f v2);
namespace moho
{
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace moho
{
  namespace
  {
    /**
     * Address: 0x00A3AD70 (FUN_00A3AD70)
     *
     * What it does:
     * Converts one quaternion lane set in binary order `(x, y, z, w)` into a
     * 3x3 rotation matrix lane buffer.
     */
    [[maybe_unused]] double* QuaternionToRotationMatrix3x3(
      const double* const quaternionLanes,
      double* const outMatrixLanes
    ) noexcept
    {
      const double x = quaternionLanes[0];
      const double y = quaternionLanes[1];
      const double z = quaternionLanes[2];
      const double w = quaternionLanes[3];

      const double twoY = y * 2.0;
      const double twoZ = z * 2.0;
      const double twoW = w * 2.0;

      const double twoXY = x * twoY;
      const double twoXZ = x * twoZ;
      const double twoXW = x * twoW;
      const double twoYY = y * twoY;
      const double twoYZ = y * twoZ;
      const double twoYW = y * twoW;
      const double twoZZ = z * twoZ;
      const double twoZW = z * twoW;
      const double twoWW = w * twoW;

      outMatrixLanes[0] = 1.0 - (twoWW + twoZZ);
      outMatrixLanes[1] = twoYZ - twoXW;
      outMatrixLanes[2] = twoYW + twoXZ;
      outMatrixLanes[3] = twoXW + twoYZ;
      outMatrixLanes[4] = 1.0 - (twoWW + twoYY);
      outMatrixLanes[5] = twoZW - twoXY;
      outMatrixLanes[6] = twoYW - twoXZ;
      outMatrixLanes[7] = twoZW + twoXY;
      outMatrixLanes[8] = 1.0 - (twoYY + twoZZ);
      return outMatrixLanes;
    }
  } // namespace

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
   * Address: 0x0062FBA0 (FUN_0062FBA0)
   *
   * What it does:
   * Rotates one vector by the conjugate of one raw quaternion lane set.
   */
  [[maybe_unused]] Wm3::Vector3f* RotateVectorByConjugateQuaternionLanes(
    const float* const quaternionLanes,
    Wm3::Vector3f* const outVector,
    const Wm3::Vector3f* const sourceVector
  )
  {
    Wm3::Quaternionf conjugate{};
    conjugate.x = quaternionLanes[0];
    conjugate.y = -quaternionLanes[1];
    conjugate.z = -quaternionLanes[2];
    conjugate.w = -quaternionLanes[3];
    moho::MultQuadVec(outVector, sourceVector, &conjugate);
    return outVector;
  }

  /**
   * Address: 0x00694AF0 (FUN_00694AF0)
   *
   * What it does:
   * Extracts the quaternion-derived Y-axis matrix column
   * `(m01, m11, m21)` into `outAxis` for one `(w,x,y,z)` quaternion lane.
   */
  [[maybe_unused]] Wm3::Vector3f* QuaternionExtractYAxisColumn(
    Wm3::Vector3f* const outAxis,
    const Wm3::Quaternionf* const quaternion
  ) noexcept
  {
    const float x = quaternion->x;
    const float y = quaternion->y;
    const float z = quaternion->z;
    const float w = quaternion->w;

    outAxis->x = ((y * x) - (w * z)) * 2.0f;
    outAxis->y = 1.0f - ((z * z) + (x * x)) * 2.0f;
    outAxis->z = ((z * y) + (w * x)) * 2.0f;
    return outAxis;
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
  Wm3::Quaternionf* MatrixToQuat(const Wm3::Vector3f* const matrixRows, Wm3::Quaternionf* const out) noexcept
  {
    const auto lane = [matrixRows](const int row, const int col) noexcept -> float {
      const Wm3::Vector3f& r = matrixRows[row];
      if (col == 0) {
        return r.x;
      }
      if (col == 1) {
        return r.y;
      }
      return r.z;
    };

    const float diagonal0 = lane(0, 0);
    const float diagonal1 = lane(1, 1);
    const float diagonal2 = lane(2, 2);
    const float trace = diagonal0 + diagonal1 + diagonal2;
    if (trace > 0.0f) {
      const float root = std::sqrt(trace + 1.0f);
      const float invRoot = 0.5f / root;
      out->w = root * 0.5f;
      out->x = (lane(1, 2) - lane(2, 1)) * invRoot;
      out->y = (lane(2, 0) - lane(0, 2)) * invRoot;
      out->z = (lane(0, 1) - lane(1, 0)) * invRoot;
      return out;
    }

    constexpr int kCrossShuffle[3] = {1, 2, 0};
    int dominantAxis = (diagonal1 > diagonal0) ? 1 : 0;
    if (diagonal2 > lane(dominantAxis, dominantAxis)) {
      dominantAxis = 2;
    }

    const int axisB = kCrossShuffle[dominantAxis];
    const int axisC = kCrossShuffle[axisB];
    const float root = std::sqrt((lane(dominantAxis, dominantAxis) - (lane(axisB, axisB) + lane(axisC, axisC))) + 1.0f);
    const float invRoot = 0.5f / root;

    float axisComponents[3] = {0.0f, 0.0f, 0.0f};
    axisComponents[dominantAxis] = root * 0.5f;
    axisComponents[axisB] = (lane(dominantAxis, axisB) + lane(axisB, dominantAxis)) * invRoot;
    axisComponents[axisC] = (lane(dominantAxis, axisC) + lane(axisC, dominantAxis)) * invRoot;

    out->w = (lane(axisB, axisC) - lane(axisC, axisB)) * invRoot;
    out->x = axisComponents[0];
    out->y = axisComponents[1];
    out->z = axisComponents[2];
    return out;
  }

  /**
   * Address: 0x004F0CB0 (FUN_004F0CB0, sub_4F0CB0)
   *
   * What it does:
   * Converts one 3x3 basis matrix (row lanes) into quaternion output using
   * the canonical trace/dominant-axis branch variant.
   */
  Wm3::Quaternionf*
  MatrixRowsToQuatCanonical(const Wm3::Vector3f* const matrixRows, Wm3::Quaternionf* const out) noexcept
  {
    const auto lane = [matrixRows](const int row, const int col) noexcept -> float {
      const Wm3::Vector3f& r = matrixRows[row];
      if (col == 0) {
        return r.x;
      }
      if (col == 1) {
        return r.y;
      }
      return r.z;
    };

    const float diagonal0 = lane(0, 0);
    const float diagonal1 = lane(1, 1);
    const float diagonal2 = lane(2, 2);
    const float trace = diagonal0 + diagonal1 + diagonal2;
    if (trace > 0.0f) {
      const float root = std::sqrt(trace + 1.0f);
      const float invRoot = 0.5f / root;
      out->w = root * 0.5f;
      out->x = (lane(2, 1) - lane(1, 2)) * invRoot;
      out->y = (lane(0, 2) - lane(2, 0)) * invRoot;
      out->z = (lane(1, 0) - lane(0, 1)) * invRoot;
      return out;
    }

    constexpr int kCrossShuffle[3] = {1, 2, 0};
    int dominantAxis = (diagonal1 > diagonal0) ? 1 : 0;
    if (diagonal2 > lane(dominantAxis, dominantAxis)) {
      dominantAxis = 2;
    }

    const int axisB = kCrossShuffle[dominantAxis];
    const int axisC = kCrossShuffle[axisB];
    const float root = std::sqrt((lane(dominantAxis, dominantAxis) - (lane(axisB, axisB) + lane(axisC, axisC))) + 1.0f);
    const float invRoot = 0.5f / root;

    float vectorComponents[3] = {0.0f, 0.0f, 0.0f};
    vectorComponents[dominantAxis] = root * 0.5f;
    vectorComponents[axisB] = (lane(dominantAxis, axisB) + lane(axisB, dominantAxis)) * invRoot;
    vectorComponents[axisC] = (lane(dominantAxis, axisC) + lane(axisC, dominantAxis)) * invRoot;

    out->w = (lane(axisC, axisB) - lane(axisB, axisC)) * invRoot;
    out->x = vectorComponents[0];
    out->y = vectorComponents[1];
    out->z = vectorComponents[2];
    return out;
  }

  /**
   * Address: 0x006D1E20 (FUN_006D1E20)
   *
   * What it does:
   * Thin thunk alias that forwards one row-major 3x3 matrix conversion request
   * to the canonical matrix-to-quaternion path.
   */
  [[maybe_unused]] Wm3::Quaternionf*
  MatrixRowsToQuatCanonicalThunk(const Wm3::Vector3f* const matrixRows, Wm3::Quaternionf* const out) noexcept
  {
    return MatrixRowsToQuatCanonical(matrixRows, out);
  }

  /**
   * Address: 0x004F0AE0 (FUN_004F0AE0, func_MatrixToQuat_0)
   *
   * What it does:
   * Transposes one 3x3 matrix from column lanes into row lanes, then converts
   * the transposed rows with `MatrixRowsToQuatCanonical`.
   */
  Wm3::Quaternionf*
  MatrixColumnsToQuatCanonical(const Wm3::Vector3f* const matrixColumns, Wm3::Quaternionf* const out) noexcept
  {
    Wm3::Vector3f rows[3]{};
    rows[0] = {matrixColumns[0].x, matrixColumns[1].x, matrixColumns[2].x};
    rows[1] = {matrixColumns[0].y, matrixColumns[1].y, matrixColumns[2].y};
    rows[2] = {matrixColumns[0].z, matrixColumns[1].z, matrixColumns[2].z};
    return MatrixRowsToQuatCanonical(rows, out);
  }

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
    const Wm3::Quaternionf* const q1,
    const Wm3::Quaternionf* const q2,
    Wm3::Quaternionf* const out,
    float amount
  ) noexcept
  {
    if (QuatsNearEqual(*q2, *q1)) {
      *out = *q2;
      return out;
    }

    if (amount >= 1.0f) {
      amount = 1.0f;
    }
    if (amount < 0.0f) {
      amount = 0.0f;
    }

    float q1x = q1->x;
    float q1y = q1->y;
    float q1z = q1->z;
    float q1w = q1->w;
    const float oneMinusAmount = 1.0f - amount;
    const float dot = (q2->x * q1x) + (q2->y * q1y) + (q2->z * q1z) + (q2->w * q1w);
    if (dot < 0.0f) {
      q1x = -q1x;
      q1y = -q1y;
      q1z = -q1z;
      q1w = -q1w;
    }

    out->x = (q2->x * oneMinusAmount) + (amount * q1x);
    out->y = (q2->y * oneMinusAmount) + (amount * q1y);
    out->z = (q2->z * oneMinusAmount) + (amount * q1z);
    out->w = (q2->w * oneMinusAmount) + (amount * q1w);
    NormalizeQuatInPlace(out);
    return out;
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

  /**
   * Address: 0x006C1070 (FUN_006C1070)
   *
   * What it does:
   * Extracts one axis-angle representation from a quaternion, returning the
   * normalized axis in `axisOut` and angle (radians) in `angleRadiansOut`.
   */
  void QuatToAxisAndAngle(
    const Wm3::Quaternionf& quaternion,
    Wm3::Vector3f* const axisOut,
    float* const angleRadiansOut
  ) noexcept
  {
    if (axisOut == nullptr || angleRadiansOut == nullptr) {
      return;
    }

    constexpr float kAxisEpsilon = 1.0e-6f;
    constexpr float kPi = 3.1415927f;
    const float axisLengthSquared =
      (quaternion.x * quaternion.x) + (quaternion.y * quaternion.y) + (quaternion.z * quaternion.z);

    if (axisLengthSquared <= kAxisEpsilon) {
      axisOut->x = 1.0f;
      axisOut->y = 0.0f;
      axisOut->z = 0.0f;
      *angleRadiansOut = 0.0f;
      return;
    }

    float halfAngle = 0.0f;
    if (quaternion.w <= -1.0f) {
      halfAngle = kPi;
    } else if (quaternion.w < 1.0f) {
      halfAngle = static_cast<float>(std::acos(static_cast<double>(quaternion.w)));
    }

    *angleRadiansOut = halfAngle * 2.0f;
    const float inverseAxisLength = 1.0f / std::sqrt(axisLengthSquared);
    axisOut->x = quaternion.x * inverseAxisLength;
    axisOut->y = quaternion.y * inverseAxisLength;
    axisOut->z = quaternion.z * inverseAxisLength;
  }

  /**
   * Address: 0x00697360 (FUN_00697360, func_VecToQuatB)
   *
   * What it does:
   * Converts one axis-angle vector into a quaternion. The vector direction is
   * normalized to become the axis and the magnitude becomes the rotation angle.
   */
  Wm3::Quaternionf* QuatFromAxisAngleVector(Wm3::Quaternionf* const quat, Wm3::Vector3f axisAngle) noexcept
  {
    const float angle = Wm3::Vector3f::Normalize(&axisAngle);
    const float halfAngle = angle * 0.5f;
    const float sinHalfAngle = std::sinf(halfAngle);

    quat->w = std::cosf(halfAngle);
    quat->x = axisAngle.x * sinHalfAngle;
    quat->y = axisAngle.y * sinHalfAngle;
    quat->z = axisAngle.z * sinHalfAngle;
    return quat;
  }
} // namespace moho
