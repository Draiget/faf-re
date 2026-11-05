// Definitions the recovered math TUs under test need but which live in
// src files too entangled to compile standalone. Each one is a verbatim
// copy of the engine source it names; keep them in sync (a stale mirror tests
// nothing). Everything else the harness exercises is compiled straight from
// src (see build.bat: QuaternionMath.cpp, Vector3f.cpp, X87Math.cpp).

#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"

// DIFFFUZZ_ENGINE_LINKED (faf_math_dump, linked against the engine's objects):
// the engine defines QuatCrossAdd itself, so only the manipulator mirrors
// below are compiled.
#if !defined(DIFFFUZZ_ENGINE_LINKED)
/**
 * Mirrors src\moho\sim\Sim.cpp:5130-5160 (moho::QuatCrossAdd,
 * Address: 0x0044F880). Verbatim body.
 */
Wm3::Quaternionf* moho::QuatCrossAdd(
  Wm3::Quaternionf* const dest, Wm3::Vector3f v1, Wm3::Vector3f v2, const Wm3::Vector3f& fallbackAxis
)
{
  Wm3::Vector3f::Normalize(&v1);
  Wm3::Vector3f::Normalize(&v2);

  Wm3::Vector3f add{
    v2.x + v1.x,
    v1.y + v2.y,
    v1.z + v2.z,
  };

  if (!(Wm3::Vector3f::Normalize(&add) > 0.0f)) {
    // Opposed inputs: a half turn about the caller's fallback axis - scalar 0,
    // the normalised axis in the imaginary lanes.
    (void)NormalizeVectorInto(&v1, fallbackAxis);
    dest->x = v1.x;
    dest->y = v1.y;
    dest->z = v1.z;
    dest->w = 0.0f;
    return dest;
  }

  // 0x0044F920..0x0044F952 sums the dot as (z + y) + x.
  dest->w = ((add.z * v1.z) + (v1.y * add.y)) + (add.x * v1.x);
  dest->x = (add.z * v1.y) - (v1.z * add.y);
  dest->y = (v1.z * add.x) - (add.z * v1.x);
  dest->z = (add.y * v1.x) - (v1.y * add.x);
  return dest;
}
#endif

// ---- third wave: manipulator angle lanes ----------------------------------
//
// The manipulator classes are far too entangled to compile here, so the
// bodies below are verbatim copies of their angle math with `this->` lanes
// moved into small state structs. Only the world-space tracking path is
// mirrored (the harness always passes kTrackingModeWorldSpace, which skips the
// watch-bone transform). Keep them in sync with the lines they name.

#include "legacy/math/X87Math.h"
#include "moho/math/Angle.h"
#include "sdk_mirror.h"

#include <cmath>
#include <cstdint>
#include <cstring>

namespace mirror
{
  namespace
  {
    constexpr float kHalfScale = 0.5f;
    constexpr std::uint8_t kTrackingModeHeading = 0x01;
    constexpr std::uint8_t kTrackingResultOutsideTolerance = 0x01;
    constexpr std::uint8_t kTrackingResultHeadingMotion = 0x02;

    // CBuilderArmManipulator.cpp anonymous-namespace constants.
    constexpr float kClampAngleLimit = 3.1405928f;
    constexpr float kHeadingMotionEpsilon = 9.999999747378752e-06f;
    constexpr float kHeadingOnTargetTolerance = 0.2617993950843811f;

    // CAimManipulator.cpp anonymous-namespace constants.
    constexpr float kAngleNormalizationClamp = 3.1405928f;
    constexpr float kTrackingMotionEpsilon = 0.001f;
  } // namespace

  /**
   * Mirrors src\moho\entity\Entity.cpp:7791-7799 (moho::COORDS_Pitch,
   * Address: 0x0050B710). Verbatim body.
   */
  float COORDS_Pitch(const Wm3::Vector3f& velocity) noexcept
  {
    using moho::kHalfPi;
    const float length = std::sqrt((velocity.x * velocity.x) + (velocity.y * velocity.y) + (velocity.z * velocity.z));
    const float normalizedY = velocity.y / length;
    const float rootTerm = std::sqrt(1.0f - normalizedY);
    const float polynomial =
      normalizedY * (((normalizedY * -0.018729299f) + 0.074261002f) * normalizedY - 0.21211439f) + 1.5707288f;
    return (rootTerm * polynomial) - kHalfPi;
  }

  /// Mirrors src\moho\ai\CAimManipulator.cpp moho::CAimManipulator::SetFiringArc (0x00630CB0).
  void AimSetFiringArc(AimArcLanes& self, const AimFiringArc arc)
  {
    self.mMinHeading = moho::NormalizeAngleSignedRadiansX87(fa::HalfSumX87(arc.mMinHeading, arc.mMaxHeading));
    self.mHeadingMaxSlew = arc.mHeadingMaxSlew;
    self.mMaxHeading = fa::HalfAbsDifferenceX87(arc.mMaxHeading, arc.mMinHeading);

    self.mMinPitch = moho::NormalizeAngleSignedRadiansX87(fa::HalfSumX87(arc.mMinPitch, arc.mMaxPitch));
    self.mPitchMaxSlew = arc.mPitchMaxSlew;
    self.mMaxPitch = fa::HalfAbsDifferenceX87(arc.mMaxPitch, arc.mMinPitch);
  }

  /// Mirrors src\moho\ai\CBuilderArmManipulator.cpp
  /// moho::CBuilderArmManipulator::SetAimingArc (0x00636490).
  void BuilderArmSetAimingArc(
    BuilderArmArcLanes& self,
    const float minHeading,
    const float maxHeading,
    const float headingMaxSlew,
    const float minPitch,
    const float maxPitch,
    const float pitchMaxSlew
  )
  {
    self.mHeadingCenter = moho::NormalizeAngleSignedRadiansX87(fa::HalfSumX87(minHeading, maxHeading));
    self.mHeadingMaxSlew = headingMaxSlew;
    self.mHeadingHalfArc = fa::HalfAbsDifferenceX87(maxHeading, minHeading);

    self.mPitchCenter = moho::NormalizeAngleSignedRadiansX87(fa::HalfSumX87(minPitch, maxPitch));
    self.mPitchMaxSlew = pitchMaxSlew;
    self.mPitchHalfArc = fa::HalfAbsDifferenceX87(maxPitch, minPitch);
  }

  /// Mirrors src\moho\ai\CBuilderArmManipulator.cpp
  /// moho::CBuilderArmManipulator::UpdateTrackingAxis (0x00636220), world-space path.
  std::uint8_t BuilderArmUpdateTrackingAxis(
    TrackLanes& self,
    const Wm3::Vector3f& targetDirection,
    const float angleCenter,
    const float angleHalfArc,
    const float maxSlew,
    const std::uint8_t trackingModeFlags
  )
  {
    using moho::NormalizeAngleSignedRadians;
    Wm3::Vector3f transformedTarget = targetDirection;

    float desiredAngle = 0.0f;
    float* currentAngleLane = nullptr;
    if ((trackingModeFlags & kTrackingModeHeading) != 0u) {
      currentAngleLane = &self.mHeading;
      desiredAngle = fa::atan2(transformedTarget.x, transformedTarget.z);
    } else {
      const float halfCenter = angleCenter * kHalfScale;
      Wm3::Quaternionf pitchBasis{};
      pitchBasis.w = fa::cos(halfCenter);
      pitchBasis.x = fa::sin(halfCenter);
      pitchBasis.y = 0.0f;
      pitchBasis.z = 0.0f;

      Wm3::Vector3f pitchSpaceTarget{};
      moho::MultQuadVec(&pitchSpaceTarget, &transformedTarget, &pitchBasis);
      currentAngleLane = &self.mPitch;
      desiredAngle = angleCenter - COORDS_Pitch(pitchSpaceTarget);
    }

    const float currentAngle = *currentAngleLane;
    float step = 0.0f;
    if (!(angleHalfArc >= kClampAngleLimit)) {
      float constrained = NormalizeAngleSignedRadians(desiredAngle - angleCenter);
      if (!(angleHalfArc > constrained)) {
        constrained = angleHalfArc;
      }
      if (-angleHalfArc > constrained) {
        constrained = -angleHalfArc;
      }
      step = (constrained + angleCenter) - currentAngle;
    } else {
      step = NormalizeAngleSignedRadians(desiredAngle - currentAngle);
    }

    if (std::fabs(step) > maxSlew) {
      step = std::copysign(maxSlew, step);
    }

    const float nextAngle = NormalizeAngleSignedRadians(step + currentAngle);
    *currentAngleLane = nextAngle;

    std::uint8_t trackingResult = 0u;
    if ((trackingModeFlags & kTrackingModeHeading) != 0u) {
      if (std::fabs(step) > kHeadingMotionEpsilon) {
        trackingResult |= kTrackingResultHeadingMotion;
      }

      const float onTargetDelta = NormalizeAngleSignedRadians(nextAngle - desiredAngle);
      if (std::fabs(onTargetDelta) > kHeadingOnTargetTolerance) {
        trackingResult |= kTrackingResultOutsideTolerance;
      }
    }

    return trackingResult;
  }

  /// Mirrors src\moho\ai\CAimManipulator.cpp moho::CAimManipulator::CheckTracking
  /// (0x006309F0), world-space path with a null weapon blueprint (so the
  /// pitch-only tolerance skip never applies).
  std::uint8_t AimCheckTracking(
    TrackLanes& self,
    const Wm3::Vector3f& targetDirection,
    const float minAngleCenter,
    const float maxAngleHalfRange,
    const float maxAngleSlew,
    const float tolerance,
    const std::uint8_t trackingModeFlags
  )
  {
    using moho::NormalizeAngleSignedRadians;
    Wm3::Vector3f transformedTarget = targetDirection;

    float desiredAngle = 0.0f;
    float* currentAngleLane = nullptr;
    if ((trackingModeFlags & kTrackingModeHeading) != 0u) {
      currentAngleLane = &self.mHeading;
      desiredAngle = fa::Atan2Plus(transformedTarget.x, transformedTarget.z, self.mHeadingOffset);
    } else {
      const float halfCenter = minAngleCenter * kHalfScale;
      Wm3::Quaternionf pitchBasis{};
      pitchBasis.w = fa::cos(halfCenter);
      pitchBasis.x = fa::sin(halfCenter);
      pitchBasis.y = 0.0f;
      pitchBasis.z = 0.0f;

      Wm3::Vector3f pitchSpaceTarget{};
      moho::MultQuadVec(&pitchSpaceTarget, &transformedTarget, &pitchBasis);
      currentAngleLane = &self.mPitch;
      desiredAngle = minAngleCenter - COORDS_Pitch(pitchSpaceTarget);
    }

    const float currentAngle = *currentAngleLane;
    float step = 0.0f;
    if (!(maxAngleHalfRange >= kAngleNormalizationClamp)) {
      float constrained = NormalizeAngleSignedRadians(desiredAngle - minAngleCenter);
      if (!(maxAngleHalfRange > constrained)) {
        constrained = maxAngleHalfRange;
      }
      if (-maxAngleHalfRange > constrained) {
        constrained = -maxAngleHalfRange;
      }
      step = (constrained + minAngleCenter) - currentAngle;
    } else {
      step = NormalizeAngleSignedRadians(desiredAngle - currentAngle);
    }

    if (std::fabs(step) > maxAngleSlew) {
      step = std::copysign(maxAngleSlew, step);
    }

    const float nextAngle = NormalizeAngleSignedRadians(step + currentAngle);
    *currentAngleLane = nextAngle;

    std::uint8_t trackingResult = 0u;
    if ((trackingModeFlags & kTrackingModeHeading) != 0u && std::fabs(step) > kTrackingMotionEpsilon) {
      trackingResult |= kTrackingResultHeadingMotion;
    }

    const float toleranceDelta = NormalizeAngleSignedRadians(nextAngle - desiredAngle);
    if (std::fabs(toleranceDelta) > tolerance) {
      trackingResult |= kTrackingResultOutsideTolerance;
    }

    return trackingResult;
  }

  /// Mirrors src\moho\animation\CAnimTexture.cpp moho::WrapPositiveModulo (0x00422940).
  float WrapPositiveModulo(const float value, const float range) noexcept
  {
    float wrapped = static_cast<float>(fa::fmod(value, range));
    if ((0.0f > wrapped) != (0.0f > range)) {
      wrapped += range;
    }
    return wrapped;
  }

  // ---- fourth wave ----------------------------------------------------------

  /// Mirrors src\moho\sim\SimDriver.cpp moho::RATE_GameRateToSpeed (0x0055AE10).
  int RATE_GameRateToSpeed(const float rate)
  {
    const float speed = fa::IntrinsicLnQuotient(rate, 10.0) * 10.0f;
    const float nearest = std::nearbyint(speed);
    const auto whole = static_cast<std::uint32_t>(fa::RoundToInt(nearest));
    const std::uint32_t borrow = (speed < nearest || std::isunordered(speed, nearest)) ? 1u : 0u;
    return static_cast<int>(whole - borrow);
  }

  /// Mirrors src\gpg\core\algorithms\Cluster.cpp gpg::HaStar::Cluster::QuantizeEdgeCost (0x0092D8B0).
  float QuantizeEdgeCost(const float a, const float b)
  {
    const float scaled = fa::ScaledLnQuotient(a, b, 6.0f);
    const float nearest = std::nearbyint(scaled);
    int quantized = static_cast<int>(
      static_cast<std::uint32_t>(fa::RoundToInt(nearest)) + (scaled > nearest ? 1u : 0u)
    );
    if (quantized > 31) {
      quantized = 31;
    }
    if (quantized < 0) {
      quantized = 0;
    }
    return static_cast<float>(quantized);
  }

  /// Mirrors src\moho\entity\Entity.cpp moho::COORDS_ToGridRect (0x0050AFA0).
  void COORDS_ToGridRect(int* const outRect, const float centerX, const float centerZ, const int sizeX, const int sizeZ)
  {
    const std::int16_t halfSizeX = static_cast<std::int16_t>(fa::RoundToInt(centerX - (static_cast<float>(sizeX) * 0.5f)));
    const std::int16_t halfSizeZ = static_cast<std::int16_t>(fa::RoundToInt(centerZ - (static_cast<float>(sizeZ) * 0.5f)));
    outRect[0] = halfSizeX;
    outRect[1] = halfSizeZ;
    outRect[2] = sizeX + halfSizeX;
    outRect[3] = sizeZ + halfSizeZ;
  }

  /// Mirrors src\moho\collision\CColPrimitiveBase.cpp ProjectBoxOntoAxis (0x00475550), anonymous namespace.
  void ProjectBoxOntoAxis(const float* const box, const float* const axis, float* const outMin, float* const outMax) noexcept
  {
    const float centerProjection = (axis[1] * box[1] + axis[2] * box[2]) + axis[0] * box[0];
    const float radius = fa::BoxRadiusOnAxisX87(box, axis);
    *outMin = centerProjection - radius;
    *outMax = centerProjection + radius;
  }

  /// Mirrors src\moho\math\MathReflection.cpp moho::VAxes3::VAxes3(const Quaternionf&) (0x004EC590).
  void VAxes3FromQuat(float* const outAxes, const Wm3::Quaternionf& orientation)
  {
    const float twoW = orientation.w * 2.0f;
    const float twoX = orientation.x * 2.0f;
    const float twoY = orientation.y * 2.0f;
    const float twoZ = orientation.z * 2.0f;

    const float xx = twoX * orientation.x;
    const float yy = twoY * orientation.y;
    const float zz = twoZ * orientation.z;
    const float wx = twoW * orientation.x;
    const float wy = twoW * orientation.y;
    const float wz = twoW * orientation.z;
    const float xy = twoY * orientation.x;
    const float xz = twoZ * orientation.x;
    const float yz = twoZ * orientation.y;

    outAxes[0] = 1.0f - (zz + yy);
    outAxes[1] = wz + xy;
    outAxes[2] = xz - wy;

    outAxes[3] = xy - wz;
    outAxes[4] = 1.0f - (zz + xx);
    outAxes[5] = yz + wx;

    outAxes[6] = wy + xz;
    outAxes[7] = yz - wx;
    outAxes[8] = 1.0f - (yy + xx);
  }

  /// Mirrors src\moho\math\MathReflection.cpp moho::VMatrix4::Set(quat, vec) (0x004EE980).
  void VMatrix4Set(float* const outRows, const Wm3::Quaternionf& quat, const Wm3::Vector3f& vec)
  {
    const float twoX = quat.x * 2.0f;
    const float twoY = quat.y * 2.0f;
    const float twoZ = quat.z * 2.0f;
    const float twoW = quat.w * 2.0f;

    const float xx2 = twoX * quat.x;
    const float yy2 = twoY * quat.y;
    const float zz2 = twoZ * quat.z;
    const float xy2 = twoY * quat.x;
    const float xz2 = twoZ * quat.x;
    const float yz2 = twoZ * quat.y;
    const float wx2 = twoW * quat.x;
    const float wy2 = twoW * quat.y;
    const float wz2 = twoW * quat.z;

    outRows[0] = 1.0f - (zz2 + yy2);
    outRows[1] = wz2 + xy2;
    outRows[2] = xz2 - wy2;
    outRows[3] = 0.0f;
    outRows[4] = xy2 - wz2;
    outRows[5] = 1.0f - (zz2 + xx2);
    outRows[6] = yz2 + wx2;
    outRows[7] = 0.0f;
    outRows[8] = wy2 + xz2;
    outRows[9] = yz2 - wx2;
    outRows[10] = 1.0f - (yy2 + xx2);
    outRows[11] = 0.0f;
    outRows[12] = vec.x;
    outRows[13] = vec.y;
    outRows[14] = vec.z;
    outRows[15] = 1.0f;
  }

  /// Mirrors src\moho\math\Wm3AxisAlignedBox3FafExtras.cpp moho::AxisAlignedBoundsFromBox
  /// (0x004FE2D0) with Wild Magic's ContAlignedBox (Containment\Wm3ContBox3.cpp:24-127, no
  /// validity mask) inlined: that TU needs half of Wild Magic. Its box has identity axes,
  /// and the radius still multiplies them in, as both the engine and retail do.
  void AxisAlignedBoundsFromBox(const Wm3::Box3f& box, float* const outMin, float* const outMax)
  {
    Wm3::Vector3f vertices[8];
    box.ComputeVertices(vertices);

    Wm3::Vector3f kMin = vertices[0], kMax = kMin;
    for (int i = 1; i < 8; i++) {
      for (int j = 0; j < 3; j++) {
        if (vertices[i][j] < kMin[j]) {
          kMin[j] = vertices[i][j];
        } else if (vertices[i][j] > kMax[j]) {
          kMax[j] = vertices[i][j];
        }
      }
    }
    const Wm3::Vector3f center = 0.5f * (kMin + kMax);
    const Wm3::Vector3f halfDiagonal = 0.5f * (kMax - kMin);
    const float axes[3][3] = {{1.0f, 0.0f, 0.0f}, {0.0f, 1.0f, 0.0f}, {0.0f, 0.0f, 1.0f}};

    for (int axis = 0; axis < 3; ++axis) {
      const float radius =
        (axes[0][axis] * halfDiagonal[0] + axes[1][axis] * halfDiagonal[1]) + axes[2][axis] * halfDiagonal[2];
      outMin[axis] = center[axis] - radius;
      outMax[axis] = center[axis] + radius;
    }
  }

  // ---- sixth wave -----------------------------------------------------------

  namespace
  {
    /// Mirrors src\moho\sim\STIMap.cpp ClampIndex (anonymous namespace).
    [[nodiscard]] int ClampIndex(const int value, const int limitInclusive) noexcept
    {
      if (limitInclusive <= 0) {
        return 0;
      }
      if (value < 0) {
        return 0;
      }
      if (value >= limitInclusive) {
        return limitInclusive;
      }
      return value;
    }
  } // namespace

  /// Mirrors src\moho\sim\STIMap.cpp moho::CHeightField::GetElevation (0x0044FB90).
  float HeightFieldElevation(const std::uint16_t* const data, const int width, const int height, const float x, const float z)
  {
    const int fx = fa::FloorToIntX87(x);
    const int fz = fa::FloorToIntX87(z);

    const float fracX = x - static_cast<float>(fx);
    const float fracZ = z - static_cast<float>(fz);

    const int wMax = width - 1;
    const int hMax = height - 1;

    const int fxNext = static_cast<int>(static_cast<std::uint32_t>(fx) + 1u);
    const int fzNext = static_cast<int>(static_cast<std::uint32_t>(fz) + 1u);
    const int x0 = ClampIndex(fx, wMax);
    const int x1 = ClampIndex(fxNext, wMax);
    const int z0 = ClampIndex(fz, hMax);
    const int z1 = ClampIndex(fzNext, hMax);

    const float h00 = static_cast<float>(data[x0 + z0 * width]) * 0.0078125f;
    const float h01 = static_cast<float>(data[x0 + z1 * width]) * 0.0078125f;
    const float h10 = static_cast<float>(data[x1 + z0 * width]) * 0.0078125f;
    const float h11 = static_cast<float>(data[x1 + z1 * width]) * 0.0078125f;

    return fa::BilinearHeight(h00, h01, h10, h11, fracX, fracZ);
  }

  /// Mirrors src\moho\sim\CRandomStream.cpp CMersenneTwister::ShuffleState (0x0040EBB0),
  /// NextUInt32 (0x0040E9F0) and CRandomStream::FRand(lower, upper) (0x0051B5C0).
  float RandomStreamFRand(std::uint32_t* const state, std::uint32_t& k, const float lower, const float upper)
  {
    constexpr std::uint32_t kStateWordCount = 0x270;
    constexpr std::uint32_t kTwistMiddle = 0x18D;
    constexpr std::uint32_t kTwistSplit = 0x0E3;
    constexpr std::uint32_t kLow31Mask = 0x7FFFFFFFu;
    constexpr std::uint32_t kTwistMagTable[2] = {0u, 0x9908B0DFu};

    if (k >= kStateWordCount) {
      std::uint32_t i = 0;
      for (; i < kTwistSplit; ++i) {
        const std::uint32_t mixed = ((state[i + 1] ^ state[i]) & kLow31Mask) ^ state[i];
        state[i] = (mixed >> 1) ^ kTwistMagTable[mixed & 1u] ^ state[i + kTwistMiddle];
      }
      for (; i < (kStateWordCount - 1); ++i) {
        const std::uint32_t mixed = ((state[i + 1] ^ state[i]) & kLow31Mask) ^ state[i];
        state[i] = (mixed >> 1) ^ kTwistMagTable[mixed & 1u] ^ state[i - kTwistSplit];
      }
      const std::uint32_t tailMixed = ((state[0] ^ state[kStateWordCount - 1]) & kLow31Mask) ^ state[kStateWordCount - 1];
      state[kStateWordCount - 1] = (tailMixed >> 1) ^ kTwistMagTable[tailMixed & 1u] ^ state[kTwistMiddle - 1];
      k = 0;
    }

    std::uint32_t word = state[k++];
    word ^= (word >> 11);
    word ^= (word & 0xFF3A58ADu) << 7;
    word ^= (word & 0xFFFFDF8Cu) << 15;
    word = (word >> 18) ^ word;

    return fa::TwisterWordInRange(lower, upper, word);
  }

  /// Mirrors src\moho\render\camera\VTransform.cpp moho::VTransform::Inverse (0x0046FBF0).
  void VTransformInverse(const float* const transform, float* const outTransform)
  {
    Wm3::Quaternionf orient;
    Wm3::Vector3f pos;
    std::memcpy(&orient, transform, sizeof(orient));
    std::memcpy(&pos, transform + 4, sizeof(pos));

    Wm3::Quaternionf invertedOrient;
    invertedOrient.w = orient.w;
    invertedOrient.x = -orient.x;
    invertedOrient.y = -orient.y;
    invertedOrient.z = -orient.z;

    const Wm3::Vector3f negatedPosition{-pos.x, -pos.y, -pos.z};
    Wm3::Vector3f invertedPos{0.0f, 0.0f, 0.0f};
    moho::MultQuadVec(&invertedPos, &negatedPosition, &invertedOrient);

    std::memcpy(outTransform, &invertedOrient, sizeof(invertedOrient));
    std::memcpy(outTransform + 4, &invertedPos, sizeof(invertedPos));
  }
} // namespace mirror
