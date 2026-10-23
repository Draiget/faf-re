// Definitions the recovered math TUs under test need but which live in
// src files too entangled to compile standalone. Each one is a verbatim
// copy of the engine source it names; keep them in sync (a stale mirror tests
// nothing). Everything else the harness exercises is compiled straight from
// src (see build.bat: QuaternionMath.cpp, Vector3f.cpp, X87Math.cpp).

#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"

// Mirrors src\moho\math\MathReflection.cpp:1295
// (`extern "C" int global_mode_sse2 = 1;`). The retail copy lives at
// 0x01107030 and is set by register_sseCompatMode (0x00A8ECBF) from the
// CPUID/movapd probe, i.e. 1 on any machine that runs the game; the harness
// pokes the same 1 into the mapped retail image.
extern "C" int global_mode_sse2 = 1;

/**
 * Mirrors src\moho\sim\Sim.cpp:6119-6170 (moho::QuatCrossAdd,
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
    self.mMinHeading = moho::NormalizeAngleSignedRadiansX87(msvc8::HalfSumX87(arc.mMinHeading, arc.mMaxHeading));
    self.mHeadingMaxSlew = arc.mHeadingMaxSlew;
    self.mMaxHeading = msvc8::HalfAbsDifferenceX87(arc.mMaxHeading, arc.mMinHeading);

    self.mMinPitch = moho::NormalizeAngleSignedRadiansX87(msvc8::HalfSumX87(arc.mMinPitch, arc.mMaxPitch));
    self.mPitchMaxSlew = arc.mPitchMaxSlew;
    self.mMaxPitch = msvc8::HalfAbsDifferenceX87(arc.mMaxPitch, arc.mMinPitch);
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
    self.mHeadingCenter = moho::NormalizeAngleSignedRadiansX87(msvc8::HalfSumX87(minHeading, maxHeading));
    self.mHeadingMaxSlew = headingMaxSlew;
    self.mHeadingHalfArc = msvc8::HalfAbsDifferenceX87(maxHeading, minHeading);

    self.mPitchCenter = moho::NormalizeAngleSignedRadiansX87(msvc8::HalfSumX87(minPitch, maxPitch));
    self.mPitchMaxSlew = pitchMaxSlew;
    self.mPitchHalfArc = msvc8::HalfAbsDifferenceX87(maxPitch, minPitch);
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
      desiredAngle = msvc8::atan2(transformedTarget.x, transformedTarget.z);
    } else {
      const float halfCenter = angleCenter * kHalfScale;
      Wm3::Quaternionf pitchBasis{};
      pitchBasis.w = msvc8::cos(halfCenter);
      pitchBasis.x = msvc8::sin(halfCenter);
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
      desiredAngle = msvc8::Atan2Plus(transformedTarget.x, transformedTarget.z, self.mHeadingOffset);
    } else {
      const float halfCenter = minAngleCenter * kHalfScale;
      Wm3::Quaternionf pitchBasis{};
      pitchBasis.w = msvc8::cos(halfCenter);
      pitchBasis.x = msvc8::sin(halfCenter);
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
    float wrapped = static_cast<float>(msvc8::fmod(value, range));
    if ((0.0f > wrapped) != (0.0f > range)) {
      wrapped += range;
    }
    return wrapped;
  }
} // namespace mirror
