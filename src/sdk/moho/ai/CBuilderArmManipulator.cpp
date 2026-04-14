#include "moho/ai/CBuilderArmManipulator.h"

#include <cmath>

#include "moho/ai/IAiBuilder.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/math/QuaternionMath.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr float kHalfScale = 0.5f;
  constexpr float kQuarterScale = 0.25f;
  constexpr float kPiRadians = 3.1415927f;
  constexpr float kNegativePiRadians = -3.1415927f;
  constexpr float kTwoPiRadians = 6.283185482025146f;
  constexpr float kClampAngleLimit = 3.1405928f;
  constexpr float kHeadingMotionEpsilon = 9.999999747378752e-06f;
  constexpr float kHeadingOnTargetTolerance = 0.2617993950843811f;

  constexpr std::uint8_t kTrackingModeHeading = 0x01;
  constexpr std::uint8_t kTrackingModePitch = 0x02;
  constexpr std::uint8_t kTrackingModeWorldSpace = 0x04;
  constexpr std::uint8_t kTrackingResultOutsideTolerance = 0x01;
  constexpr std::uint8_t kTrackingResultHeadingMotion = 0x02;

  [[nodiscard]] moho::CAniPoseBone* ResolvePoseBone(moho::CAniActor* const ownerActor, const std::int32_t boneIndex) noexcept
  {
    if (ownerActor == nullptr || ownerActor->mPose.px == nullptr || boneIndex < 0) {
      return nullptr;
    }

    moho::CAniPose* const pose = ownerActor->mPose.px;
    moho::CAniPoseBone* const bonesBegin = pose->mBones.begin();
    moho::CAniPoseBone* const bonesEnd = pose->mBones.end();
    if (bonesBegin == nullptr || bonesEnd == nullptr || bonesBegin >= bonesEnd) {
      return nullptr;
    }

    const std::ptrdiff_t boneCount = bonesEnd - bonesBegin;
    if (boneIndex >= boneCount) {
      return nullptr;
    }

    return &bonesBegin[boneIndex];
  }

  [[nodiscard]] moho::CAniPoseBone* ResolveWatchBone(
    moho::CBuilderArmManipulator* const manipulator, const std::size_t watchSlot
  ) noexcept
  {
    if (manipulator->mWatchBones.mBegin == nullptr) {
      return nullptr;
    }

    return ResolvePoseBone(manipulator->mOwnerActor, manipulator->mWatchBones.mBegin[watchSlot].mBoneIndex);
  }

  [[nodiscard]] float ComputePitchRadians(const Wm3::Vector3f& vector) noexcept
  {
    const float horizontalLength = std::sqrt((vector.x * vector.x) + (vector.z * vector.z));
    return std::atan2(vector.y, horizontalLength);
  }

  [[nodiscard]] float WrapSignedRadians(const float angle) noexcept
  {
    float wrapped = static_cast<float>(std::fmod(static_cast<double>(angle), static_cast<double>(kTwoPiRadians)));
    if (wrapped < kNegativePiRadians) {
      wrapped += kTwoPiRadians;
    } else if (wrapped > kPiRadians) {
      wrapped -= kTwoPiRadians;
    }
    return wrapped;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00635BB0 (FUN_00635BB0, ??0CBuilderArmManipulator@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one builder-arm manipulator lane with default heading/pitch
   * tracking parameters and cleared weak-target state.
   */
  CBuilderArmManipulator::CBuilderArmManipulator()
    : IAniManipulator()
    , mGoalUnit()
    , mHeading(0.0f)
    , mPitch(0.0f)
    , mTrackingScriptActive(false)
    , mHeadingCenter(0.0f)
    , mHeadingHalfArc(kPiRadians)
    , mHeadingMaxSlew(0.06283185631036758f)
    , mPitchCenter(15.0f)
    , mPitchHalfArc(30.0f)
    , mPitchMaxSlew(0.06108652427792549f)
    , mOnTarget(false)
  {
    // Binary constructor leaves the 0x90 lane untouched.
  }

  /**
   * Address: 0x00636490 (FUN_00636490, Moho::CBuilderArmManipulator::SetAimingArc)
   *
   * What it does:
   * Stores heading/pitch aim-center, half-arc, and max-slew lanes from
   * radians-domain Lua callback payload.
   */
  void CBuilderArmManipulator::SetAimingArc(
    const float minHeading,
    const float maxHeading,
    const float headingMaxSlew,
    const float minPitch,
    const float maxPitch,
    const float pitchMaxSlew
  )
  {
    mHeadingCenter = WrapSignedRadians((minHeading + maxHeading) * kHalfScale);
    mHeadingMaxSlew = headingMaxSlew;
    mHeadingHalfArc = std::fabs(maxHeading - minHeading) * kHalfScale;

    mPitchCenter = WrapSignedRadians((minPitch + maxPitch) * kHalfScale);
    mPitchMaxSlew = pitchMaxSlew;
    mPitchHalfArc = std::fabs(maxPitch - minPitch) * kHalfScale;
  }

  /**
   * Address: 0x006366F0 (FUN_006366F0, sub_6366F0)
   *
   * What it does:
   * Builds normalized direction from configured reference bone position to
   * builder aim target.
   */
  Wm3::Vector3f* CBuilderArmManipulator::ComputeDirectionToReferenceBone(
    Wm3::Vector3f* const outDirection, const Wm3::Vector3f& targetPoint
  ) const
  {
    const CAniPoseBone* const referenceBone = ResolvePoseBone(mOwnerActor, mReferenceBoneIdx);
    if (referenceBone == nullptr) {
      outDirection->x = 0.0f;
      outDirection->y = 0.0f;
      outDirection->z = 0.0f;
      return outDirection;
    }

    const VTransform& compositeTransform = referenceBone->GetCompositeTransform();
    const float deltaX = targetPoint.x - compositeTransform.pos_.x;
    const float deltaY = targetPoint.y - compositeTransform.pos_.y;
    const float deltaZ = targetPoint.z - compositeTransform.pos_.z;

    const float length = std::sqrt((deltaX * deltaX) + (deltaY * deltaY) + (deltaZ * deltaZ));
    if (length <= 0.0f) {
      outDirection->x = 0.0f;
      outDirection->y = 0.0f;
      outDirection->z = 0.0f;
      return outDirection;
    }

    const float inverseLength = 1.0f / length;
    outDirection->x = deltaX * inverseLength;
    outDirection->y = deltaY * inverseLength;
    outDirection->z = deltaZ * inverseLength;
    return outDirection;
  }

  /**
   * Address: 0x00636220 (FUN_00636220, sub_636220)
   *
   * What it does:
   * Updates one heading/pitch tracking lane against one watched bone and
   * returns tracking-state bits (`outside-tolerance`, `heading-moving`).
   */
  std::uint8_t CBuilderArmManipulator::UpdateTrackingAxis(
    const Wm3::Vector3f& targetDirection,
    CAniPoseBone* const watchBone,
    const float angleCenter,
    const float angleHalfArc,
    const float maxSlew,
    const std::uint8_t trackingModeFlags
  )
  {
    if (watchBone == nullptr) {
      return 0u;
    }

    Wm3::Vector3f transformedTarget = targetDirection;
    if ((trackingModeFlags & kTrackingModeWorldSpace) == 0u) {
      const VTransform& compositeTransform = watchBone->GetCompositeTransform();
      Wm3::Quaternionf inverseOrientation{};
      inverseOrientation.w = compositeTransform.orient_.w;
      inverseOrientation.x = -compositeTransform.orient_.x;
      inverseOrientation.y = -compositeTransform.orient_.y;
      inverseOrientation.z = -compositeTransform.orient_.z;
      Wm3::MultiplyQuaternionVector(&transformedTarget, targetDirection, inverseOrientation);
    }

    float desiredAngle = 0.0f;
    float* currentAngleLane = nullptr;
    if ((trackingModeFlags & kTrackingModeHeading) != 0u) {
      currentAngleLane = &mHeading;
      desiredAngle = std::atan2(transformedTarget.x, transformedTarget.z);
    } else {
      const float halfCenter = angleCenter * kHalfScale;
      Wm3::Quaternionf pitchBasis{};
      pitchBasis.w = std::cos(halfCenter);
      pitchBasis.x = std::sin(halfCenter);
      pitchBasis.y = 0.0f;
      pitchBasis.z = 0.0f;

      Wm3::Vector3f pitchSpaceTarget{};
      Wm3::MultiplyQuaternionVector(&pitchSpaceTarget, transformedTarget, pitchBasis);
      currentAngleLane = &mPitch;
      desiredAngle = angleCenter - ComputePitchRadians(pitchSpaceTarget);
    }

    const float currentAngle = *currentAngleLane;
    float laneDelta = 0.0f;
    if (angleHalfArc < kClampAngleLimit) {
      float constrained = NormalizeAngleSignedRadians(desiredAngle - angleCenter);
      if (constrained > angleHalfArc) {
        constrained = angleHalfArc;
      } else if (constrained < -angleHalfArc) {
        constrained = -angleHalfArc;
      }
      laneDelta = (constrained + angleCenter) - currentAngle;
    } else {
      laneDelta = NormalizeAngleSignedRadians(desiredAngle - currentAngle);
    }

    float step = laneDelta;
    if (std::fabs(step) > maxSlew) {
      step = std::copysign(maxSlew, step);
    }

    float nextAngle = static_cast<float>(std::fmod(static_cast<double>(step + currentAngle), static_cast<double>(kTwoPiRadians)));
    if (nextAngle >= kNegativePiRadians) {
      if (nextAngle > kPiRadians) {
        nextAngle -= kTwoPiRadians;
      }
    } else {
      nextAngle += kTwoPiRadians;
    }
    *currentAngleLane = nextAngle;

    std::uint8_t trackingResult = 0u;
    if ((trackingModeFlags & kTrackingModeHeading) != 0u) {
      if (std::fabs(laneDelta) > kHeadingMotionEpsilon) {
        trackingResult |= kTrackingResultHeadingMotion;
      }

      const float onTargetDelta = NormalizeAngleSignedRadians(nextAngle - desiredAngle);
      if (std::fabs(onTargetDelta) > kHeadingOnTargetTolerance) {
        trackingResult |= kTrackingResultOutsideTolerance;
      }
    }

    return trackingResult;
  }

  /**
   * Address: 0x00635FE0 (FUN_00635FE0, sub_635FE0)
   *
   * What it does:
   * Runs heading/pitch track steps, rotates watched bones, triggers
   * builder-tracking script callbacks, and returns on-target state.
   */
  bool CBuilderArmManipulator::TrackAimDirection(
    const Wm3::Vector3f& targetDirection,
    const std::uint8_t trackingModeFlags,
    const bool reducedSlew
  )
  {
    std::uint8_t trackingResult = 0u;

    if (CAniPoseBone* const headingBone = ResolveWatchBone(this, 0u); headingBone != nullptr) {
      float headingSlew = mHeadingMaxSlew;
      if (reducedSlew) {
        headingSlew *= kQuarterScale;
      }

      trackingResult = UpdateTrackingAxis(
        targetDirection,
        headingBone,
        mHeadingCenter,
        mHeadingHalfArc,
        headingSlew,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModeHeading)
      );

      const float halfHeading = mHeading * kHalfScale;
      Wm3::Quaternionf headingRotation{};
      headingRotation.w = std::cos(halfHeading);
      headingRotation.x = 0.0f;
      headingRotation.y = std::sin(halfHeading);
      headingRotation.z = 0.0f;
      headingBone->Rotate(headingRotation);
    }

    if (CAniPoseBone* const pitchBone = ResolveWatchBone(this, 1u); pitchBone != nullptr) {
      float pitchSlew = mPitchMaxSlew;
      if (reducedSlew) {
        pitchSlew *= kQuarterScale;
      }

      trackingResult |= UpdateTrackingAxis(
        targetDirection,
        pitchBone,
        mPitchCenter,
        mPitchHalfArc,
        pitchSlew,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModePitch)
      );

      const float halfPitch = (-mPitch) * kHalfScale;
      Wm3::Quaternionf pitchRotation{};
      pitchRotation.w = std::cos(halfPitch);
      pitchRotation.x = std::sin(halfPitch);
      pitchRotation.y = 0.0f;
      pitchRotation.z = 0.0f;
      pitchBone->Rotate(pitchRotation);
    }

    const bool isTracking = (trackingResult & kTrackingResultHeadingMotion) != 0u;
    if (isTracking) {
      if (!mTrackingScriptActive) {
        if (Unit* const unit = mGoalUnit.GetObjectPtr(); unit != nullptr) {
          unit->RunScript("OnStartBuilderTracking");
        }
      }
    } else if (mTrackingScriptActive) {
      if (Unit* const unit = mGoalUnit.GetObjectPtr(); unit != nullptr) {
        unit->RunScript("OnStopBuilderTracking");
      }
    }

    mTrackingScriptActive = isTracking;
    return (trackingResult & kTrackingResultOutsideTolerance) == 0u;
  }

  /**
   * Address: 0x00636590 (FUN_00636590, Moho::CBuilderArmManipulator::MoveManipulator)
   *
   * What it does:
   * Advances builder-arm tracking from builder aim target, updates on-target
   * state in `IAiBuilder`, and toggles task-event signaled state.
   */
  bool CBuilderArmManipulator::ManipulatorUpdate()
  {
    Unit* const unit = mGoalUnit.GetObjectPtr();
    if (unit == nullptr || unit->AiBuilder == nullptr || unit->IsDead()) {
      return false;
    }

    const Wm3::Vector3f aimTarget = unit->AiBuilder->BuilderGetAimTarget();
    if (aimTarget.x != 0.0f || aimTarget.y != 0.0f || aimTarget.z != 0.0f) {
      Wm3::Vector3f direction{};
      (void)ComputeDirectionToReferenceBone(&direction, aimTarget);
      mOnTarget = TrackAimDirection(direction, 0u, false);

      if (unit->AiBuilder != nullptr) {
        unit->AiBuilder->BuilderSetOnTarget(mOnTarget);
      }
      EventSetSignaled(mOnTarget);
      return true;
    }

    const Wm3::Vector3f forward{0.0f, 0.0f, 1.0f};
    (void)TrackAimDirection(forward, kTrackingModeWorldSpace, true);
    if (unit->AiBuilder != nullptr) {
      unit->AiBuilder->BuilderSetOnTarget(false);
    }
    mTriggered = false;
    return true;
  }
} // namespace moho
