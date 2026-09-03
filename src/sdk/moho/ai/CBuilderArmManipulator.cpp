#include "moho/ai/CBuilderArmManipulator.h"

#include <cstddef>
#include <cstdlib>
#include <cmath>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "lua/LuaObject.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/math/QuaternionMath.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/ManipulatorLuaFunctionThunks.h"
#include "moho/sim/Sim.h"
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

  [[nodiscard]] gpg::RType* CachedIAniManipulatorType()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  // Addresses 0x00637190/0x00617AF0/0x0064B360 (deserialize "ThunkA", three
  // compiled addresses) and 0x00637300/0x006354C0/0x0064B4D0 (deserialize
  // "ThunkB", three more) and 0x006371A0 (serialize "ThunkA") and
  // 0x00637310/0x00617B40 (serialize "ThunkB") formerly modeled here are all
  // dead: zero data_refs/call_edges for all nine, and no source-level caller
  // anywhere in src/sdk/**. `CBuilderArmManipulatorSerializer::Deserialize`/
  // `Serialize` (CBuilderArmManipulatorSerializer.cpp, wired via that
  // class's ctor -- independently confirmed by the 2026-08-26
  // ArchiveSerialization audit) already call `CBuilderArmManipulator::
  // MemberDeserialize`/`MemberSerialize` directly.

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
   * Address: 0x00637510 (FUN_00637510)
   *
   * IDA signature:
   * void __usercall Moho::CBuilderArmManipulator::MemberDeserialize(
   *     Moho::CBuilderArmManipulator *object@<eax>, gpg::ReadArchive *archive@<esi>);
   *
   * What it does:
   * Deserializes one `CBuilderArmManipulator` lane by loading
   * `IAniManipulator` base state, goal weak-pointer lane, and all builder-arm
   * tracking parameters.
   */
  void CBuilderArmManipulator::MemberDeserialize(
    CBuilderArmManipulator* const object,
    gpg::ReadArchive* const archive
  )
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedIAniManipulatorType(), static_cast<IAniManipulator*>(object), owner);
    archive->Read(CachedWeakPtrUnitType(), &object->mGoalUnit, owner);

    archive->ReadFloat(&object->mHeading);
    archive->ReadFloat(&object->mPitch);
    archive->ReadInt(&object->mReferenceBoneIdx);
    archive->ReadBool(&object->mTrackingScriptActive);
    archive->ReadFloat(&object->mHeadingCenter);
    archive->ReadFloat(&object->mHeadingHalfArc);
    archive->ReadFloat(&object->mHeadingMaxSlew);
    archive->ReadFloat(&object->mPitchCenter);
    archive->ReadFloat(&object->mPitchHalfArc);
    archive->ReadFloat(&object->mPitchMaxSlew);
    archive->ReadBool(&object->mOnTarget);
  }

  /**
   * Address: 0x00637640 (FUN_00637640)
   *
   * IDA signature:
   * void __usercall Moho::CBuilderArmManipulator::MemberSerialize(
   *     Moho::CBuilderArmManipulator *object@<edi>, gpg::WriteArchive *archive@<esi>);
   *
   * What it does:
   * Serializes one `CBuilderArmManipulator` lane by saving IAniManipulator
   * base state, goal weak-pointer lane, and all builder-arm tracking fields.
   */
  void CBuilderArmManipulator::MemberSerialize(
    const CBuilderArmManipulator* const object,
    gpg::WriteArchive* const archive
  )
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(CachedIAniManipulatorType(), object, owner);
    archive->Write(CachedWeakPtrUnitType(), &object->mGoalUnit, owner);

    archive->WriteFloat(object->mHeading);
    archive->WriteFloat(object->mPitch);
    archive->WriteInt(object->mReferenceBoneIdx);
    archive->WriteBool(object->mTrackingScriptActive);
    archive->WriteFloat(object->mHeadingCenter);
    archive->WriteFloat(object->mHeadingHalfArc);
    archive->WriteFloat(object->mHeadingMaxSlew);
    archive->WriteFloat(object->mPitchCenter);
    archive->WriteFloat(object->mPitchHalfArc);
    archive->WriteFloat(object->mPitchMaxSlew);
    archive->WriteBool(object->mOnTarget);
  }

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
   * Address: 0x00635CA0 (FUN_00635CA0, ??0CBuilderArmManipulator@Moho@@QAE@PAVUnit@1@PAVSim@1@IHH@Z)
   *
   * IDA signature:
   * Moho::CBuilderArmManipulator *__fastcall Moho::CBuilderArmManipulator::CBuilderArmManipulator(
   *     Moho::Unit *unit, Moho::Sim *sim, Moho::CBuilderArmManipulator *this,
   *     unsigned int boneA, int boneB, int boneMuzzle);
   *
   * What it does:
   * Builds one builder-arm aim manipulator bound to `{unit, sim}`: constructs the
   * `IAniManipulator` base on the unit's actor, head-inserts the intrusive weak
   * goal-unit link, seeds arc/tracking defaults, materializes the Lua script
   * object, registers the two watched bones, records the reference (muzzle) bone,
   * seeds the heading center from the watched bone's local orientation, and clears
   * the unit builder's on-target latch.
   */
  CBuilderArmManipulator::CBuilderArmManipulator(
    Unit* const unit,
    Sim* const sim,
    const std::uint32_t boneA,
    const std::int32_t boneB,
    const std::int32_t boneMuzzle
  )
    : IAniManipulator(sim, unit->AniActor, 0)
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
    // Head-insert the intrusive weak goal-unit link (freshly constructed node,
    // known-unlinked → bind-then-head-insert; mirrors the binary's list insert).
    mGoalUnit.BindObjectUnlinked(unit);
    (void)mGoalUnit.LinkIntoOwnerChainHeadUnlinked();

    // Materialize the Lua script object through the builder-arm metatable factory
    // (FUN_006371B0).
    {
      LuaPlus::LuaObject scriptContext3{};
      LuaPlus::LuaObject scriptContext2{};
      LuaPlus::LuaObject scriptContext1{};
      LuaPlus::LuaObject metatableObject{};
      (void)func_CreateLuaBuilderArmObject(&metatableObject, sim != nullptr ? sim->mLuaState : nullptr);
      static_cast<CScriptObject*>(this)->CreateLuaObject(metatableObject, scriptContext1, scriptContext2, scriptContext3);
    }

    // Read the goal unit's actor skeleton (RAII shared_ptr; released at scope end).
    Unit* const goalUnit = mGoalUnit.GetObjectPtr();
    const boost::shared_ptr<const CAniSkel> skeleton = goalUnit->AniActor->GetSkeleton();
    const CAniSkel* const skel = skeleton.get();

    // Register the two watched bones, then record the reference (muzzle) bone:
    // muzzle, then boneB, then boneA in priority order.
    AddWatchBone(static_cast<int>(boneA));
    AddWatchBone(boneB);

    std::int32_t referenceBone = boneMuzzle;
    if (boneMuzzle < 0) {
      referenceBone = boneB;
      if (boneB < 0) {
        referenceBone = static_cast<std::int32_t>(boneA);
      }
    }
    mReferenceBoneIdx = referenceBone;

    // Seed the heading center from the watched (boneA) bone local orientation.
    const SAniSkelBone* const bonesBegin = skel != nullptr ? skel->mBones.begin() : nullptr;
    if (bonesBegin != nullptr) {
      const std::size_t boneCount = static_cast<std::size_t>(skel->mBones.end() - bonesBegin);
      if (boneA < boneCount) {
        const Wm3::Quaternionf& ori = bonesBegin[boneA].mBoneTransform.orient_;
        mHeadingCenter = std::atan2(
          ((ori.w * ori.y) + (ori.x * ori.z)) * 2.0f,
          1.0f - (((ori.z * ori.z) + (ori.y * ori.y)) * 2.0f)
        );
      }
    }

    // Clear the unit builder's on-target latch (IAiBuilder vtable slot 17).
    if (Unit* const targetUnit = mGoalUnit.GetObjectPtr();
        targetUnit != nullptr && targetUnit->AiBuilder != nullptr) {
      targetUnit->AiBuilder->BuilderSetOnTarget(false);
    }
  }

  /**
   * Address: 0x00635FA0 (FUN_00635FA0, ??1CBuilderArmManipulator@Moho@@UAE@XZ)
   * Address: 0x00635C50 (FUN_00635C50, vtable-slot-2 scalar deleting
   * destructor: the full compiler-emitted picture -- sets this object's own
   * vtable and the `CScriptObject` sub-object vtable, unlinks the weak
   * goal-target node from its intrusive owner chain (decompiled as a
   * pointer-chasing loop over a mis-typed "vtable" field -- it is really the
   * weak-link's `next` pointer, the same shape as `RWeakPtr`-style unlink
   * elsewhere in this codebase), tail-calls `IAniManipulator::~IAniManipulator`,
   * then conditionally frees the object)
   *
   * What it does:
   * Runs weak-target lane teardown and forwards destruction into
   * `IAniManipulator`.
   */
  CBuilderArmManipulator::~CBuilderArmManipulator() = default;

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
   *
   * Same .x-scalar-vs-.w-scalar mismatch as `CAimManipulator::CheckTracking`
   * (identical structure): ground truth (`FUN_00636220.c`) conjugates
   * `orient_` keeping `.x` fixed and negating `.y/.z/.w`, and rotates via
   * `Moho::MultQuadVec`, not `Wm3::MultiplyQuaternionVector`. The local
   * pitch-basis quaternion's raw stack-offset construction (`FUN_00636220.asm`
   * -- Hex-Rays falls back to unnamed stack slots here) resolves to
   * `.x = cos(halfCenter)`, `.y = sin(halfCenter)`, `.z = 0`, `.w = 0` once
   * traced by physical offset from its `lea`-established base address.
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
      // Scalar-first conjugate: keep `.w`, negate `.x/.y/.z`. Every conjugate
      // decoded in this binary copies lane 0 verbatim and negates lanes 1-3 -
      // see `VTransform::Inverse` (0x0046FBF0) and the raw-lane helpers at
      // 0x0062FBA0 and 0x006377B0.
      Wm3::Quaternionf inverseOrientation{};
      inverseOrientation.w = compositeTransform.orient_.w;
      inverseOrientation.x = -compositeTransform.orient_.x;
      inverseOrientation.y = -compositeTransform.orient_.y;
      inverseOrientation.z = -compositeTransform.orient_.z;
      MultQuadVec(&transformedTarget, &targetDirection, &inverseOrientation);
    }

    float desiredAngle = 0.0f;
    float* currentAngleLane = nullptr;
    if ((trackingModeFlags & kTrackingModeHeading) != 0u) {
      currentAngleLane = &mHeading;
      desiredAngle = std::atan2(transformedTarget.x, transformedTarget.z);
    } else {
      const float halfCenter = angleCenter * kHalfScale;
      Wm3::Quaternionf pitchBasis{};
      pitchBasis.x = std::cos(halfCenter);
      pitchBasis.y = std::sin(halfCenter);
      pitchBasis.z = 0.0f;
      pitchBasis.w = 0.0f;

      Wm3::Vector3f pitchSpaceTarget{};
      MultQuadVec(&pitchSpaceTarget, &transformedTarget, &pitchBasis);
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

