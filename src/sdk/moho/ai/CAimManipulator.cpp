// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/ai/CAimManipulator.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "lua/LuaObject.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/entity/Entity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/Sim.h"
#include "moho/task/CTaskEvent.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"

bool moho::dbg_Ballistics = false;
gpg::RType* moho::CAimManipulator::sType = nullptr;
moho::CScrLuaMetatableFactory<moho::CAimManipulator>
  moho::CScrLuaMetatableFactory<moho::CAimManipulator>::sInstance{};

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kAimManipulatorLuaClassName = "CAimManipulator";

  constexpr const char* kCAimManipulatorSetFiringArcName = "SetFiringArc";
  constexpr const char* kCAimManipulatorSetFiringArcHelpText =
    "AimManipulator:SetFiringArc(minHeading, maxHeading, headingMaxSlew, minPitch, maxPitch, pitchMaxSlew)";

  constexpr const char* kCAimManipulatorSetResetPoseTimeName = "SetResetPoseTime";
  constexpr const char* kCAimManipulatorSetResetPoseTimeHelpText = "AimManipulator:SetResetPoseTime(resetTime)";

  constexpr const char* kCAimManipulatorOnTargetName = "OnTarget";
  constexpr const char* kCAimManipulatorOnTargetHelpText = "AimManipulator:OnTarget()";

  constexpr const char* kCAimManipulatorSetEnabledName = "SetEnabled";
  constexpr const char* kCAimManipulatorSetEnabledHelpText = "AimManipulator:SetEnabled(flag)";

  constexpr const char* kCAimManipulatorGetHeadingPitchName = "GetHeadingPitch";
  constexpr const char* kCAimManipulatorGetHeadingPitchHelpText = "AimManipulator:GetHeadingPitch()";

  constexpr const char* kCAimManipulatorSetHeadingPitchName = "SetHeadingPitch";
  constexpr const char* kCAimManipulatorSetHeadingPitchHelpText = "AimManipulator:SetHeadingPitch( heading, pitch )";

  constexpr const char* kCAimManipulatorSetAimHeadingOffsetName = "SetAimHeadingOffset";
  constexpr const char* kCAimManipulatorSetAimHeadingOffsetHelpText = "AimManipulator:SetAimHeadingOffset( offset )";

  constexpr float kDegreesToRadians = 0.017453292f;
  constexpr float kSlewScale = 0.1f;
  constexpr float kHalfScale = 0.5f;
  constexpr float kTwoPiRadians = 6.283185482025146f;
  constexpr float kPiRadians = 3.1415927f;
  constexpr float kAngleNormalizationClamp = 3.1405928f;
  constexpr float kTrackingMotionEpsilon = 0.001f;
  constexpr float kFiringToleranceToRadians = 0.017453292f;

  constexpr std::uint8_t kTrackingModeHeading = 0x01;
  constexpr std::uint8_t kTrackingModePitch = 0x02;
  constexpr std::uint8_t kTrackingModeWorldSpace = 0x04;

  constexpr std::uint8_t kTrackingResultOutsideTolerance = 0x01;
  constexpr std::uint8_t kTrackingResultHeadingMotion = 0x02;

  constexpr float kAimVectorEpsilon = 0.001f;
  constexpr float kAimDistanceSqEpsilon = 0.000099999997f;
  constexpr float kLeadPolynomialA = 0.0076100002f;
  constexpr float kLeadPolynomialB = 0.16605f;
  constexpr float kAimVelocityScale = 10.0f;
  constexpr float kAimVelocityStepScale = 0.1f;
  constexpr float kAimGravityStepScale = 0.010000001f;
  constexpr float kInterceptIterationDeltaEpsilon = 0.1f;
  constexpr std::int32_t kInterceptIterationLimit = 10;
  constexpr const char* kInvalidMuzzleBoneWarningFormat =
    "Using non-existant muzzle bone in aim manipulator for unit %s";

  struct CAimManipulatorBaseRuntimeView
  {
    std::uint8_t mUnresolved00_03[0x04];
    bool mTaskEventTriggered;                     // +0x04
    std::uint8_t mUnresolved05_4B[0x47];
    bool mBaseEnabled;                            // +0x4C
    std::uint8_t mUnresolved4D_4F[0x03];
    moho::CAniActor* mOwnerActor;                 // +0x50
    moho::Sim* mOwnerSim;                         // +0x54
    std::int32_t mPrecedence;                     // +0x58
    std::uint32_t mUnknown5C;                     // +0x5C
    moho::SAniManipBindingStorage mWatchBones;    // +0x60
  };

  static_assert(
    offsetof(CAimManipulatorBaseRuntimeView, mTaskEventTriggered) == 0x04,
    "CAimManipulatorBaseRuntimeView::mTaskEventTriggered offset must be 0x04"
  );
  static_assert(
    offsetof(CAimManipulatorBaseRuntimeView, mOwnerActor) == 0x50,
    "CAimManipulatorBaseRuntimeView::mOwnerActor offset must be 0x50"
  );
  static_assert(
    offsetof(CAimManipulatorBaseRuntimeView, mOwnerSim) == 0x54,
    "CAimManipulatorBaseRuntimeView::mOwnerSim offset must be 0x54"
  );
  static_assert(
    offsetof(CAimManipulatorBaseRuntimeView, mWatchBones) == 0x60,
    "CAimManipulatorBaseRuntimeView::mWatchBones offset must be 0x60"
  );
  static_assert(sizeof(CAimManipulatorBaseRuntimeView) == 0x80, "CAimManipulatorBaseRuntimeView size must be 0x80");

  struct CAimManipulatorRuntimeView
  {
    std::uint8_t mUnresolved00_7F[0x80];
    moho::WeakPtr<moho::Unit> mUnit;             // +0x80
    moho::WeakPtr<moho::UnitWeapon> mWeapon;     // +0x88
    msvc8::string mLabel;                        // +0x90
    moho::RUnitBlueprintWeapon* mUnitWepBlueprint; // +0xAC
    moho::RProjectileBlueprintPhysics* mProjPhysBlueprint; // +0xB0
    bool mEnabled; // +0xB4
    std::uint8_t mUnresolvedB5_B7[0x03];
    float mHeading; // +0xB8
    float mPitch;   // +0xBC
    std::int32_t mMuzzleBone; // +0xC0
    bool mIsTracking;         // +0xC4
    std::uint8_t mUnresolvedC5_C7[0x03];
    float mMinHeading;     // +0xC8
    float mMaxHeading;     // +0xCC
    float mHeadingMaxSlew; // +0xD0
    float mMinPitch;       // +0xD4
    float mMaxPitch;       // +0xD8
    float mPitchMaxSlew;   // +0xDC
    bool mOnTarget;     // +0xE0
    bool mUnknownBoolE1; // +0xE1
    std::uint8_t mUnresolvedE2_E3[0x02];
    std::int32_t mResetPoseTime; // +0xE4
    std::int32_t mResetTime; // +0xE8
    Wm3::Quaternionf mBone0Rot; // +0xEC
    Wm3::Quaternionf mBone1Rot; // +0xFC
    float mHeadingOffset; // +0x10C
  };

  static_assert(offsetof(CAimManipulatorRuntimeView, mUnit) == 0x80, "CAimManipulatorRuntimeView::mUnit offset must be 0x80");
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mWeapon) == 0x88,
    "CAimManipulatorRuntimeView::mWeapon offset must be 0x88"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mLabel) == 0x90,
    "CAimManipulatorRuntimeView::mLabel offset must be 0x90"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mUnitWepBlueprint) == 0xAC,
    "CAimManipulatorRuntimeView::mUnitWepBlueprint offset must be 0xAC"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mProjPhysBlueprint) == 0xB0,
    "CAimManipulatorRuntimeView::mProjPhysBlueprint offset must be 0xB0"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mEnabled) == 0xB4,
    "CAimManipulatorRuntimeView::mEnabled offset must be 0xB4"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mHeading) == 0xB8,
    "CAimManipulatorRuntimeView::mHeading offset must be 0xB8"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mPitch) == 0xBC,
    "CAimManipulatorRuntimeView::mPitch offset must be 0xBC"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mMuzzleBone) == 0xC0,
    "CAimManipulatorRuntimeView::mMuzzleBone offset must be 0xC0"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mIsTracking) == 0xC4,
    "CAimManipulatorRuntimeView::mIsTracking offset must be 0xC4"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mMinHeading) == 0xC8,
    "CAimManipulatorRuntimeView::mMinHeading offset must be 0xC8"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mMaxHeading) == 0xCC,
    "CAimManipulatorRuntimeView::mMaxHeading offset must be 0xCC"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mHeadingMaxSlew) == 0xD0,
    "CAimManipulatorRuntimeView::mHeadingMaxSlew offset must be 0xD0"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mMinPitch) == 0xD4,
    "CAimManipulatorRuntimeView::mMinPitch offset must be 0xD4"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mMaxPitch) == 0xD8,
    "CAimManipulatorRuntimeView::mMaxPitch offset must be 0xD8"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mPitchMaxSlew) == 0xDC,
    "CAimManipulatorRuntimeView::mPitchMaxSlew offset must be 0xDC"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mOnTarget) == 0xE0,
    "CAimManipulatorRuntimeView::mOnTarget offset must be 0xE0"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mUnknownBoolE1) == 0xE1,
    "CAimManipulatorRuntimeView::mUnknownBoolE1 offset must be 0xE1"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mResetPoseTime) == 0xE4,
    "CAimManipulatorRuntimeView::mResetPoseTime offset must be 0xE4"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mResetTime) == 0xE8,
    "CAimManipulatorRuntimeView::mResetTime offset must be 0xE8"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mBone0Rot) == 0xEC,
    "CAimManipulatorRuntimeView::mBone0Rot offset must be 0xEC"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mBone1Rot) == 0xFC,
    "CAimManipulatorRuntimeView::mBone1Rot offset must be 0xFC"
  );
  static_assert(
    offsetof(CAimManipulatorRuntimeView, mHeadingOffset) == 0x10C,
    "CAimManipulatorRuntimeView::mHeadingOffset offset must be 0x10C"
  );

  [[nodiscard]] gpg::RType* CachedCAimManipulatorType()
  {
    gpg::RType* type = moho::CAimManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAimManipulator));
      moho::CAimManipulator::sType = type;
    }
    return type;
  }

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
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitWeaponType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::WeakPtr<moho::UnitWeapon>));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Quaternionf));
    }
    return type;
  }

  [[nodiscard]] gpg::RRef NullOwnerRef() noexcept
  {
    return {};
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] float NormalizeCenteredAngle(const float minimum, const float maximum) noexcept
  {
    float centered = std::fmod((minimum + maximum) * kHalfScale, kTwoPiRadians);
    if (centered < -kPiRadians) {
      centered += kTwoPiRadians;
    } else if (centered > kPiRadians) {
      centered -= kTwoPiRadians;
    }
    return centered;
  }

  [[nodiscard]] float NormalizeAngleRadians(float angleRadians) noexcept
  {
    angleRadians = std::fmod(angleRadians, kTwoPiRadians);
    if (angleRadians < -kPiRadians) {
      angleRadians += kTwoPiRadians;
    } else if (angleRadians > kPiRadians) {
      angleRadians -= kTwoPiRadians;
    }
    return angleRadians;
  }

  [[nodiscard]] float ComputePitchRadians(const Wm3::Vector3f& vector) noexcept
  {
    const float horizontalLength = std::sqrt((vector.x * vector.x) + (vector.z * vector.z));
    return std::atan2(vector.y, horizontalLength);
  }

  [[nodiscard]] CAimManipulatorBaseRuntimeView* AimManipulatorBaseView(moho::CAimManipulator* const manipulator) noexcept
  {
    return reinterpret_cast<CAimManipulatorBaseRuntimeView*>(manipulator);
  }

  [[nodiscard]] const CAimManipulatorBaseRuntimeView*
  AimManipulatorBaseView(const moho::CAimManipulator* const manipulator) noexcept
  {
    return reinterpret_cast<const CAimManipulatorBaseRuntimeView*>(manipulator);
  }

  [[nodiscard]] CAimManipulatorRuntimeView* AimManipulatorRuntimeView(moho::CAimManipulator* const manipulator) noexcept
  {
    return reinterpret_cast<CAimManipulatorRuntimeView*>(manipulator);
  }

  [[nodiscard]] const CAimManipulatorRuntimeView*
  AimManipulatorRuntimeView(const moho::CAimManipulator* const manipulator) noexcept
  {
    return reinterpret_cast<const CAimManipulatorRuntimeView*>(manipulator);
  }

  [[nodiscard]] moho::CAniPoseBone* ResolvePoseBone(moho::CAniActor* const actor, const int boneIndex) noexcept
  {
    if (actor == nullptr || actor->mPose.px == nullptr || boneIndex < 0) {
      return nullptr;
    }

    moho::CAniPose* const pose = actor->mPose.px;
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
    moho::CAimManipulator* const manipulator, const std::size_t watchIndex
  ) noexcept
  {
    CAimManipulatorBaseRuntimeView* const baseView = AimManipulatorBaseView(manipulator);
    if (baseView->mWatchBones.mBegin == nullptr) {
      return nullptr;
    }

    return ResolvePoseBone(baseView->mOwnerActor, baseView->mWatchBones.mBegin[watchIndex].mBoneIndex);
  }

  [[nodiscard]] std::string ToStdString(const msvc8::string& value)
  {
    const std::string_view view = value.view();
    return std::string(view.data(), view.size());
  }

  [[nodiscard]] const Wm3::Vector3f& InvalidAimVector() noexcept
  {
    static bool initialized = false;
    static Wm3::Vector3f invalid{};
    if (!initialized) {
      invalid = Wm3::Vector3f::NaN();
      initialized = true;
    }
    return invalid;
  }

  [[nodiscard]] bool IsAimVectorValid(const Wm3::Vector3f& value) noexcept
  {
    return Wm3::Vector3f::IsntNaN(value);
  }

  [[nodiscard]] Wm3::Vector3f ComputeUnitForwardDirection(const moho::Unit& unit) noexcept
  {
    const moho::VTransform& transform = unit.GetTransform();
    Wm3::Vector3f direction{};
    direction.y =
      ((transform.orient_.w * transform.orient_.z) - (transform.orient_.x * transform.orient_.y)) * 2.0f;
    direction.x =
      ((transform.orient_.x * transform.orient_.z) + (transform.orient_.w * transform.orient_.y)) * 2.0f;
    direction.z =
      1.0f - (((transform.orient_.z * transform.orient_.z) + (transform.orient_.y * transform.orient_.y)) * 2.0f);
    return direction;
  }

  /**
   * Address: 0x006312B0 (FUN_006312B0)
   *
   * What it does:
   * Predicts one intercept point for a moving target under constant projectile
   * speed using the original polynomial lead approximation lane.
   */
  Wm3::Vector3f* PredictInterceptPointConstantSpeed(
    Wm3::Vector3f* const outIntercept,
    const Wm3::Vector3f& targetPosition,
    const Wm3::Vector3f& targetVelocity,
    const float projectileSpeed,
    const Wm3::Vector3f& muzzlePosition
  )
  {
    const float velocityMagnitude = std::sqrt(
      (targetVelocity.x * targetVelocity.x) + (targetVelocity.y * targetVelocity.y) + (targetVelocity.z * targetVelocity.z)
    );
    if (velocityMagnitude < kAimVectorEpsilon) {
      *outIntercept = targetPosition;
      return outIntercept;
    }

    const float distanceX = muzzlePosition.x - targetPosition.x;
    const float distanceY = muzzlePosition.y - targetPosition.y;
    const float distanceZ = muzzlePosition.z - targetPosition.z;
    const float distanceToMuzzle = std::sqrt((distanceX * distanceX) + (distanceY * distanceY) + (distanceZ * distanceZ));
    if ((distanceToMuzzle * distanceToMuzzle) < kAimDistanceSqEpsilon) {
      *outIntercept = targetPosition;
      return outIntercept;
    }

    const float invDistance = 1.0f / distanceToMuzzle;
    const float invVelocity = 1.0f / velocityMagnitude;
    const Wm3::Vector3f normalizedDistance{distanceX * invDistance, distanceY * invDistance, distanceZ * invDistance};
    const Wm3::Vector3f normalizedVelocity{
      targetVelocity.x * invVelocity,
      targetVelocity.y * invVelocity,
      targetVelocity.z * invVelocity,
    };

    const float alignment =
      2.0f -
      ((normalizedVelocity.x * normalizedDistance.x) + (normalizedVelocity.y * normalizedDistance.y) +
       (normalizedVelocity.z * normalizedDistance.z));
    const float speedDelta = (velocityMagnitude * velocityMagnitude) - (projectileSpeed * projectileSpeed);
    if ((speedDelta * speedDelta) < kAimDistanceSqEpsilon) {
      *outIntercept = targetPosition;
      return outIntercept;
    }

    const float alignmentSq = alignment * alignment;
    const float interceptTerm = ((((alignmentSq * kLeadPolynomialA) - kLeadPolynomialB) * alignmentSq) + 1.0f) * alignment *
                                distanceToMuzzle * velocityMagnitude;
    const float discriminant =
      (interceptTerm * interceptTerm) - ((speedDelta * distanceToMuzzle) * distanceToMuzzle);
    if (discriminant < 0.0f) {
      *outIntercept = targetPosition;
      return outIntercept;
    }

    const float timeToIntercept = (interceptTerm - std::sqrt(discriminant)) / speedDelta;
    outIntercept->x = targetPosition.x + (targetVelocity.x * timeToIntercept);
    outIntercept->y = targetPosition.y + (targetVelocity.y * timeToIntercept);
    outIntercept->z = targetPosition.z + (targetVelocity.z * timeToIntercept);
    return outIntercept;
  }

  /**
   * Address: 0x00631580 (FUN_00631580)
   *
   * What it does:
   * Iteratively predicts one intercept point in horizontal plane using muzzle
   * forward projected speed and target velocity lanes.
   */
  Wm3::Vector3f* PredictInterceptPointFromForwardVelocity(
    Wm3::Vector3f* const outIntercept,
    const Wm3::Quaternionf& muzzleOrientation,
    const float projectileSpeed,
    const Wm3::Vector3f& targetPosition,
    const Wm3::Vector3f& targetVelocity,
    const Wm3::Vector3f& muzzlePosition
  )
  {
    const float forwardProjection = (muzzleOrientation.w * muzzleOrientation.y) + (muzzleOrientation.x * muzzleOrientation.z);
    const float horizontalProjection =
      1.0f - (((muzzleOrientation.z * muzzleOrientation.z) + (muzzleOrientation.y * muzzleOrientation.y)) * 2.0f);
    const float horizontalSpeed = std::sqrt(
                                    ((forwardProjection * 2.0f) * (forwardProjection * 2.0f)) +
                                    (horizontalProjection * horizontalProjection)
                                  ) *
                                  projectileSpeed;
    if (horizontalSpeed <= kAimVectorEpsilon) {
      *outIntercept = targetPosition;
      return outIntercept;
    }

    const float invHorizontalSpeed = 1.0f / horizontalSpeed;
    float interceptTime = std::sqrt(
                            ((muzzlePosition.x - targetPosition.x) * (muzzlePosition.x - targetPosition.x)) +
                            ((muzzlePosition.z - targetPosition.z) * (muzzlePosition.z - targetPosition.z))
                          ) *
                          invHorizontalSpeed;

    for (std::int32_t iteration = 0; iteration < kInterceptIterationLimit; ++iteration) {
      const float previousTime = interceptTime;
      const float predictedX = targetPosition.x + (targetVelocity.x * interceptTime);
      const float predictedZ = targetPosition.z + (targetVelocity.z * interceptTime);
      interceptTime = std::sqrt(
                        ((muzzlePosition.x - predictedX) * (muzzlePosition.x - predictedX)) +
                        ((muzzlePosition.z - predictedZ) * (muzzlePosition.z - predictedZ))
                      ) *
                      invHorizontalSpeed;
      if (std::fabs(interceptTime - previousTime) <= kInterceptIterationDeltaEpsilon) {
        break;
      }
    }

    outIntercept->x = targetPosition.x + (targetVelocity.x * interceptTime);
    outIntercept->y = targetPosition.y + (targetVelocity.y * interceptTime);
    outIntercept->z = targetPosition.z + (targetVelocity.z * interceptTime);
    return outIntercept;
  }

  /**
   * Address: 0x005D6310 (FUN_005D6310, Moho::AI_CalculateFiringPitch)
   *
   * What it does:
   * Solves high/low ballistic firing angles from start/end points, gravity,
   * and muzzle velocity.
   */
  [[nodiscard]] bool CalculateFiringPitch(
    float* const highArc,
    const Wm3::Vector3f& muzzlePosition,
    const Wm3::Vector3f& targetPosition,
    const moho::SPhysConstants& physConstants,
    const float muzzleVelocity,
    float* const lowArc
  )
  {
    const float dz = targetPosition.z - muzzlePosition.z;
    const float horizontalDistance = std::sqrt((dz * dz) + ((targetPosition.x - muzzlePosition.x) * (targetPosition.x - muzzlePosition.x)));
    const float pitchScalar = (0.0f - ((horizontalDistance * horizontalDistance) * physConstants.mGravity.y)) /
                              ((muzzleVelocity * muzzleVelocity) * 2.0f);
    const float negDistance = 0.0f - horizontalDistance;
    const float discriminant =
      (negDistance * negDistance) - ((((targetPosition.y - muzzlePosition.y) + pitchScalar) * pitchScalar) * 4.0f);
    if (discriminant < 0.0f) {
      return false;
    }

    const float discriminantRoot = std::sqrt(discriminant);
    const float denominator = pitchScalar * 2.0f;
    if (highArc != nullptr) {
      *highArc = -std::atan2((discriminantRoot - negDistance) / denominator, 1.0f);
    }
    if (lowArc != nullptr) {
      *lowArc = -std::atan2(((-negDistance) - discriminantRoot) / denominator, 1.0f);
    }

    return true;
  }

  /**
   * Address: 0x005D6440 (FUN_005D6440, Moho::AI_CalculateFiringDirection)
   *
   * What it does:
   * Builds one normalized firing direction vector from start/end points and
   * selected ballistic pitch.
   */
  Wm3::Vector3f* CalculateFiringDirection(
    Wm3::Vector3f* const outDirection,
    const Wm3::Vector3f& from,
    const Wm3::Vector3f& to,
    const float pitch
  )
  {
    outDirection->x = from.x - to.x;
    outDirection->z = from.z - to.z;
    outDirection->y = 0.0f;

    const float cosinePitch = std::cos(pitch);
    const float horizontalMagnitude = std::sqrt((outDirection->x * outDirection->x) + (outDirection->z * outDirection->z));
    if (horizontalMagnitude > 0.0f) {
      const float scale = cosinePitch / horizontalMagnitude;
      outDirection->x *= scale;
      outDirection->z *= scale;
    }

    outDirection->y = -std::sin(pitch);
    return outDirection;
  }
} // namespace

/**
 * Address: 0x0062FDF0 (FUN_0062FDF0, Moho::CAimManipulator::StaticGetClass)
 *
 * What it does:
 * Returns cached reflection type for `CAimManipulator`, resolving it from
 * RTTI on first use.
 */
gpg::RType* moho::CAimManipulator::StaticGetClass()
{
  return CachedCAimManipulatorType();
}

/**
 * Address: 0x0062FE10 (FUN_0062FE10, Moho::CAimManipulator::GetClass)
 *
 * What it does:
 * Returns cached reflection type for this object view.
 */
gpg::RType* moho::CAimManipulator::GetClass() const
{
  return CachedCAimManipulatorType();
}

/**
 * Address: 0x0062FE30 (FUN_0062FE30, Moho::CAimManipulator::GetDerivedObjectRef)
 *
 * What it does:
 * Builds one reflected object reference for this manipulator instance.
 */
gpg::RRef moho::CAimManipulator::GetDerivedObjectRef()
{
  return MakeDerivedRef(this, CachedCAimManipulatorType());
}

/**
 * Address: 0x00630200 (FUN_00630200, Moho::CAimManipulator::dtr)
 *
 * What it does:
 * Executes CAimManipulator teardown and conditionally frees this object when
 * `deleteFlags & 1` is set.
 */
void moho::CAimManipulator::operator_delete(const std::int32_t deleteFlags)
{
  this->~CAimManipulator();
  if ((deleteFlags & 1) != 0) {
    ::operator delete(this);
  }
}

/**
 * Address: 0x00630DB0 (FUN_00630DB0, Moho::CAimManipulator::AimManip)
 *
 * What it does:
 * Executes one manipulator update: validates owner/weapon state, drives aim
 * target tracking, mirrors on-target state into weapon lanes, and updates
 * task-event signaling.
 */
void moho::CAimManipulator::AimManip()
{
  auto* const runtimeView = AimManipulatorRuntimeView(this);
  Unit* const unit = runtimeView->mUnit.GetObjectPtr();
  if (unit == nullptr) {
    return;
  }

  if (unit->IsBeingBuilt()) {
    return;
  }

  const bool aimsStraightOnDisable =
    runtimeView->mUnitWepBlueprint != nullptr && runtimeView->mUnitWepBlueprint->AimsStraightOnDisable != 0u;
  if (!runtimeView->mEnabled && !aimsStraightOnDisable) {
    return;
  }

  auto* const taskEvent = reinterpret_cast<CTaskEvent*>(this);
  UnitWeapon* const weapon = runtimeView->mWeapon.GetObjectPtr();
  if (weapon == nullptr || unit->IsDead() || unit->StunnedState != 0) {
    runtimeView->mOnTarget = false;
    if (CAniPoseBone* const watchBone0 = ResolveWatchBone(this, 0u); watchBone0 != nullptr) {
      watchBone0->Rotate(runtimeView->mBone0Rot);
    }
    if (CAniPoseBone* const watchBone1 = ResolveWatchBone(this, 1u); watchBone1 != nullptr) {
      watchBone1->Rotate(runtimeView->mBone1Rot);
    }
    taskEvent->EventSetSignaled(false);
    return;
  }

  weapon->mUnknown174 = 1u;
  weapon->mAimingAt = InvalidAimVector();

  const bool shouldTrackTarget = runtimeView->mEnabled || !aimsStraightOnDisable;
  CAiTarget* const target = &weapon->mTarget;
  if (target->targetType != EAiTargetType::AITARGET_None && shouldTrackTarget) {
    if (!target->HasTarget()) {
      runtimeView->mOnTarget = false;
      Rotate1(true);
      Rotate2(true);
    } else {
      if (runtimeView->mResetPoseTime <= 0) {
        std::int32_t resetTime = 1;
        if (weapon->mWeaponBlueprint != nullptr) {
          resetTime = static_cast<std::int32_t>(std::lround(weapon->mWeaponBlueprint->TargetCheckInterval * 10.0f));
          if (resetTime < 1) {
            resetTime = 1;
          }
        }
        runtimeView->mResetTime = resetTime;
      } else {
        runtimeView->mResetTime = runtimeView->mResetPoseTime;
      }

      Wm3::Vector3f aimDirection{};
      Aim(&aimDirection, target);
      if (!IsAimVectorValid(aimDirection)) {
        weapon->mUnknown174 = 0u;
        runtimeView->mOnTarget = false;
        Rotate1(true);
        Rotate2(true);
      } else {
        runtimeView->mOnTarget = Track(aimDirection, 0u);
        weapon->mAimingAt = aimDirection;
      }
    }
  } else {
    if (runtimeView->mResetTime <= 0) {
      const Wm3::Vector3f forwardDirection{0.0f, 0.0f, 1.0f};
      (void)Track(forwardDirection, kTrackingModeWorldSpace);
    } else {
      --runtimeView->mResetTime;
      Rotate1(true);
      Rotate2(true);
    }
    runtimeView->mOnTarget = false;
  }

  bool isWeaponLabelMatch = false;
  if (weapon != nullptr) {
    msvc8::string weaponLabel;
    (void)weapon->GetLabel(&weaponLabel);
    isWeaponLabelMatch = (_stricmp(weaponLabel.c_str(), runtimeView->mLabel.c_str()) == 0);
  }

  if (isWeaponLabelMatch) {
    weapon->mCanFire = runtimeView->mOnTarget ? 1u : 0u;
  }

  if (runtimeView->mOnTarget) {
    taskEvent->EventSetSignaled(true);
    return;
  }

  taskEvent->EventSetSignaled(false);
}

/**
 * Address: 0x006317B0 (FUN_006317B0, Moho::CAimManipulator::Aim)
 *
 * What it does:
 * Computes one muzzle-relative aiming direction for the current target using
 * lead prediction and optional ballistic correction paths.
 */
Wm3::Vector3f* moho::CAimManipulator::Aim(Wm3::Vector3f* const outDirection, CAiTarget* const target)
{
  auto* const baseView = AimManipulatorBaseView(this);
  auto* const runtimeView = AimManipulatorRuntimeView(this);
  UnitWeapon* const weapon = runtimeView->mWeapon.GetObjectPtr();
  RUnitBlueprintWeapon* const weaponBlueprint = (weapon != nullptr) ? weapon->mWeaponBlueprint : nullptr;

  Wm3::Vector3f aimDirection = InvalidAimVector();

  CAniPoseBone* muzzleBone = nullptr;
  if (baseView->mOwnerActor != nullptr && baseView->mOwnerActor->mPriorPose.px != nullptr) {
    CAniPose* const priorPose = baseView->mOwnerActor->mPriorPose.px;
    CAniPoseBone* const boneBegin = priorPose->mBones.begin();
    CAniPoseBone* const boneEnd = priorPose->mBones.end();
    if (boneBegin != nullptr && boneEnd != nullptr && boneBegin < boneEnd && runtimeView->mMuzzleBone >= 0) {
      const std::ptrdiff_t boneCount = boneEnd - boneBegin;
      if (runtimeView->mMuzzleBone < boneCount) {
        muzzleBone = &boneBegin[runtimeView->mMuzzleBone];
      }
    }
  }

  Unit* const unit = runtimeView->mUnit.GetObjectPtr();
  if (muzzleBone == nullptr) {
    const RUnitBlueprint* const unitBlueprint = (unit != nullptr) ? unit->GetBlueprint() : nullptr;
    const char* const unitBlueprintId = (unitBlueprint != nullptr) ? unitBlueprint->mBlueprintId.c_str() : "<null>";
    gpg::Warnf(kInvalidMuzzleBoneWarningFormat, unitBlueprintId);

    if (unit != nullptr) {
      aimDirection = ComputeUnitForwardDirection(*unit);
    }
    *outDirection = aimDirection;
    return outDirection;
  }

  const VTransform& muzzleTransform = muzzleBone->GetCompositeTransform();
  Wm3::Quaternionf muzzleOrientation = muzzleTransform.orient_;
  Wm3::Vector3f muzzlePosition = muzzleTransform.pos_;
  if (unit != nullptr && unit->IsMobile()) {
    const Wm3::Vector3f unitVelocity = unit->Entity::GetVelocity();
    muzzlePosition.x += unitVelocity.x;
    muzzlePosition.y += unitVelocity.y;
    muzzlePosition.z += unitVelocity.z;
  }

  Wm3::Vector3f targetVelocity{0.0f, 0.0f, 0.0f};
  if (target != nullptr) {
    if (Entity* const targetEntity = target->targetEntity.GetObjectPtr(); targetEntity != nullptr) {
      targetVelocity = targetEntity->GetVelocity();
    }
  }

  Wm3::Vector3f targetPosition{0.0f, 0.0f, 0.0f};
  if (target != nullptr) {
    targetPosition = target->GetTargetPosGun(false);
  }

  Wm3::Vector3f predictedImpact{
    targetPosition.x + targetVelocity.x,
    targetPosition.y + targetVelocity.y,
    targetPosition.z + targetVelocity.z,
  };

  const float horizontalDistance = std::sqrt(
    ((muzzlePosition.x - predictedImpact.x) * (muzzlePosition.x - predictedImpact.x)) +
    ((muzzlePosition.z - predictedImpact.z) * (muzzlePosition.z - predictedImpact.z))
  );

  float projectileSpeed = 0.0f;
  if (weaponBlueprint != nullptr) {
    if (weaponBlueprint->MuzzleVelocityReduceDistance <= horizontalDistance) {
      projectileSpeed = weaponBlueprint->MuzzleVelocity;
    } else {
      projectileSpeed = std::sqrt(horizontalDistance / weaponBlueprint->MuzzleVelocityReduceDistance) *
                        weaponBlueprint->MuzzleVelocity;
    }
  }

  if (weaponBlueprint != nullptr && weaponBlueprint->LeadTarget != 0u && target != nullptr &&
      target->targetType == EAiTargetType::AITARGET_Entity) {
    const Wm3::Vector3f scaledTargetVelocity{
      targetVelocity.x * kAimVelocityScale,
      targetVelocity.y * kAimVelocityScale,
      targetVelocity.z * kAimVelocityScale,
    };
    const RProjectileBlueprintPhysics* const projPhys = runtimeView->mProjPhysBlueprint;
    if (projPhys != nullptr && projPhys->TrackTarget != 0u) {
      (void)PredictInterceptPointConstantSpeed(
        &predictedImpact,
        predictedImpact,
        scaledTargetVelocity,
        projPhys->MaxSpeed,
        muzzlePosition
      );
    } else if (projPhys != nullptr && projPhys->UseGravity != 0u) {
      (void)PredictInterceptPointFromForwardVelocity(
        &predictedImpact,
        muzzleOrientation,
        projectileSpeed,
        predictedImpact,
        scaledTargetVelocity,
        muzzlePosition
      );
    } else {
      (void)PredictInterceptPointConstantSpeed(
        &predictedImpact,
        predictedImpact,
        scaledTargetVelocity,
        projectileSpeed,
        muzzlePosition
      );
    }
  }

  const RProjectileBlueprintPhysics* const projPhys = runtimeView->mProjPhysBlueprint;
  if (projPhys != nullptr && projPhys->TrackTarget == 0u && projPhys->UseGravity != 0u) {
    Sim* const sim = baseView->mOwnerSim;
    float highArc = 0.0f;
    float lowArc = 0.0f;
    if (sim != nullptr && sim->mPhysConstants != nullptr &&
        CalculateFiringPitch(&highArc, muzzlePosition, predictedImpact, *sim->mPhysConstants, projectileSpeed, &lowArc))
    {
      const float selectedArc =
        (runtimeView->mUnitWepBlueprint != nullptr && runtimeView->mUnitWepBlueprint->BallisticArc == RULEUBA_HighArc)
          ? highArc
          : lowArc;
      (void)CalculateFiringDirection(&aimDirection, predictedImpact, muzzlePosition, selectedArc);

      if (dbg_Ballistics && sim->CheatsEnabled()) {
        if (CDebugCanvas* const debugCanvas = sim->GetDebugCanvas(); debugCanvas != nullptr) {
          const Wm3::Quaternionf aimOrientation = COORDS_Orient(aimDirection);
          debugCanvas->AddWireCoords(muzzlePosition, aimOrientation, 2.0f);
          const Wm3::Quaternionf identityOrientation = Wm3::Quaternionf::Identity();
          debugCanvas->AddWireCoords(predictedImpact, identityOrientation, 2.0f);

          const Wm3::Vector3f gravityStep{
            sim->mPhysConstants->mGravity.x * kAimGravityStepScale,
            sim->mPhysConstants->mGravity.y * kAimGravityStepScale,
            sim->mPhysConstants->mGravity.z * kAimGravityStepScale,
          };
          const float velocityStep = projectileSpeed * kAimVelocityStepScale;
          debugCanvas->AddParabolaClosedForm(predictedImpact, muzzlePosition, -highArc, velocityStep, gravityStep.y);
          debugCanvas->AddParabolaClosedForm(predictedImpact, muzzlePosition, -lowArc, velocityStep, gravityStep.y);

          const Wm3::Vector3f steppedVelocity{
            aimDirection.x * velocityStep,
            aimDirection.y * velocityStep,
            aimDirection.z * velocityStep,
          };
          debugCanvas->AddParabolaStepped(steppedVelocity, muzzlePosition, predictedImpact, gravityStep);
        }
      }
    }
  } else {
    Wm3::Vector3f directionToTarget{
      predictedImpact.x - muzzlePosition.x,
      predictedImpact.y - muzzlePosition.y,
      predictedImpact.z - muzzlePosition.z,
    };
    aimDirection = directionToTarget;
    (void)Wm3::Vector3f::Normalize(&aimDirection);
  }

  *outDirection = aimDirection;
  return outDirection;
}

moho::CScrLuaMetatableFactory<moho::CAimManipulator>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

moho::CScrLuaMetatableFactory<moho::CAimManipulator>&
moho::CScrLuaMetatableFactory<moho::CAimManipulator>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00632C40 (FUN_00632C40)
 * Mangled: ?Create@?$CScrLuaMetatableFactory@VCAimManipulator@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z
 *
 * What it does:
 * Creates the `CAimManipulator` Lua metatable through
 * `SCR_CreateSimpleMetatable`.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CAimManipulator>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x00632140 (FUN_00632140, cfunc_CAimManipulatorSetFiringArc)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAimManipulatorSetFiringArcL`.
 */
int moho::cfunc_CAimManipulatorSetFiringArc(lua_State* const luaContext)
{
  return cfunc_CAimManipulatorSetFiringArcL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00632160 (FUN_00632160, func_CAimManipulatorSetFiringArc_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAimManipulator:SetFiringArc(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CAimManipulatorSetFiringArc_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCAimManipulatorSetFiringArcName,
    &moho::cfunc_CAimManipulatorSetFiringArc,
    &CScrLuaMetatableFactory<CAimManipulator>::Instance(),
    kAimManipulatorLuaClassName,
    kCAimManipulatorSetFiringArcHelpText
  );
  return &binder;
}

/**
 * Address: 0x006321C0 (FUN_006321C0, cfunc_CAimManipulatorSetFiringArcL)
 *
 * What it does:
 * Reads six angle/slew values from Lua, converts to radians/runtime units,
 * and applies them through `CAimManipulator::SetFiringArc`.
 */
int moho::cfunc_CAimManipulatorSetFiringArcL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 7) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCAimManipulatorSetFiringArcHelpText, 7, argumentCount);
  }

  const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
  CAimManipulator* const manipulator = SCR_FromLua_CAimManipulator(manipulatorObject, state);

  CAimFiringArc radiansArc{};
  float* const radiansLanes[6] = {
    &radiansArc.mMinHeading,
    &radiansArc.mMaxHeading,
    &radiansArc.mHeadingMaxSlew,
    &radiansArc.mMinPitch,
    &radiansArc.mMaxPitch,
    &radiansArc.mPitchMaxSlew,
  };

  for (int stackIndex = 2; stackIndex <= 7; ++stackIndex) {
    const LuaPlus::LuaStackObject valueArg(state, stackIndex);
    if (lua_type(rawState, stackIndex) != LUA_TNUMBER) {
      const LuaPlus::LuaObject valueObject(valueArg);
      valueObject.TypeError("number");
    }

    *radiansLanes[stackIndex - 2] = static_cast<float>(lua_tonumber(rawState, stackIndex)) * kDegreesToRadians;
  }

  CAimFiringArc runtimeArc{};
  runtimeArc.mMinHeading = radiansArc.mMinHeading;
  runtimeArc.mMaxHeading = radiansArc.mMaxHeading;
  runtimeArc.mHeadingMaxSlew = radiansArc.mHeadingMaxSlew * kSlewScale;
  runtimeArc.mMinPitch = radiansArc.mMinPitch;
  runtimeArc.mMaxPitch = radiansArc.mMaxPitch;
  runtimeArc.mPitchMaxSlew = radiansArc.mPitchMaxSlew * kSlewScale;

  manipulator->SetFiringArc(runtimeArc);
  return 0;
}

/**
 * Address: 0x00630CB0 (FUN_00630CB0, Moho::CAimManipulator::SetFiringArc)
 *
 * What it does:
 * Stores centered heading/pitch arc lanes and corresponding half-range
 * extents for runtime aiming.
 */
void moho::CAimManipulator::SetFiringArc(const CAimFiringArc arc)
{
  auto* const runtimeView = reinterpret_cast<CAimManipulatorRuntimeView*>(this);

  runtimeView->mMinHeading = NormalizeCenteredAngle(arc.mMinHeading, arc.mMaxHeading);
  runtimeView->mHeadingMaxSlew = arc.mHeadingMaxSlew;
  runtimeView->mMaxHeading = std::fabs(arc.mMaxHeading - arc.mMinHeading) * kHalfScale;

  runtimeView->mMinPitch = NormalizeCenteredAngle(arc.mMinPitch, arc.mMaxPitch);
  runtimeView->mPitchMaxSlew = arc.mPitchMaxSlew;
  runtimeView->mMaxPitch = std::fabs(arc.mMaxPitch - arc.mMinPitch) * kHalfScale;
}

/**
 * Address: 0x006309F0 (FUN_006309F0, Moho::CAimManipulator::CheckTracking)
 *
 * What it does:
 * Computes one heading/pitch tracking step against one watched pose bone,
 * clamps slew and arc lanes, and returns tracking-state bit flags.
 */
std::uint8_t moho::CAimManipulator::CheckTracking(
  const Wm3::Vector3f& targetDirection,
  CAniPoseBone* const watchBone,
  const float minAngleCenter,
  const float maxAngleHalfRange,
  const float maxAngleSlew,
  const float tolerance,
  const std::uint8_t trackingModeFlags
)
{
  if (watchBone == nullptr) {
    return 0u;
  }

  auto* const runtimeView = AimManipulatorRuntimeView(this);
  Wm3::Vector3f transformedTarget = targetDirection;

  if ((trackingModeFlags & kTrackingModeWorldSpace) == 0u) {
    const VTransform& compositeTransform = watchBone->GetCompositeTransform();
    Wm3::Quaternionf inverseOrientation{};
    inverseOrientation.w = compositeTransform.orient_.w;
    inverseOrientation.x = -compositeTransform.orient_.x;
    inverseOrientation.y = -compositeTransform.orient_.y;
    inverseOrientation.z = -compositeTransform.orient_.z;

    const Wm3::Vector3f sourceTarget = targetDirection;
    Wm3::MultiplyQuaternionVector(&transformedTarget, sourceTarget, inverseOrientation);
  }

  float desiredAngle = 0.0f;
  float* currentAngleLane = nullptr;
  if ((trackingModeFlags & kTrackingModeHeading) != 0u) {
    currentAngleLane = &runtimeView->mHeading;
    desiredAngle = std::atan2(transformedTarget.x, transformedTarget.z) + runtimeView->mHeadingOffset;
  } else {
    const float halfCenter = minAngleCenter * kHalfScale;
    Wm3::Quaternionf pitchBasis{};
    pitchBasis.w = std::cos(halfCenter);
    pitchBasis.x = std::sin(halfCenter);
    pitchBasis.y = 0.0f;
    pitchBasis.z = 0.0f;

    Wm3::Vector3f pitchSpaceTarget{};
    Wm3::MultiplyQuaternionVector(&pitchSpaceTarget, transformedTarget, pitchBasis);
    currentAngleLane = &runtimeView->mPitch;
    desiredAngle = minAngleCenter - ComputePitchRadians(pitchSpaceTarget);
  }

  const float currentAngle = *currentAngleLane;
  float laneDelta = 0.0f;
  if (maxAngleHalfRange < kAngleNormalizationClamp) {
    float constrained = NormalizeAngleRadians(desiredAngle - minAngleCenter);
    if (constrained > maxAngleHalfRange) {
      constrained = maxAngleHalfRange;
    } else if (constrained < -maxAngleHalfRange) {
      constrained = -maxAngleHalfRange;
    }
    laneDelta = (constrained + minAngleCenter) - currentAngle;
  } else {
    laneDelta = NormalizeAngleRadians(desiredAngle - currentAngle);
  }

  float step = laneDelta;
  if (std::fabs(step) > maxAngleSlew) {
    step = std::copysign(maxAngleSlew, step);
  }

  const float nextAngle = NormalizeAngleRadians(currentAngle + step);
  *currentAngleLane = nextAngle;

  std::uint8_t trackingResult = 0u;
  if ((trackingModeFlags & kTrackingModeHeading) != 0u && std::fabs(laneDelta) > kTrackingMotionEpsilon) {
    trackingResult |= kTrackingResultHeadingMotion;
  }

  const bool skipToleranceForPitchOnly =
    ((trackingModeFlags & kTrackingModePitch) != 0u) &&
    runtimeView->mUnitWepBlueprint != nullptr &&
    runtimeView->mUnitWepBlueprint->YawOnlyOnTarget != 0u;

  if (!skipToleranceForPitchOnly) {
    const float toleranceDelta = NormalizeAngleRadians(nextAngle - desiredAngle);
    if (std::fabs(toleranceDelta) > tolerance) {
      trackingResult |= kTrackingResultOutsideTolerance;
    }
  }

  return trackingResult;
}

/**
 * Address: 0x00631190 (FUN_00631190, Moho::CAimManipulator::Rotate1)
 *
 * What it does:
 * Applies first-axis (heading) bone rotation using tracked quaternion lane.
 */
void moho::CAimManipulator::Rotate1(const bool reset)
{
  auto* const runtimeView = AimManipulatorRuntimeView(this);
  CAniPoseBone* const watchBone = ResolveWatchBone(this, 0u);
  if (watchBone == nullptr) {
    return;
  }

  if (reset) {
    const float halfHeading = runtimeView->mHeading * kHalfScale;
    runtimeView->mBone0Rot.w = std::cos(halfHeading);
    runtimeView->mBone0Rot.x = 0.0f;
    runtimeView->mBone0Rot.y = std::sin(halfHeading);
    runtimeView->mBone0Rot.z = 0.0f;
  }

  watchBone->Rotate(runtimeView->mBone0Rot);
}

/**
 * Address: 0x00631220 (FUN_00631220, Moho::CAimManipulator::Rotate2)
 *
 * What it does:
 * Applies second-axis (pitch) bone rotation using tracked quaternion lane.
 */
void moho::CAimManipulator::Rotate2(const bool reset)
{
  auto* const runtimeView = AimManipulatorRuntimeView(this);
  CAniPoseBone* const watchBone = ResolveWatchBone(this, 1u);
  if (watchBone == nullptr) {
    return;
  }

  if (reset) {
    const float halfPitch = (-runtimeView->mPitch) * kHalfScale;
    runtimeView->mBone1Rot.w = std::cos(halfPitch);
    runtimeView->mBone1Rot.x = std::sin(halfPitch);
    runtimeView->mBone1Rot.y = 0.0f;
    runtimeView->mBone1Rot.z = 0.0f;
  }

  watchBone->Rotate(runtimeView->mBone1Rot);
}

/**
 * Address: 0x00630760 (FUN_00630760, Moho::CAimManipulator::Track)
 *
 * What it does:
 * Updates heading/pitch tracking lanes for one target direction and sends
 * start/stop tracking script callbacks on tracking state transitions.
 */
bool moho::CAimManipulator::Track(const Wm3::Vector3f& targetDirection, const std::uint8_t trackingModeFlags)
{
  auto* const baseView = AimManipulatorBaseView(this);
  auto* const runtimeView = AimManipulatorRuntimeView(this);
  UnitWeapon* const weapon = runtimeView->mWeapon.GetObjectPtr();
  if (weapon == nullptr) {
    return false;
  }

  float firingTolerance = weapon->mAttributes.mFiringTolerance;
  if (firingTolerance < 0.0f && weapon->mAttributes.mBlueprint != nullptr) {
    firingTolerance = weapon->mAttributes.mBlueprint->FiringTolerance;
  }
  const float toleranceRadians = firingTolerance * kFiringToleranceToRadians;

  std::uint8_t trackingResult = 0u;
  const bool useSharedBoneTracking = baseView->mWatchBones.mBegin != nullptr &&
                                     baseView->mWatchBones.mBegin[1].mBoneIndex == baseView->mWatchBones.mBegin[0].mBoneIndex &&
                                     runtimeView->mUnknownBoolE1;

  if (useSharedBoneTracking) {
    if (CAniPoseBone* const sharedBone = ResolveWatchBone(this, 0u); sharedBone != nullptr) {
      const std::uint8_t pitchResult = CheckTracking(
        targetDirection,
        sharedBone,
        runtimeView->mMinPitch,
        runtimeView->mMaxPitch,
        runtimeView->mPitchMaxSlew,
        toleranceRadians,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModePitch)
      );
      Rotate2(true);

      const std::uint8_t headingResult = CheckTracking(
        targetDirection,
        sharedBone,
        runtimeView->mMinHeading,
        runtimeView->mMaxHeading,
        runtimeView->mHeadingMaxSlew,
        toleranceRadians,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModeHeading)
      );
      Rotate1(true);
      trackingResult = static_cast<std::uint8_t>(pitchResult | headingResult);
    }
  } else {
    if (CAniPoseBone* const headingBone = ResolveWatchBone(this, 0u); headingBone != nullptr) {
      trackingResult |= CheckTracking(
        targetDirection,
        headingBone,
        runtimeView->mMinHeading,
        runtimeView->mMaxHeading,
        runtimeView->mHeadingMaxSlew,
        toleranceRadians,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModeHeading)
      );
      Rotate1(true);
    }

    if (CAniPoseBone* const pitchBone = ResolveWatchBone(this, 1u); pitchBone != nullptr) {
      trackingResult |= CheckTracking(
        targetDirection,
        pitchBone,
        runtimeView->mMinPitch,
        runtimeView->mMaxPitch,
        runtimeView->mPitchMaxSlew,
        toleranceRadians,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModePitch)
      );
      Rotate2(true);
    }
  }

  const bool onTarget = (trackingResult & kTrackingResultOutsideTolerance) == 0u;
  const bool shouldBeTracking = (trackingResult & kTrackingResultHeadingMotion) != 0u;
  if (shouldBeTracking) {
    if (!runtimeView->mIsTracking) {
      weapon->CallString("OnStartTracking", ToStdString(runtimeView->mLabel));
      runtimeView->mIsTracking = true;
    }
  } else if (runtimeView->mIsTracking) {
    weapon->CallString("OnStopTracking", ToStdString(runtimeView->mLabel));
    runtimeView->mIsTracking = false;
  }

  return onTarget;
}

/**
 * Address: 0x00632340 (FUN_00632340, cfunc_CAimManipulatorSetResetPoseTime)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAimManipulatorSetResetPoseTimeL`.
 */
int moho::cfunc_CAimManipulatorSetResetPoseTime(lua_State* const luaContext)
{
  return cfunc_CAimManipulatorSetResetPoseTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00632360 (FUN_00632360, func_CAimManipulatorSetResetPoseTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAimManipulator:SetResetPoseTime(resetTime)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CAimManipulatorSetResetPoseTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCAimManipulatorSetResetPoseTimeName,
    &moho::cfunc_CAimManipulatorSetResetPoseTime,
    &CScrLuaMetatableFactory<CAimManipulator>::Instance(),
    kAimManipulatorLuaClassName,
    kCAimManipulatorSetResetPoseTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006323C0 (FUN_006323C0, cfunc_CAimManipulatorSetResetPoseTimeL)
 *
 * What it does:
 * Resolves one `CAimManipulator*` and stores reset-pose time in simulation
 * ticks (`seconds * 10`).
 */
int moho::cfunc_CAimManipulatorSetResetPoseTimeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kCAimManipulatorSetResetPoseTimeHelpText,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
  CAimManipulator* const manipulator = SCR_FromLua_CAimManipulator(manipulatorObject, state);

  const LuaPlus::LuaStackObject resetTimeArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    resetTimeArg.TypeError("number");
  }

  auto* const runtimeView = reinterpret_cast<CAimManipulatorRuntimeView*>(manipulator);
  runtimeView->mResetPoseTime = static_cast<int>(lua_tonumber(rawState, 2) * 10.0);
  return 0;
}

/**
 * Address: 0x006324B0 (FUN_006324B0, cfunc_CAimManipulatorOnTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAimManipulatorOnTargetL`.
 */
int moho::cfunc_CAimManipulatorOnTarget(lua_State* const luaContext)
{
  return cfunc_CAimManipulatorOnTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006324D0 (FUN_006324D0, func_CAimManipulatorOnTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAimManipulator:OnTarget()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CAimManipulatorOnTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCAimManipulatorOnTargetName,
    &moho::cfunc_CAimManipulatorOnTarget,
    &CScrLuaMetatableFactory<CAimManipulator>::Instance(),
    kAimManipulatorLuaClassName,
    kCAimManipulatorOnTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x00632530 (FUN_00632530, cfunc_CAimManipulatorOnTargetL)
 *
 * What it does:
 * Resolves one `CAimManipulator*` and returns its on-target flag to Lua.
 */
int moho::cfunc_CAimManipulatorOnTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCAimManipulatorOnTargetHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CAimManipulator* const manipulator = moho::SCR_FromLua_CAimManipulator(manipObject, state);

  const auto* const runtimeView = reinterpret_cast<const CAimManipulatorRuntimeView*>(manipulator);
  lua_pushboolean(rawState, runtimeView->mOnTarget ? 1 : 0);
  lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006325F0 (FUN_006325F0, cfunc_CAimManipulatorSetEnabled)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAimManipulatorSetEnabledL`.
 */
int moho::cfunc_CAimManipulatorSetEnabled(lua_State* const luaContext)
{
  return cfunc_CAimManipulatorSetEnabledL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00632610 (FUN_00632610, func_CAimManipulatorSetEnabled_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAimManipulator:SetEnabled(flag)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CAimManipulatorSetEnabled_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCAimManipulatorSetEnabledName,
    &moho::cfunc_CAimManipulatorSetEnabled,
    &CScrLuaMetatableFactory<CAimManipulator>::Instance(),
    kAimManipulatorLuaClassName,
    kCAimManipulatorSetEnabledHelpText
  );
  return &binder;
}

/**
 * Address: 0x00632670 (FUN_00632670, cfunc_CAimManipulatorSetEnabledL)
 *
 * What it does:
 * Resolves one `CAimManipulator*`, writes enabled state, and clears the
 * on-target latch.
 */
int moho::cfunc_CAimManipulatorSetEnabledL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCAimManipulatorSetEnabledHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CAimManipulator* const manipulator = moho::SCR_FromLua_CAimManipulator(manipObject, state);

  const LuaPlus::LuaStackObject enabledArg(state, 2);
  auto* const runtimeView = reinterpret_cast<CAimManipulatorRuntimeView*>(manipulator);
  runtimeView->mEnabled = enabledArg.GetBoolean();
  runtimeView->mOnTarget = false;
  return 0;
}

/**
 * Address: 0x00632730 (FUN_00632730, cfunc_CAimManipulatorGetHeadingPitch)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAimManipulatorGetHeadingPitchL`.
 */
int moho::cfunc_CAimManipulatorGetHeadingPitch(lua_State* const luaContext)
{
  return cfunc_CAimManipulatorGetHeadingPitchL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00632750 (FUN_00632750, func_CAimManipulatorGetHeadingPitch_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAimManipulator:GetHeadingPitch()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CAimManipulatorGetHeadingPitch_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCAimManipulatorGetHeadingPitchName,
    &moho::cfunc_CAimManipulatorGetHeadingPitch,
    &CScrLuaMetatableFactory<CAimManipulator>::Instance(),
    kAimManipulatorLuaClassName,
    kCAimManipulatorGetHeadingPitchHelpText
  );
  return &binder;
}

/**
 * Address: 0x006327B0 (FUN_006327B0, cfunc_CAimManipulatorGetHeadingPitchL)
 *
 * What it does:
 * Resolves one `CAimManipulator*` and pushes heading/pitch to Lua.
 */
int moho::cfunc_CAimManipulatorGetHeadingPitchL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCAimManipulatorGetHeadingPitchHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CAimManipulator* const manipulator = moho::SCR_FromLua_CAimManipulator(manipObject, state);

  const auto* const runtimeView = reinterpret_cast<const CAimManipulatorRuntimeView*>(manipulator);
  lua_pushnumber(rawState, runtimeView->mHeading);
  lua_gettop(rawState);
  lua_pushnumber(rawState, runtimeView->mPitch);
  lua_gettop(rawState);
  return 2;
}

/**
 * Address: 0x00632890 (FUN_00632890, cfunc_CAimManipulatorSetHeadingPitch)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAimManipulatorSetHeadingPitchL`.
 */
int moho::cfunc_CAimManipulatorSetHeadingPitch(lua_State* const luaContext)
{
  return cfunc_CAimManipulatorSetHeadingPitchL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006328B0 (FUN_006328B0, func_CAimManipulatorSetHeadingPitch_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAimManipulator:SetHeadingPitch(heading, pitch)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CAimManipulatorSetHeadingPitch_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCAimManipulatorSetHeadingPitchName,
    &moho::cfunc_CAimManipulatorSetHeadingPitch,
    &CScrLuaMetatableFactory<CAimManipulator>::Instance(),
    kAimManipulatorLuaClassName,
    kCAimManipulatorSetHeadingPitchHelpText
  );
  return &binder;
}

/**
 * Address: 0x00632910 (FUN_00632910, cfunc_CAimManipulatorSetHeadingPitchL)
 *
 * What it does:
 * Validates Lua args `(self, heading, pitch)`, resolves one
 * `CAimManipulator*`, and writes heading/pitch lanes.
 */
int moho::cfunc_CAimManipulatorSetHeadingPitchL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCAimManipulatorSetHeadingPitchHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CAimManipulator* const manipulator = moho::SCR_FromLua_CAimManipulator(manipObject, state);

  const LuaPlus::LuaStackObject pitchArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    pitchArg.TypeError("number");
  }
  const float pitch = static_cast<float>(lua_tonumber(rawState, 3));

  const LuaPlus::LuaStackObject headingArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    headingArg.TypeError("number");
  }
  const float heading = static_cast<float>(lua_tonumber(rawState, 2));

  auto* const runtimeView = reinterpret_cast<CAimManipulatorRuntimeView*>(manipulator);
  runtimeView->mHeading = heading;
  runtimeView->mPitch = pitch;
  return 0;
}

/**
 * Address: 0x00632A40 (FUN_00632A40, cfunc_CAimManipulatorSetAimHeadingOffset)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAimManipulatorSetAimHeadingOffsetL`.
 */
int moho::cfunc_CAimManipulatorSetAimHeadingOffset(lua_State* const luaContext)
{
  return cfunc_CAimManipulatorSetAimHeadingOffsetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00632A60 (FUN_00632A60, func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAimManipulator:SetAimHeadingOffset(offset)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCAimManipulatorSetAimHeadingOffsetName,
    &moho::cfunc_CAimManipulatorSetAimHeadingOffset,
    &CScrLuaMetatableFactory<CAimManipulator>::Instance(),
    kAimManipulatorLuaClassName,
    kCAimManipulatorSetAimHeadingOffsetHelpText
  );
  return &binder;
}

/**
 * Address: 0x00632AC0 (FUN_00632AC0, cfunc_CAimManipulatorSetAimHeadingOffsetL)
 *
 * What it does:
 * Resolves one `CAimManipulator*` and stores heading-offset radians.
 */
int moho::cfunc_CAimManipulatorSetAimHeadingOffsetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kCAimManipulatorSetAimHeadingOffsetHelpText,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject manipObject(LuaPlus::LuaStackObject(state, 1));
  CAimManipulator* const manipulator = moho::SCR_FromLua_CAimManipulator(manipObject, state);

  const LuaPlus::LuaStackObject headingOffsetArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    headingOffsetArg.TypeError("number");
  }

  auto* const runtimeView = reinterpret_cast<CAimManipulatorRuntimeView*>(manipulator);
  runtimeView->mHeadingOffset = static_cast<float>(lua_tonumber(rawState, 2)) * kDegreesToRadians;
  return 0;
}

/**
 * Address: 0x00633730 (FUN_00633730, Moho::CAimManipulator::MemberDeserialize)
 *
 * What it does:
 * Loads serialized `CAimManipulator` member lanes from archive state.
 */
void moho::CAimManipulator::MemberDeserialize(CAimManipulator* const object, gpg::ReadArchive* const archive)
{
  if (object == nullptr || archive == nullptr) {
    return;
  }

  auto* const runtimeView = reinterpret_cast<CAimManipulatorRuntimeView*>(object);
  const gpg::RRef ownerRef = NullOwnerRef();

  archive->Read(CachedIAniManipulatorType(), object, ownerRef);
  archive->Read(CachedWeakPtrUnitType(), &runtimeView->mUnit, ownerRef);
  archive->Read(CachedWeakPtrUnitWeaponType(), &runtimeView->mWeapon, ownerRef);
  archive->ReadString(&runtimeView->mLabel);

  archive->ReadPointer_RUnitBlueprintWeapon(&runtimeView->mUnitWepBlueprint, &ownerRef);

  if (UnitWeapon* const weapon = runtimeView->mWeapon.GetObjectPtr(); weapon != nullptr) {
    RProjectileBlueprint* projectileBlueprint = weapon->mProjectileBlueprint;
    archive->ReadPointer_RProjectileBlueprint(&projectileBlueprint, &ownerRef);
    if (projectileBlueprint != nullptr) {
      runtimeView->mProjPhysBlueprint = &projectileBlueprint->Physics;
    }
  }

  archive->ReadBool(&runtimeView->mEnabled);
  archive->ReadFloat(&runtimeView->mHeading);
  archive->ReadFloat(&runtimeView->mPitch);
  archive->ReadInt(&runtimeView->mMuzzleBone);
  archive->ReadBool(&runtimeView->mIsTracking);
  archive->ReadFloat(&runtimeView->mMinHeading);
  archive->ReadFloat(&runtimeView->mMaxHeading);
  archive->ReadFloat(&runtimeView->mHeadingMaxSlew);
  archive->ReadFloat(&runtimeView->mMinPitch);
  archive->ReadFloat(&runtimeView->mMaxPitch);
  archive->ReadFloat(&runtimeView->mPitchMaxSlew);
  archive->ReadBool(&runtimeView->mOnTarget);
  archive->ReadBool(&runtimeView->mUnknownBoolE1);
  archive->ReadInt(&runtimeView->mResetPoseTime);
  archive->ReadInt(&runtimeView->mResetTime);
  archive->Read(CachedQuaternionfType(), &runtimeView->mBone0Rot, ownerRef);
  archive->Read(CachedQuaternionfType(), &runtimeView->mBone1Rot, ownerRef);
  archive->ReadFloat(&runtimeView->mHeadingOffset);
}

/**
 * Address: 0x006339D0 (FUN_006339D0, Moho::CAimManipulator::MemberSerialize)
 *
 * What it does:
 * Saves serialized `CAimManipulator` member lanes into archive state.
 */
void moho::CAimManipulator::MemberSerialize(const CAimManipulator* const object, gpg::WriteArchive* const archive)
{
  if (object == nullptr || archive == nullptr) {
    return;
  }

  auto* const runtimeView = const_cast<CAimManipulatorRuntimeView*>(
    reinterpret_cast<const CAimManipulatorRuntimeView*>(object)
  );
  const gpg::RRef ownerRef = NullOwnerRef();

  archive->Write(CachedIAniManipulatorType(), object, ownerRef);
  archive->Write(CachedWeakPtrUnitType(), &runtimeView->mUnit, ownerRef);
  archive->Write(CachedWeakPtrUnitWeaponType(), &runtimeView->mWeapon, ownerRef);
  archive->WriteString(&runtimeView->mLabel);

  gpg::RRef unitWeaponBlueprintRef{};
  gpg::RRef_RUnitBlueprintWeapon(&unitWeaponBlueprintRef, runtimeView->mUnitWepBlueprint);
  gpg::WriteRawPointer(archive, unitWeaponBlueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);

  if (UnitWeapon* const weapon = runtimeView->mWeapon.GetObjectPtr(); weapon != nullptr) {
    RProjectileBlueprint* const projectileBlueprint = weapon->mProjectileBlueprint;
    gpg::RRef projectileBlueprintRef{};
    gpg::RRef_RProjectileBlueprint(&projectileBlueprintRef, projectileBlueprint);
    gpg::WriteRawPointer(archive, projectileBlueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);
    if (projectileBlueprint != nullptr) {
      runtimeView->mProjPhysBlueprint = &projectileBlueprint->Physics;
    }
  }

  archive->WriteBool(runtimeView->mEnabled);
  archive->WriteFloat(runtimeView->mHeading);
  archive->WriteFloat(runtimeView->mPitch);
  archive->WriteInt(runtimeView->mMuzzleBone);
  archive->WriteBool(runtimeView->mIsTracking);
  archive->WriteFloat(runtimeView->mMinHeading);
  archive->WriteFloat(runtimeView->mMaxHeading);
  archive->WriteFloat(runtimeView->mHeadingMaxSlew);
  archive->WriteFloat(runtimeView->mMinPitch);
  archive->WriteFloat(runtimeView->mMaxPitch);
  archive->WriteFloat(runtimeView->mPitchMaxSlew);
  archive->WriteBool(runtimeView->mOnTarget);
  archive->WriteBool(runtimeView->mUnknownBoolE1);
  archive->WriteInt(runtimeView->mResetPoseTime);
  archive->WriteInt(runtimeView->mResetTime);
  archive->Write(CachedQuaternionfType(), &runtimeView->mBone0Rot, ownerRef);
  archive->Write(CachedQuaternionfType(), &runtimeView->mBone1Rot, ownerRef);
  archive->WriteFloat(runtimeView->mHeadingOffset);
}

namespace gpg
{
  /**
   * Address: 0x00633580 (FUN_00633580, gpg::RRef_CAimManipulator)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CAimManipulator*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CAimManipulator(gpg::RRef* const outRef, moho::CAimManipulator* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCAimManipulatorType());
    return outRef;
  }
} // namespace gpg
