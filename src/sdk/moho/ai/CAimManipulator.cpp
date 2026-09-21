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
#include "moho/animation/CAniSkel.h"
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
#include "moho/sim/ManipulatorLuaFunctionThunks.h"
#include "moho/task/CTaskEvent.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"

namespace moho
{
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
  Wm3::Quaternionf ConjugateQuat(const Wm3::Quaternionf& q) noexcept;
}

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


  // ---------------------------------------------------------------------
  // The helpers below carry no `Address:` block on purpose: the binary has no
  // out-of-line body for them, because every call site inlined them. The two
  // big bodies in this file are where they went -- `Aim` is 1896 bytes / 468
  // instructions at 0x006317B0 and `ManipulatorUpdate` 989 / 284 at
  // 0x00630DB0. Enumerating every function the binary places in this
  // translation unit's address run (0x0062FC00..0x00634400, 124 of them)
  // accounts for all of them without a candidate for any helper here, so
  // their absence is a fact about the binary rather than a missing
  // annotation.
  //
  // `CachedCAimManipulatorType` is the exception that proves it: it *is* a
  // real body, emitted twice, but both copies already carry their address on
  // the methods that are nothing but this body --
  // `CAimManipulator::StaticGetClass` (0x0062FDF0) and
  // `CAimManipulator::GetClass` (0x0062FE10), each 28 bytes / 8 instructions
  // reading the cache at 0x010C7390 and passing the type descriptor at
  // 0x00F71B3C to `gpg::LookupRType` (0x008E0750).
  // ---------------------------------------------------------------------

  [[nodiscard]] gpg::RType* CachedCAimManipulatorType()
  {
    gpg::RType* type = moho::CAimManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAimManipulator));
      moho::CAimManipulator::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00632C20 (FUN_00632C20)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `IAniManipulator`,
   * reading the cache at 0x010C738C and passing the type descriptor at
   * 0x00F71B60 to `gpg::LookupRType` (0x008E0750).
   *
   * One emission per translation unit that needs it. This is this file's
   * copy: 0x00632C20 sits inside `CAimManipulator`'s own COMDAT run, between
   * `Moho::runtime` glue at 0x00632C10 and this class's Lua metatable factory
   * `Create` at 0x00632C40. The other two copies of the same body are
   * `IAniManipulator::StaticGetClass` (0x0062FC10) and the virtual
   * `IAniManipulator::GetClass` (0x0062FC30). No caller calls any of them --
   * `GetClass` goes through the vtable and the reflection paths inlined the
   * rest.
   */
  [[nodiscard]] gpg::RType* CachedIAniManipulatorType()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00633540 (FUN_00633540)
   *
   * What it does:
   * Upcasts one reflected reference lane to `moho::CAimManipulator*`.
   */
  [[maybe_unused]] [[nodiscard]] void* TryUpcastCAimManipulatorRefObject(gpg::RRef* const sourceRef)
  {
    if (!sourceRef) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(*sourceRef, CachedCAimManipulatorType());
    return upcast.mObj;
  }

  /**
   * Address: 0x00633CD0 (FUN_00633CD0)
   *
   * What it does:
   * Reads one archive object lane using cached `IAniManipulator` reflection
   * type metadata.
   */
  [[maybe_unused]] [[nodiscard]] gpg::ReadArchive* ReadIAniManipulatorArchiveObjectLane(
    gpg::ReadArchive* const archive,
    void* const objectStorage,
    gpg::RRef* const ownerRef
  )
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Read(CachedIAniManipulatorType(), objectStorage, owner);
    return archive;
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
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("Sim");
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
    if (manipulator->mWatchBones.begin() == nullptr) {
      return nullptr;
    }

    return ResolvePoseBone(manipulator->mOwnerActor, manipulator->mWatchBones[watchIndex].mBoneIndex);
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
      ((transform.orient_.y * transform.orient_.z) - (transform.orient_.w * transform.orient_.x)) * 2.0f;
    direction.x =
      ((transform.orient_.x * transform.orient_.z) + (transform.orient_.w * transform.orient_.y)) * 2.0f;
    direction.z =
      1.0f - (((transform.orient_.x * transform.orient_.x) + (transform.orient_.y * transform.orient_.y)) * 2.0f);
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
      1.0f - (((muzzleOrientation.x * muzzleOrientation.x) + (muzzleOrientation.y * muzzleOrientation.y)) * 2.0f);
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
   *
   * DETERMINISM NOTE -- deliberate divergence from the binary, shared by every
   * `std::sin`/`std::cos`/`std::atan2` in this file's sim paths
   * (`CalculateFiringPitch` 0x005D6310, `CheckTracking` 0x006309F0,
   * `RotateHeadingBone` 0x00631190, `RotatePitchBone` 0x00631220).
   *
   * The binary computes these with the x87 transcendental instructions -- this
   * function is `fcos` at 0x005D644F and `fsin` at 0x005D647E, and the
   * `CAimManipulator` rotations are the same pair. Those instructions are NOT
   * exactly specified by IEEE 754: their low-order bits are implementation
   * defined, and AMD and Intel genuinely disagree (Intel's `fsin` argument
   * reduction uses a 66-bit pi and is badly wrong near multiples of pi, where
   * AMD's is not). The engine's `_controlfp(_PC_24, _MCW_PC)` rounds results to
   * a 24-bit mantissa, which hides almost all of that -- which is exactly why a
   * lockstep match normally survives for hours before anything shows.
   *
   * MEASURED, AND IT IS NOT A LIVE DESYNC VECTOR -- recorded here because it
   * looks like one and will be re-proposed otherwise. Under `_PC_24`, x87
   * `fsin`/`fcos` were compared against the correctly-rounded reference over
   * ~1.4M *distinct* float values: 320,008 consecutive floats spanning 1*pi
   * through 8*pi (where Intel's reduction is worst), 917,504 sampled
   * exhaustively across exponent bands 2^0..2^7, and 160,004 around odd
   * multiples of pi/2 for `cos`. Deviation was **zero ulp everywhere**. At
   * 24-bit precision these instructions are correctly rounded, so any CPU
   * accurate to better than half a float-ulp produces the identical `float` and
   * the vendor difference cannot be observed. Note the earlier sweep that
   * "confirmed" a difference was bogus: it stepped a `double` by 1e-8 and cast
   * to `float`, so millions of samples collapsed onto a handful of distinct
   * floats.
   *
   * So `_PC_24` is doing real work -- it is what makes the x87 transcendentals
   * safe for lockstep, not merely tidy. That is the reason to keep it.
   *
   * `std::sin`/`std::cos` here do NOT lower to `fsin`/`fcos`; on the modern
   * toolchain they call the CRT's SSE2 software implementations, which are
   * vendor independent. So this recovery is deterministic across CPUs where the
   * binary was not -- but it is correspondingly NOT bit-identical to the binary
   * for these calls. That trade is intentional: the two properties cannot both
   * hold, and a lockstep simulation is worth more than matching a defect. Do
   * not "restore fidelity" by reaching for `fsin`/`fcos` inline asm.
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
 * Address: 0x006300F0 (FUN_006300F0, ??0CAimManipulator@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes weak owner links, label/runtime defaults, tracking state, and
 * identity quaternions for both watched aim bones.
 */
moho::CAimManipulator::CAimManipulator()
{
  this->mUnit.ClearLinkState();
  this->mWeapon.ClearLinkState();

  this->mLabel.clear();
  this->mUnitWepBlueprint = nullptr;
  this->mProjPhysBlueprint = nullptr;
  this->mEnabled = false;
  this->mMuzzleBone = 0;
  this->mIsTracking = false;
  this->mOnTarget = false;
  this->mUnknownBoolE1 = false;
  this->mResetPoseTime = 0;
  this->mResetTime = 0;
  this->mHeading = 0.0f;
  this->mPitch = 0.0f;
  this->mMinHeading = 0.0f;
  this->mMaxHeading = 0.0f;
  this->mHeadingMaxSlew = 0.0f;
  this->mMinPitch = 0.0f;
  this->mMaxPitch = 0.0f;
  this->mPitchMaxSlew = 0.0f;

  this->mHeadingRot.w = 1.0f;
  this->mHeadingRot.x = 0.0f;
  this->mHeadingRot.y = 0.0f;
  this->mHeadingRot.z = 0.0f;

  this->mPitchRot.w = 1.0f;
  this->mPitchRot.x = 0.0f;
  this->mPitchRot.y = 0.0f;
  this->mPitchRot.z = 0.0f;

  this->mHeadingOffset = 0.0f;
}

/**
 * Address: 0x00630220 (FUN_00630220, ??0CAimManipulator@Moho@@QAE@PAVUnitWeapon@1@PAVSim@1@PBDIHH@Z)
 *
 * IDA signature:
 * Moho::CAimManipulator *__thiscall Moho::CAimManipulator::CAimManipulator(
 *     Moho::UnitWeapon *weapon, Moho::CAimManipulator *this, Moho::Sim *sim,
 *     const char *label, unsigned int boneA, int boneB, int boneMuzzle);
 *
 * What it does:
 * Builds one aim manipulator bound to `{weapon, sim}`: constructs the
 * `IAniManipulator` base on the weapon owner's actor, head-inserts intrusive weak
 * links to the owning unit and weapon, seeds label/arc/tracking/quaternion
 * defaults, resolves the projectile physics sub-blueprint, materializes the Lua
 * script object, registers the two watched aim bones, and seeds the heading arc
 * from the turret bone's local orientation.
 */
moho::CAimManipulator::CAimManipulator(
  UnitWeapon* const weapon,
  Sim* const sim,
  const char* const label,
  const std::uint32_t boneA,
  const std::int32_t boneB,
  const std::int32_t boneMuzzle
)
  : IAniManipulator(sim, weapon->mUnit->AniActor, 0)
{
  Unit* const ownerUnit = weapon->mUnit;


  // Head-insert the intrusive weak links (owning unit + weapon). Both nodes are
  // freshly constructed and known-unlinked, so bind-then-head-insert mirrors the
  // binary's open-coded list insert (no prior-link scan).
  (void)new (static_cast<void*>(&this->mUnit)) moho::WeakPtr<moho::Unit>();
  this->mUnit.BindObjectUnlinked(ownerUnit);
  (void)this->mUnit.LinkIntoOwnerChainHeadUnlinked();

  (void)new (static_cast<void*>(&this->mWeapon)) moho::WeakPtr<moho::UnitWeapon>();
  this->mWeapon.BindObjectUnlinked(weapon);
  (void)this->mWeapon.LinkIntoOwnerChainHeadUnlinked();

  // Label.
  (void)new (static_cast<void*>(&this->mLabel)) msvc8::string(label, std::strlen(label));

  // Field defaults (firing arc, tracking state, identity bone quaternions).
  this->mMaxHeading = 3.1415927f;
  this->mHeadingMaxSlew = 0.062831849f;
  this->mMinPitch = 15.0f;
  this->mMaxPitch = 30.0f;
  this->mPitchMaxSlew = 0.061086524f;
  this->mUnitWepBlueprint = weapon->mWeaponBlueprint;
  this->mProjPhysBlueprint = nullptr;
  this->mEnabled = true;
  this->mHeading = 0.0f;
  this->mPitch = 0.0f;
  this->mIsTracking = false;
  this->mMinHeading = 0.0f;
  this->mOnTarget = false;
  this->mUnknownBoolE1 = false;
  this->mResetPoseTime = 0;
  this->mResetTime = 0;
  this->mHeadingRot.w = 1.0f;
  this->mHeadingRot.x = 0.0f;
  this->mHeadingRot.y = 0.0f;
  this->mHeadingRot.z = 0.0f;
  this->mPitchRot.w = 1.0f;
  this->mPitchRot.x = 0.0f;
  this->mPitchRot.y = 0.0f;
  this->mPitchRot.z = 0.0f;
  this->mHeadingOffset = 0.0f;

  // Materialize the Lua script object through the CAimManipulator metatable
  // factory (FUN_00633050).
  {
    LuaPlus::LuaObject scriptContext3{};
    LuaPlus::LuaObject scriptContext2{};
    LuaPlus::LuaObject scriptContext1{};
    LuaPlus::LuaObject metatableObject{};
    (void)func_CreateLuaAimManipulatorObject(&metatableObject, sim != nullptr ? sim->mLuaState : nullptr);
    this->CreateLuaObject(metatableObject, scriptContext1, scriptContext2, scriptContext3);
  }

  // Resolve the projectile physics sub-blueprint from the weapon's projectile
  // blueprint (typed navigation of the binary's weapon->blueprint->physics chain).
  if (RProjectileBlueprint* const projectileBlueprint = weapon->mProjectileBlueprint; projectileBlueprint != nullptr) {
    this->mProjPhysBlueprint = &projectileBlueprint->Physics;
  }

  // Read the owner actor skeleton (RAII shared_ptr; released at scope end).
  const boost::shared_ptr<const CAniSkel> skeleton = ownerUnit->AniActor->GetSkeleton();
  const CAniSkel* const skel = skeleton.get();

  // Register the two watched aim bones, then pick the muzzle bone (muzzle, then
  // barrel, then turret in priority order).
  (void)this->AddWatchBone(static_cast<int>(boneA));
  (void)this->AddWatchBone(boneB);

  std::int32_t muzzleBone = boneMuzzle;
  if (boneMuzzle < 0) {
    muzzleBone = boneB;
    if (boneB < 0) {
      muzzleBone = static_cast<std::int32_t>(boneA);
    }
  }
  this->mMuzzleBone = muzzleBone;

  // Seed the heading arc from the turret (boneA) bone local orientation quaternion.
  const SAniSkelBone* const bonesBegin = skel != nullptr ? skel->mBones.begin() : nullptr;
  if (bonesBegin != nullptr) {
    const std::size_t boneCount = static_cast<std::size_t>(skel->mBones.end() - bonesBegin);
    if (boneA < boneCount) {
      const SAniSkelBone& bone = bonesBegin[boneA];
      const Wm3::Quaternionf& ori = bone.mBoneTransform.orient_;

      const RUnitBlueprintWeapon* const weaponBlueprint = this->mUnitWepBlueprint;
      this->mMinHeading =
        std::atan2(
          ((ori.w * ori.y) + (ori.x * ori.z)) * 2.0f,
          1.0f - (((ori.x * ori.x) + (ori.y * ori.y)) * 2.0f)
        )
        + weaponBlueprint->HeadingArcCenter * kDegreesToRadians;
      this->mMaxHeading = weaponBlueprint->HeadingArcRange * kDegreesToRadians;

      if (std::fabs(((ori.w * ori.z) - (ori.y * ori.x)) * 2.0f) > 0.70700002f) {
        this->mUnknownBoolE1 = true;
      }
    }
  }

  // Clear the weapon's can-fire latch, then drop the task-event signal so a
  // freshly built manipulator is not already signalled to anything waiting on
  // it (`mov byte [eax+0xF0], bl` / `mov byte [ebp+4], bl`, 0x00630677).
  weapon->SetCanFire(false);
  this->EventSetSignaled(false);
}

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
 * Address: 0x006306A0 (FUN_006306A0, Moho::CAniManipulator::~CAniManipulator)
 *
 * What it does:
 * Clears weak owner links and label storage before running
 * `IAniManipulator` base teardown.
 */
moho::CAimManipulator::~CAimManipulator()
{
  if (UnitWeapon* const weapon = this->mWeapon.GetObjectPtr(); weapon != nullptr) {
    weapon->SetCanFire(true);
  }

  // 0x006306D3 is `mov byte [edi+4], 0` -- offset 0x04 is `CTaskEvent::
  // mTriggered`, reached as `EventSetSignaled(false)` (its false path at
  // 0x00406E17 is exactly this one store). The destructor has no store to
  // 0x4C at all, so the `IAniManipulator::mEnabled = false` that used to
  // stand here was both a write the binary never makes and a dropped
  // de-signal: anything still parked on this manipulator's event stayed
  // latched as the object died.
  this->EventSetSignaled(false);

  // `mLabel` is a real member now, so the compiler emits `~msvc8::string`
  // after this body -- the same teardown the binary runs, and the one the
  // 2007 source never wrote down. Tidying it here as well would release the
  // storage twice.
  this->mWeapon.UnlinkFromOwnerChain();
  this->mUnit.UnlinkFromOwnerChain();

  // IAniManipulator is now a real base, so its destructor runs automatically
  // via ordinary base-destructor chaining after this body returns - calling
  // it explicitly here would destroy it twice.
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
 * Address: 0x00630DB0 (FUN_00630DB0, IDA `Moho::CAimManipulator::MoveManipulator`)
 *
 * VFTable SLOT: 1 of `??_7CAimManipulator@Moho@@6B@` -- the same slot
 * `CAnimationManipulator::ManipulatorUpdate` (0x0063FDD0) occupies in its own
 * vtable, which is why IDA gives both bodies the name `MoveManipulator`.
 * Declaring this as a fresh virtual instead of an override left the slot
 * holding `IAniManipulator::ManipulatorUpdate`, so `CAniActor::UpdateManipulators`
 * never ran the aim update: turrets never tracked, and every weapon fired along
 * the hull's facing instead of at its target.
 *
 * The binary leaves the return value undefined (0x0063118C returns with eax
 * holding whatever the last computation left), and the sole call site --
 * 0x0063AB29 in CAniActor::UpdateManipulators -- discards it, so this reports
 * no frame change.
 *
 * What it does:
 * Executes one manipulator update: validates owner/weapon state, drives aim
 * target tracking, mirrors on-target state into weapon lanes, and updates
 * task-event signaling.
 */
bool moho::CAimManipulator::ManipulatorUpdate()
{
  Unit* const unit = this->mUnit.GetObjectPtr();
  if (unit == nullptr) {
    return false;
  }

  if (unit->IsBeingBuilt()) {
    return false;
  }

  const bool aimsStraightOnDisable =
    this->mUnitWepBlueprint != nullptr && this->mUnitWepBlueprint->AimsStraightOnDisable != 0u;
  if (!this->mEnabled && !aimsStraightOnDisable) {
    return false;
  }

  UnitWeapon* const weapon = this->mWeapon.GetObjectPtr();
  if (weapon == nullptr || unit->IsDead() || unit->StunnedState != 0) {
    this->mOnTarget = false;
    if (CAniPoseBone* const watchBone0 = ResolveWatchBone(this, 0u); watchBone0 != nullptr) {
      watchBone0->Rotate(this->mHeadingRot);
    }
    if (CAniPoseBone* const watchBone1 = ResolveWatchBone(this, 1u); watchBone1 != nullptr) {
      watchBone1->Rotate(this->mPitchRot);
    }
    this->EventSetSignaled(false);
    return false;
  }

  weapon->SetAimReachable(true);
  weapon->SetAimingAt(InvalidAimVector());

  const bool shouldTrackTarget = this->mEnabled || !aimsStraightOnDisable;
  CAiTarget* const target = &weapon->mTarget;
  if (target->targetType != EAiTargetType::AITARGET_None && shouldTrackTarget) {
    if (!target->HasTarget()) {
      this->mOnTarget = false;
      RotateHeadingBone(true);
      RotatePitchBone(true);
    } else {
      if (this->mResetPoseTime <= 0) {
        std::int32_t resetTime = 1;
        if (weapon->mWeaponBlueprint != nullptr) {
          resetTime = static_cast<std::int32_t>(std::lround(weapon->mWeaponBlueprint->TargetCheckInterval * 10.0f));
          if (resetTime < 1) {
            resetTime = 1;
          }
        }
        this->mResetTime = resetTime;
      } else {
        this->mResetTime = this->mResetPoseTime;
      }

      Wm3::Vector3f aimDirection{};
      (void)Aim(&aimDirection, target);
      if (!IsAimVectorValid(aimDirection)) {
        weapon->SetAimReachable(false);
        this->mOnTarget = false;
        RotateHeadingBone(true);
        RotatePitchBone(true);
      } else {
        this->mOnTarget = Track(aimDirection, 0u);
        weapon->SetAimingAt(aimDirection);
      }
    }
  } else {
    if (this->mResetTime <= 0) {
      const Wm3::Vector3f forwardDirection{0.0f, 0.0f, 1.0f};
      (void)Track(forwardDirection, kTrackingModeWorldSpace);
    } else {
      --this->mResetTime;
      RotateHeadingBone(true);
      RotatePitchBone(true);
    }
    this->mOnTarget = false;
  }

  bool isWeaponLabelMatch = false;
  if (weapon != nullptr) {
    msvc8::string weaponLabel;
    (void)weapon->GetLabel(&weaponLabel);
    isWeaponLabelMatch = (_stricmp(weaponLabel.c_str(), this->mLabel.c_str()) == 0);
  }

  if (isWeaponLabelMatch) {
    weapon->SetCanFire(this->mOnTarget);
  }

  if (this->mOnTarget) {
    this->EventSetSignaled(true);
    return false;
  }

  this->EventSetSignaled(false);
  return false;
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
  UnitWeapon* const weapon = this->mWeapon.GetObjectPtr();
  RUnitBlueprintWeapon* const weaponBlueprint = (weapon != nullptr) ? weapon->mWeaponBlueprint : nullptr;

  Wm3::Vector3f aimDirection = InvalidAimVector();

  CAniPoseBone* muzzleBone = nullptr;
  if (this->mOwnerActor != nullptr && this->mOwnerActor->mPriorPose.px != nullptr) {
    CAniPose* const priorPose = this->mOwnerActor->mPriorPose.px;
    CAniPoseBone* const boneBegin = priorPose->mBones.begin();
    CAniPoseBone* const boneEnd = priorPose->mBones.end();
    if (boneBegin != nullptr && boneEnd != nullptr && boneBegin < boneEnd && this->mMuzzleBone >= 0) {
      const std::ptrdiff_t boneCount = boneEnd - boneBegin;
      if (this->mMuzzleBone < boneCount) {
        muzzleBone = &boneBegin[this->mMuzzleBone];
      }
    }
  }

  Unit* const unit = this->mUnit.GetObjectPtr();
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
    const RProjectileBlueprintPhysics* const projPhys = this->mProjPhysBlueprint;
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

  const RProjectileBlueprintPhysics* const projPhys = this->mProjPhysBlueprint;
  if (projPhys != nullptr && projPhys->TrackTarget == 0u && projPhys->UseGravity != 0u) {
    Sim* const sim = this->mOwnerSim;
    float highArc = 0.0f;
    float lowArc = 0.0f;
    if (sim != nullptr && sim->mPhysConstants != nullptr &&
        CalculateFiringPitch(&highArc, muzzlePosition, predictedImpact, *sim->mPhysConstants, projectileSpeed, &lowArc))
    {
      const float selectedArc =
        (this->mUnitWepBlueprint != nullptr && this->mUnitWepBlueprint->BallisticArc == RULEUBA_HighArc)
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

  this->mMinHeading = NormalizeCenteredAngle(arc.mMinHeading, arc.mMaxHeading);
  this->mHeadingMaxSlew = arc.mHeadingMaxSlew;
  this->mMaxHeading = std::fabs(arc.mMaxHeading - arc.mMinHeading) * kHalfScale;

  this->mMinPitch = NormalizeCenteredAngle(arc.mMinPitch, arc.mMaxPitch);
  this->mPitchMaxSlew = arc.mPitchMaxSlew;
  this->mMaxPitch = std::fabs(arc.mMaxPitch - arc.mMinPitch) * kHalfScale;
}

/**
 * Address: 0x006309F0 (FUN_006309F0, Moho::CAimManipulator::CheckTracking)
 *
 * What it does:
 * Computes one heading/pitch tracking step against one watched pose bone,
 * clamps slew and arc lanes, and returns tracking-state bit flags.
 *
 * Rotates via `Moho::MultQuadVec`, not `Wm3::MultiplyQuaternionVector` - that
 * part of the earlier recovery was right and is unchanged.
 *
 * Both quaternions here are ordinary scalar-first ones. The conjugate at
 * 0x00630A2D..0x00630A41 keeps lane 0 and negates lanes 1-3, and the
 * pitch-basis quaternion at 0x00630ADC..0x00630AF0 is written `(cos, sin, 0,
 * 0)` - a rotation about X. A prior revision recorded both as scalar-first,
 * citing `QuatToMatrix`/`MultQuadVec`; those have since been read off their
 * own disassembly and are scalar-first too.
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

  Wm3::Vector3f transformedTarget = targetDirection;

  if ((trackingModeFlags & kTrackingModeWorldSpace) == 0u) {
    const VTransform& compositeTransform = watchBone->GetCompositeTransform();
    // 0x00630A2D copies lane 0 verbatim (`movss xmm3, [eax]`) and 0x00630A34/
    // 0x00630A3C/0x00630A41 subtract lanes 1-3 from the zero constant
    // `dword_E4F748`: the ordinary scalar-first conjugate, same as
    // `VTransform::Inverse` (0x0046FBF0).
    const Wm3::Quaternionf inverseOrientation = ConjugateQuat(compositeTransform.orient_);

    const Wm3::Vector3f sourceTarget = targetDirection;
    MultQuadVec(&transformedTarget, &sourceTarget, &inverseOrientation);
  }

  float desiredAngle = 0.0f;
  float* currentAngleLane = nullptr;
  if ((trackingModeFlags & kTrackingModeHeading) != 0u) {
    currentAngleLane = &this->mHeading;
    desiredAngle = std::atan2(transformedTarget.x, transformedTarget.z) + this->mHeadingOffset;
  } else {
    const float halfCenter = minAngleCenter * kHalfScale;
    // The four consecutive stack floats handed to `MultQuadVec` as the
    // quaternion are written as `(cos, sin, 0, 0)`: 0x00630ADC/0x00630AE4 zero
    // the last two lanes, 0x00630AE2 `fcos` stores lane 0 and 0x00630AEE
    // `fsin` stores lane 1. Scalar-first, so this is a rotation about X.
    Wm3::Quaternionf pitchBasis{};
    pitchBasis.w = std::cos(halfCenter);
    pitchBasis.x = std::sin(halfCenter);
    pitchBasis.y = 0.0f;
    pitchBasis.z = 0.0f;

    Wm3::Vector3f pitchSpaceTarget{};
    MultQuadVec(&pitchSpaceTarget, &transformedTarget, &pitchBasis);
    currentAngleLane = &this->mPitch;
    // 0x00630B04 calls `Moho::COORDS_Pitch(Wm3::Vector3<float> const&)` (0x0050B710),
    // which returns `acos(y/|v|) - pi/2` -- the NEGATED elevation. A local
    // `atan2(y, hypot(x, z))` re-implementation stood here and returned `+asin(y/|v|)`
    // instead, so every gun mirrored its pitch: aiming at a target below the muzzle
    // elevated the barrel by the same angle, and the shot left along the reflected
    // direction. `CBuilderArmManipulator` (0x0063632E) carried the same duplicate.
    desiredAngle = minAngleCenter - moho::COORDS_Pitch(pitchSpaceTarget);
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
    this->mUnitWepBlueprint != nullptr &&
    this->mUnitWepBlueprint->YawOnlyOnTarget != 0u;

  if (!skipToleranceForPitchOnly) {
    const float toleranceDelta = NormalizeAngleRadians(nextAngle - desiredAngle);
    if (std::fabs(toleranceDelta) > tolerance) {
      trackingResult |= kTrackingResultOutsideTolerance;
    }
  }

  return trackingResult;
}

/**
 * Address: 0x00631190 (FUN_00631190, labelled `Moho::CAimManipulator::Rotate1`
 * in the lost IDA database -- an annotation, not a symbol; this image has no
 * function names in it at all)
 *
 * What it does:
 * Turns watched bone 0 -- the turret -- to the tracked heading, about the Y
 * axis. The FPU sequence at 0x006311CD..0x00631202 is `fld [mHeading]`,
 * `fmul 0.5`, then `fcos`/`fsin` stored to +0xEC and +0xF4 with +0xF0 and
 * +0xF8 zeroed, i.e. `{cos(h/2), 0, sin(h/2), 0}` over a `{w,x,y,z}`
 * quaternion.
 */
void moho::CAimManipulator::RotateHeadingBone(const bool recomputeFromAngle)
{
  CAniPoseBone* const watchBone = ResolveWatchBone(this, 0u);
  if (watchBone == nullptr) {
    return;
  }

  if (recomputeFromAngle) {
    const float halfHeading = this->mHeading * kHalfScale;
    this->mHeadingRot.w = std::cos(halfHeading);
    this->mHeadingRot.x = 0.0f;
    this->mHeadingRot.y = std::sin(halfHeading);
    this->mHeadingRot.z = 0.0f;
  }

  watchBone->Rotate(this->mHeadingRot);
}

/**
 * Address: 0x00631220 (FUN_00631220, labelled `Moho::CAimManipulator::Rotate2`
 * in the lost IDA database -- likewise an annotation, not a symbol)
 *
 * What it does:
 * Turns watched bone 1 -- the barrel -- to the tracked pitch, about the X
 * axis, negating `mPitch` because the bone's X axis runs opposite to the sign
 * convention the pitch lane is tracked in.
 */
void moho::CAimManipulator::RotatePitchBone(const bool recomputeFromAngle)
{
  CAniPoseBone* const watchBone = ResolveWatchBone(this, 1u);
  if (watchBone == nullptr) {
    return;
  }

  if (recomputeFromAngle) {
    const float halfPitch = (-this->mPitch) * kHalfScale;
    this->mPitchRot.w = std::cos(halfPitch);
    this->mPitchRot.x = std::sin(halfPitch);
    this->mPitchRot.y = 0.0f;
    this->mPitchRot.z = 0.0f;
  }

  watchBone->Rotate(this->mPitchRot);
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
  UnitWeapon* const weapon = this->mWeapon.GetObjectPtr();
  if (weapon == nullptr) {
    return false;
  }

  float firingTolerance = weapon->mAttributes.mFiringTolerance;
  if (firingTolerance < 0.0f && weapon->mAttributes.mBlueprint != nullptr) {
    firingTolerance = weapon->mAttributes.mBlueprint->FiringTolerance;
  }
  const float toleranceRadians = firingTolerance * kFiringToleranceToRadians;

  std::uint8_t trackingResult = 0u;
  const bool useSharedBoneTracking = this->mWatchBones.begin() != nullptr &&
                                     this->mWatchBones[1].mBoneIndex == this->mWatchBones[0].mBoneIndex &&
                                     this->mUnknownBoolE1;

  if (useSharedBoneTracking) {
    if (CAniPoseBone* const sharedBone = ResolveWatchBone(this, 0u); sharedBone != nullptr) {
      const std::uint8_t pitchResult = CheckTracking(
        targetDirection,
        sharedBone,
        this->mMinPitch,
        this->mMaxPitch,
        this->mPitchMaxSlew,
        toleranceRadians,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModePitch)
      );
      RotatePitchBone(true);

      const std::uint8_t headingResult = CheckTracking(
        targetDirection,
        sharedBone,
        this->mMinHeading,
        this->mMaxHeading,
        this->mHeadingMaxSlew,
        toleranceRadians,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModeHeading)
      );
      RotateHeadingBone(true);
      trackingResult = static_cast<std::uint8_t>(pitchResult | headingResult);
    }
  } else {
    if (CAniPoseBone* const headingBone = ResolveWatchBone(this, 0u); headingBone != nullptr) {
      trackingResult |= CheckTracking(
        targetDirection,
        headingBone,
        this->mMinHeading,
        this->mMaxHeading,
        this->mHeadingMaxSlew,
        toleranceRadians,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModeHeading)
      );
      RotateHeadingBone(true);
    }

    if (CAniPoseBone* const pitchBone = ResolveWatchBone(this, 1u); pitchBone != nullptr) {
      trackingResult |= CheckTracking(
        targetDirection,
        pitchBone,
        this->mMinPitch,
        this->mMaxPitch,
        this->mPitchMaxSlew,
        toleranceRadians,
        static_cast<std::uint8_t>(trackingModeFlags | kTrackingModePitch)
      );
      RotatePitchBone(true);
    }
  }

  const bool onTarget = (trackingResult & kTrackingResultOutsideTolerance) == 0u;
  const bool shouldBeTracking = (trackingResult & kTrackingResultHeadingMotion) != 0u;
  if (shouldBeTracking) {
    if (!this->mIsTracking) {
      weapon->CallString("OnStartTracking", ToStdString(this->mLabel));
      this->mIsTracking = true;
    }
  } else if (this->mIsTracking) {
    weapon->CallString("OnStopTracking", ToStdString(this->mLabel));
    this->mIsTracking = false;
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

  manipulator->SetResetPoseTime(static_cast<std::int32_t>(lua_tonumber(rawState, 2) * 10.0));
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

  lua_pushboolean(rawState, manipulator->OnTarget() ? 1 : 0);
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
  manipulator->SetEnabled(enabledArg.GetBoolean());
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

  lua_pushnumber(rawState, manipulator->GetHeading());
  lua_gettop(rawState);
  lua_pushnumber(rawState, manipulator->GetPitch());
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

  manipulator->SetHeadingPitch(heading, pitch);
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

  const float headingOffsetDegrees = static_cast<float>(lua_tonumber(rawState, 2));
  manipulator->SetAimHeadingOffset(headingOffsetDegrees);
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

  const gpg::RRef ownerRef = NullOwnerRef();

  archive->Read(CachedIAniManipulatorType(), object, ownerRef);
  archive->Read(CachedWeakPtrUnitType(), &object->mUnit, ownerRef);
  archive->Read(CachedWeakPtrUnitWeaponType(), &object->mWeapon, ownerRef);
  archive->ReadString(&object->mLabel);

  archive->ReadPointer_RUnitBlueprintWeapon(&object->mUnitWepBlueprint, &ownerRef);

  if (UnitWeapon* const weapon = object->mWeapon.GetObjectPtr(); weapon != nullptr) {
    RProjectileBlueprint* projectileBlueprint = weapon->mProjectileBlueprint;
    archive->ReadPointer_RProjectileBlueprint(&projectileBlueprint, &ownerRef);
    if (projectileBlueprint != nullptr) {
      object->mProjPhysBlueprint = &projectileBlueprint->Physics;
    }
  }

  archive->ReadBool(&object->mEnabled);
  archive->ReadFloat(&object->mHeading);
  archive->ReadFloat(&object->mPitch);
  archive->ReadInt(&object->mMuzzleBone);
  archive->ReadBool(&object->mIsTracking);
  archive->ReadFloat(&object->mMinHeading);
  archive->ReadFloat(&object->mMaxHeading);
  archive->ReadFloat(&object->mHeadingMaxSlew);
  archive->ReadFloat(&object->mMinPitch);
  archive->ReadFloat(&object->mMaxPitch);
  archive->ReadFloat(&object->mPitchMaxSlew);
  archive->ReadBool(&object->mOnTarget);
  archive->ReadBool(&object->mUnknownBoolE1);
  archive->ReadInt(&object->mResetPoseTime);
  archive->ReadInt(&object->mResetTime);
  archive->Read(CachedQuaternionfType(), &object->mHeadingRot, ownerRef);
  archive->Read(CachedQuaternionfType(), &object->mPitchRot, ownerRef);
  archive->ReadFloat(&object->mHeadingOffset);
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

  const gpg::RRef ownerRef = NullOwnerRef();

  // The save path is declared const by the reflection contract but is not one:
  // the binary hands `mLabel` to the non-const `WriteString` and refreshes
  // `mProjPhysBlueprint` from the weapon's current projectile blueprint before
  // writing it out. Name that aliasing once here instead of casting per site.
  CAimManipulator* const self = const_cast<CAimManipulator*>(object);

  archive->Write(CachedIAniManipulatorType(), object, ownerRef);
  archive->Write(CachedWeakPtrUnitType(), &object->mUnit, ownerRef);
  archive->Write(CachedWeakPtrUnitWeaponType(), &object->mWeapon, ownerRef);
  archive->WriteString(&self->mLabel);

  gpg::RRef unitWeaponBlueprintRef{};
  gpg::RRef_RUnitBlueprintWeapon(&unitWeaponBlueprintRef, object->mUnitWepBlueprint);
  gpg::WriteRawPointer(archive, unitWeaponBlueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);

  if (UnitWeapon* const weapon = object->mWeapon.GetObjectPtr(); weapon != nullptr) {
    RProjectileBlueprint* const projectileBlueprint = weapon->mProjectileBlueprint;
    gpg::RRef projectileBlueprintRef{};
    gpg::RRef_RProjectileBlueprint(&projectileBlueprintRef, projectileBlueprint);
    gpg::WriteRawPointer(archive, projectileBlueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);
    if (projectileBlueprint != nullptr) {
      self->mProjPhysBlueprint = &projectileBlueprint->Physics;
    }
  }

  archive->WriteBool(object->mEnabled);
  archive->WriteFloat(object->mHeading);
  archive->WriteFloat(object->mPitch);
  archive->WriteInt(object->mMuzzleBone);
  archive->WriteBool(object->mIsTracking);
  archive->WriteFloat(object->mMinHeading);
  archive->WriteFloat(object->mMaxHeading);
  archive->WriteFloat(object->mHeadingMaxSlew);
  archive->WriteFloat(object->mMinPitch);
  archive->WriteFloat(object->mMaxPitch);
  archive->WriteFloat(object->mPitchMaxSlew);
  archive->WriteBool(object->mOnTarget);
  archive->WriteBool(object->mUnknownBoolE1);
  archive->WriteInt(object->mResetPoseTime);
  archive->WriteInt(object->mResetTime);
  archive->Write(CachedQuaternionfType(), &object->mHeadingRot, ownerRef);
  archive->Write(CachedQuaternionfType(), &object->mPitchRot, ownerRef);
  archive->WriteFloat(object->mHeadingOffset);
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

  /**
   * Address: 0x006333C0 (FUN_006333C0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CAimManipulator` and
   * copies object/type fields into the destination reference record.
   */
  [[maybe_unused]] gpg::RRef* AssignCAimManipulatorRef(gpg::RRef* const outRef, moho::CAimManipulator* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef tmp{};
    (void)RRef_CAimManipulator(&tmp, value);
    outRef->mObj = tmp.mObj;
    outRef->mType = tmp.mType;
    return outRef;
  }
} // namespace gpg

namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct CAimManipulatorLuaFuncDefBootstrap
  {
    CAimManipulatorLuaFuncDefBootstrap()
    {
      (void)::moho::func_CAimManipulatorSetFiringArc_LuaFuncDef();
      (void)::moho::func_CAimManipulatorSetResetPoseTime_LuaFuncDef();
      (void)::moho::func_CAimManipulatorOnTarget_LuaFuncDef();
      (void)::moho::func_CAimManipulatorSetEnabled_LuaFuncDef();
      (void)::moho::func_CAimManipulatorGetHeadingPitch_LuaFuncDef();
      (void)::moho::func_CAimManipulatorSetHeadingPitch_LuaFuncDef();
      (void)::moho::func_CAimManipulatorSetAimHeadingOffset_LuaFuncDef();
    }
  };

  const CAimManipulatorLuaFuncDefBootstrap gCAimManipulatorLuaFuncDefBootstrap{};
} // namespace
