#include "moho/ai/CAiPathSpline.h"

#include "moho/ai/IFormationInstance.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/misc/Stats.h"
#include "moho/misc/WeakPtr.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/utils/Logging.h"
#include "moho/math/Vector3f.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"

using namespace moho;

namespace
{
  using CollisionLinkWeakUnit = WeakPtr<IUnit>;
  constexpr float kDegreesToSteeringRadiansPerTick = 0.0017453292f;
  constexpr float kSpeedScalePerTick = 0.1f;
  constexpr float kAccelerationScalePerTick = 0.0099999998f;
  constexpr float kTurnSinePolyA = 0.0076100002f;
  constexpr float kTurnSinePolyB = 0.16605f;
  constexpr float kTurnVectorUnitTolerance = 0.001f;

  static_assert(sizeof(CollisionLinkWeakUnit) == sizeof(SCollisionLink), "SCollisionLink/WeakPtr<IUnit> layout mismatch");
  static_assert(
    offsetof(CollisionLinkWeakUnit, ownerLinkSlot) == offsetof(SCollisionLink, mUnitIntrusiveSlot),
    "SCollisionLink::mUnitIntrusiveSlot owner slot mismatch"
  );
  static_assert(
    offsetof(CollisionLinkWeakUnit, nextInOwner) == offsetof(SCollisionLink, mNextInUnitChain),
    "SCollisionLink::mNextInUnitChain next slot mismatch"
  );

  [[nodiscard]] CollisionLinkWeakUnit& AsCollisionWeakLink(SCollisionLink& link) noexcept
  {
    return *reinterpret_cast<CollisionLinkWeakUnit*>(&link);
  }

  [[nodiscard]] const CollisionLinkWeakUnit& AsCollisionWeakLink(const SCollisionLink& link) noexcept
  {
    return *reinterpret_cast<const CollisionLinkWeakUnit*>(&link);
  }
} // namespace

/**
 * Address: 0x006990E0 (FUN_006990E0, ??0struct_SteeringParams@@QAE@@Z)
 */
SteeringParams::SteeringParams(
  Unit* const unit,
  const Wm3::Vector3f& sourcePosition,
  const Wm3::Vector3f& destinationPosition,
  const Wm3::Vector3f& forwardVector,
  const float speedLimit,
  const bool skipDynamicLimits
) noexcept
  : mMaxSpeed(0.0f)
  , mMaxReverseSpeed(0.0f)
  , mMaxAcceleration(0.0f)
  , mMaxBrake(0.0f)
  , mMaxSteer(0.0f)
  , mInvTurnRadius(0.0f)
  , mTurnRate(0.0f)
  , mTurnFacingRate(0.0f)
  , mDeltaX(destinationPosition.x - sourcePosition.x)
  , mDeltaZ(-(destinationPosition.z - sourcePosition.z))
  , mForwardXZ{forwardVector.x, -forwardVector.z}
  , mDistance(0.0f)
  , mDistanceSq(0.0f)
  , mRotateOnSpot(0u)
  , mRotateOnSpotThreshold(0.0f)
{
  mDistanceSq = (mDeltaX * mDeltaX) + (mDeltaZ * mDeltaZ);
  mDistance = std::sqrt(mDistanceSq);
  (void)mForwardXZ.Normalize();

  if (unit == nullptr) {
    return;
  }

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  if (blueprint == nullptr) {
    return;
  }

  const UnitAttributes& attributes = unit->GetAttributes();
  const float turnMult = attributes.turnMult;
  const RUnitBlueprintPhysics& physics = blueprint->Physics;

  mTurnRate = (physics.TurnRate * turnMult) * kDegreesToSteeringRadiansPerTick;
  mTurnFacingRate = (physics.TurnFacingRate * turnMult) * kDegreesToSteeringRadiansPerTick;

  if (skipDynamicLimits) {
    return;
  }

  const float speedMult = attributes.moveSpeedMult;
  const float accMult = attributes.accelerationMult;

  float maxSpeed = physics.MaxSpeed;
  if (speedLimit <= maxSpeed) {
    maxSpeed = speedLimit;
  }
  mMaxSpeed = (maxSpeed * speedMult) * kSpeedScalePerTick;

  float maxReverseSpeed = physics.MaxSpeedReverse;
  if (speedLimit <= maxReverseSpeed) {
    maxReverseSpeed = speedLimit;
  }
  mMaxReverseSpeed = (maxReverseSpeed * speedMult) * kSpeedScalePerTick;

  float maxAcceleration = (physics.MaxAcceleration * accMult) * kAccelerationScalePerTick;
  mMaxAcceleration = maxAcceleration;

  if (physics.MaxBrake != 0.0f) {
    maxAcceleration = (physics.MaxBrake * accMult) * kAccelerationScalePerTick;
  }
  mMaxBrake = maxAcceleration;

  if (physics.MaxSteerForce != 0.0f) {
    mMaxSteer = (physics.MaxSteerForce * accMult) * kAccelerationScalePerTick;
  } else {
    mMaxSteer = mMaxAcceleration;
  }

  if (physics.TurnRadius == 0.0f) {
    mInvTurnRadius = std::numeric_limits<float>::infinity();
  } else {
    mInvTurnRadius = physics.TurnRadius / turnMult;
  }

  mRotateOnSpot = physics.RotateOnSpot;
  mRotateOnSpotThreshold = physics.RotateOnSpotThreshold;
}

/**
 * Address: 0x006990B0 (FUN_006990B0)
 *
 * What it does:
 * Register-shape adapter that placement-constructs one `SteeringParams`
 * object with dynamic limits enabled.
 */
[[maybe_unused]] SteeringParams* ConstructSteeringParamsAdapter(
  const Wm3::Vector3f* const sourcePosition,
  const Wm3::Vector3f* const destinationPosition,
  const Wm3::Vector3f* const forwardVector,
  SteeringParams* const outParams,
  Unit* const unit,
  const float speedLimit
) noexcept
{
  ::new (outParams) SteeringParams(
    unit,
    *sourcePosition,
    *destinationPosition,
    *forwardVector,
    speedLimit,
    false
  );
  return outParams;
}

namespace moho
{
/**
 * Address: 0x00698FF0 (FUN_00698FF0)
 */
SteeringParams BuildSteeringParamsFromTransform(
  Unit* const unit,
  const VTransform& transform,
  const Wm3::Vector3f& destination
) noexcept
{
  const Wm3::Quaternionf& q = transform.orient_;
  Wm3::Vector3f forward{};
  forward.x = ((q.x * q.z) + (q.w * q.y)) * 2.0f;
  forward.y = ((q.y * q.z) - (q.w * q.x)) * 2.0f;
  forward.z = 1.0f - (((q.x * q.x) + (q.y * q.y)) * 2.0f);

  Wm3::Vector3f source{};
  source.x = transform.pos_.x;
  source.y = 0.0f;
  source.z = transform.pos_.z;

  return SteeringParams(unit, source, destination, forward, 0.0f, true);
}
} // namespace moho

/**
 * Address: 0x00698F40 (FUN_00698F40)
 *
 * What it does:
 * Normalizes one input 2D direction lane into caller-owned output storage.
 */
[[maybe_unused]] Wm3::Vector2f* NormalizeDirection2DUnchecked(
  Wm3::Vector2f* const outDirection,
  const Wm3::Vector2f* const inputDirection
) noexcept
{
  const float x = inputDirection->x;
  const float y = inputDirection->y;
  const float invLength = 1.0f / std::sqrt((x * x) + (y * y));
  outDirection->x = x * invLength;
  outDirection->y = y * invLength;
  return outDirection;
}

/**
 * Address: 0x00699500 (FUN_00699500)
 *
 * What it does:
 * Applies one steering blend/clamp lane to a 3D direction vector, preserving
 * orientation while enforcing a maximum magnitude cap.
 */
[[maybe_unused]] void BlendAndClampDirection3D(
  const Wm3::Vector3f* const blendDirection,
  Wm3::Vector3f* const inOutDirection,
  const float maxMagnitude
) noexcept
{
  const float lengthSq =
    (inOutDirection->x * inOutDirection->x) +
    (inOutDirection->y * inOutDirection->y) +
    (inOutDirection->z * inOutDirection->z);

  if (lengthSq <= (maxMagnitude * maxMagnitude)) {
    return;
  }

  const float deltaLength = std::sqrt(lengthSq) - maxMagnitude;
  inOutDirection->x = ((blendDirection->x * deltaLength) + maxMagnitude) * inOutDirection->x;
  inOutDirection->y = ((blendDirection->y * deltaLength) + maxMagnitude) * inOutDirection->y;
  inOutDirection->z = ((blendDirection->z * deltaLength) + maxMagnitude) * inOutDirection->z;

  const float adjustedLengthSq =
    (inOutDirection->x * inOutDirection->x) +
    (inOutDirection->y * inOutDirection->y) +
    (inOutDirection->z * inOutDirection->z);
  const float normalizeScale = maxMagnitude / std::sqrt(adjustedLengthSq);

  inOutDirection->x *= normalizeScale;
  inOutDirection->y *= normalizeScale;
  inOutDirection->z *= normalizeScale;
}

/**
 * Address: 0x00699760 (FUN_00699760)
 *
 * What it does:
 * Computes one steering speed cap from `SteeringParams` by combining
 * rotate-on-spot gating, heading-alignment tests, and turn-radius limits.
 */
float ComputeSteeringSpeedCapFromParams(
  const SteeringParams* const params,
  const float distanceGate
) noexcept
{
  constexpr float kHeadingAlignmentThreshold = 0.98000002f;
  constexpr float kHalfScale = 0.5f;

  if (params->mRotateOnSpot != 0u && params->mRotateOnSpotThreshold > distanceGate) {
    const float deltaX = params->mDeltaX;
    const float deltaZ = params->mDeltaZ;
    const float inverseLength = 1.0f / std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));

    const float headingAlignment =
      (params->mForwardXZ.y * (deltaZ * inverseLength)) +
      (params->mForwardXZ.x * (deltaX * inverseLength));
    if (headingAlignment < kHeadingAlignmentThreshold) {
      return 0.0f;
    }

    return params->mMaxSpeed;
  }

  const float crossLane =
    (params->mDeltaZ * params->mForwardXZ.x) -
    (params->mForwardXZ.y * params->mDeltaX);
  const float turnScale = (crossLane == 0.0f)
    ? 0.0f
    : (params->mDistanceSq * kHalfScale) / crossLane;

  const float radiusLimit = params->mInvTurnRadius;
  const float absTurnScale = std::fabs(turnScale);
  if (absTurnScale < radiusLimit) {
    if (absTurnScale == 0.0f) {
      return params->mMaxSpeed;
    }

    return (params->mTurnRate * absTurnScale) * kHalfScale;
  }

  if (radiusLimit < 0.0f) {
    return 0.0f;
  }

  return radiusLimit;
}

namespace moho
{
/**
 * Address: 0x006992C0 (FUN_006992C0)
 */
Wm3::Vector2f* RotateDirectionTowardTargetLimited(
  Wm3::Vector2f* const outDirection,
  float maxTurnRadians,
  const float sourceX,
  const float sourceZ,
  const float targetX,
  const float targetZ
) noexcept
{
  if (maxTurnRadians >= 3.1415927f) {
    maxTurnRadians = 3.1415927f;
  }

  const float sourceLength = std::sqrt((sourceX * sourceX) + (sourceZ * sourceZ));
  const float targetLength = std::sqrt((targetX * targetX) + (targetZ * targetZ));
  const float lengthProduct = sourceLength * targetLength;
  const float maxTurnCos = std::cos(maxTurnRadians);

  if (lengthProduct == 0.0f) {
    outDirection->x = sourceX;
    outDirection->y = sourceZ;
    return outDirection;
  }

  const float dot = (targetZ * sourceZ) + (targetX * sourceX);
  if (dot >= (maxTurnCos * lengthProduct)) {
    const float scale = sourceLength / targetLength;
    outDirection->x = targetX * scale;
    outDirection->y = targetZ * scale;
    return outDirection;
  }

  const float cross = (targetZ * sourceX) - (sourceZ * targetX);
  const float maxTurnSq = maxTurnRadians * maxTurnRadians;
  float turnSin =
    (((maxTurnSq * kTurnSinePolyA) - kTurnSinePolyB) * maxTurnSq + 1.0f) * maxTurnRadians;
  if (cross < 0.0f) {
    turnSin = -turnSin;
  }

  Wm3::Vector2f turnVector{maxTurnCos, turnSin};
  if (std::fabs((turnSin * turnSin + maxTurnCos * maxTurnCos) - 1.0f) > kTurnVectorUnitTolerance) {
    (void)turnVector.Normalize();
  }

  const float rotatedZ = (turnVector.x * sourceZ) + (turnVector.y * sourceX);
  outDirection->x = (turnVector.x * sourceX) - (turnVector.y * sourceZ);
  outDirection->y = rotatedZ;
  return outDirection;
}
} // namespace moho

namespace moho
{
/**
 * Address: 0x00699940 (FUN_00699940)
 */
Wm3::Quaternionf*
BuildHeadingQuaternionFromDirection2D(const Wm3::Vector2f* const direction, Wm3::Quaternionf* const outOrientation) noexcept
{
  const float directionX = direction ? direction->x : 0.0f;
  const float negDirectionY = direction ? -direction->y : 0.0f;

  Wm3::Vector3f matrixRows[3]{};
  matrixRows[0].x = negDirectionY;
  matrixRows[0].y = 0.0f;
  matrixRows[0].z = -directionX;
  matrixRows[1].x = 0.0f;
  matrixRows[1].y = 1.0f;
  matrixRows[1].z = 0.0f;
  matrixRows[2].x = directionX;
  matrixRows[2].y = 0.0f;
  matrixRows[2].z = negDirectionY;

  Wm3::Quaternionf temp{};
  (void)moho::MatrixToQuat(matrixRows, &temp);
  *outOrientation = temp;
  return outOrientation;
}
} // namespace moho

Unit* SCollisionLink::ResolveUnitFromIntrusiveSlot() const noexcept
{
  if (IUnit* const iunit = AsCollisionWeakLink(*this).GetObjectPtr()) {
    return iunit->IsUnit();
  }
  return nullptr;
}

void** SCollisionLink::GetIntrusiveSlotAddress() const noexcept
{
  return reinterpret_cast<void**>(AsCollisionWeakLink(*this).ownerLinkSlot);
}

bool SCollisionLink::HasLinkedUnit() const noexcept
{
  return AsCollisionWeakLink(*this).HasValue();
}

void SCollisionLink::AssignUnit(Unit* const unit) noexcept
{
  AsCollisionWeakLink(*this).ResetFromObject(static_cast<IUnit*>(unit));
}

void SCollisionLink::ClearLink() noexcept
{
  AsCollisionWeakLink(*this).ResetFromOwnerLinkSlot(nullptr);
}

namespace
{
  void RemoveFromIntrusiveCollisionChain(SCollisionInfo& info)
  {
    auto& weakLink = AsCollisionWeakLink(info.mUnit);
    weakLink.UnlinkFromOwnerChain();
    weakLink.ClearLinkState();
  }
} // namespace

gpg::RType* CAiPathSpline::sType = nullptr;
gpg::RType* SContinueInfo::sType = nullptr;
gpg::RType* CPathPoint::sType = nullptr;

namespace
{
  class FastVectorCPathPointTypeInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x005B5990 (FUN_005B5990)
     * Demangled: gpg::RFastVectorType_CPathPoint::dtr (scalar-deleting)
     *
     * What it does:
     * Frees the `RType` base's two `msvc8::vector<RField>` storage lanes
     * (`bases_._Myfirst` @ +0x2C, `fields_._Myfirst` @ +0x3C), restores the
     * `gpg::RObject` vftable, and conditionally deletes `this`. Defaulted in
     * source: the compiler-generated `~RType()` reproduces this behavior,
     * identical shape to `RVectorType<moho::SimArmy*>::~RVectorType()`
     * (Reflection.h) and `RVectorType<moho::SPointVector>::~RVectorType()`
     * (SPointVector.h). Vtable-confirmed:
     * `??_7?$RFastVectorType@VCPathPoint@Moho@@@gpg@@6B@+0x8` writes this
     * address; the class has no declared destructor otherwise, so this is
     * an explicit declaration purely to carry the address citation (the
     * implicit destructor already produces the same base-chaining behavior).
     */
    ~FastVectorCPathPointTypeInfo() override = default;

    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    /**
     * Address: 0x005B4AD0 (FUN_005B4AD0, gpg::RFastVectorType_CPathPoint::SetCount)
     *
     * What it does:
     * Resizes one reflected `fastvector<CPathPoint>` lane and fills new slots
     * with zero vectors plus `PPS_7` state.
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(FastVectorCPathPointTypeInfo) == 0x68, "FastVectorCPathPointTypeInfo size must be 0x68");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ECollisionType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ECollisionType@Moho@@H@gpg'`):
   * `FUN_00BCBD70` (real, `__xc_a`-reachable, sole ctor-shaped writer for
   * this global's storage). A separate `gpg::SerSaveLoadHelper<
   * Moho::ECollisionType>` writer, `FUN_00598440`, shares no storage with
   * this global and is itself zero-xref/unreachable -- same "dead
   * sibling-writer" pattern documented for other enums on the
   * `PrimitiveSerHelper` template (see `Reflection.h`); already correctly
   * classified `skip` in the progress DB.
   *
   * Confirmed via raw asm: the real ctor default-constructs
   * `gpg::SerHelperBase`, binds `mDeserialize`/`mSerialize` to
   * `FUN_00598400`/`FUN_00598420`, installs the
   * `PrimitiveSerHelper<ECollisionType,int>` vtable, and explicitly
   * registers `atexit(&sub_BF6520)` -- confirmed bare unlink-then-self-link
   * shape matching `SerHelperBase::ResetLinks()` -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed. Two
   * zero-xref duplicate emissions of that same unlink logic
   * (`FUN_005966D0`, `FUN_00596700`) are already correctly marked `skip`.
   *
   * Previously modeled as its own hand-rolled `SerHelperBase`-derived class
   * (correctly identifying the real ctor/vtable, but not actually reusing
   * the shared template, so its compiled vtable identity would diverge from
   * the binary's real `?$PrimitiveSerHelper@W4ECollisionType@Moho@@H@gpg`
   * symbol). Collapsed into the canonical template alias.
   */
  using ECollisionTypePrimitiveSerializer = gpg::PrimitiveSerHelper<ECollisionType, int>;
} // namespace

namespace
{
  alignas(moho::SCollisionInfoTypeInfo)
    unsigned char gSCollisionInfoTypeInfoStorage[sizeof(moho::SCollisionInfoTypeInfo)] = {};
  bool gSCollisionInfoTypeInfoConstructed = false;

  alignas(moho::ECollisionTypeTypeInfo)
    unsigned char gECollisionTypeTypeInfoStorage[sizeof(moho::ECollisionTypeTypeInfo)] = {};
  bool gECollisionTypeTypeInfoConstructed = false;

  alignas(moho::EPathPointStateTypeInfo)
    unsigned char gEPathPointStateTypeInfoStorage[sizeof(moho::EPathPointStateTypeInfo)] = {};
  bool gEPathPointStateTypeInfoConstructed = false;

  alignas(moho::CPathPointTypeInfo) unsigned char gCPathPointTypeInfoStorage[sizeof(moho::CPathPointTypeInfo)] = {};
  bool gCPathPointTypeInfoConstructed = false;
  alignas(FastVectorCPathPointTypeInfo)
    unsigned char gFastVectorCPathPointTypeStorage[sizeof(FastVectorCPathPointTypeInfo)] = {};
  bool gFastVectorCPathPointTypeConstructed = false;

  // Address: 0x010AE1EC -- process-global `PrimitiveSerHelper<ECollisionType,int>`
  // singleton (constructed by FUN_00BCBD70, self-registering via `__xc_a`;
  // see the class Doxygen above for the real-ctor/atexit-target/dead-writer
  // evidence).
  ECollisionTypePrimitiveSerializer gECollisionTypePrimitiveSerializer;

  // Address: 0x010AE29C -- process-global `SCollisionInfoSerializer`
  // singleton. Constructing it runs SCollisionInfoSerializer::
  // SCollisionInfoSerializer() (0x00BCBDD0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~SCollisionInfoSerializer,
  // 0x00BF65B0) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::SCollisionInfoSerializer gSCollisionInfoSerializer;

  // Address: 0x010B2038 -- process-global `PrimitiveSerHelper<EPathPointState,int>`
  // singleton (constructed by FUN_00BD20E0, self-registering via `__xc_a`;
  // see CAiPathSpline.h for the real-ctor/atexit-target/dead-writer
  // evidence).
  moho::EPathPointStatePrimitiveSerializer gEPathPointStatePrimitiveSerializer;

  // Address: 0x010B204C -- process-global `CPathPointSerializer` singleton.
  // Constructing it runs MSVC's compiler-generated dynamic initializer for
  // this global (0x00BD2140, __xc_a-reachable; dead zero-xref COMDAT
  // duplicate: 0x0062F8E0), which runs the real `gpg::SerSaveLoadHelper<
  // CPathPoint>` ctor (self-links into `sNewHelpers`, binds
  // `mLoadCallback`/`mSaveCallback` to the template's `Deserialize`/
  // `Serialize`, installs the vtable) and registers the real destructor
  // (0x00BFA880, no recovered mangled name; body confirmed via raw asm to
  // just call `ResetLinks()`) via `atexit`.
  moho::CPathPointSerializer gCPathPointSerializer;

  gpg::RType* gWeakUnitType = nullptr;
  gpg::RType* gSCollisionInfoType = nullptr;
  gpg::RType* gECollisionTypeType = nullptr;
  gpg::RType* gEPathPointStateType = nullptr;
  gpg::RType* gVector3fType = nullptr;
  gpg::RType* gCPathPointType = nullptr;
  gpg::RType* gFastVectorCPathPointType = nullptr;
  msvc8::string gFastVectorCPathPointTypeName{};
  bool gFastVectorCPathPointTypeNameCleanupRegistered = false;
  gpg::RType* gPathSplineTypeType = nullptr;
  gpg::RType* gPathSplineContinuationType = nullptr;
  EngineStats* gRecoveredAiPathSplineStartupStatsSlot = nullptr;

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    if (gVector3fType == nullptr) {
      gVector3fType = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return gVector3fType;
  }

  [[nodiscard]] gpg::RType* ResolveWeakUnitType()
  {
    if (gWeakUnitType == nullptr) {
      gWeakUnitType = gpg::LookupRType(typeid(WeakPtr<Unit>));
    }
    return gWeakUnitType;
  }

  [[nodiscard]] gpg::RType* ResolveSCollisionInfoType()
  {
    if (gSCollisionInfoType == nullptr) {
      gSCollisionInfoType = gpg::LookupRType(typeid(moho::SCollisionInfo));
    }
    return gSCollisionInfoType;
  }

  /**
   * Address: 0x00598470 (FUN_00598470)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `ECollisionType`.
   */
  [[nodiscard]] gpg::RType* ResolveECollisionTypeTypePrimary()
  {
    if (gECollisionTypeType == nullptr) {
      gECollisionTypeType = gpg::LookupRType(typeid(moho::ECollisionType));
    }
    return gECollisionTypeType;
  }

  [[nodiscard]] gpg::RType* ResolveECollisionTypeType()
  {
    return ResolveECollisionTypeTypePrimary();
  }

  [[nodiscard]] gpg::RType* ResolveEPathPointStateType()
  {
    if (gEPathPointStateType == nullptr) {
      gEPathPointStateType = gpg::LookupRType(typeid(moho::EPathPointState));
    }
    return gEPathPointStateType;
  }

  [[nodiscard]] gpg::RType* ResolveCPathPointType()
  {
    if (gCPathPointType == nullptr) {
      gCPathPointType = gpg::LookupRType(typeid(moho::CPathPoint));
    }
    return gCPathPointType;
  }

  [[nodiscard]] moho::SCollisionInfoTypeInfo* AcquireSCollisionInfoTypeInfo()
  {
    if (!gSCollisionInfoTypeInfoConstructed) {
      new (gSCollisionInfoTypeInfoStorage) moho::SCollisionInfoTypeInfo();
      gSCollisionInfoTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::SCollisionInfoTypeInfo*>(gSCollisionInfoTypeInfoStorage);
  }

  [[nodiscard]] moho::ECollisionTypeTypeInfo* AcquireECollisionTypeTypeInfo()
  {
    if (!gECollisionTypeTypeInfoConstructed) {
      new (gECollisionTypeTypeInfoStorage) moho::ECollisionTypeTypeInfo();
      gECollisionTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::ECollisionTypeTypeInfo*>(gECollisionTypeTypeInfoStorage);
  }

  [[nodiscard]] FastVectorCPathPointTypeInfo* AcquireFastVectorCPathPointType()
  {
    if (!gFastVectorCPathPointTypeConstructed) {
      new (gFastVectorCPathPointTypeStorage) FastVectorCPathPointTypeInfo();
      gFastVectorCPathPointTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorCPathPointTypeInfo*>(gFastVectorCPathPointTypeStorage);
  }

  [[nodiscard]] gpg::RType* preregister_FastVectorCPathPointType();

  [[nodiscard]] gpg::RType* ResolveFastVectorCPathPointType()
  {
    if (gFastVectorCPathPointType == nullptr) {
      gFastVectorCPathPointType = gpg::LookupRType(typeid(gpg::fastvector<moho::CPathPoint>));
      if (gFastVectorCPathPointType == nullptr) {
        gFastVectorCPathPointType = preregister_FastVectorCPathPointType();
      }
    }
    return gFastVectorCPathPointType;
  }

  [[nodiscard]] gpg::RType* ResolvePathSplineTypeType()
  {
    if (gPathSplineTypeType == nullptr) {
      gPathSplineTypeType = gpg::LookupRType(typeid(moho::EPathType));
    }
    return gPathSplineTypeType;
  }

  [[nodiscard]] gpg::RType* ResolvePathSplineContinuationType()
  {
    if (gPathSplineContinuationType == nullptr) {
      gPathSplineContinuationType = SContinueInfo::sType;
      if (gPathSplineContinuationType == nullptr) {
        gPathSplineContinuationType = gpg::LookupRType(typeid(moho::SContinueInfo));
        SContinueInfo::sType = gPathSplineContinuationType;
      }
    }
    return gPathSplineContinuationType;
  }

  /**
   * Address: 0x005B4F20 (FUN_005B4F20)
   *
   * What it does:
   * Reads one contiguous `fastvector<CPathPoint>` payload: element count,
   * resizes to that count via `fastvector::Resize` (`FUN_005B4D30`, the
   * canonical `gpg::fastvector<T>::Resize` for this 28-byte element -- cited
   * on `FastVector.h`), then reads that many reflected `moho::CPathPoint`
   * values in place. `fill`'s `mState` is set to `PPS_7` (not left
   * zero-initialized): confirmed against the `.c` -- the local fill value
   * this function builds before calling `Resize` has its state lane set to
   * the literal `7`, not `0`. Bound as `RType::serLoadFunc_` via
   * `FastVectorCPathPointTypeInfo::Init` below.
   */
  void LoadFastVectorCPathPoint(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& vec = *reinterpret_cast<gpg::fastvector<moho::CPathPoint>*>(objectPtr);
    unsigned int count = 0;
    archive->ReadUInt(&count);

    moho::CPathPoint fill{};
    fill.mState = moho::EPathPointState::PPS_7;
    vec.Resize(count, fill);

    gpg::RType* const elementType = ResolveCPathPointType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &vec[i], owner);
    }
  }

  /**
   * Address: 0x005B4FF0 (FUN_005B4FF0)
   *
   * What it does:
   * Writes one contiguous `fastvector<CPathPoint>` payload: element count
   * via `(end-begin)/28` (direct pointer arithmetic, not a `.size()` call --
   * confirmed against the `.asm`), then each reflected lane in order. The
   * element type is resolved through `moho::CPathPoint::sType2` directly
   * (lazily populated via `gpg::LookupRType` on first use, matching the
   * class's own public static member) rather than through this file's
   * generic `ResolveCPathPointType()` helper -- a real, deliberate
   * difference from the `Load` side confirmed against the `.c`/`.asm`.
   * Bound as `RType::serSaveFunc_` via `FastVectorCPathPointTypeInfo::Init`
   * below. DB-integrity fix: a second, unwired copy of this function
   * previously lived in `gpg/core/containers/ArchiveSerialization.cpp`
   * wrongly claiming this same address through a generic container-view
   * helper pair whose calls do not appear anywhere in this address's real
   * disassembly -- removed there; this is the real, already-wired body.
   */
  void SaveFastVectorCPathPoint(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& vec = *reinterpret_cast<const gpg::fastvector<moho::CPathPoint>*>(objectPtr);
    const unsigned int count = static_cast<unsigned int>(vec.size());
    archive->WriteUInt(count);

    gpg::RType* const elementType = ResolveCPathPointType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, const_cast<moho::CPathPoint*>(&vec[i]), owner);
    }
  }

  /**
   * Address: 0x005B58C0 (FUN_005B58C0, preregister_FastVectorCPathPointType)
   *
   * What it does:
   * Constructs and preregisters startup RTTI descriptor for
   * `gpg::fastvector<CPathPoint>`.
   */
  [[nodiscard]] gpg::RType* preregister_FastVectorCPathPointType()
  {
    FastVectorCPathPointTypeInfo* const type = AcquireFastVectorCPathPointType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<moho::CPathPoint>), type);
    gFastVectorCPathPointType = type;
    return type;
  }

  /**
   * Address: 0x0062F520 (FUN_0062F520, construct_EPathPointStateTypeInfo)
   *
   * What it does:
   * Constructs and preregisters `EPathPointStateTypeInfo` in static startup
   * storage.
   */
  [[nodiscard]] gpg::REnumType* construct_EPathPointStateTypeInfo()
  {
    if (!gEPathPointStateTypeInfoConstructed) {
      auto* const typeInfo = new (gEPathPointStateTypeInfoStorage) moho::EPathPointStateTypeInfo();
      gpg::PreRegisterRType(typeid(moho::EPathPointState), typeInfo);
      gEPathPointStateType = typeInfo;
      gEPathPointStateTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::REnumType*>(gEPathPointStateTypeInfoStorage);
  }

  /**
   * Address: 0x00BFA7E0 (FUN_00BFA7E0, cleanup_EPathPointStateTypeInfo)
   *
   * What it does:
   * Tears down the recovered `EPathPointState` enum type descriptor.
   */
  void cleanup_EPathPointStateTypeInfo()
  {
    if (!gEPathPointStateTypeInfoConstructed) {
      return;
    }

    reinterpret_cast<moho::EPathPointStateTypeInfo*>(gEPathPointStateTypeInfoStorage)->~EPathPointStateTypeInfo();
    gEPathPointStateType = nullptr;
    gEPathPointStateTypeInfoConstructed = false;
  }

  /**
   * Address: 0x0062F650 (FUN_0062F650, construct_CPathPointTypeInfo)
   *
   * What it does:
   * Constructs and preregisters `CPathPointTypeInfo` in static startup storage.
   */
  [[nodiscard]] gpg::RType* construct_CPathPointTypeInfo()
  {
    if (!gCPathPointTypeInfoConstructed) {
      auto* const typeInfo = new (gCPathPointTypeInfoStorage) moho::CPathPointTypeInfo();
      gpg::PreRegisterRType(typeid(moho::CPathPoint), typeInfo);
      gCPathPointType = typeInfo;
      gCPathPointTypeInfoConstructed = true;
    }

    return reinterpret_cast<gpg::RType*>(gCPathPointTypeInfoStorage);
  }

  /**
   * Address: 0x00BFA820 (FUN_00BFA820, cleanup_CPathPointTypeInfo)
   *
   * What it does:
   * Tears down the recovered `CPathPoint` type descriptor.
   */
  void cleanup_CPathPointTypeInfo()
  {
    if (!gCPathPointTypeInfoConstructed) {
      return;
    }

    reinterpret_cast<moho::CPathPointTypeInfo*>(gCPathPointTypeInfoStorage)->~CPathPointTypeInfo();
    gCPathPointType = nullptr;
    gCPathPointTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BF6510 (FUN_00BF6510, Moho::ECollisionTypeTypeInfo::~ECollisionTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `ECollisionTypeTypeInfo` reflection storage.
   */
  void cleanup_ECollisionTypeTypeInfo()
  {
    if (!gECollisionTypeTypeInfoConstructed) {
      return;
    }

    AcquireECollisionTypeTypeInfo()->~ECollisionTypeTypeInfo();
    gECollisionTypeTypeInfoConstructed = false;
    gECollisionTypeType = nullptr;
  }

  /**
   * Address: 0x00BF6550 (FUN_00BF6550, cleanup_SCollisionInfoTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SCollisionInfoTypeInfo` reflection storage.
   */
  void cleanup_SCollisionInfoTypeInfo()
  {
    if (!gSCollisionInfoTypeInfoConstructed) {
      return;
    }

    AcquireSCollisionInfoTypeInfo()->~SCollisionInfoTypeInfo();
    gSCollisionInfoTypeInfoConstructed = false;
    gSCollisionInfoType = nullptr;
  }

  /**
   * Address: 0x00BF75A0 (FUN_00BF75A0, cleanup_FastVectorCPathPointType)
   *
   * What it does:
   * Tears down startup-owned `fastvector<CPathPoint>` reflection storage.
   */
  void cleanup_FastVectorCPathPointType()
  {
    if (!gFastVectorCPathPointTypeConstructed) {
      return;
    }

    AcquireFastVectorCPathPointType()->~FastVectorCPathPointTypeInfo();
    gFastVectorCPathPointTypeConstructed = false;
    gFastVectorCPathPointType = nullptr;
  }

  /**
   * Address: 0x00BF7570 (FUN_00BF7570, cleanup_FastVectorCPathPointTypeName)
   *
   * What it does:
   * Clears cached lexical type-name storage for
   * `gpg::RFastVectorType_CPathPoint::GetName`.
   */
  void cleanup_FastVectorCPathPointTypeName()
  {
    gFastVectorCPathPointTypeName.clear();
    gFastVectorCPathPointTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00BF7600 (FUN_00BF7600, cleanup_CAiPathSplineStartupStats)
   *
   * What it does:
   * Tears down one startup-owned AI path-spline stats slot.
   */
  void cleanup_CAiPathSplineStartupStats()
  {
    if (!gRecoveredAiPathSplineStartupStatsSlot) {
      return;
    }

    delete gRecoveredAiPathSplineStartupStatsSlot;
    gRecoveredAiPathSplineStartupStatsSlot = nullptr;
  }

} // namespace

/**
 * Address: 0x00596560 (FUN_00596560, sub_596560)
 */
void moho::ResetCollisionInfo(SCollisionInfo& info)
{
  RemoveFromIntrusiveCollisionChain(info);
  info.mPos = Wm3::Vector3f::Zero();
  info.mCollisionType = COLLISIONTYPE_None;
  info.mTickGate = -1;
}

/**
 * Address: 0x005984E0 (FUN_005984E0, Moho::SCollisionInfo::MemberDeserialize)
 */
void SCollisionInfo::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const weakUnitType = ResolveWeakUnitType();
  gpg::RType* const vectorType = ResolveVector3fType();
  gpg::RType* const collisionType = ResolveECollisionTypeType();
  GPG_ASSERT(weakUnitType != nullptr);
  GPG_ASSERT(vectorType != nullptr);
  GPG_ASSERT(collisionType != nullptr);

  archive->Read(weakUnitType, &mUnit, ownerRef);
  archive->Read(vectorType, &mPos, ownerRef);
  archive->Read(collisionType, &mCollisionType, ownerRef);
  archive->ReadUInt(reinterpret_cast<unsigned int*>(&mTickGate));
}

/**
 * Address: 0x005985A0 (FUN_005985A0, Moho::SCollisionInfo::MemberSerialize)
 */
void SCollisionInfo::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const weakUnitType = ResolveWeakUnitType();
  gpg::RType* const vectorType = ResolveVector3fType();
  gpg::RType* const collisionType = ResolveECollisionTypeType();
  GPG_ASSERT(weakUnitType != nullptr);
  GPG_ASSERT(vectorType != nullptr);
  GPG_ASSERT(collisionType != nullptr);

  archive->Write(weakUnitType, const_cast<SCollisionLink*>(&mUnit), ownerRef);
  archive->Write(vectorType, const_cast<Wm3::Vector3f*>(&mPos), ownerRef);
  archive->Write(collisionType, const_cast<ECollisionType*>(&mCollisionType), ownerRef);
  archive->WriteUInt(static_cast<unsigned int>(mTickGate));
}

/**
 * Address: 0x005B5530 (FUN_005B5530, Moho::SContinueInfo::MemberDeserialize)
 */
void SContinueInfo::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const vectorType = ResolveVector3fType();
  gpg::RType* const stateType = ResolveEPathPointStateType();
  GPG_ASSERT(vectorType != nullptr);
  GPG_ASSERT(stateType != nullptr);

  archive->Read(vectorType, &mOldPosition, ownerRef);
  archive->Read(vectorType, &mOldDirection, ownerRef);
  archive->Read(vectorType, &mOldVelocity, ownerRef);
  archive->Read(stateType, &mState, ownerRef);
}

/**
 * Address: 0x005B5610 (FUN_005B5610, Moho::SContinueInfo::MemberSerialize)
 */
void SContinueInfo::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const vectorType = ResolveVector3fType();
  gpg::RType* const stateType = ResolveEPathPointStateType();
  GPG_ASSERT(vectorType != nullptr);
  GPG_ASSERT(stateType != nullptr);

  archive->Write(vectorType, const_cast<Wm3::Vector3f*>(&mOldPosition), ownerRef);
  archive->Write(vectorType, const_cast<Wm3::Vector3f*>(&mOldDirection), ownerRef);
  archive->Write(vectorType, const_cast<Wm3::Vector3f*>(&mOldVelocity), ownerRef);
  archive->Write(stateType, const_cast<EPathPointState*>(&mState), ownerRef);
}

/**
 * Address: 0x005B2550 (FUN_005B2550, ??0CAiPathSpline@Moho@@QAE@@Z)
 */
CAiPathSpline::CAiPathSpline()
  : mCurrentNodeIndex(0)
  , mNodeCount(0)
  , mPathType(PT_0)
  , mContinuation{Wm3::Vector3f::Zero(), Wm3::Vector3f::Zero(), Wm3::Vector3f::Zero(), PPS_8}
  , mTailWord(0)
{
  ResetNodesToInline();
}

/**
 * Address: 0x005D45D0 (FUN_005D45D0, ??1CAiPathSpline@Moho@@QAE@@Z)
 */
CAiPathSpline::~CAiPathSpline()
{
  ResetNodesToInline();
}

/**
  * Alias of FUN_005B2550 (non-canonical helper lane).
 */
void CAiPathSpline::ResetNodesToInline()
{
  nodes.ResetStorageToInline();
}

/**
 * Address: 0x005965E0 (FUN_005965E0, sub_5965E0)
 */
CPathPoint* CAiPathSpline::TryGetNode(const std::uint32_t index)
{
  if (index >= mNodeCount) {
    return nullptr;
  }
  return &nodes[index];
}

/**
    * Alias of FUN_005965E0 (non-canonical helper lane).
 */
const CPathPoint* CAiPathSpline::TryGetNode(const std::uint32_t index) const
{
  if (index >= mNodeCount) {
    return nullptr;
  }
  return &nodes[index];
}

/**
 * Address: 0x005B26C0 (FUN_005B26C0, Moho::CAiPathSpline::Update)
 *
 * IDA signature:
 * int __userpurge Moho::CAiPathSpline::Update@<eax>(Moho::Unit *a1@<eax>,
 *     Moho::CAiPathSpline *a2@<edi>, int a3);
 *
 * What it does:
 * Predicts where the unit comes to rest if it brakes from here, and records
 * that path as spline nodes. Each iteration applies full reverse thrust to
 * the current velocity, clamps the result to the blueprint's brake and speed
 * limits, steps the position by the surviving velocity, and drops the node
 * onto the terrain (or the water line for water/amphibious/hover hulls).
 *
 * The whole simulation runs in the (x, -z) plane - y is never integrated,
 * only sampled from the height field - which is why a unit driving off a
 * cliff still produces a path that follows the ground.
 *
 * Because the braking acceleration is exactly the negated velocity, the
 * acceleration-vs-brake test below always resolves to the brake limit. The
 * binary evaluates it anyway; it is kept so the limit selection still reads
 * the way the original expressed it.
 *
 * Termination is driven entirely by the caller's mode: only modes 3 and 4
 * can set the terminal state, and mode 4 additionally requires more than
 * five nodes. A caller passing any other mode would not terminate, so the
 * binary is only ever reached with 3 or 4.
 *
 * Returns the number of nodes produced.
 *
 * Ground truth (`FUN_005B26C0.c`) matches the engine scalar-first rotation
 * matrix term-by-term for the initial forward sample, not the generic
 * `Quaternion::Rotate` (upstream WildMagic, `.w`-scalar `ToMat3()`) the
 * previous body here used.
 */
int CAiPathSpline::Update(Unit* const unit, const int updateMode)
{
  ResetNodesToInline();
  nodes.Clear();
  mPathType = static_cast<EPathType>(updateMode);
  mCurrentNodeIndex = 0;
  mNodeCount = 0;

  // The hull's facing, straight from the orientation - not flattened and not
  // renormalised, so a pitched or rolled hull contributes its real heading.
  const Wm3::Vector3f forwardAxis{0.0f, 0.0f, 1.0f};
  Wm3::Vector3f forward{};
  MultQuadVec(&forward, &forwardAxis, &unit->GetTransform().orient_);

  CPathPoint point{};
  point.mPosition = unit->GetPosition();
  point.mDirection = forward;
  point.mState = PPS_1;

  const float speedLimit = unit->mInfoCache.mFormationTopSpeed;

  const Wm3::Vector3f velocity = unit->GetVelocity();
  const float speed = std::sqrt(
    (velocity.x * velocity.x) + (velocity.y * velocity.y) + (velocity.z * velocity.z));

  // Momentum carried into the simulation: the facing scaled to the current
  // speed, so a unit that is stationary but pointed somewhere contributes no
  // travel.
  Wm3::Vector3f step = forward;
  (void)VecSetLength(&step, speed);

  // A stopped unit has no travel direction; the binary marks that with a
  // saturated vector rather than a flag, and every later use is a dot product
  // whose sign is all that matters.
  Wm3::Vector3f travelDirection{
    std::numeric_limits<float>::max(),
    std::numeric_limits<float>::max(),
    std::numeric_limits<float>::max()
  };
  if (speed != 0.0f) {
    const float inverseSpeed = 1.0f / speed;
    travelDirection = Wm3::Vector3f{
      velocity.x * inverseSpeed, velocity.y * inverseSpeed, velocity.z * inverseSpeed};
  }

  const RUnitBlueprintPhysics& physics = unit->GetBlueprint()->Physics;
  STIMap* const map = unit->SimulationRef->mMapData;
  CHeightField* const heightField = map->mHeightField.get();

  // Reversing: the hull is travelling against its facing, so the momentum
  // that gets braked points backwards too.
  const float facingAlignment = (travelDirection.y * forward.y)
    + (travelDirection.z * forward.z)
    + (travelDirection.x * forward.x);
  if (facingAlignment < 0.0f) {
    step = Wm3::Vector3f{-step.x, -step.y, -step.z};
    point.mState = PPS_2;
  }

  do {
    // Snapshot for whoever regenerates this spline next tick.
    mContinuation.mOldDirection = forward;
    mContinuation.mOldPosition = point.mPosition;
    mContinuation.mOldVelocity = step;
    mContinuation.mState = PPS_0;

    // One unit further along the current heading - enough for the steering
    // build to derive a direction, which is all it is used for here.
    const Wm3::Vector3f target{
      point.mPosition.x + travelDirection.x,
      point.mPosition.y + travelDirection.y,
      point.mPosition.z + travelDirection.z
    };

    SteeringParams steering(unit, point.mPosition, target, travelDirection, speedLimit, false);
    if (mPathType == PT_4) {
      steering.mMaxAcceleration = steering.mMaxAcceleration * 2.0f;
      steering.mMaxBrake = steering.mMaxBrake * 2.0f;
    }

    // Planar frame: x as-is, z negated. The negation is undone when the
    // result is written back to the position and the stored velocity.
    const float planarX = step.x;
    const float planarZ = -step.z;
    float brakeX = -step.x;
    float brakeZ = step.z;

    float planarSpeedSq = (planarZ * planarZ) + (planarX * planarX);
    float newVelocityX = planarX;
    float newVelocityZ = planarZ;

    if (planarSpeedSq > 0.0f) {
      const bool opposingTravel = ((brakeZ * planarZ) + (brakeX * planarX)) <= 0.0f;
      const float thrustLimit = opposingTravel ? steering.mMaxBrake : steering.mMaxAcceleration;

      const float brakeMagnitudeSq = (brakeZ * brakeZ) + (brakeX * brakeX);
      if (brakeMagnitudeSq > (thrustLimit * thrustLimit)) {
        const float scale = thrustLimit / std::sqrt(brakeMagnitudeSq);
        brakeX = brakeX * scale;
        brakeZ = brakeZ * scale;
      }

      newVelocityX = brakeX + planarX;
      newVelocityZ = brakeZ + planarZ;

      const float newSpeedSq = (newVelocityZ * newVelocityZ) + (newVelocityX * newVelocityX);
      if (newSpeedSq > (steering.mMaxSpeed * steering.mMaxSpeed)) {
        const float scale = steering.mMaxSpeed / std::sqrt(newSpeedSq);
        newVelocityX = newVelocityX * scale;
        newVelocityZ = newVelocityZ * scale;
      }

      if (((newVelocityZ * newVelocityZ) + (newVelocityX * newVelocityX)) <= 1.0e-6f) {
        // Braked to a standstill - stop advancing, and let the terminal test
        // below decide whether the path ends here.
        step = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
        planarSpeedSq = 0.0f;
      } else {
        point.mPosition.x = newVelocityX + point.mPosition.x;
        point.mPosition.z = -newVelocityZ + point.mPosition.z;
        step = Wm3::Vector3f{newVelocityX, 0.0f, -newVelocityZ};
      }
    }

    if (std::isnan(point.mPosition.x) || std::isnan(point.mPosition.y)
      || std::isnan(point.mPosition.z)) {
      // Diagnostic dump kept as the original wrote it - the operands that
      // produced the NaN are what makes this reproducible.
      const Wm3::Vector3f& currentPosition = unit->GetPosition();
      gpg::Logf("unit = %s\n", unit->GetBlueprint()->mBlueprintId.c_str());
      gpg::Logf("curPos = %f, %f, %f\n",
        currentPosition.x, currentPosition.y, currentPosition.z);
      gpg::Logf("oldVel = %f, %f\n", step.x, -step.z);
      gpg::Logf("v = %f, %f\n", newVelocityX, newVelocityZ);
      const Wm3::Vector3f& previousVelocity = mContinuation.mOldVelocity;
      gpg::Logf("prevSpeed = %f\n", std::sqrt(
        (previousVelocity.x * previousVelocity.x)
        + (previousVelocity.y * previousVelocity.y)
        + (previousVelocity.z * previousVelocity.z)));
      gpg::Logf("prevPos = %f, %f, %f\n",
        mContinuation.mOldPosition.x,
        mContinuation.mOldPosition.y,
        mContinuation.mOldPosition.z);
      gpg::Logf("acc = %f, %f\n", brakeX, brakeZ);
    }

    if (planarSpeedSq <= 1.0e-6f
      && (updateMode == 3 || (updateMode == 4 && nodes.size() > 5))) {
      point.mState = PPS_8;
    }

    // Nodes sit on the surface the hull actually rides.
    const float groundElevation =
      heightField->GetElevation(point.mPosition.x, point.mPosition.z);
    const ERuleBPUnitMovementType motionType = physics.MotionType;
    if (motionType == RULEUMT_Water
      || motionType == RULEUMT_AmphibiousFloating
      || motionType == RULEUMT_Hover) {
      float surface = groundElevation;
      if (map->mWaterEnabled && map->mWaterElevation > surface) {
        surface = map->mWaterElevation;
      }
      point.mPosition.y = surface;
    } else {
      point.mPosition.y = groundElevation;
    }

    nodes.PushBack(point);
  } while (point.mState != PPS_8);

  mNodeCount = static_cast<std::uint32_t>(nodes.size());
  return static_cast<int>(mNodeCount);
}

namespace
{
  /**
   * Node budget for a spline generated while the unit follows a formation
   * command (IDA `formation_path_value`, a process global at 0x00F59978
   * initialised to 5). Only `CAiPathSpline::Generate` reads it.
   */
  int sFormationPathNodeLimit = 5;

  constexpr int kDefaultPathNodeLimit = 20;
  constexpr float kStoppedSpeedRatio = 0.0099999998f;
  constexpr float kHeadingBlendNew = 0.2f;
  constexpr float kHeadingBlendOld = 0.80000001f;
  constexpr float kForwardAlignedCos = 0.866f;
  constexpr float kReverseAlignedCos = 0.15000001f;

  /**
   * Forward axis of a unit orientation. A unit pitched almost straight up or
   * down (|forward.y| > 0.99) has no usable heading and falls back to +Z.
   */
  [[nodiscard]] Wm3::Vector3f HeadingFromOrientation(const Wm3::Quatf& orient) noexcept
  {
    Wm3::Vector3f forward{};
    forward.x = ((orient.x * orient.z) + (orient.w * orient.y)) * 2.0f;
    forward.y = ((orient.w * orient.z) - (orient.x * orient.y)) * 2.0f;
    forward.z = 1.0f - (((orient.z * orient.z) + (orient.y * orient.y)) * 2.0f);
    if (std::fabs(forward.y) > 0.99000001f) {
      forward = Wm3::Vector3f{0.0f, 0.0f, 1.0f};
    }
    return forward;
  }

  /**
   * Unit direction of an XZ delta whose length is already known; a zero
   * length yields the FLT_MAX sentinel the binary's inline normalize produces.
   */
  [[nodiscard]] Wm3::Vector3f DirectionOfDelta(const float deltaX, const float deltaZ, const float length) noexcept
  {
    if (length == 0.0f) {
      constexpr float kMax = std::numeric_limits<float>::max();
      return Wm3::Vector3f{kMax, kMax, kMax};
    }
    const float invLength = 1.0f / length;
    return Wm3::Vector3f{invLength * deltaX, invLength * 0.0f, invLength * deltaZ};
  }

  /**
   * Distance needed to brake from `speedPerTick` (converted back to units per
   * second) with the stronger of the blueprint's acceleration and brake.
   */
  [[nodiscard]] float BrakingDistanceFor(const RUnitBlueprintPhysics& physics, const float speedPerTick) noexcept
  {
    float decel = physics.MaxAcceleration;
    if (physics.MaxBrake > decel) {
      decel = physics.MaxBrake;
    }
    if (decel <= 0.0f) {
      return 0.0f;
    }
    const float speedPerSecond = speedPerTick * 10.0f;
    return (speedPerSecond * speedPerSecond) / (decel * 2.0f);
  }

  [[nodiscard]] float LargerBlueprintExtent(const Unit& unit) noexcept
  {
    const RUnitBlueprint* const blueprint = unit.GetBlueprint();
    float extent = blueprint->mSizeX;
    if (blueprint->mSizeZ > extent) {
      extent = blueprint->mSizeZ;
    }
    return extent;
  }
} // namespace

/**
 * Address: 0x005B2FF0 (FUN_005B2FF0, Moho::CAiPathSpline::Generate)
 *
 * IDA signature:
 * void __userpurge Moho::CAiPathSpline::Generate(Moho::Unit *a1@<eax>, Moho::CAiPathSpline *this,
 *   Wm3::Vector3f *destin, int a4, char a5);
 *
 * What it does:
 * Integrates the unit's steering physics tick by tick from its current pose
 * (or the continuation pose of the previous spline) toward `destination`,
 * emitting one CPathPoint per tick until the node budget, the destination, or
 * a terminal steering state is reached. Each tick builds SteeringParams,
 * turns the heading toward the goal within the turn limit, damps the sideways
 * velocity, picks a wanted speed (turn/brake/backup limited), accelerates
 * toward it, and samples the terrain or water height for the node. The
 * state machine drives approach (PPS_7), braking (PPS_3), stop-and-reverse
 * (PPS_4/PPS_5/PPS_6) and completion (PPS_8).
 */
void CAiPathSpline::Generate(
  Unit* const unit,
  const Wm3::Vector3f& destination,
  const int pathType,
  const bool allowContinuation
)
{
  if (unit->IsDead()) {
    gpg::Logf("Attempting to generate path spline for a dead unit!!!");
    return;
  }

  ResetNodesToInline();
  mPathType = static_cast<EPathType>(pathType);
  mCurrentNodeIndex = 0;
  mNodeCount = 0;

  const RUnitBlueprintPhysics& physics = unit->GetBlueprint()->Physics;
  int nodeLimit = kDefaultPathNodeLimit;
  if (unit->GetFormation() != nullptr && unit->GetFormation()->CommandIsForm()) {
    nodeLimit = sFormationPathNodeLimit;
  }
  if (physics.TurnRadius > physics.TurnRate) {
    nodeLimit *= 3;
  }

  bool doBackup = false;
  const float topSpeed = unit->mInfoCache.mFormationTopSpeed;
  Wm3::Vector3f forward = HeadingFromOrientation(unit->GetTransform().orient_);

  CPathPoint point{};
  point.mPosition = unit->GetPosition();
  point.mDirection = forward;
  point.mState = PPS_7;

  // The destination cell and the orientation axes are computed but unused
  // in the shipped body; kept so the emitted call set matches.
  const SFootprint& footprint = unit->GetFootprint();
  [[maybe_unused]] const int destinationCellZ =
    static_cast<int>(std::lrintf(destination.z - (static_cast<float>(footprint.mSizeZ) * 0.5f)));
  [[maybe_unused]] const int destinationCellX =
    static_cast<int>(std::lrintf(destination.x - (static_cast<float>(footprint.mSizeX) * 0.5f)));
  [[maybe_unused]] const VAxes3 orientationAxes(unit->GetTransform().orient_);

  float deltaX = destination.x - point.mPosition.x;
  float deltaZ = destination.z - point.mPosition.z;
  const float distance = std::sqrt((deltaZ * deltaZ) + (deltaX * deltaX));
  STIMap* const map = unit->SimulationRef->mMapData;
  if (distance < 0.001f) {
    return;
  }
  Wm3::Vector3f toDestination = DirectionOfDelta(deltaX, deltaZ, distance);
  Wm3::Vector3f oldVelocity = unit->GetVelocity();
  float alignment =
    (toDestination.z * forward.z) + (toDestination.y * forward.y) + (toDestination.x * forward.x);
  const float currentSpeed = std::sqrt(
    ((oldVelocity.x * oldVelocity.x) + (oldVelocity.z * oldVelocity.z)) + (oldVelocity.y * oldVelocity.y)
  );
  float speedRatio = (currentSpeed * 10.0f) / physics.MaxSpeed;
  const bool turnRadiusDominant = physics.TurnRadius > physics.TurnRate;

  EPathPointState state = PPS_7;
  if (!allowContinuation) {
    const EPathPointState continuedState = mContinuation.mState;
    point.mPosition = mContinuation.mOldPosition;
    forward = mContinuation.mOldDirection;
    oldVelocity = mContinuation.mOldVelocity;
    if (continuedState != PPS_0) {
      state = continuedState;
    }
  } else if (physics.MaxSpeedReverse > 0.0f && physics.RotateOnSpot == 0u) {
    const Wm3::Vector3f velocity = unit->GetVelocity();
    const bool movingBackward =
      (((velocity.z * forward.z) + (velocity.y * forward.y)) + (velocity.x * forward.x)) < 0.0f;
    if (alignment < 0.0f && (speedRatio < 0.5f || turnRadiusDominant)) {
      state = (speedRatio > kStoppedSpeedRatio && !movingBackward) ? PPS_4 : PPS_5;
    } else if (movingBackward) {
      state = (alignment >= 0.0f) ? PPS_6 : PPS_5;
    }
  }

  if (state == PPS_5) {
    if (physics.BackUpDistance > distance && alignment < -0.5f) {
      doBackup = true;
    }
  } else if (state == PPS_8) {
    mNodeCount = static_cast<std::uint32_t>(nodes.size());
    return;
  }

  for (;;) {
    mContinuation.mOldDirection = forward;
    mContinuation.mOldPosition = point.mPosition;
    mContinuation.mOldVelocity = oldVelocity;
    mContinuation.mState = PPS_0;

    float speedScale = 1.0f;
    if (physics.LayerChangeOffsetHeight < -0.5f && physics.MotionType == RULEUMT_AmphibiousFloating) {
      const float depthLimit = physics.LayerChangeOffsetHeight * 3.0f;
      const float elevation = map->mHeightField->GetElevation(point.mPosition.x, point.mPosition.z);
      const float depth = elevation - map->GetWaterElevation();
      if (depth > depthLimit && depth < 0.0f) {
        const float depthFraction = depth / depthLimit;
        speedScale = 0.5f;
        if (depthFraction > 0.5f) {
          speedScale = depthFraction;
        }
      }
    }

    SteeringParams params(unit, point.mPosition, destination, forward, speedScale * topSpeed, false);

    // Steering works in the (x, -z) plane.
    const float velocityX = oldVelocity.x;
    const float velocityZ = -0.0f - oldVelocity.z;
    float speedPerTick = std::sqrt((velocityZ * velocityZ) + (velocityX * velocityX));
    float turnLimit = speedPerTick / params.mInvTurnRadius;
    if (params.mTurnRate > turnLimit) {
      turnLimit = params.mTurnRate;
    }
    if (mPathType == PT_2) {
      params.mMaxAcceleration = params.mMaxAcceleration * 2.0f;
      params.mMaxBrake = params.mMaxBrake * 2.0f;
      turnLimit = turnLimit * 2.0f;
    }

    // The limiter rotates its SOURCE (arg 3/4) toward its TARGET (arg 5/6):
    // 0x005B2FF0 passes `mForwardXZ` as the source and `(mDeltaX, mDeltaZ)` as
    // the target (and negates the FORWARD, not the delta, on the backup path).
    // Swapping them turned every large course change into a near-instant snap:
    // outside the limit it rotated the destination delta by one tick's worth,
    // landing almost on the goal heading, and inside the limit it returned the
    // current heading unchanged, so small corrections never happened at all.
    Wm3::Vector2f heading{};
    if (doBackup) {
      Wm3::Vector2f reversed{};
      (void)RotateDirectionTowardTargetLimited(
        &reversed, turnLimit, -0.0f - params.mForwardXZ.x, -0.0f - params.mForwardXZ.y, params.mDeltaX, params.mDeltaZ
      );
      heading.x = -0.0f - reversed.x;
      heading.y = -0.0f - reversed.y;
    } else {
      (void)RotateDirectionTowardTargetLimited(
        &heading, turnLimit, params.mForwardXZ.x, params.mForwardXZ.y, params.mDeltaX, params.mDeltaZ
      );
    }
    forward = Wm3::Vector3f{heading.x, 0.0f, -0.0f - heading.y};

    Wm3::Vector2f driveHeading = heading;
    if (state == PPS_5 || state == PPS_6 || state == PPS_2) {
      driveHeading.x = -0.0f - heading.x;
      driveHeading.y = -0.0f - heading.y;
    }
    const float driveHeadingLenSq = (driveHeading.x * driveHeading.x) + (driveHeading.y * driveHeading.y);

    Wm3::Vector2f alongHeading{};
    if (driveHeadingLenSq > 0.0f) {
      const float projection = ((driveHeading.y * velocityZ) + (driveHeading.x * velocityX)) / driveHeadingLenSq;
      alongHeading.x = projection * driveHeading.x;
      alongHeading.y = driveHeading.y * projection;
    }
    float sideX = velocityX - alongHeading.x;
    float sideZ = velocityZ - alongHeading.y;
    const float sideLenSq = (sideX * sideX) + (sideZ * sideZ);
    if (sideLenSq > (params.mMaxSteer * params.mMaxSteer)) {
      const float scale = static_cast<float>(params.mMaxSteer / std::sqrt(static_cast<double>(sideLenSq)));
      sideX = sideX * scale;
      sideZ = scale * sideZ;
    }
    float driveX = velocityX - sideX;
    float driveZ = velocityZ - sideZ;

    float wantSpeed = 0.0f;
    float speedCap = 0.0f;
    bool coasting = state == PPS_1 || state == PPS_3 || state == PPS_4 || state == PPS_6;
    if (!coasting) {
      float cap = ComputeSteeringSpeedCapFromParams(&params, speedRatio);
      if (state == PPS_5 || state == PPS_2) {
        if (cap > params.mMaxReverseSpeed) {
          cap = params.mMaxReverseSpeed;
        }
      } else if (cap > params.mMaxSpeed) {
        cap = params.mMaxSpeed;
      }
      speedCap = cap;
      wantSpeed = cap;
      if (mPathType == PT_0) {
        float stoppingSpeed = params.mDistance;
        if (params.mMaxBrake < params.mDistance) {
          stoppingSpeed = static_cast<float>(std::sqrt(
            static_cast<double>((params.mDistance * params.mMaxBrake) + (params.mDistance * params.mMaxBrake))
          ));
        }
        if (stoppingSpeed <= speedCap) {
          speedCap = stoppingSpeed;
          wantSpeed = stoppingSpeed;
        }
      }
      if (turnRadiusDominant) {
        float facing = doBackup ? (-0.0f - alignment) : alignment;
        if (facing < -0.5f) {
          facing = -0.5f;
        }
        speedCap = ((facing + 1.0f) * 0.5f) * speedCap;
        wantSpeed = speedCap;
      }
      coasting = speedCap < 0.001f;
    }
    if (coasting) {
      float blendX = driveHeading.x;
      float blendZ = driveHeading.y;
      if (driveHeadingLenSq != 0.0f) {
        const float driveLen = std::sqrt((driveX * driveX) + (driveZ * driveZ));
        const float ratio = static_cast<float>(driveLen / std::sqrt(static_cast<double>(driveHeadingLenSq)));
        blendX = driveHeading.x * ratio;
        blendZ = ratio * driveHeading.y;
      }
      driveX = (blendX * kHeadingBlendNew) + (driveX * kHeadingBlendOld);
      speedCap = wantSpeed;
      driveZ = (blendZ * kHeadingBlendNew) + (driveZ * kHeadingBlendOld);
    }

    float accelX = (driveHeading.x * speedCap) - driveX;
    float accelZ = (driveHeading.y * speedCap) - driveZ;
    const float accelLimit =
      (((accelX * driveX) + (accelZ * driveZ)) <= 0.0f) ? params.mMaxBrake : params.mMaxAcceleration;
    const float accelLenSq = (accelX * accelX) + (accelZ * accelZ);
    if (accelLenSq > (accelLimit * accelLimit)) {
      const float scale = static_cast<float>(accelLimit / std::sqrt(static_cast<double>(accelLenSq)));
      accelX = accelX * scale;
      accelZ = scale * accelZ;
    }
    float moveX = accelX + driveX;
    float moveZ = accelZ + driveZ;
    const float moveCap =
      (state == PPS_5 || state == PPS_6 || state == PPS_2) ? params.mMaxReverseSpeed : params.mMaxSpeed;
    const float moveLenSq = (moveX * moveX) + (moveZ * moveZ);
    if (moveLenSq > (moveCap * moveCap)) {
      const float scale = static_cast<float>(moveCap / std::sqrt(static_cast<double>(moveLenSq)));
      moveX = moveX * scale;
      moveZ = scale * moveZ;
    }

    point.mPosition.x = moveX + point.mPosition.x;
    point.mPosition.z = (-0.0f - moveZ) + point.mPosition.z;
    point.mDirection = forward;
    Wm3::Vector3f moveVec{moveX, 0.0f, -0.0f - moveZ};
    oldVelocity = moveVec;
    speedPerTick = std::sqrt((moveX * moveX) + (moveVec.z * moveVec.z));
    speedRatio = speedPerTick / params.mMaxSpeed;

    if (std::isnan(point.mPosition.x) || std::isnan(point.mPosition.y) || std::isnan(point.mPosition.z)) {
      gpg::Logf("unit = %s\n", unit->GetBlueprint()->mBlueprintId.c_str());
      const Wm3::Vector3f unitPosition = unit->GetPosition();
      gpg::Logf("curPos = %f, %f, %f\n", unitPosition.x, unitPosition.y, unitPosition.z);
      gpg::Logf("oldVel = %f, %f\n", velocityX, velocityZ);
      gpg::Logf("v = %f, %f\n", moveX, moveZ);
      gpg::Logf("moveVec = %f, %f, %f\n", moveX, 0.0f, moveVec.z);
      const Wm3::Vector3f& prevVel = mContinuation.mOldVelocity;
      gpg::Logf(
        "prevSpeed = %f\n",
        std::sqrt(((prevVel.x * prevVel.x) + (prevVel.y * prevVel.y)) + (prevVel.z * prevVel.z))
      );
      gpg::Logf("curSpeed = %f\n", speedPerTick);
      gpg::Logf("wantSpeed = %f\n", wantSpeed);
      gpg::Logf("newforward = %f, %f, %f\n", driveHeading.x, driveHeading.y, forward.z);
      gpg::Logf(
        "prevPos = %f, %f, %f\n",
        mContinuation.mOldPosition.x, mContinuation.mOldPosition.y, mContinuation.mOldPosition.z
      );
      gpg::Logf("acc = %f, %f\n", accelX, accelZ);
    }

    const ERuleBPUnitMovementType motionType = physics.MotionType;
    if (motionType == RULEUMT_Water || motionType == RULEUMT_AmphibiousFloating || motionType == RULEUMT_Hover) {
      const float elevation = map->mHeightField->GetElevation(point.mPosition.x, point.mPosition.z);
      float surface = elevation;
      if (map->mWaterEnabled != 0u && map->mWaterElevation > elevation) {
        surface = map->mWaterElevation;
      }
      point.mPosition.y = surface;
    } else {
      point.mPosition.y = map->mHeightField->GetElevation(point.mPosition.x, point.mPosition.z);
    }
    nodes.push_back(point);

    deltaX = destination.x - point.mPosition.x;
    deltaZ = destination.z - point.mPosition.z;
    const float remaining = std::sqrt((deltaZ * deltaZ) + (deltaX * deltaX));
    if (static_cast<int>(nodes.size()) >= nodeLimit || remaining < 0.001f) {
      mContinuation.mState = state;
      state = PPS_8;
    }
    toDestination = DirectionOfDelta(deltaX, deltaZ, remaining);
    alignment = ((forward.z * toDestination.z) + (toDestination.x * forward.x)) + (toDestination.y * 0.0f);
    if (unit->IsAtPosition(destination)) {
      state = PPS_8;
    }

    bool finished = false;
    switch (state) {
      case PPS_3:
        finished = speedRatio <= kStoppedSpeedRatio;
        break;
      case PPS_4:
        if (speedRatio > kStoppedSpeedRatio) {
          break;
        }
        state = (physics.MaxSpeedReverse <= 0.0f || physics.RotateOnSpot != 0u) ? PPS_7 : PPS_5;
        break;
      case PPS_5: {
        const float brakingDistance = BrakingDistanceFor(physics, speedPerTick);
        (void)VecSetLength(&moveVec, LargerBlueprintExtent(*unit) + brakingDistance);
        const Wm3::Vector3f probe{
          moveVec.x + point.mPosition.x, moveVec.y + point.mPosition.y, moveVec.z + point.mPosition.z
        };
        if (UnitWontFitAt(probe, unit)) {
          state = PPS_6;
          break;
        }
        const bool keepReversing = doBackup ? (brakingDistance <= remaining) : (alignment <= kReverseAlignedCos);
        if (!keepReversing) {
          state = PPS_6;
        }
        break;
      }
      case PPS_6:
        if (speedRatio > kStoppedSpeedRatio) {
          break;
        }
        if (doBackup) {
          finished = true;
          break;
        }
        state = PPS_7;
        break;
      case PPS_7: {
        const float brakingDistance = BrakingDistanceFor(physics, speedPerTick);
        if (mPathType == PT_0 && brakingDistance > remaining) {
          state = PPS_3;
        }
        if (alignment >= kForwardAlignedCos) {
          break;
        }
        (void)VecSetLength(&moveVec, LargerBlueprintExtent(*unit) + brakingDistance);
        const Wm3::Vector3f probe{
          moveVec.x + point.mPosition.x, moveVec.y + point.mPosition.y, moveVec.z + point.mPosition.z
        };
        if (UnitWontFitAt(probe, unit)) {
          state = PPS_4;
        } else if (turnRadiusDominant && UnitIsBlockedAt(probe, unit, 2)) {
          state = PPS_4;
        }
        break;
      }
      default:
        finished = state == PPS_8;
        break;
    }
    if (finished) {
      break;
    }
  }

  mNodeCount = static_cast<std::uint32_t>(nodes.size());
}

/**
 * Address: 0x005B5FB0 (FUN_005B5FB0, Moho::CAiPathSpline::MemberDeserialize)
 */
void CAiPathSpline::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const pathNodeVectorType = ResolveFastVectorCPathPointType();
  archive->Read(pathNodeVectorType, this, ownerRef);

  // `nodes` is this class's first member (offset 0x00), which is why the
  // binary passes `this` straight to the fastvector<CPathPoint> reflection type.
  const std::size_t nodeCount = nodes.size();
  gpg::RType* const nodeType = ResolveCPathPointType();
  for (std::size_t i = 0; i < nodeCount; ++i) {
    gpg::RRef nodeRef{};
    nodeRef.mObj = &nodes[i];
    nodeRef.mType = nodeType;
    archive->TrackPointer(nodeRef);
  }

  archive->ReadUInt(&mCurrentNodeIndex);
  archive->ReadUInt(&mNodeCount);

  gpg::RType* const pathTypeType = ResolvePathSplineTypeType();
  archive->Read(pathTypeType, &mPathType, ownerRef);

  gpg::RType* const continuationType = ResolvePathSplineContinuationType();
  archive->Read(continuationType, &mContinuation, ownerRef);
}

/**
 * Address: 0x005B60E0 (FUN_005B60E0, Moho::CAiPathSpline::MemberSerialize)
 */
void CAiPathSpline::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const pathNodeVectorType = ResolveFastVectorCPathPointType();
  archive->Write(pathNodeVectorType, this, ownerRef);

  const std::size_t nodeCount = nodes.size();
  gpg::RType* const nodeType = ResolveCPathPointType();
  for (std::size_t i = 0; i < nodeCount; ++i) {
    gpg::RRef nodeRef{};
    nodeRef.mObj = const_cast<CPathPoint*>(&nodes[i]);
    nodeRef.mType = nodeType;
    archive->PreCreatedPtr(nodeRef);
  }

  archive->WriteUInt(mCurrentNodeIndex);
  archive->WriteUInt(mNodeCount);

  gpg::RType* const pathTypeType = ResolvePathSplineTypeType();
  archive->Write(pathTypeType, &mPathType, ownerRef);

  gpg::RType* const continuationType = ResolvePathSplineContinuationType();
  archive->Write(continuationType, &mContinuation, ownerRef);
}

/**
 * Address: 0x00596730 (FUN_00596730, Moho::SCollisionInfoTypeInfo::SCollisionInfoTypeInfo)
 */
SCollisionInfoTypeInfo::SCollisionInfoTypeInfo()
{
  gpg::PreRegisterRType(typeid(SCollisionInfo), this);
  gSCollisionInfoType = this;
}

/**
 * Address: 0x005967C0 (FUN_005967C0)
 * Demangled: Moho::SCollisionInfoTypeInfo::dtr (scalar-deleting)
 *
 * What it does:
 * Frees the `RType` base's two `msvc8::vector<RField>` storage lanes
 * (`bases_._Myfirst` @ +0x2C, `fields_._Myfirst` @ +0x3C), restores the
 * `gpg::RObject` vftable, and conditionally deletes `this`. Defaulted in
 * source: the compiler-generated `~RType()` reproduces this behavior,
 * identical shape to `RVectorType<moho::SimArmy*>::~RVectorType()`
 * (Reflection.h) and `RVectorType<moho::SPointVector>::~RVectorType()`
 * (SPointVector.h). Vtable-confirmed:
 * `??_7SCollisionInfoTypeInfo@Moho@@6B@+0x8` writes this address, and that
 * vtable is constructed by this class's own ctor (0x00596730, above).
 */
SCollisionInfoTypeInfo::~SCollisionInfoTypeInfo() = default;

/**
 * Address: 0x005967B0 (FUN_005967B0, Moho::SCollisionInfoTypeInfo::GetName)
 */
const char* SCollisionInfoTypeInfo::GetName() const
{
  return "SCollisionInfo";
}

/**
 * Address: 0x00596790 (FUN_00596790, SCollisionInfoTypeInfo::Init)
 */
void SCollisionInfoTypeInfo::Init()
{
  size_ = sizeof(SCollisionInfo);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00596600 (FUN_00596600, Moho::ECollisionTypeTypeInfo::ECollisionTypeTypeInfo)
 */
ECollisionTypeTypeInfo::ECollisionTypeTypeInfo()
{
  gpg::PreRegisterRType(typeid(ECollisionType), this);
  gECollisionTypeType = this;
}

/**
 * Address: 0x00BF6510 (FUN_00BF6510, Moho::ECollisionTypeTypeInfo::~ECollisionTypeTypeInfo)
 */
ECollisionTypeTypeInfo::~ECollisionTypeTypeInfo() = default;

/**
 * Address: 0x00596680 (FUN_00596680, Moho::ECollisionTypeTypeInfo::GetName)
 */
const char* ECollisionTypeTypeInfo::GetName() const
{
  return "ECollisionType";
}

/**
 * Address: 0x00596660 (FUN_00596660, Moho::ECollisionTypeTypeInfo::Init)
 */
void ECollisionTypeTypeInfo::Init()
{
  size_ = sizeof(ECollisionType);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x0062F740 (FUN_0062F740, CPathPointTypeInfo non-deleting cleanup body)
 *
 * What it does:
 * Executes one non-deleting destruction lane for `CPathPointTypeInfo`.
 */
[[maybe_unused]] void DestroyCPathPointTypeInfoBody(CPathPointTypeInfo* const typeInfo) noexcept
{
  typeInfo->~CPathPointTypeInfo();
}

CPathPointTypeInfo::~CPathPointTypeInfo() = default;

const char* CPathPointTypeInfo::GetName() const
{
  return "CPathPoint";
}

/**
 * Address: 0x0062F6B0 (FUN_0062F6B0, CPathPointTypeInfo::Init)
 */
void CPathPointTypeInfo::Init()
{
  size_ = sizeof(CPathPoint);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x0062F5B0 (FUN_0062F5B0, vtable-slot-2 scalar deleting
 * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
 * conditionally frees the object -- ordinary C++ `delete` semantics, not
 * modeled as a separate function here)
 */
EPathPointStateTypeInfo::~EPathPointStateTypeInfo() = default;

const char* EPathPointStateTypeInfo::GetName() const
{
  return "EPathPointState";
}

void EPathPointStateTypeInfo::Init()
{
  size_ = sizeof(EPathPointState);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x005B4950 (FUN_005B4950, gpg::RFastVectorType_CPathPoint::GetName)
 *
 * What it does:
 * Lazily builds and caches the reflected `fastvector<CPathPoint>` type name
 * from the resolved `CPathPoint` element RTTI lane.
 */
const char* FastVectorCPathPointTypeInfo::GetName() const
{
  if (gFastVectorCPathPointTypeName.empty()) {
    const gpg::RType* const elementType = ResolveCPathPointType();
    const char* const elementName = elementType ? elementType->GetName() : "CPathPoint";
    gFastVectorCPathPointTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "CPathPoint");
    if (!gFastVectorCPathPointTypeNameCleanupRegistered) {
      gFastVectorCPathPointTypeNameCleanupRegistered = true;
      (void)std::atexit(&cleanup_FastVectorCPathPointTypeName);
    }
  }

  return gFastVectorCPathPointTypeName.c_str();
}

/**
 * Address: 0x005B4A10 (FUN_005B4A10, gpg::RFastVectorType_CPathPoint::GetLexical)
 *
 * What it does:
 * Formats vector lexical text and appends the runtime path-point count.
 */
msvc8::string FastVectorCPathPointTypeInfo::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

const gpg::RIndexed* FastVectorCPathPointTypeInfo::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x005B49F0 (FUN_005B49F0, gpg::RFastVectorType_CPathPoint::Init)
 *
 * What it does:
 * Records the element byte-size (16 = `sizeof(gpg::fastvector<
 * moho::CPathPoint>)`), version 1, and installs the element (de)serialize
 * callbacks (`serLoadFunc_ = &LoadFastVectorCPathPoint`, `serSaveFunc_ =
 * &SaveFastVectorCPathPoint`). DB-integrity fix: was fake-recovered (note
 * cited `gpg/core/reflection/Reflection.cpp`, but this class -- and both
 * callbacks it wires -- has always lived here in CAiPathSpline.cpp; the
 * address was simply never annotated).
 */
void FastVectorCPathPointTypeInfo::Init()
{
  size_ = 0x10;
  version_ = 1;
  serLoadFunc_ = &LoadFastVectorCPathPoint;
  serSaveFunc_ = &SaveFastVectorCPathPoint;
}

gpg::RRef FastVectorCPathPointTypeInfo::SubscriptIndex(void* obj, const int ind) const
{
  gpg::RRef out{};
  out.mType = ResolveCPathPointType();
  out.mObj = nullptr;
  if (!obj || ind < 0) {
    return out;
  }

  auto& vec = *static_cast<gpg::fastvector<CPathPoint>*>(obj);
  if (vec.Data() == nullptr || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    return out;
  }

  out.mObj = &vec[static_cast<std::size_t>(ind)];
  return out;
}

size_t FastVectorCPathPointTypeInfo::GetCount(void* obj) const
{
  if (!obj) {
    return 0u;
  }

  return static_cast<const gpg::fastvector<CPathPoint>*>(obj)->size();
}

/**
 * Address: 0x005B4AD0 (FUN_005B4AD0, gpg::RFastVectorType_CPathPoint::SetCount)
 *
 * What it does:
 * Resizes one reflected `fastvector<CPathPoint>` lane and fills new slots
 * with zero vectors plus `PPS_7` state.
 */
void FastVectorCPathPointTypeInfo::SetCount(void* obj, const int count) const
{
  if (!obj || count < 0) {
    return;
  }

  auto& vec = *static_cast<gpg::fastvector<CPathPoint>*>(obj);
  CPathPoint fill{};
  fill.mPosition = Wm3::Vector3f{};
  fill.mDirection = Wm3::Vector3f{};
  fill.mState = PPS_7;
  vec.Resize(static_cast<std::size_t>(count), fill);
}

/**
 * Address: 0x00596870 (FUN_00596870, Moho::SCollisionInfoSerializer::Deserialize)
 */
void SCollisionInfoSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const info = reinterpret_cast<SCollisionInfo*>(static_cast<std::uintptr_t>(objectPtr));
  if (archive == nullptr || info == nullptr) {
    return;
  }
  info->MemberDeserialize(archive);
}

/**
 * Address: 0x00596880 (FUN_00596880, Moho::SCollisionInfoSerializer::Serialize)
 */
void SCollisionInfoSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const info = reinterpret_cast<SCollisionInfo*>(static_cast<std::uintptr_t>(objectPtr));
  if (archive == nullptr || info == nullptr) {
    return;
  }
  info->MemberSerialize(archive);
}

/**
 * Address: 0x00BCBDD0 (FUN_00BCBDD0, dynamic initializer for the global
 * `SCollisionInfoSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
SCollisionInfoSerializer::SCollisionInfoSerializer()
  : mDeserialize(&SCollisionInfoSerializer::Deserialize)
  , mSerialize(&SCollisionInfoSerializer::Serialize)
{}

/**
 * Address: 0x00BF65B0 (FUN_00BF65B0, ??1SCollisionInfoSerializer@Moho@@QAE@@Z)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits in
 * and restores a self-linked sentinel state.
 */
SCollisionInfoSerializer::~SCollisionInfoSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x00598390 (FUN_00598390, gpg::SerSaveLoadHelper<Moho::SCollisionInfo>::Init)
 */
void SCollisionInfoSerializer::Init()
{
  gpg::RType* const type = ResolveSCollisionInfoType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mDeserialize;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerialize;
}

/**
 * Address: 0x0062F9F0 (FUN_0062F9F0, Moho::CPathPoint::MemberDeserialize)
 *
 * What it does:
 * Loads path-point position/direction vectors and state enum lanes from a
 * read archive payload.
 */
void CPathPoint::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (archive == nullptr) {
    return;
  }

  gpg::RRef positionOwner{};
  gpg::RType* const vectorType = ResolveVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  if (vectorType == nullptr) {
    return;
  }
  archive->Read(vectorType, &mPosition, positionOwner);

  gpg::RRef directionOwner{};
  archive->Read(vectorType, &mDirection, directionOwner);

  gpg::RRef stateOwner{};
  gpg::RType* const stateType = ResolveEPathPointStateType();
  GPG_ASSERT(stateType != nullptr);
  if (stateType == nullptr) {
    return;
  }
  archive->Read(stateType, &mState, stateOwner);
}

/**
 * Address: 0x0062FAA0 (FUN_0062FAA0, Moho::CPathPoint::MemberSerialize)
 *
 * What it does:
 * Writes `CPathPoint` position/direction vectors and path-state enum lanes
 * into archive storage using reflected runtime types.
 */
void CPathPoint::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (archive == nullptr) {
    return;
  }

  gpg::RRef positionOwner{};
  gpg::RRef directionOwner{};
  gpg::RRef stateOwner{};

  gpg::RType* const vectorType = ResolveVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Write(vectorType, &mPosition, positionOwner);
  archive->Write(vectorType, &mDirection, directionOwner);

  gpg::RType* const stateType = ResolveEPathPointStateType();
  GPG_ASSERT(stateType != nullptr);
  archive->Write(stateType, &mState, stateOwner);
}

/**
 * Address: 0x00BCBDB0 (FUN_00BCBDB0, register_SCollisionInfoTypeInfo)
 */
int moho::register_SCollisionInfoTypeInfo()
{
  (void)AcquireSCollisionInfoTypeInfo();
  return std::atexit(&cleanup_SCollisionInfoTypeInfo);
}

/**
 * Address: 0x00BCBD50 (FUN_00BCBD50, register_ECollisionTypeTypeInfo)
 */
void moho::register_ECollisionTypeTypeInfo()
{
  (void)AcquireECollisionTypeTypeInfo();
  (void)std::atexit(&cleanup_ECollisionTypeTypeInfo);
}

/**
 * Address: 0x00BD20C0 (FUN_00BD20C0, register_EPathPointStateTypeInfo)
 *
 * What it does:
 * Constructs/preregisters `EPathPointState` type info and schedules teardown.
 */
int moho::register_EPathPointStateTypeInfo()
{
  (void)construct_EPathPointStateTypeInfo();
  return std::atexit(&cleanup_EPathPointStateTypeInfo);
}

/**
 * Address: 0x00BD2120 (FUN_00BD2120, register_CPathPointTypeInfo)
 *
 * What it does:
 * Constructs/preregisters `CPathPoint` type info and schedules teardown.
 */
int moho::register_CPathPointTypeInfo()
{
  (void)construct_CPathPointTypeInfo();
  return std::atexit(&cleanup_CPathPointTypeInfo);
}

/**
 * Address: 0x00BCD390 (FUN_00BCD390, register_FastVectorCPathPointTypeAtexit)
 *
 * What it does:
 * Constructs/preregisters startup RTTI metadata for `gpg::fastvector<CPathPoint>`
 * and installs process-exit teardown.
 */
int moho::register_FastVectorCPathPointTypeAtexit()
{
  (void)preregister_FastVectorCPathPointType();
  return std::atexit(&cleanup_FastVectorCPathPointType);
}

/**
 * Address: 0x00BCD3B0 (FUN_00BCD3B0, register_CAiPathSplineStartupStatsCleanup)
 *
 * What it does:
 * Installs process-exit cleanup for one startup-owned AI path-spline stats slot.
 */
int moho::register_CAiPathSplineStartupStatsCleanup()
{
  return std::atexit(&cleanup_CAiPathSplineStartupStats);
}

namespace
{
  // `ECollisionTypePrimitiveSerializer`, `SCollisionInfoSerializer`,
  // `EPathPointStatePrimitiveSerializer`, and `CPathPointSerializer` are now
  // genuine namespace-scope globals (declared above), so their constructors
  // already run unconditionally at static-init time; this bootstrap no
  // longer needs to force them.
  struct CPathPointReflectionBootstrap
  {
    CPathPointReflectionBootstrap()
    {
      (void)moho::register_SCollisionInfoTypeInfo();
      moho::register_ECollisionTypeTypeInfo();
      (void)moho::register_FastVectorCPathPointTypeAtexit();
      (void)moho::register_CAiPathSplineStartupStatsCleanup();
      (void)moho::register_EPathPointStateTypeInfo();
      (void)moho::register_CPathPointTypeInfo();
    }
  };

  [[maybe_unused]] CPathPointReflectionBootstrap gCPathPointReflectionBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SCollisionInfoTypeInfo_9ee641, moho::register_SCollisionInfoTypeInfo)
GPG_PREREGISTER_INIT(register_ECollisionTypeTypeInfo_9ee641, moho::register_ECollisionTypeTypeInfo)
GPG_PREREGISTER_INIT(register_EPathPointStateTypeInfo_9ee641, moho::register_EPathPointStateTypeInfo)
GPG_PREREGISTER_INIT(register_CPathPointTypeInfo_9ee641, moho::register_CPathPointTypeInfo)

GPG_PREREGISTER_INIT(register_FastVectorCPathPointTypeAtexit_9ee641, moho::register_FastVectorCPathPointTypeAtexit)

GPG_PREREGISTER_INIT(preregister_FastVectorCPathPointType_9ee641, preregister_FastVectorCPathPointType)
GPG_PREREGISTER_INIT(construct_EPathPointStateTypeInfo_9ee641, construct_EPathPointStateTypeInfo)
GPG_PREREGISTER_INIT(construct_CPathPointTypeInfo_9ee641, construct_CPathPointTypeInfo)
