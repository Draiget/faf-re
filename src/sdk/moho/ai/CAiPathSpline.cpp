#include "moho/ai/CAiPathSpline.h"

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
#include "moho/math/QuaternionMath.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

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
  forward.y = ((q.w * q.z) - (q.x * q.y)) * 2.0f;
  forward.z = 1.0f - (((q.z * q.z) + (q.y * q.y)) * 2.0f);

  Wm3::Vector3f source{};
  source.x = transform.pos_.x;
  source.y = 0.0f;
  source.z = transform.pos_.z;

  return SteeringParams(unit, source, destination, forward, 0.0f, true);
}

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

  [[nodiscard]] Wm3::Vector3f UnitForwardXZ(const Unit* unit) noexcept
  {
    if (!unit) {
      return {0.0f, 0.0f, 1.0f};
    }

    const Wm3::Vector3f forward = unit->GetTransform().orient_.Rotate(Wm3::Vector3f{0.0f, 0.0f, 1.0f});
    Wm3::Vector3f flat{forward.x, 0.0f, forward.z};
    const Wm3::Vector3f normalized = Wm3::Vector3f::NormalizeOrZero(flat);
    if (Wm3::Vector3f::LengthSq(normalized) <= 1.0e-6f) {
      return {0.0f, 0.0f, 1.0f};
    }
    return normalized;
  }

  void PushPathPoint(
    gpg::core::FastVectorN<CPathPoint, 20>& nodes,
    const Wm3::Vector3f& pos,
    const Wm3::Vector3f& forward,
    const EPathPointState state
  )
  {
    CPathPoint point{};
    point.mPosition = pos;
    point.mDirection = forward;
    point.mState = state;
    nodes.PushBack(point);
  }

} // namespace

gpg::RType* CAiPathSpline::sType = nullptr;
gpg::RType* SContinueInfo::sType = nullptr;

namespace
{
  class FastVectorCPathPointTypeInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
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

  class ECollisionTypePrimitiveSerializer
  {
  public:
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(ECollisionTypePrimitiveSerializer, mHelperNext) == 0x04,
    "ECollisionTypePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ECollisionTypePrimitiveSerializer, mHelperPrev) == 0x08,
    "ECollisionTypePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ECollisionTypePrimitiveSerializer, mDeserialize) == 0x0C,
    "ECollisionTypePrimitiveSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(ECollisionTypePrimitiveSerializer, mSerialize) == 0x10,
    "ECollisionTypePrimitiveSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(ECollisionTypePrimitiveSerializer) == 0x14, "ECollisionTypePrimitiveSerializer size must be 0x14"
  );
} // namespace

namespace
{
  alignas(moho::SCollisionInfoTypeInfo)
    unsigned char gSCollisionInfoTypeInfoStorage[sizeof(moho::SCollisionInfoTypeInfo)] = {};
  bool gSCollisionInfoTypeInfoConstructed = false;

  alignas(moho::ECollisionTypeTypeInfo)
    unsigned char gECollisionTypeTypeInfoStorage[sizeof(moho::ECollisionTypeTypeInfo)] = {};
  bool gECollisionTypeTypeInfoConstructed = false;

  alignas(ECollisionTypePrimitiveSerializer)
    unsigned char gECollisionTypePrimitiveSerializerStorage[sizeof(ECollisionTypePrimitiveSerializer)] = {};
  bool gECollisionTypePrimitiveSerializerConstructed = false;

  alignas(moho::SCollisionInfoSerializer)
    unsigned char gSCollisionInfoSerializerStorage[sizeof(moho::SCollisionInfoSerializer)] = {};
  bool gSCollisionInfoSerializerConstructed = false;

  alignas(moho::EPathPointStateTypeInfo)
    unsigned char gEPathPointStateTypeInfoStorage[sizeof(moho::EPathPointStateTypeInfo)] = {};
  bool gEPathPointStateTypeInfoConstructed = false;

  alignas(moho::CPathPointTypeInfo) unsigned char gCPathPointTypeInfoStorage[sizeof(moho::CPathPointTypeInfo)] = {};
  bool gCPathPointTypeInfoConstructed = false;
  alignas(FastVectorCPathPointTypeInfo)
    unsigned char gFastVectorCPathPointTypeStorage[sizeof(FastVectorCPathPointTypeInfo)] = {};
  bool gFastVectorCPathPointTypeConstructed = false;

  moho::EPathPointStatePrimitiveSerializer gEPathPointStatePrimitiveSerializer{};
  moho::CPathPointSerializer gCPathPointSerializer{};

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

  [[nodiscard]] gpg::RType* ResolveECollisionTypeType()
  {
    if (gECollisionTypeType == nullptr) {
      gECollisionTypeType = gpg::LookupRType(typeid(moho::ECollisionType));
    }
    return gECollisionTypeType;
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

  [[nodiscard]] ECollisionTypePrimitiveSerializer* AcquireECollisionTypePrimitiveSerializer()
  {
    if (!gECollisionTypePrimitiveSerializerConstructed) {
      new (gECollisionTypePrimitiveSerializerStorage) ECollisionTypePrimitiveSerializer();
      gECollisionTypePrimitiveSerializerConstructed = true;
    }

    return reinterpret_cast<ECollisionTypePrimitiveSerializer*>(gECollisionTypePrimitiveSerializerStorage);
  }

  [[nodiscard]] moho::SCollisionInfoSerializer* AcquireSCollisionInfoSerializer()
  {
    if (!gSCollisionInfoSerializerConstructed) {
      new (gSCollisionInfoSerializerStorage) moho::SCollisionInfoSerializer();
      gSCollisionInfoSerializerConstructed = true;
    }

    return reinterpret_cast<moho::SCollisionInfoSerializer*>(gSCollisionInfoSerializerStorage);
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

  void LoadFastVectorCPathPoint(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::CPathPoint>(reinterpret_cast<void*>(objectPtr));
    unsigned int count = 0;
    archive->ReadUInt(&count);

    const moho::CPathPoint fill{};
    gpg::FastVectorRuntimeResizeFill(&fill, count, view);

    gpg::RType* const elementType = ResolveCPathPointType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, view.ElementAtUnchecked(i), owner);
    }
  }

  void SaveFastVectorCPathPoint(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::CPathPoint>(reinterpret_cast<const void*>(objectPtr));
    const unsigned int count = view.begin ? static_cast<unsigned int>(view.Size()) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const elementType = ResolveCPathPointType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, view.ElementAtUnchecked(i), owner);
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
   * Address: 0x00BFA7F0 (FUN_00BFA7F0, cleanup_EPathPointStatePrimitiveSerializer)
   *
   * What it does:
   * Unlinks the recovered `EPathPointState` primitive serializer helper node.
   */
  gpg::SerHelperBase* cleanup_EPathPointStatePrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEPathPointStatePrimitiveSerializer);
  }

  void cleanup_EPathPointStatePrimitiveSerializer_atexit()
  {
    (void)cleanup_EPathPointStatePrimitiveSerializer();
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
   * Address: 0x00BFA880 (FUN_00BFA880, cleanup_CPathPointSerializer)
   *
   * What it does:
   * Unlinks the recovered `CPathPointSerializer` helper node.
   */
  gpg::SerHelperBase* cleanup_CPathPointSerializer()
  {
    return UnlinkSerializerNode(gCPathPointSerializer);
  }

  void cleanup_CPathPointSerializer_atexit()
  {
    (void)cleanup_CPathPointSerializer();
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
   * Address: 0x00BF6520 (FUN_00BF6520, cleanup_PrimitiveSerHelper_ECollisionType_int)
   *
   * What it does:
   * Unlinks the recovered primitive serializer helper node for `ECollisionType`.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_PrimitiveSerHelper_ECollisionType_int()
  {
    if (!gECollisionTypePrimitiveSerializerConstructed) {
      return nullptr;
    }
    return UnlinkSerializerNode(*AcquireECollisionTypePrimitiveSerializer());
  }

  void cleanup_PrimitiveSerHelper_ECollisionType_int_atexit()
  {
    (void)cleanup_PrimitiveSerHelper_ECollisionType_int();
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
   * Address: 0x00BF65B0 (FUN_00BF65B0, cleanup_SCollisionInfoSerializer)
   *
   * What it does:
   * Unlinks the recovered `SCollisionInfo` serializer helper node.
   */
  [[nodiscard]] gpg::SerHelperBase* cleanup_SCollisionInfoSerializer()
  {
    if (!gSCollisionInfoSerializerConstructed) {
      return nullptr;
    }
    return UnlinkSerializerNode(*AcquireSCollisionInfoSerializer());
  }

  void cleanup_SCollisionInfoSerializer_atexit()
  {
    (void)cleanup_SCollisionInfoSerializer();
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

  /**
   * Address: 0x0062F980 (FUN_0062F980, Deserialize_EPathPointState)
   *
   * What it does:
   * Reads one enum lane as `int` and stores it into `EPathPointState`.
   */
  void Deserialize_EPathPointState(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<moho::EPathPointState*>(static_cast<std::uintptr_t>(objectPtr)) =
      static_cast<moho::EPathPointState>(value);
  }

  /**
   * Address: 0x0062F9A0 (FUN_0062F9A0, Serialize_EPathPointState)
   *
   * What it does:
   * Writes one `EPathPointState` enum lane as `int`.
   */
  void Serialize_EPathPointState(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const value = reinterpret_cast<const moho::EPathPointState*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(*value));
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
 * Address: 0x005B2550 (FUN_005B2550)
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
 * Address: 0x005965E0 (FUN_005965E0, sub_5965E0)
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
 */
int CAiPathSpline::Update(Unit* const unit, const int updateMode)
{
  // TODO(binary-fidelity): current body is a provisional typed lift. Exact FA behavior
  // depends on sub_6990E0/sub_6992C0/sub_699760 math and additional physics helpers.
  ResetNodesToInline();
  mCurrentNodeIndex = 0;
  mNodeCount = 0;
  mPathType = static_cast<EPathType>(updateMode);

  if (!unit) {
    return 0;
  }

  const Wm3::Vector3f start = unit->GetPosition();
  const Wm3::Vector3f forward = UnitForwardXZ(unit);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  const float maxSpeed = blueprint ? blueprint->Physics.MaxSpeed : 0.0f;
  const float stepLen = std::max(0.1f, maxSpeed * 0.1f);
  const int nodeCount = (updateMode == 3 || updateMode == 4) ? 6 : 4;

  Wm3::Vector3f cursor = start;
  for (int i = 0; i < nodeCount; ++i) {
    cursor = cursor + forward * stepLen;
    PushPathPoint(nodes, cursor, forward, i + 1 == nodeCount ? PPS_8 : PPS_1);
  }

  mContinuation.mOldPosition = start;
  mContinuation.mOldDirection = forward;
  mContinuation.mOldVelocity = forward * stepLen;
  mContinuation.mState = PPS_0;

  mNodeCount = static_cast<std::uint32_t>(nodes.size());
  return static_cast<int>(mNodeCount);
}

/**
 * Address: 0x005B2FF0 (FUN_005B2FF0, Moho::CAiPathSpline::Generate)
 */
void CAiPathSpline::Generate(
  Unit* const unit,
  const Wm3::Vector3f& destination,
  const int pathType,
  const bool allowContinuation
)
{
  // TODO(binary-fidelity): current body is a provisional typed lift. Exact FA behavior
  // depends on full PPS state-machine reconstruction from 0x005B2FF0.
  ResetNodesToInline();
  mCurrentNodeIndex = 0;
  mNodeCount = 0;
  mPathType = static_cast<EPathType>(pathType);

  if (!unit || unit->IsDead()) {
    return;
  }

  Wm3::Vector3f start = unit->GetPosition();
  if (!allowContinuation && mContinuation.mState != PPS_0 && mContinuation.mState != PPS_8) {
    start = mContinuation.mOldPosition;
  }

  Wm3::Vector3f delta = destination - start;
  const float distSq2D = delta.x * delta.x + delta.z * delta.z;
  if (distSq2D < 1.0e-6f) {
    return;
  }

  const float distance2D = std::sqrt(distSq2D);
  const int steps = std::clamp(static_cast<int>(distance2D / 1.5f) + 1, 2, 20);

  for (int i = 1; i <= steps; ++i) {
    const float t = static_cast<float>(i) / static_cast<float>(steps);
    const Wm3::Vector3f pos = start + delta * t;
    Wm3::Vector3f dir = destination - pos;
    dir.y = 0.0f;
    dir = Wm3::Vector3f::NormalizeOrZero(dir);
    if (Wm3::Vector3f::LengthSq(dir) <= 1.0e-6f) {
      dir = UnitForwardXZ(unit);
    }

    PushPathPoint(nodes, pos, dir, i == steps ? PPS_8 : PPS_1);
  }

  if (!nodes.empty()) {
    const CPathPoint& tail = nodes.back();
    mContinuation.mOldPosition = tail.mPosition;
    mContinuation.mOldDirection = tail.mDirection;
    mContinuation.mOldVelocity = tail.mDirection;
    mContinuation.mState = tail.mState;
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

  auto& nodeView = gpg::AsFastVectorRuntimeView<CPathPoint>(this);
  const std::size_t nodeCount = nodeView.begin ? nodeView.Size() : 0u;
  gpg::RType* const nodeType = ResolveCPathPointType();
  for (std::size_t i = 0; i < nodeCount; ++i) {
    gpg::RRef nodeRef{};
    nodeRef.mObj = nodeView.ElementAtUnchecked(i);
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

  const auto& nodeView = gpg::AsFastVectorRuntimeView<CPathPoint>(this);
  const std::size_t nodeCount = nodeView.begin ? nodeView.Size() : 0u;
  gpg::RType* const nodeType = ResolveCPathPointType();
  for (std::size_t i = 0; i < nodeCount; ++i) {
    gpg::RRef nodeRef{};
    nodeRef.mObj = const_cast<CPathPoint*>(nodeView.ElementAtUnchecked(i));
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

  auto& view = gpg::AsFastVectorRuntimeView<CPathPoint>(obj);
  if (!view.begin || static_cast<std::size_t>(ind) >= GetCount(obj)) {
    return out;
  }

  out.mObj = view.ElementAtUnchecked(static_cast<std::size_t>(ind));
  return out;
}

size_t FastVectorCPathPointTypeInfo::GetCount(void* obj) const
{
  if (!obj) {
    return 0u;
  }

  const auto& view = gpg::AsFastVectorRuntimeView<CPathPoint>(obj);
  if (!view.begin) {
    return 0u;
  }

  return view.Size();
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

  auto& view = gpg::AsFastVectorRuntimeView<CPathPoint>(obj);
  CPathPoint fill{};
  fill.mPosition = Wm3::Vector3f{};
  fill.mDirection = Wm3::Vector3f{};
  fill.mState = PPS_7;
  gpg::FastVectorRuntimeResizeFill(&fill, static_cast<unsigned int>(count), view);
}

void EPathPointStatePrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = ResolveEPathPointStateType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
  type->serLoadFunc_ = mDeserialize;
  type->serSaveFunc_ = mSerialize;
}

/**
 * Address: 0x00598400 (FUN_00598400, gpg::PrimitiveSerHelper_ECollisionType_int::Deserialize)
 */
void ECollisionTypePrimitiveSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (archive == nullptr || objectPtr == 0) {
    return;
  }

  int value = 0;
  archive->ReadInt(&value);
  *reinterpret_cast<ECollisionType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<ECollisionType>(value);
}

/**
 * Address: 0x00598420 (FUN_00598420, gpg::PrimitiveSerHelper_ECollisionType_int::Serialize)
 */
void ECollisionTypePrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (archive == nullptr || objectPtr == 0) {
    return;
  }

  const auto* const value = reinterpret_cast<const ECollisionType*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(*value));
}

void ECollisionTypePrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = ResolveECollisionTypeType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
  type->serLoadFunc_ = mDeserialize;
  type->serSaveFunc_ = mSerialize;
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
 * Address: 0x00598390 (FUN_00598390, gpg::SerSaveLoadHelper<Moho::SCollisionInfo>::Init)
 */
void SCollisionInfoSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = ResolveSCollisionInfoType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mDeserialize;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerialize;
}

/**
 * Address: 0x0062F790 (FUN_0062F790, CPathPointSerializer::Deserialize)
 *
 * What it does:
 * Loads `mPosition`, `mDirection`, and `mState` lanes for a `CPathPoint`.
 */
void CPathPointSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (archive == nullptr || objectPtr == 0) {
    return;
  }

  auto* const point = reinterpret_cast<CPathPoint*>(static_cast<std::uintptr_t>(objectPtr));
  gpg::RRef valueRef{};
  gpg::RRef directionRef{};
  gpg::RRef stateRef{};

  gpg::RType* const vectorType = ResolveVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Read(vectorType, &point->mPosition, valueRef);
  archive->Read(vectorType, &point->mDirection, directionRef);

  gpg::RType* const stateType = ResolveEPathPointStateType();
  GPG_ASSERT(stateType != nullptr);
  archive->Read(stateType, &point->mState, stateRef);
}

/**
 * Address: 0x0062F7A0 (FUN_0062F7A0, CPathPointSerializer::Serialize)
 *
 * What it does:
 * Saves `mPosition`, `mDirection`, and `mState` lanes for a `CPathPoint`.
 */
void CPathPointSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  if (archive == nullptr || objectPtr == 0) {
    return;
  }

  auto* const point = reinterpret_cast<CPathPoint*>(static_cast<std::uintptr_t>(objectPtr));
  gpg::RRef valueRef{};
  gpg::RRef directionRef{};
  gpg::RRef stateRef{};

  gpg::RType* const vectorType = ResolveVector3fType();
  GPG_ASSERT(vectorType != nullptr);
  archive->Write(vectorType, &point->mPosition, valueRef);
  archive->Write(vectorType, &point->mDirection, directionRef);

  gpg::RType* const stateType = ResolveEPathPointStateType();
  GPG_ASSERT(stateType != nullptr);
  archive->Write(stateType, &point->mState, stateRef);
}

void CPathPointSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = ResolveCPathPointType();
  GPG_ASSERT(type != nullptr);
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
  type->serLoadFunc_ = mDeserialize;
  type->serSaveFunc_ = mSerialize;
}

namespace
{
  /**
   * Address: 0x00598440 (FUN_00598440, construct_PrimitiveSerHelper_ECollisionType_int)
   *
   * What it does:
   * Constructs startup serializer-helper state for `ECollisionType` and binds
   * raw integer load/save callbacks.
   */
  [[nodiscard]] ECollisionTypePrimitiveSerializer* construct_PrimitiveSerHelper_ECollisionType_int()
  {
    ECollisionTypePrimitiveSerializer* const serializer = AcquireECollisionTypePrimitiveSerializer();
    InitializeSerializerNode(*serializer);
    serializer->mDeserialize = &ECollisionTypePrimitiveSerializer::Deserialize;
    serializer->mSerialize = &ECollisionTypePrimitiveSerializer::Serialize;
    return serializer;
  }
} // namespace

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
 * Address: 0x00BCBD70 (FUN_00BCBD70, register_PrimitiveSerHelper_ECollisionType_int)
 */
void moho::register_PrimitiveSerHelper_ECollisionType_int()
{
  (void)construct_PrimitiveSerHelper_ECollisionType_int();
  (void)std::atexit(&cleanup_PrimitiveSerHelper_ECollisionType_int_atexit);
}

/**
 * Address: 0x00BCBDD0 (FUN_00BCBDD0, register_SCollisionInfoSerializer)
 */
void moho::register_SCollisionInfoSerializer()
{
  SCollisionInfoSerializer* const serializer = AcquireSCollisionInfoSerializer();
  InitializeSerializerNode(*serializer);
  serializer->mDeserialize = &SCollisionInfoSerializer::Deserialize;
  serializer->mSerialize = &SCollisionInfoSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_SCollisionInfoSerializer_atexit);
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
 * Address: 0x00BD20E0 (FUN_00BD20E0, register_EPathPointStatePrimitiveSerializer)
 *
 * What it does:
 * Registers primitive serializer callbacks for `EPathPointState`.
 */
int moho::register_EPathPointStatePrimitiveSerializer()
{
  InitializeSerializerNode(gEPathPointStatePrimitiveSerializer);
  gEPathPointStatePrimitiveSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(
    &Deserialize_EPathPointState
  );
  gEPathPointStatePrimitiveSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(
    &Serialize_EPathPointState
  );
  gEPathPointStatePrimitiveSerializer.RegisterSerializeFunctions();
  return std::atexit(&cleanup_EPathPointStatePrimitiveSerializer_atexit);
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
 * Address: 0x00BD2140 (FUN_00BD2140, register_CPathPointSerializer)
 *
 * What it does:
 * Registers `CPathPoint` serializer callbacks and schedules helper teardown.
 */
void moho::register_CPathPointSerializer()
{
  InitializeSerializerNode(gCPathPointSerializer);
  gCPathPointSerializer.mDeserialize = &CPathPointSerializer::Deserialize;
  gCPathPointSerializer.mSerialize = &CPathPointSerializer::Serialize;
  gCPathPointSerializer.RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_CPathPointSerializer_atexit);
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
  struct CPathPointReflectionBootstrap
  {
    CPathPointReflectionBootstrap()
    {
      (void)moho::register_SCollisionInfoTypeInfo();
      moho::register_ECollisionTypeTypeInfo();
      moho::register_PrimitiveSerHelper_ECollisionType_int();
      moho::register_SCollisionInfoSerializer();
      (void)moho::register_FastVectorCPathPointTypeAtexit();
      (void)moho::register_CAiPathSplineStartupStatsCleanup();
      (void)moho::register_EPathPointStateTypeInfo();
      (void)moho::register_EPathPointStatePrimitiveSerializer();
      (void)moho::register_CPathPointTypeInfo();
      moho::register_CPathPointSerializer();
    }
  };

  [[maybe_unused]] CPathPointReflectionBootstrap gCPathPointReflectionBootstrap;
} // namespace
