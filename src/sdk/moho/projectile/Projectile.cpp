#include "moho/projectile/Projectile.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/projectile/CProjectileAttributes.h"
#include "moho/projectile/ProjectileStartupRegistrations.h"
#include "moho/sim/EImpactTypeTypeInfo.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  constexpr std::uint32_t kProjectileCollisionBucketFlags = 0x400u;
  constexpr float kProjectileUnsetValue = -1.0f;
  constexpr float kProjectileBounceVelocityDampingDefault = 0.5f;

  struct ProjectileImpactBroadcasterStorage
  {
    std::uint8_t bytes[0x08];
  };
  static_assert(sizeof(ProjectileImpactBroadcasterStorage) == 0x08, "Impact broadcaster storage size must be 0x08");

  struct ProjectileDeserializeRuntimeView
  {
    std::uint8_t mEntityStateStorage[0x270];
    ProjectileImpactBroadcasterStorage mImpactEventBroadcaster;
    moho::WeakPtr<moho::Entity> mLauncherWeak;
    Wm3::Vector3f mVelocity;
    Wm3::Vector3f mLocalAngularVelocity;
    Wm3::Vector3f mScaleVelocity;
    float mImpactInterpolation;
    bool mCollideSurface;
    bool mDoCollision;
    bool mTrackTarget;
    bool mVelocityAlign;
    bool mStayUpright;
    bool mLeadTarget;
    bool mStayUnderwater;
    bool mDestroyOnWater;
    float mTurnRateDegrees;
    float mMaxSpeed;
    float mAcceleration;
    Wm3::Vector3f mBallisticAcceleration;
    Wm3::Vector3f mUnknownVelocityVector;
    bool mUnknownTrajectoryFlag;
    std::uint8_t mUnknownTrajectoryPadding[3];
    float mDamage;
    float mDamageRadius;
    msvc8::string mDamageTypeName;
    moho::CAiTarget mTargetPosData;
    Wm3::Vector3f mImpactPosition;
    moho::WeakPtr<moho::Entity> mUnknownEntityWeak;
    std::uint32_t mLifetimeEnd;
    bool mBelowWater;
    std::uint8_t mBelowWaterPadding[3];
    std::int32_t mBounceLimit;
    std::int32_t mGroundTick;
    bool mDirectAwayFromGround;
    std::uint8_t mGroundDirectionPadding[3];
    Wm3::Vector3f mGroundDirection;
    float mBounceVelocityDamping;
    std::int32_t mUnknownBounceCount;
    Wm3::Vector3f mUnknownGroundVector;
    moho::EImpactType mImpactType;
    moho::CProjectileAttributes mAttributes;
    bool mUnknownTailFlag;
    std::uint8_t mTailPadding[3];
  };

  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mImpactEventBroadcaster) == 0x270,
    "ProjectileDeserializeRuntimeView::mImpactEventBroadcaster offset must be 0x270"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mLauncherWeak) == 0x278,
    "ProjectileDeserializeRuntimeView::mLauncherWeak offset must be 0x278"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mVelocity) == 0x280,
    "ProjectileDeserializeRuntimeView::mVelocity offset must be 0x280"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mLocalAngularVelocity) == 0x28C,
    "ProjectileDeserializeRuntimeView::mLocalAngularVelocity offset must be 0x28C"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mScaleVelocity) == 0x298,
    "ProjectileDeserializeRuntimeView::mScaleVelocity offset must be 0x298"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mImpactInterpolation) == 0x2A4,
    "ProjectileDeserializeRuntimeView::mImpactInterpolation offset must be 0x2A4"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mDestroyOnWater) == 0x2AF,
    "ProjectileDeserializeRuntimeView::mDestroyOnWater offset must be 0x2AF"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mTurnRateDegrees) == 0x2B0,
    "ProjectileDeserializeRuntimeView::mTurnRateDegrees offset must be 0x2B0"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mAcceleration) == 0x2B8,
    "ProjectileDeserializeRuntimeView::mAcceleration offset must be 0x2B8"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mBallisticAcceleration) == 0x2BC,
    "ProjectileDeserializeRuntimeView::mBallisticAcceleration offset must be 0x2BC"
  );
  // Layout evidence for this mid-structure lane is still being reconciled.
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mImpactPosition) == 0x31C,
    "ProjectileDeserializeRuntimeView::mImpactPosition offset must be 0x31C"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mUnknownEntityWeak) == 0x328,
    "ProjectileDeserializeRuntimeView::mUnknownEntityWeak offset must be 0x328"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mLifetimeEnd) == 0x330,
    "ProjectileDeserializeRuntimeView::mLifetimeEnd offset must be 0x330"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mBelowWater) == 0x334,
    "ProjectileDeserializeRuntimeView::mBelowWater offset must be 0x334"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mBounceLimit) == 0x338,
    "ProjectileDeserializeRuntimeView::mBounceLimit offset must be 0x338"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mGroundTick) == 0x33C,
    "ProjectileDeserializeRuntimeView::mGroundTick offset must be 0x33C"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mDirectAwayFromGround) == 0x340,
    "ProjectileDeserializeRuntimeView::mDirectAwayFromGround offset must be 0x340"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mGroundDirection) == 0x344,
    "ProjectileDeserializeRuntimeView::mGroundDirection offset must be 0x344"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mBounceVelocityDamping) == 0x350,
    "ProjectileDeserializeRuntimeView::mBounceVelocityDamping offset must be 0x350"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mUnknownBounceCount) == 0x354,
    "ProjectileDeserializeRuntimeView::mUnknownBounceCount offset must be 0x354"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mUnknownGroundVector) == 0x358,
    "ProjectileDeserializeRuntimeView::mUnknownGroundVector offset must be 0x358"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mImpactType) == 0x364,
    "ProjectileDeserializeRuntimeView::mImpactType offset must be 0x364"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mAttributes) == 0x368,
    "ProjectileDeserializeRuntimeView::mAttributes offset must be 0x368"
  );
  static_assert(
    offsetof(ProjectileDeserializeRuntimeView, mUnknownTailFlag) == 0x37C,
    "ProjectileDeserializeRuntimeView::mUnknownTailFlag offset must be 0x37C"
  );
  static_assert(sizeof(ProjectileDeserializeRuntimeView) == 0x380, "ProjectileDeserializeRuntimeView size must be 0x380");

  template <class T>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(T));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* CachedEntityType()
  {
    static gpg::RType* cached = nullptr;
    return CachedType<moho::Entity>(cached);
  }

  [[nodiscard]] gpg::RType* CachedImpactBroadcasterType()
  {
    return CachedType<moho::ManyToOneBroadcaster_EProjectileImpactEvent>(moho::ManyToOneBroadcaster_EProjectileImpactEvent::sType);
  }

  [[nodiscard]] gpg::RType* CachedWeakEntityType()
  {
    return CachedType<moho::WeakPtr<moho::Entity>>(moho::WeakPtr<moho::Entity>::sType);
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    return CachedType<Wm3::Vector3f>(cached);
  }

  [[nodiscard]] gpg::RType* CachedAiTargetType()
  {
    return CachedType<moho::CAiTarget>(moho::CAiTarget::sType);
  }

  [[nodiscard]] gpg::RType* CachedProjectileAttributesType()
  {
    return CachedType<moho::CProjectileAttributes>(moho::CProjectileAttributes::sType);
  }

  [[nodiscard]] gpg::RType* CachedProjectileType()
  {
    return CachedType<moho::Projectile>(moho::Projectile::sType);
  }

  [[nodiscard]] gpg::RRef MakeProjectileRef(moho::Projectile* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedProjectileType();
    return out;
  }

  void AddInstanceCounterDelta(moho::StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }

#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  void UnlinkImpactBroadcaster(ProjectileImpactBroadcasterStorage& broadcaster) noexcept
  {
    auto& weakLink = reinterpret_cast<moho::WeakPtr<void>&>(broadcaster);
    weakLink.UnlinkFromOwnerChain();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0069AC30 (FUN_0069AC30, Moho::Projectile::Projectile)
   *
   * What it does:
   * Constructs one archive-owned projectile shell from simulation owner
   * context, initializes runtime lanes, and increments the projectile
   * instance counter stat.
   */
  Projectile::Projectile(Sim* const sim)
    : Entity(sim, kProjectileCollisionBucketFlags)
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);
    view.mImpactEventBroadcaster = {};

    AddInstanceCounterDelta(InstanceCounter<Projectile>::GetStatItem(), 1L);

    view.mLauncherWeak.ClearLinkState();
    view.mVelocity = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mLocalAngularVelocity = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mScaleVelocity = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mImpactInterpolation = kProjectileUnsetValue;
    view.mCollideSurface = false;
    view.mDoCollision = false;
    view.mTrackTarget = false;
    view.mVelocityAlign = false;
    view.mStayUpright = false;
    view.mLeadTarget = false;
    view.mStayUnderwater = false;
    view.mDestroyOnWater = false;
    view.mTurnRateDegrees = 0.0f;
    view.mMaxSpeed = 0.0f;
    view.mAcceleration = 0.0f;
    view.mBallisticAcceleration = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mDamage = 0.0f;
    view.mDamageRadius = 0.0f;

    view.mTargetPosData.targetType = EAiTargetType::AITARGET_Entity;
    view.mTargetPosData.targetEntity.ClearLinkState();
    view.mTargetPosData.targetPoint = -1;
    view.mTargetPosData.targetIsMobile = false;
    view.mTargetPosData.PickTargetPoint();

    view.mUnknownVelocityVector = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mUnknownTrajectoryFlag = false;
    view.mImpactPosition = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mUnknownEntityWeak.ClearLinkState();
    view.mLifetimeEnd = 0u;
    view.mBelowWater = false;
    view.mBounceLimit = 0;
    view.mGroundTick = 0;
    view.mDirectAwayFromGround = false;
    view.mGroundDirection = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mBounceVelocityDamping = kProjectileBounceVelocityDampingDefault;
    view.mUnknownBounceCount = 0;
    view.mUnknownGroundVector = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    view.mImpactType = IMPACT_Air;
    view.mAttributes.mBlueprint = nullptr;
    view.mAttributes.mMaxZigZag = kProjectileUnsetValue;
    view.mAttributes.mZigZagFrequency = kProjectileUnsetValue;
    view.mAttributes.mDetonateAboveHeight = kProjectileUnsetValue;
    view.mAttributes.mDetonateBelowHeight = kProjectileUnsetValue;
    view.mUnknownTailFlag = false;
  }

  /**
   * Address: 0x0069AED0 (FUN_0069AED0, Moho::Projectile::~Projectile)
   *
   * What it does:
   * Unlinks intrusive weak/broadcaster lanes owned by this projectile and
   * decrements the projectile instance-counter stat before member/base
   * destructors run.
   */
  Projectile::~Projectile()
  {
    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);
    view.mTargetPosData.targetEntity.UnlinkFromOwnerChain();
    view.mLauncherWeak.UnlinkFromOwnerChain();

    AddInstanceCounterDelta(InstanceCounter<Projectile>::GetStatItem(), -1L);
    UnlinkImpactBroadcaster(view.mImpactEventBroadcaster);
  }

  /**
   * Address: 0x0069A610 (FUN_0069A610, Moho::Projectile::IsProjectile)
   *
   * What it does:
   * Returns this projectile pointer through the RTTI/downcast lane.
   */
  Projectile* Projectile::IsProjectile()
  {
    return this;
  }

  /**
   * Address: 0x0069E520 (FUN_0069E520, Moho::Projectile::MemberConstruct)
   *
   * What it does:
   * Reads owner `Sim` pointer from archive payload, allocates one projectile
   * object through the archive ctor lane, and publishes it as unowned
   * construct output.
   */
  void Projectile::MemberConstruct(gpg::ReadArchive* const archive, gpg::SerConstructResult* const result)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(result != nullptr);
    if (!archive || !result) {
      return;
    }

    Sim* ownerSim = nullptr;
    gpg::RRef ownerRef{};
    (void)archive->ReadPointer_Sim(&ownerSim, &ownerRef);

    Projectile* const object = new (std::nothrow) Projectile(ownerSim);
    result->SetUnowned(MakeProjectileRef(object), 0u);
  }

  /**
   * Address: 0x0069EDF0 (FUN_0069EDF0, Moho::InstanceCounter<Moho::Projectile>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for Projectile
   * instance counting (`Instance Counts_<type-name-without-underscores>`).
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::Projectile>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::Projectile).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  /**
   * Address: 0x006A0370 (FUN_006A0370, Moho::Projectile::MemberDeserialize)
   *
   * What it does:
   * Restores projectile runtime state from archive payload, including base
   * entity lanes, physics vectors, impact state, weak links, and attributes.
   */
  void Projectile::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    auto& view = *reinterpret_cast<ProjectileDeserializeRuntimeView*>(this);
    const gpg::RRef ownerRef{};

    archive->Read(CachedEntityType(), this, ownerRef);
    archive->Read(CachedImpactBroadcasterType(), &view.mImpactEventBroadcaster, ownerRef);
    archive->Read(CachedWeakEntityType(), &view.mLauncherWeak, ownerRef);
    archive->Read(CachedVector3fType(), &view.mVelocity, ownerRef);
    archive->Read(CachedVector3fType(), &view.mLocalAngularVelocity, ownerRef);
    archive->Read(CachedVector3fType(), &view.mScaleVelocity, ownerRef);

    archive->ReadFloat(&view.mImpactInterpolation);
    archive->ReadBool(&view.mCollideSurface);
    archive->ReadBool(&view.mDoCollision);
    archive->ReadBool(&view.mTrackTarget);
    archive->ReadBool(&view.mVelocityAlign);
    archive->ReadBool(&view.mStayUpright);
    archive->ReadBool(&view.mLeadTarget);
    archive->ReadBool(&view.mStayUnderwater);
    archive->ReadBool(&view.mDestroyOnWater);

    archive->ReadFloat(&view.mTurnRateDegrees);
    archive->ReadFloat(&view.mMaxSpeed);
    archive->ReadFloat(&view.mAcceleration);
    archive->Read(CachedVector3fType(), &view.mBallisticAcceleration, ownerRef);
    archive->Read(CachedVector3fType(), &view.mUnknownVelocityVector, ownerRef);
    archive->ReadBool(&view.mUnknownTrajectoryFlag);

    archive->ReadFloat(&view.mDamage);
    archive->ReadFloat(&view.mDamageRadius);
    archive->ReadString(&view.mDamageTypeName);

    archive->Read(CachedAiTargetType(), &view.mTargetPosData, ownerRef);
    archive->Read(CachedVector3fType(), &view.mImpactPosition, ownerRef);
    archive->Read(CachedWeakEntityType(), &view.mUnknownEntityWeak, ownerRef);

    archive->ReadUInt(&view.mLifetimeEnd);
    archive->ReadBool(&view.mBelowWater);
    archive->ReadInt(&view.mBounceLimit);
    archive->ReadInt(&view.mGroundTick);
    archive->ReadBool(&view.mDirectAwayFromGround);
    archive->Read(CachedVector3fType(), &view.mGroundDirection, ownerRef);
    archive->ReadFloat(&view.mBounceVelocityDamping);
    archive->ReadInt(&view.mUnknownBounceCount);
    archive->Read(CachedVector3fType(), &view.mUnknownGroundVector, ownerRef);
    archive->Read(CachedProjectileAttributesType(), &view.mAttributes, ownerRef);
    archive->ReadBool(&view.mUnknownTailFlag);
  }

  /**
   * Address: 0x006A0820 (FUN_006A0820, Moho::Projectile::MemberSerialize)
   *
   * What it does:
   * Serializes projectile runtime state to archive payload, including base
   * entity lanes, physics vectors, impact state, weak links, and attributes.
   */
  void Projectile::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const auto& view = *reinterpret_cast<const ProjectileDeserializeRuntimeView*>(this);
    const gpg::RRef ownerRef{};

    archive->Write(CachedEntityType(), this, ownerRef);
    archive->Write(CachedImpactBroadcasterType(), &view.mImpactEventBroadcaster, ownerRef);
    archive->Write(CachedWeakEntityType(), &view.mLauncherWeak, ownerRef);
    archive->Write(CachedVector3fType(), &view.mVelocity, ownerRef);
    archive->Write(CachedVector3fType(), &view.mLocalAngularVelocity, ownerRef);
    archive->Write(CachedVector3fType(), &view.mScaleVelocity, ownerRef);

    archive->WriteFloat(view.mImpactInterpolation);
    archive->WriteBool(view.mCollideSurface);
    archive->WriteBool(view.mDoCollision);
    archive->WriteBool(view.mTrackTarget);
    archive->WriteBool(view.mVelocityAlign);
    archive->WriteBool(view.mStayUpright);
    archive->WriteBool(view.mLeadTarget);
    archive->WriteBool(view.mStayUnderwater);
    archive->WriteBool(view.mDestroyOnWater);

    archive->WriteFloat(view.mTurnRateDegrees);
    archive->WriteFloat(view.mMaxSpeed);
    archive->WriteFloat(view.mAcceleration);
    archive->Write(CachedVector3fType(), &view.mBallisticAcceleration, ownerRef);
    archive->Write(CachedVector3fType(), &view.mUnknownVelocityVector, ownerRef);
    archive->WriteBool(view.mUnknownTrajectoryFlag);

    archive->WriteFloat(view.mDamage);
    archive->WriteFloat(view.mDamageRadius);
    archive->WriteString(const_cast<msvc8::string*>(&view.mDamageTypeName));

    archive->Write(CachedAiTargetType(), &view.mTargetPosData, ownerRef);
    archive->Write(CachedVector3fType(), &view.mImpactPosition, ownerRef);
    archive->Write(CachedWeakEntityType(), &view.mUnknownEntityWeak, ownerRef);

    archive->WriteUInt(view.mLifetimeEnd);
    archive->WriteBool(view.mBelowWater);
    archive->WriteInt(view.mBounceLimit);
    archive->WriteInt(view.mGroundTick);
    archive->WriteBool(view.mDirectAwayFromGround);
    archive->Write(CachedVector3fType(), &view.mGroundDirection, ownerRef);
    archive->WriteFloat(view.mBounceVelocityDamping);
    archive->WriteInt(view.mUnknownBounceCount);
    archive->Write(CachedVector3fType(), &view.mUnknownGroundVector, ownerRef);
    archive->Write(CachedProjectileAttributesType(), &view.mAttributes, ownerRef);
    archive->WriteBool(view.mUnknownTailFlag);
  }
} // namespace moho
