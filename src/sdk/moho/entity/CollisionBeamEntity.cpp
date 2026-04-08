#include "moho/entity/CollisionBeamEntity.h"

#include <cstdint>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/CollisionBeamStartupRegistrations.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "wm3/Box3.h"

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
  constexpr std::uint32_t kCollisionBeamCollisionBucketFlags = 0x800u;
  constexpr std::int32_t kCollisionBeamFamilySourceBaseWord = 0x500;
  constexpr std::uint32_t kEntityIdFamilySourceShift = 20u;
  constexpr std::uint32_t kCollisionBeamDebugColorDisabled = 0xFF00FF00u;
  constexpr std::uint32_t kCollisionBeamDebugColorEnabled = 0xFFFF0000u;
  gpg::RType* gCollisionBeamEntityBaseTypeCache = nullptr;

  template <typename T>
  [[nodiscard]] gpg::RType* ResolveSerializerType(gpg::RType*& cache)
  {
    if (cache == nullptr) {
      cache = gpg::LookupRType(typeid(T));
    }
    GPG_ASSERT(cache != nullptr);
    return cache;
  }

  [[nodiscard]] std::uint32_t ResolveCollisionBeamDebugColor(const bool enabled) noexcept
  {
    return enabled ? kCollisionBeamDebugColorEnabled : kCollisionBeamDebugColorDisabled;
  }

  void AddInstanceCounterDelta(moho::StatItem* const statItem, const long delta)
  {
    if (!statItem) {
      return;
    }

    (void)InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
  }

  [[nodiscard]] Wm3::Box3f BuildCollisionBeamDebugBox(const moho::CollisionBeamEntity& entity)
  {
    const Wm3::Quaternionf orientation{
      entity.Orientation.x,
      entity.Orientation.y,
      entity.Orientation.z,
      entity.Orientation.w,
    };

    const Wm3::Vector3f axisX = orientation.Rotate(Wm3::Vector3f{1.0f, 0.0f, 0.0f});
    const Wm3::Vector3f axisY = orientation.Rotate(Wm3::Vector3f{0.0f, 1.0f, 0.0f});
    const Wm3::Vector3f axisZ = orientation.Rotate(Wm3::Vector3f{0.0f, 0.0f, 1.0f});
    const Wm3::Vector3f extents{1.0f, 1.0f, 1.0f};
    return Wm3::Box3f(entity.Position, axisX, axisY, axisZ, extents);
  }

  [[nodiscard]] std::uint32_t BuildCollisionBeamFamilySourceBits(const moho::UnitWeapon* const launcherWeapon) noexcept
  {
    std::int32_t sourceWord = -1;
    if (launcherWeapon != nullptr && launcherWeapon->mUnit != nullptr && launcherWeapon->mUnit->ArmyRef != nullptr) {
      sourceWord = launcherWeapon->mUnit->ArmyRef->ArmyId;
    }

    const std::uint32_t packedFamilySourceWord = static_cast<std::uint32_t>(sourceWord | kCollisionBeamFamilySourceBaseWord);
    return packedFamilySourceWord << kEntityIdFamilySourceShift;
  }

  [[nodiscard]] moho::EntId ReserveCollisionBeamEntityId(const moho::UnitWeapon* const launcherWeapon) noexcept
  {
    moho::Sim* const ownerSim = launcherWeapon != nullptr ? launcherWeapon->mSim : nullptr;
    if (ownerSim != nullptr && ownerSim->mEntityDB != nullptr) {
      return static_cast<moho::EntId>(ownerSim->mEntityDB->DoReserveId(BuildCollisionBeamFamilySourceBits(launcherWeapon)));
    }

    return static_cast<moho::EntId>(BuildCollisionBeamFamilySourceBits(nullptr) | 1u);
  }

  void ResetCollisionBeamListenerLink(moho::ManyToOneBroadcaster_ECollisionBeamEvent& listener) noexcept
  {
    listener.ownerLinkSlot = nullptr;
    listener.nextInOwner = nullptr;
  }

  void UnlinkCollisionBeamListenerLink(moho::ManyToOneBroadcaster_ECollisionBeamEvent& listener) noexcept
  {
    auto& weakLink = reinterpret_cast<moho::WeakPtr<void>&>(listener);
    weakLink.UnlinkFromOwnerChain();
  }
} // namespace

namespace moho
{
  gpg::RType* CollisionBeamEntity::sType = nullptr;

  /**
   * Address: 0x00675070 (FUN_00675070, Moho::InstanceCounter<Moho::CollisionBeamEntity>::GetStatItem)
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::CollisionBeamEntity>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::CollisionBeamEntity).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  /**
   * Address: 0x006746B0 (FUN_006746B0, constructor instance-counter helper)
   *
   * What it does:
   * Increments `CollisionBeamEntity` instance-count stat and returns input.
   */
  [[maybe_unused]] void* IncrementCollisionBeamInstanceCounterAndReturn(void* const objectPtr)
  {
    AddInstanceCounterDelta(InstanceCounter<CollisionBeamEntity>::GetStatItem(), 1L);
    return objectPtr;
  }

  /**
   * Address: 0x00672F80 (FUN_00672F80, Moho::CollisionBeamEntity::CollisionBeamEntity)
   */
  CollisionBeamEntity::CollisionBeamEntity(const LuaPlus::LuaObject& specObject, UnitWeapon* const launcherWeapon)
    : Entity(launcherWeapon != nullptr ? launcherWeapon->mSim : nullptr, kCollisionBeamCollisionBucketFlags)
    , mListener{}
    , mSerializedBeamState(0.0f)
    , mCollisionCheckInterval(1)
    , mLastBeamLength(0.0f)
    , mEffect{}
    , mLauncher{}
    , mEnabled(1u)
    , mCollisionListenerBound(0u)
    , mPad296_297{0u, 0u}
    , mCollisionCheckTickCounter(0)
    , mPad29C_29F{0u, 0u, 0u, 0u}
  {
    ResetCollisionBeamListenerLink(mListener);
    (void)IncrementCollisionBeamInstanceCounterAndReturn(this);

    mCoordNode.ListUnlink();
    StandardInit(launcherWeapon != nullptr ? launcherWeapon->mSim : nullptr, ReserveCollisionBeamEntityId(launcherWeapon));

    mLauncher.ResetFromObject(launcherWeapon);

    SetLuaObject(specObject);
    LuaCall("OnCreate", const_cast<LuaPlus::LuaObject*>(&specObject));
  }

  /**
   * Address: 0x00672DD0 (FUN_00672DD0, Moho::CollisionBeamEntity::CollisionBeamEntity)
   */
  CollisionBeamEntity::CollisionBeamEntity(Sim* const ownerSim)
    : Entity(ownerSim, kCollisionBeamCollisionBucketFlags)
    , mListener{}
    , mSerializedBeamState(0.0f)
    , mCollisionCheckInterval(0)
    , mLastBeamLength(0.0f)
    , mEffect{}
    , mLauncher{}
    , mEnabled(0u)
    , mCollisionListenerBound(0u)
    , mPad296_297{0u, 0u}
    , mCollisionCheckTickCounter(0)
    , mPad29C_29F{0u, 0u, 0u, 0u}
  {
    ResetCollisionBeamListenerLink(mListener);
    AddInstanceCounterDelta(InstanceCounter<CollisionBeamEntity>::GetStatItem(), 1L);
  }

  /**
   * Address: 0x00672EC0 (FUN_00672EC0, Moho::CollisionBeamEntity destructor body)
   */
  CollisionBeamEntity::~CollisionBeamEntity()
  {
    mLauncher.UnlinkFromOwnerChain();
    mEffect.UnlinkFromOwnerChain();
    AddInstanceCounterDelta(InstanceCounter<CollisionBeamEntity>::GetStatItem(), -1L);
    UnlinkCollisionBeamListenerLink(mListener);
  }

  /**
   * Address: 0x00672C30 (FUN_00672C30, Moho::CollisionBeamEntity::SetEfxBeam)
   */
  void CollisionBeamEntity::SetEfxBeam(IEffect* const beamEmitter, const bool checkCollision)
  {
    mEffect.ResetFromObject(beamEmitter);

    if (mLauncher.GetObjectPtr() != nullptr && checkCollision) {
      CheckCollision();
    }
  }

  /**
   * Address: 0x00672C60 (FUN_00672C60, Moho::CollisionBeamEntity::SetCollisionCheckInterval)
   */
  void CollisionBeamEntity::SetCollisionCheckInterval(const std::int32_t intervalTicks)
  {
    mCollisionCheckInterval = intervalTicks;
  }

  /**
   * Address: 0x006731A0 (FUN_006731A0, Moho::CollisionBeamEntity::GetBoneLocalTransform)
   */
  VTransform CollisionBeamEntity::GetBoneLocalTransform(const int boneIndex) const
  {
    VTransform result{};
    result.orient_.w = 1.0f;
    result.orient_.x = 0.0f;
    result.orient_.y = 0.0f;
    result.orient_.z = 0.0f;
    result.pos_.x = 0.0f;
    result.pos_.y = 0.0f;
    result.pos_.z = 0.0f;

    if (boneIndex == 1) {
      result.pos_.z += mLastBeamLength;
    }

    return result;
  }

  /**
   * Address: 0x006731F0 (FUN_006731F0, Moho::CollisionBeamEntity::EnableCollisionCheck)
   */
  void CollisionBeamEntity::EnableCollisionCheck(const bool enabled)
  {
    mEnabled = static_cast<std::uint8_t>(enabled ? 1u : 0u);
    if (!enabled) {
      return;
    }

    mCollisionCheckTickCounter = mCollisionCheckInterval;
    if (mCollisionListenerBound != 0u) {
      return;
    }

    UnitWeapon* const launcherWeapon = mLauncher.GetObjectPtr();
    if (launcherWeapon == nullptr) {
      return;
    }

    Unit* const launcherUnit = launcherWeapon->mUnit;
    if (launcherUnit == nullptr) {
      return;
    }

    CAiAttackerImpl* const attacker = launcherUnit->AiAttacker;
    if (attacker == nullptr) {
      return;
    }

    const LuaPlus::LuaObject* const launcherWeaponLuaObject = &launcherWeapon->mLuaObj;
    attacker->TransmitBeamImpactEvent(launcherWeaponLuaObject, this);
    mCollisionListenerBound = 1u;
  }

  /**
   * Address: 0x006735C0 (FUN_006735C0, Moho::CollisionBeamEntity::MotionTick)
   */
  int CollisionBeamEntity::MotionTick()
  {
    if (mLauncher.GetObjectPtr() == nullptr) {
      return -1;
    }

    if (mAttachInfo.GetAttachTargetEntity() == nullptr) {
      return -1;
    }

    if (mEnabled != 0u) {
      const std::int32_t previousTick = mCollisionCheckTickCounter;
      const bool belowInterval = previousTick < mCollisionCheckInterval;
      mCollisionCheckTickCounter = previousTick + 1;
      if (!belowInterval) {
        CheckCollision();
        mCollisionCheckTickCounter = 0;
      }
    }

    if (dbg_CollisionBeam) {
      const Wm3::Box3f debugBox = BuildCollisionBeamDebugBox(*this);
      const std::uint32_t debugColor = ResolveCollisionBeamDebugColor(mEnabled != 0u);
      CDebugCanvas* const debugCanvas = SimulationRef->GetDebugCanvas();
      debugCanvas->AddWireBox(debugBox, debugColor);
    }

    return 1;
  }

  /**
   * Address: 0x00673A50 (FUN_00673A50, Moho::CollisionBeamEntity::MemberConstruct)
   */
  void CollisionBeamEntity::MemberConstruct(
    gpg::ReadArchive& archive,
    const int,
    const gpg::RRef& ownerRef,
    gpg::SerConstructResult& result
  )
  {
    Sim* ownerSim = nullptr;
    (void)archive.ReadPointer_Sim(&ownerSim, &ownerRef);

    CollisionBeamEntity* const object = new CollisionBeamEntity(ownerSim);

    gpg::RRef objectRef{};
    gpg::RRef_CollisionBeamEntity(&objectRef, object);
    result.SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x006762F0 (FUN_006762F0, Moho::CollisionBeamEntity::MemberDeserialize)
   */
  void CollisionBeamEntity::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};

    gpg::RType* const entityType = ResolveSerializerType<moho::Entity>(gCollisionBeamEntityBaseTypeCache);
    archive->Read(entityType, this, ownerRef);

    gpg::RType* const listenerType =
      ResolveSerializerType<ManyToOneBroadcaster_ECollisionBeamEvent>(ManyToOneBroadcaster_ECollisionBeamEvent::sType);
    archive->Read(listenerType, &mListener, ownerRef);

    archive->ReadFloat(&mSerializedBeamState);
    archive->ReadInt(&mCollisionCheckInterval);
    archive->ReadFloat(&mLastBeamLength);

    gpg::RType* const effectWeakType = ResolveSerializerType<WeakPtr<IEffect>>(WeakPtr<IEffect>::sType);
    archive->Read(effectWeakType, &mEffect, ownerRef);

    gpg::RType* const launcherWeakType = ResolveSerializerType<WeakPtr<UnitWeapon>>(WeakPtr<UnitWeapon>::sType);
    archive->Read(launcherWeakType, &mLauncher, ownerRef);

    bool enabled = false;
    archive->ReadBool(&enabled);
    mEnabled = static_cast<std::uint8_t>(enabled ? 1u : 0u);

    bool listenerBound = false;
    archive->ReadBool(&listenerBound);
    mCollisionListenerBound = static_cast<std::uint8_t>(listenerBound ? 1u : 0u);

    archive->ReadInt(&mCollisionCheckTickCounter);
  }

  /**
   * Address: 0x00676450 (FUN_00676450, Moho::CollisionBeamEntity::MemberSerialize)
   */
  void CollisionBeamEntity::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef ownerRef{};

    gpg::RType* const entityType = ResolveSerializerType<moho::Entity>(gCollisionBeamEntityBaseTypeCache);
    archive->Write(entityType, this, ownerRef);

    gpg::RType* const listenerType =
      ResolveSerializerType<ManyToOneBroadcaster_ECollisionBeamEvent>(ManyToOneBroadcaster_ECollisionBeamEvent::sType);
    archive->Write(listenerType, &mListener, ownerRef);

    archive->WriteFloat(mSerializedBeamState);
    archive->WriteInt(mCollisionCheckInterval);
    archive->WriteFloat(mLastBeamLength);

    gpg::RType* const effectWeakType = ResolveSerializerType<WeakPtr<IEffect>>(WeakPtr<IEffect>::sType);
    archive->Write(effectWeakType, &mEffect, ownerRef);

    gpg::RType* const launcherWeakType = ResolveSerializerType<WeakPtr<UnitWeapon>>(WeakPtr<UnitWeapon>::sType);
    archive->Write(launcherWeakType, &mLauncher, ownerRef);

    archive->WriteBool(mEnabled != 0u);
    archive->WriteBool(mCollisionListenerBound != 0u);
    archive->WriteInt(mCollisionCheckTickCounter);
  }
} // namespace moho
