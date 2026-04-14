#include "moho/entity/CollisionBeamEntity.h"

#include <cstdint>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/CollisionBeamStartupRegistrations.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/WeakObject.h"
#include "moho/misc/Stats.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "Wm3Box3.h"

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

  struct CollisionBeamHelperRuntimeView
  {
    std::uint8_t mUnknown00_07[0x08];
    moho::WeakPtr<moho::Entity> mTargetEntity; // +0x08
    std::uint8_t mUnknown10_23[0x14];
    moho::WeakPtr<moho::Entity> mSourceEntity; // +0x24
  };
  static_assert(sizeof(CollisionBeamHelperRuntimeView) == 0x2C, "CollisionBeamHelperRuntimeView size must be 0x2C");
  static_assert(
    offsetof(CollisionBeamHelperRuntimeView, mTargetEntity) == 0x08,
    "CollisionBeamHelperRuntimeView::mTargetEntity offset must be 0x08"
  );
  static_assert(
    offsetof(CollisionBeamHelperRuntimeView, mSourceEntity) == 0x24,
    "CollisionBeamHelperRuntimeView::mSourceEntity offset must be 0x24"
  );

  /**
   * Address: 0x00673580 (FUN_00673580, Moho::CollisionBeamHelper::~CollisionBeamHelper)
   *
   * What it does:
   * Unlinks source and target entity weak-link lanes from their owner chains.
   */
  [[maybe_unused]] void DestroyCollisionBeamHelperLinks(CollisionBeamHelperRuntimeView& helper) noexcept
  {
    helper.mSourceEntity.UnlinkFromOwnerChain();
    helper.mTargetEntity.UnlinkFromOwnerChain();
  }
} // namespace

namespace moho
{
  gpg::RType* CollisionBeamEntity::sType = nullptr;

  /**
   * Address: 0x005DC340 (FUN_005DC340, Moho::ManyToOneBroadcaster_ECollisionBeamEvent::BroadcastEvent)
   *
   * What it does:
   * Rebinds one collision-beam broadcaster node to the supplied listener chain
   * head while preserving intrusive owner-chain integrity.
   */
  void ManyToOneBroadcaster<ECollisionBeamEvent>::BroadcastEvent(
    ManyToOneListener<ECollisionBeamEvent>* const listener
  )
  {
    void** const newOwnerLinkSlot = listener != nullptr
      ? reinterpret_cast<void**>(reinterpret_cast<WeakObject*>(listener)->WeakLinkHeadSlot())
      : nullptr;
    void** const currentOwnerLinkSlot = static_cast<void**>(ownerLinkSlot);
    if (newOwnerLinkSlot == currentOwnerLinkSlot) {
      return;
    }

    if (currentOwnerLinkSlot != nullptr) {
      void** cursor = currentOwnerLinkSlot;
      while (static_cast<ManyToOneBroadcaster<ECollisionBeamEvent>*>(*cursor) != this) {
        cursor = &static_cast<ManyToOneBroadcaster<ECollisionBeamEvent>*>(*cursor)->nextInOwner;
      }
      *cursor = nextInOwner;
    }

    ownerLinkSlot = newOwnerLinkSlot;
    if (newOwnerLinkSlot != nullptr) {
      nextInOwner = *newOwnerLinkSlot;
      *newOwnerLinkSlot = this;
    } else {
      nextInOwner = nullptr;
    }
  }

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
   * Address: 0x00672C00 (FUN_00672C00, Moho::CollisionBeamEntity::GetDerivedObjectRef)
   */
  gpg::RRef CollisionBeamEntity::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x00672C20 (FUN_00672C20, Moho::CollisionBeamEntity::IsCollisionBeam)
   */
  CollisionBeamEntity* CollisionBeamEntity::IsCollisionBeam()
  {
    return this;
  }

  /**
   * Address: 0x00672CB0 (FUN_00672CB0, Moho::CollisionBeamEntity::GetBoneCount)
   */
  int CollisionBeamEntity::GetBoneCount() const
  {
    return 3;
  }

  /**
   * Address: 0x006730B0 (FUN_006730B0, Moho::CollisionBeamEntity::GetBoneWorldTransform)
   *
   * What it does:
   * Returns the current entity world transform and, for non-zero bone indices,
   * offsets translation by `mLastBeamLength` along the transform's local +Z axis.
   */
  VTransform CollisionBeamEntity::GetBoneWorldTransform(const int boneIndex) const
  {
    VTransform result{};
    result.orient_.w = Orientation.x;
    result.orient_.x = Orientation.y;
    result.orient_.y = Orientation.z;
    result.orient_.z = Orientation.w;
    result.pos_.x = Position.x;
    result.pos_.y = Position.y;
    result.pos_.z = Position.z;

    if (boneIndex != 0) {
      const float orientationW = result.orient_.w;
      const float orientationX = result.orient_.x;
      const float orientationY = result.orient_.y;
      const float orientationZ = result.orient_.z;

      const float rotatedXTerm = (orientationW * orientationY) + (orientationZ * orientationX);
      const float rotatedYTerm = (orientationZ * orientationY) - (orientationW * orientationX);
      const float rotatedZTerm = 1.0f - ((orientationY * orientationY + orientationX * orientationX) * 2.0f);

      result.pos_.x += (rotatedXTerm * 2.0f) * mLastBeamLength;
      result.pos_.y += (rotatedYTerm * 2.0f) * mLastBeamLength;
      result.pos_.z += rotatedZTerm * mLastBeamLength;
    }

    return result;
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

    attacker->TransmitBeamImpactEvent(launcherWeapon, this);
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
   * Address: 0x006736B0 (FUN_006736B0, Moho::CollisionBeamEntity::OnDestroy)
   *
   * What it does:
   * Forwards base destroy flow, tears down active beam effect ownership, and
   * unlinks the effect weak-pointer lane from its owner chain.
   */
  void CollisionBeamEntity::OnDestroy()
  {
    Entity::OnDestroy();

    if (IEffect* const activeEffect = mEffect.GetObjectPtr(); activeEffect != nullptr) {
      reinterpret_cast<IEffectManager*>(SimulationRef->mEffectManager)->DestroyEffect(activeEffect);
      mEffect.UnlinkFromOwnerChain();
    }
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
