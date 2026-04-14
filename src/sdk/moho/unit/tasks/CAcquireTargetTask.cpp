#include "moho/unit/tasks/CAcquireTargetTask.h"

#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/entity/Entity.h"

using namespace moho;

namespace
{
  template <class T>
  [[nodiscard]] gpg::RType* CachedRType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(T));
    }
    return cached;
  }

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  [[nodiscard]] gpg::RType* CachedCTaskType()
  {
    if (!CTask::sType) {
      CTask::sType = gpg::LookupRType(typeid(CTask));
    }
    return CTask::sType;
  }

  [[nodiscard]] gpg::RType* CachedUnitWeaponType()
  {
    return CachedRType<UnitWeapon>();
  }

  [[nodiscard]] gpg::RType* CachedCAiAttackerImplType()
  {
    return CachedRType<CAiAttackerImpl>();
  }

  [[nodiscard]] gpg::RType* CachedUnitType()
  {
    return CachedRType<Unit>();
  }

  template <class T>
  [[nodiscard]] gpg::RRef MakeTrackedRef(T* object)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedRType<T>();
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = out.mType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = out.mType;
    }

    int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(out.mType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  template <class T>
  [[nodiscard]] T* ReadTrackedPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RType* const expectedType = CachedRType<T>();
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<T*>(upcast.mObj);
    }

    const char* const expectedName = expectedType ? expectedType->GetName() : "null";
    const char* const actualName = source.GetTypeName();
    const msvc8::string errorMessage = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expectedName ? expectedName : "null",
      actualName ? actualName : "null"
    );
    throw gpg::SerializationError(errorMessage.c_str());
  }

  template <class T>
  void WriteTrackedPointer(
    gpg::WriteArchive* archive,
    T* pointer,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef pointerRef = MakeTrackedRef(pointer);
    gpg::WriteRawPointer(archive, pointerRef, state, ownerRef);
  }

  void ClearWeakObjectChain(WeakObject& weakObject)
  {
    auto* cursor = reinterpret_cast<WeakObject::WeakLinkNodeView**>(weakObject.WeakLinkHeadSlot());
    while (cursor && *cursor) {
      WeakObject::WeakLinkNodeView* const node = *cursor;
      *cursor = node->nextInOwner;
      node->ownerLinkSlot = nullptr;
      node->nextInOwner = nullptr;
    }
  }

  void AddBase(gpg::RType* const ownerType, gpg::RType* const baseType, const std::int32_t offset)
  {
    GPG_ASSERT(ownerType != nullptr);
    GPG_ASSERT(baseType != nullptr);

    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = offset;
    field.v4 = 0;
    field.mDesc = nullptr;
    ownerType->AddBase(field);
  }

  void AddStatCounter(moho::StatItem* const statItem, const long delta) noexcept
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

  constexpr std::int32_t kAcquireTargetRetargetCooldownTicks = 30;
  constexpr std::int32_t kAcquireTargetRetargetReprobeThresholdPrimary = 5;
  constexpr std::int32_t kAcquireTargetRetargetReprobeThresholdSecondary = 10;
  constexpr std::int32_t kAcquireTargetBlacklistTicks = 10;

  [[nodiscard]] bool PositionUnchanged(const Wm3::Vector3f& lhs, const Wm3::Vector3f& rhs) noexcept
  {
    return std::memcmp(&lhs, &rhs, sizeof(Wm3::Vector3f)) == 0;
  }

  void AddWeaponBlacklistEntry(UnitWeapon& weapon, Entity* const entity, const std::int32_t value)
  {
    if (entity == nullptr) {
      return;
    }

    for (SBlackListInfo& entry : weapon.mBlacklist) {
      if (entry.mEntity.GetObjectPtr() == entity) {
        entry.mValue = value;
        return;
      }
    }

    SBlackListInfo entry{};
    entry.mEntity.ResetFromObject(entity);
    entry.mValue = value;
    weapon.mBlacklist.push_back(entry);
  }

  void ResetWeaponTargetAfterRetargetProbe(UnitWeapon& weapon)
  {
    CAiTarget clearedTarget{};
    clearedTarget.targetType = EAiTargetType::AITARGET_Entity;
    clearedTarget.targetEntity.ClearLinkState();
    clearedTarget.targetPoint = -1;
    clearedTarget.targetIsMobile = false;
    clearedTarget.PickTargetPoint();

    weapon.mTarget = clearedTarget;
    weapon.PickNewTargetAimSpot();
    weapon.mUnknown170 = 0;
    weapon.mUnknown174 = 1u;
    weapon.mShotsAtTarget = 0;
  }
} // namespace

namespace moho
{
  gpg::RType* ManyToOneListener_EProjectileImpactEvent::sType = nullptr;
  gpg::RType* ManyToOneListener_ECollisionBeamEvent::sType = nullptr;
  gpg::RType* CAcquireTargetTask::sType = nullptr;
  gpg::RType* CAcquireTargetTask::sPointerType = nullptr;

  /**
   * Address: 0x005DCDF0 (FUN_005DCDF0, Moho::CAcquireTargetTask::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI for `CAcquireTargetTask*`.
   */
  gpg::RType* CAcquireTargetTask::GetPointerType()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CAcquireTargetTask));
    }

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CAcquireTargetTask*));
      sPointerType = cached;
    }

    return cached;
  }

  /**
   * Address: 0x005DCC20 (FUN_005DCC20, Moho::InstanceCounter<Moho::CAcquireTargetTask>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for acquire-target
   * task instance counting (`Instance Counts_<type-name-without-underscores>`).
   */
  template <>
  StatItem* InstanceCounter<CAcquireTargetTask>::GetStatItem()
  {
    static StatItem* sEngineStat_InstanceCounts_CAcquireTargetTask = nullptr;
    if (sEngineStat_InstanceCounts_CAcquireTargetTask) {
      return sEngineStat_InstanceCounts_CAcquireTargetTask;
    }

    const std::string statName = BuildInstanceCounterStatPath(typeid(CAcquireTargetTask).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sEngineStat_InstanceCounts_CAcquireTargetTask = engineStats->GetItem(statName.c_str(), true);
    return sEngineStat_InstanceCounts_CAcquireTargetTask;
  }

  /**
   * Address: 0x005D8A20 (??0CAcquireTargetTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes the task, both listener lanes, and the weapon/attacker state
   * tracked by the acquire-target scheduler.
   */
  CAcquireTargetTask::CAcquireTargetTask(UnitWeapon* const weapon, CAiAttackerImpl* const attacker)
    : CTask(nullptr, false)
    , mWeapon(weapon)
    , mAttacker(attacker)
    , mUnit(weapon ? weapon->mUnit : nullptr)
    , mTargetCooldown(0)
    , mUpdateAttackerState(0u)
  {
    AddStatCounter(InstanceCounter<CAcquireTargetTask>::GetStatItem(), 1);
    static_cast<ManyToOneListener_EProjectileImpactEvent&>(*this).weakLinkHead_ = 0u;
    static_cast<ManyToOneListener_ECollisionBeamEvent&>(*this).weakLinkHead_ = 0u;
  }

  /**
   * Address: 0x005D88D0 (FUN_005D88D0, scalar deleting thunk)
   * Address: 0x005D8970 (FUN_005D8970, Moho::CAcquireTargetTask::~CAcquireTargetTask body)
   *
   * What it does:
   * Decrements acquire-target instance stats, clears both listener weak-link
   * chains, and runs base-task teardown.
   * Slot: 0
   */
  CAcquireTargetTask::~CAcquireTargetTask()
  {
    AddStatCounter(InstanceCounter<CAcquireTargetTask>::GetStatItem(), -1);
    ClearWeakObjectChain(static_cast<ManyToOneListener_ECollisionBeamEvent&>(*this));
    ClearWeakObjectChain(static_cast<ManyToOneListener_EProjectileImpactEvent&>(*this));
  }

  /**
   * Address: 0x005D8D10 (FUN_005D8D10, Moho::CAcquireTargetTask::TaskTick)
   * Slot: 1
   */
  int CAcquireTargetTask::Execute()
  {
    return 1;
  }

  /**
   * Address: 0x005D97F0 (FUN_005D97F0, listener callback lane)
   */
  int CAcquireTargetTask::HandleProjectileImpactListenerState(const int action)
  {
    if (mWeapon == nullptr || mWeapon->mWeaponBlueprint == nullptr) {
      return action;
    }
    if (mWeapon->mWeaponBlueprint->AutoInitiateAttackCommand == 0u) {
      return action;
    }

    if (action == 1) {
      HandleRetargetProbeOnListenerTick();
      return action;
    }

    if (action == 0 || action == 2) {
      mTargetCooldown = 0;
      mWeapon->mUnknown170 = 0;
    }

    return action;
  }

  /**
   * Address: 0x005D9830 (FUN_005D9830, listener callback lane)
   */
  int CAcquireTargetTask::HandleCollisionBeamListenerState(const int action)
  {
    if (mWeapon == nullptr || mWeapon->mWeaponBlueprint == nullptr) {
      return action;
    }
    if (mWeapon->mWeaponBlueprint->AutoInitiateAttackCommand == 0u) {
      return action;
    }

    if (action == 1) {
      HandleRetargetProbeOnListenerTick();
      return action;
    }

    if (action == 0 || action == 2) {
      mTargetCooldown = 0;
      mWeapon->mUnknown170 = 0;
    }

    return action;
  }

  /**
   * Address: 0x005D9630 (FUN_005D9630, helper used by listener action==1 lanes)
   *
   * What it does:
   * Probes desired/current entity targets for repeated stationary-aim cases,
   * then either repicks aim-spot, applies cooldown tagging, or blacklists and
   * clears the stuck target lane.
   */
  void CAcquireTargetTask::HandleRetargetProbeOnListenerTick()
  {
    GPG_ASSERT(mWeapon != nullptr);
    GPG_ASSERT(mAttacker != nullptr);
    GPG_ASSERT(mUnit != nullptr);
    if (mWeapon == nullptr || mAttacker == nullptr || mUnit == nullptr) {
      return;
    }

    CAiTarget* const desiredTarget = mAttacker->GetDesiredTarget();
    CAiTarget* const currentWeaponTarget = &mWeapon->mTarget;

    if (mWeapon->mWeaponIndex == 0 && desiredTarget != nullptr) {
      Entity* const desiredEntity = desiredTarget->GetEntity();
      if (
        desiredEntity != nullptr && mUnit->IsMobile()
        && PositionUnchanged(mUnit->Position, mUnit->PrevPosition)
        && desiredEntity->mCurrentLayer != LAYER_Air
        && PositionUnchanged(desiredEntity->Position, desiredEntity->PrevPosition)
      ) {
        ++mWeapon->mUnknown170;
        if (mWeapon->mUnknown170 > kAcquireTargetRetargetReprobeThresholdPrimary) {
          mTargetCooldown = kAcquireTargetRetargetCooldownTicks;
          return;
        }

        mWeapon->PickNewTargetAimSpot();
        return;
      }
    }

    Entity* const currentTargetEntity = currentWeaponTarget->GetEntity();
    if (
      currentTargetEntity != nullptr
      && PositionUnchanged(mUnit->Position, mUnit->PrevPosition)
      && currentTargetEntity->mCurrentLayer != LAYER_Air
      && PositionUnchanged(currentTargetEntity->Position, currentTargetEntity->PrevPosition)
    ) {
      ++mWeapon->mUnknown170;
      if (mWeapon->mUnknown170 > kAcquireTargetRetargetReprobeThresholdSecondary) {
        AddWeaponBlacklistEntry(*mWeapon, currentTargetEntity, kAcquireTargetBlacklistTicks);
        ResetWeaponTargetAfterRetargetProbe(*mWeapon);
        return;
      }

      mWeapon->PickNewTargetAimSpot();
    }
  }

  /**
   * Address: 0x005E16A0 (FUN_005E16A0, Moho::CAcquireTargetTask::MemberDeserialize)
   */
  void CAcquireTargetTask::MemberDeserialize(
    gpg::ReadArchive* const archive,
    CAcquireTargetTask* const task,
    const int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    gpg::RType* const baseTaskType = CachedCTaskType();
    archive->Read(baseTaskType, task, owner);

    task->mWeapon = ReadTrackedPointer<UnitWeapon>(archive, owner);
    task->mAttacker = ReadTrackedPointer<CAiAttackerImpl>(archive, owner);
    task->mUnit = ReadTrackedPointer<Unit>(archive, owner);
    archive->ReadInt(&task->mTargetCooldown);

    bool updateAttackerState = (task->mUpdateAttackerState != 0u);
    archive->ReadBool(&updateAttackerState);
    task->mUpdateAttackerState = updateAttackerState ? 1u : 0u;
  }

  /**
   * Address: 0x005E1750 (FUN_005E1750, Moho::CAcquireTargetTask::MemberSerialize)
   */
  void CAcquireTargetTask::MemberSerialize(
    gpg::WriteArchive* const archive,
    const CAcquireTargetTask* const task,
    const int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (!archive || !task) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    gpg::RType* const baseTaskType = CachedCTaskType();
    archive->Write(baseTaskType, task, owner);

    WriteTrackedPointer(archive, task->mWeapon, gpg::TrackedPointerState::Unowned, owner);
    WriteTrackedPointer(archive, task->mAttacker, gpg::TrackedPointerState::Unowned, owner);
    WriteTrackedPointer(archive, task->mUnit, gpg::TrackedPointerState::Unowned, owner);

    archive->WriteInt(task->mTargetCooldown);
    archive->WriteBool(task->mUpdateAttackerState != 0u);
  }

  /**
   * Address: 0x005D8C40 (FUN_005D8C40, Moho::CAcquireTargetTask::CheckAutoInitiate)
   *
   * What it does:
   * Returns true when auto-initiate should repick targeting because the queue
   * head is missing or the final attack command resolves to a dead/queued
   * focus entity.
   */
  bool CAcquireTargetTask::CheckAutoInitiate() const
  {
    if (mWeapon == nullptr || mWeapon->mWeaponBlueprint == nullptr || mUnit == nullptr) {
      return false;
    }

    if (mWeapon->mWeaponBlueprint->AutoInitiateAttackCommand == 0u) {
      return false;
    }

    CUnitCommandQueue* const commandQueue = mUnit->CommandQueue;
    CUnitCommand* const currentCommand = commandQueue ? commandQueue->GetCurrentCommand() : nullptr;
    CUnitCommand* const nextCommand = commandQueue ? commandQueue->GetNextCommand() : nullptr;

    if (currentCommand == nullptr) {
      return true;
    }

    if (nextCommand == nullptr) {
      const EUnitCommandType commandType = currentCommand->mVarDat.mCmdType;
      if (commandType == EUnitCommandType::UNITCOMMAND_Attack || commandType == EUnitCommandType::UNITCOMMAND_FormAttack)
      {
        CAiTarget commandTarget = currentCommand->mTarget;
        Entity* const focusEntity = commandTarget.GetEntity();
        if (
          commandTarget.targetType == EAiTargetType::AITARGET_Entity
          && (focusEntity == nullptr || focusEntity->Dead != 0u || focusEntity->DestroyQueuedFlag != 0u)
        ) {
          return true;
        }
      }
    }

    return false;
  }
} // namespace moho
