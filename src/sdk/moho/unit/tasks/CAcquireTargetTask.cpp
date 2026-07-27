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
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/Sim.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/SSTITarget.h"
#include "moho/task/ETaskStatus.h"
#include "moho/unit/core/EFireStateTypeInfo.h"
#include "gpg/core/utils/Logging.h"

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

  /**
   * Address: 0x005D8AD0 (FUN_005D8AD0)
   *
   * IDA signature:
   * char __userpurge sub_5D8AD0@<al>(int target@<ebx>, CAcquireTargetTask *task@<edi>);
   *
   * What it does:
   * Decides whether the acquire-target task should treat the current desired
   * `target` as exempt (drop it) this tick. Returns true when either:
   *   1. The unit is attacking, has a guard position (its own guarded-unit
   *      position when guarding a unit, otherwise its stored guard point), and
   *      has strayed farther than the blueprint guard-return radius from it, or
   *   2. The target resolves to an entity, the unit is immobile, and that entity
   *      is a recon blip the owning army sees as fake (per-army recon flags with
   *      the low 5 bits clear).
   * Returns false otherwise. Mirrors FUN_005D8AD0's two-branch structure.
   */
  [[nodiscard]] bool CheckTargetGuardExempt(const CAiTarget& target, CAcquireTargetTask& task)
  {
    Unit* const unit = task.mUnit;
    if (!unit->IsUnitState(EUnitState::UNITSTATE_Attacking)) {
      return false;
    }

    // Guard position: the guarded unit's live position when guarding a unit,
    // otherwise this unit's stored guard point.
    Wm3::Vector3f guardPosition = unit->GuardedPos;
    if (Unit* const guardedUnit = unit->GetGuardedUnit(); guardedUnit != nullptr) {
      guardPosition = guardedUnit->GetPosition();
    }

    // Wm3::Vector3f::Compare returns true when the vectors differ, so this is a
    // "guard position is set (non-zero)" test.
    if (const Wm3::Vector3f zero = Wm3::Vector3f::Zero(); Wm3::Vector3f::Compare(&guardPosition, &zero)) {
      const RUnitBlueprintAI& ai = unit->GetBlueprint()->AI;
      const Wm3::Vec3f& unitPosition = unit->GetPosition();
      const float deltaX = unitPosition.x - guardPosition.x;
      const float deltaY = unitPosition.y - guardPosition.y;
      const float deltaZ = unitPosition.z - guardPosition.z;
      const float distance = std::sqrt((deltaZ * deltaZ) + (deltaY * deltaY) + (deltaX * deltaX));
      if (distance > ai.GuardReturnRadius) {
        return true;
      }
    }

    // Recon-fake exemption: immobile unit targeting an entity that the owning
    // army sees as a fake recon blip.
    Entity* const targetEntity = target.targetEntity.GetObjectPtr();
    if (targetEntity != nullptr && !unit->IsMobile()) {
      if (ReconBlip* const blip = targetEntity->IsReconBlip(); blip != nullptr) {
        const std::int32_t armyIndex = unit->ArmyRef->ArmyId;
        if ((blip->mReconDat[static_cast<std::size_t>(armyIndex)].mReconFlags & 0x1Fu) == 0u) {
          return true;
        }
      }
    }

    return false;
  }
} // namespace

namespace moho
{
  gpg::RType* ManyToOneListener_EProjectileImpactEvent::sType = nullptr;
  gpg::RType* ManyToOneListener_ECollisionBeamEvent::sType = nullptr;
  gpg::RType* CAcquireTargetTask::sType = nullptr;
  gpg::RType* CAcquireTargetTask::sPointerType = nullptr;

  /**
   * Address: 0x005D88F0 (FUN_005D88F0)
   *
   * What it does:
   * Initializes projectile-impact listener weak-link storage to an empty owner
   * chain.
   */
  ManyToOneListener_EProjectileImpactEvent::ManyToOneListener()
    : WeakObject()
  {
    weakLinkHead_ = 0u;
  }

  /**
   * Address: 0x005D8930 (FUN_005D8930)
   *
   * What it does:
   * Initializes collision-beam listener weak-link storage to an empty owner
   * chain.
   */
  ManyToOneListener_ECollisionBeamEvent::ManyToOneListener()
    : WeakObject()
  {
    weakLinkHead_ = 0u;
  }

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
      cached = gpg::preregister_CAcquireTargetTaskPointerTypeStartup();
      if (!cached) {
        cached = gpg::LookupRType(typeid(CAcquireTargetTask*));
      }
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
   *
   * IDA signature:
   * Moho::ETaskStatus __thiscall TaskTick(Moho::CAcquireTargetTask *this);
   *
   * What it does:
   * One acquire-target scheduler tick. Computes the reschedule interval, then —
   * unless the unit is mid-unpack-move — resolves the weapon's target for this
   * tick: honours manual fire and primary-weapon target sharing, evaluates the
   * attacker's desired target (recording an attacker `State`), and, when no
   * higher-priority target applies, either intercepts the closest tracked
   * projectile (`TrackToTarget`) or picks the best enemy blip
   * (`FindBestEnemy` over `GetBlipsInRange`) and optionally auto-issues an attack
   * command. Returns `TASKSTATUS_Done` (manual fire), `TASKSTATUS_Wait`
   * (auto-initiate / can-target / mid-unpack-attacking short-circuit), or the
   * interval wait value (`ceil(TargetCheckInterval*10)` clamped to >=1, plus 1).
   */
  int CAcquireTargetTask::Execute()
  {
    RUnitBlueprintWeapon* const weaponBlueprint = mWeapon->mWeaponBlueprint;

    // Reschedule interval: ceil(TargetCheckInterval * 10) clamped to at least 1,
    // then +1 (the ">= 2 => wait N-1 beats" band). This is the default return.
    const float intervalTicksFloat = weaponBlueprint->TargetCheckInterval * 10.0f;
    int intervalTicks = static_cast<int>(std::ceil(intervalTicksFloat));
    if (intervalTicks < 1) {
      intervalTicks = 1;
    }
    const int waitStatus = intervalTicks + 1;

    // Selected-unit set used by the auto-issue attack command below.
    SEntitySetTemplateUnit selectedUnits{};
    (void)selectedUnits.AddUnit(mUnit);

    // Mid-unpack move short-circuit: units that must unpack before firing simply
    // wait while moving / (un)loading transport.
    const bool needsUnpack = mUnit->GetBlueprint()->AI.NeedUnpack != 0u;
    if (needsUnpack
        && (mUnit->IsUnitState(UNITSTATE_Moving) || mUnit->IsUnitState(UNITSTATE_TransportLoading)
            || mUnit->IsUnitState(UNITSTATE_WaitingForTransport))) {
      return waitStatus;
    }

    UnitWeapon* const weapon = mWeapon;
    if (weapon->mWeaponBlueprint != nullptr && weapon->mWeaponBlueprint->ManualFire != 0u) {
      return TASKSTATUS_Done;
    }

    // Clear the target blacklist whenever the unit has moved this tick.
    if (Wm3::Vector3f::Compare(&mUnit->Position, &mUnit->PrevPosition)) {
      WeaponResetBlacklist(*weapon);
    }

    if (mUnit->IsBeingBuilt() || mWeapon->mEnabled == 0u) {
      return waitStatus;
    }

    // Stop-on-primary-weapon-busy: if a different primary weapon already has an
    // attackable target, drop this weapon's target and wait.
    if (weaponBlueprint->StopOnPrimaryWeaponBusy != 0u) {
      if (UnitWeapon* const primaryWeapon = mAttacker->GetPrimaryWeapon(); primaryWeapon != nullptr) {
        if (mWeapon != primaryWeapon && primaryWeapon->mTarget.HasTarget()
            && UnitWeapon::CanAttackTarget(&primaryWeapon->mTarget, primaryWeapon)) {
          CAiTarget clearedTarget{};
          clearedTarget.targetPoint = -1;
          mWeapon->SetTarget(&clearedTarget);
          return waitStatus;
        }
      }
    }

    // Prefer-primary-weapon-target: adopt the primary weapon's target when this
    // weapon has a firing solution for it.
    if (weaponBlueprint->PrefersPrimaryWeaponTarget != 0u) {
      if (UnitWeapon* const primaryWeapon = mAttacker->GetPrimaryWeapon(); primaryWeapon != nullptr) {
        if (mWeapon != primaryWeapon && primaryWeapon->mTarget.HasTarget()
            && UnitWeapon::CanAttackTarget(&primaryWeapon->mTarget, mWeapon)) {
          const Wm3::Vec3f targetPositionGun = primaryWeapon->mTarget.GetTargetPosGun(false);
          float distanceSq = 0.0f;
          if (mWeapon->TargetSolutionStatusGun(&targetPositionGun, &distanceSq) == ESolutionStatus::TRS_Available) {
            mWeapon->SetTarget(&primaryWeapon->mTarget);
            return waitStatus;
          }
        }
      }
    }

    // Evaluate the attacker's desired target and record the resulting state.
    CAiTarget* const desiredTarget = mAttacker->GetDesiredTarget();
    const bool desiredHasNoTarget = desiredTarget->NoTarget();
    UnitWeapon* const desiredTargetWeapon = mAttacker->GetTargetWeapon(desiredTarget);

    // Whether this weapon "owns" the desired target (drives whether SetState runs).
    bool ownsDesiredTarget;
    if (desiredTarget->HasTarget() && desiredTargetWeapon != nullptr) {
      ownsDesiredTarget = (mWeapon == desiredTargetWeapon);
    } else {
      ownsDesiredTarget = (mWeapon == mAttacker->GetPrimaryWeapon());
    }
    mUpdateAttackerState = ownsDesiredTarget ? 1u : 0u;

    const ESolutionStatus desiredTooClose = mWeapon->TargetIsTooClose(desiredTarget);

    CAiAttackerImpl::State reportedState;
    if (!desiredTarget->HasTarget() || desiredHasNoTarget) {
      reportedState = CAiAttackerImpl::State::AAS_NoTarget;
    } else if (CheckTargetGuardExempt(*desiredTarget, *this)
               || mAttacker->IsTargetExempt(desiredTarget->GetEntity())) {
      reportedState = CAiAttackerImpl::State::AAS_TargetExempt;
    } else if (mTargetCooldown != 0 || mWeapon->mUnknown174 == 0u) {
      reportedState = CAiAttackerImpl::State::AAS_6;
    } else if (desiredTooClose != ESolutionStatus::TRS_Available
               || UnitWeapon::CanAttackTarget(desiredTarget, mWeapon)) {
      // `a2.mSpot != 0` in the binary == "too-close status is not Available".
      const bool canFly = mUnit->GetBlueprint()->Air.CanFly != 0u;
      if (canFly || desiredTooClose == ESolutionStatus::TRS_Available) {
        if (desiredTarget->targetType == EAiTargetType::AITARGET_Ground
            && mWeapon->mShotsAtTarget >= mWeapon->mWeaponBlueprint->AttackGroundTries
            && mUnit->CommandQueue->GetNextCommand() != nullptr) {
          reportedState = CAiAttackerImpl::State::AAS_OverShotCount;
        } else if (UnitWeapon::CanAttackTarget(desiredTarget, mWeapon)) {
          reportedState = CAiAttackerImpl::State::AAS_CanTarget;
          mWeapon->SetTarget(desiredTarget);
        } else {
          reportedState = CAiAttackerImpl::State::AAS_CannotTarget;
        }
      } else {
        reportedState = (desiredTooClose != ESolutionStatus::TRS_InsideMinRange)
          ? CAiAttackerImpl::State::AAS_2
          : CAiAttackerImpl::State::AAS_7;
      }
    } else {
      reportedState = CAiAttackerImpl::State::AAS_CannotAttack;
    }

    if (mUpdateAttackerState != 0u) {
      mAttacker->SetState(reportedState);
    }
    if (mTargetCooldown > 0) {
      --mTargetCooldown;
    }

    // Auto-initiate / can-target / mid-unpack-attacking short-circuit: wait.
    CAiTarget* const weaponTarget = &mWeapon->mTarget;
    if (mUnit->IsUnitState(UNITSTATE_Attacking)
        && ((mWeapon->mWeaponBlueprint->AutoInitiateAttackCommand != 0u && !CheckAutoInitiate())
            || mUnit->GetBlueprint()->AI.NeedUnpack != 0u
            || reportedState == CAiAttackerImpl::State::AAS_CanTarget)) {
      return TASKSTATUS_Wait;
    }

    // Keep the current weapon target if it is still attackable and in range.
    if (mWeapon->mWeaponBlueprint->AlwaysRecheckTarget == 0u
        && mWeapon->TargetIsTooClose(weaponTarget) == ESolutionStatus::TRS_Available) {
      if (UnitWeapon::CanAttackTarget(weaponTarget, mWeapon) && weaponTarget->HasTarget()) {
        Entity* const weaponTargetEntity = weaponTarget->GetEntity();
        if (!mAttacker->IsTargetExempt(weaponTargetEntity)) {
          return waitStatus;
        }
      }
    }

    // Hold-fire clears the weapon target and waits.
    if (mUnit->FireState == FIRESTATE_HoldFire) {
      if (mWeapon != nullptr) {
        CAiTarget clearedTarget{};
        clearedTarget.targetPoint = -1;
        mWeapon->SetTarget(&clearedTarget);
        return waitStatus;
      }
    }

    // Warn on a zero-radius weapon (mirrors the binary's diagnostic).
    {
      const float instanceMaxRadius = mWeapon->mAttributes.mMaxRadius;
      const float effectiveMaxRadius =
        (instanceMaxRadius < 0.0f) ? mWeapon->mAttributes.mBlueprint->MaxRadius : instanceMaxRadius;
      if (effectiveMaxRadius <= 0.0f) {
        gpg::Warnf(
          "%s's weapon %s has 0 max radius.",
          mUnit->GetBlueprint()->mBlueprintId.c_str(),
          mWeapon->mWeaponBlueprint->Label.c_str()
        );
      }
    }

    if (weaponBlueprint->TargetType == ERuleBPUnitWeaponTargetType::RULEWTT_Projectile) {
      // Projectile-tracking weapon: intercept the closest incoming projectile.
      if (Entity* const trackedProjectile = mAttacker->TrackToTarget(mWeapon); trackedProjectile != nullptr) {
        CAiTarget projectileTarget{};
        projectileTarget.UpdateTarget(trackedProjectile);
        mWeapon->SetTarget(&projectileTarget);
        return waitStatus;
      }
      if (!desiredTarget->HasTarget()) {
        CAiTarget clearedTarget{};
        clearedTarget.targetPoint = -1;
        mWeapon->SetTarget(&clearedTarget);
        return waitStatus;
      }
      return waitStatus;
    }

    // Normal weapon: search for the best enemy blip within effective range.
    const float instanceMaxRadius = mWeapon->mAttributes.mMaxRadius;
    const float floorRadius =
      (instanceMaxRadius < 0.0f) ? mWeapon->mAttributes.mBlueprint->MaxRadius : instanceMaxRadius;
    const float scaledRadius =
      (instanceMaxRadius < 0.0f) ? mWeapon->mAttributes.mBlueprint->MaxRadius : instanceMaxRadius;
    float searchRadius = weaponBlueprint->TrackingRadius * scaledRadius;
    if (searchRadius <= floorRadius) {
      searchRadius = floorRadius;
    }
    const bool use3DDistance = weaponBlueprint->Turreted != 0u || weaponBlueprint->SlavedToBody != 0u;

    if (Entity* const attachedTarget = ResolveAttachedParentDesiredTarget(mAttacker, mWeapon);
        attachedTarget != nullptr) {
      CAiTarget attachedAiTarget{};
      attachedAiTarget.UpdateTarget(attachedTarget);
      mWeapon->SetTarget(&attachedAiTarget);
      return waitStatus;
    }

    // The reschedule value (waitStatus == v6 == intervalTicks + 1) doubles as the
    // blip staleness bound: a value of 1 would use the raw cached list, but since
    // v6 is always >= 2, the binary always refreshes through GetBlipsInRange with
    // a max-age of v6 - 1 (== intervalTicks).
    gpg::core::FastVectorN<SWeakRefSlot, 20>* blipsInRange;
    if (waitStatus == 1) {
      blipsInRange = &mUnit->mBlipsInRange;
    } else {
      blipsInRange = &mUnit->GetBlipsInRange(static_cast<unsigned int>(waitStatus - 1));
    }

    Entity* const bestEnemy = mAttacker->FindBestEnemy(mWeapon, blipsInRange, searchRadius, use3DDistance);
    if (bestEnemy == nullptr) {
      if (desiredTarget->HasTarget() && UnitWeapon::CanAttackTarget(desiredTarget, mWeapon)) {
        mWeapon->SetTarget(desiredTarget);
        return waitStatus;
      }
      CAiTarget clearedTarget{};
      clearedTarget.targetPoint = -1;
      mWeapon->SetTarget(&clearedTarget);
      return waitStatus;
    }

    if (!CheckAutoInitiate()) {
      CAiTarget bestEnemyTarget{};
      bestEnemyTarget.UpdateTarget(bestEnemy);
      mWeapon->SetTarget(&bestEnemyTarget);
      return waitStatus;
    }

    // Auto-initiate an attack command on the best enemy.
    {
      CAiTarget bestEnemyTarget{};
      bestEnemyTarget.UpdateTarget(bestEnemy);
      mWeapon->SetTarget(&bestEnemyTarget);
    }

    const EntId bestEnemyId = bestEnemy->id_;
    SSTICommandIssueData attackCommand(EUnitCommandType::UNITCOMMAND_Attack);
    attackCommand.mTarget.mType = EAiTargetType::AITARGET_Entity;
    attackCommand.mTarget.mEnt = static_cast<std::uint32_t>(bestEnemyId);
    attackCommand.mTarget.mPos.x = 0.0f;
    attackCommand.mTarget.mPos.y = 0.0f;
    attackCommand.mTarget.mPos.z = 0.0f;
    (void)IssueCommandToSelectedUnits(mUnit->SimulationRef, selectedUnits, attackCommand, true);

    return waitStatus;
  }

  /**
   * Address: 0x005D79C0 (FUN_005D79C0)
   *
   * What it does:
   * Copies one linked target payload into `outTarget` and relinks its weak
   * entity reference at the source owner-chain head.
   */
  CAiTarget* CAcquireTargetTask::CopyLinkedTargetFromPointer(
    CAiTarget* const outTarget,
    const CAiTarget* const sourceTarget
  )
  {
    GPG_ASSERT(outTarget != nullptr);
    GPG_ASSERT(sourceTarget != nullptr);
    if (outTarget == nullptr || sourceTarget == nullptr) {
      return outTarget;
    }

    outTarget->targetType = sourceTarget->targetType;
    outTarget->targetEntity.ownerLinkSlot = sourceTarget->targetEntity.ownerLinkSlot;
    if (outTarget->targetEntity.ownerLinkSlot != nullptr) {
      auto** const ownerHead =
        reinterpret_cast<WeakPtr<Entity>**>(outTarget->targetEntity.ownerLinkSlot);
      outTarget->targetEntity.nextInOwner = *ownerHead;
      *ownerHead = &outTarget->targetEntity;
    } else {
      outTarget->targetEntity.nextInOwner = nullptr;
    }

    outTarget->position = sourceTarget->position;
    outTarget->targetPoint = sourceTarget->targetPoint;
    outTarget->targetIsMobile = sourceTarget->targetIsMobile;
    return outTarget;
  }

  /**
   * Address: 0x005D78E0 (FUN_005D78E0)
   *
   * What it does:
   * Resolves one desired target from the attacker's attached parent unit and
   * returns that entity when attack/range checks pass.
   */
  Entity* CAcquireTargetTask::ResolveAttachedParentDesiredTarget(
    CAiAttackerImpl* const attacker,
    UnitWeapon* const weapon
  )
  {
    if (attacker == nullptr || weapon == nullptr) {
      return nullptr;
    }

    Unit* const attackerUnit = attacker->GetUnit();
    if (attackerUnit == nullptr) {
      return nullptr;
    }

    Entity* const attachedEntity = attackerUnit->mAttachInfo.GetAttachTargetEntity();
    Unit* const attachedParentUnit = (attachedEntity != nullptr) ? attachedEntity->IsUnit() : nullptr;
    if (attachedParentUnit == nullptr || attachedParentUnit->AiAttacker == nullptr) {
      return nullptr;
    }

    CAiTarget* const parentDesiredTarget = attachedParentUnit->AiAttacker->GetDesiredTarget();
    if (parentDesiredTarget == nullptr) {
      return nullptr;
    }

    CAiTarget desiredTarget{};
    CopyLinkedTargetFromPointer(&desiredTarget, parentDesiredTarget);
    if (desiredTarget.GetEntity() == nullptr) {
      return nullptr;
    }
    if (!attacker->CanAttackTarget(&desiredTarget)) {
      return nullptr;
    }
    if (weapon->TargetIsTooClose(&desiredTarget) != ESolutionStatus::TRS_Available) {
      return nullptr;
    }

    return desiredTarget.GetEntity();
  }

  /**
   * Address: 0x005D97F0 (FUN_005D97F0, listener callback lane)
   */
  int CAcquireTargetTask::OnEvent(const EProjectileImpactEvent event)
  {
    if (mWeapon == nullptr || mWeapon->mWeaponBlueprint == nullptr) {
      return event;
    }
    if (mWeapon->mWeaponBlueprint->AutoInitiateAttackCommand == 0u) {
      return event;
    }

    if (event == ProjectileImpactEvent_Other) {
      HandleRetargetProbeOnListenerTick();
      return event;
    }

    if (event == ProjectileImpactEvent_HitTarget || event == ProjectileImpactEvent_SelfOrProjectile) {
      mTargetCooldown = 0;
      mWeapon->mUnknown170 = 0;
    }

    return event;
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
        CAiTarget commandTarget{};
        CopyLinkedTargetFromPointer(&commandTarget, &currentCommand->mTarget);
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
