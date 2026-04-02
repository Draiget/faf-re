#include "moho/unit/tasks/CAcquireTargetTask.h"

#include <cstdlib>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"

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
} // namespace

namespace moho
{
  gpg::RType* ManyToOneListener_EProjectileImpactEvent::sType = nullptr;
  gpg::RType* ManyToOneListener_ECollisionBeamEvent::sType = nullptr;
  gpg::RType* CAcquireTargetTask::sType = nullptr;

  template <>
  StatItem* InstanceCounter<CAcquireTargetTask>::GetStatItem()
  {
    static StatItem* sEngineStat_InstanceCounts_CAcquireTargetTask = nullptr;
    if (sEngineStat_InstanceCounts_CAcquireTargetTask) {
      return sEngineStat_InstanceCounts_CAcquireTargetTask;
    }

    std::string statName = BuildInstanceCounterStatPath(typeid(CAcquireTargetTask).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (!engineStats) {
      return nullptr;
    }

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
   * Address: 0x005D88D0 (FUN_005D88D0, Moho::CAcquireTargetTask::dtr)
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
    if (action == 0 || action == 2) {
      mTargetCooldown = 0;
      if (mWeapon) {
        mWeapon->mShotsAtTarget = 0;
      }
    }

    return action;
  }

  /**
   * Address: 0x005D9830 (FUN_005D9830, listener callback lane)
   */
  int CAcquireTargetTask::HandleCollisionBeamListenerState(const int action)
  {
    if (action == 0 || action == 2) {
      mUpdateAttackerState = 0u;
      if (mAttacker) {
        (void)mAttacker;
      }
    }

    return action;
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
   */
  bool CAcquireTargetTask::CheckAutoInitiate() const
  {
    return false;
  }
} // namespace moho
