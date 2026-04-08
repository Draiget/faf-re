#include "CFireWeaponTask.h"

#include <cmath>
#include <cstdlib>
#include <new>
#include <string>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/entity/Entity.h"
#include "moho/misc/StatItem.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptObject.h"
#include "moho/unit/core/CWeaponAttributes.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace moho
{
  class CFireWeaponTaskSerializer;
  class CFireWeaponTaskTypeInfo;
  void register_CFireWeaponTaskSerializer();
  void register_CFireWeaponTaskTypeInfo();

  template <>
  StatItem* InstanceCounter<CFireWeaponTask>::GetStatItem();
} // namespace moho

namespace
{
  constexpr std::int32_t kHoldFireState = 1;

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

  template <class T>
  gpg::RType* CachedRType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(T));
    }
    return cached;
  }

  template <class T>
  gpg::RRef MakeTrackedRef(T* object)
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

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(out.mType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
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
  T* ReadTrackedPointer(gpg::ReadArchive* archive, const gpg::RType* expectedType, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    if (gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType); upcast.mObj) {
      return static_cast<T*>(upcast.mObj);
    }

    const char* const expected = expectedType ? expectedType->GetName() : "null";
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "null",
      actual ? actual : "null"
    );
    throw std::runtime_error(msg.c_str());
  }

  [[nodiscard]] const Wm3::Vector3f& WeaponTargetPosition(const UnitWeapon* const weapon) noexcept
  {
    if (!weapon) {
      static const Wm3::Vector3f kZeroVector{};
      return kZeroVector;
    }

    if (weapon->mTarget.targetType == EAiTargetType::AITARGET_Entity) {
      if (Entity* const entity = weapon->mTarget.targetEntity.GetObjectPtr()) {
        return entity->GetPositionWm3();
      }
    }

    return weapon->mTarget.position;
  }

  [[nodiscard]] bool WeaponHasTarget(const UnitWeapon* const weapon) noexcept
  {
    return weapon != nullptr && weapon->mTarget.targetType != EAiTargetType::AITARGET_None;
  }

  [[nodiscard]] bool WeaponCanAttackTarget(UnitWeapon* const weapon) noexcept
  {
    if (weapon == nullptr || !WeaponHasTarget(weapon)) {
      return false;
    }

    return UnitWeapon::CanAttackTarget(&weapon->mTarget, weapon);
  }

  [[nodiscard]] bool WeaponCheckSilo(const UnitWeapon* const weapon) noexcept
  {
    if (!weapon || !weapon->mWeaponBlueprint || weapon->mWeaponBlueprint->CountedProjectile == 0u) {
      return true;
    }

    if (!weapon->mUnit || !weapon->mUnit->AiSiloBuild) {
      return true;
    }

    const std::int32_t storageCount =
      weapon->mUnit->AiSiloBuild->SiloGetStorageCount(static_cast<ESiloType>(weapon->mWeaponBlueprint->NukeWeapon));
    return storageCount != 0;
  }

  [[nodiscard]] bool WeaponTargetIsTooClose(const UnitWeapon* const weapon) noexcept
  {
    if (!weapon || !weapon->mUnit || !weapon->mWeaponBlueprint) {
      return false;
    }

    const float minRadius = weapon->mAttributes.mMinRadius >= 0.0f ? weapon->mAttributes.mMinRadius
                                                                   : weapon->mWeaponBlueprint->MinRadius;
    if (minRadius <= 0.0f) {
      return false;
    }

    const Wm3::Vector3f& unitPos = weapon->mUnit->GetPosition();
    const Wm3::Vector3f& targetPos = WeaponTargetPosition(weapon);
    const float dx = targetPos.x - unitPos.x;
    const float dy = targetPos.y - unitPos.y;
    const float dz = targetPos.z - unitPos.z;
    const float distSq = (dx * dx) + (dy * dy) + (dz * dz);
    return distSq < (minRadius * minRadius);
  }

  void FireWeapon(UnitWeapon* const weapon)
  {
    if (!weapon) {
      return;
    }

    (void)weapon->RunScript("OnFire");
    ++weapon->mShotsAtTarget;
  }

  template <class T>
  void WriteTrackedPointer(gpg::WriteArchive* archive, T* pointer, gpg::TrackedPointerState state, const gpg::RRef& owner)
  {
    const gpg::RRef objectRef = MakeTrackedRef(pointer);
    gpg::WriteRawPointer(archive, objectRef, state, owner);
  }
} // namespace

namespace moho
{
/**
 * Address: 0x006D3C50 (FUN_006D3C50, default construction body)
 *
 * What it does:
 * Initializes a reflected fire-task object with null unit/weapon lanes.
 */
CFireWeaponTask::CFireWeaponTask()
  : CTask(nullptr, false)
{
  AddStatCounter(InstanceCounter<CFireWeaponTask>::GetStatItem(), 1);
  mUnit = nullptr;
  mWeapon = nullptr;
  mFireClock = 0;
}

/**
 * Address: 0x006D3D40 (FUN_006D3D40, unit-weapon construction body)
 *
 * What it does:
 * Binds this task to a unit weapon, captures its owning unit, and resets the
 * fire clock.
 */
CFireWeaponTask::CFireWeaponTask(UnitWeapon* const weapon)
  : CTask(nullptr, false)
{
  AddStatCounter(InstanceCounter<CFireWeaponTask>::GetStatItem(), 1);
  mUnit = weapon ? weapon->mUnit : nullptr;
  mFireClock = 0;
  mWeapon = weapon;
}

/**
 * Address: 0x006D3CF0 (FUN_006D3CF0, non-deleting body)
 *
 * What it does:
 * Decrements the fire-task instance counter before base-task teardown.
 */
CFireWeaponTask::~CFireWeaponTask()
{
  AddStatCounter(InstanceCounter<CFireWeaponTask>::GetStatItem(), -1);
}

/**
 * Address: 0x006D3DC0 (FUN_006D3DC0, ?Execute@CFireWeaponTask@Moho@@UAEHXZ)
 *
 * What it does:
 * Services weapon-fire cooldown, checks target/weapon gates, and triggers a
 * weapon fire when the task is ready.
 */
int CFireWeaponTask::Execute()
{
  if (mFireClock != 0) {
    --mFireClock;
  }

  UnitWeapon* const weapon = mWeapon;
  if (!weapon || weapon->mEnabled == 0u) {
    return mFireClock != 0 ? 1 : -2;
  }

  if (weapon->mWeaponBlueprint && weapon->mWeaponBlueprint->ManualFire != 0u) {
    return mFireClock != 0 ? 1 : -2;
  }

  Unit* const unit = mUnit;
  if (!unit) {
    return 1;
  }

  if (mFireClock == 0 && unit->FireState != kHoldFireState && WeaponHasTarget(weapon)) {
    if (WeaponCanAttackTarget(weapon) && WeaponCheckSilo(weapon) && !WeaponTargetIsTooClose(weapon)) {
      const bool canAttackGround =
        weapon->mWeaponBlueprint == nullptr || weapon->mWeaponBlueprint->CannotAttackGround == 0u;
      if (canAttackGround || weapon->mTarget.targetType != EAiTargetType::AITARGET_Ground) {
        FireWeapon(weapon);

        float rateOfFire = weapon->mAttributes.mRateOfFire;
        if (rateOfFire < 0.0f && weapon->mAttributes.mBlueprint) {
          rateOfFire = weapon->mAttributes.mBlueprint->RateOfFire;
        }

        if (rateOfFire > 0.0f) {
          mFireClock = static_cast<std::int32_t>(10.0f / rateOfFire);
        }
      }
    }
  }

  return 1;
}

/**
 * Address: 0x006DF270 (FUN_006DF270, MemberDeserialize)
 *
 * What it does:
 * Loads the reflected base task, weapon pointer, unit pointer, and fire clock
 * from archive storage.
 */
void CFireWeaponTask::MemberDeserialize(gpg::ReadArchive* const archive, CFireWeaponTask* const task, int /*version*/, gpg::RRef* ownerRef)
{
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(task != nullptr);
  if (!archive || !task) {
    return;
  }

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  archive->Read(CachedRType<CTask>(), task, owner);
  task->mWeapon = ReadTrackedPointer<UnitWeapon>(archive, CachedRType<UnitWeapon>(), owner);
  task->mUnit = ReadTrackedPointer<Unit>(archive, CachedRType<Unit>(), owner);
  archive->ReadInt(&task->mFireClock);
}

/**
 * Address: 0x006DF300 (FUN_006DF300, MemberSerialize)
 *
 * What it does:
 * Saves the reflected base task, weapon pointer, unit pointer, and fire clock
 * into archive storage.
 */
void CFireWeaponTask::MemberSerialize(
  gpg::WriteArchive* const archive, const CFireWeaponTask* const task, int /*version*/, gpg::RRef* ownerRef
)
{
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(task != nullptr);
  if (!archive || !task) {
    return;
  }

  const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
  archive->Write(CachedRType<CTask>(), task, owner);
  WriteTrackedPointer(archive, task->mWeapon, gpg::TrackedPointerState::Unowned, owner);
  WriteTrackedPointer(archive, task->mUnit, gpg::TrackedPointerState::Unowned, owner);
  archive->WriteInt(task->mFireClock);
}
} // namespace moho

/**
 * Address: 0x006DC240 (FUN_006DC240, Moho::InstanceCounter<Moho::CFireWeaponTask>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for fire-task instance
 * counting.
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CFireWeaponTask>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  moho::EngineStats* const engineStats = moho::GetEngineStats();
  if (!engineStats) {
    return nullptr;
  }

  std::string statPath("Instance Counts_");
  const char* const rawTypeName = typeid(moho::CFireWeaponTask).name();
  for (const char* it = rawTypeName; it && *it != '\0'; ++it) {
    if (*it != '_') {
      statPath.push_back(*it);
    }
  }

  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

namespace
{
  struct FireWeaponTaskReflectionBootstrap
  {
    FireWeaponTaskReflectionBootstrap()
    {
      (void)moho::register_CFireWeaponTaskTypeInfo();
      (void)moho::register_CFireWeaponTaskSerializer();
    }
  };

  FireWeaponTaskReflectionBootstrap gFireWeaponTaskReflectionBootstrap;
} // namespace
