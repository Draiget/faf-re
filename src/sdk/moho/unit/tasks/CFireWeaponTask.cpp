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
#include "moho/misc/StatItem.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptObject.h"
#include "moho/unit/core/CWeaponAttributes.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace moho
{
  class CFireWeaponTaskTypeInfo;
  void register_CFireWeaponTaskTypeInfo();
} // namespace moho

namespace
{
  constexpr std::int32_t kHoldFireState = 1;

  /**
   * x87 `fld`/`fistp` conversion under the default control word: round to
   * nearest-even, and the integer-indefinite value 0x80000000 for NaN or any
   * value outside the int32 range (+inf included). `std::lrintf` is not a
   * substitute here: the MSVC CRT returns 0 for +inf.
   */
  [[nodiscard]] std::int32_t RoundToFireClockTicks(const float ticks) noexcept
  {
    constexpr float kInt32Bound = 2147483648.0f;
    if (!(ticks >= -kInt32Bound && ticks < kInt32Bound)) {
      return static_cast<std::int32_t>(0x80000000u);
    }
    return static_cast<std::int32_t>(std::nearbyint(ticks));
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
    if (!weapon) {
      return true;
    }

    return const_cast<UnitWeapon*>(weapon)->CheckSilo();
  }

  [[nodiscard]] bool WeaponTargetIsTooClose(UnitWeapon* const weapon) noexcept
  {
    if (!weapon) {
      return false;
    }

    return weapon->TargetIsTooClose(&weapon->mTarget) != ESolutionStatus::TRS_Available;
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
  mUnit = weapon ? weapon->mUnit : nullptr;
  mFireClock = 0;
  mWeapon = weapon;
}

/**
 * Address: 0x006D3CF0 (FUN_006D3CF0, non-deleting body)
 * Address: 0x006D3CD0 (FUN_006D3CD0, vtable-slot-2 scalar deleting
 * destructor: tail-calls the body below then conditionally frees the
 * object -- ordinary C++ `delete` semantics, not modeled as a separate
 * function here)
 *
 * What it does:
 * Base teardown only: `InstanceCounter<CFireWeaponTask>`'s -1, then `CTask`.
 */
CFireWeaponTask::~CFireWeaponTask()
{
}

/**
 * Address: 0x006D3AE0 (FUN_006D3AE0)
 */
std::int32_t CFireWeaponTask::GetFireClock() const
{
  return mFireClock;
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
    // `add eax, -1` at 0x006D3DCD wraps; a fistp-indefinite clock
    // (0x80000000) rolls over to INT_MAX instead of reaching zero.
    mFireClock = static_cast<std::int32_t>(static_cast<std::uint32_t>(mFireClock) - 1u);
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

  if (mFireClock == 0 && unit->mUnitVarDat.mFireState != kHoldFireState && WeaponHasTarget(weapon)) {
    // 0x006D3DC0 nests the gate as CanAttackTarget, then
    // `CanFire && CheckSilo && !TargetIsTooClose`. The `CanFire` term was
    // missing here, and for every non-winged unit that call reduces to
    // `weapon->mCanFire` -- the flag CAimManipulator raises once the turret has
    // actually reached its aim point. Without it the gun fires the moment it has
    // a target, while the turret is still slewing, so the shot leaves along
    // whatever direction the muzzle happens to be pointing rather than at the
    // ordered position.
    if (WeaponCanAttackTarget(weapon)
        && UnitWeapon::CanFire(weapon, &weapon->mTarget)
        && WeaponCheckSilo(weapon)
        && !WeaponTargetIsTooClose(weapon)) {
      const bool canAttackGround =
        weapon->mWeaponBlueprint == nullptr || weapon->mWeaponBlueprint->CannotAttackGround == 0u;
      if (canAttackGround || weapon->mTarget.targetType != EAiTargetType::AITARGET_Ground) {
        weapon->Fire();

        float rateOfFire = weapon->mAttributes.mRateOfFire;
        if (rateOfFire < 0.0f) {
          rateOfFire = weapon->mAttributes.mBlueprint->RateOfFire;
        }

        // 0x006D3EAA..0x006D3EC8: `divss 10.0, rof` then `fld`/`fistp` with no
        // zero guard, so the clock is rounded to nearest, not truncated. A
        // `RateOfFire = 0` weapon (the unlabeled target-acquisition dummy in
        // slot 0 of every T3 strategic bomber) gets fistp(+inf) = 0x80000000:
        // it fires once and its clock never counts back to zero. Skipping the
        // store for rof <= 0 re-fired that dummy every tick, pushing the
        // desired-target owner's mShotsAtTarget past AttackGroundTries and
        // letting CAcquireTargetTask report AAS_OverShotCount, which ends the
        // attack order before the Bomb weapon (slot 1) gets its run.
        mFireClock = RoundToFireClockTicks(10.0f / rateOfFire);
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
void CFireWeaponTask::MemberDeserialize(gpg::ReadArchive* const archive, int /*version*/, const gpg::RRef& ownerRef)
{
  GPG_ASSERT(archive != nullptr);
  if (!archive) {
    return;
  }

  archive->Read(CachedRType<CTask>(), this, ownerRef);
  mWeapon = ReadTrackedPointer<UnitWeapon>(archive, CachedRType<UnitWeapon>(), ownerRef);
  mUnit = ReadTrackedPointer<Unit>(archive, CachedRType<Unit>(), ownerRef);
  archive->ReadInt(&mFireClock);
}

/**
 * Address: 0x006DF300 (FUN_006DF300, MemberSerialize)
 *
 * What it does:
 * Saves the reflected base task, weapon pointer, unit pointer, and fire clock
 * into archive storage.
 */
void CFireWeaponTask::MemberSerialize(gpg::WriteArchive* const archive, int /*version*/, const gpg::RRef& ownerRef) const
{
  GPG_ASSERT(archive != nullptr);
  if (!archive) {
    return;
  }

  archive->Write(CachedRType<CTask>(), this, ownerRef);
  WriteTrackedPointer(archive, mWeapon, gpg::TrackedPointerState::Unowned, ownerRef);
  WriteTrackedPointer(archive, mUnit, gpg::TrackedPointerState::Unowned, ownerRef);
  archive->WriteInt(mFireClock);
}
} // namespace moho

namespace
{
  struct FireWeaponTaskReflectionBootstrap
  {
    FireWeaponTaskReflectionBootstrap()
    {
      // moho::CFireWeaponTaskSerializer registers itself via its own plain
      // global's dynamic initializer (see CFireWeaponTaskSerializer.cpp);
      // this bootstrap only needs to force the TypeInfo provider.
      (void)moho::register_CFireWeaponTaskTypeInfo();
    }
  };

  FireWeaponTaskReflectionBootstrap gFireWeaponTaskReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CFireWeaponTask>`, vtable 0x00E2E2EC.
   *
   * Address: 0x00BD8890 (FUN_00BD8890 -- constructs the global and registers its destructor.)
   * Address: 0x00BFE710 (FUN_00BFE710 -- the global's destructor.)
   * Address: 0x006DD3C0 (FUN_006DD3C0 -- an unreferenced copy of `Serialize`.)
   * Address: 0x006DE5F0 (FUN_006DE5F0 -- an unreferenced copy of `Serialize`.)
   * Address: 0x006DD3B0 (FUN_006DD3B0 -- an unreferenced copy of `Deserialize`.)
   * Address: 0x006DB850 (FUN_006DB850 -- `Init`.)
   * Address: 0x006D3EF0 (FUN_006D3EF0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006D3F00 (FUN_006D3F00 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CFireWeaponTaskSerializer : gpg::SerSaveLoadHelper<CFireWeaponTask>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B7BC4 -- process-global `CFireWeaponTaskSerializer` singleton.
  moho::CFireWeaponTaskSerializer gCFireWeaponTaskSerializer;
} // namespace
