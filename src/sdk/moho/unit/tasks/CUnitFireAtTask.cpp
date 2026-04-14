#include "moho/unit/tasks/CUnitFireAtTask.h"

#include <new>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"

namespace
{
  [[nodiscard]] bool MatchesManualFireProfile(const moho::RUnitBlueprintWeapon* const weaponBlueprint, const std::int32_t isNuclearMode)
  {
    if (weaponBlueprint == nullptr) {
      return false;
    }

    if (weaponBlueprint->ManualFire == 0u || weaponBlueprint->OverChargeWeapon != 0u) {
      return false;
    }

    const bool isNukeWeapon = weaponBlueprint->NukeWeapon != 0u;
    if (isNuclearMode == 1) {
      return isNukeWeapon;
    }

    if (isNuclearMode == 0) {
      return !isNukeWeapon;
    }

    return false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0060B1B0 (FUN_0060B1B0, ??2CUnitFireAtTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Allocates one fire-at task object and forwards constructor arguments into
   * in-place task construction.
   */
  CUnitFireAtTask* CUnitFireAtTask::Create(
    IAiCommandDispatchImpl* const dispatchTask,
    CAiTarget* const target,
    const std::int32_t isNuclear
  )
  {
    void* const storage = ::operator new(sizeof(CUnitFireAtTask), std::nothrow);
    if (storage == nullptr) {
      return nullptr;
    }

    return new (storage) CUnitFireAtTask(static_cast<CCommandTask*>(dispatchTask), target, isNuclear);
  }

  /**
   * Address: 0x0060B260 (FUN_0060B260, ??0CUnitFireAtTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one fire-at task from dispatch context and picks the first
   * matching manual-fire weapon lane for the requested nuke/non-nuke mode.
   */
  CUnitFireAtTask::CUnitFireAtTask(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    const std::int32_t isNuclear
  )
    : CCommandTask(dispatchTask)
    , mDispatch(static_cast<IAiCommandDispatchImpl*>(dispatchTask))
    , mTarget()
    , mWeapon(nullptr)
    , mIsNuclear(isNuclear)
  {
    if (target != nullptr) {
      mTarget = *target;
    }

    Unit* const unit = mUnit;
    CAiAttackerImpl* const attacker = (unit != nullptr) ? unit->AiAttacker : nullptr;
    if (attacker == nullptr) {
      return;
    }

    const int weaponCount = attacker->GetWeaponCount();
    for (int weaponIndex = 0; weaponIndex < weaponCount; ++weaponIndex) {
      UnitWeapon* const weapon = attacker->GetWeapon(weaponIndex);
      if (weapon == nullptr) {
        continue;
      }

      if (!MatchesManualFireProfile(weapon->mWeaponBlueprint, mIsNuclear)) {
        continue;
      }

      mWeapon = weapon;
      break;
    }
  }
} // namespace moho
