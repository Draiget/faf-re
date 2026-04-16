#include "moho/unit/tasks/CUnitFireAtTask.h"

#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
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

  [[nodiscard]] gpg::RType* CachedCUnitFireAtTaskType()
  {
    gpg::RType* type = moho::CUnitFireAtTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CUnitFireAtTask));
      moho::CUnitFireAtTask::sType = type;
    }
    return type;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitFireAtTask::sType = nullptr;

  /**
   * Address: 0x0060B800 (FUN_0060B800, ??1CUnitFireAtTask@Moho@@QAE@@Z)
   * Mangled: ??1CUnitFireAtTask@Moho@@QAE@@Z
   *
   * What it does:
   * Clears the owner-unit busy bit, unlinks the embedded target weak node,
   * and then falls through to inherited command-task teardown.
   */
  CUnitFireAtTask::~CUnitFireAtTask()
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~(1ull << static_cast<std::uint32_t>(UNITSTATE_Busy));
    }

    mTarget.targetEntity.UnlinkFromOwnerChain();
    mTarget.targetEntity.ClearLinkState();
  }

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

  /**
   * Address: 0x0060B380 (FUN_0060B380, Moho::CUnitFireAtTask::TaskTick) — placeholder
   *
   * What it does (placeholder):
   * Provides a non-pure CTask::Execute override so this class is
   * instantiable from `Create`. The real body is the 373-instruction
   * weapon/target acquisition state machine at `0x0060B380`; recovery
   * of that body is tracked as `needs_evidence` for `FUN_0060B380` in
   * `recovered_progress.json`. Returning -1 (engine-style "no result"
   * sentinel) keeps any accidental dispatch inert until the real body
   * lands.
   */
  int CUnitFireAtTask::Execute()
  {
    return -1;
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0060CE10 (FUN_0060CE10, gpg::RRef_CUnitFireAtTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitFireAtTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitFireAtTask(gpg::RRef* const outRef, moho::CUnitFireAtTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitFireAtTaskType());
    return outRef;
  }

  /**
   * Address: 0x0060C800 (FUN_0060C800)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitFireAtTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitFireAtTaskRef(gpg::RRef* const outRef, moho::CUnitFireAtTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef temporaryRef{};
    (void)RRef_CUnitFireAtTask(&temporaryRef, value);
    outRef->mObj = temporaryRef.mObj;
    outRef->mType = temporaryRef.mType;
    return outRef;
  }
} // namespace gpg
