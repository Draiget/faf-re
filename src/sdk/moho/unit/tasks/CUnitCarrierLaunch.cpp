#include "moho/unit/tasks/CUnitCarrierLaunch.h"

#include <new>
#include <type_traits>
#include <typeinfo>

#include "gpg/core/containers/WriteArchive.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskCarrierLaunch = 0x0000000000000200ull;

  [[nodiscard]] gpg::RType* CachedSNavGoalType()
  {
    gpg::RType* type = moho::SNavGoal::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SNavGoal));
      moho::SNavGoal::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedEntitySetTemplateUnitType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SEntitySetTemplateUnit));
    }
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00606E60 (FUN_00606E60, Moho::CUnitCarrierLaunch::CUnitCarrierLaunch)
   *
   * What it does:
   * Initializes one carrier-launch task from parent dispatch context, copies
   * launch-goal state, collects candidate carried units, and links the set
   * into the simulation registered-set lane.
   */
  CUnitCarrierLaunch::CUnitCarrierLaunch(
    CCommandTask* const parentTask,
    const SNavGoal& launchGoal,
    const SCommandUnitSet& commandUnits
  )
    : CCommandTask(parentTask)
    , mLaunchGoal(launchGoal)
    , mHasCarrierTransportedUnit(false)
    , mPad55{}
    , mCarriedUnits()
  {
    for (CScriptObject* const entry : commandUnits.mVec) {
      if (!SCommandUnitSet::IsUsableEntry(entry)) {
        continue;
      }

      Unit* const candidate = SCommandUnitSet::UnitFromEntry(entry);
      if (!candidate || candidate->IsDead() || candidate == mUnit) {
        continue;
      }

      Unit* const transportOwner = candidate->GetTransportedBy();
      if (!transportOwner) {
        continue;
      }

      mHasCarrierTransportedUnit = true;
      if (transportOwner == mUnit) {
        (void)mCarriedUnits.AddUnit(candidate);
      }
    }

    if (mUnit && mUnit->SimulationRef && mUnit->SimulationRef->mEntityDB) {
      mUnit->SimulationRef->mEntityDB->RegisterEntitySet(mCarriedUnits);
      mUnit->UnitStateMask |= kUnitStateMaskCarrierLaunch;
    }
  }

  /**
   * Address: 0x00607680 (FUN_00607680, Moho::CUnitCarrierLaunch::operator new)
   *
   * What it does:
   * Allocates one carrier-launch task and forwards constructor arguments into
   * in-place construction.
   */
  CUnitCarrierLaunch* CUnitCarrierLaunch::Create(
    CCommandTask* const parentTask,
    const SNavGoal* const launchGoal,
    const SCommandUnitSet* const commandUnits
  )
  {
    void* const storage = ::operator new(sizeof(CUnitCarrierLaunch));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitCarrierLaunch(parentTask, *launchGoal, *commandUnits);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x00608A10 (FUN_00608A10, Moho::CUnitCarrierLaunch::MemberSerialize)
   *
   * What it does:
   * Serializes the `CCommandTask` base, launch goal, launch-state bool, and
   * carried-unit set.
   */
  void CUnitCarrierLaunch::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    gpg::RType* commandTaskType = CCommandTask::sType;
    if (!commandTaskType) {
      commandTaskType = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = commandTaskType;
    }

    const gpg::RRef ownerRef{};
    archive->Write(commandTaskType, this, ownerRef);

    const gpg::RRef launchGoalOwnerRef{};
    archive->Write(CachedSNavGoalType(), &mLaunchGoal, launchGoalOwnerRef);
    archive->WriteBool(mHasCarrierTransportedUnit);

    const gpg::RRef carriedUnitsOwnerRef{};
    archive->Write(CachedEntitySetTemplateUnitType(), &mCarriedUnits, carriedUnitsOwnerRef);
  }
} // namespace moho
