#include "moho/unit/tasks/CUnitCarrierLaunch.h"

#include <new>
#include <type_traits>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskCarrierLaunch = 0x0000000000000200ull;

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

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
   * Address: 0x00606E10 (FUN_00606E10, Moho::CUnitCarrierLaunch::CUnitCarrierLaunch)
   *
   * What it does:
   * Initializes one detached carrier-launch task with empty launch-goal state
   * and an unregistered carried-unit set.
   */
  CUnitCarrierLaunch::CUnitCarrierLaunch()
    : CCommandTask()
    , mLaunchGoal()
    , mHasCarrierTransportedUnit(false)
    , mPad55{}
    , mCarriedUnits()
  {}

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
   * Address: 0x00606F90 (FUN_00606F90, Moho::CUnitCarrierLaunch::~CUnitCarrierLaunch)
   *
   * What it does:
   * Clears the carrier-launch unit-state bit before member/base teardown.
   */
  CUnitCarrierLaunch::~CUnitCarrierLaunch()
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~kUnitStateMaskCarrierLaunch;
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
   * Address: 0x00608950 (FUN_00608950, Moho::CUnitCarrierLaunch::MemberDeserialize)
   *
   * What it does:
   * Deserializes the `CCommandTask` base, launch goal, launch-state bool, and
   * carried-unit set.
   */
  void CUnitCarrierLaunch::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), this, ownerRef);

    const gpg::RRef launchGoalOwnerRef{};
    archive->Read(CachedSNavGoalType(), &mLaunchGoal, launchGoalOwnerRef);
    archive->ReadBool(&mHasCarrierTransportedUnit);

    const gpg::RRef carriedUnitsOwnerRef{};
    archive->Read(CachedEntitySetTemplateUnitType(), &mCarriedUnits, carriedUnitsOwnerRef);
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

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), this, ownerRef);

    const gpg::RRef launchGoalOwnerRef{};
    archive->Write(CachedSNavGoalType(), &mLaunchGoal, launchGoalOwnerRef);
    archive->WriteBool(mHasCarrierTransportedUnit);

    const gpg::RRef carriedUnitsOwnerRef{};
    archive->Write(CachedEntitySetTemplateUnitType(), &mCarriedUnits, carriedUnitsOwnerRef);
  }
} // namespace moho
