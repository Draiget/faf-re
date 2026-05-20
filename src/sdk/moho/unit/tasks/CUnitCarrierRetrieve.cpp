#include "moho/unit/tasks/CUnitCarrierRetrieve.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

namespace
{
  // CarrierRetrieve sets bit 0x100 in Unit::mUnitVarDat.mUnitStates while the
  // task is active (sibling Launch task uses bit 0x200). The dtor (recovered
  // elsewhere) pairs with this set.
  constexpr std::uint64_t kUnitStateMaskCarrierRetrieve = 0x0000000000000100ull;

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
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
   * Address: 0x00605D10 (FUN_00605D10, Moho::CUnitCarrierRetrieve::CUnitCarrierRetrieve)
   *
   * IDA signature:
   * Moho::CUnitCarrierRetrieve *__userpurge sub_605D10@<eax>(
   *     Moho::CCommandTask *parent@<edi>,
   *     Moho::CUnitCarrierRetrieve *arg0,
   *     Moho::EntitySetTemplate_Entity *a2);
   *
   * What it does:
   * Initializes one retrieve-task from parent dispatch context, copies the
   * tracked-unit set template into the task's local storage, runs the
   * unit's `OnStartTransportLoading` script callback, then registers the
   * tracked-unit set into the simulation entity DB and flips the unit's
   * "carrier-retrieve in progress" state bit (0x100). The dtor clears the
   * state bit on teardown.
   */
  CUnitCarrierRetrieve::CUnitCarrierRetrieve(
    CCommandTask* const parentTask,
    const SEntitySetTemplateUnit& trackedUnits
  )
    : CCommandTask(parentTask)
    , mRetrievalComplete(false)
    , mPad31_37{}
    , mTrackedUnits(trackedUnits)
  {
    if (mUnit == nullptr) {
      return;
    }

    (void)mUnit->RunScript("OnStartTransportLoading");

    if (mUnit->SimulationRef != nullptr && mUnit->SimulationRef->mEntityDB != nullptr) {
      mUnit->SimulationRef->mEntityDB->RegisterEntitySet(mTrackedUnits);
      mUnit->UnitStateMask |= kUnitStateMaskCarrierRetrieve;
    }
  }

  /**
   * Address: 0x00606450 (FUN_00606450, Moho::CUnitCarrierRetrieve::operator new)
   *
   * IDA signature:
   * Moho::CUnitCarrierRetrieve *__usercall sub_606450@<eax>(
   *     Moho::CCommandTask *parent@<edi>,
   *     Moho::EntitySetTemplate_Entity *a2);
   *
   * What it does:
   * Allocates one retrieve-task (0x60 bytes) via `operator new`, then
   * forwards `parentTask` and `trackedUnits` into in-place construction.
   * On allocation failure returns `nullptr`; on constructor throw the
   * allocation is released before the exception propagates. Mirrors the
   * sibling `CUnitCarrierLaunch::Create` RAII shape.
   */
  CUnitCarrierRetrieve* CUnitCarrierRetrieve::Create(
    CCommandTask* const parentTask,
    const SEntitySetTemplateUnit& trackedUnits
  )
  {
    void* const storage = ::operator new(sizeof(CUnitCarrierRetrieve));
    if (storage == nullptr) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitCarrierRetrieve(parentTask, trackedUnits);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }


  /**
   * Address: 0x006085A0 (FUN_006085A0, Moho::CUnitCarrierRetrieve::MemberDeserialize)
   *
   * What it does:
   * Deserializes one retrieve-task payload: base `CCommandTask` state,
   * retrieval-complete flag, and tracked transport-unit set.
   */
  void CUnitCarrierRetrieve::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), this, ownerRef);
    archive->ReadBool(&mRetrievalComplete);

    const gpg::RRef trackedUnitsOwnerRef{};
    archive->Read(CachedEntitySetTemplateUnitType(), &mTrackedUnits, trackedUnitsOwnerRef);
  }

  /**
   * Address: 0x00608630 (FUN_00608630, Moho::CUnitCarrierRetrieve::MemberSerialize)
   *
   * What it does:
   * Serializes one retrieve-task payload: base `CCommandTask` state,
   * retrieval-complete flag, and tracked transport-unit set.
   */
  void CUnitCarrierRetrieve::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), this, ownerRef);
    archive->WriteBool(mRetrievalComplete);

    const gpg::RRef trackedUnitsOwnerRef{};
    archive->Write(CachedEntitySetTemplateUnitType(), &mTrackedUnits, trackedUnitsOwnerRef);
  }

  /**
   * Address: 0x00607E80 (FUN_00607E80)
   *
   * What it does:
   * Preserves one deserialize thunk lane for `CUnitCarrierRetrieve` serializer
   * callback registration.
   */
  [[maybe_unused]] void CUnitCarrierRetrieveMemberDeserializeAdapterLaneA(
    CUnitCarrierRetrieve* const task,
    gpg::ReadArchive* const archive
  )
  {
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00608030 (FUN_00608030)
   *
   * What it does:
   * Alternate deserialize thunk lane for `CUnitCarrierRetrieve` serializer
   * callback registration.
   */
  [[maybe_unused]] void CUnitCarrierRetrieveMemberDeserializeAdapterLaneB(
    CUnitCarrierRetrieve* const task,
    gpg::ReadArchive* const archive
  )
  {
    task->MemberDeserialize(archive);
  }
} // namespace moho

namespace
{
  gpg::SerSaveLoadHelperListRuntime gCUnitCarrierRetrieveSerializer{};

  /**
   * Address: 0x006063F0 (FUN_006063F0)
   *
   * What it does:
   * Unlinks `CUnitCarrierRetrieveSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCarrierRetrieveSerializerNodePrimary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitCarrierRetrieveSerializer);
  }

  /**
   * Address: 0x00606420 (FUN_00606420)
   *
   * What it does:
   * Performs the same intrusive-list unlink/self-link sequence for
   * `CUnitCarrierRetrieveSerializer` helper storage.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitCarrierRetrieveSerializerNodeSecondary()
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gCUnitCarrierRetrieveSerializer);
  }
} // namespace
