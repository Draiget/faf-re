#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/sim/ArmyUnitSet.h"
#include "moho/task/CCommandTask.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  /**
   * Task lane used by carrier transport retrieval command flow.
   */
  class CUnitCarrierRetrieve : public CCommandTask
  {
  public:
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
     * unit's `OnStartTransportLoading` script callback, registers the
     * tracked-unit set into the simulation entity DB, and flips the unit's
     * "carrier-retrieve in progress" state bit (0x100).
     */
    CUnitCarrierRetrieve(CCommandTask* parentTask, const SEntitySetTemplateUnit& trackedUnits);

    /**
     * Address: 0x00605DD0 (FUN_00605DD0, ??1CUnitCarrierRetrieve@Moho@@QAE@@Z)
     *
     * IDA signature:
     * void __stdcall Moho::CUnitCarrierRetrieve::~CUnitCarrierRetrieve(
     *     Moho::CUnitCarrierRetrieve *this);
     *
     * What it does:
     * Tears down one retrieve-task. Runs the unit's `OnStopTransportLoading`
     * script callback, releases the transport reservation, clears the carrier-
     * retrieve in-progress state bit (0x100), and writes the dispatch result:
     * `EAiResult` value 1 (success) when the load run reported retrieval-
     * complete, otherwise value 2 (failure) after asking every still-living
     * tracked unit's AI navigator to abort its in-flight motion. Member
     * subobject (`mTrackedUnits`) and base `CCommandTask` destructors then
     * run via the standard C++ teardown chain.
     */
    ~CUnitCarrierRetrieve() override;

    /**
     * Address: 0x00606450 (FUN_00606450, Moho::CUnitCarrierRetrieve::operator new)
     *
     * IDA signature:
     * Moho::CUnitCarrierRetrieve *__usercall sub_606450@<eax>(
     *     Moho::CCommandTask *parent@<edi>,
     *     Moho::EntitySetTemplate_Entity *a2);
     *
     * What it does:
     * Allocates one retrieve-task (0x60 bytes) and forwards constructor
     * arguments into in-place construction. On allocation failure returns
     * `nullptr`; on constructor throw the allocation is released before
     * the exception propagates.
     */
    static CUnitCarrierRetrieve* Create(
      CCommandTask* parentTask,
      const SEntitySetTemplateUnit& trackedUnits
    );

    /**
     * Address: 0x00605EF0 (FUN_00605EF0, Moho::CUnitCarrierRetrieve::TaskTick)
     *
     * IDA signature:
     * int __thiscall sub_605EF0(Moho::CUnitCarrierRetrieve *this);
     *
     * What it does:
     * Executes one carrier-retrieve task tick. Pre-switch guard returns -1
     * (task complete) on dead carrier or on `UNITSTATE_MovingDown` once the
     * task has reached Starting. State machine: (Preparing) cancels the
     * tick when any tracked unit drifts to a different command, otherwise
     * re-targets the carrier into the water layer for surfacing-sub
     * carriers and advances to Waiting; (Waiting) resets the AiTransport
     * reservation when the carrier reaches its water/air destination and
     * advances to Starting; (Starting) drains units that finished docking
     * from the tracked set, returning -1 once the tracked set is empty
     * (with `mRetrievalComplete` flipped to true) or 10 (sleep 9 frames)
     * while units are still loading; default returns 1.
     */
    int Execute() override;

    /**
     * Address: 0x00608630 (FUN_00608630, Moho::CUnitCarrierRetrieve::MemberSerialize)
     *
     * What it does:
     * Serializes one retrieve-task payload: base `CCommandTask` state,
     * retrieval-complete flag, and tracked transport-unit set.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x006085A0 (FUN_006085A0, Moho::CUnitCarrierRetrieve::MemberDeserialize)
     *
     * What it does:
     * Deserializes one retrieve-task payload: base `CCommandTask` state,
     * retrieval-complete flag, and tracked transport-unit set.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

  public:
    bool mRetrievalComplete;             // 0x30
    std::uint8_t mPad31_37[0x07];        // 0x31
    SEntitySetTemplateUnit mTrackedUnits; // 0x38
  };

  static_assert(sizeof(CUnitCarrierRetrieve) == 0x60, "CUnitCarrierRetrieve size must be 0x60");
  static_assert(
    offsetof(CUnitCarrierRetrieve, mRetrievalComplete) == 0x30,
    "CUnitCarrierRetrieve::mRetrievalComplete offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitCarrierRetrieve, mTrackedUnits) == 0x38,
    "CUnitCarrierRetrieve::mTrackedUnits offset must be 0x38"
  );
} // namespace moho
