#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/EFormationdStatusTypeInfo.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/ECommandEvent.h"

namespace moho
{
  class CAiFormationInstance;
  class IAiCommandDispatchImpl;

  /**
   * Recovered form-and-move command task.
   */
  class CUnitFormAndMoveTask
    : public CCommandTask
    , public Listener<EAiNavigatorEvent>
    , public Listener<EFormationdStatus>
    , public Listener<ECommandEvent>
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x006191F0 (FUN_006191F0, ctor helper lane)
     *
     * What it does:
     * Initializes one detached form-move task with self-linked listener lanes.
     */
    CUnitFormAndMoveTask();

    /**
     * Address: 0x00619250 (FUN_00619250, ??0CUnitFormAndMoveTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one form-move task from dispatch/formation context, seeds
     * the current formation-adjusted navigator goal, and links listener lanes.
     */
    CUnitFormAndMoveTask(CCommandTask* dispatchTask, CAiFormationInstance* formation);

    /**
     * Address: 0x006194E0 (FUN_006194E0, ??1CUnitFormAndMoveTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks all listener lanes, aborts navigator movement, clears unit
     * form-move state bit, and tears down command-task ownership.
     */
    ~CUnitFormAndMoveTask() override;

    /**
     * Address: 0x00619A90 (FUN_00619A90, ??2CUnitFormAndMoveTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Allocates one form-move task when formation and dispatch navigator lanes
     * are valid, then forwards into constructor logic.
     */
    [[nodiscard]] static CUnitFormAndMoveTask* Create(
      CAiFormationInstance* formation,
      IAiCommandDispatchImpl* dispatchTask
    );

    /**
     * Address: 0x00619650 (FUN_00619650, Moho::CUnitFormAndMoveTask::TaskTick)
     *
     * What it does:
     * Returns active-task status when formation lane is valid and the unit has
     * not yet consumed cached formation-speed data.
     */
    int Execute() override;

    /**
     * Address: 0x0061A9C0 (FUN_0061A9C0)
     *
     * What it does:
     * Deserializes base command-task state, weak formation pointer lane, and
     * the formation-arrival flag.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0061AA30 (FUN_0061AA30)
     *
     * What it does:
     * Serializes base command-task state, weak formation pointer lane, and the
     * formation-arrival flag.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00619680 (FUN_00619680, Moho::CUnitFormAndMoveTask::OnEvent)
     * Primary vtable: `Listener<EAiNavigatorEvent>` secondary slot 0
     * (`??_7CUnitFormAndMoveTask@Moho@@6B?$Listener@W4EAiNavigatorEvent@Moho@@@Moho@@@`).
     *
     * What it does:
     * Applies navigator event state transitions and resumes owner thread
     * processing.
     */
    void OnEvent(EAiNavigatorEvent event) override;

    /**
     * Address: 0x00619770 (FUN_00619770, Moho::CUnitFormAndMoveTask::OnEvent)
     * Primary vtable: `Listener<EFormationdStatus>` secondary slot 0
     * (`??_7CUnitFormAndMoveTask@Moho@@6B?$Listener@W4EFormationdStatus@Moho@@@Moho@@@`).
     *
     * What it does:
     * Handles formation status transitions by refreshing current formation goal
     * or marking form-move completion when the unit reaches valid formation lane.
     */
    void OnEvent(EFormationdStatus event) override;

    /**
     * Address: 0x006196F0 (FUN_006196F0, Moho::CUnitFormAndMoveTask::OnEvent)
     * Primary vtable: `Listener<ECommandEvent>` secondary slot 0
     * (`??_7CUnitFormAndMoveTask@Moho@@6B?$Listener@W4ECommandEvent@Moho@@@Moho@@@`).
     *
     * What it does:
     * Re-applies current formation-adjusted navigator goal when command
     * dispatch payload changes.
     */
    void OnEvent(ECommandEvent event) override;

  private:
    void ApplyFormationGoalFromCurrentUnit();
    void ResumeOwnerThreadNow();

  public:
    CAiFormationInstance* mFormation; // 0x60
    std::uint8_t mFormationArrivalSatisfied; // 0x64
    std::uint8_t mPad0065_0068[3]; // 0x65
  };

  static_assert(sizeof(CUnitFormAndMoveTask) == 0x68, "CUnitFormAndMoveTask size must be 0x68");
  static_assert(offsetof(CUnitFormAndMoveTask, mFormation) == 0x60, "CUnitFormAndMoveTask::mFormation offset must be 0x60");
  static_assert(
    offsetof(CUnitFormAndMoveTask, mFormationArrivalSatisfied) == 0x64,
    "CUnitFormAndMoveTask::mFormationArrivalSatisfied offset must be 0x64"
  );

  /**
   * Address: 0x0061A3E0 (FUN_0061A3E0)
   *
   * What it does:
   * Thin alias lane that forwards one `(task, archive)` pair into
   * `CUnitFormAndMoveTask::MemberSerialize`.
   */
  void CUnitFormAndMoveTaskMemberSerializeAlias(const CUnitFormAndMoveTask* task, gpg::WriteArchive* archive);
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0061A5A0 (FUN_0061A5A0, gpg::RRef_CUnitFormAndMoveTask)
   *
   * What it does:
   * Builds one typed reflection reference for
   * `moho::CUnitFormAndMoveTask*`, preserving dynamic-derived ownership and
   * base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitFormAndMoveTask(gpg::RRef* outRef, moho::CUnitFormAndMoveTask* value);

  /**
   * Address: 0x0061A380 (FUN_0061A380)
   *
   * What it does:
   * Wrapper lane that materializes one temporary
   * `RRef_CUnitFormAndMoveTask` and copies object/type fields into the
   * destination reference record.
   */
  gpg::RRef* AssignCUnitFormAndMoveTaskRef(gpg::RRef* outRef, moho::CUnitFormAndMoveTask* value);
} // namespace gpg
