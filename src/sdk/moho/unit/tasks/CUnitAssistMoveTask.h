#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Vector3.h"
#include "moho/path/SNavGoal.h"
#include "moho/task/CCommandTask.h"

namespace gpg
{
  class RRef;
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  struct SEntitySetTemplateUnit;
  class Unit;

  class CUnitAssistMoveTask final : public CCommandTask
  {
  public:
    /**
     * Address: 0x005F0CF0 (FUN_005F0CF0)
     *
     * What it does:
     * Builds one default assist-move task lane with zeroed dispatch/goal state.
     */
    CUnitAssistMoveTask();

    /**
     * Address: 0x005F0BC0 (FUN_005F0BC0, Moho::CUnitAssistMoveTask::CUnitAssistMoveTask)
     *
     * What it does:
     * Initializes one assist-move task from parent command-task context and
     * cached move-goal payload, then enables `UNITSTATE_AssistMoving`.
     */
    CUnitAssistMoveTask(CCommandTask* dispatchTask, const SNavGoal& moveGoal);

    /**
     * Address: 0x005F0D40 (FUN_005F0D40, Moho::CUnitAssistMoveTask::~CUnitAssistMoveTask)
     *
     * What it does:
     * Clears assist-move unit state and loaded-unit command queues, then
     * unreserves transport unattached slots.
     */
    ~CUnitAssistMoveTask() override;

    /**
     * Address: 0x005F19D0 (FUN_005F19D0, Moho::CUnitAssistMoveTask::operator new)
     *
     * What it does:
     * Allocates one assist-move task and forwards constructor arguments.
     */
    [[nodiscard]] static CUnitAssistMoveTask* Create(CCommandTask* dispatchTask, const SNavGoal* moveGoal);

    /**
     * Address: 0x005F1F30 (FUN_005F1F30, CUnitAssistMoveTask serializer load callback body)
     *
     * What it does:
     * Deserializes base command-task, dispatch pointer, move-goal payload,
     * goal world-position vector, and pathfinding-candidate flag.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CUnitAssistMoveTask* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005F2010 (FUN_005F2010, CUnitAssistMoveTask serializer save callback body)
     *
     * What it does:
     * Serializes base command-task, dispatch pointer, move-goal payload,
     * goal world-position vector, and pathfinding-candidate flag.
     */
    static void MemberSerialize(
      gpg::WriteArchive* archive, const CUnitAssistMoveTask* task, int version, gpg::RRef* ownerRef
    );

    /**
     * Address: 0x005F1950 (FUN_005F1950, Moho::CUnitAssistMoveTask::TaskTick)
     *
     * What it does:
     * Advances assist-move task state through wait/start/process transitions.
     */
    int Execute() override;

    /**
     * Address: 0x005F14E0 (FUN_005F14E0, Moho::CUnitAssistMoveTask::Wait)
     *
     * What it does:
     * Collects eligible pickup units near the assist goal and dispatches
     * load-task or unload-task progression state transitions.
     */
    void Wait();

    /**
     * Address: 0x005F15D0 (FUN_005F15D0, Moho::CUnitAssistMoveTask::Start)
     *
     * What it does:
     * Chooses unload target cell from carried-unit command context and
     * dispatches one `CUnitUnloadUnits` child task.
     */
    void Start();

    /**
     * Address: 0x005F1920 (FUN_005F1920, Moho::CUnitAssistMoveTask::IssueMoveTaskAndComplete)
     *
     * What it does:
     * Dispatches one move task using this assist task's cached goal and
     * parent dispatch lane, then marks this task complete.
     */
    void IssueMoveTaskAndComplete();

    /**
     * Address: 0x005F1060 (FUN_005F1060, Moho::CUnitAssistMoveTask::GetEntitiesAlreadyAtLoc)
     *
     * What it does:
     * Builds one candidate set of loadable allied mobile land units near
     * this assist task's context and writes filtered results into `outUnits`.
     */
    SEntitySetTemplateUnit* GetEntitiesAlreadyAtLoc(SEntitySetTemplateUnit* outUnits);

  public:
    static gpg::RType* sType;

    CCommandTask* mDispatchTask;                  // 0x30
    SNavGoal mMoveGoal;                           // 0x34
    Wm3::Vector3f mMoveGoalWorldPosition;         // 0x58
    std::uint8_t mHasPathFindingPickupCandidate;  // 0x64
    std::uint8_t mPad65_67[3];                    // 0x65
  };

  static_assert(offsetof(CUnitAssistMoveTask, mDispatchTask) == 0x30, "CUnitAssistMoveTask::mDispatchTask offset must be 0x30");
  static_assert(offsetof(CUnitAssistMoveTask, mMoveGoal) == 0x34, "CUnitAssistMoveTask::mMoveGoal offset must be 0x34");
  static_assert(
    offsetof(CUnitAssistMoveTask, mMoveGoalWorldPosition) == 0x58,
    "CUnitAssistMoveTask::mMoveGoalWorldPosition offset must be 0x58"
  );
  static_assert(
    offsetof(CUnitAssistMoveTask, mHasPathFindingPickupCandidate) == 0x64,
    "CUnitAssistMoveTask::mHasPathFindingPickupCandidate offset must be 0x64"
  );
  static_assert(sizeof(CUnitAssistMoveTask) == 0x68, "CUnitAssistMoveTask size must be 0x68");
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x005F1D80 (FUN_005F1D80, gpg::RRef_CUnitAssistMoveTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitAssistMoveTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitAssistMoveTask(gpg::RRef* outRef, moho::CUnitAssistMoveTask* value);
} // namespace gpg
