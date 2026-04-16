#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/path/SNavGoal.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/Broadcaster.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class RType;
  class WriteArchive;
}

namespace moho
{
  class CUnitCommand;
  enum class EUnitCommandType : std::int32_t;
  enum EAiNavigatorEvent : std::int32_t;
  struct SOCellPos;

  class CUnitMoveTask : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0061A750 (FUN_0061A750)
     *
     * What it does:
     * Deserializes move-task runtime state (base command-task lane, dispatch
     * command pointer, move goal, command weak-link lane, and state flags).
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0061A880 (FUN_0061A880)
     *
     * What it does:
     * Serializes move-task runtime state (base command-task lane, dispatch
     * command pointer, move goal, command weak-link lane, and state flags).
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00618030 (FUN_00618030, Moho::CUnitMoveTask::CUnitMoveTask)
     *
     * What it does:
     * Initializes one detached move-task with self-linked listener nodes and
     * empty dispatch/goal/command lanes.
     */
    CUnitMoveTask();

    /**
     * Address: 0x006180E0 (FUN_006180E0, Moho::CUnitMoveTask::CUnitMoveTask)
     *
     * What it does:
     * Initializes move-task dispatch state, links navigator-listener lane, and
     * seeds one initial movement goal from command/target context.
     */
    CUnitMoveTask(
      CCommandTask* dispatchTask,
      const SNavGoal& moveGoal,
      std::uint8_t requiresTransportCategoryCheck,
      CUnitCommand* sourceCommand,
      std::uint8_t moveVariant
    );

    /**
     * Address: 0x00618A00 (FUN_00618A00, sub_618A00)
     *
     * What it does:
     * Returns true when the unit is in a single-command lane suitable for
     * dynamic target-position move-goal derivation.
     */
    [[nodiscard]] bool ShouldUseCurrentCommandTargetPosition() const;

    /**
     * Address: 0x00618A70 (FUN_00618A70, Moho::CUnitMoveTask::OnEvent)
     *
     * What it does:
     * Issues a follow-up call-transport task once for the owning unit when
     * ferry-assigned transport context is valid, and unlinks the navigator
     * listener lane before dispatching.
     */
    int Execute() override;

    /**
     * Address: 0x00618BB0 (FUN_00618BB0)
     *
     * What it does:
     * Applies navigator-event result transitions, clears instant-command lane,
     * and resumes owner-thread execution immediately.
     */
    void HandleNavigatorEvent(EAiNavigatorEvent event);

  public:
    std::uint32_t mUnknown0030; // 0x30
    std::uint32_t mNavigatorListenerVftable; // 0x34
    Broadcaster mNavigatorListenerLink; // 0x38
    std::uint32_t mUnknown0040; // 0x40
    std::uint32_t mFormationStatusListenerVftable; // 0x44
    Broadcaster mFormationStatusListenerLink; // 0x48
    std::uint32_t mUnknown0050; // 0x50
    std::uint32_t mCommandEventListenerVftable; // 0x54
    Broadcaster mCommandEventListenerLink; // 0x58
    CCommandTask* mDispatchTask; // 0x60
    SNavGoal mMoveGoal; // 0x64
    WeakPtr<CUnitCommand> mCommandRef; // 0x88
    std::uint8_t mNextCmdIsInstant; // 0x90
    std::uint8_t mRequiresTransportCategoryCheck; // 0x91
    std::uint8_t mIsOccupying; // 0x92
    std::uint8_t mTransportDispatchIssued; // 0x93
    std::uint8_t mMoveVariant; // 0x94
    std::uint8_t mHasPreparedDynamicGoal; // 0x95
    std::uint8_t mPad_0096_0098[2]; // 0x96
  };

  static_assert(sizeof(CUnitMoveTask) == 0x98, "CUnitMoveTask size must be 0x98");
  static_assert(offsetof(CUnitMoveTask, mNavigatorListenerVftable) == 0x34, "CUnitMoveTask::mNavigatorListenerVftable offset must be 0x34");
  static_assert(offsetof(CUnitMoveTask, mNavigatorListenerLink) == 0x38, "CUnitMoveTask::mNavigatorListenerLink offset must be 0x38");
  static_assert(offsetof(CUnitMoveTask, mFormationStatusListenerVftable) == 0x44, "CUnitMoveTask::mFormationStatusListenerVftable offset must be 0x44");
  static_assert(offsetof(CUnitMoveTask, mFormationStatusListenerLink) == 0x48, "CUnitMoveTask::mFormationStatusListenerLink offset must be 0x48");
  static_assert(offsetof(CUnitMoveTask, mCommandEventListenerVftable) == 0x54, "CUnitMoveTask::mCommandEventListenerVftable offset must be 0x54");
  static_assert(offsetof(CUnitMoveTask, mCommandEventListenerLink) == 0x58, "CUnitMoveTask::mCommandEventListenerLink offset must be 0x58");
  static_assert(offsetof(CUnitMoveTask, mDispatchTask) == 0x60, "CUnitMoveTask::mDispatchTask offset must be 0x60");
  static_assert(offsetof(CUnitMoveTask, mMoveGoal) == 0x64, "CUnitMoveTask::mMoveGoal offset must be 0x64");
  static_assert(offsetof(CUnitMoveTask, mCommandRef) == 0x88, "CUnitMoveTask::mCommandRef offset must be 0x88");
  static_assert(offsetof(CUnitMoveTask, mNextCmdIsInstant) == 0x90, "CUnitMoveTask::mNextCmdIsInstant offset must be 0x90");
  static_assert(
    offsetof(CUnitMoveTask, mRequiresTransportCategoryCheck) == 0x91,
    "CUnitMoveTask::mRequiresTransportCategoryCheck offset must be 0x91"
  );
  static_assert(
    offsetof(CUnitMoveTask, mIsOccupying) == 0x92,
    "CUnitMoveTask::mIsOccupying offset must be 0x92"
  );
  static_assert(
    offsetof(CUnitMoveTask, mTransportDispatchIssued) == 0x93,
    "CUnitMoveTask::mTransportDispatchIssued offset must be 0x93"
  );
  static_assert(offsetof(CUnitMoveTask, mMoveVariant) == 0x94, "CUnitMoveTask::mMoveVariant offset must be 0x94");
  static_assert(
    offsetof(CUnitMoveTask, mHasPreparedDynamicGoal) == 0x95,
    "CUnitMoveTask::mHasPreparedDynamicGoal offset must be 0x95"
  );

  /**
   * Address: 0x006189C0 (FUN_006189C0, Moho::CommandIsInstant)
   *
   * What it does:
   * Returns whether one unit command type is treated as an instant command lane
   * by move-task teardown/relink logic.
   */
  [[nodiscard]] bool CommandIsInstant(EUnitCommandType commandType) noexcept;

  /**
   * Address: 0x006190A0 (FUN_006190A0, Moho::NewMoveTask)
   *
   * What it does:
   * Sets one navigator goal for `dispatchTask->mUnit`, then allocates and
   * constructs one `CUnitMoveTask` when navigator state is available.
   */
  void NewMoveTask(
    const SNavGoal& goal,
    CCommandTask* dispatchTask,
    std::uint8_t requiresTransportCategoryCheck,
    CUnitCommand* sourceCommand,
    std::uint8_t moveVariant
  );

  /**
   * Address: 0x0061A3C0 (FUN_0061A3C0)
   *
   * What it does:
   * Thin alias lane that forwards one `(task, archive)` pair into
   * `CUnitMoveTask::MemberSerialize`.
   */
  void CUnitMoveTaskMemberSerializeAlias(const CUnitMoveTask* task, gpg::WriteArchive* archive);
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x0061A3F0 (FUN_0061A3F0, gpg::RRef_CUnitMoveTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitMoveTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitMoveTask(gpg::RRef* outRef, moho::CUnitMoveTask* value);

  /**
   * Address: 0x0061A350 (FUN_0061A350)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CUnitMoveTask` and
   * copies object/type fields into the destination reference record.
   */
  gpg::RRef* AssignCUnitMoveTaskRef(gpg::RRef* outRef, moho::CUnitMoveTask* value);
} // namespace gpg
