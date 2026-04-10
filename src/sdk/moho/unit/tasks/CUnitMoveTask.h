#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/path/SNavGoal.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/Broadcaster.h"

namespace moho
{
  class CUnitCommand;
  struct SOCellPos;

  class CUnitMoveTask : public CCommandTask
  {
  public:
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
} // namespace moho
