#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/Listener.h"
#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"

namespace moho
{
  class CAiTarget;
  class CUnitCommand;
  class Entity;
  class Unit;

  struct CUnitCaptureTaskListenerPad
  {
    std::uint32_t mListenerPad{};
  };

  static_assert(sizeof(CUnitCaptureTaskListenerPad) == 0x04, "CUnitCaptureTaskListenerPad size must be 0x04");

  /**
   * Runtime owner for unit-capture command task state.
   */
  class CUnitCaptureTask : public CCommandTask, public CUnitCaptureTaskListenerPad, public Listener<ECommandEvent>
  {
  public:
    /**
     * Address: 0x00603F40 (FUN_00603F40, Moho::CUnitCaptureTask::CUnitCaptureTask)
     *
     * What it does:
     * Initializes capture-task command/listener slices and zeroes capture
     * bookkeeping/economy lanes.
     */
    CUnitCaptureTask();

    /**
     * Address: 0x00603F90 (FUN_00603F90, ??0CUnitCaptureTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one capture-task lane from parent dispatch context, binds
     * target/listener ownership links, and seeds owner focus/target blip state.
     */
    CUnitCaptureTask(CCommandTask* parentTask, Entity* targetEntity);

    /**
     * Address: 0x006050F0 (FUN_006050F0, ??1CUnitCaptureTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks command/listener lanes, clears capture state from owner/target,
     * flushes economy request ownership, and tears down weak-target links.
     */
    ~CUnitCaptureTask() override;

    /**
     * Address: 0x00604360 (FUN_00604360, ??2CUnitCaptureTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Resolves one capture target from command payload, writes dispatch failure
     * result when absent, and allocates/constructs one capture-task object.
     */
    [[nodiscard]] static CUnitCaptureTask* Create(CCommandTask* parentTask, CAiTarget* commandTarget);

    /**
     * Address: 0x006043E0 (FUN_006043E0, Moho::CUnitCaptureTask::TaskTick)
     *
     * What it does:
     * Runs capture-task state transitions from range/setup through capture-cost
     * budgeting, economy-consumption progress, and final capture callbacks.
     */
    [[nodiscard]] int TaskTick();

    int Execute() override;

    /**
     * Address: 0x00604FC0 (FUN_00604FC0, Moho::CUnitCaptureTask::Receive)
     *
     * What it does:
     * Refreshes target/focus links from current command payload, resets capture
     * progress/economy lanes, and wakes owner task thread for immediate retick.
     */
    void OnEvent(ECommandEvent event) override;

  private:
    /**
     * Address: 0x00604E10 (FUN_00604E10, Moho::CUnitCaptureTask::DoCallback)
     *
     * What it does:
     * Toggles target capture-state/captor-count bookkeeping and dispatches
     * start/failed capture script callbacks on owner and target lanes.
     */
    void DoCallback(bool start);

  public:
    CUnitCommand* mCommand; // +0x40
    WeakPtr<Entity> mTargetEntity; // +0x44
    bool mHasStarted; // +0x4C
    std::uint8_t mPad4D[0x03]; // +0x4D
    std::int32_t mCaptureProgress; // +0x50
    std::int32_t mCaptureTime; // +0x54
    CEconRequest* mConsumptionData; // +0x58
    SEconValue mCaptureRate; // +0x5C
  };

  static_assert(sizeof(CUnitCaptureTask) == 0x64, "CUnitCaptureTask size must be 0x64");
  static_assert(offsetof(CUnitCaptureTask, mCommand) == 0x40, "CUnitCaptureTask::mCommand offset must be 0x40");
  static_assert(
    offsetof(CUnitCaptureTask, mTargetEntity) == 0x44, "CUnitCaptureTask::mTargetEntity offset must be 0x44"
  );
  static_assert(
    offsetof(CUnitCaptureTask, mHasStarted) == 0x4C, "CUnitCaptureTask::mHasStarted offset must be 0x4C"
  );
  static_assert(
    offsetof(CUnitCaptureTask, mCaptureProgress) == 0x50, "CUnitCaptureTask::mCaptureProgress offset must be 0x50"
  );
  static_assert(
    offsetof(CUnitCaptureTask, mCaptureTime) == 0x54, "CUnitCaptureTask::mCaptureTime offset must be 0x54"
  );
  static_assert(
    offsetof(CUnitCaptureTask, mConsumptionData) == 0x58, "CUnitCaptureTask::mConsumptionData offset must be 0x58"
  );
  static_assert(
    offsetof(CUnitCaptureTask, mCaptureRate) == 0x5C, "CUnitCaptureTask::mCaptureRate offset must be 0x5C"
  );
} // namespace moho
