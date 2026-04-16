#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/Listener.h"
#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"

namespace moho
{
  class CUnitCommand;
  class Entity;

  struct CUnitReclaimTaskListenerPad
  {
    std::uint32_t mListenerPad{};
  };

  static_assert(sizeof(CUnitReclaimTaskListenerPad) == 0x04, "CUnitReclaimTaskListenerPad size must be 0x04");

  /**
   * Recovered runtime layout used by reclaim-task reflection constructors.
   */
  class CUnitReclaimTask : public CCommandTask, public CUnitReclaimTaskListenerPad, public Listener<ECommandEvent>
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0061EB00 (FUN_0061EB00, sub_61EB00)
     *
     * What it does:
     * Initializes reclaim-task command/listener base slices and resets task
     * runtime lanes used by reflection allocation paths.
     */
    CUnitReclaimTask();

    /**
     * Address: 0x0061EB60 (FUN_0061EB60, Moho::CUnitReclaimTask::CUnitReclaimTask)
     *
     * What it does:
     * Initializes one reclaim task from dispatch context, target entity, and
     * target position snapshot, then seeds economy/request and command-listener
     * lanes.
     */
    CUnitReclaimTask(CCommandTask* parentTask, Entity* targetEntity, const Wm3::Vector3f& targetPos);

    /**
     * Address: 0x00620280 (FUN_00620280, Moho::CUnitReclaimTask::~CUnitReclaimTask)
     *
     * What it does:
     * Unlinks reclaim listeners/requests, clears reclaim/focus runtime state on
     * owner and target units, and tears down task/listener base slices.
     */
    ~CUnitReclaimTask() override;

    /**
     * Address: 0x00620160 (FUN_00620160, listener callback lane)
     *
     * What it does:
     * Refreshes reclaim target from current command payload, rebinds unit focus
     * target, clears per-task progress state, and wakes owner task thread.
     */
    void OnEvent(ECommandEvent event) override;

    /**
     * Address: 0x0061F000 (FUN_0061F000, Moho::CUnitReclaimTask::TaskTick)
     *
     * What it does:
     * Runs reclaim task state transitions: validates target lanes, handles
     * approach/setup, evaluates reclaim costs, applies per-tick reclaim
     * materialization, and credits reclaimed resources to army economy totals.
     */
    [[nodiscard]] int TaskTick();

    /**
     * Alias of FUN_0061F000.
     *
     * What it does:
     * Dispatches the command-task execute slot into `TaskTick`.
     */
    int Execute() override;

    /**
     * Address: 0x00620C60 (FUN_00620C60, Moho::CUnitReclaimTask::MemberDeserialize)
     *
     * What it does:
     * Loads base command-task state and reclaim-task payload lanes, then
     * swaps owned economy request pointer ownership from archive state.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00620DD0 (FUN_00620DD0, Moho::CUnitReclaimTask::MemberSerialize)
     *
     * What it does:
     * Saves base command-task state and reclaim-task payload lanes including
     * tracked pointer ownership for command and economy request references.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    CUnitCommand* mCommand;           // +0x40
    WeakPtr<Entity> mTargetEntity;    // +0x44
    bool mTargetHasNoMotor;           // +0x4C
    std::uint8_t mPad4D[0x03];        // +0x4D
    Wm3::Vector3f mTargetPosition;    // +0x50
    bool mHasStarted;                 // +0x5C
    std::uint8_t mPad5D[0x03];        // +0x5D
    CEconRequest* mConsumptionData;   // +0x60
    float mReclaimRate;               // +0x64
    SEconValue mReclaimPerSecond;     // +0x68

  private:
    /**
     * Address: 0x00620110 (FUN_00620110, sub_620110)
     *
     * What it does:
     * Toggles reclaim-script active state and dispatches
     * `OnStartReclaim`/`OnStopReclaim` callbacks when state changes.
     */
    void SetReclaimScriptActive(bool active);
  };

  static_assert(sizeof(CUnitReclaimTask) == 0x70, "CUnitReclaimTask size must be 0x70");
  static_assert(offsetof(CUnitReclaimTask, mCommand) == 0x40, "CUnitReclaimTask::mCommand offset must be 0x40");
  static_assert(
    offsetof(CUnitReclaimTask, mTargetEntity) == 0x44, "CUnitReclaimTask::mTargetEntity offset must be 0x44"
  );
  static_assert(
    offsetof(CUnitReclaimTask, mTargetHasNoMotor) == 0x4C, "CUnitReclaimTask::mTargetHasNoMotor offset must be 0x4C"
  );
  static_assert(
    offsetof(CUnitReclaimTask, mTargetPosition) == 0x50, "CUnitReclaimTask::mTargetPosition offset must be 0x50"
  );
  static_assert(
    offsetof(CUnitReclaimTask, mHasStarted) == 0x5C, "CUnitReclaimTask::mHasStarted offset must be 0x5C"
  );
  static_assert(
    offsetof(CUnitReclaimTask, mConsumptionData) == 0x60, "CUnitReclaimTask::mConsumptionData offset must be 0x60"
  );
  static_assert(
    offsetof(CUnitReclaimTask, mReclaimRate) == 0x64, "CUnitReclaimTask::mReclaimRate offset must be 0x64"
  );
  static_assert(
    offsetof(CUnitReclaimTask, mReclaimPerSecond) == 0x68, "CUnitReclaimTask::mReclaimPerSecond offset must be 0x68"
  );
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00620AB0 (FUN_00620AB0, gpg::RRef_CUnitReclaimTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitReclaimTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitReclaimTask(gpg::RRef* outRef, moho::CUnitReclaimTask* value);
} // namespace gpg
