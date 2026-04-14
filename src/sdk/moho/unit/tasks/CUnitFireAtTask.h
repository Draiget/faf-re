#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/CAiTarget.h"
#include "moho/task/CCommandTask.h"

namespace moho
{
  class IAiCommandDispatchImpl;
  class UnitWeapon;

  class CUnitFireAtTask : public CCommandTask
  {
  public:
    /**
     * Address: 0x0060B1B0 (FUN_0060B1B0, ??2CUnitFireAtTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Allocates one fire-at task object and forwards constructor arguments into
     * in-place task construction.
     */
    [[nodiscard]] static CUnitFireAtTask* Create(
      IAiCommandDispatchImpl* dispatchTask,
      CAiTarget* target,
      std::int32_t isNuclear
    );

    /**
     * Address: 0x0060B260 (FUN_0060B260, ??0CUnitFireAtTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one fire-at task from dispatch context and picks the first
     * matching manual-fire weapon lane for the requested nuke/non-nuke mode.
     */
    CUnitFireAtTask(CCommandTask* dispatchTask, CAiTarget* target, std::int32_t isNuclear);

    /**
     * Execute override placeholder. The actual body lives at
     * 0x0060B380 (Moho::CUnitFireAtTask::TaskTick, 373 instructions —
     * extensive weapon/target acquisition state machine that needs
     * dedicated recovery). Provided here as a non-pure stub so the
     * class is instantiable from `Create` until the real body is
     * lifted; tracked as needs_evidence in `recovered_progress.json`.
     */
    int Execute() override;

  public:
    IAiCommandDispatchImpl* mDispatch; // +0x30
    CAiTarget mTarget;                 // +0x34
    UnitWeapon* mWeapon;               // +0x54
    std::int32_t mIsNuclear;           // +0x58
  };

  static_assert(offsetof(CUnitFireAtTask, mDispatch) == 0x30, "CUnitFireAtTask::mDispatch offset must be 0x30");
  static_assert(offsetof(CUnitFireAtTask, mTarget) == 0x34, "CUnitFireAtTask::mTarget offset must be 0x34");
  static_assert(offsetof(CUnitFireAtTask, mWeapon) == 0x54, "CUnitFireAtTask::mWeapon offset must be 0x54");
  static_assert(
    offsetof(CUnitFireAtTask, mIsNuclear) == 0x58,
    "CUnitFireAtTask::mIsNuclear offset must be 0x58"
  );
  static_assert(sizeof(CUnitFireAtTask) == 0x5C, "CUnitFireAtTask size must be 0x5C");
} // namespace moho
