#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Vector3.h"
#include "moho/ai/CAiTarget.h"
#include "moho/misc/WeakPtr.h"
#include "moho/path/SNavGoal.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/Broadcaster.h"

namespace moho
{
  class CUnitCommand;
  class Entity;
  class Unit;

  /**
   * Recovered command-task owner for unit guard behavior state.
   */
  class CUnitGuardTask : public CCommandTask
  {
  public:
    /**
     * Address: 0x006110F0 (FUN_006110F0, Moho::CUnitGuardTask::CUnitGuardTask)
     *
     * What it does:
     * Initializes guard-task command/listener lanes, clears weak references,
     * resets target payload, and zeros guard-goal rectangle state.
     */
    CUnitGuardTask();

    /**
     * Address: 0x006141A0 (FUN_006141A0, Moho::CUnitGuardTask::TaskTick)
     * Slot: 1
     *
     * What it does:
     * Advances guard-task behavior one tick: scans enemies around the guarded
     * unit and routes new targets through the owner's command queue. Body not
     * yet fully recovered; placeholder override satisfies the CTask contract.
     */
    int Execute() override;

  private:
    /**
     * Address: 0x00612AF0 (FUN_00612AF0, Moho::CUnitGuardTask::GetBestEnemy)
     *
     * What it does:
     * Uses the owner's attacker interface to pick the best enemy in guard-scan
     * range and clears any cached guard-move reservation direction when a new
     * enemy target is acquired.
     */
    [[nodiscard]] Entity* GetBestEnemy();

  public:
    std::uint32_t mUnknown0030; // +0x30
    std::uint32_t mCommandEventListenerVftable; // +0x34
    Broadcaster mCommandEventListenerLink; // +0x38
    CCommandTask* mCommandTask; // +0x40
    WeakPtr<Unit> mPrimaryUnit; // +0x44
    WeakPtr<CUnitCommand> mCommandRef; // +0x4C
    CAiTarget mTarget; // +0x54
    bool mTrackGuardedUnit; // +0x74 (v13a)
    bool mRefreshGuardedUnitFromNearby; // +0x75 (v13b)
    bool mDisableBestEnemySearch; // +0x76 (v13c)
    bool mDisableReactionState; // +0x77 (v13d)
    bool mPreferTransportRefuel; // +0x78 (v14a)
    bool mAllowFerryBeaconRedirect; // +0x79 (v14b)
    bool mUnknown7A; // +0x7A (v14c)
    std::uint8_t mPad007B; // +0x7B
    WeakPtr<Unit> mSecondaryUnit; // +0x7C
    Wm3::Vector3f mGuardDirection; // +0x84 (v17)
    std::uint8_t mPad0090_009B[0x0C]; // +0x90
    SNavGoal mGuardGoal; // +0x9C (v23)
  };

  static_assert(sizeof(CUnitGuardTask) == 0xC0, "CUnitGuardTask size must be 0xC0");
  static_assert(offsetof(CUnitGuardTask, mUnknown0030) == 0x30, "CUnitGuardTask::mUnknown0030 offset must be 0x30");
  static_assert(
    offsetof(CUnitGuardTask, mCommandEventListenerVftable) == 0x34,
    "CUnitGuardTask::mCommandEventListenerVftable offset must be 0x34"
  );
  static_assert(
    offsetof(CUnitGuardTask, mCommandEventListenerLink) == 0x38,
    "CUnitGuardTask::mCommandEventListenerLink offset must be 0x38"
  );
  static_assert(offsetof(CUnitGuardTask, mCommandTask) == 0x40, "CUnitGuardTask::mCommandTask offset must be 0x40");
  static_assert(offsetof(CUnitGuardTask, mPrimaryUnit) == 0x44, "CUnitGuardTask::mPrimaryUnit offset must be 0x44");
  static_assert(offsetof(CUnitGuardTask, mCommandRef) == 0x4C, "CUnitGuardTask::mCommandRef offset must be 0x4C");
  static_assert(offsetof(CUnitGuardTask, mTarget) == 0x54, "CUnitGuardTask::mTarget offset must be 0x54");
  static_assert(
    offsetof(CUnitGuardTask, mTrackGuardedUnit) == 0x74,
    "CUnitGuardTask::mTrackGuardedUnit offset must be 0x74"
  );
  static_assert(
    offsetof(CUnitGuardTask, mRefreshGuardedUnitFromNearby) == 0x75,
    "CUnitGuardTask::mRefreshGuardedUnitFromNearby offset must be 0x75"
  );
  static_assert(
    offsetof(CUnitGuardTask, mDisableBestEnemySearch) == 0x76,
    "CUnitGuardTask::mDisableBestEnemySearch offset must be 0x76"
  );
  static_assert(
    offsetof(CUnitGuardTask, mDisableReactionState) == 0x77,
    "CUnitGuardTask::mDisableReactionState offset must be 0x77"
  );
  static_assert(
    offsetof(CUnitGuardTask, mPreferTransportRefuel) == 0x78,
    "CUnitGuardTask::mPreferTransportRefuel offset must be 0x78"
  );
  static_assert(
    offsetof(CUnitGuardTask, mAllowFerryBeaconRedirect) == 0x79,
    "CUnitGuardTask::mAllowFerryBeaconRedirect offset must be 0x79"
  );
  static_assert(offsetof(CUnitGuardTask, mUnknown7A) == 0x7A, "CUnitGuardTask::mUnknown7A offset must be 0x7A");
  static_assert(offsetof(CUnitGuardTask, mSecondaryUnit) == 0x7C, "CUnitGuardTask::mSecondaryUnit offset must be 0x7C");
  static_assert(
    offsetof(CUnitGuardTask, mGuardDirection) == 0x84,
    "CUnitGuardTask::mGuardDirection offset must be 0x84"
  );
  static_assert(offsetof(CUnitGuardTask, mGuardGoal) == 0x9C, "CUnitGuardTask::mGuardGoal offset must be 0x9C");
} // namespace moho
