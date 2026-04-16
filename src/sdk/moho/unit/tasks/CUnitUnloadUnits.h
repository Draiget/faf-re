#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "moho/path/SNavGoal.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/task/CCommandTask.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  class CUnitCommand;
  struct SCommandUnitSet;

  /**
   * Task lane used by transport unload command flow.
   */
  class CUnitUnloadUnits : public CCommandTask
  {
  public:
    /**
     * Address: 0x00625E80 (FUN_00625E80, Moho::CUnitUnloadUnits::CUnitUnloadUnits)
     *
     * What it does:
     * Initializes one detached unload-units task with cleared goal/set/link
     * lanes.
     */
    CUnitUnloadUnits();

    /**
     * Address: 0x00626070 (FUN_00626070, Moho::CUnitUnloadUnits::~CUnitUnloadUnits)
     *
     * What it does:
     * Clears owner-unit unload state, requests variable-data refresh, unlinks
     * task-owner weak-link lane, then tears down base task state.
     */
    ~CUnitUnloadUnits() override;

    /**
     * Address: 0x00625EE0 (FUN_00625EE0, Moho::CUnitUnloadUnits::CUnitUnloadUnits)
     *
     * What it does:
     * Initializes one unload-units task from dispatch context, copies unload
     * goal rectangle state, collects eligible transported units, links the
     * loaded-unit set into EntityDB, and updates owner unit unload state.
     */
    CUnitUnloadUnits(
      CUnitCommand* ownerCommand,
      CCommandTask* dispatchTask,
      const SNavGoal& unloadGoal,
      const SCommandUnitSet& commandUnits
    );

    /**
     * Address: 0x00626330 (FUN_00626330, Moho::CUnitUnloadUnits::operator new)
     *
     * What it does:
     * Allocates one unload-units task and forwards constructor arguments into
     * in-place construction.
     */
    static CUnitUnloadUnits* Create(
      CCommandTask* dispatchTask,
      const SNavGoal* unloadGoal,
      const SCommandUnitSet* commandUnits,
      CUnitCommand* ownerCommand
    );

    /**
     * Address: 0x00626390 (FUN_00626390, Moho::CUnitUnloadUnits::TaskTick)
     *
     * What it does:
     * Runs unload state transitions, detaches transported units, lands/warps
     * them onto valid map positions, and optionally issues one follow-up move
     * command toward the unload goal.
     */
    int Execute() override;

    /**
     * Address: 0x00629880 (FUN_00629880, Moho::CUnitUnloadUnits::MemberDeserialize)
     *
     * What it does:
     * Reads base command-task state, unload-goal payload, task-state booleans,
     * and loaded-unit entity-set lanes from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00629950 (FUN_00629950, Moho::CUnitUnloadUnits::MemberSerialize)
     *
     * What it does:
     * Writes base command-task state, unload-goal payload, task-state booleans,
     * and loaded-unit entity-set lanes into archive storage.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    SNavGoal mUnloadGoal;                     // 0x30
    bool mIsStagingPlatform;                  // 0x54
    bool mHasEligibleLoadedUnits;             // 0x55
    std::uint8_t mPad56_57[2];                // 0x56
    SEntitySetTemplateUnit mLoadedUnits;      // 0x58
    WeakPtr<CUnitCommand> mOwnerCommandLinkLane; // 0x80
  };

  static_assert(sizeof(CUnitUnloadUnits) == 0x88, "CUnitUnloadUnits size must be 0x88");
  static_assert(offsetof(CUnitUnloadUnits, mUnloadGoal) == 0x30, "CUnitUnloadUnits::mUnloadGoal offset must be 0x30");
  static_assert(
    offsetof(CUnitUnloadUnits, mIsStagingPlatform) == 0x54,
    "CUnitUnloadUnits::mIsStagingPlatform offset must be 0x54"
  );
  static_assert(
    offsetof(CUnitUnloadUnits, mHasEligibleLoadedUnits) == 0x55,
    "CUnitUnloadUnits::mHasEligibleLoadedUnits offset must be 0x55"
  );
  static_assert(
    offsetof(CUnitUnloadUnits, mLoadedUnits) == 0x58, "CUnitUnloadUnits::mLoadedUnits offset must be 0x58"
  );
  static_assert(
    offsetof(CUnitUnloadUnits, mOwnerCommandLinkLane) == 0x80,
    "CUnitUnloadUnits::mOwnerCommandLinkLane offset must be 0x80"
  );
} // namespace moho
