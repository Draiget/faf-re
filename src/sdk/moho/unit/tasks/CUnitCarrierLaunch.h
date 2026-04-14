#pragma once

#include <cstddef>
#include <cstdint>

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
  struct SCommandUnitSet;

  /**
   * Task lane used for carrier unit launch command flow.
   */
  class CUnitCarrierLaunch : public CCommandTask
  {
  public:
    /**
     * Address: 0x00606E10 (FUN_00606E10, Moho::CUnitCarrierLaunch::CUnitCarrierLaunch)
     *
     * What it does:
     * Initializes one detached carrier-launch task with empty launch-goal state
     * and an unregistered carried-unit set.
     */
    CUnitCarrierLaunch();

    /**
     * Address: 0x00606E60 (FUN_00606E60, Moho::CUnitCarrierLaunch::CUnitCarrierLaunch)
     *
     * What it does:
     * Initializes one carrier-launch task from parent dispatch context, copies
     * launch-goal state, collects candidate carried units, and links the set
     * into the simulation registered-set lane.
     */
    CUnitCarrierLaunch(CCommandTask* parentTask, const SNavGoal& launchGoal, const SCommandUnitSet& commandUnits);

    /**
     * Address: 0x00607680 (FUN_00607680, Moho::CUnitCarrierLaunch::operator new)
     *
     * What it does:
     * Allocates one carrier-launch task and forwards constructor arguments into
     * in-place construction.
     */
    static CUnitCarrierLaunch* Create(
      CCommandTask* parentTask,
      const SNavGoal* launchGoal,
      const SCommandUnitSet* commandUnits
    );

    /**
     * Address: 0x00607000 (FUN_00607000, Moho::CUnitCarrierLaunch::TaskTick)
     *
     * What it does:
     * Executes one carrier-launch task tick.
     */
    int Execute() override;

    /**
     * Address: 0x00608A10 (FUN_00608A10, Moho::CUnitCarrierLaunch::MemberSerialize)
     *
     * What it does:
     * Serializes the `CCommandTask` base, launch goal, launch-state bool, and
     * carried-unit set.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00608950 (FUN_00608950, Moho::CUnitCarrierLaunch::MemberDeserialize)
     *
     * What it does:
     * Deserializes the `CCommandTask` base, launch goal, launch-state bool, and
     * carried-unit set.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

  public:
    SNavGoal mLaunchGoal;                 // 0x30
    bool mHasCarrierTransportedUnit;      // 0x54
    std::uint8_t mPad55[0x03];            // 0x55
    SEntitySetTemplateUnit mCarriedUnits; // 0x58
  };

  static_assert(sizeof(CUnitCarrierLaunch) == 0x80, "CUnitCarrierLaunch size must be 0x80");
  static_assert(offsetof(CUnitCarrierLaunch, mLaunchGoal) == 0x30, "CUnitCarrierLaunch::mLaunchGoal offset must be 0x30");
  static_assert(
    offsetof(CUnitCarrierLaunch, mHasCarrierTransportedUnit) == 0x54,
    "CUnitCarrierLaunch::mHasCarrierTransportedUnit offset must be 0x54"
  );
  static_assert(
    offsetof(CUnitCarrierLaunch, mCarriedUnits) == 0x58,
    "CUnitCarrierLaunch::mCarriedUnits offset must be 0x58"
  );
} // namespace moho
