#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/ai/SPickUpInfo.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/task/CCommandTask.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class RType;
  class WriteArchive;
}

namespace moho
{
  class CUnitLoadUnits : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00624AC0 (FUN_00624AC0, Moho::CUnitLoadUnits::CUnitLoadUnits)
     *
     * What it does:
     * Initializes one detached load-units task lane with empty pickup queue,
     * empty requested-unit set, and cleared runtime flags.
     */
    CUnitLoadUnits();

    /**
     * Address: 0x00624B70 (FUN_00624B70, Moho::CUnitLoadUnits::CUnitLoadUnits)
     *
     * What it does:
     * Initializes one parent-linked load-units task, copies requested units,
     * binds transport mode flags, links unit-set ownership in EntityDB, and
     * starts transport-loading script/state.
     */
    CUnitLoadUnits(CCommandTask* parentTask, const SEntitySetTemplateUnit& requestedUnits);

    /**
     * Address: 0x00624CC0 (FUN_00624CC0, Moho::CUnitLoadUnits::~CUnitLoadUnits)
     *
     * What it does:
     * Stops transport-loading task state, clears waiting-formation lanes,
     * aborts pending pickup units on failure paths, and finalizes dispatch
     * result/status.
     */
    ~CUnitLoadUnits() override;

    /**
     * Address: 0x006250B0 (FUN_006250B0, Moho::CUnitLoadUnits::operator new)
     *
     * What it does:
     * Allocates one load-units task and forwards constructor arguments into
     * in-place construction.
     */
    [[nodiscard]] static CUnitLoadUnits* Create(CCommandTask* parentTask, const SEntitySetTemplateUnit* requestedUnits);

    /**
     * Address: 0x00625110 (FUN_00625110, Moho::CUnitLoadUnits::DoTask)
     *
     * What it does:
     * Rebuilds pickup candidates, selects loadable units by transport slot
     * availability, computes pickup center, and submits pickup orders into
     * transport AI.
     */
    void DoTask();

    /**
     * Address: 0x00625950 (FUN_00625950, Moho::CUnitLoadUnits::TaskTick)
     *
     * What it does:
     * Executes the transport-loading task state machine across prepare/wait/
     * start/process/complete phases, including teleporter checks and retry
     * transitions.
     */
    int Execute() override;

    /**
     * Address: 0x00629070 (FUN_00629070)
     *
     * What it does:
     * Loads base task state, pickup queue lanes, requested-unit set, pickup
     * center, counters, and transport mode flags from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x006291B0 (FUN_006291B0)
     *
     * What it does:
     * Saves base task state, pickup queue lanes, requested-unit set, pickup
     * center, counters, and transport mode flags into archive storage.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    msvc8::vector<SPickUpInfo> mPickupQueue;  // 0x30
    SEntitySetTemplateUnit mRequestedUnits;   // 0x40
    Wm3::Vector3f mPickupCenter;              // 0x68
    std::int32_t mReadyUnitCount;             // 0x74
    std::int32_t mLoadedUnitCount;            // 0x78
    std::int32_t mProcessingTicks;            // 0x7C
    bool mIsStagingPlatform;                  // 0x80
    bool mIsTeleporter;                       // 0x81
    bool mCompletedSuccessfully;              // 0x82
    std::uint8_t mPadding83_87[5];            // 0x83
  };

  static_assert(sizeof(CUnitLoadUnits) == 0x88, "CUnitLoadUnits size must be 0x88");
  static_assert(offsetof(CUnitLoadUnits, mPickupQueue) == 0x30, "CUnitLoadUnits::mPickupQueue offset must be 0x30");
  static_assert(offsetof(CUnitLoadUnits, mRequestedUnits) == 0x40, "CUnitLoadUnits::mRequestedUnits offset must be 0x40");
  static_assert(offsetof(CUnitLoadUnits, mPickupCenter) == 0x68, "CUnitLoadUnits::mPickupCenter offset must be 0x68");
  static_assert(offsetof(CUnitLoadUnits, mReadyUnitCount) == 0x74, "CUnitLoadUnits::mReadyUnitCount offset must be 0x74");
  static_assert(offsetof(CUnitLoadUnits, mLoadedUnitCount) == 0x78, "CUnitLoadUnits::mLoadedUnitCount offset must be 0x78");
  static_assert(offsetof(CUnitLoadUnits, mProcessingTicks) == 0x7C, "CUnitLoadUnits::mProcessingTicks offset must be 0x7C");
  static_assert(offsetof(CUnitLoadUnits, mIsStagingPlatform) == 0x80, "CUnitLoadUnits::mIsStagingPlatform offset must be 0x80");
  static_assert(offsetof(CUnitLoadUnits, mIsTeleporter) == 0x81, "CUnitLoadUnits::mIsTeleporter offset must be 0x81");
  static_assert(
    offsetof(CUnitLoadUnits, mCompletedSuccessfully) == 0x82,
    "CUnitLoadUnits::mCompletedSuccessfully offset must be 0x82"
  );
} // namespace moho
