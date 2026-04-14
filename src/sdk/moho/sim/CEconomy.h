#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/CEconomyEvent.h"
#include "moho/sim/CSimArmyEconomyInfo.h"

namespace gpg
{
  class RType;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CEconStorage;
  class Sim;

  /**
   * Runtime economy state serialized on army save/load lanes.
   */
  class CEconomy
  {
  public:
    /**
     * Address: 0x007048F0 (FUN_007048F0, Moho::CEconomy::Clear)
     *
     * What it does:
     * Unlinks the consumption-request sentinel node, releases extra-storage
     * ownership (with max-storage rollback), then frees this economy object.
     */
    CEconomy* Clear();

    /**
     * Address: 0x00774860 (FUN_00774860, Moho::CEconomy::MemberSerialize)
     *
     * What it does:
     * Serializes Sim owner, index/value lanes, totals, storage pointer ownership,
     * sharing flag, then emits the intrusive CEconRequest chain terminator.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x007731B0 (FUN_007731B0, Moho::CEconomy::SerializeRequests)
     *
     * What it does:
     * Writes economy-request intrusive-list pointers in reverse link order and
     * appends one null pointer terminator.
     */
    void SerializeRequests(gpg::WriteArchive* archive);

  public:
    static gpg::RType* sType;

    Sim* mSim;                         // +0x00
    std::int32_t mIndex;               // +0x04
    SEconValue mResources;             // +0x08
    SEconValue mPendingResources;      // +0x10
    SEconTotals mTotals;               // +0x18
    CEconStorage* mExtraStorage;       // +0x50
    std::uint8_t mResourceSharing;     // +0x54
    std::uint8_t mPad55To57[0x03];     // +0x55
    TDatListItem<void, void> mConsumptionData; // +0x58
  };

  static_assert(offsetof(CEconomy, mSim) == 0x00, "CEconomy::mSim offset must be 0x00");
  static_assert(offsetof(CEconomy, mIndex) == 0x04, "CEconomy::mIndex offset must be 0x04");
  static_assert(offsetof(CEconomy, mResources) == 0x08, "CEconomy::mResources offset must be 0x08");
  static_assert(
    offsetof(CEconomy, mPendingResources) == 0x10, "CEconomy::mPendingResources offset must be 0x10"
  );
  static_assert(offsetof(CEconomy, mTotals) == 0x18, "CEconomy::mTotals offset must be 0x18");
  static_assert(offsetof(CEconomy, mExtraStorage) == 0x50, "CEconomy::mExtraStorage offset must be 0x50");
  static_assert(
    offsetof(CEconomy, mResourceSharing) == 0x54, "CEconomy::mResourceSharing offset must be 0x54"
  );
  static_assert(
    offsetof(CEconomy, mConsumptionData) == 0x58, "CEconomy::mConsumptionData offset must be 0x58"
  );
  static_assert(sizeof(CEconomy) == 0x60, "CEconomy size must be 0x60");
} // namespace moho
