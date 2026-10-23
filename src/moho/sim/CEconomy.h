#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/scoped_ptr.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/sim/CSimArmyEconomyInfo.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class RType;
  class SerConstructResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CEconStorage;
  class Sim;

  class CEconomy;

  /**
   * Address: 0x00771B50 (FUN_00771B50, func_ArmyProcessEconomy)
   *
   * What it does:
   * Runs one army's per-tick economy: pools outstanding consumption demand,
   * serves it from stored plus banked production at a ratio bounded by the
   * scarcer resource, publishes `mIncome`/`mLastUse*`, offers overflow above
   * max storage to allies with room when `mResourceSharing` is set, stores
   * the rest clamped to max storage, publishes the twenty-four `Economy_*`
   * army stats, and empties the per-tick banks. Called once per tick by
   * `CArmyImpl::OnTick` with `army->EconomyInfo`.
   */
  void ProcessArmyEconomy(CEconomy& economy);

  /**
   * Runtime economy state serialized on army save/load lanes.
   *
   * The destructor is implicit: `mConsumptionData` unlinks, then
   * `mExtraStorage` deletes its storage (taking it back out of max storage).
   *
   * Address: 0x007048F0 (FUN_007048F0 -- the scalar deleting destructor;
   * formerly recovered as a `Clear()` member that freed `this`.)
   */
  class CEconomy
  {
  public:
    /**
     * What it does:
     * An empty economy for an archive load (inlined into `MemberConstruct`
     * 0x00772FC0): no sim, index -1, zeroed resources, sharing on.
     */
    CEconomy();

    /**
     * Address: 0x00771880 (FUN_00771880, struct_EconomyData::struct_EconomyData)
     * Mangled: ??0struct_EconomyData@@QAE@@Z
     *
     * CEconomy(Sim* sim, std::int32_t armyIndex)
     *
     * IDA signature:
     * Moho::CEconomy *__thiscall struct_EconomyData::struct_EconomyData(
     *   int index, Moho::CEconomy *this, Moho::Sim *sim);
     *
     * What it does:
     * Initializes one army economy state, creates its max-storage lane, and
     * seeds stored energy/mass from the initial economy convars.
     */
    CEconomy(Sim* sim, std::int32_t armyIndex);

    /**
     * Address: 0x00772FC0 (FUN_00772FC0)
     *
     * What it does:
     * Builds an empty economy for an archive load and hands it back unowned;
     * its members are loaded over it afterwards.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
    );

    /**
     * Address: 0x00774860 (FUN_00774860, Moho::CEconomy::MemberSerialize)
     *
     * What it does:
     * Serializes Sim owner, index/value lanes, totals, storage pointer ownership,
     * sharing flag, then emits the intrusive CEconRequest chain terminator.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00774730 (FUN_00774730, Moho::CEconomy::MemberDeserialize)
     *
     * What it does:
     * Deserializes Sim owner, index/value lanes, totals, owned extra-storage
     * pointer, sharing flag, and request list lanes from archive input.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x007731B0 (FUN_007731B0, Moho::CEconomy::SerializeRequests)
     *
     * What it does:
     * Writes economy-request intrusive-list pointers in reverse link order and
     * appends one null pointer terminator.
     */
    void SerializeRequests(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x00773130 (FUN_00773130, Moho::CEconomy::DeserializeRequests)
     *
     * What it does:
     * Reads CEconRequest intrusive nodes from archive and relinks each request
     * into `mConsumptionData` until a null pointer terminator is read.
     */
    void DeserializeRequests(gpg::ReadArchive* archive);

  public:
    static gpg::RType* sType;

    Sim* mSim;                                     // +0x00
    std::int32_t mIndex;                           // +0x04
    SEconValue mResources;                         // +0x08
    SEconValue mPendingResources;                  // +0x10
    SEconTotals mTotals;                           // +0x18
    boost::scoped_ptr<CEconStorage> mExtraStorage; // +0x50
    std::uint8_t mResourceSharing;                 // +0x54
    TDatListItem<void, void> mConsumptionData;     // +0x58
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

  /**
   * Address: 0x00563B10 (FUN_00563B10, preregister_SEconValueTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SEconValue`.
   */
  [[nodiscard]] gpg::RType* preregister_SEconValueTypeInfo();

  /**
   * Address: 0x00563D40 (FUN_00563D40, preregister_SEconTotalsTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SEconTotals`.
   */
  [[nodiscard]] gpg::RType* preregister_SEconTotalsTypeInfo();

} // namespace moho
