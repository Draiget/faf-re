#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace moho
{
  using EntId = std::int32_t;

  class CAniPose;
  struct SSTIUnitVariableData;
  struct SSyncData;
  struct SUnitVariableUpdateEntry;

  /**
   * Engine addition, not in the binary: what `ReconBlip::SyncInterface` writes over a unit-update
   * record after the payload copy. The two pose handles come from the focus army's recon snapshot;
   * the stun ticks only when the blip's creator is alive.
   */
  struct SUnitUpdateOverrides
  {
    const boost::shared_ptr<CAniPose>* mPriorPose = nullptr; // with mPose: replace both handles
    const boost::shared_ptr<CAniPose>* mPose = nullptr;
    bool mHasStunTicks = false;
    std::int32_t mStunTicks = 0;
  };

  /**
   * Engine addition, not in the binary: the unit-update payload copies of `Sim::Sync` on
   * CSimWorkerPool. Switch: `sim_ParallelSync`, active only while `sim_Workers > 0`.
   *
   * `QueueUnitVariableUpdate` appends one record per synced unit or blip and copies the whole
   * `SSTIUnitVariableData` into it. While a `CUnitUpdateFills` is active for a packet:
   * - the sim thread still appends every record in walk order, and copies the members that may
   *   allocate (`SSTIUnitVariableData::AssignHeapMembersFrom`), so the packet allocates exactly
   *   what, and in the order, the serial walk allocates;
   * - the rest of each copy (`AssignInlineMembersFrom`, then any `SUnitUpdateOverrides`) is
   *   recorded and done by `Finish`, on workers. That half never allocates or frees: the record's
   *   pose handles start empty, so copying them only retains, and an override releases a handle
   *   the source still holds.
   *
   * Each fill writes only its own record. It reads a payload that nothing writes between the
   * append and `Finish`: a unit's `Sync` writes only its own payload, before appending it.
   * The packet is not checksummed, but the client reads it, so it must be byte-identical to the
   * serial one, and it is: the same fields get the same values, only later.
   */
  class CUnitUpdateFills
  {
  public:
    /// Becomes the active fill list for `syncData` when the phase is enabled; otherwise does nothing.
    explicit CUnitUpdateFills(SSyncData* syncData);

    /// Finishes any fills still pending, serially (the walk threw).
    ~CUnitUpdateFills();

    CUnitUpdateFills(const CUnitUpdateFills&) = delete;
    CUnitUpdateFills& operator=(const CUnitUpdateFills&) = delete;

    /// Completes every deferred record (on workers) and deactivates. Call once the walk is done.
    void Finish();

  private:
    void FillRange(std::size_t begin, std::size_t end) const;

    SSyncData* mSyncData = nullptr;
  };

  /**
   * Engine addition, not in the binary: appends `entityId`'s record the way
   * `QueueUnitVariableUpdate` does, leaving the allocation-free half of the copy, and the
   * `overrides`, to `CUnitUpdateFills::Finish`. Returns the record, or nullptr when no fill list
   * is active for `syncData` (or it is full); the caller then takes the serial path.
   */
  [[nodiscard]] SUnitVariableUpdateEntry* QueueUnitVariableUpdateDeferred(
    SSyncData* syncData,
    EntId entityId,
    const SSTIUnitVariableData& variableData,
    const SUnitUpdateOverrides& overrides = {}
  );
} // namespace moho
