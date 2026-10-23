#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace moho
{
  using EntId = std::int32_t;

  class CAniPose;
  struct SPerArmyReconInfo;
  struct SSTIEntityVariableData;
  struct SSTIUnitVariableData;
  struct SSyncData;
  struct SEntityVariableUpdateEntry;
  struct SUnitVariableUpdateEntry;

  /// Engine additions: `sim_ParallelSyncHeap` (unit records' allocating copy half on the fill
  /// workers too) and `sim_ParallelEntitySync` (entity records' copy on the fill workers). Both
  /// only act while `sim_ParallelSync` defers unit records. The packet only goes to the client:
  /// the allocations land on worker threads (the engine allocator is thread-safe) and in a
  /// different order, and every byte the client reads is the serial one.
  extern bool sim_ParallelSyncHeap;
  extern bool sim_ParallelEntitySync;

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
    void FillEntityRange(std::size_t begin, std::size_t end) const;

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

  /**
   * Engine addition (`sim_ParallelEntitySync`): appends `entityId`'s entity-update record the way
   * `QueueEntityVariableUpdate` does and leaves the payload copy to `CUnitUpdateFills::Finish`.
   * Returns nullptr when entity records are not being deferred; the caller then queues serially.
   * The copy takes `variableData` as it is at `Finish`, except `mRequestRefreshUI`, which is
   * taken now (`Entity::Sync` clears it right after queueing).
   */
  [[nodiscard]] SEntityVariableUpdateEntry* QueueEntityVariableUpdateDeferred(
    SSyncData* syncData, EntId entityId, const SSTIEntityVariableData& variableData
  );

  /**
   * Engine addition (`sim_ParallelEntitySync`): when the newest entity-update record of
   * `syncData` was deferred, has `Finish` overwrite its mesh, health, completion and dead lanes
   * from `reconInfo` after the copy (what `ReconBlip::SyncInterface` writes) and returns true.
   */
  [[nodiscard]] bool OverrideDeferredEntityUpdateFromRecon(SSyncData* syncData, const SPerArmyReconInfo* reconInfo);
} // namespace moho
