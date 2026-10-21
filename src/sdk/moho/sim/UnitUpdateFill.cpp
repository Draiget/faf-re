#include "moho/sim/UnitUpdateFill.h"

#include "moho/animation/CAniPose.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  namespace
  {
    /// One deferred record: where it is, and what completes it.
    struct SUnitUpdateFill
    {
      std::size_t mIndex;                  // into SSyncData::mUnitUpdates
      const SSTIUnitVariableData* mSource; // the payload passed to the queue call
      SUnitUpdateOverrides mOverrides;
    };

    // Static, so recording a fill never allocates (that would shift the sim heap). A packet with
    // more records than this sends the rest down the serial path.
    constexpr std::size_t kMaxUnitUpdateFills = 1u << 16;
    SUnitUpdateFill sUnitUpdateFills[kMaxUnitUpdateFills];
    std::size_t sUnitUpdateFillCount = 0;
    const CUnitUpdateFills* sActiveUnitUpdateFills = nullptr;
    SSyncData* sActiveSyncData = nullptr;

    // Records per worker chunk. Fills are independent, so this only sets the dispatch overhead;
    // it never depends on the worker count.
    constexpr std::size_t kUnitUpdateFillGrain = 128;
  } // namespace

  CUnitUpdateFills::CUnitUpdateFills(SSyncData* const syncData)
  {
    if (syncData == nullptr || sActiveUnitUpdateFills != nullptr || !sim_ParallelSync ||
        !CSimWorkerPool::ParallelEnabled()) {
      return;
    }
    mSyncData = syncData;
    sActiveUnitUpdateFills = this;
    sActiveSyncData = syncData;
    sUnitUpdateFillCount = 0;
  }

  CUnitUpdateFills::~CUnitUpdateFills()
  {
    if (mSyncData == nullptr) {
      return;
    }
    FillRange(0, sUnitUpdateFillCount);
    sUnitUpdateFillCount = 0;
    sActiveUnitUpdateFills = nullptr;
    sActiveSyncData = nullptr;
  }

  void CUnitUpdateFills::Finish()
  {
    if (mSyncData == nullptr) {
      return;
    }
    // Stop deferring before the fills run: nothing may append while workers write records.
    sActiveUnitUpdateFills = nullptr;
    sActiveSyncData = nullptr;
    const std::size_t count = sUnitUpdateFillCount;
    CSimWorkerPool::Get().ParallelFor(
      count, kUnitUpdateFillGrain, [this](const std::size_t begin, const std::size_t end) { FillRange(begin, end); }
    );
    sUnitUpdateFillCount = 0;
    mSyncData = nullptr;
  }

  void CUnitUpdateFills::FillRange(const std::size_t begin, const std::size_t end) const
  {
    for (std::size_t i = begin; i < end; ++i) {
      const SUnitUpdateFill& fill = sUnitUpdateFills[i];
      SSTIUnitVariableData& payload = mSyncData->mUnitUpdates[fill.mIndex].mVariableData;
      payload.AssignInlineMembersFrom(*fill.mSource);

      const SUnitUpdateOverrides& overrides = fill.mOverrides;
      if (overrides.mPose != nullptr) {
        payload.mSharedPose = *overrides.mPose;
        payload.mPriorSharedPose = *overrides.mPriorPose;
      }
      if (overrides.mHasStunTicks) {
        payload.mStunTicks = overrides.mStunTicks;
      }
    }
  }

  SUnitVariableUpdateEntry* QueueUnitVariableUpdateDeferred(
    SSyncData* const syncData,
    const EntId entityId,
    const SSTIUnitVariableData& variableData,
    const SUnitUpdateOverrides& overrides
  )
  {
    if (syncData == nullptr || syncData != sActiveSyncData || sUnitUpdateFillCount == kMaxUnitUpdateFills) {
      return nullptr;
    }

    // QueueUnitVariableUpdate inserts a copy of a default record; constructing it in place leaves
    // the same bytes and allocates the same nothing. Growth, when the reserve falls short,
    // reallocates and copies the records exactly as the insert would.
    SUnitVariableUpdateEntry& entry = syncData->mUnitUpdates.emplace_back();
    entry.mEntityId = entityId;
    entry.mVariableData.AssignHeapMembersFrom(variableData);

    sUnitUpdateFills[sUnitUpdateFillCount++] =
      SUnitUpdateFill{syncData->mUnitUpdates.size() - 1u, &variableData, overrides};
    return &entry;
  }
} // namespace moho
