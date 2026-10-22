#include "moho/sim/UnitUpdateFill.h"

#include "moho/animation/CAniPose.h"
#include "moho/console/CConCommand.h"
#include "moho/sim/ReconBlip.h"
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
      bool mHeapDeferred;                  // sim_ParallelSyncHeap: the allocating half too
    };

    // Static, so recording a fill never allocates (that would shift the sim heap). A packet with
    // more records than this sends the rest down the serial path.
    constexpr std::size_t kMaxUnitUpdateFills = 1u << 16;
    SUnitUpdateFill sUnitUpdateFills[kMaxUnitUpdateFills];
    std::size_t sUnitUpdateFillCount = 0;
    const CUnitUpdateFills* sActiveUnitUpdateFills = nullptr;

    /// One deferred entity-update record (sim_ParallelEntitySync).
    struct SEntityUpdateFill
    {
      std::size_t mIndex;                    // into SSyncData::mEntityUpdates
      const SSTIEntityVariableData* mSource; // the payload passed to the queue call
      std::uint8_t mRequestRefreshUI;        // the source's value when queued
      const SPerArmyReconInfo* mReconOverrides;
    };
    SEntityUpdateFill sEntityUpdateFills[kMaxUnitUpdateFills];
    std::size_t sEntityUpdateFillCount = 0;
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
    sEntityUpdateFillCount = 0;
  }

  CUnitUpdateFills::~CUnitUpdateFills()
  {
    if (mSyncData == nullptr) {
      return;
    }
    FillRange(0, sUnitUpdateFillCount);
    FillEntityRange(0, sEntityUpdateFillCount);
    sUnitUpdateFillCount = 0;
    sEntityUpdateFillCount = 0;
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
    const std::size_t entityCount = sEntityUpdateFillCount;
    CSimWorkerPool::Get().ParallelFor(
      entityCount, kUnitUpdateFillGrain, [this](const std::size_t begin, const std::size_t end) {
        FillEntityRange(begin, end);
      }
    );
    sUnitUpdateFillCount = 0;
    sEntityUpdateFillCount = 0;
    mSyncData = nullptr;
  }

  void CUnitUpdateFills::FillRange(const std::size_t begin, const std::size_t end) const
  {
    for (std::size_t i = begin; i < end; ++i) {
      const SUnitUpdateFill& fill = sUnitUpdateFills[i];
      SSTIUnitVariableData& payload = mSyncData->mUnitUpdates[fill.mIndex].mVariableData;
      if (fill.mHeapDeferred) {
        payload.AssignHeapMembersFrom(*fill.mSource);
      }
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
    const bool heapDeferred = sim_ParallelSyncHeap;
    if (!heapDeferred) {
      entry.mVariableData.AssignHeapMembersFrom(variableData);
    }

    sUnitUpdateFills[sUnitUpdateFillCount++] =
      SUnitUpdateFill{syncData->mUnitUpdates.size() - 1u, &variableData, overrides, heapDeferred};
    return &entry;
  }

  void CUnitUpdateFills::FillEntityRange(const std::size_t begin, const std::size_t end) const
  {
    for (std::size_t i = begin; i < end; ++i) {
      const SEntityUpdateFill& fill = sEntityUpdateFills[i];
      SSTIEntityVariableData& payload = mSyncData->mEntityUpdates[fill.mIndex].mVariableData;
      payload = *fill.mSource;
      payload.mRequestRefreshUI = fill.mRequestRefreshUI;
      if (const SPerArmyReconInfo* const recon = fill.mReconOverrides; recon != nullptr) {
        payload.mMeshBlueprint = recon->mStiMesh;
        payload.mScmResource = recon->mMesh;
        payload.mHealth = recon->mHealth;
        payload.mMaxHealth = recon->mMaxHealth;
        payload.mFractionComplete = recon->mFractionComplete;
        payload.mIsDead = recon->mMaybeDead;
      }
    }
  }

  SEntityVariableUpdateEntry* QueueEntityVariableUpdateDeferred(
    SSyncData* const syncData, const EntId entityId, const SSTIEntityVariableData& variableData
  )
  {
    if (!sim_ParallelEntitySync || syncData == nullptr || syncData != sActiveSyncData ||
        sEntityUpdateFillCount == kMaxUnitUpdateFills) {
      return nullptr;
    }

    // QueueEntityVariableUpdate pushes a default record, then writes the id and assigns the payload;
    // the assignment is what Finish does.
    syncData->mEntityUpdates.push_back(SEntityVariableUpdateEntry{});
    SEntityVariableUpdateEntry& entry = syncData->mEntityUpdates.back();
    entry.mEntityId = entityId;
    sEntityUpdateFills[sEntityUpdateFillCount++] = SEntityUpdateFill{
      syncData->mEntityUpdates.size() - 1u, &variableData, variableData.mRequestRefreshUI, nullptr
    };
    return &entry;
  }

  bool OverrideDeferredEntityUpdateFromRecon(SSyncData* const syncData, const SPerArmyReconInfo* const reconInfo)
  {
    if (syncData == nullptr || syncData != sActiveSyncData || sEntityUpdateFillCount == 0u) {
      return false;
    }
    SEntityUpdateFill& last = sEntityUpdateFills[sEntityUpdateFillCount - 1u];
    if (last.mIndex + 1u != syncData->mEntityUpdates.size()) {
      return false; // the newest record was queued serially
    }
    last.mReconOverrides = reconInfo;
    return true;
  }

  bool sim_ParallelSyncHeap = true;
  TConVar<bool> gTConVar_sim_ParallelSyncHeap(
    "sim_ParallelSyncHeap",
    "With sim_ParallelSync, copy the allocating members of unit-update records on workers too (same packet).",
    &sim_ParallelSyncHeap
  );

  bool sim_ParallelEntitySync = true;
  TConVar<bool> gTConVar_sim_ParallelEntitySync(
    "sim_ParallelEntitySync",
    "With sim_ParallelSync, copy entity-update records on workers (same packet).",
    &sim_ParallelEntitySync
  );
} // namespace moho
