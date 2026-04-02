#include "moho/particles/ParticleRenderWorkItemRuntime.h"

#include <new>

namespace moho
{
  /**
   * Address: 0x00493CE0 (FUN_00493CE0)
   * Address: 0x004948C0 (FUN_004948C0)
   *
   * What it does:
   * Releases interval storage owned by one work-item, then frees the work-item.
   */
  ParticleRenderWorkItemRuntime* DestroyParticleRenderWorkItem(ParticleRenderWorkItemRuntime* const workItem)
  {
    if (workItem == nullptr) {
      return nullptr;
    }

    ResetParticleRenderWorkItemIntervals(*workItem);
    ParticleRenderWorkItemRuntime* const destroyedWorkItem = workItem;
    ::operator delete(workItem);
    return destroyedWorkItem;
  }

  /**
   * Address: 0x00493D20 (FUN_00493D20)
   * Address: 0x00494900 (FUN_00494900)
   *
   * What it does:
   * Releases interval storage owned by one work-item and resets interval lanes.
   */
  void ResetParticleRenderWorkItemIntervals(ParticleRenderWorkItemRuntime& workItem)
  {
    if (workItem.mIntervalsBegin != nullptr) {
      ::operator delete(workItem.mIntervalsBegin);
    }

    workItem.mIntervalsBegin = nullptr;
    workItem.mIntervalsEnd = nullptr;
    workItem.mIntervalsCapacityEnd = nullptr;
  }

  /**
   * Address: 0x00493D50 (FUN_00493D50)
   *
   * What it does:
   * Initializes one render work-item with particle-buffer owner and interval cap.
   */
  ParticleRenderWorkItemRuntime* InitializeParticleRenderWorkItem(
    ParticleRenderWorkItemRuntime& workItem,
    const std::uint32_t intervalCapacityHint,
    void* const particleBuffer
  )
  {
    workItem.mIntervalsBegin = nullptr;
    workItem.mIntervalsEnd = nullptr;
    workItem.mIntervalsCapacityEnd = nullptr;
    workItem.mIntervalCapacityHint = intervalCapacityHint;
    workItem.mParticleBuffer = particleBuffer;
    workItem.mRenderStartIndex = 0U;
    workItem.mIntervalCursor = 0U;
    return &workItem;
  }

  /**
   * Address: 0x00493D70 (FUN_00493D70)
   *
   * What it does:
   * Advances interval cursor while intervals are expired for the current frame.
   * Returns true when no active interval remains.
   */
  bool AdvanceParticleRenderWorkItemCursorToFrame(ParticleRenderWorkItemRuntime& workItem, const float frameValue)
  {
    auto* interval = reinterpret_cast<ParticleRenderIntervalRuntime*>(
      reinterpret_cast<std::uintptr_t>(workItem.mIntervalsBegin) +
      (static_cast<std::uintptr_t>(workItem.mIntervalCursor) * sizeof(ParticleRenderIntervalRuntime))
    );

    if (interval == workItem.mIntervalsEnd) {
      return true;
    }

    while ((interval->beginFrame + interval->lifeFrames) <= frameValue) {
      ++workItem.mIntervalCursor;
      ++interval;
      if (interval == workItem.mIntervalsEnd) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00494730 (FUN_00494730)
   *
   * What it does:
   * Appends one trail payload to the trailing trail-vector in a trail bucket
   * entry.
   */
  void AppendTrailToBucketEntry(const TrailRuntimeView& trail, TrailBucketEntryRuntime& bucketEntry)
  {
    AppendTrailToVector(bucketEntry.mTrails, trail);
  }
} // namespace moho
