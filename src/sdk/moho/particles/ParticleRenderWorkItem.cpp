#include "moho/particles/ParticleRenderWorkItem.h"

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
  SParticleRenderWorkItem* DestroyParticleRenderWorkItem(SParticleRenderWorkItem* const workItem)
  {
    if (workItem == nullptr) {
      return nullptr;
    }

    ResetParticleRenderWorkItemIntervals(*workItem);
    SParticleRenderWorkItem* const destroyedWorkItem = workItem;
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
  void ResetParticleRenderWorkItemIntervals(SParticleRenderWorkItem& workItem)
  {
    // `msvc8::vector<SParticleRenderInterval>::_Tidy` (cited on Vector.h).
    workItem.mIntervals.tidy();
  }

  /**
   * Address: 0x00493D50 (FUN_00493D50)
   *
   * What it does:
   * Initializes one render work-item with particle-buffer owner and interval cap.
   */
  SParticleRenderWorkItem* InitializeParticleRenderWorkItem(
    SParticleRenderWorkItem& workItem,
    const std::uint32_t intervalCapacityHint,
    void* const particleBuffer
  )
  {
    ::new (static_cast<void*>(&workItem.mIntervals)) msvc8::vector<SParticleRenderInterval>();
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
  bool AdvanceParticleRenderWorkItemCursorToFrame(SParticleRenderWorkItem& workItem, const float frameValue)
  {
    const SParticleRenderInterval* interval = workItem.mIntervals.begin() + workItem.mIntervalCursor;
    if (interval == workItem.mIntervals.end()) {
      return true;
    }

    while ((interval->beginFrame + interval->lifeFrames) <= frameValue) {
      ++workItem.mIntervalCursor;
      ++interval;
      if (interval == workItem.mIntervals.end()) {
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
  void AppendTrailToBucketEntry(const SWorldTrail& trail, STrailBucketEntry& bucketEntry)
  {
    bucketEntry.mTrails.push_back(trail);
  }
} // namespace moho
