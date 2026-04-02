#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/particles/BeamRenderHelpers.h"

namespace moho
{
  /**
   * What it does:
   * One time-interval lane consumed by the particle render work-item cursor.
   */
  struct ParticleRenderIntervalRuntime
  {
    float beginFrame = 0.0F;   // +0x00
    float lifeFrames = 0.0F;   // +0x04
  };

  static_assert(
    offsetof(ParticleRenderIntervalRuntime, beginFrame) == 0x00,
    "ParticleRenderIntervalRuntime::beginFrame offset must be 0x00"
  );
  static_assert(
    offsetof(ParticleRenderIntervalRuntime, lifeFrames) == 0x04,
    "ParticleRenderIntervalRuntime::lifeFrames offset must be 0x04"
  );
  static_assert(sizeof(ParticleRenderIntervalRuntime) == 0x08, "ParticleRenderIntervalRuntime size must be 0x08");

  /**
   * What it does:
   * Runtime work-item lane used by particle render queue helpers around
   * `func_RenderParticle2`.
   */
  struct ParticleRenderWorkItemRuntime
  {
    void* mParticleBuffer = nullptr;                              // +0x00
    std::uint32_t mReserved04 = 0U;                               // +0x04
    ParticleRenderIntervalRuntime* mIntervalsBegin = nullptr;     // +0x08
    ParticleRenderIntervalRuntime* mIntervalsEnd = nullptr;       // +0x0C
    ParticleRenderIntervalRuntime* mIntervalsCapacityEnd = nullptr; // +0x10
    std::uint32_t mIntervalCursor = 0U;                           // +0x14
    std::uint32_t mRenderStartIndex = 0U;                         // +0x18
    std::uint32_t mIntervalCapacityHint = 0U;                     // +0x1C
  };

  static_assert(
    offsetof(ParticleRenderWorkItemRuntime, mParticleBuffer) == 0x00,
    "ParticleRenderWorkItemRuntime::mParticleBuffer offset must be 0x00"
  );
  static_assert(
    offsetof(ParticleRenderWorkItemRuntime, mIntervalsBegin) == 0x08,
    "ParticleRenderWorkItemRuntime::mIntervalsBegin offset must be 0x08"
  );
  static_assert(
    offsetof(ParticleRenderWorkItemRuntime, mIntervalsEnd) == 0x0C,
    "ParticleRenderWorkItemRuntime::mIntervalsEnd offset must be 0x0C"
  );
  static_assert(
    offsetof(ParticleRenderWorkItemRuntime, mIntervalsCapacityEnd) == 0x10,
    "ParticleRenderWorkItemRuntime::mIntervalsCapacityEnd offset must be 0x10"
  );
  static_assert(
    offsetof(ParticleRenderWorkItemRuntime, mIntervalCursor) == 0x14,
    "ParticleRenderWorkItemRuntime::mIntervalCursor offset must be 0x14"
  );
  static_assert(
    offsetof(ParticleRenderWorkItemRuntime, mRenderStartIndex) == 0x18,
    "ParticleRenderWorkItemRuntime::mRenderStartIndex offset must be 0x18"
  );
  static_assert(
    offsetof(ParticleRenderWorkItemRuntime, mIntervalCapacityHint) == 0x1C,
    "ParticleRenderWorkItemRuntime::mIntervalCapacityHint offset must be 0x1C"
  );
  static_assert(sizeof(ParticleRenderWorkItemRuntime) == 0x20, "ParticleRenderWorkItemRuntime size must be 0x20");

  /**
   * What it does:
   * Temporary trail bucket entry lane with a `TrailBucketKeyRuntime`-sized
   * key prefix and trailing trail vector.
   */
  struct TrailBucketEntryRuntime
  {
    std::uint8_t mKeyLane[0x34]{};               // +0x00
    msvc8::vector<TrailRuntimeView> mTrails;     // +0x34
  };

  static_assert(
    offsetof(TrailBucketEntryRuntime, mTrails) == 0x34,
    "TrailBucketEntryRuntime::mTrails offset must be 0x34"
  );
  static_assert(sizeof(TrailBucketEntryRuntime) == 0x44, "TrailBucketEntryRuntime size must be 0x44");

  /**
   * Address: 0x00493CE0 (FUN_00493CE0)
   * Address: 0x004948C0 (FUN_004948C0)
   *
   * What it does:
   * Releases interval storage owned by one work-item, then frees the work-item.
   */
  ParticleRenderWorkItemRuntime* DestroyParticleRenderWorkItem(ParticleRenderWorkItemRuntime* workItem);

  /**
   * Address: 0x00493D20 (FUN_00493D20)
   * Address: 0x00494900 (FUN_00494900)
   *
   * What it does:
   * Releases interval storage owned by one work-item and resets interval lanes.
   */
  void ResetParticleRenderWorkItemIntervals(ParticleRenderWorkItemRuntime& workItem);

  /**
   * Address: 0x00493D50 (FUN_00493D50)
   *
   * What it does:
   * Initializes one render work-item with particle-buffer owner and interval cap.
   */
  ParticleRenderWorkItemRuntime* InitializeParticleRenderWorkItem(
    ParticleRenderWorkItemRuntime& workItem,
    std::uint32_t intervalCapacityHint,
    void* particleBuffer
  );

  /**
   * Address: 0x00493D70 (FUN_00493D70)
   *
   * What it does:
   * Advances interval cursor while intervals are expired for the current frame.
   * Returns true when no active interval remains.
   */
  bool AdvanceParticleRenderWorkItemCursorToFrame(ParticleRenderWorkItemRuntime& workItem, float frameValue);

  /**
   * Address: 0x00494730 (FUN_00494730)
   *
   * What it does:
   * Appends one trail payload to the trailing trail-vector in a trail bucket
   * entry.
   */
  void AppendTrailToBucketEntry(const TrailRuntimeView& trail, TrailBucketEntryRuntime& bucketEntry);
} // namespace moho
