#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/particles/BeamRenderHelpers.h"

namespace moho
{
  /**
   * What it does:
   * One time-interval lane consumed by the particle render work-item cursor.
   * Address: 0x004A00A0 (FUN_004A00A0 -- the compiler-generated copy constructor (placement copy into a raw slot) of `SParticleRenderInterval` as emitted for its `msvc8::vector` instantiation; zero callers, unreachable; formerly `CopySingleDwordPairIfDestinationPresent` in moho/particles/CWorldParticles.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x004A00C0 (FUN_004A00C0 -- the compiler-generated copy constructor (placement copy into a raw slot) of `SParticleRenderInterval` as emitted for its `msvc8::vector` instantiation; zero callers, unreachable; formerly `CopySingleDwordPairIfDestinationPresentDuplicateA` in moho/particles/CWorldParticles.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x004A06D0 (FUN_004A06D0 -- the compiler-generated copy constructor (placement copy into a raw slot) of `SParticleRenderInterval` as emitted for its `msvc8::vector` instantiation; zero callers, unreachable; formerly `CopySingleDwordPairIfDestinationPresentDuplicateB` in moho/particles/CWorldParticles.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x004A06F0 (FUN_004A06F0 -- the compiler-generated copy constructor (placement copy into a raw slot) of `SParticleRenderInterval` as emitted for its `msvc8::vector` instantiation; zero callers, unreachable; formerly `CopySingleDwordPairIfDestinationPresentDuplicateC` in moho/particles/CWorldParticles.cpp (RULE ONE), removed 2026-09-10.)
   */
  struct SParticleRenderInterval
  {
    float beginFrame = 0.0F;   // +0x00
    float lifeFrames = 0.0F;   // +0x04
  };

  static_assert(
    offsetof(SParticleRenderInterval, beginFrame) == 0x00,
    "SParticleRenderInterval::beginFrame offset must be 0x00"
  );
  static_assert(
    offsetof(SParticleRenderInterval, lifeFrames) == 0x04,
    "SParticleRenderInterval::lifeFrames offset must be 0x04"
  );
  static_assert(sizeof(SParticleRenderInterval) == 0x08, "SParticleRenderInterval size must be 0x08");

  /**
   * What it does:
   * One in-flight particle/trail render work item, used by the queue helpers around
   * `func_RenderParticle2`.
   */
  struct SParticleRenderWorkItem
  {
    void* mParticleBuffer = nullptr;                              // +0x00
    msvc8::vector<SParticleRenderInterval> mIntervals;      // +0x04
    std::uint32_t mIntervalCursor = 0U;                           // +0x14
    std::uint32_t mRenderStartIndex = 0U;                         // +0x18
    std::uint32_t mIntervalCapacityHint = 0U;                     // +0x1C
  };

  static_assert(
    offsetof(SParticleRenderWorkItem, mParticleBuffer) == 0x00,
    "SParticleRenderWorkItem::mParticleBuffer offset must be 0x00"
  );
  static_assert(
    offsetof(SParticleRenderWorkItem, mIntervals) == 0x04,
    "SParticleRenderWorkItem::mIntervals offset must be 0x04"
  );
  static_assert(
    offsetof(SParticleRenderWorkItem, mIntervalCursor) == 0x14,
    "SParticleRenderWorkItem::mIntervalCursor offset must be 0x14"
  );
  static_assert(
    offsetof(SParticleRenderWorkItem, mRenderStartIndex) == 0x18,
    "SParticleRenderWorkItem::mRenderStartIndex offset must be 0x18"
  );
  static_assert(
    offsetof(SParticleRenderWorkItem, mIntervalCapacityHint) == 0x1C,
    "SParticleRenderWorkItem::mIntervalCapacityHint offset must be 0x1C"
  );
  static_assert(sizeof(SParticleRenderWorkItem) == 0x20, "SParticleRenderWorkItem size must be 0x20");

  /**
   * What it does:
   * Temporary trail bucket entry lane with a `STrailBucketKey`-sized
   * key prefix and trailing trail vector.
   */
  struct STrailBucketEntry
  {
    std::uint8_t mKeyLane[0x34]{};               // +0x00
    msvc8::vector<SWorldTrail> mTrails;     // +0x34
  };

  static_assert(
    offsetof(STrailBucketEntry, mTrails) == 0x34,
    "STrailBucketEntry::mTrails offset must be 0x34"
  );
  static_assert(sizeof(STrailBucketEntry) == 0x44, "STrailBucketEntry size must be 0x44");

  /**
   * Address: 0x00493CE0 (FUN_00493CE0)
   * Address: 0x004948C0 (FUN_004948C0)
   *
   * What it does:
   * Releases interval storage owned by one work-item, then frees the work-item.
   */
  SParticleRenderWorkItem* DestroyParticleRenderWorkItem(SParticleRenderWorkItem* workItem);

  /**
   * Address: 0x00493D20 (FUN_00493D20)
   * Address: 0x00494900 (FUN_00494900)
   *
   * What it does:
   * Releases interval storage owned by one work-item and resets interval lanes.
   */
  void ResetParticleRenderWorkItemIntervals(SParticleRenderWorkItem& workItem);

  /**
   * Address: 0x00493D50 (FUN_00493D50)
   *
   * What it does:
   * Initializes one render work-item with particle-buffer owner and interval cap.
   */
  SParticleRenderWorkItem* InitializeParticleRenderWorkItem(
    SParticleRenderWorkItem& workItem,
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
  bool AdvanceParticleRenderWorkItemCursorToFrame(SParticleRenderWorkItem& workItem, float frameValue);

  /**
   * Address: 0x00494730 (FUN_00494730)
   *
   * What it does:
   * Appends one trail payload to the trailing trail-vector in a trail bucket
   * entry.
   */
  void AppendTrailToBucketEntry(const SWorldTrail& trail, STrailBucketEntry& bucketEntry);
} // namespace moho
