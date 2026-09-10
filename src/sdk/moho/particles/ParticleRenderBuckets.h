#pragma once

#include "legacy/containers/Set.h"
#include "legacy/containers/Vector.h"
#include <cstddef>
#include <cstdint>

#include "moho/resource/CParticleTexture.h"

namespace moho
{
  class CWorldParticles;
  class ID3DVertexSheet;
  class ParticleBuffer;
  struct ParticleRenderWorkItemRuntime;
  struct SWorldParticle;
  struct SWorldBeam;
  struct TrailRuntimeView;

  /**
   * What it does:
   * One pooled trail-segment render buffer lane owned by `CWorldParticles`.
   */
  struct TrailSegmentBufferRuntime
  {
    ID3DVertexSheet* vertexSheet = nullptr;    // +0x00
    std::uint8_t unknown04_0F[0x0C]{};         // +0x04
    std::uint32_t maxSegments = 0U;            // +0x10
    void* mappedVertexData = nullptr;          // +0x14
  };

  static_assert(
    offsetof(TrailSegmentBufferRuntime, vertexSheet) == 0x00,
    "TrailSegmentBufferRuntime::vertexSheet offset must be 0x00"
  );
  static_assert(
    offsetof(TrailSegmentBufferRuntime, maxSegments) == 0x10,
    "TrailSegmentBufferRuntime::maxSegments offset must be 0x10"
  );
  static_assert(
    offsetof(TrailSegmentBufferRuntime, mappedVertexData) == 0x14,
    "TrailSegmentBufferRuntime::mappedVertexData offset must be 0x14"
  );
  static_assert(sizeof(TrailSegmentBufferRuntime) == 0x18, "TrailSegmentBufferRuntime size must be 0x18");

  /**
   * What it does:
   * One owner-pool RB-tree node lane for trail segment buffers, preserving the
   * original `left/parent/right + key + color/is-nil` shape.
   */
  /**
   * The trail-segment owner pool is `std::set<TrailSegmentBufferRuntime*>`:
   * the node is 0x14 with links at 0/4/8, the buffer pointer at +0x0C and the
   * colour/nil pair at +0x10/+0x11, which is exactly what `msvc8::set` lays
   * out for a 4-byte value. Ordering is by raw pointer, so the default
   * `std::less` is the right predicate.
   */
  using TrailSegmentPoolRuntime = msvc8::set<TrailSegmentBufferRuntime*>;

  static_assert(sizeof(TrailSegmentPoolRuntime) == 0x0C, "TrailSegmentPoolRuntime size must be 0x0C");

  /**
   * What it does:
   * Runtime lane keyed by world-particle render properties and retaining pending
   * particles plus active work items.
   */
  struct ParticleRenderBucketRuntime
  {
    bool stateByte = false;                                    // +0x00
    std::uint8_t statePadding01_03[0x03]{};                    // +0x01
    CParticleTexture::TextureResourceHandle texture0;          // +0x04
    CParticleTexture::TextureResourceHandle texture1;          // +0x0C
    msvc8::string tag;                                         // +0x14
    std::int32_t blendMode = 0;                                // +0x30
    std::int32_t zMode = 0;                                    // +0x34
    msvc8::vector<SWorldParticle> pendingParticles; // +0x38
    msvc8::vector<ParticleRenderWorkItemRuntime*> activeWorkItems; // +0x48
    CWorldParticles* owner = nullptr;                          // +0x58
  };

  static_assert(
    offsetof(ParticleRenderBucketRuntime, stateByte) == 0x00,
    "ParticleRenderBucketRuntime::stateByte offset must be 0x00"
  );
  static_assert(
    offsetof(ParticleRenderBucketRuntime, texture0) == 0x04,
    "ParticleRenderBucketRuntime::texture0 offset must be 0x04"
  );
  static_assert(
    offsetof(ParticleRenderBucketRuntime, texture1) == 0x0C,
    "ParticleRenderBucketRuntime::texture1 offset must be 0x0C"
  );
  static_assert(offsetof(ParticleRenderBucketRuntime, tag) == 0x14, "ParticleRenderBucketRuntime::tag offset must be 0x14");
  static_assert(
    offsetof(ParticleRenderBucketRuntime, blendMode) == 0x30,
    "ParticleRenderBucketRuntime::blendMode offset must be 0x30"
  );
  static_assert(
    offsetof(ParticleRenderBucketRuntime, zMode) == 0x34,
    "ParticleRenderBucketRuntime::zMode offset must be 0x34"
  );
  static_assert(
    offsetof(ParticleRenderBucketRuntime, pendingParticles) == 0x38,
    "ParticleRenderBucketRuntime::pendingParticles offset must be 0x38"
  );
  static_assert(
    offsetof(ParticleRenderBucketRuntime, activeWorkItems) == 0x48,
    "ParticleRenderBucketRuntime::activeWorkItems offset must be 0x48"
  );
  static_assert(
    offsetof(ParticleRenderBucketRuntime, owner) == 0x58,
    "ParticleRenderBucketRuntime::owner offset must be 0x58"
  );
  static_assert(sizeof(ParticleRenderBucketRuntime) == 0x5C, "ParticleRenderBucketRuntime size must be 0x5C");

  /**
   * What it does:
   * Runtime lane keyed by trail render properties and retaining pending trail
   * segments plus active work items.
   */
  struct TrailRenderBucketRuntime
  {
    CParticleTexture::TextureResourceHandle texture0;         // +0x00
    CParticleTexture::TextureResourceHandle texture1;         // +0x08
    msvc8::string tag;                                        // +0x10
    float uvScalar = 0.0f;                                    // +0x2C
    std::uint32_t renderStartIndex = 0U;                      // +0x30
    msvc8::vector<TrailRuntimeView> pendingTrails; // +0x34
    msvc8::vector<ParticleRenderWorkItemRuntime*> activeWorkItems; // +0x44
    CWorldParticles* owner = nullptr;                         // +0x54
  };

  static_assert(
    offsetof(TrailRenderBucketRuntime, texture0) == 0x00,
    "TrailRenderBucketRuntime::texture0 offset must be 0x00"
  );
  static_assert(
    offsetof(TrailRenderBucketRuntime, texture1) == 0x08,
    "TrailRenderBucketRuntime::texture1 offset must be 0x08"
  );
  static_assert(offsetof(TrailRenderBucketRuntime, tag) == 0x10, "TrailRenderBucketRuntime::tag offset must be 0x10");
  static_assert(
    offsetof(TrailRenderBucketRuntime, uvScalar) == 0x2C,
    "TrailRenderBucketRuntime::uvScalar offset must be 0x2C"
  );
  static_assert(
    offsetof(TrailRenderBucketRuntime, renderStartIndex) == 0x30,
    "TrailRenderBucketRuntime::renderStartIndex offset must be 0x30"
  );
  static_assert(
    offsetof(TrailRenderBucketRuntime, pendingTrails) == 0x34,
    "TrailRenderBucketRuntime::pendingTrails offset must be 0x34"
  );
  static_assert(
    offsetof(TrailRenderBucketRuntime, activeWorkItems) == 0x44,
    "TrailRenderBucketRuntime::activeWorkItems offset must be 0x44"
  );
  static_assert(offsetof(TrailRenderBucketRuntime, owner) == 0x54, "TrailRenderBucketRuntime::owner offset must be 0x54");
  static_assert(sizeof(TrailRenderBucketRuntime) == 0x58, "TrailRenderBucketRuntime size must be 0x58");

  /**
   * Address: 0x00493480 (FUN_00493480, sub_493480)
   *
   * What it does:
   * Initializes one particle render bucket key/runtime lane from one world
   * particle payload and stores owner context.
   */
  ParticleRenderBucketRuntime* InitializeParticleRenderBucketFromWorldParticle(
    ParticleRenderBucketRuntime& bucket,
    const SWorldParticle& particle,
    CWorldParticles* owner
  );

  /**
   * Address: 0x00494140 (FUN_00494140, sub_494140)
   *
   * What it does:
   * Initializes one trail render bucket key/runtime lane from one trail payload
   * and stores owner context.
   */
  TrailRenderBucketRuntime* InitializeTrailRenderBucketFromTrail(
    TrailRenderBucketRuntime& bucket,
    const TrailRuntimeView& trail,
    CWorldParticles* owner
  );

  /**
   * Address: 0x00493C30 (FUN_00493C30, func_RenderParticle2)
   *
   * What it does:
   * Selects the particle technique, then renders active particle work items in
   * reverse order when the current bucket is allowed to draw.
   */
  bool RenderParticleBucket(ParticleRenderBucketRuntime& bucket, float frameValue, bool onlyTLight);

  /**
   * Address: 0x00493DA0 (FUN_00493DA0, sub_493DA0)
   *
   * What it does:
   * Uploads a bounded batch of pending trail payloads into one trail work-item
   * instance stream for the current frame.
   */
  bool UploadPendingTrailsIntoWorkItem(
    ParticleRenderWorkItemRuntime& workItem,
    float frameDelta,
    msvc8::vector<TrailRuntimeView>& pendingTrails
  );

  /**
   * Address: 0x00494480 (FUN_00494480, sub_494480)
   *
   * What it does:
   * Advances active trail work items to the target frame and compacts the
   * active lane while recycling expired entries.
   */
  void PruneExpiredTrailBucketWorkItems(TrailRenderBucketRuntime& bucket, float frameValue);

  /**
   * Address: 0x004945C0 (FUN_004945C0, sub_4945C0)
   *
   * What it does:
   * Ensures active trail work items exist for pending trail payloads and uploads
   * data batches until payload is consumed or pool capacity is exhausted.
   */
  bool EnsureAndFillTrailBucketWorkItems(TrailRenderBucketRuntime& bucket, float frameDelta);

  /**
   * Address: 0x00494850 (FUN_00494850, func_RenderParticle)
   *
   * What it does:
   * Selects the trail technique, then renders active trail work items in order
   * when the current bucket is allowed to draw.
   */
  bool RenderTrailBucket(TrailRenderBucketRuntime& bucket, float frameValue, bool onlyTLight);

  /**
   * Address: 0x00493210 (FUN_00493210, sub_493210)
   *
   * What it does:
   * Uploads a bounded batch of pending world particles into one particle
   * work-item instance stream for the current frame.
   */
  bool UploadPendingParticlesIntoWorkItem(
    ParticleRenderWorkItemRuntime& workItem,
    float frameDelta,
    msvc8::vector<SWorldParticle>& pendingParticles
  );

  /**
   * Address: 0x00493720 (FUN_00493720, sub_493720)
   *
   * What it does:
   * Returns active particle work-item buffers to the owner pool and destroys
   * the work-item objects.
   */
  void RecycleAndDestroyParticleBucketWorkItems(ParticleRenderBucketRuntime& bucket);

  /**
   * Address: 0x00493620 (FUN_00493620, sub_493620)
   *
   * What it does:
   * Releases one particle render bucket runtime lane including key state,
   * pending payload lanes, and active work-item lanes.
  */
  void DestroyParticleRenderBucket(ParticleRenderBucketRuntime& bucket);

  /**
   * Address: 0x004943E0 (FUN_004943E0, sub_4943E0)
   *
   * What it does:
   * Returns active trail work-item segment buffers to the owner pool and
   * destroys the work-item objects.
   */
  void RecycleAndDestroyTrailBucketWorkItems(TrailRenderBucketRuntime& bucket);

  /**
   * Address: 0x004942E0 (FUN_004942E0, sub_4942E0)
   *
   * What it does:
   * Releases one trail render bucket runtime lane including key state,
   * pending trail payload lanes, and active work-item lanes.
   */
  void DestroyTrailRenderBucket(TrailRenderBucketRuntime& bucket);

  /**
   * Address: 0x004937E0 (FUN_004937E0, sub_4937E0)
   *
   * What it does:
   * Advances active particle work items to the target frame and compacts the
   * active lane while recycling expired entries.
   */
  void PruneExpiredParticleBucketWorkItems(ParticleRenderBucketRuntime& bucket, float frameValue);

  /**
   * Address: 0x00493940 (FUN_00493940, sub_493940)
   *
   * What it does:
   * Ensures active work items exist for pending particle payload and uploads
   * data batches until payload is consumed or pool capacity is exhausted.
   */
  bool EnsureAndFillParticleBucketWorkItems(ParticleRenderBucketRuntime& bucket, float frameDelta);
} // namespace moho
