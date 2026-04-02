#pragma once

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
   * Models one VC8 debug-vector lane (`_Myfirstiter + begin/end/capacity`) used
   * by particle/trail render buckets.
   */
  template <typename TValue>
  struct RenderBucketVectorRuntime
  {
    std::uint32_t iteratorProxy = 0U; // +0x00
    TValue* begin = nullptr;          // +0x04
    TValue* end = nullptr;            // +0x08
    TValue* capacityEnd = nullptr;    // +0x0C
  };

  static_assert(
    sizeof(RenderBucketVectorRuntime<std::uint32_t>) == 0x10,
    "RenderBucketVectorRuntime size must be 0x10"
  );

  /**
   * What it does:
   * One intrusive list node lane used by `CWorldParticles` particle-buffer pools.
   */
  struct ParticleBufferPoolNodeRuntime
  {
    ParticleBufferPoolNodeRuntime* next = nullptr; // +0x00
    ParticleBufferPoolNodeRuntime* prev = nullptr; // +0x04
    ParticleBuffer* value = nullptr;               // +0x08
  };

  static_assert(sizeof(ParticleBufferPoolNodeRuntime) == 0x0C, "ParticleBufferPoolNodeRuntime size must be 0x0C");

  /**
   * What it does:
   * One VC8 debug-list lane used by the owner pool queue.
   */
  struct ParticleBufferPoolListRuntime
  {
    std::uint32_t iteratorProxy = 0U;                // +0x00
    ParticleBufferPoolNodeRuntime* head = nullptr;   // +0x04
    std::uint32_t size = 0U;                         // +0x08
  };

  static_assert(sizeof(ParticleBufferPoolListRuntime) == 0x0C, "ParticleBufferPoolListRuntime size must be 0x0C");

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
  struct TrailSegmentPoolNodeRuntime
  {
    TrailSegmentPoolNodeRuntime* left = nullptr;   // +0x00
    TrailSegmentPoolNodeRuntime* parent = nullptr; // +0x04
    TrailSegmentPoolNodeRuntime* right = nullptr;  // +0x08
    TrailSegmentBufferRuntime* segmentBuffer = nullptr; // +0x0C
    std::uint8_t color = 0U;                       // +0x10
    std::uint8_t isNil = 0U;                       // +0x11
    std::uint16_t padding12 = 0U;                  // +0x12
  };

  static_assert(
    offsetof(TrailSegmentPoolNodeRuntime, segmentBuffer) == 0x0C,
    "TrailSegmentPoolNodeRuntime::segmentBuffer offset must be 0x0C"
  );
  static_assert(
    offsetof(TrailSegmentPoolNodeRuntime, color) == 0x10,
    "TrailSegmentPoolNodeRuntime::color offset must be 0x10"
  );
  static_assert(
    offsetof(TrailSegmentPoolNodeRuntime, isNil) == 0x11,
    "TrailSegmentPoolNodeRuntime::isNil offset must be 0x11"
  );
  static_assert(sizeof(TrailSegmentPoolNodeRuntime) == 0x14, "TrailSegmentPoolNodeRuntime size must be 0x14");

  /**
   * What it does:
   * One `CWorldParticles` trail-segment owner pool header lane (`+0x1C`).
   */
  struct TrailSegmentPoolRuntime
  {
    std::uint32_t iteratorProxy = 0U;            // +0x00
    TrailSegmentPoolNodeRuntime* head = nullptr; // +0x04
    std::uint32_t size = 0U;                     // +0x08
  };

  static_assert(sizeof(TrailSegmentPoolRuntime) == 0x0C, "TrailSegmentPoolRuntime size must be 0x0C");

  /**
   * What it does:
   * Partial owner view exposing only the particle-buffer pool lane used by
   * particle bucket work-item helpers.
   */
  struct CWorldParticlesParticlePoolRuntimeView
  {
    std::uint8_t unknown00_0F[0x10]{};               // +0x00
    ParticleBufferPoolListRuntime availableBuffers;  // +0x10
  };

  static_assert(
    offsetof(CWorldParticlesParticlePoolRuntimeView, availableBuffers) == 0x10,
    "CWorldParticlesParticlePoolRuntimeView::availableBuffers offset must be 0x10"
  );

  /**
   * What it does:
   * Partial owner view exposing trail-segment pool lane used by trail
   * work-item paths.
   */
  struct CWorldParticlesTrailSegmentPoolRuntimeView
  {
    std::uint8_t unknown00_1B[0x1C]{};        // +0x00
    TrailSegmentPoolRuntime trailSegmentPool; // +0x1C
  };

  static_assert(
    offsetof(CWorldParticlesTrailSegmentPoolRuntimeView, trailSegmentPool) == 0x1C,
    "CWorldParticlesTrailSegmentPoolRuntimeView::trailSegmentPool offset must be 0x1C"
  );

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
    RenderBucketVectorRuntime<SWorldParticle> pendingParticles; // +0x38
    RenderBucketVectorRuntime<ParticleRenderWorkItemRuntime*> activeWorkItems; // +0x48
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
    RenderBucketVectorRuntime<TrailRuntimeView> pendingTrails; // +0x34
    RenderBucketVectorRuntime<ParticleRenderWorkItemRuntime*> activeWorkItems; // +0x44
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
   * Address: 0x00495590 (FUN_00495590, sub_495590)
   *
   * What it does:
   * Writes the begin-pointer lane of one world-particle render vector into
   * caller-provided iterator storage.
   */
  SWorldParticle** GetWorldParticleVectorBeginPointer(
    SWorldParticle** outBeginPointer,
    const RenderBucketVectorRuntime<SWorldParticle>& pendingParticles
  ) noexcept;

  /**
   * Address: 0x004955A0 (FUN_004955A0, sub_4955A0)
   *
   * What it does:
   * Returns the active world-particle element count from one render vector
   * lane.
   */
  [[nodiscard]] std::int32_t GetWorldParticleVectorCount(
    const RenderBucketVectorRuntime<SWorldParticle>& pendingParticles
  ) noexcept;

  /**
   * Address: 0x00495740 (FUN_00495740, sub_495740)
   *
   * What it does:
   * Writes the begin-pointer lane of one trail render vector into
   * caller-provided iterator storage.
   */
  TrailRuntimeView** GetTrailVectorBeginPointer(
    TrailRuntimeView** outBeginPointer,
    const RenderBucketVectorRuntime<TrailRuntimeView>& pendingTrails
  ) noexcept;

  /**
   * Address: 0x00495750 (FUN_00495750, sub_495750)
   *
   * What it does:
   * Returns the active trail element count from one render vector lane.
   */
  [[nodiscard]] std::int32_t GetTrailVectorCount(
    const RenderBucketVectorRuntime<TrailRuntimeView>& pendingTrails
  ) noexcept;

  /**
   * Address: 0x004956B0 (FUN_004956B0, sub_4956B0)
   *
   * What it does:
   * Erases one world-particle range from a pending vector lane by shifting the
   * tail left with typed copy semantics and destroying trailing entries.
   */
  SWorldParticle** EraseWorldParticleVectorRange(
    RenderBucketVectorRuntime<SWorldParticle>& pendingParticles,
    SWorldParticle** outBeginPointer,
    SWorldParticle* eraseBegin,
    SWorldParticle* eraseEnd
  ) noexcept;

  /**
   * Address: 0x00495850 (FUN_00495850, sub_495850)
   *
   * What it does:
   * Erases one trail range from a pending vector lane by shifting the tail left
   * with typed copy semantics and destroying trailing entries.
   */
  TrailRuntimeView** EraseTrailVectorRange(
    RenderBucketVectorRuntime<TrailRuntimeView>& pendingTrails,
    TrailRuntimeView** outBeginPointer,
    TrailRuntimeView* eraseBegin,
    TrailRuntimeView* eraseEnd
  ) noexcept;

  /**
   * Address: 0x00495930 (FUN_00495930, sub_495930)
   *
   * What it does:
   * Writes the begin-pointer lane of one beam vector into caller-provided
   * iterator storage.
   */
  SWorldBeam** GetBeamVectorBeginPointer(
    SWorldBeam** outBeginPointer,
    const RenderBucketVectorRuntime<SWorldBeam>& beams
  ) noexcept;

  /**
   * Address: 0x00495940 (FUN_00495940, sub_495940)
   *
   * What it does:
   * Writes the end-pointer lane of one beam vector into caller-provided
   * iterator storage.
   */
  SWorldBeam** GetBeamVectorEndPointer(
    SWorldBeam** outEndPointer,
    const RenderBucketVectorRuntime<SWorldBeam>& beams
  ) noexcept;

  /**
   * Address: 0x00495950 (FUN_00495950, sub_495950)
   *
   * What it does:
   * Returns the active beam element count from one beam vector lane.
   */
  [[nodiscard]] std::int32_t GetBeamVectorCount(
    const RenderBucketVectorRuntime<SWorldBeam>& beams
  ) noexcept;

  /**
   * Address: 0x004958F0 (FUN_004958F0, sub_4958F0)
   *
   * What it does:
   * Releases one beam-vector storage lane (including intrusive texture refs on
   * each beam payload) and clears begin/end/capacity pointers.
   */
  void ResetBeamVectorStorage(RenderBucketVectorRuntime<SWorldBeam>& beams) noexcept;

  /**
   * Address: 0x00492CA0 (FUN_00492CA0, sub_492CA0)
   *
   * What it does:
   * Appends one particle-buffer pointer into the owner available-buffer pool
   * list.
   */
  std::uint32_t AppendParticleBufferToOwnerAvailablePool(
    CWorldParticles* owner,
    ParticleBuffer* particleBuffer
  );

  /**
   * Address: 0x00492CE0 (FUN_00492CE0, sub_492CE0)
   *
   * What it does:
   * Pops and returns one trail-segment buffer pointer from the owner pool.
   * Returns `nullptr` when the pool is empty.
   */
  [[nodiscard]] TrailSegmentBufferRuntime* AcquireTrailSegmentBufferFromOwnerPool(CWorldParticles* owner);

  /**
   * Address: 0x00492D10 (FUN_00492D10, sub_492D10)
   *
   * What it does:
   * Returns one trail-segment buffer pointer back into the owner pool.
   */
  void ReturnTrailSegmentBufferToOwnerPool(
    CWorldParticles* owner,
    TrailSegmentBufferRuntime* segmentBuffer
  );

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
    RenderBucketVectorRuntime<TrailRuntimeView>& pendingTrails
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
    RenderBucketVectorRuntime<SWorldParticle>& pendingParticles
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
