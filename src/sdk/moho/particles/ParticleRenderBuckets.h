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
  struct SParticleRenderWorkItem;
  struct SWorldParticle;
  struct SWorldBeam;
  struct SWorldTrail;

  /**
   * What it does:
   * One pooled trail-segment render buffer lane owned by `CWorldParticles`.
   */
  struct STrailSegmentBuffer
  {
    ID3DVertexSheet* vertexSheet = nullptr;    // +0x00
    std::uint8_t unknown04_0F[0x0C]{};         // +0x04
    std::uint32_t maxSegments = 0U;            // +0x10
    void* mappedVertexData = nullptr;          // +0x14
  };

  static_assert(
    offsetof(STrailSegmentBuffer, vertexSheet) == 0x00,
    "STrailSegmentBuffer::vertexSheet offset must be 0x00"
  );
  static_assert(
    offsetof(STrailSegmentBuffer, maxSegments) == 0x10,
    "STrailSegmentBuffer::maxSegments offset must be 0x10"
  );
  static_assert(
    offsetof(STrailSegmentBuffer, mappedVertexData) == 0x14,
    "STrailSegmentBuffer::mappedVertexData offset must be 0x14"
  );
  static_assert(sizeof(STrailSegmentBuffer) == 0x18, "STrailSegmentBuffer size must be 0x18");

  /**
   * What it does:
   * One owner-pool RB-tree node lane for trail segment buffers, preserving the
   * original `left/parent/right + key + color/is-nil` shape.
   */
  /**
   * The trail-segment owner pool is `std::set<STrailSegmentBuffer*>`:
   * the node is 0x14 with links at 0/4/8, the buffer pointer at +0x0C and the
   * colour/nil pair at +0x10/+0x11, which is exactly what `msvc8::set` lays
   * out for a 4-byte value. Ordering is by raw pointer, so the default
   * `std::less` is the right predicate.
   */
  using TrailSegmentPool = msvc8::set<STrailSegmentBuffer*>;

  static_assert(sizeof(TrailSegmentPool) == 0x0C, "TrailSegmentPool size must be 0x0C");

  /**
   * What it does:
   * One world-particle render bucket: everything that decides how a particle is
   * drawn (drag, both textures, technique tag, blend and z modes), the particles
   * waiting to be uploaded, and the work items currently drawing them.
   */
  struct SParticleRenderBucket
  {
    /**
     * Address: 0x00493AE0 (FUN_00493AE0, func_ParticleSelectTechnique2)
     *
     * IDA signature:
     * void __thiscall sub_493AE0(SParticleRenderBucket *this);
     *
     * What it does:
     * Publishes this bucket's drag flag and two textures to their shader
     * variables, then selects `tag` + the blend-mode suffix as the active
     * technique. Six suffixes here against the trail path's five: a particle
     * bucket can also be `_REFRACT`.
     *
     * Reads `[this+0]`, `[this+4]`, `[this+0xC]`, `[this+0x14]` and
     * `[this+0x30]` -- this object, not a copy of its prefix.
     */
    void SelectTechnique() const;

    bool dragEnabled = false;                                  // +0x00  SWorldParticle::mDragEnabled
    std::uint8_t statePadding01_03[0x03]{};                    // +0x01
    CParticleTexture::TextureResourceHandle texture0;          // +0x04
    CParticleTexture::TextureResourceHandle texture1;          // +0x0C
    msvc8::string tag;                                         // +0x14
    std::int32_t blendMode = 0;                                // +0x30
    std::int32_t zMode = 0;                                    // +0x34
    msvc8::vector<SWorldParticle> pendingParticles; // +0x38
    msvc8::vector<SParticleRenderWorkItem*> activeWorkItems; // +0x48
    CWorldParticles* owner = nullptr;                          // +0x58
  };

  static_assert(
    offsetof(SParticleRenderBucket, dragEnabled) == 0x00,
    "SParticleRenderBucket::dragEnabled offset must be 0x00"
  );
  static_assert(
    offsetof(SParticleRenderBucket, texture0) == 0x04,
    "SParticleRenderBucket::texture0 offset must be 0x04"
  );
  static_assert(
    offsetof(SParticleRenderBucket, texture1) == 0x0C,
    "SParticleRenderBucket::texture1 offset must be 0x0C"
  );
  static_assert(offsetof(SParticleRenderBucket, tag) == 0x14, "SParticleRenderBucket::tag offset must be 0x14");
  static_assert(
    offsetof(SParticleRenderBucket, blendMode) == 0x30,
    "SParticleRenderBucket::blendMode offset must be 0x30"
  );
  static_assert(
    offsetof(SParticleRenderBucket, zMode) == 0x34,
    "SParticleRenderBucket::zMode offset must be 0x34"
  );
  static_assert(
    offsetof(SParticleRenderBucket, pendingParticles) == 0x38,
    "SParticleRenderBucket::pendingParticles offset must be 0x38"
  );
  static_assert(
    offsetof(SParticleRenderBucket, activeWorkItems) == 0x48,
    "SParticleRenderBucket::activeWorkItems offset must be 0x48"
  );
  static_assert(
    offsetof(SParticleRenderBucket, owner) == 0x58,
    "SParticleRenderBucket::owner offset must be 0x58"
  );
  static_assert(sizeof(SParticleRenderBucket) == 0x5C, "SParticleRenderBucket size must be 0x5C");

  /**
   * What it does:
   * One trail render bucket: the same, for trail ribbons -- no drag flag and no
   * z mode, and the pending lane holds `SWorldTrail` segments.
   */
  struct STrailRenderBucket
  {
    /**
     * Address: 0x00494740 (FUN_00494740, func_ParticleSelectTechnique)
     *
     * IDA signature:
     * void __thiscall sub_494740(STrailRenderBucket *this);
     *
     * What it does:
     * Publishes this bucket's two textures to their shader variables, then
     * selects `tag` + the blend-mode suffix as the active technique. Same body
     * as the particle bucket's, without the drag flag and without `_REFRACT`.
     *
     * Reads `[this+0]`, `[this+8]`, `[this+0x10]` and `[this+0x2C]`;
     * `RenderTrailBucket` reaches it as `mov ecx, edi; call 0x494740` at
     * 0x0049488F, `edi` being the bucket itself.
     */
    void SelectTechnique() const;

    CParticleTexture::TextureResourceHandle texture0;         // +0x00
    CParticleTexture::TextureResourceHandle texture1;         // +0x08
    msvc8::string tag;                                        // +0x10
    std::int32_t blendMode = 0;                               // +0x2C  blueprint BlendMode
    std::uint32_t renderStartIndex = 0U;                      // +0x30
    msvc8::vector<SWorldTrail> pendingTrails; // +0x34
    msvc8::vector<SParticleRenderWorkItem*> activeWorkItems; // +0x44
    CWorldParticles* owner = nullptr;                         // +0x54
  };

  static_assert(
    offsetof(STrailRenderBucket, texture0) == 0x00,
    "STrailRenderBucket::texture0 offset must be 0x00"
  );
  static_assert(
    offsetof(STrailRenderBucket, texture1) == 0x08,
    "STrailRenderBucket::texture1 offset must be 0x08"
  );
  static_assert(offsetof(STrailRenderBucket, tag) == 0x10, "STrailRenderBucket::tag offset must be 0x10");
  static_assert(
    offsetof(STrailRenderBucket, blendMode) == 0x2C,
    "STrailRenderBucket::blendMode offset must be 0x2C"
  );
  static_assert(
    offsetof(STrailRenderBucket, renderStartIndex) == 0x30,
    "STrailRenderBucket::renderStartIndex offset must be 0x30"
  );
  static_assert(
    offsetof(STrailRenderBucket, pendingTrails) == 0x34,
    "STrailRenderBucket::pendingTrails offset must be 0x34"
  );
  static_assert(
    offsetof(STrailRenderBucket, activeWorkItems) == 0x44,
    "STrailRenderBucket::activeWorkItems offset must be 0x44"
  );
  static_assert(offsetof(STrailRenderBucket, owner) == 0x54, "STrailRenderBucket::owner offset must be 0x54");
  static_assert(sizeof(STrailRenderBucket) == 0x58, "STrailRenderBucket size must be 0x58");

  /**
   * Address: 0x00493480 (FUN_00493480, sub_493480)
   *
   * What it does:
   * Initializes one particle render bucket key/runtime lane from one world
   * particle payload and stores owner context.
   */
  SParticleRenderBucket* InitializeParticleRenderBucketFromWorldParticle(
    SParticleRenderBucket& bucket,
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
  STrailRenderBucket* InitializeTrailRenderBucketFromTrail(
    STrailRenderBucket& bucket,
    const SWorldTrail& trail,
    CWorldParticles* owner
  );

  /**
   * Address: 0x00493C30 (FUN_00493C30, func_RenderParticle2)
   *
   * What it does:
   * Selects the particle technique, then renders active particle work items in
   * reverse order when the current bucket is allowed to draw.
   */
  bool RenderParticleBucket(SParticleRenderBucket& bucket, float frameValue, bool onlyTLight);

  /**
   * Address: 0x00493DA0 (FUN_00493DA0, sub_493DA0)
   *
   * What it does:
   * Uploads a bounded batch of pending trail payloads into one trail work-item
   * instance stream for the current frame.
   */
  bool UploadPendingTrailsIntoWorkItem(
    SParticleRenderWorkItem& workItem,
    float frameDelta,
    msvc8::vector<SWorldTrail>& pendingTrails
  );

  /**
   * Address: 0x00494480 (FUN_00494480, sub_494480)
   *
   * What it does:
   * Advances active trail work items to the target frame and compacts the
   * active lane while recycling expired entries.
   */
  void PruneExpiredTrailBucketWorkItems(STrailRenderBucket& bucket, float frameValue);

  /**
   * Address: 0x004945C0 (FUN_004945C0, sub_4945C0)
   *
   * What it does:
   * Ensures active trail work items exist for pending trail payloads and uploads
   * data batches until payload is consumed or pool capacity is exhausted.
   */
  bool EnsureAndFillTrailBucketWorkItems(STrailRenderBucket& bucket, float frameDelta);

  /**
   * Address: 0x00494850 (FUN_00494850, func_RenderParticle)
   *
   * What it does:
   * Selects the trail technique, then renders active trail work items in order
   * when the current bucket is allowed to draw.
   */
  bool RenderTrailBucket(STrailRenderBucket& bucket, float frameValue, bool onlyTLight);

  /**
   * Address: 0x00493210 (FUN_00493210, sub_493210)
   *
   * What it does:
   * Uploads a bounded batch of pending world particles into one particle
   * work-item instance stream for the current frame.
   */
  void UploadPendingParticlesIntoWorkItem(
    SParticleRenderWorkItem& workItem,
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
  void RecycleAndDestroyParticleBucketWorkItems(SParticleRenderBucket& bucket);

  /**
   * Address: 0x00493620 (FUN_00493620, sub_493620)
   *
   * What it does:
   * Releases one particle render bucket runtime lane including key state,
   * pending payload lanes, and active work-item lanes.
  */
  void DestroyParticleRenderBucket(SParticleRenderBucket& bucket);

  /**
   * Address: 0x004943E0 (FUN_004943E0, sub_4943E0)
   *
   * What it does:
   * Returns active trail work-item segment buffers to the owner pool and
   * destroys the work-item objects.
   */
  void RecycleAndDestroyTrailBucketWorkItems(STrailRenderBucket& bucket);

  /**
   * Address: 0x004942E0 (FUN_004942E0, sub_4942E0)
   *
   * What it does:
   * Releases one trail render bucket runtime lane including key state,
   * pending trail payload lanes, and active work-item lanes.
   */
  void DestroyTrailRenderBucket(STrailRenderBucket& bucket);

  /**
   * Address: 0x004937E0 (FUN_004937E0, sub_4937E0)
   *
   * What it does:
   * Advances active particle work items to the target frame and compacts the
   * active lane while recycling expired entries.
   */
  void PruneExpiredParticleBucketWorkItems(SParticleRenderBucket& bucket, float frameValue);

  /**
   * Address: 0x00493940 (FUN_00493940, sub_493940)
   *
   * What it does:
   * Ensures active work items exist for pending particle payload and uploads
   * data batches until payload is consumed or pool capacity is exhausted.
   */
  bool EnsureAndFillParticleBucketWorkItems(SParticleRenderBucket& bucket, float frameDelta);
} // namespace moho
