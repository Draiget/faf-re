#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/weak_ptr.h"
#include "moho/particles/ParticleRenderBuckets.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/particles/BeamRenderHelpers.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/SWorldParticle.h"

namespace gpg::gal
{
  class TextureD3D9;
}

namespace moho
{
  class GeomCamera3;
  class ID3DIndexSheet;
  struct ParticleBucketTreeNodeRuntime;
  struct TrailBucketTreeNodeRuntime;

  /**
   * What it does:
   * Typed runtime view for one world-particle submit buffer passed through
   * `CWorldParticles::AddParticles`.
   */
  struct ParticleSubmitBufferRuntimeView
  {
    std::uint32_t particlesIteratorProxy; // +0x00
    SWorldParticle* particlesBegin;       // +0x04
    SWorldParticle* particlesEnd;         // +0x08
    SWorldParticle* particlesCapacityEnd; // +0x0C

    std::uint32_t trailsIteratorProxy;    // +0x10
    TrailRuntimeView* trailsBegin;        // +0x14
    TrailRuntimeView* trailsEnd;          // +0x18
    TrailRuntimeView* trailsCapacityEnd;  // +0x1C

    std::uint32_t beamsIteratorProxy;     // +0x20
    SWorldBeam* beamsBegin;               // +0x24
    SWorldBeam* beamsEnd;                 // +0x28
    SWorldBeam* beamsCapacityEnd;         // +0x2C
  };

  static_assert(
    offsetof(ParticleSubmitBufferRuntimeView, particlesBegin) == 0x04,
    "ParticleSubmitBufferRuntimeView::particlesBegin offset must be 0x04"
  );
  static_assert(
    offsetof(ParticleSubmitBufferRuntimeView, particlesEnd) == 0x08,
    "ParticleSubmitBufferRuntimeView::particlesEnd offset must be 0x08"
  );
  static_assert(
    offsetof(ParticleSubmitBufferRuntimeView, trailsBegin) == 0x14,
    "ParticleSubmitBufferRuntimeView::trailsBegin offset must be 0x14"
  );
  static_assert(
    offsetof(ParticleSubmitBufferRuntimeView, trailsEnd) == 0x18,
    "ParticleSubmitBufferRuntimeView::trailsEnd offset must be 0x18"
  );
  static_assert(
    offsetof(ParticleSubmitBufferRuntimeView, beamsBegin) == 0x24,
    "ParticleSubmitBufferRuntimeView::beamsBegin offset must be 0x24"
  );
  static_assert(
    offsetof(ParticleSubmitBufferRuntimeView, beamsEnd) == 0x28,
    "ParticleSubmitBufferRuntimeView::beamsEnd offset must be 0x28"
  );
  static_assert(sizeof(ParticleSubmitBufferRuntimeView) == 0x30, "ParticleSubmitBufferRuntimeView size must be 0x30");

  /**
   * What it does:
   * Stores beam render-bucket state on `CWorldParticles` at the recovered
   * `+0xCC` lane.
   */
  struct BeamBucketContainerRuntime
  {
    CD3DVertexSheet* mVertexSheet = nullptr; // +0x00
    BeamTextureBucketMapRuntime mBuckets;     // +0x04
  };

  static_assert(
    offsetof(BeamBucketContainerRuntime, mVertexSheet) == 0x00,
    "BeamBucketContainerRuntime::mVertexSheet offset must be 0x00"
  );

  /**
   * What it does:
   * One red-black tree node runtime lane used by world-particle bucket maps at
   * `CWorldParticles + 0x28` and `+0x34`.
   */
  struct ParticleBucketTreeNodeRuntime
  {
    ParticleBucketTreeNodeRuntime* left = nullptr;   // +0x00
    ParticleBucketTreeNodeRuntime* parent = nullptr; // +0x04
    ParticleBucketTreeNodeRuntime* right = nullptr;  // +0x08
    std::uint8_t payload0C_4B[0x40]{};               // +0x0C
    std::uint8_t color = 0U;                         // +0x4C
    std::uint8_t isNil = 0U;                         // +0x4D
    std::uint16_t padding4E = 0U;                    // +0x4E
  };

  static_assert(
    offsetof(ParticleBucketTreeNodeRuntime, color) == 0x4C,
    "ParticleBucketTreeNodeRuntime::color offset must be 0x4C"
  );
  static_assert(
    offsetof(ParticleBucketTreeNodeRuntime, isNil) == 0x4D,
    "ParticleBucketTreeNodeRuntime::isNil offset must be 0x4D"
  );
  static_assert(sizeof(ParticleBucketTreeNodeRuntime) == 0x50, "ParticleBucketTreeNodeRuntime size must be 0x50");

  /**
   * What it does:
   * One red-black tree node runtime lane used by world-trail bucket maps at
   * `CWorldParticles + 0x40`.
   */
  struct TrailBucketTreeNodeRuntime
  {
    TrailBucketTreeNodeRuntime* left = nullptr;      // +0x00
    TrailBucketTreeNodeRuntime* parent = nullptr;    // +0x04
    TrailBucketTreeNodeRuntime* right = nullptr;     // +0x08
    std::uint8_t payload0C_43[0x38]{};               // +0x0C
    std::uint8_t color = 0U;                         // +0x44
    std::uint8_t isNil = 0U;                         // +0x45
    std::uint16_t padding46 = 0U;                    // +0x46
  };

  static_assert(
    offsetof(TrailBucketTreeNodeRuntime, color) == 0x44,
    "TrailBucketTreeNodeRuntime::color offset must be 0x44"
  );
  static_assert(
    offsetof(TrailBucketTreeNodeRuntime, isNil) == 0x45,
    "TrailBucketTreeNodeRuntime::isNil offset must be 0x45"
  );
  static_assert(sizeof(TrailBucketTreeNodeRuntime) == 0x48, "TrailBucketTreeNodeRuntime size must be 0x48");

  /**
   * What it does:
   * Legacy tree-map header lane (`proxy + head + size`) used by world-particle
   * bucket maps.
   */
  struct ParticleBucketTreeRuntime
  {
    std::uint32_t iteratorProxy = 0U;             // +0x00
    ParticleBucketTreeNodeRuntime* head = nullptr; // +0x04
    std::uint32_t size = 0U;                      // +0x08
  };

  static_assert(sizeof(ParticleBucketTreeRuntime) == 0x0C, "ParticleBucketTreeRuntime size must be 0x0C");

  /**
   * What it does:
   * Legacy tree-map header lane (`proxy + head + size`) used by world-trail
   * bucket maps.
   */
  struct TrailBucketTreeRuntime
  {
    std::uint32_t iteratorProxy = 0U;          // +0x00
    TrailBucketTreeNodeRuntime* head = nullptr; // +0x04
    std::uint32_t size = 0U;                   // +0x08
  };

  static_assert(sizeof(TrailBucketTreeRuntime) == 0x0C, "TrailBucketTreeRuntime size must be 0x0C");

  /**
   * What it does:
   * Typed constructor/init runtime view for `CWorldParticles` lanes through
   * offset `+0xC8`.
   */
  struct CWorldParticlesRuntimeView
  {
    void* vtable = nullptr;                                 // +0x00
    ParticleBufferPoolListRuntime allParticleBuffers;       // +0x04
    ParticleBufferPoolListRuntime availableParticleBuffers; // +0x10
    TrailSegmentPoolRuntime trailSegmentPool;               // +0x1C
    ParticleBucketTreeRuntime particleBuckets;              // +0x28
    ParticleBucketTreeRuntime refractingParticleBuckets;    // +0x34
    TrailBucketTreeRuntime trailBuckets;                    // +0x40
    ParticleBucketKeyRuntime particleBucketLookupKey;       // +0x4C
    ParticleRenderBucketRuntime* cachedParticleBucket = nullptr; // +0x88
    TrailBucketKeyRuntime trailBucketLookupKey;             // +0x8C
    TrailRenderBucketRuntime* cachedTrailBucket = nullptr;  // +0xC0
    std::int32_t beatsSincePause = 0;                       // +0xC4
    bool instantiated = false;                              // +0xC8
    std::uint8_t paddingC9_CB[0x03]{};                      // +0xC9
  };

  static_assert(
    offsetof(CWorldParticlesRuntimeView, allParticleBuffers) == 0x04,
    "CWorldParticlesRuntimeView::allParticleBuffers offset must be 0x04"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, availableParticleBuffers) == 0x10,
    "CWorldParticlesRuntimeView::availableParticleBuffers offset must be 0x10"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, trailSegmentPool) == 0x1C,
    "CWorldParticlesRuntimeView::trailSegmentPool offset must be 0x1C"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, particleBuckets) == 0x28,
    "CWorldParticlesRuntimeView::particleBuckets offset must be 0x28"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, refractingParticleBuckets) == 0x34,
    "CWorldParticlesRuntimeView::refractingParticleBuckets offset must be 0x34"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, trailBuckets) == 0x40,
    "CWorldParticlesRuntimeView::trailBuckets offset must be 0x40"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, particleBucketLookupKey) == 0x4C,
    "CWorldParticlesRuntimeView::particleBucketLookupKey offset must be 0x4C"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, cachedParticleBucket) == 0x88,
    "CWorldParticlesRuntimeView::cachedParticleBucket offset must be 0x88"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, trailBucketLookupKey) == 0x8C,
    "CWorldParticlesRuntimeView::trailBucketLookupKey offset must be 0x8C"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, cachedTrailBucket) == 0xC0,
    "CWorldParticlesRuntimeView::cachedTrailBucket offset must be 0xC0"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, beatsSincePause) == 0xC4,
    "CWorldParticlesRuntimeView::beatsSincePause offset must be 0xC4"
  );
  static_assert(
    offsetof(CWorldParticlesRuntimeView, instantiated) == 0xC8,
    "CWorldParticlesRuntimeView::instantiated offset must be 0xC8"
  );
  static_assert(sizeof(CWorldParticlesRuntimeView) == 0xCC, "CWorldParticlesRuntimeView size must be 0xCC");

  class CWorldParticles
  {
  public:
    /**
     * Address: 0x004925E0 (FUN_004925E0)
     * Mangled: ??0CWorldParticles@Moho@@QAE@XZ
     *
     * What it does:
     * Initializes global world-particle pool/map sentinel lanes and key scratch
     * storage.
     */
    CWorldParticles();

    /**
     * Address: 0x00492780 (FUN_00492780)
     * Mangled: ??1CWorldParticles@Moho@@QAE@XZ
     *
     * What it does:
     * Tears down the singleton world-particles state, including beam buckets
     * and pooled render storage.
     */
    virtual ~CWorldParticles();

    /**
     * Address: 0x004928A0 (FUN_004928A0)
     *
     * What it does:
     * Lazily allocates particle and trail pooled buffers used by world-particle
     * render bucket upload paths.
     */
    void Init();

    /**
     * Address: 0x00492D30 (FUN_00492D30)
     * Mangled: ?AddBeam@CWorldParticles@Moho@@UAEXPBUSWorldBeam@2@@Z
     *
     * What it does:
     * Inserts one beam into the persistent beam render-bucket map.
     */
    void AddBeam(const SWorldBeam& beam);

    /**
     * Address: 0x00492D50 (FUN_00492D50)
     * Mangled: ?AddParticles@CWorldParticles@Moho@@UAEXPBUSParticleBuffer@2@@Z
     *
     * What it does:
     * Dispatches one submit-buffer payload into world-particle, trail, and beam
     * append paths in original order.
     */
    void AddParticles(const ParticleSubmitBufferRuntimeView& batch);

    /**
     * Address: 0x00492E30 (FUN_00492E30)
     * Mangled: ?AdvancementBeat@CWorldParticles@Moho@@UAEXXZ
     *
     * What it does:
     * Advances beat counter and clears transient beam bucket contents.
     */
    void AdvancementBeat();

    /**
     * Address: 0x00495080 (FUN_00495080)
     *
     * What it does:
     * Sets particle camera shader variables, optionally renders beams, then
     * renders particle buckets on the correct side of the water-surface gate.
     */
    char RenderEffects(
      GeomCamera3* camera,
      char renderWaterSurface,
      char suppressTLight,
      int tick,
      float frameAlpha
    );

    /**
     * Address: 0x004952A0 (FUN_004952A0)
     *
     * What it does:
     * Renders the refracting particle-bucket lane with the particle background
     * texture bound and camera shader state initialized.
     */
    void RenderRefractingEffects(
      GeomCamera3* camera,
      int tick,
      float frameDelta,
      boost::weak_ptr<gpg::gal::TextureD3D9> backgroundTexture
    );

  protected:
    /**
     * Address: 0x00494930 (FUN_00494930, Moho::CWorldParticles::AddWorldParticle)
     *
     * What it does:
     * Resolves/creates the world-particle bucket for one particle payload and
     * appends that payload into the bucket pending vector.
     */
    void AddWorldParticle(
      const SWorldParticle& particle,
      ParticleRenderBucketRuntime** bucketCacheSlot
    );

    /**
     * Address: 0x00494C20 (FUN_00494C20, Moho::CWorldParticles::AddTrail)
     *
     * What it does:
     * Resolves/creates the trail bucket for one trail payload and appends that
     * payload into the bucket pending vector.
     */
    void AddTrail(
      const TrailRuntimeView& trail,
      TrailRenderBucketRuntime** bucketCacheSlot
    );

  private:
    friend void ResetWorldParticlesRuntimeState(CWorldParticles& worldParticles);

    /**
     * Address: 0x00493090 (FUN_00493090, sub_493090)
     *
     * What it does:
     * Releases beam-bucket map resources and destroys the retained beam vertex
     * sheet lane.
     */
    void ShutdownBeamBuckets();

    std::uint8_t mUnknown04_C3[0xC0]{};     // +0x04
    std::int32_t mBeatsSincePause = 0;      // +0xC4
    bool mInstantiated = false;             // +0xC8
    std::uint8_t mPaddingC9_CB[0x03]{};     // +0xC9
    BeamBucketContainerRuntime mBeams;      // +0xCC
  };

  extern CWorldParticles sWorldParticles;

  /**
   * Address: 0x00492AC0 (FUN_00492AC0)
   *
   * What it does:
   * Destroys the world-particles singleton runtime storage and resets the
   * pooled bucket/list state.
   */
  void DestroyWorldParticlesSingleton();

  /**
   * Address: 0x00492E70 (FUN_00492E70)
   *
   * What it does:
   * Returns the global world-particles singleton after restoring the base
   * interface lane used by legacy exit paths.
   */
  [[nodiscard]] CWorldParticles* GetLegacyWorldParticlesSingleton() noexcept;

  /**
   * Address: 0x00494E10 (FUN_00494E10)
   *
   * What it does:
   * Clears the runtime particle, refracting-particle, and trail bucket lanes
   * owned by one world-particles instance.
   */
  void ResetWorldParticlesRuntimeState(CWorldParticles& worldParticles);

  /**
   * Address: 0x00495440 (FUN_00495440, sub_495440)
   *
   * What it does:
   * Returns the global world-particles singleton used by engine render/update
   * paths.
   */
  [[nodiscard]] CWorldParticles* GetGlobalWorldParticles() noexcept;

  /**
   * What it does:
   * Returns the shared trail-quad index sheet used by trail bucket draw
   * helpers.
   */
  [[nodiscard]] ID3DIndexSheet* GetSharedTrailQuadIndexSheet() noexcept;

  /**
   * What it does:
   * Releases the shared trail-quad index-sheet singleton and clears its global
   * ownership lane.
   */
  void DestroySharedTrailQuadIndexSheet() noexcept;

  /**
   * Address: 0x004986F0 (FUN_004986F0, func_CreateIndexSheet1)
   *
   * What it does:
   * Rebuilds the shared trail-quad index sheet and populates one 4-vertex /
   * 6-index quad pattern for `0x4000` quads.
   */
  int RebuildSharedTrailQuadIndexSheet();

  static_assert(sizeof(CWorldParticles) == 0xDC, "CWorldParticles size must be 0xDC");

} // namespace moho
