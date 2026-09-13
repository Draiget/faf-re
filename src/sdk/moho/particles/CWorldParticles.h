#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Map.h"
#include "boost/weak_ptr.h"
#include "moho/particles/ParticleRenderBuckets.h"
#include "moho/particles/SParticleBuffer.h"
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
  class ID3DRenderTarget;
  struct GeomCamera3;
  class ID3DIndexSheet;


  /**
   * What it does:
   * Stores beam render-bucket state on `CWorldParticles` at the recovered
   * `+0xCC` lane.
   * Address: 0x004914B0 (FUN_004914B0 -- the aggregate's implicit default constructor: null the vertex sheet, then `rb_tree()` buys the header sentinel and self-links it for `msvc8::map<BeamTextureBucketKeyRuntime, msvc8::vector<SWorldBeam>>` (`CWorldParticles::mBeams.mBuckets`; pair 0x24, node 0x34, colour@+0x30, isNil@+0x31); callers 0x004925E0, 0x004928A0, 0x00493090; formerly `InitializeBeamBucketMapStorage` in moho/particles/BeamRenderHelpers.cpp (RULE ONE), removed 2026-09-10.)
   */
  struct BeamBucketContainerRuntime
  {
    CD3DVertexSheet* mVertexSheet = nullptr; // +0x00
    BeamTextureBucketMapRuntime mBuckets;     // +0x04

    /**
     * Address: 0x00493090 (FUN_00493090, sub_493090)
     *
     * What it does:
     * Drains the bucket map (`erase_range(leftmost(), header())` through
     * 0x00499E50), frees its header and nulls `head_`/`size_`, then releases
     * the retained vertex sheet through its virtual deleting destructor
     * (`call [[ecx]]` with the delete flag at 0x004930F8).
     *
     * Its only two xrefs are `~CWorldParticles` (0x004927C3) and that
     * function's unwind funclet (0x00BAAA77), so the container is torn down
     * exactly once per owner. It used to live as
     * `CWorldParticles::ShutdownBeamBuckets`, called explicitly from the
     * destructor body -- and since `mBeams` is an ordinary member, the
     * compiler emitted this teardown again afterwards. The second pass found
     * `head_` already null and faulted in `leftmost()` on every process exit.
     *
     * The binary releases the map before the sheet, which is reverse
     * declaration order and therefore emitted rather than written; a body
     * runs before its members, so the order here is the other way round.
     * Neither object reaches the other, so nothing observes the difference.
     */
    ~BeamBucketContainerRuntime()
    {
      delete mVertexSheet;
    }
  };

  static_assert(
    offsetof(BeamBucketContainerRuntime, mVertexSheet) == 0x00,
    "BeamBucketContainerRuntime::mVertexSheet offset must be 0x00"
  );
  static_assert(sizeof(BeamBucketContainerRuntime) == 0x10, "BeamBucketContainerRuntime size must be 0x10");

  /**
   * Ordering of the render buckets: ascending `sortScalar`, then the state
   * byte, blend and z modes, the two texture handles and the tag. The binary's
   * comparator is spelled as `rhs < lhs` (0x00492290), so the map's `Less` is
   * that call with its arguments swapped.
   */
  struct ParticleBucketKeyLess
  {
    [[nodiscard]] bool operator()(const ParticleBucketKeyRuntime& lhs, const ParticleBucketKeyRuntime& rhs) const noexcept
    {
      return IsParticleBucketKeyRhsLessThanLhs(rhs, lhs);
    }
  };

  /** The render-bucket map: 0x0C of `{proxy, head, size}`, nodes at 0x50. */
  using ParticleBucketMap = msvc8::map<ParticleBucketKeyRuntime, ParticleRenderBucketRuntime*, ParticleBucketKeyLess>;

  static_assert(sizeof(ParticleBucketMap) == 0x0C, "ParticleBucketMap size must be 0x0C");

  /**
   * What it does:
   * Legacy tree-map header lane (`proxy + head + size`) used by world-trail
   * bucket maps.
   */
  /** Same ordering for the trail buckets (comparator 0x00492520). */
  struct TrailBucketKeyLess
  {
    [[nodiscard]] bool operator()(const TrailBucketKeyRuntime& lhs, const TrailBucketKeyRuntime& rhs) const noexcept
    {
      return IsTrailBucketKeyRhsLessThanLhs(rhs, lhs);
    }
  };

  using TrailBucketMap = msvc8::map<TrailBucketKeyRuntime, TrailRenderBucketRuntime*, TrailBucketKeyLess>;

  static_assert(sizeof(TrailBucketMap) == 0x0C, "TrailBucketMap size must be 0x0C");

  /**
   * What it does:
   * Typed constructor/init runtime view for `CWorldParticles` lanes through
   * offset `+0xC8`.
   */
  struct CWorldParticlesRuntimeView
  {
    void* vtable = nullptr;                                 // +0x00
    msvc8::list<ParticleBuffer*> allParticleBuffers;       // +0x04
    msvc8::list<ParticleBuffer*> availableParticleBuffers; // +0x10
    TrailSegmentPoolRuntime trailSegmentPool;               // +0x1C
    ParticleBucketMap particleBuckets;                      // +0x28
    ParticleBucketMap refractingParticleBuckets;            // +0x34
    TrailBucketMap trailBuckets;                            // +0x40
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
     *
     * Not virtual: the `Q` in the mangled name is public non-virtual, and slot
     * 0 of `??_7CWorldParticles@Moho@@6B@` holds 0x00494E10
     * (`ClearRenderBuckets`, 216 instructions), not a deleting destructor.
     * Declaring it virtual put a phantom slot in front of the eight real ones
     * and shifted every one of them down a place. Nothing deletes this class
     * polymorphically -- the only instance is the `sWorldParticles` singleton
     * at 0x010A81B0.
     */
    ~CWorldParticles();

    /**
     * Address: 0x004928A0 (FUN_004928A0)
     *
     * What it does:
     * Lazily allocates particle and trail pooled buffers used by world-particle
     * render bucket upload paths.
     */
    void Init();

    /**
     * Pops the next free particle buffer from `mAvailableParticleBuffers`, or
     * returns `nullptr` when the pool is empty. The binary inlines this
     * `front()` / `pop_front()` pair into `EnsureAndFillParticleBucketWorkItems`
     * (0x00493940).
     */
    [[nodiscard]] ParticleBuffer* AcquireParticleBuffer();

    /**
     * Address: 0x00492CA0 (FUN_00492CA0, sub_492CA0)
     *
     * What it does:
     * Returns one particle buffer to the available pool
     * (`mAvailableParticleBuffers.push_back`).
     */
    void ReleaseParticleBuffer(ParticleBuffer* particleBuffer);

    /**
     * Address: 0x00492CE0 (FUN_00492CE0, sub_492CE0)
     *
     * What it does:
     * Takes the lowest-addressed pooled trail-segment buffer out of
     * `mTrailSegmentPool`; `nullptr` when the pool is empty.
     */
    [[nodiscard]] TrailSegmentBufferRuntime* AcquireTrailSegmentBuffer();

    /**
     * Address: 0x00492D10 (FUN_00492D10, sub_492D10)
     *
     * What it does:
     * Returns one trail-segment buffer to `mTrailSegmentPool`.
     */
    void ReleaseTrailSegmentBuffer(TrailSegmentBufferRuntime* segmentBuffer);

  public:
    // ---- the eight virtuals, in vtable order -------------------------------
    //
    // `??_7CWorldParticles@Moho@@6B@` lives at 0x00E06908 and the singleton
    // constructor (0x004925FF) stores it into `sWorldParticles` at offset
    // +0x00, the only vtable store anywhere in the class, so this is the whole
    // table and the class is singly derived. Read out of the shipped image the
    // eight words are 0x00494E10, 0x00492D30, 0x00494930, 0x00494C20,
    // 0x00492D50, 0x00495080, 0x004952A0, 0x00492E30 -- which is the order
    // below. The pure-virtual base they implement is `IWorldParticles`, whose
    // own table at 0x00E068CC is eight consecutive `_purecall` slots.
    //
    // None of them may be reordered or made non-virtual: every one has zero
    // code xrefs, so the vtable is the only way any of them is ever reached.

    /**
     * Address: 0x00494E10 (FUN_00494E10)
     * Slot: 0
     *
     * What it does:
     * Clears the runtime particle, refracting-particle and trail bucket lanes
     * this instance owns, deleting each bucket payload before its node and
     * dropping the two cached bucket pointers and lookup keys.
     */
    virtual void ClearRenderBuckets();

    /**
     * Address: 0x00492D30 (FUN_00492D30)
     * Mangled: ?AddBeam@CWorldParticles@Moho@@UAEXPBUSWorldBeam@2@@Z
     * Slot: 1
     *
     * What it does:
     * Inserts one beam into the persistent beam render-bucket map.
     */
    virtual void AddBeam(const SWorldBeam& beam);

    /**
     * Address: 0x00494930 (FUN_00494930, Moho::CWorldParticles::AddWorldParticle)
     * Slot: 2
     *
     * What it does:
     * Resolves/creates the world-particle bucket for one particle payload and
     * appends that payload into the bucket pending vector. Also called
     * directly by particle emitters (`WaveGenerator::Update`, asm direct call
     * at 0x0088873E), so it is a public entry as well as a slot.
     */
    virtual void AddWorldParticle(
      const SWorldParticle& particle,
      ParticleRenderBucketRuntime** bucketCacheSlot
    );

    /**
     * Address: 0x00494C20 (FUN_00494C20, Moho::CWorldParticles::AddTrail)
     * Slot: 3
     *
     * What it does:
     * Resolves/creates the trail bucket for one trail payload and appends that
     * payload into the bucket pending vector.
     */
    virtual void AddTrail(
      const TrailRuntimeView& trail,
      TrailRenderBucketRuntime** bucketCacheSlot
    );

    /**
     * Address: 0x00492D50 (FUN_00492D50)
     * Mangled: ?AddParticles@CWorldParticles@Moho@@UAEXPBUSParticleBuffer@2@@Z
     * Slot: 4
     *
     * What it does:
     * Dispatches one submit-buffer payload into world-particle, trail, and beam
     * append paths in original order.
     */
    virtual void AddParticles(const SParticleBuffer& batch);

    /**
     * Address: 0x00495080 (FUN_00495080)
     * Slot: 5
     *
     * What it does:
     * Sets particle camera shader variables, optionally renders beams, then
     * renders particle buckets on the correct side of the water-surface gate.
     */
    virtual char RenderEffects(
      GeomCamera3* camera,
      char renderWaterSurface,
      char suppressTLight,
      int tick,
      float frameAlpha
    );

    /**
     * Address: 0x004952A0 (FUN_004952A0)
     * Slot: 6
     *
     * What it does:
     * Renders the refracting particle-bucket lane with the particle background
     * texture bound and camera shader state initialized.
     */
    virtual void RenderRefractingEffects(
      GeomCamera3* camera,
      int tick,
      float frameDelta,
      const boost::shared_ptr<ID3DRenderTarget>& backgroundTexture
    );

    /**
     * Address: 0x00492E30 (FUN_00492E30)
     * Mangled: ?AdvancementBeat@CWorldParticles@Moho@@UAEXXZ
     * Slot: 7
     *
     * What it does:
     * Advances beat counter and clears transient beam bucket contents.
     */
    virtual void AdvancementBeat();

  private:
    friend void DestroyWorldParticlesSingleton();

    /**
     * Every pooled particle buffer (IDA: `mParticleBuffers`) and the subset not
     * bound to a render work item. Both list heads are bought by the member
     * constructors (`_Buy_head`, 0x00497D00) before the constructor body runs;
     * `~CWorldParticles` tears them down through `_Tidy` (0x00495F30).
     */
    msvc8::list<ParticleBuffer*> mParticleBuffers;            // +0x04
    msvc8::list<ParticleBuffer*> mAvailableParticleBuffers;   // +0x10
    /** Pooled trail-segment vertex buffers (head bought through 0x0049C620). */
    msvc8::set<TrailSegmentBufferRuntime*> mTrailSegmentPool; // +0x1C
    std::uint8_t mUnknown28_C3[0x9C]{};     // +0x28  bucket maps + lookup keys, see CWorldParticlesRuntimeView
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
