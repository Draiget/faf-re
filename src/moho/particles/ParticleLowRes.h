#pragma once

#include <cstddef>
#include <cstdint>

// Large particles in a lower-resolution target (docs/RENDERER_BACKENDS.md, "Large particles in a lower-resolution
// target").
//
// The explosions of the game are a few hundred quads of 100,000 pixels and more, drawn over each other with blending:
// 100 and more screens of overdraw, which costs blend/ROP bandwidth and nothing else. This path draws the quads at or
// above a size threshold into a half (or quarter) resolution target and composites it onto the scene; everything
// smaller stays at full resolution.
//
// How (all of it behind the effect patch of ParticleEffectPatch.h, so Direct3D 11, 12 and Vulkan and nothing else):
//   - the scene depth is copied (the scene's own depth stays a depth output) and downsampled once per RenderEffects
//     call (the farthest depth of each low-resolution pixel's footprint, into the depth buffer of the low-resolution
//     target);
//   - for a run of buckets (same sort scalar; the bucket order of the game is ALPHABLEND, PREMODALPHA, ADD in any mix)
//     the large quads are drawn into a cleared accumulation target with the `_LR` techniques (depth tested by the
//     hardware), the target is composited onto the scene with a depth-aware upsample, then the small quads of the same
//     buckets are drawn at full resolution;
//   - only buckets that could hold a large quad from this camera take part (an estimate kept per pooled particle
//     buffer); the others, and runs without such a bucket, draw once at full resolution exactly as before;
//   - one instanced draw per bucket is issued twice from the same data; the vertex shader collapses the quads of the
//     other size class (the size is a function of the instance data and the camera only, so both draws agree on which
//     quad is which).
// The soft particles (docs/RENDERER_BACKENDS.md, "Soft particles") share this file's runtime because they need the
// same thing: a sampled copy of the scene depth, taken once per RenderEffects call before the particle pass, and the
// patched particle effect. They work with the low-resolution path off or on (the low-resolution passes read the same
// copy at full resolution).
// ADD and the "over" blends (ALPHABLEND, PREMODALPHA) accumulate together in their drawing order (see
// ParticleEffectPatch.h), which is exact up to the 8 bit clamping of the scene. MODULATE*, REFRACT and TLight buckets
// are not touched; they end a run.
namespace moho
{
  struct GeomCamera3;
  struct LargeQuadGate;
  struct LargeQuadStats;
  struct SParticleRenderBucket;

  /** 0 off, 1 half resolution, 2 quarter resolution (console variable `ren_ParticleLowRes`; FAF_PARTICLE_LOWRES
   * overrides it). */
  extern int ren_ParticleLowRes;
  /** Side in pixels (full resolution) of a square quad that counts as large (`ren_ParticleLowResSize`;
   * FAF_PARTICLE_LOWRES_SIZE). */
  extern float ren_ParticleLowResSize;
  /** Millions of pixels (full resolution, overdraw included) of large quads a run needs before it takes the
   * low-resolution path (`ren_ParticleLowResMinMpix`; FAF_PARTICLE_LOWRES_MINMPIX). */
  extern float ren_ParticleLowResMinMpix;
  /** How many times the large quads of a bucket must cover the screen rectangle they lie in, on average, before the
   * bucket takes the low-resolution path (`ren_ParticleLowResMinOverdraw`; FAF_PARTICLE_LOWRES_MINOVERDRAW). */
  extern float ren_ParticleLowResMinOverdraw;
  /** Millions of pixels the viewport needs before the path runs at all (`ren_ParticleLowResMinViewport`;
   * FAF_PARTICLE_LOWRES_MINVIEWPORT). */
  extern float ren_ParticleLowResMinViewport;

  /** Soft particles level (console variable `ren_SoftParticles`; FAF_SOFT_PARTICLES overrides it): 0 off, 1 low, 2
   * high. */
  extern int ren_SoftParticles;
  /** Multiplies the soft-edge distance of the level (`ren_SoftParticleScale`; FAF_SOFT_PARTICLE_SCALE). */
  extern float ren_SoftParticleScale;

  /** Whether the active backend can run the path at all (Direct3D 11, 12 or Vulkan, effect patched). The settings
   * registry asks this. */
  [[nodiscard]] bool ParticleLowResSupported();

  /** Whether the soft particles can run (same condition: the patched particle effect on a backend that copies the
   * depth). */
  [[nodiscard]] bool SoftParticlesSupported();

  /** Whether a bucket may take part (a world-particle technique with the ADD, ALPHABLEND or PREMODALPHA blend). */
  [[nodiscard]] bool ParticleLowResEligible(const SParticleRenderBucket& bucket) noexcept;

  namespace particlelowres
  {
    /**
     * Whether particle.fx should be built with the patch (ParticleEffectPatch.h): soft particles are on, or the
     * low-resolution path is on and a viewport that can ever take it exists (ren_ParticleLowResMinViewport million
     * pixels; the back buffer's size until the first particle pass has measured the viewport it really draws into, then
     * the viewports of the last 600 passes). False with every particle option off, or on a small viewport with the soft
     * particles off: the effect is then upstream's text, and costs what it costs. The effect loader asks, and the
     * answer is what the effect in use was built with (ApplyLive compares it to the answer of the day).
     */
    [[nodiscard]] bool PatchWanted();

    /**
     * Each frame, before anything is drawn: when what the effect should be (PatchWanted) differs from what it was built
     * as (a soft-particle or large-particle option switched on or off, a window resized to or from a viewport the
     * low-resolution path can use), builds it again. True when the effect was replaced.
     */
    bool ApplyLive();

    /**
     * Starts one RenderEffects call (the output target and viewport are the scene's). False: neither the low-resolution
     * path nor the soft particles are on or usable right now, and nothing in the other calls may be used. True: call
     * End when the buckets are drawn; the low-resolution calls (Gate, WorthIt, BeginAccumulate, ...) need LowResActive
     * too.
     */
    [[nodiscard]] bool Begin(const GeomCamera3& camera);

    /**
     * Whether the per-particle estimate of the large quads (ParticleBucketLargeStats) is made: the low-resolution path
     * ran within the last 600 calls of Begin. While it is not, an uploaded particle is not copied for it.
     */
    [[nodiscard]] bool EstimateWanted() noexcept;

    /** Whether the low-resolution path runs in this call (after a successful Begin). */
    [[nodiscard]] bool LowResActive();

    /**
     * Soft particles: copies the scene depth once per call (shared with the low-resolution path) and binds it to the
     * particle effect. Call it before drawing the first bucket that is eligible for it (ParticleLowResEligible); cheap
     * afterwards. A copy that fails turns them off.
     */
    void EnsureSoftDepth();

    /** The camera as the large-quad estimate sees it (valid after a successful Begin). */
    [[nodiscard]] const LargeQuadGate& Gate();

    /**
     * Whether one bucket whose large quads are estimated as `stats` is worth the cost of its passes: it must hold
     * `ren_ParticleLowResMinMpix` million pixels of large quads (the fill saved has to exceed the fixed cost of the
     * passes) and cover its rectangle `ren_ParticleLowResMinOverdraw` times over (the composite costs by the area of
     * the rectangle, the fill saved by the overdraw: a wide thin cover at a high resolution loses).
     */
    [[nodiscard]] bool WorthIt(const LargeQuadStats& stats);

    /** Opens the accumulation of one bucket whose large quads are estimated as `stats`: switches to the accumulation
     * target. False (nothing changed): the scene depth could not be copied, draw the bucket as ever. */
    [[nodiscard]] bool BeginAccumulate(const LargeQuadStats& stats);

    /** Composites the accumulation onto the scene, over the rectangle of the large quads that BeginAccumulate was
     * given, and restores the scene target. The next draws take every quad (SelectQuads(false)). */
    void Composite();

    /** Which quads the next full-resolution draws take: only the small ones (a bucket that was in the accumulation
     * pass) or all. */
    void SelectQuads(bool onlySmall);

    /** FAF_PARTICLE_LOWRES_DEBUG: describes one run now and then (its sort scalar, class, buckets and the buckets that
     * may have large quads). */
    void NoteRun(float sortScalar, std::size_t buckets, const LargeQuadStats& stats);

    /** Closes the bucket: every quad is drawn again (LRParams mode 0). */
    void EndRun();

    /** Ends the RenderEffects call. */
    void End();
  } // namespace particlelowres
} // namespace moho
