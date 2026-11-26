#pragma once

#include <string>

// Source-level patch of FAF's particle.fx for the low-resolution large-particle path and the soft particles
// (docs/RENDERER_BACKENDS.md, "Large particles in a lower-resolution target" and "Soft particles"; the runtime is
// ParticleLowRes.cpp).
//
// The game's effect files are user data and are never copied into this repository: the patch runs on the text that is
// about to be compiled (CD3DEffect::InitEffectFromFile), on the backends that compile the Direct3D 10 effect dialect
// (Direct3D 11, 12 and Vulkan) only. Pure text in, text out; an unexpected source leaves the text untouched and says
// why in `error`, so the effect still compiles, without the path.
//
// What the patched effect has on top of the original:
//   - LRParams: x is 0 to draw every particle, 1 only the quads below the size threshold, 2 only the quads at or above
//     it; y is the threshold in pixels^2 at full resolution; zw is half the viewport size. WorldVS and WorldVSAlign
//     collapse the other quads to nothing when x is not 0, so one instanced draw of a bucket can be issued twice, once
//     per resolution, from the same data.
//   - for every WorldVS/WorldVSAlign technique with the ADD, ALPHABLEND or PREMODALPHA blend, a `<name>_LR` twin that
//     accumulates into the low-resolution target and is depth tested by the hardware against the downsampled scene
//     depth (the target's own depth buffer). The accumulation holds S (rgb) and coverage A (alpha). An "over" layer
//     (ALPHABLEND, PREMODALPHA) does S = c*a + S*(1-a), A = a + A*(1-a) (premultiplied "over"; the backends blend alpha
//     with the colour factors), an ADD layer does S += c*a and leaves A alone (colour-only writes). Any order of the
//     two kinds composes exactly: scene' = S + scene*(1-A).
//   - LRDownsample2 / LRDownsample4: the farthest scene depth of the footprint of each low-resolution pixel, written as
//     depth.
//   - LRComposite: the depth-aware upsample of S and A onto the scene (the nearest low-resolution pixel in depth at
//     depth edges).
//
// Soft particles (feature `soft_particles`) are in the same patch:
//   - SoftParams.x is the soft-edge distance in world units (0 = off, then every pixel shader below is the plain one).
//   - the ADD, ALPHABLEND and PREMODALPHA techniques (and their `_LR` twins) use WorldPSSoft / WorldPSSoftPremod
//     (WorldPSSoftLR* for the twins). They scale the particle's alpha (the whole colour for PREMODALPHA, whose alpha is
//     in the colour) by a smoothstep of (scene view depth - fragment view depth) / SoftParams.x. The scene depth is
//     LRSceneDepthTexture, the copy taken before the particle pass that the low-resolution passes sample too; the twins
//     look it up at the full-resolution pixel their low-resolution pixel sits on.
namespace moho
{
  struct ParticleEffectPatchResult
  {
    bool patched = false;
    int techniques = 0; // low-resolution twins added
    int softened = 0;   // techniques whose pixel shader fades by the scene depth (soft particles)
    std::string error;  // why nothing was patched, when `patched` is false
  };

  ParticleEffectPatchResult PatchParticleEffect(std::string& source);

  // True when the environment variable FAF_NO_RENDER_ADDITIONS is 1: the same kill switch as RenderAdditionsDisabled()
  // in WRenViewport.cpp (which is private to that file). The effect is then left alone and the particle passes stay
  // off.
  [[nodiscard]] bool ParticleAdditionsDisabled() noexcept;

  // Whether the effect that is loaded now has the patch (set by CD3DEffect::InitEffectFromFile, read by
  // ParticleLowRes).
  void SetParticleEffectPatched(bool patched) noexcept;
  [[nodiscard]] bool ParticleEffectPatched() noexcept;
} // namespace moho
