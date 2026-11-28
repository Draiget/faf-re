#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/particles/BeamRenderHelpers.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/SWorldLight.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/particles/SWorldTrail.h"

namespace moho
{
  /**
   * Typed submit buffer owner used by sim/effect particle emission paths.
   *
   * Layout:
   *   +0x00: particle lane
   *   +0x10: trail lane
   *   +0x20: beam lane
   *   +0x30: dynamic light lane (FAF addition, not in the shipped binary)
   */
  struct SParticleBuffer
  {
    /**
     * Address: 0x00746890 (FUN_00746890, ??0SParticleBuffer@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes the three submit lanes to empty legacy-vector state.
     */
    SParticleBuffer();

    fa::vector<SWorldParticle> mParticles; // +0x00
    fa::vector<SWorldTrail> mTrails;       // +0x10
    fa::vector<SWorldBeam> mBeams;         // +0x20
    fa::vector<SWorldLight> mLights;       // +0x30, FAF addition: Lua lights of this tick (visual only)
  };

  static_assert(offsetof(SParticleBuffer, mParticles) == 0x00, "SParticleBuffer::mParticles offset must be 0x00");
  static_assert(offsetof(SParticleBuffer, mTrails) == 0x10, "SParticleBuffer::mTrails offset must be 0x10");
  static_assert(offsetof(SParticleBuffer, mBeams) == 0x20, "SParticleBuffer::mBeams offset must be 0x20");
  static_assert(offsetof(SParticleBuffer, mLights) == 0x30, "SParticleBuffer::mLights offset must be 0x30");
  static_assert(
    sizeof(SParticleBuffer) == 0x40,
    "SParticleBuffer size must be 0x40 (0x30 in the shipped binary plus the light lane)"
  );
} // namespace moho
