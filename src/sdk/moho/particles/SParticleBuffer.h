#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/particles/BeamRenderHelpers.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/SWorldParticle.h"

namespace moho
{
  /**
   * Typed submit buffer owner used by sim/effect particle emission paths.
   *
   * Layout:
   *   +0x00: particle lane
   *   +0x10: trail lane
   *   +0x20: beam lane
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

    msvc8::vector<SWorldParticle> mParticles; // +0x00
    msvc8::vector<TrailRuntimeView> mTrails;  // +0x10
    msvc8::vector<SWorldBeam> mBeams;         // +0x20
  };

  using ParticleSubmitBufferRuntimeView = SParticleBuffer;

  static_assert(offsetof(SParticleBuffer, mParticles) == 0x00, "SParticleBuffer::mParticles offset must be 0x00");
  static_assert(offsetof(SParticleBuffer, mTrails) == 0x10, "SParticleBuffer::mTrails offset must be 0x10");
  static_assert(offsetof(SParticleBuffer, mBeams) == 0x20, "SParticleBuffer::mBeams offset must be 0x20");
  static_assert(sizeof(SParticleBuffer) == 0x30, "SParticleBuffer size must be 0x30");
} // namespace moho
