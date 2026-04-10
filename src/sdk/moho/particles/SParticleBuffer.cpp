#include "moho/particles/SParticleBuffer.h"

namespace moho
{
  /**
   * Address: 0x00746890 (FUN_00746890, ??0SParticleBuffer@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes the three submit lanes to empty legacy-vector state.
   */
  SParticleBuffer::SParticleBuffer()
    : mParticles()
    , mTrails()
    , mBeams()
  {
  }
} // namespace moho
