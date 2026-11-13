#pragma once

#include <atomic>

namespace gpg::gal
{
  // Dynamic lights (docs/DYNAMIC_LIGHTS.md): the effect patch marks every technique that carries a light pass with the
  // annotation `int dynLightPasses = N;` (its last N passes). While this flag is false - no light on screen, lights off
  // - the effect runtime does not report those passes, so the draw loops of the engine skip them and the lit effects
  // cost what they did without the patch. Written by the light system once per rendered frame
  // (moho::lights::BeginFrame), read by the effect runtimes.
  inline std::atomic<bool> gDynLightPassActive{false};
} // namespace gpg::gal
