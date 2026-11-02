#pragma once

// Engine addition: the translated effect source of the D3D12 and Vulkan backends, kept between
// runs and built in parallel.
//
// Both backends build every game effect the same way when the device starts: D3DPreprocess with
// their macros, then d3d11::TranslateEffectSource, which rewrites the D3D9 effect into the HLSL
// they compile. The translation took ~0.9 s of the main thread at every launch (mesh.fx alone
// 400 ms), one effect after another. It depends only on its inputs and on the translator, so:
//   - its result is kept in the shader cache, under a key of the inputs and of this executable
//     (a rebuild, which may change the translator, starts over), and read back in later runs;
//   - PrepareEffectSources builds a whole set of effects on worker threads ahead of their
//     creation, so the backend's CreateEffect finds each translation waiting.

#include <vector>

#include "gpg/gal/backends/d3d11/EffectSourceD3D11.h"

namespace gpg::gal
{
  class EffectContext;
}

namespace gpg::gal::effects
{
  /**
   * `ren_EffectSourceCache` (registered in moho/render/GpuPathSettings.cpp): false translates every
   * effect when it is created, one after another, as the original does. `/noeffectcache` turns it
   * off at startup, before the device creates its effects.
   */
  extern bool gEffectSourceCache;

  /**
   * The effect's source preprocessed with its macros, then translated as by
   * d3d11::TranslateEffectSource(source, true, {}): from a translation PrepareEffectSources left
   * waiting, else the cache, else the translator, whose result is then cached. A preprocessor
   * error is thrown as `errorFile`'s.
   */
  [[nodiscard]] d3d11::TranslatedEffectSource TranslateEffect(const EffectContext& context, const char* errorFile);

  /** A backend's CreateEffect source step (its macros, then TranslateEffect), which it sets. */
  using EffectSourceBuilder = d3d11::TranslatedEffectSource (*)(const EffectContext& context);
  void SetEffectSourceBuilder(EffectSourceBuilder builder) noexcept;

  /**
   * Runs the builder on every context on worker threads and returns when all are done, leaving
   * their translations waiting for CreateEffect. Without a builder it does nothing; a context that
   * fails is left for CreateEffect to report.
   */
  void PrepareEffectSources(const std::vector<EffectContext>& contexts);
} // namespace gpg::gal::effects
