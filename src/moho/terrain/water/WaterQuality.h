#pragma once

#include <cstdint>

#include <memory>
#include "gpg/gal/DeviceContext.hpp"

namespace moho
{
  class CD3DRenderTarget;
  class CD3DDepthStencil;
} // namespace moho

// FAF addition: water reflection and refraction quality (docs/WATER_SIMULATION.md). The console variable
// ren_WaterQuality (0..3) picks three things per level:
//   - the size of the reflection render target relative to the screen (the shipped game draws the mirrored units into a
//   screen-sized target);
//   - the number of taps of the footprint filter the water pixel shader takes from the reflection map, and from the
//   refraction map
//     (WaterEffectPatch: the shader source is patched when water2.fx is read);
//   - nothing else: the water, the sim and the game data are untouched.
namespace moho::water
{
  // 0 = the shipped renderer, 1 = Low, 2 = Medium, 3 = High; -1 = not set (the default of the graphics API decides).
  extern int ren_WaterQuality;

  struct QualityParams
  {
    float reflectionScale; // reflection target size / screen size
    float reflectionTaps;  // 0 (one bilinear tap, as shipped), 4 or 8
    float refractionTaps;  // 0 or 4
    float shorelineBlend;  // 0 or 1: water pixels next to land take the land's colour by their land neighbours (soft
                           // shoreline)
  };

  // The parameters of a level (clamped to 0..3). Pure.
  [[nodiscard]] QualityParams ParamsForLevel(int level) noexcept;

  // The level in force: the console variable, else the chosen option / the API's default; 0 when the API does not
  // support the feature.
  [[nodiscard]] int CurrentLevel();

  // Whether the effect source is to be patched on this API (the feature is supported there and the API compiles the
  // D3D10 effect dialect).
  [[nodiscard]] bool EffectPatchWanted(gpg::gal::DeviceApi api);

  // Writes the filter tap counts into the water effect (water2.faf_WaterFilter); a no-op when the effect was not
  // patched.
  void BindShaderParams();

  // The reflection target of a head. `color`/`depth` are null (use the shipped screen-sized target) when the level
  // keeps the screen size. `scale` is the factor to apply to the viewport rectangle. Created on demand, recreated when
  // the size changes.
  struct ReflectionTarget
  {
    std::shared_ptr<CD3DRenderTarget> color;
    std::shared_ptr<CD3DDepthStencil> depth;
    float scale = 1.0f;
    int width = 0; // size of the target in pixels
    int height = 0;
  };
  [[nodiscard]] ReflectionTarget AcquireReflectionTarget(int head, int headWidth, int headHeight);

  // Drops the reflection targets (device lost / reset / exit).
  void ReleaseReflectionTargets();
} // namespace moho::water
