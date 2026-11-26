#pragma once

#include <string>

// Source-level patch of FAF's water2.fx that filters the two lookups the water pixel shader makes with a screen
// position the wave normal has moved (docs/WATER_SIMULATION.md, "Shader side"): the refraction map (the scene before
// the water) and the reflection map (the mirrored units).
//
// The shipped pixel shader reads both with one bilinear tap at `screenPos - N.xz * depth * refractionScale`. The normal
// map has a repeat rate of 0.5 per world unit in its finest layer, so neighbouring screen pixels land several texels
// apart and the lookup aliases: reflected units and the sea floor shimmer and crawl, and the edge of a reflected hull
// is a staircase. The patch replaces the two lookups with a filter whose footprint is the screen-space derivative of
// the lookup position (what a mip level / anisotropic filter would do for a texture that cannot have mips), taken with
// 4 or 8 taps weighted by the reflection's alpha so a reflected edge fades into the sky instead of into black.
//
// Pure text in, text out; no engine headers. The effect parameter `faf_WaterFilter` (float3: reflection taps,
// refraction taps, shoreline blend; all 0 = the shipped lookups) is declared by the patch and set by WaterQuality every
// frame. A source the patch does not recognise (a FAF update that changed the shader) is left untouched and `error`
// says why, so the effect still compiles, unfiltered.
namespace moho::water
{
  struct EffectPatchResult
  {
    bool patched = false;
    std::string error; // why nothing was patched, when `patched` is false
  };

  EffectPatchResult PatchWaterEffect(std::string& source);
} // namespace moho::water
