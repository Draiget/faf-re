#pragma once

#include <string>

// Source-level patch of FAF's mesh.fx and terrain.fx that replaces the shadow-map lookup with a filtered one
// (docs/SHADOW_FILTERING.md, "Shader side").
//
// Like the dynamic-light patch (moho/render/lights/LightEffectPatch.h) it is pure text in, text out: the effect files
// are user data, they are never copied into this repository. The two patches touch different places (this one the
// shadow lookup functions, the lights the vertex shaders, PBR helpers and technique list) and are chained by
// CD3DEffect::InitEffectFromFile: this one runs first, the lights patch continues from its output, so neither depends
// on the other's text.
//
// An unexpected source (a FAF update that moved something this patch relies on) leaves the text untouched and says why
// in `error`.
//
// Effect parameters the patched text declares: mesh.fx `shadowFilter`, `shadowFilter2`; terrain.fx `ShadowFilter`,
// `ShadowFilter2` (both float4, set by ShadowFilter.cpp every frame):
//   filter.x   tap count; 0 selects the shipped lookup (the patched shader then behaves as the original one)
//   filter.y   kernel radius in shadow texels (the smallest radius when the penumbra estimate is on); texels of the
//   cascade tile that holds
//              the lookup when the shadow texture is an atlas
//   filter.z   largest radius in texels, also the blocker search radius
//   filter.w   penumbra scale (shadow map uv per unit of depth difference); 0 = fixed radius, no blocker search
//   filter2.x  scale of the constant depth bias (the effect's own for meshes, 0.0003 for the ground), filter2.y scale
//   of the receiver-plane
//              (slope) bias, filter2.z how far (depth units) the terrain in the map is moved from the light as a caster
//
// PatchTerrainEffect also repairs the terrain depth the shipped TerrainDepthPS writes (1/128 of the depth, see
// docs/SHADOW_FILTERING.md), so the ground is a caster like a mesh: hills shade the ground.
namespace moho::shadowfilter
{
  struct PatchResult
  {
    bool patched = false;
    int lookups = 0; // lookup sites that now go through the filter
    std::string error;
  };

  // `tileAware`: the lookup reads the shadow texture through the effect layer's tile helpers (tex2Dtile, tex2Dtilesize,
  // tex2Dtileload of gpg/gal/effects/ModernHlsl.cpp: Direct3D 12 and Vulkan), so that on a cascade atlas its taps are
  // in the texels of the tile that holds the lookup. Otherwise (Direct3D 11) the texture is the whole-view map.
  PatchResult PatchMeshEffect(std::string& source, bool tileAware);
  PatchResult PatchTerrainEffect(std::string& source, bool tileAware);

  // True for the base names of the effects this patch handles ("mesh", "terrain").
  bool HandlesEffect(const std::string& baseName);
} // namespace moho::shadowfilter
