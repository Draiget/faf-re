#pragma once

#include "gpg/gal/DeviceContext.hpp"

// Engine side of the filtered shadows (docs/SHADOW_FILTERING.md): the quality level, the shadow map size that goes with
// it, the shader parameters of the patched lookup (ShadowEffectPatch) and the render features registry entry
// (`shadow_filter`). Render only: nothing here reads or writes sim state.
namespace moho::shadowfilter
{
  // 0 = Off (the shipped lookup), 1..4 = Low, Medium, High, Ultra. Console variable ren_ShadowFilter; set live by the
  // Options > Video entry.
  extern int ren_ShadowFilter;

  struct LevelParams
  {
    int mapSize; // shadow map edge in texels (the edge of one cascade tile when the shadow map is an atlas, capped by
                 // kAtlasTileLimit)
    int taps;    // filter taps
    float minRadius;   // kernel radius in texels
    float maxRadius;   // largest radius (blocker search radius) when the penumbra estimate is on
    float penumbraTan; // tangent of the light's angular radius for the penumbra estimate; 0 = fixed radius
  };

  // The parameters of a level (1..4); level 0 returns the Low entry.
  const LevelParams& ParamsFor(int level);

  // The largest tile of a shadow atlas (ren_ShadowCascades) a level asks for: the atlas has four of them (2 x 2), so a
  // 4096 tile would be an 8192 x 8192 target twice.
  inline constexpr int kAtlasTileLimit = 2048;

  // Whether the effects can be patched on this API (the Direct3D 10 effect dialect: Direct3D 11, 12 and Vulkan).
  bool Supported(gpg::gal::DeviceApi api);

  // Whether the effect patch is to be applied to mesh.fx and terrain.fx as they are built: the filter is on (render
  // features registry or ren_ShadowFilter) on an API that supports it. Read live; the answer of the last call is what
  // the effects in use were built with.
  bool EffectPatchWanted(gpg::gal::DeviceApi api);

  // The tile helpers (tex2Dtile ...) of the effect layer exist on this API: the patched text reads the cascade atlas in
  // the texels of the tile that holds each lookup (Direct3D 12 and Vulkan; Direct3D 11 has no cascades).
  bool TileAware(gpg::gal::DeviceApi api);

  // CD3DEffect::InitEffectFromFile reports the effects it patched, so that the engine never selects the filtered path
  // for an effect that does not have it. Not for the background compile of a live switch (lights::OnWarmupThread),
  // which builds throw-away effects.
  void NoteEffectPatched(bool terrain, bool patched);

  // The filter was switched on after the effects were built without the patch: mesh.fx and terrain.fx have to be built
  // again (lights::ApplyLiveLevel does it, in one go with the lights' effects). NoteRebuilt() says they were.
  bool LiveRebuildWanted();
  void NoteRebuilt();

  // The filter is on: the level is above Off, both effects carry the patch, and the lookups are not the ray-traced ones
  // (a ray-traced frame keeps the shipped lookups and the shipped map, which the rays complete).
  bool Active();

  // The shadow map edge the shadow renderer should have: the larger of the level's and the user's ren_ShadowSize, or
  // just the user's while the filter is off. `atlas`: the map is a cascade atlas, whose tiles are at most
  // kAtlasTileLimit across unless the user asks for more.
  int WantedMapSize(int userSize, bool atlas);

  // The reach of the kernel in texels of a cascade tile, 0 while the filter is off. A cascade tile keeps lookups this
  // far from its edge, where the tile ends and the next one (or the cleared gutter) begins.
  float FootprintTexels();

  // Called by the shadow renderer when it derives the light camera: the world size of the light volume (width of the
  // map in world units, depth range in world units).
  void SetLightVolume(float width, float depthRange);

  // Writes the shader parameters of the current level (every frame, before the shadow lookups are drawn). `textureSize`
  // is the edge of the shadow texture in use (the terrain effect's ShadowSize; the blur passes that set it otherwise do
  // not run with the filter on). `cameraValid` is whether the frame has a light camera: without one the terrain keeps
  // the shipped lookup (its depth comparison would run against a stale light matrix; the light field forces the
  // terrain's shadow path on for the sun term while the camera is invalid).
  void UpdateShaderVars(int textureSize, bool cameraValid);
} // namespace moho::shadowfilter
