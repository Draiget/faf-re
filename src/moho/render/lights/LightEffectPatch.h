#pragma once

#include <string>

// Source-level patch of FAF's mesh.fx and terrain.fx that adds the dynamic lights (docs/DYNAMIC_LIGHTS.md, "Shader
// side").
//
// The game's effect files are user data and are never copied into this repository: the patch runs on the text that is
// about to be compiled (CD3DEffect::InitEffectFromFile), on the Direct3D 11/12/Vulkan backends only (Direct3D 9 keeps
// the FA-Binary-Patches version). It is a port of the FA-DynamicLights generator (make_lab_shaders.py) with one change
// of design: the lights are not constant arrays walked in three or four extra passes, but the light data and light grid
// textures of LightGrid.h, read in ONE extra pass (meshes) / one extra pass plus the decal and splat lighting
// (terrain). Nothing else of the effect changes except what the light pass needs: the vertex shaders that feed the lit
// mesh techniques also store the view distance in an unused interpolator.
//
// Pure text in, text out; no engine headers. An unexpected source (a FAF update that moved something this patch relies
// on) leaves the text untouched and says why in `error`, so the effect still compiles, without lights.
//
// Effect parameters the patched text declares (see LightBinding.h): dynLightData, dynLightGrid, dynLightParams,
// dynLightGridSize, dynLightDataSize, and in the mesh effect dynLightCamera (world position of the camera; the pixel
// shaders rebuild the world position from the view distance). Technique annotation `int dynLightPasses = 1;` marks a
// technique whose LAST pass is the light pass: the effect runtime drops it from the pass count while no light is
// active.
namespace moho::lights
{
  struct EffectPatchResult
  {
    bool patched = false;
    int techniques = 0;     // techniques that got the light pass
    bool sunShadow = false; // the sun shadow term of the effect also takes the terrain's shadow from the light field
    int sunShadowSites = 0; // how many shadow reads were wrapped
    std::string error;      // why nothing was patched, when `patched` is false
  };

  // `flood` is a diagnostic (/dynlightsflood = 1): the light passes paint every pixel magenta; 2 (/dynlightsflood2)
  // paints what the terrain pass finds: red = the light parameters arrived, green = the grid cell has a light, blue =
  // the light data texture holds a light. Otherwise it only paints magenta instead of reading the lights, which shows
  // whether the passes run at all, apart from whether the light data is right.
  EffectPatchResult PatchMeshEffect(std::string& source, int flood = 0);
  // `sunReads` = false leaves the PBR shaders' shadow reads alone (each such read samples the light field: on a shader
  // model with 16 samplers a technique that already uses 15 cannot take it); the effect builder asks for it when the
  // first compile fails.
  EffectPatchResult PatchTerrainEffect(std::string& source, int flood = 0, bool sunReads = true);

  // water2.fx: the light field as light of the water surface (glints, scatter); declares the field variables
  // (docs/LIGHTING_V2.md).
  EffectPatchResult PatchWaterEffect(std::string& source);

  // Which patch an effect file wants, from its base name ("mesh", "terrain"); nullptr-like false for the others.
  enum class PatchedEffect
  {
    None,
    Mesh,
    Terrain
  };
  PatchedEffect EffectForName(const std::string& baseName);
} // namespace moho::lights
