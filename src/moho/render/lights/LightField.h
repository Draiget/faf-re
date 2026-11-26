#pragma once

#include <cstdint>

#include <memory>
#include "moho/render/lights/LightGrid.h"
#include "moho/render/lights/LightWaterLevels.h"

namespace gpg::gal
{
  class RenderTarget;
}

namespace moho
{
  struct GeomCamera3;
}

// Lighting V2, stage 2 (docs/LIGHTING_V2.md): a world-fixed irradiance field of the visible ground. A compute shader
// evaluates every light of the frame for each cell of the field (cells of 0.5 to 16 world units, a few layers of height
// above the terrain); the result goes into an RGBA16F atlas that the terrain and mesh shaders sample once at their
// world position instead of looping over the lights of a grid cell. The cost depends on the size of the field, not on
// the number of lights or of the passes that read it.
//
// Atlas layout (width = cells * layers, height = 3 * cells): layer l, cell (x, y) is at pixel (l * cells + x, y) for
// the first part, (l * cells + x, cells + y) for the second and (l * cells + x, 2 * cells + y) for the third (x = how
// much of the sun reaches the cell: the terrain between the cell and the sun, layers 0 and 1 only):
//   first half   rgb = sum of colour x attenuation of the lights (irradiance without a normal); alpha of layer 0 = the
//   terrain height at
//                the cell, of layer 1 = the surface height (the water surface over water, else the terrain)
// Layers: 0 the terrain 0.5 above it (the sea bed under water), 1 to 4 the surface 0.3, 3, 10 and 30 above it. Over
// water the lights are weakened by the water between them and the point (red first): docs/LIGHTING_V2.md.
//   second half  xyz = sum of luminance x attenuation x direction to the light, w = sum of luminance x attenuation
//   third part   x = how much of the sun reaches the cell; y = the water level over the cell (a map with water bodies
//                has one per water: LightWaterLevels.h; kNoWaterLevel where there is none)
// A surface with normal n then receives E * (1/3) + E * (2/3) * dot(n, D) / W, which is the wrapped diffuse term the
// grid path sums per light, exact for lights in the linear range of the wrap.
//
// Render thread only.
namespace moho::lights
{
  // 1 (the default): the irradiance field; 0: the light grid and the shader loops of docs/DYNAMIC_LIGHTS.md.
  extern int ren_DynLightsMode;
  // 1 (the default): a map with water bodies is lit with the water level of each cell; 0: the sea level for all.
  extern int ren_DynLightsWaterLevels;
  // 0 (the default): the terrain does not take the field's sun shadow (its own height-field march: blocky patches on
  // hill faces); 1: it does. The sun shadow on meshes and water is not affected.
  extern int ren_DynLightsTerrainSunShadow;

  // Elevation of the terrain at x, z; `context` is whatever the caller needs (the height field).
  using ElevationFunction = float (*)(const void* context, float x, float z);
  // One raw height sample (the engine's uint16, 1 / 128 world unit), clamped to the map.
  using HeightSampleFunction = std::uint16_t (*)(const void* context, std::int32_t x, std::int32_t z);

  // What the field needs to know about the map: the terrain and the water.
  struct FieldTerrain
  {
    const void* context = nullptr;
    ElevationFunction elevation = nullptr;
    HeightSampleFunction sample = nullptr;
    std::uint32_t width = 0; // height samples (the map is width - 1 units wide)
    std::uint32_t height = 0;
    std::uint64_t revision = 0;  // changes when the heights do (HeightFieldRevision)
    float waterElevation = 0.0f; // the sea
    bool waterEnabled = false;
    // A map with water bodies: the level of the block whose first corner is the vertex (x, z), and the generation of
    // the bodies (0 = none: the whole map has the one level above). The table is rebuilt when the generation or the
    // context changes.
    const void* waterContext = nullptr;
    WaterBlockLevelFunction waterLevel = nullptr;
    std::uint32_t waterGeneration = 0;
    float sunDirection[3] = {0.0f, 1.0f, 0.0f}; // unit vector towards the sun
    bool sunValid = false;
  };

  struct FieldFrame
  {
    std::shared_ptr<gpg::gal::RenderTarget> atlas;
    float params[4] = {0.0f, 0.0f, 1.0f, 1.0f}; // originX, originZ, 1 / cellSize, cells
    float params2[4] = {
      0.0f,
      0.0f,
      1.0f,
      1.0f
    }; // mode (1: sample the field, 0: use the grid), layers, 1 / atlas width, 1 / atlas height
    float layerHeights[4] = {0.5f, 3.0f, 10.0f, 30.0f}; // metres above the terrain, one per layer
    // x: 1 = the third part of the atlas holds the water level of each cell in y;
    // y: 1 = the terrain takes the sun shadow
    float water[4] = {0.0f, 0.0f, 0.0f, 0.0f};
    bool valid = false;
  };

  // Fits the field to the camera's view of the ground, uploads the lights of `image` and runs the compute and the copy
  // into the atlas. False (with `CurrentField().valid` false) when the field is off, unavailable on this API or has no
  // light: the shaders then use the grid.
  bool UpdateField(const GeomCamera3& camera, const LightGridImage& image, const FieldTerrain& terrain);

  const FieldFrame& CurrentField();

  // True while the field of this frame carries the sun's shadow of the terrain (the terrain and mesh shaders then
  // multiply it into their shadow term).
  bool SunShadowActive();

  // True while the terrain shaders multiply the field's sun shadow into their own shadow term:
  // SunShadowActive() and ren_DynLightsTerrainSunShadow. The bake of ren_TerrainShadows and the terrain's
  // ShadowsEnabled look at this one, not at SunShadowActive().
  bool TerrainSunShadowActive();

  // Frees the buffers, programs and the atlas (a device reset, shutdown).
  void ReleaseField();

  struct FieldStats
  {
    std::uint32_t frames = 0;
    float cellSize = 0.0f;
    std::uint32_t cells = 0;
    std::uint32_t lights = 0;
  };
  const FieldStats& GetFieldStats();
} // namespace moho::lights
