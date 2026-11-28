#pragma once

#include "gpg/gal/Matrix.h"
#include "moho/render/lights/LightField.h"
#include "moho/render/lights/LightGrid.h"

// Owns the two dynamic light textures, fills them from a LightGridImage and binds them, with their parameters, to the
// effects that declare them (docs/DYNAMIC_LIGHTS.md). Stage 2: the variables below do not exist in any shader yet (the
// translator step of stage 3 adds them to the lit techniques), so every bind is a no-op until then; the upload still
// runs, which exercises the Float4 dynamic texture on each backend.
//
// Effect parameters (declared by the injected HLSL, both in the "mesh" and the "terrain" effect):
//   Texture dynLightData      RGBA32F, see LightGrid.h
//   Texture dynLightGrid      RGBA32F
//   float4  dynLightParams    (gridOriginX, gridOriginZ, 1 / cellSize, lightCount)
//   float4  dynLightGridSize  (cellsX, cellsZ, 1 / (4 cellsX), 1 / cellsZ)         texel size of the grid texture, x
//   per cell of 4 texels float4  dynLightDataSize  (1 / kDataWidth, 1 / rows, kDataWidth, rows)
//
// Render thread only.
namespace moho::lights
{
  // Uploads `image` (skipped while it is empty and was empty) and binds the textures and parameters. With `uploadGrid`
  // false the cell table and lists (`image.grid`) are not uploaded: the irradiance field does not read them.
  void UpdateBinding(const LightGridImage& image, bool uploadGrid = true);

  // Binds (or, when `frame` is not valid, switches off) the irradiance field the shaders sample: docs/LIGHTING_V2.md.
  void BindField(const FieldFrame& frame);

  // The inverse of the sun's shadow matrix (the shadow camera's inverse view projection): the shaders rebuild the world
  // position of a pixel from its shadow coordinates with it, to ask the field how much sun reaches that position.
  void SetSunShadowCamera(const gpg::gal::Matrix& inverseViewProjection, bool valid);

  // World position of the camera of the view that is about to draw; the mesh pixel shaders rebuild their world position
  // from it.
  void SetCameraPosition(float x, float y, float z);

  // Drops the textures (default-pool resources) ahead of a device reset or shutdown; the next UpdateBinding recreates
  // them.
  void ReleaseBinding();

  // For the log line and the debug view.
  struct BindingStats
  {
    std::uint32_t uploads = 0;        // texture uploads since start
    std::uint32_t creates = 0;        // textures (re)created
    std::uint32_t failures = 0;       // uploads that threw or found no texture
    std::uint32_t boundVariables = 0; // effect variables that exist right now (0 until a shader declares them)
  };
  const BindingStats& GetBindingStats();
} // namespace moho::lights
