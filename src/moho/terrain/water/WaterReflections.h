#pragma once

#include "gpg/gal/DeviceContext.hpp"

namespace gpg::gal
{
  class Device;
}

namespace moho
{
  struct GeomCamera3;
  class Shadow;
} // namespace moho

// What the water shows of the scene around it (docs/WATER_REFLECTIONS.md): screen-space reflections, the water's
// thickness from the real scene depth, caustics on the sea bed, a physical sheen and the sun shadow of units, buildings
// and trees. The shader side is the source patch of water2.fx (WaterReflectionPatch.cpp); this file owns the console
// variables, the copy of the scene depth the shader reads and the per-frame binding of the parameters. Render only;
// Direct3D 11, 12 and Vulkan (the other backends keep the shipped water).
namespace moho::water
{
  // Whether the water effect gets the patch on this API: the Direct3D 10 effect dialect backends. The switches below
  // are shader constants set every frame, so all of them change at once in a running game.
  [[nodiscard]] bool ReflectionPatchWanted(gpg::gal::DeviceApi api);

  // Once per frame right before the water is drawn, with the world's colour and depth targets bound: copies the scene
  // depth, binds it and the parameters to the water effect. The parameters of the effects that need no depth (the
  // sheen) are bound regardless; the others are bound "off" when the view cannot use the depth (orthographic, no
  // sampled depth, a backend that cannot copy it). `shadow`: the viewport's shadow renderer (the sun shadow map of the
  // units for the water), null for none.
  void BindWaterReflections(gpg::gal::Device* device, const moho::GeomCamera3& camera, const moho::Shadow* shadow);

  // Frees the GPU resources (a device reset, shutdown).
  void ReleaseWaterReflections();
} // namespace moho::water
