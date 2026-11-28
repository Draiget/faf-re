#pragma once

#include <cstdint>

namespace gpg::gal
{
  class Device;
}

namespace moho
{
  struct GeomCamera3;
}

// FAF addition, not in the shipped binary: the screen-space ambient occlusion kernel (GTAO) that
// AmbientOcclusionRenderer runs in the frame slot of ren_Ao (docs/AMBIENT_OCCLUSION.md). The world view's colour is
// darkened where the geometry closes in; the pass itself is gpg::gal::AmbientOcclusionPass. Render only; nothing here
// touches the simulation.
namespace moho
{
  // The one Ambient Occlusion option (render feature "ambient_occlusion", console variable ren_AmbientOcclusion):
  //   0 Off          no occlusion at all
  //   1 Standard     ren_Ao's own kernel (AmbientOcclusionRenderer) with its contact and terrain shadows, where the API
  //   has it
  //                  (Direct3D 12 and Vulkan; Direct3D 11 draws Low instead); the default there
  //   2 Low, 3 Medium, 4 High   the GTAO kernel (half resolution at Low and Medium), with the same contact and terrain
  //   shadows
  // /ao off|standard|low|medium|high on the command line sets it at start. At most one occlusion kernel runs at a time:
  // GTAO, ren_Ao's, or the traced one while ray-traced shadows trace (ren_RayAo).
  extern int ren_AmbientOcclusion;

  // The level after the command line was applied (once).
  [[nodiscard]] int REN_GetAmbientOcclusionLevel();

  // The GTAO quality (gpg::gal::AmbientOcclusionLevel, 1..3) that `level` of ren_AmbientOcclusion asks for; 0 when it
  // asks for none. `legacyAvailable`: ren_Ao's own kernel can run on this device, which is what Standard means; without
  // it Standard is Low.
  [[nodiscard]] int REN_GtaoQualityFor(int level, bool legacyAvailable);

  // Darkens the colour target that is bound now, from the depth target bound with it, seen through `camera`, inside the
  // pixel rectangle (x, y, width, height), at GTAO quality `quality` (1..3). Nothing is drawn for an orthographic
  // camera or when the backend cannot (the first refusal is logged once). True when the pass drew.
  bool REN_ApplyAmbientOcclusion(
    gpg::gal::Device* device,
    const GeomCamera3& camera,
    int x,
    int y,
    int width,
    int height,
    int quality
  );
} // namespace moho
