#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_RayBounce`): one bounce of diffuse light by ray (BounceLightShader.h). Grass, sunlit cliffs
// and buildings light what stands next to them in their own colour. Needs the ray-traced scene
// (ren_RayTracedShadows) on Direct3D 12 or Vulkan with ray queries; off by default.

#include <cstdint>

#include <memory>

namespace gpg::gal
{
  class Device;
  class GpuBuffer;
  class GpuProgram;
  class RenderTarget;
} // namespace gpg::gal

namespace moho
{
  struct GeomCamera3;

  extern int ren_RayBounce;

  class BounceLight
  {
  public:
    [[nodiscard]] static BounceLight& Get();

    /**
     * `ren_RayBounce` is on, the device traces rays, the programs built, and the ray-traced scene was published this
     * frame (ren_RayTracedShadows).
     */
    [[nodiscard]] bool IsActive();

    /**
     * Brightens the bound colour target over the view at (`x`, `y`), `width` by `height` by the light the scene
     * around each point bounces onto it; `frame` is a copy of the colour so far (read, never the bound target).
     * `waterLevel` is the water's surface height (-1e9 without water): hits under it give no light.
     */
    void Render(
      const GeomCamera3& camera,
      gpg::gal::RenderTarget& frame,
      float waterLevel,
      int x,
      int y,
      int width,
      int height
    );

  private:
    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    std::shared_ptr<gpg::gal::GpuProgram> mCompute;
    std::shared_ptr<gpg::gal::GpuProgram> mComposite;
    std::shared_ptr<gpg::gal::GpuBuffer> mTerms;
    std::uint32_t mTermCapacity = 0U;
  };
} // namespace moho
