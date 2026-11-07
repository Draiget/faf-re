#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class Device;
  class GpuBuffer;
  class GpuProgram;
} // namespace gpg::gal

namespace moho
{
  struct GeomCamera3;

  extern int ren_Ao;

  /**
   * Engine addition (`ren_Ao`): ambient occlusion, the darkening in creases, under units and where
   * terrain meets them, from the depth of terrain and the opaque meshes. Direct3D 12 and Vulkan only:
   * it reads the bound depth target (`GpuBindings::readBoundDepth`). Direct3D 9 and 11 keep the
   * original look.
   */
  class AmbientOcclusionRenderer
  {
  public:
    [[nodiscard]] static AmbientOcclusionRenderer& Get();

    /** `ren_Ao` is on, the renderer is Direct3D 12 or Vulkan with compute, and the programs built. */
    [[nodiscard]] bool IsActive();

    /**
     * Darkens the bound colour target over the view at (`x`, `y`), `width` by `height` pixels, by the
     * occlusion the bound depth shows. Call it with the world view's viewport set, after the opaque
     * meshes and before effects and water.
     */
    void Render(const GeomCamera3& camera, int x, int y, int width, int height);

  private:
    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    boost::shared_ptr<gpg::gal::GpuProgram> mCompute;
    boost::shared_ptr<gpg::gal::GpuProgram> mComposite;
    boost::shared_ptr<gpg::gal::GpuBuffer> mTerms;
    std::uint32_t mTermCapacity = 0U;
  };
} // namespace moho
