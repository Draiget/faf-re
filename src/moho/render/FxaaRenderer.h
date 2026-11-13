#pragma once

#include <memory>

namespace gpg::gal
{
  class Device;
  class GpuProgram;
  class RenderTarget;
} // namespace gpg::gal

namespace moho
{
  extern int ren_Fxaa;

  /**
   * Engine addition (`ren_Fxaa`): anti-aliasing of the finished world views on Direct3D 11, 12 and Vulkan, which have
   * no multisampled back buffer and so ignored the Anti-Aliasing option until now. 0 off, 1 FXAA (this class, on by
   * default), 2 SMAA 1x (SmaaRenderer); Options > Video > Anti-aliasing sets it.
   */
  class FxaaRenderer
  {
  public:
    [[nodiscard]] static FxaaRenderer& Get();

    /** On for this frame: `ren_Fxaa`, the renderer and the program allow it. */
    [[nodiscard]] bool IsActive();

    /**
     * Draws the anti-aliased image of `copy` (a copy of the bound colour target, `width` by `height`)
     * into the bound colour target over the current viewport, colour only.
     */
    void Render(gpg::gal::RenderTarget& copy, int width, int height);

  private:
    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    std::shared_ptr<gpg::gal::GpuProgram> mProgram;
  };
} // namespace moho
