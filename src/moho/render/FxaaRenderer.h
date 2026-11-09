#pragma once

#include "boost/shared_ptr.h"

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
   * Engine addition (`ren_Fxaa`): FXAA over the finished world views on Direct3D 12 and Vulkan,
   * which have no multisampled back buffer and so ignored the Anti-Aliasing option until now. On by
   * default (1), off at 0; Options > Video > Anti-aliasing (FXAA) sets it. Direct3D 9 and 11 keep
   * their own anti-aliasing and the original look.
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
    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
  };
} // namespace moho
