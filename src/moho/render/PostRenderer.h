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
  extern float ren_Sharpen;
  extern int ren_Grade;
  extern float ren_GradeVibrance;
  extern float ren_GradeContrast;

  /**
   * Engine addition (`ren_Sharpen`, `ren_Grade`): contrast-adaptive sharpening and a mild colour
   * grade over the finished world views on Direct3D 12 and Vulkan, after FXAA and before the
   * interface, in one pass. On by default; Options > Video > Sharpening and Colour grading set them.
   * Direct3D 9 and 11 keep the original look.
   */
  class PostRenderer
  {
  public:
    [[nodiscard]] static PostRenderer& Get();

    /** On for this frame: a switch asks for it, and the renderer and the program allow it. */
    [[nodiscard]] bool IsActive();

    /**
     * Draws the sharpened and graded image of `copy` (a copy of the bound colour target, `width`
     * by `height`) into the bound colour target over the current viewport, colour only.
     */
    void Render(gpg::gal::RenderTarget& copy, int width, int height);

  private:
    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
  };
} // namespace moho
