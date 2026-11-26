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
  /**
   * Engine addition (`ren_Fxaa 2`): SMAA 1x over the finished world views on Direct3D 11, 12 and Vulkan, as the second
   * algorithm behind the Anti-aliasing option. It hosts like FxaaRenderer (the view's head copy in, the view's
   * rectangle of the head out) and adds the two working targets of the edge and blend-weight passes, made at the size
   * of the copy.
   */
  class SmaaRenderer
  {
  public:
    [[nodiscard]] static SmaaRenderer& Get();

    /** On for this frame: `ren_Fxaa` is 2, and the renderer and the programs allow it. */
    [[nodiscard]] bool IsActive();

    /**
     * Draws the anti-aliased image of `copy` (a copy of the bound colour target) into the bound colour target over the
     * current viewport, colour only. The bound targets and the viewport are the same on return.
     */
    void Render(gpg::gal::RenderTarget& copy, int width, int height);

    /** Frees the working targets and programs (a device reset or exit). */
    void Release();

  private:
    bool EnsureTargets(int width, int height);

    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    bool mFailed = false;
    int mWidth = 0;
    int mHeight = 0;
    std::shared_ptr<gpg::gal::GpuProgram> mEdges;
    std::shared_ptr<gpg::gal::GpuProgram> mWeights;
    std::shared_ptr<gpg::gal::GpuProgram> mBlend;
    std::shared_ptr<gpg::gal::RenderTarget> mEdgeTarget;
    std::shared_ptr<gpg::gal::RenderTarget> mWeightTarget;
  };
} // namespace moho
