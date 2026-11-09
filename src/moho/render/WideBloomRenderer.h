#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class Device;
  class GpuProgram;
} // namespace gpg::gal

namespace moho
{
  class ID3DRenderTarget;

  extern float ren_BloomWide;

  /**
   * Engine addition (`ren_BloomWide`): a wide, soft glow added after the original bloom on
   * Direct3D 12 and Vulkan. It reads the original bloom's blurred glow (half the head's size),
   * halves it four times, adds the levels back up through tent filters and adds the sum onto the
   * head, so glowing things get a halo that falls off over a large part of the screen. The
   * original bloom is untouched; Direct3D 9 and 11 keep the original look.
   */
  class WideBloomRenderer
  {
  public:
    static constexpr int kLevels = 4;

    /** The renderer for `head` (0 or 1). */
    [[nodiscard]] static WideBloomRenderer& Get(int head);

    /** On for this frame: `ren_BloomWide`, the renderer and the programs allow it. */
    [[nodiscard]] bool IsActive();

    /**
     * Adds the wide glow made from `glow` (the original bloom's result, `glowWidth` by
     * `glowHeight`) onto `head`'s back buffer, and leaves that back buffer bound with the
     * viewport it found.
     */
    void Render(int head, const boost::shared_ptr<ID3DRenderTarget>& glow, int glowWidth, int glowHeight);

  private:
    struct Level
    {
      boost::shared_ptr<ID3DRenderTarget> target;
      int width = 0;
      int height = 0;
    };

    bool EnsureLevels(int glowWidth, int glowHeight);

    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    boost::shared_ptr<gpg::gal::GpuProgram> mDown;
    boost::shared_ptr<gpg::gal::GpuProgram> mUp;
    Level mLevels[kLevels];
    int mGlowWidth = 0;
    int mGlowHeight = 0;
  };
} // namespace moho
