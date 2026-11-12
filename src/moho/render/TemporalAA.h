#pragma once

// FAF addition, not in the shipped binary.
//
// Engine addition (`ren_Taa`): temporal anti-aliasing for the first world view on Direct3D 12 and Vulkan
// (TemporalAAShader.h). `Jitter` hands the world passes a copy of the view's camera whose projection is moved by a
// sub-pixel offset that changes every frame; the view's overlay (strategic icons) draws with the unmoved camera, so
// it stays pixel-exact. `Resolve`, in the post passes, blends the frame with the reprojected
// history and replaces FXAA while it runs. Off by default.

#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/render/camera/GeomCamera3.h"

namespace gpg::gal
{
  class Device;
  class GpuBuffer;
  class GpuProgram;
  class RenderTarget;
} // namespace gpg::gal

namespace moho
{
  extern int ren_Taa;
  extern float ren_RenderScale;

  class TemporalAA
  {
  public:
    [[nodiscard]] static TemporalAA& Get();

    /** `ren_Taa` is on, the renderer is Direct3D 12 or Vulkan with compute, and the programs built. */
    [[nodiscard]] bool IsActive();

    /**
     * This frame's camera for the world passes: `camera` with its projection moved by this frame's offset and, with
     * ren_RenderScale under 1, a smaller viewport. `allowScale` says the post passes will run; without them, or
     * without history buffers, it is `camera` unchanged and nothing waits for a resolve.
     */
    [[nodiscard]] GeomCamera3* Jitter(const GeomCamera3& camera, bool allowScale);

    /** The view's full rectangle this frame (origin x, y, width, height), what the post passes and overlays use. */
    [[nodiscard]] const int* FullRect() const noexcept
    {
      return mFullRect;
    }

    /** A frame was jittered and waits for its resolve. */
    [[nodiscard]] bool Pending() const noexcept
    {
      return mPending;
    }

    /** The end of a world view: a frame the resolve didn't take is dropped (its history isn't trusted). */
    void EndView() noexcept
    {
      if (mPending) {
        mPending = false;
        mHistoryValid = false;
      }
    }

    /** A preview picture is being drawn (WRenViewport::RenderPreviewImage): no offset, no history. */
    void SetPreviewRender(
      bool preview
    ) noexcept
    {
      mPreview = preview;
    }
    [[nodiscard]] bool PreviewRender() const noexcept
    {
      return mPreview;
    }

    /**
     * Blends the frame (`copy`, the head's colour, also bound as the target) over the view at (`x`, `y`), `width` by
     * `height`, with the history, and writes the result into the bound target. Reads the bound depth. False when it
     * didn't (the caller then anti-aliases the frame another way).
     */
    [[nodiscard]] bool Resolve(gpg::gal::RenderTarget& copy, int x, int y, int width, int height);

  private:
    /** Both history buffers hold `width` x `height`; false when they can't. */
    [[nodiscard]] bool EnsureHistory(int width, int height);

    gpg::gal::Device* mDevice = nullptr;
    bool mSupported = false;
    boost::shared_ptr<gpg::gal::GpuProgram> mCompute;
    boost::shared_ptr<gpg::gal::GpuProgram> mComposite;
    boost::shared_ptr<gpg::gal::GpuProgram> mCompositeAlpha; // writes alpha too (ren_RenderScale under 1)
    boost::shared_ptr<gpg::gal::GpuBuffer> mHistory[2];
    std::uint32_t mHistoryCapacity = 0U;
    int mHistoryWidth = 0;
    int mHistoryHeight = 0;
    int mCurrent = 0; // the history buffer the last resolve wrote
    bool mHistoryValid = false;
    bool mPending = false;
    bool mPreview = false;
    // What the history belongs to: a different camera, map or an earlier game tick starts it over.
    const GeomCamera3* mHistoryCamera = nullptr;
    const void* mHistoryMap = nullptr;
    int mHistoryTick = 0;
    float mHistoryEye[3]{};
    std::uint32_t mFrame = 0U;
    float mScale = 1.0f; // ren_RenderScale this frame
    int mLowWidth = 0;   // the area the world is drawn into this frame
    int mLowHeight = 0;
    float mJitterPixels[2]{}; // this frame's offset in drawn pixels (x right, y down)
    int mFullRect[4]{};       // the view's rectangle at full size
    GeomCamera3 mJittered;
    gpg::gal::Matrix mViewProjection{};        // this frame's unmoved view-projection
    gpg::gal::Matrix mInverseViewProjection{}; // and its inverse
    gpg::gal::Matrix mPrevViewProjection{};    // the last resolved frame's
  };
} // namespace moho
