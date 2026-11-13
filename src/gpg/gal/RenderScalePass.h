#pragma once

#include <cstdint>

#include <memory>
#include "gpg/gal/DepthStencilTarget.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/OutputContext.hpp"
#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/backends/common/RenderScale.h"

namespace gpg::gal
{
  class Device;

  /**
   * FAF addition, not in the shipped binary: the render-scale pass on any backend that has the GPU-driven programs
   * (`kGpuFeatureVertexPulling`: Direct3D 11, 12 and Vulkan; docs/RENDERER_BACKENDS.md, "Render scale").
   *
   * Written against the public `Device` calls only (`CreateRenderTarget`, `ClearTarget`, `SetViewport`,
   * `CreateGpuProgram`, `DrawGpuProgram`), so one implementation serves all three. It owns the colour and depth target
   * the world is drawn into (the colour target is sampled by the upscale, the depth target is created sampled so the
   * passes that read the bound depth (ren_Ao, the lights) can still read it) and the upscale programs; `Resolve` draws
   * one view's rectangle of the scaled colour target into the head's back buffer.
   */
  class RenderScalePass
  {
  public:
    [[nodiscard]] static RenderScalePass& Instance();

    /**
     * Makes the scaled targets for a window of `windowWidth` x `windowHeight` pixels at `factor` (recreated when the
     * size changes). False when the backend has no GPU programs or a target or program could not be created (the first
     * refusal is logged once).
     */
    bool Prepare(Device& device, std::uint32_t windowWidth, std::uint32_t windowHeight, float factor);

    [[nodiscard]] const std::shared_ptr<RenderTarget>& Color() const noexcept
    {
      return mColor;
    }
    [[nodiscard]] const std::shared_ptr<DepthStencilTarget>& Depth() const noexcept
    {
      return mDepth;
    }
    [[nodiscard]] std::uint32_t Width() const noexcept
    {
      return mWidth;
    }
    [[nodiscard]] std::uint32_t Height() const noexcept
    {
      return mHeight;
    }

    /**
     * Upscales `source` (texels of the scaled colour target) into `dest` (pixels of head `head`'s back buffer), then
     * sharpens when `sharpness` > 0. The engine's bound targets and viewport are put back. False when nothing was
     * drawn.
     */
    bool Resolve(
      Device& device,
      std::uint32_t head,
      const RenderScaleRect& source,
      const RenderScaleRect& dest,
      float sharpness
    );

    /** Frees the targets and programs (a device reset or exit, or the scale turned off). */
    void Release();

    /** Frees only the targets (the scale turned off; the programs stay compiled). */
    void ReleaseTargets();

    [[nodiscard]] std::uint32_t ResolvesDrawn() const noexcept
    {
      return mResolves;
    }

  private:
    bool EnsureProgram(Device& device);

    Device* mDevice = nullptr;
    std::shared_ptr<GpuProgram> mUpscale;
    std::shared_ptr<GpuProgram> mSharpen;
    std::shared_ptr<RenderTarget> mColor;
    std::shared_ptr<DepthStencilTarget> mDepth;
    std::shared_ptr<RenderTarget> mMiddle; ///< the upscaled image before sharpening, back buffer sized
    std::uint32_t mWidth = 0U;
    std::uint32_t mHeight = 0U;
    std::uint32_t mWindowWidth = 0U;
    std::uint32_t mWindowHeight = 0U;
    std::uint32_t mMiddleWidth = 0U;
    std::uint32_t mMiddleHeight = 0U;
    std::uint32_t mResolves = 0U;
    bool mFailed = false;
    bool mLoggedRefusal = false;
  };
} // namespace gpg::gal
