#pragma once

#include <cstdint>

#include <memory>
#include "gpg/gal/DepthStencilTarget.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/backends/common/AmbientOcclusion.h"

namespace gpg::gal
{
  class Device;

  /**
   * FAF addition, not in the shipped binary: the screen-space ambient occlusion pass on any backend that has the
   * GPU-driven programs
   * (`kGpuFeatureVertexPulling`: Direct3D 11, 12 and Vulkan; docs/RENDERER_BACKENDS.md, "Ambient occlusion").
   *
   * It is written against the public `Device` calls only (render targets, `SetViewport`, `ClearTarget`,
   * `CreateGpuProgram`, `DrawGpuProgram`), so one implementation serves all three; the backends contribute the sampled
   * depth buffer (the head's, created sampled) and the binding of a depth or colour target (`GpuBindings::depthTarget`
   * at `t6`, `GpuBindings::targets` at `t4`).
   *
   * Three draws: the horizon search into a target of its own (half the size at Low and Medium), a horizontal blur into
   * a second target, and a vertical blur at back buffer resolution that is blended onto the head's back buffer as black
   * with alpha = 1 - occlusion (with the smoothing over smooth ground, `AmbientOcclusionParams::smoothReach`, two more
   * draws sit before that last one: the vertical blur back into the first target, the smoothing along x into the
   * second). The engine's bound targets and viewport are put back.
   */
  class AmbientOcclusionPass
  {
  public:
    [[nodiscard]] static AmbientOcclusionPass& Instance();

    /**
     * Darkens the colour target that is bound now, from the depth target bound with it (the world view's, between the
     * opaque meshes and the effects). False (having drawn nothing) when the backend has no GPU programs, the depth
     * buffer cannot be sampled, or a program did not compile; the first refusal is logged once. The engine's bound
     * targets and viewport are put back.
     */
    bool Apply(Device& device, const AmbientOcclusionParams& params);

    /** Frees the targets and programs (a device reset or exit). */
    void Release();

    /** Number of passes drawn since start (diagnostics and tests). */
    [[nodiscard]] std::uint32_t FramesDrawn() const noexcept
    {
      return mFrames;
    }

  private:
    bool EnsureResources(Device& device, std::uint32_t width, std::uint32_t height, bool halfRes);

    Device* mDevice = nullptr;
    std::shared_ptr<GpuProgram> mCompute;
    std::shared_ptr<GpuProgram> mBlur;
    std::shared_ptr<GpuProgram> mWide;
    std::shared_ptr<GpuProgram> mComposite;
    std::shared_ptr<RenderTarget> mTargetA;
    std::shared_ptr<RenderTarget> mTargetB;
    std::uint32_t mTargetWidth = 0U;
    std::uint32_t mTargetHeight = 0U;
    std::uint32_t mFrames = 0U;
    bool mFailed = false;
    bool mLoggedRefusal = false;
  };
} // namespace gpg::gal
