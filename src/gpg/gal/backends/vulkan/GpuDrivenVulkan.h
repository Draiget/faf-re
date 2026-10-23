#pragma once

// FAF addition, not in the shipped binary: the Vulkan side of the GPU-driven
// gal interfaces (gpg/gal/GpuDriven.h) and of the render profiler's GPU
// timestamps. The work itself is done by DeviceVulkan's GPU-driven members
// (GpuDrivenVulkan.cpp); these are the objects they hand out.
//
// Binding model (GpuDriven.h) as Vulkan sees it: one descriptor set, compiled
// by DXC with -fvk-b-shift 0, -fvk-t-shift 1, -fvk-u-shift 7, -fvk-s-shift 9:
//   0      b0, a uniform buffer in the upload ring
//   1..4   t0..t3, storage buffers
//   5..6   t4..t5, sampled images
//   7..8   u0..u1, storage buffers
//   9      s0, the program's sampler

#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "VulkanCore.h"
#include "gpg/gal/GpuDriven.h"

namespace gpg::gal
{
  class DeviceVulkan;

  class GpuBufferVulkan final : public GpuBuffer
  {
  public:
    GpuBufferVulkan(DeviceVulkan& device, const GpuBufferDesc& desc);
    ~GpuBufferVulkan() override;

    [[nodiscard]] vulkan::TrackedBuffer& Buffer() noexcept { return mBuffer; }

  private:
    vulkan::TrackedBuffer mBuffer;
  };

  class GpuProgramVulkan final : public GpuProgram
  {
  public:
    GpuProgramVulkan() = default;
    ~GpuProgramVulkan() override;

    GpuProgramDesc mDesc{}; // the render state (source pointers are not kept)
    std::string mName;
    std::string mVertexEntry;
    std::string mPixelEntry;
    std::string mComputeEntry;
    VkShaderModule mVertex = VK_NULL_HANDLE;
    VkShaderModule mPixel = VK_NULL_HANDLE;
    VkShaderModule mCompute = VK_NULL_HANDLE;
    VkPipeline mComputePipeline = VK_NULL_HANDLE;
    /** Draw pipelines by (colour format, depth format). */
    /// By colour format, depth format and - for inheritDepthStencil programs - the engine's
    /// depth-stencil state and stencil reference at the draw (else 0).
    std::map<std::tuple<VkFormat, VkFormat, std::uint64_t>, VkPipeline> mPipelines;
  };
} // namespace gpg::gal
