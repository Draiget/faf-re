#pragma once

// FAF addition, not in the shipped binary: the Direct3D 12 side of the
// GPU-driven gal interfaces (gpg/gal/GpuDriven.h) and of the render profiler's
// GPU timestamps. The work itself is done by DeviceD3D12's GPU-driven members
// (GpuDrivenD3D12.cpp); these are the objects they hand out.
//
// Binding model (GpuDriven.h) as Direct3D 12 sees it: one root signature per
// GpuSampler - a root CBV at b0, a table of six SRVs (t0..t3 buffers, t4..t5
// textures), a table of two UAVs (u0..u1) and the sampler as a static sampler
// at s0 - shared by draw and compute programs.

#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <d3d12.h>
#include <wrl/client.h>

#include "D3D12Core.h"
#include "gpg/gal/GpuDriven.h"

namespace gpg::gal
{
  class DeviceD3D12;

  class GpuBufferD3D12 final : public GpuBuffer
  {
  public:
    GpuBufferD3D12(DeviceD3D12& device, const GpuBufferDesc& desc);
    ~GpuBufferD3D12() override;

    [[nodiscard]] d3d12::TrackedResource& Resource() noexcept { return mResource; }
    [[nodiscard]] D3D12_CPU_DESCRIPTOR_HANDLE ShaderView() const noexcept { return mShaderView; }
    [[nodiscard]] D3D12_CPU_DESCRIPTOR_HANDLE WriteView() const noexcept { return mWriteView; }
    [[nodiscard]] std::uint64_t ByteWidth() const noexcept { return mByteWidth; }

  private:
    d3d12::TrackedResource mResource;
    D3D12_CPU_DESCRIPTOR_HANDLE mShaderView{};
    D3D12_CPU_DESCRIPTOR_HANDLE mWriteView{};
    std::uint64_t mByteWidth = 0U;
  };

  class GpuProgramD3D12 final : public GpuProgram
  {
  public:
    GpuProgramD3D12() = default;
    ~GpuProgramD3D12() override;

    GpuProgramDesc mDesc{};          // the render state (source pointers are not kept)
    std::string mName;
    std::vector<std::uint8_t> mVertexCode;
    std::vector<std::uint8_t> mPixelCode;
    std::vector<std::uint8_t> mComputeCode;
    Microsoft::WRL::ComPtr<ID3D12PipelineState> mCompute;
    /** Draw pipelines by (render-target format, depth format). */
    /// By render-target format, depth format and - for inheritDepthStencil programs - the
    /// engine's depth-stencil state at the draw (DepthStencilDesc::PackedKey, else 0).
    std::map<std::tuple<DXGI_FORMAT, DXGI_FORMAT, std::uint64_t>, Microsoft::WRL::ComPtr<ID3D12PipelineState>> mPipelines;
  };
} // namespace gpg::gal
