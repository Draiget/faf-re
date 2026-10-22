#pragma once

// FAF addition, not in the shipped binary: the Direct3D 11 side of the
// GPU-driven gal interfaces (gpg/gal/GpuDriven.h) and of the render profiler's
// GPU timestamps (gpg/gal/RenderProfiler.h). Owned by DeviceD3D11.

#include <cstdint>
#include <vector>

#include <d3d11.h>
#include <wrl/client.h>

#include "boost/shared_ptr.h"
#include "gpg/gal/GpuDriven.h"

namespace gpg::gal
{
  class GpuBufferD3D11 final : public GpuBuffer
  {
  public:
    GpuBufferD3D11(ID3D11Device* device, const GpuBufferDesc& desc);
    ~GpuBufferD3D11() override;

    [[nodiscard]] ID3D11Buffer* Buffer() const noexcept { return mBuffer.Get(); }
    [[nodiscard]] ID3D11ShaderResourceView* ShaderView() const noexcept { return mShaderView.Get(); }
    [[nodiscard]] ID3D11UnorderedAccessView* WriteView() const noexcept { return mWriteView.Get(); }

  private:
    Microsoft::WRL::ComPtr<ID3D11Buffer> mBuffer;
    Microsoft::WRL::ComPtr<ID3D11ShaderResourceView> mShaderView;
    Microsoft::WRL::ComPtr<ID3D11UnorderedAccessView> mWriteView;
  };

  class GpuProgramD3D11 final : public GpuProgram
  {
  public:
    GpuProgramD3D11() = default;
    ~GpuProgramD3D11() override;

    Microsoft::WRL::ComPtr<ID3D11VertexShader> mVertexShader;
    Microsoft::WRL::ComPtr<ID3D11PixelShader> mPixelShader;
    Microsoft::WRL::ComPtr<ID3D11ComputeShader> mComputeShader;
    Microsoft::WRL::ComPtr<ID3D11BlendState> mBlend;
    Microsoft::WRL::ComPtr<ID3D11DepthStencilState> mDepthStencil;
    Microsoft::WRL::ComPtr<ID3D11RasterizerState> mRasterizer;
    Microsoft::WRL::ComPtr<ID3D11SamplerState> mSampler;
    UINT mStencilReference = 0U;
    bool mInheritDepthStencil = false; // GpuProgramDesc::inheritDepthStencil
  };

  class GpuDrivenD3D11
  {
  public:
    GpuDrivenD3D11(ID3D11Device* device, ID3D11DeviceContext* immediate, D3D_FEATURE_LEVEL featureLevel);
    ~GpuDrivenD3D11();
    GpuDrivenD3D11(const GpuDrivenD3D11&) = delete;
    GpuDrivenD3D11& operator=(const GpuDrivenD3D11&) = delete;

    [[nodiscard]] std::uint32_t Features() const noexcept { return mFeatures; }

    [[nodiscard]] boost::shared_ptr<GpuBuffer> CreateBuffer(const GpuBufferDesc& desc);
    void UpdateBuffer(GpuBuffer& buffer, std::uint32_t firstElement, std::uint32_t count, const void* data);
    /** Diagnostics: copies elements of `buffer` to `out` through a staging buffer, waiting for the GPU. */
    bool ReadBuffer(GpuBuffer& buffer, std::uint32_t firstElement, std::uint32_t count, void* out);
    [[nodiscard]] boost::shared_ptr<GpuProgram> CreateProgram(const GpuProgramDesc& desc);
    void Draw(const GpuDrawCall& call);
    void Dispatch(const GpuDispatch& dispatch);

    void BeginProfileRegion(std::uint32_t region);
    void EndProfileRegion(std::uint32_t region);
    /** Closes the frame's timestamps (before the swap chain's Present) and collects finished frames. */
    void EndProfileFrame();

  private:
    void UploadConstants(const GpuBindings& bindings);
    void CollectProfileFrames(bool wait);

    struct TimedRegion
    {
      std::uint32_t region = 0U;
      std::uint32_t queryPair = 0U;
    };

    struct ProfileFrame
    {
      Microsoft::WRL::ComPtr<ID3D11Query> disjoint;
      std::vector<Microsoft::WRL::ComPtr<ID3D11Query>> timestamps; // pairs; pair 0 is the frame itself
      std::vector<Microsoft::WRL::ComPtr<ID3D11Query>> statistics; // FAF_GPU_PROFILE_PIXELS: one per pair
      std::vector<TimedRegion> regions;
      std::uint32_t usedPairs = 0U;
      bool open = false;
      bool pending = false;
    };

    static constexpr std::uint32_t kProfileFrames = 4U;
    static constexpr std::uint32_t kMaxTimedRegionsPerFrame = 160U;

    Microsoft::WRL::ComPtr<ID3D11Device> mDevice;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> mImmediate;
    std::uint32_t mFeatures = 0U;
    Microsoft::WRL::ComPtr<ID3D11Buffer> mConstants;
    ProfileFrame mProfileFrames[kProfileFrames];
    std::uint32_t mProfileFrame = 0U;
    std::vector<std::uint32_t> mOpenRegions; // indices into the current frame's `regions`
  };
} // namespace gpg::gal
