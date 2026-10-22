// FAF addition, not in the shipped binary (see GpuDrivenD3D11.h).

#include "GpuDrivenD3D11.h"

#include <algorithm>
#include <cstring>
#include <string>

#include <d3dcompiler.h>

#include "BufferD3D11.h"
#include "D3D11Common.h"
#include "TextureD3D11.h"

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/RenderProfiler.h"

namespace gpg::gal
{
  using Microsoft::WRL::ComPtr;
  using d3d11::CheckHresult;

  namespace
  {
    constexpr UINT kShaderCompileFlags = D3DCOMPILE_ENABLE_STRICTNESS | D3DCOMPILE_OPTIMIZATION_LEVEL3;

    // The registers of the gal binding model (GpuDriven.h).
    constexpr UINT kFirstTextureRegister = kGpuMaxReadBuffers; // t4

    [[nodiscard]] ComPtr<ID3DBlob> CompileStage(
      const GpuProgramDesc& desc, const char* const entry, const char* const profile
    )
    {
      ComPtr<ID3DBlob> code;
      ComPtr<ID3DBlob> errors;
      const HRESULT result = ::D3DCompile(
        desc.source, desc.sourceBytes, desc.name, nullptr, nullptr, entry, profile, kShaderCompileFlags, 0U, &code, &errors
      );
      if (FAILED(result)) {
        std::string message = errors != nullptr
          ? std::string(static_cast<const char*>(errors->GetBufferPointer()), errors->GetBufferSize())
          : std::string("unknown error");
        gpg::Warnf("D3D11: GPU program %s, %s %s does not compile: %s", desc.name, profile, entry, message.c_str());
        return nullptr;
      }
      return code;
    }

    [[nodiscard]] D3D11_COMPARISON_FUNC ToD3D11(const GpuCompare compare) noexcept
    {
      // GpuCompare follows D3D11_COMPARISON_FUNC's order, one below it.
      return static_cast<D3D11_COMPARISON_FUNC>(static_cast<int>(compare) + 1);
    }

    [[nodiscard]] D3D11_STENCIL_OP ToD3D11(const GpuStencilOp op) noexcept
    {
      switch (op) {
      case GpuStencilOp::Zero:
        return D3D11_STENCIL_OP_ZERO;
      case GpuStencilOp::Replace:
        return D3D11_STENCIL_OP_REPLACE;
      case GpuStencilOp::IncrementSaturate:
        return D3D11_STENCIL_OP_INCR_SAT;
      case GpuStencilOp::DecrementSaturate:
        return D3D11_STENCIL_OP_DECR_SAT;
      case GpuStencilOp::Invert:
        return D3D11_STENCIL_OP_INVERT;
      case GpuStencilOp::Increment:
        return D3D11_STENCIL_OP_INCR;
      case GpuStencilOp::Decrement:
        return D3D11_STENCIL_OP_DECR;
      case GpuStencilOp::Keep:
      default:
        return D3D11_STENCIL_OP_KEEP;
      }
    }

    [[nodiscard]] D3D11_DEPTH_STENCILOP_DESC ToD3D11(const GpuStencilFace& face) noexcept
    {
      return D3D11_DEPTH_STENCILOP_DESC{ToD3D11(face.fail), ToD3D11(face.depthFail), ToD3D11(face.pass), ToD3D11(face.func)};
    }

    [[nodiscard]] D3D11_BLEND_DESC BlendDesc(const GpuProgramDesc& desc) noexcept
    {
      D3D11_BLEND_DESC blend{};
      D3D11_RENDER_TARGET_BLEND_DESC& target = blend.RenderTarget[0];
      target.BlendEnable = desc.blend != GpuBlend::Opaque ? TRUE : FALSE;
      target.SrcBlend = desc.blend != GpuBlend::Opaque ? D3D11_BLEND_SRC_ALPHA : D3D11_BLEND_ONE;
      target.DestBlend = desc.blend == GpuBlend::AlphaBlend ? D3D11_BLEND_INV_SRC_ALPHA
        : desc.blend == GpuBlend::Additive                  ? D3D11_BLEND_ONE
                                                             : D3D11_BLEND_ZERO;
      target.BlendOp = D3D11_BLEND_OP_ADD;
      target.SrcBlendAlpha = D3D11_BLEND_ONE;
      target.DestBlendAlpha = D3D11_BLEND_ZERO;
      target.BlendOpAlpha = D3D11_BLEND_OP_ADD;
      target.RenderTargetWriteMask = desc.colorWriteMask;
      return blend;
    }

    /** Every pipeline binding a GPU-driven draw replaces, restored after it. */
    class SavedDrawState
    {
    public:
      explicit SavedDrawState(ID3D11DeviceContext* const context)
        : mContext(context)
      {
        mContext->IAGetInputLayout(&mInputLayout);
        mContext->IAGetIndexBuffer(&mIndexBuffer, &mIndexFormat, &mIndexOffset);
        mContext->IAGetPrimitiveTopology(&mTopology);
        mContext->VSGetShader(&mVertexShader, nullptr, nullptr);
        mContext->PSGetShader(&mPixelShader, nullptr, nullptr);
        mContext->VSGetConstantBuffers(0U, 1U, &mVertexConstants);
        mContext->PSGetConstantBuffers(0U, 1U, &mPixelConstants);
        mContext->VSGetShaderResources(0U, kViews, mVertexViews);
        mContext->PSGetShaderResources(0U, kViews, mPixelViews);
        mContext->PSGetSamplers(0U, 1U, &mSampler);
        mContext->OMGetBlendState(&mBlend, mBlendFactor, &mSampleMask);
        mContext->OMGetDepthStencilState(&mDepthStencil, &mStencilRef);
        mContext->RSGetState(&mRasterizer);
      }

      ~SavedDrawState()
      {
        mContext->IASetInputLayout(mInputLayout.Get());
        mContext->IASetIndexBuffer(mIndexBuffer.Get(), mIndexFormat, mIndexOffset);
        mContext->IASetPrimitiveTopology(mTopology);
        mContext->VSSetShader(mVertexShader.Get(), nullptr, 0U);
        mContext->PSSetShader(mPixelShader.Get(), nullptr, 0U);
        ID3D11Buffer* const vertexConstants = mVertexConstants.Get();
        ID3D11Buffer* const pixelConstants = mPixelConstants.Get();
        mContext->VSSetConstantBuffers(0U, 1U, &vertexConstants);
        mContext->PSSetConstantBuffers(0U, 1U, &pixelConstants);
        mContext->VSSetShaderResources(0U, kViews, mVertexViews);
        mContext->PSSetShaderResources(0U, kViews, mPixelViews);
        // The Get* calls above added a reference to each view they returned.
        for (UINT index = 0U; index < kViews; ++index) {
          if (mVertexViews[index] != nullptr) {
            mVertexViews[index]->Release();
          }
          if (mPixelViews[index] != nullptr) {
            mPixelViews[index]->Release();
          }
        }
        ID3D11SamplerState* const sampler = mSampler.Get();
        mContext->PSSetSamplers(0U, 1U, &sampler);
        mContext->OMSetBlendState(mBlend.Get(), mBlendFactor, mSampleMask);
        mContext->OMSetDepthStencilState(mDepthStencil.Get(), mStencilRef);
        mContext->RSSetState(mRasterizer.Get());
      }

      SavedDrawState(const SavedDrawState&) = delete;
      SavedDrawState& operator=(const SavedDrawState&) = delete;

    private:
      static constexpr UINT kViews = kGpuMaxReadBuffers + kGpuMaxTextures;

      ID3D11DeviceContext* mContext;
      ComPtr<ID3D11InputLayout> mInputLayout;
      ComPtr<ID3D11Buffer> mIndexBuffer;
      DXGI_FORMAT mIndexFormat = DXGI_FORMAT_UNKNOWN;
      UINT mIndexOffset = 0U;
      D3D11_PRIMITIVE_TOPOLOGY mTopology = D3D11_PRIMITIVE_TOPOLOGY_UNDEFINED;
      ComPtr<ID3D11VertexShader> mVertexShader;
      ComPtr<ID3D11PixelShader> mPixelShader;
      ComPtr<ID3D11Buffer> mVertexConstants;
      ComPtr<ID3D11Buffer> mPixelConstants;
      ID3D11ShaderResourceView* mVertexViews[kViews]{};
      ID3D11ShaderResourceView* mPixelViews[kViews]{};
      ComPtr<ID3D11SamplerState> mSampler;
      ComPtr<ID3D11BlendState> mBlend;
      FLOAT mBlendFactor[4]{};
      UINT mSampleMask = 0xFFFFFFFFU;
      ComPtr<ID3D11DepthStencilState> mDepthStencil;
      UINT mStencilRef = 0U;
      ComPtr<ID3D11RasterizerState> mRasterizer;
    };

    /** The t0..t5 views of `bindings`, in register order. */
    void GatherShaderViews(const GpuBindings& bindings, ID3D11ShaderResourceView* (&views)[kGpuMaxReadBuffers + kGpuMaxTextures])
    {
      for (std::uint32_t index = 0U; index < kGpuMaxReadBuffers; ++index) {
        views[index] = bindings.readBuffers[index] != nullptr
          ? static_cast<GpuBufferD3D11*>(bindings.readBuffers[index])->ShaderView()
          : nullptr;
      }
      for (std::uint32_t index = 0U; index < kGpuMaxTextures; ++index) {
        views[kFirstTextureRegister + index] = bindings.textures[index] != nullptr
          ? static_cast<TextureD3D11*>(bindings.textures[index])->GetShaderResourceView()
          : nullptr;
      }
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // GpuBufferD3D11

  GpuBufferD3D11::GpuBufferD3D11(ID3D11Device* const device, const GpuBufferDesc& desc)
    : GpuBuffer(desc)
  {
    const bool indirect = desc.kind == GpuBufferKind::IndirectArgs;
    const UINT stride = indirect ? 16U : std::max(desc.stride, 4U);
    const UINT capacity = std::max(desc.capacity, 1U);
    mDesc.stride = stride;
    mDesc.capacity = capacity;

    D3D11_BUFFER_DESC bufferDesc{};
    bufferDesc.ByteWidth = stride * capacity;
    bufferDesc.Usage = D3D11_USAGE_DEFAULT;
    bufferDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE | (desc.shaderWrite ? D3D11_BIND_UNORDERED_ACCESS : 0U);
    bufferDesc.MiscFlags = indirect ? (D3D11_RESOURCE_MISC_DRAWINDIRECT_ARGS | D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS)
                                    : D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
    bufferDesc.StructureByteStride = indirect ? 0U : stride;
    CheckHresult("GpuDrivenD3D11.cpp", __LINE__, device->CreateBuffer(&bufferDesc, nullptr, &mBuffer));

    D3D11_SHADER_RESOURCE_VIEW_DESC viewDesc{};
    if (indirect) {
      viewDesc.Format = DXGI_FORMAT_R32_TYPELESS;
      viewDesc.ViewDimension = D3D11_SRV_DIMENSION_BUFFEREX;
      viewDesc.BufferEx.FirstElement = 0U;
      viewDesc.BufferEx.NumElements = bufferDesc.ByteWidth / 4U;
      viewDesc.BufferEx.Flags = D3D11_BUFFEREX_SRV_FLAG_RAW;
    } else {
      viewDesc.Format = DXGI_FORMAT_UNKNOWN;
      viewDesc.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
      viewDesc.Buffer.FirstElement = 0U;
      viewDesc.Buffer.NumElements = capacity;
    }
    CheckHresult("GpuDrivenD3D11.cpp", __LINE__, device->CreateShaderResourceView(mBuffer.Get(), &viewDesc, &mShaderView));

    if (desc.shaderWrite) {
      D3D11_UNORDERED_ACCESS_VIEW_DESC writeDesc{};
      writeDesc.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
      writeDesc.Buffer.FirstElement = 0U;
      if (indirect) {
        writeDesc.Format = DXGI_FORMAT_R32_TYPELESS;
        writeDesc.Buffer.NumElements = bufferDesc.ByteWidth / 4U;
        writeDesc.Buffer.Flags = D3D11_BUFFER_UAV_FLAG_RAW;
      } else {
        writeDesc.Format = DXGI_FORMAT_UNKNOWN;
        writeDesc.Buffer.NumElements = capacity;
      }
      CheckHresult("GpuDrivenD3D11.cpp", __LINE__, device->CreateUnorderedAccessView(mBuffer.Get(), &writeDesc, &mWriteView));
    }
  }

  GpuBufferD3D11::~GpuBufferD3D11() = default;

  GpuProgramD3D11::~GpuProgramD3D11() = default;

  // ---------------------------------------------------------------------------
  // GpuDrivenD3D11

  GpuDrivenD3D11::GpuDrivenD3D11(
    ID3D11Device* const device, ID3D11DeviceContext* const immediate, const D3D_FEATURE_LEVEL featureLevel
  )
    : mDevice(device)
    , mImmediate(immediate)
  {
    // Structured buffers in every stage, vs/ps/cs_5_0 and indirect draws are
    // all guaranteed from feature level 11_0 on; below it the engine keeps its
    // original paths.
    if (featureLevel >= D3D_FEATURE_LEVEL_11_0) {
      mFeatures = kGpuFeatureVertexPulling | kGpuFeatureCompute | kGpuFeatureIndirectDraw;
    }
    mFeatures |= kGpuFeatureTimestamps;

    D3D11_BUFFER_DESC constantsDesc{};
    constantsDesc.ByteWidth = kGpuMaxConstantBytes;
    constantsDesc.Usage = D3D11_USAGE_DYNAMIC;
    constantsDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    constantsDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    CheckHresult("GpuDrivenD3D11.cpp", __LINE__, mDevice->CreateBuffer(&constantsDesc, nullptr, &mConstants));
  }

  GpuDrivenD3D11::~GpuDrivenD3D11() = default;

  boost::shared_ptr<GpuBuffer> GpuDrivenD3D11::CreateBuffer(const GpuBufferDesc& desc)
  {
    if ((mFeatures & kGpuFeatureVertexPulling) == 0U) {
      return {};
    }
    return boost::shared_ptr<GpuBuffer>(new GpuBufferD3D11(mDevice.Get(), desc));
  }

  void GpuDrivenD3D11::UpdateBuffer(GpuBuffer& buffer, const std::uint32_t firstElement, const std::uint32_t count, const void* const data)
  {
    const GpuBufferDesc& desc = buffer.Desc();
    if (count == 0U || firstElement >= desc.capacity) {
      return;
    }
    const std::uint32_t elements = std::min(count, desc.capacity - firstElement);
    D3D11_BOX box{};
    box.left = firstElement * desc.stride;
    box.right = (firstElement + elements) * desc.stride;
    box.top = 0U;
    box.bottom = 1U;
    box.front = 0U;
    box.back = 1U;
    mImmediate->UpdateSubresource(static_cast<GpuBufferD3D11&>(buffer).Buffer(), 0U, &box, data, 0U, 0U);
    RecordUpload(box.right - box.left);
  }

  bool GpuDrivenD3D11::ReadBuffer(GpuBuffer& buffer, const std::uint32_t firstElement, const std::uint32_t count, void* const out)
  {
    const GpuBufferDesc& desc = buffer.Desc();
    if (count == 0U || out == nullptr || firstElement >= desc.capacity || count > desc.capacity - firstElement) {
      return false;
    }
    const UINT bytes = count * desc.stride;
    D3D11_BUFFER_DESC stagingDesc{};
    stagingDesc.ByteWidth = bytes;
    stagingDesc.Usage = D3D11_USAGE_STAGING;
    stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    ComPtr<ID3D11Buffer> staging;
    if (FAILED(mDevice->CreateBuffer(&stagingDesc, nullptr, &staging))) {
      return false;
    }
    D3D11_BOX box{};
    box.left = firstElement * desc.stride;
    box.right = box.left + bytes;
    box.bottom = 1U;
    box.back = 1U;
    mImmediate->CopySubresourceRegion(staging.Get(), 0U, 0U, 0U, 0U, static_cast<GpuBufferD3D11&>(buffer).Buffer(), 0U, &box);
    D3D11_MAPPED_SUBRESOURCE mapped{};
    if (FAILED(mImmediate->Map(staging.Get(), 0U, D3D11_MAP_READ, 0U, &mapped))) {
      return false;
    }
    std::memcpy(out, mapped.pData, bytes);
    mImmediate->Unmap(staging.Get(), 0U);
    return true;
  }

  boost::shared_ptr<GpuProgram> GpuDrivenD3D11::CreateProgram(const GpuProgramDesc& desc)
  {
    if ((mFeatures & kGpuFeatureVertexPulling) == 0U || desc.source == nullptr) {
      return {};
    }

    boost::shared_ptr<GpuProgramD3D11> program(new GpuProgramD3D11());
    if (desc.computeEntry != nullptr) {
      const ComPtr<ID3DBlob> code = CompileStage(desc, desc.computeEntry, "cs_5_0");
      if (code == nullptr ||
          FAILED(mDevice->CreateComputeShader(code->GetBufferPointer(), code->GetBufferSize(), nullptr, &program->mComputeShader))) {
        return {};
      }
      return program;
    }

    if (desc.vertexEntry == nullptr || desc.pixelEntry == nullptr) {
      return {};
    }
    const ComPtr<ID3DBlob> vertexCode = CompileStage(desc, desc.vertexEntry, "vs_5_0");
    const ComPtr<ID3DBlob> pixelCode = CompileStage(desc, desc.pixelEntry, "ps_5_0");
    if (vertexCode == nullptr || pixelCode == nullptr ||
        FAILED(mDevice->CreateVertexShader(vertexCode->GetBufferPointer(), vertexCode->GetBufferSize(), nullptr, &program->mVertexShader)) ||
        FAILED(mDevice->CreatePixelShader(pixelCode->GetBufferPointer(), pixelCode->GetBufferSize(), nullptr, &program->mPixelShader))) {
      return {};
    }

    const D3D11_BLEND_DESC blend = BlendDesc(desc);
    CheckHresult("GpuDrivenD3D11.cpp", __LINE__, mDevice->CreateBlendState(&blend, &program->mBlend));

    D3D11_DEPTH_STENCIL_DESC depth{};
    depth.DepthEnable = desc.depthTest ? TRUE : FALSE;
    depth.DepthWriteMask = desc.depthWrite ? D3D11_DEPTH_WRITE_MASK_ALL : D3D11_DEPTH_WRITE_MASK_ZERO;
    depth.DepthFunc = ToD3D11(desc.depthFunc);
    depth.StencilEnable = desc.stencil.enable ? TRUE : FALSE;
    depth.StencilReadMask = desc.stencil.readMask;
    depth.StencilWriteMask = desc.stencil.writeMask;
    depth.FrontFace = ToD3D11(desc.stencil.front);
    depth.BackFace = ToD3D11(desc.stencil.back);
    program->mStencilReference = desc.stencil.reference;
    program->mInheritDepthStencil = desc.inheritDepthStencil;
    CheckHresult("GpuDrivenD3D11.cpp", __LINE__, mDevice->CreateDepthStencilState(&depth, &program->mDepthStencil));

    // Solid fill, no scissor; depth clipping as the program asks (D3D9 clips).
    D3D11_RASTERIZER_DESC rasterizer{};
    rasterizer.FillMode = D3D11_FILL_SOLID;
    rasterizer.CullMode = desc.cullBackFaces ? D3D11_CULL_BACK : D3D11_CULL_NONE;
    rasterizer.FrontCounterClockwise = FALSE;
    rasterizer.DepthClipEnable = desc.depthClip ? TRUE : FALSE;
    rasterizer.ScissorEnable = FALSE;
    rasterizer.MultisampleEnable = TRUE;
    CheckHresult("GpuDrivenD3D11.cpp", __LINE__, mDevice->CreateRasterizerState(&rasterizer, &program->mRasterizer));

    D3D11_SAMPLER_DESC sampler{};
    sampler.Filter = desc.sampler == GpuSampler::PointClamp ? D3D11_FILTER_MIN_MAG_MIP_POINT : D3D11_FILTER_MIN_MAG_MIP_LINEAR;
    const D3D11_TEXTURE_ADDRESS_MODE address =
      desc.sampler == GpuSampler::LinearWrap ? D3D11_TEXTURE_ADDRESS_WRAP : D3D11_TEXTURE_ADDRESS_CLAMP;
    sampler.AddressU = address;
    sampler.AddressV = address;
    sampler.AddressW = address;
    sampler.MaxAnisotropy = 1U;
    sampler.ComparisonFunc = D3D11_COMPARISON_NEVER;
    sampler.MinLOD = 0.0f;
    sampler.MaxLOD = D3D11_FLOAT32_MAX;
    CheckHresult("GpuDrivenD3D11.cpp", __LINE__, mDevice->CreateSamplerState(&sampler, &program->mSampler));
    return program;
  }

  void GpuDrivenD3D11::UploadConstants(const GpuBindings& bindings)
  {
    if (bindings.constants == nullptr || bindings.constantBytes == 0U) {
      return;
    }
    D3D11_MAPPED_SUBRESOURCE mapped{};
    CheckHresult("GpuDrivenD3D11.cpp", __LINE__, mImmediate->Map(mConstants.Get(), 0U, D3D11_MAP_WRITE_DISCARD, 0U, &mapped));
    std::memcpy(mapped.pData, bindings.constants, std::min(bindings.constantBytes, kGpuMaxConstantBytes));
    mImmediate->Unmap(mConstants.Get(), 0U);
    RecordUpload(bindings.constantBytes);
  }

  void GpuDrivenD3D11::Draw(const GpuDrawCall& call)
  {
    auto* const program = static_cast<GpuProgramD3D11*>(call.program);
    if (program == nullptr || program->mVertexShader == nullptr) {
      return;
    }
    if (call.indirectArgs == nullptr && (call.vertexCountPerInstance == 0U || call.instanceCount == 0U)) {
      return;
    }

    const SavedDrawState saved(mImmediate.Get());
    UploadConstants(call.bindings);

    ID3D11ShaderResourceView* views[kGpuMaxReadBuffers + kGpuMaxTextures];
    GatherShaderViews(call.bindings, views);
    ID3D11Buffer* const constants = mConstants.Get();
    ID3D11SamplerState* const sampler = program->mSampler.Get();

    mImmediate->IASetInputLayout(nullptr);
    mImmediate->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    mImmediate->VSSetShader(program->mVertexShader.Get(), nullptr, 0U);
    mImmediate->PSSetShader(program->mPixelShader.Get(), nullptr, 0U);
    mImmediate->VSSetConstantBuffers(0U, 1U, &constants);
    mImmediate->PSSetConstantBuffers(0U, 1U, &constants);
    mImmediate->VSSetShaderResources(0U, static_cast<UINT>(std::size(views)), views);
    mImmediate->PSSetShaderResources(0U, static_cast<UINT>(std::size(views)), views);
    mImmediate->PSSetSamplers(0U, 1U, &sampler);
    mImmediate->OMSetBlendState(program->mBlend.Get(), nullptr, 0xFFFFFFFFU);
    if (!program->mInheritDepthStencil) {
      mImmediate->OMSetDepthStencilState(program->mDepthStencil.Get(), program->mStencilReference);
    }
    mImmediate->RSSetState(program->mRasterizer.Get());
    RecordStateChange();

    if (call.indexBuffer != nullptr) {
      auto* const indices = static_cast<IndexBufferD3D11*>(call.indexBuffer);
      mImmediate->IASetIndexBuffer(indices->GetBuffer(), indices->GetIndexFormat(), 0U);
      mImmediate->DrawIndexedInstanced(call.vertexCountPerInstance, call.instanceCount, 0U, 0, call.firstInstance);
      RecordDraw((call.vertexCountPerInstance / 3U) * call.instanceCount, call.vertexCountPerInstance * call.instanceCount);
    } else if (call.indirectArgs != nullptr) {
      mImmediate->DrawInstancedIndirect(static_cast<GpuBufferD3D11*>(call.indirectArgs)->Buffer(), call.indirectArgsOffset);
      RecordDraw(0U, 0U);
    } else {
      mImmediate->DrawInstanced(call.vertexCountPerInstance, call.instanceCount, 0U, call.firstInstance);
      RecordDraw((call.vertexCountPerInstance / 3U) * call.instanceCount, call.vertexCountPerInstance * call.instanceCount);
    }
  }

  void GpuDrivenD3D11::Dispatch(const GpuDispatch& dispatch)
  {
    auto* const program = static_cast<GpuProgramD3D11*>(dispatch.program);
    if (program == nullptr || program->mComputeShader == nullptr) {
      return;
    }

    UploadConstants(dispatch.bindings);
    ID3D11ShaderResourceView* views[kGpuMaxReadBuffers + kGpuMaxTextures];
    GatherShaderViews(dispatch.bindings, views);
    ID3D11UnorderedAccessView* writeViews[kGpuMaxWriteBuffers]{};
    for (std::uint32_t index = 0U; index < kGpuMaxWriteBuffers; ++index) {
      if (dispatch.bindings.writeBuffers[index] != nullptr) {
        writeViews[index] = static_cast<GpuBufferD3D11*>(dispatch.bindings.writeBuffers[index])->WriteView();
      }
    }
    ID3D11Buffer* const constants = mConstants.Get();

    mImmediate->CSSetShader(program->mComputeShader.Get(), nullptr, 0U);
    mImmediate->CSSetConstantBuffers(0U, 1U, &constants);
    mImmediate->CSSetShaderResources(0U, static_cast<UINT>(std::size(views)), views);
    mImmediate->CSSetUnorderedAccessViews(0U, kGpuMaxWriteBuffers, writeViews, nullptr);
    mImmediate->Dispatch(dispatch.groupsX, dispatch.groupsY, dispatch.groupsZ);
    RecordStateChange();

    // Unbind, so the written buffers can be read by the draws that follow.
    ID3D11ShaderResourceView* const noViews[kGpuMaxReadBuffers + kGpuMaxTextures]{};
    ID3D11UnorderedAccessView* const noWriteViews[kGpuMaxWriteBuffers]{};
    mImmediate->CSSetShaderResources(0U, static_cast<UINT>(std::size(noViews)), noViews);
    mImmediate->CSSetUnorderedAccessViews(0U, kGpuMaxWriteBuffers, noWriteViews, nullptr);
    mImmediate->CSSetShader(nullptr, nullptr, 0U);
  }

  // ---------------------------------------------------------------------------
  // Timestamps

  void GpuDrivenD3D11::BeginProfileRegion(const std::uint32_t region)
  {
    ProfileFrame& frame = mProfileFrames[mProfileFrame];
    if (frame.pending) {
      // The GPU is more than kProfileFrames frames behind: this slot's
      // results are still out, so this frame goes unmeasured.
      return;
    }
    if (!frame.open) {
      if (frame.disjoint == nullptr) {
        D3D11_QUERY_DESC disjointDesc{D3D11_QUERY_TIMESTAMP_DISJOINT, 0U};
        if (FAILED(mDevice->CreateQuery(&disjointDesc, &frame.disjoint))) {
          return;
        }
        frame.timestamps.resize(2U * (kMaxTimedRegionsPerFrame + 1U));
        D3D11_QUERY_DESC timestampDesc{D3D11_QUERY_TIMESTAMP, 0U};
        for (ComPtr<ID3D11Query>& query : frame.timestamps) {
          if (FAILED(mDevice->CreateQuery(&timestampDesc, &query))) {
            frame.disjoint.Reset();
            return;
          }
        }
        if (RenderProfiler::PixelStatisticsEnabled()) {
          frame.statistics.resize(kMaxTimedRegionsPerFrame + 1U);
          D3D11_QUERY_DESC statisticsDesc{D3D11_QUERY_PIPELINE_STATISTICS, 0U};
          for (ComPtr<ID3D11Query>& query : frame.statistics) {
            if (FAILED(mDevice->CreateQuery(&statisticsDesc, &query))) {
              frame.statistics.clear();
              break;
            }
          }
        }
      }
      frame.open = true;
      frame.usedPairs = 1U;
      frame.regions.clear();
      mOpenRegions.clear();
      mImmediate->Begin(frame.disjoint.Get());
      mImmediate->End(frame.timestamps[0].Get());
    }
    if (frame.usedPairs > kMaxTimedRegionsPerFrame) {
      mOpenRegions.push_back(0xFFFFFFFFU);
      return;
    }
    const std::uint32_t pair = frame.usedPairs++;
    mImmediate->End(frame.timestamps[2U * pair].Get());
    if (pair < frame.statistics.size()) {
      mImmediate->Begin(frame.statistics[pair].Get());
    }
    mOpenRegions.push_back(static_cast<std::uint32_t>(frame.regions.size()));
    frame.regions.push_back(TimedRegion{region, pair});
  }

  void GpuDrivenD3D11::EndProfileRegion(const std::uint32_t region)
  {
    static_cast<void>(region);
    ProfileFrame& frame = mProfileFrames[mProfileFrame];
    if (!frame.open || mOpenRegions.empty()) {
      return;
    }
    const std::uint32_t timed = mOpenRegions.back();
    mOpenRegions.pop_back();
    if (timed != 0xFFFFFFFFU) {
      const std::uint32_t pair = frame.regions[timed].queryPair;
      mImmediate->End(frame.timestamps[2U * pair + 1U].Get());
      if (pair < frame.statistics.size()) {
        mImmediate->End(frame.statistics[pair].Get());
      }
    }
  }

  void GpuDrivenD3D11::EndProfileFrame()
  {
    ProfileFrame& frame = mProfileFrames[mProfileFrame];
    if (frame.open) {
      mImmediate->End(frame.timestamps[1].Get());
      mImmediate->End(frame.disjoint.Get());
      frame.open = false;
      frame.pending = true;
      mOpenRegions.clear();
      mProfileFrame = (mProfileFrame + 1U) % kProfileFrames;
    }
    CollectProfileFrames(false);
  }

  void GpuDrivenD3D11::CollectProfileFrames(const bool wait)
  {
    RenderProfiler& profiler = RenderProfiler::Get();
    for (std::uint32_t age = 0U; age < kProfileFrames; ++age) {
      ProfileFrame& frame = mProfileFrames[(mProfileFrame + age) % kProfileFrames];
      if (!frame.pending) {
        continue;
      }
      D3D11_QUERY_DATA_TIMESTAMP_DISJOINT disjoint{};
      const UINT flags = wait ? 0U : D3D11_ASYNC_GETDATA_DONOTFLUSH;
      if (mImmediate->GetData(frame.disjoint.Get(), &disjoint, sizeof(disjoint), flags) != S_OK) {
        continue;
      }
      frame.pending = false;
      if (disjoint.Disjoint || disjoint.Frequency == 0U) {
        continue;
      }
      const double toMilliseconds = 1000.0 / static_cast<double>(disjoint.Frequency);
      const auto read = [&](ID3D11Query* const query, UINT64& value) {
        return mImmediate->GetData(query, &value, sizeof(value), flags) == S_OK;
      };
      UINT64 frameBegin = 0U;
      UINT64 frameEnd = 0U;
      if (read(frame.timestamps[0].Get(), frameBegin) && read(frame.timestamps[1].Get(), frameEnd) && frameEnd >= frameBegin) {
        profiler.AddGpuFrameTime(static_cast<double>(frameEnd - frameBegin) * toMilliseconds);
      }
      for (const TimedRegion& timed : frame.regions) {
        UINT64 begin = 0U;
        UINT64 end = 0U;
        if (read(frame.timestamps[2U * timed.queryPair].Get(), begin) &&
            read(frame.timestamps[2U * timed.queryPair + 1U].Get(), end) && end >= begin) {
          profiler.AddGpuTime(timed.region, static_cast<double>(end - begin) * toMilliseconds);
        }
        D3D11_QUERY_DATA_PIPELINE_STATISTICS statistics{};
        if (timed.queryPair < frame.statistics.size() &&
            mImmediate->GetData(frame.statistics[timed.queryPair].Get(), &statistics, sizeof(statistics), flags) == S_OK) {
          profiler.AddGpuPipelineStatistics(timed.region, statistics.PSInvocations, statistics.CPrimitives);
        }
      }
    }
  }
} // namespace gpg::gal
