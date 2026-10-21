// FAF addition, not in the shipped binary: textures, targets, buffers, vertex
// formats, pipeline state and cursor of the Direct3D 11 gal backend.

#include <algorithm>
#include <cstring>

#include "BufferD3D11.h"
#include "D3D11Common.h"
#include "D3D11VertexLayouts.h"
#include "DeviceD3D11.h"
#include "PipelineStateD3D11.h"
#include "RenderTargetD3D11.h"
#include "TextureD3D11.h"

#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/Device.hpp"

namespace gpg::gal
{
  using Microsoft::WRL::ComPtr;
  using d3d11::CheckHresult;
  using d3d11::ThrowError;

  namespace
  {
    [[nodiscard]] DeviceD3D11& ActiveDevice()
    {
      return *static_cast<DeviceD3D11*>(Device::GetInstance());
    }

    [[nodiscard]] bool HasFlag(const int flags, const MohoD3DLockFlags flag) noexcept
    {
      return (static_cast<std::uint32_t>(flags) & static_cast<std::uint32_t>(flag)) != 0U;
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // TextureD3D11

  TextureD3D11::TextureD3D11(
    const TextureContext& context,
    ID3D11Device* const device,
    ID3D11DeviceContext* const immediate,
    ID3D11Resource* const resource,
    ID3D11ShaderResourceView* const shaderResourceView,
    const bool contentsFromEngine
  )
    : mContext(context)
    , mDevice(device)
    , mImmediate(immediate)
    , mResource(resource)
    , mShaderResourceView(shaderResourceView)
    , mContentsFromEngine(contentsFromEngine)
  {
    // The context keeps no file data once the texture exists (D3D10 clears
    // it too, `TextureD3D10::InitializeState`).
    mContext.ClearDataBuffer();

    if (mResource != nullptr && SUCCEEDED(mResource.As(&mTexture2D))) {
      mTexture2D->GetDesc(&mDesc);
      mContext.width_ = mDesc.Width;
      mContext.height_ = mDesc.Height;
      mContext.mipmapLevels_ = mDesc.MipLevels;
      mContext.format_ = d3d11::DxgiToTextureFormat(mDesc.Format);
      mContext.type_ = (mDesc.MiscFlags & D3D11_RESOURCE_MISC_TEXTURECUBE) != 0U ? 2U : 1U;
    } else {
      // A volume texture: sampled through its view, never locked.
      mContext.type_ = 3U;
      mContext.mipmapLevels_ = 1U;
    }
    mLevels.resize(mContext.mipmapLevels_);
  }

  TextureD3D11::~TextureD3D11() = default;

  TextureContext* TextureD3D11::GetContext()
  {
    return &mContext;
  }

  void TextureD3D11::ReadBackLevel(const std::uint32_t level)
  {
    D3D11_TEXTURE2D_DESC stagingDesc = mDesc;
    stagingDesc.Usage = D3D11_USAGE_STAGING;
    stagingDesc.BindFlags = 0U;
    stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    stagingDesc.MiscFlags = 0U;
    stagingDesc.ArraySize = 1U;

    ComPtr<ID3D11Texture2D> staging;
    CheckHresult("TextureD3D11.cpp", __LINE__, mDevice->CreateTexture2D(&stagingDesc, nullptr, &staging));

    const UINT subresource = D3D11CalcSubresource(level, 0U, mDesc.MipLevels);
    mImmediate->CopySubresourceRegion(staging.Get(), subresource, 0U, 0U, 0U, mTexture2D.Get(), subresource, nullptr);

    D3D11_MAPPED_SUBRESOURCE mapped{};
    CheckHresult("TextureD3D11.cpp", __LINE__, mImmediate->Map(staging.Get(), subresource, D3D11_MAP_READ, 0U, &mapped));

    const d3d11::LevelLayout layout = d3d11::ComputeLevelLayout(
      mDesc.Format, std::max(1U, mDesc.Width >> level), std::max(1U, mDesc.Height >> level)
    );
    std::vector<std::uint8_t>& bytes = mLevels[level];
    bytes.resize(layout.ByteSize());
    const auto* const source = static_cast<const std::uint8_t*>(mapped.pData);
    for (std::uint32_t row = 0U; row < layout.rowCount; ++row) {
      std::memcpy(bytes.data() + static_cast<std::size_t>(row) * layout.rowPitch,
                  source + static_cast<std::size_t>(row) * mapped.RowPitch,
                  layout.rowPitch);
    }
    mImmediate->Unmap(staging.Get(), subresource);
  }

  TextureLockRect TextureD3D11::Lock(const int level, const RECT& rect, const int flags)
  {
    if (mTexture2D == nullptr) {
      ThrowError("TextureD3D11.cpp", __LINE__, "attempt to map invalid texture");
    }
    if (level < 0 || level >= static_cast<int>(mDesc.MipLevels)) {
      ThrowError("TextureD3D11.cpp", __LINE__, "attempt to map invalid texture level");
    }
    if (mLocked) {
      ThrowError("TextureD3D11.cpp", __LINE__, "texture map/unmap mismatch");
    }

    const std::uint32_t levelIndex = static_cast<std::uint32_t>(level);
    const std::uint32_t width = std::max(1U, mDesc.Width >> levelIndex);
    const std::uint32_t height = std::max(1U, mDesc.Height >> levelIndex);
    const d3d11::LevelLayout layout = d3d11::ComputeLevelLayout(mDesc.Format, width, height);

    std::vector<std::uint8_t>& bytes = mLevels[levelIndex];
    if (bytes.size() != layout.ByteSize()) {
      if (mContentsFromEngine || HasFlag(flags, MohoD3DLockFlags::Discard)) {
        bytes.assign(layout.ByteSize(), 0U);
      } else {
        ReadBackLevel(levelIndex);
      }
    }

    // An empty rect locks the whole level, as TextureD3D9::Lock.
    std::size_t offset = 0U;
    if (rect.left != rect.right) {
      const std::uint32_t elementBytes = d3d11::FormatElementBytes(mDesc.Format);
      if (d3d11::IsBlockCompressed(mDesc.Format)) {
        offset = static_cast<std::size_t>(rect.top / 4) * layout.rowPitch + static_cast<std::size_t>(rect.left / 4) * elementBytes;
      } else {
        offset = static_cast<std::size_t>(rect.top) * layout.rowPitch + static_cast<std::size_t>(rect.left) * elementBytes;
      }
    }

    mLocked = true;
    mLockedLevel = level;
    mLockedFlags = flags;

    TextureLockRect lock{};
    lock.flags = flags;
    lock.level = level;
    lock.pitch = static_cast<int>(layout.rowPitch);
    lock.bits = bytes.data() + offset;
    return lock;
  }

  int TextureD3D11::Unlock(const TextureLockRect lock)
  {
    return Unlock(lock.level);
  }

  int TextureD3D11::Unlock(const int level)
  {
    if (!mLocked || level != mLockedLevel) {
      ThrowError("TextureD3D11.cpp", __LINE__, "texture lock/unlock mismatch");
    }

    const std::uint32_t levelIndex = static_cast<std::uint32_t>(level);
    std::vector<std::uint8_t>& bytes = mLevels[levelIndex];
    if (!HasFlag(mLockedFlags, MohoD3DLockFlags::ReadOnly)) {
      const d3d11::LevelLayout layout = d3d11::ComputeLevelLayout(
        mDesc.Format, std::max(1U, mDesc.Width >> levelIndex), std::max(1U, mDesc.Height >> levelIndex)
      );
      mImmediate->UpdateSubresource(
        mTexture2D.Get(), D3D11CalcSubresource(levelIndex, 0U, mDesc.MipLevels), nullptr, bytes.data(), layout.rowPitch, 0U
      );
    } else if (!mContentsFromEngine) {
      // A read of a file texture (the cursor icon): the GPU copy stays the
      // authority, so drop the CPU one.
      std::vector<std::uint8_t>().swap(bytes);
    }

    mLocked = false;
    mLockedLevel = 0;
    mLockedFlags = 0;
    return 0;
  }

  void TextureD3D11::SaveToBuffer(gpg::MemBuffer<char>* const outBuffer)
  {
    if (mResource == nullptr) {
      ThrowError("TextureD3D11.cpp", __LINE__, "attempt to save invalid texture");
    }

    ComPtr<ID3D10Blob> encoded;
    constexpr int kDds = 4; // D3DX11_IFF_DDS
    CheckHresult("TextureD3D11.cpp", __LINE__, ActiveDevice().EncodeTexture(mResource.Get(), kDds, &encoded));

    const std::size_t encodedSize = encoded->GetBufferSize();
    if (outBuffer->Size() != encodedSize) {
      *outBuffer = gpg::AllocMemBuffer(encodedSize);
    }
    std::copy_n(static_cast<const char*>(encoded->GetBufferPointer()), encodedSize, outBuffer->GetPtr(0U, 0U));
  }

  void TextureD3D11::DiscardCpuCopy() noexcept
  {
    for (std::vector<std::uint8_t>& level : mLevels) {
      std::vector<std::uint8_t>().swap(level);
    }
    mContentsFromEngine = false;
  }

  ID3D11ShaderResourceView* TextureD3D11::GetShaderResourceView() const
  {
    if (mShaderResourceView == nullptr) {
      ThrowError("TextureD3D11.cpp", __LINE__, "invalid shader resource view");
    }
    return mShaderResourceView.Get();
  }

  ID3D11Texture2D* TextureD3D11::GetTexture2D() const
  {
    if (mTexture2D == nullptr) {
      ThrowError("TextureD3D11.cpp", __LINE__, "invalid texture");
    }
    return mTexture2D.Get();
  }

  // ---------------------------------------------------------------------------
  // RenderTargetD3D11 / DepthStencilTargetD3D11 / CubeRenderTargetD3D11

  RenderTargetD3D11::RenderTargetD3D11(
    ID3D11Texture2D* const texture,
    ID3D11RenderTargetView* const renderTargetView,
    ID3D11ShaderResourceView* const shaderResourceView
  )
    : mTexture(texture)
    , mRenderTargetView(renderTargetView)
    , mShaderResourceView(shaderResourceView)
  {
    D3D11_TEXTURE2D_DESC desc{};
    texture->GetDesc(&desc);
    mContext.width_ = desc.Width;
    mContext.height_ = desc.Height;
    mContext.format_ = d3d11::DxgiToRenderTargetFormat(desc.Format);
  }

  RenderTargetD3D11::~RenderTargetD3D11() = default;

  RenderTargetContext* RenderTargetD3D11::GetContext()
  {
    return &mContext;
  }

  HDC RenderTargetD3D11::GetDC()
  {
    return nullptr;
  }

  ID3D11Texture2D* RenderTargetD3D11::GetTexture() const
  {
    if (mTexture == nullptr) {
      ThrowError("RenderTargetD3D11.cpp", __LINE__, "invalid render target");
    }
    return mTexture.Get();
  }

  ID3D11RenderTargetView* RenderTargetD3D11::GetRenderTargetView() const
  {
    if (mRenderTargetView == nullptr) {
      ThrowError("RenderTargetD3D11.cpp", __LINE__, "invalid render target view");
    }
    return mRenderTargetView.Get();
  }

  ID3D11ShaderResourceView* RenderTargetD3D11::GetShaderResourceView() const
  {
    if (mShaderResourceView == nullptr) {
      ThrowError("RenderTargetD3D11.cpp", __LINE__, "invalid shader resource view");
    }
    return mShaderResourceView.Get();
  }

  DepthStencilTargetD3D11::DepthStencilTargetD3D11(
    const DepthStencilTargetContext& context,
    ID3D11Texture2D* const texture,
    ID3D11DepthStencilView* const depthStencilView,
    ID3D11ShaderResourceView* const shaderResourceView
  )
    : mContext(context)
    , mTexture(texture)
    , mDepthStencilView(depthStencilView)
    , mShaderResourceView(shaderResourceView)
  {}

  DepthStencilTargetD3D11::~DepthStencilTargetD3D11() = default;

  DepthStencilTargetContext* DepthStencilTargetD3D11::GetContext()
  {
    return &mContext;
  }

  ID3D11DepthStencilView* DepthStencilTargetD3D11::GetDepthStencilView() const
  {
    if (mDepthStencilView == nullptr) {
      ThrowError("DepthStencilTargetD3D11.cpp", __LINE__, "invalid depth stencil view");
    }
    return mDepthStencilView.Get();
  }

  ID3D11ShaderResourceView* DepthStencilTargetD3D11::GetShaderResourceView() const
  {
    if (mShaderResourceView == nullptr) {
      ThrowError("DepthStencilTargetD3D11.cpp", __LINE__, "invalid shader resource view");
    }
    return mShaderResourceView.Get();
  }

  CubeRenderTargetD3D11::CubeRenderTargetD3D11(const CubeRenderTargetContext& context)
    : mContext(context)
  {}

  CubeRenderTargetD3D11::~CubeRenderTargetD3D11() = default;

  CubeRenderTargetContext* CubeRenderTargetD3D11::GetContext()
  {
    return &mContext;
  }

  // ---------------------------------------------------------------------------
  // Buffers

  BufferStorageD3D11::BufferStorageD3D11(
    ID3D11Device* const device,
    ID3D11DeviceContext* const immediate,
    const std::uint32_t byteWidth,
    const UINT bindFlags,
    const bool dynamic,
    const char* const kind
  )
    : mImmediate(immediate)
    , mByteWidth(std::max(byteWidth, 4U))
    , mKind(kind)
    , mDynamic(dynamic)
  {
    D3D11_BUFFER_DESC desc{};
    desc.ByteWidth = mByteWidth;
    desc.Usage = dynamic ? D3D11_USAGE_DYNAMIC : D3D11_USAGE_DEFAULT;
    desc.BindFlags = bindFlags;
    desc.CPUAccessFlags = dynamic ? D3D11_CPU_ACCESS_WRITE : 0U;
    CheckHresult(kind, __LINE__, device->CreateBuffer(&desc, nullptr, &mBuffer));

    if (!dynamic) {
      mShadow.assign(mByteWidth, 0U);
    }
  }

  std::uint8_t* BufferStorageD3D11::Lock(const std::uint32_t offset, const std::uint32_t size, const MohoD3DLockFlags flags)
  {
    if (mLocked) {
      ThrowError(mKind, __LINE__, "buffer lock/unlock mismatch");
    }
    if (offset >= mByteWidth) {
      ThrowError(mKind, __LINE__, "buffer lock offset out of range");
    }

    mLockOffset = offset;
    mLockSize = (size == 0U || offset + size > mByteWidth) ? (mByteWidth - offset) : size;
    const auto rawFlags = static_cast<std::uint32_t>(flags);
    mLockWrites = (rawFlags & static_cast<std::uint32_t>(MohoD3DLockFlags::ReadOnly)) == 0U;

    std::uint8_t* data = nullptr;
    if (mDynamic) {
      D3D11_MAP mapType = D3D11_MAP_WRITE_NO_OVERWRITE;
      if ((rawFlags & static_cast<std::uint32_t>(MohoD3DLockFlags::Discard)) != 0U) {
        mapType = D3D11_MAP_WRITE_DISCARD;
      } else if ((rawFlags & static_cast<std::uint32_t>(MohoD3DLockFlags::NoOverwrite)) == 0U && offset == 0U) {
        // A plain lock from the start: everything after it is being
        // rewritten too, which is what DISCARD promises.
        mapType = D3D11_MAP_WRITE_DISCARD;
      }

      D3D11_MAPPED_SUBRESOURCE mapped{};
      CheckHresult(mKind, __LINE__, mImmediate->Map(mBuffer.Get(), 0U, mapType, 0U, &mapped));
      data = static_cast<std::uint8_t*>(mapped.pData) + offset;
    } else {
      data = mShadow.data() + offset;
    }

    mLocked = true;
    return data;
  }

  void BufferStorageD3D11::Unlock()
  {
    if (!mLocked) {
      ThrowError(mKind, __LINE__, "buffer lock/unlock mismatch");
    }

    if (mDynamic) {
      mImmediate->Unmap(mBuffer.Get(), 0U);
    } else if (mLockWrites && mLockSize != 0U) {
      D3D11_BOX box{};
      box.left = mLockOffset;
      box.right = mLockOffset + mLockSize;
      box.top = 0U;
      box.bottom = 1U;
      box.front = 0U;
      box.back = 1U;
      mImmediate->UpdateSubresource(mBuffer.Get(), 0U, &box, mShadow.data() + mLockOffset, 0U, 0U);
    }

    mLocked = false;
  }

  VertexBufferD3D11::VertexBufferD3D11(
    const VertexBufferContext& context, ID3D11Device* const device, ID3D11DeviceContext* const immediate
  )
    : mContext(context)
    , mStorage(
        device,
        immediate,
        context.vertexCount_ * context.stride_,
        D3D11_BIND_VERTEX_BUFFER,
        context.usage_ == 2U,
        "VertexBufferD3D11.cpp"
      )
  {}

  VertexBufferD3D11::~VertexBufferD3D11() = default;

  VertexBufferContext* VertexBufferD3D11::GetContext()
  {
    return &mContext;
  }

  void* VertexBufferD3D11::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    return mStorage.Lock(offset, size, lockFlags);
  }

  void VertexBufferD3D11::Unlock()
  {
    mStorage.Unlock();
  }

  IndexBufferD3D11::IndexBufferD3D11(
    const IndexBufferContext& context, ID3D11Device* const device, ID3D11DeviceContext* const immediate
  )
    : mContext(context)
    , mStorage(
        device,
        immediate,
        context.size_ * ((context.format_ == 1U) ? 2U : 4U),
        D3D11_BIND_INDEX_BUFFER,
        context.type_ == 2U,
        "IndexBufferD3D11.cpp"
      )
  {}

  IndexBufferD3D11::~IndexBufferD3D11() = default;

  IndexBufferContext* IndexBufferD3D11::GetContext()
  {
    return &mContext;
  }

  std::int16_t* IndexBufferD3D11::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    return reinterpret_cast<std::int16_t*>(mStorage.Lock(offset, size, lockFlags));
  }

  void IndexBufferD3D11::Unlock()
  {
    mStorage.Unlock();
  }

  DXGI_FORMAT IndexBufferD3D11::GetIndexFormat() const noexcept
  {
    return (mContext.format_ == 1U) ? DXGI_FORMAT_R16_UINT : DXGI_FORMAT_R32_UINT;
  }

  VertexFormatD3D11::VertexFormatD3D11(const std::uint32_t formatCode, ID3D11InputLayout* const inputLayout)
    : mInputLayout(inputLayout)
  {
    formatCode_ = formatCode;
    for (const D3D11_INPUT_ELEMENT_DESC& element : d3d11::VertexLayoutElements(formatCode)) {
      if (streamStrides_.size() <= element.InputSlot) {
        streamStrides_.resize(element.InputSlot + 1U, 0U);
      }
      std::uint32_t& stride = streamStrides_[element.InputSlot];
      stride = std::max(stride, element.AlignedByteOffset + d3d11::FormatElementBytes(element.Format));
    }
  }

  VertexFormatD3D11::~VertexFormatD3D11() = default;

  ID3D11InputLayout* VertexFormatD3D11::GetInputLayout() const
  {
    if (mInputLayout == nullptr) {
      ThrowError("VertexFormatD3D11.cpp", __LINE__, "invalid vertex layout");
    }
    return mInputLayout.Get();
  }

  // ---------------------------------------------------------------------------
  // PipelineStateD3D11

  namespace
  {
    [[nodiscard]] D3D11_BLEND_DESC OpaqueBlendDesc() noexcept
    {
      D3D11_BLEND_DESC desc{};
      desc.AlphaToCoverageEnable = FALSE;
      desc.IndependentBlendEnable = FALSE;
      D3D11_RENDER_TARGET_BLEND_DESC& target = desc.RenderTarget[0];
      target.BlendEnable = FALSE;
      target.SrcBlend = D3D11_BLEND_ONE;
      target.DestBlend = D3D11_BLEND_ZERO;
      target.BlendOp = D3D11_BLEND_OP_ADD;
      target.SrcBlendAlpha = D3D11_BLEND_ONE;
      target.DestBlendAlpha = D3D11_BLEND_ZERO;
      target.BlendOpAlpha = D3D11_BLEND_OP_ADD;
      target.RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
      return desc;
    }

    [[nodiscard]] D3D11_DEPTH_STENCIL_DESC DepthWriteDesc(const D3D11_COMPARISON_FUNC depthFunc) noexcept
    {
      D3D11_DEPTH_STENCIL_DESC desc{};
      desc.DepthEnable = TRUE;
      desc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
      desc.DepthFunc = depthFunc;
      desc.StencilEnable = FALSE;
      desc.FrontFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;
      desc.FrontFace.StencilDepthFailOp = D3D11_STENCIL_OP_KEEP;
      desc.FrontFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
      desc.FrontFace.StencilFunc = D3D11_COMPARISON_ALWAYS;
      desc.BackFace = desc.FrontFace;
      return desc;
    }

    [[nodiscard]] D3D11_RASTERIZER_DESC SolidRasterizerDesc(const D3D11_CULL_MODE cull, const BOOL frontCounterClockwise) noexcept
    {
      D3D11_RASTERIZER_DESC desc{};
      desc.FillMode = D3D11_FILL_SOLID;
      desc.CullMode = cull;
      desc.FrontCounterClockwise = frontCounterClockwise;
      desc.DepthClipEnable = FALSE;
      desc.ScissorEnable = FALSE;
      desc.MultisampleEnable = TRUE;
      desc.AntialiasedLineEnable = FALSE;
      return desc;
    }
  } // namespace

  PipelineStateD3D11::PipelineStateD3D11(ID3D11Device* const device, ID3D11DeviceContext* const immediate)
    : mDevice(device)
    , mImmediate(immediate)
  {
    // Pack 1 (D3D10 `CreateState1`).
    const D3D11_RASTERIZER_DESC startupRasterizer = SolidRasterizerDesc(D3D11_CULL_NONE, TRUE);
    CheckHresult("PipelineStateD3D11.cpp", __LINE__, mDevice->CreateRasterizerState(&startupRasterizer, &mStartupRasterizer));
    const D3D11_DEPTH_STENCIL_DESC startupDepth = DepthWriteDesc(D3D11_COMPARISON_ALWAYS);
    CheckHresult("PipelineStateD3D11.cpp", __LINE__, mDevice->CreateDepthStencilState(&startupDepth, &mStartupDepthStencil));
    const D3D11_BLEND_DESC blend = OpaqueBlendDesc();
    CheckHresult("PipelineStateD3D11.cpp", __LINE__, mDevice->CreateBlendState(&blend, &mStartupBlend));

    D3D11_SAMPLER_DESC sampler{};
    sampler.Filter = D3D11_FILTER_MIN_MAG_LINEAR_MIP_POINT;
    sampler.AddressU = D3D11_TEXTURE_ADDRESS_WRAP;
    sampler.AddressV = D3D11_TEXTURE_ADDRESS_WRAP;
    sampler.AddressW = D3D11_TEXTURE_ADDRESS_WRAP;
    sampler.MaxAnisotropy = 1U;
    sampler.ComparisonFunc = D3D11_COMPARISON_ALWAYS;
    sampler.MinLOD = 0.0f;
    sampler.MaxLOD = D3D11_FLOAT32_MAX;
    CheckHresult("PipelineStateD3D11.cpp", __LINE__, mDevice->CreateSamplerState(&sampler, &mStartupSampler));

    // Pack 2 (D3D10 `CreateState2`).
    const D3D11_RASTERIZER_DESC techniqueRasterizer = SolidRasterizerDesc(D3D11_CULL_BACK, FALSE);
    CheckHresult("PipelineStateD3D11.cpp", __LINE__, mDevice->CreateRasterizerState(&techniqueRasterizer, &mTechniqueRasterizer));
    const D3D11_DEPTH_STENCIL_DESC techniqueDepth = DepthWriteDesc(D3D11_COMPARISON_LESS_EQUAL);
    CheckHresult("PipelineStateD3D11.cpp", __LINE__, mDevice->CreateDepthStencilState(&techniqueDepth, &mTechniqueDepthStencil));
    CheckHresult("PipelineStateD3D11.cpp", __LINE__, mDevice->CreateBlendState(&blend, &mTechniqueBlend));
  }

  PipelineStateD3D11::~PipelineStateD3D11() = default;

  void PipelineStateD3D11::SetDeviceState()
  {
    mImmediate->RSSetState(mStartupRasterizer.Get());
    mImmediate->OMSetDepthStencilState(mStartupDepthStencil.Get(), 0U);
    mImmediate->OMSetBlendState(mStartupBlend.Get(), nullptr, 0xFFFFFFFFU);

    ID3D11SamplerState* samplers[16];
    std::fill(std::begin(samplers), std::end(samplers), mStartupSampler.Get());
    mImmediate->PSSetSamplers(0U, 16U, samplers);
  }

  void PipelineStateD3D11::ClearTextures()
  {
    ID3D11ShaderResourceView* const noViews[D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT]{};
    mImmediate->PSSetShaderResources(0U, D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT, noViews);
  }

  void PipelineStateD3D11::BeginTechnique()
  {
    mImmediate->RSSetState(mTechniqueRasterizer.Get());
    mImmediate->OMSetDepthStencilState(mTechniqueDepthStencil.Get(), 0U);
    mImmediate->OMSetBlendState(mTechniqueBlend.Get(), nullptr, 0xFFFFFFFFU);
  }

  void PipelineStateD3D11::EndTechnique() {}

  void PipelineStateD3D11::SetColorWriteMask(const bool writeColor, const bool writeAlpha) noexcept
  {
    // The D3D9 backend's mask (`PipelineStateD3D9::SetColorWriteState`):
    // both or neither write everything, colour alone RGB, alpha alone A.
    constexpr UINT8 kRgb = D3D11_COLOR_WRITE_ENABLE_RED | D3D11_COLOR_WRITE_ENABLE_GREEN | D3D11_COLOR_WRITE_ENABLE_BLUE;
    if (writeColor) {
      mColorWriteMask = writeAlpha ? static_cast<UINT8>(D3D11_COLOR_WRITE_ENABLE_ALL) : kRgb;
    } else {
      mColorWriteMask = writeAlpha ? static_cast<UINT8>(D3D11_COLOR_WRITE_ENABLE_ALPHA)
                                   : static_cast<UINT8>(D3D11_COLOR_WRITE_ENABLE_ALL);
    }
  }

  void PipelineStateD3D11::ApplyOverrides(const bool passSetsBlend, const bool passSetsRasterizer)
  {
    if (mColorWriteMask != D3D11_COLOR_WRITE_ENABLE_ALL && !passSetsBlend) {
      ComPtr<ID3D11BlendState> bound;
      FLOAT blendFactor[4]{};
      UINT sampleMask = 0U;
      mImmediate->OMGetBlendState(&bound, blendFactor, &sampleMask);

      D3D11_BLEND_DESC desc = OpaqueBlendDesc();
      if (bound != nullptr) {
        bound->GetDesc(&desc);
      }
      if (desc.RenderTarget[0].RenderTargetWriteMask == D3D11_COLOR_WRITE_ENABLE_ALL) {
        desc.RenderTarget[0].RenderTargetWriteMask = mColorWriteMask;
        // The device hands back the existing object for a description it has
        // seen, so this allocates once per distinct state.
        ComPtr<ID3D11BlendState> masked;
        if (SUCCEEDED(mDevice->CreateBlendState(&desc, &masked))) {
          mImmediate->OMSetBlendState(masked.Get(), blendFactor, sampleMask);
        }
      }
    }

    if (mWireframe && !passSetsRasterizer) {
      ComPtr<ID3D11RasterizerState> bound;
      mImmediate->RSGetState(&bound);

      D3D11_RASTERIZER_DESC desc{};
      desc.FillMode = D3D11_FILL_SOLID;
      desc.CullMode = D3D11_CULL_BACK;
      desc.DepthClipEnable = TRUE;
      if (bound != nullptr) {
        bound->GetDesc(&desc);
      }
      if (desc.FillMode == D3D11_FILL_SOLID) {
        desc.FillMode = D3D11_FILL_WIREFRAME;
        ComPtr<ID3D11RasterizerState> wireframe;
        if (SUCCEEDED(mDevice->CreateRasterizerState(&desc, &wireframe))) {
          mImmediate->RSSetState(wireframe.Get());
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // CursorD3D11

  namespace
  {
    /**
     * A 32x32 colour cursor from the cursor texture, as the D3D10 backend's
     * `BuildCursorIcon` (0x008F8130) builds it: rows bottom-up, red and blue
     * swapped. Our textures keep D3D9's byte order (B8G8R8A8), so the swap of
     * the D3D10 (R8G8B8A8) path is not wanted here.
     */
    HICON BuildCursorIcon(const int hotspotX, const int hotspotY, Texture& texture)
    {
      BITMAPV5HEADER bitmapInfo{};
      bitmapInfo.bV5Size = sizeof(BITMAPV5HEADER);
      bitmapInfo.bV5Width = 32L;
      bitmapInfo.bV5Height = 32L;
      bitmapInfo.bV5Planes = 1;
      bitmapInfo.bV5BitCount = 32;
      bitmapInfo.bV5Compression = BI_BITFIELDS;
      bitmapInfo.bV5RedMask = 0x00FF0000U;
      bitmapInfo.bV5GreenMask = 0x0000FF00U;
      bitmapInfo.bV5BlueMask = 0x000000FFU;
      bitmapInfo.bV5AlphaMask = 0xFF000000U;

      HDC const dc = ::GetDC(nullptr);
      void* dibPixels = nullptr;
      HBITMAP const colorBitmap =
        ::CreateDIBSection(dc, reinterpret_cast<const BITMAPINFO*>(&bitmapInfo), DIB_RGB_COLORS, &dibPixels, nullptr, 0U);
      ::ReleaseDC(nullptr, dc);
      if (colorBitmap == nullptr || dibPixels == nullptr) {
        return nullptr;
      }

      const RECT wholeSurface{};
      const TextureLockRect lock = texture.Lock(0, wholeSurface, static_cast<int>(MohoD3DLockFlags::ReadOnly));
      auto* const destination = static_cast<std::uint32_t*>(dibPixels);
      const auto* const sourceBytes = static_cast<const std::uint8_t*>(lock.bits);
      const bool rgbaSource = static_cast<TextureD3D11&>(texture).GetFormat() == DXGI_FORMAT_R8G8B8A8_UNORM;
      for (std::uint32_t y = 0U; y < 32U; ++y) {
        const auto* const sourceRow =
          reinterpret_cast<const std::uint32_t*>(sourceBytes + static_cast<std::size_t>(lock.pitch) * (31U - y));
        for (std::uint32_t x = 0U; x < 32U; ++x) {
          const std::uint32_t pixel = sourceRow[x];
          destination[y * 32U + x] = rgbaSource
            ? ((pixel & 0xFF00FF00U) | ((pixel & 0x000000FFU) << 16U) | ((pixel & 0x00FF0000U) >> 16U))
            : pixel;
        }
      }
      static_cast<void>(texture.Unlock(lock));

      HBITMAP const maskBitmap = ::CreateBitmap(32, 32, 1U, 1U, nullptr);
      ICONINFO iconInfo{};
      iconInfo.fIcon = FALSE;
      iconInfo.xHotspot = static_cast<DWORD>(hotspotX);
      iconInfo.yHotspot = static_cast<DWORD>(hotspotY);
      iconInfo.hbmMask = maskBitmap;
      iconInfo.hbmColor = colorBitmap;
      HICON const icon = ::CreateIconIndirect(&iconInfo);
      ::DeleteObject(colorBitmap);
      ::DeleteObject(maskBitmap);
      return icon;
    }
  } // namespace

  CursorD3D11::~CursorD3D11()
  {
    Destroy();
  }

  void CursorD3D11::Destroy() noexcept
  {
    if (mCursorIcon != nullptr) {
      ::SetCursor(mPreviousCursor);
      ::DestroyIcon(mCursorIcon);
    }
    mPreviousCursor = nullptr;
    mCursorIcon = nullptr;
  }

  HCURSOR CursorD3D11::SetCursor(const CursorContext& context)
  {
    HICON const icon =
      (context.texture_ != nullptr) ? BuildCursorIcon(context.hotspotX_, context.hotspotY_, *context.texture_) : nullptr;
    HICON const previousIcon = mCursorIcon;
    mCursorIcon = icon;
    HCURSOR const previous = ::SetCursor(mCursorIcon);
    if (previousIcon == nullptr) {
      mPreviousCursor = previous;
    } else {
      ::DestroyIcon(previousIcon);
    }
    return previous;
  }

  HCURSOR CursorD3D11::InitCursor()
  {
    if (mCursorIcon == nullptr) {
      ThrowError("CursorD3D11.cpp", __LINE__, "attempt to use uninitialized cursor");
    }
    return ::SetCursor(mCursorIcon);
  }

  int CursorD3D11::ShowCursor(const bool show)
  {
    if (mCursorIcon == nullptr) {
      ThrowError("CursorD3D11.cpp", __LINE__, "attempt to use uninitialized cursor");
    }

    int count = 0;
    if (show) {
      do {
        count = ::ShowCursor(TRUE);
      } while (count < 0);
    } else {
      do {
        count = ::ShowCursor(FALSE);
      } while (count >= 0);
    }
    return count;
  }
} // namespace gpg::gal
