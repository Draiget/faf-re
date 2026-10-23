// FAF addition, not in the shipped binary: see ResourcesD3D12.h.

#include "ResourcesD3D12.h"

#include <algorithm>
#include <atomic>
#include <cstring>

#include "DeviceD3D12.h"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "gpg/gal/backends/d3d11/D3D11VertexLayouts.h"
#include "gpg/gal/backends/dxgi/DxgiFormats.h"
#include "gpg/gal/backends/dxgi/DxgiSwapChain.h"

namespace gpg::gal
{
  using Microsoft::WRL::ComPtr;
  using backend::CheckHresult;
  using backend::ThrowError;

  namespace
  {
    /** The Direct3D 12 device, while it exists (resources can outlive it at exit). */
    [[nodiscard]] DeviceD3D12* ActiveDevice() noexcept
    {
      Device* const device = Device::GetInstance();
      if (device == nullptr) {
        return nullptr;
      }
      const DeviceContext* const context = device->GetDeviceContext();
      return (context != nullptr && context->mDeviceType == DeviceApi::Direct3D12) ? static_cast<DeviceD3D12*>(device) : nullptr;
    }

    [[nodiscard]] DeviceD3D12& RequireDevice(const char* const file, const int line)
    {
      DeviceD3D12* const device = ActiveDevice();
      if (device == nullptr) {
        ThrowError(file, line, "the Direct3D 12 device is gone");
      }
      return *device;
    }

    [[nodiscard]] bool HasFlag(const std::uint32_t flags, const MohoD3DLockFlags flag) noexcept
    {
      return (flags & static_cast<std::uint32_t>(flag)) != 0U;
    }

    void RetireResource(ComPtr<ID3D12Resource>& resource)
    {
      if (resource == nullptr) {
        return;
      }
      if (DeviceD3D12* const device = ActiveDevice()) {
        device->Retire(std::move(resource));
      }
      resource.Reset();
    }

    void RetireView(const D3D12_DESCRIPTOR_HEAP_TYPE type, D3D12_CPU_DESCRIPTOR_HANDLE& handle)
    {
      if (handle.ptr == 0U) {
        return;
      }
      if (DeviceD3D12* const device = ActiveDevice()) {
        device->RetireDescriptor(type, handle);
      }
      handle.ptr = 0U;
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // TextureD3D12

  TextureD3D12::TextureD3D12(
    const TextureContext& context,
    d3d12::TrackedResource resource,
    const D3D12_CPU_DESCRIPTOR_HANDLE view,
    const bool cube,
    const bool contentsFromEngine
  )
    : mContext(context)
    , mResource(std::move(resource))
    , mView(view)
    , mContentsFromEngine(contentsFromEngine)
  {
    mContext.ClearDataBuffer();
    mDesc = mResource.resource->GetDesc();
    mContext.width_ = static_cast<std::uint32_t>(mDesc.Width);
    mContext.height_ = mDesc.Height;
    mContext.mipmapLevels_ = mDesc.MipLevels;
    mContext.format_ = dxgi::DxgiToTextureFormat(mDesc.Format);
    if (mDesc.Dimension == D3D12_RESOURCE_DIMENSION_TEXTURE3D) {
      mContext.type_ = 3U;
    } else {
      mContext.type_ = cube ? 2U : 1U;
    }
    mLevels.resize(mDesc.MipLevels);
  }

  namespace
  {
    std::atomic<std::uint64_t> sTextureCpuCopyBytes{0};
  }

  TextureD3D12::~TextureD3D12()
  {
    sTextureCpuCopyBytes.fetch_sub(mAccountedBytes);
    RetireResource(mResource.resource);
    RetireView(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, mView);
  }

  std::uint64_t TextureD3D12::CpuCopyBytes() noexcept
  {
    return sTextureCpuCopyBytes.load();
  }

  void TextureD3D12::AccountCpuCopy() noexcept
  {
    std::uint64_t bytes = 0U;
    for (const std::vector<std::uint8_t>& level : mLevels) {
      bytes += level.capacity();
    }
    sTextureCpuCopyBytes.fetch_add(bytes);
    sTextureCpuCopyBytes.fetch_sub(mAccountedBytes);
    mAccountedBytes = bytes;
  }

  TextureContext* TextureD3D12::GetContext()
  {
    return &mContext;
  }

  TextureLockRect TextureD3D12::Lock(const int level, const RECT& rect, const int flags)
  {
    if (mResource.resource == nullptr || IsVolume()) {
      ThrowError("TextureD3D12.cpp", __LINE__, "attempt to map invalid texture");
    }
    if (level < 0 || level >= static_cast<int>(mDesc.MipLevels)) {
      ThrowError("TextureD3D12.cpp", __LINE__, "attempt to map invalid texture level");
    }
    if (mLocked) {
      ThrowError("TextureD3D12.cpp", __LINE__, "texture map/unmap mismatch");
    }

    const auto levelIndex = static_cast<std::uint32_t>(level);
    const std::uint32_t width = std::max(1U, static_cast<std::uint32_t>(mDesc.Width) >> levelIndex);
    const std::uint32_t height = std::max(1U, mDesc.Height >> levelIndex);
    const dxgi::LevelLayout layout = dxgi::ComputeLevelLayout(mDesc.Format, width, height);

    std::vector<std::uint8_t>& bytes = mLevels[levelIndex];
    if (bytes.size() != layout.ByteSize()) {
      if (mContentsFromEngine || HasFlag(static_cast<std::uint32_t>(flags), MohoD3DLockFlags::Discard)) {
        bytes.assign(layout.ByteSize(), 0U);
      } else {
        DeviceD3D12& device = RequireDevice("TextureD3D12.cpp", __LINE__);
        std::uint32_t rowPitch = 0U;
        device.ReadSubresource(mResource, levelIndex, bytes, rowPitch);
      }
    }

    // An empty rect locks the whole level, as TextureD3D9::Lock.
    std::size_t offset = 0U;
    if (rect.left != rect.right) {
      const std::uint32_t elementBytes = dxgi::FormatElementBytes(mDesc.Format);
      if (dxgi::IsBlockCompressed(mDesc.Format)) {
        offset = static_cast<std::size_t>(rect.top / 4) * layout.rowPitch + static_cast<std::size_t>(rect.left / 4) * elementBytes;
      } else {
        offset = static_cast<std::size_t>(rect.top) * layout.rowPitch + static_cast<std::size_t>(rect.left) * elementBytes;
      }
    }

    mLocked = true;
    mLockedLevel = level;
    mLockedFlags = flags;
    AccountCpuCopy();

    TextureLockRect lock{};
    lock.flags = flags;
    lock.level = level;
    lock.pitch = static_cast<int>(layout.rowPitch);
    lock.bits = bytes.data() + offset;
    return lock;
  }

  int TextureD3D12::Unlock(const TextureLockRect lock)
  {
    return Unlock(lock.level);
  }

  int TextureD3D12::Unlock(const int level)
  {
    if (!mLocked || level != mLockedLevel) {
      ThrowError("TextureD3D12.cpp", __LINE__, "texture lock/unlock mismatch");
    }
    const auto levelIndex = static_cast<std::uint32_t>(level);
    std::vector<std::uint8_t>& bytes = mLevels[levelIndex];
    if (!HasFlag(static_cast<std::uint32_t>(mLockedFlags), MohoD3DLockFlags::ReadOnly)) {
      RecordUpload(bytes.size());
      const dxgi::LevelLayout layout = dxgi::ComputeLevelLayout(
        mDesc.Format, std::max(1U, static_cast<std::uint32_t>(mDesc.Width) >> levelIndex), std::max(1U, mDesc.Height >> levelIndex)
      );
      RequireDevice("TextureD3D12.cpp", __LINE__).UploadSubresource(mResource, levelIndex, bytes.data(), layout.rowPitch);
    } else if (!mContentsFromEngine) {
      // A read of a file texture (the cursor icon): the GPU copy stays the authority.
      std::vector<std::uint8_t>().swap(bytes);
    }
    mLocked = false;
    mLockedLevel = 0;
    mLockedFlags = 0;
    AccountCpuCopy();
    return 0;
  }

  void TextureD3D12::SaveToBuffer(gpg::MemBuffer<char>* const outBuffer)
  {
    imaging::ImageCodec* const codec = imaging::ImageCodec::Instance();
    if (codec == nullptr || mResource.resource == nullptr) {
      ThrowError("TextureD3D12.cpp", __LINE__, "attempt to save invalid texture");
    }
    imaging::Image image;
    RequireDevice("TextureD3D12.cpp", __LINE__).ReadTexture(mResource, image);
    image.cube = IsCube();
    std::vector<std::uint8_t> encoded;
    CheckHresult("TextureD3D12.cpp", __LINE__, codec->Encode(image, imaging::FileFormat::Dds, encoded));
    if (outBuffer->Size() != encoded.size()) {
      *outBuffer = gpg::AllocMemBuffer(encoded.size());
    }
    std::copy(encoded.begin(), encoded.end(), outBuffer->GetPtr(0U, 0U));
  }

  void TextureD3D12::DiscardCpuCopy() noexcept
  {
    for (std::vector<std::uint8_t>& level : mLevels) {
      std::vector<std::uint8_t>().swap(level);
    }
    mContentsFromEngine = false;
    AccountCpuCopy();
  }

  // ---------------------------------------------------------------------------
  // RenderTargetD3D12 / DepthStencilTargetD3D12 / CubeRenderTargetD3D12

  RenderTargetD3D12::RenderTargetD3D12(std::vector<Buffer> buffers, const dxgi::SwapChain* const swapChain)
    : mBuffers(std::move(buffers))
    , mSwapChain(swapChain)
  {
    const D3D12_RESOURCE_DESC desc = mBuffers.front().resource.resource->GetDesc();
    mContext.width_ = static_cast<std::uint32_t>(desc.Width);
    mContext.height_ = desc.Height;
    mContext.format_ = dxgi::DxgiToRenderTargetFormat(desc.Format);
    mFormat = desc.Format;
  }

  RenderTargetD3D12::~RenderTargetD3D12()
  {
    for (Buffer& buffer : mBuffers) {
      RetireResource(buffer.resource.resource);
      RetireView(D3D12_DESCRIPTOR_HEAP_TYPE_RTV, buffer.renderTargetView);
      RetireView(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, buffer.shaderResourceView);
    }
  }

  RenderTargetContext* RenderTargetD3D12::GetContext()
  {
    return &mContext;
  }

  HDC RenderTargetD3D12::GetDC()
  {
    return nullptr;
  }

  RenderTargetD3D12::Buffer& RenderTargetD3D12::Current()
  {
    if (mSwapChain != nullptr && mBuffers.size() > 1U) {
      const std::uint32_t index = mSwapChain->CurrentBufferIndex();
      return mBuffers[std::min<std::size_t>(index, mBuffers.size() - 1U)];
    }
    return mBuffers.front();
  }

  DepthStencilTargetD3D12::DepthStencilTargetD3D12(
    const DepthStencilTargetContext& context,
    d3d12::TrackedResource resource,
    const D3D12_CPU_DESCRIPTOR_HANDLE depthView,
    const D3D12_CPU_DESCRIPTOR_HANDLE shaderView,
    const DXGI_FORMAT depthFormat
  )
    : mContext(context)
    , mResource(std::move(resource))
    , mDepthView(depthView)
    , mShaderView(shaderView)
    , mDepthFormat(depthFormat)
  {}

  DepthStencilTargetD3D12::~DepthStencilTargetD3D12()
  {
    RetireResource(mResource.resource);
    RetireView(D3D12_DESCRIPTOR_HEAP_TYPE_DSV, mDepthView);
    RetireView(D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV, mShaderView);
  }

  DepthStencilTargetContext* DepthStencilTargetD3D12::GetContext()
  {
    return &mContext;
  }

  CubeRenderTargetD3D12::CubeRenderTargetD3D12(const CubeRenderTargetContext& context)
    : mContext(context)
  {}

  CubeRenderTargetD3D12::~CubeRenderTargetD3D12() = default;

  CubeRenderTargetContext* CubeRenderTargetD3D12::GetContext()
  {
    return &mContext;
  }

  // ---------------------------------------------------------------------------
  // Buffers

  BufferStorageD3D12::BufferStorageD3D12(
    const std::uint32_t byteWidth, const bool dynamic, const D3D12_RESOURCE_STATES readState, const char* const kind
  )
    : mByteWidth(std::max(byteWidth, 4U))
    , mKind(kind)
    , mDynamic(dynamic)
    , mReadState(readState)
  {
    mShadow.Reset(mByteWidth);
    if (mDynamic) {
      return;
    }
    DeviceD3D12& device = RequireDevice(mKind, __LINE__);
    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_DEFAULT;
    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    desc.Width = mByteWidth;
    desc.Height = 1U;
    desc.DepthOrArraySize = 1U;
    desc.MipLevels = 1U;
    desc.SampleDesc.Count = 1U;
    desc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    CheckHresult(
      mKind, __LINE__,
      device.Native()->CreateCommittedResource(
        &heap, D3D12_HEAP_FLAG_NONE, &desc, D3D12_RESOURCE_STATE_COMMON, nullptr, IID_PPV_ARGS(&mResource.resource)
      )
    );
    mResource.state = D3D12_RESOURCE_STATE_COMMON;
  }

  BufferStorageD3D12::~BufferStorageD3D12()
  {
    RetireResource(mResource.resource);
  }

  std::uint8_t* BufferStorageD3D12::Lock(const std::uint32_t offset, const std::uint32_t size, const MohoD3DLockFlags flags)
  {
    if (mLocked) {
      ThrowError(mKind, __LINE__, "buffer lock/unlock mismatch");
    }
    if (offset >= mByteWidth) {
      ThrowError(mKind, __LINE__, "buffer lock offset out of range");
    }
    mLockOffset = offset;
    mLockSize = (size == 0U || offset + size > mByteWidth) ? (mByteWidth - offset) : size;
    mLockFlags = static_cast<std::uint32_t>(flags);
    mLocked = true;
    return mShadow.Map(offset, size, mKind);
  }

  void BufferStorageD3D12::Unlock()
  {
    if (!mLocked) {
      ThrowError(mKind, __LINE__, "buffer lock/unlock mismatch");
    }
    mLocked = false;
    mShadow.CheckGuard(mKind);
    if (HasFlag(mLockFlags, MohoD3DLockFlags::ReadOnly) || mLockSize == 0U) {
      return;
    }
    RecordUpload(mLockSize);
    DeviceD3D12& device = RequireDevice(mKind, __LINE__);
    const std::lock_guard<std::recursive_mutex> lock(device.Mutex());
    if (!mDynamic) {
      device.UploadBuffer(mResource, mLockOffset, mShadow.data() + mLockOffset, mLockSize);
      return;
    }

    if (HasFlag(mLockFlags, MohoD3DLockFlags::NoOverwrite) && mChunkCpu != nullptr && mChunkSerial == device.RecordingSerial()) {
      // The caller promises not to touch what earlier draws read.
      std::memcpy(mChunkCpu + mLockOffset, mShadow.data() + mLockOffset, mLockSize);
      return;
    }
    // A new copy: earlier draws keep reading the old one. The whole buffer
    // goes in, DISCARD too: the bytes outside the locked range keep their
    // last values, as the renamed buffer a D3D9 driver hands back does. The
    // engine reads past what it wrote - the vision pass draws its total
    // circle count from every ring batch - and fresh upload memory there
    // drew garbage vision volumes into the minimap fog.
    const d3d12::UploadAllocation chunk = device.AllocateUpload(mByteWidth, 256U);
    std::memcpy(chunk.cpu, mShadow.data(), mByteWidth);
    TakeChunk(device, chunk);
  }

  void BufferStorageD3D12::TakeChunk(DeviceD3D12& device, const d3d12::UploadAllocation& chunk)
  {
    mChunk = chunk.gpu;
    mChunkCpu = chunk.cpu;
    mChunkResource = chunk.resource;
    mChunkOffset = chunk.offset;
    mChunkSerial = device.RecordingSerial();
  }

  D3D12_GPU_VIRTUAL_ADDRESS BufferStorageD3D12::PrepareForDraw(DeviceD3D12& device)
  {
    if (!mDynamic) {
      device.Transition(mResource, mReadState);
      return mResource.resource->GetGPUVirtualAddress();
    }
    if (mChunkCpu == nullptr || mChunkSerial != device.RecordingSerial()) {
      // The copy a previous submission read may be recycled; take a fresh one.
      const d3d12::UploadAllocation chunk = device.AllocateUpload(mByteWidth, 256U);
      std::memcpy(chunk.cpu, mShadow.data(), mByteWidth);
      TakeChunk(device, chunk);
    }
    return mChunk;
  }

  void BufferStorageD3D12::PrepareForCopySource(DeviceD3D12& device, ID3D12Resource*& resource, std::uint64_t& offset)
  {
    if (!mDynamic) {
      device.Transition(mResource, D3D12_RESOURCE_STATE_COPY_SOURCE);
      resource = mResource.resource.Get();
      offset = 0U;
      return;
    }
    // Upload memory stays in GENERIC_READ, which includes COPY_SOURCE.
    static_cast<void>(PrepareForDraw(device));
    resource = mChunkResource;
    offset = mChunkOffset;
  }

  VertexBufferD3D12::VertexBufferD3D12(const VertexBufferContext& context)
    : mContext(context)
    , mStorage(
        context.vertexCount_ * context.stride_,
        context.usage_ == 2U,
        D3D12_RESOURCE_STATE_VERTEX_AND_CONSTANT_BUFFER,
        "VertexBufferD3D12.cpp"
      )
  {}

  VertexBufferD3D12::~VertexBufferD3D12() = default;

  VertexBufferContext* VertexBufferD3D12::GetContext()
  {
    return &mContext;
  }

  void* VertexBufferD3D12::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    return mStorage.Lock(offset, size, lockFlags);
  }

  void VertexBufferD3D12::Unlock()
  {
    mStorage.Unlock();
  }

  IndexBufferD3D12::IndexBufferD3D12(const IndexBufferContext& context)
    : mContext(context)
    , mStorage(
        context.size_ * ((context.format_ == 1U) ? 2U : 4U), context.type_ == 2U, D3D12_RESOURCE_STATE_INDEX_BUFFER, "IndexBufferD3D12.cpp"
      )
  {}

  IndexBufferD3D12::~IndexBufferD3D12() = default;

  IndexBufferContext* IndexBufferD3D12::GetContext()
  {
    return &mContext;
  }

  std::int16_t* IndexBufferD3D12::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    return reinterpret_cast<std::int16_t*>(mStorage.Lock(offset, size, lockFlags));
  }

  void IndexBufferD3D12::Unlock()
  {
    mStorage.Unlock();
  }

  DXGI_FORMAT IndexBufferD3D12::IndexFormat() const noexcept
  {
    return (mContext.format_ == 1U) ? DXGI_FORMAT_R16_UINT : DXGI_FORMAT_R32_UINT;
  }

  VertexFormatD3D12::VertexFormatD3D12(const std::uint32_t formatCode)
  {
    formatCode_ = formatCode;
    for (const D3D11_INPUT_ELEMENT_DESC& element : d3d11::VertexLayoutElements(formatCode)) {
      if (streamStrides_.size() <= element.InputSlot) {
        streamStrides_.resize(element.InputSlot + 1U, 0U);
      }
      std::uint32_t& stride = streamStrides_[element.InputSlot];
      stride = std::max(stride, element.AlignedByteOffset + dxgi::FormatElementBytes(element.Format));
    }
  }

  VertexFormatD3D12::~VertexFormatD3D12() = default;

  PipelineStateD3D12::~PipelineStateD3D12() = default;
} // namespace gpg::gal
