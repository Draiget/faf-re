// FAF addition, not in the shipped binary: see ResourcesVulkan.h.

#include "ResourcesVulkan.h"

#include <algorithm>
#include <cstring>

#include "DeviceVulkan.h"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/backends/common/ImageCodec.h"
#include "gpg/gal/backends/d3d11/D3D11VertexLayouts.h"
#include "gpg/gal/backends/dxgi/DxgiFormats.h"

namespace gpg::gal
{
  using backend::CheckHresult;
  using backend::ThrowError;

  namespace
  {
    [[nodiscard]] DeviceVulkan* ActiveDevice() noexcept
    {
      Device* const device = Device::GetInstance();
      if (device == nullptr) {
        return nullptr;
      }
      const DeviceContext* const context = device->GetDeviceContext();
      return (context != nullptr && context->mDeviceType == DeviceApi::Vulkan) ? static_cast<DeviceVulkan*>(device) : nullptr;
    }

    [[nodiscard]] DeviceVulkan& RequireDevice(const char* const file, const int line)
    {
      DeviceVulkan* const device = ActiveDevice();
      if (device == nullptr) {
        ThrowError(file, line, "the Vulkan device is gone");
      }
      return *device;
    }

    [[nodiscard]] bool HasFlag(const std::uint32_t flags, const MohoD3DLockFlags flag) noexcept
    {
      return (flags & static_cast<std::uint32_t>(flag)) != 0U;
    }

    void RetireImage(vulkan::TrackedImage& image, VkImageView view)
    {
      if (DeviceVulkan* const device = ActiveDevice()) {
        device->Retire(image, view);
      }
      image = vulkan::TrackedImage{};
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // TextureVulkan

  TextureVulkan::TextureVulkan(
    const TextureContext& context,
    vulkan::TrackedImage image,
    const VkImageView view,
    const DXGI_FORMAT dxgiFormat,
    const bool cube,
    const bool contentsFromEngine
  )
    : mContext(context)
    , mImage(image)
    , mView(view)
    , mDxgiFormat(dxgiFormat)
    , mContentsFromEngine(contentsFromEngine)
  {
    mContext.ClearDataBuffer();
    mContext.width_ = mImage.width;
    mContext.height_ = mImage.height;
    mContext.mipmapLevels_ = mImage.mipLevels;
    mContext.format_ = dxgi::DxgiToTextureFormat(dxgiFormat);
    mContext.type_ = (mImage.depth > 1U) ? 3U : (cube ? 2U : 1U);
    mLevels.resize(mImage.mipLevels);
  }

  TextureVulkan::~TextureVulkan()
  {
    RetireImage(mImage, mView);
    mView = VK_NULL_HANDLE;
  }

  TextureContext* TextureVulkan::GetContext()
  {
    return &mContext;
  }

  TextureLockRect TextureVulkan::Lock(const int level, const RECT& rect, const int flags)
  {
    if (mImage.image == VK_NULL_HANDLE || IsVolume()) {
      ThrowError("TextureVulkan.cpp", __LINE__, "attempt to map invalid texture");
    }
    if (level < 0 || level >= static_cast<int>(mImage.mipLevels)) {
      ThrowError("TextureVulkan.cpp", __LINE__, "attempt to map invalid texture level");
    }
    if (mLocked) {
      ThrowError("TextureVulkan.cpp", __LINE__, "texture map/unmap mismatch");
    }
    const auto levelIndex = static_cast<std::uint32_t>(level);
    const dxgi::LevelLayout layout =
      dxgi::ComputeLevelLayout(mDxgiFormat, std::max(1U, mImage.width >> levelIndex), std::max(1U, mImage.height >> levelIndex));
    std::vector<std::uint8_t>& bytes = mLevels[levelIndex];
    if (bytes.size() != layout.ByteSize()) {
      if (mContentsFromEngine || HasFlag(static_cast<std::uint32_t>(flags), MohoD3DLockFlags::Discard)) {
        bytes.assign(layout.ByteSize(), 0U);
      } else {
        RequireDevice("TextureVulkan.cpp", __LINE__).ReadImageLevel(mImage, mDxgiFormat, levelIndex, 0U, bytes);
      }
    }
    std::size_t offset = 0U;
    if (rect.left != rect.right) {
      const std::uint32_t elementBytes = dxgi::FormatElementBytes(mDxgiFormat);
      if (dxgi::IsBlockCompressed(mDxgiFormat)) {
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

  int TextureVulkan::Unlock(const TextureLockRect lock)
  {
    return Unlock(lock.level);
  }

  int TextureVulkan::Unlock(const int level)
  {
    if (!mLocked || level != mLockedLevel) {
      ThrowError("TextureVulkan.cpp", __LINE__, "texture lock/unlock mismatch");
    }
    const auto levelIndex = static_cast<std::uint32_t>(level);
    std::vector<std::uint8_t>& bytes = mLevels[levelIndex];
    if (!HasFlag(static_cast<std::uint32_t>(mLockedFlags), MohoD3DLockFlags::ReadOnly)) {
      RecordUpload(bytes.size());
      RequireDevice("TextureVulkan.cpp", __LINE__).UploadImageLevel(mImage, mDxgiFormat, levelIndex, 0U, bytes.data());
    } else if (!mContentsFromEngine) {
      std::vector<std::uint8_t>().swap(bytes);
    }
    mLocked = false;
    mLockedLevel = 0;
    mLockedFlags = 0;
    return 0;
  }

  void TextureVulkan::SaveToBuffer(gpg::MemBuffer<char>* const outBuffer)
  {
    imaging::ImageCodec* const codec = imaging::ImageCodec::Instance();
    if (codec == nullptr || mImage.image == VK_NULL_HANDLE) {
      ThrowError("TextureVulkan.cpp", __LINE__, "attempt to save invalid texture");
    }
    imaging::Image image;
    RequireDevice("TextureVulkan.cpp", __LINE__).ReadImage(mImage, mDxgiFormat, image);
    image.cube = IsCube();
    std::vector<std::uint8_t> encoded;
    CheckHresult("TextureVulkan.cpp", __LINE__, codec->Encode(image, imaging::FileFormat::Dds, encoded));
    if (outBuffer->Size() != encoded.size()) {
      *outBuffer = gpg::AllocMemBuffer(encoded.size());
    }
    std::copy(encoded.begin(), encoded.end(), outBuffer->GetPtr(0U, 0U));
  }

  void TextureVulkan::DiscardCpuCopy() noexcept
  {
    for (std::vector<std::uint8_t>& level : mLevels) {
      std::vector<std::uint8_t>().swap(level);
    }
    mContentsFromEngine = false;
  }

  // ---------------------------------------------------------------------------
  // Targets

  RenderTargetVulkan::RenderTargetVulkan(std::vector<Buffer> buffers, const DXGI_FORMAT dxgiFormat, const int swapChainIndex)
    : mBuffers(std::move(buffers))
    , mDxgiFormat(dxgiFormat)
    , mSwapChainIndex(swapChainIndex)
  {
    mContext.width_ = mBuffers.front().image.width;
    mContext.height_ = mBuffers.front().image.height;
    mContext.format_ = dxgi::DxgiToRenderTargetFormat(dxgiFormat);
  }

  RenderTargetVulkan::~RenderTargetVulkan()
  {
    for (Buffer& buffer : mBuffers) {
      RetireImage(buffer.image, buffer.view);
      buffer.view = VK_NULL_HANDLE;
    }
  }

  RenderTargetContext* RenderTargetVulkan::GetContext()
  {
    return &mContext;
  }

  HDC RenderTargetVulkan::GetDC()
  {
    return nullptr;
  }

  RenderTargetVulkan::Buffer& RenderTargetVulkan::Current()
  {
    if (mSwapChainIndex >= 0 && mBuffers.size() > 1U) {
      DeviceVulkan* const device = ActiveDevice();
      const std::uint32_t index = (device != nullptr) ? device->AcquiredImage(static_cast<std::uint32_t>(mSwapChainIndex)) : 0U;
      return mBuffers[std::min<std::size_t>(index, mBuffers.size() - 1U)];
    }
    return mBuffers.front();
  }

  DepthStencilTargetVulkan::DepthStencilTargetVulkan(
    const DepthStencilTargetContext& context, vulkan::TrackedImage image, const VkImageView view
  )
    : mContext(context)
    , mImage(image)
    , mView(view)
  {}

  DepthStencilTargetVulkan::~DepthStencilTargetVulkan()
  {
    RetireImage(mImage, mView);
    mView = VK_NULL_HANDLE;
  }

  DepthStencilTargetContext* DepthStencilTargetVulkan::GetContext()
  {
    return &mContext;
  }

  CubeRenderTargetVulkan::CubeRenderTargetVulkan(const CubeRenderTargetContext& context)
    : mContext(context)
  {}

  CubeRenderTargetVulkan::~CubeRenderTargetVulkan() = default;

  CubeRenderTargetContext* CubeRenderTargetVulkan::GetContext()
  {
    return &mContext;
  }

  // ---------------------------------------------------------------------------
  // Buffers

  BufferStorageVulkan::BufferStorageVulkan(
    const std::uint32_t byteWidth, const bool dynamic, const VkBufferUsageFlags usage, const char* const kind
  )
    : mByteWidth(std::max(byteWidth, 4U))
    , mKind(kind)
    , mDynamic(dynamic)
  {
    mShadow.Reset(mByteWidth);
    if (mDynamic) {
      return;
    }
    // Transfer both ways: uploads write it, and Device::CopyVertexBufferRegion
    // copies between static buffers on the GPU.
    mBuffer = RequireDevice(mKind, __LINE__).CreateDeviceBuffer(
      mByteWidth, usage | VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT
    );
  }

  BufferStorageVulkan::~BufferStorageVulkan()
  {
    if (mBuffer.buffer != VK_NULL_HANDLE) {
      if (DeviceVulkan* const device = ActiveDevice()) {
        device->Retire(mBuffer);
      }
    }
  }

  std::uint8_t* BufferStorageVulkan::Lock(const std::uint32_t offset, const std::uint32_t size, const MohoD3DLockFlags flags)
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

  void BufferStorageVulkan::Unlock()
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
    DeviceVulkan& device = RequireDevice(mKind, __LINE__);
    const std::lock_guard<std::recursive_mutex> lock(device.Mutex());
    if (!mDynamic) {
      device.UploadBuffer(mBuffer, mLockOffset, mShadow.data() + mLockOffset, mLockSize);
      return;
    }
    if (HasFlag(mLockFlags, MohoD3DLockFlags::NoOverwrite) && mChunkCpu != nullptr && mChunkSerial == device.RecordingSerial()) {
      std::memcpy(mChunkCpu + mLockOffset, mShadow.data() + mLockOffset, mLockSize);
      return;
    }
    // The whole buffer, DISCARD too: bytes outside the locked range keep their
    // last values, as a D3D9 driver's renamed buffer does (see BufferStorageD3D12).
    const vulkan::UploadAllocation chunk = device.AllocateUpload(mByteWidth, 256U);
    std::memcpy(chunk.cpu, mShadow.data(), mByteWidth);
    mChunkBuffer = chunk.buffer;
    mChunkOffset = chunk.offset;
    mChunkCpu = chunk.cpu;
    mChunkSerial = device.RecordingSerial();
  }

  void BufferStorageVulkan::PrepareForDraw(DeviceVulkan& device, VkBuffer& outBuffer, VkDeviceSize& outOffset)
  {
    if (!mDynamic) {
      outBuffer = mBuffer.buffer;
      outOffset = 0U;
      return;
    }
    if (mChunkCpu == nullptr || mChunkSerial != device.RecordingSerial()) {
      const vulkan::UploadAllocation chunk = device.AllocateUpload(mByteWidth, 256U);
      std::memcpy(chunk.cpu, mShadow.data(), mByteWidth);
      mChunkBuffer = chunk.buffer;
      mChunkOffset = chunk.offset;
      mChunkCpu = chunk.cpu;
      mChunkSerial = device.RecordingSerial();
    }
    outBuffer = mChunkBuffer;
    outOffset = mChunkOffset;
  }

  VertexBufferVulkan::VertexBufferVulkan(const VertexBufferContext& context)
    : mContext(context)
    , mStorage(context.vertexCount_ * context.stride_, context.usage_ == 2U, VK_BUFFER_USAGE_VERTEX_BUFFER_BIT, "VertexBufferVulkan.cpp")
  {}

  VertexBufferVulkan::~VertexBufferVulkan() = default;

  VertexBufferContext* VertexBufferVulkan::GetContext()
  {
    return &mContext;
  }

  void* VertexBufferVulkan::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    return mStorage.Lock(offset, size, lockFlags);
  }

  void VertexBufferVulkan::Unlock()
  {
    mStorage.Unlock();
  }

  IndexBufferVulkan::IndexBufferVulkan(const IndexBufferContext& context)
    : mContext(context)
    , mStorage(
        context.size_ * ((context.format_ == 1U) ? 2U : 4U), context.type_ == 2U, VK_BUFFER_USAGE_INDEX_BUFFER_BIT, "IndexBufferVulkan.cpp"
      )
  {}

  IndexBufferVulkan::~IndexBufferVulkan() = default;

  IndexBufferContext* IndexBufferVulkan::GetContext()
  {
    return &mContext;
  }

  std::int16_t* IndexBufferVulkan::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    return reinterpret_cast<std::int16_t*>(mStorage.Lock(offset, size, lockFlags));
  }

  void IndexBufferVulkan::Unlock()
  {
    mStorage.Unlock();
  }

  VkIndexType IndexBufferVulkan::IndexType() const noexcept
  {
    return (mContext.format_ == 1U) ? VK_INDEX_TYPE_UINT16 : VK_INDEX_TYPE_UINT32;
  }

  VertexFormatVulkan::VertexFormatVulkan(const std::uint32_t formatCode)
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

  VertexFormatVulkan::~VertexFormatVulkan() = default;

  PipelineStateVulkan::~PipelineStateVulkan() = default;
} // namespace gpg::gal
