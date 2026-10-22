#pragma once

// FAF addition, not in the shipped binary: textures, targets, buffers and
// vertex formats of the Vulkan gal backend.

#include <cstdint>
#include <vector>

#include "VulkanCore.h"
#include "gpg/gal/backends/common/LockShadow.h"
#include "gpg/gal/CubeRenderTarget.hpp"
#include "gpg/gal/CubeRenderTargetContext.hpp"
#include "gpg/gal/DepthStencilTarget.hpp"
#include "gpg/gal/DepthStencilTargetContext.hpp"
#include "gpg/gal/IndexBuffer.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/PipelineState.hpp"
#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/Texture.hpp"
#include "gpg/gal/TextureContext.h"
#include "gpg/gal/VertexBuffer.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/VertexFormat.hpp"

namespace gpg::gal
{
  class DeviceVulkan;

  class TextureVulkan final : public Texture
  {
  public:
    /** `contentsFromEngine`: an engine-filled texture, whose CPU copy starts as zeros. */
    TextureVulkan(
      const TextureContext& context, vulkan::TrackedImage image, VkImageView view, DXGI_FORMAT dxgiFormat, bool cube, bool contentsFromEngine
    );
    ~TextureVulkan() override;

    TextureContext* GetContext() override;
    TextureLockRect Lock(int level, const RECT& rect, int flags) override;
    int Unlock(TextureLockRect lock) override;
    int Unlock(int level) override;
    void SaveToBuffer(gpg::MemBuffer<char>* outBuffer) override;

    void DiscardCpuCopy() noexcept;

    [[nodiscard]] vulkan::TrackedImage& Image() noexcept { return mImage; }
    [[nodiscard]] VkImageView View() const noexcept { return mView; }
    [[nodiscard]] DXGI_FORMAT DxgiFormat() const noexcept { return mDxgiFormat; }
    [[nodiscard]] bool IsCube() const noexcept { return mContext.type_ == 2U; }
    [[nodiscard]] bool IsVolume() const noexcept { return mContext.type_ == 3U; }

  private:
    TextureContext mContext;
    vulkan::TrackedImage mImage;
    VkImageView mView = VK_NULL_HANDLE;
    DXGI_FORMAT mDxgiFormat = DXGI_FORMAT_UNKNOWN;
    std::vector<std::vector<std::uint8_t>> mLevels;
    bool mContentsFromEngine = false;
    bool mLocked = false;
    int mLockedLevel = 0;
    int mLockedFlags = 0;
  };

  /** A colour target: an owned image, or a swap chain's images (the acquired one is current). */
  class RenderTargetVulkan final : public RenderTarget
  {
  public:
    struct Buffer
    {
      vulkan::TrackedImage image;
      VkImageView view = VK_NULL_HANDLE; // attachment and sampled view
    };

    /** `swapChainIndex`: the device's swap chain this target shows, or -1. */
    RenderTargetVulkan(std::vector<Buffer> buffers, DXGI_FORMAT dxgiFormat, int swapChainIndex);
    ~RenderTargetVulkan() override;

    RenderTargetContext* GetContext() override;
    HDC GetDC() override;

    [[nodiscard]] Buffer& Current();
    [[nodiscard]] bool IsBackBuffer() const noexcept { return mSwapChainIndex >= 0; }
    [[nodiscard]] std::vector<Buffer>& Buffers() noexcept { return mBuffers; }
    [[nodiscard]] DXGI_FORMAT DxgiFormat() const noexcept { return mDxgiFormat; }
    [[nodiscard]] VkFormat Format() const noexcept { return mBuffers.front().image.format; }

  private:
    RenderTargetContext mContext;
    std::vector<Buffer> mBuffers;
    DXGI_FORMAT mDxgiFormat = DXGI_FORMAT_UNKNOWN;
    int mSwapChainIndex = -1;
  };

  class DepthStencilTargetVulkan final : public DepthStencilTarget
  {
  public:
    DepthStencilTargetVulkan(const DepthStencilTargetContext& context, vulkan::TrackedImage image, VkImageView view);
    ~DepthStencilTargetVulkan() override;

    DepthStencilTargetContext* GetContext() override;

    [[nodiscard]] vulkan::TrackedImage& Image() noexcept { return mImage; }
    [[nodiscard]] VkImageView View() const noexcept { return mView; }

  private:
    DepthStencilTargetContext mContext;
    vulkan::TrackedImage mImage;
    VkImageView mView = VK_NULL_HANDLE;
  };

  /** Cube targets stay empty, as on D3D10, D3D11 and D3D12. */
  class CubeRenderTargetVulkan final : public CubeRenderTarget
  {
  public:
    explicit CubeRenderTargetVulkan(const CubeRenderTargetContext& context);
    ~CubeRenderTargetVulkan() override;

    CubeRenderTargetContext* GetContext() override;

  private:
    CubeRenderTargetContext mContext;
  };

  /** Buffer storage with D3D9 lock semantics (see BufferStorageD3D12). */
  class BufferStorageVulkan
  {
  public:
    BufferStorageVulkan(std::uint32_t byteWidth, bool dynamic, VkBufferUsageFlags usage, const char* kind);
    ~BufferStorageVulkan();

    BufferStorageVulkan(const BufferStorageVulkan&) = delete;
    BufferStorageVulkan& operator=(const BufferStorageVulkan&) = delete;

    [[nodiscard]] std::uint8_t* Lock(std::uint32_t offset, std::uint32_t size, MohoD3DLockFlags flags);
    void Unlock();

    /** The buffer and offset draws read from. */
    void PrepareForDraw(DeviceVulkan& device, VkBuffer& outBuffer, VkDeviceSize& outOffset);
    [[nodiscard]] std::uint32_t ByteWidth() const noexcept { return mByteWidth; }

  private:
    std::uint32_t mByteWidth = 0;
    const char* mKind = nullptr;
    bool mDynamic = false;
    backend::LockShadow mShadow;
    vulkan::TrackedBuffer mBuffer; // static buffers
    VkBuffer mChunkBuffer = VK_NULL_HANDLE;
    VkDeviceSize mChunkOffset = 0;
    std::uint8_t* mChunkCpu = nullptr;
    std::uint64_t mChunkSerial = 0;
    bool mLocked = false;
    std::uint32_t mLockOffset = 0;
    std::uint32_t mLockSize = 0;
    std::uint32_t mLockFlags = 0;
  };

  class VertexBufferVulkan final : public VertexBuffer
  {
  public:
    explicit VertexBufferVulkan(const VertexBufferContext& context);
    ~VertexBufferVulkan() override;

    VertexBufferContext* GetContext() override;
    void* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags) override;
    void Unlock() override;

    [[nodiscard]] BufferStorageVulkan& Storage() noexcept { return mStorage; }

  private:
    VertexBufferContext mContext;
    BufferStorageVulkan mStorage;
  };

  class IndexBufferVulkan final : public IndexBuffer
  {
  public:
    explicit IndexBufferVulkan(const IndexBufferContext& context);
    ~IndexBufferVulkan() override;

    IndexBufferContext* GetContext() override;
    std::int16_t* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags) override;
    void Unlock() override;

    [[nodiscard]] BufferStorageVulkan& Storage() noexcept { return mStorage; }
    [[nodiscard]] VkIndexType IndexType() const noexcept;

  private:
    IndexBufferContext mContext;
    BufferStorageVulkan mStorage;
  };

  class VertexFormatVulkan final : public VertexFormat
  {
  public:
    explicit VertexFormatVulkan(std::uint32_t formatCode);
    ~VertexFormatVulkan() override;
  };

  class PipelineStateVulkan final : public PipelineState
  {
  public:
    PipelineStateVulkan() = default;
    ~PipelineStateVulkan() override;
  };
} // namespace gpg::gal
