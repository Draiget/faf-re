#pragma once

// FAF addition, not in the shipped binary: textures, targets, buffers and
// vertex formats of the Direct3D 12 gal backend.

#include <cstdint>
#include <vector>

#include <d3d12.h>
#include <wrl/client.h>

#include "D3D12Core.h"
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
  class DeviceD3D12;

  namespace dxgi
  {
    class SwapChain;
  }

  class TextureD3D12 final : public Texture
  {
  public:
    /** `contentsFromEngine`: an engine-filled texture, whose CPU copy starts as zeros. */
    TextureD3D12(
      const TextureContext& context, d3d12::TrackedResource resource, D3D12_CPU_DESCRIPTOR_HANDLE view, bool cube, bool contentsFromEngine
    );
    ~TextureD3D12() override;

    TextureContext* GetContext() override;
    TextureLockRect Lock(int level, const RECT& rect, int flags) override;
    int Unlock(TextureLockRect lock) override;
    int Unlock(int level) override;
    void SaveToBuffer(gpg::MemBuffer<char>* outBuffer) override;

    /** After the GPU wrote the texture: the CPU copy is stale. */
    void DiscardCpuCopy() noexcept;

    [[nodiscard]] d3d12::TrackedResource& Resource() noexcept { return mResource; }
    [[nodiscard]] D3D12_CPU_DESCRIPTOR_HANDLE View() const noexcept { return mView; }
    [[nodiscard]] const D3D12_RESOURCE_DESC& Desc() const noexcept { return mDesc; }
    [[nodiscard]] bool IsCube() const noexcept { return mContext.type_ == 2U; }
    [[nodiscard]] bool IsVolume() const noexcept { return mContext.type_ == 3U; }

    /** Bytes held by every texture's CPU copies (memory diagnostics). */
    [[nodiscard]] static std::uint64_t CpuCopyBytes() noexcept;

  private:
    void AccountCpuCopy() noexcept;

    TextureContext mContext;
    d3d12::TrackedResource mResource;
    D3D12_CPU_DESCRIPTOR_HANDLE mView{};
    D3D12_RESOURCE_DESC mDesc{};
    std::vector<std::vector<std::uint8_t>> mLevels; // CPU copies of slice 0's levels, filled on demand
    bool mContentsFromEngine = false;
    bool mLocked = false;
    int mLockedLevel = 0;
    int mLockedFlags = 0;
    std::uint64_t mAccountedBytes = 0; // this texture's share of CpuCopyBytes
  };

  /**
   * A colour target: an owned texture with its views, or a swap chain's back
   * buffers (which one is current changes with every present).
   */
  class RenderTargetD3D12 final : public RenderTarget
  {
  public:
    struct Buffer
    {
      d3d12::TrackedResource resource;
      D3D12_CPU_DESCRIPTOR_HANDLE renderTargetView{};
      D3D12_CPU_DESCRIPTOR_HANDLE shaderResourceView{};
    };

    RenderTargetD3D12(std::vector<Buffer> buffers, const dxgi::SwapChain* swapChain);
    ~RenderTargetD3D12() override;

    RenderTargetContext* GetContext() override;
    HDC GetDC() override;

    [[nodiscard]] Buffer& Current();
    [[nodiscard]] bool IsBackBuffer() const noexcept { return mSwapChain != nullptr; }
    [[nodiscard]] std::vector<Buffer>& Buffers() noexcept { return mBuffers; }
    [[nodiscard]] DXGI_FORMAT Format() const noexcept { return mFormat; }

  private:
    RenderTargetContext mContext;
    std::vector<Buffer> mBuffers;
    const dxgi::SwapChain* mSwapChain = nullptr;
    DXGI_FORMAT mFormat = DXGI_FORMAT_UNKNOWN;
  };

  class DepthStencilTargetD3D12 final : public DepthStencilTarget
  {
  public:
    DepthStencilTargetD3D12(
      const DepthStencilTargetContext& context,
      d3d12::TrackedResource resource,
      D3D12_CPU_DESCRIPTOR_HANDLE depthView,
      D3D12_CPU_DESCRIPTOR_HANDLE shaderView,
      DXGI_FORMAT depthFormat
    );
    ~DepthStencilTargetD3D12() override;

    DepthStencilTargetContext* GetContext() override;

    [[nodiscard]] d3d12::TrackedResource& Resource() noexcept { return mResource; }
    [[nodiscard]] D3D12_CPU_DESCRIPTOR_HANDLE DepthView() const noexcept { return mDepthView; }
    [[nodiscard]] D3D12_CPU_DESCRIPTOR_HANDLE ShaderView() const noexcept { return mShaderView; }
    [[nodiscard]] DXGI_FORMAT DepthFormat() const noexcept { return mDepthFormat; }

  private:
    DepthStencilTargetContext mContext;
    d3d12::TrackedResource mResource;
    D3D12_CPU_DESCRIPTOR_HANDLE mDepthView{};
    D3D12_CPU_DESCRIPTOR_HANDLE mShaderView{};
    DXGI_FORMAT mDepthFormat = DXGI_FORMAT_UNKNOWN;
  };

  /** Cube targets stay empty, as on D3D10 and D3D11. */
  class CubeRenderTargetD3D12 final : public CubeRenderTarget
  {
  public:
    explicit CubeRenderTargetD3D12(const CubeRenderTargetContext& context);
    ~CubeRenderTargetD3D12() override;

    CubeRenderTargetContext* GetContext() override;

  private:
    CubeRenderTargetContext mContext;
  };

  /**
   * Buffer storage with D3D9 lock semantics. A static buffer lives in the
   * default heap and takes each unlocked range by a copy; a dynamic one is
   * renamed into upload memory - a fresh copy whenever the GPU may still read
   * the old one, in place for NOOVERWRITE locks within one submission.
   */
  class BufferStorageD3D12
  {
  public:
    BufferStorageD3D12(std::uint32_t byteWidth, bool dynamic, D3D12_RESOURCE_STATES readState, const char* kind);
    ~BufferStorageD3D12();

    BufferStorageD3D12(const BufferStorageD3D12&) = delete;
    BufferStorageD3D12& operator=(const BufferStorageD3D12&) = delete;

    [[nodiscard]] std::uint8_t* Lock(std::uint32_t offset, std::uint32_t size, MohoD3DLockFlags flags);
    void Unlock();

    /** The address draws read from, ready for reading. */
    [[nodiscard]] D3D12_GPU_VIRTUAL_ADDRESS PrepareForDraw(DeviceD3D12& device);
    [[nodiscard]] std::uint32_t ByteWidth() const noexcept { return mByteWidth; }
    [[nodiscard]] bool IsDynamic() const noexcept { return mDynamic; }

    /**
     * Where a GPU copy reads this buffer: the default-heap resource, moved to
     * COPY_SOURCE, or a dynamic buffer's current copy in upload memory.
     */
    void PrepareForCopySource(DeviceD3D12& device, ID3D12Resource*& resource, std::uint64_t& offset);
    /** A static buffer's resource, for a GPU copy into it; nullptr for a dynamic buffer. */
    [[nodiscard]] d3d12::TrackedResource* CopyDestination();

  private:
    void TakeChunk(DeviceD3D12& device, const d3d12::UploadAllocation& chunk);
    /** A placed buffer's first upload sends the whole zeroed shadow (see the constructor). */
    void FillUnwritten(DeviceD3D12& device);

    std::uint32_t mByteWidth = 0;
    const char* mKind = nullptr;
    bool mDynamic = false;
    D3D12_RESOURCE_STATES mReadState = D3D12_RESOURCE_STATE_GENERIC_READ;
    backend::LockShadow mShadow;
    d3d12::TrackedResource mResource;    // static buffers
    bool mUnwritten = false;             // placed, and not yet uploaded whole
    D3D12_GPU_VIRTUAL_ADDRESS mChunk = 0; // dynamic buffers: the current copy in upload memory
    std::uint8_t* mChunkCpu = nullptr;
    ID3D12Resource* mChunkResource = nullptr; // the upload page holding that copy, and where in it
    std::uint64_t mChunkOffset = 0;
    std::uint64_t mChunkSerial = 0;
    bool mLocked = false;
    std::uint32_t mLockOffset = 0;
    std::uint32_t mLockSize = 0;
    std::uint32_t mLockFlags = 0;
  };

  class VertexBufferD3D12 final : public VertexBuffer
  {
  public:
    explicit VertexBufferD3D12(const VertexBufferContext& context);
    ~VertexBufferD3D12() override;

    VertexBufferContext* GetContext() override;
    void* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags) override;
    void Unlock() override;

    [[nodiscard]] BufferStorageD3D12& Storage() noexcept { return mStorage; }

  private:
    VertexBufferContext mContext;
    BufferStorageD3D12 mStorage;
  };

  class IndexBufferD3D12 final : public IndexBuffer
  {
  public:
    explicit IndexBufferD3D12(const IndexBufferContext& context);
    ~IndexBufferD3D12() override;

    IndexBufferContext* GetContext() override;
    std::int16_t* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags) override;
    void Unlock() override;

    [[nodiscard]] BufferStorageD3D12& Storage() noexcept { return mStorage; }
    [[nodiscard]] DXGI_FORMAT IndexFormat() const noexcept;

  private:
    IndexBufferContext mContext;
    BufferStorageD3D12 mStorage;
  };

  class VertexFormatD3D12 final : public VertexFormat
  {
  public:
    explicit VertexFormatD3D12(std::uint32_t formatCode);
    ~VertexFormatD3D12() override;
  };

  /** The gal pipeline-state object: opaque to the engine; the device keeps the state. */
  class PipelineStateD3D12 final : public PipelineState
  {
  public:
    PipelineStateD3D12() = default;
    ~PipelineStateD3D12() override;
  };
} // namespace gpg::gal
