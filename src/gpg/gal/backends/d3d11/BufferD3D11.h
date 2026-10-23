#pragma once

// FAF addition, not in the shipped binary: the Direct3D 11 counterparts of
// VertexBufferD3D10, IndexBufferD3D10 and VertexFormatD3D10.

#include <cstdint>
#include <vector>

#include <d3d11.h>
#include <wrl/client.h>

#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/IndexBuffer.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBuffer.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/VertexFormat.hpp"
#include "gpg/gal/backends/common/LockShadow.h"

namespace gpg::gal
{
  /**
   * The storage behind one vertex or index buffer.
   *
   * Dynamic buffers (gal usage 2, D3D9's D3DUSAGE_DYNAMIC) are D3D11 dynamic
   * buffers mapped directly: Discard maps WRITE_DISCARD and NoOverwrite
   * WRITE_NO_OVERWRITE, which is the ring-buffer pattern the engine's vertex
   * streams and particle buffers use. Static buffers are default-usage
   * buffers with a CPU copy; a lock returns the copy and the unlock uploads
   * the locked range. The copy is a `backend::LockShadow`: a lock past the end
   * or a write past the locked range is logged instead of corrupting the heap. The D3D10 backend instead mapped a staging buffer and
   * copied the whole of it into the GPU buffer on every unlock.
   */
  class BufferStorageD3D11
  {
  public:
    BufferStorageD3D11(
      ID3D11Device* device,
      ID3D11DeviceContext* immediate,
      std::uint32_t byteWidth,
      UINT bindFlags,
      bool dynamic,
      const char* kind
    );

    /** Returns a pointer `offset` bytes in; `size` 0 means to the end. */
    [[nodiscard]] std::uint8_t* Lock(std::uint32_t offset, std::uint32_t size, MohoD3DLockFlags flags);
    void Unlock();

    [[nodiscard]] ID3D11Buffer* Get() const noexcept { return mBuffer.Get(); }
    [[nodiscard]] std::uint32_t ByteWidth() const noexcept { return mByteWidth; }

  private:
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> mImmediate;
    Microsoft::WRL::ComPtr<ID3D11Buffer> mBuffer;
    backend::LockShadow mShadow; // static buffers only
    std::uint32_t mByteWidth = 0;
    std::uint32_t mLockOffset = 0;
    std::uint32_t mLockSize = 0;
    const char* mKind = "";
    bool mDynamic = false;
    bool mLocked = false;
    bool mLockWrites = false;
  };

  class VertexBufferD3D11 final : public VertexBuffer
  {
  public:
    VertexBufferD3D11(const VertexBufferContext& context, ID3D11Device* device, ID3D11DeviceContext* immediate);
    ~VertexBufferD3D11() override;

    VertexBufferContext* GetContext() override;
    void* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags) override;
    void Unlock() override;

    [[nodiscard]] ID3D11Buffer* GetBuffer() const noexcept { return mStorage.Get(); }

  private:
    VertexBufferContext mContext;
    BufferStorageD3D11 mStorage;
  };

  class IndexBufferD3D11 final : public IndexBuffer
  {
  public:
    IndexBufferD3D11(const IndexBufferContext& context, ID3D11Device* device, ID3D11DeviceContext* immediate);
    ~IndexBufferD3D11() override;

    IndexBufferContext* GetContext() override;
    std::int16_t* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags) override;
    void Unlock() override;

    [[nodiscard]] ID3D11Buffer* GetBuffer() const noexcept { return mStorage.Get(); }
    /** 32-bit indices for gal index format 2, 16-bit otherwise (as SetBufferIndices on D3D10). */
    [[nodiscard]] DXGI_FORMAT GetIndexFormat() const noexcept;

  private:
    IndexBufferContext mContext;
    BufferStorageD3D11 mStorage;
  };

  /** One gal vertex format: its input layout and the stride of each stream. */
  class VertexFormatD3D11 final : public VertexFormat
  {
  public:
    VertexFormatD3D11(std::uint32_t formatCode, ID3D11InputLayout* inputLayout);
    ~VertexFormatD3D11() override;

    [[nodiscard]] ID3D11InputLayout* GetInputLayout() const;

  private:
    Microsoft::WRL::ComPtr<ID3D11InputLayout> mInputLayout;
  };
} // namespace gpg::gal
