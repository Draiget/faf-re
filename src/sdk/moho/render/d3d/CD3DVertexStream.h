#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "moho/render/ID3DVertexStream.h"

namespace moho
{
  class CD3DDevice;

  class CD3DVertexStream : public ID3DVertexStream
  {
  public:
    using BufferHandle = ID3DVertexStream::BufferHandle;

    /**
     * Address: 0x0043FA60 (FUN_0043FA60)
     *
     * CD3DDevice *,int,int,bool
     *
     * What it does:
     * Initializes vertex-buffer context metadata and clears retained buffer
     * ownership state.
     */
    CD3DVertexStream(CD3DDevice* device, std::uint32_t width, std::uint32_t strideBytes, bool dynamicUsage);

    /**
     * Address: 0x0043FAE0 (FUN_0043FAE0, deleting thunk)
     * Address: 0x0043FB50 (FUN_0043FB50, non-deleting body)
     *
     * What it does:
     * Releases retained vertex-buffer ownership and destroys embedded context state.
     */
    ~CD3DVertexStream() override;

    /**
     * Address: 0x0043FD60 (FUN_0043FD60)
     *
     * boost::shared_ptr<gpg::gal::VertexBufferD3D9> &
     *
     * What it does:
     * Copies retained vertex-buffer ownership into caller storage.
     */
    BufferHandle& GetBuffer(BufferHandle& outBuffer) override;

    /**
     * Address: 0x0043FDB0 (FUN_0043FDB0)
     *
     * int,int,bool,bool
     *
     * What it does:
     * Locks one vertex range using context stride and returns mapped data.
     */
    void* Lock(int startVertex, int vertexCount, bool readOnly, bool discard) override;

    /**
     * Address: 0x0043FE50 (FUN_0043FE50)
     *
     * What it does:
     * Unlocks the retained vertex buffer when present.
     */
    void Unlock() override;

    /**
     * Address: 0x0043FC20 (FUN_0043FC20)
     *
     * What it does:
     * Creates one gal vertex-buffer wrapper from retained context metadata.
     */
    bool CreateBuffer();

  public:
    CD3DDevice* mDevice;                   // +0x04
    gpg::gal::VertexBufferContext mContext; // +0x08
    BufferHandle mBuffer;                  // +0x1C
  };

  static_assert(sizeof(CD3DVertexStream::BufferHandle) == 0x08, "CD3DVertexStream::BufferHandle size must be 0x08");
  static_assert(offsetof(CD3DVertexStream, mDevice) == 0x04, "CD3DVertexStream::mDevice offset must be 0x04");
  static_assert(offsetof(CD3DVertexStream, mContext) == 0x08, "CD3DVertexStream::mContext offset must be 0x08");
  static_assert(offsetof(CD3DVertexStream, mBuffer) == 0x1C, "CD3DVertexStream::mBuffer offset must be 0x1C");
  static_assert(sizeof(CD3DVertexStream) == 0x24, "CD3DVertexStream size must be 0x24");
} // namespace moho
