#pragma once

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class VertexBufferD3D9;
}

namespace moho
{
  class ID3DVertexStream
  {
  public:
    using BufferHandle = boost::shared_ptr<gpg::gal::VertexBufferD3D9>;

    /**
     * Address: 0x0043FB00 (FUN_0043FB00, sub_43FB00)
     *
     * What it does:
     * Initializes the base interface vftable lane for derived vertex streams.
     */
    ID3DVertexStream();

    /**
     * Address: 0x0043CCF0 (FUN_0043CCF0, sub_43CCF0)
     *
     * What it does:
     * Resets base vftable state and owns the deleting-destructor entrypoint.
     */
    virtual ~ID3DVertexStream();

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * boost::shared_ptr<gpg::gal::VertexBufferD3D9> &
     *
     * What it does:
     * Copies one vertex-buffer ownership lane into caller storage.
     */
    virtual BufferHandle& GetBuffer(BufferHandle& outBuffer) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * int,int,bool,bool
     *
     * What it does:
     * Locks one vertex-buffer byte range derived from stream element stride.
     */
    virtual void* Lock(int startVertex, int vertexCount, bool readOnly, bool discard) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Unlocks the active vertex-buffer lock lane when present.
     */
    virtual void Unlock() = 0;
  };

  static_assert(sizeof(ID3DVertexStream) == 0x04, "ID3DVertexStream size must be 0x04");
} // namespace moho
