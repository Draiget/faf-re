#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class IndexBufferD3D9;
}

namespace moho
{
  class CD3DDevice;

  class ID3DIndexSheet
  {
  public:
    using BufferHandle = boost::shared_ptr<gpg::gal::IndexBufferD3D9>;

    /**
     * Address: 0x0043F5D0 (FUN_0043F5D0, sub_43F5D0)
     *
     * What it does:
     * Initializes the base interface vftable lane for derived index sheets.
     */
    ID3DIndexSheet();

    /**
     * Address: 0x0043CD50 (FUN_0043CD50, sub_43CD50)
     *
     * What it does:
     * Resets base vftable state and owns the deleting-destructor entrypoint.
     */
    virtual ~ID3DIndexSheet();

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Deletes this wrapper through the virtual destructor path.
     */
    virtual void Destroy() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns the owning D3D device wrapper lane.
     */
    virtual CD3DDevice* GetDevice() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns whether the retained index-buffer lane is in non-default mode.
     */
    virtual bool Func3() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * boost::shared_ptr<gpg::gal::IndexBufferD3D9> &
     *
     * What it does:
     * Copies one index-buffer ownership lane into caller storage.
     */
    virtual BufferHandle& GetBuffer(BufferHandle& outBuffer) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns the retained index count.
     */
    virtual std::uint32_t GetSize() const = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * std::uint32_t
     *
     * What it does:
     * Updates retained index count and recreates backing buffer as needed.
     */
    virtual bool SetSize(std::uint32_t size) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * std::uint32_t,std::uint32_t,bool,bool
     *
     * What it does:
     * Locks one index-buffer byte range derived from index stride.
     */
    virtual std::int16_t* Lock(std::uint32_t startIndex, std::uint32_t indexCount, bool readOnly, bool discard) = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Unlocks the active index-buffer lock lane when present.
     */
    virtual void Unlock() = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Binds the retained index buffer on the active gal device.
     */
    virtual void SetBufferIndices() = 0;
  };

  static_assert(sizeof(ID3DIndexSheet) == 0x04, "ID3DIndexSheet size must be 0x04");
} // namespace moho
