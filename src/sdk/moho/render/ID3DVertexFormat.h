#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class VertexFormatD3D9;
}

namespace moho
{
  class ID3DVertexFormat
  {
  public:
    using FormatHandle = boost::shared_ptr<gpg::gal::VertexFormatD3D9>;

    /**
     * Address: 0x0043F420 (FUN_0043F420, sub_43F420)
     *
     * What it does:
     * Initializes the base interface vftable lane for derived vertex formats.
     */
    ID3DVertexFormat();

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Returns the number of 32-bit vertex-element tokens retained by this format.
     */
    virtual std::uint32_t GetElementCount() const = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * std::uint32_t
     *
     * What it does:
     * Returns one packed vertex-element token by element index.
     */
    virtual std::uint32_t GetElement(std::uint32_t elementIndex) const = 0;

    /**
     * Address: 0x00A82547 (_purecall slot)
     *
     * What it does:
     * Binds this format's retained declaration on the active gal device.
     */
    virtual bool SetVertexDeclaration() = 0;
  };

  static_assert(sizeof(ID3DVertexFormat) == 0x04, "ID3DVertexFormat size must be 0x04");
} // namespace moho
