#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/render/ID3DVertexFormat.h"

namespace moho
{
  class CD3DVertexFormat : public ID3DVertexFormat
  {
  public:
    using FormatHandle = ID3DVertexFormat::FormatHandle;

    /**
     * Address: 0x0043CFC0 (FUN_0043CFC0)
     *
     * std::uint32_t
     *
     * What it does:
     * Requests one gal vertex-format wrapper for the incoming format token and
     * stores retained ownership.
     */
    explicit CD3DVertexFormat(std::uint32_t formatCode);

    /**
     * Address: 0x0043F430 (FUN_0043F430)
     *
     * What it does:
     * Returns the number of retained 32-bit vertex-element tokens.
     */
    std::uint32_t GetElementCount() const override;

    /**
     * Address: 0x0043F450 (FUN_0043F450)
     *
     * std::uint32_t
     *
     * What it does:
     * Returns one retained vertex-element token by index.
     */
    std::uint32_t GetElement(std::uint32_t elementIndex) const override;

    /**
     * Address: 0x0043F460 (FUN_0043F460)
     *
     * What it does:
     * Binds the retained vertex declaration on the active gal device.
     */
    bool SetVertexDeclaration() override;

  public:
    FormatHandle mFormat; // +0x04
  };

  static_assert(
    sizeof(CD3DVertexFormat::FormatHandle) == 0x08, "CD3DVertexFormat::FormatHandle size must be 0x08"
  );
  static_assert(offsetof(CD3DVertexFormat, mFormat) == 0x04, "CD3DVertexFormat::mFormat offset must be 0x04");
  static_assert(sizeof(CD3DVertexFormat) == 0x0C, "CD3DVertexFormat size must be 0x0C");
} // namespace moho
