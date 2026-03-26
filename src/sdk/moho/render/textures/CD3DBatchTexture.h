#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E02A84
   * COL: 0x00E5FBF0
   */
  class CD3DBatchTexture
  {
  public:
    /**
     * Address: 0x00447170 (Moho::CD3DBatchTexture::dtr)
     *
     * What it does:
     * Releases one batch-texture object through its virtual ownership chain.
     */
    virtual ~CD3DBatchTexture();

    /**
     * Address: 0x004478C0 (?FromSolidColor@CD3DBatchTexture@Moho@@SA?AV?$shared_ptr@VCD3DBatchTexture@Moho@@@boost@@I@Z)
     *
     * What it does:
     * Returns a shared batch-texture handle for a solid RGBA color.
     */
    [[nodiscard]] static boost::shared_ptr<CD3DBatchTexture> FromSolidColor(std::uint32_t rgba);
  };
} // namespace moho
