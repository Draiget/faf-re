#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace gpg::gal::imaging
{
  /**
   * How many top mip levels texture quality drops from this file, as the original's D3DX9 load
   * does. The 2D call passes D3DX_SKIP_DDS_MIP_LEVELS (0x008EB42A..0x008EB455); cubes and volumes
   * get no skip (0x008EB131, 0x008EB291). Measured on d3dx9_35 with that call: only a 2D DDS with
   * more than one level is skipped, by at most its level count minus one, and the levels left are
   * the whole load's levels byte for byte. A one-level DDS and every other format load whole.
   * Do not alter resizing or explicit mip limits.
   */
  [[nodiscard]] inline std::uint32_t TextureQualityMipLevels(
    const void* const data, const std::size_t bytes, const std::uint32_t requestedSkip
  ) noexcept
  {
    if (requestedSkip == 0U || data == nullptr || bytes < 128U) {
      return 0U;
    }
    const auto* const source = static_cast<const std::uint8_t*>(data);
    const auto word = [source](const std::size_t offset) {
      std::uint32_t value;
      std::memcpy(&value, source + offset, sizeof(value));
      return value;
    };
    if (word(0U) != 0x20534444U) { // DDS magic
      return 0U;
    }
    // DX10's topology supersedes legacy caps2. Only interpret the extension
    // when the pixel format declares a FourCC and the whole extension exists.
    if (bytes >= 148U && (word(80U) & 0x4U) != 0U && word(84U) == 0x30315844U) {
      const std::uint32_t dimension = word(132U);
      const std::uint32_t miscFlags = word(136U);
      if (dimension == 4U || (miscFlags & 0x4U) != 0U) {
        return 0U;
      }
    } else if ((word(112U) & (0x200U | 0x200000U)) != 0U) {
      // Avoid stricter header validation than D3DX: it owns format validation.
      return 0U;
    }
    const std::uint32_t levels = (word(8U) & 0x20000U) != 0U ? word(28U) : 1U; // DDSD_MIPMAPCOUNT
    return levels > 1U ? std::min(requestedSkip, levels - 1U) : 0U;
  }
}
