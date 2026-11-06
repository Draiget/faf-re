#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace gpg::gal::imaging
{
  /**
   * The original D3D9 loader applies texture quality's DDS mip skip only to
   * 2D textures. Cubes and volumes use D3DX_DEFAULT, including their top mip.
   * Inspect the resource kind before direct decode and cache lookup as well as
   * D3DX loading. Do not alter 2D quality, resizing, or explicit mip limits.
   */
  [[nodiscard]] inline std::uint32_t TextureQualityMipLevels(
    const void* const data, const std::size_t bytes, const std::uint32_t requestedSkip
  ) noexcept
  {
    if (requestedSkip == 0U || data == nullptr || bytes < 128U) {
      return requestedSkip;
    }
    const auto* const source = static_cast<const std::uint8_t*>(data);
    const auto word = [source](const std::size_t offset) {
      std::uint32_t value;
      std::memcpy(&value, source + offset, sizeof(value));
      return value;
    };
    if (word(0U) != 0x20534444U) { // DDS magic
      return requestedSkip;
    }
    // DX10's topology supersedes legacy caps2. Only interpret the extension
    // when the pixel format declares a FourCC and the whole extension exists.
    if (bytes >= 148U && (word(80U) & 0x4U) != 0U && word(84U) == 0x30315844U) {
      const std::uint32_t dimension = word(132U);
      const std::uint32_t miscFlags = word(136U);
      return dimension == 4U || (miscFlags & 0x4U) != 0U ? 0U : requestedSkip;
    }
    // Avoid stricter header validation than D3DX: it owns format validation.
    return (word(112U) & (0x200U | 0x200000U)) != 0U ? 0U : requestedSkip;
  }
}
