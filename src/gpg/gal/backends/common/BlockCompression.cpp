// FAF addition, not in the shipped binary: see BlockCompression.h.

#include "BlockCompression.h"

#include <algorithm>
#include <cstring>

namespace gpg::gal::imaging
{
  namespace
  {
    [[nodiscard]] std::uint32_t Read16(
      const std::uint8_t* const at
    ) noexcept
    {
      return static_cast<std::uint32_t>(at[0]) | (static_cast<std::uint32_t>(at[1]) << 8U);
    }

    [[nodiscard]] std::uint32_t Expand5(
      const std::uint32_t value
    ) noexcept
    {
      return (value << 3U) | (value >> 2U);
    }

    [[nodiscard]] std::uint32_t Expand6(
      const std::uint32_t value
    ) noexcept
    {
      return (value << 2U) | (value >> 4U);
    }

    /**
     * A colour block's 16 texels as R8G8B8A8, texel i at rgba[i * 4]. A BC1 block whose first endpoint is not
     * greater than the second has three colours and transparent black; inside BC2 and BC3 the colour block
     * always has four colours (`threeColours` false).
     */
    void DecodeColourBlock(
      const std::uint8_t* const block,
      const bool threeColours,
      std::uint8_t* const rgba
    ) noexcept
    {
      const std::uint32_t c0 = Read16(block);
      const std::uint32_t c1 = Read16(block + 2);
      const std::uint32_t r0 = Expand5(c0 >> 11U);
      const std::uint32_t g0 = Expand6((c0 >> 5U) & 63U);
      const std::uint32_t b0 = Expand5(c0 & 31U);
      const std::uint32_t r1 = Expand5(c1 >> 11U);
      const std::uint32_t g1 = Expand6((c1 >> 5U) & 63U);
      const std::uint32_t b1 = Expand5(c1 & 31U);
      // Two thirds of one and a third of the other: 171 and 85 of 256, truncated. A half is the truncated mean.
      const auto third = [](const std::uint32_t mostly, const std::uint32_t partly) {
        return static_cast<std::uint8_t>((mostly * 171U + partly * 85U) >> 8U);
      };
      std::uint8_t palette[4][4] = {
        {static_cast<std::uint8_t>(r0), static_cast<std::uint8_t>(g0), static_cast<std::uint8_t>(b0), 255U},
        {static_cast<std::uint8_t>(r1), static_cast<std::uint8_t>(g1), static_cast<std::uint8_t>(b1), 255U},
      };
      if (c0 > c1 || !threeColours) {
        const std::uint8_t two[4] = {third(r0, r1), third(g0, g1), third(b0, b1), 255U};
        const std::uint8_t three[4] = {third(r1, r0), third(g1, g0), third(b1, b0), 255U};
        std::memcpy(palette[2], two, 4U);
        std::memcpy(palette[3], three, 4U);
      } else {
        const std::uint8_t half[4] = {
          static_cast<std::uint8_t>((r0 + r1) / 2U),
          static_cast<std::uint8_t>((g0 + g1) / 2U),
          static_cast<std::uint8_t>((b0 + b1) / 2U),
          255U,
        };
        std::memcpy(palette[2], half, 4U);
        std::memset(palette[3], 0, 4U);
      }
      const std::uint32_t indices = Read16(block + 4) | (Read16(block + 6) << 16U);
      for (std::uint32_t texel = 0U; texel < 16U; ++texel) {
        std::memcpy(rgba + texel * 4U, palette[(indices >> (texel * 2U)) & 3U], 4U);
      }
    }

    /** BC3's alpha block into the alpha bytes of 16 R8G8B8A8 texels. */
    void DecodeAlphaBlock(
      const std::uint8_t* const block,
      std::uint8_t* const rgba
    ) noexcept
    {
      const std::uint32_t a0 = block[0];
      const std::uint32_t a1 = block[1];
      std::uint32_t palette[8] = {a0, a1};
      if (a0 > a1) {
        for (std::uint32_t step = 1U; step < 7U; ++step) {
          palette[step + 1U] = ((7U - step) * a0 + step * a1 + 3U) / 7U;
        }
      } else {
        for (std::uint32_t step = 1U; step < 5U; ++step) {
          palette[step + 1U] = ((5U - step) * a0 + step * a1 + 2U) / 5U;
        }
        palette[6] = 0U;
        palette[7] = 255U;
      }
      std::uint64_t indices = 0U;
      for (int byte = 7; byte >= 2; --byte) {
        indices = (indices << 8U) | block[byte];
      }
      for (std::uint32_t texel = 0U; texel < 16U; ++texel) {
        rgba[texel * 4U + 3U] = static_cast<std::uint8_t>(palette[(indices >> (texel * 3U)) & 7U]);
      }
    }
  } // namespace

  bool IsBc123(
    const DXGI_FORMAT format
  ) noexcept
  {
    return format >= DXGI_FORMAT_BC1_TYPELESS && format <= DXGI_FORMAT_BC3_UNORM_SRGB;
  }

  void DecodeBc123(
    const DXGI_FORMAT format,
    const void* const blocks,
    const std::size_t rowPitch,
    const std::uint32_t width,
    const std::uint32_t height,
    std::uint8_t* const rgba
  ) noexcept
  {
    const bool bc1 = format <= DXGI_FORMAT_BC1_UNORM_SRGB;
    const bool bc2 = format >= DXGI_FORMAT_BC2_TYPELESS && format <= DXGI_FORMAT_BC2_UNORM_SRGB;
    const std::size_t blockBytes = bc1 ? 8U : 16U;
    std::uint8_t texels[16U * 4U];
    for (std::uint32_t blockY = 0U; blockY * 4U < height; ++blockY) {
      const auto* const row = static_cast<const std::uint8_t*>(blocks) + blockY * rowPitch;
      for (std::uint32_t blockX = 0U; blockX * 4U < width; ++blockX) {
        const std::uint8_t* const block = row + blockX * blockBytes;
        if (bc1) {
          DecodeColourBlock(block, true, texels);
        } else {
          DecodeColourBlock(block + 8, false, texels);
          if (bc2) {
            // Four bits of alpha per texel, scaled to 8 by repeating them.
            for (std::uint32_t texel = 0U; texel < 16U; ++texel) {
              texels[texel * 4U + 3U] =
                static_cast<std::uint8_t>(((block[texel / 2U] >> ((texel & 1U) * 4U)) & 15U) * 17U);
            }
          } else {
            DecodeAlphaBlock(block, texels);
          }
        }
        const std::uint32_t columns = std::min(4U, width - blockX * 4U);
        for (std::uint32_t y = 0U; y < 4U && blockY * 4U + y < height; ++y) {
          std::memcpy(
            rgba + (static_cast<std::size_t>(blockY * 4U + y) * width + blockX * 4U) * 4U,
            texels + y * 16U,
            columns * 4U
          );
        }
      }
    }
  }
} // namespace gpg::gal::imaging
