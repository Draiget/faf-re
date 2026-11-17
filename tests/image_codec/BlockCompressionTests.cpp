// FAF addition: gpg/gal/backends/common/BlockCompression.h, BC1 to BC3 decoded on the CPU for a Vulkan device
// without BC textures. The blocks are written here by the Direct3D 11 functional specification's layout: BC1 is
// two RGB565 endpoints (little-endian) and 16 two-bit indices, texel 0 in the lowest bits; BC2 puts 16 four-bit
// alphas before such a colour block, BC3 two alpha endpoints and 16 three-bit indices.

#include "gpg/gal/backends/common/BlockCompression.h"

#include <array>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

namespace
{
  using gpg::gal::imaging::DecodeBc123;
  using gpg::gal::imaging::IsBc123;

  using Texel = std::array<std::uint8_t, 4>;

  constexpr std::uint16_t kRed565 = 0xF800U;
  constexpr std::uint16_t kBlue565 = 0x001FU;

  /** A colour block whose texel i takes index i % 4. */
  std::array<std::uint8_t, 8> ColourBlock(
    const std::uint16_t c0,
    const std::uint16_t c1
  )
  {
    return {
      static_cast<std::uint8_t>(c0 & 0xFFU),
      static_cast<std::uint8_t>(c0 >> 8U),
      static_cast<std::uint8_t>(c1 & 0xFFU),
      static_cast<std::uint8_t>(c1 >> 8U),
      0xE4U,
      0xE4U,
      0xE4U,
      0xE4U,
    };
  }

  /** A block of one colour: every texel takes index 0. */
  std::array<std::uint8_t, 8> SolidBlock(
    const std::uint16_t colour
  )
  {
    std::array<std::uint8_t, 8> block = ColourBlock(colour, colour);
    block[4] = block[5] = block[6] = block[7] = 0U;
    return block;
  }

  /** The texels of one decoded 4x4 level. */
  std::vector<Texel> DecodeBlock(
    const DXGI_FORMAT format,
    const std::vector<std::uint8_t>& block
  )
  {
    std::vector<std::uint8_t> rgba(16U * 4U, 0xCDU);
    DecodeBc123(format, block.data(), block.size(), 4U, 4U, rgba.data());
    std::vector<Texel> texels(16U);
    for (std::size_t texel = 0U; texel < 16U; ++texel) {
      for (std::size_t channel = 0U; channel < 4U; ++channel) {
        texels[texel][channel] = rgba[texel * 4U + channel];
      }
    }
    return texels;
  }
} // namespace

TEST(
  BlockCompression,
  Bc1WithTheGreaterEndpointFirstHasFourColours
)
{
  const std::array<std::uint8_t, 8> block = ColourBlock(kRed565, kBlue565);
  const std::vector<Texel> texels = DecodeBlock(DXGI_FORMAT_BC1_UNORM, {block.begin(), block.end()});
  // The endpoints expand by repeating their top bits; the colours between are 171 and 85 of 256 of each, truncated.
  EXPECT_EQ(texels[0], (Texel{255U, 0U, 0U, 255U}));
  EXPECT_EQ(texels[1], (Texel{0U, 0U, 255U, 255U}));
  EXPECT_EQ(texels[2], (Texel{170U, 0U, 84U, 255U}));
  EXPECT_EQ(texels[3], (Texel{84U, 0U, 170U, 255U}));
  EXPECT_EQ(texels[15], texels[3]);
}

TEST(
  BlockCompression,
  Bc1WithTheLesserEndpointFirstHasThreeColoursAndTransparentBlack
)
{
  const std::array<std::uint8_t, 8> block = ColourBlock(kBlue565, kRed565);
  const std::vector<Texel> texels = DecodeBlock(DXGI_FORMAT_BC1_UNORM_SRGB, {block.begin(), block.end()});
  EXPECT_EQ(texels[0], (Texel{0U, 0U, 255U, 255U}));
  EXPECT_EQ(texels[1], (Texel{255U, 0U, 0U, 255U}));
  EXPECT_EQ(texels[2], (Texel{127U, 0U, 127U, 255U})) << "the truncated mean";
  EXPECT_EQ(texels[3], (Texel{0U, 0U, 0U, 0U}));
}

TEST(
  BlockCompression,
  Bc2HasFourBitAlphasAndAlwaysFourColours
)
{
  std::vector<std::uint8_t> block;
  for (std::uint32_t pair = 0U; pair < 8U; ++pair) {
    block.push_back(static_cast<std::uint8_t>((pair * 2U) | ((pair * 2U + 1U) << 4U))); // texel i: alpha i
  }
  const std::array<std::uint8_t, 8> colours = ColourBlock(kBlue565, kRed565);
  block.insert(block.end(), colours.begin(), colours.end());
  const std::vector<Texel> texels = DecodeBlock(DXGI_FORMAT_BC2_UNORM, block);
  for (std::uint32_t texel = 0U; texel < 16U; ++texel) {
    EXPECT_EQ(texels[texel][3], texel * 17U) << "texel " << texel;
  }
  // The lesser endpoint first, as in the three-colour BC1 block above, still gives four colours.
  EXPECT_EQ(texels[2], (Texel{84U, 0U, 170U, 34U}));
  EXPECT_EQ(texels[3], (Texel{170U, 0U, 84U, 51U}));
}

TEST(
  BlockCompression,
  Bc3AlphasAreTheRoundedMeansOfItsEndpoints
)
{
  // Texel i takes alpha index i % 8: three bits each, texel 0 in the lowest bits of bytes 2 to 7.
  std::uint64_t indices = 0U;
  for (std::uint32_t texel = 0U; texel < 16U; ++texel) {
    indices |= static_cast<std::uint64_t>(texel % 8U) << (texel * 3U);
  }
  const auto block = [&](const std::uint8_t a0, const std::uint8_t a1) {
    std::vector<std::uint8_t> bytes{a0, a1};
    for (int byte = 0; byte < 6; ++byte) {
      bytes.push_back(static_cast<std::uint8_t>(indices >> (byte * 8)));
    }
    const std::array<std::uint8_t, 8> colours = ColourBlock(kRed565, kBlue565);
    bytes.insert(bytes.end(), colours.begin(), colours.end());
    return bytes;
  };
  // The greater endpoint first: six alphas between, in sevenths.
  std::vector<Texel> texels = DecodeBlock(DXGI_FORMAT_BC3_UNORM, block(255U, 0U));
  const std::uint8_t eight[8] = {255U, 0U, 219U, 182U, 146U, 109U, 73U, 36U};
  for (std::uint32_t texel = 0U; texel < 16U; ++texel) {
    EXPECT_EQ(texels[texel][3], eight[texel % 8U]) << "texel " << texel;
  }
  EXPECT_EQ(texels[2], (Texel{170U, 0U, 84U, 219U}));
  // The lesser first: four alphas between, in fifths, then 0 and 255.
  texels = DecodeBlock(DXGI_FORMAT_BC3_TYPELESS, block(0U, 255U));
  const std::uint8_t six[8] = {0U, 255U, 51U, 102U, 153U, 204U, 0U, 255U};
  for (std::uint32_t texel = 0U; texel < 16U; ++texel) {
    EXPECT_EQ(texels[texel][3], six[texel % 8U]) << "texel " << texel;
  }
}

TEST(
  BlockCompression,
  PartialBlocksWriteOnlyTheLevelsTexels
)
{
  // A 5x3 level: two blocks in a row of 16 bytes, of which the second has one column inside the level.
  const std::array<std::uint8_t, 8> red = SolidBlock(kRed565);
  const std::array<std::uint8_t, 8> blue = SolidBlock(kBlue565);
  std::vector<std::uint8_t> blocks(red.begin(), red.end());
  blocks.insert(blocks.end(), blue.begin(), blue.end());
  std::vector<std::uint8_t> rgba(5U * 3U * 4U + 4U, 0xCDU);
  DecodeBc123(DXGI_FORMAT_BC1_UNORM, blocks.data(), blocks.size(), 5U, 3U, rgba.data());
  for (std::uint32_t y = 0U; y < 3U; ++y) {
    for (std::uint32_t x = 0U; x < 5U; ++x) {
      const std::uint8_t* const texel = rgba.data() + (y * 5U + x) * 4U;
      EXPECT_EQ(texel[0], (x < 4U) ? 255U : 0U) << x << "," << y;
      EXPECT_EQ(texel[2], (x < 4U) ? 0U : 255U) << x << "," << y;
    }
  }
  EXPECT_EQ(rgba[5U * 3U * 4U], 0xCDU) << "nothing past the level";

  // A 1x1 level, as the last mip.
  std::vector<std::uint8_t> one(4U + 4U, 0xCDU);
  DecodeBc123(DXGI_FORMAT_BC1_UNORM, blue.data(), blue.size(), 1U, 1U, one.data());
  EXPECT_EQ(one, (std::vector<std::uint8_t>{0U, 0U, 255U, 255U, 0xCDU, 0xCDU, 0xCDU, 0xCDU}));
}

TEST(
  BlockCompression,
  OnlyBc1ToBc3AreDecoded
)
{
  for (const DXGI_FORMAT format :
       {DXGI_FORMAT_BC1_TYPELESS,
        DXGI_FORMAT_BC1_UNORM,
        DXGI_FORMAT_BC1_UNORM_SRGB,
        DXGI_FORMAT_BC2_UNORM,
        DXGI_FORMAT_BC3_UNORM_SRGB}) {
    EXPECT_TRUE(IsBc123(format)) << format;
  }
  for (const DXGI_FORMAT format :
       {DXGI_FORMAT_BC4_UNORM,
        DXGI_FORMAT_BC5_UNORM,
        DXGI_FORMAT_BC7_UNORM,
        DXGI_FORMAT_R8G8B8A8_UNORM,
        DXGI_FORMAT_UNKNOWN}) {
    EXPECT_FALSE(IsBc123(format)) << format;
  }
}
