// FAF addition: BC1 to BC3 on the CPU against DirectXTex (gpg/gal/backends/common/BlockCompression.h and
// EncodeBc123WithDirectXTex): what the Vulkan backend reads back from a texture it decoded on the CPU decodes to
// the texels it came from, and the decode stays within DirectXTex's own. And which textures a Vulkan device without
// BC textures holds decoded (HeldTextureFormat and DecodedOnCpu, gpg/gal/backends/vulkan/VulkanCore.h).

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include <gtest/gtest.h>

#include "DirectXTex.h"
#include "gpg/gal/backends/common/BlockCompression.h"
#include "gpg/gal/backends/common/ImageCodecDirectXTex.h"
#include "gpg/gal/backends/dxgi/DxgiFormats.h"
#include "gpg/gal/backends/vulkan/VulkanCore.h"

namespace
{
  using gpg::gal::imaging::DecodeBc123;
  using gpg::gal::imaging::EncodeBc123WithDirectXTex;
  using gpg::gal::vulkan::DecodedOnCpu;
  using gpg::gal::vulkan::HeldTextureFormat;

  /** An 8x6 level BC encodes exactly: per 4x4 block two RGB565 colours, and alphas BC2 and BC3 keep as they are. */
  std::vector<std::uint8_t> ExactLevel(
    const DXGI_FORMAT format
  )
  {
    constexpr std::uint8_t kColours[4][3] = {{255U, 0U, 0U}, {0U, 0U, 255U}, {0U, 255U, 0U}, {255U, 255U, 255U}};
    std::vector<std::uint8_t> rgba;
    for (std::uint32_t y = 0U; y < 6U; ++y) {
      for (std::uint32_t x = 0U; x < 8U; ++x) {
        const std::uint32_t block = (y / 4U) * 2U + x / 4U;
        const std::uint8_t* const colour = kColours[(block + ((x + y) & 1U)) % 4U];
        std::uint8_t alpha = 255U;
        if (format == DXGI_FORMAT_BC2_UNORM) {
          alpha = static_cast<std::uint8_t>(((x + y * 8U) % 16U) * 17U);
        } else if (format == DXGI_FORMAT_BC3_UNORM_SRGB) {
          alpha = ((x + y) % 3U == 0U) ? 0U : 255U;
        }
        rgba.insert(rgba.end(), {colour[0], colour[1], colour[2], alpha});
      }
    }
    return rgba;
  }
} // namespace

TEST(
  BlockCompressionCodec,
  EncodedLevelsDecodeToTheTexelsTheyCameFrom
)
{
  for (const DXGI_FORMAT format : {DXGI_FORMAT_BC1_UNORM, DXGI_FORMAT_BC2_UNORM, DXGI_FORMAT_BC3_UNORM_SRGB}) {
    const std::vector<std::uint8_t> rgba = ExactLevel(format);
    const gpg::gal::dxgi::LevelLayout layout = gpg::gal::dxgi::ComputeLevelLayout(format, 8U, 6U);
    std::vector<std::uint8_t> blocks(layout.ByteSize(), 0xCDU);
    ASSERT_EQ(EncodeBc123WithDirectXTex(format, rgba.data(), 8U, 6U, blocks.data(), layout.rowPitch), S_OK) << format;
    std::vector<std::uint8_t> decoded(rgba.size(), 0xCDU);
    DecodeBc123(format, blocks.data(), layout.rowPitch, 8U, 6U, decoded.data());
    EXPECT_EQ(decoded, rgba) << "format " << format;
  }
  std::uint8_t block[8]{};
  const std::uint8_t texel[4]{};
  EXPECT_EQ(EncodeBc123WithDirectXTex(DXGI_FORMAT_BC4_UNORM, texel, 1U, 1U, block, sizeof(block)), E_INVALIDARG);
}

TEST(
  BlockCompressionCodec,
  DecodeIsWithinTwoOfDirectXTexs
)
{
  // DirectXTex interpolates in floats and rounds; Direct3D's decode weighs in 256ths and truncates.
  constexpr std::uint32_t kSize = 64U;
  std::uint32_t state = 12345U;
  for (const DXGI_FORMAT format : {DXGI_FORMAT_BC1_UNORM, DXGI_FORMAT_BC2_UNORM, DXGI_FORMAT_BC3_UNORM}) {
    const gpg::gal::dxgi::LevelLayout layout = gpg::gal::dxgi::ComputeLevelLayout(format, kSize, kSize);
    std::vector<std::uint8_t> blocks(layout.ByteSize());
    for (std::uint8_t& byte : blocks) {
      state = state * 1664525U + 1013904223U;
      byte = static_cast<std::uint8_t>(state >> 24U);
    }
    DirectX::Image image{};
    image.width = kSize;
    image.height = kSize;
    image.format = format;
    image.rowPitch = layout.rowPitch;
    image.slicePitch = blocks.size();
    image.pixels = blocks.data();
    DirectX::ScratchImage reference;
    ASSERT_EQ(DirectX::Decompress(image, DXGI_FORMAT_R8G8B8A8_UNORM, reference), S_OK);
    std::vector<std::uint8_t> decoded(static_cast<std::size_t>(kSize) * kSize * 4U);
    DecodeBc123(format, blocks.data(), layout.rowPitch, kSize, kSize, decoded.data());
    int largest = 0;
    for (std::size_t index = 0U; index < decoded.size(); ++index) {
      largest = std::max(largest, std::abs(int{decoded[index]} - int{reference.GetPixels()[index]}));
    }
    EXPECT_LE(largest, 2) << "format " << format;
  }
}

TEST(
  BlockCompressionCodec,
  OnlyBc1ToBc3AreHeldDecodedWithoutBcTextures
)
{
  struct Held
  {
    DXGI_FORMAT format;
    VkFormat withBc;    // as ToVulkanTexture maps it
    VkFormat withoutBc; // on a device without BC textures
  };
  // BC1 to BC3 in each of their forms: R8G8B8A8 of their encoding, which the uploads decode into. BC4 and up stay
  // as they are (their textures fail to load without BC textures), as do formats that are not BC.
  constexpr Held kHeld[] = {
    {DXGI_FORMAT_BC1_TYPELESS, VK_FORMAT_BC1_RGBA_UNORM_BLOCK, VK_FORMAT_R8G8B8A8_UNORM},
    {DXGI_FORMAT_BC1_UNORM, VK_FORMAT_BC1_RGBA_UNORM_BLOCK, VK_FORMAT_R8G8B8A8_UNORM},
    {DXGI_FORMAT_BC1_UNORM_SRGB, VK_FORMAT_BC1_RGBA_SRGB_BLOCK, VK_FORMAT_R8G8B8A8_SRGB},
    {DXGI_FORMAT_BC2_UNORM, VK_FORMAT_BC2_UNORM_BLOCK, VK_FORMAT_R8G8B8A8_UNORM},
    {DXGI_FORMAT_BC2_UNORM_SRGB, VK_FORMAT_BC2_SRGB_BLOCK, VK_FORMAT_R8G8B8A8_SRGB},
    {DXGI_FORMAT_BC3_UNORM, VK_FORMAT_BC3_UNORM_BLOCK, VK_FORMAT_R8G8B8A8_UNORM},
    {DXGI_FORMAT_BC3_UNORM_SRGB, VK_FORMAT_BC3_SRGB_BLOCK, VK_FORMAT_R8G8B8A8_SRGB},
    {DXGI_FORMAT_BC4_UNORM, VK_FORMAT_BC4_UNORM_BLOCK, VK_FORMAT_BC4_UNORM_BLOCK},
    {DXGI_FORMAT_BC5_UNORM, VK_FORMAT_BC5_UNORM_BLOCK, VK_FORMAT_BC5_UNORM_BLOCK},
    {DXGI_FORMAT_BC7_UNORM, VK_FORMAT_BC7_UNORM_BLOCK, VK_FORMAT_BC7_UNORM_BLOCK},
    {DXGI_FORMAT_R8G8B8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM},
  };
  for (const Held& held : kHeld) {
    EXPECT_EQ(HeldTextureFormat(held.format, true).format, held.withBc) << "format " << held.format;
    EXPECT_EQ(HeldTextureFormat(held.format, false).format, held.withoutBc) << "format " << held.format;
    // Uploads decode and readbacks encode only a BC1 to BC3 texture's R8G8B8A8 image.
    EXPECT_EQ(DecodedOnCpu(held.format, held.withoutBc), held.withoutBc != held.withBc) << "format " << held.format;
    EXPECT_FALSE(DecodedOnCpu(held.format, held.withBc)) << "format " << held.format;
  }
}
