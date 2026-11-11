// The material editor's DDS files (src/editor/graph/EdTextureBake.cpp), read back by the engine's own decoder.

#include "editor/graph/EdTextureBake.h"

#include "gpg/gal/backends/common/ImageCodec.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstring>

namespace
{
  using namespace faf::editor;

  /** A smooth tiling pattern with alpha (block compression keeps smooth images close). */
  TexImage Pattern(const int size)
  {
    TexImage image;
    image.Reset(size, 4);
    for (int y = 0; y < size; ++y) {
      for (int x = 0; x < size; ++x) {
        const float u = static_cast<float>(x) / static_cast<float>(size) * 6.2831853f;
        const float v = static_cast<float>(y) / static_cast<float>(size) * 6.2831853f;
        float* p = image.Pixel(x, y);
        p[0] = 0.5f + 0.4f * std::sin(u);
        p[1] = 0.5f + 0.4f * std::cos(v);
        p[2] = 0.3f;
        p[3] = 0.5f + 0.4f * std::sin(u + v);
      }
    }
    return image;
  }

  /** The worst channel difference between the DDS's top level, decoded to BGRA, and the image. */
  float Worst(const std::vector<std::uint8_t>& dds, const TexImage& image, std::uint32_t& mips, std::uint32_t& width)
  {
    gpg::gal::imaging::ImageCodec* codec = gpg::gal::imaging::ImageCodec::Instance();
    EXPECT_NE(codec, nullptr);
    if (codec == nullptr) {
      return 1.0f;
    }
    // The file's own shape first (its mip chain), then its top level as 32-bit pixels.
    gpg::gal::imaging::Image asFile;
    EXPECT_TRUE(SUCCEEDED(codec->Decode(dds.data(), dds.size(), gpg::gal::imaging::DecodeOptions{}, asFile)));
    mips = asFile.mipLevels;
    width = asFile.width;
    gpg::gal::imaging::DecodeOptions options;
    options.format = DXGI_FORMAT_B8G8R8A8_UNORM;
    options.mipLevels = 1;
    gpg::gal::imaging::Image decoded;
    EXPECT_TRUE(SUCCEEDED(codec->Decode(dds.data(), dds.size(), options, decoded)));
    if (decoded.subresources.empty()) {
      return 1.0f;
    }
    const auto& level = decoded.subresources.front();
    float worst = 0.0f;
    for (int y = 0; y < image.size; ++y) {
      const std::uint8_t* row = decoded.bytes.data() + level.offset + static_cast<std::size_t>(y) * level.rowPitch;
      for (int x = 0; x < image.size; ++x) {
        const float* p = image.Pixel(x, y);
        const std::uint8_t* d = row + static_cast<std::size_t>(x) * 4U;
        const float bgra[4] = {p[2], p[1], p[0], p[3]};
        for (int c = 0; c < 4; ++c) {
          worst = std::max(worst, std::fabs(static_cast<float>(d[c]) / 255.0f - bgra[c]));
        }
      }
    }
    return worst;
  }

  TEST(TextureBake, UncompressedReadsBackExactlyWithItsMips)
  {
    const TexImage image = Pattern(64);
    std::vector<std::uint8_t> dds;
    std::string error;
    ASSERT_TRUE(EncodeDds(image, DdsKind::Bgra, dds, error)) << error;
    ASSERT_GE(dds.size(), 128U);
    EXPECT_EQ(std::memcmp(dds.data(), "DDS ", 4), 0);
    std::uint32_t mips = 0;
    std::uint32_t width = 0;
    EXPECT_LE(Worst(dds, image, mips, width), 1.0f / 255.0f + 1e-4f);
    EXPECT_EQ(mips, 7U); // 64, 32, ... 1
    EXPECT_EQ(width, 64U);
  }

  TEST(TextureBake, Bc3KeepsTheImageAndItsAlphaClose)
  {
    const TexImage image = Pattern(128);
    std::vector<std::uint8_t> dds;
    std::string error;
    ASSERT_TRUE(EncodeDds(image, DdsKind::Bc3, dds, error)) << error;
    // The classic header: the game's Direct3D 9 decoder reads DXT5 by its FourCC, not a DX10 extension.
    EXPECT_EQ(std::memcmp(dds.data() + 84, "DXT5", 4), 0);
    std::uint32_t mips = 0;
    std::uint32_t width = 0;
    EXPECT_LT(Worst(dds, image, mips, width), 0.06f);
    EXPECT_EQ(mips, 8U);
  }

  TEST(TextureBake, Bc1ForOpaqueImages)
  {
    // As large as the BC3 test: block compression follows a gradient this smooth (at 32 px it changes 4x as fast per block).
    TexImage image = Pattern(128);
    for (int y = 0; y < 128; ++y) {
      for (int x = 0; x < 128; ++x) {
        image.Pixel(x, y)[3] = 1.0f;
      }
    }
    std::vector<std::uint8_t> dds;
    std::string error;
    ASSERT_TRUE(EncodeDds(image, DdsKind::Bc1, dds, error)) << error;
    EXPECT_EQ(std::memcmp(dds.data() + 84, "DXT1", 4), 0);
    std::uint32_t mips = 0;
    std::uint32_t width = 0;
    EXPECT_LT(Worst(dds, image, mips, width), 0.06f);
  }

  TEST(TextureBake, AGreyImageIsWrittenAsGreyRgb)
  {
    TexImage grey;
    grey.Reset(16, 1, 0.25f);
    TexImage rgba;
    rgba.Reset(16, 4);
    for (std::size_t i = 0; i < rgba.data.size(); i += 4) {
      rgba.data[i] = rgba.data[i + 1] = rgba.data[i + 2] = 0.25f;
      rgba.data[i + 3] = 1.0f;
    }
    std::vector<std::uint8_t> dds;
    std::string error;
    ASSERT_TRUE(EncodeDds(grey, DdsKind::Bgra, dds, error)) << error;
    std::uint32_t mips = 0;
    std::uint32_t width = 0;
    EXPECT_LE(Worst(dds, rgba, mips, width), 1.0f / 255.0f);
  }
} // namespace
