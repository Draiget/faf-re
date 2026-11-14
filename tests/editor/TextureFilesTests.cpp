#include "editor/tools/EdTextureFiles.h"

#include <gtest/gtest.h>

namespace faf::editor
{
  TEST(
    TextureFiles,
    ReliefLightsTheNorthWestSlopes
  )
  {
    // Flat (128, 128), a normal leaning west (low red), one leaning east (high red); x in red.
    std::vector<std::uint32_t> pixels{0xFF8080FFu, 0xFF2080FFu, 0xFFE080FFu, 0xFF8080FFu};
    NormalRelief(pixels);
    const auto grey = [&](const std::size_t i) {
      return pixels[i] & 0xFFu;
    };
    EXPECT_EQ(pixels[0] >> 24, 0xFFu);
    EXPECT_EQ((pixels[0] >> 16) & 0xFFu, grey(0)) << "grey";
    EXPECT_GT(grey(1), grey(0)) << "facing the light (west)";
    EXPECT_LT(grey(2), grey(0)) << "facing away";
    // The DXT5 packing: red flat, x in alpha.
    std::vector<std::uint32_t> packed{0x80FF80FFu, 0x20FF80FFu, 0xE0FF80FFu, 0x80FF80FFu};
    NormalRelief(packed);
    EXPECT_GT(packed[1] & 0xFFu, packed[0] & 0xFFu);
    EXPECT_LT(packed[2] & 0xFFu, packed[0] & 0xFFu);
  }

  TEST(
    TextureFiles,
    MaskSetNames
  )
  {
    EXPECT_EQ(MaskSetFile("C:/x/masks.png", 0), std::filesystem::path("C:/x/masks_1.png"));
    EXPECT_EQ(MaskSetFile("C:/x/masks_3.png", 7), std::filesystem::path("C:/x/masks_8.png"));
    EXPECT_EQ(MaskSetBase("C:/x/masks_5.png"), std::filesystem::path("C:/x/masks.png"));
    EXPECT_EQ(MaskSetBase("C:/x/masks_9.png"), std::filesystem::path("C:/x/masks_9.png")) << "not a stratum";
    EXPECT_EQ(MaskSetBase("C:/x/plain.raw"), std::filesystem::path("C:/x/plain.raw"));
  }
} // namespace faf::editor
