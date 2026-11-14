#include "editor/tools/EdUnitIcon.h"

#include <gtest/gtest.h>

#include <vector>

namespace faf::editor
{
  TEST(
    UnitIcon,
    TheDrawnPartIsFramedAndAveraged
  )
  {
    // A 16 x 16 render: a 4 x 2 red block (opaque) at x 6..9, y 7..8; the rest clear.
    constexpr int kSide = 16;
    std::vector<std::uint32_t> render(kSide * kSide, 0U);
    for (int y = 7; y <= 8; ++y) {
      for (int x = 6; x <= 9; ++x) {
        render[y * kSide + x] = 0xFFFF0000u; // A 255, R 255
      }
    }
    const IconBox box = AlphaBox(render.data(), kSide);
    EXPECT_FALSE(box.empty);
    EXPECT_EQ(box.x0, 6);
    EXPECT_EQ(box.x1, 9);
    EXPECT_EQ(box.y0, 7);
    EXPECT_EQ(box.y1, 8);
    // Filling the whole icon: the 4-pixel span, centred on (8, 8), at 4 x 4: two rows of red in the middle.
    const std::vector<float> icon = IconPixels(render.data(), kSide, 4, 1.0f);
    ASSERT_EQ(icon.size(), 4U * 4U * 4U);
    const auto px = [&](const int x, const int y) {
      return &icon[(y * 4 + x) * 4];
    };
    EXPECT_FLOAT_EQ(px(0, 1)[0], 1.0f) << "red";
    EXPECT_FLOAT_EQ(px(0, 1)[1], 0.0f);
    EXPECT_FLOAT_EQ(px(0, 1)[3], 1.0f);
    EXPECT_FLOAT_EQ(px(3, 2)[3], 1.0f);
    EXPECT_FLOAT_EQ(px(0, 0)[3], 0.0f) << "above the block: clear";
    EXPECT_FLOAT_EQ(px(0, 3)[3], 0.0f);
    // Half the icon: each icon pixel covers 2 x 2 render pixels; the edge ones average with clear.
    const std::vector<float> half = IconPixels(render.data(), kSide, 4, 0.5f);
    ASSERT_EQ(half.size(), 64U);
    float total = 0.0f;
    for (int i = 0; i < 16; ++i) {
      total += half[i * 4 + 3];
    }
    EXPECT_NEAR(total, 8.0f / 4.0f, 1e-5f) << "8 drawn pixels, 4 render pixels an icon pixel";
    EXPECT_FLOAT_EQ(half[(1 * 4 + 1) * 4 + 0], 1.0f) << "colour isn't darkened by the clear part";
    // Nothing drawn: no icon.
    std::vector<std::uint32_t> clear(kSide * kSide, 0x00FFFFFFu);
    EXPECT_TRUE(AlphaBox(clear.data(), kSide).empty);
    EXPECT_TRUE(IconPixels(clear.data(), kSide, 4, 0.9f).empty());
  }

  TEST(
    UnitIcon,
    RendersThatCantBeIconsSayWhy
  )
  {
    constexpr int kSide = 8;
    std::vector<std::uint32_t> render(kSide * kSide, 0U);
    EXPECT_EQ(IconRenderProblem(render.data(), kSide, 0.08f), "the model drew nothing");
    render[3 * kSide + 3] = 0xFFC0C0C0u;
    EXPECT_EQ(IconRenderProblem(render.data(), kSide, 0.08f), "");
    render[3 * kSide + 3] = 0xFF000008u; // a navy so dark it's black
    EXPECT_EQ(IconRenderProblem(render.data(), kSide, 0.08f).rfind("the render is too dark", 0), 0U);
    std::vector<std::uint32_t> opaque(kSide * kSide, 0xFF000000u);
    opaque[3 * kSide + 3] = 0xFFFFFFFFu;
    EXPECT_EQ(
      IconRenderProblem(opaque.data(), kSide, 0.08f), "the render is opaque edge to edge (no outline to frame)"
    );
  }

  TEST(
    UnitIcon,
    KeyedFromABlackAndAWhiteRender
  )
  {
    // 2 x 2: the background (black, white), a solid grey pixel (same in both), a half-covering pixel.
    const std::uint32_t black[4] = {0xFF000000u, 0xFF404040u, 0xFF202020u, 0xFF000000u};
    const std::uint32_t white[4] = {0xFFFFFFFFu, 0xFF404040u, 0xFF9F9F9Fu, 0xFFFFFFFFu};
    const std::vector<std::uint32_t> keyed = faf::editor::KeyedIcon(black, white, 2, 0.0f);
    ASSERT_EQ(keyed.size(), 4U);
    EXPECT_EQ(keyed[0] >> 24, 0U) << "the background: clear";
    EXPECT_EQ(keyed[1], 0xFF404040u) << "solid: as drawn";
    EXPECT_NEAR(static_cast<int>(keyed[2] >> 24), 128, 2) << "half covered";
    EXPECT_NEAR(static_cast<int>(keyed[2] & 0xFFu), 0x40, 2) << "its colour over its alpha";
    // A dark render lifted.
    const std::vector<std::uint32_t> lifted = faf::editor::KeyedIcon(black, white, 2, 0.5f);
    EXPECT_GT(lifted[1] & 0xFFu, 0x40u);
    EXPECT_EQ(lifted[1] >> 24, 0xFFu);
  }
} // namespace faf::editor
