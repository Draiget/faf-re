// Checks the stable shadow box (`ren_ShadowStable`): it always covers the volume, its corner sits on
// the texel grid, and panning over uneven ground keeps the texel size.

#include "moho/render/ShadowCascadeFit.h"
#include "moho/render/ShadowStableFit.h"

#include <gtest/gtest.h>

#include <cmath>
#include <random>

namespace
{
  // The corner is a whole number of texels, within what a float can hold at this distance.
  [[nodiscard]] bool OnGrid(const float value, const float extent, const int size)
  {
    const double texel = static_cast<double>(extent) / (size - 2);
    const double nearest = std::round(static_cast<double>(value) / texel) * texel;
    const double ulp = std::fabs(static_cast<double>(std::nextafter(value, value + 1.0f)) - value);
    return std::fabs(nearest - value) <= ulp;
  }
} // namespace

TEST(ShadowStableFit, CoversAndSnaps)
{
  std::mt19937 rng(1234);
  std::uniform_real_distribution<float> position(-6000.0f, 6000.0f);
  std::uniform_real_distribution<float> length(20.0f, 3000.0f);
  const int sizes[] = {512, 1024, 1536, 2048, 4096};

  for (int i = 0; i < 200000; ++i) {
    const int size = sizes[i % 5];
    const float minX = position(rng);
    const float maxX = minX + length(rng);
    const float minY = position(rng);
    const float maxY = minY + length(rng);
    float heldWidth = 0.0f;
    float heldHeight = 0.0f;
    const moho::ShadowStableBox box =
      moho::FitShadowStableBox(minX, maxX, minY, maxY, size, heldWidth, heldHeight);

    SCOPED_TRACE(testing::Message() << "i=" << i << " size=" << size << " minX=" << minX << " maxX=" << maxX
                                    << " minY=" << minY << " maxY=" << maxY);
    ASSERT_TRUE(box.minX <= minX && box.maxX >= maxX) << "box covers the volume on X";
    ASSERT_TRUE(box.minY <= minY && box.maxY >= maxY) << "box covers the volume on Y";
    ASSERT_TRUE(OnGrid(box.minX, heldWidth, size)) << "X corner on the texel grid";
    ASSERT_TRUE(OnGrid(box.minY, heldHeight, size)) << "Y corner on the texel grid";
    ASSERT_LE(heldWidth, (maxX - minX) * 1.08f) << "width wastes at most one step";
  }
}

TEST(ShadowStableFit, PanKeepsTexelSize)
{
  // A pan where hills change the volume's length by up to 8%.
  std::mt19937 rng(99);
  std::uniform_real_distribution<float> hills(0.0f, 0.08f);
  float heldWidth = 0.0f;
  float heldHeight = 0.0f;
  int changes = 0;
  float previous = 0.0f;
  for (int frame = 0; frame < 5000; ++frame) {
    const float pan = 0.37f * static_cast<float>(frame);
    const float length = 400.0f * (1.0f + hills(rng));
    const moho::ShadowStableBox box = moho::FitShadowStableBox(
      pan, pan + length, pan * 0.5f, pan * 0.5f + length, 1024, heldWidth, heldHeight
    );
    ASSERT_GE(box.maxX, pan + length) << "held box still covers the volume, frame " << frame;
    if (frame != 0 && heldWidth != previous) {
      ++changes;
    }
    previous = heldWidth;
  }
  EXPECT_LE(changes, 2) << "uneven ground changes the texel size at most twice";
}

TEST(ShadowStableFit, ShrinksAfterZoomIn)
{
  float held = 0.0f;
  (void)moho::FitShadowStableAxis(0.0f, 1000.0f, 1024, held);
  const float wide = held;
  (void)moho::FitShadowStableAxis(0.0f, 100.0f, 1024, held);
  EXPECT_LT(held, wide / 5.0f) << "zooming in gives the resolution back";
}

// Engine addition (ren_ShadowCascades): a world point looked up through any tile that holds it lands on
// the texel that tile drew it into, and a tile answers only inside its own viewport, clear of the gutter.
TEST(ShadowCascadeFit, TilesMapTheWholeViewCoordinateOntoTheirViewport)
{
  const moho::ShadowStableBox base{-300.0f, 500.0f, 100.0f, 700.0f};
  const moho::ShadowStableBox tile{-120.0f, 40.0f, 380.0f, 520.0f};
  const float content = 1016.0f;
  const float atlas = 2048.0f;
  const float originX = 1028.0f;
  const float originY = 4.0f;
  const moho::ShadowCascadeLookup lookup = moho::FitShadowCascadeLookup(base, tile, originX, originY, content, atlas, 5.0f);

  std::mt19937 rng(77);
  std::uniform_real_distribution<float> x(tile.minX, tile.maxX);
  std::uniform_real_distribution<float> y(tile.minY, tile.maxY);
  for (int i = 0; i < 10000; ++i) {
    const float wx = x(rng);
    const float wy = y(rng);
    // The effects' whole-view coordinate, and the texel the tile's own projection drew the point into.
    const float u = (wx - base.minX) / (base.maxX - base.minX);
    const float v = (base.maxY - wy) / (base.maxY - base.minY);
    const float drawnU = (originX + (wx - tile.minX) / (tile.maxX - tile.minX) * content) / atlas;
    const float drawnV = (originY + (tile.maxY - wy) / (tile.maxY - tile.minY) * content) / atlas;
    EXPECT_NEAR(u * lookup.map[0] + lookup.map[2], drawnU, 1.0e-5f);
    EXPECT_NEAR(v * lookup.map[1] + lookup.map[3], drawnV, 1.0e-5f);

    const bool answers = u >= lookup.box[0] && v >= lookup.box[1] && u <= lookup.box[2] && v <= lookup.box[3];
    if (answers) {
      const float texelX = drawnU * atlas - originX;
      const float texelY = drawnV * atlas - originY;
      EXPECT_GE(texelX, 5.0f - 1.0e-2f);
      EXPECT_LE(texelX, content - 5.0f + 1.0e-2f);
      EXPECT_GE(texelY, 5.0f - 1.0e-2f);
      EXPECT_LE(texelY, content - 5.0f + 1.0e-2f);
    }
  }
}

TEST(ShadowCascadeFit, TheWholeViewTileAnswersInsideTheMapAndNowhereElse)
{
  const moho::ShadowStableBox base{0.0f, 1000.0f, 0.0f, 1000.0f};
  const moho::ShadowCascadeLookup lookup = moho::FitShadowCascadeLookup(base, base, 4.0f, 4.0f, 1016.0f, 2048.0f, 5.0f);
  EXPECT_NEAR(lookup.map[0], 1016.0f / 2048.0f, 1.0e-7f);
  EXPECT_NEAR(lookup.map[2], 4.0f / 2048.0f, 1.0e-7f);
  EXPECT_GT(lookup.box[0], 0.0f);
  EXPECT_LT(lookup.box[2], 1.0f);

  // A tile reaching past the whole-view map answers only inside it: nothing past it was drawn.
  const moho::ShadowStableBox wide{-100.0f, 300.0f, 900.0f, 1200.0f};
  const moho::ShadowCascadeLookup clipped = moho::FitShadowCascadeLookup(base, wide, 1028.0f, 4.0f, 1016.0f, 2048.0f, 5.0f);
  EXPECT_EQ(clipped.box[0], 0.0f);
  EXPECT_EQ(clipped.box[1], 0.0f);
}
