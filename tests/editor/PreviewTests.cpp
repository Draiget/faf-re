#include "editor/doc/EdNewMap.h"
#include "editor/doc/EdPreview.h"

#include <gtest/gtest.h>

#include <cstring>

namespace faf::editor
{
  namespace
  {
    /** A 512 x 256 map's heights: a ramp rising to the east from 0 to 100 units. */
    HeightImage Ramp()
    {
      HeightImage image;
      image.width = 65;
      image.height = 33;
      for (int y = 0; y < image.height; ++y) {
        for (int x = 0; x < image.width; ++x) {
          image.words.push_back(static_cast<std::uint16_t>(x * 100 * 128 / 64));
        }
      }
      return image;
    }

    std::uint32_t At(
      const std::vector<std::uint32_t>& pixels,
      const int x,
      const int y
    )
    {
      return pixels[static_cast<std::size_t>(y) * kPreviewSide + x];
    }
  } // namespace

  TEST(
    Preview,
    AMapThatIsntSquareIsCentred
  )
  {
    const PreviewFrame f = PreviewFrameOf(512.0f, 256.0f);
    EXPECT_FLOAT_EQ(f.scale, 2.0f);
    EXPECT_FLOAT_EQ(f.offsetX, 0.0f);
    EXPECT_FLOAT_EQ(f.offsetZ, 64.0f);
    const std::vector<std::uint32_t> pixels = PreviewPixels(Ramp(), 512.0f, 256.0f, {});
    ASSERT_EQ(pixels.size(), static_cast<std::size_t>(kPreviewSide * kPreviewSide));
    EXPECT_EQ(At(pixels, 128, 10), 0xFF000000u) << "above the map: black";
    EXPECT_EQ(At(pixels, 128, 250), 0xFF000000u) << "below it";
    EXPECT_NE(At(pixels, 128, 128), 0xFF000000u) << "the map";
  }

  TEST(
    Preview,
    WaterIsBlueAndPeaksAreLight
  )
  {
    PreviewOptions options;
    options.water = true;
    options.waterLevel = 30.0f;
    options.dots.push_back({500.0f, 128.0f, 0xFFFF0000u, 2.0f});
    const std::vector<std::uint32_t> pixels = PreviewPixels(Ramp(), 512.0f, 256.0f, options);
    const std::uint32_t sea = At(pixels, 5, 128);
    EXPECT_GT(sea & 0xFFu, (sea >> 16) & 0xFFu) << "the west, under the sea: more blue than red";
    const std::uint32_t peak = At(pixels, 240, 100);
    EXPECT_GT((peak >> 16) & 0xFFu, 150u) << "the east's top: light";
    EXPECT_EQ(At(pixels, 250, 128), 0xFFFF0000u) << "the dot";
  }

  TEST(
    Preview,
    RecordHoldsThePixels
  )
  {
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kPreviewSide * kPreviewSide), 0xFF123456u);
    const std::vector<char> chunk = PreviewRecord(1024.0f, 512.0f, pixels);
    float depth = 0.0f;
    std::memcpy(&depth, chunk.data() + 12, 4);
    EXPECT_FLOAT_EQ(depth, 512.0f);
    std::uint32_t first = 0;
    std::memcpy(&first, chunk.data() + 26 + 128, 4);
    EXPECT_EQ(first, 0xFF123456u);
    // The new map's preview: centred too (its spawn dots inside the band).
    NewMapSettings settings;
    settings.size = 3;
    settings.sizeZ = 2;
    settings.players = 2;
    const std::vector<char> made = NewMapPreviewRecord(settings);
    std::uint32_t corner = 0;
    std::memcpy(&corner, made.data() + 26 + 128, 4);
    EXPECT_EQ(corner, 0xFF000000u) << "the top left is outside a wide map's band";
  }
} // namespace faf::editor
