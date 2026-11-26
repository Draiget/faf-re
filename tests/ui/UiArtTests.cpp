// The UI's own pictures (moho/ui/UiArt.h): icons from SVG elements, rounded boxes, PNG bytes, the memory table.

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <zlib.h>

#include "moho/ui/UiArt.h"

namespace
{
  using namespace moho::uiart;

  std::uint32_t U32(
    const std::vector<std::uint8_t>& bytes,
    const std::size_t at
  )
  {
    return (std::uint32_t(bytes[at]) << 24) | (std::uint32_t(bytes[at + 1]) << 16) |
      (std::uint32_t(bytes[at + 2]) << 8) | std::uint32_t(bytes[at + 3]);
  }

  std::uint8_t Alpha(
    const Image& image,
    const int x,
    const int y
  )
  {
    return image.rgba[(static_cast<std::size_t>(y) * image.width + x) * 4 + 3];
  }

  /** The pixels a PNG of EncodePng holds, read back with zlib: what a decoder would get. */
  std::vector<std::uint8_t> PngPixels(
    const std::vector<std::uint8_t>& png,
    int& width,
    int& height
  )
  {
    std::vector<std::uint8_t> packed;
    std::size_t at = 8;
    while (at + 12 <= png.size()) {
      const std::uint32_t length = U32(png, at);
      const std::string type(png.begin() + at + 4, png.begin() + at + 8);
      if (type == "IHDR") {
        width = static_cast<int>(U32(png, at + 8));
        height = static_cast<int>(U32(png, at + 12));
      } else if (type == "IDAT") {
        packed.insert(packed.end(), png.begin() + at + 8, png.begin() + at + 8 + length);
      }
      // Each chunk's CRC covers its type and data.
      const uLong crc = crc32(0L, &png[at + 4], static_cast<uInt>(4 + length));
      EXPECT_EQ(U32(png, at + 8 + length), static_cast<std::uint32_t>(crc)) << type;
      at += 12 + length;
    }
    std::vector<std::uint8_t> raw(static_cast<std::size_t>(width * 4 + 1) * height);
    uLongf rawSize = static_cast<uLongf>(raw.size());
    EXPECT_EQ(uncompress(raw.data(), &rawSize, packed.data(), static_cast<uLong>(packed.size())), Z_OK);
    std::vector<std::uint8_t> pixels;
    for (int y = 0; y < height; ++y) {
      const std::size_t row = static_cast<std::size_t>(y) * (width * 4 + 1);
      EXPECT_EQ(raw[row], 0) << "filter of row " << y;
      pixels.insert(pixels.end(), raw.begin() + row + 1, raw.begin() + row + 1 + width * 4);
    }
    return pixels;
  }
} // namespace

TEST(
  UiArt,
  ReadsColoursAsTheUiWritesThem
)
{
  Rgba color;
  ASSERT_TRUE(ParseColor("80102030", color));
  EXPECT_EQ(color.a, 0x80);
  EXPECT_EQ(color.r, 0x10);
  EXPECT_EQ(color.g, 0x20);
  EXPECT_EQ(color.b, 0x30);
  ASSERT_TRUE(ParseColor("A1B2C3", color));
  EXPECT_EQ(color.a, 0xFF);
  EXPECT_EQ(color.r, 0xA1);
  EXPECT_FALSE(ParseColor("12345", color));
  EXPECT_FALSE(ParseColor("ff1020zz", color));
}

TEST(
  UiArt,
  APngHoldsThePixelsItWasMadeFrom
)
{
  Image image;
  image.width = 3;
  image.height = 2;
  for (int i = 0; i < 6; ++i) {
    image.rgba.insert(image.rgba.end(), {std::uint8_t(i * 40), std::uint8_t(255 - i), std::uint8_t(7 * i), 200});
  }
  const std::vector<std::uint8_t> png = EncodePng(image);
  ASSERT_GE(png.size(), 8u);
  EXPECT_EQ(
    std::vector<std::uint8_t>(png.begin(), png.begin() + 8),
    (std::vector<std::uint8_t>{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'})
  );
  EXPECT_EQ(png[24], 8); // bit depth
  EXPECT_EQ(png[25], 6); // RGBA
  int width = 0;
  int height = 0;
  EXPECT_EQ(PngPixels(png, width, height), image.rgba);
  EXPECT_EQ(width, 3);
  EXPECT_EQ(height, 2);
}

TEST(
  UiArt,
  StrokesALineAlongItsPathOnly
)
{
  // Lucide's minus: a 16-unit line across the middle of its 24-unit grid; 24 pixels, so one unit is one pixel.
  const auto icon = DrawIcon("<path d=\"M5 12h14\" />", 24, Rgba{255, 255, 255, 255}, 2.0f);
  ASSERT_TRUE(icon) << icon.error();
  EXPECT_EQ(Alpha(*icon, 12, 11), 255); // on the line (rows 11 and 12 straddle y = 12)
  EXPECT_EQ(Alpha(*icon, 12, 12), 255);
  EXPECT_EQ(Alpha(*icon, 12, 6), 0); // well above it
  EXPECT_EQ(Alpha(*icon, 1, 12), 0); // past its round end
  EXPECT_GT(Alpha(*icon, 4, 12), 0); // the round cap reaches one unit past the end
  EXPECT_EQ(icon->rgba[(12 * 24 + 12) * 4], 255);
}

TEST(
  UiArt,
  StrokesACircleAndLeavesItsMiddleEmpty
)
{
  const auto icon = DrawIcon("<circle cx=\"12\" cy=\"12\" r=\"10\" />", 48, Rgba{255, 0, 0, 255}, 2.0f);
  ASSERT_TRUE(icon) << icon.error();
  EXPECT_EQ(Alpha(*icon, 24, 24), 0);   // the middle
  EXPECT_EQ(Alpha(*icon, 24, 4), 255);  // the top of the ring: y = 2 units, 4 pixels at 2 pixels a unit
  EXPECT_EQ(Alpha(*icon, 44, 24), 255); // its right
  EXPECT_EQ(Alpha(*icon, 1, 1), 0);
}

TEST(
  UiArt,
  FillsAShapeWithAFill
)
{
  // A filled triangle written with relative commands and an arc-free path; the play triangle of Lucide's
  // circle-play is drawn the same way.
  const auto icon = DrawIcon("<path d=\"m4 4 16 8-16 8z\" fill=\"currentColor\" />", 24, Rgba{}, 0.5f);
  ASSERT_TRUE(icon) << icon.error();
  EXPECT_EQ(Alpha(*icon, 8, 12), 255); // inside
  EXPECT_EQ(Alpha(*icon, 20, 4), 0);   // outside, above the slope
}

TEST(
  UiArt,
  DrawsArcsAndSmoothCurves
)
{
  // Lucide's circle-play: an arc, relative lines and a closing arc; then a cubic with its smooth continuation.
  const auto play = DrawIcon(
    "<path d=\"M9 9.003a1 1 0 0 1 1.517-.859l4.997 2.997a1 1 0 0 1 0 1.718l-4.997 2.997A1 1 0 0 1 9 14.996z\" />"
    "<circle cx=\"12\" cy=\"12\" r=\"10\" />",
    24,
    Rgba{},
    2.0f
  );
  ASSERT_TRUE(play) << play.error();
  // Covered: at least 200 of 255 (a pixel's centre half a pixel off a line's middle is still mostly inside).
  EXPECT_GE(Alpha(*play, 9, 12), 200); // the triangle's left edge, x = 9
  EXPECT_GE(Alpha(*play, 12, 1), 200); // the circle's top, y = 2
  EXPECT_EQ(Alpha(*play, 12, 5), 0);   // between the circle and the triangle
  // A cubic from (2,12) through its peak (5,9) to (8,12), then its smooth continuation down to (11,15).
  const auto wave = DrawIcon("<path d=\"M2 12c2-4 4-4 6 0s4 4 6 0\" />", 24, Rgba{}, 2.0f);
  ASSERT_TRUE(wave) << wave.error();
  EXPECT_GE(Alpha(*wave, 4, 8), 200);   // the peak
  EXPECT_GE(Alpha(*wave, 10, 14), 200); // the reflected half's trough
  EXPECT_EQ(Alpha(*wave, 5, 15), 0);    // under the peak
  EXPECT_FALSE(DrawIcon("<path d=\"12 12\" />", 24, Rgba{}));
}

TEST(
  UiArt,
  RoundsABoxsCornersAndDrawsItsBorderInside
)
{
  const Rgba fill{10, 20, 30, 255};
  const Rgba border{200, 210, 220, 255};
  const Image box = DrawRoundedRect(40, 20, 8.0f, fill, border, 1.0f);
  EXPECT_EQ(Alpha(box, 0, 0), 0); // outside the rounded corner
  const auto at = [&](const int x, const int y) {
    return &box.rgba[(static_cast<std::size_t>(y) * box.width + x) * 4];
  };
  EXPECT_EQ(at(20, 10)[0], 10); // the middle is the fill
  EXPECT_EQ(at(20, 10)[3], 255);
  EXPECT_EQ(at(20, 0)[0], 200); // the top row is the border
  EXPECT_EQ(at(20, 0)[3], 255);
  const Image corner = DrawCorner(2, 8, fill, border, 1.0f);
  ASSERT_EQ(corner.width, 8);
  EXPECT_EQ(Alpha(corner, 7, 7), 0);   // the bottom right corner's outer tip
  EXPECT_EQ(Alpha(corner, 0, 0), 255); // its inner side is filled
}

TEST(
  UiArt,
  KeepsPicturesUnderTheMemoryPrefix
)
{
  EXPECT_TRUE(IsMemoryPath("/fafengine-mem/icon/1.png"));
  EXPECT_TRUE(IsMemoryPath("/FAFENGINE-MEM/icon/1.png"));
  EXPECT_FALSE(IsMemoryPath("/textures/ui/common/x.dds"));
  EXPECT_EQ(FindImage("/fafengine-mem/test/none.png"), nullptr);
  RegisterImage("/fafengine-mem/test/a.png", {1, 2, 3});
  const auto kept = FindImage("/FafEngine-Mem/Test/A.png");
  ASSERT_NE(kept, nullptr);
  EXPECT_EQ(*kept, (std::vector<std::uint8_t>{1, 2, 3}));
}
