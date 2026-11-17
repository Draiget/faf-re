// Terrain extras: height files (.r32, 8-bit, TIFF), the resampling filters, the symmetry centre, the Gaea / World
// Machine sheet and named masks.

#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdHeightFile.h"
#include "editor/tools/EdInterop.h"

#include <gtest/gtest.h>

#include <filesystem>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] HeightImage Ramp(
      const int width,
      const int height
    )
    {
      HeightImage image;
      image.width = width;
      image.height = height;
      for (int z = 0; z < height; ++z) {
        for (int x = 0; x < width; ++x) {
          image.words.push_back(static_cast<std::uint16_t>((x * 65535) / std::max(1, width - 1)));
        }
      }
      return image;
    }
  } // namespace

  TEST(
    HeightFiles,
    R32RoundTripAndEightBit
  )
  {
    const std::filesystem::path folder = std::filesystem::temp_directory_path() / "faf_editor_terrain_extras";
    std::filesystem::create_directories(folder);
    const HeightImage ramp = Ramp(17, 17);
    const auto wroteR32 = WriteHeightImage(folder / "ramp.r32", ramp);
    ASSERT_TRUE(wroteR32) << wroteR32.error();
    EXPECT_EQ(std::filesystem::file_size(folder / "ramp.r32"), 17U * 17U * 4U);
    const auto back = ReadHeightImage(folder / "ramp.r32", 0, 0);
    ASSERT_TRUE(back) << back.error();
    ASSERT_EQ(back->words.size(), ramp.words.size());
    for (std::size_t i = 0; i < ramp.words.size(); ++i) {
      EXPECT_NEAR(back->words[i], ramp.words[i], 1);
    }
    const auto wrotePng8 = WriteHeightImage(folder / "ramp8.png", ramp, true);
    ASSERT_TRUE(wrotePng8) << wrotePng8.error();
    const auto eight = ReadHeightImage(folder / "ramp8.png", 0, 0);
    ASSERT_TRUE(eight) << eight.error();
    // 8 bits spread back over 16: within one step of 257.
    EXPECT_NEAR(eight->words.back(), 65535, 257);
    EXPECT_NEAR(eight->words.front(), 0, 257);
    const auto wroteTiff = WriteHeightImage(folder / "ramp.tif", ramp);
    ASSERT_TRUE(wroteTiff) << wroteTiff.error();
    const auto tiff = ReadHeightImage(folder / "ramp.tif", 0, 0);
    ASSERT_TRUE(tiff) << tiff.error();
    EXPECT_EQ(tiff->words, ramp.words);
    std::filesystem::remove_all(folder);
  }

  TEST(
    HeightFiles,
    FiltersKeepARampAndDiffer
  )
  {
    const HeightImage ramp = Ramp(33, 33);
    for (const ResampleFilter filter :
         {ResampleFilter::Bilinear, ResampleFilter::Nearest, ResampleFilter::Bicubic, ResampleFilter::Lanczos3}) {
      const HeightImage out = ResampleHeights(ramp, 65, 65, filter);
      ASSERT_EQ(out.words.size(), 65U * 65U) << ResampleFilterName(filter);
      EXPECT_NEAR(out.words[0], 0, 300) << ResampleFilterName(filter);
      EXPECT_NEAR(out.words[64], 65535, 300) << ResampleFilterName(filter);
      EXPECT_NEAR(out.words[32], 32767, 1200) << ResampleFilterName(filter);
    }
    // A step: nearest keeps it hard, bilinear makes it a slope, bicubic overshoots a little (Catmull-Rom).
    HeightImage step;
    step.width = 4;
    step.height = 1;
    step.words = {0, 0, 60000, 60000};
    const HeightImage nearest = ResampleHeights(step, 13, 1, ResampleFilter::Nearest);
    const HeightImage linear = ResampleHeights(step, 13, 1, ResampleFilter::Bilinear);
    EXPECT_TRUE(nearest.words[6] == 0 || nearest.words[6] == 60000);
    EXPECT_GT(linear.words[6], 20000);
    EXPECT_LT(linear.words[6], 40000);
  }

  TEST(
    SymmetryCentre,
    CopiesFollowTheCentre
  )
  {
    int xs[kMaxSymmetryCopies];
    int zs[kMaxSymmetryCopies];
    SetSymmetryCentreOffset(0.0f, 0.0f);
    ASSERT_EQ(SymmetricSamples(Symmetry::LeftRight, 2, 257, 257, 10, 40, xs, zs), 2);
    EXPECT_EQ(xs[1], 246);                 // about the middle, 128
    SetSymmetryCentreOffset(-20.0f, 0.0f); // centre at x 108
    ASSERT_EQ(SymmetricSamples(Symmetry::LeftRight, 2, 257, 257, 10, 40, xs, zs), 2);
    EXPECT_EQ(xs[1], 206);
    EXPECT_EQ(zs[1], 40);
    // A copy that would leave the map is the point itself.
    ASSERT_EQ(SymmetricSamples(Symmetry::LeftRight, 2, 257, 257, 250, 40, xs, zs), 2);
    EXPECT_EQ(xs[1], 250);
    SetSymmetryCentreOffset(0.0f, 0.0f);
  }

  TEST(
    Interop,
    GaeaSheetAndNamedMasks
  )
  {
    ExportFacts facts;
    facts.map = "test";
    facts.mapWidth = 512;
    facts.mapHeight = 512;
    facts.imageWidth = 513;
    facts.imageHeight = 513;
    facts.lowest = 10.0f;
    facts.highest = 61.2f;
    const std::string sheet = ExportSheet(facts);
    EXPECT_NE(sheet.find("10.00 x 10.00 km"), std::string::npos) << sheet;
    EXPECT_NE(sheet.find("Gaea: Terrain > Scale 10.00 km"), std::string::npos) << sheet;
    EXPECT_NE(sheet.find("195 to 1195 m"), std::string::npos) << sheet;
    const std::vector<std::string> files = {
      "C:/x/terrain.png", "C:/x/terrain_wear.png", "C:/x/Flow.TIF", "C:/x/notes_wear.txt", "C:/x/deposit_old.png"
    };
    EXPECT_EQ(FindNamedMask(files, "wear"), "C:/x/terrain_wear.png");
    EXPECT_EQ(FindNamedMask(files, "flow"), "C:/x/Flow.TIF");
    EXPECT_EQ(FindNamedMask(files, "deposit"), "");
    EXPECT_EQ(FindNamedMask(files, ""), "");
  }
} // namespace faf::editor
