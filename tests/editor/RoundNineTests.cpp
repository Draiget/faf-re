// The seventh comparison with FAF Studio (brush target): the shipped brush images, areas kept inside the map, the
// performance timing's report.

#include "editor/tools/EdAreaLimit.h"
#include "editor/tools/EdBrushLibrary.h"
#include "editor/ui/EdPerf.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <system_error>

namespace
{
  using namespace faf::editor;

  TEST(
    RoundNine,
    TheFiveShippedBrushImages
  )
  {
    const auto images = ShippedBrushImages(64);
    ASSERT_EQ(images.size(), 5U);
    const auto value = [](const HeightImage& image, const int x, const int y) {
      return image.words[static_cast<std::size_t>(y) * image.width + x];
    };
    for (const auto& [name, image] : images) {
      ASSERT_EQ(image.width, 64) << name;
      ASSERT_EQ(image.words.size(), 64U * 64U) << name;
      EXPECT_EQ(value(image, 0, 0), 0) << name << ": the corner is outside every shape";
    }
    const HeightImage& crater = images[1].second;
    ASSERT_EQ(images[1].first, "crater");
    EXPECT_GT(value(crater, 32 + 17, 32), value(crater, 32, 32)) << "the rim higher than the bowl";
    const HeightImage& volcano = images[4].second;
    EXPECT_GT(value(volcano, 32 + 10, 32), value(volcano, 32 + 28, 32)) << "the cone falls away from the top";
    // Written once: the stamp keeps a deleted one deleted.
    const std::filesystem::path folder = std::filesystem::temp_directory_path() / "faf_round9_brushes";
    std::error_code ec;
    std::filesystem::remove_all(folder, ec);
    std::string error;
    EXPECT_EQ(WriteShippedBrushImages(folder, error), 5) << error;
    EXPECT_EQ(ListBrushImages(folder).size(), 5U);
    std::filesystem::remove(folder / "dunes.png", ec);
    EXPECT_EQ(WriteShippedBrushImages(folder, error), 0) << "not again";
    EXPECT_EQ(ListBrushImages(folder).size(), 4U);
    const auto grid = LoadBrushImage(folder / "crater.png", 33);
    EXPECT_TRUE(grid) << grid.error();
  }

  TEST(
    RoundNine,
    AreasAreKeptInside
  )
  {
    const AreaBounds map{0.0f, 0.0f, 512.0f, 512.0f};
    float moved[4] = {500.0f, -10.0f, 540.0f, 30.0f};
    LimitArea(moved, map, true);
    EXPECT_FLOAT_EQ(moved[0], 472.0f) << "a move keeps the size, pushed back in";
    EXPECT_FLOAT_EQ(moved[2], 512.0f);
    EXPECT_FLOAT_EQ(moved[1], 0.0f);
    EXPECT_FLOAT_EQ(moved[3], 40.0f);
    float drawn[4] = {500.0f, -10.0f, 540.0f, 30.0f};
    LimitArea(drawn, map, false);
    EXPECT_FLOAT_EQ(drawn[0], 500.0f) << "a drawing is cut";
    EXPECT_FLOAT_EQ(drawn[2], 512.0f);
    EXPECT_FLOAT_EQ(drawn[1], 0.0f);
    EXPECT_FLOAT_EQ(drawn[3], 30.0f);
    float outside[4] = {600.0f, 600.0f, 620.0f, 620.0f};
    LimitArea(outside, map, false);
    EXPECT_GE(outside[2] - outside[0], 1.0f) << "never empty";
    EXPECT_LE(outside[2], 512.0f);
    float loose[4] = {-50.0f, -50.0f, 10.0f, 10.0f};
    LimitArea(loose, AreaBounds{}, true);
    EXPECT_FLOAT_EQ(loose[0], -50.0f) << "no limit: as it is";
  }

  TEST(
    RoundNine,
    ThePerformanceReportEveryPeriod
  )
  {
    EdPerf perf;
    std::string report;
    EXPECT_FALSE(perf.EndFrame(0.1, report)) << "off: nothing";
    perf.SetOn(true);
    for (int frame = 0; frame < 4; ++frame) {
      perf.Add("panels", 2.0);
      perf.Add("scene update", frame == 2 ? 9.0 : 1.0);
      const bool done = perf.EndFrame(0.25, report, 1.0);
      EXPECT_EQ(done, frame == 3) << frame;
    }
    EXPECT_NE(report.find("4 frames (4.0 fps"), std::string::npos) << report;
    EXPECT_NE(report.find("scene update 3.00 ms (slowest 9.0)"), std::string::npos) << report;
    EXPECT_LT(report.find("scene update"), report.find("panels")) << "the largest first: " << report;
    EXPECT_FALSE(perf.EndFrame(0.25, report, 1.0)) << "counts start again";
  }
} // namespace
