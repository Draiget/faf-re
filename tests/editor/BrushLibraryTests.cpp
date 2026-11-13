// The Terrain tool's brush library and stamps (src/editor/tools/EdBrushLibrary.cpp, EdHeightBrush.cpp): shapes on a
// grid, the brush folder's images listed, read and imported, a stamp stroke's dabs along the cursor's path, the
// stamp's modes and turn, and an image as a brush shape.

#include "editor/tools/EdBrushLibrary.h"
#include "editor/tools/EdHeightFile.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace
{
  using faf::editor::ApplyHeightBrush;
  using faf::editor::BrushShape;
  using faf::editor::HeightBrush;
  using faf::editor::HeightBrushMode;
  using faf::editor::HeightStamp;
  using faf::editor::ShapeGrid;
  using faf::editor::StampMode;

  /** A folder of its own under the temporary folder, removed with the test. */
  struct TempFolder
  {
    std::filesystem::path path;
    explicit TempFolder(
      const char* const name
    )
      : path(std::filesystem::temp_directory_path() / ("faf_brushlib_" + std::string(name)))
    {
      std::filesystem::remove_all(path);
      std::filesystem::create_directories(path);
    }
    ~TempFolder()
    {
      std::error_code ignored;
      std::filesystem::remove_all(path, ignored);
    }
  };

  /** A 16-bit image rising from black on the left to white on the right. */
  faf::editor::HeightImage RampImage(
    const int size
  )
  {
    faf::editor::HeightImage image;
    image.width = size;
    image.height = size;
    for (int z = 0; z < size; ++z) {
      for (int x = 0; x < size; ++x) {
        image.words.push_back(static_cast<std::uint16_t>(x * 65535 / (size - 1)));
      }
    }
    return image;
  }

  TEST(
    BrushLibrary,
    ShapesRasteriseOnAnOddGrid
  )
  {
    const ShapeGrid cone = faf::editor::RasterizeShape(BrushShape::Cone);
    ASSERT_EQ(cone.n, faf::editor::kShapeGridSize);
    EXPECT_FLOAT_EQ(cone.Sample(0.0f, 0.0f), 1.0f) << "the peak is on a sample";
    EXPECT_FLOAT_EQ(cone.Sample(1.0f, 1.0f), 0.0f);
    EXPECT_FLOAT_EQ(cone.Sample(1.5f, 0.0f), 0.0f) << "outside the square";
    EXPECT_NEAR(cone.Sample(0.5f, 0.0f), 0.5f, 0.02f) << "read between samples";
  }

  TEST(
    BrushLibrary,
    FolderImagesAreListedReadAndImported
  )
  {
    const TempFolder source("source");
    const TempFolder library("library");
    std::string error;
    ASSERT_TRUE(faf::editor::WriteHeightImage(source.path / "ramp.png", RampImage(33), error)) << error;
    ASSERT_TRUE(faf::editor::WriteHeightImage(source.path / "Another.png", RampImage(17), error)) << error;
    std::ofstream(source.path / "notes.txt") << "not an image";

    EXPECT_EQ(
      faf::editor::ImportBrushImages({source.path / "ramp.png", source.path / "Another.png"}, library.path, error), 2
    ) << error;
    const std::vector<faf::editor::BrushImage> images = faf::editor::ListBrushImages(library.path);
    ASSERT_EQ(images.size(), 2u);
    EXPECT_EQ(images[0].name, "Another") << "by name";
    EXPECT_EQ(images[1].name, "ramp");
    EXPECT_EQ(faf::editor::ListBrushImages(source.path).size(), 2u) << "the text file isn't an image";

    ShapeGrid grid;
    ASSERT_TRUE(faf::editor::LoadBrushImage(images[1].path, 65, grid, error)) << error;
    EXPECT_EQ(grid.n, 65);
    EXPECT_NEAR(grid.Sample(-1.0f, 0.0f), 0.0f, 0.01f) << "black on the left";
    EXPECT_NEAR(grid.Sample(1.0f, 0.0f), 1.0f, 0.01f) << "white on the right";
    EXPECT_NEAR(grid.Sample(0.0f, 0.5f), 0.5f, 0.02f);
    EXPECT_FALSE(faf::editor::LoadBrushImage(source.path / "missing.png", 65, grid, error));
  }

  TEST(
    BrushLibrary,
    StampDabsFallEverySpacingAlongThePath
  )
  {
    float travelled = 10.0f; // a new stroke: its first point is a dab
    std::vector<faf::editor::StampDab> dabs = faf::editor::StampDabsAlong(0.0f, 0.0f, 25.0f, 0.0f, 10.0f, travelled);
    ASSERT_EQ(dabs.size(), 3u);
    EXPECT_FLOAT_EQ(dabs[0].x, 0.0f);
    EXPECT_FLOAT_EQ(dabs[1].x, 10.0f);
    EXPECT_FLOAT_EQ(dabs[2].x, 20.0f);
    EXPECT_FLOAT_EQ(travelled, 5.0f);
    dabs = faf::editor::StampDabsAlong(25.0f, 0.0f, 25.0f, 7.0f, 10.0f, travelled);
    ASSERT_EQ(dabs.size(), 1u) << "5 carried plus 7: one more, 5 into the move";
    EXPECT_FLOAT_EQ(dabs[0].z, 5.0f);
    EXPECT_FLOAT_EQ(travelled, 2.0f);
    EXPECT_TRUE(faf::editor::StampDabsAlong(25.0f, 7.0f, 25.0f, 8.0f, 10.0f, travelled).empty()) << "not far enough";

    // Spacing 0: one dab per click.
    travelled = 1.0f;
    EXPECT_EQ(faf::editor::StampDabsAlong(3.0f, 3.0f, 3.0f, 3.0f, 0.0f, travelled).size(), 1u);
    EXPECT_TRUE(faf::editor::StampDabsAlong(3.0f, 3.0f, 30.0f, 3.0f, 0.0f, travelled).empty());
  }

  struct Grid
  {
    std::vector<std::uint16_t> words = std::vector<std::uint16_t>(65 * 65, 4000);
    [[nodiscard]] std::uint16_t At(
      const int x,
      const int z
    ) const
    {
      return words[static_cast<std::size_t>(z) * 65 + static_cast<std::size_t>(x)];
    }
  };

  /** A stamp dab at the middle of a 65 x 65 grid, full strength, a hard edge. */
  Grid Stamped(
    const HeightStamp& stamp,
    const StampMode mode,
    const std::uint16_t ground,
    const float turn = 0.0f
  )
  {
    Grid grid;
    std::fill(grid.words.begin(), grid.words.end(), ground);
    HeightBrush brush;
    brush.mode = HeightBrushMode::Stamp;
    brush.stamp = &stamp;
    brush.stampMode = mode;
    brush.stampHeight = 1000.0f;
    brush.stampBase = 4000.0f;
    brush.stampTurn = turn;
    brush.strength = 1.0f;
    brush.falloff = 0.0f;
    brush.radius = 12.0f;
    (void)ApplyHeightBrush(grid.words.data(), 65, 65, 32.0f, 32.0f, brush, 0.1f);
    return grid;
  }

  TEST(
    BrushLibrary,
    StampModesMeetTheGroundAsNamed
  )
  {
    ShapeGrid white;
    white.n = 3;
    white.values.assign(9, 1.0f);
    const HeightStamp full = faf::editor::StampFromGrid(white);
    EXPECT_EQ(Stamped(full, StampMode::Add, 4000).At(32, 32), 5000);
    EXPECT_EQ(Stamped(full, StampMode::Subtract, 4000).At(32, 32), 3000);
    EXPECT_EQ(Stamped(full, StampMode::Max, 4000).At(32, 32), 5000) << "risen to base + stamp";
    EXPECT_EQ(Stamped(full, StampMode::Max, 6000).At(32, 32), 6000) << "ground above the stamp stays";
    EXPECT_EQ(Stamped(full, StampMode::Min, 4000).At(32, 32), 3000) << "sunk to base - stamp";
    EXPECT_EQ(Stamped(full, StampMode::Min, 2000).At(32, 32), 2000) << "ground below it stays";
    EXPECT_EQ(Stamped(full, StampMode::Replace, 9000).At(32, 32), 5000) << "the ground becomes base + stamp";
    EXPECT_EQ(Stamped(full, StampMode::Add, 4000).At(32 + 14, 32), 4000) << "nothing outside the brush";
  }

  TEST(
    BrushLibrary,
    ATurnedStampTurnsItsPicture
  )
  {
    // A picture rising towards +x; turned a quarter it rises towards +z.
    ShapeGrid ramp;
    ramp.n = 33;
    for (int z = 0; z < 33; ++z) {
      for (int x = 0; x < 33; ++x) {
        ramp.values.push_back(static_cast<float>(x) / 32.0f);
      }
    }
    const HeightStamp stamp = faf::editor::StampFromGrid(ramp);
    const Grid straight = Stamped(stamp, StampMode::Add, 4000);
    EXPECT_GT(straight.At(38, 32), straight.At(26, 32));
    EXPECT_EQ(straight.At(32, 38), straight.At(32, 26));
    const Grid turned = Stamped(stamp, StampMode::Add, 4000, 90.0f);
    EXPECT_NEAR(turned.At(32, 38), straight.At(38, 32), 1.0) << "the high side now towards +z";
    EXPECT_NEAR(turned.At(32, 26), straight.At(26, 32), 1.0);
    EXPECT_NEAR(turned.At(38, 32), turned.At(26, 32), 1.0);
  }

  TEST(
    BrushLibrary,
    AnImageShapesTheBrush
  )
  {
    // Left half white, right half black: a raise only on the left.
    ShapeGrid half;
    half.n = 33;
    for (int z = 0; z < 33; ++z) {
      for (int x = 0; x < 33; ++x) {
        half.values.push_back(x < 16 ? 1.0f : 0.0f);
      }
    }
    Grid grid;
    HeightBrush brush;
    brush.mode = HeightBrushMode::Raise;
    brush.shape = BrushShape::Image;
    brush.shapeImage = &half;
    brush.radius = 12.0f;
    brush.strength = 1.0f;
    (void)ApplyHeightBrush(grid.words.data(), 65, 65, 32.0f, 32.0f, brush, 0.1f);
    EXPECT_GT(grid.At(26, 32), 4000);
    EXPECT_EQ(grid.At(38, 32), 4000);
  }
} // namespace
