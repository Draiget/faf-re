#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdTerrainPath.h"

#include <gtest/gtest.h>

#include <vector>

namespace faf::editor
{
  namespace
  {
    constexpr int kSide = 65;

    std::vector<std::uint16_t> Flat(
      const float units
    )
    {
      return std::vector<std::uint16_t>(
        static_cast<std::size_t>(kSide) * kSide, static_cast<std::uint16_t>(units * 128.0f)
      );
    }

    float At(
      const std::vector<std::uint16_t>& field,
      const int x,
      const int z
    )
    {
      return static_cast<float>(field[static_cast<std::size_t>(z) * kSide + x]) / 128.0f;
    }
  } // namespace

  TEST(
    TerrainPath,
    SampledCurvePassesThroughItsPoints
  )
  {
    const std::vector<TerrainPathPoint> points{{0.0f, 0.0f, 10.0f}, {10.0f, 0.0f, 20.0f}, {20.0f, 10.0f, 30.0f}};
    const std::vector<TerrainPathPoint> curve = SamplePath(points, false, 1.0f);
    ASSERT_GE(curve.size(), 20U);
    EXPECT_FLOAT_EQ(curve.front().x, 0.0f);
    EXPECT_FLOAT_EQ(curve.back().x, 20.0f);
    EXPECT_FLOAT_EQ(curve.back().height, 30.0f);
    bool middle = false;
    for (const TerrainPathPoint& p : curve) {
      middle = middle || (p.x == 10.0f && p.z == 0.0f && p.height == 20.0f);
    }
    EXPECT_TRUE(middle) << "the middle point is on the curve";
    const std::vector<TerrainPathPoint> loop = SamplePath(points, true, 1.0f);
    EXPECT_FLOAT_EQ(loop.back().x, 0.0f) << "a loop ends where it began";
  }

  TEST(
    TerrainPath,
    RampClimbsFromStartToEnd
  )
  {
    std::vector<std::uint16_t> field = Flat(10.0f);
    PathOptions o;
    o.mode = PathMode::Ramp;
    o.width = 8.0f;
    o.falloff = 0.0f;
    const SampleRect rect =
      ApplyTerrainPath(field.data(), kSide, kSide, {{8.0f, 32.0f, 10.0f}, {56.0f, 32.0f, 34.0f}}, o);
    EXPECT_LE(rect.x0, 9);
    EXPECT_GE(rect.x1, 55);
    EXPECT_NEAR(At(field, 32, 32), 22.0f, 0.05f) << "halfway up";
    EXPECT_NEAR(At(field, 56, 33), 34.0f, 0.05f) << "the top, across the width";
    EXPECT_FLOAT_EQ(At(field, 32, 40), 10.0f) << "outside the width";
  }

  TEST(
    TerrainPath,
    CarveDigsRiverRoundsAndRaiseBuilds
  )
  {
    PathOptions o;
    o.width = 10.0f;
    o.falloff = 0.0f;
    o.depth = 4.0f;
    const std::vector<TerrainPathPoint> line{{10.0f, 32.0f, 20.0f}, {54.0f, 32.0f, 20.0f}};
    std::vector<std::uint16_t> carve = Flat(20.0f);
    o.mode = PathMode::Carve;
    (void)ApplyTerrainPath(carve.data(), kSide, kSide, line, o);
    EXPECT_NEAR(At(carve, 30, 32), 16.0f, 0.05f);
    EXPECT_NEAR(At(carve, 30, 36), 16.0f, 0.05f) << "flat bottom across";
    std::vector<std::uint16_t> river = Flat(20.0f);
    o.mode = PathMode::River;
    (void)ApplyTerrainPath(river.data(), kSide, kSide, line, o);
    EXPECT_NEAR(At(river, 30, 32), 16.0f, 0.05f);
    EXPECT_GT(At(river, 30, 36), 17.0f) << "shallower towards the bank";
    std::vector<std::uint16_t> dyke = Flat(20.0f);
    o.mode = PathMode::Raise;
    (void)ApplyTerrainPath(dyke.data(), kSide, kSide, line, o);
    EXPECT_NEAR(At(dyke, 30, 32), 24.0f, 0.05f);
    // Carve never raises: ground already below the trench stays.
    std::vector<std::uint16_t> low = Flat(5.0f);
    o.mode = PathMode::Carve;
    const SampleRect none = ApplyTerrainPath(low.data(), kSide, kSide, line, o);
    EXPECT_LT(none.x1, none.x0);
  }

  TEST(
    TerrainPath,
    FalloffSoftensTheEdgeAndStatsCount
  )
  {
    std::vector<std::uint16_t> field = Flat(10.0f);
    const std::vector<std::uint16_t> before = field;
    PathOptions o;
    o.mode = PathMode::Level;
    o.width = 16.0f;
    o.falloff = 1.0f;
    (void)ApplyTerrainPath(field.data(), kSide, kSide, {{10.0f, 32.0f, 20.0f}, {54.0f, 32.0f, 40.0f}}, o);
    EXPECT_NEAR(At(field, 30, 32), 20.0f, 0.05f) << "Level: the first point's height";
    const float edge = At(field, 30, 38);
    EXPECT_GT(edge, 10.0f);
    EXPECT_LT(edge, 20.0f) << "the falloff blends";
    HeightChange change;
    for (std::size_t i = 0; i < field.size(); ++i) {
      AddHeightChange(change, before[i], field[i]);
    }
    EXPECT_GT(change.samples, 100U);
    EXPECT_GT(change.added, 0.0);
    EXPECT_EQ(change.removed, 0.0);
    EXPECT_NEAR(change.highest, 10.0f, 0.05f);
  }

  TEST(
    TerrainPath,
    InvertedModes
  )
  {
    EXPECT_EQ(InvertedHeightMode(HeightBrushMode::Raise), HeightBrushMode::Lower);
    EXPECT_EQ(InvertedHeightMode(HeightBrushMode::Sharpen), HeightBrushMode::Smooth);
    EXPECT_EQ(InvertedHeightMode(HeightBrushMode::WaterErode), HeightBrushMode::Deposit);
    EXPECT_EQ(InvertedHeightMode(HeightBrushMode::Flatten), HeightBrushMode::Flatten);
  }
} // namespace faf::editor
