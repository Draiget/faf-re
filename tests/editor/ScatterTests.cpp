// Map-wide scatter (src/editor/tools/EdScatter.cpp): points at a density, apart by the spacing, filtered, repeatable.

#include "editor/tools/EdScatter.h"

#include <gtest/gtest.h>

#include <cmath>

namespace
{
  using faf::editor::ScatterOptions;
  using faf::editor::ScatterPoints;
  using faf::editor::SlopeDegrees;

  const auto kAll = [](float, float) {
    return true;
  };

  TEST(
    Scatter,
    DensityGivesAboutTheCount
  )
  {
    ScatterOptions options;
    options.x1 = 1000.0f;
    options.z1 = 1000.0f;
    options.density = 20.0f; // per 100 x 100: 2000 over the square
    options.spacing = 4.0f;
    const auto points = ScatterPoints(options, kAll);
    // Some candidates fall too near a neighbour and are dropped: fewer than asked, but most.
    EXPECT_GT(points.size(), 1500U);
    EXPECT_LE(points.size(), 2100U);
    for (const auto& [x, z] : points) {
      ASSERT_GE(x, 0.0f);
      ASSERT_LE(x, 1000.0f);
      ASSERT_GE(z, 0.0f);
      ASSERT_LE(z, 1000.0f);
    }
  }

  TEST(
    Scatter,
    NoTwoNearerThanTheSpacing
  )
  {
    ScatterOptions options;
    options.x1 = 200.0f;
    options.z1 = 200.0f;
    options.density = 400.0f; // every cell a candidate
    options.spacing = 6.0f;
    const auto points = ScatterPoints(options, kAll);
    ASSERT_GT(points.size(), 300U);
    for (std::size_t a = 0; a < points.size(); ++a) {
      for (std::size_t b = a + 1; b < points.size(); ++b) {
        ASSERT_GE(std::hypot(points[a].first - points[b].first, points[a].second - points[b].second), 6.0f - 1e-4f);
      }
    }
  }

  TEST(
    Scatter,
    FilteredRepeatableAndLimited
  )
  {
    ScatterOptions options;
    options.x1 = 300.0f;
    options.z1 = 300.0f;
    options.density = 50.0f;
    const auto left = ScatterPoints(options, [](const float x, float) {
      return x < 150.0f;
    });
    for (const auto& [x, z] : left) {
      ASSERT_LT(x, 150.0f) << "accept decides";
    }
    EXPECT_EQ(ScatterPoints(options, kAll), ScatterPoints(options, kAll)) << "the same options give the same points";
    ScatterOptions other = options;
    other.seed = 2;
    EXPECT_NE(ScatterPoints(options, kAll), ScatterPoints(other, kAll)) << "another seed, other points";
    options.limit = 10;
    EXPECT_EQ(ScatterPoints(options, kAll).size(), 10U);
    options.density = 0.0f;
    EXPECT_TRUE(ScatterPoints(options, kAll).empty());
  }

  TEST(
    Scatter,
    SlopeInDegrees
  )
  {
    EXPECT_NEAR(SlopeDegrees(5.0f, 5.0f, 5.0f, 5.0f), 0.0f, 1e-4f);
    EXPECT_NEAR(SlopeDegrees(0.0f, 2.0f, 0.0f, 0.0f), 45.0f, 1e-3f) << "one up for one across";
    EXPECT_NEAR(SlopeDegrees(0.0f, 0.0f, 2.0f, 0.0f), 45.0f, 1e-3f) << "either way";
  }
} // namespace
