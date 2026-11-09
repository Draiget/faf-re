// The map editor's decal footprints (src/editor/tools/EdDecalShape.cpp): a decal centred on a point has that point
// as its middle, its corners follow CWldTerrainDecal::ComputeCorner, and the inside test is their exact inverse.

#include "editor/tools/EdDecalShape.h"

#include <gtest/gtest.h>

#include <cmath>

namespace
{
  using faf::editor::DecalFootprint;

  TEST(DecalShape, CentredDecalHasItsMiddleThere)
  {
    for (const float yaw : {0.0f, 0.7f, 1.5707963f, 3.0f, -2.2f}) {
      const DecalFootprint decal = faf::editor::DecalAround(100.0f, 200.0f, 12.0f, 4.0f, yaw);
      float cx = 0.0f, cz = 0.0f;
      faf::editor::DecalCentre(decal, cx, cz);
      EXPECT_NEAR(cx, 100.0f, 1e-3f);
      EXPECT_NEAR(cz, 200.0f, 1e-3f);
      EXPECT_TRUE(faf::editor::DecalContains(decal, 100.0f, 200.0f));
    }
  }

  TEST(DecalShape, CornersAsTheGameComputesThem)
  {
    // Unturned: the corner, then along x by sizeX, then along z by sizeZ.
    const DecalFootprint flat{10.0f, 20.0f, 8.0f, 2.0f, 0.0f};
    float x[4], z[4];
    faf::editor::DecalCorners(flat, x, z);
    EXPECT_FLOAT_EQ(x[0], 10.0f);
    EXPECT_FLOAT_EQ(z[0], 20.0f);
    EXPECT_FLOAT_EQ(x[1], 18.0f);
    EXPECT_FLOAT_EQ(z[1], 20.0f);
    EXPECT_FLOAT_EQ(x[2], 18.0f);
    EXPECT_FLOAT_EQ(z[2], 22.0f);
    // A quarter turn: sizeX runs along +z, sizeZ along -x.
    const DecalFootprint turned{10.0f, 20.0f, 8.0f, 2.0f, 1.5707963f};
    faf::editor::DecalCorners(turned, x, z);
    EXPECT_NEAR(x[1], 10.0f, 1e-4f);
    EXPECT_NEAR(z[1], 28.0f, 1e-4f);
    EXPECT_NEAR(x[3], 8.0f, 1e-4f);
    EXPECT_NEAR(z[3], 20.0f, 1e-4f);
  }

  TEST(DecalShape, InsideIsTheCornersInverse)
  {
    const DecalFootprint decal = faf::editor::DecalAround(50.0f, 50.0f, 20.0f, 6.0f, 0.6f);
    float x[4], z[4];
    faf::editor::DecalCorners(decal, x, z);
    // Just inside each corner, towards the middle, is on it; just outside is not.
    for (int i = 0; i < 4; ++i) {
      const float inX = x[i] + (50.0f - x[i]) * 0.02f;
      const float inZ = z[i] + (50.0f - z[i]) * 0.02f;
      const float outX = x[i] - (50.0f - x[i]) * 0.02f;
      const float outZ = z[i] - (50.0f - z[i]) * 0.02f;
      EXPECT_TRUE(faf::editor::DecalContains(decal, inX, inZ)) << i;
      EXPECT_FALSE(faf::editor::DecalContains(decal, outX, outZ)) << i;
    }
  }

  TEST(DecalShape, PathPassesThroughItsPoints)
  {
    const std::vector<std::pair<float, float>> points = {{0.0f, 0.0f}, {50.0f, 20.0f}, {100.0f, 0.0f}, {120.0f, 60.0f}};
    for (std::size_t i = 0; i < points.size(); ++i) {
      const auto p = faf::editor::PathPoint(points, static_cast<float>(i));
      EXPECT_NEAR(p.first, points[i].first, 1e-3f) << i;
      EXPECT_NEAR(p.second, points[i].second, 1e-3f) << i;
    }
  }

  TEST(DecalShape, DecalsAlongAStraightPath)
  {
    // A 100-unit line along x, decals 20 long without overlap: five, centred at 10, 30, ..., 90, turned along x.
    const std::vector<std::pair<float, float>> line = {{0.0f, 5.0f}, {100.0f, 5.0f}};
    const std::vector<DecalFootprint> decals = faf::editor::DecalsAlongPath(line, 20.0f, 6.0f, 0.0f);
    ASSERT_EQ(decals.size(), 5u);
    for (std::size_t i = 0; i < decals.size(); ++i) {
      float cx = 0.0f, cz = 0.0f;
      faf::editor::DecalCentre(decals[i], cx, cz);
      EXPECT_NEAR(cx, 10.0f + 20.0f * static_cast<float>(i), 1e-2f) << i;
      EXPECT_NEAR(cz, 5.0f, 1e-2f) << i;
      EXPECT_NEAR(decals[i].yaw, 0.0f, 1e-4f) << i;
      EXPECT_FLOAT_EQ(decals[i].sizeX, 20.0f);
      EXPECT_FLOAT_EQ(decals[i].sizeZ, 6.0f);
    }
    // Half overlap: one every 10 units, ten of them.
    EXPECT_EQ(faf::editor::DecalsAlongPath(line, 20.0f, 6.0f, 0.5f).size(), 10u);
    // Fewer than two points: none.
    EXPECT_TRUE(faf::editor::DecalsAlongPath({{0.0f, 0.0f}}, 20.0f, 6.0f, 0.0f).empty());
  }

  TEST(DecalShape, DecalsTurnWithTheCurve)
  {
    // Up along z, then right along x: the first decals point along +z, the last along +x.
    const std::vector<std::pair<float, float>> corner = {{0.0f, 0.0f}, {0.0f, 100.0f}, {100.0f, 100.0f}};
    const std::vector<DecalFootprint> decals = faf::editor::DecalsAlongPath(corner, 10.0f, 4.0f, 0.0f);
    ASSERT_GE(decals.size(), 15u);
    EXPECT_NEAR(decals.front().yaw, 1.5707963f, 0.15f);
    EXPECT_NEAR(decals.back().yaw, 0.0f, 0.15f);
  }

  TEST(DecalShape, TypeFromTheTexturesName)
  {
    EXPECT_EQ(faf::editor::DecalTypeForTexture("/env/Evergreen/decals/eg_rock01_albedo.dds"), 1);
    EXPECT_EQ(faf::editor::DecalTypeForTexture("/env/Evergreen/decals/eg_rock01_NORMALS.dds"), 2);
    EXPECT_EQ(faf::editor::DecalTypeForTexture("/env/common/decals/lava_glow.dds"), 6);
    // A folder name doesn't count, only the file's.
    EXPECT_EQ(faf::editor::DecalTypeForTexture("/env/normalworld/decals/crater.dds"), 1);
    EXPECT_STREQ(faf::editor::DecalTypeName(2), "normals");
  }
} // namespace
