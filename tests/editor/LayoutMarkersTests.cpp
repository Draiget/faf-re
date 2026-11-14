#include "editor/tools/EdLayoutMarkers.h"

#include <gtest/gtest.h>

#include <cmath>

namespace faf::editor
{
  namespace
  {
    LayoutGround Flat(
      const float size,
      const float height = 20.0f,
      const float water = -1000.0f
    )
    {
      LayoutGround g;
      g.x1 = size;
      g.z1 = size;
      g.height = [height](float, float) {
        return height;
      };
      g.water = water;
      return g;
    }
  } // namespace

  TEST(
    LayoutMarkers,
    PatternsPutTheStartsAroundTheMiddle
  )
  {
    LayoutMarkerSettings s;
    const LayoutGround g = Flat(256.0f);
    std::vector<LayoutPoint> starts = LayoutStarts(s, g, {}, {});
    ASSERT_EQ(starts.size(), 4U);
    EXPECT_NEAR(starts[0].x, 128.0f, 0.01f) << "the ring starts at the top";
    EXPECT_NEAR(starts[0].z, 128.0f - 0.68f * 128.0f, 0.01f);
    EXPECT_NEAR(starts[0].x + starts[2].x, 256.0f, 0.01f) << "opposite starts across the middle";
    EXPECT_NEAR(starts[0].z + starts[2].z, 256.0f, 0.01f);
    s.pattern = LayoutPattern::Corners;
    s.count = 8;
    EXPECT_EQ(LayoutStarts(s, g, {}, {}).size(), 4U) << "four corners at most";
    s.pattern = LayoutPattern::Sides;
    EXPECT_EQ(LayoutStarts(s, g, {}, {}).size(), 2U);
    s.pattern = LayoutPattern::Line;
    s.count = 3;
    starts = LayoutStarts(s, g, {}, {});
    ASSERT_EQ(starts.size(), 3U);
    EXPECT_NEAR(starts[1].x, 128.0f, 0.01f);
    s.starts = LayoutStartMode::Bases;
    EXPECT_EQ(LayoutStarts(s, g, {}, {{10.0f, 20.0f, {}}}).size(), 1U);
    s.starts = LayoutStartMode::Existing;
    const std::vector<LayoutPoint> existing = {{1.0f, 2.0f, "ARMY_1"}, {3.0f, 4.0f, "ARMY_2"}};
    EXPECT_EQ(LayoutStarts(s, g, existing, {})[1].name, "ARMY_2");
  }

  TEST(
    LayoutMarkers,
    ShapesKeepTheirDistancesAndFacing
  )
  {
    const float facing = 0.0f;
    const std::vector<LayoutPoint> ring = LayoutShapePoints(LayoutShape::Ring, 0, 0, facing, 6, 16, 30, 2.8f, 7);
    ASSERT_EQ(ring.size(), 6U);
    for (const LayoutPoint& p : ring) {
      const float d = std::hypot(p.x, p.z);
      EXPECT_TRUE(std::fabs(d - 19.5f) < 0.01f || std::fabs(d - 26.5f) < 0.01f) << d;
    }
    const float arcWidth = 160.0f * 3.14159265f / 180.0f;
    for (const LayoutPoint& p : LayoutShapePoints(LayoutShape::Arc, 0, 0, facing, 5, 16, 30, arcWidth, 7)) {
      EXPECT_LE(std::fabs(std::atan2(p.z, p.x)), arcWidth / 2.0f + 1e-4f) << "inside the fan";
    }
    EXPECT_EQ(LayoutShapePoints(LayoutShape::Pairs, 0, 0, facing, 5, 16, 30, 2.8f, 7).size(), 5U);
    EXPECT_EQ(LayoutShapePoints(LayoutShape::Cluster, 0, 0, facing, 4, 16, 30, 2.8f, 7).size(), 4U);
    const std::vector<LayoutPoint> line = LayoutShapePoints(LayoutShape::Line, 0, 0, facing, 3, 20, 20, 2.8f, 7);
    ASSERT_EQ(line.size(), 3U);
    EXPECT_NEAR(line[1].x, 20.0f, 0.01f) << "a row across the facing, at the middle distance";
    EXPECT_NEAR(line[0].z, -7.0f * 1.35f, 0.01f);
    EXPECT_TRUE(LayoutShapePoints(LayoutShape::Ring, 0, 0, facing, 0, 16, 30, 2.8f, 7).empty());
  }

  TEST(
    LayoutMarkers,
    PlanFitsEveryResourceOnOpenGroundWithItsSpacing
  )
  {
    LayoutMarkerSettings s;
    s.count = 2; // a half turn
    const LayoutGround g = Flat(1024.0f);
    const std::vector<LayoutPoint> starts = LayoutStarts(s, g, {}, {});
    const LayoutMarkerPlan plan = PlanLayoutMarkers(s, g, starts, {});
    EXPECT_EQ(plan.failed, 0) << plan.text;
    EXPECT_EQ(plan.hydros, 2);
    EXPECT_EQ(plan.masses, 2 * (6 + 4) + 4);
    EXPECT_EQ(plan.text, "2 starts, 24 mass, 2 hydrocarbon");
    for (std::size_t i = 0; i < plan.items.size(); ++i) {
      const LayoutMarkerItem& a = plan.items[i];
      EXPECT_FLOAT_EQ(a.x - std::floor(a.x), 0.5f) << "on a build cell's middle";
      for (std::size_t j = i + 1; j < plan.items.size(); ++j) {
        const LayoutMarkerItem& b = plan.items[j];
        EXPECT_GE(std::hypot(a.x - b.x, a.z - b.z), s.spacing - 1e-3f) << i << " " << j;
      }
    }
    // The second start's resources are the first's turned by half: the same shapes face the middle.
    const LayoutMarkerItem* hydro1 = nullptr;
    const LayoutMarkerItem* hydro2 = nullptr;
    for (const LayoutMarkerItem& item : plan.items) {
      if (item.hydro) {
        (item.start == 1 ? hydro1 : hydro2) = &item;
      }
    }
    ASSERT_NE(hydro1, nullptr);
    ASSERT_NE(hydro2, nullptr);
    EXPECT_NEAR(hydro1->x + hydro2->x, 1024.0f, 1.01f);
    EXPECT_NEAR(hydro1->z + hydro2->z, 1024.0f, 1.01f);
    // A marker that stays keeps its spacing free; the resources skip ground under water.
    const LayoutMarkerPlan blocked = PlanLayoutMarkers(s, g, starts, {{hydro1->x, hydro1->z, {}}});
    for (const LayoutMarkerItem& item : blocked.items) {
      EXPECT_GE(std::hypot(item.x - hydro1->x, item.z - hydro1->z), s.spacing - 1e-3f);
    }
    const LayoutMarkerPlan wet = PlanLayoutMarkers(s, Flat(1024.0f, 0.0f, 10.0f), starts, {});
    EXPECT_TRUE(wet.items.empty());
    EXPECT_EQ(wet.failed, 2 * (1 + 6 + 4) + 4);
  }
} // namespace faf::editor
