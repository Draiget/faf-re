// Arrange (src/editor/tools/EdArrange.cpp): a selection's places aligned, distributed, on a circle, snapped, mirrored.

#include "editor/tools/EdArrange.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <set>

namespace
{
  using faf::editor::Arrange;
  using faf::editor::ArrangeFromId;
  using faf::editor::ArrangeId;
  using faf::editor::ArrangeOp;
  using faf::editor::ArrangePlaces;

  constexpr float kPi = 3.14159265358979f;

  ArrangePlaces Four()
  {
    return ArrangePlaces{{10.0f, 40.0f, 25.0f, 31.0f}, {5.0f, 9.0f, 20.0f, 13.0f}, {0.0f, 0.5f, 1.0f, -2.0f}};
  }

  TEST(
    Arrange,
    AlignsToTheEdgesAndTheMiddle
  )
  {
    ArrangePlaces p = Four();
    ASSERT_TRUE(Arrange(ArrangeOp::AlignLeft, p));
    for (const float x : p.x) {
      EXPECT_FLOAT_EQ(x, 10.0f);
    }
    EXPECT_FLOAT_EQ(p.z[2], 20.0f) << "the other axis stays";
    p = Four();
    ASSERT_TRUE(Arrange(ArrangeOp::AlignCentreX, p));
    EXPECT_FLOAT_EQ(p.x[0], 25.0f) << "the middle of the leftmost and rightmost, not the mean";
    p = Four();
    ASSERT_TRUE(Arrange(ArrangeOp::AlignRight, p));
    EXPECT_FLOAT_EQ(p.x[3], 40.0f);
    p = Four();
    ASSERT_TRUE(Arrange(ArrangeOp::AlignTop, p));
    EXPECT_FLOAT_EQ(p.z[1], 5.0f) << "top is the smallest z";
    p = Four();
    ASSERT_TRUE(Arrange(ArrangeOp::AlignBottom, p));
    EXPECT_FLOAT_EQ(p.z[0], 20.0f);
    p = Four();
    ASSERT_TRUE(Arrange(ArrangeOp::AlignCentreZ, p));
    EXPECT_FLOAT_EQ(p.z[0], 12.5f);
    // Headings are kept.
    EXPECT_FLOAT_EQ(p.heading[3], -2.0f);
  }

  TEST(
    Arrange,
    DistributesEvenlyInTheirOrder
  )
  {
    ArrangePlaces p = Four();
    ASSERT_TRUE(Arrange(ArrangeOp::DistributeX, p));
    // In x order: 10 (0), 25 (2), 31 (3), 40 (1) -> 10, 20, 30, 40.
    EXPECT_FLOAT_EQ(p.x[0], 10.0f);
    EXPECT_FLOAT_EQ(p.x[2], 20.0f);
    EXPECT_FLOAT_EQ(p.x[3], 30.0f);
    EXPECT_FLOAT_EQ(p.x[1], 40.0f);
    EXPECT_FLOAT_EQ(p.z[1], 9.0f);
    ArrangePlaces two{{0.0f, 9.0f}, {0.0f, 0.0f}, {}};
    EXPECT_FALSE(Arrange(ArrangeOp::DistributeX, two)) << "two have nothing between them";
    EXPECT_FLOAT_EQ(two.x[1], 9.0f);
  }

  TEST(
    Arrange,
    CircleKeepsTheirTurnRoundTheMiddle
  )
  {
    ArrangePlaces p{{0.0f, 10.0f, 10.0f, 0.0f, 5.0f}, {0.0f, 0.0f, 10.0f, 10.0f, 1.0f}, {}};
    ASSERT_TRUE(Arrange(ArrangeOp::Circle, p));
    const float cx = (0.0f + 10.0f + 10.0f + 0.0f + 5.0f) / 5.0f;
    const float cz = (0.0f + 0.0f + 10.0f + 10.0f + 1.0f) / 5.0f;
    float radius = -1.0f;
    std::set<int> steps;
    for (std::size_t i = 0; i < p.x.size(); ++i) {
      const float r = std::hypot(p.x[i] - cx, p.z[i] - cz);
      if (radius < 0.0f) {
        radius = r;
      }
      EXPECT_NEAR(r, radius, 1e-3f) << "every one on the same circle";
      steps.insert(static_cast<int>(std::lround(std::atan2(p.z[i] - cz, p.x[i] - cx) / (2.0f * kPi / 5.0f) * 1000.0f)));
    }
    EXPECT_EQ(steps.size(), 5U) << "five different places";
    // Evenly: neighbours one fifth of a turn apart.
    for (std::size_t i = 0; i < p.x.size(); ++i) {
      float nearest = 1e9f;
      for (std::size_t j = 0; j < p.x.size(); ++j) {
        if (i != j) {
          nearest = std::min(nearest, std::hypot(p.x[i] - p.x[j], p.z[i] - p.z[j]));
        }
      }
      EXPECT_NEAR(nearest, 2.0f * radius * std::sin(kPi / 5.0f), 1e-3f);
    }
  }

  TEST(
    Arrange,
    SnapsToTheStep
  )
  {
    ArrangePlaces p{{3.1f, 6.9f}, {-1.2f, 9.0f}, {}};
    ASSERT_TRUE(Arrange(ArrangeOp::Snap, p, 4.0f));
    EXPECT_FLOAT_EQ(p.x[0], 4.0f);
    EXPECT_FLOAT_EQ(p.x[1], 8.0f);
    EXPECT_FLOAT_EQ(p.z[0], 0.0f);
    EXPECT_FLOAT_EQ(p.z[1], 8.0f);
    EXPECT_FALSE(Arrange(ArrangeOp::Snap, p, 0.0f));
  }

  TEST(
    Arrange,
    MirrorsPlacesAndHeadings
  )
  {
    ArrangePlaces p{{10.0f, 30.0f}, {0.0f, 4.0f}, {kPi * 0.5f, 0.3f}};
    ASSERT_TRUE(Arrange(ArrangeOp::MirrorX, p));
    EXPECT_FLOAT_EQ(p.x[0], 30.0f);
    EXPECT_FLOAT_EQ(p.x[1], 10.0f);
    EXPECT_FLOAT_EQ(p.z[1], 4.0f);
    EXPECT_NEAR(std::sin(p.heading[0]), -1.0f, 1e-5f) << "facing +x turns to facing -x";
    EXPECT_NEAR(p.heading[1], -0.3f, 1e-5f);
    ArrangePlaces q{{10.0f, 30.0f}, {0.0f, 4.0f}, {0.0f, kPi * 0.5f}};
    ASSERT_TRUE(Arrange(ArrangeOp::MirrorZ, q));
    EXPECT_FLOAT_EQ(q.z[0], 4.0f);
    EXPECT_FLOAT_EQ(q.z[1], 0.0f);
    EXPECT_NEAR(std::cos(q.heading[0]), -1.0f, 1e-5f) << "facing +z turns to facing -z";
    EXPECT_NEAR(std::sin(q.heading[1]), 1.0f, 1e-5f) << "facing +x stays";
    // Twice is the start.
    ASSERT_TRUE(Arrange(ArrangeOp::MirrorZ, q));
    EXPECT_FLOAT_EQ(q.z[0], 0.0f);
    EXPECT_NEAR(std::cos(q.heading[0]), 1.0f, 1e-5f);
  }

  TEST(
    Arrange,
    IdsRoundTrip
  )
  {
    for (int i = 0; i < static_cast<int>(ArrangeOp::Count); ++i) {
      EXPECT_EQ(ArrangeFromId(ArrangeId(static_cast<ArrangeOp>(i))), static_cast<ArrangeOp>(i));
    }
    EXPECT_EQ(ArrangeFromId("nope"), ArrangeOp::Count);
    ArrangePlaces one{{1.0f}, {1.0f}, {}};
    EXPECT_FALSE(Arrange(ArrangeOp::AlignLeft, one)) << "one place has nothing to line up with";
  }
} // namespace
