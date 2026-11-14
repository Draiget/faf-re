// Follow symmetry (src/editor/tools/EdSymmetryFollow.cpp): an object's mirrored copies found by the images of its
// place, and an edit carried to them through the same images.

#include "editor/tools/EdSymmetryFollow.h"

#include <gtest/gtest.h>

#include <cmath>
#include <vector>

namespace
{
  using faf::editor::FindSymmetryPartners;
  using faf::editor::FollowItem;
  using faf::editor::kMaxSymmetryCopies;
  using faf::editor::Symmetry;
  using faf::editor::SymmetricPlaces;

  constexpr int kSide = 257; // a 256-unit map

  TEST(
    SymmetryFollow,
    PartnersAreTheSameKindAtTheImages
  )
  {
    // A half-turn map: a pine at (40, 60) and its copy at (216, 196); a rock at the copy's place too; a pine elsewhere.
    const std::vector<FollowItem> items = {
      {40.0f, 60.0f, "pine"},
      {216.2f, 195.9f, "rock"},
      {216.0f, 196.0f, "pine"},
      {100.0f, 100.0f, "pine"},
    };
    const auto partners = FindSymmetryPartners(items, {0}, kSide, kSide, Symmetry::HalfTurn, 2, 1.5f);
    ASSERT_EQ(partners.size(), 1U);
    ASSERT_EQ(partners[0].size(), 1U) << "a half turn has one copy";
    EXPECT_EQ(partners[0][0], 2) << "the pine at the image, not the rock beside it";
    // A selected partner is edited itself: it isn't a copy of another.
    const auto both = FindSymmetryPartners(items, {0, 2}, kSide, kSide, Symmetry::HalfTurn, 2, 1.5f);
    EXPECT_EQ(both[0][0], -1);
    EXPECT_EQ(both[1][0], -1);
    // Nothing near the image: none.
    const auto alone = FindSymmetryPartners(items, {3}, kSide, kSide, Symmetry::HalfTurn, 2, 1.5f);
    EXPECT_EQ(alone[0][0], -1);
  }

  TEST(
    SymmetryFollow,
    QuarterTurnsFindAllThree
  )
  {
    // (40, 60) turned about (128, 128) a quarter at a time.
    std::vector<FollowItem> items = {{40.0f, 60.0f, "mass"}};
    float x[kMaxSymmetryCopies];
    float z[kMaxSymmetryCopies];
    float h[kMaxSymmetryCopies];
    const int copies = SymmetricPlaces(kSide, kSide, Symmetry::QuarterTurns, 4, 40.0f, 60.0f, 0.0f, x, z, h);
    ASSERT_EQ(copies, 4);
    for (int c = 1; c < copies; ++c) {
      items.push_back({x[c] + 0.3f, z[c] - 0.2f, "mass"});
    }
    const auto partners = FindSymmetryPartners(items, {0}, kSide, kSide, Symmetry::QuarterTurns, 4, 1.0f);
    ASSERT_EQ(partners[0].size(), 3U);
    EXPECT_EQ(partners[0][0], 1);
    EXPECT_EQ(partners[0][1], 2);
    EXPECT_EQ(partners[0][2], 3);
  }

  TEST(
    SymmetryFollow,
    HeadingsTurnWithTheImage
  )
  {
    float x[kMaxSymmetryCopies];
    float z[kMaxSymmetryCopies];
    float h[kMaxSymmetryCopies];
    // Left-right: facing +x (heading pi/2) mirrors to facing -x.
    ASSERT_EQ(SymmetricPlaces(kSide, kSide, Symmetry::LeftRight, 2, 40.0f, 60.0f, 1.5707963f, x, z, h), 2);
    EXPECT_NEAR(x[1], 216.0f, 1e-3f);
    EXPECT_NEAR(z[1], 60.0f, 1e-3f);
    EXPECT_NEAR(std::sin(h[1]), -1.0f, 1e-4f);
    // Half turn: facing +z (heading 0) turns to facing -z.
    ASSERT_EQ(SymmetricPlaces(kSide, kSide, Symmetry::HalfTurn, 2, 40.0f, 60.0f, 0.0f, x, z, h), 2);
    EXPECT_NEAR(std::cos(h[1]), -1.0f, 1e-4f);
  }
} // namespace
