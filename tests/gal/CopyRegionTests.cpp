// The copy box cut shared by the backends' StretchRect and UpdateSurface (backends/common/CopyRegion.h).

#include <gtest/gtest.h>

#include "gpg/gal/backends/common/CopyRegion.h"

namespace
{
  using gpg::gal::ClampCopyRegion;
  using gpg::gal::CopyRegion;
} // namespace

TEST(
  CopyRegion,
  A_box_inside_both_surfaces_is_unchanged
)
{
  CopyRegion region{10, 20, 110, 70, 5, 6};
  ASSERT_TRUE(ClampCopyRegion(region, 200, 100, 300, 300));
  EXPECT_EQ(region.left, 10);
  EXPECT_EQ(region.top, 20);
  EXPECT_EQ(region.right, 110);
  EXPECT_EQ(region.bottom, 70);
  EXPECT_EQ(region.x, 5);
  EXPECT_EQ(region.y, 6);
}

TEST(
  CopyRegion,
  The_refraction_copy_one_row_too_tall_loses_its_last_row
)
{
  // the view rectangle of a 1280x720 window, as the engine passes it: one row below the surface
  CopyRegion region{0, 0, 1280, 721, 0, 0};
  ASSERT_TRUE(ClampCopyRegion(region, 1280, 720, 1280, 720));
  EXPECT_EQ(region.right, 1280);
  EXPECT_EQ(region.bottom, 720);
}

TEST(
  CopyRegion,
  A_destination_offset_cuts_the_box_to_what_fits
)
{
  CopyRegion region{0, 0, 100, 100, 60, 90};
  ASSERT_TRUE(ClampCopyRegion(region, 100, 100, 100, 100));
  EXPECT_EQ(region.right, 40);
  EXPECT_EQ(region.bottom, 10);
  EXPECT_EQ(region.x, 60);
  EXPECT_EQ(region.y, 90);
}

TEST(
  CopyRegion,
  A_smaller_destination_cuts_the_box
)
{
  CopyRegion region{0, 0, 256, 256, 0, 0};
  ASSERT_TRUE(ClampCopyRegion(region, 256, 256, 64, 128));
  EXPECT_EQ(region.right, 64);
  EXPECT_EQ(region.bottom, 128);
}

TEST(
  CopyRegion,
  A_box_before_the_origin_moves_the_destination_along
)
{
  CopyRegion region{-10, -4, 50, 50, 20, 30};
  ASSERT_TRUE(ClampCopyRegion(region, 100, 100, 100, 100));
  EXPECT_EQ(region.left, 0);
  EXPECT_EQ(region.top, 0);
  EXPECT_EQ(region.x, 30);
  EXPECT_EQ(region.y, 34);
  EXPECT_EQ(region.right, 50);
}

TEST(
  CopyRegion,
  A_destination_before_the_origin_drops_the_source_pixels_that_miss
)
{
  CopyRegion region{0, 0, 50, 50, -5, -7};
  ASSERT_TRUE(ClampCopyRegion(region, 100, 100, 100, 100));
  EXPECT_EQ(region.left, 5);
  EXPECT_EQ(region.top, 7);
  EXPECT_EQ(region.x, 0);
  EXPECT_EQ(region.y, 0);
}

TEST(
  CopyRegion,
  Nothing_is_left_when_the_box_misses_a_surface
)
{
  CopyRegion past{0, 0, 10, 10, 100, 0};
  EXPECT_FALSE(ClampCopyRegion(past, 100, 100, 100, 100));
  CopyRegion below{0, 0, 10, 10, 0, 100};
  EXPECT_FALSE(ClampCopyRegion(below, 100, 100, 100, 100));
  CopyRegion outside{200, 0, 300, 10, 0, 0};
  EXPECT_FALSE(ClampCopyRegion(outside, 100, 100, 100, 100));
  CopyRegion empty{5, 5, 5, 9, 0, 0};
  EXPECT_FALSE(ClampCopyRegion(empty, 100, 100, 100, 100));
  CopyRegion inverted{9, 0, 3, 9, 0, 0};
  EXPECT_FALSE(ClampCopyRegion(inverted, 100, 100, 100, 100));
}
