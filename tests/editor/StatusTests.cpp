// The map editor's status bar (src/editor/ui/EdStatus.cpp): which items stay when the window is narrow, the selection
// said as a count, how long ago the last message was, and the message itself.

#include "editor/ui/EdStatus.h"

#include <gtest/gtest.h>

using faf::editor::AgoText;
using faf::editor::FitStatusItems;
using faf::editor::PostStatusMessageAt;
using faf::editor::SelectionCountText;
using faf::editor::StatusMessage;
using faf::editor::StatusMessageTime;

namespace
{
  using Kept = std::vector<std::size_t>;

  TEST(
    Status,
    EverythingFitsWhenThereIsRoom
  )
  {
    EXPECT_EQ(FitStatusItems({10, 20, 30}, {7, 0, 3}, 100, 5), (Kept{0, 1, 2}));
    EXPECT_EQ(FitStatusItems({10, 20, 30}, {7, 0, 3}, 70, 5), (Kept{0, 1, 2})) << "exactly 70 with the gaps";
    EXPECT_TRUE(FitStatusItems({}, {}, 10, 5).empty());
  }

  TEST(
    Status,
    TheLeastWantedGoFirst
  )
  {
    // renderer (7), mode (0), warnings (1), cursor (2), GPU (8), undo (5)
    const std::vector<float> widths = {40, 50, 60, 70, 80, 90};
    const std::vector<int> priorities = {7, 0, 1, 2, 8, 5};
    EXPECT_EQ(FitStatusItems(widths, priorities, 390, 0).size(), 6u) << "390 wide: all fit";
    EXPECT_EQ(FitStatusItems(widths, priorities, 380, 0), (Kept{0, 1, 2, 3, 5})) << "the GPU goes first";
    EXPECT_EQ(FitStatusItems(widths, priorities, 300, 0), (Kept{1, 2, 3, 5})) << "then the renderer";
    EXPECT_EQ(FitStatusItems(widths, priorities, 200, 0), (Kept{1, 2, 3})) << "then the undo step";
    EXPECT_EQ(FitStatusItems(widths, priorities, 10, 0), (Kept{1})) << "the mode always stays, even when too wide";
  }

  TEST(
    Status,
    EqualPrioritiesDropTheLastFirst
  )
  {
    EXPECT_EQ(FitStatusItems({30, 30, 30}, {2, 2, 2}, 65, 0), (Kept{0, 1}));
  }

  TEST(
    Status,
    SelectionAsACount
  )
  {
    EXPECT_EQ(SelectionCountText("3 markers: ARMY_1, ..."), "3 markers");
    EXPECT_EQ(SelectionCountText("1 unit: uel0001 (ARMY_1)"), "1 unit");
    EXPECT_EQ(SelectionCountText("Nothing selected"), "");
    EXPECT_EQ(SelectionCountText(""), "");
  }

  TEST(
    Status,
    HowLongAgo
  )
  {
    EXPECT_EQ(AgoText(0.0), "now");
    EXPECT_EQ(AgoText(4.9), "now");
    EXPECT_EQ(AgoText(12.4), "12 s ago");
    EXPECT_EQ(AgoText(185.0), "3 min ago");
    EXPECT_EQ(AgoText(7300.0), "2 h ago");

    PostStatusMessageAt("Saved scmp_009", 42.0);
    EXPECT_EQ(StatusMessage(), "Saved scmp_009");
    EXPECT_DOUBLE_EQ(StatusMessageTime(), 42.0);
  }
} // namespace
