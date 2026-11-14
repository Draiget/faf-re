// The map editor's History panel (src/editor/ui/EdHistory.cpp): the rows from the undo and redo orders, oldest first,
// numbered where names repeat, and how many Undos or Redos reach a row.

#include "editor/ui/EdHistory.h"

#include <gtest/gtest.h>

using faf::editor::HistoryRows;
using faf::editor::StepsTo;

namespace
{
  TEST(
    History,
    RowsOldestFirstWithTheUndoneAfter
  )
  {
    // Done: a stroke, props, another stroke. Undone: decals (undone last, so the next Redo), then water.
    const auto rows = HistoryRows({"height stroke", "props", "height stroke"}, {"water", "decals"});
    ASSERT_EQ(rows.size(), 6u);
    EXPECT_EQ(rows[0].label, "Opened");
    EXPECT_EQ(rows[0].position, 0);
    EXPECT_EQ(rows[1].label, "height stroke");
    EXPECT_EQ(rows[3].label, "height stroke 2") << "repeated names numbered";
    EXPECT_EQ(rows[3].position, 3);
    EXPECT_TRUE(rows[3].done);
    EXPECT_EQ(rows[4].label, "decals") << "the next Redo comes first among the undone";
    EXPECT_FALSE(rows[4].done);
    EXPECT_EQ(rows[5].label, "water");
    EXPECT_EQ(rows[5].position, 5);
  }

  TEST(
    History,
    NothingDoneYet
  )
  {
    const auto rows = HistoryRows({}, {});
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0].label, "Opened");
    EXPECT_TRUE(rows[0].done);
  }

  TEST(
    History,
    StepsToARow
  )
  {
    EXPECT_EQ(StepsTo(3, 0), -3) << "three Undos back to as opened";
    EXPECT_EQ(StepsTo(3, 5), 2) << "two Redos";
    EXPECT_EQ(StepsTo(2, 2), 0);
  }
} // namespace
