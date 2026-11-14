#include "editor/tools/EdSelectModes.h"

#include <gtest/gtest.h>

namespace faf::editor
{
  TEST(
    SelectModes,
    AllNoneInvertAndSameTypeOverTheSelectableItems
  )
  {
    const std::vector<std::string> keys = {"pine", "rock", "pine", "bush", "pine", "rock"};
    const std::vector<bool> selectable = {true, true, true, true, false, true}; // item 4 hidden
    using V = std::vector<std::size_t>;
    EXPECT_EQ(SelectByMode(keys, selectable, {}, SelectMode::All), (V{0, 1, 2, 3, 5}));
    EXPECT_EQ(SelectByMode(keys, selectable, {1, 2}, SelectMode::None), V{});
    EXPECT_EQ(SelectByMode(keys, selectable, {1, 2}, SelectMode::Invert), (V{0, 3, 5})) << "the hidden one stays out";
    EXPECT_EQ(SelectByMode(keys, selectable, {0}, SelectMode::Same), (V{0, 2})) << "pines, not the hidden one";
    EXPECT_EQ(SelectByMode(keys, selectable, {0, 5}, SelectMode::Same), (V{0, 1, 2, 5}));
    EXPECT_EQ(SelectByMode(keys, selectable, {}, SelectMode::Same), V{}) << "nothing selected: nothing alike";
    EXPECT_EQ(SelectByMode(keys, {}, {3}, SelectMode::Invert), (V{0, 1, 2, 4, 5})) << "no flags: all selectable";
    EXPECT_STREQ(SelectModeName(SelectMode::Same), "same type");
  }
} // namespace faf::editor
