#include "editor/ui/EdViewMenu.h"

#include <gtest/gtest.h>

#include <algorithm>

namespace faf::editor
{
  TEST(
    ViewMenu,
    WithASelectionItActsOnItWithoutOneOnTheCameraAndClipboard
  )
  {
    const std::vector<std::string> selected = ViewMenuCommands(true);
    const std::vector<std::string> none = ViewMenuCommands(false);
    const auto has = [](const std::vector<std::string>& list, const char* id) {
      return std::find(list.begin(), list.end(), id) != list.end();
    };
    EXPECT_TRUE(has(selected, "view.focus"));
    EXPECT_TRUE(has(selected, "edit.delete"));
    EXPECT_TRUE(has(selected, "select.same"));
    EXPECT_FALSE(has(selected, "edit.paste"));
    EXPECT_TRUE(has(none, "edit.paste"));
    EXPECT_TRUE(has(none, "view.frame"));
    EXPECT_FALSE(has(none, "edit.delete"));
    // Separators only between entries.
    for (const auto* list : {&selected, &none}) {
      EXPECT_FALSE(list->front().empty());
      EXPECT_FALSE(list->back().empty());
      for (std::size_t i = 1; i < list->size(); ++i) {
        EXPECT_FALSE((*list)[i].empty() && (*list)[i - 1].empty());
      }
    }
  }
} // namespace faf::editor
