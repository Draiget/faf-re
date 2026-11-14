// The panels' lists fill what their panel has left (src/editor/ui/EdLayout.h FillHeightFor): the room less what
// follows, never under the minimum.

#include "editor/ui/EdLayout.h"

#include <gtest/gtest.h>

using faf::editor::FillHeightFor;

namespace
{
  TEST(
    Layout,
    ListsFillWhatThePanelHasLeft
  )
  {
    EXPECT_FLOAT_EQ(FillHeightFor(900.0f, 200.0f, 150.0f), 700.0f) << "the room less what follows";
    EXPECT_FLOAT_EQ(FillHeightFor(300.0f, 200.0f, 150.0f), 150.0f) << "a short panel: the minimum, the panel scrolls";
    EXPECT_FLOAT_EQ(FillHeightFor(-50.0f, 0.0f, 120.0f), 120.0f) << "scrolled past: still the minimum";
  }
} // namespace
