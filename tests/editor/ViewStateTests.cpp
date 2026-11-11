// The view switches and tool kept per map (src/editor/doc/EdViewState.cpp).

#include "editor/doc/EdViewState.h"

#include <gtest/gtest.h>

namespace
{
  TEST(ViewState, WrittenAndReadBack)
  {
    faf::editor::ViewState state;
    state.tool = 6;
    state.grid = true;
    state.gridStep = 4.0f;
    state.pathing = true;
    state.pathingLayer = 2;
    state.props = false;
    state.gameUnits = false;
    state.hiddenMarkerTypes = {"Air Path Node", "Land Path Node"};
    const faf::editor::ViewState back = faf::editor::ReadViewState(faf::editor::WriteViewState(state), faf::editor::ViewState{});
    EXPECT_EQ(back, state);
  }

  TEST(ViewState, MissingKeysKeepTheirValues)
  {
    faf::editor::ViewState now;
    now.slope = true;
    now.hiddenMarkerTypes = {"Mass"};
    // Only the tool: the rest as it was (a file of an older editor).
    const faf::editor::ViewState read = faf::editor::ReadViewState("grid=1\r\n", now);
    EXPECT_TRUE(read.grid);
    EXPECT_TRUE(read.slope);
    EXPECT_EQ(read.hiddenMarkerTypes, now.hiddenMarkerTypes);
    // A full file without hidden types hides none.
    EXPECT_TRUE(faf::editor::ReadViewState("tool=1\ngrid=0\n", now).hiddenMarkerTypes.empty());
    // A bad step falls back to 1.
    EXPECT_EQ(faf::editor::ReadViewState("gridStep=0\n", now).gridStep, 1.0f);
  }

  TEST(ViewState, AFileAMap)
  {
    const std::string a = faf::editor::ViewStateFileName("/maps/scmp_009/scmp_009_scenario.lua");
    EXPECT_EQ(a.rfind("scmp_009-", 0), 0u);
    EXPECT_EQ(a.substr(a.size() - 4), ".txt");
    EXPECT_EQ(a, faf::editor::ViewStateFileName("/MAPS/SCMP_009/scmp_009_scenario.lua")); // the same map whatever its case
    EXPECT_NE(a, faf::editor::ViewStateFileName("C:/Users/x/Maps/scmp_009/scmp_009_scenario.lua")); // a copy elsewhere
  }
} // namespace
