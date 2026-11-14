// The map editor's workspaces (src/editor/ui/EdWorkspaces.cpp): ten of them on Alt+1 to Alt+0, each panel a window of
// its own per workspace (the first keeping the names layouts were saved with), each workspace's own dock space, and
// the panels a workspace starts with.

#include "editor/ui/EdCommands.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdWorkspaces.h"

#include <set>

#include <gtest/gtest.h>

using faf::editor::CanonicalChord;
using faf::editor::DefaultPanels;
using faf::editor::DockSpaceName;
using faf::editor::JoinPanelList;
using faf::editor::PanelId;
using faf::editor::PanelWindowName;
using faf::editor::PanelWindowNameBeforeIcons;
using faf::editor::SplitPanelList;
using faf::editor::WorkspaceByKey;
using faf::editor::Workspaces;

namespace
{
  TEST(
    Workspaces,
    TenOnAltOneToAltZero
  )
  {
    ASSERT_EQ(Workspaces().size(), 10u);
    std::set<std::string> keys;
    std::set<std::string> ids;
    for (std::size_t i = 0; i < Workspaces().size(); ++i) {
      const auto& w = Workspaces()[i];
      const std::string expected = "Alt+" + std::to_string((i + 1) % 10);
      EXPECT_EQ(CanonicalChord(w.keys), expected) << w.name;
      keys.insert(w.keys);
      ids.insert(w.key);
      EXPECT_EQ(WorkspaceByKey(w.key), static_cast<int>(i));
    }
    EXPECT_EQ(keys.size(), 10u);
    EXPECT_EQ(ids.size(), 10u);
    EXPECT_EQ(WorkspaceByKey("nope"), -1);
    EXPECT_EQ(Workspaces()[0].name, std::string("Terrain"));
    EXPECT_TRUE(Workspaces()[9].readOnly) << "Review only looks";
    for (std::size_t i = 0; i < 9; ++i) {
      EXPECT_FALSE(Workspaces()[i].readOnly) << Workspaces()[i].name;
    }
  }

  TEST(
    Workspaces,
    EachPanelIsAWindowOfItsOwnPerWorkspace
  )
  {
    // The titles carry the panel's icon; the id after ### is the one the window had before icons.
    EXPECT_EQ(PanelWindowName("Tools", 0), ICON_WAND "  Tools###Tools") << "the first: the bare title as its id";
    EXPECT_EQ(PanelWindowName("Tools", 1), ICON_WAND "  Tools###Tools@objects");
    EXPECT_EQ(PanelWindowName("Script Editor###ScriptEditor", 5), ICON_SCRIPT "  Script Editor###ScriptEditor@mission");
    EXPECT_EQ(PanelWindowName("Script Editor###ScriptEditor", 0), ICON_SCRIPT "  Script Editor###ScriptEditor");
    EXPECT_EQ(PanelWindowName("Log", 99), ICON_CONSOLE "  Log###Log") << "no such workspace: the panel's own id";
    EXPECT_EQ(PanelWindowName("Nameless", 1), "Nameless###Nameless@objects") << "no icon: the name as before";
    // Where a saved layout has them.
    EXPECT_EQ(PanelWindowNameBeforeIcons("Tools", 0), "Tools");
    EXPECT_EQ(PanelWindowNameBeforeIcons("Tools", 1), "Tools###Tools@objects");
    EXPECT_EQ(PanelWindowNameBeforeIcons("Script Editor###ScriptEditor", 5), "Script Editor###ScriptEditor@mission");
    EXPECT_EQ(DockSpaceName(0), "EditorDockSpace");
    EXPECT_EQ(DockSpaceName(6), "EditorDockSpace@effects");
    EXPECT_EQ(PanelId("Script Editor###ScriptEditor"), "ScriptEditor");
    EXPECT_EQ(PanelId("Tools"), "Tools");
  }

  TEST(
    Workspaces,
    PanelListsAndFirstPanels
  )
  {
    EXPECT_EQ(SplitPanelList(" Tools, Log ,,Map "), (std::vector<std::string>{"Tools", "Log", "Map"}));
    EXPECT_TRUE(SplitPanelList("").empty());
    EXPECT_EQ(JoinPanelList({"Tools", "Log"}), "Tools,Log");
    EXPECT_EQ(
      DefaultPanels(0),
      (std::vector<std::string>{
        "Tools", "Layers", "Info", "Properties", "Problems", "Log", "History", "Markers", "Check", "Map"
      })
    ) << "Terrain: the tool at the left, Layers and Info at the right with Properties under them, the rest below";
    // A layout saved before Terrain's changed is laid out again once; the others keep theirs.
    EXPECT_EQ(faf::editor::LayoutVersionOf("terrain"), 2);
    EXPECT_EQ(faf::editor::LayoutVersionOf("environment"), 1);
    EXPECT_EQ(faf::editor::LayoutVersionOf("objects"), 2) << "Objects: Assets beside Properties";
    const std::vector<std::string> mission = DefaultPanels(5);
    EXPECT_NE(std::find(mission.begin(), mission.end(), "ScriptEditor"), mission.end()) << "ids, not window names";
    EXPECT_TRUE(DefaultPanels(42).empty());
    for (std::size_t i = 0; i < Workspaces().size(); ++i) {
      EXPECT_FALSE(DefaultPanels(static_cast<int>(i)).empty()) << Workspaces()[i].name << " shows something";
    }
  }
} // namespace
