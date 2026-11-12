// The map editor's help (src/editor/ui/EdHelpTopics.cpp): every panel and tool has a topic, F1 finds the topic from
// the window under the mouse in any workspace, the search, and the tour's steps.

#include "editor/ui/EdHelpTopics.h"

#include <set>

#include <gtest/gtest.h>

using faf::editor::FindHelpTopic;
using faf::editor::HelpTopicForWindow;
using faf::editor::HelpTopics;
using faf::editor::SearchHelp;
using faf::editor::TourSteps;

namespace
{
  TEST(
    HelpTopics,
    EveryPanelAndToolHasOne
  )
  {
    // The panels' ids (EdShell::PanelFlags, PanelId) and the eight tools.
    for (const char* const id :
         {"Tools",
          "Properties",
          "Map",
          "Info",
          "Markers",
          "Check",
          "Armies",
          "Lighting",
          "ScriptEditor",
          "AdaptiveMap",
          "Material Editor",
          "Particle Editor",
          "Particle Browser",
          "Log",
          "History"}) {
      const std::string topic = HelpTopicForWindow(id, 1);
      EXPECT_NE(topic, "view") << id << " has no topic of its own";
      EXPECT_NE(FindHelpTopic(topic), nullptr) << id;
    }
    std::set<std::string> ids;
    for (const auto& topic : HelpTopics()) {
      EXPECT_TRUE(ids.insert(topic.id).second) << "two topics " << topic.id;
      EXPECT_GT(std::string(topic.text).size(), 40u) << topic.id;
    }
    for (int tool = 0; tool < 8; ++tool) {
      EXPECT_NE(FindHelpTopic(HelpTopicForWindow("Tools", tool)), nullptr) << tool;
    }
  }

  TEST(
    HelpTopics,
    F1FindsThePanelInAnyWorkspace
  )
  {
    EXPECT_EQ(HelpTopicForWindow("Tools", 1), "tool.terrain") << "the Tools panel: the tool in use";
    EXPECT_EQ(HelpTopicForWindow("Tools###Tools@objects", 0), "tool.select");
    EXPECT_EQ(HelpTopicForWindow("Tools###Tools@objects/##toolsettings_1234", 7), "tool.units") << "a child window";
    EXPECT_EQ(HelpTopicForWindow("Script Editor###ScriptEditor@mission", 0), "ScriptEditor");
    EXPECT_EQ(HelpTopicForWindow("Info", 0), "Info");
    EXPECT_EQ(HelpTopicForWindow("Start###Home", 0), "start");
    EXPECT_EQ(HelpTopicForWindow("", 0), "view") << "over no panel: the view";
    EXPECT_EQ(HelpTopicForWindow("##SomethingElse", 0), "view");
  }

  TEST(
    HelpTopics,
    SearchAndTour
  )
  {
    const auto symmetry = SearchHelp("symmetry");
    ASSERT_FALSE(symmetry.empty());
    EXPECT_STREQ(symmetry.front()->id, "tool.terrain");
    EXPECT_EQ(SearchHelp("").size(), HelpTopics().size()) << "no words: all";
    EXPECT_TRUE(SearchHelp("zzzz qqqq").empty());
    EXPECT_FALSE(SearchHelp("UNDO").empty()) << "case aside";

    ASSERT_GE(TourSteps().size(), 5u);
    for (const auto& step : TourSteps()) {
      EXPECT_NE(std::string(step.text), "");
    }
  }
} // namespace
