#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  /** One help topic (design §8 Help): a panel's, a tool's, or the view's. */
  struct EdHelpTopic
  {
    const char* id;       // "Tools", "tool.terrain", "view": a panel's id, a tool's command, or a place
    const char* title;    // "Terrain tool"
    const char* text;     // paragraphs split by "\n\n"
    const char* commands; // commands whose keys the topic lists, comma-separated ("tool.1,edit.undo")
  };

  /** Every topic, in the Help window's order. */
  [[nodiscard]] const std::vector<EdHelpTopic>& HelpTopics();
  /** The topic with this id, or null. */
  [[nodiscard]] const EdHelpTopic* FindHelpTopic(std::string_view id);

  /**
   * F1's topic: the panel under the mouse (its window name, as Begin got it: "Tools", "Tools###Tools@objects",
   * "Script Editor###ScriptEditor@mission"), the Tools panel's topic being the tool in use (`tool` 0 Select ... 7
   * Units); "view" when the mouse is over no panel (an empty name).
   */
  [[nodiscard]] std::string HelpTopicForWindow(std::string_view windowName, int tool);

  /** The topics whose title or text has every word of `query` (case aside), in the topics' order. */
  [[nodiscard]] std::vector<const EdHelpTopic*> SearchHelp(std::string_view query);

  /** One step of the tour: what it points at (a window by name, or "view" for the map view) and what it says. */
  struct EdTourStep
  {
    const char* target;
    const char* title;
    const char* text;
  };
  [[nodiscard]] const std::vector<EdTourStep>& TourSteps();
} // namespace faf::editor
