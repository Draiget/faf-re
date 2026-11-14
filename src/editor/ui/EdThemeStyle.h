#pragma once

#include <string>
#include <vector>

struct ImGuiStyle;

namespace faf::editor
{
  struct EdTheme;

  /**
   * The theme over a style whose sizes are still at 100 % (before the screen's DPI and the user's UI scale): ImGui's
   * dark or light colours, then the accent's (ticks, sliders, selection, the active tab, text selection, drop target),
   * then the theme's own by name; corners when it sets them. Returns the colour names ImGui doesn't have.
   */
  std::vector<std::string> ApplyTheme(const EdTheme& theme, ImGuiStyle& style);
} // namespace faf::editor
