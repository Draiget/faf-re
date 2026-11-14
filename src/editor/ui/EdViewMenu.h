#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The view's context menu (a right click that doesn't drag; design §5): the commands it offers, in order ("" a
   * separator). With a selection: what to do with it; without: the camera and the clipboard. Each entry is a command,
   * shown greyed with its reason when it can't run.
   */
  [[nodiscard]] std::vector<std::string> ViewMenuCommands(bool selection);
} // namespace faf::editor
