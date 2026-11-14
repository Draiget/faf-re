#include "editor/ui/EdViewMenu.h"

namespace faf::editor
{
  std::vector<std::string> ViewMenuCommands(
    const bool selection
  )
  {
    if (selection) {
      return {
        "view.focus",
        "",
        "edit.duplicate",
        "edit.copy",
        "edit.delete",
        "",
        "select.same",
        "select.invert",
        "select.none",
        "",
        "object.turnleft",
        "object.turnright",
      };
    }
    return {
      "edit.paste",
      "select.all",
      "",
      "view.frame",
      "view.north",
      "view.down",
      "",
      "view.bookmark.save.1",
      "view.bookmark.go.1",
    };
  }
} // namespace faf::editor
