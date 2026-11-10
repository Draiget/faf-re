#pragma once

#include "imgui.h"

namespace faf::editor
{
  /** The toolbar's small drawn icons (no image files): the kinds of things the view can show or hide. */
  enum class EdIcon
  {
    Tree,
    Tank,
    Resource,
    Flag,
    Crosshair,
    PathNodes,
    Pin,
    Border,
  };

  /** Draws `icon` in the square at `p`, `s` wide. */
  void DrawEdIcon(ImDrawList* draw, EdIcon icon, ImVec2 p, float s, ImU32 color);

  /**
   * A square toolbar button with `icon`, lit while `on` (the toolbar's toggle colour) and dimmed while off;
   * returns true when clicked.
   */
  bool IconToggle(const char* id, EdIcon icon, bool on);
} // namespace faf::editor
