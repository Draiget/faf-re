#pragma once

#include "imgui.h"

namespace faf::editor
{
  /** The toolbar's small drawn icons (no image files). */
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
    NewFile,
    Folder,
    Save,
    SaveAs,
    Undo,
    Redo,
    Grid,
    Magnet,
    OnGround,
    Slope,
    Ruler,
  };

  /** Where a button sits in a row of buttons joined into one (1 px apart, rounded only at the row's ends). */
  enum class EdSegment
  {
    Alone,
    First,
    Middle,
    Last,
  };

  /** Draws `icon` in the square at `p`, `s` wide. */
  void DrawEdIcon(ImDrawList* draw, EdIcon icon, ImVec2 p, float s, ImU32 color);

  /**
   * A toolbar button with `icon` and, when `label` isn't null, the label after it; returns true when clicked.
   * A toggle (`toggle`) is lit while `on` (the toolbar's toggle colour) and its icon dimmed while off. The next
   * button of a joined row goes after `ImGui::SameLine(0.0f, 1.0f)`.
   */
  bool EdToolButton(
    const char* id,
    EdIcon icon,
    const char* label,
    bool toggle,
    bool on,
    EdSegment segment = EdSegment::Alone
  );

  /** A square toggle with `icon` only. */
  bool IconToggle(const char* id, EdIcon icon, bool on, EdSegment segment = EdSegment::Alone);

  /** A plain button with centred `text` that joins a row as the icon ones do (at least `minWidth` wide). */
  bool EdTextSegment(const char* id, const char* text, EdSegment segment, bool enabled = true, float minWidth = 0.0f);
  /** The width `EdTextSegment` takes for `text`. */
  [[nodiscard]] float EdTextSegmentWidth(const char* text, float minWidth = 0.0f);
} // namespace faf::editor
