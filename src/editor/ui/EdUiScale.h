#pragma once

#include "editor/ui/EdLayout.h"
#include "imgui.h"

namespace faf::editor
{
  /**
   * A size given in pixels at the panels' base font (16 px), at the font's size now: the screen's DPI and the user's UI
   * scale (the toolbar's - / % / +) both follow. For column positions, widths and window sizes laid out by hand.
   */
  [[nodiscard]] inline float Em(
    const float px
  )
  {
    return px * ImGui::GetFontSize() / 16.0f;
  }

  /** FillHeightFor from where the cursor is now in the current window. */
  [[nodiscard]] inline float FillHeight(
    const float reserve,
    const float minimum
  )
  {
    return FillHeightFor(ImGui::GetContentRegionAvail().y, reserve, minimum);
  }
} // namespace faf::editor
