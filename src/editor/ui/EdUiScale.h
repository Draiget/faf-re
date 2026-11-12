#pragma once

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
} // namespace faf::editor
