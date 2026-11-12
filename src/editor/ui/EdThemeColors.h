#pragma once

#include "imgui.h"

namespace faf::editor
{
  /**
   * The theme's accent (ui/EdTheme: ticks, the tool in use, a picked tile, the current army), for what panels draw
   * themselves: ImGui's CheckMark colour, which the theme's `accent` sets. Panels use this, never a colour of their
   * own, so every theme recolours them.
   */
  [[nodiscard]] inline ImVec4 AccentColor(
    const float alpha = 1.0f
  )
  {
    ImVec4 colour = ImGui::GetStyleColorVec4(ImGuiCol_CheckMark);
    colour.w = alpha;
    return colour;
  }

  [[nodiscard]] inline ImU32 AccentU32(
    const float alpha = 1.0f
  )
  {
    return ImGui::ColorConvertFloat4ToU32(AccentColor(alpha));
  }

  // What panels draw themselves (tiles, cards, chips, their lines and text) in the theme's colours, so a light theme
  // has light tiles with dark text. Colours that mean something (a marker value's kind, an option's state, red and
  // green) stay the panels' own.

  /** A tile or card under content: the theme's frame colour. */
  [[nodiscard]] inline ImU32 SurfaceU32()
  {
    return ImGui::GetColorU32(ImGuiCol_FrameBg);
  }

  /** A tile under the mouse. */
  [[nodiscard]] inline ImU32 SurfaceHotU32()
  {
    return ImGui::GetColorU32(ImGuiCol_FrameBgHovered);
  }

  /** A chip (a rounded label): the theme's button colour. */
  [[nodiscard]] inline ImU32 ChipU32()
  {
    return ImGui::GetColorU32(ImGuiCol_Button);
  }

  /** A tile's or card's outline. */
  [[nodiscard]] inline ImU32 LineU32()
  {
    return ImGui::GetColorU32(ImGuiCol_Border);
  }

  /** Text and icons, full and dimmed. */
  [[nodiscard]] inline ImU32 InkU32()
  {
    return ImGui::GetColorU32(ImGuiCol_Text);
  }

  [[nodiscard]] inline ImU32 InkDimU32()
  {
    return ImGui::GetColorU32(ImGuiCol_TextDisabled);
  }
} // namespace faf::editor
