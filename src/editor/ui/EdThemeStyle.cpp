#include "editor/ui/EdThemeStyle.h"

#include <cstring>

#include "editor/ui/EdTheme.h"
#include "imgui.h"

namespace faf::editor
{
  std::vector<std::string> ApplyTheme(
    const EdTheme& theme,
    ImGuiStyle& style
  )
  {
    if (theme.light) {
      ImGui::StyleColorsLight(&style);
    } else {
      ImGui::StyleColorsDark(&style);
    }
    ImVec4* const c = style.Colors;
    if (theme.hasAccent) {
      const auto with = [&theme](const float alpha) {
        return ImVec4(theme.accent[0], theme.accent[1], theme.accent[2], alpha);
      };
      c[ImGuiCol_CheckMark] = with(1.0f);
      c[ImGuiCol_SliderGrab] = with(0.85f);
      c[ImGuiCol_SliderGrabActive] = with(1.0f);
      c[ImGuiCol_Header] = with(0.30f);
      c[ImGuiCol_HeaderHovered] = with(0.45f);
      c[ImGuiCol_HeaderActive] = with(0.60f);
      c[ImGuiCol_ButtonActive] = with(0.55f);
      c[ImGuiCol_SeparatorActive] = with(1.0f);
      c[ImGuiCol_ResizeGripActive] = with(1.0f);
      c[ImGuiCol_TabSelectedOverline] = with(1.0f);
      c[ImGuiCol_DockingPreview] = with(0.55f);
      c[ImGuiCol_TextSelectedBg] = with(0.35f);
      c[ImGuiCol_DragDropTarget] = with(1.0f);
      c[ImGuiCol_NavCursor] = with(1.0f);
      c[ImGuiCol_TextLink] = with(1.0f);
      // The title row's mark runs from the accent to a lighter one (EdTitleBar: CheckMark to PlotHistogram).
      c[ImGuiCol_PlotHistogram] = ImVec4(
        theme.accent[0] + (1.0f - theme.accent[0]) * 0.45f,
        theme.accent[1] + (1.0f - theme.accent[1]) * 0.45f,
        theme.accent[2] + (1.0f - theme.accent[2]) * 0.45f,
        1.0f
      );
    }
    std::vector<std::string> unknown;
    for (const EdThemeColor& color : theme.colors) {
      int found = -1;
      for (int i = 0; i < ImGuiCol_COUNT; ++i) {
        if (std::strcmp(ImGui::GetStyleColorName(i), color.name.c_str()) == 0) {
          found = i;
          break;
        }
      }
      if (found < 0) {
        unknown.push_back(color.name);
        continue;
      }
      c[found] = ImVec4(color.rgba[0], color.rgba[1], color.rgba[2], color.rgba[3]);
    }
    if (theme.rounding >= 0.0f) {
      style.WindowRounding = theme.rounding;
      style.ChildRounding = theme.rounding;
      style.FrameRounding = theme.rounding;
      style.PopupRounding = theme.rounding;
      style.GrabRounding = theme.rounding;
      style.TabRounding = theme.rounding;
      style.ScrollbarRounding = theme.rounding + 2.0f;
    }
    return unknown;
  }
} // namespace faf::editor
