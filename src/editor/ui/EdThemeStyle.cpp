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
    // The mockup's tokens (mockup/styles.css): bg-0 window, bg-1 docks and inputs, bg-2 panels, bg-3 raised, bg-4
    // pressed; line; text-0 to text-3.
    struct Tokens
    {
      ImU32 bg0, bg1, bg2, bg3, bg4, line, lineSoft, text0, text1, text2, text3;
    };
    static constexpr Tokens kDark{
      0x0d1014, 0x14181e, 0x1b2028, 0x242b35, 0x2e3743, 0x2a313b, 0x20262e, 0xe9edf2, 0xb5bfcb, 0x7f8a97, 0x5b6571
    };
    static constexpr Tokens kLight{
      0xe9ecf0, 0xf6f7f9, 0xffffff, 0xeef1f5, 0xe1e6ec, 0xd5dbe2, 0xe6eaef, 0x141a21, 0x3b4652, 0x66717d, 0x8d97a2
    };
    const Tokens& t = theme.light ? kLight : kDark;
    const auto rgb = [](const ImU32 hex, const float alpha = 1.0f) {
      return ImVec4(
        static_cast<float>((hex >> 16) & 0xFF) / 255.0f,
        static_cast<float>((hex >> 8) & 0xFF) / 255.0f,
        static_cast<float>(hex & 0xFF) / 255.0f,
        alpha
      );
    };
    const auto mix = [](const ImVec4& a, const ImVec4& b, const float k) {
      return ImVec4(a.x + (b.x - a.x) * k, a.y + (b.y - a.y) * k, a.z + (b.z - a.z) * k, a.w + (b.w - a.w) * k);
    };
    c[ImGuiCol_Text] = rgb(t.text0);
    c[ImGuiCol_TextDisabled] = rgb(t.text2);
    c[ImGuiCol_WindowBg] = rgb(t.bg2);
    c[ImGuiCol_ChildBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_PopupBg] = rgb(t.bg2);
    c[ImGuiCol_Border] = rgb(t.line);
    c[ImGuiCol_BorderShadow] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_FrameBg] = rgb(t.bg1);
    c[ImGuiCol_FrameBgHovered] = mix(rgb(t.bg1), rgb(t.bg3), 0.6f);
    c[ImGuiCol_FrameBgActive] = rgb(t.bg3);
    c[ImGuiCol_TitleBg] = rgb(t.bg1);
    c[ImGuiCol_TitleBgActive] = rgb(t.bg1);
    c[ImGuiCol_TitleBgCollapsed] = rgb(t.bg1);
    c[ImGuiCol_MenuBarBg] = rgb(t.bg1);
    c[ImGuiCol_ScrollbarBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_ScrollbarGrab] = rgb(t.bg4);
    c[ImGuiCol_ScrollbarGrabHovered] = rgb(t.text3);
    c[ImGuiCol_ScrollbarGrabActive] = rgb(t.text2);
    c[ImGuiCol_Button] = rgb(t.bg3);
    c[ImGuiCol_ButtonHovered] = rgb(t.bg4);
    c[ImGuiCol_ButtonActive] = mix(rgb(t.bg4), rgb(t.text3), 0.4f);
    c[ImGuiCol_Header] = rgb(t.bg3);
    c[ImGuiCol_HeaderHovered] = rgb(t.bg3);
    c[ImGuiCol_HeaderActive] = rgb(t.bg4);
    c[ImGuiCol_Separator] = rgb(t.line);
    c[ImGuiCol_SeparatorHovered] = rgb(t.text3);
    c[ImGuiCol_ResizeGrip] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_ResizeGripHovered] = rgb(t.text3);
    c[ImGuiCol_Tab] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_TabHovered] = rgb(t.bg2);
    c[ImGuiCol_TabSelected] = rgb(t.bg2);
    c[ImGuiCol_TabDimmed] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_TabDimmedSelected] = rgb(t.bg2);
    c[ImGuiCol_TabSelectedOverline] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_TabDimmedSelectedOverline] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_DockingEmptyBg] = rgb(t.bg0);
    c[ImGuiCol_TableHeaderBg] = rgb(t.bg1);
    c[ImGuiCol_TableBorderStrong] = rgb(t.line);
    c[ImGuiCol_TableBorderLight] = rgb(t.lineSoft);
    c[ImGuiCol_TableRowBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_TableRowBgAlt] = theme.light ? ImVec4(0.0f, 0.0f, 0.0f, 0.025f) : ImVec4(1.0f, 1.0f, 1.0f, 0.02f);
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0.0f, 0.0f, 0.0f, theme.light ? 0.25f : 0.5f);
    // The mockup's frames: a 1 px line round inputs, tracks and buttons, rows a little taller than ImGui's.
    style.FrameBorderSize = 1.0f;
    style.FramePadding = ImVec2(7.0f, 5.0f);
    style.ItemSpacing = ImVec2(6.0f, 5.0f);
    style.ItemInnerSpacing = ImVec2(5.0f, 4.0f);
    style.WindowPadding = ImVec2(9.0f, 8.0f);
    style.ScrollbarSize = 11.0f;
    style.GrabMinSize = 8.0f;
    style.WindowBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;
    style.TabBorderSize = 0.0f;
    // The mockup's tabs: a tab's close button shows on hover only; the panel's menu at the tab row's right end.
    style.TabCloseButtonMinWidthSelected = 0.0f;
    style.TabCloseButtonMinWidthUnselected = 0.0f;
    style.WindowMenuButtonPosition = ImGuiDir_Right;
    style.WindowRounding = 6.0f;
    style.ChildRounding = 5.0f;
    style.FrameRounding = 4.0f;
    style.PopupRounding = 6.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 5.0f;
    style.ScrollbarRounding = 6.0f;
    if (theme.hasAccent) {
      const auto with = [&theme](const float alpha) {
        return ImVec4(theme.accent[0], theme.accent[1], theme.accent[2], alpha);
      };
      c[ImGuiCol_CheckMark] = with(1.0f);
      c[ImGuiCol_SliderGrab] = with(0.85f);
      c[ImGuiCol_SliderGrabActive] = with(1.0f);
      // A picked list row: the accent's soft fill (the mockup's --accent-soft).
      c[ImGuiCol_Header] = with(0.16f);
      c[ImGuiCol_HeaderHovered] = with(0.24f);
      c[ImGuiCol_HeaderActive] = with(0.32f);
      c[ImGuiCol_SeparatorActive] = with(1.0f);
      c[ImGuiCol_ResizeGripActive] = with(1.0f);
      // Dock tabs: the picked one in the panel's colour (the mockup's tabs), set above.
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
