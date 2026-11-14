#include "editor/ui/EdIcons.h"
#include "editor/ui/EdThemeColors.h"

#include <algorithm>
#include <cmath>
#include <initializer_list>

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265f;
  }

  void DrawEdIcon(
    ImDrawList* const draw,
    const EdIcon icon,
    const ImVec2 p,
    const float s,
    const ImU32 color
  )
  {
    // Redo is Undo mirrored.
    const bool mirror = icon == EdIcon::Redo;
    const auto at = [&](const float x, const float y) {
      return ImVec2(p.x + (mirror ? 1.0f - x : x) * s, p.y + y * s);
    };
    const float line = s * 0.09f;
    // A floppy disk in the square from (x0, y0), `k` of the icon wide.
    const auto floppy = [&](const float x0, const float y0, const float k) {
      const auto f = [&](const float x, const float y) {
        return at(x0 + x * k, y0 + y * k);
      };
      draw->AddRect(f(0.1f, 0.1f), f(0.9f, 0.9f), color, s * 0.08f, 0, line);
      draw->AddRectFilled(f(0.3f, 0.1f), f(0.66f, 0.38f), color);
      draw->AddRect(f(0.26f, 0.56f), f(0.74f, 0.9f), color, 0.0f, 0, line);
    };
    switch (icon) {
    case EdIcon::Tree:
      draw->AddTriangleFilled(at(0.5f, 0.08f), at(0.78f, 0.5f), at(0.22f, 0.5f), color);
      draw->AddTriangleFilled(at(0.5f, 0.3f), at(0.86f, 0.78f), at(0.14f, 0.78f), color);
      draw->AddRectFilled(at(0.45f, 0.78f), at(0.55f, 0.94f), color);
      break;
    case EdIcon::Tank:
      draw->AddRectFilled(at(0.1f, 0.55f), at(0.9f, 0.85f), color, s * 0.06f);
      draw->AddCircleFilled(at(0.45f, 0.48f), s * 0.16f, color);
      draw->AddLine(at(0.5f, 0.45f), at(0.92f, 0.3f), color, line);
      break;
    case EdIcon::Resource:
      // The mass point's rings.
      draw->AddCircle(at(0.5f, 0.5f), s * 0.38f, color, 20, line);
      draw->AddCircle(at(0.5f, 0.5f), s * 0.22f, color, 16, line);
      draw->AddCircleFilled(at(0.5f, 0.5f), s * 0.08f, color);
      break;
    case EdIcon::Flag:
      draw->AddLine(at(0.28f, 0.1f), at(0.28f, 0.92f), color, line);
      draw->AddTriangleFilled(at(0.28f, 0.12f), at(0.85f, 0.3f), at(0.28f, 0.5f), color);
      break;
    case EdIcon::Crosshair:
      draw->AddCircle(at(0.5f, 0.5f), s * 0.3f, color, 20, line);
      draw->AddLine(at(0.5f, 0.05f), at(0.5f, 0.3f), color, line);
      draw->AddLine(at(0.5f, 0.7f), at(0.5f, 0.95f), color, line);
      draw->AddLine(at(0.05f, 0.5f), at(0.3f, 0.5f), color, line);
      draw->AddLine(at(0.7f, 0.5f), at(0.95f, 0.5f), color, line);
      break;
    case EdIcon::PathNodes:
      draw->AddLine(at(0.2f, 0.75f), at(0.5f, 0.3f), color, line);
      draw->AddLine(at(0.5f, 0.3f), at(0.8f, 0.7f), color, line);
      draw->AddCircleFilled(at(0.2f, 0.75f), s * 0.12f, color);
      draw->AddCircleFilled(at(0.5f, 0.3f), s * 0.12f, color);
      draw->AddCircleFilled(at(0.8f, 0.7f), s * 0.12f, color);
      break;
    case EdIcon::Border:
      // A square inside the map's square, its corners as handles.
      draw->AddRect(at(0.05f, 0.05f), at(0.95f, 0.95f), color, 0.0f, 0, line * 0.6f);
      draw->AddRect(at(0.25f, 0.25f), at(0.75f, 0.75f), color, 0.0f, 0, line * 1.3f);
      for (const ImVec2 corner : {at(0.25f, 0.25f), at(0.75f, 0.25f), at(0.75f, 0.75f), at(0.25f, 0.75f)}) {
        draw->AddRectFilled(
          ImVec2(corner.x - s * 0.08f, corner.y - s * 0.08f), ImVec2(corner.x + s * 0.08f, corner.y + s * 0.08f), color
        );
      }
      break;
    case EdIcon::Pin:
      draw->AddCircle(at(0.5f, 0.38f), s * 0.22f, color, 16, line * 1.4f);
      draw->AddTriangleFilled(at(0.3f, 0.52f), at(0.7f, 0.52f), at(0.5f, 0.94f), color);
      break;
    case EdIcon::NewFile: {
      // A page with its corner folded, and a plus.
      const ImVec2 page[] = {at(0.18f, 0.06f), at(0.6f, 0.06f), at(0.82f, 0.28f), at(0.82f, 0.94f), at(0.18f, 0.94f)};
      draw->AddPolyline(page, 5, color, ImDrawFlags_Closed, line);
      const ImVec2 fold[] = {at(0.6f, 0.06f), at(0.6f, 0.28f), at(0.82f, 0.28f)};
      draw->AddPolyline(fold, 3, color, 0, line);
      draw->AddLine(at(0.5f, 0.46f), at(0.5f, 0.78f), color, line * 1.2f);
      draw->AddLine(at(0.34f, 0.62f), at(0.66f, 0.62f), color, line * 1.2f);
      break;
    }
    case EdIcon::Folder: {
      // The back with its tab, and the open front over it.
      const ImVec2 back[] = {
        at(0.06f, 0.84f), at(0.06f, 0.16f), at(0.38f, 0.16f), at(0.46f, 0.26f), at(0.82f, 0.26f), at(0.82f, 0.4f)
      };
      draw->AddPolyline(back, 6, color, 0, line);
      draw->AddQuadFilled(at(0.2f, 0.42f), at(0.98f, 0.42f), at(0.84f, 0.86f), at(0.06f, 0.86f), color);
      break;
    }
    case EdIcon::Save:
      floppy(0.0f, 0.0f, 1.0f);
      break;
    case EdIcon::SaveAs:
      // A smaller floppy and a plus: a new copy.
      floppy(0.0f, 0.0f, 0.8f);
      draw->AddLine(at(0.8f, 0.6f), at(0.8f, 1.0f), color, line * 1.3f);
      draw->AddLine(at(0.6f, 0.8f), at(1.0f, 0.8f), color, line * 1.3f);
      break;
    case EdIcon::Undo:
    case EdIcon::Redo: {
      // An arrow pointing back, its tail hooked round to the right and down (the usual undo arrow).
      constexpr int kSteps = 12;
      ImVec2 path[kSteps + 3];
      path[0] = at(0.3f, 0.34f);
      for (int i = 0; i <= kSteps; ++i) {
        const float a = -kPi * 0.5f + kPi * static_cast<float>(i) / static_cast<float>(kSteps);
        path[i + 1] = at(0.58f + 0.26f * std::cos(a), 0.6f + 0.26f * std::sin(a));
      }
      path[kSteps + 2] = at(0.26f, 0.86f);
      draw->AddPolyline(path, kSteps + 3, color, 0, line * 1.3f);
      draw->AddTriangleFilled(at(0.04f, 0.34f), at(0.34f, 0.1f), at(0.34f, 0.58f), color);
      break;
    }
    case EdIcon::Grid:
      draw->AddRect(at(0.08f, 0.08f), at(0.92f, 0.92f), color, 0.0f, 0, line);
      for (const float k : {0.36f, 0.64f}) {
        draw->AddLine(at(k, 0.08f), at(k, 0.92f), color, line * 0.8f);
        draw->AddLine(at(0.08f, k), at(0.92f, k), color, line * 0.8f);
      }
      break;
    case EdIcon::Magnet: {
      // A horseshoe magnet, its poles up, the caps apart from the legs.
      const float thick = s * 0.17f;
      constexpr int kSteps = 12;
      ImVec2 bend[kSteps + 1];
      for (int i = 0; i <= kSteps; ++i) {
        const float a = kPi * static_cast<float>(i) / static_cast<float>(kSteps);
        bend[i] = ImVec2(p.x + (0.5f + 0.3f * std::cos(a)) * s, p.y + (0.52f + 0.3f * std::sin(a)) * s);
      }
      draw->AddPolyline(bend, kSteps + 1, color, 0, thick);
      draw->AddLine(at(0.2f, 0.53f), at(0.2f, 0.3f), color, thick);
      draw->AddLine(at(0.8f, 0.53f), at(0.8f, 0.3f), color, thick);
      draw->AddRectFilled(at(0.115f, 0.06f), at(0.285f, 0.22f), color);
      draw->AddRectFilled(at(0.715f, 0.06f), at(0.885f, 0.22f), color);
      break;
    }
    case EdIcon::OnGround:
      // An arrow down onto the ground's line.
      draw->AddLine(at(0.5f, 0.06f), at(0.5f, 0.5f), color, line * 1.2f);
      draw->AddTriangleFilled(at(0.28f, 0.46f), at(0.72f, 0.46f), at(0.5f, 0.74f), color);
      draw->AddLine(at(0.06f, 0.88f), at(0.94f, 0.88f), color, line * 1.4f);
      break;
    case EdIcon::Slope:
      // A ramp, and the angle at its foot.
      draw->AddTriangleFilled(at(0.06f, 0.88f), at(0.94f, 0.88f), at(0.94f, 0.2f), color);
      draw->AddLine(at(0.06f, 0.94f), at(0.94f, 0.94f), color, line * 0.6f);
      break;
    case EdIcon::Ruler:
      // A ruler with its ticks: the kilometre lines and measuring.
      draw->AddRect(at(0.04f, 0.3f), at(0.96f, 0.7f), color, s * 0.05f, 0, line);
      for (int i = 1; i < 6; ++i) {
        const float x = 0.04f + 0.92f * static_cast<float>(i) / 6.0f;
        draw->AddLine(at(x, 0.3f), at(x, (i % 2) != 0 ? 0.44f : 0.54f), color, line * 0.8f);
      }
      break;
    }
  }

  bool EdToolButton(
    const char* const id,
    const EdIcon icon,
    const char* const label,
    const bool toggle,
    const bool on,
    const EdSegment segment
  )
  {
    const ImGuiStyle& style = ImGui::GetStyle();
    const float side = ImGui::GetFrameHeight();
    const float inset = side * 0.18f;
    const float iconSide = side - inset * 2.0f;
    const ImVec2 textSize = label != nullptr ? ImGui::CalcTextSize(label) : ImVec2(0.0f, 0.0f);
    const float width =
      label != nullptr ? inset + iconSide + style.ItemInnerSpacing.x + textSize.x + style.FramePadding.x : side;
    const ImVec2 at = ImGui::GetCursorScreenPos();
    const bool clicked = ImGui::InvisibleButton(id, ImVec2(width, side));
    const bool hovered = ImGui::IsItemHovered();
    const bool held = ImGui::IsItemActive();

    ImU32 fill = 0;
    if (toggle && on) {
      // The theme's accent, filled (a pressed toggle looks the same in every theme and panel).
      fill = AccentU32(held ? 0.70f : hovered ? 0.58f : 0.45f);
    } else {
      fill = ImGui::GetColorU32(held ? ImGuiCol_ButtonActive : hovered ? ImGuiCol_ButtonHovered : ImGuiCol_Button);
    }
    ImDrawFlags corners = ImDrawFlags_RoundCornersAll;
    if (segment == EdSegment::First) {
      corners = ImDrawFlags_RoundCornersLeft;
    } else if (segment == EdSegment::Middle) {
      corners = ImDrawFlags_RoundCornersNone;
    } else if (segment == EdSegment::Last) {
      corners = ImDrawFlags_RoundCornersRight;
    }
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    const ImVec2 end(at.x + width, at.y + side);
    draw->AddRectFilled(at, end, fill, style.FrameRounding, corners);
    if (style.FrameBorderSize > 0.0f) {
      draw->AddRect(at, end, ImGui::GetColorU32(ImGuiCol_Border), style.FrameRounding, corners, style.FrameBorderSize);
    }
    const ImU32 ink = toggle && !on ? ImGui::GetColorU32(ImGuiCol_TextDisabled) : ImGui::GetColorU32(ImGuiCol_Text);
    DrawEdIcon(draw, icon, ImVec2(at.x + inset, at.y + inset), iconSide, ink);
    if (label != nullptr) {
      draw->AddText(
        ImVec2(at.x + inset + iconSide + style.ItemInnerSpacing.x, at.y + (side - textSize.y) * 0.5f),
        ImGui::GetColorU32(ImGuiCol_Text),
        label
      );
    }
    return clicked;
  }

  bool IconToggle(
    const char* const id,
    const EdIcon icon,
    const bool on,
    const EdSegment segment
  )
  {
    return EdToolButton(id, icon, nullptr, true, on, segment);
  }

  float EdTextSegmentWidth(
    const char* const text,
    const float minWidth
  )
  {
    return std::max(minWidth, ImGui::CalcTextSize(text).x + ImGui::GetStyle().FramePadding.x * 2.0f);
  }

  bool EdTextSegment(
    const char* const id,
    const char* const text,
    const EdSegment segment,
    const bool enabled,
    const float minWidth
  )
  {
    const ImGuiStyle& style = ImGui::GetStyle();
    const float side = ImGui::GetFrameHeight();
    const float width = EdTextSegmentWidth(text, minWidth);
    const ImVec2 at = ImGui::GetCursorScreenPos();
    ImGui::BeginDisabled(!enabled);
    const bool clicked = ImGui::InvisibleButton(id, ImVec2(width, side));
    ImGui::EndDisabled();
    const bool hovered = enabled && ImGui::IsItemHovered();
    const bool held = enabled && ImGui::IsItemActive();
    ImDrawFlags corners = ImDrawFlags_RoundCornersAll;
    if (segment == EdSegment::First) {
      corners = ImDrawFlags_RoundCornersLeft;
    } else if (segment == EdSegment::Middle) {
      corners = ImDrawFlags_RoundCornersNone;
    } else if (segment == EdSegment::Last) {
      corners = ImDrawFlags_RoundCornersRight;
    }
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    const ImVec2 end(at.x + width, at.y + side);
    draw->AddRectFilled(
      at,
      end,
      ImGui::GetColorU32(
        held        ? ImGuiCol_ButtonActive
          : hovered ? ImGuiCol_ButtonHovered
                    : ImGuiCol_Button
      ),
      style.FrameRounding,
      corners
    );
    const ImVec2 textSize = ImGui::CalcTextSize(text);
    draw->AddText(
      ImVec2(at.x + (width - textSize.x) * 0.5f, at.y + (side - textSize.y) * 0.5f),
      ImGui::GetColorU32(enabled ? ImGuiCol_Text : ImGuiCol_TextDisabled),
      text
    );
    return clicked && enabled;
  }
} // namespace faf::editor
