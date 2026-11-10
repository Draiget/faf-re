#include "editor/ui/EdIcons.h"

namespace faf::editor
{
  void DrawEdIcon(ImDrawList* const draw, const EdIcon icon, const ImVec2 p, const float s, const ImU32 color)
  {
    const auto at = [&](const float x, const float y) { return ImVec2(p.x + x * s, p.y + y * s); };
    const float line = s * 0.09f;
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
    case EdIcon::Pin:
      draw->AddCircle(at(0.5f, 0.38f), s * 0.22f, color, 16, line * 1.4f);
      draw->AddTriangleFilled(at(0.3f, 0.52f), at(0.7f, 0.52f), at(0.5f, 0.94f), color);
      break;
    }
  }

  bool IconToggle(const char* const id, const EdIcon icon, const bool on)
  {
    const float side = ImGui::GetFrameHeight();
    if (on) {
      ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.55f, 0.36f, 0.16f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.66f, 0.44f, 0.20f, 1.0f));
    }
    const ImVec2 at = ImGui::GetCursorScreenPos();
    const bool clicked = ImGui::Button(id, ImVec2(side, side));
    if (on) {
      ImGui::PopStyleColor(2);
    }
    const float inset = side * 0.16f;
    const ImU32 colour = on ? ImGui::GetColorU32(ImGuiCol_Text) : ImGui::GetColorU32(ImGuiCol_TextDisabled);
    DrawEdIcon(ImGui::GetWindowDrawList(), icon, ImVec2(at.x + inset, at.y + inset), side - inset * 2.0f, colour);
    return clicked;
  }
} // namespace faf::editor
