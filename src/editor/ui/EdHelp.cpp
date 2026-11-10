#include "editor/ui/EdHelp.h"

#include <string>

#include "imgui.h"

namespace faf::editor
{
  bool& FullHelpText()
  {
    static bool full = false;
    return full;
  }

  void HelpNote(const char* const text)
  {
    if (text == nullptr || text[0] == '\0') {
      return;
    }
    const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
    if (FullHelpText()) {
      ImGui::PushStyleColor(ImGuiCol_Text, dim);
      ImGui::TextWrapped("%s", text);
      ImGui::PopStyleColor();
      return;
    }
    // The first sentence (to its full stop), or the whole text when it is one.
    std::string line = text;
    if (const std::size_t stop = line.find(". "); stop != std::string::npos) {
      line.resize(stop + 1);
    }
    const bool more = line.size() < std::string(text).size();
    const float size = ImGui::GetFontSize();
    const float badge = size * 0.9f;
    const float avail = ImGui::GetContentRegionAvail().x - badge - size * 0.35f;
    // Cut to the width, with an ellipsis.
    if (ImGui::CalcTextSize(line.c_str()).x > avail) {
      while (!line.empty() && ImGui::CalcTextSize((line + "...").c_str()).x > avail) {
        line.pop_back();
      }
      line += "...";
    } else if (more) {
      line += " ...";
      if (ImGui::CalcTextSize(line.c_str()).x > avail) {
        line.resize(line.size() - 4);
      }
    }
    const ImVec2 at = ImGui::GetCursorScreenPos();
    const float height = ImGui::GetTextLineHeight();
    ImDrawList* const draw = ImGui::GetWindowDrawList();
    const ImU32 colour = ImGui::GetColorU32(dim);
    const ImVec2 centre(at.x + badge * 0.5f, at.y + height * 0.5f);
    draw->AddCircle(centre, badge * 0.45f, colour, 12, 1.2f);
    const ImVec2 mark = ImGui::CalcTextSize("?");
    draw->AddText(nullptr, size * 0.75f, ImVec2(centre.x - mark.x * 0.375f, centre.y - mark.y * 0.375f), colour, "?");
    draw->AddText(ImVec2(at.x + badge + size * 0.35f, at.y), colour, line.c_str());
    ImGui::Dummy(ImVec2(ImGui::GetContentRegionAvail().x, height));
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
      ImGui::BeginTooltip();
      ImGui::PushTextWrapPos(size * 26.0f);
      ImGui::TextUnformatted(text);
      ImGui::PopTextWrapPos();
      ImGui::EndTooltip();
    }
  }
} // namespace faf::editor
