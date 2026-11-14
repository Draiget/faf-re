#include "editor/ui/EdPalette.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "editor/ui/EdCommands.h"
#include "editor/ui/EdUiScale.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"

namespace faf::editor
{
  namespace
  {
    struct PaletteState
    {
      bool wanted = false;
      bool open = false;
      std::string pending; // typed in when it opens
      char query[256] = {};
      int selected = 0;
      std::vector<std::string> recent; // command ids, run last first
    };

    PaletteState& State()
    {
      static PaletteState state;
      return state;
    }

    struct Row
    {
      const EdCommand* command = nullptr;
      int score = 0;
      int recentAt = -1;
    };
  } // namespace

  void OpenCommandPalette(
    const char* const query
  )
  {
    State().wanted = true;
    State().pending = query != nullptr ? query : "";
  }

  bool CommandPaletteOpen()
  {
    return State().open || State().wanted;
  }

  void DrawCommandPalette(
    EdCommands& commands
  )
  {
    PaletteState& s = State();
    constexpr const char* kId = "##CommandPalette";
    bool focusInput = false;
    if (s.wanted) {
      s.wanted = false;
      (void)std::snprintf(s.query, sizeof(s.query), "%s", s.pending.c_str());
      s.selected = 0;
      ImGui::OpenPopup(kId);
      focusInput = true;
    }
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const float width = std::min(Em(620.0f), viewport->WorkSize.x - Em(40.0f));
    ImGui::SetNextWindowPos(
      ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + Em(56.0f)),
      ImGuiCond_Always,
      ImVec2(0.5f, 0.0f)
    );
    ImGui::SetNextWindowSize(ImVec2(width, 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, Em(10.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(10.0f), Em(10.0f)));
    const bool shown = ImGui::BeginPopupModal(
      kId, nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings
    );
    ImGui::PopStyleVar(2);
    s.open = shown;
    if (!shown) {
      return;
    }

    // The rows: every command the palette lists, matched and ordered by the query, or the ones run last first.
    std::vector<Row> rows;
    for (const EdCommand& command : commands.All()) {
      if (!command.palette) {
        continue;
      }
      Row row;
      row.command = &command;
      row.score = FuzzyScore(s.query, command.category + " " + command.title);
      const auto recent = std::find(s.recent.begin(), s.recent.end(), command.id);
      row.recentAt = recent == s.recent.end() ? -1 : static_cast<int>(recent - s.recent.begin());
      if (row.score > 0) {
        rows.push_back(row);
      }
    }
    const bool typed = s.query[0] != 0;
    std::stable_sort(rows.begin(), rows.end(), [typed](const Row& a, const Row& b) {
      if (!typed && (a.recentAt >= 0) != (b.recentAt >= 0)) {
        return a.recentAt >= 0;
      }
      if (!typed && a.recentAt >= 0) {
        return a.recentAt < b.recentAt;
      }
      if (typed && a.score != b.score) {
        return a.score > b.score;
      }
      return a.command->category + a.command->title < b.command->category + b.command->title;
    });
    const int count = static_cast<int>(rows.size());
    s.selected = count == 0 ? 0 : std::clamp(s.selected, 0, count - 1);

    if (focusInput) {
      ImGui::SetKeyboardFocusHere();
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(Em(10.0f), Em(7.0f)));
    if (
      ImGui::InputTextWithHint("##query", "Type a command: save, symmetry, reset layout ...", s.query, sizeof(s.query))
    ) {
      s.selected = 0;
    }
    ImGui::PopStyleVar();
    bool run = false;
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
      s.selected = count == 0 ? 0 : (s.selected + 1) % count;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
      s.selected = count == 0 ? 0 : (s.selected + count - 1) % count;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter)) {
      run = true;
    }
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape);

    const float rowHeight = ImGui::GetTextLineHeightWithSpacing() + Em(6.0f);
    const int shownRows = std::min(count, 14);
    ImGui::BeginChild("##rows", ImVec2(0.0f, std::max(rowHeight, rowHeight * static_cast<float>(shownRows))));
    if (count == 0) {
      ImGui::TextDisabled("No command matches \"%s\".", s.query);
    }
    for (int i = 0; i < count; ++i) {
      const EdCommand& command = *rows[static_cast<std::size_t>(i)].command;
      const std::string why = commands.WhyNot(command.id);
      ImGui::PushID(command.id.c_str());
      const ImVec2 at = ImGui::GetCursorScreenPos();
      if (ImGui::Selectable("##row", i == s.selected, ImGuiSelectableFlags_None, ImVec2(0.0f, rowHeight - Em(2.0f)))) {
        s.selected = i;
        run = true;
      }
      if (i == s.selected && (ImGui::IsKeyPressed(ImGuiKey_DownArrow) || ImGui::IsKeyPressed(ImGuiKey_UpArrow))) {
        ImGui::SetScrollHereY(0.5f);
      }
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      const float textY = at.y + (rowHeight - Em(2.0f) - ImGui::GetFontSize()) * 0.5f;
      const ImU32 dim = ImGui::GetColorU32(ImGuiCol_TextDisabled);
      const ImU32 main = why.empty() ? ImGui::GetColorU32(ImGuiCol_Text) : dim;
      const std::string category = command.category + "  ";
      dl->AddText(ImVec2(at.x + Em(8.0f), textY), dim, category.c_str());
      const float cw = ImGui::CalcTextSize(category.c_str()).x;
      dl->AddText(ImVec2(at.x + Em(8.0f) + cw, textY), main, command.title.c_str());
      const std::string right = !why.empty() ? why : command.keys;
      if (!right.empty()) {
        const float rw = ImGui::CalcTextSize(right.c_str()).x;
        dl->AddText(ImVec2(at.x + ImGui::GetContentRegionAvail().x - rw - Em(8.0f), textY), dim, right.c_str());
      }
      ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::TextDisabled("Up/Down pick, Enter runs, Esc closes.  %d commands", count);

    if (run && count > 0) {
      const EdCommand& command = *rows[static_cast<std::size_t>(s.selected)].command;
      const std::string id = command.id;
      const std::string why = commands.WhyNot(id);
      if (why.empty()) {
        s.recent.erase(std::remove(s.recent.begin(), s.recent.end(), id), s.recent.end());
        s.recent.insert(s.recent.begin(), id);
        if (s.recent.size() > 8) {
          s.recent.resize(8);
        }
        close = true;
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        s.open = false;
        gpg::Logf("editor: palette: %s", id.c_str());
        (void)commands.Run(id);
        return;
      }
      gpg::Logf("editor: palette: %s can't run now: %s", id.c_str(), why.c_str());
    }
    if (close) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }
} // namespace faf::editor
