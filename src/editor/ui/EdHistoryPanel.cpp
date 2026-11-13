// The History panel (View > History): EdShell's member that draws it.

#include <string>
#include "editor/ui/EdControls.h"
#include <vector>

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/ui/EdCommands.h"
#include "editor/ui/EdHistory.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  void EdShell::DrawHistoryPanel()
  {
    // The first time, a tab beside the Log (the bottom row), where the design puts it.
    if (const ImGuiWindow* const log = ImGui::FindWindowByName(Panel("Log")); log != nullptr && log->DockId != 0) {
      ImGui::SetNextWindowDockID(log->DockId, ImGuiCond_FirstUseEver);
    }
    if (!ImGui::Begin(Panel("History"), &mShowHistory)) {
      ImGui::End();
      return;
    }
    if (mDocument.GetState() != EdDocument::State::Open) {
      ImGui::TextDisabled("Open a map: its edits are listed here.");
      ImGui::End();
      return;
    }
    std::vector<std::string> undo;
    std::vector<std::string> redo;
    for (const EdDocument::EditKind kind : mDocument.UndoOrder()) {
      undo.emplace_back(EdDocument::EditKindName(kind));
    }
    for (const EdDocument::EditKind kind : mDocument.RedoOrder()) {
      redo.emplace_back(EdDocument::EditKindName(kind));
    }
    const std::vector<EdHistoryRow> rows = HistoryRows(undo, redo);
    const int current = static_cast<int>(undo.size());
    ImGui::TextDisabled(
      "%d step%s, %d undone. A click goes back (or forward) to that step.",
      current,
      current == 1 ? "" : "s",
      static_cast<int>(redo.size())
    );
    ImGui::BeginChild("##historyrows");
    int target = -1;
    // Newest at the top, as the steps pile up.
    for (auto it = rows.rbegin(); it != rows.rend(); ++it) {
      const EdHistoryRow& row = *it;
      ImGui::PushID(row.position);
      const bool now = row.position == current;
      if (!row.done) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
      }
      if (ImGui::Selectable(row.label.c_str(), now, ImGuiSelectableFlags_None, ImVec2(0.0f, Em(22.0f))) && !now) {
        target = row.position;
      }
      if (!row.done) {
        ImGui::PopStyleColor();
      }
      if (ImGui::IsItemHovered() && !now) {
        const int steps = StepsTo(current, row.position);
        EdSetTooltip(
          "%s %d step%s",
          steps < 0 ? "Undo" : "Redo",
          steps < 0 ? -steps : steps,
          (steps == 1 || steps == -1) ? "" : "s"
        );
      }
      ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::End();

    // Undo or Redo until the step is reached, or until one doesn't move (a kind keeps only its newest steps).
    if (target >= 0 && mCommands != nullptr) {
      const int steps = StepsTo(current, target);
      const char* const command = steps < 0 ? "edit.undo" : "edit.redo";
      int done = 0;
      for (int i = 0; i < (steps < 0 ? -steps : steps); ++i) {
        const std::size_t before = mDocument.UndoOrder().size();
        (void)mCommands->Run(command);
        if (mDocument.UndoOrder().size() == before) {
          break;
        }
        ++done;
      }
      gpg::Logf("editor: history: %s x%d to step %d (%d asked)", command, done, target, steps < 0 ? -steps : steps);
    }
  }
} // namespace faf::editor
