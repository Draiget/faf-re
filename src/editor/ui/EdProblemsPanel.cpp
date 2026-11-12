// The Problems panel (View > Problems, the status bar's count): EdShell's members.

#include <string>
#include <vector>

#include "editor/EdLog.h"
#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/ui/EdCodeEditor.h"
#include "editor/ui/EdProblems.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  void EdShell::GoToIssue(
    const CheckIssue& issue
  )
  {
    if (!issue.file.empty()) {
      // A script's error: its file in the Script Editor, at the line.
      const auto endsWith = [&](const char* const tail) {
        const std::string end = tail;
        return issue.file.size() >= end.size() &&
          issue.file.compare(issue.file.size() - end.size(), end.size(), end) == 0;
      };
      mScriptFile = endsWith("_options.lua") ? 1 : endsWith("_tables.lua") ? 2 : 0;
      mShowScript = true;
      mFocusScript = true;
      mScriptErrorLine = issue.line;
      mScriptMessage = issue.file + " line " + std::to_string(issue.line) + ": " + issue.text;
      LuaCodeScrollTo(issue.line);
    } else if (issue.marker == "Props" || issue.marker.rfind("Prop ", 0) == 0) {
      // A prop's finding: the view to its place (props have no names to select by).
      mTools.AskPointFrame(issue.x, issue.z);
    } else if (!issue.marker.empty()) {
      mTools.AskMarkerSelect({issue.marker}, false);
      mTools.AskMarkerFrame(issue.marker);
    }
  }

  void EdShell::OpenProblems() noexcept
  {
    mShowProblems = true;
    mFocusProblems = true;
  }

  void EdShell::DrawProblemsPanel()
  {
    // The first time, a tab beside the Log (the bottom row), where the design puts it.
    if (const ImGuiWindow* const log = ImGui::FindWindowByName(Panel("Log")); log != nullptr && log->DockId != 0) {
      ImGui::SetNextWindowDockID(log->DockId, ImGuiCond_FirstUseEver);
    }
    if (std::exchange(mFocusProblems, false)) {
      ImGui::SetNextWindowFocus();
    }
    if (!ImGui::Begin(Panel("Problems"), &mShowProblems)) {
      ImGui::End();
      return;
    }
    // The check's findings belong to the map they ran on.
    const bool checked =
      mCheckRan && mCheckedPath == mDocument.Path() && mDocument.GetState() == EdDocument::State::Open;
    static const std::vector<CheckIssue> kNone;
    const std::vector<CheckIssue>& checks = checked ? mCheckIssues : kNone;
    const std::vector<std::string> warnings = mLog.Warnings();
    const std::vector<EdProblem> all = ProblemRows(checks, warnings, 0x7U, 0x3U);
    const std::vector<EdProblem> rows = ProblemRows(checks, warnings, mProblemLevels, mProblemSources);
    const EdProblemCounts counts = CountProblems(all);

    // The filters as toggles (filled when on), the counts in them; then Run the check.
    static const ImVec4 kColors[3] = {
      ImVec4(0.95f, 0.40f, 0.35f, 1.0f), ImVec4(0.95f, 0.75f, 0.30f, 1.0f), ImVec4(0.55f, 0.70f, 0.95f, 1.0f)
    };
    const auto toggle = [](const char* const label, unsigned& mask, const unsigned bit) {
      const bool on = (mask & bit) != 0;
      ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(on ? ImGuiCol_Header : ImGuiCol_FrameBg));
      if (ImGui::SmallButton(label)) {
        mask ^= bit;
      }
      ImGui::PopStyleColor();
      ImGui::SameLine();
    };
    char label[48];
    (void)std::snprintf(label, sizeof(label), "%d errors###errors", counts.errors);
    toggle(label, mProblemLevels, 1U << 0);
    (void)std::snprintf(label, sizeof(label), "%d warnings###warnings", counts.warnings);
    toggle(label, mProblemLevels, 1U << 1);
    (void)std::snprintf(label, sizeof(label), "%d notes###notes", counts.notes);
    toggle(label, mProblemLevels, 1U << 2);
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    toggle("Check", mProblemSources, 1U << static_cast<unsigned>(EdProblemSource::Check));
    toggle("Log", mProblemSources, 1U << static_cast<unsigned>(EdProblemSource::Log));
    ImGui::BeginDisabled(mDocument.GetState() != EdDocument::State::Open);
    if (ImGui::SmallButton("Run the check")) {
      RunCheck();
    }
    ImGui::EndDisabled();
    if (!checked && mDocument.GetState() == EdDocument::State::Open) {
      ImGui::SameLine();
      ImGui::TextDisabled("The map's findings come with a run of the check.");
    }

    ImGui::BeginChild("##problemrows");
    if (rows.empty()) {
      ImGui::TextDisabled(all.empty() ? "No problems." : "None with these filters.");
    }
    const float line = ImGui::GetTextLineHeight();
    for (std::size_t i = 0; i < rows.size(); ++i) {
      const EdProblem& row = rows[i];
      ImGui::PushID(static_cast<int>(i));
      const ImVec2 at = ImGui::GetCursorScreenPos();
      if (
        ImGui::Selectable("##problem", false, ImGuiSelectableFlags_SpanAvailWidth, ImVec2(0.0f, line * 2.0f + 2.0f))
      ) {
        if (row.source == EdProblemSource::Check && row.index < checks.size()) {
          GoToIssue(checks[row.index]);
          gpg::Logf("editor: problems: went to %s", row.title.c_str());
        } else {
          // A log warning: the log, filtered to it.
          mShowLog = true;
          mLog.SetFilter(row.text.substr(0, 60));
          ImGui::SetWindowFocus(Panel("Log"));
          gpg::Logf("editor: problems: the log for \"%s\"", row.text.substr(0, 60).c_str());
        }
      }
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        ImGui::SetTooltip("%s\n%s\nClick to go to it", row.title.c_str(), row.text.c_str());
      }
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      dl->AddCircleFilled(
        ImVec2(at.x + line * 0.4f, at.y + line * 0.5f),
        line * 0.28f,
        ImGui::GetColorU32(kColors[static_cast<int>(row.level)])
      );
      std::string title = row.title;
      if (row.count > 1) {
        title += "  x" + std::to_string(row.count);
      }
      dl->AddText(ImVec2(at.x + line * 1.1f, at.y), InkU32(), title.c_str());
      dl->PushClipRect(at, ImVec2(ImGui::GetItemRectMax().x, at.y + line * 2.0f + 2.0f), true);
      dl->AddText(ImVec2(at.x + line * 1.1f, at.y + line), InkDimU32(), row.text.c_str());
      dl->PopClipRect();
      ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::End();
  }
} // namespace faf::editor
