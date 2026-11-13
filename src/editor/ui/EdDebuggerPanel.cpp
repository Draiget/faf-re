// The Debugger panel (View > Debugger, the Mission workspace): EdShell's members.

#include <algorithm>
#include "editor/ui/EdControls.h"
#include <string>
#include <vector>

#include "editor/EdLuaDebugger.h"
#include "editor/EdPlay.h"
#include "editor/EdShell.h"
#include "editor/ui/EdCodeEditor.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  void EdShell::DrawDebuggerPanel()
  {
    EdLuaDebugger& debugger = EdLuaDebugger::Get();
    const EdLuaDebugger::Pause pause = debugger.Snapshot();
    // A new pause: the Script Editor on its line, this panel in front.
    if (pause.paused && !mDebugWasPaused) {
      mShowScript = true;
      mFocusScript = true;
      mScriptFile = pause.file.find("_options.lua") != std::string::npos ? 1
        : pause.file.find("_tables.lua") != std::string::npos            ? 2
                                                                         : 0;
      LuaCodeScrollTo(pause.line);
      ImGui::SetNextWindowFocus();
    }
    mDebugWasPaused = pause.paused;
    if (const ImGuiWindow* const log = ImGui::FindWindowByName(Panel("Log")); log != nullptr && log->DockId != 0) {
      ImGui::SetNextWindowDockID(log->DockId, ImGuiCond_FirstUseEver);
    }
    if (!ImGui::Begin(Panel("Debugger"), &mShowDebugger)) {
      ImGui::End();
      return;
    }
    bool armed = debugger.Armed();
    if (ImGui::Checkbox("Stop at breakpoints in plays", &armed)) {
      debugger.SetArmed(armed);
      gpg::Logf("editor: debugger %s", armed ? "armed" : "off");
    }
    EdSetItemTooltip(
      "From the next play (F5 or Check's test run): the map's scripts stop at their breakpoints. Off, plays run as "
      "always."
    );
    if (armed && mPlay.Active() && !pause.paused && !debugger.Hooked()) {
      ImGui::SameLine();
      ImGui::TextDisabled("(takes effect from the next play if this one began unarmed)");
    }

    if (pause.paused) {
      ImGui::TextColored(ImVec4(0.95f, 0.80f, 0.30f, 1.0f), "Paused at %s line %d", pause.file.c_str(), pause.line);
      if (ImGui::Button("Continue")) {
        debugger.Resume(EdStepMode::Run);
      }
      ImGui::SameLine();
      if (ImGui::Button("Step into")) {
        debugger.Resume(EdStepMode::Into);
      }
      ImGui::SameLine();
      if (ImGui::Button("Step over")) {
        debugger.Resume(EdStepMode::Over);
      }
      ImGui::SameLine();
      if (ImGui::Button("Step out")) {
        debugger.Resume(EdStepMode::Out);
      }
      ImGui::SameLine();
      if (ImGui::Button("Show the line")) {
        mShowScript = true;
        mFocusScript = true;
        LuaCodeScrollTo(pause.line);
      }
    } else if (mPlay.Active()) {
      ImGui::TextDisabled("Running.");
    } else {
      ImGui::TextDisabled("Not playing. A click on a line's number in the Script Editor sets a breakpoint.");
    }

    // Breakpoints.
    ImGui::SeparatorText("Breakpoints");
    const std::vector<EdLuaDebugger::Breakpoint> breakpoints = debugger.Breakpoints();
    if (breakpoints.empty()) {
      ImGui::TextDisabled("None.");
    }
    for (const EdLuaDebugger::Breakpoint& b : breakpoints) {
      ImGui::PushID((b.file + std::to_string(b.line)).c_str());
      if (ImGui::SmallButton("x")) {
        debugger.ToggleBreakpoint(b.file, b.line);
      }
      ImGui::SameLine();
      ImGui::Text("%s line %d", b.file.c_str(), b.line);
      ImGui::PopID();
    }

    // The locals, the watches and the stack while paused.
    ImGui::SeparatorText("Locals");
    if (!pause.paused) {
      ImGui::TextDisabled("Shown while paused.");
    } else if (pause.locals.empty()) {
      ImGui::TextDisabled("None here.");
    } else if (ImGui::BeginTable("##locals", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV)) {
      for (const auto& [name, value] : pause.locals) {
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::TextUnformatted(name.c_str());
        ImGui::TableSetColumnIndex(1);
        ImGui::TextDisabled("%s", value.c_str());
      }
      ImGui::EndTable();
    }
    ImGui::SeparatorText("Watch");
    ImGui::SetNextItemWidth(Em(260.0f));
    const bool add = ImGui::InputTextWithHint(
      "##watch",
      "an expression, such as ScenarioInfo.Options.Victory",
      mWatchInput,
      sizeof(mWatchInput),
      ImGuiInputTextFlags_EnterReturnsTrue
    );
    ImGui::SameLine();
    if ((ImGui::Button("Add") || add) && mWatchInput[0] != 0) {
      mWatches.emplace_back(mWatchInput);
      mWatchInput[0] = 0;
      debugger.SetWatches(mWatches);
    }
    for (std::size_t i = 0; i < mWatches.size(); ++i) {
      ImGui::PushID(static_cast<int>(i));
      if (ImGui::SmallButton("x")) {
        mWatches.erase(mWatches.begin() + static_cast<std::ptrdiff_t>(i));
        debugger.SetWatches(mWatches);
        ImGui::PopID();
        break;
      }
      ImGui::SameLine();
      ImGui::TextUnformatted(mWatches[i].c_str());
      for (const auto& [expression, value] : pause.watches) {
        if (expression == mWatches[i]) {
          ImGui::SameLine();
          ImGui::TextDisabled("= %s", value.c_str());
        }
      }
      ImGui::PopID();
    }
    if (pause.paused && !pause.stack.empty()) {
      ImGui::SeparatorText("Stack");
      for (const std::string& line : pause.stack) {
        ImGui::TextDisabled("%s", line.c_str());
      }
    }
    ImGui::End();
  }
} // namespace faf::editor
