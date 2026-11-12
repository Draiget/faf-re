// Help (design §8): the Help window with its topics, F1's topic under the mouse, and the tour. EdShell's members.

#include <algorithm>
#include <string>
#include <vector>

#include "editor/EdShell.h"
#include "editor/ui/EdCommands.h"
#include "editor/ui/EdHelpTopics.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  void EdShell::OpenHelp(
    const std::string& topic
  )
  {
    mShowHelp = true;
    mHelpTopic = FindHelpTopic(topic) != nullptr ? topic : std::string("view");
    mHelpFront = true;
    gpg::Logf("editor: help: %s", mHelpTopic.c_str());
  }

  std::string EdShell::HelpTopicUnderMouse() const
  {
    const ImGuiContext* const g = ImGui::GetCurrentContext();
    const ImGuiWindow* const hovered = g != nullptr ? g->HoveredWindow : nullptr;
    // A panel (its root: a child window's own name is its parent's plus its id); the dock space's host is the view.
    std::string name;
    if (hovered != nullptr && hovered->RootWindow != nullptr) {
      name = hovered->RootWindow->Name;
    }
    if (name.rfind("##EditorDockHost", 0) == 0 || name.rfind("##Toolbar", 0) == 0) {
      name.clear();
    }
    return HelpTopicForWindow(name, mTools.Tool());
  }

  void EdShell::StartTour()
  {
    mTourStep = 0;
    mShowHome = false;
    gpg::Logf("editor: tour: %zu steps", TourSteps().size());
  }

  void EdShell::DrawHelpWindow()
  {
    if (!mShowHelp) {
      return;
    }
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(
      ImVec2(std::min(Em(760.0f), viewport->WorkSize.x * 0.8f), std::min(Em(520.0f), viewport->WorkSize.y * 0.7f)),
      ImGuiCond_Appearing
    );
    ImGui::SetNextWindowPos(
      ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
      ImGuiCond_Appearing,
      ImVec2(0.5f, 0.5f)
    );
    if (ImGui::Begin("Help###Help", &mShowHelp, ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings)) {
      if (std::exchange(mHelpFront, false)) {
        ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
      }
      // The topics at the left (found by the search), the picked one at the right.
      ImGui::BeginChild("##helptopics", ImVec2(Em(210.0f), 0.0f));
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::InputTextWithHint("##helpsearch", "Search the help", mHelpSearch, sizeof(mHelpSearch));
      for (const EdHelpTopic* const topic : SearchHelp(mHelpSearch)) {
        if (
          ImGui::Selectable(topic->title, mHelpTopic == topic->id, ImGuiSelectableFlags_None, ImVec2(0.0f, Em(24.0f)))
        ) {
          mHelpTopic = topic->id;
        }
      }
      ImGui::EndChild();
      ImGui::SameLine(0.0f, Em(14.0f));
      ImGui::BeginChild("##helptext");
      if (const EdHelpTopic* const topic = FindHelpTopic(mHelpTopic); topic != nullptr) {
        ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 1.25f);
        ImGui::TextUnformatted(topic->title);
        ImGui::PopFont();
        ImGui::Spacing();
        ImGui::PushTextWrapPos(0.0f);
        // Paragraphs split by blank lines.
        std::string_view text = topic->text;
        while (!text.empty()) {
          const std::size_t end = text.find("\n\n");
          const std::string paragraph(text.substr(0, end));
          ImGui::TextUnformatted(paragraph.c_str());
          ImGui::Spacing();
          text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 2);
        }
        ImGui::PopTextWrapPos();
        // The topic's commands with their keys now (Settings > Keys can change them).
        if (topic->commands[0] != 0 && mCommands != nullptr) {
          ImGui::Spacing();
          ImGui::PushStyleColor(ImGuiCol_Text, AccentColor());
          ImGui::TextUnformatted("Keys");
          ImGui::PopStyleColor();
          std::string_view list = topic->commands;
          while (!list.empty()) {
            const std::size_t comma = list.find(',');
            const std::string id(list.substr(0, comma));
            list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
            if (const EdCommand* const command = mCommands->Find(id); command != nullptr) {
              ImGui::TextUnformatted(command->title.c_str());
              ImGui::SameLine(Em(260.0f));
              ImGui::TextDisabled("%s", command->keys.empty() ? "no key" : command->keys.c_str());
            }
          }
        }
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::TextDisabled("F1 over a panel opens its topic.");
        if (ImGui::SmallButton("Take the tour")) {
          mShowHelp = false;
          StartTour();
        }
      }
      ImGui::EndChild();
    }
    ImGui::End();
  }

  void EdShell::DrawTour()
  {
    const std::vector<EdTourStep>& steps = TourSteps();
    if (mTourStep < 0 || mTourStep >= static_cast<int>(steps.size())) {
      mTourStep = -1;
      return;
    }
    const EdTourStep& step = steps[static_cast<std::size_t>(mTourStep)];
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    // What the step points at: a window by name (a panel in this workspace), or the map view.
    ImVec2 min(viewport->Pos.x + mGameView.x, viewport->Pos.y + mGameView.y);
    ImVec2 max(min.x + mGameView.z, min.y + mGameView.w);
    if (std::string(step.target) != "view") {
      const char* const name = step.target[0] == '#' ? step.target : Panel(step.target);
      if (const ImGuiWindow* const window = ImGui::FindWindowByName(name); window != nullptr && window->WasActive) {
        min = window->Pos;
        max = ImVec2(window->Pos.x + window->Size.x, window->Pos.y + window->Size.y);
      }
    }
    // Everything else dimmed, the target outlined in the accent: drawn in a window of its own that lets the mouse
    // through, in front of the panels and behind the note (the foreground layer would dim the note too).
    const ImVec2 v0 = viewport->Pos;
    const ImVec2 v1(viewport->Pos.x + viewport->Size.x, viewport->Pos.y + viewport->Size.y);
    ImGui::SetNextWindowPos(v0);
    ImGui::SetNextWindowSize(viewport->Size);
    constexpr ImGuiWindowFlags kDimFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs |
      ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
      ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav;
    ImGui::Begin("##tourdim", nullptr, kDimFlags);
    ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
    ImDrawList* const dl = ImGui::GetWindowDrawList();
    dl->PushClipRect(v0, v1, false);
    const ImU32 dim = IM_COL32(0, 0, 0, 140);
    dl->AddRectFilled(v0, ImVec2(v1.x, min.y), dim);
    dl->AddRectFilled(ImVec2(v0.x, max.y), v1, dim);
    dl->AddRectFilled(ImVec2(v0.x, min.y), ImVec2(min.x, max.y), dim);
    dl->AddRectFilled(ImVec2(max.x, min.y), ImVec2(v1.x, max.y), dim);
    dl->AddRect(min, max, AccentU32(), Em(4.0f), 0, Em(2.5f));
    dl->PopClipRect();
    ImGui::End();

    // The bubble: under the target when there is room, else above it, kept on the screen.
    const float width = Em(380.0f);
    ImVec2 at((min.x + max.x) * 0.5f - width * 0.5f, max.y + Em(12.0f));
    if (at.y + Em(170.0f) > v1.y) {
      at.y = std::max(v0.y + Em(8.0f), min.y - Em(180.0f));
    }
    if (max.y - min.y > viewport->Size.y * 0.5f) {
      at.y = (min.y + max.y) * 0.5f - Em(60.0f); // a tall target: the bubble inside it
    }
    at.x = std::clamp(at.x, v0.x + Em(8.0f), v1.x - width - Em(8.0f));
    ImGui::SetNextWindowPos(at);
    ImGui::SetNextWindowSize(ImVec2(width, 0.0f));
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
      ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoMove;
    if (ImGui::Begin("##tour", nullptr, kFlags)) {
      ImGui::BringWindowToDisplayFront(ImGui::GetCurrentWindow());
      ImGui::TextDisabled("%d of %zu", mTourStep + 1, steps.size());
      ImGui::SameLine();
      ImGui::TextUnformatted(step.title);
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextUnformatted(step.text);
      ImGui::PopTextWrapPos();
      ImGui::Spacing();
      const bool last = mTourStep + 1 == static_cast<int>(steps.size());
      if (mTourStep > 0 && ImGui::Button("Back")) {
        --mTourStep;
      }
      if (mTourStep > 0) {
        ImGui::SameLine();
      }
      if (ImGui::Button(last ? "Done" : "Next")) {
        mTourStep = last ? -1 : mTourStep + 1;
      }
      ImGui::SameLine();
      if (ImGui::SmallButton("Close") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        mTourStep = -1;
      }
    }
    ImGui::End();
  }
} // namespace faf::editor
