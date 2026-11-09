#include "editor/EdShell.h"

#include <algorithm>
#include <cstdio>

#include "editor/EdLog.h"
#include "editor/EdPlay.h"
#include "gpg/gal/Device.hpp"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  namespace
  {
    constexpr const char* kToolsWindow = "Tools";
    constexpr const char* kMapWindow = "Map";
    constexpr const char* kLogWindow = "Log";
    constexpr const char* kDockSpace = "EditorDockSpace";

    const ImVec4 kPlayGreen(0.24f, 0.55f, 0.28f, 1.0f);
    const ImVec4 kStopRed(0.62f, 0.22f, 0.20f, 1.0f);
  } // namespace

  EdShell::EdShell(EdLog& log, EdPlay& play)
    : mLog(log)
    , mPlay(play)
  {
    gpg::gal::DeviceRuntimeInfo info;
    if (gpg::gal::Device::IsReady() && gpg::gal::Device::GetInstance()->GetRuntimeInfo(info)) {
      mApi = info.api.c_str();
      mAdapter = info.adapter.c_str();
    }
  }

  void EdShell::HandleKeys()
  {
    // F5 plays the picked map or stops the running one, wherever the focus is (EdApp.cpp keeps it from the game).
    if (ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
      if (mPlay.Active()) {
        mPlay.Stop();
      } else if (mPlay.CanPlay()) {
        mPlay.Play();
      }
    }
  }

  void EdShell::Draw()
  {
    HandleKeys();
    const bool playing = mPlay.Active();
    const bool panels = !playing || mPanelsWhilePlaying;

    // The dock space over the window. Its middle stays empty: the game's viewport is put over it (EdApp.cpp), so
    // the game's picture and input are there, inside the panels.
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const float statusHeight = ImGui::GetFrameHeight();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - statusHeight));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kHostFlags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
                                            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
                                            ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBackground;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("##EditorDockHost", nullptr, kHostFlags);
    ImGui::PopStyleVar(3);
    const ImGuiID dockspaceId = ImGui::GetID(kDockSpace);
    if (!mLayoutBuilt || mResetLayout) {
      if (mResetLayout || ImGui::DockBuilderGetNode(dockspaceId) == nullptr) {
        BuildDefaultLayout(dockspaceId);
      }
      mLayoutBuilt = true;
      mResetLayout = false;
    }
    ImGui::DockSpace(dockspaceId, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_PassthruCentralNode);
    if (const ImGuiDockNode* const middle = ImGui::DockBuilderGetCentralNode(dockspaceId); middle != nullptr) {
      mGameView = ImVec4(middle->Pos.x - viewport->Pos.x, middle->Pos.y - viewport->Pos.y, middle->Size.x, middle->Size.y);
    }
    ImGui::End();

    if (panels) {
      if (mShowTools) {
        DrawToolsPanel();
      }
      if (mShowMap) {
        DrawMapPanel();
      }
      if (mShowLog) {
        if (ImGui::Begin(kLogWindow, &mShowLog)) {
          mLog.Draw();
        }
        ImGui::End();
      }
    }
    if (mShowDemo) {
      ImGui::ShowDemoWindow(&mShowDemo);
    }
    DrawStatusBar();
  }

  void EdShell::BuildDefaultLayout(const unsigned int dockspaceId)
  {
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::DockBuilderRemoveNode(dockspaceId);
    ImGui::DockBuilderAddNode(dockspaceId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspaceId, viewport->WorkSize);
    ImGuiID center = dockspaceId;
    const ImGuiID left = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.21f, nullptr, &center);
    const ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.22f, nullptr, &center);
    const ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.22f, nullptr, &center);
    ImGui::DockBuilderDockWindow(kToolsWindow, left);
    ImGui::DockBuilderDockWindow(kMapWindow, right);
    ImGui::DockBuilderDockWindow(kLogWindow, bottom);
    ImGui::DockBuilderFinish(dockspaceId);
  }

  void EdShell::DrawToolsPanel()
  {
    if (ImGui::Begin(kToolsWindow, &mShowTools)) {
      mTools.Draw();
    }
    ImGui::End();
  }

  void EdShell::DrawMapPanel()
  {
    if (!ImGui::Begin(kMapWindow, &mShowMap)) {
      ImGui::End();
      return;
    }
    // Play: the picked map, Play or Stop, and what the session is doing.
    const std::vector<std::string>& maps = mPlay.Maps();
    const int selected = mPlay.Selected();
    if (!mPlay.Active()) {
      ImGui::BeginDisabled(!mPlay.CanPlay());
      ImGui::PushStyleColor(ImGuiCol_Button, kPlayGreen);
      if (ImGui::Button("Play  (F5)", ImVec2(-1.0f, 0.0f))) {
        mPlay.Play();
      }
      ImGui::PopStyleColor();
      ImGui::EndDisabled();
    } else {
      ImGui::PushStyleColor(ImGuiCol_Button, kStopRed);
      if (ImGui::Button("Stop  (F5)", ImVec2(-1.0f, 0.0f))) {
        mPlay.Stop();
      }
      ImGui::PopStyleColor();
    }
    const std::vector<std::string>& titles = mPlay.Titles();
    if (!maps.empty()) {
      const std::size_t at = static_cast<std::size_t>(selected);
      ImGui::TextUnformatted(titles[at].c_str());
      ImGui::SameLine();
      ImGui::TextDisabled("%s", MapDisplayName(maps[at]).c_str());
    }
    ImGui::TextDisabled("%s", mPlay.StateText());

    // Play setup: solo (fastest: no AI brains, so no AI map analysis) or against one AI type, the
    // player's faction, and the fog.
    PlaySetup& setup = mPlay.Setup();
    ImGui::BeginDisabled(mPlay.Active());
    int opponents = setup.withAi ? 1 : 0;
    ImGui::RadioButton("Solo", &opponents, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Against AI", &opponents, 1);
    setup.withAi = opponents == 1;
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("Every other army is an AI. The AI's map analysis adds about 2 s to each start.");
    }
    const std::vector<PlayChoice>& aiTypes = mPlay.AiTypes();
    if (setup.withAi && !aiTypes.empty()) {
      setup.ai = std::clamp(setup.ai, 0, static_cast<int>(aiTypes.size()) - 1);
      ImGui::SetNextItemWidth(-1.0f);
      if (ImGui::BeginCombo("##ai", aiTypes[static_cast<std::size_t>(setup.ai)].name.c_str())) {
        for (int i = 0; i < static_cast<int>(aiTypes.size()); ++i) {
          if (ImGui::Selectable(aiTypes[static_cast<std::size_t>(i)].name.c_str(), i == setup.ai)) {
            setup.ai = i;
          }
        }
        ImGui::EndCombo();
      }
    }
    const std::vector<PlayChoice>& factions = mPlay.Factions();
    setup.faction = std::clamp(setup.faction, 0, static_cast<int>(factions.size()));
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.5f);
    if (ImGui::BeginCombo("Faction", setup.faction == 0 ? "Random" : factions[static_cast<std::size_t>(setup.faction - 1)].name.c_str())) {
      if (ImGui::Selectable("Random", setup.faction == 0)) {
        setup.faction = 0;
      }
      for (int i = 0; i < static_cast<int>(factions.size()); ++i) {
        if (ImGui::Selectable(factions[static_cast<std::size_t>(i)].name.c_str(), setup.faction == i + 1)) {
          setup.faction = i + 1;
        }
      }
      ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::Checkbox("Fog", &setup.fog);
    ImGui::EndDisabled();

    // During play: the whole map, as an observer sees it, or the player's own view with its fog.
    ImGui::BeginDisabled(moho::WLD_GetFrameAction() != moho::EWldFrameAction::Playing);
    bool wholeMap = mPlay.SeesWholeMap();
    if (ImGui::Checkbox("See the whole map", &wholeMap)) {
      mPlay.SetSeesWholeMap(wholeMap);
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("While playing: view the map as an observer, with no fog,\nthen back to your army. "
                        "The Fog setting above applies from the next Play.");
    }
    ImGui::EndDisabled();
    ImGui::Separator();

    // Each map by its title, then its folder name; the filter matches either.
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##mapfilter", "Filter maps", mMapFilter, sizeof(mMapFilter));
    ImGui::BeginDisabled(mPlay.Active());
    if (ImGui::BeginChild("##maps", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
      for (int i = 0; i < static_cast<int>(maps.size()); ++i) {
        const std::size_t at = static_cast<std::size_t>(i);
        const std::string folder = MapDisplayName(maps[at]);
        if (mMapFilter[0] != '\0' && ImStristr(titles[at].c_str(), nullptr, mMapFilter, nullptr) == nullptr &&
            ImStristr(folder.c_str(), nullptr, mMapFilter, nullptr) == nullptr) {
          continue;
        }
        ImGui::PushID(i);
        if (ImGui::Selectable("##map", i == selected, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_AllowOverlap)) {
          mPlay.Select(i);
          if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && mPlay.CanPlay()) {
            mPlay.Play();
          }
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("%s\n%s\nDouble-click to play", titles[at].c_str(), maps[at].c_str());
        }
        ImGui::SameLine(ImGui::GetStyle().ItemSpacing.x);
        ImGui::TextUnformatted(titles[at].c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("%s", folder.c_str());
        ImGui::PopID();
      }
    }
    ImGui::EndChild();
    ImGui::EndDisabled();
    ImGui::End();
  }

  void EdShell::DrawStatusBar()
  {
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const float height = ImGui::GetFrameHeight();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - height));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoDocking |
                                        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                                        ImGuiWindowFlags_NoNav;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 2.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    if (ImGui::Begin("##StatusBar", nullptr, kFlags)) {
      ImGui::Text("%s", mApi.empty() ? "?" : mApi.c_str());
      if (!mAdapter.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", mAdapter.c_str());
      }
      ImGui::SameLine();
      ImGui::TextDisabled("| %s", mPlay.StateText());
      const int warnings = mLog.WarningCount();
      if (warnings > 0) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "| %d warnings in the log", warnings);
      }
      char text[32];
      (void)std::snprintf(text, sizeof(text), "%.0f fps", ImGui::GetIO().Framerate);
      ImGui::SameLine(ImGui::GetWindowWidth() - ImGui::CalcTextSize(text).x - 12.0f);
      ImGui::TextUnformatted(text);
    }
    ImGui::End();
    ImGui::PopStyleVar(2);
  }
} // namespace faf::editor
