#include "editor/EdShell.h"

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

    // The tools the plan lists, in its order (.plans/map-editor, "Goal").
    constexpr const char* kTools[] = {"Select", "Terrain", "Texture", "Water", "Props", "Decals", "Markers"};

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

  void EdShell::Draw()
  {
    DrawMenuBar();
    const bool panels = !mPlay.Active() || mPanelsWhilePlaying;

    // The dock space over the whole window. Its middle stays empty and lets the mouse through, so the game's
    // picture and input are there.
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
    const ImGuiID left = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.17f, nullptr, &center);
    const ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.22f, nullptr, &center);
    const ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.22f, nullptr, &center);
    ImGui::DockBuilderDockWindow(kToolsWindow, left);
    ImGui::DockBuilderDockWindow(kMapWindow, right);
    ImGui::DockBuilderDockWindow(kLogWindow, bottom);
    ImGui::DockBuilderFinish(dockspaceId);
  }

  void EdShell::DrawMenuBar()
  {
    if (!ImGui::BeginMainMenuBar()) {
      return;
    }
    if (ImGui::BeginMenu("File")) {
      ImGui::BeginDisabled();
      ImGui::MenuItem("New map...", "Ctrl+N");
      ImGui::MenuItem("Open map...", "Ctrl+O");
      ImGui::MenuItem("Save", "Ctrl+S");
      ImGui::MenuItem("Save as new version...");
      ImGui::EndDisabled();
      ImGui::Separator();
      if (ImGui::MenuItem("Exit")) {
        mExit = true;
      }
      ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("View")) {
      ImGui::MenuItem(kToolsWindow, nullptr, &mShowTools);
      ImGui::MenuItem(kMapWindow, nullptr, &mShowMap);
      ImGui::MenuItem(kLogWindow, nullptr, &mShowLog);
      ImGui::MenuItem("Panels while playing", nullptr, &mPanelsWhilePlaying);
      ImGui::Separator();
      if (ImGui::MenuItem("Reset layout")) {
        mResetLayout = true;
      }
      ImGui::MenuItem("ImGui demo", nullptr, &mShowDemo);
      ImGui::EndMenu();
    }

    // The play bar: the map, Play or Stop, and what the session is doing.
    ImGui::Separator();
    const std::vector<std::string>& maps = mPlay.Maps();
    const int selected = mPlay.Selected();
    const std::string current = maps.empty() ? std::string("(no maps found)") : MapDisplayName(maps[static_cast<std::size_t>(selected)]);
    ImGui::SetNextItemWidth(260.0f);
    ImGui::BeginDisabled(mPlay.Active());
    if (ImGui::BeginCombo("##map", current.c_str(), ImGuiComboFlags_HeightLarge)) {
      static char filter[64] = "";
      ImGui::SetNextItemWidth(-1.0f);
      if (ImGui::IsWindowAppearing()) {
        ImGui::SetKeyboardFocusHere();
      }
      ImGui::InputTextWithHint("##mapfilter", "Filter maps", filter, sizeof(filter));
      for (int i = 0; i < static_cast<int>(maps.size()); ++i) {
        const std::string name = MapDisplayName(maps[static_cast<std::size_t>(i)]);
        if (filter[0] != '\0' && ImStristr(name.c_str(), nullptr, filter, nullptr) == nullptr) {
          continue;
        }
        if (ImGui::Selectable(name.c_str(), i == selected)) {
          mPlay.Select(i);
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("%s", maps[static_cast<std::size_t>(i)].c_str());
        }
      }
      ImGui::EndCombo();
    }
    ImGui::EndDisabled();

    if (!mPlay.Active()) {
      ImGui::BeginDisabled(!mPlay.CanPlay());
      ImGui::PushStyleColor(ImGuiCol_Button, kPlayGreen);
      if (ImGui::Button("  Play  ") || (ImGui::IsKeyPressed(ImGuiKey_F5) && mPlay.CanPlay())) {
        mPlay.Play();
      }
      ImGui::PopStyleColor();
      ImGui::EndDisabled();
    } else {
      ImGui::PushStyleColor(ImGuiCol_Button, kStopRed);
      if (ImGui::Button("  Stop  ") || ImGui::IsKeyPressed(ImGuiKey_F5)) {
        mPlay.Stop();
      }
      ImGui::PopStyleColor();
    }
    ImGui::SetItemTooltip("F5");
    ImGui::TextDisabled("%s", mPlay.StateText());
    ImGui::EndMainMenuBar();
  }

  void EdShell::DrawToolsPanel()
  {
    if (ImGui::Begin(kToolsWindow, &mShowTools)) {
      for (int i = 0; i < static_cast<int>(IM_ARRAYSIZE(kTools)); ++i) {
        if (ImGui::Selectable(kTools[i], mTool == i)) {
          mTool = i;
        }
      }
      ImGui::Separator();
      ImGui::TextWrapped("The tools come in stages 3 to 6 of the plan (.plans/map-editor).");
    }
    ImGui::End();
  }

  void EdShell::DrawMapPanel()
  {
    if (ImGui::Begin(kMapWindow, &mShowMap)) {
      ImGui::TextDisabled("No map open for editing.");
      ImGui::Spacing();
      ImGui::TextWrapped("Pick a map in the play bar and press Play (F5) to play it here; Stop or F5 returns to the editor.");
      ImGui::Spacing();
      ImGui::TextWrapped("Opening and saving FAF maps is stage 2 of the plan.");
    }
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
