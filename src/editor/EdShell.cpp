#include "editor/EdShell.h"
#include "editor/ui/EdIcons.h"
#include "editor/tools/EdMarkers.h"

#include <set>
#include <cctype>

#include <algorithm>
#include <cstdio>
#include <cstdlib>

#include "editor/EdLog.h"
#include "editor/EdPlay.h"
#include "editor/doc/EdDocument.h"
#include "gpg/gal/Device.hpp"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "legacy/containers/String.h"
#include "moho/misc/StartupHelpers.h"

namespace faf::editor
{
  namespace
  {
    constexpr const char* kToolsWindow = "Tools";
    constexpr const char* kMapWindow = "Map";
    constexpr const char* kInfoWindow = "Info";
    constexpr const char* kMarkersWindow = "Markers";
    constexpr const char* kCheckWindow = "Check";
    constexpr const char* kLogWindow = "Log";
    constexpr const char* kDockSpace = "EditorDockSpace";

    const ImVec4 kPlayGreen(0.24f, 0.55f, 0.28f, 1.0f);
    const ImVec4 kStopRed(0.62f, 0.22f, 0.20f, 1.0f);
  } // namespace

  EdShell::EdShell(EdLog& log, EdPlay& play, EdDocument& document)
    : mBrowser(play, document)
    , mLog(log)
    , mPlay(play)
    , mDocument(document)
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

  void EdShell::UpdateTestRun()
  {
    const double now = ImGui::GetTime();
    switch (mTestRunStep) {
    case 1: {
      // The open map, picked in the Map panel's list, and played.
      const std::vector<std::string>& maps = mPlay.Maps();
      const auto at = std::find(maps.begin(), maps.end(), mDocument.Path());
      if (at == maps.end() || mPlay.Active() || !mPlay.CanPlay()) {
        gpg::Warnf("editor: test run: %s is not in the map list, or a play is on", mDocument.Path().c_str());
        mTestRunStep = 0;
        return;
      }
      mPlay.Select(static_cast<int>(at - maps.begin()));
      mTestRunMap = mDocument.Path();
      mLog.BeginCapture();
      mPlay.Play();
      mTestRunStarted = now;
      mTestRunStep = 2;
      gpg::Logf("editor: test run of %s", mTestRunMap.c_str());
      return;
    }
    case 2:
      if (moho::WLD_GetFrameAction() == moho::EWldFrameAction::Playing) {
        mTestRunStarted = now;
        mTestRunStep = 3;
      } else if (now - mTestRunStarted > 120.0) {
        gpg::Warnf("editor: test run: the session did not start in 2 minutes");
        mPlay.Stop();
        mTestRunStep = 4;
      }
      return;
    case 3:
      if (now - mTestRunStarted >= 8.0 || !mPlay.Active()) {
        mPlay.Stop();
        mTestRunStep = 4;
      }
      return;
    case 4:
      if (!mPlay.Active()) {
        // The warnings logged meanwhile: Lua errors (their text names a .lua file) first, the map's own files as errors.
        mTestRunIssues.clear();
        const std::string folder = MapDisplayName(mTestRunMap);
        for (const std::string& line : mLog.EndCapture()) {
          std::string lower = line;
          for (char& c : lower) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
          std::string lowerFolder = folder;
          for (char& c : lowerFolder) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
          CheckIssue issue;
          issue.marker = "test run";
          issue.text = line.size() > 400 ? line.substr(0, 400) + "..." : line;
          if (!lowerFolder.empty() && lower.find(lowerFolder) != std::string::npos) {
            issue.level = CheckIssue::Level::Error;
          } else if (lower.find(".lua") != std::string::npos || lower.find("traceback") != std::string::npos) {
            issue.level = CheckIssue::Level::Warning;
          } else {
            issue.level = CheckIssue::Level::Note;
          }
          mTestRunIssues.push_back(std::move(issue));
        }
        std::stable_sort(mTestRunIssues.begin(), mTestRunIssues.end(),
                         [](const CheckIssue& a, const CheckIssue& b) { return static_cast<int>(a.level) < static_cast<int>(b.level); });
        int counts[3] = {0, 0, 0};
        for (const CheckIssue& issue : mTestRunIssues) {
          ++counts[static_cast<int>(issue.level)];
        }
        gpg::Logf("editor: test run done: %d errors (the map's files), %d warnings (other Lua), %d notes", counts[0], counts[1], counts[2]);
        mTestRunSummary = "Last test run: " + std::to_string(counts[0]) + " errors, " + std::to_string(counts[1]) + " warnings, " +
                          std::to_string(counts[2]) + " notes";
        for (const CheckIssue& issue : mTestRunIssues) {
          if (issue.level != CheckIssue::Level::Note) {
            gpg::Logf("editor: test run %s: %s", CheckLevelName(issue.level), issue.text.c_str());
          }
        }
        mTestRunDone = true;
        mTestRunStep = 0;
      }
      return;
    default:
      return;
    }
  }

  void EdShell::Draw()
  {
    // The rings panels ask the view for are this frame's only; the lobby preview's hidden things only while it is on.
    mTools.ClearViewRings();
    if (!mShowAdaptiveWindow || !mAdaptivePreview) {
      if (!mTools.PreviewHiddenUnits().empty() || !mTools.PreviewHiddenMarkers().empty()) {
        mTools.SetPreviewHidden({}, {});
      }
      mAdaptivePreviewDone.clear();
    }
    HandleKeys();
    UpdateTestRun();
    mBrowser.Update();
    const bool playing = mPlay.Active();
    const bool panels = !playing || mPanelsWhilePlaying;

    // The dock space over the window. Its middle stays empty: the game's viewport is put over it (EdApp.cpp), so
    // the game's picture and input are there, inside the panels.
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const float statusHeight = ImGui::GetFrameHeight();
    const float toolbarHeight = ImGui::GetFrameHeight() + 12.0f;
    DrawToolbar(toolbarHeight);
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + toolbarHeight));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - statusHeight - toolbarHeight));
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
    // A layout saved before the Properties panel existed: the panel goes under the Tools panel, once.
    if (!mPropertiesPlaced) {
      if (const ImGuiWindow* const tools = ImGui::FindWindowByName(kToolsWindow); tools != nullptr) {
        mPropertiesPlaced = true;
        if (ImGui::FindWindowSettingsByID(ImHashStr("Properties")) == nullptr && tools->DockId != 0) {
          ImGuiID top = 0;
          ImGuiID bottom = 0;
          ImGui::DockBuilderSplitNode(tools->DockId, ImGuiDir_Down, 0.42f, &bottom, &top);
          ImGui::DockBuilderDockWindow("Properties", bottom);
          ImGui::DockBuilderFinish(dockspaceId);
        }
      }
    }
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
      if (mShowInfo) {
        DrawInfoPanel();
      }
      if (mShowMarkers) {
        DrawMarkersPanel();
      }
      if (mShowCheck) {
        DrawCheckPanel();
      }
      if (mShowScript) {
        DrawScriptPanel();
      }
      if (mShowLighting) {
        DrawLightingPanel();
      }
      if (mShowMaterialEditor) {
        mMaterialEditor.Draw(mShowMaterialEditor);
      }
      if (mShowParticleEditor) {
        mParticleEditor.Draw(mShowParticleEditor);
      }
      if (mShowParticleBrowser) {
        mParticleEditor.DrawBrowserWindow(mShowParticleBrowser);
      }
      if (mShowAdaptiveWindow) {
        DrawAdaptiveWindow();
      }
      if (mParticleEditor.TakeOpenEditorAsk()) {
        // The browser's "Edit": the editor takes over, the browser closes.
        mShowParticleEditor = true;
        mShowParticleBrowser = false;
      }
      if (mParticleEditor.TakeOpenBrowserAsk()) {
        mShowParticleBrowser = true;
      }
      if (mTools.TakeOpenArmies()) {
        mShowArmies = true;
        mFocusArmies = true;
      }
      if (mShowArmies) {
        DrawArmiesPanel();
      }
      if (mShowProperties) {
        DrawPropertiesPanel();
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
    DrawSaveAsDialog();
    mBrowser.Draw();
    DrawNewMapDialog();
    DrawPackageDialog();
    DrawStatusBar();
  }

  void EdShell::BuildDefaultLayout(const unsigned int dockspaceId)
  {
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::DockBuilderRemoveNode(dockspaceId);
    ImGui::DockBuilderAddNode(dockspaceId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspaceId, viewport->WorkSize);
    ImGuiID center = dockspaceId;
    ImGuiID left = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.21f, nullptr, &center);
    // The Properties panel under the Tools panel.
    const ImGuiID leftBottom = ImGui::DockBuilderSplitNode(left, ImGuiDir_Down, 0.42f, nullptr, &left);
    ImGui::DockBuilderDockWindow("Properties", leftBottom);
    const ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.22f, nullptr, &center);
    const ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.22f, nullptr, &center);
    ImGui::DockBuilderDockWindow(kToolsWindow, left);
    ImGui::DockBuilderDockWindow(kMapWindow, right);
    ImGui::DockBuilderDockWindow(kInfoWindow, right);
    ImGui::DockBuilderDockWindow(kMarkersWindow, right);
    ImGui::DockBuilderDockWindow(kCheckWindow, right);
    ImGui::DockBuilderDockWindow(kLogWindow, bottom);
    ImGui::DockBuilderFinish(dockspaceId);
  }

  void EdShell::DrawToolbar(const float height)
  {
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoDocking |
                                        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                                        ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoScrollbar;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8.0f, 6.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, ImGui::GetStyle().FramePadding.y));
    if (ImGui::Begin("##Toolbar", nullptr, kFlags)) {
      const bool playing = mPlay.Active();
      const bool open = mDocument.GetState() == EdDocument::State::Open;
      const float buttonHeight = ImGui::GetFrameHeight();
      const auto tip = [](const char* const text) {
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayShort)) {
          ImGui::SetTooltip("%s", text);
        }
      };
      const auto divider = [] {
        ImGui::SameLine();
        ImGui::SeparatorEx(ImGuiSeparatorFlags_Vertical);
        ImGui::SameLine();
      };

      // Play / Stop: green or red, its icon drawn, the key beside the word.
      {
        const ImVec4 base = playing ? kStopRed : kPlayGreen;
        ImGui::PushStyleColor(ImGuiCol_Button, base);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(base.x * 1.25f, base.y * 1.25f, base.z * 1.25f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(base.x * 0.85f, base.y * 0.85f, base.z * 0.85f, 1.0f));
        ImGui::BeginDisabled(!playing && !mPlay.CanPlay());
        const ImVec2 at = ImGui::GetCursorScreenPos();
        const ImVec2 size(118.0f, buttonHeight);
        if (ImGui::Button("##playstop", size)) {
          if (playing) {
            mPlay.Stop();
          } else {
            mPlay.Play();
          }
        }
        ImDrawList* const draw = ImGui::GetWindowDrawList();
        const ImU32 white = ImGui::GetColorU32(ImGuiCol_Text);
        const float cy = at.y + size.y * 0.5f;
        const float r = size.y * 0.24f;
        if (playing) {
          draw->AddRectFilled(ImVec2(at.x + 12.0f, cy - r), ImVec2(at.x + 12.0f + 2.0f * r, cy + r), white, 1.5f);
        } else {
          draw->AddTriangleFilled(ImVec2(at.x + 12.0f, cy - r * 1.1f), ImVec2(at.x + 12.0f, cy + r * 1.1f),
                                  ImVec2(at.x + 12.0f + 2.0f * r, cy), white);
        }
        const char* const word = playing ? "Stop" : "Play";
        const float textY = at.y + (size.y - ImGui::GetTextLineHeight()) * 0.5f;
        draw->AddText(ImVec2(at.x + 20.0f + 2.0f * r, textY), white, word);
        // The key, on a darker cap so it reads on the green and the red.
        const ImVec2 keySize = ImGui::CalcTextSize("F5");
        const ImVec2 capMin(at.x + size.x - keySize.x - 14.0f, at.y + 4.0f);
        const ImVec2 capMax(at.x + size.x - 6.0f, at.y + size.y - 4.0f);
        draw->AddRectFilled(capMin, capMax, IM_COL32(0, 0, 0, 90), 3.0f);
        draw->AddRect(capMin, capMax, IM_COL32(255, 255, 255, 70), 3.0f);
        draw->AddText(ImVec2(capMin.x + 4.0f, textY), IM_COL32(255, 255, 255, 230), "F5");
        ImGui::EndDisabled();
        tip(playing ? "Stop the session and go back to editing (F5)" : "Play the map picked in the Map panel (F5)");
        // The setup, one click away.
        ImGui::SameLine(0.0f, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4.0f, ImGui::GetStyle().FramePadding.y));
        if (ImGui::ArrowButton("##playsetup", ImGuiDir_Down)) {
          ImGui::OpenPopup("##playsetuppopup");
        }
        ImGui::PopStyleVar();
        ImGui::PopStyleColor(3);
        tip("Play options: start slot, faction, AI opponents, fog, prebuilt units; while playing, hide the fog or watch as an observer");
        ImGui::SetNextWindowSize(ImVec2(ImGui::GetFontSize() * 22.0f, 0.0f));
        if (ImGui::BeginPopup("##playsetuppopup")) {
          const std::vector<std::string>& playMaps = mPlay.Maps();
          if (!playMaps.empty()) {
            ImGui::TextUnformatted(mPlay.Titles()[static_cast<std::size_t>(mPlay.Selected())].c_str());
            ImGui::SameLine();
            ImGui::TextDisabled("%s", MapDisplayName(playMaps[static_cast<std::size_t>(mPlay.Selected())]).c_str());
            ImGui::Separator();
          }
          DrawPlaySetup();
          ImGui::EndPopup();
        }
      }
      divider();

      // File.
      ImGui::BeginDisabled(playing);
      if (EdToolButton("##new", EdIcon::NewFile, "New", false, false)) {
        mOpenNewMap = true;
      }
      tip("A new map: size, players, height and sea (Ctrl+N)");
      ImGui::SameLine();
      const std::vector<std::string>& maps = mPlay.Maps();
      ImGui::BeginDisabled(maps.empty() || mDocument.GetState() == EdDocument::State::Loading);
      if (EdToolButton("##open", EdIcon::Folder, "Open", false, false)) {
        mBrowser.Show();
      }
      ImGui::EndDisabled();
      tip("Browse maps: every map on this computer (the game's, FAF's folder, your vault) and maps from the FAF vault");
      ImGui::SameLine();
      ImGui::BeginDisabled(!open);
      if (EdToolButton("##save", EdIcon::Save, "Save", false, false)) {
        mCommand = Command::Save;
      }
      tip("Save the map into its folder (Ctrl+S)");
      ImGui::SameLine();
      if (EdToolButton("##saveas", EdIcon::SaveAs, "Save as", false, false)) {
        mOpenSaveAs = true;
      }
      tip("Save the map as a new folder in your vault");
      ImGui::EndDisabled();
      divider();

      // Edit.
      ImGui::BeginDisabled(!open || !mDocument.CanUndo());
      if (EdToolButton("##undo", EdIcon::Undo, "Undo", false, false, EdSegment::First)) {
        mCommand = Command::Undo;
      }
      ImGui::EndDisabled();
      tip("Undo the last edit (Ctrl+Z)");
      ImGui::SameLine(0.0f, 1.0f);
      ImGui::BeginDisabled(!open || !mDocument.CanRedo());
      if (EdToolButton("##redo", EdIcon::Redo, "Redo", false, false, EdSegment::Last)) {
        mCommand = Command::Redo;
      }
      ImGui::EndDisabled();
      tip("Redo (Ctrl+Y)");
      ImGui::EndDisabled();
      divider();

      // The build grid and snapping.
      const auto toggle = [](const char* const label, const EdIcon icon, const bool on) {
        ImGui::PushID(label);
        const bool clicked = EdToolButton("##toggle", icon, label, true, on);
        ImGui::PopID();
        return clicked;
      };
      if (toggle("Grid", EdIcon::Grid, mTools.ShowGrid())) {
        mTools.SetShowGrid(!mTools.ShowGrid());
      }
      tip("The build grid on the ground around the cursor: cells of the step's size, one unit being the cell units are built on");
      ImGui::SameLine();
      if (toggle("Snap", EdIcon::Magnet, mTools.SnapToGrid())) {
        mTools.SetSnapToGrid(!mTools.SnapToGrid());
      }
      tip("Markers and props placed or dragged go to the middle of a grid cell (mass and hydrocarbon points always sit on half units, as the game's saves place them)");
      ImGui::SameLine();
      if (toggle("On ground", EdIcon::OnGround, mTools.KeepOnGround())) {
        mTools.SetKeepOnGround(!mTools.KeepOnGround());
      }
      tip("The move arrows keep markers and props on the ground when they move across it; off, they keep their height. "
          "Nothing is moved under the ground either way.");
      ImGui::SameLine();
      if (toggle("Slope", EdIcon::Slope, mTools.ShowSlope())) {
        mTools.SetShowSlope(!mTools.ShowSlope());
      }
      tip("Each cell's slope as the game's pathing reads it (its steepest edge): yellow above 0.25 (too steep to build on), orange "
          "above 0.5, red above 0.75 (steeper than most land units climb)");
      ImGui::SameLine();
      if (toggle("Km grid", EdIcon::Ruler, mTools.ShowKmGrid())) {
        mTools.SetShowKmGrid(!mTools.ShowKmGrid());
      }
      tip("Lines every kilometre (51.2 units, the game's scale) and the map's centre lines. Alt+drag in the view measures a distance.");
      ImGui::SameLine();
      {
        static constexpr float kSteps[] = {0.5f, 1.0f, 2.0f, 4.0f, 8.0f};
        static constexpr const char* kStepNames[] = {"0.5", "1", "2", "4", "8"};
        int current = 1;
        for (int i = 0; i < 5; ++i) {
          if (mTools.GridStep() == kSteps[i]) {
            current = i;
          }
        }
        ImGui::SetNextItemWidth(ImGui::CalcTextSize("0.5").x + ImGui::GetFrameHeight() * 2.0f);
        if (ImGui::BeginCombo("##gridstep", kStepNames[current])) {
          for (int i = 0; i < 5; ++i) {
            if (ImGui::Selectable(kStepNames[i], i == current)) {
              mTools.SetGridStep(kSteps[i]);
            }
          }
          ImGui::EndCombo();
        }
        tip("The grid's step in game units");
      }
      ImGui::SameLine();
      divider();
      // The map border, edited from any tool.
      if (IconToggle("##border", EdIcon::Border, mTools.EditingBorder())) {
        mTools.EditingBorder() = !mTools.EditingBorder();
        mShowProperties = mShowProperties || mTools.EditingBorder();
      }
      tip(mTools.EditingBorder() ? "Map border: on. Drag its edges in the view; its settings are in the Properties panel"
                                 : "Map border (the playable area): edit it from any tool");
      divider();
      // What the view shows, one toggle per kind (Blender's object type visibility); hidden things aren't picked.
      // One joined row (1 px apart, rounded at its ends), as Blender's and the image editors' toggle groups.
      if (IconToggle("##showprops", EdIcon::Tree, mTools.ShowProps(), EdSegment::First)) {
        mTools.ShowProps() = !mTools.ShowProps();
      }
      tip(mTools.ShowProps() ? "Props shown (trees, rocks, wrecks): click to hide them" : "Props hidden: click to show them");
      ImGui::SameLine(0.0f, 1.0f);
      if (IconToggle("##showunits", EdIcon::Tank, mTools.ShowUnits(), EdSegment::Middle)) {
        mTools.ShowUnits() = !mTools.ShowUnits();
      }
      tip(mTools.ShowUnits() ? "Units shown (the armies' and civilians' units): click to hide them" : "Units hidden: click to show them");
      // Markers by the palette's groups: shown while none of the group's types is hidden; a click shows or hides all of them.
      struct MarkerGroup
      {
        const char* group;
        EdIcon icon;
        const char* what;
      };
      static constexpr MarkerGroup kGroups[] = {
        {"Resources", EdIcon::Resource, "Mass and hydrocarbon markers"},
        {"Starts", EdIcon::Flag, "Start positions"},
        {"AI", EdIcon::Crosshair, "AI markers (expansions, rally points, defensive points...)"},
        {"Path nodes", EdIcon::PathNodes, "Path nodes and their links (land, air, water, amphibious)"},
        {"Other", EdIcon::Pin, "Other markers (camera, weather, effects...)"},
      };
      std::set<std::string>& hidden = mTools.HiddenMarkerTypes();
      for (const MarkerGroup& group : kGroups) {
        const EdSegment segment = &group == &kGroups[std::size(kGroups) - 1] ? EdSegment::Last : EdSegment::Middle;
        bool shown = true;
        for (const MarkerType& type : MarkerTypes()) {
          shown = shown && (std::string(group.group) != type.group || hidden.count(type.type) == 0);
        }
        ImGui::SameLine(0.0f, 1.0f);
        ImGui::PushID(group.group);
        if (IconToggle("##showmarkers", group.icon, shown, segment)) {
          for (const MarkerType& type : MarkerTypes()) {
            if (std::string(group.group) == type.group) {
              if (shown) {
                hidden.insert(type.type);
              } else {
                hidden.erase(type.type);
              }
            }
          }
        }
        ImGui::PopID();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
          ImGui::SetTooltip("%s %s: click to %s them", group.what, shown ? "shown" : "hidden", shown ? "hide" : "show");
        }
      }

      // The open map, at the right: its name, its folder, and a dot while it has unsaved edits.
      if (open) {
        const MapFacts& facts = mDocument.Facts();
        const std::string name = facts.name.empty() ? MapDisplayName(facts.scenarioPath) : facts.name;
        const std::string folder = MapDisplayName(facts.scenarioPath);
        const char* const edited = mDocument.Modified() ? "  edited" : "";
        const float width = ImGui::CalcTextSize(name.c_str()).x + ImGui::CalcTextSize(folder.c_str()).x +
                            ImGui::CalcTextSize(edited).x + 24.0f;
        ImGui::SameLine(std::max(ImGui::GetCursorPosX() + 16.0f, ImGui::GetWindowWidth() - width - 8.0f));
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(name.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("%s", folder.c_str());
        if (mDocument.Modified()) {
          ImGui::SameLine(0.0f, 4.0f);
          ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "%s", edited);
        }
      }
    }
    ImGui::End();
    ImGui::PopStyleVar(4);
  }

  void EdShell::DrawToolsPanel()
  {
    if (ImGui::Begin(kToolsWindow, &mShowTools)) {
      mTools.Draw();
      if (int slot = -1; mTools.TakeMaterialAsk(slot)) {
        mShowMaterialEditor = true;
        mMaterialEditor.OpenForSlot(slot);
      }
    }
    ImGui::End();
  }

  void EdShell::DrawPlaySetup()
  {
    // Solo (fastest: no AI brains, so no AI map analysis) or against one AI type, the player's start and
    // faction, and the game's options the editor sets.
    PlaySetup& setup = mPlay.Setup();
    ImGui::BeginDisabled(mPlay.Active());

    // The slots: the open map's armies when it is the picked one, else numbers.
    const std::vector<std::string>& maps = mPlay.Maps();
    std::vector<std::string> slots;
    if (!maps.empty() && mDocument.GetState() == EdDocument::State::Open &&
        mDocument.Path() == maps[static_cast<std::size_t>(mPlay.Selected())]) {
      const std::vector<ScenarioTeam> teams = mDocument.Teams();
      if (!teams.empty()) {
        slots = teams.front().armies;
      }
    }
    const int slotCount = slots.empty() ? 16 : static_cast<int>(slots.size());

    // Profiles: built-in setups and the mapper's own; Save keeps the setup as it is under a name.
    {
      const std::vector<PlayProfile> profiles = mPlay.Profiles();
      ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.55f);
      if (ImGui::BeginCombo("##profile", "Profile...")) {
        bool savedHeader = false;
        for (const PlayProfile& profile : profiles) {
          if (!profile.builtIn && !savedHeader) {
            ImGui::SeparatorText("Saved");
            savedHeader = true;
          }
          if (ImGui::Selectable(profile.name.c_str())) {
            mPlay.ApplyProfile(profile.name, slots.empty() ? 8 : slotCount);
          }
        }
        ImGui::EndCombo();
      }
      ImGui::SameLine();
      ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("Save").x - ImGui::GetStyle().FramePadding.x * 4.0f);
      ImGui::InputTextWithHint("##profilename", "name", mProfileName, sizeof(mProfileName));
      ImGui::SameLine();
      ImGui::BeginDisabled(mProfileName[0] == '\0');
      if (ImGui::Button("Save")) {
        mPlay.SaveProfile(mProfileName);
        mProfileName[0] = '\0';
      }
      ImGui::EndDisabled();
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("Keep this setup as a profile of that name (play_setups.ini)");
      }
    }

    int mode = !setup.slots.empty() ? 2 : setup.withAi ? 1 : 0;
    const int modeBefore = mode;
    ImGui::RadioButton("Solo", &mode, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Against AI", &mode, 1);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("Other slots get an AI. The AI's map analysis adds about 2 s to each start.");
    }
    ImGui::SameLine();
    ImGui::RadioButton("Custom", &mode, 2);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("Slot by slot: you, an AI or empty, and teams (a team's armies start allied)");
    }
    if (mode != modeBefore) {
      setup.withAi = mode != 0;
      if (mode == 2 && setup.slots.empty()) {
        // Every slot: you in your start, AIs in the others.
        const int count = slots.empty() ? 8 : slotCount;
        for (int i = 0; i < count; ++i) {
          PlaySlot slot;
          slot.role = i == setup.slot ? PlaySlot::Role::You : PlaySlot::Role::Ai;
          slot.ai = setup.ai;
          setup.slots.push_back(slot);
        }
      } else if (mode != 2) {
        setup.slots.clear();
      }
      mPlay.PrepareRules();
    }
    const bool custom = mode == 2;
    setup.slot = std::clamp(setup.slot, 0, slotCount - 1);
    const auto slotName = [&](const int i) {
      return slots.empty() ? "Slot " + std::to_string(i + 1) : std::to_string(i + 1) + "  " + slots[static_cast<std::size_t>(i)];
    };
    const float labelWidth = ImGui::CalcTextSize("AI opponents").x + ImGui::GetStyle().ItemSpacing.x * 2.0f;
    const auto label = [&](const char* const text) {
      ImGui::AlignTextToFramePadding();
      ImGui::TextDisabled("%s", text);
      ImGui::SameLine(labelWidth);
      ImGui::SetNextItemWidth(-1.0f);
    };
    if (!custom) {
    label("Start");
    if (ImGui::BeginCombo("##slot", slotName(setup.slot).c_str())) {
      for (int i = 0; i < slotCount; ++i) {
        if (ImGui::Selectable(slotName(i).c_str(), i == setup.slot)) {
          setup.slot = i;
        }
      }
      ImGui::EndCombo();
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("The lobby slot you play (its army's start position)");
    }
    }
    const std::vector<PlayChoice>& factions = mPlay.Factions();
    setup.faction = std::clamp(setup.faction, 0, static_cast<int>(factions.size()));
    label("Faction");
    if (ImGui::BeginCombo("##faction", setup.faction == 0 ? "Random" : factions[static_cast<std::size_t>(setup.faction - 1)].name.c_str())) {
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
    const std::vector<PlayChoice>& aiTypes = mPlay.AiTypes();
    if (setup.withAi && !aiTypes.empty()) {
      setup.ai = std::clamp(setup.ai, 0, static_cast<int>(aiTypes.size()) - 1);
      label("AI");
      if (ImGui::BeginCombo("##ai", aiTypes[static_cast<std::size_t>(setup.ai)].name.c_str())) {
        for (int i = 0; i < static_cast<int>(aiTypes.size()); ++i) {
          if (ImGui::Selectable(aiTypes[static_cast<std::size_t>(i)].name.c_str(), i == setup.ai)) {
            setup.ai = i;
            mPlay.PrepareRules(); // an AI mod's type brings its mod
          }
        }
        ImGui::EndCombo();
      }
      if (!custom) {
      setup.aiCount = std::clamp(setup.aiCount, 0, slotCount - 1);
      label("AI opponents");
      const std::string count = setup.aiCount == 0 ? std::string("Every other slot") : std::to_string(setup.aiCount);
      if (ImGui::BeginCombo("##aicount", count.c_str())) {
        if (ImGui::Selectable("Every other slot", setup.aiCount == 0)) {
          setup.aiCount = 0;
        }
        for (int i = 1; i < slotCount; ++i) {
          if (ImGui::Selectable(std::to_string(i).c_str(), setup.aiCount == i)) {
            setup.aiCount = i;
          }
        }
        ImGui::EndCombo();
      }
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("How many slots get an AI, taken in slot order; the rest stay empty");
      }
      }
    }
    // Custom: one row per slot (role, its AI, its team); one You at most.
    if (custom && !aiTypes.empty()) {
      static const char* const kRoles[3] = {"Empty", "You", "AI"};
      static const char* const kTeams[5] = {"-", "Team 1", "Team 2", "Team 3", "Team 4"};
      bool changed = false;
      const float roleWidth = ImGui::CalcTextSize("Empty").x + ImGui::GetFrameHeight() * 1.6f;
      const float teamWidth = ImGui::CalcTextSize("Team 4").x + ImGui::GetFrameHeight() * 1.6f;
      const float factionWidth = ImGui::CalcTextSize("Random").x + ImGui::GetFrameHeight() * 1.6f;
      for (std::size_t i = 0; i < setup.slots.size(); ++i) {
        PlaySlot& slot = setup.slots[i];
        ImGui::PushID(static_cast<int>(i));
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%zu", i + 1);
        ImGui::SameLine(ImGui::GetFontSize() * 1.6f);
        int role = static_cast<int>(slot.role);
        ImGui::SetNextItemWidth(roleWidth);
        if (ImGui::Combo("##role", &role, kRoles, 3)) {
          slot.role = static_cast<PlaySlot::Role>(role);
          if (slot.role == PlaySlot::Role::You) {
            for (std::size_t k = 0; k < setup.slots.size(); ++k) {
              if (k != i && setup.slots[k].role == PlaySlot::Role::You) {
                setup.slots[k].role = PlaySlot::Role::Empty;
              }
            }
          }
          changed = true;
        }
        ImGui::SameLine();
        const float aiWidth = ImGui::GetContentRegionAvail().x - teamWidth - factionWidth - ImGui::GetStyle().ItemSpacing.x * 2.0f;
        if (slot.role == PlaySlot::Role::Ai) {
          slot.ai = std::clamp(slot.ai, 0, static_cast<int>(aiTypes.size()) - 1);
          ImGui::SetNextItemWidth(aiWidth);
          if (ImGui::BeginCombo("##slotai", aiTypes[static_cast<std::size_t>(slot.ai)].name.c_str())) {
            for (int k = 0; k < static_cast<int>(aiTypes.size()); ++k) {
              if (ImGui::Selectable(aiTypes[static_cast<std::size_t>(k)].name.c_str(), k == slot.ai)) {
                slot.ai = k;
                changed = true;
              }
            }
            ImGui::EndCombo();
          }
        } else {
          ImGui::Dummy(ImVec2(aiWidth, ImGui::GetFrameHeight()));
        }
        ImGui::SameLine();
        // An AI's faction (yours is the setup's Faction above).
        if (slot.role == PlaySlot::Role::Ai) {
          slot.faction = std::clamp(slot.faction, 0, static_cast<int>(factions.size()));
          ImGui::SetNextItemWidth(factionWidth);
          if (ImGui::BeginCombo("##slotfaction",
                                slot.faction == 0 ? "Random" : factions[static_cast<std::size_t>(slot.faction - 1)].name.c_str())) {
            if (ImGui::Selectable("Random", slot.faction == 0)) {
              slot.faction = 0;
            }
            for (int k = 0; k < static_cast<int>(factions.size()); ++k) {
              if (ImGui::Selectable(factions[static_cast<std::size_t>(k)].name.c_str(), slot.faction == k + 1)) {
                slot.faction = k + 1;
              }
            }
            ImGui::EndCombo();
          }
        } else {
          ImGui::Dummy(ImVec2(factionWidth, ImGui::GetFrameHeight()));
        }
        ImGui::SameLine();
        slot.team = std::clamp(slot.team, 0, 4);
        ImGui::SetNextItemWidth(teamWidth);
        changed = ImGui::Combo("##team", &slot.team, kTeams, 5) || changed;
        ImGui::PopID();
      }
      if (changed) {
        mPlay.PrepareRules();
      }
    }
    // The sim mods played with; an AI mod's AI types are in the AI list, and its mod comes along when one is chosen.
    if (!mPlay.Mods().empty()) {
      const std::size_t on = setup.mods.size();
      char header[64];
      (void)std::snprintf(header, sizeof(header), "Mods (%zu of %zu)###playmods", on, mPlay.Mods().size());
      if (ImGui::TreeNodeEx(header, ImGuiTreeNodeFlags_SpanAvailWidth)) {
        bool changed = false;
        for (const PlayMod& mod : mPlay.Mods()) {
          bool enabled = std::find(setup.mods.begin(), setup.mods.end(), mod.uid) != setup.mods.end();
          const std::string label = mod.name + (mod.aiTypes.empty() ? "" : "  (AI)");
          ImGui::PushID(mod.uid.c_str());
          if (ImGui::Checkbox(label.c_str(), &enabled)) {
            if (enabled) {
              setup.mods.push_back(mod.uid);
            } else {
              setup.mods.erase(std::remove(setup.mods.begin(), setup.mods.end(), mod.uid), setup.mods.end());
            }
            changed = true;
          }
          ImGui::PopID();
        }
        if (changed) {
          mPlay.PrepareRules();
        }
        ImGui::TreePop();
      }
    }
    ImGui::Checkbox("Fog of war", &setup.fog);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("The game's Fog of War option (explored, or none), set when the play starts");
    }
    ImGui::SameLine();
    ImGui::Checkbox("Prebuilt units", &setup.prebuilt);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("The game's Prebuilt Units option: each army starts with a small base");
    }
    {
      static const char* const kVictoryKeys[5] = {"sandbox", "demoralization", "domination", "eradication", "decapitation"};
      static const char* const kVictoryNames[5] = {"Sandbox (no end)", "Assassination", "Supremacy", "Annihilation", "Decapitation"};
      int victory = 0;
      for (int i = 0; i < 5; ++i) {
        victory = setup.victory == kVictoryKeys[i] ? i : victory;
      }
      label("Victory");
      if (ImGui::Combo("##victory", &victory, kVictoryNames, 5)) {
        setup.victory = kVictoryKeys[victory];
      }
      label("Unit cap");
      ImGui::SliderInt("##unitcap", &setup.unitCap, 250, 1500, "%d units");
      setup.unitCap = std::clamp(setup.unitCap / 50 * 50, 250, 1500);
      label("AI cheat x");
      ImGui::SliderFloat("##cheatmult", &setup.cheatMult, 1.0f, 5.0f, "%.1f");
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("The cheating AIs' resource and build multiplier (the lobby's AIx options)");
      }
      setup.cheatMult = std::round(setup.cheatMult * 10.0f) / 10.0f;
    }
    bool keepOwn = mPlay.KeepsOwnSetup();
    if (ImGui::Checkbox("Keep this setup for this map", &keepOwn)) {
      mPlay.SetKeepsOwnSetup(keepOwn);
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("On: this map plays with its own setup, saved at each Play.\n"
                        "Off: it plays with the setup of the last Play on any map.");
    }
    ImGui::EndDisabled();

    // During play: the fog's shading left out of the view (the player keeps their army), or the observer's view.
    ImGui::BeginDisabled(moho::WLD_GetFrameAction() != moho::EWldFrameAction::Playing);
    bool noFog = mPlay.FogHidden();
    if (ImGui::Checkbox("Hide the fog", &noFog)) {
      mPlay.SetFogHidden(noFog);
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("While playing: the view leaves out the fog's shading and you keep your army.\n"
                        "Enemy units your army has no intel on stay unseen; Observer view shows them.");
    }
    ImGui::SameLine();
    bool wholeMap = mPlay.SeesWholeMap();
    if (ImGui::Checkbox("Observer view", &wholeMap)) {
      mPlay.SetSeesWholeMap(wholeMap);
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("While playing: view the map as an observer (every army's units, no fog), then back to your army.");
    }
    ImGui::EndDisabled();
  }

  void EdShell::DrawMapPanel()
  {
    // `/mapscroll <pixels>` (test runs): the panel scrolled there, a while after a map opened.
    static int scrollFrames = 0;
    if (mDocument.GetState() == EdDocument::State::Open && scrollFrames < 80 && ++scrollFrames >= 70) {
      if (fa::vector<fa::string> value; moho::CFG_GetArgOption("/mapscroll", 1, &value) && !value.empty()) {
        ImGui::SetNextWindowScroll(ImVec2(-1.0f, static_cast<float>(std::atof(value[0].c_str()))));
      }
    }
    if (!ImGui::Begin(kMapWindow, &mShowMap)) {
      ImGui::End();
      return;
    }
    // Play: the picked map (the one open, or Play > Map), and what the session is doing.
    const std::vector<std::string>& maps = mPlay.Maps();
    const int selected = mPlay.Selected();
    const std::vector<std::string>& titles = mPlay.Titles();
    if (!maps.empty()) {
      const std::size_t at = static_cast<std::size_t>(selected);
      ImGui::TextUnformatted(titles[at].c_str());
      ImGui::SameLine();
      ImGui::TextDisabled("%s", MapDisplayName(maps[at]).c_str());
    }
    ImGui::TextDisabled("%s", mPlay.StateText());
    if (ImGui::Button("Open a map...", ImVec2(-1.0f, 0.0f))) {
      mBrowser.Show();
    }
    ImGui::SetItemTooltip("Every map on this computer and the FAF vault (File > Open, Ctrl+O); recent ones are in File > Open Recent");
    ImGui::Separator();

    DrawPlaySetup();

    // The open map: what it is, and its adaptive setup when it has one.
    if (mDocument.GetState() == EdDocument::State::Open) {
      const MapFacts& facts = mDocument.Facts();
      ImGui::Separator();
      if (ImGui::CollapsingHeader("Map", ImGuiTreeNodeFlags_DefaultOpen)) {
        const auto row = [](const char* const label) {
          ImGui::AlignTextToFramePadding();
          ImGui::TextDisabled("%s", label);
          ImGui::SameLine(ImGui::GetFontSize() * 6.5f);
        };
        row("Name");
        ImGui::TextUnformatted(facts.name.empty() ? MapDisplayName(facts.scenarioPath).c_str() : facts.name.c_str());
        row("Folder");
        ImGui::TextUnformatted(MapDisplayName(facts.scenarioPath).c_str());
        if (facts.mapVersion > 0) {
          ImGui::SameLine();
          ImGui::TextDisabled("version %d", facts.mapVersion);
        }
        row("Type");
        ImGui::Text("%s%s", facts.type.empty() ? "skirmish" : facts.type.c_str(), mDocument.Adaptive() ? ", adaptive" : "");
        row("Size");
        ImGui::Text("%.0f x %.0f km (%d x %d)", static_cast<double>(facts.sizeX) / 51.2, static_cast<double>(facts.sizeZ) / 51.2, facts.sizeX, facts.sizeZ);
        row("Players");
        ImGui::Text("%zu", mDocument.Teams().empty() ? facts.armies.size() : mDocument.Teams().front().armies.size());
        row("Water");
        if (facts.water) {
          ImGui::Text("at %.1f (deep %.1f, abyss %.1f)", static_cast<double>(facts.waterElevation), static_cast<double>(facts.waterDeep),
                      static_cast<double>(facts.waterAbyss));
        } else {
          ImGui::TextUnformatted("none");
        }
        row("Contents");
        ImGui::Text("%d markers, %d props, %d decals", facts.markerCount, facts.props, facts.decals);
        if (!facts.description.empty()) {
          row("About");
          ImGui::PushTextWrapPos(0.0f);
          ImGui::TextUnformatted(facts.description.c_str());
          ImGui::PopTextWrapPos();
        }
        if (ImGui::SmallButton("More in the Info panel")) {
          mShowInfo = true;
          ImGui::SetWindowFocus(kInfoWindow);
        }
      }
      if (ImGui::CollapsingHeader("Adaptive map", mDocument.Adaptive() ? ImGuiTreeNodeFlags_DefaultOpen : ImGuiTreeNodeFlags_None)) {
        ImGui::PushID("adaptive");
        DrawAdaptivePanel();
        ImGui::PopID();
      }
    }
    ImGui::End();
  }

  void EdShell::DrawSaveAsDialog()
  {
    constexpr const char* kTitle = "Save as new map folder";
    if (mOpenSaveAs) {
      mOpenSaveAs = false;
      if (mDocument.GetState() != EdDocument::State::Open) {
        gpg::Warnf("editor: open a map first");
        return;
      }
      (void)std::snprintf(mSaveAsName, sizeof(mSaveAsName), "%s", mDocument.NextVersionFolder().c_str());
      ImGui::OpenPopup(kTitle);
    }
    if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
      return;
    }
    ImGui::TextUnformatted("The new folder goes into your vault's maps folder:");
    ImGui::TextDisabled("%s", (mDocument.VaultFolder() / "maps").string().c_str());
    ImGui::SetNextItemWidth(420.0f);
    const bool enter = ImGui::InputText("Folder", mSaveAsName, sizeof(mSaveAsName), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::TextDisabled("FAF names map folders name.vNNNN; the files take the name without the version.");
    if (ImGui::Button("Save", ImVec2(120.0f, 0.0f)) || enter) {
      std::string message;
      if (mDocument.SaveAsNewFolder(mSaveAsName, message)) {
        gpg::Logf("editor: %s", message.c_str());
        ImGui::CloseCurrentPopup();
      } else {
        gpg::Warnf("editor: %s", message.c_str());
      }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120.0f, 0.0f)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  namespace
  {
    /** The folder FAF would give a map of this title: lower case, letters and digits, `_` between words, `.v0001`. */
    std::string FolderForTitle(const char* const title)
    {
      std::string folder;
      for (const char* c = title; *c != '\0'; ++c) {
        const unsigned char ch = static_cast<unsigned char>(*c);
        if (std::isalnum(ch) != 0) {
          folder += static_cast<char>(std::tolower(ch));
        } else if (!folder.empty() && folder.back() != '_') {
          folder += '_';
        }
      }
      while (!folder.empty() && folder.back() == '_') {
        folder.pop_back();
      }
      return (folder.empty() ? std::string("new_map") : folder) + ".v0001";
    }
  } // namespace

  void EdShell::DrawNewMapDialog()
  {
    constexpr const char* kTitle = "New map";
    if (mOpenNewMap) {
      mOpenNewMap = false;
      mNewMap = NewMapSettings{};
      (void)std::snprintf(mNewMapTitle, sizeof(mNewMapTitle), "%s", mNewMap.title.c_str());
      (void)std::snprintf(mNewMapFolder, sizeof(mNewMapFolder), "%s", FolderForTitle(mNewMapTitle).c_str());
      mNewMapFolderEdited = false;
      ImGui::OpenPopup(kTitle);
    }
    if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
      return;
    }
    constexpr float kWidth = 300.0f;
    ImGui::SetNextItemWidth(kWidth);
    if (ImGui::InputText("Title", mNewMapTitle, sizeof(mNewMapTitle)) && !mNewMapFolderEdited) {
      (void)std::snprintf(mNewMapFolder, sizeof(mNewMapFolder), "%s", FolderForTitle(mNewMapTitle).c_str());
    }
    ImGui::SetNextItemWidth(kWidth);
    if (ImGui::InputText("Folder", mNewMapFolder, sizeof(mNewMapFolder))) {
      mNewMapFolderEdited = true;
    }
    ImGui::TextDisabled("In %s", (mDocument.VaultFolder() / "maps").string().c_str());
    ImGui::Separator();
    ImGui::TextUnformatted("Type");
    ImGui::SameLine(110.0f);
    if (ImGui::RadioButton("Skirmish", !mNewMap.campaign)) {
      mNewMap.campaign = false;
    }
    ImGui::SameLine();
    if (ImGui::RadioButton("Campaign", mNewMap.campaign)) {
      mNewMap.campaign = true;
    }
    ImGui::TextUnformatted("Size");
    ImGui::SameLine(110.0f);
    for (int i = 0; i < kNewMapSizeCount; ++i) {
      if (i > 0) {
        ImGui::SameLine();
      }
      if (ImGui::RadioButton(kNewMapSizes[i].name, mNewMap.size == i)) {
        mNewMap.size = i;
      }
    }
    ImGui::SetNextItemWidth(kWidth);
    ImGui::SliderInt("Players", &mNewMap.players, 1, kNewMapMaxPlayers);
    ImGui::SetNextItemWidth(kWidth);
    ImGui::DragFloat("Ground height", &mNewMap.height, 0.25f, 0.0f, 500.0f, "%.1f");
    ImGui::Checkbox("Sea", &mNewMap.sea);
    if (mNewMap.sea) {
      ImGui::SameLine();
      ImGui::SetNextItemWidth(kWidth - 60.0f);
      ImGui::DragFloat("Sea level", &mNewMap.seaLevel, 0.25f, 0.0f, 500.0f, "%.1f");
    }
    ImGui::TextDisabled("Start positions ARMY_1 to ARMY_%d in a ring; ARMY_17 and NEUTRAL_CIVILIAN as extra armies.", mNewMap.players);
    ImGui::Separator();
    if (ImGui::Button("Create", ImVec2(120.0f, 0.0f))) {
      mNewMap.title = mNewMapTitle;
      mNewMap.folder = mNewMapFolder;
      std::string message;
      if (mDocument.CreateNew(mNewMap, message)) {
        gpg::Logf("editor: %s", message.c_str());
        ImGui::CloseCurrentPopup();
      } else {
        gpg::Warnf("editor: %s", message.c_str());
      }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(120.0f, 0.0f)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  void EdShell::DrawPackageDialog()
  {
    constexpr const char* kTitle = "Package for the FAF vault";
    if (mOpenPackage) {
      mOpenPackage = false;
      if (mDocument.GetState() != EdDocument::State::Open) {
        gpg::Warnf("editor: open a map first");
        return;
      }
      mPackagePlan = mDocument.PlanPackage();
      mPackageMessage.clear();
      ImGui::OpenPopup(kTitle);
    }
    if (!ImGui::BeginPopupModal(kTitle, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
      return;
    }
    ImGui::Text("%s", mPackagePlan.folder.empty() ? "(no folder)" : mPackagePlan.folder.c_str());
    ImGui::TextDisabled("A zip with this folder at its top, as the vault takes maps: %s",
                        (mDocument.VaultFolder() / "packages" / (mPackagePlan.folder + ".zip")).string().c_str());
    ImGui::Separator();
    for (const std::string& error : mPackagePlan.errors) {
      ImGui::TextColored(ImVec4(0.95f, 0.40f, 0.35f, 1.0f), "error: %s", error.c_str());
    }
    for (const std::string& warning : mPackagePlan.warnings) {
      ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "warning: %s", warning.c_str());
    }
    if (mPackagePlan.errors.empty() && mPackagePlan.warnings.empty()) {
      ImGui::TextColored(ImVec4(0.55f, 0.80f, 0.55f, 1.0f), "The folder's name, version and scenario paths are as the vault wants them.");
    }
    ImGui::TextDisabled("%zu files go in:", mPackagePlan.files.size());
    if (ImGui::BeginChild("##packagefiles", ImVec2(520.0f, ImGui::GetTextLineHeightWithSpacing() * 7.0f), ImGuiChildFlags_Borders)) {
      for (const std::string& file : mPackagePlan.files) {
        ImGui::TextUnformatted(file.c_str());
      }
    }
    ImGui::EndChild();
    ImGui::BeginDisabled(!mPackagePlan.errors.empty());
    if (ImGui::Button("Package", ImVec2(120.0f, 0.0f))) {
      std::filesystem::path written;
      const bool ok = mDocument.WritePackage(mPackagePlan, written, mPackageMessage);
      (ok ? gpg::Logf : gpg::Warnf)("editor: %s", mPackageMessage.c_str());
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Close", ImVec2(120.0f, 0.0f)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      ImGui::CloseCurrentPopup();
    }
    if (!mPackageMessage.empty()) {
      ImGui::TextWrapped("%s", mPackageMessage.c_str());
    }
    ImGui::TextDisabled("Uploading to the vault is done in the FAF client (or its website) for now.");
    ImGui::EndPopup();
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
      if (!mTools.CursorText().empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", mTools.CursorText().c_str());
      }
      if (!mTools.RulerText().empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.86f, 0.40f, 1.0f), "| ruler %s", mTools.RulerText().c_str());
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
