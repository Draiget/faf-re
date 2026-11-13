#include "editor/EdShell.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdFonts.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdCommands.h"
#include "editor/ui/EdPalette.h"
#include "editor/ui/EdTitleBar.h"
#include "editor/ui/EdUiScale.h"
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
#include "editor/EdLuaDebugger.h"
#include "editor/ui/EdProblems.h"
#include "editor/ui/EdStatus.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/ui/EdWorkspaces.h"
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

    const ImVec4 kPlayGreen(0.24f, 0.55f, 0.28f, 1.0f);
    const ImVec4 kStopRed(0.62f, 0.22f, 0.20f, 1.0f);
  } // namespace

  EdShell::EdShell(
    EdLog& log,
    EdPlay& play,
    EdDocument& document
  )
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

  namespace
  {
    // The panels' scales the toolbar's - and + (and Ctrl+- / Ctrl+=) step between.
    constexpr float kUiScaleSteps[] = {0.75f, 0.85f, 1.0f, 1.1f, 1.25f, 1.4f, 1.6f, 1.8f, 2.0f};
  } // namespace

  void EdShell::StepUiScale(
    const int direction
  )
  {
    if (direction == 0) {
      mUiScale = 1.0f;
      return;
    }
    float smaller = kUiScaleSteps[0];
    float larger = kUiScaleSteps[std::size(kUiScaleSteps) - 1];
    for (const float step : kUiScaleSteps) {
      smaller = step < mUiScale - 0.01f ? step : smaller;
    }
    for (auto it = std::rbegin(kUiScaleSteps); it != std::rend(kUiScaleSteps); ++it) {
      larger = *it > mUiScale + 0.01f ? *it : larger;
    }
    mUiScale = direction < 0 ? smaller : larger;
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
        // The warnings logged meanwhile: Lua errors (their text names a .lua file) first, the map's own files as
        // errors.
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
        std::stable_sort(mTestRunIssues.begin(), mTestRunIssues.end(), [](const CheckIssue& a, const CheckIssue& b) {
          return static_cast<int>(a.level) < static_cast<int>(b.level);
        });
        int counts[3] = {0, 0, 0};
        for (const CheckIssue& issue : mTestRunIssues) {
          ++counts[static_cast<int>(issue.level)];
        }
        gpg::Logf(
          "editor: test run done: %d errors (the map's files), %d warnings (other Lua), %d notes",
          counts[0],
          counts[1],
          counts[2]
        );
        mTestRunSummary = "Last test run: " + std::to_string(counts[0]) + " errors, " + std::to_string(counts[1]) +
          " warnings, " + std::to_string(counts[2]) + " notes";
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
    UpdateTestRun();
    mBrowser.Update();
    const bool playing = mPlay.Active();
    const bool panels = !playing || mPanelsWhilePlaying;

    // The dock space over the window. Its middle stays empty: the game's viewport is put over it (EdApp.cpp), so
    // the game's picture and input are there, inside the panels.
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const float statusHeight = StatusBarHeight();
    const float toolbarHeight = std::round(Em(38.0f));
    // The first frame: the first workspace's panels' saved places under the names their tabs have now.
    if (!mPanelPlacesCarried) {
      mPanelPlacesCarried = true;
      CarryPanelPlaces();
    }
    // The title row first (the editor draws its own: map name, menus, search, the window's buttons), always, also
    // while a play runs, so the window can be moved and closed.
    float titleHeight = 0.0f;
    if (mCommands != nullptr && mMenus != nullptr) {
      EdTitleInfo info;
      if (mDocument.GetState() == EdDocument::State::Open) {
        // The map's own title (as the game's list has it), else its folder.
        info.document = mDocument.FolderName();
        const std::vector<std::string>& maps = mPlay.Maps();
        for (std::size_t i = 0; i < maps.size() && i < mPlay.Titles().size(); ++i) {
          if (_stricmp(maps[i].c_str(), mDocument.Path().c_str()) == 0) {
            info.document = mPlay.Titles()[i];
            break;
          }
        }
        info.modified = mDocument.Modified();
      } else if (mDocument.GetState() == EdDocument::State::Loading) {
        info.document = "Opening a map...";
      } else {
        info.document = "FAF Map Editor";
      }
      if (playing) {
        info.state = mPlay.StateText();
      }
      for (std::size_t i = 0; i < Workspaces().size(); ++i) {
        const EdWorkspace& workspace = Workspaces()[i];
        EdTitleInfo::Tab tab;
        tab.command = "workspace." + std::to_string(i);
        tab.label = workspace.name;
        const char* const icon = WorkspaceIcon(workspace.key);
        tab.icon = icon != nullptr ? icon : "";
        tab.keys = workspace.keys;
        tab.about = workspace.about;
        // The mockup's groups: making the map (Terrain to Mission), its assets (Effects to Materials), Review.
        tab.groupStart = std::string_view(workspace.key) == "effects" || std::string_view(workspace.key) == "review";
        info.tabs.push_back(std::move(tab));
      }
      info.activeTab = ActiveWorkspace();
      titleHeight = DrawTitleBar(*mCommands, *mMenus, info, [] {
        OpenCommandPalette();
      });
      DrawCommandPalette(*mCommands);
    }
    DrawToolbar(toolbarHeight, titleHeight);
    const float top = titleHeight + toolbarHeight;
    // The tool strip down the window's left edge (the mockup's), the panels and the view beside it.
    const float stripWidth = panels ? std::round(Em(40.0f)) : 0.0f;
    if (stripWidth > 0.0f) {
      DrawToolStrip(top, stripWidth, statusHeight);
    }
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x + stripWidth, viewport->WorkPos.y + top));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x - stripWidth, viewport->WorkSize.y - statusHeight - top));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kHostFlags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
      ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
      ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoBackground;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("##EditorDockHost", nullptr, kHostFlags);
    ImGui::PopStyleVar(3);
    // The workspace's own dock space: laid out from its EdWorkspace the first time (no layout saved for it), or on
    // Reset layout. The panels it showed last, at the start (layout.ini has them by then).
    if (!mWorkspaceStarted) {
      mWorkspaceStarted = true;
      const auto saved = ShownPanels().find(Workspaces()[static_cast<std::size_t>(ActiveWorkspace())].key);
      ShowPanels(saved != ShownPanels().end() ? saved->second : DefaultPanels(ActiveWorkspace()));
      mTools.SetReadOnly(Workspaces()[static_cast<std::size_t>(ActiveWorkspace())].readOnly);
    }
    const int workspace = ActiveWorkspace();
    if (mWorkspaceBuilt.size() < Workspaces().size()) {
      mWorkspaceBuilt.resize(Workspaces().size(), false);
    }
    const ImGuiID dockspaceId = ImGui::GetID(DockSpaceName(workspace).c_str());
    if (!mWorkspaceBuilt[static_cast<std::size_t>(workspace)] || mResetLayout) {
      if (mResetLayout || ImGui::DockBuilderGetNode(dockspaceId) == nullptr) {
        BuildDefaultLayout(dockspaceId);
        if (mResetLayout) {
          ShowPanels(DefaultPanels(workspace));
        }
      }
      mWorkspaceBuilt[static_cast<std::size_t>(workspace)] = true;
      mLayoutBuilt = true;
      mResetLayout = false;
    }
    // The panels' tab titles with room around them (ImGui lays out a dock node's tab bar with the frame padding,
    // 4 x 3 px by default, which crowds the titles).
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(Em(9.0f), Em(5.0f)));
    ImGui::DockSpace(dockspaceId, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_PassthruCentralNode);
    ImGui::PopStyleVar();
    // A layout saved before the Properties panel existed: the panel goes under the Tools panel, once (the first
    // workspace's windows are the ones from before workspaces).
    if (!mPropertiesPlaced && workspace == 0) {
      if (const ImGuiWindow* const tools = ImGui::FindWindowByName(Panel(kToolsWindow)); tools != nullptr) {
        mPropertiesPlaced = true;
        if (
          ImGui::FindWindowSettingsByID(ImHashStr(PanelWindowName("Properties", 0).c_str())) == nullptr &&
          tools->DockId != 0
        ) {
          ImGuiID top = 0;
          ImGuiID bottom = 0;
          ImGui::DockBuilderSplitNode(tools->DockId, ImGuiDir_Down, 0.42f, &bottom, &top);
          ImGui::DockBuilderDockWindow(PanelWindowName("Properties", 0).c_str(), bottom);
          ImGui::DockBuilderFinish(dockspaceId);
        }
      }
    }
    if (const ImGuiDockNode* const middle = ImGui::DockBuilderGetCentralNode(dockspaceId); middle != nullptr) {
      mGameView =
        ImVec4(middle->Pos.x - viewport->Pos.x, middle->Pos.y - viewport->Pos.y, middle->Size.x, middle->Size.y);
    }
    ImGui::End();
    DrawEffectStage();
    // The panels shown now are the workspace's to keep (layout.ini, [FafEditor][Ui] Panels.<key>=).
    {
      std::vector<std::string>& kept = ShownPanels()[Workspaces()[static_cast<std::size_t>(workspace)].key];
      std::vector<std::string> now = ShownPanelIds();
      if (kept != now) {
        kept = std::move(now);
        ImGui::MarkIniSettingsDirty();
      }
    }

    // The map is up but its props and units aren't yet (they wait for the game's blueprints): said at the view's top,
    // with a spinner and the time so far, so a map without its trees and wrecks isn't taken for finished (user report).
    {
      static double loadingSince = -1.0;
      if (mTools.ModelsLoading() && (!playing || mEditorViewInPlay)) {
        const double now = ImGui::GetTime();
        if (loadingSince < 0.0) {
          loadingSince = now;
        }
        // In front of a play the view draws them with the play's own rules (WPE.51), so this is the same short wait.
        char text[200];
        (void)std::snprintf(
          text,
          sizeof(text),
          "Loading models: trees, rocks, wrecks and units appear when the game's blueprints are ready (%.0f s)",
          now - loadingSince
        );
        ImDrawList* const dl = ImGui::GetForegroundDrawList();
        const ImVec2 size = ImGui::CalcTextSize(text);
        const float pad = 8.0f;
        const float spinner = size.y;
        const float width = spinner + pad * 3.0f + size.x;
        const ImVec2 at(
          viewport->Pos.x + mGameView.x + (mGameView.z - width) * 0.5f, viewport->Pos.y + mGameView.y + 12.0f
        );
        dl->AddRectFilled(at, ImVec2(at.x + width, at.y + size.y + pad * 2.0f), IM_COL32(20, 22, 28, 225), 6.0f);
        dl->AddRect(at, ImVec2(at.x + width, at.y + size.y + pad * 2.0f), IM_COL32(240, 180, 70, 200), 6.0f);
        // A turning arc.
        const ImVec2 centre(at.x + pad + spinner * 0.5f, at.y + pad + spinner * 0.5f);
        const float start = static_cast<float>(now * 6.0);
        dl->PathArcTo(centre, spinner * 0.42f, start, start + 4.2f, 20);
        dl->PathStroke(IM_COL32(240, 180, 70, 255), 0, 2.5f);
        dl->AddText(ImVec2(at.x + pad * 2.0f + spinner, at.y + pad), IM_COL32(235, 235, 235, 255), text);
      } else {
        if (loadingSince >= 0.0 && !playing) {
          gpg::Logf(
            "editor: the map's models were loading for %.1f s (the view said so)", ImGui::GetTime() - loadingSince
          );
        }
        loadingSince = -1.0;
      }
    }

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
      if (mShowHistory) {
        DrawHistoryPanel();
      }
      if (mShowProblems) {
        DrawProblemsPanel();
      }
      // The debugger's pause brings its panel up, whether shown or not.
      if (mShowDebugger || EdLuaDebugger::Get().Snapshot().paused) {
        mShowDebugger = true;
        DrawDebuggerPanel();
      }
      if (mShowLog) {
        if (ImGui::Begin(Panel(kLogWindow), &mShowLog)) {
          mLog.Draw();
        }
        ImGui::End();
      }
    }
    if (mShowDemo) {
      ImGui::ShowDemoWindow(&mShowDemo);
    }
    // The view's overlays: a map open, its view showing (not the start screen, not the effect or material stage).
    {
      mTools.SetMinimapRect(0.0f, 0.0f, 0.0f, 0.0f);
      const std::string key = Workspaces()[static_cast<std::size_t>(ActiveWorkspace())].key;
      const bool stage = key == "effects" || key == "materials";
      if (
        panels && !mShowHome && !stage && mDocument.GetState() == EdDocument::State::Open &&
        (!playing || mEditorViewInPlay) && mGameView.z > Em(320.0f) && mGameView.w > Em(200.0f)
      ) {
        DrawViewOverlays();
      }
    }
    DrawSaveAsDialog();
    DrawHome(top, statusHeight);
    DrawHelpWindow();
    DrawTour();
    DrawNewMapDialog();
    DrawPackageDialog();
    DrawStatusBar();
  }

  void EdShell::BuildDefaultLayout(
    const unsigned int dockspaceId
  )
  {
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const EdWorkspace& w = Workspaces()[static_cast<std::size_t>(ActiveWorkspace())];
    ImGui::DockBuilderRemoveNode(dockspaceId);
    ImGui::DockBuilderAddNode(dockspaceId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspaceId, viewport->WorkSize);
    const auto dock = [](const char* const list, const ImGuiID node) {
      for (const std::string& panel : SplitPanelList(list)) {
        ImGui::DockBuilderDockWindow(PanelWindowName(panel, ActiveWorkspace()).c_str(), node);
      }
    };
    // Left and right columns (each split in two when the workspace has a lower part), then the bottom row under the
    // middle; what is left in the middle is the view.
    ImGuiID center = dockspaceId;
    if (w.leftWidth > 0.0f && (w.left[0] != 0 || w.leftBottom[0] != 0)) {
      ImGuiID left = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, w.leftWidth, nullptr, &center);
      if (w.leftBottom[0] != 0 && w.left[0] != 0) {
        const ImGuiID lower = ImGui::DockBuilderSplitNode(left, ImGuiDir_Down, 0.42f, nullptr, &left);
        dock(w.leftBottom, lower);
      } else if (w.leftBottom[0] != 0) {
        dock(w.leftBottom, left);
      }
      dock(w.left, left);
    }
    if (w.right[0] != 0 || w.rightBottom[0] != 0) {
      ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, w.rightWidth, nullptr, &center);
      if (w.rightBottom[0] != 0 && w.right[0] != 0) {
        const ImGuiID lower = ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.40f, nullptr, &right);
        dock(w.rightBottom, lower);
      } else if (w.rightBottom[0] != 0) {
        dock(w.rightBottom, right);
      }
      dock(w.right, right);
    }
    if (w.bottom[0] != 0) {
      const ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.22f, nullptr, &center);
      dock(w.bottom, bottom);
    }
    ImGui::DockBuilderFinish(dockspaceId);
    gpg::Logf("editor: workspace %s laid out", w.name);
  }

  void EdShell::DrawEffectStage()
  {
    // The Effects workspace: the effect's own view in the map view's place (design §4), while the particle editor or
    // browser is shown and no play runs.
    const std::string key = Workspaces()[static_cast<std::size_t>(ActiveWorkspace())].key;
    const bool free = !mPlay.Active() && !mShowHome;
    const bool effects = key == "effects" && (mShowParticleEditor || mShowParticleBrowser) && free;
    // The Materials workspace likewise: the material's preview there.
    const bool materials = key == "materials" && mShowMaterialEditor && free;
    mParticleEditor.SetStaged(effects);
    mMaterialEditor.SetStaged(materials);
    if ((!effects && !materials) || mGameView.z < 64.0f || mGameView.w < 64.0f) {
      return;
    }
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x + mGameView.x, viewport->Pos.y + mGameView.y));
    ImGui::SetNextWindowSize(ImVec2(mGameView.z, mGameView.w));
    // A floating window (not NoBringToFrontOnFocus), so the game's view is cut out under it.
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar |
      ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    if (ImGui::Begin("Stage###EffectStage", nullptr, kFlags)) {
      if (effects) {
        mParticleEditor.DrawStage();
      } else {
        mMaterialEditor.DrawStage();
      }
    }
    ImGui::End();
    ImGui::PopStyleVar(2);
  }

  const std::vector<EdShell::PanelFlag>& EdShell::PanelFlags()
  {
    static const std::vector<PanelFlag> kFlags = {
      {kToolsWindow, &EdShell::mShowTools},
      {"Properties", &EdShell::mShowProperties},
      {kMapWindow, &EdShell::mShowMap},
      {kInfoWindow, &EdShell::mShowInfo},
      {kMarkersWindow, &EdShell::mShowMarkers},
      {kCheckWindow, &EdShell::mShowCheck},
      {"Armies", &EdShell::mShowArmies},
      {"Lighting", &EdShell::mShowLighting},
      {"Script Editor###ScriptEditor", &EdShell::mShowScript},
      {"Adaptive Map###AdaptiveMap", &EdShell::mShowAdaptiveWindow},
      {"Material Editor", &EdShell::mShowMaterialEditor},
      {"Particle Editor", &EdShell::mShowParticleEditor},
      {"Particle Browser", &EdShell::mShowParticleBrowser},
      {kLogWindow, &EdShell::mShowLog},
      {"History", &EdShell::mShowHistory},
      {"Problems", &EdShell::mShowProblems},
      {"Debugger", &EdShell::mShowDebugger},
    };
    return kFlags;
  }

  std::vector<std::string> EdShell::ShownPanelIds() const
  {
    std::vector<std::string> out;
    for (const PanelFlag& flag : PanelFlags()) {
      if (this->*flag.shown) {
        out.push_back(PanelId(flag.window));
      }
    }
    return out;
  }

  void EdShell::ShowPanels(
    const std::vector<std::string>& ids
  )
  {
    for (const PanelFlag& flag : PanelFlags()) {
      this->*flag.shown = std::find(ids.begin(), ids.end(), PanelId(flag.window)) != ids.end();
    }
  }

  void EdShell::SwitchWorkspace(
    const int workspace
  )
  {
    mShowHome = false;
    if (workspace < 0 || workspace >= static_cast<int>(Workspaces().size()) || workspace == ActiveWorkspace()) {
      return;
    }
    ShownPanels()[Workspaces()[static_cast<std::size_t>(ActiveWorkspace())].key] = ShownPanelIds();
    SetActiveWorkspace(workspace);
    const EdWorkspace& w = Workspaces()[static_cast<std::size_t>(workspace)];
    const auto saved = ShownPanels().find(w.key);
    ShowPanels(saved != ShownPanels().end() ? saved->second : DefaultPanels(workspace));
    mTools.SetReadOnly(w.readOnly);
    ImGui::MarkIniSettingsDirty();
    gpg::Logf("editor: workspace %s", w.name);
    PostStatusMessage(std::string(w.name) + " workspace");
  }

  void EdShell::DrawToolbar(
    const float height,
    const float top
  )
  {
    // The mockup's toolbar (styles.css .toolbar): flat buttons (an icon, maybe a word) in groups with thin rules
    // between them; a pressed toggle in the accent's soft fill and colour; Play in green.
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + top));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
      ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoScrollbar;
    const float buttonHeight = std::round(Em(26.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(7.0f), std::round((height - buttonHeight) * 0.5f)));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, Em(4.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(Em(2.0f), 0.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
    if (ImGui::Begin("##Toolbar", nullptr, kFlags)) {
      const bool playing = mPlay.Active();
      const bool open = mDocument.GetState() == EdDocument::State::Open;
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      ImFont* const font = ImGui::GetFont();
      const float fontSize = ImGui::GetFontSize();
      const ImVec4 text = ImGui::GetStyleColorVec4(ImGuiCol_Text);
      const ImVec4 dim = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
      // The mockup's text-1: the toolbar's words, between the bright and the dimmed text.
      const ImU32 ink1 = ImGui::GetColorU32(
        ImVec4((text.x * 2.0f + dim.x) / 3.0f, (text.y * 2.0f + dim.y) / 3.0f, (text.z * 2.0f + dim.z) / 3.0f, 1.0f)
      );
      {
        // The line under the toolbar.
        const ImVec2 at = ImGui::GetWindowPos();
        const ImVec2 size = ImGui::GetWindowSize();
        draw->AddLine(
          ImVec2(at.x, at.y + size.y - 0.5f),
          ImVec2(at.x + size.x, at.y + size.y - 0.5f),
          ImGui::GetColorU32(ImGuiCol_Border)
        );
      }
      const auto tip = [](const char* const words) {
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayShort)) {
          ImGui::SetTooltip("%s", words);
        }
      };
      const auto withAlpha = [](const ImU32 colour, const float alpha) {
        const auto a = static_cast<ImU32>(static_cast<float>((colour >> IM_COL32_A_SHIFT) & 0xFFU) * alpha);
        return (colour & ~IM_COL32_A_MASK) | (a << IM_COL32_A_SHIFT);
      };
      // A flat button: its icon, then its word if any. `pressed` (toggles) fills it with the accent's soft colour.
      const auto button = [&](
                            const char* const id,
                            const char* const icon,
                            const char* const label,
                            const bool pressed = false,
                            const bool enabled = true,
                            const float inkAlpha = 1.0f
                          ) {
        const ImVec2 iconSize = icon != nullptr ? ImGui::CalcTextSize(icon) : ImVec2(0.0f, 0.0f);
        const ImVec2 labelSize = label != nullptr ? ImGui::CalcTextSize(label) : ImVec2(0.0f, 0.0f);
        const float pad = label != nullptr ? Em(8.0f) : Em(6.0f);
        const float gap = icon != nullptr && label != nullptr ? Em(5.0f) : 0.0f;
        const float width = std::round(std::max(buttonHeight, pad * 2.0f + iconSize.x + gap + labelSize.x));
        const ImVec2 at = ImGui::GetCursorScreenPos();
        ImGui::PushID(id);
        const bool clicked = ImGui::InvisibleButton("##tb", ImVec2(width, buttonHeight)) && enabled;
        const bool hovered = enabled && ImGui::IsItemHovered();
        const bool held = enabled && ImGui::IsItemActive();
        ImGui::PopID();
        const ImVec2 end(at.x + width, at.y + buttonHeight);
        if (pressed) {
          draw->AddRectFilled(at, end, AccentU32(held ? 0.30f : hovered ? 0.24f : 0.16f), Em(4.0f));
        } else if (hovered) {
          draw->AddRectFilled(at, end, ImGui::GetColorU32(held ? ImGuiCol_ButtonHovered : ImGuiCol_Button), Em(4.0f));
        }
        ImU32 ink = pressed ? AccentU32() : hovered ? ImGui::GetColorU32(ImGuiCol_Text) : ink1;
        if (!enabled) {
          ink = withAlpha(ink, 0.4f);
        } else if (inkAlpha < 1.0f && !hovered) {
          ink = withAlpha(ink, inkAlpha);
        }
        float x = at.x + (label != nullptr ? pad : (width - iconSize.x) * 0.5f);
        // Segoe UI's capitals centre 0.55 of the size below the line's top: that point on the button's middle.
        const float y = std::round(at.y + buttonHeight * 0.5f - fontSize * 0.55f);
        if (icon != nullptr) {
          draw->AddText(ImVec2(std::round(x), std::round(y)), ink, icon);
          x += iconSize.x + gap;
        }
        if (label != nullptr) {
          draw->AddText(ImVec2(std::round(x), std::round(y)), ink, label);
        }
        ImGui::SameLine();
        return clicked;
      };
      // The rule between groups (the mockup's .tb-group border).
      const auto group = [&] {
        ImGui::SameLine(0.0f, Em(5.0f));
        const ImVec2 at = ImGui::GetCursorScreenPos();
        const float x = std::round(at.x) + 0.5f;
        draw->AddLine(
          ImVec2(x, at.y + Em(4.0f)),
          ImVec2(x, at.y + buttonHeight - Em(4.0f)),
          ImGui::GetColorU32(ImGuiCol_TableBorderLight)
        );
        ImGui::Dummy(ImVec2(1.0f, buttonHeight));
        ImGui::SameLine(0.0f, Em(5.0f));
      };

      // Play / Stop: the mockup's green (red to stop) with dark words, the key beside them; the setup at its side.
      {
        const ImU32 base = playing ? IM_COL32(0xFF, 0x5D, 0x5D, 0xFF) : IM_COL32(0x3F, 0xCF, 0x7A, 0xFF);
        const ImU32 onBase = playing ? IM_COL32(0x2A, 0x06, 0x06, 0xFF) : IM_COL32(0x06, 0x21, 0x0F, 0xFF);
        const bool canPlay = playing || mPlay.CanPlay();
        const char* const icon = playing ? ICON_STOP : ICON_PLAY;
        const char* const word = playing ? "Stop" : "Play";
        const ImVec2 iconSize = ImGui::CalcTextSize(icon);
        const ImVec2 wordSize = ImGui::CalcTextSize(word);
        const float pad = Em(11.0f);
        const float keyFont = fontSize * 0.85f;
        const ImVec2 keyText = font->CalcTextSizeA(keyFont, FLT_MAX, 0.0f, "F5");
        const float capWidth = std::round(keyText.x + Em(10.0f));
        // The same room at both ends (the cap ended nearer the edge than the icon began).
        const float width = std::round(
          pad - std::round(iconSize.y * 7.0f / 24.0f * 0.8f) + iconSize.x + Em(6.0f) + wordSize.x + Em(9.0f) +
          capWidth + pad
        );
        const ImVec2 at = ImGui::GetCursorScreenPos();
        const bool clicked = ImGui::InvisibleButton("##playstop", ImVec2(width, buttonHeight)) && canPlay;
        const bool hovered = canPlay && ImGui::IsItemHovered();
        tip(playing ? "Stop the session and go back to editing (F5)" : "Play the map picked in the Map panel (F5)");
        ImGui::SameLine(0.0f, 0.0f);
        const float splitWidth = std::round(Em(22.0f));
        const ImVec2 splitAt = ImGui::GetCursorScreenPos();
        if (ImGui::InvisibleButton("##playsetup", ImVec2(splitWidth, buttonHeight))) {
          ImGui::OpenPopup("##playsetuppopup");
        }
        const bool splitHovered = ImGui::IsItemHovered();
        tip(
          "Play options: start slot, faction, AI opponents, fog, prebuilt units; while playing, hide the fog or watch "
          "as an observer"
        );
        // One green shape, the split a step lighter when hovered, a thin dark line between the halves.
        const float brighten = 1.08f;
        const auto lit = [&](const ImU32 colour, const bool on) {
          if (!on) {
            return colour;
          }
          ImVec4 c = ImGui::ColorConvertU32ToFloat4(colour);
          c.x = std::min(1.0f, c.x * brighten);
          c.y = std::min(1.0f, c.y * brighten);
          c.z = std::min(1.0f, c.z * brighten);
          return ImGui::ColorConvertFloat4ToU32(c);
        };
        const ImU32 shown = canPlay ? base : withAlpha(base, 0.45f);
        draw->AddRectFilled(
          at, ImVec2(at.x + width, at.y + buttonHeight), lit(shown, hovered), Em(4.0f), ImDrawFlags_RoundCornersLeft
        );
        draw->AddRectFilled(
          splitAt,
          ImVec2(splitAt.x + splitWidth, splitAt.y + buttonHeight),
          lit(base, splitHovered),
          Em(4.0f),
          ImDrawFlags_RoundCornersRight
        );
        draw->AddLine(
          ImVec2(splitAt.x + 0.5f, splitAt.y), ImVec2(splitAt.x + 0.5f, splitAt.y + buttonHeight), IM_COL32(0, 0, 0, 46)
        );
        const float y = std::round(at.y + buttonHeight * 0.5f - fontSize * 0.55f);
        // The play glyph has empty space at its left (7 of 24 units): it counts toward the padding.
        float x = at.x + pad - std::round(iconSize.y * 7.0f / 24.0f * 0.8f);
        draw->AddText(ImVec2(x, y), onBase, icon);
        x += iconSize.x + Em(6.0f);
        if (gBoldFont != nullptr) {
          draw->AddText(gBoldFont, fontSize, ImVec2(x, y), onBase, word);
        } else {
          draw->AddText(ImVec2(x, y), onBase, word);
        }
        x += wordSize.x + Em(9.0f);
        // The key on an outlined cap, as the mockup's kbd.
        // The cap on the words' line (centred on their capitals, as the icon is), not on the button's middle.
        const float lineMid = y + fontSize * 0.55f;
        const float capHalf = std::round((buttonHeight - Em(10.0f)) * 0.5f);
        const ImVec2 capMin(std::round(x), std::round(lineMid - capHalf));
        const ImVec2 capMax(std::round(x + capWidth), std::round(lineMid + capHalf));
        draw->AddRect(capMin, capMax, IM_COL32(0, 0, 0, 64), Em(3.0f));
        // Its capitals on the cap's middle: at this smaller size they sit 0.63 of it below the line's top (measured
        // on a capture; 0.55 left them 1.3 px low).
        draw->AddText(
          font,
          keyFont,
          ImVec2(
            std::round(capMin.x + (capMax.x - capMin.x - keyText.x) * 0.5f),
            std::round((capMin.y + capMax.y) * 0.5f - keyFont * 0.63f)
          ),
          onBase,
          "F5"
        );
        const char* const chevron = ICON_CHEVRON;
        const ImVec2 chevronSize = ImGui::CalcTextSize(chevron);
        draw->AddText(ImVec2(std::round(splitAt.x + (splitWidth - chevronSize.x) * 0.5f), y), onBase, chevron);
        if (clicked) {
          if (playing) {
            mPlay.Stop();
          } else {
            mPlay.Play();
          }
        }
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
        ImGui::SameLine();
        // While a play runs: the editor's view or the game's (F6); the game runs on behind the editor's.
        if (playing) {
          ImGui::SameLine(0.0f, Em(6.0f));
          const bool editorView = mEditorViewInPlay;
          if (button("##view", ICON_REVIEW, editorView ? "Editor view" : "Game view", editorView)) {
            mEditorViewInPlay = !mEditorViewInPlay;
            gpg::Logf("editor: the toolbar: the %s view", mEditorViewInPlay ? "editor's" : "game's");
          }
          tip(
            editorView ? "The editor's view of the map, the play running on behind it: F6 for the game's view"
                       : "The game's view: F6 for the editor's view of the map (the play keeps running)"
          );
          if (editorView) {
            if (button("##gameunits", ICON_UNIT, "Game units", mTools.ShowGameUnits())) {
              mTools.ShowGameUnits() = !mTools.ShowGameUnits();
            }
            tip(
              "The play's own units in the editor's view: shown (click one to select it, drag to move it, change it "
              "in Properties) or hidden"
            );
          }
        }
      }
      group();

      // File.
      const std::vector<std::string>& maps = mPlay.Maps();
      if (button("##new", ICON_NEW, nullptr, false, !playing)) {
        mOpenNewMap = true;
      }
      tip("New map: size, players, height and sea (Ctrl+N)");
      if (
        button(
          "##open",
          ICON_OPEN,
          "Open",
          false,
          !playing && !maps.empty() && mDocument.GetState() != EdDocument::State::Loading
        )
      ) {
        mBrowser.Show();
      }
      tip("Browse maps: every map on this computer (the game's, FAF's folder, your vault) and maps from the FAF vault");
      if (button("##save", ICON_SAVE, "Save", false, !playing && open)) {
        mCommand = Command::Save;
      }
      tip("Save the map into its folder (Ctrl+S). Save as a new folder is in the File menu.");
      group();

      // Edit: Undo names its step, as the mockup's.
      {
        const bool canUndo = open && !playing && mDocument.CanUndo();
        std::string undo = "Undo";
        if (const char* const step = mDocument.UndoStepName(); canUndo && step != nullptr) {
          undo = std::string("Undo ") + step;
          if (undo.size() > 27) {
            undo = undo.substr(0, 26) + "...";
          }
        }
        if (button("##undo", ICON_UNDO, undo.c_str(), false, canUndo)) {
          mCommand = Command::Undo;
        }
        tip("Undo the last edit (Ctrl+Z)");
        if (button("##redo", ICON_REDO, nullptr, false, open && !playing && mDocument.CanRedo())) {
          mCommand = Command::Redo;
        }
        tip("Redo (Ctrl+Y)");
      }
      group();

      // Symmetry: the five common modes as pictures; all ten are in the Terrain tool's settings.
      {
        const float wordSize = std::round(fontSize * 0.85f);
        const ImVec2 word = font->CalcTextSizeA(wordSize, FLT_MAX, 0.0f, "Symmetry");
        const ImVec2 at = ImGui::GetCursorScreenPos();
        draw->AddText(
          font,
          wordSize,
          ImVec2(at.x + Em(2.0f), std::round(at.y + (buttonHeight - word.y) * 0.5f)),
          ImGui::GetColorU32(ImGuiCol_TextDisabled),
          "Symmetry"
        );
        ImGui::Dummy(ImVec2(word.x + Em(5.0f), buttonHeight));
        ImGui::SameLine(0.0f, 0.0f);
        static constexpr int kModes[] = {0, 1, 5, 6, 8};
        for (const int mode : kModes) {
          ImGui::PushID(mode);
          const ImVec2 p = ImGui::GetCursorScreenPos();
          const float side = buttonHeight;
          const bool on = mTools.SymmetryIndex() == mode;
          if (ImGui::InvisibleButton("##sym", ImVec2(side, side)) && !playing) {
            mTools.PickSymmetry(mode);
          }
          const bool hovered = ImGui::IsItemHovered();
          if (on) {
            draw->AddRectFilled(p, ImVec2(p.x + side, p.y + side), AccentU32(0.16f), Em(4.0f));
          } else if (hovered) {
            draw->AddRectFilled(p, ImVec2(p.x + side, p.y + side), ImGui::GetColorU32(ImGuiCol_Button), Em(4.0f));
          }
          const float picture = std::round(side * 0.92f);
          mTools.DrawSymmetryPicture(
            draw, mode, ImVec2(p.x + (side - picture) * 0.5f, p.y + (side - picture) * 0.5f), picture
          );
          if (hovered) {
            ImGui::SetTooltip(
              "Symmetry: %s\nAll ten modes are in the Terrain tool's settings", EdTools::SymmetryName(mode)
            );
          }
          ImGui::PopID();
          ImGui::SameLine();
        }
      }
      group();

      // Snapping to the build grid and its step, keeping things on the ground.
      // Grid and Slope change what the view shows: they are the view's pills (DrawViewOverlays), not here twice.
      if (button("##snap", ICON_MAGNET, "Snap", mTools.SnapToGrid())) {
        mTools.SetSnapToGrid(!mTools.SnapToGrid());
      }
      tip(
        "Markers and props placed or dragged go to the middle of a grid cell (mass and hydrocarbon points always sit "
        "on half units, as the game's saves place them)"
      );
      {
        static constexpr float kSteps[] = {0.5f, 1.0f, 2.0f, 4.0f, 8.0f};
        static constexpr const char* kStepNames[] = {"0.5", "1", "2", "4", "8"};
        int current = 1;
        for (int i = 0; i < 5; ++i) {
          if (mTools.GridStep() == kSteps[i]) {
            current = i;
          }
        }
        ImGui::SameLine(0.0f, Em(4.0f));
        const float framePad = std::max(0.0f, std::round((buttonHeight - fontSize) * 0.5f) - 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(Em(7.0f), framePad));
        ImGui::SetNextItemWidth(std::round(Em(52.0f)));
        const bool stepOpen = EdBeginCombo("##gridstep", kStepNames[current], ImGuiComboFlags_NoArrowButton);
        {
          // The mockup's select: the value and a small chevron at the right.
          const ImVec2 max = ImGui::GetItemRectMax();
          const ImVec2 min = ImGui::GetItemRectMin();
          const ImVec2 chevron = ImGui::CalcTextSize(ICON_CHEVRON);
          draw->AddText(
            ImVec2(std::round(max.x - chevron.x - Em(6.0f)), std::round((min.y + max.y - fontSize) * 0.5f)),
            ink1,
            ICON_CHEVRON
          );
        }
        if (stepOpen) {
          for (int i = 0; i < 5; ++i) {
            if (ImGui::Selectable(kStepNames[i], i == current)) {
              mTools.SetGridStep(kSteps[i]);
            }
          }
          ImGui::EndCombo();
        }
        ImGui::PopStyleVar();
        tip("The grid's step in game units");
        ImGui::SameLine(0.0f, Em(4.0f));
      }
      if (button("##onground", ICON_GROUND, "On ground", mTools.KeepOnGround())) {
        mTools.SetKeepOnGround(!mTools.KeepOnGround());
      }
      tip(
        "The move arrows keep markers and props on the ground when they move across it; off, they keep their height. "
        "Nothing is moved under the ground either way."
      );
      group();

      // What the view shows, one toggle per kind (Blender's object type visibility); hidden things aren't picked.
      if (button("##border", ICON_AREA, nullptr, mTools.EditingBorder())) {
        mTools.EditingBorder() = !mTools.EditingBorder();
        mShowProperties = mShowProperties || mTools.EditingBorder();
      }
      tip(
        mTools.EditingBorder() ? "Map border: on. Drag its edges in the view; its settings are in the Properties panel"
                               : "Map border (the playable area): edit it from any tool"
      );
      // At the right: Check and Release, then the panels' scale.
      const float scaleWidth = DrawUiScaleButtons(true);
      const auto width = [&](const char* const icon, const char* const label) {
        return std::round(Em(16.0f) + ImGui::CalcTextSize(icon).x + Em(5.0f) + ImGui::CalcTextSize(label).x);
      };
      const float rightWidth =
        width(ICON_OK, "Check") + width(ICON_PACKAGE, "Release") + Em(2.0f) + Em(11.0f) + 1.0f + scaleWidth;
      ImGui::SameLine(
        std::max(
          ImGui::GetCursorPosX() + Em(10.0f), ImGui::GetWindowWidth() - rightWidth - ImGui::GetStyle().WindowPadding.x
        )
      );
      if (button("##check", ICON_OK, "Check", false, open)) {
        mShowCheck = true;
        mRunCheck = true;
      }
      tip("Run the map check and show its findings in the Check panel");
      if (button("##release", ICON_PACKAGE, "Release", false, open && !playing) && mCommands != nullptr) {
        (void)mCommands->Run("file.package");
      }
      tip("Package the map for the FAF vault");
      group();
      ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(Em(7.0f), std::round((buttonHeight - fontSize) * 0.5f)));
      (void)DrawUiScaleButtons(false);
      ImGui::PopStyleVar();
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(5);
  }

  float EdShell::DrawUiScaleButtons(
    const bool measure
  )
  {
    // The steps a click moves between; the middle button shows the scale and puts it back to 100%.
    const auto& kSteps = kUiScaleSteps;
    // One joined row, as the view's toggle groups: - | 100% | +, the ends square buttons.
    char percent[16];
    (void)std::snprintf(percent, sizeof(percent), "%d%%", static_cast<int>(std::lround(mUiScale * 100.0f)));
    const float side = ImGui::GetFrameHeight();
    const float middle = EdTextSegmentWidth("100%");
    if (measure) {
      return side * 2.0f + middle + 2.0f;
    }
    float smaller = kSteps[0];
    float larger = kSteps[std::size(kSteps) - 1];
    for (const float step : kSteps) {
      smaller = step < mUiScale - 0.01f ? step : smaller;
    }
    for (auto it = std::rbegin(kSteps); it != std::rend(kSteps); ++it) {
      larger = *it > mUiScale + 0.01f ? *it : larger;
    }
    if (EdTextSegment("##uiscaledown", "-", EdSegment::First, mUiScale > kSteps[0] + 0.01f, side)) {
      mUiScale = smaller;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayShort)) {
      ImGui::SetTooltip("Smaller panels and text");
    }
    ImGui::SameLine(0.0f, 1.0f);
    if (EdTextSegment("##uiscale", percent, EdSegment::Middle, true, middle)) {
      mUiScale = 1.0f;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
      ImGui::SetTooltip("The panels' scale (kept over restarts); click for 100%%");
    }
    ImGui::SameLine(0.0f, 1.0f);
    if (EdTextSegment("##uiscaleup", "+", EdSegment::Last, mUiScale < kSteps[std::size(kSteps) - 1] - 0.01f, side)) {
      mUiScale = larger;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayShort)) {
      ImGui::SetTooltip("Larger panels and text");
    }
    return 0.0f;
  }

  void EdShell::DrawToolStrip(
    const float top,
    const float width,
    const float bottom
  )
  {
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + top));
    ImGui::SetNextWindowSize(ImVec2(width, viewport->WorkSize.y - top - bottom));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
      ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, Em(7.0f)));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
    if (ImGui::Begin("##ToolStrip", nullptr, kFlags)) {
      const ImVec2 at = ImGui::GetWindowPos();
      const ImVec2 size = ImGui::GetWindowSize();
      ImGui::GetWindowDrawList()->AddLine(
        ImVec2(at.x + size.x - 0.5f, at.y),
        ImVec2(at.x + size.x - 0.5f, at.y + size.y),
        ImGui::GetColorU32(ImGuiCol_Border)
      );
      if (mTools.DrawStrip(width - 1.0f)) {
        mShowTools = true;
        mFocusTools = true;
      }
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(3);
  }

  void EdShell::DrawViewOverlays()
  {
    // The mockup's view overlays (styles.css .vp-header .pill-group, .vp-hud): dark see-through pill bars at the
    // view's top-left, the tool's line at its bottom. They are floating windows, so the mouse over them is theirs
    // (EdApp cuts them out of the view's input).
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const ImVec2 view(viewport->Pos.x + mGameView.x, viewport->Pos.y + mGameView.y);
    const ImVec2 viewSize(mGameView.z, mGameView.w);
    const ImU32 ground = IM_COL32(13, 16, 20, 184);
    const ImU32 edge = IM_COL32(255, 255, 255, 18);
    const ImU32 ink = IM_COL32(0xD6, 0xDD, 0xE6, 0xFF);
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
      ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoDocking |
      ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav;
    const float margin = std::round(Em(8.0f));
    const float pillHeight = std::round(Em(28.0f));
    const float fontSize = ImGui::GetFontSize();

    const auto begin = [&](const char* const id, const ImVec2 at, const ImVec2 pivot) {
      ImGui::SetNextWindowPos(at, ImGuiCond_Always, pivot);
      ImGui::SetNextWindowViewport(viewport->ID);
      ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(3.0f), Em(3.0f)));
      ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, Em(9.0f));
      ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
      ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(1.0f, 1.0f));
      ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::ColorConvertU32ToFloat4(ground));
      ImGui::PushStyleColor(ImGuiCol_Border, ImGui::ColorConvertU32ToFloat4(edge));
      const bool shown = ImGui::Begin(id, nullptr, kFlags);
      ImGui::PopStyleColor(2);
      ImGui::PopStyleVar(4);
      ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(Em(2.0f), 0.0f));
      return shown;
    };
    const auto end = [] {
      ImGui::PopStyleVar();
      ImGui::End();
    };
    // A pill (.pill-group button): an icon and maybe a word; on, the accent's fill and white words.
    const auto pill = [&](const char* const id, const char* const icon, const char* const label, const bool on) {
      const ImVec2 iconSize = ImGui::CalcTextSize(icon);
      const ImVec2 labelSize = label != nullptr ? ImGui::CalcTextSize(label) : ImVec2(0.0f, 0.0f);
      const float pad = Em(9.0f);
      const float gap = label != nullptr ? Em(6.0f) : 0.0f;
      const float width = std::round(pad * 2.0f + iconSize.x + gap + labelSize.x);
      const ImVec2 at = ImGui::GetCursorScreenPos();
      ImGui::PushID(id);
      const bool clicked = ImGui::InvisibleButton("##pill", ImVec2(width, pillHeight));
      const bool hovered = ImGui::IsItemHovered();
      ImGui::PopID();
      ImDrawList* const dl = ImGui::GetWindowDrawList();
      const ImVec2 to(at.x + width, at.y + pillHeight);
      if (on) {
        dl->AddRectFilled(at, to, AccentU32(hovered ? 0.34f : 0.25f), Em(7.0f));
      } else if (hovered) {
        dl->AddRectFilled(at, to, IM_COL32(255, 255, 255, 20), Em(7.0f));
      }
      const ImU32 words = on ? IM_COL32_WHITE : ink;
      // The capitals on the pill's middle (Segoe UI's centre 0.55 of the size below the line's top).
      const float y = std::round(at.y + pillHeight * 0.5f - fontSize * 0.55f);
      dl->AddText(ImVec2(std::round(at.x + pad), y), words, icon);
      if (label != nullptr) {
        dl->AddText(ImVec2(std::round(at.x + pad + iconSize.x + gap), y), words, label);
      }
      ImGui::SameLine();
      return clicked;
    };
    const auto tip = [](const char* const words) {
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        ImGui::SetTooltip("%s", words);
      }
    };

    // The top-left: the camera, then what the view shows.
    float x = view.x + margin;
    if (begin("##viewcamera", ImVec2(x, view.y + margin), ImVec2(0.0f, 0.0f))) {
      if (pill("camera", ICON_CAMERA, "Camera", false)) {
        ImGui::OpenPopup("##cameramenu");
      }
      tip("The camera: WASD moves, the right button turns, the wheel zooms");
      if (pill("frame", ICON_FRAME, nullptr, false) && mCommands != nullptr) {
        (void)mCommands->Run("view.frame");
      }
      tip("Frame the whole map (Home)");
      if (ImGui::BeginPopup("##cameramenu")) {
        if (ImGui::MenuItem("Frame the whole map", "Home") && mCommands != nullptr) {
          (void)mCommands->Run("view.frame");
        }
        ImGui::Separator();
        ImGui::TextDisabled("WASD moves, the right button turns, the wheel zooms");
        ImGui::EndPopup();
      }
      x += ImGui::GetWindowWidth() + Em(6.0f);
    }
    end();
    if (begin("##viewshows", ImVec2(x, view.y + margin), ImVec2(0.0f, 0.0f))) {
      if (pill("grid", ICON_GRID, "Grid", mTools.ShowGrid())) {
        mTools.SetShowGrid(!mTools.ShowGrid());
      }
      tip("The build grid on the ground around the cursor");
      if (pill("slope", ICON_SLOPE, "Slope", mTools.ShowSlope())) {
        mTools.SetShowSlope(!mTools.ShowSlope());
      }
      tip("Each cell's slope as the game's pathing reads it: yellow, orange, red as it gets steeper");
      if (pill("weight", ICON_LAYERS, "Weight", mTools.ShowLayerWeight())) {
        mTools.SetShowLayerWeight(!mTools.ShowLayerWeight());
      }
      tip("The paint layer's weight on the terrain");
      if (pill("pathing", ICON_PATH, "Pathing", mTools.ShowPathing())) {
        mTools.ShowPathing() = !mTools.ShowPathing();
      }
      tip("Where units can go: the land unit's or the ship's pathing (the layer is in the Check panel)");
      // Markers by the palette's groups: Paths are the path nodes, Markers the rest.
      std::set<std::string>& hidden = mTools.HiddenMarkerTypes();
      const auto groupShown = [&](const bool paths) {
        for (const MarkerType& type : MarkerTypes()) {
          if ((std::string(type.group) == "Path nodes") == paths && hidden.count(type.type) != 0) {
            return false;
          }
        }
        return true;
      };
      const auto setGroup = [&](const bool paths, const bool show) {
        for (const MarkerType& type : MarkerTypes()) {
          if ((std::string(type.group) == "Path nodes") == paths) {
            if (show) {
              hidden.erase(type.type);
            } else {
              hidden.insert(type.type);
            }
          }
        }
      };
      const bool markers = groupShown(false);
      if (pill("markers", ICON_MARKER, "Markers", markers)) {
        setGroup(false, !markers);
      }
      tip("Start positions, resources, AI and other markers");
      const bool paths = groupShown(true);
      if (pill("paths", ICON_CHAIN, "Paths", paths)) {
        setGroup(true, !paths);
      }
      tip("Path nodes and their links (land, air, water, amphibious)");
      if (pill("props", ICON_TREE, "Props", mTools.ShowProps())) {
        mTools.ShowProps() = !mTools.ShowProps();
      }
      tip("Trees, rocks and wrecks");
      if (pill("units", ICON_UNIT, "Units", mTools.ShowUnits())) {
        mTools.ShowUnits() = !mTools.ShowUnits();
      }
      tip("The armies' and civilians' units");
    }
    end();

    // The bottom: the tool, its mode, how many copies an edit makes (.vp-hud).
    if (begin("##viewhud", ImVec2(view.x + viewSize.x * 0.5f, view.y + viewSize.y - margin), ImVec2(0.5f, 1.0f))) {
      const int tool = mTools.Tool();
      ImGui::Dummy(ImVec2(Em(6.0f), pillHeight));
      ImGui::SameLine(0.0f, 0.0f);
      const float y = std::round(ImGui::GetCursorScreenPos().y + pillHeight * 0.5f - fontSize * 0.55f);
      const auto words = [&](const char* const text, ImFont* const font, const ImU32 colour, const float after) {
        const ImVec2 at = ImGui::GetCursorScreenPos();
        ImFont* const use = font != nullptr ? font : ImGui::GetFont();
        const ImVec2 size = use->CalcTextSizeA(fontSize, FLT_MAX, 0.0f, text);
        ImGui::GetWindowDrawList()->AddText(use, fontSize, ImVec2(at.x, y), colour, text);
        ImGui::Dummy(ImVec2(size.x, pillHeight));
        ImGui::SameLine(0.0f, after);
      };
      words(EdTools::ToolIcon(tool), nullptr, ink, Em(7.0f));
      words(EdTools::ToolName(tool), gBoldFont, IM_COL32_WHITE, Em(12.0f));
      if (const char* const mode = mTools.HudMode(); mode != nullptr) {
        words(mode, nullptr, ink, Em(12.0f));
      }
      if (const int copies = mTools.HudCopies(); copies > 1) {
        char text[32];
        (void)std::snprintf(text, sizeof(text), "%d copies", copies);
        words(ICON_SYM, nullptr, IM_COL32(0x8E, 0x9A, 0xA7, 0xFF), Em(5.0f));
        words(text, nullptr, IM_COL32(0x8E, 0x9A, 0xA7, 0xFF), Em(6.0f));
      }
      ImGui::Dummy(ImVec2(0.0f, pillHeight));
    }
    end();

    // The view's right side (.vp-gizmo, .vp-mini): the compass, and the minimap with what the camera sees.
    const EdTools::ViewFrame& frame = mTools.View();
    if (frame.valid && frame.maxX > frame.minX && frame.maxZ > frame.minZ) {
      // The compass: where the map's north (-z) and east (+x) are on the screen.
      const float radius = std::round(Em(30.0f));
      ImGui::SetNextWindowPos(
        ImVec2(view.x + viewSize.x - margin, view.y + margin), ImGuiCond_Always, ImVec2(1.0f, 0.0f)
      );
      ImGui::SetNextWindowSize(ImVec2(radius * 2.0f, radius * 2.0f));
      ImGui::SetNextWindowViewport(viewport->ID);
      ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
      ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
      ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
      if (ImGui::Begin("##viewcompass", nullptr, kFlags & ~ImGuiWindowFlags_AlwaysAutoResize)) {
        ImDrawList* const dl = ImGui::GetWindowDrawList();
        const ImVec2 centre(ImGui::GetWindowPos().x + radius, ImGui::GetWindowPos().y + radius);
        dl->AddCircleFilled(centre, radius, ground, 40);
        dl->AddCircle(centre, radius, edge, 40);
        // A world direction (x, z) as a screen direction: its parts along the view's right and up.
        const auto onScreen = [&](const float x, const float z) {
          ImVec2 d(x * frame.rightX + z * frame.rightZ, -(x * frame.upX + z * frame.upZ));
          const float length = std::max(1e-4f, std::hypot(d.x, d.y));
          return ImVec2(d.x / length, d.y / length);
        };
        const auto axis = [&](const ImVec2 dir, const ImU32 colour, const char* const letter) {
          const ImVec2 tip(centre.x + dir.x * radius * 0.62f, centre.y + dir.y * radius * 0.62f);
          dl->AddLine(centre, tip, colour, Em(2.0f));
          const float dot = Em(8.0f);
          dl->AddCircleFilled(tip, dot, colour, 20);
          const float size = std::round(fontSize * 0.7f);
          const ImVec2 text = ImGui::GetFont()->CalcTextSizeA(size, FLT_MAX, 0.0f, letter);
          dl->AddText(
            gBoldFont != nullptr ? gBoldFont : ImGui::GetFont(),
            size,
            ImVec2(std::round(tip.x - text.x * 0.5f), std::round(tip.y - text.y * 0.5f)),
            IM_COL32(0x10, 0x12, 0x16, 0xFF),
            letter
          );
        };
        axis(onScreen(1.0f, 0.0f), IM_COL32(0x4F, 0xD1, 0x8B, 0xFF), "E");
        axis(onScreen(0.0f, -1.0f), IM_COL32(0xFF, 0x5D, 0x5D, 0xFF), "N");
        dl->AddCircleFilled(centre, Em(5.0f), IM_COL32(0xE9, 0xED, 0xF2, 0xFF), 16);
        if (ImGui::IsWindowHovered()) {
          ImGui::SetTooltip("Where the map's north and east are");
        }
      }
      ImGui::End();
      ImGui::PopStyleColor();
      ImGui::PopStyleVar(2);

      // The minimap: the map's picture, the camera's ground as a frame; a click or a drag moves the camera there.
      const float mapW = frame.maxX - frame.minX;
      const float mapH = frame.maxZ - frame.minZ;
      const float longest = std::round(Em(160.0f));
      const ImVec2 size = mapW >= mapH ? ImVec2(longest, std::round(longest * mapH / mapW))
                                       : ImVec2(std::round(longest * mapW / mapH), longest);
      ImGui::SetNextWindowPos(
        ImVec2(view.x + viewSize.x - margin, view.y + viewSize.y - margin), ImGuiCond_Always, ImVec2(1.0f, 1.0f)
      );
      ImGui::SetNextWindowSize(size);
      ImGui::SetNextWindowViewport(viewport->ID);
      ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
      ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, Em(8.0f));
      ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.0f);
      ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
      ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(1.0f, 1.0f, 1.0f, 0.14f));
      if (ImGui::Begin("##viewminimap", nullptr, kFlags & ~ImGuiWindowFlags_AlwaysAutoResize)) {
        ImDrawList* const dl = ImGui::GetWindowDrawList();
        const ImVec2 at = ImGui::GetWindowPos();
        // The map itself is the scene's: an overhead camera draws it into this rectangle of the view (no cursor, no
        // markers), so the window only frames it.
        mTools.SetMinimapRect(at.x - view.x, at.y - view.y, size.x, size.y);
        const auto toMini = [&](const float x, const float z) {
          return ImVec2(at.x + (x - frame.minX) / mapW * size.x, at.y + (z - frame.minZ) / mapH * size.y);
        };
        if (frame.corners >= 3) {
          ImVec2 points[4];
          for (int i = 0; i < frame.corners; ++i) {
            points[i] = toMini(frame.cornerX[i], frame.cornerZ[i]);
          }
          dl->PushClipRect(at, ImVec2(at.x + size.x, at.y + size.y), true);
          dl->AddPolyline(points, frame.corners, IM_COL32_WHITE, ImDrawFlags_Closed, Em(1.5f));
          dl->PopClipRect();
        }
        ImGui::SetCursorScreenPos(at);
        (void)ImGui::InvisibleButton("##minimapjump", size);
        if (ImGui::IsItemActive()) {
          const ImVec2 mouse = ImGui::GetIO().MousePos;
          const float u = std::clamp((mouse.x - at.x) / size.x, 0.0f, 1.0f);
          const float v = std::clamp((mouse.y - at.y) / size.y, 0.0f, 1.0f);
          mTools.AskCameraAt(frame.minX + u * mapW, frame.minZ + v * mapH);
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
          ImGui::SetTooltip("The map: click or drag to look there");
        }
      }
      ImGui::End();
      ImGui::PopStyleColor(2);
      ImGui::PopStyleVar(3);
    }
  }

  void EdShell::CarryPanelPlaces()
  {
    // Before the tabs had icons, the first workspace's windows were named by their titles alone, which were their
    // ids. Their places in layout.ini (dock node, order, size) go to the new names once.
    static constexpr const char* kPanels[] = {
      "Tools",
      "Properties",
      "Map",
      "Info",
      "Markers",
      "Check",
      "Log",
      "History",
      "Problems",
      "Lighting",
      "Debugger",
      "Armies",
      "Material Editor",
      "Particle Browser",
      "Particle Editor",
    };
    ImGuiContext& g = *GImGui;
    int carried = 0;
    for (const char* const panel : kPanels) {
      const std::string before = PanelWindowNameBeforeIcons(panel, 0);
      const std::string now = PanelWindowName(panel, 0);
      const ImGuiID oldId = ImHashStr(before.c_str());
      const ImGuiID newId = ImHashStr(now.c_str());
      if (oldId == newId || ImGui::FindWindowSettingsByID(newId) != nullptr) {
        continue;
      }
      const ImGuiWindowSettings* const old = ImGui::FindWindowSettingsByID(oldId);
      if (old == nullptr) {
        continue;
      }
      // Copied first: a new entry can move the settings' storage.
      const ImGuiWindowSettings kept = *old;
      ImGuiWindowSettings* const moved = ImGui::CreateNewWindowSettings(now.c_str());
      moved->Pos = kept.Pos;
      moved->Size = kept.Size;
      moved->ViewportPos = kept.ViewportPos;
      moved->ViewportId = kept.ViewportId;
      moved->DockId = kept.DockId;
      moved->ClassId = kept.ClassId;
      moved->DockOrder = kept.DockOrder;
      moved->Collapsed = kept.Collapsed;
      // The tab a dock node shows is kept by the window's id (the nodes are built from layout.ini by now).
      for (const ImGuiStoragePair& pair : g.DockContext.Nodes.Data) {
        if (
          auto* const node = static_cast<ImGuiDockNode*>(pair.val_p); node != nullptr && node->SelectedTabId == oldId
        ) {
          node->SelectedTabId = newId;
        }
      }
      ++carried;
    }
    if (carried > 0) {
      gpg::Logf("editor: %d panels' places carried to their names with icons", carried);
      ImGui::MarkIniSettingsDirty();
    }
  }

  void EdShell::DrawToolsPanel()
  {
    // The tab is the chosen tool's name and icon (the mockup's), the window's id staying the panel's.
    const std::string panel = Panel(kToolsWindow);
    const std::size_t id = panel.find("###");
    const std::string window = std::string(EdTools::ToolIcon(mTools.Tool())) + "  " + EdTools::ToolName(mTools.Tool()) +
      (id == std::string::npos ? "###" + panel : panel.substr(id));
    if (mFocusTools) {
      mFocusTools = false;
      ImGui::SetNextWindowFocus();
    }
    if (ImGui::Begin(window.c_str(), &mShowTools)) {
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
    if (
      !maps.empty() && mDocument.GetState() == EdDocument::State::Open &&
      mDocument.Path() == maps[static_cast<std::size_t>(mPlay.Selected())]
    ) {
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
      if (EdBeginCombo("##profile", "Profile...")) {
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
      ImGui::SetNextItemWidth(
        ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("Save").x - ImGui::GetStyle().FramePadding.x * 4.0f
      );
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
      return slots.empty() ? "Slot " + std::to_string(i + 1)
                           : std::to_string(i + 1) + "  " + slots[static_cast<std::size_t>(i)];
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
      if (EdBeginCombo("##slot", slotName(setup.slot).c_str())) {
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
    if (
      EdBeginCombo(
        "##faction", setup.faction == 0 ? "Random" : factions[static_cast<std::size_t>(setup.faction - 1)].name.c_str()
      )
    ) {
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
      if (EdBeginCombo("##ai", aiTypes[static_cast<std::size_t>(setup.ai)].name.c_str())) {
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
        if (EdBeginCombo("##aicount", count.c_str())) {
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
        if (EdCombo("##role", &role, kRoles, 3)) {
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
        const float aiWidth =
          ImGui::GetContentRegionAvail().x - teamWidth - factionWidth - ImGui::GetStyle().ItemSpacing.x * 2.0f;
        if (slot.role == PlaySlot::Role::Ai) {
          slot.ai = std::clamp(slot.ai, 0, static_cast<int>(aiTypes.size()) - 1);
          ImGui::SetNextItemWidth(aiWidth);
          if (EdBeginCombo("##slotai", aiTypes[static_cast<std::size_t>(slot.ai)].name.c_str())) {
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
          if (
            EdBeginCombo(
              "##slotfaction",
              slot.faction == 0 ? "Random" : factions[static_cast<std::size_t>(slot.faction - 1)].name.c_str()
            )
          ) {
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
        changed = EdCombo("##team", &slot.team, kTeams, 5) || changed;
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
    ImGui::SameLine();
    ImGui::Checkbox("Quick start", &setup.quickStart);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip(
        "The commanders are there and take orders at once, without the game's warp-in\n"
        "(about 5 s), and the camera starts over yours. Off: the game's own start."
      );
    }
    {
      static const char* const kVictoryKeys[5] = {
        "sandbox", "demoralization", "domination", "eradication", "decapitation"
      };
      static const char* const kVictoryNames[5] = {
        "Sandbox (no end)", "Assassination", "Supremacy", "Annihilation", "Decapitation"
      };
      int victory = 0;
      for (int i = 0; i < 5; ++i) {
        victory = setup.victory == kVictoryKeys[i] ? i : victory;
      }
      label("Victory");
      if (EdCombo("##victory", &victory, kVictoryNames, 5)) {
        setup.victory = kVictoryKeys[victory];
      }
      label("Unit cap");
      FillSliderInt("##unitcap", &setup.unitCap, 250, 1500, "%d units");
      setup.unitCap = std::clamp(setup.unitCap / 50 * 50, 250, 1500);
      label("AI cheat x");
      FillSliderFloat("##cheatmult", &setup.cheatMult, 1.0f, 5.0f, "%.1f");
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
      ImGui::SetTooltip(
        "On: this map plays with its own setup, saved at each Play.\n"
        "Off: it plays with the setup of the last Play on any map."
      );
    }
    ImGui::EndDisabled();

    // During play: the fog's shading left out of the view (the player keeps their army), or the observer's view.
    ImGui::BeginDisabled(moho::WLD_GetFrameAction() != moho::EWldFrameAction::Playing);
    bool noFog = mPlay.FogHidden();
    if (ImGui::Checkbox("Hide the fog", &noFog)) {
      mPlay.SetFogHidden(noFog);
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip(
        "While playing: the view leaves out the fog's shading and you keep your army.\n"
        "Enemy units your army has no intel on stay unseen; Observer view shows them."
      );
    }
    ImGui::SameLine();
    bool wholeMap = mPlay.SeesWholeMap();
    if (ImGui::Checkbox("Observer view", &wholeMap)) {
      mPlay.SetSeesWholeMap(wholeMap);
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip(
        "While playing: view the map as an observer (every army's units, no fog), then back to your army."
      );
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
    if (!ImGui::Begin(Panel(kMapWindow), &mShowMap)) {
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
    ImGui::SetItemTooltip(
      "Every map on this computer and the FAF vault (File > Open, Ctrl+O); recent ones are in File > Open Recent"
    );
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
        ImGui::Text(
          "%s%s", facts.type.empty() ? "skirmish" : facts.type.c_str(), mDocument.Adaptive() ? ", adaptive" : ""
        );
        row("Size");
        ImGui::Text(
          "%.0f x %.0f km (%d x %d)",
          static_cast<double>(facts.sizeX) / 51.2,
          static_cast<double>(facts.sizeZ) / 51.2,
          facts.sizeX,
          facts.sizeZ
        );
        row("Players");
        ImGui::Text("%zu", mDocument.Teams().empty() ? facts.armies.size() : mDocument.Teams().front().armies.size());
        row("Water");
        if (facts.water) {
          ImGui::Text(
            "at %.1f (deep %.1f, abyss %.1f)",
            static_cast<double>(facts.waterElevation),
            static_cast<double>(facts.waterDeep),
            static_cast<double>(facts.waterAbyss)
          );
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
          ImGui::SetWindowFocus(Panel(kInfoWindow));
        }
      }
      if (
        ImGui::CollapsingHeader(
          "Adaptive map", mDocument.Adaptive() ? ImGuiTreeNodeFlags_DefaultOpen : ImGuiTreeNodeFlags_None
        )
      ) {
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
    ImGui::SetNextItemWidth(Em(420.0f));
    const bool enter =
      ImGui::InputText("Folder", mSaveAsName, sizeof(mSaveAsName), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::TextDisabled("FAF names map folders name.vNNNN; the files take the name without the version.");
    if (ImGui::Button("Save", ImVec2(Em(120.0f), 0.0f)) || enter) {
      std::string message;
      if (mDocument.SaveAsNewFolder(mSaveAsName, message)) {
        gpg::Logf("editor: %s", message.c_str());
        ImGui::CloseCurrentPopup();
      } else {
        gpg::Warnf("editor: %s", message.c_str());
      }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(Em(120.0f), 0.0f)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
  }

  namespace
  {
    /** The folder FAF would give a map of this title: lower case, letters and digits, `_` between words, `.v0001`. */
    std::string FolderForTitle(
      const char* const title
    )
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
    ImGui::SameLine(Em(110.0f));
    if (ImGui::RadioButton("Skirmish", !mNewMap.campaign)) {
      mNewMap.campaign = false;
    }
    ImGui::SameLine();
    if (ImGui::RadioButton("Campaign", mNewMap.campaign)) {
      mNewMap.campaign = true;
    }
    ImGui::TextUnformatted("Size");
    ImGui::SameLine(Em(110.0f));
    for (int i = 0; i < kNewMapSizeCount; ++i) {
      if (i > 0) {
        ImGui::SameLine();
      }
      if (ImGui::RadioButton(kNewMapSizes[i].name, mNewMap.size == i)) {
        mNewMap.size = i;
      }
    }
    ImGui::SetNextItemWidth(kWidth);
    FillSliderInt("Players", &mNewMap.players, 1, kNewMapMaxPlayers);
    ImGui::SetNextItemWidth(kWidth);
    FillDragFloat("Ground height", &mNewMap.height, 0.25f, 0.0f, 500.0f, "%.1f");
    ImGui::Checkbox("Sea", &mNewMap.sea);
    if (mNewMap.sea) {
      ImGui::SameLine();
      ImGui::SetNextItemWidth(kWidth - 60.0f);
      FillDragFloat("Sea level", &mNewMap.seaLevel, 0.25f, 0.0f, 500.0f, "%.1f");
    }
    ImGui::TextDisabled(
      "Start positions ARMY_1 to ARMY_%d in a ring; ARMY_17 and NEUTRAL_CIVILIAN as extra armies.", mNewMap.players
    );
    ImGui::Separator();
    if (ImGui::Button("Create", ImVec2(Em(120.0f), 0.0f))) {
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
    if (ImGui::Button("Cancel", ImVec2(Em(120.0f), 0.0f)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
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
    ImGui::TextDisabled(
      "A zip with this folder at its top, as the vault takes maps: %s",
      (mDocument.VaultFolder() / "packages" / (mPackagePlan.folder + ".zip")).string().c_str()
    );
    ImGui::Separator();
    for (const std::string& error : mPackagePlan.errors) {
      ImGui::TextColored(ImVec4(0.95f, 0.40f, 0.35f, 1.0f), "error: %s", error.c_str());
    }
    for (const std::string& warning : mPackagePlan.warnings) {
      ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "warning: %s", warning.c_str());
    }
    if (mPackagePlan.errors.empty() && mPackagePlan.warnings.empty()) {
      ImGui::TextColored(
        ImVec4(0.55f, 0.80f, 0.55f, 1.0f), "The folder's name, version and scenario paths are as the vault wants them."
      );
    }
    ImGui::TextDisabled("%zu files go in:", mPackagePlan.files.size());
    if (
      ImGui::BeginChild(
        "##packagefiles", ImVec2(Em(520.0f), ImGui::GetTextLineHeightWithSpacing() * 7.0f), ImGuiChildFlags_Borders
      )
    ) {
      for (const std::string& file : mPackagePlan.files) {
        ImGui::TextUnformatted(file.c_str());
      }
    }
    ImGui::EndChild();
    ImGui::BeginDisabled(!mPackagePlan.errors.empty());
    if (ImGui::Button("Package", ImVec2(Em(120.0f), 0.0f))) {
      std::filesystem::path written;
      const bool ok = mDocument.WritePackage(mPackagePlan, written, mPackageMessage);
      (ok ? gpg::Logf : gpg::Warnf)("editor: %s", mPackageMessage.c_str());
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Close", ImVec2(Em(120.0f), 0.0f)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
      ImGui::CloseCurrentPopup();
    }
    if (!mPackageMessage.empty()) {
      ImGui::TextWrapped("%s", mPackageMessage.c_str());
    }
    ImGui::TextDisabled("Uploading to the vault is done in the FAF client (or its website) for now.");
    ImGui::EndPopup();
  }

  float EdShell::StatusBarHeight()
  {
    return std::round(Em(24.0f));
  }

  void EdShell::DrawStatusBar()
  {
    // The mockup's status bar (styles.css .statusbar): a live dot by the renderer, the items in the dimmed text with
    // room between them, the problems count in the warning colour with its icon (a click shows them), the last message
    // and the frame rate at the right.
    const ImGuiViewport* const viewport = ImGui::GetMainViewport();
    const float height = StatusBarHeight();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - height));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, height));
    ImGui::SetNextWindowViewport(viewport->ID);
    constexpr ImGuiWindowFlags kFlags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
      ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
      ImGuiWindowFlags_NoNav;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(Em(10.0f), 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
    if (ImGui::Begin("##StatusBar", nullptr, kFlags)) {
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      const ImVec2 origin = ImGui::GetWindowPos();
      const float barWidth = ImGui::GetWindowWidth();
      draw->AddLine(
        ImVec2(origin.x, origin.y + 0.5f),
        ImVec2(origin.x + barWidth, origin.y + 0.5f),
        ImGui::GetColorU32(ImGuiCol_Border)
      );
      ImFont* const font = ImGui::GetFont();
      const float size = std::round(ImGui::GetFontSize() * 0.9f);
      const float textY = std::round(origin.y + (height - size) * 0.5f);
      const ImVec4 text = ImGui::GetStyleColorVec4(ImGuiCol_Text);
      const ImVec4 dimmed = ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
      const ImU32 dim = ImGui::GetColorU32(ImGuiCol_TextDisabled);
      const ImU32 plain = ImGui::GetColorU32(ImVec4(
        (text.x * 2.0f + dimmed.x) / 3.0f, (text.y * 2.0f + dimmed.y) / 3.0f, (text.z * 2.0f + dimmed.z) / 3.0f, 1.0f
      ));
      const ImU32 warn = IM_COL32(0xF0, 0xB0, 0x4A, 0xFF);
      const ImU32 ok = IM_COL32(0x4F, 0xD1, 0x8B, 0xFF);

      // The items (design §3), each with how much it is wanted when the window is narrow (0 always stays; the
      // highest number goes first): the mode, the problems, cursor and ruler, selection, the undo step, then the
      // renderer and the GPU.
      struct Item
      {
        std::string text;
        int priority;
        ImU32 ink;
        const char* icon = nullptr; // drawn before the text, in its colour
        bool live = false;          // the green dot before it (the renderer)
        bool problems = false;      // a click shows the problems
      };
      std::vector<Item> items;
      const EdWorkspace& workspace = Workspaces()[static_cast<std::size_t>(ActiveWorkspace())];
      const std::string mode = mPlay.Active() ? mPlay.StateText()
        : workspace.readOnly                  ? "Review (read-only)"
                                              : "Editing";
      items.push_back({mApi.empty() ? "?" : mApi, 7, plain, nullptr, true});
      if (!mAdapter.empty()) {
        items.push_back({mAdapter, 8, dim});
      }
      items.push_back({mode, 0, mPlay.Active() || workspace.readOnly ? AccentU32() : plain});
      // The Problems panel's count: the check's findings (for this map) and each different log warning once.
      const bool checked = mCheckRan && mCheckedPath == mDocument.Path();
      static const std::vector<CheckIssue> kNoChecks;
      const EdProblemCounts problems =
        CountProblems(ProblemRows(checked ? mCheckIssues : kNoChecks, mLog.Warnings(), 0x7U, 0x3U));
      const int warnings = problems.errors + problems.warnings + problems.notes;
      if (warnings > 0) {
        items.push_back(
          {std::to_string(warnings) + (warnings == 1 ? " warning" : " warnings"), 1, warn, ICON_WARN, false, true}
        );
      } else {
        items.push_back({"no warnings", 1, dim, ICON_OK, false, true});
      }
      if (!mTools.CursorText().empty()) {
        items.push_back({mTools.CursorText(), 2, dim});
      }
      if (!mTools.RulerText().empty()) {
        items.push_back({"ruler " + mTools.RulerText(), 2, warn, ICON_RULER});
      }
      const std::string count = SelectionCountText(mStatusSelection);
      items.push_back({count.empty() ? std::string("nothing selected") : count + " selected", 3, dim});
      const char* const step = mDocument.UndoStepName();
      items.push_back({std::string("undo: ") + (step != nullptr ? step : "\xE2\x80\x94"), 5, dim});

      const auto measure = [&](const Item& item) {
        float width = font->CalcTextSizeA(size, FLT_MAX, 0.0f, item.text.c_str()).x;
        if (item.icon != nullptr) {
          width += font->CalcTextSizeA(size, FLT_MAX, 0.0f, item.icon).x + Em(5.0f);
        }
        if (item.live) {
          width += Em(13.0f);
        }
        return width;
      };
      // At the right: the last message (shown while there is room for it), then the frame rate.
      char fps[32];
      (void)std::snprintf(fps, sizeof(fps), "%.0f fps", ImGui::GetIO().Framerate);
      const float fpsWidth = font->CalcTextSizeA(size, FLT_MAX, 0.0f, fps).x;
      const std::string message = StatusMessage().empty()
        ? std::string(mDocument.Modified() ? "Unsaved changes" : "")
        : StatusMessage() + " (" + AgoText(StatusClock() - StatusMessageTime()) + ")";
      const float messageWidth = message.empty() ? 0.0f : font->CalcTextSizeA(size, FLT_MAX, 0.0f, message.c_str()).x;

      const float gap = Em(14.0f);
      const float left = origin.x + ImGui::GetStyle().WindowPadding.x;
      const float right = origin.x + barWidth - ImGui::GetStyle().WindowPadding.x;
      std::vector<float> widths;
      std::vector<int> priorities;
      for (const Item& item : items) {
        widths.push_back(measure(item));
        priorities.push_back(item.priority);
      }
      const float room = right - left - fpsWidth - gap;
      const std::vector<std::size_t> shown = FitStatusItems(widths, priorities, room, gap);
      float x = left;
      for (const std::size_t i : shown) {
        const Item& item = items[i];
        const float width = widths[i];
        if (item.problems) {
          // A button: the mockup's hover fill, a click opens the Problems panel.
          ImGui::SetCursorScreenPos(ImVec2(x - Em(4.0f), origin.y + Em(3.0f)));
          if (ImGui::InvisibleButton("##problems", ImVec2(width + Em(8.0f), height - Em(6.0f)))) {
            OpenProblems();
            gpg::Logf("editor: status bar: the problems, %d", warnings);
          }
          if (ImGui::IsItemHovered()) {
            draw->AddRectFilled(
              ImGui::GetItemRectMin(), ImGui::GetItemRectMax(), ImGui::GetColorU32(ImGuiCol_Button), Em(4.0f)
            );
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            ImGui::SetTooltip("Show the problems");
          }
        }
        float at = x;
        if (item.live) {
          const ImVec2 centre(at + Em(4.0f), origin.y + height * 0.5f);
          draw->AddCircleFilled(centre, Em(6.0f), (ok & ~IM_COL32_A_MASK) | (0x2EU << IM_COL32_A_SHIFT));
          draw->AddCircleFilled(centre, Em(4.0f), ok);
          at += Em(13.0f);
        }
        if (item.icon != nullptr) {
          draw->AddText(font, size, ImVec2(at, textY), item.ink, item.icon);
          at += font->CalcTextSizeA(size, FLT_MAX, 0.0f, item.icon).x + Em(5.0f);
        }
        draw->AddText(font, size, ImVec2(at, textY), item.ink, item.text.c_str());
        x += width + gap;
      }
      draw->AddText(font, size, ImVec2(right - fpsWidth, textY), dim, fps);
      if (!message.empty() && x + messageWidth < right - fpsWidth - gap) {
        draw->AddText(font, size, ImVec2(right - fpsWidth - gap - messageWidth, textY), plain, message.c_str());
      }
    }
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(4);
  }
} // namespace faf::editor
