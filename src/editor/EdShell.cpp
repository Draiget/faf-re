#include "editor/EdShell.h"

#include <cctype>

#include <algorithm>
#include <cstdio>

#include "editor/EdLog.h"
#include "editor/EdPlay.h"
#include "editor/doc/EdDocument.h"
#include "gpg/gal/Device.hpp"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  namespace
  {
    constexpr const char* kToolsWindow = "Tools";
    constexpr const char* kMapWindow = "Map";
    constexpr const char* kInfoWindow = "Info";
    constexpr const char* kLogWindow = "Log";
    constexpr const char* kDockSpace = "EditorDockSpace";

    const ImVec4 kPlayGreen(0.24f, 0.55f, 0.28f, 1.0f);
    const ImVec4 kStopRed(0.62f, 0.22f, 0.20f, 1.0f);
  } // namespace

  EdShell::EdShell(EdLog& log, EdPlay& play, EdDocument& document)
    : mLog(log)
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
      if (mShowInfo) {
        DrawInfoPanel();
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
    DrawNewMapDialog();
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
    ImGui::DockBuilderDockWindow(kInfoWindow, right);
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
    // Open: the picked map into the editor's document (the Info panel shows what it read).
    ImGui::BeginDisabled(maps.empty() || mDocument.GetState() == EdDocument::State::Loading);
    if (ImGui::Button("Open for editing", ImVec2(-1.0f, 0.0f)) && !maps.empty()) {
      (void)mDocument.Open(maps[static_cast<std::size_t>(selected)]);
    }
    ImGui::EndDisabled();
    ImGui::Separator();

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
    bool keepOwn = mPlay.KeepsOwnSetup();
    if (ImGui::Checkbox("Keep this setup for this map", &keepOwn)) {
      mPlay.SetKeepsOwnSetup(keepOwn);
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      ImGui::SetTooltip("On: this map plays with its own setup, saved at each Play.\n"
                        "Off: it plays with the setup of the last Play on any map.");
    }
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

  void EdShell::DrawInfoPanel()
  {
    // A layout saved before this panel existed has no place for it: it goes beside the Map panel.
    if (const ImGuiWindow* const map = ImGui::FindWindowByName(kMapWindow); map != nullptr && map->DockId != 0) {
      ImGui::SetNextWindowDockID(map->DockId, ImGuiCond_FirstUseEver);
    }
    // A map that starts opening (the Map panel's button, `/open`) brings this tab to the front once, after the
    // first frames: on those the saved layout picks each dock's front tab and would override it.
    if (!mDocument.Path().empty() && mDocument.Path() != mInfoShownFor && ImGui::GetFrameCount() > 3) {
      mInfoShownFor = mDocument.Path();
      mShowInfo = true;
      ImGui::SetNextWindowFocus();
    }
    if (!ImGui::Begin(kInfoWindow, &mShowInfo)) {
      ImGui::End();
      return;
    }
    switch (mDocument.GetState()) {
    case EdDocument::State::Empty:
      ImGui::TextDisabled("No map open. Pick one in the Map panel and press Open for editing.");
      ImGui::End();
      return;
    case EdDocument::State::Loading:
      ImGui::Text("Opening %s ...", MapDisplayName(mDocument.Path()).c_str());
      ImGui::End();
      return;
    case EdDocument::State::Failed:
      ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.40f, 1.0f), "%s did not open", MapDisplayName(mDocument.Path()).c_str());
      ImGui::TextWrapped("%s", mDocument.Error().c_str());
      ImGui::End();
      return;
    case EdDocument::State::Open:
      break;
    }

    const MapFacts& facts = mDocument.Facts();
    ImGui::TextUnformatted(facts.name.empty() ? MapDisplayName(facts.scenarioPath).c_str() : facts.name.c_str());
    if (facts.mapVersion > 0) {
      ImGui::TextDisabled("%s, version %d, opened in %.2f s", MapDisplayName(facts.scenarioPath).c_str(), facts.mapVersion,
                          facts.loadSeconds);
    } else {
      ImGui::TextDisabled("%s, opened in %.2f s", MapDisplayName(facts.scenarioPath).c_str(), facts.loadSeconds);
    }
    if (!mDocument.Error().empty()) {
      ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "%s", mDocument.Error().c_str());
    }
    if (!facts.description.empty()) {
      ImGui::TextWrapped("%s", facts.description.c_str());
    }
    ImGui::Separator();

    constexpr ImGuiTableFlags kTable = ImGuiTableFlags_SizingStretchProp | ImGuiTableFlags_RowBg;
    const auto row = [](const char* const label, const char* const format, auto... values) {
      ImGui::TableNextRow();
      ImGui::TableSetColumnIndex(0);
      ImGui::TextDisabled("%s", label);
      ImGui::TableSetColumnIndex(1);
      ImGui::Text(format, values...);
    };
    if (ImGui::BeginTable("##facts", 2, kTable)) {
      ImGui::TableSetupColumn("##label", ImGuiTableColumnFlags_WidthFixed);
      ImGui::TableSetupColumn("##value", ImGuiTableColumnFlags_WidthStretch);
      row("Size", "%d x %d (%.0f x %.0f km)", facts.sizeX, facts.sizeZ, facts.sizeX / 51.2, facts.sizeZ / 51.2);
      row("Height field", "%d x %d samples", facts.fieldWidth, facts.fieldHeight);
      if (facts.water) {
        row("Water", "at %.2f", static_cast<double>(facts.waterElevation));
      } else {
        row("Water", "%s", "none");
      }
      row("Type", "%s", facts.type.c_str());
      row("Terrain shader", "%s", facts.terrainShader.c_str());
      row("Props", "%d", facts.props);
      row("Decals", "%d", facts.decals);
      row("Markers", "%d", facts.markerCount);
      row("Armies", "%zu", facts.armies.size());
      ImGui::EndTable();
    }

    if (ImGui::CollapsingHeader("Texture layers", ImGuiTreeNodeFlags_DefaultOpen)) {
      static constexpr const char* kSlots[] = {"Lower", "1", "2", "3", "4", "5", "6", "7", "8", "Upper"};
      if (ImGui::BeginTable("##layers", 2, kTable)) {
        ImGui::TableSetupColumn("##slot", ImGuiTableColumnFlags_WidthFixed);
        ImGui::TableSetupColumn("##texture", ImGuiTableColumnFlags_WidthStretch);
        for (std::size_t i = 0; i < facts.layers.size() && i < std::size(kSlots); ++i) {
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          ImGui::TextDisabled("%s", kSlots[i]);
          ImGui::TableSetColumnIndex(1);
          if (facts.layers[i].empty()) {
            ImGui::TextDisabled("(empty)");
          } else {
            ImGui::TextUnformatted(facts.layers[i].c_str());
          }
        }
        ImGui::EndTable();
      }
    }
    if (ImGui::CollapsingHeader("Markers")) {
      for (const auto& [type, count] : facts.markers) {
        ImGui::Text("%d", count);
        ImGui::SameLine(48.0f);
        ImGui::TextUnformatted(type.c_str());
      }
    }
    if (ImGui::CollapsingHeader("Armies")) {
      for (const std::string& army : facts.armies) {
        ImGui::BulletText("%s", army.c_str());
      }
    }
    if (ImGui::CollapsingHeader("Files")) {
      ImGui::TextWrapped("%s", facts.scenarioPath.c_str());
      ImGui::TextWrapped("%s", facts.mapPath.c_str());
      ImGui::TextWrapped("%s", facts.savePath.c_str());
      ImGui::TextWrapped("%s", facts.scriptPath.c_str());
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
