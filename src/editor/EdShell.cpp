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
    constexpr const char* kMarkersWindow = "Markers";
    constexpr const char* kCheckWindow = "Check";
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
        const ImVec2 keySize = ImGui::CalcTextSize("F5");
        draw->AddText(ImVec2(at.x + size.x - keySize.x - 10.0f, textY), ImGui::GetColorU32(ImGuiCol_TextDisabled), "F5");
        ImGui::EndDisabled();
        ImGui::PopStyleColor(3);
        tip(playing ? "Stop the session and go back to editing (F5)" : "Play the map picked in the Map panel (F5)");
      }
      divider();

      // File.
      ImGui::BeginDisabled(playing);
      if (ImGui::Button("New")) {
        mOpenNewMap = true;
      }
      tip("A new map: size, players, height and sea (Ctrl+N)");
      ImGui::SameLine();
      const std::vector<std::string>& maps = mPlay.Maps();
      ImGui::BeginDisabled(maps.empty() || mDocument.GetState() == EdDocument::State::Loading);
      if (ImGui::Button("Open") && !maps.empty()) {
        (void)mDocument.Open(maps[static_cast<std::size_t>(mPlay.Selected())]);
      }
      ImGui::EndDisabled();
      tip("Open the map picked in the Map panel for editing (or double-click it there)");
      ImGui::SameLine();
      ImGui::BeginDisabled(!open);
      if (ImGui::Button("Save")) {
        mCommand = Command::Save;
      }
      tip("Save the map into its folder (Ctrl+S)");
      ImGui::SameLine();
      if (ImGui::Button("Save as")) {
        mOpenSaveAs = true;
      }
      tip("Save the map as a new folder in your vault");
      ImGui::EndDisabled();
      divider();

      // Edit.
      ImGui::BeginDisabled(!open || !mDocument.CanUndo());
      if (ImGui::Button("Undo")) {
        mCommand = Command::Undo;
      }
      ImGui::EndDisabled();
      tip("Undo the last edit (Ctrl+Z)");
      ImGui::SameLine();
      ImGui::BeginDisabled(!open || !mDocument.CanRedo());
      if (ImGui::Button("Redo")) {
        mCommand = Command::Redo;
      }
      ImGui::EndDisabled();
      tip("Redo (Ctrl+Y)");
      ImGui::EndDisabled();
      divider();

      // The build grid and snapping.
      const auto toggle = [](const char* const label, const bool on) {
        if (on) {
          ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.55f, 0.36f, 0.16f, 1.0f));
          ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.66f, 0.44f, 0.20f, 1.0f));
        }
        const bool clicked = ImGui::Button(label);
        if (on) {
          ImGui::PopStyleColor(2);
        }
        return clicked;
      };
      if (toggle("Grid", mTools.ShowGrid())) {
        mTools.SetShowGrid(!mTools.ShowGrid());
      }
      tip("The build grid on the ground around the cursor: cells of the step's size, one unit being the cell units are built on");
      ImGui::SameLine();
      if (toggle("Snap", mTools.SnapToGrid())) {
        mTools.SetSnapToGrid(!mTools.SnapToGrid());
      }
      tip("Markers and props placed or dragged go to the middle of a grid cell (mass and hydrocarbon points always sit on half units, as the game's saves place them)");
      ImGui::SameLine();
      if (toggle("On ground", mTools.KeepOnGround())) {
        mTools.SetKeepOnGround(!mTools.KeepOnGround());
      }
      tip("The move arrows keep markers and props on the ground when they move across it; off, they keep their height. "
          "Nothing is moved under the ground either way.");
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
          // A double-click opens the map for editing; Play (F5) plays it.
          if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && mDocument.GetState() != EdDocument::State::Loading) {
            (void)mDocument.Open(maps[at]);
          }
        }
        if (ImGui::IsItemHovered()) {
          ImGui::SetTooltip("%s\n%s\nDouble-click to open for editing; Play (F5) plays it", titles[at].c_str(), maps[at].c_str());
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
