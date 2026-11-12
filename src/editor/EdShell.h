#pragma once

#include <cstdio>
#include <map>
#include <string>
#include <utility>

#include "editor/EdTools.h"
#include "editor/doc/EdAdaptiveModel.h"
#include "editor/tools/EdChecks.h"
#include "editor/doc/EdLighting.h"
#include "editor/doc/EdNewMap.h"
#include "editor/doc/EdPackage.h"
#include "editor/doc/EdSaveFile.h"
#include "editor/ui/EdMapBrowser.h"
#include "editor/ui/EdMaterialEditor.h"
#include "editor/ui/EdParticleEditor.h"
#include "imgui.h"

#include <vector>

namespace faf::editor
{
  class EdCommands;
  struct EdMenu;
  class EdDocument;
  class EdLog;
  class EdPlay;

  /**
   * The editor's panels over the game's frame: the title row (the editor draws its own, with the menus; ui/EdTitleBar),
   * the toolbar, the docked panels (tools, map, log) around an empty middle where the game's picture shows through,
   * and the status bar. While a session runs the panels and the status bar step aside unless "Panels while playing" is
   * on; the title row stays.
   */
  class EdShell
  {
  public:
    EdShell(EdLog& log, EdPlay& play, EdDocument& document);

    /** Builds this frame's UI. */
    void Draw();
    /** The map browser (on this computer, and the FAF vault). */
    [[nodiscard]] EdMapBrowser& Browser() noexcept
    {
      return mBrowser;
    }

    // What the window's menu bar shows and changes.
    bool& ShowTools() noexcept
    {
      return mShowTools;
    }
    bool& ShowMap() noexcept
    {
      return mShowMap;
    }
    bool& ShowInfo() noexcept
    {
      return mShowInfo;
    }
    bool& ShowMarkers() noexcept
    {
      return mShowMarkers;
    }
    bool& ShowCheck() noexcept
    {
      return mShowCheck;
    }
    bool& ShowScript() noexcept
    {
      return mShowScript;
    }
    /** While a play runs: the editor's view in front of it (true) or the game's (F6, the toolbar's switch). */
    bool& EditorViewInPlay() noexcept
    {
      return mEditorViewInPlay;
    }
    /** The panels' scale (1 at the screen's DPI): the toolbar's - / % / + at its right; kept in layout.ini. */
    float& UiScale() noexcept
    {
      return mUiScale;
    }
    /** The toolbar's - and + as keys (Ctrl+- / Ctrl+=): the next smaller or larger step; 0 puts it back to 100 %. */
    void StepUiScale(int direction);
    /** The Adaptive Map window (View > Adaptive Map). */
    bool& ShowAdaptiveWindow() noexcept
    {
      return mShowAdaptiveWindow;
    }
    /** Test runs (`/adaptivepreview <key>=<choice index>,...[;<players>]`): the window's preview on with those picks.
     */
    void TestAdaptivePreview(
      const std::string& spec
    )
    {
      mShowAdaptiveWindow = true;
      mAdaptivePreview = true;
      const std::size_t semicolon = spec.find(';');
      const std::string picks = spec.substr(0, semicolon);
      mAdaptivePreviewPlayers = semicolon == std::string::npos ? 0 : std::atoi(spec.c_str() + semicolon + 1);
      for (std::size_t at = 0; at < picks.size();) {
        const std::size_t comma = std::min(picks.find(',', at), picks.size());
        const std::string pair = picks.substr(at, comma - at);
        if (const std::size_t eq = pair.find('='); eq != std::string::npos) {
          mAdaptivePreviewPicks[pair.substr(0, eq)] = std::atoi(pair.c_str() + eq + 1);
        }
        at = comma + 1;
      }
    }
    /** Shows it with an option picked (test runs: `/adaptivewindow <key>`). */
    void OpenAdaptiveWindow(
      const std::string& key
    )
    {
      mShowAdaptiveWindow = true;
      mFocusAdaptiveWindow = true;
      if (!key.empty()) {
        mAdaptivePick = key;
      }
    }
    bool& ShowLighting() noexcept
    {
      return mShowLighting;
    }
    /** The material editor (View > Material Editor): node graphs that make terrain textures. */
    bool& ShowMaterialEditor() noexcept
    {
      return mShowMaterialEditor;
    }
    [[nodiscard]] EdMaterialEditor& MaterialEditor() noexcept
    {
      return mMaterialEditor;
    }
    /** The particle editor (View > Particle Editor): the game's emitter blueprints, previewed live on the map. */
    bool& ShowParticleEditor() noexcept
    {
      return mShowParticleEditor;
    }
    /** The Particle Browser (View > Particle Browser). */
    bool& ShowParticleBrowser() noexcept
    {
      return mShowParticleBrowser;
    }
    [[nodiscard]] EdParticleEditor& ParticleEditor() noexcept
    {
      return mParticleEditor;
    }
    /** The Armies panel; the Markers tool's "Open the Armies panel" also brings it to the front. */
    bool& ShowArmies() noexcept
    {
      return mShowArmies;
    }
    /** The Properties panel: the selected marker, unit, prop or decal, by kind (ui/EdPropertiesPanel.cpp). */
    bool& ShowProperties() noexcept
    {
      return mShowProperties;
    }
    /** The Lighting panel's Import / Export buttons, taken by the app (it asks for the file). */
    [[nodiscard]] bool TakeLightingImport() noexcept
    {
      return std::exchange(mLightingImport, false);
    }
    [[nodiscard]] bool TakeLightingExport() noexcept
    {
      return std::exchange(mLightingExport, false);
    }
    /** The Lighting panel's sky Import / Export (FAFME's `.scmskybox`), taken by the app. */
    [[nodiscard]] bool TakeSkyboxImport() noexcept
    {
      return std::exchange(mSkyboxImport, false);
    }
    [[nodiscard]] std::string TakeLightingFromMap()
    {
      return std::exchange(mLightingFromMap, std::string());
    }
    [[nodiscard]] bool TakeSkyboxExport() noexcept
    {
      return std::exchange(mSkyboxExport, false);
    }
    /**
     * A test run: the open map (as saved) played solo for 8 s of game time, then stopped; the Lua errors and other
     * warnings logged meanwhile join the Check's findings (`/testrun` for test runs).
     */
    void RequestTestRun() noexcept
    {
      mShowCheck = true;
      mTestRunStep = 1;
    }
    /** Runs the check at the next frame (`/check` for test runs). */
    void RequestCheck() noexcept
    {
      mShowCheck = true;
      mRunCheck = true;
    }
    /** Test runs (`/unitspawn <group>`): the selected unit's Spawns choice set to that group, as a pick in its list. */
    void TestUnitSpawn(
      const std::string& group
    )
    {
      mSpawnAsk = group;
    }
    bool& ShowLog() noexcept
    {
      return mShowLog;
    }
    bool& ShowDemo() noexcept
    {
      return mShowDemo;
    }
    bool& PanelsWhilePlaying() noexcept
    {
      return mPanelsWhilePlaying;
    }
    /** View > Reset layout: the workspace shown now gets its first layout again. */
    void ResetLayout() noexcept
    {
      mResetLayout = true;
    }
    /**
     * Shows workspace `workspace` (ui/EdWorkspaces): its own layout and the panels it showed last (its first ones
     * the first time). The panels shown in the one left are kept for it.
     */
    void SwitchWorkspace(int workspace);
    /**
     * The start screen (design §8 Files) over the panels: `page` 0 Home, 1 On this computer, 2 FAF vault. File > Open
     * and every "Open a map..." show its pages; a map opening, a workspace tab or Continue put it away.
     */
    void ShowHome(int page = 0) noexcept;
    void HideHome() noexcept
    {
      mShowHome = false;
    }
    [[nodiscard]] bool HomeShown() const noexcept
    {
      return mShowHome;
    }
    /** Settings > General: the start screen when the editor starts; its FAF vault rows. */
    bool& HomeAtStart() noexcept
    {
      return mHomeAtStart;
    }
    bool& HomeVaultItems() noexcept
    {
      return mHomeVaultItems;
    }
    bool& ShowHistory() noexcept
    {
      return mShowHistory;
    }
    bool& ShowProblems() noexcept
    {
      return mShowProblems;
    }
    /** The Problems panel shown and in front (the status bar's count). */
    void OpenProblems() noexcept;
    /** Help (ui/EdHelpWindow.cpp): the Help window on a topic (ui/EdHelpTopics), F1's topic, the tour. */
    void OpenHelp(const std::string& topic);
    [[nodiscard]] std::string HelpTopicUnderMouse() const;
    void StartTour();
    /** The scene's selection, said in the status bar as a count ("3 markers"). */
    void SetStatusSelection(
      std::string text
    )
    {
      mStatusSelection = std::move(text);
    }
    /** The ids of the panels shown now (PanelId), in the shell's order. */
    [[nodiscard]] std::vector<std::string> ShownPanelIds() const;
    /** File > Save as new map folder: the dialog asks for the folder's name. */
    void OpenSaveAs() noexcept
    {
      mOpenSaveAs = true;
    }
    /** File > New map: the dialog asks for the map's name, size, players, height and sea. */
    void OpenNewMap() noexcept
    {
      mOpenNewMap = true;
    }
    /** File > Package for the FAF vault: the checks, the file list, then the zip. */
    void OpenPackage() noexcept
    {
      mOpenPackage = true;
    }
    void RequestExit() noexcept
    {
      mExit = true;
    }

    [[nodiscard]] EdTools& Tools() noexcept
    {
      return mTools;
    }

    /** A toolbar button the app carries out (it owns saving and the scene's undo); taken once per frame. */
    enum class Command
    {
      None,
      Save,
      Undo,
      Redo,
    };
    [[nodiscard]] Command TakeCommand() noexcept
    {
      return std::exchange(mCommand, Command::None);
    }

    /** File > Exit was chosen. */
    [[nodiscard]] bool ExitRequested() const noexcept
    {
      return mExit;
    }

    /** Where the game's picture goes: the dock layout's middle (x, y, width, height in the panels' pixels). */
    [[nodiscard]] ImVec4 GameViewRect() const noexcept
    {
      return mGameView;
    }

    /**
     * The command registry and the title row's menus (EdApp owns both): the title row draws the menus and the command
     * palette runs the commands. Without them the shell draws no title row.
     */
    void SetCommands(
      EdCommands* commands,
      const std::vector<EdMenu>* menus
    ) noexcept
    {
      mCommands = commands;
      mMenus = menus;
    }

  private:
    EdCommands* mCommands = nullptr;
    const std::vector<EdMenu>* mMenus = nullptr;
    /** The active workspace's first layout (its EdWorkspace's places) in its dock space. */
    void BuildDefaultLayout(unsigned int dockspaceId);
    /** Shows exactly these panels (ids), hides the others. */
    void ShowPanels(const std::vector<std::string>& ids);
    /** Each panel's window name (as its Begin has it) and its shown flag. */
    struct PanelFlag
    {
      const char* window;
      bool EdShell::* shown;
    };
    static const std::vector<PanelFlag>& PanelFlags();
    /** The workspaces whose dock space has been laid out this run. */
    std::vector<bool> mWorkspaceBuilt;
    bool mWorkspaceStarted = false;
    std::string mStatusSelection;
    // The start screen (ui/EdHomePage.cpp).
    void DrawHome(float top, float bottom);
    void DrawHomePage();
    void DrawHomeRecent();
    void DrawHomeVault(bool loggedIn);
    void DrawHomeSearch(bool loggedIn);
    /** View > History (ui/EdHistoryPanel.cpp): the edits, a click goes back or forward to one. */
    void DrawHistoryPanel();
    bool mShowHistory = false;
    void DrawHelpWindow();
    /** The Problems panel (ui/EdProblemsPanel.cpp): the check's findings and the log's warnings in one list. */
    void DrawProblemsPanel();
    /** A check finding's place: its script line, its prop's place, or its marker selected and framed. */
    void GoToIssue(const CheckIssue& issue);
    bool mShowProblems = false;
    bool mFocusProblems = false;
    unsigned mProblemLevels = 0x7U;
    unsigned mProblemSources = 0x3U;
    void DrawTour();
    bool mShowHelp = false;
    bool mHelpFront = false;
    std::string mHelpTopic = "view";
    char mHelpSearch[96] = {};
    int mTourStep = -1;
    bool mShowHome = false;
    bool mHomeFocusSearch = false;
    bool mHomeFront = false;
    int mHomePage = 0;
    char mHomeSearch[128] = {};
    std::string mHomeSearchAsked;
    double mHomeTypedAt = 0.0;
    bool mHomeAtStart = true;
    bool mHomeVaultItems = true;
    /** The toolbar under the title row: Play/Stop (F5) first, then New, Open, Save, Save as, Undo, Redo, and the open
     * map. `top` is where it starts (the title row's height). */
    EdMapBrowser mBrowser;
    void DrawToolbar(float height, float top);
    Command mCommand = Command::None;
    void DrawToolsPanel();
    void DrawMapPanel();
    /** The Play setup (opponents, AI, faction, start slot, fog, prebuilt units) and the in-play view switches. */
    void DrawPlaySetup();
    char mProfileName[64]{};
    /** The open map: title, kind as chips, counts as cards, layers with thumbnails, armies, files
     * (ui/EdInfoPanels.cpp). */
    void DrawInfoPanel();
    /** The map's markers as a tree by group and type: select, go to, hide a type (ui/EdInfoPanels.cpp). */
    void DrawMarkersPanel();
    /** The Check: runs the map's checks and lists what they found; a click goes to it (ui/EdInfoPanels.cpp). */
    void DrawCheckPanel();
    /** The map's `_script.lua`, edited: Apply makes the change one undo step, Check compiles it (ui/EdInfoPanels.cpp).
     */
    void DrawScriptPanel();
    /** The map's lighting, edited live; Import / Export of FAFME's `.scmlighting` (ui/EdInfoPanels.cpp). */
    void DrawLightingPanel();
    /** The Markers panel's chains: made, renamed, deleted, their markers added, ordered, taken out
     * (ui/EdInfoPanels.cpp). */
    void DrawChains();
    /** The player slots and extra armies as cards, and the chosen army's settings (ui/EdArmiesPanel.cpp). */
    void DrawArmiesPanel();
    void DrawPropertiesPanel();
    /** A selected unit's group, what becomes of it in a game, its wreck's value, and the wreck switch
     * (ui/EdUnitFatePanel.cpp). */
    void DrawUnitFate(const SelectionProperties& unit);
    /** The game's own units selected in front of a play: state, toggles, enhancements, actions
     * (ui/EdLiveUnitPanel.cpp). */
    void DrawLiveUnitPanel();
    /** The unit's "Spawns" choice: the start groups, or a group a lobby setting makes the script create. */
    void DrawUnitSpawn(
      const SelectionProperties& unit,
      const UnitGroup& root,
      const std::string& current,
      bool civilian,
      const std::string& fateText,
      const std::vector<std::string>& lobbyLines
    );
    std::string mSpawnAsk;
    /** The Adaptive tool's panel: the files, the players' resources and the crazyrush lists (ui/EdAdaptivePanel.cpp).
     */
    void DrawAdaptivePanel();
    /** The Adaptive Map window: the lobby's options, each with its choices and what they put on the map
     * (ui/EdAdaptiveWindow.cpp). */
    void DrawAdaptiveWindow();
    void DrawAdaptiveOption(
      const AdaptiveOption& option,
      const std::vector<LobbyOptionInfo>& lobby,
      const AdaptiveTables& tables,
      const std::vector<std::string>& selectedMass,
      const std::vector<std::string>& selectedHydro,
      const std::vector<std::string>& selectedUnits,
      const UnitGroup& army
    );
    bool mShowAdaptiveWindow = false;
    bool mEditorViewInPlay = false;
    float mUiScale = 1.0f;
    /** The Properties panel's prop browser: open, its search, and a test run's click on its first tile. */
    bool mPropBrowserOpen = false;
    char mPropBrowserFilter[64]{};
    bool mTestPropSwap = false;
    void DrawPropBrowser(const std::string& current, int selected);

  public:
    /** Test runs (`/propswap <part>`): the prop browser opened on that search, its first tile clicked once. */
    void TestPropSwap(
      const std::string& filter
    )
    {
      mPropBrowserOpen = true;
      mTestPropSwap = true;
      (void)std::snprintf(mPropBrowserFilter, sizeof(mPropBrowserFilter), "%s", filter.c_str());
    }

  private:
    /** The toolbar's UI scale buttons; returns their width when `measure` (nothing drawn). */
    float DrawUiScaleButtons(bool measure);
    bool mFocusAdaptiveWindow = false;
    /** The option the window shows (its key; "#players" for the players' resources). */
    std::string mAdaptivePick;
    /** The window's preview of a game: on, each option's picked choice (index into its values), and the players in it
     * (0: all). */
    bool mAdaptivePreview = false;
    std::map<std::string, int> mAdaptivePreviewPicks;
    int mAdaptivePreviewPlayers = 0;
    /** What the preview's hidden things were worked out for (cleared when the preview ends). */
    std::string mAdaptivePreviewDone;
    /** Works out what the preview hides and gives it to the view (ui/EdAdaptiveWindow.cpp). */
    void UpdateAdaptivePreview(
      const std::vector<AdaptiveOption>& options,
      const std::vector<LobbyOptionInfo>& lobby,
      const AdaptiveTables& tables
    );
    /** View > Script on one of the map's Lua files (0 script, 1 lobby options, 2 adaptive tables). */
    void ShowLuaFile(
      int file
    )
    {
      mScriptFile = file;
      mShowScript = true;
      mFocusScript = true;
    }
    bool mShowProperties = true;
    bool mPropertiesPlaced = false;
    /** The panel's copy of the values while a field is held or typed in; sent as one edit when it lets go. */
    SelectionProperties mPropertiesEdit;
    bool mPropertiesEditing = false;
    char mPropertiesName[128]{};
    std::vector<std::string> mPropertiesFields;
    bool mShowArmies = false;
    bool mFocusArmies = false;
    std::string mArmySelected;
    char mNewExtraArmy[64]{};
    ArmySettings mArmyEdit;
    std::string mArmyEditName;
    bool mArmyEditing = false;
    char mNewChainName[128]{};
    bool mShowLighting = false;
    bool mShowMaterialEditor = false;
    bool mShowParticleEditor = false;
    bool mShowParticleBrowser = false;
    LightingState mLighting;
    LightingState mLightingBefore;
    bool mLightingEditing = false;
    bool mLightingImport = false;
    bool mLightingExport = false;
    bool mSkyboxImport = false;
    /** The Lighting panel's "from another map": the scenario picked, taken by the app. */
    std::string mLightingFromMap;
    char mLightingFromFilter[64]{};
    bool mSkyboxExport = false;
    bool mShowScript = false;
    bool mFocusScript = false;
    std::string mScriptBuffer;
    std::string mScriptFor;
    /** The Script panel's file: 0 `_script.lua`, 1 `_options.lua`, 2 `_tables.lua` (adaptive maps). */
    int mScriptFile = 0;
    std::string mScriptMessage;
    int mScriptErrorLine = 0;
    void RunCheck();
    /** The pathing part of the Check: what each start reaches by land, and the overlay. */
    void CheckPathing(const MarkerCheckInput& input);
    bool mShowCheck = true;
    std::vector<CheckIssue> mCheckIssues;
    bool mCheckRan = false;
    bool mRunCheck = false;
    void UpdateTestRun();
    /** 0 idle, 1 asked, 2 starting, 3 playing, 4 stopping. */
    int mTestRunStep = 0;
    double mTestRunStarted = 0.0;
    std::string mTestRunMap;
    std::vector<CheckIssue> mTestRunIssues;
    bool mTestRunDone = false;
    std::string mTestRunSummary;
    std::string mCheckedPath;
    bool mShowMarkers = true;
    bool mFocusMarkers = false;
    char mMarkerFilter[64]{};
    void DrawSaveAsDialog();
    bool mOpenSaveAs = false;
    char mSaveAsName[128]{};
    void DrawNewMapDialog();
    void DrawPackageDialog();
    bool mOpenPackage = false;
    PackagePlan mPackagePlan;
    std::string mPackageMessage;
    bool mOpenNewMap = false;
    NewMapSettings mNewMap;
    char mNewMapTitle[128]{};
    char mNewMapFolder[128]{};
    bool mNewMapFolderEdited = false;
    void DrawStatusBar();

    EdLog& mLog;
    EdPlay& mPlay;
    EdDocument& mDocument;
    std::string mApi;
    std::string mAdapter;
    EdTools mTools;
    EdMaterialEditor mMaterialEditor;
    EdParticleEditor mParticleEditor;
    ImVec4 mGameView{0.0f, 0.0f, 0.0f, 0.0f};
    /** The document path the Info tab was last brought to the front for. */
    std::string mInfoShownFor;
    bool mExit = false;
    bool mShowDemo = false;
    bool mShowTools = true;
    bool mShowMap = true;
    bool mShowInfo = true;
    bool mShowLog = true;
    bool mPanelsWhilePlaying = true;
    bool mLayoutBuilt = false;
    bool mResetLayout = false;
  };
} // namespace faf::editor
