#pragma once

#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <utility>

#include "editor/tools/EdMeshImport.h"
#include "editor/ui/EdFieldsPanel.h"
#include "editor/doc/EdLuaApi.h"
#include "editor/EdTools.h"
#include "editor/tools/EdMeshData.h"
#include "editor/doc/EdAdaptiveModel.h"
#include "editor/tools/EdChecks.h"
#include "editor/tools/EdTerrainChecks.h"
#include "editor/doc/EdLighting.h"
#include "editor/doc/EdLooks.h"
#include "editor/doc/EdNewMap.h"
#include "editor/doc/EdPackage.h"
#include "editor/doc/EdSaveFile.h"
#include "editor/tools/EdResize.h"
#include "editor/ui/EdMapBrowser.h"
#include "editor/ui/EdGenerate.h"
#include "editor/ui/EdLayoutPanel.h"
#include "editor/ui/EdMissionPanel.h"
#include "editor/ui/EdModPanel.h"
#include "editor/ui/EdAssetBrowser.h"
#include "editor/ui/EdModHost.h"
#include "editor/ui/EdUnitViewer.h"
#include "editor/ui/EdUnitLabPanel.h"
#include "editor/ui/EdPathsPanel.h"
#include "editor/ui/EdUnitWizardPanel.h"
#include "editor/tools/EdDetailPass.h"
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
    bool& ShowLayers() noexcept
    {
      return mShowLayers;
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
    /** The Generate workspace's terrain graph and its three panels. */
    [[nodiscard]] EdGenerate& Generate() noexcept
    {
      return mGenerate;
    }
    /** Shows the terrain graph's panels (Terrain > Generate). */
    void ShowGenerate() noexcept
    {
      mShowGenNodes = mShowGenGraph = mShowGenInspector = true;
    }
    [[nodiscard]] bool GenerateShown() const noexcept
    {
      return mShowGenGraph || mShowGenNodes || mShowGenInspector;
    }
    /** The Layout workspace's drawing and its two panels. */
    [[nodiscard]] EdLayoutPanel& LayoutPanel() noexcept
    {
      return mLayoutPanel;
    }
    /** Shows the layout's panels (Terrain > Layout canvas). */
    void ShowLayout() noexcept
    {
      mShowLayoutLayers = mShowLayoutCanvas = mShowLayoutStarts = true;
    }
    [[nodiscard]] EdMissionPanel& MissionPanel() noexcept
    {
      return mMissionPanel;
    }
    [[nodiscard]] EdPathsPanel& PathsPanel() noexcept
    {
      return mPathsPanel;
    }
    [[nodiscard]] EdUnitWizardPanel& UnitWizard() noexcept
    {
      return mUnitWizard;
    }
    /** Terrain > Paths: the Paths panel up, editing on the map on. */
    void ShowPaths() noexcept
    {
      mShowPaths = true;
    }
    void ShowDetail() noexcept
    {
      mShowDetail = true;
    }
    /** The Detail pass panel's ask (1 plan, 2 run, 3 measure; 0 none) and its run settings; the app answers with
     * SetDetailText. `environment` empty: the panel wants the map's guess. */
    int TakeDetailAsk(
      DetailRun& run
    ) noexcept
    {
      run = mDetailRun;
      run.only.clear();
      return std::exchange(mDetailAsk, 0);
    }
    void SetDetailText(
      std::string text
    )
    {
      mDetailText = std::move(text);
    }
    /** The map's guessed environment, once a map is open (the panel's default). */
    void SetDetailEnvironment(
      const std::string& environment
    )
    {
      if (!mDetailEnvironmentSet) {
        mDetailRun.environment = environment;
        mDetailEnvironmentSet = true;
      }
    }
    void ResetDetailEnvironment() noexcept
    {
      mDetailEnvironmentSet = false;
    }
    [[nodiscard]] const std::vector<std::string>& DetailClassesOff() const noexcept
    {
      return mDetailClassesOff;
    }
    [[nodiscard]] EdModPanel& ModPanel() noexcept
    {
      return mModPanel;
    }
    void ShowModProject() noexcept
    {
      mShowModProject = mShowUnitLab = true;
    }
    [[nodiscard]] EdUnitLabPanel& UnitLab() noexcept
    {
      return mUnitLab;
    }
    [[nodiscard]] EdAssetBrowser& Assets() noexcept
    {
      return mAssets;
    }
    void ShowAssets() noexcept
    {
      mShowAssets = true;
    }
    /** Shows the Mission workspace's Stages and Strings. */
    void ShowMission() noexcept
    {
      mShowMissionStages = mShowMissionStrings = mShowMissionRun = mShowMissionBases = mShowMissionPlatoons = true;
    }
    [[nodiscard]] bool LayoutShown() const noexcept
    {
      return mShowLayoutLayers || mShowLayoutCanvas || mShowLayoutStarts;
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
    /** The Looks section's asks, taken by the app: try one, apply or revert the one tried, save or delete one. */
    struct LookRequest
    {
      enum class What
      {
        None,
        Try,
        Apply,
        Revert,
        Save,
        Delete,
      };
      What what = What::None;
      std::string id; // a map's scenario path, or "mine:<name>"
      unsigned sections = kLookAll;
      float blend = 1.0f;
      std::string name; // Save: the new look's name
    };
    [[nodiscard]] bool TakeLookRequest(
      LookRequest& request
    )
    {
      request = std::exchange(mLookRequest, LookRequest{});
      return request.what != LookRequest::What::None;
    }
    void RequestLook(
      LookRequest request
    )
    {
      mLookRequest = std::move(request);
    }
    /** What the app says of the looks: the one tried (empty: none), its words, the user's own looks. */
    void SetLookState(
      std::string tried,
      std::string status
    )
    {
      mLookTried = std::move(tried);
      mLookStatus = std::move(status);
    }
    void SetMyLooks(
      std::vector<std::string> names
    )
    {
      mMyLooks = std::move(names);
    }
    /** A look's colours once it has been read (sky horizon and zenith, sun, water), for its row. */
    struct LookSwatch
    {
      float colours[4][3]{};
    };
    void SetLookSwatch(
      const std::string& id,
      const LookSwatch& swatch
    )
    {
      mLookSwatches[id] = swatch;
    }
    /** A look's picture (this map painted under its light, FAF Studio's look thumbnails); 0 = it can't be drawn. */
    void SetLookThumb(
      const std::string& id,
      const std::uint64_t image
    )
    {
      mLookThumbs[id] = image;
    }
    /** The next look whose row is on screen without its picture. */
    [[nodiscard]] bool TakeLookThumbWanted(
      std::string& id
    )
    {
      if (mLookThumbWanted.empty()) {
        return false;
      }
      id = mLookThumbWanted.front();
      mLookThumbWanted.erase(mLookThumbWanted.begin());
      return true;
    }
    /** Redraw pictures was pressed (the map changed under them). */
    [[nodiscard]] bool TakeLookThumbsRedraw() noexcept
    {
      const bool redraw = mLookThumbsRedraw;
      mLookThumbsRedraw = false;
      return redraw;
    }
    /** Lets every look picture go (another map, or a redraw). */
    void ClearLookThumbs();
    [[nodiscard]] bool LookTrying() const noexcept
    {
      return !mLookTried.empty();
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
    /** The Check's settings panel's values (test runs: `/checksettings`). */
    void SetCheckSettings(
      const TerrainCheckSettings& settings,
      const int unitClass,
      const bool validators,
      const bool symmetry,
      const bool paths
    ) noexcept
    {
      mTerrainCheck = settings;
      mTerrainCheckClass = unitClass;
      mCheckValidators = validators;
      mCheckSymmetry = symmetry;
      mCheckPaths = paths;
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
    /** After a named layout is read: the active workspace shows the panels the layout lists for it. */
    void ApplyShownPanels();
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
    bool& ShowDebugger() noexcept
    {
      return mShowDebugger;
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
    /** A Check fix asked for: the marker and where it goes (taken once each). */
    [[nodiscard]] bool TakeCheckFix(
      std::string& marker,
      float& x,
      float& z
    )
    {
      if (mCheckFixes.empty()) {
        return false;
      }
      marker = mCheckFixes.front().marker;
      x = mCheckFixes.front().fixX;
      z = mCheckFixes.front().fixZ;
      mCheckFixes.erase(mCheckFixes.begin());
      return true;
    }
    /** File > Save as new map folder: the dialog asks for the folder's name. */
    void OpenSaveAs() noexcept
    {
      mOpenSaveAs = true;
    }
    /** Map > Resize: the dialog asks for the new size, the way (canvas or scale) and the new folder. */
    void OpenResize() noexcept
    {
      mOpenResize = true;
    }
    struct ResizeRequest
    {
      ResizeOptions options;
      /** The new map's folder in the vault's maps (the new size is a copy; the map open now stays as it is). */
      std::string folder;
      /** kNewMapSizes' indexes of the new width and depth. */
      int widthIndex = 2;
      int depthIndex = 2;
    };
    /** The dialog's Resize, once. */
    [[nodiscard]] bool TakeResize(
      ResizeRequest& out
    ) noexcept
    {
      if (!mResizeAsked) {
        return false;
      }
      mResizeAsked = false;
      out = mResizeRequest;
      return true;
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
      mModHost.Attach(commands);
    }
    [[nodiscard]] EdFieldsPanel& Fields() noexcept
    {
      return mFieldsPanel;
    }
    /** The Images panel's asks: export or import one picture ("heights", "preview", "mask<n>", "water<n>", "all"). */
    struct ImageAsk
    {
      std::string what;
      bool exportIt = true;
    };
    [[nodiscard]] bool TakeImageAsk(
      ImageAsk& out
    )
    {
      if (mImageAsks.empty()) {
        return false;
      }
      out = mImageAsks.front();
      mImageAsks.erase(mImageAsks.begin());
      return true;
    }
    /** The Images panel's previews (an ImTextureID each, 0 = none): the rows on screen ask, the app makes them. */
    void SetImageThumb(
      const std::string& what,
      const std::uint64_t image
    )
    {
      mImageThumbs[what] = image;
    }
    [[nodiscard]] bool TakeImageThumbWanted(
      std::string& what
    )
    {
      if (mImageThumbWanted.empty()) {
        return false;
      }
      what = mImageThumbWanted.front();
      mImageThumbWanted.erase(mImageThumbWanted.begin());
      return true;
    }
    /** Lets every preview go (the map changed under them). */
    void ClearImageThumbs();
    void SetImageStatus(
      std::string status
    )
    {
      mImageStatus = std::move(status);
    }
    /** The Mesh terrain panel's import ask. */
    struct MeshAsk
    {
      bool import = false;
      std::string file;
      MeshImportOptions options;
      /** The scenario names the manifest: the map becomes a mesh terrain map. */
      bool makeMeshMap = false;
    };
    /** The mesh terrain view's mode (0 the height field, 1 the mesh, 2 both) and its other asks. */
    int mMeshMode = 1;
    bool mMeshMakeMap = true;
    int mMeshAskMore = 0; // 1 load again, 2 check, 3 save the manifest, 4 unset, 5 set, 6 sync map, 7 new
    int mMeshSetting = 0; // the settings list's chosen row (edmesh::SettingKeys)
    edmesh::MeshMap* mMeshMapView = nullptr;
    int mMeshMaterial = 0;
    void SetMeshMapView(
      edmesh::MeshMap* mesh
    ) noexcept
    {
      mMeshMapView = mesh;
    }
    std::vector<std::string> mMeshFindings;
    [[nodiscard]] int MeshMode() const noexcept
    {
      return mMeshMode;
    }
    [[nodiscard]] int TakeMeshMore() noexcept
    {
      return std::exchange(mMeshAskMore, 0);
    }
    /** Test runs: the panel's Load / Check / Save / Unset / Set (1..5). */
    void AskMeshMore(
      const int ask
    ) noexcept
    {
      mMeshAskMore = ask;
    }
    void SetMeshFindings(
      std::vector<std::string> findings
    )
    {
      mMeshFindings = std::move(findings);
    }
    /** An import asked for from outside the panel (`/meshtest`), as its Import button asks after the file dialog. */
    void AskMeshImport(
      const std::string& file,
      const bool makeMeshMap
    )
    {
      mMeshAsk = MeshAsk{};
      mMeshAsk.import = true;
      mMeshAsk.file = file;
      mMeshAsk.makeMeshMap = makeMeshMap;
    }
    [[nodiscard]] bool TakeMeshAsk(
      MeshAsk& out
    )
    {
      if (!mMeshAsk.import) {
        return false;
      }
      out = mMeshAsk;
      mMeshAsk = MeshAsk{};
      return true;
    }
    void SetMeshStatus(
      std::string status
    )
    {
      mMeshStatus = std::move(status);
    }
    [[nodiscard]] bool MeshShown() const noexcept
    {
      return mMeshShown;
    }
    void SetMeshShown(
      const bool shown
    ) noexcept
    {
      mMeshShown = shown;
    }
    [[nodiscard]] EdModHost& ModHost() noexcept
    {
      return mModHost;
    }
    void ShowEditorMods() noexcept
    {
      mShowEditorMods = true;
    }
    [[nodiscard]] EdUnitViewer& UnitViewer() noexcept
    {
      return mUnitViewer;
    }
    void ShowUnitViewer() noexcept
    {
      mShowUnitViewer = true;
    }
    /** Where the view's menu was opened, and what stands there (the app fills it from the view). */
    struct ViewMenuPoint
    {
      bool valid = false;
      float x = 0.0f;
      float z = 0.0f;
      float height = 0.0f;
      std::string what;
      std::string marker;
      std::string markerType;
      std::string unitArmy;
      std::string unitName;
      std::vector<std::string> armies;              // for Set army
      std::vector<std::vector<std::string>> groups; // the unit's army's groups, for Move to group
      std::string unitToPlace;                      // the Units tool's unit
      std::string propToPlace;                      // the Props tool's prop
    };
    /** An entry of the menu that acts at its point (the app runs it). */
    struct ViewMenuAction
    {
      enum class Kind
      {
        None,
        PlaceMarker, // arg: the type
        AddArea,
        PlaceUnit,
        PlaceProp,
        FocusHere,
        SnapToGrid,
        SetArmy, // arg: the army
        MoveToGroup,
      } kind = Kind::None;
      std::string arg;
      std::vector<std::string> path;
    };
    /** The view's context menu, at the mouse, the next frame (ViewMenuCommands). */
    void OpenViewMenu(
      const bool selection
    )
    {
      OpenViewMenu(selection, ViewMenuPoint());
    }
    void OpenViewMenu(
      const bool selection,
      ViewMenuPoint point
    ) noexcept
    {
      mViewMenuAsk = true;
      mViewMenuSelection = selection;
      mViewMenuPoint = std::move(point);
    }
    [[nodiscard]] bool TakeViewMenuAction(
      ViewMenuPoint& point,
      ViewMenuAction& action
    )
    {
      if (mViewMenuAction.kind == ViewMenuAction::Kind::None) {
        return false;
      }
      point = mViewMenuPoint;
      action = std::exchange(mViewMenuAction, {});
      return true;
    }

  private:
    EdCommands* mCommands = nullptr;
    /** A list row's Delete: edit.delete once its selection has been made (a couple of frames later). */
    bool mDeleteAsked = false;
    std::vector<ImageAsk> mImageAsks;
    MeshAsk mMeshAsk;
    int mDeleteWait = 0;
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

  public:
    /** A panel's shown flag by its id (`Properties`, `MissionStages`, `UnitLab`), or null. */
    [[nodiscard]] bool* PanelShown(std::string_view id);
    /** Every panel's window name (as its Begin has it), for the QA runs that walk the panels. */
    [[nodiscard]] std::vector<std::string> PanelWindows() const;
    /** Shows or hides a panel by its window name; whether it was shown before. */
    bool ShowPanelWindow(const std::string& window, bool on);

  private:
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
    // The Script panel's check as you type: the text it last checked, when it was last typed in, the typos found.
    std::size_t mScriptCheckedHash = 0;
    double mScriptTypedAt = 0.0;
    std::vector<EdLuaTypo> mScriptTypos;
    void DrawHelpWindow();
    /** The Debugger panel (ui/EdDebuggerPanel.cpp): arm, breakpoints, a pause's place, locals, watches, stack. */
    void DrawDebuggerPanel();
    bool mShowDebugger = false;
    bool mShowGenNodes = false;
    float mCornerBottom = 0.0f; // the view's top-right buttons' lower edge (the compass goes under them)
    bool mShowGenGraph = false;
    bool mShowGenInspector = false;
    bool mShowLayoutLayers = false;
    bool mShowLayoutCanvas = false;
    bool mShowLayoutStarts = false;
    bool mShowMissionStages = false;
    bool mShowMissionStrings = false;
    bool mShowMissionRun = false;
    bool mShowMissionBases = false;
    bool mShowMissionPlatoons = false;
    bool mShowModProject = false;
    bool mShowUnitLab = false;
    bool mShowUnitWizard = false;
    bool mShowAssets = false;
    bool mShowEditorMods = false;
    bool mShowUnitViewer = false;
    bool mShowFields = false;
    bool mShowStatistics = false;
    bool mShowImages = false;
    bool mShowMesh = false;
    bool mShowPaths = false;
    bool mShowDetail = false;
    void DrawDetailPanel();
    DetailRun mDetailRun;
    bool mDetailEnvironmentSet = false;
    std::vector<std::string> mDetailClassesOff;
    std::string mDetailText;
    int mDetailAsk = 0; // 1 plan, 2 run, 3 measure
    char mMeshFile[512] = {};
    MeshImportOptions mMeshOptions;
    bool mMeshShown = true;
    std::string mMeshStatus;
    std::string mImageStatus;
    std::map<std::string, std::uint64_t> mImageThumbs;
    std::vector<std::string> mImageThumbWanted;
    EdFieldsPanel mFieldsPanel;
    bool mViewMenuAsk = false;
    ViewMenuPoint mViewMenuPoint;
    ViewMenuAction mViewMenuAction;
    char mSaveAsParent[512] = {};
    /** Map info's fields being typed in: key -> text (the scenario's value otherwise). */
    std::map<std::string, std::string> mInfoEdits;
    void DrawMapInfoFields();
    bool mViewMenuSelection = false;
    void DrawViewMenu();
    bool mDebugWasPaused = false;
    char mWatchInput[160] = {};
    std::vector<std::string> mWatches;
    /** The Effects workspace's stage: the effect's view where the map view is. */
    void DrawEffectStage();
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
    /** The start screen's tip (FAF Studio's tips.lua): its number, -1 until the first is picked by the clock. */
    int mHomeTip = -1;
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
    /** The tool strip down the window's left edge, `width` wide, between the toolbar and the status bar. */
    void DrawToolStrip(float top, float width, float bottom);
    /** The first frame: the first workspace's panels' saved places under the names their tabs have now. */
    void CarryPanelPlaces();
    /** The view's overlays: the camera and show pills at its top-left, the tool's line at its bottom. */
    void DrawViewOverlays();
    /** The status bar's height at the current scale. */
    [[nodiscard]] static float StatusBarHeight();
    bool mPanelPlacesCarried = false;
    std::vector<std::string> mFrontPanels; // a layout just built: the windows to bring in front once
    bool mFocusTools = false; // the strip picked a tool: the Tools panel comes forward
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
    /** The Markers panel's Areas section (the save's AREA_n rectangles). */
    void DrawAreasSection();
    /** View > Statistics: the map's counts and each start's resources and reclaim (ui/EdStatsPanel.cpp). */
    void DrawStatisticsPanel();
    void DrawImagesPanel();
    void DrawMeshPanel();
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
    WaterState mLightingWaterBefore; // the water, when the lighting sun turns its sun too
    bool mLightingMovedWater = false;
    // The Sky and Reflection cubes sections: the panel's copies while a control is held, and their befores.
    SkyboxState mSky;
    SkyboxState mSkyBefore;
    bool mSkyEditing = false;
    std::vector<std::pair<std::string, std::string>> mCubes;
    char mCubeName[64]{};
    char mCubePath[256]{};
    void DrawSkyEditor();
    /** The strategic view's settings (FAF Studio's panel): contours, imager offset, the five height colours. */
    void DrawStrategicView();
    void DrawCubes();
    bool mLightingImport = false;
    bool mLightingExport = false;
    bool mSkyboxImport = false;
    /** The Lighting panel's "from another map": the scenario picked, taken by the app. */
    std::string mLightingFromMap;
    char mLightingFromFilter[64]{};
    LookRequest mLookRequest;
    unsigned mLookSections = kLookAll;
    float mLookBlend = 1.0f;
    bool mLookTryOnClick = true;
    std::string mLookChosen;
    std::string mLookTried;
    std::string mLookStatus;
    std::vector<std::string> mMyLooks;
    std::map<std::string, LookSwatch> mLookSwatches;
    std::map<std::string, std::uint64_t> mLookThumbs;
    std::vector<std::string> mLookThumbWanted;
    bool mLookThumbsShown = true;
    bool mLookThumbsRedraw = false;
    char mLookSaveName[64]{};
    void DrawLooks();
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

  public:
    /**
     * The Check's resource part through the game's build rules (FAF Studio's validate.lua "blocked"): each mass and
     * hydrocarbon marker tested with its building's footprint (slope, water, playable area, units, props). Set by the
     * app (the view's unit fit).
     */
    std::function<std::vector<CheckIssue>()> resourceFit;

  private:
    /** The pathing part of the Check: what each start reaches by land, and the overlay. */
    void CheckPathing(const MarkerCheckInput& input);
    /** The Check's settings (FAF Studio's terrain checks panel): the terrain checks' thresholds and which parts run. */
    TerrainCheckSettings mTerrainCheck;
    int mTerrainCheckClass = 2;   // 1 small .. 4 experimental: the footprint window 1, 2, 3, 5
    bool mCheckValidators = true; // the resources through the game's build rules
    bool mCheckSymmetry = true;   // markers and props without a partner at their symmetric copies
    bool mCheckPaths = true;      // the kept paths steeper than their grade
    void DrawCheckSettings();
    bool mShowCheck = true;
    std::vector<CheckIssue> mCheckIssues;
    bool mCheckRan = false;
    /** The edits the last check saw; a change runs it again once the edits have rested a second. */
    std::uint64_t mCheckedEdits = 0;
    std::uint64_t mRecheckEdits = 0;
    double mRecheckAt = -1.0;
    void AutoRecheck();
    bool mRunCheck = false;
    void UpdateTestRun();
    /** 0 idle, 1 asked, 2 starting, 3 playing, 4 stopping. */
    int mTestRunStep = 0;
    double mTestRunStarted = 0.0;
    std::string mTestRunMap;
    std::vector<CheckIssue> mTestRunIssues;
    std::vector<CheckIssue> mCheckFixes;
    bool mTestRunDone = false;
    std::string mTestRunSummary;
    std::string mCheckedPath;
    bool mShowMarkers = true;
    bool mFocusMarkers = false;
    char mMarkerFilter[64]{};
    void DrawSaveAsDialog();
    bool mOpenSaveAs = false;
    char mSaveAsName[128]{};
    void DrawResizeDialog();
    bool mOpenResize = false;
    bool mResizeAsked = false;
    ResizeRequest mResizeRequest;
    char mResizeFolder[128]{};
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
    EdGenerate mGenerate;
    EdLayoutPanel mLayoutPanel{mDocument};
    EdMissionPanel mMissionPanel{mDocument};
    EdPathsPanel mPathsPanel{mDocument};
    EdModPanel mModPanel{mDocument};
    EdUnitLabPanel mUnitLab{mModPanel};
    EdUnitWizardPanel mUnitWizard{mModPanel};
    EdAssetBrowser mAssets{mTools};
    EdModHost mModHost{mDocument};
    EdUnitViewer mUnitViewer{mUnitLab, mModPanel};
    ImVec4 mGameView{0.0f, 0.0f, 0.0f, 0.0f};
    /** The document path the Info tab was last brought to the front for. */
    std::string mInfoShownFor;
    bool mExit = false;
    bool mShowDemo = false;
    bool mShowTools = true;
    bool mShowMap = true;
    bool mShowInfo = true;
    bool mShowLayers = true;
    bool mShowLog = true;
    bool mPanelsWhilePlaying = true;
    bool mLayoutBuilt = false;
    bool mResetLayout = false;
  };
} // namespace faf::editor
