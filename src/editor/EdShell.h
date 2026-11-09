#pragma once

#include <string>
#include <utility>

#include "editor/EdTools.h"
#include "editor/tools/EdChecks.h"
#include "editor/doc/EdLighting.h"
#include "editor/doc/EdNewMap.h"
#include "editor/doc/EdPackage.h"
#include "imgui.h"

namespace faf::editor
{
  class EdDocument;
  class EdLog;
  class EdPlay;

  /**
   * The editor's panels over the game's frame: the docked panels (tools, map, log) around an empty middle where
   * the game's picture shows through, and the status bar. The window's own menu bar (EdApp.cpp) holds File,
   * View and Play, outside the game's picture, so the game's interface keeps its whole area. While a session
   * runs the panels and the status bar step aside unless "Panels while playing" is on.
   */
  class EdShell
  {
  public:
    EdShell(EdLog& log, EdPlay& play, EdDocument& document);

    /** Builds this frame's UI. */
    void Draw();

    // What the window's menu bar shows and changes.
    bool& ShowTools() noexcept { return mShowTools; }
    bool& ShowMap() noexcept { return mShowMap; }
    bool& ShowInfo() noexcept { return mShowInfo; }
    bool& ShowMarkers() noexcept { return mShowMarkers; }
    bool& ShowCheck() noexcept { return mShowCheck; }
    bool& ShowScript() noexcept { return mShowScript; }
    bool& ShowLighting() noexcept { return mShowLighting; }
    /** The Lighting panel's Import / Export buttons, taken by the app (it asks for the file). */
    [[nodiscard]] bool TakeLightingImport() noexcept { return std::exchange(mLightingImport, false); }
    [[nodiscard]] bool TakeLightingExport() noexcept { return std::exchange(mLightingExport, false); }
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
    bool& ShowLog() noexcept { return mShowLog; }
    bool& ShowDemo() noexcept { return mShowDemo; }
    bool& PanelsWhilePlaying() noexcept { return mPanelsWhilePlaying; }
    void ResetLayout() noexcept { mResetLayout = true; }
    /** File > Save as new map folder: the dialog asks for the folder's name. */
    void OpenSaveAs() noexcept { mOpenSaveAs = true; }
    /** File > New map: the dialog asks for the map's name, size, players, height and sea. */
    void OpenNewMap() noexcept { mOpenNewMap = true; }
    /** File > Package for the FAF vault: the checks, the file list, then the zip. */
    void OpenPackage() noexcept { mOpenPackage = true; }
    void RequestExit() noexcept { mExit = true; }

    [[nodiscard]] EdTools& Tools() noexcept { return mTools; }

    /** A toolbar button the app carries out (it owns saving and the scene's undo); taken once per frame. */
    enum class Command
    {
      None,
      Save,
      Undo,
      Redo,
    };
    [[nodiscard]] Command TakeCommand() noexcept { return std::exchange(mCommand, Command::None); }

    /** File > Exit was chosen. */
    [[nodiscard]] bool ExitRequested() const noexcept { return mExit; }

    /** Where the game's picture goes: the dock layout's middle (x, y, width, height in the panels' pixels). */
    [[nodiscard]] ImVec4 GameViewRect() const noexcept { return mGameView; }

  private:
    void BuildDefaultLayout(unsigned int dockspaceId);
    /** The toolbar over the panels: Play/Stop (F5) first, then New, Open, Save, Save as, Undo, Redo, and the open map. */
    void DrawToolbar(float height);
    Command mCommand = Command::None;
    void HandleKeys();
    void DrawToolsPanel();
    void DrawMapPanel();
    /** The open map: title, kind as chips, counts as cards, layers with thumbnails, armies, files (ui/EdInfoPanels.cpp). */
    void DrawInfoPanel();
    /** The map's markers as a tree by group and type: select, go to, hide a type (ui/EdInfoPanels.cpp). */
    void DrawMarkersPanel();
    /** The Check: runs the map's checks and lists what they found; a click goes to it (ui/EdInfoPanels.cpp). */
    void DrawCheckPanel();
    /** The map's `_script.lua`, edited: Apply makes the change one undo step, Check compiles it (ui/EdInfoPanels.cpp). */
    void DrawScriptPanel();
    /** The map's lighting, edited live; Import / Export of FAFME's `.scmlighting` (ui/EdInfoPanels.cpp). */
    void DrawLightingPanel();
    bool mShowLighting = false;
    LightingState mLighting;
    LightingState mLightingBefore;
    bool mLightingEditing = false;
    bool mLightingImport = false;
    bool mLightingExport = false;
    bool mShowScript = false;
    bool mFocusScript = false;
    std::string mScriptBuffer;
    std::string mScriptFor;
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
    ImVec4 mGameView{0.0f, 0.0f, 0.0f, 0.0f};
    char mMapFilter[64]{};
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
