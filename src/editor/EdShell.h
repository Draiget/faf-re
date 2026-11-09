#pragma once

#include <string>
#include <utility>

#include "editor/EdTools.h"
#include "editor/tools/EdChecks.h"
#include "editor/doc/EdNewMap.h"
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
    void RunCheck();
    bool mShowCheck = true;
    std::vector<CheckIssue> mCheckIssues;
    bool mCheckRan = false;
    bool mRunCheck = false;
    std::string mCheckedPath;
    bool mShowMarkers = true;
    bool mFocusMarkers = false;
    char mMarkerFilter[64]{};
    void DrawSaveAsDialog();
    bool mOpenSaveAs = false;
    char mSaveAsName[128]{};
    void DrawNewMapDialog();
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
