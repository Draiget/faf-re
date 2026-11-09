#pragma once

#include <string>

namespace faf::editor
{
  class EdLog;
  class EdPlay;

  /**
   * The editor's layout over the game's frame: the menu bar with the play bar (map, Play/Stop, state), the
   * docked panels (tools, map, log) around an empty middle where the game's picture shows through, and the
   * status bar. While a session runs the panels step aside unless "Panels while playing" is on.
   */
  class EdShell
  {
  public:
    EdShell(EdLog& log, EdPlay& play);

    /** Builds this frame's UI. */
    void Draw();

    /** File > Exit was chosen. */
    [[nodiscard]] bool ExitRequested() const noexcept { return mExit; }

  private:
    void BuildDefaultLayout(unsigned int dockspaceId);
    void DrawMenuBar();
    void DrawToolsPanel();
    void DrawMapPanel();
    void DrawStatusBar();

    EdLog& mLog;
    EdPlay& mPlay;
    std::string mApi;
    std::string mAdapter;
    int mTool = 1;
    bool mExit = false;
    bool mShowDemo = false;
    bool mShowTools = true;
    bool mShowMap = true;
    bool mShowLog = true;
    bool mPanelsWhilePlaying = false;
    bool mLayoutBuilt = false;
    bool mResetLayout = false;
  };
} // namespace faf::editor
