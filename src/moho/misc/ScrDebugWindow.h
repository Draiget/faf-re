#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "legacy/containers/List.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "platform/sdl/ToolWindow.h"

namespace moho
{
  class ScrSourceCtrl;
  class ScrWatchCtrl;

  /**
   * VFTABLE: 0x00E07834 (??_7ScrDebugWindow@Moho@@6B@)
   *
   * The Lua script debugger: the File, View and Debug menus and their tools (resume, step,
   * enable, disable and clear breakpoints, find), the game folder's .lua files beside the open
   * sources, and the call stack, locals and globals under them. A wx frame in the binary; Dear
   * ImGui in a window of its own since issue #413, on every platform. The preferences it keeps
   * (Windows.Debug.*, Options.Debug.Files) are the binary's.
   */
  class ScrDebugWindow final : public platform::tools::ToolWindow
  {
  public:
    /**
     * Address: 0x004BC110 (FUN_004BC110, Moho::ScrDebugWindow::ScrDebugWindow)
     *
     * What it does:
     * Builds the debugger at its saved geometry and reopens the saved files; a file that no
     * longer opens leaves the list.
     */
    ScrDebugWindow();
    ~ScrDebugWindow() override;

    /**
     * Address: 0x004BEBE0 (FUN_004BEBE0)
     *
     * What it does:
     * Opens a file in the source tabs and remembers it in Options.Debug.Files.
     */
    bool OpenFile(const fa::string& fileName);

    /**
     * Address: 0x004BECF0 (FUN_004BECF0, OnScriptPause)
     *
     * What it does:
     * Shows where a script stopped: its file at the line, the call stack, the locals of the top
     * frame and the globals; the game view stops taking input until the script goes on. A script
     * that stopped where no file opens is resumed.
     */
    void OnScriptPause(const fa::string& sourceName, int sourceLine);

    // ScrDebugHooks.h's sScrDebugWindowPostPause, from the paused script's thread: OnScriptPause
    // runs on the main thread (Tick), as the binary's ScrPauseEvent went through AddPendingEvent.
    void PostPause(const fa::string& sourceName, int sourceLine);

    // SCR_DestroyDebugWindow's request: the window goes at its next Tick.
    void RequestDestroy()
    {
      mDestroyRequested = true;
    }

    // The menu and tool commands (0x004BF120 .. 0x004BF730).
    void OnCloseFile();
    void OnCloseAllFiles();
    void OnReloadAll();
    void OnGotoLine();
    void OnFind();
    void OnFindNext();
    void OnFindPrevious();
    void OnStep();
    void OnResume();
    void OnEnableBreakpoints();
    void OnDisableBreakpoints();
    void OnClearBreakpoints();
    void OnCallStackSelected(int index);
    void OnSourceFileActivated(const std::string& diskPath);

  protected:
    void Tick() override;
    void Draw() override;
    /**
     * Address: 0x004C0100 (FUN_004C0100, OnCloseWindow)
     *
     * What it does:
     * Closing the window ends the debugger (SCR_DestroyDebugWindow).
     */
    void OnCloseRequested() override;

  private:
    struct CallStackRow
    {
      std::string source;
      std::string function;
      std::string line;
    };

    // A folder of the source tree, listed the first time it opens (wxGenericDirCtrl).
    struct FolderNode
    {
      std::string path;
      std::string name;
      bool listed = false;
      std::vector<std::unique_ptr<FolderNode>> folders;
      std::vector<std::string> files; // *.lua names
    };

    void DrawMenuBar();
    void DrawToolBar();
    void DrawSourceTree(FolderNode& folder);
    void DrawGotoPopup();
    void HandleShortcuts();
    void SaveGeometry();
    static void ListFolder(FolderNode& folder);

    std::uint32_t mThreadId; // the creating thread
    std::unique_ptr<ScrSourceCtrl> mSourceCtrl;
    std::unique_ptr<ScrWatchCtrl> mLocals;
    std::unique_ptr<ScrWatchCtrl> mGlobals;
    std::vector<CallStackRow> mCallStack;
    int mCallStackSelection = -1;
    int mStackWidths[3];
    fa::string mFindString;
    std::array<char, 256> mFindText{};
    fa::list<fa::string> mRecentFiles; // Options.Debug.Files
    FolderNode mSourceRoot;
    float mVerticalSash;   // the source tree's width
    float mHorizontalSash; // the sources' height
    bool mOpenGoto = false;
    std::array<char, 32> mGotoText{};
    bool mDestroyRequested = false;
    int mSavedX = -1;
    int mSavedY = -1;
    int mSavedWidth = -1;
    int mSavedHeight = -1;

    std::mutex mPauseMutex;
    std::vector<std::pair<fa::string, int>> mPendingPauses;
  };
} // namespace moho
