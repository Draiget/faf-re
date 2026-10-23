#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "platform/WxWidgets.h"
#include <wx/frame.h>

class wxGenericDirCtrl;
class wxListCtrl;
class wxListEvent;
class wxSplitterEvent;
class wxTextCtrl;
class wxTreeEvent;

namespace moho
{
  class ScrPauseEvent;
  class ScrSourceCtrl;
  class ScrWatchCtrl;

  /**
   * VFTABLE: 0x00E0863C (??_7ScrDebugWindow@Moho@@6B@)
   *
   * The Lua debugger. A source-file tree beside a notebook of open files
   * (ScrSourceCtrl) above a notebook of the call stack and the local and
   * global watches; File/View/Debug menus, a toolbar with a find field, and
   * keys for the common commands. Position, size, sashes and column widths
   * live in the Windows.Debug.* preferences, the open files in
   * Options.Debug.Files. Created and destroyed by SCR_CreateDebugWindow /
   * SCR_DestroyDebugWindow; a paused Lua thread posts it an EVT_SCR_PAUSE.
   *
   * Overrides nothing but the event table: slot 0 is wxFrame's GetClassInfo
   * (0x004BABC0) and the rest are inline wx copies. The destructor
   * (0x004BEB70, deleting 0x004BEB40) is the compiler's.
   */
  class ScrDebugWindow : public wxFrame
  {
  public:
    /**
     * Address: 0x004BC110 (FUN_004BC110, Moho::ScrDebugWindow::ScrDebugWindow)
     *
     * What it does:
     * Builds the menus, the toolbar and the panes, restores the saved
     * geometry, sashes and column widths, installs the accelerators, then
     * reopens the saved files, dropping (and saving without) any that no
     * longer open.
     */
    ScrDebugWindow();

    /**
     * Address: 0x004BEBE0 (FUN_004BEBE0)
     *
     * What it does:
     * Opens `fileName` in the source notebook and, the first time, adds it
     * to the saved file list.
     */
    bool OpenFile(const msvc8::string& fileName);

    /**
     * Address: 0x004BECF0 (FUN_004BECF0)
     *
     * What it does:
     * Shows where the thread stopped - or resumes it when the file or line
     * will not show - fills the call stack and both watches, and takes input
     * away from the game viewport.
     */
    void OnScriptPause(ScrPauseEvent& event);

    /**
     * Address: 0x004BF120 (FUN_004BF120)
     *
     * What it does:
     * Closes the selected file and drops it from the saved file list.
     */
    void OnCloseFile(wxCommandEvent& event);

    /**
     * Address: 0x004BF220 (FUN_004BF220)
     *
     * What it does:
     * OnCloseFile until no file is left.
     */
    void OnCloseAllFiles(wxCommandEvent& event);

    /**
     * Address: 0x004BF3F0 (FUN_004BF3F0)
     *
     * What it does:
     * Reloads every open file.
     */
    void OnReloadAll(wxCommandEvent& event);

    /**
     * Address: 0x004BF400 (FUN_004BF400)
     *
     * What it does:
     * Asks for a line with ScrGotoDialog and selects it in the open file.
     */
    void OnGotoLine(wxCommandEvent& event);

    /**
     * Address: 0x004BF4C0 (FUN_004BF4C0)
     *
     * What it does:
     * Takes the find field's text and selects its first match.
     */
    void OnFind(wxCommandEvent& event);

    /**
     * Address: 0x004BF5B0 (FUN_004BF5B0)
     *
     * What it does:
     * Selects the next match of the last find.
     */
    void OnFindNext(wxCommandEvent& event);

    /**
     * Address: 0x004BF5F0 (FUN_004BF5F0)
     *
     * What it does:
     * Selects the previous match of the last find.
     */
    void OnFindPrevious(wxCommandEvent& event);

    /**
     * Address: 0x004BF630 (FUN_004BF630)
     *
     * What it does:
     * Clears the cursor and the locals, steps, and gives the game viewport
     * its input back.
     */
    void OnStep(wxCommandEvent& event);

    /**
     * Address: 0x004BF690 (FUN_004BF690)
     *
     * What it does:
     * As OnStep, resuming instead.
     */
    void OnResume(wxCommandEvent& event);

    /**
     * Address: 0x004BF6F0 (FUN_004BF6F0)
     *
     * What it does:
     * Enables every breakpoint, markers and set.
     */
    void OnEnableBreakpoints(wxCommandEvent& event);

    /**
     * Address: 0x004BF710 (FUN_004BF710)
     *
     * What it does:
     * Disables every breakpoint, markers and set.
     */
    void OnDisableBreakpoints(wxCommandEvent& event);

    /**
     * Address: 0x004BF730 (FUN_004BF730)
     *
     * What it does:
     * Removes every breakpoint, markers and set.
     */
    void OnClearBreakpoints(wxCommandEvent& event);

    /**
     * Address: 0x004BF750 (FUN_004BF750)
     *
     * What it does:
     * Shows the selected stack level's line and its locals.
     */
    void OnCallStackSelected(wxListEvent& event);

    /**
     * Address: 0x004BF840 (FUN_004BF840)
     *
     * What it does:
     * Opens the file activated in the source tree, by its mounted path.
     * Connected in the constructor, on the tree control's id.
     */
    void OnSourceFileActivated(wxTreeEvent& event);

    /**
     * Address: 0x004BF960 (FUN_004BF960)
     *
     * What it does:
     * Saves the tree/source sash as Windows.Debug.Sash.vertical.
     */
    void OnVerticalSashChanged(wxSplitterEvent& event);

    /**
     * Address: 0x004BFA00 (FUN_004BFA00)
     *
     * What it does:
     * Saves the source/stack sash as Windows.Debug.Sash.horizontal.
     */
    void OnHorizontalSashChanged(wxSplitterEvent& event);

    /**
     * Address: 0x004BFAA0 (FUN_004BFAA0)
     *
     * What it does:
     * Saves the call stack's column widths.
     */
    void OnCallStackColumnResized(wxListEvent& event);

    /**
     * Address: 0x004BFC00 (FUN_004BFC00)
     *
     * What it does:
     * Saves the locals' column widths.
     */
    void OnLocalsColumnResized(wxListEvent& event);

    /**
     * Address: 0x004BFD60 (FUN_004BFD60)
     *
     * What it does:
     * Saves the globals' column widths.
     */
    void OnGlobalsColumnResized(wxListEvent& event);

    /**
     * Address: 0x004BFEC0 (FUN_004BFEC0)
     *
     * What it does:
     * Saves the position as Windows.Debug.x/y.
     */
    void OnMove(wxMoveEvent& event);

    /**
     * Address: 0x004BFFE0 (FUN_004BFFE0)
     *
     * What it does:
     * Lays the frame out (wxTopLevelWindowBase::OnSize), then saves the size
     * as Windows.Debug.width/height.
     */
    void OnSize(wxSizeEvent& event);

    /**
     * Address: 0x004C0100 (FUN_004C0100)
     *
     * What it does:
     * SCR_DestroyDebugWindow.
     */
    void OnCloseWindow(wxCloseEvent& event);

    bool mInitializing;                        // +0x178 holds the save handlers off while building
    std::uint32_t mThreadId;                   // +0x17C the creating thread
    wxGenericDirCtrl* mSourceTree;             // +0x180
    ScrSourceCtrl* mSourceCtrl;                // +0x184
    wxListCtrl* mCallStack;                    // +0x188
    ScrWatchCtrl* mLocals;                     // +0x18C
    ScrWatchCtrl* mGlobals;                    // +0x190
    msvc8::string mFindString;                 // +0x194
    wxTextCtrl* mFindText;                     // +0x1B0
    msvc8::list<msvc8::string> mRecentFiles;   // +0x1B4 Options.Debug.Files

    DECLARE_EVENT_TABLE()
  };

  static_assert(offsetof(ScrDebugWindow, mInitializing) == 0x178, "ScrDebugWindow::mInitializing offset must be 0x178");
  static_assert(offsetof(ScrDebugWindow, mThreadId) == 0x17C, "ScrDebugWindow::mThreadId offset must be 0x17C");
  static_assert(offsetof(ScrDebugWindow, mSourceTree) == 0x180, "ScrDebugWindow::mSourceTree offset must be 0x180");
  static_assert(offsetof(ScrDebugWindow, mSourceCtrl) == 0x184, "ScrDebugWindow::mSourceCtrl offset must be 0x184");
  static_assert(offsetof(ScrDebugWindow, mCallStack) == 0x188, "ScrDebugWindow::mCallStack offset must be 0x188");
  static_assert(offsetof(ScrDebugWindow, mLocals) == 0x18C, "ScrDebugWindow::mLocals offset must be 0x18C");
  static_assert(offsetof(ScrDebugWindow, mGlobals) == 0x190, "ScrDebugWindow::mGlobals offset must be 0x190");
  static_assert(offsetof(ScrDebugWindow, mFindString) == 0x194, "ScrDebugWindow::mFindString offset must be 0x194");
  static_assert(offsetof(ScrDebugWindow, mFindText) == 0x1B0, "ScrDebugWindow::mFindText offset must be 0x1B0");
  static_assert(offsetof(ScrDebugWindow, mRecentFiles) == 0x1B4, "ScrDebugWindow::mRecentFiles offset must be 0x1B4");
  static_assert(sizeof(ScrDebugWindow) == 0x1C0, "ScrDebugWindow size must be 0x1C0");
} // namespace moho
