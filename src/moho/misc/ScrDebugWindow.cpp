#include "moho/misc/ScrDebugWindow.h"

#include <algorithm>
#include <sstream>

#include <wx/accel.h>
#include <wx/bitmap.h>
#include <wx/dirctrl.h>
#include <wx/listctrl.h>
#include <wx/menu.h>
#include <wx/notebook.h>
#include <wx/splitter.h>
#include <wx/textctrl.h>
#include <wx/toolbar.h>
#include <wx/treectrl.h>

#include "gpg/core/containers/String.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ScrActivation.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/misc/ScrGotoDialog.h"
#include "moho/misc/ScrPauseEvent.h"
#include "moho/misc/ScrSourceCtrl.h"
#include "moho/misc/ScrWatch.h"
#include "moho/misc/ScrWatchCtrl.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/WRenViewport.h"

namespace
{
  // Menu, toolbar and accelerator commands.
  enum
  {
    ID_CloseFile = 101,
    ID_CloseAllFiles = 102,
    ID_ReloadAll = 103,
    ID_GotoLine = 201,
    ID_Step = 301,
    ID_Resume = 302,
    ID_EnableBreakpoints = 303,
    ID_DisableBreakpoints = 304,
    ID_ClearBreakpoints = 305,
    ID_FindText = 1001,
    ID_Find = 1002,
    ID_FindNext = 1003,
    ID_FindPrevious = 1004,
  };

  // Window ids. Three repeat a command's number; the event types keep them
  // apart. The source notebook is 202 (ScrSourceCtrl).
  enum
  {
    ID_SourceSplitter = 101,
    ID_MainSplitter = 102,
    ID_SourceTree = 201,
    ID_CallStack = 301,
    ID_Locals = 302,
    ID_Globals = 303,
  };

  /**
   * A toolbar bitmap: the mounted path resolved through the VFS, loaded as a
   * BMP. Inlined at each of the eight tools.
   */
  wxBitmap LoadToolBitmap(const char* const mountedPath)
  {
    msvc8::string diskPath;
    (void)moho::DISK_GetVFS()->FindFile(&diskPath, mountedPath, nullptr);
    return wxBitmap(gpg::STR_Utf8ToWide(diskPath.c_str()).c_str(), wxBITMAP_TYPE_BMP);
  }
} // namespace

// Table 0x00DFF660 = {&wxFrame::sm_eventTable (0x00D56F70), rows 0x00F59488};
// GetEventTable (0x004BC100) comes with it.
BEGIN_EVENT_TABLE(moho::ScrDebugWindow, wxFrame)
  EVT_CUSTOM(moho::EVT_SCR_PAUSE, -1, moho::ScrDebugWindow::OnScriptPause)
  EVT_MENU(ID_CloseFile, moho::ScrDebugWindow::OnCloseFile)
  EVT_MENU(ID_CloseAllFiles, moho::ScrDebugWindow::OnCloseAllFiles)
  EVT_MENU(ID_ReloadAll, moho::ScrDebugWindow::OnReloadAll)
  EVT_MENU(ID_GotoLine, moho::ScrDebugWindow::OnGotoLine)
  EVT_MENU(ID_Find, moho::ScrDebugWindow::OnFind)
  EVT_MENU(ID_FindNext, moho::ScrDebugWindow::OnFindNext)
  EVT_MENU(ID_FindPrevious, moho::ScrDebugWindow::OnFindPrevious)
  EVT_MENU(ID_Step, moho::ScrDebugWindow::OnStep)
  EVT_MENU(ID_Resume, moho::ScrDebugWindow::OnResume)
  EVT_MENU(ID_EnableBreakpoints, moho::ScrDebugWindow::OnEnableBreakpoints)
  EVT_MENU(ID_DisableBreakpoints, moho::ScrDebugWindow::OnDisableBreakpoints)
  EVT_MENU(ID_ClearBreakpoints, moho::ScrDebugWindow::OnClearBreakpoints)
  EVT_LIST_ITEM_SELECTED(ID_CallStack, moho::ScrDebugWindow::OnCallStackSelected)
  EVT_SPLITTER_SASH_POS_CHANGED(ID_SourceSplitter, moho::ScrDebugWindow::OnVerticalSashChanged)
  EVT_SPLITTER_SASH_POS_CHANGED(ID_MainSplitter, moho::ScrDebugWindow::OnHorizontalSashChanged)
  EVT_LIST_COL_END_DRAG(ID_CallStack, moho::ScrDebugWindow::OnCallStackColumnResized)
  EVT_LIST_COL_END_DRAG(ID_Locals, moho::ScrDebugWindow::OnLocalsColumnResized)
  EVT_LIST_COL_END_DRAG(ID_Globals, moho::ScrDebugWindow::OnGlobalsColumnResized)
  EVT_MOVE(moho::ScrDebugWindow::OnMove)
  EVT_SIZE(moho::ScrDebugWindow::OnSize)
  EVT_CLOSE(moho::ScrDebugWindow::OnCloseWindow)
END_EVENT_TABLE()

/**
 * Address: 0x004BC110 (FUN_004BC110, Moho::ScrDebugWindow::ScrDebugWindow)
 *
 * Inline wx bodies emitted beside it: wxMenu::wxMenu (0x004BB050),
 * wxMenuBase::AppendSeparator (0x004BAF20), the label/bitmap/short-help
 * wxToolBarBase::AddTool (0x004BB2D0), wxSplitterWindow's constructor
 * (0x004BB380) and wxGenericDirCtrl's (0x004BB4A0) with this file's style,
 * id and filter folded in, and wxAcceleratorEntry's default constructor
 * (0x004BEB60) run over `accelerators`.
 */
moho::ScrDebugWindow::ScrDebugWindow()
  : wxFrame(
      nullptr, -1, wxT("Debugger"), wxDefaultPosition, wxDefaultSize, wxDEFAULT_FRAME_STYLE, wxT("ScrDebugWindow")
    )
  , mInitializing(true)
  , mThreadId(0)
  , mSourceTree(nullptr)
  , mSourceCtrl(nullptr)
  , mCallStack(nullptr)
  , mLocals(nullptr)
  , mGlobals(nullptr)
  , mFindString()
  , mFindText(nullptr)
  , mRecentFiles()
{
  mThreadId = ::GetCurrentThreadId();
  IUserPrefs* const prefs = USER_GetPreferences();

  wxMenuBar* const menuBar = new wxMenuBar;
  wxMenu* const fileMenu = new wxMenu;
  fileMenu->Append(ID_CloseFile, wxT("Close"), wxT("Close source file"));
  fileMenu->Append(ID_CloseAllFiles, wxT("Close All"), wxT("Close all files"));
  fileMenu->Append(ID_ReloadAll, wxT("Reload All"), wxT("Reload all source file"));
  wxMenu* const viewMenu = new wxMenu;
  viewMenu->Append(ID_GotoLine, wxT("Goto"), wxT("Goto line number"));
  wxMenu* const debugMenu = new wxMenu;
  debugMenu->Append(ID_Step, wxT("Step"), wxT("Step execution"));
  debugMenu->Append(ID_Resume, wxT("Resume"), wxT("Resume execution"));
  debugMenu->AppendSeparator();
  debugMenu->Append(ID_EnableBreakpoints, wxT("Enable breakpoints"), wxT("Enable all breakpoints"));
  debugMenu->Append(ID_DisableBreakpoints, wxT("Disable breakpoints"), wxT("Disable all breakpoints"));
  debugMenu->AppendSeparator();
  debugMenu->Append(ID_ClearBreakpoints, wxT("Clear breakpoints"), wxT("Clear all breakpoints"));
  menuBar->Append(fileMenu, wxT("File"));
  menuBar->Append(viewMenu, wxT("View"));
  menuBar->Append(debugMenu, wxT("Debug"));
  SetMenuBar(menuBar);

  wxToolBar* const toolBar = CreateToolBar(wxNO_BORDER | wxTB_HORIZONTAL | wxTB_FLAT);
  toolBar->AddTool(
    ID_Resume, wxT("Resume"), LoadToolBitmap("/coderes/engine/dbg_tool_resume.bmp"), wxT("Resume execution")
  );
  toolBar->AddTool(ID_Step, wxT("Step"), LoadToolBitmap("/coderes/engine/dbg_tool_step.bmp"), wxT("Step into"));
  toolBar->AddSeparator();
  toolBar->AddTool(
    ID_EnableBreakpoints, wxT("Enable"), LoadToolBitmap("/coderes/engine/dbg_tool_enablebreakpoints.bmp"),
    wxT("Enable all breakpoints")
  );
  toolBar->AddTool(
    ID_DisableBreakpoints, wxT("Disable"), LoadToolBitmap("/coderes/engine/dbg_tool_disablebreakpoints.bmp"),
    wxT("Disable all breakpoints")
  );
  toolBar->AddSeparator();
  toolBar->AddTool(
    ID_ClearBreakpoints, wxT("Clear"), LoadToolBitmap("/coderes/engine/dbg_tool_clearbreakpoints.bmp"),
    wxT("Clear breakpoints")
  );
  toolBar->AddSeparator();
  mFindText = new wxTextCtrl(toolBar, ID_FindText, wxEmptyString, wxDefaultPosition, wxSize(196, -1));
  toolBar->AddControl(mFindText);
  toolBar->AddTool(ID_Find, wxT("Find"), LoadToolBitmap("/coderes/engine/dbg_tool_find.bmp"), wxT("Find"));
  toolBar->AddTool(
    ID_FindNext, wxT("Next"), LoadToolBitmap("/coderes/engine/dbg_tool_findnext.bmp"), wxT("Find Next")
  );
  toolBar->AddTool(
    ID_FindPrevious, wxT("Previous"), LoadToolBitmap("/coderes/engine/dbg_tool_findprev.bmp"), wxT("Find Previous")
  );
  toolBar->Realize();

  wxSplitterWindow* const mainSplitter =
    new wxSplitterWindow(this, ID_MainSplitter, wxDefaultPosition, wxDefaultSize, 0);
  mainSplitter->SetMinimumPaneSize(8);
  wxSplitterWindow* const sourceSplitter =
    new wxSplitterWindow(mainSplitter, ID_SourceSplitter, wxDefaultPosition, wxDefaultSize, 0);
  sourceSplitter->SetMinimumPaneSize(8);

  msvc8::string rootPath;
  (void)DISK_GetVFS()->FindFile(&rootPath, "/", nullptr);
  mSourceTree = new wxGenericDirCtrl(
    sourceSplitter, ID_SourceTree, gpg::STR_Utf8ToWide(rootPath.c_str()).c_str(), wxDefaultPosition, wxDefaultSize, 0,
    wxT("Script files (*.lua)|*.lua")
  );
  mSourceCtrl = new ScrSourceCtrl(sourceSplitter);

  wxNotebook* const watchBook =
    new wxNotebook(mainSplitter, -1, wxDefaultPosition, wxDefaultSize, wxNB_BOTTOM | wxNB_FIXEDWIDTH);
  mCallStack = new wxListCtrl(watchBook, ID_CallStack, wxDefaultPosition, wxDefaultSize, wxLC_REPORT);
  watchBook->AddPage(mCallStack, wxT("Stack"));
  mCallStack->InsertColumn(
    0, wxT("Source"), wxLIST_FORMAT_LEFT, prefs->GetInteger("Windows.Debug.Watch.Stack.source", 196)
  );
  mCallStack->InsertColumn(
    1, wxT("Function"), wxLIST_FORMAT_LEFT, prefs->GetInteger("Windows.Debug.Watch.Stack.block", 96)
  );
  mCallStack->InsertColumn(2, wxT("Line"), wxLIST_FORMAT_RIGHT, prefs->GetInteger("Windows.Debug.Watch.Stack.line", 64));

  mLocals = new ScrWatchCtrl(
    watchBook, ID_Locals, prefs->GetInteger("Windows.Debug.Watch.Local.name", 96),
    prefs->GetInteger("Windows.Debug.Watch.Local.type", 64), prefs->GetInteger("Windows.Debug.Watch.Local.value", 128)
  );
  watchBook->AddPage(mLocals, wxT("Locals"));
  mGlobals = new ScrWatchCtrl(
    watchBook, ID_Globals, prefs->GetInteger("Windows.Debug.Watch.Global.name", 96),
    prefs->GetInteger("Windows.Debug.Watch.Global.type", 64), prefs->GetInteger("Windows.Debug.Watch.Global.value", 128)
  );
  watchBook->AddPage(mGlobals, wxT("Globals"));

  Connect(
    mSourceTree->GetTreeCtrl()->GetId(), -1, wxEVT_COMMAND_TREE_ITEM_ACTIVATED,
    (wxObjectEventFunction)(wxEventFunction)(wxTreeEventFunction)&ScrDebugWindow::OnSourceFileActivated
  );

  SetSize(
    prefs->GetInteger("Windows.Debug.x", -1), prefs->GetInteger("Windows.Debug.y", -1),
    prefs->GetInteger("Windows.Debug.width", -1), prefs->GetInteger("Windows.Debug.height", -1)
  );
  int clientWidth;
  int clientHeight;
  GetClientSize(&clientWidth, &clientHeight);
  mainSplitter->SplitHorizontally(
    sourceSplitter, watchBook,
    prefs->GetInteger("Windows.Debug.Sash.horizontal", static_cast<int>(clientHeight * 0.8f))
  );
  sourceSplitter->SplitVertically(
    mSourceTree, mSourceCtrl, prefs->GetInteger("Windows.Debug.Sash.vertical", static_cast<int>(clientWidth * 0.25f))
  );

  wxAcceleratorEntry accelerators[8];
  accelerators[0].Set(wxACCEL_CTRL, WXK_F4, ID_CloseFile);
  accelerators[1].Set(wxACCEL_CTRL, 'G', ID_GotoLine);
  accelerators[2].Set(wxACCEL_NORMAL, WXK_F5, ID_Resume);
  accelerators[3].Set(wxACCEL_NORMAL, WXK_F10, ID_Step);
  accelerators[4].Set(wxACCEL_CTRL | wxACCEL_SHIFT, WXK_F9, ID_ClearBreakpoints);
  accelerators[5].Set(wxACCEL_NORMAL, WXK_F3, ID_FindNext);
  accelerators[6].Set(wxACCEL_SHIFT, WXK_F3, ID_FindPrevious);
  accelerators[7].Set(wxACCEL_CTRL, 'R', ID_ReloadAll);
  wxAcceleratorTable acceleratorTable(8, accelerators);
  SetAcceleratorTable(acceleratorTable);

  mInitializing = false;

  // Reopen the saved files; any that no longer opens leaves the list.
  bool filesDropped = false;
  mRecentFiles = prefs->GetStringArr("Options.Debug.Files", msvc8::list<msvc8::string>());
  for (msvc8::list<msvc8::string>::iterator file = mRecentFiles.begin(); file != mRecentFiles.end();) {
    if (mSourceCtrl->Open(*file)) {
      ++file;
    } else {
      file = mRecentFiles.erase(file);
      filesDropped = true;
    }
  }
  if (filesDropped) {
    prefs->SetStringArr("Options.Debug.Files", mRecentFiles);
    USER_SavePreferences();
  }
}

/**
 * Address: 0x004BEBE0 (FUN_004BEBE0)
 */
bool moho::ScrDebugWindow::OpenFile(const msvc8::string& fileName)
{
  if (!mSourceCtrl->Open(fileName)) {
    return false;
  }

  if (std::find(mRecentFiles.begin(), mRecentFiles.end(), fileName) == mRecentFiles.end()) {
    mRecentFiles.push_back(fileName);
    USER_GetPreferences()->SetStringArr("Options.Debug.Files", mRecentFiles);
    USER_SavePreferences();
  }
  return true;
}

/**
 * Address: 0x004BECF0 (FUN_004BECF0)
 */
void moho::ScrDebugWindow::OnScriptPause(ScrPauseEvent& event)
{
  if (!OpenFile(event.mSourceName) || !mSourceCtrl->SetCursorLine(event.mSourceName, event.mSourceLine)) {
    SCR_DebugResume();
    return;
  }

  mCallStack->DeleteAllItems();
  msvc8::vector<ScrActivation> callStack;
  SCR_EnumerateCallStack(callStack);
  int row = 0;
  for (msvc8::vector<ScrActivation>::iterator activation = callStack.begin(); activation != callStack.end();
       ++activation, ++row) {
    std::ostringstream line;
    line << activation->line;
    mCallStack->InsertItem(row, gpg::STR_Utf8ToWide(activation->file.c_str()).c_str());
    mCallStack->SetItem(row, 1, gpg::STR_Utf8ToWide(activation->name.c_str()).c_str());
    mCallStack->SetItem(row, 2, gpg::STR_Utf8ToWide(line.str().c_str()).c_str());
  }
  if (!callStack.empty()) {
    mCallStack->SetItemState(0, wxLIST_STATE_SELECTED, wxLIST_STATE_SELECTED);
  }

  msvc8::vector<ScrWatch> locals;
  SCR_EnumerateLocals(0, locals);
  mLocals->Update(locals);
  msvc8::vector<ScrWatch> globals;
  SCR_EnumerateGlobals(globals);
  mGlobals->Update(globals);

  if (ren_Viewport != nullptr) {
    ren_Viewport->SetEvtHandlerEnabled(false);
  }
}

/**
 * Address: 0x004BF120 (FUN_004BF120)
 *
 * std::remove here is the out-of-line 0x004C04D0; the erase is 0x004C01A0.
 */
void moho::ScrDebugWindow::OnCloseFile(wxCommandEvent& event)
{
  const msvc8::string fileName = mSourceCtrl->GetCurrentFileName();
  mSourceCtrl->CloseCurrent();
  mRecentFiles.erase(std::remove(mRecentFiles.begin(), mRecentFiles.end(), fileName), mRecentFiles.end());
  USER_GetPreferences()->SetStringArr("Options.Debug.Files", mRecentFiles);
  USER_SavePreferences();
}

/**
 * Address: 0x004BF220 (FUN_004BF220)
 */
void moho::ScrDebugWindow::OnCloseAllFiles(wxCommandEvent& event)
{
  msvc8::string fileName = mSourceCtrl->GetCurrentFileName();
  while (!fileName.empty()) {
    mSourceCtrl->CloseCurrent();
    mRecentFiles.erase(std::remove(mRecentFiles.begin(), mRecentFiles.end(), fileName), mRecentFiles.end());
    USER_GetPreferences()->SetStringArr("Options.Debug.Files", mRecentFiles);
    USER_SavePreferences();
    fileName = mSourceCtrl->GetCurrentFileName();
  }
}

/**
 * Address: 0x004BF3F0 (FUN_004BF3F0)
 */
void moho::ScrDebugWindow::OnReloadAll(wxCommandEvent& event)
{
  mSourceCtrl->ReloadAll();
}

/**
 * Address: 0x004BF400 (FUN_004BF400)
 */
void moho::ScrDebugWindow::OnGotoLine(wxCommandEvent& event)
{
  ScrGotoDialog dialog;
  if (dialog.ShowModal() == wxID_OK) {
    mSourceCtrl->GotoLine(dialog.GetLine());
  }
}

/**
 * Address: 0x004BF4C0 (FUN_004BF4C0)
 */
void moho::ScrDebugWindow::OnFind(wxCommandEvent& event)
{
  mFindString = gpg::STR_WideToUtf8(mFindText->GetValue().c_str());
  if (!mFindString.empty()) {
    mSourceCtrl->FindFirst(mFindString);
  }
}

/**
 * Address: 0x004BF5B0 (FUN_004BF5B0)
 */
void moho::ScrDebugWindow::OnFindNext(wxCommandEvent& event)
{
  if (!mFindString.empty()) {
    mSourceCtrl->FindNext(mFindString);
  }
}

/**
 * Address: 0x004BF5F0 (FUN_004BF5F0)
 */
void moho::ScrDebugWindow::OnFindPrevious(wxCommandEvent& event)
{
  if (!mFindString.empty()) {
    mSourceCtrl->FindPrevious(mFindString);
  }
}

/**
 * Address: 0x004BF630 (FUN_004BF630)
 */
void moho::ScrDebugWindow::OnStep(wxCommandEvent& event)
{
  mSourceCtrl->ClearCursor();
  mLocals->Clear();
  SCR_DebugStep();
  if (ren_Viewport != nullptr) {
    ren_Viewport->SetEvtHandlerEnabled(true);
  }
}

/**
 * Address: 0x004BF690 (FUN_004BF690)
 */
void moho::ScrDebugWindow::OnResume(wxCommandEvent& event)
{
  mSourceCtrl->ClearCursor();
  mLocals->Clear();
  SCR_DebugResume();
  if (ren_Viewport != nullptr) {
    ren_Viewport->SetEvtHandlerEnabled(true);
  }
}

/**
 * Address: 0x004BF6F0 (FUN_004BF6F0)
 */
void moho::ScrDebugWindow::OnEnableBreakpoints(wxCommandEvent& event)
{
  mSourceCtrl->EnableBreakpoints(true);
  SCR_EnableAllBreakpoints(true);
}

/**
 * Address: 0x004BF710 (FUN_004BF710)
 */
void moho::ScrDebugWindow::OnDisableBreakpoints(wxCommandEvent& event)
{
  mSourceCtrl->EnableBreakpoints(false);
  SCR_EnableAllBreakpoints(false);
}

/**
 * Address: 0x004BF730 (FUN_004BF730)
 */
void moho::ScrDebugWindow::OnClearBreakpoints(wxCommandEvent& event)
{
  mSourceCtrl->RemoveAllBreakpoints();
  SCR_RemoveAllBreakpoints();
}

/**
 * Address: 0x004BF750 (FUN_004BF750)
 */
void moho::ScrDebugWindow::OnCallStackSelected(wxListEvent& event)
{
  msvc8::vector<ScrActivation> callStack;
  SCR_EnumerateCallStack(callStack);
  if (event.GetIndex() < static_cast<long>(callStack.size())) {
    const ScrActivation& activation = callStack[event.GetIndex()];
    OpenFile(activation.file);
    mSourceCtrl->SetCursorLine(activation.file, activation.line);

    msvc8::vector<ScrWatch> locals;
    SCR_EnumerateLocals(event.GetIndex(), locals);
    mLocals->Update(locals);
  }
}

/**
 * Address: 0x004BF840 (FUN_004BF840)
 */
void moho::ScrDebugWindow::OnSourceFileActivated(wxTreeEvent& event)
{
  CVirtualFileSystem* const vfs = DISK_GetVFS();
  msvc8::string mountedPath;
  (void)vfs->ToMountedPath(&mountedPath, gpg::STR_WideToUtf8(mSourceTree->GetPath().c_str()).c_str());
  OpenFile(mountedPath);
}

/**
 * Address: 0x004BF960 (FUN_004BF960)
 */
void moho::ScrDebugWindow::OnVerticalSashChanged(wxSplitterEvent& event)
{
  if (!mInitializing) {
    USER_GetPreferences()->SetInteger("Windows.Debug.Sash.vertical", event.GetSashPosition());
  }
}

/**
 * Address: 0x004BFA00 (FUN_004BFA00)
 */
void moho::ScrDebugWindow::OnHorizontalSashChanged(wxSplitterEvent& event)
{
  if (!mInitializing) {
    USER_GetPreferences()->SetInteger("Windows.Debug.Sash.horizontal", event.GetSashPosition());
  }
}

/**
 * Address: 0x004BFAA0 (FUN_004BFAA0)
 */
void moho::ScrDebugWindow::OnCallStackColumnResized(wxListEvent& event)
{
  if (mInitializing) {
    return;
  }

  IUserPrefs* const prefs = USER_GetPreferences();
  prefs->SetInteger("Windows.Debug.Watch.Stack.source", mCallStack->GetColumnWidth(0));
  prefs->SetInteger("Windows.Debug.Watch.Stack.block", mCallStack->GetColumnWidth(1));
  prefs->SetInteger("Windows.Debug.Watch.Stack.line", mCallStack->GetColumnWidth(2));
}

/**
 * Address: 0x004BFC00 (FUN_004BFC00)
 */
void moho::ScrDebugWindow::OnLocalsColumnResized(wxListEvent& event)
{
  if (mInitializing) {
    return;
  }

  IUserPrefs* const prefs = USER_GetPreferences();
  prefs->SetInteger("Windows.Debug.Watch.Local.name", mLocals->GetColumnWidth(0));
  prefs->SetInteger("Windows.Debug.Watch.Local.type", mLocals->GetColumnWidth(1));
  prefs->SetInteger("Windows.Debug.Watch.Local.value", mLocals->GetColumnWidth(2));
}

/**
 * Address: 0x004BFD60 (FUN_004BFD60)
 */
void moho::ScrDebugWindow::OnGlobalsColumnResized(wxListEvent& event)
{
  if (mInitializing) {
    return;
  }

  IUserPrefs* const prefs = USER_GetPreferences();
  prefs->SetInteger("Windows.Debug.Watch.Global.name", mGlobals->GetColumnWidth(0));
  prefs->SetInteger("Windows.Debug.Watch.Global.type", mGlobals->GetColumnWidth(1));
  prefs->SetInteger("Windows.Debug.Watch.Global.value", mGlobals->GetColumnWidth(2));
}

/**
 * Address: 0x004BFEC0 (FUN_004BFEC0)
 */
void moho::ScrDebugWindow::OnMove(wxMoveEvent& event)
{
  if (mInitializing) {
    return;
  }

  IUserPrefs* const prefs = USER_GetPreferences();
  prefs->SetInteger("Windows.Debug.x", GetPosition().x);
  prefs->SetInteger("Windows.Debug.y", GetPosition().y);
}

/**
 * Address: 0x004BFFE0 (FUN_004BFFE0)
 */
void moho::ScrDebugWindow::OnSize(wxSizeEvent& event)
{
  wxFrame::OnSize(event);
  if (mInitializing) {
    return;
  }

  IUserPrefs* const prefs = USER_GetPreferences();
  prefs->SetInteger("Windows.Debug.width", GetSize().x);
  prefs->SetInteger("Windows.Debug.height", GetSize().y);
}

/**
 * Address: 0x004C0100 (FUN_004C0100)
 */
void moho::ScrDebugWindow::OnCloseWindow(wxCloseEvent& event)
{
  SCR_DestroyDebugWindow();
}
