#include "moho/misc/ScrDebugWindow.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <sstream>

#include <Windows.h>

#include "imgui.h"

#include "gpg/core/containers/String.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ScrActivation.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/misc/ScrSourceCtrl.h"
#include "moho/misc/ScrWatch.h"
#include "moho/misc/ScrWatchCtrl.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/WRenViewport.h"

namespace
{
  constexpr float kMinimumPane = 8.0f; // SplitterWindow::SetMinimumPaneSize(8)

  [[nodiscard]] bool EndsWithLua(
    const std::string& name
  )
  {
    if (name.size() < 4u) {
      return false;
    }
    std::string extension = name.substr(name.size() - 4u);
    std::transform(extension.begin(), extension.end(), extension.begin(), [](const unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    return extension == ".lua";
  }

  // A splitter's sash between two panes: dragging it moves `position` (the first pane's size).
  bool Sash(
    const char* const id,
    const bool vertical,
    float& position,
    const float total
  )
  {
    const ImVec2 size = vertical ? ImVec2(6.0f, -1.0f) : ImVec2(-1.0f, 6.0f);
    ImGui::InvisibleButton(
      id,
      ImVec2(
        size.x < 0.0f ? ImGui::GetContentRegionAvail().x : size.x,
        size.y < 0.0f ? ImGui::GetContentRegionAvail().y : size.y
      )
    );
    if (ImGui::IsItemHovered() || ImGui::IsItemActive()) {
      ImGui::SetMouseCursor(vertical ? ImGuiMouseCursor_ResizeEW : ImGuiMouseCursor_ResizeNS);
    }
    if (!ImGui::IsItemActive()) {
      return ImGui::IsItemDeactivated();
    }
    const float delta = vertical ? ImGui::GetIO().MouseDelta.x : ImGui::GetIO().MouseDelta.y;
    position = std::clamp(position + delta, kMinimumPane, std::max(kMinimumPane, total - kMinimumPane));
    return false;
  }
} // namespace

/**
 * Address: 0x004BC110 (FUN_004BC110, Moho::ScrDebugWindow::ScrDebugWindow)
 *
 * The binary built a menu bar, a toolbar of eight BMP tools (/coderes/engine/dbg_tool_*.bmp) with
 * the find box, two splitters, a wxGenericDirCtrl of the game folder's *.lua files and a notebook
 * holding the call stack, locals and globals, and an accelerator table; Draw lays out the same.
 */
moho::ScrDebugWindow::ScrDebugWindow()
  : platform::tools::ToolWindow("Debugger", 1024, 768)
  , mThreadId(0)
  , mSourceCtrl(std::make_unique<ScrSourceCtrl>())
  , mStackWidths{196, 96, 64}
  , mFindString()
  , mRecentFiles()
  , mVerticalSash(0.0f)
  , mHorizontalSash(0.0f)
{
  mThreadId = ::GetCurrentThreadId();
  IUserPrefs* const prefs = USER_GetPreferences();

  mStackWidths[0] = prefs->GetInteger("Windows.Debug.Watch.Stack.source", 196);
  mStackWidths[1] = prefs->GetInteger("Windows.Debug.Watch.Stack.block", 96);
  mStackWidths[2] = prefs->GetInteger("Windows.Debug.Watch.Stack.line", 64);
  mLocals = std::make_unique<ScrWatchCtrl>(
    prefs->GetInteger("Windows.Debug.Watch.Local.name", 96),
    prefs->GetInteger("Windows.Debug.Watch.Local.type", 64),
    prefs->GetInteger("Windows.Debug.Watch.Local.value", 128)
  );
  mGlobals = std::make_unique<ScrWatchCtrl>(
    prefs->GetInteger("Windows.Debug.Watch.Global.name", 96),
    prefs->GetInteger("Windows.Debug.Watch.Global.type", 64),
    prefs->GetInteger("Windows.Debug.Watch.Global.value", 128)
  );

  fa::string rootPath;
  (void)DISK_GetVFS()->FindFile(&rootPath, "/", nullptr);
  mSourceRoot.path = rootPath.c_str();
  mSourceRoot.name = rootPath.c_str();

  mSavedX = prefs->GetInteger("Windows.Debug.x", -1);
  mSavedY = prefs->GetInteger("Windows.Debug.y", -1);
  mSavedWidth = prefs->GetInteger("Windows.Debug.width", -1);
  mSavedHeight = prefs->GetInteger("Windows.Debug.height", -1);
  SetBounds(mSavedX, mSavedY, mSavedWidth, mSavedHeight);
  int x = 0;
  int y = 0;
  int clientWidth = 1024;
  int clientHeight = 768;
  (void)GetBounds(x, y, clientWidth, clientHeight);
  mHorizontalSash = static_cast<float>(
    prefs->GetInteger("Windows.Debug.Sash.horizontal", static_cast<int>(static_cast<float>(clientHeight) * 0.8f))
  );
  mVerticalSash = static_cast<float>(
    prefs->GetInteger("Windows.Debug.Sash.vertical", static_cast<int>(static_cast<float>(clientWidth) * 0.25f))
  );

  // Reopen the saved files; any that no longer opens leaves the list.
  bool filesDropped = false;
  mRecentFiles = prefs->GetStringArr("Options.Debug.Files", fa::list<fa::string>());
  for (fa::list<fa::string>::iterator file = mRecentFiles.begin(); file != mRecentFiles.end();) {
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

moho::ScrDebugWindow::~ScrDebugWindow() = default;

/**
 * Address: 0x004BEBE0 (FUN_004BEBE0)
 */
bool moho::ScrDebugWindow::OpenFile(
  const fa::string& fileName
)
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

void moho::ScrDebugWindow::PostPause(
  const fa::string& sourceName,
  const int sourceLine
)
{
  std::lock_guard<std::mutex> lock(mPauseMutex);
  mPendingPauses.emplace_back(sourceName, sourceLine);
}

/**
 * Address: 0x004BECF0 (FUN_004BECF0)
 */
void moho::ScrDebugWindow::OnScriptPause(
  const fa::string& sourceName,
  const int sourceLine
)
{
  if (!OpenFile(sourceName) || !mSourceCtrl->SetCursorLine(sourceName, sourceLine)) {
    SCR_DebugResume();
    return;
  }

  mCallStack.clear();
  fa::vector<ScrActivation> callStack;
  SCR_EnumerateCallStack(callStack);
  for (fa::vector<ScrActivation>::iterator activation = callStack.begin(); activation != callStack.end();
       ++activation) {
    std::ostringstream line;
    line << activation->line;
    mCallStack.push_back(CallStackRow{activation->file.c_str(), activation->name.c_str(), line.str()});
  }
  mCallStackSelection = callStack.empty() ? -1 : 0;

  fa::vector<ScrWatch> locals;
  SCR_EnumerateLocals(0, locals);
  mLocals->Update(locals);
  fa::vector<ScrWatch> globals;
  SCR_EnumerateGlobals(globals);
  mGlobals->Update(globals);

  if (ren_Viewport != nullptr) {
    ren_Viewport->SetEvtHandlerEnabled(false);
  }
  Show(true);
  Raise();
}

/**
 * Address: 0x004BF120 (FUN_004BF120)
 */
void moho::ScrDebugWindow::OnCloseFile()
{
  const fa::string fileName = mSourceCtrl->GetCurrentFileName();
  mSourceCtrl->CloseCurrent();
  mRecentFiles.erase(std::remove(mRecentFiles.begin(), mRecentFiles.end(), fileName), mRecentFiles.end());
  USER_GetPreferences()->SetStringArr("Options.Debug.Files", mRecentFiles);
  USER_SavePreferences();
}

/**
 * Address: 0x004BF220 (FUN_004BF220)
 */
void moho::ScrDebugWindow::OnCloseAllFiles()
{
  fa::string fileName = mSourceCtrl->GetCurrentFileName();
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
void moho::ScrDebugWindow::OnReloadAll()
{
  mSourceCtrl->ReloadAll();
}

/**
 * Address: 0x004BF400 (FUN_004BF400)
 *
 * The binary ran the modal ScrGotoDialog (0x004BB730: "Goto", a number box, Goto and Cancel, its
 * position kept in Windows.Debug.Goto.x/y); a popup inside the window asks for the line here.
 */
void moho::ScrDebugWindow::OnGotoLine()
{
  mGotoText.fill('\0');
  mOpenGoto = true;
}

/**
 * Address: 0x004BF4C0 (FUN_004BF4C0)
 */
void moho::ScrDebugWindow::OnFind()
{
  mFindString = mFindText.data();
  if (!mFindString.empty()) {
    mSourceCtrl->FindFirst(mFindString);
  }
}

/**
 * Address: 0x004BF5B0 (FUN_004BF5B0)
 */
void moho::ScrDebugWindow::OnFindNext()
{
  if (!mFindString.empty()) {
    mSourceCtrl->FindNext(mFindString);
  }
}

/**
 * Address: 0x004BF5F0 (FUN_004BF5F0)
 */
void moho::ScrDebugWindow::OnFindPrevious()
{
  if (!mFindString.empty()) {
    mSourceCtrl->FindPrevious(mFindString);
  }
}

/**
 * Address: 0x004BF630 (FUN_004BF630)
 */
void moho::ScrDebugWindow::OnStep()
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
void moho::ScrDebugWindow::OnResume()
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
void moho::ScrDebugWindow::OnEnableBreakpoints()
{
  mSourceCtrl->EnableBreakpoints(true);
  SCR_EnableAllBreakpoints(true);
}

/**
 * Address: 0x004BF710 (FUN_004BF710)
 */
void moho::ScrDebugWindow::OnDisableBreakpoints()
{
  mSourceCtrl->EnableBreakpoints(false);
  SCR_EnableAllBreakpoints(false);
}

/**
 * Address: 0x004BF730 (FUN_004BF730)
 */
void moho::ScrDebugWindow::OnClearBreakpoints()
{
  mSourceCtrl->RemoveAllBreakpoints();
  SCR_RemoveAllBreakpoints();
}

/**
 * Address: 0x004BF750 (FUN_004BF750)
 */
void moho::ScrDebugWindow::OnCallStackSelected(
  const int index
)
{
  mCallStackSelection = index;
  fa::vector<ScrActivation> callStack;
  SCR_EnumerateCallStack(callStack);
  if (index >= 0 && index < static_cast<int>(callStack.size())) {
    const ScrActivation& activation = callStack[static_cast<std::size_t>(index)];
    OpenFile(activation.file);
    mSourceCtrl->SetCursorLine(activation.file, activation.line);

    fa::vector<ScrWatch> locals;
    SCR_EnumerateLocals(index, locals);
    mLocals->Update(locals);
  }
}

/**
 * Address: 0x004BF840 (FUN_004BF840)
 */
void moho::ScrDebugWindow::OnSourceFileActivated(
  const std::string& diskPath
)
{
  CVirtualFileSystem* const vfs = DISK_GetVFS();
  fa::string mountedPath;
  (void)vfs->ToMountedPath(&mountedPath, diskPath.c_str());
  OpenFile(mountedPath);
}

/**
 * Address: 0x004C0100 (FUN_004C0100)
 */
void moho::ScrDebugWindow::OnCloseRequested()
{
  SCR_DestroyDebugWindow();
}

/**
 * Address: 0x004BFEC0 (FUN_004BFEC0, OnMove) and 0x004BFFE0 (FUN_004BFFE0, OnSize)
 *
 * What it does:
 * Stores the window's position in Windows.Debug.x/y and its size in Windows.Debug.width/height
 * when they change.
 */
void moho::ScrDebugWindow::SaveGeometry()
{
  int x = 0;
  int y = 0;
  int width = 0;
  int height = 0;
  if (!IsShown() || !GetBounds(x, y, width, height)) {
    return;
  }
  IUserPrefs* const prefs = USER_GetPreferences();
  if (x != mSavedX || y != mSavedY) {
    mSavedX = x;
    mSavedY = y;
    prefs->SetInteger("Windows.Debug.x", x);
    prefs->SetInteger("Windows.Debug.y", y);
  }
  if (width != mSavedWidth || height != mSavedHeight) {
    mSavedWidth = width;
    mSavedHeight = height;
    prefs->SetInteger("Windows.Debug.width", width);
    prefs->SetInteger("Windows.Debug.height", height);
  }
}

void moho::ScrDebugWindow::Tick()
{
  if (mDestroyRequested) {
    delete this; // SCR_DestroyDebugWindow's window.Destroy()
    return;
  }
  std::vector<std::pair<fa::string, int>> pauses;
  {
    std::lock_guard<std::mutex> lock(mPauseMutex);
    pauses.swap(mPendingPauses);
  }
  for (const auto& [source, line] : pauses) {
    OnScriptPause(source, line);
  }
  SaveGeometry();
}

void moho::ScrDebugWindow::ListFolder(
  FolderNode& folder
)
{
  folder.listed = true;
  std::error_code error;
  for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(folder.path, error)) {
    const std::string name = entry.path().filename().string();
    if (entry.is_directory(error)) {
      auto child = std::make_unique<FolderNode>();
      child->path = entry.path().string();
      child->name = name;
      folder.folders.push_back(std::move(child));
    } else if (EndsWithLua(name)) {
      folder.files.push_back(name);
    }
  }
  std::sort(folder.folders.begin(), folder.folders.end(), [](const auto& left, const auto& right) {
    return left->name < right->name;
  });
  std::sort(folder.files.begin(), folder.files.end());
}

// The source tree (GenericDirCtrl, id 201, filter "Script files (*.lua)|*.lua"): a double-click
// on a file opens it (OnSourceFileActivated).
void moho::ScrDebugWindow::DrawSourceTree(
  FolderNode& folder
)
{
  if (!folder.listed) {
    ListFolder(folder);
  }
  for (const std::unique_ptr<FolderNode>& child : folder.folders) {
    ImGui::PushID(child.get());
    if (ImGui::TreeNodeEx("##folder", ImGuiTreeNodeFlags_SpanFullWidth, "%s", child->name.c_str())) {
      DrawSourceTree(*child);
      ImGui::TreePop();
    }
    ImGui::PopID();
  }
  for (const std::string& file : folder.files) {
    ImGui::TreeNodeEx(
      file.c_str(), ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen | ImGuiTreeNodeFlags_SpanFullWidth
    );
    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
      OnSourceFileActivated((std::filesystem::path(folder.path) / file).string());
    }
  }
}

void moho::ScrDebugWindow::DrawMenuBar()
{
  if (!ImGui::BeginMenuBar()) {
    return;
  }
  if (ImGui::BeginMenu("File")) {
    if (ImGui::MenuItem("Close", "Ctrl+F4")) {
      OnCloseFile();
    }
    if (ImGui::MenuItem("Close All")) {
      OnCloseAllFiles();
    }
    if (ImGui::MenuItem("Reload All", "Ctrl+R")) {
      OnReloadAll();
    }
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("View")) {
    if (ImGui::MenuItem("Goto", "Ctrl+G")) {
      OnGotoLine();
    }
    ImGui::EndMenu();
  }
  if (ImGui::BeginMenu("Debug")) {
    if (ImGui::MenuItem("Step", "F10")) {
      OnStep();
    }
    if (ImGui::MenuItem("Resume", "F5")) {
      OnResume();
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Enable breakpoints")) {
      OnEnableBreakpoints();
    }
    if (ImGui::MenuItem("Disable breakpoints")) {
      OnDisableBreakpoints();
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Clear breakpoints", "Ctrl+Shift+F9")) {
      OnClearBreakpoints();
    }
    ImGui::EndMenu();
  }
  ImGui::EndMenuBar();
}

void moho::ScrDebugWindow::DrawToolBar()
{
  const auto tool = [](const char* const label, const char* const help) {
    const bool pressed = ImGui::Button(label);
    if (ImGui::IsItemHovered()) {
      ImGui::SetTooltip("%s", help);
    }
    ImGui::SameLine();
    return pressed;
  };
  if (tool("Resume", "Resume execution")) {
    OnResume();
  }
  if (tool("Step", "Step into")) {
    OnStep();
  }
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  if (tool("Enable", "Enable all breakpoints")) {
    OnEnableBreakpoints();
  }
  if (tool("Disable", "Disable all breakpoints")) {
    OnDisableBreakpoints();
  }
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  if (tool("Clear", "Clear breakpoints")) {
    OnClearBreakpoints();
  }
  ImGui::TextDisabled("|");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(196.0f);
  if (ImGui::InputText("##find", mFindText.data(), mFindText.size(), ImGuiInputTextFlags_EnterReturnsTrue)) {
    OnFind();
  }
  ImGui::SameLine();
  if (tool("Find", "Find")) {
    OnFind();
  }
  if (tool("Next", "Find Next")) {
    OnFindNext();
  }
  if (ImGui::Button("Previous")) {
    OnFindPrevious();
  }
  if (ImGui::IsItemHovered()) {
    ImGui::SetTooltip("Find Previous");
  }
}

void moho::ScrDebugWindow::DrawGotoPopup()
{
  if (mOpenGoto) {
    ImGui::OpenPopup("Goto");
    mOpenGoto = false;
  }
  if (!ImGui::BeginPopupModal("Goto", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    return;
  }
  ImGui::TextUnformatted("Goto");
  ImGui::SameLine();
  ImGui::SetNextItemWidth(96.0f);
  if (ImGui::IsWindowAppearing()) {
    ImGui::SetKeyboardFocusHere();
  }
  const bool entered = ImGui::InputText(
    "##line",
    mGotoText.data(),
    mGotoText.size(),
    ImGuiInputTextFlags_CharsDecimal | ImGuiInputTextFlags_EnterReturnsTrue
  );
  // Address: 0x004BBFD0 (OnOK) and 0x004BBFF0 (GetLine, atoi of the box's text).
  if (ImGui::Button("Goto") || entered) {
    mSourceCtrl->GotoLine(std::atoi(mGotoText.data()));
    ImGui::CloseCurrentPopup();
  }
  ImGui::SameLine();
  if (ImGui::Button("Cancel") || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
    ImGui::CloseCurrentPopup();
  }
  ImGui::EndPopup();
}

// The binary's accelerator table (0x004BC110): Ctrl+F4 close, Ctrl+G goto, F5 resume, F10 step,
// Ctrl+Shift+F9 clear breakpoints, F3 and Shift+F3 find next and previous, Ctrl+R reload all.
void moho::ScrDebugWindow::HandleShortcuts()
{
  const ImGuiIO& io = ImGui::GetIO();
  const bool ctrl = io.KeyCtrl;
  const bool shift = io.KeyShift;
  if (ctrl && ImGui::IsKeyPressed(ImGuiKey_F4, false)) {
    OnCloseFile();
  }
  if (ctrl && ImGui::IsKeyPressed(ImGuiKey_G, false)) {
    OnGotoLine();
  }
  if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
    OnResume();
  }
  if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_F10, false)) {
    OnStep();
  }
  if (ctrl && shift && ImGui::IsKeyPressed(ImGuiKey_F9, false)) {
    OnClearBreakpoints();
  }
  if (ImGui::IsKeyPressed(ImGuiKey_F3, false)) {
    if (shift) {
      OnFindPrevious();
    } else {
      OnFindNext();
    }
  }
  if (ctrl && ImGui::IsKeyPressed(ImGuiKey_R, false)) {
    OnReloadAll();
  }
}

void moho::ScrDebugWindow::Draw()
{
  // The full-window ImGui window has no menu bar of its own; this child carries it.
  const ImVec2 available = ImGui::GetContentRegionAvail();
  if (!ImGui::BeginChild("##debugger", available, ImGuiChildFlags_None, ImGuiWindowFlags_MenuBar)) {
    ImGui::EndChild();
    return;
  }
  DrawMenuBar();
  HandleShortcuts();
  DrawToolBar();

  IUserPrefs* const prefs = USER_GetPreferences();
  const ImVec2 area = ImGui::GetContentRegionAvail();
  mHorizontalSash = std::clamp(mHorizontalSash, kMinimumPane, std::max(kMinimumPane, area.y - kMinimumPane));
  mVerticalSash = std::clamp(mVerticalSash, kMinimumPane, std::max(kMinimumPane, area.x - kMinimumPane));

  // The sources: the folder tree beside the open files.
  if (ImGui::BeginChild("##sources", ImVec2(area.x, mHorizontalSash))) {
    if (ImGui::BeginChild("##tree", ImVec2(mVerticalSash, 0.0f), ImGuiChildFlags_Borders)) {
      DrawSourceTree(mSourceRoot);
    }
    ImGui::EndChild();
    ImGui::SameLine(0.0f, 0.0f);
    // Address: 0x004BF960 (FUN_004BF960, OnVerticalSashChanged)
    if (Sash("##vsash", true, mVerticalSash, area.x)) {
      prefs->SetInteger("Windows.Debug.Sash.vertical", static_cast<int>(mVerticalSash));
    }
    ImGui::SameLine(0.0f, 0.0f);
    if (ImGui::BeginChild("##files", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
      mSourceCtrl->Draw();
    }
    ImGui::EndChild();
  }
  ImGui::EndChild();

  // Address: 0x004BFA00 (FUN_004BFA00, OnHorizontalSashChanged)
  if (Sash("##hsash", false, mHorizontalSash, area.y)) {
    prefs->SetInteger("Windows.Debug.Sash.horizontal", static_cast<int>(mHorizontalSash));
  }

  // The watch notebook (NB_BOTTOM in the binary): Stack, Locals, Globals.
  if (ImGui::BeginTabBar("##watch")) {
    if (ImGui::BeginTabItem("Stack")) {
      constexpr ImGuiTableFlags kFlags = ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;
      if (ImGui::BeginTable("##stack", 3, kFlags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, static_cast<float>(mStackWidths[0]));
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, static_cast<float>(mStackWidths[1]));
        ImGui::TableSetupColumn("Line", ImGuiTableColumnFlags_WidthFixed, static_cast<float>(mStackWidths[2]));
        ImGui::TableHeadersRow();
        for (int row = 0; row < static_cast<int>(mCallStack.size()); ++row) {
          const CallStackRow& entry = mCallStack[static_cast<std::size_t>(row)];
          ImGui::TableNextRow();
          ImGui::TableSetColumnIndex(0);
          ImGui::PushID(row);
          if (
            ImGui::Selectable(entry.source.c_str(), row == mCallStackSelection, ImGuiSelectableFlags_SpanAllColumns)
          ) {
            OnCallStackSelected(row);
          }
          ImGui::PopID();
          ImGui::TableSetColumnIndex(1);
          ImGui::TextUnformatted(entry.function.c_str());
          ImGui::TableSetColumnIndex(2);
          ImGui::TextUnformatted(entry.line.c_str());
        }
        // Address: 0x004BFAA0 (FUN_004BFAA0, OnCallStackColumnResized)
        if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
          bool resized = false;
          for (int column = 0; column < 3; ++column) {
            ImGui::TableSetColumnIndex(column);
            const int width =
              static_cast<int>(ImGui::GetContentRegionAvail().x + ImGui::GetStyle().CellPadding.x * 2.0f);
            if (width > 0 && width != mStackWidths[column]) {
              mStackWidths[column] = width;
              resized = true;
            }
          }
          if (resized) {
            prefs->SetInteger("Windows.Debug.Watch.Stack.source", mStackWidths[0]);
            prefs->SetInteger("Windows.Debug.Watch.Stack.block", mStackWidths[1]);
            prefs->SetInteger("Windows.Debug.Watch.Stack.line", mStackWidths[2]);
          }
        }
        ImGui::EndTable();
      }
      ImGui::EndTabItem();
    }
    int widths[3] = {};
    if (ImGui::BeginTabItem("Locals")) {
      // Address: 0x004BFC00 (FUN_004BFC00, OnLocalsColumnResized)
      if (mLocals->Draw("##locals", widths)) {
        prefs->SetInteger("Windows.Debug.Watch.Local.name", widths[0]);
        prefs->SetInteger("Windows.Debug.Watch.Local.type", widths[1]);
        prefs->SetInteger("Windows.Debug.Watch.Local.value", widths[2]);
      }
      ImGui::EndTabItem();
    }
    if (ImGui::BeginTabItem("Globals")) {
      // Address: 0x004BFD60 (FUN_004BFD60, OnGlobalsColumnResized)
      if (mGlobals->Draw("##globals", widths)) {
        prefs->SetInteger("Windows.Debug.Watch.Global.name", widths[0]);
        prefs->SetInteger("Windows.Debug.Watch.Global.type", widths[1]);
        prefs->SetInteger("Windows.Debug.Watch.Global.value", widths[2]);
      }
      ImGui::EndTabItem();
    }
    ImGui::EndTabBar();
  }

  DrawGotoPopup();
  ImGui::EndChild();
}

namespace
{
  // Engine addition (dedicated-server plan WPL.4): the window side of the script
  // debugger, for moho/misc/ScrDebugHooks.cpp (see ScrDebugHooks.h). The bodies are
  // what SCR_CreateDebugWindow, SCR_DestroyDebugWindow and the pause path did before
  // the move.
  void OpenScrDebugWindow(
    moho::ScrDebugWindow*& runtimeWindow
  )
  {
    auto* const window = new moho::ScrDebugWindow();
    runtimeWindow = window;
    window->Show(true);
  }

  void DestroyScrDebugWindow(
    moho::ScrDebugWindow& window
  )
  {
    // Destroyed at its next Tick, not inside the event or menu handler that asked.
    window.Show(false);
    window.RequestDestroy();
  }

  void PostScrDebugPause(
    moho::ScrDebugWindow& window,
    const fa::string& source,
    const int line
  )
  {
    window.PostPause(source, line);
  }

  [[maybe_unused]] const bool gScrDebugWindowHooksSet =
    (moho::sScrDebugWindowOpen = &OpenScrDebugWindow,
     moho::sScrDebugWindowDestroy = &DestroyScrDebugWindow,
     moho::sScrDebugWindowPostPause = &PostScrDebugPause,
     true);
} // namespace
