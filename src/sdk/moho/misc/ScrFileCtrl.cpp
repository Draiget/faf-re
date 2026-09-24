#include "moho/misc/ScrFileCtrl.h"

#include <fstream>

#include <wx/bitmap.h>
#include <wx/colour.h>
#include <wx/font.h>
#include <wx/imaglist.h>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ScrBreakpoint.h"
#include "moho/misc/ScrDebugHooks.h"

namespace
{
  // ScrFileLine::mMarkerState is the row's image, in the order the
  // constructor loads the bitmaps; -1 shows none.
  constexpr int kNoMarker = -1;
  constexpr int kCursorMarker = 0;
  constexpr int kCursorOnBreakpointMarker = 1;
  constexpr int kCursorOnDisabledBreakpointMarker = 2;
  constexpr int kBreakpointMarker = 3;
  constexpr int kDisabledBreakpointMarker = 4;

  constexpr long kSourceColumn = 2;
  constexpr long kFoundLineState = wxLIST_STATE_FOCUSED | wxLIST_STATE_SELECTED;

  /**
   * A marker bitmap: the mounted path resolved through the VFS, loaded as a
   * BMP. Inlined at each of the constructor's five images.
   */
  wxBitmap LoadMarkerBitmap(const char* const mountedPath)
  {
    msvc8::string diskPath;
    (void)moho::DISK_GetVFS()->FindFile(&diskPath, mountedPath, nullptr);
    return wxBitmap(gpg::STR_Utf8ToWide(diskPath.c_str()).c_str(), wxBITMAP_TYPE_BMP);
  }
} // namespace

// Table 0x00DFF644 = {&wxListCtrl::sm_eventTable (0x00D56818), rows 0x00F59654};
// GetEventTable (0x004C1ED0) comes with it.
BEGIN_EVENT_TABLE(moho::ScrFileCtrl, wxListCtrl)
  EVT_SIZE(moho::ScrFileCtrl::OnSize)
END_EVENT_TABLE()

/**
 * Address: 0x004C1EE0 (FUN_004C1EE0)
 */
moho::ScrFileCtrl::ScrFileCtrl(wxWindow* const parent)
  : wxListCtrl(
      parent, -1, wxDefaultPosition, wxDefaultSize, wxLC_REPORT | wxLC_VIRTUAL | wxLC_NO_HEADER | wxLC_SINGLE_SEL
    )
  , mCursorLine(0)
  , mImageList(nullptr)
  , mSourcePath()
  , mLines()
{
  mImageList = new wxImageList(24, 12, true, 5);
  mImageList->Add(LoadMarkerBitmap("/coderes/engine/dbg_cursor.bmp"));
  mImageList->Add(LoadMarkerBitmap("/coderes/engine/dbg_cursor_enabled.bmp"));
  mImageList->Add(LoadMarkerBitmap("/coderes/engine/dbg_cursor_disabled.bmp"));
  mImageList->Add(LoadMarkerBitmap("/coderes/engine/dbg_break_enabled.bmp"));
  mImageList->Add(LoadMarkerBitmap("/coderes/engine/dbg_break_disabled.bmp"));
  SetImageList(mImageList, wxIMAGE_LIST_SMALL);

  InsertColumn(0, wxT("image"), wxLIST_FORMAT_LEFT, 32);
  InsertColumn(1, wxT("line"), wxLIST_FORMAT_LEFT, 64);
  InsertColumn(kSourceColumn, wxT("source"), wxLIST_FORMAT_LEFT, -1);

  Connect(
    GetId(), -1, wxEVT_COMMAND_LIST_ITEM_ACTIVATED,
    (wxObjectEventFunction)(wxEventFunction)(wxListEventFunction)&ScrFileCtrl::OnLineActivated
  );
}

/**
 * Address: 0x004C26A0 (FUN_004C26A0)
 * Deleting: 0x004C2680 (FUN_004C2680)
 */
moho::ScrFileCtrl::~ScrFileCtrl() = default;

/**
 * Address: 0x004C2730 (FUN_004C2730)
 *
 * The loop stops on badbit or eofbit only: a line that fills the buffer sets
 * failbit alone, after which every getline fails without reaching either and
 * the loop keeps appending empty lines. A last line with no newline is
 * dropped. Both as shipped.
 */
bool moho::ScrFileCtrl::Load(const msvc8::string& fileName)
{
  Clear();
  if (fileName.empty()) {
    return false;
  }

  msvc8::string diskPath;
  (void)DISK_GetVFS()->FindFile(&diskPath, fileName.c_str(), nullptr);
  if (diskPath.empty()) {
    return false;
  }

  std::fstream file(diskPath.c_str(), std::ios::in);
  if (!file.is_open()) {
    return false;
  }

  char buffer[1024];
  int lineNumber = 1;
  file.getline(buffer, sizeof(buffer));
  while (!file.bad() && !file.eof()) {
    mLines.push_back(ScrFileLine(lineNumber++, buffer));
    file.getline(buffer, sizeof(buffer));
  }

  mSourcePath = fileName;
  LoadBreakpoints();
  SetItemCount(static_cast<long>(mLines.size()));
  return true;
}

/**
 * Address: 0x004C2DA0 (FUN_004C2DA0)
 */
void moho::ScrFileCtrl::Clear()
{
  mLines.clear();
  SetItemCount(0);
  mCursorLine = 0;
}

/**
 * Address: 0x004C2A40 (FUN_004C2A40)
 */
void moho::ScrFileCtrl::FindFirst(const msvc8::string& text)
{
  const int lineCount = static_cast<int>(mLines.size());
  bool found = false;
  for (int index = 0; !found && index < lineCount; ++index) {
    found = mLines[index].mSourceText.find(text.c_str(), 0, text.size()) != msvc8::string::npos;
    if (found) {
      SetItemState(index, kFoundLineState, kFoundLineState);
      EnsureVisible(index);
    }
  }
}

/**
 * Address: 0x004C2AE0 (FUN_004C2AE0)
 */
void moho::ScrFileCtrl::FindNext(const msvc8::string& text)
{
  const long selected = GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
  if (selected < 0) {
    return;
  }

  const int lineCount = static_cast<int>(mLines.size());
  bool found = false;
  for (int index = selected + 1; !found && index < lineCount; ++index) {
    found = mLines[index].mSourceText.find(text.c_str(), 0, text.size()) != msvc8::string::npos;
    if (found) {
      SetItemState(index, kFoundLineState, kFoundLineState);
      EnsureVisible(index);
    }
  }
}

/**
 * Address: 0x004C2B90 (FUN_004C2B90)
 */
void moho::ScrFileCtrl::FindPrevious(const msvc8::string& text)
{
  const long selected = GetNextItem(-1, wxLIST_NEXT_ALL, wxLIST_STATE_SELECTED);
  if (selected < 0) {
    return;
  }

  bool found = false;
  for (int index = selected - 1; !found && index > -1; --index) {
    found = mLines[index].mSourceText.find(text.c_str(), 0, text.size()) != msvc8::string::npos;
    if (found) {
      SetItemState(index, kFoundLineState, kFoundLineState);
      EnsureVisible(index);
    }
  }
}

/**
 * Address: 0x004C2C20 (FUN_004C2C20)
 */
void moho::ScrFileCtrl::GotoLine(const int line)
{
  const int index = line - 1;
  if (index > -1 && index < static_cast<int>(mLines.size())) {
    SetItemState(index, kFoundLineState, kFoundLineState);
    EnsureVisible(index);
  }
}

/**
 * Address: 0x004C2C60 (FUN_004C2C60)
 */
void moho::ScrFileCtrl::EnableBreakpoints(const bool enable)
{
  const int lineCount = static_cast<int>(mLines.size());
  for (int index = 0; index < lineCount; ++index) {
    ScrFileLine& fileLine = mLines[index];
    switch (fileLine.mMarkerState) {
      case kCursorOnBreakpointMarker:
      case kCursorOnDisabledBreakpointMarker:
        fileLine.mMarkerState = enable ? kCursorOnBreakpointMarker : kCursorOnDisabledBreakpointMarker;
        break;
      case kBreakpointMarker:
      case kDisabledBreakpointMarker:
        fileLine.mMarkerState = enable ? kBreakpointMarker : kDisabledBreakpointMarker;
        break;
    }
    RefreshItem(index);
  }
}

/**
 * Address: 0x004C2CF0 (FUN_004C2CF0)
 */
void moho::ScrFileCtrl::RemoveBreakpoint(const int line)
{
  const int index = line - 1;
  if (index < 0 || index >= static_cast<int>(mLines.size())) {
    return;
  }

  ScrFileLine& fileLine = mLines[index];
  switch (fileLine.mMarkerState) {
    case kCursorOnBreakpointMarker:
    case kCursorOnDisabledBreakpointMarker:
      fileLine.mMarkerState = kCursorMarker;
      break;
    case kBreakpointMarker:
    case kDisabledBreakpointMarker:
      fileLine.mMarkerState = kNoMarker;
      break;
  }
  RefreshItem(index);
}

/**
 * Address: 0x004C2D60 (FUN_004C2D60)
 */
void moho::ScrFileCtrl::RemoveAllBreakpoints()
{
  const int lineCount = static_cast<int>(mLines.size());
  for (int index = 0; index < lineCount; ++index) {
    RemoveBreakpoint(index + 1);
  }
}

/**
 * Address: 0x004C2DE0 (FUN_004C2DE0)
 */
bool moho::ScrFileCtrl::SetCursorLine(const int line)
{
  const int index = line - 1;
  if (index > -1 && index < static_cast<int>(mLines.size())) {
    ScrFileLine& fileLine = mLines[index];
    mCursorLine = line;
    switch (fileLine.mMarkerState) {
      case kNoMarker:
        fileLine.mMarkerState = kCursorMarker;
        break;
      case kBreakpointMarker:
        fileLine.mMarkerState = kCursorOnBreakpointMarker;
        break;
      case kDisabledBreakpointMarker:
        fileLine.mMarkerState = kCursorOnDisabledBreakpointMarker;
        break;
    }
    RefreshItem(index);
    EnsureVisible(index);
    return true;
  }

  gpg::Warnf("invalid cursor location: %s(%i)", mSourcePath.c_str(), line);
  return false;
}

/**
 * Address: 0x004C2EA0 (FUN_004C2EA0)
 */
void moho::ScrFileCtrl::ClearCursor()
{
  if (mCursorLine < 1) {
    return;
  }

  const int index = mCursorLine - 1;
  ScrFileLine& fileLine = mLines[index];
  mCursorLine = 0;
  switch (fileLine.mMarkerState) {
    case kCursorMarker:
      fileLine.mMarkerState = kNoMarker;
      break;
    case kCursorOnBreakpointMarker:
      fileLine.mMarkerState = kBreakpointMarker;
      break;
    case kCursorOnDisabledBreakpointMarker:
      fileLine.mMarkerState = kDisabledBreakpointMarker;
      break;
  }
  RefreshItem(index);
}

/**
 * Address: 0x004C2F30 (FUN_004C2F30)
 */
wxString moho::ScrFileCtrl::OnGetItemText(const long item, const long column) const
{
  if (column == 1) {
    return gpg::STR_Utf8ToWide(mLines[item].mLineNumberText.c_str()).c_str();
  }
  if (column == kSourceColumn) {
    return gpg::STR_Utf8ToWide(mLines[item].mSourceText.c_str()).c_str();
  }
  return wxT("");
}

/**
 * Address: 0x004C2F10 (FUN_004C2F10)
 */
int moho::ScrFileCtrl::OnGetItemImage(const long item) const
{
  return mLines[item].mMarkerState;
}

/**
 * Address: 0x004C30B0 (FUN_004C30B0)
 *
 * The four statics are guarded by bits 1, 2, 4 and 8 of 0x011040BC, in this
 * order: the font (0x01103EE0), black (0x01103EEC), the odd-line colour
 * (0x011040AC) and the even-line colour (0x0110409C). The attribute's
 * constructor (0x004C1A60) has the text colour and the font folded in.
 */
wxListItemAttr* moho::ScrFileCtrl::OnGetItemAttr(const long item) const
{
  static wxFont sourceFont(10, wxDEFAULT, wxNORMAL, wxNORMAL, false, wxT("Courier New"));
  static wxColour textColour(0, 0, 0);
  static wxColour oddLineColour(247, 247, 255);
  static wxColour evenLineColour(254, 254, 255);
  return new wxListItemAttr(textColour, (item % 2) != 0 ? oddLineColour : evenLineColour, sourceFont);
}

/**
 * Address: 0x004C3270 (FUN_004C3270)
 */
void moho::ScrFileCtrl::OnLineActivated(wxListEvent& event)
{
  const long item = event.GetIndex();
  ScrFileLine& fileLine = mLines[item];
  switch (fileLine.mMarkerState) {
    case kNoMarker:
      fileLine.mMarkerState = kBreakpointMarker;
      SCR_AddBreakpoint(ScrBreakpoint(mSourcePath, item + 1));
      break;
    case kCursorMarker:
      fileLine.mMarkerState = kCursorOnBreakpointMarker;
      SCR_AddBreakpoint(ScrBreakpoint(mSourcePath, item + 1));
      break;
    case kCursorOnBreakpointMarker:
    case kCursorOnDisabledBreakpointMarker:
      fileLine.mMarkerState = kCursorMarker;
      SCR_RemoveBreakpoint(ScrBreakpoint(mSourcePath, item + 1));
      break;
    case kBreakpointMarker:
    case kDisabledBreakpointMarker:
      fileLine.mMarkerState = kNoMarker;
      SCR_RemoveBreakpoint(ScrBreakpoint(mSourcePath, item + 1));
      break;
  }
  RefreshItem(item);
}

/**
 * Address: 0x004C33D0 (FUN_004C33D0)
 */
void moho::ScrFileCtrl::OnSize(wxSizeEvent& event)
{
  SetColumnWidth(kSourceColumn, event.GetSize().x - 100);
}

/**
 * Address: 0x004C3400 (FUN_004C3400)
 *
 * A breakpoint on line 0 or below passes the check and writes in front of
 * mLines, as shipped.
 */
void moho::ScrFileCtrl::LoadBreakpoints()
{
  msvc8::vector<ScrBreakpoint> breakpoints;
  SCR_EnumerateBreakpoints(mSourcePath, breakpoints);
  for (const ScrBreakpoint& breakpoint : breakpoints) {
    const int index = breakpoint.line - 1;
    if (index < static_cast<int>(mLines.size())) {
      mLines[index].mMarkerState = breakpoint.enabled ? kBreakpointMarker : kDisabledBreakpointMarker;
    } else {
      gpg::Warnf("Invalid breakpoint: %s(%d)", breakpoint.name.c_str(), breakpoint.line);
    }
  }
}
