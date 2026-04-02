#include "moho/misc/ScrFileCtrl.h"

#include <cstdint>
#include <fstream>
#include <new>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <CommCtrl.h>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ScrBreakpoint.h"
#include "moho/misc/ScrDebugHooks.h"

namespace
{
  constexpr std::uint32_t kSelectStateFlags = 6u;
  constexpr std::uint32_t kSelectStateMask = 6u;
  constexpr int kMarkerImageWidth = 24;
  constexpr int kMarkerImageHeight = 12;

  constexpr const char* kCursorMarkerImagePath = "/coderes/engine/dbg_cursor.bmp";
  constexpr const char* kCursorEnabledMarkerImagePath = "/coderes/engine/dbg_cursor_enabled.bmp";
  constexpr const char* kCursorDisabledMarkerImagePath = "/coderes/engine/dbg_cursor_disabled.bmp";
  constexpr const char* kBreakpointEnabledMarkerImagePath = "/coderes/engine/dbg_break_enabled.bmp";
  constexpr const char* kBreakpointDisabledMarkerImagePath = "/coderes/engine/dbg_break_disabled.bmp";

  struct wxListActivationEventRuntimeView
  {
    std::uint8_t mUnknown00To3F[0x40];
    std::int32_t mItemIndex = -1;
  };

  static_assert(
    offsetof(wxListActivationEventRuntimeView, mItemIndex) == 0x40,
    "wxListActivationEventRuntimeView::mItemIndex offset must be 0x40"
  );

  struct wxSizeEventRuntimeView
  {
    std::uint8_t mUnknown00To1F[0x20];
    std::int32_t mWidth = 0;
    std::int32_t mHeight = 0;
  };

  static_assert(offsetof(wxSizeEventRuntimeView, mWidth) == 0x20, "wxSizeEventRuntimeView::mWidth offset must be 0x20");
  static_assert(
    offsetof(wxSizeEventRuntimeView, mHeight) == 0x24,
    "wxSizeEventRuntimeView::mHeight offset must be 0x24"
  );

  [[nodiscard]] HWND AsListViewHandle(void* const runtimeHandle) noexcept
  {
    return reinterpret_cast<HWND>(runtimeHandle);
  }

  [[nodiscard]] wxStringRuntime BorrowUtf8AsWxString(const msvc8::string& text)
  {
    static thread_local std::wstring wideScratch{};
    wideScratch = gpg::STR_Utf8ToWide(text.c_str());
    return wxStringRuntime::Borrow(wideScratch.c_str());
  }

  [[nodiscard]] bool ResolveMountedPath(
    const msvc8::string& mountedPath,
    msvc8::string& outResolvedPath
  )
  {
    outResolvedPath.assign(mountedPath, 0U, msvc8::string::npos);
    if (outResolvedPath.empty()) {
      return false;
    }

    moho::FILE_EnsureWaitHandleSet();
    if (moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS(); vfs != nullptr) {
      (void)vfs->FindFile(&outResolvedPath, outResolvedPath.c_str(), nullptr);
    }

    return !outResolvedPath.empty();
  }

  void InsertDefaultColumns(HWND const listView)
  {
    if (listView == nullptr) {
      return;
    }

    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_FMT | LVCF_WIDTH;
    column.fmt = LVCFMT_LEFT;

    column.pszText = const_cast<wchar_t*>(L"image");
    column.cx = 32;
    (void)::SendMessageW(listView, LVM_INSERTCOLUMNW, 0, reinterpret_cast<LPARAM>(&column));

    column.pszText = const_cast<wchar_t*>(L"line");
    column.cx = 64;
    (void)::SendMessageW(listView, LVM_INSERTCOLUMNW, 1, reinterpret_cast<LPARAM>(&column));

    column.pszText = const_cast<wchar_t*>(L"source");
    column.cx = -1;
    (void)::SendMessageW(listView, LVM_INSERTCOLUMNW, 2, reinterpret_cast<LPARAM>(&column));
  }

  void TryAddMarkerBitmap(const HIMAGELIST imageList, const msvc8::string& mountedPath)
  {
    if (imageList == nullptr || mountedPath.empty()) {
      return;
    }

    msvc8::string resolvedPath{};
    if (!ResolveMountedPath(mountedPath, resolvedPath)) {
      return;
    }

    const std::wstring resolvedWidePath = gpg::STR_Utf8ToWide(resolvedPath.c_str());
    const HBITMAP bitmap = reinterpret_cast<HBITMAP>(
      ::LoadImageW(nullptr, resolvedWidePath.c_str(), IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE)
    );
    if (bitmap == nullptr) {
      return;
    }

    (void)::ImageList_AddMasked(imageList, bitmap, RGB(255, 0, 255));
    (void)::DeleteObject(bitmap);
  }
} // namespace

void* moho::ScrFileCtrl::sm_eventTable[1] = {nullptr};

/**
 * Address: 0x004C1EE0 (FUN_004C1EE0)
 *
 * wxWindow *
 *
 * What it does:
 * Constructs one virtual source-file list control, binds marker imagery, and
 * initializes virtual columns used by script source rows.
 */
moho::ScrFileCtrl::ScrFileCtrl(wxWindowBase* const parentWindow)
{
  INITCOMMONCONTROLSEX commonControls{};
  commonControls.dwSize = sizeof(commonControls);
  commonControls.dwICC = ICC_LISTVIEW_CLASSES;
  (void)::InitCommonControlsEx(&commonControls);

  const HWND parentHandle = parentWindow != nullptr ? reinterpret_cast<HWND>(parentWindow->GetHandle()) : nullptr;
  const DWORD style = WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_OWNERDATA;
  const HWND listViewHandle = ::CreateWindowExW(
    0,
    WC_LISTVIEWW,
    L"wxListCtrl",
    style,
    0,
    0,
    0,
    0,
    parentHandle,
    reinterpret_cast<HMENU>(static_cast<std::intptr_t>(-1)),
    nullptr,
    nullptr
  );
  mListViewHandle = listViewHandle;

  const HIMAGELIST markerImages = ::ImageList_Create(kMarkerImageWidth, kMarkerImageHeight, ILC_COLOR32 | ILC_MASK, 5, 0);
  mMarkerImageList = markerImages;
  if (markerImages != nullptr) {
    TryAddMarkerBitmap(markerImages, msvc8::string(kCursorMarkerImagePath));
    TryAddMarkerBitmap(markerImages, msvc8::string(kCursorEnabledMarkerImagePath));
    TryAddMarkerBitmap(markerImages, msvc8::string(kCursorDisabledMarkerImagePath));
    TryAddMarkerBitmap(markerImages, msvc8::string(kBreakpointEnabledMarkerImagePath));
    TryAddMarkerBitmap(markerImages, msvc8::string(kBreakpointDisabledMarkerImagePath));
  }

  if (listViewHandle != nullptr) {
    if (markerImages != nullptr) {
      (void)::SendMessageW(
        listViewHandle,
        LVM_SETIMAGELIST,
        static_cast<WPARAM>(LVSIL_SMALL),
        reinterpret_cast<LPARAM>(markerImages)
      );
    }
    InsertDefaultColumns(listViewHandle);
    SetVirtualLineCount(0);
  }
}

/**
 * Address: 0x004C1ED0 (FUN_004C1ED0)
 *
 * What it does:
 * Returns this control's wx event-table lane.
 */
const void* moho::ScrFileCtrl::GetEventTable() const
{
  return sm_eventTable;
}

/**
 * Address: 0x004C2680 (FUN_004C2680)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for one script-file control.
 */
moho::ScrFileCtrl* moho::ScrFileCtrl::DeleteWithFlag(
  ScrFileCtrl* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  object->~ScrFileCtrl();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004C26A0 (FUN_004C26A0)
 *
 * What it does:
 * Releases source-file state lanes and returns to base list-control state.
 */
moho::ScrFileCtrl::~ScrFileCtrl()
{
  if (mMarkerImageList != nullptr) {
    (void)::ImageList_Destroy(reinterpret_cast<HIMAGELIST>(mMarkerImageList));
    mMarkerImageList = nullptr;
  }
}

int moho::ScrFileCtrl::GetLineCount() const noexcept
{
  return static_cast<int>(mLines.size());
}

int moho::ScrFileCtrl::GetSelectedRowIndex() const noexcept
{
  const HWND listView = AsListViewHandle(mListViewHandle);
  if (listView == nullptr) {
    return -1;
  }

  return static_cast<int>(
    ::SendMessageW(
      listView,
      LVM_GETNEXTITEM,
      static_cast<WPARAM>(-1),
      static_cast<LPARAM>(LVNI_SELECTED)
    )
  );
}

void moho::ScrFileCtrl::SetRowState(
  const int lineIndexZeroBased,
  const std::uint32_t stateFlags,
  const std::uint32_t stateMask
) noexcept
{
  const HWND listView = AsListViewHandle(mListViewHandle);
  if (listView == nullptr || lineIndexZeroBased < 0) {
    return;
  }

  LVITEMW listItem{};
  listItem.state = stateFlags;
  listItem.stateMask = stateMask;
  (void)::SendMessageW(
    listView,
    LVM_SETITEMSTATE,
    static_cast<WPARAM>(lineIndexZeroBased),
    reinterpret_cast<LPARAM>(&listItem)
  );
}

void moho::ScrFileCtrl::EnsureRowVisible(const int lineIndexZeroBased) noexcept
{
  const HWND listView = AsListViewHandle(mListViewHandle);
  if (listView == nullptr || lineIndexZeroBased < 0) {
    return;
  }

  (void)::SendMessageW(
    listView,
    LVM_ENSUREVISIBLE,
    static_cast<WPARAM>(lineIndexZeroBased),
    static_cast<LPARAM>(0)
  );
}

void moho::ScrFileCtrl::RedrawRow(const int lineIndexZeroBased) noexcept
{
  const HWND listView = AsListViewHandle(mListViewHandle);
  if (listView == nullptr || lineIndexZeroBased < 0) {
    return;
  }

  (void)::SendMessageW(
    listView,
    LVM_REDRAWITEMS,
    static_cast<WPARAM>(lineIndexZeroBased),
    static_cast<LPARAM>(lineIndexZeroBased)
  );
}

void moho::ScrFileCtrl::SetVirtualLineCount(const int lineCount) noexcept
{
  const HWND listView = AsListViewHandle(mListViewHandle);
  if (listView == nullptr) {
    return;
  }

  (void)::SendMessageW(
    listView,
    LVM_SETITEMCOUNT,
    static_cast<WPARAM>(lineCount >= 0 ? lineCount : 0),
    static_cast<LPARAM>(0)
  );
}

bool moho::ScrFileCtrl::ContainsSourceMatch(
  const int lineIndexZeroBased,
  const msvc8::string& needle
) const
{
  if (lineIndexZeroBased < 0 || lineIndexZeroBased >= GetLineCount() || needle.empty()) {
    return false;
  }

  const ScrFileLine& sourceLine = mLines[static_cast<std::size_t>(lineIndexZeroBased)];
  return sourceLine.mSourceText.find(needle.c_str(), 0U, needle.size()) != msvc8::string::npos;
}

/**
 * Address: 0x004C2A40 (FUN_004C2A40)
 *
 * msvc8::string const &
 *
 * What it does:
 * Finds and selects the first source line containing one search token.
 */
bool moho::ScrFileCtrl::FindAndSelectFirstSourceMatch(const msvc8::string& needle)
{
  const int lineCount = GetLineCount();
  for (int lineIndex = 0; lineIndex < lineCount; ++lineIndex) {
    if (!ContainsSourceMatch(lineIndex, needle)) {
      continue;
    }

    SetRowState(lineIndex, kSelectStateFlags, kSelectStateMask);
    EnsureRowVisible(lineIndex);
    return true;
  }

  return false;
}

/**
 * Address: 0x004C2AE0 (FUN_004C2AE0)
 *
 * msvc8::string const &
 *
 * What it does:
 * Finds and selects the next source line containing one search token.
 */
bool moho::ScrFileCtrl::FindAndSelectNextSourceMatch(const msvc8::string& needle)
{
  const int selectedLine = GetSelectedRowIndex();
  if (selectedLine < 0) {
    return false;
  }

  const int lineCount = GetLineCount();
  for (int lineIndex = selectedLine + 1; lineIndex < lineCount; ++lineIndex) {
    if (!ContainsSourceMatch(lineIndex, needle)) {
      continue;
    }

    SetRowState(lineIndex, kSelectStateFlags, kSelectStateMask);
    EnsureRowVisible(lineIndex);
    return true;
  }

  return false;
}

/**
 * Address: 0x004C2B90 (FUN_004C2B90)
 *
 * msvc8::string const &
 *
 * What it does:
 * Finds and selects the previous source line containing one search token.
 */
bool moho::ScrFileCtrl::FindAndSelectPreviousSourceMatch(const msvc8::string& needle)
{
  const int selectedLine = GetSelectedRowIndex();
  if (selectedLine < 0) {
    return false;
  }

  for (int lineIndex = selectedLine - 1; lineIndex >= 0; --lineIndex) {
    if (!ContainsSourceMatch(lineIndex, needle)) {
      continue;
    }

    SetRowState(lineIndex, kSelectStateFlags, kSelectStateMask);
    EnsureRowVisible(lineIndex);
    return true;
  }

  return false;
}

/**
 * Address: 0x004C2C20 (FUN_004C2C20)
 *
 * int
 *
 * What it does:
 * Selects and focuses the line immediately before the provided one-based
 * source line.
 */
void moho::ScrFileCtrl::SelectPreviousSourceLine(const int lineOneBased)
{
  const int lineIndexZeroBased = lineOneBased - 1;
  if (lineIndexZeroBased < 0 || lineIndexZeroBased >= GetLineCount()) {
    return;
  }

  SetRowState(lineIndexZeroBased, kSelectStateFlags, kSelectStateMask);
  EnsureRowVisible(lineIndexZeroBased);
}

/**
 * Address: 0x004C2C60 (FUN_004C2C60)
 *
 * bool
 *
 * What it does:
 * Enables or disables all breakpoint marker lanes already present in this
 * control.
 */
void moho::ScrFileCtrl::SetBreakpointMarkersEnabled(const bool enabled)
{
  const int lineCount = GetLineCount();
  for (int lineIndex = 0; lineIndex < lineCount; ++lineIndex) {
    ScrFileLine& line = mLines[static_cast<std::size_t>(lineIndex)];
    switch (line.mMarkerState) {
      case 1:
      case 2:
        line.mMarkerState = enabled ? 1 : 2;
        break;
      case 3:
      case 4:
        line.mMarkerState = enabled ? 3 : 4;
        break;
      default:
        break;
    }

    RedrawRow(lineIndex);
  }
}

/**
 * Address: 0x004C2CF0 (FUN_004C2CF0)
 *
 * int
 *
 * What it does:
 * Clears one breakpoint marker lane at the provided one-based source line.
 */
void moho::ScrFileCtrl::ClearBreakpointMarkerAtLine(const int lineOneBased)
{
  const int lineIndexZeroBased = lineOneBased - 1;
  if (lineIndexZeroBased < 0 || lineIndexZeroBased >= GetLineCount()) {
    return;
  }

  ScrFileLine& line = mLines[static_cast<std::size_t>(lineIndexZeroBased)];
  switch (line.mMarkerState) {
    case 1:
    case 2:
      line.mMarkerState = 0;
      break;
    case 3:
    case 4:
      line.mMarkerState = -1;
      break;
    default:
      break;
  }

  RedrawRow(lineIndexZeroBased);
}

/**
 * Address: 0x004C2DE0 (FUN_004C2DE0)
 *
 * int
 *
 * What it does:
 * Sets one active cursor location and updates marker state for that line.
 */
bool moho::ScrFileCtrl::SetCursorLocation(const int lineOneBased)
{
  const int lineIndexZeroBased = lineOneBased - 1;
  if (lineIndexZeroBased < 0 || lineIndexZeroBased >= GetLineCount()) {
    gpg::Warnf("invalid cursor location: %s(%i)", mSourcePath.c_str(), lineOneBased);
    return false;
  }

  mActiveCursorLineOneBased = lineOneBased;
  ScrFileLine& line = mLines[static_cast<std::size_t>(lineIndexZeroBased)];
  switch (line.mMarkerState) {
    case -1:
      line.mMarkerState = 0;
      break;
    case 3:
      line.mMarkerState = 1;
      break;
    case 4:
      line.mMarkerState = 2;
      break;
    default:
      break;
  }

  RedrawRow(lineIndexZeroBased);
  EnsureRowVisible(lineIndexZeroBased);
  return true;
}

/**
 * Address: 0x004C2EA0 (FUN_004C2EA0)
 *
 * What it does:
 * Clears the current active cursor location marker.
 */
void moho::ScrFileCtrl::ClearCursorLocation()
{
  if (mActiveCursorLineOneBased < 1) {
    return;
  }

  const int lineIndexZeroBased = mActiveCursorLineOneBased - 1;
  mActiveCursorLineOneBased = 0;
  if (lineIndexZeroBased < 0 || lineIndexZeroBased >= GetLineCount()) {
    return;
  }

  ScrFileLine& line = mLines[static_cast<std::size_t>(lineIndexZeroBased)];
  switch (line.mMarkerState) {
    case 0:
      line.mMarkerState = -1;
      break;
    case 1:
      line.mMarkerState = 3;
      break;
    case 2:
      line.mMarkerState = 4;
      break;
    default:
      break;
  }

  RedrawRow(lineIndexZeroBased);
}

/**
 * Address: 0x004C2F10 (FUN_004C2F10)
 *
 * int
 *
 * What it does:
 * Returns one stored marker-state lane for the requested source row index.
 */
int moho::ScrFileCtrl::GetLineMarkerState(const int lineIndexZeroBased) const
{
  if (lineIndexZeroBased < 0 || lineIndexZeroBased >= GetLineCount()) {
    return -1;
  }

  return mLines[static_cast<std::size_t>(lineIndexZeroBased)].mMarkerState;
}

/**
 * Address: 0x004C2F30 (FUN_004C2F30)
 *
 * int,int
 *
 * What it does:
 * Returns one virtual-list text lane for source-line and column indices.
 */
wxStringRuntime moho::ScrFileCtrl::GetVirtualItemText(
  const int lineIndexZeroBased,
  const int columnIndex
) const
{
  if (lineIndexZeroBased < 0 || lineIndexZeroBased >= GetLineCount()) {
    return wxStringRuntime::Borrow(L"");
  }

  const ScrFileLine& line = mLines[static_cast<std::size_t>(lineIndexZeroBased)];
  if (columnIndex == 1) {
    return BorrowUtf8AsWxString(line.mLineNumberText);
  }
  if (columnIndex == 2) {
    return BorrowUtf8AsWxString(line.mSourceText);
  }
  return wxStringRuntime::Borrow(L"");
}

/**
 * Address: 0x004C3270 (FUN_004C3270)
 *
 * void *
 *
 * What it does:
 * Toggles one line breakpoint marker from an item-activation event.
 */
void moho::ScrFileCtrl::OnLineActivated(const void* const listEvent)
{
  const auto* const eventView = reinterpret_cast<const wxListActivationEventRuntimeView*>(listEvent);
  const int lineIndexZeroBased = eventView != nullptr ? eventView->mItemIndex : -1;
  if (lineIndexZeroBased < 0 || lineIndexZeroBased >= GetLineCount()) {
    return;
  }

  ScrFileLine& line = mLines[static_cast<std::size_t>(lineIndexZeroBased)];
  const int lineOneBased = lineIndexZeroBased + 1;
  const ScrBreakpoint breakpoint(mSourcePath, lineOneBased);

  switch (line.mMarkerState) {
    case -1:
      line.mMarkerState = 3;
      SCR_AddBreakpoint(breakpoint);
      break;
    case 0:
      line.mMarkerState = 1;
      SCR_AddBreakpoint(breakpoint);
      break;
    case 1:
    case 2:
      line.mMarkerState = 0;
      SCR_RemoveBreakpoint(breakpoint);
      break;
    case 3:
    case 4:
      line.mMarkerState = -1;
      SCR_RemoveBreakpoint(breakpoint);
      break;
    default:
      break;
  }

  RedrawRow(lineIndexZeroBased);
}

/**
 * Address: 0x004C3400 (FUN_004C3400)
 *
 * What it does:
 * Reapplies persisted breakpoints for this source file into line markers.
 */
void moho::ScrFileCtrl::RefreshBreakpointMarkers()
{
  msvc8::vector<ScrBreakpoint> breakpoints{};
  SCR_EnumerateBreakpoints(mSourcePath, breakpoints);

  const int lineCount = GetLineCount();
  for (const ScrBreakpoint& breakpoint : breakpoints) {
    const int lineIndexZeroBased = breakpoint.line - 1;
    if (lineIndexZeroBased < 0 || lineIndexZeroBased >= lineCount) {
      gpg::Warnf("Invalid breakpoint: %s(%d)", breakpoint.name.c_str(), breakpoint.line);
      continue;
    }

    ScrFileLine& line = mLines[static_cast<std::size_t>(lineIndexZeroBased)];
    line.mMarkerState = breakpoint.enabled ? 3 : 4;
  }
}

/**
 * Address: 0x004C2730 (FUN_004C2730)
 *
 * msvc8::string const &
 *
 * What it does:
 * Clears existing rows, loads one mounted source file line-by-line, reapplies
 * persisted breakpoint states, and refreshes virtual row count.
 */
bool moho::ScrFileCtrl::LoadSourceFile(const msvc8::string& mountedSourcePath)
{
  ClearLoadedSource();
  if (mountedSourcePath.empty()) {
    return false;
  }

  msvc8::string resolvedPath{};
  if (!ResolveMountedPath(mountedSourcePath, resolvedPath)) {
    return false;
  }

  std::fstream sourceStream(resolvedPath.c_str(), std::ios::in);
  if (!sourceStream.is_open()) {
    return false;
  }

  std::string sourceLineBuffer{};
  int nextLineNumberOneBased = 1;
  while (std::getline(sourceStream, sourceLineBuffer)) {
    msvc8::string sourceLine{};
    sourceLine.assign(sourceLineBuffer.c_str(), sourceLineBuffer.size());
    mLines.push_back(ScrFileLine(nextLineNumberOneBased, sourceLine));
    ++nextLineNumberOneBased;
  }

  mSourcePath.assign(mountedSourcePath, 0U, msvc8::string::npos);
  RefreshBreakpointMarkers();
  SetVirtualLineCount(GetLineCount());
  return true;
}

/**
 * Address: 0x004C2DA0 (FUN_004C2DA0)
 *
 * What it does:
 * Clears all loaded line records, resets virtual item count, and clears active
 * cursor location.
 */
void moho::ScrFileCtrl::ClearLoadedSource()
{
  mLines.clear();
  SetVirtualLineCount(0);
  mActiveCursorLineOneBased = 0;
}

/**
 * Address: 0x004C30B0 (FUN_004C30B0)
 *
 * int
 *
 * What it does:
 * Returns one heap-allocated alternating-row text style object for virtual
 * source rows.
 */
void* moho::ScrFileCtrl::GetVirtualItemTextStyle(const int lineIndexZeroBased) const
{
  static const wxColourRuntime kForeground = wxColourRuntime::FromRgb(0x00, 0x00, 0x00);
  static const wxColourRuntime kOddBackground = wxColourRuntime::FromRgb(0xF7, 0xF7, 0xFF);
  static const wxColourRuntime kEvenBackground = wxColourRuntime::FromRgb(0xFE, 0xFE, 0xFF);

  const wxColourRuntime& background = ((lineIndexZeroBased & 1) == 0) ? kEvenBackground : kOddBackground;
  return new (std::nothrow) wxTextAttrRuntime(kForeground, background, wxFontRuntime::Null());
}

/**
 * Address: 0x004C33D0 (FUN_004C33D0)
 *
 * void *
 *
 * What it does:
 * Resizes the source-text column to keep it width-coupled to the current
 * control client width.
 */
void moho::ScrFileCtrl::OnResizeAdjustSourceColumn(const void* const sizeEvent)
{
  const auto* const eventView = reinterpret_cast<const wxSizeEventRuntimeView*>(sizeEvent);
  if (eventView == nullptr) {
    return;
  }

  const int sourceColumnWidth = eventView->mWidth - 100;
  const HWND listView = AsListViewHandle(mListViewHandle);
  if (listView == nullptr) {
    return;
  }

  (void)::SendMessageW(
    listView,
    LVM_SETCOLUMNWIDTH,
    static_cast<WPARAM>(2),
    static_cast<LPARAM>(sourceColumnWidth)
  );
}
