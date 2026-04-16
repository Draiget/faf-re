#include "moho/misc/ScrDebugWindow.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <new>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <CommCtrl.h>

#include "gpg/core/containers/String.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ScrActivation.h"
#include "moho/misc/ScrBreakpoint.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/misc/ScrFileCtrl.h"
#include "moho/misc/ScrGotoDialog.h"
#include "moho/misc/ScrPauseEvent.h"
#include "moho/misc/ScrWatchCtrl.h"
#include "moho/misc/StartupHelpers.h"

namespace
{
  constexpr char kDebugVerticalSashPreferenceKey[] = "Windows.Debug.Sash.vertical";
  constexpr char kDebugHorizontalSashPreferenceKey[] = "Windows.Debug.Sash.horizontal";
  constexpr char kDebugCallStackSourceColumnPreferenceKey[] = "Windows.Debug.Watch.Stack.source";
  constexpr char kDebugCallStackBlockColumnPreferenceKey[] = "Windows.Debug.Watch.Stack.block";
  constexpr char kDebugCallStackLineColumnPreferenceKey[] = "Windows.Debug.Watch.Stack.line";
  constexpr char kDebugLocalWatchNameColumnPreferenceKey[] = "Windows.Debug.Watch.Local.name";
  constexpr char kDebugLocalWatchTypeColumnPreferenceKey[] = "Windows.Debug.Watch.Local.type";
  constexpr char kDebugLocalWatchValueColumnPreferenceKey[] = "Windows.Debug.Watch.Local.value";
  constexpr char kDebugGlobalWatchNameColumnPreferenceKey[] = "Windows.Debug.Watch.Global.name";
  constexpr char kDebugGlobalWatchTypeColumnPreferenceKey[] = "Windows.Debug.Watch.Global.type";
  constexpr char kDebugGlobalWatchValueColumnPreferenceKey[] = "Windows.Debug.Watch.Global.value";
  constexpr char kDebugRecentFilesPreferenceKey[] = "Options.Debug.Files";
  constexpr char kDebugWindowXPreferenceKey[] = "Windows.Debug.x";
  constexpr char kDebugWindowYPreferenceKey[] = "Windows.Debug.y";
  constexpr std::int32_t kWxDialogModalOk = 0x13EC;

  struct wxSplitterSashEventRuntimeView
  {
    std::uint8_t mUnknown00To37[0x38];
    std::int32_t mSashPosition = 0;
  };

  static_assert(sizeof(wxSplitterSashEventRuntimeView) == 0x3C, "wxSplitterSashEventRuntimeView size must be 0x3C");
  static_assert(
    offsetof(wxSplitterSashEventRuntimeView, mSashPosition) == 0x38,
    "wxSplitterSashEventRuntimeView::mSashPosition offset must be 0x38"
  );

  struct wxRectRuntime
  {
    std::int32_t x = 0;
    std::int32_t y = 0;
    std::int32_t width = 0;
    std::int32_t height = 0;
  };

  static_assert(sizeof(wxRectRuntime) == 0x10, "wxRectRuntime size must be 0x10");

  struct ScrSourceLineRuntimeRecord
  {
    std::uint8_t mUnknown00To03[0x04];
    std::int32_t mMarkerState = 0;
    std::uint8_t mUnknown08To23[0x1C];
    msvc8::string mLineText{};
  };

  static_assert(sizeof(ScrSourceLineRuntimeRecord) == 0x40, "ScrSourceLineRuntimeRecord size must be 0x40");
  static_assert(
    offsetof(ScrSourceLineRuntimeRecord, mMarkerState) == 0x04,
    "ScrSourceLineRuntimeRecord::mMarkerState offset must be 0x04"
  );
  static_assert(
    offsetof(ScrSourceLineRuntimeRecord, mLineText) == 0x24,
    "ScrSourceLineRuntimeRecord::mLineText offset must be 0x24"
  );

  struct ScrSourcePageRuntime : wxWindowBase
  {
    std::uint8_t mUnknown004To107[0x104];
    HWND mListViewHandle = nullptr;
    std::uint8_t mUnknown10CTo14F[0x44];
    std::int32_t mActiveCursorLineOneBased = 0;
    std::uint8_t mUnknown154To157[0x4];
    msvc8::string mSourcePath{};
    std::uint8_t mUnknown174To177[0x4];
    ScrSourceLineRuntimeRecord* mLineRecordsBegin = nullptr;
    ScrSourceLineRuntimeRecord* mLineRecordsEnd = nullptr;
    ScrSourceLineRuntimeRecord* mLineRecordsCapacity = nullptr;
  };

  static_assert(offsetof(ScrSourcePageRuntime, mListViewHandle) == 0x108, "ScrSourcePageRuntime::mListViewHandle offset must be 0x108");
  static_assert(
    offsetof(ScrSourcePageRuntime, mActiveCursorLineOneBased) == 0x150,
    "ScrSourcePageRuntime::mActiveCursorLineOneBased offset must be 0x150"
  );
  static_assert(
    offsetof(ScrSourcePageRuntime, mSourcePath) == 0x158,
    "ScrSourcePageRuntime::mSourcePath offset must be 0x158"
  );
  static_assert(
    offsetof(ScrSourcePageRuntime, mLineRecordsBegin) == 0x178,
    "ScrSourcePageRuntime::mLineRecordsBegin offset must be 0x178"
  );
  static_assert(
    offsetof(ScrSourcePageRuntime, mLineRecordsEnd) == 0x17C,
    "ScrSourcePageRuntime::mLineRecordsEnd offset must be 0x17C"
  );
  static_assert(
    offsetof(ScrSourcePageRuntime, mLineRecordsCapacity) == 0x180,
    "ScrSourcePageRuntime::mLineRecordsCapacity offset must be 0x180"
  );
  static_assert(sizeof(ScrSourcePageRuntime) == 0x184, "ScrSourcePageRuntime size must be 0x184");

  struct ScrSourceControlRuntimeView
  {
    std::uint8_t mUnknown000To14B[0x14C];
    ScrSourcePageRuntime** mPagesBegin = nullptr;
    ScrSourcePageRuntime** mPagesEnd = nullptr;
  };

  static_assert(
    offsetof(ScrSourceControlRuntimeView, mPagesBegin) == 0x14C,
    "ScrSourceControlRuntimeView::mPagesBegin offset must be 0x14C"
  );
  static_assert(
    offsetof(ScrSourceControlRuntimeView, mPagesEnd) == 0x150,
    "ScrSourceControlRuntimeView::mPagesEnd offset must be 0x150"
  );

  struct ScrListControlRuntime : wxWindowBase
  {
    std::uint8_t mUnknown004To107[0x104];
    HWND mListViewHandle = nullptr;
  };

  static_assert(
    offsetof(ScrListControlRuntime, mListViewHandle) == 0x108,
    "ScrListControlRuntime::mListViewHandle offset must be 0x108"
  );

  struct wxListSelectionEventRuntimeView
  {
    std::uint8_t mUnknown00To3F[0x40];
    std::int32_t mSelectedItemIndex = -1;
  };

  static_assert(
    offsetof(wxListSelectionEventRuntimeView, mSelectedItemIndex) == 0x40,
    "wxListSelectionEventRuntimeView::mSelectedItemIndex offset must be 0x40"
  );

  struct ScrWatchColumnRuntime
  {
    std::uint8_t mUnknown00To1B[0x1C];
    std::int32_t mWidth = -1;
  };

  static_assert(offsetof(ScrWatchColumnRuntime, mWidth) == 0x1C, "ScrWatchColumnRuntime::mWidth offset must be 0x1C");

  struct ScrWatchColumnOwnerRuntime
  {
    std::uint8_t mUnknown000To143[0x144];
    std::uint32_t mColumnCount = 0;
    ScrWatchColumnRuntime** mColumns = nullptr;
  };

  static_assert(
    offsetof(ScrWatchColumnOwnerRuntime, mColumnCount) == 0x144,
    "ScrWatchColumnOwnerRuntime::mColumnCount offset must be 0x144"
  );
  static_assert(
    offsetof(ScrWatchColumnOwnerRuntime, mColumns) == 0x148,
    "ScrWatchColumnOwnerRuntime::mColumns offset must be 0x148"
  );

  struct ScrWatchControlRuntime
  {
    std::uint8_t mUnknown000To12F[0x130];
    ScrWatchColumnOwnerRuntime* mColumnOwner = nullptr;
  };

  static_assert(
    offsetof(ScrWatchControlRuntime, mColumnOwner) == 0x130,
    "ScrWatchControlRuntime::mColumnOwner offset must be 0x130"
  );

  void PersistIntegerPreference(const char* const key, const std::int32_t value)
  {
    moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
    if (preferences == nullptr || key == nullptr) {
      return;
    }

    preferences->SetInteger(msvc8::string(key), value);
  }

  [[nodiscard]] std::int32_t GetListControlColumnWidth(
    const ScrListControlRuntime* const listControl,
    const std::uint32_t columnIndex
  )
  {
    if (listControl == nullptr || listControl->mListViewHandle == nullptr) {
      return -1;
    }

    return static_cast<std::int32_t>(
      ::SendMessageW(
        listControl->mListViewHandle,
        LVM_GETCOLUMNWIDTH,
        static_cast<WPARAM>(columnIndex),
        static_cast<LPARAM>(0)
      )
    );
  }

  [[nodiscard]] std::int32_t GetWatchControlColumnWidth(
    const ScrWatchControlRuntime* const watchControl,
    const std::uint32_t columnIndex
  )
  {
    if (watchControl == nullptr || watchControl->mColumnOwner == nullptr) {
      return -1;
    }

    const ScrWatchColumnOwnerRuntime* const columnOwner = watchControl->mColumnOwner;
    if (columnIndex >= columnOwner->mColumnCount || columnOwner->mColumns == nullptr) {
      return -1;
    }

    const ScrWatchColumnRuntime* const column = columnOwner->mColumns[columnIndex];
    return column != nullptr ? column->mWidth : -1;
  }

  void ClearListControlRows(ScrListControlRuntime* const listControl) noexcept
  {
    if (listControl == nullptr || listControl->mListViewHandle == nullptr) {
      return;
    }

    (void)::SendMessageW(
      listControl->mListViewHandle,
      LVM_DELETEALLITEMS,
      static_cast<WPARAM>(0),
      static_cast<LPARAM>(0)
    );
  }

  [[nodiscard]] bool InsertListControlRowText(
    ScrListControlRuntime* const listControl,
    const std::int32_t rowIndex,
    const msvc8::string& textUtf8
  )
  {
    if (listControl == nullptr || listControl->mListViewHandle == nullptr || rowIndex < 0) {
      return false;
    }

    const std::wstring textWide = gpg::STR_Utf8ToWide(textUtf8.c_str());
    LVITEMW listItem{};
    listItem.mask = LVIF_TEXT;
    listItem.iItem = rowIndex;
    listItem.iSubItem = 0;
    listItem.pszText = const_cast<wchar_t*>(textWide.c_str());

    const LRESULT insertedRow = ::SendMessageW(
      listControl->mListViewHandle,
      LVM_INSERTITEMW,
      static_cast<WPARAM>(0),
      reinterpret_cast<LPARAM>(&listItem)
    );
    return insertedRow != -1;
  }

  void SetListControlSubItemText(
    ScrListControlRuntime* const listControl,
    const std::int32_t rowIndex,
    const std::int32_t columnIndex,
    const msvc8::string& textUtf8
  ) noexcept
  {
    if (listControl == nullptr || listControl->mListViewHandle == nullptr || rowIndex < 0 || columnIndex < 0) {
      return;
    }

    const std::wstring textWide = gpg::STR_Utf8ToWide(textUtf8.c_str());
    LVITEMW listItem{};
    listItem.iSubItem = columnIndex;
    listItem.pszText = const_cast<wchar_t*>(textWide.c_str());

    (void)::SendMessageW(
      listControl->mListViewHandle,
      LVM_SETITEMTEXTW,
      static_cast<WPARAM>(rowIndex),
      reinterpret_cast<LPARAM>(&listItem)
    );
  }

  void SetListControlRowState(
    ScrListControlRuntime* const listControl,
    const std::int32_t rowIndex,
    const std::uint32_t stateFlags,
    const std::uint32_t stateMask
  ) noexcept
  {
    if (listControl == nullptr || listControl->mListViewHandle == nullptr || rowIndex < 0) {
      return;
    }

    LVITEMW listItem{};
    listItem.state = stateFlags;
    listItem.stateMask = stateMask;
    (void)::SendMessageW(
      listControl->mListViewHandle,
      LVM_SETITEMSTATE,
      static_cast<WPARAM>(rowIndex),
      reinterpret_cast<LPARAM>(&listItem)
    );
  }

  using SourceControlGetSelectionIndexFn = std::int32_t(__thiscall*)(void*);
  using SourceControlDeletePageFn = void(__thiscall*)(void*, std::int32_t);
  using SourceControlAddPageFn =
    void(__thiscall*)(void*, ScrSourcePageRuntime*, const wxStringRuntime*, std::int32_t, std::int32_t);
  using SourceControlSetSelectionFn = void(__thiscall*)(void*, std::int32_t);
  using SourcePathOwnerGetSelectedPathFn = wxStringRuntime*(__thiscall*)(void*, wxStringRuntime*);

  constexpr std::size_t kSourceControlGetSelectionIndexVtableOffset = 0x218;
  constexpr std::size_t kSourcePathOwnerGetSelectedPathVtableOffset = 0x228;
  constexpr std::size_t kSourceControlDeletePageVtableOffset = 0x244;
  constexpr std::size_t kSourceControlAddPageVtableOffset = 0x250;
  constexpr std::size_t kSourceControlSetSelectionVtableOffset = 0x258;

  [[nodiscard]] SourceControlGetSelectionIndexFn ResolveSourceControlGetSelectionIndex(void* const sourceControl)
  {
    if (sourceControl == nullptr) {
      return nullptr;
    }

    void** const vtable = *reinterpret_cast<void***>(sourceControl);
    if (vtable == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<SourceControlGetSelectionIndexFn>(
      vtable[kSourceControlGetSelectionIndexVtableOffset / sizeof(void*)]
    );
  }

  [[nodiscard]] SourceControlDeletePageFn ResolveSourceControlDeletePage(void* const sourceControl)
  {
    if (sourceControl == nullptr) {
      return nullptr;
    }

    void** const vtable = *reinterpret_cast<void***>(sourceControl);
    if (vtable == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<SourceControlDeletePageFn>(
      vtable[kSourceControlDeletePageVtableOffset / sizeof(void*)]
    );
  }

  [[nodiscard]] SourceControlAddPageFn ResolveSourceControlAddPage(void* const sourceControl)
  {
    if (sourceControl == nullptr) {
      return nullptr;
    }

    void** const vtable = *reinterpret_cast<void***>(sourceControl);
    if (vtable == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<SourceControlAddPageFn>(
      vtable[kSourceControlAddPageVtableOffset / sizeof(void*)]
    );
  }

  [[nodiscard]] SourceControlSetSelectionFn ResolveSourceControlSetSelection(void* const sourceControl)
  {
    if (sourceControl == nullptr) {
      return nullptr;
    }

    void** const vtable = *reinterpret_cast<void***>(sourceControl);
    if (vtable == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<SourceControlSetSelectionFn>(
      vtable[kSourceControlSetSelectionVtableOffset / sizeof(void*)]
    );
  }

  [[nodiscard]] SourcePathOwnerGetSelectedPathFn ResolveSourcePathOwnerGetSelectedPath(
    void* const sourcePathOwnerControl
  )
  {
    if (sourcePathOwnerControl == nullptr) {
      return nullptr;
    }

    void** const vtable = *reinterpret_cast<void***>(sourcePathOwnerControl);
    if (vtable == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<SourcePathOwnerGetSelectedPathFn>(
      vtable[kSourcePathOwnerGetSelectedPathVtableOffset / sizeof(void*)]
    );
  }

  [[nodiscard]] std::int32_t GetSourceControlSelectedPageIndex(ScrSourceControlRuntimeView* const sourceControl)
  {
    if (sourceControl == nullptr) {
      return -1;
    }

    auto const getSelectionIndex = ResolveSourceControlGetSelectionIndex(sourceControl);
    return getSelectionIndex != nullptr ? getSelectionIndex(sourceControl) : -1;
  }

  [[nodiscard]] std::int32_t GetSourceControlPageCount(const ScrSourceControlRuntimeView* const sourceControl)
  {
    if (sourceControl == nullptr || sourceControl->mPagesBegin == nullptr || sourceControl->mPagesEnd == nullptr) {
      return 0;
    }

    const std::ptrdiff_t pageCount = sourceControl->mPagesEnd - sourceControl->mPagesBegin;
    return pageCount > 0 ? static_cast<std::int32_t>(pageCount) : 0;
  }

  [[nodiscard]] std::int32_t GetSourcePageLineCount(const ScrSourcePageRuntime* const sourcePage)
  {
    if (sourcePage == nullptr || sourcePage->mLineRecordsBegin == nullptr || sourcePage->mLineRecordsEnd == nullptr) {
      return 0;
    }

    const std::ptrdiff_t lineCount = sourcePage->mLineRecordsEnd - sourcePage->mLineRecordsBegin;
    return lineCount > 0 ? static_cast<std::int32_t>(lineCount) : 0;
  }

  void DestroySourcePageLineRecords(ScrSourcePageRuntime* const sourcePage)
  {
    if (sourcePage == nullptr) {
      return;
    }

    if (sourcePage->mLineRecordsBegin == nullptr) {
      sourcePage->mLineRecordsBegin = nullptr;
      sourcePage->mLineRecordsEnd = nullptr;
      sourcePage->mLineRecordsCapacity = nullptr;
      sourcePage->mActiveCursorLineOneBased = 0;
      return;
    }

    const std::int32_t lineCount = GetSourcePageLineCount(sourcePage);
    for (std::int32_t lineIndexZeroBased = 0; lineIndexZeroBased < lineCount; ++lineIndexZeroBased) {
      sourcePage->mLineRecordsBegin[lineIndexZeroBased].mLineText.tidy(true, 0U);
    }

    delete[] sourcePage->mLineRecordsBegin;
    sourcePage->mLineRecordsBegin = nullptr;
    sourcePage->mLineRecordsEnd = nullptr;
    sourcePage->mLineRecordsCapacity = nullptr;
    sourcePage->mActiveCursorLineOneBased = 0;
  }

  [[nodiscard]] bool SelectSourcePageByIndex(
    ScrSourceControlRuntimeView* const sourceControl,
    const std::int32_t pageIndex
  )
  {
    if (sourceControl == nullptr || pageIndex < 0) {
      return false;
    }

    auto const setSelection = ResolveSourceControlSetSelection(sourceControl);
    if (setSelection == nullptr) {
      return false;
    }

    setSelection(sourceControl, pageIndex);
    return true;
  }

  [[nodiscard]] bool LoadSourcePageFromMountedPath(
    ScrSourcePageRuntime* sourcePage,
    const msvc8::string& mountedSourcePath
  );

  [[nodiscard]] std::int32_t FindSourcePageIndexByMountedPath(
    const ScrSourceControlRuntimeView* const sourceControl,
    const msvc8::string& mountedSourcePath
  )
  {
    if (sourceControl == nullptr || mountedSourcePath.empty()) {
      return -1;
    }

    const std::int32_t pageCount = GetSourceControlPageCount(sourceControl);
    for (std::int32_t pageIndex = 0; pageIndex < pageCount; ++pageIndex) {
      const ScrSourcePageRuntime* const sourcePage = sourceControl->mPagesBegin[pageIndex];
      if (sourcePage == nullptr) {
        continue;
      }

      if (sourcePage->mSourcePath.view() == mountedSourcePath.view()) {
        return pageIndex;
      }
    }

    return -1;
  }

  /**
   * Address: 0x004C39A0 (FUN_004C39A0)
   *
   * What it does:
   * Reloads all currently open source pages from their mounted source paths.
   */
  [[maybe_unused]] void ReloadOpenSourcePages(ScrSourceControlRuntimeView* const sourceControl)
  {
    if (sourceControl == nullptr || sourceControl->mPagesBegin == nullptr || sourceControl->mPagesEnd == nullptr) {
      return;
    }

    for (ScrSourcePageRuntime** page = sourceControl->mPagesBegin; page != sourceControl->mPagesEnd; ++page) {
      ScrSourcePageRuntime* const sourcePage = *page;
      if (sourcePage == nullptr) {
        continue;
      }

      msvc8::string mountedSourcePath{};
      mountedSourcePath.assign(sourcePage->mSourcePath, 0U, msvc8::string::npos);
      (void)LoadSourcePageFromMountedPath(sourcePage, mountedSourcePath);
    }
  }

  void ApplyBreakpointMarkersToSourcePage(ScrSourcePageRuntime* const sourcePage)
  {
    if (sourcePage == nullptr || sourcePage->mSourcePath.empty()) {
      return;
    }

    msvc8::vector<moho::ScrBreakpoint> breakpoints;
    moho::SCR_EnumerateBreakpoints(sourcePage->mSourcePath, breakpoints);
    const std::int32_t lineCount = GetSourcePageLineCount(sourcePage);
    for (const moho::ScrBreakpoint& breakpoint : breakpoints) {
      const std::int32_t lineIndexZeroBased = breakpoint.line - 1;
      if (lineIndexZeroBased < 0 || lineIndexZeroBased >= lineCount) {
        continue;
      }

      sourcePage->mLineRecordsBegin[lineIndexZeroBased].mMarkerState = breakpoint.enabled ? 3 : 4;
    }
  }

  [[nodiscard]] bool LoadSourcePageFromMountedPath(
    ScrSourcePageRuntime* const sourcePage,
    const msvc8::string& mountedSourcePath
  )
  {
    if (sourcePage == nullptr || mountedSourcePath.empty()) {
      return false;
    }

    DestroySourcePageLineRecords(sourcePage);

    msvc8::string resolvedPath;
    resolvedPath.assign(mountedSourcePath, 0U, msvc8::string::npos);
    if (moho::CVirtualFileSystem* const vfs = moho::DISK_GetVFS(); vfs != nullptr) {
      (void)vfs->FindFile(&resolvedPath, resolvedPath.c_str(), nullptr);
    }

    std::ifstream sourceStream(resolvedPath.c_str(), std::ios::in);
    if (!sourceStream.is_open()) {
      return false;
    }

    std::vector<std::string> lines;
    std::string sourceLine;
    while (std::getline(sourceStream, sourceLine)) {
      if (!sourceLine.empty() && sourceLine.back() == '\r') {
        sourceLine.pop_back();
      }
      lines.push_back(sourceLine);
    }

    const std::size_t lineCount = lines.size();
    if (lineCount > 0) {
      auto* const lineRecords = new (std::nothrow) ScrSourceLineRuntimeRecord[lineCount];
      if (lineRecords == nullptr) {
        return false;
      }

      for (std::size_t lineIndex = 0; lineIndex < lineCount; ++lineIndex) {
        lineRecords[lineIndex].mMarkerState = -1;
        lineRecords[lineIndex].mLineText.assign(lines[lineIndex].c_str(), lines[lineIndex].size());
      }

      sourcePage->mLineRecordsBegin = lineRecords;
      sourcePage->mLineRecordsEnd = lineRecords + lineCount;
      sourcePage->mLineRecordsCapacity = sourcePage->mLineRecordsEnd;
    }

    sourcePage->mSourcePath.assign(mountedSourcePath, 0U, msvc8::string::npos);
    sourcePage->mActiveCursorLineOneBased = 0;
    ApplyBreakpointMarkersToSourcePage(sourcePage);
    return true;
  }

  /**
   * Address: 0x004C3670 (FUN_004C3670)
   *
   * What it does:
   * Opens one mounted source path as a new source page or selects the already
   * open page owning that path.
   */
  [[nodiscard]] bool OpenOrSelectMountedSourcePath(
    ScrSourceControlRuntimeView* const sourceControl,
    const msvc8::string& mountedSourcePath
  )
  {
    if (sourceControl == nullptr || mountedSourcePath.empty()) {
      return false;
    }

    const std::int32_t existingPageIndex = FindSourcePageIndexByMountedPath(sourceControl, mountedSourcePath);
    if (existingPageIndex >= 0) {
      return SelectSourcePageByIndex(sourceControl, existingPageIndex);
    }

    auto* const sourcePage = new (std::nothrow) ScrSourcePageRuntime{};
    if (sourcePage == nullptr) {
      return false;
    }

    if (!LoadSourcePageFromMountedPath(sourcePage, mountedSourcePath)) {
      delete sourcePage;
      return false;
    }

    auto const addPage = ResolveSourceControlAddPage(sourceControl);
    if (addPage == nullptr) {
      DestroySourcePageLineRecords(sourcePage);
      delete sourcePage;
      return false;
    }

    const msvc8::string baseNameUtf8 = moho::FILE_Base(mountedSourcePath.c_str(), false);
    const std::wstring baseNameWide = gpg::STR_Utf8ToWide(baseNameUtf8.c_str());
    const wxStringRuntime pageTitle = wxStringRuntime::Borrow(baseNameWide.c_str());
    addPage(sourceControl, sourcePage, &pageTitle, 1, -1);
    return true;
  }

  /**
   * Address: 0x004C39E0 (FUN_004C39E0)
   *
   * What it does:
   * Copies the currently selected source-page mounted path into `outSourcePath`.
   */
  void GetSelectedSourcePagePath(
    ScrSourceControlRuntimeView* const sourceControl,
    msvc8::string& outSourcePath
  )
  {
    outSourcePath.clear();

    const std::int32_t selectedPageIndex = GetSourceControlSelectedPageIndex(sourceControl);
    if (selectedPageIndex < 0) {
      return;
    }

    const std::int32_t pageCount = GetSourceControlPageCount(sourceControl);
    if (selectedPageIndex >= pageCount || sourceControl == nullptr) {
      return;
    }

    ScrSourcePageRuntime* const selectedPage = sourceControl->mPagesBegin[selectedPageIndex];
    if (selectedPage == nullptr) {
      return;
    }

    outSourcePath.assign(selectedPage->mSourcePath, 0, 0xFFFFFFFF);
  }

  [[nodiscard]] bool RemoveSourcePageAtIndex(
    ScrSourceControlRuntimeView* const sourceControl,
    const std::int32_t pageIndex
  )
  {
    if (sourceControl == nullptr || pageIndex < 0) {
      return false;
    }

    const std::int32_t pageCount = GetSourceControlPageCount(sourceControl);
    if (pageIndex >= pageCount) {
      return false;
    }

    auto const deletePage = ResolveSourceControlDeletePage(sourceControl);
    if (deletePage != nullptr) {
      deletePage(sourceControl, pageIndex);
    }

    ScrSourcePageRuntime** const removeSlot = sourceControl->mPagesBegin + pageIndex;
    ScrSourcePageRuntime** const nextSlot = removeSlot + 1;
    const std::int32_t trailingPageCount = static_cast<std::int32_t>(sourceControl->mPagesEnd - nextSlot);
    if (trailingPageCount > 0) {
      const std::size_t moveBytes =
        static_cast<std::size_t>(trailingPageCount) * sizeof(ScrSourcePageRuntime*);
      (void)memmove_s(removeSlot, moveBytes, nextSlot, moveBytes);
    }

    sourceControl->mPagesEnd -= 1;
    return true;
  }

  /**
   * Address: 0x004C38A0 (FUN_004C38A0)
   *
   * What it does:
   * Removes one open source page by mounted source-path match.
   */
  [[maybe_unused]] bool RemoveSourcePageByMountedPath(
    ScrSourceControlRuntimeView* const sourceControl,
    const msvc8::string& mountedSourcePath
  )
  {
    const std::int32_t pageIndex = FindSourcePageIndexByMountedPath(sourceControl, mountedSourcePath);
    return RemoveSourcePageAtIndex(sourceControl, pageIndex);
  }

  /**
   * Address: 0x004C3940 (FUN_004C3940)
   *
   * What it does:
   * Removes the currently selected source page from the open-page list.
   */
  void RemoveSelectedSourcePage(ScrSourceControlRuntimeView* const sourceControl)
  {
    if (sourceControl == nullptr) {
      return;
    }

    const std::int32_t selectedPageIndex = GetSourceControlSelectedPageIndex(sourceControl);
    if (selectedPageIndex < 0) {
      return;
    }

    (void)RemoveSourcePageAtIndex(sourceControl, selectedPageIndex);
  }

  void FocusSourcePageLine(ScrSourcePageRuntime* const sourcePage, const std::int32_t lineOneBased)
  {
    if (sourcePage == nullptr || sourcePage->mListViewHandle == nullptr) {
      return;
    }

    const std::int32_t lineIndexZeroBased = lineOneBased - 1;
    if (lineIndexZeroBased < 0) {
      return;
    }

    const std::int32_t lineCount = (sourcePage->mLineRecordsBegin == nullptr)
                                     ? 0
                                     : static_cast<std::int32_t>(
                                         (reinterpret_cast<std::uintptr_t>(sourcePage->mLineRecordsEnd) -
                                          reinterpret_cast<std::uintptr_t>(sourcePage->mLineRecordsBegin)) /
                                         sizeof(ScrSourceLineRuntimeRecord)
                                       );
    if (lineIndexZeroBased >= lineCount) {
      return;
    }

    LVITEMW listItemState{};
    listItemState.stateMask = 0x6U;
    listItemState.state = 0x6U;

    (void)::SendMessageW(
      sourcePage->mListViewHandle,
      LVM_SETITEMSTATE,
      static_cast<WPARAM>(lineIndexZeroBased),
      reinterpret_cast<LPARAM>(&listItemState)
    );
    (void)::SendMessageW(
      sourcePage->mListViewHandle,
      LVM_ENSUREVISIBLE,
      static_cast<WPARAM>(lineIndexZeroBased),
      static_cast<LPARAM>(0)
    );
  }

  void FocusFirstSourceLineContainingText(
    ScrSourcePageRuntime* const sourcePage,
    const msvc8::string& searchText
  )
  {
    if (sourcePage == nullptr) {
      return;
    }

    const std::string_view searchTextView = searchText.view();
    const std::int32_t lineCount = (sourcePage->mLineRecordsBegin == nullptr)
                                     ? 0
                                     : static_cast<std::int32_t>(
                                         (reinterpret_cast<std::uintptr_t>(sourcePage->mLineRecordsEnd) -
                                          reinterpret_cast<std::uintptr_t>(sourcePage->mLineRecordsBegin)) /
                                         sizeof(ScrSourceLineRuntimeRecord)
                                       );
    for (std::int32_t lineIndexZeroBased = 0; lineIndexZeroBased < lineCount; ++lineIndexZeroBased) {
      const std::string_view lineTextView = sourcePage->mLineRecordsBegin[lineIndexZeroBased].mLineText.view();
      if (lineTextView.find(searchTextView) != std::string_view::npos) {
        FocusSourcePageLine(sourcePage, lineIndexZeroBased + 1);
        return;
      }
    }
  }

  void RemoveFirstRecentSourceFileMatch(
    msvc8::list<msvc8::string>& recentSourceFiles,
    const msvc8::string& sourcePath
  )
  {
    const std::string_view sourcePathView = sourcePath.view();
    for (auto it = recentSourceFiles.begin(); it != recentSourceFiles.end(); ++it) {
      if (it->view() == sourcePathView) {
        recentSourceFiles.erase(it);
        return;
      }
    }
  }

  void PersistRecentSourceFiles(const msvc8::list<msvc8::string>& recentSourceFiles)
  {
    moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
    if (preferences == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> recentFilesVec;
    for (const auto& s : recentSourceFiles) {
      recentFilesVec.push_back(s);
    }
    preferences->SetStringArr(msvc8::string(kDebugRecentFilesPreferenceKey), recentFilesVec);
    moho::USER_SavePreferences();
  }

  void RefreshSourcePageLineMarker(ScrSourcePageRuntime* const page, const std::int32_t lineIndexZeroBased) noexcept
  {
    RECT listRect{};
    listRect.left = 0;
    (void)::SendMessageW(
      page->mListViewHandle,
      LVM_GETITEMRECT,
      static_cast<WPARAM>(lineIndexZeroBased),
      reinterpret_cast<LPARAM>(&listRect)
    );

    wxRectRuntime refreshRect{};
    refreshRect.x = static_cast<std::int32_t>(listRect.left);
    refreshRect.y = static_cast<std::int32_t>(listRect.top);
    refreshRect.width = static_cast<std::int32_t>(listRect.right - listRect.left);
    refreshRect.height = static_cast<std::int32_t>(listRect.bottom - listRect.top);
    page->Refresh(true, &refreshRect);
  }

  void ClearSourcePageActiveExecutionMarker(ScrSourcePageRuntime* const page) noexcept
  {
    const std::int32_t activeLineOneBased = page->mActiveCursorLineOneBased;
    if (activeLineOneBased < 1) {
      return;
    }

    const std::int32_t lineIndexZeroBased = activeLineOneBased - 1;
    ScrSourceLineRuntimeRecord& lineRecord = page->mLineRecordsBegin[lineIndexZeroBased];
    page->mActiveCursorLineOneBased = 0;

    switch (lineRecord.mMarkerState) {
      case 0:
        lineRecord.mMarkerState = -1;
        break;
      case 1:
        lineRecord.mMarkerState = 3;
        break;
      case 2:
        lineRecord.mMarkerState = 4;
        break;
      default:
        break;
    }

    RefreshSourcePageLineMarker(page, lineIndexZeroBased);
  }

  void SetSourcePageBreakpointMarkersEnabled(ScrSourcePageRuntime* const page, const bool enabled) noexcept
  {
    const std::int32_t lineCount = (page->mLineRecordsBegin == nullptr)
                                     ? 0
                                     : static_cast<std::int32_t>(
                                         (reinterpret_cast<std::uintptr_t>(page->mLineRecordsEnd) -
                                          reinterpret_cast<std::uintptr_t>(page->mLineRecordsBegin)) /
                                         sizeof(ScrSourceLineRuntimeRecord)
                                       );

    for (std::int32_t lineIndexZeroBased = 0; lineIndexZeroBased < lineCount; ++lineIndexZeroBased) {
      ScrSourceLineRuntimeRecord& lineRecord = page->mLineRecordsBegin[lineIndexZeroBased];

      switch (lineRecord.mMarkerState) {
        case 1:
        case 2:
          lineRecord.mMarkerState = enabled ? 1 : 2;
          break;
        case 3:
        case 4:
          lineRecord.mMarkerState = enabled ? 3 : 4;
          break;
        default:
          break;
      }

      RefreshSourcePageLineMarker(page, lineIndexZeroBased);
    }
  }

  /**
   * Address: 0x004C3B90 (FUN_004C3B90)
   *
   * What it does:
   * Iterates every open source page and clears breakpoint markers line-by-line
   * by forwarding one-based line indices into `ScrFileCtrl::ClearBreakpointMarkerAtLine`.
   */
  void ClearAllSourcePageBreakpointMarkers(ScrSourceControlRuntimeView* const sourceControl) noexcept
  {
    if (sourceControl == nullptr || sourceControl->mPagesBegin == nullptr || sourceControl->mPagesEnd == nullptr) {
      return;
    }

    for (ScrSourcePageRuntime** page = sourceControl->mPagesBegin; page != sourceControl->mPagesEnd; ++page) {
      ScrSourcePageRuntime* const sourcePage = *page;
      if (sourcePage == nullptr || sourcePage->mLineRecordsBegin == nullptr) {
        continue;
      }

      const std::int32_t lineCount = static_cast<std::int32_t>(sourcePage->mLineRecordsEnd - sourcePage->mLineRecordsBegin);
      if (lineCount <= 0) {
        continue;
      }

      auto* const fileControl = reinterpret_cast<moho::ScrFileCtrl*>(sourcePage);
      for (std::int32_t lineOneBased = 1; lineOneBased <= lineCount; ++lineOneBased) {
        fileControl->ClearBreakpointMarkerAtLine(lineOneBased);
      }
    }
  }

  void ClearAllSourcePageActiveExecutionMarkers(ScrSourceControlRuntimeView* const sourceControl) noexcept
  {
    for (ScrSourcePageRuntime** page = sourceControl->mPagesBegin; page != sourceControl->mPagesEnd; ++page) {
      ClearSourcePageActiveExecutionMarker(*page);
    }
  }

  [[nodiscard]] bool SetSourcePageActiveExecutionMarker(
    ScrSourcePageRuntime* const sourcePage,
    const std::int32_t lineOneBased
  )
  {
    if (sourcePage == nullptr) {
      return false;
    }

    const std::int32_t lineIndexZeroBased = lineOneBased - 1;
    const std::int32_t lineCount = (sourcePage->mLineRecordsBegin == nullptr)
                                     ? 0
                                     : static_cast<std::int32_t>(sourcePage->mLineRecordsEnd - sourcePage->mLineRecordsBegin);
    if (lineIndexZeroBased < 0 || lineIndexZeroBased >= lineCount) {
      gpg::Warnf("invalid cursor location: %s(%i)", sourcePage->mSourcePath.c_str(), lineOneBased);
      return false;
    }

    sourcePage->mActiveCursorLineOneBased = lineOneBased;
    ScrSourceLineRuntimeRecord& lineRecord = sourcePage->mLineRecordsBegin[lineIndexZeroBased];
    switch (lineRecord.mMarkerState) {
      case -1:
        lineRecord.mMarkerState = 0;
        break;
      case 3:
        lineRecord.mMarkerState = 1;
        break;
      case 4:
        lineRecord.mMarkerState = 2;
        break;
      default:
        break;
    }

    FocusSourcePageLine(sourcePage, lineOneBased);
    RefreshSourcePageLineMarker(sourcePage, lineIndexZeroBased);
    return true;
  }

  /**
   * Address: 0x004C3C00 (FUN_004C3C00)
   *
   * What it does:
   * Clears active execution markers, selects the source page matching one
   * mounted path, and applies the active execution marker at `lineOneBased`.
   */
  [[nodiscard]] bool FocusMountedSourcePathLine(
    ScrSourceControlRuntimeView* const sourceControl,
    const msvc8::string& mountedSourcePath,
    const std::int32_t lineOneBased
  )
  {
    if (sourceControl == nullptr) {
      return false;
    }

    ClearAllSourcePageActiveExecutionMarkers(sourceControl);

    const msvc8::string mountedSourcePathLower = gpg::STR_ToLower(mountedSourcePath.c_str());
    const std::int32_t pageIndex = FindSourcePageIndexByMountedPath(sourceControl, mountedSourcePathLower);
    const std::int32_t pageCount = GetSourceControlPageCount(sourceControl);
    if (pageIndex < 0 || pageIndex >= pageCount) {
      return false;
    }

    (void)SelectSourcePageByIndex(sourceControl, pageIndex);
    return SetSourcePageActiveExecutionMarker(sourceControl->mPagesBegin[pageIndex], lineOneBased);
  }

  /**
   * Address: 0x004C3B00 (FUN_004C3B00)
   *
   * What it does:
   * Enables or disables breakpoint marker lanes across all open source pages.
   */
  void SetAllSourcePageBreakpointMarkersEnabled(
    ScrSourceControlRuntimeView* const sourceControl,
    const bool enabled
  ) noexcept
  {
    for (ScrSourcePageRuntime** page = sourceControl->mPagesBegin; page != sourceControl->mPagesEnd; ++page) {
      SetSourcePageBreakpointMarkersEnabled(*page, enabled);
    }
  }
} // namespace

void* moho::ScrDebugWindow::sm_eventTable[1] = {nullptr};

/**
 * Address: 0x004BEB70 (FUN_004BEB70)
 *
 * What it does:
 * Runs non-deleting teardown for one script-debug window instance, including
 * selected-path/list storage release before frame-base teardown.
 */
moho::ScrDebugWindow* moho::ScrDebugWindow::DestroyWithoutDelete(ScrDebugWindow* const object) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  object->mRecentSourceFiles.~list<msvc8::string>();
  object->mSelectedSourcePath.tidy(true, 0U);
  return reinterpret_cast<ScrDebugWindow*>(
    WX_FrameDestroyWithoutDelete(static_cast<wxTopLevelWindowRuntime*>(object))
  );
}

/**
 * Address: 0x004BEB40 (FUN_004BEB40)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for one script-debug window.
 */
moho::ScrDebugWindow* moho::ScrDebugWindow::DeleteWithFlag(
  ScrDebugWindow* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  DestroyWithoutDelete(object);
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004BEBE0 (FUN_004BEBE0)
 *
 * msvc8::string const &
 *
 * What it does:
 * Opens or selects one mounted source path in the source-page control and
 * appends it to recent debug source files when not already listed.
 */
bool moho::ScrDebugWindow::OpenMountedSourcePathAndTrackRecent(const msvc8::string& mountedSourcePath)
{
  auto* const sourceControl = reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl);
  if (!OpenOrSelectMountedSourcePath(sourceControl, mountedSourcePath)) {
    return false;
  }

  const std::string_view mountedSourcePathView = mountedSourcePath.view();
  for (const msvc8::string& recentSourcePath : mRecentSourceFiles) {
    if (recentSourcePath.view() == mountedSourcePathView) {
      return true;
    }
  }

  mRecentSourceFiles.push_back(mountedSourcePath);
  PersistRecentSourceFiles(mRecentSourceFiles);
  return true;
}

/**
 * Address: 0x004BC100 (FUN_004BC100)
 *
 * What it does:
 * Returns this debug-window event-table lane.
 */
const void* moho::ScrDebugWindow::GetEventTable() const
{
  return sm_eventTable;
}

/**
 * Address: 0x004BECF0 (FUN_004BECF0)
 *
 * void *
 *
 * What it does:
 * Opens/focuses paused source location, rebuilds call-stack + watch lanes,
 * and disables viewport render while script execution is paused.
 */
void moho::ScrDebugWindow::OnScriptPauseEvent(void* const pauseEvent)
{
  const auto* const pauseEventView = reinterpret_cast<const ScrPauseEvent*>(pauseEvent);
  auto* const sourceControl = reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl);

  if (pauseEventView == nullptr ||
      !OpenMountedSourcePathAndTrackRecent(pauseEventView->GetSourceName()) ||
      !FocusMountedSourcePathLine(sourceControl, pauseEventView->GetSourceName(), pauseEventView->GetSourceLine())) {
    SCR_DebugResume();
    return;
  }

  auto* const callStackControl = reinterpret_cast<ScrListControlRuntime*>(mCallStackControl);
  ClearListControlRows(callStackControl);

  msvc8::vector<ScrActivation> callStack;
  SCR_EnumerateCallStack(callStack);

  for (std::size_t activationIndex = 0; activationIndex < callStack.size(); ++activationIndex) {
    const ScrActivation& activation = callStack[activationIndex];
    const std::int32_t rowIndex = static_cast<std::int32_t>(activationIndex);

    if (!InsertListControlRowText(callStackControl, rowIndex, activation.file)) {
      continue;
    }
    SetListControlSubItemText(callStackControl, rowIndex, 1, activation.name);

    std::ostringstream lineNumberStream{};
    lineNumberStream << activation.line;
    msvc8::string lineNumberText{};
    lineNumberText.assign_owned(lineNumberStream.str());
    SetListControlSubItemText(callStackControl, rowIndex, 2, lineNumberText);
  }

  if (!callStack.empty()) {
    SetListControlRowState(callStackControl, 0, 4u, 4u);
  }

  msvc8::vector<ScrWatch> localWatches;
  SCR_EnumerateLocals(0, localWatches);
  if (mLocalWatchControl != nullptr) {
    mLocalWatchControl->Update(localWatches);
  }

  msvc8::vector<ScrWatch> globalWatches;
  SCR_EnumerateGlobals(globalWatches);
  if (mGlobalWatchControl != nullptr) {
    mGlobalWatchControl->Update(globalWatches);
  }

  if (ren_Viewport != nullptr) {
    ren_Viewport->mEnabled = 0;
  }
}

/**
 * Address: 0x004BF750 (FUN_004BF750)
 *
 * void *
 *
 * What it does:
 * Focuses the call-stack-selected activation source location and rebuilds
 * local watch lanes for that activation level.
 */
void moho::ScrDebugWindow::OnCallStackSelectionChanged(void* const listEvent)
{
  const auto* const listEventView = reinterpret_cast<const wxListSelectionEventRuntimeView*>(listEvent);
  const std::int32_t selectedActivationIndex = (listEventView != nullptr) ? listEventView->mSelectedItemIndex : -1;

  msvc8::vector<ScrActivation> callStack;
  SCR_EnumerateCallStack(callStack);

  if (selectedActivationIndex < 0 || static_cast<std::size_t>(selectedActivationIndex) >= callStack.size()) {
    return;
  }

  const ScrActivation& selectedActivation = callStack[static_cast<std::size_t>(selectedActivationIndex)];
  (void)OpenMountedSourcePathAndTrackRecent(selectedActivation.file);

  auto* const sourceControl = reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl);
  (void)FocusMountedSourcePathLine(sourceControl, selectedActivation.file, selectedActivation.line);

  msvc8::vector<ScrWatch> localWatches;
  SCR_EnumerateLocals(selectedActivationIndex, localWatches);
  if (mLocalWatchControl != nullptr) {
    mLocalWatchControl->Update(localWatches);
  }
}

/**
 * Address: 0x004BF630 (FUN_004BF630)
 *
 * void *
 *
 * IDA signature:
 * Moho::WRenViewport *__thiscall sub_4BF630(int this, int a2)
 *
 * What it does:
 * Clears active source-line execution markers across all open source pages,
 * clears watch rows, then performs one script-debug step.
 */
void moho::ScrDebugWindow::OnStepCommand(void* const commandEvent)
{
  (void)commandEvent;

  ClearAllSourcePageActiveExecutionMarkers(
    reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl)
  );
  static_cast<wxWindowBase*>(mLocalWatchControl)->Clear();
  SCR_DebugStep();

  if (ren_Viewport != nullptr) {
    ren_Viewport->mEnabled = 1;
  }
}

/**
 * Address: 0x004BF690 (FUN_004BF690)
 *
 * void *
 *
 * IDA signature:
 * Moho::WRenViewport *__thiscall sub_4BF690(int this, int a2)
 *
 * What it does:
 * Clears active source-line execution markers across all open source pages,
 * clears watch rows, then resumes script-debug execution.
 */
void moho::ScrDebugWindow::OnResumeCommand(void* const commandEvent)
{
  (void)commandEvent;

  ClearAllSourcePageActiveExecutionMarkers(
    reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl)
  );
  static_cast<wxWindowBase*>(mLocalWatchControl)->Clear();
  SCR_DebugResume();

  if (ren_Viewport != nullptr) {
    ren_Viewport->mEnabled = 1;
  }
}

/**
 * Address: 0x004BF6F0 (FUN_004BF6F0)
 *
 * void *
 *
 * IDA signature:
 * void __stdcall sub_4BF6F0(int a1)
 *
 * What it does:
 * Marks all source-line breakpoint indicators as enabled and enables all
 * persisted global script breakpoints.
 */
void moho::ScrDebugWindow::OnEnableAllBreakpointsCommand(void* const commandEvent)
{
  (void)commandEvent;

  SetAllSourcePageBreakpointMarkersEnabled(
    reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl),
    true
  );
  SCR_EnableAllBreakpoints(true);
}

/**
 * Address: 0x004BF710 (FUN_004BF710)
 *
 * void *
 *
 * IDA signature:
 * void __stdcall sub_4BF710(int a1)
 *
 * What it does:
 * Marks all source-line breakpoint indicators as disabled and disables all
 * persisted global script breakpoints.
 */
void moho::ScrDebugWindow::OnDisableAllBreakpointsCommand(void* const commandEvent)
{
  (void)commandEvent;

  SetAllSourcePageBreakpointMarkersEnabled(
    reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl),
    false
  );
  SCR_EnableAllBreakpoints(false);
}

/**
 * Address: 0x004BF960 (FUN_004BF960)
 *
 * void *
 *
 * IDA signature:
 * void __thiscall sub_4BF960(_BYTE *this, int a2)
 *
 * What it does:
 * Persists the vertical splitter sash position while startup control wiring is
 * complete.
 */
void moho::ScrDebugWindow::OnVerticalSashPositionChanged(void* const splitterEvent)
{
  if (mIsInitializingControls != 0U || splitterEvent == nullptr) {
    return;
  }

  const auto* const eventView = reinterpret_cast<const wxSplitterSashEventRuntimeView*>(splitterEvent);
  PersistIntegerPreference(kDebugVerticalSashPreferenceKey, eventView->mSashPosition);
}

/**
 * Address: 0x004BFA00 (FUN_004BFA00)
 *
 * void *
 *
 * IDA signature:
 * void __thiscall sub_4BFA00(_BYTE *this, int a2)
 *
 * What it does:
 * Persists the horizontal splitter sash position while startup control wiring
 * is complete.
 */
void moho::ScrDebugWindow::OnHorizontalSashPositionChanged(void* const splitterEvent)
{
  if (mIsInitializingControls != 0U || splitterEvent == nullptr) {
    return;
  }

  const auto* const eventView = reinterpret_cast<const wxSplitterSashEventRuntimeView*>(splitterEvent);
  PersistIntegerPreference(kDebugHorizontalSashPreferenceKey, eventView->mSashPosition);
}

/**
 * Address: 0x004BFAA0 (FUN_004BFAA0)
 *
 * void *
 *
 * IDA signature:
 * void __userpurge sub_4BFAA0(int a1@<ecx>, int a2@<ebp>, int a3@<esi>, int a4)
 *
 * What it does:
 * Persists call-stack column widths (source/block/line) to user preferences
 * while startup control wiring is complete.
 */
void moho::ScrDebugWindow::OnCallStackColumnsResized(void* const commandEvent)
{
  (void)commandEvent;

  if (mIsInitializingControls != 0U) {
    return;
  }

  const auto* const callStackControl = reinterpret_cast<const ScrListControlRuntime*>(mCallStackControl);
  PersistIntegerPreference(kDebugCallStackSourceColumnPreferenceKey, GetListControlColumnWidth(callStackControl, 0U));
  PersistIntegerPreference(kDebugCallStackBlockColumnPreferenceKey, GetListControlColumnWidth(callStackControl, 1U));
  PersistIntegerPreference(kDebugCallStackLineColumnPreferenceKey, GetListControlColumnWidth(callStackControl, 2U));
}

/**
 * Address: 0x004BFC00 (FUN_004BFC00)
 *
 * void *
 *
 * IDA signature:
 * void __userpurge sub_4BFC00(int a1@<ecx>, int a2@<ebp>, int a3@<esi>, int a4)
 *
 * What it does:
 * Persists local-watch column widths (name/type/value) to user preferences
 * while startup control wiring is complete.
 */
void moho::ScrDebugWindow::OnLocalWatchColumnsResized(void* const commandEvent)
{
  (void)commandEvent;

  if (mIsInitializingControls != 0U) {
    return;
  }

  const auto* const localWatchControl = reinterpret_cast<const ScrWatchControlRuntime*>(mLocalWatchControl);
  PersistIntegerPreference(kDebugLocalWatchNameColumnPreferenceKey, GetWatchControlColumnWidth(localWatchControl, 0U));
  PersistIntegerPreference(kDebugLocalWatchTypeColumnPreferenceKey, GetWatchControlColumnWidth(localWatchControl, 1U));
  PersistIntegerPreference(kDebugLocalWatchValueColumnPreferenceKey, GetWatchControlColumnWidth(localWatchControl, 2U));
}

/**
 * Address: 0x004BFD60 (FUN_004BFD60)
 *
 * void *
 *
 * IDA signature:
 * void __userpurge sub_4BFD60(int a1@<ecx>, int a2@<ebp>, int a3@<esi>, int a4)
 *
 * What it does:
 * Persists global-watch column widths (name/type/value) to user preferences
 * while startup control wiring is complete.
 */
void moho::ScrDebugWindow::OnGlobalWatchColumnsResized(void* const commandEvent)
{
  (void)commandEvent;

  if (mIsInitializingControls != 0U) {
    return;
  }

  const auto* const globalWatchControl = reinterpret_cast<const ScrWatchControlRuntime*>(mGlobalWatchControl);
  PersistIntegerPreference(kDebugGlobalWatchNameColumnPreferenceKey, GetWatchControlColumnWidth(globalWatchControl, 0U));
  PersistIntegerPreference(kDebugGlobalWatchTypeColumnPreferenceKey, GetWatchControlColumnWidth(globalWatchControl, 1U));
  PersistIntegerPreference(kDebugGlobalWatchValueColumnPreferenceKey, GetWatchControlColumnWidth(globalWatchControl, 2U));
}

/**
 * Address: 0x004BF120 (FUN_004BF120)
 *
 * void *
 *
 * IDA signature:
 * void __thiscall sub_4BF120(_DWORD *this, int a2)
 *
 * What it does:
 * Removes the currently selected source page, removes one matching recent
 * source-file entry, and persists the updated recent-file list.
 */
void moho::ScrDebugWindow::OnRemoveCurrentSourceCommand(void* const commandEvent)
{
  (void)commandEvent;

  auto* const sourceControl = reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl);

  msvc8::string selectedSourcePath;
  GetSelectedSourcePagePath(sourceControl, selectedSourcePath);
  RemoveSelectedSourcePage(sourceControl);
  RemoveFirstRecentSourceFileMatch(mRecentSourceFiles, selectedSourcePath);
  PersistRecentSourceFiles(mRecentSourceFiles);
}

/**
 * Address: 0x004BF220 (FUN_004BF220)
 *
 * void *
 *
 * IDA signature:
 * void __thiscall sub_4BF220(_DWORD *this, int a2)
 *
 * What it does:
 * Repeatedly removes selected source pages until no source remains selected,
 * erasing matching recent-file entries and persisting each update.
 */
void moho::ScrDebugWindow::OnRemoveAllSourcePagesCommand(void* const commandEvent)
{
  (void)commandEvent;

  auto* const sourceControl = reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl);

  msvc8::string selectedSourcePath;
  GetSelectedSourcePagePath(sourceControl, selectedSourcePath);

  while (!selectedSourcePath.empty()) {
    RemoveSelectedSourcePage(sourceControl);
    RemoveFirstRecentSourceFileMatch(mRecentSourceFiles, selectedSourcePath);
    PersistRecentSourceFiles(mRecentSourceFiles);
    GetSelectedSourcePagePath(sourceControl, selectedSourcePath);
  }
}

/**
 * Address: 0x004BF400 (FUN_004BF400)
 *
 * void *
 *
 * IDA signature:
 * int __thiscall sub_4BF400(_DWORD *this, int a2)
 *
 * What it does:
 * Shows the goto-line dialog and focuses the requested source line on the
 * currently selected source page.
 */
void moho::ScrDebugWindow::OnGotoLineCommand(void* const commandEvent)
{
  (void)commandEvent;

  ScrGotoDialog gotoDialog;
  if (gotoDialog.ShowModal() != kWxDialogModalOk) {
    return;
  }

  const std::int32_t requestedLine = gotoDialog.ParseRequestedLineNumber();
  auto* const sourceControl = reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl);
  const std::int32_t selectedPageIndex = GetSourceControlSelectedPageIndex(sourceControl);
  const std::int32_t pageCount = GetSourceControlPageCount(sourceControl);
  if (selectedPageIndex < 0 || selectedPageIndex >= pageCount || sourceControl == nullptr) {
    return;
  }

  FocusSourcePageLine(sourceControl->mPagesBegin[selectedPageIndex], requestedLine);
}

/**
 * Address: 0x004BF4C0 (FUN_004BF4C0)
 *
 * void *
 *
 * IDA signature:
 * void __thiscall sub_4BF4C0(int this, int a2)
 *
 * What it does:
 * Copies selected-source text into window state and focuses the first matching
 * source line in the currently selected source page.
 */
void moho::ScrDebugWindow::OnSelectedSourcePathChanged(void* const commandEvent)
{
  (void)commandEvent;

  auto* const selectedSourceControl = reinterpret_cast<wxTextCtrlRuntime*>(mSelectedSourceControl);
  if (selectedSourceControl == nullptr) {
    mSelectedSourcePath.clear();
    return;
  }

  const msvc8::string selectedSourceText = selectedSourceControl->GetValueUtf8();
  mSelectedSourcePath.assign(selectedSourceText, 0U, msvc8::string::npos);
  if (mSelectedSourcePath.empty()) {
    return;
  }

  auto* const sourceControl = reinterpret_cast<ScrSourceControlRuntimeView*>(mSourceControl);
  const std::int32_t selectedPageIndex = GetSourceControlSelectedPageIndex(sourceControl);
  const std::int32_t pageCount = GetSourceControlPageCount(sourceControl);
  if (sourceControl == nullptr || selectedPageIndex < 0 || selectedPageIndex >= pageCount) {
    return;
  }

  FocusFirstSourceLineContainingText(
    sourceControl->mPagesBegin[selectedPageIndex],
    mSelectedSourcePath
  );
}

/**
 * Address: 0x004BF840 (FUN_004BF840)
 *
 * void *
 *
 * IDA signature:
 * void __thiscall sub_4BF840(int this, int a2)
 *
 * What it does:
 * Reads the currently activated source path from the source-tree owner
 * control, converts it to mounted-path form, and opens/tracks that source.
 */
void moho::ScrDebugWindow::OnSourceTreeItemActivated(void* const commandEvent)
{
  (void)commandEvent;

  if (mSourcePathOwnerControl == nullptr) {
    return;
  }

  auto const getSelectedPath = ResolveSourcePathOwnerGetSelectedPath(mSourcePathOwnerControl);
  if (getSelectedPath == nullptr) {
    return;
  }

  wxStringRuntime selectedPathStorage{};
  wxStringRuntime* const selectedPath = getSelectedPath(mSourcePathOwnerControl, &selectedPathStorage);
  if (selectedPath == nullptr) {
    return;
  }

  const msvc8::string selectedPathUtf8 = selectedPath->ToUtf8();
  msvc8::string mountedPath;
  (void)moho::FILE_ToMountedPath(&mountedPath, selectedPathUtf8.c_str());
  (void)OpenMountedSourcePathAndTrackRecent(mountedPath);
}

/**
 * Address: 0x004BFEC0 (FUN_004BFEC0)
 *
 * void *
 *
 * IDA signature:
 * void __userpurge sub_4BFEC0(_BYTE *a1@<ecx>, int a2@<esi>, int a3)
 *
 * What it does:
 * Persists debug-window X/Y position lanes while startup control wiring is
 * complete.
 */
void moho::ScrDebugWindow::OnWindowMoved(void* const commandEvent)
{
  (void)commandEvent;

  if (mIsInitializingControls != 0U) {
    return;
  }

  std::int32_t windowX = 0;
  std::int32_t windowY = 0;
  DoGetPosition(&windowX, &windowY);
  PersistIntegerPreference(kDebugWindowXPreferenceKey, windowX);
  PersistIntegerPreference(kDebugWindowYPreferenceKey, windowY);
}

/**
 * Address: 0x004BEB60 (FUN_004BEB60)
 *
 * What it does:
 * Clears one accelerator-entry runtime lane before constructor wiring.
 */
void moho::ResetAccelTableEntry(wxAccelTableEntryRuntime& entry) noexcept
{
  entry.flags = 0;
  entry.keyCode = 0;
  entry.commandId = 0;
  entry.commandTarget = nullptr;
}
