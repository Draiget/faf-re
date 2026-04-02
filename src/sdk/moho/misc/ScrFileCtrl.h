#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/misc/ScrFileLine.h"

namespace moho
{
  class ScrFileCtrl : public wxControlRuntime
  {
  public:
    /**
     * Address: 0x004C1EE0 (FUN_004C1EE0)
     *
     * wxWindow *
     *
     * What it does:
     * Constructs one virtual source-file list control, binds marker imagery,
     * and initializes virtual columns used by script source rows.
     */
    explicit ScrFileCtrl(wxWindowBase* parentWindow);

    /**
     * Address: 0x004C1ED0 (FUN_004C1ED0)
     *
     * What it does:
     * Returns this control's wx event-table lane.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x004C2680 (FUN_004C2680)
     *
     * What it does:
     * Implements deleting-dtor thunk semantics for one script-file control.
     */
    static ScrFileCtrl* DeleteWithFlag(ScrFileCtrl* object, std::uint8_t deleteFlags) noexcept;

    /**
     * Address: 0x004C26A0 (FUN_004C26A0)
     *
     * What it does:
     * Releases source-file state lanes and returns to base list-control state.
     */
    ~ScrFileCtrl();

    /**
     * Address: 0x004C2A40 (FUN_004C2A40)
     *
     * msvc8::string const &
     *
     * What it does:
     * Finds and selects the first source line containing one search token.
     */
    [[nodiscard]] bool FindAndSelectFirstSourceMatch(const msvc8::string& needle);

    /**
     * Address: 0x004C2AE0 (FUN_004C2AE0)
     *
     * msvc8::string const &
     *
     * What it does:
     * Finds and selects the next source line containing one search token.
     */
    [[nodiscard]] bool FindAndSelectNextSourceMatch(const msvc8::string& needle);

    /**
     * Address: 0x004C2B90 (FUN_004C2B90)
     *
     * msvc8::string const &
     *
     * What it does:
     * Finds and selects the previous source line containing one search token.
     */
    [[nodiscard]] bool FindAndSelectPreviousSourceMatch(const msvc8::string& needle);

    /**
     * Address: 0x004C2C20 (FUN_004C2C20)
     *
     * int
     *
     * What it does:
     * Selects and focuses the line immediately before the provided one-based
     * source line.
     */
    void SelectPreviousSourceLine(int lineOneBased);

    /**
     * Address: 0x004C2C60 (FUN_004C2C60)
     *
     * bool
     *
     * What it does:
     * Enables or disables all breakpoint marker lanes already present in this
     * control.
     */
    void SetBreakpointMarkersEnabled(bool enabled);

    /**
     * Address: 0x004C2CF0 (FUN_004C2CF0)
     *
     * int
     *
     * What it does:
     * Clears one breakpoint marker lane at the provided one-based source line.
     */
    void ClearBreakpointMarkerAtLine(int lineOneBased);

    /**
     * Address: 0x004C2DE0 (FUN_004C2DE0)
     *
     * int
     *
     * What it does:
     * Sets one active cursor location and updates marker state for that line.
     */
    [[nodiscard]] bool SetCursorLocation(int lineOneBased);

    /**
     * Address: 0x004C2EA0 (FUN_004C2EA0)
     *
     * What it does:
     * Clears the current active cursor location marker.
     */
    void ClearCursorLocation();

    /**
     * Address: 0x004C2F10 (FUN_004C2F10)
     *
     * int
     *
     * What it does:
     * Returns one stored marker-state lane for the requested source row index.
     */
    [[nodiscard]] int GetLineMarkerState(int lineIndexZeroBased) const;

    /**
     * Address: 0x004C2F30 (FUN_004C2F30)
     *
     * int,int
     *
     * What it does:
     * Returns one virtual-list text lane for source-line and column indices.
     */
    [[nodiscard]] wxStringRuntime GetVirtualItemText(
      int lineIndexZeroBased,
      int columnIndex
    ) const;

    /**
     * Address: 0x004C3270 (FUN_004C3270)
     *
     * void *
     *
     * What it does:
     * Toggles one line breakpoint marker from an item-activation event.
     */
    void OnLineActivated(const void* listEvent);

    /**
     * Address: 0x004C3400 (FUN_004C3400)
     *
     * What it does:
     * Reapplies persisted breakpoints for this source file into line markers.
     */
    void RefreshBreakpointMarkers();

    /**
     * Address: 0x004C2730 (FUN_004C2730)
     *
     * msvc8::string const &
     *
     * What it does:
     * Clears existing rows, loads one mounted source file line-by-line,
     * reapplies persisted breakpoint states, and refreshes virtual row count.
     */
    [[nodiscard]] bool LoadSourceFile(const msvc8::string& mountedSourcePath);

    /**
     * Address: 0x004C2DA0 (FUN_004C2DA0)
     *
     * What it does:
     * Clears all loaded line records, resets virtual item count, and clears
     * active cursor location.
     */
    void ClearLoadedSource();

    /**
     * Address: 0x004C30B0 (FUN_004C30B0)
     *
     * int
     *
     * What it does:
     * Returns one heap-allocated alternating-row text style object for virtual
     * source rows.
     */
    [[nodiscard]] void* GetVirtualItemTextStyle(int lineIndexZeroBased) const;

    /**
     * Address: 0x004C33D0 (FUN_004C33D0)
     *
     * void *
     *
     * What it does:
     * Resizes the source-text column to keep it width-coupled to the current
     * control client width.
     */
    void OnResizeAdjustSourceColumn(const void* sizeEvent);

  private:
    [[nodiscard]] int GetLineCount() const noexcept;
    [[nodiscard]] int GetSelectedRowIndex() const noexcept;
    [[nodiscard]] bool ContainsSourceMatch(int lineIndexZeroBased, const msvc8::string& needle) const;
    void SetRowState(int lineIndexZeroBased, std::uint32_t stateFlags, std::uint32_t stateMask) noexcept;
    void EnsureRowVisible(int lineIndexZeroBased) noexcept;
    void RedrawRow(int lineIndexZeroBased) noexcept;
    void SetVirtualLineCount(int lineCount) noexcept;

  public:
    static void* sm_eventTable[1];

    std::uint8_t mUnknown004To107[0x104]{};
    void* mListViewHandle = nullptr; // +0x108
    std::uint8_t mUnknown10CTo14F[0x44]{};
    int mActiveCursorLineOneBased = 0; // +0x150
    void* mMarkerImageList = nullptr; // +0x154
    msvc8::string mSourcePath{}; // +0x158
    msvc8::vector<ScrFileLine> mLines{}; // +0x174
  };

  static_assert(offsetof(ScrFileCtrl, mListViewHandle) == 0x108, "ScrFileCtrl::mListViewHandle offset must be 0x108");
  static_assert(
    offsetof(ScrFileCtrl, mActiveCursorLineOneBased) == 0x150,
    "ScrFileCtrl::mActiveCursorLineOneBased offset must be 0x150"
  );
  static_assert(
    offsetof(ScrFileCtrl, mMarkerImageList) == 0x154,
    "ScrFileCtrl::mMarkerImageList offset must be 0x154"
  );
  static_assert(offsetof(ScrFileCtrl, mSourcePath) == 0x158, "ScrFileCtrl::mSourcePath offset must be 0x158");
  static_assert(offsetof(ScrFileCtrl, mLines) == 0x174, "ScrFileCtrl::mLines offset must be 0x174");
  static_assert(sizeof(ScrFileCtrl) == 0x184, "ScrFileCtrl size must be 0x184");
} // namespace moho
