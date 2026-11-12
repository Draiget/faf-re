#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/ScrFileLine.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E07A24 (??_7ScrFileCtrl@Moho@@6B@)
   *
   * One open Lua source in the debugger: its lines, each with its breakpoint and cursor marker,
   * the line number and the text. A virtual wxListCtrl (wxLC_REPORT | wxLC_VIRTUAL |
   * wxLC_NO_HEADER | wxLC_SINGLE_SEL) in the binary; drawn with Dear ImGui by Draw since issue
   * #413. Double-clicking a line sets or clears its breakpoint, as activating the list's row did.
   */
  class ScrFileCtrl
  {
  public:
    /**
     * Address: 0x004C1EE0 (FUN_004C1EE0)
     *
     * What it does:
     * An empty page; the binary also loaded the five marker bitmaps and made the three columns.
     */
    ScrFileCtrl();

    /**
     * Address: 0x004C26A0 (FUN_004C26A0)
     */
    ~ScrFileCtrl();

    /**
     * Address: 0x004C2730 (FUN_004C2730)
     *
     * What it does:
     * Reads the file's lines through the VFS and marks its breakpoints. False when the name is
     * empty or the file can't be read.
     */
    bool Load(const fa::string& fileName);

    /**
     * Address: 0x004C2DA0 (FUN_004C2DA0)
     */
    void Clear();

    /**
     * Address: 0x004C2A40 (FUN_004C2A40), 0x004C2AE0 (FUN_004C2AE0), 0x004C2B90 (FUN_004C2B90)
     *
     * What they do:
     * Select and show the first line holding `text`, the next one after the selected line, or the
     * one before it.
     */
    void FindFirst(const fa::string& text);
    void FindNext(const fa::string& text);
    void FindPrevious(const fa::string& text);

    /**
     * Address: 0x004C2C20 (FUN_004C2C20)
     */
    void GotoLine(int line);

    /**
     * Address: 0x004C2C60 (FUN_004C2C60)
     */
    void EnableBreakpoints(bool enable);

    /**
     * Address: 0x004C2CF0 (FUN_004C2CF0)
     */
    void RemoveBreakpoint(int line);

    /**
     * Address: 0x004C2D60 (FUN_004C2D60)
     */
    void RemoveAllBreakpoints();

    /**
     * Address: 0x004C2DE0 (FUN_004C2DE0)
     */
    bool SetCursorLine(int line);

    /**
     * Address: 0x004C2EA0 (FUN_004C2EA0)
     */
    void ClearCursor();

    /**
     * Address: 0x004C3270 (FUN_004C3270, OnLineActivated)
     *
     * What it does:
     * Sets a breakpoint on the line, or clears the one it has.
     */
    void ToggleBreakpoint(int index);

    // The lines, with the markers and the striped rows OnGetItemImage (0x004C2F10),
    // OnGetItemText (0x004C2F30) and OnGetItemAttr (0x004C30B0) gave the list.
    void Draw();

  private:
    /**
     * Address: 0x004C3400 (FUN_004C3400)
     */
    void LoadBreakpoints();

    // The selected row and showing it (SetItemState(.., LIST_STATE_SELECTED), EnsureVisible).
    void SelectLine(int index);

  public:
    int mCursorLine;                // one-based, 0 when none
    fa::string mSourcePath;         // the mounted path the page shows
    fa::vector<ScrFileLine> mLines; // the file, one entry a line
    int mSelectedLine = -1;         // zero-based, -1 when none
    int mScrollToLine = -1;         // zero-based row to bring into view on the next Draw
  };
} // namespace moho
