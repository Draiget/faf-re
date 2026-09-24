#pragma once

#include <cstddef>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/ScrFileLine.h"
#include "platform/WxWidgets.h"
#include <wx/control.h>
#include <wx/listctrl.h>

class wxImageList;

namespace moho
{
  /**
   * VFTABLE: 0x00E08D2C (??_7ScrFileCtrl@Moho@@6B@)
   *
   * One page of the debugger's source notebook: a virtual report list with an
   * image, a line-number and a source column, one row per line of the file.
   * A row's image is its ScrFileLine::mMarkerState - the execution cursor and
   * the breakpoints. Double-click or Enter toggles a breakpoint.
   *
   * No class info of its own (slot 0 is wxListCtrl::GetClassInfo, emitted at
   * 0x004BB700). Slots 131-133 are wxControl's inline virtuals (0x004A3830,
   * 0x004A3840, 0x004A3850).
   */
  class ScrFileCtrl : public wxListCtrl
  {
  public:
    /**
     * Address: 0x004C1EE0 (FUN_004C1EE0)
     *
     * What it does:
     * A single-selection virtual report list with no header, the five
     * marker bitmaps from /coderes/engine as its small images, and the
     * image/line/source columns. Item activation toggles breakpoints.
     */
    explicit ScrFileCtrl(wxWindow* parent);

    /**
     * Address: 0x004C26A0 (FUN_004C26A0)
     * Deleting: 0x004C2680 (FUN_004C2680)
     *
     * What it does:
     * Member teardown only. The image list is never freed: SetImageList
     * does not hand it to the list control.
     */
    ~ScrFileCtrl() override;

    /**
     * Address: 0x004C2730 (FUN_004C2730)
     *
     * What it does:
     * Clears the page, then reads the file one line at a time through the
     * VFS into mLines, marks its breakpoints and sizes the list. False when
     * the name is empty, the VFS does not find it, or it will not open.
     */
    bool Load(const msvc8::string& fileName);

    /**
     * Address: 0x004C2DA0 (FUN_004C2DA0)
     *
     * What it does:
     * Drops every line, empties the list and forgets the cursor. Overrides
     * wxWindow::Clear (slot 62).
     */
    void Clear() override;

    /**
     * Address: 0x004C2A40 (FUN_004C2A40)
     *
     * What it does:
     * Selects and shows the first line whose source contains `text`.
     */
    void FindFirst(const msvc8::string& text);

    /**
     * Address: 0x004C2AE0 (FUN_004C2AE0)
     *
     * What it does:
     * The same search, starting after the selected line; nothing without a
     * selection.
     */
    void FindNext(const msvc8::string& text);

    /**
     * Address: 0x004C2B90 (FUN_004C2B90)
     *
     * What it does:
     * The same search backwards, starting before the selected line.
     */
    void FindPrevious(const msvc8::string& text);

    /**
     * Address: 0x004C2C20 (FUN_004C2C20)
     *
     * What it does:
     * Selects and shows the one-based `line` when the file has it.
     */
    void GotoLine(int line);

    /**
     * Address: 0x004C2C60 (FUN_004C2C60)
     *
     * What it does:
     * Shows every breakpoint marker as enabled or disabled, with or without
     * the cursor on it, and repaints each row.
     */
    void EnableBreakpoints(bool enable);

    /**
     * Address: 0x004C2CF0 (FUN_004C2CF0)
     *
     * What it does:
     * Takes the breakpoint marker off the one-based `line`, keeping the
     * cursor. The breakpoint itself is left to the caller.
     */
    void RemoveBreakpoint(int line);

    /**
     * Address: 0x004C2D60 (FUN_004C2D60)
     *
     * What it does:
     * RemoveBreakpoint on every line. Inlined where it is used
     * (ScrSourceCtrl::RemoveAllBreakpoints); nothing in the image calls this
     * copy.
     */
    void RemoveAllBreakpoints();

    /**
     * Address: 0x004C2DE0 (FUN_004C2DE0)
     *
     * What it does:
     * Puts the execution cursor on the one-based `line` and scrolls to it.
     * A line the file does not have is reported and refused.
     */
    bool SetCursorLine(int line);

    /**
     * Address: 0x004C2EA0 (FUN_004C2EA0)
     *
     * What it does:
     * Takes the execution cursor off its line, keeping that line's
     * breakpoint.
     */
    void ClearCursor();

    /**
     * Address: 0x004C2F30 (FUN_004C2F30)
     *
     * What it does:
     * Column 1 is the line number, column 2 the tab-expanded source; the
     * image column has no text.
     */
    wxString OnGetItemText(long item, long column) const override;

    /**
     * Address: 0x004C2F10 (FUN_004C2F10)
     *
     * What it does:
     * The row's marker state is its image.
     */
    int OnGetItemImage(long item) const override;

    /**
     * Address: 0x004C30B0 (FUN_004C30B0)
     *
     * What it does:
     * 10pt Courier New in black, on alternating light backgrounds. Every
     * call allocates a new attribute that nothing frees.
     */
    wxListItemAttr* OnGetItemAttr(long item) const override;

    /**
     * Address: 0x004C3270 (FUN_004C3270)
     *
     * What it does:
     * Toggles the activated line's breakpoint, both the marker and the
     * breakpoint set (SCR_AddBreakpoint / SCR_RemoveBreakpoint).
     */
    void OnLineActivated(wxListEvent& event);

    /**
     * Address: 0x004C33D0 (FUN_004C33D0)
     *
     * What it does:
     * Stretches the source column to the new width less 100 pixels. Does not
     * skip the event.
     */
    void OnSize(wxSizeEvent& event);

  private:
    /**
     * Address: 0x004C3400 (FUN_004C3400)
     *
     * What it does:
     * Marks this file's breakpoints from SCR_EnumerateBreakpoints. Only the
     * upper bound of each line is checked.
     */
    void LoadBreakpoints();

  public:
    int mCursorLine;                    // +0x150 one-based, 0 when none
    wxImageList* mImageList;            // +0x154
    msvc8::string mSourcePath;          // +0x158
    msvc8::vector<ScrFileLine> mLines;  // +0x174

    DECLARE_EVENT_TABLE()
  };

  static_assert(offsetof(ScrFileCtrl, mCursorLine) == 0x150, "ScrFileCtrl::mCursorLine offset must be 0x150");
  static_assert(offsetof(ScrFileCtrl, mImageList) == 0x154, "ScrFileCtrl::mImageList offset must be 0x154");
  static_assert(offsetof(ScrFileCtrl, mSourcePath) == 0x158, "ScrFileCtrl::mSourcePath offset must be 0x158");
  static_assert(offsetof(ScrFileCtrl, mLines) == 0x174, "ScrFileCtrl::mLines offset must be 0x174");
  static_assert(sizeof(ScrFileCtrl) == 0x184, "ScrFileCtrl size must be 0x184");
} // namespace moho
