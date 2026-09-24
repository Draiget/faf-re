#pragma once

#include <cstddef>

#include "platform/WxWidgets.h"
#include <wx/dialog.h>

class wxTextCtrl;

namespace moho
{
  /**
   * VFTABLE: 0x00E088CC (??_7ScrGotoDialog@Moho@@6B@)
   *
   * The debugger's "Goto" line prompt, shown modally from
   * ScrDebugWindow::OnGotoLineCommand. It reopens where it was last moved to
   * (Windows.Debug.Goto.x/y).
   *
   * Slot 0 is wxDialog::GetClassInfo (0x004A3970); 47, 139 and 140 are inline
   * wx copies. The destructor (0x004BBEA0, deleting 0x004BC0C0) is the
   * compiler's. The one stack instance (OnGotoLineCommand) has 0x17C bytes of
   * frame before its EH record, which bounds the size.
   */
  class ScrGotoDialog : public wxDialog
  {
  public:
    /**
     * Address: 0x004BB730 (FUN_004BB730, ??0ScrGotoDialog@Moho@@QAE@@Z)
     *
     * What it does:
     * A captioned dialog at the saved position: a "Goto" label beside a
     * 96-pixel line field, over a default Goto (wxID_OK) and a Cancel button.
     * mInitializing holds OnMove off until the layout is done.
     */
    ScrGotoDialog();

    /**
     * Address: 0x004BBFF0 (FUN_004BBFF0)
     *
     * What it does:
     * The typed line number, through atoi: 0 for anything that is not one.
     */
    [[nodiscard]] int GetLine() const;

    /**
     * Address: 0x004BBFD0 (FUN_004BBFD0)
     *
     * What it does:
     * Ends the dialog with wxID_OK, without wxDialog's validation.
     */
    void OnOK(wxCommandEvent& event);

    /**
     * Address: 0x004BBEB0 (FUN_004BBEB0)
     *
     * What it does:
     * Saves the position to Windows.Debug.Goto.x/y, once constructed.
     */
    void OnMove(wxMoveEvent& event);

    bool mInitializing;      // +0x170
    wxTextCtrl* mLineText;   // +0x174

    DECLARE_EVENT_TABLE()
  };

  static_assert(offsetof(ScrGotoDialog, mInitializing) == 0x170, "ScrGotoDialog::mInitializing offset must be 0x170");
  static_assert(offsetof(ScrGotoDialog, mLineText) == 0x174, "ScrGotoDialog::mLineText offset must be 0x174");
  static_assert(sizeof(ScrGotoDialog) == 0x178, "ScrGotoDialog size must be 0x178");
} // namespace moho
