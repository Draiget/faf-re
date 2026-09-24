#pragma once

#include <cstddef>

#include "legacy/containers/Vector.h"
#include "moho/misc/ScrWatch.h"
#include "platform/WxWidgets.h"
#include <wx/control.h>
#include <wx/treectrl.h>
#include <wx/treelistctrl.h>

namespace moho
{
  /**
   * VFTABLE: 0x00E0AAAC (??_7ScrWatchCtrl@Moho@@6B@)
   *
   * A watch pane of the debugger, locals or globals: one row per variable with
   * its name, type and value. Activating a table lists its fields the first
   * time, then opens or closes it.
   *
   * Slot 0 is wxTreeListCtrl::GetClassInfo and slot 34 its inline
   * GetWindowStyleFlag, both emitted near the reflection editor (0x004A3C70,
   * 0x004A3C50). The deleting destructor (0x004D71E0) and the destructor are
   * the compiler's.
   */
  class ScrWatchCtrl : public wxTreeListCtrl
  {
  public:
    /**
     * Address: 0x004D6FF0 (FUN_004D6FF0, ??0ScrWatchCtrl@Moho@@QAE@PAVwxWindow@@ABHHHHABVwxPoint@@ABVwxSize@@@Z)
     *
     * What it does:
     * A tree list with buttons, hidden root and full-row highlight; the
     * Variable/Type/Value columns at the given widths under a "VARIABLES"
     * root. Item activation goes to OnItemActivate. The shipped code has
     * `pos` and `size` dropped, every caller passing the defaults.
     */
    ScrWatchCtrl(
      wxWindow* parent,
      const int& id,
      int nameWidth,
      int typeWidth,
      int valueWidth,
      const wxPoint& pos = wxDefaultPosition,
      const wxSize& size = wxDefaultSize
    );

    /**
     * Address: 0x004D7270 (FUN_004D7270, ?Clear@ScrWatchCtrl@Moho@@UAEXXZ)
     *
     * What it does:
     * Deletes every row under the root. Overrides wxWindow::Clear (slot 62).
     */
    void Clear() override;

    /**
     * Address: 0x004D7220 (FUN_004D7220, ?Update@ScrWatchCtrl@Moho@@QAEXABV?$vector@VScrWatch@Moho@@V?$allocator@VScrWatch@Moho@@@std@@@std@@@Z)
     *
     * What it does:
     * Replaces the rows with `watches`, sorted by name.
     */
    void Update(const msvc8::vector<ScrWatch>& watches);

    /**
     * Address: 0x004D7380 (FUN_004D7380, ?OnItemActivate@ScrWatchCtrl@Moho@@QAEXAAVwxTreeEvent@@@Z)
     *
     * What it does:
     * For a table row: adds its fields as child rows, sorted, the first time
     * it has none; then collapses it if expanded, else expands it.
     */
    void OnItemActivate(wxTreeEvent& event);

  private:
    /**
     * Address: 0x004D7580 (FUN_004D7580, ?AddWatch@ScrWatchCtrl@Moho@@AAEXABVwxTreeItemId@@ABVScrWatch@2@@Z)
     *
     * What it does:
     * Appends a row under `parent` for `watch`, carrying a copy of it as the
     * row's TreeData, with its type and value in columns 1 and 2.
     */
    void AddWatch(const wxTreeItemId& parent, const ScrWatch& watch);

  public:
    wxTreeItemId mRoot; // +0x140

    DECLARE_EVENT_TABLE()
  };

  static_assert(offsetof(ScrWatchCtrl, mRoot) == 0x140, "ScrWatchCtrl::mRoot offset must be 0x140");
  static_assert(sizeof(ScrWatchCtrl) == 0x144, "ScrWatchCtrl size must be 0x144");
} // namespace moho
