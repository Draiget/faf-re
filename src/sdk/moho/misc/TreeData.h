#pragma once

#include <cstddef>

#include "moho/misc/ScrWatch.h"
#include "platform/WxWidgets.h"
#include <wx/window.h>
#include <wx/treebase.h>

namespace moho
{
  /**
   * VFTABLE: 0x00E0ACCC (??_7TreeData@Moho@@6B@)
   *
   * A watch-pane row's copy of its watch, so activating the row can list a
   * table's fields. The destructor (0x004D6F70, deleting 0x004D6FC0) is the
   * compiler's.
   */
  class TreeData : public wxTreeItemData
  {
  public:
    /**
     * Address: 0x004D6F00 (FUN_004D6F00)
     *
     * What it does:
     * Copies the watch.
     */
    explicit TreeData(const ScrWatch& watch);

    ScrWatch mWatch; // +0x08
  };

  static_assert(offsetof(TreeData, mWatch) == 0x08, "TreeData::mWatch offset must be 0x08");
  static_assert(sizeof(TreeData) == 0x3C, "TreeData size must be 0x3C");
} // namespace moho
