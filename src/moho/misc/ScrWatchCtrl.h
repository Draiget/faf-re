#pragma once

#include <cstddef>
#include <memory>
#include <vector>

#include "legacy/containers/Vector.h"
#include "moho/misc/ScrWatch.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E07D3C (??_7ScrWatchCtrl@Moho@@6B@)
   *
   * The debugger's Locals and Globals: a Variable/Type/Value tree whose table rows open into
   * their fields the first time. A wxTreeListCtrl with a hidden "VARIABLES" root in the binary,
   * whose rows carried a TreeData (0x004D7580) holding the watch; Dear ImGui since issue #413.
   */
  class ScrWatchCtrl
  {
  public:
    /**
     * Address: 0x004D6FF0 (FUN_004D6FF0, ??0ScrWatchCtrl@Moho@@QAE@PAVwxWindow@@ABHHHHABVwxPoint@@ABVwxSize@@@Z)
     *
     * What it does:
     * An empty tree with the three columns at the widths given.
     */
    ScrWatchCtrl(int nameWidth, int typeWidth, int valueWidth);

    /**
     * Address: 0x004D7270 (FUN_004D7270, ?Clear@ScrWatchCtrl@Moho@@UAEXXZ)
     */
    void Clear();

    /**
     * Address: 0x004D7220 (FUN_004D7220,
     * ?Update@ScrWatchCtrl@Moho@@QAEXABV?$vector@VScrWatch@Moho@@V?$allocator@VScrWatch@Moho@@@std@@@std@@@Z)
     *
     * What it does:
     * Shows `watches` as the top rows, sorted by name.
     */
    void Update(const fa::vector<ScrWatch>& watches);

    // The tree, its columns resizable; true when a column width changed this frame
    // (EVT_LIST_COL_END_DRAG in the binary's window), with the widths in `widths`.
    bool Draw(const char* id, int widths[3]);

  private:
    struct Row
    {
      ScrWatch watch;
      fa::string type;
      fa::string value;
      bool listed = false; // its fields were added (HasChildren in the binary)
      std::vector<std::unique_ptr<Row>> children;
    };

    /**
     * Address: 0x004D7580 (FUN_004D7580, ?AddWatch@ScrWatchCtrl@Moho@@AAEXABVwxTreeItemId@@ABVScrWatch@2@@Z)
     */
    static void AddWatch(std::vector<std::unique_ptr<Row>>& parent, const ScrWatch& watch);

    /**
     * Address: 0x004D7380 (FUN_004D7380, ?OnItemActivate@ScrWatchCtrl@Moho@@QAEXAAVwxTreeEvent@@@Z)
     *
     * What it does:
     * Lists a table's fields under its row the first time it opens, sorted by name.
     */
    static void ListFields(Row& row);

    static void SortRows(std::vector<std::unique_ptr<Row>>& rows);
    void DrawRow(Row& row);

    std::vector<std::unique_ptr<Row>> mRows; // the hidden root's children
    int mWidths[3];
  };
} // namespace moho
