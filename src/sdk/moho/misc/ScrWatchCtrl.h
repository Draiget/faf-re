#pragma once

#include <cstddef>

#include "legacy/containers/Vector.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/misc/ScrWatch.h"

namespace moho
{
  class ScrWatchCtrl : public wxTreeListCtrlRuntime
  {
  public:
    /**
     * Address: 0x004D6FF0 (FUN_004D6FF0, ??0ScrWatchCtrl@Moho@@QAE@PAVwxWindow@@ABHHHHABVwxPoint@@ABVwxSize@@@Z)
     * Mangled: ??0ScrWatchCtrl@Moho@@QAE@PAVwxWindow@@ABHHHHABVwxPoint@@ABVwxSize@@@Z
     *
     * What it does:
     * Builds the base tree-list control (fixed style, default name), appends
     * the Variable/Type/Value columns at the given widths, seeds the root
     * item, and dynamically connects tree-item-activation to
     * `OnItemActivate` (this control's static event table is empty - the
     * binary wires this handler per-instance instead).
     */
    ScrWatchCtrl(
      wxWindowBase* parentWindow,
      std::int32_t windowId,
      std::uint32_t nameColumnWidth,
      std::uint32_t typeColumnWidth,
      std::uint32_t valueColumnWidth
    );

    /**
     * Address: 0x004D6FE0 (FUN_004D6FE0, Moho::ScrWatchCtrl::GetEventTable)
     *
     * What it does:
     * Returns this control's wx event-table lane.
     */
    [[nodiscard]] const void* GetEventTable() const override;

    /**
     * Address: 0x004D7270 (FUN_004D7270, Moho::ScrWatchCtrl::Clear)
     *
     * What it does:
     * Clears watch rows under the root tree item lane.
     */
    void Clear() override;

    /**
     * Address: 0x004D7220 (FUN_004D7220, Moho::ScrWatchCtrl::Update)
     *
     * What it does:
     * Rebuilds this watch tree from one watch-vector snapshot.
     */
    void Update(const msvc8::vector<ScrWatch>& watches);

    /**
     * Address: 0x004D7380 (FUN_004D7380, Moho::ScrWatchCtrl::OnItemActivate)
     *
     * What it does:
     * Expands one activated watch row by materializing Lua-table children and
     * toggles that row's expanded state.
     */
    void OnItemActivate(wxTreeEventRuntime& event);

  private:
    /**
     * Address: 0x004D7580 (FUN_004D7580, Moho::ScrWatchCtrl::AddWatch)
     *
     * What it does:
     * Appends one watch row and fills name/type/value columns plus payload.
     */
    void AddWatch(const wxTreeItemIdRuntime& parentItem, const ScrWatch& watch);

  public:
    static wxEventTable sm_eventTable;
    wxTreeItemIdRuntime mRootItem{}; // +0x140
  };

  static_assert(offsetof(ScrWatchCtrl, mRootItem) == 0x140, "ScrWatchCtrl::mRootItem offset must be 0x140");
  static_assert(sizeof(ScrWatchCtrl) == 0x144, "ScrWatchCtrl size must be 0x144");
} // namespace moho
