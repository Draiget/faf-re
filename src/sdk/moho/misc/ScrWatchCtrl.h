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
    static void* sm_eventTable[1];
    wxTreeItemIdRuntime mRootItem{}; // +0x140
  };

  static_assert(offsetof(ScrWatchCtrl, mRootItem) == 0x140, "ScrWatchCtrl::mRootItem offset must be 0x140");
  static_assert(sizeof(ScrWatchCtrl) == 0x144, "ScrWatchCtrl size must be 0x144");
} // namespace moho
