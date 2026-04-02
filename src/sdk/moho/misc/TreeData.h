#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/app/WxRuntimeTypes.h"
#include "moho/misc/ScrWatch.h"

namespace moho
{
  /**
   * Tree-item payload used by script-watch controls.
   */
  class TreeData : public wxTreeItemDataRuntime
  {
  public:
    /**
     * Address: 0x004D6F00 (FUN_004D6F00)
     *
     * What it does:
     * Initializes one tree-item payload from one watch snapshot.
     */
    explicit TreeData(const ScrWatch& watch);

    /**
     * Address: 0x004D6F70 (FUN_004D6F70)
     *
     * What it does:
     * Releases embedded watch lanes and returns to wx client-data base state.
     */
    ~TreeData() override;

    /**
     * Address: 0x004D6FC0 (FUN_004D6FC0)
     *
     * What it does:
     * Implements deleting-dtor thunk semantics for one watch tree payload.
     */
    static TreeData* DeleteWithFlag(TreeData* object, std::uint8_t deleteFlags) noexcept;

  public:
    ScrWatch mWatch{}; // +0x08
  };

  static_assert(offsetof(TreeData, mWatch) == 0x08, "TreeData::mWatch offset must be 0x08");
  static_assert(sizeof(TreeData) == 0x3C, "TreeData size must be 0x3C");
} // namespace moho

