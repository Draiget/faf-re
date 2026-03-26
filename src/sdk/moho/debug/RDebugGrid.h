#pragma once

#include "moho/debug/RDebugOverlay.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E23524
   * COL: 0x00E7D8AC
   */
  class RDebugGrid : public RDebugOverlay
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0064D020 (FUN_0064D020, Moho::RDebugGrid::GetClass)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `RDebugGrid`.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0064D040 (FUN_0064D040, Moho::RDebugGrid::GetDerivedObjectRef)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0064ED30 (FUN_0064ED30, Moho::RDebugGrid::dtr)
     * Slot: 2
     */
    ~RDebugGrid() override;

    /**
     * Address: 0x0064D7A0 (FUN_0064D7A0, Moho::RDebugGrid::OnTick)
     * Slot: 3
     *
     * What it does:
     * Drives world-grid overlay rendering for the active sim map.
     */
    void Tick(Sim* sim) override;
  };

  static_assert(sizeof(RDebugGrid) == 0x0C, "RDebugGrid size must be 0x0C");
} // namespace moho
