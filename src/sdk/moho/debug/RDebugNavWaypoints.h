#pragma once

#include "moho/debug/RDebugOverlay.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E236B0
   * COL: 0x00E7DA14
   */
  class RDebugNavWaypoints : public RDebugOverlay
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00650730 (FUN_00650730, Moho::RDebugNavWaypoints::GetClass)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `RDebugNavWaypoints`.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x00650750 (FUN_00650750, Moho::RDebugNavWaypoints::GetDerivedObjectRef)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00650F40 (FUN_00650F40, Moho::RDebugNavWaypoints::dtr)
     * Slot: 2
     */
    ~RDebugNavWaypoints() override;

    /**
     * Address: 0x006508A0 (FUN_006508A0, Moho::RDebugNavWaypoints::OnTick)
     * Slot: 3
     *
     * What it does:
     * Iterates all units and draws steering waypoint circles.
     */
    void Tick(Sim* sim) override;
  };

  static_assert(sizeof(RDebugNavWaypoints) == 0x0C, "RDebugNavWaypoints size must be 0x0C");
} // namespace moho
