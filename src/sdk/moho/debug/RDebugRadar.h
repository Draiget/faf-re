#pragma once

#include "moho/debug/RDebugOverlay.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E23568
   * COL: 0x00E7D7F8
   */
  class RDebugRadar : public RDebugOverlay
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0064ED20 (FUN_0064ED20)
     *
     * What it does:
     * Initializes the radar-overlay vtable lane and inherited intrusive
     * debug-overlay links.
     */
    RDebugRadar();

    /**
     * Address: 0x0064D880 (FUN_0064D880, Moho::RDebugRadar::GetClass)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `RDebugRadar`.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0064D8A0 (FUN_0064D8A0, Moho::RDebugRadar::GetDerivedObjectRef)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0064ED70 (FUN_0064ED70, Moho::RDebugRadar::dtr)
     * Slot: 2
     */
    ~RDebugRadar() override;

    /**
     * Address: 0x0064E020 (FUN_0064E020, Moho::RDebugRadar::OnTick)
     * Slot: 3
     *
     * What it does:
     * Drives radar-debug overlay rendering for active recon data.
     */
    void Tick(Sim* sim) override;
  };

  static_assert(sizeof(RDebugRadar) == 0x0C, "RDebugRadar size must be 0x0C");
} // namespace moho
