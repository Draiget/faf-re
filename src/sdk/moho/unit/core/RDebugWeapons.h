#pragma once

#include "moho/debug/RDebugOverlay.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E238A8
   * COL: 0x00E7DC28
   */
  class RDebugWeapons : public RDebugOverlay
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x006537D0 (FUN_006537D0)
     *
     * What it does:
     * Initializes the weapons-overlay vtable lane and inherited intrusive
     * debug-overlay links.
     */
    RDebugWeapons();

    /**
     * Address: 0x00652C90 (FUN_00652C90, ?GetClass@RDebugWeapons@Moho@@UBEPAVRType@gpg@@XZ)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `RDebugWeapons`.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x00652CB0 (FUN_00652CB0, ?GetDerivedObjectRef@RDebugWeapons@Moho@@UAE?AVRRef@gpg@@XZ)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x006537E0 (FUN_006537E0, Moho::RDebugWeapons::dtr)
     * Slot: 2
     */
    ~RDebugWeapons() override;

    /**
     * Address: 0x00652E00 (FUN_00652E00, Moho::RDebugWeapons::OnTick)
     * Slot: 3
     *
     * What it does:
     * Draws per-unit weapon range circles and world-space weapon labels.
     */
    void Tick(Sim* sim) override;
  };

  static_assert(sizeof(RDebugWeapons) == 0x0C, "RDebugWeapons size must be 0x0C");
} // namespace moho
