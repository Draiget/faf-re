#pragma once

#include "moho/debug/RDebugOverlay.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E236F4
   * COL: 0x00E7D960
   */
  class RDebugNavSteering : public RDebugOverlay
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00650EF0 (FUN_00650EF0)
     *
     * What it does:
     * Initializes the steering-overlay vtable lane and inherited intrusive
     * debug-overlay links.
     */
    RDebugNavSteering();

    /**
     * Address: 0x00650930 (FUN_00650930, Moho::RDebugNavSteering::GetClass)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `RDebugNavSteering`.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x00650950 (FUN_00650950, Moho::RDebugNavSteering::GetDerivedObjectRef)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00650F80 (FUN_00650F80, Moho::RDebugNavSteering::dtr)
     * Slot: 2
     */
    ~RDebugNavSteering() override;

    /**
     * Address: 0x00650AA0 (FUN_00650AA0, Moho::RDebugNavSteering::OnTick)
     * Slot: 3
     *
     * What it does:
     * Iterates all units and draws steering target lines.
     */
    void Tick(Sim* sim) override;
  };

  static_assert(sizeof(RDebugNavSteering) == 0x0C, "RDebugNavSteering size must be 0x0C");
} // namespace moho
