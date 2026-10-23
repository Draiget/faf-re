#pragma once

#include "moho/render/RDebugOverlay.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E2366C
   * COL: 0x00E7DAC8
   */
  class RDebugNavPath : public RDebugOverlay
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00650ED0 (FUN_00650ED0)
     *
     * What it does:
     * Initializes the nav-path overlay vtable lane and inherited intrusive
     * debug-overlay links.
     */
    RDebugNavPath();

    /**
     * Address: 0x00650520 (FUN_00650520, ?GetClass@RDebugNavPath@Moho@@UBEPAVRType@gpg@@XZ)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `RDebugNavPath`.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x00650540 (FUN_00650540, ?GetDerivedObjectRef@RDebugNavPath@Moho@@UAE?AVRRef@gpg@@XZ)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x00650F00 (FUN_00650F00, scalar deleting body)
     * Slot: 2
     */
    ~RDebugNavPath() override;

    /**
     * Address: 0x00650690 (FUN_00650690, Moho::RDebugNavPath::OnTick)
     * Slot: 3
     *
     * What it does:
     * Iterates all sim units and draws debug overlays for each navigator path.
     */
    void Tick(Sim* sim) override;
  };

  static_assert(sizeof(RDebugNavPath) == 0x0C, "RDebugNavPath size must be 0x0C");
} // namespace moho
