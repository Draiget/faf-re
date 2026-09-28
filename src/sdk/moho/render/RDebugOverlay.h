#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/containers/DList.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E2346C
   * COL: 0x00E7D62C
   *
   * RTTI: `gpg::DListItem<RDebugOverlay>` at +0x04, the node on
   * `Sim::mDebugOverlays`.
   */
  class RDebugOverlay : public gpg::RObject, public gpg::DListItem<RDebugOverlay>
  {
  public:
    /**
     * Address: 0x00651AE0 (FUN_00651AE0)
     *
     * What it does:
     * Initializes the debug-overlay base lane and seeds intrusive links as a
     * singleton ring.
     */
    RDebugOverlay();

    /**
     * Address: 0x0064C1E0 (FUN_0064C1E0, scalar deleting body)
     * Address: 0x0064C1B0 (FUN_0064C1B0, the non-deleting body: vtable back to
     *   `RDebugOverlay`'s, the node unlinks (the `DListItem` base), vtable back
     *   to `gpg::RObject`'s; formerly `DestroyRDebugOverlayNonDeletingBody`)
     * Slot: 2
     *
     * What it does:
     * Nothing of its own; the base destructor takes the overlay off
     * `Sim::mDebugOverlays`.
     */
    ~RDebugOverlay() override;

    /**
     * Address: 0x00651AF0 (FUN_00651AF0, nullsub_1684)
     * Slot: 3
     *
     * What it does:
     * Default per-tick debug overlay hook. Base implementation is a no-op.
     */
    virtual void Tick(Sim* sim);

    /**
     * Address: 0x006527B0 (FUN_006527B0, Moho::RDebugOverlay::NewPtr)
     *
     * What it does:
     * Creates one reflected object through `typeInfo`, upcasts it to
     * `RDebugOverlay`, and returns the typed object pointer.
     */
    [[nodiscard]] static RDebugOverlay* NewPtr(gpg::RType& typeInfo);

  public:
    static gpg::RType* sType;
  };

  static_assert(sizeof(RDebugOverlay) == 0x0C, "RDebugOverlay size must be 0x0C");
} // namespace moho
