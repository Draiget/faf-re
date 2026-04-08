#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E2346C
   * COL: 0x00E7D62C
   */
  class RDebugOverlay : public gpg::RObject, public TDatListItem<RDebugOverlay, void>
  {
  public:
    /**
     * Address: 0x0064C1E0 (FUN_0064C1E0, scalar deleting body)
     * Slot: 2
     *
     * What it does:
     * Unlinks this overlay from the intrusive debug-overlay list and tears down
     * base reflection object state.
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
