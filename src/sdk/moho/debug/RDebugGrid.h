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
     * Address: 0x0064ED10 (FUN_0064ED10)
     *
     * What it does:
     * Initializes the grid-overlay vtable lane and inherited intrusive
     * debug-overlay links.
     */
    RDebugGrid();

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
     * Address: 0x0064EDB0 (FUN_0064EDB0 -- the non-deleting `??1` half of the same
     * destructor; the `??_G` above is `test byte [esp+4],1` wrapped around
     * this body plus `::operator delete`. Neither is source: `~RDebugGrid` is
     * trivial, so the whole body is the compiler chaining into
     * `~RDebugOverlay` -- latch `RDebugOverlay`'s vtable (0x00E2346C), unlink
     * the intrusive node, latch `gpg::RObject`'s (0x00D4145C). Eight of these
     * bodies are byte-identical (0x0064C1B0, 0x0064C8A0, 0x0064EDB0,
     * 0x0064EDE0, 0x00650FC0, 0x00650FF0, 0x00651020, 0x00653820) because
     * every overlay class's destructor is equally trivial; the other seven
     * belong to those classes, not to this one. Formerly transcribed as
     * `DestroyRDebugGridNonDeletingBody`, `[[maybe_unused]]` with zero callers.)
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
