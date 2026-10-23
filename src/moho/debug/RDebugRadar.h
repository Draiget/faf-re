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
     * Address: 0x0064EDE0 (FUN_0064EDE0 -- the non-deleting `??1` half of the same
     * destructor; the `??_G` above is `test byte [esp+4],1` wrapped around
     * this body plus `::operator delete`. Neither is source: `~RDebugRadar` is
     * trivial, so the whole body is the compiler chaining into
     * `~RDebugOverlay` -- latch `RDebugOverlay`'s vtable (0x00E2346C), unlink
     * the intrusive node, latch `gpg::RObject`'s (0x00D4145C). Eight of these
     * bodies are byte-identical (0x0064C1B0, 0x0064C8A0, 0x0064EDB0,
     * 0x0064EDE0, 0x00650FC0, 0x00650FF0, 0x00651020, 0x00653820) because
     * every overlay class's destructor is equally trivial; the other seven
     * belong to those classes, not to this one. Formerly transcribed as
     * `DestroyRDebugRadarNonDeletingBody`, `[[maybe_unused]]` with zero callers.)
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
