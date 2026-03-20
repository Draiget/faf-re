#pragma once

namespace moho
{
  /**
   * VFTABLE: 0x00E25DEC
   * COL:  0x00E7ED84
   */
  class CEffectManagerImpl
  {
  public:
    /**
     * Address: 0x0066B400
     * Slot: 0
     */
    virtual ~CEffectManagerImpl() = default;

    virtual void _slot1() = 0;
    virtual void _slot2() = 0;
    virtual void _slot3() = 0;
    virtual void _slot4() = 0;
    virtual void _slot5() = 0;
    virtual void _slot6() = 0;
    virtual void _slot7() = 0;
    virtual void _slot8() = 0;
    virtual void _slot9() = 0;
    virtual void _slot10() = 0;
    virtual void _slot11() = 0;
    virtual void _slot12() = 0;

    /**
     * Address: 0x0066B4F0
     * Slot: 13
     *
     * What it does:
     * Advances active effect lifetimes and per-frame effect simulation.
     */
    virtual void Tick() = 0;

    virtual void _slot14() = 0;

    /**
     * Address: 0x0066B570
     * Slot: 15
     *
     * What it does:
     * Removes effects that were marked for destruction during this frame.
     */
    virtual void PurgeDestroyedEffects() = 0;
  };
} // namespace moho
