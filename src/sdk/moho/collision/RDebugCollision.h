#pragma once

#include "moho/debug/RDebugOverlayClass.h"
#include "moho/render/RDebugOverlay.h"

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E23480
   * COL: 0x00E7D5D4
   */
  class RDebugCollision : public RDebugOverlay
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0064C270 (FUN_0064C270, ?GetClass@RDebugCollision@Moho@@UBEPAVRType@gpg@@XZ)
     * Slot: 0
     *
     * What it does:
     * Returns cached reflection descriptor for `RDebugCollision`.
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0064C290 (FUN_0064C290, ?GetDerivedObjectRef@RDebugCollision@Moho@@UAE?AVRRef@gpg@@XZ)
     * Slot: 1
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0064C860 (FUN_0064C860, scalar deleting body)
     * Slot: 2
     */
    ~RDebugCollision() override;

    /**
     * Address: 0x0064C500 (FUN_0064C500)
     * Slot: 3
     *
     * What it does:
     * Debug-overlay tick hook for rendering unit/entity collision volumes.
     */
    void Tick(Sim* sim) override;
  };

  /**
   * VFTABLE: 0x00E23494
   * COL: 0x00E7D578
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugCollisionTypeInfo : public RDebugOverlayClass
  {
  public:
    /**
     * Address: 0x0064C2B0 (FUN_0064C2B0, Moho::RDebugCollisionTypeInfo::RDebugCollisionTypeInfo)
     *
     * What it does:
     * Initializes debug-overlay class RTTI lanes and preregisters
     * `RDebugCollision` reflection ownership.
     */
    RDebugCollisionTypeInfo();

    /**
     * Address: 0x0064C3A0 (FUN_0064C3A0, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RDebugCollisionTypeInfo() override;

    /**
     * Address: 0x0064C390 (FUN_0064C390)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `RDebugCollision`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0064C340 (FUN_0064C340)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RDebugCollision`
     * (`sizeof = 0x0C`) and registers the `RDebugOverlay` base.
     */
    void Init() override;
  };

  static_assert(sizeof(RDebugCollision) == 0x0C, "RDebugCollision size must be 0x0C");
#if defined(MOHO_STRICT_LAYOUT_ASSERTS)
  static_assert(sizeof(RDebugCollisionTypeInfo) == 0xA8, "RDebugCollisionTypeInfo size must be 0xA8");
#endif
} // namespace moho
