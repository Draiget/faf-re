#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E23850
   * COL: 0x00E7DB20
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugOverlayTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00651AA0 (FUN_00651AA0, Moho::RDebugOverlayTypeInfo::dtr)
     * Slot: 2
     */
    ~RDebugOverlayTypeInfo() override;

    /**
     * Address: 0x00651A90 (FUN_00651A90, Moho::RDebugOverlayTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `RDebugOverlay`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00651A60 (FUN_00651A60, Moho::RDebugOverlayTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RDebugOverlay`
     * (`sizeof = 0x0C`) and registers the `gpg::RObject` base.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00652750 (FUN_00652750, Moho::RDebugOverlayTypeInfo::AddBase_RObject)
     *
     * What it does:
     * Registers `gpg::RObject` as reflection base for `RDebugOverlay`.
     */
    static void AddBase_RObject(gpg::RType* typeInfo);
  };

  static_assert(sizeof(RDebugOverlayTypeInfo) == 0x64, "RDebugOverlayTypeInfo size must be 0x64");
} // namespace moho
