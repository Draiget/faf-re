#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E23820
   * COL: 0x00E7DB7C
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class RDebugOverlayClassTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00651870 (FUN_00651870, Moho::RDebugOverlayClassTypeInfo::dtr)
     * Slot: 2
     */
    ~RDebugOverlayClassTypeInfo() override;

    /**
     * Address: 0x00651860 (FUN_00651860, Moho::RDebugOverlayClassTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `RDebugOverlayClass`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00651830 (FUN_00651830, Moho::RDebugOverlayClassTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `RDebugOverlayClass`
     * (`sizeof = 0xA8`) and registers the `gpg::RType` base.
     */
    void Init() override;

  private:
    /**
     * Address: 0x006526F0 (FUN_006526F0, Moho::RDebugOverlayClassTypeInfo::AddBase_RType)
     *
     * What it does:
     * Registers `gpg::RType` as reflection base for `RDebugOverlayClass`.
     */
    static void AddBase_RType(gpg::RType* typeInfo);
  };

  static_assert(sizeof(RDebugOverlayClassTypeInfo) == 0x64, "RDebugOverlayClassTypeInfo size must be 0x64");
} // namespace moho
