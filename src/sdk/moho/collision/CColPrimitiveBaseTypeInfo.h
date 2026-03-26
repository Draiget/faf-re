#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0D450
   * COL: 0x00E66DB8
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class CColPrimitiveBaseTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004FE590 (FUN_004FE590, Moho::CColPrimitiveBaseTypeInfo::dtr)
     * Slot: 2
     */
    ~CColPrimitiveBaseTypeInfo() override;

    /**
     * Address: 0x004FE580 (FUN_004FE580, Moho::CColPrimitiveBaseTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `CColPrimitiveBase`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004FE560 (FUN_004FE560, Moho::CColPrimitiveBaseTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CColPrimitiveBase`
     * (`sizeof = 0x04`) and finalizes type setup.
     */
    void Init() override;
  };

  static_assert(sizeof(CColPrimitiveBaseTypeInfo) == 0x64, "CColPrimitiveBaseTypeInfo size must be 0x64");
} // namespace moho

