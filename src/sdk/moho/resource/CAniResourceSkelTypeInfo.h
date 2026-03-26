#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E16310
   * COL: 0x00E6A9F4
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class CAniResourceSkelTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00538610 (FUN_00538610, Moho::CAniResourceSkelTypeInfo::dtr)
     * Slot: 2
     */
    ~CAniResourceSkelTypeInfo() override;

    /**
     * Address: 0x00538600 (FUN_00538600, Moho::CAniResourceSkelTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005385E0 (FUN_005385E0, Moho::CAniResourceSkelTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CAniResourceSkel` and registers
     * `CAniSkel` as the single base type.
     */
    void Init() override;
  };

  static_assert(sizeof(CAniResourceSkelTypeInfo) == 0x64, "CAniResourceSkelTypeInfo size must be 0x64");
} // namespace moho
