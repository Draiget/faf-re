#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E37378
   * COL: 0x00E91578
   *
   * Source hints:
   * - c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\reflection.cpp
   */
  class CDecalBufferTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00778F80 (FUN_00778F80, Moho::CDecalBufferTypeInfo::dtr)
     * Slot: 2
     */
    ~CDecalBufferTypeInfo() override;

    /**
     * Address: 0x00778F70 (FUN_00778F70, Moho::CDecalBufferTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00778F30 (FUN_00778F30, Moho::CDecalBufferTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets `CDecalBuffer` size metadata and reflection allocation/deallocation
     * callback lanes, then finalizes the type.
     */
    void Init() override;
  };

  static_assert(sizeof(CDecalBufferTypeInfo) == 0x64, "CDecalBufferTypeInfo size must be 0x64");
} // namespace moho
