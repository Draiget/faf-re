#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E362DC
   * COL:  0x00E90090
   */
  class CIntelPosHandleTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0076F0D0 (FUN_0076F0D0, Moho::CIntelPosHandleTypeInfo::dtr)
     * Slot: 2
     *
     * What it does:
     * Scalar deleting destructor thunk for CIntelPosHandleTypeInfo.
     */
    ~CIntelPosHandleTypeInfo() override;

    /**
     * Address: 0x0076F0C0 (FUN_0076F0C0, Moho::CIntelPosHandleTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type label for CIntelPosHandle.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0076F0A0 (FUN_0076F0A0, Moho::CIntelPosHandleTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets CIntelPosHandle size metadata and finalizes the reflected type.
     */
    void Init() override;
  };

  static_assert(sizeof(CIntelPosHandleTypeInfo) == 0x64, "CIntelPosHandleTypeInfo size must be 0x64");
} // namespace moho
