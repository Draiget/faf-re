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
     * Address: 0x0076F040 (FUN_0076F040, Moho::CIntelPosHandleTypeInfo::CIntelPosHandleTypeInfo)
     *
     * What it does:
     * Constructs `CIntelPosHandle` type-info storage and preregisters its RTTI mapping.
     */
    CIntelPosHandleTypeInfo();

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

  /**
   * Address: 0x00C01E40 (FUN_00C01E40, cleanup_CIntelPosHandleTypeInfo)
   *
   * What it does:
   * Runs process-exit teardown for startup `CIntelPosHandleTypeInfo` storage.
   */
  void cleanup_CIntelPosHandleTypeInfo();

  /**
   * Address: 0x00BDCC90 (FUN_00BDCC90, register_CIntelPosHandleTypeInfo)
   *
   * What it does:
   * Builds startup `CIntelPosHandleTypeInfo` storage and installs process-exit cleanup.
   */
  void register_CIntelPosHandleTypeInfo();
} // namespace moho
