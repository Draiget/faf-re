#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3632C
   * COL:  0x00E8FEE8
   */
  class CIntelCounterHandleTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0076F520 (FUN_0076F520, Moho::CIntelCounterHandleTypeInfo::dtr)
     * Slot: 2
     *
     * What it does:
     * Scalar deleting destructor thunk for CIntelCounterHandleTypeInfo.
     */
    ~CIntelCounterHandleTypeInfo() override;

    /**
     * Address: 0x0076F510 (FUN_0076F510, Moho::CIntelCounterHandleTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type label for CIntelCounterHandle.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0076F4F0 (FUN_0076F4F0, Moho::CIntelCounterHandleTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets CIntelCounterHandle size metadata, registers CIntelPosHandle as
     * reflected base, and finalizes the reflected type.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0076FD30 (FUN_0076FD30, Moho::CIntelCounterHandleTypeInfo::AddBase_CIntelPosHandle)
     *
     * What it does:
     * Adds CIntelPosHandle base metadata to the CIntelCounterHandle type.
     */
    static void AddBase_CIntelPosHandle(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CIntelCounterHandleTypeInfo) == 0x64, "CIntelCounterHandleTypeInfo size must be 0x64");
} // namespace moho
