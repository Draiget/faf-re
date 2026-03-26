#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F388
   * COL:  0x00E76748
   */
  class IAiTransportTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005E47D0 (FUN_005E47D0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~IAiTransportTypeInfo() override;

    /**
     * Address: 0x005E47C0 (FUN_005E47C0, ?GetName@IAiTransportTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E47A0 (FUN_005E47A0, ?Init@IAiTransportTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(IAiTransportTypeInfo) == 0x64, "IAiTransportTypeInfo size must be 0x64");
} // namespace moho
