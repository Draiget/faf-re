#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B37C
   * COL:  0x00E70638
   */
  class IAiCommandDispatchTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x00598C50 (FUN_00598C50, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~IAiCommandDispatchTypeInfo() override;

    /**
     * Address: 0x00598C40 (FUN_00598C40, ?GetName@IAiCommandDispatchTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00598C20 (FUN_00598C20, ?Init@IAiCommandDispatchTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(IAiCommandDispatchTypeInfo) == 0x64, "IAiCommandDispatchTypeInfo size must be 0x64");
} // namespace moho

