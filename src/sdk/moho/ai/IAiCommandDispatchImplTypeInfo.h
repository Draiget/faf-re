#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B3C8
   * COL:  0x00E704C8
   */
  class IAiCommandDispatchImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005991D0 (FUN_005991D0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~IAiCommandDispatchImplTypeInfo() override;

    /**
     * Address: 0x005991C0 (FUN_005991C0, ?GetName@IAiCommandDispatchImplTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00599190 (FUN_00599190, ?Init@IAiCommandDispatchImplTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(IAiCommandDispatchImplTypeInfo) == 0x64, "IAiCommandDispatchImplTypeInfo size must be 0x64");
} // namespace moho

