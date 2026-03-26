#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B7CC
   * COL:  0x00E70DE0
   */
  class CAiBuilderImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0059FC40 (FUN_0059FC40, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiBuilderImplTypeInfo() override;

    /**
     * Address: 0x0059FC30 (FUN_0059FC30, ?GetName@CAiBuilderImplTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0059FC10 (FUN_0059FC10, ?Init@CAiBuilderImplTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiBuilderImplTypeInfo) == 0x64, "CAiBuilderImplTypeInfo size must be 0x64");
} // namespace moho
