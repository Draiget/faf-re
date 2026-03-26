#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1E118
   * COL:  0x00E74DB4
   */
  class CAiSteeringImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005D22A0 (FUN_005D22A0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiSteeringImplTypeInfo() override;

    /**
     * Address: 0x005D2290 (FUN_005D2290, ?GetName@CAiSteeringImplTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005D2240 (FUN_005D2240, ?Init@CAiSteeringImplTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiSteeringImplTypeInfo) == 0x64, "CAiSteeringImplTypeInfo size must be 0x64");
} // namespace moho
