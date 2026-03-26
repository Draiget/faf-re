#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C110
   * COL:  0x00E7151C
   */
  class CAiNavigatorAirTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005A54F0 (FUN_005A54F0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiNavigatorAirTypeInfo() override;

    /**
     * Address: 0x005A54E0 (FUN_005A54E0, ?GetName@CAiNavigatorAirTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A54C0 (FUN_005A54C0, ?Init@CAiNavigatorAirTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiNavigatorAirTypeInfo) == 0x64, "CAiNavigatorAirTypeInfo size must be 0x64");
} // namespace moho

