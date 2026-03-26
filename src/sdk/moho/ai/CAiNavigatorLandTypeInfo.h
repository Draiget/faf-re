#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C0C0
   * COL:  0x00E716C4
   */
  class CAiNavigatorLandTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005A45F0 (FUN_005A45F0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiNavigatorLandTypeInfo() override;

    /**
     * Address: 0x005A45E0 (FUN_005A45E0, ?GetName@CAiNavigatorLandTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A45C0 (FUN_005A45C0, ?Init@CAiNavigatorLandTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiNavigatorLandTypeInfo) == 0x64, "CAiNavigatorLandTypeInfo size must be 0x64");
} // namespace moho

