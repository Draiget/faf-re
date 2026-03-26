#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F47C
   * COL:  0x00E765FC
   */
  class CAiTransportImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005E83B0 (FUN_005E83B0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~CAiTransportImplTypeInfo() override;

    /**
     * Address: 0x005E83A0 (FUN_005E83A0, ?GetName@CAiTransportImplTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E8380 (FUN_005E8380, ?Init@CAiTransportImplTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CAiTransportImplTypeInfo) == 0x64, "CAiTransportImplTypeInfo size must be 0x64");
} // namespace moho
