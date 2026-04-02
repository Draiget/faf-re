#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1F240
   * COL:  0x00E76B0C
   */
  class SAiReservedTransportBoneTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005E3FF0 (FUN_005E3FF0, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~SAiReservedTransportBoneTypeInfo() override;

    /**
     * Address: 0x005E3FE0 (FUN_005E3FE0, ?GetName@SAiReservedTransportBoneTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005E3FC0 (FUN_005E3FC0, ?Init@SAiReservedTransportBoneTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  /**
   * Address: 0x00BCED70 (FUN_00BCED70, register_SAiReservedTransportBoneTypeInfo)
   *
   * What it does:
   * Registers `SAiReservedTransportBone` type-info and installs process-exit
   * cleanup.
   */
  int register_SAiReservedTransportBoneTypeInfo();

  static_assert(sizeof(SAiReservedTransportBoneTypeInfo) == 0x64, "SAiReservedTransportBoneTypeInfo size must be 0x64");
} // namespace moho
