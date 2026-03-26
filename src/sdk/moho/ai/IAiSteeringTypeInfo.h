#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1E0E8
   * COL:  0x00E74E04
   */
  class IAiSteeringTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005D2060 (FUN_005D2060, scalar deleting thunk)
     *
     * VFTable SLOT: 2
     */
    ~IAiSteeringTypeInfo() override;

    /**
     * Address: 0x005D2050 (FUN_005D2050, ?GetName@IAiSteeringTypeInfo@Moho@@UBEPBDXZ)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005D2030 (FUN_005D2030, ?Init@IAiSteeringTypeInfo@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 9
     */
    void Init() override;
  };

  static_assert(sizeof(IAiSteeringTypeInfo) == 0x64, "IAiSteeringTypeInfo size must be 0x64");
} // namespace moho
