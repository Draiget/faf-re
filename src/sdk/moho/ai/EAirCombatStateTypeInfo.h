#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2AC68
   * COL:  0x00E841C4
   */
  class EAirCombatStateTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x006B7700 (FUN_006B7700, scalar deleting thunk)
     */
    ~EAirCombatStateTypeInfo() override;

    /**
     * Address: 0x006B76F0 (FUN_006B76F0)
     *
     * What it does:
     * Returns the reflection type name literal for EAirCombatState.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x006B76D0 (FUN_006B76D0)
     *
     * What it does:
     * Writes enum width and finalizes metadata.
     */
    void Init() override;
  };

  static_assert(sizeof(EAirCombatStateTypeInfo) == 0x78, "EAirCombatStateTypeInfo size must be 0x78");
} // namespace moho
