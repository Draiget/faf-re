#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E10FE8
   */
  class RPropBlueprintDisplayTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0051D450 (FUN_0051D450, Moho::RPropBlueprintDisplayTypeInfo::RPropBlueprintDisplayTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RPropBlueprintDisplay`.
     */
    RPropBlueprintDisplayTypeInfo();

    /**
     * Address: 0x0051D510 (FUN_0051D510, scalar deleting destructor thunk)
     * Slot: 2
     */
    ~RPropBlueprintDisplayTypeInfo() override;

    /**
     * Address: 0x0051D500 (FUN_0051D500)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051D4B0 (FUN_0051D4B0)
     * Slot: 9
     *
     * What it does:
     * Sets `RPropBlueprintDisplay` size and publishes display field metadata.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC87B0 (FUN_00BC87B0, register_RPropBlueprintDisplayTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RPropBlueprintDisplayTypeInfo`.
   */
  int register_RPropBlueprintDisplayTypeInfo();

  static_assert(sizeof(RPropBlueprintDisplayTypeInfo) == 0x64, "RPropBlueprintDisplayTypeInfo size must be 0x64");
} // namespace moho
