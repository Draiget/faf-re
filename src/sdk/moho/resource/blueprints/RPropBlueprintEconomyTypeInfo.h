#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection descriptor for `RPropBlueprintEconomy`.
   *
   * Without it the type reports zero fields, and `SCR_RObjectToLuaMerge`
   * (0x004CF0B0) falls through its `GetNumFields() > 0` arm to the trailing
   * `GetLexical()` stringify -- so `blueprint.Economy` reaches Lua as the string
   * "RPropBlueprintEconomy at 0x...." instead of an indexable table.
   */
  class RPropBlueprintEconomyTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0051D7A0 (FUN_0051D7A0)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RPropBlueprintEconomy`.
     */
    RPropBlueprintEconomyTypeInfo();

    /**
     * Address: 0x0051D870 (FUN_0051D870, Moho::RPropBlueprintEconomyTypeInfo::dtr)
     * Slot: 2
     */
    ~RPropBlueprintEconomyTypeInfo() override;

    /**
     * Address: 0x0051D860 (FUN_0051D860, Moho::RPropBlueprintEconomyTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051D800 (FUN_0051D800, Moho::RPropBlueprintEconomyTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets `RPropBlueprintEconomy` size to 8 and publishes `ReclaimMassMax`
     * (+0x00) and `ReclaimEnergyMax` (+0x04), both floats at version 3.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC87F0 (FUN_00BC87F0)
   *
   * What it does:
   * Materializes and startup-registers `RPropBlueprintEconomyTypeInfo`.
   */
  int register_RPropBlueprintEconomyTypeInfo();
} // namespace moho
