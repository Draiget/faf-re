#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection descriptor for `RPropBlueprintDefense`.
   *
   * Without it the type reports zero fields, and `SCR_RObjectToLuaMerge`
   * (0x004CF0B0) falls through its `GetNumFields() > 0` arm to the trailing
   * `GetLexical()` stringify -- so `blueprint.Defense` reaches Lua as the string
   * "RPropBlueprintDefense at 0x...." instead of an indexable table.
   */
  class RPropBlueprintDefenseTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0051D5F0 (FUN_0051D5F0)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RPropBlueprintDefense`.
     */
    RPropBlueprintDefenseTypeInfo();

    /**
     * Address: 0x0051D6C0 (FUN_0051D6C0, Moho::RPropBlueprintDefenseTypeInfo::dtr)
     * Slot: 2
     */
    ~RPropBlueprintDefenseTypeInfo() override;

    /**
     * Address: 0x0051D6B0 (FUN_0051D6B0, Moho::RPropBlueprintDefenseTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051D650 (FUN_0051D650, Moho::RPropBlueprintDefenseTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets `RPropBlueprintDefense` size to 8 and publishes `MaxHealth` (+0x00)
     * and `Health` (+0x04), both floats at version 3.
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC87D0 (FUN_00BC87D0)
   *
   * What it does:
   * Materializes and startup-registers `RPropBlueprintDefenseTypeInfo`.
   */
  int register_RPropBlueprintDefenseTypeInfo();
} // namespace moho
