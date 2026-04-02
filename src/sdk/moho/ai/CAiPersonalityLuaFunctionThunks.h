#pragma once

namespace moho
{
  class CScrLuaInitForm;

  // Underlying Lua function-definition publishers referenced by this thunk pack.
  CScrLuaInitForm* func_CAiPersonalityGetPersonalityName_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetChatPersonality_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetDifficulty_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityAdjustDelay_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetArmySize_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetPlatoonSize_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetAttackFrequency_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetRepeatAttackFrequency_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetCounterForces_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetIntelGathering_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetCoordinatedAttacks_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetExpansionDriven_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetTechAdvancement_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetUpgradesDriven_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetDefenseDriven_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetEconomyDriven_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetFactoryTycoon_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetIntelBuildingTycoon_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSuperWeaponTendency_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetFavouriteStructures_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetAirUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetTankUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetBotUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSeaUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSpecialtyForcesEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSupportUnitsEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetDirectDamageEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetInDirectDamageEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetFavouriteUnits_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetSurvivalEmphasis_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetTeamSupport_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetFormationUse_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetTargetSpread_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetQuittingTendency_LuaFuncDef();
  CScrLuaInitForm* func_CAiPersonalityGetChatFrequency_LuaFuncDef();

  /**
   * Address: 0x00BCD730 (FUN_00BCD730)
   *
   * What it does:
   * Saves current `sim` Lua-init form chain head and relinks it to the
   * recovered AI-personality startup anchor lane (`off_F5997C`).
   */
  CScrLuaInitForm* register_sim_SimInits_mForms_aiPersonalityStartupAnchor();

  /**
   * Address: 0x00BCD750 (FUN_00BCD750, j_func_CAiPersonalityGetPersonalityName_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetPersonalityName_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetPersonalityName_LuaFuncDef();

  /**
   * Address: 0x00BCD760 (FUN_00BCD760, register_CAiPersonalityGetChatPersonality_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetChatPersonality_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetChatPersonality_LuaFuncDef();

  /**
   * Address: 0x00BCD770 (FUN_00BCD770, j_func_CAiPersonalityGetDifficulty_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetDifficulty_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetDifficulty_LuaFuncDef();

  /**
   * Address: 0x00BCD780 (FUN_00BCD780, register_CAiPersonalityAdjustDelay_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityAdjustDelay_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityAdjustDelay_LuaFuncDef();

  /**
   * Address: 0x00BCD790 (FUN_00BCD790, register_CAiPersonalityGetArmySize_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetArmySize_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetArmySize_LuaFuncDef();

  /**
   * Address: 0x00BCD7A0 (FUN_00BCD7A0, j_func_CAiPersonalityGetPlatoonSize_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetPlatoonSize_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetPlatoonSize_LuaFuncDef();

  /**
   * Address: 0x00BCD7B0 (FUN_00BCD7B0, j_func_CAiPersonalityGetAttackFrequency_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetAttackFrequency_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetAttackFrequency_LuaFuncDef();

  /**
   * Address: 0x00BCD7C0 (FUN_00BCD7C0, j_func_CAiPersonalityGetRepeatAttackFrequency_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetRepeatAttackFrequency_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetRepeatAttackFrequency_LuaFuncDef();

  /**
   * Address: 0x00BCD7D0 (FUN_00BCD7D0, j_func_CAiPersonalityGetCounterForces_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetCounterForces_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetCounterForces_LuaFuncDef();

  /**
   * Address: 0x00BCD7E0 (FUN_00BCD7E0, register_CAiPersonalityGetIntelGathering_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetIntelGathering_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetIntelGathering_LuaFuncDef();

  /**
   * Address: 0x00BCD7F0 (FUN_00BCD7F0, register_CAiPersonalityGetCoordinatedAttacks_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetCoordinatedAttacks_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetCoordinatedAttacks_LuaFuncDef();

  /**
   * Address: 0x00BCD800 (FUN_00BCD800, j_func_CAiPersonalityGetExpansionDriven_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetExpansionDriven_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetExpansionDriven_LuaFuncDef();

  /**
   * Address: 0x00BCD810 (FUN_00BCD810, j_func_CAiPersonalityGetTechAdvancement_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetTechAdvancement_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetTechAdvancement_LuaFuncDef();

  /**
   * Address: 0x00BCD820 (FUN_00BCD820, register_CAiPersonalityGetUpgradesDriven_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetUpgradesDriven_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetUpgradesDriven_LuaFuncDef();

  /**
   * Address: 0x00BCD830 (FUN_00BCD830, j_func_CAiPersonalityGetDefenseDriven_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetDefenseDriven_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetDefenseDriven_LuaFuncDef();

  /**
   * Address: 0x00BCD840 (FUN_00BCD840, j_func_CAiPersonalityGetEconomyDriven_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetEconomyDriven_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetEconomyDriven_LuaFuncDef();

  /**
   * Address: 0x00BCD850 (FUN_00BCD850, register_CAiPersonalityGetFactoryTycoon_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetFactoryTycoon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetFactoryTycoon_LuaFuncDef();

  /**
   * Address: 0x00BCD860 (FUN_00BCD860, j_func_CAiPersonalityGetIntelBuildingTycoon_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetIntelBuildingTycoon_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetIntelBuildingTycoon_LuaFuncDef();

  /**
   * Address: 0x00BCD870 (FUN_00BCD870, j_func_CAiPersonalityGetSuperWeaponTendency_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetSuperWeaponTendency_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetSuperWeaponTendency_LuaFuncDef();

  /**
   * Address: 0x00BCD880 (FUN_00BCD880, j_func_CAiPersonalityGetFavouriteStructures_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetFavouriteStructures_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetFavouriteStructures_LuaFuncDef();

  /**
   * Address: 0x00BCD890 (FUN_00BCD890, j_func_CAiPersonalityGetAirUnitsEmphasis_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetAirUnitsEmphasis_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetAirUnitsEmphasis_LuaFuncDef();

  /**
   * Address: 0x00BCD8A0 (FUN_00BCD8A0, j_func_CAiPersonalityGetTankUnitsEmphasis_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetTankUnitsEmphasis_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetTankUnitsEmphasis_LuaFuncDef();

  /**
   * Address: 0x00BCD8B0 (FUN_00BCD8B0, register_CAiPersonalityGetBotUnitsEmphasis_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetBotUnitsEmphasis_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetBotUnitsEmphasis_LuaFuncDef();

  /**
   * Address: 0x00BCD8C0 (FUN_00BCD8C0, j_func_CAiPersonalityGetSeaUnitsEmphasis_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetSeaUnitsEmphasis_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetSeaUnitsEmphasis_LuaFuncDef();

  /**
   * Address: 0x00BCD8D0 (FUN_00BCD8D0, j_func_CAiPersonalityGetSpecialtyForcesEmphasis_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetSpecialtyForcesEmphasis_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetSpecialtyForcesEmphasis_LuaFuncDef();

  /**
   * Address: 0x00BCD8E0 (FUN_00BCD8E0, register_CAiPersonalityGetSupportUnitsEmphasis_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetSupportUnitsEmphasis_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetSupportUnitsEmphasis_LuaFuncDef();

  /**
   * Address: 0x00BCD8F0 (FUN_00BCD8F0, j_func_CAiPersonalityGetDirectDamageEmphasis_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetDirectDamageEmphasis_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetDirectDamageEmphasis_LuaFuncDef();

  /**
   * Address: 0x00BCD900 (FUN_00BCD900, register_CAiPersonalityGetInDirectDamageEmphasis_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetInDirectDamageEmphasis_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetInDirectDamageEmphasis_LuaFuncDef();

  /**
   * Address: 0x00BCD910 (FUN_00BCD910, register_CAiPersonalityGetFavouriteUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetFavouriteUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetFavouriteUnits_LuaFuncDef();

  /**
   * Address: 0x00BCD920 (FUN_00BCD920, j_func_CAiPersonalityGetSurvivalEmphasis_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetSurvivalEmphasis_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetSurvivalEmphasis_LuaFuncDef();

  /**
   * Address: 0x00BCD930 (FUN_00BCD930, j_func_CAiPersonalityGetTeamSupport_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetTeamSupport_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetTeamSupport_LuaFuncDef();

  /**
   * Address: 0x00BCD940 (FUN_00BCD940, register_CAiPersonalityGetFormationUse_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetFormationUse_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetFormationUse_LuaFuncDef();

  /**
   * Address: 0x00BCD950 (FUN_00BCD950, j_func_CAiPersonalityGetTargetSpread_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetTargetSpread_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CAiPersonalityGetTargetSpread_LuaFuncDef();

  /**
   * Address: 0x00BCD960 (FUN_00BCD960, register_CAiPersonalityGetQuittingTendency_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetQuittingTendency_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetQuittingTendency_LuaFuncDef();

  /**
   * Address: 0x00BCD970 (FUN_00BCD970, register_CAiPersonalityGetChatFrequency_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CAiPersonalityGetChatFrequency_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CAiPersonalityGetChatFrequency_LuaFuncDef();
} // namespace moho
