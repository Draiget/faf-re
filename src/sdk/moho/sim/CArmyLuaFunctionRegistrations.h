#pragma once

#include <cstdint>

#include "legacy/containers/String.h"

namespace moho
{
  class CScrLuaInitForm;

  /**
   * Address: 0x005068B0 (FUN_005068B0, ?GetPlayerColor@Moho@@YAIH@Z)
   *
   * int idx
   *
   * What it does:
   * Resolves one configured player color entry by index and decodes it into
   * packed ARGB.
   */
  std::uint32_t GetPlayerColor(int idx);

  /**
   * Address: 0x00506970 (FUN_00506970, ?GetArmyColor@Moho@@YAIH@Z)
   *
   * int idx
   *
   * What it does:
   * Resolves one configured army color entry by index and decodes it into
   * packed ARGB.
   */
  std::uint32_t GetArmyColor(int idx);

  /**
   * Address: 0x00506A30 (FUN_00506A30, ?GetPlayerColorName@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@H@Z)
   *
   * int idx
   *
   * What it does:
   * Returns one player-color token string from the game color table.
   */
  msvc8::string GetPlayerColorName(int idx);

  /**
   * Address: 0x00506B20 (FUN_00506B20, ?GetPlayerColorCount@Moho@@YAIXZ)
   *
   * What it does:
   * Returns the number of configured player colors.
   */
  std::uint32_t GetPlayerColorCount();

  /**
   * Address: 0x00506BB0 (FUN_00506BB0, ?GetCivilianArmyColor@Moho@@YAIXZ)
   *
   * What it does:
   * Decodes the configured civilian army color token into packed ARGB.
   */
  std::uint32_t GetCivilianArmyColor();

  /**
   * Address: 0x00506C40 (FUN_00506C40, ?GetUnidentifiedColor@Moho@@YAIXZ)
   *
   * What it does:
   * Decodes the configured unidentified color token into packed ARGB.
   */
  std::uint32_t GetUnidentifiedColor();

  /**
   * Address: 0x00506CD0 (FUN_00506CD0, func_GetColorIndex)
   *
   * int packedColor
   *
   * What it does:
   * Scans the configured army-color table and returns the first index whose
   * decoded color matches `packedColor`; defaults to `3` when not found.
   */
  int func_GetColorIndex(int packedColor);

  // Underlying Lua function-definition publishers referenced by this thunk pack.
  CScrLuaInitForm* func_ListArmies_LuaFuncDef();
  CScrLuaInitForm* func_GetArmyBrain_LuaFuncDef();
  CScrLuaInitForm* func_SetArmyStart_LuaFuncDef();
  CScrLuaInitForm* func_GenerateArmyStart_LuaFuncDef();
  CScrLuaInitForm* func_SetArmyPlans_LuaFuncDef();
  CScrLuaInitForm* func_InitializeArmyAI_LuaFuncDef();
  CScrLuaInitForm* func_ArmyInitializePrebuiltUnits_LuaFuncDef();
  CScrLuaInitForm* func_ArmyGetHandicap_LuaFuncDef();
  CScrLuaInitForm* func_SetArmyEconomy_LuaFuncDef();
  CScrLuaInitForm* func_GetArmyUnitCostTotal_LuaFuncDef();
  CScrLuaInitForm* func_GetArmyUnitCap_LuaFuncDef();
  CScrLuaInitForm* func_SetArmyUnitCap_LuaFuncDef();
  CScrLuaInitForm* func_SetIgnoreArmyUnitCap_LuaFuncDef();
  CScrLuaInitForm* func_SetIgnorePlayableRect_LuaFuncDef();

  /**
   * Address: 0x007092E0 (FUN_007092E0, func_CreateInitialArmyUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `CreateInitialArmyUnit`.
   */
  CScrLuaInitForm* func_CreateInitialArmyUnit_LuaFuncDef();
  CScrLuaInitForm* func_SetAlliance_LuaFuncDef();
  CScrLuaInitForm* func_SetAllianceOneWay_LuaFuncDef();
  CScrLuaInitForm* func_SetAlliedVictory_LuaFuncDef();

  /**
   * Address: 0x007099E0 (FUN_007099E0, func_IsAllySim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsAlly`.
   */
  CScrLuaInitForm* func_IsAllySim_LuaFuncDef();

  /**
   * Address: 0x00709B10 (FUN_00709B10, func_IsEnemySim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsEnemy`.
   */
  CScrLuaInitForm* func_IsEnemySim_LuaFuncDef();

  /**
   * Address: 0x00709C40 (FUN_00709C40, func_IsNeutralSim_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `IsNeutral`.
   */
  CScrLuaInitForm* func_IsNeutralSim_LuaFuncDef();

  /**
   * Address: 0x00709D70 (FUN_00709D70, func_ArmyIsCivilian_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ArmyIsCivilian`.
   */
  CScrLuaInitForm* func_ArmyIsCivilian_LuaFuncDef();

  /**
   * Address: 0x00709E70 (FUN_00709E70, func_SetArmyColorIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyColorIndex`.
   */
  CScrLuaInitForm* func_SetArmyColorIndex_LuaFuncDef();

  /**
   * Address: 0x00709FD0 (FUN_00709FD0, func_SetArmyFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyFactionIndex`.
   */
  CScrLuaInitForm* func_SetArmyFactionIndex_LuaFuncDef();
  CScrLuaInitForm* func_SetArmyAIPersonality_LuaFuncDef();
  CScrLuaInitForm* func_SetArmyColor_LuaFuncDef();
  CScrLuaInitForm* func_SetArmyShowScore_LuaFuncDef();

  /**
   * Address: 0x0070A700 (FUN_0070A700, func_AddBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `AddBuildRestriction`.
   */
  CScrLuaInitForm* func_AddBuildRestriction_LuaFuncDef();

  /**
   * Address: 0x0070A820 (FUN_0070A820, func_RemoveBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `RemoveBuildRestriction`.
   */
  CScrLuaInitForm* func_RemoveBuildRestriction_LuaFuncDef();

  /**
   * Address: 0x0070A940 (FUN_0070A940, func_OkayToMessWithArmy_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `OkayToMessWithArmy`.
   */
  CScrLuaInitForm* func_OkayToMessWithArmy_LuaFuncDef();

  /**
   * Address: 0x0070AA80 (FUN_0070AA80, func_ArmyIsOutOfGame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `ArmyIsOutOfGame`.
   */
  CScrLuaInitForm* func_ArmyIsOutOfGame_LuaFuncDef();

  /**
   * Address: 0x0070AB80 (FUN_0070AB80, func_SetArmyOutOfGame_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `SetArmyOutOfGame`.
   */
  CScrLuaInitForm* func_SetArmyOutOfGame_LuaFuncDef();

  /**
   * Address: 0x00BD9EA0 (FUN_00BD9EA0, register_SetArmyColor_ConAliasDef)
   *
   * What it does:
   * Registers the `SetArmyColor` console alias that dispatches
   * into sim command handling.
   */
  void register_SetArmyColor_ConAliasDef();

  /**
   * Address: 0x00BD9ED0 (FUN_00BD9ED0, register_SetArmyColor_SimConFuncDef)
   *
   * What it does:
   * Registers the `SetArmyColor` sim-console command callback.
   */
  void register_SetArmyColor_SimConFuncDef();

  /**
   * Address: 0x00BD9D00 (FUN_00BD9D00, j_func_ListArmies_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_ListArmies_LuaFuncDef` to `func_ListArmies_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_ListArmies_LuaFuncDef();

  /**
   * Address: 0x00BD9D10 (FUN_00BD9D10, register_GetArmyBrain_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_GetArmyBrain_LuaFuncDef` to `func_GetArmyBrain_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetArmyBrain_LuaFuncDef();

  /**
   * Address: 0x00BD9D20 (FUN_00BD9D20, j_func_SetArmyStart_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyStart_LuaFuncDef` to `func_SetArmyStart_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyStart_LuaFuncDef();

  /**
   * Address: 0x00BD9D30 (FUN_00BD9D30, register_GenerateArmyStart_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_GenerateArmyStart_LuaFuncDef` to `func_GenerateArmyStart_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GenerateArmyStart_LuaFuncDef();

  /**
   * Address: 0x00BD9D40 (FUN_00BD9D40, register_SetArmyPlans_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyPlans_LuaFuncDef` to `func_SetArmyPlans_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyPlans_LuaFuncDef();

  /**
   * Address: 0x00BD9D50 (FUN_00BD9D50, register_InitializeArmyAI_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_InitializeArmyAI_LuaFuncDef` to `func_InitializeArmyAI_LuaFuncDef`.
   */
  CScrLuaInitForm* register_InitializeArmyAI_LuaFuncDef();

  /**
   * Address: 0x00BD9D60 (FUN_00BD9D60, register_ArmyInitializePrebuiltUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_ArmyInitializePrebuiltUnits_LuaFuncDef` to `func_ArmyInitializePrebuiltUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ArmyInitializePrebuiltUnits_LuaFuncDef();

  /**
   * Address: 0x00BD9D70 (FUN_00BD9D70, register_ArmyGetHandicap_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_ArmyGetHandicap_LuaFuncDef` to `func_ArmyGetHandicap_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ArmyGetHandicap_LuaFuncDef();

  /**
   * Address: 0x00BD9D80 (FUN_00BD9D80, j_func_SetArmyEconomy_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyEconomy_LuaFuncDef` to `func_SetArmyEconomy_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyEconomy_LuaFuncDef();

  /**
   * Address: 0x00BD9D90 (FUN_00BD9D90, j_func_GetArmyUnitCostTotal_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_GetArmyUnitCostTotal_LuaFuncDef` to `func_GetArmyUnitCostTotal_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_GetArmyUnitCostTotal_LuaFuncDef();

  /**
   * Address: 0x00BD9DA0 (FUN_00BD9DA0, register_GetArmyUnitCap_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_GetArmyUnitCap_LuaFuncDef` to `func_GetArmyUnitCap_LuaFuncDef`.
   */
  CScrLuaInitForm* register_GetArmyUnitCap_LuaFuncDef();

  /**
   * Address: 0x00BD9DB0 (FUN_00BD9DB0, register_SetArmyUnitCap_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyUnitCap_LuaFuncDef` to `func_SetArmyUnitCap_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyUnitCap_LuaFuncDef();

  /**
   * Address: 0x00BD9DC0 (FUN_00BD9DC0, register_SetIgnoreArmyUnitCap_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetIgnoreArmyUnitCap_LuaFuncDef` to `func_SetIgnoreArmyUnitCap_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetIgnoreArmyUnitCap_LuaFuncDef();

  /**
   * Address: 0x00BD9DD0 (FUN_00BD9DD0, j_func_SetIgnorePlayableRect_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetIgnorePlayableRect_LuaFuncDef` to `func_SetIgnorePlayableRect_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetIgnorePlayableRect_LuaFuncDef();

  /**
   * Address: 0x00BD9DE0 (FUN_00BD9DE0, register_CreateInitialArmyUnit_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_CreateInitialArmyUnit_LuaFuncDef` to `func_CreateInitialArmyUnit_LuaFuncDef`.
   */
  CScrLuaInitForm* register_CreateInitialArmyUnit_LuaFuncDef();

  /**
   * Address: 0x00BD9DF0 (FUN_00BD9DF0, register_SetAlliance_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetAlliance_LuaFuncDef` to `func_SetAlliance_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetAlliance_LuaFuncDef();

  /**
   * Address: 0x00BD9E00 (FUN_00BD9E00, register_SetAllianceOneWay_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetAllianceOneWay_LuaFuncDef` to `func_SetAllianceOneWay_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetAllianceOneWay_LuaFuncDef();

  /**
   * Address: 0x00BD9E10 (FUN_00BD9E10, j_func_SetAlliedVictory_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetAlliedVictory_LuaFuncDef` to `func_SetAlliedVictory_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetAlliedVictory_LuaFuncDef();

  /**
   * Address: 0x00BD9E20 (FUN_00BD9E20, j_func_IsAllySim_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IsAllySim_LuaFuncDef` to `func_IsAllySim_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IsAllySim_LuaFuncDef();

  /**
   * Address: 0x00BD9E30 (FUN_00BD9E30, register_IsEnemySim_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IsEnemySim_LuaFuncDef` to `func_IsEnemySim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IsEnemySim_LuaFuncDef();

  /**
   * Address: 0x00BD9E40 (FUN_00BD9E40, register_IsNeutralSim_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IsNeutralSim_LuaFuncDef` to `func_IsNeutralSim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IsNeutralSim_LuaFuncDef();

  /**
   * Address: 0x00BD9E50 (FUN_00BD9E50, j_func_ArmyIsCivilian_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_ArmyIsCivilian_LuaFuncDef` to `func_ArmyIsCivilian_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_ArmyIsCivilian_LuaFuncDef();

  /**
   * Address: 0x00BD9E60 (FUN_00BD9E60, j_func_SetArmyColorIndex_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyColorIndex_LuaFuncDef` to `func_SetArmyColorIndex_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyColorIndex_LuaFuncDef();

  /**
   * Address: 0x00BD9E70 (FUN_00BD9E70, register_SetArmyFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyFactionIndex_LuaFuncDef` to `func_SetArmyFactionIndex_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyFactionIndex_LuaFuncDef();

  /**
   * Address: 0x00BD9E80 (FUN_00BD9E80, j_func_SetArmyAIPersonality_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyAIPersonality_LuaFuncDef` to `func_SetArmyAIPersonality_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyAIPersonality_LuaFuncDef();

  /**
   * Address: 0x00BD9E90 (FUN_00BD9E90, register_SetArmyColor_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyColor_LuaFuncDef` to `func_SetArmyColor_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyColor_LuaFuncDef();

  /**
   * Address: 0x00BD9F10 (FUN_00BD9F10, j_func_SetArmyShowScore_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_SetArmyShowScore_LuaFuncDef` to `func_SetArmyShowScore_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_SetArmyShowScore_LuaFuncDef();

  /**
   * Address: 0x00BD9F20 (FUN_00BD9F20, register_AddBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_AddBuildRestriction_LuaFuncDef` to `func_AddBuildRestriction_LuaFuncDef`.
   */
  CScrLuaInitForm* register_AddBuildRestriction_LuaFuncDef();

  /**
   * Address: 0x00BD9F30 (FUN_00BD9F30, register_RemoveBuildRestriction_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_RemoveBuildRestriction_LuaFuncDef` to `func_RemoveBuildRestriction_LuaFuncDef`.
   */
  CScrLuaInitForm* register_RemoveBuildRestriction_LuaFuncDef();

  /**
   * Address: 0x00BD9F40 (FUN_00BD9F40, j_func_OkayToMessWithArmy_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_OkayToMessWithArmy_LuaFuncDef` to `func_OkayToMessWithArmy_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_OkayToMessWithArmy_LuaFuncDef();

  /**
   * Address: 0x00BD9F50 (FUN_00BD9F50, register_ArmyIsOutOfGame_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_ArmyIsOutOfGame_LuaFuncDef` to `func_ArmyIsOutOfGame_LuaFuncDef`.
   */
  CScrLuaInitForm* register_ArmyIsOutOfGame_LuaFuncDef();

  /**
   * Address: 0x00BD9F60 (FUN_00BD9F60, register_SetArmyOutOfGame_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_SetArmyOutOfGame_LuaFuncDef` to `func_SetArmyOutOfGame_LuaFuncDef`.
   */
  CScrLuaInitForm* register_SetArmyOutOfGame_LuaFuncDef();

} // namespace moho
