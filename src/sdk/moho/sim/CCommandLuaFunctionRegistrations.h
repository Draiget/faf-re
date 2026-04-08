#pragma once

namespace LuaPlus
{
  class LuaState;
}
struct lua_State;

namespace moho
{
  class CScrLuaInitForm;

  // Underlying Lua function-definition publishers referenced by this thunk pack.
  /**
   * Address: 0x006F17D0 (FUN_006F17D0, func_IsCommandDone_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IsCommandDone`.
   */
  CScrLuaInitForm* func_IsCommandDone_LuaFuncDef();
  /**
   * Address: 0x006F1900 (FUN_006F1900, func_IssueClearCommands_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueClearCommands`.
   */
  CScrLuaInitForm* func_IssueClearCommands_LuaFuncDef();
  /**
   * Address: 0x006F1A60 (FUN_006F1A60, func_IssueStop_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueStop`.
   */
  CScrLuaInitForm* func_IssueStop_LuaFuncDef();
  /**
   * Address: 0x006F1C00 (FUN_006F1C00, func_IssuePause_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssuePause`.
   */
  CScrLuaInitForm* func_IssuePause_LuaFuncDef();
  /**
   * Address: 0x006F1DA0 (FUN_006F1DA0, func_IssueOverCharge_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueOverCharge`.
   */
  CScrLuaInitForm* func_IssueOverCharge_LuaFuncDef();
  /**
   * Address: 0x006F2050 (FUN_006F2050, func_IssueDive_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueDive`.
   */
  CScrLuaInitForm* func_IssueDive_LuaFuncDef();
  /**
   * Address: 0x006F2270 (FUN_006F2270, func_IssueFactoryRallyPoint_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueFactoryRallyPoint`.
   */
  CScrLuaInitForm* func_IssueFactoryRallyPoint_LuaFuncDef();
  /**
   * Address: 0x006F2530 (FUN_006F2530, func_IssueClearFactoryCommands_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueClearFactoryCommands`.
   */
  CScrLuaInitForm* func_IssueClearFactoryCommands_LuaFuncDef();
  /**
   * Address: 0x00836920 (FUN_00836920, func_DecreaseBuildCountInQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `DecreaseBuildCountInQueue(queueIndex, count)`.
   */
  CScrLuaInitForm* func_DecreaseBuildCountInQueue_LuaFuncDef();

  /**
   * Address: 0x008400D0 (FUN_008400D0, func_GetUnitCommandData_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `GetUnitCommandData(unitSet)` returning
   * order/build category unions for the selected units.
   */
  CScrLuaInitForm* func_GetUnitCommandData_LuaFuncDef();

  /**
   * Address: 0x00840A10 (FUN_00840A10, func_IssueDockCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueDockCommand(clear)`.
   */
  CScrLuaInitForm* func_IssueDockCommand_LuaFuncDef();

  /**
   * Address: 0x00841550 (FUN_00841550, func_IssueCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueCommand(command,[string],[clear])`.
   */
  CScrLuaInitForm* func_IssueCommand_LuaFuncDef();
  /**
   * Address: 0x00841860 (FUN_00841860, func_IssueUnitCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueUnitCommand(unitList,command,[string],[clear])`.
   */
  CScrLuaInitForm* func_IssueUnitCommand_LuaFuncDef();

  /**
   * Address: 0x00841BB0 (FUN_00841BB0, func_IssueBlueprintCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueBlueprintCommand(command, blueprintid, count, clear = false)`.
   */
  CScrLuaInitForm* func_IssueBlueprintCommand_LuaFuncDef();

  /**
   * Address: 0x008428C0 (FUN_008428C0, func_GetRolloverInfo_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `GetRolloverInfo()`.
   */
  CScrLuaInitForm* func_GetRolloverInfo_LuaFuncDef();

  /**
   * Address: 0x00846B80 (FUN_00846B80, func_SetOverlayFilter_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `SetOverlayFilter()`.
   */
  CScrLuaInitForm* func_SetOverlayFilter_LuaFuncDef();

  /**
   * Address: 0x00847290 (FUN_00847290, func_GetActiveBuildTemplate_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `GetActiveBuildTemplate()`.
   */
  CScrLuaInitForm* func_GetActiveBuildTemplate_LuaFuncDef();

  /**
   * Address: 0x00847580 (FUN_00847580, func_SetActiveBuildTemplate_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `SetActiveBuildTemplate()`.
   */
  CScrLuaInitForm* func_SetActiveBuildTemplate_LuaFuncDef();

  /**
   * Address: 0x00847FF0 (FUN_00847FF0, func_OpenURL_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `OpenURL(string)`.
   */
  CScrLuaInitForm* func_OpenURL_LuaFuncDef();

  /**
   * Address: 0x0084DCA0 (FUN_0084DCA0, func_SetCursor_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `SetCursor(cursor)`.
   */
  CScrLuaInitForm* func_SetCursor_LuaFuncDef();

  CScrLuaInitForm* func_IssueMove_LuaFuncDef();
  CScrLuaInitForm* func_IssueMoveOffFactory_LuaFuncDef();
  CScrLuaInitForm* func_IssueFormMove_LuaFuncDef();
  CScrLuaInitForm* func_IssueGuard_LuaFuncDef();
  CScrLuaInitForm* func_IssueFactoryAssist_LuaFuncDef();
  CScrLuaInitForm* func_IssueAttack_LuaFuncDef();
  /**
   * Address: 0x006F3930 (FUN_006F3930, func_CoordinateAttacks_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `CoordinateAttacks(commandList)`.
   */
  CScrLuaInitForm* func_CoordinateAttacks_LuaFuncDef();
  CScrLuaInitForm* func_IssueFormAttack_LuaFuncDef();
  CScrLuaInitForm* func_IssueSiloBuildTactical_LuaFuncDef();
  CScrLuaInitForm* func_IssueSiloBuildNuke_LuaFuncDef();
  CScrLuaInitForm* func_IssueNuke_LuaFuncDef();
  CScrLuaInitForm* func_IssueTactical_LuaFuncDef();
  CScrLuaInitForm* func_IssueTeleport_LuaFuncDef();
  CScrLuaInitForm* func_IssuePatrol_LuaFuncDef();
  CScrLuaInitForm* func_IssueFormPatrol_LuaFuncDef();
  CScrLuaInitForm* func_IssueAggressiveMove_LuaFuncDef();
  CScrLuaInitForm* func_IssueFormAggressiveMove_LuaFuncDef();
  CScrLuaInitForm* func_IssueFerry_LuaFuncDef();
  CScrLuaInitForm* func_IssueBuildMobile_LuaFuncDef();
  CScrLuaInitForm* func_IssueRepair_LuaFuncDef();
  CScrLuaInitForm* func_IssueSacrifice_LuaFuncDef();
  CScrLuaInitForm* func_IssueUpgrade_LuaFuncDef();
  CScrLuaInitForm* func_IssueScript_LuaFuncDef();
  CScrLuaInitForm* func_IssueReclaim_LuaFuncDef();
  CScrLuaInitForm* func_IssueCapture_LuaFuncDef();
  CScrLuaInitForm* func_IssueKillSelf_LuaFuncDef();
  CScrLuaInitForm* func_IssueDestroySelf_LuaFuncDef();
  CScrLuaInitForm* func_IssueTransportLoad_LuaFuncDef();
  CScrLuaInitForm* func_IssueTransportUnload_LuaFuncDef();
  CScrLuaInitForm* func_IssueTeleportToBeacon_LuaFuncDef();
  CScrLuaInitForm* func_IssueTransportUnloadSpecific_LuaFuncDef();
  CScrLuaInitForm* func_IssueBuildFactory_LuaFuncDef();

  /**
   * Address: 0x006F17B0 (FUN_006F17B0, cfunc_IsCommandDone)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IsCommandDoneL`.
   */
  int cfunc_IsCommandDone(lua_State* luaContext);

  /**
   * Address: 0x006F1820 (FUN_006F1820, cfunc_IsCommandDoneL)
   *
   * What it does:
   * Resolves one optional command handle and returns true when command is
   * null/expired.
   */
  int cfunc_IsCommandDoneL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006F18E0 (FUN_006F18E0, cfunc_IssueClearCommands)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueClearCommandsL`.
   */
  int cfunc_IssueClearCommands(lua_State* luaContext);

  /**
   * Address: 0x006F1950 (FUN_006F1950, cfunc_IssueClearCommandsL)
   *
   * What it does:
   * Clears command queues for one unit-table argument and stops active
   * attacker state per unit.
   */
  int cfunc_IssueClearCommandsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006F1A40 (FUN_006F1A40, cfunc_IssueStop)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueStopL`.
   */
  int cfunc_IssueStop(lua_State* luaContext);

  /**
   * Address: 0x006F1AB0 (FUN_006F1AB0, cfunc_IssueStopL)
   *
   * What it does:
   * Parses one unit-list argument and issues `UNITCOMMAND_Stop` through the
   * sim command sink.
   */
  int cfunc_IssueStopL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006F1BE0 (FUN_006F1BE0, cfunc_IssuePause)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssuePauseL`.
   */
  int cfunc_IssuePause(lua_State* luaContext);

  /**
   * Address: 0x006F1C50 (FUN_006F1C50, cfunc_IssuePauseL)
   *
   * What it does:
   * Parses one unit-list argument and issues `UNITCOMMAND_Pause` through the
   * sim command sink.
   */
  int cfunc_IssuePauseL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00836900 (FUN_00836900, cfunc_DecreaseBuildCountInQueue)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_DecreaseBuildCountInQueueL`.
   */
  int cfunc_DecreaseBuildCountInQueue(lua_State* luaContext);

  /**
   * Address: 0x008400B0 (FUN_008400B0, cfunc_GetUnitCommandData)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_GetUnitCommandDataL`.
   */
  int cfunc_GetUnitCommandData(lua_State* luaContext);

  /**
   * Address: 0x008409F0 (FUN_008409F0, cfunc_IssueDockCommand)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueDockCommandL`.
   */
  int cfunc_IssueDockCommand(lua_State* luaContext);

  /**
   * Address: 0x00841530 (FUN_00841530, cfunc_IssueCommand)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueCommandL`.
   */
  int cfunc_IssueCommand(lua_State* luaContext);

  /**
   * Address: 0x00841840 (FUN_00841840, cfunc_IssueUnitCommand)
   *
   * What it does:
   * Lua callback target for `func_IssueUnitCommand_LuaFuncDef`.
   */
  int cfunc_IssueUnitCommand(lua_State* luaContext);

  /**
   * Address: 0x00841B90 (FUN_00841B90, cfunc_IssueBlueprintCommand)
   *
   * What it does:
   * Lua callback target for `func_IssueBlueprintCommand_LuaFuncDef`.
   */
  int cfunc_IssueBlueprintCommand(lua_State* luaContext);

  /**
   * Address: 0x008428A0 (FUN_008428A0, cfunc_GetRolloverInfo)
   *
   * What it does:
   * Lua callback target for `func_GetRolloverInfo_LuaFuncDef`.
   */
  int cfunc_GetRolloverInfo(lua_State* luaContext);

  /**
   * Address: 0x00846B60 (FUN_00846B60, cfunc_SetOverlayFilter)
   *
   * What it does:
   * Lua callback target for `func_SetOverlayFilter_LuaFuncDef`.
   */
  int cfunc_SetOverlayFilter(lua_State* luaContext);

  /**
   * Address: 0x00847270 (FUN_00847270, cfunc_GetActiveBuildTemplate)
   *
   * What it does:
   * Lua callback target for `func_GetActiveBuildTemplate_LuaFuncDef`.
   */
  int cfunc_GetActiveBuildTemplate(lua_State* luaContext);

  /**
   * Address: 0x00847560 (FUN_00847560, cfunc_SetActiveBuildTemplate)
   *
   * What it does:
   * Lua callback target for `func_SetActiveBuildTemplate_LuaFuncDef`.
   */
  int cfunc_SetActiveBuildTemplate(lua_State* luaContext);

  /**
   * Address: 0x00847FD0 (FUN_00847FD0, cfunc_OpenURL)
   *
   * What it does:
   * Lua callback target for `func_OpenURL_LuaFuncDef`.
   */
  int cfunc_OpenURL(lua_State* luaContext);

  /**
   * Address: 0x0084DC80 (FUN_0084DC80, cfunc_SetCursor)
   *
   * What it does:
   * Lua callback target for `func_SetCursor_LuaFuncDef`.
   */
  int cfunc_SetCursor(lua_State* luaContext);

  /**
   * Address: 0x0084DD00 (FUN_0084DD00, cfunc_SetCursorL)
   *
   * What it does:
   * Resolves one optional cursor userdata argument and updates
   * `UI_Manager` cursor binding.
   */
  int cfunc_SetCursorL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006F2510 (FUN_006F2510, cfunc_IssueClearFactoryCommands)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_IssueClearFactoryCommandsL`.
   */
  int cfunc_IssueClearFactoryCommands(lua_State* luaContext);

  /**
   * Address: 0x006F2580 (FUN_006F2580, cfunc_IssueClearFactoryCommandsL)
   *
   * What it does:
   * Resolves one unit-table argument and clears each live unit's factory queue.
   */
  int cfunc_IssueClearFactoryCommandsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006F3910 (FUN_006F3910, cfunc_CoordinateAttacks)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CoordinateAttacksL`.
   */
  int cfunc_CoordinateAttacks(lua_State* luaContext);

  /**
   * Address: 0x006F3980 (FUN_006F3980, cfunc_CoordinateAttacksL)
   *
   * What it does:
   * Resolves command objects from arg#1 table and links every command pair for
   * coordinated execution.
   */
  int cfunc_CoordinateAttacksL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006F3F40 (FUN_006F3F40, cfunc_IssueSiloBuildTactical)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueSiloBuildTacticalL`.
   */
  int cfunc_IssueSiloBuildTactical(lua_State* luaContext);

  /**
   * Address: 0x006F3FB0 (FUN_006F3FB0, cfunc_IssueSiloBuildTacticalL)
   *
   * What it does:
   * Resolves one unit-table argument and queues tactical silo build on each
   * live unit with a silo-build component.
   */
  int cfunc_IssueSiloBuildTacticalL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006F40A0 (FUN_006F40A0, cfunc_IssueSiloBuildNuke)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueSiloBuildNukeL`.
   */
  int cfunc_IssueSiloBuildNuke(lua_State* luaContext);

  /**
   * Address: 0x006F4110 (FUN_006F4110, cfunc_IssueSiloBuildNukeL)
   *
   * What it does:
   * Resolves one unit-table argument and queues nuke silo build on each live
   * unit with a silo-build component.
   */
  int cfunc_IssueSiloBuildNukeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00BD9350 (FUN_00BD9350, j_func_IsCommandDone_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IsCommandDone_LuaFuncDef` to `func_IsCommandDone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IsCommandDone_LuaFuncDef();

  /**
   * Address: 0x00BD9360 (FUN_00BD9360, register_IssueClearCommands_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueClearCommands_LuaFuncDef` to `func_IssueClearCommands_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueClearCommands_LuaFuncDef();

  /**
   * Address: 0x00BD9370 (FUN_00BD9370, register_IssueStop_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueStop_LuaFuncDef` to `func_IssueStop_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueStop_LuaFuncDef();

  /**
   * Address: 0x00BD9380 (FUN_00BD9380, j_func_IssuePause_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssuePause_LuaFuncDef` to `func_IssuePause_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssuePause_LuaFuncDef();

  /**
   * Address: 0x00BD9390 (FUN_00BD9390, register_IssueOverCharge_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueOverCharge_LuaFuncDef` to `func_IssueOverCharge_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueOverCharge_LuaFuncDef();

  /**
   * Address: 0x00BD93A0 (FUN_00BD93A0, register_IssueDive_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueDive_LuaFuncDef` to `func_IssueDive_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueDive_LuaFuncDef();

  /**
   * Address: 0x00BD93B0 (FUN_00BD93B0, register_IssueFactoryRallyPoint_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFactoryRallyPoint_LuaFuncDef` to `func_IssueFactoryRallyPoint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFactoryRallyPoint_LuaFuncDef();

  /**
   * Address: 0x00BD93C0 (FUN_00BD93C0, register_IssueClearFactoryCommands_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueClearFactoryCommands_LuaFuncDef` to `func_IssueClearFactoryCommands_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueClearFactoryCommands_LuaFuncDef();

  /**
   * Address: 0x00BD93D0 (FUN_00BD93D0, j_func_IssueMove_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueMove_LuaFuncDef` to `func_IssueMove_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueMove_LuaFuncDef();

  /**
   * Address: 0x00BD93E0 (FUN_00BD93E0, j_func_IssueMoveOffFactory_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueMoveOffFactory_LuaFuncDef` to `func_IssueMoveOffFactory_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueMoveOffFactory_LuaFuncDef();

  /**
   * Address: 0x00BD93F0 (FUN_00BD93F0, register_IssueFormMove_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFormMove_LuaFuncDef` to `func_IssueFormMove_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFormMove_LuaFuncDef();

  /**
   * Address: 0x00BD9400 (FUN_00BD9400, j_func_IssueGuard_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueGuard_LuaFuncDef` to `func_IssueGuard_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueGuard_LuaFuncDef();

  /**
   * Address: 0x00BD9410 (FUN_00BD9410, j_func_IssueFactoryAssist_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueFactoryAssist_LuaFuncDef` to `func_IssueFactoryAssist_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueFactoryAssist_LuaFuncDef();

  /**
   * Address: 0x00BD9420 (FUN_00BD9420, register_IssueAttack_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueAttack_LuaFuncDef` to `func_IssueAttack_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueAttack_LuaFuncDef();

  /**
   * Address: 0x00BD9430 (FUN_00BD9430, j_func_CoordinateAttacks_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CoordinateAttacks_LuaFuncDef` to `func_CoordinateAttacks_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CoordinateAttacks_LuaFuncDef();

  /**
   * Address: 0x00BD9440 (FUN_00BD9440, register_IssueFormAttack_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFormAttack_LuaFuncDef` to `func_IssueFormAttack_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFormAttack_LuaFuncDef();

  /**
   * Address: 0x00BD9450 (FUN_00BD9450, register_IssueSiloBuildTactical_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueSiloBuildTactical_LuaFuncDef` to `func_IssueSiloBuildTactical_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueSiloBuildTactical_LuaFuncDef();

  /**
   * Address: 0x00BD9460 (FUN_00BD9460, register_IssueSiloBuildNuke_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueSiloBuildNuke_LuaFuncDef` to `func_IssueSiloBuildNuke_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueSiloBuildNuke_LuaFuncDef();

  /**
   * Address: 0x00BD9470 (FUN_00BD9470, register_IssueNuke_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueNuke_LuaFuncDef` to `func_IssueNuke_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueNuke_LuaFuncDef();

  /**
   * Address: 0x00BD9480 (FUN_00BD9480, register_IssueTactical_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueTactical_LuaFuncDef` to `func_IssueTactical_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueTactical_LuaFuncDef();

  /**
   * Address: 0x00BD9490 (FUN_00BD9490, j_func_IssueTeleport_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueTeleport_LuaFuncDef` to `func_IssueTeleport_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueTeleport_LuaFuncDef();

  /**
   * Address: 0x00BD94A0 (FUN_00BD94A0, register_IssuePatrol_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssuePatrol_LuaFuncDef` to `func_IssuePatrol_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssuePatrol_LuaFuncDef();

  /**
   * Address: 0x00BD94B0 (FUN_00BD94B0, register_IssueFormPatrol_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFormPatrol_LuaFuncDef` to `func_IssueFormPatrol_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFormPatrol_LuaFuncDef();

  /**
   * Address: 0x00BD94C0 (FUN_00BD94C0, j_func_IssueAggressiveMove_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueAggressiveMove_LuaFuncDef` to `func_IssueAggressiveMove_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueAggressiveMove_LuaFuncDef();

  /**
   * Address: 0x00BD94D0 (FUN_00BD94D0, register_IssueFormAggressiveMove_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFormAggressiveMove_LuaFuncDef` to `func_IssueFormAggressiveMove_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFormAggressiveMove_LuaFuncDef();

  /**
   * Address: 0x00BD94E0 (FUN_00BD94E0, register_IssueFerry_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFerry_LuaFuncDef` to `func_IssueFerry_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFerry_LuaFuncDef();

  /**
   * Address: 0x00BD94F0 (FUN_00BD94F0, j_func_IssueBuildMobile_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueBuildMobile_LuaFuncDef` to `func_IssueBuildMobile_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueBuildMobile_LuaFuncDef();

  /**
   * Address: 0x00BD9500 (FUN_00BD9500, register_IssueRepair_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueRepair_LuaFuncDef` to `func_IssueRepair_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueRepair_LuaFuncDef();

  /**
   * Address: 0x00BD9510 (FUN_00BD9510, register_IssueSacrifice_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueSacrifice_LuaFuncDef` to `func_IssueSacrifice_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueSacrifice_LuaFuncDef();

  /**
   * Address: 0x00BD9520 (FUN_00BD9520, register_IssueUpgrade_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueUpgrade_LuaFuncDef` to `func_IssueUpgrade_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueUpgrade_LuaFuncDef();

  /**
   * Address: 0x00BD9530 (FUN_00BD9530, register_IssueScript_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueScript_LuaFuncDef` to `func_IssueScript_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueScript_LuaFuncDef();

  /**
   * Address: 0x00BD9540 (FUN_00BD9540, register_IssueReclaim_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueReclaim_LuaFuncDef` to `func_IssueReclaim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueReclaim_LuaFuncDef();

  /**
   * Address: 0x00BD9550 (FUN_00BD9550, j_func_IssueCapture_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueCapture_LuaFuncDef` to `func_IssueCapture_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueCapture_LuaFuncDef();

  /**
   * Address: 0x00BD9560 (FUN_00BD9560, register_IssueKillSelf_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueKillSelf_LuaFuncDef` to `func_IssueKillSelf_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueKillSelf_LuaFuncDef();

  /**
   * Address: 0x00BD9570 (FUN_00BD9570, register_IssueDestroySelf_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueDestroySelf_LuaFuncDef` to `func_IssueDestroySelf_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueDestroySelf_LuaFuncDef();

  /**
   * Address: 0x00BD9580 (FUN_00BD9580, j_func_IssueTransportLoad_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueTransportLoad_LuaFuncDef` to `func_IssueTransportLoad_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueTransportLoad_LuaFuncDef();

  /**
   * Address: 0x00BD9590 (FUN_00BD9590, register_IssueTransportUnload_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueTransportUnload_LuaFuncDef` to `func_IssueTransportUnload_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueTransportUnload_LuaFuncDef();

  /**
   * Address: 0x00BD95A0 (FUN_00BD95A0, register_IssueTeleportToBeacon_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueTeleportToBeacon_LuaFuncDef` to `func_IssueTeleportToBeacon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueTeleportToBeacon_LuaFuncDef();

  /**
   * Address: 0x00BD95B0 (FUN_00BD95B0, j_func_IssueTransportUnloadSpecific_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueTransportUnloadSpecific_LuaFuncDef` to `func_IssueTransportUnloadSpecific_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueTransportUnloadSpecific_LuaFuncDef();

  /**
   * Address: 0x00BD95C0 (FUN_00BD95C0, register_IssueBuildFactory_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueBuildFactory_LuaFuncDef` to `func_IssueBuildFactory_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueBuildFactory_LuaFuncDef();
} // namespace moho
