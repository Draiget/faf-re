#pragma once

namespace moho
{
  class CScrLuaInitForm;

  // Underlying Lua function-definition publishers referenced by this thunk pack.
  CScrLuaInitForm* func_IsCommandDone_LuaFuncDef();
  CScrLuaInitForm* func_IssueClearCommands_LuaFuncDef();
  CScrLuaInitForm* func_IssueStop_LuaFuncDef();
  CScrLuaInitForm* func_IssuePause_LuaFuncDef();
  CScrLuaInitForm* func_IssueOverCharge_LuaFuncDef();
  CScrLuaInitForm* func_IssueDive_LuaFuncDef();
  CScrLuaInitForm* func_IssueFactoryRallyPoint_LuaFuncDef();
  CScrLuaInitForm* func_IssueClearFactoryCommands_LuaFuncDef();
  CScrLuaInitForm* func_IssueMove_LuaFuncDef();
  CScrLuaInitForm* func_IssueMoveOffFactory_LuaFuncDef();
  CScrLuaInitForm* func_IssueFormMove_LuaFuncDef();
  CScrLuaInitForm* func_IssueGuard_LuaFuncDef();
  CScrLuaInitForm* func_IssueFactoryAssist_LuaFuncDef();
  CScrLuaInitForm* func_IssueAttack_LuaFuncDef();
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
