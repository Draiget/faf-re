#pragma once

namespace moho
{
  class CScrLuaInitForm;

  // Underlying Lua function-definition publishers referenced by this thunk pack.
  CScrLuaInitForm* func_UnitSetBusy_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetProductionActive_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetConsumptionActive_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetPaused_LuaFuncDef();
  CScrLuaInitForm* func_UnitIsPaused_LuaFuncDef();
  CScrLuaInitForm* func_UnitIsBeingBuilt_LuaFuncDef();
  CScrLuaInitForm* func_UnitIsStunned_LuaFuncDef();
  CScrLuaInitForm* func_UnitIsIdleState_LuaFuncDef();
  CScrLuaInitForm* func_UnitIsUnitState_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetStrategicUnderlay_LuaFuncDef();
  CScrLuaInitForm* func_UnitScaleGetBuiltEmitter_LuaFuncDef();
  CScrLuaInitForm* func_UnitKillManipulators_LuaFuncDef();
  CScrLuaInitForm* func_UnitKillManipulator_LuaFuncDef();
  CScrLuaInitForm* func_UnitEnableManipulators_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetAttacker_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetHealth_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetTargetEntity_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetWeaponCount_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetWeapon_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetFocusUnit_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetFocusEntity_LuaFuncDef();
  CScrLuaInitForm* func_UnitClearFocusEntity_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetArmorMult_LuaFuncDef();
  CScrLuaInitForm* func_UnitAlterArmor_LuaFuncDef();

  /**
   * Address: 0x006C3DA0 (FUN_006C3DA0, func_UnitGetCargo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetCargo()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetCargo_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetCreator_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetUnitId_LuaFuncDef();

  /**
   * Address: 0x006C7D30 (FUN_006C7D30, func_UnitSetFireState_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:SetFireState(stateName)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetFireState_LuaFuncDef();
  CScrLuaInitForm* func_UnitToggleFireState_LuaFuncDef();
  CScrLuaInitForm* func_UnitToggleScriptBit_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetScriptBit_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetScriptBit_LuaFuncDef();
  CScrLuaInitForm* func_UnitCalculateWorldPositionFromRelative_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetNumBuildOrders_LuaFuncDef();
  CScrLuaInitForm* func_UnitIsValidTarget_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetIsValidTarget_LuaFuncDef();
  CScrLuaInitForm* func_UnitStopSiloBuild_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetUnitState_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetDoNotTarget_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetUnSelectable_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetStunned_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetImmobile_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetBlockCommandQueue_LuaFuncDef();

  /**
   * Address: 0x006C9480 (FUN_006C9480, func_UnitSetReclaimable_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetReclaimable(flag)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetReclaimable_LuaFuncDef();
  CScrLuaInitForm* func_UnitRevertRegenRate_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetRegenRate_LuaFuncDef();
  CScrLuaInitForm* func_UnitTestToggleCaps_LuaFuncDef();
  CScrLuaInitForm* func_UnitRestoreToggleCaps_LuaFuncDef();
  CScrLuaInitForm* func_UnitRemoveToggleCap_LuaFuncDef();
  CScrLuaInitForm* func_UnitAddToggleCap_LuaFuncDef();
  CScrLuaInitForm* func_UnitTestCommandCaps_LuaFuncDef();
  CScrLuaInitForm* func_UnitRestoreCommandCaps_LuaFuncDef();
  CScrLuaInitForm* func_UnitRemoveCommandCap_LuaFuncDef();
  CScrLuaInitForm* func_UnitAddCommandCap_LuaFuncDef();
  CScrLuaInitForm* func_UnitRestoreBuildRestrictions_LuaFuncDef();
  CScrLuaInitForm* func_UnitRemoveBuildRestriction_LuaFuncDef();
  CScrLuaInitForm* func_UnitAddBuildRestriction_LuaFuncDef();

  /**
   * Address: 0x008BAD80 (FUN_008BAD80, func_SetAutoMode_LuaFuncDef)
   *
   * What it does:
   * Publishes the global user-Lua binder for `SetAutoMode`.
   */
  CScrLuaInitForm* func_UnitSetAutoMode_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetFireState_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetElevation_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetResourceConsumed_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetProductionPerSecondMass_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetProductionPerSecondEnergy_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetConsumptionPerSecondMass_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetProductionPerSecondMass_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetProductionPerSecondEnergy_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetConsumptionPerSecondMass_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef();
  CScrLuaInitForm* func_UnitGetBuildRate_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetBuildRate_LuaFuncDef();

  /**
   * Address: 0x006C99A0 (FUN_006C99A0, func_UnitIsOverchargePaused_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:IsOverchargePaused()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsOverchargePaused_LuaFuncDef();

  /**
   * Address: 0x006C9860 (FUN_006C9860, func_UnitSetOverchargePaused_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetOverchargePaused(flag)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetOverchargePaused_LuaFuncDef();

  /**
   * Address: 0x006C9720 (FUN_006C9720, func_UnitIsCapturable_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:IsCapturable()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsCapturable_LuaFuncDef();

  /**
   * Address: 0x006C95D0 (FUN_006C95D0, func_UnitSetCapturable_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetCapturable(flag)` Lua binder definition.
  */
  CScrLuaInitForm* func_UnitSetCapturable_LuaFuncDef();

  /**
   * Address: 0x006CC440 (FUN_006CC440, func_UnitGetVelocity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetVelocity() -> x,y,z` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetVelocity_LuaFuncDef();

  /**
   * Address: 0x006CC5C0 (FUN_006CC5C0, func_UnitGetStat_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetStat(name[, defaultValue])` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetStat_LuaFuncDef();

  /**
   * Address: 0x006CC2F0 (FUN_006CC2F0, func_UnitGetNavigator_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetNavigator()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetNavigator_LuaFuncDef();

  /**
   * Address: 0x006CC1A0 (FUN_006CC1A0, func_UnitIsMoving_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:IsMoving()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsMoving_LuaFuncDef();

  /**
   * Address: 0x006CC060 (FUN_006CC060, func_UnitIsMobile_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:IsMobile()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitIsMobile_LuaFuncDef();
  CScrLuaInitForm* func_UnitCanPathToRect_LuaFuncDef();

  /**
   * Address: 0x006CB900 (FUN_006CB900, func_UnitCanPathTo_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:CanPathTo(goal)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitCanPathTo_LuaFuncDef();

  /**
   * Address: 0x006CB7B0 (FUN_006CB7B0, func_UnitGetCurrentLayer_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetCurrentLayer()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetCurrentLayer_LuaFuncDef();

  /**
   * Address: 0x006CB5A0 (FUN_006CB5A0, func_UnitRecoilImpulse_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:RecoilImpulse(x, y, z)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRecoilImpulse_LuaFuncDef();

  /**
   * Address: 0x006CB470 (FUN_006CB470, func_UnitRevertCollisionShape_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:RevertCollisionShape()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRevertCollisionShape_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetBreakOffDistanceMult_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetBreakOffTriggerMult_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetTurnMult_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetAccMult_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetSpeedMult_LuaFuncDef();
  CScrLuaInitForm* func_UnitRevertElevation_LuaFuncDef();

  /**
   * Address: 0x006CECE0 (FUN_006CECE0, func_UnitGiveNukeSiloAmmo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GiveNukeSiloAmmo(num)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGiveNukeSiloAmmo_LuaFuncDef();

  /**
   * Address: 0x006CEA80 (FUN_006CEA80, func_UnitGetCurrentMoveLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetCurrentMoveLocation()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetCurrentMoveLocation_LuaFuncDef();

  /**
   * Address: 0x006CE440 (FUN_006CE440, func_UnitPrintCommandQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:PrintCommandQueue()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitPrintCommandQueue_LuaFuncDef();

  /**
   * Address: 0x006CE220 (FUN_006CE220, func_UnitGetCommandQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetCommandQueue()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetCommandQueue_LuaFuncDef();

  /**
   * Address: 0x006CDEF0 (FUN_006CDEF0, func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:MeleeWarpAdjacentToTarget(target)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef();

  /**
   * Address: 0x006CDCB0 (FUN_006CDCB0, func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:HasMeleeSpaceAroundTarget(target)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetCustomName_LuaFuncDef();

  /**
   * Address: 0x006CD970 (FUN_006CD970, func_UnitAddUnitToStorage_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:AddUnitToStorage(storedUnit)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitAddUnitToStorage_LuaFuncDef();

  /**
   * Address: 0x006CD800 (FUN_006CD800, func_UnitHasValidTeleportDest_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:HasValidTeleportDest()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitHasValidTeleportDest_LuaFuncDef();

  /**
   * Address: 0x006CD680 (FUN_006CD680, func_UnitGetTransportFerryBeacon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetTransportFerryBeacon()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetTransportFerryBeacon_LuaFuncDef();

  /**
   * Address: 0x006CD480 (FUN_006CD480, func_UnitGetGuards_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetGuards()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetGuards_LuaFuncDef();

  /**
   * Address: 0x006CD320 (FUN_006CD320, func_UnitGetGuardedUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetGuardedUnit()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetGuardedUnit_LuaFuncDef();
  void func_NotifyUpgrade_LuaFuncDef();

  /**
   * Address: 0x006CCCD0 (FUN_006CCCD0, func_UnitGetWorkProgress_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetWorkProgress()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetWorkProgress_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetWorkProgress_LuaFuncDef();

  /**
   * Address: 0x006CC900 (FUN_006CC900, func_UnitSetStat_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:SetStat(name, value)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitSetStat_LuaFuncDef();

  /**
   * Address: 0x006CEE30 (FUN_006CEE30, func_UnitRemoveNukeSiloAmmo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:RemoveNukeSiloAmmo(num)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRemoveNukeSiloAmmo_LuaFuncDef();

  /**
   * Address: 0x006CEF80 (FUN_006CEF80, func_UnitGetNukeSiloAmmoCount_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetNukeSiloAmmoCount()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetNukeSiloAmmoCount_LuaFuncDef();

  /**
   * Address: 0x006CF0F0 (FUN_006CF0F0, func_UnitGiveTacticalSiloAmmo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GiveTacticalSiloAmmo(num)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGiveTacticalSiloAmmo_LuaFuncDef();

  /**
   * Address: 0x006CF240 (FUN_006CF240, func_UnitRemoveTacticalSiloAmmo_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:RemoveTacticalSiloAmmo(num)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitRemoveTacticalSiloAmmo_LuaFuncDef();

  /**
   * Address: 0x006CF390 (FUN_006CF390, func_UnitGetTacticalSiloAmmoCount_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Unit:GetTacticalSiloAmmoCount()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetTacticalSiloAmmoCount_LuaFuncDef();
  CScrLuaInitForm* func_CreateUnit_LuaFuncDef();
  CScrLuaInitForm* func_CreateUnitHPR_LuaFuncDef();
  CScrLuaInitForm* func_CreateUnit2_LuaFuncDef();
  CScrLuaInitForm* func_UnitCanBuild_LuaFuncDef();

  /**
   * Address: 0x006D05F0 (FUN_006D05F0, func_UnitGetRallyPoint_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetRallyPoint()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetRallyPoint_LuaFuncDef();

  /**
   * Address: 0x006D0790 (FUN_006D0790, func_UnitGetFuelUseTime_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetFuelUseTime()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetFuelUseTime_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetFuelUseTime_LuaFuncDef();

  /**
   * Address: 0x006D0A70 (FUN_006D0A70, func_UnitGetFuelRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetFuelRatio()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetFuelRatio_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetFuelRatio_LuaFuncDef();
  CScrLuaInitForm* func_UnitSetShieldRatio_LuaFuncDef();

  /**
   * Address: 0x006D0EC0 (FUN_006D0EC0, func_UnitGetShieldRatio_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetShieldRatio()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetShieldRatio_LuaFuncDef();

  /**
   * Address: 0x006D1000 (FUN_006D1000, func_UnitGetBlip_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetBlip(armyIndex)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetBlip_LuaFuncDef();

  /**
   * Address: 0x006D1190 (FUN_006D1190, func_UnitTransportHasSpaceFor_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:TransportHasSpaceFor(target)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitTransportHasSpaceFor_LuaFuncDef();

  /**
   * Address: 0x006D1340 (FUN_006D1340, func_UnitTransportHasAvailableStorage_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:TransportHasAvailableStorage()` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitTransportHasAvailableStorage_LuaFuncDef();

  /**
   * Address: 0x005E8660 (FUN_005E8660, func_UnitTransportDetachAllUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:TransportDetachAllUnits(destroySomeUnits)` Lua binder
   * definition.
   */
  CScrLuaInitForm* func_UnitTransportDetachAllUnits_LuaFuncDef();

  /**
   * Address: 0x006D1490 (FUN_006D1490, func_UnitShowBone_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:ShowBone(self,bone,affectChildren)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitShowBone_LuaFuncDef();

  /**
   * Address: 0x006D1630 (FUN_006D1630, func_UnitHideBone_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:HideBone(self,bone,affectChildren)` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitHideBone_LuaFuncDef();
  CScrLuaInitForm* func_CUnitScriptTaskGetUnit_LuaFuncDef();
  CScrLuaInitForm* func_CUnitScriptTaskSetAIResult_LuaFuncDef();
  CScrLuaInitForm* func_LUnitMove_LuaFuncDef();
  CScrLuaInitForm* func_LUnitMoveNear_LuaFuncDef();

  /**
   * Address: 0x00BD19E0 (FUN_00BD19E0, j_func_CUnitScriptTaskGetUnit_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CUnitScriptTaskGetUnit_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CUnitScriptTaskGetUnit_LuaFuncDef();

  /**
   * Address: 0x00BD19F0 (FUN_00BD19F0, j_func_CUnitScriptTaskSetAIResult_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_CUnitScriptTaskSetAIResult_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CUnitScriptTaskSetAIResult_LuaFuncDef();

  /**
   * Address: 0x00BD1A00 (FUN_00BD1A00, register_LUnitMove_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_LUnitMove_LuaFuncDef`.
   */
  CScrLuaInitForm* register_LUnitMove_LuaFuncDef();

  /**
   * Address: 0x00BD1A10 (FUN_00BD1A10, register_LUnitMoveNear_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_LUnitMoveNear_LuaFuncDef`.
   */
  CScrLuaInitForm* register_LUnitMoveNear_LuaFuncDef();

  /**
   * Address: 0x00BD7950 (FUN_00BD7950, j_func_UnitGetUnitId_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetUnitId_LuaFuncDef();

  /**
   * Address: 0x00BD7960 (FUN_00BD7960, register_UnitSetCreator_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetCreator_LuaFuncDef();

  /**
   * Address: 0x00BD7970 (FUN_00BD7970, register_UnitGetCargo_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetCargo_LuaFuncDef();

  /**
   * Address: 0x00BD7980 (FUN_00BD7980, j_func_UnitAlterArmor_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitAlterArmor_LuaFuncDef();

  /**
   * Address: 0x00BD7990 (FUN_00BD7990, register_UnitGetArmorMult_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetArmorMult_LuaFuncDef();

  /**
   * Address: 0x00BD79A0 (FUN_00BD79A0, j_func_UnitClearFocusEntity_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitClearFocusEntity_LuaFuncDef();

  /**
   * Address: 0x00BD79B0 (FUN_00BD79B0, j_func_UnitSetFocusEntity_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetFocusEntity_LuaFuncDef();

  /**
   * Address: 0x00BD79C0 (FUN_00BD79C0, register_UnitGetFocusUnit_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetFocusUnit_LuaFuncDef();

  /**
   * Address: 0x00BD79D0 (FUN_00BD79D0, register_UnitGetWeapon_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetWeapon_LuaFuncDef();

  /**
   * Address: 0x00BD79E0 (FUN_00BD79E0, j_func_UnitGetWeaponCount_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetWeaponCount_LuaFuncDef();

  /**
   * Address: 0x00BD79F0 (FUN_00BD79F0, register_UnitGetTargetEntity_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetTargetEntity_LuaFuncDef();

  /**
   * Address: 0x00BD7A00 (FUN_00BD7A00, j_func_UnitGetHealth_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetHealth_LuaFuncDef();

  /**
   * Address: 0x00BD7A10 (FUN_00BD7A10, j_func_UnitGetAttacker_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetAttacker_LuaFuncDef();

  /**
   * Address: 0x00BD7A20 (FUN_00BD7A20, register_UnitEnableManipulators_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitEnableManipulators_LuaFuncDef();

  /**
   * Address: 0x00BD7A30 (FUN_00BD7A30, j_func_UnitKillManipulator_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitKillManipulator_LuaFuncDef();

  /**
   * Address: 0x00BD7A40 (FUN_00BD7A40, j_func_UnitKillManipulators_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitKillManipulators_LuaFuncDef();

  /**
   * Address: 0x00BD7A50 (FUN_00BD7A50, register_UnitScaleGetBuiltEmitter_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitScaleGetBuiltEmitter_LuaFuncDef();

  /**
   * Address: 0x00BD7A60 (FUN_00BD7A60, register_UnitSetStrategicUnderlay_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetStrategicUnderlay_LuaFuncDef();

  /**
   * Address: 0x00BD7A70 (FUN_00BD7A70, j_func_UnitIsUnitState_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitIsUnitState_LuaFuncDef();

  /**
   * Address: 0x00BD7A80 (FUN_00BD7A80, j_func_UnitIsIdleState_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitIsIdleState_LuaFuncDef();

  /**
   * Address: 0x00BD7A90 (FUN_00BD7A90, register_UnitIsStunned_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitIsStunned_LuaFuncDef();

  /**
   * Address: 0x00BD7AA0 (FUN_00BD7AA0, register_UnitIsBeingBuilt_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitIsBeingBuilt_LuaFuncDef();

  /**
   * Address: 0x00BD7AB0 (FUN_00BD7AB0, register_UnitIsPaused_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitIsPaused_LuaFuncDef();

  /**
   * Address: 0x00BD7AC0 (FUN_00BD7AC0, j_func_UnitSetPaused_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetPaused_LuaFuncDef();

  /**
   * Address: 0x00BD7AD0 (FUN_00BD7AD0, j_func_UnitSetConsumptionActive_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetConsumptionActive_LuaFuncDef();

  /**
   * Address: 0x00BD7AE0 (FUN_00BD7AE0, register_UnitSetProductionActive_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetProductionActive_LuaFuncDef();

  /**
   * Address: 0x00BD7AF0 (FUN_00BD7AF0, register_UnitSetBusy_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetBusy_LuaFuncDef();

  /**
   * Address: 0x00BD7B00 (FUN_00BD7B00, register_UnitSetBlockCommandQueue_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetBlockCommandQueue_LuaFuncDef();

  /**
   * Address: 0x00BD7B10 (FUN_00BD7B10, register_UnitSetImmobile_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetImmobile_LuaFuncDef();

  /**
   * Address: 0x00BD7B20 (FUN_00BD7B20, j_func_UnitSetStunned_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetStunned_LuaFuncDef();

  /**
   * Address: 0x00BD7B30 (FUN_00BD7B30, register_UnitSetUnSelectable_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetUnSelectable_LuaFuncDef();

  /**
   * Address: 0x00BD7B40 (FUN_00BD7B40, register_UnitSetDoNotTarget_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetDoNotTarget_LuaFuncDef();

  /**
   * Address: 0x00BD7B50 (FUN_00BD7B50, register_UnitSetUnitState_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetUnitState_LuaFuncDef();

  /**
   * Address: 0x00BD7B60 (FUN_00BD7B60, register_UnitStopSiloBuild_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitStopSiloBuild_LuaFuncDef();

  /**
   * Address: 0x00BD7B70 (FUN_00BD7B70, register_UnitSetIsValidTarget_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetIsValidTarget_LuaFuncDef();

  /**
   * Address: 0x00BD7B80 (FUN_00BD7B80, j_func_UnitIsValidTarget_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitIsValidTarget_LuaFuncDef();

  /**
   * Address: 0x00BD7B90 (FUN_00BD7B90, j_func_UnitGetNumBuildOrders_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetNumBuildOrders_LuaFuncDef();

  /**
   * Address: 0x00BD7BA0 (FUN_00BD7BA0, register_UnitCalculateWorldPositionFromRelative_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitCalculateWorldPositionFromRelative_LuaFuncDef();

  /**
   * Address: 0x00BD7BB0 (FUN_00BD7BB0, register_UnitGetScriptBit_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetScriptBit_LuaFuncDef();

  /**
   * Address: 0x00BD7BC0 (FUN_00BD7BC0, j_func_UnitSetScriptBit_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetScriptBit_LuaFuncDef();

  /**
   * Address: 0x00BD7BD0 (FUN_00BD7BD0, register_UnitToggleScriptBit_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitToggleScriptBit_LuaFuncDef();

  /**
   * Address: 0x00BD7BE0 (FUN_00BD7BE0, j_func_UnitToggleFireState_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitToggleFireState_LuaFuncDef();

  /**
   * Address: 0x00BD7BF0 (FUN_00BD7BF0, register_UnitSetFireState_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetFireState_LuaFuncDef();

  /**
   * Address: 0x00BD7C00 (FUN_00BD7C00, register_UnitGetFireState_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetFireState_LuaFuncDef();

  /**
   * Address: 0x00BD7C10 (FUN_00BD7C10, register_UnitSetAutoMode_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetAutoMode_LuaFuncDef();

  /**
   * Address: 0x00BD7C20 (FUN_00BD7C20, j_func_UnitAddBuildRestriction_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitAddBuildRestriction_LuaFuncDef();

  /**
   * Address: 0x00BD7C30 (FUN_00BD7C30, register_UnitRemoveBuildRestriction_LuaFuncDef)
   */
  void register_UnitRemoveBuildRestriction_LuaFuncDef();

  /**
   * Address: 0x00BD7C40 (FUN_00BD7C40, register_UnitRestoreBuildRestrictions_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitRestoreBuildRestrictions_LuaFuncDef();

  /**
   * Address: 0x00BD7C50 (FUN_00BD7C50, register_UnitAddCommandCap_LuaFuncDef)
   */
  void register_UnitAddCommandCap_LuaFuncDef();

  /**
   * Address: 0x00BD7C60 (FUN_00BD7C60, register_UnitRemoveCommandCap_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitRemoveCommandCap_LuaFuncDef();

  /**
   * Address: 0x00BD7C70 (FUN_00BD7C70, register_UnitRestoreCommandCaps_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitRestoreCommandCaps_LuaFuncDef();

  /**
   * Address: 0x00BD7C80 (FUN_00BD7C80, j_func_UnitTestCommandCaps_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitTestCommandCaps_LuaFuncDef();

  /**
   * Address: 0x00BD7C90 (FUN_00BD7C90, register_UnitAddToggleCap_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitAddToggleCap_LuaFuncDef();

  /**
   * Address: 0x00BD7CA0 (FUN_00BD7CA0, j_func_UnitRemoveToggleCap_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitRemoveToggleCap_LuaFuncDef();

  /**
   * Address: 0x00BD7CB0 (FUN_00BD7CB0, j_func_UnitRestoreToggleCaps_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitRestoreToggleCaps_LuaFuncDef();

  /**
   * Address: 0x00BD7CC0 (FUN_00BD7CC0, register_UnitTestToggleCaps_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitTestToggleCaps_LuaFuncDef();

  /**
   * Address: 0x00BD7CD0 (FUN_00BD7CD0, register_UnitSetRegenRate_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetRegenRate_LuaFuncDef();

  /**
   * Address: 0x00BD7CE0 (FUN_00BD7CE0, j_func_UnitRevertRegenRate)
   */
  CScrLuaInitForm* j_func_UnitRevertRegenRate();

  /**
   * Address: 0x00BD7CF0 (FUN_00BD7CF0, register_UnitSetReclaimable_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetReclaimable_LuaFuncDef();

  /**
   * Address: 0x00BD7D00 (FUN_00BD7D00, register_UnitSetCapturable_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetCapturable_LuaFuncDef();

  /**
   * Address: 0x00BD7D10 (FUN_00BD7D10, register_UnitIsCapturable_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitIsCapturable_LuaFuncDef();

  /**
   * Address: 0x00BD7D20 (FUN_00BD7D20, j_func_UnitSetOverchargePaused_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetOverchargePaused_LuaFuncDef();

  /**
   * Address: 0x00BD7D30 (FUN_00BD7D30, j_func_UnitIsOverchargePaused_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitIsOverchargePaused_LuaFuncDef();

  /**
   * Address: 0x00BD7D40 (FUN_00BD7D40, register_UnitSetBuildRate_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetBuildRate_LuaFuncDef();

  /**
   * Address: 0x00BD7D50 (FUN_00BD7D50, register_UnitGetBuildRate_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetBuildRate_LuaFuncDef();

  /**
   * Address: 0x00BD7D60 (FUN_00BD7D60, register_UnitSetConsumptionPerSecondEnergy_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetConsumptionPerSecondEnergy_LuaFuncDef();

  /**
   * Address: 0x00BD7D70 (FUN_00BD7D70, j_func_UnitSetConsumptionPerSecondMass_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetConsumptionPerSecondMass_LuaFuncDef();

  /**
   * Address: 0x00BD7D80 (FUN_00BD7D80, register_UnitSetProductionPerSecondEnergy_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetProductionPerSecondEnergy_LuaFuncDef();

  /**
   * Address: 0x00BD7D90 (FUN_00BD7D90, register_UnitSetProductionPerSecondMass_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetProductionPerSecondMass_LuaFuncDef();

  /**
   * Address: 0x00BD7DA0 (FUN_00BD7DA0, j_func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef();

  /**
   * Address: 0x00BD7DB0 (FUN_00BD7DB0, register_UnitGetConsumptionPerSecondMass_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetConsumptionPerSecondMass_LuaFuncDef();

  /**
   * Address: 0x00BD7DC0 (FUN_00BD7DC0, j_func_UnitGetProductionPerSecondEnergy_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetProductionPerSecondEnergy_LuaFuncDef();

  /**
   * Address: 0x00BD7DD0 (FUN_00BD7DD0, j_func_UnitGetProductionPerSecondMass_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetProductionPerSecondMass_LuaFuncDef();

  /**
   * Address: 0x00BD7DE0 (FUN_00BD7DE0, register_UnitGetResourceConsumed_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetResourceConsumed_LuaFuncDef();

  /**
   * Address: 0x00BD7DF0 (FUN_00BD7DF0, register_UnitSetElevation_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetElevation_LuaFuncDef();

  /**
   * Address: 0x00BD7E00 (FUN_00BD7E00, register_UnitRevertElevation_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitRevertElevation_LuaFuncDef();

  /**
   * Address: 0x00BD7E10 (FUN_00BD7E10, register_UnitSetSpeedMult_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetSpeedMult_LuaFuncDef();

  /**
   * Address: 0x00BD7E20 (FUN_00BD7E20, register_UnitSetAccMult_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetAccMult_LuaFuncDef();

  /**
   * Address: 0x00BD7E30 (FUN_00BD7E30, j_func_UnitSetTurnMult_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetTurnMult_LuaFuncDef();

  /**
   * Address: 0x00BD7E40 (FUN_00BD7E40, j_func_UnitSetBreakOffTriggerMult_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetBreakOffTriggerMult_LuaFuncDef();

  /**
   * Address: 0x00BD7E50 (FUN_00BD7E50, j_func_UnitSetBreakOffDistanceMult_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetBreakOffDistanceMult_LuaFuncDef();

  /**
   * Address: 0x00BD7E60 (FUN_00BD7E60, j_func_UnitRevertCollisionShape_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitRevertCollisionShape_LuaFuncDef();

  /**
   * Address: 0x00BD7E70 (FUN_00BD7E70, register_UnitRecoilImpulse_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitRecoilImpulse_LuaFuncDef();

  /**
   * Address: 0x00BD7E80 (FUN_00BD7E80, register_UnitGetCurrentLayer_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetCurrentLayer_LuaFuncDef();

  /**
   * Address: 0x00BD7E90 (FUN_00BD7E90, j_func_UnitCanPathTo_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitCanPathTo_LuaFuncDef();

  /**
   * Address: 0x00BD7EA0 (FUN_00BD7EA0, register_UnitCanPathToRect_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitCanPathToRect_LuaFuncDef();

  /**
   * Address: 0x00BD7EB0 (FUN_00BD7EB0, register_UnitIsMobile_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitIsMobile_LuaFuncDef();

  /**
   * Address: 0x00BD7EC0 (FUN_00BD7EC0, register_UnitIsMoving_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitIsMoving_LuaFuncDef();

  /**
   * Address: 0x00BD7ED0 (FUN_00BD7ED0, register_UnitGetNavigator_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetNavigator_LuaFuncDef();

  /**
   * Address: 0x00BD7EE0 (FUN_00BD7EE0, j_func_UnitGetVelocity_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetVelocity_LuaFuncDef();

  /**
   * Address: 0x00BD7EF0 (FUN_00BD7EF0, j_func_UnitGetStat_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetStat_LuaFuncDef();

  /**
   * Address: 0x00BD7F00 (FUN_00BD7F00, register_UnitSetStat_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetStat_LuaFuncDef();

  /**
   * Address: 0x00BD7F10 (FUN_00BD7F10, register_UnitSetWorkProgress_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetWorkProgress_LuaFuncDef();

  /**
   * Address: 0x00BD7F20 (FUN_00BD7F20, register_UnitGetWorkProgress_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetWorkProgress_LuaFuncDef();

  /**
   * Address: 0x00BD7F30 (FUN_00BD7F30, register_NotifyUpgrade_LuaFuncDef)
   */
  void register_NotifyUpgrade_LuaFuncDef();

  /**
   * Address: 0x00BD7F40 (FUN_00BD7F40, register_UserGetGuardedUnit_LuaFuncDef)
   */
  CScrLuaInitForm* register_UserGetGuardedUnit_LuaFuncDef();

  /**
   * Address: 0x00BD7F50 (FUN_00BD7F50, j_func_UnitGetGuards_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetGuards_LuaFuncDef();

  /**
   * Address: 0x00BD7F60 (FUN_00BD7F60, register_UnitGetTransportFerryBeacon_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetTransportFerryBeacon_LuaFuncDef();

  /**
   * Address: 0x00BD7F70 (FUN_00BD7F70, register_UnitHasValidTeleportDest_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitHasValidTeleportDest_LuaFuncDef();

  /**
   * Address: 0x00BD7F80 (FUN_00BD7F80, j_func_UnitAddUnitToStorage_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitAddUnitToStorage_LuaFuncDef();

  /**
   * Address: 0x00BD7F90 (FUN_00BD7F90, register_UnitSetCustomName_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetCustomName_LuaFuncDef();

  /**
   * Address: 0x00BD7FA0 (FUN_00BD7FA0, register_UnitHasMeleeSpaceAroundTarget_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitHasMeleeSpaceAroundTarget_LuaFuncDef();

  /**
   * Address: 0x00BD7FB0 (FUN_00BD7FB0, register_UnitMeleeWarpAdjacentToTarget_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitMeleeWarpAdjacentToTarget_LuaFuncDef();

  /**
   * Address: 0x00BD7FC0 (FUN_00BD7FC0, register_UnitGetCommandQueue_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetCommandQueue_LuaFuncDef();

  /**
   * Address: 0x00BD7FD0 (FUN_00BD7FD0, register_UnitPrintCommandQueue_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitPrintCommandQueue_LuaFuncDef();

  /**
   * Address: 0x00BD7FE0 (FUN_00BD7FE0, j_func_UnitGetCurrentMoveLocation_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetCurrentMoveLocation_LuaFuncDef();

  /**
   * Address: 0x00BD7FF0 (FUN_00BD7FF0, register_UnitGiveNukeSiloAmmo_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGiveNukeSiloAmmo_LuaFuncDef();

  /**
   * Address: 0x00BD8000 (FUN_00BD8000, register_UnitRemoveNukeSiloAmmo_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitRemoveNukeSiloAmmo_LuaFuncDef();

  /**
   * Address: 0x00BD8010 (FUN_00BD8010, j_func_UnitGetNukeSiloAmmoCount_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetNukeSiloAmmoCount_LuaFuncDef();

  /**
   * Address: 0x00BD8020 (FUN_00BD8020, register_UnitGiveTacticalSiloAmmo_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGiveTacticalSiloAmmo_LuaFuncDef();

  /**
   * Address: 0x00BD8030 (FUN_00BD8030, register_UnitRemoveTacticalSiloAmmo_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitRemoveTacticalSiloAmmo_LuaFuncDef();

  /**
   * Address: 0x00BD8040 (FUN_00BD8040, j_func_UnitGetTacticalSiloAmmoCount_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetTacticalSiloAmmoCount_LuaFuncDef();

  /**
   * Address: 0x00BD8050 (FUN_00BD8050, j_func_CreateUnit_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateUnit_LuaFuncDef();

  /**
   * Address: 0x00BD8060 (FUN_00BD8060, j_func_CreateUnitHPR_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateUnitHPR_LuaFuncDef();

  /**
   * Address: 0x00BD8070 (FUN_00BD8070, j_func_CreateUnit2_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_CreateUnit2_LuaFuncDef();

  /**
   * Address: 0x00BD8080 (FUN_00BD8080, register_UnitCanBuild_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitCanBuild_LuaFuncDef();

  /**
   * Address: 0x00BD8090 (FUN_00BD8090, j_func_UnitGetRallyPoint_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetRallyPoint_LuaFuncDef();

  /**
   * Address: 0x00BD80A0 (FUN_00BD80A0, register_UserGetFuelUseTime_LuaFuncDef)
   */
  CScrLuaInitForm* register_UserGetFuelUseTime_LuaFuncDef();

  /**
   * Address: 0x00BD80B0 (FUN_00BD80B0, register_UnitSetFuelUseTime_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitSetFuelUseTime_LuaFuncDef();

  /**
   * Address: 0x00BD80C0 (FUN_00BD80C0, register_UnitGetFuelRatio_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetFuelRatio_LuaFuncDef();

  /**
   * Address: 0x00BD80D0 (FUN_00BD80D0, j_func_UnitSetFuelRatio_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetFuelRatio_LuaFuncDef();

  /**
   * Address: 0x00BD80E0 (FUN_00BD80E0, j_func_UnitSetShieldRatio_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitSetShieldRatio_LuaFuncDef();

  /**
   * Address: 0x00BD80F0 (FUN_00BD80F0, register_UnitGetShieldRatio_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitGetShieldRatio_LuaFuncDef();

  /**
   * Address: 0x00BD8100 (FUN_00BD8100, j_func_UnitGetBlip_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitGetBlip_LuaFuncDef();

  /**
   * Address: 0x00BD8110 (FUN_00BD8110, register_UnitTransportHasSpaceFor_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitTransportHasSpaceFor_LuaFuncDef();

  /**
   * Address: 0x00BD8120 (FUN_00BD8120, register_UnitTransportHasAvailableStorage_LuaFuncDef)
   */
  CScrLuaInitForm* register_UnitTransportHasAvailableStorage_LuaFuncDef();

  /**
   * Address: 0x00BCEF90 (FUN_00BCEF90, register_UnitTransportDetachAllUnits_LuaFuncDef)
   *
   * What it does:
   * Forwards the startup thunk to `func_UnitTransportDetachAllUnits_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UnitTransportDetachAllUnits_LuaFuncDef();

  /**
   * Address: 0x00BD8130 (FUN_00BD8130, j_func_UnitShowBone_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitShowBone_LuaFuncDef();

  /**
   * Address: 0x00BD8140 (FUN_00BD8140, j_func_UnitHideBone_LuaFuncDef)
   */
  CScrLuaInitForm* j_func_UnitHideBone_LuaFuncDef();
} // namespace moho
