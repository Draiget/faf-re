// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/Unit.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <list>
#include <limits>
#include <new>
#include <string>
#include <stdexcept>
#include <typeinfo>

#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/path/PathTables.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/ReconBlip.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SPhysBody.h"
#include "moho/sim/SimStartupRegistrations.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UnitLuaFunctionThunks.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/core/UserUnit.h"

using namespace moho;

namespace moho
{
  int cfunc_UnitGetUnitIdL(LuaPlus::LuaState* state);
  int cfunc_UnitGetUnitId(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetUnitId_LuaFuncDef();
  int cfunc_UnitSetCreatorL(LuaPlus::LuaState* state);
  int cfunc_UnitSetCreator(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetCreator_LuaFuncDef();
  int cfunc_UnitGetCargoL(LuaPlus::LuaState* state);
  int cfunc_UnitGetCargo(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetCargo_LuaFuncDef();
  int cfunc_UnitAlterArmor(lua_State* luaContext);
  CScrLuaInitForm* func_UnitAlterArmor_LuaFuncDef();
  int cfunc_UnitAlterArmorL(LuaPlus::LuaState* state);
  int cfunc_UnitGetArmorMult(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetArmorMult_LuaFuncDef();
  int cfunc_UnitGetArmorMultL(LuaPlus::LuaState* state);
  int cfunc_UnitClearFocusEntity(lua_State* luaContext);
  CScrLuaInitForm* func_UnitClearFocusEntity_LuaFuncDef();
  int cfunc_UnitClearFocusEntityL(LuaPlus::LuaState* state);
  int cfunc_UnitSetFocusEntity(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetFocusEntity_LuaFuncDef();
  int cfunc_UnitSetFocusEntityL(LuaPlus::LuaState* state);
  int cfunc_UnitGetFocusUnit(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetFocusUnit_LuaFuncDef();
  int cfunc_UnitGetFocusUnitL(LuaPlus::LuaState* state);
  int cfunc_UnitGetWeaponL(LuaPlus::LuaState* state);
  int cfunc_UnitGetWeapon(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetWeapon_LuaFuncDef();
  int cfunc_UnitGetWeaponCountL(LuaPlus::LuaState* state);
  int cfunc_UnitGetWeaponCount(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetWeaponCount_LuaFuncDef();
  int cfunc_UnitGetTargetEntityL(LuaPlus::LuaState* state);
  int cfunc_UnitGetTargetEntity(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetTargetEntity_LuaFuncDef();
  int cfunc_UnitGetHealthL(LuaPlus::LuaState* state);
  int cfunc_UnitGetHealth(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetHealth_LuaFuncDef();
  int cfunc_UnitGetAttackerL(LuaPlus::LuaState* state);
  int cfunc_UnitGetAttacker(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetAttacker_LuaFuncDef();
  int cfunc_UnitEnableManipulatorsL(LuaPlus::LuaState* state);
  int cfunc_UnitEnableManipulators(lua_State* luaContext);
  CScrLuaInitForm* func_UnitEnableManipulators_LuaFuncDef();
  int cfunc_UnitKillManipulator(lua_State* luaContext);
  CScrLuaInitForm* func_UnitKillManipulator_LuaFuncDef();
  int cfunc_UnitKillManipulatorL(LuaPlus::LuaState* state);
  int cfunc_UnitKillManipulators(lua_State* luaContext);
  CScrLuaInitForm* func_UnitKillManipulators_LuaFuncDef();
  int cfunc_UnitKillManipulatorsL(LuaPlus::LuaState* state);
  int cfunc_UnitScaleGetBuiltEmitter(lua_State* luaContext);
  CScrLuaInitForm* func_UnitScaleGetBuiltEmitter_LuaFuncDef();
  int cfunc_UnitScaleGetBuiltEmitterL(LuaPlus::LuaState* state);
  int cfunc_UnitSetStrategicUnderlay(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetStrategicUnderlay_LuaFuncDef();
  int cfunc_UnitSetStrategicUnderlayL(LuaPlus::LuaState* state);
  int cfunc_GetIsPausedL(LuaPlus::LuaState* state);
  int cfunc_GetIsPaused(lua_State* luaContext);
  CScrLuaInitForm* func_GetIsPaused_LuaFuncDef();
  int cfunc_GetIsAutoModeL(LuaPlus::LuaState* state);
  int cfunc_GetIsAutoMode(lua_State* luaContext);
  CScrLuaInitForm* func_GetIsAutoMode_LuaFuncDef();
  int cfunc_SetFireStateL(LuaPlus::LuaState* state);
  int cfunc_SetFireState(lua_State* luaContext);
  CScrLuaInitForm* func_SetFireState_LuaFuncDef();
  int cfunc_ToggleFireStateL(LuaPlus::LuaState* state);
  int cfunc_ToggleFireState(lua_State* luaContext);
  CScrLuaInitForm* func_ToggleFireState_LuaFuncDef();
  int cfunc_GetFireStateL(LuaPlus::LuaState* state);
  int cfunc_GetFireState(lua_State* luaContext);
  CScrLuaInitForm* func_GetFireState_LuaFuncDef();
  int cfunc_GetIsSubmergedL(LuaPlus::LuaState* state);
  int cfunc_GetIsSubmerged(lua_State* luaContext);
  CScrLuaInitForm* func_GetIsSubmerged_LuaFuncDef();
  int cfunc_GetIsAutoSurfaceModeL(LuaPlus::LuaState* state);
  int cfunc_GetIsAutoSurfaceMode(lua_State* luaContext);
  CScrLuaInitForm* func_GetIsAutoSurfaceMode_LuaFuncDef();
  int cfunc_UnitGetGuardsL(LuaPlus::LuaState* state);
  int cfunc_UnitGetGuards(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetGuards_LuaFuncDef();
  int cfunc_UnitGetTransportFerryBeaconL(LuaPlus::LuaState* state);
  int cfunc_UnitGetTransportFerryBeacon(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetTransportFerryBeacon_LuaFuncDef();
  int cfunc_UnitGetGuardedUnitL(LuaPlus::LuaState* state);
  int cfunc_UnitGetGuardedUnit(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetGuardedUnit_LuaFuncDef();
  int cfunc_UnitHasValidTeleportDestL(LuaPlus::LuaState* state);
  int cfunc_UnitHasValidTeleportDest(lua_State* luaContext);
  CScrLuaInitForm* func_UnitHasValidTeleportDest_LuaFuncDef();
  int cfunc_UnitAddUnitToStorageL(LuaPlus::LuaState* state);
  int cfunc_UnitAddUnitToStorage(lua_State* luaContext);
  CScrLuaInitForm* func_UnitAddUnitToStorage_LuaFuncDef();
  int cfunc_UnitGetCurrentMoveLocationL(LuaPlus::LuaState* state);
  int cfunc_UnitGetCurrentMoveLocation(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetCurrentMoveLocation_LuaFuncDef();
  int cfunc_UnitGiveNukeSiloAmmoL(LuaPlus::LuaState* state);
  int cfunc_UnitGiveNukeSiloAmmo(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGiveNukeSiloAmmo_LuaFuncDef();
  int cfunc_UnitRemoveNukeSiloAmmoL(LuaPlus::LuaState* state);
  int cfunc_UnitRemoveNukeSiloAmmo(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRemoveNukeSiloAmmo_LuaFuncDef();
  int cfunc_UnitGetNukeSiloAmmoCountL(LuaPlus::LuaState* state);
  int cfunc_UnitGetNukeSiloAmmoCount(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetNukeSiloAmmoCount_LuaFuncDef();
  int cfunc_UnitGiveTacticalSiloAmmoL(LuaPlus::LuaState* state);
  int cfunc_UnitGiveTacticalSiloAmmo(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGiveTacticalSiloAmmo_LuaFuncDef();
  int cfunc_UnitRemoveTacticalSiloAmmoL(LuaPlus::LuaState* state);
  int cfunc_UnitRemoveTacticalSiloAmmo(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRemoveTacticalSiloAmmo_LuaFuncDef();
  int cfunc_UnitGetTacticalSiloAmmoCountL(LuaPlus::LuaState* state);
  int cfunc_UnitGetTacticalSiloAmmoCount(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetTacticalSiloAmmoCount_LuaFuncDef();
  int cfunc_UnitSetCustomName(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetCustomName_LuaFuncDef();
  int cfunc_UnitSetCustomNameL(LuaPlus::LuaState* state);
  int cfunc_UnitGetCommandQueueL(LuaPlus::LuaState* state);
  int cfunc_UnitGetCommandQueue(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetCommandQueue_LuaFuncDef();
  int cfunc_UnitPrintCommandQueueL(LuaPlus::LuaState* state);
  int cfunc_UnitPrintCommandQueue(lua_State* luaContext);
  CScrLuaInitForm* func_UnitPrintCommandQueue_LuaFuncDef();
  int cfunc_UnitIsIdleStateL(LuaPlus::LuaState* state);
  int cfunc_UnitIsIdleState(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsIdleState_LuaFuncDef();
  int cfunc_UnitIsStunnedL(LuaPlus::LuaState* state);
  int cfunc_UnitIsStunned(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsStunned_LuaFuncDef();
  int cfunc_UnitIsBeingBuiltL(LuaPlus::LuaState* state);
  int cfunc_UnitIsBeingBuilt(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsBeingBuilt_LuaFuncDef();
  int cfunc_UnitIsPausedL(LuaPlus::LuaState* state);
  int cfunc_UnitIsPaused(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsPaused_LuaFuncDef();
  int cfunc_UnitSetPausedL(LuaPlus::LuaState* state);
  int cfunc_UnitSetPaused(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetPaused_LuaFuncDef();
  int cfunc_UnitSetConsumptionActiveL(LuaPlus::LuaState* state);
  int cfunc_UnitSetConsumptionActive(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetConsumptionActive_LuaFuncDef();
  int cfunc_UnitSetConsumptionPerSecondEnergyL(LuaPlus::LuaState* state);
  int cfunc_UnitSetConsumptionPerSecondEnergy(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef();
  int cfunc_UnitSetConsumptionPerSecondMassL(LuaPlus::LuaState* state);
  int cfunc_UnitSetConsumptionPerSecondMass(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetConsumptionPerSecondMass_LuaFuncDef();
  int cfunc_UnitSetRegenRate(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetRegenRate_LuaFuncDef();
  int cfunc_UnitSetRegenRateL(LuaPlus::LuaState* state);
  int cfunc_UnitRevertRegenRate(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRevertRegenRate_LuaFuncDef();
  int cfunc_UnitRevertRegenRateL(LuaPlus::LuaState* state);
  int cfunc_UnitSetBuildRate(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetBuildRate_LuaFuncDef();
  int cfunc_UnitSetBuildRateL(LuaPlus::LuaState* state);
  int cfunc_UnitGetBuildRate(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetBuildRate_LuaFuncDef();
  int cfunc_UnitGetBuildRateL(LuaPlus::LuaState* state);
  int cfunc_UnitSetProductionPerSecondEnergy(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetProductionPerSecondEnergy_LuaFuncDef();
  int cfunc_UnitSetProductionPerSecondEnergyL(LuaPlus::LuaState* state);
  int cfunc_UnitSetProductionPerSecondMass(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetProductionPerSecondMass_LuaFuncDef();
  int cfunc_UnitSetProductionPerSecondMassL(LuaPlus::LuaState* state);
  int cfunc_UnitGetConsumptionPerSecondEnergy(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef();
  int cfunc_UnitGetConsumptionPerSecondEnergyL(LuaPlus::LuaState* state);
  int cfunc_UnitGetConsumptionPerSecondMass(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetConsumptionPerSecondMass_LuaFuncDef();
  int cfunc_UnitGetConsumptionPerSecondMassL(LuaPlus::LuaState* state);
  int cfunc_UnitGetProductionPerSecondEnergy(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetProductionPerSecondEnergy_LuaFuncDef();
  int cfunc_UnitGetProductionPerSecondEnergyL(LuaPlus::LuaState* state);
  int cfunc_UnitGetProductionPerSecondMass(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetProductionPerSecondMass_LuaFuncDef();
  int cfunc_UnitGetProductionPerSecondMassL(LuaPlus::LuaState* state);
  int cfunc_UnitGetResourceConsumed(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetResourceConsumed_LuaFuncDef();
  int cfunc_UnitGetResourceConsumedL(LuaPlus::LuaState* state);
  int cfunc_UnitSetElevation(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetElevation_LuaFuncDef();
  int cfunc_UnitSetElevationL(LuaPlus::LuaState* state);
  int cfunc_UnitRevertElevation(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRevertElevation_LuaFuncDef();
  int cfunc_UnitRevertElevationL(LuaPlus::LuaState* state);
  int cfunc_UnitSetSpeedMult(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetSpeedMult_LuaFuncDef();
  int cfunc_UnitSetSpeedMultL(LuaPlus::LuaState* state);
  int cfunc_UnitSetAccMult(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetAccMult_LuaFuncDef();
  int cfunc_UnitSetAccMultL(LuaPlus::LuaState* state);
  int cfunc_UnitSetTurnMult(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetTurnMult_LuaFuncDef();
  int cfunc_UnitSetTurnMultL(LuaPlus::LuaState* state);
  int cfunc_UnitSetBreakOffTriggerMult(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetBreakOffTriggerMult_LuaFuncDef();
  int cfunc_UnitSetBreakOffTriggerMultL(LuaPlus::LuaState* state);
  int cfunc_UnitSetBreakOffDistanceMult(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetBreakOffDistanceMult_LuaFuncDef();
  int cfunc_UnitSetBreakOffDistanceMultL(LuaPlus::LuaState* state);
  int cfunc_UnitSetStat(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetStat_LuaFuncDef();
  int cfunc_UnitSetStatL(LuaPlus::LuaState* state);
  int cfunc_UnitSetWorkProgress(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetWorkProgress_LuaFuncDef();
  int cfunc_UnitSetWorkProgressL(LuaPlus::LuaState* state);
  int cfunc_UnitGetWorkProgress(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetWorkProgress_LuaFuncDef();
  int cfunc_UnitGetWorkProgressL(LuaPlus::LuaState* state);
  int cfunc_UnitIsUnitStateL(LuaPlus::LuaState* state);
  int cfunc_UnitIsUnitState(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsUnitState_LuaFuncDef();
  int cfunc_UnitSetProductionActiveL(LuaPlus::LuaState* state);
  int cfunc_UnitSetProductionActive(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetProductionActive_LuaFuncDef();
  int cfunc_UnitSetBusyL(LuaPlus::LuaState* state);
  int cfunc_UnitSetBusy(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetBusy_LuaFuncDef();
  int cfunc_UnitSetBlockCommandQueueL(LuaPlus::LuaState* state);
  int cfunc_UnitSetBlockCommandQueue(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetBlockCommandQueue_LuaFuncDef();
  int cfunc_UnitSetImmobileL(LuaPlus::LuaState* state);
  int cfunc_UnitSetImmobile(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetImmobile_LuaFuncDef();
  int cfunc_UnitSetUnSelectableL(LuaPlus::LuaState* state);
  int cfunc_UnitSetUnSelectable(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetUnSelectable_LuaFuncDef();
  int cfunc_UnitSetDoNotTargetL(LuaPlus::LuaState* state);
  int cfunc_UnitSetDoNotTarget(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetDoNotTarget_LuaFuncDef();
  int cfunc_UnitStopSiloBuildL(LuaPlus::LuaState* state);
  int cfunc_UnitStopSiloBuild(lua_State* luaContext);
  CScrLuaInitForm* func_UnitStopSiloBuild_LuaFuncDef();
  int cfunc_UnitSetIsValidTargetL(LuaPlus::LuaState* state);
  int cfunc_UnitSetIsValidTarget(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetIsValidTarget_LuaFuncDef();
  int cfunc_UnitIsValidTargetL(LuaPlus::LuaState* state);
  int cfunc_UnitIsValidTarget(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsValidTarget_LuaFuncDef();
  int cfunc_UnitGetNumBuildOrdersL(LuaPlus::LuaState* state);
  int cfunc_UnitGetNumBuildOrders(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetNumBuildOrders_LuaFuncDef();
  int cfunc_UnitCalculateWorldPositionFromRelativeL(LuaPlus::LuaState* state);
  int cfunc_UnitCalculateWorldPositionFromRelative(lua_State* luaContext);
  CScrLuaInitForm* func_UnitCalculateWorldPositionFromRelative_LuaFuncDef();
  int cfunc_UnitSetStunnedL(LuaPlus::LuaState* state);
  int cfunc_UnitSetStunned(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetStunned_LuaFuncDef();
  int cfunc_UnitSetUnitStateL(LuaPlus::LuaState* state);
  int cfunc_UnitSetUnitState(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetUnitState_LuaFuncDef();
  /**
   * Address: 0x008BBB90 (FUN_008BBB90, cfunc_GetScriptBit)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetScriptBitL`.
   */
  int cfunc_GetScriptBit(lua_State* luaContext);

  /**
   * Address: 0x008BBBB0 (FUN_008BBBB0, func_GetScriptBit_LuaFuncDef)
   *
   * What it does:
   * Publishes the global Lua binder definition for `GetScriptBit`.
   */
  CScrLuaInitForm* func_GetScriptBit_LuaFuncDef();

  /**
   * Address: 0x008BBC10 (FUN_008BBC10, cfunc_GetScriptBitL)
   *
   * What it does:
   * Returns true if any non-dead user unit in the input table supports `bit`
   * via toggle caps and currently has that script bit set.
   */
  int cfunc_GetScriptBitL(LuaPlus::LuaState* state);
  int cfunc_UnitGetScriptBitL(LuaPlus::LuaState* state);
  int cfunc_UnitGetScriptBit(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetScriptBit_LuaFuncDef();
  int cfunc_UnitSetScriptBitL(LuaPlus::LuaState* state);
  int cfunc_UnitSetScriptBit(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetScriptBit_LuaFuncDef();
  int cfunc_UnitToggleScriptBitL(LuaPlus::LuaState* state);
  int cfunc_UnitToggleScriptBit(lua_State* luaContext);
  CScrLuaInitForm* func_UnitToggleScriptBit_LuaFuncDef();
  int cfunc_UnitToggleFireStateL(LuaPlus::LuaState* state);
  int cfunc_UnitToggleFireState(lua_State* luaContext);
  CScrLuaInitForm* func_UnitToggleFireState_LuaFuncDef();
  int cfunc_UnitSetFireStateL(LuaPlus::LuaState* state);
  int cfunc_UnitSetFireState(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetFireState_LuaFuncDef();
  int cfunc_UnitGetFireStateL(LuaPlus::LuaState* state);
  int cfunc_UnitGetFireState(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetFireState_LuaFuncDef();
  int cfunc_UnitSetAutoMode(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetAutoMode_LuaFuncDef();
  int cfunc_UnitSetAutoModeL(LuaPlus::LuaState* state);
  int cfunc_UnitAddBuildRestriction(lua_State* luaContext);
  CScrLuaInitForm* func_UnitAddBuildRestriction_LuaFuncDef();
  int cfunc_UnitAddBuildRestrictionL(LuaPlus::LuaState* state);
  int cfunc_UnitRemoveBuildRestriction(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRemoveBuildRestriction_LuaFuncDef();
  int cfunc_UnitRemoveBuildRestrictionL(LuaPlus::LuaState* state);
  int cfunc_UnitRestoreBuildRestrictions(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRestoreBuildRestrictions_LuaFuncDef();
  int cfunc_UnitRestoreBuildRestrictionsL(LuaPlus::LuaState* state);
  int cfunc_UnitAddCommandCapL(LuaPlus::LuaState* state);
  int cfunc_UnitAddCommandCap(lua_State* luaContext);
  CScrLuaInitForm* func_UnitAddCommandCap_LuaFuncDef();
  int cfunc_UnitRemoveCommandCapL(LuaPlus::LuaState* state);
  int cfunc_UnitRemoveCommandCap(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRemoveCommandCap_LuaFuncDef();
  int cfunc_UnitRestoreCommandCapsL(LuaPlus::LuaState* state);
  int cfunc_UnitRestoreCommandCaps(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRestoreCommandCaps_LuaFuncDef();
  int cfunc_UnitAddToggleCapL(LuaPlus::LuaState* state);
  int cfunc_UnitAddToggleCap(lua_State* luaContext);
  CScrLuaInitForm* func_UnitAddToggleCap_LuaFuncDef();
  int cfunc_UnitRemoveToggleCapL(LuaPlus::LuaState* state);
  int cfunc_UnitRemoveToggleCap(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRemoveToggleCap_LuaFuncDef();
  int cfunc_UnitRestoreToggleCapsL(LuaPlus::LuaState* state);
  int cfunc_UnitRestoreToggleCaps(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRestoreToggleCaps_LuaFuncDef();
  int cfunc_UnitTestCommandCapsL(LuaPlus::LuaState* state);
  int cfunc_UnitTestCommandCaps(lua_State* luaContext);
  CScrLuaInitForm* func_UnitTestCommandCaps_LuaFuncDef();
  int cfunc_UnitTestToggleCapsL(LuaPlus::LuaState* state);
  int cfunc_UnitTestToggleCaps(lua_State* luaContext);
  CScrLuaInitForm* func_UnitTestToggleCaps_LuaFuncDef();
  /**
   * Address: 0x006D03E0 (FUN_006D03E0, cfunc_UnitCanBuild)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitCanBuildL`.
   */
  int cfunc_UnitCanBuild(lua_State* luaContext);

  /**
   * Address: 0x006D0460 (FUN_006D0460, cfunc_UnitCanBuildL)
   *
   * What it does:
   * Resolves one unit and one blueprint id string, then returns whether the
   * unit can build that blueprint according to `Unit::CanBuild`.
   */
  int cfunc_UnitCanBuildL(LuaPlus::LuaState* state);
  int cfunc_UnitGetRallyPoint(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetRallyPoint_LuaFuncDef();
  int cfunc_UnitGetRallyPointL(LuaPlus::LuaState* state);
  int cfunc_UnitGetFuelUseTime(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetFuelUseTime_LuaFuncDef();
  int cfunc_UnitGetFuelUseTimeL(LuaPlus::LuaState* state);
  int cfunc_UnitGetFuelRatio(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetFuelRatio_LuaFuncDef();
  int cfunc_UnitGetFuelRatioL(LuaPlus::LuaState* state);
  int cfunc_UnitGetShieldRatio(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetShieldRatio_LuaFuncDef();
  int cfunc_UnitGetShieldRatioL(LuaPlus::LuaState* state);
  int cfunc_UnitGetBlip(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetBlip_LuaFuncDef();
  int cfunc_UnitGetBlipL(LuaPlus::LuaState* state);
  int cfunc_UnitTransportHasSpaceFor(lua_State* luaContext);
  CScrLuaInitForm* func_UnitTransportHasSpaceFor_LuaFuncDef();
  int cfunc_UnitTransportHasSpaceForL(LuaPlus::LuaState* state);
  int cfunc_UnitTransportHasAvailableStorage(lua_State* luaContext);
  CScrLuaInitForm* func_UnitTransportHasAvailableStorage_LuaFuncDef();
  int cfunc_UnitTransportHasAvailableStorageL(LuaPlus::LuaState* state);
  int cfunc_UnitTransportDetachAllUnits(lua_State* luaContext);
  CScrLuaInitForm* func_UnitTransportDetachAllUnits_LuaFuncDef();
  int cfunc_UnitTransportDetachAllUnitsL(LuaPlus::LuaState* state);
  int cfunc_UnitShowBone(lua_State* luaContext);
  CScrLuaInitForm* func_UnitShowBone_LuaFuncDef();
  int cfunc_UnitShowBoneL(LuaPlus::LuaState* state);
  int cfunc_UnitHideBone(lua_State* luaContext);
  CScrLuaInitForm* func_UnitHideBone_LuaFuncDef();
  int cfunc_UnitHideBoneL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D08D0 (FUN_006D08D0, cfunc_UnitSetFuelUseTime)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFuelUseTimeL`.
   */
  int cfunc_UnitSetFuelUseTime(lua_State* luaContext);

  /**
   * Address: 0x006D0950 (FUN_006D0950, cfunc_UnitSetFuelUseTimeL)
   *
   * What it does:
   * Validates `(self, fuelUseTime)` and writes the unit motion fuel-use-time
   * lane; throws a Lua error when the unit has no motion object.
   */
  int cfunc_UnitSetFuelUseTimeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006D0BB0 (FUN_006D0BB0, cfunc_UnitSetFuelRatio)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFuelRatioL`.
   */
  int cfunc_UnitSetFuelRatio(lua_State* luaContext);

  /**
   * Address: 0x006D0C30 (FUN_006D0C30, cfunc_UnitSetFuelRatioL)
   *
   * What it does:
   * Validates `(self, fuelRatio)` and writes the unit fuel-ratio runtime lane;
   * throws a Lua error when the unit has no motion object.
   */
  int cfunc_UnitSetFuelRatioL(LuaPlus::LuaState* state);

  int cfunc_UnitSetShieldRatio(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetShieldRatio_LuaFuncDef();
  int cfunc_UnitSetShieldRatioL(LuaPlus::LuaState* state);
  int cfunc_UnitSetReclaimable(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetReclaimable_LuaFuncDef();
  int cfunc_UnitSetReclaimableL(LuaPlus::LuaState* state);
  int cfunc_UnitSetCapturable(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetCapturable_LuaFuncDef();
  int cfunc_UnitSetCapturableL(LuaPlus::LuaState* state);
  int cfunc_UnitIsCapturable(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsCapturable_LuaFuncDef();
  int cfunc_UnitIsCapturableL(LuaPlus::LuaState* state);
  int cfunc_UnitSetOverchargePaused(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetOverchargePaused_LuaFuncDef();
  int cfunc_UnitSetOverchargePausedL(LuaPlus::LuaState* state);
  int cfunc_UnitIsOverchargePaused(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsOverchargePaused_LuaFuncDef();
  int cfunc_UnitIsOverchargePausedL(LuaPlus::LuaState* state);
  int cfunc_UnitRevertCollisionShape(lua_State* luaContext);
  CScrLuaInitForm* func_UnitRevertCollisionShape_LuaFuncDef();
  int cfunc_UnitRevertCollisionShapeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006CB580 (FUN_006CB580, cfunc_UnitRecoilImpulse)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitRecoilImpulseL`.
   */
  int cfunc_UnitRecoilImpulse(lua_State* luaContext);

  CScrLuaInitForm* func_UnitRecoilImpulse_LuaFuncDef();
  int cfunc_UnitGetCurrentLayer(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetCurrentLayer_LuaFuncDef();
  int cfunc_UnitGetCurrentLayerL(LuaPlus::LuaState* state);
  int cfunc_UnitCanPathTo(lua_State* luaContext);
  CScrLuaInitForm* func_UnitCanPathTo_LuaFuncDef();
  int cfunc_UnitCanPathToL(LuaPlus::LuaState* state);
  int cfunc_UnitRecoilImpulseL(LuaPlus::LuaState* state);
  int cfunc_UnitCanPathToRectL(LuaPlus::LuaState* state);
  int cfunc_UnitCanPathToRect(lua_State* luaContext);
  CScrLuaInitForm* func_UnitCanPathToRect_LuaFuncDef();
  int cfunc_UnitIsMobile(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsMobile_LuaFuncDef();
  int cfunc_UnitIsMobileL(LuaPlus::LuaState* state);
  int cfunc_UnitIsMoving(lua_State* luaContext);
  CScrLuaInitForm* func_UnitIsMoving_LuaFuncDef();
  int cfunc_UnitIsMovingL(LuaPlus::LuaState* state);
  int cfunc_UnitGetNavigator(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetNavigator_LuaFuncDef();
  int cfunc_UnitGetNavigatorL(LuaPlus::LuaState* state);
  int cfunc_UnitGetVelocity(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetVelocity_LuaFuncDef();
  int cfunc_UnitGetVelocityL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006CC5A0 (FUN_006CC5A0, cfunc_UnitGetStat)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetStatL`.
   */
  int cfunc_UnitGetStat(lua_State* luaContext);

  /**
   * Address: 0x006CC5C0 (FUN_006CC5C0, func_UnitGetStat_LuaFuncDef)
   *
   * What it does:
   * Publishes `Unit:GetStat(name[, defaultValue])` Lua binder definition.
   */
  CScrLuaInitForm* func_UnitGetStat_LuaFuncDef();

  /**
   * Address: 0x006CC620 (FUN_006CC620, cfunc_UnitGetStatL)
   *
   * What it does:
   * Resolves one unit stat path and returns the stat node as a Lua table.
   */
  int cfunc_UnitGetStatL(LuaPlus::LuaState* state);

  template <>
  class CScrLuaMetatableFactory<Unit> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<Unit>) == 0x08, "CScrLuaMetatableFactory<Unit> size must be 0x08");
} // namespace moho

namespace
{
  // Guard condition recovered from Unit::ToggleScriptBit: state 14 == UNITSTATE_Attached.
  constexpr EUnitState kTransportScriptBitGuardState = UNITSTATE_Attached;
  constexpr std::uint32_t kCommandCapPause = 0x00020000u;  // RULEUCC_Pause
  constexpr std::uint32_t kToggleCapGeneric = 0x00000040u; // RULEUTC_GenericToggle
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedArgsRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kUnitGetCargoName = "GetCargo";
  constexpr const char* kUnitGetCargoHelpText = "GetCargo(self)";
  constexpr const char* kUnitAlterArmorName = "AlterArmor";
  constexpr const char* kUnitAlterArmorHelpText = "Unit:AlterArmor(damageTypeName, multiplier)";
  constexpr const char* kUnitGetArmorMultName = "GetArmorMult";
  constexpr const char* kUnitGetArmorMultHelpText = "mult = Unit:GetArmorMult(damageTypeName)";
  constexpr std::uint8_t kArmorMapColorRed = 0u;
  constexpr std::uint8_t kArmorMapColorBlack = 1u;
  constexpr std::uint32_t kArmorMapMaxSize = 0x07FFFFFEu;
  constexpr const char* kUnitClearFocusEntityName = "ClearFocusEntity";
  constexpr const char* kUnitClearFocusEntityHelpText = "ClearFocusEntity(self)";
  constexpr const char* kUnitSetFocusEntityName = "SetFocusEntity";
  constexpr const char* kUnitSetFocusEntityHelpText = "SetFocusUnit(self, focus)";
  constexpr const char* kUnitGetFocusUnitName = "GetFocusUnit";
  constexpr const char* kUnitGetFocusUnitHelpText = "GetFocusUnit(self)";
  constexpr const char* kUnitOnAssignedFocusEntityScript = "OnAssignedFocusEntity";
  constexpr const char* kUnitGetWeaponName = "GetWeapon";
  constexpr const char* kUnitGetWeaponHelpText =
    "GetWeapon(self,index) -- return the index'th weapon of this unit. Index must be between 1 and self:GetWeaponCount(), inclusive.";
  constexpr const char* kUnitGetWeaponInvalidIndexError =
    "Invalid weapon index %d; must be between 1 and %d (inclusive)";
  constexpr const char* kUnitGetWeaponCountName = "GetWeaponCount";
  constexpr const char* kUnitGetWeaponCountHelpText =
    "GetWeaponCount(self) -- return the number of weapons on this unit. Note that dummy weapons are not included in the count, so this may differ from the number of weapons defined in the unit's blueprint.";
  constexpr const char* kUnitGetTargetEntityName = "GetTargetEntity";
  constexpr const char* kUnitGetTargetEntityHelpText = "Return our target unit if we have one";
  constexpr const char* kUnitGetHealthName = "GetHealth";
  constexpr const char* kUnitGetHealthHelpText = "GetHealth(self)";
  constexpr const char* kUnitGetAttackerName = "GetAttacker";
  constexpr const char* kUnitGetAttackerHelpText = "GetAttacker() - get the tactical attack manager object of this unit";
  constexpr const char* kUnitEnableManipulatorsName = "EnableManipulators";
  constexpr const char* kUnitEnableManipulatorsHelpText =
    "Unit:EnableManipulators([string boneName | int boneIndex], bool Enable)";
  constexpr const char* kUnitKillManipulatorName = "KillManipulator";
  constexpr const char* kUnitKillManipulatorHelpText = "Kill a specific manipulator held by a script object";
  constexpr const char* kUnitKillManipulatorsName = "KillManipulators";
  constexpr const char* kUnitKillManipulatorsHelpText = "Unit:KillManipulators([boneName|boneIndex])";
  constexpr const char* kUnitScaleGetBuiltEmitterName = "ScaleGetBuiltEmitter";
  constexpr const char* kUnitScaleGetBuiltEmitterHelpText = "ScaleGetBuiltEmitter(self, emitter)";
  constexpr const char* kUnitSetStrategicUnderlayName = "SetStrategicUnderlay";
  constexpr const char* kUnitSetStrategicUnderlayHelpText = "SetStrategicUnderlay(icon)";
  constexpr const char* kSetFireStateName = "SetFireState";
  constexpr const char* kSetFireStateArgsHelpText = "SetFireState(units, newFireState)";
  constexpr const char* kSetFireStateBindHelpText = "Set the specific fire state for the units passed in";
  constexpr const char* kToggleFireStateGlobalName = "ToggleFireState";
  constexpr const char* kToggleFireStateGlobalArgsHelpText = "ToggleFireState(units, currentFireState)";
  constexpr const char* kToggleFireStateGlobalBindHelpText = "Set the right fire state for the units passed in";
  constexpr const char* kGetFireStateName = "GetFireState";
  constexpr const char* kGetFireStateArgsHelpText = "GetFireState(units)";
  constexpr const char* kGetFireStateBindHelpText = "Get the right fire state for the units passed in";
  constexpr const char* kGetIsPausedGlobalName = "GetIsPaused";
  constexpr const char* kGetIsPausedGlobalHelpText = "Is anyone ins this list builder paused?";
  constexpr const char* kGetIsAutoModeGlobalName = "GetIsAutoMode";
  constexpr const char* kGetIsAutoModeGlobalHelpText = "See if anyone in the list is auto building";
  constexpr const char* kGetIsSubmergedGlobalName = "GetIsSubmerged";
  constexpr const char* kGetIsSubmergedGlobalHelpText =
    "Determine if units are submerged (-1), not submerged(1) or unable to tell (0)";
  constexpr const char* kGetIsAutoSurfaceModeGlobalName = "GetIsAutoSurfaceMode";
  constexpr const char* kGetIsAutoSurfaceModeGlobalHelpText = "See if anyone in the list is auto surfacing";
  constexpr const char* kUnitGetCommandQueueName = "GetCommandQueue";
  constexpr const char* kUnitGetCommandQueueHelpText = "Unit:GetCommandQueue()";
  constexpr const char* kUnitGetCommandQueueInvalidUnitError = "UnitScript:GetCommandQueue Passed in an invalid unit";
  constexpr const char* kUnitGetCommandQueueInvalidQueueError = "UnitScript:GetCommandQueue invalid UnitCommandQueue";
  constexpr const char* kUnitPrintCommandQueueName = "PrintCommandQueue";
  constexpr const char* kUnitPrintCommandQueueHelpText = "Unit:PrintCommandQueue()";
  constexpr const char* kUnitPrintCommandQueueHeaderLogFormat = "*AI DEBUG: Command List for %s: \n";
  constexpr const char* kUnitPrintCommandQueueEntryLogFormat = "*AI DEBUG: %s\n";
  constexpr const char* kUnitPrintCommandQueueUnknownCommandName = "Bad Command";
  constexpr const char* kUnitGetGuardedUnitName = "GetGuardedUnit";
  constexpr const char* kUnitGetGuardedUnitHelpText = "Unit:GetGuardedUnit()";
  constexpr const char* kUnitGetGuardsName = "GetGuards";
  constexpr const char* kUnitGetGuardsHelpText = "Unit:GetGuards()";
  constexpr const char* kUnitGetTransportFerryBeaconName = "GetTransportFerryBeacon";
  constexpr const char* kUnitGetTransportFerryBeaconHelpText = "Unit:GetTransportFerryBeacon()";
  constexpr const char* kUnitHasValidTeleportDestName = "HasValidTeleportDest";
  constexpr const char* kUnitHasValidTeleportDestHelpText = "Unit:HasValidTeleportDest()";
  constexpr const char* kUnitAddUnitToStorageName = "AddUnitToStorage";
  constexpr const char* kUnitAddUnitToStorageHelpText = "Unit:AddUnitToStorage( storedUnit )";
  constexpr const char* kUnitAddUnitToStorageNoRoomWarning = "No more room available in carrier for unit to be stored";
  constexpr const char* kUnitGetCurrentMoveLocationName = "GetCurrentMoveLocation";
  constexpr const char* kUnitGetCurrentMoveLocationHelpText = "Unit:GetCurrentMoveLocation()";
  constexpr const char* kUnitGetCurrentMoveLocationInvalidUnitError =
    "UnitScript:GetCurrentMoveLocation Passed in an invalid unit";
  constexpr const char* kUnitGiveNukeSiloAmmoName = "GiveNukeSiloAmmo";
  constexpr const char* kUnitGiveNukeSiloAmmoHelpText = "Unit:GiveNukeSiloAmmo(num)";
  constexpr const char* kUnitRemoveNukeSiloAmmoName = "RemoveNukeSiloAmmo";
  constexpr const char* kUnitRemoveNukeSiloAmmoHelpText = "Unit:RemoveNukeSiloAmmo(num)";
  constexpr const char* kUnitGetNukeSiloAmmoCountName = "GetNukeSiloAmmoCount";
  constexpr const char* kUnitGetNukeSiloAmmoCountHelpText = "Unit:GetNukeSiloAmmoCount()";
  constexpr const char* kUnitGiveTacticalSiloAmmoName = "GiveTacticalSiloAmmo";
  constexpr const char* kUnitGiveTacticalSiloAmmoHelpText = "Unit:GiveTacticalSiloAmmo(num)";
  constexpr const char* kUnitRemoveTacticalSiloAmmoName = "RemoveTacticalSiloAmmo";
  constexpr const char* kUnitRemoveTacticalSiloAmmoHelpText = "Unit:RemoveTacticalSiloAmmo(num)";
  constexpr const char* kUnitGetTacticalSiloAmmoCountName = "GetTacticalSiloAmmoCount";
  constexpr const char* kUnitGetTacticalSiloAmmoCountHelpText = "Unit:GetTacticalSiloAmmoCount()";
  constexpr const char* kUnitIsIdleStateName = "IsIdleState";
  constexpr const char* kUnitIsIdleStateHelpText = "IsIdleState(unit)";
  constexpr const char* kUnitIsStunnedName = "IsStunned";
  constexpr const char* kUnitIsStunnedHelpText = "IsStunned(unit)";
  constexpr const char* kUnitIsBeingBuiltName = "IsBeingBuilt";
  constexpr const char* kUnitIsBeingBuiltHelpText = "Unit:IsBeingBuilt()";
  constexpr const char* kUnitIsPausedName = "IsPaused";
  constexpr const char* kUnitIsPausedHelpText = "Unit:IsPaused()";
  constexpr const char* kUnitSetPausedName = "SetPaused";
  constexpr const char* kUnitSetPausedHelpText = "Unit:SetPaused()";
  constexpr const char* kUnitSetConsumptionActiveName = "SetConsumptionActive";
  constexpr const char* kUnitSetConsumptionActiveHelpText = "Unit:SetConsumptionActive(flag)";
  constexpr const char* kUnitSetConsumptionPerSecondEnergyName = "SetConsumptionPerSecondEnergy";
  constexpr const char* kUnitSetConsumptionPerSecondEnergyHelpText =
    "unit:SetConsumptionPerSecondEnergy(value) -- Set the consumption of energy of a unit";
  constexpr const char* kUnitSetConsumptionPerSecondMassName = "SetConsumptionPerSecondMass";
  constexpr const char* kUnitSetConsumptionPerSecondMassHelpText = "Set the consumption of mass of the unit";
  constexpr const char* kUnitSetRegenRateName = "SetRegenRate";
  constexpr const char* kUnitSetRegenRateHelpText = "unit:SetRegenRate(rate) -- Set the regen rate of a unit.";
  constexpr const char* kUnitRevertRegenRateName = "RevertRegenRate";
  constexpr const char* kUnitRevertRegenRateHelpText = "Restore regen rate of the unit back to blueprint spec.";
  constexpr const char* kUnitSetBuildRateName = "SetBuildRate";
  constexpr const char* kUnitSetBuildRateHelpText =
    "unit:SetBuildRate(frac) -- Set the build rate of a unit: what fraction of target unit it builds per second.";
  constexpr const char* kUnitGetBuildRateName = "GetBuildRate";
  constexpr const char* kUnitGetBuildRateHelpText =
    "unit:GetBuildRate() -- returns the build rate of a unit: what fraction of target unit it builds per second.";
  constexpr const char* kUnitSetProductionPerSecondEnergyName = "SetProductionPerSecondEnergy";
  constexpr const char* kUnitSetProductionPerSecondEnergyHelpText = "Set the production of energy of the unit";
  constexpr const char* kUnitSetProductionPerSecondMassName = "SetProductionPerSecondMass";
  constexpr const char* kUnitSetProductionPerSecondMassHelpText = "Set the production of mass of the unit";
  constexpr const char* kUnitGetConsumptionPerSecondEnergyName = "GetConsumptionPerSecondEnergy";
  constexpr const char* kUnitGetConsumptionPerSecondEnergyHelpText = "Get the consumption of energy of the unit";
  constexpr const char* kUnitGetConsumptionPerSecondMassName = "GetConsumptionPerSecondMass";
  constexpr const char* kUnitGetConsumptionPerSecondMassHelpText = "Get the consumption of mass of the unit";
  constexpr const char* kUnitGetProductionPerSecondEnergyName = "GetProductionPerSecondEnergy";
  constexpr const char* kUnitGetProductionPerSecondEnergyHelpText = "Get the production of energy of the unit";
  constexpr const char* kUnitGetProductionPerSecondMassName = "GetProductionPerSecondMass";
  constexpr const char* kUnitGetProductionPerSecondMassHelpText = "Get the production of mass of the unit";
  constexpr const char* kUnitGetResourceConsumedName = "GetResourceConsumed";
  constexpr const char* kUnitGetResourceConsumedHelpText =
    "Return the fraction of requested resources this unit consumed last tick. Normally 1, but can be fractional if economy is struggling.";
  constexpr const char* kUnitSetElevationName = "SetElevation";
  constexpr const char* kUnitSetElevationHelpText = "Set the elevation of the unit";
  constexpr const char* kUnitRevertElevationName = "RevertElevation";
  constexpr const char* kUnitRevertElevationHelpText = "Revert the elevation of the unit back to the blueperint spec";
  constexpr const char* kUnitSetSpeedMultName = "SetSpeedMult";
  constexpr const char* kUnitSetSpeedMultHelpText = "Set the speed multiplier of the unit";
  constexpr const char* kUnitSetAccMultName = "SetAccMult";
  constexpr const char* kUnitSetAccMultHelpText = "Set the acceleration multiplier of the unit";
  constexpr const char* kUnitSetTurnMultName = "SetTurnMult";
  constexpr const char* kUnitSetTurnMultHelpText = "Set the turn multiplier of the unit";
  constexpr const char* kUnitSetBreakOffTriggerMultName = "SetBreakOffTriggerMult";
  constexpr const char* kUnitSetBreakOffTriggerMultHelpText = "Set the break off trigger multiplier of the unit";
  constexpr const char* kUnitSetBreakOffDistanceMultName = "SetBreakOffDistanceMult";
  constexpr const char* kUnitSetBreakOffDistanceMultHelpText = "Set the break off distance multiplier of the unit";
  constexpr const char* kUnitSetWorkProgressName = "SetWorkProgress";
  constexpr const char* kUnitSetWorkProgressHelpText = "SetWorkProgress(float)";
  constexpr const char* kUnitIsUnitStateName = "IsUnitState";
  constexpr const char* kUnitIsUnitStateHelpText = "IsUnitState(unit, stateName)";
  constexpr const char* kUnitToggleFireStateName = "ToggleFireState";
  constexpr const char* kUnitToggleFireStateHelpText = "Toggle the fire state for the retaliation state of the unit";
  constexpr const char* kUnitSetFireStateHelpText = "Set a specific fire state for the retaliation state of the unit";
  constexpr const char* kUnitGetFireStateName = "GetFireState";
  constexpr const char* kUnitGetFireStateHelpText = "Get the fire state for the unit";
  constexpr const char* kUnitSetAutoModeName = "SetAutoMode";
  constexpr const char* kUnitSetAutoModeHelpText = "Set auto silo build mode to on/off";
  constexpr const char* kUnitAddBuildRestrictionName = "AddBuildRestriction";
  constexpr const char* kUnitAddBuildRestrictionHelpText = "Disallow building of these categories for this unit";
  constexpr const char* kUnitRemoveBuildRestrictionName = "RemoveBuildRestriction";
  constexpr const char* kUnitRemoveBuildRestrictionHelpText = "Allow building of categories for this unit";
  constexpr const char* kUnitRestoreBuildRestrictionsName = "RestoreBuildRestrictions";
  constexpr const char* kUnitRestoreBuildRestrictionsHelpText =
    "Restore buildable categories to that as defined in the blueprint";
  constexpr const char* kUnitSetProductionActiveName = "SetProductionActive";
  constexpr const char* kUnitSetProductionActiveHelpText = "Unit:SetProductionActive(flag)";
  constexpr const char* kUnitSetBusyName = "SetBusy";
  constexpr const char* kUnitSetBusyHelpText = "SetBusy(unit, flag)";
  constexpr const char* kUnitSetBlockCommandQueueName = "SetBlockCommandQueue";
  constexpr const char* kUnitSetBlockCommandQueueHelpText = "SetBlockCommandQueue(unit, flag)";
  constexpr const char* kUnitSetImmobileName = "SetImmobile";
  constexpr const char* kUnitSetImmobileHelpText = "SetImmobile(unit, flag)";
  constexpr const char* kUnitSetUnSelectableName = "SetUnSelectable";
  constexpr const char* kUnitSetUnSelectableHelpText = "SetUnSelectable(unit, flag)";
  constexpr const char* kUnitSetDoNotTargetName = "SetDoNotTarget";
  constexpr const char* kUnitSetDoNotTargetHelpText = "SetDoNotTarget(unit, flag)";
  constexpr const char* kUnitStopSiloBuildName = "StopSiloBuild";
  constexpr const char* kUnitStopSiloBuildHelpText = "StopSiloBuild(unit)";
  constexpr const char* kUnitSetIsValidTargetName = "SetIsValidTarget";
  constexpr const char* kUnitSetIsValidTargetHelpText = "SetIsValidTarget(self,bool)";
  constexpr const char* kUnitIsValidTargetName = "IsValidTarget";
  constexpr const char* kUnitIsValidTargetHelpText = "bool = IsValidTarget(self)";
  constexpr const char* kUnitGetNumBuildOrdersName = "GetNumBuildOrders";
  constexpr const char* kUnitGetNumBuildOrdersHelpText =
    "Get number of factory/engineer build orders that fit in the specified category";
  constexpr const char* kUnitCalculateWorldPositionFromRelativeName = "CalculateWorldPositionFromRelative";
  constexpr const char* kUnitCalculateWorldPositionFromRelativeHelpText =
    "Calculate the desired world position from the supplied relative vector from the center of the unit";
  constexpr const char* kUnitSetStunnedName = "SetStunned";
  constexpr const char* kUnitSetStunnedHelpText = "SetStunned(unit, time)";
  constexpr const char* kUnitSetUnitStateName = "SetUnitState";
  constexpr const char* kUnitSetUnitStateHelpText = "SetUnitState(name, bool)";
  constexpr const char* kUnitCanBuildName = "CanBuild";
  constexpr const char* kUnitCanBuildHelpText = "CanBuild(self, blueprint";
  constexpr const char* kUnitCanBuildUnknownBlueprintError = "Unknown unit blueprint id: %s";
  constexpr const char* kUnitGetRallyPointName = "GetRallyPoint";
  constexpr const char* kUnitGetRallyPointHelpText = "Get the rally point for the factory";
  constexpr const char* kUnitGetFuelUseTimeName = "GetFuelUseTime";
  constexpr const char* kUnitGetFuelUseTimeHelpText = "Get the fuel use time";
  constexpr const char* kUnitGetFuelRatioName = "GetFuelRatio";
  constexpr const char* kUnitGetFuelRatioHelpText = "Get the fuel ratio";
  constexpr const char* kUnitGetShieldRatioName = "GetShieldRatio";
  constexpr const char* kUnitGetShieldRatioHelpText = "Get the shield ratio";
  constexpr const char* kUnitGetBlipName = "GetBlip";
  constexpr const char* kUnitGetBlipHelpText =
    "blip = GetBlip(armyIndex) - returns a blip (if any) that the given army has for the unit";
  constexpr const char* kUnitTransportHasSpaceForName = "TransportHasSpaceFor";
  constexpr const char* kUnitTransportHasSpaceForHelpText = "TransportHasSpaceFor(self,target)";
  constexpr const char* kUnitTransportHasAvailableStorageName = "TransportHasAvailableStorage";
  constexpr const char* kUnitTransportHasAvailableStorageHelpText = "TransportHasAvailableStorage(self)";
  constexpr const char* kUnitTransportDetachAllUnitsName = "TransportDetachAllUnits";
  constexpr const char* kUnitTransportDetachAllUnitsHelpText = "DetachAllUnits(self,destroySomeUnits)";
  constexpr const char* kUnitTransportDetachAllUnitsTransportError =
    "Unit:TransportDetachAllUnits can only be called for transports";
  constexpr const char* kUnitShowBoneName = "ShowBone";
  constexpr const char* kUnitShowBoneHelpText = "ShowBone(self,bone,affectChildren)";
  constexpr const char* kUnitHideBoneName = "HideBone";
  constexpr const char* kUnitHideBoneHelpText = "HideBone(self,bone,affectChildren)";
  constexpr const char* kUnitSetFuelUseTimeName = "SetFuelUseTime";
  constexpr const char* kUnitSetFuelUseTimeHelpText = "Set the fuel use time";
  constexpr const char* kUnitSetFuelRatioName = "SetFuelRatio";
  constexpr const char* kUnitSetFuelRatioHelpText = "Set the fuel ratio";
  constexpr const char* kUnitSetCustomNameName = "SetCustomName";
  constexpr const char* kUnitSetCustomNameHelpText = "Unit:SetCustomName(name)";
  constexpr const char* kUnitSetShieldRatioName = "SetShieldRatio";
  constexpr const char* kUnitSetShieldRatioHelpText = "Set the shield ratio";
  constexpr const char* kUnitGetScriptBitHelpText = "GetScriptBit(units, bit)";
  constexpr const char* kUnitGetScriptBitName = "GetScriptBit";
  constexpr const char* kUnitGetScriptBitMethodHelpText = "Get the current toggle state of the script bit that matches the string";
  constexpr const char* kUnitSetScriptBitName = "SetScriptBit";
  constexpr const char* kUnitSetScriptBitHelpText = "Set the script bit that matches the string to the desired state";
  constexpr const char* kUnitToggleScriptBitName = "ToggleScriptBit";
  constexpr const char* kUnitToggleScriptBitHelpText = "Toggle the script bit that matches the string";
  constexpr const char* kUnitAddCommandCapName = "AddCommandCap";
  constexpr const char* kUnitAddCommandCapHelpText = "unit:AddCommandCap(capName) -- Add a command cap to a unit.";
  constexpr const char* kUnitRemoveCommandCapName = "RemoveCommandCap";
  constexpr const char* kUnitRemoveCommandCapHelpText =
    "unit:RemoveCommandCap(capName) -- Remove a command cap to a unit.";
  constexpr const char* kUnitRestoreCommandCapsName = "RestoreCommandCaps";
  constexpr const char* kUnitRestoreCommandCapsHelpText =
    "Restore the command caps of the unit back to blueprint spec.";
  constexpr const char* kUnitAddToggleCapName = "AddToggleCap";
  constexpr const char* kUnitAddToggleCapHelpText = "unit:AddToggleCap(capName) -- Add a toggle cap to a unit.";
  constexpr const char* kUnitRemoveToggleCapName = "RemoveToggleCap";
  constexpr const char* kUnitRemoveToggleCapHelpText =
    "unit:RemoveToggleCap(capName) -- Remove a toggle cap to a unit.";
  constexpr const char* kUnitRestoreToggleCapsName = "RestoreToggleCaps";
  constexpr const char* kUnitRestoreToggleCapsHelpText =
    "Restore the toggle caps of the unit back to blueprint spec.";
  constexpr const char* kUnitTestCommandCapsName = "TestCommandCaps";
  constexpr const char* kUnitTestCommandCapsHelpText =
    "Test if a unit has this specified set to true in the blueprint spec.";
  constexpr const char* kUnitTestToggleCapsName = "TestToggleCaps";
  constexpr const char* kUnitTestToggleCapsHelpText =
    "Test if a unit has this specified set to true in the blueprint spec.";
  constexpr const char* kUnitRecoilImpulseName = "RecoilImpulse";
  constexpr const char* kUnitRecoilImpulseHelpText = "RecoilImpulse(self, x, y, z)";
  constexpr const char* kUnitGetUnitIdName = "GetUnitId";
  constexpr const char* kUnitGetUnitIdHelpText = "GetUnitId(self)";
  constexpr const char* kUnitSetCreatorName = "SetCreator";
  constexpr const char* kUnitSetCreatorHelpText = "Set the creator for this unit";
  constexpr const char* kUnitGetCurrentLayerName = "GetCurrentLayer";
  constexpr const char* kUnitGetCurrentLayerHelpText = "GetUnitId(self)";
  constexpr const char* kUnitCanPathToName = "CanPathTo";
  constexpr const char* kUnitCanPathToHelpText = "See if the unit can path to the goal";
  constexpr const char* kUnitCanPathToRectName = "CanPathToRect";
  constexpr const char* kUnitCanPathToRectHelpText = "See if the unit can path to the goal rectangle";
  constexpr const char* kUnitSetReclaimableName = "SetReclaimable";
  constexpr const char* kUnitSetReclaimableHelpText = "Set if this unit can be reclaimed or not.";
  constexpr const char* kUnitSetCapturableName = "SetCapturable";
  constexpr const char* kUnitSetCapturableHelpText = "Set if this unit can be captured or not.";
  constexpr const char* kUnitIsCapturableName = "IsCapturable";
  constexpr const char* kUnitIsCapturableHelpText = "Returns if this unit can be captured or not";
  constexpr const char* kUnitSetOverchargePausedName = "SetOverchargePaused";
  constexpr const char* kUnitSetOverchargePausedHelpText = "Set if this unit has an overcharge pasued.";
  constexpr const char* kUnitIsOverchargePausedName = "IsOverchargePaused";
  constexpr const char* kUnitIsOverchargePausedHelpText = "Returns if this unit has its overcharge paused";
  constexpr const char* kUnitRevertCollisionShapeName = "RevertCollisionShape";
  constexpr const char* kUnitRevertCollisionShapeHelpText = "Revert the collision shape to the blueprint spec";
  constexpr const char* kUnitIsMobileName = "IsMobile";
  constexpr const char* kUnitIsMobileHelpText = "bool IsMobile() - Is this a mobile unit?";
  constexpr const char* kUnitIsMovingName = "IsMoving";
  constexpr const char* kUnitIsMovingHelpText = "bool IsMoving() - Is this unit moving?";
  constexpr const char* kUnitGetNavigatorName = "GetNavigator";
  constexpr const char* kUnitGetNavigatorHelpText = "GetNavigator() - get the navigator object of this unit";
  constexpr const char* kUnitGetVelocityName = "GetVelocity";
  constexpr const char* kUnitGetVelocityHelpText = "GetVelocity() -> x,y,z";
  constexpr const char* kUnitGetStatName = "GetStat";
  constexpr const char* kUnitGetStatHelpText = "GetStat(Name[,defaultVal])";
  constexpr const char* kUnitSetStatName = "SetStat";
  constexpr const char* kUnitSetStatHelpText = "SetStat(Name, Value)";
  constexpr const char* kUnitGetWorkProgressName = "GetWorkProgress";
  constexpr const char* kUnitGetWorkProgressHelpText = "GetWorkProgress()";
  constexpr std::uint8_t kUnitGetStatHoverOccupancyCaps = static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER) |
    static_cast<std::uint8_t>(EOccupancyCaps::OC_LAND);
  constexpr std::uint8_t kUnitGetStatWaterOccupancyCaps = static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER);
  constexpr float kUnitGetStatWaterOnlyMaxWaterDepth = 1.5f;
  REntityBlueprint* gUnitGetStatOriginalBlueprint = nullptr;
  RUnitBlueprint gUnitGetStatBlueprint{};
  constexpr const char* kUnitGetCargoTransportOnlyText = "Unit:GetCargo only valid for transport units";
  constexpr const char* kUnitOnProductionActiveScript = "OnProductionActive";
  constexpr const char* kUnitOnProductionInactiveScript = "OnProductionInActive";
  constexpr const char* kUnitLuaClassName = "Unit";
  constexpr const char* kGlobalLuaClassName = "<global>";
  constexpr std::uintptr_t kInvalidWeakCommandSentinel = 4u;

  [[nodiscard]] bool BlueprintHasOccupancyCaps(const REntityBlueprint* const blueprint, const std::uint8_t caps) noexcept
  {
    return blueprint != nullptr && static_cast<std::uint8_t>(blueprint->mFootprint.mOccupancyCaps) == caps;
  }

  void RefreshUnitGetStatBlueprintSnapshot(Unit& unit)
  {
    gUnitGetStatOriginalBlueprint = unit.BluePrint;

    if (const RUnitBlueprint* const unitBlueprint = unit.BluePrint->IsUnitBlueprint(); unitBlueprint != nullptr) {
      gUnitGetStatBlueprint = *unitBlueprint;
    } else {
      static_cast<REntityBlueprint&>(gUnitGetStatBlueprint) = *unit.BluePrint;
    }

    gUnitGetStatBlueprint.mFootprint.mOccupancyCaps = EOccupancyCaps::OC_WATER;
    gUnitGetStatBlueprint.mFootprint.mFlags = EFootprintFlags::FPFLAG_None;
    gUnitGetStatBlueprint.mFootprint.mMaxWaterDepth = kUnitGetStatWaterOnlyMaxWaterDepth;
  }

  void ApplyUnitGetStatH1BlueprintOverride(Unit& unit, const int defaultValue)
  {
    if (!BlueprintHasOccupancyCaps(gUnitGetStatOriginalBlueprint, kUnitGetStatHoverOccupancyCaps)) {
      RefreshUnitGetStatBlueprintSnapshot(unit);
    }

    if (defaultValue != 0) {
      if (!BlueprintHasOccupancyCaps(unit.BluePrint, kUnitGetStatHoverOccupancyCaps)) {
        unit.BluePrint = gUnitGetStatOriginalBlueprint;
      }
      return;
    }

    if (!BlueprintHasOccupancyCaps(unit.BluePrint, kUnitGetStatWaterOccupancyCaps)) {
      unit.BluePrint = &gUnitGetStatBlueprint;
    }
  }

  [[nodiscard]] const char* UnitCommandTypeDebugName(const EUnitCommandType commandType) noexcept
  {
    switch (commandType) {
      case EUnitCommandType::UNITCOMMAND_None:
        return "None";
      case EUnitCommandType::UNITCOMMAND_Stop:
        return "Stop";
      case EUnitCommandType::UNITCOMMAND_Move:
        return "Move";
      case EUnitCommandType::UNITCOMMAND_Dive:
        return "Dive";
      case EUnitCommandType::UNITCOMMAND_FormMove:
        return "FormMove";
      case EUnitCommandType::UNITCOMMAND_BuildSiloTactical:
        return "BuildSiloTactical";
      case EUnitCommandType::UNITCOMMAND_BuildSiloNuke:
        return "BuildSiloNuke";
      case EUnitCommandType::UNITCOMMAND_BuildFactory:
        return "BuildFactory";
      case EUnitCommandType::UNITCOMMAND_BuildMobile:
        return "BuildMobile ";
      case EUnitCommandType::UNITCOMMAND_BuildAssist:
        return "BuildAssist";
      case EUnitCommandType::UNITCOMMAND_Attack:
        return "Attack";
      case EUnitCommandType::UNITCOMMAND_FormAttack:
        return "FormAttack";
      case EUnitCommandType::UNITCOMMAND_Nuke:
        return "Nuke";
      case EUnitCommandType::UNITCOMMAND_Tactical:
        return "Tactical";
      case EUnitCommandType::UNITCOMMAND_Teleport:
        return "Teleport";
      case EUnitCommandType::UNITCOMMAND_Guard:
        return "Guard";
      case EUnitCommandType::UNITCOMMAND_Patrol:
        return "Patrol";
      case EUnitCommandType::UNITCOMMAND_Ferry:
        return "Ferry";
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
        return "FormPatrol";
      case EUnitCommandType::UNITCOMMAND_Reclaim:
        return "Reclaim";
      case EUnitCommandType::UNITCOMMAND_Repair:
        return "Repair";
      case EUnitCommandType::UNITCOMMAND_Capture:
        return "Capture";
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
        return "TransportLoadUnits";
      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits:
        return "TransportReverseLoadUnits";
      case EUnitCommandType::UNITCOMMAND_TransportUnloadUnits:
        return "TransportUnloadUnits";
      case EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits:
        return "TransportUnloadSpecificUnits";
      case EUnitCommandType::UNITCOMMAND_DetachFromTransport:
        return "DetachFromTransport";
      case EUnitCommandType::UNITCOMMAND_Upgrade:
        return "Upgrade";
      case EUnitCommandType::UNITCOMMAND_Script:
        return "Script";
      case EUnitCommandType::UNITCOMMAND_AssistCommander:
        return "AssistCommander";
      case EUnitCommandType::UNITCOMMAND_KillSelf:
        return "KillSelf";
      case EUnitCommandType::UNITCOMMAND_DestroySelf:
        return "DestroySelf";
      case EUnitCommandType::UNITCOMMAND_Sacrifice:
        return "Sacrifice";
      case EUnitCommandType::UNITCOMMAND_Pause:
        return "Pause";
      case EUnitCommandType::UNITCOMMAND_OverCharge:
        return "OverCharge";
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
        return "AggressiveMove";
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
        return "FormAggressiveMove";
      case EUnitCommandType::UNITCOMMAND_AssistMove:
        return "AssistMove";
      case EUnitCommandType::UNITCOMMAND_SpecialAction:
        return "SpecialAction";
      case EUnitCommandType::UNITCOMMAND_Dock:
        return "Dock";
      default:
        return kUnitPrintCommandQueueUnknownCommandName;
    }
  }

  [[nodiscard]] std::string BuildPrintCommandQueueLabel(const CUnitCommand& command)
  {
    std::string label = UnitCommandTypeDebugName(command.mVarDat.mCmdType);
    if (command.mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_BuildMobile) {
      if (const REntityBlueprint* const blueprint = command.mConstDat.blueprint; blueprint != nullptr) {
        const char* const blueprintName = blueprint->mBlueprintId.c_str();
        if (blueprintName != nullptr && blueprintName[0] != '\0') {
          label.append(blueprintName);
        }
      }
    }
    return label;
  }

  [[nodiscard]] Entity* DecodeGuardedByOwnerSlot(const SGuardedByWeakOwnerSlot slot) noexcept
  {
    if (slot.ownerLinkSlot == nullptr) {
      return nullptr;
    }

    constexpr std::uintptr_t kGuardedByOwnerDecodeOffset = 0x8u;
    const std::uintptr_t encoded = reinterpret_cast<std::uintptr_t>(slot.ownerLinkSlot);
    if (encoded <= kGuardedByOwnerDecodeOffset) {
      return nullptr;
    }

    return reinterpret_cast<Entity*>(encoded - kGuardedByOwnerDecodeOffset);
  }

  [[nodiscard]] CAniPoseBone* ResolveUnitPoseBone(Unit& unit, const int boneIndex) noexcept
  {
    if (unit.AniActor == nullptr || unit.AniActor->mPose.px == nullptr || boneIndex < 0) {
      return nullptr;
    }

    CAniPose* const pose = unit.AniActor->mPose.px;
    CAniPoseBone* const bonesBegin = pose->mBones.begin();
    CAniPoseBone* const bonesEnd = pose->mBones.end();
    if (bonesBegin == nullptr || bonesEnd == nullptr || bonesBegin > bonesEnd) {
      return nullptr;
    }

    CAniPoseBone* bone = bonesBegin;
    for (int index = 0; index < boneIndex; ++index) {
      if (bone == bonesEnd) {
        return nullptr;
      }
      ++bone;
    }

    if (bone == bonesEnd) {
      return nullptr;
    }

    return bone;
  }

  /**
   * Address: 0x00552C10 (FUN_00552C10, func_UnitStateIsBusy)
   *
   * What it does:
   * Returns whether `commandType` is one of the movement/engagement command
   * families that keep air-unit speed-through navigation active.
   */
  [[nodiscard]] bool IsSpeedThroughBusyCommandType(const EUnitCommandType commandType) noexcept
  {
    switch (commandType) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_Guard:
        return true;
      default:
        return false;
    }
  }

  [[nodiscard]] gpg::RRef MakeUnitStateRef(EUnitState* const unitState)
  {
    gpg::RRef enumRef{};
    if (unitState == nullptr) {
      return enumRef;
    }

    static gpg::RType* sUnitStateType = nullptr;
    if (sUnitStateType == nullptr) {
      sUnitStateType = gpg::LookupRType(typeid(EUnitState));
    }

    enumRef.mObj = unitState;
    enumRef.mType = sUnitStateType;
    return enumRef;
  }

  [[nodiscard]] gpg::RRef MakeRuleUnitToggleCapsRef(ERuleBPUnitToggleCaps* const toggleCap)
  {
    gpg::RRef enumRef{};
    if (toggleCap == nullptr) {
      return enumRef;
    }

    static gpg::RType* sToggleCapType = nullptr;
    if (sToggleCapType == nullptr) {
      sToggleCapType = gpg::LookupRType(typeid(ERuleBPUnitToggleCaps));
    }

    enumRef.mObj = toggleCap;
    enumRef.mType = sToggleCapType;
    return enumRef;
  }

  [[nodiscard]] gpg::RRef MakeRuleUnitCommandCapsRef(ERuleBPUnitCommandCaps* const commandCap)
  {
    gpg::RRef enumRef{};
    if (commandCap == nullptr) {
      return enumRef;
    }

    static gpg::RType* sCommandCapType = nullptr;
    if (sCommandCapType == nullptr) {
      sCommandCapType = gpg::LookupRType(typeid(ERuleBPUnitCommandCaps));
    }

    enumRef.mObj = commandCap;
    enumRef.mType = sCommandCapType;
    return enumRef;
  }

  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const rawState = userDataObject.GetActiveCState();
    if (!rawState) {
      return out;
    }

    const int top = lua_gettop(rawState);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(rawState);

    void* const rawUserData = lua_touserdata(rawState, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }

    lua_settop(rawState, top);
    return out;
  }

  [[nodiscard]] gpg::RType* CachedEntityCategorySetType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(EntityCategorySet));
    }
    return sType;
  }

  [[nodiscard]] EntityCategorySet* ResolveEntityCategorySetFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    if (gpg::RType* const expectedType = CachedEntityCategorySetType(); expectedType != nullptr) {
      const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, expectedType);
      if (upcast.mObj != nullptr) {
        return static_cast<EntityCategorySet*>(upcast.mObj);
      }
    }

    const char* const typeName = userDataRef.GetTypeName();
    if (typeName != nullptr
        && (std::strstr(typeName, "EntityCategory") != nullptr || std::strstr(typeName, "BVSet") != nullptr)) {
      return static_cast<EntityCategorySet*>(userDataRef.mObj);
    }

    return nullptr;
  }

  [[nodiscard]] bool ParseFireStateLexical(const char* const lexical, std::int32_t& outFireState)
  {
    if (lexical == nullptr) {
      return false;
    }

    static gpg::RType* sFireStateType = nullptr;
    static bool sTypeLookupDone = false;
    if (!sTypeLookupDone) {
      sTypeLookupDone = true;
      sFireStateType = gpg::REF_FindTypeNamed("EFireState");
      if (sFireStateType == nullptr) {
        sFireStateType = gpg::REF_FindTypeNamed("Moho::EFireState");
      }
      if (sFireStateType == nullptr) {
        sFireStateType = gpg::REF_FindTypeNamed("moho::EFireState");
      }
    }

    if (sFireStateType != nullptr) {
      gpg::RRef fireStateRef{};
      fireStateRef.mObj = &outFireState;
      fireStateRef.mType = sFireStateType;
      if (fireStateRef.SetLexical(lexical)) {
        return true;
      }
    }

    char* end = nullptr;
    const long value = std::strtol(lexical, &end, 10);
    if (end != lexical && end != nullptr && *end == '\0' && value >= 0 && value <= 2) {
      outFireState = static_cast<std::int32_t>(value);
      return true;
    }

    return false;
  }

  [[nodiscard]] int ScriptBitIndexFromToggleCapValue(int toggleCapValue) noexcept
  {
    int bitIndex = 0;
    if (toggleCapValue == 1) {
      return bitIndex;
    }

    do {
      toggleCapValue >>= 1;
      ++bitIndex;
    } while (toggleCapValue != 1);
    return bitIndex;
  }

  [[nodiscard]] SEfxCurve BuildSingleEmitterScaleCurve(const Wm3::Vector3f& key)
  {
    SEfxCurve curve{};
    curve.mKeys.clear();
    curve.mKeys.push_back(key);
    curve.mBoundsMin.y = key.y;
    curve.mBoundsMax.y = key.y;
    return curve;
  }

  [[nodiscard]] const char* UnitStateToDebugLexical(const EUnitState state) noexcept
  {
    switch (state) {
    case UNITSTATE_Immobile:
      return "Immobile";
    case UNITSTATE_Moving:
      return "Moving";
    case UNITSTATE_Attacking:
      return "Attacking";
    case UNITSTATE_Guarding:
      return "Guarding";
    case UNITSTATE_Building:
      return "Building";
    case UNITSTATE_Upgrading:
      return "Upgrading";
    case UNITSTATE_WaitingForTransport:
      return "WaitingForTransport";
    case UNITSTATE_TransportLoading:
      return "TransportLoading";
    case UNITSTATE_TransportUnloading:
      return "TransportUnloading";
    case UNITSTATE_MovingDown:
      return "MovingDown";
    case UNITSTATE_MovingUp:
      return "MovingUp";
    case UNITSTATE_Patrolling:
      return "Patrolling";
    case UNITSTATE_Busy:
      return "Busy";
    case UNITSTATE_Attached:
      return "Attached";
    case UNITSTATE_BeingReclaimed:
      return "BeingReclaimed";
    case UNITSTATE_Repairing:
      return "Repairing";
    case UNITSTATE_Diving:
      return "Diving";
    case UNITSTATE_Surfacing:
      return "Surfacing";
    case UNITSTATE_Teleporting:
      return "Teleporting";
    case UNITSTATE_Ferrying:
      return "Ferrying";
    case UNITSTATE_WaitForFerry:
      return "WaitForFerry";
    case UNITSTATE_AssistMoving:
      return "AssistMoving";
    case UNITSTATE_PathFinding:
      return "PathFinding";
    case UNITSTATE_ProblemGettingToGoal:
      return "ProblemGettingToGoal";
    case UNITSTATE_NeedToTerminateTask:
      return "NeedToTerminateTask";
    case UNITSTATE_Capturing:
      return "Capturing";
    case UNITSTATE_BeingCaptured:
      return "BeingCaptured";
    case UNITSTATE_Reclaiming:
      return "Reclaiming";
    case UNITSTATE_AssistingCommander:
      return "AssistingCommander";
    case UNITSTATE_Refueling:
      return "Refueling";
    case UNITSTATE_GuardBusy:
      return "GuardBusy";
    case UNITSTATE_ForceSpeedThrough:
      return "ForceSpeedThrough";
    case UNITSTATE_UnSelectable:
      return "UnSelectable";
    case UNITSTATE_DoNotTarget:
      return "DoNotTarget";
    case UNITSTATE_LandingOnPlatform:
      return "LandingOnPlatform";
    case UNITSTATE_CannotFindPlaceToLand:
      return "CannotFindPlaceToLand";
    case UNITSTATE_BeingUpgraded:
      return "BeingUpgraded";
    case UNITSTATE_Enhancing:
      return "Enhancing";
    case UNITSTATE_BeingBuilt:
      return "BeingBuilt";
    case UNITSTATE_NoReclaim:
      return "NoReclaim";
    case UNITSTATE_NoCost:
      return "NoCost";
    case UNITSTATE_BlockCommandQueue:
      return "BlockCommandQueue";
    case UNITSTATE_MakingAttackRun:
      return "MakingAttackRun";
    case UNITSTATE_HoldingPattern:
      return "HoldingPattern";
    case UNITSTATE_SiloBuildingAmmo:
      return "SiloBuildingAmmo";
    default:
      return "";
    }
  }

  void AddIntStatCounter(StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }
#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  void IncrementAIDebugStateStat(CArmyStats* const armyStats, const msvc8::string& statPath)
  {
    if (!armyStats || statPath.empty()) {
      return;
    }

    CArmyStatItem* const item = armyStats->TraverseTables(statPath.c_str(), true);
    if (!item) {
      return;
    }

    item->SynchronizeAsInt();
    AddIntStatCounter(item, 1L);
  }

  [[nodiscard]] std::int32_t RoundGridCoordDown(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value));
  }

  [[nodiscard]] std::int32_t RoundGridCoordUp(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::ceil(value));
  }

  [[nodiscard]] Wm3::Vector3f& InvalidNavigatorTargetLane() noexcept
  {
    static bool initialized = false;
    static Wm3::Vector3f invalidTarget{};

    if (!initialized) {
      invalidTarget = Wm3::Vector3f::NaN();
      initialized = true;
    }

    return invalidTarget;
  }

  using NavigatorCanPathToRectVFunc =
    bool(__thiscall*)(moho::IAiNavigator* navigator, const moho::SAiNavigatorGoal* goal, Wm3::Vector3f* outTargetPos);

  [[nodiscard]] bool InvokeNavigatorCanPathToRect(
    moho::IAiNavigator* const navigator,
    const moho::SAiNavigatorGoal& goal,
    Wm3::Vector3f* const outTargetPos
  )
  {
    // FUN_006CBD70 dispatches slot 15 with an additional out-target vector lane.
    // Keep this localized ABI shim until IAiNavigator slot typing is fully lifted.
    auto** const vtable = *reinterpret_cast<void***>(navigator);
    const auto method = reinterpret_cast<NavigatorCanPathToRectVFunc>(vtable[15]);
    return method(navigator, &goal, outTargetPos);
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("user"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("user");
    return fallbackSet;
  }

  [[nodiscard]] gpg::RType* CachedUnitRType()
  {
    static gpg::RType* unitType = nullptr;
    if (unitType == nullptr) {
      unitType = gpg::LookupRType(typeid(Unit));
    }
    return unitType;
  }

  /**
   * Address: 0x00593970 (FUN_00593970, func_GetUnitOpt)
   *
   * What it does:
   * Converts one Lua object to `Unit*` without throwing Lua conversion errors.
   */
  [[nodiscard]] Unit* GetUnitOptional(const LuaPlus::LuaObject& unitObject)
  {
    CScriptObject* const scriptObject = SCR_GetScriptObjectFromLuaObject(unitObject);
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = scriptObject->GetDerivedObjectRef();
    const gpg::RRef unitRef = gpg::REF_UpcastPtr(sourceRef, CachedUnitRType());
    return static_cast<Unit*>(unitRef.mObj);
  }

  [[nodiscard]] Unit* ResolveUnitBridge(UserUnit* const userUnit) noexcept
  {
    return userUnit ? reinterpret_cast<Unit*>(userUnit->mIUnitAndScriptBridge) : nullptr;
  }

  /**
   * Address: 0x006ADD30 (FUN_006ADD30, func_hasArmorType)
   *
   * What it does:
   * Performs one lower-bound lookup in the unit armor-multiplier map and
   * returns the exact key-match node when present.
   */
  [[nodiscard]] bool IsArmorMapSentinel(const SArmorMultiplierMapNode* const node) noexcept
  {
    return node == nullptr || node->isNil != 0u;
  }

  [[nodiscard]] bool ArmorTypeNameLess(const msvc8::string& lhs, const std::string_view rhs) noexcept
  {
    return lhs.view() < rhs;
  }

  [[nodiscard]] bool ArmorTypeNameLess(const std::string_view lhs, const msvc8::string& rhs) noexcept
  {
    return lhs < rhs.view();
  }

  [[nodiscard]] const SArmorMultiplierMapNode*
  FindArmorLowerBoundNode(const SArmorMultiplierMap& armorMap, const std::string_view damageTypeName) noexcept
  {
    const SArmorMultiplierMapNode* const head = armorMap.head;
    if (head == nullptr) {
      return nullptr;
    }

    const SArmorMultiplierMapNode* candidate = head;
    for (const SArmorMultiplierMapNode* node = head->parent; !IsArmorMapSentinel(node);) {
      if (ArmorTypeNameLess(node->damageTypeName, damageTypeName)) {
        node = node->right;
      } else {
        candidate = node;
        node = node->left;
      }
    }

    return candidate;
  }

  [[nodiscard]] const SArmorMultiplierMapNode*
  FindArmorMultiplierNode(const SArmorMultiplierMap& armorMap, const std::string_view damageTypeName) noexcept
  {
    const SArmorMultiplierMapNode* const candidate = FindArmorLowerBoundNode(armorMap, damageTypeName);
    if (candidate == nullptr) {
      return nullptr;
    }

    const SArmorMultiplierMapNode* const head = armorMap.head;
    if (candidate == head) {
      return nullptr;
    }

    if (ArmorTypeNameLess(damageTypeName, candidate->damageTypeName) ||
        ArmorTypeNameLess(candidate->damageTypeName, damageTypeName)) {
      return nullptr;
    }

    return candidate;
  }

  void RotateArmorMapLeft(SArmorMultiplierMap& armorMap, SArmorMultiplierMapNode* const node) noexcept
  {
    SArmorMultiplierMapNode* const replacement = node->right;
    node->right = replacement->left;
    if (!IsArmorMapSentinel(replacement->left)) {
      replacement->left->parent = node;
    }

    replacement->parent = node->parent;

    SArmorMultiplierMapNode* const head = armorMap.head;
    if (node == head->parent) {
      head->parent = replacement;
    } else if (node == node->parent->left) {
      node->parent->left = replacement;
    } else {
      node->parent->right = replacement;
    }

    replacement->left = node;
    node->parent = replacement;
  }

  void RotateArmorMapRight(SArmorMultiplierMap& armorMap, SArmorMultiplierMapNode* const node) noexcept
  {
    SArmorMultiplierMapNode* const replacement = node->left;
    node->left = replacement->right;
    if (!IsArmorMapSentinel(replacement->right)) {
      replacement->right->parent = node;
    }

    replacement->parent = node->parent;

    SArmorMultiplierMapNode* const head = armorMap.head;
    if (node == head->parent) {
      head->parent = replacement;
    } else if (node == node->parent->right) {
      node->parent->right = replacement;
    } else {
      node->parent->left = replacement;
    }

    replacement->right = node;
    node->parent = replacement;
  }

  void RebalanceArmorMapAfterInsert(SArmorMultiplierMap& armorMap, SArmorMultiplierMapNode* insertedNode) noexcept
  {
    SArmorMultiplierMapNode* const head = armorMap.head;
    while (insertedNode->parent->color == kArmorMapColorRed) {
      if (insertedNode->parent == insertedNode->parent->parent->left) {
        SArmorMultiplierMapNode* const uncle = insertedNode->parent->parent->right;
        if (uncle->color == kArmorMapColorRed) {
          insertedNode->parent->color = kArmorMapColorBlack;
          uncle->color = kArmorMapColorBlack;
          insertedNode->parent->parent->color = kArmorMapColorRed;
          insertedNode = insertedNode->parent->parent;
        } else {
          if (insertedNode == insertedNode->parent->right) {
            insertedNode = insertedNode->parent;
            RotateArmorMapLeft(armorMap, insertedNode);
          }
          insertedNode->parent->color = kArmorMapColorBlack;
          insertedNode->parent->parent->color = kArmorMapColorRed;
          RotateArmorMapRight(armorMap, insertedNode->parent->parent);
        }
      } else {
        SArmorMultiplierMapNode* const uncle = insertedNode->parent->parent->left;
        if (uncle->color == kArmorMapColorRed) {
          insertedNode->parent->color = kArmorMapColorBlack;
          uncle->color = kArmorMapColorBlack;
          insertedNode->parent->parent->color = kArmorMapColorRed;
          insertedNode = insertedNode->parent->parent;
        } else {
          if (insertedNode == insertedNode->parent->left) {
            insertedNode = insertedNode->parent;
            RotateArmorMapRight(armorMap, insertedNode);
          }
          insertedNode->parent->color = kArmorMapColorBlack;
          insertedNode->parent->parent->color = kArmorMapColorRed;
          RotateArmorMapLeft(armorMap, insertedNode->parent->parent);
        }
      }
    }
    head->parent->color = kArmorMapColorBlack;
  }

  [[nodiscard]] SArmorMultiplierMapNode* CreateArmorMultiplierMapNode(
    SArmorMultiplierMapNode* const head,
    SArmorMultiplierMapNode* const parent,
    const std::string_view damageTypeName
  )
  {
    auto* const node = new SArmorMultiplierMapNode{};
    try {
      node->damageTypeName.assign_owned(damageTypeName);
    } catch (...) {
      delete node;
      throw;
    }

    node->left = head;
    node->parent = parent;
    node->right = head;
    node->armorMultiplier = 0.0f;
    node->color = kArmorMapColorRed;
    node->isNil = 0u;
    node->reserved = 0u;
    return node;
  }

  [[nodiscard]] float*
  FindOrInsertArmorMultiplierValue(SArmorMultiplierMap& armorMap, const std::string_view damageTypeName)
  {
    SArmorMultiplierMapNode* const head = armorMap.head;
    SArmorMultiplierMapNode* parent = head;
    SArmorMultiplierMapNode* node = head->parent;
    bool insertLeft = true;

    while (!IsArmorMapSentinel(node)) {
      parent = node;
      if (ArmorTypeNameLess(damageTypeName, node->damageTypeName)) {
        insertLeft = true;
        node = node->left;
      } else if (ArmorTypeNameLess(node->damageTypeName, damageTypeName)) {
        insertLeft = false;
        node = node->right;
      } else {
        return &node->armorMultiplier;
      }
    }

    if (armorMap.size >= kArmorMapMaxSize) {
      throw std::length_error("map/set<T> too long");
    }

    SArmorMultiplierMapNode* const inserted = CreateArmorMultiplierMapNode(head, parent, damageTypeName);
    ++armorMap.size;

    if (parent == head) {
      head->parent = inserted;
      head->left = inserted;
      head->right = inserted;
    } else if (insertLeft) {
      parent->left = inserted;
      if (parent == head->left) {
        head->left = inserted;
      }
    } else {
      parent->right = inserted;
      if (parent == head->right) {
        head->right = inserted;
      }
    }

    RebalanceArmorMapAfterInsert(armorMap, inserted);
    return &inserted->armorMultiplier;
  }

  [[nodiscard]] float LookupArmorMultiplier(const Unit& unit, const std::string_view damageTypeName) noexcept
  {
    if (const SArmorMultiplierMapNode* const match = FindArmorMultiplierNode(unit.ArmorMultipliers, damageTypeName);
        match != nullptr) {
      return match->armorMultiplier;
    }

    return 1.0f;
  }

  struct UnitAttributesBuildRestrictionRuntimeView
  {
    std::uint8_t mUnresolved00[0x08];
    CategoryWordRangeView mBuildRestrictionCategorySet; // +0x08
  };
  static_assert(
    offsetof(UnitAttributesBuildRestrictionRuntimeView, mBuildRestrictionCategorySet) == 0x08,
    "UnitAttributesBuildRestrictionRuntimeView::mBuildRestrictionCategorySet offset must be 0x08"
  );
  static_assert(sizeof(UnitAttributesBuildRestrictionRuntimeView) == 0x30, "UnitAttributes view size must be 0x30");

  struct CArmyBuildCategoryFilterRuntimeView
  {
    std::uint8_t mUnresolved00[0x198];
    CategoryWordRangeView mBuildCategoryFilterSet; // +0x198
  };
  static_assert(
    offsetof(CArmyBuildCategoryFilterRuntimeView, mBuildCategoryFilterSet) == 0x198,
    "CArmyBuildCategoryFilterRuntimeView::mBuildCategoryFilterSet offset must be 0x198"
  );

  static_assert(
    sizeof(RUnitBlueprintEconomyCategoryCache) == sizeof(CategoryWordRangeView),
    "RUnitBlueprintEconomyCategoryCache layout must match CategoryWordRangeView size"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, RuntimeWord08) == offsetof(CategoryWordRangeView, mStartWordIndex),
    "RUnitBlueprintEconomyCategoryCache::RuntimeWord08 offset must match CategoryWordRangeView::mStartWordIndex"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, First) == offsetof(CategoryWordRangeView, mWordsBegin),
    "RUnitBlueprintEconomyCategoryCache::First offset must match CategoryWordRangeView::mWordsBegin"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, Last) == offsetof(CategoryWordRangeView, mWordsEnd),
    "RUnitBlueprintEconomyCategoryCache::Last offset must match CategoryWordRangeView::mWordsEnd"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, End) == offsetof(CategoryWordRangeView, mWordsCapacityEnd),
    "RUnitBlueprintEconomyCategoryCache::End offset must match CategoryWordRangeView::mWordsCapacityEnd"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, InlineStoragePtr) == offsetof(CategoryWordRangeView, mWordsInlineBase),
    "RUnitBlueprintEconomyCategoryCache::InlineStoragePtr offset must match CategoryWordRangeView::mWordsInlineBase"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, InlineStorage) == offsetof(CategoryWordRangeView, mWordsInlineStorage),
    "RUnitBlueprintEconomyCategoryCache::InlineStorage offset must match CategoryWordRangeView::mWordsInlineStorage"
  );

  [[nodiscard]] const CategoryWordRangeView&
  AsCategoryWordRange(const RUnitBlueprintEconomyCategoryCache& categoryCache) noexcept
  {
    return reinterpret_cast<const CategoryWordRangeView&>(categoryCache);
  }

  [[nodiscard]] BVIntSet& AsCategoryWordBitset(CategoryWordRangeView& range) noexcept
  {
    static_assert(
      offsetof(CategoryWordRangeView, mStartWordIndex) == 0x08,
      "CategoryWordRangeView::mStartWordIndex offset must be 0x08"
    );
    static_assert(sizeof(BVIntSet) == 0x20, "BVIntSet size must be 0x20");
    return *reinterpret_cast<BVIntSet*>(&range.mStartWordIndex);
  }

  [[nodiscard]] CategoryWordRangeView& UnitBuildRestrictionCategoryWords(Unit& unit) noexcept
  {
    auto& runtimeView = reinterpret_cast<UnitAttributesBuildRestrictionRuntimeView&>(unit.GetAttributes());
    return runtimeView.mBuildRestrictionCategorySet;
  }

  void ResetCategoryWordRange(CategoryWordRangeView& range) noexcept
  {
    AsCategoryWordBitset(range).mFirstWordIndex = 0u;

    if (std::uint32_t* const wordsBegin = range.mWordsBegin; wordsBegin != range.mWordsInlineBase) {
      delete[] wordsBegin;
      range.mWordsBegin = range.mWordsInlineBase;
      range.mWordsCapacityEnd = range.mWordsInlineBase + 2;
    }

    range.mWordsEnd = range.mWordsBegin;
  }

  [[nodiscard]] std::int32_t PickUniformIndexFromU32(const std::uint32_t randomValue, const std::uint32_t count) noexcept
  {
    const std::uint64_t product = static_cast<std::uint64_t>(randomValue) * static_cast<std::uint64_t>(count);
    return static_cast<std::int32_t>(product >> 32u);
  }

  [[nodiscard]] bool HasFootprintFlag(const EFootprintFlags value, const EFootprintFlags flag) noexcept
  {
    return (static_cast<std::uint8_t>(value) & static_cast<std::uint8_t>(flag)) != 0u;
  }

  [[nodiscard]] Wm3::Vector3f ForwardXZ(const Unit& unit) noexcept
  {
    Wm3::Vector3f forward = unit.GetTransform().orient_.Rotate({0.0f, 0.0f, 1.0f});
    forward.y = 0.0f;
    return Wm3::Vector3f::NormalizeOrZero(forward);
  }

  [[nodiscard]] [[maybe_unused]] const Wm3::Vector3f& InvalidBombDropSolutionLane() noexcept
  {
    static bool initialized = false;
    static Wm3::Vector3f invalidVector{};

    if (!initialized) {
      invalidVector = Wm3::Vector3f::NaN();
      initialized = true;
    }

    return invalidVector;
  }

  /**
   * Address: 0x0062CEF0 (FUN_0062CEF0, func_CalcBombDrop)
   *
   * What it does:
   * Solves one ballistic intercept lane from current/target position,
   * velocity, and gravity; writes NaN-vector lanes when no valid time root
   * exists.
   */
  [[nodiscard]] [[maybe_unused]] Wm3::Vector3f* ComputeBombDropAimPoint(
    const Wm3::Vector3f& velocity,
    Wm3::Vector3f* const out,
    const Wm3::Vector3f& gravity,
    const Wm3::Vector3f& targetPosition,
    const Wm3::Vector3f& currentPosition
  ) noexcept
  {
    const float gravityMagnitude = std::sqrt((gravity.x * gravity.x) + (gravity.y * gravity.y) + (gravity.z * gravity.z));

    Wm3::Vector3f oppositeGravityDirection{
      -gravity.x,
      -gravity.y,
      -gravity.z,
    };
    Wm3::Vector3f::Normalize(&oppositeGravityDirection);

    const float velocityAlongGravity = (velocity.x * oppositeGravityDirection.x) +
      (velocity.y * oppositeGravityDirection.y) + (velocity.z * oppositeGravityDirection.z);
    const float projectedSpeedMagnitude = std::sqrt(
      (oppositeGravityDirection.x * velocityAlongGravity) * (oppositeGravityDirection.x * velocityAlongGravity) +
      (oppositeGravityDirection.y * velocityAlongGravity) * (oppositeGravityDirection.y * velocityAlongGravity) +
      (oppositeGravityDirection.z * velocityAlongGravity) * (oppositeGravityDirection.z * velocityAlongGravity)
    );

    const float targetDeltaAlongGravity = ((currentPosition.x - targetPosition.x) * oppositeGravityDirection.x) +
      ((currentPosition.y - targetPosition.y) * oppositeGravityDirection.y) +
      ((currentPosition.z - targetPosition.z) * oppositeGravityDirection.z);

    const float projectedDistanceX = oppositeGravityDirection.x * targetDeltaAlongGravity;
    const float projectedDistanceY = oppositeGravityDirection.y * targetDeltaAlongGravity;
    const float projectedDistanceZ = oppositeGravityDirection.z * targetDeltaAlongGravity;
    const float projectedDistanceMagnitude = std::sqrt(
      (projectedDistanceX * projectedDistanceX) + (projectedDistanceY * projectedDistanceY) +
      (projectedDistanceZ * projectedDistanceZ)
    );

    const float signedScale = (((projectedDistanceX * oppositeGravityDirection.x) +
                                 (projectedDistanceY * oppositeGravityDirection.y) +
                                 (projectedDistanceZ * oppositeGravityDirection.z)) >= 0.0f)
      ? 2.0f
      : -2.0f;

    const float rootDiscriminant = (signedScale * projectedDistanceMagnitude * gravityMagnitude) +
      (projectedSpeedMagnitude * projectedSpeedMagnitude);

    if (rootDiscriminant < 0.0f) {
      *out = InvalidBombDropSolutionLane();
      return out;
    }

    const float root = std::sqrt(rootDiscriminant);
    const float inverseGravityMagnitude = 1.0f / gravityMagnitude;
    float travelTime = -((root - projectedSpeedMagnitude) * inverseGravityMagnitude);
    if (travelTime < 0.0f) {
      travelTime = -(((-projectedSpeedMagnitude) - root) * inverseGravityMagnitude);
    }

    if (travelTime < 0.0f) {
      *out = InvalidBombDropSolutionLane();
      return out;
    }

    const float halfTravelTimeSquared = 0.5f * travelTime * travelTime;
    out->x = targetPosition.x - ((gravity.x * halfTravelTimeSquared) + (velocity.x * travelTime));
    out->y = targetPosition.y - ((gravity.y * halfTravelTimeSquared) + (velocity.y * travelTime));
    out->z = targetPosition.z - ((gravity.z * halfTravelTimeSquared) + (velocity.z * travelTime));
    return out;
  }

  struct CollisionDBRect
  {
    std::uint16_t xPos;
    std::uint16_t zPos;
    std::uint16_t xSize;
    std::uint16_t zSize;
  };

  [[nodiscard]] CollisionDBRect COORDS_OgridRectToCollisionRect(const gpg::Rect2i& ogridRect) noexcept
  {
    // Address: 0x004FCAA0 (FUN_004FCAA0)
    const std::int32_t xPos = std::clamp(ogridRect.x0 >> 2, 0, 0xFFFF);
    const std::int32_t zPos = std::clamp(ogridRect.z0 >> 2, 0, 0xFFFF);
    const std::int32_t xEnd = (ogridRect.x1 + 3) >> 2;
    const std::int32_t zEnd = (ogridRect.z1 + 3) >> 2;

    CollisionDBRect collisionRect{};
    collisionRect.xPos = static_cast<std::uint16_t>(xPos);
    collisionRect.zPos = static_cast<std::uint16_t>(zPos);

    const std::int32_t maxXSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.xPos);
    const std::int32_t maxZSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.zPos);
    const std::int32_t xSpan =
      std::clamp(xEnd - static_cast<std::int32_t>(collisionRect.xPos), std::int32_t{1}, maxXSpan);
    const std::int32_t zSpan =
      std::clamp(zEnd - static_cast<std::int32_t>(collisionRect.zPos), std::int32_t{1}, maxZSpan);

    collisionRect.xSize = static_cast<std::uint16_t>(xSpan);
    collisionRect.zSize = static_cast<std::uint16_t>(zSpan);
    return collisionRect;
  }

  [[nodiscard]] bool IsCollisionRectEquivalentToZero(const gpg::Rect2i& ogridRect) noexcept
  {
    const gpg::Rect2i zeroRect{};
    const CollisionDBRect currentCollisionRect = COORDS_OgridRectToCollisionRect(ogridRect);
    const CollisionDBRect zeroCollisionRect = COORDS_OgridRectToCollisionRect(zeroRect);
    return currentCollisionRect.xPos == zeroCollisionRect.xPos &&
      currentCollisionRect.zPos == zeroCollisionRect.zPos &&
      currentCollisionRect.xSize == zeroCollisionRect.xSize &&
      currentCollisionRect.zSize == zeroCollisionRect.zSize;
  }

  [[nodiscard]] gpg::Rect2i GetReservedOgridRect(const Unit& unit) noexcept
  {
    return {
      unit.ReservedOgridRectMinX,
      unit.ReservedOgridRectMinZ,
      unit.ReservedOgridRectMaxX,
      unit.ReservedOgridRectMaxZ,
    };
  }

  void FillReservedOgridRect(Unit& unit, const bool occupied) noexcept
  {
    if (!unit.SimulationRef || !unit.SimulationRef->mOGrid) {
      return;
    }

    const gpg::Rect2i ogridRect = GetReservedOgridRect(unit);
    unit.SimulationRef->mOGrid->mOccupation.FillRect(
      ogridRect.x0,
      ogridRect.z0,
      ogridRect.x1 - ogridRect.x0,
      ogridRect.z1 - ogridRect.z0,
      occupied
    );
  }

  constexpr std::uint8_t kTerrainOccupancyMask = static_cast<std::uint8_t>(EOccupancyCaps::OC_LAND) |
    static_cast<std::uint8_t>(EOccupancyCaps::OC_SEABED) | static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB);

  [[nodiscard]] std::int32_t RoundOccupyRectEdge(const float value) noexcept
  {
    return static_cast<std::int32_t>(std::floor(value + 0.5f));
  }

  void ApplyOccupancyRect(const std::uint8_t occupancyCaps, COGrid* const grid, const gpg::Rect2i& rect)
  {
    if (!grid) {
      return;
    }

    const int width = rect.x1 - rect.x0;
    const int height = rect.z1 - rect.z0;
    if (width <= 0 || height <= 0) {
      return;
    }

    if ((occupancyCaps & kTerrainOccupancyMask) != 0u) {
      grid->terrainOccupation.FillRect(rect.x0, rect.z0, width, height, true);
    }

    if ((occupancyCaps & static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER)) != 0u) {
      grid->waterOccupation.FillRect(rect.x0, rect.z0, width, height, true);
    }

    if (grid->sim && grid->sim->mPathTables) {
      grid->sim->mPathTables->DirtyClusters(rect);
    }
  }

  void DrawRaisedPlatformEdge(
    CDebugCanvas& canvas,
    const Wm3::Vector3f& a,
    const Wm3::Vector3f& b
  )
  {
    SDebugLine line{};
    line.p0 = a;
    line.p1 = b;
    line.depth0 = -16711936;
    line.depth1 = -16711936;
    canvas.DebugDrawLine(line);
  }

  struct RaisedPlatformVertexRuntimeLane
  {
    float x;
    float z;
    float y;
  };
  static_assert(sizeof(RaisedPlatformVertexRuntimeLane) == 0x0C, "RaisedPlatformVertexRuntimeLane size must be 0x0C");

  struct RaisedPlatformRuntimeView
  {
    RaisedPlatformVertexRuntimeLane vertex0;
    RaisedPlatformVertexRuntimeLane vertex1;
    RaisedPlatformVertexRuntimeLane vertex2;
    RaisedPlatformVertexRuntimeLane vertex3;
  };
  static_assert(sizeof(RaisedPlatformRuntimeView) == 0x30, "RaisedPlatformRuntimeView size must be 0x30");
  static_assert(
    sizeof(RaisedPlatformRuntimeView) == sizeof(RUnitBlueprintRaisedPlatform),
    "RaisedPlatformRuntimeView must mirror RUnitBlueprintRaisedPlatform storage"
  );

  /**
   * Address: 0x0062EAC0 (FUN_0062EAC0, func_UnitMoreInLineToOther)
   */
  [[nodiscard]] const Unit* UnitMoreInLineToOther(const Unit* const a1, const Unit* const a2) noexcept
  {
    if (!a1 || !a2) {
      return nullptr;
    }

    const Wm3::Vector3f a2Forward = ForwardXZ(*a2);
    const Wm3::Vector3f a1Forward = ForwardXZ(*a1);
    const Wm3::Vector3f a2ToA1 = Wm3::Vector3f::NormalizeOrZero(a1->GetPosition() - a2->GetPosition());
    const Wm3::Vector3f a1ToA2 = Wm3::Vector3f::NormalizeOrZero(a2->GetPosition() - a1->GetPosition());

    const float a2Alignment = Wm3::Vector3f::Dot(a2ToA1, a2Forward);
    const float a1Alignment = Wm3::Vector3f::Dot(a1ToA2, a1Forward);
    if (a2Alignment <= 0.0f && a1Alignment <= 0.0f) {
      return nullptr;
    }
    return (a2Alignment <= a1Alignment) ? a2 : a1;
  }

  class ExtraDataPairBuffer
  {
  public:
    explicit ExtraDataPairBuffer(SExtraUnitData* out) noexcept
      : out_(out)
    {}

    [[nodiscard]] SExtraUnitDataPair* begin() const noexcept
    {
      return out_ ? out_->pairsBegin : nullptr;
    }

    [[nodiscard]] SExtraUnitDataPair* end() const noexcept
    {
      return out_ ? out_->pairsEnd : nullptr;
    }

    [[nodiscard]] bool push_back(const SExtraUnitDataPair& pair) noexcept
    {
      if (!out_) {
        return false;
      }

      if (out_->pairsEnd == out_->pairsCapacityEnd) {
        const std::size_t nextCount = count() + 1u;
        if (!reserve(nextCount)) {
          return false;
        }
      }

      *out_->pairsEnd++ = pair;
      return true;
    }

  private:
    [[nodiscard]] std::size_t count() const noexcept
    {
      if (!out_ || !out_->pairsBegin || !out_->pairsEnd) {
        return 0u;
      }
      return static_cast<std::size_t>(out_->pairsEnd - out_->pairsBegin);
    }

    [[nodiscard]] std::size_t capacity() const noexcept
    {
      if (!out_ || !out_->pairsBegin || !out_->pairsCapacityEnd) {
        return 0u;
      }
      return static_cast<std::size_t>(out_->pairsCapacityEnd - out_->pairsBegin);
    }

    [[nodiscard]] bool reserve(const std::size_t requiredCapacity) noexcept
    {
      const std::size_t oldCapacity = capacity();
      if (oldCapacity >= requiredCapacity) {
        return true;
      }

      std::size_t newCapacity = oldCapacity == 0u ? 4u : oldCapacity;
      while (newCapacity < requiredCapacity) {
        newCapacity *= 2u;
      }

      const std::size_t oldCount = count();
      auto* const newStorage =
        static_cast<SExtraUnitDataPair*>(::operator new(newCapacity * sizeof(SExtraUnitDataPair), std::nothrow));
      if (!newStorage) {
        return false;
      }

      if (oldCount != 0u) {
        std::copy_n(out_->pairsBegin, oldCount, newStorage);
      }

      auto* const oldStorage = out_->pairsBegin;
      auto* const inlineStorage = out_->pairsInlineBegin ? out_->pairsInlineBegin : &out_->inlinePair;
      if (oldStorage && oldStorage != inlineStorage) {
        ::operator delete(oldStorage);
      }
      out_->pairsBegin = newStorage;
      out_->pairsEnd = newStorage + oldCount;
      out_->pairsCapacityEnd = newStorage + newCapacity;
      return true;
    }

  private:
    SExtraUnitData* out_;
  };
} // namespace

/**
 * Address: 0x006AEBF0 (FUN_006AEBF0, Moho::InstanceCounter<Moho::Unit>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for Unit instance
 * counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::Unit>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::Unit).name());
  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

CScrLuaMetatableFactory<Unit> CScrLuaMetatableFactory<Unit>::sInstance{};

CScrLuaMetatableFactory<Unit>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

CScrLuaMetatableFactory<Unit>& CScrLuaMetatableFactory<Unit>::Instance()
{
  return sInstance;
}

LuaPlus::LuaObject CScrLuaMetatableFactory<Unit>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x00564660 (FUN_00564660, ?ARMOR_GetArmorDefinations@Moho@@YA?AV?$list@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V?$allocator@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@2@@std@@PAVLuaState@LuaPlus@@VStrArg@gpg@@@Z)
 *
 * What it does:
 * Loads `/lua/armordefinition.lua`, resolves `armordefinition` table rows for
 * one armor type, and returns raw `<damageType multiplier>` string lanes.
 */
msvc8::list<msvc8::string> moho::ARMOR_GetArmorDefinations(
  LuaPlus::LuaState* const state,
  const gpg::StrArg armorTypeName
)
{
  msvc8::list<msvc8::string> definitions{};

  LuaPlus::LuaObject armorModule = SCR_Import(state, "/lua/armordefinition.lua");
  if (armorModule.IsNil()) {
    gpg::Warnf("can't load the armordefinition module -- no armor for you.");
    return definitions;
  }

  LuaPlus::LuaObject armorTable = armorModule.GetByName("armordefinition");
  if (!armorTable.IsTable()) {
    gpg::Warnf("The armor module didn't define any armors.  Hmm Odd?");
    return definitions;
  }

  const int armorClassCount = armorTable.GetN();
  for (int armorClassIndex = 1; armorClassIndex <= armorClassCount; ++armorClassIndex) {
    LuaPlus::LuaObject armorClass = armorTable.GetByIndex(armorClassIndex);
    if (!armorClass.IsTable()) {
      continue;
    }

    LuaPlus::LuaObject classNameObject = armorClass.GetByIndex(1);
    const char* const className = classNameObject.GetString();
    if (!className || !armorTypeName || _stricmp(className, armorTypeName) != 0) {
      continue;
    }

    const int definitionCount = armorClass.GetN();
    for (int definitionIndex = 2; definitionIndex <= definitionCount; ++definitionIndex) {
      LuaPlus::LuaObject definitionObject = armorClass.GetByIndex(definitionIndex);
      const char* const definitionText = definitionObject.GetString();
      if (definitionText) {
        definitions.push_back(msvc8::string(definitionText));
      }
    }

    break;
  }

  return definitions;
}

/**
 * Address: 0x006C3AB0 (FUN_006C3AB0, cfunc_UnitGetUnitId)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetUnitIdL`.
 */
int moho::cfunc_UnitGetUnitId(lua_State* const luaContext)
{
  return cfunc_UnitGetUnitIdL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C3AD0 (FUN_006C3AD0, func_UnitGetUnitId_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetUnitId()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetUnitId_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetUnitIdName,
    &moho::cfunc_UnitGetUnitId,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetUnitIdHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C3B30 (FUN_006C3B30, cfunc_UnitGetUnitIdL)
 *
 * What it does:
 * Returns this unit's blueprint-id token string.
 */
int moho::cfunc_UnitGetUnitIdL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetUnitIdHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  const RUnitBlueprint* const blueprint = unit->GetBlueprint();

  const char* unitId = "";
  if (blueprint != nullptr) {
    unitId = blueprint->mBlueprintId.c_str();
  }

  lua_pushstring(rawState, unitId);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C3C00 (FUN_006C3C00, cfunc_UnitSetCreator)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetCreatorL`.
 */
int moho::cfunc_UnitSetCreator(lua_State* const luaContext)
{
  return cfunc_UnitSetCreatorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C3C20 (FUN_006C3C20, func_UnitSetCreator_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetCreator(creator)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetCreator_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetCreatorName,
    &moho::cfunc_UnitSetCreator,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetCreatorHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C3C80 (FUN_006C3C80, cfunc_UnitSetCreatorL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit creator weak lane and marks sync dirty.
 */
int moho::cfunc_UnitSetCreatorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetCreatorHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject creatorObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const creator = SCR_FromLua_Unit(creatorObject);

  if (unit != nullptr && creator != nullptr) {
    unit->CreatorRef.ResetObjectPtr<Unit>(creator);
    unit->NeedSyncGameData = true;
  }

  return 0;
}

/**
 * Address: 0x006C3E00 (FUN_006C3E00, cfunc_UnitGetCargoL)
 *
 * What it does:
 * Returns a Lua array containing script objects for all units currently loaded
 * by this transport unit.
 */
int moho::cfunc_UnitGetCargoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetCargoHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  IAiTransport* const transport = unit->AiTransport;
  if (transport == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCargoTransportOnlyText);
  }

  EntitySetTemplate<Unit> loadedUnits = transport->TransportGetLoadedUnits(false);

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, 0, 0);

  int resultIndex = 1;
  for (Unit* const* it = loadedUnits.begin(); it != loadedUnits.end(); ++it, ++resultIndex) {
    Unit* const cargoUnit = *it;
    LuaPlus::LuaObject cargoObject = cargoUnit->GetLuaObject();
    resultTable.Insert(resultIndex, cargoObject);
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x006C3D80 (FUN_006C3D80, cfunc_UnitGetCargo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetCargoL`.
 */
int moho::cfunc_UnitGetCargo(lua_State* const luaContext)
{
  return cfunc_UnitGetCargoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C3DA0 (FUN_006C3DA0, func_UnitGetCargo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetCargo()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCargo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetCargoName,
    &moho::cfunc_UnitGetCargo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCargoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C3F80 (FUN_006C3F80, cfunc_UnitAlterArmor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitAlterArmorL`.
 */
int moho::cfunc_UnitAlterArmor(lua_State* const luaContext)
{
  return cfunc_UnitAlterArmorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C3FA0 (FUN_006C3FA0, func_UnitAlterArmor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AlterArmor(damageTypeName, multiplier)` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitAlterArmor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitAlterArmorName,
    &moho::cfunc_UnitAlterArmor,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAlterArmorHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4000 (FUN_006C4000, cfunc_UnitAlterArmorL)
 *
 * What it does:
 * Writes or creates one damage-type armor multiplier entry in this unit's
 * runtime armor map.
 */
int moho::cfunc_UnitAlterArmorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitAlterArmorHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject damageTypeArg(state, 2);
  const char* damageTypeName = lua_tostring(rawState, 2);
  if (damageTypeName == nullptr) {
    damageTypeArg.TypeError("string");
    damageTypeName = "";
  }
  const std::string armorTypeName(damageTypeName);

  const LuaPlus::LuaStackObject armorMultiplierArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    armorMultiplierArg.TypeError("number");
  }
  const float armorMultiplier = lua_tonumber(rawState, 3);

  *FindOrInsertArmorMultiplierValue(unit->ArmorMultipliers, std::string_view(armorTypeName)) = armorMultiplier;
  return 0;
}

/**
 * Address: 0x006C4180 (FUN_006C4180, cfunc_UnitGetArmorMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetArmorMultL`.
 */
int moho::cfunc_UnitGetArmorMult(lua_State* const luaContext)
{
  return cfunc_UnitGetArmorMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C41A0 (FUN_006C41A0, func_UnitGetArmorMult_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetArmorMult(damageTypeName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetArmorMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetArmorMultName,
    &moho::cfunc_UnitGetArmorMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetArmorMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4200 (FUN_006C4200, cfunc_UnitGetArmorMultL)
 *
 * What it does:
 * Returns this unit's damage-type armor multiplier, defaulting to `1.0` when
 * the armor map has no matching entry.
 */
int moho::cfunc_UnitGetArmorMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetArmorMultHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject damageTypeArg(state, 2);
  const char* damageTypeName = lua_tostring(rawState, 2);
  if (damageTypeName == nullptr) {
    damageTypeArg.TypeError("string");
    damageTypeName = "";
  }

  const float armorMultiplier = LookupArmorMultiplier(*unit, std::string_view(damageTypeName));
  lua_pushnumber(rawState, armorMultiplier);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C4370 (FUN_006C4370, cfunc_UnitClearFocusEntity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitClearFocusEntityL`.
 */
int moho::cfunc_UnitClearFocusEntity(lua_State* const luaContext)
{
  return cfunc_UnitClearFocusEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4390 (FUN_006C4390, func_UnitClearFocusEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:ClearFocusEntity(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitClearFocusEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitClearFocusEntityName,
    &moho::cfunc_UnitClearFocusEntity,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitClearFocusEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C43F0 (FUN_006C43F0, cfunc_UnitClearFocusEntityL)
 *
 * What it does:
 * Clears the focused-entity weak lane and marks focus state as assigned for
 * script-side follow-up.
 */
int moho::cfunc_UnitClearFocusEntityL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitClearFocusEntityHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  unit->FocusEntityRef.ResetObjectPtr<Entity>(nullptr);
  if (unit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
    unit->RunScript(kUnitOnAssignedFocusEntityScript);
  }
  unit->NeedSyncGameData = true;
  return 0;
}

/**
 * Address: 0x006C44E0 (FUN_006C44E0, cfunc_UnitSetFocusEntity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFocusEntityL`.
 */
int moho::cfunc_UnitSetFocusEntity(lua_State* const luaContext)
{
  return cfunc_UnitSetFocusEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4500 (FUN_006C4500, func_UnitSetFocusEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetFocusEntity(self, focus)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetFocusEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetFocusEntityName,
    &moho::cfunc_UnitSetFocusEntity,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetFocusEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4560 (FUN_006C4560, cfunc_UnitSetFocusEntityL)
 *
 * What it does:
 * Resolves optional focus entity from Lua arg #2, writes it into unit focus
 * weak lane, dispatches `OnAssignedFocusEntity`, and marks focus assigned.
 */
int moho::cfunc_UnitSetFocusEntityL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetFocusEntityHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject focusEntityObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const focusEntity = SCR_FromLua_EntityOpt(focusEntityObject);
  if (focusEntity != nullptr) {
    unit->FocusEntityRef.ResetObjectPtr<Entity>(focusEntity);
    if (unit->FocusEntityRef.ResolveObjectPtr<Entity>() != nullptr) {
      unit->RunScript(kUnitOnAssignedFocusEntityScript);
    }
    unit->NeedSyncGameData = true;
  }

  return 0;
}

/**
 * Address: 0x006C4670 (FUN_006C4670, cfunc_UnitGetFocusUnit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetFocusUnitL`.
 */
int moho::cfunc_UnitGetFocusUnit(lua_State* const luaContext)
{
  return cfunc_UnitGetFocusUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4690 (FUN_006C4690, func_UnitGetFocusUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetFocusUnit(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetFocusUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetFocusUnitName,
    &moho::cfunc_UnitGetFocusUnit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetFocusUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C46F0 (FUN_006C46F0, cfunc_UnitGetFocusUnitL)
 *
 * What it does:
 * Returns focused unit Lua object when the current focused entity resolves to
 * one unit; otherwise returns `nil`.
 */
int moho::cfunc_UnitGetFocusUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetFocusUnitHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (Entity* const focusEntity = unit->GetFocusEntity(); focusEntity != nullptr) {
    if (Unit* const focusUnit = focusEntity->IsUnit(); focusUnit != nullptr) {
      LuaPlus::LuaObject focusUnitObject = focusUnit->GetLuaObject();
      focusUnitObject.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C4800 (FUN_006C4800, cfunc_UnitGetWeapon)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetWeaponL`.
 */
int moho::cfunc_UnitGetWeapon(lua_State* const luaContext)
{
  return cfunc_UnitGetWeaponL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4820 (FUN_006C4820, func_UnitGetWeapon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetWeapon(self,index)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetWeapon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetWeaponName,
    &moho::cfunc_UnitGetWeapon,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetWeaponHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4880 (FUN_006C4880, cfunc_UnitGetWeaponL)
 *
 * What it does:
 * Returns one unit weapon Lua object for arg #2 index (1-based), or nil when
 * no weapon object is available at that lane.
 */
int moho::cfunc_UnitGetWeaponL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetWeaponHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject weaponIndexArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    weaponIndexArg.TypeError("integer");
  }

  const int weaponIndex = static_cast<int>(lua_tonumber(rawState, 2)) - 1;
  CAiAttackerImpl* attacker = unit->AiAttacker;
  const int attackerWeaponCount = attacker ? attacker->GetWeaponCount() : 0;
  if (weaponIndex >= attackerWeaponCount) {
    attacker = unit->AiAttacker;
    const int maxWeaponCount = attacker ? attacker->GetWeaponCount() : 0;
    LuaPlus::LuaState::Error(state, kUnitGetWeaponInvalidIndexError, weaponIndex + 1, maxWeaponCount);
  }

  attacker = unit->AiAttacker;
  if (attacker != nullptr) {
    UnitWeapon* const weapon = static_cast<UnitWeapon*>(attacker->GetWeapon(weaponIndex));
    if (weapon != nullptr) {
      weapon->mLuaObj.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C49F0 (FUN_006C49F0, cfunc_UnitGetWeaponCount)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetWeaponCountL`.
 */
int moho::cfunc_UnitGetWeaponCount(lua_State* const luaContext)
{
  return cfunc_UnitGetWeaponCountL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4A10 (FUN_006C4A10, func_UnitGetWeaponCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetWeaponCount(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetWeaponCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetWeaponCountName,
    &moho::cfunc_UnitGetWeaponCount,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetWeaponCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4A70 (FUN_006C4A70, cfunc_UnitGetWeaponCountL)
 *
 * What it does:
 * Returns the attacker-side runtime weapon count for this unit.
 */
int moho::cfunc_UnitGetWeaponCountL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetWeaponCountHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const CAiAttackerImpl* const attacker = unit->AiAttacker;
  const int weaponCount = attacker ? const_cast<CAiAttackerImpl*>(attacker)->GetWeaponCount() : 0;
  lua_pushnumber(rawState, static_cast<float>(weaponCount));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C4B40 (FUN_006C4B40, cfunc_UnitGetTargetEntity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetTargetEntityL`.
 */
int moho::cfunc_UnitGetTargetEntity(lua_State* const luaContext)
{
  return cfunc_UnitGetTargetEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4B60 (FUN_006C4B60, func_UnitGetTargetEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetTargetEntity(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetTargetEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetTargetEntityName,
    &moho::cfunc_UnitGetTargetEntity,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetTargetEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4BC0 (FUN_006C4BC0, cfunc_UnitGetTargetEntityL)
 *
 * What it does:
 * Returns the current desired target entity Lua object from the unit attacker
 * manager, or `nil` when no desired target is available.
 */
int moho::cfunc_UnitGetTargetEntityL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetTargetEntityHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  CAiAttackerImpl* const attacker = unit->AiAttacker;
  if (attacker != nullptr) {
    CAiTarget* const desiredTarget = attacker->GetDesiredTarget();
    if (Entity* const targetEntity = desiredTarget ? desiredTarget->GetEntity() : nullptr; targetEntity != nullptr) {
      targetEntity->mLuaObj.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C4CA0 (FUN_006C4CA0, cfunc_UnitGetHealth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetHealthL`.
 */
int moho::cfunc_UnitGetHealth(lua_State* const luaContext)
{
  return cfunc_UnitGetHealthL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4CC0 (FUN_006C4CC0, func_UnitGetHealth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetHealth(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetHealth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetHealthName,
    &moho::cfunc_UnitGetHealth,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetHealthHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4D20 (FUN_006C4D20, cfunc_UnitGetHealthL)
 *
 * What it does:
 * Returns this unit's current health scalar.
 */
int moho::cfunc_UnitGetHealthL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetHealthHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = SCR_FromLua_Unit(unitObject);
  lua_pushnumber(rawState, unit->Health);
  return 1;
}

/**
 * Address: 0x006C4E10 (FUN_006C4E10, cfunc_UnitGetAttacker)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetAttackerL`.
 */
int moho::cfunc_UnitGetAttacker(lua_State* const luaContext)
{
  return cfunc_UnitGetAttackerL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4E30 (FUN_006C4E30, func_UnitGetAttacker_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetAttacker()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetAttacker_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetAttackerName,
    &moho::cfunc_UnitGetAttacker,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetAttackerHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4E90 (FUN_006C4E90, cfunc_UnitGetAttackerL)
 *
 * What it does:
 * Returns this unit's tactical attacker manager object, or nil when absent.
 */
int moho::cfunc_UnitGetAttackerL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetAttackerHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  CAiAttackerImpl* const attacker = unit->AiAttacker;
  if (attacker != nullptr) {
    attacker->PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x006C4FE0 (FUN_006C4FE0, cfunc_UnitEnableManipulatorsL)
 *
 * What it does:
 * Enables/disables one manipulator lane on a unit by bone index or bone name.
 */
int moho::cfunc_UnitEnableManipulatorsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitEnableManipulatorsHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject enabledArg(state, 3);
  const bool enabled = enabledArg.GetBoolean();

  if (lua_type(rawState, 2) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject boneIndexArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      boneIndexArg.TypeError("integer");
    }

    const int boneIndex = static_cast<int>(lua_tonumber(rawState, 2));
    unit->AniActor->EnableBoneIndex(enabled, boneIndex);
    return 0;
  }

  const LuaPlus::LuaStackObject boneNameArg(state, 2);
  const char* boneName = lua_tostring(rawState, 2);
  if (boneName == nullptr) {
    boneNameArg.TypeError("string");
    boneName = "";
  }

  unit->AniActor->EnableBoneString(boneName, enabled);
  return 0;
}

/**
 * Address: 0x006C4F60 (FUN_006C4F60, cfunc_UnitEnableManipulators)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitEnableManipulatorsL`.
 */
int moho::cfunc_UnitEnableManipulators(lua_State* const luaContext)
{
  return cfunc_UnitEnableManipulatorsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4F80 (FUN_006C4F80, func_UnitEnableManipulators_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:EnableManipulators(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitEnableManipulators_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitEnableManipulatorsName,
    &moho::cfunc_UnitEnableManipulators,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitEnableManipulatorsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5170 (FUN_006C5170, cfunc_UnitKillManipulator)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitKillManipulatorL`.
 */
int moho::cfunc_UnitKillManipulator(lua_State* const luaContext)
{
  return cfunc_UnitKillManipulatorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5190 (FUN_006C5190, func_UnitKillManipulator_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:KillManipulator(manipulator)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitKillManipulator_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitKillManipulatorName,
    &moho::cfunc_UnitKillManipulator,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitKillManipulatorHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C51F0 (FUN_006C51F0, cfunc_UnitKillManipulatorL)
 *
 * What it does:
 * Resolves `(unit, manipulator)` from Lua and destroys that exact manipulator
 * on the unit actor when present.
 */
int moho::cfunc_UnitKillManipulatorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitKillManipulatorHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 2));
  auto* const manipulator = SCR_FromLua_IAniManipulator(manipulatorObject, state);
  unit->AniActor->KillManipulator(manipulator);
  return 1;
}

/**
 * Address: 0x006C52E0 (FUN_006C52E0, cfunc_UnitKillManipulators)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitKillManipulatorsL`.
 */
int moho::cfunc_UnitKillManipulators(lua_State* const luaContext)
{
  return cfunc_UnitKillManipulatorsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5300 (FUN_006C5300, func_UnitKillManipulators_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:KillManipulators([boneName|boneIndex])` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitKillManipulators_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitKillManipulatorsName,
    &moho::cfunc_UnitKillManipulators,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitKillManipulatorsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5360 (FUN_006C5360, cfunc_UnitKillManipulatorsL)
 *
 * What it does:
 * Kills each unit manipulator that matches arg #2 by bone index (`number`) or
 * bone name wildcard (`string`).
 */
int moho::cfunc_UnitKillManipulatorsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitKillManipulatorsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (lua_type(rawState, 2) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject boneIndexArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      boneIndexArg.TypeError("integer");
    }

    const int boneIndex = static_cast<int>(lua_tonumber(rawState, 2));
    unit->AniActor->KillManipulatorByBoneIndex(boneIndex);
    return 0;
  }

  const LuaPlus::LuaStackObject boneNameArg(state, 2);
  const char* const boneName = lua_tostring(rawState, 2);
  if (boneName == nullptr) {
    boneNameArg.TypeError("string");
  }

  unit->AniActor->KillManipulatorsByBonePattern(boneName);
  return 0;
}

/**
 * Address: 0x006C5530 (FUN_006C5530, cfunc_UnitScaleGetBuiltEmitterL)
 *
 * What it does:
 * Applies unit-footprint scale curves to emitter parameters `(10, 4, 3)`.
 */
int moho::cfunc_UnitScaleGetBuiltEmitterL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitScaleGetBuiltEmitterHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);
  Unit* const unit = entity ? entity->IsUnit() : nullptr;
  if (unit == nullptr) {
    return 0;
  }

  const LuaPlus::LuaObject effectObject(LuaPlus::LuaStackObject(state, 2));
  IEffect* const effect = SCR_FromLua_IEffect(effectObject, state);

  const SFootprint& footprint = unit->GetFootprint();
  const Wm3::Vector3f scaleKey(
    static_cast<float>(footprint.mSizeX),
    static_cast<float>(footprint.mSizeZ),
    0.0f
  );

  const SEfxCurve param10Curve = BuildSingleEmitterScaleCurve(scaleKey);
  effect->SetCurveParam(10, &param10Curve);

  const SEfxCurve param4Curve = BuildSingleEmitterScaleCurve(scaleKey);
  effect->SetCurveParam(4, &param4Curve);

  const SEfxCurve param3Curve = BuildSingleEmitterScaleCurve(scaleKey);
  effect->SetCurveParam(3, &param3Curve);

  return 0;
}

/**
 * Address: 0x006C54B0 (FUN_006C54B0, cfunc_UnitScaleGetBuiltEmitter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitScaleGetBuiltEmitterL`.
 */
int moho::cfunc_UnitScaleGetBuiltEmitter(lua_State* const luaContext)
{
  return cfunc_UnitScaleGetBuiltEmitterL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C54D0 (FUN_006C54D0, func_UnitScaleGetBuiltEmitter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:ScaleGetBuiltEmitter(self, emitter)` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitScaleGetBuiltEmitter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitScaleGetBuiltEmitterName,
    &moho::cfunc_UnitScaleGetBuiltEmitter,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitScaleGetBuiltEmitterHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5800 (FUN_006C5800, cfunc_UnitSetStrategicUnderlayL)
 *
 * What it does:
 * Resolves `(self, icon)` and applies one strategic underlay icon id on the
 * unit entity.
 */
int moho::cfunc_UnitSetStrategicUnderlayL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetStrategicUnderlayHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject iconArg(state, 2);
  const char* iconName = lua_tostring(rawState, 2);
  if (iconName == nullptr) {
    iconArg.TypeError("string");
    iconName = "";
  }

  RResId underlayId{};
  gpg::STR_InitFilename(&underlayId.name, iconName);
  unit->SetStrategicUnderlay(underlayId);
  return 0;
}

/**
 * Address: 0x006C5780 (FUN_006C5780, cfunc_UnitSetStrategicUnderlay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetStrategicUnderlayL`.
 */
int moho::cfunc_UnitSetStrategicUnderlay(lua_State* const luaContext)
{
  return cfunc_UnitSetStrategicUnderlayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C57A0 (FUN_006C57A0, func_UnitSetStrategicUnderlay_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetStrategicUnderlay(icon)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetStrategicUnderlay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetStrategicUnderlayName,
    &moho::cfunc_UnitSetStrategicUnderlay,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetStrategicUnderlayHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA9F0 (FUN_008BA9F0, cfunc_GetIsPaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetIsPausedL`.
 */
int moho::cfunc_GetIsPaused(lua_State* const luaContext)
{
  return cfunc_GetIsPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BAA10 (FUN_008BAA10, func_GetIsPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetIsPaused(units)`.
 */
CScrLuaInitForm* moho::func_GetIsPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kGetIsPausedGlobalName,
    &moho::cfunc_GetIsPaused,
    nullptr,
    kGlobalLuaClassName,
    kGetIsPausedGlobalHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BAA70 (FUN_008BAA70, cfunc_GetIsPausedL)
 *
 * What it does:
 * Returns true when any live unit in the input table is paused.
 */
int moho::cfunc_GetIsPausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetIsPausedGlobalHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));
  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      Unit* const unit = ResolveUnitBridge(userUnit);
      if (userUnit != nullptr && unit != nullptr && !unit->IsDead() && userUnit->mPaused) {
        lua_pushboolean(rawState, 1);
        (void)lua_gettop(rawState);
        return 1;
      }
    }
  }

  lua_pushboolean(rawState, 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008BABA0 (FUN_008BABA0, cfunc_GetIsAutoMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetIsAutoModeL`.
 */
int moho::cfunc_GetIsAutoMode(lua_State* const luaContext)
{
  return cfunc_GetIsAutoModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BABC0 (FUN_008BABC0, func_GetIsAutoMode_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetIsAutoMode(units)`.
 */
CScrLuaInitForm* moho::func_GetIsAutoMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kGetIsAutoModeGlobalName,
    &moho::cfunc_GetIsAutoMode,
    nullptr,
    kGlobalLuaClassName,
    kGetIsAutoModeGlobalHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BAC20 (FUN_008BAC20, cfunc_GetIsAutoModeL)
 *
 * What it does:
 * Returns true when all live units in the input table report auto mode.
 */
int moho::cfunc_GetIsAutoModeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetIsAutoModeGlobalHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));
  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    if (unitCount >= 1) {
      for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
        const LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
        UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
        Unit* const unit = ResolveUnitBridge(userUnit);
        if (userUnit != nullptr && unit != nullptr && !unit->IsDead() && !userUnit->GetAutoMode()) {
          lua_pushboolean(rawState, 0);
          (void)lua_gettop(rawState);
          return 1;
        }
      }
    }
  }

  lua_pushboolean(rawState, 1);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008BAF60 (FUN_008BAF60, cfunc_GetIsSubmerged)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetIsSubmergedL`.
 */
int moho::cfunc_GetIsSubmerged(lua_State* const luaContext)
{
  return cfunc_GetIsSubmergedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BAF80 (FUN_008BAF80, func_GetIsSubmerged_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetIsSubmerged(units)`.
 */
CScrLuaInitForm* moho::func_GetIsSubmerged_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kGetIsSubmergedGlobalName,
    &moho::cfunc_GetIsSubmerged,
    nullptr,
    kGlobalLuaClassName,
    kGetIsSubmergedGlobalHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BAFE0 (FUN_008BAFE0, cfunc_GetIsSubmergedL)
 *
 * What it does:
 * Returns `-1` when all listed units are submerged, `1` when all are not
 * submerged, and `0` when mixed/unknown.
 */
int moho::cfunc_GetIsSubmergedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetIsSubmergedGlobalHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));

  std::int32_t submergedState = 0;
  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      Unit* const unit = ResolveUnitBridge(userUnit);
      const std::int32_t unitState =
        (unit != nullptr && unit->mCurrentLayer == LAYER_Sub) ? static_cast<std::int32_t>(-1) : static_cast<std::int32_t>(1);

      if (unitIndex == 1) {
        submergedState = unitState;
      } else if (unitState != submergedState) {
        submergedState = 0;
        break;
      }
    }
  }

  lua_pushnumber(rawState, static_cast<float>(submergedState));
  return 1;
}

/**
 * Address: 0x008BB120 (FUN_008BB120, cfunc_GetIsAutoSurfaceMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetIsAutoSurfaceModeL`.
 */
int moho::cfunc_GetIsAutoSurfaceMode(lua_State* const luaContext)
{
  return cfunc_GetIsAutoSurfaceModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB140 (FUN_008BB140, func_GetIsAutoSurfaceMode_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetIsAutoSurfaceMode(units)`.
 */
CScrLuaInitForm* moho::func_GetIsAutoSurfaceMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kGetIsAutoSurfaceModeGlobalName,
    &moho::cfunc_GetIsAutoSurfaceMode,
    nullptr,
    kGlobalLuaClassName,
    kGetIsAutoSurfaceModeGlobalHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB1A0 (FUN_008BB1A0, cfunc_GetIsAutoSurfaceModeL)
 *
 * What it does:
 * Returns true when all live units in the input table report auto-surface mode.
 */
int moho::cfunc_GetIsAutoSurfaceModeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetIsAutoSurfaceModeGlobalHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));
  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    if (unitCount >= 1) {
      for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
        const LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
        UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
        Unit* const unit = ResolveUnitBridge(userUnit);
        if (userUnit != nullptr && unit != nullptr && !unit->IsDead() && !userUnit->IsAutoSurfaceMode()) {
          lua_pushboolean(rawState, 0);
          (void)lua_gettop(rawState);
          return 1;
        }
      }
    }
  }

  lua_pushboolean(rawState, 1);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008BBA10 (FUN_008BBA10, cfunc_SetFireStateL)
 *
 * What it does:
 * Applies one fire-state string command to each live unit in the input table.
 */
int moho::cfunc_SetFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetFireStateArgsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));
  if (!unitsObject.IsTable()) {
    return 0;
  }

  const int unitCount = unitsObject.GetCount();
  for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
    LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
    UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
    Unit* const unit = ResolveUnitBridge(userUnit);
    if (unit == nullptr || unit->IsDead()) {
      continue;
    }

    const LuaPlus::LuaStackObject fireStateArg(state, 2);
    const char* fireStateValue = lua_tostring(rawState, 2);
    if (fireStateValue == nullptr) {
      fireStateArg.TypeError("string");
      fireStateValue = "";
    }

    if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
      activeDriver->ProcessInfoPair(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(unit->GetEntityId())),
        kSetFireStateName,
        fireStateValue
      );
    }
  }

  return 0;
}

/**
 * Address: 0x008BB990 (FUN_008BB990, cfunc_SetFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetFireStateL`.
 */
int moho::cfunc_SetFireState(lua_State* const luaContext)
{
  return cfunc_SetFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB9B0 (FUN_008BB9B0, func_SetFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `SetFireState(units, newFireState)`.
 */
CScrLuaInitForm* moho::func_SetFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kSetFireStateName,
    &moho::cfunc_SetFireState,
    nullptr,
    kGlobalLuaClassName,
    kSetFireStateBindHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB560 (FUN_008BB560, cfunc_GetFireStateL)
 *
 * What it does:
 * Reads one table of user units and returns one shared fire-state value when
 * all eligible units agree, otherwise `-1`.
 */
int moho::cfunc_GetFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetFireStateArgsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));

  std::int32_t fireState = 3;
  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      if (!userUnit) {
        continue;
      }

      Unit* const unit = ResolveUnitBridge(userUnit);
      if (!unit || unit->IsDead()) {
        continue;
      }

      if ((unit->GetAttributes().commandCapsMask & static_cast<std::uint32_t>(RULEUCC_RetaliateToggle)) == 0u) {
        continue;
      }

      if (fireState == 3) {
        fireState = userUnit->mFireState;
      } else if (fireState != userUnit->mFireState) {
        fireState = -1;
      }
    }
  }

  if (fireState == 3) {
    fireState = -1;
  }

  lua_pushnumber(rawState, static_cast<float>(fireState));
  return 1;
}

/**
 * Address: 0x008BB4E0 (FUN_008BB4E0, cfunc_GetFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetFireStateL`.
 */
int moho::cfunc_GetFireState(lua_State* const luaContext)
{
  return cfunc_GetFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB500 (FUN_008BB500, func_GetFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetFireState(units)`.
 */
CScrLuaInitForm* moho::func_GetFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kGetFireStateName,
    &moho::cfunc_GetFireState,
    nullptr,
    kGlobalLuaClassName,
    kGetFireStateBindHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB6E0 (FUN_008BB6E0, cfunc_ToggleFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ToggleFireStateL`.
 */
int moho::cfunc_ToggleFireState(lua_State* const luaContext)
{
  return cfunc_ToggleFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB700 (FUN_008BB700, func_ToggleFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `ToggleFireState(units, currentFireState)`.
 */
CScrLuaInitForm* moho::func_ToggleFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kToggleFireStateGlobalName,
    &moho::cfunc_ToggleFireState,
    nullptr,
    kGlobalLuaClassName,
    kToggleFireStateGlobalBindHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB760 (FUN_008BB760, cfunc_ToggleFireStateL)
 *
 * What it does:
 * Rotates one global fire-state lane and dispatches `SetFireState` info pairs
 * for each live unit in the input table.
 */
int moho::cfunc_ToggleFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kToggleFireStateGlobalArgsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));

  LuaPlus::LuaStackObject currentFireStateArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&currentFireStateArg, "integer");
  }

  const std::int32_t currentFireState = static_cast<std::int32_t>(lua_tonumber(rawState, 2));
  EFireState nextFireState = static_cast<EFireState>((currentFireState + 1) % 3);

  gpg::RRef nextFireStateRef{};
  gpg::RRef_EFireState(&nextFireStateRef, &nextFireState);
  const msvc8::string nextFireStateLexical = nextFireStateRef.GetLexical();

  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      Unit* const unit = ResolveUnitBridge(userUnit);
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      if (ISTIDriver* const activeDriver = SIM_GetActiveDriver(); activeDriver != nullptr) {
        const std::uintptr_t entityIdWord = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(unit->GetEntityId()));
        activeDriver->ProcessInfoPair(reinterpret_cast<void*>(entityIdWord), kSetFireStateName, nextFireStateLexical.c_str());
      }
    }
  }

  return 0;
}

/**
 * Address: 0x006CD380 (FUN_006CD380, cfunc_UnitGetGuardedUnitL)
 *
 * What it does:
 * Resolves one unit and pushes its guarded target unit Lua object, or `nil`.
 */
int moho::cfunc_UnitGetGuardedUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetGuardedUnitHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (Unit* const guardedUnit = unit->GetGuardedUnit(); guardedUnit != nullptr) {
    LuaPlus::LuaObject guardedUnitObject = guardedUnit->GetLuaObject();
    guardedUnitObject.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x006CD300 (FUN_006CD300, cfunc_UnitGetGuardedUnit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetGuardedUnitL`.
 */
int moho::cfunc_UnitGetGuardedUnit(lua_State* const luaContext)
{
  return cfunc_UnitGetGuardedUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD320 (FUN_006CD320, func_UnitGetGuardedUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetGuardedUnit()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetGuardedUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetGuardedUnitName,
    &moho::cfunc_UnitGetGuardedUnit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetGuardedUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CD4E0 (FUN_006CD4E0, cfunc_UnitGetGuardsL)
 *
 * What it does:
 * Returns a Lua array containing script objects for units currently guarding
 * this unit.
 */
int moho::cfunc_UnitGetGuardsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetGuardsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  LuaPlus::LuaObject guardsTable{};
  guardsTable.AssignNewTable(state, 0, 0);

  const gpg::fastvector_runtime_view<SGuardedByWeakOwnerSlot> guardedBySlots = unit->GuardedByList.mSlots;
  int guardIndex = 1;
  for (const SGuardedByWeakOwnerSlot* slot = guardedBySlots.begin; slot != guardedBySlots.end; ++slot) {
    Entity* const guardEntity = DecodeGuardedByOwnerSlot(*slot);
    if (guardEntity == nullptr) {
      continue;
    }

    LuaPlus::LuaObject guardObject = guardEntity->mLuaObj;
    guardsTable.Insert(guardIndex, guardObject);
    ++guardIndex;
  }

  guardsTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x006CD460 (FUN_006CD460, cfunc_UnitGetGuards)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetGuardsL`.
 */
int moho::cfunc_UnitGetGuards(lua_State* const luaContext)
{
  return cfunc_UnitGetGuardsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD480 (FUN_006CD480, func_UnitGetGuards_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetGuards()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetGuards_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetGuardsName,
    &moho::cfunc_UnitGetGuards,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetGuardsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CD6E0 (FUN_006CD6E0, cfunc_UnitGetTransportFerryBeaconL)
 *
 * What it does:
 * Returns the front command's ferry-beacon unit Lua object, or `nil` when no
 * valid beacon unit is available.
 */
int moho::cfunc_UnitGetTransportFerryBeaconL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetTransportFerryBeaconHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const CUnitCommandQueue* const commandQueue = unit->CommandQueue;
  if (commandQueue != nullptr && !commandQueue->mCommandVec.empty()) {
    const CUnitCommand* const command = commandQueue->mCommandVec.front().GetObjectPtr();
    if (command != nullptr && reinterpret_cast<std::uintptr_t>(command) != kInvalidWeakCommandSentinel) {
      boost::shared_ptr<Unit> ferryBeaconUnit = command->mUnit.lock();
      if (ferryBeaconUnit) {
        LuaPlus::LuaObject ferryBeaconLuaObject = ferryBeaconUnit->GetLuaObject();
        ferryBeaconLuaObject.PushStack(state);
        return 1;
      }
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CD660 (FUN_006CD660, cfunc_UnitGetTransportFerryBeacon)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetTransportFerryBeaconL`.
 */
int moho::cfunc_UnitGetTransportFerryBeacon(lua_State* const luaContext)
{
  return cfunc_UnitGetTransportFerryBeaconL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD680 (FUN_006CD680, func_UnitGetTransportFerryBeacon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetTransportFerryBeacon()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetTransportFerryBeacon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetTransportFerryBeaconName,
    &moho::cfunc_UnitGetTransportFerryBeacon,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetTransportFerryBeaconHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CD860 (FUN_006CD860, cfunc_UnitHasValidTeleportDestL)
 *
 * What it does:
 * Returns whether the unit has a non-zero teleport destination on its transport AI lane.
 */
int moho::cfunc_UnitHasValidTeleportDestL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitHasValidTeleportDestHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  bool hasValidTeleportDestination = false;
  if (unit != nullptr) {
    if (IAiTransport* const aiTransport = unit->AiTransport; aiTransport != nullptr) {
      const Wm3::Vec3f teleportDestination = aiTransport->TransportGetTeleportDest();
      const Wm3::Vec3f zero{};
      hasValidTeleportDestination = Wm3::Vector3f::Compare(&teleportDestination, &zero) != 0;
    }
  }

  lua_pushboolean(rawState, hasValidTeleportDestination ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CD7E0 (FUN_006CD7E0, cfunc_UnitHasValidTeleportDest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitHasValidTeleportDestL`.
 */
int moho::cfunc_UnitHasValidTeleportDest(lua_State* const luaContext)
{
  return cfunc_UnitHasValidTeleportDestL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD800 (FUN_006CD800, func_UnitHasValidTeleportDest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:HasValidTeleportDest()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitHasValidTeleportDest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitHasValidTeleportDestName,
    &moho::cfunc_UnitHasValidTeleportDest,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitHasValidTeleportDestHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CD9D0 (FUN_006CD9D0, cfunc_UnitAddUnitToStorageL)
 *
 * What it does:
 * Adds one unit argument into a carrier's storage lane when capacity is available.
 */
int moho::cfunc_UnitAddUnitToStorageL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitAddUnitToStorageHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject carrierObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const carrierUnit = SCR_FromLua_Unit(carrierObject);
  const LuaPlus::LuaObject storedUnitObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const storedUnit = SCR_FromLua_Unit(storedUnitObject);

  if (carrierUnit != nullptr && storedUnit != nullptr) {
    if (IAiTransport* const aiTransport = carrierUnit->AiTransport; aiTransport != nullptr) {
      if (aiTransport->TransportHasAvailableStorage()) {
        aiTransport->TransportAddToStorage(storedUnit);
        return 0;
      }

      gpg::Warnf(kUnitAddUnitToStorageNoRoomWarning);
    }
  }

  return 0;
}

/**
 * Address: 0x006CD950 (FUN_006CD950, cfunc_UnitAddUnitToStorage)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitAddUnitToStorageL`.
 */
int moho::cfunc_UnitAddUnitToStorage(lua_State* const luaContext)
{
  return cfunc_UnitAddUnitToStorageL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD970 (FUN_006CD970, func_UnitAddUnitToStorage_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AddUnitToStorage(storedUnit)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitAddUnitToStorage_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitAddUnitToStorageName,
    &moho::cfunc_UnitAddUnitToStorage,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAddUnitToStorageHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CE280 (FUN_006CE280, cfunc_UnitGetCommandQueueL)
 *
 * What it does:
 * Returns Lua array copy of one unit's current command queue.
 */
int moho::cfunc_UnitGetCommandQueueL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetCommandQueueHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);
  if (unit == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidUnitError);
    return 0;
  }

  CUnitCommandQueue* const commandQueue = unit->CommandQueue;
  if (commandQueue == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidQueueError);
    return 0;
  }

  const msvc8::vector<WeakPtr<CUnitCommand>> commandSnapshot = commandQueue->mCommandVec;

  LuaPlus::LuaObject queueArray{};
  const int commandCount = static_cast<int>(commandSnapshot.size());
  queueArray.AssignNewTable(state, commandCount, 0u);
  for (const WeakPtr<CUnitCommand>& commandWeakPtr : commandSnapshot) {
    CUnitCommand* const command = commandWeakPtr.GetObject();
    if (command == nullptr) {
      continue;
    }

    SimGetCommandQueueInsert(queueArray, *command);
  }

  queueArray.PushStack(state);
  return 1;
}

/**
 * Address: 0x006CE200 (FUN_006CE200, cfunc_UnitGetCommandQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetCommandQueueL`.
 */
int moho::cfunc_UnitGetCommandQueue(lua_State* const luaContext)
{
  return cfunc_UnitGetCommandQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CE220 (FUN_006CE220, func_UnitGetCommandQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetCommandQueue()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCommandQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetCommandQueueName,
    &moho::cfunc_UnitGetCommandQueue,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCommandQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CE4A0 (FUN_006CE4A0, cfunc_UnitPrintCommandQueueL)
 *
 * What it does:
 * Logs one textual dump of the unit command queue into AI debug output.
 */
int moho::cfunc_UnitPrintCommandQueueL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitPrintCommandQueueHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (unit == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidUnitError);
    return 0;
  }

  const CUnitCommandQueue* const commandQueue = unit->CommandQueue;
  if (commandQueue == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidQueueError);
    return 0;
  }

  const msvc8::vector<WeakPtr<CUnitCommand>> commandSnapshot = commandQueue->mCommandVec;

  const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
  const char* const unitName = (unitBlueprint != nullptr) ? unitBlueprint->mBlueprintId.c_str() : "";
  gpg::Logf(kUnitPrintCommandQueueHeaderLogFormat, unitName);

  for (const WeakPtr<CUnitCommand>& commandWeakPtr : commandSnapshot) {
    CUnitCommand* const command = commandWeakPtr.GetObjectPtr();
    if (command == nullptr || reinterpret_cast<std::uintptr_t>(command) == kInvalidWeakCommandSentinel) {
      continue;
    }

    const std::string commandLabel = BuildPrintCommandQueueLabel(*command);
    gpg::Logf(kUnitPrintCommandQueueEntryLogFormat, commandLabel.c_str());
  }

  return 1;
}

/**
 * Address: 0x006CE420 (FUN_006CE420, cfunc_UnitPrintCommandQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitPrintCommandQueueL`.
 */
int moho::cfunc_UnitPrintCommandQueue(lua_State* const luaContext)
{
  return cfunc_UnitPrintCommandQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CE440 (FUN_006CE440, func_UnitPrintCommandQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:PrintCommandQueue()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitPrintCommandQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitPrintCommandQueueName,
    &moho::cfunc_UnitPrintCommandQueue,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitPrintCommandQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CEAE0 (FUN_006CEAE0, cfunc_UnitGetCurrentMoveLocationL)
 *
 * What it does:
 * Returns one current command target-position vector for supported movement
 * command types, or `false` when no supported active move command exists.
 */
int moho::cfunc_UnitGetCurrentMoveLocationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetCurrentMoveLocationHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);
  if (unit == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCurrentMoveLocationInvalidUnitError);
    return 0;
  }

  const CUnitCommandQueue* const commandQueue = unit->CommandQueue;
  const CUnitCommand* command = nullptr;
  if (commandQueue != nullptr && !commandQueue->mCommandVec.empty()) {
    command = commandQueue->mCommandVec.front().GetObjectPtr();
  }

  if (command != nullptr && reinterpret_cast<std::uintptr_t>(command) != kInvalidWeakCommandSentinel) {
    switch (command->mVarDat.mCmdType) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_Reclaim:
      case EUnitCommandType::UNITCOMMAND_Repair:
      case EUnitCommandType::UNITCOMMAND_Capture:
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits:
      case EUnitCommandType::UNITCOMMAND_Upgrade:
      case EUnitCommandType::UNITCOMMAND_Sacrifice:
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
      case EUnitCommandType::UNITCOMMAND_Dock: {
        const LuaPlus::LuaObject moveLocation = SCR_ToLua<Wm3::Vector3<float>>(state, command->mVarDat.mTarget1.mPos);
        moveLocation.PushStack(state);
        return 1;
      }
      default:
        break;
    }
  }

  lua_pushboolean(rawState, 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CEA60 (FUN_006CEA60, cfunc_UnitGetCurrentMoveLocation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetCurrentMoveLocationL`.
 */
int moho::cfunc_UnitGetCurrentMoveLocation(lua_State* const luaContext)
{
  return cfunc_UnitGetCurrentMoveLocationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CEA80 (FUN_006CEA80, func_UnitGetCurrentMoveLocation_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetCurrentMoveLocation()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCurrentMoveLocation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetCurrentMoveLocationName,
    &moho::cfunc_UnitGetCurrentMoveLocation,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCurrentMoveLocationHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CED40 (FUN_006CED40, cfunc_UnitGiveNukeSiloAmmoL)
 *
 * What it does:
 * Adds nuke ammo to a unit silo, or sets current segment count when called
 * with three Lua arguments.
 */
int moho::cfunc_UnitGiveNukeSiloAmmoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  bool setSegmentAmount = false;
  if (argumentCount != 2) {
    if (argumentCount == 3) {
      setSegmentAmount = true;
    } else {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGiveNukeSiloAmmoHelpText, 2, argumentCount);
    }
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      const LuaPlus::LuaStackObject amountObject(state, 2);
      const int amount = amountObject.GetInteger();
      if (setSegmentAmount) {
        siloBuild->mCurSegments = amount;
      } else {
        siloBuild->SiloAdjustStorageCount(SILOTYPE_Nuke, amount);
      }
    }
  }

  return 0;
}

/**
 * Address: 0x006CECC0 (FUN_006CECC0, cfunc_UnitGiveNukeSiloAmmo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGiveNukeSiloAmmoL`.
 */
int moho::cfunc_UnitGiveNukeSiloAmmo(lua_State* const luaContext)
{
  return cfunc_UnitGiveNukeSiloAmmoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CECE0 (FUN_006CECE0, func_UnitGiveNukeSiloAmmo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GiveNukeSiloAmmo(num)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGiveNukeSiloAmmo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGiveNukeSiloAmmoName,
    &moho::cfunc_UnitGiveNukeSiloAmmo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGiveNukeSiloAmmoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CEE90 (FUN_006CEE90, cfunc_UnitRemoveNukeSiloAmmoL)
 *
 * What it does:
 * Removes a requested nuke ammo count from the unit silo lane.
 */
int moho::cfunc_UnitRemoveNukeSiloAmmoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRemoveNukeSiloAmmoHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      const LuaPlus::LuaStackObject amountObject(state, 2);
      const int amount = amountObject.GetInteger();
      siloBuild->SiloAdjustStorageCount(SILOTYPE_Nuke, -amount);
    }
  }

  return 0;
}

/**
 * Address: 0x006CEE10 (FUN_006CEE10, cfunc_UnitRemoveNukeSiloAmmo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveNukeSiloAmmoL`.
 */
int moho::cfunc_UnitRemoveNukeSiloAmmo(lua_State* const luaContext)
{
  return cfunc_UnitRemoveNukeSiloAmmoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CEE30 (FUN_006CEE30, func_UnitRemoveNukeSiloAmmo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveNukeSiloAmmo(num)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveNukeSiloAmmo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRemoveNukeSiloAmmoName,
    &moho::cfunc_UnitRemoveNukeSiloAmmo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveNukeSiloAmmoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CEFE0 (FUN_006CEFE0, cfunc_UnitGetNukeSiloAmmoCountL)
 *
 * What it does:
 * Returns the nuke silo stored ammo count for a unit, or `0` when absent.
 */
int moho::cfunc_UnitGetNukeSiloAmmoCountL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetNukeSiloAmmoCountHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  float nukeAmmoCount = 0.0f;
  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      nukeAmmoCount = static_cast<float>(siloBuild->SiloGetStorageCount(SILOTYPE_Nuke));
    }
  }

  lua_pushnumber(rawState, nukeAmmoCount);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CEF60 (FUN_006CEF60, cfunc_UnitGetNukeSiloAmmoCount)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetNukeSiloAmmoCountL`.
 */
int moho::cfunc_UnitGetNukeSiloAmmoCount(lua_State* const luaContext)
{
  return cfunc_UnitGetNukeSiloAmmoCountL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CEF80 (FUN_006CEF80, func_UnitGetNukeSiloAmmoCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetNukeSiloAmmoCount()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetNukeSiloAmmoCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetNukeSiloAmmoCountName,
    &moho::cfunc_UnitGetNukeSiloAmmoCount,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetNukeSiloAmmoCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CF150 (FUN_006CF150, cfunc_UnitGiveTacticalSiloAmmoL)
 *
 * What it does:
 * Adds tactical missile ammo amount to the unit silo storage lane.
 */
int moho::cfunc_UnitGiveTacticalSiloAmmoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGiveTacticalSiloAmmoHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      const LuaPlus::LuaStackObject amountObject(state, 2);
      const int amount = amountObject.GetInteger();
      siloBuild->SiloAdjustStorageCount(SILOTYPE_Tactical, amount);
    }
  }

  return 0;
}

/**
 * Address: 0x006CF0D0 (FUN_006CF0D0, cfunc_UnitGiveTacticalSiloAmmo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGiveTacticalSiloAmmoL`.
 */
int moho::cfunc_UnitGiveTacticalSiloAmmo(lua_State* const luaContext)
{
  return cfunc_UnitGiveTacticalSiloAmmoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CF0F0 (FUN_006CF0F0, func_UnitGiveTacticalSiloAmmo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GiveTacticalSiloAmmo(num)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGiveTacticalSiloAmmo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGiveTacticalSiloAmmoName,
    &moho::cfunc_UnitGiveTacticalSiloAmmo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGiveTacticalSiloAmmoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CF2A0 (FUN_006CF2A0, cfunc_UnitRemoveTacticalSiloAmmoL)
 *
 * What it does:
 * Removes requested tactical missile ammo amount from unit silo storage.
 */
int moho::cfunc_UnitRemoveTacticalSiloAmmoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRemoveTacticalSiloAmmoHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      const LuaPlus::LuaStackObject amountObject(state, 2);
      const int amount = amountObject.GetInteger();
      siloBuild->SiloAdjustStorageCount(SILOTYPE_Tactical, -amount);
    }
  }

  return 0;
}

/**
 * Address: 0x006CF220 (FUN_006CF220, cfunc_UnitRemoveTacticalSiloAmmo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveTacticalSiloAmmoL`.
 */
int moho::cfunc_UnitRemoveTacticalSiloAmmo(lua_State* const luaContext)
{
  return cfunc_UnitRemoveTacticalSiloAmmoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CF240 (FUN_006CF240, func_UnitRemoveTacticalSiloAmmo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveTacticalSiloAmmo(num)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveTacticalSiloAmmo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRemoveTacticalSiloAmmoName,
    &moho::cfunc_UnitRemoveTacticalSiloAmmo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveTacticalSiloAmmoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CF3F0 (FUN_006CF3F0, cfunc_UnitGetTacticalSiloAmmoCountL)
 *
 * What it does:
 * Returns tactical silo stored ammo count for a unit, or `0` when absent.
 */
int moho::cfunc_UnitGetTacticalSiloAmmoCountL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetTacticalSiloAmmoCountHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  float tacticalAmmoCount = 0.0f;
  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      tacticalAmmoCount = static_cast<float>(siloBuild->SiloGetStorageCount(SILOTYPE_Tactical));
    }
  }

  lua_pushnumber(rawState, tacticalAmmoCount);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CF370 (FUN_006CF370, cfunc_UnitGetTacticalSiloAmmoCount)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetTacticalSiloAmmoCountL`.
 */
int moho::cfunc_UnitGetTacticalSiloAmmoCount(lua_State* const luaContext)
{
  return cfunc_UnitGetTacticalSiloAmmoCountL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CF390 (FUN_006CF390, func_UnitGetTacticalSiloAmmoCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetTacticalSiloAmmoCount()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetTacticalSiloAmmoCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetTacticalSiloAmmoCountName,
    &moho::cfunc_UnitGetTacticalSiloAmmoCount,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetTacticalSiloAmmoCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BBB90 (FUN_008BBB90, cfunc_GetScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetScriptBitL`.
 */
int moho::cfunc_GetScriptBit(lua_State* const luaContext)
{
  return cfunc_GetScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BBBB0 (FUN_008BBBB0, func_GetScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetScriptBit`.
 */
CScrLuaInitForm* moho::func_GetScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetScriptBit",
    &moho::cfunc_GetScriptBit,
    nullptr,
    kGlobalLuaClassName,
    "Get the state for the script big"
  );
  return &binder;
}

/**
 * Address: 0x008BBC10 (FUN_008BBC10, cfunc_GetScriptBitL)
 *
 * What it does:
 * Returns true if any non-dead user unit in the input table supports `bit`
 * via toggle caps and currently has that script bit set.
 */
int moho::cfunc_GetScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetScriptBitHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));

  const LuaPlus::LuaStackObject bitArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    bitArg.TypeError("integer");
  }
  const int bitIndex = static_cast<int>(lua_tonumber(rawState, 2));

  bool hasBitSet = false;
  if (unitsObject.IsTable()) {
    const int count = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= count; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      Unit* const unit = ResolveUnitBridge(userUnit);
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      const std::uint32_t toggleMask = 1u << (static_cast<std::uint32_t>(bitIndex) & 0x1Fu);
      if ((unit->GetAttributes().toggleCapsMask & toggleMask) == 0u) {
        continue;
      }

      const std::uint32_t bitShift = static_cast<std::uint32_t>(bitIndex);
      const std::int64_t scriptBits = static_cast<std::int64_t>(static_cast<std::int32_t>(unit->ScriptBitMask));
      const std::int64_t scriptBitMask = bitShift < 64u ? static_cast<std::int64_t>(1ull << bitShift) : 0;
      if ((scriptBits & scriptBitMask) != 0) {
        hasBitSet = true;
        break;
      }
    }
  }

  lua_pushboolean(rawState, hasBitSet ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5980 (FUN_006C5980, cfunc_UnitIsUnitStateL)
 *
 * What it does:
 * Resolves `(unit, stateName)` and returns whether that runtime unit-state bit
 * is currently set.
 */
int moho::cfunc_UnitIsUnitStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsUnitStateHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  EUnitState unitState = UNITSTATE_Immobile;
  gpg::RRef enumRef = MakeUnitStateRef(&unitState);
  const LuaPlus::LuaStackObject stateArg(state, 2);
  const char* const stateName = lua_tostring(rawState, 2);
  if (stateName == nullptr) {
    stateArg.TypeError("string");
  }
  SCR_GetEnum(state, stateName, enumRef);

  lua_pushboolean(rawState, unit->IsUnitState(unitState) ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5900 (FUN_006C5900, cfunc_UnitIsUnitState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsUnitStateL`.
 */
int moho::cfunc_UnitIsUnitState(lua_State* const luaContext)
{
  return cfunc_UnitIsUnitStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5920 (FUN_006C5920, func_UnitIsUnitState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsUnitState(unit, stateName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsUnitState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsUnitStateName,
    &moho::cfunc_UnitIsUnitState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsUnitStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5B20 (FUN_006C5B20, cfunc_UnitIsIdleStateL)
 *
 * What it does:
 * Returns whether a unit has no live front command in its current queue.
 */
int moho::cfunc_UnitIsIdleStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsIdleStateHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  bool isIdle = true;
  if (const CUnitCommandQueue* const commandQueue = unit->CommandQueue;
      commandQueue != nullptr && !commandQueue->mCommandVec.empty()) {
    const CUnitCommand* const command = commandQueue->mCommandVec.front().GetObjectPtr();
    if (command != nullptr && reinterpret_cast<std::uintptr_t>(command) != kInvalidWeakCommandSentinel) {
      isIdle = false;
    }
  }

  lua_pushboolean(rawState, isIdle ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5AA0 (FUN_006C5AA0, cfunc_UnitIsIdleState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsIdleStateL`.
 */
int moho::cfunc_UnitIsIdleState(lua_State* const luaContext)
{
  return cfunc_UnitIsIdleStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5AC0 (FUN_006C5AC0, func_UnitIsIdleState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsIdleState(unit)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsIdleState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsIdleStateName,
    &moho::cfunc_UnitIsIdleState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsIdleStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5C90 (FUN_006C5C90, cfunc_UnitIsStunnedL)
 *
 * What it does:
 * Returns true when arg#1 does not resolve to a unit or the unit has active
 * stun ticks.
 */
int moho::cfunc_UnitIsStunnedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsStunnedHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = GetUnitOptional(unitObject);
  const bool isStunned = (unit == nullptr) || (unit->StunnedState != 0);
  lua_pushboolean(rawState, isStunned ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5C10 (FUN_006C5C10, cfunc_UnitIsStunned)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsStunnedL`.
 */
int moho::cfunc_UnitIsStunned(lua_State* const luaContext)
{
  return cfunc_UnitIsStunnedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5C30 (FUN_006C5C30, func_UnitIsStunned_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsStunned(unit)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsStunned_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsStunnedName,
    &moho::cfunc_UnitIsStunned,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsStunnedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5DE0 (FUN_006C5DE0, cfunc_UnitIsBeingBuiltL)
 *
 * What it does:
 * Returns true when arg#1 resolves to a unit currently in being-built state.
 */
int moho::cfunc_UnitIsBeingBuiltL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsBeingBuiltHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = GetUnitOptional(unitObject);
  lua_pushboolean(rawState, (unit != nullptr && unit->IsBeingBuilt()) ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5D60 (FUN_006C5D60, cfunc_UnitIsBeingBuilt)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsBeingBuiltL`.
 */
int moho::cfunc_UnitIsBeingBuilt(lua_State* const luaContext)
{
  return cfunc_UnitIsBeingBuiltL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5D80 (FUN_006C5D80, func_UnitIsBeingBuilt_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsBeingBuilt()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsBeingBuilt_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsBeingBuiltName,
    &moho::cfunc_UnitIsBeingBuilt,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsBeingBuiltHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5F30 (FUN_006C5F30, cfunc_UnitIsPausedL)
 *
 * What it does:
 * Returns true when arg#1 resolves to a currently paused unit.
 */
int moho::cfunc_UnitIsPausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsPausedHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = GetUnitOptional(unitObject);
  lua_pushboolean(rawState, (unit != nullptr && unit->IsPaused) ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5EB0 (FUN_006C5EB0, cfunc_UnitIsPaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsPausedL`.
 */
int moho::cfunc_UnitIsPaused(lua_State* const luaContext)
{
  return cfunc_UnitIsPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5ED0 (FUN_006C5ED0, func_UnitIsPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsPaused()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsPausedName,
    &moho::cfunc_UnitIsPaused,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6080 (FUN_006C6080, cfunc_UnitSetPausedL)
 *
 * What it does:
 * Applies paused state from arg#2 to the unit resolved from arg#1.
 */
int moho::cfunc_UnitSetPausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetPausedHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);

  const LuaPlus::LuaStackObject pausedArg(state, 2);
  const bool paused = pausedArg.GetBoolean();
  unit->SetPaused(paused);

  return 0;
}

/**
 * Address: 0x006C6000 (FUN_006C6000, cfunc_UnitSetPaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetPausedL`.
 */
int moho::cfunc_UnitSetPaused(lua_State* const luaContext)
{
  return cfunc_UnitSetPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6020 (FUN_006C6020, func_UnitSetPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetPaused()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetPausedName,
    &moho::cfunc_UnitSetPaused,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C61C0 (FUN_006C61C0, cfunc_UnitSetConsumptionActiveL)
 *
 * What it does:
 * Applies consumption-active flag from arg#2 to the unit resolved from arg#1.
 */
int moho::cfunc_UnitSetConsumptionActiveL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetConsumptionActiveHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);

  const LuaPlus::LuaStackObject activeArg(state, 2);
  const bool isActive = activeArg.GetBoolean();
  unit->SetConsumptionActive(isActive);

  return 1;
}

/**
 * Address: 0x006C6140 (FUN_006C6140, cfunc_UnitSetConsumptionActive)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetConsumptionActiveL`.
 */
int moho::cfunc_UnitSetConsumptionActive(lua_State* const luaContext)
{
  return cfunc_UnitSetConsumptionActiveL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6160 (FUN_006C6160, func_UnitSetConsumptionActive_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetConsumptionActive(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetConsumptionActive_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetConsumptionActiveName,
    &moho::cfunc_UnitSetConsumptionActive,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetConsumptionActiveHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9E20 (FUN_006C9E20, cfunc_UnitSetConsumptionPerSecondEnergyL)
 *
 * What it does:
 * Writes a clamped non-negative energy consumption-per-second value from arg#2
 * into the unit attributes resolved from arg#1, then refreshes active
 * consumption bookkeeping if needed.
 */
int moho::cfunc_UnitSetConsumptionPerSecondEnergyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetConsumptionPerSecondEnergyHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject consumptionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    consumptionArg.TypeError("number");
  }

  float consumptionPerSecond = static_cast<float>(lua_tonumber(rawState, 2));
  if (consumptionPerSecond < 0.0f) {
    consumptionPerSecond = 0.0f;
  }

  unit->GetAttributes().consumptionPerSecondEnergy = consumptionPerSecond;
  if (unit->ConsumptionActive) {
    unit->SetConsumptionActive(true);
  }

  return 0;
}

/**
 * Address: 0x006C9DA0 (FUN_006C9DA0, cfunc_UnitSetConsumptionPerSecondEnergy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetConsumptionPerSecondEnergyL`.
 */
int moho::cfunc_UnitSetConsumptionPerSecondEnergy(lua_State* const luaContext)
{
  return cfunc_UnitSetConsumptionPerSecondEnergyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9DC0 (FUN_006C9DC0, func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetConsumptionPerSecondEnergy(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetConsumptionPerSecondEnergyName,
    &moho::cfunc_UnitSetConsumptionPerSecondEnergy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetConsumptionPerSecondEnergyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9FC0 (FUN_006C9FC0, cfunc_UnitSetConsumptionPerSecondMassL)
 *
 * What it does:
 * Writes a clamped non-negative mass consumption-per-second value from arg#2
 * into the unit attributes resolved from arg#1, then refreshes active
 * consumption bookkeeping if needed.
 */
int moho::cfunc_UnitSetConsumptionPerSecondMassL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetConsumptionPerSecondMassHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject consumptionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    consumptionArg.TypeError("number");
  }

  float consumptionPerSecond = static_cast<float>(lua_tonumber(rawState, 2));
  if (consumptionPerSecond < 0.0f) {
    consumptionPerSecond = 0.0f;
  }

  unit->GetAttributes().consumptionPerSecondMass = consumptionPerSecond;
  if (unit->ConsumptionActive) {
    unit->SetConsumptionActive(true);
  }

  return 0;
}

/**
 * Address: 0x006C9F40 (FUN_006C9F40, cfunc_UnitSetConsumptionPerSecondMass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetConsumptionPerSecondMassL`.
 */
int moho::cfunc_UnitSetConsumptionPerSecondMass(lua_State* const luaContext)
{
  return cfunc_UnitSetConsumptionPerSecondMassL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9F60 (FUN_006C9F60, func_UnitSetConsumptionPerSecondMass_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetConsumptionPerSecondMass(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetConsumptionPerSecondMass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetConsumptionPerSecondMassName,
    &moho::cfunc_UnitSetConsumptionPerSecondMass,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetConsumptionPerSecondMassHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C91A0 (FUN_006C91A0, cfunc_UnitSetRegenRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetRegenRateL`.
 */
int moho::cfunc_UnitSetRegenRate(lua_State* const luaContext)
{
  return cfunc_UnitSetRegenRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C91C0 (FUN_006C91C0, func_UnitSetRegenRate_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetRegenRate(rate)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetRegenRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetRegenRateName,
    &moho::cfunc_UnitSetRegenRate,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetRegenRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9220 (FUN_006C9220, cfunc_UnitSetRegenRateL)
 *
 * What it does:
 * Writes a clamped non-negative regen-rate scalar from arg #2 into arg #1 unit
 * attributes.
 */
int moho::cfunc_UnitSetRegenRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetRegenRateHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject rateArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    rateArg.TypeError("number");
  }

  float regenRate = static_cast<float>(lua_tonumber(rawState, 2));
  if (regenRate < 0.0f) {
    regenRate = 0.0f;
  }

  unit->GetAttributes().regenRate = regenRate;
  return 0;
}

/**
 * Address: 0x006C9330 (FUN_006C9330, cfunc_UnitRevertRegenRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitRevertRegenRateL`.
 */
int moho::cfunc_UnitRevertRegenRate(lua_State* const luaContext)
{
  return cfunc_UnitRevertRegenRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9350 (FUN_006C9350, func_UnitRevertRegenRate_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:RevertRegenRate()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRevertRegenRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRevertRegenRateName,
    &moho::cfunc_UnitRevertRegenRate,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRevertRegenRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C93B0 (FUN_006C93B0, cfunc_UnitRevertRegenRateL)
 *
 * What it does:
 * Restores `UnitAttributes::regenRate` from blueprint defense regen data.
 */
int moho::cfunc_UnitRevertRegenRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRevertRegenRateHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  UnitAttributes& attributes = unit->GetAttributes();

  attributes.regenRate = attributes.blueprint->Defense.RegenRate;
  return 0;
}

/**
 * Address: 0x006C9AC0 (FUN_006C9AC0, cfunc_UnitSetBuildRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetBuildRateL`.
 */
int moho::cfunc_UnitSetBuildRate(lua_State* const luaContext)
{
  return cfunc_UnitSetBuildRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9AE0 (FUN_006C9AE0, func_UnitSetBuildRate_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetBuildRate(frac)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBuildRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetBuildRateName,
    &moho::cfunc_UnitSetBuildRate,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBuildRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9B40 (FUN_006C9B40, cfunc_UnitSetBuildRateL)
 *
 * What it does:
 * Writes a clamped non-negative build-rate scalar from arg #2 into arg #1 unit
 * attributes.
 */
int moho::cfunc_UnitSetBuildRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetBuildRateHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject rateArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    rateArg.TypeError("number");
  }

  float buildRate = static_cast<float>(lua_tonumber(rawState, 2));
  if (buildRate < 0.0f) {
    buildRate = 0.0f;
  }

  unit->GetAttributes().buildRate = buildRate;
  return 0;
}

/**
 * Address: 0x006C9C50 (FUN_006C9C50, cfunc_UnitGetBuildRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetBuildRateL`.
 */
int moho::cfunc_UnitGetBuildRate(lua_State* const luaContext)
{
  return cfunc_UnitGetBuildRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9C70 (FUN_006C9C70, func_UnitGetBuildRate_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetBuildRate()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetBuildRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetBuildRateName,
    &moho::cfunc_UnitGetBuildRate,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetBuildRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9CD0 (FUN_006C9CD0, cfunc_UnitGetBuildRateL)
 *
 * What it does:
 * Returns `UnitAttributes::buildRate` for arg #1.
 */
int moho::cfunc_UnitGetBuildRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetBuildRateHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().buildRate);
  return 1;
}

/**
 * Address: 0x006CA0E0 (FUN_006CA0E0, cfunc_UnitSetProductionPerSecondEnergy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetProductionPerSecondEnergyL`.
 */
int moho::cfunc_UnitSetProductionPerSecondEnergy(lua_State* const luaContext)
{
  return cfunc_UnitSetProductionPerSecondEnergyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA100 (FUN_006CA100, func_UnitSetProductionPerSecondEnergy_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetProductionPerSecondEnergy(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetProductionPerSecondEnergy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetProductionPerSecondEnergyName,
    &moho::cfunc_UnitSetProductionPerSecondEnergy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetProductionPerSecondEnergyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA160 (FUN_006CA160, cfunc_UnitSetProductionPerSecondEnergyL)
 *
 * What it does:
 * Writes a clamped non-negative energy production-per-second scalar from arg #2
 * into arg #1 unit attributes.
 */
int moho::cfunc_UnitSetProductionPerSecondEnergyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetProductionPerSecondEnergyHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject productionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    productionArg.TypeError("number");
  }

  float productionPerSecondEnergy = static_cast<float>(lua_tonumber(rawState, 2));
  if (productionPerSecondEnergy < 0.0f) {
    productionPerSecondEnergy = 0.0f;
  }

  unit->GetAttributes().productionPerSecondEnergy = productionPerSecondEnergy;
  return 0;
}

/**
 * Address: 0x006CA270 (FUN_006CA270, cfunc_UnitSetProductionPerSecondMass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetProductionPerSecondMassL`.
 */
int moho::cfunc_UnitSetProductionPerSecondMass(lua_State* const luaContext)
{
  return cfunc_UnitSetProductionPerSecondMassL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA290 (FUN_006CA290, func_UnitSetProductionPerSecondMass_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetProductionPerSecondMass(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetProductionPerSecondMass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetProductionPerSecondMassName,
    &moho::cfunc_UnitSetProductionPerSecondMass,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetProductionPerSecondMassHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA2F0 (FUN_006CA2F0, cfunc_UnitSetProductionPerSecondMassL)
 *
 * What it does:
 * Writes a clamped non-negative mass production-per-second scalar from arg #2
 * into arg #1 unit attributes.
 */
int moho::cfunc_UnitSetProductionPerSecondMassL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetProductionPerSecondMassHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject productionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    productionArg.TypeError("number");
  }

  float productionPerSecondMass = static_cast<float>(lua_tonumber(rawState, 2));
  if (productionPerSecondMass < 0.0f) {
    productionPerSecondMass = 0.0f;
  }

  unit->GetAttributes().productionPerSecondMass = productionPerSecondMass;
  return 0;
}

/**
 * Address: 0x006CA400 (FUN_006CA400, cfunc_UnitGetConsumptionPerSecondEnergy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetConsumptionPerSecondEnergyL`.
 */
int moho::cfunc_UnitGetConsumptionPerSecondEnergy(lua_State* const luaContext)
{
  return cfunc_UnitGetConsumptionPerSecondEnergyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA420 (FUN_006CA420, func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetConsumptionPerSecondEnergy()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetConsumptionPerSecondEnergyName,
    &moho::cfunc_UnitGetConsumptionPerSecondEnergy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetConsumptionPerSecondEnergyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA480 (FUN_006CA480, cfunc_UnitGetConsumptionPerSecondEnergyL)
 *
 * What it does:
 * Returns `UnitAttributes::consumptionPerSecondEnergy` for arg #1.
 */
int moho::cfunc_UnitGetConsumptionPerSecondEnergyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetConsumptionPerSecondEnergyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().consumptionPerSecondEnergy);
  return 1;
}

/**
 * Address: 0x006CA550 (FUN_006CA550, cfunc_UnitGetConsumptionPerSecondMass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetConsumptionPerSecondMassL`.
 */
int moho::cfunc_UnitGetConsumptionPerSecondMass(lua_State* const luaContext)
{
  return cfunc_UnitGetConsumptionPerSecondMassL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA570 (FUN_006CA570, func_UnitGetConsumptionPerSecondMass_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetConsumptionPerSecondMass()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetConsumptionPerSecondMass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetConsumptionPerSecondMassName,
    &moho::cfunc_UnitGetConsumptionPerSecondMass,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetConsumptionPerSecondMassHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA5D0 (FUN_006CA5D0, cfunc_UnitGetConsumptionPerSecondMassL)
 *
 * What it does:
 * Returns `UnitAttributes::consumptionPerSecondMass` for arg #1.
 */
int moho::cfunc_UnitGetConsumptionPerSecondMassL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetConsumptionPerSecondMassHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().consumptionPerSecondMass);
  return 1;
}

/**
 * Address: 0x006CA6A0 (FUN_006CA6A0, cfunc_UnitGetProductionPerSecondEnergy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetProductionPerSecondEnergyL`.
 */
int moho::cfunc_UnitGetProductionPerSecondEnergy(lua_State* const luaContext)
{
  return cfunc_UnitGetProductionPerSecondEnergyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA6C0 (FUN_006CA6C0, func_UnitGetProductionPerSecondEnergy_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetProductionPerSecondEnergy()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetProductionPerSecondEnergy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetProductionPerSecondEnergyName,
    &moho::cfunc_UnitGetProductionPerSecondEnergy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetProductionPerSecondEnergyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA720 (FUN_006CA720, cfunc_UnitGetProductionPerSecondEnergyL)
 *
 * What it does:
 * Returns `UnitAttributes::productionPerSecondEnergy` for arg #1.
 */
int moho::cfunc_UnitGetProductionPerSecondEnergyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetProductionPerSecondEnergyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().productionPerSecondEnergy);
  return 1;
}

/**
 * Address: 0x006CA7F0 (FUN_006CA7F0, cfunc_UnitGetProductionPerSecondMass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetProductionPerSecondMassL`.
 */
int moho::cfunc_UnitGetProductionPerSecondMass(lua_State* const luaContext)
{
  return cfunc_UnitGetProductionPerSecondMassL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA810 (FUN_006CA810, func_UnitGetProductionPerSecondMass_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetProductionPerSecondMass()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetProductionPerSecondMass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetProductionPerSecondMassName,
    &moho::cfunc_UnitGetProductionPerSecondMass,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetProductionPerSecondMassHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA870 (FUN_006CA870, cfunc_UnitGetProductionPerSecondMassL)
 *
 * What it does:
 * Returns `UnitAttributes::productionPerSecondMass` for arg #1.
 */
int moho::cfunc_UnitGetProductionPerSecondMassL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetProductionPerSecondMassHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().productionPerSecondMass);
  return 1;
}

/**
 * Address: 0x006CA940 (FUN_006CA940, cfunc_UnitGetResourceConsumed)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetResourceConsumedL`.
 */
int moho::cfunc_UnitGetResourceConsumed(lua_State* const luaContext)
{
  return cfunc_UnitGetResourceConsumedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA960 (FUN_006CA960, func_UnitGetResourceConsumed_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetResourceConsumed()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetResourceConsumed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetResourceConsumedName,
    &moho::cfunc_UnitGetResourceConsumed,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetResourceConsumedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA9C0 (FUN_006CA9C0, cfunc_UnitGetResourceConsumedL)
 *
 * What it does:
 * Returns `Unit::ResourceConsumed` for arg #1.
 */
int moho::cfunc_UnitGetResourceConsumedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetResourceConsumedHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->ResourceConsumed);
  return 1;
}

/**
 * Address: 0x006CAA80 (FUN_006CAA80, cfunc_UnitSetElevation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetElevationL`.
 */
int moho::cfunc_UnitSetElevation(lua_State* const luaContext)
{
  return cfunc_UnitSetElevationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CAAA0 (FUN_006CAAA0, func_UnitSetElevation_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetElevation(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetElevation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetElevationName,
    &moho::cfunc_UnitSetElevation,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetElevationHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CAB00 (FUN_006CAB00, cfunc_UnitSetElevationL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit elevation offset attribute.
 */
int moho::cfunc_UnitSetElevationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetElevationHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject elevationArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    elevationArg.TypeError("number");
  }

  unit->GetAttributes().spawnElevationOffset = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CABF0 (FUN_006CABF0, cfunc_UnitRevertElevation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitRevertElevationL`.
 */
int moho::cfunc_UnitRevertElevation(lua_State* const luaContext)
{
  return cfunc_UnitRevertElevationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CAC10 (FUN_006CAC10, func_UnitRevertElevation_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:RevertElevation()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRevertElevation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRevertElevationName,
    &moho::cfunc_UnitRevertElevation,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRevertElevationHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CAC70 (FUN_006CAC70, cfunc_UnitRevertElevationL)
 *
 * What it does:
 * Restores `UnitAttributes::spawnElevationOffset` from blueprint physics
 * elevation data.
 */
int moho::cfunc_UnitRevertElevationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRevertElevationHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  UnitAttributes& attributes = unit->GetAttributes();

  attributes.spawnElevationOffset = attributes.blueprint->Physics.Elevation;
  return 0;
}

/**
 * Address: 0x006CAD20 (FUN_006CAD20, cfunc_UnitSetSpeedMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetSpeedMultL`.
 */
int moho::cfunc_UnitSetSpeedMult(lua_State* const luaContext)
{
  return cfunc_UnitSetSpeedMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CAD40 (FUN_006CAD40, func_UnitSetSpeedMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetSpeedMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetSpeedMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetSpeedMultName,
    &moho::cfunc_UnitSetSpeedMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetSpeedMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CADA0 (FUN_006CADA0, cfunc_UnitSetSpeedMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit speed-multiplier attribute.
 */
int moho::cfunc_UnitSetSpeedMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetSpeedMultHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject speedArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    speedArg.TypeError("number");
  }

  unit->GetAttributes().moveSpeedMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CAE90 (FUN_006CAE90, cfunc_UnitSetAccMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetAccMultL`.
 */
int moho::cfunc_UnitSetAccMult(lua_State* const luaContext)
{
  return cfunc_UnitSetAccMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CAEB0 (FUN_006CAEB0, func_UnitSetAccMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetAccMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetAccMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetAccMultName,
    &moho::cfunc_UnitSetAccMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetAccMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CAF10 (FUN_006CAF10, cfunc_UnitSetAccMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit acceleration-multiplier attribute.
 */
int moho::cfunc_UnitSetAccMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetAccMultHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject accelerationArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    accelerationArg.TypeError("number");
  }

  unit->GetAttributes().accelerationMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CB000 (FUN_006CB000, cfunc_UnitSetTurnMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetTurnMultL`.
 */
int moho::cfunc_UnitSetTurnMult(lua_State* const luaContext)
{
  return cfunc_UnitSetTurnMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB020 (FUN_006CB020, func_UnitSetTurnMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetTurnMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetTurnMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetTurnMultName,
    &moho::cfunc_UnitSetTurnMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetTurnMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB080 (FUN_006CB080, cfunc_UnitSetTurnMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit turn-multiplier attribute.
 */
int moho::cfunc_UnitSetTurnMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetTurnMultHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject turnArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    turnArg.TypeError("number");
  }

  unit->GetAttributes().turnMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CB170 (FUN_006CB170, cfunc_UnitSetBreakOffTriggerMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetBreakOffTriggerMultL`.
 */
int moho::cfunc_UnitSetBreakOffTriggerMult(lua_State* const luaContext)
{
  return cfunc_UnitSetBreakOffTriggerMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB190 (FUN_006CB190, func_UnitSetBreakOffTriggerMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetBreakOffTriggerMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBreakOffTriggerMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetBreakOffTriggerMultName,
    &moho::cfunc_UnitSetBreakOffTriggerMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBreakOffTriggerMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB1F0 (FUN_006CB1F0, cfunc_UnitSetBreakOffTriggerMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit break-off-trigger multiplier attribute.
 */
int moho::cfunc_UnitSetBreakOffTriggerMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetBreakOffTriggerMultHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject triggerArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    triggerArg.TypeError("number");
  }

  unit->GetAttributes().breakOffTriggerMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CB2E0 (FUN_006CB2E0, cfunc_UnitSetBreakOffDistanceMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetBreakOffDistanceMultL`.
 */
int moho::cfunc_UnitSetBreakOffDistanceMult(lua_State* const luaContext)
{
  return cfunc_UnitSetBreakOffDistanceMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB300 (FUN_006CB300, func_UnitSetBreakOffDistanceMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetBreakOffDistanceMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBreakOffDistanceMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetBreakOffDistanceMultName,
    &moho::cfunc_UnitSetBreakOffDistanceMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBreakOffDistanceMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB360 (FUN_006CB360, cfunc_UnitSetBreakOffDistanceMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit break-off-distance multiplier attribute.
 */
int moho::cfunc_UnitSetBreakOffDistanceMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetBreakOffDistanceMultHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject distanceArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    distanceArg.TypeError("number");
  }

  unit->GetAttributes().breakOffDistanceMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CC8E0 (FUN_006CC8E0, cfunc_UnitSetStat)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetStatL`.
 */
int moho::cfunc_UnitSetStat(lua_State* const luaContext)
{
  return cfunc_UnitSetStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC900 (FUN_006CC900, func_UnitSetStat_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetStat(name, value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetStatName,
    &moho::cfunc_UnitSetStat,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC960 (FUN_006CC960, cfunc_UnitSetStatL)
 *
 * What it does:
 * Resolves one unit stat lane and stores arg #3 payload bits into that stat.
 */
int moho::cfunc_UnitSetStatL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetStatHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject statNameArg(state, 2);
  const char* const statName = lua_tostring(rawState, 2);
  if (statName == nullptr) {
    statNameArg.TypeError("string");
  }

  StatItem* const statItem = unit->GetStat(statName);
  if (statItem == nullptr) {
    lua_pushboolean(rawState, 1);
    return 1;
  }

  const auto storePrimaryBits = [](StatItem* const item, const std::int32_t valueBits) noexcept {
#if defined(_WIN32)
    volatile long* const slot = reinterpret_cast<volatile long*>(&item->mPrimaryValueBits);
    for (;;) {
      const long observed = InterlockedCompareExchange(slot, 0L, 0L);
      const long exchanged = InterlockedCompareExchange(slot, static_cast<long>(valueBits), observed);
      if (exchanged == observed) {
        return;
      }
    }
#else
    item->mPrimaryValueBits = valueBits;
#endif
  };

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject valueArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      valueArg.TypeError("integer");
    }

    const std::int32_t value = static_cast<std::int32_t>(lua_tonumber(rawState, 3));
    storePrimaryBits(statItem, value);
    return 0;
  }

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject valueArg(state, 3);
    const float value = static_cast<float>(valueArg.ToNumber());
    std::int32_t valueBits = 0;
    std::memcpy(&valueBits, &value, sizeof(valueBits));
    storePrimaryBits(statItem, valueBits);
    return 0;
  }

  const LuaPlus::LuaStackObject valueArg(state, 3);
  const char* const value = lua_tostring(rawState, 3);
  if (value == nullptr) {
    valueArg.TypeError("string");
  }

  const std::int32_t valueBits =
    static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(value != nullptr ? value : ""));
  storePrimaryBits(statItem, valueBits);
  return 0;
}

/**
 * Address: 0x006CCB40 (FUN_006CCB40, cfunc_UnitSetWorkProgress)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetWorkProgressL`.
 */
int moho::cfunc_UnitSetWorkProgress(lua_State* const luaContext)
{
  return cfunc_UnitSetWorkProgressL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CCB60 (FUN_006CCB60, func_UnitSetWorkProgress_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetWorkProgress(progress)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetWorkProgress_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetWorkProgressName,
    &moho::cfunc_UnitSetWorkProgress,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetWorkProgressHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CCBC0 (FUN_006CCBC0, cfunc_UnitSetWorkProgressL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit work-progress runtime lane.
 */
int moho::cfunc_UnitSetWorkProgressL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetWorkProgressHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject progressArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    progressArg.TypeError("number");
  }

  unit->WorkProgress = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CCCB0 (FUN_006CCCB0, cfunc_UnitGetWorkProgress)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetWorkProgressL`.
 */
int moho::cfunc_UnitGetWorkProgress(lua_State* const luaContext)
{
  return cfunc_UnitGetWorkProgressL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CCCD0 (FUN_006CCCD0, func_UnitGetWorkProgress_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetWorkProgress()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetWorkProgress_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetWorkProgressName,
    &moho::cfunc_UnitGetWorkProgress,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetWorkProgressHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CCD30 (FUN_006CCD30, cfunc_UnitGetWorkProgressL)
 *
 * What it does:
 * Resolves one unit and returns its current work-progress scalar.
 */
int moho::cfunc_UnitGetWorkProgressL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetWorkProgressHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  lua_pushnumber(rawState, unit->WorkProgress);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C6310 (FUN_006C6310, cfunc_UnitSetProductionActiveL)
 *
 * What it does:
 * Writes `Unit::ProductionActive` from arg #2 and dispatches
 * `OnProductionActive` / `OnProductionInActive` script callbacks.
 */
int moho::cfunc_UnitSetProductionActiveL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetProductionActiveHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject activeArg(state, 2);
  const bool isActive = activeArg.GetBoolean();
  unit->ProductionActive = isActive;

  Entity* const entitySubObject = static_cast<Entity*>(unit);
  (void)entitySubObject->RunScript(isActive ? kUnitOnProductionActiveScript : kUnitOnProductionInactiveScript);
  return 1;
}

/**
 * Address: 0x006C6290 (FUN_006C6290, cfunc_UnitSetProductionActive)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetProductionActiveL`.
 */
int moho::cfunc_UnitSetProductionActive(lua_State* const luaContext)
{
  return cfunc_UnitSetProductionActiveL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C62B0 (FUN_006C62B0, func_UnitSetProductionActive_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetProductionActive(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetProductionActive_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetProductionActiveName,
    &moho::cfunc_UnitSetProductionActive,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetProductionActiveHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6470 (FUN_006C6470, cfunc_UnitSetBusyL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_Busy` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetBusyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetBusyHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject busyArg(state, 2);
  const bool shouldBeBusy = busyArg.GetBoolean();

  constexpr std::uint64_t kBusyStateMask = 0x0000000000002000ull;
  if (shouldBeBusy) {
    unit->UnitStateMask |= kBusyStateMask;
  } else {
    unit->UnitStateMask &= ~kBusyStateMask;
  }

  return 0;
}

/**
 * Address: 0x006C63F0 (FUN_006C63F0, cfunc_UnitSetBusy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetBusyL`.
 */
int moho::cfunc_UnitSetBusy(lua_State* const luaContext)
{
  return cfunc_UnitSetBusyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6410 (FUN_006C6410, func_UnitSetBusy_LuaFuncDef)
 *
 * What it does:
 * Publishes `SetBusy(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBusy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetBusyName,
    &moho::cfunc_UnitSetBusy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBusyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C65F0 (FUN_006C65F0, cfunc_UnitSetBlockCommandQueueL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_BlockCommandQueue` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetBlockCommandQueueL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetBlockCommandQueueHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject flagArg(state, 2);
  const bool shouldBlock = flagArg.GetBoolean();

  constexpr std::uint64_t kBlockCommandQueueMask = 0x0000040000000000ull;
  if (shouldBlock) {
    unit->UnitStateMask |= kBlockCommandQueueMask;
  } else {
    unit->UnitStateMask &= ~kBlockCommandQueueMask;
  }

  return 0;
}

/**
 * Address: 0x006C6570 (FUN_006C6570, cfunc_UnitSetBlockCommandQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetBlockCommandQueueL`.
 */
int moho::cfunc_UnitSetBlockCommandQueue(lua_State* const luaContext)
{
  return cfunc_UnitSetBlockCommandQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6590 (FUN_006C6590, func_UnitSetBlockCommandQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetBlockCommandQueue(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBlockCommandQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetBlockCommandQueueName,
    &moho::cfunc_UnitSetBlockCommandQueue,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBlockCommandQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6770 (FUN_006C6770, cfunc_UnitSetImmobileL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_Immobile` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetImmobileL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetImmobileHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject flagArg(state, 2);
  const bool shouldSetImmobile = flagArg.GetBoolean();

  constexpr std::uint64_t kImmobileMask = 0x0000000000000002ull;
  if (shouldSetImmobile) {
    unit->UnitStateMask |= kImmobileMask;
  } else {
    unit->UnitStateMask &= ~kImmobileMask;
  }

  return 0;
}

/**
 * Address: 0x006C66F0 (FUN_006C66F0, cfunc_UnitSetImmobile)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetImmobileL`.
 */
int moho::cfunc_UnitSetImmobile(lua_State* const luaContext)
{
  return cfunc_UnitSetImmobileL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6710 (FUN_006C6710, func_UnitSetImmobile_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetImmobile(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetImmobile_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetImmobileName,
    &moho::cfunc_UnitSetImmobile,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetImmobileHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6A50 (FUN_006C6A50, cfunc_UnitSetUnSelectableL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_UnSelectable` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetUnSelectableL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetUnSelectableHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject flagArg(state, 2);
  const bool shouldSetUnSelectable = flagArg.GetBoolean();

  constexpr std::uint64_t kUnSelectableMask = 0x0000000200000000ull;
  if (shouldSetUnSelectable) {
    unit->UnitStateMask |= kUnSelectableMask;
  } else {
    unit->UnitStateMask &= ~kUnSelectableMask;
  }

  return 0;
}

/**
 * Address: 0x006C69D0 (FUN_006C69D0, cfunc_UnitSetUnSelectable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetUnSelectableL`.
 */
int moho::cfunc_UnitSetUnSelectable(lua_State* const luaContext)
{
  return cfunc_UnitSetUnSelectableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C69F0 (FUN_006C69F0, func_UnitSetUnSelectable_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetUnSelectable(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetUnSelectable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetUnSelectableName,
    &moho::cfunc_UnitSetUnSelectable,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetUnSelectableHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6BC0 (FUN_006C6BC0, cfunc_UnitSetDoNotTargetL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_DoNotTarget` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetDoNotTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetDoNotTargetHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject flagArg(state, 2);
  const bool shouldSetDoNotTarget = flagArg.GetBoolean();

  constexpr std::uint64_t kDoNotTargetMask = 0x0000000400000000ull;
  if (shouldSetDoNotTarget) {
    unit->UnitStateMask |= kDoNotTargetMask;
  } else {
    unit->UnitStateMask &= ~kDoNotTargetMask;
  }

  return 0;
}

/**
 * Address: 0x006C6B40 (FUN_006C6B40, cfunc_UnitSetDoNotTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetDoNotTargetL`.
 */
int moho::cfunc_UnitSetDoNotTarget(lua_State* const luaContext)
{
  return cfunc_UnitSetDoNotTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6B60 (FUN_006C6B60, func_UnitSetDoNotTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetDoNotTarget(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetDoNotTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetDoNotTargetName,
    &moho::cfunc_UnitSetDoNotTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetDoNotTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6F00 (FUN_006C6F00, cfunc_UnitStopSiloBuildL)
 *
 * What it does:
 * Stops active silo build on the unit when a silo-build AI lane exists.
 */
int moho::cfunc_UnitStopSiloBuildL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitStopSiloBuildHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
    siloBuild->SiloStopBuild();
  }

  return 0;
}

/**
 * Address: 0x006C6E80 (FUN_006C6E80, cfunc_UnitStopSiloBuild)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitStopSiloBuildL`.
 */
int moho::cfunc_UnitStopSiloBuild(lua_State* const luaContext)
{
  return cfunc_UnitStopSiloBuildL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6EA0 (FUN_006C6EA0, func_UnitStopSiloBuild_LuaFuncDef)
 *
 * What it does:
 * Publishes the `StopSiloBuild(unit)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitStopSiloBuild_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitStopSiloBuildName,
    &moho::cfunc_UnitStopSiloBuild,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitStopSiloBuildHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7030 (FUN_006C7030, cfunc_UnitSetIsValidTargetL)
 *
 * What it does:
 * Writes one boolean into `Unit::IsValidTarget`.
 */
int moho::cfunc_UnitSetIsValidTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetIsValidTargetHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject validTargetArg(state, 2);
  unit->IsValidTarget = validTargetArg.GetBoolean();
  return 0;
}

/**
 * Address: 0x006C6FB0 (FUN_006C6FB0, cfunc_UnitSetIsValidTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetIsValidTargetL`.
 */
int moho::cfunc_UnitSetIsValidTarget(lua_State* const luaContext)
{
  return cfunc_UnitSetIsValidTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6FD0 (FUN_006C6FD0, func_UnitSetIsValidTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetIsValidTarget(self,bool)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetIsValidTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetIsValidTargetName,
    &moho::cfunc_UnitSetIsValidTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetIsValidTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7170 (FUN_006C7170, cfunc_UnitIsValidTargetL)
 *
 * What it does:
 * Returns the current `Unit::IsValidTarget` lane.
 */
int moho::cfunc_UnitIsValidTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsValidTargetHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushboolean(rawState, unit->IsValidTarget ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C70F0 (FUN_006C70F0, cfunc_UnitIsValidTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsValidTargetL`.
 */
int moho::cfunc_UnitIsValidTarget(lua_State* const luaContext)
{
  return cfunc_UnitIsValidTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7110 (FUN_006C7110, func_UnitIsValidTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `bool = IsValidTarget(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsValidTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsValidTargetName,
    &moho::cfunc_UnitIsValidTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsValidTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C72B0 (FUN_006C72B0, cfunc_UnitGetNumBuildOrdersL)
 *
 * What it does:
 * Counts queued build orders for one builder unit that match a category.
 */
int moho::cfunc_UnitGetNumBuildOrdersL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetNumBuildOrdersHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  const EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  int buildOrderCount = 0;
  if (unit->AiBuilder != nullptr) {
    if (CUnitCommandQueue* const commandQueue = unit->CommandQueue; commandQueue != nullptr) {
      const msvc8::vector<WeakPtr<CUnitCommand>> commands(commandQueue->mCommandVec);
      for (const WeakPtr<CUnitCommand>& commandWeakRef : commands) {
        const CUnitCommand* const command = commandWeakRef.GetObjectPtr();
        if (!command) {
          continue;
        }

        if (
          command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildFactory
          && command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildMobile
        ) {
          continue;
        }

        const REntityBlueprint* const blueprint = command->mConstDat.blueprint;
        if (blueprint == nullptr) {
          continue;
        }

        if (categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
          buildOrderCount += command->mVarDat.mCount;
        }
      }
    }
  }

  lua_pushnumber(rawState, static_cast<float>(buildOrderCount));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C7230 (FUN_006C7230, cfunc_UnitGetNumBuildOrders)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetNumBuildOrdersL`.
 */
int moho::cfunc_UnitGetNumBuildOrders(lua_State* const luaContext)
{
  return cfunc_UnitGetNumBuildOrdersL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7250 (FUN_006C7250, func_UnitGetNumBuildOrders_LuaFuncDef)
 *
 * What it does:
 * Publishes the `GetNumBuildOrders(self, category)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetNumBuildOrders_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetNumBuildOrdersName,
    &moho::cfunc_UnitGetNumBuildOrders,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetNumBuildOrdersHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C74F0 (FUN_006C74F0, cfunc_UnitCalculateWorldPositionFromRelativeL)
 *
 * What it does:
 * Rotates one relative vector by unit orientation and offsets it by the
 * unit world position.
 */
int moho::cfunc_UnitCalculateWorldPositionFromRelativeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kUnitCalculateWorldPositionFromRelativeHelpText,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject relativePosObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f relativePos = SCR_FromLuaCopy<Wm3::Vector3f>(relativePosObject);

  Wm3::Vector3f rotatedRelativePos{};
  (void)Wm3::MultiplyQuaternionVector(&rotatedRelativePos, relativePos, unit->GetTransform().orient_);

  const Wm3::Vector3f unitPosition = unit->GetPosition();
  const Wm3::Vector3f worldPosition{
    unitPosition.x + rotatedRelativePos.x,
    unitPosition.y + rotatedRelativePos.y,
    unitPosition.z + rotatedRelativePos.z,
  };

  LuaPlus::LuaObject worldPositionObject = SCR_ToLua<Wm3::Vector3f>(state, worldPosition);
  worldPositionObject.PushStack(state);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C7470 (FUN_006C7470, cfunc_UnitCalculateWorldPositionFromRelative)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitCalculateWorldPositionFromRelativeL`.
 */
int moho::cfunc_UnitCalculateWorldPositionFromRelative(lua_State* const luaContext)
{
  return cfunc_UnitCalculateWorldPositionFromRelativeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7490 (FUN_006C7490, func_UnitCalculateWorldPositionFromRelative_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CalculateWorldPositionFromRelative(self, relPos)` binder.
 */
CScrLuaInitForm* moho::func_UnitCalculateWorldPositionFromRelative_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitCalculateWorldPositionFromRelativeName,
    &moho::cfunc_UnitCalculateWorldPositionFromRelative,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitCalculateWorldPositionFromRelativeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C68E0 (FUN_006C68E0, cfunc_UnitSetStunnedL)
 *
 * What it does:
 * Sets unit stunned ticks from arg #2 seconds, scaled by 10 simulation ticks.
 */
int moho::cfunc_UnitSetStunnedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetStunnedHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject timeArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    timeArg.TypeError("number");
  }

  unit->StunnedState = static_cast<std::int32_t>(lua_tonumber(rawState, 2) * 10.0);
  return 0;
}

/**
 * Address: 0x006C6860 (FUN_006C6860, cfunc_UnitSetStunned)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetStunnedL`.
 */
int moho::cfunc_UnitSetStunned(lua_State* const luaContext)
{
  return cfunc_UnitSetStunnedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6880 (FUN_006C6880, func_UnitSetStunned_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetStunned(unit, time)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetStunned_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetStunnedName,
    &moho::cfunc_UnitSetStunned,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetStunnedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6D30 (FUN_006C6D30, cfunc_UnitSetUnitStateL)
 *
 * What it does:
 * Resolves `(unit, stateName, enabled)` and sets/clears the corresponding
 * state bit in `Unit::UnitStateMask` when lexical enum parsing succeeds.
 */
int moho::cfunc_UnitSetUnitStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetUnitStateHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject stateArg(state, 2);
  const char* const stateName = lua_tostring(rawState, 2);
  if (stateName == nullptr) {
    stateArg.TypeError("string");
  }

  EUnitState unitState = UNITSTATE_Immobile;
  gpg::RRef enumRef = MakeUnitStateRef(&unitState);
  if (enumRef.SetLexical(stateName)) {
    const LuaPlus::LuaStackObject enabledArg(state, 3);
    const bool enabled = enabledArg.GetBoolean();
    const int bit = static_cast<int>(unitState);
    if (bit >= 0 && bit < 64) {
      const std::uint64_t mask = 1ull << static_cast<std::uint32_t>(bit);
      if (enabled) {
        unit->UnitStateMask |= mask;
      } else {
        unit->UnitStateMask &= ~mask;
      }
    }
  }

  return 0;
}

/**
 * Address: 0x006C6CB0 (FUN_006C6CB0, cfunc_UnitSetUnitState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetUnitStateL`.
 */
int moho::cfunc_UnitSetUnitState(lua_State* const luaContext)
{
  return cfunc_UnitSetUnitStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6CD0 (FUN_006C6CD0, func_UnitSetUnitState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetUnitState(name, bool)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetUnitState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetUnitStateName,
    &moho::cfunc_UnitSetUnitState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetUnitStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7710 (FUN_006C7710, cfunc_UnitGetScriptBitL)
 *
 * What it does:
 * Resolves one toggle-cap lexical name and returns whether the corresponding
 * script bit is currently set.
 */
int moho::cfunc_UnitGetScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetScriptBitMethodHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject toggleCapArg(state, 2);
  const char* const toggleCapName = lua_tostring(rawState, 2);
  if (toggleCapName == nullptr) {
    toggleCapArg.TypeError("string");
  }
  (void)enumRef.SetLexical(toggleCapName);

  const int toggleCapValue = static_cast<int>(toggleCap);
  if (toggleCapValue < 1 || toggleCapValue > 0x100) {
    return 0;
  }

  const int bitIndex = ScriptBitIndexFromToggleCapValue(toggleCapValue);
  const std::uint32_t mask = 1u << static_cast<std::uint32_t>(bitIndex);
  lua_pushboolean(rawState, (unit->ScriptBitMask & mask) != 0u ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C7690 (FUN_006C7690, cfunc_UnitGetScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetScriptBitL`.
 */
int moho::cfunc_UnitGetScriptBit(lua_State* const luaContext)
{
  return cfunc_UnitGetScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C76B0 (FUN_006C76B0, func_UnitGetScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetScriptBit(toggleName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetScriptBitName,
    &moho::cfunc_UnitGetScriptBit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetScriptBitMethodHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C78F0 (FUN_006C78F0, cfunc_UnitSetScriptBitL)
 *
 * What it does:
 * Resolves `(unit, toggleCapName, enabled)` and toggles the matching script
 * bit lane through `Unit::ToggleScriptBit` when desired/current states differ.
 */
int moho::cfunc_UnitSetScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetScriptBitHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject toggleCapArg(state, 2);
  const char* const toggleCapName = lua_tostring(rawState, 2);
  if (toggleCapName == nullptr) {
    toggleCapArg.TypeError("string");
  }
  (void)enumRef.SetLexical(toggleCapName);

  const LuaPlus::LuaStackObject enabledArg(state, 3);
  const bool enabled = enabledArg.GetBoolean();

  const int toggleCapValue = static_cast<int>(toggleCap);
  if (toggleCapValue >= 1 && toggleCapValue <= 0x100) {
    const int bitIndex = ScriptBitIndexFromToggleCapValue(toggleCapValue);
    const std::uint32_t mask = 1u << static_cast<std::uint32_t>(bitIndex);
    const bool currentlySet = (unit->ScriptBitMask & mask) != 0u;
    if (currentlySet != enabled) {
      unit->ToggleScriptBit(bitIndex);
    }
  }

  return 0;
}

/**
 * Address: 0x006C7870 (FUN_006C7870, cfunc_UnitSetScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetScriptBitL`.
 */
int moho::cfunc_UnitSetScriptBit(lua_State* const luaContext)
{
  return cfunc_UnitSetScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7890 (FUN_006C7890, func_UnitSetScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetScriptBit(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetScriptBitName,
    &moho::cfunc_UnitSetScriptBit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetScriptBitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7AB0 (FUN_006C7AB0, cfunc_UnitToggleScriptBitL)
 *
 * What it does:
 * Resolves one toggle-cap lexical name and toggles the matching script bit.
 */
int moho::cfunc_UnitToggleScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitToggleScriptBitHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject toggleCapArg(state, 2);
  const char* const toggleCapName = lua_tostring(rawState, 2);
  if (toggleCapName == nullptr) {
    toggleCapArg.TypeError("string");
  }
  (void)enumRef.SetLexical(toggleCapName);

  const int toggleCapValue = static_cast<int>(toggleCap);
  if (toggleCapValue < 1 || toggleCapValue > 0x100) {
    return 0;
  }

  const int bitIndex = ScriptBitIndexFromToggleCapValue(toggleCapValue);
  unit->ToggleScriptBit(bitIndex);
  return 0;
}

/**
 * Address: 0x006C7A30 (FUN_006C7A30, cfunc_UnitToggleScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitToggleScriptBitL`.
 */
int moho::cfunc_UnitToggleScriptBit(lua_State* const luaContext)
{
  return cfunc_UnitToggleScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7A50 (FUN_006C7A50, func_UnitToggleScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:ToggleScriptBit(toggleName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitToggleScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitToggleScriptBitName,
    &moho::cfunc_UnitToggleScriptBit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitToggleScriptBitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7C50 (FUN_006C7C50, cfunc_UnitToggleFireStateL)
 *
 * What it does:
 * Rotates one unit fire-state lane through `[0, 1, 2]`.
 */
int moho::cfunc_UnitToggleFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitToggleFireStateHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const std::int32_t nextFireState = (unit->FireState + 1) % 3;
  unit->SetFireState(nextFireState);
  return 0;
}

/**
 * Address: 0x006C7BD0 (FUN_006C7BD0, cfunc_UnitToggleFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitToggleFireStateL`.
 */
int moho::cfunc_UnitToggleFireState(lua_State* const luaContext)
{
  return cfunc_UnitToggleFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7BF0 (FUN_006C7BF0, func_UnitToggleFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:ToggleFireState()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitToggleFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitToggleFireStateName,
    &moho::cfunc_UnitToggleFireState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitToggleFireStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7D90 (FUN_006C7D90, cfunc_UnitSetFireStateL)
 *
 * What it does:
 * Parses arg #2 lexical fire-state and applies it to one unit when changed.
 */
int moho::cfunc_UnitSetFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetFireStateHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject fireStateArg(state, 2);
  const char* const fireStateLexical = lua_tostring(rawState, 2);
  if (fireStateLexical == nullptr) {
    fireStateArg.TypeError("string");
    return 0;
  }

  std::int32_t parsedFireState = unit->FireState;
  if (ParseFireStateLexical(fireStateLexical, parsedFireState) && unit->FireState != parsedFireState) {
    unit->SetFireState(parsedFireState);
  }

  return 0;
}

/**
 * Address: 0x006C7D10 (FUN_006C7D10, cfunc_UnitSetFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFireStateL`.
 */
int moho::cfunc_UnitSetFireState(lua_State* const luaContext)
{
  return cfunc_UnitSetFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7D30 (FUN_006C7D30, func_UnitSetFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetFireState(stateName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kSetFireStateName,
    &moho::cfunc_UnitSetFireState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetFireStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7F20 (FUN_006C7F20, cfunc_UnitGetFireStateL)
 *
 * What it does:
 * Pushes one unit fire-state value as Lua number.
 */
int moho::cfunc_UnitGetFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetFireStateHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  lua_pushnumber(rawState, static_cast<float>(unit->FireState));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C7EA0 (FUN_006C7EA0, cfunc_UnitGetFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetFireStateL`.
 */
int moho::cfunc_UnitGetFireState(lua_State* const luaContext)
{
  return cfunc_UnitGetFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7EC0 (FUN_006C7EC0, func_UnitGetFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetFireState()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetFireStateName,
    &moho::cfunc_UnitGetFireState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetFireStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7FE0 (FUN_006C7FE0, cfunc_UnitSetAutoMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetAutoModeL`.
 */
int moho::cfunc_UnitSetAutoMode(lua_State* const luaContext)
{
  return cfunc_UnitSetAutoModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8000 (FUN_006C8000, func_UnitSetAutoMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetAutoMode(enabled)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetAutoMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetAutoModeName,
    &moho::cfunc_UnitSetAutoMode,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetAutoModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8060 (FUN_006C8060, cfunc_UnitSetAutoModeL)
 *
 * What it does:
 * Resolves `(unit, enabled)` and dispatches to `Unit::SetAutoMode`.
 */
int moho::cfunc_UnitSetAutoModeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetAutoModeHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject enabledArg(state, 2);
  unit->SetAutoMode(enabledArg.GetBoolean());
  return 0;
}

/**
 * Address: 0x006C8120 (FUN_006C8120, cfunc_UnitAddBuildRestriction)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitAddBuildRestrictionL`.
 */
int moho::cfunc_UnitAddBuildRestriction(lua_State* const luaContext)
{
  return cfunc_UnitAddBuildRestrictionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8140 (FUN_006C8140, func_UnitAddBuildRestriction_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AddBuildRestriction(categorySet)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitAddBuildRestriction_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitAddBuildRestrictionName,
    &moho::cfunc_UnitAddBuildRestriction,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAddBuildRestrictionHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C81A0 (FUN_006C81A0, cfunc_UnitAddBuildRestrictionL)
 *
 * What it does:
 * Merges category bits into one unit build-restriction set and marks sync dirty.
 */
int moho::cfunc_UnitAddBuildRestrictionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitAddBuildRestrictionHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  const EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  CategoryWordRangeView& restrictionWords = UnitBuildRestrictionCategoryWords(*unit);
  AsCategoryWordBitset(restrictionWords).AddAllFrom(&categorySet->Bits());
  unit->DirtySyncState = 1;
  return 0;
}

/**
 * Address: 0x006C8290 (FUN_006C8290, cfunc_UnitRemoveBuildRestriction)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveBuildRestrictionL`.
 */
int moho::cfunc_UnitRemoveBuildRestriction(lua_State* const luaContext)
{
  return cfunc_UnitRemoveBuildRestrictionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C82B0 (FUN_006C82B0, func_UnitRemoveBuildRestriction_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveBuildRestriction(categorySet)` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveBuildRestriction_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRemoveBuildRestrictionName,
    &moho::cfunc_UnitRemoveBuildRestriction,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveBuildRestrictionHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8310 (FUN_006C8310, cfunc_UnitRemoveBuildRestrictionL)
 *
 * What it does:
 * Clears category bits from one unit build-restriction set and marks sync dirty.
 */
int moho::cfunc_UnitRemoveBuildRestrictionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRemoveBuildRestrictionHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  const EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  CategoryWordRangeView& restrictionWords = UnitBuildRestrictionCategoryWords(*unit);
  AsCategoryWordBitset(restrictionWords).RemoveAllFrom(&categorySet->Bits());
  unit->DirtySyncState = 1;
  return 0;
}

/**
 * Address: 0x006C8400 (FUN_006C8400, cfunc_UnitRestoreBuildRestrictions)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRestoreBuildRestrictionsL`.
 */
int moho::cfunc_UnitRestoreBuildRestrictions(lua_State* const luaContext)
{
  return cfunc_UnitRestoreBuildRestrictionsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8420 (FUN_006C8420, func_UnitRestoreBuildRestrictions_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RestoreBuildRestrictions()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRestoreBuildRestrictions_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRestoreBuildRestrictionsName,
    &moho::cfunc_UnitRestoreBuildRestrictions,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRestoreBuildRestrictionsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8480 (FUN_006C8480, cfunc_UnitRestoreBuildRestrictionsL)
 *
 * What it does:
 * Clears one unit build-restriction set back to empty/default state.
 */
int moho::cfunc_UnitRestoreBuildRestrictionsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRestoreBuildRestrictionsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  CategoryWordRangeView& restrictionWords = UnitBuildRestrictionCategoryWords(*unit);
  ResetCategoryWordRange(restrictionWords);
  unit->DirtySyncState = 1;
  return 0;
}

/**
 * Address: 0x006C85E0 (FUN_006C85E0, cfunc_UnitAddCommandCapL)
 *
 * What it does:
 * Resolves one command-cap lexical arg and ORs it into unit command-cap mask.
 */
int moho::cfunc_UnitAddCommandCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitAddCommandCapHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitCommandCaps commandCap = RULEUCC_None;
  gpg::RRef enumRef = MakeRuleUnitCommandCapsRef(&commandCap);
  const LuaPlus::LuaStackObject capArg(state, 2);
  const char* const capName = lua_tostring(rawState, 2);
  if (capName == nullptr) {
    capArg.TypeError("string");
  }

  SCR_GetEnum(state, capName, enumRef);
  unit->GetAttributes().commandCapsMask |= static_cast<std::uint32_t>(commandCap);
  unit->DirtySyncState = 1;
  return 0;
}

/**
 * Address: 0x006C8560 (FUN_006C8560, cfunc_UnitAddCommandCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitAddCommandCapL`.
 */
int moho::cfunc_UnitAddCommandCap(lua_State* const luaContext)
{
  return cfunc_UnitAddCommandCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8580 (FUN_006C8580, func_UnitAddCommandCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AddCommandCap(capName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitAddCommandCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitAddCommandCapName,
    &moho::cfunc_UnitAddCommandCap,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAddCommandCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8780 (FUN_006C8780, cfunc_UnitRemoveCommandCapL)
 *
 * What it does:
 * Resolves one command-cap lexical arg and clears it from unit command-cap
 * mask.
 */
int moho::cfunc_UnitRemoveCommandCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRemoveCommandCapHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitCommandCaps commandCap = RULEUCC_None;
  gpg::RRef enumRef = MakeRuleUnitCommandCapsRef(&commandCap);
  const LuaPlus::LuaStackObject capArg(state, 2);
  const char* const capName = lua_tostring(rawState, 2);
  if (capName == nullptr) {
    capArg.TypeError("string");
  }

  SCR_GetEnum(state, capName, enumRef);
  unit->GetAttributes().commandCapsMask &= ~static_cast<std::uint32_t>(commandCap);
  unit->DirtySyncState = 1;
  return 0;
}

/**
 * Address: 0x006C8700 (FUN_006C8700, cfunc_UnitRemoveCommandCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveCommandCapL`.
 */
int moho::cfunc_UnitRemoveCommandCap(lua_State* const luaContext)
{
  return cfunc_UnitRemoveCommandCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8720 (FUN_006C8720, func_UnitRemoveCommandCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveCommandCap(capName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveCommandCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRemoveCommandCapName,
    &moho::cfunc_UnitRemoveCommandCap,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveCommandCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8920 (FUN_006C8920, cfunc_UnitRestoreCommandCapsL)
 *
 * What it does:
 * Restores runtime command capability mask from the owning unit blueprint.
 */
int moho::cfunc_UnitRestoreCommandCapsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRestoreCommandCapsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  unit->GetAttributes().commandCapsMask = static_cast<std::uint32_t>(blueprint->General.CommandCaps);
  unit->DirtySyncState = 1;
  return 0;
}

/**
 * Address: 0x006C88A0 (FUN_006C88A0, cfunc_UnitRestoreCommandCaps)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRestoreCommandCapsL`.
 */
int moho::cfunc_UnitRestoreCommandCaps(lua_State* const luaContext)
{
  return cfunc_UnitRestoreCommandCapsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C88C0 (FUN_006C88C0, func_UnitRestoreCommandCaps_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RestoreCommandCaps()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRestoreCommandCaps_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRestoreCommandCapsName,
    &moho::cfunc_UnitRestoreCommandCaps,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRestoreCommandCapsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8C00 (FUN_006C8C00, cfunc_UnitAddToggleCapL)
 *
 * What it does:
 * Resolves one toggle-cap lexical arg and ORs it into unit toggle-cap mask.
 */
int moho::cfunc_UnitAddToggleCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitAddToggleCapHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject capArg(state, 2);
  const char* const capName = lua_tostring(rawState, 2);
  if (capName == nullptr) {
    capArg.TypeError("string");
  }

  SCR_GetEnum(state, capName, enumRef);
  unit->GetAttributes().toggleCapsMask |= static_cast<std::uint32_t>(toggleCap);
  unit->DirtySyncState = 1;
  return 0;
}

/**
 * Address: 0x006C8B80 (FUN_006C8B80, cfunc_UnitAddToggleCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitAddToggleCapL`.
 */
int moho::cfunc_UnitAddToggleCap(lua_State* const luaContext)
{
  return cfunc_UnitAddToggleCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8BA0 (FUN_006C8BA0, func_UnitAddToggleCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AddToggleCap(capName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitAddToggleCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitAddToggleCapName,
    &moho::cfunc_UnitAddToggleCap,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAddToggleCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8DA0 (FUN_006C8DA0, cfunc_UnitRemoveToggleCapL)
 *
 * What it does:
 * Resolves one toggle-cap lexical arg and clears it from unit toggle-cap mask.
 */
int moho::cfunc_UnitRemoveToggleCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRemoveToggleCapHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject capArg(state, 2);
  const char* const capName = lua_tostring(rawState, 2);
  if (capName == nullptr) {
    capArg.TypeError("string");
  }

  SCR_GetEnum(state, capName, enumRef);
  unit->GetAttributes().toggleCapsMask &= ~static_cast<std::uint32_t>(toggleCap);
  unit->DirtySyncState = 1;
  return 0;
}

/**
 * Address: 0x006C8D20 (FUN_006C8D20, cfunc_UnitRemoveToggleCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveToggleCapL`.
 */
int moho::cfunc_UnitRemoveToggleCap(lua_State* const luaContext)
{
  return cfunc_UnitRemoveToggleCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8D40 (FUN_006C8D40, func_UnitRemoveToggleCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveToggleCap(capName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveToggleCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRemoveToggleCapName,
    &moho::cfunc_UnitRemoveToggleCap,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveToggleCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8F40 (FUN_006C8F40, cfunc_UnitRestoreToggleCapsL)
 *
 * What it does:
 * Restores runtime toggle capability mask from the owning unit blueprint.
 */
int moho::cfunc_UnitRestoreToggleCapsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRestoreToggleCapsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  unit->GetAttributes().toggleCapsMask = static_cast<std::uint32_t>(blueprint->General.ToggleCaps);
  unit->DirtySyncState = 1;
  return 0;
}

/**
 * Address: 0x006C8EC0 (FUN_006C8EC0, cfunc_UnitRestoreToggleCaps)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRestoreToggleCapsL`.
 */
int moho::cfunc_UnitRestoreToggleCaps(lua_State* const luaContext)
{
  return cfunc_UnitRestoreToggleCapsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8EE0 (FUN_006C8EE0, func_UnitRestoreToggleCaps_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RestoreToggleCaps()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRestoreToggleCaps_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRestoreToggleCapsName,
    &moho::cfunc_UnitRestoreToggleCaps,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRestoreToggleCapsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8A60 (FUN_006C8A60, cfunc_UnitTestCommandCapsL)
 *
 * What it does:
 * Resolves `(unit, commandCapName)` and returns whether the corresponding
 * blueprint capability bit is present.
 *
 * Note:
 * Binary lane tests `RUnitBlueprintGeneral::ToggleCaps` at +0x180.
 */
int moho::cfunc_UnitTestCommandCapsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitTestCommandCapsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitCommandCaps commandCap = RULEUCC_None;
  gpg::RRef enumRef = MakeRuleUnitCommandCapsRef(&commandCap);
  const LuaPlus::LuaStackObject commandCapArg(state, 2);
  const char* const commandCapName = lua_tostring(rawState, 2);
  if (commandCapName == nullptr) {
    commandCapArg.TypeError("string");
  }
  SCR_GetEnum(state, commandCapName, enumRef);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  const bool hasCapability =
    (static_cast<std::uint32_t>(blueprint->General.ToggleCaps) & static_cast<std::uint32_t>(commandCap)) != 0u;
  lua_pushboolean(rawState, hasCapability ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C89E0 (FUN_006C89E0, cfunc_UnitTestCommandCaps)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitTestCommandCapsL`.
 */
int moho::cfunc_UnitTestCommandCaps(lua_State* const luaContext)
{
  return cfunc_UnitTestCommandCapsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8A00 (FUN_006C8A00, func_UnitTestCommandCaps_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:TestCommandCaps(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitTestCommandCaps_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitTestCommandCapsName,
    &moho::cfunc_UnitTestCommandCaps,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTestCommandCapsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9080 (FUN_006C9080, cfunc_UnitTestToggleCapsL)
 *
 * What it does:
 * Resolves `(unit, toggleCapName)` and returns whether that toggle capability
 * bit is present in the owning blueprint.
 */
int moho::cfunc_UnitTestToggleCapsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitTestToggleCapsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject toggleCapArg(state, 2);
  const char* const toggleCapName = lua_tostring(rawState, 2);
  if (toggleCapName == nullptr) {
    toggleCapArg.TypeError("string");
  }
  SCR_GetEnum(state, toggleCapName, enumRef);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  const bool hasCapability =
    (static_cast<std::uint32_t>(blueprint->General.ToggleCaps) & static_cast<std::uint32_t>(toggleCap)) != 0u;
  lua_pushboolean(rawState, hasCapability ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C9000 (FUN_006C9000, cfunc_UnitTestToggleCaps)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitTestToggleCapsL`.
 */
int moho::cfunc_UnitTestToggleCaps(lua_State* const luaContext)
{
  return cfunc_UnitTestToggleCapsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9020 (FUN_006C9020, func_UnitTestToggleCaps_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:TestToggleCaps(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitTestToggleCaps_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitTestToggleCapsName,
    &moho::cfunc_UnitTestToggleCaps,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTestToggleCapsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9460 (FUN_006C9460, cfunc_UnitSetReclaimable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetReclaimableL`.
 */
int moho::cfunc_UnitSetReclaimable(lua_State* const luaContext)
{
  return cfunc_UnitSetReclaimableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9480 (FUN_006C9480, func_UnitSetReclaimable_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetReclaimable(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetReclaimable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetReclaimableName,
    &moho::cfunc_UnitSetReclaimable,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetReclaimableHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C94E0 (FUN_006C94E0, cfunc_UnitSetReclaimableL)
 *
 * What it does:
 * Resolves `(self, flag)` and updates `UnitAttributes::mReclaimable`.
 */
int moho::cfunc_UnitSetReclaimableL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetReclaimableHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject reclaimableArg(state, 2);
  unit->GetAttributes().mReclaimable = reclaimableArg.GetBoolean();
  return 0;
}

/**
 * Address: 0x006C95B0 (FUN_006C95B0, cfunc_UnitSetCapturable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetCapturableL`.
 */
int moho::cfunc_UnitSetCapturable(lua_State* const luaContext)
{
  return cfunc_UnitSetCapturableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C95D0 (FUN_006C95D0, func_UnitSetCapturable_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetCapturable(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetCapturable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetCapturableName,
    &moho::cfunc_UnitSetCapturable,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetCapturableHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9630 (FUN_006C9630, cfunc_UnitSetCapturableL)
 *
 * What it does:
 * Resolves `(self, flag)` and updates `UnitAttributes::mCapturable`.
 */
int moho::cfunc_UnitSetCapturableL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetCapturableHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject capturableArg(state, 2);
  unit->GetAttributes().mCapturable = capturableArg.GetBoolean();
  return 0;
}

/**
 * Address: 0x006C9700 (FUN_006C9700, cfunc_UnitIsCapturable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsCapturableL`.
 */
int moho::cfunc_UnitIsCapturable(lua_State* const luaContext)
{
  return cfunc_UnitIsCapturableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9720 (FUN_006C9720, func_UnitIsCapturable_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:IsCapturable()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsCapturable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsCapturableName,
    &moho::cfunc_UnitIsCapturable,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsCapturableHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9780 (FUN_006C9780, cfunc_UnitIsCapturableL)
 *
 * What it does:
 * Resolves one unit and returns `UnitAttributes::mCapturable`.
 */
int moho::cfunc_UnitIsCapturableL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsCapturableHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushboolean(rawState, unit->GetAttributes().mCapturable ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C9840 (FUN_006C9840, cfunc_UnitSetOverchargePaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetOverchargePausedL`.
 */
int moho::cfunc_UnitSetOverchargePaused(lua_State* const luaContext)
{
  return cfunc_UnitSetOverchargePausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9860 (FUN_006C9860, func_UnitSetOverchargePaused_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetOverchargePaused(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetOverchargePaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetOverchargePausedName,
    &moho::cfunc_UnitSetOverchargePaused,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetOverchargePausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C98C0 (FUN_006C98C0, cfunc_UnitSetOverchargePausedL)
 *
 * What it does:
 * Resolves `(self, flag)` and updates `Unit::OverchargePaused`.
 */
int moho::cfunc_UnitSetOverchargePausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetOverchargePausedHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject pausedArg(state, 2);
  unit->OverchargePaused = pausedArg.GetBoolean();
  return 0;
}

/**
 * Address: 0x006C9980 (FUN_006C9980, cfunc_UnitIsOverchargePaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitIsOverchargePausedL`.
 */
int moho::cfunc_UnitIsOverchargePaused(lua_State* const luaContext)
{
  return cfunc_UnitIsOverchargePausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C99A0 (FUN_006C99A0, func_UnitIsOverchargePaused_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:IsOverchargePaused()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsOverchargePaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsOverchargePausedName,
    &moho::cfunc_UnitIsOverchargePaused,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsOverchargePausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9A00 (FUN_006C9A00, cfunc_UnitIsOverchargePausedL)
 *
 * What it does:
 * Resolves one unit and returns `Unit::OverchargePaused`.
 */
int moho::cfunc_UnitIsOverchargePausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsOverchargePausedHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushboolean(rawState, unit->OverchargePaused ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CB450 (FUN_006CB450, cfunc_UnitRevertCollisionShape)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRevertCollisionShapeL`.
 */
int moho::cfunc_UnitRevertCollisionShape(lua_State* const luaContext)
{
  return cfunc_UnitRevertCollisionShapeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB470 (FUN_006CB470, func_UnitRevertCollisionShape_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:RevertCollisionShape()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRevertCollisionShape_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRevertCollisionShapeName,
    &moho::cfunc_UnitRevertCollisionShape,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRevertCollisionShapeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB4D0 (FUN_006CB4D0, cfunc_UnitRevertCollisionShapeL)
 *
 * What it does:
 * Resolves one unit and restores entity collision shape from blueprint lanes.
 */
int moho::cfunc_UnitRevertCollisionShapeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRevertCollisionShapeHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  unit->Entity::RevertCollisionShape();
  return 0;
}

/**
 * Address: 0x006D03E0 (FUN_006D03E0, cfunc_UnitCanBuild)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitCanBuildL`.
 */
int moho::cfunc_UnitCanBuild(lua_State* const luaContext)
{
  return cfunc_UnitCanBuildL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0400 (FUN_006D0400, func_UnitCanBuild_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:CanBuild(blueprint)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitCanBuild_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitCanBuildName,
    &moho::cfunc_UnitCanBuild,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitCanBuildHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0460 (FUN_006D0460, cfunc_UnitCanBuildL)
 *
 * What it does:
 * Resolves one unit and one blueprint id string, then returns whether the
 * unit can build that blueprint according to `Unit::CanBuild`.
 */
int moho::cfunc_UnitCanBuildL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitCanBuildHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject blueprintArg(state, 2);
  const char* blueprintText = lua_tostring(rawState, 2);
  if (!blueprintText) {
    blueprintArg.TypeError("string");
    blueprintText = "";
  }

  RResId blueprintId{};
  gpg::STR_InitFilename(&blueprintId.name, blueprintText);

  RUnitBlueprint* blueprint = nullptr;
  if (unit && unit->SimulationRef && unit->SimulationRef->mRules) {
    blueprint = unit->SimulationRef->mRules->GetUnitBlueprint(blueprintId);
  }

  if (!blueprint) {
    LuaPlus::LuaState::Error(state, kUnitCanBuildUnknownBlueprintError, blueprintText);
  }

  const bool canBuild = unit->CanBuild(blueprint);
  lua_pushboolean(rawState, canBuild ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D05D0 (FUN_006D05D0, cfunc_UnitGetRallyPoint)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetRallyPointL`.
 */
int moho::cfunc_UnitGetRallyPoint(lua_State* const luaContext)
{
  return cfunc_UnitGetRallyPointL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D05F0 (FUN_006D05F0, func_UnitGetRallyPoint_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetRallyPoint()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetRallyPoint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetRallyPointName,
    &moho::cfunc_UnitGetRallyPoint,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetRallyPointHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0650 (FUN_006D0650, cfunc_UnitGetRallyPointL)
 *
 * What it does:
 * Returns the current factory rally-point target position when a builder
 * command is available; otherwise pushes `nil`.
 */
int moho::cfunc_UnitGetRallyPointL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetRallyPointHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (IAiBuilder* const builder = unit->AiBuilder; builder != nullptr) {
    if (CUnitCommand* const command = builder->BuilderGetFactoryCommand(0); command != nullptr) {
      const Wm3::Vec3f rallyPoint = command->mTarget.GetTargetPosGun(false);
      LuaPlus::LuaObject rallyPointObject = SCR_ToLua<Wm3::Vector3<float>>(state, rallyPoint);
      rallyPointObject.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D0770 (FUN_006D0770, cfunc_UnitGetFuelUseTime)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetFuelUseTimeL`.
 */
int moho::cfunc_UnitGetFuelUseTime(lua_State* const luaContext)
{
  return cfunc_UnitGetFuelUseTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0790 (FUN_006D0790, func_UnitGetFuelUseTime_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetFuelUseTime()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetFuelUseTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetFuelUseTimeName,
    &moho::cfunc_UnitGetFuelUseTime,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetFuelUseTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D07F0 (FUN_006D07F0, cfunc_UnitGetFuelUseTimeL)
 *
 * What it does:
 * Returns the unit motion fuel-use-time lane.
 */
int moho::cfunc_UnitGetFuelUseTimeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetFuelUseTimeHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (unit->UnitMotion == nullptr) {
    LuaPlus::LuaState::Error(state, "Unit has not motion object");
  }

  lua_pushnumber(rawState, unit->UnitMotion->mFuelUseTime);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D0A50 (FUN_006D0A50, cfunc_UnitGetFuelRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetFuelRatioL`.
 */
int moho::cfunc_UnitGetFuelRatio(lua_State* const luaContext)
{
  return cfunc_UnitGetFuelRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0A70 (FUN_006D0A70, func_UnitGetFuelRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetFuelRatio()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetFuelRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetFuelRatioName,
    &moho::cfunc_UnitGetFuelRatio,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetFuelRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0AD0 (FUN_006D0AD0, cfunc_UnitGetFuelRatioL)
 *
 * What it does:
 * Returns the unit runtime fuel-ratio lane.
 */
int moho::cfunc_UnitGetFuelRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetFuelRatioHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (unit->UnitMotion == nullptr) {
    LuaPlus::LuaState::Error(state, "Unit has not motion object");
  }

  lua_pushnumber(rawState, unit->FuelRatio);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D08D0 (FUN_006D08D0, cfunc_UnitSetFuelUseTime)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFuelUseTimeL`.
 */
int moho::cfunc_UnitSetFuelUseTime(lua_State* const luaContext)
{
  return cfunc_UnitSetFuelUseTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D08F0 (FUN_006D08F0, func_UnitSetFuelUseTime_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetFuelUseTime(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetFuelUseTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetFuelUseTimeName,
    &moho::cfunc_UnitSetFuelUseTime,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetFuelUseTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0950 (FUN_006D0950, cfunc_UnitSetFuelUseTimeL)
 *
 * What it does:
 * Validates `(self, fuelUseTime)` and writes the unit motion fuel-use-time
 * lane; throws a Lua error when the unit has no motion object.
 */
int moho::cfunc_UnitSetFuelUseTimeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetFuelUseTimeHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (!unit->UnitMotion) {
    LuaPlus::LuaState::Error(state, "Unit has not motion object");
  }

  const LuaPlus::LuaStackObject fuelUseTimeArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    fuelUseTimeArg.TypeError("number");
  }

  unit->UnitMotion->mFuelUseTime = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006D0BB0 (FUN_006D0BB0, cfunc_UnitSetFuelRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFuelRatioL`.
 */
int moho::cfunc_UnitSetFuelRatio(lua_State* const luaContext)
{
  return cfunc_UnitSetFuelRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0BD0 (FUN_006D0BD0, func_UnitSetFuelRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetFuelRatio(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetFuelRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetFuelRatioName,
    &moho::cfunc_UnitSetFuelRatio,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetFuelRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0C30 (FUN_006D0C30, cfunc_UnitSetFuelRatioL)
 *
 * What it does:
 * Validates `(self, fuelRatio)` and writes the unit fuel-ratio runtime lane;
 * throws a Lua error when the unit has no motion object.
 */
int moho::cfunc_UnitSetFuelRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetFuelRatioHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (!unit->UnitMotion) {
    LuaPlus::LuaState::Error(state, "Unit has not motion object");
  }

  const LuaPlus::LuaStackObject fuelRatioArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    fuelRatioArg.TypeError("number");
  }

  unit->FuelRatio = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006D0EA0 (FUN_006D0EA0, cfunc_UnitGetShieldRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetShieldRatioL`.
 */
int moho::cfunc_UnitGetShieldRatio(lua_State* const luaContext)
{
  return cfunc_UnitGetShieldRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0EC0 (FUN_006D0EC0, func_UnitGetShieldRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetShieldRatio()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetShieldRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetShieldRatioName,
    &moho::cfunc_UnitGetShieldRatio,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetShieldRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0F20 (FUN_006D0F20, cfunc_UnitGetShieldRatioL)
 *
 * What it does:
 * Returns the unit runtime shield-ratio lane.
 */
int moho::cfunc_UnitGetShieldRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetShieldRatioHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->ShieldRatio);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D0FE0 (FUN_006D0FE0, cfunc_UnitGetBlip)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetBlipL`.
 */
int moho::cfunc_UnitGetBlip(lua_State* const luaContext)
{
  return cfunc_UnitGetBlipL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1000 (FUN_006D1000, func_UnitGetBlip_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetBlip(armyIndex)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetBlip_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetBlipName,
    &moho::cfunc_UnitGetBlip,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetBlipHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D1060 (FUN_006D1060, cfunc_UnitGetBlipL)
 *
 * What it does:
 * Resolves one recon blip object for `(unit, army)` and pushes it, or `nil`
 * when no blip is currently tracked.
 */
int moho::cfunc_UnitGetBlipL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetBlipHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CAiReconDBImpl* const reconDatabase = army->GetReconDB();
  ReconBlip* const blip = reconDatabase->ReconGetBlip(unit);
  if (blip != nullptr) {
    blip->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x006D1170 (FUN_006D1170, cfunc_UnitTransportHasSpaceFor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitTransportHasSpaceForL`.
 */
int moho::cfunc_UnitTransportHasSpaceFor(lua_State* const luaContext)
{
  return cfunc_UnitTransportHasSpaceForL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1190 (FUN_006D1190, func_UnitTransportHasSpaceFor_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:TransportHasSpaceFor(target)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitTransportHasSpaceFor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitTransportHasSpaceForName,
    &moho::cfunc_UnitTransportHasSpaceFor,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTransportHasSpaceForHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D11F0 (FUN_006D11F0, cfunc_UnitTransportHasSpaceForL)
 *
 * What it does:
 * Returns whether one transport unit can fit one target unit blueprint in
 * storage.
 */
int moho::cfunc_UnitTransportHasSpaceForL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitTransportHasSpaceForHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject transportUnitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const transportUnit = SCR_FromLua_Unit(transportUnitObject);
  const LuaPlus::LuaObject targetUnitObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const targetUnit = SCR_FromLua_Unit(targetUnitObject);

  bool hasSpace = false;
  if (transportUnit != nullptr) {
    if (IAiTransport* const transport = transportUnit->AiTransport; transport != nullptr) {
      if (targetUnit != nullptr) {
        hasSpace = transport->TransportHasSpaceFor(targetUnit->GetBlueprint());
      }
    }
  }

  lua_pushboolean(rawState, hasSpace ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D1320 (FUN_006D1320, cfunc_UnitTransportHasAvailableStorage)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitTransportHasAvailableStorageL`.
 */
int moho::cfunc_UnitTransportHasAvailableStorage(lua_State* const luaContext)
{
  return cfunc_UnitTransportHasAvailableStorageL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1340 (FUN_006D1340, func_UnitTransportHasAvailableStorage_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:TransportHasAvailableStorage()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitTransportHasAvailableStorage_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitTransportHasAvailableStorageName,
    &moho::cfunc_UnitTransportHasAvailableStorage,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTransportHasAvailableStorageHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D13A0 (FUN_006D13A0, cfunc_UnitTransportHasAvailableStorageL)
 *
 * What it does:
 * Returns whether a transport unit currently has free storage slots.
 */
int moho::cfunc_UnitTransportHasAvailableStorageL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitTransportHasAvailableStorageHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  bool hasAvailableStorage = false;
  if (unit != nullptr) {
    if (IAiTransport* const transport = unit->AiTransport; transport != nullptr) {
      hasAvailableStorage = transport->TransportHasAvailableStorage();
    }
  }

  lua_pushboolean(rawState, hasAvailableStorage ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005E8640 (FUN_005E8640, cfunc_UnitTransportDetachAllUnits)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitTransportDetachAllUnitsL`.
 */
int moho::cfunc_UnitTransportDetachAllUnits(lua_State* const luaContext)
{
  return cfunc_UnitTransportDetachAllUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005E8660 (FUN_005E8660, func_UnitTransportDetachAllUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:TransportDetachAllUnits(destroySomeUnits)` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitTransportDetachAllUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitTransportDetachAllUnitsName,
    &moho::cfunc_UnitTransportDetachAllUnits,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTransportDetachAllUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x005E86C0 (FUN_005E86C0, cfunc_UnitTransportDetachAllUnitsL)
 *
 * What it does:
 * Validates `(self, destroySomeUnits)` and detaches all carried units from one
 * transport, throwing a Lua error when invoked on non-transport units.
 */
int moho::cfunc_UnitTransportDetachAllUnitsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitTransportDetachAllUnitsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject destroySomeUnitsArg(state, 2);
  const bool destroySomeUnits = destroySomeUnitsArg.GetBoolean();

  if (IAiTransport* const transport = unit->AiTransport; transport != nullptr) {
    transport->TransportDetachAllUnits(destroySomeUnits);
  } else {
    LuaPlus::LuaState::Error(state, kUnitTransportDetachAllUnitsTransportError);
  }

  return 0;
}

/**
 * Address: 0x006D1470 (FUN_006D1470, cfunc_UnitShowBone)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitShowBoneL`.
 */
int moho::cfunc_UnitShowBone(lua_State* const luaContext)
{
  return cfunc_UnitShowBoneL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1490 (FUN_006D1490, func_UnitShowBone_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:ShowBone(self,bone,affectChildren)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitShowBone_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitShowBoneName,
    &moho::cfunc_UnitShowBone,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitShowBoneHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D14F0 (FUN_006D14F0, cfunc_UnitShowBoneL)
 *
 * What it does:
 * Resolves a target bone and marks it visible; when `affectChildren` is true,
 * applies visibility recursively to descendant bones in the active pose lane.
 */
int moho::cfunc_UnitShowBoneL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitShowBoneHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  LuaPlus::LuaStackObject boneArg(state, 2);
  const int boneIndex = ENTSCR_ResolveBoneIndex(unit, boneArg, false);

  LuaPlus::LuaStackObject affectChildrenArg(state, 3);
  const bool affectChildren = affectChildrenArg.GetBoolean();

  if (unit != nullptr && boneIndex >= 0) {
    if (CAniPoseBone* const poseBone = ResolveUnitPoseBone(*unit, boneIndex); poseBone != nullptr) {
      if (affectChildren) {
        (void)poseBone->SetVisibleRecur(true);
      } else {
        poseBone->mVisible = 1u;
      }
    }
  }

  return 0;
}

/**
 * Address: 0x006D1610 (FUN_006D1610, cfunc_UnitHideBone)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitHideBoneL`.
 */
int moho::cfunc_UnitHideBone(lua_State* const luaContext)
{
  return cfunc_UnitHideBoneL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1630 (FUN_006D1630, func_UnitHideBone_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:HideBone(self,bone,affectChildren)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitHideBone_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitHideBoneName,
    &moho::cfunc_UnitHideBone,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitHideBoneHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D1690 (FUN_006D1690, cfunc_UnitHideBoneL)
 *
 * What it does:
 * Resolves a target bone and marks it hidden; when `affectChildren` is true,
 * applies visibility recursively to descendant bones in the active pose lane.
 */
int moho::cfunc_UnitHideBoneL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitHideBoneHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  LuaPlus::LuaStackObject boneArg(state, 2);
  const int boneIndex = ENTSCR_ResolveBoneIndex(unit, boneArg, false);

  LuaPlus::LuaStackObject affectChildrenArg(state, 3);
  const bool affectChildren = affectChildrenArg.GetBoolean();

  if (unit != nullptr && boneIndex >= 0) {
    if (CAniPoseBone* const poseBone = ResolveUnitPoseBone(*unit, boneIndex); poseBone != nullptr) {
      if (affectChildren) {
        (void)poseBone->SetVisibleRecur(false);
      } else {
        poseBone->mVisible = 0u;
      }
    }
  }

  return 0;
}

/**
 * Address: 0x006CB580 (FUN_006CB580, cfunc_UnitRecoilImpulse)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitRecoilImpulseL`.
 */
int moho::cfunc_UnitRecoilImpulse(lua_State* const luaContext)
{
  return cfunc_UnitRecoilImpulseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB5A0 (FUN_006CB5A0, func_UnitRecoilImpulse_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RecoilImpulse(x, y, z)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRecoilImpulse_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitRecoilImpulseName,
    &moho::cfunc_UnitRecoilImpulse,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRecoilImpulseHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB600 (FUN_006CB600, cfunc_UnitRecoilImpulseL)
 *
 * What it does:
 * Applies one recoil impulse vector `(x,y,z)` to the target unit motion lane.
 */
int moho::cfunc_UnitRecoilImpulseL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitRecoilImpulseHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject xArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    xArg.TypeError("number");
  }
  const float impulseX = static_cast<float>(lua_tonumber(rawState, 2));

  const LuaPlus::LuaStackObject yArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    yArg.TypeError("number");
  }
  const float impulseY = static_cast<float>(lua_tonumber(rawState, 3));

  const LuaPlus::LuaStackObject zArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    zArg.TypeError("number");
  }
  const float impulseZ = static_cast<float>(lua_tonumber(rawState, 4));

  const Wm3::Vector3f impulse{impulseX, impulseY, impulseZ};
  if (CUnitMotion* const motion = unit->UnitMotion; motion != nullptr) {
    motion->AddRecoilImpulse(impulse);
  }

  return 0;
}

/**
 * Address: 0x006CB790 (FUN_006CB790, cfunc_UnitGetCurrentLayer)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetCurrentLayerL`.
 */
int moho::cfunc_UnitGetCurrentLayer(lua_State* const luaContext)
{
  return cfunc_UnitGetCurrentLayerL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB7B0 (FUN_006CB7B0, func_UnitGetCurrentLayer_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetCurrentLayer()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCurrentLayer_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetCurrentLayerName,
    &moho::cfunc_UnitGetCurrentLayer,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCurrentLayerHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB810 (FUN_006CB810, cfunc_UnitGetCurrentLayerL)
 *
 * What it does:
 * Returns this unit's current layer string token.
 */
int moho::cfunc_UnitGetCurrentLayerL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetCurrentLayerHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const ELayer layer = unit->mCurrentLayer;
  const char* const layerName =
    (static_cast<std::uint32_t>(layer) <= static_cast<std::uint32_t>(LAYER_Orbit)) ? Entity::LayerToString(layer) : "";
  lua_pushstring(rawState, layerName);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CB8E0 (FUN_006CB8E0, cfunc_UnitCanPathTo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitCanPathToL`.
 */
int moho::cfunc_UnitCanPathTo(lua_State* const luaContext)
{
  return cfunc_UnitCanPathToL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB900 (FUN_006CB900, func_UnitCanPathTo_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:CanPathTo(goal)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitCanPathTo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitCanPathToName,
    &moho::cfunc_UnitCanPathTo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitCanPathToHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB960 (FUN_006CB960, cfunc_UnitCanPathToL)
 *
 * What it does:
 * Resolves one unit and one destination argument (unit or position), then
 * returns `(canPath, targetPos)` for navigator pathing to that footprint.
 */
int moho::cfunc_UnitCanPathToL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitCanPathToHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject destinationObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const destinationUnit = GetUnitOptional(destinationObject);

  Wm3::Vector3f destinationPosition{};
  if (destinationUnit != nullptr) {
    destinationPosition = destinationUnit->GetPosition();
  } else {
    destinationPosition = SCR_FromLuaCopy<Wm3::Vector3f>(destinationObject);
  }

  SFootprint footprint = unit->GetFootprint();
  footprint.mFlags = static_cast<EFootprintFlags>(
    static_cast<std::uint8_t>(footprint.mFlags) | static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_IgnoreStructures)
  );

  const SCoordsVec2 worldPosition2D{destinationPosition.x, destinationPosition.z};
  if (footprint.FitsAt(worldPosition2D, *unit->SimulationRef->mOGrid) == static_cast<EOccupancyCaps>(0)) {
    lua_pushboolean(rawState, 0);
    (void)lua_gettop(rawState);

    const Wm3::Vector3f unitPosition = unit->GetPosition();
    LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3f>(state, unitPosition);
    positionObject.PushStack(state);
    return 2;
  }

  const float footprintWidthHalf = static_cast<float>(footprint.mSizeX) * 0.5f;
  const float footprintDepthHalf = static_cast<float>(footprint.mSizeZ) * 0.5f;
  const std::int16_t footprintMinX = static_cast<std::int16_t>(std::lrint(destinationPosition.x - footprintWidthHalf));
  const std::int16_t footprintMinZ = static_cast<std::int16_t>(std::lrint(destinationPosition.z - footprintDepthHalf));

  SAiNavigatorGoal goal{};
  goal.minX = footprintMinX;
  goal.minZ = footprintMinZ;
  goal.maxX = static_cast<std::int32_t>(footprintMinX) + static_cast<std::int32_t>(footprint.mSizeX);
  goal.maxZ = static_cast<std::int32_t>(footprintMinZ) + static_cast<std::int32_t>(footprint.mSizeZ);

  Wm3::Vector3f targetPosition = InvalidNavigatorTargetLane();
  const bool canPath = InvokeNavigatorCanPathToRect(unit->AiNavigator, goal, &targetPosition);
  lua_pushboolean(rawState, canPath ? 1 : 0);
  (void)lua_gettop(rawState);

  LuaPlus::LuaObject targetPositionObject = SCR_ToLua<Wm3::Vector3f>(state, targetPosition);
  targetPositionObject.PushStack(state);
  return 2;
}

/**
 * Address: 0x006CBD70 (FUN_006CBD70, cfunc_UnitCanPathToRectL)
 *
 * What it does:
 * Resolves one unit plus two world-space rectangle corners, queries navigator
 * pathability to that rectangle, then returns `(canPath, targetPos)` to Lua.
 */
int moho::cfunc_UnitCanPathToRectL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitCanPathToRectHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject minCornerObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f minCorner = SCR_FromLuaCopy<Wm3::Vector3f>(minCornerObject);

  const LuaPlus::LuaObject maxCornerObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vector3f maxCorner = SCR_FromLuaCopy<Wm3::Vector3f>(maxCornerObject);

  SAiNavigatorGoal goal{};
  goal.minX = RoundGridCoordDown(minCorner.x);
  goal.minZ = RoundGridCoordDown(minCorner.z);
  goal.maxX = RoundGridCoordUp(maxCorner.x);
  goal.maxZ = RoundGridCoordUp(maxCorner.z);

  Wm3::Vector3f targetPos = InvalidNavigatorTargetLane();
  const bool canPath = InvokeNavigatorCanPathToRect(unit->AiNavigator, goal, &targetPos);

  lua_pushboolean(rawState, canPath ? 1 : 0);
  (void)lua_gettop(rawState);

  LuaPlus::LuaObject targetPosObject = SCR_ToLua<Wm3::Vector3f>(state, targetPos);
  targetPosObject.PushStack(state);
  return 2;
}

/**
 * Address: 0x006CBCF0 (FUN_006CBCF0, cfunc_UnitCanPathToRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitCanPathToRectL`.
 */
int moho::cfunc_UnitCanPathToRect(lua_State* const luaContext)
{
  return cfunc_UnitCanPathToRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CBD10 (FUN_006CBD10, func_UnitCanPathToRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:CanPathToRect(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitCanPathToRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitCanPathToRectName,
    &moho::cfunc_UnitCanPathToRect,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitCanPathToRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC040 (FUN_006CC040, cfunc_UnitIsMobile)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsMobileL`.
 */
int moho::cfunc_UnitIsMobile(lua_State* const luaContext)
{
  return cfunc_UnitIsMobileL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC060 (FUN_006CC060, func_UnitIsMobile_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:IsMobile()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsMobile_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsMobileName,
    &moho::cfunc_UnitIsMobile,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsMobileHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC0C0 (FUN_006CC0C0, cfunc_UnitIsMobileL)
 *
 * What it does:
 * Resolves one unit and returns `Unit::IsMobile()`.
 */
int moho::cfunc_UnitIsMobileL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsMobileHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushboolean(rawState, unit->IsMobile() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CC180 (FUN_006CC180, cfunc_UnitIsMoving)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsMovingL`.
 */
int moho::cfunc_UnitIsMoving(lua_State* const luaContext)
{
  return cfunc_UnitIsMovingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC1A0 (FUN_006CC1A0, func_UnitIsMoving_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:IsMoving()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsMoving_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitIsMovingName,
    &moho::cfunc_UnitIsMoving,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsMovingHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC200 (FUN_006CC200, cfunc_UnitIsMovingL)
 *
 * What it does:
 * Resolves one unit and returns whether current and previous entity position
 * lanes differ.
 */
int moho::cfunc_UnitIsMovingL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitIsMovingHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const bool isMoving = Wm3::Vector3f::Compare(&unit->Position, &unit->PrevPosition) != 0;
  lua_pushboolean(rawState, isMoving ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CC2D0 (FUN_006CC2D0, cfunc_UnitGetNavigator)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetNavigatorL`.
 */
int moho::cfunc_UnitGetNavigator(lua_State* const luaContext)
{
  return cfunc_UnitGetNavigatorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC2F0 (FUN_006CC2F0, func_UnitGetNavigator_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetNavigator()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetNavigator_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetNavigatorName,
    &moho::cfunc_UnitGetNavigator,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetNavigatorHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC350 (FUN_006CC350, cfunc_UnitGetNavigatorL)
 *
 * What it does:
 * Resolves one unit and pushes its navigator object or `nil`.
 */
int moho::cfunc_UnitGetNavigatorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetNavigatorHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
    navigator->PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x006CC420 (FUN_006CC420, cfunc_UnitGetVelocity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetVelocityL`.
 */
int moho::cfunc_UnitGetVelocity(lua_State* const luaContext)
{
  return cfunc_UnitGetVelocityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC440 (FUN_006CC440, func_UnitGetVelocity_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetVelocity() -> x,y,z` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetVelocity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetVelocityName,
    &moho::cfunc_UnitGetVelocity,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetVelocityHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC4A0 (FUN_006CC4A0, cfunc_UnitGetVelocityL)
 *
 * What it does:
 * Resolves one unit and returns velocity components `(x, y, z)` to Lua.
 */
int moho::cfunc_UnitGetVelocityL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGetVelocityHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  const Wm3::Vec3f velocity = unit->Entity::GetVelocity();

  lua_pushnumber(rawState, velocity.x);
  (void)lua_gettop(rawState);
  lua_pushnumber(rawState, velocity.y);
  (void)lua_gettop(rawState);
  lua_pushnumber(rawState, velocity.z);
  (void)lua_gettop(rawState);
  return 3;
}

/**
 * Address: 0x006CC5A0 (FUN_006CC5A0, cfunc_UnitGetStat)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetStatL`.
 */
int moho::cfunc_UnitGetStat(lua_State* const luaContext)
{
  return cfunc_UnitGetStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC5C0 (FUN_006CC5C0, func_UnitGetStat_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetStat(name[, defaultValue])` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitGetStatName,
    &moho::cfunc_UnitGetStat,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC620 (FUN_006CC620, cfunc_UnitGetStatL)
 *
 * What it does:
 * Resolves one unit stat path and pushes the resolved stat-item Lua table (or
 * `nil`) with optional default-type dispatch.
 */
int moho::cfunc_UnitGetStatL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsRangeWarning, kUnitGetStatHelpText, 2, 3, argumentCount);
  }

  lua_settop(rawState, 3);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  StatItem* statItem = nullptr;
  if (lua_type(rawState, 3) == LUA_TNIL) {
    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = lua_tostring(rawState, 2);
    if (statName == nullptr) {
      statNameArg.TypeError("string");
    }
    statItem = unit->GetStat(statName);
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      defaultArg.TypeError("integer");
    }
    const int defaultValue = defaultArg.GetInteger();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = lua_tostring(rawState, 2);
    if (statName != nullptr && statName[0] == 'h' && statName[1] == '1') {
      ApplyUnitGetStatH1BlueprintOverride(*unit, defaultValue);
    }

    if (statName == nullptr) {
      statNameArg.TypeError("string");
    }

    statItem = unit->GetStat(statName, defaultValue);
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    const float defaultValue = defaultArg.GetNumber();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = statNameArg.GetString();
    statItem = unit->GetStat(statName, defaultValue);
  } else {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    const char* const defaultString = defaultArg.GetString();
    const std::string defaultValue = defaultString ? std::string(defaultString) : std::string();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = statNameArg.GetString();
    statItem = unit->GetStat(statName, defaultValue);
  }

  if (statItem != nullptr) {
    LuaPlus::LuaObject statTable;
    STAT_GetLuaTable(state, statItem, statTable);
    statTable.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x006CDB00 (FUN_006CDB00, cfunc_UnitSetCustomName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetCustomNameL`.
 */
int moho::cfunc_UnitSetCustomName(lua_State* const luaContext)
{
  return cfunc_UnitSetCustomNameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CDB20 (FUN_006CDB20, func_UnitSetCustomName_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetCustomName(name)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetCustomName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetCustomNameName,
    &moho::cfunc_UnitSetCustomName,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetCustomNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CDB80 (FUN_006CDB80, cfunc_UnitSetCustomNameL)
 *
 * What it does:
 * Resolves `(self, name)` and dispatches `Unit::SetCustomName`.
 */
int moho::cfunc_UnitSetCustomNameL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetCustomNameHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject nameArg(state, 2);
  const char* customName = lua_tostring(rawState, 2);
  if (customName == nullptr) {
    nameArg.TypeError("string");
    customName = "";
  }

  unit->SetCustomName(std::string(customName));
  return 0;
}

/**
 * Address: 0x006D0D30 (FUN_006D0D30, cfunc_UnitSetShieldRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetShieldRatioL`.
 */
int moho::cfunc_UnitSetShieldRatio(lua_State* const luaContext)
{
  return cfunc_UnitSetShieldRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0D50 (FUN_006D0D50, func_UnitSetShieldRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetShieldRatio(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetShieldRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitSetShieldRatioName,
    &moho::cfunc_UnitSetShieldRatio,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetShieldRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0DB0 (FUN_006D0DB0, cfunc_UnitSetShieldRatioL)
 *
 * What it does:
 * Resolves `(self, value)` and writes `Unit::ShieldRatio`.
 */
int moho::cfunc_UnitSetShieldRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitSetShieldRatioHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject ratioArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    ratioArg.TypeError("number");
  }

  unit->ShieldRatio = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

void SBeatResourceAccumulators::Clear() noexcept
{
  maintenanceEnergy = 0.0f;
  maintenanceMass = 0.0f;
  resourcesSpentEnergy = 0.0f;
  resourcesSpentMass = 0.0f;
}

bool Unit::NeedsKillCleanup() const noexcept
{
  return mNeedsKillCleanup;
}

void Unit::ClearBeatResourceAccumulators() noexcept
{
  mBeatResourceAccumulators.Clear();
}

CIntel* Unit::GetIntelManager() noexcept
{
  return mIntelManager;
}

CIntel const* Unit::GetIntelManager() const noexcept
{
  return mIntelManager;
}

namespace
{
  template <class T, std::size_t N>
  void CopyFastVectorN(gpg::fastvector_n<T, N>& destination, const gpg::fastvector_n<T, N>& source)
  {
    auto& destinationView = gpg::AsFastVectorRuntimeView<T>(&destination);
    const auto& sourceView = gpg::AsFastVectorRuntimeView<T>(&source);
    gpg::FastVectorRuntimeCopyAssign(destinationView, sourceView);
  }
} // namespace

/**
 * Address: 0x005BD7A0 (FUN_005BD7A0, ??0SSTIUnitVariableData@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes one unit variable-data payload to default sim-sync values.
 */
SSTIUnitVariableData::SSTIUnitVariableData()
  : mCreator(static_cast<EntId>(0xF0000000u))
  , mCreationTick(0)
  , mAutoMode(false)
  , mAutoSurfaceMode(false)
  , mIsBusy(false)
  , mPad00B(0)
  , mFuelRatio(-1.0f)
  , mShieldRatio(0.0f)
  , mStunTicks(0)
  , mIsPaused(false)
  , mIsValidTarget(true)
  , mRepeatQueue(false)
  , mPad01B(0)
  , mJobType(0)
  , mFireState(0)
  , mWorkProgress(0.0f)
  , mTacticalSiloBuildCount(0)
  , mNukeSiloBuildCount(0)
  , mTacticalSiloStorageCount(0)
  , mNukeSiloStorageCount(0)
  , mTacticalSiloMaxStorageCount(0)
  , mNukeSiloMaxStorageCount(0)
  , mUnknown40(static_cast<EntId>(0xF0000000u))
  , mCustomName()
  , mProduced{0.0f, 0.0f}
  , mResourcesSpent{0.0f, 0.0f}
  , mMaintainenceCost{0.0f, 0.0f}
  , mFocusUnit(static_cast<EntId>(0xF0000000u))
  , mGuardedUnit(static_cast<EntId>(0xF0000000u))
  , mTargetBlip(static_cast<EntId>(0xF0000000u))
  , mPriorSharedPose()
  , mSharedPose()
  , mPad094_097{}
  , mCommands()
  , mBuildQueue()
  , mWeaponInfo()
  , mAttributes{}
  , mScriptbits(0)
  , mUnitStates(0)
  , mDidRefresh(true)
  , mOverchargePaused(false)
  , mPad222_227{}
{
  mCustomName.tidy(false, 0U);

  mAttributes.blueprint = nullptr;
  mAttributes.unknown_0004 = 0;
  mAttributes.spawnElevationOffset = std::numeric_limits<float>::infinity();
  mAttributes.moveSpeedMult = 1.0f;
  mAttributes.accelerationMult = 1.0f;
  mAttributes.turnMult = 1.0f;
  mAttributes.breakOffTriggerMult = 1.0f;
  mAttributes.breakOffDistanceMult = 1.0f;
  mAttributes.consumptionPerSecondEnergy = 0.0f;
  mAttributes.consumptionPerSecondMass = 0.0f;
  mAttributes.productionPerSecondEnergy = 0.0f;
  mAttributes.productionPerSecondMass = 0.0f;
  mAttributes.buildRate = 1.0f;
  mAttributes.regenRate = 0.0f;
  mAttributes.commandCapsMask = 0U;
  mAttributes.toggleCapsMask = 0U;
  mAttributes.mReclaimable = true;
  mAttributes.mCapturable = true;
  mAttributes.unknown_006A = 0;
  mAttributes.unknown_006B = 0;
  mAttributes.unknown_006C = 0U;
}

/**
 * Address: 0x00560500 (FUN_00560500, ??1SSTIUnitVariableData@Moho@@QAE@XZ)
 *
 * What it does:
 * Releases dynamic sync lanes through member dtors (`string`, `shared_ptr`,
 * and fastvector_n payloads).
 */
SSTIUnitVariableData::~SSTIUnitVariableData() = default;

SSTIUnitVariableData::SSTIUnitVariableData(const SSTIUnitVariableData& other)
  : SSTIUnitVariableData()
{
  AssignFrom(other);
}

SSTIUnitVariableData& SSTIUnitVariableData::operator=(const SSTIUnitVariableData& other)
{
  return AssignFrom(other);
}

/**
 * Address: 0x005BF1E0 (FUN_005BF1E0, Moho::SSTIUnitVariableData::Assign)
 *
 * What it does:
 * Copies one unit variable-data payload, including shared-pose and command/
 * build queue snapshots.
 */
SSTIUnitVariableData& SSTIUnitVariableData::AssignFrom(const SSTIUnitVariableData& other)
{
  if (this == &other) {
    return *this;
  }

  mCreator = other.mCreator;
  mCreationTick = other.mCreationTick;
  mAutoMode = other.mAutoMode;
  mAutoSurfaceMode = other.mAutoSurfaceMode;
  mIsBusy = other.mIsBusy;
  mPad00B = other.mPad00B;
  mFuelRatio = other.mFuelRatio;
  mShieldRatio = other.mShieldRatio;
  mStunTicks = other.mStunTicks;
  mIsPaused = other.mIsPaused;
  mIsValidTarget = other.mIsValidTarget;
  mRepeatQueue = other.mRepeatQueue;
  mPad01B = other.mPad01B;
  mJobType = other.mJobType;
  mFireState = other.mFireState;
  mWorkProgress = other.mWorkProgress;
  mTacticalSiloBuildCount = other.mTacticalSiloBuildCount;
  mNukeSiloBuildCount = other.mNukeSiloBuildCount;
  mTacticalSiloStorageCount = other.mTacticalSiloStorageCount;
  mNukeSiloStorageCount = other.mNukeSiloStorageCount;
  mTacticalSiloMaxStorageCount = other.mTacticalSiloMaxStorageCount;
  mNukeSiloMaxStorageCount = other.mNukeSiloMaxStorageCount;
  mUnknown40 = other.mUnknown40;
  mCustomName = other.mCustomName;
  mProduced = other.mProduced;
  mResourcesSpent = other.mResourcesSpent;
  mMaintainenceCost = other.mMaintainenceCost;
  mFocusUnit = other.mFocusUnit;
  mGuardedUnit = other.mGuardedUnit;
  mTargetBlip = other.mTargetBlip;
  mPriorSharedPose = other.mPriorSharedPose;
  mSharedPose = other.mSharedPose;
  std::memcpy(mPad094_097, other.mPad094_097, sizeof(mPad094_097));
  CopyFastVectorN(mCommands, other.mCommands);
  CopyFastVectorN(mBuildQueue, other.mBuildQueue);
  CopyFastVectorN(mWeaponInfo, other.mWeaponInfo);
  mAttributes = other.mAttributes;
  mScriptbits = other.mScriptbits;
  mUnitStates = other.mUnitStates;
  mDidRefresh = other.mDidRefresh;
  mOverchargePaused = other.mOverchargePaused;
  std::memcpy(mPad222_227, other.mPad222_227, sizeof(mPad222_227));
  return *this;
}

SSTIUnitVariableData& Unit::VarDat() noexcept
{
  return *reinterpret_cast<SSTIUnitVariableData*>(mVarDatHead);
}

SSTIUnitVariableData const& Unit::VarDat() const noexcept
{
  return *reinterpret_cast<SSTIUnitVariableData const*>(mVarDatHead);
}

/**
 * Address: 0x006A4BC0 (FUN_006A4BC0)
 *
 * What it does:
 * Returns this unit pointer through the const RTTI/downcast lane.
 */
Unit const* Unit::IsUnit() const
{
  return this;
}

/**
 * Address: 0x006A4BB0 (FUN_006A4BB0)
 *
 * What it does:
 * Returns this unit pointer through the mutable RTTI/downcast lane.
 */
Unit* Unit::IsUnit()
{
  return this;
}

// 0x006A48E0
UserUnit const* Unit::IsUserUnit() const
{
  return nullptr;
}

// 0x006A48D0
UserUnit* Unit::IsUserUnit()
{
  return nullptr;
}

// 0x006A49A0
EntId Unit::GetEntityId() const
{
  return id_;
}

// 0x006A49B0
Wm3::Vec3f const& Unit::GetPosition() const
{
  return GetPositionWm3();
}

// 0x006A49C0
VTransform const& Unit::GetTransform() const
{
  return GetTransformWm3();
}

// 0x006A8B20
RUnitBlueprint const* Unit::GetBlueprint() const
{
  const REntityBlueprint* const blueprint = BluePrint;
  return blueprint ? blueprint->IsUnitBlueprint() : nullptr;
}

/**
 * Address: 0x006A7600 (FUN_006A7600)
 * Mangled: ?GetSkirtRect@Unit@Moho@@QBE?AV?$Rect2@M@gpg@@XZ
 *
 * What it does:
 * Projects this unit position to XZ and resolves world-space skirt bounds
 * through the owning unit blueprint.
 */
gpg::Rect2f Unit::GetSkirtRect() const
{
  const Wm3::Vec3f& unitPosition = GetPosition();
  const SCoordsVec2 unitPos2d{unitPosition.x, unitPosition.z};
  const RUnitBlueprint* const blueprint = GetBlueprint();
  return blueprint->GetSkirtRect(unitPos2d);
}

/**
 * Address: 0x006AAF50 (?PickTargetPoint@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks a random index in `Blueprint->AI.TargetBones`; writes `-1` when
 * the list is empty. Returns true on all paths.
 */
bool Unit::PickTargetPoint(std::int32_t& outTargetPoint) const
{
  const RUnitBlueprint* const blueprint = GetBlueprint();
  const std::uint32_t targetBoneCount =
    (blueprint != nullptr) ? static_cast<std::uint32_t>(blueprint->AI.TargetBones.size()) : 0u;

  if (targetBoneCount == 0u || !SimulationRef || !SimulationRef->mRngState) {
    outTargetPoint = -1;
    return true;
  }

  const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
  outTargetPoint = PickUniformIndexFromU32(randomValue, targetBoneCount);
  return true;
}

/**
 * Address: 0x006AAFB0 (FUN_006AAFB0, ?PickTargetPointAboveWater@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks one target-bone index above current water elevation, or falls back
 * to unit centerline elevation when no target-bone lanes are present.
 */
bool Unit::PickTargetPointAboveWater(std::int32_t& outTargetPoint) const
{
  outTargetPoint = -1;

  const STIMap* const mapData = SimulationRef->mMapData;
  const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const msvc8::vector<msvc8::string>& targetBones = blueprint->AI.TargetBones;
  const std::int32_t targetBoneCount = static_cast<std::int32_t>(targetBones.size());
  if (targetBoneCount > 0) {
    msvc8::vector<std::int32_t> candidateIndices{};
    for (std::int32_t targetIndex = 0; targetIndex < targetBoneCount; ++targetIndex) {
      if (GetTargetPoint(targetIndex).y > waterElevation) {
        candidateIndices.push_back(targetIndex);
      }
    }

    if (!candidateIndices.empty()) {
      const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
      const std::int32_t pick = PickUniformIndexFromU32(randomValue, static_cast<std::uint32_t>(candidateIndices.size()));
      outTargetPoint = candidateIndices[static_cast<std::size_t>(pick)];
      return true;
    }

    return false;
  }

  return GetPosition().y > waterElevation;
}

/**
 * Address: 0x006AB190 (FUN_006AB190, ?PickTargetPointBelowWater@Unit@Moho@@QBE_NAAH@Z)
 *
 * What it does:
 * Picks one target-bone index below current water elevation, or falls back
 * to unit centerline elevation when no target-bone lanes are present.
 */
bool Unit::PickTargetPointBelowWater(std::int32_t& outTargetPoint) const
{
  outTargetPoint = -1;

  const STIMap* const mapData = SimulationRef->mMapData;
  const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const msvc8::vector<msvc8::string>& targetBones = blueprint->AI.TargetBones;
  const std::int32_t targetBoneCount = static_cast<std::int32_t>(targetBones.size());
  if (targetBoneCount > 0) {
    msvc8::vector<std::int32_t> candidateIndices{};
    for (std::int32_t targetIndex = 0; targetIndex < targetBoneCount; ++targetIndex) {
      if (GetTargetPoint(targetIndex).y < waterElevation) {
        candidateIndices.push_back(targetIndex);
      }
    }

    if (!candidateIndices.empty()) {
      const std::uint32_t randomValue = SimulationRef->mRngState->twister.NextUInt32();
      const std::int32_t pick = PickUniformIndexFromU32(randomValue, static_cast<std::uint32_t>(candidateIndices.size()));
      outTargetPoint = candidateIndices[static_cast<std::size_t>(pick)];
      return true;
    }

    return false;
  }

  return GetPosition().y <= waterElevation;
}

/**
 * Address: 0x006AB340 (FUN_006AB340, Moho::Unit::GetTargetPoint)
 *
 * What it does:
 * Resolves one target-bone index to world position, clamping index lanes to
 * blueprint target-bone bounds and falling back to root bone (`-1`) when the
 * request is negative.
 */
Wm3::Vec3f Unit::GetTargetPoint(std::int32_t targetPoint) const
{
  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (targetPoint >= 0 && blueprint != nullptr) {
    const msvc8::vector<msvc8::string>& targetBones = blueprint->AI.TargetBones;
    const std::int32_t maxIndex = static_cast<std::int32_t>(targetBones.size()) - 1;
    if (targetPoint >= maxIndex) {
      targetPoint = maxIndex;
    }

    if (targetPoint >= 0) {
      const int boneIndex = ResolveBoneIndex(targetBones[static_cast<std::size_t>(targetPoint)].c_str());
      return GetBoneWorldTransform(boneIndex).pos_;
    }
  }

  return GetBoneWorldTransform(-1).pos_;
}

/**
 * Address: 0x006A9E50 (FUN_006A9E50, ?CanBuild@Unit@Moho@@QBE_NPBVRUnitBlueprint@2@@Z)
 *
 * What it does:
 * Tests whether `blueprint` is present in this unit's effective build
 * category set after army and per-unit build restrictions are applied.
 */
bool Unit::CanBuild(const RUnitBlueprint* const blueprint) const
{
  const auto& armyBuildCategories =
    reinterpret_cast<const CArmyBuildCategoryFilterRuntimeView&>(*ArmyRef).mBuildCategoryFilterSet;
  const CategoryWordRangeView& unitBlueprintBuildCategories = AsCategoryWordRange(GetBlueprint()->Economy.CategoryCache);
  const auto& unitBuildRestrictions = reinterpret_cast<const UnitAttributesBuildRestrictionRuntimeView&>(GetAttributes())
                                        .mBuildRestrictionCategorySet;

  const std::uint32_t categoryBitIndex = blueprint->mCategoryBitIndex;
  return armyBuildCategories.ContainsBit(categoryBitIndex) &&
    unitBlueprintBuildCategories.ContainsBit(categoryBitIndex) &&
    !unitBuildRestrictions.ContainsBit(categoryBitIndex);
}

// 0x006A49D0
LuaPlus::LuaObject Unit::GetLuaObject()
{
  return mLuaObj;
}

// 0x006A8B30
float Unit::CalcTransportLoadFactor() const
{
  return 1.0f;
}

// 0x006A49F0
bool Unit::IsDead() const
{
  return Dead != 0;
}

// 0x006A4A00
bool Unit::DestroyQueued() const
{
  return DestroyQueuedFlag != 0;
}

// 0x006A4A10
bool Unit::IsMobile() const
{
  return UnitMotion != nullptr;
}

// 0x006A4A20
bool Unit::IsBeingBuilt() const
{
  return BeingBuilt != 0;
}

/**
 * Address: 0x0062CD40 (FUN_0062CD40, Moho::Unit::PredictAheadBomb)
 *
 * What it does:
 * Predicts near-future XZ stop position by repeatedly rotating velocity with
 * impulse-derived roll and integrating over `precision * 10` ticks.
 */
Wm3::Vec3f* Unit::PredictAheadBomb(Wm3::Vec3f* const out, const float precision) const
{
  if (!out) {
    return nullptr;
  }

  Wm3::Vec3f predicted = GetPosition();
  if (UnitMotion == nullptr) {
    *out = predicted;
    return out;
  }

  struct EntityPhysBodyRuntimeView
  {
    std::uint8_t pad_0000_01F4[0x1F4];
    SPhysBody* mPhysBody; // +0x1F4
  };
  static_assert(
    offsetof(EntityPhysBodyRuntimeView, mPhysBody) == 0x1F4,
    "EntityPhysBodyRuntimeView::mPhysBody offset must be 0x1F4"
  );

  const auto& entityView = static_cast<const Entity&>(*this);
  SPhysBody* const physBody = reinterpret_cast<const EntityPhysBodyRuntimeView&>(entityView).mPhysBody;
  if (physBody == nullptr) {
    *out = predicted;
    return out;
  }

  Wm3::Vec3f impulse = Wm3::Vec3f::Zero();
  physBody->GetImpulse(&impulse);

  Wm3::Vec3f velocity = Entity::GetVelocity();
  const Wm3::Vec3f upAxis(0.0f, 1.0f, 0.0f);
  const Wm3::Quaternionf rollRotation = Wm3::Quaternionf::FromAxisAngle(upAxis, impulse.y * 0.1f);

  float stepsRemaining = precision * 10.0f;
  while (stepsRemaining > 0.0f) {
    Wm3::Vec3f rotatedVelocity = Wm3::Vec3f::Zero();
    Wm3::MultiplyQuaternionVector(&rotatedVelocity, velocity, rollRotation);
    velocity = rotatedVelocity;

    float stepX = rotatedVelocity.x;
    float stepZ = rotatedVelocity.z;
    if (stepsRemaining <= 1.0f) {
      stepX *= stepsRemaining;
      stepZ *= stepsRemaining;
    }

    predicted.x += stepX;
    predicted.z += stepZ;
    stepsRemaining -= 1.0f;
  }

  *out = predicted;
  return out;
}

/**
 * Address: 0x006A7B90 (FUN_006A7B90, ?InitializeArmor@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * Loads armor-definition rows for the blueprint armor type and seeds
 * `ArmorMultipliers` map entries from parsed `<damageType multiplier>` pairs.
 */
void Unit::InitializeArmor()
{
  const LuaPlus::LuaObject unitObject = GetLuaObject();

  const RUnitBlueprint* const blueprint = GetBlueprint();
  const char* const armorTypeName = (blueprint != nullptr) ? blueprint->Defense.ArmorType.c_str() : "";
  const msvc8::list<msvc8::string> armorDefinitions = ARMOR_GetArmorDefinations(unitObject.GetActiveState(), armorTypeName);

  for (const msvc8::string& armorDefinition : armorDefinitions) {
    const char* definitionCursor = armorDefinition.c_str();
    msvc8::string damageTypeName{};
    if (!gpg::STR_GetToken(definitionCursor, " ", damageTypeName)) {
      continue;
    }

    const float armorMultiplier = static_cast<float>(std::atof(definitionCursor));
    *FindOrInsertArmorMultiplierValue(ArmorMultipliers, std::string_view(damageTypeName.c_str())) = armorMultiplier;
  }
}

/**
 * Address: 0x006A7D10 (FUN_006A7D10, Moho::Unit::IsBusy)
 *
 * What it does:
 * Reports whether the unit currently has active navigation movement or
 * builder-side busy state.
 */
bool Unit::IsBusy() const
{
  const IAiNavigator* const navigator = AiNavigator;
  if (!navigator || !IsMobile() || navigator->GetStatus() == AINAVSTATUS_Idle) {
    const IAiBuilder* const builder = AiBuilder;
    if (builder == nullptr || !builder->BuilderIsBusy()) {
      return false;
    }
  }

  return true;
}

/**
 * Address: 0x006AC940 (FUN_006AC940, ?UpdateSpeedThroughStatus@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Recomputes whether pathing should use speed-through-goal mode for this unit
 * from command queue state, formation leader weak-link ownership, and escort
 * movement heuristics.
 */
void Unit::UpdateSpeedThroughStatus()
{
  if (IsBeingBuilt() || IsDead() || DestroyQueued()) {
    return;
  }

  CUnitCommandQueue* const commandQueue = CommandQueue;
  IAiNavigator* const navigator = AiNavigator;
  if (commandQueue == nullptr || navigator == nullptr) {
    return;
  }

  CUnitCommand* const currentCommand = commandQueue->GetCurrentCommand();
  CUnitCommand* const nextCommand = commandQueue->GetNextCommand();

  if (IsUnitState(UNITSTATE_Refueling)) {
    navigator->SetSpeedThroughGoal(false);
    return;
  }

  bool enableSpeedThrough = false;
  if (IsUnitState(UNITSTATE_ForceSpeedThrough) || IsUnitState(UNITSTATE_CannotFindPlaceToLand)) {
    enableSpeedThrough = true;
  } else {
    bool isAirEscort = false;
    const RUnitBlueprint* const blueprint = GetBlueprint();
    if (blueprint->Air.CanFly && IsUnitState(UNITSTATE_Guarding) && !IsUnitState(UNITSTATE_Ferrying)) {
      if (!IsInCategory("EXPERIMENTAL")) {
        isAirEscort = true;
      }
    }

    if (isAirEscort) {
      enableSpeedThrough = true;
    } else if (
      currentCommand != nullptr
      && nextCommand != nullptr
      && nextCommand->GetCoordinatingOrdersSnapshot().empty()
    ) {
      if (IsSpeedThroughBusyCommandType(currentCommand->mVarDat.mCmdType)
          && IsSpeedThroughBusyCommandType(nextCommand->mVarDat.mCmdType) && !IsUnitState(UNITSTATE_AssistMoving)) {
        const Unit* const formationLead = mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
        if (formationLead == nullptr || formationLead == this) {
          enableSpeedThrough = true;
        }
      }
    }
  }

  navigator->SetSpeedThroughGoal(enableSpeedThrough);
}

/**
 * Address: 0x006AA310 (FUN_006AA310, ?Warp@Unit@Moho@@UAEXVVTransform@2@@Z)
 *
 * What it does:
 * Recomputes spawn elevation/layer for the incoming transform, warps through
 * motion component when present, then refreshes entity layer and terrain type.
 */
void Unit::Warp(const VTransform& transform)
{
  VTransform warpedTransform = transform;
  const ELayer startingLayer = GetStartingLayer(warpedTransform.pos_, LAYER_None);

  const Sim* const sim = SimulationRef;
  const STIMap* const mapData = sim ? sim->mMapData : nullptr;
  warpedTransform.pos_.y = IUnit::CalcSpawnElevation(mapData, startingLayer, warpedTransform, Attributes);

  if (UnitMotion != nullptr) {
    UnitMotion->Warp(warpedTransform);
    if (AiNavigator != nullptr) {
      AiNavigator->AbortMove();
    }
  } else {
    Entity::Warp(warpedTransform);
  }

  SetCurrentLayer(startingLayer);
}

// 0x006A7DC0
bool Unit::IsNavigatorIdle() const
{
  return !AiNavigator || AiNavigator->GetStatus() == 0;
}

// 0x006A4AF0
bool Unit::IsUnitState(const EUnitState state) const
{
  const std::uint32_t bit = static_cast<std::uint32_t>(state);
  if (bit >= 64u) {
    return false;
  }
  return (UnitStateMask & (1ull << bit)) != 0ull;
}

/**
 * Address: 0x0059A430 (FUN_0059A430, ?GetGuardedUnit@Unit@Moho@@QBEPAV12@XZ)
 */
Unit* Unit::GetGuardedUnit() const
{
  return GuardedUnitRef.ResolveObjectPtr<Unit>();
}

/**
 * Address: 0x00585B10 (FUN_00585B10, Moho::Unit::GetFocusEntity)
 */
Entity* Unit::GetFocusEntity() const
{
  return FocusEntityRef.ResolveObjectPtr<Entity>();
}

/**
 * Address: 0x0062EE00 (FUN_0062EE00, Moho::Unit::GetStagingPlatform)
 */
Unit* Unit::GetStagingPlatform() const
{
  Unit* const transport = TransportedByRef.ResolveObjectPtr<Unit>();
  if (transport == nullptr) {
    return nullptr;
  }

  if (transport->IsDead()) {
    return nullptr;
  }

  IAiTransport* const aiTransport = transport->AiTransport;
  if (aiTransport == nullptr || !aiTransport->TransportIsAirStagingPlatform()) {
    return nullptr;
  }

  return transport;
}

/**
 * Address: 0x005E3C30 (FUN_005E3C30, Moho::Unit::GetTransportedBy)
 */
Unit* Unit::GetTransportedBy() const
{
  return TransportedByRef.ResolveObjectPtr<Unit>();
}

/**
 * Address: 0x005F5540 (FUN_005F5540, Moho::Unit::GetCreator)
 *
 * What it does:
 * Resolves `CreatorRef` intrusive weak-link slot to a `Unit*`.
 */
Unit* Unit::GetCreator() const
{
  return CreatorRef.ResolveObjectPtr<Unit>();
}

/**
 * Address: 0x006A8D40 (FUN_006A8D40, Moho::Unit::IsSameFormationLayerWith)
 *
 * What it does:
 * Returns true when both units are not attacking and share the same non-null
 * formation-layer pointer.
 */
bool Unit::IsSameFormationLayerWith(const Unit* const other) const
{
  if (other == nullptr) {
    return false;
  }

  if (IsUnitState(UNITSTATE_Attacking) || other->IsUnitState(UNITSTATE_Attacking)) {
    return false;
  }

  return mInfoCache.mFormationLayer != nullptr && mInfoCache.mFormationLayer == other->mInfoCache.mFormationLayer;
}

/**
 * Address: 0x006A8D80 (FUN_006A8D80, ?IsHigherPriorityThan@Unit@Moho@@QBE_NPBV12@@Z)
 */
bool Unit::IsHigherPriorityThan(const Unit* const other) const
{
  if (!other) {
    return true;
  }

  if (IsUnitState(UNITSTATE_Immobile) || IsUnitState(UNITSTATE_Upgrading)) {
    return true;
  }
  if (other->IsUnitState(UNITSTATE_Immobile) || other->IsUnitState(UNITSTATE_Upgrading)) {
    return false;
  }

  if (mIsNaval) {
    if (!other->mIsNaval) {
      return true;
    }
  } else if (other->mIsNaval) {
    return false;
  }

  const bool thisIgnoreStructures = HasFootprintFlag(GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  const bool otherIgnoreStructures =
    HasFootprintFlag(other->GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
  if (thisIgnoreStructures) {
    if (!otherIgnoreStructures) {
      return true;
    }
  } else if (otherIgnoreStructures) {
    return false;
  }

  if (const RUnitBlueprint* const blueprint = GetBlueprint()) {
    if (blueprint->Air.CanFly && mCurrentLayer != LAYER_Air) {
      return true;
    }
  }
  if (const RUnitBlueprint* const blueprint = other->GetBlueprint()) {
    if (blueprint->Air.CanFly && other->mCurrentLayer != LAYER_Air) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_WaitingForTransport) && !other->IsUnitState(UNITSTATE_WaitingForTransport)) {
    return true;
  }

  if (GetGuardedUnit() == other) {
    return false;
  }
  if (other->GetGuardedUnit() == this) {
    return true;
  }

  bool inSharedFormation = false;
  if (mInfoCache.mFormationLayer && mInfoCache.mFormationLayer == other->mInfoCache.mFormationLayer) {
    inSharedFormation = true;

    const Unit* const formationLead = mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
    if (formationLead == this) {
      return true;
    }
    if (formationLead == other) {
      return false;
    }
  }

  if (IsUnitState(UNITSTATE_Moving) && !other->IsUnitState(UNITSTATE_Moving)) {
    return false;
  }
  if (!IsUnitState(UNITSTATE_Moving) && other->IsUnitState(UNITSTATE_Moving)) {
    return true;
  }

  if (inSharedFormation) {
    if (mInfoCache.mFormationPriorityOrder != other->mInfoCache.mFormationPriorityOrder) {
      return mInfoCache.mFormationPriorityOrder < other->mInfoCache.mFormationPriorityOrder;
    }
    return other->mInfoCache.mFormationDistanceMetric > mInfoCache.mFormationDistanceMetric;
  }

  const SFootprint& thisFootprint = GetFootprint();
  const SFootprint& otherFootprint = other->GetFootprint();
  const std::uint8_t thisFootprintSize = std::max(thisFootprint.mSizeX, thisFootprint.mSizeZ);
  const std::uint8_t otherFootprintSize = std::max(otherFootprint.mSizeX, otherFootprint.mSizeZ);
  if (thisFootprintSize > otherFootprintSize) {
    return true;
  }
  if (thisFootprintSize != otherFootprintSize) {
    return false;
  }

  if (const Unit* const moreInLine = UnitMoreInLineToOther(other, this)) {
    return moreInLine == this;
  }

  return static_cast<std::uint32_t>(GetEntityId()) < static_cast<std::uint32_t>(other->GetEntityId());
}

/**
 * Address: 0x006A7770 (FUN_006A7770, ?ExecuteOccupyGround@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Applies blueprint occupy-rect lanes (or footprint fallback rect) into
 * O-grid terrain/water occupancy masks and dirties path clusters.
 */
void Unit::ExecuteOccupyGround()
{
  const SFootprint& footprint = GetFootprint();
  const RUnitBlueprint* const blueprint = GetBlueprint();
  COGrid* const ogrid = SimulationRef ? SimulationRef->mOGrid : nullptr;
  const std::uint8_t occupancyCaps = static_cast<std::uint8_t>(footprint.mOccupancyCaps);

  const auto& occupyRects = blueprint->Physics.OccupyRects;
  if (occupyRects.empty()) {
    const Wm3::Vec3f& unitPos = GetPosition();
    const auto x0 = static_cast<std::int16_t>(
      static_cast<std::int32_t>(unitPos.x - static_cast<float>(footprint.mSizeX) * 0.5f)
    );
    const auto z0 = static_cast<std::int16_t>(
      static_cast<std::int32_t>(unitPos.z - static_cast<float>(footprint.mSizeZ) * 0.5f)
    );

    gpg::Rect2i rect{};
    rect.x0 = static_cast<std::int32_t>(x0);
    rect.z0 = static_cast<std::int32_t>(z0);
    rect.x1 = rect.x0 + static_cast<std::int32_t>(footprint.mSizeX);
    rect.z1 = rect.z0 + static_cast<std::int32_t>(footprint.mSizeZ);
    ApplyOccupancyRect(occupancyCaps, ogrid, rect);
    return;
  }

  const Wm3::Vec3f& unitPos = GetPosition();
  for (const RUnitBlueprintOccupyRect& occupyRect : occupyRects) {
    gpg::Rect2i rect{};
    rect.x0 = RoundOccupyRectEdge(unitPos.x + occupyRect.CenterOffsetX - occupyRect.HalfSizeX);
    rect.x1 = RoundOccupyRectEdge(unitPos.x + occupyRect.CenterOffsetX + occupyRect.HalfSizeX);
    rect.z0 = RoundOccupyRectEdge(unitPos.z + occupyRect.CenterOffsetZ - occupyRect.HalfSizeZ);
    rect.z1 = RoundOccupyRectEdge(unitPos.z + occupyRect.CenterOffsetZ + occupyRect.HalfSizeZ);
    ApplyOccupancyRect(occupancyCaps, ogrid, rect);
  }
}

/**
 * Address: 0x006AB6F0 (FUN_006AB6F0, ?ReserveOgridRect@Unit@Moho@@QAEXABV?$Rect2@H@gpg@@@Z)
 */
void Unit::ReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  FreeOgridRect();

  ReservedOgridRectMinX = ogridRect.x0;
  ReservedOgridRectMinZ = ogridRect.z0;
  ReservedOgridRectMaxX = ogridRect.x1;
  ReservedOgridRectMaxZ = ogridRect.z1;

  FillReservedOgridRect(*this, true);
}

/**
 * Address: 0x006AB760 (FUN_006AB760, ?FreeOgridRect@Unit@Moho@@QAEXXZ)
 */
void Unit::FreeOgridRect()
{
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  if (!IsCollisionRectEquivalentToZero(reservedRect)) {
    FillReservedOgridRect(*this, false);
  }

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;
}

/**
 * Address: 0x006AB810 (FUN_006AB810, ?CanReserveOgridRect@Unit@Moho@@QAE_NABV?$Rect2@H@gpg@@@Z)
 */
bool Unit::CanReserveOgridRect(const gpg::Rect2i& ogridRect)
{
  const gpg::Rect2i reservedRect = GetReservedOgridRect(*this);
  const bool hadReservation = !IsCollisionRectEquivalentToZero(reservedRect);
  if (hadReservation) {
    FillReservedOgridRect(*this, false);
  }

  bool canReserve = true;
  if (SimulationRef && SimulationRef->mOGrid) {
    canReserve = !SimulationRef->mOGrid->mOccupation.GetRectOr(
      ogridRect.x0,
      ogridRect.z0,
      ogridRect.x1 - ogridRect.x0,
      ogridRect.z1 - ogridRect.z0,
      true
    );
  }

  if (hadReservation) {
    FillReservedOgridRect(*this, true);
  }

  return canReserve;
}

// 0x006A4990
UnitAttributes& Unit::GetAttributes()
{
  return Attributes;
}

// 0x006A4980
UnitAttributes const& Unit::GetAttributes() const
{
  return Attributes;
}

// 0x006A4B90
StatItem* Unit::GetStat(gpg::StrArg name, const std::string&)
{
  return moho::ResolveStatString(mConstDat.mStatsRoot.get(), name);
}

// 0x006A4B70
StatItem* Unit::GetStat(gpg::StrArg name, const float&)
{
  return moho::ResolveStatFloat(mConstDat.mStatsRoot.get(), name);
}

// 0x006A4B50
StatItem* Unit::GetStat(gpg::StrArg name, const int&)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot.get(), name, 1);
}

// 0x006A4B30
StatItem* Unit::GetStat(gpg::StrArg name)
{
  return moho::ResolveStatByMode(mConstDat.mStatsRoot.get(), name, 0);
}

/**
 * Address: 0x006A73A0 (FUN_006A73A0)
 *
 * What it does:
 * Stores the auto-mode flag and dispatches the matching script callback.
 */
void Unit::SetAutoMode(const bool enabled)
{
  AutoMode = enabled;
  CallbackStr(enabled ? "OnAutoModeOn" : "OnAutoModeOff");
}

/**
 * Address: 0x006A73E0 (FUN_006A73E0)
 *
 * What it does:
 * Stores the auto-surface-mode flag.
 */
void Unit::SetAutoSurfaceMode(const bool enabled)
{
  AutoSurfaceMode = enabled;
}

/**
 * Address: 0x006A4A30 (FUN_006A4A30)
 *
 * What it does:
 * Returns the current auto-mode flag.
 */
bool Unit::IsAutoMode() const
{
  return AutoMode;
}

/**
 * Address: 0x006A4A40 (FUN_006A4A40)
 *
 * What it does:
 * Returns the current auto-surface-mode flag.
 */
bool Unit::IsAutoSurfaceMode() const
{
  return AutoSurfaceMode;
}

/**
 * Address: 0x006A4A50 (FUN_006A4A50)
 *
 * What it does:
 * Copies a caller-provided name into the unit custom-name lane.
 */
void Unit::SetCustomName(const std::string name)
{
  CustomName = name.c_str();
}

/**
 * Address: 0x006A4AB0 (FUN_006A4AB0)
 *
 * What it does:
 * Copies and returns the current custom-name lane.
 */
std::string Unit::GetCustomName() const
{
  return std::string(CustomName.c_str(), CustomName.size());
}

/**
 * Address: 0x006A8790 (FUN_006A8790)
 *
 * What it does:
 * Releases AI sidecars and command queue ownership during kill-cleanup, then
 * clears all corresponding unit pointers.
 */
void Unit::KillCleanup()
{
  mNeedsKillCleanup = false;

  if (AiAttacker) {
    AiAttacker->WeaponsOnDestroy();
  }

  auto* commandDispatch = AiCommandDispatch;
  AiCommandDispatch = nullptr;
  delete commandDispatch;

  if (CommandQueue) {
    CommandQueue->MarkForUnitKillCleanup();
  }

  auto* attacker = AiAttacker;
  AiAttacker = nullptr;
  delete attacker;

  auto* transport = AiTransport;
  AiTransport = nullptr;
  delete transport;

  auto* navigator = AiNavigator;
  AiNavigator = nullptr;
  delete navigator;

  auto* steering = AiSteering;
  AiSteering = nullptr;
  delete steering;

  auto* builder = AiBuilder;
  AiBuilder = nullptr;
  delete builder;

  auto* siloBuild = AiSiloBuild;
  AiSiloBuild = nullptr;
  delete siloBuild;

  CUnitCommandQueue* queue = CommandQueue;
  CommandQueue = nullptr;
  if (queue) {
    queue->DestroyForUnitKillCleanup();
    ::operator delete(queue);
  }
}

/**
 * Address: 0x006ACB20 (FUN_006ACB20)
 *
 * What it does:
 * Appends unit-side sync extra-data records into the provided output buffer.
 */
void Unit::GetExtraData(SExtraUnitData* out) const
{
  if (!out) {
    return;
  }
  ExtraDataPairBuffer pairBuffer{out};

  if (AiAttacker) {
    const int count = AiAttacker->GetWeaponCount();
    for (int i = 0; i < count; ++i) {
      CAiAttackerImpl::WeaponExtraData weaponExtra{};
      if (!AiAttacker->TryGetWeaponExtraData(i, weaponExtra)) {
        continue;
      }

      SExtraUnitDataPair pair{};
      pair.key = weaponExtra.key;
      pair.value = CAiAttackerImpl::ReadExtraDataValue(weaponExtra.ref);
      (void)pairBuffer.push_back(pair);
    }
  } else if (AiTransport) {
    const Unit* teleportBeacon = AiTransport->TransportGetTeleportBeaconForSync();
    if (teleportBeacon) {
      SExtraUnitDataPair pair{};
      pair.key = -1;
      pair.value = teleportBeacon->id_;
      (void)pairBuffer.push_back(pair);
    }
  }

  out->unitEntityId = id_;
}

/**
 * Address: 0x006A73F0 (FUN_006A73F0)
 *
 * What it does:
 * Applies pause/unpause when unit caps allow it, emits script callbacks on
 * state transitions, and marks sync game-data dirty.
 */
void Unit::SetPaused(const bool paused)
{
  const UnitAttributes& attributes = GetAttributes();
  const bool canToggle =
    (attributes.commandCapsMask & kCommandCapPause) != 0u || (attributes.toggleCapsMask & kToggleCapGeneric) != 0u;
  if (!canToggle) {
    return;
  }

  if (paused) {
    if (!IsPaused) {
      CallbackStr("OnPaused");
    }
  } else if (IsPaused) {
    CallbackStr("OnUnpaused");
  }

  IsPaused = paused;
  MarkNeedsSyncGameData();
}

/**
 * Address: 0x006A7450 (FUN_006A7450)
 *
 * What it does:
 * Sets repeat-queue mode, marks the dirty-sync lane, and emits
 * OnStartRepeatQueue/OnStopRepeatQueue callbacks.
 */
void Unit::SetRepeatQueue(const bool enabled)
{
  if (enabled) {
    if (!RepeatQueueEnabled) {
      CallbackStr("OnStartRepeatQueue");
    }
  } else if (RepeatQueueEnabled) {
    CallbackStr("OnStopRepeatQueue");
  }

  RepeatQueueEnabled = enabled;
  MarkNeedsSyncGameData();
}

/**
 * Address: 0x006AA900 (FUN_006AA900, ?SetConsumptionActive@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Rebuilds unit upkeep request lanes for active/inactive economy
 * consumption and dispatches matching Lua script callbacks.
 */
void Unit::SetConsumptionActive(const bool isActive)
{
  const bool oldConsumptionIsActive = ConsumptionActive;
  ConsumptionActive = isActive;

  SEconValue newConsumption{};
  newConsumption.energy = Attributes.consumptionPerSecondEnergy * 0.1f;
  newConsumption.mass = Attributes.consumptionPerSecondMass * 0.1f;

  if (mConsumptionData == nullptr) {
    auto* const request = new CEconRequest{};
    request->mRequested = newConsumption;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;

    if (ArmyRef != nullptr) {
      if (CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy(); economyInfo != nullptr) {
        request->mNode.ListLinkBefore(&economyInfo->registrationNode);
      }
    }

    if (mConsumptionData != nullptr) {
      mConsumptionData->mNode.ListUnlink();
      delete mConsumptionData;
    }
    mConsumptionData = request;
  }

  if (!ConsumptionActive) {
    if (mConsumptionData != nullptr && ArmyRef != nullptr) {
      if (CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy(); economyInfo != nullptr) {
        economyInfo->economy.mStored.ENERGY += mConsumptionData->mGranted.energy;
        economyInfo->economy.mStored.MASS += mConsumptionData->mGranted.mass;
      }
    }

    newConsumption.energy = 0.0f;
    newConsumption.mass = 0.0f;
  }

  if (mConsumptionData != nullptr) {
    mConsumptionData->mRequested = newConsumption;
  }

  SharedEconomyRateEnergy = newConsumption.energy;
  SharedEconomyRateMass = newConsumption.mass;

  if (ConsumptionActive != oldConsumptionIsActive) {
    if (ConsumptionActive) {
      CallbackStr("OnConsumptionActive");
    } else {
      CallbackStr("OnConsumptionInActive");
    }
  }
}

/**
 * Address: 0x006A9370 (FUN_006A9370, ?RenderAIDebugInfo@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * Emits per-unit AI debug stat counters under `AIDebug_<UniqueName>`,
 * including platoon metadata, idle marker, and active unit-state markers.
 */
void Unit::RenderAIDebugInfo()
{
  if (!mDebugAIStates || ArmyRef == nullptr) {
    return;
  }

  ArmyRef->UpdateAIDebugPlatoonStats(this);

  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  if (armyStats == nullptr) {
    return;
  }

  const msvc8::string debugPrefix = msvc8::string("AIDebug_") + GetUniqueName();
  const msvc8::string unitStatePrefix = debugPrefix + "_UnitStates";

  const CUnitCommand* headCommand = nullptr;
  if (CommandQueue != nullptr && !CommandQueue->mCommandVec.empty()) {
    headCommand = CommandQueue->mCommandVec.begin()->GetObjectPtr();
  }

  if (headCommand == nullptr || reinterpret_cast<std::uintptr_t>(headCommand) == kInvalidWeakCommandSentinel) {
    IncrementAIDebugStateStat(armyStats, unitStatePrefix + "_Idle");
  }

  for (
    std::int32_t stateValue = static_cast<std::int32_t>(UNITSTATE_Immobile);
    stateValue <= static_cast<std::int32_t>(UNITSTATE_SiloBuildingAmmo);
    ++stateValue
  ) {
    const EUnitState state = static_cast<EUnitState>(stateValue);
    if (!IsUnitState(state)) {
      continue;
    }

    const char* const stateLexical = UnitStateToDebugLexical(state);
    if (stateLexical == nullptr || stateLexical[0] == '\0') {
      continue;
    }

    IncrementAIDebugStateStat(armyStats, unitStatePrefix + "_" + stateLexical);
  }
}

/**
 * Address: 0x006AC2C0 (FUN_006AC2C0, ?CreateInterface@Unit@Moho@@MAEXPAUSSyncData@2@@Z)
 *
 * What it does:
 * Queues one unit-create sync packet and marks this entity interface as
 * created for subsequent SyncInterface lanes.
 */
void Unit::CreateInterface(SSyncData* const syncData)
{
  if (syncData != nullptr) {
    SCreateUnitParams createParams{};
    createParams.mEntityId = id_;
    createParams.mBlueprint = BluePrint;
    createParams.mTickCreated = mTickCreated;
    createParams.mConstDat.mBuildStateTag = mConstDat.mBuildStateTag;
    createParams.mConstDat.mStatsRoot = mConstDat.mStatsRoot;
    createParams.mConstDat.mFake = mConstDat.mFake;
    syncData->mNewUnits.push_back(createParams);
  }

  mInterfaceCreated = 1u;
}

/**
 * Address: 0x006AC530 (FUN_006AC530, ?ShowAIDebugInfo@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Resolves this unit's `AIDebug_<UniqueName>` stat path and clears it from
 * owning army stats.
 */
void Unit::ShowAIDebugInfo(const bool isEnabled)
{
  (void)isEnabled;

  if (ArmyRef == nullptr) {
    return;
  }

  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  if (armyStats == nullptr) {
    return;
  }

  const msvc8::string debugStatPath = msvc8::string("AIDebug_") + GetUniqueName();
  armyStats->Delete(debugStatPath.c_str());
}

/**
 * Address: 0x0062AF70 (FUN_0062AF70, Moho::Unit::DistanceToOccupiedRect)
 *
 * What it does:
 * Finds the first raised-platform quad covering `samplePoint` in local XZ and
 * bilinearly interpolates one additional Y offset for occupancy snap lanes.
 */
float Unit::DistanceToOccupiedRect(const Wm3::Vector3f* const samplePoint)
{
  if (samplePoint == nullptr || IsDead()) {
    return 0.0f;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint == nullptr) {
    return 0.0f;
  }

  const Wm3::Vector3f& unitPosition = GetPosition();
  const float sampleX = samplePoint->x;
  const float sampleZ = samplePoint->z;

  for (const RUnitBlueprintRaisedPlatform& raisedPlatform : blueprint->Physics.RaisedPlatforms) {
    const auto& platform = reinterpret_cast<const RaisedPlatformRuntimeView&>(raisedPlatform);
    const float x0 = platform.vertex0.x + unitPosition.x;
    const float x1 = platform.vertex1.x + unitPosition.x;
    const float x3 = platform.vertex3.x + unitPosition.x;

    const float z0 = platform.vertex0.z + unitPosition.z;
    const float z2 = platform.vertex2.z + unitPosition.z;
    const float z3 = platform.vertex3.z + unitPosition.z;

    if (sampleX <= x3 && x0 <= sampleX && sampleZ <= z3 && z0 <= sampleZ) {
      const float zBlend = (sampleZ - z0) / (z2 - z0);
      const float yOnLeftEdge = ((platform.vertex2.y - platform.vertex0.y) * zBlend) + platform.vertex0.y;
      const float yOnRightEdge = ((platform.vertex3.y - platform.vertex1.y) * zBlend) + platform.vertex1.y;
      const float xBlend = (sampleX - x0) / (x1 - x0);
      return ((yOnRightEdge - yOnLeftEdge) * xBlend) + yOnLeftEdge;
    }
  }

  return 0.0f;
}

/**
 * Address: 0x006AC600 (FUN_006AC600, ?DebugShowRaisedPlatforms@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * When `ShowRaisedPlatforms` sim-convar is enabled, draws one debug quad per
 * raised-platform blueprint polygon in world space.
 */
void Unit::DebugShowRaisedPlatforms()
{
  if (!SimulationRef) {
    return;
  }

  CSimConVarBase* const showRaisedPlatformsDef = GetShowRaisedPlatformsSimConVarDef();
  if (!showRaisedPlatformsDef) {
    return;
  }

  CSimConVarInstanceBase* const showRaisedPlatforms = SimulationRef->GetSimVar(showRaisedPlatformsDef);
  const void* const valueStorage = showRaisedPlatforms ? showRaisedPlatforms->GetValueStorage() : nullptr;
  if (!valueStorage || !*reinterpret_cast<const std::uint8_t*>(valueStorage)) {
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (!blueprint) {
    return;
  }

  CDebugCanvas* const debugCanvas = SimulationRef->GetDebugCanvas();
  if (!debugCanvas) {
    return;
  }

  const Wm3::Vector3f unitPos = GetPosition();
  for (const RUnitBlueprintRaisedPlatform& platform : blueprint->Physics.RaisedPlatforms) {
    const Wm3::Vector3f p0{
      unitPos.x + platform.Vertex0X,
      unitPos.y + platform.Vertex0Y,
      unitPos.z + platform.Vertex0Z,
    };
    const Wm3::Vector3f p1{
      unitPos.x + platform.Vertex1X,
      unitPos.y + platform.Vertex1Y,
      unitPos.z + platform.Vertex1Z,
    };
    const Wm3::Vector3f p2{
      unitPos.x + platform.Vertex2X,
      unitPos.y + platform.Vertex2Y,
      unitPos.z + platform.Vertex2Z,
    };
    const Wm3::Vector3f p3{
      unitPos.x + platform.Vertex3X,
      unitPos.y + platform.Vertex3Y,
      unitPos.z + platform.Vertex3Z,
    };

    DrawRaisedPlatformEdge(*debugCanvas, p0, p1);
    DrawRaisedPlatformEdge(*debugCanvas, p1, p3);
    DrawRaisedPlatformEdge(*debugCanvas, p3, p2);
    DrawRaisedPlatformEdge(*debugCanvas, p2, p0);
  }
}

// 0x006A7490
void Unit::ToggleScriptBit(const int bitIndex)
{
  const std::uint32_t shift = static_cast<std::uint32_t>(static_cast<std::uint8_t>(bitIndex)) & 0x1Fu;
  const std::uint32_t mask = 1u << shift;

  const UnitAttributes& attributes = GetAttributes();
  if ((attributes.toggleCapsMask & mask) == 0u) {
    return;
  }

  if (IsUnitState(kTransportScriptBitGuardState) && IsInCategory("TRANSPORTATION")) {
    return;
  }

  if ((ScriptBitMask & mask) != 0u) {
    ScriptBitMask &= ~mask;
    CallbackInt("OnScriptBitClear", bitIndex);
  } else {
    ScriptBitMask |= mask;
    CallbackInt("OnScriptBitSet", bitIndex);
  }

  MarkNeedsSyncGameData();
}

/**
 * Address: 0x006A97C0 (FUN_006A97C0)
 *
 * What it does:
 * Updates fire-state storage and marks the dirty-sync lane for replication.
 */
void Unit::SetFireState(const std::int32_t fireState)
{
  if (FireState == fireState) {
    return;
  }

  FireState = fireState;
  MarkNeedsSyncGameData();
}
