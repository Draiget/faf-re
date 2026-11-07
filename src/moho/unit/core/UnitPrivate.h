#pragma once

// Private to moho/unit/core: helpers the pieces of the former Unit.cpp share.

#include "moho/math/Wm3AxisAlignedBox3FafExtras.h"
#include "platform/Interlocked.h"
// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/Unit.h"
#include "gpg/core/profiling/Profiler.h"
#include "legacy/math/X87Math.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/CAiNavigatorImpl.h"

#include <algorithm>
#include <bit>
#include <iterator>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <list>
#include <limits>
#include <new>
#include <string>
#include <stdexcept>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiSteering.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/animation/PoseJobs.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/entity/intel/CIntel.h"
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
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/entity/EntityDb.h"
#include "moho/ai/CAiSteeringImpl.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/task/ETaskStatus.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/SSTITarget.h"
#include "moho/path/PathTables.h"
#include "moho/entity/Entity.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/FafGameVersion.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/CSimConVarInstanceBase.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/ReconBlip.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimArchiveMode.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/console/CConCommand.h"
#include "moho/sim/UnitUpdateFill.h"
#include "moho/ai/CAiTransportImpl.h"
#include "moho/sim/SPhysBody.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/sim/SimStartupRegistrations.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"
#include "moho/unit/core/EFireStateTypeInfo.h"
#include "moho/unit/core/EJobTypeTypeInfo.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UnitLuaFunctionThunks.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CUnitAssistMoveTask.h"
#include "moho/unit/core/UserUnit.h"

#include "gpg/core/reflection/StaticInitPhase.h"


using namespace moho;
namespace moho
{
  int cfunc_UnitGetUnitIdL(LuaPlus::LuaState* state);
  int cfunc_UnitGetUnitId(lua_State* luaContext);
  CScrLuaInitForm* func_UnitGetUnitId_LuaFuncDef();
  int cfunc_UnitSetCreatorL(LuaPlus::LuaState* state);
  int cfunc_UnitSetCreator(lua_State* luaContext);
  CScrLuaInitForm* func_UnitSetCreator_LuaFuncDef();
  void AssignCreatorWeakRefAndMarkSyncDirty(Unit* unit, Unit* creator);
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
  int cfunc_UnitHasMeleeSpaceAroundTargetL(LuaPlus::LuaState* state);
  int cfunc_UnitHasMeleeSpaceAroundTarget(lua_State* luaContext);
  CScrLuaInitForm* func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef();
  int cfunc_UnitForceAltFootprint(lua_State* luaContext);
  CScrLuaInitForm* func_UnitForceAltFootprint_LuaFuncDef();
  int cfunc_UnitMeleeWarpAdjacentToTargetL(LuaPlus::LuaState* state);
  int cfunc_UnitMeleeWarpAdjacentToTarget(lua_State* luaContext);
  CScrLuaInitForm* func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef();
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
}

namespace
{
  constexpr const char* kUnitOnAssignedFocusEntityScript = "OnAssignedFocusEntity";

  [[maybe_unused]] [[nodiscard]] bool IsMeleeCandidateCellNavigable(
    Unit& moveUnit,
    Unit* ignoreUnit,
    const SFootprint& moverFootprint,
    ELayer moveLayer,
    COGrid& ogrid,
    const STIMap& mapData,
    const SOCellPos& candidateCell
  );
}


[[noreturn]] void EngineThrowContainerTooLong(const char* message);
namespace moho
{
  extern bool sim_DeferBlipUnlinks;
  extern bool sim_ParallelBlipFlush;
  extern int sim_DeferBlipUnlinksTicks;
}

