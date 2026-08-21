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
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerSaveLoadHelperListRuntime.h"
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
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/EntityTransformPayload.h"
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
#include "moho/math/QuaternionMath.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/entity/EntityDb.h"
#include "moho/ai/CAiSteeringImpl.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/task/ETaskStatus.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/path/PathTables.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
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
#include "moho/sim/SimDriver.h"
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

namespace gpg
{
  // Minimal local view of gpg::SerConstructResult sufficient to invoke the
  // recovered Unit::MemberConstruct publish path (mirrors the local declaration
  // used by the other recovered *Construct translation units).
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00720F70 (FUN_00720F70, Moho::COORDS_CanMoveAt)
   *
   * What it does:
   * Validates whether `moveUnit` can occupy/move through `*pos` while filtering
   * nearby collision occupants against movement/attachment/formation rules.
   */
  bool COORDS_CanMoveAt(SOCellPos* pos, COGrid* grid, Unit* moveUnit, bool disallowAttached, Unit* ignoreUnit)
  {
    if (moveUnit == nullptr) {
      return false;
    }

    // Movement-rule category sets, resolved once up front (order preserved).
    RRuleGameRules* const rules = moveUnit->SimulationRef->mRules;
    const CategoryWordRangeView* const catFerryBeacon = rules->GetEntityCategory("FERRYBEACON");
    const CategoryWordRangeView* const catPodStagingPlatform = rules->GetEntityCategory("PODSTAGINGPLATFORM");

    const SFootprint& footprint = moveUnit->GetFootprint();
    const ELayer moveLayer = moveUnit->mCurrentLayer;
    const bool moveUnitHasStorage = moveUnit->AiTransport != nullptr;

    // Footprint-sized query box: horizontal side = max(sizeX, sizeZ); Y spans
    // [-1000, 1000] (effectively unbounded vertical), anchored at the cell.
    const int maxFootprintSide = std::max<int>(footprint.mSizeX, footprint.mSizeZ);
    Wm3::AxisAlignedBox3f box{};
    box.Min.x = static_cast<float>(pos->x);
    box.Max.x = static_cast<float>(pos->x + maxFootprintSide);
    box.Min.y = -1000.0f;
    box.Max.y = 1000.0f;
    box.Min.z = static_cast<float>(pos->z);
    box.Max.z = static_cast<float>(pos->z + maxFootprintSide);

    CollisionResultFastVectorN10 into{};
    GatherUnmarkedUnitsInBox(*grid, box, into);

    for (const CollisionResult& hit : into) {
      Entity* const source = hit.sourceEntity;
      Unit* const curUnit = (source != nullptr) ? source->IsUnit() : nullptr;

      // Ignore the requested unit and any non-unit occupant.
      if (curUnit == ignoreUnit || curUnit == nullptr) {
        continue;
      }

      // Dead / under-construction / self never block.
      if (curUnit->IsDead()) {
        continue;
      }
      if (curUnit->IsBeingBuilt()) {
        continue;
      }
      if (curUnit == moveUnit) {
        continue;
      }

      // Layer filter: air occupants never block ground movement, and a sub mover
      // is only blocked by occupants sharing its exact layer.
      const ELayer curLayer = curUnit->mCurrentLayer;
      if (curLayer == LAYER_Air || (moveLayer != curLayer && moveLayer == LAYER_Sub)) {
        continue;
      }

      // A ferry-beacon we ourselves created does not block us.
      if (EntityCategory::HasBlueprint(curUnit->GetBlueprint(), catFerryBeacon)) {
        if (curUnit->GetCreator() == moveUnit) {
          continue;
        }
      }

      // Transport-style blocker: has an AiTransport and is not a pod-staging
      // platform (the loop `break` path in the decompiler). Otherwise fall
      // through to the general velocity/attachment logic.
      bool blockedByTransport = false;
      if (curUnit->AiTransport != nullptr) {
        if (!EntityCategory::HasBlueprint(curUnit->GetBlueprint(), catPodStagingPlatform)) {
          blockedByTransport = true;
        }
      }

      // Both the transport-blocker path and the velocity path converge on the
      // same formation/attached decision. `blockOccupant` requests the
      // "this occupant blocks -> return false" outcome (unless it is attached).
      bool blockOccupant = false;

      if (blockedByTransport) {
        if (curUnit->mCurrentLayer == LAYER_Air) {
          continue;
        }
        if (disallowAttached) {
          blockOccupant = true;
        } else if (!moveUnit->IsSameFormationLayerWith(curUnit)) {
          blockOccupant = true;
        }
        // else same formation layer -> does not block.
      } else {
        // Velocity path: velocity/compare evaluated before the layer test, as in
        // the binary. The binary compares velocity to a static zero vector via a
        // raw 12-byte memcmp (FUN_004F0A50, an ICF fold of Wm3::Vector3::Compare
        // and EntityTransformPositionDiffers) — reproduce the exact byte compare.
        const Wm3::Vec3f curVel = curUnit->GetVelocity();
        const Wm3::Vec3f kZeroVelocity{0.0f, 0.0f, 0.0f};
        const bool isMoving = std::memcmp(&curVel, &kZeroVelocity, sizeof(Wm3::Vec3f)) != 0;

        if (curUnit->mCurrentLayer == LAYER_Air) {
          continue;
        }

        if (moveUnitHasStorage) {
          // We are a transport: a moving occupant, or one we are not currently
          // trying to load, does not block us here.
          if (isMoving) {
            continue;
          }
          if (moveUnit->IsUnitState(UNITSTATE_TransportLoading)) {
            continue;
          }
        }

        if (disallowAttached) {
          blockOccupant = true;
        } else if (isMoving) {
          continue;
        } else if (!moveUnit->IsSameFormationLayerWith(curUnit)) {
          blockOccupant = true;
        }
        // else stationary same-formation occupant -> does not block.
      }

      // Shared attachment gate: a blocking occupant still does NOT block if it is
      // itself attached (riding something rather than occupying the cell).
      if (blockOccupant && !curUnit->IsUnitState(UNITSTATE_Attached)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x0062ABA0 (FUN_0062ABA0, sub_62ABA0)
   *
   * IDA signature:
   * char __usercall sub_62ABA0@<al>(Wm3::Vector3f *a1@<edi>, Moho::Unit *a2@<esi>, int a3);
   *
   * What it does:
   * Converts `worldPosition` to the unit footprint's origin cell and asks the
   * occupancy grid whether the unit is blocked there under `mode`.
   *
   * The conversion is the same one `SFootprint::ToCellPos` performs, and it
   * rounds: the binary uses two bare fistp stores with no __ftol call.
   */
  bool UnitIsBlockedAt(const Wm3::Vec3f& worldPosition, Unit* const unit, const int mode)
  {
    const SFootprint& footprint = unit->GetFootprint();
    const SOCellPos cellPos = footprint.ToCellPos(worldPosition);
    return COGrid::UnitIsBlocked(cellPos, *unit->SimulationRef->mOGrid, unit, mode);
  }

  /**
   * Address: 0x0062AA90 (FUN_0062AA90, func_UnitWontFitAt)
   *
   * What it does:
   * Returns true when `unit` cannot place its footprint at `worldPosition`
   * due to map bounds or occupancy-cap fit checks.
   */
  bool UnitWontFitAt(const Wm3::Vec3f& worldPosition, const Unit* const unit)
  {
    const SFootprint& footprint = unit->GetFootprint();
    const Sim& sim = *unit->SimulationRef;
    const STIMap& mapData = *sim.mMapData;
    const bool useWholeMap = (unit->ArmyRef != nullptr) ? unit->ArmyRef->UseWholeMap() : false;
    if (!mapData.IsWithin(worldPosition, 0.0f, useWholeMap)) {
      return true;
    }

    // The binary converts these with fld/fistp (0x0062AB0D-0x0062AB11 and
    // 0x0062AB32-0x0062AB36), i.e. round-to-nearest under the default FPU
    // control word - not truncation. `SFootprint::ToCellPos` (FUN_00579300) is
    // the same computation and already rounds correctly, so defer to it rather
    // than open-code a second copy.
    const SOCellPos cellPos = footprint.ToCellPos(worldPosition);

    EOccupancyCaps occupancyCaps = OCCUPY_MobileCheck(footprint, mapData, cellPos);
    if (unit->mCurrentLayer == LAYER_Water) {
      occupancyCaps = static_cast<EOccupancyCaps>(
        static_cast<std::uint8_t>(occupancyCaps) & ~static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB)
      );
    }

    return static_cast<std::uint8_t>(OCCUPY_FootprintFits(*sim.mOGrid, cellPos, footprint, occupancyCaps)) == 0u;
  }
} // namespace moho

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
  constexpr const char* kNotifyUpgradeName = "NotifyUpgrade";
  constexpr const char* kNotifyUpgradeGlobalClassName = "<global>";
  constexpr const char* kNotifyUpgradeHelpText = "NotifyUpgrade(from,to)";
  constexpr const char* kCreateUnit2Name = "CreateUnit2";
  constexpr const char* kCreateUnit2GlobalClassName = "<global>";
  constexpr const char* kCreateUnit2HelpText = "blueprint, army, layer, x, z, heading";
  constexpr const char* kCreateUnitName = "CreateUnit";
  constexpr const char* kCreateUnitGlobalClassName = "<global>";
  constexpr const char* kCreateUnitHelpText = "blueprint, army, tx, ty, tz, qx, qy, qz, qw, [layer]";
  constexpr const char* kCreateUnitHPRName = "CreateUnitHPR";
  constexpr const char* kCreateUnitHPRGlobalClassName = "<global>";
  constexpr const char* kCreateUnitHPRHelpText = "blueprint, army, x, y, z, pitch, yaw, roll";
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
  constexpr const char* kUnitMeleeWarpAdjacentToTargetName = "MeleeWarpAdjacentToTarget";
  constexpr const char* kUnitMeleeWarpAdjacentToTargetHelpText = "Unit:MeleeWarpAdjacentToTarget(target)";
  constexpr const char* kUnitHasMeleeSpaceAroundTargetName = "HasMeleeSpaceAroundTarget";
  constexpr const char* kUnitHasMeleeSpaceAroundTargetHelpText = "Unit:HasMeleeSpaceAroundTarget(target)";
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
  RUnitBlueprint gUnitGetStatBlueprint(nullptr, RResId{});
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

  constexpr std::uintptr_t kGuardedByOwnerLinkOffset = 0x8u;

  [[nodiscard]] std::uintptr_t GuardedByOwnerSlotWord(const SGuardedByWeakOwnerSlot& slot) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(slot.ownerLinkSlot);
  }

  [[nodiscard]] SGuardedByWeakOwnerSlot EncodeGuardedByOwnerSlot(const Unit* const owner) noexcept
  {
    SGuardedByWeakOwnerSlot slot{};
    if (owner == nullptr) {
      slot.ownerLinkSlot = nullptr;
      return slot;
    }

    slot.ownerLinkSlot = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(owner) + kGuardedByOwnerLinkOffset);
    return slot;
  }

  [[nodiscard]] Entity* DecodeGuardedByOwnerSlot(const SGuardedByWeakOwnerSlot slot) noexcept
  {
    if (slot.ownerLinkSlot == nullptr) {
      return nullptr;
    }

    const std::uintptr_t encoded = reinterpret_cast<std::uintptr_t>(slot.ownerLinkSlot);
    if (encoded <= kGuardedByOwnerLinkOffset) {
      return nullptr;
    }

    return reinterpret_cast<Entity*>(encoded - kGuardedByOwnerLinkOffset);
  }

  [[nodiscard]] bool RemoveGuardedByOwner(SGuardedByRuntimeList& guardedByList, const Unit* const guardUnit) noexcept
  {
    if (guardUnit == nullptr || guardedByList.mSlots.begin == nullptr || guardedByList.mSlots.end == nullptr) {
      return false;
    }

    const std::uintptr_t targetSlotWord = GuardedByOwnerSlotWord(EncodeGuardedByOwnerSlot(guardUnit));
    SGuardedByWeakOwnerSlot* cursor = guardedByList.mSlots.begin;
    while (cursor != guardedByList.mSlots.end && GuardedByOwnerSlotWord(*cursor) < targetSlotWord) {
      ++cursor;
    }

    if (cursor == guardedByList.mSlots.end || GuardedByOwnerSlotWord(*cursor) != targetSlotWord) {
      return false;
    }

    const std::size_t tailCount = static_cast<std::size_t>(guardedByList.mSlots.end - (cursor + 1));
    if (tailCount != 0u) {
      std::memmove(cursor, cursor + 1, tailCount * sizeof(SGuardedByWeakOwnerSlot));
    }
    --guardedByList.mSlots.end;
    return true;
  }

  void AddGuardedByOwner(SGuardedByRuntimeList& guardedByList, const Unit* const guardUnit)
  {
    if (guardUnit == nullptr) {
      return;
    }

    const SGuardedByWeakOwnerSlot targetSlot = EncodeGuardedByOwnerSlot(guardUnit);
    const std::uintptr_t targetSlotWord = GuardedByOwnerSlotWord(targetSlot);

    SGuardedByWeakOwnerSlot* insertPos = guardedByList.mSlots.begin;
    while (insertPos != guardedByList.mSlots.end && GuardedByOwnerSlotWord(*insertPos) < targetSlotWord) {
      ++insertPos;
    }

    if (insertPos != guardedByList.mSlots.end && GuardedByOwnerSlotWord(*insertPos) == targetSlotWord) {
      return;
    }

    gpg::FastVectorRuntimeInsertRange(
      guardedByList.mSlots,
      insertPos,
      &targetSlot,
      &targetSlot + 1
    );
  }

  void ClearGuardFormation(Unit* const unit)
  {
    if (unit == nullptr) {
      return;
    }

    IFormationInstance* const guardFormation = unit->GuardFormation;
    unit->GuardFormation = nullptr;
    if (guardFormation != nullptr) {
      guardFormation->operator_delete(1);
    }
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

  [[nodiscard]] CEconomyEvent* EconomyEventFromNode(TDatListItem<void, void>* const node) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    auto* const rawNode = reinterpret_cast<std::uint8_t*>(node);
    return reinterpret_cast<CEconomyEvent*>(rawNode - offsetof(CEconomyEvent, mUnitEventNode));
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

  /**
   * The reflected reference is assembled from the userdata HEADER, not read out
   * of its payload. This fork carries the `gpg::RType*` in `Udata::len`, and the
   * value itself starts one header past the allocation, which is exactly what
   * `LuaPlus::LuaObject::GetUserData` (0x00907540) does:
   *
   *     lea edx, [ecx+10h]   ; mObj  = payload, laid out after the header
   *     mov ecx, [ecx+0Ch]   ; mType = Udata::len reinterpreted as RType*
   *
   * Reading `*(gpg::RRef*)lua_touserdata(...)` instead - as this helper used to -
   * takes the first eight payload bytes as if they were a reference. For a
   * `_c_object` slot those bytes are the `CScriptObject*` value followed by
   * whatever the allocator left, so every upcast failed and each caller reported
   * "Expected a game object" for a perfectly good object.
   */
  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    if (!userDataObject.IsUserData()) {
      return gpg::RRef{};
    }

    return userDataObject.GetUserData();
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

  /**
   * Address: 0x00593290 (FUN_00593290)
   *
   * What it does:
   * Resolves one army stat lane by name, synchronizes it as a float, and
   * applies one pointed float delta through `StatItem::AddFloat`.
   */
  std::int32_t AddArmyStatFloatByName(
    CArmyStats* const armyStats,
    float* const deltaValue,
    const char* const statPath
  )
  {
    CArmyStatItem* const statItem = armyStats->TraverseTables(statPath, true);
    statItem->SynchronizeAsFloat();
    return statItem->AddFloat(deltaValue);
  }

  [[nodiscard]] const ArmyBlueprintNameView* ToArmyBlueprintNameView(const RUnitBlueprint* const blueprint) noexcept
  {
    return reinterpret_cast<const ArmyBlueprintNameView*>(blueprint);
  }

  void IncrementArmyBlueprintFloatStat(
    CArmyStats* const armyStats,
    const char* const statPath,
    const RUnitBlueprint* const blueprint,
    const float delta
  )
  {
    if (armyStats == nullptr || statPath == nullptr || blueprint == nullptr) {
      return;
    }

    (void)armyStats->AddBlueprintStatDelta(statPath, ToArmyBlueprintNameView(blueprint), delta);
  }

  void IncrementArmyIntStatByName(CArmyStats* const armyStats, const char* const statPath)
  {
    if (armyStats == nullptr || statPath == nullptr) {
      return;
    }

    CArmyStatItem* const item = armyStats->GetItem(statPath);
    if (item == nullptr) {
      return;
    }

    item->SynchronizeAsInt();
    AddIntStatCounter(item, 1L);
  }

  [[nodiscard]] bool IsWithinPlayableRectOrNotCommander(const Unit& unit)
  {
    static const std::string kCommanderCategory = "COMMAND";
    if (!unit.Entity::IsInCategory(kCommanderCategory.c_str())) {
      return true;
    }

    const Sim* const sim = unit.SimulationRef;
    const STIMap* const mapData = (sim != nullptr) ? sim->mMapData : nullptr;
    if (mapData == nullptr) {
      return true;
    }

    const Wm3::Vec3f& position = unit.GetPosition();
    const gpg::Rect2i playableRect = mapData->mPlayableRect;
    return !(static_cast<float>(playableRect.x0) > position.x || static_cast<float>(playableRect.z0) > position.z ||
             position.x > static_cast<float>(playableRect.x1) || position.z > static_cast<float>(playableRect.z1));
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
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("Sim");
    return fallbackSet;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
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
   * Address: 0x00594850 (FUN_00594850, func_CastUnit)
   *
   * What it does:
   * Upcasts one reflected object lane to `Unit*` using cached `Unit` RTTI.
   */
  [[nodiscard]] Unit* UpcastUnitFromRef(const gpg::RRef& sourceRef)
  {
    const gpg::RRef unitRef = gpg::REF_UpcastPtr(sourceRef, CachedUnitRType());
    return static_cast<Unit*>(unitRef.mObj);
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

  /**
   * Address: 0x006D2490 (FUN_006D2490, func_CastUnitOpt)
   *
   * What it does:
   * Performs optional Lua `_c_object` to `Unit*` conversion: returns null for
   * missing/destroyed/non-unit payloads without raising Lua conversion errors.
   */
  [[nodiscard]] Unit* CastUnitOptionalFromLuaObject(const LuaPlus::LuaObject& unitObject)
  {
    const LuaPlus::LuaObject copiedObject(unitObject);
    CScriptObject** const scriptObjectSlot = SCR_FromLua_CScriptObject(copiedObject);
    if (!scriptObjectSlot) {
      return nullptr;
    }

    CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      return nullptr;
    }

    const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
    return UpcastUnitFromRef(sourceRef);
  }

  [[nodiscard]] Unit* ResolveUnitBridge(UserUnit* const userUnit) noexcept
  {
    return userUnit ? reinterpret_cast<Unit*>(static_cast<IUnit*>(userUnit)) : nullptr;
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

  /**
   * Address: 0x00736760 (FUN_00736760)
   *
   * What it does:
   * Advances one armor-multiplier map node cursor to the next in-order
   * sentinel-tree node and writes the advanced node back to the caller lane.
   */
  [[maybe_unused]] [[nodiscard]] SArmorMultiplierMapNode*
  AdvanceArmorMultiplierNodeCursor(SArmorMultiplierMapNode*& cursor) noexcept
  {
    if (IsArmorMapSentinel(cursor)) {
      return cursor;
    }

    SArmorMultiplierMapNode* rightNode = cursor->right;
    if (rightNode == nullptr) {
      cursor = nullptr;
      return cursor;
    }

    if (rightNode->isNil != 0u) {
      for (SArmorMultiplierMapNode* parent = cursor->parent; parent != nullptr && parent->isNil == 0u; parent = parent->parent)
      {
        if (cursor != parent->right) {
          cursor = parent;
          return cursor;
        }
        cursor = parent;
      }
      cursor = (cursor != nullptr) ? cursor->parent : nullptr;
      return cursor;
    }

    SArmorMultiplierMapNode* next = rightNode->left;
    while (next != nullptr && next->isNil == 0u) {
      rightNode = next;
      next = next->left;
    }

    cursor = rightNode;
    return cursor;
  }

  /**
   * Address: 0x00736320 (FUN_00736320)
   *
   * What it does:
   * Adapter lane that advances one armor-multiplier node cursor slot and
   * returns the slot pointer.
   */
  [[maybe_unused]] [[nodiscard]] SArmorMultiplierMapNode** AdvanceArmorMultiplierNodeCursorSlotAdapter(
    const std::uint32_t /*laneTag*/,
    SArmorMultiplierMapNode** const cursorSlot
  ) noexcept
  {
    (void)AdvanceArmorMultiplierNodeCursor(*cursorSlot);
    return cursorSlot;
  }

  /**
   * Address: 0x00736330 (FUN_00736330)
   *
   * What it does:
   * Copies one armor-multiplier cursor slot into `destinationCursorSlot`, then
   * advances the source slot to the next in-order node.
   */
  [[maybe_unused]] [[nodiscard]] SArmorMultiplierMapNode** CopyAndAdvanceArmorMultiplierNodeCursorSlot(
    SArmorMultiplierMapNode** const sourceCursorSlot,
    SArmorMultiplierMapNode** const destinationCursorSlot
  ) noexcept
  {
    *destinationCursorSlot = *sourceCursorSlot;
    (void)AdvanceArmorMultiplierNodeCursor(*sourceCursorSlot);
    return destinationCursorSlot;
  }

  [[nodiscard]] bool ArmorTypeNameLess(const msvc8::string& lhs, const std::string_view rhs) noexcept
  {
    return lhs.view() < rhs;
  }

  [[nodiscard]] bool ArmorTypeNameLess(const std::string_view lhs, const msvc8::string& rhs) noexcept
  {
    return lhs < rhs.view();
  }

  /**
   * Inlined block from FUN_006AEF60 (MSVC8 map tree erase helper).
   *
   * What it does:
   * Erases armor-multiplier map nodes in the same right/current/left order
   * used by the recovered map teardown lane.
   */
  void DestroyArmorMultiplierMapSubtree(
    SArmorMultiplierMapNode* node,
    const SArmorMultiplierMapNode* const head
  ) noexcept
  {
    while (!IsArmorMapSentinel(node) && node != head) {
      DestroyArmorMultiplierMapSubtree(node->right, head);
      SArmorMultiplierMapNode* const left = node->left;
      node->damageTypeName.tidy(true, 0u);
      ::operator delete(node);
      node = left;
    }
  }

  /**
   * Address: 0x006A5380 (FUN_006A5380, armor-multiplier map teardown)
   *
   * IDA signature:
   * int __usercall sub_6A5380@<eax>(std::map_string_float *a1@<eax>);
   *
   * What it does:
   * Destroys the `Unit::ArmorMultipliers` tree, releases its sentinel head
   * node, then clears the map head/count lanes.
   */
  [[nodiscard]] std::int32_t DestroyArmorMultiplierMapStorage(
    SArmorMultiplierMap& armorMap
  ) noexcept
  {
    SArmorMultiplierMapNode* const head = armorMap.head;
    if (head != nullptr) {
      DestroyArmorMultiplierMapSubtree(head->parent, head);
      ::operator delete(head);
    }

    armorMap.head = nullptr;
    armorMap.size = 0u;
    return 0;
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

  /**
   * Address: 0x006B01C0 (FUN_006B01C0)
   *
   * IDA signature:
   * struct_13 *__cdecl sub_6B01C0();
   *
   * What it does:
   * Allocates one 48-byte armor-multiplier map node through the legacy
   * 48-byte allocation lane, zeroes the RB-tree link triplet, and seeds
   * `color = black`, `isNil = 0`. Callers (`Unit::Unit`, `Unit::Unit(Sim*)`,
   * and the per-instance map sub-init lane) finish converting it into a
   * sentinel head by setting `isNil = 1` and self-linking the triplet.
   * Matches the MSVC8 `std::map<std::string,float>::_Buynode()` allocator
   * shape: only the binary-touched fields are written; the embedded string
   * key region is left uninitialized to mirror the binary, paired with
   * `::operator delete` teardown in `DestroyArmorMultiplierMapStorage`.
   */
  [[nodiscard]] SArmorMultiplierMapNode* AllocateArmorMultiplierMapNodeRaw() noexcept
  {
    auto* const node = static_cast<SArmorMultiplierMapNode*>(
      gpg::core::legacy::AllocateChecked48ByteLane(1u)
    );
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->color = kArmorMapColorBlack;
    node->isNil = 0u;
    return node;
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

  // RUnitBlueprintEconomyCategoryCache is a flat-field view of the same 0x28
  // BVSet payload that backs CategoryWordRangeView. Cross-check the binary
  // offsets via the canonical BVSet field path so the duplicate flat-view
  // type stays in lockstep with the canonical BVSet layout.
  static_assert(
    sizeof(RUnitBlueprintEconomyCategoryCache) == sizeof(CategoryWordRangeView),
    "RUnitBlueprintEconomyCategoryCache layout must match CategoryWordRangeView size"
  );
  static_assert(
    offsetof(RUnitBlueprintEconomyCategoryCache, RuntimeWord08)
      == offsetof(CategoryWordRangeView, mBits) + offsetof(BVIntSet, mFirstWordIndex),
    "RUnitBlueprintEconomyCategoryCache::RuntimeWord08 offset must match BVSet::mBits.mFirstWordIndex"
  );

  [[nodiscard]] const CategoryWordRangeView&
  AsCategoryWordRange(const RUnitBlueprintEconomyCategoryCache& categoryCache) noexcept
  {
    return reinterpret_cast<const CategoryWordRangeView&>(categoryCache);
  }

  [[nodiscard]] BVIntSet& AsCategoryWordBitset(CategoryWordRangeView& range) noexcept
  {
    return range.mBits;
  }

  [[nodiscard]] CategoryWordRangeView& UnitBuildRestrictionCategoryWords(Unit& unit) noexcept
  {
    auto& runtimeView = reinterpret_cast<UnitAttributesBuildRestrictionRuntimeView&>(unit.GetAttributes());
    return runtimeView.mBuildRestrictionCategorySet;
  }

  void ResetCategoryWordRange(CategoryWordRangeView& range) noexcept
  {
    range.mBits = BVIntSet{};
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

  [[nodiscard]] const Wm3::Vector3f& InvalidBombDropSolutionLane() noexcept
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
  [[nodiscard]] Wm3::Vector3f* ComputeBombDropAimPoint(
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

  [[nodiscard]] CollisionDBRect COORDS_OgridRectToCollisionRect(const gpg::Rect2i& ogridRect) noexcept
  {
    // Address: 0x004FCAA0 (FUN_004FCAA0)
    const std::int32_t xPos = std::clamp(ogridRect.x0 >> 2, 0, 0xFFFF);
    const std::int32_t zPos = std::clamp(ogridRect.z0 >> 2, 0, 0xFFFF);
    const std::int32_t xEnd = (ogridRect.x1 + 3) >> 2;
    const std::int32_t zEnd = (ogridRect.z1 + 3) >> 2;

    CollisionDBRect collisionRect{};
    collisionRect.mStartX = static_cast<std::uint16_t>(xPos);
    collisionRect.mStartZ = static_cast<std::uint16_t>(zPos);

    const std::int32_t maxXSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.mStartX);
    const std::int32_t maxZSpan = 0xFFFF - static_cast<std::int32_t>(collisionRect.mStartZ);
    const std::int32_t xSpan = std::clamp(xEnd - static_cast<std::int32_t>(collisionRect.mStartX), std::int32_t{1}, maxXSpan);
    const std::int32_t zSpan = std::clamp(zEnd - static_cast<std::int32_t>(collisionRect.mStartZ), std::int32_t{1}, maxZSpan);

    collisionRect.mWidth = static_cast<std::uint16_t>(xSpan);
    collisionRect.mHeight = static_cast<std::uint16_t>(zSpan);
    return collisionRect;
  }

  [[nodiscard]] bool IsCollisionRectEquivalentToZero(const gpg::Rect2i& ogridRect) noexcept
  {
    const gpg::Rect2i zeroRect{};
    const CollisionDBRect currentCollisionRect = COORDS_OgridRectToCollisionRect(ogridRect);
    const CollisionDBRect zeroCollisionRect = COORDS_OgridRectToCollisionRect(zeroRect);
    return !currentCollisionRect.NotEqual(zeroCollisionRect);
  }

  /**
   * Address: 0x006A4BF0 (FUN_006A4BF0)
   *
   * What it does:
   * Copies this unit's reserved O-grid rectangle bounds into one `Rect2i`.
   */
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

  /**
   * Address: 0x00565980 (FUN_00565980)
   *
   * What it does:
   * Returns the larger of the footprint X/Z side lengths.
   */
  [[nodiscard]] std::uint8_t FootprintMaxSide(const SFootprint& footprint) noexcept
  {
    return (footprint.mSizeX > footprint.mSizeZ) ? footprint.mSizeX : footprint.mSizeZ;
  }

  [[nodiscard]] bool IsMeleeCandidateCellNavigable(
    Unit& moveUnit,
    Unit* ignoreUnit,
    const SFootprint& moverFootprint,
    ELayer moveLayer,
    COGrid& ogrid,
    const STIMap& mapData,
    const SOCellPos& candidateCell
  );

  [[nodiscard]] bool ShouldTestPrepareMoveCellAgainstSkirt(
    const SOCellPos& candidateCell,
    const gpg::Rect2f& skirtRect
  ) noexcept
  {
    const float cellMinX = static_cast<float>(candidateCell.x);
    const float cellMinZ = static_cast<float>(candidateCell.z);
    const float cellMaxX = static_cast<float>(candidateCell.x + 1);
    const float cellMaxZ = static_cast<float>(candidateCell.z + 1);

    return skirtRect.x0 > cellMaxX || cellMinX > skirtRect.x1 || skirtRect.z0 > cellMaxZ || cellMinZ > skirtRect.z1 ||
      skirtRect.x1 <= skirtRect.x0 || skirtRect.z0 >= skirtRect.z1 || cellMaxX <= cellMinX || cellMinZ >= cellMaxZ;
  }

  [[nodiscard]] bool IsPrepareMoveCandidateValid(
    Unit& unit,
    const SFootprint& footprint,
    const ELayer moveLayer,
    const SOCellPos& cell,
    const Wm3::Vector3f& worldPos,
    const gpg::Rect2f& skirtRect,
    const bool useWholeMap
  )
  {
    Sim* const sim = unit.SimulationRef;
    if (sim == nullptr || sim->mMapData == nullptr || sim->mOGrid == nullptr) {
      return false;
    }

    if (!ShouldTestPrepareMoveCellAgainstSkirt(cell, skirtRect)) {
      return false;
    }

    const float border = static_cast<float>(FootprintMaxSide(footprint));
    if (!sim->mMapData->IsWithin(worldPos, border, useWholeMap)) {
      return false;
    }

    return IsMeleeCandidateCellNavigable(unit, nullptr, footprint, moveLayer, *sim->mOGrid, *sim->mMapData, cell);
  }

  [[nodiscard]] Wm3::Box3f BuildAxisAlignedCollisionProbe(
    const Wm3::Vec3f& center,
    const Wm3::Vec3f& extents
  ) noexcept
  {
    Wm3::Box3f probe{};
    probe.Center[0] = center.x;
    probe.Center[1] = center.y;
    probe.Center[2] = center.z;

    probe.Axis[0][0] = 1.0f;
    probe.Axis[0][1] = 0.0f;
    probe.Axis[0][2] = 0.0f;
    probe.Axis[1][0] = 0.0f;
    probe.Axis[1][1] = 1.0f;
    probe.Axis[1][2] = 0.0f;
    probe.Axis[2][0] = 0.0f;
    probe.Axis[2][1] = 0.0f;
    probe.Axis[2][2] = 1.0f;

    probe.Extent[0] = extents.x;
    probe.Extent[1] = extents.y;
    probe.Extent[2] = extents.z;
    return probe;
  }

  [[nodiscard]] bool IsMeleeCandidateCellNavigable(
    Unit& moveUnit,
    Unit* const ignoreUnit,
    const SFootprint& moverFootprint,
    const ELayer moveLayer,
    COGrid& ogrid,
    const STIMap& mapData,
    const SOCellPos& candidateCell
  )
  {
    EOccupancyCaps occupancyCaps = OCCUPY_MobileCheck(moverFootprint, mapData, candidateCell);
    if (moveLayer == LAYER_Water) {
      const std::uint8_t filteredCaps =
        static_cast<std::uint8_t>(occupancyCaps) & ~static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB);
      occupancyCaps = static_cast<EOccupancyCaps>(filteredCaps);
    }

    if (static_cast<std::uint8_t>(OCCUPY_FootprintFits(ogrid, candidateCell, moverFootprint, occupancyCaps)) == 0u) {
      return false;
    }

    const gpg::Rect2i ogridRect{
      static_cast<std::int32_t>(candidateCell.x),
      static_cast<std::int32_t>(candidateCell.z),
      static_cast<std::int32_t>(candidateCell.x) + static_cast<std::int32_t>(moverFootprint.mSizeX),
      static_cast<std::int32_t>(candidateCell.z) + static_cast<std::int32_t>(moverFootprint.mSizeZ),
    };

    if (!moveUnit.CanReserveOgridRect(ogridRect)) {
      return false;
    }

    SOCellPos moveCell = candidateCell;
    return COORDS_CanMoveAt(&moveCell, &ogrid, &moveUnit, true, ignoreUnit);
  }

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

} // namespace

/**
  * Alias of FUN_00593970 (non-canonical helper lane).
 *
 * What it does:
 * Public wrapper that mirrors the anonymous-namespace `GetUnitOptional`
 * helper: non-throwing conversion from Lua payload to `Unit*`, returning
 * null when the payload is missing or of a non-unit runtime type.
 */
moho::Unit* moho::SCR_GetUnitOptional(const LuaPlus::LuaObject& unitObject)
{
  static gpg::RType* sUnitType = nullptr;
  if (sUnitType == nullptr) {
    sUnitType = gpg::LookupRType(typeid(Unit));
  }

  CScriptObject* const scriptObject = SCR_GetScriptObjectFromLuaObject(unitObject);
  if (scriptObject == nullptr) {
    return nullptr;
  }

  const gpg::RRef sourceRef = scriptObject->GetDerivedObjectRef();
  const gpg::RRef unitRef = gpg::REF_UpcastPtr(sourceRef, sUnitType);
  return static_cast<Unit*>(unitRef.mObj);
}

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
 * Address: 0x0067F080 (FUN_0067F080, func_GetUnitFactory)
 *
 * What it does:
 * Returns cached `Unit` metatable object from Lua object-factory storage.
 */
LuaPlus::LuaObject* moho::func_GetUnitFactory(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
{
  if (object == nullptr) {
    return nullptr;
  }

  *object = moho::CScrLuaMetatableFactory<moho::Unit>::Instance().Get(state);
  return object;
}

namespace
{
  /**
   * Address: 0x00564970 (FUN_00564970, func_StringLinkedListCpyRange)
   *
   * What it does:
   * Clones one legacy MSVC8 string list into another, preserving the original
   * element order and producing a fresh destination list.
   */
  void CopyStringListRange(msvc8::list<msvc8::string>& destination, const msvc8::list<msvc8::string>& source)
  {
    destination = source;
  }
} // namespace

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

  msvc8::list<msvc8::string> copiedDefinitions{};
  CopyStringListRange(copiedDefinitions, definitions);
  return copiedDefinitions;
}

/**
 * Address: 0x006C3A10 (FUN_006C3A10)
 *
 * What it does:
 * Stores one stunned-state tick lane.
 */
void Unit::SetStunnedStateRaw(const std::int32_t stunnedState) noexcept
{
  StunnedState = stunnedState;
}

/**
 * Address: 0x006C3A20 (FUN_006C3A20)
 *
 * What it does:
 * Stores one overcharge-paused boolean lane.
 */
void Unit::SetOverchargePausedFlag(const bool paused) noexcept
{
  OverchargePaused = paused;
}

/**
 * Address: 0x006C3A30 (FUN_006C3A30)
 *
 * What it does:
 * Returns the overcharge-paused boolean lane.
 */
bool Unit::IsOverchargePausedFlag() const noexcept
{
  return OverchargePaused;
}

/**
 * Address: 0x006C3A40 (FUN_006C3A40)
 *
 * What it does:
 * Returns the consumption-active boolean lane.
 */
bool Unit::IsConsumptionActiveFlag() const noexcept
{
  return ConsumptionActive;
}

/**
 * Address: 0x006C3A50 (FUN_006C3A50)
 *
 * What it does:
 * Returns the valid-target boolean lane.
 */
bool Unit::IsValidTargetFlag() const noexcept
{
  return IsValidTarget;
}

/**
 * Address: 0x006C3A60 (FUN_006C3A60)
 *
 * What it does:
 * Stores one valid-target boolean lane.
 */
void Unit::SetIsValidTargetFlag(const bool validTarget) noexcept
{
  IsValidTarget = validTarget;
}

/**
 * Address: 0x006C3A70 (FUN_006C3A70)
 *
 * What it does:
 * Returns the shield-ratio float lane.
 */
float Unit::GetShieldRatioRaw() const noexcept
{
  return ShieldRatio;
}

/**
 * Address: 0x006C3A80 (FUN_006C3A80)
 *
 * What it does:
 * Stores one shield-ratio float lane.
 */
void Unit::SetShieldRatioRaw(const float shieldRatio) noexcept
{
  ShieldRatio = shieldRatio;
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
 * Address: 0x006C39F0 (FUN_006C39F0)
 *
 * What it does:
 * Rebinds this unit's creator weak-reference lane and marks game-data sync
 * dirty for replication.
 */
void moho::AssignCreatorWeakRefAndMarkSyncDirty(Unit* const unit, Unit* const creator)
{
  unit->CreatorRef.AsWeakPtr<Unit>().Set(creator);
  unit->NeedSyncGameData = true;
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
    AssignCreatorWeakRefAndMarkSyncDirty(unit, creator);
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

  const float armorMultiplier = unit->GetArmorMult(msvc8::string(damageTypeName));
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
      if (userUnit != nullptr && unit != nullptr && !unit->IsDead() && userUnit->mUnitVarDat.mIsPaused) {
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
        fireState = userUnit->mUnitVarDat.mFireState;
      } else if (fireState != userUnit->mUnitVarDat.mFireState) {
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

  Unit* const ferryBeacon = (unit != nullptr) ? unit->GetTransportFerryBeacon() : nullptr;
  if (ferryBeacon != nullptr) {
    LuaPlus::LuaObject ferryBeaconLuaObject = ferryBeacon->GetLuaObject();
    ferryBeaconLuaObject.PushStack(state);
    return 1;
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
 * Address: 0x006CDCB0 (FUN_006CDCB0, func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:HasMeleeSpaceAroundTarget(target)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitHasMeleeSpaceAroundTargetName,
    &moho::cfunc_UnitHasMeleeSpaceAroundTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitHasMeleeSpaceAroundTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CDD10 (FUN_006CDD10, cfunc_UnitHasMeleeSpaceAroundTargetL)
 *
 * IDA signature:
 * int __thiscall cfunc_UnitHasMeleeSpaceAroundTargetL(LuaPlus::LuaState *this);
 *
 * What it does:
 * Reads `(meleeUnit, target)`, computes the target footprint-origin cell, and
 * pushes whether the melee unit has adjacent melee space around the target
 * (large-target check for mobile multi-cell targets, otherwise the small-target
 * check). Returns the boolean to Lua.
 */
int moho::cfunc_UnitHasMeleeSpaceAroundTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitHasMeleeSpaceAroundTargetHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject meleeUnitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const meleeUnit = SCR_FromLua_Unit(meleeUnitObject);

  const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const target = SCR_FromLua_Unit(targetObject);

  const SFootprint& targetFootprint = target->GetFootprint();
  const Wm3::Vec3f& targetPosition = target->GetPosition();

  SOCellPos cell{};
  cell.x = static_cast<std::int16_t>(static_cast<int>(targetPosition.x - (targetFootprint.mSizeX * 0.5f)));
  cell.z = static_cast<std::int16_t>(static_cast<int>(targetPosition.z - (targetFootprint.mSizeZ * 0.5f)));

  bool useLargeTargetCheck = false;
  if (target->IsMobile()) {
    const SFootprint& mobileFootprint = target->GetFootprint();
    if (std::max<int>(mobileFootprint.mSizeX, mobileFootprint.mSizeZ) > 1) {
      useLargeTargetCheck = true;
    }
  }

  const bool hasMeleeSpace = useLargeTargetCheck
    ? meleeUnit->HasMeleeSpaceAroundLargeTarget(target, &cell, 1)
    : meleeUnit->HasMeleeSpaceAroundSmallTarget(target, &cell);

  lua_pushboolean(rawState, hasMeleeSpace ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CDC90 (FUN_006CDC90, cfunc_UnitHasMeleeSpaceAroundTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitHasMeleeSpaceAroundTargetL`.
 */
int moho::cfunc_UnitHasMeleeSpaceAroundTarget(lua_State* const luaContext)
{
  return cfunc_UnitHasMeleeSpaceAroundTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CDF50 (FUN_006CDF50, cfunc_UnitMeleeWarpAdjacentToTargetL)
 *
 * IDA signature:
 * int __thiscall cfunc_UnitMeleeWarpAdjacentToTargetL(LuaPlus::LuaState *this);
 *
 * What it does:
 * Reads `(meleeUnit, target)`, computes the target footprint-origin cell, and
 * asks the melee unit whether it has adjacent melee space around the target
 * (large-target check for mobile multi-cell targets, otherwise the small-target
 * check). When space exists, converts the (possibly adjusted) cell back to a
 * world position using the melee unit's footprint, orients the melee unit toward
 * the target, and warps it to that adjacent transform.
 */
int moho::cfunc_UnitMeleeWarpAdjacentToTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitMeleeWarpAdjacentToTargetHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject meleeUnitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const meleeUnit = SCR_FromLua_Unit(meleeUnitObject);

  const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const target = SCR_FromLua_Unit(targetObject);

  const SFootprint& targetFootprint = target->GetFootprint();
  const Wm3::Vec3f& targetPosition = target->GetPosition();

  SOCellPos cell{};
  cell.x = static_cast<std::int16_t>(static_cast<int>(targetPosition.x - (targetFootprint.mSizeX * 0.5f)));
  cell.z = static_cast<std::int16_t>(static_cast<int>(targetPosition.z - (targetFootprint.mSizeZ * 0.5f)));

  bool hasMeleeSpace = false;
  if (target->IsMobile()) {
    const SFootprint& mobileFootprint = target->GetFootprint();
    const int targetSize = std::max<int>(mobileFootprint.mSizeX, mobileFootprint.mSizeZ);
    if (targetSize > 1) {
      if (!meleeUnit->HasMeleeSpaceAroundLargeTarget(target, &cell, 1)) {
        return 0;
      }
      hasMeleeSpace = true;
    }
  }
  if (!hasMeleeSpace) {
    hasMeleeSpace = meleeUnit->HasMeleeSpaceAroundSmallTarget(target, &cell);
  }

  if (hasMeleeSpace) {
    const STIMap* const mapData = meleeUnit->SimulationRef->mMapData;
    const SFootprint& meleeFootprint = meleeUnit->GetFootprint();
    // The binary forwards the melee unit's footprint occupancy-cap byte as the
    // layer selector for the cell->world conversion (preserved 1:1).
    const Wm3::Vec3f worldPosition = COORDS_ToWorldPos(
      mapData,
      cell,
      static_cast<ELayer>(static_cast<std::uint8_t>(meleeFootprint.mOccupancyCaps)),
      meleeFootprint.mSizeX,
      meleeFootprint.mSizeZ
    );

    const Wm3::Vec3f& warpTargetPosition = target->GetPosition();
    Wm3::Vec3f facingDirection{
      warpTargetPosition.x - worldPosition.x,
      warpTargetPosition.y - worldPosition.y,
      warpTargetPosition.z - worldPosition.z,
    };
    Wm3::Vector3f::Normalize(&facingDirection);

    const Wm3::Quaternionf orientation = COORDS_Orient(facingDirection);
    const VTransform warpTransform(worldPosition, orientation);
    meleeUnit->Warp(warpTransform);
  }

  return 0;
}

/**
 * Address: 0x006CDED0 (FUN_006CDED0, cfunc_UnitMeleeWarpAdjacentToTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitMeleeWarpAdjacentToTargetL`.
 */
int moho::cfunc_UnitMeleeWarpAdjacentToTarget(lua_State* const luaContext)
{
  return cfunc_UnitMeleeWarpAdjacentToTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CDEF0 (FUN_006CDEF0, func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:MeleeWarpAdjacentToTarget(target)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kUnitMeleeWarpAdjacentToTargetName,
    &moho::cfunc_UnitMeleeWarpAdjacentToTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitMeleeWarpAdjacentToTargetHelpText
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
  const bool isIdle = (unit == nullptr) || unit->IsIdleState();

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
 * Address: 0x006D24F0 (FUN_006D24F0)
 *
 * What it does:
 * Atomically stores one primary stat-value lane and returns the previously
 * observed lane.
 */
std::int32_t StorePrimaryStatBitsAtomic(
  StatItem* const statItem,
  const std::int32_t* const newValueBits
) noexcept
{
#if defined(_WIN32)
  volatile long* const slot = reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits);
  for (;;) {
    const long observed = InterlockedCompareExchange(slot, 0L, 0L);
    const long exchanged = InterlockedCompareExchange(slot, static_cast<long>(*newValueBits), observed);
    if (exchanged == observed) {
      return static_cast<std::int32_t>(observed);
    }
  }
#else
  const std::int32_t previous = statItem->mPrimaryValueBits;
  statItem->mPrimaryValueBits = *newValueBits;
  return previous;
#endif
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

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject valueArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      valueArg.TypeError("integer");
    }

    const std::int32_t value = static_cast<std::int32_t>(lua_tonumber(rawState, 3));
    (void)StorePrimaryStatBitsAtomic(statItem, &value);
    return 0;
  }

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject valueArg(state, 3);
    const float value = static_cast<float>(valueArg.ToNumber());
    std::int32_t valueBits = 0;
    std::memcpy(&valueBits, &value, sizeof(valueBits));
    (void)StorePrimaryStatBitsAtomic(statItem, &valueBits);
    return 0;
  }

  const LuaPlus::LuaStackObject valueArg(state, 3);
  const char* const value = lua_tostring(rawState, 3);
  if (value == nullptr) {
    valueArg.TypeError("string");
  }

  const std::int32_t valueBits =
    static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(value != nullptr ? value : ""));
  (void)StorePrimaryStatBitsAtomic(statItem, &valueBits);
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
  unit->SetProductionActive(isActive);
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
  (void)EntityCategory::Add(&restrictionWords, categorySet);
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
  Unit* const destinationUnit = CastUnitOptionalFromLuaObject(destinationObject);

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
  const Wm3::Vec3f velocity = unit->GetVelocity();

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
  /**
   * Address: 0x00561C80 (FUN_00561C80, sub_561C80)
   *
   * What it does:
   * Copy-assigns one `fastvector_n<CmdId, 8>` command-id snapshot lane,
   * preserving element order while reusing existing storage when capacity
   * allows. The binary copies these as raw dword ranges (`>> 2` element count,
   * `*dst = *src` word copies), so this is a plain trivially-copyable lane copy.
   */
  void CopyUnitCommandSnapshotVector(
    gpg::fastvector_n<moho::CmdId, 8>& destination,
    const gpg::fastvector_n<moho::CmdId, 8>& source
  )
  {
    destination = source;
  }

  /**
   * Address: 0x006AB960 (FUN_006AB960, sub_6AB960)
   *
   * IDA signature:
   * unsigned int __usercall sub_6AB960@<eax>(
   *   gpg::fastvector_int* snapshot@<eax>,
   *   std::vector<WeakPtr<CUnitCommand>>* source@<ebx>);
   *
   * What it does:
   * Appends the `CmdId` of every live command in `source` (a weak-command
   * vector) onto the `snapshot` lane, in order. Each source slot is resolved
   * through its intrusive weak pointer; dead / cleared slots are skipped. The
   * caller has already reset `snapshot` to its inline storage, so this is the
   * pure append pass that rebuilds the per-sim command-id snapshot from the
   * owning queue's live commands (`command->mConstDat.cmd`).
   */
  void AppendLiveCommandIdsToSnapshot(
    gpg::fastvector_n<moho::CmdId, 8>& snapshot,
    const msvc8::vector<moho::WeakPtr<moho::CUnitCommand>>& source
  )
  {
    for (const moho::WeakPtr<moho::CUnitCommand>& commandWeakPtr : source) {
      const moho::CUnitCommand* const command = commandWeakPtr.GetObjectPtr();
      if (command == nullptr) {
        continue;
      }
      snapshot.push_back(command->mConstDat.cmd);
    }
  }

  /**
   * Instantiates `gpg::FastVectorRuntimeCopyAssign<T>` per element type. For
   * `SSTIUnitWeaponInfoSnapshot` (0x98 bytes) that emission is the copy-assign
   * body (FUN_00561D90), whose element-wise copy loop the binary emitted twice
   * as byte-identical ICF twins (FUN_0055E900) and (FUN_00562990), with the
   * uninitialised-copy lane at (FUN_00562470).
   */
  template <class T, std::size_t N>
  void CopyFastVectorN(gpg::fastvector_n<T, N>& destination, const gpg::fastvector_n<T, N>& source)
  {
    destination = source;
  }

  /**
   * Address: 0x005BF420 (FUN_005BF420)
   *
   * What it does:
   * Copies the `UnitAttributes` lanes touched by the binary helper used by
   * `SSTIUnitVariableData::AssignFrom` (intentionally excluding reserved tail
   * bytes and non-copied metadata lanes).
   */
  moho::UnitAttributes* CopyUnitAttributesSnapshot(
    moho::UnitAttributes* const destination,
    const moho::UnitAttributes* const source
  )
  {
    destination->blueprint = source->blueprint;
    destination->restrictionCategory.mUniverse = source->restrictionCategory.mUniverse;
    destination->restrictionCategory.mBits.mFirstWordIndex = source->restrictionCategory.mBits.mFirstWordIndex;

    destination->restrictionCategory.mBits.mWords = source->restrictionCategory.mBits.mWords;

    destination->spawnElevationOffset = source->spawnElevationOffset;
    destination->moveSpeedMult = source->moveSpeedMult;
    destination->accelerationMult = source->accelerationMult;
    destination->turnMult = source->turnMult;
    destination->breakOffTriggerMult = source->breakOffTriggerMult;
    destination->breakOffDistanceMult = source->breakOffDistanceMult;
    destination->consumptionPerSecondEnergy = source->consumptionPerSecondEnergy;
    destination->consumptionPerSecondMass = source->consumptionPerSecondMass;
    destination->productionPerSecondEnergy = source->productionPerSecondEnergy;
    destination->productionPerSecondMass = source->productionPerSecondMass;
    destination->buildRate = source->buildRate;
    destination->regenRate = source->regenRate;
    destination->commandCapsMask = source->commandCapsMask;
    destination->toggleCapsMask = source->toggleCapsMask;
    destination->mReclaimable = source->mReclaimable;
    destination->mCapturable = source->mCapturable;
    destination->unknown_006A = source->unknown_006A;
    destination->unknown_006B = source->unknown_006B;
    destination->unknown_006C = source->unknown_006C;
    return destination;
  }

  [[nodiscard]] gpg::RType* CachedELayerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(ELayer));
    }
    return cached;
  }

  // Lazy reflected-type caches used by SSTIUnitVariableData::MemberDeserialize.
  // Mirror the binary's `if (!X::sType) X::sType = gpg::LookupRType(&X RTTI)`
  // idiom at FUN_0055E030; typeid(T) resolves to the same ??_R0 descriptor the
  // binary passes to LookupRType.
  [[nodiscard]] gpg::RType* CachedEntIdType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(EntId));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SEconValue));
    }
    return cached;
  }

  // Write-side reflected-enum caches used by SSTIUnitVariableData::MemberSerialize.
  // The binary's FUN_0055E420 streams mJobType/mFireState through the reflected
  // Moho::EJobType / Moho::EFireState RTypes; each enum's PrimitiveSerHelper
  // (FUN_0055D390 / FUN_0055D400) bottoms out in a single WriteInt of the value,
  // so the reflected Write is stream-symmetric with MemberDeserialize's ReadInt.
  [[nodiscard]] gpg::RType* CachedEJobTypeType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(EJobType));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEFireStateType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(EFireState));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedUnitAttributesType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(UnitAttributes));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedUnitWeaponInfoVectorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SSTIUnitWeaponInfoVector));
    }
    return cached;
  }

  // Re-expresses the binary's inline shared-pointer load (which passes the
  // shared_ptr storage straight to gpg::ReadArchive::ReadPointerShared_CAniPose)
  // through the SharedPtrRaw view, matching SSTIEntityVariableData.cpp's
  // ReadSharedRScmResourcePointer wrapper.
  void ReadSharedCAniPosePointer(
    boost::shared_ptr<moho::CAniPose>& outPointer,
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef
  )
  {
    static_assert(
      sizeof(boost::shared_ptr<moho::CAniPose>) == sizeof(boost::SharedPtrRaw<moho::CAniPose>),
      "boost::shared_ptr<CAniPose> must match legacy raw shared-pointer layout"
    );

    auto& rawPointer = *reinterpret_cast<boost::SharedPtrRaw<moho::CAniPose>*>(&outPointer);
    gpg::ReadPointerShared_CAniPose(rawPointer, archive, ownerRef);
  }

  class UnitWeaponInfoTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "UnitWeaponInfo";
    }

    void Init() override
    {
      size_ = sizeof(moho::UnitWeaponInfo);
      gpg::RType::Init();
      Finish();
    }
  };

  class SSTIUnitVariableDataTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTIUnitVariableData";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTIUnitVariableData);
      gpg::RType::Init();
      Finish();
    }
  };

  // The binary global is 0x14 bytes (vtable + mNext/mPrev + load/save
  // callback lanes, matching every other SerHelperBase-derived serializer in
  // this codebase); `gpg::SerSaveLoadHelperListRuntime` only models the
  // leading 0x0C-byte intrusive-list header shared by all of them.
  struct UnitWeaponInfoSerializerHelperNode
  {
    gpg::SerSaveLoadHelperListRuntime mListLinks{};
    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(
    offsetof(UnitWeaponInfoSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "UnitWeaponInfoSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(UnitWeaponInfoSerializerHelperNode, mSerSaveFunc) == 0x10,
    "UnitWeaponInfoSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(UnitWeaponInfoSerializerHelperNode) == 0x14,
    "UnitWeaponInfoSerializerHelperNode size must be 0x14"
  );

  UnitWeaponInfoSerializerHelperNode gUnitWeaponInfoSerializer{};

  // Runtime shape of the binary's `SerSaveLoadHelper<SSTIUnitVariableData>`
  // static-init global: the 0x0C intrusive-list links followed by the two
  // published reflection callbacks (load @ +0x0C, save @ +0x10). The engine
  // install path copies mSerLoadFunc / mSerSaveFunc into the reflection
  // descriptor's serLoadFunc_ / serSaveFunc_ slots.
  struct SSTIUnitVariableDataSerializerHelperNode
  {
    gpg::SerSaveLoadHelperListRuntime mListLinks{};
    gpg::RType::load_func_t mSerLoadFunc = nullptr;
    gpg::RType::save_func_t mSerSaveFunc = nullptr;
  };
  static_assert(
    offsetof(SSTIUnitVariableDataSerializerHelperNode, mSerLoadFunc) == 0x0C,
    "SSTIUnitVariableDataSerializerHelperNode::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SSTIUnitVariableDataSerializerHelperNode, mSerSaveFunc) == 0x10,
    "SSTIUnitVariableDataSerializerHelperNode::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(SSTIUnitVariableDataSerializerHelperNode) == 0x14,
    "SSTIUnitVariableDataSerializerHelperNode size must be 0x14"
  );

  SSTIUnitVariableDataSerializerHelperNode gSSTIUnitVariableDataSerializer{};

  /**
   * Address: 0x0055C1B0 (FUN_0055C1B0, SerSaveLoadHelper<UnitWeaponInfo>::unlink lane A)
   *
   * What it does:
   * Unlinks `UnitWeaponInfo` serializer helper links and restores self-links
   * for intrusive-list sentinel state.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkUnitWeaponInfoSerializerLaneA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gUnitWeaponInfoSerializer.mListLinks);
  }

  /**
   * Address: 0x0055C1E0 (FUN_0055C1E0, SerSaveLoadHelper<UnitWeaponInfo>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the `UnitWeaponInfo` serializer
   * helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkUnitWeaponInfoSerializerLaneB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gUnitWeaponInfoSerializer.mListLinks);
  }

  /**
   * Address: 0x0055C160 (FUN_0055C160, Moho::UnitWeaponInfoSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `UnitWeaponInfo`. Forwards the
   * reflected object pointer to `UnitWeaponInfo::MemberDeserialize`; `version`
   * and the owner-ref lane are unused by the member (mirrors the binary tail
   * call).
   */
  void DeserializeUnitWeaponInfoSerializerCallback(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const info = reinterpret_cast<moho::UnitWeaponInfo*>(objectPtr);
    if (info == nullptr) {
      return;
    }
    info->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0055C170 (FUN_0055C170, Moho::UnitWeaponInfoSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `UnitWeaponInfo`. Forwards the
   * reflected object pointer to `UnitWeaponInfo::MemberSerialize`; `version`
   * and the owner-ref lane are unused by the member (mirrors the binary tail
   * call).
   */
  void SerializeUnitWeaponInfoSerializerCallback(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const info = reinterpret_cast<moho::UnitWeaponInfo*>(objectPtr);
    if (info == nullptr) {
      return;
    }
    info->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BF5300 (FUN_00BF5300, Moho::UnitWeaponInfoSerializer::~UnitWeaponInfoSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the `UnitWeaponInfo` serializer helper
   * node, matching the sibling unlink lanes used across other serializer
   * registrars.
   */
  void cleanup_UnitWeaponInfoSerializer_atexit()
  {
    (void)UnlinkUnitWeaponInfoSerializerLaneA();
  }

  /**
   * Address: 0x00BCA580 (FUN_00BCA580, register_UnitWeaponInfoSerializer)
   *
   * What it does:
   * Initializes the global `UnitWeaponInfo` serializer helper's load/save
   * callback lanes (self-linking the intrusive helper node) and installs
   * process-exit cleanup via `atexit`.
   */
  void register_UnitWeaponInfoSerializer()
  {
    (void)UnlinkUnitWeaponInfoSerializerLaneA();
    gUnitWeaponInfoSerializer.mSerLoadFunc = &DeserializeUnitWeaponInfoSerializerCallback;
    gUnitWeaponInfoSerializer.mSerSaveFunc = &SerializeUnitWeaponInfoSerializerCallback;
    (void)std::atexit(&cleanup_UnitWeaponInfoSerializer_atexit);
  }

  struct UnitWeaponInfoSerializerStartupBootstrap
  {
    UnitWeaponInfoSerializerStartupBootstrap()
    {
      (void)moho::preregister_UnitWeaponInfoTypeInfo();
      register_UnitWeaponInfoSerializer();
    }
  };

  [[maybe_unused]] UnitWeaponInfoSerializerStartupBootstrap gUnitWeaponInfoSerializerStartupBootstrap;

  /**
   * Address: 0x0055C7C0 (FUN_0055C7C0, SerSaveLoadHelper<SSTIUnitVariableData>::unlink lane A)
   *
   * What it does:
   * Unlinks `SSTIUnitVariableData` serializer helper links and restores
   * self-links for intrusive-list sentinel state.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkSSTIUnitVariableDataSerializerLaneA() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSSTIUnitVariableDataSerializer.mListLinks);
  }

  /**
   * Address: 0x0055C7F0 (FUN_0055C7F0, SerSaveLoadHelper<SSTIUnitVariableData>::unlink lane B)
   *
   * What it does:
   * Mirrors lane A unlink/self-link reset for the
   * `SSTIUnitVariableData` serializer helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSSTIUnitVariableDataSerializerLaneB() noexcept
  {
    return gpg::UnlinkSerSaveLoadHelperNode(gSSTIUnitVariableDataSerializer.mListLinks);
  }

  /**
   * Address: 0x0055C760 (FUN_0055C760, Moho::SSTIUnitVariableDataSerializer::Deserialize)
   *
   * IDA signature:
   * int sub_55C760(); // elided tail-jump: return sub_55E030();
   *
   * What it does:
   * Reflection load-callback facade for `SSTIUnitVariableData`. Forwards the
   * reflected object pointer to the class member load body; `version` and the
   * owner-ref lane are unused by the member (mirrors the binary tail-jump into
   * FUN_0055E030).
   */
  void SSTIUnitVariableDataSerializerDeserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const data = reinterpret_cast<moho::SSTIUnitVariableData*>(objectPtr);
    if (data == nullptr) {
      return;
    }
    data->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0055C770 (FUN_0055C770, Moho::SSTIUnitVariableDataSerializer::Serialize)
   *
   * IDA signature:
   * int sub_55C770(); // elided tail-jump: return sub_55E420();
   *
   * What it does:
   * Reflection save-callback facade for `SSTIUnitVariableData`. Forwards the
   * reflected object pointer to the class member save body; `version` and the
   * owner-ref lane are unused by the member (mirrors the binary tail-jump into
   * FUN_0055E420).
   */
  void SSTIUnitVariableDataSerializerSerialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const data = reinterpret_cast<moho::SSTIUnitVariableData*>(objectPtr);
    if (data == nullptr) {
      return;
    }
    data->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BF54B0 (FUN_00BF54B0, Moho::SSTIUnitVariableDataSerializer::~SSTIUnitVariableDataSerializer)
   *
   * What it does:
   * Process-exit teardown: unlinks the `SSTIUnitVariableData` serializer
   * helper node, matching the sibling unlink lanes used across other
   * serializer registrars.
   */
  void cleanup_SSTIUnitVariableDataSerializer_atexit()
  {
    (void)UnlinkSSTIUnitVariableDataSerializerLaneA();
  }

  /**
   * Address: 0x00BCA6A0 (FUN_00BCA6A0, register_SSTIUnitVariableDataSerializer)
   *
   * What it does:
   * Initializes the global `SSTIUnitVariableData` serializer helper's
   * load/save callback lanes (self-linking the intrusive helper node) and
   * installs process-exit cleanup via `atexit`. Binding both facades by name
   * here is the source-level invocation that keeps FUN_0055E030 /
   * FUN_0055E420 reachable.
   */
  void register_SSTIUnitVariableDataSerializer()
  {
    (void)UnlinkSSTIUnitVariableDataSerializerLaneA();
    gSSTIUnitVariableDataSerializer.mSerLoadFunc = &SSTIUnitVariableDataSerializerDeserialize;
    gSSTIUnitVariableDataSerializer.mSerSaveFunc = &SSTIUnitVariableDataSerializerSerialize;
    (void)std::atexit(&cleanup_SSTIUnitVariableDataSerializer_atexit);
  }

  /**
   * Static-init driver that publishes the load/save reflection callbacks for
   * `SSTIUnitVariableData`. The binary registers the equivalent helper via a
   * static-init-time `SerSaveLoadHelper<SSTIUnitVariableData>` global whose
   * ctor self-links the intrusive node and stores the two facade trampolines
   * (FUN_0055C760 / FUN_0055C770) into +0x0C / +0x10 -- that is exactly
   * `register_SSTIUnitVariableDataSerializer` (FUN_00BCA6A0), called below
   * rather than duplicated. The engine install path later copies those into
   * the reflection descriptor's serLoadFunc_ / serSaveFunc_.
   */
  struct SSTIUnitVariableDataSerializerRegistrar
  {
    SSTIUnitVariableDataSerializerRegistrar() noexcept
    {
      // Ensure the SSTIUnitVariableData reflection descriptor is pre-registered
      // before publishing callbacks; idempotent with gUnitTypeInfoPreRegisterBootstrap.
      (void)moho::preregister_SSTIUnitVariableDataTypeInfo();

      register_SSTIUnitVariableDataSerializer();
    }
  };

  [[maybe_unused]] const SSTIUnitVariableDataSerializerRegistrar gSSTIUnitVariableDataSerializerRegistrar{};
} // namespace

// Wrapped in `namespace moho` so the linker mangles these as
// `?preregister_*@moho@@YAPAVRType@gpg@@XZ`, matching the call sites that
// reference them as `moho::preregister_*`. Without the wrapper the file-scope
// versions exist but with no-namespace mangling, which the callers don't see.
namespace moho
{

/**
 * Address: 0x0055C020 (FUN_0055C020, preregister_UnitWeaponInfoTypeInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `UnitWeaponInfo`.
 */
gpg::RType* preregister_UnitWeaponInfoTypeInfo()
{
  static UnitWeaponInfoTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(UnitWeaponInfo), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x0055C620 (FUN_0055C620, preregister_SSTIUnitVariableDataTypeInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `SSTIUnitVariableData`.
 */
gpg::RType* preregister_SSTIUnitVariableDataTypeInfo()
{
  static SSTIUnitVariableDataTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(SSTIUnitVariableData), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x006CCE70 (FUN_006CCE70, cfunc_NotifyUpgradeL)
 *
 * IDA signature:
 * int __cdecl cfunc_NotifyUpgradeL(LuaPlus::LuaState* state);
 *
 * What it does:
 * Global Lua `NotifyUpgrade(from,to)` worker: transfers command queue, builder
 * commands, platoon membership, repeat-queue state, health ratio, and
 * guarded/guard links from the source unit to the destination unit during an
 * upgrade, and queues an allied-upgrade sync notification.
 */
int moho::cfunc_NotifyUpgradeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kNotifyUpgradeHelpText, 2, argumentCount);
  }

  Unit* source = nullptr;
  {
    const LuaPlus::LuaObject sourceObject(LuaPlus::LuaStackObject(state, 1));
    source = GetUnitOptional(sourceObject);
  }
  Unit* dest = nullptr;
  {
    const LuaPlus::LuaObject destObject(LuaPlus::LuaStackObject(state, 2));
    dest = GetUnitOptional(destObject);
  }

  if (source == nullptr || source->IsDead() || source->CommandQueue == nullptr) {
    LuaPlus::LuaState::Error(state, "Passed in invalid source object to upgrade");
  } else if (dest == nullptr || dest->IsDead() || dest->CommandQueue == nullptr) {
    LuaPlus::LuaState::Error(state, "Passed in invalid destination object to upgrade");
  }

  // 1) Command-queue transfer: copy every source command onto the destination,
  //    skipping the upgrade command that produced `dest`. The copied weak-ptr
  //    vector unlinks + frees on scope exit (matches the binary's manual cleanup).
  if (CUnitCommandQueue* const sourceQueue = source->CommandQueue) {
    const msvc8::vector<WeakPtr<CUnitCommand>> commandsSnapshot = sourceQueue->mCommandVec;
    const RUnitBlueprint* const destBlueprint = dest->GetBlueprint();
    for (const WeakPtr<CUnitCommand>& weakCommand : commandsSnapshot) {
      CUnitCommand* const command = weakCommand.GetObjectPtr();
      const bool isUpgradeToDest =
        command != nullptr &&
        command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_Upgrade &&
        command->mConstDat.blueprint == reinterpret_cast<const REntityBlueprint*>(destBlueprint);
      if (!isUpgradeToDest) {
        dest->CommandQueue->AddCommandToQueue(command);
      }
    }
  }

  // 2) Builder factory-command transfer.
  if (source->AiBuilder != nullptr && dest->AiBuilder != nullptr) {
    dest->AiBuilder->BuilderClearFactoryCommandQueue();
    const msvc8::vector<WeakPtr<CUnitCommand>>& builderCommands = source->AiBuilder->BuilderGetFactoryCommandQueue();
    for (std::size_t i = 0; i < builderCommands.size(); ++i) {
      CUnitCommand* const builderCommand = source->AiBuilder->BuilderGetFactoryCommand(static_cast<int>(i));
      if (builderCommand != nullptr) {
        dest->AiBuilder->BuilderAddFactoryCommand(builderCommand, -1);
      }
    }
  }

  // 3) Platoon membership transfer.
  if (CArmyImpl* const army = source->ArmyRef) {
    ESquadClass squadClass{};
    CPlatoon* const destPlatoon = army->GetPlatoonFor(reinterpret_cast<int>(dest), &squadClass);
    if (destPlatoon != nullptr) {
      destPlatoon->RemoveUnit(dest);
    }
    CPlatoon* const sourcePlatoon = army->GetPlatoonFor(reinterpret_cast<int>(source), &squadClass);
    if (sourcePlatoon != nullptr) {
      sourcePlatoon->RemoveUnit(source);
      sourcePlatoon->AppendUnitToSquad(squadClass, dest);
    }
  }

  // 4) Repeat-queue state transfer + OnStart/OnStopRepeatQueue script dispatch.
  const bool sourceRepeat = source->RepeatQueueEnabled;
  if (sourceRepeat) {
    if (!dest->RepeatQueueEnabled) {
      dest->RunScript("OnStartRepeatQueue");
    }
  } else if (dest->RepeatQueueEnabled) {
    dest->RunScript("OnStopRepeatQueue");
  }
  dest->RepeatQueueEnabled = sourceRepeat;
  dest->DirtySyncState = 1;

  // 5) Health ratio transfer.
  const float scaledHealth = dest->MaxHealth * (source->Health / source->MaxHealth);
  if (scaledHealth != dest->Health) {
    dest->SetHealth(scaledHealth);
  }

  // 6) Guarded-unit + guard-list transfer.
  dest->SetGuardedUnit(source->GuardedUnitRef.ResolveObjectPtr<Unit>());
  dest->GuardedPos = source->GuardedPos;

  // Snapshot the guard slots first: SetGuardedUnit mutates source->GuardedByList.
  const gpg::fastvector_runtime_view<SGuardedByWeakOwnerSlot> guardSlots = source->GuardedByList.mSlots;
  msvc8::vector<Unit*> guards;
  for (const SGuardedByWeakOwnerSlot* slot = guardSlots.begin; slot != guardSlots.end; ++slot) {
    guards.push_back(reinterpret_cast<Unit*>(DecodeGuardedByOwnerSlot(*slot)));
  }
  for (Unit* const guard : guards) {
    if (guard != nullptr) {
      guard->SetGuardedUnit(dest);
    }
  }

  // 7) Allied-upgrade notification: record (from,to) ids in the Sim sync lane.
  Sim* const globalUserdata = lua_getglobaluserdata_typed(rawState);
  if (dest->ArmyRef->IsAlly != 0 && globalUserdata != nullptr) {
    const SUpgradeNotifyPair pair{
      static_cast<std::int32_t>(source->GetEntityId()),
      static_cast<std::int32_t>(dest->GetEntityId())
    };
    // push_back's capacity-full path is `msvc8::vector<SUpgradeNotifyPair>::insert`
    // (FUN_006D1A90), reached through the binary's push_back (FUN_006D1960).
    globalUserdata->mAllyUpgradeNotifications.push_back(pair);
  }

  return 0;
}

/**
 * Address: 0x006CCDF0 (FUN_006CCDF0, cfunc_NotifyUpgrade)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to `cfunc_NotifyUpgradeL`.
 */
int moho::cfunc_NotifyUpgrade(lua_State* const luaContext)
{
  return cfunc_NotifyUpgradeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CCE10 (FUN_006CCE10, func_NotifyUpgrade_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `NotifyUpgrade(from,to)` Lua binder and links it into the
 * sim script init form set.
 */
void moho::func_NotifyUpgrade_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNotifyUpgradeName,
    &moho::cfunc_NotifyUpgrade,
    nullptr,
    kNotifyUpgradeGlobalClassName,
    kNotifyUpgradeHelpText
  );
  (void)binder;
}

/**
 * Address: 0x006D0080 (FUN_006D0080, cfunc_CreateUnit2L)
 *
 * IDA signature:
 * int __usercall cfunc_CreateUnit2L@<eax>(LuaPlus::LuaState* a1@<edi>);
 *
 * What it does:
 * Global Lua `CreateUnit2(blueprint, army, layer, x, z, heading)` worker. Validates
 * six arguments, resolves the unit blueprint from arg1, the owning army from the
 * 1-based index in arg2, and the movement layer from arg3. Positions the spawn at
 * (x, 0, z) with a yaw quaternion built from the heading (degrees), spawns the unit
 * through the sim, and pushes the created unit's script object back to Lua.
 */
int moho::cfunc_CreateUnit2L(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 6) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCreateUnit2HelpText, 6, argumentCount);
  }

  Sim* const sim = lua_getglobaluserdata_typed(rawState);

  // arg1: blueprint id (string) -> resolve blueprint.
  const LuaPlus::LuaStackObject blueprintArg(state, 1);
  const char* blueprintText = lua_tostring(rawState, 1);
  if (!blueprintText) {
    blueprintArg.TypeError("string");
    blueprintText = "";
  }
  RResId blueprintId{};
  gpg::STR_InitFilename(&blueprintId.name, blueprintText);
  const RUnitBlueprint* const blueprint = sim->mRules->GetUnitBlueprint(blueprintId);
  if (!blueprint) {
    LuaPlus::LuaState::Error(state, "Unknown unit blueprint id: %s", blueprintText);
  }

  // arg2: owning army, 1-based index into the sim army list.
  const LuaPlus::LuaStackObject armyArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    armyArg.TypeError("integer");
  }
  const int armyIndex = static_cast<int>(lua_tonumber(rawState, 2));
  const int armyCount = static_cast<int>(sim->mArmiesList.size());
  if (armyIndex < 1 || armyIndex > armyCount) {
    LuaPlus::LuaState::Error(state, "Invalid army index; must be >= 1 and < %d but got %d.", armyCount, armyIndex);
  }
  CArmyImpl* const army = sim->mArmiesList[armyIndex - 1];

  // arg3: movement layer (string).
  const LuaPlus::LuaStackObject layerArg(state, 3);
  const char* layerText = lua_tostring(rawState, 3);
  if (!layerText) {
    layerArg.TypeError("string");
    layerText = "";
  }
  const ELayer layer = COORDS_StringToLayer(layerText);

  // arg5 (z) is validated/read before arg4 (x), matching the binary's read order.
  const LuaPlus::LuaStackObject zArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    zArg.TypeError("number");
  }
  const float posZ = static_cast<float>(lua_tonumber(rawState, 5));

  const LuaPlus::LuaStackObject xArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    xArg.TypeError("number");
  }
  const float posX = static_cast<float>(lua_tonumber(rawState, 4));

  // arg6: heading in degrees -> half-angle yaw quaternion about the world Y axis.
  const LuaPlus::LuaStackObject headingArg(state, 6);
  if (lua_type(rawState, 6) != LUA_TNUMBER) {
    headingArg.TypeError("number");
  }
  const float halfAngle = static_cast<float>(lua_tonumber(rawState, 6) * 0.017453292 * 0.5);

  const VTransform transform(
    Wm3::Vector3f(posX, 0.0f, posZ),
    Wm3::Quatf(std::cos(halfAngle), 0.0f, std::sin(halfAngle), 0.0f)
  );

  // The binary sets the payload fields inline (an inlined SUnitConstructionParams
  // ctor) then forces mFixElevation = 0; the ctor call below yields the identical
  // final payload (mUseLayerOverride = 1 comes from the ctor, elevation is cleared).
  SUnitConstructionParams params(static_cast<std::int32_t>(layer), transform, army, blueprint, nullptr, true);
  params.mFixElevation = 0;

  Unit* const unit = sim->CreateUnitForScript(params, true);
  unit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006D0000 (FUN_006D0000, cfunc_CreateUnit2)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to `cfunc_CreateUnit2L`.
 */
int moho::cfunc_CreateUnit2(lua_State* const luaContext)
{
  return cfunc_CreateUnit2L(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0020 (FUN_006D0020, func_CreateUnit2_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `CreateUnit2(blueprint, army, layer, x, z, heading)` Lua
 * binder and links it into the sim script init form set.
 */
CScrLuaInitForm* moho::func_CreateUnit2_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCreateUnit2Name,
    &moho::cfunc_CreateUnit2,
    nullptr,
    kCreateUnit2GlobalClassName,
    kCreateUnit2HelpText
  );
  return &binder;
}

/**
 * Address: 0x006CF560 (FUN_006CF560, cfunc_CreateUnitL)
 *
 * IDA signature:
 * int __usercall cfunc_CreateUnitL@<eax>(LuaPlus::LuaState* a1@<edi>);
 *
 * What it does:
 * Global Lua `CreateUnit(blueprint, army, tx, ty, tz, qx, qy, qz, qw, [layer])`
 * worker. Validates 9-10 args, resolves the blueprint (arg1) and owning army
 * (arg2, 1-based). Reads the spawn position and orientation quaternion, rejects a
 * bit-zero quaternion (substituting identity + a warning), resolves the optional
 * layer string, spawns the unit through the sim, and pushes its script object.
 *
 * NOTE: the binary reads position args in swapped order — arg5->vec.x, arg4->vec.y,
 * arg3->vec.z — preserved here verbatim.
 */
int moho::cfunc_CreateUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 9 || argumentCount > 10) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected between %d and %d args, but got %d", kCreateUnitHelpText, 9, 10, argumentCount);
  }

  Sim* const sim = lua_getglobaluserdata_typed(rawState);
  lua_settop(rawState, 10);

  // arg1: blueprint id (string) -> resolve blueprint.
  const LuaPlus::LuaStackObject blueprintArg(state, 1);
  const char* blueprintText = lua_tostring(rawState, 1);
  if (!blueprintText) {
    blueprintArg.TypeError("string");
    blueprintText = "";
  }
  RResId blueprintId{};
  gpg::STR_InitFilename(&blueprintId.name, blueprintText);
  const RUnitBlueprint* const blueprint = sim->mRules->GetUnitBlueprint(blueprintId);
  if (!blueprint) {
    LuaPlus::LuaState::Error(state, "Unknown unit kind: %s", blueprintText);
  }

  // arg2: owning army, 1-based index into the sim army list.
  const LuaPlus::LuaStackObject armyArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    armyArg.TypeError("integer");
  }
  const int armyIndex = static_cast<int>(lua_tonumber(rawState, 2));
  const int armyCount = static_cast<int>(sim->mArmiesList.size());
  if (armyIndex < 1 || armyIndex > armyCount) {
    LuaPlus::LuaState::Error(state, "Invalid army index; must be >= 1 and < %d but got %d.", armyCount, armyIndex);
  }

  // Position: the binary reads args 5, 4, 3 into vec.x, vec.y, vec.z respectively.
  const LuaPlus::LuaStackObject vecXArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    vecXArg.TypeError("number");
  }
  const float vecX = static_cast<float>(lua_tonumber(rawState, 5));
  const LuaPlus::LuaStackObject vecYArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    vecYArg.TypeError("number");
  }
  const float vecY = static_cast<float>(lua_tonumber(rawState, 4));
  const LuaPlus::LuaStackObject vecZArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    vecZArg.TypeError("number");
  }
  const float vecZ = static_cast<float>(lua_tonumber(rawState, 3));

  // Orientation: the binary reads args 8, 7, 6 (qz, qy, qx) then 9 (qw).
  const LuaPlus::LuaStackObject quatZArg(state, 8);
  if (lua_type(rawState, 8) != LUA_TNUMBER) {
    quatZArg.TypeError("number");
  }
  const float quatZ = static_cast<float>(lua_tonumber(rawState, 8));
  const LuaPlus::LuaStackObject quatYArg(state, 7);
  if (lua_type(rawState, 7) != LUA_TNUMBER) {
    quatYArg.TypeError("number");
  }
  const float quatY = static_cast<float>(lua_tonumber(rawState, 7));
  const LuaPlus::LuaStackObject quatXArg(state, 6);
  if (lua_type(rawState, 6) != LUA_TNUMBER) {
    quatXArg.TypeError("number");
  }
  const float quatX = static_cast<float>(lua_tonumber(rawState, 6));
  const LuaPlus::LuaStackObject quatWArg(state, 9);
  if (lua_type(rawState, 9) != LUA_TNUMBER) {
    quatWArg.TypeError("number");
  }
  const float quatW = static_cast<float>(lua_tonumber(rawState, 9));

  Wm3::Quatf orient(quatW, quatX, quatY, quatZ); // (w, x, y, z)

  // A bit-zero quaternion is invalid; warn and substitute identity. Wm3::Quaternion::
  // Compare (FUN_004F0B40) is a raw 16-byte memcmp, so the rejection is bit-exact.
  static const Wm3::Quatf kZeroQuat(0.0f, 0.0f, 0.0f, 0.0f);
  if (std::memcmp(&orient, &kZeroQuat, sizeof(Wm3::Quatf)) == 0) {
    gpg::Warnf("Passed in an invalid quaternion when creating unit %s", blueprintText);
    orient = Wm3::Quatf(1.0f, 0.0f, 0.0f, 0.0f);
  }

  // Optional arg10: movement layer name (string). Absent -> layer 0.
  std::int32_t layer = 0;
  if (lua_type(rawState, 10) != 0 && lua_isstring(rawState, 10)) {
    const LuaPlus::LuaStackObject layerArg(state, 10);
    const char* layerText = lua_tostring(rawState, 10);
    if (!layerText) {
      layerArg.TypeError("string");
      layerText = "";
    }
    layer = static_cast<std::int32_t>(COORDS_StringToLayer(layerText));
  }

  CArmyImpl* const army = sim->mArmiesList[armyIndex - 1];

  const VTransform transform(Wm3::Vector3f(vecX, vecY, vecZ), orient);
  SUnitConstructionParams params(layer, transform, army, blueprint, nullptr, true);

  Unit* const unit = sim->CreateUnitForScript(params, true);
  if (!unit) {
    LuaPlus::LuaState::Error(state, "CreateUnit(%s) failed", blueprintText);
  }
  unit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006CF4E0 (FUN_006CF4E0, cfunc_CreateUnit)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to `cfunc_CreateUnitL`.
 */
int moho::cfunc_CreateUnit(lua_State* const luaContext)
{
  return cfunc_CreateUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CF500 (FUN_006CF500, func_CreateUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `CreateUnit(...)` Lua binder and links it into the sim
 * script init form set.
 */
CScrLuaInitForm* moho::func_CreateUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCreateUnitName,
    &moho::cfunc_CreateUnit,
    nullptr,
    kCreateUnitGlobalClassName,
    kCreateUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CFB70 (FUN_006CFB70, cfunc_CreateUnitHPRL)
 *
 * IDA signature:
 * int __usercall cfunc_CreateUnitHPRL@<eax>(LuaPlus::LuaState* state@<edi>);
 *
 * What it does:
 * Global Lua `CreateUnitHPR(blueprint, army, x, y, z, pitch, yaw, roll)` worker.
 * Validates exactly 8 args, resolves the blueprint (arg1) and owning army (arg2,
 * a Lua army object). Reads the spawn position (args 3,4,5 -> x,y,z) and the
 * heading/pitch/roll Euler angles (args 6,7,8), builds a row-major rotation matrix
 * and converts it to an orientation quaternion, spawns the unit through the sim,
 * and pushes its script object.
 */
int moho::cfunc_CreateUnitHPRL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 8) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCreateUnitHPRHelpText, 8, argumentCount);
  }

  Sim* const sim = lua_getglobaluserdata_typed(rawState);

  // arg1: blueprint id (string) -> kept as an msvc8::string for the lookup + errors.
  const LuaPlus::LuaStackObject blueprintArg(state, 1);
  const char* blueprintText = lua_tostring(rawState, 1);
  if (!blueprintText) {
    blueprintArg.TypeError("string");
    blueprintText = "";
  }
  const msvc8::string blueprintName(blueprintText, std::strlen(blueprintText));

  // arg2: owning army as a Lua object (not a 1-based index).
  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  // Position: args 5, 4, 3 read in that order -> x, y, z (straight, no swap).
  const LuaPlus::LuaStackObject posZArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    posZArg.TypeError("number");
  }
  const float posZ = static_cast<float>(lua_tonumber(rawState, 5));
  const LuaPlus::LuaStackObject posYArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    posYArg.TypeError("number");
  }
  const float posY = static_cast<float>(lua_tonumber(rawState, 4));
  const LuaPlus::LuaStackObject posXArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    posXArg.TypeError("number");
  }
  const float posX = static_cast<float>(lua_tonumber(rawState, 3));

  // Orientation Euler angles: arg6 -> pitch, arg7 -> heading/yaw, arg8 -> roll.
  const LuaPlus::LuaStackObject pitchArg(state, 6);
  if (lua_type(rawState, 6) != LUA_TNUMBER) {
    pitchArg.TypeError("number");
  }
  const float pitch = static_cast<float>(lua_tonumber(rawState, 6));
  const LuaPlus::LuaStackObject headingArg(state, 7);
  if (lua_type(rawState, 7) != LUA_TNUMBER) {
    headingArg.TypeError("number");
  }
  const float heading = static_cast<float>(lua_tonumber(rawState, 7));
  const LuaPlus::LuaStackObject rollArg(state, 8);
  if (lua_type(rawState, 8) != LUA_TNUMBER) {
    rollArg.TypeError("number");
  }
  const float roll = static_cast<float>(lua_tonumber(rawState, 8));

  // Blueprint lookup happens after all numeric args, matching the binary.
  RResId blueprintId{};
  gpg::STR_CopyFilename(&blueprintId.name, &blueprintName);
  const RUnitBlueprint* const blueprint = sim->mRules->GetUnitBlueprint(blueprintId);
  if (!blueprint) {
    LuaPlus::LuaState::Error(state, "Unknown unit type: %s", blueprintName.c_str());
  }

  // Euler HPR -> row-major 3x3 rotation matrix -> orientation quaternion.
  Wm3::Vector3f rotationRows[3];
  BuildRotationMatrixFromEulerHPR(rotationRows, heading, pitch, roll);
  Wm3::Quaternionf orient;
  MatrixRowsToQuatCanonical(rotationRows, &orient);

  const VTransform transform(Wm3::Vector3f(posX, posY, posZ), orient);
  SUnitConstructionParams params(0, transform, army, blueprint, nullptr, true);

  Unit* const unit = sim->CreateUnitForScript(params, true);
  if (!unit) {
    LuaPlus::LuaState::Error(state, "CreateUnitHPR(%s) failed", blueprintName.c_str());
  }
  unit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006CFAF0 (FUN_006CFAF0, cfunc_CreateUnitHPR)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to `cfunc_CreateUnitHPRL`.
 */
int moho::cfunc_CreateUnitHPR(lua_State* const luaContext)
{
  return cfunc_CreateUnitHPRL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CFB10 (FUN_006CFB10, func_CreateUnitHPR_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `CreateUnitHPR(...)` Lua binder and links it into the sim
 * script init form set.
 */
CScrLuaInitForm* moho::func_CreateUnitHPR_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kCreateUnitHPRName,
    &moho::cfunc_CreateUnitHPR,
    nullptr,
    kCreateUnitHPRGlobalClassName,
    kCreateUnitHPRHelpText
  );
  return &binder;
}

} // namespace moho

// Shared checked-allocator lane for 568-byte elements (defined in Vector.cpp,
// at file scope there); forward-declared locally the way this codebase's
// other cross-TU legacy container helpers already are.
void* AllocateChecked568ByteElements(std::uint32_t count);
[[noreturn]] void RuntimeThrowContainerTooLong(const char* message);

namespace
{
  struct UnitTypeInfoPreRegisterBootstrap
  {
    UnitTypeInfoPreRegisterBootstrap()
    {
      (void)moho::preregister_UnitWeaponInfoTypeInfo();
      (void)moho::preregister_SSTIUnitVariableDataTypeInfo();
    }
  };

  [[maybe_unused]] UnitTypeInfoPreRegisterBootstrap gUnitTypeInfoPreRegisterBootstrap;

  struct SSTIUnitVariableDataSlotRuntime
  {
    std::uint32_t mHeaderWord0 = 0;               // +0x00
    std::uint32_t mHeaderWord1 = 0;               // +0x04
    moho::SSTIUnitVariableData mVariableData{};   // +0x08
    std::uint32_t mTailWord0 = 0;                 // +0x230
  };

  static_assert(
    offsetof(SSTIUnitVariableDataSlotRuntime, mVariableData) == 0x08,
    "SSTIUnitVariableDataSlotRuntime::mVariableData offset must be 0x08"
  );
  static_assert(
    offsetof(SSTIUnitVariableDataSlotRuntime, mTailWord0) == 0x230,
    "SSTIUnitVariableDataSlotRuntime::mTailWord0 offset must be 0x230"
  );
  static_assert(sizeof(SSTIUnitVariableDataSlotRuntime) == 0x238, "SSTIUnitVariableDataSlotRuntime size must be 0x238");

  /**
   * Address: 0x005617C0 (FUN_005617C0)
   *
   * What it does:
   * Destroys one contiguous slot range by invoking `SSTIUnitVariableData`
   * destructor on each embedded payload lane at slot offset `+0x08`.
   */
  void DestroySSTIUnitVariableDataSlotPayloadRange(
    SSTIUnitVariableDataSlotRuntime* begin,
    SSTIUnitVariableDataSlotRuntime* const end
  )
  {
    while (begin != end) {
      begin->mVariableData.~SSTIUnitVariableData();
      ++begin;
    }
  }

  /**
   * Address: 0x005BDA80 (FUN_005BDA80)
   *
   * What it does:
   * Seeds one `SSTIUnitVariableData` slot header with the invalid-id sentinel
   * (`0xF0000000`) and default-constructs the payload lane at `+0x08`.
   */
  [[maybe_unused]] SSTIUnitVariableDataSlotRuntime* InitializeSSTIUnitVariableDataSlotHeaderAndPayload(
    SSTIUnitVariableDataSlotRuntime* const slot
  )
  {
    slot->mHeaderWord0 = 0xF0000000u;
    ::new (&slot->mVariableData) SSTIUnitVariableData();
    return slot;
  }

  /**
   * Address: 0x0055D980 (FUN_0055D980, copy_UnitWeaponInfo_range_with_rollback)
   *
   * What it does:
   * Copy-constructs one half-open `UnitWeaponInfo` range into destination
   * storage using the engine `UnitWeaponInfo(const UnitWeaponInfo&)` copy
   * constructor (`FUN_0055D6F0`), destroying already-constructed entries
   * before rethrowing if a copy step throws.
   */
  UnitWeaponInfo* CopyUnitWeaponInfoRangeWithRollback(
    const UnitWeaponInfo* const sourceBegin,
    const UnitWeaponInfo* const sourceEnd,
    UnitWeaponInfo* const destinationBegin
  )
  {
    if (sourceBegin == sourceEnd) {
      return destinationBegin;
    }

    if (sourceBegin == nullptr || sourceEnd == nullptr || destinationBegin == nullptr) {
      return destinationBegin;
    }

    UnitWeaponInfo* destinationCursor = destinationBegin;
    try {
      for (const UnitWeaponInfo* sourceCursor = sourceBegin;
           sourceCursor != sourceEnd;
           ++sourceCursor, ++destinationCursor) {
        ::new (destinationCursor) UnitWeaponInfo(*sourceCursor);
      }
      return destinationCursor;
    } catch (...) {
      while (destinationCursor != destinationBegin) {
        --destinationCursor;
        destinationCursor->~UnitWeaponInfo();
      }
      throw;
    }
  }

  /**
   * Address: 0x00563430 (FUN_00563430, copy_SSTIUnitVariableData_slot_range_with_rollback)
   * Address: 0x005CDF60 (FUN_005CDF60)
   *
   * What it does:
   * Copy-constructs one contiguous slot range (`header + SSTIUnitVariableData +
   * tail dword`) into destination storage and destroys already-constructed
   * payload lanes before rethrowing if a copy step throws.
   */
  SSTIUnitVariableDataSlotRuntime* CopySSTIUnitVariableDataSlotRangeWithRollback(
    const SSTIUnitVariableDataSlotRuntime* sourceBegin,
    const SSTIUnitVariableDataSlotRuntime* sourceEnd,
    SSTIUnitVariableDataSlotRuntime* destinationBegin
  )
  {
    SSTIUnitVariableDataSlotRuntime* destinationCursor = destinationBegin;
    try {
      for (const SSTIUnitVariableDataSlotRuntime* sourceCursor = sourceBegin;
           sourceCursor != sourceEnd;
           ++sourceCursor, ++destinationCursor) {
        if (destinationCursor != nullptr) {
          destinationCursor->mHeaderWord0 = sourceCursor->mHeaderWord0;
          ::new (&destinationCursor->mVariableData) SSTIUnitVariableData(sourceCursor->mVariableData);
          destinationCursor->mTailWord0 = sourceCursor->mTailWord0;
        }
      }
      return destinationCursor;
    } catch (...) {
      for (SSTIUnitVariableDataSlotRuntime* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->mVariableData.~SSTIUnitVariableData();
      }
      throw;
    }
  }

  /**
   * Address: 0x00562B70 (FUN_00562B70)
   *
   * What it does:
   * Primary adapter lane that forwards one contiguous
   * `SSTIUnitVariableData` slot-range copy into the canonical rollback helper.
   */
  [[maybe_unused]] void CopySSTIUnitVariableDataSlotRangeWithRollbackAdapterLaneA(
    SSTIUnitVariableDataSlotRuntime* const destinationBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTIUnitVariableDataSlotRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00563070 (FUN_00563070)
   *
   * What it does:
   * Secondary adapter lane that forwards one contiguous
   * `SSTIUnitVariableData` slot-range copy into the canonical rollback helper.
   */
  [[maybe_unused]] void CopySSTIUnitVariableDataSlotRangeWithRollbackAdapterLaneB(
    SSTIUnitVariableDataSlotRuntime* const destinationBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTIUnitVariableDataSlotRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x00563250 (FUN_00563250)
   *
   * What it does:
   * Tertiary adapter lane that forwards one contiguous
   * `SSTIUnitVariableData` slot-range copy into the canonical rollback helper.
   */
  [[maybe_unused]] void CopySSTIUnitVariableDataSlotRangeWithRollbackAdapterLaneC(
    SSTIUnitVariableDataSlotRuntime* const destinationBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceEnd
  )
  {
    (void)CopySSTIUnitVariableDataSlotRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x005CD1C0 (FUN_005CD1C0)
   * Address: 0x005CDA00 (FUN_005CDA00)
   *
   * What it does:
   * Source-first adapter lane for contiguous `SSTIUnitVariableData` slot
   * copy-construction with rollback.
   */
  [[maybe_unused]] SSTIUnitVariableDataSlotRuntime* CopySSTIUnitVariableDataSlotRangeWithRollbackSourceFirstAdapterLaneA(
    const SSTIUnitVariableDataSlotRuntime* const sourceBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceEnd,
    SSTIUnitVariableDataSlotRuntime* const destinationBegin
  )
  {
    return CopySSTIUnitVariableDataSlotRangeWithRollback(sourceBegin, sourceEnd, destinationBegin);
  }

  /**
   * Address: 0x005CBB20 (FUN_005CBB20, copy_SSTIUnitVariableData_slot_range_with_rollback_counted)
   *
   * What it does:
   * Copy-constructs one counted slot range (`header + SSTIUnitVariableData +
   * tail dword`) into destination storage and destroys already-constructed
   * payload lanes before rethrowing if a copy step throws.
   */
  SSTIUnitVariableDataSlotRuntime* CopySSTIUnitVariableDataSlotRangeWithRollbackCounted(
    const std::uint32_t count,
    SSTIUnitVariableDataSlotRuntime* const destinationBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceBegin
  )
  {
    if (count == 0u) {
      return destinationBegin;
    }

    if (destinationBegin == nullptr || sourceBegin == nullptr) {
      return destinationBegin;
    }

    SSTIUnitVariableDataSlotRuntime* destinationCursor = destinationBegin;
    try {
      for (std::uint32_t i = 0; i < count; ++i, ++destinationCursor) {
        const SSTIUnitVariableDataSlotRuntime* const sourceCursor = sourceBegin + i;
        destinationCursor->mHeaderWord0 = sourceCursor->mHeaderWord0;
        ::new (&destinationCursor->mVariableData) SSTIUnitVariableData(sourceCursor->mVariableData);
        destinationCursor->mTailWord0 = sourceCursor->mTailWord0;
      }
      return destinationCursor;
    } catch (...) {
      for (SSTIUnitVariableDataSlotRuntime* destroyCursor = destinationBegin;
           destroyCursor != destinationCursor;
           ++destroyCursor) {
        destroyCursor->mVariableData.~SSTIUnitVariableData();
      }
      throw;
    }
  }

  /**
   * Address: 0x005C9AD0 (FUN_005C9AD0)
   *
   * What it does:
   * Register-shape adapter that forwards counted
   * `SSTIUnitVariableData` slot copy-construction into the canonical helper.
   */
  [[maybe_unused]] void CopySSTIUnitVariableDataSlotRangeWithRollbackCountedAdapterLaneA(
    SSTIUnitVariableDataSlotRuntime* const destinationBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceBegin,
    const std::uint32_t count
  )
  {
    (void)CopySSTIUnitVariableDataSlotRangeWithRollbackCounted(count, destinationBegin, sourceBegin);
  }

  /**
   * Address: 0x00562680 (FUN_00562680)
   *
   * What it does:
   * Register-shape adapter for guarded contiguous
   * `SSTIUnitVariableData` slot copy-construction.
   */
  [[maybe_unused]] SSTIUnitVariableDataSlotRuntime* CopySSTIUnitVariableDataSlotRangeWithRollbackRegisterAdapter(
    const SSTIUnitVariableDataSlotRuntime* const sourceBegin,
    const SSTIUnitVariableDataSlotRuntime* const sourceEnd,
    SSTIUnitVariableDataSlotRuntime* const destinationBegin
  )
  {
    if (!sourceBegin || !sourceEnd || sourceEnd < sourceBegin) {
      return destinationBegin;
    }

    const std::uint32_t count = static_cast<std::uint32_t>(sourceEnd - sourceBegin);
    return CopySSTIUnitVariableDataSlotRangeWithRollbackCounted(count, destinationBegin, sourceBegin);
  }

  /**
   * Address: 0x005CD1F0 (FUN_005CD1F0)
   *
   * What it does:
   * Copy-assigns one contiguous `SSTIUnitVariableData` slot range in reverse
   * order and returns the beginning of the destination range.
   */
  SSTIUnitVariableDataSlotRuntime* CopyAssignSSTIUnitVariableDataSlotRangeReverse(
    SSTIUnitVariableDataSlotRuntime* destinationEnd,
    const SSTIUnitVariableDataSlotRuntime* sourceEnd,
    const SSTIUnitVariableDataSlotRuntime* sourceBegin
  )
  {
    const SSTIUnitVariableDataSlotRuntime* sourceCursor = sourceEnd;
    SSTIUnitVariableDataSlotRuntime* destinationCursor = destinationEnd;

    if (sourceBegin != sourceEnd) {
      do {
        --sourceCursor;
        --destinationCursor;
        destinationCursor->mHeaderWord0 = sourceCursor->mHeaderWord0;
        destinationCursor->mVariableData.AssignFrom(sourceCursor->mVariableData);
        destinationCursor->mTailWord0 = sourceCursor->mTailWord0;
      } while (sourceCursor != sourceBegin);
    }

    return destinationCursor;
  }

  /**
   * Address: 0x005CBDE0 (FUN_005CBDE0)
   *
   * What it does:
   * Copy-assigns one contiguous `SSTIUnitVariableData` slot range and returns
   * the advanced source cursor.
   */
  const SSTIUnitVariableDataSlotRuntime* CopyAssignSSTIUnitVariableDataSlotRange(
    SSTIUnitVariableDataSlotRuntime* destinationBegin,
    SSTIUnitVariableDataSlotRuntime* destinationEnd,
    const SSTIUnitVariableDataSlotRuntime* sourceBegin
  )
  {
    SSTIUnitVariableDataSlotRuntime* destinationCursor = destinationBegin;
    const SSTIUnitVariableDataSlotRuntime* sourceCursor = sourceBegin;

    while (destinationCursor != destinationEnd) {
      destinationCursor->mHeaderWord0 = sourceCursor->mHeaderWord0;
      destinationCursor->mVariableData.AssignFrom(sourceCursor->mVariableData);
      destinationCursor->mTailWord0 = sourceCursor->mTailWord0;
      ++destinationCursor;
      ++sourceCursor;
    }

    return sourceCursor;
  }

  /**
   * Address: 0x005C9E00 (FUN_005C9E00)
   *
   * What it does:
   * Register-shape adapter that forwards slot-range copy-assignment into the
   * canonical `FUN_005CBDE0` helper with source-first caller layout.
   */
  [[maybe_unused]] const SSTIUnitVariableDataSlotRuntime* CopyAssignSSTIUnitVariableDataSlotRangeAdapterLaneA(
    const SSTIUnitVariableDataSlotRuntime* const sourceBegin,
    SSTIUnitVariableDataSlotRuntime* const destinationBegin,
    SSTIUnitVariableDataSlotRuntime* const destinationEnd
  )
  {
    return CopyAssignSSTIUnitVariableDataSlotRange(destinationBegin, destinationEnd, sourceBegin);
  }

  /**
   * Address: 0x005C68E0 (FUN_005C68E0, sub_5C68E0)
   *
   * IDA signature:
   * void __thiscall sub_5C68E0(int this, _DWORD *arg0, int a1);
   * -- `this` is really the by-ref value being inserted (copied into locals
   * up front so reallocation can't invalidate it), `arg0` is the vector
   * storage (`{proxy@0, first@4, last@8, end@0xC}`), `a1` is the insert
   * position.
   *
   * What it does:
   * `msvc8::vector<SUnitVariableUpdateEntry>::_Insert_n(position, 1, value)`.
   * Throws `std::length_error` (via `sub_5617E0`) once size would exceed
   * `max_size() == 0xFFFFFFFF/568`. When capacity is insufficient, grows at
   * 1.5x (clamped to max_size, or `sub_561130(storage)+1` when that
   * undershoots the requirement), allocates through
   * `AllocateChecked568ByteElements` (FUN_005627E0), copy-constructs the
   * `[first,position)` prefix and `[position,last)` suffix through
   * `CopySSTIUnitVariableDataSlotRangeWithRollback` (FUN_005CDF60, reached
   * here both directly and via the `sub_5C9DD0` calling-convention
   * trampoline), fills the one-element gap through
   * `CopySSTIUnitVariableDataSlotRangeWithRollbackCounted` (FUN_005CBB20,
   * reached via the `sub_5C5220` adapter -- its DB note calling it a
   * "typed throw shim" is wrong, it forwards to FUN_005CBB20 with count=1),
   * then destroys and frees the old buffer. When capacity is already
   * sufficient: if `position == last` (pure append), constructs the value
   * directly at `last`; otherwise extends by copy-constructing the current
   * last element one slot past the old end
   * (`CopySSTIUnitVariableDataSlotRangeWithRollback`), copy-assigns the
   * `[position, oldLast-1)` run backward by one slot
   * (`CopyAssignSSTIUnitVariableDataSlotRangeReverse`, FUN_005CD1F0, via the
   * `sub_5C9E10` trampoline), then copy-assigns the value into the vacated
   * slot at `position` (`CopyAssignSSTIUnitVariableDataSlotRange`,
   * FUN_005CBDE0).
   */
  SSTIUnitVariableDataSlotRuntime* InsertOneSSTIUnitVariableDataSlot(
    msvc8::vector_runtime_view<SSTIUnitVariableDataSlotRuntime>& storage,
    SSTIUnitVariableDataSlotRuntime* const insertPosition,
    const SSTIUnitVariableDataSlotRuntime& value
  )
  {
    constexpr std::size_t kMaxElements = 0xFFFFFFFFu / sizeof(SSTIUnitVariableDataSlotRuntime);

    const std::size_t curSize = storage.begin != nullptr
      ? static_cast<std::size_t>(storage.end - storage.begin)
      : 0u;
    if (kMaxElements - curSize < 1u) {
      RuntimeThrowContainerTooLong("vector<T> too long");
    }

    const std::size_t capacity = storage.begin != nullptr
      ? static_cast<std::size_t>(storage.capacityEnd - storage.begin)
      : 0u;

    if (capacity < curSize + 1u) {
      // Reallocate: 1.5x growth, or exactly curSize+1 when that undershoots.
      std::size_t newCapacity = capacity + capacity / 2u;
      if (newCapacity < curSize + 1u) {
        newCapacity = curSize + 1u;
      }

      auto* const newFirst = static_cast<SSTIUnitVariableDataSlotRuntime*>(
        AllocateChecked568ByteElements(static_cast<std::uint32_t>(newCapacity))
      );

      SSTIUnitVariableDataSlotRuntime* const gapBegin =
        CopySSTIUnitVariableDataSlotRangeWithRollback(storage.begin, insertPosition, newFirst);
      SSTIUnitVariableDataSlotRuntime* const gapEnd =
        CopySSTIUnitVariableDataSlotRangeWithRollbackCounted(1u, gapBegin, &value);
      (void)CopySSTIUnitVariableDataSlotRangeWithRollback(insertPosition, storage.end, gapEnd);

      if (storage.begin != nullptr) {
        DestroySSTIUnitVariableDataSlotPayloadRange(storage.begin, storage.end);
        ::operator delete(storage.begin);
      }

      storage.begin = newFirst;
      storage.end = newFirst + curSize + 1u;
      storage.capacityEnd = newFirst + newCapacity;
      return insertPosition == nullptr ? storage.begin : (newFirst + (insertPosition - storage.begin));
    }

    // In-place: capacity already covers the extra element.
    if (insertPosition == storage.end) {
      (void)CopySSTIUnitVariableDataSlotRangeWithRollbackCounted(1u, storage.end, &value);
      ++storage.end;
      return insertPosition;
    }

    SSTIUnitVariableDataSlotRuntime* const oldLast = storage.end;
    (void)CopySSTIUnitVariableDataSlotRangeWithRollback(oldLast - 1, oldLast, oldLast);
    ++storage.end;
    (void)CopyAssignSSTIUnitVariableDataSlotRangeReverse(oldLast, oldLast - 1, insertPosition);
    (void)CopyAssignSSTIUnitVariableDataSlotRange(insertPosition, insertPosition + 1, &value);
    return insertPosition;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005C51B0 (FUN_005C51B0, sub_5C51B0)
   *
   * What it does:
   * Thin position-to-index-preserving wrapper around the `_Insert_n` core
   * (FUN_005C68E0): computes the insert position's element index before the
   * call (since reallocation can move `storage.begin`), then returns a
   * pointer rebased against the (possibly new) `begin`.
   */
  SUnitVariableUpdateEntry* InsertUnitVariableUpdateEntry(
    msvc8::vector<SUnitVariableUpdateEntry>& storage,
    SUnitVariableUpdateEntry* const insertPosition,
    const SUnitVariableUpdateEntry& value
  )
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    auto& slotView = reinterpret_cast<msvc8::vector_runtime_view<SSTIUnitVariableDataSlotRuntime>&>(view);
    const auto* const slotPosition = reinterpret_cast<const SSTIUnitVariableDataSlotRuntime*>(insertPosition);
    const auto& slotValue = reinterpret_cast<const SSTIUnitVariableDataSlotRuntime&>(value);

    SSTIUnitVariableDataSlotRuntime* const resultSlot = InsertOneSSTIUnitVariableDataSlot(
      slotView,
      const_cast<SSTIUnitVariableDataSlotRuntime*>(slotPosition),
      slotValue
    );
    return reinterpret_cast<SUnitVariableUpdateEntry*>(resultSlot);
  }
} // namespace moho

/**
 * Address: 0x0055B6E0 (FUN_0055B6E0, ??0UnitWeaponInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes both category bitset lanes to empty inline storage and seeds
 * default layer/radius/UI range visual-id values.
 */
UnitWeaponInfo::UnitWeaponInfo()
  : mCat1()
  , mCat2()
  , mLayer(LAYER_None)
  , mMinRadius(0.0f)
  , mMaxRadius(10000.0f)
  , mEffectiveRadius(0.0f)
  , mUIMinRangeVisualId()
  , mUIMaxRangeVisualId()
{
  mCat1.ResetToEmpty(EntityCategoryHelper{});
  mCat2.ResetToEmpty(EntityCategoryHelper{});
  mUIMinRangeVisualId.tidy(false, 0U);
  mUIMaxRangeVisualId.tidy(false, 0U);
}

/**
 * Address: 0x0055D170 (FUN_0055D170, ??1UnitWeaponInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Releases both UI visual-id strings and restores category bitset fastvector
 * lanes to their inline storage windows.
 */
UnitWeaponInfo::~UnitWeaponInfo()
{
  mUIMaxRangeVisualId.tidy(true, 0U);
  mUIMinRangeVisualId.tidy(true, 0U);
  mCat2.mBits.mWords.ResetStorageToInline();
  mCat1.mBits.mWords.ResetStorageToInline();
}

/**
 * Address: 0x0055D6F0 (FUN_0055D6F0, ??0UnitWeaponInfo@Moho@@QAE@ABU01@@Z)
 * Mangled: ??0UnitWeaponInfo@Moho@@QAE@ABU01@@Z
 *
 * IDA signature:
 * int __userpurge sub_55D6F0@<eax>(int source@<edi>, int destination);
 *
 * What it does:
 * Copy-constructs one `UnitWeaponInfo` from `other`. Each `EntityCategorySet`
 * lane is cloned field-wise (mUniverse + mBits.mFirstWordIndex header, then
 * the variable word list via `FastVectorN2RebindAndCopy`). Scalar layer/radius
 * lanes use plain assignment. Both UI range visual-id strings are brought up
 * to inline storage defaults (size 0, capacity 15) and then assigned from the
 * source strings.
 */
UnitWeaponInfo::UnitWeaponInfo(const UnitWeaponInfo& other)
  : mCat1()
  , mCat2()
  , mLayer(other.mLayer)
  , mMinRadius(other.mMinRadius)
  , mMaxRadius(other.mMaxRadius)
  , mEffectiveRadius(other.mEffectiveRadius)
  , mUIMinRangeVisualId()
  , mUIMaxRangeVisualId()
{
  // --- mCat1: BVSet copy (mUniverse + mBits.mFirstWordIndex + mBits.mWords) ---
  mCat1.mUniverse = other.mCat1.mUniverse;
  mCat1.mBits.mFirstWordIndex = other.mCat1.mBits.mFirstWordIndex;
  (void)gpg::FastVectorN2RebindAndCopy<unsigned int>(
    &mCat1.mBits.mWords, &other.mCat1.mBits.mWords
  );

  // --- mCat2: BVSet copy (mUniverse + mBits.mFirstWordIndex + mBits.mWords) ---
  mCat2.mUniverse = other.mCat2.mUniverse;
  mCat2.mBits.mFirstWordIndex = other.mCat2.mBits.mFirstWordIndex;
  (void)gpg::FastVectorN2RebindAndCopy<unsigned int>(
    &mCat2.mBits.mWords, &other.mCat2.mBits.mWords
  );

  // --- UI range visual-id strings: inline-default then assign from source. ---
  mUIMinRangeVisualId.tidy(false, 0U);
  mUIMinRangeVisualId.assign(other.mUIMinRangeVisualId, 0U, ~0U);
  mUIMaxRangeVisualId.tidy(false, 0U);
  mUIMaxRangeVisualId.assign(other.mUIMaxRangeVisualId, 0U, ~0U);
}

/**
 * Address: 0x0055F210 (FUN_0055F210, sub_55F210)
 *
 * IDA signature:
 * int __usercall sub_55F210@<eax>(int a1@<eax>, int a2@<esi>);
 *
 * What it does:
 * Copy-assigns one already-constructed `UnitWeaponInfo` over another. Each
 * category lane is updated header-first (`mUniverse`, then
 * `mBits.mFirstWordIndex`) and its word list copy-assigned through the
 * `gpg::fastvector_uint::cpy` lane; layer/radius values are plain stores; both
 * UI range visual-id strings are re-assigned from the source.
 *
 * Unlike the copy constructor this does NOT rebind the word lists to inline
 * storage first - the destination already owns whatever buffer it has, which is
 * why the binary calls the copy lane directly at 0x0055F225 / 0x0055F23D.
 */
UnitWeaponInfo& UnitWeaponInfo::operator=(const UnitWeaponInfo& other)
{
  // No self-assignment guard: the binary has none. Aliasing is absorbed by the
  // fastvector copy lane and by msvc8::string::assign.
  mCat1.mUniverse = other.mCat1.mUniverse;
  mCat1.mBits.mFirstWordIndex = other.mCat1.mBits.mFirstWordIndex;
  {
    mCat1.mBits.mWords = other.mCat1.mBits.mWords;
  }

  mCat2.mUniverse = other.mCat2.mUniverse;
  mCat2.mBits.mFirstWordIndex = other.mCat2.mBits.mFirstWordIndex;
  {
    mCat2.mBits.mWords = other.mCat2.mBits.mWords;
  }

  mLayer = other.mLayer;
  mMinRadius = other.mMinRadius;
  mMaxRadius = other.mMaxRadius;
  mEffectiveRadius = other.mEffectiveRadius;

  mUIMinRangeVisualId.assign(other.mUIMinRangeVisualId, 0U, ~0U);
  mUIMaxRangeVisualId.assign(other.mUIMaxRangeVisualId, 0U, ~0U);

  return *this;
}

/**
 * Address: 0x0055DA10 (FUN_0055DA10, Moho::UnitWeaponInfo::MemberDeserialize)
 *
 * What it does:
 * Loads category masks, layer/radius lanes, and both UI range visual-id
 * strings from one archive payload.
 */
void UnitWeaponInfo::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Read(CachedEntityCategorySetType(), &mCat1, ownerRef);
  archive->Read(CachedEntityCategorySetType(), &mCat2, ownerRef);
  archive->Read(CachedELayerType(), &mLayer, ownerRef);
  archive->ReadFloat(&mMinRadius);
  archive->ReadFloat(&mMaxRadius);
  archive->ReadFloat(&mEffectiveRadius);
  archive->ReadString(&mUIMinRangeVisualId);
  archive->ReadString(&mUIMaxRangeVisualId);
}

/**
 * Address: 0x0055DB00 (FUN_0055DB00, Moho::UnitWeaponInfo::MemberSerialize)
 *
 * What it does:
 * Stores category masks, layer/radius lanes, and both UI range visual-id
 * strings into one archive payload.
 */
void UnitWeaponInfo::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  archive->Write(CachedEntityCategorySetType(), &mCat1, ownerRef);
  archive->Write(CachedEntityCategorySetType(), &mCat2, ownerRef);
  archive->Write(CachedELayerType(), &mLayer, ownerRef);
  archive->WriteFloat(mMinRadius);
  archive->WriteFloat(mMaxRadius);
  archive->WriteFloat(mEffectiveRadius);
  archive->WriteString(const_cast<msvc8::string*>(&mUIMinRangeVisualId));
  archive->WriteString(const_cast<msvc8::string*>(&mUIMaxRangeVisualId));
}

/**
 * Address: 0x0055E030 (FUN_0055E030, Moho::SSTIUnitVariableData::MemberDeserialize)
 *
 * IDA signature:
 * int __usercall sub_55E030@<eax>(int this@<eax>, gpg::ReadArchive* archive@<esi>);
 *
 * What it does:
 * Loads the full reflected unit variable-data payload from one archive in the
 * serializer's field order. mCommands/mBuildQueue (+0x98/+0xC8) are runtime
 * command queues and are deliberately not serialized (the binary skips them).
 */
void SSTIUnitVariableData::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};

  archive->Read(CachedEntIdType(), &mCreator, ownerRef);
  archive->ReadInt(&mCreationTick);
  archive->ReadBool(&mAutoMode);
  archive->ReadBool(&mAutoSurfaceMode);
  archive->ReadBool(&mIsBusy);
  archive->ReadFloat(&mFuelRatio);
  archive->ReadFloat(&mShieldRatio);
  archive->ReadInt(&mStunTicks);
  archive->ReadBool(&mIsPaused);
  archive->ReadBool(&mIsValidTarget);
  archive->ReadBool(&mRepeatQueue);
  // Binary reads mJobType/mFireState via the reflected Moho::EJobType /
  // Moho::EFireState enum RTypes; those enums are not modeled in the SDK, and
  // for a 4-byte enum-storage lane the reflected read is byte-identical to a
  // plain 32-bit read, so ReadInt preserves the exact stream behavior.
  archive->ReadInt(&mJobType);
  archive->ReadInt(&mFireState);
  archive->ReadFloat(&mWorkProgress);

  // Binary emits a 2-iteration, stride-4 interleaved loop over the tactical/
  // nuke silo-count pairs (base +0x30, reads cursor-8 / cursor / cursor+8 each
  // iteration). That yields the exact stream order below.
  archive->ReadInt(&mTacticalSiloBuildCount);
  archive->ReadInt(&mTacticalSiloStorageCount);
  archive->ReadInt(&mTacticalSiloMaxStorageCount);
  archive->ReadInt(&mNukeSiloBuildCount);
  archive->ReadInt(&mNukeSiloStorageCount);
  archive->ReadInt(&mNukeSiloMaxStorageCount);

  archive->Read(CachedEntIdType(), &mSelectionInheritorId, ownerRef);
  archive->ReadString(&mCustomName);

  archive->Read(CachedSEconValueType(), &mProduced, ownerRef);
  archive->Read(CachedSEconValueType(), &mResourcesSpent, ownerRef);
  archive->Read(CachedSEconValueType(), &mMaintainenceCost, ownerRef);

  archive->Read(CachedEntIdType(), &mFocusUnit, ownerRef);
  archive->Read(CachedEntIdType(), &mGuardedUnit, ownerRef);
  archive->Read(CachedEntIdType(), &mTargetBlip, ownerRef);

  ReadSharedCAniPosePointer(mPriorSharedPose, archive, ownerRef);
  ReadSharedCAniPosePointer(mSharedPose, archive, ownerRef);

  archive->Read(CachedUnitWeaponInfoVectorType(), &mWeaponInfo, ownerRef);
  archive->Read(CachedUnitAttributesType(), &mAttributes, ownerRef);

  archive->ReadInt(reinterpret_cast<int*>(&mScriptbits));
  archive->ReadInt64(reinterpret_cast<__int64*>(&mUnitStates));
  archive->ReadBool(&mDidRefresh);
  archive->ReadBool(&mOverchargePaused);
}

/**
 * Address: 0x0055E420 (FUN_0055E420, Moho::SSTIUnitVariableData::MemberSerialize)
 *
 * IDA signature:
 * void __usercall sub_55E420(SSTIUnitVariableData* this@<edi>, gpg::WriteArchive* archive@<esi>);
 *
 * What it does:
 * Write mirror of MemberDeserialize (FUN_0055E030). Emits the full reflected
 * unit variable-data payload into one archive, field-for-field and in the same
 * order the deserializer reads. The two shared animation poses are written as
 * SHARED tracked raw pointers via gpg::RRef_CAniPose; mCommands/mBuildQueue
 * (+0x98/+0xC8) are runtime command queues the binary deliberately skips.
 */
void SSTIUnitVariableData::MemberSerialize(gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};

  archive->Write(CachedEntIdType(), &mCreator, ownerRef);
  archive->WriteInt(mCreationTick);
  archive->WriteBool(mAutoMode);
  archive->WriteBool(mAutoSurfaceMode);
  archive->WriteBool(mIsBusy);
  archive->WriteFloat(mFuelRatio);
  archive->WriteFloat(mShieldRatio);
  archive->WriteInt(mStunTicks);
  archive->WriteBool(mIsPaused);
  archive->WriteBool(mIsValidTarget);
  archive->WriteBool(mRepeatQueue);
  // Binary writes mJobType/mFireState through the reflected Moho::EJobType /
  // Moho::EFireState enum RTypes; those enums are not modeled in the SDK, and
  // for a 4-byte enum-storage lane the reflected write is byte-identical to a
  // plain 32-bit write, so WriteInt preserves the exact stream behavior.
  archive->Write(CachedEJobTypeType(), &mJobType, ownerRef);
  archive->Write(CachedEFireStateType(), &mFireState, ownerRef);
  archive->WriteFloat(mWorkProgress);

  // Binary emits a 2-iteration, stride-4 interleaved loop over the tactical/
  // nuke silo-count pairs (cursor base +0x30 = mTacticalSiloStorageCount,
  // writes cursor-8 / cursor / cursor+8 each iteration, then cursor += 4).
  // That yields the exact stream order below (Build/Storage/Max for tactical,
  // then the same three for nuke).
  archive->WriteInt(mTacticalSiloBuildCount);
  archive->WriteInt(mTacticalSiloStorageCount);
  archive->WriteInt(mTacticalSiloMaxStorageCount);
  archive->WriteInt(mNukeSiloBuildCount);
  archive->WriteInt(mNukeSiloStorageCount);
  archive->WriteInt(mNukeSiloMaxStorageCount);

  archive->Write(CachedEntIdType(), &mSelectionInheritorId, ownerRef);
  archive->WriteString(&mCustomName);

  archive->Write(CachedSEconValueType(), &mProduced, ownerRef);
  archive->Write(CachedSEconValueType(), &mResourcesSpent, ownerRef);
  archive->Write(CachedSEconValueType(), &mMaintainenceCost, ownerRef);

  archive->Write(CachedEntIdType(), &mFocusUnit, ownerRef);
  archive->Write(CachedEntIdType(), &mGuardedUnit, ownerRef);
  archive->Write(CachedEntIdType(), &mTargetBlip, ownerRef);

  // Two SHARED tracked animation-pose pointers: prior pose then current pose,
  // each wrapped via gpg::RRef_CAniPose and emitted through WriteRawPointer
  // with TrackedPointerState::Shared (the binary's `push 3; state`).
  gpg::RRef poseRef{};
  (void)gpg::RRef_CAniPose(&poseRef, mPriorSharedPose.get());
  gpg::WriteRawPointer(archive, poseRef, gpg::TrackedPointerState::Shared, ownerRef);

  (void)gpg::RRef_CAniPose(&poseRef, mSharedPose.get());
  gpg::WriteRawPointer(archive, poseRef, gpg::TrackedPointerState::Shared, ownerRef);

  archive->Write(CachedUnitWeaponInfoVectorType(), &mWeaponInfo, ownerRef);
  archive->Write(CachedUnitAttributesType(), &mAttributes, ownerRef);

  archive->WriteInt(static_cast<int>(mScriptbits));
  archive->WriteInt64(static_cast<std::int64_t>(mUnitStates));
  archive->WriteBool(mDidRefresh);
  archive->WriteBool(mOverchargePaused);
}

namespace moho
{
/**
 * Address: 0x005C3850 (FUN_005C3850, sub_5C3850, init_SSTIUnitWeaponInfoVector_inline)
 *
 * What it does:
 * Rebinds one weapon-info fastvector to inline storage and applies the
 * zero-count resize lane used during unit-variable-data construction.
 *
 * Invocation chain (verified per caller-chain audit hook):
 *   moho::InitializeSSTIUnitWeaponInfoVector
 *     ← moho::SSTIUnitVariableData::SSTIUnitVariableData (Unit.cpp:11869)
 *     ← Unit.cpp:11371 placement-new (slot allocator)
 *       Unit.cpp:11437, 11544 copy-construction in growth/shift paths
 *     ← reachable from main via Unit construction / sim-state copy.
 *
 * Symbol-binding note: the body lives in `namespace moho` to match the
 * `moho::InitializeSSTIUnitWeaponInfoVector` declaration in Unit.h:485.
 * Previously the definition sat at file scope while the declaration was
 * inside `namespace moho`, so the linker resolved external `moho::`-
 * qualified callers to the no-op stub in EngineUnrecoveredStubs.cpp.
 * Caller at Unit.cpp:11869 still resolves correctly via `using
 * namespace moho;` at Unit.cpp:128 + ADL on the parameter type.
 */
SSTIUnitWeaponInfoVector* InitializeSSTIUnitWeaponInfoVector(SSTIUnitWeaponInfoVector* const weaponInfo)
{
  // Binary writes the four FastVectorN<UnitWeaponInfo,1> lane pointers
  // unconditionally — no null check at FUN_005C3850 entry. Matches the
  // single recovered caller (SSTIUnitVariableData ctor passes
  // &mWeaponInfo which is always a valid embedded subobject).
  weaponInfo->RebindInlineNoFree();

  // Resize(0, T{}) materializes the default UnitWeaponInfo prototype on
  // the stack (the `char v2[160]` slot in the IDA decomp), then exits
  // through the `newSize < currentSize` early-return without touching
  // the prototype because `currentSize` is already 0 after the rebind.
  // The prototype's ctor / dtor still run for SEH-correctness — exactly
  // matching the binary's UnitWeaponInfo()/~UnitWeaponInfo bracket.
  weaponInfo->Resize(0u);
  return weaponInfo;
}
} // namespace moho

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
  , mSelectionInheritorId(static_cast<EntId>(0xF0000000u))
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
  (void)InitializeSSTIUnitWeaponInfoVector(&mWeaponInfo);

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
 * Address: 0x00561D40 (FUN_00561D40, FastVectorN<UnitWeaponInfo,1>::ClearAndRebindToInline)
 *
 * IDA signature:
 * Moho::UnitWeaponInfo *__usercall sub_561D40@<eax>(int a1@<ebx>);
 *
 * What it does:
 * Destructs every active `UnitWeaponInfo` element in the weapon-info fast
 * vector lane (range [start_, end_)), then, if storage is heap-backed, frees
 * the heap buffer and rebinds all three lane pointers back onto the inline
 * buffer header stored at `originalVec_` (+0x0C in the FastVectorN layout),
 * producing the post-rebind invariant `start_ == end_ == originalVec_` and
 * `capacity_ = originalVec_ + N`. When already using inline storage the lane
 * simply collapses `end_ = start_` without freeing inline bytes.
 *
 * Two aliasing JMP thunks (at 0x00560CB0 and 0x00561430) forward here as part
 * of compiler-synthesized copy-assign prologues; the CALL from
 * `~SSTIUnitVariableData` at 0x00560561 runs the same teardown for the
 * destructor case. Recovered as an intent-named method on the fastvector
 * lane and invoked explicitly from `~SSTIUnitVariableData` below.
 */
static void ClearWeaponInfoVectorAndRebindInline(moho::SSTIUnitWeaponInfoVector& vec) noexcept
{
  // Run UnitWeaponInfo destructors for every live element so the shared
  // texture / blueprint references each weapon snapshot holds are released
  // before the backing storage is freed. The stride is sizeof(UnitWeaponInfo)
  // = 0x98 exactly as the binary's `add edi, 98h` cursor.
  for (moho::UnitWeaponInfo* cursor = vec.start_; cursor != vec.end_; ++cursor) {
    cursor->~UnitWeaponInfo();
  }

  // If lanes currently reference heap storage (start_ differs from the
  // inline-buffer header stored in originalVec_), release that heap block and
  // restore pointer lanes to the inline buffer using the saved capacity
  // header that was written into the first slot of inline storage at the
  // most recent grow/init event.
  if (vec.start_ != vec.originalVec_) {
    ::operator delete[](vec.start_);
    vec.start_ = vec.originalVec_;
    vec.capacity_ = *reinterpret_cast<moho::UnitWeaponInfo**>(vec.start_);
    vec.end_ = vec.start_;
  } else {
    vec.end_ = vec.start_;
  }
}

/**
 * Address: 0x00560500 (FUN_00560500, ??1SSTIUnitVariableData@Moho@@QAE@XZ)
 *
 * What it does:
 * Releases dynamic sync lanes through member dtors (`string`, `shared_ptr`,
 * and fastvector_n payloads) and explicitly clears the weapon-info
 * fastvector lane back to inline storage so every `UnitWeaponInfo` element
 * destructor actually runs (`~FastVectorN` alone only frees heap bytes).
 */
SSTIUnitVariableData::~SSTIUnitVariableData()
{
  ClearWeaponInfoVectorAndRebindInline(mWeaponInfo);
}

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
  mSelectionInheritorId = other.mSelectionInheritorId;
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
  CopyUnitCommandSnapshotVector(mCommands, other.mCommands);
  CopyUnitCommandSnapshotVector(mBuildQueue, other.mBuildQueue);
  CopyFastVectorN(mWeaponInfo, other.mWeaponInfo);
  (void)CopyUnitAttributesSnapshot(&mAttributes, &other.mAttributes);
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
 * Address: 0x006A4920 (FUN_006A4920, Moho::Unit::StaticGetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for `Unit`.
 */
gpg::RType* Unit::StaticGetClass()
{
  return CachedUnitRType();
}

/**
 * Address: 0x006A4940 (FUN_006A4940, Moho::Unit::GetClass)
 *
 * What it does:
 * Returns cached reflection descriptor for `Unit`.
 */
gpg::RType* Unit::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x006A4960 (FUN_006A4960, Moho::Unit::GetDerivedObjectRef)
 *
 * What it does:
 * Packs `{this, GetClass()}` as a reflection reference handle.
 */
gpg::RRef Unit::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

namespace
{
  template <class T>
  void DeleteAndNull(T*& object) noexcept
  {
    T* const oldObject = object;
    object = nullptr;
    delete oldObject;
  }

  void DestroyUnitEconomyRequest(CEconRequest*& request) noexcept
  {
    CEconRequest* const oldRequest = request;
    request = nullptr;
    if (oldRequest == nullptr) {
      return;
    }

    oldRequest->mNode.ListUnlink();
    delete oldRequest;
  }

  void DestroyUnitExtraStorage(CEconStorage*& storage) noexcept
  {
    CEconStorage* const oldStorage = storage;
    storage = nullptr;
    if (oldStorage == nullptr) {
      return;
    }

    if (oldStorage->mEconomy != nullptr) {
      (void)oldStorage->Chng(-1);
    }
    delete oldStorage;
  }

  void DestroyUnitEconomyEvents(Unit& unit) noexcept
  {
    TDatListItem<void, void>* const head = &unit.mEconomyEventListHead;
    while (head->mNext != head) {
      CEconomyEvent* const event = EconomyEventFromNode(head->mNext);
      delete event;
    }
    head->ListResetLinks();
  }

  void ClearWeakObjectChain(WeakObject& weakObject) noexcept
  {
    auto* cursor = reinterpret_cast<WeakObject::WeakLinkNodeView**>(weakObject.WeakLinkHeadSlot());
    while (cursor != nullptr && *cursor != nullptr) {
      WeakObject::WeakLinkNodeView* const node = *cursor;
      *cursor = node->nextInOwner;
      node->ownerLinkSlot = nullptr;
      node->nextInOwner = nullptr;
    }
  }

  void ClearUnitWeakReferences(Unit& unit) noexcept
  {
    unit.CreatorRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
    unit.TransportedByRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
    unit.AssignedTransportRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
    unit.FocusEntityRef.AsWeakPtr<Entity>().UnlinkFromOwnerChain();
    unit.TargetBlipEntityRef.AsWeakPtr<Entity>().UnlinkFromOwnerChain();
    unit.GuardedUnitRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
    unit.mInfoCache.mFormationLeadRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();

    for (SWeakRefSlot& slot : unit.mBlipsInRange) {
      slot.AsWeakPtr<Entity>().UnlinkFromOwnerChain();
    }
    unit.mBlipsInRange.ResetStorageToInline();
  }

  void ClearGuardedByOwners(Unit& unit)
  {
    std::vector<Unit*> guardedByUnits;
    if (unit.GuardedByList.mSlots.begin != nullptr && unit.GuardedByList.mSlots.end != nullptr) {
      guardedByUnits.reserve(gpg::FastVectorRuntimeCount(unit.GuardedByList.mSlots));

      for (const SGuardedByWeakOwnerSlot* slot = unit.GuardedByList.mSlots.begin;
           slot != unit.GuardedByList.mSlots.end;
           ++slot) {
        auto* const guardedByUnit = reinterpret_cast<Unit*>(DecodeGuardedByOwnerSlot(*slot));
        if (guardedByUnit != nullptr) {
          guardedByUnits.push_back(guardedByUnit);
        }
      }
    }

    for (Unit* const guardedByUnit : guardedByUnits) {
      guardedByUnit->SetGuardedUnit(nullptr);
    }

    gpg::FastVectorRuntimeResetToInline(unit.GuardedByList.mSlots);
    unit.GuardedByList.mOwnerNode.ListUnlinkSelf();
    unit.SetGuardedUnit(nullptr);
  }

  void DecrementUnitArmyLifetimeStats(Unit& unit)
  {
    CArmyImpl* const army = unit.ArmyRef;
    if (army == nullptr) {
      return;
    }

    const RUnitBlueprint* const blueprint = unit.GetBlueprint();
    if (blueprint == nullptr) {
      return;
    }

    CArmyStats* const armyStats = army->GetArmyStats();
    if (armyStats == nullptr) {
      return;
    }

    if (unit.IsBeingBuilt()) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_BeingBuilt", blueprint, -1.0f);
      return;
    }

    if (blueprint->General.CapCost > 0.0f) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_Active", blueprint, -1.0f);
      const std::int32_t delta = -1;
      (void)armyStats->UpdateUnitStat("Units_Active", &delta);
    }
  }

  void DetachAndDestroyUnitTransport(Unit& unit)
  {
    if (unit.AiTransport == nullptr) {
      return;
    }

    EntitySetTemplate<Unit> detachedUnits = unit.AiTransport->TransportDetachAllUnits(true);
    (void)detachedUnits;
    DeleteAndNull(unit.AiTransport);
  }

  void ClearUnitOwnedSidecars(Unit& unit)
  {
    DeleteAndNull(unit.AiCommandDispatch);

    if (unit.CommandQueue != nullptr) {
      unit.CommandQueue->ClearCommandQueue();
    }

    DeleteAndNull(unit.AiAttacker);
    DetachAndDestroyUnitTransport(unit);
    DeleteAndNull(unit.AiNavigator);
    DeleteAndNull(unit.AiSteering);
    DeleteAndNull(unit.UnitMotion);
    DeleteAndNull(unit.AiBuilder);
    DeleteAndNull(unit.AiSiloBuild);
    DeleteAndNull(unit.CommandQueue);
    DeleteAndNull(unit.AniActor);
  }
} // namespace

namespace
{
  /**
   * Address: 0x007736A0 (FUN_007736A0, sub_7736A0)
   *
   * IDA signature:
   * float *__userpurge sub_7736A0(
   *     Moho::SEconValue *dest@<eax>, Moho::CEconRequest *request@<edx>, Moho::SEconValue *desired);
   *
   * What it does:
   * Clamps `desired` to what remains in `request.mGranted` (component-wise
   * min), writes the clamped amount into `dest`, then reduces
   * `request.mGranted` by that withdrawn amount (floored at zero).
   */
  SEconValue& WithdrawFromGrantedEconValue(SEconValue& dest, CEconRequest& request, const SEconValue& desired)
  {
    dest.energy = std::min(desired.energy, request.mGranted.energy);
    dest.mass = std::min(desired.mass, request.mGranted.mass);

    request.mGranted.energy = std::max(0.0f, request.mGranted.energy - dest.energy);
    request.mGranted.mass = std::max(0.0f, request.mGranted.mass - dest.mass);

    return dest;
  }
} // namespace

/**
 * Address: 0x006AD750 (FUN_006AD750, func_SetExtraStorage)
 *
 * IDA signature:
 * void callcnv_F3 func_SetExtraStorage(Moho::CEconStorage **a1@<eax>, Moho::CEconStorage *a2@<ecx>);
 */
void Unit::SetExtraStorage(CEconStorage* const newStorage)
{
  DestroyUnitExtraStorage(mExtraStorage);
  mExtraStorage = newStorage;
}

/**
 * Address: 0x006AAAC0 (FUN_006AAAC0, ?HandleResourceManagement@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * Per-tick economy step. Consumes this unit's request lane (throttling its
 * own production by the consumption fulfillment ratio when it is not a
 * natural producer), then - while alive, not under construction, and
 * production-active - maintains the extra max-storage lane the blueprint's
 * storage economy requires and contributes production output into the
 * owning army's economy and this unit's own beat accumulators. Otherwise
 * (not producing), tears down any owned extra-storage lane.
 */
void Unit::HandleResourceManagement()
{
  ResourceConsumed = 0.0f;
  float productionRate = 1.0f;

  if (!GetBlueprint()->Economy.NaturalProducer && mConsumptionData != nullptr) {
    productionRate = mConsumptionData->LimitingRate();
  }

  if (!IsDead() && ConsumptionActive && mConsumptionData != nullptr) {
    ResourceConsumed = mConsumptionData->LimitingRate();

    SEconValue desiredConsumption = mConsumptionData->mRequested;
    desiredConsumption.energy *= ResourceConsumed;
    desiredConsumption.mass *= ResourceConsumed;

    SEconValue withdrawn{};
    WithdrawFromGrantedEconValue(withdrawn, *mConsumptionData, desiredConsumption);

    mBeatResourceAccumulators.resourcesSpentEnergy += withdrawn.energy;
    mBeatResourceAccumulators.resourcesSpentMass += withdrawn.mass;
  }

  if (BeingBuilt || IsDead() || !ProductionActive) {
    DestroyUnitExtraStorage(mExtraStorage);
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();

  if (blueprint->Economy.StorageEnergy == 0.0f && blueprint->Economy.StorageMass == 0.0f) {
    DestroyUnitExtraStorage(mExtraStorage);
  } else {
    const SEconValue storageAmount{blueprint->Economy.StorageEnergy, blueprint->Economy.StorageMass};

    if (mExtraStorage != nullptr) {
      mExtraStorage->ChangeAmt(storageAmount);
    } else {
      CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy();
      SetExtraStorage(new (std::nothrow) CEconStorage(storageAmount, reinterpret_cast<CEconomy*>(economyInfo)));
    }
  }

  SEconValue producedThisTick{
    Attributes.productionPerSecondEnergy * productionRate, Attributes.productionPerSecondMass * productionRate
  };
  producedThisTick.energy *= 0.1f;
  producedThisTick.mass *= 0.1f;

  CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy();
  economyInfo->mResources.ENERGY += producedThisTick.energy;
  economyInfo->mResources.MASS += producedThisTick.mass;
  economyInfo->mPendingResources.ENERGY += producedThisTick.energy;
  economyInfo->mPendingResources.MASS += producedThisTick.mass;
  mBeatResourceAccumulators.maintenanceEnergy += producedThisTick.energy;
  mBeatResourceAccumulators.maintenanceMass += producedThisTick.mass;
}

/**
 * Address: 0x006AA7A0 (FUN_006AA7A0, ?UpdateGuardFormation@Unit@Moho@@AAEXXZ)
 *
 * What it does:
 * When this unit has no guard formation yet but has guarded units and a
 * blueprint-defined guard-formation script, builds a new
 * `CAiFormationInstance` centered on this unit (oriented along this unit's
 * own transform when mobile, or a zero orientation otherwise), disbands any
 * prior formation, and primes the new one.
 */
void Unit::UpdateGuardFormation()
{
  if (GuardFormation != nullptr || GuardedByList.empty()) {
    return;
  }

  CAiFormationDBImpl* const formationDB = SimulationRef->mFormationDB;
  const char* const guardFormationScript = GetBlueprint()->AI.GuardFormationName.c_str();
  if (guardFormationScript == nullptr || *guardFormationScript == '\0') {
    return;
  }

  const Wm3::Vec3f& position = GetPosition();
  SCoordsVec2 formationCenter{};
  formationCenter.x = position.x;
  formationCenter.z = position.z;

  const Wm3::Quatf formationOrientation = IsMobile() ? GetTransform().orient_ : Zeroed<Wm3::Quaternionf>();

  CAiFormationInstance* const newFormation = formationDB->NewFormation(
    &GuardedByList,
    guardFormationScript,
    &formationCenter,
    formationOrientation.x,
    formationOrientation.y,
    formationOrientation.z,
    formationOrientation.w,
    15
  );

  IFormationInstance* const previousFormation = GuardFormation;
  GuardFormation = newFormation;
  if (previousFormation != nullptr) {
    previousFormation->operator_delete(1);
  }

  newFormation->Func22(1.0f);
}

/**
 * Address: 0x006A9010 (FUN_006A9010, Moho::Unit::MotionTick)
 * Primary vtable slot 20 (`??_7Unit@Moho@@6BEntity@Moho@@@`, Entity subobject).
 *
 * What it does:
 * Per-tick motion driver. Logs the tick, advances the silo-build sidecar,
 * refreshes the guard formation and info cache, counts down the stun timer,
 * dispatches to the owned `CUnitMotion`'s own per-tick update, ticks every
 * pending economy event, refreshes animation manipulators from the pending
 * transform, recomputes whether this unit is currently attached to
 * something, then - while alive - either regenerates health (when not under
 * construction and the regen rate is positive) or applies build decay (when
 * still under construction, past the first tick after creation), then runs
 * the resource-management economy step. Finally, if this unit is not a POD
 * and its command queue is empty, issues an `AssistCommander` command to
 * itself; and if a builder sidecar is present, validates its factory queue.
 */
int Unit::MotionTick()
{
  SimulationRef->Logf("0x%08x's motion tick.\n", id_);

  if (AiSiloBuild != nullptr) {
    AiSiloBuild->SiloTick();
  }

  UpdateGuardFormation();
  UpdateInfoCache();

  if (StunnedState > 0) {
    --StunnedState;
  }

  const int motionResult =
    (UnitMotion != nullptr) ? static_cast<int>(UnitMotion->MotionTick()) : static_cast<int>(TASKSTATUS_Wait);

  const TDatListItem<void, void>* const econEventsHead = &mEconomyEventListHead;
  for (TDatListItem<void, void>* node = mEconomyEventListHead.mNext; node != econEventsHead; node = node->mNext) {
    EconomyEventFromNode(node)->ProcessTick();
  }

  AniActor->UpdateManipulators(reinterpret_cast<const VTransform&>(PendingOrientation));

  mIsBusy = mAttachInfo.HasAttachTarget();

  if (!BeingBuilt) {
    if (MaxHealth > Health && GetAttributes().regenRate > 0.0f) {
      AdjustHealth(this, GetAttributes().regenRate * 0.1f);
    }
  } else if (static_cast<std::int32_t>(SimulationRef->mCurTick - mCreationTick) > 1) {
    const RUnitBlueprintEconomy& economy = GetBlueprint()->Economy;
    float buildTime = std::max(economy.BuildCostEnergy, economy.BuildCostMass);
    buildTime = std::max(buildTime, economy.BuildTime);

    if (buildTime > 0.0f) {
      Materialize(-0.1f / buildTime);
      if (Health <= 0.0f) {
        RunScript("OnDecayed");
      }
    }
  }

  HandleResourceManagement();

  if (mIsNotPod && (CommandQueue == nullptr || CommandQueue->mCommandVec.empty())) {
    SEntitySetTemplateUnit selectedUnits{};
    (void)selectedUnits.AddUnit(this);
    SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_AssistCommander);
    (void)IssueCommandToSelectedUnits(SimulationRef, selectedUnits, commandData, false);
  }

  if (AiBuilder != nullptr) {
    AiBuilder->BuilderValidateFactoryCommandQueue();
  }

  return motionResult;
}

/**
 * Address: 0x006A5050 (FUN_006A5050, ??0Unit@Moho@@AAE@PAVSim@1@@Z)
 * Mangled: ??0Unit@Moho@@AAE@PAVSim@1@@Z
 *
 * IDA signature:
 * Moho::Unit *__thiscall Moho::Unit::Unit(Moho::Unit *this, Moho::Sim *sim);
 *
 * What it does:
 * Deserialization-construct constructor (private; invoked only by
 * Unit::MemberConstruct). Constructs the IUnit/Entity bases on `sim`, bumps the
 * live-Unit instance counter, default-constructs the const/variable stat-data
 * subobjects, and zero-initializes every runtime lane: AI sidecars, weak-ref
 * slots, the guarded-by list, the armor-multiplier map head, the economy-event
 * list, the info cache, the occupancy rect, and the recon/blip vectors.
 */
Unit::Unit(Sim* sim) : IUnit(), Entity(sim, ENTITYTYPE_Unit)
{
  // The binary bumps the live-instance counter here (between the base ctors and
  // the stat-data member ctors). Its ordering relative to the member ctors is
  // unobservable because none of them read the counter.
  StatItem* const instanceStat = InstanceCounter<Unit>::GetStatItem();
  InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&instanceStat->mPrimaryValueBits), 1L);

  // mConstDat is a real member and default-constructs automatically. The
  // variable stat-data subobject at +0x288 is flattened into Unit's field list
  // (see VarDat()), so construct it in place through the typed accessor.
  new (&VarDat()) SSTIUnitVariableData();

  UnitMotion = nullptr;
  CommandQueue = nullptr;
  CreatorRef = {};
  TransportedByRef = {};
  AssignedTransportRef = {};
  FocusEntityRef = {};
  TargetBlipEntityRef = {};
  GuardedUnitRef = {};
  GuardedPos.x = 0.0f;
  GuardedPos.y = 0.0f;
  GuardedPos.z = 0.0f;

  // GuardedByList.mOwnerNode self-links via its TDatListItem ctor (member init).
  // Point the fastvector runtime view at its own inline small-buffer: empty
  // (begin == end) with capacity for four slots ending at GuardFormation.
  GuardedByList.mSlots.begin = GuardedByList.mInlineSlots;
  GuardedByList.mSlots.end = GuardedByList.mInlineSlots;
  GuardedByList.mSlots.capacityEnd = GuardedByList.mInlineSlots + 4;
  GuardedByList.mSlots.metadata = GuardedByList.mInlineSlots;

  GuardFormation = nullptr;
  mNeedsKillCleanup = false;
  mCreationTick = 0;
  mExtraStorage = nullptr;
  PriorityBoost = 1;
  mConsumptionData = nullptr;
  ConsumptionActive = false;
  ProductionActive = false;
  ResourceConsumed = 0.0f;
  AniActor = nullptr;
  AiAttacker = nullptr;
  AiCommandDispatch = nullptr;
  AiNavigator = nullptr;
  AiSteering = nullptr;
  AiBuilder = nullptr;
  AiSiloBuild = nullptr;
  AiTransport = nullptr;
  FootprintDown = false;
  TransportLoadFactor = -1.0f;

  // Armor-multiplier map: allocate the sentinel head node and self-link it.
  SArmorMultiplierMapNode* const armorHead = AllocateArmorMultiplierMapNodeRaw();
  ArmorMultipliers.head = armorHead;
  armorHead->isNil = 1;
  armorHead->parent = armorHead;
  armorHead->left = armorHead;
  armorHead->right = armorHead;
  ArmorMultipliers.size = 0;

  // mEconomyEventListHead self-links via its TDatListItem ctor (member init).

  CurrentTerrainType = 0;
  mDebugAIStates = false;

  mInfoCache.mFormationLayer = nullptr;
  mInfoCache.mFormationLeadRef = {};
  mInfoCache.mFormationPriorityOrder = 0;
  mInfoCache.mHasFormationSpeedData = false;
  mInfoCache.mFormationTopSpeed = 0.0f;
  mInfoCache.mFormationDistanceMetric = 0.0f;
  mInfoCache.mFormationHeadingHint.x = 0.0f;
  mInfoCache.mFormationHeadingHint.y = 0.0f;
  mInfoCache.mFormationHeadingHint.z = 0.0f;

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;

  // mBlipsInRange (FastVectorN<SWeakRefSlot,20>) and mReconBlips
  // (FastVectorN<ReconBlip*,2>) bind to their inline buffers as members.
  mBlipLastUpdateTick = 0;

  mIsNotPod = false;
  mIsEngineer = false;
  mIsNaval = false;
  mIsAir = false;
  mUsesGridBasedMotion = false;
  mIsMelee = false;
  CaptorCount = 0;
  NeedSyncGameData = true;
}

namespace
{
  /** Half the yaw spread a randomly-facing spawn gets, in radians (~30 degrees). */
  constexpr float kRandomSpawnYawLimit = 0.52359879f;

  /** `SSTIUnitVariableData::mCreator` when the unit was not built by anything. */
  constexpr moho::EntId kNoCreatorEntityId = static_cast<moho::EntId>(0xF0000000);

  /** `UnitStateMask` bit set while a unit is still under construction. */
  constexpr std::uint64_t kUnitStateBeingBuilt = 1ULL << 39;

  /**
   * Floor the two minima and ceil the two maxima of a skirt rectangle onto the
   * occupancy grid, which is what the binary's four `frndint`s plus sign
   * fixups come out to.
   */
  [[nodiscard]] gpg::Rect2i SkirtRectToOgridRect(const gpg::Rect2f& skirt) noexcept
  {
    return gpg::Rect2i{
      static_cast<std::int32_t>(std::floor(skirt.x0)),
      static_cast<std::int32_t>(std::floor(skirt.z0)),
      static_cast<std::int32_t>(std::ceil(skirt.x1)),
      static_cast<std::int32_t>(std::ceil(skirt.z1)),
    };
  }
} // namespace

/**
 * Address: 0x006A53F0 (FUN_006A53F0, ??0Unit@Moho@@AAE@ABUSUnitConstructionParams@1@@Z)
 * Mangled: ??0Unit@Moho@@AAE@ABUSUnitConstructionParams@1@@Z
 *
 * IDA signature:
 * Moho::Unit *__stdcall Moho::Unit::Unit(Moho::Unit *unit,
 *     const Moho::SUnitConstructionParams *params);
 *
 * What it does:
 * The gameplay constructor - what `Sim::CreateUnit` calls, and the only way a
 * unit comes into existence outside a savegame load. Reserves an entity id out
 * of the owning army's id family, runs the blueprint-aware `Entity` base
 * constructor, seeds health and attributes from the blueprint, resolves the
 * spawn orientation and elevation, builds the intel manager, attaches every AI
 * sidecar the blueprint calls for (motion/navigator/steering, weapons, builder,
 * silo builder, transport, command queue, command dispatch), publishes the unit
 * into `ArmyPool`, and runs `OnCreate` plus either `OnStartBeingBuilt` or
 * `OnStopBeingBuilt`.
 */
Unit::Unit(const SUnitConstructionParams& params)
  : IUnit()
  , Entity(
      const_cast<REntityBlueprint*>(static_cast<const REntityBlueprint*>(params.mBlueprint)),
      params.mArmy->GetSim(),
      static_cast<EntId>(params.mArmy->GetSim()->mEntityDB->DoReserveId(
        static_cast<std::uint32_t>(params.mArmy->ArmyId) << 20
      )),
      ENTITYTYPE_Unit
    )
{
  StatItem* const instanceStat = InstanceCounter<Unit>::GetStatItem();
  InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&instanceStat->mPrimaryValueBits), 1L);

  new (&VarDat()) SSTIUnitVariableData();

  Sim* const sim = SimulationRef;
  const RUnitBlueprint& blueprint = *params.mBlueprint;

  // --- runtime lanes: the same zeroing the deserialization ctor above does --
  UnitMotion = nullptr;
  CommandQueue = nullptr;
  CreatorRef = {};
  CreatorRef.AsWeakPtr<Unit>().Set(params.mLinkSourceUnit);
  TransportedByRef = {};
  AssignedTransportRef = {};
  FocusEntityRef = {};
  TargetBlipEntityRef = {};
  GuardedUnitRef = {};
  GuardedPos.x = 0.0f;
  GuardedPos.y = 0.0f;
  GuardedPos.z = 0.0f;

  GuardedByList.mSlots.begin = GuardedByList.mInlineSlots;
  GuardedByList.mSlots.end = GuardedByList.mInlineSlots;
  GuardedByList.mSlots.capacityEnd = GuardedByList.mInlineSlots + 4;
  GuardedByList.mSlots.metadata = GuardedByList.mInlineSlots;

  GuardFormation = nullptr;
  mNeedsKillCleanup = false;
  mCreationTick = sim->mCurTick;
  mExtraStorage = nullptr;
  PriorityBoost = 1;
  mConsumptionData = nullptr;
  ConsumptionActive = false;
  ProductionActive = false;
  ResourceConsumed = 0.0f;
  AniActor = nullptr;
  AiAttacker = nullptr;
  AiCommandDispatch = nullptr;
  AiNavigator = nullptr;
  AiSteering = nullptr;
  AiBuilder = nullptr;
  AiSiloBuild = nullptr;
  AiTransport = nullptr;
  FootprintDown = false;
  TransportLoadFactor = -1.0f;

  SArmorMultiplierMapNode* const armorHead = AllocateArmorMultiplierMapNodeRaw();
  ArmorMultipliers.head = armorHead;
  armorHead->isNil = 1;
  armorHead->parent = armorHead;
  armorHead->left = armorHead;
  armorHead->right = armorHead;
  ArmorMultipliers.size = 0;

  CurrentTerrainType = 0;
  mDebugAIStates = false;

  mInfoCache.mFormationLayer = nullptr;
  mInfoCache.mFormationLeadRef = {};
  mInfoCache.mFormationPriorityOrder = 0;
  mInfoCache.mHasFormationSpeedData = false;
  mInfoCache.mFormationTopSpeed = 0.0f;
  mInfoCache.mFormationDistanceMetric = 0.0f;
  mInfoCache.mFormationHeadingHint.x = 0.0f;
  mInfoCache.mFormationHeadingHint.y = 0.0f;
  mInfoCache.mFormationHeadingHint.z = 0.0f;

  ReservedOgridRectMinX = 0;
  ReservedOgridRectMinZ = 0;
  ReservedOgridRectMaxX = 0;
  ReservedOgridRectMaxZ = 0;

  mBlipLastUpdateTick = 0;

  mIsNotPod = false;
  mIsEngineer = false;
  mIsNaval = false;
  mIsAir = false;
  mUsesGridBasedMotion = false;
  mIsMelee = false;
  NeedSyncGameData = true;
  CaptorCount = 0;

  // --- blueprint-derived health and attributes ---------------------------
  MaxHealth = blueprint.Defense.MaxHealth;
  Health = params.mComplete != 0 ? blueprint.Defense.Health : 1.0f;
  FractionCompleted = static_cast<float>(params.mComplete);
  BeingBuilt = 0;
  IntelAttributes.Initialize(&blueprint);

  VarDat().mCreator = params.mLinkSourceUnit != nullptr ? params.mLinkSourceUnit->id_ : kNoCreatorEntityId;
  // Constructed in place over the unit's own attribute lane (unit+0x428),
  // which is VarDat().mAttributes.
  new (&Attributes) UnitAttributes(&blueprint, static_cast<const RRuleGameRulesImpl*>(sim->mRules));
  VarDat().mCreationTick = sim->mCurTick;

  SetAutoMode(blueprint.AI.InitialAutoMode != 0);
  RunScript("OnPreCreate");

  // --- intel manager -----------------------------------------------------
  // The slot was nulled by the Entity base a moment ago, so the binary's
  // release-the-previous-manager branch cannot be taken here.
  mIntelManager = new CIntel(&blueprint.Intel, sim, ArmyRef->GetReconDB());

  // --- spawn transform ---------------------------------------------------
  VTransform spawnTransform = params.mTransform;
  if (params.mUseLayerOverride == 0) {
    // No caller-supplied orientation. Mobile units whose blueprint asks for it
    // get a facing within +/-30 degrees of default so a batch of them does not
    // spawn perfectly aligned; everything else faces the default direction.
    if (blueprint.Display.SpawnRandomRotation != 0 && blueprint.IsMobile()) {
      const float yaw = sim->mRngState->FRand(-kRandomSpawnYawLimit, kRandomSpawnYawLimit);
      const Wm3::Vector3f yawAxis{0.0f, 1.0f, 0.0f};
      Wm3::Quatf spawnRotation{};
      (void)EulerRollToQuat(&yawAxis, &spawnRotation, yaw);
      spawnTransform.orient_ = spawnRotation;
    } else {
      spawnTransform.orient_.x = 1.0f;
      spawnTransform.orient_.y = 0.0f;
      spawnTransform.orient_.z = 0.0f;
      spawnTransform.orient_.w = 0.0f;
    }
  }

  // --- placeholder mesh --------------------------------------------------
  RMeshBlueprint* placeholderMesh = nullptr;
  const msvc8::string placeholderName = gpg::STR_ToLower(blueprint.Display.PlaceholderMeshName.c_str());
  if (!placeholderName.empty()) {
    const msvc8::string meshPath =
      gpg::STR_Printf("/units/%s/%s_mesh", placeholderName.c_str(), placeholderName.c_str());
    msvc8::string meshFileName{};
    (void)gpg::STR_CopyFilename(&meshFileName, &meshPath);

    RResId placeholderId{};
    placeholderId.name.assign_owned(meshFileName.view());
    placeholderMesh = sim->mRules->GetMeshBlueprint(placeholderId);
  }

  // `mMeshRef` aliases the entity's borrowed RScmResource handle; a null object
  // word means nothing has claimed the mesh lane yet.
  if (mMeshRef.mObj == nullptr) {
    SetMesh(blueprint.Display.MeshBlueprint, placeholderMesh, true);
  }

  // --- layer, terrain type and spawn elevation ---------------------------
  SetCurrentLayer(GetStartingLayer(spawnTransform.pos_, static_cast<ELayer>(params.mLayer)));
  UpdateTerrainType(spawnTransform.pos_);
  if (params.mFixElevation == 0) {
    spawnTransform.pos_.y =
      IUnit::CalcSpawnElevation(sim->mMapData, mCurrentLayer, spawnTransform, VarDat().mAttributes);
  }

  PendingOrientation.x = spawnTransform.orient_.X();
  PendingOrientation.y = spawnTransform.orient_.Y();
  PendingOrientation.z = spawnTransform.orient_.Z();
  PendingOrientation.w = spawnTransform.orient_.W();
  PendingPosition = spawnTransform.pos_;
  // Twice, as the binary does: the first call publishes the spawn pose into the
  // current lane and the second copies it into the previous-frame lane, so the
  // unit does not interpolate in from wherever that lane happened to point.
  AdvanceCoords();
  AdvanceCoords();

  AniActor->GetPriorPoseShared()->SetWorldTransform(GetTransformWm3());
  AniActor->GetPoseShared()->SetWorldTransform(GetTransformWm3());
  VarDat().mPriorSharedPose = AniActor->GetPriorPoseShared();
  VarDat().mSharedPose = AniActor->GetPoseShared();

  // --- motion, navigator, steering ---------------------------------------
  // RULEUMT_None and RULEUMT_Special both leave the unit immobile; every value
  // between them gets a navigator, and only RULEUMT_Air gets the air one.
  const ERuleBPUnitMovementType motionType = blueprint.Physics.MotionType;
  if (motionType >= RULEUMT_Land && motionType <= RULEUMT_AmphibiousFloating) {
    UnitMotion = new CUnitMotion(this);
    AiNavigator =
      motionType == RULEUMT_Air ? AI_CreateAirNavigator(this) : AI_CreatePathingNavigator(this);
    AiSteering = AI_CreateSteering(this, UnitMotion, mCurrentLayer);
  } else {
    // Immobile units claim their footprint at spawn. Ferry beacons and in-place
    // upgrades are the exceptions: both sit on ground another unit already owns.
    if (!IsInCategory("FERRYBEACON") && !IsInCategory("UPGRADE")) {
      ExecuteOccupyGround();
      FootprintDown = true;
    }
  }

  // --- weapons -----------------------------------------------------------
  for (const RUnitBlueprintWeapon& weaponBlueprint : blueprint.Weapons.WeaponBlueprints) {
    if (weaponBlueprint.DummyWeapon != 0) {
      continue;
    }

    if (AiAttacker == nullptr) {
      AiAttacker = AI_CreateAttacker(this);
      mConstDat.mBuildStateTag = 1;
    }
    AiAttacker->CreateWeapon(const_cast<RUnitBlueprintWeapon*>(&weaponBlueprint));
  }

  // --- builder -----------------------------------------------------------
  if (!blueprint.Economy.BuildableCategories.empty() || IsInCategory("REBUILDER")) {
    AiBuilder = AI_CreateBuilder(this);

    if (IsInCategory("FACTORY")) {
      AiBuilder->BuilderSetIsFactory(true);
      if (UnitMotion == nullptr) {
        const Wm3::Vector3f& position = GetPosition();
        const SCoordsVec2 origin{position.x, position.z};
        ReserveOgridRect(SkirtRectToOgridRect(GetBlueprint()->GetSkirtRect(origin)));
      }
    }
  }

  // --- silo builder and transport ----------------------------------------
  if (IsInCategory("SILO")) {
    AiSiloBuild = static_cast<CAiSiloBuildImpl*>(AI_CreateSiloBuilder(this));
  }

  if ((VarDat().mAttributes.commandCapsMask & RULEUCC_Transport) != 0 || IsInCategory("PODSTAGINGPLATFORM")) {
    AiTransport = AI_CreateTransport(this);
  }

  // --- command plumbing --------------------------------------------------
  CommandQueue = new CUnitCommandQueue(this);
  AiCommandDispatch = static_cast<IAiCommandDispatchImpl*>(AI_CreateCommandDispatch(this));

  // --- publish into the army pool ----------------------------------------
  {
    SEntitySetTemplateUnit spawnedSet{};
    (void)spawnedSet.AddUnit(this);
    ArmyRef->AssignUnitsToPlatoon(&spawnedSet, "ArmyPool");
  }

  if (AiBuilder != nullptr && AiBuilder->BuilderIsFactory()) {
    AiBuilder->BuilderSetUpInitialRally();
  }

  InitializeArmor();
  RunScript("OnCreate");

  // --- being-built vs finished -------------------------------------------
  CArmyStats* const armyStats = ArmyRef->GetArmyStats();
  const char* const layerName = LayerToString(mCurrentLayer);
  const LuaPlus::LuaObject creatorObject =
    params.mLinkSourceUnit != nullptr ? params.mLinkSourceUnit->GetLuaObject() : GetLuaObject();

  if (params.mComplete == 0) {
    UnitStateMask |= kUnitStateBeingBuilt;
    BeingBuilt = 1;
    if (armyStats != nullptr) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_BeingBuilt", &blueprint, 1.0f);
    }
    RunScript("OnStartBeingBuilt", creatorObject, layerName);
  } else {
    if (UnitMotion == nullptr) {
      SEntitySetTemplateUnit overlapping{};
      (void)CollectAllOverlapping(&overlapping, this);
      for (Entity* const entry : overlapping.mVec) {
        Unit* const neighbour = SEntitySetTemplateUnit::UnitFromEntry(entry);
        if (neighbour == nullptr) {
          continue;
        }
        RunScript("OnAdjacentTo", neighbour, this);
        neighbour->RunScript("OnAdjacentTo", this, neighbour);
      }
    }

    RunScript("OnStopBeingBuilt", creatorObject, layerName);

    if (blueprint.General.CapCost > 0.0f && armyStats != nullptr) {
      IncrementArmyBlueprintFloatStat(armyStats, "Units_Active", &blueprint, 1.0f);
      const std::int32_t delta = 1;
      (void)armyStats->UpdateUnitStat("Units_Active", &delta);
      IncrementArmyBlueprintFloatStat(armyStats, "Units_History", &blueprint, 1.0f);
      (void)armyStats->UpdateUnitStat("Units_History", &delta);
    }
  }

  if (ArmyRef != nullptr) {
    ArmyRef->AddUnitToCategorySet(this);
  }

  // --- cached category flags ---------------------------------------------
  mIsNotPod = IsInCategory("POD") || IsInCategory("STATIONASSISTPOD");
  mIsEngineer = IsInCategory("ENGINEER");
  mIsNaval = IsInCategory("NAVAL");
  mIsAir = IsInCategory("AIR");
  mIsMelee = IsInCategory("MELEE");
  mUsesGridBasedMotion = IsInCategory("GRIDBASEDMOTION");
}

/**
 * Address: 0x006AD3C0 (FUN_006AD3C0,
 * ?MemberConstruct@Unit@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z)
 *
 * What it does:
 * Reflection construct-callback. Reads the owning `Sim*` from the archive,
 * allocates and constructs a fresh `Unit` on it, then publishes the constructed
 * object (paired with its owning Sim) to the `SerConstructResult` as unowned.
 */
void Unit::MemberConstruct(
  gpg::ReadArchive& archive,
  const int,
  const gpg::RRef&,
  gpg::SerConstructResult& result
)
{
  Sim* sim = nullptr;
  gpg::RRef nullOwner{};
  archive.ReadPointer_Sim(&sim, &nullOwner);

  Unit* unit = nullptr;
  void* const storage = ::operator new(sizeof(Unit));
  if (storage != nullptr) {
    unit = new (storage) Unit(sim);
  }

  gpg::RRef unitRef{};
  gpg::RRef_Unit(&unitRef, unit);

  // SetUnowned records the constructed object paired with its owning Sim: the
  // binary keeps RRef_Unit's base-adjusted object pointer but stores the Sim in
  // the ref's second slot rather than the Unit RType.
  gpg::RRef constructed{};
  constructed.mObj = unitRef.mObj;
  constructed.mType = reinterpret_cast<gpg::RType*>(sim);
  result.SetUnowned(constructed, 0u);
}

/**
 * Address: 0x006A6BF0 (FUN_006A6BF0, ??1Unit@Moho@@UAE@XZ)
 *
 * What it does:
 * Releases unit-owned AI, command, guard, economy, occupancy, recon, and
 * weak-link runtime lanes before base/member teardown.
 */
Unit::~Unit()
{
  if (ArmyRef != nullptr) {
    (void)ArmyRef->ConsumeUnitFromCategorySet(this);
  }

  ClearUnitOwnedSidecars(*this);
  (void)DestroyArmorMultiplierMapStorage(ArmorMultipliers);
  ClearGuardFormation(this);
  DestroyUnitEconomyEvents(*this);
  ReleaseOccupyGround();
  DecrementUnitArmyLifetimeStats(*this);
  ClearGuardedByOwners(*this);

  if (ArmyRef != nullptr) {
    ArmyRef->RemoveFromPlatoon(this);
  }

  mReconBlips.ResetStorageToInline();
  ClearUnitWeakReferences(*this);
  mEconomyEventListHead.ListUnlinkSelf();
  DestroyUnitEconomyRequest(mConsumptionData);
  DestroyUnitExtraStorage(mExtraStorage);

  ClearWeakObjectChain(static_cast<WeakObject&>(static_cast<IUnit&>(*this)));

  // Decrement the Unit instance-count stat (binary FUN_006A6BF0 line ~467). The
  // constructor bumps it +1; the recovered destructor had dropped the matching
  // decrement, so the live-Unit stat only grew. Mirror the ctor's inline form.
  StatItem* const instanceStat = InstanceCounter<Unit>::GetStatItem();
  InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&instanceStat->mPrimaryValueBits), -1L);
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
 * Address: 0x0062CC40 (FUN_0062CC40, Moho::Unit::IsAtPosition)
 *
 * What it does:
 * Compares this unit's footprint-aligned grid anchor against one candidate
 * world position using the same half-footprint cell projection.
 */
bool Unit::IsAtPosition(const Wm3::Vec3f& position) const
{
  const SFootprint& unitFootprint = GetFootprint();
  const Wm3::Vec3f& currentPosition = GetPosition();

  const std::int16_t currentCellZ = static_cast<std::int16_t>(
    static_cast<int>(currentPosition.z - static_cast<float>(unitFootprint.mSizeZ) * 0.5f)
  );
  const std::int16_t currentCellX = static_cast<std::int16_t>(
    static_cast<int>(currentPosition.x - static_cast<float>(unitFootprint.mSizeX) * 0.5f)
  );

  const SFootprint& targetFootprint = GetFootprint();
  const std::int16_t targetCellZ = static_cast<std::int16_t>(
    static_cast<int>(position.z - static_cast<float>(targetFootprint.mSizeZ) * 0.5f)
  );
  const std::int16_t targetCellX = static_cast<std::int16_t>(
    static_cast<int>(position.x - static_cast<float>(targetFootprint.mSizeX) * 0.5f)
  );

  return currentCellX == targetCellX && currentCellZ == targetCellZ;
}

/**
 * Address: 0x006AAEC0 (FUN_006AAEC0, ?AddRecoilImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
 * Mangled: ?AddRecoilImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
 *
 * What it does:
 * Forwards one recoil impulse into `UnitMotion` when present.
 */
void Unit::AddRecoilImpulse(const Wm3::Vec3f& impulse)
{
  CUnitMotion* const unitMotion = UnitMotion;
  if (unitMotion != nullptr) {
    unitMotion->AddRecoilImpulse(impulse);
  }
}

/**
 * Address: 0x006AAEE0 (FUN_006AAEE0, ?AddImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
 * Mangled: ?AddImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
 *
 * What it does:
 * Forwards one world impulse to `UnitMotion` when present.
 */
void Unit::AddImpulse(const Wm3::Vec3f& impulse)
{
  CUnitMotion* const unitMotion = UnitMotion;
  if (unitMotion != nullptr) {
    unitMotion->AddImpulse(impulse, false);
  }
}

/**
 * Address: 0x006AAF00 (FUN_006AAF00, ?AddLocalImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z)
 * Mangled: ?AddLocalImpulse@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z
 *
 * What it does:
 * Routes local impulse handling by motion type: airborne units use body-local
 * impulse integration, non-air units feed unit-motion impulse blending.
 */
void Unit::AddLocalImpulse(const Wm3::Vec3f& localImpulse, const Wm3::Vec3f& localPoint)
{
  CUnitMotion* const unitMotion = UnitMotion;
  if (unitMotion == nullptr) {
    return;
  }

  const Unit* const motionOwner = unitMotion->mUnit;
  const RUnitBlueprint* const blueprint = motionOwner->GetBlueprint();
  if (blueprint->Physics.MotionType == RULEUMT_Air) {
    SPhysBody* const body = static_cast<Entity*>(unitMotion->mUnit)->GetPhysBody(false);
    body->AddLocalImpulse(localImpulse, localPoint);
    return;
  }

  unitMotion->AddImpulse(localImpulse, false);
}

/**
 * Address: 0x006AAF50 (FUN_006AAF50, ?PickTargetPoint@Unit@Moho@@QBE_NAAH@Z)
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
 * Address: 0x006AA5C0 (FUN_006AA5C0, ?GetBoneWorldTransform@Unit@Moho@@UBE?AVVTransform@2@H@Z)
 *
 * What it does:
 * Resolves one unit bone world transform from pose composite lanes when the
 * bone index is valid, otherwise composes unit world transform with the
 * fallback local anchor (`+SizeY*0.5` for root `-1`).
 */
VTransform Unit::GetBoneWorldTransform(const int boneIndex) const
{
  if (AniActor != nullptr && AniActor->mPose.px != nullptr && boneIndex >= 0) {
    const CAniPose* const pose = AniActor->mPose.px;
    const CAniPoseBone* const bonesBegin = pose->mBones.begin();
    const CAniPoseBone* const bonesEnd = pose->mBones.end();
    if (bonesBegin != nullptr && bonesEnd != nullptr && bonesEnd >= bonesBegin) {
      const std::size_t boneCount = static_cast<std::size_t>(bonesEnd - bonesBegin);
      if (static_cast<std::size_t>(boneIndex) < boneCount) {
        return bonesBegin[boneIndex].GetCompositeTransform();
      }
    }
  }

  VTransform localAnchor{};
  localAnchor.orient_.w = 1.0f;
  localAnchor.orient_.x = 0.0f;
  localAnchor.orient_.y = 0.0f;
  localAnchor.orient_.z = 0.0f;
  localAnchor.pos_.x = 0.0f;
  localAnchor.pos_.y = 0.0f;
  localAnchor.pos_.z = 0.0f;

  if (boneIndex == -1) {
    if (const RUnitBlueprint* const blueprint = GetBlueprint(); blueprint != nullptr) {
      localAnchor.pos_.y = blueprint->mSizeY * 0.5f;
    }
  }

  return VTransform::Compose(GetTransform(), localAnchor);
}

/**
 * Address: 0x006AA440 (FUN_006AA440, ?GetBoneLocalTransform@Unit@Moho@@UBE?AVVTransform@2@H@Z)
 *
 * What it does:
 * Resolves one unit bone local transform from animation pose composite lanes,
 * with `-1` fallback to blueprint center-height anchor.
 */
VTransform Unit::GetBoneLocalTransform(const int boneIndex) const
{
  VTransform localTransform{};
  localTransform.orient_.w = 1.0f;
  localTransform.orient_.x = 0.0f;
  localTransform.orient_.y = 0.0f;
  localTransform.orient_.z = 0.0f;
  localTransform.pos_.x = 0.0f;
  localTransform.pos_.y = 0.0f;
  localTransform.pos_.z = 0.0f;

  if (AniActor != nullptr && AniActor->mPose.px != nullptr) {
    const CAniPose* const pose = AniActor->mPose.px;
    const CAniPoseBone* const bonesBegin = pose->mBones.begin();
    const CAniPoseBone* const bonesEnd = pose->mBones.end();
    if (bonesBegin != nullptr && bonesEnd != nullptr && bonesEnd >= bonesBegin) {
      const std::size_t boneCount = static_cast<std::size_t>(bonesEnd - bonesBegin);
      if (boneIndex >= 0 && static_cast<std::size_t>(boneIndex) < boneCount) {
        localTransform = bonesBegin[boneIndex].GetCompositeTransform();
        const VTransform poseInverse = pose->mLocalTransform.Inverse();
        localTransform = VTransform::Compose(localTransform, poseInverse);
        return localTransform;
      }
    }
  }

  if (boneIndex == -1) {
    localTransform.pos_.y = GetBlueprint()->mSizeY * 0.5f;
  }

  return localTransform;
}

/**
 * Address: 0x006AB9C0 (FUN_006AB9C0, ?SetMesh@Unit@Moho@@UAEXABVRResId@2@PAVRMeshBlueprint@2@_N@Z)
 *
 * IDA signature:
 * void __thiscall Moho::Unit::SetMesh(Moho::Unit *this, const Moho::RResId &meshResId,
 *   Moho::RMeshBlueprint *meshBlueprint, char rebuildAniActor);
 *
 * What it does:
 * Forwards to `Entity::SetMesh` with `allowExplicitPlaceholder=true`, then
 * (when `rebuildAniActor` is set) recreates the unit's `CAniPose` and
 * `CAniActor` runtime chain so the visible animation tracks the new mesh's
 * skeleton.
 */
void Unit::SetMesh(const RResId& meshResId, RMeshBlueprint* const meshBlueprint, const bool rebuildAniActor)
{
  Entity::SetMesh(meshResId, meshBlueprint, true);
  if (!rebuildAniActor) {
    return;
  }

  boost::shared_ptr<const CAniSkel> skeleton;
  if (auto* const scmResource = static_cast<RScmResource*>(mMeshRef.mObj); scmResource != nullptr) {
    skeleton = scmResource->GetSkeleton();
  }

  CAniPose* newPose = nullptr;
  if (void* const poseStorage = ::operator new(sizeof(CAniPose)); poseStorage != nullptr) {
    const float scale = GetUniformScale();
    newPose = ::new (poseStorage) CAniPose(skeleton, scale);
  }

  SSTIUnitVariableData& varDat = VarDat();
  varDat.mSharedPose.reset(newPose);
  varDat.mSharedPose->SetWorldTransform(GetTransformWm3());
  varDat.mPriorSharedPose = varDat.mSharedPose;

  CAniActor* newActor = nullptr;
  if (void* const actorStorage = ::operator new(sizeof(CAniActor)); actorStorage != nullptr) {
    const boost::SharedPtrRaw<CAniPose> priorRaw = boost::SharedPtrRawFromSharedBorrow(varDat.mPriorSharedPose);
    const boost::SharedPtrRaw<CAniPose> currentRaw = boost::SharedPtrRawFromSharedBorrow(varDat.mSharedPose);
    newActor = ::new (actorStorage) CAniActor(priorRaw, currentRaw);
  }

  CAniActor* const oldActor = AniActor;
  AniActor = newActor;
  if (oldActor != nullptr) {
    oldActor->~CAniActor();
    ::operator delete(oldActor);
  }
}

/**
 * Address: 0x006ABB90 (FUN_006ABB90, ?SetPoses@Unit@Moho@@QAEXABV?$shared_ptr@VCAniPose@Moho@@@boost@@0@Z)
 *
 * What it does:
 * Copies prior/current shared animation poses into variable-data lanes and
 * mirrors them into `AniActor::{mPose,mPriorPose}`.
 */
void Unit::SetPoses(
  const boost::shared_ptr<CAniPose>& priorSharedPose,
  const boost::shared_ptr<CAniPose>& sharedPose
)
{
  SSTIUnitVariableData& varDat = VarDat();
  varDat.mSharedPose = sharedPose;
  varDat.mPriorSharedPose = priorSharedPose;

  const boost::SharedPtrRaw<CAniPose> sharedPoseRaw = boost::SharedPtrRawFromSharedBorrow(sharedPose);
  const boost::SharedPtrRaw<CAniPose> priorSharedPoseRaw = boost::SharedPtrRawFromSharedBorrow(priorSharedPose);
  // Routes through the out-of-line pair-assign helper emitted at 0x0063AA20
  // so the linker preserves that body's symbol against this caller.
  AniActor->AssignPoses(sharedPoseRaw, priorSharedPoseRaw);
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

/**
 * Address: 0x0062D780 (FUN_0062D780, Moho::Unit::CanStartBuilding)
 *
 * What it does:
 * Returns true when this unit's army economy can start a build tick from
 * stored resources or by satisfying required income gates.
 */
bool Unit::CanStartBuilding(const float energyCost, const float massCost) const
{
  constexpr float kBuildResourceEpsilon = 0.001f;

  if (ArmyRef == nullptr) {
    return false;
  }

  const CSimArmyEconomyInfo* const economyInfo = ArmyRef->GetEconomy();
  if (economyInfo == nullptr) {
    return false;
  }

  const SEconTotals& totals = economyInfo->economy;
  if (totals.mStored.ENERGY > kBuildResourceEpsilon && totals.mStored.MASS > kBuildResourceEpsilon) {
    return true;
  }

  const bool hasEnergyBudget = (energyCost <= 0.0f) || (totals.mIncome.ENERGY >= kBuildResourceEpsilon);
  const bool hasMassBudget = (massCost <= 0.0f) || (totals.mIncome.MASS >= kBuildResourceEpsilon);
  return hasEnergyBudget && hasMassBudget;
}

// 0x006A49D0
LuaPlus::LuaObject Unit::GetLuaObject()
{
  return mLuaObj;
}

/**
 * Address: 0x00603F10 (FUN_00603F10, Moho::Unit::DecrementCapturers)
 *
 * What it does:
 * Decrements the non-negative captor reference count at `CaptorCount`
 * (+0x690), clamped at zero. Returns the post-decrement count.
 */
std::int32_t Unit::DecrementCapturers()
{
  if (CaptorCount > 0) {
    --CaptorCount;
  }
  return CaptorCount;
}

/**
 * Address: 0x00603F30 (FUN_00603F30)
 *
 * What it does:
 * Returns the current non-negative captor reference count lane.
 */
std::int32_t Unit::GetCapturerCount() const noexcept
{
  return CaptorCount;
}

/**
 * Address: 0x005F24C0 (FUN_005F24C0)
 *
 * What it does:
 * Returns whether this unit belongs to the MELEE category lane.
 */
bool Unit::IsMeleeUnit() const noexcept
{
  return mIsMelee;
}

/**
 * Address: 0x005F5570 (FUN_005F5570)
 *
 * What it does:
 * Returns the current retaliation fire-state lane.
 */
std::int32_t Unit::GetFireStateValue() const noexcept
{
  return FireState;
}

/**
 * Address: 0x005F5560 (FUN_005F5560)
 *
 * What it does:
 * Stores one upgraded-unit entity id lane and returns that id.
 */
EntId Unit::SetUpgradedToEntityId(const EntId upgradedToEntityId) noexcept
{
  UpgradedToEntityId = upgradedToEntityId;
  return upgradedToEntityId;
}

/**
 * Address: 0x005F5590 (FUN_005F5590)
 *
 * What it does:
 * Returns the current silo-build implementation lane pointer.
 */
CAiSiloBuildImpl* Unit::GetSiloBuildImpl() const noexcept
{
  return AiSiloBuild;
}

/**
 * Address: 0x006A75C0 (FUN_006A75C0, ?GetMaxFootprintSize@Unit@Moho@@QBEHXZ)
 *
 * What it does:
 * Returns the larger side length of this unit's footprint (`sizeX`/`sizeZ`).
 */
int Unit::GetMaxFootprintSize() const
{
  const SFootprint& footprint = GetFootprint();
  const int sizeX = static_cast<int>(footprint.mSizeX);
  const int sizeZ = static_cast<int>(footprint.mSizeZ);
  return (sizeX >= sizeZ) ? sizeX : sizeZ;
}

/**
 * Address: 0x006A7640 (FUN_006A7640, Moho::Unit::SetFocusEntity)
 * Mangled: ?SetFocusEntity@Unit@Moho@@QAEXPAVEntity@2@@Z
 *
 * What it does:
 * Rebinds the focus-entity weak reference at +0x4D0, runs the
 * `OnAssignedFocusEntity` Lua callback when the slot now holds a live
 * target (non-null, non-sentinel), then unconditionally marks the unit
 * dirty for sync replication.
 */
void Unit::SetFocusEntity(Entity* const focusEntity)
{
  FocusEntityRef.ResetObjectPtr<Entity>(focusEntity);

  const WeakPtr<Entity>& focusLane = FocusEntityRef.AsWeakPtr<Entity>();
  if (focusLane.HasValue()) {
    RunScript(kUnitOnAssignedFocusEntityScript);
  }

  NeedSyncGameData = true;
}

/**
 * Address: 0x006A7680 (FUN_006A7680, ?SetTargetBlipEntity@Unit@Moho@@QAEXPAVEntity@2@@Z)
 *
 * What it does:
 * Rebinds target-blip weak-reference ownership and marks unit sync state
 * dirty for replication.
 */
void Unit::SetTargetBlipEntity(Entity* const blipEntity)
{
  TargetBlipEntityRef.AsWeakPtr<Entity>().Set(blipEntity);
  NeedSyncGameData = true;
}

/**
 * Address: 0x006A8B30 (FUN_006A8B30, ?CalcTransportLoadFactor@Unit@Moho@@UBEMXZ)
 *
 * What it does:
 * Returns cached transport load-factor for carried units; when the cache is
 * invalid (`< 0`), recomputes it from own mass and attached-unit masses.
 */
float Unit::CalcTransportLoadFactor() const
{
  if (GetTransportedBy() == nullptr) {
    return 1.0f;
  }

  if (TransportLoadFactor < 0.0f) {
    const RUnitBlueprint* const thisBlueprint = GetBlueprint();
    const float thisMass = thisBlueprint != nullptr
      ? (thisBlueprint->mAverageDensity * thisBlueprint->mSizeZ) * thisBlueprint->mSizeY * thisBlueprint->mSizeX
      : 0.0f;

    float attachedMass = 0.0f;
    if (thisMass > 0.0f) {
      for (Entity* const attachedEntity : mAttachedEntities) {
        Unit* const attachedUnit = attachedEntity != nullptr ? attachedEntity->IsUnit() : nullptr;
        if (attachedUnit == nullptr) {
          continue;
        }

        const RUnitBlueprint* const attachedBlueprint = attachedUnit->GetBlueprint();
        if (attachedBlueprint == nullptr) {
          continue;
        }

        attachedMass +=
          (attachedBlueprint->mAverageDensity * attachedBlueprint->mSizeZ) * attachedBlueprint->mSizeY *
          attachedBlueprint->mSizeX;
      }

      const_cast<Unit*>(this)->TransportLoadFactor = (attachedMass + thisMass) / thisMass;
    }
  }

  return TransportLoadFactor;
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
 * Address: 0x006A4BD0 (FUN_006A4BD0, Moho::Unit::GetUniformScale)
 *
 * What it does:
 * Returns display uniform scale from the unit blueprint lane.
 */
float Unit::GetUniformScale() const
{
  return GetBlueprint()->Display.UniformScale;
}

/**
 * Address: 0x006A9C90 (FUN_006A9C90, Moho::Unit::GetVelocity)
 *
 * What it does:
 * Returns motion velocity when a unit-motion lane is active on non-air
 * layers; otherwise computes per-tick position delta scaled by
 * `mVelocityScale`.
 */
Wm3::Vec3f Unit::GetVelocity() const
{
  if (UnitMotion != nullptr && mCurrentLayer != LAYER_Air) {
    Wm3::Vec3f velocity{};
    (void)UnitMotion->GetVelocity(&velocity);
    return velocity;
  }

  Wm3::Vec3f velocity{};
  velocity.x = (Position.x - PrevPosition.x) * mVelocityScale;
  velocity.y = (Position.y - PrevPosition.y) * mVelocityScale;
  velocity.z = (Position.z - PrevPosition.z) * mVelocityScale;
  return velocity;
}

/**
 * Address: 0x006A9350 (FUN_006A9350, Moho::Unit::AdjustHealth)
 *
 * What it does:
 * Forwards unit health adjustments to the shared `Entity` health mutation
 * path.
 */
void Unit::AdjustHealth(Entity* const instigator, const float delta)
{
  Entity::AdjustHealth(instigator, delta);
}

/**
 * Address: 0x006A9B50 (FUN_006A9B50, Moho::Unit::UpdateTerrainType)
 * Mangled: ?UpdateTerrainType@Unit@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
 *
 * What it does:
 * Samples terrain type under this unit's footprint-centered cell, updates
 * `CurrentTerrainType`, and dispatches terrain-change script data when it
 * changes.
 */
void Unit::UpdateTerrainType(const Wm3::Vector3f& position)
{
  STIMap* const mapData = SimulationRef->mMapData;
  const SFootprint& footprint = GetFootprint();

  const auto sampleX = static_cast<std::int16_t>(
    static_cast<std::int32_t>(position.x - (static_cast<float>(footprint.mSizeX) * 0.5f))
  );
  const auto sampleZ = static_cast<std::int16_t>(
    static_cast<std::int32_t>(position.z - (static_cast<float>(footprint.mSizeZ) * 0.5f))
  );

  const std::uint8_t previousTerrainType = CurrentTerrainType;
  std::uint8_t nextTerrainType = 1u;

  const CHeightField* const heightField = mapData->mHeightField.get();
  if (static_cast<std::uint32_t>(sampleX) < static_cast<std::uint32_t>(heightField->width - 1)
      && static_cast<std::uint32_t>(sampleZ) < static_cast<std::uint32_t>(heightField->height - 1)) {
    const std::size_t index =
      static_cast<std::size_t>(sampleZ) * static_cast<std::size_t>(mapData->mTerrainType.width)
      + static_cast<std::size_t>(sampleX);
    nextTerrainType = mapData->mTerrainType.data[index];
  }

  CurrentTerrainType = nextTerrainType;
  if (nextTerrainType == previousTerrainType) {
    return;
  }

  LuaPlus::LuaObject previousTerrain = mapData->GetTerrainType(previousTerrainType);
  LuaPlus::LuaObject currentTerrain = mapData->GetTerrainType(CurrentTerrainType);
  RunScriptOnTerrainTypeChange(currentTerrain, previousTerrain);
}

/**
 * Address: 0x006A9A40 (FUN_006A9A40, Moho::Unit::HandleTerranEffects)
 *
 * What it does:
 * Reads terrain-type Lua data for this unit, applies periodic
 * `HealthEffectPerSecond` scaling against max health every 10 ticks, and
 * kills the unit when health reaches zero.
 */
void Unit::HandleTerranEffects()
{
  LuaPlus::LuaObject terrainType = SimulationRef->mMapData->GetTerrainType(CurrentTerrainType);
  if (!terrainType.IsTable()) {
    return;
  }

  if ((SimulationRef->mCurTick % 10u) != 0u) {
    return;
  }

  LuaPlus::LuaObject healthEffect = terrainType["HealthEffectPerSecond"];
  if (healthEffect.IsNil()) {
    return;
  }

  const float delta = healthEffect.GetNumber() * MaxHealth;
  AdjustHealth(nullptr, delta);
  if (Health <= 0.0f) {
    Kill(nullptr, "", 0.0f);
  }
}

/**
 * Address: 0x006AB520 (FUN_006AB520, Moho::Unit::UpdateCollision)
 *
 * What it does:
 * Pushes current transform into the active collision primitive, widens
 * box-shape X/Z extents to include blueprint skirt dimensions, and then
 * forwards to `Entity::UpdateCollision` for relink and bounds refresh.
 */
void Unit::UpdateCollision()
{
  if (CollisionExtents == nullptr) {
    return;
  }

  const EntityTransformPayload current = ReadEntityTransformPayload(Orientation, Position);
  CollisionExtents->SetTransform(current);

  if (const Wm3::Box3f* const existingBox = CollisionExtents->GetBox(); existingBox != nullptr) {
    const RUnitBlueprint* const blueprint = GetBlueprint();
    if (blueprint != nullptr) {
      Wm3::Box3f expandedBox(*existingBox);

      const float skirtExtentX = std::fabs(blueprint->Physics.SkirtOffsetX) + blueprint->Physics.SkirtSizeX;
      const float skirtExtentZ = std::fabs(blueprint->Physics.SkirtOffsetZ) + blueprint->Physics.SkirtSizeZ;

      expandedBox.Extent[0] = 0.5f * std::max(blueprint->mSizeX, skirtExtentX);
      expandedBox.Extent[2] = 0.5f * std::max(blueprint->mSizeZ, skirtExtentZ);

      static_cast<BoxCollisionPrimitive*>(CollisionExtents)->mShape = expandedBox;
    }
  }

  Entity::UpdateCollision();
}

/**
 * Address: 0x006ABC30 (FUN_006ABC30, Moho::Unit::UpdateVisibility)
 *
 * What it does:
 * Recomputes base entity visibility lanes, then keeps unit visibility enabled
 * only for the focused army or when no army is focused.
 */
void Unit::UpdateVisibility()
{
  Entity::UpdateVisibility();
  const std::int32_t focusArmy = SimulationRef->mSyncFilter.focusArmy;
  mVisibilityState = static_cast<std::uint8_t>(focusArmy == -1 || focusArmy == ArmyRef->ArmyId);
}

/**
 * Address: 0x006AB410 (FUN_006AB410, ?AttachTo@Unit@Moho@@UAE_NABUSEntAttachInfo@2@@Z)
 *
 * What it does:
 * Attaches through `Entity::AttachTo`, then (for mobile units) notifies unit
 * motion and sets attached-state bit; resets cached transport load factor.
 */
bool Unit::AttachTo(const SEntAttachInfo& attachInfo)
{
  if (!Entity::AttachTo(attachInfo)) {
    return false;
  }

  if (IsMobile()) {
    UnitMotion->NotifyAttached(attachInfo);
    UnitStateMask |= (1ull << static_cast<std::uint32_t>(UNITSTATE_Attached));
  }

  TransportLoadFactor = -1.0f;
  return true;
}

/**
 * Address: 0x006AB480 (FUN_006AB480, ?DetachFrom@Unit@Moho@@UAE_NPAVEntity@2@_N@Z)
 *
 * What it does:
 * Detaches through `Entity::DetachFrom`, then (for mobile units) notifies unit
 * motion and clears attached-state bit; resets cached transport load factor
 * and unlinks the transport weak-pointer chain.
 */
bool Unit::DetachFrom(Entity* const parent, const bool skipBallistic)
{
  if (!Entity::DetachFrom(parent, skipBallistic)) {
    return false;
  }

  if (IsMobile()) {
    UnitMotion->NotifyDetached(parent, skipBallistic);
    UnitStateMask &= ~(1ull << static_cast<std::uint32_t>(UNITSTATE_Attached));
  }

  TransportLoadFactor = -1.0f;
  TransportedByRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
  return true;
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
  const Wm3::Quaternionf rollRotation = Wm3::Quaternionf::MakeFromAxisAngle(upAxis, impulse.y * 0.1f);

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
 * Address: 0x006D3A40 (FUN_006D3A40, Moho::Unit::CalcBombDrop)
 *
 * What it does:
 * Scales current world velocity by ten ticks and resolves one ballistic
 * drop-point lane against `targetPosition` using sim gravity.
 */
Wm3::Vec3f* Unit::CalcBombDrop(Wm3::Vec3f* const out, const Wm3::Vec3f& targetPosition) const
{
  Wm3::Vec3f velocity = Entity::GetVelocity();
  velocity.x *= 10.0f;
  velocity.y *= 10.0f;
  velocity.z *= 10.0f;

  return ComputeBombDropAimPoint(
    velocity,
    out,
    SimulationRef->mPhysConstants->mGravity,
    targetPosition,
    GetPosition()
  );
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
 * Address: 0x006A9D60 (FUN_006A9D60, ?ProcessArmorOnDamage@Unit@Moho@@QBEMMV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
 *
 * What it does:
 * Applies one armor multiplier lane to incoming damage when the incoming
 * damage-type token exists in `ArmorMultipliers`.
 */
float Unit::ProcessArmorOnDamage(const float amount, const msvc8::string damageType) const
{
  float scaledAmount = amount;
  if (const SArmorMultiplierMapNode* const match =
        FindArmorMultiplierNode(ArmorMultipliers, std::string_view(damageType.c_str()));
      match != nullptr) {
    scaledAmount *= match->armorMultiplier;
  }

  return scaledAmount;
}

/**
 * Address: 0x006A9E10 (FUN_006A9E10, Moho::Unit::GetArmorMult)
 *
 * What it does:
 * Returns this unit's armor multiplier for one damage type. A damage type the
 * blueprint never listed returns 1.0, so it passes through unmodified.
 */
float Unit::GetArmorMult(const msvc8::string& damageType) const
{
  if (const SArmorMultiplierMapNode* const match =
        FindArmorMultiplierNode(ArmorMultipliers, std::string_view(damageType.c_str()));
      match != nullptr) {
    return match->armorMultiplier;
  }

  return 1.0f;
}


/**
 * Address: 0x006A9F40 (FUN_006A9F40, Moho::Unit::Materialize)
 * Slot: 29 of ??_7Unit@Moho@@6BEntity@Moho@@@ (0x00E2A5EC)
 *
 * What it does:
 * Advances construction by `delta` and scales health to match. See the header
 * for the completion side effects.
 *
 * The declared float result is never produced: the epilogue at 0x006AA2F2
 * loads a frame slot the body never writes, and every call site discards it.
 * `Entity` declares this slot as returning float so the signature keeps it;
 * 0.0f is returned to keep the function well-defined.
 */
float Unit::Materialize(const float delta)
{
  SimulationRef->Logf(
    "Unit[0x%08x]->Materialize(%.5f [0x%08x])\n", static_cast<std::uint32_t>(id_), delta, delta
  );

  // Any non-reversing step restamps the creation tick, so a unit dates from
  // when it finished rather than when it was placed.
  if (delta >= 0.0f) {
    mCreationTick = static_cast<std::int32_t>(SimulationRef->mCurTick);
  }

  if (delta == 0.0f) {
    return 0.0f;
  }

  const float stepped = FractionCompleted + delta;
  if (delta <= 0.0f) {
    FractionCompleted = std::clamp(stepped, 0.0f, 1.0f);
  } else {
    float progressed = (stepped < 1.0f) ? stepped : 1.0f;
    if (progressed < 0.0f) {
      progressed = 0.0f;
    }
    // Never report less complete than the health already implies - health runs
    // ahead of the fraction when a part-built unit is repaired.
    const float healthRatio = Health / MaxHealth;
    FractionCompleted = (healthRatio > progressed) ? healthRatio : progressed;
  }

  AdjustHealth(nullptr, MaxHealth * delta);

  if (BeingBuilt == 0u || FractionCompleted != 1.0f) {
    return 0.0f;
  }

  VarDat().mUnitStates &= ~(1ull << UNITSTATE_BeingBuilt);
  BeingBuilt = 0u;

  const char* const layerName = (static_cast<unsigned int>(mCurrentLayer) > LAYER_Orbit)
                                  ? ""
                                  : Entity::LayerToString(mCurrentLayer);
  RunScriptOnStopBeingBuilt(CreatorRef.AsWeakPtr<Unit>(), layerName);

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint != nullptr && blueprint->General.CapCost > 0.0f) {
    if (CArmyStats* const armyStats = (ArmyRef != nullptr) ? ArmyRef->GetArmyStats() : nullptr;
        armyStats != nullptr) {
      const std::int32_t one = 1;
      IncrementArmyBlueprintFloatStat(armyStats, "Units_Active", blueprint, 1.0f);
      (void)armyStats->UpdateUnitStat("Units_Active", &one);
      IncrementArmyBlueprintFloatStat(armyStats, "Units_History", blueprint, 1.0f);
      (void)armyStats->UpdateUnitStat("Units_History", &one);

      // Booked at blueprint cost, not at what the builder actually spent.
      float massCost = blueprint->Economy.BuildCostMass;
      float energyCost = blueprint->Economy.BuildCostEnergy;
      (void)AddArmyStatFloatByName(armyStats, &massCost, "Units_MassValue_Built");
      (void)AddArmyStatFloatByName(armyStats, &energyCost, "Units_EnergyValue_Built");

      IncrementArmyBlueprintFloatStat(armyStats, "Units_BeingBuilt", blueprint, -1.0f);
    }
  }

  // Adjacency is a structure concept; mobile units never bond to neighbours.
  if (!IsMobile()) {
    SEntitySetTemplateUnit overlapping{};
    (void)CollectAllOverlapping(&overlapping, this);
    for (Entity* const entry : overlapping.mVec) {
      Unit* const neighbour = SEntitySetTemplateUnit::UnitFromEntry(entry);
      if (neighbour == nullptr) {
        continue;
      }
      // Both directions: each side gets told about the other.
      RunScriptOnAdjacentTo(neighbour, this);
      neighbour->RunScriptOnAdjacentTo(this, this);
    }
  }

  return 0.0f;
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
 * Address: 0x005F0E80 (FUN_005F0E80, Moho::Unit::NeedsPickup)
 *
 * What it does:
 * Estimates whether assisting `task->mUnit` should switch to pickup by
 * comparing this unit's goal ETA against assisted-unit interception ETA.
 */
bool Unit::NeedsPickup(const CUnitAssistMoveTask* const task) const
{
  if (IsUnitState(UNITSTATE_ProblemGettingToGoal)) {
    return true;
  }

  const Unit* const assistedUnit = task ? task->mUnit : nullptr;
  if (assistedUnit == nullptr) {
    return false;
  }

  const RUnitBlueprint* const assistedBlueprint = assistedUnit->GetBlueprint();
  const float assistedMaxSpeed =
    (assistedBlueprint->Air.CanFly != 0u) ? assistedBlueprint->Air.MaxAirspeed : assistedBlueprint->Physics.MaxSpeed;
  if (assistedMaxSpeed < 0.001f) {
    return false;
  }

  const RUnitBlueprint* const selfBlueprint = GetBlueprint();
  const float selfMaxSpeed = (selfBlueprint->Air.CanFly != 0u) ? selfBlueprint->Air.MaxAirspeed : selfBlueprint->Physics.MaxSpeed;
  if (selfMaxSpeed < 0.001f) {
    return false;
  }

  const IAiNavigator* const navigator = AiNavigator;
  if (navigator == nullptr) {
    return false;
  }

  const Wm3::Vec3f& selfPosition = GetPosition();
  const Wm3::Vector3f goalPosition = navigator->GetGoalPos();
  const float goalDx = goalPosition.x - selfPosition.x;
  const float goalDz = goalPosition.z - selfPosition.z;
  const float goalDistance = std::sqrt((goalDx * goalDx) + (goalDz * goalDz));
  const float goalTime = goalDistance / selfMaxSpeed;

  const Wm3::Vec3f& assistedPosition = assistedUnit->GetPosition();
  const float taskDx = assistedPosition.x - selfPosition.x;
  const float taskDz = assistedPosition.z - selfPosition.z;
  const float taskDistance = std::sqrt((taskDx * taskDx) + (taskDz * taskDz));

  float pickupEta = ((taskDistance + goalDistance) / assistedMaxSpeed) + 5.0f;
  if (assistedUnit->mCurrentLayer == LAYER_Air || taskDistance > selfBlueprint->AI.GuardScanRadius) {
    pickupEta += 4.0f;
  } else {
    pickupEta += taskDistance / selfMaxSpeed;
  }

  return goalTime > pickupEta;
}

/**
 * Address: 0x006A7D60 (FUN_006A7D60, ?IsIdleState@Unit@Moho@@QBE_NXZ)
 *
 * What it does:
 * Returns true when the command queue has no valid head command.
 */
bool Unit::IsIdleState() const
{
  const CUnitCommandQueue* const commandQueue = CommandQueue;
  if (commandQueue == nullptr || commandQueue->mCommandVec.empty()) {
    return true;
  }

  const CUnitCommand* const headCommand = commandQueue->mCommandVec.front().GetObjectPtr();
  return headCommand == nullptr || reinterpret_cast<std::uintptr_t>(headCommand) == kInvalidWeakCommandSentinel;
}

/**
 * Address: 0x0062F030 (FUN_0062F030, Moho::Unit::FindPlatform)
 *
 * IDA signature:
 * Moho::Unit* __usercall FindPlatform@<eax>(Moho::Unit* this@<ecx>, int @<ebx>);
 *
 * What it does:
 * For an air unit needing refuel/repair (and not its own formation lead),
 * scans the owning army's AIRSTAGINGPLATFORM units for the first idle,
 * in-bounds transport within staging-platform scan radius that can receive
 * this unit. Returns that platform, or null.
 */
Unit* Unit::FindPlatform()
{
  // Guard: alive flying unit, fueled (or no motor), with the refuel-order cap.
  if (IsDead()) {
    return nullptr;
  }
  if (!GetBlueprint()->Air.CanFly) {
    return nullptr;
  }
  if (UnitMotion != nullptr && FuelRatio < 0.0f) {
    return nullptr;
  }
  if ((GetAttributes().commandCapsMask & 0x400000u) == 0u) {
    return nullptr;
  }

  // Skip if this unit is its own formation lead.
  if (IUnit* const formationLead = mInfoCache.mFormationLeadRef.ResolveObjectPtr<IUnit>();
      formationLead != nullptr && formationLead->IsUnit() == this) {
    return nullptr;
  }

  // Need refuel: threshold ratio exceeds current fuel ratio.
  const float fuelRatio = FuelRatio;
  bool needsService = false;
  if (CSimConVarBase* const needRefuelDef = GetNeedRefuelThresholdRatioSimConVarDef();
      needRefuelDef != nullptr) {
    if (CSimConVarInstanceBase* const needRefuel = SimulationRef->GetSimVar(needRefuelDef);
        needRefuel != nullptr) {
      needsService = *static_cast<const float*>(needRefuel->GetValueStorage()) > fuelRatio;
    }
  }
  // Need repair: threshold ratio exceeds (maxHealth / health).
  if (!needsService) {
    const float health = Health;
    const float maxHealth = MaxHealth;
    if (CSimConVarBase* const needRepairDef = GetNeedRepairThresholdRatioSimConVarDef();
        needRepairDef != nullptr) {
      if (CSimConVarInstanceBase* const needRepair = SimulationRef->GetSimVar(needRepairDef);
          needRepair != nullptr) {
        needsService = *static_cast<const float*>(needRepair->GetValueStorage()) > (maxHealth / health);
      }
    }
  }
  if (!needsService) {
    return nullptr;
  }

  RRuleGameRules* const rules = SimulationRef->mRules;
  const EntityCategorySet* const stagingPlatformCategory = rules->GetEntityCategory("AIRSTAGINGPLATFORM");
  const EntityCategorySet* const carrierCategory = rules->GetEntityCategory("CARRIER");

  EntitySetTemplate<Entity> stagingPlatforms;
  ArmyRef->GetUnits(&stagingPlatforms, const_cast<EntityCategorySet*>(stagingPlatformCategory));

  for (Entity* const platformEntity : stagingPlatforms) {
    if (platformEntity == nullptr) {
      continue;
    }
    Unit* const platform = static_cast<Unit*>(platformEntity);
    if (platform->IsDead() || platform->IsBeingBuilt() || platform->DestroyQueued()) {
      continue;
    }
    IAiTransport* const transport = platform->AiTransport;
    if (transport == nullptr) {
      continue;
    }

    const Wm3::Vec3f& platformPos = platform->GetPosition();
    const Wm3::Vec3f& selfPos = GetPosition();
    const float dz = selfPos.z - platformPos.z;
    const float dx = selfPos.x - platformPos.x;
    const float distance = std::sqrt(dz * dz + dx * dx);
    if (distance > platform->GetBlueprint()->AI.StagingPlatformScanRadius) {
      continue;
    }
    if (!platform->IsInBounds(ArmyRef->UseWholeMap(), 1.0f)) {
      continue;
    }
    if (!platform->IsIdleState()) {
      continue;
    }
    const ELayer platformLayer = platform->mCurrentLayer;
    if (platformLayer == LAYER_Seabed || platformLayer == LAYER_Sub) {
      continue;
    }

    if (EntityCategory::HasBlueprint(platform->GetBlueprint(), carrierCategory)) {
      if (transport->TransportHasAvailableStorage()) {
        return platform;
      }
    } else if (transport->TransportHasSpaceFor(GetBlueprint())) {
      return platform;
    }
  }

  return nullptr;
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
 * Address: 0x006AD060 (FUN_006AD060,
 *   ?GetBlipsInRange@Unit@Moho@@QAEAAV?$fastvector_n@V?$WeakPtr@VEntity@Moho@@@Moho@@$0BE@@gpg@@I@Z)
 *
 * IDA signature:
 * gpg::fastvector_n20_WeakPtr_Entity *__userpurge GetBlipsInRange@<eax>(
 *   Moho::Unit *this@<esi>, unsigned int interval);
 *
 * What it does:
 * Refreshes `mBlipsInRange` via `UpdateBlipsInRange()` when it is at least
 * `maxAgeTicks` ticks stale (current sim tick minus the last update tick, as an
 * unsigned compare), then returns a reference to the cached list.
 */
gpg::core::FastVectorN<SWeakRefSlot, 20>& Unit::GetBlipsInRange(const unsigned int maxAgeTicks)
{
  const unsigned int ticksSinceUpdate =
    SimulationRef->mCurTick - static_cast<unsigned int>(mBlipLastUpdateTick);
  if (ticksSinceUpdate >= maxAgeTicks) {
    UpdateBlipsInRange();
  }
  return mBlipsInRange;
}

/**
 * Address: 0x006ACC60 (FUN_006ACC60, ?UpdateBlipsInRange@Unit@Moho@@QAEXXZ)
 *
 * IDA signature:
 * void __stdcall Moho::Unit::UpdateBlipsInRange(Moho::Unit *this);
 *
 * What it does:
 * Rebuilds `mBlipsInRange` (see the field-by-field walk in the header). Computes
 * the effective scan radius (guard-scan blueprint radius when the head command is
 * a guard/patrol command, extended by the attacker's max weapon range), gathers
 * enemy units in that radius via `COGrid::EntitiesAroundPoint`, keeps those the
 * army can see as recon blips and (when set) within the army no-rush radius,
 * records a weak reference to each, and additionally records the jamming-shadow
 * blips of any candidate whose intel manager has active jamming. Finally stamps
 * `mBlipLastUpdateTick` with the current sim tick.
 */
void Unit::UpdateBlipsInRange()
{
  const RUnitBlueprint* const blueprint = GetBlueprint();
  CAiAttackerImpl* const attacker = AiAttacker;

  // Guard-scan radius: zero unless the head command is a guard/patrol command
  // (mVarDat flag bits 0x30), in which case use the blueprint guard-scan radius.
  float scanRadius = 0.0f;
  CUnitCommand* const headCommand = CommandQueue->GetCurrentCommand();
  if (headCommand != nullptr && (headCommand->mVarDat.v2 & 0x30) != 0) {
    scanRadius = blueprint->AI.GuardScanRadius;
  }

  // Extend the scan radius by the attacker's max weapon range.
  if (attacker != nullptr) {
    const float maxWeaponRange = attacker->GetMaxWeaponRange();
    if (maxWeaponRange > scanRadius) {
      scanRadius = maxWeaponRange;
    }
  }

  // No-rush centre = army start position + configured no-rush offset; used to
  // reject blips outside the no-rush radius while the no-rush timer is active.
  CArmyImpl* const army = ArmyRef;
  const float noRushOffsetX = army->NoRushOffsetX;
  const float noRushOffsetY = army->NoRushOffsetY;
  Wm3::Vector2f armyStartPosition{};
  army->GetArmyStartPos(armyStartPosition);
  const float noRushCenterX = armyStartPosition.x + noRushOffsetX;
  const float noRushCenterZ = armyStartPosition.y + noRushOffsetY;
  const float noRushRadius = army->NoRushRadius;

  // Gather every unit within the scan radius of this unit's position.
  CollisionResultFastVectorN10 unitsInRange{};
  COGrid* const grid = SimulationRef->mOGrid;
  EntitiesAroundPoint(unitsInRange, scanRadius, *grid, ENTITYTYPE_Unit, GetPosition());

  // Reset the blip list: unlink every currently-held weak reference from its
  // owner chain, release escaped heap storage, and rebind to inline storage.
  UnlinkWeakPtrRangeWithoutClearing(
    reinterpret_cast<WeakPtr<void>*>(mBlipsInRange.begin()),
    reinterpret_cast<WeakPtr<void>*>(mBlipsInRange.end())
  );
  mBlipsInRange.ResetStorageToInline();

  for (const CollisionResult& hit : unitsInRange) {
    Entity* const candidate = hit.sourceEntity;
    if (candidate == nullptr || candidate->Dead != 0u) {
      continue;
    }

    Unit* const candidateUnit = candidate->IsUnit();
    if (candidateUnit == nullptr || candidate->DestroyQueuedFlag != 0u) {
      continue;
    }

    CArmyImpl* const candidateArmy = candidate->ArmyRef;
    const std::uint32_t candidateArmyIndex =
      (candidateArmy != nullptr) ? static_cast<std::uint32_t>(candidateArmy->ArmyId) : 0xFFFFFFFFu;
    // IArmy::IsAlly (FUN_005BD630) is shadowed on CArmyImpl by the same-named
    // cached byte field (+0x128); its body is the allies bit-set membership
    // test, replicated here via the shared `Set::Contains` helper.
    if (army->Allies.Contains(candidateArmyIndex)) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    ReconBlip* const blip = (reconDb != nullptr) ? reconDb->ReconGetBlip(candidateUnit) : nullptr;
    if (blip == nullptr) {
      continue;
    }

    if (army->NoRushTicks > 0) {
      const float deltaX = noRushCenterX - candidate->Position.x;
      const float deltaZ = noRushCenterZ - candidate->Position.z;
      const float distance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
      if (distance > noRushRadius) {
        continue;
      }
    }

    // Record a weak reference to the visible enemy.
    WeakPtr<Entity> blipRef(candidate);
    mBlipsInRange.push_back(reinterpret_cast<const SWeakRefSlot&>(blipRef));

    // When the candidate is actively jamming, also record its shadow blips.
    if (candidateUnit->mIntelManager->HasActiveJamming()) {
      EntitySetTemplate<Entity> jammingBlips = army->GetReconDB()->ReconGetJamingBlips(candidateUnit);
      for (Entity* const jammingEntity : jammingBlips) {
        WeakPtr<Entity> jammingRef(jammingEntity);
        mBlipsInRange.push_back(reinterpret_cast<const SWeakRefSlot&>(jammingRef));
      }
    }
  }

  mBlipLastUpdateTick = static_cast<std::int32_t>(SimulationRef->mCurTick);
}

/**
 * Address: 0x006A76A0 (FUN_006A76A0, Moho::Unit::SetGuardedUnit)
 *
 * What it does:
 * Rebinds guarded-unit weak-link ownership, updates guarded-by slot lanes on
 * old/new guarded units, clears stale guard-formation lanes, and marks this
 * unit sync-dirty.
 */
void Unit::SetGuardedUnit(Unit* const guarded)
{
  Unit* const oldGuardedUnit = GuardedUnitRef.ResolveObjectPtr<Unit>();
  if (oldGuardedUnit != nullptr) {
    (void)RemoveGuardedByOwner(oldGuardedUnit->GuardedByList, this);
    ClearGuardFormation(oldGuardedUnit);
  }

  GuardedUnitRef.AsWeakPtr<Unit>().Set(guarded);

  Unit* const newGuardedUnit = GuardedUnitRef.ResolveObjectPtr<Unit>();
  if (newGuardedUnit != nullptr) {
    AddGuardedByOwner(newGuardedUnit->GuardedByList, this);
    ClearGuardFormation(newGuardedUnit);
  }

  NeedSyncGameData = true;
}

/**
 * Address: 0x006AA720 (FUN_006AA720, ?RemoveGuardedByUnit@Unit@Moho@@AAEXPAV12@@Z)
 * Mangled: ?RemoveGuardedByUnit@Unit@Moho@@AAEXPAV12@@Z
 *
 * What it does:
 * Inserts one guarding owner into this unit's guarded-by list when non-null,
 * then clears this unit's guard-formation lane.
 */
void Unit::RemoveGuardedByUnit(Unit* const guardedByUnit)
{
  if (guardedByUnit != nullptr) {
    AddGuardedByOwner(GuardedByList, guardedByUnit);
  }

  ClearGuardFormation(this);
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
 * Address: 0x005F0980 (FUN_005F0980, Moho::Unit::GetFerryUnit)
 *
 * IDA signature:
 * Moho::Unit *__usercall Moho::Unit::GetFerryUnit@<eax>(Moho::Unit *a1@<eax>);
 *
 * What it does:
 * Returns the unit currently bound to this unit's assigned-transport weak
 * lane (Unit +0x4C8). Identical accessor body to the binary's tiny FUN_005F0980
 * thunk: load the slot, return owner-decoded pointer or null on sentinel.
 */
Unit* Unit::GetFerryUnit() const
{
  return AssignedTransportRef.ResolveObjectPtr<Unit>();
}

/**
 * Address: 0x0060DAD0 (FUN_0060DAD0, Moho::Unit::SetAssignedTransport)
 *
 * What it does:
 * Rebinds this unit's assigned-transport weak-reference lane.
 */
void Unit::SetAssignedTransport(Unit* const assignedTransport)
{
  AssignedTransportRef.AsWeakPtr<Unit>().Set(assignedTransport);
}

/**
 * Address: 0x006A8890 (FUN_006A8890, Moho::Unit::GetTransportFerryBeacon)
 *
 * What it does:
 * Returns ferry-beacon unit ownership from the current command-queue head
 * command when the weak unit lane resolves to a live unit.
 */
Unit* Unit::GetTransportFerryBeacon() const
{
  const CUnitCommandQueue* const commandQueue = CommandQueue;
  if (commandQueue == nullptr || commandQueue->mCommandVec.empty()) {
    return nullptr;
  }

  const CUnitCommand* const command = commandQueue->mCommandVec.front().GetObjectPtr();
  if (command == nullptr || reinterpret_cast<std::uintptr_t>(command) == kInvalidWeakCommandSentinel) {
    return nullptr;
  }

  return command->mUnit.GetObjectPtr();
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
 * Address: 0x006AD5D0 (FUN_006AD5D0, ?SerEconomyEvents@Unit@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 *
 * What it does:
 * Reads tracked owned `CEconomyEvent*` lanes until a null terminator is read,
 * unlinking each loaded event node from its prior ring and linking it into
 * this unit's event-list head.
 */
void Unit::SerEconomyEvents(gpg::ReadArchive& archive, const int)
{
  CEconomyEvent* economyEvent = nullptr;
  gpg::RRef ownerRef{};
  archive.ReadPointerOwned_CEconomyEvent(&economyEvent, &ownerRef);

  while (economyEvent != nullptr) {
    economyEvent->mUnitEventNode.ListLinkBefore(&mEconomyEventListHead);
    economyEvent = nullptr;
    ownerRef = gpg::RRef{};
    archive.ReadPointerOwned_CEconomyEvent(&economyEvent, &ownerRef);
  }
}

/**
 * Address: 0x006AD540 (FUN_006AD540, ?SerEconomyEvents@Unit@Moho@@ABEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Serializes unit-owned economy-event pointer lanes as tracked owned pointers,
 * then writes a null terminator pointer lane.
 */
void Unit::SerEconomyEvents(gpg::WriteArchive& archive, const int) const
{
  const TDatListItem<void, void>* const listHead = &mEconomyEventListHead;
  for (TDatListItem<void, void>* node = mEconomyEventListHead.mNext; node != listHead; node = node->mNext) {
    gpg::RRef eventOwnerRef{};
    gpg::RRef eventRef{};
    gpg::RRef_CEconomyEvent(&eventRef, EconomyEventFromNode(node));
    gpg::WriteRawPointer(&archive, eventRef, gpg::TrackedPointerState::Owned, eventOwnerRef);
  }

  gpg::RRef tailOwnerRef{};
  gpg::RRef nullRef{};
  gpg::RRef_CEconomyEvent_P(&nullRef, nullptr);
  gpg::WriteRawPointer(&archive, nullRef, gpg::TrackedPointerState::Owned, tailOwnerRef);
}

/**
 * Address: 0x0062D2B0 (FUN_0062D2B0, Moho::Unit::OverlapsWith)
 *
 * What it does:
 * Returns true when this unit skirt rectangle overlaps `other` using the
 * original 1.0f edge-contact tolerance checks.
 */
bool Unit::OverlapsWith(Unit* const other) const
{
  if (other == nullptr || IsDead() || other->IsDead()) {
    return false;
  }

  const gpg::Rect2f thisSkirt = GetSkirtRect();
  const gpg::Rect2f otherSkirt = other->GetSkirtRect();

  const float xEdgeDelta0 = std::fabs(thisSkirt.x0 - otherSkirt.x1);
  const float xEdgeDelta1 = std::fabs(thisSkirt.x1 - otherSkirt.x0);
  const bool xEdge0WithinTolerance = xEdgeDelta0 >= 0.0f && xEdgeDelta0 < 1.0f;
  const bool xEdge1WithinTolerance = xEdgeDelta1 >= 0.0f && xEdgeDelta1 < 1.0f;

  if (xEdge0WithinTolerance || xEdge1WithinTolerance) {
    return (thisSkirt.z0 >= otherSkirt.z0 && otherSkirt.z1 >= thisSkirt.z1) ||
      (otherSkirt.z0 >= thisSkirt.z0 && thisSkirt.z1 >= otherSkirt.z1);
  }

  const float yEdgeDelta0 = std::fabs(thisSkirt.z0 - otherSkirt.z1);
  const float yEdgeDelta1 = std::fabs(thisSkirt.z1 - otherSkirt.z0);
  const bool yEdge0WithinTolerance = yEdgeDelta0 >= 0.0f && yEdgeDelta0 < 1.0f;
  const bool yEdge1WithinTolerance = yEdgeDelta1 >= 0.0f && yEdgeDelta1 < 1.0f;

  if (!(yEdge0WithinTolerance || yEdge1WithinTolerance)) {
    return false;
  }

  return (thisSkirt.x0 >= otherSkirt.x0 && otherSkirt.x1 >= thisSkirt.x1) ||
    (otherSkirt.x0 >= thisSkirt.x0 && thisSkirt.x1 >= otherSkirt.x1);
}

/**
 * Address: 0x006A8C20 (FUN_006A8C20, Moho::Unit::GetFormationVector)
 *
 * What it does:
 * Resolves one unit movement vector from formation runtime lanes, with
 * air-leader fallback to leader forward heading when applicable.
 */
Wm3::Vector3f Unit::GetFormationVector() const
{
  Wm3::Vector3f result{0.0f, 0.0f, 0.0f};

  if (IsUnitState(UNITSTATE_TransportLoading) || IsUnitState(UNITSTATE_Refueling) ||
      mInfoCache.mFormationLayer == nullptr) {
    return result;
  }

  if (mIsAir) {
    const Unit* const formationLead = mInfoCache.mFormationLeadRef.ResolveObjectPtr<Unit>();
    if (formationLead != nullptr && !formationLead->mIsAir) {
      return ForwardXZ(*formationLead);
    }
  }

  const auto* const formationLayer = reinterpret_cast<const CAiFormationInstance*>(mInfoCache.mFormationLayer);
  if (formationLayer != nullptr && formationLayer->CommandIsForm()) {
    formationLayer->Func19(&result, const_cast<Unit*>(this));
  }

  return result;
}

/**
 * Address: 0x006A9720 (FUN_006A9720, Moho::Unit::GetFormation)
 *
 * What it does:
 * Resolves active formation ownership either from guarded-unit formation lane
 * or from the current command queue head command.
 */
IFormationInstance* Unit::GetFormation() const
{
  Unit* const guardedUnit = GuardedUnitRef.ResolveObjectPtr<Unit>();
  if (guardedUnit != nullptr && !mIsEngineer) {
    if (IsUnitState(UNITSTATE_GuardBusy)) {
      return nullptr;
    }

    return guardedUnit->GuardFormation;
  }

  const CUnitCommandQueue* const commandQueue = CommandQueue;
  if (commandQueue != nullptr && !commandQueue->mCommandVec.empty()) {
    CUnitCommand* const currentCommand = commandQueue->mCommandVec.front().GetObjectPtr();
    if (currentCommand != nullptr) {
      CAiFormationInstance* const commandFormation = currentCommand->mFormationInstance;
      if (commandFormation != nullptr && commandFormation->Func17(const_cast<Unit*>(this), true)) {
        return commandFormation;
      }
    }
  }

  return nullptr;
}

/**
 * Address: 0x006A9810 (FUN_006A9810, Moho::Unit::UpdateInfoCache)
 *
 * What it does:
 * Refreshes cached formation-owner/speed lanes and recomputes movement top
 * speed for mobile units.
 */
void Unit::UpdateInfoCache()
{
  if (!IsMobile()) {
    return;
  }

  CAiFormationInstance* const formation = reinterpret_cast<CAiFormationInstance*>(GetFormation());
  SFormationLaneEntry* laneEntry = nullptr;

  if (formation != nullptr && formation->CommandIsForm() && formation->Func17(this, false)) {
    laneEntry = formation->Func6(this);
    mInfoCache.mFormationLayer = reinterpret_cast<CFormationInstance*>(formation);
    mInfoCache.mHasFormationSpeedData = formation->Func21(this);

    Unit* const formationLead = formation->Func14(this, laneEntry);
    mInfoCache.mFormationLeadRef.AsWeakPtr<Unit>().Set(formationLead);

    Wm3::Vec3f headingHint{};
    formation->Func10(&headingHint, this, laneEntry);
    mInfoCache.mFormationHeadingHint = headingHint;
    mInfoCache.mFormationDistanceMetric = formation->Func11(this, laneEntry);
    mInfoCache.mFormationPriorityOrder = formation->Func12(this, laneEntry);
  } else {
    mInfoCache.mFormationLayer = nullptr;
    mInfoCache.mHasFormationSpeedData = true;
    mInfoCache.mFormationLeadRef.AsWeakPtr<Unit>().Set(nullptr);
    mInfoCache.mFormationHeadingHint = GetPosition();
    mInfoCache.mFormationDistanceMetric = 0.0f;
    mInfoCache.mFormationPriorityOrder = 0;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint == nullptr) {
    mInfoCache.mFormationTopSpeed = 0.0f;
    return;
  }

  const float speedMult = GetAttributes().moveSpeedMult;
  float topSpeed = 0.0f;
  if (!blueprint->Air.CanFly) {
    topSpeed = blueprint->Physics.MaxSpeed * speedMult;
  } else {
    topSpeed = (blueprint->Air.MaxAirspeed * speedMult) / CalcTransportLoadFactor();
  }

  float speedScale = 1.0f;
  float clampedFormationSpeed = topSpeed;
  if (formation != nullptr && laneEntry != nullptr) {
    const float formationSpeed = formation->CalcFormationSpeed(this, &speedScale, laneEntry);
    if (formationSpeed > 0.0f) {
      clampedFormationSpeed = (formationSpeed > topSpeed) ? topSpeed : formationSpeed;
    }
  }

  const float scaledSpeed = speedScale * clampedFormationSpeed;
  if (scaledSpeed <= topSpeed) {
    topSpeed = scaledSpeed;
  }

  mInfoCache.mFormationTopSpeed = topSpeed;
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
 * Address: 0x0062B780 (FUN_0062B780, Moho::Unit::PrepareMove)
 *
 * What it does:
 * Coerces one world-space move destination into the nearest valid move cell
 * for this unit, honoring occupancy/pathability and skirt exclusion.
 */
bool Unit::PrepareMove(
  const int moveFlags,
  Wm3::Vector3f* const inOutPos,
  gpg::Rect2f* const skirtRect,
  const bool useWholeMap
)
{
  if (inOutPos == nullptr || skirtRect == nullptr) {
    return false;
  }

  Sim* const sim = SimulationRef;
  if (sim == nullptr || sim->mMapData == nullptr || sim->mOGrid == nullptr) {
    return false;
  }

  SFootprint footprint = GetFootprint();
  const std::uint8_t footprintSearchSide = FootprintMaxSide(footprint);
  const int searchStep = (moveFlags > 0) ? moveFlags : static_cast<int>(footprintSearchSide) * 2;

  const ELayer moveLayer = mCurrentLayer;
  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint != nullptr && blueprint->Air.CanFly) {
    const std::uint8_t adjustedCaps = static_cast<std::uint8_t>(
      (static_cast<std::uint8_t>(footprint.mOccupancyCaps) - static_cast<std::uint8_t>(EOccupancyCaps::OC_AIR)) |
      static_cast<std::uint8_t>(EOccupancyCaps::OC_LAND)
    );
    footprint.mOccupancyCaps = static_cast<EOccupancyCaps>(adjustedCaps);

    const std::uint8_t maxSide = FootprintMaxSide(footprint);
    footprint.mSizeX = maxSide;
    footprint.mSizeZ = maxSide;

    if (IsInCategory("CANLANDONWATER")) {
      const STIMap* const mapData = sim->mMapData;
      const CHeightField* const heightField = (mapData != nullptr && mapData->mHeightField) ? mapData->mHeightField.get() : nullptr;
      const float terrainElevation = (heightField != nullptr) ? heightField->GetElevation(inOutPos->x, inOutPos->z) : inOutPos->y;
      const float waterElevation = (mapData != nullptr && mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : -10000.0f;
      if (waterElevation > terrainElevation) {
        const std::uint8_t withWaterCaps = static_cast<std::uint8_t>(
          static_cast<std::uint8_t>(footprint.mOccupancyCaps) | static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER)
        );
        footprint.mOccupancyCaps = static_cast<EOccupancyCaps>(withWaterCaps);
      }
    }
  }

  const float halfSizeX = static_cast<float>(footprint.mSizeX) * 0.5f;
  const float halfSizeZ = static_cast<float>(footprint.mSizeZ) * 0.5f;

  const int rawStartX = static_cast<int>(inOutPos->x - halfSizeX);
  const int rawStartZ = static_cast<int>(inOutPos->z - halfSizeZ);
  SOCellPos startCell{
    static_cast<std::int16_t>(rawStartX),
    static_cast<std::int16_t>(rawStartZ),
  };

  if (IsPrepareMoveCandidateValid(*this, footprint, moveLayer, startCell, *inOutPos, *skirtRect, useWholeMap)) {
    return true;
  }

  std::vector<Wm3::Vector3f> candidatePositions{};
  candidatePositions.reserve(16);

  int minRing = -1;
  int maxRing = 1;
  int checkedCellCount = 0;
  constexpr int kPrepareMoveMaxCheckedCells = 900;
  while (true) {
    candidatePositions.clear();

    for (int ringX = minRing; ringX <= maxRing; ++ringX) {
      const int ringStepZ = (ringX == minRing || ringX == maxRing) ? 1 : (2 * maxRing);
      const int rawX = static_cast<int>(startCell.x) + (ringX * searchStep);
      const std::int16_t cellX = static_cast<std::int16_t>(rawX);

      for (int ringZ = minRing; ringZ <= maxRing; ringZ += ringStepZ) {
        ++checkedCellCount;

        const int rawZ = static_cast<int>(startCell.z) + (ringZ * searchStep);
        const std::int16_t cellZ = static_cast<std::int16_t>(rawZ);
        const SOCellPos candidateCell{cellX, cellZ};

        const Wm3::Vector3f candidateWorldPos{
          static_cast<float>(cellX) + halfSizeX,
          0.0f,
          static_cast<float>(cellZ) + halfSizeZ,
        };

        if (!IsPrepareMoveCandidateValid(
              *this,
              footprint,
              moveLayer,
              candidateCell,
              candidateWorldPos,
              *skirtRect,
              useWholeMap
            ))
        {
          continue;
        }

        candidatePositions.push_back(candidateWorldPos);
      }
    }

    if (!candidatePositions.empty()) {
      break;
    }

    if (checkedCellCount >= kPrepareMoveMaxCheckedCells) {
      return false;
    }

    ++maxRing;
    --minRing;
  }

  const Wm3::Vector3f unitPosition = GetPosition();
  float bestDistanceSq = std::numeric_limits<float>::infinity();
  Wm3::Vector3f bestCandidatePos = *inOutPos;
  for (const Wm3::Vector3f& candidateWorldPos : candidatePositions) {
    const float dx = candidateWorldPos.x - unitPosition.x;
    const float dy = candidateWorldPos.y - unitPosition.y;
    const float dz = candidateWorldPos.z - unitPosition.z;
    const float distanceSq = (dx * dx) + (dy * dy) + (dz * dz);
    if (distanceSq < bestDistanceSq) {
      bestDistanceSq = distanceSq;
      bestCandidatePos = candidateWorldPos;
    }
  }

  inOutPos->x = bestCandidatePos.x;
  inOutPos->y = bestCandidatePos.y;
  inOutPos->z = bestCandidatePos.z;
  return true;
}

[[nodiscard]] bool PrepareMove(
  int moveFlags,
  Unit* unit,
  Wm3::Vector3f* inOutPos,
  gpg::Rect2f* outSkirtRect,
  bool useWholeMap
)
{
  // Alias of FUN_0062B780 canonical body in Unit::PrepareMove.
  if (unit == nullptr) {
    return false;
  }
  return unit->PrepareMove(moveFlags, inOutPos, outSkirtRect, useWholeMap);
}

namespace moho
{
  [[nodiscard]] bool PrepareMove(
    int moveFlags,
    Unit* unit,
    Wm3::Vector3f* inOutPos,
    gpg::Rect2f* outSkirtRect,
    bool useWholeMap
  )
  {
    return ::PrepareMove(moveFlags, unit, inOutPos, outSkirtRect, useWholeMap);
  }
} // namespace moho

/**
 * Address: 0x0062BEE0 (FUN_0062BEE0, Moho::Unit::HasMeleeSpaceAroundSmallTarget)
 *
 * What it does:
 * Scans perimeter candidate cells around `target` using this unit footprint,
 * filters by occupancy/pathability checks, and writes nearest valid melee
 * destination into `inOutCell`.
 */
bool Unit::HasMeleeSpaceAroundSmallTarget(Unit* const target, SOCellPos* const inOutCell)
{
  if (target == nullptr || inOutCell == nullptr) {
    return false;
  }

  Sim* const sim = SimulationRef;
  if (sim == nullptr || sim->mOGrid == nullptr || sim->mMapData == nullptr) {
    return false;
  }

  COGrid& ogrid = *sim->mOGrid;
  const STIMap& mapData = *sim->mMapData;

  const SFootprint& moverFootprint = GetFootprint();
  const SFootprint& targetFootprint = target->GetFootprint();
  const ELayer moveLayer = mCurrentLayer;
  const bool useWholeMap = (ArmyRef != nullptr) ? ArmyRef->UseWholeMap() : false;
  const float mapBorder = static_cast<float>(FootprintMaxSide(moverFootprint));

  const int minX = static_cast<int>(inOutCell->x) - static_cast<int>(moverFootprint.mSizeX);
  const int maxX = static_cast<int>(inOutCell->x) + static_cast<int>(targetFootprint.mSizeX);
  const int minZ = static_cast<int>(inOutCell->z) - static_cast<int>(moverFootprint.mSizeZ);
  const int maxZ = static_cast<int>(inOutCell->z) + static_cast<int>(targetFootprint.mSizeZ);
  if (minZ > maxZ) {
    return false;
  }

  const float moverHalfSizeX = static_cast<float>(moverFootprint.mSizeX) * 0.5f;
  const float moverHalfSizeZ = static_cast<float>(moverFootprint.mSizeZ) * 0.5f;

  bool found = false;
  float bestDistanceSq = std::numeric_limits<float>::infinity();
  SOCellPos bestCell = *inOutCell;

  for (int z = minZ; z <= maxZ; ++z) {
    int stepX = ((z == minZ) || (z == maxZ)) ? 1 : (maxX - minX);
    if (stepX <= 0) {
      stepX = 1;
    }

    for (int x = minX; x <= maxX; x += stepX) {
      const SOCellPos candidateCell{static_cast<std::int16_t>(x), static_cast<std::int16_t>(z)};
      const Wm3::Vec3f candidateWorldPos{
        static_cast<float>(x) + moverHalfSizeX,
        0.0f,
        static_cast<float>(z) + moverHalfSizeZ,
      };

      if (!mapData.IsWithin(candidateWorldPos, mapBorder, useWholeMap)) {
        continue;
      }

      if (!IsMeleeCandidateCellNavigable(*this, target, moverFootprint, moveLayer, ogrid, mapData, candidateCell)) {
        continue;
      }

      const Wm3::Vec3f unitPos = GetPosition();
      const float deltaX = candidateWorldPos.x - unitPos.x;
      const float deltaZ = candidateWorldPos.z - unitPos.z;
      const float distanceSq = (deltaX * deltaX) + (deltaZ * deltaZ);
      if (distanceSq < bestDistanceSq) {
        bestDistanceSq = distanceSq;
        bestCell = candidateCell;
        found = true;
      }
    }
  }

  if (!found) {
    return false;
  }

  *inOutCell = bestCell;
  return true;
}

/**
 * Address: 0x0062C340 (FUN_0062C340, Moho::Unit::HasMeleeSpaceAroundLargeTarget)
 *
 * What it does:
 * Scans a collision-bounds search window around `target`, applies shell
 * collision probes plus occupancy/pathability checks, and writes nearest
 * valid melee destination into `inOutCell`.
 */
bool Unit::HasMeleeSpaceAroundLargeTarget(Unit* const target, SOCellPos* const inOutCell, const int targetSize)
{
  if (target == nullptr || inOutCell == nullptr) {
    return false;
  }

  Sim* const sim = SimulationRef;
  if (sim == nullptr || sim->mOGrid == nullptr || sim->mMapData == nullptr) {
    return false;
  }

  EntityCollisionUpdater* const targetCollisionShape = target->CollisionExtents;
  if (targetCollisionShape == nullptr) {
    return false;
  }

  COGrid& ogrid = *sim->mOGrid;
  const STIMap& mapData = *sim->mMapData;

  const SFootprint& moverFootprint = GetFootprint();
  const ELayer moveLayer = mCurrentLayer;
  const bool useWholeMap = (ArmyRef != nullptr) ? ArmyRef->UseWholeMap() : false;
  const float mapBorder = static_cast<float>(FootprintMaxSide(moverFootprint));

  const float innerHalfExtentX = static_cast<float>(targetSize + static_cast<int>(moverFootprint.mSizeX)) * 0.5f;
  const float innerHalfExtentZ = static_cast<float>(targetSize + static_cast<int>(moverFootprint.mSizeZ)) * 0.5f;
  const float outerHalfExtentX = innerHalfExtentX + 1.0f;
  const float outerHalfExtentZ = innerHalfExtentZ + 1.0f;

  constexpr float kMeleeProbeHalfHeight = 1000.0f;
  Wm3::Box3f outerProbe = BuildAxisAlignedCollisionProbe(
    Wm3::Vec3f::Zero(),
    Wm3::Vec3f(outerHalfExtentX, kMeleeProbeHalfHeight, outerHalfExtentZ)
  );
  Wm3::Box3f innerProbe = BuildAxisAlignedCollisionProbe(
    Wm3::Vec3f::Zero(),
    Wm3::Vec3f(innerHalfExtentX, kMeleeProbeHalfHeight, innerHalfExtentZ)
  );
  CollisionResult collisionResult{};

  const int minX = RoundGridCoordDown(target->mCollisionBoundsMin.x) - static_cast<int>(moverFootprint.mSizeX);
  const int maxX = RoundGridCoordUp(target->mCollisionBoundsMax.x) + 1;
  const int minZ = RoundGridCoordDown(target->mCollisionBoundsMin.z) - static_cast<int>(moverFootprint.mSizeZ);
  const int maxZ = RoundGridCoordUp(target->mCollisionBoundsMax.z) + 1;
  if (minZ > maxZ) {
    return false;
  }

  const float moverHalfSizeX = static_cast<float>(moverFootprint.mSizeX) * 0.5f;
  const float moverHalfSizeZ = static_cast<float>(moverFootprint.mSizeZ) * 0.5f;

  bool found = false;
  float bestDistanceSq = std::numeric_limits<float>::infinity();
  SOCellPos bestCell = *inOutCell;

  for (int z = minZ; z <= maxZ; ++z) {
    for (int x = minX; x <= maxX; ++x) {
      const SOCellPos candidateCell{static_cast<std::int16_t>(x), static_cast<std::int16_t>(z)};
      const Wm3::Vec3f candidateWorldPos{
        static_cast<float>(x) + moverHalfSizeX,
        0.0f,
        static_cast<float>(z) + moverHalfSizeZ,
      };

      if (!mapData.IsWithin(candidateWorldPos, mapBorder, useWholeMap)) {
        continue;
      }

      outerProbe.Center[0] = candidateWorldPos.x;
      outerProbe.Center[1] = candidateWorldPos.y;
      outerProbe.Center[2] = candidateWorldPos.z;
      if (!targetCollisionShape->CollideBox(&outerProbe, &collisionResult)) {
        continue;
      }

      innerProbe.Center[0] = candidateWorldPos.x;
      innerProbe.Center[1] = candidateWorldPos.y;
      innerProbe.Center[2] = candidateWorldPos.z;
      if (targetCollisionShape->CollideBox(&innerProbe, &collisionResult)) {
        continue;
      }

      if (!IsMeleeCandidateCellNavigable(*this, target, moverFootprint, moveLayer, ogrid, mapData, candidateCell)) {
        continue;
      }

      const Wm3::Vec3f unitPos = GetPosition();
      const float deltaX = candidateWorldPos.x - unitPos.x;
      const float deltaZ = candidateWorldPos.z - unitPos.z;
      const float distanceSq = (deltaX * deltaX) + (deltaZ * deltaZ);
      if (distanceSq < bestDistanceSq) {
        bestDistanceSq = distanceSq;
        bestCell = candidateCell;
        found = true;
      }
    }
  }

  if (!found) {
    return false;
  }

  *inOutCell = bestCell;
  return true;
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
 * Address: 0x006A7AB0 (FUN_006A7AB0, Moho::Unit::ReleaseOccupyGround)
 *
 * What it does:
 * Clears the occupied-ground lane previously applied by `ExecuteOccupyGround`
 * and releases the matching footprint rectangle from the sim O-grid.
 */
void Unit::ReleaseOccupyGround()
{
  if (!FootprintDown) {
    return;
  }

  const SFootprint& footprint = GetFootprint();
  const Wm3::Vec3f& unitPos = GetPosition();
  gpg::Rect2i occupyRect{};
  occupyRect.x0 = static_cast<std::int16_t>(
    static_cast<std::int32_t>(unitPos.x - static_cast<float>(footprint.mSizeX) * 0.5f)
  );
  occupyRect.z0 = static_cast<std::int16_t>(
    static_cast<std::int32_t>(unitPos.z - static_cast<float>(footprint.mSizeZ) * 0.5f)
  );
  occupyRect.x1 = static_cast<std::int16_t>(occupyRect.x0 + static_cast<std::int32_t>(footprint.mSizeX));
  occupyRect.z1 = static_cast<std::int16_t>(occupyRect.z0 + static_cast<std::int32_t>(footprint.mSizeZ));

  if (SimulationRef != nullptr && SimulationRef->mOGrid != nullptr) {
    SimulationRef->mOGrid->ReleaseOccupy(footprint.mOccupancyCaps, occupyRect);
  }

  FootprintDown = false;
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
 * Address: 0x0062D460 (FUN_0062D460, Moho::Unit::CollectAllOverlapping)
 *
 * What it does:
 * Gathers nearby non-mobile same-army same-layer structures and appends
 * those whose skirt rectangles overlap `unit`.
 */
SEntitySetTemplateUnit* Unit::CollectAllOverlapping(SEntitySetTemplateUnit* const outSet, Unit* const unit)
{
  if (outSet == nullptr) {
    return nullptr;
  }

  outSet->ListResetLinks();
  outSet->mVec.RebindInlineNoFree();

  if (unit == nullptr || unit->SimulationRef == nullptr || unit->SimulationRef->mOGrid == nullptr) {
    return outSet;
  }

  const Wm3::Vec3f& position = unit->GetPosition();
  gpg::Rect2f queryRect{};
  queryRect.x0 = position.x - 20.0f;
  queryRect.z0 = position.z - 20.0f;
  queryRect.x1 = position.x + 20.0f;
  queryRect.z1 = position.z + 20.0f;

  CollisionDBRect collisionRect{};
  (void)func_Rect2fToInt16(&collisionRect, queryRect);

  EntityGatherVector gatheredEntities{};
  (void)unit->SimulationRef->mOGrid->mEntityOccupationManager.GatherUnmarkedEntities(
    gatheredEntities,
    collisionRect,
    ENTITYTYPE_Unit
  );

  for (Entity* const entity : gatheredEntities) {
    Unit* const other = (entity != nullptr) ? entity->IsUnit() : nullptr;
    if (other == nullptr) {
      continue;
    }

    const Wm3::Vec3f& otherPosition = other->GetPosition();
    const float deltaX = otherPosition.x - position.x;
    const float deltaZ = otherPosition.z - position.z;
    if ((deltaX * deltaX) + (deltaZ * deltaZ) > (20.0f * 20.0f)) {
      continue;
    }

    if (other->IsDead() || other->IsMobile()) {
      continue;
    }
    if (unit->ArmyRef != other->ArmyRef) {
      continue;
    }
    if (other == unit) {
      continue;
    }
    if (other->mCurrentLayer != unit->mCurrentLayer) {
      continue;
    }
    if (!unit->OverlapsWith(other)) {
      continue;
    }

    (void)outSet->AddUnit(other);
  }

  return outSet;
}

/**
 * Address: 0x006A7E00 (FUN_006A7E00, ?LookForStructureRebuilder@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Scans same-army REBUILDER units for guard commands matching this structure
 * blueprint/position and queues one rebuild entry on the first matching
 * command per builder.
 */
void Unit::LookForStructureRebuilder()
{
  if (ArmyRef == nullptr || SimulationRef == nullptr || SimulationRef->mRules == nullptr) {
    return;
  }

  const RUnitBlueprint* const blueprint = GetBlueprint();
  if (blueprint == nullptr) {
    return;
  }

  const CategoryWordRangeView* const rebuilderCategory = SimulationRef->mRules->GetEntityCategory("REBUILDER");
  if (rebuilderCategory == nullptr) {
    return;
  }

  SEntitySetTemplateUnit rebuilderUnits{};
  (void)ArmyRef->GetUnits(&rebuilderUnits, const_cast<CategoryWordRangeView*>(rebuilderCategory));

  for (Entity* const entry : rebuilderUnits.mVec) {
    Unit* const rebuilder = SEntitySetTemplateUnit::UnitFromEntry(entry);
    if (rebuilder == nullptr) {
      continue;
    }

    if (rebuilder->IsDead() || rebuilder->DestroyQueued() || rebuilder->IsBeingBuilt() || rebuilder->AiBuilder == nullptr ||
        rebuilder->CommandQueue == nullptr) {
      continue;
    }

    const msvc8::vector<WeakPtr<CUnitCommand>> commandSnapshot(rebuilder->CommandQueue->mCommandVec);
    for (const WeakPtr<CUnitCommand>& commandRef : commandSnapshot) {
      CUnitCommand* const command = commandRef.GetObjectPtr();
      if (command == nullptr || command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_Guard) {
        continue;
      }

      const RUnitBlueprint* const commandBlueprint = static_cast<const RUnitBlueprint*>(command->mConstDat.blueprint);
      if (commandBlueprint != blueprint) {
        continue;
      }

      const Wm3::Vec3f targetPosition = command->mTarget.GetTargetPosGun(false);
      const Wm3::Vec3f& myPosition = GetPosition();
      const float deltaX = targetPosition.x - myPosition.x;
      const float deltaZ = targetPosition.z - myPosition.z;
      if (std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ)) >= 0.001f) {
        continue;
      }

      const SOCellPos cellPos = GetFootprint().ToCellPos(GetPosition());
      rebuilder->AiBuilder->BuilderAddRebuildStructure(cellPos, blueprint);
      break;
    }
  }
}

/**
 * Address: 0x006A8090 (FUN_006A8090, ?Kill@Unit@Moho@@UAEXPAVEntity@2@VStrArg@gpg@@M@Z)
 *
 * What it does:
 * Applies unit death gating and teardown, notifies adjacency/transport and
 * script lanes, then updates army/platoon kill-value statistics.
 */
void Unit::Kill(Entity* const instigator, const gpg::StrArg reason, float excessDamageRatio)
{
  if (IsDead()) {
    return;
  }

  const bool scriptAllowsKill = RunScriptUnitBool("CheckCanBeKilled", this);
  if (!scriptAllowsKill && IsWithinPlayableRectOrNotCommander(*this)) {
    return;
  }

  UnitStateMask |= (1ull << static_cast<std::uint32_t>(UNITSTATE_TransportUnloading));

  SEntitySetTemplateUnit overlappingStructures{};
  if (!IsMobile()) {
    CollectAllOverlapping(&overlappingStructures, this);
    LookForStructureRebuilder();
  }

  if (Unit* const transportOwner = GetTransportedBy(); transportOwner != nullptr) {
    if (transportOwner->AiTransport != nullptr && mAttachInfo.GetAttachTargetEntity() != nullptr) {
      (void)transportOwner->AiTransport->TransportDetachUnit(this);
    }
    TransportedByRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
    excessDamageRatio = 10.0f;
  }

  if (IsBeingBuilt() && WorkProgress < 0.5f) {
    excessDamageRatio = 10.0f;
  }

  (void)RunScript("SetDead");
  Entity::Kill(nullptr, "", 0.0f);
  mNeedsKillCleanup = true;

  if (!IsMobile() && !IsBeingBuilt()) {
    for (Entity* const entry : overlappingStructures.mVec) {
      Unit* const adjacent = SEntitySetTemplateUnit::UnitFromEntry(entry);
      if (adjacent == nullptr) {
        continue;
      }

      RunScriptUnit("OnNotAdjacentTo", adjacent);
      adjacent->RunScriptUnit("OnNotAdjacentTo", this);
      adjacent->ReserveOgridRect(GetReservedOgridRect(*adjacent));
    }
  }

  if (AiTransport != nullptr) {
    (void)AiTransport->TransportDetachAllUnits(true);
  }

  if (CommandQueue != nullptr) {
    CommandQueue->ClearCommandQueue();
  }

  RunScriptUnitOnKilled(instigator, reason, excessDamageRatio);

  const RUnitBlueprint* const blueprint = GetBlueprint();
  float massValue = (blueprint != nullptr) ? blueprint->Economy.BuildCostMass : 0.0f;
  float energyValue = (blueprint != nullptr) ? blueprint->Economy.BuildCostEnergy : 0.0f;
  if (IsBeingBuilt()) {
    massValue *= WorkProgress;
    energyValue *= WorkProgress;
  }

  if (ArmyRef != nullptr) {
    if (CArmyStats* const armyStats = ArmyRef->GetArmyStats(); armyStats != nullptr) {
      if (blueprint != nullptr) {
        IncrementArmyBlueprintFloatStat(armyStats, "Units_Killed", blueprint, 1.0f);
      }
      IncrementArmyIntStatByName(armyStats, "Units_Killed");
      (void)AddArmyStatFloatByName(armyStats, &massValue, "Units_MassValue_Lost");
      (void)AddArmyStatFloatByName(armyStats, &energyValue, "Units_EnergyValue_Lost");
    }

    ESquadClass squadClass = ESquadClass::Unassigned;
    if (CPlatoon* const platoon =
          ArmyRef->GetPlatoonFor(static_cast<int>(reinterpret_cast<std::uintptr_t>(this)), &squadClass);
        platoon != nullptr) {
      ++platoon->mLifetimeStat2;
    }
  }

  CArmyImpl* const instigatorArmy = (instigator != nullptr) ? instigator->ArmyRef : nullptr;
  if (instigatorArmy == nullptr || ArmyRef == nullptr ||
      !ArmyRef->IsEnemy(static_cast<std::uint32_t>(instigatorArmy->ArmyId))) {
    return;
  }

  if (Unit* const instigatorUnit = instigator->IsUnit(); instigatorUnit != nullptr && instigatorUnit->ArmyRef != nullptr) {
    ESquadClass instigatorSquadClass = ESquadClass::Unassigned;
    if (CPlatoon* const instigatorPlatoon = instigatorUnit->ArmyRef->GetPlatoonFor(
          static_cast<int>(reinterpret_cast<std::uintptr_t>(instigatorUnit)),
          &instigatorSquadClass
        );
        instigatorPlatoon != nullptr) {
      ++instigatorPlatoon->mLifetimeStat1;
    }
  }

  CArmyStats* const enemyArmyStats = instigatorArmy->GetArmyStats();
  if (enemyArmyStats == nullptr) {
    return;
  }

  IncrementArmyIntStatByName(enemyArmyStats, "Enemies_Killed");
  if (blueprint != nullptr) {
    IncrementArmyBlueprintFloatStat(enemyArmyStats, "Enemies_Killed", blueprint, 1.0f);
  }
  (void)AddArmyStatFloatByName(enemyArmyStats, &massValue, "Enemies_MassValue_Destroyed");
  (void)AddArmyStatFloatByName(enemyArmyStats, &energyValue, "Enemies_EnergyValue_Destroyed");

  static const std::string kCommanderCategory = "COMMAND";
  if (Entity::IsInCategory(kCommanderCategory.c_str())) {
    const std::int32_t delta = 1;
    (void)enemyArmyStats->UpdateUnitStat("Enemies_Commanders_Destroyed", &delta);
  }
}

/**
 * Address: 0x006A88D0 (FUN_006A88D0, ?OnDestroy@Unit@Moho@@UAEXXZ)
 *
 * What it does:
 * Dispatches unit destruction-side adjacency/transport cleanup and then
 * forwards to the base entity destroy-dispatch path.
 */
void Unit::OnDestroy()
{
  if (AiAttacker != nullptr) {
    AiAttacker->WeaponsOnDestroy();
  }

  if (FootprintDown) {
    FreeOgridRect();
  }

  if (!IsDead()) {
    if (!IsMobile() && !IsBeingBuilt()) {
      SEntitySetTemplateUnit adjacentUnits{};
      CollectAllOverlapping(&adjacentUnits, this);
      for (Entity* const entry : adjacentUnits.mVec) {
        Unit* const adjacent = SEntitySetTemplateUnit::UnitFromEntry(entry);
        RunScriptUnit("OnNotAdjacentTo", adjacent);
        adjacent->RunScriptUnit("OnNotAdjacentTo", this);
        adjacent->ReserveOgridRect(GetReservedOgridRect(*adjacent));
      }
    }

    RunScriptUnit("SetDead", this);
    Dead = 1u;

    if (Unit* const transportOwner = GetTransportedBy(); transportOwner != nullptr && !transportOwner->IsDead()) {
      (void)transportOwner->AiTransport->TransportDetachUnit(this);
      TransportedByRef.AsWeakPtr<Unit>().UnlinkFromOwnerChain();
    }

    if (AiTransport != nullptr) {
      EntitySetTemplate<Unit> detachedUnits = AiTransport->TransportDetachAllUnits(false);
      (void)detachedUnits;
    }
  }

  Entity::OnDestroy();
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
      out->pairs.PushBack(pair);
    }
  } else if (AiTransport) {
    const Unit* teleportBeacon = AiTransport->TransportGetTeleportBeaconForSync();
    if (teleportBeacon) {
      SExtraUnitDataPair pair{};
      pair.key = -1;
      pair.value = teleportBeacon->id_;
      out->pairs.PushBack(pair);
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
 * Address: 0x006AAE20 (FUN_006AAE20, Moho::Unit::GetConsumptionRequest)
 *
 * What it does:
 * Returns the requested per-tick consumption pair from `mConsumptionData`.
 */
SEconValue Unit::GetConsumptionRequest() const
{
  SEconValue request{};
  request.energy = mConsumptionData->mRequested.energy;
  request.mass = mConsumptionData->mRequested.mass;
  return request;
}

/**
 * Address: 0x006AAE40 (FUN_006AAE40, Moho::Unit::UpdateResourceProduction)
 *
 * What it does:
 * Stores one economy-rate pair in the shared runtime production lane.
 */
void Unit::UpdateResourceProduction(const SEconValue& resourceProduction)
{
  SharedEconomyRateEnergy = resourceProduction.energy;
  SharedEconomyRateMass = resourceProduction.mass;
}

/**
 * Address: 0x006ABC70 (FUN_006ABC70, ?ResetEconValues@Unit@Moho@@QAEXXZ)
 *
 * What it does:
 * Clears the unit's produced and resources-spent economy totals.
 */
Unit* Unit::ResetEconValues()
{
  SSTIUnitVariableData& varDat = VarDat();
  varDat.mResourcesSpent.ENERGY = 0.0f;
  varDat.mResourcesSpent.MASS = 0.0f;
  varDat.mProduced.ENERGY = 0.0f;
  varDat.mProduced.MASS = 0.0f;
  return this;
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
 * Address: 0x006AAA90 (FUN_006AAA90, ?SetProductionActive@Unit@Moho@@QAEX_N@Z)
 *
 * What it does:
 * Writes one production-active flag lane and dispatches matching
 * `OnProductionActive` / `OnProductionInActive` script callbacks.
 */
void Unit::SetProductionActive(const bool isActive)
{
  ProductionActive = isActive;
  (void)RunScript(isActive ? kUnitOnProductionActiveScript : kUnitOnProductionInactiveScript);
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

namespace
{
  /**
   * Collapse one weak reference slot to the referenced entity's id, or to the
   * `0xF0000000` sentinel when the slot is empty or its target has died.
   *
   * `Unit::Sync` publishes four of these into the sync payload; the binary
   * inlines the same null-tag test and `id_` load at each one.
   */
  template <class TObject>
  [[nodiscard]] moho::EntId WeakRefEntityId(const moho::SWeakRefSlot& slot) noexcept
  {
    const TObject* const target = slot.ResolveObjectPtr<TObject>();
    return target != nullptr ? target->id_ : kNoCreatorEntityId;
  }

  /**
   * A weapon's effective min/max radius: the live attribute when it has been
   * set, otherwise the blueprint default. The binary encodes "unset" as a
   * negative attribute value, and reaches the blueprint only on that path -
   * hence the member pointer rather than an eagerly-loaded fallback value.
   */
  [[nodiscard]] float ResolveWeaponRadius(
    const float attributeRadius,
    const moho::RUnitBlueprintWeapon* const blueprint,
    float moho::RUnitBlueprintWeapon::* const blueprintRadius
  ) noexcept
  {
    return attributeRadius < 0.0f ? blueprint->*blueprintRadius : attributeRadius;
  }
} // namespace

/**
 * Address: 0x006ABCC0 (FUN_006ABCC0, ?Sync@Unit@Moho@@UAEXPAUSSyncData@2@@Z)
 * Mangled: ?Sync@Unit@Moho@@UAEXPAUSSyncData@2@@Z
 * VFTable SLOT: 12 (over `Entity::Sync`)
 *
 * IDA signature:
 * void __thiscall Moho::Unit::Sync(Moho::Unit* this, Moho::SSyncData* syncData);
 *
 * What it does:
 * Refreshes the on-demand half of `VarDat()` and chains into `Entity::Sync`.
 *
 * Everything behind `NeedSyncGameData` is republished only when some gameplay
 * path has marked the unit dirty, and the flag is cleared on the way out:
 * the four weak references become entity ids, the six silo counters are
 * re-read (a unit with no silo controller reports zero rather than keeping a
 * stale count), and the weapon-info snapshot lane is regrown and refilled.
 *
 * The weapon pass is skipped entirely for a dead or destroy-queued unit -
 * its weapons are already being torn down - which leaves the last published
 * snapshot in place for the UI to keep drawing.
 *
 * Both shared animation poses are refreshed on every sync, dirty or not,
 * because they change every frame the unit animates.
 */
void Unit::Sync(SSyncData* const syncData)
{
  if (NeedSyncGameData) {
    SSTIUnitVariableData& varDat = VarDat();

    varDat.mCreator = WeakRefEntityId<Unit>(CreatorRef);
    varDat.mFocusUnit = WeakRefEntityId<Entity>(FocusEntityRef);
    varDat.mGuardedUnit = WeakRefEntityId<Unit>(GuardedUnitRef);
    varDat.mTargetBlip = WeakRefEntityId<Entity>(TargetBlipEntityRef);

    varDat.mTacticalSiloBuildCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetBuildCount(SILOTYPE_Tactical) : 0;
    varDat.mNukeSiloBuildCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetBuildCount(SILOTYPE_Nuke) : 0;
    varDat.mTacticalSiloStorageCount =
      AiSiloBuild != nullptr ? AiSiloBuild->SiloGetStorageCount(SILOTYPE_Tactical) : 0;
    varDat.mNukeSiloStorageCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetStorageCount(SILOTYPE_Nuke) : 0;
    varDat.mTacticalSiloMaxStorageCount =
      AiSiloBuild != nullptr ? AiSiloBuild->SiloGetMaxStorageCount(SILOTYPE_Tactical) : 0;
    varDat.mNukeSiloMaxStorageCount = AiSiloBuild != nullptr ? AiSiloBuild->SiloGetMaxStorageCount(SILOTYPE_Nuke) : 0;

    if (!IsDead() && !DestroyQueued()) {
      const std::int32_t weaponCount = AiAttacker != nullptr ? AiAttacker->GetWeaponCount() : 0;

      SSTIUnitWeaponInfoVector& weaponInfo = varDat.mWeaponInfo;
      if (static_cast<std::size_t>(weaponCount) > weaponInfo.size()) {
        weaponInfo.resize(static_cast<std::size_t>(weaponCount), UnitWeaponInfo{});
      }

      for (std::int32_t index = 0; index < weaponCount; ++index) {
        CAiAttackerImpl* const attacker = AiAttacker;
        if (attacker == nullptr) {
          continue;
        }

        const UnitWeapon* const weapon = attacker->GetWeapon(index);
        if (weapon == nullptr) {
          continue;
        }

        UnitWeaponInfo& snapshot = weaponInfo[static_cast<std::size_t>(index)];

        {
          EntityCategorySet category;
          snapshot.mCat1 = *weapon->GetCat1(&category);
        }
        {
          EntityCategorySet category;
          snapshot.mCat2 = *weapon->GetCat2(&category);
        }

        snapshot.mLayer = weapon->mFireTargetLayerCaps;

        const CWeaponAttributes& attributes = weapon->mAttributes;
        snapshot.mMinRadius =
          ResolveWeaponRadius(attributes.mMinRadius, attributes.mBlueprint, &RUnitBlueprintWeapon::MinRadius);
        snapshot.mMaxRadius =
          ResolveWeaponRadius(attributes.mMaxRadius, attributes.mBlueprint, &RUnitBlueprintWeapon::MaxRadius);

        if (weapon->mWeaponBlueprint != nullptr) {
          snapshot.mUIMinRangeVisualId = weapon->mWeaponBlueprint->UIMinRangeVisualId;
          snapshot.mUIMaxRangeVisualId = weapon->mWeaponBlueprint->UIMaxRangeVisualId;
        }

        // The blueprint's own effective radius wins when it is set; otherwise
        // the weapon falls back to whatever it resolved as its max range.
        if (weapon->mWeaponBlueprint != nullptr && weapon->mWeaponBlueprint->EffectiveRadius >= 0.0f) {
          snapshot.mEffectiveRadius = weapon->mWeaponBlueprint->EffectiveRadius;
        } else {
          snapshot.mEffectiveRadius =
            ResolveWeaponRadius(attributes.mMaxRadius, attributes.mBlueprint, &RUnitBlueprintWeapon::MaxRadius);
        }
      }
    }

    NeedSyncGameData = false;
  }

  VarDat().mSharedPose = AniActor->GetPoseShared();
  VarDat().mPriorSharedPose = AniActor->GetPriorPoseShared();

  Entity::Sync(syncData);
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
    (void)QueueCreateUnitParams(syncData, createParams);
  }

  mInterfaceCreated = 1u;
}

/**
 * Address: 0x006AC3A0 (FUN_006AC3A0, ?SyncInterface@Unit@Moho@@MAEXPAUSSyncData@2@@Z)
 *
 * IDA signature:
 * void __thiscall Moho::Unit::SyncInterface(Moho::Unit* this, Moho::SSyncData* syncData);
 *
 * What it does:
 * Rebuilds the per-sim command / build-queue CmdId snapshots when their source
 * queues are marked dirty, then queues a `{ id_, mUnitVarDat }` record onto
 * `SSyncData::mUnitUpdates` (+0x158) with the recon-flag word set to 28, and
 * finally chains into the base `Entity::SyncInterface`.
 *   1. `mUnitVarDat.mDidRefresh` is cleared up front.
 *   2. If the command queue is present and dirty, the `mCommands` snapshot is
 *      reset to inline storage and rebuilt from the queue's live commands, the
 *      queue's dirty flag is cleared, and `mDidRefresh` is set.
 *   3. If the AI builder is present and its factory queue is dirty, the
 *      `mBuildQueue` snapshot is likewise rebuilt from the builder's factory
 *      command queue, the builder's dirty flag is cleared, and `mDidRefresh` is
 *      set.
 *   4. A default unit-update record is pushed, `id_` + `mUnitVarDat` are copied
 *      into it, and its recon-flag word (+0x230) is set to 28.
 */
void Unit::SyncInterface(SSyncData* const syncData)
{
  SSTIUnitVariableData& varData = VarDat();
  varData.mDidRefresh = false;

  if (CommandQueue != nullptr && CommandQueue->mNeedsRefresh) {
    varData.mCommands.ResetStorageToInline();
    AppendLiveCommandIdsToSnapshot(varData.mCommands, CommandQueue->mCommandVec);
    CommandQueue->mNeedsRefresh = false;
    varData.mDidRefresh = true;
  }

  if (AiBuilder != nullptr && AiBuilder->BuilderIsFactoryQueueDirty()) {
    varData.mBuildQueue.ResetStorageToInline();
    AppendLiveCommandIdsToSnapshot(varData.mBuildQueue, AiBuilder->BuilderGetFactoryCommandQueue());
    AiBuilder->BuilderSetFactoryQueueDirty(false);
    varData.mDidRefresh = true;
  }

  SUnitVariableUpdateEntry* const entry = QueueUnitVariableUpdate(syncData, id_, varData);
  SetUnitUpdateReconFlags(entry, 28);

  Entity::SyncInterface(syncData);
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

// ===== Recovered Unit reflection serializer bodies (FUN_006B33A0 / FUN_006B2B50) =====
namespace gpg
{
  gpg::RRef* RRef_CEconStorage(gpg::RRef* outRef, moho::CEconStorage* value);
} // namespace gpg

namespace moho
{

namespace
{
  /**
   * Reflection type-descriptor cache used by the runtime `Unit` member
   * serializer pair. Mirrors the per-type `LookupRType(typeid(T))` cache the
   * binary emits inline as one static `gpg::RType*` slot per member lane.
   */
  template <class TReflected>
  [[nodiscard]] gpg::RType* ResolveUnitSerializerType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(TReflected));
    }
    return sType;
  }

  /**
   * Typed view over the four contiguous `Unit` reserved-O-grid bound lanes
   * (`ReservedOgridRect{Min,Max}{X,Z}` at +0x5A8), which together form the
   * unit occupation rectangle serialized/read as a single `gpg::Rect2i`.
   */
  [[nodiscard]] gpg::Rect2i& UnitOccupationRect(moho::Unit& unit) noexcept
  {
    static_assert(
      offsetof(moho::Unit, ReservedOgridRectMinX) == 0x05A8,
      "Unit occupation rect must begin at +0x5A8"
    );
    return reinterpret_cast<gpg::Rect2i&>(unit.ReservedOgridRectMinX);
  }
} // namespace

/**
 * Address: 0x006B33A0 (FUN_006B33A0, ?MemberSerialize@Unit@Moho@@SAXPAVWriteArchive@gpg@@PAV12@H@Z)
 * Mangled: Moho::Unit::MemberSerialize
 *
 * IDA signature:
 * void __userpurge Moho::Unit::MemberSerialize(BinaryWriteArchive *archive@<eax>, Moho::Unit *unit@<ecx>, int vers);
 *
 * What it does:
 * Serializes every runtime `Unit` state lane, in declaration order, into the
 * write archive: the `Entity` base sub-object, the constant/variable unit data
 * payloads, the owned AI/command sidecar pointers (tracked OWNED pointers),
 * the weak-reference lanes, formation/guard state, economy lanes, and the
 * cached recon/blip state. Throws `gpg::SerializationError` for archive
 * versions below 1.
 */
void Unit::MemberSerialize(gpg::WriteArchive* const archive, Unit* const unit, const int vers)
{
  if (vers < 1) {
    throw gpg::SerializationError("unsupported version.");
  }

  const gpg::RRef ownerRef{};
  const gpg::RRef unowned{};

  // Entity base sub-object (adjusted `this + 0x08`).
  archive->Write(ResolveUnitSerializerType<Entity>(), static_cast<const Entity*>(unit), ownerRef);

  // Constant / variable unit-data payloads.
  archive->Write(ResolveUnitSerializerType<SSTIUnitConstantData>(), &unit->mConstDat, ownerRef);
  archive->Write(ResolveUnitSerializerType<SSTIUnitVariableData>(), &unit->VarDat(), ownerRef);

  // Owned AI / motion / command sidecar pointers (tracked OWNED lanes).
  {
    gpg::RRef ref{};
    gpg::RRef_IAiSteering(&ref, unit->AiSteering);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    gpg::RRef ref{};
    gpg::RRef_CUnitMotion(&ref, unit->UnitMotion);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    gpg::RRef ref{};
    gpg::RRef_CUnitCommandQueue(&ref, unit->CommandQueue);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }

  // Weak-reference lanes.
  archive->Write(ResolveUnitSerializerType<WeakPtr<Unit>>(), &unit->CreatorRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Unit>>(), &unit->TransportedByRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Unit>>(), &unit->AssignedTransportRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Entity>>(), &unit->FocusEntityRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Entity>>(), &unit->TargetBlipEntityRef, ownerRef);
  archive->Write(ResolveUnitSerializerType<WeakPtr<Unit>>(), &unit->GuardedUnitRef, ownerRef);

  // Guarded-position vector and guarded-by unit set.
  archive->Write(ResolveUnitSerializerType<Wm3::Vector3f>(), &unit->GuardedPos, ownerRef);
  archive->Write(ResolveUnitSerializerType<EntitySetTemplate<Unit>>(), &unit->GuardedByList, ownerRef);

  // Owned formation instance.
  {
    gpg::RRef ref{};
    gpg::RRef_IFormationInstance(&ref, unit->GuardFormation);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }

  archive->WriteBool(unit->mNeedsKillCleanup);
  archive->WriteInt(unit->mCreationTick);

  // Owned extra economy storage.
  {
    gpg::RRef ref{};
    gpg::RRef_CEconStorage(&ref, unit->mExtraStorage);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }

  archive->WriteInt(unit->PriorityBoost);

  // Owned consumption (upkeep) request.
  {
    gpg::RRef ref{};
    gpg::RRef_CEconRequest(&ref, unit->mConsumptionData);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }

  archive->WriteBool(unit->ConsumptionActive);
  archive->WriteBool(unit->ProductionActive);
  archive->WriteFloat(unit->ResourceConsumed);

  // Owned animation actor.
  {
    gpg::RRef ref{};
    gpg::RRef_CAniActor(&ref, unit->AniActor);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }

  // Owned AI implementation lanes.
  {
    gpg::RRef ref{};
    gpg::RRef_IAiAttacker(&ref, reinterpret_cast<IAiAttacker*>(unit->AiAttacker));
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    gpg::RRef ref{};
    gpg::RRef_IAiCommandDispatch(&ref, unit->AiCommandDispatch);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    gpg::RRef ref{};
    gpg::RRef_IAiNavigator(&ref, unit->AiNavigator);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    gpg::RRef ref{};
    gpg::RRef_IAiBuilder(&ref, unit->AiBuilder);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    gpg::RRef ref{};
    gpg::RRef_IAiSiloBuild(&ref, unit->AiSiloBuild);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }
  {
    gpg::RRef ref{};
    gpg::RRef_IAiTransport(&ref, unit->AiTransport);
    gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Owned, unowned);
  }

  archive->WriteBool(unit->FootprintDown);
  archive->WriteFloat(unit->TransportLoadFactor);

  // Armor-multiplier map (`std::map<std::string,float>` reflection lane).
  archive->Write(
    ResolveUnitSerializerType<std::map<std::string, float>>(),
    &unit->ArmorMultipliers,
    ownerRef
  );

  // Owned economy-event pointer list terminated by a null lane.
  unit->SerEconomyEvents(*archive, vers);

  archive->WriteUByte(unit->CurrentTerrainType);
  archive->WriteBool(unit->mDebugAIStates);

  archive->Write(ResolveUnitSerializerType<SInfoCache>(), &unit->mInfoCache, ownerRef);
  archive->Write(ResolveUnitSerializerType<gpg::Rect2i>(), &UnitOccupationRect(*unit), ownerRef);
  archive->Write(
    ResolveUnitSerializerType<gpg::fastvector<WeakPtr<Entity>>>(),
    &unit->mBlipsInRange,
    ownerRef
  );

  archive->WriteUInt(static_cast<unsigned int>(unit->mBlipLastUpdateTick));
  archive->WriteBool(unit->mIsNotPod);
  archive->WriteBool(unit->mIsEngineer);
  archive->WriteBool(unit->mIsNaval);
  archive->WriteBool(unit->mIsAir);
  archive->WriteBool(unit->mIsMelee);
  archive->WriteBool(unit->mUsesGridBasedMotion);
  archive->WriteInt(unit->CaptorCount);

  archive->Write(
    ResolveUnitSerializerType<gpg::fastvector<ReconBlip*>>(),
    &unit->mReconBlips,
    ownerRef
  );
}

/**
 * Address: 0x006B2B50 (FUN_006B2B50, ?MemberDeserialize@Unit@Moho@@SAXPAVReadArchive@gpg@@PAV12@H@Z)
 * Mangled: Moho::Unit::MemberDeserialize
 *
 * IDA signature:
 * void __userpurge Moho::Unit::MemberDeserialize(gpg::ReadArchive *archive@<eax>, Moho::Unit *unit@<esi>, int vers);
 *
 * What it does:
 * Mirror of `MemberSerialize`: reads every runtime `Unit` state lane back in
 * declaration order, destroying any pre-existing owned sidecar object as each
 * owned pointer lane is replaced, then re-applies occupancy/collision state
 * (re-occupy ground, re-mark the O-grid occupation rect if non-degenerate, and
 * refresh collision when a collision shape is present). Throws
 * `gpg::SerializationError` for archive versions below 1.
 */
void Unit::MemberDeserialize(gpg::ReadArchive* const archive, Unit* const unit, const int vers)
{
  if (vers < 1) {
    throw gpg::SerializationError("unsupported version.");
  }

  const gpg::RRef ownerRef{};

  // Entity base sub-object (adjusted `this + 0x08`).
  archive->Read(ResolveUnitSerializerType<Entity>(), static_cast<Entity*>(unit), ownerRef);

  // Constant / variable unit-data payloads.
  archive->Read(ResolveUnitSerializerType<SSTIUnitConstantData>(), &unit->mConstDat, ownerRef);
  archive->Read(ResolveUnitSerializerType<SSTIUnitVariableData>(), &unit->VarDat(), ownerRef);

  // Steering: read new owned pointer, swap in, release prior instance.
  {
    IAiSteering* steering = nullptr;
    archive->ReadPointerOwned_IAiSteering(&steering, &ownerRef);
    IAiSteering* const prior = unit->AiSteering;
    unit->AiSteering = steering;
    delete prior;
  }

  // Unit motion.
  {
    CUnitMotion* motion = nullptr;
    archive->ReadPointerOwned_CUnitMotion(&motion, &ownerRef);
    CUnitMotion* const prior = unit->UnitMotion;
    unit->UnitMotion = motion;
    delete prior;
  }

  // Command queue.
  {
    CUnitCommandQueue* queue = nullptr;
    archive->ReadPointerOwned_CUnitCommandQueue(&queue, &ownerRef);
    CUnitCommandQueue* const prior = unit->CommandQueue;
    unit->CommandQueue = queue;
    delete prior;
  }

  // Weak-reference lanes.
  archive->Read(ResolveUnitSerializerType<WeakPtr<Unit>>(), &unit->CreatorRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Unit>>(), &unit->TransportedByRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Unit>>(), &unit->AssignedTransportRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Entity>>(), &unit->FocusEntityRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Entity>>(), &unit->TargetBlipEntityRef, ownerRef);
  archive->Read(ResolveUnitSerializerType<WeakPtr<Unit>>(), &unit->GuardedUnitRef, ownerRef);

  // Guarded-position vector and guarded-by unit set.
  archive->Read(ResolveUnitSerializerType<Wm3::Vector3f>(), &unit->GuardedPos, ownerRef);
  archive->Read(ResolveUnitSerializerType<EntitySetTemplate<Unit>>(), &unit->GuardedByList, ownerRef);

  // Formation instance (deleted through the reflection deleting-destructor slot).
  {
    IFormationInstance* formation = nullptr;
    archive->ReadPointerOwned_IFormationInstance(&formation, &ownerRef);
    IFormationInstance* const prior = unit->GuardFormation;
    unit->GuardFormation = static_cast<CAiFormationInstance*>(formation);
    if (prior) {
      prior->operator_delete(1);
    }
  }

  archive->ReadBool(&unit->mNeedsKillCleanup);
  archive->ReadInt(&unit->mCreationTick);

  // Extra economy storage: detach from its economy then free raw storage.
  {
    CEconStorage* storage = nullptr;
    archive->ReadPointerOwned_CEconStorage(&storage, &ownerRef);
    CEconStorage* const prior = unit->mExtraStorage;
    unit->mExtraStorage = storage;
    if (prior) {
      if (prior->mEconomy) {
        prior->Chng(-1);
      }
      ::operator delete(prior);
    }
  }

  archive->ReadInt(&unit->PriorityBoost);

  // Consumption (upkeep) request: unlink its intrusive node then free storage.
  {
    CEconRequest* request = nullptr;
    archive->ReadPointerOwned_CEconRequest(&request, &ownerRef);
    CEconRequest* const prior = unit->mConsumptionData;
    unit->mConsumptionData = request;
    if (prior) {
      prior->mNode.ListUnlink();
      ::operator delete(prior);
    }
  }

  archive->ReadBool(&unit->ConsumptionActive);
  archive->ReadBool(&unit->ProductionActive);
  archive->ReadFloat(&unit->ResourceConsumed);

  // Animation actor.
  {
    CAniActor* actor = nullptr;
    archive->ReadPointerOwned_CAniActor(&actor, &ownerRef);
    CAniActor* const prior = unit->AniActor;
    unit->AniActor = actor;
    delete prior;
  }

  // AI implementation lanes.
  {
    IAiAttacker* attacker = nullptr;
    archive->ReadPointerOwned_IAiAttacker(&attacker, &ownerRef);
    CAiAttackerImpl* const prior = unit->AiAttacker;
    unit->AiAttacker = reinterpret_cast<CAiAttackerImpl*>(attacker);
    delete prior;
  }
  {
    IAiCommandDispatch* dispatch = nullptr;
    archive->ReadPointerOwned_IAiCommandDispatch(&dispatch, &ownerRef);
    IAiCommandDispatchImpl* const prior = unit->AiCommandDispatch;
    unit->AiCommandDispatch = static_cast<IAiCommandDispatchImpl*>(dispatch);
    delete prior;
  }
  {
    IAiNavigator* navigator = nullptr;
    archive->ReadPointerOwned_IAiNavigator(&navigator, &ownerRef);
    IAiNavigator* const prior = unit->AiNavigator;
    unit->AiNavigator = navigator;
    delete prior;
  }
  {
    IAiBuilder* builder = nullptr;
    archive->ReadPointerOwned_IAiBuilder(&builder, &ownerRef);
    IAiBuilder* const prior = unit->AiBuilder;
    unit->AiBuilder = builder;
    delete prior;
  }
  {
    IAiSiloBuild* siloBuild = nullptr;
    archive->ReadPointerOwned_IAiSiloBuild(&siloBuild, &ownerRef);
    CAiSiloBuildImpl* const prior = unit->AiSiloBuild;
    unit->AiSiloBuild = static_cast<CAiSiloBuildImpl*>(siloBuild);
    delete prior;
  }
  {
    IAiTransport* transport = nullptr;
    archive->ReadPointerOwned_IAiTransport(&transport, &ownerRef);
    IAiTransport* const prior = unit->AiTransport;
    unit->AiTransport = transport;
    delete prior;
  }

  archive->ReadBool(&unit->FootprintDown);
  archive->ReadFloat(&unit->TransportLoadFactor);

  // Armor-multiplier map (`std::map<std::string,float>` reflection lane).
  archive->Read(
    ResolveUnitSerializerType<std::map<std::string, float>>(),
    &unit->ArmorMultipliers,
    ownerRef
  );

  // Owned economy-event pointer list terminated by a null lane.
  unit->SerEconomyEvents(*archive, vers);

  archive->ReadUByte(&unit->CurrentTerrainType);
  archive->ReadBool(&unit->mDebugAIStates);

  archive->Read(ResolveUnitSerializerType<SInfoCache>(), &unit->mInfoCache, ownerRef);
  archive->Read(ResolveUnitSerializerType<gpg::Rect2i>(), &UnitOccupationRect(*unit), ownerRef);
  archive->Read(
    ResolveUnitSerializerType<gpg::fastvector<WeakPtr<Entity>>>(),
    &unit->mBlipsInRange,
    ownerRef
  );

  archive->ReadUInt(reinterpret_cast<unsigned int*>(&unit->mBlipLastUpdateTick));
  archive->ReadBool(&unit->mIsNotPod);
  archive->ReadBool(&unit->mIsEngineer);
  archive->ReadBool(&unit->mIsNaval);
  archive->ReadBool(&unit->mIsAir);
  archive->ReadBool(&unit->mIsMelee);
  archive->ReadBool(&unit->mUsesGridBasedMotion);
  archive->ReadInt(&unit->CaptorCount);

  archive->Read(
    ResolveUnitSerializerType<gpg::fastvector<ReconBlip*>>(),
    &unit->mReconBlips,
    ownerRef
  );

  // Post-load fixups: re-occupy ground, re-mark the occupation rect on the
  // O-grid when it is non-degenerate, then refresh collision when present.
  if (unit->FootprintDown) {
    unit->ExecuteOccupyGround();
  }

  if (!IsCollisionRectEquivalentToZero(GetReservedOgridRect(*unit))) {
    if (unit->SimulationRef && unit->SimulationRef->mOGrid) {
      unit->SimulationRef->mOGrid->OccupyRect(UnitOccupationRect(*unit));
    }
  }

  unit->NeedSyncGameData = true;

  if (unit->CollisionExtents) {
    unit->UpdateCollision();
  }
}

} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_UnitWeaponInfoTypeInfo_d3b904, moho::preregister_UnitWeaponInfoTypeInfo)
GPG_PREREGISTER_INIT(preregister_SSTIUnitVariableDataTypeInfo_d3b904, moho::preregister_SSTIUnitVariableDataTypeInfo)

namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct UnitLuaFuncDefBootstrap
  {
    UnitLuaFuncDefBootstrap()
    {
      (void)::moho::func_UnitGetUnitId_LuaFuncDef();
      (void)::moho::func_UnitSetCreator_LuaFuncDef();
      (void)::moho::func_UnitGetCargo_LuaFuncDef();
      (void)::moho::func_UnitAlterArmor_LuaFuncDef();
      (void)::moho::func_UnitGetArmorMult_LuaFuncDef();
      (void)::moho::func_UnitClearFocusEntity_LuaFuncDef();
      (void)::moho::func_UnitSetFocusEntity_LuaFuncDef();
      (void)::moho::func_UnitGetFocusUnit_LuaFuncDef();
      (void)::moho::func_UnitGetWeapon_LuaFuncDef();
      (void)::moho::func_UnitGetWeaponCount_LuaFuncDef();
      (void)::moho::func_UnitGetTargetEntity_LuaFuncDef();
      (void)::moho::func_UnitGetHealth_LuaFuncDef();
      (void)::moho::func_UnitGetAttacker_LuaFuncDef();
      (void)::moho::func_UnitEnableManipulators_LuaFuncDef();
      (void)::moho::func_UnitKillManipulator_LuaFuncDef();
      (void)::moho::func_UnitKillManipulators_LuaFuncDef();
      (void)::moho::func_UnitScaleGetBuiltEmitter_LuaFuncDef();
      (void)::moho::func_UnitSetStrategicUnderlay_LuaFuncDef();
      (void)::moho::func_GetIsPaused_LuaFuncDef();
      (void)::moho::func_GetIsAutoMode_LuaFuncDef();
      (void)::moho::func_SetFireState_LuaFuncDef();
      (void)::moho::func_ToggleFireState_LuaFuncDef();
      (void)::moho::func_GetFireState_LuaFuncDef();
      (void)::moho::func_GetIsSubmerged_LuaFuncDef();
      (void)::moho::func_GetIsAutoSurfaceMode_LuaFuncDef();
      (void)::moho::func_UnitGetGuards_LuaFuncDef();
      (void)::moho::func_UnitGetTransportFerryBeacon_LuaFuncDef();
      (void)::moho::func_UnitGetGuardedUnit_LuaFuncDef();
      (void)::moho::func_UnitHasValidTeleportDest_LuaFuncDef();
      (void)::moho::func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef();
      (void)::moho::func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef();
      (void)::moho::func_UnitAddUnitToStorage_LuaFuncDef();
      (void)::moho::func_UnitGetCurrentMoveLocation_LuaFuncDef();
      (void)::moho::func_UnitGiveNukeSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitRemoveNukeSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitGetNukeSiloAmmoCount_LuaFuncDef();
      (void)::moho::func_UnitGiveTacticalSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitRemoveTacticalSiloAmmo_LuaFuncDef();
      (void)::moho::func_UnitGetTacticalSiloAmmoCount_LuaFuncDef();
      (void)::moho::func_UnitSetCustomName_LuaFuncDef();
      (void)::moho::func_UnitGetCommandQueue_LuaFuncDef();
      (void)::moho::func_UnitPrintCommandQueue_LuaFuncDef();
      (void)::moho::func_UnitIsIdleState_LuaFuncDef();
      (void)::moho::func_UnitIsStunned_LuaFuncDef();
      (void)::moho::func_UnitIsBeingBuilt_LuaFuncDef();
      (void)::moho::func_UnitIsPaused_LuaFuncDef();
      (void)::moho::func_UnitSetPaused_LuaFuncDef();
      (void)::moho::func_UnitSetConsumptionActive_LuaFuncDef();
      (void)::moho::func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitSetConsumptionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitSetRegenRate_LuaFuncDef();
      (void)::moho::func_UnitRevertRegenRate_LuaFuncDef();
      (void)::moho::func_UnitSetBuildRate_LuaFuncDef();
      (void)::moho::func_UnitGetBuildRate_LuaFuncDef();
      (void)::moho::func_UnitSetProductionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitSetProductionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitGetConsumptionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitGetProductionPerSecondEnergy_LuaFuncDef();
      (void)::moho::func_UnitGetProductionPerSecondMass_LuaFuncDef();
      (void)::moho::func_UnitGetResourceConsumed_LuaFuncDef();
      (void)::moho::func_UnitSetElevation_LuaFuncDef();
      (void)::moho::func_UnitRevertElevation_LuaFuncDef();
      (void)::moho::func_UnitSetSpeedMult_LuaFuncDef();
      (void)::moho::func_UnitSetAccMult_LuaFuncDef();
      (void)::moho::func_UnitSetTurnMult_LuaFuncDef();
      (void)::moho::func_UnitSetBreakOffTriggerMult_LuaFuncDef();
      (void)::moho::func_UnitSetBreakOffDistanceMult_LuaFuncDef();
      (void)::moho::func_UnitSetStat_LuaFuncDef();
      (void)::moho::func_UnitSetWorkProgress_LuaFuncDef();
      (void)::moho::func_UnitGetWorkProgress_LuaFuncDef();
      (void)::moho::func_UnitIsUnitState_LuaFuncDef();
      (void)::moho::func_UnitSetProductionActive_LuaFuncDef();
      (void)::moho::func_UnitSetBusy_LuaFuncDef();
      (void)::moho::func_UnitSetBlockCommandQueue_LuaFuncDef();
      (void)::moho::func_UnitSetImmobile_LuaFuncDef();
      (void)::moho::func_UnitSetUnSelectable_LuaFuncDef();
      (void)::moho::func_UnitSetDoNotTarget_LuaFuncDef();
      (void)::moho::func_UnitStopSiloBuild_LuaFuncDef();
      (void)::moho::func_UnitSetIsValidTarget_LuaFuncDef();
      (void)::moho::func_UnitIsValidTarget_LuaFuncDef();
      (void)::moho::func_UnitGetNumBuildOrders_LuaFuncDef();
      (void)::moho::func_UnitCalculateWorldPositionFromRelative_LuaFuncDef();
      (void)::moho::func_UnitSetStunned_LuaFuncDef();
      (void)::moho::func_UnitSetUnitState_LuaFuncDef();
      (void)::moho::func_GetScriptBit_LuaFuncDef();
      (void)::moho::func_UnitGetScriptBit_LuaFuncDef();
      (void)::moho::func_UnitSetScriptBit_LuaFuncDef();
      (void)::moho::func_UnitToggleScriptBit_LuaFuncDef();
      (void)::moho::func_UnitToggleFireState_LuaFuncDef();
      (void)::moho::func_UnitSetFireState_LuaFuncDef();
      (void)::moho::func_UnitGetFireState_LuaFuncDef();
      (void)::moho::func_UnitSetAutoMode_LuaFuncDef();
      (void)::moho::func_UnitAddBuildRestriction_LuaFuncDef();
      (void)::moho::func_UnitRemoveBuildRestriction_LuaFuncDef();
      (void)::moho::func_UnitRestoreBuildRestrictions_LuaFuncDef();
      (void)::moho::func_UnitAddCommandCap_LuaFuncDef();
      (void)::moho::func_UnitRemoveCommandCap_LuaFuncDef();
      (void)::moho::func_UnitRestoreCommandCaps_LuaFuncDef();
      (void)::moho::func_UnitAddToggleCap_LuaFuncDef();
      (void)::moho::func_UnitRemoveToggleCap_LuaFuncDef();
      (void)::moho::func_UnitRestoreToggleCaps_LuaFuncDef();
      (void)::moho::func_UnitTestCommandCaps_LuaFuncDef();
      (void)::moho::func_UnitTestToggleCaps_LuaFuncDef();
      (void)::moho::func_UnitGetRallyPoint_LuaFuncDef();
      (void)::moho::func_UnitGetFuelUseTime_LuaFuncDef();
      (void)::moho::func_UnitGetFuelRatio_LuaFuncDef();
      (void)::moho::func_UnitGetShieldRatio_LuaFuncDef();
      (void)::moho::func_UnitGetBlip_LuaFuncDef();
      (void)::moho::func_UnitTransportHasSpaceFor_LuaFuncDef();
      (void)::moho::func_UnitTransportHasAvailableStorage_LuaFuncDef();
      (void)::moho::func_UnitTransportDetachAllUnits_LuaFuncDef();
      (void)::moho::func_UnitShowBone_LuaFuncDef();
      (void)::moho::func_UnitHideBone_LuaFuncDef();
      (void)::moho::func_UnitSetShieldRatio_LuaFuncDef();
      (void)::moho::func_UnitSetReclaimable_LuaFuncDef();
      (void)::moho::func_UnitSetCapturable_LuaFuncDef();
      (void)::moho::func_UnitIsCapturable_LuaFuncDef();
      (void)::moho::func_UnitSetOverchargePaused_LuaFuncDef();
      (void)::moho::func_UnitIsOverchargePaused_LuaFuncDef();
      (void)::moho::func_UnitRevertCollisionShape_LuaFuncDef();
      (void)::moho::func_UnitRecoilImpulse_LuaFuncDef();
      (void)::moho::func_UnitGetCurrentLayer_LuaFuncDef();
      (void)::moho::func_UnitCanPathTo_LuaFuncDef();
      (void)::moho::func_UnitCanPathToRect_LuaFuncDef();
      (void)::moho::func_UnitIsMobile_LuaFuncDef();
      (void)::moho::func_UnitIsMoving_LuaFuncDef();
      (void)::moho::func_UnitGetNavigator_LuaFuncDef();
      (void)::moho::func_UnitGetVelocity_LuaFuncDef();
      (void)::moho::func_UnitGetStat_LuaFuncDef();
      (void)::moho::func_UnitCanBuild_LuaFuncDef();
      (void)::moho::func_UnitSetFuelUseTime_LuaFuncDef();
      (void)::moho::func_UnitSetFuelRatio_LuaFuncDef();
      (void)::moho::func_CreateUnit2_LuaFuncDef();
      (void)::moho::func_CreateUnit_LuaFuncDef();
      (void)::moho::func_CreateUnitHPR_LuaFuncDef();
    }
  };

  const UnitLuaFuncDefBootstrap gUnitLuaFuncDefBootstrap{};
} // namespace
