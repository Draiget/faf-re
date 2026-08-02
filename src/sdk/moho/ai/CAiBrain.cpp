#include "moho/ai/CAiBrain.h"

#include "legacy/algorithms/Sort.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <map>
#include <new>
#include <string>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/ai/EEconResourceTypeInfo.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/EngineVectorHelpers.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/serialization/SBuildReserveInfo.h"
#include "moho/serialization/typeinfo/SBuildReserveInfoTypeInfo.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/SConditionTriggerTypes.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/sim/STIMap.h"
#include "moho/math/Vector3f.h"
#include "moho/math/Wm3DistanceFafExtras.h"
#include "platform/Platform.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"

#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace moho
{
  class CUnitCommand;

  int cfunc_CAiBrainCreateUnitNearSpot(lua_State* luaContext);
  int cfunc_CAiBrainCreateUnitNearSpotL(LuaPlus::LuaState* state);
  int cfunc_CAiBrainCreateResourceBuildingNearest(lua_State* luaContext);
  int cfunc_CAiBrainCreateResourceBuildingNearestL(LuaPlus::LuaState* state);
  int cfunc_CAiBrainFindPlaceToBuild(lua_State* luaContext);
  int cfunc_CAiBrainFindPlaceToBuildL(LuaPlus::LuaState* state);

  // Recovered in CUnitCallTeleport.cpp; forward-declared here so the build-order
  // helper below can invoke it by name (matches the binary's cross-TU call).
  [[nodiscard]] bool TryBuildStructureAt(
    SCoordsVec2* tryPos, const RUnitBlueprint* blueprint, Sim* sim,
    int border, bool wholeMap, bool doCoerce, bool useSkirt);

  /**
   * Address: 0x0057A790 (FUN_0057A790, func_OrderBuildStructure)
   *
   * IDA signature:
   * Moho::CUnitCommand *__thiscall func_OrderBuildStructure(Wm3::Vector3f *ori,
   *   Moho::CAiBrain *brain, Moho::Unit *builder, const char *bpName,
   *   Wm3::Vector3f *pos, float angle);
   *
   * What it does:
   * Resolves `bpName` to a unit blueprint, coerces the build cell to a free
   * footprint around `pos` (TryBuildStructureAt), then issues a
   * UNITCOMMAND_BuildMobile command to `builder`: builds a Y-axis build
   * orientation from `angle`, samples terrain elevation for the target height,
   * assembles a single-cell cell-list and a ground target/secondary target, and
   * dispatches through IssueCommandToSelectedUnits. Returns the created
   * CUnitCommand* (or nullptr when the blueprint is unknown or no free placement
   * exists).
   */
  CUnitCommand* func_OrderBuildStructure(
    Wm3::Vector3f* const ori,
    CAiBrain* const brain,
    Unit* const builder,
    const char* const bpName,
    Wm3::Vector3f* const pos,
    const float angle)
  {
    STIMap* const mapData = brain->mSim->mMapData;

    // Y-axis half-angle build orientation.
    const float halfAngleRad = angle * 0.017453292f * -0.5f;
    const float sinHalf = std::sin(halfAngleRad);
    const float cosHalf = std::cos(halfAngleRad);

    SCoordsVec2 cellPos{};
    cellPos.x = pos->x;
    cellPos.z = pos->z;

    RResId lookupId{};
    gpg::STR_InitFilename(&lookupId.name, bpName);
    RUnitBlueprint* const blueprint = brain->mSim->mRules->GetUnitBlueprint(lookupId);
    if (blueprint == nullptr) {
      return nullptr;
    }

    // Largest footprint side, clamped to a minimum of 8, is the placement border.
    int maxSide = static_cast<int>(blueprint->mFootprint.mSizeX);
    if (maxSide < static_cast<int>(blueprint->mFootprint.mSizeZ)) {
      maxSide = static_cast<int>(blueprint->mFootprint.mSizeZ);
    }
    int border = 8;
    if (maxSide > 8) {
      border = maxSide;
    }

    const bool useWholeMap = builder->ArmyRef->UseWholeMap();
    if (!TryBuildStructureAt(&cellPos, blueprint, brain->mSim, border, useWholeMap, false, false)) {
      return nullptr;
    }

    const float elevation = mapData->GetHeightField()->GetElevation(cellPos.x, cellPos.z);

    SEntitySetTemplateUnit selectedUnits{};
    (void)selectedUnits.AddUnit(builder);

    const Wm3::Vector3f orientation = *ori;

    SSTICommandIssueData commandData(EUnitCommandType::UNITCOMMAND_BuildMobile);

    // Primary target: ground at the resolved cell (Y from terrain elevation).
    commandData.mTarget.mType = EAiTargetType::AITARGET_Ground;
    commandData.mTarget.mEntityId = 0xF0000000u;
    commandData.mTarget.mPos.x = cellPos.x;
    commandData.mTarget.mPos.y = elevation;
    commandData.mTarget.mPos.z = cellPos.z;

    // Build orientation quaternion about the Y axis (W=cos, Y=sin, X=Z=0). The
    // sin*0 stores match the binary's exact writes at +0x40/+0x48.
    commandData.mOri[0] = cosHalf;
    commandData.mOri[1] = sinHalf * 0.0f;
    commandData.mOri[2] = sinHalf;
    commandData.mOri[3] = sinHalf * 0.0f;

    // Single-cell cell-list at the footprint origin.
    // FUN_0057A790 converts both coordinates with bare fistp and never calls
    // __ftol, so this rounds to nearest rather than truncating.
    const SOCellPos cell =
      blueprint->mFootprint.ToCellPos(Wm3::Vec3f{cellPos.x, 0.0f, cellPos.z});
    commandData.mCells.PushBack(cell);

    commandData.mBlueprint = blueprint;

    // Secondary target: ground at the caller-provided orientation vector.
    commandData.mTarget2.mType = EAiTargetType::AITARGET_Ground;
    commandData.mTarget2.mEntityId = 0xF0000000u;
    commandData.mTarget2.mPos.x = orientation.x;
    commandData.mTarget2.mPos.y = orientation.y;
    commandData.mTarget2.mPos.z = orientation.z;

    return IssueCommandToSelectedUnits(brain->mSim, selectedUnits, commandData, false);
  }

  /**
   * Address: 0x0057CA20 (FUN_0057CA20, func_ScheduleBuildStructure)
   *
   * What it does:
   * Records one `(builder, command)` weak reservation pair in
   * `brain->mBuildStructureMap` at `where`.
   */
  void func_ScheduleBuildStructure(Unit* builder, CAiBrain* brain, CUnitCommand* command, Wm3::Vector2i where);
}

namespace
{
  constexpr const char* kAiBrainModulePath = "/lua/aibrain.lua";
  constexpr const char* kAiBrainClassName = "AIBrain";
  constexpr const char* kAiBrainGetUnitBlueprintHelpText = "blueprint = brain:GetUnitBlueprint(bpName)";
  constexpr const char* kAiBrainGetListOfUnitsHelpText =
    "brain:GetListOfUnits(entityCategory, needToBeIdle, requireBuilt)";
  constexpr const char* kAiBrainGetListOfUnitsName = "GetListOfUnits";
  constexpr const char* kAiBrainSetResourceSharingHelpText = "SetResourceSharing(bool)";
  constexpr const char* kAiBrainSetResourceSharingName = "SetResourceSharing";
  constexpr const char* kAiBrainGetArmyStartPosHelpText = "brain:GetArmyStartPos()";
  constexpr const char* kAiBrainGetArmyStartPosName = "GetArmyStartPos";
  constexpr const char* kAiBrainCreateUnitNearSpotHelpText = "brain:CreateUnitNearSpot(unitName, posX, posY)";
  constexpr const char* kAiBrainCreateUnitNearSpotName = "CreateUnitNearSpot";
  constexpr const char* kAiBrainCreateResourceBuildingNearestHelpText =
    "brain:CreateResourceBuildingNearest(structureName, posX, posY)";
  constexpr const char* kAiBrainCreateResourceBuildingNearestName = "CreateResourceBuildingNearest";
  constexpr const char* kAiBrainFindPlaceToBuildHelpText =
    "brain:FindPlaceToBuild(type, structureName, buildingTypes, relative, builder, "
    "optIgnoreAlliance, optOverridePosX, optOverridePosZ, optIgnoreThreatOver)";
  constexpr const char* kAiBrainFindPlaceToBuildName = "FindPlaceToBuild";
  constexpr const char* kAiBrainGetCurrentEnemyHelpText = "Return this brain's current enemy";
  constexpr const char* kAiBrainGetCurrentEnemyName = "GetCurrentEnemy";
  constexpr const char* kAiBrainGetUnitBlueprintName = "GetUnitBlueprint";
  constexpr const char* kAiBrainGetArmyStatHelpText = "brain:GetArmyStat(StatName,defaultValue)";
  constexpr const char* kAiBrainGetArmyStatName = "GetArmyStat";
  constexpr const char* kAiBrainSetArmyStatHelpText = "SetArmyStat(statname,val)";
  constexpr const char* kAiBrainSetArmyStatName = "SetArmyStat";
  constexpr const char* kAiBrainAddArmyStatHelpText = "AddArmyStat(statname,val)";
  constexpr const char* kAiBrainAddArmyStatName = "AddArmyStat";
  constexpr const char* kAiBrainSetGreaterOfHelpText = "SetGreaterOf(statname,val)";
  constexpr const char* kAiBrainSetGreaterOfName = "SetGreaterOf";
  constexpr const char* kAiBrainGetBlueprintStatHelpText = "Return a blueprint stat filtered by category";
  constexpr const char* kAiBrainGetBlueprintStatName = "GetBlueprintStat";
  constexpr const char* kAiBrainGetCurrentUnitsHelpText = "Return how many units of the given categories exist";
  constexpr const char* kAiBrainGetCurrentUnitsName = "GetCurrentUnits";
  constexpr const char* kAiBrainSetArmyStatsTriggerHelpText = "Sets an army stat trigger";
  constexpr const char* kAiBrainSetArmyStatsTriggerName = "SetArmyStatsTrigger";
  constexpr const char* kAiBrainRemoveArmyStatsTriggerHelpText = "Remove an army stats trigger";
  constexpr const char* kAiBrainRemoveArmyStatsTriggerName = "RemoveArmyStatsTrigger";
  constexpr const char* kAiBrainActiveUnitsStatPath = "Units_Active";
  constexpr const char* kAiBrainGetAttackVectorsHelpText = "CAiBrain:GetAttackVectors()";
  constexpr const char* kAiBrainGetAttackVectorsName = "GetAttackVectors";
  constexpr const char* kAiBrainGetUnitsAroundPointHelpText = "CAiBrain:GetUnitsAroundPoint()";
  constexpr const char* kAiBrainGetUnitsAroundPointName = "GetUnitsAroundPoint";
  constexpr const char* kAiBrainGetNumUnitsAroundPointHelpText = "CAiBrain:GetNumUnitsAroundPoint()";
  constexpr const char* kAiBrainGetNumUnitsAroundPointName = "GetNumUnitsAroundPoint";
  constexpr const char* kAiBrainCheckBlockingTerrainHelpText =
    "CAiBrain:CheckBlockingTerrain( startPos, endPos, arcType )";
  constexpr const char* kAiBrainCheckBlockingTerrainName = "CheckBlockingTerrain";
  constexpr const char* kAiBrainCheckBlockingTerrainArcNone = "none";
  constexpr const char* kAiBrainCheckBlockingTerrainArcLow = "low";
  // flt_F6A1D4: 4 arc-sample step multipliers (offset 0x00F6A1D4; the loop bound
  // 0x00F6A1E4 is where the table ends, at the Moho::Unit RTTI descriptor). The
  // cumulative sum {0.707, 1.0, 0.707, 0.0} is a half-sine arc-height profile.
  constexpr float kAiBrainCheckBlockingTerrainArcSteps[] = {0.707f, 0.293f, -0.293f, -0.707f};
  constexpr float kAiBrainCheckBlockingTerrainStartYLift = 1.0f;
  constexpr float kAiBrainCheckBlockingTerrainEndYLift = 0.5f;
  constexpr float kAiBrainCheckBlockingTerrainQuarterStep = 0.25f;
  constexpr float kAiBrainCheckBlockingTerrainArcHighScale = 2.0f;
  constexpr float kAiBrainCheckBlockingTerrainArcLowScale = 0.5f;
  constexpr const char* kAiBrainGetEconomyStoredHelpText = "CAiBrain:GetEconomyStored()";
  constexpr const char* kAiBrainGetEconomyStoredName = "GetEconomyStored";
  constexpr const char* kAiBrainGetEconomyIncomeHelpText = "CAiBrain:GetEconomyIncome()";
  constexpr const char* kAiBrainGetEconomyIncomeName = "GetEconomyIncome";
  constexpr const char* kAiBrainGetEconomyUsageHelpText = "CAiBrain:GetEconomyUsage()";
  constexpr const char* kAiBrainGetEconomyUsageName = "GetEconomyUsage";
  constexpr const char* kAiBrainGetEconomyRequestedHelpText = "CAiBrain:GetEconomyRequested()";
  constexpr const char* kAiBrainGetEconomyRequestedName = "GetEconomyRequested";
  constexpr const char* kAiBrainGetEconomyTrendHelpText = "CAiBrain:GetEconomyTrend()";
  constexpr const char* kAiBrainGetEconomyTrendName = "GetEconomyTrend";
  constexpr const char* kAiBrainGetMapWaterRatioHelpText = "CAiBrain:GetMapWaterRatio()";
  constexpr const char* kAiBrainGetMapWaterRatioName = "GetMapWaterRatio";
  constexpr const char* kAiBrainGetEconomyStoredRatioHelpText = "brain:GetEconomyStoredRatio(resourceType)";
  constexpr const char* kAiBrainGetEconomyStoredRatioName = "GetEconomyStoredRatio";
  constexpr const char* kAiBrainGiveResourceHelpText = "GiveResource(type,amount)";
  constexpr const char* kAiBrainGiveResourceName = "GiveResource";
  constexpr const char* kAiBrainGiveStorageHelpText = "GiveStorage(type,amount)";
  constexpr const char* kAiBrainGiveStorageName = "GiveStorage";
  constexpr const char* kAiBrainTakeResourceHelpText = "taken = TakeResource(type,amount)";
  constexpr const char* kAiBrainTakeResourceName = "TakeResource";
  constexpr const char* kAiBrainFindUnitHelpText =
    "brain:FindUnit(unitCategory, needToBeIdle) -- Return an unit that matches the unit name (can specify idle or not)";
  constexpr const char* kAiBrainFindUnitName = "FindUnit";
  constexpr const char* kAiBrainFindUpgradeBPHelpText =
    "brain:FindUpgradeBP(unitName, upgradeList) -- Return an upgrade blueprint for the unit passed in";
  constexpr const char* kAiBrainFindUpgradeBPName = "FindUpgradeBP";
  constexpr const char* kAiBrainFindUnitToUpgradeHelpText =
    "brain:FindUnitToUpgrade(upgradeList) -- Return a unit and it's upgrade blueprint";
  constexpr const char* kAiBrainFindUnitToUpgradeName = "FindUnitToUpgrade";
  constexpr const char* kAiBrainDecideWhatToBuildHelpText = "brain:DecideWhatToBuild(builder, type, buildingTypes)";
  constexpr const char* kAiBrainDecideWhatToBuildName = "DecideWhatToBuild";
  constexpr const char* kAiBrainBuildStructureHelpText = "brain:BuildStructure(builder, structureName, locationInfo)";
  constexpr const char* kAiBrainBuildStructureName = "BuildStructure";
  constexpr const char* kAiBrainGetAvailableFactoriesName = "GetAvailableFactories";
  constexpr const char* kAiBrainGetAvailableFactoriesHelpText =
    "CAiBrain:GetAvailableFactories([referencePosition[, maxDistance]]) - returns a Lua table of "
    "live non-busy factory units owned by this brain, optionally filtered by XZ distance to a "
    "reference world position";
  constexpr const char* kAiBrainGetThreatAtPositionName = "GetThreatAtPosition";
  constexpr const char* kAiBrainGetThreatAtPositionHelpText =
    "CAiBrain:GetThreatAtPosition(position, ringRadius, restrictToOnMap[, threatTypeName[, armyIndex]]) - "
    "samples the army influence map around `position` (as cell coordinates) and returns the aggregate "
    "threat value for the given threat type, optionally filtered to one army";
  constexpr const char* kAiBrainGetThreatAtPositionInvalidArmyError = "Invalid army index passed in to GetThreatAtPosition";
  constexpr const char* kAiBrainGetThreatBetweenPositionsName = "GetThreatBetweenPositions";
  constexpr const char* kAiBrainGetThreatBetweenPositionsHelpText =
    "CAiBrain:GetThreatBetweenPositions(positionA, positionB, useRingMode, restrictToOnMap[, threatTypeName[, armyIndex]]) - "
    "samples threat along a grid-aligned path between two world positions and returns the aggregated value";
  constexpr const char* kAiBrainGetThreatBetweenPositionsInvalidArmyError = "Invalid army index passed in to GetThreatBetweenPositions";
  constexpr const char* kAiBrainGetThreatsAroundPositionName = "GetThreatsAroundPosition";
  constexpr const char* kAiBrainGetThreatsAroundPositionHelpText =
    "CAiBrain:GetThreatsAroundPosition( position, ring, restriction, [threatType], [armyIndex] )";
  constexpr const char* kAiBrainGetThreatsAroundPositionInvalidArmyError = "Invalid army index passed in to GetThreatsAroundPosition";
  constexpr const char* kAiBrainAssignThreatAtPositionName = "AssignThreatAtPosition";
  constexpr const char* kAiBrainAssignThreatAtPositionHelpText =
    "CAiBrain:AssignThreatAtPosition(position, threatValue[, decayRate[, threatTypeName]]) - "
    "adds `threatValue` to the influence cell containing `position`, then re-derives the matching "
    "decay lane. `decayRate` is clamped to `[0, 1]` and defaults to `-1` (binary substitutes 0.01)";
  constexpr const char* kAiBrainGetHighestThreatPositionName = "GetHighestThreatPosition";
  constexpr const char* kAiBrainGetHighestThreatPositionHelpText =
    "CAiBrain:GetHighestThreatPosition(radius, restrictToOnMap[, threatTypeName[, armyIndex]]) - "
    "returns `(position, threat)` for the cell with the highest threat across this brain's "
    "influence map. Ties are broken by closeness to the army start position";
  constexpr const char* kAiBrainGetHighestThreatPositionInvalidArmyError = "Invalid army index passed in to GetHighestThreatPosition";
  constexpr const char* kAiBrainNumCurrentlyBuildingHelpText =
    "brain:NumCurrentlyBuilding( entityCategoryOfBuildee, entityCategoryOfBuilder )";
  constexpr const char* kAiBrainNumCurrentlyBuildingName = "NumCurrentlyBuilding";
  constexpr const char* kAiBrainBuildUnitHelpText = "brain:BuildUnit()";
  constexpr const char* kAiBrainBuildUnitName = "BuildUnit";
  constexpr const char* kAiBrainIsAnyEngineerBuildingHelpText = "brain:IsAnyEngineerBuilding(category)";
  constexpr const char* kAiBrainIsAnyEngineerBuildingName = "IsAnyEngineerBuilding";
  constexpr const char* kAiBrainGetNumPlatoonsWithAIHelpText = "GetNumPlatoonsWithAI";
  constexpr const char* kAiBrainGetNumPlatoonsWithAIName = "GetNumPlatoonsWithAI";
  constexpr const char* kAiBrainGetNumPlatoonsTemplateNamedHelpText = "GetNumPlatoonsTemplateNamed";
  constexpr const char* kAiBrainGetNumPlatoonsTemplateNamedName = "GetNumPlatoonsTemplateNamed";
  constexpr const char* kAiBrainPlatoonExistsHelpText = "CAiBrain:PlatoonExists()";
  constexpr const char* kAiBrainPlatoonExistsName = "PlatoonExists";
  constexpr const char* kAiBrainGetPlatoonsListHelpText = "CAiBrain:GetPlatoonsList()";
  constexpr const char* kAiBrainGetPlatoonsListName = "GetPlatoonsList";
  constexpr const char* kAiBrainDisbandPlatoonHelpText = "CAiBrain:DisbandPlatoon()";
  constexpr const char* kAiBrainDisbandPlatoonName = "DisbandPlatoon";
  constexpr const char* kAiBrainDisbandPlatoonUniquelyNamedHelpText = "CAiBrain:DisbandPlatoonUniquelyNamed()";
  constexpr const char* kAiBrainDisbandPlatoonUniquelyNamedName = "DisbandPlatoonUniquelyNamed";
  constexpr const char* kAiBrainGetPlatoonUniquelyNamedHelpText = "CAiBrain:GetPlatoonUniquelyNamed()";
  constexpr const char* kAiBrainGetPlatoonUniquelyNamedName = "GetPlatoonUniquelyNamed";
  constexpr const char* kAiBrainGetNoRushTicksHelpText = "CAiBrain:GetNoRushTicks()";
  constexpr const char* kAiBrainGetNoRushTicksName = "GetNoRushTicks";
  constexpr const char* kAiBrainIsOpponentAIRunningHelpText = "Returns true if opponent AI should be running";
  constexpr const char* kAiBrainIsOpponentAIRunningName = "IsOpponentAIRunning";
  constexpr const char* kAiBrainGetArmyIndexHelpText = "Returns the ArmyIndex of the army represented by this brain";
  constexpr const char* kAiBrainGetArmyIndexName = "GetArmyIndex";
  constexpr const char* kAiBrainGetFactionIndexHelpText = "Returns the faction of the army represented by this brain";
  constexpr const char* kAiBrainGetFactionIndexName = "GetFactionIndex";
  constexpr const char* kAiBrainSetCurrentPlanHelpText = "Set the current plan for this brain to run";
  constexpr const char* kAiBrainSetCurrentPlanName = "SetCurrentPlan";
  constexpr const char* kAiBrainGetPersonalityHelpText = "Return the personality for this brain to use";
  constexpr const char* kAiBrainGetPersonalityName = "GetPersonality";
  constexpr const char* kAiBrainSetCurrentEnemyHelpText = "Set the current enemy for this brain to attack";
  constexpr const char* kAiBrainSetCurrentEnemyName = "SetCurrentEnemy";
  constexpr const char* kAiBrainLuaClassName = "CAiBrain";
  constexpr const char* kAiBrainCanBuildStructureAtName = "CanBuildStructureAt";
  constexpr const char* kAiBrainCanBuildStructureAtHelpText = "brain:CanBuildStructureAt(blueprint, location)";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedArgRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kAiBrainSetUpAttackVectorsToArmyName = "SetUpAttackVectorsToArmy";
  constexpr const char* kAiBrainSetUpAttackVectorsToArmyHelpText = "CAiBrain:SetUpAttackVectorsToArmy()";
  constexpr const char* kAiBrainPickBestAttackVectorName = "PickBestAttackVector";
  constexpr const char* kAiBrainPickBestAttackVectorHelpText = "CAiBrain:PickBestAttackVector()";
  // Binary string literals (bin/2025.7.1/ForgedAlliance.exe): the arg-count Warnf and the
  // two user-callback error strings emitted by CAiBrain::PickBestAttackVector.
  constexpr const char* kAiBrainPickBestAttackVectorArgCountWarning =
    "Error in CAiBrain::PickBestAttackVector: Expected 6 or 8 arguments, got 7 instead.";
  constexpr const char* kAiBrainPickBestAttackVectorLoadCallbackError =
    "Error loading user-supplied callback in CAiBrain::PickBestAttackVector: %s";
  constexpr const char* kAiBrainPickBestAttackVectorRunCallbackError =
    "Error running user-supplied callback in CAiBrain::PickBestAttackVector: %s";
  constexpr const char* kAiBrainFindClosestArmyWithBaseName = "FindClosestArmyWithBase";
  constexpr const char* kAiBrainFindClosestArmyWithBaseHelpText =
    "CAiBrain:FindClosestArmyWithBase(allianceState) - returns the brain of the closest "
    "army (filtered by alliance with this brain) that owns at least one structure, or nil";
  constexpr const char* kAiBrainBuildPlatoonName = "BuildPlatoon";
  constexpr const char* kAiBrainBuildPlatoonHelpText =
    "CAiBrain:BuildPlatoon(buildPlanTable, builderTable, countMultiplier) - issues build "
    "commands for each `(blueprintId, ?, baseCount)` row, multiplied by `countMultiplier`, "
    "rotating across `builderTable` builders";
  constexpr const char* kAiBrainAssignUnitsToPlatoonName = "AssignUnitsToPlatoon";
  constexpr const char* kAiBrainAssignUnitsToPlatoonHelpText =
    "CAiBrain:AssignUnitsToPlatoon(platoonOrName, unitTable, squadClass, squadName) - moves "
    "every unit from `unitTable` into the named platoon's `squadClass` squad (creating the "
    "squad if it doesn't exist), removing them from any other platoon they currently belong to";
  constexpr const char* kAiBrainMakePlatoonName = "MakePlatoon";
  constexpr const char* kAiBrainMakePlatoonHelpText =
    "CAiBrain:MakePlatoon(nameOrTable, plan?) - creates a platoon from a (name, plan) pair "
    "of strings, or builds a multi-squad platoon from a table of "
    "{platoonName, planName, [bp, ?, count, squadClass, squadName]...} entries";
  constexpr const char* kAiBrainCanBuildPlatoonName = "CanBuildPlatoon";
  constexpr const char* kAiBrainCanBuildPlatoonHelpText =
    "CAiBrain:CanBuildPlatoon(platoonTemplate, suggestedFactories?) - returns either nil "
    "(cannot build) or a table of concrete factory units that can collectively build every "
    "row of the template; optionally restricted to `suggestedFactories`";
  constexpr const char* kAiBrainSuggestedFactoryListNotTable = "Suggested factory list is not a table!";
  constexpr std::int32_t kAiDebugGridStep = 32;
  constexpr std::int32_t kAiDebugGridLineDepth = static_cast<std::int32_t>(0xFF7FFF7Fu);
  constexpr std::int32_t kAiDebugAttackLineDepth = static_cast<std::int32_t>(0xFFFFFF00u);
  constexpr std::uint32_t kAiDebugAttackRingDepth = 0xFFFF0000u;
  constexpr std::uint32_t kAiDebugAttackRingPrecision = 6u;
  constexpr float kAiDebugAttackRingRadius = 5.0f;
  constexpr const char* kEngineerCategoryName = "ENGINEER";
  constexpr std::int32_t kBuildingStateTag = 5;
  std::int32_t gRecoveredCScrLuaMetatableFactoryCAiBrainIndex = 0;

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  /**
   * Address: 0x0057C9F0 (FUN_0057C9F0, func_CopySPointVector)
   *
   * What it does:
   * Copies one `SPointVector` payload into destination storage and returns
   * the destination pointer.
   */
  [[maybe_unused]] [[nodiscard]] SPointVector* CopySPointVectorAndReturnDestination(
    SPointVector* const destination,
    const SPointVector* const source
  ) noexcept
  {
    destination->point = source->point;
    destination->vector = source->vector;
    return destination;
  }

  /**
   * Address: 0x00583130 (FUN_00583130, func_CopyPointVects)
   *
   * What it does:
   * Copies one half-open `SPointVector` range into destination storage and
   * returns the end pointer reached by the copy loop.
   */
  [[maybe_unused]] [[nodiscard]] SPointVector* CopyPointVectorRangeAndReturnEnd(
    SPointVector* destination,
    const SPointVector* sourceBegin,
    const SPointVector* sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      (void)CopySPointVectorAndReturnDestination(destination, sourceBegin);
      ++destination;
      ++sourceBegin;
    }

    return destination;
  }

  /**
   * Address: 0x0057D8B0 (FUN_0057D8B0)
   *
   * What it does:
   * Resets one `vector<SPointVector>` logical size to zero while preserving the
   * current allocation block.
   */
  [[maybe_unused]] [[nodiscard]] SPointVector* ResetSPointVectorVectorEndToBegin(
    msvc8::vector<SPointVector>& storage
  ) noexcept
  {
    auto& runtime = msvc8::AsVectorRuntimeView(storage);
    if (runtime.begin != runtime.end) {
      runtime.end = CopyPointVectorRangeAndReturnEnd(runtime.begin, runtime.end, runtime.end);
    }

    return runtime.end;
  }

  /**
   * Address: 0x00583A20 (FUN_00583A20, vector-int assign lane)
   *
   * What it does:
   * Copy-assigns one legacy `msvc8::vector<int>` lane into destination and
   * returns destination.
   */
  [[maybe_unused]] [[nodiscard]] msvc8::vector<int>* CopyAssignLegacyIntVector(
    msvc8::vector<int>* const destination,
    const msvc8::vector<int>* const source
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    if (destination != source) {
      *destination = *source;
    }
    return destination;
  }

  struct ScalarAndIntVectorLane
  {
    std::int32_t mScalar = 0;
    msvc8::vector<int> mValues{};
  };
  static_assert(sizeof(ScalarAndIntVectorLane) == 0x14, "ScalarAndIntVectorLane size must be 0x14");

  /**
   * Address: 0x005837F0 (FUN_005837F0, scalar+vector reset range lane)
   * Address: 0x00580D10 (FUN_00580D10)
   *
   * What it does:
   * Resets each scalar lane to zero and releases each backing int-vector
   * allocation in one half-open `[begin, end)` range.
   */
  [[maybe_unused]] void ResetScalarAndIntVectorLaneRange(
    ScalarAndIntVectorLane* begin,
    ScalarAndIntVectorLane* const end
  ) noexcept
  {
    while (begin != end) {
      begin->mScalar = 0;

      auto& valuesView = msvc8::AsVectorRuntimeView(begin->mValues);
      if (valuesView.begin != nullptr) {
        ::operator delete(valuesView.begin);
      }
      valuesView.begin = nullptr;
      valuesView.end = nullptr;
      valuesView.capacityEnd = nullptr;

      ++begin;
    }
  }

  /**
   * Address: 0x00583C30 (FUN_00583C30, vector-int clear logical range lane)
   *
   * What it does:
   * Clears one legacy int-vector logical range while retaining capacity.
   */
  [[maybe_unused]] void ClearLegacyIntVectorLogicalRange(msvc8::vector<int>* const storage) noexcept
  {
    if (storage != nullptr) {
      storage->clear();
    }
  }

  /**
   * Address: 0x00584480 (FUN_00584480, copy int range lane)
   *
   * What it does:
   * Copies one half-open int range into `destination` and returns the
   * one-past-end destination pointer.
   */
  [[maybe_unused]] [[nodiscard]] int* CopyLegacyIntRangeAndReturnEnd(
    int* const destination,
    const int* const sourceBegin,
    const int* const sourceEnd
  ) noexcept
  {
    if (destination == nullptr || sourceBegin == nullptr || sourceEnd == nullptr || sourceEnd <= sourceBegin) {
      return destination;
    }

    const std::size_t count = static_cast<std::size_t>(sourceEnd - sourceBegin);
    std::memmove(destination, sourceBegin, count * sizeof(int));
    return destination + count;
  }

  /**
   * Address: 0x00583850 (FUN_00583850, scalar+vector fill-copy range lane)
   *
   * What it does:
   * Fills one half-open destination range by copying the scalar lane and
   * legacy int-vector lane from a single prototype element.
   */
  [[maybe_unused]] [[nodiscard]] ScalarAndIntVectorLane* FillScalarAndIntVectorRangeFromPrototype(
    ScalarAndIntVectorLane* destinationBegin,
    ScalarAndIntVectorLane* const destinationEnd,
    const ScalarAndIntVectorLane& prototype
  )
  {
    while (destinationBegin != destinationEnd) {
      destinationBegin->mScalar = prototype.mScalar;
      (void)CopyAssignLegacyIntVector(&destinationBegin->mValues, &prototype.mValues);
      ++destinationBegin;
    }

    return destinationBegin;
  }

  /**
   * Address: 0x00582380 (FUN_00582380)
   *
   * What it does:
   * Source-first register adapter for one scalar+legacy-int-vector
   * fill-from-prototype range-copy lane.
   */
  [[maybe_unused]] [[nodiscard]] ScalarAndIntVectorLane* FillScalarAndIntVectorRangeFromPrototypeSourceFirstAdapter(
    const ScalarAndIntVectorLane* const prototype,
    ScalarAndIntVectorLane* const destinationEnd,
    ScalarAndIntVectorLane* const destinationBegin
  )
  {
    if (prototype == nullptr) {
      return destinationBegin;
    }

    return FillScalarAndIntVectorRangeFromPrototype(destinationBegin, destinationEnd, *prototype);
  }

  struct CSquadUnitsRuntimeView
  {
    std::uint8_t pad_0000_0010[0x10];
    void** mUnitSlotsStart; // +0x10
    void** mUnitSlotsEnd;   // +0x14
  };
  static_assert(
    offsetof(CSquadUnitsRuntimeView, mUnitSlotsStart) == 0x10, "CSquadUnitsRuntimeView::mUnitSlotsStart offset must be 0x10"
  );
  static_assert(
    offsetof(CSquadUnitsRuntimeView, mUnitSlotsEnd) == 0x14, "CSquadUnitsRuntimeView::mUnitSlotsEnd offset must be 0x14"
  );

  struct CPlatoonLuaRuntimeView
  {
    std::uint8_t pad_0000_0020[0x20];
    LuaPlus::LuaObject mLuaObj; // +0x20
    std::uint8_t pad_0034_0040[0x0C];
    CSquadUnitsRuntimeView** mSquadStart; // +0x40
    CSquadUnitsRuntimeView** mSquadEnd;   // +0x44
    std::uint8_t pad_0048_00AC[0x64];
    msvc8::string mUniqueName; // +0xAC
  };
  static_assert(offsetof(CPlatoonLuaRuntimeView, mLuaObj) == 0x20, "CPlatoonLuaRuntimeView::mLuaObj offset must be 0x20");
  static_assert(
    offsetof(CPlatoonLuaRuntimeView, mSquadStart) == 0x40, "CPlatoonLuaRuntimeView::mSquadStart offset must be 0x40"
  );
  static_assert(offsetof(CPlatoonLuaRuntimeView, mSquadEnd) == 0x44, "CPlatoonLuaRuntimeView::mSquadEnd offset must be 0x44");
  static_assert(
    offsetof(CPlatoonLuaRuntimeView, mUniqueName) == 0xAC, "CPlatoonLuaRuntimeView::mUniqueName offset must be 0xAC"
  );

  [[nodiscard]] std::int32_t CountSquadUnits(const CSquadUnitsRuntimeView* const squad) noexcept
  {
    if (squad == nullptr || squad->mUnitSlotsStart == nullptr || squad->mUnitSlotsEnd == nullptr
        || squad->mUnitSlotsEnd < squad->mUnitSlotsStart) {
      return 0;
    }

    return static_cast<std::int32_t>(squad->mUnitSlotsEnd - squad->mUnitSlotsStart);
  }

  [[nodiscard]] std::int32_t CountPlatoonUnits(const CPlatoonLuaRuntimeView& platoon) noexcept
  {
    if (platoon.mSquadStart == nullptr || platoon.mSquadEnd == nullptr || platoon.mSquadEnd < platoon.mSquadStart) {
      return 0;
    }

    std::int32_t unitCount = 0;
    for (CSquadUnitsRuntimeView* const* squadIt = platoon.mSquadStart; squadIt != platoon.mSquadEnd; ++squadIt) {
      unitCount += CountSquadUnits(*squadIt);
    }
    return unitCount;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("Sim");
    return fallbackSet;
  }

  [[nodiscard]] gpg::RRef MakeEconResourceRef(moho::EEconResource* const resource)
  {
    gpg::RRef enumRef{};
    if (resource == nullptr) {
      return enumRef;
    }

    static gpg::RType* sEconResourceType = nullptr;
    if (sEconResourceType == nullptr) {
      sEconResourceType = gpg::LookupRType(typeid(moho::EEconResource));
    }

    enumRef.mObj = resource;
    enumRef.mType = sEconResourceType;
    return enumRef;
  }

  [[nodiscard]] float& SelectResourceLane(moho::SEconPair& value, const moho::EEconResource resource) noexcept
  {
    return resource == moho::ECON_MASS ? value.MASS : value.ENERGY;
  }

  [[nodiscard]] const float& SelectResourceLane(const moho::SEconPair& value, const moho::EEconResource resource) noexcept
  {
    return resource == moho::ECON_MASS ? value.MASS : value.ENERGY;
  }

  [[nodiscard]] std::uint64_t SelectResourceLane(
    const moho::SEconStoragePair& value, const moho::EEconResource resource
  ) noexcept
  {
    return resource == moho::ECON_MASS ? value.MASS : value.ENERGY;
  }

  [[nodiscard]] moho::CAiBrain* DecodeEconomyResourceQueryArgs(
    LuaPlus::LuaState* const state,
    const char* const helpText,
    moho::EEconResource& outResource
  )
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, helpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
    moho::CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

    gpg::RRef enumRef = MakeEconResourceRef(&outResource);
    const LuaPlus::LuaStackObject resourceTypeArg(state, 2);
    const char* const resourceTypeName = lua_tostring(rawState, 2);
    if (resourceTypeName == nullptr) {
      resourceTypeArg.TypeError("string");
    }
    SCR_GetEnum(state, resourceTypeName, enumRef);
    return brain;
  }

  [[nodiscard]] std::int32_t AtomicLoadStatValueBits(volatile std::int32_t* const valueBits) noexcept
  {
    return static_cast<std::int32_t>(
      InterlockedCompareExchange(reinterpret_cast<volatile long*>(valueBits), 0L, 0L)
    );
  }

  void AtomicStoreStatValueBits(volatile std::int32_t* const valueBits, const std::int32_t nextValueBits) noexcept
  {
    for (;;) {
      const std::int32_t observedValueBits = AtomicLoadStatValueBits(valueBits);
      const std::int32_t exchangedValueBits = static_cast<std::int32_t>(InterlockedCompareExchange(
        reinterpret_cast<volatile long*>(valueBits),
        static_cast<long>(nextValueBits),
        static_cast<long>(observedValueBits)
      ));
      if (exchangedValueBits == observedValueBits) {
        return;
      }
    }
  }

  void AtomicAddFloatStatValueBits(volatile std::int32_t* const valueBits, const float delta) noexcept
  {
    for (;;) {
      const std::int32_t observedValueBits = AtomicLoadStatValueBits(valueBits);

      float observedValue = 0.0f;
      std::memcpy(&observedValue, &observedValueBits, sizeof(observedValue));
      const float nextValue = observedValue + delta;

      std::int32_t nextValueBits = 0;
      std::memcpy(&nextValueBits, &nextValue, sizeof(nextValueBits));

      const std::int32_t exchangedValueBits = static_cast<std::int32_t>(InterlockedCompareExchange(
        reinterpret_cast<volatile long*>(valueBits),
        static_cast<long>(nextValueBits),
        static_cast<long>(observedValueBits)
      ));
      if (exchangedValueBits == observedValueBits) {
        return;
      }
    }
  }

  [[nodiscard]] moho::CArmyStats* ResolveArmyStats(moho::CAiBrain* const brain)
  {
    if (brain == nullptr || brain->mArmy == nullptr) {
      return nullptr;
    }

    return brain->mArmy->GetArmyStats();
  }

  [[nodiscard]] moho::CArmyStatItem* ResolveArmyStatPathAsInt(
    moho::CArmyStats* const armyStats, const char* const statPath
  )
  {
    if (armyStats == nullptr) {
      return nullptr;
    }

    return armyStats->TraverseTables(statPath ? statPath : "", true);
  }

  [[nodiscard]] moho::CArmyStatItem* ResolveArmyStatPathAsFloat(
    moho::CArmyStats* const armyStats, const char* const statPath
  )
  {
    if (armyStats == nullptr) {
      return nullptr;
    }

    const char* const normalizedPath = statPath ? statPath : "";
    if (moho::CArmyStatItem* const existing = armyStats->TraverseTables(normalizedPath, false); existing != nullptr) {
      return existing;
    }

    moho::CArmyStatItem* const created = armyStats->TraverseTables(normalizedPath, true);
    if (created != nullptr) {
      created->SynchronizeAsFloat();
    }

    return created;
  }

  [[nodiscard]] moho::CArmyStatItem* ResolveCachedArmyStatPath(
    moho::CArmyStats* const armyStats, const char* const statPath
  )
  {
    if (armyStats == nullptr) {
      return nullptr;
    }

    const char* const normalizedPath = statPath ? statPath : "";
    if (moho::CArmyStatItem* const existing = armyStats->GetStat(normalizedPath); existing != nullptr) {
      return existing;
    }

    moho::CArmyStatItem* const created = armyStats->TraverseTables(normalizedPath, true);
    if (created == nullptr) {
      return nullptr;
    }

    if (moho::CArmyStatItem* const cached = armyStats->GetStat(normalizedPath); cached != nullptr) {
      return cached;
    }

    return created;
  }

  void SetArmyStatIntToGreaterOf(
    moho::CArmyStats* const armyStats, const char* const statPath, const std::int32_t candidate
  )
  {
    if (moho::CArmyStatItem* const statItem = ResolveCachedArmyStatPath(armyStats, statPath); statItem != nullptr) {
      statItem->SynchronizeAsInt();

      for (;;) {
        const std::int32_t observed = AtomicLoadStatValueBits(&statItem->mPrimaryValueBits);
        if (candidate <= observed) {
          return;
        }

        const std::int32_t exchanged = static_cast<std::int32_t>(InterlockedCompareExchange(
          reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits),
          static_cast<long>(candidate),
          static_cast<long>(observed)
        ));
        if (exchanged == observed) {
          return;
        }
      }
    }
  }

  void SetArmyStatFloatToGreaterOf(moho::CArmyStats* const armyStats, const char* const statPath, const float candidate)
  {
    if (moho::CArmyStatItem* const statItem = ResolveCachedArmyStatPath(armyStats, statPath); statItem != nullptr) {
      statItem->SynchronizeAsFloat();

      std::int32_t candidateBits = 0;
      std::memcpy(&candidateBits, &candidate, sizeof(candidateBits));

      for (;;) {
        const std::int32_t observedBits = AtomicLoadStatValueBits(&statItem->mPrimaryValueBits);
        float observed = 0.0f;
        std::memcpy(&observed, &observedBits, sizeof(observed));
        if (candidate <= observed) {
          return;
        }

        const std::int32_t exchangedBits = static_cast<std::int32_t>(InterlockedCompareExchange(
          reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits),
          static_cast<long>(candidateBits),
          static_cast<long>(observedBits)
        ));
        if (exchangedBits == observedBits) {
          return;
        }
      }
    }
  }

  [[nodiscard]] gpg::RRef MakeTriggerOperatorRef(moho::ETriggerOperator* const triggerOperator)
  {
    gpg::RRef out{};
    if (triggerOperator == nullptr) {
      return out;
    }

    static gpg::RType* sTriggerOperatorType = nullptr;
    if (sTriggerOperatorType == nullptr) {
      sTriggerOperatorType = gpg::LookupRType(typeid(moho::ETriggerOperator));
    }

    out.mObj = triggerOperator;
    out.mType = sTriggerOperatorType;
    return out;
  }

  struct CEconStorageRuntimeView
  {
    std::uint8_t* economyRuntime; // +0x00
    float amounts[4];             // +0x04
  };

  static_assert(
    offsetof(CEconStorageRuntimeView, economyRuntime) == 0x00,
    "CEconStorageRuntimeView::economyRuntime offset must be 0x00"
  );
  static_assert(offsetof(CEconStorageRuntimeView, amounts) == 0x04, "CEconStorageRuntimeView::amounts offset must be 0x04");

  void ApplyEconStorageDelta(CEconStorageRuntimeView& storage, const std::int32_t direction)
  {
    auto* const econStorage = reinterpret_cast<moho::CEconStorage*>(&storage);
    (void)econStorage->Chng(direction);
  }

  struct UnitBuilderSubsystemView
  {
    std::uint8_t mPad0000To0553[0x554];
    void* mBuilderSubsystem; // +0x554
  };

  static_assert(
    offsetof(UnitBuilderSubsystemView, mBuilderSubsystem) == 0x554,
    "UnitBuilderSubsystemView::mBuilderSubsystem offset must be 0x554"
  );

  [[nodiscard]] bool UnitHasBuilderSubsystem(const Unit* const unit) noexcept
  {
    if (unit == nullptr) {
      return false;
    }

    const auto* const view = reinterpret_cast<const UnitBuilderSubsystemView*>(unit);
    return view->mBuilderSubsystem != nullptr;
  }

  /**
   * Address: 0x0057B0C0 (FUN_0057B0C0, sub_57B0C0)
   * Mangled: (file-static; no external linkage)
   *
   * IDA signature:
   * char __userpurge sub_57B0C0@<al>(Moho::Unit *builder@<ecx>, int count@<edx>,
   *                                  Moho::RUnitBlueprint *blueprint@<edi>,
   *                                  Moho::CAiBrain *brain);
   *
   * What it does:
   * Verifies `builder` owns a builder subsystem and `blueprint` is non-null,
   * builds a single-element selected-unit set from `builder`, then issues one
   * `UNITCOMMAND_BuildFactory` command carrying `blueprint` `count` times
   * against `brain->mSim`. Returns false when the builder/blueprint gate fails.
   */
  [[nodiscard]] bool IssueBuildFactoryCommands(
    Unit* const builder, const int count, RUnitBlueprint* const blueprint, CAiBrain* const brain
  )
  {
    if (!UnitHasBuilderSubsystem(builder) || blueprint == nullptr) {
      return false;
    }

    SEntitySetTemplateUnit selectedUnits{};
    (void)selectedUnits.AddUnit(builder);

    for (int issueIndex = 0; issueIndex < count; ++issueIndex) {
      SSTICommandIssueData issueData(EUnitCommandType::UNITCOMMAND_BuildFactory);
      issueData.mBlueprint = blueprint;
      (void)IssueCommandToSelectedUnits(brain->mSim, selectedUnits, issueData, false);
    }

    return true;
  }

  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData != nullptr) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, top);
    return out;
  }

  [[nodiscard]] gpg::RType* CachedEntityCategorySetType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::EntityCategorySet));
    }
    return sType;
  }

  [[nodiscard]] moho::EntityCategorySet* ResolveEntityCategorySetFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    if (gpg::RType* const expectedType = CachedEntityCategorySetType(); expectedType != nullptr) {
      const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, expectedType);
      if (upcast.mObj != nullptr) {
        return static_cast<moho::EntityCategorySet*>(upcast.mObj);
      }
    }

    const char* const typeName = userDataRef.GetTypeName();
    if (typeName != nullptr
        && (std::strstr(typeName, "EntityCategory") != nullptr || std::strstr(typeName, "BVSet") != nullptr)) {
      return static_cast<moho::EntityCategorySet*>(userDataRef.mObj);
    }

    return nullptr;
  }

  [[nodiscard]] bool CategoryContainsBlueprint(
    const moho::EntityCategorySet* const categorySet,
    const moho::RUnitBlueprint* const blueprint
  )
  {
    if (categorySet == nullptr || blueprint == nullptr) {
      return false;
    }

    return categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  }

  [[nodiscard]] bool UnitHasHeadCommand(const moho::Unit* const unit)
  {
    if (unit == nullptr || unit->CommandQueue == nullptr) {
      return false;
    }

    const msvc8::vector<moho::WeakPtr<moho::CUnitCommand>>& commands = unit->CommandQueue->mCommandVec;
    if (commands.empty()) {
      return false;
    }

    return commands.front().GetObjectPtr() != nullptr;
  }

  void SubtractCategoryWordRange(CategoryWordRangeView& lhs, const CategoryWordRangeView& rhs)
  {
    const std::size_t lhsCount = lhs.WordCount();
    const std::size_t rhsCount = rhs.WordCount();
    if (lhsCount == 0 || rhsCount == 0) {
      return;
    }

    const std::uint32_t lhsBeginWord = lhs.mBits.mFirstWordIndex;
    const std::uint32_t rhsBeginWord = rhs.mBits.mFirstWordIndex;
    const std::uint32_t lhsEndWord = lhsBeginWord + static_cast<std::uint32_t>(lhsCount);
    const std::uint32_t rhsEndWord = rhsBeginWord + static_cast<std::uint32_t>(rhsCount);

    const std::uint32_t overlapBegin = lhsBeginWord < rhsBeginWord ? rhsBeginWord : lhsBeginWord;
    const std::uint32_t overlapEnd = lhsEndWord < rhsEndWord ? lhsEndWord : rhsEndWord;
    if (overlapBegin >= overlapEnd) {
      return;
    }

    std::uint32_t* const lhsWords = lhs.WordData();
    const std::uint32_t* const rhsWords = rhs.WordData();
    for (std::uint32_t absoluteWord = overlapBegin; absoluteWord < overlapEnd; ++absoluteWord) {
      const std::size_t lhsIndex = static_cast<std::size_t>(absoluteWord - lhsBeginWord);
      const std::size_t rhsIndex = static_cast<std::size_t>(absoluteWord - rhsBeginWord);
      lhsWords[lhsIndex] &= ~rhsWords[rhsIndex];
    }
  }

  [[nodiscard]] moho::Unit* FindUpgradeableArmyUnitByBlueprint(
    moho::CAiBrain* const brain,
    const moho::RUnitBlueprint* const fromBlueprint
  )
  {
    if (brain == nullptr || brain->mArmy == nullptr || fromBlueprint == nullptr) {
      return nullptr;
    }

    moho::Sim* const sim = brain->mArmy->Simulation;
    if (sim == nullptr || sim->mEntityDB == nullptr) {
      return nullptr;
    }

    const std::uint32_t armyIndex = static_cast<std::uint32_t>(brain->mArmy->ArmyId);
    moho::CEntityDbAllUnitsNode* node = sim->mEntityDB->AllUnitsEnd(armyIndex);
    moho::CEntityDbAllUnitsNode* const endNode = sim->mEntityDB->AllUnitsEnd(armyIndex + 1u);
    while (node != endNode) {
      moho::Unit* const unit = moho::CEntityDb::UnitFromAllUnitsNode(node);
      if (unit == nullptr) {
        break;
      }

      if (!unit->IsDead() && !unit->IsBeingBuilt() && !UnitHasHeadCommand(unit)) {
        const moho::RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
        if (
          unitBlueprint != nullptr
          && gpg::STR_EqualsNoCase(unitBlueprint->mBlueprintId.c_str(), fromBlueprint->mBlueprintId.c_str())
        ) {
          return unit;
        }
      }

      node = moho::CEntityDb::NextAllUnitsNode(node);
    }

    return nullptr;
  }

  /**
   * Address: 0x0062D7E0 (FUN_0062D7E0, func_CalulateWaterRatio)
   *
   * What it does:
   * Samples the map height field at an 8x8 grid step and returns the ratio
   * of sampled cells where water elevation is above sampled terrain elevation.
   */
  [[nodiscard]] float CalculateMapWaterRatio(const moho::STIMap& map)
  {
    const moho::CHeightField* const heightField = map.mHeightField.get();
    const int mapWidth = heightField->width;
    const int mapHeight = heightField->height;

    int widthBucketCount = static_cast<int>((static_cast<std::uint32_t>(mapWidth - 1) >> 3) - 1u);
    int heightBucketCount = static_cast<int>((static_cast<std::uint32_t>(mapHeight - 1) >> 3) - 1u);

    const float waterElevation = (map.mWaterEnabled != 0u) ? map.mWaterElevation : -10000.0f;
    constexpr float kHeightToWorldScale = 0.0078125f;
    constexpr float kSampleUnit = 1.0f;

    auto ClampX = [mapWidth](const int x) noexcept -> int {
      int clamped = (x < (mapWidth - 1)) ? x : (mapWidth - 1);
      if (clamped < 0) {
        clamped = 0;
      }
      return clamped;
    };

    auto ClampZ = [mapHeight](const int z) noexcept -> int {
      int clamped = (z < (mapHeight - 1)) ? z : (mapHeight - 1);
      if (clamped < 0) {
        clamped = 0;
      }
      return clamped;
    };

    auto SampleElevation = [&](const int x, const int z) noexcept -> float {
      const int sx = ClampX(x);
      const int sz = ClampZ(z);
      const std::uint16_t heightValue = heightField->data[sx + (sz * mapWidth)];
      return static_cast<float>(heightValue) * kHeightToWorldScale;
    };

    float underwaterSampleCount = 0.0f;
    float totalSampleCount = 0.0f;

    if (widthBucketCount > 1) {
      int sampleX = 8;
      int xLoopCount = widthBucketCount - 1;
      while (xLoopCount != 0) {
        int zBlockBase = 1;
        if ((heightBucketCount - 1) >= 4) {
          int zBlockLoopCount = static_cast<int>((static_cast<std::uint32_t>(heightBucketCount - 5) >> 2) + 1u);
          zBlockBase = (zBlockLoopCount * 4) + 1;

          int sampleZ = 24;
          while (zBlockLoopCount != 0) {
            if (waterElevation > SampleElevation(sampleX, sampleZ - 16)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;

            if (waterElevation > SampleElevation(sampleX, sampleZ - 8)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;

            if (waterElevation > SampleElevation(sampleX, sampleZ)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;

            if (waterElevation > SampleElevation(sampleX, sampleZ + 8)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;

            sampleZ += 32;
            --zBlockLoopCount;
          }
        }

        if (zBlockBase < heightBucketCount) {
          int sampleZ = zBlockBase * 8;
          int zTailCount = heightBucketCount - zBlockBase;
          while (zTailCount != 0) {
            if (waterElevation > SampleElevation(sampleX, sampleZ)) {
              underwaterSampleCount += kSampleUnit;
            }
            totalSampleCount += kSampleUnit;
            sampleZ += 8;
            --zTailCount;
          }
        }

        sampleX += 8;
        --xLoopCount;
      }
    }

    return underwaterSampleCount / totalSampleCount;
  }

  /**
   * Address: 0x00581910 (FUN_00581910, func_CreateCAiBrainLuaObject)
   *
   * What it does:
   * Returns one cached `CAiBrain` metatable object from
   * `CScrLuaMetatableFactory<CAiBrain>`.
   */
  [[nodiscard]] LuaPlus::LuaObject CreateCAiBrainLuaObject(LuaPlus::LuaState* const state)
  {
    return CScrLuaMetatableFactory<CAiBrain>::Instance().Get(state);
  }

  /**
   * Address: 0x0057A350 (FUN_0057A350, func_LoadAiBrain)
   *
   * What it does:
   * Imports `/lua/aibrain.lua` and returns the `AIBrain` class table when
   * present; otherwise logs one warning and falls back to the native
   * `CAiBrain` metatable factory object.
   */
  [[nodiscard]] LuaPlus::LuaObject LoadAiBrainFactoryObject(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject moduleObj = SCR_ImportLuaModule(state, kAiBrainModulePath);
    if (moduleObj) {
      LuaPlus::LuaObject classObj = SCR_GetLuaTableField(state, moduleObj, kAiBrainClassName);
      if (!classObj.IsNil()) {
        return classObj;
      }
    }

    gpg::Logf("Can't find AIBrain, using CAiBrain directly");
    return CreateCAiBrainLuaObject(state);
  }

  [[nodiscard]] SBuildStructurePositionNode* AllocateBuildStructureNode()
  {
    auto* const node = static_cast<SBuildStructurePositionNode*>(::operator new(sizeof(SBuildStructurePositionNode)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->mGridPosition = {};
    node->mBuildInfo.mPlacementLink.mOwnerSlot = nullptr;
    node->mBuildInfo.mPlacementLink.mNext = nullptr;
    node->mBuildInfo.mResourceLink.mOwnerSlot = nullptr;
    node->mBuildInfo.mResourceLink.mNext = nullptr;
    node->mColor = 1;
    node->mIsNil = 0;
    node->mPad26[0] = 0;
    node->mPad26[1] = 0;
    return node;
  }

  void InitializeBuildStructureMap(SBuildStructurePositionMap& map)
  {
    map.mMeta00 = 0;
    map.mHead = AllocateBuildStructureNode();
    map.mHead->mIsNil = 1;
    map.mHead->parent = map.mHead;
    map.mHead->left = map.mHead;
    map.mHead->right = map.mHead;
    map.mSize = 0;
  }

  [[nodiscard]] SBuildResourceInfoLink** UnlinkBuildResourceInfoLinkNoReset(SBuildResourceInfoLink& link) noexcept
  {
    SBuildResourceInfoLink** cursor = link.mOwnerSlot;
    if (!cursor) {
      return nullptr;
    }

    while (*cursor != &link) {
      if (!*cursor) {
        return cursor;
      }
      cursor = &(*cursor)->mNext;
    }

    *cursor = link.mNext;
    return cursor;
  }

  void UnlinkBuildResourceInfoLink(SBuildResourceInfoLink& link)
  {
    (void)UnlinkBuildResourceInfoLinkNoReset(link);
    link.mOwnerSlot = nullptr;
    link.mNext = nullptr;
  }

  /**
   * Address: 0x0057CAF0 (FUN_0057CAF0, sub_57CAF0)
   *
   * What it does:
   * Unlinks both intrusive lanes in one `SBuildResourceInfo` in binary order
   * (resource lane first, placement lane second) without rewriting local
   * link fields.
   */
  [[maybe_unused]] [[nodiscard]] SBuildResourceInfoLink** UnlinkBuildResourceInfoLinksNoReset(
    SBuildResourceInfo& info
  ) noexcept
  {
    (void)UnlinkBuildResourceInfoLinkNoReset(info.mResourceLink);
    return UnlinkBuildResourceInfoLinkNoReset(info.mPlacementLink);
  }

  void RebindBuildResourceInfoLinkToOwnerSlot(
    SBuildResourceInfoLink& link,
    SBuildResourceInfoLink** const newOwnerSlot
  ) noexcept
  {
    if (link.mOwnerSlot == newOwnerSlot) {
      return;
    }

    if (SBuildResourceInfoLink** cursor = link.mOwnerSlot; cursor != nullptr) {
      while (*cursor != &link) {
        cursor = &(*cursor)->mNext;
      }
      *cursor = link.mNext;
    }

    link.mOwnerSlot = newOwnerSlot;
    if (newOwnerSlot != nullptr) {
      link.mNext = *newOwnerSlot;
      *newOwnerSlot = &link;
      return;
    }

    link.mNext = nullptr;
  }

  /**
   * Address: 0x0057CB30 (FUN_0057CB30)
   *
   * What it does:
   * Rebinds both intrusive-link lanes in one `SBuildResourceInfo` to the
   * owner-slot heads from another link-pair, preserving list-head insertion
   * and unlink ordering for each lane.
   */
  [[maybe_unused]] void RebindBuildResourceInfoLinks(
    SBuildResourceInfo& destination,
    const SBuildResourceInfo& source
  ) noexcept
  {
    RebindBuildResourceInfoLinkToOwnerSlot(destination.mPlacementLink, source.mPlacementLink.mOwnerSlot);
    RebindBuildResourceInfoLinkToOwnerSlot(destination.mResourceLink, source.mResourceLink.mOwnerSlot);
  }

  struct SBuildResourceInfoOwnerSlots
  {
    SBuildResourceInfoLink** mPlacementOwnerSlot; // +0x00
    SBuildResourceInfoLink** mResourceOwnerSlot;  // +0x04
  };
  static_assert(sizeof(SBuildResourceInfoOwnerSlots) == 0x08, "SBuildResourceInfoOwnerSlots size must be 0x08");

  struct SBuildStructurePositionValue
  {
    Wm3::Vector2i mGridPosition;      // +0x00
    SBuildResourceInfo mBuildInfo;    // +0x08
  };
  static_assert(sizeof(SBuildStructurePositionValue) == 0x18, "SBuildStructurePositionValue size must be 0x18");
  static_assert(
    offsetof(SBuildStructurePositionValue, mGridPosition) == 0x00,
    "SBuildStructurePositionValue::mGridPosition offset must be 0x00"
  );
  static_assert(
    offsetof(SBuildStructurePositionValue, mBuildInfo) == 0x08,
    "SBuildStructurePositionValue::mBuildInfo offset must be 0x08"
  );

  /**
   * Address: 0x0057FBF0 (FUN_0057FBF0)
   *
   * What it does:
   * Copies one `(gridPosition, buildInfo)` value lane and relinks both
   * intrusive build-resource links at the head of caller-supplied owner slots.
   */
  [[maybe_unused]] [[nodiscard]] SBuildStructurePositionValue* CopyBuildStructurePositionValueWithRelink(
    SBuildStructurePositionValue* const destination,
    const SBuildResourceInfoOwnerSlots& ownerSlots,
    const SBuildStructurePositionValue& source
  ) noexcept
  {
    destination->mGridPosition = source.mGridPosition;

    destination->mBuildInfo.mPlacementLink.mOwnerSlot = ownerSlots.mPlacementOwnerSlot;
    if (ownerSlots.mPlacementOwnerSlot != nullptr) {
      destination->mBuildInfo.mPlacementLink.mNext = *ownerSlots.mPlacementOwnerSlot;
      *ownerSlots.mPlacementOwnerSlot = &destination->mBuildInfo.mPlacementLink;
    } else {
      destination->mBuildInfo.mPlacementLink.mNext = nullptr;
    }

    destination->mBuildInfo.mResourceLink.mOwnerSlot = ownerSlots.mResourceOwnerSlot;
    if (ownerSlots.mResourceOwnerSlot != nullptr) {
      destination->mBuildInfo.mResourceLink.mNext = *ownerSlots.mResourceOwnerSlot;
      *ownerSlots.mResourceOwnerSlot = &destination->mBuildInfo.mResourceLink;
    } else {
      destination->mBuildInfo.mResourceLink.mNext = nullptr;
    }

    return destination;
  }

  void DestroyBuildStructureTree(SBuildStructurePositionNode* node)
  {
    while (node && node->mIsNil == 0u) {
      DestroyBuildStructureTree(node->right);
      SBuildStructurePositionNode* const left = node->left;

      // Matches sub_5812C0 unlink order (+0x1C link first, then +0x14 link).
      (void)UnlinkBuildResourceInfoLinksNoReset(node->mBuildInfo);
      ::operator delete(node);

      node = left;
    }
  }

  /**
   * Address: 0x00579F50 (FUN_00579F50)
   *
   * What it does:
   * Clears and releases one build-structure reservation map by deleting all
   * owned tree nodes, deleting the sentinel node, and zeroing map lanes.
   */
  void DestroyBuildStructureMap(SBuildStructurePositionMap& map)
  {
    if (!map.mHead) {
      return;
    }

    DestroyBuildStructureTree(map.mHead->parent);
    ::operator delete(map.mHead);
    map.mHead = nullptr;
    map.mSize = 0;
  }

  [[nodiscard]] CTaskStage* AllocateTaskStage()
  {
    auto* const stage = static_cast<CTaskStage*>(::operator new(sizeof(CTaskStage)));
    stage->mThreads.mPrev = &stage->mThreads;
    stage->mThreads.mNext = &stage->mThreads;
    stage->mStagedThreads.mPrev = &stage->mStagedThreads;
    stage->mStagedThreads.mNext = &stage->mStagedThreads;
    stage->mActive = true;
    stage->mAlignmentPad11[0] = 0;
    stage->mAlignmentPad11[1] = 0;
    stage->mAlignmentPad11[2] = 0;
    return stage;
  }

  void DestroyTaskStageAndDelete(CTaskStage*& stage)
  {
    if (!stage) {
      return;
    }

    stage->Teardown();
    stage->mStagedThreads.ListUnlink();
    stage->mThreads.ListUnlink();
    ::operator delete(stage);
    stage = nullptr;
  }

  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  using BuildReserveMapStorage = std::map<Wm3::Vector2i, moho::SBuildReserveInfo>;

  struct LegacyMapRuntimeView
  {
    void* allocProxy;
    void* head;
    std::uint32_t size;
  };

  [[nodiscard]] std::size_t CountLegacyMapElements(const void* const object) noexcept
  {
    if (object == nullptr) {
      return 0u;
    }

    const auto* const mapView = static_cast<const LegacyMapRuntimeView*>(object);
    return mapView->size;
  }

  [[nodiscard]] gpg::RType* ResolveBuildReserveKeyType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector2i));
      if (!type) {
        type = ResolveTypeByAnyName({"Wm3::IVector2<int>", "Wm3::Vector2i", "Vector2i"});
      }
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveBuildReserveValueType()
  {
    gpg::RType* type = moho::SBuildReserveInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SBuildReserveInfo));
      if (!type) {
        type = moho::preregister_SBuildReserveInfoTypeInfo();
      }
      moho::SBuildReserveInfo::sType = type;
    }
    return type;
  }

  class BuildReserveMapTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>";
    }

    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override
    {
      const msvc8::string base = gpg::RType::GetLexical(ref);
      return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(CountLegacyMapElements(ref.mObj)));
    }

    static void SerLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      auto* const mapObject = reinterpret_cast<BuildReserveMapStorage*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
      );
      if (!archive || !mapObject) {
        return;
      }

      unsigned int count = 0u;
      archive->ReadUInt(&count);
      mapObject->clear();

      gpg::RType* const keyType = ResolveBuildReserveKeyType();
      gpg::RType* const valueType = ResolveBuildReserveValueType();
      GPG_ASSERT(keyType != nullptr);
      GPG_ASSERT(valueType != nullptr);
      if (!keyType || !valueType) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (unsigned int i = 0u; i < count; ++i) {
        Wm3::Vector2i key{};
        moho::SBuildReserveInfo value{};
        archive->Read(keyType, &key, owner);
        archive->Read(valueType, &value, owner);
        (*mapObject)[key] = value;
      }
    }

    /**
     * Address: 0x0057F680 (FUN_0057F680, gpg::RMapType_IVector2i_SBuildReserveInfo::SerSave)
     *
     * What it does:
     * Serializes one `std::map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>` payload
     * by writing each key/value pair through reflected type lanes.
     */
    static void SerSave(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
    {
      const auto* const mapObject = reinterpret_cast<const BuildReserveMapStorage*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
      );
      if (!archive || !mapObject) {
        return;
      }

      archive->WriteUInt(static_cast<unsigned int>(mapObject->size()));

      gpg::RType* const keyType = ResolveBuildReserveKeyType();
      gpg::RType* const valueType = ResolveBuildReserveValueType();
      GPG_ASSERT(keyType != nullptr);
      GPG_ASSERT(valueType != nullptr);
      if (!keyType || !valueType) {
        return;
      }

      const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
      for (auto it = mapObject->begin(); it != mapObject->end(); ++it) {
        Wm3::Vector2i key = it->first;
        moho::SBuildReserveInfo value = it->second;
        archive->Write(keyType, &key, owner);
        archive->Write(valueType, &value, owner);
      }
    }

    void Init() override
    {
      size_ = 0x0C;
      version_ = 1;
      serLoadFunc_ = &BuildReserveMapTypeInfo::SerLoad;
      serSaveFunc_ = &BuildReserveMapTypeInfo::SerSave;
    }
  };

  alignas(BuildReserveMapTypeInfo) unsigned char gBuildReserveMapTypeInfoStorage[sizeof(BuildReserveMapTypeInfo)]{};
  bool gBuildReserveMapTypeInfoConstructed = false;

  [[nodiscard]] BuildReserveMapTypeInfo& AcquireBuildReserveMapTypeInfo()
  {
    if (!gBuildReserveMapTypeInfoConstructed) {
      new (gBuildReserveMapTypeInfoStorage) BuildReserveMapTypeInfo();
      gBuildReserveMapTypeInfoConstructed = true;
    }
    return *reinterpret_cast<BuildReserveMapTypeInfo*>(gBuildReserveMapTypeInfoStorage);
  }

  /**
   * Address: 0x00582610 (FUN_00582610, preregister_BuildReserveMapTypeInfo)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for
   * `std::map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>`.
   */
  [[nodiscard]] gpg::RType* preregister_BuildReserveMapTypeInfo()
  {
    BuildReserveMapTypeInfo& typeInfo = AcquireBuildReserveMapTypeInfo();
    gpg::PreRegisterRType(typeid(BuildReserveMapStorage), &typeInfo);
    return &typeInfo;
  }

  [[nodiscard]] gpg::RType* CachedScriptObjectType()
  {
    gpg::RType* type = CScriptObject::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CScriptObject));
      CScriptObject::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedAttackVectorType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = ResolveTypeByAnyName(
        {"std::vector<Moho::SPointVector>",
         "std::vector<Moho::SPointVector >",
         "vector<Moho::SPointVector>",
         "vector<SPointVector>"}
      );
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedBuildReserveMapType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(BuildReserveMapStorage));
      if (!type) {
        type = preregister_BuildReserveMapTypeInfo();
      }
      if (!type) {
        type = ResolveTypeByAnyName(
          {"std::map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>",
           "std::map<Wm3::IVector2<int>, Moho::SBuildReserveInfo>",
           "map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>"}
        );
      }
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedSimType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Sim));
      if (!type) {
        type = ResolveTypeByAnyName({"Moho::Sim", "Sim"});
      }
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedTaskStageType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(CTaskStage));
      if (!type) {
        type = ResolveTypeByAnyName({"Moho::CTaskStage", "CTaskStage"});
      }
    }
    return type;
  }

  /**
   * Address: 0x00579570 (FUN_00579570)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `CAiBrain`.
   */
  [[nodiscard]] gpg::RType* ResolveCAiBrainTypeCachePrimary()
  {
    gpg::RType* type = moho::CAiBrain::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAiBrain));
      moho::CAiBrain::sType = type;
    }
    return type;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakePointerRef(TObject* const object, gpg::RType* const type)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = (object != nullptr) ? type : nullptr;
    return out;
  }

  void ReplaceOwnedTaskStage(CTaskStage*& field, CTaskStage* const replacement)
  {
    CTaskStage* const previous = field;
    field = replacement;
    if (previous != nullptr) {
      previous->~CTaskStage();
      ::operator delete(previous);
    }
  }

  struct CAiBrainStartupBootstrap
  {
    CAiBrainStartupBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_CAiBrain_Index();
    }
  };

  [[maybe_unused]] CAiBrainStartupBootstrap gCAiBrainStartupBootstrap;

  /**
   * Address: 0x005919F0 (FUN_005919F0, sub_5919F0)
   *
   * IDA signature:
   * _DWORD *__stdcall sub_5919F0(int destSet, LuaPlus::LuaObject sourceTable);
   *
   * What it does:
   * Walks one Lua table top-to-bottom, resolves each entry through
   * `SCR_FromLua_Unit`, and appends every successfully-resolved unit's
   * `Entity*` lane into the destination unit-set fastvector. Used by the
   * Platoon Lua bindings to pull a Lua-side unit list into a typed unit set
   * before issuing army-side reassignment / squad-add operations.
   */
  void PopulateUnitSetFromLuaList(SEntitySetTemplateUnit& destSet, const LuaPlus::LuaObject& sourceTable)
  {
    const int rowCount = sourceTable.GetCount();
    for (int row = 1; row <= rowCount; ++row) {
      const LuaPlus::LuaObject rowObject = sourceTable[row];
      Unit* const unit = SCR_FromLua_Unit(rowObject);
      if (unit != nullptr) {
        destSet.mVec.PushBack(static_cast<Entity*>(unit));
      }
    }
  }

  /**
   * Address: 0x006934E0 (FUN_006934E0, func_FillLuaTableWithEntities)
   *
   * What it does:
   * Initializes `outTable` as a Lua array sized to `entities` and fills slots
   * `1..N` with each entity's script object lane in storage order.
   */
  LuaPlus::LuaObject* FillLuaTableWithEntities(
    const SEntitySetTemplateUnit& entities,
    LuaPlus::LuaObject* const outTable,
    LuaPlus::LuaState* const state
  )
  {
    outTable->AssignNewTable(state, static_cast<std::int32_t>(entities.mVec.Size()), 0);

    std::int32_t tableIndex = 1;
    for (Entity* const* entitySlot = entities.mVec.begin(); entitySlot != entities.mVec.end(); ++entitySlot) {
      outTable->Insert(tableIndex, (*entitySlot)->mLuaObj);
      ++tableIndex;
    }

    return outTable;
  }

  constexpr int kAiBrainAllianceAnySentinel = 3;
} // namespace

namespace moho
{
  /**
   * Address: 0x0057B290 (FUN_0057B290, func_GetUnitsAroundPoint)
   *
   * What it does:
   * Resets one output unit-set lane, gathers nearby unit entities around
   * `position` within `dist`, filters by liveness/destroy-queue/alliance/recon
   * visibility/category membership, and appends matching units.
   *
   * Called by CPlatoon::FindClosestUnitToPos (the COMPARE_LeastDefended lane)
   * to score how well-defended each candidate is.
   */
  SEntitySetTemplateUnit* CollectUnitsAroundPointFiltered(
    CAiBrain* const brain,
    SEntitySetTemplateUnit* const outUnits,
    const EntityCategorySet* const categorySet,
    const Wm3::Vector3f& position,
    const float dist,
    const EAlliance alliance
  )
  {
    outUnits->ListResetLinks();
    outUnits->mVec.ResetStorageToInline();

    CAiReconDBImpl* const reconDb = brain->mArmy->GetReconDB();

    const gpg::Rect2f queryRect{
      position.x - dist,
      position.z - dist,
      position.x + dist,
      position.z + dist
    };
    CollisionDBRect collisionRect{};
    (void)func_Rect2fToInt16(&collisionRect, queryRect);

    EntityGatherVector gatheredEntities{};
    (void)brain->mSim->mOGrid->mEntityOccupationManager.GatherUnmarkedEntities(
      gatheredEntities,
      collisionRect,
      ENTITYTYPE_Unit
    );

    for (Entity* const candidateEntity : gatheredEntities) {
      if (candidateEntity == nullptr || candidateEntity->Dead != 0u || candidateEntity->DestroyQueuedFlag != 0u) {
        continue;
      }

      if (static_cast<int>(alliance) != kAiBrainAllianceAnySentinel) {
        const IArmy* const candidateArmy =
          (candidateEntity->ArmyRef != nullptr) ? static_cast<const IArmy*>(candidateEntity->ArmyRef) : nullptr;
        if (brain->mArmy->GetAllianceWith(candidateArmy) != alliance) {
          continue;
        }
      }

      Unit* const candidateUnit = candidateEntity->IsUnit();
      if (candidateUnit == nullptr) {
        continue;
      }

      if (brain->mArmy != candidateEntity->ArmyRef && reconDb->ReconGetBlip(candidateUnit) == nullptr) {
        continue;
      }

      if (EntityCategory::HasBlueprint(candidateEntity->BluePrint, categorySet)) {
        (void)outUnits->AddUnit(candidateUnit);
      }
    }

    return outUnits;
  }

  /**
   * Address: 0x0057B480 (FUN_0057B480, func_GetNumUnitsAroundPoint)
   *
   * IDA signature:
   * int __stdcall sub_57B480(CAiBrain* this, EntityCategory* cat, Vector3f* pos,
   *                          float dist, EAlliance ally);
   *
   * What it does:
   * Counting twin of `CollectUnitsAroundPointFiltered`: gathers unit entities
   * within `dist` of `position` and returns how many pass the
   * liveness / destroy-queue / alliance / recon-visibility / category filters.
   * Backs the `CAiBrain:GetNumUnitsAroundPoint()` Lua binding.
   */
  int CountUnitsAroundPointFiltered(
    CAiBrain* const brain,
    const EntityCategorySet* const categorySet,
    const Wm3::Vector3f& position,
    const float dist,
    const EAlliance alliance)
  {
    int matchCount = 0;

    CAiReconDBImpl* const reconDb = brain->mArmy->GetReconDB();

    CollisionResultFastVectorN10 gatheredEntities{};
    EntitiesAroundPoint(gatheredEntities, dist, *brain->mSim->mOGrid, ENTITYTYPE_Unit, position);

    for (const CollisionResult& hit : gatheredEntities) {
      Entity* const candidateEntity = hit.sourceEntity;
      if (candidateEntity == nullptr || candidateEntity->Dead != 0u || candidateEntity->DestroyQueuedFlag != 0u) {
        continue;
      }

      if (static_cast<int>(alliance) != kAiBrainAllianceAnySentinel) {
        const IArmy* const candidateArmy =
          (candidateEntity->ArmyRef != nullptr) ? static_cast<const IArmy*>(candidateEntity->ArmyRef) : nullptr;
        if (brain->mArmy->GetAllianceWith(candidateArmy) != alliance) {
          continue;
        }
      }

      Unit* const candidateUnit = candidateEntity->IsUnit();
      if (candidateUnit == nullptr) {
        continue;
      }

      if (brain->mArmy != candidateEntity->ArmyRef && reconDb->ReconGetBlip(candidateUnit) == nullptr) {
        continue;
      }

      if (EntityCategory::HasBlueprint(candidateEntity->BluePrint, categorySet)) {
        ++matchCount;
      }
    }

    return matchCount;
  }

  namespace
  {
    /**
     * Footprint-size multiplier (`ds:dword_DFF31C == 10.0`) that scales a
     * candidate's footprint extent into the LeastDefended threat-scan radius.
     */
    constexpr float kLeastDefendedFootprintRadiusScale = 10.0f;

    /**
     * Nearby-unit scan radius (`ds:flt_E4F92C == 32.0`) used by the
     * HighestValue / count comparison lanes of `PickBestAttackVector`.
     */
    constexpr float kLeastDefendedScanRadius = 32.0f;

    /**
     * Initial "no candidate scored yet" sentinel (`ds:flt_E4F6E8 == -1.0`) for
     * the running best score in both candidate-ranking functions.
     */
    constexpr float kNoBestScoreSentinel = -1.0f;

    /**
     * Sum of a unit's build-cost mass and energy (blueprint `Economy`
     * `BuildCostMass + BuildCostEnergy`). Mirrors the binary's `[bp+0x4EC] +
     * [bp+0x4E8]` value read used to rank candidates by economic worth.
     */
    [[nodiscard]] float UnitBuildValue(const RUnitBlueprint* const blueprint) noexcept
    {
      if (blueprint == nullptr) {
        return 0.0f;
      }
      return blueprint->Economy.BuildCostMass + blueprint->Economy.BuildCostEnergy;
    }

    /**
     * Squared XYZ distance between two positions.
     */
    [[nodiscard]] float DistanceSquared(const Wm3::Vector3f& a, const Wm3::Vector3f& b) noexcept
    {
      const float dx = a.x - b.x;
      const float dy = a.y - b.y;
      const float dz = a.z - b.z;
      return (dx * dx) + (dy * dy) + (dz * dz);
    }
  } // namespace

  /**
   * Address: 0x0057B620 (FUN_0057B620, sub_57B620)
   *
   * IDA signature:
   * Value* __stdcall sub_57B620(CAiBrain* brain, ECompareType compareType,
   *     EAlliance alliance, EntityCategory* category, Wm3::Vector3f* refPos);
   *
   * What it does:
   * Gathers candidate entities and returns the single best-scored one relative
   * to `referencePosition`, ranked by `compareType`. When `alliance ==
   * ALLIANCE_Ally` the ally set is filled from `mArmy->GetUnits(category)`; that
   * ally set is the one actually scored. A recon-blip set is also built (each
   * live blip creator), matching the binary — the shipped code populates it but
   * never scores it, so it is preserved as a faithful, if inert, side effect.
   *
   * Each scored candidate must be allied per `IArmy::GetAllianceWith` and must
   * NOT be a member of `category` (the binary's category test is an exclusion
   * filter, the inverse of `HasBlueprint`). Scoring:
   *   COMPARE_Closest / COMPARE_Furthest : nearest / farthest to referencePosition.
   *   COMPARE_HighestValue               : highest build-cost value.
   *   COMPARE_LeastDefended              : lowest summed build value of armed
   *                                        units within footprint*10 of it.
   * Returns the best candidate `Entity*`, or nullptr when none qualify.
   */
  Entity* CollectAttackCandidateEntities(
    CAiBrain* const brain,
    const ECompareType compareType,
    const EAlliance alliance,
    const EntityCategorySet* const category,
    const Wm3::Vector3f& referencePosition)
  {
    // Recon-blip candidate set (populated for parity with the binary; the
    // shipped function never scores it — see the ally set below).
    SEntitySetTemplateUnit reconCandidates{};
    // Ally candidate set — this is the set actually iterated for scoring.
    SEntitySetTemplateUnit allyCandidates{};

    if (alliance == ALLIANCE_Ally) {
      SEntitySetTemplateUnit armyUnits{};
      brain->mArmy->GetUnits(&armyUnits, const_cast<EntityCategorySet*>(category));
      allyCandidates.mVec.AddAll(&armyUnits.mVec);
    }

    CAiReconDBImpl* const reconDb = brain->mArmy->GetReconDB();
    for (ReconBlip* const blip : reconDb->ReconGetBlips()) {
      Unit* const creator = blip ? blip->GetCreator() : nullptr;
      if (creator != nullptr && !creator->IsDead()) {
        (void)reconCandidates.AddUnit(creator);
      }
    }

    Entity* bestCandidate = nullptr;
    float bestScore = kNoBestScoreSentinel;

    for (Entity* const candidate : allyCandidates.mVec) {
      if (candidate == nullptr) {
        continue;
      }

      const IArmy* const candidateArmy =
        (candidate->ArmyRef != nullptr) ? static_cast<const IArmy*>(candidate->ArmyRef) : nullptr;
      if (brain->mArmy->GetAllianceWith(candidateArmy) != alliance) {
        continue;
      }

      Unit* const candidateUnit = candidate->IsUnit();
      const RUnitBlueprint* const candidateBlueprint =
        (candidateUnit != nullptr) ? candidateUnit->GetBlueprint() : nullptr;

      // Exclusion filter: the binary keeps candidates that are NOT in `category`
      // (or whose category bit falls outside the set's word range).
      if (EntityCategory::HasBlueprint(candidate->BluePrint, category)) {
        continue;
      }

      switch (compareType) {
        case COMPARE_Closest: {
          const float score = DistanceSquared(candidate->GetPositionWm3(), referencePosition);
          if (score < bestScore || bestScore < 0.0f) {
            bestCandidate = candidate;
            bestScore = score;
          }
          break;
        }
        case COMPARE_Furthest: {
          const float score = DistanceSquared(candidate->GetPositionWm3(), referencePosition);
          if (score > bestScore || bestScore < 0.0f) {
            bestCandidate = candidate;
            bestScore = score;
          }
          break;
        }
        case COMPARE_HighestValue: {
          const float score = UnitBuildValue(candidateBlueprint);
          if (score > bestScore || bestScore < 0.0f) {
            bestCandidate = candidate;
            bestScore = score;
          }
          break;
        }
        case COMPARE_LeastDefended: {
          float nearbyDefenseValue = 0.0f;

          const SFootprint& footprint = candidate->GetFootprint();
          const std::uint8_t footprintExtent = std::max(footprint.mSizeX, footprint.mSizeZ);
          const float scanRadius = static_cast<float>(footprintExtent) * kLeastDefendedFootprintRadiusScale;
          const Wm3::Vector3f& candidatePos = candidate->GetPositionWm3();

          // The binary re-derives the scoring brain from the candidate's own
          // army (`[candidate+0x154]` -> army vtable slot GetArmyBrain), so the
          // surrounding-defense scan is run from that army's perspective.
          CAiBrain* const candidateBrain =
            (candidate->ArmyRef != nullptr) ? candidate->ArmyRef->GetArmyBrain() : nullptr;

          SEntitySetTemplateUnit nearbyDefenders{};
          CollectUnitsAroundPointFiltered(
            candidateBrain, &nearbyDefenders, category, candidatePos, scanRadius, ALLIANCE_Ally
          );

          for (Entity* const defenderEntity : nearbyDefenders.mVec) {
            Unit* const defenderUnit = defenderEntity ? defenderEntity->IsUnit() : nullptr;
            const RUnitBlueprint* const defenderBlueprint =
              (defenderUnit != nullptr) ? defenderUnit->GetBlueprint() : nullptr;
            if (defenderBlueprint != nullptr && !defenderBlueprint->Weapons.WeaponBlueprints.empty()) {
              nearbyDefenseValue += UnitBuildValue(defenderBlueprint);
            }
          }

          if (bestScore > nearbyDefenseValue || bestScore < 0.0f) {
            bestCandidate = candidate;
            bestScore = nearbyDefenseValue;
          }
          break;
        }
        default:
          break;
      }
    }

    return bestCandidate;
  }

  /**
   * Address: 0x0057C290 (FUN_0057C290, Moho::CAiBrain::PickBestAttackVector)
   *
   * What it does:
   * See the header declaration. Scores this brain's debug attack vectors and
   * writes the winning vector's origin/direction into `outResult`.
   */
  SPointVector* CAiBrain::PickBestAttackVector(
    SPointVector* const outResult,
    CPlatoon* const platoon,
    const ESquadClass squadClass,
    const EAlliance alliance,
    const ECompareType compareType,
    const EntityCategorySet* const category,
    const char* const scoreScript,
    const char* const scoreFunc)
  {
    // Winning attack vector kept as an SPointVector (point=origin, vector=direction).
    const Wm3::Vector3f zeroVector = Wm3::Vector3f::Zero();
    SPointVector bestVector{zeroVector, zeroVector};
    float bestScore = kNoBestScoreSentinel;

    // Locate the squad of the requested class by linear scan over the platoon's
    // squad list (the binary inlines this rather than calling GetSquad).
    CSquad* matchingSquad = nullptr;
    for (CSquad* const squad : platoon->mSquadList) {
      if (squad != nullptr && squad->mSquadClass == squadClass) {
        matchingSquad = squad;
        break;
      }
    }

    // Early-out guards -> zero result: no current enemy, no matching squad, or
    // an empty squad unit set.
    if (mCurrentEnemy == nullptr || matchingSquad == nullptr ||
        matchingSquad->mUnits.mVec.begin() == matchingSquad->mUnits.mVec.end()) {
      outResult->point = bestVector.point;
      outResult->vector = bestVector.vector;
      return outResult;
    }

    // Optional user-supplied Lua scorer.
    LuaPlus::LuaObject scorerFunctionObject;
    if (scoreFunc != nullptr) {
      LuaPlus::LuaState* const luaState = mSim->GetLuaState();
      LuaPlus::LuaObject scoreModule = SCR_Import(luaState, scoreScript);
      scorerFunctionObject = scoreModule[scoreFunc];
    }

    Wm3::Vector3f squadCenter{};
    (void)matchingSquad->GetCenter(&squadCenter);

    // Iterate this brain's attack vectors (origin + direction).
    for (const SAiAttackVectorDebug& attackVector : mAttackVectors) {
      const Wm3::Vector3f candidatePoint{
        attackVector.mOrigin.x + attackVector.mDirection.x,
        attackVector.mOrigin.y + attackVector.mDirection.y,
        attackVector.mOrigin.z + attackVector.mDirection.z
      };

      if (!matchingSquad->FitsAt(candidatePoint)) {
        continue;
      }

      // When a scorer is supplied, gate on scorer(centerX, centerZ, candidateX, candidateZ).
      if (scoreFunc != nullptr) {
        LuaPlus::LuaFunction scorer(scorerFunctionObject);
        const bool approved = scorer.Call_Num4_bool(
          squadCenter.x, squadCenter.z, candidatePoint.x, candidatePoint.z
        );
        if (!approved) {
          continue;
        }
      }

      switch (compareType) {
        case COMPARE_Closest: {
          float score;
          if (category->Empty()) {
            score = DistanceSquared(squadCenter, candidatePoint);
          } else {
            Entity* const bestEntity =
              CollectAttackCandidateEntities(this, COMPARE_Closest, alliance, category, squadCenter);
            score = (bestEntity != nullptr)
                      ? DistanceSquared(candidatePoint, bestEntity->GetPositionWm3())
                      : std::numeric_limits<float>::infinity();
          }
          if (bestScore > score || bestScore < 0.0f) {
            (void)CopySPointVectorAndReturnDestination(
              &bestVector, reinterpret_cast<const SPointVector*>(&attackVector)
            );
            bestScore = score;
          }
          break;
        }
        case COMPARE_Furthest: {
          float score;
          if (category->Empty()) {
            score = DistanceSquared(squadCenter, candidatePoint);
          } else {
            Entity* const bestEntity =
              CollectAttackCandidateEntities(this, COMPARE_Furthest, alliance, category, squadCenter);
            score = (bestEntity != nullptr)
                      ? DistanceSquared(candidatePoint, bestEntity->GetPositionWm3())
                      : std::numeric_limits<float>::infinity();
          }
          if (score > bestScore || bestScore < 0.0f) {
            (void)CopySPointVectorAndReturnDestination(
              &bestVector, reinterpret_cast<const SPointVector*>(&attackVector)
            );
            bestScore = score;
          }
          break;
        }
        case COMPARE_HighestValue: {
          SEntitySetTemplateUnit nearbyUnits{};
          CollectUnitsAroundPointFiltered(this, &nearbyUnits, category, squadCenter, 0.0f, alliance);

          float score = 0.0f;
          for (Entity* const nearbyEntity : nearbyUnits.mVec) {
            Unit* const nearbyUnit = nearbyEntity ? nearbyEntity->IsUnit() : nullptr;
            score += UnitBuildValue(nearbyUnit != nullptr ? nearbyUnit->GetBlueprint() : nullptr);
          }

          bool keep = false;
          if (score > bestScore) {
            keep = true;
          } else if (bestScore < 0.0f) {
            keep = true;
          } else if (score == bestScore) {
            // Tie-break (asm 0x57C776): on equal value, prefer the vector whose
            // candidate point is closer to the squad center than the kept
            // vector's origin is.
            const float keptOriginDist = DistanceSquared(bestVector.point, squadCenter);
            const float candidateDist = DistanceSquared(candidatePoint, squadCenter);
            keep = keptOriginDist > candidateDist;
          }
          if (keep) {
            (void)CopySPointVectorAndReturnDestination(
              &bestVector, reinterpret_cast<const SPointVector*>(&attackVector)
            );
            bestScore = score;
          }
          break;
        }
        case COMPARE_LeastDefended: {
          SEntitySetTemplateUnit nearbyUnits{};
          CollectUnitsAroundPointFiltered(this, &nearbyUnits, category, squadCenter, kLeastDefendedScanRadius, alliance);

          const float score =
            static_cast<float>((nearbyUnits.mVec.end() - nearbyUnits.mVec.begin()));

          if (score > bestScore || bestScore < 0.0f) {
            (void)CopySPointVectorAndReturnDestination(
              &bestVector, reinterpret_cast<const SPointVector*>(&attackVector)
            );
            bestScore = score;
          }
          break;
        }
        default:
          break;
      }
    }

    // When value/count scoring found nothing near any vector, retry once in
    // COMPARE_Closest with the same squad/alliance/category/scorer.
    if ((compareType == COMPARE_HighestValue || compareType == COMPARE_LeastDefended) && bestScore == 0.0f) {
      SPointVector retryResult{zeroVector, zeroVector};
      (void)PickBestAttackVector(
        &retryResult, platoon, squadClass, alliance, COMPARE_Closest, category, scoreScript, scoreFunc
      );
      outResult->point = retryResult.point;
      outResult->vector = retryResult.vector;
      return outResult;
    }

    outResult->point = bestVector.point;
    outResult->vector = bestVector.vector;
    return outResult;
  }
} // namespace moho

gpg::RType* CAiBrain::sType = nullptr;

/**
 * Address: 0x0057EC10 (FUN_0057EC10, Moho::InstanceCounter<Moho::CAiBrain>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for CAiBrain instance
 * counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CAiBrain>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CAiBrain).name());
  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x00579E40 (FUN_00579E40, default ctor)
 */
CAiBrain::CAiBrain()
  : mArmy(nullptr)
  , mCurrentEnemy(nullptr)
  , mPersonality(nullptr)
  , mCurrentPlan()
  , mAttackVectors()
  , mBuildCategoryRange()
  , mBuildStructureMap{}
  , mSim(nullptr)
  , mAiThreadStage(nullptr)
  , mAttackerThreadStage(nullptr)
  , mReservedThreadStage(nullptr)
  , mTailWord(0)
{
  // Increment the CAiBrain instance-count stat (binary FUN_00579E40). The
  // (CArmyImpl*) ctor delegates here via `: CAiBrain()`, so it inherits the +1 --
  // one increment per construction, matching the binary.
  ::InterlockedExchangeAdd(
    reinterpret_cast<volatile long*>(&InstanceCounter<CAiBrain>::GetStatItem()->mPrimaryValueBits), 1L);

  mCurrentPlan.assign("", 0);
  InitializeBuildStructureMap(mBuildStructureMap);
}

/**
 * Address: 0x00579F80 (FUN_00579F80, army ctor)
 */
CAiBrain::CAiBrain(CArmyImpl* const army)
  : CAiBrain()
{
  mArmy = army;
  mCurrentEnemy = nullptr;
  mSim = army ? army->GetSim() : nullptr;

  if (mSim && mSim->mLuaState) {
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject factory = LoadAiBrainFactoryObject(mSim->mLuaState);
    CreateLuaObject(factory, arg1, arg2, arg3);
  }

  mPersonality = new (std::nothrow) CAiPersonality(mSim);

  mAiThreadStage = AllocateTaskStage();
  mAttackerThreadStage = AllocateTaskStage();
  mReservedThreadStage = AllocateTaskStage();

  if (mPersonality) {
    mPersonality->ReadData();
  }
}

/**
 * Address: 0x0057A440 (FUN_0057A440, Moho::CAiBrain::Initialize)
 *
 * What it does:
 * Resolves this brain's army-plan text (or `"None"` fallback), then calls
 * `OnCreateHuman` for human armies and `OnCreateAI` for non-human armies.
 */
void CAiBrain::Initialize()
{
  LuaPlus::LuaObject armyPlanArg;
  const char* const armyPlan = (mArmy != nullptr) ? mArmy->GetArmyPlans() : nullptr;
  if (armyPlan != nullptr) {
    armyPlanArg.AssignString(mSim->mLuaState, armyPlan);
  } else {
    armyPlanArg.AssignString(mSim->mLuaState, "None");
  }

  if (mArmy != nullptr && mArmy->IsHuman()) {
    LuaCall("OnCreateHuman", &armyPlanArg);
  } else {
    LuaCall("OnCreateAI", &armyPlanArg);
  }
}

/**
 * Address: 0x00579590 (FUN_00579590, ?GetClass@CAiBrain@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CAiBrain::GetClass() const
{
  return ResolveCAiBrainTypeCachePrimary();
}

/**
 * Address: 0x005795B0 (FUN_005795B0, ?GetDerivedObjectRef@CAiBrain@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CAiBrain::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

/**
 * Address: 0x00583CB0 (FUN_00583CB0, Moho::CAiBrain::MemberDeserialize)
 *
 * What it does:
 * Loads CAiBrain runtime lanes from archive storage, replacing owned
 * personality/task-stage pointers with freshly deserialized instances.
 */
void CAiBrain::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  gpg::RType* const scriptObjectType = CachedScriptObjectType();
  GPG_ASSERT(scriptObjectType != nullptr);
  if (scriptObjectType != nullptr) {
    archive->Read(scriptObjectType, static_cast<CScriptObject*>(this), owner);
  }

  (void)archive->ReadPointer_SimArmy(reinterpret_cast<moho::SimArmy**>(&mArmy), &owner);
  (void)archive->ReadPointer_SimArmy(reinterpret_cast<moho::SimArmy**>(&mCurrentEnemy), &owner);

  CAiPersonality* loadedPersonality = nullptr;
  (void)archive->ReadPointerOwned_CAiPersonality(&loadedPersonality, &owner);
  CAiPersonality* const previousPersonality = mPersonality;
  mPersonality = loadedPersonality;
  delete previousPersonality;

  archive->ReadString(&mCurrentPlan);

  gpg::RType* const attackVectorType = CachedAttackVectorType();
  GPG_ASSERT(attackVectorType != nullptr);
  if (attackVectorType != nullptr) {
    archive->Read(attackVectorType, &mAttackVectors, owner);
  }

  gpg::RType* const buildReserveMapType = CachedBuildReserveMapType();
  GPG_ASSERT(buildReserveMapType != nullptr);
  if (buildReserveMapType != nullptr) {
    archive->Read(buildReserveMapType, &mBuildStructureMap, owner);
  }

  (void)archive->ReadPointer_Sim(&mSim, &owner);

  CTaskStage* loadedAiThreadStage = nullptr;
  (void)archive->ReadPointerOwned_CTaskStage(&loadedAiThreadStage, &owner);
  ReplaceOwnedTaskStage(mAiThreadStage, loadedAiThreadStage);

  CTaskStage* loadedAttackerThreadStage = nullptr;
  (void)archive->ReadPointerOwned_CTaskStage(&loadedAttackerThreadStage, &owner);
  ReplaceOwnedTaskStage(mAttackerThreadStage, loadedAttackerThreadStage);

  CTaskStage* loadedReservedThreadStage = nullptr;
  (void)archive->ReadPointerOwned_CTaskStage(&loadedReservedThreadStage, &owner);
  ReplaceOwnedTaskStage(mReservedThreadStage, loadedReservedThreadStage);

  gpg::RType* const categorySetType = CachedEntityCategorySetType();
  GPG_ASSERT(categorySetType != nullptr);
  if (categorySetType != nullptr) {
    archive->Read(categorySetType, &mBuildCategoryRange, owner);
  }
}

/**
 * Address: 0x00583ED0 (FUN_00583ED0, Moho::CAiBrain::MemberSerialize)
 *
 * What it does:
 * Saves CAiBrain runtime lanes to archive storage, preserving original
 * tracked-pointer ownership states for each pointer field.
 */
void CAiBrain::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef owner{};
  gpg::RType* const scriptObjectType = CachedScriptObjectType();
  GPG_ASSERT(scriptObjectType != nullptr);
  if (scriptObjectType != nullptr) {
    archive->Write(scriptObjectType, static_cast<const CScriptObject*>(this), owner);
  }

  gpg::RRef armyRef{};
  (void)gpg::RRef_SimArmy(&armyRef, mArmy);
  gpg::WriteRawPointer(archive, armyRef, gpg::TrackedPointerState::Unowned, owner);

  gpg::RRef currentEnemyRef{};
  (void)gpg::RRef_SimArmy(&currentEnemyRef, mCurrentEnemy);
  gpg::WriteRawPointer(archive, currentEnemyRef, gpg::TrackedPointerState::Unowned, owner);

  gpg::RRef personalityRef{};
  (void)gpg::RRef_CAiPersonality(&personalityRef, mPersonality);
  gpg::WriteRawPointer(archive, personalityRef, gpg::TrackedPointerState::Owned, owner);

  archive->WriteString(const_cast<msvc8::string*>(&mCurrentPlan));

  gpg::RType* const attackVectorType = CachedAttackVectorType();
  GPG_ASSERT(attackVectorType != nullptr);
  if (attackVectorType != nullptr) {
    archive->Write(attackVectorType, &mAttackVectors, owner);
  }

  gpg::RType* const buildReserveMapType = CachedBuildReserveMapType();
  GPG_ASSERT(buildReserveMapType != nullptr);
  if (buildReserveMapType != nullptr) {
    archive->Write(buildReserveMapType, &mBuildStructureMap, owner);
  }

  gpg::RType* const simType = CachedSimType();
  GPG_ASSERT(simType != nullptr || mSim == nullptr);
  gpg::RRef simRef = MakePointerRef(mSim, simType);
  gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, owner);

  gpg::RType* const taskStageType = CachedTaskStageType();
  GPG_ASSERT(
    taskStageType != nullptr
    || (mAiThreadStage == nullptr && mAttackerThreadStage == nullptr && mReservedThreadStage == nullptr)
  );

  gpg::RRef aiThreadStageRef = MakePointerRef(mAiThreadStage, taskStageType);
  gpg::WriteRawPointer(archive, aiThreadStageRef, gpg::TrackedPointerState::Owned, owner);

  gpg::RRef attackerThreadStageRef = MakePointerRef(mAttackerThreadStage, taskStageType);
  gpg::WriteRawPointer(archive, attackerThreadStageRef, gpg::TrackedPointerState::Owned, owner);

  gpg::RRef reservedThreadStageRef = MakePointerRef(mReservedThreadStage, taskStageType);
  gpg::WriteRawPointer(archive, reservedThreadStageRef, gpg::TrackedPointerState::Owned, owner);

  gpg::RType* const categorySetType = CachedEntityCategorySetType();
  GPG_ASSERT(categorySetType != nullptr);
  if (categorySetType != nullptr) {
    archive->Write(categorySetType, &mBuildCategoryRange, owner);
  }
}

/**
 * Address: 0x00BCB4B0 (FUN_00BCB4B0, sub_BCB4B0)
 *
 * What it does:
 * Allocates the next Lua metatable-factory object index for the CAiBrain startup lane.
 */
int moho::register_CScrLuaMetatableFactory_CAiBrain_Index()
{
  const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
  gRecoveredCScrLuaMetatableFactoryCAiBrainIndex = index;
  return index;
}

/**
 * Address: 0x00579F30 (FUN_00579F30, scalar deleting thunk)
 * Address: 0x0057A1E0 (FUN_0057A1E0, core destructor)
 */
CAiBrain::~CAiBrain()
{
  DestroyTaskStageAndDelete(mReservedThreadStage);
  DestroyTaskStageAndDelete(mAttackerThreadStage);
  DestroyTaskStageAndDelete(mAiThreadStage);

  DestroyBuildStructureMap(mBuildStructureMap);

  // mCurrentPlan has no automatic heap cleanup in this legacy wrapper.
  mCurrentPlan.tidy(true, 0U);

  delete mPersonality;
  mPersonality = nullptr;

  // Decrement the CAiBrain instance-count stat (binary FUN_0057A1E0), balancing
  // the constructor's increment.
  ::InterlockedExchangeAdd(
    reinterpret_cast<volatile long*>(&InstanceCounter<CAiBrain>::GetStatItem()->mPrimaryValueBits), -1L);
}

/**
 * Address: 0x0057A6D0 (FUN_0057A6D0, Moho::CAiBrain::CanBuildUnit)
 *
 * What it does:
 * Resolves a unit blueprint id through active sim rules and tests whether
 * `builder` can construct that blueprint under current build restrictions.
 */
bool CAiBrain::CanBuildUnit(const char* const blueprintId, CAiBrain* const brain, Unit* const builder)
{
  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintId);

  const RUnitBlueprint* const blueprint = brain->mSim->mRules->GetUnitBlueprint(lookupId);
  return blueprint != nullptr && builder->CanBuild(blueprint);
}

/**
 * Address: 0x0057B1E0 (FUN_0057B1E0, Moho::CAiBrain::BuildUnit)
 *
 * What it does:
 * Resolves one blueprint id through `brain->mSim->mRules` and, when it maps to
 * a real blueprint, delegates to `IssueBuildFactoryCommands` (0x0057B0C0) which
 * validates the builder lane and emits `UNITCOMMAND_BuildFactory` `count` times.
 */
bool CAiBrain::BuildUnit(const char* const blueprintId, CAiBrain* const brain, Unit* const builder, const int count)
{
  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintId);

  RUnitBlueprint* const blueprint = brain->mSim->mRules->GetUnitBlueprint(lookupId);
  if (blueprint == nullptr) {
    return false;
  }

  return IssueBuildFactoryCommands(builder, count, blueprint, brain);
}

/**
 * Address: 0x0057BDB0 (FUN_0057BDB0, Moho::CAiBrain::ProcessAttackVectors)
 *
 * What it does:
 * Rebuilds attack-vector debug lanes from current enemy army unit positions.
 */
void CAiBrain::ProcessAttackVectors()
{
  mAttackVectors.clear();

  if (mCurrentEnemy == nullptr || mArmy == nullptr) {
    return;
  }

  SEntitySetTemplateUnit enemyUnits{};
  mCurrentEnemy->GetUnits(&enemyUnits, &mBuildCategoryRange);

  float sumX = 0.0f;
  float sumY = 0.0f;
  float sumZ = 0.0f;
  std::uint32_t enemyUnitCount = 0u;

  for (Entity* const* unitIt = enemyUnits.mVec.begin(); unitIt != enemyUnits.mVec.end(); ++unitIt) {
    Unit* const enemyUnit = SEntitySetTemplateUnit::UnitFromEntry(*unitIt);
    if (enemyUnit == nullptr || enemyUnit->IsDead() || enemyUnit->DestroyQueued()) {
      continue;
    }

    const Wm3::Vec3f& enemyPosition = enemyUnit->GetPosition();
    sumX += enemyPosition.x;
    sumY += enemyPosition.y;
    sumZ += enemyPosition.z;
    ++enemyUnitCount;
  }

  if (enemyUnitCount == 0u) {
    return;
  }

  const float inverseEnemyCount = 1.0f / static_cast<float>(enemyUnitCount);

  SAiAttackVectorDebug debugVector{};
  debugVector.mOrigin.x = sumX * inverseEnemyCount;
  debugVector.mOrigin.y = sumY * inverseEnemyCount;
  debugVector.mOrigin.z = sumZ * inverseEnemyCount;

  Wm3::Vector2f armyStartPosition{};
  mArmy->GetArmyStartPos(armyStartPosition);

  float directionX = debugVector.mOrigin.x - armyStartPosition.x;
  float directionZ = debugVector.mOrigin.z - armyStartPosition.y;
  const float directionLength = std::sqrt((directionX * directionX) + (directionZ * directionZ));
  if (directionLength > 0.0001f) {
    const float inverseDirectionLength = 1.0f / directionLength;
    directionX *= inverseDirectionLength;
    directionZ *= inverseDirectionLength;
  } else {
    directionX = 0.0f;
    directionZ = 1.0f;
  }

  constexpr float kAttackVectorDebugLength = 32.0f;
  debugVector.mDirection.x = directionX * kAttackVectorDebugLength;
  debugVector.mDirection.y = 0.0f;
  debugVector.mDirection.z = directionZ * kAttackVectorDebugLength;

  mAttackVectors.push_back(debugVector);
}

/**
 * Address: 0x0057BAA0 (FUN_0057BAA0, Moho::CAiBrain::DrawDebug)
 *
 * What it does:
 * Draws terrain debug grid lines and attack-vector markers to the active
 * simulation debug canvas.
 */
CAiBrain* CAiBrain::DrawDebug(CAiBrain* const brain)
{
  CDebugCanvas* const debugCanvas = brain->mSim->GetDebugCanvas();
  CHeightField* const heightField = brain->mSim->mMapData->mHeightField.get();

  const std::int32_t maxX = heightField->width - 1;
  const std::int32_t maxZ = heightField->height - 1;

  std::int32_t zLineCount = maxX / kAiDebugGridStep;
  std::int32_t xLineCount = maxZ / kAiDebugGridStep;

  if (zLineCount > 0) {
    const float maxXf = static_cast<float>(maxX);
    std::int32_t z = 0;
    do {
      SDebugLine line{};
      line.p0.x = 0.0f;
      line.p0.y = 0.0f;
      line.p0.z = static_cast<float>(z);
      line.p1.x = maxXf;
      line.p1.y = 0.0f;
      line.p1.z = static_cast<float>(z);
      line.depth0 = kAiDebugGridLineDepth;
      line.depth1 = kAiDebugGridLineDepth;
      debugCanvas->DebugDrawLine(line);

      z += kAiDebugGridStep;
      --zLineCount;
    } while (zLineCount != 0);

    xLineCount = maxZ / kAiDebugGridStep;
  }

  if (xLineCount > 0) {
    const float maxZf = static_cast<float>(maxZ);
    std::int32_t x = 0;
    do {
      SDebugLine line{};
      line.p0.x = static_cast<float>(x);
      line.p0.y = 0.0f;
      line.p0.z = 0.0f;
      line.p1.x = static_cast<float>(x);
      line.p1.y = 0.0f;
      line.p1.z = maxZf;
      line.depth0 = kAiDebugGridLineDepth;
      line.depth1 = kAiDebugGridLineDepth;
      debugCanvas->DebugDrawLine(line);

      x += kAiDebugGridStep;
      --xLineCount;
    } while (xLineCount != 0);
  }

  const Wm3::Vector3f upAxis{0.0f, 1.0f, 0.0f};
  for (const SAiAttackVectorDebug& attackVector : brain->mAttackVectors) {
    debugCanvas->AddWireCircle(
      upAxis,
      attackVector.mOrigin,
      kAiDebugAttackRingRadius,
      kAiDebugAttackRingDepth,
      kAiDebugAttackRingPrecision
    );

    SDebugLine line{};
    line.p0 = attackVector.mOrigin;
    line.p1.x = attackVector.mOrigin.x + attackVector.mDirection.x;
    line.p1.y = attackVector.mOrigin.y + attackVector.mDirection.y;
    line.p1.z = attackVector.mOrigin.z + attackVector.mDirection.z;
    line.depth0 = kAiDebugAttackLineDepth;
    line.depth1 = kAiDebugAttackLineDepth;
    debugCanvas->DebugDrawLine(line);
  }

  return brain;
}

/**
 * Address: 0x0057AEC0 (FUN_0057AEC0, Moho::CAiBrain::GetAvailableFactories)
 *
 * What it does:
 * Builds one `(FACTORY - MOBILE)` category set, then appends live non-busy
 * factory builders into `outSet`, with optional XZ distance filtering.
 */
SEntitySetTemplateUnit* CAiBrain::GetAvailableFactories(
  SEntitySetTemplateUnit* const outSet,
  const Wm3::Vector3f* const referencePosition,
  const float maxDistance
)
{
  const CategoryWordRangeView* const mobileCategory = mSim->mRules->GetEntityCategory("MOBILE");
  const CategoryWordRangeView* const factoryCategory = mSim->mRules->GetEntityCategory("FACTORY");

  CategoryWordRangeView candidateCategory{};
  if (factoryCategory != nullptr) {
    candidateCategory = *factoryCategory;
    if (mobileCategory != nullptr) {
      SubtractCategoryWordRange(candidateCategory, *mobileCategory);
    }
  } else if (mobileCategory != nullptr) {
    candidateCategory.ResetToEmpty(mobileCategory->mUniverse);
  }

  SEntitySetTemplateUnit foundUnits{};
  mArmy->GetUnits(&foundUnits, &candidateCategory);

  for (Entity* const* unitIt = foundUnits.mVec.begin(); unitIt != foundUnits.mVec.end(); ++unitIt) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*unitIt);
    if (unit == nullptr || unit->IsDead() || unit->DestroyQueued()) {
      continue;
    }

    IAiBuilder* const builder = unit->AiBuilder;
    if (builder == nullptr || !builder->BuilderIsFactory()) {
      continue;
    }

    if (unit->IsBeingBuilt() || unit->IsBusy()) {
      continue;
    }

    if (maxDistance > 0.0f) {
      const Wm3::Vec3f& unitPosition = unit->GetPosition();
      const float deltaX = referencePosition->x - unitPosition.x;
      const float deltaZ = referencePosition->z - unitPosition.z;
      const float planarDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
      if (planarDistance > maxDistance) {
        continue;
      }
    }

    (void)outSet->AddUnit(unit);
  }

  return outSet;
}

/**
 * Address: 0x0057AC30 (FUN_0057AC30, Moho::FindAvailableFactory)
 *
 * IDA signature:
 * Moho::Unit *__fastcall Moho::FindAvailableFactory(
 *   gpg::fastvector_Unit *candidateList,
 *   const char *blueprintId,
 *   Moho::CAiBrain *brain);
 *
 * What it does:
 * Returns the first builder unit (from a caller-supplied candidate list or,
 * if that list is empty, every non-mobile `FACTORY` owned by the brain's
 * army) that is live, idle, fully built, and capable of building the unit
 * blueprint identified by `blueprintId`. Returns null when the blueprint
 * cannot be resolved or no matching builder exists.
 *
 * The candidate-list parameter arrives as a `gpg::fastvector<Unit*>`; the
 * 2007 source first eagerly copied it to a local `std::vector<Unit*>` via
 * `moho::CopyFastvectorUnitToStdVector` (FUN_0057E550) so the iteration
 * loop could iterate the standard container.
 */
moho::Unit* moho::FindAvailableFactory(
  gpg::core::FastVector<Unit*>& candidateList, const char* const blueprintId, CAiBrain* const brain
)
{
  // Eagerly snapshot the fastvector candidates into a std::vector<Unit*>
  // following the 2007 layout. The per-T named copy helper preserves the
  // engine-emitted FUN_0057E550 symbol shape.
  std::vector<Unit*> stdCandidates;
  moho::CopyFastvectorUnitToStdVector(candidateList, stdCandidates);

  // Resolve target blueprint once (by normalized filename).
  RResId blueprintResId{};
  (void)gpg::STR_InitFilename(&blueprintResId.name, blueprintId);

  RRuleGameRules* const rules = brain->mSim->mRules;
  const RUnitBlueprint* const targetBlueprint = rules->GetUnitBlueprint(blueprintResId);
  if (targetBlueprint == nullptr) {
    if (blueprintId != nullptr) {
      gpg::Warnf("Passed in a bad unit blueprint name (%s) to FindAvailableFactory!", blueprintId);
    }
    return nullptr;
  }

  // If caller didn't pre-populate `candidateList`, harvest all static
  // factories owned by this brain's army into the local std::vector copy.
  if (stdCandidates.empty()) {
    const CategoryWordRangeView* const mobileCategory = rules->GetEntityCategory("MOBILE");
    const CategoryWordRangeView* const factoryCategory = rules->GetEntityCategory("FACTORY");

    CategoryWordRangeView staticFactoryCategory{};
    if (factoryCategory != nullptr) {
      staticFactoryCategory = *factoryCategory;
      if (mobileCategory != nullptr) {
        SubtractCategoryWordRange(staticFactoryCategory, *mobileCategory);
      }
    }

    SEntitySetTemplateUnit foundFactories{};
    brain->mArmy->GetUnits(&foundFactories, &staticFactoryCategory);

    for (Entity* const* slot = foundFactories.mVec.begin(); slot != foundFactories.mVec.end(); ++slot) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*slot);
      if (unit != nullptr) {
        stdCandidates.push_back(unit);
      }
    }
  }

  // Linear walk for the first builder that passes every buildability gate.
  for (Unit* const candidate : stdCandidates) {
    if (candidate == nullptr) {
      continue;
    }
    if (candidate->IsDead() || candidate->DestroyQueued() || candidate->IsBeingBuilt()) {
      continue;
    }
    if (candidate->IsBusy()) {
      continue;
    }
    if (!candidate->CanBuild(targetBlueprint)) {
      continue;
    }
    return candidate;
  }
  return nullptr;
}

/**
 * Address: 0x00585EF0 (FUN_00585EF0, cfunc_CAiBrainIsOpponentAIRunning)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainIsOpponentAIRunningL`.
 */
int moho::cfunc_CAiBrainIsOpponentAIRunning(lua_State* const luaContext)
{
  return cfunc_CAiBrainIsOpponentAIRunningL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00585F10 (FUN_00585F10, func_CAiBrainIsOpponentAIRunning_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:IsOpponentAIRunning()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainIsOpponentAIRunning_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainIsOpponentAIRunningName,
    &moho::cfunc_CAiBrainIsOpponentAIRunning,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainIsOpponentAIRunningHelpText
  );
  return &binder;
}

/**
 * Address: 0x00585F70 (FUN_00585F70, cfunc_CAiBrainIsOpponentAIRunningL)
 *
 * What it does:
 * Returns whether opponent AI should run for one brain, honoring `/noai`
 * override and `AI_RunOpponentAI` sim-convar state.
 */
int moho::cfunc_CAiBrainIsOpponentAIRunningL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainIsOpponentAIRunningHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);
  Sim* const sim = brain->mArmy->GetSim();

  bool shouldRunOpponentAi = false;
  if (!CFG_GetArgOption("/noai", 0u, nullptr)) {
    CSimConVarBase* const runOpponentAiConVar = GetAI_RunOpponentAI_SimConVarDef();
    CSimConVarInstanceBase* const runOpponentAiVar = (sim && runOpponentAiConVar) ? sim->GetSimVar(runOpponentAiConVar) : nullptr;
    const void* const runOpponentAiStorage = runOpponentAiVar ? runOpponentAiVar->GetValueStorage() : nullptr;
    shouldRunOpponentAi = runOpponentAiStorage && (*reinterpret_cast<const std::uint8_t*>(runOpponentAiStorage) != 0u);
  }

  lua_pushboolean(rawState, shouldRunOpponentAi ? 1 : 0);
  lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00586070 (FUN_00586070, cfunc_CAiBrainGetArmyIndex)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetArmyIndexL`.
 */
int moho::cfunc_CAiBrainGetArmyIndex(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetArmyIndexL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00586090 (FUN_00586090, func_CAiBrainGetArmyIndex_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetArmyIndex()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetArmyIndex_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetArmyIndexName,
    &moho::cfunc_CAiBrainGetArmyIndex,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetArmyIndexHelpText
  );
  return &binder;
}

/**
 * Address: 0x005860F0 (FUN_005860F0, cfunc_CAiBrainGetArmyIndexL)
 *
 * What it does:
 * Returns one-based army index for the brain's owning army.
 */
int moho::cfunc_CAiBrainGetArmyIndexL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetArmyIndexHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  lua_pushnumber(rawState, static_cast<float>(brain->mArmy->ArmyId + 1));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005861C0 (FUN_005861C0, cfunc_CAiBrainGetFactionIndex)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetFactionIndexL`.
 */
int moho::cfunc_CAiBrainGetFactionIndex(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetFactionIndexL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005861E0 (FUN_005861E0, func_CAiBrainGetFactionIndex_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetFactionIndex()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetFactionIndex_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetFactionIndexName,
    &moho::cfunc_CAiBrainGetFactionIndex,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetFactionIndexHelpText
  );
  return &binder;
}

/**
 * Address: 0x00586240 (FUN_00586240, cfunc_CAiBrainGetFactionIndexL)
 *
 * What it does:
 * Returns one-based faction index for the brain's owning army.
 */
int moho::cfunc_CAiBrainGetFactionIndexL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetFactionIndexHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  lua_pushnumber(rawState, static_cast<float>(brain->mArmy->FactionIndex + 1));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00586310 (FUN_00586310, cfunc_CAiBrainSetCurrentPlan)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainSetCurrentPlanL`.
 */
int moho::cfunc_CAiBrainSetCurrentPlan(lua_State* const luaContext)
{
  return cfunc_CAiBrainSetCurrentPlanL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00586330 (FUN_00586330, func_CAiBrainSetCurrentPlan_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:SetCurrentPlan(planName)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainSetCurrentPlan_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainSetCurrentPlanName,
    &moho::cfunc_CAiBrainSetCurrentPlan,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainSetCurrentPlanHelpText
  );
  return &binder;
}

/**
 * Address: 0x00586390 (FUN_00586390, cfunc_CAiBrainSetCurrentPlanL)
 *
 * What it does:
 * Updates the brain current-plan string from Lua arg #2 when it is a string.
 */
int moho::cfunc_CAiBrainSetCurrentPlanL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainSetCurrentPlanHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject planObject(LuaPlus::LuaStackObject(state, 2));
  if (planObject.IsString()) {
    const char* const planName = planObject.GetString();
    brain->mCurrentPlan.assign(planName, std::strlen(planName));
  }

  return 1;
}

/**
 * Address: 0x005864A0 (FUN_005864A0, cfunc_CAiBrainGetPersonality)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetPersonalityL`.
 */
int moho::cfunc_CAiBrainGetPersonality(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetPersonalityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005864C0 (FUN_005864C0, func_CAiBrainGetPersonality_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetPersonality()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetPersonality_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetPersonalityName,
    &moho::cfunc_CAiBrainGetPersonality,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetPersonalityHelpText
  );
  return &binder;
}

/**
 * Address: 0x00586520 (FUN_00586520, cfunc_CAiBrainGetPersonalityL)
 *
 * What it does:
 * Returns personality Lua object for this brain, or `nil` when unavailable.
 */
int moho::cfunc_CAiBrainGetPersonalityL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetPersonalityHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  if (brain->mPersonality != nullptr) {
    brain->mPersonality->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x005865F0 (FUN_005865F0, cfunc_CAiBrainSetCurrentEnemy)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainSetCurrentEnemyL`.
 */
int moho::cfunc_CAiBrainSetCurrentEnemy(lua_State* const luaContext)
{
  return cfunc_CAiBrainSetCurrentEnemyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00586610 (FUN_00586610, func_CAiBrainSetCurrentEnemy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:SetCurrentEnemy(enemyBrain)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainSetCurrentEnemy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainSetCurrentEnemyName,
    &moho::cfunc_CAiBrainSetCurrentEnemy,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainSetCurrentEnemyHelpText
  );
  return &binder;
}

/**
 * Address: 0x00586670 (FUN_00586670, cfunc_CAiBrainSetCurrentEnemyL)
 *
 * What it does:
 * Stores enemy army pointer from Lua arg #2 brain (or clears it on nil/invalid).
 */
int moho::cfunc_CAiBrainSetCurrentEnemyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainSetCurrentEnemyHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject enemyObject(LuaPlus::LuaStackObject(state, 2));
  if (enemyObject.IsNil()) {
    brain->mCurrentEnemy = nullptr;
  } else {
    CAiBrain* const enemyBrain = SCR_FromLua_CAiBrain(enemyObject, state);
    brain->mCurrentEnemy = enemyBrain ? enemyBrain->mArmy : nullptr;
  }

  return 1;
}

/**
 * Address: 0x00586770 (FUN_00586770, cfunc_CAiBrainGetCurrentEnemy)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetCurrentEnemyL`.
 */
int moho::cfunc_CAiBrainGetCurrentEnemy(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetCurrentEnemyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00586790 (FUN_00586790, func_CAiBrainGetCurrentEnemy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetCurrentEnemy()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetCurrentEnemy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetCurrentEnemyName,
    &moho::cfunc_CAiBrainGetCurrentEnemy,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetCurrentEnemyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005867F0 (FUN_005867F0, cfunc_CAiBrainGetCurrentEnemyL)
 *
 * What it does:
 * Returns current enemy brain Lua object for this brain, or `nil` when none.
 */
int moho::cfunc_CAiBrainGetCurrentEnemyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetCurrentEnemyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  CAiBrain* enemyBrain = nullptr;
  if (brain->mCurrentEnemy != nullptr) {
    enemyBrain = brain->mCurrentEnemy->GetArmyBrain();
  }

  if (enemyBrain != nullptr) {
    enemyBrain->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x005868D0 (FUN_005868D0, cfunc_CAiBrainGetUnitBlueprint)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetUnitBlueprintL`.
 */
int moho::cfunc_CAiBrainGetUnitBlueprint(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetUnitBlueprintL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005868F0 (FUN_005868F0, func_CAiBrainGetUnitBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetUnitBlueprint(bpName)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetUnitBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetUnitBlueprintName,
    &moho::cfunc_CAiBrainGetUnitBlueprint,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetUnitBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x00586950 (FUN_00586950, cfunc_CAiBrainGetUnitBlueprintL)
 *
 * What it does:
 * Resolves one unit blueprint id string for the given AI brain and returns
 * the matching Lua blueprint object, or `nil` when no blueprint is found.
 */
int moho::cfunc_CAiBrainGetUnitBlueprintL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetUnitBlueprintHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const char* const blueprintName = lua_tostring(state->m_state, 2);
  if (!blueprintName) {
    LuaPlus::LuaStackObject typeErrorArg(state, 2);
    LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
  }

  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintName ? blueprintName : "");

  RUnitBlueprint* blueprint = nullptr;
  if (brain != nullptr && brain->mSim != nullptr && brain->mSim->mRules != nullptr) {
    blueprint = brain->mSim->mRules->GetUnitBlueprint(lookupId);
  }

  if (blueprint != nullptr) {
    LuaPlus::LuaObject luaBlueprint = blueprint->GetLuaBlueprint(state);
    luaBlueprint.PushStack(state);
  } else {
    lua_pushnil(state->m_state);
  }

  return 1;
}

/**
 * Address: 0x00586AD0 (FUN_00586AD0, cfunc_CAiBrainGetArmyStat)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetArmyStatL`.
 */
int moho::cfunc_CAiBrainGetArmyStat(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetArmyStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00586AF0 (FUN_00586AF0, func_CAiBrainGetArmyStat_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetArmyStat(statName, defaultValue)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetArmyStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetArmyStatName,
    &moho::cfunc_CAiBrainGetArmyStat,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetArmyStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x00586B50 (FUN_00586B50, cfunc_CAiBrainGetArmyStatL)
 *
 * What it does:
 * Resolves one army stat by path and pushes its Lua table serialization.
 */
int moho::cfunc_CAiBrainGetArmyStatL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetArmyStatHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject statNameArg(state, 2);
  const char* const statName = lua_tostring(rawState, 2);
  if (statName == nullptr) {
    statNameArg.TypeError("string");
  }

  LuaPlus::LuaStackObject defaultValueArg(state, 3);
  CArmyStats* const armyStats = ResolveArmyStats(brain);
  CArmyStatItem* statItem = nullptr;

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      defaultValueArg.TypeError("integer");
    }
    (void)lua_tonumber(rawState, 3);
    statItem = ResolveArmyStatPathAsInt(armyStats, statName);
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    (void)defaultValueArg.GetNumber();
    statItem = ResolveArmyStatPathAsFloat(armyStats, statName);
  } else {
    LuaPlus::LuaState::Error(state, "Could not deduce default type for stat.");
  }

  LuaPlus::LuaObject statValue;
  STAT_GetLuaTable(state, statItem, statValue);
  statValue.PushStack(state);
  return 1;
}

/**
 * Address: 0x00586DA0 (FUN_00586DA0, cfunc_CAiBrainSetArmyStat)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainSetArmyStatL`.
 */
int moho::cfunc_CAiBrainSetArmyStat(lua_State* const luaContext)
{
  return cfunc_CAiBrainSetArmyStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00586DC0 (FUN_00586DC0, func_CAiBrainSetArmyStat_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:SetArmyStat(statName, value)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainSetArmyStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainSetArmyStatName,
    &moho::cfunc_CAiBrainSetArmyStat,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainSetArmyStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x00586E20 (FUN_00586E20, cfunc_CAiBrainSetArmyStatL)
 *
 * What it does:
 * Writes one numeric value into one army stat lane selected by stat path.
 */
int moho::cfunc_CAiBrainSetArmyStatL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainSetArmyStatHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject statNameArg(state, 2);
  const char* const statName = lua_tostring(rawState, 2);
  if (statName == nullptr) {
    statNameArg.TypeError("string");
  }

  LuaPlus::LuaStackObject valueArg(state, 3);
  CArmyStats* const armyStats = ResolveArmyStats(brain);

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      valueArg.TypeError("integer");
    }

    const std::int32_t intValue = static_cast<std::int32_t>(lua_tonumber(rawState, 3));
    if (CArmyStatItem* const statItem = ResolveCachedArmyStatPath(armyStats, statName); statItem != nullptr) {
      statItem->SynchronizeAsInt();
      AtomicStoreStatValueBits(&statItem->mPrimaryValueBits, intValue);
    }
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const float floatValue = valueArg.GetNumber();
    if (CArmyStatItem* const statItem = ResolveCachedArmyStatPath(armyStats, statName); statItem != nullptr) {
      statItem->SynchronizeAsFloat();

      std::int32_t floatValueBits = 0;
      std::memcpy(&floatValueBits, &floatValue, sizeof(floatValueBits));
      AtomicStoreStatValueBits(&statItem->mPrimaryValueBits, floatValueBits);
    }
  }

  return 0;
}

/**
 * Address: 0x00587020 (FUN_00587020, cfunc_CAiBrainAddArmyStat)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainAddArmyStatL`.
 */
int moho::cfunc_CAiBrainAddArmyStat(lua_State* const luaContext)
{
  return cfunc_CAiBrainAddArmyStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00587040 (FUN_00587040, func_CAiBrainAddArmyStat_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:AddArmyStat(statName, value)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainAddArmyStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainAddArmyStatName,
    &moho::cfunc_CAiBrainAddArmyStat,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainAddArmyStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x005870A0 (FUN_005870A0, cfunc_CAiBrainAddArmyStatL)
 *
 * What it does:
 * Adds one numeric delta to one army stat lane selected by stat path.
 */
int moho::cfunc_CAiBrainAddArmyStatL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainAddArmyStatHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject statNameArg(state, 2);
  const char* const statName = lua_tostring(rawState, 2);
  if (statName == nullptr) {
    statNameArg.TypeError("string");
  }

  LuaPlus::LuaStackObject valueArg(state, 3);
  CArmyStats* const armyStats = ResolveArmyStats(brain);

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      valueArg.TypeError("integer");
    }

    const std::int32_t intDelta = static_cast<std::int32_t>(lua_tonumber(rawState, 3));
    if (CArmyStatItem* const statItem = ResolveCachedArmyStatPath(armyStats, statName); statItem != nullptr) {
      statItem->SynchronizeAsInt();
      (void)InterlockedExchangeAdd(
        reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits),
        static_cast<long>(intDelta)
      );
    }
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const float floatDelta = valueArg.GetNumber();
    if (CArmyStatItem* const statItem = ResolveCachedArmyStatPath(armyStats, statName); statItem != nullptr) {
      statItem->SynchronizeAsFloat();
      AtomicAddFloatStatValueBits(&statItem->mPrimaryValueBits, floatDelta);
    }
  }

  return 0;
}

/**
 * Address: 0x005872A0 (FUN_005872A0, cfunc_CAiBrainSetGreaterOf)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainSetGreaterOfL`.
 */
int moho::cfunc_CAiBrainSetGreaterOf(lua_State* const luaContext)
{
  return cfunc_CAiBrainSetGreaterOfL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005872C0 (FUN_005872C0, func_CAiBrainSetGreaterOf_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:SetGreaterOf(statName, value)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainSetGreaterOf_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainSetGreaterOfName,
    &moho::cfunc_CAiBrainSetGreaterOf,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainSetGreaterOfHelpText
  );
  return &binder;
}

/**
 * Address: 0x00587320 (FUN_00587320, cfunc_CAiBrainSetGreaterOfL)
 *
 * What it does:
 * Updates one army stat only when the incoming value is greater than the
 * currently stored value.
 */
int moho::cfunc_CAiBrainSetGreaterOfL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainSetGreaterOfHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject statNameArg(state, 2);
  const char* const statName = lua_tostring(rawState, 2);
  if (statName == nullptr) {
    statNameArg.TypeError("string");
  }

  LuaPlus::LuaStackObject valueArg(state, 3);
  CArmyStats* const armyStats = ResolveArmyStats(brain);

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      valueArg.TypeError("integer");
    }

    const std::int32_t intValue = static_cast<std::int32_t>(lua_tonumber(rawState, 3));
    SetArmyStatIntToGreaterOf(armyStats, statName, intValue);
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const float floatValue = valueArg.GetNumber();
    SetArmyStatFloatToGreaterOf(armyStats, statName, floatValue);
  }

  return 0;
}

/**
 * Address: 0x00587520 (FUN_00587520, cfunc_CAiBrainGetBlueprintStat)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetBlueprintStatL`.
 */
int moho::cfunc_CAiBrainGetBlueprintStat(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetBlueprintStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00587540 (FUN_00587540, func_CAiBrainGetBlueprintStat_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetBlueprintStat(statName, category)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetBlueprintStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetBlueprintStatName,
    &moho::cfunc_CAiBrainGetBlueprintStat,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetBlueprintStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x005875A0 (FUN_005875A0, cfunc_CAiBrainGetBlueprintStatL)
 *
 * What it does:
 * Resolves one stat path and returns its blueprint-category aggregate.
 */
int moho::cfunc_CAiBrainGetBlueprintStatL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetBlueprintStatHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject statNameArg(state, 2);
  const char* const statName = lua_tostring(rawState, 2);
  if (statName == nullptr) {
    statNameArg.TypeError("string");
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 3));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  float result = 0.0f;
  if (CArmyStats* const armyStats = ResolveArmyStats(brain); armyStats != nullptr) {
    if (CArmyStatItem* const statItem = armyStats->GetStat(statName); statItem != nullptr) {
      result = statItem->SumCategory(categorySet);
    }
  }

  lua_pushnumber(rawState, result);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005876E0 (FUN_005876E0, cfunc_CAiBrainGetCurrentUnits)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetCurrentUnitsL`.
 */
int moho::cfunc_CAiBrainGetCurrentUnits(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetCurrentUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00587700 (FUN_00587700, func_CAiBrainGetCurrentUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetCurrentUnits(category)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetCurrentUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetCurrentUnitsName,
    &moho::cfunc_CAiBrainGetCurrentUnits,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetCurrentUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00587760 (FUN_00587760, cfunc_CAiBrainGetCurrentUnitsL)
 *
 * What it does:
 * Returns category-filtered `Units_Active` count truncated to integer.
 */
int moho::cfunc_CAiBrainGetCurrentUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetCurrentUnitsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  float unitCount = 0.0f;
  if (CArmyStats* const armyStats = ResolveArmyStats(brain); armyStats != nullptr) {
    if (CArmyStatItem* const statItem = armyStats->GetStat(kAiBrainActiveUnitsStatPath); statItem != nullptr) {
      unitCount = statItem->SumCategory(categorySet);
    }
  }

  const std::int32_t truncatedCount = static_cast<std::int32_t>(unitCount);
  lua_pushnumber(rawState, static_cast<float>(truncatedCount));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00587B80 (FUN_00587B80, cfunc_CAiBrainSetArmyStatsTrigger)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainSetArmyStatsTriggerL`.
 */
int moho::cfunc_CAiBrainSetArmyStatsTrigger(lua_State* const luaContext)
{
  return cfunc_CAiBrainSetArmyStatsTriggerL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00587BA0 (FUN_00587BA0, func_CAiBrainSetArmyStatsTrigger_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:SetArmyStatsTrigger(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainSetArmyStatsTrigger_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainSetArmyStatsTriggerName,
    &moho::cfunc_CAiBrainSetArmyStatsTrigger,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainSetArmyStatsTriggerHelpText
  );
  return &binder;
}

/**
 * Address: 0x00587C00 (FUN_00587C00, cfunc_CAiBrainSetArmyStatsTriggerL)
 *
 * What it does:
 * Adds one trigger condition bound to `(triggerName, statPath)` with optional
 * category filtering.
 */
int moho::cfunc_CAiBrainSetArmyStatsTriggerL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 5 || argumentCount > 6) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainSetArmyStatsTriggerHelpText,
      5,
      6,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject statPathArg(state, 2);
  const char* const statPath = lua_tostring(rawState, 2);
  if (statPath == nullptr) {
    statPathArg.TypeError("string");
  }

  LuaPlus::LuaStackObject triggerNameArg(state, 3);
  const char* const triggerName = lua_tostring(rawState, 3);
  if (triggerName == nullptr) {
    triggerNameArg.TypeError("string");
  }

  LuaPlus::LuaStackObject triggerOperatorArg(state, 4);
  const char* const triggerOperatorName = lua_tostring(rawState, 4);
  if (triggerOperatorName == nullptr) {
    triggerOperatorArg.TypeError("string");
  }

  ETriggerOperator triggerOperator = TRIGGER_GreaterThan;
  gpg::RRef enumRef = MakeTriggerOperatorRef(&triggerOperator);
  SCR_GetEnum(state, triggerOperatorName, enumRef);

  LuaPlus::LuaStackObject thresholdArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    thresholdArg.TypeError("number");
  }
  const float threshold = static_cast<float>(lua_tonumber(rawState, 5));

  EntityCategorySet categorySet{};
  if (argumentCount > 5 && lua_type(rawState, 6) != LUA_TNIL) {
    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 6));
    if (EntityCategorySet* const parsedCategorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);
        parsedCategorySet != nullptr) {
      categorySet = *parsedCategorySet;
    }
  }

  if (CArmyStats* const armyStats = ResolveArmyStats(brain); armyStats != nullptr) {
    armyStats->EnsureTriggerExists(triggerName);
    CArmyStats::SetArmyStatsTrigger(&categorySet, armyStats, triggerName, statPath, triggerOperator, threshold);
  }

  return 0;
}

/**
 * Address: 0x00587FA0 (FUN_00587FA0, cfunc_CAiBrainRemoveArmyStatsTrigger)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainRemoveArmyStatsTriggerL`.
 */
int moho::cfunc_CAiBrainRemoveArmyStatsTrigger(lua_State* const luaContext)
{
  return cfunc_CAiBrainRemoveArmyStatsTriggerL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00587FC0 (FUN_00587FC0, func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:RemoveArmyStatsTrigger(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainRemoveArmyStatsTriggerName,
    &moho::cfunc_CAiBrainRemoveArmyStatsTrigger,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainRemoveArmyStatsTriggerHelpText
  );
  return &binder;
}

/**
 * Address: 0x00588020 (FUN_00588020, cfunc_CAiBrainRemoveArmyStatsTriggerL)
 *
 * What it does:
 * Removes one named army-stats trigger from the owning army.
 */
int moho::cfunc_CAiBrainRemoveArmyStatsTriggerL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainRemoveArmyStatsTriggerHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject unusedStatPathArg(state, 2);
  const char* const unusedStatPath = lua_tostring(rawState, 2);
  if (unusedStatPath == nullptr) {
    unusedStatPathArg.TypeError("string");
  }
  (void)unusedStatPath;

  LuaPlus::LuaStackObject triggerNameArg(state, 3);
  const char* const triggerName = lua_tostring(rawState, 3);
  if (triggerName == nullptr) {
    triggerNameArg.TypeError("string");
  }

  if (CArmyStats* const armyStats = ResolveArmyStats(brain); armyStats != nullptr) {
    armyStats->RemoveArmyStatsTrigger(triggerName);
  }

  return 0;
}

/**
 * Address: 0x00587870 (FUN_00587870, cfunc_CAiBrainGetListOfUnits)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetListOfUnitsL`.
 */
int moho::cfunc_CAiBrainGetListOfUnits(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetListOfUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00587890 (FUN_00587890, func_CAiBrainGetListOfUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetListOfUnits(entityCategory, needToBeIdle, requireBuilt)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetListOfUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetListOfUnitsName,
    &moho::cfunc_CAiBrainGetListOfUnits,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetListOfUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x005878F0 (FUN_005878F0, cfunc_CAiBrainGetListOfUnitsL)
 *
 * What it does:
 * Returns a Lua array of unit Lua objects matching category arg #2, with
 * optional idle/build filtering via args #3 and #4.
 */
int moho::cfunc_CAiBrainGetListOfUnitsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 3 || argumentCount > 4) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainGetListOfUnitsHelpText,
      3,
      4,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  const bool needToBeIdle = LuaPlus::LuaStackObject(state, 3).GetBoolean();
  bool requireBuilt = true;
  if (argumentCount > 3) {
    requireBuilt = LuaPlus::LuaStackObject(state, 4).GetBoolean();
  }

  SEntitySetTemplateUnit categoryUnits{};
  brain->mArmy->GetUnits(&categoryUnits, categorySet);

  SEntitySetTemplateUnit filteredUnits{};
  for (Entity* const* it = categoryUnits.mVec.begin(); it != categoryUnits.mVec.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (unit == nullptr) {
      continue;
    }

    if (unit->IsDead() || unit->DestroyQueued()) {
      continue;
    }

    if (requireBuilt && unit->IsBeingBuilt()) {
      continue;
    }

    if (needToBeIdle && UnitHasHeadCommand(unit)) {
      continue;
    }

    (void)filteredUnits.AddUnit(unit);
  }

  LuaPlus::LuaObject outUnits{};
  (void)FillLuaTableWithEntities(filteredUnits, &outUnits, state);

  outUnits.PushStack(state);
  return 1;
}

/**
 * Address: 0x00588850 (FUN_00588850, cfunc_CAiBrainSetResourceSharing)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainSetResourceSharingL`.
 */
int moho::cfunc_CAiBrainSetResourceSharing(lua_State* const luaContext)
{
  return cfunc_CAiBrainSetResourceSharingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588870 (FUN_00588870, func_CAiBrainSetResourceSharing_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:SetResourceSharing(bool)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainSetResourceSharing_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainSetResourceSharingName,
    &moho::cfunc_CAiBrainSetResourceSharing,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainSetResourceSharingHelpText
  );
  return &binder;
}

/**
 * Address: 0x005888D0 (FUN_005888D0, cfunc_CAiBrainSetResourceSharingL)
 *
 * What it does:
 * Sets per-army economy resource-sharing enable flag from Lua arg #2.
 */
int moho::cfunc_CAiBrainSetResourceSharingL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainSetResourceSharingHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const bool enableSharing = LuaPlus::LuaStackObject(state, 2).GetBoolean();
  brain->mArmy->GetEconomy()->isResourceSharingEnabled = enableSharing ? 1u : 0u;
  return 0;
}

/**
 * Address: 0x00589720 (FUN_00589720, cfunc_CAiBrainGetArmyStartPos)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetArmyStartPosL`.
 */
int moho::cfunc_CAiBrainGetArmyStartPos(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetArmyStartPosL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00589740 (FUN_00589740, func_CAiBrainGetArmyStartPos_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetArmyStartPos()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetArmyStartPos_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetArmyStartPosName,
    &moho::cfunc_CAiBrainGetArmyStartPos,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetArmyStartPosHelpText
  );
  return &binder;
}

/**
 * Address: 0x005897A0 (FUN_005897A0, cfunc_CAiBrainGetArmyStartPosL)
 *
 * What it does:
 * Returns army start position as two Lua numbers: `x`, `y`.
 */
int moho::cfunc_CAiBrainGetArmyStartPosL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetArmyStartPosHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  Wm3::Vector2f startPosition{};
  (void)lua_getglobaluserdata(rawState);
  brain->mArmy->GetArmyStartPos(startPosition);

  lua_pushnumber(rawState, startPosition.x);
  (void)lua_gettop(rawState);
  lua_pushnumber(rawState, startPosition.y);
  (void)lua_gettop(rawState);
  return 2;
}

/**
 * Address: 0x00589910 (FUN_00589910, cfunc_CAiBrainCreateUnitNearSpotL)
 *
 * IDA signature:
 * int __cdecl cfunc_CAiBrainCreateUnitNearSpotL(LuaPlus::LuaState* state);
 *
 * What it does:
 * `brain:CreateUnitNearSpot(unitName, posX, posY)` worker: resolves the unit
 * blueprint, occupies a small grid rect around the army start, tries to place
 * the structure at (posX,posY), and — on success — constructs the unit and
 * returns its Lua object (or nil).
 */
int moho::cfunc_CAiBrainCreateUnitNearSpotL(LuaPlus::LuaState* const state)
{
  Sim* const sim = lua_getglobaluserdata_typed(state->m_state);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected %d args, but got %d", kAiBrainCreateUnitNearSpotHelpText, 4, argumentCount);
  }
  if (lua_type(state->m_state, 2) == 0 || !lua_isstring(state->m_state, 2)) {
    LuaPlus::LuaState::Error(state, "Invalid unit name passed in");
  }
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaState::Error(state, "Invalid posX passed in");
  }
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaState::Error(state, "Invalid posY passed in");
  }

  CAiBrain* brain = nullptr;
  {
    const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
    brain = SCR_FromLua_CAiBrain(brainObject, state);
  }

  const char* const unitName = lua_tostring(state->m_state, 2);
  if (unitName == nullptr) {
    LuaPlus::LuaStackObject nameObject(state, 2);
    nameObject.TypeError("string");
  }

  CArmyImpl* const army = brain->mArmy;

  const float posY = static_cast<float>(lua_tonumber(state->m_state, 4));
  const float posX = static_cast<float>(lua_tonumber(state->m_state, 3));
  SCoordsVec2 tryPos{};
  tryPos.x = posX;
  tryPos.z = posY;

  msvc8::string blueprintName;
  gpg::STR_InitFilename(&blueprintName, unitName);
  RUnitBlueprint* const blueprint = sim->mRules->GetUnitBlueprint(RResId(blueprintName));

  COGrid* const grid = sim->mOGrid;

  Wm3::Vector2f startPosition;
  army->GetArmyStartPos(startPosition);
  gpg::Rect2i occupyRect{};
  occupyRect.x0 = static_cast<int>(startPosition.x) - 5;
  occupyRect.x1 = static_cast<int>(startPosition.x) + 5;
  occupyRect.z0 = static_cast<int>(startPosition.y) - 5;
  occupyRect.z1 = static_cast<int>(startPosition.y) + 5;

  const EOccupancyCaps occupancyCaps = blueprint->mFootprint.mOccupancyCaps;
  grid->ExecuteOccupy(occupancyCaps, occupyRect);

  Unit* createdUnit = nullptr;
  if (TryBuildStructureAt(&tryPos, blueprint, sim, true, true, true, true)) {
    SUnitConstructionParams params(0, Wm3::Vector3f(tryPos.x, 0.0f, tryPos.z), army, blueprint, nullptr, true);
    params.mUseLayerOverride = 1;
    createdUnit = sim->CreateUnitForScript(params, true);
  }

  grid->ReleaseOccupy(occupancyCaps, occupyRect);

  if (createdUnit != nullptr) {
    LuaPlus::LuaObject unitLuaObject = createdUnit->GetLuaObject();
    unitLuaObject.PushStack(state);
    return 1;
  }

  lua_pushnil(state->m_state);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00589890 (FUN_00589890, cfunc_CAiBrainCreateUnitNearSpot)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to
 * `cfunc_CAiBrainCreateUnitNearSpotL`.
 */
int moho::cfunc_CAiBrainCreateUnitNearSpot(lua_State* const luaContext)
{
  return cfunc_CAiBrainCreateUnitNearSpotL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005898B0 (FUN_005898B0, func_CAiBrainCreateUnitNearSpot_LuaFuncDef)
 *
 * What it does:
 * Publishes the `brain:CreateUnitNearSpot(unitName, posX, posY)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainCreateUnitNearSpot_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainCreateUnitNearSpotName,
    &moho::cfunc_CAiBrainCreateUnitNearSpot,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainCreateUnitNearSpotHelpText
  );
  return &binder;
}

/**
 * Address: 0x00589E30 (FUN_00589E30, cfunc_CAiBrainCreateResourceBuildingNearestL)
 *
 * IDA signature:
 * int __cdecl cfunc_CAiBrainCreateResourceBuildingNearestL(LuaPlus::LuaState* state);
 *
 * What it does:
 * `brain:CreateResourceBuildingNearest(structureName, posX, posY)` worker.
 * Resolves the structure blueprint and the resource-deposit class it consumes
 * (kHydrocarbon when the blueprint carries the HYDROCARBON category, otherwise
 * kMass), gathers every deposit of that class into a nearest-first candidate
 * list (sorted by squared distance from the requested (posX,posY)), and walks
 * it: for the first candidate where `CanBuildStructureAt` succeeds it computes
 * the placement elevation (terrain height, clamped up to the water surface for
 * non-seabed structures), spawns the unit at the deposit centre, and returns
 * its Lua object. Pushes nil when no candidate can host the structure.
 */
int moho::cfunc_CAiBrainCreateResourceBuildingNearestL(LuaPlus::LuaState* const state)
{
  Sim* const sim = lua_getglobaluserdata_typed(state->m_state);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected %d args, but got %d", kAiBrainCreateResourceBuildingNearestHelpText, 4, argumentCount);
  }
  if (lua_type(state->m_state, 2) == 0 || !lua_isstring(state->m_state, 2)) {
    LuaPlus::LuaState::Error(state, "Invalid structure name passed in");
  }
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    LuaPlus::LuaState::Error(state, "Invalid posX passed in");
  }
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    LuaPlus::LuaState::Error(state, "Invalid posY passed in");
  }

  CAiBrain* brain = nullptr;
  {
    const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
    brain = SCR_FromLua_CAiBrain(brainObject, state);
  }

  const char* const structureName = lua_tostring(state->m_state, 2);
  if (structureName == nullptr) {
    LuaPlus::LuaStackObject nameObject(state, 2);
    nameObject.TypeError("string");
  }

  CArmyImpl* const army = brain->mArmy;

  // Numeric args read in the binary's order: posY (arg 4) then posX (arg 3),
  // each re-validated right before extraction.
  LuaPlus::LuaStackObject posYObject(state, 4);
  if (lua_type(state->m_state, 4) != LUA_TNUMBER) {
    posYObject.TypeError("number");
  }
  const float posY = static_cast<float>(lua_tonumber(state->m_state, 4));

  LuaPlus::LuaStackObject posXObject(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    posXObject.TypeError("number");
  }
  const float posX = static_cast<float>(lua_tonumber(state->m_state, 3));

  RUnitBlueprint* structureBlueprint = nullptr;
  {
    msvc8::string blueprintName;
    gpg::STR_InitFilename(&blueprintName, structureName);
    structureBlueprint = sim->mRules->GetUnitBlueprint(RResId(blueprintName));
  }

  // Hydrocarbon buildings sit on kHydrocarbon deposits; everything else on kMass.
  const CategoryWordRangeView* const hydrocarbonCategory = sim->mRules->GetEntityCategory("HYDROCARBON");
  const EDepositType wantedDeposit =
    EntityCategory::HasBlueprint(structureBlueprint, hydrocarbonCategory) ? kHydrocarbon : kMass;

  CSimResources* const resources = sim->mSimResources.px;
  const msvc8::vector<ResourceDeposit>& deposits = resources->GetDeposits();

  // A candidate is one deposit footprint centre plus its squared distance from
  // the requested point; the list is walked nearest-first.
  struct SDepositCandidate
  {
    float centerX;
    float centerZ;
    float distanceSq;
  };
  std::vector<SDepositCandidate> candidates;
  for (const ResourceDeposit& deposit : deposits) {
    if (deposit.depositType != wantedDeposit) {
      continue;
    }
    const float centerX = static_cast<float>(deposit.footprintRect.x0 + deposit.footprintRect.x1) * 0.5f;
    const float centerZ = static_cast<float>(deposit.footprintRect.z0 + deposit.footprintRect.z1) * 0.5f;
    const float dx = posX - centerX;
    const float dz = posY - centerZ;
    candidates.push_back(SDepositCandidate{centerX, centerZ, (dx * dx) + (dz * dz)});
  }

  msvc8::sort(candidates.data(), candidates.data() + candidates.size(), [](const SDepositCandidate& a, const SDepositCandidate& b) {
    return a.distanceSq < b.distanceSq;
  });

  for (const SDepositCandidate& candidate : candidates) {
    const Wm3::Vector3f queryPos(candidate.centerX, 0.0f, candidate.centerZ);
    if (!brain->CanBuildStructureAt(
          queryPos, structureBlueprint, ALLIANCE_None, static_cast<int>(candidate.centerX),
          static_cast<int>(candidate.centerZ))) {
      continue;
    }

    STIMap* const mapData = sim->mMapData;
    float elevation = mapData->GetHeightField()->GetElevation(candidate.centerX, candidate.centerZ);
    const bool occupiesSeabed = (static_cast<std::uint8_t>(structureBlueprint->mFootprint.mOccupancyCaps) &
                                 static_cast<std::uint8_t>(EOccupancyCaps::OC_SEABED)) != 0u;
    if (!occupiesSeabed && mapData->mWaterEnabled) {
      if (mapData->mWaterElevation > elevation) {
        elevation = mapData->mWaterElevation;
      }
    }

    const VTransform transform(
      Wm3::Vector3f(candidate.centerX, elevation, candidate.centerZ), Wm3::Quaternionf(1.0f, 0.0f, 0.0f, 0.0f));
    SUnitConstructionParams params(1, transform, army, structureBlueprint, nullptr, true);

    Unit* const createdUnit = sim->CreateUnitForScript(params, true);
    if (createdUnit != nullptr) {
      LuaPlus::LuaObject unitLuaObject = createdUnit->GetLuaObject();
      unitLuaObject.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(state->m_state);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00589DB0 (FUN_00589DB0, cfunc_CAiBrainCreateResourceBuildingNearest)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to
 * `cfunc_CAiBrainCreateResourceBuildingNearestL`.
 */
int moho::cfunc_CAiBrainCreateResourceBuildingNearest(lua_State* const luaContext)
{
  return cfunc_CAiBrainCreateResourceBuildingNearestL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00589DD0 (FUN_00589DD0, func_CAiBrainCreateResourceBuildingNearest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `brain:CreateResourceBuildingNearest(structureName, posX, posY)` Lua binder.
 */
void moho::func_CAiBrainCreateResourceBuildingNearest_LuaFuncDef()
{
  [[maybe_unused]] static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainCreateResourceBuildingNearestName,
    &moho::cfunc_CAiBrainCreateResourceBuildingNearest,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainCreateResourceBuildingNearestHelpText
  );
}

/**
 * Address: 0x0058A4C0 (FUN_0058A4C0, cfunc_CAiBrainFindPlaceToBuildL)
 *
 * IDA signature:
 * int __cdecl cfunc_CAiBrainFindPlaceToBuildL(LuaPlus::LuaState* state);
 *
 * What it does:
 * brain:FindPlaceToBuild(type, structureName, buildingTypes, relative, [builder],
 * [optIgnoreAlliance], [optOverridePosX, optOverridePosZ], [optIgnoreThreatOver]).
 * Finds a placement for a structure and returns it as a {x, z, 0} Lua table, or
 * nil, via two paths:
 *   Resource path (type is Resource / T1..T3Resource / T1HydroCarbon, and the
 *     "/nomass" arg is unset): scans resource deposits of the structure's class
 *     nearest-first from the army start (or override position) and returns the
 *     first deposit centre that clears the threat gate and CanBuildStructureAt.
 *   General path: walks the caller-supplied buildingTypes table (groups of
 *     {typeNameList, positions...}); for every group whose type list contains
 *     `type`, scores each candidate position by distance to the reference point
 *     (builder position / override / army start) and keeps the closest that
 *     passes CanBuildStructureAt, does not overlap a resource deposit, and
 *     clears the threat gate.
 */
int moho::cfunc_CAiBrainFindPlaceToBuildL(LuaPlus::LuaState* const state)
{
  Sim* const sim = lua_getglobaluserdata_typed(state->m_state);
  const int numArgs = lua_gettop(state->m_state);
  if (numArgs < 6 || numArgs > 10) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected between %d and %d args, but got %d", kAiBrainFindPlaceToBuildHelpText, 6, 10, numArgs);
  }

  // Arg types: 2 = type (string), 3 = structureName (string), 4 = buildingTypes (table).
  if (lua_type(state->m_state, 2) == 0 || !lua_isstring(state->m_state, 2)) {
    LuaPlus::LuaState::Error(state, "Invalid Type name passed in");
  }
  if (lua_type(state->m_state, 3) == 0 || !lua_isstring(state->m_state, 3)) {
    LuaPlus::LuaState::Error(state, "Invalid Structure name passed in");
  }
  {
    const LuaPlus::LuaObject buildingTypesArg(LuaPlus::LuaStackObject(state, 4));
    if (lua_type(state->m_state, 4) == 0 || !buildingTypesArg.IsTable()) {
      LuaPlus::LuaState::Error(state, "Invalid buildingTypes passed in. Not a lua table!");
    }
  }

  CAiBrain* aiBrain = nullptr;
  {
    const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
    aiBrain = SCR_FromLua_CAiBrain(brainObject, state);
  }

  LuaPlus::LuaStackObject typeArg(state, 2);
  const char* const type = lua_tostring(state->m_state, 2);
  if (type == nullptr) {
    typeArg.TypeError("string");
  }
  LuaPlus::LuaStackObject structureNameArg(state, 3);
  const char* const structureName = lua_tostring(state->m_state, 3);
  if (structureName == nullptr) {
    structureNameArg.TypeError("string");
  }

  const LuaPlus::LuaObject buildingTypes(LuaPlus::LuaStackObject(state, 4));
  const bool relative = LuaPlus::LuaStackObject(state, 5).GetBoolean();

  // Optional builder unit (arg 6).
  Unit* builderUnit = nullptr;
  if (lua_type(state->m_state, 6) != 0) {
    const LuaPlus::LuaObject builderObject(LuaPlus::LuaStackObject(state, 6));
    builderUnit = SCR_FromLua_Unit(builderObject);
  }

  // Optional alliance filter to ignore (arg 7); default = ALLIANCE_None.
  EAlliance optIgnoreAlliance = ALLIANCE_None;
  if (numArgs >= 7 && lua_type(state->m_state, 7) != 0) {
    gpg::RRef enumRef;
    (void)gpg::RRef_EAlliance(&enumRef, &optIgnoreAlliance);
    LuaPlus::LuaStackObject allianceArg(state, 7);
    const char* const allianceName = lua_tostring(state->m_state, 7);
    if (allianceName == nullptr) {
      allianceArg.TypeError("string");
    }
    SCR_GetEnum(state, allianceName, enumRef);
  }

  // Optional override position (args 8 = X, 9 = Z).
  bool hasOverridePos = false;
  Wm3::Vector3f overridePos(0.0f, 0.0f, 0.0f);
  if (numArgs >= 9 && lua_type(state->m_state, 8) != 0 && lua_type(state->m_state, 9) != 0) {
    hasOverridePos = true;
    overridePos.x = static_cast<float>(LuaPlus::LuaStackObject(state, 8).GetNumber());
    overridePos.z = static_cast<float>(LuaPlus::LuaStackObject(state, 9).GetNumber());
  }

  // Optional threat ceiling (arg 10).
  int optIgnoreThreatOver = 0;
  if (numArgs >= 10 && lua_type(state->m_state, 10) != 0) {
    optIgnoreThreatOver = LuaPlus::LuaStackObject(state, 10).GetInteger();
  }

  CArmyImpl* const mArmy = aiBrain->mArmy;

  RUnitBlueprint* structureBp = nullptr;
  {
    msvc8::string structureFilename;
    gpg::STR_InitFilename(&structureFilename, structureName);
    structureBp = sim->mRules->GetUnitBlueprint(RResId(structureFilename));
  }

  CSimResources* const resources = sim->mSimResources.px;

  Wm3::Vector2f armyStart;
  mArmy->GetArmyStartPos(armyStart);
  Wm3::Vector3f startingPos;
  startingPos.x = armyStart.x;
  startingPos.z = armyStart.y;
  const float armyStartZ = armyStart.y;

  // ---- Resource path -------------------------------------------------------
  const bool isResourceType = _stricmp(type, "Resource") == 0 || _stricmp(type, "T1Resource") == 0 ||
    _stricmp(type, "T2Resource") == 0 || _stricmp(type, "T3Resource") == 0 || _stricmp(type, "T1HydroCarbon") == 0;
  if (!CFG_GetArgOption("/nomass", 0, nullptr) && isResourceType) {
    if (hasOverridePos) {
      startingPos.x = overridePos.x;
      startingPos.z = overridePos.z;
    }

    const CategoryWordRangeView* const hydrocarbonCategory = sim->mRules->GetEntityCategory("HYDROCARBON");
    const EDepositType wantedDeposit =
      EntityCategory::HasBlueprint(structureBp, hydrocarbonCategory) ? kHydrocarbon : kMass;

    struct SDepositCandidate
    {
      float centerX;
      float centerZ;
      float distanceSq;
    };
    std::vector<SDepositCandidate> candidates;
    for (const ResourceDeposit& deposit : resources->GetDeposits()) {
      if (deposit.depositType != wantedDeposit) {
        continue;
      }
      const float centerX = static_cast<float>(deposit.footprintRect.x0 + deposit.footprintRect.x1) * 0.5f;
      const float centerZ = static_cast<float>(deposit.footprintRect.z0 + deposit.footprintRect.z1) * 0.5f;
      const float dx = startingPos.x - centerX;
      const float dz = startingPos.z - centerZ;
      candidates.push_back(SDepositCandidate{centerX, centerZ, (dx * dx) + (dz * dz)});
    }

    msvc8::sort(candidates.data(), candidates.data() + candidates.size(), [](const SDepositCandidate& a, const SDepositCandidate& b) {
      return a.distanceSq < b.distanceSq;
    });

    for (const SDepositCandidate& candidate : candidates) {
      const int cellWorldX = static_cast<int>(candidate.centerX);
      const int cellWorldZ = static_cast<int>(candidate.centerZ);
      if (optIgnoreThreatOver > 0) {
        CInfluenceMap* const igrid = mArmy->GetIGrid();
        const int mWidth = igrid->mWidth;
        int locX = cellWorldX / igrid->mGridSize;
        if (locX >= mWidth - 1) {
          locX = mWidth - 1;
        }
        if (locX < 0) {
          locX = 0;
        }
        int locY = cellWorldZ / igrid->mGridSize;
        if (locY >= igrid->mHeight - 1) {
          locY = igrid->mHeight - 1;
        }
        if (locY < 0) {
          locY = 0;
        }
        const int cellIndex = locX + locY * mWidth;
        const float threat = igrid->GetThreatRect(
          cellIndex % igrid->mWidth, cellIndex / igrid->mWidth, 0, true, THREATTYPE_AntiSurface, -1);
        if (threat >= static_cast<float>(optIgnoreThreatOver)) {
          continue;
        }
      }

      const Wm3::Vector3f buildPos(candidate.centerX, 0.0f, candidate.centerZ);
      if (aiBrain->CanBuildStructureAt(buildPos, structureBp, optIgnoreAlliance, cellWorldX, cellWorldZ)) {
        float resultX = candidate.centerX;
        float resultZ = candidate.centerZ;
        if (relative) {
          resultX -= startingPos.x;
          resultZ -= startingPos.z;
        }
        LuaPlus::LuaObject resultTable;
        resultTable.AssignNewTable(state, 0, 3);
        resultTable.SetNumber(1, resultX);
        resultTable.SetNumber(2, resultZ);
        resultTable.SetNumber(3, 0.0f);
        resultTable.PushStack(state);
        return 1;
      }
    }

    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  // ---- General building-types path ----------------------------------------
  Wm3::Vector3f targetPos(startingPos.x, 0.0f, armyStartZ);
  if (builderUnit != nullptr) {
    targetPos = builderUnit->GetPosition();
  }
  if (hasOverridePos) {
    targetPos.x = overridePos.x;
    targetPos.y = 0.0f;
    targetPos.z = overridePos.z;
    startingPos.x = overridePos.x;
    startingPos.z = overridePos.z;
  }

  LuaPlus::LuaObject closestPlacement;
  float closestDist = std::numeric_limits<float>::infinity();

  for (int groupIndex = 1; groupIndex <= buildingTypes.GetCount(); ++groupIndex) {
    LuaPlus::LuaObject buildingGroup = buildingTypes[groupIndex];
    LuaPlus::LuaObject typeNameList = buildingGroup[1];
    if (buildingGroup.IsNil() || !buildingGroup.IsTable()) {
      LuaPlus::LuaState::Error(state, "Error parsing building types. Missing type list lua table!");
    } else if (typeNameList.IsNil() || !typeNameList.IsTable()) {
      LuaPlus::LuaState::Error(state, "Error parsing building types. Missing type match lua table!");
    }

    // Does this group's type-name list contain the requested type?
    bool typeMatches = false;
    if (typeNameList.GetCount() >= 1) {
      for (int typeIndex = 1; typeIndex <= typeNameList.GetCount(); ++typeIndex) {
        LuaPlus::LuaObject typeNameObject = typeNameList[typeIndex];
        if (_stricmp(typeNameObject.GetString(), type) == 0) {
          typeMatches = true;
          break;
        }
      }
    }
    if (!typeMatches) {
      continue;
    }

    // Score each candidate position in the group (entries [2 .. GetCount()]).
    const float dy2 = targetPos.y * targetPos.y;
    for (int posIndex = 2; posIndex <= buildingGroup.GetCount(); ++posIndex) {
      LuaPlus::LuaObject positionEntry = buildingGroup[posIndex];
      LuaPlus::LuaObject entryX = positionEntry[1];
      LuaPlus::LuaObject entryZ = positionEntry[2];
      Wm3::Vector3f position;
      position.x = static_cast<float>(entryX.GetNumber());
      position.z = static_cast<float>(entryZ.GetNumber());

      float worldX = position.x;
      float worldZ = position.z;
      if (relative) {
        worldX = position.x + startingPos.x;
        worldZ = startingPos.z + position.z;
        position.x = worldX;
        position.z = worldZ;
      }

      const float ddx = worldX - targetPos.x;
      const float ddz = worldZ - targetPos.z;
      const float curDist = (ddx * ddx) + (ddz * ddz) + dy2;
      if (closestDist <= curDist) {
        continue;
      }

      const Wm3::Vector3f buildPos(worldX, 0.0f, worldZ);
      if (!aiBrain->CanBuildStructureAt(
            buildPos, structureBp, optIgnoreAlliance, static_cast<int>(worldX), static_cast<int>(worldZ))) {
        continue;
      }

      // Reject positions whose structure skirt overlaps a live resource deposit.
      bool skirtFits = true;
      SCoordsVec2 skirtPos{};
      skirtPos.x = position.x;
      skirtPos.z = position.z;
      const gpg::Rect2f skirt = structureBp->GetSkirtRect(skirtPos);
      for (const ResourceDeposit& deposit : resources->GetDeposits()) {
        const float depX0 = static_cast<float>(deposit.footprintRect.x0);
        const float depZ0 = static_cast<float>(deposit.footprintRect.z0);
        const float depX1 = static_cast<float>(deposit.footprintRect.x1);
        const float depZ1 = static_cast<float>(deposit.footprintRect.z1);
        if (skirt.x1 > depX0 && depX1 > skirt.x0 && skirt.z1 > depZ0 && depZ1 > skirt.z0 && depX1 > depX0 &&
            depZ0 < depZ1 && skirt.x1 > skirt.x0 && skirt.z0 < skirt.z1) {
          skirtFits = false;
          break;
        }
      }

      // Threat gate. (Preserves the binary's double-divide clamp exactly.)
      bool unthreatened = true;
      if (optIgnoreThreatOver > 0) {
        CInfluenceMap* const igrid = mArmy->GetIGrid();
        const int mGridSize = igrid->mGridSize;
        const int gridWidth = igrid->mWidth;
        int xCell = static_cast<int>(worldX) / mGridSize;
        if (xCell / mGridSize >= gridWidth - 1) {
          xCell = gridWidth - 1;
        }
        if (xCell < 0) {
          xCell = 0;
        }
        int zCell = static_cast<int>(worldZ) / mGridSize;
        if (zCell / mGridSize >= igrid->mHeight - 1) {
          zCell = igrid->mHeight - 1;
        }
        if (zCell < 0) {
          zCell = 0;
        }
        const int cellIndex = xCell + zCell * gridWidth;
        const float localThreat = igrid->GetThreatRect(
          cellIndex % igrid->mWidth, cellIndex / igrid->mWidth, 0, true, THREATTYPE_AntiSurface, -1);
        unthreatened = static_cast<float>(optIgnoreThreatOver) > localThreat;
      }

      if (skirtFits && unthreatened) {
        closestPlacement = positionEntry;
        closestDist = curDist;
      }
    }
  }

  if (closestDist >= std::numeric_limits<float>::infinity()) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  closestPlacement.PushStack(state);
  return 1;
}

/**
 * Address: 0x0058A440 (FUN_0058A440, cfunc_CAiBrainFindPlaceToBuild)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to
 * `cfunc_CAiBrainFindPlaceToBuildL`.
 */
int moho::cfunc_CAiBrainFindPlaceToBuild(lua_State* const luaContext)
{
  return cfunc_CAiBrainFindPlaceToBuildL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058A460 (FUN_0058A460, func_CAiBrainFindPlaceToBuild_LuaFuncDef)
 *
 * What it does:
 * Publishes the `brain:FindPlaceToBuild(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainFindPlaceToBuild_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainFindPlaceToBuildName,
    &moho::cfunc_CAiBrainFindPlaceToBuild,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainFindPlaceToBuildHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058ED60 (FUN_0058ED60, cfunc_CAiBrainGetAttackVectors)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetAttackVectorsL`.
 */
int moho::cfunc_CAiBrainGetAttackVectors(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetAttackVectorsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058ED80 (FUN_0058ED80, func_CAiBrainGetAttackVectors_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetAttackVectors()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetAttackVectors_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetAttackVectorsName,
    &moho::cfunc_CAiBrainGetAttackVectors,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetAttackVectorsHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058EDE0 (FUN_0058EDE0, cfunc_CAiBrainGetAttackVectorsL)
 *
 * What it does:
 * Returns one Lua array of `SPointVector` objects built from the brain's
 * current attack-vector debug lanes, or `nil` when none exist.
 */
int moho::cfunc_CAiBrainGetAttackVectorsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetAttackVectorsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);
  if (brain == nullptr || brain->mAttackVectors.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject outVectors;
  outVectors.AssignNewTable(state, static_cast<std::int32_t>(brain->mAttackVectors.size()), 0u);

  std::int32_t luaIndex = 1;
  for (const SAiAttackVectorDebug& attackVector : brain->mAttackVectors) {
    SPointVector pointVector{};
    pointVector.point = attackVector.mOrigin;
    pointVector.vector = attackVector.mDirection;

    const LuaPlus::LuaObject vectorObject = SCR_ToLua<SPointVector>(state, pointVector);
    outVectors.Insert(luaIndex, vectorObject);
    ++luaIndex;
  }

  outVectors.PushStack(state);
  return 1;
}

/**
 * Address: 0x0058F390 (FUN_0058F390, func_CAiBrainGetEconomyStored_LuaFuncDef)
 * Alias export: 0x0058F3A0 (FUN_0058F3A0)
 *
 * What it does:
 * Publishes the `CAiBrain:GetEconomyStored()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetEconomyStored_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetEconomyStoredName,
    &moho::cfunc_CAiBrainGetEconomyStored,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetEconomyStoredHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058F370 (FUN_0058F370, cfunc_CAiBrainGetEconomyStored)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetEconomyStoredL`.
 */
int moho::cfunc_CAiBrainGetEconomyStored(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetEconomyStoredL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058F3F0 (FUN_0058F3F0, cfunc_CAiBrainGetEconomyStoredL)
 *
 * What it does:
 * Returns the stored economy amount (`ENERGY` or `MASS`) selected by
 * `resourceType`.
 */
int moho::cfunc_CAiBrainGetEconomyStoredL(LuaPlus::LuaState* const state)
{
  EEconResource resource = ECON_ENERGY;
  CAiBrain* const brain = DecodeEconomyResourceQueryArgs(state, kAiBrainGetEconomyStoredHelpText, resource);

  float value = 0.0f;
  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  if (economyInfo != nullptr) {
    value = SelectResourceLane(economyInfo->economy.mStored, resource);
  }

  lua_State* const rawState = state->m_state;
  lua_pushnumber(rawState, value);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058F750 (FUN_0058F750, func_CAiBrainGetEconomyIncome_LuaFuncDef)
 * Alias export: 0x0058F760 (FUN_0058F760)
 *
 * What it does:
 * Publishes the `CAiBrain:GetEconomyIncome()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetEconomyIncome_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetEconomyIncomeName,
    &moho::cfunc_CAiBrainGetEconomyIncome,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetEconomyIncomeHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058F730 (FUN_0058F730, cfunc_CAiBrainGetEconomyIncome)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetEconomyIncomeL`.
 */
int moho::cfunc_CAiBrainGetEconomyIncome(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetEconomyIncomeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058F7B0 (FUN_0058F7B0, cfunc_CAiBrainGetEconomyIncomeL)
 *
 * What it does:
 * Returns the current economy income amount (`ENERGY` or `MASS`) selected by
 * `resourceType`.
 */
int moho::cfunc_CAiBrainGetEconomyIncomeL(LuaPlus::LuaState* const state)
{
  EEconResource resource = ECON_ENERGY;
  CAiBrain* const brain = DecodeEconomyResourceQueryArgs(state, kAiBrainGetEconomyIncomeHelpText, resource);

  float value = 0.0f;
  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  if (economyInfo != nullptr) {
    value = SelectResourceLane(economyInfo->economy.mIncome, resource);
  }

  lua_State* const rawState = state->m_state;
  lua_pushnumber(rawState, value);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058F910 (FUN_0058F910, func_CAiBrainGetEconomyUsage_LuaFuncDef)
 * Alias export: 0x0058F920 (FUN_0058F920)
 *
 * What it does:
 * Publishes the `CAiBrain:GetEconomyUsage()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetEconomyUsage_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetEconomyUsageName,
    &moho::cfunc_CAiBrainGetEconomyUsage,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetEconomyUsageHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058F8F0 (FUN_0058F8F0, cfunc_CAiBrainGetEconomyUsage)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetEconomyUsageL`.
 */
int moho::cfunc_CAiBrainGetEconomyUsage(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetEconomyUsageL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058F970 (FUN_0058F970, cfunc_CAiBrainGetEconomyUsageL)
 *
 * What it does:
 * Returns last-actual economy usage (`ENERGY` or `MASS`) for `resourceType`.
 */
int moho::cfunc_CAiBrainGetEconomyUsageL(LuaPlus::LuaState* const state)
{
  EEconResource resource = ECON_ENERGY;
  CAiBrain* const brain = DecodeEconomyResourceQueryArgs(state, kAiBrainGetEconomyUsageHelpText, resource);

  float value = 0.0f;
  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  if (economyInfo != nullptr) {
    value = SelectResourceLane(economyInfo->economy.mLastUseActual, resource);
  }

  lua_State* const rawState = state->m_state;
  lua_pushnumber(rawState, value);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058FAD0 (FUN_0058FAD0, func_CAiBrainGetEconomyRequested_LuaFuncDef)
 * Alias export: 0x0058FAE0 (FUN_0058FAE0)
 *
 * What it does:
 * Publishes the `CAiBrain:GetEconomyRequested()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetEconomyRequested_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetEconomyRequestedName,
    &moho::cfunc_CAiBrainGetEconomyRequested,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetEconomyRequestedHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058FAB0 (FUN_0058FAB0, cfunc_CAiBrainGetEconomyRequested)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetEconomyRequestedL`.
 */
int moho::cfunc_CAiBrainGetEconomyRequested(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetEconomyRequestedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058FB30 (FUN_0058FB30, cfunc_CAiBrainGetEconomyRequestedL)
 *
 * What it does:
 * Returns last-requested economy amount (`ENERGY` or `MASS`) for
 * `resourceType`.
 */
int moho::cfunc_CAiBrainGetEconomyRequestedL(LuaPlus::LuaState* const state)
{
  EEconResource resource = ECON_ENERGY;
  CAiBrain* const brain = DecodeEconomyResourceQueryArgs(state, kAiBrainGetEconomyRequestedHelpText, resource);

  float value = 0.0f;
  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  if (economyInfo != nullptr) {
    value = SelectResourceLane(economyInfo->economy.mLastUseRequested, resource);
  }

  lua_State* const rawState = state->m_state;
  lua_pushnumber(rawState, value);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058FC90 (FUN_0058FC90, func_CAiBrainGetEconomyTrend_LuaFuncDef)
 * Alias export: 0x0058FCA0 (FUN_0058FCA0)
 *
 * What it does:
 * Publishes the `CAiBrain:GetEconomyTrend()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetEconomyTrend_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetEconomyTrendName,
    &moho::cfunc_CAiBrainGetEconomyTrend,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetEconomyTrendHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058FC70 (FUN_0058FC70, cfunc_CAiBrainGetEconomyTrend)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetEconomyTrendL`.
 */
int moho::cfunc_CAiBrainGetEconomyTrend(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetEconomyTrendL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058FCF0 (FUN_0058FCF0, cfunc_CAiBrainGetEconomyTrendL)
 *
 * What it does:
 * Returns `(income - lastActualUse)` for the selected economy resource lane.
 */
int moho::cfunc_CAiBrainGetEconomyTrendL(LuaPlus::LuaState* const state)
{
  EEconResource resource = ECON_ENERGY;
  CAiBrain* const brain = DecodeEconomyResourceQueryArgs(state, kAiBrainGetEconomyTrendHelpText, resource);

  float trend = 0.0f;
  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  if (economyInfo != nullptr) {
    trend = SelectResourceLane(economyInfo->economy.mIncome, resource)
          - SelectResourceLane(economyInfo->economy.mLastUseActual, resource);
  }

  lua_State* const rawState = state->m_state;
  lua_pushnumber(rawState, trend);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058FE30 (FUN_0058FE30, cfunc_CAiBrainGetMapWaterRatio)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetMapWaterRatioL`.
 */
int moho::cfunc_CAiBrainGetMapWaterRatio(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetMapWaterRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058FE50 (FUN_0058FE50, func_CAiBrainGetMapWaterRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetMapWaterRatio()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetMapWaterRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetMapWaterRatioName,
    &moho::cfunc_CAiBrainGetMapWaterRatio,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetMapWaterRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058FEB0 (FUN_0058FEB0, cfunc_CAiBrainGetMapWaterRatioL)
 *
 * What it does:
 * Samples the current sim map and returns the share of sampled points that
 * are underwater according to map water elevation.
 */
int moho::cfunc_CAiBrainGetMapWaterRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetMapWaterRatioHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const STIMap* const map = (brain != nullptr && brain->mSim != nullptr) ? brain->mSim->mMapData : nullptr;
  const float mapWaterRatio = (map != nullptr) ? CalculateMapWaterRatio(*map) : 0.0f;
  lua_pushnumber(rawState, mapWaterRatio);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058F530 (FUN_0058F530, cfunc_CAiBrainGetEconomyStoredRatio)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetEconomyStoredRatioL`.
 */
int moho::cfunc_CAiBrainGetEconomyStoredRatio(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetEconomyStoredRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058F550 (FUN_0058F550, func_CAiBrainGetEconomyStoredRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetEconomyStoredRatio(resourceType)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetEconomyStoredRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetEconomyStoredRatioName,
    &moho::cfunc_CAiBrainGetEconomyStoredRatio,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetEconomyStoredRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058F5B0 (FUN_0058F5B0, cfunc_CAiBrainGetEconomyStoredRatioL)
 *
 * What it does:
 * Reads `(brain, resourceType)`, resolves one economy resource enum, and
 * returns `stored/maxStorage` for the selected lane (or `0` when unavailable).
 */
int moho::cfunc_CAiBrainGetEconomyStoredRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetEconomyStoredRatioHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  EEconResource resource = ECON_ENERGY;
  gpg::RRef enumRef = MakeEconResourceRef(&resource);
  const LuaPlus::LuaStackObject resourceTypeArg(state, 2);
  const char* const resourceTypeName = lua_tostring(rawState, 2);
  if (resourceTypeName == nullptr) {
    resourceTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, resourceTypeName, enumRef);

  float ratio = 0.0f;
  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  if (economyInfo != nullptr) {
    const double maxStorage = static_cast<double>(SelectResourceLane(economyInfo->economy.mMaxStorage, resource));
    if (maxStorage > 0.0) {
      ratio = static_cast<float>(static_cast<double>(SelectResourceLane(economyInfo->economy.mStored, resource)) / maxStorage);
    }
  }

  lua_pushnumber(rawState, ratio);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005881F0 (FUN_005881F0, cfunc_CAiBrainGiveResource)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGiveResourceL`.
 */
int moho::cfunc_CAiBrainGiveResource(lua_State* const luaContext)
{
  return cfunc_CAiBrainGiveResourceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588210 (FUN_00588210, func_CAiBrainGiveResource_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GiveResource(type,amount)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGiveResource_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGiveResourceName,
    &moho::cfunc_CAiBrainGiveResource,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGiveResourceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00588270 (FUN_00588270, cfunc_CAiBrainGiveResourceL)
 *
 * What it does:
 * Reads `(brain, resourceType, amount)` and adds `amount` into the selected
 * stored economy-resource lane.
 */
int moho::cfunc_CAiBrainGiveResourceL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGiveResourceHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  EEconResource resource = ECON_ENERGY;
  gpg::RRef enumRef = MakeEconResourceRef(&resource);
  const LuaPlus::LuaStackObject resourceTypeArg(state, 2);
  const char* const resourceTypeName = lua_tostring(rawState, 2);
  if (resourceTypeName == nullptr) {
    resourceTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, resourceTypeName, enumRef);

  const LuaPlus::LuaStackObject amountArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    amountArg.TypeError("number");
  }
  const float amount = static_cast<float>(lua_tonumber(rawState, 3));

  SEconPair valueToAdd{0.0f, 0.0f};
  SelectResourceLane(valueToAdd, resource) = amount;

  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  SEconPair& stored = economyInfo->economy.mStored;
  stored.ENERGY += valueToAdd.ENERGY;
  stored.MASS += valueToAdd.MASS;
  return 0;
}

/**
 * Address: 0x005883E0 (FUN_005883E0, cfunc_CAiBrainGiveStorage)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGiveStorageL`.
 */
int moho::cfunc_CAiBrainGiveStorage(lua_State* const luaContext)
{
  return cfunc_CAiBrainGiveStorageL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588400 (FUN_00588400, func_CAiBrainGiveStorage_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GiveStorage(type,amount)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGiveStorage_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGiveStorageName,
    &moho::cfunc_CAiBrainGiveStorage,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGiveStorageHelpText
  );
  return &binder;
}

/**
 * Address: 0x00588460 (FUN_00588460, cfunc_CAiBrainGiveStorageL)
 *
 * What it does:
 * Replaces one economy extra-storage lane (`ENERGY` or `MASS`) with `amount`
 * after decoding `(brain, resourceType, amount)` from Lua.
 */
int moho::cfunc_CAiBrainGiveStorageL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGiveStorageHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  EEconResource resource = ECON_ENERGY;
  gpg::RRef enumRef = MakeEconResourceRef(&resource);
  const LuaPlus::LuaStackObject resourceTypeArg(state, 2);
  const char* const resourceTypeName = lua_tostring(rawState, 2);
  if (resourceTypeName == nullptr) {
    resourceTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, resourceTypeName, enumRef);

  const LuaPlus::LuaStackObject amountArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    amountArg.TypeError("number");
  }
  const float amount = static_cast<float>(lua_tonumber(rawState, 3));

  SEconPair newStorage{0.0f, 0.0f};
  SelectResourceLane(newStorage, resource) = amount;

  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  auto* const extraStorage = reinterpret_cast<CEconStorageRuntimeView*>(economyInfo->storageDelta);
  ApplyEconStorageDelta(*extraStorage, -1);
  extraStorage->amounts[0] = newStorage.ENERGY;
  extraStorage->amounts[1] = newStorage.MASS;
  ApplyEconStorageDelta(*extraStorage, 1);
  return 0;
}

/**
 * Address: 0x005885E0 (FUN_005885E0, cfunc_CAiBrainTakeResource)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainTakeResourceL`.
 */
int moho::cfunc_CAiBrainTakeResource(lua_State* const luaContext)
{
  return cfunc_CAiBrainTakeResourceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588600 (FUN_00588600, func_CAiBrainTakeResource_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:TakeResource(type,amount)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainTakeResource_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainTakeResourceName,
    &moho::cfunc_CAiBrainTakeResource,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainTakeResourceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00588660 (FUN_00588660, cfunc_CAiBrainTakeResourceL)
 *
 * What it does:
 * Reads `(brain, resourceType, amount)`, removes up to `amount` from the
 * selected stored resource, and returns the actual amount removed.
 */
int moho::cfunc_CAiBrainTakeResourceL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainTakeResourceHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  EEconResource resource = ECON_ENERGY;
  gpg::RRef enumRef = MakeEconResourceRef(&resource);
  const LuaPlus::LuaStackObject resourceTypeArg(state, 2);
  const char* const resourceTypeName = lua_tostring(rawState, 2);
  if (resourceTypeName == nullptr) {
    resourceTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, resourceTypeName, enumRef);

  const LuaPlus::LuaStackObject amountArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    amountArg.TypeError("number");
  }
  const float amount = static_cast<float>(lua_tonumber(rawState, 3));

  SEconPair request{0.0f, 0.0f};
  SelectResourceLane(request, resource) = amount;

  CSimArmyEconomyInfo* const economyInfo = brain->mArmy->GetEconomy();
  SEconPair& stored = economyInfo->economy.mStored;

  SEconPair taken{
    request.ENERGY <= stored.ENERGY ? request.ENERGY : stored.ENERGY,
    request.MASS <= stored.MASS ? request.MASS : stored.MASS,
  };

  const float updatedEnergy = stored.ENERGY - taken.ENERGY;
  const float updatedMass = stored.MASS - taken.MASS;
  stored.ENERGY = updatedEnergy > 0.0f ? updatedEnergy : 0.0f;
  stored.MASS = updatedMass > 0.0f ? updatedMass : 0.0f;

  lua_pushnumber(rawState, SelectResourceLane(taken, resource));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005889A0 (FUN_005889A0, cfunc_CAiBrainFindUnit)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainFindUnitL`.
 */
int moho::cfunc_CAiBrainFindUnit(lua_State* const luaContext)
{
  return cfunc_CAiBrainFindUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588A20 (FUN_00588A20, cfunc_CAiBrainFindUnitL)
 *
 * What it does:
 * Returns the first live army unit matching the category filter in arg #2,
 * optionally requiring idle-state when arg #3 is true.
 */
int moho::cfunc_CAiBrainFindUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainFindUnitHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  const bool needToBeIdle = LuaPlus::LuaStackObject(state, 3).GetBoolean();

  SEntitySetTemplateUnit categoryUnits{};
  brain->mArmy->GetUnits(&categoryUnits, categorySet);

  for (Entity* const* it = categoryUnits.mVec.begin(); it != categoryUnits.mVec.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (unit == nullptr) {
      continue;
    }

    if (unit->IsDead() || unit->DestroyQueued() || unit->IsBeingBuilt()) {
      continue;
    }

    if (needToBeIdle && UnitHasHeadCommand(unit)) {
      continue;
    }

    unit->GetLuaObject().PushStack(state);
    return 1;
  }

  lua_pushnil(rawState);
  return 1;
}

/**
 * Address: 0x005889C0 (FUN_005889C0, func_CAiBrainFindUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:FindUnit(unitCategory, needToBeIdle)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainFindUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainFindUnitName,
    &moho::cfunc_CAiBrainFindUnit,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainFindUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x00588C10 (FUN_00588C10, cfunc_CAiBrainFindUpgradeBP)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainFindUpgradeBPL`.
 */
int moho::cfunc_CAiBrainFindUpgradeBP(lua_State* const luaContext)
{
  return cfunc_CAiBrainFindUpgradeBPL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588C30 (FUN_00588C30, func_CAiBrainFindUpgradeBP_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:FindUpgradeBP(unitName, upgradeList)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainFindUpgradeBP_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainFindUpgradeBPName,
    &moho::cfunc_CAiBrainFindUpgradeBP,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainFindUpgradeBPHelpText
  );
  return &binder;
}

/**
 * Address: 0x00588C90 (FUN_00588C90, cfunc_CAiBrainFindUpgradeBPL)
 *
 * What it does:
 * Scans one upgrade candidate table and returns the first `toBlueprintId`
 * whose `fromBlueprintId` matches the requested `unitName` (case-insensitive).
 */
int moho::cfunc_CAiBrainFindUpgradeBPL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainFindUpgradeBPHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  (void)SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaStackObject unitNameArg(state, 2);
  const char* const requestedUnitName = lua_tostring(rawState, 2);
  if (requestedUnitName == nullptr) {
    unitNameArg.TypeError("string");
  }

  const LuaPlus::LuaObject upgradeList(LuaPlus::LuaStackObject(state, 3));
  const int candidateCount = upgradeList.GetCount();
  for (int index = 1; index <= candidateCount; ++index) {
    const LuaPlus::LuaObject candidate(upgradeList[index]);
    if (!candidate.IsTable()) {
      continue;
    }

    const LuaPlus::LuaObject fromBlueprintId(candidate[1]);
    if (_stricmp(requestedUnitName, fromBlueprintId.GetString()) == 0) {
      const LuaPlus::LuaObject toBlueprintId(candidate[2]);
      lua_pushstring(rawState, toBlueprintId.GetString());
      (void)lua_gettop(rawState);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00588EB0 (FUN_00588EB0, cfunc_CAiBrainFindUnitToUpgrade)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainFindUnitToUpgradeL`.
 */
int moho::cfunc_CAiBrainFindUnitToUpgrade(lua_State* const luaContext)
{
  return cfunc_CAiBrainFindUnitToUpgradeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00588F30 (FUN_00588F30, cfunc_CAiBrainFindUnitToUpgradeL)
 *
 * What it does:
 * Scans candidate `(fromBlueprintId, toBlueprintId)` upgrade pairs and returns
 * the first idle army unit matching `fromBlueprintId` plus `toBlueprintId`.
 */
int moho::cfunc_CAiBrainFindUnitToUpgradeL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainFindUnitToUpgradeHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject upgradeListObject(LuaPlus::LuaStackObject(state, 2));
  if (brain != nullptr && brain->mSim != nullptr && brain->mSim->mRules != nullptr && upgradeListObject.IsTable()) {
    const int pairCount = upgradeListObject.GetCount();
    for (int pairIndex = 1; pairIndex <= pairCount; ++pairIndex) {
      LuaPlus::LuaObject upgradePair = upgradeListObject[pairIndex];
      if (!upgradePair.IsTable()) {
        continue;
      }

      const char* const fromBlueprintId = upgradePair[1].GetString();
      const char* const toBlueprintId = upgradePair[2].GetString();
      if (fromBlueprintId == nullptr || toBlueprintId == nullptr) {
        continue;
      }

      RResId fromId{};
      gpg::STR_InitFilename(&fromId.name, fromBlueprintId);
      RResId toId{};
      gpg::STR_InitFilename(&toId.name, toBlueprintId);

      const RUnitBlueprint* const fromBlueprint = brain->mSim->mRules->GetUnitBlueprint(fromId);
      const RUnitBlueprint* const toBlueprint = brain->mSim->mRules->GetUnitBlueprint(toId);
      if (fromBlueprint == nullptr || toBlueprint == nullptr) {
        continue;
      }

      Unit* const candidateUnit = FindUpgradeableArmyUnitByBlueprint(brain, fromBlueprint);
      if (candidateUnit == nullptr) {
        continue;
      }

      candidateUnit->GetLuaObject().PushStack(state);
      lua_pushstring(rawState, toBlueprint->mBlueprintId.c_str());
      return 2;
    }
  }

  lua_pushnil(rawState);
  lua_pushnil(rawState);
  return 2;
}

/**
 * Address: 0x00588ED0 (FUN_00588ED0, func_CAiBrainFindUnitToUpgrade_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:FindUnitToUpgrade(upgradeList)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainFindUnitToUpgrade_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainFindUnitToUpgradeName,
    &moho::cfunc_CAiBrainFindUnitToUpgrade,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainFindUnitToUpgradeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00589380 (FUN_00589380, cfunc_CAiBrainDecideWhatToBuild)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainDecideWhatToBuildL`.
 */
int moho::cfunc_CAiBrainDecideWhatToBuild(lua_State* const luaContext)
{
  return cfunc_CAiBrainDecideWhatToBuildL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00589400 (FUN_00589400, cfunc_CAiBrainDecideWhatToBuildL)
 *
 * What it does:
 * Selects and returns the first buildable blueprint id from a typed
 * candidate table (`buildingTypes`) for the requested builder/type pair.
 */
int moho::cfunc_CAiBrainDecideWhatToBuildL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainDecideWhatToBuildHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject builderObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const builder = SCR_FromLua_Unit(builderObject);

  const LuaPlus::LuaStackObject typeArgument(state, 3);
  const char* const requestedType = lua_tostring(rawState, 3);
  if (requestedType == nullptr) {
    typeArgument.TypeError("string");
  }

  const LuaPlus::LuaObject typedCandidates(LuaPlus::LuaStackObject(state, 4));
  if (typedCandidates.IsTable()) {
    const int groupCount = typedCandidates.GetCount();
    for (int groupIndex = 1; groupIndex <= groupCount; ++groupIndex) {
      LuaPlus::LuaObject typeGroup = typedCandidates[groupIndex];
      const char* const groupType = typeGroup[1].GetString();
      if (_stricmp(groupType, requestedType) != 0) {
        continue;
      }

      const int candidateCount = typeGroup.GetCount();
      for (int candidateIndex = 2; candidateIndex <= candidateCount; ++candidateIndex) {
        LuaPlus::LuaObject blueprintToken = typeGroup[candidateIndex];
        if (CAiBrain::CanBuildUnit(blueprintToken.GetString(), brain, builder)) {
          blueprintToken.PushStack(state);
          return 1;
        }
      }
    }
  }

  lua_pushnil(rawState);
  return 1;
}

/**
 * Address: 0x005893A0 (FUN_005893A0, func_CAiBrainDecideWhatToBuild_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:DecideWhatToBuild(builder, type, buildingTypes)`
 * Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainDecideWhatToBuild_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainDecideWhatToBuildName,
    &moho::cfunc_CAiBrainDecideWhatToBuild,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainDecideWhatToBuildHelpText
  );
  return &binder;
}

/**
 * Address: 0x0057CA20 (FUN_0057CA20, func_ScheduleBuildStructure)
 *
 * What it does:
 * Stages one temporary weak `(builder, command)` reservation pair, ensures
 * one reservation entry exists at `where`, rebases both intrusive weak-link
 * lanes into that map entry, then unlinks the temporary staging lanes.
 */
void moho::func_ScheduleBuildStructure(
  Unit* const builder,
  CAiBrain* const brain,
  CUnitCommand* const command,
  const Wm3::Vector2i where
)
{
  SBuildResourceInfo pendingReservation{};
  reinterpret_cast<WeakPtr<Unit>&>(pendingReservation.mPlacementLink).Set(builder);
  reinterpret_cast<WeakPtr<CUnitCommand>&>(pendingReservation.mResourceLink).Set(command);

  auto& reserveMap = reinterpret_cast<BuildReserveMapStorage&>(brain->mBuildStructureMap);
  SBuildReserveInfo& reserveEntry = reserveMap[where];
  auto& reserveEntryLinks = reinterpret_cast<SBuildResourceInfo&>(reserveEntry);

  RebindBuildResourceInfoLinks(reserveEntryLinks, pendingReservation);

  // Binary cleanup order: command lane first, then unit lane.
  UnlinkBuildResourceInfoLink(pendingReservation.mResourceLink);
  UnlinkBuildResourceInfoLink(pendingReservation.mPlacementLink);
}

/**
 * Address: 0x0058B610 (FUN_0058B610, cfunc_CAiBrainBuildStructure)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainBuildStructureL`.
 */
int moho::cfunc_CAiBrainBuildStructure(lua_State* const luaContext)
{
  return cfunc_CAiBrainBuildStructureL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058BCB0 (FUN_0058BCB0, cfunc_CAiBrainGetAvailableFactories)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetAvailableFactoriesL`.
 */
int moho::cfunc_CAiBrainGetAvailableFactories(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetAvailableFactoriesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058BD30 (FUN_0058BD30, cfunc_CAiBrainGetAvailableFactoriesL)
 *
 * IDA signature:
 * int __usercall cfunc_CAiBrainGetAvailableFactoriesL@<eax>(LuaPlus::LuaState *ebx0@<ebx>);
 *
 * What it does:
 * Reads `(brain[, referencePosition, maxDistance])` from the Lua stack,
 * builds an empty `SEntitySetTemplateUnit`, calls
 * `CAiBrain::GetAvailableFactories(set, &position, distance)` to populate
 * it with live non-busy factory units, then fills a Lua table from the
 * collected entities and pushes it on the stack.
 *
 * Argument count is validated to be 1..3. When only the brain is
 * supplied the position lane is left zero-initialized and the distance
 * is `0.0f`, matching the binary's stack-local pre-zero pass.
 */
int moho::cfunc_CAiBrainGetAvailableFactoriesL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 3) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainGetAvailableFactoriesHelpText,
      1,
      3,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  Wm3::Vector3f referencePosition{};
  float maxDistance = 0.0f;
  if (argumentCount > 2) {
    const LuaPlus::LuaObject referenceObject(LuaPlus::LuaStackObject(state, 2));
    referencePosition = SCR_FromLuaCopy<Wm3::Vector3<float>>(referenceObject);
    LuaPlus::LuaStackObject distanceStackObject(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      distanceStackObject.TypeError("number");
    }
    maxDistance = static_cast<float>(lua_tonumber(rawState, 3));
  }

  SEntitySetTemplateUnit availableFactories{};
  brain->GetAvailableFactories(&availableFactories, &referencePosition, maxDistance);

  LuaPlus::LuaObject resultTable;
  FillLuaTableWithEntities(availableFactories, &resultTable, state);
  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0058BCD0 (FUN_0058BCD0, func_CAiBrainGetAvailableFactories_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetAvailableFactories([referencePosition[, maxDistance]])`
 * Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetAvailableFactories_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetAvailableFactoriesName,
    &moho::cfunc_CAiBrainGetAvailableFactories,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetAvailableFactoriesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00590280 (FUN_00590280, cfunc_CAiBrainGetThreatAtPosition)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetThreatAtPositionL`.
 */
int moho::cfunc_CAiBrainGetThreatAtPosition(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetThreatAtPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005902E0 (FUN_005902E0, cfunc_CAiBrainGetThreatAtPositionL)
 *
 * IDA signature:
 * int __usercall cfunc_CAiBrainGetThreatAtPositionL@<eax>(LuaPlus::LuaState *ebx0@<ebx>);
 *
 * What it does:
 * Reads `(brain, position, ringRadius, restrictToOnMap[, threatTypeName,
 * armyIndex])` from the Lua stack, samples the army influence map at
 * `position`, and pushes the rectangle-aggregated threat value back on
 * the stack.
 *
 * Argument count is validated to be 4..6. The optional fifth arg is a
 * threat-type enum name resolved via `SCR_GetEnum`; the optional sixth
 * arg is a 1-based army index validated against `mSim->mArmiesList`.
 * The position is converted to cell coordinates via
 * `CInfluenceMap::VectorToCoords`, then aggregated through
 * `CInfluenceMap::GetThreatRect`.
 */
int moho::cfunc_CAiBrainGetThreatAtPositionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 4 || argumentCount > 6) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainGetThreatAtPositionHelpText,
      4,
      6,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);

  LuaPlus::LuaStackObject ringStackObject(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    ringStackObject.TypeError("integer");
  }
  const int ringRadius = static_cast<int>(lua_tonumber(rawState, 3));

  LuaPlus::LuaStackObject restrictionStackObject(state, 4);
  const bool restrictToOnMap = restrictionStackObject.GetBoolean();

  EThreatType threatType = THREATTYPE_Overall;
  int armyIndex = -1;

  if (argumentCount > 4) {
    gpg::RRef threatRef{};
    gpg::RRef_EThreatType(&threatRef, &threatType);
    LuaPlus::LuaStackObject threatNameStackObject(state, 5);
    const char* const threatName = lua_tostring(rawState, 5);
    if (threatName == nullptr) {
      threatNameStackObject.TypeError("string");
    }
    SCR_GetEnum(state, threatName, threatRef);
  }

  if (argumentCount > 5) {
    LuaPlus::LuaStackObject armyStackObject(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      armyStackObject.TypeError("integer");
    }
    const int oneBasedArmyIndex = static_cast<int>(lua_tonumber(rawState, 6));
    armyIndex = oneBasedArmyIndex - 1;
    const int armyCount = static_cast<int>(brain->mSim->mArmiesList.size());
    if (armyIndex < 0 || armyIndex >= armyCount) {
      LuaPlus::LuaState::Error(state, kAiBrainGetThreatAtPositionInvalidArmyError);
    }
  }

  CInfluenceMap* const influenceGrid = brain->mArmy->GetIGrid();
  const std::int32_t cellIndex = influenceGrid->VectorToCoords(position);
  const std::int32_t cellX = cellIndex % influenceGrid->mWidth;
  const std::int32_t cellZ = cellIndex / influenceGrid->mWidth;

  const float threatValue =
    influenceGrid->GetThreatRect(cellX, cellZ, ringRadius, restrictToOnMap, threatType, armyIndex);

  lua_pushnumber(rawState, threatValue);
  return 1;
}

/**
 * Address: 0x00590300 (FUN_00590300, func_CAiBrainGetThreatAtPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetThreatAtPosition(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetThreatAtPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetThreatAtPositionName,
    &moho::cfunc_CAiBrainGetThreatAtPosition,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetThreatAtPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x005905D0 (FUN_005905D0, cfunc_CAiBrainGetThreatBetweenPositions)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetThreatBetweenPositionsL`.
 */
int moho::cfunc_CAiBrainGetThreatBetweenPositions(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetThreatBetweenPositionsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00590630 (FUN_00590630, cfunc_CAiBrainGetThreatBetweenPositionsL)
 *
 * IDA signature:
 * int __usercall cfunc_CAiBrainGetThreatBetweenPositionsL@<eax>(LuaPlus::LuaState *ebx0@<ebx>);
 *
 * What it does:
 * Reads `(brain, positionA, positionB, useRingMode[, threatTypeName,
 * armyIndex])` from the Lua stack, samples a grid-aligned threat
 * traversal between the two world positions through
 * `CInfluenceMap::GetThreatBetweenPositions`, and pushes the
 * aggregated value back on the Lua stack.
 *
 * Argument count is validated to be 4..6. Threat type defaults to
 * `THREATTYPE_Overall`; army index defaults to `-1` (any). The
 * optional 1-based army index is validated against
 * `mSim->mArmiesList`.
 */
int moho::cfunc_CAiBrainGetThreatBetweenPositionsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 4 || argumentCount > 6) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainGetThreatBetweenPositionsHelpText,
      4,
      6,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject positionAObject(LuaPlus::LuaStackObject(state, 2));
  Wm3::Vector3f positionA{};
  positionA = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionAObject);

  const LuaPlus::LuaObject positionBObject(LuaPlus::LuaStackObject(state, 3));
  Wm3::Vector3f positionB{};
  positionB = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionBObject);

  LuaPlus::LuaStackObject ringStackObject(state, 4);
  const bool useRingMode = ringStackObject.GetBoolean();

  EThreatType threatType = THREATTYPE_Overall;
  int armyIndex = -1;

  if (argumentCount > 4) {
    gpg::RRef threatRef{};
    gpg::RRef_EThreatType(&threatRef, &threatType);
    LuaPlus::LuaStackObject threatNameStackObject(state, 5);
    const char* const threatName = lua_tostring(rawState, 5);
    if (threatName == nullptr) {
      threatNameStackObject.TypeError("string");
    }
    SCR_GetEnum(state, threatName, threatRef);
  }

  if (argumentCount > 5) {
    LuaPlus::LuaStackObject armyStackObject(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      armyStackObject.TypeError("integer");
    }
    const int oneBasedArmyIndex = static_cast<int>(lua_tonumber(rawState, 6));
    armyIndex = oneBasedArmyIndex - 1;
    const int armyCount = static_cast<int>(brain->mSim->mArmiesList.size());
    if (armyIndex < 0 || armyIndex >= armyCount) {
      LuaPlus::LuaState::Error(state, kAiBrainGetThreatBetweenPositionsInvalidArmyError);
    }
  }

  CInfluenceMap* const influenceGrid = brain->mArmy->GetIGrid();
  const float threatValue =
    influenceGrid->GetThreatBetweenPositions(positionA, positionB, useRingMode, threatType, armyIndex);

  lua_pushnumber(rawState, threatValue);
  return 1;
}

/**
 * Address: 0x005905F0 (FUN_005905F0, func_CAiBrainGetThreatBetweenPositions_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetThreatBetweenPositions(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetThreatBetweenPositions_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetThreatBetweenPositionsName,
    &moho::cfunc_CAiBrainGetThreatBetweenPositions,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetThreatBetweenPositionsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00590C00 (FUN_00590C00, cfunc_CAiBrainGetThreatsAroundPosition)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetThreatsAroundPositionL`.
 */
int moho::cfunc_CAiBrainGetThreatsAroundPosition(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetThreatsAroundPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00590C20 (FUN_00590C20, func_CAiBrainGetThreatsAroundPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetThreatsAroundPosition(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetThreatsAroundPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetThreatsAroundPositionName,
    &moho::cfunc_CAiBrainGetThreatsAroundPosition,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetThreatsAroundPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x00590C80 (FUN_00590C80, cfunc_CAiBrainGetThreatsAroundPositionL)
 *
 * IDA signature:
 * int __usercall cfunc_CAiBrainGetThreatsAroundPositionL@<eax>(LuaPlus::LuaState *ebx0@<ebx>);
 *
 * What it does:
 * Reads `(brain, position, ring, restriction[, threatTypeName, armyIndex])`
 * from the Lua stack, gathers every positive-threat cell around `position`
 * into a `msvc8::vector<SPositionThreat>` via
 * `CInfluenceMap::GetThreatsAroundPosition`, then builds and pushes a Lua array
 * whose rows are `{ [1]=x, [2]=z, [3]=threat }`.
 *
 * Argument count is validated to be 4..6. The optional fifth arg is a
 * threat-type enum name resolved via `SCR_GetEnum`; the optional sixth arg is
 * a 1-based army index validated against `mSim->mArmiesList`.
 */
int moho::cfunc_CAiBrainGetThreatsAroundPositionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 4 || argumentCount > 6) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainGetThreatsAroundPositionHelpText,
      4,
      6,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);

  LuaPlus::LuaStackObject ringStackObject(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    ringStackObject.TypeError("integer");
  }
  const int ring = static_cast<int>(lua_tonumber(rawState, 3));

  LuaPlus::LuaStackObject restrictionStackObject(state, 4);
  const bool restrictToPlayable = restrictionStackObject.GetBoolean();

  EThreatType threatType = THREATTYPE_Overall;
  int armyIndex = -1;

  if (argumentCount > 4) {
    gpg::RRef threatRef{};
    gpg::RRef_EThreatType(&threatRef, &threatType);
    LuaPlus::LuaStackObject threatNameStackObject(state, 5);
    const char* const threatName = lua_tostring(rawState, 5);
    if (threatName == nullptr) {
      threatNameStackObject.TypeError("string");
    }
    SCR_GetEnum(state, threatName, threatRef);
  }

  if (argumentCount > 5) {
    LuaPlus::LuaStackObject armyStackObject(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      armyStackObject.TypeError("integer");
    }
    const int oneBasedArmyIndex = static_cast<int>(lua_tonumber(rawState, 6));
    armyIndex = oneBasedArmyIndex - 1;
    const int armyCount = static_cast<int>(brain->mSim->mArmiesList.size());
    if (armyIndex < 0 || armyIndex >= armyCount) {
      LuaPlus::LuaState::Error(state, kAiBrainGetThreatsAroundPositionInvalidArmyError);
    }
  }

  msvc8::vector<SPositionThreat> threats;
  CInfluenceMap* const influenceGrid = brain->mArmy->GetIGrid();
  influenceGrid->GetThreatsAroundPosition(threats, position, ring, restrictToPlayable, threatType, armyIndex);

  LuaPlus::LuaObject threatsTable;
  threatsTable.AssignNewTable(state, static_cast<std::int32_t>(threats.size()), 0);
  for (const SPositionThreat& sample : threats) {
    LuaPlus::LuaObject row;
    row.AssignNewTable(state, 3, 0);
    row.SetNumber(1, sample.x);
    row.SetNumber(2, sample.z);
    row.SetNumber(3, sample.threat);
    threatsTable.Insert(row);
  }

  threatsTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0058EF60 (FUN_0058EF60, cfunc_CAiBrainPickBestAttackVector)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainPickBestAttackVectorL`.
 */
int moho::cfunc_CAiBrainPickBestAttackVector(lua_State* const luaContext)
{
  return cfunc_CAiBrainPickBestAttackVectorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058EF80 (FUN_0058EF80, func_CAiBrainPickBestAttackVector_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:PickBestAttackVector(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainPickBestAttackVector_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainPickBestAttackVectorName,
    &moho::cfunc_CAiBrainPickBestAttackVector,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainPickBestAttackVectorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0057CBB0 (FUN_0057CBB0, Moho::CAiBrain::CanBuildStructureAt)
 *
 * IDA signature:
 * bool __thiscall CAiBrain::CanBuildStructureAt(CAiBrain* this,
 *     const Wm3::Vector3f& pos, RUnitBlueprint* structureBp, EAlliance alliance,
 *     int cellX, int cellZ);
 *
 * What it does:
 * Full "can this structure be placed here?" test, in three stages that preserve
 * the binary's control flow and short-circuit ordering exactly:
 *
 *   Stage 1 - grid placement check via `func_LocationIsFree`. When the site is
 *     free, stage 2A is skipped and the common stages 2B/3 run.
 *   Stage 2A (only when Stage 1 failed) - rescue path. A `ALLIANCE_None`
 *     request or a null blueprint fails outright. Otherwise the candidate skirt
 *     is scanned for nearby structures of the opposite-and-neutral alliance
 *     lanes; the placement is only rescued when the relevant structure sets are
 *     empty. On success the code FALLS THROUGH into Stage 2B (it is not an
 *     if/else against the free path).
 *   Stage 2B (common) - reject the site when the requested skirt overlaps any
 *     nearby live, non-mobile enemy unit.
 *   Stage 3 (common, only when the running result is still true) - walk this
 *     brain's outstanding build reservations. A reservation whose builder or
 *     command lane is dead is erased in place; a live reservation whose reserved
 *     structure skirt overlaps the requested skirt rejects the placement.
 */
bool moho::CAiBrain::CanBuildStructureAt(
  const Wm3::Vector3f& pos,
  RUnitBlueprint* const structureBp,
  const EAlliance alliance,
  const int cellX,
  const int cellZ
)
{
  (void)cellX;
  (void)cellZ;

  // Stage 1: grid placement check. `func_LocationIsFree` writes its resolved
  // occupation into a scratch result that is otherwise unused here.
  const SCoordsVec2 worldXZ{pos.x, pos.z};
  SOccupationResult placementResult{};
  bool locationOk = false;
  if (structureBp != nullptr) {
    locationOk = func_LocationIsFree(*structureBp, *mSim->mOGrid, worldXZ, placementResult);
  }

  // Stage 2A: rescue path when the raw grid check failed.
  if (!locationOk) {
    if (structureBp == nullptr || alliance == ALLIANCE_None) {
      return false;
    }

    const gpg::Rect2f candidateSkirt = structureBp->GetSkirtRect(worldXZ);
    const float extent = std::max(candidateSkirt.x1 - candidateSkirt.x0, candidateSkirt.z1 - candidateSkirt.z0);

    RRuleGameRules* const rules = mSim->mRules;
    const EntityCategorySet* const structureCategory = rules->GetEntityCategory("STRUCTURE");

    // Structures whose alliance is the mirror of the requested one
    // (Ally request -> gather Enemy, Enemy request -> gather Ally), plus the
    // neutral-alliance structures, both around the candidate position.
    const EAlliance mirroredAlliance = (alliance == ALLIANCE_Enemy) ? ALLIANCE_Ally : ALLIANCE_Enemy;

    SEntitySetTemplateUnit mirroredStructures{};
    (void)CollectUnitsAroundPointFiltered(this, &mirroredStructures, structureCategory, pos, extent, mirroredAlliance);

    SEntitySetTemplateUnit neutralStructures{};
    (void)CollectUnitsAroundPointFiltered(this, &neutralStructures, structureCategory, pos, extent, ALLIANCE_Neutral);

    if (alliance == ALLIANCE_Enemy) {
      // Requesting an enemy placement: only the mirrored (ally) set must be empty.
      locationOk = mirroredStructures.Empty();
    } else {
      // Requesting an ally placement: both the mirrored (enemy) and neutral
      // structure sets must be empty.
      locationOk = mirroredStructures.Empty() && neutralStructures.Empty();
    }

    if (!locationOk) {
      return false;
    }
    // else: fall through into the common stages below.
  }

  // Stage 2B (common): reject when the requested skirt overlaps a nearby live,
  // non-mobile enemy unit.
  if (structureBp != nullptr) {
    const gpg::Rect2f requestedSkirt = structureBp->GetSkirtRect(worldXZ);

    Wm3::AxisAlignedBox3f queryBox{};
    queryBox.Min.x = requestedSkirt.x0;
    queryBox.Max.x = requestedSkirt.x1;
    queryBox.Min.y = -1000.0f;
    queryBox.Max.y = 1000.0f;
    queryBox.Min.z = requestedSkirt.z0;
    queryBox.Max.z = requestedSkirt.z1;

    CollisionResultFastVectorN10 nearbyUnits{};
    GatherUnmarkedUnitsInBox(*mSim->mOGrid, queryBox, nearbyUnits);

    for (const CollisionResult& hit : nearbyUnits) {
      Entity* const source = hit.sourceEntity;
      Unit* const unit = (source != nullptr) ? source->IsUnit() : nullptr;
      if (unit == nullptr) {
        continue;
      }
      if (unit->IsDead()) {
        continue;
      }
      if (unit->DestroyQueued()) {
        continue;
      }
      if (alliance != ALLIANCE_None) {
        const IArmy* const unitArmy =
          (unit->ArmyRef != nullptr) ? static_cast<const IArmy*>(unit->ArmyRef) : nullptr;
        if (mArmy->GetAllianceWith(unitArmy) == alliance) {
          continue;
        }
      }
      if (unit->IsMobile()) {
        continue;
      }
      if (requestedSkirt.Overlaps(unit->GetSkirtRect())) {
        return false;
      }
    }
  }

  if (!locationOk) {
    return false;
  }

  // Stage 3 (common): scan outstanding build reservations. Erase reservations
  // whose builder/command lane has died; reject the placement when a live
  // reservation's reserved structure skirt overlaps the requested skirt.
  // (The reserved structure blueprint is the command's build blueprint,
  // mConstDat.blueprint; the binary reaches it via the command's target lane.)
  auto& reserveMap = reinterpret_cast<BuildReserveMapStorage&>(mBuildStructureMap);
  const gpg::Rect2f requestedSkirt = (structureBp != nullptr) ? structureBp->GetSkirtRect(worldXZ) : gpg::Rect2f{};

  for (auto it = reserveMap.begin(); it != reserveMap.end();) {
    SBuildReserveInfo& reservation = it->second;
    Unit* const builder = reservation.mUnit.GetObjectPtr();
    CUnitCommand* const command = reservation.mCom.GetObjectPtr();

    // A reservation with no live command lane, no live builder, or a dead
    // builder is stale and is dropped from the map.
    if (command == nullptr || builder == nullptr || builder->IsDead()) {
      it = reserveMap.erase(it);
      continue;
    }

    // Reserved structure blueprint and its target position drive the reserved
    // skirt rectangle.
    auto* const reservedBlueprint = static_cast<RUnitBlueprint*>(command->mConstDat.blueprint);
    if (reservedBlueprint == nullptr) {
      ++it;
      continue;
    }

    const Wm3::Vec3f reservedPos = command->mTarget.GetTargetPosGun(false);
    const SCoordsVec2 reservedXZ{reservedPos.x, reservedPos.z};
    const gpg::Rect2f reservedSkirt = reservedBlueprint->GetSkirtRect(reservedXZ);

    if (structureBp != nullptr && reservedSkirt.Overlaps(requestedSkirt)) {
      return false;
    }

    ++it;
  }

  return locationOk;
}

/**
 * Address: 0x0058B3A0 (FUN_0058B3A0, cfunc_CAiBrainCanBuildStructureAt)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainCanBuildStructureAtL`.
 */
int moho::cfunc_CAiBrainCanBuildStructureAt(lua_State* const luaContext)
{
  return cfunc_CAiBrainCanBuildStructureAtL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058B3C0 (FUN_0058B3C0, func_CAiBrainCanBuildStructureAt_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:CanBuildStructureAt(blueprint, location)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainCanBuildStructureAt_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainCanBuildStructureAtName,
    &moho::cfunc_CAiBrainCanBuildStructureAt,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainCanBuildStructureAtHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058B420 (FUN_0058B420, cfunc_CAiBrainCanBuildStructureAtL)
 *
 * IDA signature:
 * int __usercall cfunc_CAiBrainCanBuildStructureAtL@<eax>(LuaPlus::LuaState *ebx0@<ebx>);
 *
 * What it does:
 * Reads `(brain, blueprintName, location)` from the Lua stack, resolves the unit
 * blueprint by name, and pushes the boolean result of
 * `CAiBrain::CanBuildStructureAt` evaluated at `location` with `ALLIANCE_None`
 * and the truncated integer cell coordinates of the location.
 */
int moho::cfunc_CAiBrainCanBuildStructureAtL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainCanBuildStructureAtHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject blueprintStackObject(state, 2);
  const char* const blueprintName = lua_tostring(rawState, 2);
  if (blueprintName == nullptr) {
    blueprintStackObject.TypeError("string");
  }

  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintName ? blueprintName : "");
  RUnitBlueprint* const blueprint = brain->mSim->mRules->GetUnitBlueprint(lookupId);

  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);

  const bool canBuild = brain->CanBuildStructureAt(
    position,
    blueprint,
    ALLIANCE_None,
    static_cast<int>(position.x),
    static_cast<int>(position.z)
  );

  lua_pushboolean(rawState, canBuild ? 1 : 0);
  lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058EFE0 (FUN_0058EFE0, cfunc_CAiBrainPickBestAttackVectorL)
 *
 * IDA signature:
 * int __usercall cfunc_CAiBrainPickBestAttackVectorL@<eax>(LuaPlus::LuaState* state);
 *
 * What it does:
 * Reads `(brain, platoon, squadClass, alliance, compareType, category
 * [, scoreScript, scoreFunc])` from the Lua stack, invokes
 * `CAiBrain::PickBestAttackVector`, and returns the result as an `SPointVector`
 * Lua object — or `nil` when the returned point equals the zero vector.
 *
 * The argument count must be 6 or 8; a count of 7 emits a Warnf and proceeds
 * with null score-script/function pointers.
 */
int moho::cfunc_CAiBrainPickBestAttackVectorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 6 || argumentCount > 8) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainPickBestAttackVectorHelpText,
      6,
      8,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 2));
  CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

  ESquadClass squadClass{};
  gpg::RRef squadClassRef{};
  (void)gpg::RRef_ESquadClass(&squadClassRef, &squadClass);
  LuaPlus::LuaStackObject squadClassArg(state, 3);
  const char* const squadClassName = lua_tostring(rawState, 3);
  if (squadClassName == nullptr) {
    squadClassArg.TypeError("string");
  }
  SCR_GetEnum(state, squadClassName, squadClassRef);

  EAlliance alliance{};
  gpg::RRef allianceRef{};
  (void)gpg::RRef_EAlliance(&allianceRef, &alliance);
  LuaPlus::LuaStackObject allianceArg(state, 4);
  const char* const allianceName = lua_tostring(rawState, 4);
  if (allianceName == nullptr) {
    allianceArg.TypeError("string");
  }
  SCR_GetEnum(state, allianceName, allianceRef);

  ECompareType compareType{};
  gpg::RRef compareTypeRef{};
  (void)gpg::RRef_ECompareType(&compareTypeRef, &compareType);
  LuaPlus::LuaStackObject compareTypeArg(state, 5);
  const char* const compareTypeName = lua_tostring(rawState, 5);
  if (compareTypeName == nullptr) {
    compareTypeArg.TypeError("string");
  }
  SCR_GetEnum(state, compareTypeName, compareTypeRef);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 6));
  EntityCategorySet* const category = func_GetCObj_EntityCategory(categoryObject);

  SPointVector result{};
  if (lua_gettop(rawState) == 8) {
    LuaPlus::LuaStackObject scoreScriptArg(state, 7);
    const char* const scoreScript = lua_tostring(rawState, 7);
    if (scoreScript == nullptr) {
      scoreScriptArg.TypeError("string");
    }
    LuaPlus::LuaStackObject scoreFuncArg(state, 8);
    const char* const scoreFunc = lua_tostring(rawState, 8);
    if (scoreFunc == nullptr) {
      scoreFuncArg.TypeError("string");
    }
    brain->PickBestAttackVector(&result, platoon, squadClass, alliance, compareType, category, scoreScript, scoreFunc);
  } else {
    if (lua_gettop(rawState) == 7) {
      gpg::Warnf(kAiBrainPickBestAttackVectorArgCountWarning);
    }
    brain->PickBestAttackVector(&result, platoon, squadClass, alliance, compareType, category, nullptr, nullptr);
  }

  const Wm3::Vector3f zeroVector = Wm3::Vector3f::Zero();
  if (Wm3::Vector3f::Compare(&result.point, &zeroVector)) {
    LuaPlus::LuaObject resultObject = SCR_ToLua<SPointVector>(state, result);
    resultObject.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }
  return 1;
}

/**
 * Address: 0x0058FFA0 (FUN_0058FFA0, cfunc_CAiBrainAssignThreatAtPosition)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainAssignThreatAtPositionL`.
 */
int moho::cfunc_CAiBrainAssignThreatAtPosition(lua_State* const luaContext)
{
  return cfunc_CAiBrainAssignThreatAtPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00590000 (FUN_00590000, cfunc_CAiBrainAssignThreatAtPositionL)
 *
 * IDA signature:
 * int __usercall cfunc_CAiBrainAssignThreatAtPositionL@<eax>(LuaPlus::LuaState *state@<ebx>);
 *
 * What it does:
 * Reads `(brain, position, threatValue[, decayRate, threatTypeName])`
 * from the Lua stack and forwards the assignment into
 * `CInfluenceMap::AssignThreatAtPosition`. Decay rate is clamped to
 * `[0, 1]`; defaults to `-1` so the underlying helper substitutes its
 * fallback `0.01` rate. Threat type defaults to `THREATTYPE_Overall`.
 */
int moho::cfunc_CAiBrainAssignThreatAtPositionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 3 || argumentCount > 5) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainAssignThreatAtPositionHelpText,
      3,
      5,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 2));
  Wm3::Vector3f position{};
  position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);

  LuaPlus::LuaStackObject threatStackObject(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    threatStackObject.TypeError("number");
  }
  const float threatValue = static_cast<float>(lua_tonumber(rawState, 3));

  float decayRate = -1.0f;
  EThreatType threatType = THREATTYPE_Overall;

  if (argumentCount > 3) {
    LuaPlus::LuaStackObject decayStackObject(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      decayStackObject.TypeError("number");
    }
    float rawDecay = static_cast<float>(lua_tonumber(rawState, 4));
    if (rawDecay >= 1.0f) {
      rawDecay = 1.0f;
    }
    if (rawDecay < 0.0f) {
      rawDecay = 0.0f;
    }
    decayRate = rawDecay;
  }

  if (argumentCount > 4) {
    gpg::RRef threatRef{};
    gpg::RRef_EThreatType(&threatRef, &threatType);
    LuaPlus::LuaStackObject threatNameStackObject(state, 5);
    const char* const threatName = lua_tostring(rawState, 5);
    if (threatName == nullptr) {
      threatNameStackObject.TypeError("string");
    }
    SCR_GetEnum(state, threatName, threatRef);
  }

  CInfluenceMap* const influenceGrid = brain->mArmy->GetIGrid();
  influenceGrid->AssignThreatAtPosition(position, threatType, threatValue, decayRate);
  return 0;
}

/**
 * Address: 0x0058FFC0 (FUN_0058FFC0, func_CAiBrainAssignThreatAtPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:AssignThreatAtPosition(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainAssignThreatAtPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainAssignThreatAtPositionName,
    &moho::cfunc_CAiBrainAssignThreatAtPosition,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainAssignThreatAtPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x005908F0 (FUN_005908F0, cfunc_CAiBrainGetHighestThreatPosition)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetHighestThreatPositionL`.
 */
int moho::cfunc_CAiBrainGetHighestThreatPosition(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetHighestThreatPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00590950 (FUN_00590950, cfunc_CAiBrainGetHighestThreatPositionL)
 *
 * IDA signature:
 * int __thiscall cfunc_CAiBrainGetHighestThreatPositionL(LuaPlus::LuaState *this);
 *
 * What it does:
 * Reads `(brain, radius, restrictToOnMap[, threatTypeName, armyIndex])`,
 * scans the brain's influence map for the cell with the highest
 * threat value, and pushes both the world-space position and the
 * peak threat scalar back onto the Lua stack. Returns 2 values to
 * Lua.
 */
int moho::cfunc_CAiBrainGetHighestThreatPositionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 3 || argumentCount > 5) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainGetHighestThreatPositionHelpText,
      3,
      5,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject radiusStackObject(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    radiusStackObject.TypeError("integer");
  }
  const int radius = static_cast<int>(lua_tonumber(rawState, 2));

  LuaPlus::LuaStackObject restrictionStackObject(state, 3);
  const bool restrictToOnMap = restrictionStackObject.GetBoolean();

  EThreatType threatType = THREATTYPE_Overall;
  int armyIndex = -1;

  if (argumentCount > 3) {
    gpg::RRef threatRef{};
    gpg::RRef_EThreatType(&threatRef, &threatType);
    LuaPlus::LuaStackObject threatNameStackObject(state, 4);
    const char* const threatName = lua_tostring(rawState, 4);
    if (threatName == nullptr) {
      threatNameStackObject.TypeError("string");
    }
    SCR_GetEnum(state, threatName, threatRef);
  }

  if (argumentCount > 4) {
    LuaPlus::LuaStackObject armyStackObject(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      armyStackObject.TypeError("integer");
    }
    const int oneBasedArmyIndex = static_cast<int>(lua_tonumber(rawState, 5));
    armyIndex = oneBasedArmyIndex - 1;
    const int armyCount = static_cast<int>(brain->mSim->mArmiesList.size());
    if (armyIndex < 0 || armyIndex >= armyCount) {
      LuaPlus::LuaState::Error(state, kAiBrainGetHighestThreatPositionInvalidArmyError);
    }
  }

  Wm3::Vector3f outPosition{};
  float outThreat = 0.0f;
  CInfluenceMap* const influenceGrid = brain->mArmy->GetIGrid();
  influenceGrid->GetHighestThreatPosition(&outPosition, &outThreat, radius, restrictToOnMap, threatType, armyIndex);

  LuaPlus::LuaObject positionResult = moho::SCR_ToLua<Wm3::Vector3<float>>(state, outPosition);
  positionResult.PushStack(state);
  lua_pushnumber(rawState, outThreat);
  return 2;
}

/**
 * Address: 0x00590910 (FUN_00590910, func_CAiBrainGetHighestThreatPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetHighestThreatPosition(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetHighestThreatPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetHighestThreatPositionName,
    &moho::cfunc_CAiBrainGetHighestThreatPosition,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetHighestThreatPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058B690 (FUN_0058B690, cfunc_CAiBrainBuildStructureL)
 *
 * What it does:
 * Reads `(brain, builder, blueprintId, locationInfo[, relativeToArmyStart])`,
 * issues one build-structure command, and schedules build-structure bookkeeping
 * at the integer cell derived from the final build position.
 */
int moho::cfunc_CAiBrainBuildStructureL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 4 || argumentCount > 5) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainBuildStructureHelpText,
      4,
      5,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject builderObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const builder = SCR_FromLua_Unit(builderObject);

  const LuaPlus::LuaObject blueprintObject(LuaPlus::LuaStackObject(state, 3));
  const char* const blueprintId = blueprintObject.GetString();

  const LuaPlus::LuaObject locationInfoObject(LuaPlus::LuaStackObject(state, 4));
  const LuaPlus::LuaObject locationZObject = locationInfoObject[2];
  const LuaPlus::LuaObject locationXObject = locationInfoObject[1];
  const float locationX = locationXObject.GetNumber();
  const float locationZ = locationZObject.GetNumber();

  Wm3::Vector3f buildPosition{};
  buildPosition.x = locationX;
  buildPosition.y = 0.0f;
  buildPosition.z = locationZ;

  Wm3::Vector3f orientation{};
  const LuaPlus::LuaObject angleObject = locationInfoObject[3];
  const float angle = angleObject.GetNumber();

  if (locationInfoObject.GetCount() > 3) {
    const LuaPlus::LuaObject orientationZObject = locationInfoObject[5];
    const LuaPlus::LuaObject orientationXObject = locationInfoObject[4];
    orientation.x = orientationXObject.GetNumber();
    orientation.y = 0.0f;
    orientation.z = orientationZObject.GetNumber();
  }

  if (argumentCount > 4) {
    if (LuaPlus::LuaStackObject(state, 5).GetBoolean()) {
      Wm3::Vector2f armyStartPosA{};
      brain->mArmy->GetArmyStartPos(armyStartPosA);
      Wm3::Vector2f armyStartPosB{};
      brain->mArmy->GetArmyStartPos(armyStartPosB);
      buildPosition.x = armyStartPosB.x + locationX;
      buildPosition.y = 0.0f;
      buildPosition.z = armyStartPosA.y + locationZ;
    }
  }

  CUnitCommand* const command = func_OrderBuildStructure(&orientation, brain, builder, blueprintId, &buildPosition, angle);
  const Wm3::Vector2i buildCellPosition{
    static_cast<int>(buildPosition.x),
    static_cast<int>(buildPosition.z),
  };
  func_ScheduleBuildStructure(builder, brain, command, buildCellPosition);
  return 1;
}

/**
 * Address: 0x0058B630 (FUN_0058B630, func_CAiBrainBuildStructure_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:BuildStructure(builder, structureName, locationInfo)`
 * Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainBuildStructure_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainBuildStructureName,
    &moho::cfunc_CAiBrainBuildStructure,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainBuildStructureHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058BA40 (FUN_0058BA40, cfunc_CAiBrainNumCurrentlyBuilding)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainNumCurrentlyBuildingL`.
 */
int moho::cfunc_CAiBrainNumCurrentlyBuilding(lua_State* const luaContext)
{
  return cfunc_CAiBrainNumCurrentlyBuildingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058BA60 (FUN_0058BA60, func_CAiBrainNumCurrentlyBuilding_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:NumCurrentlyBuilding(entityCategoryOfBuildee,entityCategoryOfBuilder)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainNumCurrentlyBuilding_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainNumCurrentlyBuildingName,
    &moho::cfunc_CAiBrainNumCurrentlyBuilding,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainNumCurrentlyBuildingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058BAC0 (FUN_0058BAC0, cfunc_CAiBrainNumCurrentlyBuildingL)
 *
 * What it does:
 * Counts live non-destroy-queued builder-category units in `Building`/`Upgrading`
 * state whose focused build target blueprint matches the requested buildee category.
 */
int moho::cfunc_CAiBrainNumCurrentlyBuildingL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainNumCurrentlyBuildingHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject buildeeCategoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const buildeeCategory = ResolveEntityCategorySetFromLuaObject(buildeeCategoryObject);

  const LuaPlus::LuaObject builderCategoryObject(LuaPlus::LuaStackObject(state, 3));
  EntityCategorySet* const builderCategory = ResolveEntityCategorySetFromLuaObject(builderCategoryObject);

  std::int32_t count = 0;
  if (brain != nullptr && brain->mArmy != nullptr) {
    SEntitySetTemplateUnit builderUnits{};
    brain->mArmy->GetUnits(&builderUnits, builderCategory);

    for (Entity* const* it = builderUnits.mVec.begin(); it != builderUnits.mVec.end(); ++it) {
      Unit* const builder = SEntitySetTemplateUnit::UnitFromEntry(*it);
      if (builder == nullptr || builder->IsDead() || builder->DestroyQueued()) {
        continue;
      }

      if (!builder->IsUnitState(UNITSTATE_Building) && !builder->IsUnitState(UNITSTATE_Upgrading)) {
        continue;
      }

      Entity* const focusedEntity = builder->FocusEntityRef.ResolveObjectPtr<Entity>();
      Unit* const focusedUnit = focusedEntity ? focusedEntity->IsUnit() : nullptr;
      if (focusedUnit == nullptr) {
        continue;
      }

      if (CategoryContainsBlueprint(buildeeCategory, focusedUnit->GetBlueprint())) {
        ++count;
      }
    }
  }

  lua_pushnumber(rawState, static_cast<float>(count));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058C840 (FUN_0058C840, cfunc_CAiBrainBuildUnit)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainBuildUnitL`.
 */
int moho::cfunc_CAiBrainBuildUnit(lua_State* const luaContext)
{
  return cfunc_CAiBrainBuildUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058C860 (FUN_0058C860, func_CAiBrainBuildUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:BuildUnit()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainBuildUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainBuildUnitName,
    &moho::cfunc_CAiBrainBuildUnit,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainBuildUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058C8C0 (FUN_0058C8C0, cfunc_CAiBrainBuildUnitL)
 *
 * What it does:
 * Reads `(brain, builder, blueprintId, count)` from Lua and calls
 * `CAiBrain::BuildUnit` when arg#3 is a string.
 */
int moho::cfunc_CAiBrainBuildUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainBuildUnitHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject builderObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const builder = SCR_FromLua_Unit(builderObject);

  const LuaPlus::LuaObject blueprintObject(LuaPlus::LuaStackObject(state, 3));
  const LuaPlus::LuaObject countObject(LuaPlus::LuaStackObject(state, 4));

  if (blueprintObject.IsString()) {
    const int count = countObject.GetInteger();
    const char* const blueprintId = blueprintObject.GetString();
    (void)CAiBrain::BuildUnit(blueprintId, brain, builder, count);
  }

  return 1;
}

/**
 * Address: 0x0058CA40 (FUN_0058CA40, cfunc_CAiBrainIsAnyEngineerBuilding)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainIsAnyEngineerBuildingL`.
 */
int moho::cfunc_CAiBrainIsAnyEngineerBuilding(lua_State* const luaContext)
{
  return cfunc_CAiBrainIsAnyEngineerBuildingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058CAC0 (FUN_0058CAC0, cfunc_CAiBrainIsAnyEngineerBuildingL)
 *
 * What it does:
 * Returns whether any engineer currently in build state matches the requested
 * category filter.
 */
int moho::cfunc_CAiBrainIsAnyEngineerBuildingL(LuaPlus::LuaState* const state)
{
  if (state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainIsAnyEngineerBuildingHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = ResolveEntityCategorySetFromLuaObject(categoryObject);

  bool foundMatch = false;
  if (brain != nullptr && brain->mArmy != nullptr && brain->mSim != nullptr && brain->mSim->mRules != nullptr) {
    const CategoryWordRangeView* const engineerCategory = brain->mSim->mRules->GetEntityCategory(kEngineerCategoryName);

    SEntitySetTemplateUnit engineerUnits{};
    brain->mArmy->GetUnits(&engineerUnits, const_cast<CategoryWordRangeView*>(engineerCategory));

    for (Entity* const* it = engineerUnits.mVec.begin(); it != engineerUnits.mVec.end(); ++it) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      if (!unit->IsUnitState(static_cast<EUnitState>(kBuildingStateTag))) {
        continue;
      }

      if (CategoryContainsBlueprint(categorySet, unit->GetBlueprint())) {
        foundMatch = true;
        break;
      }
    }
  }

  lua_pushboolean(rawState, foundMatch ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0058CA60 (FUN_0058CA60, func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:IsAnyEngineerBuilding(category)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainIsAnyEngineerBuildingName,
    &moho::cfunc_CAiBrainIsAnyEngineerBuilding,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainIsAnyEngineerBuildingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058CCA0 (FUN_0058CCA0, cfunc_CAiBrainGetNumPlatoonsWithAI)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetNumPlatoonsWithAIL`.
 */
int moho::cfunc_CAiBrainGetNumPlatoonsWithAI(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetNumPlatoonsWithAIL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058CCC0 (FUN_0058CCC0, func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetNumPlatoonsWithAI(planName)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetNumPlatoonsWithAIName,
    &moho::cfunc_CAiBrainGetNumPlatoonsWithAI,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetNumPlatoonsWithAIHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058CD10 (FUN_0058CD10, cfunc_CAiBrainGetNumPlatoonsWithAIL)
 *
 * What it does:
 * Resolves `(brain, planName)` and returns matching platoon count.
 */
int moho::cfunc_CAiBrainGetNumPlatoonsWithAIL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetNumPlatoonsWithAIHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject aiPlanObject(LuaPlus::LuaStackObject(state, 2));
  int platoonCount = 0;
  if (aiPlanObject.IsString() && brain != nullptr && brain->mArmy != nullptr) {
    platoonCount = brain->mArmy->GetNumPlatoonWithPlan(aiPlanObject.GetString());
  }

  lua_pushnumber(rawState, static_cast<float>(platoonCount));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058CE30 (FUN_0058CE30, cfunc_CAiBrainGetNumPlatoonsTemplateNamed)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetNumPlatoonsTemplateNamedL`.
 */
int moho::cfunc_CAiBrainGetNumPlatoonsTemplateNamed(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetNumPlatoonsTemplateNamedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058CE50 (FUN_0058CE50, func_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetNumPlatoonsTemplateNamed(templateName)`
 * Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetNumPlatoonsTemplateNamedName,
    &moho::cfunc_CAiBrainGetNumPlatoonsTemplateNamed,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetNumPlatoonsTemplateNamedHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058CEA0 (FUN_0058CEA0, cfunc_CAiBrainGetNumPlatoonsTemplateNamedL)
 *
 * What it does:
 * Resolves `(brain, templateName)` and returns matching platoon count.
 */
int moho::cfunc_CAiBrainGetNumPlatoonsTemplateNamedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kAiBrainGetNumPlatoonsTemplateNamedHelpText,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject templateNameObject(LuaPlus::LuaStackObject(state, 2));
  int platoonCount = 0;
  if (templateNameObject.IsString() && brain != nullptr && brain->mArmy != nullptr) {
    platoonCount = brain->mArmy->GetNumPlatoonsTemplateNamed(templateNameObject.GetString());
  }

  lua_pushnumber(rawState, static_cast<float>(platoonCount));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058CFC0 (FUN_0058CFC0, cfunc_CAiBrainPlatoonExists)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainPlatoonExistsL`.
 */
int moho::cfunc_CAiBrainPlatoonExists(lua_State* const luaContext)
{
  return cfunc_CAiBrainPlatoonExistsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058CFE0 (FUN_0058CFE0, func_CAiBrainPlatoonExists_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:PlatoonExists()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainPlatoonExists_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainPlatoonExistsName,
    &moho::cfunc_CAiBrainPlatoonExists,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainPlatoonExistsHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058D040 (FUN_0058D040, cfunc_CAiBrainPlatoonExistsL)
 *
 * What it does:
 * Returns whether arg #2 resolves to a live platoon object.
 */
int moho::cfunc_CAiBrainPlatoonExistsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainPlatoonExistsHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  (void)SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 2));
  const CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
  lua_pushboolean(rawState, platoon != nullptr ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058D140 (FUN_0058D140, cfunc_CAiBrainGetPlatoonsList)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetPlatoonsListL`.
 */
int moho::cfunc_CAiBrainGetPlatoonsList(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetPlatoonsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058D160 (FUN_0058D160, func_CAiBrainGetPlatoonsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetPlatoonsList()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetPlatoonsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetPlatoonsListName,
    &moho::cfunc_CAiBrainGetPlatoonsList,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetPlatoonsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058D1C0 (FUN_0058D1C0, cfunc_CAiBrainGetPlatoonsListL)
 *
 * What it does:
 * Returns a Lua array of non-empty platoons from the owning army, skipping
 * the synthetic `ArmyPool` platoon entry.
 */
int moho::cfunc_CAiBrainGetPlatoonsListL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetPlatoonsListHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  ArmyPool platoonPool{};
  if (brain != nullptr && brain->mArmy != nullptr) {
    brain->mArmy->GetPlatoonsList(platoonPool);
  }

  LuaPlus::LuaObject outPlatoons;
  outPlatoons.AssignNewTable(state, 0, 0);
  std::int32_t platoonLuaIndex = 1;

  for (CPlatoon** platoonIt = platoonPool.platoons.start_; platoonIt != platoonPool.platoons.end_; ++platoonIt) {
    CPlatoon* const platoon = *platoonIt;
    if (platoon == nullptr) {
      continue;
    }

    const auto& platoonView = *reinterpret_cast<const CPlatoonLuaRuntimeView*>(platoon);
    if (platoonView.mUniqueName.equals_no_case("ArmyPool")) {
      continue;
    }

    if (CountPlatoonUnits(platoonView) > 0) {
      outPlatoons.Insert(platoonLuaIndex, platoonView.mLuaObj);
      ++platoonLuaIndex;
    }
  }

  outPlatoons.PushStack(state);
  return 1;
}

/**
 * Address: 0x0058D360 (FUN_0058D360, cfunc_CAiBrainDisbandPlatoon)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainDisbandPlatoonL`.
 */
int moho::cfunc_CAiBrainDisbandPlatoon(lua_State* const luaContext)
{
  return cfunc_CAiBrainDisbandPlatoonL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058D380 (FUN_0058D380, func_CAiBrainDisbandPlatoon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:DisbandPlatoon()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainDisbandPlatoon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainDisbandPlatoonName,
    &moho::cfunc_CAiBrainDisbandPlatoon,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainDisbandPlatoonHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058D3E0 (FUN_0058D3E0, cfunc_CAiBrainDisbandPlatoonL)
 *
 * What it does:
 * Resolves `(brain, platoon)` from Lua and disbands the platoon via army
 * ownership.
 */
int moho::cfunc_CAiBrainDisbandPlatoonL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainDisbandPlatoonHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 2));
  CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
  brain->mArmy->DisbandPlatoon(platoon);
  return 1;
}

/**
 * Address: 0x0058D4D0 (FUN_0058D4D0, cfunc_CAiBrainDisbandPlatoonUniquelyNamed)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainDisbandPlatoonUniquelyNamedL`.
 */
int moho::cfunc_CAiBrainDisbandPlatoonUniquelyNamed(lua_State* const luaContext)
{
  return cfunc_CAiBrainDisbandPlatoonUniquelyNamedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058D4F0 (FUN_0058D4F0, func_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:DisbandPlatoonUniquelyNamed()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainDisbandPlatoonUniquelyNamedName,
    &moho::cfunc_CAiBrainDisbandPlatoonUniquelyNamed,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainDisbandPlatoonUniquelyNamedHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058D550 (FUN_0058D550, cfunc_CAiBrainDisbandPlatoonUniquelyNamedL)
 *
 * What it does:
 * Resolves `(brain, uniqueName)` and disbands one uniquely named platoon.
 */
int moho::cfunc_CAiBrainDisbandPlatoonUniquelyNamedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kAiBrainDisbandPlatoonUniquelyNamedHelpText,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonNameObject(LuaPlus::LuaStackObject(state, 2));
  if (platoonNameObject.IsString()) {
    brain->mArmy->DisbandPlatoonUniquelyNamed(platoonNameObject.GetString());
  }
  return 1;
}

/**
 * Address: 0x0058DFA0 (FUN_0058DFA0, cfunc_CAiBrainGetPlatoonUniquelyNamed)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetPlatoonUniquelyNamedL`.
 */
int moho::cfunc_CAiBrainGetPlatoonUniquelyNamed(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetPlatoonUniquelyNamedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058DFC0 (FUN_0058DFC0, func_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetPlatoonUniquelyNamed()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetPlatoonUniquelyNamedName,
    &moho::cfunc_CAiBrainGetPlatoonUniquelyNamed,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetPlatoonUniquelyNamedHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058E020 (FUN_0058E020, cfunc_CAiBrainGetPlatoonUniquelyNamedL)
 *
 * What it does:
 * Resolves `(brain, platoonName)` and returns the matching platoon Lua object,
 * or `nil` when no matching platoon exists.
 */
int moho::cfunc_CAiBrainGetPlatoonUniquelyNamedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetPlatoonUniquelyNamedHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonNameObject(LuaPlus::LuaStackObject(state, 2));
  if (platoonNameObject.IsString() && brain != nullptr && brain->mArmy != nullptr) {
    if (const CPlatoon* const platoon = brain->mArmy->GetPlatoonByName(platoonNameObject.GetString()); platoon != nullptr) {
      const auto& platoonView = *reinterpret_cast<const CPlatoonLuaRuntimeView*>(platoon);
      platoonView.mLuaObj.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005917F0 (FUN_005917F0, cfunc_CAiBrainGetNoRushTicks)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainGetNoRushTicksL`.
 */
int moho::cfunc_CAiBrainGetNoRushTicks(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetNoRushTicksL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00591810 (FUN_00591810, func_CAiBrainGetNoRushTicks_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetNoRushTicks()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetNoRushTicks_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetNoRushTicksName,
    &moho::cfunc_CAiBrainGetNoRushTicks,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetNoRushTicksHelpText
  );
  return &binder;
}

/**
 * Address: 0x00591870 (FUN_00591870, cfunc_CAiBrainGetNoRushTicksL)
 *
 * What it does:
 * Returns current no-rush timer ticks for the brain owning army.
 */
int moho::cfunc_CAiBrainGetNoRushTicksL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainGetNoRushTicksHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  lua_pushnumber(rawState, static_cast<float>(brain->mArmy->NoRushTicks));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0057A510 (FUN_0057A510, Moho::CAiBrain::CenterOfArmy)
 *
 * What it does:
 * Iterates the brain's mobile (non-structure) army units, sums their world
 * positions, and writes the average into `outPosition`. Mirrors the
 * recovered ProcessAttackVectors traversal pattern.
 */
Wm3::Vec3f* moho::CAiBrain::CenterOfArmy(Wm3::Vec3f* const outPosition)
{
  outPosition->x = 0.0f;
  outPosition->y = 0.0f;
  outPosition->z = 0.0f;

  if (mArmy == nullptr || mSim == nullptr || mSim->mRules == nullptr) {
    return outPosition;
  }

  RRuleGameRules* const rules = mSim->mRules;
  const CategoryWordRangeView* const mobileCategory = rules->GetEntityCategory("MOBILE");
  const CategoryWordRangeView* const structureCategory = rules->GetEntityCategory("STRUCTURE");

  EntityCategorySet mobileMinusStructure{};
  EntityCategory::Sub(&mobileMinusStructure, mobileCategory, structureCategory);

  SEntitySetTemplateUnit candidateUnits{};
  mArmy->GetUnits(&candidateUnits, &mobileMinusStructure);

  std::uint32_t aliveUnitCount = 0u;
  for (Entity* const* unitIt = candidateUnits.mVec.begin(); unitIt != candidateUnits.mVec.end(); ++unitIt) {
    Unit* const candidateUnit = SEntitySetTemplateUnit::UnitFromEntry(*unitIt);
    if (candidateUnit == nullptr || candidateUnit->IsDead() || candidateUnit->DestroyQueued()) {
      continue;
    }

    const Wm3::Vec3f& unitPosition = candidateUnit->GetPosition();
    outPosition->x += unitPosition.x;
    outPosition->y += unitPosition.y;
    outPosition->z += unitPosition.z;
    ++aliveUnitCount;
  }

  if (aliveUnitCount == 0u) {
    return outPosition;
  }

  const float invCount = 1.0f / static_cast<float>(aliveUnitCount);
  outPosition->x *= invCount;
  outPosition->y *= invCount;
  outPosition->z *= invCount;
  return outPosition;
}

/**
 * Address: 0x0058EB40 (FUN_0058EB40, cfunc_CAiBrainSetUpAttackVectorsToArmy)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainSetUpAttackVectorsToArmyL`.
 */
int moho::cfunc_CAiBrainSetUpAttackVectorsToArmy(lua_State* const luaContext)
{
  return cfunc_CAiBrainSetUpAttackVectorsToArmyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058EB60 (FUN_0058EB60, func_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:SetUpAttackVectorsToArmy()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainSetUpAttackVectorsToArmyName,
    &moho::cfunc_CAiBrainSetUpAttackVectorsToArmy,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainSetUpAttackVectorsToArmyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058EBC0 (FUN_0058EBC0, cfunc_CAiBrainSetUpAttackVectorsToArmyL)
 *
 * What it does:
 * Updates the brain's attack-vector category filter from an explicit category
 * argument or, when none is supplied, the default `MOBILE - STRUCTURE`
 * category, then rebuilds the brain attack vectors.
 */
int moho::cfunc_CAiBrainSetUpAttackVectorsToArmyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgRangeWarning,
      kAiBrainSetUpAttackVectorsToArmyHelpText,
      1,
      2,
      argumentCount
    );
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  if (argumentCount > 1 && lua_type(rawState, 2) != 0) {
    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    EntityCategorySet* const explicitCategory = func_GetCObj_EntityCategory(categoryObject);
    brain->mBuildCategoryRange = *explicitCategory;
  } else {
    RRuleGameRules* const rules = brain->mSim->mRules;
    const CategoryWordRangeView* const mobileCategory = rules->GetEntityCategory("MOBILE");
    const CategoryWordRangeView* const structureCategory = rules->GetEntityCategory("STRUCTURE");

    EntityCategorySet defaultCategory{};
    EntityCategory::Sub(&defaultCategory, mobileCategory, structureCategory);
    brain->mBuildCategoryRange = defaultCategory;
  }

  brain->ProcessAttackVectors();
  return 1;
}

/**
 * Address: 0x0058E830 (FUN_0058E830, cfunc_CAiBrainFindClosestArmyWithBase)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainFindClosestArmyWithBaseL`.
 */
int moho::cfunc_CAiBrainFindClosestArmyWithBase(lua_State* const luaContext)
{
  return cfunc_CAiBrainFindClosestArmyWithBaseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058E850 (FUN_0058E850, func_CAiBrainFindClosestArmyWithBase_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:FindClosestArmyWithBase()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainFindClosestArmyWithBase_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainFindClosestArmyWithBaseName,
    &moho::cfunc_CAiBrainFindClosestArmyWithBase,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainFindClosestArmyWithBaseHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058E8B0 (FUN_0058E8B0, cfunc_CAiBrainFindClosestArmyWithBaseL)
 *
 * What it does:
 * Walks the army's recon-blip list, filters to live units of the requested
 * alliance state that own at least one `STRUCTURE` blueprint bit, then
 * returns the Lua object of the closest qualifying army's brain (or nil).
 */
int moho::cfunc_CAiBrainFindClosestArmyWithBaseL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainFindClosestArmyWithBaseHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  EAlliance requestedAlliance{};
  gpg::RRef enumRef{};
  (void)gpg::RRef_EAlliance(&enumRef, &requestedAlliance);

  const LuaPlus::LuaStackObject allianceArg(state, 2);
  const char* const allianceName = lua_tostring(rawState, 2);
  if (!allianceName) {
    allianceArg.TypeError("string");
  }
  SCR_GetEnum(state, allianceName, enumRef);

  Wm3::Vec3f searchPosition{};
  brain->CenterOfArmy(&searchPosition);

  CArmyImpl* closestArmy = nullptr;
  float closestDistance = std::numeric_limits<float>::infinity();

  CAiReconDBImpl* const reconDB = brain->mArmy->GetReconDB();
  if (reconDB == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  const CategoryWordRangeView* const structureCategory = brain->mSim->mRules->GetEntityCategory("STRUCTURE");

  const msvc8::vector<ReconBlip*>& blips = reconDB->ReconGetBlips();
  for (ReconBlip* const blip : blips) {
    if (blip == nullptr) {
      continue;
    }

    Unit* const sourceUnit = blip->GetCreator();
    if (sourceUnit == nullptr || sourceUnit->IsDead()) {
      continue;
    }

    CArmyImpl* const sourceArmy = sourceUnit->ArmyRef;
    const IArmy* const sourceArmyBase = sourceArmy != nullptr ? static_cast<const IArmy*>(sourceArmy) : nullptr;
    if (brain->mArmy->GetAllianceWith(sourceArmyBase) != requestedAlliance) {
      continue;
    }

    if (structureCategory == nullptr) {
      continue;
    }
    if (!structureCategory->ContainsBit(static_cast<std::uint32_t>(sourceUnit->GetBlueprint()->mCategoryBitIndex))) {
      continue;
    }

    const Wm3::Vec3f& unitPosition = sourceUnit->GetPosition();
    const float dx = searchPosition.x - unitPosition.x;
    const float dy = searchPosition.y - unitPosition.y;
    const float dz = searchPosition.z - unitPosition.z;
    const float distanceSq = (dx * dx) + (dy * dy) + (dz * dz);
    if (distanceSq < closestDistance) {
      closestDistance = distanceSq;
      closestArmy = sourceArmy;
    }
  }

  if (closestArmy == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  CAiBrain* const closestBrain = closestArmy->GetArmyBrain();
  closestBrain->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0058E450 (FUN_0058E450, cfunc_CAiBrainGetUnitsAroundPointL)
 *
 * IDA signature:
 * int __usercall cfunc_CAiBrainGetUnitsAroundPointL@<eax>(LuaPlus::LuaState *state@<ebx>);
 *
 * What it does:
 * Implements `CAiBrain:GetUnitsAroundPoint(category, position, radius[, allianceState])`.
 * Parses the brain, entity-category set, Vector3 position and numeric radius
 * (plus an optional alliance-enum string), gathers the matching units via
 * CollectUnitsAroundPointFiltered, and returns a Lua array of their script
 * objects.
 */
int moho::cfunc_CAiBrainGetUnitsAroundPointL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 4 || argumentCount > 5) {
    LuaPlus::LuaState::Error(
      state, kLuaExpectedArgRangeWarning, kAiBrainGetUnitsAroundPointHelpText, 4, 5, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 3));
  Wm3::Vector3f point{};
  (void)SCR_FromLuaCopy<Wm3::Vector3<float>>(&positionObject, &point);

  LuaPlus::LuaStackObject radiusArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    radiusArg.TypeError("number");
  }
  const float radius = static_cast<float>(lua_tonumber(rawState, 4));

  SEntitySetTemplateUnit gatheredUnits{};

  if (lua_gettop(rawState) == 5) {
    EAlliance requestedAlliance{};
    gpg::RRef allianceRef{};
    (void)gpg::RRef_EAlliance(&allianceRef, &requestedAlliance);

    LuaPlus::LuaStackObject allianceArg(state, 5);
    const char* const allianceName = lua_tostring(rawState, 5);
    if (!allianceName) {
      allianceArg.TypeError("string");
    }
    SCR_GetEnum(state, allianceName, allianceRef);

    SEntitySetTemplateUnit scratchUnits{};
    (void)CollectUnitsAroundPointFiltered(brain, &scratchUnits, categorySet, point, radius, requestedAlliance);
    gatheredUnits.mVec.AddAll(&scratchUnits.mVec);
  } else {
    SEntitySetTemplateUnit scratchUnits{};
    (void)CollectUnitsAroundPointFiltered(
      brain, &scratchUnits, categorySet, point, radius, static_cast<EAlliance>(kAiBrainAllianceAnySentinel));
    gatheredUnits.mVec.AddAll(&scratchUnits.mVec);
  }

  LuaPlus::LuaObject resultTable{};
  resultTable.AssignNewTable(state, 0, 0);
  for (Entity* const* it = gatheredUnits.mVec.begin(); it != gatheredUnits.mVec.end(); ++it) {
    // Entries are Unit-owned Entity* lanes; the Entity subobject sits at +0x8 in
    // Unit (Unit : IUnit, Entity), so the static_cast recovers the Unit* the
    // binary reaches via the `-0x8` adjustment before its GetLuaObject vtable call.
    Unit* const unit = static_cast<Unit*>(*it);
    LuaPlus::LuaObject entryObject = unit->GetLuaObject();
    resultTable.Insert(entryObject);
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0058E3D0 (FUN_0058E3D0, cfunc_CAiBrainGetUnitsAroundPoint)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetUnitsAroundPointL`.
 */
int moho::cfunc_CAiBrainGetUnitsAroundPoint(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetUnitsAroundPointL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058E3F0 (FUN_0058E3F0, func_CAiBrainGetUnitsAroundPoint_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetUnitsAroundPoint()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetUnitsAroundPoint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetUnitsAroundPointName,
    &moho::cfunc_CAiBrainGetUnitsAroundPoint,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetUnitsAroundPointHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058E140 (FUN_0058E140, cfunc_CAiBrainGetNumUnitsAroundPoint)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainGetNumUnitsAroundPointL`.
 */
int moho::cfunc_CAiBrainGetNumUnitsAroundPoint(lua_State* const luaContext)
{
  return cfunc_CAiBrainGetNumUnitsAroundPointL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058E160 (FUN_0058E160, func_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:GetNumUnitsAroundPoint()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainGetNumUnitsAroundPointName,
    &moho::cfunc_CAiBrainGetNumUnitsAroundPoint,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetNumUnitsAroundPointHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058E1C0 (FUN_0058E1C0, cfunc_CAiBrainGetNumUnitsAroundPointL)
 *
 * IDA signature:
 * int __usercall cfunc_CAiBrainGetNumUnitsAroundPointL@<eax>(LuaPlus::LuaState* state@<ebx>);
 *
 * What it does:
 * Implements `CAiBrain:GetNumUnitsAroundPoint(category, position, radius[, allianceState])`.
 * Reads the brain, category set, query point and radius from the Lua stack,
 * optionally a filter alliance, then returns the count from
 * `CountUnitsAroundPointFiltered`.
 */
int moho::cfunc_CAiBrainGetNumUnitsAroundPointL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 4 || argumentCount > 5) {
    LuaPlus::LuaState::Error(
      state, kLuaExpectedArgRangeWarning, kAiBrainGetNumUnitsAroundPointHelpText, 4, 5, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  const LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 3));
  Wm3::Vector3f point{};
  (void)SCR_FromLuaCopy<Wm3::Vector3<float>>(&positionObject, &point);

  LuaPlus::LuaStackObject radiusArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    radiusArg.TypeError("number");
  }
  const float radius = static_cast<float>(lua_tonumber(rawState, 4));

  EAlliance requestedAlliance = static_cast<EAlliance>(kAiBrainAllianceAnySentinel);
  if (lua_gettop(rawState) == 5) {
    gpg::RRef allianceRef{};
    (void)gpg::RRef_EAlliance(&allianceRef, &requestedAlliance);

    LuaPlus::LuaStackObject allianceArg(state, 5);
    const char* const allianceName = lua_tostring(rawState, 5);
    if (!allianceName) {
      allianceArg.TypeError("string");
    }
    SCR_GetEnum(state, allianceName, allianceRef);
  }

  const int unitCount = CountUnitsAroundPointFiltered(brain, categorySet, point, radius, requestedAlliance);

  lua_pushnumber(rawState, static_cast<float>(unitCount));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00591020 (FUN_00591020, cfunc_CAiBrainCheckBlockingTerrain)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainCheckBlockingTerrainL`.
 */
int moho::cfunc_CAiBrainCheckBlockingTerrain(lua_State* const luaContext)
{
  return cfunc_CAiBrainCheckBlockingTerrainL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00591040 (FUN_00591040, func_CAiBrainCheckBlockingTerrain_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:CheckBlockingTerrain()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainCheckBlockingTerrain_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainCheckBlockingTerrainName,
    &moho::cfunc_CAiBrainCheckBlockingTerrain,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainCheckBlockingTerrainHelpText
  );
  return &binder;
}

/**
 * Address: 0x005910A0 (FUN_005910A0, cfunc_CAiBrainCheckBlockingTerrainL)
 *
 * IDA signature:
 * int __cdecl cfunc_CAiBrainCheckBlockingTerrainL(LuaPlus::LuaState* state);
 *
 * What it does:
 * Implements `CAiBrain:CheckBlockingTerrain(startPos, endPos, arcType)`. Lifts
 * `startPos.y` by 1.0 and `endPos.y` by 0.5, then terrain-raycasts. When
 * `arcType == "none"` a single straight segment start->end is cast; otherwise a
 * 4-sample arc (`kAiBrainCheckBlockingTerrainArcSteps`) is walked between the
 * endpoints, each sub-segment lifted on Y by (stepMul * quarterLength) scaled by
 * 0.5 for `"low"` arcs or 2.0 otherwise. Each segment is intersected against the
 * map height field via `CHeightField::Intersection`; the query returns `true`
 * (terrain blocks) when a valid hit lies within the segment span.
 */
int moho::cfunc_CAiBrainCheckBlockingTerrainL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(
      state, kLuaExpectedArgsWarning, kAiBrainCheckBlockingTerrainHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject startObject(LuaPlus::LuaStackObject(state, 2));
  Wm3::Vector3f startPosition{};
  (void)SCR_FromLuaCopy<Wm3::Vector3<float>>(&startObject, &startPosition);

  const LuaPlus::LuaObject endObject(LuaPlus::LuaStackObject(state, 3));
  Wm3::Vector3f endPosition{};
  (void)SCR_FromLuaCopy<Wm3::Vector3<float>>(&endObject, &endPosition);

  LuaPlus::LuaStackObject arcTypeArg(state, 4);
  const char* const arcTypeCStr = lua_tostring(rawState, 4);
  if (!arcTypeCStr) {
    arcTypeArg.TypeError("string");
  }
  const std::string arcType(arcTypeCStr, std::strlen(arcTypeCStr));

  // Lift the endpoints just above the surface (matches the binary's
  // startPos.y += 1.0 / endPos.y += 0.5 before any raycast).
  startPosition.y += kAiBrainCheckBlockingTerrainStartYLift;
  endPosition.y += kAiBrainCheckBlockingTerrainEndYLift;

  const float nanSentinel = std::numeric_limits<float>::quiet_NaN();
  CHeightField* const heightField = brain->mSim->mMapData->mHeightField.get();

  // Shared helper: cast one sub-segment and report whether a valid terrain hit
  // falls within the segment span. `hitResult.distance` is seeded to NaN so a
  // segment with no recorded distance never reports blockage.
  const auto segmentBlocked =
    [&](const Wm3::Vector3f& segStart, const Wm3::Vector3f& segEnd) -> bool {
      const Wm3::Segment3f segment = Wm3::MakeSegment3fFromEndpoints(segStart, segEnd);

      GeomLine3 line{};
      line.pos.x = segment.Origin.x - (segment.Direction.x * segment.Extent);
      line.pos.y = segment.Origin.y - (segment.Direction.y * segment.Extent);
      line.pos.z = segment.Origin.z - (segment.Direction.z * segment.Extent);
      line.dir = segment.Direction;
      line.closest = 0.0f;
      line.farthest = segment.Extent * kAiBrainCheckBlockingTerrainArcHighScale;

      CGeomHitResult hitResult{};
      hitResult.distance = nanSentinel;
      hitResult.v1 = nanSentinel;
      const Wm3::Vector3f hitPoint = heightField->Intersection(line, &hitResult);

      const float spanDx = segStart.x - segEnd.x;
      const float spanDy = segStart.y - segEnd.y;
      const float spanDz = segStart.z - segEnd.z;
      const float segmentLength =
        std::sqrt((spanDx * spanDx) + (spanDz * spanDz) + (spanDy * spanDy));

      return IsValidVector3f(hitPoint) && segmentLength >= hitResult.distance;
    };

  bool blocked = false;

  if (_stricmp(arcType.c_str(), kAiBrainCheckBlockingTerrainArcNone) != 0) {
    // Arc mode: sample four sub-segments between start and end, each lifted on Y.
    const Wm3::Vector3f quarterStep{
      (endPosition.x - startPosition.x) * kAiBrainCheckBlockingTerrainQuarterStep,
      (endPosition.y - startPosition.y) * kAiBrainCheckBlockingTerrainQuarterStep,
      (endPosition.z - startPosition.z) * kAiBrainCheckBlockingTerrainQuarterStep,
    };
    const float quarterLength = std::sqrt(
      (quarterStep.z * quarterStep.z) + (quarterStep.y * quarterStep.y) + (quarterStep.x * quarterStep.x));

    const bool isLowArc = (_stricmp(arcType.c_str(), kAiBrainCheckBlockingTerrainArcLow) == 0);
    const float arcScale =
      isLowArc ? kAiBrainCheckBlockingTerrainArcLowScale : kAiBrainCheckBlockingTerrainArcHighScale;

    Wm3::Vector3f previousPoint = startPosition;
    Wm3::Vector3f currentPoint = startPosition;
    for (const float stepMultiplier : kAiBrainCheckBlockingTerrainArcSteps) {
      currentPoint.x += quarterStep.x;
      currentPoint.y += quarterStep.y;
      currentPoint.z += quarterStep.z;
      currentPoint.y += (stepMultiplier * quarterLength) * arcScale;

      if (segmentBlocked(previousPoint, currentPoint)) {
        blocked = true;
        break;
      }

      previousPoint = currentPoint;
    }
  } else {
    // Straight mode: a single segment from start to end.
    blocked = segmentBlocked(startPosition, endPosition);
  }

  lua_pushboolean(rawState, blocked ? 1 : 0);
  lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0058C490 (FUN_0058C490, cfunc_CAiBrainBuildPlatoon)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainBuildPlatoonL`.
 */
int moho::cfunc_CAiBrainBuildPlatoon(lua_State* const luaContext)
{
  return cfunc_CAiBrainBuildPlatoonL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058C4B0 (FUN_0058C4B0, func_CAiBrainBuildPlatoon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:BuildPlatoon()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainBuildPlatoon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainBuildPlatoonName,
    &moho::cfunc_CAiBrainBuildPlatoon,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainBuildPlatoonHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058C510 (FUN_0058C510, cfunc_CAiBrainBuildPlatoonL)
 *
 * What it does:
 * Issues `BuildUnit(blueprintId, brain, builder, scaledCount)` for every
 * `(blueprintId, ?, baseCount)` row in the build-plan table, scaling each row
 * count by the supplied multiplier (rounded down) and rotating across the
 * builder table for each plan row.
 */
int moho::cfunc_CAiBrainBuildPlatoonL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 4) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainBuildPlatoonHelpText, 4, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject buildPlanTable(LuaPlus::LuaStackObject(state, 2));
  const LuaPlus::LuaObject builderTable(LuaPlus::LuaStackObject(state, 3));
  const LuaPlus::LuaObject countMultiplierObj(LuaPlus::LuaStackObject(state, 4));

  if (!buildPlanTable.IsTable() || !builderTable.IsTable()) {
    return 0;
  }

  const int planRowCount = buildPlanTable.GetCount();
  const int builderRowCount = builderTable.GetCount();
  if (planRowCount < 1) {
    return 0;
  }

  int builderIndex = 1;
  for (int planRow = 1; planRow <= planRowCount; ++planRow) {
    if (builderIndex > builderRowCount) {
      builderIndex = 1;
    }

    const LuaPlus::LuaObject planRowObject = buildPlanTable[planRow];
    if (!planRowObject.IsTable()) {
      continue;
    }

    const LuaPlus::LuaObject blueprintIdObject = planRowObject[1];
    const LuaPlus::LuaObject baseCountObject = planRowObject[3];

    const float baseCount = static_cast<float>(baseCountObject.GetInteger());
    const float scaledCountFloat = static_cast<float>(countMultiplierObj.GetNumber()) * baseCount;
    const int scaledCount = static_cast<int>(std::floor(scaledCountFloat));

    const LuaPlus::LuaObject builderUnitObject = builderTable[builderIndex];
    Unit* const builderUnit = SCR_FromLua_Unit(builderUnitObject);

    if (builderUnit != nullptr) {
      const char* const blueprintId = blueprintIdObject.GetString();
      (void)CAiBrain::BuildUnit(blueprintId, brain, builderUnit, scaledCount);
    }

    ++builderIndex;
  }

  return 0;
}

/**
 * Address: 0x0058DC60 (FUN_0058DC60, cfunc_CAiBrainAssignUnitsToPlatoon)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to
 * `cfunc_CAiBrainAssignUnitsToPlatoonL`.
 */
int moho::cfunc_CAiBrainAssignUnitsToPlatoon(lua_State* const luaContext)
{
  return cfunc_CAiBrainAssignUnitsToPlatoonL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058DC80 (FUN_0058DC80, func_CAiBrainAssignUnitsToPlatoon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:AssignUnitsToPlatoon()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainAssignUnitsToPlatoon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainAssignUnitsToPlatoonName,
    &moho::cfunc_CAiBrainAssignUnitsToPlatoon,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainAssignUnitsToPlatoonHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058DCE0 (FUN_0058DCE0, cfunc_CAiBrainAssignUnitsToPlatoonL)
 *
 * What it does:
 * Pulls the requested unit list out of Lua, removes those units from any
 * platoon they currently belong to, looks up (or creates) the destination
 * squad on the target platoon, range-adds the units into the squad's
 * unit-set, then dispatches the `OnUnitsAddedToPlatoon` script callback.
 *
 * Argument layout: `(brain, platoonOrName, unitTable, squadClassName, squadName)`.
 * `platoonOrName` accepts either a Lua string (looked up via
 * `IArmy::GetPlatoonByName`) or a CPlatoon userdata.
 */
int moho::cfunc_CAiBrainAssignUnitsToPlatoonL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAiBrainAssignUnitsToPlatoonHelpText, 5, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonOrNameObject(LuaPlus::LuaStackObject(state, 2));
  const LuaPlus::LuaObject unitTableObject(LuaPlus::LuaStackObject(state, 3));

  ESquadClass squadClass{};
  gpg::RRef squadClassRef{};
  (void)gpg::RRef_ESquadClass(&squadClassRef, &squadClass);

  const LuaPlus::LuaStackObject squadClassArg(state, 4);
  const char* const squadClassName = lua_tostring(rawState, 4);
  if (!squadClassName) {
    squadClassArg.TypeError("string");
  }
  SCR_GetEnum(state, squadClassName, squadClassRef);

  const LuaPlus::LuaObject squadNameObject(LuaPlus::LuaStackObject(state, 5));

  if (!unitTableObject.IsTable()) {
    return 1;
  }

  CPlatoon* targetPlatoon = nullptr;
  if (platoonOrNameObject.IsString()) {
    targetPlatoon = brain->mArmy->GetPlatoonByName(platoonOrNameObject.GetString());
  } else {
    targetPlatoon = SCR_FromLua_CPlatoon(platoonOrNameObject, state);
  }

  if (targetPlatoon == nullptr) {
    return 1;
  }

  SEntitySetTemplateUnit incomingUnits{};
  PopulateUnitSetFromLuaList(incomingUnits, unitTableObject);

  brain->mArmy->RemoveUnitsFromPlatoons(&incomingUnits);

  CSquad* destinationSquad = targetPlatoon->GetSquad(squadClass);
  if (destinationSquad == nullptr) {
    destinationSquad = CSquad::AllocateOnPlatoon(targetPlatoon, squadClass, squadNameObject.GetString());
  }

  destinationSquad->mUnits.AddRange(incomingUnits.mVec.begin(), incomingUnits.mVec.end());

  targetPlatoon->mHasLuaList = 0;
  (void)targetPlatoon->RunScript("OnUnitsAddedToPlatoon");
  return 1;
}

/**
 * Address: 0x0058D650 (FUN_0058D650, cfunc_CAiBrainMakePlatoon)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainMakePlatoonL`.
 */
int moho::cfunc_CAiBrainMakePlatoon(lua_State* const luaContext)
{
  return cfunc_CAiBrainMakePlatoonL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058D670 (FUN_0058D670, func_CAiBrainMakePlatoon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:MakePlatoon()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainMakePlatoon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainMakePlatoonName,
    &moho::cfunc_CAiBrainMakePlatoon,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainMakePlatoonHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058D6D0 (FUN_0058D6D0, cfunc_CAiBrainMakePlatoonL)
 *
 * What it does:
 * Two-mode platoon constructor:
 *
 * - String form `(brain, name, planName)`: directly calls `IArmy::MakePlatoon`
 *   and pushes the result, returning nil if creation fails.
 *
 * - Table form `(brain, configTable)`: looks up the army-pool platoon, reads
 *   the new platoon's name and plan from `configTable[1]/[2]`, creates the
 *   platoon, then walks every table row in `configTable` and for each
 *   `[bpName, ?, count, squadClassName, squadName]` config row pulls
 *   `count` matching live units out of the army-pool's unassigned squad,
 *   removes them from any prior platoon, and inserts them into the requested
 *   squad on the new platoon (creating the squad if needed).
 */
int moho::cfunc_CAiBrainMakePlatoonL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgRangeWarning, kAiBrainMakePlatoonHelpText, 2, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject nameOrConfigObject(LuaPlus::LuaStackObject(state, 2));

  if (!nameOrConfigObject.IsTable()) {
    // String form: arg2 = platoon name, arg3 = plan name.
    if (nameOrConfigObject.IsString() && argumentCount > 2) {
      const LuaPlus::LuaObject planObject(LuaPlus::LuaStackObject(state, 3));
      if (planObject.IsString()) {
        CPlatoon* const newPlatoon =
          brain->mArmy->MakePlatoon(nameOrConfigObject.GetString(), planObject.GetString());
        if (newPlatoon != nullptr) {
          newPlatoon->mLuaObj.PushStack(state);
          return 1;
        }
      }
    }

    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  // Table form: full multi-squad platoon configuration.
  CPlatoon* const armyPool = brain->mArmy->GetPlatoonByName("ArmyPool");
  if (armyPool == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  const int configRowCount = nameOrConfigObject.GetCount();
  const LuaPlus::LuaObject platoonNameRow = nameOrConfigObject[1];
  const LuaPlus::LuaObject platoonPlanRow = nameOrConfigObject[2];

  // Cache name/plan into local strings since the Lua-side strings may be
  // invalidated by subsequent table lookups.
  msvc8::string platoonName;
  platoonName.assign(platoonNameRow.GetString());
  msvc8::string platoonPlan;
  platoonPlan.assign(platoonPlanRow.GetString());

  CPlatoon* const newPlatoon = brain->mArmy->MakePlatoon(platoonName.c_str(), platoonPlan.c_str());
  if (newPlatoon == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  for (int row = 1; row <= configRowCount; ++row) {
    const LuaPlus::LuaObject squadConfigRow = nameOrConfigObject[row];
    if (!squadConfigRow.IsTable()) {
      continue;
    }

    const LuaPlus::LuaObject blueprintIdObject = squadConfigRow[1];
    const LuaPlus::LuaObject countObject = squadConfigRow[3];
    const LuaPlus::LuaObject squadNameObject = squadConfigRow[5];
    const LuaPlus::LuaObject squadClassNameObject = squadConfigRow[4];

    ESquadClass squadClass{};
    gpg::RRef squadClassRef{};
    (void)gpg::RRef_ESquadClass(&squadClassRef, &squadClass);
    SCR_GetEnum(state, squadClassNameObject.GetString(), squadClassRef);

    SEntitySetTemplateUnit pulledUnits{};
    armyPool->GetUnassignedUnitsWithBP(blueprintIdObject.GetString(), countObject.GetInteger(), pulledUnits);
    brain->mArmy->RemoveUnitsFromPlatoons(&pulledUnits);

    CSquad* destinationSquad = newPlatoon->GetSquad(squadClass);
    if (destinationSquad == nullptr) {
      destinationSquad = CSquad::AllocateOnPlatoon(newPlatoon, squadClass, squadNameObject.GetString());
    }

    destinationSquad->mUnits.AddRange(pulledUnits.mVec.begin(), pulledUnits.mVec.end());
    newPlatoon->mHasLuaList = 0;
  }

  newPlatoon->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0058BF80 (FUN_0058BF80, cfunc_CAiBrainCanBuildPlatoon)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CAiBrainCanBuildPlatoonL`.
 */
int moho::cfunc_CAiBrainCanBuildPlatoon(lua_State* const luaContext)
{
  return cfunc_CAiBrainCanBuildPlatoonL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0058BFA0 (FUN_0058BFA0, func_CAiBrainCanBuildPlatoon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiBrain:CanBuildPlatoon()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiBrainCanBuildPlatoon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kAiBrainCanBuildPlatoonName,
    &moho::cfunc_CAiBrainCanBuildPlatoon,
    &CScrLuaMetatableFactory<CScriptObject*>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainCanBuildPlatoonHelpText
  );
  return &binder;
}

/**
 * Address: 0x0058C000 (FUN_0058C000, cfunc_CAiBrainCanBuildPlatoonL)
 *
 * What it does:
 * Decides whether the brain's army can currently construct every blueprint
 * row in a platoon template table, optionally using only a caller-supplied
 * subset of factories. On success, returns a Lua array of the concrete
 * factory units used (one per template row). On failure (any row has no
 * available factory, or the suggested factory list is empty after
 * filtering), pushes nil.
 *
 * Lua signature: `CAiBrain:CanBuildPlatoon(platoonTemplate [, suggestedFactories])`.
 */
int moho::cfunc_CAiBrainCanBuildPlatoonL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgRangeWarning, kAiBrainCanBuildPlatoonHelpText, 2, 3, argumentCount);
  }

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject templateTable(LuaPlus::LuaStackObject(state, 2));
  if (!templateTable.IsTable()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  gpg::core::FastVector<Unit*> candidateFactories;

  if (argumentCount > 2) {
    const LuaPlus::LuaObject suggestedObject(LuaPlus::LuaStackObject(state, 3));
    if (!suggestedObject.IsTable()) {
      LuaPlus::LuaState::Error(state, kAiBrainSuggestedFactoryListNotTable);
    }

    const int suggestedCount = suggestedObject.GetCount();
    for (int row = 1; row <= suggestedCount; ++row) {
      const LuaPlus::LuaObject rowObject = suggestedObject[row];
      if (Unit* const unit = SCR_GetUnitOptional(rowObject); unit != nullptr) {
        candidateFactories.PushBack(unit);
      }
    }

    // Binary preserves a "no usable slots" bail here. In modern terms, this
    // translates to an empty candidate list once filtering is done.
    const std::size_t candidateSize = static_cast<std::size_t>(candidateFactories.end_ - candidateFactories.start_);
    const std::size_t candidateCap = static_cast<std::size_t>(candidateFactories.capacity_ - candidateFactories.start_);
    if (candidateSize == 0u || candidateSize == candidateCap) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }
  }

  // For each template row, look up an available factory and collect the
  // chosen unit. Any row that can't be satisfied aborts the whole platoon
  // check with a nil result.
  std::vector<Unit*> chosenFactories;
  const int templateCount = templateTable.GetCount();
  for (int row = 1; row <= templateCount; ++row) {
    const LuaPlus::LuaObject rowObject = templateTable[row];
    if (!rowObject.IsTable()) {
      continue;
    }

    const LuaPlus::LuaObject blueprintIdObject = rowObject[1];
    const char* const blueprintId = blueprintIdObject.GetString();

    Unit* const availableBuilder = FindAvailableFactory(candidateFactories, blueprintId, brain);
    if (availableBuilder == nullptr) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }
    chosenFactories.push_back(availableBuilder);
  }

  // All rows satisfied — emit a Lua array of the concrete factory units.
  LuaPlus::LuaObject resultArray;
  resultArray.AssignNewTable(state, static_cast<std::int32_t>(chosenFactories.size()), 0);
  for (std::size_t index = 0; index < chosenFactories.size(); ++index) {
    const LuaPlus::LuaObject unitLuaObject = chosenFactories[index]->GetLuaObject();
    resultArray.Insert(static_cast<std::int32_t>(index + 1u), unitLuaObject);
  }
  resultArray.PushStack(state);
  return 1;
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_BuildReserveMapTypeInfo_f3fc29, preregister_BuildReserveMapTypeInfo)

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
  struct CAiBrainLuaFuncDefBootstrap
  {
    CAiBrainLuaFuncDefBootstrap()
    {
      (void)::moho::func_CAiBrainIsOpponentAIRunning_LuaFuncDef();
      (void)::moho::func_CAiBrainGetArmyIndex_LuaFuncDef();
      (void)::moho::func_CAiBrainGetFactionIndex_LuaFuncDef();
      (void)::moho::func_CAiBrainSetCurrentPlan_LuaFuncDef();
      (void)::moho::func_CAiBrainGetPersonality_LuaFuncDef();
      (void)::moho::func_CAiBrainSetCurrentEnemy_LuaFuncDef();
      (void)::moho::func_CAiBrainGetCurrentEnemy_LuaFuncDef();
      (void)::moho::func_CAiBrainGetUnitBlueprint_LuaFuncDef();
      (void)::moho::func_CAiBrainGetArmyStat_LuaFuncDef();
      (void)::moho::func_CAiBrainSetArmyStat_LuaFuncDef();
      (void)::moho::func_CAiBrainAddArmyStat_LuaFuncDef();
      (void)::moho::func_CAiBrainSetGreaterOf_LuaFuncDef();
      (void)::moho::func_CAiBrainGetBlueprintStat_LuaFuncDef();
      (void)::moho::func_CAiBrainGetCurrentUnits_LuaFuncDef();
      (void)::moho::func_CAiBrainSetArmyStatsTrigger_LuaFuncDef();
      (void)::moho::func_CAiBrainRemoveArmyStatsTrigger_LuaFuncDef();
      (void)::moho::func_CAiBrainGetListOfUnits_LuaFuncDef();
      (void)::moho::func_CAiBrainSetResourceSharing_LuaFuncDef();
      (void)::moho::func_CAiBrainGetArmyStartPos_LuaFuncDef();
      (void)::moho::func_CAiBrainCreateUnitNearSpot_LuaFuncDef();
      (void)::moho::func_CAiBrainFindPlaceToBuild_LuaFuncDef();
      (void)::moho::func_CAiBrainGetAttackVectors_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyStored_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyIncome_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyUsage_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyRequested_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyTrend_LuaFuncDef();
      (void)::moho::func_CAiBrainGetMapWaterRatio_LuaFuncDef();
      (void)::moho::func_CAiBrainGetEconomyStoredRatio_LuaFuncDef();
      (void)::moho::func_CAiBrainGiveResource_LuaFuncDef();
      (void)::moho::func_CAiBrainGiveStorage_LuaFuncDef();
      (void)::moho::func_CAiBrainTakeResource_LuaFuncDef();
      (void)::moho::func_CAiBrainFindUnit_LuaFuncDef();
      (void)::moho::func_CAiBrainFindUpgradeBP_LuaFuncDef();
      (void)::moho::func_CAiBrainFindUnitToUpgrade_LuaFuncDef();
      (void)::moho::func_CAiBrainDecideWhatToBuild_LuaFuncDef();
      (void)::moho::func_CAiBrainGetAvailableFactories_LuaFuncDef();
      (void)::moho::func_CAiBrainGetThreatAtPosition_LuaFuncDef();
      (void)::moho::func_CAiBrainGetThreatBetweenPositions_LuaFuncDef();
      (void)::moho::func_CAiBrainGetThreatsAroundPosition_LuaFuncDef();
      (void)::moho::func_CAiBrainPickBestAttackVector_LuaFuncDef();
      (void)::moho::func_CAiBrainCanBuildStructureAt_LuaFuncDef();
      (void)::moho::func_CAiBrainAssignThreatAtPosition_LuaFuncDef();
      (void)::moho::func_CAiBrainGetHighestThreatPosition_LuaFuncDef();
      (void)::moho::func_CAiBrainBuildStructure_LuaFuncDef();
      (void)::moho::func_CAiBrainNumCurrentlyBuilding_LuaFuncDef();
      (void)::moho::func_CAiBrainBuildUnit_LuaFuncDef();
      (void)::moho::func_CAiBrainIsAnyEngineerBuilding_LuaFuncDef();
      (void)::moho::func_CAiBrainGetNumPlatoonsWithAI_LuaFuncDef();
      (void)::moho::func_CAiBrainGetNumPlatoonsTemplateNamed_LuaFuncDef();
      (void)::moho::func_CAiBrainPlatoonExists_LuaFuncDef();
      (void)::moho::func_CAiBrainGetPlatoonsList_LuaFuncDef();
      (void)::moho::func_CAiBrainDisbandPlatoon_LuaFuncDef();
      (void)::moho::func_CAiBrainDisbandPlatoonUniquelyNamed_LuaFuncDef();
      (void)::moho::func_CAiBrainGetPlatoonUniquelyNamed_LuaFuncDef();
      (void)::moho::func_CAiBrainGetNoRushTicks_LuaFuncDef();
      (void)::moho::func_CAiBrainSetUpAttackVectorsToArmy_LuaFuncDef();
      (void)::moho::func_CAiBrainFindClosestArmyWithBase_LuaFuncDef();
      (void)::moho::func_CAiBrainGetUnitsAroundPoint_LuaFuncDef();
      (void)::moho::func_CAiBrainGetNumUnitsAroundPoint_LuaFuncDef();
      (void)::moho::func_CAiBrainCheckBlockingTerrain_LuaFuncDef();
      (void)::moho::func_CAiBrainBuildPlatoon_LuaFuncDef();
      (void)::moho::func_CAiBrainAssignUnitsToPlatoon_LuaFuncDef();
      (void)::moho::func_CAiBrainMakePlatoon_LuaFuncDef();
      (void)::moho::func_CAiBrainCanBuildPlatoon_LuaFuncDef();
    }
  };

  const CAiBrainLuaFuncDefBootstrap gCAiBrainLuaFuncDefBootstrap{};
} // namespace
