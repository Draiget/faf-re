#include "moho/ai/CAiBrain.h"

#include <cmath>
#include <cstring>
#include <initializer_list>
#include <limits>
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
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/Stats.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/SConditionTriggerTypes.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/sim/STIMap.h"
#include "platform/Platform.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace moho
{
  class CUnitCommand;

  CUnitCommand* func_OrderBuildStructure(
    Wm3::Vector3f* ori,
    CAiBrain* brain,
    Unit* builder,
    const char* bpName,
    Wm3::Vector3f* pos,
    float angle
  );
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
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedArgRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kAiBrainSetUpAttackVectorsToArmyName = "SetUpAttackVectorsToArmy";
  constexpr const char* kAiBrainSetUpAttackVectorsToArmyHelpText = "CAiBrain:SetUpAttackVectorsToArmy()";
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
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
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
    // Address: 0x007732C0 (FUN_007732C0, Moho::CEconStorage::Chng)
    if (storage.economyRuntime == nullptr) {
      return;
    }

    const std::int64_t signedDirection = static_cast<std::int64_t>(direction);
    constexpr std::size_t kAccumOffset = 0x40;
    constexpr std::size_t kAccumCount = 4;
    for (std::size_t i = 0; i < kAccumCount; ++i) {
      auto* const accumulator =
        reinterpret_cast<std::int64_t*>(storage.economyRuntime + kAccumOffset + (i * sizeof(std::int64_t)));
      const std::int64_t delta = static_cast<std::int64_t>(storage.amounts[i]) * signedDirection;
      *accumulator += delta;
    }
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

  void UnlinkBuildResourceInfoLink(SBuildResourceInfoLink& link)
  {
    SBuildResourceInfoLink** cursor = link.mOwnerSlot;
    if (!cursor) {
      return;
    }

    while (*cursor != &link) {
      if (!*cursor) {
        return;
      }
      cursor = &(*cursor)->mNext;
    }

    *cursor = link.mNext;
    link.mOwnerSlot = nullptr;
    link.mNext = nullptr;
  }

  void DestroyBuildStructureTree(SBuildStructurePositionNode* node)
  {
    while (node && node->mIsNil == 0u) {
      DestroyBuildStructureTree(node->right);
      SBuildStructurePositionNode* const left = node->left;

      // Matches sub_5812C0 unlink order (+0x1C link first, then +0x14 link).
      UnlinkBuildResourceInfoLink(node->mBuildInfo.mResourceLink);
      UnlinkBuildResourceInfoLink(node->mBuildInfo.mPlacementLink);
      ::operator delete(node);

      node = left;
    }
  }

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
      type = ResolveTypeByAnyName(
        {"std::map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>",
         "std::map<Wm3::IVector2<int>, Moho::SBuildReserveInfo>",
         "map<Wm3::IVector2<int>,Moho::SBuildReserveInfo>"}
      );
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
} // namespace

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
  gpg::RType* type = sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiBrain));
    sType = type;
  }
  return type;
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
 * Resolves one blueprint id, validates builder capability lane, and emits
 * `UNITCOMMAND_BuildFactory` commands for the builder `count` times.
 */
bool CAiBrain::BuildUnit(const char* const blueprintId, CAiBrain* const brain, Unit* const builder, const int count)
{
  if (brain == nullptr || brain->mSim == nullptr || brain->mSim->mRules == nullptr) {
    return false;
  }

  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintId);
  RUnitBlueprint* const blueprint = brain->mSim->mRules->GetUnitBlueprint(lookupId);
  if (!UnitHasBuilderSubsystem(builder) || blueprint == nullptr) {
    return false;
  }

  if (count <= 0) {
    return true;
  }

  BVSet<EntId, EntIdUniverse> selectedUnits{};
  (void)selectedUnits.mBits.Add(static_cast<unsigned int>(builder->id_));

  for (int issueIndex = 0; issueIndex < count; ++issueIndex) {
    SSTICommandIssueData issueData(EUnitCommandType::UNITCOMMAND_BuildFactory);
    issueData.mBlueprint = blueprint;
    brain->mSim->IssueCommand(selectedUnits, issueData, false);
  }

  return true;
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
 */
moho::Unit* moho::FindAvailableFactory(
  gpg::core::FastVector<Unit*>& candidateList, const char* const blueprintId, CAiBrain* const brain
)
{
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
  // factories owned by this brain's army.
  if (candidateList.start_ == candidateList.end_) {
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
        candidateList.PushBack(unit);
      }
    }
  }

  // Linear walk for the first builder that passes every buildability gate.
  for (Unit* const* it = candidateList.start_; it != candidateList.end_; ++it) {
    Unit* const candidate = *it;
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
