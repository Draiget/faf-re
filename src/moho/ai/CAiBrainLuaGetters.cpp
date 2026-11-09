#include "moho/ai/CAiBrainLuaPrivate.h"

namespace
{
  constexpr const char* kAiBrainGetUnitBlueprintHelpText = "blueprint = brain:GetUnitBlueprint(bpName)";
  constexpr const char* kAiBrainGetListOfUnitsHelpText =
    "brain:GetListOfUnits(entityCategory, needToBeIdle, requireBuilt)";
  constexpr const char* kAiBrainGetListOfUnitsName = "GetListOfUnits";
  constexpr const char* kAiBrainGetArmyStartPosHelpText = "brain:GetArmyStartPos()";
  constexpr const char* kAiBrainGetArmyStartPosName = "GetArmyStartPos";
  constexpr const char* kAiBrainFindPlaceToBuildHelpText =
    "brain:FindPlaceToBuild(type, structureName, buildingTypes, relative, builder, "
    "optIgnoreAlliance, optOverridePosX, optOverridePosZ, optIgnoreThreatOver)";
  constexpr const char* kAiBrainFindPlaceToBuildName = "FindPlaceToBuild";
  constexpr const char* kAiBrainGetCurrentEnemyHelpText = "Return this brain's current enemy";
  constexpr const char* kAiBrainGetCurrentEnemyName = "GetCurrentEnemy";
  constexpr const char* kAiBrainGetUnitBlueprintName = "GetUnitBlueprint";
  constexpr const char* kAiBrainGetArmyStatHelpText = "brain:GetArmyStat(StatName,defaultValue)";
  constexpr const char* kAiBrainGetArmyStatName = "GetArmyStat";
  constexpr const char* kAiBrainGetBlueprintStatHelpText = "Return a blueprint stat filtered by category";
  constexpr const char* kAiBrainGetBlueprintStatName = "GetBlueprintStat";
  constexpr const char* kAiBrainGetCurrentUnitsHelpText = "Return how many units of the given categories exist";
  constexpr const char* kAiBrainGetCurrentUnitsName = "GetCurrentUnits";
  constexpr const char* kAiBrainActiveUnitsStatPath = "Units_Active";
  constexpr const char* kAiBrainGetAttackVectorsHelpText = "CAiBrain:GetAttackVectors()";
  constexpr const char* kAiBrainGetAttackVectorsName = "GetAttackVectors";
  constexpr const char* kAiBrainGetUnitsAroundPointHelpText = "CAiBrain:GetUnitsAroundPoint()";
  constexpr const char* kAiBrainGetUnitsAroundPointName = "GetUnitsAroundPoint";
  constexpr const char* kAiBrainGetNumUnitsAroundPointHelpText = "CAiBrain:GetNumUnitsAroundPoint()";
  constexpr const char* kAiBrainGetNumUnitsAroundPointName = "GetNumUnitsAroundPoint";
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
  constexpr const char* kAiBrainFindUnitHelpText =
    "brain:FindUnit(unitCategory, needToBeIdle) -- Return an unit that matches the unit name (can specify idle or not)";
  constexpr const char* kAiBrainFindUnitName = "FindUnit";
  constexpr const char* kAiBrainFindUpgradeBPHelpText =
    "brain:FindUpgradeBP(unitName, upgradeList) -- Return an upgrade blueprint for the unit passed in";
  constexpr const char* kAiBrainFindUpgradeBPName = "FindUpgradeBP";
  constexpr const char* kAiBrainFindUnitToUpgradeHelpText =
    "brain:FindUnitToUpgrade(upgradeList) -- Return a unit and it's upgrade blueprint";
  constexpr const char* kAiBrainFindUnitToUpgradeName = "FindUnitToUpgrade";
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
  constexpr const char* kAiBrainGetHighestThreatPositionName = "GetHighestThreatPosition";
  constexpr const char* kAiBrainGetHighestThreatPositionHelpText =
    "CAiBrain:GetHighestThreatPosition(radius, restrictToOnMap[, threatTypeName[, armyIndex]]) - "
    "returns `(position, threat)` for the cell with the highest threat across this brain's "
    "influence map. Ties are broken by closeness to the army start position";
  constexpr const char* kAiBrainGetHighestThreatPositionInvalidArmyError = "Invalid army index passed in to GetHighestThreatPosition";
  constexpr const char* kAiBrainNumCurrentlyBuildingHelpText =
    "brain:NumCurrentlyBuilding( entityCategoryOfBuildee, entityCategoryOfBuilder )";
  constexpr const char* kAiBrainNumCurrentlyBuildingName = "NumCurrentlyBuilding";
  constexpr const char* kAiBrainIsAnyEngineerBuildingHelpText = "brain:IsAnyEngineerBuilding(category)";
  constexpr const char* kAiBrainIsAnyEngineerBuildingName = "IsAnyEngineerBuilding";
  constexpr const char* kAiBrainGetNumPlatoonsWithAIHelpText = "GetNumPlatoonsWithAI";
  constexpr const char* kAiBrainGetNumPlatoonsWithAIName = "GetNumPlatoonsWithAI";
  constexpr const char* kAiBrainGetNumPlatoonsTemplateNamedHelpText = "GetNumPlatoonsTemplateNamed";
  constexpr const char* kAiBrainGetNumPlatoonsTemplateNamedName = "GetNumPlatoonsTemplateNamed";
  constexpr const char* kAiBrainGetPlatoonsListHelpText = "CAiBrain:GetPlatoonsList()";
  constexpr const char* kAiBrainGetPlatoonsListName = "GetPlatoonsList";
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
  constexpr const char* kAiBrainGetPersonalityHelpText = "Return the personality for this brain to use";
  constexpr const char* kAiBrainGetPersonalityName = "GetPersonality";
  constexpr const char* kAiBrainCanBuildStructureAtName = "CanBuildStructureAt";
  constexpr const char* kAiBrainCanBuildStructureAtHelpText = "brain:CanBuildStructureAt(blueprint, location)";
  constexpr const char* kAiBrainFindClosestArmyWithBaseName = "FindClosestArmyWithBase";
  constexpr const char* kAiBrainFindClosestArmyWithBaseHelpText =
    "CAiBrain:FindClosestArmyWithBase(allianceState) - returns the brain of the closest "
    "army (filtered by alliance with this brain) that owns at least one structure, or nil";
  constexpr const char* kAiBrainCanBuildPlatoonName = "CanBuildPlatoon";
  constexpr const char* kAiBrainCanBuildPlatoonHelpText =
    "CAiBrain:CanBuildPlatoon(platoonTemplate, suggestedFactories?) - returns either nil "
    "(cannot build) or a table of concrete factory units that can collectively build every "
    "row of the template; optionally restricted to `suggestedFactories`";
  constexpr const char* kAiBrainSuggestedFactoryListNotTable = "Suggested factory list is not a table!";
  constexpr const char* kEngineerCategoryName = "ENGINEER";
  constexpr std::int32_t kBuildingStateTag = 5;

  [[nodiscard]] moho::CAiBrain* DecodeEconomyResourceQueryArgs(
    LuaPlus::LuaState* const state,
    const char* const helpText,
    moho::EEconResource& outResource
  )
  {
    lua_State* const rawState = state->m_state;
    moho::SCR_ExpectExactArgs(state, 2, helpText);

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

    const fa::vector<moho::WeakPtr<moho::CUnitCommand>>& commands = unit->CommandQueue->mCommandVec;
    if (commands.empty()) {
      return false;
    }

    return commands.front().GetObjectPtr() != nullptr;
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

    const std::uint32_t armyIndex = static_cast<std::uint32_t>(brain->mArmy->mConstDat.mArmyIndex);
    moho::CEntityDbAllUnitsNode* node = sim->mEntityDB->AllUnitsEnd(armyIndex);
    moho::CEntityDbAllUnitsNode* const endNode = sim->mEntityDB->AllUnitsEnd(armyIndex + 1u);
    while (node != endNode) {
      moho::Unit* const unit = moho::EntityDB::UnitFromAllUnitsNode(node);
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

      node = moho::EntityDB::NextAllUnitsNode(node);
    }

    return nullptr;
  }
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainIsOpponentAIRunningName,
    &moho::cfunc_CAiBrainIsOpponentAIRunning,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainIsOpponentAIRunningHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);
  Sim* const sim = brain->mArmy->GetSim();

  bool shouldRunOpponentAi = false;
  if (!CFG_GetArgOption("/noai", 0u, nullptr)) {
    CSimConVarBase* const runOpponentAiConVar = &moho::gSimConVar_AI_RunOpponentAI;
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetArmyIndexName,
    &moho::cfunc_CAiBrainGetArmyIndex,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainGetArmyIndexHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  lua_pushnumber(rawState, static_cast<float>(brain->mArmy->mConstDat.mArmyIndex + 1));
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetFactionIndexName,
    &moho::cfunc_CAiBrainGetFactionIndex,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainGetFactionIndexHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  lua_pushnumber(rawState, static_cast<float>(brain->mArmy->mVarDat.mFaction + 1));
  (void)lua_gettop(rawState);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetPersonalityName,
    &moho::cfunc_CAiBrainGetPersonality,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainGetPersonalityHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetCurrentEnemyName,
    &moho::cfunc_CAiBrainGetCurrentEnemy,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainGetCurrentEnemyHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetUnitBlueprintName,
    &moho::cfunc_CAiBrainGetUnitBlueprint,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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

  moho::SCR_ExpectExactArgs(state, 2, kAiBrainGetUnitBlueprintHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetArmyStatName,
    &moho::cfunc_CAiBrainGetArmyStat,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainGetArmyStatHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetBlueprintStatName,
    &moho::cfunc_CAiBrainGetBlueprintStat,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainGetBlueprintStatHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  LuaPlus::LuaStackObject statNameArg(state, 2);
  const char* const statName = lua_tostring(rawState, 2);
  if (statName == nullptr) {
    statNameArg.TypeError("string");
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 3));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetCurrentUnitsName,
    &moho::cfunc_CAiBrainGetCurrentUnits,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainGetCurrentUnitsHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetListOfUnitsName,
    &moho::cfunc_CAiBrainGetListOfUnits,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  const bool needToBeIdle = LuaPlus::LuaStackObject(state, 3).GetBoolean();
  bool requireBuilt = true;
  if (argumentCount > 3) {
    requireBuilt = LuaPlus::LuaStackObject(state, 4).GetBoolean();
  }

  EntitySetTemplate<Unit> categoryUnits{};
  brain->mArmy->GetUnits(&categoryUnits, categorySet);

  // Retail (0x00587A30..0x00587A98) adds the units passing the filter back
  // into the SAME set it iterates (`Add` at 0x0057DDD0 with this = the
  // GetUnits output at [esp+0x60]); every unit is already present, so the
  // filter is a no-op and the returned table holds every category unit,
  // dead/destroy-queued/being-built/busy ones included. Kept bug-for-bug.
  for (Entity* const* it = categoryUnits.mVec.begin(); it != categoryUnits.mVec.end(); ++it) {
    Unit* const unit = static_cast<Unit*>(*it);
    if (unit == nullptr) {
      continue;
    }

    if (unit->IsDead() || unit->DestroyQueued()) {
      continue;
    }

    if (unit->IsBeingBuilt() && requireBuilt) {
      continue;
    }

    if (needToBeIdle && !unit->IsIdleState()) {
      continue;
    }

    (void)categoryUnits.Add(unit);
  }

  // Retail builds the table inline: AssignNewTable(size, 0) then the append
  // `Insert(obj)` (0x00909AF0) of each unit's `GetLuaObject()`.
  LuaPlus::LuaObject outUnits{};
  outUnits.AssignNewTable(brain->mLuaObj.m_state, static_cast<std::int32_t>(categoryUnits.mVec.Size()), 0);
  for (Entity* const* it = categoryUnits.mVec.begin(); it != categoryUnits.mVec.end(); ++it) {
    outUnits.Insert(static_cast<Unit*>(*it)->GetLuaObject());
  }

  outUnits.PushStack(state);
  return 1;
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetArmyStartPosName,
    &moho::cfunc_CAiBrainGetArmyStartPos,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainGetArmyStartPosHelpText);

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
    enumRef = gpg::MakeRRef<moho::EAlliance>(&optIgnoreAlliance);
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
    fa::string structureFilename;
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

    const EntityCategorySet* const hydrocarbonCategory = sim->mRules->GetEntityCategory("HYDROCARBON");
    const EDepositType wantedDeposit =
      EntityCategory::HasBlueprint(structureBp, hydrocarbonCategory) ? kHydrocarbon : kMass;

    struct SDepositCandidate
    {
      float centerX;
      float centerZ;
      float distanceSq;
    };
    fa::vector<SDepositCandidate> candidates;
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

    fa::sort(candidates.data(), candidates.data() + candidates.size(), [](const SDepositCandidate& a, const SDepositCandidate& b) {
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
  float closestDist = gpg::pInf;

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
      // 0x0058B081: `comiss closest, cur; jbe skip` -- an unordered (NaN)
      // distance is skipped too, so this is `!(closest > cur)`.
      if (!(closestDist > curDist)) {
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

      // Threat gate. 0x0058B1EA-0x0058B22A divides each truncated world
      // coordinate by mGridSize once (`idiv edi`) and clamps that quotient
      // directly against `width-1` / `height-1` -- there is no second divide.
      bool unthreatened = true;
      if (optIgnoreThreatOver > 0) {
        CInfluenceMap* const igrid = mArmy->GetIGrid();
        const int mGridSize = igrid->mGridSize;
        const int gridWidth = igrid->mWidth;
        int xCell = static_cast<int>(worldX) / mGridSize;
        if (xCell >= gridWidth - 1) {
          xCell = gridWidth - 1;
        }
        if (xCell < 0) {
          xCell = 0;
        }
        int zCell = static_cast<int>(worldZ) / mGridSize;
        if (zCell >= igrid->mHeight - 1) {
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

  if (closestDist >= gpg::pInf) {
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainFindPlaceToBuildName,
    &moho::cfunc_CAiBrainFindPlaceToBuild,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetAttackVectorsName,
    &moho::cfunc_CAiBrainGetAttackVectors,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainGetAttackVectorsHelpText);

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
  for (const SPointVector& attackVector : brain->mAttackVectors) {
    const LuaPlus::LuaObject vectorObject = SCR_ToLua<SPointVector>(state, attackVector);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetEconomyStoredName,
    &moho::cfunc_CAiBrainGetEconomyStored,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetEconomyIncomeName,
    &moho::cfunc_CAiBrainGetEconomyIncome,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetEconomyUsageName,
    &moho::cfunc_CAiBrainGetEconomyUsage,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetEconomyRequestedName,
    &moho::cfunc_CAiBrainGetEconomyRequested,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetEconomyTrendName,
    &moho::cfunc_CAiBrainGetEconomyTrend,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetMapWaterRatioName,
    &moho::cfunc_CAiBrainGetMapWaterRatio,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainGetMapWaterRatioHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetEconomyStoredRatioName,
    &moho::cfunc_CAiBrainGetEconomyStoredRatio,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainGetEconomyStoredRatioHelpText);

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
    // 0x0058F6A4-0x0058F6F7: the u64 max-storage lane is converted to float
    // (fild/fchs/faddp at PC24, then `fst dword`), compared `> 0`, and the
    // ratio is a float `divss stored, maxStorage` -- not a double division.
    const float maxStorage = static_cast<float>(SelectResourceLane(economyInfo->economy.mMaxStorage, resource));
    if (maxStorage > 0.0f) {
      ratio = SelectResourceLane(economyInfo->economy.mStored, resource) / maxStorage;
    }
  }

  lua_pushnumber(rawState, ratio);
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainFindUnitHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  const bool needToBeIdle = LuaPlus::LuaStackObject(state, 3).GetBoolean();

  EntitySetTemplate<Unit> categoryUnits{};
  brain->mArmy->GetUnits(&categoryUnits, categorySet);

  for (Entity* const* it = categoryUnits.mVec.begin(); it != categoryUnits.mVec.end(); ++it) {
    Unit* const unit = static_cast<Unit*>(*it);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainFindUnitName,
    &moho::cfunc_CAiBrainFindUnit,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainFindUpgradeBPName,
    &moho::cfunc_CAiBrainFindUpgradeBP,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainFindUpgradeBPHelpText);

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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainFindUnitToUpgradeHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainFindUnitToUpgradeName,
    &moho::cfunc_CAiBrainFindUnitToUpgrade,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainFindUnitToUpgradeHelpText
  );
  return &binder;
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
 * builds an empty `EntitySetTemplate<Unit>`, calls
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

  EntitySetTemplate<Unit> availableFactories{};
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetAvailableFactoriesName,
    &moho::cfunc_CAiBrainGetAvailableFactories,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    threatRef = gpg::MakeRRef<moho::EThreatType>(&threatType);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetThreatAtPositionName,
    &moho::cfunc_CAiBrainGetThreatAtPosition,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    threatRef = gpg::MakeRRef<moho::EThreatType>(&threatType);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetThreatBetweenPositionsName,
    &moho::cfunc_CAiBrainGetThreatBetweenPositions,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetThreatsAroundPositionName,
    &moho::cfunc_CAiBrainGetThreatsAroundPosition,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
 * into a `fa::vector<SPositionThreat>` via
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
    threatRef = gpg::MakeRRef<moho::EThreatType>(&threatType);
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

  fa::vector<SPositionThreat> threats;
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainCanBuildStructureAtName,
    &moho::cfunc_CAiBrainCanBuildStructureAt,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainCanBuildStructureAtHelpText);

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
    threatRef = gpg::MakeRRef<moho::EThreatType>(&threatType);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetHighestThreatPositionName,
    &moho::cfunc_CAiBrainGetHighestThreatPosition,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGetHighestThreatPositionHelpText
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainNumCurrentlyBuildingName,
    &moho::cfunc_CAiBrainNumCurrentlyBuilding,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainNumCurrentlyBuildingHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject buildeeCategoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const buildeeCategory = func_GetCObj_EntityCategory(buildeeCategoryObject);

  const LuaPlus::LuaObject builderCategoryObject(LuaPlus::LuaStackObject(state, 3));
  EntityCategorySet* const builderCategory = func_GetCObj_EntityCategory(builderCategoryObject);

  std::int32_t count = 0;
  if (brain != nullptr && brain->mArmy != nullptr) {
    EntitySetTemplate<Unit> builderUnits{};
    brain->mArmy->GetUnits(&builderUnits, builderCategory);

    for (Entity* const* it = builderUnits.mVec.begin(); it != builderUnits.mVec.end(); ++it) {
      Unit* const builder = static_cast<Unit*>(*it);
      if (builder == nullptr || builder->IsDead() || builder->DestroyQueued()) {
        continue;
      }

      if (!builder->IsUnitState(UNITSTATE_Building) && !builder->IsUnitState(UNITSTATE_Upgrading)) {
        continue;
      }

      Entity* const focusedEntity = builder->FocusEntityRef.GetObjectPtr();
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainIsAnyEngineerBuildingHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  bool foundMatch = false;
  if (brain != nullptr && brain->mArmy != nullptr && brain->mSim != nullptr && brain->mSim->mRules != nullptr) {
    const EntityCategorySet* const engineerCategory = brain->mSim->mRules->GetEntityCategory(kEngineerCategoryName);

    EntitySetTemplate<Unit> engineerUnits{};
    brain->mArmy->GetUnits(&engineerUnits, const_cast<EntityCategorySet*>(engineerCategory));

    for (Entity* const* it = engineerUnits.mVec.begin(); it != engineerUnits.mVec.end(); ++it) {
      Unit* const unit = static_cast<Unit*>(*it);
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      if (!unit->IsUnitState(static_cast<EUnitState>(kBuildingStateTag))) {
        continue;
      }

      // 0x0058CBD9..0x0058CC17: the category is tested against the FOCUS
      // entity's blueprint (the structure being built), not the engineer's.
      const Entity* const focusEntity = unit->FocusEntityRef.GetObjectPtr();
      if (focusEntity == nullptr || focusEntity->BluePrint == nullptr) {
        continue;
      }

      if (EntityCategory::HasBlueprint(focusEntity->BluePrint, categorySet)) {
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainIsAnyEngineerBuildingName,
    &moho::cfunc_CAiBrainIsAnyEngineerBuilding,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetNumPlatoonsWithAIName,
    &moho::cfunc_CAiBrainGetNumPlatoonsWithAI,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainGetNumPlatoonsWithAIHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetNumPlatoonsTemplateNamedName,
    &moho::cfunc_CAiBrainGetNumPlatoonsTemplateNamed,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainGetNumPlatoonsTemplateNamedHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetPlatoonsListName,
    &moho::cfunc_CAiBrainGetPlatoonsList,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainGetPlatoonsListHelpText);

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

    if (platoon->mUniqueName.equals_no_case("ArmyPool")) {
      continue;
    }

    if (platoon->CountUnits() > 0) {
      outPlatoons.Insert(platoonLuaIndex, platoon->mLuaObj);
      ++platoonLuaIndex;
    }
  }

  outPlatoons.PushStack(state);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetPlatoonUniquelyNamedName,
    &moho::cfunc_CAiBrainGetPlatoonUniquelyNamed,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainGetPlatoonUniquelyNamedHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonNameObject(LuaPlus::LuaStackObject(state, 2));
  if (platoonNameObject.IsString() && brain != nullptr && brain->mArmy != nullptr) {
    if (const CPlatoon* const platoon = brain->mArmy->GetPlatoonByName(platoonNameObject.GetString()); platoon != nullptr) {
      platoon->mLuaObj.PushStack(state);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetNoRushTicksName,
    &moho::cfunc_CAiBrainGetNoRushTicks,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 1, kAiBrainGetNoRushTicksHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  lua_pushnumber(rawState, static_cast<float>(brain->mArmy->mVarDat.mNoRushTimer));
  (void)lua_gettop(rawState);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainFindClosestArmyWithBaseName,
    &moho::cfunc_CAiBrainFindClosestArmyWithBase,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainFindClosestArmyWithBaseHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  EAlliance requestedAlliance{};
  gpg::RRef enumRef{};
  enumRef = gpg::MakeRRef<moho::EAlliance>(&requestedAlliance);

  const LuaPlus::LuaStackObject allianceArg(state, 2);
  const char* const allianceName = lua_tostring(rawState, 2);
  if (!allianceName) {
    allianceArg.TypeError("string");
  }
  SCR_GetEnum(state, allianceName, enumRef);

  Wm3::Vec3f searchPosition{};
  brain->CenterOfArmy(&searchPosition);

  CArmyImpl* closestArmy = nullptr;
  float closestDistance = gpg::pInf;

  CAiReconDBImpl* const reconDB = brain->mArmy->GetReconDB();
  if (reconDB == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  const EntityCategorySet* const structureCategory = brain->mSim->mRules->GetEntityCategory("STRUCTURE");

  const fa::vector<ReconBlip*>& blips = reconDB->ReconGetBlips();
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
    // 0x0058EA9D-0x0058EAB9 sums `(dz*dz + dy*dy) + dx*dx` (z first).
    const float distanceSq = ((dz * dz) + (dy * dy)) + (dx * dx);
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

  EntitySetTemplate<Unit> gatheredUnits{};

  if (lua_gettop(rawState) == 5) {
    EAlliance requestedAlliance{};
    gpg::RRef allianceRef{};
    allianceRef = gpg::MakeRRef<moho::EAlliance>(&requestedAlliance);

    LuaPlus::LuaStackObject allianceArg(state, 5);
    const char* const allianceName = lua_tostring(rawState, 5);
    if (!allianceName) {
      allianceArg.TypeError("string");
    }
    SCR_GetEnum(state, allianceName, allianceRef);

    EntitySetTemplate<Unit> scratchUnits{};
    (void)CollectUnitsAroundPointFiltered(brain, &scratchUnits, categorySet, point, radius, requestedAlliance);
    gatheredUnits.mVec.AddAll(&scratchUnits.mVec);
  } else {
    EntitySetTemplate<Unit> scratchUnits{};
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetUnitsAroundPointName,
    &moho::cfunc_CAiBrainGetUnitsAroundPoint,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGetNumUnitsAroundPointName,
    &moho::cfunc_CAiBrainGetNumUnitsAroundPoint,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    allianceRef = gpg::MakeRRef<moho::EAlliance>(&requestedAlliance);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainCanBuildPlatoonName,
    &moho::cfunc_CAiBrainCanBuildPlatoon,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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

  fa::vector<Unit*> candidateFactories;

  if (argumentCount > 2) {
    const LuaPlus::LuaObject suggestedObject(LuaPlus::LuaStackObject(state, 3));
    if (!suggestedObject.IsTable()) {
      LuaPlus::LuaState::Error(state, kAiBrainSuggestedFactoryListNotTable);
    }

    const int suggestedCount = suggestedObject.GetCount();
    for (int row = 1; row <= suggestedCount; ++row) {
      const LuaPlus::LuaObject rowObject = suggestedObject[row];
      if (Unit* const unit = SCR_GetUnitOptional(rowObject); unit != nullptr) {
        candidateFactories.push_back(unit);
      }
    }

    // A suggested list that filtered down to nothing bails with nil
    // (0x0058C1BB: `if (_Myfirst) { if ((_Mylast - _Myfirst) >> 2) goto
    // haveCandidates; }`).
    if (candidateFactories.empty()) {
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
