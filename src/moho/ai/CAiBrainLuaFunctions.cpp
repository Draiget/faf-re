#include "moho/ai/CAiBrainLuaPrivate.h"

namespace moho
{

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
    const float sinHalf = fa::sin(halfAngleRad);
    const float cosHalf = fa::cos(halfAngleRad);

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

    EntitySetTemplate<Unit> selectedUnits{};
    (void)selectedUnits.Add(builder);

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
}

namespace
{
  constexpr const char* kAiBrainSetResourceSharingHelpText = "SetResourceSharing(bool)";
  constexpr const char* kAiBrainSetResourceSharingName = "SetResourceSharing";
  constexpr const char* kAiBrainCreateUnitNearSpotHelpText = "brain:CreateUnitNearSpot(unitName, posX, posY)";
  constexpr const char* kAiBrainCreateUnitNearSpotName = "CreateUnitNearSpot";
  constexpr const char* kAiBrainCreateResourceBuildingNearestHelpText =
    "brain:CreateResourceBuildingNearest(structureName, posX, posY)";
  constexpr const char* kAiBrainCreateResourceBuildingNearestName = "CreateResourceBuildingNearest";
  constexpr const char* kAiBrainSetArmyStatHelpText = "SetArmyStat(statname,val)";
  constexpr const char* kAiBrainSetArmyStatName = "SetArmyStat";
  constexpr const char* kAiBrainAddArmyStatHelpText = "AddArmyStat(statname,val)";
  constexpr const char* kAiBrainAddArmyStatName = "AddArmyStat";
  constexpr const char* kAiBrainSetGreaterOfHelpText = "SetGreaterOf(statname,val)";
  constexpr const char* kAiBrainSetGreaterOfName = "SetGreaterOf";
  constexpr const char* kAiBrainSetArmyStatsTriggerHelpText = "Sets an army stat trigger";
  constexpr const char* kAiBrainSetArmyStatsTriggerName = "SetArmyStatsTrigger";
  constexpr const char* kAiBrainRemoveArmyStatsTriggerHelpText = "Remove an army stats trigger";
  constexpr const char* kAiBrainRemoveArmyStatsTriggerName = "RemoveArmyStatsTrigger";
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
  constexpr const char* kAiBrainGiveResourceHelpText = "GiveResource(type,amount)";
  constexpr const char* kAiBrainGiveResourceName = "GiveResource";
  constexpr const char* kAiBrainGiveStorageHelpText = "GiveStorage(type,amount)";
  constexpr const char* kAiBrainGiveStorageName = "GiveStorage";
  constexpr const char* kAiBrainTakeResourceHelpText = "taken = TakeResource(type,amount)";
  constexpr const char* kAiBrainTakeResourceName = "TakeResource";
  constexpr const char* kAiBrainDecideWhatToBuildHelpText = "brain:DecideWhatToBuild(builder, type, buildingTypes)";
  constexpr const char* kAiBrainDecideWhatToBuildName = "DecideWhatToBuild";
  constexpr const char* kAiBrainBuildStructureHelpText = "brain:BuildStructure(builder, structureName, locationInfo)";
  constexpr const char* kAiBrainBuildStructureName = "BuildStructure";
  constexpr const char* kAiBrainAssignThreatAtPositionName = "AssignThreatAtPosition";
  constexpr const char* kAiBrainAssignThreatAtPositionHelpText =
    "CAiBrain:AssignThreatAtPosition(position, threatValue[, decayRate[, threatTypeName]]) - "
    "adds `threatValue` to the influence cell containing `position`, then re-derives the matching "
    "decay lane. `decayRate` is clamped to `[0, 1]` and defaults to `-1` (binary substitutes 0.01)";
  constexpr const char* kAiBrainBuildUnitHelpText = "brain:BuildUnit()";
  constexpr const char* kAiBrainBuildUnitName = "BuildUnit";
  constexpr const char* kAiBrainPlatoonExistsHelpText = "CAiBrain:PlatoonExists()";
  constexpr const char* kAiBrainPlatoonExistsName = "PlatoonExists";
  constexpr const char* kAiBrainDisbandPlatoonHelpText = "CAiBrain:DisbandPlatoon()";
  constexpr const char* kAiBrainDisbandPlatoonName = "DisbandPlatoon";
  constexpr const char* kAiBrainDisbandPlatoonUniquelyNamedHelpText = "CAiBrain:DisbandPlatoonUniquelyNamed()";
  constexpr const char* kAiBrainDisbandPlatoonUniquelyNamedName = "DisbandPlatoonUniquelyNamed";
  constexpr const char* kAiBrainSetCurrentPlanHelpText = "Set the current plan for this brain to run";
  constexpr const char* kAiBrainSetCurrentPlanName = "SetCurrentPlan";
  constexpr const char* kAiBrainSetCurrentEnemyHelpText = "Set the current enemy for this brain to attack";
  constexpr const char* kAiBrainSetCurrentEnemyName = "SetCurrentEnemy";
  constexpr const char* kAiBrainSetUpAttackVectorsToArmyName = "SetUpAttackVectorsToArmy";
  constexpr const char* kAiBrainSetUpAttackVectorsToArmyHelpText = "CAiBrain:SetUpAttackVectorsToArmy()";
  constexpr const char* kAiBrainPickBestAttackVectorName = "PickBestAttackVector";
  constexpr const char* kAiBrainPickBestAttackVectorHelpText = "CAiBrain:PickBestAttackVector()";
  // Binary string literals (bin/2025.7.1/ForgedAlliance.exe): the arg-count Warnf and the
  // two user-callback error strings emitted by CAiBrain::PickBestAttackVector.
  constexpr const char* kAiBrainPickBestAttackVectorArgCountWarning =
    "Error in CAiBrain::PickBestAttackVector: Expected 6 or 8 arguments, got 7 instead.";
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
        const std::int32_t observed = platform::AtomicLoad(&statItem->mPrimaryValueBits);
        if (candidate <= observed) {
          return;
        }

        const std::int32_t exchanged = platform::AtomicCompareExchange(&statItem->mPrimaryValueBits, candidate, observed);
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

      const std::int32_t candidateBits = std::bit_cast<std::int32_t>(candidate);

      for (;;) {
        const std::int32_t observedBits = platform::AtomicLoad(&statItem->mPrimaryValueBits);
        const float observed = std::bit_cast<float>(observedBits);
        if (candidate <= observed) {
          return;
        }

        const std::int32_t exchangedBits = platform::AtomicCompareExchange(&statItem->mPrimaryValueBits, candidateBits, observedBits);
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
  void PopulateUnitSetFromLuaList(EntitySetTemplate<Unit>& destSet, const LuaPlus::LuaObject& sourceTable)
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainSetCurrentPlanName,
    &moho::cfunc_CAiBrainSetCurrentPlan,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainSetCurrentPlanHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainSetCurrentEnemyName,
    &moho::cfunc_CAiBrainSetCurrentEnemy,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainSetCurrentEnemyHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainSetArmyStatName,
    &moho::cfunc_CAiBrainSetArmyStat,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainSetArmyStatHelpText);

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
      (void)platform::AtomicExchange(&statItem->mPrimaryValueBits, intValue);
    }
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const float floatValue = valueArg.GetNumber();
    if (CArmyStatItem* const statItem = ResolveCachedArmyStatPath(armyStats, statName); statItem != nullptr) {
      statItem->SynchronizeAsFloat();

      const std::int32_t floatValueBits = std::bit_cast<std::int32_t>(floatValue);
      (void)platform::AtomicExchange(&statItem->mPrimaryValueBits, floatValueBits);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainAddArmyStatName,
    &moho::cfunc_CAiBrainAddArmyStat,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainAddArmyStatHelpText);

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
      (void)statItem->AddPrimaryBits(intDelta);
    }
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const float floatDelta = valueArg.GetNumber();
    if (CArmyStatItem* const statItem = ResolveCachedArmyStatPath(armyStats, statName); statItem != nullptr) {
      statItem->SynchronizeAsFloat();
      (void)platform::AtomicAddFloat(&statItem->mPrimaryValueBits, floatDelta);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainSetGreaterOfName,
    &moho::cfunc_CAiBrainSetGreaterOf,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainSetGreaterOfHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainSetArmyStatsTriggerName,
    &moho::cfunc_CAiBrainSetArmyStatsTrigger,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    if (EntityCategorySet* const parsedCategorySet = func_GetCObj_EntityCategory(categoryObject);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainRemoveArmyStatsTriggerName,
    &moho::cfunc_CAiBrainRemoveArmyStatsTrigger,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainRemoveArmyStatsTriggerHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainSetResourceSharingName,
    &moho::cfunc_CAiBrainSetResourceSharing,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainSetResourceSharingHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const bool enableSharing = LuaPlus::LuaStackObject(state, 2).GetBoolean();
  brain->mArmy->GetEconomy()->isResourceSharingEnabled = enableSharing ? 1u : 0u;
  return 0;
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
  moho::SCR_ExpectExactArgs(state, 4, kAiBrainCreateUnitNearSpotHelpText);
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

  fa::string blueprintName;
  gpg::STR_InitFilename(&blueprintName, unitName);
  RUnitBlueprint* const blueprint = sim->mRules->GetUnitBlueprint(RResId(blueprintName));

  COGrid* const grid = sim->mOGrid;

  Wm3::Vector2f startPosition;
  army->GetArmyStartPos(startPosition);
  // 0x00589BAF-0x00589C45: each corner converts the start coordinate with
  // `fld; fistp` (current x87 rounding mode, round-to-nearest), not a
  // truncating `_ftol`, so an `x.5` army start rounds rather than truncates.
  gpg::Rect2i occupyRect{};
  occupyRect.x0 = fa::RoundToInt(startPosition.x) - 5;
  occupyRect.x1 = fa::RoundToInt(startPosition.x) + 5;
  occupyRect.z0 = fa::RoundToInt(startPosition.y) - 5;
  occupyRect.z1 = fa::RoundToInt(startPosition.y) + 5;

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainCreateUnitNearSpotName,
    &moho::cfunc_CAiBrainCreateUnitNearSpot,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 4, kAiBrainCreateResourceBuildingNearestHelpText);
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
    fa::string blueprintName;
    gpg::STR_InitFilename(&blueprintName, structureName);
    structureBlueprint = sim->mRules->GetUnitBlueprint(RResId(blueprintName));
  }

  // Hydrocarbon buildings sit on kHydrocarbon deposits; everything else on kMass.
  const EntityCategorySet* const hydrocarbonCategory = sim->mRules->GetEntityCategory("HYDROCARBON");
  const EDepositType wantedDeposit =
    EntityCategory::HasBlueprint(structureBlueprint, hydrocarbonCategory) ? kHydrocarbon : kMass;

  CSimResources* const resources = sim->mSimResources.px;
  const fa::vector<ResourceDeposit>& deposits = resources->GetDeposits();

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

  fa::sort(candidates.data(), candidates.data() + candidates.size(), [](const SDepositCandidate& a, const SDepositCandidate& b) {
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainCreateResourceBuildingNearestName,
    &moho::cfunc_CAiBrainCreateResourceBuildingNearest,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainCreateResourceBuildingNearestHelpText
  );
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGiveResourceName,
    &moho::cfunc_CAiBrainGiveResource,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainGiveResourceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00588270 (FUN_00588270, cfunc_CAiBrainGiveResourceL)
 *
 * What it does:
 * Reads `(brain, resourceType, amount)` and banks `amount` into the selected
 * lane of the economy's per-tick resources. 0x005883A4 adds to
 * `GetEconomy() + 0x08` (`mResources`), so the gift is reported as income by
 * the next economy tick and reaches storage through it.
 */
int moho::cfunc_CAiBrainGiveResourceL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainGiveResourceHelpText);

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
  SEconPair& banked = economyInfo->mResources;
  banked.ENERGY += valueToAdd.ENERGY;
  banked.MASS += valueToAdd.MASS;
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainGiveStorageName,
    &moho::cfunc_CAiBrainGiveStorage,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainGiveStorageHelpText);

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
  CEconStorage* const extraStorage = economyInfo->storageDelta;
  (void)extraStorage->Chng(-1);
  extraStorage->mAmt.energy = newStorage.ENERGY;
  extraStorage->mAmt.mass = newStorage.MASS;
  (void)extraStorage->Chng(1);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainTakeResourceName,
    &moho::cfunc_CAiBrainTakeResource,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 3, kAiBrainTakeResourceHelpText);

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

  // Spelled as `request > stored ? stored : request`, not the equivalent-looking
  // `request <= stored ? request : stored`. The two differ on exactly one input:
  // a NaN request. 0x005887A8 is `comiss xmm0, [eax+0x18]` followed at
  // 0x005887B7 by `ja`, over a pointer that already defaults to `&stored`:
  //
  //   mov edx, ecx            ; edx = &stored
  //   ja  0x5887bd            ; request > stored  -> keep &stored
  //   lea edx, [esp+0x14]     ; otherwise         -> &request
  //
  // `comiss` reports NaN as unordered (CF=ZF=1), so `ja` is not taken and the
  // NaN path falls through to `&request`. The binary therefore *propagates* a
  // NaN request into `taken` -- and `taken` is what 0x0058881D loads back for
  // the Lua return value. Writing the `<=` form instead selects `stored` on
  // NaN and silently launders it, which is a behaviour change, not a tidy-up:
  // FAF's GiveResourcesToPlayer guards only `data.Mass < 0`, and that test is
  // false for NaN, so a NaN reaches here and the caller hands the result
  // straight to GiveResource -- whose binary body (0x005883B7) is a bare
  // `addss` with no clamp at all. The recipient's mStored then stays NaN for
  // the rest of the match, and Sim::UpdateChecksum hashes SEconTotals raw.
  SEconPair taken{
    request.ENERGY > stored.ENERGY ? stored.ENERGY : request.ENERGY,
    request.MASS > stored.MASS ? stored.MASS : request.MASS,
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
  moho::SCR_ExpectExactArgs(state, 4, kAiBrainDecideWhatToBuildHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainDecideWhatToBuildName,
    &moho::cfunc_CAiBrainDecideWhatToBuild,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  SBuildReserveInfo pendingReservation{};
  pendingReservation.mUnit.Set(builder);
  pendingReservation.mCom.Set(command);

  RebindBuildReservation(brain->mBuildStructureMap[where], pendingReservation);

  // Binary cleanup order: command lane first, then unit lane.
  UnlinkBuildReservation(pendingReservation);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainPickBestAttackVectorName,
    &moho::cfunc_CAiBrainPickBestAttackVector,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainPickBestAttackVectorHelpText
  );
  return &binder;
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
  squadClassRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);
  LuaPlus::LuaStackObject squadClassArg(state, 3);
  const char* const squadClassName = lua_tostring(rawState, 3);
  if (squadClassName == nullptr) {
    squadClassArg.TypeError("string");
  }
  SCR_GetEnum(state, squadClassName, squadClassRef);

  EAlliance alliance{};
  gpg::RRef allianceRef{};
  allianceRef = gpg::MakeRRef<moho::EAlliance>(&alliance);
  LuaPlus::LuaStackObject allianceArg(state, 4);
  const char* const allianceName = lua_tostring(rawState, 4);
  if (allianceName == nullptr) {
    allianceArg.TypeError("string");
  }
  SCR_GetEnum(state, allianceName, allianceRef);

  ECompareType compareType{};
  gpg::RRef compareTypeRef{};
  compareTypeRef = gpg::MakeRRef<moho::ECompareType>(&compareType);
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
  if (result.point != zeroVector) {
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
    // 0x00590182-0x005901AC: `fld1; fcompi; jbe` keeps the argument only
    // when `1.0 > decay` (a NaN decay therefore becomes 1.0), then
    // `comiss 0, decay; jbe` clamps to 0 only when `0 > decay`.
    float rawDecay = static_cast<float>(lua_tonumber(rawState, 4));
    rawDecay = (1.0f > rawDecay) ? rawDecay : 1.0f;
    if (0.0f > rawDecay) {
      rawDecay = 0.0f;
    }
    decayRate = rawDecay;
  }

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainAssignThreatAtPositionName,
    &moho::cfunc_CAiBrainAssignThreatAtPosition,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainAssignThreatAtPositionHelpText
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainBuildStructureName,
    &moho::cfunc_CAiBrainBuildStructure,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
    kAiBrainLuaClassName,
    kAiBrainBuildStructureHelpText
  );
  return &binder;
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainBuildUnitName,
    &moho::cfunc_CAiBrainBuildUnit,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 4, kAiBrainBuildUnitHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainPlatoonExistsName,
    &moho::cfunc_CAiBrainPlatoonExists,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainPlatoonExistsHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  (void)SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 2));
  const CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
  lua_pushboolean(rawState, platoon != nullptr ? 1 : 0);
  (void)lua_gettop(rawState);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainDisbandPlatoonName,
    &moho::cfunc_CAiBrainDisbandPlatoon,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainDisbandPlatoonHelpText);

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainDisbandPlatoonUniquelyNamedName,
    &moho::cfunc_CAiBrainDisbandPlatoonUniquelyNamed,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 2, kAiBrainDisbandPlatoonUniquelyNamedHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonNameObject(LuaPlus::LuaStackObject(state, 2));
  if (platoonNameObject.IsString()) {
    brain->mArmy->DisbandPlatoonUniquelyNamed(platoonNameObject.GetString());
  }
  return 1;
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainSetUpAttackVectorsToArmyName,
    &moho::cfunc_CAiBrainSetUpAttackVectorsToArmy,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
    const EntityCategorySet* const mobileCategory = rules->GetEntityCategory("MOBILE");
    const EntityCategorySet* const structureCategory = rules->GetEntityCategory("STRUCTURE");

    EntityCategorySet defaultCategory{};
    // 0x0058ECDF..0x0058ECE6: STRUCTURE is the `this` (lhs) of Sub and MOBILE
    // the stack operand, so the default range is STRUCTURE - MOBILE.
    EntityCategory::Sub(&defaultCategory, structureCategory, mobileCategory);
    brain->mBuildCategoryRange = defaultCategory;
  }

  brain->ProcessAttackVectors();
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainCheckBlockingTerrainName,
    &moho::cfunc_CAiBrainCheckBlockingTerrain,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 4, kAiBrainCheckBlockingTerrainHelpText);

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

  const float nanSentinel = gpg::NaN;
  CHeightField* const heightField = brain->mSim->mMapData->mHeightField.get();

  // Shared helper: cast one sub-segment and report whether a valid terrain hit
  // falls within the segment span. `hitResult.distance` is seeded to NaN so a
  // segment with no recorded distance never reports blockage.
  const auto segmentBlocked =
    [&](const Wm3::Vector3f& segStart, const Wm3::Vector3f& segEnd, const bool straightSegment) -> bool {
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
      // The two binary paths sum the span length in different orders:
      // straight (0x00591445-0x0059147A) is `(dz*dz + dy*dy) + dx*dx`, the
      // arc loop (0x0059170F-0x0059174D) is `(dx*dx + dz*dz) + dy*dy`.
      const float segmentLengthSq = straightSegment
        ? ((spanDz * spanDz) + (spanDy * spanDy)) + (spanDx * spanDx)
        : ((spanDx * spanDx) + (spanDz * spanDz)) + (spanDy * spanDy);
      const float segmentLength = std::sqrt(segmentLengthSq);

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

      if (segmentBlocked(previousPoint, currentPoint, false)) {
        blocked = true;
        break;
      }

      previousPoint = currentPoint;
    }
  } else {
    // Straight mode: a single segment from start to end.
    blocked = segmentBlocked(startPosition, endPosition, true);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainBuildPlatoonName,
    &moho::cfunc_CAiBrainBuildPlatoon,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 4, kAiBrainBuildPlatoonHelpText);

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
    const int scaledCount = fa::FloorToIntX87(scaledCountFloat); // 0x0058C6F5..0x0058C708

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
    moho::SCR_SimLuaInitSet(),
    kAiBrainAssignUnitsToPlatoonName,
    &moho::cfunc_CAiBrainAssignUnitsToPlatoon,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  moho::SCR_ExpectExactArgs(state, 5, kAiBrainAssignUnitsToPlatoonHelpText);

  const LuaPlus::LuaObject brainObject(LuaPlus::LuaStackObject(state, 1));
  CAiBrain* const brain = SCR_FromLua_CAiBrain(brainObject, state);

  const LuaPlus::LuaObject platoonOrNameObject(LuaPlus::LuaStackObject(state, 2));
  const LuaPlus::LuaObject unitTableObject(LuaPlus::LuaStackObject(state, 3));

  ESquadClass squadClass{};
  gpg::RRef squadClassRef{};
  squadClassRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

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

  EntitySetTemplate<Unit> incomingUnits{};
  PopulateUnitSetFromLuaList(incomingUnits, unitTableObject);

  brain->mArmy->RemoveUnitsFromPlatoons(&incomingUnits);

  CSquad* destinationSquad = targetPlatoon->GetSquad(squadClass);
  if (destinationSquad == nullptr) {
    destinationSquad = CSquad::AllocateOnPlatoon(targetPlatoon, squadClass, squadNameObject.GetString());
  }

  targetPlatoon->AppendUnitsToSquad(destinationSquad, incomingUnits);
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
    moho::SCR_SimLuaInitSet(),
    kAiBrainMakePlatoonName,
    &moho::cfunc_CAiBrainMakePlatoon,
    &CScrLuaMetatableFactory<CAiBrain>::Instance(),
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
  fa::string platoonName;
  platoonName.assign(platoonNameRow.GetString());
  fa::string platoonPlan;
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
    squadClassRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);
    SCR_GetEnum(state, squadClassNameObject.GetString(), squadClassRef);

    EntitySetTemplate<Unit> pulledUnits{};
    armyPool->GetUnassignedUnitsWithBP(blueprintIdObject.GetString(), countObject.GetInteger(), pulledUnits);
    brain->mArmy->RemoveUnitsFromPlatoons(&pulledUnits);

    CSquad* destinationSquad = newPlatoon->GetSquad(squadClass);
    if (destinationSquad == nullptr) {
      destinationSquad = CSquad::AllocateOnPlatoon(newPlatoon, squadClass, squadNameObject.GetString());
    }

    newPlatoon->AppendUnitsToSquad(destinationSquad, pulledUnits);
  }

  newPlatoon->mLuaObj.PushStack(state);
  return 1;
}
