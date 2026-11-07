#include "moho/lua/ScrLuaUserData.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/CPlatoonPrivate.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace
{
  constexpr int kLuaNumberTypeTag = 3;

  constexpr const char* kCanConsiderFormingPlatoonHelpText = "CPlatoon:CanConsiderFormingPlatoon()";
  constexpr const char* kGetPlatoonUnitsHelpText = "platoon:GetPlatoonUnits()";
  constexpr const char* kCanFormPlatoonHelpText = "CPlatoon:CanFormPlatoon()";
  constexpr const char* kFormPlatoonHelpText = "CPlatoon:FormPlatoon()";
  constexpr const char* kSetPrioritizedTargetListHelpText = "CPlatoon:SetPrioritizedTargetList()";
  constexpr const char* kFindClosestUnitToBaseHelpText = "CPlatoon:FindClosestUnitToBase()";
  constexpr const char* kCanAttackTargetHelpText = "CPlatoon:CanAttackTarget()";
  constexpr const char* kAttackTargetHelpText = "CPlatoon:AttackTarget()";
  constexpr const char* kMoveToTargetHelpText = "CPlatoon:MoveToTarget()";
  constexpr const char* kLoadUnitsHelpText = "CPlatoon:LoadUnits()";
  constexpr const char* kFindPrioritizedUnitHelpText = "CPlatoon:FindPrioritizedUnit()";
  constexpr const char* kFindClosestUnitHelpText = "CPlatoon:FindClosestUnit()";
  constexpr const char* kFindFurthestUnitHelpText = "CPlatoon:FindFurthestUnit()";
  constexpr const char* kIsOpponentAIRunningHelpText = "CPlatoon:IsOpponentAIRunning()";
  constexpr const char* kGetPersonalityHelpText = "CPlatoon:GetPersonality()";
  constexpr const char* kGetBrainHelpText = "CPlatoon:GetBrain()";
  constexpr const char* kGetFactionIndexHelpText = "CPlatoon:GetFactionIndex()";
  constexpr const char* kUniquelyNamePlatoonHelpText = "CPlatoon:UniquelyNamePlatoon()";
  constexpr const char* kGetPlatoonUniqueNameHelpText = "CPlatoon:GetPlatoonUniqueName()";
  constexpr const char* kGetAIPlanHelpText = "CPlatoon:GetAIPlan()";
  constexpr const char* kSwitchAIPlanHelpText = "CPlatoon:SwitchAIPlan()";
  constexpr const char* kGetPlatoonPositionHelpText = "CPlatoon:GetPlatoonPosition()";
  constexpr const char* kGetSquadPositionHelpText = "CPlatoon:GetSquadPosition()";
  constexpr const char* kGetSquadUnitsHelpText = "CPlatoon:GetSquadUnits()";
  constexpr const char* kIsAttackingHelpText = "CPlatoon:IsAttacking()";
  constexpr const char* kIsMovingHelpText = "CPlatoon:IsMoving()";
  constexpr const char* kIsPatrollingHelpText = "CPlatoon:IsPatrolling()";
  constexpr const char* kIsFerryingHelpText = "CPlatoon:IsFerrying()";
  constexpr const char* kDisbandOnIdleHelpText = "CPlatoon:DisbandOnIdle()";
  constexpr const char* kIsCommandsActiveHelpText = "CPlatoon:IsCommandsActive()";
  constexpr const char* kFindHighestValueUnitHelpText = "CPlatoon:FindHighestValueUnit()";
  constexpr const char* kStopHelpText = "CPlatoon:Stop()";
  constexpr const char* kMoveToLocationHelpText = "CPlatoon:MoveToLocation()";
  constexpr const char* kAggressiveMoveToLocationHelpText = "CPlatoon:AggressiveMoveToLocation()";
  constexpr const char* kFerryToLocationHelpText = "CPlatoon:FerryToLocation()";
  constexpr const char* kUnloadUnitsAtLocationHelpText = "CPlatoon:UnloadUnitsAtLocation()";
  constexpr const char* kUnloadAllAtLocationHelpText = "CPlatoon:UnloadAllAtLocation()";
  constexpr const char* kPatrolHelpText = "CPlatoon:Patrol()";
  constexpr const char* kGuardTargetHelpText = "CPlatoon:GuardTarget()";
  constexpr const char* kDestroyHelpText = "CPlatoon:Destroy()";
  constexpr const char* kGetFerryBeaconsHelpText = "CPlatoon:GetFerryBeacons()";
  constexpr const char* kUseFerryBeaconHelpText = "CPlatoon:UseFerryBeacon()";
  constexpr const char* kUseTeleporterHelpText = "CPlatoon:UseTeleporter()";
  constexpr const char* kSetPlatoonFormationOverrideHelpText = "CPlatoon:SetPlatoonFormationOverride()";
  constexpr const char* kGetPlatoonLifetimeStatsHelpText = "CPlatoon:GetPlatoonLifetimeStats()";
  constexpr const char* kCalculatePlatoonThreatHelpText = "CPlatoon:CalculatePlatoonThreat()";
  constexpr const char* kCalculatePlatoonThreatAroundPositionHelpText =
    "CPlatoon:CalculatePlatoonThreatAroundPosition()";
  constexpr const char* kPlatoonCategoryCountAroundPositionHelpText =
    "Count how many units fit the specified category around a position";
  constexpr const char* kPlatoonCategoryCountHelpText = "Count how many units fit the specified category";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

  enum class PlatoonThreatType : std::int32_t
  {
    Air = 0,
    Surface = 1,
    Sub = 2,
    Economy = 3,
    Unknown = -1,
  };

  [[nodiscard]] PlatoonThreatType ParsePlatoonThreatType(const char* const threatTypeName) noexcept
  {
    if (threatTypeName == nullptr) {
      return PlatoonThreatType::Unknown;
    }

    if (::_stricmp(threatTypeName, "Air") == 0) {
      return PlatoonThreatType::Air;
    }
    if (::_stricmp(threatTypeName, "Surface") == 0) {
      return PlatoonThreatType::Surface;
    }
    if (::_stricmp(threatTypeName, "Sub") == 0) {
      return PlatoonThreatType::Sub;
    }
    if (::_stricmp(threatTypeName, "Economy") == 0) {
      return PlatoonThreatType::Economy;
    }

    return PlatoonThreatType::Unknown;
  }

  [[nodiscard]] bool BlueprintMatchesCategory(
    const moho::RUnitBlueprint* const blueprint,
    const moho::EntityCategorySet* const categorySet
  ) noexcept
  {
    if (!blueprint || !categorySet) {
      return false;
    }
    return categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  }

  /**
   * Adds one blueprint's threat to the running platoon total.
   *
   * The "all threat types" lane folds each level into the running total in
   * turn -- `(((air + total) + surface) + sub) + economy` -- rather than
   * summing the four levels first (0x007327DD-0x007327FB in
   * CalculatePlatoonThreat, 0x00732D3A-0x00732D58 in ...AroundPosition).
   */
  [[nodiscard]] float AddBlueprintThreat(
    const float totalThreat,
    const moho::RUnitBlueprint& blueprint,
    const PlatoonThreatType threatType
  ) noexcept
  {
    switch (threatType) {
      case PlatoonThreatType::Air:
        return blueprint.Defense.AirThreatLevel + totalThreat;
      case PlatoonThreatType::Surface:
        return blueprint.Defense.SurfaceThreatLevel + totalThreat;
      case PlatoonThreatType::Sub:
        return blueprint.Defense.SubThreatLevel + totalThreat;
      case PlatoonThreatType::Economy:
        return blueprint.Defense.EconomyThreatLevel + totalThreat;
      case PlatoonThreatType::Unknown:
      default:
        return (((blueprint.Defense.AirThreatLevel + totalThreat) + blueprint.Defense.SurfaceThreatLevel)
                + blueprint.Defense.SubThreatLevel)
          + blueprint.Defense.EconomyThreatLevel;
    }
  }

  [[nodiscard]] bool IsThreatCandidateUnit(const moho::Unit* const unit) noexcept
  {
    return unit && !unit->IsDead() && !unit->DestroyQueued();
  }

  [[nodiscard]] float ReadSquaredRadiusArg(LuaPlus::LuaState* const state, const int stackIndex)
  {
    LuaPlus::LuaStackObject radiusArg(state, stackIndex);
    if (lua_type(state->m_state, stackIndex) != kLuaNumberTypeTag) {
      LuaPlus::LuaStackObject::TypeError(&radiusArg, "number");
    }

    const float radius = static_cast<float>(lua_tonumber(state->m_state, stackIndex));
    return radius * radius;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandType()
  {
    return moho::CUnitCommand::StaticGetClass();
  }

  /**
   * Address: 0x006F8D80 (FUN_006F8D80, func_GetCUnitCommandOpt)
   *
   * What it does:
   * Resolves one Lua game-object handle to an optional `CUnitCommand*`,
   * raising Lua type errors on invalid/non-command userdata.
   */
  [[nodiscard]] moho::CUnitCommand* func_GetCUnitCommandOpt(
    const LuaPlus::LuaObject& object,
    LuaPlus::LuaState* const state
  )
  {
    moho::CScriptObject** const scriptObjectSlot = moho::SCR_ScriptObjectSlot(object);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCUnitCommandType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CUnitCommand*>(upcast.mObj);
  }
}

namespace moho
{

  /**
   * Address: 0x0072AC30 (FUN_0072AC30)
   *
   * What it does:
   * Returns cached `CPlatoon` metatable object from Lua object-factory
   * storage.
   */
  LuaPlus::LuaObject* func_GetCPlatoonFactory(
    LuaPlus::LuaObject* const object,
    LuaPlus::LuaState* const state
  )
  {
    return SCR_WriteMetatable<CPlatoon>(object, state);
  }

  /**
   * Address: 0x00725060 (FUN_00725060, func_LoadPlatoon)
   *
   * IDA signature:
   * LuaPlus::LuaObject* __thiscall func_LoadPlatoon(
   *     LuaPlus::LuaState* state, LuaPlus::LuaObject* outObject);
   *
   * What it does:
   * Imports `/lua/platoon.lua` and stores its `Platoon` field into the
   * caller-provided `outObject`. When the module/class is missing, logs the
   * fallback diagnostic and writes the `CPlatoon` metatable factory into
   * `outObject` so `CPlatoon` can still bind into Lua.
   *
   * Callsite evidence (per CLAUDE.md callsite verification rule):
   *  - code xref from Moho::CPlatoon::CPlatoon ctor (FUN_00724CC0) at 0x00724D24
   */
  LuaPlus::LuaObject* func_LoadPlatoon(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaObject* const outObject
  )
  {
    *outObject = LuaPlus::LuaObject{};

    LuaPlus::LuaObject platoonModule = SCR_Import(state, "/lua/platoon.lua");
    if (!platoonModule.IsNil()) {
      LuaPlus::LuaObject platoonClass = platoonModule.GetByName("Platoon");
      *outObject = platoonClass;
    }

    if (outObject->IsNil()) {
      gpg::Logf(" can't find Platoon, using CPlatoon directly");
      LuaPlus::LuaObject fallbackFactory;
      (void)func_GetCPlatoonFactory(&fallbackFactory, state);
      *outObject = fallbackFactory;
    }

    return outObject;
  }

  /**
   * Address: 0x0072B810 (FUN_0072B810, cfunc_CPlatoonIsOpponentAIRunning)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonIsOpponentAIRunningL`.
   */
  int cfunc_CPlatoonIsOpponentAIRunning(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsOpponentAIRunningL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072B830 (FUN_0072B830, func_CPlatoonIsOpponentAIRunning_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsOpponentAIRunning()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsOpponentAIRunning_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsOpponentAIRunning",
      &cfunc_CPlatoonIsOpponentAIRunning,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsOpponentAIRunningHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072B970 (FUN_0072B970, cfunc_CPlatoonGetPersonality)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPersonalityL`.
   */
  int cfunc_CPlatoonGetPersonality(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPersonalityL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072B9F0 (FUN_0072B9F0, cfunc_CPlatoonGetPersonalityL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning brain personality object, or
   * `nil` when no personality exists.
   */
  int cfunc_CPlatoonGetPersonalityL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kGetPersonalityHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    CAiPersonality* const personality = platoon->mArmy->GetArmyBrain()->mPersonality;

    if (personality != nullptr) {
      personality->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
    }

    return 1;
  }

  /**
   * Address: 0x0072B990 (FUN_0072B990, func_CPlatoonGetPersonality_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPersonality()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPersonality_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPersonality",
      &cfunc_CPlatoonGetPersonality,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPersonalityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BAD0 (FUN_0072BAD0, cfunc_CPlatoonGetBrain)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetBrainL`.
   */
  int cfunc_CPlatoonGetBrain(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetBrainL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BB50 (FUN_0072BB50, cfunc_CPlatoonGetBrainL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning army-brain Lua object.
   */
  int cfunc_CPlatoonGetBrainL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kGetBrainHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    platoon->mArmy->GetArmyBrain()->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072BAF0 (FUN_0072BAF0, func_CPlatoonGetBrain_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetBrain()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetBrain_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetBrain",
      &cfunc_CPlatoonGetBrain,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetBrainHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BC10 (FUN_0072BC10, cfunc_CPlatoonGetFactionIndex)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetFactionIndexL`.
   */
  int cfunc_CPlatoonGetFactionIndex(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetFactionIndexL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BC90 (FUN_0072BC90, cfunc_CPlatoonGetFactionIndexL)
   *
   * What it does:
   * Resolves one platoon and returns one-based faction index from the owning
   * army brain.
   */
  int cfunc_CPlatoonGetFactionIndexL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kGetFactionIndexHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    const CAiBrain* const brain = platoon->mArmy->GetArmyBrain();

    lua_pushnumber(state->m_state, static_cast<float>(brain->mArmy->mVarDat.mFaction + 1));
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072BC30 (FUN_0072BC30, func_CPlatoonGetFactionIndex_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetFactionIndex()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetFactionIndex_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetFactionIndex",
      &cfunc_CPlatoonGetFactionIndex,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetFactionIndexHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BD60 (FUN_0072BD60, cfunc_CPlatoonUniquelyNamePlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonUniquelyNamePlatoonL`.
   */
  int cfunc_CPlatoonUniquelyNamePlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUniquelyNamePlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BD80 (FUN_0072BD80, func_CPlatoonUniquelyNamePlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UniquelyNamePlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUniquelyNamePlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UniquelyNamePlatoon",
      &cfunc_CPlatoonUniquelyNamePlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUniquelyNamePlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BDE0 (FUN_0072BDE0, cfunc_CPlatoonUniquelyNamePlatoonL)
   *
   * What it does:
   * Resolves `(platoon, uniqueName)` and stores the provided platoon unique
   * name when argument #2 is a string.
   */
  int cfunc_CPlatoonUniquelyNamePlatoonL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kUniquelyNamePlatoonHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject uniqueNameObject(LuaPlus::LuaStackObject(state, 2));
    if (platoon != nullptr && uniqueNameObject.IsString()) {
      platoon->mUniqueName.assign(uniqueNameObject.GetString());
    }

    return 1;
  }

  /**
   * Address: 0x0072BEF0 (FUN_0072BEF0, cfunc_CPlatoonGetPlatoonUniqueName)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetPlatoonUniqueNameL`.
   */
  int cfunc_CPlatoonGetPlatoonUniqueName(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonUniqueNameL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072BF10 (FUN_0072BF10, func_CPlatoonGetPlatoonUniqueName_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonUniqueName()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonUniqueName_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonUniqueName",
      &cfunc_CPlatoonGetPlatoonUniqueName,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonUniqueNameHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072BF70 (FUN_0072BF70, cfunc_CPlatoonGetPlatoonUniqueNameL)
   *
   * What it does:
   * Resolves one platoon and pushes its unique-name string.
   */
  int cfunc_CPlatoonGetPlatoonUniqueNameL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kGetPlatoonUniqueNameHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    lua_pushstring(state->m_state, platoon->mUniqueName.c_str());
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072C040 (FUN_0072C040, cfunc_CPlatoonGetAIPlan)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetAIPlanL`.
   */
  int cfunc_CPlatoonGetAIPlan(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetAIPlanL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C060 (FUN_0072C060, func_CPlatoonGetAIPlan_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetAIPlan()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetAIPlan_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetAIPlan",
      &cfunc_CPlatoonGetAIPlan,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetAIPlanHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C0C0 (FUN_0072C0C0, cfunc_CPlatoonGetAIPlanL)
   *
   * What it does:
   * Resolves one platoon and pushes the owning army-brain AI-plan string.
   */
  int cfunc_CPlatoonGetAIPlanL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kGetAIPlanHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    const CAiBrain* const armyBrain = platoon->mArmy->GetArmyBrain();

    lua_pushstring(state->m_state, armyBrain->mCurrentPlan.c_str());
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072C190 (FUN_0072C190, cfunc_CPlatoonSwitchAIPlan)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonSwitchAIPlanL`.
   */
  int cfunc_CPlatoonSwitchAIPlan(lua_State* const luaContext)
  {
    return cfunc_CPlatoonSwitchAIPlanL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C1B0 (FUN_0072C1B0, func_CPlatoonSwitchAIPlan_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SwitchAIPlan()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSwitchAIPlan_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SwitchAIPlan",
      &cfunc_CPlatoonSwitchAIPlan,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kSwitchAIPlanHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C210 (FUN_0072C210, cfunc_CPlatoonSwitchAIPlanL)
   *
   * What it does:
   * Resolves `(platoon, planName)` and switches AI plan when argument #2 is
   * a string.
   */
  int cfunc_CPlatoonSwitchAIPlanL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kSwitchAIPlanHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject aiPlanObject(LuaPlus::LuaStackObject(state, 2));
    if (aiPlanObject.IsString()) {
      platoon->SwitchAIPlan(aiPlanObject.GetString());
    }

    return 1;
  }

  /**
   * Address: 0x0072C300 (FUN_0072C300, cfunc_CPlatoonGetPlatoonPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetPlatoonPositionL`.
   */
  int cfunc_CPlatoonGetPlatoonPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C380 (FUN_0072C380, cfunc_CPlatoonGetPlatoonPositionL)
   *
   * What it does:
   * Returns the mean position of the platoon's units, or nil when it has
   * none.
   */
  int cfunc_CPlatoonGetPlatoonPositionL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kGetPlatoonPositionHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const EntitySetTemplate<Unit> units = platoon->GetPlatoonUnits();
    if (units.Size() == 0u) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    // Every entry is summed, and the divide is `Vector3f::operator/=`, which
    // gives FLT_MAX components for a zero divisor (0x0072C4C3..0x0072C526).
    Wm3::Vector3f center = Wm3::Vector3f::ZERO;
    for (Entity* const entity : units.mVec) {
      center += static_cast<Unit*>(entity)->GetPosition();
    }
    center /= static_cast<float>(units.Size());

    LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3<float>>(state, center);
    centerObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072C320 (FUN_0072C320, func_CPlatoonGetPlatoonPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonPosition",
      &cfunc_CPlatoonGetPlatoonPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C5C0 (FUN_0072C5C0, cfunc_CPlatoonGetSquadPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonGetSquadPositionL`.
   */
  int cfunc_CPlatoonGetSquadPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetSquadPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C640 (FUN_0072C640, cfunc_CPlatoonGetSquadPositionL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns the average world position
   * of units currently present in the selected squad.
   */
  int cfunc_CPlatoonGetSquadPositionL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kGetSquadPositionHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const CSquad* const squad = platoon->GetSquad(squadClass);
    if (squad == nullptr) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    // The binary makes this call and drops the result (0x0072C775..0x0072C77D).
    (void)platoon->mArmy->GetArmyBrain();

    Wm3::Vector3f squadCenter{};
    (void)squad->GetCenter(&squadCenter);

    LuaPlus::LuaObject centerObject = SCR_ToLua<Wm3::Vector3<float>>(state, squadCenter);
    centerObject.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072C5E0 (FUN_0072C5E0, func_CPlatoonGetSquadPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetSquadPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetSquadPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetSquadPosition",
      &cfunc_CPlatoonGetSquadPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetSquadPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072C7D0 (FUN_0072C7D0, cfunc_CPlatoonGetSquadUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetSquadUnitsL`.
   */
  int cfunc_CPlatoonGetSquadUnits(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetSquadUnitsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C850 (FUN_0072C850, cfunc_CPlatoonGetSquadUnitsL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns a Lua array of unit objects
   * for members currently present in the selected squad.
   */
  int cfunc_CPlatoonGetSquadUnitsL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kGetSquadUnitsHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const CSquad* const squad = platoon->GetSquad(squadClass);
    if (squad == nullptr) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    LuaPlus::LuaObject unitTable{};
    (void)squad->GetUnits(&unitTable, state);

    unitTable.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072C7F0 (FUN_0072C7F0, func_CPlatoonGetSquadUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetSquadUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetSquadUnits_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetSquadUnits",
      &cfunc_CPlatoonGetSquadUnits,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetSquadUnitsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072B890 (FUN_0072B890, cfunc_CPlatoonIsOpponentAIRunningL)
   *
   * What it does:
   * Resolves one platoon and returns the `AI_RunOpponentAI` sim-convar state.
   */
  int cfunc_CPlatoonIsOpponentAIRunningL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kIsOpponentAIRunningHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    SimArmy* const army = platoon->mArmy;
    Sim* const sim = army ? army->GetSim() : nullptr;

    CSimConVarBase* const runOpponentAiConVar = &moho::gSimConVar_AI_RunOpponentAI;
    CSimConVarInstanceBase* const runOpponentAiVar = (sim && runOpponentAiConVar) ? sim->GetSimVar(runOpponentAiConVar)
                                                                                   : nullptr;
    const void* const runOpponentAiStorage = runOpponentAiVar ? runOpponentAiVar->GetValueStorage() : nullptr;
    const bool shouldRunOpponentAi =
      runOpponentAiStorage && (*reinterpret_cast<const std::uint8_t*>(runOpponentAiStorage) != 0u);

    lua_pushboolean(state->m_state, shouldRunOpponentAi ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072CC00 (FUN_0072CC00, cfunc_CPlatoonCanConsiderFormingPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanConsiderFormingPlatoonL`.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanConsiderFormingPlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072CC80 (FUN_0072CC80, cfunc_CPlatoonCanConsiderFormingPlatoonL)
   *
   * What it does:
   * Validates one `CPlatoon` method call and returns whether arg#3 matches
   * the first element of arg#2 case-insensitively.
   */
  int cfunc_CPlatoonCanConsiderFormingPlatoonL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    moho::SCR_ExpectExactArgs(state, 3, kCanConsiderFormingPlatoonHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    (void)SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaObject compareTable(LuaPlus::LuaStackObject(state, 2));
    const char* inputString = lua_tostring(state->m_state, 3);
    if (!inputString) {
      LuaPlus::LuaStackObject typeErrorArg(state, 3);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }

    std::string inputText(inputString ? inputString : "");
    LuaPlus::LuaObject compareObject = compareTable[1];
    const char* compareString = compareObject.GetString();

    const int compareResult = _memicmp(inputText.c_str(), compareString, inputText.size());
    lua_pushboolean(state->m_state, compareResult ? 0 : 1);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x00731690 (FUN_00731690, cfunc_CPlatoonDisbandOnIdle)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonDisbandOnIdleL`.
   */
  int cfunc_CPlatoonDisbandOnIdle(lua_State* const luaContext)
  {
    return cfunc_CPlatoonDisbandOnIdleL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731710 (FUN_00731710, cfunc_CPlatoonDisbandOnIdleL)
   *
   * What it does:
   * Resolves one `CPlatoon` object from Lua and sets its disband-on-idle flag.
   */
  int cfunc_CPlatoonDisbandOnIdleL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kDisbandOnIdleHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);
    platoon->MarkDisbandOnIdle();
    return 0;
  }

  /**
   * Address: 0x007316B0 (FUN_007316B0, func_CPlatoonDisbandOnIdle_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:DisbandOnIdle()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonDisbandOnIdle_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "DisbandOnIdle",
      &cfunc_CPlatoonDisbandOnIdle,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kDisbandOnIdleHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731F00 (FUN_00731F00, cfunc_CPlatoonIsCommandsActive)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsCommandsActiveL`.
   */
  int cfunc_CPlatoonIsCommandsActive(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsCommandsActiveL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731F80 (FUN_00731F80, cfunc_CPlatoonIsCommandsActiveL)
   *
   * What it does:
   * Resolves `(platoon, commandsTable)` and returns true when any listed
   * command object is currently live.
   */
  int cfunc_CPlatoonIsCommandsActiveL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kIsCommandsActiveHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    (void)SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaObject commandsObject(LuaPlus::LuaStackObject(state, 2));
    const int commandCount = commandsObject.GetCount();
    for (int commandIndex = 1; commandIndex <= commandCount; ++commandIndex) {
      const LuaPlus::LuaObject commandObject = commandsObject[commandIndex];
      if (func_GetCUnitCommandOpt(commandObject, state)) {
        lua_pushboolean(state->m_state, 1);
        (void)lua_gettop(state->m_state);
        return 1;
      }
    }

    lua_pushboolean(state->m_state, 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x00731F20 (FUN_00731F20, func_CPlatoonIsCommandsActive_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsCommandsActive()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsCommandsActive_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsCommandsActive",
      &cfunc_CPlatoonIsCommandsActive,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsCommandsActiveHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E240 (FUN_0072E240, cfunc_CPlatoonIsAttacking)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsAttackingL`.
   */
  int cfunc_CPlatoonIsAttacking(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsAttackingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E260 (FUN_0072E260, func_CPlatoonIsAttacking_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsAttacking()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsAttacking_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsAttacking",
      &cfunc_CPlatoonIsAttacking,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsAttackingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E2C0 (FUN_0072E2C0, cfunc_CPlatoonIsAttackingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Attacking`.
   */
  int cfunc_CPlatoonIsAttackingL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kIsAttackingHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Attacking);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072E3E0 (FUN_0072E3E0, cfunc_CPlatoonIsMoving)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsMovingL`.
   */
  int cfunc_CPlatoonIsMoving(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsMovingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E400 (FUN_0072E400, func_CPlatoonIsMoving_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsMoving()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsMoving_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsMoving",
      &cfunc_CPlatoonIsMoving,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsMovingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E460 (FUN_0072E460, cfunc_CPlatoonIsMovingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Moving`.
   */
  int cfunc_CPlatoonIsMovingL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kIsMovingHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Moving);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072E580 (FUN_0072E580, cfunc_CPlatoonIsPatrolling)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsPatrollingL`.
   */
  int cfunc_CPlatoonIsPatrolling(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsPatrollingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E5A0 (FUN_0072E5A0, func_CPlatoonIsPatrolling_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsPatrolling()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsPatrolling_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsPatrolling",
      &cfunc_CPlatoonIsPatrolling,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsPatrollingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E600 (FUN_0072E600, cfunc_CPlatoonIsPatrollingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Patrolling`.
   */
  int cfunc_CPlatoonIsPatrollingL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kIsPatrollingHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Patrolling);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072E720 (FUN_0072E720, cfunc_CPlatoonIsFerrying)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonIsFerryingL`.
   */
  int cfunc_CPlatoonIsFerrying(lua_State* const luaContext)
  {
    return cfunc_CPlatoonIsFerryingL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E740 (FUN_0072E740, func_CPlatoonIsFerrying_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:IsFerrying()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonIsFerrying_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IsFerrying",
      &cfunc_CPlatoonIsFerrying,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kIsFerryingHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E7A0 (FUN_0072E7A0, cfunc_CPlatoonIsFerryingL)
   *
   * What it does:
   * Resolves `(platoon, squadClass)` and returns whether any unit in that
   * squad currently has `UNITSTATE_Ferrying`.
   */
  int cfunc_CPlatoonIsFerryingL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kIsFerryingHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

    const char* squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    const bool hasState = CPlatoon::SquadHasState(squadClass, platoon, UNITSTATE_Ferrying);
    lua_pushboolean(state->m_state, hasState ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072C9B0 (FUN_0072C9B0, cfunc_CPlatoonGetPlatoonUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPlatoonUnitsL`.
   */
  int cfunc_CPlatoonGetPlatoonUnits(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonUnitsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072C9D0 (FUN_0072C9D0, func_CPlatoonGetPlatoonUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonUnits_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonUnits",
      &cfunc_CPlatoonGetPlatoonUnits,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonUnitsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072CA30 (FUN_0072CA30, cfunc_CPlatoonGetPlatoonUnitsL)
   *
   * What it does:
   * Resolves one platoon and returns a cached Lua table containing all
   * currently tracked platoon units.
   */
  int cfunc_CPlatoonGetPlatoonUnitsL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kGetPlatoonUnitsHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      LuaPlus::LuaObject emptyUnits{};
      emptyUnits.AssignNewTable(state, 0, 0);
      emptyUnits.PushStack(state);
      return 1;
    }

    if (!platoon->mHasLuaList) {
      const EntitySetTemplate<Unit> platoonUnits = platoon->GetPlatoonUnits();

      platoon->mLuaUnitList.AssignNewTable(state, static_cast<int>(platoonUnits.Size()), 0);
      std::int32_t luaIndex = 1;
      for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
        Unit* const unit = static_cast<Unit*>(*entityIt);
        if (!unit) {
          continue;
        }

        LuaPlus::LuaObject unitObject = unit->GetLuaObject();
        platoon->mLuaUnitList.Insert(luaIndex, unitObject);
        ++luaIndex;
      }

      platoon->mHasLuaList = true;
    }

    platoon->mLuaUnitList.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072CC20 (FUN_0072CC20, func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanConsiderFormingPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanConsiderFormingPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanConsiderFormingPlatoon",
      &cfunc_CPlatoonCanConsiderFormingPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanConsiderFormingPlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072CEF0 (FUN_0072CEF0, cfunc_CPlatoonCanFormPlatoonL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonCanFormPlatoonL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Implements `CPlatoon:CanFormPlatoon(template, sizeMultiplier[, center, radius])`.
   * A platoon template is `{name, aiPlan, {unitFilter, perSquadCount}, ...}`; the
   * leading name/plan strings are extracted (as the binary does) but do not feed
   * the feasibility test. For each squad spec the required count is
   * `floor(sizeMultiplier * perSquadCount)`. With <=4 args the check counts every
   * unassigned unit matching the filter (blueprint id or category); with 5 args it
   * counts only unassigned, live units within `radius` of `center`. If any squad
   * spec has fewer available units than required the platoon cannot be formed and
   * the callback returns `false`; otherwise it returns `true` when at least one
   * unit was counted across all specs.
   */
  int cfunc_CPlatoonCanFormPlatoonL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 3 || argumentCount > 5) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected between %d and %d args, but got %d", kCanFormPlatoonHelpText, 3, 5, argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject templatesObject(LuaPlus::LuaStackObject(state, 2));
    const LuaPlus::LuaObject sizeObject(LuaPlus::LuaStackObject(state, 3));

    // The binary reads the template's leading name (index 1) and AI-plan (index 2)
    // strings before scanning the squad specs. They are not consumed by the
    // feasibility test, but the extraction is a preserved side effect.
    const LuaPlus::LuaObject nameObject = templatesObject[1];
    const fa::string platoonName(nameObject.GetString());
    const LuaPlus::LuaObject planObject = templatesObject[2];
    const fa::string platoonPlan(planObject.GetString());
    (void)platoonName;
    (void)platoonPlan;

    if (!templatesObject.IsTable()) {
      LuaPlus::LuaState::Error(state, "Attempted to pass in a non table as a platoon template");
      lua_pushboolean(state->m_state, 0);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    const int templateCount = templatesObject.GetCount();
    int totalAvailable = 0;
    for (int specIndex = 1; specIndex <= templateCount; ++specIndex) {
      const LuaPlus::LuaObject squadSpec = templatesObject[specIndex];
      if (!squadSpec.IsTable()) {
        continue;  // skip the leading name/plan string entries
      }

      const LuaPlus::LuaObject unitFilter = squadSpec[1];
      const LuaPlus::LuaObject countObject = squadSpec[2];
      // The binary reads the size multiplier as a float and multiplies in float
      // (x87 float*float), so narrow before the multiply to avoid a double-rounding
      // that could shift the floor result by one at boundary values.
      const float scaledSize =
        static_cast<float>(sizeObject.GetNumber()) * static_cast<float>(countObject.GetInteger());
      const int requiredSize = fa::FloorToIntX87(scaledSize); // 0x0072D220..0x0072D236

      if (argumentCount <= 4) {
        int available;
        if (unitFilter.IsString()) {
          available = platoon->CountUnassignedUnitsWithBP(unitFilter.GetString());
        } else {
          const EntityCategorySet* const category = func_GetCObj_EntityCategory(unitFilter);
          available = platoon->CountUnassignedUnitsInCategory(category);
        }
        totalAvailable += available;
        if (available < requiredSize) {
          lua_pushboolean(state->m_state, 0);
          (void)lua_gettop(state->m_state);
          return 1;
        }
      } else {
        EntitySetTemplate<Unit> candidates{};
        if (unitFilter.IsString()) {
          platoon->GetUnassignedUnitsWithBP(unitFilter.GetString(), 1000, candidates);
        } else {
          const EntityCategorySet* const category = func_GetCObj_EntityCategory(unitFilter);
          platoon->GetUnassignedUnitsInCategory(category, 1000, candidates);
        }

        const LuaPlus::LuaObject centerObject(LuaPlus::LuaStackObject(state, 4));
        const Wm3::Vector3f center = SCR_FromLuaCopy<Wm3::Vector3<float>>(centerObject);

        LuaPlus::LuaStackObject radiusArg(state, 5);
        if (lua_type(state->m_state, 5) != 3 /* LUA_TNUMBER */) {
          LuaPlus::LuaStackObject::TypeError(&radiusArg, "number");
        }
        const float radius = static_cast<float>(lua_tonumber(state->m_state, 5));

        int inRadius = 0;
        for (Entity* const* entityIt = candidates.mVec.begin(); entityIt != candidates.mVec.end(); ++entityIt) {
          Entity* const entity = *entityIt;
          if (entity == nullptr) {
            continue;
          }
          // Entries are unassigned units; Entity is the +8 base subobject of Unit,
          // so the static downcast performs the -8 adjustment the binary emits.
          Unit* const unit = static_cast<Unit*>(entity);
          if (unit == nullptr) {
            continue;
          }
          if (unit->IsDead() || unit->DestroyQueued() || unit->IsBeingBuilt()) {
            continue;
          }
          const Wm3::Vec3f& unitPosition = unit->GetPosition();
          const float deltaX = unitPosition.x - center.x;
          const float deltaZ = unitPosition.z - center.z;
          if (radius > std::sqrt(deltaX * deltaX + deltaZ * deltaZ)) {
            ++inRadius;
            ++totalAvailable;
          }
        }
        if (inRadius < requiredSize) {
          lua_pushboolean(state->m_state, 0);
          (void)lua_gettop(state->m_state);
          return 1;
        }
      }
    }

    lua_pushboolean(state->m_state, totalAvailable != 0 ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072D8F0 (FUN_0072D8F0, cfunc_CPlatoonFormPlatoonL)
   *
   * IDA signature:
   * int __cdecl cfunc_CPlatoonFormPlatoonL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Implements `CPlatoon:FormPlatoon(template, sizeMultiplier[, center, radius])`.
   * Creates a fresh platoon on the owning army, then for each squad spec
   * `{filter, min, max, squadClass, formation}` gathers up to
   * `floor(sizeMultiplier * max)` of this platoon's unassigned units matching the
   * filter (optionally distance-filtered nearest-first to a center/radius), pulls
   * them out of any prior platoon, and assigns them into the matching squad
   * (created if absent). Returns the new platoon's Lua object.
   */
  int cfunc_CPlatoonFormPlatoonL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 3 || argumentCount > 5) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected between %d and %d args, but got %d", kFormPlatoonHelpText, 3, 5, argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject templatesObject(LuaPlus::LuaStackObject(state, 2));
    const LuaPlus::LuaObject sizeObject(LuaPlus::LuaStackObject(state, 3));

    const int templateCount = templatesObject.GetCount();
    const LuaPlus::LuaObject nameObject = templatesObject[1];
    const fa::string platoonName(nameObject.GetString());
    const LuaPlus::LuaObject planObject = templatesObject[2];
    const fa::string platoonPlan(planObject.GetString());

    CPlatoon* const newPlatoon = platoon->mArmy->MakePlatoon(platoonName.data(), platoonPlan.data());

    for (int specIndex = 1; specIndex <= templateCount; ++specIndex) {
      const LuaPlus::LuaObject squadSpec = templatesObject[specIndex];
      if (!squadSpec.IsTable()) {
        continue;  // skip the leading name/plan string entries
      }

      const LuaPlus::LuaObject unitFilter = squadSpec[1];
      const LuaPlus::LuaObject baseCountObject = squadSpec[3];
      const int baseCount = baseCountObject.GetInteger();

      // 0x0072DBDC-0x0072DC28: the row's [5] (formation name) is fetched here but
      // only read as the new squad's name below; the multiplier is the call's
      // arg 3 (`sizeObject`, 0x0072DC01 GetNumber on [esp+160h]), fimul'd by the
      // row's [3] count and floored, exactly as CanFormPlatoon scales row [2].
      const LuaPlus::LuaObject formationObject = squadSpec[5];
      const float scaledSize = static_cast<float>(sizeObject.GetNumber()) * static_cast<float>(baseCount);
      const int requiredSize = fa::FloorToIntX87(scaledSize); // 0x0072DC15..0x0072DC28

      ESquadClass squadClass = static_cast<ESquadClass>(0);
      gpg::RRef enumRef{};
      enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);
      const LuaPlus::LuaObject squadClassNameObject = squadSpec[4];
      const char* const squadClassName = squadClassNameObject.GetString();
      SCR_GetEnum(state, squadClassName, enumRef);

      // 0x0072DD5B / 0x0072DD8D / 0x0072E015 / 0x0072E044: units are drawn from
      // the Unassigned squad of the platoon the method was called on (arg 1,
      // the army pool), never from the freshly made, squadless `newPlatoon`.
      EntitySetTemplate<Unit> ref{};
      if (argumentCount <= 4) {
        if (unitFilter.IsString()) {
          platoon->GetUnassignedUnitsWithBP(unitFilter.GetString(), requiredSize, ref);
        } else {
          const EntityCategorySet* const category = func_GetCObj_EntityCategory(unitFilter);
          platoon->GetUnassignedUnitsInCategory(category, requiredSize, ref);
        }
      } else {
        EntitySetTemplate<Unit> candidates{};
        if (unitFilter.IsString()) {
          platoon->GetUnassignedUnitsWithBP(unitFilter.GetString(), 1000, candidates);
        } else {
          const EntityCategorySet* const category = func_GetCObj_EntityCategory(unitFilter);
          platoon->GetUnassignedUnitsInCategory(category, 1000, candidates);
        }

        const LuaPlus::LuaObject centerObject(LuaPlus::LuaStackObject(state, 4));
        const Wm3::Vector3f center = SCR_FromLuaCopy<Wm3::Vector3<float>>(centerObject);

        LuaPlus::LuaStackObject radiusArg(state, 5);
        if (lua_type(state->m_state, 5) != kLuaNumberTypeTag) {
          LuaPlus::LuaStackObject::TypeError(&radiusArg, "number");
        }
        const float radius = static_cast<float>(lua_tonumber(state->m_state, 5));
        const float radiusSquared = radius * radius;

        fa::vector<PlatoonUnitSearchEntry> nearbyUnits;
        for (Entity* const* entityIt = candidates.mVec.begin(); entityIt != candidates.mVec.end(); ++entityIt) {
          Entity* const entity = *entityIt;
          if (entity == nullptr) {
            continue;
          }
          Unit* const unit = static_cast<Unit*>(entity);
          if (unit->IsDead() || unit->DestroyQueued() || unit->IsBeingBuilt()) {
            continue;
          }
          const Wm3::Vec3f& unitPosition = unit->GetPosition();
          const float deltaX = unitPosition.x - center.x;
          const float deltaZ = unitPosition.z - center.z;
          const float distanceSquared = deltaX * deltaX + deltaZ * deltaZ;
          if (radiusSquared > distanceSquared) {
            nearbyUnits.push_back(PlatoonUnitSearchEntry{unit, distanceSquared});
          }
        }

        // The call inlines the `std::sort` entry and runs the MSVC8 introsort
        // driver for the 8-byte entry directly, seeding the recursion budget
        // with the element count; the instantiation (driver, partition,
        // ninther, insertion sort, heap fallback) is catalogued on
        // legacy/algorithms/Sort.h. Units at equal distance are taken in the
        // order that algorithm leaves them, which the modern `std::sort` does
        // not reproduce.
        fa::sort(
          nearbyUnits.begin(),
          nearbyUnits.end(),
          [](const PlatoonUnitSearchEntry& lhs, const PlatoonUnitSearchEntry& rhs) noexcept {
            return lhs.distanceSq < rhs.distanceSq;
          }
        );

        int added = 0;
        for (const PlatoonUnitSearchEntry& candidate : nearbyUnits) {
          (void)ref.Add(candidate.unit);
          if (++added == requiredSize) {
            break;
          }
        }
      }

      newPlatoon->mArmy->RemoveUnitsFromPlatoons(&ref);

      // 0x0072E08C-0x0072E0A0: a missing squad is created named after the row's
      // [5] formation string, not the [4] squad-class string.
      CSquad* squad = newPlatoon->GetSquad(squadClass);
      if (squad == nullptr) {
        squad = CSquad::AllocateOnPlatoon(newPlatoon, squadClass, formationObject.GetString());
      }
      newPlatoon->AppendUnitsToSquad(squad, ref);
    }

    // 0x0072E17C-0x0072E18C: returns the new platoon's own script object
    // (`CScriptObject::mLuaObj`, +0x20), not its cached unit list.
    newPlatoon->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x0072CE70 (FUN_0072CE70, cfunc_CPlatoonCanFormPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanFormPlatoonL`.
   */
  int cfunc_CPlatoonCanFormPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanFormPlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072CE90 (FUN_0072CE90, func_CPlatoonCanFormPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanFormPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanFormPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanFormPlatoon",
      &cfunc_CPlatoonCanFormPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanFormPlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072D870 (FUN_0072D870, cfunc_CPlatoonFormPlatoon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFormPlatoonL`.
   */
  int cfunc_CPlatoonFormPlatoon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFormPlatoonL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072D890 (FUN_0072D890, func_CPlatoonFormPlatoon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FormPlatoon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFormPlatoon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FormPlatoon",
      &cfunc_CPlatoonFormPlatoon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFormPlatoonHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072E940 (FUN_0072E940, cfunc_CPlatoonSetPrioritizedTargetListL)
   *
   * What it does:
   * Resolves `(platoon, squadClass, categoryTable)` from Lua, copies category
   * entries into a temporary prioritized-category vector, then replaces the
   * matching squad's prioritized target list.
   */
  int cfunc_CPlatoonSetPrioritizedTargetListL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 3, kSetPrioritizedTargetListHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    fa::vector<EntityCategorySet> prioritizedCategories{};
    const LuaPlus::LuaObject categoryTable(LuaPlus::LuaStackObject(state, 3));
    if (categoryTable.IsTable()) {
      const int categoryCount = categoryTable.GetCount();
      for (int categoryIndex = 1; categoryIndex <= categoryCount; ++categoryIndex) {
        const LuaPlus::LuaObject categoryObject = categoryTable[categoryIndex];
        if (EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); categorySet != nullptr) {
          // Route per-T push_back through the canonical helper (FUN_006DB010)
          // so the MSVC8 vector<EntityCategorySet>::push_back template
          // emission symbol shape is preserved.
          moho::PushBackEntityCategorySetVector(prioritizedCategories, *categorySet);
        }
      }

      platoon->SetPrioritizedTargetList(squadClass, prioritizedCategories);
    }

    return 0;
  }

  /**
   * Address: 0x0072E8C0 (FUN_0072E8C0, cfunc_CPlatoonSetPrioritizedTargetList)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonSetPrioritizedTargetListL`.
   */
  int cfunc_CPlatoonSetPrioritizedTargetList(lua_State* const luaContext)
  {
    return cfunc_CPlatoonSetPrioritizedTargetListL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072E8E0 (FUN_0072E8E0, func_CPlatoonSetPrioritizedTargetList_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SetPrioritizedTargetList()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSetPrioritizedTargetList_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetPrioritizedTargetList",
      &cfunc_CPlatoonSetPrioritizedTargetList,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kSetPrioritizedTargetListHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072EB30 (FUN_0072EB30, cfunc_CPlatoonFindPrioritizedUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindPrioritizedUnitL`.
   */
  int cfunc_CPlatoonFindPrioritizedUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindPrioritizedUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072EB50 (FUN_0072EB50, func_CPlatoonFindPrioritizedUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindPrioritizedUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindPrioritizedUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindPrioritizedUnit",
      &cfunc_CPlatoonFindPrioritizedUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindPrioritizedUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072EBB0 (FUN_0072EBB0, cfunc_CPlatoonFindPrioritizedUnitL)
   *
   * IDA signature:
   * int __usercall cfunc_CPlatoonFindPrioritizedUnitL@<eax>(LuaPlus::LuaState *state@<ebx>);
   *
   * What it does:
   * Parses `(platoon, squadClassName, allianceName, canAttack, center, radius)`
   * from Lua, calls `CPlatoon::FindPrioritizedUnit`, and pushes the found unit's
   * Lua object (or nil).
   */
  int cfunc_CPlatoonFindPrioritizedUnitL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 6, kFindPrioritizedUnitHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef squadClassRef{};
    squadClassRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);
    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, squadClassRef);

    EAlliance alliance = static_cast<EAlliance>(0);
    gpg::RRef allianceRef{};
    allianceRef = gpg::MakeRRef<moho::EAlliance>(&alliance);
    const char* const allianceName = lua_tostring(state->m_state, 3);
    if (allianceName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 3);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, allianceName, allianceRef);

    LuaPlus::LuaStackObject canAttackArg(state, 4);
    const bool canAttack = canAttackArg.GetBoolean();

    const LuaPlus::LuaObject centerObject(LuaPlus::LuaStackObject(state, 5));
    const Wm3::Vector3f center = SCR_FromLuaCopy<Wm3::Vector3<float>>(centerObject);

    LuaPlus::LuaStackObject radiusArg(state, 6);
    if (lua_type(state->m_state, 6) != 3 /* LUA_TNUMBER */) {
      LuaPlus::LuaStackObject::TypeError(&radiusArg, "number");
    }
    const float radius = static_cast<float>(lua_tonumber(radiusArg.m_state->m_state, radiusArg.m_stackIndex));

    Unit* const foundUnit = platoon->FindPrioritizedUnit(squadClass, alliance, canAttack, center, radius);
    if (foundUnit != nullptr) {
      foundUnit->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
    }
    return 1;
  }

  /**
   * Address: 0x0072EE60 (FUN_0072EE60, cfunc_CPlatoonFindClosestUnitL)
   *
   * What it does:
   * Resolves `(platoon, squadClass, alliance, canAttack, category)` from Lua and
   * returns the nearest matching unit to the requested squad center.
   */
  int cfunc_CPlatoonFindClosestUnitL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 5, kFindClosestUnitHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef squadClassRef{};
    squadClassRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);
    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, squadClassRef);

    EAlliance alliance = static_cast<EAlliance>(0);
    gpg::RRef allianceRef{};
    allianceRef = gpg::MakeRRef<moho::EAlliance>(&alliance);
    const char* const allianceName = lua_tostring(state->m_state, 3);
    if (allianceName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 3);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, allianceName, allianceRef);

    LuaPlus::LuaStackObject canAttackArg(state, 4);
    const bool canAttack = canAttackArg.GetBoolean();

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 5));
    EntityCategorySet* const category = func_GetCObj_EntityCategory(categoryObject);

    Unit* const foundUnit = platoon->FindClosestUnit(category, COMPARE_Closest, squadClass, alliance, canAttack);
    if (foundUnit != nullptr) {
      foundUnit->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
    }
    return 1;
  }

  /**
   * Address: 0x0072F310 (FUN_0072F310, cfunc_CPlatoonFindFurthestUnitL)
   *
   * What it does:
   * Twin of `cfunc_CPlatoonFindClosestUnitL` selecting the furthest matching
   * unit from the requested squad center (COMPARE_Furthest).
   */
  int cfunc_CPlatoonFindFurthestUnitL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 5, kFindFurthestUnitHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef squadClassRef{};
    squadClassRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);
    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, squadClassRef);

    EAlliance alliance = static_cast<EAlliance>(0);
    gpg::RRef allianceRef{};
    allianceRef = gpg::MakeRRef<moho::EAlliance>(&alliance);
    const char* const allianceName = lua_tostring(state->m_state, 3);
    if (allianceName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 3);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, allianceName, allianceRef);

    LuaPlus::LuaStackObject canAttackArg(state, 4);
    const bool canAttack = canAttackArg.GetBoolean();

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 5));
    EntityCategorySet* const category = func_GetCObj_EntityCategory(categoryObject);

    Unit* const foundUnit = platoon->FindClosestUnit(category, COMPARE_Furthest, squadClass, alliance, canAttack);
    if (foundUnit != nullptr) {
      foundUnit->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
    }
    return 1;
  }

  /**
   * Address: 0x0072F550 (FUN_0072F550, cfunc_CPlatoonFindHighestValueUnitL)
   *
   * What it does:
   * Twin of `cfunc_CPlatoonFindClosestUnitL` selecting the highest build-value
   * matching unit (COMPARE_HighestValue).
   */
  int cfunc_CPlatoonFindHighestValueUnitL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 5, kFindHighestValueUnitHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef squadClassRef{};
    squadClassRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);
    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, squadClassRef);

    EAlliance alliance = static_cast<EAlliance>(0);
    gpg::RRef allianceRef{};
    allianceRef = gpg::MakeRRef<moho::EAlliance>(&alliance);
    const char* const allianceName = lua_tostring(state->m_state, 3);
    if (allianceName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 3);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, allianceName, allianceRef);

    LuaPlus::LuaStackObject canAttackArg(state, 4);
    const bool canAttack = canAttackArg.GetBoolean();

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 5));
    EntityCategorySet* const category = func_GetCObj_EntityCategory(categoryObject);

    Unit* const foundUnit = platoon->FindClosestUnit(category, COMPARE_HighestValue, squadClass, alliance, canAttack);
    if (foundUnit != nullptr) {
      foundUnit->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
    }
    return 1;
  }

  /**
   * Address: 0x0072F0A0 (FUN_0072F0A0, cfunc_CPlatoonFindClosestUnitToBaseL)
   *
   * What it does:
   * Like `cfunc_CPlatoonFindClosestUnitL` but references the army's base center
   * (`CAiBrain::CenterOfArmy`) instead of a squad center, calling the leaf query
   * directly with COMPARE_Closest.
   */
  int cfunc_CPlatoonFindClosestUnitToBaseL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 5, kFindClosestUnitToBaseHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef squadClassRef{};
    squadClassRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);
    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, squadClassRef);

    EAlliance alliance = static_cast<EAlliance>(0);
    gpg::RRef allianceRef{};
    allianceRef = gpg::MakeRRef<moho::EAlliance>(&alliance);
    const char* const allianceName = lua_tostring(state->m_state, 3);
    if (allianceName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 3);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, allianceName, allianceRef);

    LuaPlus::LuaStackObject canAttackArg(state, 4);
    const bool canAttack = canAttackArg.GetBoolean();

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 5));
    EntityCategorySet* const category = func_GetCObj_EntityCategory(categoryObject);

    Wm3::Vector3f baseCenter;
    platoon->mArmy->GetArmyBrain()->CenterOfArmy(&baseCenter);

    Unit* const foundUnit =
      platoon->FindClosestUnitToPos(category, COMPARE_Closest, squadClass, alliance, canAttack, baseCenter);
    if (foundUnit != nullptr) {
      foundUnit->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
    }
    return 1;
  }

  /**
   * Address: 0x0072EDE0 (FUN_0072EDE0, cfunc_CPlatoonFindClosestUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindClosestUnitL`.
   */
  int cfunc_CPlatoonFindClosestUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindClosestUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072EE00 (FUN_0072EE00, func_CPlatoonFindClosestUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindClosestUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindClosestUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindClosestUnit",
      &cfunc_CPlatoonFindClosestUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindClosestUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F020 (FUN_0072F020, cfunc_CPlatoonFindClosestUnitToBase)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindClosestUnitToBaseL`.
   */
  int cfunc_CPlatoonFindClosestUnitToBase(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindClosestUnitToBaseL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F040 (FUN_0072F040, func_CPlatoonFindClosestUnitToBase_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindClosestUnitToBase()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindClosestUnitToBase_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindClosestUnitToBase",
      &cfunc_CPlatoonFindClosestUnitToBase,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindClosestUnitToBaseHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F290 (FUN_0072F290, cfunc_CPlatoonFindFurthestUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindFurthestUnitL`.
   */
  int cfunc_CPlatoonFindFurthestUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindFurthestUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F2B0 (FUN_0072F2B0, func_CPlatoonFindFurthestUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindFurthestUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindFurthestUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindFurthestUnit",
      &cfunc_CPlatoonFindFurthestUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindFurthestUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F4D0 (FUN_0072F4D0, cfunc_CPlatoonFindHighestValueUnit)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFindHighestValueUnitL`.
   */
  int cfunc_CPlatoonFindHighestValueUnit(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFindHighestValueUnitL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F4F0 (FUN_0072F4F0, func_CPlatoonFindHighestValueUnit_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FindHighestValueUnit()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFindHighestValueUnit_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FindHighestValueUnit",
      &cfunc_CPlatoonFindHighestValueUnit,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFindHighestValueUnitHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F790 (FUN_0072F790, cfunc_CPlatoonCanAttackTargetL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonCanAttackTargetL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, squadClass, targetUnit)`, finds the first squad in
   * the requested class, and forwards the target to `CSquad::CanAttackTarget`.
   * When the class is absent the Lua callback returns no values.
   */
  int cfunc_CPlatoonCanAttackTargetL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 3, kCanAttackTargetHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = static_cast<ESquadClass>(0);
    gpg::RRef enumRef{};
    enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

    const char* const squadClassName = lua_tostring(state->m_state, 2);
    if (squadClassName == nullptr) {
      LuaPlus::LuaStackObject typeErrorArg(state, 2);
      LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
    }
    SCR_GetEnum(state, squadClassName, enumRef);

    CSquad* const squad = platoon->GetSquad(squadClass);
    if (squad == nullptr) {
      return 0;
    }

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 3));
    Unit* const targetUnit = SCR_FromLua_Unit(targetObject);
    const bool canAttack = squad->CanAttackTarget(targetUnit);

    lua_pushboolean(state->m_state, canAttack ? 1 : 0);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  /**
   * Address: 0x0072F710 (FUN_0072F710, cfunc_CPlatoonCanAttackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCanAttackTargetL`.
   */
  int cfunc_CPlatoonCanAttackTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCanAttackTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F730 (FUN_0072F730, func_CPlatoonCanAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CanAttackTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCanAttackTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CanAttackTarget",
      &cfunc_CPlatoonCanAttackTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCanAttackTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072F940 (FUN_0072F940, cfunc_CPlatoonStop)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonStopL`.
   */
  int cfunc_CPlatoonStop(lua_State* const luaContext)
  {
    return cfunc_CPlatoonStopL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072F9C0 (FUN_0072F9C0, cfunc_CPlatoonStopL)
   *
   * What it does:
   * Resolves `(platoon [, squadClass])` and dispatches `CPlatoon::Stop` with
   * default squad class `6` (all squads) when arg#2 is omitted.
   */
  int cfunc_CPlatoonStopL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kStopHelpText,
        1,
        2,
        argumentCount
      );
    }

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    ESquadClass squadClass = kAllSquadClasses;
    if (argumentCount > 1) {
      gpg::RRef enumRef{};
      enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

      const char* squadClassName = lua_tostring(state->m_state, 2);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 2);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }

      SCR_GetEnum(state, squadClassName, enumRef);
    }

    platoon->Stop(squadClass);
    return 0;
  }

  /**
   * Address: 0x0072F960 (FUN_0072F960, func_CPlatoonStop_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Stop()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonStop_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Stop",
      &cfunc_CPlatoonStop,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kStopHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072FB60 (FUN_0072FB60, cfunc_CPlatoonAttackTargetL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonAttackTargetL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, targetEntity[, squadClass])` and issues the attack via
   * `CPlatoon::AttackTarget`, returning the issued commands as a Lua array. The
   * squad class defaults to the all-classes sentinel; arg 3 overrides it.
   */
  int cfunc_CPlatoonAttackTargetL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kAttackTargetHelpText, 2, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const target = SCR_FromLua_Entity(targetObject, state);

    ESquadClass squadClass = kAllSquadClasses;
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->AttackTarget(target, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x0072FAE0 (FUN_0072FAE0, cfunc_CPlatoonAttackTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonAttackTargetL`.
   */
  int cfunc_CPlatoonAttackTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonAttackTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072FB00 (FUN_0072FB00, func_CPlatoonAttackTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:AttackTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonAttackTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "AttackTarget",
      &cfunc_CPlatoonAttackTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kAttackTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0072FE30 (FUN_0072FE30, cfunc_CPlatoonMoveToTargetL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonMoveToTargetL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, targetEntity, useTransports[, squadClass])` and issues the
   * move via `CPlatoon::MoveToTarget`, returning the issued commands as a Lua
   * array. The squad class defaults to the all-classes sentinel; arg 4 overrides.
   */
  int cfunc_CPlatoonMoveToTargetL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 4) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kMoveToTargetHelpText, 2, 4, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const target = SCR_FromLua_Entity(targetObject, state);

    LuaPlus::LuaStackObject useTransportsArg(state, 3);
    const bool useTransports = useTransportsArg.GetBoolean();

    ESquadClass squadClass = kAllSquadClasses;
    if (lua_gettop(state->m_state) > 3) {
      gpg::RRef enumRef{};
      enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 4);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 4);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->MoveToTarget(target, useTransports, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x0072FDB0 (FUN_0072FDB0, cfunc_CPlatoonMoveToTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonMoveToTargetL`.
   */
  int cfunc_CPlatoonMoveToTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonMoveToTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0072FDD0 (FUN_0072FDD0, func_CPlatoonMoveToTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:MoveToTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonMoveToTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "MoveToTarget",
      &cfunc_CPlatoonMoveToTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kMoveToTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00730120 (FUN_00730120, cfunc_CPlatoonMoveToLocationL)
   *
   * IDA signature:
   * int __usercall cfunc_CPlatoonMoveToLocationL@<eax>(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, point, useTransports[, squadClass])`, validates the point,
   * and issues the move via `CPlatoon::MoveToLocation`, returning the issued
   * commands as a Lua array. The squad class defaults to the all-classes sentinel.
   */
  int cfunc_CPlatoonMoveToLocationL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 4) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kMoveToLocationHelpText, 2, 4, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    Wm3::Vector3f targetPoint = SCR_FromLuaCopy<Wm3::Vector3<float>>(locationObject);

    LuaPlus::LuaStackObject useTransportsArg(state, 3);
    const bool useTransports = useTransportsArg.GetBoolean();

    if (!IsValidVector3f(targetPoint)) {
      // NB: the binary's literal reads "Platoon:MoveToTarget" here -- an original-source
      // copy-paste artifact in the MoveToLocation worker; preserved verbatim for 1:1.
      LuaPlus::LuaState::Error(state, "Platoon:MoveToTarget Passed in an invalid target point");
    }

    ESquadClass squadClass = kAllSquadClasses;
    if (lua_gettop(state->m_state) > 3) {
      gpg::RRef enumRef{};
      enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 4);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 4);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->MoveToLocation(targetPoint, useTransports, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x007300A0 (FUN_007300A0, cfunc_CPlatoonMoveToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonMoveToLocationL`.
   */
  int cfunc_CPlatoonMoveToLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonMoveToLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007300C0 (FUN_007300C0, func_CPlatoonMoveToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:MoveToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonMoveToLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "MoveToLocation",
      &cfunc_CPlatoonMoveToLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kMoveToLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00730420 (FUN_00730420, cfunc_CPlatoonAggressiveMoveToLocationL)
   *
   * What it does:
   * Parses `(platoon, location[, squadClass])`, validates the point, issues the
   * aggressive-move orders via `CPlatoon::AggressiveMoveToLocation`, returns the
   * issued commands as a Lua array, then releases the weak command links.
   */
  int cfunc_CPlatoonAggressiveMoveToLocationL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kAggressiveMoveToLocationHelpText, 2, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    Wm3::Vector3f targetPoint = SCR_FromLuaCopy<Wm3::Vector3<float>>(locationObject);
    if (!IsValidVector3f(targetPoint)) {
      LuaPlus::LuaState::Error(state, "Platoon:AggressiveMoveToLocation Passed in an invalid target point");
    }

    ESquadClass squadClass = kAllSquadClasses;
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->AggressiveMoveToLocation(targetPoint, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x007303A0 (FUN_007303A0, cfunc_CPlatoonAggressiveMoveToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonAggressiveMoveToLocationL`.
   */
  int cfunc_CPlatoonAggressiveMoveToLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonAggressiveMoveToLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007303C0 (FUN_007303C0, func_CPlatoonAggressiveMoveToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:AggressiveMoveToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonAggressiveMoveToLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "AggressiveMoveToLocation",
      &cfunc_CPlatoonAggressiveMoveToLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kAggressiveMoveToLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00730700 (FUN_00730700, cfunc_CPlatoonFerryToLocationL)
   *
   * What it does:
   * Parses `(platoon, location)`, validates the point, issues the ferry orders
   * via `CPlatoon::FerryToLocation`, returns the issued commands as a Lua array,
   * then releases the weak command links.
   */
  int cfunc_CPlatoonFerryToLocationL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kFerryToLocationHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    Wm3::Vector3f targetPos = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);
    if (!IsValidVector3f(targetPos)) {
      LuaPlus::LuaState::Error(state, "Platoon:FerryToLocation Passed in an invalid target point");
    }

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->FerryToLocation(targetPos);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00730680 (FUN_00730680, cfunc_CPlatoonFerryToLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonFerryToLocationL`.
   */
  int cfunc_CPlatoonFerryToLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonFerryToLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007306A0 (FUN_007306A0, func_CPlatoonFerryToLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:FerryToLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonFerryToLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "FerryToLocation",
      &cfunc_CPlatoonFerryToLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kFerryToLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007308F0 (FUN_007308F0, cfunc_CPlatoonLoadUnits)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonLoadUnitsL`.
   */
  int cfunc_CPlatoonLoadUnits(lua_State* const luaContext)
  {
    return cfunc_CPlatoonLoadUnitsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00730910 (FUN_00730910, func_CPlatoonLoadUnits_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:LoadUnits()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonLoadUnits_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "LoadUnits",
      &cfunc_CPlatoonLoadUnits,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kLoadUnitsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00730970 (FUN_00730970, cfunc_CPlatoonLoadUnitsL)
   *
   * IDA signature:
   * int __thiscall cfunc_CPlatoonLoadUnitsL(LuaPlus::LuaState *state)
   *
   * What it does:
   * Resolves `(platoon, category)`, issues platoon transport-load commands,
   * builds a Lua array of resulting command objects, and unlinks temporary
   * weak command links before returning.
   */
  int cfunc_CPlatoonLoadUnitsL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kLoadUnitsHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->LoadUnits(categorySet);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00730B90 (FUN_00730B90, cfunc_CPlatoonUnloadUnitsAtLocationL)
   *
   * What it does:
   * Parses `(platoon, category, location)`, resolves the reflected
   * `EntityCategorySet`, validates the point, issues the unload orders via
   * `CPlatoon::UnloadUnitsAtLocation`, returns the issued commands as a Lua array,
   * then releases the weak command links.
   */
  int cfunc_CPlatoonUnloadUnitsAtLocationL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 3, kUnloadUnitsAtLocationHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const category = func_GetCObj_EntityCategory(categoryObject);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 3));
    Wm3::Vector3f targetPos = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);
    if (!IsValidVector3f(targetPos)) {
      LuaPlus::LuaState::Error(state, "Platoon:UnloadUnitsAtLocation Passed in an invalid target point");
    }

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->UnloadUnitsAtLocation(category, targetPos);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00730B10 (FUN_00730B10, cfunc_CPlatoonUnloadUnitsAtLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUnloadUnitsAtLocationL`.
   */
  int cfunc_CPlatoonUnloadUnitsAtLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUnloadUnitsAtLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00730B30 (FUN_00730B30, func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UnloadUnitsAtLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUnloadUnitsAtLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UnloadUnitsAtLocation",
      &cfunc_CPlatoonUnloadUnitsAtLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUnloadUnitsAtLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00730E30 (FUN_00730E30, cfunc_CPlatoonUnloadAllAtLocationL)
   *
   * What it does:
   * Parses `(platoon, location)`, validates the point, issues the unload orders
   * via `CPlatoon::UnloadAllAtLocation`, returns the issued commands as a Lua
   * array, then releases the weak command links.
   */
  int cfunc_CPlatoonUnloadAllAtLocationL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kUnloadAllAtLocationHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject locationObject(LuaPlus::LuaStackObject(state, 2));
    const Wm3::Vector3f targetPos = SCR_FromLuaCopy<Wm3::Vec3f>(locationObject);
    if (!IsValidVector3f(targetPos)) {
      LuaPlus::LuaState::Error(state, "Platoon:UnloadAllAtLocation Passed in an invalid target point");
    }

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->UnloadAllAtLocation(targetPos);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00730DB0 (FUN_00730DB0, cfunc_CPlatoonUnloadAllAtLocation)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUnloadAllAtLocationL`.
   */
  int cfunc_CPlatoonUnloadAllAtLocation(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUnloadAllAtLocationL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00730DD0 (FUN_00730DD0, func_CPlatoonUnloadAllAtLocation_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UnloadAllAtLocation()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUnloadAllAtLocation_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UnloadAllAtLocation",
      &cfunc_CPlatoonUnloadAllAtLocation,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUnloadAllAtLocationHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731370 (FUN_00731370, cfunc_CPlatoonPatrolL)
   *
   * IDA signature:
   * int __usercall cfunc_CPlatoonPatrolL@<eax>(LuaPlus::LuaState *state@<ebx>)
   *
   * What it does:
   * Resolves `(platoon, targetPoint[, squadClass])`, validates the point, and
   * issues the patrol via `CPlatoon::Patrol`. The squad class defaults to the
   * all-classes sentinel and is only read from arg 3 when supplied.
   */
  int cfunc_CPlatoonPatrolL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kPatrolHelpText, 2, 3, argumentCount);
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Wm3::Vector3f targetPoint = SCR_FromLuaCopy<Wm3::Vector3<float>>(targetObject);
    if (!IsValidVector3f(targetPoint)) {
      LuaPlus::LuaState::Error(state, "Platoon:Patrol Passed in an invalid target point");
    }

    ESquadClass squadClass = kAllSquadClasses;
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }
      SCR_GetEnum(state, squadClassName, enumRef);
    }

    platoon->Patrol(targetPoint, squadClass);
    return 0;
  }

  /**
   * Address: 0x007312F0 (FUN_007312F0, cfunc_CPlatoonPatrol)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonPatrolL`.
   */
  int cfunc_CPlatoonPatrol(lua_State* const luaContext)
  {
    return cfunc_CPlatoonPatrolL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731310 (FUN_00731310, func_CPlatoonPatrol_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Patrol()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPatrol_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Patrol",
      &cfunc_CPlatoonPatrol,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kPatrolHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007310A0 (FUN_007310A0, cfunc_CPlatoonGuardTargetL)
   *
   * What it does:
   * Parses `(platoon, targetUnit, [squadClass])`, issues guard orders on the
   * platoon via `CPlatoon::GuardTarget`, returns the issued commands as a
   * Lua array, then releases the weak command links.
   */
  int cfunc_CPlatoonGuardTargetL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kGuardTargetHelpText,
        2,
        3,
        argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Unit* const guardTarget = SCR_FromLua_Unit(targetObject);

    ESquadClass squadClass = kAllSquadClasses;
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }

      SCR_GetEnum(state, squadClassName, enumRef);
    }

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->GuardTarget(guardTarget, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00731020 (FUN_00731020, cfunc_CPlatoonGuardTarget)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGuardTargetL`.
   */
  int cfunc_CPlatoonGuardTarget(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGuardTargetL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731040 (FUN_00731040, func_CPlatoonGuardTarget_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GuardTarget()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGuardTarget_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GuardTarget",
      &cfunc_CPlatoonGuardTarget,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGuardTargetHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731570 (FUN_00731570, cfunc_CPlatoonDestroyL)
   *
   * What it does:
   * Parses `(platoon, [squadClass])`, and when the platoon is still alive,
   * destroys the selected squads via `CPlatoon::DestroySquads`.
   */
  int cfunc_CPlatoonDestroyL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected between %d and %d args, but got %d", kDestroyHelpText, 1, 2, argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (platoon != nullptr) {
      ESquadClass squadClass = kAllSquadClasses;
      if (lua_gettop(state->m_state) > 1) {
        gpg::RRef enumRef{};
        enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

        const char* const squadClassName = lua_tostring(state->m_state, 2);
        if (squadClassName == nullptr) {
          LuaPlus::LuaStackObject typeErrorArg(state, 2);
          LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
        }

        SCR_GetEnum(state, squadClassName, enumRef);
      }

      platoon->DestroySquads(squadClass);
    }

    return 0;
  }

  /**
   * Address: 0x007314F0 (FUN_007314F0, cfunc_CPlatoonDestroy)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonDestroyL`.
   */
  int cfunc_CPlatoonDestroy(lua_State* const luaContext)
  {
    return cfunc_CPlatoonDestroyL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731510 (FUN_00731510, func_CPlatoonDestroy_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:Destroy()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonDestroy_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Destroy",
      &cfunc_CPlatoonDestroy,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kDestroyHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731840 (FUN_00731840, cfunc_CPlatoonGetFerryBeaconsL)
   *
   * What it does:
   * Parses `(platoon)`, gathers the platoon's ferry beacons via
   * `CPlatoon::GetFerryBeacons`, and returns them as a Lua array of unit objects.
   */
  int cfunc_CPlatoonGetFerryBeaconsL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kGetFerryBeaconsHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    EntitySetTemplate<Unit> ferryBeacons{};
    platoon->GetFerryBeacons(ferryBeacons);

    LuaPlus::LuaObject beaconTable{};
    beaconTable.AssignNewTable(state, static_cast<int>(ferryBeacons.Size()), 0);

    int beaconIndex = 1;
    for (Entity* const* entry = ferryBeacons.mVec.begin(); entry != ferryBeacons.mVec.end(); ++entry) {
      Unit* const beacon = static_cast<Unit*>(*entry);
      if (beacon == nullptr) {
        continue;
      }
      LuaPlus::LuaObject beaconObject = beacon->GetLuaObject();
      beaconTable.Insert(beaconIndex, beaconObject);
      ++beaconIndex;
    }

    beaconTable.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x007317C0 (FUN_007317C0, cfunc_CPlatoonGetFerryBeacons)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetFerryBeaconsL`.
   */
  int cfunc_CPlatoonGetFerryBeacons(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetFerryBeaconsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007317E0 (FUN_007317E0, func_CPlatoonGetFerryBeacons_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetFerryBeacons()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetFerryBeacons_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetFerryBeacons",
      &cfunc_CPlatoonGetFerryBeacons,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetFerryBeaconsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731A30 (FUN_00731A30, cfunc_CPlatoonUseFerryBeaconL)
   *
   * What it does:
   * Parses `(platoon, category, beacon)`, resolves the reflected `EntityCategorySet`
   * and the beacon unit, issues the load orders via `CPlatoon::UseFerryBeacon`,
   * returns the issued commands as a Lua array, then releases the weak command links.
   */
  int cfunc_CPlatoonUseFerryBeaconL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 3, kUseFerryBeaconHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const category = func_GetCObj_EntityCategory(categoryObject);

    const LuaPlus::LuaObject beaconObject(LuaPlus::LuaStackObject(state, 3));
    Unit* const beacon = SCR_FromLua_Unit(beaconObject);

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->UseFerryBeacon(category, beacon);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x007319B0 (FUN_007319B0, cfunc_CPlatoonUseFerryBeacon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUseFerryBeaconL`.
   */
  int cfunc_CPlatoonUseFerryBeacon(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUseFerryBeaconL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007319D0 (FUN_007319D0, func_CPlatoonUseFerryBeacon_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UseFerryBeacon()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUseFerryBeacon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UseFerryBeacon",
      &cfunc_CPlatoonUseFerryBeacon,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUseFerryBeaconHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00731CB0 (FUN_00731CB0, cfunc_CPlatoonUseTeleporterL)
   *
   * What it does:
   * Parses `(platoon, teleporterUnit, [squadClass])`, issues the teleporter-load
   * orders via `CPlatoon::UseTeleporter`, returns the issued commands as a Lua
   * array, then releases the weak command links.
   */
  int cfunc_CPlatoonUseTeleporterL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount < 2 || argumentCount > 3) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kUseTeleporterHelpText,
        2,
        3,
        argumentCount
      );
    }

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    const LuaPlus::LuaObject teleporterObject(LuaPlus::LuaStackObject(state, 2));
    Unit* const teleporter = SCR_FromLua_Unit(teleporterObject);

    ESquadClass squadClass = kAllSquadClasses;
    if (lua_gettop(state->m_state) > 2) {
      gpg::RRef enumRef{};
      enumRef = gpg::MakeRRef<moho::ESquadClass>(&squadClass);

      const char* const squadClassName = lua_tostring(state->m_state, 3);
      if (squadClassName == nullptr) {
        LuaPlus::LuaStackObject typeErrorArg(state, 3);
        LuaPlus::LuaStackObject::TypeError(&typeErrorArg, "string");
      }

      SCR_GetEnum(state, squadClassName, enumRef);
    }

    fa::vector<WeakPtr<CUnitCommand>> issuedCommands = platoon->UseTeleporter(teleporter, squadClass);

    LuaPlus::LuaObject commandTable{};
    commandTable.AssignNewTable(state, static_cast<int>(issuedCommands.size()), 0);

    // Appends each command's own script object (`Insert(obj)` 0x00909AF0 on
    // `command + 0x20`, `CScriptObject::mLuaObj`), as every platoon order
    // binding does in 0x0072FB60-0x00731E6B; `mArgs` is unbound for
    // platoon-issued commands and tripped `m_state == obj.m_state`.
    for (const WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      CUnitCommand* const command = commandLink.GetObjectPtr();
      commandTable.Insert(command->mLuaObj);
    }

    commandTable.PushStack(state);

    for (WeakPtr<CUnitCommand>& commandLink : issuedCommands) {
      commandLink.ResetFromObject(nullptr);
    }

    return 1;
  }

  /**
   * Address: 0x00731C30 (FUN_00731C30, cfunc_CPlatoonUseTeleporter)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonUseTeleporterL`.
   */
  int cfunc_CPlatoonUseTeleporter(lua_State* const luaContext)
  {
    return cfunc_CPlatoonUseTeleporterL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00731C50 (FUN_00731C50, func_CPlatoonUseTeleporter_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:UseTeleporter()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonUseTeleporter_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "UseTeleporter",
      &cfunc_CPlatoonUseTeleporter,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kUseTeleporterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00732140 (FUN_00732140, cfunc_CPlatoonSetPlatoonFormationOverrideL)
   *
   * What it does:
   * Resolves `(platoon, formationName)` from Lua, maps `"None"` to empty text,
   * and stores the formation override.
   */
  int cfunc_CPlatoonSetPlatoonFormationOverrideL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kSetPlatoonFormationOverrideHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoon(platoonObject, state);

    LuaPlus::LuaStackObject formationArg(state, 2);
    const char* formationText = lua_tostring(state->m_state, 2);
    if (formationText == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&formationArg, "string");
      formationText = "";
    }

    fa::string formationOverride{};
    if (_stricmp(formationText, "None") != 0) {
      formationOverride.assign(formationText);
    }

    platoon->SetPlatoonFormationOverride(formationOverride);
    return 0;
  }

  /**
   * Address: 0x007320C0 (FUN_007320C0, cfunc_CPlatoonSetPlatoonFormationOverride)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonSetPlatoonFormationOverrideL`.
   */
  int cfunc_CPlatoonSetPlatoonFormationOverride(lua_State* const luaContext)
  {
    return cfunc_CPlatoonSetPlatoonFormationOverrideL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x007320E0 (FUN_007320E0, func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:SetPlatoonFormationOverride()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonSetPlatoonFormationOverride_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetPlatoonFormationOverride",
      &cfunc_CPlatoonSetPlatoonFormationOverride,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kSetPlatoonFormationOverrideHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007322D0 (FUN_007322D0, cfunc_CPlatoonGetPlatoonLifetimeStats)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonGetPlatoonLifetimeStatsL`.
   */
  int cfunc_CPlatoonGetPlatoonLifetimeStats(lua_State* const luaContext)
  {
    return cfunc_CPlatoonGetPlatoonLifetimeStatsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732350 (FUN_00732350, cfunc_CPlatoonGetPlatoonLifetimeStatsL)
   *
   * What it does:
   * Resolves one platoon and pushes its four lifetime stats (kills, losses, damage dealt, damage received), or
   * `nil` when the platoon object is absent.
   */
  int cfunc_CPlatoonGetPlatoonLifetimeStatsL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 1, kGetPlatoonLifetimeStatsHelpText);

    const LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (platoon == nullptr) {
      lua_pushnil(state->m_state);
      (void)lua_gettop(state->m_state);
      return 1;
    }

    lua_pushnumber(state->m_state, static_cast<float>(platoon->GetKills()));
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, static_cast<float>(platoon->GetLosses()));
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, platoon->GetDamageDealt());
    (void)lua_gettop(state->m_state);
    lua_pushnumber(state->m_state, platoon->GetDamageReceived());
    (void)lua_gettop(state->m_state);
    return 4;
  }

  /**
   * Address: 0x007322F0 (FUN_007322F0, func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:GetPlatoonLifetimeStats()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonGetPlatoonLifetimeStats_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "GetPlatoonLifetimeStats",
      &cfunc_CPlatoonGetPlatoonLifetimeStats,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kGetPlatoonLifetimeStatsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007324A0 (FUN_007324A0, cfunc_CPlatoonCalculatePlatoonThreat)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonCalculatePlatoonThreatL`.
   */
  int cfunc_CPlatoonCalculatePlatoonThreat(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCalculatePlatoonThreatL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732520 (FUN_00732520, cfunc_CPlatoonCalculatePlatoonThreatL)
   *
   * What it does:
   * Resolves `(platoon, threatType, category)` and returns total threat across
   * live platoon units matching the requested category.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 3, kCalculatePlatoonThreatHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaStackObject threatTypeArg(state, 2);
    const char* const threatTypeName = lua_tostring(state->m_state, 2);
    if (threatTypeName == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&threatTypeArg, "string");
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 3));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);
    const PlatoonThreatType threatType = ParsePlatoonThreatType(threatTypeName);

    EntitySetTemplate<Unit> platoonUnits = platoon->GetPlatoonUnits();

    float totalThreat = 0.0f;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = static_cast<Unit*>(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (!BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        continue;
      }

      totalThreat = AddBlueprintThreat(totalThreat, *unitBlueprint, threatType);
    }

    lua_pushnumber(state->m_state, totalThreat);
    return 1;
  }

  /**
   * Address: 0x007324C0 (FUN_007324C0, func_CPlatoonCalculatePlatoonThreat_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CalculatePlatoonThreat()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCalculatePlatoonThreat_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CalculatePlatoonThreat",
      &cfunc_CPlatoonCalculatePlatoonThreat,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCalculatePlatoonThreatHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007328E0 (FUN_007328E0, cfunc_CPlatoonCalculatePlatoonThreatAroundPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL`.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732960 (FUN_00732960, cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL)
   *
   * What it does:
   * Resolves `(platoon, threatType, category, position, radius)` and returns
   * category-filtered threat from live platoon units within 2D radius.
   */
  int cfunc_CPlatoonCalculatePlatoonThreatAroundPositionL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 5, kCalculatePlatoonThreatAroundPositionHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaStackObject threatTypeArg(state, 2);
    const char* const threatTypeName = lua_tostring(state->m_state, 2);
    if (threatTypeName == nullptr) {
      LuaPlus::LuaStackObject::TypeError(&threatTypeArg, "string");
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 3));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 4));
    const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);
    const float radiusSq = ReadSquaredRadiusArg(state, 5);
    const PlatoonThreatType threatType = ParsePlatoonThreatType(threatTypeName);

    EntitySetTemplate<Unit> platoonUnits = platoon->GetPlatoonUnits();

    float totalThreat = 0.0f;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = static_cast<Unit*>(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const Wm3::Vector3f& unitPosition = unit->GetPosition();
      const float dx = position.x - unitPosition.x;
      const float dz = position.z - unitPosition.z;
      if ((dx * dx + dz * dz) > radiusSq) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (!BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        continue;
      }

      totalThreat = AddBlueprintThreat(totalThreat, *unitBlueprint, threatType);
    }

    lua_pushnumber(state->m_state, totalThreat);
    return 1;
  }

  /**
   * Address: 0x00732900 (FUN_00732900, func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:CalculatePlatoonThreatAroundPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonCalculatePlatoonThreatAroundPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CalculatePlatoonThreatAroundPosition",
      &cfunc_CPlatoonCalculatePlatoonThreatAroundPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kCalculatePlatoonThreatAroundPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00732E40 (FUN_00732E40, cfunc_CPlatoonPlatoonCategoryCountAroundPosition)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_CPlatoonPlatoonCategoryCountAroundPositionL`.
   */
  int cfunc_CPlatoonPlatoonCategoryCountAroundPosition(lua_State* const luaContext)
  {
    return cfunc_CPlatoonPlatoonCategoryCountAroundPositionL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00732EC0 (FUN_00732EC0, cfunc_CPlatoonPlatoonCategoryCountAroundPositionL)
   *
   * What it does:
   * Resolves `(platoon, category, position, radius)` and counts live platoon
   * units matching the category within 2D radius.
   */
  int cfunc_CPlatoonPlatoonCategoryCountAroundPositionL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 4, kPlatoonCategoryCountAroundPositionHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);
    LuaPlus::LuaObject positionObject(LuaPlus::LuaStackObject(state, 3));
    const Wm3::Vector3f position = SCR_FromLuaCopy<Wm3::Vector3<float>>(positionObject);
    const float radiusSq = ReadSquaredRadiusArg(state, 4);

    EntitySetTemplate<Unit> platoonUnits = platoon->GetPlatoonUnits();

    int matchingCount = 0;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = static_cast<Unit*>(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const Wm3::Vector3f& unitPosition = unit->GetPosition();
      const float dx = position.x - unitPosition.x;
      const float dz = position.z - unitPosition.z;
      if ((dx * dx + dz * dz) > radiusSq) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        ++matchingCount;
      }
    }

    lua_pushnumber(state->m_state, static_cast<float>(matchingCount));
    return 1;
  }

  /**
   * Address: 0x00732E60 (FUN_00732E60, func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:PlatoonCategoryCountAroundPosition()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPlatoonCategoryCountAroundPosition_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "PlatoonCategoryCountAroundPosition",
      &cfunc_CPlatoonPlatoonCategoryCountAroundPosition,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kPlatoonCategoryCountAroundPositionHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x007331C0 (FUN_007331C0, cfunc_CPlatoonPlatoonCategoryCount)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CPlatoonPlatoonCategoryCountL`.
   */
  int cfunc_CPlatoonPlatoonCategoryCount(lua_State* const luaContext)
  {
    return cfunc_CPlatoonPlatoonCategoryCountL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00733240 (FUN_00733240, cfunc_CPlatoonPlatoonCategoryCountL)
   *
   * What it does:
   * Resolves `(platoon, category)` and counts live platoon units matching
   * that category.
   */
  int cfunc_CPlatoonPlatoonCategoryCountL(LuaPlus::LuaState* const state)
  {
    moho::SCR_ExpectExactArgs(state, 2, kPlatoonCategoryCountHelpText);

    LuaPlus::LuaObject platoonObject(LuaPlus::LuaStackObject(state, 1));
    CPlatoon* const platoon = SCR_FromLua_CPlatoonOpt(platoonObject, state);
    if (!platoon) {
      lua_pushnumber(state->m_state, 0.0f);
      return 1;
    }

    LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    EntitySetTemplate<Unit> platoonUnits = platoon->GetPlatoonUnits();

    int matchingCount = 0;
    for (moho::Entity* const* entityIt = platoonUnits.mVec.begin(); entityIt != platoonUnits.mVec.end(); ++entityIt) {
      const Unit* const unit = static_cast<Unit*>(*entityIt);
      if (!IsThreatCandidateUnit(unit)) {
        continue;
      }

      const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
      if (BlueprintMatchesCategory(unitBlueprint, categorySet)) {
        ++matchingCount;
      }
    }

    lua_pushnumber(state->m_state, static_cast<float>(matchingCount));
    return 1;
  }

  /**
   * Address: 0x007331E0 (FUN_007331E0, func_CPlatoonPlatoonCategoryCount_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CPlatoon:PlatoonCategoryCount()` Lua binder form.
   */
  CScrLuaInitForm* func_CPlatoonPlatoonCategoryCount_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "PlatoonCategoryCount",
      &cfunc_CPlatoonPlatoonCategoryCount,
      &CScrLuaMetatableFactory<CPlatoon>::Instance(),
      "CPlatoon",
      kPlatoonCategoryCountHelpText
    );
    return &binder;
  }
}

