#include "moho/sim/SimLuaPrivate.h"

namespace
{
  /**
   * Address: 0x00707BF0 (FUN_00707BF0, func_IsNeutral)
   *
   * What it does:
   * Returns whether `targetArmyIndex` is in one neutral-relation bitset lane.
   * Legacy behavior treats `0xFFFFFFFF` as neutral by default.
   */
  [[nodiscard]] bool IsArmyMarkedNeutral(const std::uint32_t targetArmyIndex, const moho::BVIntSet& neutralSet) noexcept
  {
    if (targetArmyIndex == std::numeric_limits<std::uint32_t>::max()) {
      return true;
    }

    return neutralSet.Contains(targetArmyIndex);
  }
  constexpr const char* kIsGameOverHelpText = "Return true if the game is over (i.e. EndGame() has been called).";
  constexpr const char* kGetGameTimeSecondsSimHelpText =
    "Get the current game time in seconds. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kGetGameTickHelpText =
    "Get the current game time in ticks. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kGetSystemTimeSecondsOnlyForProfileUseHelpText =
    "float GetSystemTimeSecondsOnlyForProfileUse() - returns System time in seconds";
  constexpr const char* kGetTimeForProfileSimHelpText = "(OriginTime)";
  constexpr const char* kGetMouseWorldPosHelpText = "vector GetMouseWorldPos()";
  constexpr const char* kGetMouseWorldPosArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kGetMouseWorldPosNoSessionText = "No session started.";
  constexpr const char* kGetDepositsAroundPointHelpText = "(X, Z, Radius, Type)";
  constexpr const char* kIsEntityHelpText = "bool = IsEntity(object)";
  constexpr const char* kIsUnitHelpText = "Unit = IsUnit(entity)";
  constexpr const char* kIsPropHelpText = "Prop = IsProp(entity)";
  constexpr const char* kIsBlipHelpText = "Blip = IsBlip(entity)";
  constexpr const char* kIsProjectileHelpText = "Projectile = IsProjectile(entity)";
  constexpr const char* kIsCollisionBeamHelpText = "CollisionBeam = IsCollisionBeam(entity)";
  constexpr const char* kGetCurrentCommandSourceHelpText = "Return the (1 based) index of the current command source.";
  constexpr const char* kGetEntitiesInRectHelpText = "Return the enitities inside the given rectangle";
  constexpr const char* kGetUnitsInRectHelpText = "Return the units inside the given rectangle";
  constexpr const char* kGetReclaimablesInRectHelpText = "Return the reclamable things inside the given rectangle";
  constexpr const char* kGetMapSizeHelpText = "sizeX, sizeZ = GetMapSize()";
  constexpr const char* kGetFocusArmySimHelpText = "GetFocusArmy()";
  constexpr const char* kHasLocalizedVOSimHelpText = "HasLocalizedVO(language)";
  constexpr const char* kGetArmyBrainHelpText = "army";
  constexpr const char* kIsAllySimHelpText = "IsAlly(army1,army2)";
  constexpr const char* kIsEnemySimHelpText = "IsEnemy(army1,army2)";
  constexpr const char* kIsNeutralSimHelpText = "IsNeutral(army1,army2)";
  constexpr const char* kGetArmyUnitCostTotalHelpText = "army";
  constexpr const char* kGetArmyUnitCapHelpText = "army";
  constexpr const char* kGetEntityByIdHelpText = "Get entity by entity id";
  constexpr const char* kGetUnitByIdSimHelpText = "Get entity by entity id";
  constexpr const char* kGetTerrainHeightHelpText = "type = GetTerrainHeight(x,z)";
  constexpr const char* kGetSurfaceHeightHelpText = "type = GetSurfaceHeight(x,z)";
  constexpr const char* kGetTerrainTypeOffsetHelpText = "type = GetTerrainTypeOffset(x,z)";
  constexpr const char* kGetTerrainTypeLuaDefHelpText = "type = GetTerrainType(x,z)";
  constexpr const char* kGetTerrainTypeHelpText = "GetTerrainType( x, z )";
  constexpr const char* kGetUnitBlueprintByNameLuaDefHelpText = "blueprint = GetUnitBlueprintByName(bpName)";
  constexpr const char* kGetUnitBlueprintByNameHelpText = "GetUnitBlueprintByName(blueprint_name)";

  [[nodiscard]] Entity* ResolveRequiredEntityLuaArg(
    LuaPlus::LuaState* const state,
    const char* const helpText
  )
  {
    if (!state || !state->m_state) {
      return nullptr;
    }

    moho::SCR_ExpectExactArgs(state, 1, helpText);

    const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
    return SCR_FromLua_Entity(entityObject, state);
  }

  template <typename TEntityLike>
  int PushEntityScriptObjectOrNil(LuaPlus::LuaState* const state, TEntityLike* const object)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    if (object == nullptr) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    object->mLuaObj.PushStack(state);
    return 1;
  }

  template <typename TValue>
  void LuaPushNumberField(lua_State* const state, const char* const key, const TValue value)
  {
    lua_pushstring(state, key);
    lua_pushnumber(state, static_cast<lua_Number>(value));
    lua_rawset(state, -3);
  }
}


/**
 * Address: 0x0075E4E0 (FUN_0075E4E0, cfunc_IsEntity)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsEntityL`.
 */
int moho::cfunc_IsEntity(lua_State* const luaContext)
{
  return cfunc_IsEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E500 (FUN_0075E500, func_IsEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsEntity`.
 */
moho::CScrLuaInitForm* moho::func_IsEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsEntity",
    &moho::cfunc_IsEntity,
    nullptr,
    "<global>",
    kIsEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E560 (FUN_0075E560, cfunc_IsEntityL)
 *
 * What it does:
 * Returns true when arg#1 resolves to an entity userdata object.
 */
int moho::cfunc_IsEntityL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kIsEntityHelpText);

  const LuaPlus::LuaObject objectArg(LuaPlus::LuaStackObject(state, 1));
  const Entity* const entity = SCR_FromLuaNoError_Entity(objectArg);
  lua_pushboolean(rawState, entity ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0075E620 (FUN_0075E620, cfunc_IsUnit)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsUnitL`.
 */
int moho::cfunc_IsUnit(lua_State* const luaContext)
{
  return cfunc_IsUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E640 (FUN_0075E640, func_IsUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsUnit`.
 */
moho::CScrLuaInitForm* moho::func_IsUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsUnit",
    &moho::cfunc_IsUnit,
    nullptr,
    "<global>",
    kIsUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E6A0 (FUN_0075E6A0, cfunc_IsUnitL)
 *
 * What it does:
 * Returns arg#1 as unit Lua object when the entity is a unit; otherwise nil.
 */
int moho::cfunc_IsUnitL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsUnitHelpText);
  Unit* const unit = entity ? entity->IsUnit() : nullptr;
  return PushEntityScriptObjectOrNil(state, unit);
}

/**
 * Address: 0x0075E780 (FUN_0075E780, cfunc_IsProp)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsPropL`.
 */
int moho::cfunc_IsProp(lua_State* const luaContext)
{
  return cfunc_IsPropL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E7A0 (FUN_0075E7A0, func_IsProp_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsProp`.
 */
moho::CScrLuaInitForm* moho::func_IsProp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsProp",
    &moho::cfunc_IsProp,
    nullptr,
    "<global>",
    kIsPropHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E800 (FUN_0075E800, cfunc_IsPropL)
 *
 * What it does:
 * Returns arg#1 as prop Lua object when the entity is a prop; otherwise nil.
 */
int moho::cfunc_IsPropL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsPropHelpText);
  Prop* const prop = entity ? entity->IsProp() : nullptr;
  return PushEntityScriptObjectOrNil(state, prop);
}

/**
 * Address: 0x0075E8E0 (FUN_0075E8E0, cfunc_IsBlip)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsBlipL`.
 */
int moho::cfunc_IsBlip(lua_State* const luaContext)
{
  return cfunc_IsBlipL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075E900 (FUN_0075E900, func_IsBlip_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsBlip`.
 */
moho::CScrLuaInitForm* moho::func_IsBlip_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsBlip",
    &moho::cfunc_IsBlip,
    nullptr,
    "<global>",
    kIsBlipHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075E960 (FUN_0075E960, cfunc_IsBlipL)
 *
 * What it does:
 * Returns arg#1 as recon-blip Lua object when the entity is a blip;
 * otherwise nil.
 */
int moho::cfunc_IsBlipL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsBlipHelpText);
  ReconBlip* const blip = entity ? entity->IsReconBlip() : nullptr;
  return PushEntityScriptObjectOrNil(state, blip);
}

/**
 * Address: 0x0075EA40 (FUN_0075EA40, cfunc_IsProjectile)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsProjectileL`.
 */
int moho::cfunc_IsProjectile(lua_State* const luaContext)
{
  return cfunc_IsProjectileL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075EA60 (FUN_0075EA60, func_IsProjectile_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsProjectile`.
 */
moho::CScrLuaInitForm* moho::func_IsProjectile_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsProjectile",
    &moho::cfunc_IsProjectile,
    nullptr,
    "<global>",
    kIsProjectileHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075EAC0 (FUN_0075EAC0, cfunc_IsProjectileL)
 *
 * What it does:
 * Returns arg#1 as projectile Lua object when the entity is a projectile;
 * otherwise nil.
 */
int moho::cfunc_IsProjectileL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsProjectileHelpText);
  Projectile* const projectile = entity ? entity->IsProjectile() : nullptr;
  return PushEntityScriptObjectOrNil(state, projectile);
}

/**
 * Address: 0x0075EBA0 (FUN_0075EBA0, cfunc_IsCollisionBeam)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsCollisionBeamL`.
 */
int moho::cfunc_IsCollisionBeam(lua_State* const luaContext)
{
  return cfunc_IsCollisionBeamL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075EBC0 (FUN_0075EBC0, func_IsCollisionBeam_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsCollisionBeam`.
 */
moho::CScrLuaInitForm* moho::func_IsCollisionBeam_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsCollisionBeam",
    &moho::cfunc_IsCollisionBeam,
    nullptr,
    "<global>",
    kIsCollisionBeamHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075EC20 (FUN_0075EC20, cfunc_IsCollisionBeamL)
 *
 * What it does:
 * Returns arg#1 as collision-beam Lua object when the entity is a collision
 * beam; otherwise nil.
 */
int moho::cfunc_IsCollisionBeamL(LuaPlus::LuaState* const state)
{
  Entity* const entity = ResolveRequiredEntityLuaArg(state, kIsCollisionBeamHelpText);
  CollisionBeamEntity* const collisionBeam = entity ? entity->IsCollisionBeam() : nullptr;
  return PushEntityScriptObjectOrNil(state, collisionBeam);
}

/**
 * Address: 0x0074B710 (FUN_0074B710, cfunc_GetCurrentCommandSource)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_GetCurrentCommandSourceL`.
 */
int moho::cfunc_GetCurrentCommandSource(lua_State* const luaContext)
{
  return cfunc_GetCurrentCommandSourceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0074B730 (FUN_0074B730, func_GetCurrentCommandSource_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetCurrentCommandSource()` Lua binder in the sim init
 * set.
 */
moho::CScrLuaInitForm* moho::func_GetCurrentCommandSource_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetCurrentCommandSource",
    &moho::cfunc_GetCurrentCommandSource,
    nullptr,
    "<global>",
    kGetCurrentCommandSourceHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074B790 (FUN_0074B790, cfunc_GetCurrentCommandSourceL)
 *
 * What it does:
 * Returns the current command source index as 1-based Lua number, or nil
 * when no source is active.
 */
int moho::cfunc_GetCurrentCommandSourceL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetCurrentCommandSourceHelpText);

  const Sim* const sim = ResolveGlobalSim(state->m_state);
  const SSTICommandSource* const source = sim != nullptr ? sim->GetCurrentCommandSource() : nullptr;
  if (source == nullptr) {
    lua_pushnil(state->m_state);
    (void)lua_gettop(state->m_state);
    return 1;
  }

  lua_pushnumber(state->m_state, static_cast<float>(source->mIndex + 1u));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0074B980 (FUN_0074B980, cfunc_IsGameOverL)
 *
 * What it does:
 * Validates Lua argument count and pushes Sim end-game state.
 */
int moho::cfunc_IsGameOverL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    luaL_error(rawState, "%s\n  expected %d args, but got %d", kIsGameOverHelpText, 0, argumentCount);
  }

  const Sim* const sim = ResolveGlobalSim(rawState);
  const bool isGameOver = sim && (sim->mGameEnded || sim->mGameOver);
  lua_pushboolean(rawState, isGameOver ? 1 : 0);
  return 1;
}

/**
 * Address: 0x0074B900 (FUN_0074B900, cfunc_IsGameOver)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_IsGameOverL`.
 */
int moho::cfunc_IsGameOver(lua_State* const luaContext)
{
  return cfunc_IsGameOverL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A770 (FUN_0075A770, cfunc_GetGameTimeSecondsSim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetGameTimeSecondsSimL`.
 */
int moho::cfunc_GetGameTimeSecondsSim(lua_State* const luaContext)
{
  return cfunc_GetGameTimeSecondsSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A790 (FUN_0075A790, func_GetGameTimeSecondsSim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetGameTimeSeconds()` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_GetGameTimeSecondsSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetGameTimeSeconds",
    &moho::cfunc_GetGameTimeSecondsSim,
    nullptr,
    "<global>",
    kGetGameTimeSecondsSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A7F0 (FUN_0075A7F0, cfunc_GetGameTimeSecondsSimL)
 *
 * What it does:
 * Validates no Lua args and returns simulation time in seconds.
 */
int moho::cfunc_GetGameTimeSecondsSimL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetGameTimeSecondsSimHelpText);

  const Sim* const sim = ResolveGlobalSim(state->m_state);
  lua_pushnumber(state->m_state, static_cast<float>(sim->mCurTick) * 0.1f);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0075A860 (FUN_0075A860, cfunc_GetGameTick)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetGameTickL`.
 */
int moho::cfunc_GetGameTick(lua_State* const luaContext)
{
  return cfunc_GetGameTickL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A880 (FUN_0075A880, func_GetGameTick_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetGameTick()` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_GetGameTick_LuaFuncDef()
{
  static CScrLuaBinder
    binder(SimLuaInitSet(), "GetGameTick", &moho::cfunc_GetGameTick, nullptr, "<global>", kGetGameTickHelpText);
  return &binder;
}

/**
 * Address: 0x0075A8E0 (FUN_0075A8E0, cfunc_GetGameTickL)
 *
 * What it does:
 * Validates no Lua args and returns simulation tick count.
 */
int moho::cfunc_GetGameTickL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetGameTickHelpText);

  const Sim* const sim = ResolveGlobalSim(state->m_state);
  lua_pushnumber(state->m_state, static_cast<float>(sim->mCurTick));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0075A950 (FUN_0075A950, cfunc_GetSystemTimeSecondsOnlyForProfileUse)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_GetSystemTimeSecondsOnlyForProfileUseL`.
 */
int moho::cfunc_GetSystemTimeSecondsOnlyForProfileUse(lua_State* const luaContext)
{
  return cfunc_GetSystemTimeSecondsOnlyForProfileUseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075A970 (FUN_0075A970, func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetSystemTimeSecondsOnlyForProfileUse()` Lua binder in
 * the sim init set.
 */
moho::CScrLuaInitForm* moho::func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetSystemTimeSecondsOnlyForProfileUse",
    &moho::cfunc_GetSystemTimeSecondsOnlyForProfileUse,
    nullptr,
    "<global>",
    kGetSystemTimeSecondsOnlyForProfileUseHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075A9D0 (FUN_0075A9D0, cfunc_GetSystemTimeSecondsOnlyForProfileUseL)
 *
 * What it does:
 * Validates no Lua args and returns system timer elapsed seconds.
 */
int moho::cfunc_GetSystemTimeSecondsOnlyForProfileUseL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetSystemTimeSecondsOnlyForProfileUseHelpText);

  lua_pushnumber(state->m_state, gpg::time::GetSystemTimer().ElapsedSeconds());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0075AA30 (FUN_0075AA30, cfunc_GetEntitiesInRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetEntitiesInRectL`.
 */
int moho::cfunc_GetEntitiesInRect(lua_State* const luaContext)
{
  return cfunc_GetEntitiesInRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075AA50 (FUN_0075AA50, func_GetEntitiesInRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetEntitiesInRect(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetEntitiesInRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetEntitiesInRect",
    &moho::cfunc_GetEntitiesInRect,
    nullptr,
    "<global>",
    kGetEntitiesInRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075AAB0 (FUN_0075AAB0, cfunc_GetEntitiesInRectL)
 *
 * What it does:
 * Reads one rectangle (`rect` or `x0,z0,x1,z1`) and returns a Lua table of
 * entities (unit/prop/projectile/entity) inside the query rectangle.
 */
int moho::cfunc_GetEntitiesInRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 4) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kGetEntitiesInRectHelpText,
      1,
      4,
      argumentCount
    );
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  COGrid* const oGrid = sim ? sim->mOGrid : nullptr;
  if (oGrid == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  gpg::Rect2f queryRect{};
  if (lua_gettop(rawState) == 1) {
    auto rectObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 1));
    queryRect = SCR_FromLuaCopy<gpg::Rect2f>(rectObject);
  } else {
    LuaPlus::LuaStackObject x0Arg(state, 1);
    if (lua_type(rawState, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x0Arg, "number");
    }
    queryRect.x0 = static_cast<float>(lua_tonumber(rawState, 1));

    LuaPlus::LuaStackObject z0Arg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z0Arg, "number");
    }
    queryRect.z0 = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject x1Arg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x1Arg, "number");
    }
    queryRect.x1 = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject z1Arg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z1Arg, "number");
    }
    queryRect.z1 = static_cast<float>(lua_tonumber(rawState, 4));
  }

  CollisionDBRect collisionRect{};
  (void)func_Rect2fToInt16(&collisionRect, queryRect);

  gpg::core::FastVectorN<CollisionShapeBase*, 20> gatheredSpans{};
  constexpr EEntityType kEntityMask = static_cast<EEntityType>(
    ENTITYTYPE_Unit | ENTITYTYPE_Prop | ENTITYTYPE_Projectile | ENTITYTYPE_Entity
  );
  const int gatheredCount = oGrid->mEntityOccupationManager.GatherUnmarkedUnitsInRect(
    gatheredSpans,
    collisionRect,
    kEntityMask
  );
  if (gatheredCount <= 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  auto resultTable = LuaPlus::LuaObject();
  resultTable.AssignNewTable(state, gatheredCount, 0);
  int luaIndex = 1;
  for (int index = 0; index < gatheredCount; ++index) {
    Entity* const entity = CollisionShape<Entity>::OwnerOf(gatheredSpans[index]);
    const auto entityObject = LuaPlus::LuaObject(entity->mLuaObj);
    resultTable.SetObject(luaIndex, entityObject);
    ++luaIndex;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075AE00 (FUN_0075AE00, cfunc_GetUnitsInRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUnitsInRectL`.
 */
int moho::cfunc_GetUnitsInRect(lua_State* const luaContext)
{
  return cfunc_GetUnitsInRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075AE20 (FUN_0075AE20, func_GetUnitsInRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetUnitsInRect(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetUnitsInRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetUnitsInRect",
    &moho::cfunc_GetUnitsInRect,
    nullptr,
    "<global>",
    kGetUnitsInRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075AE80 (FUN_0075AE80, cfunc_GetUnitsInRectL)
 *
 * What it does:
 * Reads one rectangle (`rect` or `x0,z0,x1,z1`) and returns a Lua table of
 * unit objects inside the query rectangle.
 */
int moho::cfunc_GetUnitsInRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 4) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kGetUnitsInRectHelpText,
      1,
      4,
      argumentCount
    );
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  COGrid* const oGrid = sim ? sim->mOGrid : nullptr;
  if (oGrid == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  gpg::Rect2f queryRect{};
  if (lua_gettop(rawState) == 1) {
    auto rectObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 1));
    queryRect = SCR_FromLuaCopy<gpg::Rect2f>(rectObject);
  } else {
    LuaPlus::LuaStackObject x0Arg(state, 1);
    if (lua_type(rawState, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x0Arg, "number");
    }
    queryRect.x0 = static_cast<float>(lua_tonumber(rawState, 1));

    LuaPlus::LuaStackObject z0Arg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z0Arg, "number");
    }
    queryRect.z0 = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject x1Arg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x1Arg, "number");
    }
    queryRect.x1 = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject z1Arg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z1Arg, "number");
    }
    queryRect.z1 = static_cast<float>(lua_tonumber(rawState, 4));
  }

  CollisionDBRect collisionRect{};
  (void)func_Rect2fToInt16(&collisionRect, queryRect);

  gpg::core::FastVectorN<CollisionShapeBase*, 20> gatheredSpans{};
  const int gatheredCount =
    oGrid->mEntityOccupationManager.GatherUnmarkedUnitsInRect(gatheredSpans, collisionRect, ENTITYTYPE_Unit);
  if (gatheredCount <= 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  auto resultTable = LuaPlus::LuaObject();
  resultTable.AssignNewTable(state, gatheredCount, 0);
  int luaIndex = 1;
  for (int index = 0; index < gatheredCount; ++index) {
    Entity* const entity = CollisionShape<Entity>::OwnerOf(gatheredSpans[index]);
    Unit* const unit = entity != nullptr ? entity->IsUnit() : nullptr;
    if (unit == nullptr) {
      continue;
    }

    const auto unitObject = LuaPlus::LuaObject(unit->GetLuaObject());
    resultTable.SetObject(luaIndex, unitObject);
    ++luaIndex;
  }

  // 0x0075B198: once anything was gathered retail pushes the table even when
  // no entry turned out to be a unit (no second nil path).
  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075B200 (FUN_0075B200, cfunc_GetReclaimablesInRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_GetReclaimablesInRectL`.
 */
int moho::cfunc_GetReclaimablesInRect(lua_State* const luaContext)
{
  return cfunc_GetReclaimablesInRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075B220 (FUN_0075B220, func_GetReclaimablesInRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetReclaimablesInRect(...)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetReclaimablesInRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetReclaimablesInRect",
    &moho::cfunc_GetReclaimablesInRect,
    nullptr,
    "<global>",
    kGetReclaimablesInRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075B280 (FUN_0075B280, cfunc_GetReclaimablesInRectL)
 *
 * What it does:
 * Reads one rectangle (`rect` or `x0,z0,x1,z1`) and returns a Lua table of
 * reclaimable entity objects (units/props) inside the query rectangle.
 */
int moho::cfunc_GetReclaimablesInRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 4) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kGetReclaimablesInRectHelpText,
      1,
      4,
      argumentCount
    );
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  COGrid* const oGrid = sim ? sim->mOGrid : nullptr;
  if (oGrid == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  gpg::Rect2f queryRect{};
  if (lua_gettop(rawState) == 1) {
    auto rectObject = LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 1));
    queryRect = SCR_FromLuaCopy<gpg::Rect2f>(rectObject);
  } else {
    LuaPlus::LuaStackObject x0Arg(state, 1);
    if (lua_type(rawState, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x0Arg, "number");
    }
    queryRect.x0 = static_cast<float>(lua_tonumber(rawState, 1));

    LuaPlus::LuaStackObject z0Arg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z0Arg, "number");
    }
    queryRect.z0 = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject x1Arg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&x1Arg, "number");
    }
    queryRect.x1 = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject z1Arg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&z1Arg, "number");
    }
    queryRect.z1 = static_cast<float>(lua_tonumber(rawState, 4));
  }

  CollisionDBRect collisionRect{};
  (void)func_Rect2fToInt16(&collisionRect, queryRect);

  gpg::core::FastVectorN<CollisionShapeBase*, 20> gatheredSpans{};
  constexpr EEntityType kReclaimableMask = static_cast<EEntityType>(ENTITYTYPE_Unit | ENTITYTYPE_Prop);
  const int gatheredCount = oGrid->mEntityOccupationManager.GatherUnmarkedUnitsInRect(
    gatheredSpans,
    collisionRect,
    kReclaimableMask
  );
  if (gatheredCount <= 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  auto resultTable = LuaPlus::LuaObject();
  resultTable.AssignNewTable(state, gatheredCount, 0);
  int luaIndex = 1;
  for (int index = 0; index < gatheredCount; ++index) {
    Entity* const entity = CollisionShape<Entity>::OwnerOf(gatheredSpans[index]);
    const auto entityObject = LuaPlus::LuaObject(entity->mLuaObj);
    resultTable.SetObject(luaIndex, entityObject);
    ++luaIndex;
  }

  if (luaIndex <= 1) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075BBE0 (FUN_0075BBE0, cfunc_GetMapSize)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetMapSizeL`.
 */
int moho::cfunc_GetMapSize(lua_State* const luaContext)
{
  return cfunc_GetMapSizeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075BC00 (FUN_0075BC00, func_GetMapSize_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetMapSize()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetMapSize_LuaFuncDef()
{
  static CScrLuaBinder
    binder(SimLuaInitSet(), "GetMapSize", &moho::cfunc_GetMapSize, nullptr, "<global>", kGetMapSizeHelpText);
  return &binder;
}

/**
 * Address: 0x0075BC60 (FUN_0075BC60, cfunc_GetMapSizeL)
 *
 * What it does:
 * Validates no Lua args and returns map width/height extents in terrain grid
 * coordinates.
 */
int moho::cfunc_GetMapSizeL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetMapSizeHelpText);

  Sim* const sim = ResolveGlobalSim(state->m_state);
  STIMap* const map = sim->mMapData;
  CHeightField* const field = map->mHeightField.get();
  lua_pushnumber(state->m_state, static_cast<float>(field->width - 1));
  (void)lua_gettop(state->m_state);
  lua_pushnumber(state->m_state, static_cast<float>(field->height - 1));
  (void)lua_gettop(state->m_state);
  return 2;
}

/**
 * Address: 0x0075BD10 (FUN_0075BD10, func_GetTerrainHeight_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetTerrainHeight(x,z)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetTerrainHeight_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetTerrainHeight",
    &moho::cfunc_GetTerrainHeight,
    nullptr,
    "<global>",
    kGetTerrainHeightHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075BCF0 (FUN_0075BCF0, cfunc_GetTerrainHeight)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetTerrainHeightL`.
 */
int moho::cfunc_GetTerrainHeight(lua_State* const luaContext)
{
  return cfunc_GetTerrainHeightL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075BD70 (FUN_0075BD70, cfunc_GetTerrainHeightL)
 *
 * What it does:
 * Reads `(x, z)` and returns terrain elevation sampled from map heightfield.
 */
int moho::cfunc_GetTerrainHeightL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kGetTerrainHeightHelpText);

  LuaPlus::LuaStackObject xArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }
  const float x = static_cast<float>(lua_tonumber(rawState, 1));

  LuaPlus::LuaStackObject zArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "number");
  }
  const float z = static_cast<float>(lua_tonumber(rawState, 2));

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  CHeightField* const field = map ? map->mHeightField.get() : nullptr;
  const float terrainHeight = field ? field->GetElevation(x, z) : 0.0f;
  lua_pushnumber(rawState, terrainHeight);
  return 1;
}

/**
 * Address: 0x0075BE90 (FUN_0075BE90, func_GetSurfaceHeight_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetSurfaceHeight(x,z)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetSurfaceHeight_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetSurfaceHeight",
    &moho::cfunc_GetSurfaceHeight,
    nullptr,
    "<global>",
    kGetSurfaceHeightHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075BE70 (FUN_0075BE70, cfunc_GetSurfaceHeight)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetSurfaceHeightL`.
 */
int moho::cfunc_GetSurfaceHeight(lua_State* const luaContext)
{
  return cfunc_GetSurfaceHeightL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075BEF0 (FUN_0075BEF0, cfunc_GetSurfaceHeightL)
 *
 * What it does:
 * Reads `(x, z)` and returns max(terrainHeight, waterElevation) when water is
 * enabled, otherwise terrain height.
 */
int moho::cfunc_GetSurfaceHeightL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kGetSurfaceHeightHelpText);

  LuaPlus::LuaStackObject xArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }
  const float x = static_cast<float>(lua_tonumber(rawState, 1));

  LuaPlus::LuaStackObject zArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "number");
  }
  const float z = static_cast<float>(lua_tonumber(rawState, 2));

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  CHeightField* const field = map ? map->mHeightField.get() : nullptr;

  float surfaceHeight = field ? field->GetElevation(x, z) : 0.0f;
  // Engine addition (water bodies): the level at (x, z); -10000 without water.
  const float waterHeight = map ? map->GetWaterElevationAt(x, z) : -10000.0f;
  if (waterHeight > surfaceHeight) {
    surfaceHeight = waterHeight;
  }

  lua_pushnumber(rawState, surfaceHeight);
  return 1;
}

/**
 * Address: 0x0075C050 (FUN_0075C050, func_GetTerrainTypeOffset_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetTerrainTypeOffset(x,z)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetTerrainTypeOffset_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetTerrainTypeOffset",
    &moho::cfunc_GetTerrainTypeOffset,
    nullptr,
    "<global>",
    kGetTerrainTypeOffsetHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075C030 (FUN_0075C030, cfunc_GetTerrainTypeOffset)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetTerrainTypeOffsetL`.
 */
int moho::cfunc_GetTerrainTypeOffset(lua_State* const luaContext)
{
  return cfunc_GetTerrainTypeOffsetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C0B0 (FUN_0075C0B0, cfunc_GetTerrainTypeOffsetL)
 *
 * What it does:
 * Reads `(x, z)` and returns terrain texture offset value at map position.
 */
int moho::cfunc_GetTerrainTypeOffsetL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kGetTerrainTypeOffsetHelpText);

  LuaPlus::LuaStackObject xArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "number");
  }
  const float x = static_cast<float>(lua_tonumber(rawState, 1));

  LuaPlus::LuaStackObject zArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "number");
  }
  const float z = static_cast<float>(lua_tonumber(rawState, 2));

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  const float terrainTypeOffset = map ? map->GetTerrainTypeOffset(x, z) : 0.0f;
  lua_pushnumber(rawState, terrainTypeOffset);
  return 1;
}

/**
 * Address: 0x0075C1D0 (FUN_0075C1D0, func_GetTerrainType_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetTerrainType(x,z)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetTerrainType_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetTerrainType",
    &moho::cfunc_GetTerrainType,
    nullptr,
    "<global>",
    kGetTerrainTypeLuaDefHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075C1B0 (FUN_0075C1B0, cfunc_GetTerrainType)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetTerrainTypeL`.
 */
int moho::cfunc_GetTerrainType(lua_State* const luaContext)
{
  return cfunc_GetTerrainTypeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C230 (FUN_0075C230, cfunc_GetTerrainTypeL)
 *
 * What it does:
 * Reads `(x, z)` from Lua, queries terrain type from `Sim::mMapData`, and
 * returns the terrain-type Lua table.
 */
int moho::cfunc_GetTerrainTypeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kGetTerrainTypeHelpText);

  LuaPlus::LuaStackObject xArg{};
  xArg.m_state = state;
  xArg.m_stackIndex = 1;
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&xArg, "integer");
  }
  const std::uint32_t x = static_cast<std::uint32_t>(static_cast<std::int64_t>(lua_tonumber(rawState, 1)));

  LuaPlus::LuaStackObject zArg{};
  zArg.m_state = state;
  zArg.m_stackIndex = 2;
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&zArg, "integer");
  }
  const std::uint32_t z = static_cast<std::uint32_t>(static_cast<std::int64_t>(lua_tonumber(rawState, 2)));

  Sim* const sim = lua_getglobaluserdata(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  if (!map) {
    return 0;
  }

  LuaPlus::LuaObject terrainType = map->GetTerrainType(x, z);
  terrainType.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075CC40 (FUN_0075CC40, func_GetUnitBlueprintByName_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetUnitBlueprintByName(bpName)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_GetUnitBlueprintByName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetUnitBlueprintByName",
    &moho::cfunc_GetUnitBlueprintByName,
    nullptr,
    "<global>",
    kGetUnitBlueprintByNameLuaDefHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075CC20 (FUN_0075CC20, cfunc_GetUnitBlueprintByName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUnitBlueprintByNameL`.
 */
int moho::cfunc_GetUnitBlueprintByName(lua_State* const luaContext)
{
  return cfunc_GetUnitBlueprintByNameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075CCA0 (FUN_0075CCA0, cfunc_GetUnitBlueprintByNameL)
 *
 * What it does:
 * Reads one unit blueprint id string, resolves it via `Sim::mRules`, and
 * returns the blueprint Lua object (or `nil` when unresolved).
 */
int moho::cfunc_GetUnitBlueprintByNameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetUnitBlueprintByNameHelpText);

  LuaPlus::LuaStackObject blueprintArg{};
  blueprintArg.m_state = state;
  blueprintArg.m_stackIndex = 1;
  const char* const blueprintName = lua_tostring(rawState, 1);
  if (blueprintName == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
  }

  Sim* const sim = lua_getglobaluserdata(rawState);
  RRuleGameRules* const rules = sim ? sim->mRules : nullptr;
  const RUnitBlueprint* blueprint = nullptr;
  if (rules != nullptr) {
    RResId resourceId{};
    gpg::STR_InitFilename(&resourceId.name, blueprintName);
    blueprint = rules->GetUnitBlueprint(resourceId);
  }

  if (blueprint != nullptr) {
    LuaPlus::LuaObject luaBlueprint = blueprint->GetLuaBlueprint(state);
    luaBlueprint.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }
  return 1;
}
namespace
{
  /**
   * The shared body of section/SimGetDepositsAroundPoint.cpp: reads `(x, z,
   * radius, type)` and returns an array of `{ X1, Z1, X2, Z2, Type, Dist }`
   * (the key spelling of the string block at 0x012938C3) from `resources`.
   */
  int PushDepositsAroundPoint(lua_State* const luaContext, moho::CSimResources* const resources)
  {
    const float x = static_cast<float>(lua_tonumber(luaContext, 1));
    const float z = static_cast<float>(lua_tonumber(luaContext, 2));
    const float radius = static_cast<float>(lua_tonumber(luaContext, 3));
    const float nanGuard = x + z + radius;
    if (nanGuard != nanGuard) {
      return 0;
    }

    const auto type = static_cast<moho::EDepositType>(static_cast<int>(lua_tonumber(luaContext, 4)));

    lua_newtable(luaContext);
    if (!resources) {
      return 1;
    }

    gpg::fastvector<moho::ResourceDepositDistance> nearbyDeposits{};
    resources->GetDepositsAroundPoint(x, z, radius, type, &nearbyDeposits);

    for (std::size_t i = 0; i < nearbyDeposits.size(); ++i) {
      const moho::ResourceDepositDistance& hit = nearbyDeposits[i];
      const moho::ResourceDeposit& deposit = hit.deposit;

      lua_pushnumber(luaContext, static_cast<lua_Number>(i + 1u));
      lua_newtable(luaContext);
      LuaPushNumberField(luaContext, "X1", deposit.footprintRect.x0);
      LuaPushNumberField(luaContext, "Z1", deposit.footprintRect.z0);
      LuaPushNumberField(luaContext, "X2", deposit.footprintRect.x1);
      LuaPushNumberField(luaContext, "Z2", deposit.footprintRect.z1);
      LuaPushNumberField(luaContext, "Type", static_cast<int>(deposit.depositType));
      LuaPushNumberField(luaContext, "Dist", hit.centerDistance);
      lua_settable(luaContext, -3);
    }

    return 1;
  }
}



/**
 * Address: 0x0128B884 (FUN_0128B884, cfunc_GetDepositsAroundPoint)
 *
 * What it does:
 * Reads `(x, z, radius, type)` from Lua and returns an array of deposits:
 * `{ X1, Z1, X2, Z2, Type, Dist }`, from the sim's resources.
 */
int moho::cfunc_GetDepositsAroundPoint(lua_State* const luaContext)
{
  if (!luaContext) {
    return 0;
  }

  Sim* const sim = ResolveGlobalSim(luaContext);
  return PushDepositsAroundPoint(luaContext, sim ? sim->mSimResources.px : nullptr);
}

/**
 * Address: 0x0128B884 (FUN_0128B884; the same body registered in the user set)
 *
 * What it does:
 * The user-state `GetDepositsAroundPoint`. The patch reads the process's sim
 * (`g_Sim`, 0x010A63F0) from the user state too; this reads the same deposit
 * list through the active session's resources, which the UI already uses for
 * extractor snapping, so the user state never touches the sim.
 */
int moho::cfunc_GetDepositsAroundPointUser(lua_State* const luaContext)
{
  if (!luaContext) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  return PushDepositsAroundPoint(luaContext, session ? session->mSimResources.px : nullptr);
}

/**
 * Address: 0x0128B0BF (FUN_0128B0BF, cfunc_GetTimeForProfileSim)
 *
 * What it does:
 * Reads start time from Lua arg #1 and pushes elapsed time in seconds from
 * `QueryPerformanceCounter`.
 */
int moho::cfunc_GetTimeForProfileSim(lua_State* const luaContext)
{
  LARGE_INTEGER performanceCount{};
  LARGE_INTEGER frequency{};
  ::QueryPerformanceCounter(&performanceCount);
  ::QueryPerformanceFrequency(&frequency);

  const float startSeconds = static_cast<float>(lua_tonumber(luaContext, 1));
  const float frequencyValue = static_cast<float>(frequency.QuadPart);
  const float counterValue = static_cast<float>(performanceCount.QuadPart);
  const float elapsedSeconds = (counterValue - (startSeconds * frequencyValue)) / frequencyValue;
  lua_pushnumber(luaContext, elapsedSeconds);
  return 1;
}

/**
 * Address: 0x00842BB0 (FUN_00842BB0, cfunc_GetMouseWorldPos)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetMouseWorldPosL`.
 */
int moho::cfunc_GetMouseWorldPos(lua_State* const luaContext)
{
  return cfunc_GetMouseWorldPosL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * What it does:
 * Publishes the sim-lane Lua binder definition for global `GetMouseWorldPos`:
 * FA-Binary-Patches section/SimGetMouseWorldPos.cpp registers the stock user
 * body (0x00842BB0) in the sim set too (.exxt block 0x0129287D..0x012928A5). It
 * reads the local session's cursor, so it is not deterministic in the sim, as in
 * the FAF exe.
 */
moho::CScrLuaInitForm* moho::func_GetMouseWorldPosSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetMouseWorldPos",
    &moho::cfunc_GetMouseWorldPos,
    nullptr,
    "<global>",
    kGetMouseWorldPosHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842C30 (FUN_00842C30, cfunc_GetMouseWorldPosL)
 *
 * What it does:
 * Pushes current world-space mouse position as one Lua vector.
 */
int moho::cfunc_GetMouseWorldPosL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kGetMouseWorldPosArgsWarning, kGetMouseWorldPosHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kGetMouseWorldPosNoSessionText);
  }

  const LuaPlus::LuaObject worldPositionObject = SCR_ToLua<Wm3::Vector3<float>>(state, session->CursorWorldPos);
  worldPositionObject.PushStack(state);
  return 1;
}

/**
 * What it does:
 * Publishes the sim-lane Lua binder definition for global
 * `GetTimeForProfile` (`.exxt` def chain node 0x0128EA70, function slot
 * 0x0128B0BF).
 */
moho::CScrLuaInitForm* moho::func_GetTimeForProfileSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetTimeForProfile",
    &moho::cfunc_GetTimeForProfileSim,
    nullptr,
    "<global>",
    kGetTimeForProfileSimHelpText
  );
  return &binder;
}

/**
 * What it does:
 * Publishes the sim-lane Lua binder definition for global
 * `GetDepositsAroundPoint` (`.exxt` def chain node 0x0128EA8C, function
 * slot 0x0128B884).
 */
moho::CScrLuaInitForm* moho::func_GetDepositsAroundPoint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetDepositsAroundPoint",
    &moho::cfunc_GetDepositsAroundPoint,
    nullptr,
    "<global>",
    kGetDepositsAroundPointHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708310 (FUN_00708310, cfunc_GetArmyBrain)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetArmyBrainL`.
 */
int moho::cfunc_GetArmyBrain(lua_State* const luaContext)
{
  return cfunc_GetArmyBrainL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708330 (FUN_00708330, func_GetArmyBrain_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmyBrain`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyBrain_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetArmyBrain",
    &moho::cfunc_GetArmyBrain,
    nullptr,
    "<global>",
    kGetArmyBrainHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708390 (FUN_00708390, cfunc_GetArmyBrainL)
 *
 * What it does:
 * Resolves one army selector and pushes that army brain Lua object.
 */
int moho::cfunc_GetArmyBrainL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kGetArmyBrainHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CAiBrain* const brain = army->GetArmyBrain();
  // 0x00708409..0x0070841F: the binary builds and discards an empty table
  // here, which the Lua allocator and collector both see.
  LuaPlus::LuaObject scratch(state);
  scratch.AssignNewTable(state, 0, 0u);
  brain->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007099C0 (FUN_007099C0, cfunc_IsAllySim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_IsAllySimL`.
 */
int moho::cfunc_IsAllySim(lua_State* const luaContext)
{
  return cfunc_IsAllySimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007099E0 (FUN_007099E0, func_IsAllySim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsAlly`.
 */
moho::CScrLuaInitForm* moho::func_IsAllySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsAlly",
    &moho::cfunc_IsAllySim,
    nullptr,
    "<global>",
    kIsAllySimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709A40 (FUN_00709A40, cfunc_IsAllySimL)
 *
 * What it does:
 * Reads `(army1, army2)` and returns whether army1 treats army2 as allied.
 */
int moho::cfunc_IsAllySimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kIsAllySimHelpText);

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  const bool isAlly = firstArmy != nullptr && secondArmy != nullptr &&
    firstArmy->mVarDat.mAllies.Contains(static_cast<std::uint32_t>(secondArmy->mConstDat.mArmyIndex));
  lua_pushboolean(rawState, isAlly ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00709AF0 (FUN_00709AF0, cfunc_IsEnemySim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_IsEnemySimL`.
 */
int moho::cfunc_IsEnemySim(lua_State* const luaContext)
{
  return cfunc_IsEnemySimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709B10 (FUN_00709B10, func_IsEnemySim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsEnemy`.
 */
moho::CScrLuaInitForm* moho::func_IsEnemySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsEnemy",
    &moho::cfunc_IsEnemySim,
    nullptr,
    "<global>",
    kIsEnemySimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709B70 (FUN_00709B70, cfunc_IsEnemySimL)
 *
 * What it does:
 * Reads `(army1, army2)` and returns whether army1 treats army2 as enemy.
 */
int moho::cfunc_IsEnemySimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kIsEnemySimHelpText);

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  const bool isEnemy = firstArmy != nullptr && secondArmy != nullptr &&
    firstArmy->mVarDat.mEnemies.Contains(static_cast<std::uint32_t>(secondArmy->mConstDat.mArmyIndex));
  lua_pushboolean(rawState, isEnemy ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00709C20 (FUN_00709C20, cfunc_IsNeutralSim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_IsNeutralSimL`.
 */
int moho::cfunc_IsNeutralSim(lua_State* const luaContext)
{
  return cfunc_IsNeutralSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709C40 (FUN_00709C40, func_IsNeutralSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsNeutral`.
 */
moho::CScrLuaInitForm* moho::func_IsNeutralSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsNeutral",
    &moho::cfunc_IsNeutralSim,
    nullptr,
    "<global>",
    kIsNeutralSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709CA0 (FUN_00709CA0, cfunc_IsNeutralSimL)
 *
 * What it does:
 * Reads `(army1, army2)` and returns whether army1 treats army2 as neutral.
 */
int moho::cfunc_IsNeutralSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kIsNeutralSimHelpText);

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  const bool isNeutral = firstArmy != nullptr && secondArmy != nullptr
    && IsArmyMarkedNeutral(static_cast<std::uint32_t>(secondArmy->mConstDat.mArmyIndex), firstArmy->mVarDat.mNeutrals);
  lua_pushboolean(rawState, isNeutral ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00708D60 (FUN_00708D60, cfunc_GetArmyUnitCostTotal)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetArmyUnitCostTotalL`.
 */
int moho::cfunc_GetArmyUnitCostTotal(lua_State* const luaContext)
{
  return cfunc_GetArmyUnitCostTotalL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708D80 (FUN_00708D80, func_GetArmyUnitCostTotal_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmyUnitCostTotal`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyUnitCostTotal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetArmyUnitCostTotal",
    &moho::cfunc_GetArmyUnitCostTotal,
    nullptr,
    "<global>",
    kGetArmyUnitCostTotalHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708DE0 (FUN_00708DE0, cfunc_GetArmyUnitCostTotalL)
 *
 * What it does:
 * Resolves one army selector and returns the army total unit cost as a Lua
 * number.
 */
int moho::cfunc_GetArmyUnitCostTotalL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kGetArmyUnitCostTotalHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  lua_pushnumber(state->m_state, army ? army->GetArmyUnitCostTotal() : 0.0f);
  return 1;
}

/**
 * Address: 0x00708E60 (FUN_00708E60, cfunc_GetArmyUnitCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetArmyUnitCapL`.
 */
int moho::cfunc_GetArmyUnitCap(lua_State* const luaContext)
{
  return cfunc_GetArmyUnitCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708E80 (FUN_00708E80, func_GetArmyUnitCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmyUnitCap`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyUnitCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetArmyUnitCap",
    &moho::cfunc_GetArmyUnitCap,
    nullptr,
    "<global>",
    kGetArmyUnitCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708EE0 (FUN_00708EE0, cfunc_GetArmyUnitCapL)
 *
 * What it does:
 * Resolves one army selector and returns that army's unit-cap value as a Lua
 * number.
 */
int moho::cfunc_GetArmyUnitCapL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kGetArmyUnitCapHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  lua_pushnumber(state->m_state, army->GetUnitCap());
  return 1;
}

/**
 * Address: 0x0074B920 (FUN_0074B920, func_IsGameOver_LuaFuncDef)
 *
 * What it does:
 * Creates/returns the global Lua binder form for `IsGameOver`.
 */
moho::CScrLuaInitForm* moho::func_IsGameOver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "IsGameOver",
    &moho::cfunc_IsGameOver,
    nullptr,
    "<global>",
    "Return true if the game is over (i.e. EndGame() has been called)."
  );
  return &binder;
}

/**
 * Address: 0x0074B9F0 (FUN_0074B9F0, cfunc_GetEntityById)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetEntityByIdL`.
 */
int moho::cfunc_GetEntityById(lua_State* const luaContext)
{
  return cfunc_GetEntityByIdL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0074BA10 (FUN_0074BA10, func_GetEntityById_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetEntityById`.
 */
moho::CScrLuaInitForm* moho::func_GetEntityById_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetEntityById",
    &moho::cfunc_GetEntityById,
    nullptr,
    "<global>",
    kGetEntityByIdHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074BA70 (FUN_0074BA70, cfunc_GetEntityByIdL)
 *
 * What it does:
 * Resolves one string entity-id argument and returns matching entity Lua
 * object (or nil).
 */
int moho::cfunc_GetEntityByIdL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetEntityByIdHelpText);

  Sim* const sim = lua_getglobaluserdata(rawState);
  const LuaPlus::LuaStackObject entityIdArg(state, 1);
  const char* entityIdText = lua_tostring(rawState, 1);
  if (entityIdText == nullptr) {
    entityIdArg.TypeError("string");
    entityIdText = "";
  }

  const EntId entityId = static_cast<EntId>(std::atoi(entityIdText));
  Entity* const entity = FindEntityById(sim ? sim->mEntityDB : nullptr, entityId);
  if (entity == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  entity->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0074BB40 (FUN_0074BB40, cfunc_GetUnitByIdSim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUnitByIdSimL`.
 */
int moho::cfunc_GetUnitByIdSim(lua_State* const luaContext)
{
  return cfunc_GetUnitByIdSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0074BB60 (FUN_0074BB60, func_GetUnitByIdSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetUnitById`.
 */
moho::CScrLuaInitForm* moho::func_GetUnitByIdSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetUnitById",
    &moho::cfunc_GetUnitByIdSim,
    nullptr,
    "<global>",
    kGetUnitByIdSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x0074BBC0 (FUN_0074BBC0, cfunc_GetUnitByIdSimL)
 *
 * What it does:
 * Resolves one string entity-id argument and returns the matching unit Lua
 * object when that id is a unit (or nil).
 */
int moho::cfunc_GetUnitByIdSimL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetUnitByIdSimHelpText);

  Sim* const sim = lua_getglobaluserdata(rawState);
  const LuaPlus::LuaStackObject entityIdArg(state, 1);
  const char* entityIdText = lua_tostring(rawState, 1);
  if (entityIdText == nullptr) {
    entityIdArg.TypeError("string");
    entityIdText = "";
  }

  const EntId entityId = static_cast<EntId>(std::atoi(entityIdText));
  Entity* const entity = FindEntityById(sim ? sim->mEntityDB : nullptr, entityId);
  Unit* const unit = entity ? entity->IsUnit() : nullptr;
  if (unit == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  unit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0075CDD0 (FUN_0075CDD0, cfunc_GetFocusArmySim)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetFocusArmySimL`.
 */
int moho::cfunc_GetFocusArmySim(lua_State* const luaContext)
{
  return cfunc_GetFocusArmySimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075CDF0 (FUN_0075CDF0, func_GetFocusArmySim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GetFocusArmy()` Lua binder for sim state.
 */
moho::CScrLuaInitForm* moho::func_GetFocusArmySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "GetFocusArmy",
    &moho::cfunc_GetFocusArmySim,
    nullptr,
    "<global>",
    kGetFocusArmySimHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075CE50 (FUN_0075CE50, cfunc_GetFocusArmySimL)
 *
 * What it does:
 * Validates no Lua args and returns current focused army index (1-based, or
 * `-1` when unset).
 */
int moho::cfunc_GetFocusArmySimL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetFocusArmySimHelpText);

  Sim* const sim = ResolveGlobalSim(state->m_state);
  int focusArmy = sim->mSyncFilter.focusArmy;
#if FAF_SERVER_MODE
  if (sSyncRouting != nullptr) {
    focusArmy = sSyncRouting->FocusForLua();
  }
#endif
  if (focusArmy != -1) {
    ++focusArmy;
  }

  lua_pushnumber(state->m_state, static_cast<float>(focusArmy));
  (void)lua_gettop(state->m_state);
  return 1;
}


/**
 * Address: 0x0075CF90 (FUN_0075CF90, cfunc_HasLocalizedVOSim)
 *
 * What it does:
 * Validates `HasLocalizedVO(language)` argument count on the sim Lua lane.
 */
int moho::cfunc_HasLocalizedVOSim(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  moho::SCR_ExpectExactArgs(state, 1, kHasLocalizedVOSimHelpText);
  return 0;
}

/**
 * Address: 0x0075CFD0 (FUN_0075CFD0, func_HasLocalizedVOSim_LuaFuncDef)
 *
 * What it does:
 * Publishes global `HasLocalizedVO(language)` Lua binder in the sim init set.
 */
moho::CScrLuaInitForm* moho::func_HasLocalizedVOSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "HasLocalizedVO",
    &moho::cfunc_HasLocalizedVOSim,
    nullptr,
    "<global>",
    kHasLocalizedVOSimHelpText
  );
  return &binder;
}
