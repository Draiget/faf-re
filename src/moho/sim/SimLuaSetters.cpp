#include "moho/sim/SimLuaPrivate.h"

namespace
{
  constexpr const char* kSetFocusArmySimHelpText = "SetFocusArmy(armyIndex or -1)";
  constexpr const char* kSetCommandSourceSimHelpText = "(targetArmyIndex, sourceHumanIndex, Set or Unset)";
  constexpr const char* kSetArmyStartHelpText = "army, x, z";
  constexpr const char* kSetIgnoreArmyUnitCapHelpText = "army, flag";
  constexpr const char* kSetIgnorePlayableRectHelpText = "army, flag";
  constexpr const char* kSetArmyFactionIndexHelpText = "SetArmyFactionIndex(army,index)";
  constexpr const char* kSetArmyOutOfGameHelpText =
    "SetArmyOutOfGame(army) -- indicate that the supplied army has been defeated.";
  constexpr const char* kSetArmyEconomyHelpText = "army, mass, energy";
  constexpr const char* kSetArmyUnitCapHelpText = "army, unitCap";
  constexpr const char* kSetArmyAIPersonalityHelpText = "SetArmyAIPersonality(army,personality)";
  constexpr const char* kSetArmyShowScoreHelpText =
    "SetArmyColor(army, bool) - determines if the user should be able to see the army score";
  constexpr const char* kSetArmyStatsSyncArmyHelpText = "Set the army index for which to sync army stats (-1 for none)";
  constexpr const char* kSetArmyPlansHelpText = "army, plans";
  constexpr const char* kSetArmyColorHelpText = "SetArmyColor(army,r,g,b)";
  constexpr const char* kSetAlliedVictoryHelpText = "SetAlliedVictory(army,bool)";
  constexpr const char* kSetAllianceHelpText = "SetAlliance(army1,army2,<Neutral|Enemy|Ally>";
  constexpr const char* kSetAllianceOneWayHelpText = "SetAllianceOneWay(army1,army2,<Neutral|Enemy|Ally>";
  constexpr const char* kSetTerrainTypeLuaDefHelpText = "SetTerrainType(x,z,type)";
  constexpr const char* kSetTerrainTypeRectLuaDefHelpText = "SetTerrainType(rect,type)";
  constexpr const char* kSetTerrainTypeHelpText = "SetTerrainType( x, z, terrainTypeTable )";
  constexpr const char* kSetTerrainTypeRectHelpText = "SetTerrainTypeRect( rect, terrainTypeTable )";
  constexpr const char* kSetPlayableRectHelpText = "SetPlayableRect( minX, minZ, maxX, maxZ )";

  [[nodiscard]] gpg::RRef MakeEAllianceRef(moho::EAlliance* const allianceType)
  {
    gpg::RRef enumRef{};
    if (allianceType == nullptr) {
      return enumRef;
    }

    static gpg::RType* sEAllianceType = nullptr;
    if (sEAllianceType == nullptr) {
      sEAllianceType = gpg::LookupRType(typeid(moho::EAlliance));
    }

    enumRef.mObj = allianceType;
    enumRef.mType = sEAllianceType;
    return enumRef;
  }

  void SetArmyValidCommandSourceBit(
    CArmyImpl& army,
    const std::int32_t sourceIndex,
    const bool enabled
  ) noexcept
  {
    // `Moho::Set` already implements both halves of this, and the reader side
    // -- `BVIntSet::Contains` (0x004035F0) and `Set::Contains`, which is what
    // `Sim::OkayToMessWith` calls on this very set -- addresses a word as
    // `(value >> 5) - baseWordIndex`. The open-coded copy that stood here
    // computed `value >> (5 - baseWordIndex)` instead: a variable shift, right
    // only for `baseWordIndex == 0`, off by whole words for any other base, and
    // undefined once the base reaches 6. A source bit written into one word and
    // read back from another leaves `OkayToMessWith` answering false, and every
    // command arriving from that source is then dropped before it reaches a
    // unit. `Set::Add`/`Set::Remove` also keep the used-word window and the
    // empty-set case right, which the copy did not.
    BVIntSet& validSources = army.mVarDat.mValidCommandSources;

    const std::uint32_t source = static_cast<std::uint32_t>(sourceIndex);
    if (enabled) {
      (void)validSources.Add(source);
    } else {
      (void)validSources.Remove(source);
    }
  }

  template <int StackIndex>
  [[nodiscard]] std::uint8_t ReadLuaColorByteArg(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaStackObject arg(state, StackIndex);
    if (lua_type(state->m_state, StackIndex) != LUA_TNUMBER) {
      arg.TypeError("integer");
    }

    const auto value = static_cast<std::int32_t>(lua_tonumber(state->m_state, StackIndex));
    return static_cast<std::uint8_t>(value & 0xFF);
  }
}


/**
 * Address: 0x0075C3D0 (FUN_0075C3D0, func_SetTerrainType_LuaFuncDef)
 *
 * What it does:
 * Publishes global `SetTerrainType(x,z,type)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetTerrainType_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetTerrainType",
    &moho::cfunc_SetTerrainType,
    nullptr,
    "<global>",
    kSetTerrainTypeLuaDefHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075C3B0 (FUN_0075C3B0, cfunc_SetTerrainType)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetTerrainTypeL`.
 */
int moho::cfunc_SetTerrainType(lua_State* const luaContext)
{
  return cfunc_SetTerrainTypeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C430 (FUN_0075C430, cfunc_SetTerrainTypeL)
 *
 * What it does:
 * Reads `(x, z, terrainTypeTable)` from Lua and applies the table `TypeCode`
 * entry through `STIMap::SetTerrainType`.
 */
int moho::cfunc_SetTerrainTypeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kSetTerrainTypeHelpText);

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  if (!map) {
    return 0;
  }

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

  lua_pushstring(rawState, "TypeCode");
  lua_gettable(rawState, 3);

  const int typeCodeIndex = lua_gettop(rawState);
  LuaPlus::LuaStackObject typeCodeArg{};
  typeCodeArg.m_state = state;
  typeCodeArg.m_stackIndex = typeCodeIndex;
  if (lua_type(rawState, typeCodeIndex) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&typeCodeArg, "integer");
  }
  const std::uint8_t terrainType = static_cast<std::uint8_t>(static_cast<std::int32_t>(lua_tonumber(rawState, typeCodeIndex)));

  map->SetTerrainType(x, z, terrainType);
  return 0;
}

/**
 * Address: 0x0075F2D0 (FUN_0075F2D0, func_SetTerrainTypeRect)
 *
 * What it does:
 * Writes one terrain-type rectangle into `grid` after clamping
 * `(x, z, x + width, z + height)` against map bounds, preserving the original
 * nested row/column fill order.
 */
static std::int32_t FillTerrainTypeRectClamped(
  const std::int32_t x,
  const std::int32_t z,
  const std::uint8_t terrainType,
  moho::TerrainTypeGrid* const grid,
  const std::int32_t width,
  const std::int32_t height
) noexcept
{
  std::int32_t endX = x + width;
  std::int32_t endZ = z + height;

  std::int32_t startX = x;
  if (startX < 0) {
    startX = 0;
  }

  std::int32_t startZ = z;
  if (startZ < 0) {
    startZ = 0;
  }

  if (endX >= grid->width) {
    endX = grid->width;
  }
  if (endZ >= grid->height) {
    endZ = grid->height;
  }

  std::int32_t result = startX;
  if (endX > startX && startZ < endZ) {
    do {
      if (result < endX) {
        do {
          ++result;
          grid->data[static_cast<std::size_t>(startZ) * static_cast<std::size_t>(grid->width) + static_cast<std::size_t>(result - 1)] =
            terrainType;
        } while (result < endX);
        result = startX;
      }
      ++startZ;
    } while (startZ < endZ);
  }

  return result;
}

/**
 * Address: 0x0075C5F0 (FUN_0075C5F0, func_SetTerrainTypeRect_LuaFuncDef)
 *
 * What it does:
 * Publishes global `SetTerrainTypeRect(rect,type)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetTerrainTypeRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetTerrainTypeRect",
    &moho::cfunc_SetTerrainTypeRect,
    nullptr,
    "<global>",
    kSetTerrainTypeRectLuaDefHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075C5D0 (FUN_0075C5D0, cfunc_SetTerrainTypeRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetTerrainTypeRectL`.
 */
int moho::cfunc_SetTerrainTypeRect(lua_State* const luaContext)
{
  return cfunc_SetTerrainTypeRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075C650 (FUN_0075C650, cfunc_SetTerrainTypeRectL)
 *
 * What it does:
 * Reads `(rectTable, terrainTypeTable)` from Lua and writes one clamped
 * terrain-type rectangle into `STIMap::mTerrainType`.
 */
int moho::cfunc_SetTerrainTypeRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kSetTerrainTypeRectHelpText);

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  if (!map) {
    return 0;
  }

  // 0x0075C6DA: arg#1 converts through SCR_FromLuaCopy<gpg::Rect2<int>>
  // (0x004D0B60).
  const LuaPlus::LuaObject rectObject(LuaPlus::LuaStackObject(state, 1));
  const gpg::Rect2i rect = SCR_FromLuaCopy<gpg::Rect2<int>>(rectObject);

  lua_pushstring(rawState, "TypeCode");
  lua_gettable(rawState, 2);

  const int typeCodeIndex = lua_gettop(rawState);
  LuaPlus::LuaStackObject typeCodeArg{};
  typeCodeArg.m_state = state;
  typeCodeArg.m_stackIndex = typeCodeIndex;
  if (lua_type(rawState, typeCodeIndex) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&typeCodeArg, "integer");
  }
  const std::uint8_t terrainType = static_cast<std::uint8_t>(static_cast<std::int32_t>(lua_tonumber(rawState, typeCodeIndex)));

  TerrainTypeGrid* const terrainTypeGrid = &map->mTerrainType;
  (void)FillTerrainTypeRectClamped(
    rect.x0,
    rect.z0,
    terrainType,
    terrainTypeGrid,
    rect.x1 - rect.x0,
    rect.z1 - rect.z0
  );

  return 0;
}

/**
 * Address: 0x0075C830 (FUN_0075C830, cfunc_SetPlayableRectL)
 *
 * What it does:
 * Reads `(minX, minZ, maxX, maxZ)` from Lua, validates integer lanes,
 * and writes the playable map rectangle through `STIMap::SetPlayableMapRect`.
 */
int moho::cfunc_SetPlayableRectL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 4, kSetPlayableRectHelpText);

  LuaPlus::LuaStackObject maxZArg{};
  maxZArg.m_state = state;
  maxZArg.m_stackIndex = 4;
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&maxZArg, "integer");
  }
  const std::int32_t maxZ = static_cast<std::int32_t>(lua_tonumber(rawState, 4));

  LuaPlus::LuaStackObject maxXArg{};
  maxXArg.m_state = state;
  maxXArg.m_stackIndex = 3;
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&maxXArg, "integer");
  }
  const std::int32_t maxX = static_cast<std::int32_t>(lua_tonumber(rawState, 3));

  LuaPlus::LuaStackObject minZArg{};
  minZArg.m_state = state;
  minZArg.m_stackIndex = 2;
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&minZArg, "integer");
  }
  const std::int32_t minZ = static_cast<std::int32_t>(lua_tonumber(rawState, 2));

  LuaPlus::LuaStackObject minXArg{};
  minXArg.m_state = state;
  minXArg.m_stackIndex = 1;
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&minXArg, "integer");
  }
  const std::int32_t minX = static_cast<std::int32_t>(lua_tonumber(rawState, 1));

  Sim* const sim = ResolveGlobalSim(rawState);
  STIMap* const map = sim ? sim->mMapData : nullptr;
  if (!map) {
    return 0;
  }

  gpg::Rect2i playableRect{};
  playableRect.x0 = minX;
  playableRect.z0 = minZ;
  playableRect.x1 = maxX;
  playableRect.z1 = maxZ;
  if (!map->SetPlayableMapRect(playableRect)) {
    LuaPlus::LuaState::Error(state, "Attempted to set an invalid playable rect.");
  }

  return 0;
}

/**
 * Address: 0x0075C7B0 (FUN_0075C7B0, cfunc_SetPlayableRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetPlayableRectL`.
 */
int moho::cfunc_SetPlayableRect(lua_State* const luaContext)
{
  return cfunc_SetPlayableRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075D970 (FUN_0075D970, cfunc_SetArmyStatsSyncArmy)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SetArmyStatsSyncArmyL`.
 */
int moho::cfunc_SetArmyStatsSyncArmy(lua_State* const luaContext)
{
  return cfunc_SetArmyStatsSyncArmyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0075D990 (FUN_0075D990, func_SetArmyStatsSyncArmy_LuaFuncDef)
 *
 * What it does:
 * Publishes global `SetArmyStatsSyncArmy(army)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_SetArmyStatsSyncArmy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyStatsSyncArmy",
    &moho::cfunc_SetArmyStatsSyncArmy,
    nullptr,
    "<global>",
    kSetArmyStatsSyncArmyHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075D9F0 (FUN_0075D9F0, cfunc_SetArmyStatsSyncArmyL)
 *
 * What it does:
 * Reads one integer and stores it in `Sim::mSyncArmy`.
 */
int moho::cfunc_SetArmyStatsSyncArmyL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kSetArmyStatsSyncArmyHelpText);

  LuaPlus::LuaStackObject armyArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    armyArg.TypeError("integer");
  }

  Sim* const sim = ResolveGlobalSim(rawState);
  if (sim) {
    sim->mSyncArmy = static_cast<std::int32_t>(lua_tonumber(rawState, 1));
  }
  return 0;
}

/**
 * What it does:
 * Publishes the sim-lane Lua binder definition for global `SetFocusArmy`.
 * The shipped build binds this through the `.exxt` patch def chain (node
 * 0x0128EA38, function slot 0x0128BBFC) rather than a `func_*_LuaFuncDef`
 * factory, so only the bound worker has an address.
 */
moho::CScrLuaInitForm* moho::func_SetFocusArmySim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetFocusArmy",
    &moho::cfunc_SetFocusArmySim,
    nullptr,
    "<global>",
    kSetFocusArmySimHelpText
  );
  return &binder;
}

/**
 * What it does:
 * Publishes the sim-lane Lua binder definition for global
 * `SetCommandSource` (`.exxt` def chain node 0x0128EAA8, function slot
 * 0x0128BB51). `/lua/sim/victorycondition/abstractvictorycondition.lua`
 * calls it from `ToObserver` while processing a defeated army; leaving it
 * unregistered aborted that pass, so the victory flow never removed the
 * defeated players' command sources and the session never concluded.
 */
moho::CScrLuaInitForm* moho::func_SetCommandSourceSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetCommandSource",
    &moho::cfunc_SetCommandSourceSim,
    nullptr,
    "<global>",
    kSetCommandSourceSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x0128BBFC (FUN_0128BBFC, cfunc_SetFocusArmySim)
 *
 * What it does:
 * Reads focus-army index from Lua arg #1 and writes the pending driver focus lane.
 */
int moho::cfunc_SetFocusArmySim(lua_State* const luaContext)
{
  if (!luaContext) {
    return 0;
  }

  const int focusArmy = static_cast<int>(lua_tonumber(luaContext, 1));

#if FAF_SERVER_MODE
  if (sSyncRouting != nullptr) {
    sSyncRouting->SetFocusFromLua(focusArmy);
    return 0;
  }
#endif
  if (ISTIDriver* activeDriver = WLD_GetDriver()) {
#if FAF_SERVER_MODE
    // Engine addition, server mode: under /loopback the session's driver stands in for a
    // server; the focus belongs to the lockstep driver it wraps.
    activeDriver = faf::remote::client::LockstepDriverOf(activeDriver);
#endif
    if (auto* const simDriver = dynamic_cast<CSimDriver*>(activeDriver)) {
      simDriver->SetPendingFocusArmyRaw(focusArmy);
    } else {
      activeDriver->SetArmyIndex(focusArmy);
    }
  }

  return 0;
}

/**
 * Address: 0x0128BB51 (FUN_0128BB51, cfunc_SetCommandSourceSim)
 *
 * What it does:
 * Reads `(armyIndex, sourceIndex, enabled)` from Lua args and toggles the
 * corresponding bit in `CArmyImpl::MohoSetValidCommandSources`.
 */
int moho::cfunc_SetCommandSourceSim(lua_State* const luaContext)
{
  if (!luaContext) {
    return 0;
  }

  const std::int32_t armyIndex = static_cast<std::int32_t>(lua_tonumber(luaContext, 1));
  const std::int32_t sourceIndex = static_cast<std::int32_t>(lua_tonumber(luaContext, 2));
  const bool enabled = lua_toboolean(luaContext, 3) != 0;

  Sim* const sim = ResolveGlobalSim(luaContext);
  if (!sim || armyIndex < 0 || static_cast<std::size_t>(armyIndex) >= sim->mArmiesList.size()) {
    return 0;
  }

  CArmyImpl* const army = sim->mArmiesList[static_cast<std::size_t>(armyIndex)];
  if (!army || !army->mVarDat.mValidCommandSources.mWords.start_) {
    return 0;
  }

  // Engine addition: command sources travel as one byte, 0xFF meaning none
  // (`CMDST_SetCommandSource`), so no real source is outside [0, 0xFF). The
  // bit set grows to the index it is given: an index of 2^31 from script
  // allocated 256 MB in every sim.
  if (sourceIndex < 0 || sourceIndex >= 0xFF) {
    return 0;
  }

  SetArmyValidCommandSourceBit(*army, sourceIndex, enabled);
  return 0;
}

/**
 * Address: 0x00708460 (FUN_00708460, cfunc_SetArmyStart)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyStartL`.
 */
int moho::cfunc_SetArmyStart(lua_State* const luaContext)
{
  return cfunc_SetArmyStartL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708480 (FUN_00708480, func_SetArmyStart_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyStart`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyStart_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyStart",
    &moho::cfunc_SetArmyStart,
    nullptr,
    "<global>",
    kSetArmyStartHelpText
  );
  return &binder;
}

/**
 * Address: 0x007084E0 (FUN_007084E0, cfunc_SetArmyStartL)
 *
 * What it does:
 * Reads `(army, x, z)` from Lua and forwards one start-position vector to
 * `CArmyImpl::SetArmyStart`.
 */
int moho::cfunc_SetArmyStartL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 3, kSetArmyStartHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  LuaPlus::LuaStackObject xArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    xArg.TypeError("number");
  }

  LuaPlus::LuaStackObject zArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    zArg.TypeError("number");
  }

  Wm3::Vector2f startPosition{};
  startPosition.x = static_cast<float>(lua_tonumber(state->m_state, 2));
  startPosition.y = static_cast<float>(lua_tonumber(state->m_state, 3));
  army->SetArmyStart(startPosition);
  return 0;
}

/**
 * Address: 0x007090A0 (FUN_007090A0, cfunc_SetIgnoreArmyUnitCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_SetIgnoreArmyUnitCapL`.
 */
int moho::cfunc_SetIgnoreArmyUnitCap(lua_State* const luaContext)
{
  return cfunc_SetIgnoreArmyUnitCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007090C0 (FUN_007090C0, func_SetIgnoreArmyUnitCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetIgnoreArmyUnitCap`.
 */
moho::CScrLuaInitForm* moho::func_SetIgnoreArmyUnitCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetIgnoreArmyUnitCap",
    &moho::cfunc_SetIgnoreArmyUnitCap,
    nullptr,
    "<global>",
    kSetIgnoreArmyUnitCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709120 (FUN_00709120, cfunc_SetIgnoreArmyUnitCapL)
 *
 * What it does:
 * Reads `(army, flag)` from Lua and updates unit-cap ignore mode through the
 * army interface.
 */
int moho::cfunc_SetIgnoreArmyUnitCapL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kSetIgnoreArmyUnitCapHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  LuaPlus::LuaStackObject flagArg(state, 2);
  const bool useUnitCap = flagArg.GetBoolean();
  army->SetUseUnitCap(useUnitCap);
  return 0;
}

/**
 * Address: 0x007091B0 (FUN_007091B0, cfunc_SetIgnorePlayableRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_SetIgnorePlayableRectL`.
 */
int moho::cfunc_SetIgnorePlayableRect(lua_State* const luaContext)
{
  return cfunc_SetIgnorePlayableRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007091D0 (FUN_007091D0, func_SetIgnorePlayableRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetIgnorePlayableRect`.
 */
moho::CScrLuaInitForm* moho::func_SetIgnorePlayableRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetIgnorePlayableRect",
    &moho::cfunc_SetIgnorePlayableRect,
    nullptr,
    "<global>",
    kSetIgnorePlayableRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709230 (FUN_00709230, cfunc_SetIgnorePlayableRectL)
 *
 * What it does:
 * Reads `(army, flag)` from Lua and updates playable-rect ignore mode through
 * the army interface.
 */
int moho::cfunc_SetIgnorePlayableRectL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kSetIgnorePlayableRectHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  LuaPlus::LuaStackObject flagArg(state, 2);
  const bool ignorePlayableRect = flagArg.GetBoolean();
  army->SetIgnorePlayableRect(ignorePlayableRect);
  return 0;
}

/**
 * Address: 0x00709FB0 (FUN_00709FB0, cfunc_SetArmyFactionIndex)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyFactionIndexL`.
 */
int moho::cfunc_SetArmyFactionIndex(lua_State* const luaContext)
{
  return cfunc_SetArmyFactionIndexL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709FD0 (FUN_00709FD0, func_SetArmyFactionIndex_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyFactionIndex`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyFactionIndex_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyFactionIndex",
    &moho::cfunc_SetArmyFactionIndex,
    nullptr,
    "<global>",
    kSetArmyFactionIndexHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070A030 (FUN_0070A030, cfunc_SetArmyFactionIndexL)
 *
 * What it does:
 * Reads `(army, index)` and updates the army faction index lane.
 */
int moho::cfunc_SetArmyFactionIndexL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kSetArmyFactionIndexHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  LuaPlus::LuaStackObject factionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    factionArg.TypeError("integer");
  }

  if (army != nullptr) {
    army->mVarDat.mFaction = static_cast<std::int32_t>(lua_tonumber(rawState, 2));
  }
  return 0;
}

/**
 * Address: 0x0070AB60 (FUN_0070AB60, cfunc_SetArmyOutOfGame)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyOutOfGameL`.
 */
int moho::cfunc_SetArmyOutOfGame(lua_State* const luaContext)
{
  return cfunc_SetArmyOutOfGameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070AB80 (FUN_0070AB80, func_SetArmyOutOfGame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyOutOfGame`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyOutOfGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyOutOfGame",
    &moho::cfunc_SetArmyOutOfGame,
    nullptr,
    "<global>",
    kSetArmyOutOfGameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070ABE0 (FUN_0070ABE0, cfunc_SetArmyOutOfGameL)
 *
 * What it does:
 * Marks one selected army as out-of-game.
 */
int moho::cfunc_SetArmyOutOfGameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kSetArmyOutOfGameHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (army != nullptr) {
    army->mVarDat.mIsOutOfGame = 1u;
  }
  return 0;
}

/**
 * Address: 0x00709590 (FUN_00709590, cfunc_SetAlliance)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetAllianceL`.
 */
int moho::cfunc_SetAlliance(lua_State* const luaContext)
{
  return cfunc_SetAllianceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007095B0 (FUN_007095B0, func_SetAlliance_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetAlliance`.
 */
moho::CScrLuaInitForm* moho::func_SetAlliance_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetAlliance",
    &moho::cfunc_SetAlliance,
    nullptr,
    "<global>",
    kSetAllianceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709610 (FUN_00709610, cfunc_SetAllianceL)
 *
 * What it does:
 * Reads `(army1, army2, relation)` and writes symmetric alliance relation
 * lanes on both armies.
 */
int moho::cfunc_SetAllianceL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kSetAllianceHelpText);

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);

  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  EAlliance alliance = ALLIANCE_Neutral;
  gpg::RRef enumRef = MakeEAllianceRef(&alliance);
  const LuaPlus::LuaStackObject allianceArg(state, 3);
  const char* allianceText = lua_tostring(rawState, 3);
  if (allianceText == nullptr) {
    allianceArg.TypeError("string");
    allianceText = "";
  }
  SCR_GetEnum(state, allianceText, enumRef);

  const std::uint32_t secondArmyId = secondArmy ? static_cast<std::uint32_t>(secondArmy->mConstDat.mArmyIndex) : 0u;
  firstArmy->SetAlliance(secondArmyId, static_cast<int>(alliance));

  const std::uint32_t firstArmyId = firstArmy ? static_cast<std::uint32_t>(firstArmy->mConstDat.mArmyIndex) : 0u;
  secondArmy->SetAlliance(firstArmyId, static_cast<int>(alliance));
  return 0;
}

/**
 * Address: 0x00709720 (FUN_00709720, cfunc_SetAllianceOneWay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetAllianceOneWayL`.
 */
int moho::cfunc_SetAllianceOneWay(lua_State* const luaContext)
{
  return cfunc_SetAllianceOneWayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00709740 (FUN_00709740, func_SetAllianceOneWay_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetAllianceOneWay`.
 */
moho::CScrLuaInitForm* moho::func_SetAllianceOneWay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetAllianceOneWay",
    &moho::cfunc_SetAllianceOneWay,
    nullptr,
    "<global>",
    kSetAllianceOneWayHelpText
  );
  return &binder;
}

/**
 * Address: 0x007097A0 (FUN_007097A0, cfunc_SetAllianceOneWayL)
 *
 * What it does:
 * Reads `(army1, army2, relation)` and writes one-way alliance relation on
 * the first army only.
 */
int moho::cfunc_SetAllianceOneWayL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kSetAllianceOneWayHelpText);

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const firstArmy = ARMY_FromLuaState(state, firstArmyObject);

  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const secondArmy = ARMY_FromLuaState(state, secondArmyObject);

  EAlliance alliance = ALLIANCE_Neutral;
  gpg::RRef enumRef = MakeEAllianceRef(&alliance);
  const LuaPlus::LuaStackObject allianceArg(state, 3);
  const char* allianceText = lua_tostring(rawState, 3);
  if (allianceText == nullptr) {
    allianceArg.TypeError("string");
    allianceText = "";
  }
  SCR_GetEnum(state, allianceText, enumRef);

  const std::uint32_t secondArmyId = secondArmy ? static_cast<std::uint32_t>(secondArmy->mConstDat.mArmyIndex) : 0u;
  firstArmy->SetAlliance(secondArmyId, static_cast<int>(alliance));
  return 0;
}

/**
 * Address: 0x007098A0 (FUN_007098A0, cfunc_SetAlliedVictory)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetAlliedVictoryL`.
 */
int moho::cfunc_SetAlliedVictory(lua_State* const luaContext)
{
  return cfunc_SetAlliedVictoryL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007098C0 (FUN_007098C0, func_SetAlliedVictory_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetAlliedVictory`.
 */
moho::CScrLuaInitForm* moho::func_SetAlliedVictory_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetAlliedVictory",
    &moho::cfunc_SetAlliedVictory,
    nullptr,
    "<global>",
    kSetAlliedVictoryHelpText
  );
  return &binder;
}

/**
 * Address: 0x00709920 (FUN_00709920, cfunc_SetAlliedVictoryL)
 *
 * What it does:
 * Reads `(army, enabled)` and updates `RequestingAlliedVictory` on that army's
 * brain script object.
 */
int moho::cfunc_SetAlliedVictoryL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kSetAlliedVictoryHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CAiBrain* const brain = army ? army->GetArmyBrain() : nullptr;
  if (brain == nullptr) {
    return 0;
  }

  const LuaPlus::LuaStackObject enabledArg(state, 2);
  brain->mLuaObj.SetBoolean("RequestingAlliedVictory", enabledArg.GetBoolean());
  return 0;
}

/**
 * Address: 0x00708B90 (FUN_00708B90, cfunc_SetArmyEconomy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyEconomyL`.
 */
int moho::cfunc_SetArmyEconomy(lua_State* const luaContext)
{
  return cfunc_SetArmyEconomyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708BB0 (FUN_00708BB0, func_SetArmyEconomy_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyEconomy`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyEconomy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyEconomy",
    &moho::cfunc_SetArmyEconomy,
    nullptr,
    "<global>",
    kSetArmyEconomyHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708C10 (FUN_00708C10, cfunc_SetArmyEconomyL)
 *
 * What it does:
 * Reads `(army, mass, energy)` and adds those deltas to the army stored
 * economy pair.
 */
int moho::cfunc_SetArmyEconomyL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 3, kSetArmyEconomyHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CSimArmyEconomyInfo* const economyInfo = army ? army->GetEconomy() : nullptr;
  if (!economyInfo) {
    return 0;
  }

  LuaPlus::LuaStackObject massArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    massArg.TypeError("number");
  }
  const float massDelta = static_cast<float>(lua_tonumber(state->m_state, 2));

  LuaPlus::LuaStackObject energyArg(state, 3);
  if (lua_type(state->m_state, 3) != LUA_TNUMBER) {
    energyArg.TypeError("number");
  }
  const float energyDelta = static_cast<float>(lua_tonumber(state->m_state, 3));

  // 0x00708CAE `add edi, 8`: both deltas land in the production pool at
  // `GetEconomy() + 8` (mResources) as {0, mass} then {energy, 0} pairs, so the
  // economy tick banks them as income -- they never touch mStored directly.
  economyInfo->mResources.ENERGY += 0.0f;
  economyInfo->mResources.MASS += massDelta;
  economyInfo->mResources.ENERGY += energyDelta;
  economyInfo->mResources.MASS += 0.0f;
  return 0;
}

/**
 * Address: 0x00708F70 (FUN_00708F70, cfunc_SetArmyUnitCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyUnitCapL`.
 */
int moho::cfunc_SetArmyUnitCap(lua_State* const luaContext)
{
  return cfunc_SetArmyUnitCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708F90 (FUN_00708F90, func_SetArmyUnitCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyUnitCap`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyUnitCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyUnitCap",
    &moho::cfunc_SetArmyUnitCap,
    nullptr,
    "<global>",
    kSetArmyUnitCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00708FF0 (FUN_00708FF0, cfunc_SetArmyUnitCapL)
 *
 * What it does:
 * Reads `(army, unitCap)` from Lua and updates that army's unit-cap lane.
 */
int moho::cfunc_SetArmyUnitCapL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kSetArmyUnitCapHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  LuaPlus::LuaStackObject unitCapArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    unitCapArg.TypeError("number");
  }

  const float unitCap = static_cast<float>(lua_tonumber(state->m_state, 2));
  army->SetUnitCap(unitCap);
  return 0;
}

/**
 * Address: 0x0070A180 (FUN_0070A180, cfunc_SetArmyAIPersonalityL)
 *
 * What it does:
 * Reads `(army, personality)` from Lua and updates the army personality lane.
 */
int moho::cfunc_SetArmyAIPersonalityL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 2, kSetArmyAIPersonalityHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (!army) {
    return 0;
  }

  LuaPlus::LuaStackObject personalityArg(state, 2);
  const char* personalityName = lua_tostring(state->m_state, 2);
  if (!personalityName) {
    LuaPlus::LuaStackObject::TypeError(&personalityArg, "string");
    personalityName = "";
  }

  if (personalityName[0] != '\0') {
    army->mVarDat.mArmyType.assign(personalityName, 0U, fa::string::npos);
  }
  return 0;
}

/**
 * Address: 0x0070A100 (FUN_0070A100, cfunc_SetArmyAIPersonality)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyAIPersonalityL`.
 */
int moho::cfunc_SetArmyAIPersonality(lua_State* const luaContext)
{
  return cfunc_SetArmyAIPersonalityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070A120 (FUN_0070A120, func_SetArmyAIPersonality_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyAIPersonality`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyAIPersonality_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyAIPersonality",
    &moho::cfunc_SetArmyAIPersonality,
    nullptr,
    "<global>",
    kSetArmyAIPersonalityHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070A5E0 (FUN_0070A5E0, cfunc_SetArmyShowScore)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyShowScoreL`.
 */
int moho::cfunc_SetArmyShowScore(lua_State* const luaContext)
{
  return cfunc_SetArmyShowScoreL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070A600 (FUN_0070A600, func_SetArmyShowScore_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyShowScore`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyShowScore_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyShowScore",
    &moho::cfunc_SetArmyShowScore,
    nullptr,
    "<global>",
    kSetArmyShowScoreHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070A660 (FUN_0070A660, cfunc_SetArmyShowScoreL)
 *
 * What it does:
 * Reads `(army, showScore)` and stores score visibility in the army runtime
 * variable lane.
 */
int moho::cfunc_SetArmyShowScoreL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kSetArmyShowScoreHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  LuaPlus::LuaStackObject showScoreArg(state, 2);
  const bool showScore = showScoreArg.GetBoolean();
  if (army != nullptr) {
    army->mVarDat.mShowScore = showScore ? 1u : 0u;
  }
  return 0;
}

/**
 * Address: 0x007086D0 (FUN_007086D0, cfunc_SetArmyPlans)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyPlansL`.
 */
int moho::cfunc_SetArmyPlans(lua_State* const luaContext)
{
  return cfunc_SetArmyPlansL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00708750 (FUN_00708750, cfunc_SetArmyPlansL)
 *
 * What it does:
 * Reads `(army, plans)` from Lua and forwards the plans string to
 * `CArmyImpl::SetArmyPlans`.
 */
int moho::cfunc_SetArmyPlansL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kSetArmyPlansHelpText);

  const char* plansText = "";
  if (lua_isstring(state->m_state, 2)) {
    const LuaPlus::LuaStackObject plansArg(state, 2);
    plansText = lua_tostring(state->m_state, 2);
    if (plansText == nullptr) {
      plansArg.TypeError("string");
    }
  }

  const fa::string plansValue(plansText ? plansText : "");
  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  army->SetArmyPlans(plansValue);
  return 0;
}

/**
 * Address: 0x007086F0 (FUN_007086F0, func_SetArmyPlans_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyPlans`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyPlans_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyPlans",
    &moho::cfunc_SetArmyPlans,
    nullptr,
    "<global>",
    kSetArmyPlansHelpText
  );
  return &binder;
}

/**
 * Address: 0x0070A320 (FUN_0070A320, cfunc_SetArmyColorL)
 *
 * What it does:
 * Reads `(army, r, g, b)` from Lua and writes packed color lanes to the army.
 */
int moho::cfunc_SetArmyColorL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 4, kSetArmyColorHelpText);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 1));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  if (!army) {
    return 0;
  }

  const std::uint8_t red = ReadLuaColorByteArg<2>(state);
  const std::uint8_t green = ReadLuaColorByteArg<3>(state);
  const std::uint8_t blue = ReadLuaColorByteArg<4>(state);
  const std::uint32_t packedColor = PackOpaqueArmyColor(red, green, blue);
  army->mVarDat.mPlayerColorBgra = packedColor;
  army->mVarDat.mArmyColorBgra = packedColor;
  return 0;
}

/**
 * Address: 0x0070A2A0 (FUN_0070A2A0, cfunc_SetArmyColor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetArmyColorL`.
 */
int moho::cfunc_SetArmyColor(lua_State* const luaContext)
{
  return cfunc_SetArmyColorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0070A2C0 (FUN_0070A2C0, func_SetArmyColor_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetArmyColor`.
 */
moho::CScrLuaInitForm* moho::func_SetArmyColor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetArmyColor",
    &moho::cfunc_SetArmyColor,
    nullptr,
    "<global>",
    kSetArmyColorHelpText
  );
  return &binder;
}

/**
 * Address: 0x0075C7D0 (FUN_0075C7D0, func_SetPlayableRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetPlayableRect`.
 */
moho::CScrLuaInitForm* moho::func_SetPlayableRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "SetPlayableRect",
    &moho::cfunc_SetPlayableRect,
    nullptr,
    "<global>",
    kSetPlayableRectHelpText
  );
  return &binder;
}
