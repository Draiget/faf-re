#include "moho/sim/UserLuaPrivate.h"

namespace
{
  constexpr const char* kGetArmiesTableHelpText = "armyInfo GetArmiesTable()";
  constexpr const char* kGetArmyAvatarsHelpText = "table GetArmyAvatars() - return a table of avatar units for the army";
  constexpr const char* kGetArmyScoreHelpText = "int GetArmyScore(armyIndex)";
  constexpr const char* kGetEconomyTotalsHelpText = "table GetEconomyTotals()";
  constexpr const char* kGetEconomyTotalsMissingSessionWarning =
    "Attempt to call GetEconomyTotals before world sessions exists.";
  constexpr const char* kGetFocusArmyUserHelpText = "GetFocusArmy()";
  constexpr const char* kGetResourceSharingHelpText = "bool GetResourceSharing()";
  constexpr const char* kIsAllyUserHelpText = "IsAlly(army1,army2)";
  constexpr const char* kIsEnemyUserHelpText = "IsEnemy(army1,army2)";
  constexpr const char* kIsNeutralUserHelpText = "IsNeutral(army1,army2)";
  constexpr const char* kIsObserverHelpText = "IsObserver()";
  constexpr const char* kSetFocusArmyUserHelpText = "SetFocusArmy(armyIndex or -1)";
}


/**
 * Address: 0x008BE490 (FUN_008BE490, cfunc_IsAllyUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsAllyUserL`.
 */
int moho::cfunc_IsAllyUser(lua_State* const luaContext)
{
  return cfunc_IsAllyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE4B0 (FUN_008BE4B0, func_IsAllyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `IsAlly`.
 */
moho::CScrLuaInitForm* moho::func_IsAllyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsAlly",
    &moho::cfunc_IsAllyUser,
    nullptr,
    "<global>",
    kIsAllyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE510 (FUN_008BE510, cfunc_IsAllyUserL)
 *
 * What it does:
 * Resolves `(army1, army2)` and returns whether army1 treats army2 as ally.
 */
int moho::cfunc_IsAllyUserL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kIsAllyUserHelpText);

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  UserArmy* const firstArmy = USER_ResolveArmyFromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  UserArmy* const secondArmy = USER_ResolveArmyFromLuaState(state, secondArmyObject);

  const bool isAlly = firstArmy != nullptr && secondArmy != nullptr && firstArmy->IsAlly(secondArmy->mArmyIndex);
  lua_pushboolean(rawState, isAlly ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008BE5D0 (FUN_008BE5D0, cfunc_IsEnemyUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsEnemyUserL`.
 */
int moho::cfunc_IsEnemyUser(lua_State* const luaContext)
{
  return cfunc_IsEnemyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE5F0 (FUN_008BE5F0, func_IsEnemyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `IsEnemy`.
 */
moho::CScrLuaInitForm* moho::func_IsEnemyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsEnemy",
    &moho::cfunc_IsEnemyUser,
    nullptr,
    "<global>",
    kIsEnemyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE650 (FUN_008BE650, cfunc_IsEnemyUserL)
 *
 * What it does:
 * Resolves `(army1, army2)` and returns whether army1 treats army2 as enemy.
 */
int moho::cfunc_IsEnemyUserL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kIsEnemyUserHelpText);

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  UserArmy* const firstArmy = USER_ResolveArmyFromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  UserArmy* const secondArmy = USER_ResolveArmyFromLuaState(state, secondArmyObject);

  const bool isEnemy = firstArmy != nullptr && secondArmy != nullptr &&
    firstArmy->mVarDat.mEnemies.Contains(secondArmy->mArmyIndex);
  lua_pushboolean(rawState, isEnemy ? 1 : 0);
  return 1;
}
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
}


/**
 * Address: 0x008BE710 (FUN_008BE710, cfunc_IsNeutral)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsNeutralL`.
 */
int moho::cfunc_IsNeutral(lua_State* const luaContext)
{
  return cfunc_IsNeutralL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE730 (FUN_008BE730, func_IsNeutral_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `IsNeutral`.
 */
moho::CScrLuaInitForm* moho::func_IsNeutral_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsNeutral",
    &moho::cfunc_IsNeutral,
    nullptr,
    "<global>",
    kIsNeutralUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE790 (FUN_008BE790, cfunc_IsNeutralL)
 *
 * What it does:
 * Resolves `(army1, army2)` and returns whether army1 treats army2 as neutral.
 */
int moho::cfunc_IsNeutralL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kIsNeutralUserHelpText);

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  UserArmy* const firstArmy = USER_ResolveArmyFromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  UserArmy* const secondArmy = USER_ResolveArmyFromLuaState(state, secondArmyObject);

  const bool isNeutral = firstArmy != nullptr && secondArmy != nullptr
    && IsArmyMarkedNeutral(secondArmy->mArmyIndex, firstArmy->mVarDat.mNeutrals);
  lua_pushboolean(rawState, isNeutral ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008BCC30 (FUN_008BCC30, cfunc_GetArmyAvatars)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetArmyAvatarsL`.
 */
int moho::cfunc_GetArmyAvatars(lua_State* const luaContext)
{
  return cfunc_GetArmyAvatarsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BCC50 (FUN_008BCC50, func_GetArmyAvatars_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetArmyAvatars`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyAvatars_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetArmyAvatars",
    &moho::cfunc_GetArmyAvatars,
    nullptr,
    "<global>",
    kGetArmyAvatarsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BCCB0 (FUN_008BCCB0, cfunc_GetArmyAvatarsL)
 *
 * What it does:
 * Returns one Lua array of focus-army avatar unit script objects.
 */
int moho::cfunc_GetArmyAvatarsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->GetFocusArmy() == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetArmyAvatarsHelpText);

  const fa::vector<WeakPtr<UserUnit>> avatars = session->GetFocusArmy()->GetAvatars();
  if (avatars.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(avatars.size()), 0u);

  std::int32_t luaIndex = 1;
  for (const WeakPtr<UserUnit>& avatar : avatars) {
    if (UserUnit* const unit = avatar.GetObjectPtr(); unit != nullptr) {
      LuaPlus::LuaObject unitObject = unit->GetLuaObject();
      resultTable.SetObject(luaIndex, unitObject);
      ++luaIndex;
    }
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0083F880 (FUN_0083F880, cfunc_GetEconomyTotalsL)
 *
 * What it does:
 * Builds and returns one table containing focus-army economy totals.
 */
int moho::cfunc_GetEconomyTotalsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 0, kGetEconomyTotalsHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    gpg::Warnf(kGetEconomyTotalsMissingSessionWarning);
    return 0;
  }

  const UserArmy* const focusArmy = session->GetFocusUserArmy();
  const SEconTotals zeroTotals{};
  const SEconTotals& totals = focusArmy ? focusArmy->mVarDat.mEconomyTotals : zeroTotals;

  LuaPlus::LuaObject stored(state);
  stored.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject income(state);
  income.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject reclaimed(state);
  reclaimed.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject lastUseRequested(state);
  lastUseRequested.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject lastUseActual(state);
  lastUseActual.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject maxStorage(state);
  maxStorage.AssignNewTable(state, 2, 0u);

  constexpr std::array<const char*, 2> kResourceLexical = {"ENERGY", "MASS"};
  const std::array<float, 2> storedValues = {totals.mStored.ENERGY, totals.mStored.MASS};
  const std::array<float, 2> incomeValues = {totals.mIncome.ENERGY, totals.mIncome.MASS};
  const std::array<float, 2> reclaimedValues = {totals.mReclaimed.ENERGY, totals.mReclaimed.MASS};
  const std::array<float, 2> requestedValues = {totals.mLastUseRequested.ENERGY, totals.mLastUseRequested.MASS};
  const std::array<float, 2> actualValues = {totals.mLastUseActual.ENERGY, totals.mLastUseActual.MASS};
  const std::array<std::uint32_t, 2> storageValues = {
    static_cast<std::uint32_t>(totals.mMaxStorage.ENERGY),
    static_cast<std::uint32_t>(totals.mMaxStorage.MASS)
  };

  for (std::size_t resourceIndex = 0; resourceIndex < kResourceLexical.size(); ++resourceIndex) {
    const char* const key = kResourceLexical[resourceIndex];
    stored.SetNumber(key, storedValues[resourceIndex]);
    income.SetNumber(key, incomeValues[resourceIndex]);
    reclaimed.SetNumber(key, reclaimedValues[resourceIndex]);
    lastUseRequested.SetNumber(key, requestedValues[resourceIndex]);
    lastUseActual.SetNumber(key, actualValues[resourceIndex]);
    maxStorage.SetInteger(key, static_cast<std::int32_t>(storageValues[resourceIndex]));
  }

  LuaPlus::LuaObject totalsTable(state);
  totalsTable.AssignNewTable(state, 6, 0u);
  totalsTable.SetObject("stored", stored);
  totalsTable.SetObject("income", income);
  totalsTable.SetObject("reclaimed", reclaimed);
  totalsTable.SetObject("lastUseRequested", lastUseRequested);
  totalsTable.SetObject("lastUseActual", lastUseActual);
  totalsTable.SetObject("maxStorage", maxStorage);

  totalsTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0083F800 (FUN_0083F800, cfunc_GetEconomyTotals)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetEconomyTotalsL`.
 */
int moho::cfunc_GetEconomyTotals(lua_State* const luaContext)
{
  return cfunc_GetEconomyTotalsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F820 (FUN_0083F820, func_GetEconomyTotals_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetEconomyTotals`.
 */
moho::CScrLuaInitForm* moho::func_GetEconomyTotals_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetEconomyTotals",
    &moho::cfunc_GetEconomyTotals,
    nullptr,
    "<global>",
    kGetEconomyTotalsHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083FED0 (FUN_0083FED0, cfunc_GetResourceSharing)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetResourceSharingL`.
 */
int moho::cfunc_GetResourceSharing(lua_State* const luaContext)
{
  return cfunc_GetResourceSharingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083FEF0 (FUN_0083FEF0, func_GetResourceSharing_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetResourceSharing`.
 */
moho::CScrLuaInitForm* moho::func_GetResourceSharing_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetResourceSharing",
    &moho::cfunc_GetResourceSharing,
    nullptr,
    "<global>",
    kGetResourceSharingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083FF50 (FUN_0083FF50, cfunc_GetResourceSharingL)
 *
 * What it does:
 * Pushes whether the focused user army has resource sharing enabled.
 */
int moho::cfunc_GetResourceSharingL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetResourceSharingHelpText);

  const CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    gpg::Warnf(kGetEconomyTotalsMissingSessionWarning);
    return 0;
  }

  bool isResourceSharingEnabled = false;
  const int focusArmyIndex = session->FocusArmy;
  if (focusArmyIndex >= 0) {
    const std::size_t armyIndex = static_cast<std::size_t>(focusArmyIndex);
    if (armyIndex < session->userArmies.size()) {
      const UserArmy* const focusedArmy = session->userArmies[armyIndex];
      if (focusedArmy != nullptr && focusedArmy->mVarDat.mIsResourceSharingEnabled != 0u) {
        isResourceSharingEnabled = true;
      }
    }
  }

  lua_pushboolean(rawState, isResourceSharingEnabled ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00842E60 (FUN_00842E60, cfunc_SetFocusArmyUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SetFocusArmyUserL`.
 */
int moho::cfunc_SetFocusArmyUser(lua_State* const luaContext)
{
  return cfunc_SetFocusArmyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842E80 (FUN_00842E80, func_SetFocusArmyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetFocusArmy`.
 */
moho::CScrLuaInitForm* moho::func_SetFocusArmyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetFocusArmy",
    &moho::cfunc_SetFocusArmyUser,
    nullptr,
    "<global>",
    kSetFocusArmyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842EE0 (FUN_00842EE0, cfunc_SetFocusArmyUserL)
 *
 * What it does:
 * Validates one-based army index input and requests focus-army update.
 */
int moho::cfunc_SetFocusArmyUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kSetFocusArmyUserHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  LuaPlus::LuaStackObject indexArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }

  int focusArmyIndex = static_cast<int>(lua_tonumber(rawState, 1));
  if (focusArmyIndex != -1) {
    const int maxArmyIndexOneBased = static_cast<int>(session->userArmies.size());
    if (focusArmyIndex < 1 || focusArmyIndex > maxArmyIndexOneBased) {
      LuaPlus::LuaState::Error(
        state,
        "Invalid army index of %d; must be between 1 and %d inclusive.",
        focusArmyIndex,
        maxArmyIndexOneBased
      );
    }

    --focusArmyIndex;
  }

  session->RequestFocusArmy(focusArmyIndex);
  return 0;
}

/**
 * Address: 0x00842FD0 (FUN_00842FD0, cfunc_GetFocusArmyUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetFocusArmyUserL`.
 */
int moho::cfunc_GetFocusArmyUser(lua_State* const luaContext)
{
  return cfunc_GetFocusArmyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842FF0 (FUN_00842FF0, func_GetFocusArmyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetFocusArmy`.
 */
moho::CScrLuaInitForm* moho::func_GetFocusArmyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetFocusArmy",
    &moho::cfunc_GetFocusArmyUser,
    nullptr,
    "<global>",
    kGetFocusArmyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843050 (FUN_00843050, cfunc_GetFocusArmyUserL)
 *
 * What it does:
 * Pushes the focused army as a one-based Lua index (`-1` when unset).
 */
int moho::cfunc_GetFocusArmyUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetFocusArmyUserHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  int focusArmy = session->FocusArmy;
  if (focusArmy != -1) {
    ++focusArmy;
  }

  lua_pushnumber(rawState, static_cast<float>(focusArmy));
  return 1;
}

/**
 * Address: 0x008430D0 (FUN_008430D0, cfunc_IsObserver)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_IsObserverL`.
 */
int moho::cfunc_IsObserver(lua_State* const luaContext)
{
  return cfunc_IsObserverL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008430F0 (FUN_008430F0, func_IsObserver_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsObserver`.
 */
moho::CScrLuaInitForm* moho::func_IsObserver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "IsObserver",
    &moho::cfunc_IsObserver,
    nullptr,
    "<global>",
    kIsObserverHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843150 (FUN_00843150, cfunc_IsObserverL)
 *
 * What it does:
 * Pushes whether the active focus army has no owning `UserArmy` entry.
 */
int moho::cfunc_IsObserverL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kIsObserverHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  UserArmy* focusArmy = nullptr;
  const int focusArmyIndex = session->FocusArmy;
  if (focusArmyIndex >= 0) {
    focusArmy = session->userArmies[static_cast<std::size_t>(focusArmyIndex)];
  }

  lua_pushboolean(rawState, focusArmy == nullptr);
  return 1;
}

/**
 * Address: 0x008439A0 (FUN_008439A0, cfunc_GetArmiesTable)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetArmiesTableL`.
 */
int moho::cfunc_GetArmiesTable(lua_State* const luaContext)
{
  return cfunc_GetArmiesTableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008439C0 (FUN_008439C0, func_GetArmiesTable_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmiesTable`.
 */
moho::CScrLuaInitForm* moho::func_GetArmiesTable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetArmiesTable",
    &moho::cfunc_GetArmiesTable,
    nullptr,
    "<global>",
    kGetArmiesTableHelpText
  );
  return &binder;
}

/**
 * Address: 0x008485C0 (FUN_008485C0)
 *
 * What it does:
 * Copies one `UserArmy*` vector lane into caller scratch storage for stable
 * iteration during Lua table materialization.
 */
static fa::vector<moho::UserArmy*>* SnapshotUserArmyVector(
  const fa::vector<moho::UserArmy*>& source,
  fa::vector<moho::UserArmy*>* const outSnapshot
)
{
  if (outSnapshot == nullptr) {
    return nullptr;
  }

  *outSnapshot = source;
  return outSnapshot;
}

/**
 * Address: 0x00843A20 (FUN_00843A20, cfunc_GetArmiesTableL)
 *
 * What it does:
 * Builds and returns one Lua table describing session armies and command
 * source authorization lanes.
 */
int moho::cfunc_GetArmiesTableL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 0, kGetArmiesTableHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  fa::vector<UserArmy*> armiesSnapshot{};
  SnapshotUserArmyVector(session->userArmies, &armiesSnapshot);
  const fa::vector<UserArmy*>& armies = armiesSnapshot;
  const std::size_t armyCount = armies.size();

  LuaPlus::LuaObject result(state);
  result.AssignNewTable(state, 0, 0u);
  result.SetInteger("numArmies", static_cast<std::int32_t>(armyCount));

  int focusArmy = session->FocusArmy;
  if (focusArmy != -1) {
    ++focusArmy;
  }
  result.SetInteger("focusArmy", focusArmy);

  LuaPlus::LuaObject armiesTable(state);
  armiesTable.AssignNewTable(state, static_cast<int>(armyCount), 0u);

  for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
    UserArmy* const army = armies[armyIndex];

    LuaPlus::LuaObject armyEntry(state);
    armyEntry.AssignNewTable(state, 0, 0u);
    armyEntry.SetString("name", army->mArmyName.c_str());
    armyEntry.SetString("nickname", army->mPlayerName.c_str());
    armyEntry.SetInteger("faction", army->mVarDat.mFaction);

    const LuaPlus::LuaObject playerColor = SCR_EncodeColor(state, army->mVarDat.mPlayerColorBgra);
    armyEntry.SetObject("color", playerColor);

    const LuaPlus::LuaObject iconColor = SCR_EncodeColor(state, army->mVarDat.mArmyColorBgra);
    armyEntry.SetObject("iconColor", iconColor);

    armyEntry.SetBoolean("showScore", army->mVarDat.mShowScore != 0u);
    armyEntry.SetBoolean("civilian", army->mIsCivilian != 0u);
    armyEntry.SetBoolean("human", gpg::STR_CompareNoCase(army->mVarDat.mArmyType.c_str(), "human") == 0);
    armyEntry.SetBoolean("outOfGame", army->mVarDat.mIsOutOfGame != 0u);

    LuaPlus::LuaObject authorizedCommandSources(state);
    authorizedCommandSources.AssignNewTable(state, 0, 0u);
    const BVIntSet& validSources = army->mVarDat.mValidCommandSources;
    int luaSourceIndex = 1;
    const std::size_t usedWords = static_cast<std::size_t>(validSources.mWords.end_ - validSources.mWords.start_);
    for (std::size_t wordIndex = 0; wordIndex < usedWords; ++wordIndex) {
      const std::uint32_t wordBits = validSources.mWords.start_[wordIndex];
      if (wordBits == 0u) {
        continue;
      }

      for (std::uint32_t bit = 0; bit < 32u; ++bit) {
        if ((wordBits & (1u << bit)) == 0u) {
          continue;
        }
        const std::uint32_t sourceId =
          static_cast<std::uint32_t>((static_cast<std::int32_t>(validSources.mFirstWordIndex) + static_cast<std::int32_t>(wordIndex)) * 32u + bit);
        authorizedCommandSources.SetInteger(luaSourceIndex++, static_cast<std::int32_t>(sourceId + 1u));
      }
    }

    armyEntry.SetObject("authorizedCommandSources", authorizedCommandSources);
    armiesTable.SetObject(static_cast<std::int32_t>(armyIndex + 1u), armyEntry);
  }

  result.SetObject("armiesTable", armiesTable);
  result.PushStack(state);
  return 1;
}

/**
 * Address: 0x00843E50 (FUN_00843E50, cfunc_GetArmyScore)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetArmyScoreL`.
 */
int moho::cfunc_GetArmyScore(lua_State* const luaContext)
{
  return cfunc_GetArmyScoreL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00843E70 (FUN_00843E70, func_GetArmyScore_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmyScore`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyScore_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetArmyScore",
    &moho::cfunc_GetArmyScore,
    nullptr,
    "<global>",
    kGetArmyScoreHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843ED0 (FUN_00843ED0, cfunc_GetArmyScoreL)
 *
 * What it does:
 * Validates one argument and active-session precondition for the
 * `GetArmyScore` global Lua callback lane.
 */
int moho::cfunc_GetArmyScoreL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kGetArmyScoreHelpText);

  if (WLD_GetActiveSession() == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  return 0;
}
