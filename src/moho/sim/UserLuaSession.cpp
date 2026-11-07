#include "moho/lua/CScrLuaInitForm.h"
#include "moho/sim/UserLuaPrivate.h"
#include "gpg/core/diagnostics/BuildInfo.h"

namespace
{
  constexpr const char* kAddToSessionExtraSelectListHelpText = "Add unit to the session extra select list";
  constexpr const char* kClearSessionExtraSelectListHelpText = "Clear the session extra select list";
  constexpr const char* kCurrentTimeHelpText =
    "Get the current time in seconds, counting from 0 at application start. This is wall-clock time and is unaffected by gameplay.";
  constexpr const char* kEjectSessionClientHelpText =
    "EjectSessionClient(int clientIndex) -- eject another client from your session";
  constexpr const char* kExitGameHelpText = "ExitGame() - Quits the sim, but not the app";
  constexpr const char* kFormatTimeHelpText =
    "string FormatTime(seconds) - format a string displaying the time specified in seconds";
  constexpr const char* kGameTickUserHelpText =
    "Get the current game time in ticks. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kGameTimeUserHelpText =
    "Get the current game time in seconds. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kGetGameSpeedHelpText = "Return the current game speed";
  constexpr const char* kGetGameTimeHelpText =
    "string GetGameTime() - returns a formatted string displaying the time the game has been played";
  constexpr const char* kGetGameTimeSecondsUserHelpText = "float GetGameTimeSeconds() - returns game time in seconds";
  constexpr const char* kGetSimRateHelpText = "number GetSimRate()";
  constexpr const char* kGetSimTicksPerSecondHelpText = "int GetSimTicksPerSecond()";
  constexpr const char* kGetSystemTimeHelpText =
    "string GetSystemTime() - returns a formatted string displaying the System time";
  constexpr const char* kGetSystemTimeSecondsHelpText =
    "float GetSystemTimeSeconds() - returns System time in seconds";
  constexpr CommandSourceId kInvalidCommandSource = 0xFF;
  constexpr const char* kNoActiveSessionPeriodText = "No active session.";
  constexpr const char* kNoActiveSessionText = "No active session";
  constexpr const char* kRandomUserHelpText = "Random([[min,] max])";
  constexpr const char* kRemoveFromSessionExtraSelectListHelpText = "Remove unit from the session extra select list";
  constexpr const char* kRestartSessionHelpText = "RestartSession() - Restart the current mission/skirmish/etc";
  constexpr const char* kSessionCanRestartHelpText = "Return true iff the active session can be restarted.";
  constexpr const char* kSessionEndGameHelpText =
    "End the current game session.  The session says active, we just disconnect from everyone else and freeze play.";
  constexpr const char* kSessionGetLocalCommandSourceHelpText =
    "Return the local command source.  Returns 0 if the local client can't issue commands.";
  constexpr const char* kSessionGetLocalCommandSourceNoActiveSessionText =
    "SessionGetLocalCommandSource(): no active session.";
  constexpr const char* kSessionGetScenarioInfoHelpText =
    "Return the table of scenario info that was originally passed to the sim on launch.";
  constexpr const char* kSessionGetScenarioInfoNoActiveSessionText = "no active session.";
  constexpr const char* kSessionIsActiveHelpText = "Return true iff there is a session currently running";
  constexpr const char* kSessionIsBeingRecordedHelpText = "Return true iff the active session is a being recorded.";
  constexpr const char* kSessionIsGameOverHelpText = "Return true iff the session has been won or lost yet.";
  constexpr const char* kSessionIsGameOverNoActiveSessionText = "SessionIsGameOver(): no active session.";
  constexpr const char* kSessionIsMultiplayerHelpText = "Return true iff the active session is a multiplayer session.";
  constexpr const char* kSessionIsObservingAllowedHelpText =
    "Return true iff observing is allowed in the active session.";
  constexpr const char* kSessionIsPausedHelpText = "Return true iff the session is paused.";
  constexpr const char* kSessionIsPausedNoActiveSessionText = "SessionIsPaused(): no active session.";
  constexpr const char* kSessionIsReplayUserHelpText = "Return true iff the active session is a replay session.";
  constexpr const char* kSessionRequestPauseHelpText = "Pause the world simulation.";
  constexpr const char* kSessionRequestPauseNoActiveSessionText = "SessionRequestPause(): no active session.";
  constexpr const char* kSessionResumeHelpText = "Resume the world simulation.";
  constexpr const char* kSessionResumeNoActiveSessionText = "SessionResume(): no active session.";
  constexpr const char* kSetGameSpeedHelpText = "Set the desired game speed";
  constexpr const char* kSyncPlayableRectHelpText = "SyncPlayableRect(region)";
  constexpr const char* kWorldIsLoadingHelpText = "bool = WorldIsLoading()";
  constexpr const char* kWorldIsPlayingHelpText = "bool = WorldIsPlaying()";
  constexpr const char* kWrongLuaStateText = "wrong lua state.";
}

/**
 * Address: 0x0088D970 (FUN_0088D970, cfunc_EjectSessionClientL)
 *
 * What it does:
 * Validates one client index argument and ejects the selected non-local
 * client from the active session.
 */
int moho::cfunc_EjectSessionClientL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kEjectSessionClientHelpText);

  auto* const simDriver = dynamic_cast<CSimDriver*>(WLD_GetDriver());
  if (simDriver == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  IClientManager* const clientManager = simDriver->GetClientManager();
  if (clientManager == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  LuaPlus::LuaStackObject clientIndexArg{};
  clientIndexArg.m_state = state;
  clientIndexArg.m_stackIndex = 1;
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&clientIndexArg, "integer");
  }

  const int clientIndex = static_cast<int>(lua_tonumber(rawState, 1));
  const int clientCount = static_cast<int>(clientManager->NumberOfClients());
  if (clientIndex < 1 || clientIndex > clientCount) {
    LuaPlus::LuaState::Error(state, "Invalid client index %d, must be >= 1 and <= %d", clientIndex, clientCount);
  }

  IClient* const targetClient = clientManager->GetClient(clientIndex - 1);
  if (targetClient == nullptr) {
    LuaPlus::LuaState::Error(state, "Invalid client index %d, must be >= 1 and <= %d", clientIndex, clientCount);
  }

  if (targetClient == clientManager->GetLocalClient()) {
    LuaPlus::LuaState::Error(state, "Can't eject ourselves!");
  }

  targetClient->Eject();
  return 0;
}

/**
 * Address: 0x0088D8F0 (FUN_0088D8F0, cfunc_EjectSessionClient)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EjectSessionClientL`.
 */
int moho::cfunc_EjectSessionClient(lua_State* const luaContext)
{
  return cfunc_EjectSessionClientL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088D910 (FUN_0088D910, func_EjectSessionClient_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EjectSessionClient`.
 */
moho::CScrLuaInitForm* moho::func_EjectSessionClient_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "EjectSessionClient",
    &moho::cfunc_EjectSessionClient,
    nullptr,
    "<global>",
    kEjectSessionClientHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088DF50 (FUN_0088DF50, cfunc_WorldIsLoadingL)
 *
 * What it does:
 * Returns whether the current world frame action is loading or preload.
 */
int moho::cfunc_WorldIsLoadingL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kWorldIsLoadingHelpText);

  const EWldFrameAction frameAction = WLD_GetFrameAction();
  lua_pushboolean(
    state->m_state,
    frameAction == EWldFrameAction::Loading || frameAction == EWldFrameAction::Preload
  );
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0088DED0 (FUN_0088DED0, cfunc_WorldIsLoading)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_WorldIsLoadingL`.
 */
int moho::cfunc_WorldIsLoading(lua_State* const luaContext)
{
  return cfunc_WorldIsLoadingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088DEF0 (FUN_0088DEF0, func_WorldIsLoading_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `WorldIsLoading`.
 */
moho::CScrLuaInitForm* moho::func_WorldIsLoading_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "WorldIsLoading",
    &moho::cfunc_WorldIsLoading,
    nullptr,
    "<global>",
    kWorldIsLoadingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088E030 (FUN_0088E030, cfunc_WorldIsPlayingL)
 *
 * What it does:
 * Returns whether the current world frame action is actively playing.
 */
int moho::cfunc_WorldIsPlayingL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kWorldIsPlayingHelpText);

  lua_pushboolean(state->m_state, WLD_GetFrameAction() == EWldFrameAction::Playing);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0088DFB0 (FUN_0088DFB0, cfunc_WorldIsPlaying)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_WorldIsPlayingL`.
 */
int moho::cfunc_WorldIsPlaying(lua_State* const luaContext)
{
  return cfunc_WorldIsPlayingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088DFD0 (FUN_0088DFD0, func_WorldIsPlaying_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `WorldIsPlaying`.
 */
moho::CScrLuaInitForm* moho::func_WorldIsPlaying_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "WorldIsPlaying",
    &moho::cfunc_WorldIsPlaying,
    nullptr,
    "<global>",
    kWorldIsPlayingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088E260 (FUN_0088E260, cfunc_GetGameSpeedL)
 *
 * What it does:
 * Returns the current requested sim speed from the active client manager.
 */
int moho::cfunc_GetGameSpeedL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kGetGameSpeedHelpText);

  ISTIDriver* const activeDriver = WLD_GetDriver();
  if (activeDriver == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
  lua_pushnumber(state->m_state, static_cast<float>(clientManager->GetSimRateRequested()));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0088E1E0 (FUN_0088E1E0, cfunc_GetGameSpeed)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_GetGameSpeedL`.
 */
int moho::cfunc_GetGameSpeed(lua_State* const luaContext)
{
  return cfunc_GetGameSpeedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088E200 (FUN_0088E200, func_GetGameSpeed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetGameSpeed`.
 */
moho::CScrLuaInitForm* moho::func_GetGameSpeed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetGameSpeed",
    &moho::cfunc_GetGameSpeed,
    nullptr,
    "<global>",
    kGetGameSpeedHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088E360 (FUN_0088E360, cfunc_SetGameSpeedL)
 *
 * What it does:
 * Validates one requested speed and forwards it to the active client manager.
 */
int moho::cfunc_SetGameSpeedL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kSetGameSpeedHelpText);

  ISTIDriver* const activeDriver = WLD_GetDriver();
  if (activeDriver == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  if (WLD_CanAdjustSimRate()) {
    CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
    LuaPlus::LuaStackObject speedArg(state, 1);
    if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&speedArg, "integer");
    }

    const int requestedSpeed = static_cast<int>(lua_tonumber(state->m_state, 1));
    clientManager->SetSimRate(requestedSpeed);
  }

  return 0;
}

/**
 * Address: 0x0088E2E0 (FUN_0088E2E0, cfunc_SetGameSpeed)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SetGameSpeedL`.
 */
int moho::cfunc_SetGameSpeed(lua_State* const luaContext)
{
  return cfunc_SetGameSpeedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088E300 (FUN_0088E300, func_SetGameSpeed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetGameSpeed`.
 */
moho::CScrLuaInitForm* moho::func_SetGameSpeed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetGameSpeed",
    &moho::cfunc_SetGameSpeed,
    nullptr,
    "<global>",
    kSetGameSpeedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BDEC0 (FUN_008BDEC0, cfunc_AddToSessionExtraSelectListL)
 *
 * What it does:
 * Reads one user-unit Lua object and adds it to world-session extra selection.
 */
int moho::cfunc_AddToSessionExtraSelectListL(LuaPlus::LuaState* const state)
{
  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    moho::SCR_ExpectExactArgs(state, 1, kAddToSessionExtraSelectListHelpText);

    LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
    UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
    session->AddToExtraSelectList(userEntity);
  }

  return 0;
}

/**
 * Address: 0x008BDE40 (FUN_008BDE40, cfunc_AddToSessionExtraSelectList)
 *
 * What it does:
 * Unwraps Lua callback state and dispatches to
 * `cfunc_AddToSessionExtraSelectListL`.
 */
int moho::cfunc_AddToSessionExtraSelectList(lua_State* const luaContext)
{
  return cfunc_AddToSessionExtraSelectListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BDE60 (FUN_008BDE60, func_AddToSessionExtraSelectList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `AddToSessionExtraSelectList`.
 */
moho::CScrLuaInitForm* moho::func_AddToSessionExtraSelectList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "AddToSessionExtraSelectList",
    &moho::cfunc_AddToSessionExtraSelectList,
    nullptr,
    "<global>",
    kAddToSessionExtraSelectListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BDFF0 (FUN_008BDFF0, cfunc_RemoveFromSessionExtraSelectListL)
 *
 * What it does:
 * Reads one user-unit Lua object and removes it from world-session extra
 * selection.
 */
int moho::cfunc_RemoveFromSessionExtraSelectListL(LuaPlus::LuaState* const state)
{
  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    moho::SCR_ExpectExactArgs(state, 1, kRemoveFromSessionExtraSelectListHelpText);

    LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
    UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
    session->RemoveFromExtraSelectList(userEntity);
  }

  return 0;
}

/**
 * Address: 0x008BDF70 (FUN_008BDF70, cfunc_RemoveFromSessionExtraSelectList)
 *
 * What it does:
 * Unwraps Lua callback state and dispatches to
 * `cfunc_RemoveFromSessionExtraSelectListL`.
 */
int moho::cfunc_RemoveFromSessionExtraSelectList(lua_State* const luaContext)
{
  return cfunc_RemoveFromSessionExtraSelectListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BDF90 (FUN_008BDF90, func_RemoveFromSessionExtraSelectList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `RemoveFromSessionExtraSelectList`.
 */
moho::CScrLuaInitForm* moho::func_RemoveFromSessionExtraSelectList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "RemoveFromSessionExtraSelectList",
    &moho::cfunc_RemoveFromSessionExtraSelectList,
    nullptr,
    "<global>",
    kRemoveFromSessionExtraSelectListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE0D0 (FUN_008BE0D0, cfunc_ClearSessionExtraSelectList)
 *
 * What it does:
 * Validates zero-argument call shape and clears the active session extra
 * selection set when a world session exists.
 */
int moho::cfunc_ClearSessionExtraSelectList(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  CWldSession* const activeSession = WLD_GetActiveSession();
  if (activeSession == nullptr) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 0, kClearSessionExtraSelectListHelpText);

  activeSession->ClearExtraSelectList();
  return 0;
}

/**
 * Address: 0x008BE120 (FUN_008BE120, func_ClearSessionExtraSelectList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `ClearSessionExtraSelectList`.
 */
moho::CScrLuaInitForm* moho::func_ClearSessionExtraSelectList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ClearSessionExtraSelectList",
    &moho::cfunc_ClearSessionExtraSelectList,
    nullptr,
    "<global>",
    kClearSessionExtraSelectListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE1C0 (FUN_008BE1C0, cfunc_CurrentTime)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_CurrentTimeL`.
 */
int moho::cfunc_CurrentTime(lua_State* const luaContext)
{
  return cfunc_CurrentTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE1E0 (FUN_008BE1E0, func_CurrentTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CurrentTime`.
 */
moho::CScrLuaInitForm* moho::func_CurrentTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "CurrentTime",
    &moho::cfunc_CurrentTime,
    nullptr,
    "<global>",
    kCurrentTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE240 (FUN_008BE240, cfunc_CurrentTimeL)
 *
 * What it does:
 * Validates zero-argument call shape and returns wall-clock elapsed seconds.
 */
int moho::cfunc_CurrentTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kCurrentTimeHelpText);

  lua_pushnumber(rawState, gpg::time::GetSystemTimer().ElapsedSeconds());
  return 1;
}

/**
 * Address: 0x008BE2A0 (FUN_008BE2A0, cfunc_GameTime)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_GameTimeL`.
 */
int moho::cfunc_GameTime(lua_State* const luaContext)
{
  return cfunc_GameTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE2C0 (FUN_008BE2C0, func_GameTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GameTime`.
 */
moho::CScrLuaInitForm* moho::func_GameTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GameTime",
    &moho::cfunc_GameTime,
    nullptr,
    "<global>",
    kGameTimeUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE320 (FUN_008BE320, cfunc_GameTimeL)
 *
 * What it does:
 * Returns current game time in seconds from the active world session.
 */
int moho::cfunc_GameTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGameTimeUserHelpText);

  const CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  const float gameTimeSeconds = (static_cast<float>(session->mGameTick) + session->mTimeSinceLastTick) * 0.1f;
  lua_pushnumber(rawState, gameTimeSeconds);
  return 1;
}

/**
 * Address: 0x008BE3A0 (FUN_008BE3A0, cfunc_GameTick)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_GameTickL`.
 */
int moho::cfunc_GameTick(lua_State* const luaContext)
{
  return cfunc_GameTickL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE3C0 (FUN_008BE3C0, func_GameTick_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GameTick`.
 */
moho::CScrLuaInitForm* moho::func_GameTick_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GameTick",
    &moho::cfunc_GameTick,
    nullptr,
    "<global>",
    kGameTickUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE420 (FUN_008BE420, cfunc_GameTickL)
 *
 * What it does:
 * Returns current game time in ticks from the active world session.
 */
int moho::cfunc_GameTickL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGameTickUserHelpText);

  const CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  lua_pushnumber(rawState, static_cast<float>(session->mGameTick));
  return 1;
}

/**
 * Address: 0x008BE8D0 (FUN_008BE8D0, cfunc_SyncPlayableRectL)
 *
 * What it does:
 * Reads one rect table and synchronizes active-session playable bounds +
 * user-entity visibility against that rectangle.
 */
int moho::cfunc_SyncPlayableRectL(LuaPlus::LuaState* const state)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kSyncPlayableRectHelpText);

  const LuaPlus::LuaObject rectObject(LuaPlus::LuaStackObject(state, 1));
  const gpg::Rect2i playableRect = SCR_FromLuaCopy<gpg::Rect2<int>>(rectObject);
  session->SyncPlayableRect(playableRect);
  return 0;
}

/**
 * Address: 0x008BE850 (FUN_008BE850, cfunc_SyncPlayableRect)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SyncPlayableRectL`.
 */
int moho::cfunc_SyncPlayableRect(lua_State* const luaContext)
{
  return cfunc_SyncPlayableRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE870 (FUN_008BE870, func_SyncPlayableRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SyncPlayableRect`.
 */
moho::CScrLuaInitForm* moho::func_SyncPlayableRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SyncPlayableRect",
    &moho::cfunc_SyncPlayableRect,
    nullptr,
    "<global>",
    kSyncPlayableRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE980 (FUN_008BE980, cfunc_RandomUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_RandomUserL`.
 */
int moho::cfunc_RandomUser(lua_State* const luaContext)
{
  return cfunc_RandomUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE9A0 (FUN_008BE9A0, func_RandomUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `Random`.
 */
moho::CScrLuaInitForm* moho::func_RandomUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "Random",
    &moho::cfunc_RandomUser,
    nullptr,
    "<global>",
    kRandomUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BEA00 (FUN_008BEA00, cfunc_RandomUserL)
 *
 * What it does:
 * Produces one random float or integer range sample from the process-wide
 * random stream for `Random([[min,] max])`.
 */
int moho::cfunc_RandomUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kRandomUserHelpText,
      0,
      2,
      argumentCount
    );
  }

  std::lock_guard<std::mutex> randomLock(math_GlobalRandomMutex);
  if (argumentCount == 0) {
    // 0x008BEB38..0x008BEB4D: `fild; jge; fadd 2^32; fmul [0x00E4F7B0]`, the
    // float 2^-32 (0x2F800000), stored to float once.
    constexpr float kInvTwoTo32 = 0x1p-32f;
    const float value = fa::MulTwisterWord(kInvTwoTo32, math_GlobalRandomStream.twister.NextUInt32());
    lua_pushnumber(rawState, value);
    return 1;
  }

  if (argumentCount == 1) {
    const int maxValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
    const std::uint32_t randomValue = math_GlobalRandomStream.twister.NextUInt32();
    const std::uint32_t scaledValue = static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(static_cast<std::uint32_t>(maxValue)) * static_cast<std::uint64_t>(randomValue)) >>
      32u
    );
    const int result = static_cast<int>(scaledValue + 1u);
    lua_pushnumber(rawState, static_cast<float>(result));
    return 1;
  }

  const int minValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
  const int maxValue = LuaPlus::LuaStackObject(state, 2).GetInteger();
  const std::uint32_t randomValue = math_GlobalRandomStream.twister.NextUInt32();
  const std::uint32_t span = (static_cast<std::uint32_t>(maxValue) + 1u) - static_cast<std::uint32_t>(minValue);
  const std::uint32_t scaledOffset =
    static_cast<std::uint32_t>((static_cast<std::uint64_t>(span) * static_cast<std::uint64_t>(randomValue)) >> 32u);
  const int result = static_cast<int>(static_cast<std::uint32_t>(minValue) + scaledOffset);
  lua_pushnumber(rawState, static_cast<float>(result));
  return 1;
}

/**
 * Address: 0x0083F2B0 (FUN_0083F2B0, cfunc_ExitGame)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and requests sim exit.
 */
int moho::cfunc_ExitGame(lua_State* const luaContext)
{
  return cfunc_ExitGameL(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x0083F360 (FUN_0083F360, sub_83F360)
 *
 * What it does:
 * Validates zero args and requests world-frame action `Exit`.
 */
int moho::cfunc_ExitGameL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 0, kExitGameHelpText);

  if (WLD_GetFrameAction() != EWldFrameAction::Inactive) {
    WLD_SetFrameAction(EWldFrameAction::Exit);
  }

  return 0;
}

/**
 * Address: 0x0083F300 (FUN_0083F300, func_ExitGame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ExitGame`.
 */
moho::CScrLuaInitForm* moho::func_ExitGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ExitGame",
    &moho::cfunc_ExitGame,
    nullptr,
    "<global>",
    kExitGameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F3A0 (FUN_0083F3A0, cfunc_RestartSession)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_RestartSessionL`.
 */
int moho::cfunc_RestartSession(lua_State* const luaContext)
{
  return cfunc_RestartSessionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F3C0 (FUN_0083F3C0, func_RestartSession_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RestartSession`.
 */
moho::CScrLuaInitForm* moho::func_RestartSession_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "RestartSession",
    &moho::cfunc_RestartSession,
    nullptr,
    "<global>",
    kRestartSessionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F420 (FUN_0083F420, cfunc_RestartSessionL)
 *
 * What it does:
 * Validates zero arguments and requests world-frame action `CreateSession`
 * when restart prerequisites are present.
 */
int moho::cfunc_RestartSessionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 0, kRestartSessionHelpText);

  if (WLD_GetFrameAction() != EWldFrameAction::Inactive) {
    CWldSession* const session = WLD_GetActiveSession();
    if (session != nullptr && session->mLaunchInfo.get() != nullptr) {
      WLD_SetFrameAction(EWldFrameAction::CreateSession);
    }
  }

  return 0;
}

/**
 * Address: 0x0083FFE0 (FUN_0083FFE0, cfunc_GetSimTicksPerSecond)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSimTicksPerSecondL`.
 */
int moho::cfunc_GetSimTicksPerSecond(lua_State* const luaContext)
{
  return cfunc_GetSimTicksPerSecondL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00840000 (FUN_00840000, func_GetSimTicksPerSecond_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSimTicksPerSecond`.
 */
moho::CScrLuaInitForm* moho::func_GetSimTicksPerSecond_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSimTicksPerSecond",
    &moho::cfunc_GetSimTicksPerSecond,
    nullptr,
    "<global>",
    kGetSimTicksPerSecondHelpText
  );
  return &binder;
}

/**
 * Address: 0x00840060 (FUN_00840060, cfunc_GetSimTicksPerSecondL)
 *
 * What it does:
 * Pushes fixed simulation ticks-per-second (10.0) as a Lua number.
 */
int moho::cfunc_GetSimTicksPerSecondL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetSimTicksPerSecondHelpText);

  lua_pushnumber(rawState, 10.0);
  return 1;
}

/**
 * Address: 0x00897780 (FUN_00897780, cfunc_SessionRequestPause)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionRequestPauseL`.
 */
int moho::cfunc_SessionRequestPause(lua_State* const luaContext)
{
  return cfunc_SessionRequestPauseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008977A0 (FUN_008977A0, func_SessionRequestPause_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionRequestPause`.
 */
moho::CScrLuaInitForm* moho::func_SessionRequestPause_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionRequestPause",
    &moho::cfunc_SessionRequestPause,
    nullptr,
    "<global>",
    kSessionRequestPauseHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897800 (FUN_00897800, cfunc_SessionRequestPauseL)
 *
 * What it does:
 * Requests world-session pause from Lua after validating active session.
 */
int moho::cfunc_SessionRequestPauseL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 0, kSessionRequestPauseHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionRequestPauseNoActiveSessionText);
  }

  session->RequestPause();
  return 0;
}

/**
 * Address: 0x00897850 (FUN_00897850, cfunc_SessionResume)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionResumeL`.
 */
int moho::cfunc_SessionResume(lua_State* const luaContext)
{
  return cfunc_SessionResumeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897870 (FUN_00897870, func_SessionResume_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionResume`.
 */
moho::CScrLuaInitForm* moho::func_SessionResume_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionResume",
    &moho::cfunc_SessionResume,
    nullptr,
    "<global>",
    kSessionResumeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008978D0 (FUN_008978D0, cfunc_SessionResumeL)
 *
 * What it does:
 * Requests world-session resume from Lua after validating active session.
 */
int moho::cfunc_SessionResumeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 0, kSessionResumeHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionResumeNoActiveSessionText);
  }

  session->Resume();
  return 0;
}

/**
 * Address: 0x00897920 (FUN_00897920, cfunc_SessionIsPaused)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsPausedL`.
 */
int moho::cfunc_SessionIsPaused(lua_State* const luaContext)
{
  return cfunc_SessionIsPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897940 (FUN_00897940, func_SessionIsPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsPaused`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionIsPaused",
    &moho::cfunc_SessionIsPaused,
    nullptr,
    "<global>",
    kSessionIsPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008979A0 (FUN_008979A0, cfunc_SessionIsPausedL)
 *
 * What it does:
 * Pushes pause state from replay/requested/non-local session lanes.
 */
int moho::cfunc_SessionIsPausedL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionIsPausedNoActiveSessionText);
  }

  std::uint8_t isPaused = 0;
  if (session->IsReplay) {
    isPaused = session->mReplayIsPaused;
  } else if (session->mRequestingPauseState != 0u) {
    isPaused = session->mRequestingPause;
  } else {
    isPaused = session->mSessionPauseStateA;
  }

  lua_pushboolean(state->m_state, isPaused != 0u ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897A00 (FUN_00897A00, cfunc_SessionIsGameOver)
 *
 * What it does:
 * Pushes whether the active world-session game-over flag is set.
 */
int moho::cfunc_SessionIsGameOver(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionIsGameOverNoActiveSessionText);
  }

  lua_pushboolean(state->m_state, session->IsGameOver != 0u ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897A50 (FUN_00897A50, func_SessionIsGameOver_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsGameOver`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsGameOver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionIsGameOver",
    &moho::cfunc_SessionIsGameOver,
    nullptr,
    "<global>",
    kSessionIsGameOverHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897C70 (FUN_00897C70, cfunc_SessionGetLocalCommandSource)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionGetLocalCommandSourceL`.
 */
int moho::cfunc_SessionGetLocalCommandSource(lua_State* const luaContext)
{
  return cfunc_SessionGetLocalCommandSourceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897C90 (FUN_00897C90, func_SessionGetLocalCommandSource_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionGetLocalCommandSource`.
 */
moho::CScrLuaInitForm* moho::func_SessionGetLocalCommandSource_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionGetLocalCommandSource",
    &moho::cfunc_SessionGetLocalCommandSource,
    nullptr,
    "<global>",
    kSessionGetLocalCommandSourceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897CF0 (FUN_00897CF0, cfunc_SessionGetLocalCommandSourceL)
 *
 * What it does:
 * Returns one-based local command-source id (`0` when unavailable).
 */
int moho::cfunc_SessionGetLocalCommandSourceL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kSessionGetLocalCommandSourceHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetLocalCommandSourceNoActiveSessionText);
  }

  int localCommandSource = session->ourCmdSource;
  if (localCommandSource == static_cast<int>(kInvalidCommandSource)) {
    localCommandSource = 0;
  } else {
    ++localCommandSource;
  }

  lua_pushnumber(rawState, static_cast<float>(localCommandSource));
  return 1;
}

/**
 * Address: 0x00897D70 (FUN_00897D70, cfunc_SessionIsReplayUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsReplayUserL`.
 */
int moho::cfunc_SessionIsReplayUser(lua_State* const luaContext)
{
  return cfunc_SessionIsReplayUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897D90 (FUN_00897D90, func_SessionIsReplayUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsReplay`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsReplayUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionIsReplay",
    &moho::cfunc_SessionIsReplayUser,
    nullptr,
    "<global>",
    kSessionIsReplayUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897DF0 (FUN_00897DF0, cfunc_SessionIsReplayUserL)
 *
 * What it does:
 * Pushes whether the active world-session is replay-backed.
 */
int moho::cfunc_SessionIsReplayUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kSessionIsReplayUserHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsReplay ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897E60 (FUN_00897E60, cfunc_SessionIsBeingRecorded)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionIsBeingRecordedL`.
 */
int moho::cfunc_SessionIsBeingRecorded(lua_State* const luaContext)
{
  return cfunc_SessionIsBeingRecordedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897E80 (FUN_00897E80, func_SessionIsBeingRecorded_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsBeingRecorded`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsBeingRecorded_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionIsBeingRecorded",
    &moho::cfunc_SessionIsBeingRecorded,
    nullptr,
    "<global>",
    kSessionIsBeingRecordedHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897EE0 (FUN_00897EE0, cfunc_SessionIsBeingRecordedL)
 *
 * What it does:
 * Pushes whether the active world-session is currently being recorded.
 */
int moho::cfunc_SessionIsBeingRecordedL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kSessionIsBeingRecordedHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsBeingRecorded ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897F50 (FUN_00897F50, cfunc_SessionIsMultiplayer)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsMultiplayerL`.
 */
int moho::cfunc_SessionIsMultiplayer(lua_State* const luaContext)
{
  return cfunc_SessionIsMultiplayerL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897F70 (FUN_00897F70, func_SessionIsMultiplayer_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsMultiplayer`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsMultiplayer_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionIsMultiplayer",
    &moho::cfunc_SessionIsMultiplayer,
    nullptr,
    "<global>",
    kSessionIsMultiplayerHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897FD0 (FUN_00897FD0, cfunc_SessionIsMultiplayerL)
 *
 * What it does:
 * Pushes whether the active world-session is multiplayer.
 */
int moho::cfunc_SessionIsMultiplayerL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kSessionIsMultiplayerHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsMultiplayer ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00898040 (FUN_00898040, cfunc_SessionIsObservingAllowed)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionIsObservingAllowedL`.
 */
int moho::cfunc_SessionIsObservingAllowed(lua_State* const luaContext)
{
  return cfunc_SessionIsObservingAllowedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898060 (FUN_00898060, func_SessionIsObservingAllowed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsObservingAllowed`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsObservingAllowed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionIsObservingAllowed",
    &moho::cfunc_SessionIsObservingAllowed,
    nullptr,
    "<global>",
    kSessionIsObservingAllowedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008980C0 (FUN_008980C0, cfunc_SessionIsObservingAllowedL)
 *
 * What it does:
 * Pushes whether observing is enabled for the active world-session.
 */
int moho::cfunc_SessionIsObservingAllowedL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kSessionIsObservingAllowedHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsObservingAllowed ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00898130 (FUN_00898130, cfunc_SessionCanRestart)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionCanRestartL`.
 */
int moho::cfunc_SessionCanRestart(lua_State* const luaContext)
{
  return cfunc_SessionCanRestartL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898150 (FUN_00898150, func_SessionCanRestart_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionCanRestart`.
 */
moho::CScrLuaInitForm* moho::func_SessionCanRestart_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionCanRestart",
    &moho::cfunc_SessionCanRestart,
    nullptr,
    "<global>",
    kSessionCanRestartHelpText
  );
  return &binder;
}

/**
 * Address: 0x008981B0 (FUN_008981B0, cfunc_SessionCanRestartL)
 *
 * What it does:
 * Pushes whether restart launch metadata exists for the active session.
 */
int moho::cfunc_SessionCanRestartL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kSessionCanRestartHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->mLaunchInfo.get() != nullptr ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00898220 (FUN_00898220, cfunc_SessionIsActive)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsActiveL`.
 */
int moho::cfunc_SessionIsActive(lua_State* const luaContext)
{
  return cfunc_SessionIsActiveL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898240 (FUN_00898240, func_SessionIsActive_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsActive`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsActive_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionIsActive",
    &moho::cfunc_SessionIsActive,
    nullptr,
    "<global>",
    kSessionIsActiveHelpText
  );
  return &binder;
}

/**
 * Address: 0x008982A0 (FUN_008982A0, cfunc_SessionIsActiveL)
 *
 * What it does:
 * Pushes whether any world-session is currently active.
 */
int moho::cfunc_SessionIsActiveL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kSessionIsActiveHelpText);

  lua_pushboolean(rawState, WLD_GetActiveSession() != nullptr ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008982F0 (FUN_008982F0, cfunc_SessionGetScenarioInfo)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionGetScenarioInfoL`.
 */
int moho::cfunc_SessionGetScenarioInfo(lua_State* const luaContext)
{
  return cfunc_SessionGetScenarioInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898310 (FUN_00898310, func_SessionGetScenarioInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionGetScenarioInfo`.
 */
moho::CScrLuaInitForm* moho::func_SessionGetScenarioInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionGetScenarioInfo",
    &moho::cfunc_SessionGetScenarioInfo,
    nullptr,
    "<global>",
    kSessionGetScenarioInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x00898370 (FUN_00898370, cfunc_SessionGetScenarioInfoL)
 *
 * What it does:
 * Validates user-lua state ownership and pushes the active session
 * `ScenarioInfo` table.
 */
int moho::cfunc_SessionGetScenarioInfoL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 0, kSessionGetScenarioInfoHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  if (state->m_rootState != session->mState) {
    LuaPlus::LuaState::Error(state, kWrongLuaStateText);
  }

  const LuaPlus::LuaObject scenarioInfo = session->GetScenarioInfo();
  scenarioInfo.PushStack(state);
  return 1;
}

/**
 * Address: 0x00898430 (FUN_00898430, cfunc_SessionEndGame)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionEndGameL`.
 */
int moho::cfunc_SessionEndGame(lua_State* const luaContext)
{
  return cfunc_SessionEndGameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898450 (FUN_00898450, func_SessionEndGame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionEndGame`.
 */
moho::CScrLuaInitForm* moho::func_SessionEndGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SessionEndGame",
    &moho::cfunc_SessionEndGame,
    nullptr,
    "<global>",
    kSessionEndGameHelpText
  );
  return &binder;
}

/**
 * Address: 0x008984B0 (FUN_008984B0, j_func_SessionEndGame)
 *
 * What it does:
 * Validates zero args, then disconnects every client from the active sim
 * driver. The world session is deliberately left alive - the help text spells
 * this out: play freezes, it is not torn down.
 *
 * In game version 3835's exe FAF's old desync fix has overwritten the first
 * nine bytes at 0x008984B0 with a `jmp` into `.exxt` (0x0128F9A0) + four
 * `nop`s, so IDA shows only the replacement - which wraps this same logic in
 * a quit handshake (a `WaitForSingleObject` of up to 9.5 s for the other
 * clients' acknowledgement, then zeroing its client table). FA-Binary-Patches
 * #173 (Remove old desync-fix code, 3840) removed it. The engine's own body is
 * still present in the image directly behind the patch, and it is what this
 * recovery follows:
 *
 *   0x008984B9  push eax / call lua_gettop / test eax,eax / jz 0x008984D8
 *   0x008984C6  push eax, 0, esi(help), "%s\n  expected %d args, but got %d",
 *               edi(state) -> LuaPlus::LuaState::Error
 *   0x008984D8  mov eax, sSimDriver ; test ; jnz 0x008984F1
 *   0x008984E3  push "no active session." / edi -> LuaState::Error
 *   0x008984F1  mov edx,[esi] / mov eax,[edx+4] / call eax
 *   0x008984F9  xor eax,eax / ret
 *
 * `[vtable+0x04]` is slot 1 on `ISTIDriver`, `DisconnectClients`.
 */
int moho::cfunc_SessionEndGameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 0, kSessionEndGameHelpText);

  ISTIDriver* const driver = WLD_GetDriver();
  if (driver == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
    return 0;
  }

  driver->DisconnectClients();
  return 0;
}

/**
 * Address: 0x008431D0 (FUN_008431D0, cfunc_GetGameTime)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetGameTimeL`.
 */
int moho::cfunc_GetGameTime(lua_State* const luaContext)
{
  return cfunc_GetGameTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008431F0 (FUN_008431F0, func_GetGameTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetGameTime`.
 */
moho::CScrLuaInitForm* moho::func_GetGameTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetGameTime",
    &moho::cfunc_GetGameTime,
    nullptr,
    "<global>",
    kGetGameTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843250 (FUN_00843250, cfunc_GetGameTimeL)
 *
 * What it does:
 * Formats active-session simulation time as `HH:MM:SS` and returns one Lua
 * string result.
 */
int moho::cfunc_GetGameTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetGameTimeHelpText);

  CWldSession* session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
    session = WLD_GetActiveSession();
    if (!session) {
      LuaPlus::LuaState::Error(state, kNoActiveSessionText);
    }
  }

  // 0x008432C6..0x008432DA: `fild tick; fadd timeSinceLastTick; fmul 0.1f`
  // (0x00E4F714 holds the float 0x3DCCCCCD), then __ftol2_sse.
  const int wholeSeconds = static_cast<int>((static_cast<float>(session->mGameTick) + session->mTimeSinceLastTick) * 0.1f);
  const auto signedSeconds = static_cast<long long>(wholeSeconds);
  const bool isNegative = signedSeconds < 0;
  const unsigned long long absoluteSeconds = isNegative
    ? static_cast<unsigned long long>(-(signedSeconds + 1)) + 1ULL
    : static_cast<unsigned long long>(signedSeconds);
  const int hours = static_cast<int>((absoluteSeconds / 3600ULL) % 24ULL);
  const int minutes = static_cast<int>((absoluteSeconds / 60ULL) % 60ULL);
  const int seconds = static_cast<int>(absoluteSeconds % 60ULL);

  char formatted[16]{};
  std::snprintf(
    formatted,
    sizeof(formatted),
    isNegative ? "-%02d:%02d:%02d" : "%02d:%02d:%02d",
    hours,
    minutes,
    seconds
  );

  lua_pushstring(rawState, formatted);
  return 1;
}

/**
 * Address: 0x00843380 (FUN_00843380, cfunc_GetGameTimeSecondsUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetGameTimeSecondsUserL`.
 */
int moho::cfunc_GetGameTimeSecondsUser(lua_State* const luaContext)
{
  return cfunc_GetGameTimeSecondsUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008433A0 (FUN_008433A0, func_GetGameTimeSecondsUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetGameTimeSeconds`.
 */
moho::CScrLuaInitForm* moho::func_GetGameTimeSecondsUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetGameTimeSeconds",
    &moho::cfunc_GetGameTimeSecondsUser,
    nullptr,
    "<global>",
    kGetGameTimeSecondsUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843400 (FUN_00843400, cfunc_GetGameTimeSecondsUserL)
 *
 * What it does:
 * Pushes active-session elapsed game time in seconds as a Lua number.
 */
int moho::cfunc_GetGameTimeSecondsUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetGameTimeSecondsUserHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  const float gameTimeSeconds = (static_cast<float>(session->mGameTick) + session->mTimeSinceLastTick) * 0.1f;
  lua_pushnumber(rawState, gameTimeSeconds);
  return 1;
}

/**
 * Address: 0x00843480 (FUN_00843480, cfunc_GetSystemTime)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSystemTimeL`.
 */
int moho::cfunc_GetSystemTime(lua_State* const luaContext)
{
  return cfunc_GetSystemTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008434A0 (FUN_008434A0, func_GetSystemTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSystemTime`.
 */
moho::CScrLuaInitForm* moho::func_GetSystemTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSystemTime",
    &moho::cfunc_GetSystemTime,
    nullptr,
    "<global>",
    kGetSystemTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843500 (FUN_00843500, cfunc_GetSystemTimeL)
 *
 * What it does:
 * Formats process-system elapsed seconds as `HH:MM:SS` and returns one Lua
 * string result.
 */
int moho::cfunc_GetSystemTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetSystemTimeHelpText);

  const auto totalSeconds = static_cast<long long>(gpg::time::GetSystemTimer().ElapsedSeconds());
  const bool isNegative = totalSeconds < 0;
  const unsigned long long absoluteSeconds = isNegative
    ? static_cast<unsigned long long>(-(totalSeconds + 1)) + 1ULL
    : static_cast<unsigned long long>(totalSeconds);
  const int hours = static_cast<int>((absoluteSeconds / 3600ULL) % 24ULL);
  const int minutes = static_cast<int>((absoluteSeconds / 60ULL) % 60ULL);
  const int seconds = static_cast<int>(absoluteSeconds % 60ULL);

  char formatted[16]{};
  std::snprintf(
    formatted,
    sizeof(formatted),
    isNegative ? "-%02d:%02d:%02d" : "%02d:%02d:%02d",
    hours,
    minutes,
    seconds
  );

  lua_pushstring(rawState, formatted);
  return 1;
}

/**
 * Address: 0x008435F4 (FUN_008435F4)
 * Address: 0x008365B4 (FUN_008365B4)
 *
 * What it does:
 * Normalizes Lua callback entry calling convention and forwards to
 * `cfunc_GetSystemTimeSecondsL`.
 */
static int cfunc_GetSystemTimeSecondsDispatch(lua_State* const luaContext)
{
  return moho::cfunc_GetSystemTimeSecondsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008435F0 (FUN_008435F0, cfunc_GetSystemTimeSeconds)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSystemTimeSecondsL`.
 */
int moho::cfunc_GetSystemTimeSeconds(lua_State* const luaContext)
{
  return cfunc_GetSystemTimeSecondsDispatch(luaContext);
}

/**
 * Address: 0x00843610 (FUN_00843610, func_GetSystemTimeSeconds_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSystemTimeSeconds`.
 */
moho::CScrLuaInitForm* moho::func_GetSystemTimeSeconds_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSystemTimeSeconds",
    &moho::cfunc_GetSystemTimeSeconds,
    nullptr,
    "<global>",
    kGetSystemTimeSecondsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843670 (FUN_00843670, cfunc_GetSystemTimeSecondsL)
 *
 * What it does:
 * Pushes process-system elapsed time in seconds as a Lua number.
 */
int moho::cfunc_GetSystemTimeSecondsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetSystemTimeSecondsHelpText);

  lua_pushnumber(rawState, gpg::time::GetSystemTimer().ElapsedSeconds());
  return 1;
}

/**
 * Address: 0x00843750 (FUN_00843750, cfunc_FormatTimeL)
 *
 * What it does:
 * Validates one numeric seconds argument and returns a formatted `HH:MM:SS`
 * text value for Lua scripts.
 */
int moho::cfunc_FormatTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kFormatTimeHelpText);

  if (!WLD_GetActiveSession()) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  LuaPlus::LuaStackObject secondsArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&secondsArg, "number");
  }

  const auto totalSeconds = static_cast<long long>(lua_tonumber(rawState, 1));
  const bool isNegative = totalSeconds < 0;
  const unsigned long long absoluteSeconds = isNegative
    ? static_cast<unsigned long long>(-(totalSeconds + 1)) + 1ULL
    : static_cast<unsigned long long>(totalSeconds);
  const int hours = static_cast<int>((absoluteSeconds / 3600ULL) % 24ULL);
  const int minutes = static_cast<int>((absoluteSeconds / 60ULL) % 60ULL);
  const int seconds = static_cast<int>(absoluteSeconds % 60ULL);

  char formatted[16]{};
  std::snprintf(
    formatted,
    sizeof(formatted),
    isNegative ? "-%02d:%02d:%02d" : "%02d:%02d:%02d",
    hours,
    minutes,
    seconds
  );

  lua_pushstring(rawState, formatted);
  return 1;
}

/**
 * Address: 0x008436D0 (FUN_008436D0, cfunc_FormatTime)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_FormatTimeL`.
 */
int moho::cfunc_FormatTime(lua_State* const luaContext)
{
  return cfunc_FormatTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008436F0 (FUN_008436F0, func_FormatTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `FormatTime`.
 */
moho::CScrLuaInitForm* moho::func_FormatTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "FormatTime",
    &moho::cfunc_FormatTime,
    nullptr,
    "<global>",
    kFormatTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008438A0 (FUN_008438A0, cfunc_GetSimRate)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSimRateL`.
 */
int moho::cfunc_GetSimRate(lua_State* const luaContext)
{
  return cfunc_GetSimRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008438C0 (FUN_008438C0, func_GetSimRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSimRate`.
 */
moho::CScrLuaInitForm* moho::func_GetSimRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSimRate",
    &moho::cfunc_GetSimRate,
    nullptr,
    "<global>",
    kGetSimRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843920 (FUN_00843920, cfunc_GetSimRateL)
 *
 * What it does:
 * Pushes the current client-manager simulation rate as a Lua number.
 */
int moho::cfunc_GetSimRateL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetSimRateHelpText);

  if (!WLD_GetActiveSession()) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  ISTIDriver* const activeDriver = WLD_GetDriver();
  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
  lua_pushnumber(rawState, static_cast<float>(clientManager->GetSimRate()));
  return 1;
}
/**
 * Engine addition (replay timeline): the viewer's bar, `/lua/ui/game/replay_timeline.lua`.
 */
namespace
{
  template <int (*Body)(lua_State*)>
  int ReplayTimelineBinding(lua_State* const luaContext)
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    return state != nullptr && state->m_state != nullptr ? Body(state->m_state) : 0;
  }

  int ReplayTotalTicksBody(lua_State* const rawState)
  {
    lua_pushnumber(rawState, static_cast<lua_Number>(moho::REPLAY_TotalTicks()));
    return 1;
  }

  int ReplayKeyframeTicksBody(lua_State* const rawState)
  {
    const std::vector<std::int32_t> ticks = moho::REPLAY_KeyframeTicks();
    lua_newtable(rawState);
    int index = 1;
    for (const std::int32_t tick : ticks) {
      lua_pushnumber(rawState, static_cast<lua_Number>(index));
      lua_pushnumber(rawState, static_cast<lua_Number>(tick));
      lua_rawset(rawState, -3);
      ++index;
    }
    return 1;
  }

  int ReplaySeekBody(lua_State* const rawState)
  {
    moho::CWldSession* const session = moho::WLD_GetActiveSession();
    if (session != nullptr && lua_isnumber(rawState, 1)) {
      moho::REPLAY_SeekTo(*session, static_cast<std::int32_t>(lua_tonumber(rawState, 1)));
    }
    return 0;
  }

  int ReplaySeekKindBody(lua_State* const rawState)
  {
    moho::CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr || !lua_isnumber(rawState, 1)) {
      lua_pushnil(rawState);
      return 1;
    }
    switch (moho::REPLAY_SeekKind(*session, static_cast<std::int32_t>(lua_tonumber(rawState, 1)))) {
    case moho::EReplaySeekKind::LoadKeyframe:
      lua_pushstring(rawState, "load");
      break;
    case moho::EReplaySeekKind::PlayForward:
      lua_pushstring(rawState, "play");
      break;
    default:
      lua_pushnil(rawState);
      break;
    }
    return 1;
  }

  int ReplayCancelSeekBody(lua_State* const)
  {
    moho::REPLAY_CancelSeek();
    return 0;
  }

  int ReplaySeekProgressBody(lua_State* const rawState)
  {
    moho::CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr || !moho::REPLAY_IsSeeking()) {
      lua_pushnil(rawState);
      return 1;
    }
    const moho::SReplaySeekProgress progress = moho::REPLAY_SeekProgress(*session);
    lua_newtable(rawState);
    lua_pushstring(rawState, "targetTick");
    lua_pushnumber(rawState, static_cast<lua_Number>(progress.targetTick));
    lua_rawset(rawState, -3);
    lua_pushstring(rawState, "currentTick");
    lua_pushnumber(rawState, static_cast<lua_Number>(progress.currentTick));
    lua_rawset(rawState, -3);
    lua_pushstring(rawState, "progress");
    lua_pushnumber(rawState, static_cast<lua_Number>(progress.progress));
    lua_rawset(rawState, -3);
    lua_pushstring(rawState, "restarting");
    lua_pushboolean(rawState, progress.restarting ? 1 : 0);
    lua_rawset(rawState, -3);
    return 1;
  }

  /**
   * Engine addition (issue #327): `GetEngineInfo()` - which engine runs the UI. FAF's own Lua carries
   * faf-re's options and screens behind `if rawget(_G, 'GetEngineInfo') then`, so on the original
   * executable, which has no such function, nothing changes. Name is always "faf-re"; Version is the
   * release or nightly tag (or the short commit of any other build), Commit the short commit.
   */
  int GetEngineInfoBody(lua_State* const rawState)
  {
    lua_newtable(rawState);
    lua_pushstring(rawState, "Name");
    lua_pushstring(rawState, "faf-re");
    lua_rawset(rawState, -3);
    lua_pushstring(rawState, "Version");
    lua_pushstring(rawState, gpg::diag::BuildVersion());
    lua_rawset(rawState, -3);
    lua_pushstring(rawState, "Commit");
    lua_pushstring(rawState, gpg::diag::BuildCommitShort());
    lua_rawset(rawState, -3);
    return 1;
  }

  void RegisterReplayTimelineBindings()
  {
    static CScrLuaBinder engineInfo(moho::SCR_UserLuaInitSet(), "GetEngineInfo", &ReplayTimelineBinding<&GetEngineInfoBody>, nullptr, "<global>",
      "table GetEngineInfo() - the engine running the UI: Name 'faf-re', Version (release or nightly tag), Commit. Absent on the original executable.");
    static CScrLuaBinder total(moho::SCR_UserLuaInitSet(), "GetReplayTotalTicks", &ReplayTimelineBinding<&ReplayTotalTicksBody>, nullptr, "<global>",
      "int GetReplayTotalTicks() - the replay's length in ticks; 0 when not known.");
    static CScrLuaBinder keyframes(moho::SCR_UserLuaInitSet(), "GetReplayKeyframeTicks", &ReplayTimelineBinding<&ReplayKeyframeTicksBody>, nullptr, "<global>",
      "table GetReplayKeyframeTicks() - the ticks with a keyframe to move back to, in order.");
    static CScrLuaBinder seek(moho::SCR_UserLuaInitSet(), "ReplaySeek", &ReplayTimelineBinding<&ReplaySeekBody>, nullptr, "<global>",
      "ReplaySeek(tick) - moves the replay to a tick, either way, keeping the view.");
    static CScrLuaBinder seekKind(moho::SCR_UserLuaInitSet(), "ReplaySeekKind", &ReplayTimelineBinding<&ReplaySeekKindBody>, nullptr, "<global>",
      "string ReplaySeekKind(tick) - what ReplaySeek(tick) would do now: 'load' a keyframe or 'play' forward; nil when nothing or not known yet.");
    static CScrLuaBinder cancel(moho::SCR_UserLuaInitSet(), "ReplayCancelSeek", &ReplayTimelineBinding<&ReplayCancelSeekBody>, nullptr, "<global>",
      "ReplayCancelSeek() - stops a seek where it is.");
    static CScrLuaBinder progress(moho::SCR_UserLuaInitSet(), "ReplaySeekProgress", &ReplayTimelineBinding<&ReplaySeekProgressBody>, nullptr, "<global>",
      "table ReplaySeekProgress() - targetTick, currentTick, progress, restarting; nil when not seeking.");
  }
} // namespace

namespace
{
  /**
   * Engine addition (dedicated-server plan WPL.4): drives this file's Lua binder
   * definitions, the calls Sim.cpp's SimLuaFuncDefBootstrap made for them, in
   * the same order (see that object for why a bootstrap is needed).
   */
  struct UserLuaFuncDefBootstrap
  {
    UserLuaFuncDefBootstrap()
    {
      RegisterReplayTimelineBindings();
      (void)::moho::func_ParseEntityCategoryUser_LuaFuncDef();
      (void)::moho::func_GetUnitCommandFromCommandCap_LuaFuncDef();
      (void)::moho::func_EjectSessionClient_LuaFuncDef();
      (void)::moho::func_WorldIsLoading_LuaFuncDef();
      (void)::moho::func_WorldIsPlaying_LuaFuncDef();
      (void)::moho::func_GetGameSpeed_LuaFuncDef();
      (void)::moho::func_SetGameSpeed_LuaFuncDef();
      (void)::moho::func_AddToSessionExtraSelectList_LuaFuncDef();
      (void)::moho::func_RemoveFromSessionExtraSelectList_LuaFuncDef();
      (void)::moho::func_ClearSessionExtraSelectList_LuaFuncDef();
      (void)::moho::func_CurrentTime_LuaFuncDef();
      (void)::moho::func_GameTime_LuaFuncDef();
      (void)::moho::func_GameTick_LuaFuncDef();
      (void)::moho::func_IsAllyUser_LuaFuncDef();
      (void)::moho::func_IsEnemyUser_LuaFuncDef();
      (void)::moho::func_IsNeutral_LuaFuncDef();
      (void)::moho::func_SyncPlayableRect_LuaFuncDef();
      (void)::moho::func_RandomUser_LuaFuncDef();
      (void)::moho::func_EntityCategoryContainsUser_LuaFuncDef();
      (void)::moho::func_EntityCategoryFilterDownUser_LuaFuncDef();
      (void)::moho::func_EntityCategoryFilterOut_LuaFuncDef();
      (void)::moho::func_ExecLuaInSim_LuaFuncDef();
      (void)::moho::func_SimCallback_LuaFuncDef();
      (void)::moho::func_SetAutoMode_LuaFuncDef();
      (void)::moho::func_SetAutoSurfaceMode_LuaFuncDef();
      (void)::moho::func_ToggleScriptBit_LuaFuncDef();
      (void)::moho::func_SetPaused_LuaFuncDef();
      (void)::moho::func_GetAttachedUnitsList_LuaFuncDef();
      (void)::moho::func_ValidateUnitsList_LuaFuncDef();
      (void)::moho::func_GetAssistingUnitsList_LuaFuncDef();
      (void)::moho::func_GetArmyAvatars_LuaFuncDef();
      (void)::moho::func_GetIdleEngineers_LuaFuncDef();
      (void)::moho::func_GetIdleFactories_LuaFuncDef();
      (void)::moho::func_GetSelectedUnits_LuaFuncDef();
      (void)::moho::func_GetValidAttackingUnits_LuaFuncDef();
      (void)::moho::func_SelectUnits_LuaFuncDef();
      (void)::moho::func_AddSelectUnits_LuaFuncDef();
      (void)::moho::func_EngineStartSplashScreens_LuaFuncDef();
      (void)::moho::func_EngineStartFrontEndUI_LuaFuncDef();
      (void)::moho::func_ExitApplication_LuaFuncDef();
      (void)::moho::func_ExitGame_LuaFuncDef();
      (void)::moho::func_RestartSession_LuaFuncDef();
      (void)::moho::func_GetFrame_LuaFuncDef();
      (void)::moho::func_ClearFrame_LuaFuncDef();
      (void)::moho::func_GetNumRootFrames_LuaFuncDef();
      (void)::moho::func_GetEconomyTotals_LuaFuncDef();
      (void)::moho::func_GetResourceSharing_LuaFuncDef();
      (void)::moho::func_GetCurrentUIState_LuaFuncDef();
      (void)::moho::func_GetSimTicksPerSecond_LuaFuncDef();
      (void)::moho::func_SessionRequestPause_LuaFuncDef();
      (void)::moho::func_SessionResume_LuaFuncDef();
      (void)::moho::func_SessionIsPaused_LuaFuncDef();
      (void)::moho::func_SessionIsGameOver_LuaFuncDef();
      (void)::moho::func_SessionGetLocalCommandSource_LuaFuncDef();
      (void)::moho::func_SessionIsReplayUser_LuaFuncDef();
      (void)::moho::func_SessionIsBeingRecorded_LuaFuncDef();
      (void)::moho::func_SessionIsMultiplayer_LuaFuncDef();
      (void)::moho::func_SessionIsObservingAllowed_LuaFuncDef();
      (void)::moho::func_SessionCanRestart_LuaFuncDef();
      (void)::moho::func_SessionIsActive_LuaFuncDef();
      (void)::moho::func_SessionGetScenarioInfo_LuaFuncDef();
      (void)::moho::func_SessionEndGame_LuaFuncDef();
      (void)::moho::func_GetMouseWorldPosUser_LuaFuncDef();
      (void)::moho::func_GetMouseScreenPos_LuaFuncDef();
      (void)::moho::func_CopyToClipboard_LuaFuncDef();
      (void)::moho::func_GetTimeForProfileUser_LuaFuncDef();
      (void)::moho::func_GetDepositsAroundPointUser_LuaFuncDef();
      (void)::moho::func_GetHighlightCommand_LuaFuncDef();
      (void)::moho::func_SetFocusArmyUser_LuaFuncDef();
      (void)::moho::func_SetInvertMidMouseButton_LuaFuncDef();
      (void)::moho::func_GetFocusArmyUser_LuaFuncDef();
      (void)::moho::func_IsObserver_LuaFuncDef();
      (void)::moho::func_GetGameTime_LuaFuncDef();
      (void)::moho::func_GetGameTimeSecondsUser_LuaFuncDef();
      (void)::moho::func_GetSystemTime_LuaFuncDef();
      (void)::moho::func_GetSystemTimeSeconds_LuaFuncDef();
      (void)::moho::func_FormatTime_LuaFuncDef();
      (void)::moho::func_GetSimRate_LuaFuncDef();
      (void)::moho::func_GetArmiesTable_LuaFuncDef();
      (void)::moho::func_GetArmyScore_LuaFuncDef();
      (void)::moho::func_DeleteCommand_LuaFuncDef();
      (void)::moho::func_GetSpecialFiles_LuaFuncDef();
      (void)::moho::func_GetSpecialFilePath_LuaFuncDef();
      (void)::moho::func_GetSpecialFolder_LuaFuncDef();
      (void)::moho::func_RemoveSpecialFile_LuaFuncDef();
      (void)::moho::func_GetSpecialFileInfo_LuaFuncDef();
      (void)::moho::func_RemoveProfileDirectories_LuaFuncDef();
      (void)::moho::func_CopyCurrentReplay_LuaFuncDef();
      (void)::moho::func_SetOverlayFilters_LuaFuncDef();
      (void)::moho::func_GenerateBuildTemplateFromSelection_LuaFuncDef();
      (void)::moho::func_ClearBuildTemplates_LuaFuncDef();
      (void)::moho::func_RenderOverlayMilitary_LuaFuncDef();
      (void)::moho::func_RenderOverlayIntel_LuaFuncDef();
      (void)::moho::func_RenderOverlayEconomy_LuaFuncDef();
      (void)::moho::func_TeamColorMode_LuaFuncDef();
      (void)::moho::func_GetUnitByIdUser_LuaFuncDef();
      (void)::moho::func_CreateUnitAtMouse_LuaFuncDef();
      (void)::moho::func_AudioSetLanguageUser_LuaFuncDef();
      (void)::moho::func_HasLocalizedVOUser_LuaFuncDef();
    }
  };

  const UserLuaFuncDefBootstrap gUserLuaFuncDefBootstrap{};
}

