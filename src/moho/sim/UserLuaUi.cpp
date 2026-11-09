#include "moho/sim/UserLuaPrivate.h"

namespace
{
  /**
   * Address: 0x008ADF40 (FUN_008ADF40, func_GetVoiceDir)
   *
   * What it does:
   * Checks whether `/sounds/voice/<language>` exists in the mounted virtual
   * file-system lane.
   */
  [[nodiscard]] bool HasLocalizedVoiceDirectory(const fa::string& language)
  {
    const fa::string voiceDirectory = gpg::STR_Printf("/sounds/voice/%s", language.c_str());
    return FILE_GetFileInfo(voiceDirectory.c_str(), nullptr, false);
  }
  constexpr const char* kAudioSetLanguageUserHelpText = "AudioSetLanguage(name)";
  constexpr const char* kClearFrameHelpText =
    "ClearFrame(int head) - destroy all controls in frame, nil head will clear all frames";
  constexpr const char* kEngineStartFrontEndUIHelpText =
    "EngineStartFrontEndUI() - kill current UI and start main menu from top";
  constexpr const char* kEngineStartSplashScreensHelpText =
    "EngineStartSplashScreens() - kill current UI and start splash screens";
  constexpr const char* kExitApplicationHelpText = "ExitApplication - request that the application shut down";
  constexpr const char* kGetCurrentUIStateHelpText =
    "state GetCurrentUIState() - returns 'splash', 'frontend' or 'game' depending on the current state of the ui";
  constexpr const char* kGetFrameHelpText = "frame GetFrame(int head) - return the root UI frame for a given head";
  constexpr const char* kGetMouseScreenPosHelpText = "vector GetMouseScreenPos()";
  constexpr const char* kGetMouseWorldPosUserHelpText = "vector GetMouseWorldPos()";
  constexpr const char* kGetNumRootFramesHelpText =
    "int GetNumRootFrames() - returns the current number of root frames (typically one per head";
  constexpr const char* kHasLocalizedVOUserHelpText = "HasLocalizedVO(languageCode)";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaInvalidBoolWarning = "%s\n  invalid argument %d, use as boolean";
  constexpr const char* kRenderOverlayEconomyHelpText = "RenderOverlayEconomy(bool)";
  constexpr const char* kRenderOverlayIntelHelpText = "RenderOverlayIntel(bool)";
  constexpr const char* kRenderOverlayMilitaryHelpText = "RenderOverlayMilitary(bool)";
  constexpr const char* kSetInvertMidMouseButtonHelpText = "SetInvertMidMouseButton";
  constexpr const char* kSetOverlayFiltersHelpText = "SetOverlayFilters(list)";
  constexpr const char* kTeamColorModeHelpText = "TeamColorMode(bool)";

  // Help texts of the sim functions the user state registers too (moho/sim/Sim.cpp).
  constexpr const char* kGetTimeForProfileHelpText = "(OriginTime)";
  constexpr const char* kGetDepositsAroundPointHelpText = "(X, Z, Radius, Type)";

  /**
   * FA-Binary-Patches section/TeamColorMode.cpp (`TeamColorMode` stub): reads
   * hex colours separated by any non-hex character ("ffrrggbb,ffrrggbb,...")
   * into `teamcolors` from slot 0; slots the text does not reach keep their
   * values. The stub steps past the terminator after the last colour and keeps
   * parsing whatever follows the string, and has no slot limit; this stops at
   * the terminator and after the palette's 32 slots.
   */
  void ParseTeamColorPalette(const char* const text)
  {
    const char* cursor = text;
    for (std::size_t slot = 0; *cursor != '\0' && slot < moho::kTeamColorPaletteSize; ++slot) {
      std::uint32_t color = 0u;
      for (;; ++cursor) {
        const char c = *cursor;
        std::uint32_t digit = 0u;
        if (c >= '0' && c <= '9') {
          digit = static_cast<std::uint32_t>(c - '0');
        } else if (c >= 'A' && c <= 'F') {
          digit = static_cast<std::uint32_t>(c - 'A' + 10);
        } else if (c >= 'a' && c <= 'f') {
          digit = static_cast<std::uint32_t>(c - 'a' + 10);
        } else {
          break;
        }
        color = (color << 4) + digit;
      }
      moho::teamcolors[slot] = color;
      if (*cursor == '\0') {
        break;
      }
      ++cursor;
    }
  }
  constexpr const char* kUiLayerNotInitializedText = "UI layer has not been initialized.";
}


/**
 * Address: 0x0083F000 (FUN_0083F000, func_EngineStartSplashScreens)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and starts splash-screen UI.
 */
int moho::func_EngineStartSplashScreens(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  moho::SCR_ExpectExactArgs(state, 0, kEngineStartSplashScreensHelpText);

  (void)UI_StartSplashScreens();
  return 0;
}

/**
 * Address: 0x0083F040 (FUN_0083F040, func_EngineStartSplashScreens_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EngineStartSplashScreens`.
 */
moho::CScrLuaInitForm* moho::func_EngineStartSplashScreens_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "EngineStartSplashScreens",
    &moho::func_EngineStartSplashScreens,
    nullptr,
    "<global>",
    kEngineStartSplashScreensHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F0E0 (FUN_0083F0E0, cfunc_EngineStartFrontEndUI)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and starts front-end UI.
 */
int moho::cfunc_EngineStartFrontEndUI(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  moho::SCR_ExpectExactArgs(state, 0, kEngineStartFrontEndUIHelpText);

  (void)UI_StartFrontEnd();
  return 0;
}

/**
 * Address: 0x0083F120 (FUN_0083F120, func_EngineStartFrontEndUI_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EngineStartFrontEndUI`.
 */
moho::CScrLuaInitForm* moho::func_EngineStartFrontEndUI_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "EngineStartFrontEndUI",
    &moho::cfunc_EngineStartFrontEndUI,
    nullptr,
    "<global>",
    kEngineStartFrontEndUIHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F1C0 (FUN_0083F1C0, cfunc_ExitApplication)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and requests app shutdown.
 */
int moho::cfunc_ExitApplication(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  moho::SCR_ExpectExactArgs(state, 0, kExitApplicationHelpText);

  wxTheApp->ExitMainLoop();
  return 0;
}

/**
 * Address: 0x0083F210 (FUN_0083F210, func_ExitApplication_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ExitApplication`.
 */
moho::CScrLuaInitForm* moho::func_ExitApplication_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ExitApplication",
    &moho::cfunc_ExitApplication,
    nullptr,
    "<global>",
    kExitApplicationHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F470 (FUN_0083F470, cfunc_GetFrame)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetFrameL`.
 */
int moho::cfunc_GetFrame(lua_State* const luaContext)
{
  return cfunc_GetFrameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F490 (FUN_0083F490, func_GetFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetFrame`.
 */
moho::CScrLuaInitForm* moho::func_GetFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetFrame",
    &moho::cfunc_GetFrame,
    nullptr,
    "<global>",
    kGetFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F4F0 (FUN_0083F4F0, cfunc_GetFrameL)
 *
 * What it does:
 * Resolves one root UI frame index and pushes the corresponding Lua frame
 * object when it belongs to the same root Lua state.
 */
int moho::cfunc_GetFrameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetFrameHelpText);

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager == nullptr || !uiManager->HasFrames()) {
    LuaPlus::LuaState::Error(state, kUiLayerNotInitializedText);
    return 1;
  }

  LuaPlus::LuaStackObject headArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    headArg.TypeError("number");
  }

  const int frameHead = static_cast<int>(lua_tonumber(rawState, 1));
  if (frameHead < 0 || static_cast<std::size_t>(frameHead) >= uiManager->mFrames.Size()) {
    return 0;
  }

  CMauiFrame* const frame = uiManager->mFrames[static_cast<std::size_t>(frameHead)].get();
  if (frame == nullptr) {
    return 0;
  }

  if (frame->mLuaObj.m_state != state->m_rootState) {
    return 0;
  }

  frame->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0083F5D0 (FUN_0083F5D0, cfunc_ClearFrame)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_ClearFrameL`.
 */
int moho::cfunc_ClearFrame(lua_State* const luaContext)
{
  return cfunc_ClearFrameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F5F0 (FUN_0083F5F0, func_ClearFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ClearFrame`.
 */
moho::CScrLuaInitForm* moho::func_ClearFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ClearFrame",
    &moho::cfunc_ClearFrame,
    nullptr,
    "<global>",
    kClearFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F650 (FUN_0083F650, cfunc_ClearFrameL)
 *
 * What it does:
 * Clears one frame by index or all frames when the optional argument is nil.
 */
int moho::cfunc_ClearFrameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount >= 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kClearFrameHelpText,
      0,
      1,
      argumentCount
    );
  }

  lua_settop(rawState, 1);

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager == nullptr || !uiManager->HasFrames()) {
    LuaPlus::LuaState::Error(state, kUiLayerNotInitializedText);
    return 0;
  }

  int frameHead = -1;
  if (lua_type(rawState, 1) != LUA_TNIL) {
    LuaPlus::LuaStackObject headArg(state, 1);
    frameHead = static_cast<int>(headArg.ToNumber());
  }

  uiManager->ClearChildren(frameHead);
  return 0;
}

/**
 * Address: 0x0083F700 (FUN_0083F700, cfunc_GetNumRootFrames)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetNumRootFramesL`.
 */
int moho::cfunc_GetNumRootFrames(lua_State* const luaContext)
{
  return cfunc_GetNumRootFramesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F720 (FUN_0083F720, func_GetNumRootFrames_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetNumRootFrames`.
 */
moho::CScrLuaInitForm* moho::func_GetNumRootFrames_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetNumRootFrames",
    &moho::cfunc_GetNumRootFrames,
    nullptr,
    "<global>",
    kGetNumRootFramesHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F780 (FUN_0083F780, cfunc_GetNumRootFramesL)
 *
 * What it does:
 * Pushes the current root-frame count as a Lua number.
 */
int moho::cfunc_GetNumRootFramesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetNumRootFramesHelpText);

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager != nullptr && uiManager->HasFrames()) {
    lua_pushnumber(rawState, static_cast<float>(uiManager->mFrames.Size()));
    (void)lua_gettop(rawState);
  } else {
    LuaPlus::LuaState::Error(state, kUiLayerNotInitializedText);
  }

  return 1;
}

/**
 * Address: 0x008420A0 (FUN_008420A0, cfunc_GetCurrentUIState)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetCurrentUIStateL`.
 */
int moho::cfunc_GetCurrentUIState(lua_State* const luaContext)
{
  return cfunc_GetCurrentUIStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008420C0 (FUN_008420C0, func_GetCurrentUIState_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetCurrentUIState`.
 */
moho::CScrLuaInitForm* moho::func_GetCurrentUIState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetCurrentUIState",
    &moho::cfunc_GetCurrentUIState,
    nullptr,
    "<global>",
    kGetCurrentUIStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842120 (FUN_00842120, cfunc_GetCurrentUIStateL)
 *
 * What it does:
 * Pushes current UI-state lexical value (`splash`, `frontend`, or `game`).
 */
int moho::cfunc_GetCurrentUIStateL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetCurrentUIStateHelpText);

  gpg::RRef currentUiStateRef{};
  gpg::RRef::CurrentUIState(&currentUiStateRef);
  const fa::string lexical = currentUiStateRef.GetLexical();
  lua_pushstring(rawState, lexical.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00842BD0 (FUN_00842BD0, func_GetMouseWorldPosUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetMouseWorldPos`.
 */
moho::CScrLuaInitForm* moho::func_GetMouseWorldPosUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetMouseWorldPos",
    &moho::cfunc_GetMouseWorldPos,
    nullptr,
    "<global>",
    kGetMouseWorldPosUserHelpText
  );
  return &binder;
}

/**
 * What it does:
 * Publishes the user-lane Lua binder definition for global
 * `GetTimeForProfile`, the same body as the sim one (section/GetTimeForProfile.cpp
 * registers both; the name string 0x01293D36 is referenced from 0x012924BE and
 * 0x0129251D).
 */
moho::CScrLuaInitForm* moho::func_GetTimeForProfileUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetTimeForProfile",
    &moho::cfunc_GetTimeForProfileSim,
    nullptr,
    "<global>",
    kGetTimeForProfileHelpText
  );
  return &binder;
}

/**
 * What it does:
 * Publishes the user-lane Lua binder definition for global
 * `GetDepositsAroundPoint` (section/SimGetDepositsAroundPoint.cpp `UIRegFunc
 * SGDAPRegDesc`).
 */
moho::CScrLuaInitForm* moho::func_GetDepositsAroundPointUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetDepositsAroundPoint",
    &moho::cfunc_GetDepositsAroundPointUser,
    nullptr,
    "<global>",
    kGetDepositsAroundPointHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842D10 (FUN_00842D10, cfunc_GetMouseScreenPos)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetMouseScreenPosL`.
 */
int moho::cfunc_GetMouseScreenPos(lua_State* const luaContext)
{
  return cfunc_GetMouseScreenPosL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842D30 (FUN_00842D30, func_GetMouseScreenPos_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetMouseScreenPos`.
 */
moho::CScrLuaInitForm* moho::func_GetMouseScreenPos_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetMouseScreenPos",
    &moho::cfunc_GetMouseScreenPos,
    nullptr,
    "<global>",
    kGetMouseScreenPosHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842D90 (FUN_00842D90, cfunc_GetMouseScreenPosL)
 *
 * What it does:
 * Pushes current screen-space mouse position as one Lua vector.
 */
int moho::cfunc_GetMouseScreenPosL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 0, kGetMouseScreenPosHelpText);

  const CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  const LuaPlus::LuaObject screenPositionObject = SCR_ToLua<Wm3::Vector2<float>>(state, session->CursorScreenPos);
  screenPositionObject.PushStack(state);
  return 1;
}

/**
 * FAF FA-Binary-Patches (section/CopyToClipBoard.cpp, LuaCopyToClipboard):
 * `CopyToClipboard(val):bool`.
 *
 * What it does:
 * Puts the one argument, as a string read as UTF-8, on the Windows clipboard
 * through `WIN_CopyToClipboard` (0x004F2730) and returns whether that worked.
 * Any other argument count raises the engine's "expected 1 args" error under
 * the patch's own function name.
 */
int moho::cfunc_CopyToClipboard(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = SCR_ResolveBindingState(luaContext);
  const int argumentCount = lua_gettop(luaContext);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, "LuaCopyToClipboard", 1, argumentCount);
  }

  // The patch converts `lua_tostring` with `wstring(const char*)`, i.e.
  // `gpg::STR_Utf8ToWide` (0x00938720). A non-string argument (nil) copies
  // the empty string here instead of handing that conversion a null pointer.
  const char* const text = lua_tostring(luaContext, 1);
  const std::wstring wideText = gpg::STR_Utf8ToWide(text != nullptr ? text : "");
  lua_pushboolean(luaContext, WIN_CopyToClipboard(wideText.c_str()) ? 1 : 0);
  return 1;
}

moho::CScrLuaInitForm* moho::func_CopyToClipboard_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "CopyToClipboard",
    &moho::cfunc_CopyToClipboard,
    nullptr,
    "<global>",
    "CopyToClipboard(val):bool"
  );
  return &binder;
}

/**
 * Address: 0x00846F70 (FUN_00846F70, cfunc_SetOverlayFilters)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetOverlayFiltersL`.
 */
int moho::cfunc_SetOverlayFilters(lua_State* const luaContext)
{
  return cfunc_SetOverlayFiltersL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846F90 (FUN_00846F90, func_SetOverlayFilters_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetOverlayFilters`.
 */
moho::CScrLuaInitForm* moho::func_SetOverlayFilters_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetOverlayFilters",
    &moho::cfunc_SetOverlayFilters,
    nullptr,
    "<global>",
    kSetOverlayFiltersHelpText
  );
  return &binder;
}

/**
 * Address: 0x00846FF0 (FUN_00846FF0, cfunc_SetOverlayFiltersL)
 *
 * What it does:
 * Reads one Lua table of overlay filter strings and replaces
 * `CWldSession::mOverlayFilters`.
 */
int moho::cfunc_SetOverlayFiltersL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kSetOverlayFiltersHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return 0;
  }

  LuaPlus::LuaObject filterTable(LuaPlus::LuaStackObject(state, 1));
  if (!filterTable.IsTable()) {
    return 0;
  }

  fa::vector<fa::string> parsedFilters{};
  for (LuaPlus::LuaTableIterator iter(&filterTable, 1); !iter.m_isDone; iter.Next()) {
    LuaPlus::LuaObject filterValue = iter.GetValue();
    const char* const filterText = filterValue.GetString();
    parsedFilters.push_back(fa::string(filterText, std::strlen(filterText)));
  }

  session->mOverlayFilters = std::move(parsedFilters);
  return 0;
}

/**
 * Address: 0x00847AD0 (FUN_00847AD0, cfunc_RenderOverlayMilitary)
 *
 * What it does:
 * Retains legacy `RenderOverlayMilitary(bool)` argument validation and emits a
 * deprecation warning.
 */
int moho::cfunc_RenderOverlayMilitary(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  moho::SCR_ExpectExactArgs(state, 1, kRenderOverlayMilitaryHelpText);
  gpg::Warnf("RenderOverlayMilitary is deprecated");
  return 0;
}

/**
 * Address: 0x00847B20 (FUN_00847B20, func_RenderOverlayMilitary_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `RenderOverlayMilitary`.
 */
moho::CScrLuaInitForm* moho::func_RenderOverlayMilitary_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "RenderOverlayMilitary",
    &moho::cfunc_RenderOverlayMilitary,
    nullptr,
    "<global>",
    kRenderOverlayMilitaryHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847BC0 (FUN_00847BC0, cfunc_RenderOverlayIntel)
 *
 * What it does:
 * Retains legacy `RenderOverlayIntel(bool)` argument validation and emits a
 * deprecation warning.
 */
int moho::cfunc_RenderOverlayIntel(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  moho::SCR_ExpectExactArgs(state, 1, kRenderOverlayIntelHelpText);
  gpg::Warnf("RenderOverlayIntel is deprecated");
  return 0;
}

/**
 * Address: 0x00847C10 (FUN_00847C10, func_RenderOverlayIntel_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `RenderOverlayIntel`.
 */
moho::CScrLuaInitForm* moho::func_RenderOverlayIntel_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "RenderOverlayIntel",
    &moho::cfunc_RenderOverlayIntel,
    nullptr,
    "<global>",
    kRenderOverlayIntelHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847CB0 (FUN_00847CB0, cfunc_RenderOverlayEconomy)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_RenderOverlayEconomyL`.
 */
int moho::cfunc_RenderOverlayEconomy(lua_State* const luaContext)
{
  return cfunc_RenderOverlayEconomyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00847CD0 (FUN_00847CD0, func_RenderOverlayEconomy_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for
 * `RenderOverlayEconomy`.
 */
moho::CScrLuaInitForm* moho::func_RenderOverlayEconomy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "RenderOverlayEconomy",
    &moho::cfunc_RenderOverlayEconomy,
    nullptr,
    "<global>",
    kRenderOverlayEconomyHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847D30 (FUN_00847D30, cfunc_RenderOverlayEconomyL)
 *
 * What it does:
 * Reads one Lua bool and updates the active user session economy-overlay flag.
 */
int moho::cfunc_RenderOverlayEconomyL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kRenderOverlayEconomyHelpText);

  if (CWldSession* const session = WLD_GetActiveSession()) {
    const LuaPlus::LuaStackObject enabledArg(state, 1);
    session->DisplayEconomyOverlay = enabledArg.GetBoolean();
  }
  return 0;
}

/**
 * Address: 0x00847D90 (FUN_00847D90, cfunc_TeamColorMode)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_TeamColorModeL`.
 */
int moho::cfunc_TeamColorMode(lua_State* const luaContext)
{
  return cfunc_TeamColorModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00847DB0 (FUN_00847DB0, func_TeamColorMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `TeamColorMode`.
 */
moho::CScrLuaInitForm* moho::func_TeamColorMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "TeamColorMode",
    &moho::cfunc_TeamColorMode,
    nullptr,
    "<global>",
    kTeamColorModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847E10 (FUN_00847E10, cfunc_TeamColorModeL)
 *
 * What it does:
 * A Lua bool turns the active user session's team-color mode on or off. FAF
 * hot-patch (FA-Binary-Patches TeamColorMode, 0x00847E51): a string such as
 * "ffrrggbb,ffrrggbb,..." instead fills the per-army palette `teamcolors` in
 * army order and leaves the mode alone.
 */
int moho::cfunc_TeamColorModeL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kTeamColorModeHelpText);

  if (CWldSession* const session = WLD_GetActiveSession()) {
    const LuaPlus::LuaStackObject modeArg(state, 1);
    const int argumentType = lua_type(state->m_state, 1);
    if (argumentType == LUA_TSTRING || argumentType == LUA_TNUMBER) {
      ParseTeamColorPalette(lua_tostring(state->m_state, 1));
      return 0;
    }
    if (argumentType != LUA_TBOOLEAN) {
      modeArg.TypeError("bool");
    }
    session->mTeamColorMode = modeArg.GetBoolean();
  }
  return 0;
}

/**
 * Address: 0x0128B2F9 (FUN_0128B2F9, cfunc_SetInvertMidMouseButton)
 *
 * What it does:
 * Reads one Lua boolean, patches middle-mouse scrub opcodes to add/sub mode,
 * and preserves page protection around the patch write.
 */
int moho::cfunc_SetInvertMidMouseButton(lua_State* const luaContext)
{
  const int argumentCount = lua_gettop(luaContext);
  if (argumentCount != 1) {
    gpg::Warnf(kLuaExpectedArgsWarning, kSetInvertMidMouseButtonHelpText, 1, argumentCount);
  }

  if (lua_type(luaContext, 1) != LUA_TBOOLEAN) {
    gpg::Warnf(kLuaInvalidBoolWarning, kSetInvertMidMouseButtonHelpText, 1);
  }

  const bool invertMiddleMouse = lua_toboolean(luaContext, 1) != 0;
  UI_SetInvertMidMouseScrub(invertMiddleMouse);
  return 0;
}

/**
 * What it does:
 * Publishes the global Lua binder definition for `SetInvertMidMouseButton`.
 *
 * The shipped build carries this binding in its `.exxt` patch section rather
 * than a `func_*_LuaFuncDef` factory, so there is no address to cite for the
 * factory itself - only for the bound worker, `cfunc_SetInvertMidMouseButton`
 * at 0x0128B2F9. `/lua/options/options.lua` calls the global from the
 * `invert_middle_mouse_button` option's `set` handler, which runs at startup,
 * so without this registration every options pass died on "access to
 * nonexistent global variable".
 */
moho::CScrLuaInitForm* moho::func_SetInvertMidMouseButton_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetInvertMidMouseButton",
    &moho::cfunc_SetInvertMidMouseButton,
    nullptr,
    "<global>",
    kSetInvertMidMouseButtonHelpText
  );
  return &binder;
}

/**
 * Address: 0x008ADFF0 (FUN_008ADFF0, cfunc_AudioSetLanguageUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_AudioSetLanguageUserL`.
 */
int moho::cfunc_AudioSetLanguageUser(lua_State* const luaContext)
{
  return cfunc_AudioSetLanguageUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008AE010 (FUN_008AE010, func_AudioSetLanguageUser_LuaFuncDef)
 *
 * What it does:
 * Publishes user-lane global `AudioSetLanguage(name)` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_AudioSetLanguageUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "AudioSetLanguage",
    &moho::cfunc_AudioSetLanguageUser,
    nullptr,
    "<global>",
    kAudioSetLanguageUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008AE070 (FUN_008AE070, cfunc_AudioSetLanguageUserL)
 *
 * What it does:
 * Validates one language code, then rebuilds localized voice/tutorial engines
 * when the normalized language tag changes and localized VO data exists.
 */
int moho::cfunc_AudioSetLanguageUserL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kAudioSetLanguageUserHelpText);

  LuaPlus::LuaStackObject languageArg(state, 1);
  const char* languageText = lua_tostring(state->m_state, 1);
  if (languageText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&languageArg, "string");
    languageText = "";
  }

  // Engine addition (snd_CreateEarly): while the sound manager is still being built, the language
  // is set by the thread building it, right after; nothing comes back to Lua either way.
  const fa::string normalizedLanguage = gpg::STR_ToLower(languageText);
  USER_WithSound([normalizedLanguage](IUserSoundManager* const sound) {
    CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(sound);
    if (userSound == nullptr) {
      return;
    }

    if (normalizedLanguage == userSound->mLanguageTag || !HasLocalizedVoiceDirectory(normalizedLanguage)) {
      return;
    }

    fa::string localizedRootPath = gpg::STR_Printf("/sounds/voice/%s", normalizedLanguage.c_str());
    if (AudioEngine* const voiceEngine = userSound->mTutorialEngine.get(); voiceEngine != nullptr) {
      voiceEngine->Shutdown();
    }
    userSound->mTutorialEngine = AudioEngine::Create(localizedRootPath.c_str());

    localizedRootPath.append("/tutorials");
    if (AudioEngine* const tutorialEngine = userSound->mAmbientEngine.get(); tutorialEngine != nullptr) {
      tutorialEngine->Shutdown();
    }
    userSound->mAmbientEngine = AudioEngine::Create(localizedRootPath.c_str());

    userSound->mLanguageTag.assign(normalizedLanguage, 0u, fa::string::npos);
  });
  return 0;
}

/**
 * Address: 0x008AE300 (FUN_008AE300, cfunc_HasLocalizedVOUserL)
 *
 * What it does:
 * Returns whether the requested localized voice directory exists.
 */
int moho::cfunc_HasLocalizedVOUserL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kHasLocalizedVOUserHelpText);

  LuaPlus::LuaStackObject languageArg(state, 1);
  const char* languageText = lua_tostring(state->m_state, 1);
  if (languageText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&languageArg, "string");
    languageText = "";
  }

  const fa::string language(languageText);
  lua_pushboolean(state->m_state, HasLocalizedVoiceDirectory(language) ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x008AE280 (FUN_008AE280, cfunc_HasLocalizedVOUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_HasLocalizedVOUserL`.
 */
int moho::cfunc_HasLocalizedVOUser(lua_State* const luaContext)
{
  return cfunc_HasLocalizedVOUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008AE2A0 (FUN_008AE2A0, func_HasLocalizedVOUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `HasLocalizedVO`.
 */
moho::CScrLuaInitForm* moho::func_HasLocalizedVOUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "HasLocalizedVO",
    &moho::cfunc_HasLocalizedVOUser,
    nullptr,
    "<global>",
    kHasLocalizedVOUserHelpText
  );
  return &binder;
}
