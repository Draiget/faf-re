#include "moho/lua/ScrLuaUserData.h"
#include "moho/sim/UserLuaPrivate.h"

using EntId = std::int32_t;
namespace
{

// Engine addition: helpers shared with the file these functions came from.
  /**
   * Address: 0x008B5BB0 (FUN_008B5BB0, sub_8B5BB0)
   *
   * What it does:
   * Finds one command-issue helper by command id in the session command-manager
   * map and returns the mapped helper pointer, or `nullptr` when absent.
   *
   * Real disassembly (`std::map_CmdId_CommandIssueHelper::find`, FUN_008B6160,
   * cited on `rb_tree::find_node` in `RbTree.h`) is a plain
   * `commandManager->mCommands.find(cmdId)`; this used to reach in through a
   * bespoke `CommandDbMapStorageView`/`CommandDbMapNodeView` pair
   * (`CommandIssueMapOf` + `FindCommandNode`) that hand-walked the same real
   * `fa::map<CmdId, UserCommandIssueHelper*> CommandManager::mCommands`
   * (`CommandManager.h`) member instead of calling it.
   */
  [[nodiscard]] UserCommandIssueHelper* FindCommandIssueHelperInManager(
    CommandManager* const commandManager,
    const CmdId cmdId
  ) noexcept
  {
    if (commandManager == nullptr) {
      return nullptr;
    }

    const auto it = commandManager->mCommands.find(cmdId);
    if (it == commandManager->mCommands.end()) {
      return nullptr;
    }

    return it->second;
  }
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";
  [[nodiscard]] IUnit* ResolveIUnitBridge(UserUnit* const unit) noexcept
  {
    return unit ? static_cast<IUnit*>(unit) : nullptr;
  }

  void AppendSelectionUnitUnique(fa::vector<UserUnit*>& selectionUnits, UserUnit* const unit)
  {
    if (unit == nullptr) {
      return;
    }

    if (std::find(selectionUnits.begin(), selectionUnits.end(), unit) == selectionUnits.end()) {
      selectionUnits.push_back(unit);
    }
  }
  [[nodiscard]] std::int64_t BuildScriptBitMask(const int bitIndex) noexcept
  {
    const std::uint32_t bitShift = static_cast<std::uint32_t>(bitIndex);
    return bitShift < 64u ? static_cast<std::int64_t>(1ull << bitShift) : 0;
  }
  [[nodiscard]] UserCommandIssueHelper* FindCommandIssueHelper(CWldSession* const session, const CmdId cmdId)
  {
    if (!session || !session->mCommandManager) {
      return nullptr;
    }

    CommandManager* const commandManager = session->mCommandManager;
    return FindCommandIssueHelperInManager(commandManager, cmdId);
  }
  [[nodiscard]] UserEntity*
  FindUserSessionEntityById(CWldSession* const session, const std::int32_t entityId) noexcept
  {
    if (session == nullptr) {
      return nullptr;
    }

    return session->LookupEntityId(entityId);
  }
  constexpr const char* kAddSelectUnitsHelpText = "Add these units to the currently Selected lists";
  constexpr const char* kClearBuildTemplatesHelpText = "clear and disable the build templates.";
  constexpr const char* kCreateUnitAtMouseHelpText = "CreateUnitAtMouse";
  constexpr const char* kDeleteCommandHelpText = "DeleteCommand(id)";
  constexpr const char* kEntityCategoryContainsUserHelpText = "See if a unit category contains this unit";
  constexpr const char* kEntityCategoryContainsUserNoSessionText = "EntityCategoryContains: no session loaded";
  constexpr const char* kEntityCategoryFilterDownUserHelpText =
    "Filter a list of units to only those found in the category";
  constexpr const char* kEntityCategoryFilterDownUserInvalidCategoryText =
    "EntityCategoryFilterDown: expected an entity category object";
  constexpr const char* kEntityCategoryFilterDownUserNoSessionText = "EntityCategoryFilterDown: no session loaded";
  constexpr const char* kEntityCategoryFilterOutHelpText =
    "Filter a list of units to exclude those found in the category";
  constexpr const char* kEntityCategoryFilterOutInvalidCategoryText =
    "EntityCategoryFilterOut: expected an entity category object";
  constexpr const char* kEntityCategoryFilterOutNoSessionText = "EntityCategoryFilterOut: no session loaded";
  constexpr const char* kExecLuaInSimHelpText = "Execute some lua code in the sim";
  constexpr const char* kGenerateBuildTemplateFromSelectionHelpText =
    "generate and enable build templates from the current selection.";
  constexpr const char* kGetAssistingUnitsListHelpText = "Get a list of units assisting me";
  constexpr const char* kGetAttachedUnitsListHelpText = "Get a list of units blueprint attached to transports";
  constexpr const char* kGetIdleEngineersHelpText =
    "table GetIdleEngineers() - return a table of idle engineer units for the army";
  constexpr const char* kGetIdleFactoriesHelpText =
    "table GetIdleFactories() - return a table of idle factory units for the army";
  constexpr const char* kGetSelectedUnitsHelpText = "table GetSelectedUnits() - return a table of the currently selected units";
  constexpr const char* kGetUnitByIdUserHelpText = "GetUnitById(id)";
  constexpr const char* kGetUnitCommandFromCommandCapErrorHelpText = "string GetUnitCommandFromCommandCap(string)";
  constexpr const char* kGetUnitCommandFromCommandCapHelpText =
    "string GetUnitCommandFromCommandCap(string) - given a RULEUCC type command, return the equivalent UNITCOMMAND command";
  constexpr const char* kGetValidAttackingUnitsHelpText =
    "table GetValidAttackingUnits() - return a table of the currently selected units";
  constexpr const char* kParseEntityCategoryUserHelpText = "parse a string to generate a new entity category";
  constexpr const char* kParseEntityCategoryUserNoSessionText = "ParseEntityCategory: no session loaded";
  constexpr const char* kSelectUnitsHelpText = "Select the specified units";
  constexpr const char* kSetAutoModeHelpText = "See if anyone in the list is auto building";
  constexpr const char* kSetAutoSurfaceModeHelpText = "See if anyone in the list is auto surfacing";
  constexpr const char* kSetPausedHelpText = "Pause builders in this list";
  constexpr const char* kSimCallbackHelpText =
    "SimCallback(callback[,bool]): Execute a lua function in sim\n"
    "callback = {\n"
    "   Func    =   function name (in the SimCallbacks.lua module) to call\n"
    "   Args    =   Arguments as a lua object\n"
    "}\n"
    "If bool is specified and true, sends the current selection with the command\n";
  constexpr const char* kToggleScriptBitExpectedArgsText = "ToggleScriptBit(units, bit, curState)";
  constexpr const char* kToggleScriptBitHelpText = "Set the right fire state for the units passed in";
  constexpr const char* kValidateUnitsListHelpText = "Validate a list of units ";
  /**
   * Address: 0x008B49D0 (FUN_008B49D0, sub_8B49D0)
   *
   * What it does:
   * Queues one local "decrease count" edit of `deltaCount`.
   *
   * Address: 0x008B4960 (FUN_008B4960 -- the "increase count" sibling, the same
   * body with kind 1; zero callers and no references in the image, a
   * linker-retained copy nothing runs.)
   */
  void QueueCommandIssueDecreaseCountEvent(UserCommandIssueHelper& helper, const CmdId cmdId, const std::int32_t deltaCount)
  {
    UserCommandIssueLocalEvent event(cmdId, ECommandIssueEvent::DecreaseCount);
    event.mCount = deltaCount;
    helper.mLocalQueue.push_back(event);
  }
  [[nodiscard]] CmdId ReadLuaCommandIdArg(LuaPlus::LuaState* const state, const int stackIndex)
  {
    LuaPlus::LuaStackObject arg(state, stackIndex);
    if (lua_type(state->m_state, stackIndex) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&arg, "integer");
    }

    // Binary lane uses an x87 integer-store conversion and consumes the low dword.
    const std::int64_t truncated = static_cast<std::int64_t>(lua_tonumber(state->m_state, stackIndex));
    return static_cast<CmdId>(static_cast<std::uint32_t>(truncated));
  }
  [[nodiscard]] const RUnitBlueprint* ResolveEntityCategoryFilterBlueprint(
    const LuaPlus::LuaObject& valueObject,
    CWldSession* const session,
    LuaPlus::LuaState* const state
  )
  {
    if (valueObject.IsString()) {
      const char* const blueprintText = valueObject.GetString();
      if (!blueprintText || !session || !session->mRules) {
        return nullptr;
      }

      RResId blueprintId{};
      gpg::STR_SetFilename(&blueprintId.name, blueprintText);
      return session->mRules->GetUnitBlueprint(blueprintId);
    }

    UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
    if (!userUnit) {
      return nullptr;
    }

    const IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    return iunitBridge ? iunitBridge->GetBlueprint() : nullptr;
  }
  [[nodiscard]] Sim* ResolveGlobalSim(lua_State* const luaContext) noexcept
  {
    if (!luaContext || !luaContext->l_G) {
      return nullptr;
    }
    return luaContext->l_G->globalUserData;
  }
  [[nodiscard]] UserUnit* ResolveSelectableTransportAttachmentParent(UserUnit* const unit) noexcept
  {
    if (unit == nullptr) {
      return nullptr;
    }

    auto* const entity = reinterpret_cast<UserEntity*>(unit);
    const std::uint32_t attachmentParentRef = entity->mVariableData.mAttachmentParentRef;
    if (attachmentParentRef == 0u || attachmentParentRef == ToRaw(EEntityIdSentinel::Invalid)) {
      return nullptr;
    }

    UserEntity* const attachmentParentEntity = FindUserSessionEntityById(
      entity->mSession,
      static_cast<std::int32_t>(attachmentParentRef)
    );
    if (attachmentParentEntity == nullptr || !attachmentParentEntity->IsSelectable()) {
      return nullptr;
    }

    UserUnit* const attachmentParentUnit = attachmentParentEntity->IsUserUnit();
    if (attachmentParentUnit == nullptr) {
      return nullptr;
    }

    static const fa::string kTransportationCategory("TRANSPORTATION");
    return attachmentParentEntity->IsInCategory(kTransportationCategory) ? attachmentParentUnit : nullptr;
  }
  [[nodiscard]] UserUnit* ResolveUserUnitOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
  {
    CScriptObject** const scriptObjectSlot = moho::SCR_ScriptObjectSlot(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, gpg::RTypeOf<UserUnit>());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<UserUnit*>(upcast.mObj);
  }
}



/**
 * Address: 0x008B9B80 (FUN_008B9B80, cfunc_ParseEntityCategoryUserL)
 *
 * What it does:
 * Parses one category expression string and returns a new entity-category
 * userdata object.
 */
int moho::cfunc_ParseEntityCategoryUserL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kParseEntityCategoryUserHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  RRuleGameRulesImpl* const rules = session ? session->mRules : nullptr;
  if (!rules) {
    LuaPlus::LuaState::Error(state, kParseEntityCategoryUserNoSessionText);
  }

  LuaPlus::LuaStackObject categoryTextArg(state, 1);
  const char* categoryText = lua_tostring(rawState, 1);
  if (!categoryText) {
    categoryTextArg.TypeError("string");
    categoryText = "";
  }

  EntityCategorySet parsedCategory = rules->ParseEntityCategory(categoryText);

  LuaPlus::LuaObject out;
  (void)func_NewEntityCategory(state, &out, &parsedCategory);
  out.PushStack(state);
  return 1;
}

/**
 * Address: 0x008B9B00 (FUN_008B9B00, cfunc_ParseEntityCategoryUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_ParseEntityCategoryUserL`.
 */
int moho::cfunc_ParseEntityCategoryUser(lua_State* const luaContext)
{
  return cfunc_ParseEntityCategoryUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008B9B20 (FUN_008B9B20, func_ParseEntityCategoryUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ParseEntityCategory`.
 */
moho::CScrLuaInitForm* moho::func_ParseEntityCategoryUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ParseEntityCategory",
    &moho::cfunc_ParseEntityCategoryUser,
    nullptr,
    "<global>",
    kParseEntityCategoryUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00840840 (FUN_00840840, cfunc_GetUnitCommandFromCommandCap)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to
 * `cfunc_GetUnitCommandFromCommandCapL`.
 */
int moho::cfunc_GetUnitCommandFromCommandCap(lua_State* const luaContext)
{
  return cfunc_GetUnitCommandFromCommandCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00840860 (FUN_00840860, func_GetUnitCommandFromCommandCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `GetUnitCommandFromCommandCap`.
 */
moho::CScrLuaInitForm* moho::func_GetUnitCommandFromCommandCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetUnitCommandFromCommandCap",
    &moho::cfunc_GetUnitCommandFromCommandCap,
    nullptr,
    "<global>",
    kGetUnitCommandFromCommandCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00821F50 (FUN_00821F50, Moho::UnitCommandCapToCommandType)
 *
 * What it does:
 * Converts one command-capability enum into the matching unit command enum.
 */
moho::EUnitCommandType moho::UnitCommandCapToCommandType(const ERuleBPUnitCommandCaps commandCap)
{
  if (commandCap > RULEUCC_Tactical) {
    if (commandCap > RULEUCC_Pause) {
      if (commandCap > RULEUCC_Reclaim) {
        if (commandCap == RULEUCC_SpecialAction) {
          return EUnitCommandType::UNITCOMMAND_SpecialAction;
        }
      } else {
        switch (commandCap) {
        case RULEUCC_Reclaim:
          return EUnitCommandType::UNITCOMMAND_Reclaim;
        case RULEUCC_Overcharge:
          return EUnitCommandType::UNITCOMMAND_OverCharge;
        case RULEUCC_Dive:
          return EUnitCommandType::UNITCOMMAND_Dive;
        default:
          break;
        }
      }
    } else {
      if (commandCap == RULEUCC_Pause) {
        return EUnitCommandType::UNITCOMMAND_Pause;
      }

      if (commandCap > RULEUCC_SiloBuildTactical) {
        if (commandCap == RULEUCC_SiloBuildNuke) {
          return EUnitCommandType::UNITCOMMAND_BuildSiloNuke;
        }
        if (commandCap == RULEUCC_Sacrifice) {
          return EUnitCommandType::UNITCOMMAND_Sacrifice;
        }
      } else {
        switch (commandCap) {
        case RULEUCC_SiloBuildTactical:
          return EUnitCommandType::UNITCOMMAND_BuildSiloTactical;
        case RULEUCC_Teleport:
          return EUnitCommandType::UNITCOMMAND_Teleport;
        case RULEUCC_Ferry:
          return EUnitCommandType::UNITCOMMAND_Ferry;
        default:
          break;
        }
      }
    }

    return EUnitCommandType::UNITCOMMAND_None;
  }

  if (commandCap == RULEUCC_Tactical) {
    return EUnitCommandType::UNITCOMMAND_Tactical;
  }

  if (commandCap > RULEUCC_Repair) {
    if (commandCap > RULEUCC_CallTransport) {
      if (commandCap == RULEUCC_Nuke) {
        return EUnitCommandType::UNITCOMMAND_Nuke;
      }
    } else {
      switch (commandCap) {
      case RULEUCC_CallTransport:
        return EUnitCommandType::UNITCOMMAND_TransportLoadUnits;
      case RULEUCC_Capture:
        return EUnitCommandType::UNITCOMMAND_Capture;
      case RULEUCC_Transport:
        return EUnitCommandType::UNITCOMMAND_TransportUnloadUnits;
      default:
        break;
      }
    }

    return EUnitCommandType::UNITCOMMAND_None;
  }

  if (commandCap == RULEUCC_Repair) {
    return EUnitCommandType::UNITCOMMAND_Repair;
  }

  switch (commandCap) {
  case RULEUCC_Move:
    return EUnitCommandType::UNITCOMMAND_Move;
  case RULEUCC_Stop:
    return EUnitCommandType::UNITCOMMAND_Stop;
  case RULEUCC_Attack:
    return EUnitCommandType::UNITCOMMAND_Attack;
  case RULEUCC_Guard:
    return EUnitCommandType::UNITCOMMAND_Guard;
  case RULEUCC_Patrol:
    return EUnitCommandType::UNITCOMMAND_Patrol;
  default:
    return EUnitCommandType::UNITCOMMAND_None;
  }
}

/**
 * Address: 0x008408C0 (FUN_008408C0, cfunc_GetUnitCommandFromCommandCapL)
 *
 * What it does:
 * Converts one `RULEUCC` lexical token to its corresponding `UNITCOMMAND`
 * lexical token and returns it as a Lua string.
 */
int moho::cfunc_GetUnitCommandFromCommandCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetUnitCommandFromCommandCapErrorHelpText);

  const LuaPlus::LuaStackObject commandCapArg(state, 1);
  const char* const commandCapLexical = lua_tostring(rawState, 1);
  if (commandCapLexical == nullptr) {
    commandCapArg.TypeError("string");
  }

  ERuleBPUnitCommandCaps commandCap = RULEUCC_None;
  gpg::RRef commandCapRef(&commandCap, gpg::RTypeOf<moho::ERuleBPUnitCommandCaps>());
  (void)commandCapRef.SetLexical(commandCapLexical);

  EUnitCommandType commandType = moho::UnitCommandCapToCommandType(commandCap);

  gpg::RRef commandTypeRef(&commandType, gpg::RTypeOf<moho::EUnitCommandType>());
  const fa::string commandTypeLexical = commandTypeRef.GetLexical();
  lua_pushstring(rawState, commandTypeLexical.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008B9D10 (FUN_008B9D10, cfunc_EntityCategoryContainsUserL)
 *
 * What it does:
 * Tests whether arg#1 category set contains arg#2 unit/blueprint category.
 */
int moho::cfunc_EntityCategoryContainsUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kEntityCategoryContainsUserHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session || !session->mRules) {
    LuaPlus::LuaState::Error(state, kEntityCategoryContainsUserNoSessionText);
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); // 0x005575E0: raises on a non-category

  const LuaPlus::LuaObject valueObject(LuaPlus::LuaStackObject(state, 2));
  const RUnitBlueprint* const blueprint = ResolveEntityCategoryFilterBlueprint(valueObject, session, state);

  const bool contains =
    categorySet != nullptr && blueprint != nullptr && categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  lua_pushboolean(rawState, contains ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008B9C90 (FUN_008B9C90, cfunc_EntityCategoryContainsUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryContainsUserL`.
 */
int moho::cfunc_EntityCategoryContainsUser(lua_State* const luaContext)
{
  return cfunc_EntityCategoryContainsUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008B9CB0 (FUN_008B9CB0, func_EntityCategoryContainsUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `EntityCategoryContains`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryContainsUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "EntityCategoryContains",
    &moho::cfunc_EntityCategoryContainsUser,
    nullptr,
    "<global>",
    kEntityCategoryContainsUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008B9F70 (FUN_008B9F70, cfunc_EntityCategoryFilterDownUserL)
 *
 * What it does:
 * Filters arg#2 values into a result table by keeping entries whose resolved
 * unit blueprint category bit is present in arg#1 category set.
 */
int moho::cfunc_EntityCategoryFilterDownUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kEntityCategoryFilterDownUserHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session || !session->mRules) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterDownUserNoSessionText);
  }

  if (lua_type(rawState, 1) == 0 || lua_type(rawState, 2) == 0) {
    return 0;
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); // 0x005575E0: raises on a non-category
  if (!categorySet) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterDownUserInvalidCategoryText);
  }

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0u);

  int resultIndex = 1;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];
    const RUnitBlueprint* const blueprint = ResolveEntityCategoryFilterBlueprint(valueObject, session, state);
    if (!blueprint) {
      continue;
    }

    if (categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      resultObject.SetObject(resultIndex, valueObject); // 0x008BA177: plain table set
      ++resultIndex;
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008B9EF0 (FUN_008B9EF0, cfunc_EntityCategoryFilterDownUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterDownUserL`.
 */
int moho::cfunc_EntityCategoryFilterDownUser(lua_State* const luaContext)
{
  return cfunc_EntityCategoryFilterDownUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008B9F10 (FUN_008B9F10, func_EntityCategoryFilterDownUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryFilterDown`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryFilterDownUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "EntityCategoryFilterDown",
    &moho::cfunc_EntityCategoryFilterDownUser,
    nullptr,
    "<global>",
    kEntityCategoryFilterDownUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA2A0 (FUN_008BA2A0, cfunc_EntityCategoryFilterOutL)
 *
 * What it does:
 * Filters arg#2 values into a result table by excluding entries whose resolved
 * unit blueprint category bit is present in arg#1 category set.
 */
int moho::cfunc_EntityCategoryFilterOutL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 2, kEntityCategoryFilterOutHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session || !session->mRules) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterOutNoSessionText);
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); // 0x005575E0: raises on a non-category
  if (!categorySet) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterOutInvalidCategoryText);
  }

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0u);

  int resultIndex = 1;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];

    const RUnitBlueprint* const blueprint = ResolveEntityCategoryFilterBlueprint(valueObject, session, state);
    if (!blueprint) {
      continue;
    }

    if (!categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      resultObject.SetObject(resultIndex, valueObject); // 0x008BA4A9: plain table set
      ++resultIndex;
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BA220 (FUN_008BA220, cfunc_EntityCategoryFilterOut)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterOutL`.
 */
int moho::cfunc_EntityCategoryFilterOut(lua_State* const luaContext)
{
  return cfunc_EntityCategoryFilterOutL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BA240 (FUN_008BA240, func_EntityCategoryFilterOut_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryFilterOut`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryFilterOut_LuaFuncDef()
{
  // User, not Sim. The binary links this one into scr_UserInits
  // (FUN_008BA240) - the UI reads it while the front end comes up, and the
  // Sim set is not run against the user Lua state at all.
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "EntityCategoryFilterOut",
    &moho::cfunc_EntityCategoryFilterOut,
    nullptr,
    "<global>",
    kEntityCategoryFilterOutHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA540 (FUN_008BA540, cfunc_ExecLuaInSim)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_ExecLuaInSimL`.
 */
int moho::cfunc_ExecLuaInSim(lua_State* const luaContext)
{
  return cfunc_ExecLuaInSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BA560 (FUN_008BA560, func_ExecLuaInSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ExecLuaInSim`.
 */
moho::CScrLuaInitForm* moho::func_ExecLuaInSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ExecLuaInSim",
    &moho::cfunc_ExecLuaInSim,
    nullptr,
    "<global>",
    kExecLuaInSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA5C0 (FUN_008BA5C0, cfunc_ExecLuaInSimL)
 *
 * What it does:
 * Reads `(functionName,args)` from Lua and forwards one
 * `ExecuteLuaInSim(functionName,args)` request through the active sim driver.
 */
int moho::cfunc_ExecLuaInSimL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kExecLuaInSimHelpText);

  LuaPlus::LuaStackObject functionNameArg(state, 1);
  const char* functionNameText = lua_tostring(state->m_state, 1);
  if (!functionNameText) {
    LuaPlus::LuaStackObject::TypeError(&functionNameArg, "string");
    functionNameText = "";
  }

  const std::string functionName(functionNameText);
  if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
    LuaPlus::LuaObject callbackArgs(LuaPlus::LuaStackObject(state, 2));
    activeDriver->ExecuteLuaInSim(functionName.c_str(), callbackArgs);
  }
  return 0;
}

/**
 * Address: 0x008BA770 (FUN_008BA770, cfunc_SimCallbackL)
 *
 * What it does:
 * Reads callback payload (`Func`,`Args`) and optional selection forwarding
 * flag, then marshals `CMDST_LuaSimCallback` through the active sim driver.
 */
int moho::cfunc_SimCallbackL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kSimCallbackHelpText,
      1,
      2,
      argumentCount
    );
  }

  lua_settop(rawState, 2);

  lua_pushstring(rawState, "Func");
  lua_gettable(rawState, 1);
  const int callbackNameIndex = lua_gettop(rawState);
  LuaPlus::LuaStackObject callbackNameArg(state, callbackNameIndex);

  const char* callbackNameText = lua_tostring(rawState, callbackNameIndex);
  if (!callbackNameText) {
    LuaPlus::LuaStackObject::TypeError(&callbackNameArg, "string");
    callbackNameText = "";
  }
  const fa::string callbackName(callbackNameText);

  lua_pushstring(rawState, "Args");
  lua_gettable(rawState, 1);
  LuaPlus::LuaObject callbackArgs(LuaPlus::LuaStackObject(state, lua_gettop(rawState)));

  LuaPlus::LuaStackObject includeSelectionArg(state, 2);
  BVSet<EntId, EntIdUniverse> selectedEntities{};

  if (LuaPlus::LuaStackObject::GetBoolean(&includeSelectionArg)) {
    if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
      fa::vector<UserUnit*> selectedUnits{};
      session->GetSelectionUnits(selectedUnits);
      for (UserUnit* const selectedUnit : selectedUnits) {
        IUnit* const iunitBridge = ResolveIUnitBridge(selectedUnit);
        if (!iunitBridge) {
          continue;
        }

        selectedEntities.Bits().Add(static_cast<unsigned int>(iunitBridge->GetEntityId()));
      }
    }
  }

  if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
    activeDriver->LuaSimCallback(callbackName.c_str(), callbackArgs, selectedEntities);
  }
  return 0;
}

/**
 * Address: 0x008BA6F0 (FUN_008BA6F0, cfunc_SimCallback)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SimCallbackL`.
 */
int moho::cfunc_SimCallback(lua_State* const luaContext)
{
  return cfunc_SimCallbackL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BA710 (FUN_008BA710, func_SimCallback_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SimCallback`.
 */
moho::CScrLuaInitForm* moho::func_SimCallback_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SimCallback",
    &moho::cfunc_SimCallback,
    nullptr,
    "<global>",
    kSimCallbackHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BADE0 (FUN_008BADE0, cfunc_SetAutoModeL)
 *
 * What it does:
 * Reads `(unitTable, enabled)` and emits one `SetAutoMode` info-pair per
 * live user-unit entry.
 */
int moho::cfunc_SetAutoModeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 2, kSetAutoModeHelpText);

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject enabledArg(state, 2);
  const bool enabled = LuaPlus::LuaStackObject::GetBoolean(&enabledArg);

  if (!unitListObject.IsTable()) {
    return 0;
  }

  const int unitCount = unitListObject.GetCount();
  for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
    LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
    UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
    IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    if (!iunitBridge || iunitBridge->IsDead()) {
      continue;
    }

    if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
      activeDriver->ProcessInfoPair(
        iunitBridge->GetEntityId(),
        "SetAutoMode",
        enabled ? "true" : "false"
      );
    }
  }

  return 0;
}

/**
 * Address: 0x008BAD60 (FUN_008BAD60, cfunc_SetAutoMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SetAutoModeL`.
 */
int moho::cfunc_SetAutoMode(lua_State* const luaContext)
{
  return cfunc_SetAutoModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BAD80 (FUN_008BAD80, func_SetAutoMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder for `SetAutoMode`.
 */
moho::CScrLuaInitForm* moho::func_SetAutoMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetAutoMode",
    &moho::cfunc_SetAutoMode,
    nullptr,
    "<global>",
    kSetAutoModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB360 (FUN_008BB360, cfunc_SetAutoSurfaceModeL)
 *
 * What it does:
 * Reads `(unitTable, enabled)` and emits one `SetAutoSurfaceMode` info-pair
 * per live user-unit entry.
 */
int moho::cfunc_SetAutoSurfaceModeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 2, kSetAutoSurfaceModeHelpText);

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject enabledArg(state, 2);
  const bool enabled = LuaPlus::LuaStackObject::GetBoolean(&enabledArg);

  if (!unitListObject.IsTable()) {
    return 0;
  }

  const int unitCount = unitListObject.GetCount();
  for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
    LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
    UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
    IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    if (!iunitBridge || iunitBridge->IsDead()) {
      continue;
    }

    if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
      activeDriver->ProcessInfoPair(
        iunitBridge->GetEntityId(),
        "SetAutoSurfaceMode",
        enabled ? "true" : "false"
      );
    }
  }

  return 0;
}

/**
 * Address: 0x008BB2E0 (FUN_008BB2E0, cfunc_SetAutoSurfaceMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SetAutoSurfaceModeL`.
 */
int moho::cfunc_SetAutoSurfaceMode(lua_State* const luaContext)
{
  return cfunc_SetAutoSurfaceModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB300 (FUN_008BB300, func_SetAutoSurfaceMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `SetAutoSurfaceMode`.
 */
moho::CScrLuaInitForm* moho::func_SetAutoSurfaceMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetAutoSurfaceMode",
    &moho::cfunc_SetAutoSurfaceMode,
    nullptr,
    "<global>",
    kSetAutoSurfaceModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BBE60 (FUN_008BBE60, cfunc_ToggleScriptBitL)
 *
 * What it does:
 * Reads `(unitTable, bit, currentState)` and emits `ToggleScriptBit`
 * info-pairs for live units whose toggle-cap lane exposes that bit and whose
 * current script-bit value matches `currentState`.
 */
int moho::cfunc_ToggleScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kToggleScriptBitExpectedArgsText);

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));

  LuaPlus::LuaStackObject bitArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    bitArg.TypeError("integer");
  }
  const int bitIndex = static_cast<int>(lua_tonumber(rawState, 2));

  LuaPlus::LuaStackObject currentStateArg(state, 3);
  const bool currentState = currentStateArg.GetBoolean();

  char bitText[0x10]{};
  std::snprintf(bitText, sizeof(bitText), "%d", bitIndex);

  if (unitListObject.IsTable()) {
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead()) {
        continue;
      }

      const std::uint32_t toggleCapMask = 1u << (static_cast<std::uint32_t>(bitIndex) & 0x1Fu);
      if ((iunitBridge->GetAttributes().toggleCapsMask & toggleCapMask) == 0u) {
        continue;
      }

      // `cdq` at 0x008BBFE9: the bits are widened as a signed 32-bit value.
      const auto scriptBits = static_cast<std::int64_t>(static_cast<std::int32_t>(userUnit->mUnitVarDat.mScriptbits));
      const bool scriptBitStateMatches = (scriptBits & BuildScriptBitMask(bitIndex)) != 0;
      if (scriptBitStateMatches != currentState) {
        continue;
      }

      if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
        activeDriver->ProcessInfoPair(iunitBridge->GetEntityId(), "ToggleScriptBit", bitText);
      }
    }
  }

  return 0;
}

/**
 * Address: 0x008BBDE0 (FUN_008BBDE0, cfunc_ToggleScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_ToggleScriptBitL`.
 */
int moho::cfunc_ToggleScriptBit(lua_State* const luaContext)
{
  return cfunc_ToggleScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BBE00 (FUN_008BBE00, func_ToggleScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `ToggleScriptBit`.
 */
moho::CScrLuaInitForm* moho::func_ToggleScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ToggleScriptBit",
    &moho::cfunc_ToggleScriptBit,
    nullptr,
    "<global>",
    kToggleScriptBitHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC100 (FUN_008BC100, cfunc_SetPausedL)
 *
 * What it does:
 * Reads `(unitTable, paused)` and emits one `SetPaused` info-pair per live
 * user-unit entry while callback dispatch remains enabled.
 */
int moho::cfunc_SetPausedL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kSetPausedHelpText);

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject pausedArg(state, 2);
  const bool paused = pausedArg.GetBoolean();

  if (unitListObject.IsTable()) {
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead()) {
        continue;
      }

      if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
        activeDriver->ProcessInfoPair(
          iunitBridge->GetEntityId(),
          "SetPaused",
          paused ? "true" : "false"
        );
      }
    }
  }

  return 0;
}

/**
 * Address: 0x008BC080 (FUN_008BC080, cfunc_SetPaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SetPausedL`.
 */
int moho::cfunc_SetPaused(lua_State* const luaContext)
{
  return cfunc_SetPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC0A0 (FUN_008BC0A0, func_SetPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `SetPaused`.
 */
moho::CScrLuaInitForm* moho::func_SetPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SetPaused",
    &moho::cfunc_SetPaused,
    nullptr,
    "<global>",
    kSetPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC280 (FUN_008BC280, cfunc_GetAttachedUnitsList)
 *
 * What it does:
 * Unwraps Lua callback state and dispatches to `cfunc_GetAttachedUnitsListL`.
 */
int moho::cfunc_GetAttachedUnitsList(lua_State* const luaContext)
{
  return cfunc_GetAttachedUnitsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC2A0 (FUN_008BC2A0, func_GetAttachedUnitsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetAttachedUnitsList`.
 */
moho::CScrLuaInitForm* moho::func_GetAttachedUnitsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetAttachedUnitsList",
    &moho::cfunc_GetAttachedUnitsList,
    nullptr,
    "<global>",
    kGetAttachedUnitsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC300 (FUN_008BC300, cfunc_GetAttachedUnitsListL)
 *
 * What it does:
 * Builds one Lua table containing alive attached user-unit script objects for
 * each source unit in the input table.
 */
int moho::cfunc_GetAttachedUnitsListL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession() || state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kGetAttachedUnitsListHelpText);

  const LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0);

  if (unitListObject.IsTable()) {
    int resultIndex = 1;
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject sourceUnitObject = unitListObject[unitIndex];
      UserUnit* const sourceUnit = SCR_FromLua_UserUnit(sourceUnitObject, state);
      IUnit* const sourceUnitBridge = ResolveIUnitBridge(sourceUnit);
      if (sourceUnitBridge == nullptr || sourceUnitBridge->IsDead()) {
        continue;
      }

      UserEntity* const sourceEntity = reinterpret_cast<UserEntity*>(sourceUnit);
      CWldSession* const session = sourceEntity->mSession;
      if (session == nullptr) {
        continue;
      }

      for (const SSTIEntityAttachInfo& attachment : sourceEntity->mVariableData.mAuxValueVector) {
        UserEntity* const attachedEntity = FindUserSessionEntityById(session, attachment.mAttachedEntityId);
        if (attachedEntity == nullptr || attachedEntity->mVariableData.mIsDead != 0u) {
          continue;
        }

        UserUnit* const attachedUnit = attachedEntity->IsUserUnit();
        IUnit* const attachedUnitBridge = ResolveIUnitBridge(attachedUnit);
        if (attachedUnitBridge == nullptr) {
          continue;
        }

        LuaPlus::LuaObject attachedUnitObject = attachedUnitBridge->GetLuaObject();
        // 0x008BC4C9: `LuaObject::Insert(i, obj)` (Lua `table.insert`), not a raw store.
        resultObject.Insert(resultIndex, attachedUnitObject);
        ++resultIndex;
      }
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BC5F0 (FUN_008BC5F0, cfunc_ValidateUnitsListL)
 *
 * What it does:
 * Filters one input unit table down to alive, non-destroy-queued unit Lua
 * objects and returns the filtered table.
 */
int moho::cfunc_ValidateUnitsListL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  if (!WLD_GetActiveSession()) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kValidateUnitsListHelpText);

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0);

  if (unitListObject.IsTable()) {
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitListObject[unitIndex];
      UserUnit* const userUnit = ResolveUserUnitOptional(unitObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead() || iunitBridge->DestroyQueued()) {
        continue;
      }

      LuaPlus::LuaObject unitLuaObject = iunitBridge->GetLuaObject();
      // 0x008BC72C: `LuaObject::Insert(obj)` -- the Lua `table.insert(t, v)` append.
      resultObject.Insert(unitLuaObject);
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BC570 (FUN_008BC570, cfunc_ValidateUnitsList)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to
 * `cfunc_ValidateUnitsListL`.
 */
int moho::cfunc_ValidateUnitsList(lua_State* const luaContext)
{
  return cfunc_ValidateUnitsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC590 (FUN_008BC590, func_ValidateUnitsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `ValidateUnitsList`.
 */
moho::CScrLuaInitForm* moho::func_ValidateUnitsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ValidateUnitsList",
    &moho::cfunc_ValidateUnitsList,
    nullptr,
    "<global>",
    kValidateUnitsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC7A0 (FUN_008BC7A0, cfunc_GetAssistingUnitsList)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_GetAssistingUnitsListL`.
 */
int moho::cfunc_GetAssistingUnitsList(lua_State* const luaContext)
{
  return cfunc_GetAssistingUnitsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC7C0 (FUN_008BC7C0, func_GetAssistingUnitsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetAssistingUnitsList`.
 */
moho::CScrLuaInitForm* moho::func_GetAssistingUnitsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetAssistingUnitsList",
    &moho::cfunc_GetAssistingUnitsList,
    nullptr,
    "<global>",
    kGetAssistingUnitsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC820 (FUN_008BC820, cfunc_GetAssistingUnitsListL)
 *
 * What it does:
 * Returns one Lua array of focused-army pod units that are assisting one of
 * the input units (or the unit itself when matching POD filters).
 */
int moho::cfunc_GetAssistingUnitsListL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->mRules == nullptr) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kGetAssistingUnitsListHelpText);

  const LuaPlus::LuaObject sourceUnitsObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, 0, 0u);

  const EntityCategorySet* const podStagingCategoryRange = session->mRules->GetEntityCategory("PODSTAGINGPLATFORM");
  const EntityCategorySet* const podCategoryRange = session->mRules->GetEntityCategory("POD");
  const EntityCategorySet* const podStagingCategory =
    podStagingCategoryRange != nullptr ? reinterpret_cast<const EntityCategorySet*>(podStagingCategoryRange) : nullptr;
  const EntityCategorySet* const podCategory =
    podCategoryRange != nullptr ? reinterpret_cast<const EntityCategorySet*>(podCategoryRange) : nullptr;
  const UserArmy* const focusArmy = session->GetFocusUserArmy();
  if (!sourceUnitsObject.IsTable() || podCategory == nullptr || focusArmy == nullptr) {
    resultTable.PushStack(state);
    return 1;
  }

  std::set<UserUnit*> emittedUnits{};

  const int sourceCount = sourceUnitsObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    const LuaPlus::LuaObject sourceObject = sourceUnitsObject[sourceIndex];
    UserUnit* const sourceUnit = ResolveUserUnitOptional(sourceObject, state);
    IUnit* const sourceBridge = ResolveIUnitBridge(sourceUnit);
    if (sourceBridge == nullptr || sourceBridge->IsDead() || sourceUnit->IsBeingBuilt()) {
      continue;
    }

    const REntityBlueprint* const sourceBlueprint = sourceBridge->GetBlueprint();
    const bool sourceIsPodStaging =
      (podStagingCategory != nullptr) && (sourceBlueprint != nullptr)
      && EntityCategory::HasBlueprint(sourceBlueprint, podStagingCategory);
    const bool sourceIsPod =
      (sourceBlueprint != nullptr) && EntityCategory::HasBlueprint(sourceBlueprint, podCategory);
    if (!sourceIsPodStaging && !sourceIsPod) {
      continue;
    }

    // Every entity in the session. The private walker this replaced returned
    // null unless the map head's `_Isnil` byte was set at +0x15, and the
    // session's own hand-written tree kept that flag at +0x19, so this loop
    // never ran and the query always came back empty.
    for (const auto& [entityId, entity] : session->mEntities) {
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const candidateUnit = entity->IsUserUnit();
      IUnit* const candidateBridge = ResolveIUnitBridge(candidateUnit);
      if (candidateBridge == nullptr || candidateBridge->IsDead() || candidateUnit->IsBeingBuilt()) {
        continue;
      }

      UserEntity* const candidateEntity = reinterpret_cast<UserEntity*>(candidateUnit);
      if (candidateEntity->mArmy != focusArmy) {
        continue;
      }

      const REntityBlueprint* const candidateBlueprint = candidateBridge->GetBlueprint();
      if (candidateBlueprint == nullptr || !EntityCategory::HasBlueprint(candidateBlueprint, podCategory)) {
        continue;
      }

      // 0x008BCADF: kept when the candidate is the source or was built by it.
      if (candidateUnit != sourceUnit && candidateUnit->GetCreator() != sourceUnit) {
        continue;
      }

      if (!emittedUnits.insert(candidateUnit).second) {
        continue;
      }

      LuaPlus::LuaObject unitObject = candidateBridge->GetLuaObject();
      // 0x008BCB3E: `LuaObject::Insert(obj)` -- the Lua `table.insert(t, v)` append.
      resultTable.Insert(unitObject);
    }
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BCE70 (FUN_008BCE70, cfunc_GetIdleEngineers)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetIdleEngineersL`.
 */
int moho::cfunc_GetIdleEngineers(lua_State* const luaContext)
{
  return cfunc_GetIdleEngineersL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BCE90 (FUN_008BCE90, func_GetIdleEngineers_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetIdleEngineers`.
 */
moho::CScrLuaInitForm* moho::func_GetIdleEngineers_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetIdleEngineers",
    &moho::cfunc_GetIdleEngineers,
    nullptr,
    "<global>",
    kGetIdleEngineersHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BCEF0 (FUN_008BCEF0, cfunc_GetIdleEngineersL)
 *
 * What it does:
 * Returns one Lua array of focus-army idle engineer unit script objects.
 */
int moho::cfunc_GetIdleEngineersL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->GetFocusArmy() == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetIdleEngineersHelpText);

  WeakSet<UserUnit> idleUnits = session->GetFocusArmy()->GetIdleEngineers();
  if (idleUnits.Size() == 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(idleUnits.Size()), 0u);

  std::int32_t luaIndex = 1;
  for (UserUnit* const unit : idleUnits) {
    if (unit != nullptr) {
      LuaPlus::LuaObject unitObject = unit->GetLuaObject();
      resultTable.SetObject(luaIndex, unitObject);
      ++luaIndex;
    }
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD100 (FUN_008BD100, cfunc_GetIdleFactories)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetIdleFactoriesL`.
 */
int moho::cfunc_GetIdleFactories(lua_State* const luaContext)
{
  return cfunc_GetIdleFactoriesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD120 (FUN_008BD120, func_GetIdleFactories_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetIdleFactories`.
 */
moho::CScrLuaInitForm* moho::func_GetIdleFactories_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetIdleFactories",
    &moho::cfunc_GetIdleFactories,
    nullptr,
    "<global>",
    kGetIdleFactoriesHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD180 (FUN_008BD180, cfunc_GetIdleFactoriesL)
 *
 * What it does:
 * Returns one Lua array of focus-army idle factory unit script objects.
 */
int moho::cfunc_GetIdleFactoriesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->GetFocusArmy() == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetIdleFactoriesHelpText);

  WeakSet<UserUnit> idleUnits = session->GetFocusArmy()->GetIdleFactories();
  if (idleUnits.Size() == 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(idleUnits.Size()), 0u);

  std::int32_t luaIndex = 1;
  for (UserUnit* const unit : idleUnits) {
    if (unit != nullptr) {
      LuaPlus::LuaObject unitObject = unit->GetLuaObject();
      resultTable.SetObject(luaIndex, unitObject);
      ++luaIndex;
    }
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD680 (FUN_008BD680, cfunc_GetSelectedUnitsL)
 *
 * What it does:
 * Builds and returns a Lua array containing currently selected unit script objects.
 */
int moho::cfunc_GetSelectedUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetSelectedUnitsHelpText);

  fa::vector<UserUnit*> selectedUnits{};
  session->GetSelectionUnits(selectedUnits);
  if (selectedUnits.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(selectedUnits.size()), 0u);

  std::int32_t resultIndex = 1;
  for (UserUnit* const selectedUnit : selectedUnits) {
    IUnit* const iunitBridge = ResolveIUnitBridge(selectedUnit);
    if (!iunitBridge) {
      continue;
    }

    LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
    resultTable.SetObject(resultIndex, unitObject);
    ++resultIndex;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD600 (FUN_008BD600, cfunc_GetSelectedUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSelectedUnitsL`.
 */
int moho::cfunc_GetSelectedUnits(lua_State* const luaContext)
{
  return cfunc_GetSelectedUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD620 (FUN_008BD620, func_GetSelectedUnits_LuaFuncDef)
 *
 * What it does:
 * Creates/returns the global Lua binder form for `GetSelectedUnits`.
 */
moho::CScrLuaInitForm* moho::func_GetSelectedUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetSelectedUnits",
    &moho::cfunc_GetSelectedUnits,
    nullptr,
    "<global>",
    kGetSelectedUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD410 (FUN_008BD410, cfunc_GetValidAttackingUnitsL)
 *
 * IDA signature:
 * int __cdecl cfunc_GetValidAttackingUnitsL(LuaPlus::LuaState *state);
 *
 * What it does:
 * Builds and returns a Lua array of the currently-selected units that can attack
 * the hovered target (via `CWldSession::GetValidAttackingUnits`), each as its
 * script object. Returns nil when the set is empty.
 */
int moho::cfunc_GetValidAttackingUnitsL(LuaPlus::LuaState* const state)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 0, kGetValidAttackingUnitsHelpText);

  fa::vector<UserUnit*> validUnits{};
  session->GetValidAttackingUnits(validUnits);
  if (validUnits.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(validUnits.size()), 0u);

  std::int32_t resultIndex = 1;
  for (UserUnit* const validUnit : validUnits) {
    IUnit* const iunitBridge = ResolveIUnitBridge(validUnit);
    if (!iunitBridge) {
      continue;
    }

    LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
    resultTable.SetObject(resultIndex, unitObject);
    ++resultIndex;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD5C0 (FUN_008BD5C0, cfunc_GetValidAttackingUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetValidAttackingUnitsL`.
 */
int moho::cfunc_GetValidAttackingUnits(lua_State* const luaContext)
{
  return cfunc_GetValidAttackingUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD3B0 (FUN_008BD3B0, func_GetValidAttackingUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane global Lua binder form for `GetValidAttackingUnits`.
 */
moho::CScrLuaInitForm* moho::func_GetValidAttackingUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetValidAttackingUnits",
    &moho::cfunc_GetValidAttackingUnits,
    nullptr,
    "<global>",
    kGetValidAttackingUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD870 (FUN_008BD870, cfunc_SelectUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SelectUnitsL`.
 */
int moho::cfunc_SelectUnits(lua_State* const luaContext)
{
  return cfunc_SelectUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD890 (FUN_008BD890, func_SelectUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `SelectUnits`.
 */
moho::CScrLuaInitForm* moho::func_SelectUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "SelectUnits",
    &moho::cfunc_SelectUnits,
    nullptr,
    "<global>",
    kSelectUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD8F0 (FUN_008BD8F0, cfunc_SelectUnitsL)
 *
 * What it does:
 * Builds one validated selection set from Lua input units and applies it to
 * the world session. FAF hot-patch (FA-Binary-Patches SelecUnitsTableFix): the
 * result table's AssignNewTable (0x008BD9BF) and PushStack (0x008BDBA6) are
 * NOPed and 0x008BDC18 returns 0, so nothing is returned.
 */
int moho::cfunc_SelectUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kSelectUnitsHelpText);

  const LuaPlus::LuaObject sourceUnitsObject(LuaPlus::LuaStackObject(state, 1));

  fa::vector<UserUnit*> selectionUnits{};
  if (sourceUnitsObject.IsTable()) {
    const int unitCount = sourceUnitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = sourceUnitsObject[unitIndex];
      UserUnit* const userUnit = ResolveUserUnitOptional(unitObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead() || iunitBridge->DestroyQueued()) {
        continue;
      }

      UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
      if (userEntity != nullptr && userEntity->IsSelectable()) {
        AppendSelectionUnitUnique(selectionUnits, userUnit);
      } else if (UserUnit* const attachmentParent = ResolveSelectableTransportAttachmentParent(userUnit);
                 attachmentParent != nullptr) {
        AppendSelectionUnitUnique(selectionUnits, attachmentParent);
      }
    }
  }

  session->SetSelectionUnits(selectionUnits);
  return 0;
}

/**
 * Address: 0x008BDC30 (FUN_008BDC30, cfunc_AddSelectUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_AddSelectUnitsL`.
 */
int moho::cfunc_AddSelectUnits(lua_State* const luaContext)
{
  return cfunc_AddSelectUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BDC50 (FUN_008BDC50, func_AddSelectUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `AddSelectUnits`.
 */
moho::CScrLuaInitForm* moho::func_AddSelectUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "AddSelectUnits",
    &moho::cfunc_AddSelectUnits,
    nullptr,
    "<global>",
    kAddSelectUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BDCB0 (FUN_008BDCB0, cfunc_AddSelectUnitsL)
 *
 * What it does:
 * Adds validated selectable units from Lua input to current selection and
 * applies the merged set back into the world session.
 */
int moho::cfunc_AddSelectUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kAddSelectUnitsHelpText);

  const LuaPlus::LuaObject sourceUnitsObject(LuaPlus::LuaStackObject(state, 1));
  fa::vector<UserUnit*> mergedSelection{};
  session->GetSelectionUnits(mergedSelection);

  if (sourceUnitsObject.IsTable()) {
    const int unitCount = sourceUnitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = sourceUnitsObject[unitIndex];
      UserUnit* const userUnit = ResolveUserUnitOptional(unitObject, state);
      UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
      if (userEntity == nullptr || !userEntity->IsSelectable()) {
        continue;
      }
      AppendSelectionUnitUnique(mergedSelection, userUnit);
    }
  }

  session->SetSelectionUnits(mergedSelection);
  return 0;
}

/**
 * FAF FA-Binary-Patches (section/GetHighlightCommand.cpp, UIGetHighlightCommand):
 * `GetHighlightCommand() - return table of command or nil`.
 *
 * What it does:
 * For the command the cursor highlights (`CWldSession::HighlightCommandId`,
 * -1 for none), looked up in the session command manager
 * (`FindCommandIssueHelperInManager`, 0x008B5BB0), returns
 * `{commandType, x, y, z, commandId, targetId?, blueprintId?}`: the command
 * type, the target position, the id, the target entity id as a decimal string
 * unless it is the empty id 0xF0000000, and the build blueprint id when there
 * is one. Returns nothing otherwise.
 */
int moho::cfunc_GetHighlightCommand(lua_State* const luaContext)
{
  // The patch reads the session global without a check; without a session
  // there is nothing to highlight.
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return 0;
  }
  const CmdId commandId = session->HighlightCommandId;
  if (commandId == -1) {
    return 0;
  }
  const UserCommandIssueHelper* const command = FindCommandIssueHelper(session, commandId);
  if (command == nullptr) {
    return 0;
  }

  const auto setNumber = [luaContext](const char* const key, const lua_Number value) {
    lua_pushstring(luaContext, key);
    lua_pushnumber(luaContext, value);
    lua_rawset(luaContext, -3);
  };
  const SSTITarget& target = command->mVariableData.mTarget1;

  lua_newtable(luaContext);
  setNumber("commandType", static_cast<lua_Number>(static_cast<std::int32_t>(command->mVariableData.mCmdType)));
  setNumber("x", static_cast<lua_Number>(target.mPos.x));
  setNumber("y", static_cast<lua_Number>(target.mPos.y));
  setNumber("z", static_cast<lua_Number>(target.mPos.z));
  setNumber("commandId", static_cast<lua_Number>(commandId));

  constexpr std::uint32_t kNoTargetEntityId = 0xF0000000U;
  if (target.mEntityId != kNoTargetEntityId) {
    char targetIdText[16];
    std::snprintf(targetIdText, sizeof(targetIdText), "%d", static_cast<std::int32_t>(target.mEntityId));
    lua_pushstring(luaContext, "targetId");
    lua_pushstring(luaContext, targetIdText);
    lua_rawset(luaContext, -3);
  }

  if (const REntityBlueprint* const blueprint = command->mConstantData.blueprint; blueprint != nullptr) {
    lua_pushstring(luaContext, "blueprintId");
    lua_pushstring(luaContext, blueprint->mBlueprintId.c_str());
    lua_rawset(luaContext, -3);
  }
  return 1;
}

moho::CScrLuaInitForm* moho::func_GetHighlightCommand_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetHighlightCommand",
    &moho::cfunc_GetHighlightCommand,
    nullptr,
    "<global>",
    "GetHighlightCommand() - return table of command or nil"
  );
  return &binder;
}

/**
 * Address: 0x00843F20 (FUN_00843F20, cfunc_DeleteCommand)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_DeleteCommandL`.
 */
int moho::cfunc_DeleteCommand(lua_State* const luaContext)
{
  return cfunc_DeleteCommandL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00843F40 (FUN_00843F40, func_DeleteCommand_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `DeleteCommand`.
 */
moho::CScrLuaInitForm* moho::func_DeleteCommand_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "DeleteCommand",
    &moho::cfunc_DeleteCommand,
    nullptr,
    "<global>",
    kDeleteCommandHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843FA0 (FUN_00843FA0, cfunc_DeleteCommandL)
 *
 * What it does:
 * Looks up one command issue helper by Lua command id and marshals one
 * `DecreaseCommandCount` request through the active sim driver, then records
 * one local helper queue update for the same command id/count delta.
 */
int moho::cfunc_DeleteCommandL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  moho::SCR_ExpectExactArgs(state, 1, kDeleteCommandHelpText);

  const CmdId commandId = ReadLuaCommandIdArg(state, 1);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, "No active session!");
    return 0;
  }

  UserCommandIssueHelper* const commandIssue = FindCommandIssueHelper(session, commandId);
  if (!commandIssue) {
    return 0;
  }

  if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
    // The driver marshals the decrement and returns the resulting command
    // cookie; the event is queued with that cookie (FUN_00843FA0 passes the
    // DecreaseCommandCount result, not the input command id).
    const CmdId resultCookie = activeDriver->DecreaseCommandCount(commandIssue->mConstantData.cmd, 1);
    QueueCommandIssueDecreaseCountEvent(*commandIssue, resultCookie, 1);
  }

  return 0;
}

/**
 * Address: 0x00836980 (FUN_00836980, cfunc_DecreaseBuildCountInQueueL)
 *
 * IDA signature:
 * int __usercall cfunc_DecreaseBuildCountInQueueL@<eax>(LuaPlus::LuaState *a1@<eax>);
 *
 * What it does:
 * Lua worker for `DecreaseBuildCountInQueue(queueIndex, count)`. Reads the
 * 1-based factory build-queue item index and a decrement count, then walks that
 * item's queued command ids from the most recently queued command backward. For
 * each command still tracked by a live command-issue helper it marshals a
 * `DecreaseCommandCount` through the active sim driver (clamped to the helper's
 * remaining effective build count) and records the matching local decrease-count
 * update event, stopping once the requested count has been fully consumed.
 */
int moho::cfunc_DecreaseBuildCountInQueueL(LuaPlus::LuaState* const state)
{
  constexpr const char* kDecreaseBuildCountInQueueHelpText = "DecreaseBuildCountInQueue(queueIndex, count)";

  moho::SCR_ExpectExactArgs(state, 2, kDecreaseBuildCountInQueueHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, "No active session!");
    return 0;
  }

  LuaPlus::LuaStackObject queueIndexArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&queueIndexArg, "integer");
  }
  const int oneBasedQueueIndex = static_cast<int>(static_cast<std::int64_t>(lua_tonumber(state->m_state, 1)));

  LuaPlus::LuaStackObject countArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&countArg, "integer");
  }
  std::int32_t remaining = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));

  const CmdId* commandBegin = nullptr;
  const CmdId* commandEnd = nullptr;
  CurrentBuildQueueItemCommands(oneBasedQueueIndex, &commandBegin, &commandEnd);

  // Walk the item's queued command ids from the last-queued command backward.
  for (const CmdId* cursor = commandEnd; cursor != commandBegin; --cursor) {
    const CmdId commandId = *(cursor - 1);

    UserCommandIssueHelper* const helper = FindCommandIssueHelper(session, commandId);
    if (helper == nullptr) {
      continue;
    }

    const std::int32_t available = QueuedBuildCommandCount(*helper);
    std::int32_t take = remaining;
    if (remaining <= available) {
      remaining = 0;
    } else {
      take = available;
      remaining -= available;
    }

    // The driver marshals the decrement and returns the resulting command cookie;
    // the local event is queued with that cookie (not the input command id).
    ISTIDriver* const activeDriver = WLD_GetDriver();
    const CmdId resultCookie = activeDriver->DecreaseCommandCount(helper->mConstantData.cmd, take);
    QueueCommandIssueDecreaseCountEvent(*helper, resultCookie, take);

    if (remaining <= 0) {
      break;
    }
  }

  return 0;
}

/**
 * Address: 0x00836740 (FUN_00836740, cfunc_IncreaseBuildCountInQueueL)
 *
 * IDA signature:
 * int __usercall cfunc_IncreaseBuildCountInQueueL@<eax>(LuaPlus::LuaState *a1@<eax>);
 *
 * What it does:
 * Lua worker for `IncreaseBuildCountInQueue(queueIndex, count)`. Reads the 1-based
 * factory build-queue item index and a count, then walks that item's queued
 * command ids from the most recently queued command backward. Re-issues the first
 * live factory-build command found (helper present, resolved type == BuildFactory,
 * count > 0) via `ISSUE_IncreaseCommandCount(helper, count)` and stops.
 */
int moho::cfunc_IncreaseBuildCountInQueueL(LuaPlus::LuaState* const state)
{
  // Binary reuses the Decrease help string verbatim here (copy-paste in the
  // original 2007 source: luadef_IncreaseBuildCountInQueue.mHelp -> the Decrease
  // text, proven by the string xref at FUN_008366E0).
  constexpr const char* kIncreaseBuildCountInQueueHelpText = "DecreaseBuildCountInQueue(queueIndex, count)";

  moho::SCR_ExpectExactArgs(state, 2, kIncreaseBuildCountInQueueHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, "No active session!");
    return 0;
  }

  LuaPlus::LuaStackObject queueIndexArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&queueIndexArg, "integer");
  }
  const int oneBasedQueueIndex = static_cast<int>(static_cast<std::int64_t>(lua_tonumber(state->m_state, 1)));

  LuaPlus::LuaStackObject countArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&countArg, "integer");
  }
  const int count = static_cast<int>(lua_tonumber(state->m_state, 2));

  const CmdId* commandBegin = nullptr;
  const CmdId* commandEnd = nullptr;
  CurrentBuildQueueItemCommands(oneBasedQueueIndex, &commandBegin, &commandEnd);

  // Walk the item's queued command ids from the last-queued command backward,
  // re-issuing the first live factory-build command found and stopping.
  for (const CmdId* cursor = commandEnd; cursor != commandBegin; --cursor) {
    const CmdId commandId = *(cursor - 1);

    UserCommandIssueHelper* const helper = FindCommandIssueHelper(session, commandId);
    if (helper == nullptr) {
      continue;
    }

    if (ResolveCommandIssueHelperCommandType(*helper)
          == EUnitCommandType::UNITCOMMAND_BuildFactory
        && count > 0) {
      ISSUE_IncreaseCommandCount(helper, count);
      break;
    }
  }

  return 0;
}

/**
 * Address: 0x008471C0 (FUN_008471C0, cfunc_GenerateBuildTemplateFromSelection)
 *
 * IDA signature:
 * int __cdecl cfunc_GenerateBuildTemplateFromSelection(LuaPlus::LuaState *a1);
 *
 * What it does:
 * Lua callback for the global `GenerateBuildTemplateFromSelection()` binding.
 * Resolves the LuaPlus state wrapper (result unused) and, when a world session
 * is active, regenerates its build templates from the current selection.
 * Pushes no return values.
 */
int moho::cfunc_GenerateBuildTemplateFromSelection(lua_State* const luaContext)
{
  (void)LuaPlus::LuaState::CastState(luaContext);

  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    session->GenerateBuildTemplates();
  }

  return 0;
}

/**
 * Address: 0x008471F0 (FUN_008471F0, func_GenerateBuildTemplateFromSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GenerateBuildTemplateFromSelection()` Lua binder metadata.
 */
moho::CScrLuaInitForm* moho::func_GenerateBuildTemplateFromSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GenerateBuildTemplateFromSelection",
    &moho::cfunc_GenerateBuildTemplateFromSelection,
    nullptr,
    "<global>",
    kGenerateBuildTemplateFromSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847A20 (FUN_00847A20, cfunc_ClearBuildTemplates)
 *
 * What it does:
 * Clears user-session build-template state when a world session is active.
 */
int moho::cfunc_ClearBuildTemplates(lua_State* const luaContext)
{
  (void)LuaPlus::LuaState::CastState(luaContext);
  if (CWldSession* const session = WLD_GetActiveSession()) {
    session->ClearBuildTemplates();
  }
  return 0;
}

/**
 * Address: 0x00847A50 (FUN_00847A50, func_ClearBuildTemplates_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `ClearBuildTemplates`.
 */
moho::CScrLuaInitForm* moho::func_ClearBuildTemplates_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "ClearBuildTemplates",
    &moho::cfunc_ClearBuildTemplates,
    nullptr,
    "<global>",
    kClearBuildTemplatesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847E70 (FUN_00847E70, cfunc_GetUnitByIdUser)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUnitByIdUserL`.
 */
int moho::cfunc_GetUnitByIdUser(lua_State* const luaContext)
{
  return cfunc_GetUnitByIdUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00847E90 (FUN_00847E90, func_GetUnitByIdUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `GetUnitById`.
 */
moho::CScrLuaInitForm* moho::func_GetUnitByIdUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetUnitById",
    &moho::cfunc_GetUnitByIdUser,
    nullptr,
    "<global>",
    kGetUnitByIdUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847EF0 (FUN_00847EF0, cfunc_GetUnitByIdUserL)
 *
 * What it does:
 * Resolves one entity id through user-session map lanes and returns the
 * matching user-unit Lua object, or `nil` when no unit is found.
 */
int moho::cfunc_GetUnitByIdUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetUnitByIdUserHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  const LuaPlus::LuaStackObject entityIdArg(state, 1);
  const char* entityIdText = lua_tostring(rawState, 1);
  if (entityIdText == nullptr) {
    entityIdArg.TypeError("string");
    entityIdText = "";
  }

  const std::int32_t entityId = std::atoi(entityIdText);
  UserEntity* const entity = FindUserSessionEntityById(session, entityId);
  UserUnit* const userUnit = entity ? entity->IsUserUnit() : nullptr;
  if (userUnit == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  userUnit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x007B5170 (FUN_007B5170, cfunc_CreateUnitAtMouse)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CreateUnitAtMouseL`.
 */
int moho::cfunc_CreateUnitAtMouse(lua_State* const luaContext)
{
  return cfunc_CreateUnitAtMouseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007B5190 (FUN_007B5190, func_CreateUnitAtMouse_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CreateUnitAtMouse`.
 */
moho::CScrLuaInitForm* moho::func_CreateUnitAtMouse_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "CreateUnitAtMouse",
    &moho::cfunc_CreateUnitAtMouse,
    nullptr,
    "<global>",
    kCreateUnitAtMouseHelpText
  );
  return &binder;
}

/**
 * Address: 0x007B51E0 (FUN_007B51E0, cfunc_CreateUnitAtMouseL)
 *
 * What it does:
 * Reads `(blueprintId, armyIndex, offsetX, offsetZ, rotation)`, resolves one
 * unit blueprint, snaps non-mobile units to footprint-aligned map cells, and
 * submits one create-unit command through the active sim driver.
 */
int moho::cfunc_CreateUnitAtMouseL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 5, kCreateUnitAtMouseHelpText);

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, "No active session.");
    return 0;
  }

  LuaPlus::LuaStackObject blueprintArg(state, 1);
  const char* const blueprintText = lua_tostring(rawState, 1);
  if (!blueprintText) {
    LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
  }

  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintText ? blueprintText : "");

  RUnitBlueprint* const blueprint = session->mRules ? session->mRules->GetUnitBlueprint(lookupId) : nullptr;
  if (!blueprint) {
    LuaPlus::LuaState::Error(state, "Unknown unit kind: %s", blueprintText ? blueprintText : "");
    return 0;
  }

  LuaPlus::LuaStackObject armyIndexArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&armyIndexArg, "integer");
  }
  const int armyIndex = static_cast<int>(lua_tonumber(rawState, 2));

  const int armyCount = static_cast<int>(session->userArmies.size());
  if (armyIndex < 0 || armyIndex >= armyCount) {
    LuaPlus::LuaState::Error(
      state,
      "Invalid army index, must be >= 0 and < %d but got %d.",
      armyCount,
      armyIndex
    );
    return 0;
  }

  LuaPlus::LuaStackObject offsetZArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&offsetZArg, "number");
  }
  const float offsetZ = static_cast<float>(lua_tonumber(rawState, 4));

  LuaPlus::LuaStackObject offsetXArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&offsetXArg, "number");
  }
  const float offsetX = static_cast<float>(lua_tonumber(rawState, 3));

  SCoordsVec2 spawnPos{};
  spawnPos.x = session->CursorWorldPos.x + offsetX;
  spawnPos.z = session->CursorWorldPos.z + offsetZ;

  LuaPlus::LuaStackObject rotationArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&rotationArg, "number");
  }
  const float rotation = static_cast<float>(lua_tonumber(rawState, 5));

  if (!blueprint->IsMobile()) {
    Sim* const sim = ResolveGlobalSim(rawState);
    STIMap* const map = sim ? sim->mMapData : nullptr;
    if (map != nullptr) {
      const float anchorZ = spawnPos.z - (static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f);
      const float anchorX = spawnPos.x - (static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f);

      SOCellPos anchorCell{};
      anchorCell.x = static_cast<std::int16_t>(static_cast<int>(anchorX));
      anchorCell.z = static_cast<std::int16_t>(static_cast<int>(anchorZ));

      const Wm3::Vector3f alignedPos = COORDS_ToWorldPos(
        map,
        anchorCell,
        static_cast<ELayer>(blueprint->mFootprint.mOccupancyCaps),
        static_cast<int>(blueprint->mFootprint.mSizeX),
        static_cast<int>(blueprint->mFootprint.mSizeZ)
      );
      spawnPos.x = alignedPos.x;
      spawnPos.z = alignedPos.z;
    }
  }

  ISTIDriver* const activeDriver = WLD_GetDriver();
  if (activeDriver != nullptr) {
    RResId createId{};
    gpg::STR_CopyFilename(&createId.name, &blueprint->mBlueprintId);
    activeDriver->CreateUnit(static_cast<std::uint32_t>(armyIndex), createId, spawnPos, rotation);
  }

  return 0;
}
