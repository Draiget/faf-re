#include "moho/lua/CScrLuaInitForm.h"
#include "moho/unit/core/UserUnitPrivate.h"
#include "moho/lua/CScrLuaObjectFactory.h"

namespace
{

  constexpr const char* kLuaExpectedArgsRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kUserUnitCanAttackTargetName = "CanAttackTarget";
  constexpr const char* kUserUnitCanAttackTargetHelpText = "UserUnit:CanAttackTarget(target, rangeCheck)";
  constexpr const char* kUserUnitGetFootPrintSizeName = "GetFootPrintSize";
  constexpr const char* kUserUnitGetFootPrintSizeHelpText = "UserUnit:GetFootPrintSize()";
  constexpr const char* kUserUnitGetUnitIdName = "GetUnitId";
  constexpr const char* kUserUnitGetUnitIdHelpText = "UserUnit:GetUnitId()";
  constexpr const char* kUserUnitGetBlueprintName = "GetBlueprint";
  constexpr const char* kUserUnitGetBlueprintHelpText = "blueprint = UserUnit:GetBlueprint()";
  constexpr const char* kUserUnitIsAutoModeName = "IsAutoMode";
  constexpr const char* kUserUnitIsAutoModeHelpText = "bool = UserUnit:IsAutoMode()";
  constexpr const char* kUserUnitIsAutoSurfaceModeName = "IsAutoSurfaceMode";
  constexpr const char* kUserUnitIsAutoSurfaceModeHelpText = "bool = UserUnit:IsAutoSurfaceMode()";
  constexpr const char* kUserUnitIsRepeatQueueName = "IsRepeatQueue";
  constexpr const char* kUserUnitIsRepeatQueueHelpText = "bool = UserUnit:IsRepeatQueue()";
  constexpr const char* kUserUnitIsInCategoryName = "IsInCategory";
  constexpr const char* kUserUnitLuaClassName = "UserUnit";
  constexpr const char* kUserUnitIsInCategoryHelpText = "bool = UserUnit:IsInCategory(category)";
  constexpr const char* kUserUnitProcessInfoName = "ProcessInfo";
  constexpr const char* kUserUnitProcessInfoHelpText = "UserUnit:ProcessInfoPair()";
  constexpr const char* kUserUnitGetEntityIdName = "GetEntityId";
  constexpr const char* kUserUnitGetEntityIdHelpText = "Entity:GetEntityId()";
  constexpr const char* kUserUnitHasUnloadCommandQueuedUpName = "HasUnloadCommandQueuedUp";
  constexpr const char* kUserUnitHasUnloadCommandQueuedUpHelpText =
    "See if this unit already has an unload from transport queued up";
  constexpr const char* kUserUnitSetCustomNameName = "SetCustomName";
  constexpr const char* kUserUnitSetCustomNameHelpText = "SetCustomName(string) -- Set a custom name for the unit";
  constexpr const char* kUserUnitSetCustomNameInfoKey = "CustomName";
  constexpr const char* kUserUnitAddSelectionSetName = "AddSelectionSet";
  constexpr const char* kUserUnitAddSelectionSetHelpText = "AddSelectionSet(string) -- add a selection set name to a unit";
  constexpr const char* kUserUnitRemoveSelectionSetName = "RemoveSelectionSet";
  constexpr const char* kUserUnitRemoveSelectionSetHelpText =
    "RemoveSelectionSet(string) -- remove a selection set name from a unit";
  constexpr const char* kUserUnitGetSelectionSetsName = "GetSelectionSets";
  constexpr const char* kUserUnitGetSelectionSetsHelpText =
    "table GetSelectionSets() -- get table of all selection sets unit belongs to";
  constexpr const char* kUserUnitGetHealthName = "GetHealth";
  constexpr const char* kUserUnitGetHealthHelpText = "GetHealth() -- return current health";
  constexpr const char* kUserUnitGetMaxHealthName = "GetMaxHealth";
  constexpr const char* kUserUnitGetMaxHealthHelpText = "GetMaxHealth() -- return max health";
  constexpr const char* kUserUnitGetBuildRateName = "GetBuildRate";
  constexpr const char* kUserUnitGetBuildRateHelpText = "GetBuildRate() -- return current unit build rate";
  constexpr const char* kUserUnitIsOverchargePausedName = "IsOverchargePaused";
  constexpr const char* kUserUnitIsOverchargePausedHelpText =
    "IsOverchargePaused() -- return current overcharge paused status";
  constexpr const char* kUserUnitIsDeadName = "IsDead";
  constexpr const char* kUserUnitIsDeadHelpText = "IsDead() -- return true if the unit has been destroyed";
  constexpr const char* kUserUnitGetFuelRatioName = "GetFuelRatio";
  constexpr const char* kUserUnitGetFuelRatioHelpText = "GetFuelRatio()";
  constexpr const char* kUserUnitGetShieldRatioName = "GetShieldRatio";
  constexpr const char* kUserUnitGetShieldRatioHelpText = "GetShieldRatio()";
  constexpr const char* kUserUnitGetWorkProgressName = "GetWorkProgress";
  constexpr const char* kUserUnitGetWorkProgressHelpText = "GetWorkProgress()";
  constexpr const char* kUserUnitGetStatName = "GetStat";
  constexpr const char* kUserUnitGetStatHelpText = "GetStat(Name[,defaultVal])";
  constexpr const char* kUserUnitIsStunnedName = "IsStunned";
  constexpr const char* kUserUnitIsStunnedHelpText = "flag = UserUnit:IsStunned()";
  constexpr const char* kUserUnitGetCustomNameName = "GetCustomName";
  constexpr const char* kUserUnitGetCustomNameHelpText =
    "string GetCustomName() -- get the current custom name, nil if none";
  constexpr const char* kUserUnitHasSelectionSetName = "HasSelectionSet";
  constexpr const char* kUserUnitHasSelectionSetHelpText =
    "bool HasSelectionSet(string) -- see if a unit belongs to a given selection set";
  constexpr const char* kUserUnitIsIdleName = "IsIdle";
  constexpr const char* kUserUnitIsIdleHelpText = "IsIdle() -- return true if the unit is idle";
  constexpr const char* kUserUnitGetFocusName = "GetFocus";
  constexpr const char* kUserUnitGetFocusHelpText = "GetFocus() -- returns the unit this unit is currently focused on, or nil";
  constexpr const char* kUserUnitGetGuardedEntityName = "GetGuardedEntity";
  constexpr const char* kUserUnitGetGuardedEntityHelpText =
    "GetGuardedEntity() -- returns the units guard target, or nil";
  constexpr const char* kUserUnitGetCreatorName = "GetCreator";
  constexpr const char* kUserUnitGetCreatorHelpText = "GetCreator() -- returns the units creator, or nil";
  constexpr const char* kUserUnitGetPositionName = "GetPosition";
  constexpr const char* kUserUnitGetPositionHelpText = "VECTOR3 GetPosition() - returns the current world posititon of the unit";
  constexpr const char* kUserUnitGetArmyName = "GetArmy";
  constexpr const char* kUserUnitGetArmyHelpText = "GetArmy() -- returns the army index";
  constexpr const char* kUserUnitGetEconDataName = "GetEconData";
  constexpr const char* kUserUnitGetEconDataHelpText = "GetEconData() - returns a table of economy data";
  constexpr const char* kUserUnitGetCommandQueueName = "GetCommandQueue";
  constexpr const char* kUserUnitGetCommandQueueHelpText = "table GetCommandQueue() - returns table of commands ";
  constexpr const char* kUserUnitGetMissileInfoName = "GetMissileInfo";
  constexpr const char* kUserUnitGetMissileInfoHelpText =
    "table GetMissileInfo() - returns a table of the missile info for this unit";
  constexpr const char* kSetCurrentFactoryForQueueDisplayName = "SetCurrentFactoryForQueueDisplay";
  constexpr const char* kSetCurrentFactoryForQueueDisplayHelpText =
    "currentQueueTable SetCurrentFactoryForQueueDisplay(unit)";
  constexpr const char* kGetBlueprintUserName = "GetBlueprint";
  constexpr const char* kGetBlueprintUserHelpText = "blueprint = GetBlueprint()";
  constexpr const char* kCommandQueueIdKey = "ID";
  constexpr const char* kCommandQueueTypeKey = "type";
  constexpr const char* kCommandQueuePositionKey = "position";
  constexpr const char* kFactoryQueueItemIdKey = "id";
  constexpr const char* kFactoryQueueItemCountKey = "count";
  constexpr const char* kShowQueueCategoryName = "SHOWQUEUE";
  constexpr const char* kEconEnergyConsumedKey = "energyConsumed";
  constexpr const char* kEconMassConsumedKey = "massConsumed";
  constexpr const char* kEconEnergyRequestedKey = "energyRequested";
  constexpr const char* kEconMassRequestedKey = "massRequested";
  constexpr const char* kEconEnergyProducedKey = "energyProduced";
  constexpr const char* kEconMassProducedKey = "massProduced";
  constexpr const char* kMissileTacticalBuildCountKey = "tacticalSiloBuildCount";
  constexpr const char* kMissileTacticalStorageCountKey = "tacticalSiloStorageCount";
  constexpr const char* kMissileTacticalMaxStorageCountKey = "tacticalSiloMaxStorageCount";
  constexpr const char* kMissileNukeBuildCountKey = "nukeSiloBuildCount";
  constexpr const char* kMissileNukeStorageCountKey = "nukeSiloStorageCount";
  constexpr const char* kMissileNukeMaxStorageCountKey = "nukeSiloMaxStorageCount";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";
  constexpr float kEconomyPerSecondToUiRate = 10.0f;

  [[nodiscard]] bool IsFactoryQueueCommandType(const EUnitCommandType commandType) noexcept
  {
    return commandType == EUnitCommandType::UNITCOMMAND_BuildFactory
      || commandType == EUnitCommandType::UNITCOMMAND_BuildMobile
      || commandType == EUnitCommandType::UNITCOMMAND_Upgrade;
  }

  /**
   * Address: 0x00836EF0 (FUN_00836EF0, sub_836EF0)
   *
   * IDA signature:
   * void __usercall sub_836EF0(gpg::fastvector_BuildQueueItem *queue@<eax>,
   *                            struct_BuildQueueItem *item@<ecx>);
   *
   * What it does:
   * Appends one queue-display row to the caller's factory queue vector, growing
   * the 0x30-stride buffer when the live size has reached capacity.
   */
  void AppendFactoryQueueDisplayItem(
    FactoryQueueDisplaySnapshot& queueItems,
    const FactoryQueueDisplayItem& item
  )
  {
    queueItems.push_back(item);
  }

  /**
   * Address: 0x0052B1E0 (FUN_0052B1E0, RRuleGameRulesImpl::GetEntityCategory)
   *
   * What it does:
   * Resolves the `SHOWQUEUE` entity category from the active session's rules and
   * reports whether the unit's blueprint ordinal is a member. `0x00835E47` loads
   * `sWldSession->mRules`, dispatches vtable slot 22 (+0x58) with the literal
   * `"SHOWQUEUE"`, then `0x00835E5C` reads the unit's blueprint through the
   * `IUnit` sub-object's slot 7 (+0x1C) and bit-tests the returned category's
   * word range at `+0x08` (first word index) / `+0x10`..`+0x14` (word range).
   */
  [[nodiscard]] bool IsFactoryQueueDisplayEnabledForUnit(const UserUnit* const userUnit) noexcept
  {
    const CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr || session->mRules == nullptr) {
      return false;
    }

    const EntityCategorySet* const showQueueCategory =
      session->mRules->GetEntityCategory(kShowQueueCategoryName);
    if (showQueueCategory == nullptr) {
      return false;
    }

    const IUnit* const unitBridge = userUnit;
    const RUnitBlueprint* const blueprint = unitBridge->GetBlueprint();
    if (blueprint == nullptr) {
      return false;
    }

    return showQueueCategory->ContainsBit(blueprint->mCategoryBitIndex);
  }

  [[nodiscard]] const UserCommandQueue* SelectActiveQueue(const UserUnit* const userUnit) noexcept
  {
    if (const UserCommandQueue* const factoryQueue = userUnit->GetFactoryCommandQueue();
        factoryQueue != nullptr) {
      return factoryQueue;
    }

    return userUnit->GetCommandQueue();
  }

  [[nodiscard]] const UserUnit* ResolveAttachmentParentUserUnit(UserUnit* const userUnit) noexcept
  {
    if (userUnit == nullptr) {
      return nullptr;
    }

    UserEntity* const entityView = userUnit;
    const std::int32_t attachmentParentId = static_cast<std::int32_t>(entityView->mVariableData.mAttachmentParentRef);
    if (attachmentParentId == 0) {
      return nullptr;
    }

    UserEntity* const attachmentParentEntity = FindSessionEntityById(entityView->mSession, attachmentParentId);
    return attachmentParentEntity ? attachmentParentEntity->IsUserUnit() : nullptr;
  }

  [[nodiscard]] bool TransportHasQueuedUnloadCommand(const UserUnit& transportUserUnit) noexcept
  {
    const IUnit* const iunitBridge = GetIUnitBridge(&transportUserUnit);
    const Unit* const unit = iunitBridge ? iunitBridge->IsUnit() : nullptr;
    const CUnitCommandQueue* const commandQueue = unit ? unit->CommandQueue : nullptr;
    if (commandQueue == nullptr) {
      return false;
    }

    for (const WeakPtr<CUnitCommand>& weakCommand : commandQueue->mCommandVec) {
      const CUnitCommand* const command = weakCommand.GetObjectPtr();
      if (command == nullptr) {
        continue;
      }

      const EUnitCommandType commandType = command->mVarDat.mCmdType;
      if (commandType == EUnitCommandType::UNITCOMMAND_TransportUnloadUnits) {
        return true;
      }

      if (
        commandType == EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits
        && !command->mVarDat.mEntIds.empty()
      ) {
        return true;
      }
    }

    return false;
  }
}

namespace moho
{
  /**
   * Address: 0x008377E0 (FUN_008377E0, func_GetUserUnitOpt)
   *
   * What it does:
   * Converts one Lua object to `UserUnit*`, raising Lua errors for missing or
   * type-mismatched game-object payloads while allowing destroyed-object slots.
   */
  [[nodiscard]] UserUnit*
  GetUserUnitOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
  {
    CScriptObject** const scriptObjectSlot = SCR_FromLua_CScriptObject(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUserUnitType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<UserUnit*>(upcast.mObj);
  }
}

namespace
{

}


CScrLuaMetatableFactory<UserUnit>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

CScrLuaMetatableFactory<UserUnit>& CScrLuaMetatableFactory<UserUnit>::Instance()
{
  return sInstance;
}
namespace moho
{

  CScrLuaMetatableFactory<UserUnit>* startup_CScrLuaMetatableFactory_UserUnit_Index()
  {
    auto& instance = CScrLuaMetatableFactory<UserUnit>::Instance();
    instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }
}


/**
 * Address: 0x008C5CD0 (FUN_008C5CD0, Moho::CScrLuaMetatableFactory<Moho::UserUnit>::Create)
 *
 * What it does:
 * Builds the simple Lua metatable used for `UserUnit` userdata bindings.
 */
LuaPlus::LuaObject CScrLuaMetatableFactory<UserUnit>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x008C2010 (FUN_008C2010, cfunc_UserUnitCanAttackTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitCanAttackTargetL`.
 */
int moho::cfunc_UserUnitCanAttackTarget(lua_State* const luaContext)
{
  return cfunc_UserUnitCanAttackTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2030 (FUN_008C2030, func_UserUnitCanAttackTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:CanAttackTarget(target, rangeCheck)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitCanAttackTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitCanAttackTargetName,
    &moho::cfunc_UserUnitCanAttackTarget,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitCanAttackTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2090 (FUN_008C2090, cfunc_UserUnitCanAttackTargetL)
 *
 * What it does:
 * Resolves one user-unit, one target-entity, and one range-check flag; then
 * pushes whether the unit can attack that target.
 */
int moho::cfunc_UserUnitCanAttackTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kUserUnitCanAttackTargetHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const LuaPlus::LuaObject targetEntityObject(LuaPlus::LuaStackObject(state, 2));
  UserEntity* const targetEntity = SCR_FromLua_UserEntity(targetEntityObject, state);
  const bool rangeCheck = LuaPlus::LuaStackObject(state, 3).GetBoolean();
  (void)GetIUnitBridge(userUnit)->GetBlueprint();

  const bool canAttack = targetEntity != nullptr && userUnit->CanAttackTarget(targetEntity, rangeCheck);
  lua_pushboolean(rawState, canAttack ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C21D0 (FUN_008C21D0, cfunc_UserUnitGetFootPrintSize)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitGetFootPrintSizeL`.
 */
int moho::cfunc_UserUnitGetFootPrintSize(lua_State* const luaContext)
{
  return cfunc_UserUnitGetFootPrintSizeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C21F0 (FUN_008C21F0, func_UserUnitGetFootPrintSize_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetFootPrintSize()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetFootPrintSize_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetFootPrintSizeName,
    &moho::cfunc_UserUnitGetFootPrintSize,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetFootPrintSizeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2250 (FUN_008C2250, cfunc_UserUnitGetFootPrintSizeL)
 *
 * What it does:
 * Returns the larger footprint axis (`max(SizeX, SizeZ)`) for one user unit.
 */
int moho::cfunc_UserUnitGetFootPrintSizeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetFootPrintSizeHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const RUnitBlueprint* const blueprint = GetIUnitBridge(userUnit)->GetBlueprint();
  const std::uint8_t sizeX = blueprint->mFootprint.mSizeX;
  const std::uint8_t sizeZ = blueprint->mFootprint.mSizeZ;
  const std::uint8_t maxSize = sizeX < sizeZ ? sizeZ : sizeX;
  lua_pushnumber(rawState, static_cast<float>(maxSize));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2340 (FUN_008C2340, cfunc_UserUnitGetUnitId)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetUnitIdL`.
 */
int moho::cfunc_UserUnitGetUnitId(lua_State* const luaContext)
{
  return cfunc_UserUnitGetUnitIdL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2360 (FUN_008C2360, func_UserUnitGetUnitId_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetUnitId()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetUnitId_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetUnitIdName,
    &moho::cfunc_UserUnitGetUnitId,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetUnitIdHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C23C0 (FUN_008C23C0, cfunc_UserUnitGetUnitIdL)
 *
 * What it does:
 * Pushes one user-unit blueprint id string.
 */
int moho::cfunc_UserUnitGetUnitIdL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetUnitIdHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const RUnitBlueprint* const blueprint = GetIUnitBridge(userUnit)->GetBlueprint();
  lua_pushstring(rawState, blueprint->mBlueprintId.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2620 (FUN_008C2620, cfunc_UserUnitGetBlueprint)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetBlueprintL`.
 */
int moho::cfunc_UserUnitGetBlueprint(lua_State* const luaContext)
{
  return cfunc_UserUnitGetBlueprintL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2640 (FUN_008C2640, func_UserUnitGetBlueprint_LuaFuncDef)
 *
 * What it does:
 * Publishes the `blueprint = UserUnit:GetBlueprint()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetBlueprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetBlueprintName,
    &moho::cfunc_UserUnitGetBlueprint,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetBlueprintHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C26A0 (FUN_008C26A0, cfunc_UserUnitGetBlueprintL)
 *
 * What it does:
 * Resolves one user unit and pushes its Lua blueprint object.
 */
int moho::cfunc_UserUnitGetBlueprintL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetBlueprintHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const RUnitBlueprint* const blueprint = GetIUnitBridge(userUnit)->GetBlueprint();
  LuaPlus::LuaObject luaBlueprint = blueprint->GetLuaBlueprint(state);
  luaBlueprint.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C2B60 (FUN_008C2B60, cfunc_UserUnitIsAutoMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsAutoModeL`.
 */
int moho::cfunc_UserUnitIsAutoMode(lua_State* const luaContext)
{
  return cfunc_UserUnitIsAutoModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2B80 (FUN_008C2B80, func_UserUnitIsAutoMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsAutoMode()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsAutoMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitIsAutoModeName,
    &moho::cfunc_UserUnitIsAutoMode,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsAutoModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2BE0 (FUN_008C2BE0, cfunc_UserUnitIsAutoModeL)
 *
 * What it does:
 * Pushes one user-unit auto-mode flag.
 */
int moho::cfunc_UserUnitIsAutoModeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitIsAutoModeHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, userUnit->GetAutoMode() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2CA0 (FUN_008C2CA0, cfunc_UserUnitIsAutoSurfaceMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitIsAutoSurfaceModeL`.
 */
int moho::cfunc_UserUnitIsAutoSurfaceMode(lua_State* const luaContext)
{
  return cfunc_UserUnitIsAutoSurfaceModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2CC0 (FUN_008C2CC0, func_UserUnitIsAutoSurfaceMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsAutoSurfaceMode()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsAutoSurfaceMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitIsAutoSurfaceModeName,
    &moho::cfunc_UserUnitIsAutoSurfaceMode,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsAutoSurfaceModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2D20 (FUN_008C2D20, cfunc_UserUnitIsAutoSurfaceModeL)
 *
 * What it does:
 * Pushes one user-unit auto-surface-mode flag.
 */
int moho::cfunc_UserUnitIsAutoSurfaceModeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitIsAutoSurfaceModeHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, userUnit->IsAutoSurfaceMode() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2DE0 (FUN_008C2DE0, cfunc_UserUnitIsRepeatQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsRepeatQueueL`.
 */
int moho::cfunc_UserUnitIsRepeatQueue(lua_State* const luaContext)
{
  return cfunc_UserUnitIsRepeatQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2E00 (FUN_008C2E00, func_UserUnitIsRepeatQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsRepeatQueue()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsRepeatQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitIsRepeatQueueName,
    &moho::cfunc_UserUnitIsRepeatQueue,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsRepeatQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2E60 (FUN_008C2E60, cfunc_UserUnitIsRepeatQueueL)
 *
 * What it does:
 * Pushes one user-unit repeat-queue flag.
 */
int moho::cfunc_UserUnitIsRepeatQueueL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitIsRepeatQueueHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, userUnit->IsRepeatQueueEnabled() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C24A0 (FUN_008C24A0, cfunc_UserUnitGetEntityId)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_UserUnitGetEntityIdL`.
 */
int moho::cfunc_UserUnitGetEntityId(lua_State* const luaContext)
{
  return cfunc_UserUnitGetEntityIdL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C24C0 (FUN_008C24C0, func_UserUnitGetEntityId_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetEntityId()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetEntityId_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetEntityIdName,
    &moho::cfunc_UserUnitGetEntityId,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetEntityIdHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2520 (FUN_008C2520, cfunc_UserUnitGetEntityIdL)
 *
 * What it does:
 * Validates one `UserUnit` argument and pushes the unit entity id as string.
 */
int moho::cfunc_UserUnitGetEntityIdL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetEntityIdHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserEntity* const entityView = userUnit;
  const std::int32_t entityId = entityView != nullptr ? static_cast<std::int32_t>(entityView->mParams.mEntityId) : 0;
  const fa::string entityIdText = gpg::STR_Printf("%d", entityId);

  const char* const entityIdChars = entityIdText.c_str();
  lua_pushstring(rawState, entityIdChars ? entityIdChars : "");
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C2790 (FUN_008C2790, cfunc_UserUnitHasUnloadCommandQueuedUp)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitHasUnloadCommandQueuedUpL`.
 */
int moho::cfunc_UserUnitHasUnloadCommandQueuedUp(lua_State* const luaContext)
{
  return cfunc_UserUnitHasUnloadCommandQueuedUpL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C27B0 (FUN_008C27B0, func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:HasUnloadCommandQueuedUp()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitHasUnloadCommandQueuedUpName,
    &moho::cfunc_UserUnitHasUnloadCommandQueuedUp,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitHasUnloadCommandQueuedUpHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2810 (FUN_008C2810, cfunc_UserUnitHasUnloadCommandQueuedUpL)
 *
 * What it does:
 * Returns whether the transport this unit is attached to already has an
 * unload command queued.
 */
int moho::cfunc_UserUnitHasUnloadCommandQueuedUpL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitHasUnloadCommandQueuedUpHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserUnit* const attachmentParentUserUnit = ResolveAttachmentParentUserUnit(userUnit);

  const bool hasUnloadCommandQueued =
    attachmentParentUserUnit != nullptr && TransportHasQueuedUnloadCommand(*attachmentParentUserUnit);
  lua_pushboolean(rawState, hasUnloadCommandQueued ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C29D0 (FUN_008C29D0, cfunc_UserUnitProcessInfo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitProcessInfoL`.
 */
int moho::cfunc_UserUnitProcessInfo(lua_State* const luaContext)
{
  return cfunc_UserUnitProcessInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C29F0 (FUN_008C29F0, func_UserUnitProcessInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:ProcessInfoPair(key, value)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitProcessInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitProcessInfoName,
    &moho::cfunc_UserUnitProcessInfo,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitProcessInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2A50 (FUN_008C2A50, cfunc_UserUnitProcessInfoL)
 *
 * What it does:
 * Validates one `UserUnit`, one key string, and one value string, then
 * forwards the pair through `ISTIDriver::ProcessInfoPair`.
 */
int moho::cfunc_UserUnitProcessInfoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kUserUnitProcessInfoHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  UserEntity* const entityView = userUnit;

  const LuaPlus::LuaStackObject keyArg(state, 2);
  const char* infoKey = lua_tostring(rawState, 2);
  if (infoKey == nullptr) {
    keyArg.TypeError("string");
    infoKey = "";
  }

  const LuaPlus::LuaStackObject valueArg(state, 3);
  const char* infoValue = lua_tostring(rawState, 3);
  if (infoValue == nullptr) {
    valueArg.TypeError("string");
    infoValue = "";
  }

  if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
    activeDriver->ProcessInfoPair(
      entityView->mParams.mEntityId,
      infoKey,
      infoValue
    );
  }

  return 0;
}

/**
 * Address: 0x008C3580 (FUN_008C3580, cfunc_UserUnitSetCustomName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitSetCustomNameL`.
 */
int moho::cfunc_UserUnitSetCustomName(lua_State* const luaContext)
{
  return cfunc_UserUnitSetCustomNameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C35A0 (FUN_008C35A0, func_UserUnitSetCustomName_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:SetCustomName(name)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitSetCustomName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitSetCustomNameName,
    &moho::cfunc_UserUnitSetCustomName,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitSetCustomNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3600 (FUN_008C3600, cfunc_UserUnitSetCustomNameL)
 *
 * What it does:
 * Validates one `UserUnit` plus name string, then forwards
 * `("CustomName", name)` through `ISTIDriver::ProcessInfoPair`.
 */
int moho::cfunc_UserUnitSetCustomNameL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUserUnitSetCustomNameHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  if (userUnit == nullptr) {
    return 0;
  }

  const LuaPlus::LuaStackObject nameArg(state, 2);
  const char* customName = lua_tostring(rawState, 2);
  if (customName == nullptr) {
    nameArg.TypeError("string");
    customName = "";
  }

  UserEntity* const entityView = userUnit;
  if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
    activeDriver->ProcessInfoPair(
      entityView->mParams.mEntityId,
      kUserUnitSetCustomNameInfoKey,
      customName
    );
  }

  return 0;
}

/**
 * Address: 0x008C3880 (FUN_008C3880, cfunc_UserUnitAddSelectionSet)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitAddSelectionSetL`.
 */
int moho::cfunc_UserUnitAddSelectionSet(lua_State* const luaContext)
{
  return cfunc_UserUnitAddSelectionSetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C38A0 (FUN_008C38A0, func_UserUnitAddSelectionSet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:AddSelectionSet(name)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitAddSelectionSet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitAddSelectionSetName,
    &moho::cfunc_UserUnitAddSelectionSet,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitAddSelectionSetHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3900 (FUN_008C3900, cfunc_UserUnitAddSelectionSetL)
 *
 * What it does:
 * Resolves one `UserUnit` plus one selection-set name and inserts the name
 * into the unit's selection-set container.
 */
int moho::cfunc_UserUnitAddSelectionSetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUserUnitAddSelectionSetHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  if (userUnit == nullptr) {
    return 0;
  }

  const LuaPlus::LuaStackObject selectionSetArg(state, 2);
  const char* selectionSetName = lua_tostring(rawState, 2);
  if (selectionSetName == nullptr) {
    selectionSetArg.TypeError("string");
    selectionSetName = "";
  }

  userUnit->AddSelectionSet(selectionSetName);
  return 0;
}

/**
 * Address: 0x008C39E0 (FUN_008C39E0, cfunc_UserUnitRemoveSelectionSet)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitRemoveSelectionSetL`.
 */
int moho::cfunc_UserUnitRemoveSelectionSet(lua_State* const luaContext)
{
  return cfunc_UserUnitRemoveSelectionSetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3A00 (FUN_008C3A00, func_UserUnitRemoveSelectionSet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:RemoveSelectionSet(name)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitRemoveSelectionSet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitRemoveSelectionSetName,
    &moho::cfunc_UserUnitRemoveSelectionSet,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitRemoveSelectionSetHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3A60 (FUN_008C3A60, cfunc_UserUnitRemoveSelectionSetL)
 *
 * What it does:
 * Resolves one `UserUnit` plus one selection-set name and erases that name
 * from the unit's selection-set container.
 */
int moho::cfunc_UserUnitRemoveSelectionSetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUserUnitRemoveSelectionSetHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  if (userUnit == nullptr) {
    return 0;
  }

  const LuaPlus::LuaStackObject selectionSetArg(state, 2);
  const char* selectionSetName = lua_tostring(rawState, 2);
  if (selectionSetName == nullptr) {
    selectionSetArg.TypeError("string");
    selectionSetName = "";
  }

  userUnit->RemoveSelectionSet(selectionSetName);
  return 0;
}

/**
 * Address: 0x008C3CD0 (FUN_008C3CD0, cfunc_UserUnitGetSelectionSets)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitGetSelectionSetsL`.
 */
int moho::cfunc_UserUnitGetSelectionSets(lua_State* const luaContext)
{
  return cfunc_UserUnitGetSelectionSetsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3CF0 (FUN_008C3CF0, func_UserUnitGetSelectionSets_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetSelectionSets()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetSelectionSets_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetSelectionSetsName,
    &moho::cfunc_UserUnitGetSelectionSets,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetSelectionSetsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3D50 (FUN_008C3D50, cfunc_UserUnitGetSelectionSetsL)
 *
 * What it does:
 * Returns a Lua array of selection-set names currently attached to one
 * `UserUnit`.
 */
int moho::cfunc_UserUnitGetSelectionSetsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetSelectionSetsHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  if (userUnit == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable;
  resultTable.AssignNewTable(state, static_cast<int>(userUnit->mSelectionSets.size()), 0);

  int luaIndex = 1;
  for (const fa::string& selectionSetName : userUnit->mSelectionSets) {
    resultTable.SetString(luaIndex++, selectionSetName.c_str());
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C2F20 (FUN_008C2F20, cfunc_UserUnitIsInCategory)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitIsInCategoryL`.
 */
int moho::cfunc_UserUnitIsInCategory(lua_State* const luaContext)
{
  return cfunc_UserUnitIsInCategoryL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C2F40 (FUN_008C2F40, func_UserUnitIsInCategory_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsInCategory(category)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitIsInCategory_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitIsInCategoryName,
    &moho::cfunc_UserUnitIsInCategory,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsInCategoryHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C2FA0 (FUN_008C2FA0, cfunc_UserUnitIsInCategoryL)
 *
 * What it does:
 * Validates one category string and returns whether the input user-unit is
 * a member of that category.
 */
int moho::cfunc_UserUnitIsInCategoryL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUserUnitIsInCategoryHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  const LuaPlus::LuaStackObject categoryArg(state, 2);
  const char* categoryText = lua_tostring(rawState, 2);
  if (categoryText == nullptr) {
    categoryArg.TypeError("string");
    categoryText = "";
  }

  const fa::string category(categoryText);
  const UserEntity* const entityView = userUnit;
  const bool inCategory = entityView != nullptr && entityView->IsInCategory(category);
  lua_pushboolean(rawState, inCategory ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C3EA0 (FUN_008C3EA0, cfunc_UserUnitGetHealth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetHealthL`.
 */
int moho::cfunc_UserUnitGetHealth(lua_State* const luaContext)
{
  return cfunc_UserUnitGetHealthL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3EC0 (FUN_008C3EC0, func_UserUnitGetHealth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetHealth()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetHealth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetHealthName,
    &moho::cfunc_UserUnitGetHealth,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetHealthHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3F20 (FUN_008C3F20, cfunc_UserUnitGetHealthL)
 *
 * What it does:
 * Returns current health for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetHealthL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetHealthHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserEntity* const entityView = userUnit;
  lua_pushnumber(rawState, entityView->mVariableData.mHealth);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C3FE0 (FUN_008C3FE0, cfunc_UserUnitGetMaxHealth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetMaxHealthL`.
 */
int moho::cfunc_UserUnitGetMaxHealth(lua_State* const luaContext)
{
  return cfunc_UserUnitGetMaxHealthL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4000 (FUN_008C4000, func_UserUnitGetMaxHealth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetMaxHealth()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetMaxHealth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetMaxHealthName,
    &moho::cfunc_UserUnitGetMaxHealth,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetMaxHealthHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4060 (FUN_008C4060, cfunc_UserUnitGetMaxHealthL)
 *
 * What it does:
 * Returns max health for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetMaxHealthL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetMaxHealthHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const UserEntity* const entityView = userUnit;
  lua_pushnumber(rawState, entityView->mVariableData.mMaxHealth);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4120 (FUN_008C4120, cfunc_UserUnitGetBuildRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetBuildRateL`.
 */
int moho::cfunc_UserUnitGetBuildRate(lua_State* const luaContext)
{
  return cfunc_UserUnitGetBuildRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4140 (FUN_008C4140, func_UserUnitGetBuildRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetBuildRate()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetBuildRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetBuildRateName,
    &moho::cfunc_UserUnitGetBuildRate,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetBuildRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C41A0 (FUN_008C41A0, cfunc_UserUnitGetBuildRateL)
 *
 * What it does:
 * Returns current build-rate value for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetBuildRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetBuildRateHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const IUnit* const iunit = GetIUnitBridge(userUnit);
  const UnitAttributes& attributes = iunit->GetAttributes();
  lua_pushnumber(rawState, static_cast<lua_Number>(attributes.buildRate));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4270 (FUN_008C4270, cfunc_UserUnitIsOverchargePaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsOverchargePausedL`.
 */
int moho::cfunc_UserUnitIsOverchargePaused(lua_State* const luaContext)
{
  return cfunc_UserUnitIsOverchargePausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4290 (FUN_008C4290, func_UserUnitIsOverchargePaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsOverchargePaused()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitIsOverchargePaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitIsOverchargePausedName,
    &moho::cfunc_UserUnitIsOverchargePaused,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsOverchargePausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C42F0 (FUN_008C42F0, cfunc_UserUnitIsOverchargePausedL)
 *
 * What it does:
 * Returns overcharge-paused state for one user-unit as Lua boolean.
 */
int moho::cfunc_UserUnitIsOverchargePausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitIsOverchargePausedHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, userUnit->IsOverchargePaused() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C43B0 (FUN_008C43B0, cfunc_UserUnitIsDead)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsDeadL`.
 */
int moho::cfunc_UserUnitIsDead(lua_State* const luaContext)
{
  return cfunc_UserUnitIsDeadL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C43D0 (FUN_008C43D0, func_UserUnitIsDead_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsDead()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitIsDead_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitIsDeadName,
    &moho::cfunc_UserUnitIsDead,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsDeadHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4430 (FUN_008C4430, cfunc_UserUnitIsDeadL)
 *
 * What it does:
 * Returns true when input user-unit is missing or reports dead.
 */
int moho::cfunc_UserUnitIsDeadL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitIsDeadHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  const bool isDead = (userUnit == nullptr) || GetIUnitBridge(userUnit)->IsDead();
  lua_pushboolean(rawState, isDead ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4DA0 (FUN_008C4DA0, cfunc_UserUnitGetFuelRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetFuelRatioL`.
 */
int moho::cfunc_UserUnitGetFuelRatio(lua_State* const luaContext)
{
  return cfunc_UserUnitGetFuelRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4DC0 (FUN_008C4DC0, func_UserUnitGetFuelRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetFuelRatio()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetFuelRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetFuelRatioName,
    &moho::cfunc_UserUnitGetFuelRatio,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetFuelRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4E20 (FUN_008C4E20, cfunc_UserUnitGetFuelRatioL)
 *
 * What it does:
 * Returns current fuel ratio for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetFuelRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetFuelRatioHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushnumber(rawState, userUnit->GetFuel());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4EE0 (FUN_008C4EE0, cfunc_UserUnitGetShieldRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetShieldRatioL`.
 */
int moho::cfunc_UserUnitGetShieldRatio(lua_State* const luaContext)
{
  return cfunc_UserUnitGetShieldRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4F00 (FUN_008C4F00, func_UserUnitGetShieldRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetShieldRatio()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetShieldRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetShieldRatioName,
    &moho::cfunc_UserUnitGetShieldRatio,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetShieldRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4F60 (FUN_008C4F60, cfunc_UserUnitGetShieldRatioL)
 *
 * What it does:
 * Returns current shield ratio for one user-unit as Lua number.
 */
int moho::cfunc_UserUnitGetShieldRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetShieldRatioHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushnumber(rawState, userUnit->GetShield());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C5020 (FUN_008C5020, cfunc_UserUnitGetWorkProgress)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetWorkProgressL`.
 */
int moho::cfunc_UserUnitGetWorkProgress(lua_State* const luaContext)
{
  return cfunc_UserUnitGetWorkProgressL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5040 (FUN_008C5040, func_UserUnitGetWorkProgress_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetWorkProgress()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UserUnitGetWorkProgress_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetWorkProgressName,
    &moho::cfunc_UserUnitGetWorkProgress,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetWorkProgressHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C50A0 (FUN_008C50A0, cfunc_UserUnitGetWorkProgressL)
 *
 * What it does:
 * Returns current unit work-progress ratio as Lua number.
 */
int moho::cfunc_UserUnitGetWorkProgressL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetWorkProgressHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushnumber(rawState, userUnit->mUnitVarDat.mWorkProgress);
  (void)lua_gettop(rawState);
  return 1;
}

// --- FAF community binary-patch additions: UserUnit:GetInterpolatedPosition and
// UserUnit:GetFractionComplete. No `Address:` blocks -- these never existed in the
// original 2007 binary; they ship only via FA-Binary-Patches (section/UserUnit.cpp,
// `UIRegFuncT<0x00E4DA64, 0x00F8D89C>` on class "UserUnit"). The argument count
// error names the function, as the patch's `__FUNCTION__` does.

int moho::cfunc_UserUnitGetInterpolatedPosition(lua_State* const luaContext)
{
  return cfunc_UserUnitGetInterpolatedPositionL(moho::SCR_ResolveBindingState(luaContext));
}

CScrLuaInitForm* moho::func_UserUnitGetInterpolatedPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetInterpolatedPosition",
    &moho::cfunc_UserUnitGetInterpolatedPosition,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    "UserUnit:GetInterpolatedPosition()"
  );
  return &binder;
}

int moho::cfunc_UserUnitGetInterpolatedPositionL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, "GetInterpolatedPosition");

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  if (userUnit == nullptr || userUnit->mMeshInstance == nullptr) {
    return 0;
  }

  // The patch refreshes the interpolated transform (0x007DEC80) and returns the
  // position as a plain {x, y, z} array, without the vector metatable.
  MeshInstance* const meshInstance = userUnit->mMeshInstance;
  meshInstance->UpdateInterpolatedFields();
  const Wm3::Vec3f& position = meshInstance->interpolatedPosition;
  lua_newtable(rawState);
  lua_pushnumber(rawState, position.x);
  lua_rawseti(rawState, -2, 1);
  lua_pushnumber(rawState, position.y);
  lua_rawseti(rawState, -2, 2);
  lua_pushnumber(rawState, position.z);
  lua_rawseti(rawState, -2, 3);
  return 1;
}

int moho::cfunc_UserUnitGetFractionComplete(lua_State* const luaContext)
{
  return cfunc_UserUnitGetFractionCompleteL(moho::SCR_ResolveBindingState(luaContext));
}

CScrLuaInitForm* moho::func_UserUnitGetFractionComplete_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetFractionComplete",
    &moho::cfunc_UserUnitGetFractionComplete,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    "UserUnit:GetFractionComplete()"
  );
  return &binder;
}

int moho::cfunc_UserUnitGetFractionCompleteL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, "GetFractionComplete");

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  const UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  if (userUnit == nullptr) {
    return 0;
  }
  lua_pushnumber(rawState, userUnit->mVariableData.mFractionComplete);
  return 1;
}

/**
 * Address: 0x008C30E0 (FUN_008C30E0, cfunc_UserUnitGetStat)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetStatL`.
 */
int moho::cfunc_UserUnitGetStat(lua_State* const luaContext)
{
  return cfunc_UserUnitGetStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3100 (FUN_008C3100, func_UserUnitGetStat_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetStat(name[, defaultVal])` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetStatName,
    &moho::cfunc_UserUnitGetStat,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3160 (FUN_008C3160, cfunc_UserUnitGetStatL)
 *
 * What it does:
 * Resolves one stat path and pushes the resolved stat-item Lua table (or
 * `nil`) with optional default-type dispatch.
 */
int moho::cfunc_UserUnitGetStatL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsRangeWarning, kUserUnitGetStatHelpText, 2, 3, argumentCount);
  }

  lua_settop(rawState, 3);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  IUnit* const iunit = GetIUnitBridge(userUnit);

  StatItem* statItem = nullptr;
  if (lua_type(rawState, 3) == LUA_TNIL) {
    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = lua_tostring(rawState, 2);
    if (statName == nullptr) {
      statNameArg.TypeError("string");
    }
    statItem = iunit->GetStat(statName);
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      defaultArg.TypeError("integer");
    }
    const int defaultValue = defaultArg.GetInteger();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = lua_tostring(rawState, 2);
    if (statName == nullptr) {
      statNameArg.TypeError("string");
    }

    statItem = iunit->GetStat(statName, defaultValue);
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    const float defaultValue = defaultArg.GetNumber();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = statNameArg.GetString();
    statItem = iunit->GetStat(statName, defaultValue);
  } else {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    const char* const defaultString = defaultArg.GetString();
    const std::string defaultValue = defaultString ? std::string(defaultString) : std::string();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = statNameArg.GetString();
    statItem = iunit->GetStat(statName, defaultValue);
  }

  if (statItem != nullptr) {
    LuaPlus::LuaObject statTable;
    STAT_GetLuaTable(state, statItem, statTable);
    statTable.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C3440 (FUN_008C3440, cfunc_UserUnitIsStunned)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsStunnedL`.
 */
int moho::cfunc_UserUnitIsStunned(lua_State* const luaContext)
{
  return cfunc_UserUnitIsStunnedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3460 (FUN_008C3460, func_UserUnitIsStunned_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsStunned()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsStunned_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitIsStunnedName,
    &moho::cfunc_UserUnitIsStunned,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsStunnedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C34C0 (FUN_008C34C0, cfunc_UserUnitIsStunnedL)
 *
 * What it does:
 * Pushes one stunned-state boolean from replicated user-unit runtime state.
 */
int moho::cfunc_UserUnitIsStunnedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitIsStunnedHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  lua_pushboolean(rawState, userUnit->mUnitVarDat.mStunTicks != 0 ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C3700 (FUN_008C3700, cfunc_UserUnitGetCustomName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetCustomNameL`.
 */
int moho::cfunc_UserUnitGetCustomName(lua_State* const luaContext)
{
  return cfunc_UserUnitGetCustomNameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3720 (FUN_008C3720, func_UserUnitGetCustomName_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetCustomName()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetCustomName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetCustomNameName,
    &moho::cfunc_UserUnitGetCustomName,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetCustomNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3780 (FUN_008C3780, cfunc_UserUnitGetCustomNameL)
 *
 * What it does:
 * Pushes one custom-name string (or `nil` when empty).
 */
int moho::cfunc_UserUnitGetCustomNameL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUserUnitGetCustomNameHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  if (userUnit != nullptr) {
    const fa::string& customName = userUnit->mUnitVarDat.mCustomName;
    if (!customName.empty()) {
      lua_pushstring(rawState, customName.c_str());
      (void)lua_gettop(rawState);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
  }

  return 1;
}

/**
 * Address: 0x008C3B40 (FUN_008C3B40, cfunc_UserUnitHasSelectionSet)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitHasSelectionSetL`.
 */
int moho::cfunc_UserUnitHasSelectionSet(lua_State* const luaContext)
{
  return cfunc_UserUnitHasSelectionSetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C3B60 (FUN_008C3B60, func_UserUnitHasSelectionSet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:HasSelectionSet(name)` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitHasSelectionSet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitHasSelectionSetName,
    &moho::cfunc_UserUnitHasSelectionSet,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitHasSelectionSetHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C3BC0 (FUN_008C3BC0, cfunc_UserUnitHasSelectionSetL)
 *
 * What it does:
 * Pushes one boolean membership result for the provided selection-set name.
 */
int moho::cfunc_UserUnitHasSelectionSetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUserUnitHasSelectionSetHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);
  if (userUnit != nullptr) {
    const LuaPlus::LuaStackObject selectionSetNameArg(state, 2);
    const char* const selectionSetName = lua_tostring(rawState, 2);
    if (selectionSetName == nullptr) {
      selectionSetNameArg.TypeError("string");
    }

    const bool hasSelectionSet = userUnit->HasSelectionSet(selectionSetName);
    lua_pushboolean(rawState, hasSelectionSet ? 1 : 0);
    (void)lua_gettop(rawState);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C4500 (FUN_008C4500, cfunc_UserUnitIsIdle)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitIsIdleL`.
 */
int moho::cfunc_UserUnitIsIdle(lua_State* const luaContext)
{
  return cfunc_UserUnitIsIdleL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4520 (FUN_008C4520, func_UserUnitIsIdle_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:IsIdle()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitIsIdle_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitIsIdleName,
    &moho::cfunc_UserUnitIsIdle,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitIsIdleHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4580 (FUN_008C4580, cfunc_UserUnitIsIdleL)
 *
 * What it does:
 * Pushes one idle-state boolean derived from busy + queue-empty state.
 */
int moho::cfunc_UserUnitIsIdleL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitIsIdleHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = GetUserUnitOptional(userUnitObject, state);

  bool isIdle = false;
  if (userUnit != nullptr && userUnit->mUnitVarDat.mIsBusy == 0u) {
    const gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const commandRange = ResolveUserCommandQueueRange(userUnit->GetCommandQueue());
    if (commandRange == nullptr || commandRange->empty()) {
      isIdle = true;
    }
  }

  lua_pushboolean(rawState, isIdle ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C4660 (FUN_008C4660, cfunc_UserUnitGetFocus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetFocusL`.
 */
int moho::cfunc_UserUnitGetFocus(lua_State* const luaContext)
{
  return cfunc_UserUnitGetFocusL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4680 (FUN_008C4680, func_UserUnitGetFocus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetFocus()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetFocus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetFocusName,
    &moho::cfunc_UserUnitGetFocus,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetFocusHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C46E0 (FUN_008C46E0, cfunc_UserUnitGetFocusL)
 *
 * What it does:
 * Pushes focused target user-unit Lua object, or `nil` when unresolved.
 */
int moho::cfunc_UserUnitGetFocusL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetFocusHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  UserEntity* const userEntity = userUnit;
  UserEntity* const focusEntity =
    FindSessionEntityById(userEntity ? userEntity->mSession : nullptr, static_cast<std::int32_t>(userUnit->mUnitVarDat.mFocusUnit));

  if (focusEntity != nullptr) {
    if (UserUnit* const focusUnit = focusEntity->IsUserUnit(); focusUnit != nullptr) {
      focusUnit->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C47F0 (FUN_008C47F0, cfunc_UserUnitGetGuardedEntity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitGetGuardedEntityL`.
 */
int moho::cfunc_UserUnitGetGuardedEntity(lua_State* const luaContext)
{
  return cfunc_UserUnitGetGuardedEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4810 (FUN_008C4810, func_UserUnitGetGuardedEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetGuardedEntity()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetGuardedEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetGuardedEntityName,
    &moho::cfunc_UserUnitGetGuardedEntity,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetGuardedEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4870 (FUN_008C4870, cfunc_UserUnitGetGuardedEntityL)
 *
 * What it does:
 * Pushes guarded-target user-unit Lua object, or `nil` when unresolved.
 */
int moho::cfunc_UserUnitGetGuardedEntityL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetGuardedEntityHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  UserEntity* const userEntity = userUnit;
  UserEntity* const guardedEntity = FindSessionEntityById(
    userEntity ? userEntity->mSession : nullptr, static_cast<std::int32_t>(userUnit->mUnitVarDat.mGuardedUnit)
  );

  if (guardedEntity != nullptr) {
    if (UserUnit* const guardedUnit = guardedEntity->IsUserUnit(); guardedUnit != nullptr) {
      guardedUnit->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C4980 (FUN_008C4980, cfunc_UserUnitGetCreator)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetCreatorL`.
 */
int moho::cfunc_UserUnitGetCreator(lua_State* const luaContext)
{
  return cfunc_UserUnitGetCreatorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C49A0 (FUN_008C49A0, func_UserUnitGetCreator_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetCreator()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetCreator_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetCreatorName,
    &moho::cfunc_UserUnitGetCreator,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetCreatorHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4A00 (FUN_008C4A00, cfunc_UserUnitGetCreatorL)
 *
 * What it does:
 * Pushes creator user-unit Lua object, or `nil` when unavailable.
 */
int moho::cfunc_UserUnitGetCreatorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetCreatorHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  UserEntity* const creatorEntity = userUnit->mCreator.GetObjectPtr();

  if (creatorEntity != nullptr) {
    if (UserUnit* const creatorUnit = creatorEntity->IsUserUnit(); creatorUnit != nullptr) {
      creatorUnit->mLuaObj.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008C4AF0 (FUN_008C4AF0, cfunc_UserUnitGetPosition)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetPositionL`.
 */
int moho::cfunc_UserUnitGetPosition(lua_State* const luaContext)
{
  return cfunc_UserUnitGetPositionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4B10 (FUN_008C4B10, func_UserUnitGetPosition_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetPosition()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetPosition_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetPositionName,
    &moho::cfunc_UserUnitGetPosition,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetPositionHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4B70 (FUN_008C4B70, cfunc_UserUnitGetPositionL)
 *
 * What it does:
 * Pushes world position as one Lua VECTOR3 object.
 */
int moho::cfunc_UserUnitGetPositionL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetPositionHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const Wm3::Vec3f& unitPosition = GetIUnitBridge(userUnit)->GetPosition();

  LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3<float>>(state, unitPosition);
  positionObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C4C50 (FUN_008C4C50, cfunc_UserUnitGetArmy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetArmyL`.
 */
int moho::cfunc_UserUnitGetArmy(lua_State* const luaContext)
{
  return cfunc_UserUnitGetArmyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C4C70 (FUN_008C4C70, func_UserUnitGetArmy_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetArmy()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetArmy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetArmyName,
    &moho::cfunc_UserUnitGetArmy,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetArmyHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C4CD0 (FUN_008C4CD0, cfunc_UserUnitGetArmyL)
 *
 * What it does:
 * Pushes one-based army index for the unit owner, preserving `-1` sentinel.
 */
int moho::cfunc_UserUnitGetArmyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetArmyHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  int armyIndex = -1;
  if (const UserArmy* const army = userUnit->mArmy; army != nullptr) {
    armyIndex = static_cast<int>(army->mArmyIndex);
  }
  if (armyIndex != -1) {
    ++armyIndex;
  }

  lua_pushnumber(rawState, static_cast<float>(armyIndex));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008C5160 (FUN_008C5160, cfunc_UserUnitGetEconData)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetEconDataL`.
 */
int moho::cfunc_UserUnitGetEconData(lua_State* const luaContext)
{
  return cfunc_UserUnitGetEconDataL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5180 (FUN_008C5180, func_UserUnitGetEconData_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetEconData()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetEconData_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetEconDataName,
    &moho::cfunc_UserUnitGetEconData,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetEconDataHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C51E0 (FUN_008C51E0, cfunc_UserUnitGetEconDataL)
 *
 * What it does:
 * Pushes one Lua table with per-second economy lanes for this user unit.
 */
int moho::cfunc_UserUnitGetEconDataL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetEconDataHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const SSTIUnitVariableData& runtime = userUnit->mUnitVarDat;

  LuaPlus::LuaObject econTable;
  econTable.AssignNewTable(state, 0, 0);
  econTable.SetNumber(kEconEnergyConsumedKey, runtime.mResourcesSpent.ENERGY * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconMassConsumedKey, runtime.mResourcesSpent.MASS * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconEnergyRequestedKey, runtime.mMaintainenceCost.ENERGY * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconMassRequestedKey, runtime.mMaintainenceCost.MASS * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconEnergyProducedKey, runtime.mProduced.ENERGY * kEconomyPerSecondToUiRate);
  econTable.SetNumber(kEconMassProducedKey, runtime.mProduced.MASS * kEconomyPerSecondToUiRate);
  econTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C5400 (FUN_008C5400, cfunc_UserUnitGetCommandQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UserUnitGetCommandQueueL`.
 */
int moho::cfunc_UserUnitGetCommandQueue(lua_State* const luaContext)
{
  return cfunc_UserUnitGetCommandQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5420 (FUN_008C5420, func_UserUnitGetCommandQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetCommandQueue()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetCommandQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetCommandQueueName,
    &moho::cfunc_UserUnitGetCommandQueue,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetCommandQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C5480 (FUN_008C5480, cfunc_UserUnitGetCommandQueueL)
 *
 * What it does:
 * Pushes one Lua array of queued command descriptors (`ID`, `type`,
 * `position`) for this user unit.
 */
int moho::cfunc_UserUnitGetCommandQueueL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetCommandQueueHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);

  const gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const commandRange = ResolveUserCommandQueueRange(SelectActiveQueue(userUnit));
  if (commandRange == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject queueTable;
  queueTable.AssignNewTable(state, 0, 0);

  UserEntity* const userEntity = userUnit;
  CWldSession* const session = userEntity ? userEntity->mSession : nullptr;

  int tableIndex = 1;
  for (const WeakPtr<UserCommandIssueHelper>& link : *commandRange) {
    UserCommandIssueHelper* const helper = link.GetObjectPtr();
    if (helper == nullptr) {
      continue;
    }

    LuaPlus::LuaObject row;
    row.AssignNewTable(state, 0, 0);
    row.SetInteger(kCommandQueueIdKey, static_cast<int>(helper->mConstantData.cmd));

    EUnitCommandType commandTypeValue = ResolveHelperCommandType(*helper);
    gpg::RRef commandTypeRef{};
    commandTypeRef = gpg::MakeRRef<moho::EUnitCommandType>(&commandTypeValue);
    const fa::string commandTypeLexical = commandTypeRef.GetLexical();
    row.SetString(kCommandQueueTypeKey, commandTypeLexical.c_str());

    const Wm3::Vector3<float> commandPosition = ResolveHelperTargetPosition(*helper, session);
    LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3<float>>(state, commandPosition);
    row.SetObject(kCommandQueuePositionKey, positionObject);

    queueTable.SetObject(tableIndex++, row);
  }

  queueTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C5750 (FUN_008C5750, cfunc_UserUnitGetMissileInfo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UserUnitGetMissileInfoL`.
 */
int moho::cfunc_UserUnitGetMissileInfo(lua_State* const luaContext)
{
  return cfunc_UserUnitGetMissileInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5770 (FUN_008C5770, func_UserUnitGetMissileInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `UserUnit:GetMissileInfo()` Lua binder.
 */
CScrLuaInitForm* moho::func_UserUnitGetMissileInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kUserUnitGetMissileInfoName,
    &moho::cfunc_UserUnitGetMissileInfo,
    &CScrLuaMetatableFactory<UserUnit>::Instance(),
    kUserUnitLuaClassName,
    kUserUnitGetMissileInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C57D0 (FUN_008C57D0, cfunc_UserUnitGetMissileInfoL)
 *
 * What it does:
 * Pushes one Lua table with tactical/nuke silo build and storage counters.
 */
int moho::cfunc_UserUnitGetMissileInfoL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUserUnitGetMissileInfoHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const SSTIUnitVariableData& runtime = userUnit->mUnitVarDat;

  LuaPlus::LuaObject missileInfoTable;
  missileInfoTable.AssignNewTable(state, 0, 0);
  missileInfoTable.SetInteger(kMissileTacticalBuildCountKey, runtime.mTacticalSiloBuildCount);
  missileInfoTable.SetInteger(kMissileTacticalStorageCountKey, runtime.mTacticalSiloStorageCount);
  missileInfoTable.SetInteger(kMissileTacticalMaxStorageCountKey, runtime.mTacticalSiloMaxStorageCount);
  missileInfoTable.SetInteger(kMissileNukeBuildCountKey, runtime.mNukeSiloBuildCount);
  missileInfoTable.SetInteger(kMissileNukeStorageCountKey, runtime.mNukeSiloStorageCount);
  missileInfoTable.SetInteger(kMissileNukeMaxStorageCountKey, runtime.mNukeSiloMaxStorageCount);
  missileInfoTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x00836360 (FUN_00836360, cfunc_SetCurrentFactoryForQueueDisplay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_SetCurrentFactoryForQueueDisplayL`.
 */
int moho::cfunc_SetCurrentFactoryForQueueDisplay(lua_State* const luaContext)
{
  return cfunc_SetCurrentFactoryForQueueDisplayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00836380 (FUN_00836380, func_SetCurrentFactoryForQueueDisplay_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `SetCurrentFactoryForQueueDisplay(unit)` Lua binder.
 */
CScrLuaInitForm* moho::func_SetCurrentFactoryForQueueDisplay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kSetCurrentFactoryForQueueDisplayName,
    &moho::cfunc_SetCurrentFactoryForQueueDisplay,
    nullptr,
    "<global>",
    kSetCurrentFactoryForQueueDisplayHelpText
  );
  return &binder;
}

/**
 * Address: 0x00835DF0 (FUN_00835DF0, sub_835DF0)
 *
 * IDA signature:
 * void __usercall sub_835DF0(gpg::fastvector_BuildQueueItem *queue@<ebx>,
 *                            Moho::WeakPtr_UserUnit factoryLink);
 *
 * What it does:
 * Appends the currently-bound factory's command queue into `queue` as
 * blueprint/count display rows, coalescing runs of the same blueprint id and
 * collecting each contributing command id onto the row it folded into. Gated on
 * the unit's blueprint carrying the `SHOWQUEUE` category; when it passes, the
 * link is also published into the global `sCurrentBuildFactory`. The by-value
 * weak node is unlinked from the unit's owner chain before returning, which is
 * the argument destruction the binary performs at 0x0083600C.
 *
 * Fidelity note: the SHOWQUEUE gate, the `sCurrentBuildFactory` publish, the
 * command-id collection and the by-value node teardown are recovered from the
 * disassembly. The queue walk itself reuses this TU's already-recovered
 * command-queue resolution (0x008B6F60) and helper decoders (0x008B4140,
 * 0x008B4220) - the binary re-invokes 0x008B6F60 once per loop test rather than
 * hoisting the range, which is an artefact of the emitted loop, not a behaviour
 * difference, because the resolver is idempotent for an unchanged queue.
 */
void moho::RebuildFactoryQueueDisplaySnapshot(
  FactoryQueueDisplaySnapshot& queue,
  WeakPtr<UserUnit>& factoryLink
)
{
  // 0x00835E17: a null owner-link slot means the argument node never linked, so
  // there is nothing to walk and nothing to unlink.
  if (!factoryLink.HasValue()) {
    return;
  }

  UserUnit* const userUnit = factoryLink.GetObjectPtr();
  if (userUnit != nullptr && IsFactoryQueueDisplayEnabledForUnit(userUnit)) {
    UserCommandQueue* const commandQueue = userUnit->GetCommandQueue();
    if (commandQueue != nullptr) {
      // 0x00835ECB republishes the current factory from the incoming link.
      sCurrentBuildFactory = factoryLink;

      const gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const commandRange = ResolveUserCommandQueueRange(commandQueue);
      if (commandRange != nullptr) {
        for (const WeakPtr<UserCommandIssueHelper>& link : *commandRange) {
          const UserCommandIssueHelper* const helper = link.GetObjectPtr();
          if (helper == nullptr) {
            continue;
          }

          const EUnitCommandType commandType = ResolveHelperCommandType(*helper);
          if (!IsFactoryQueueCommandType(commandType)) {
            continue;
          }

          const REntityBlueprint* const blueprint = helper->mConstantData.blueprint;
          if (blueprint == nullptr || blueprint->mBlueprintId.empty()) {
            continue;
          }

          // 0x00835F5A / 0x00835F6F: fold into the tail row when the queue is
          // non-empty and its last blueprint id matches.
          if (!queue.empty() && queue.back().blueprintId == blueprint->mBlueprintId) {
            FactoryQueueDisplayItem& tail = queue.back();
            tail.count += ResolveHelperBuildCount(*helper);
            tail.commands.push_back(helper->mConstantData.cmd);
            continue;
          }

          FactoryQueueDisplayItem item(blueprint->mBlueprintId, ResolveHelperBuildCount(*helper));
          item.commands.push_back(helper->mConstantData.cmd);
          AppendFactoryQueueDisplayItem(queue, item);
        }
      }
    }
  }

  factoryLink.UnlinkFromOwnerChain();
}

/**
 * Address: 0x00836080 (FUN_00836080, func_AddScriptUIBuildQueueItem)
 *
 * IDA signature:
 * void __usercall func_AddScriptUIBuildQueueItem(gpg::fastvector_BuildQueueItem *queue@<esi>,
 *                                                LuaPlus::LuaState *state,
 *                                                LuaPlus::LuaObject *outQueueTable);
 *
 * What it does:
 * Rewrites `outQueueTable` as a fresh Lua array sized to the queue, one
 * `{ id = <blueprint id>, count = <queued count> }` sub-table per row.
 */
void moho::BuildFactoryQueueLuaTable(
  const FactoryQueueDisplaySnapshot& queue,
  LuaPlus::LuaState* const state,
  LuaPlus::LuaObject* const outQueueTable
)
{
  outQueueTable->AssignNewTable(state, static_cast<int>(queue.size()), 0);

  unsigned int tableIndex = 0;
  for (const FactoryQueueDisplayItem& buildItem : queue) {
    LuaPlus::LuaObject row;
    row.AssignNewTable(state, 2, 0);
    row.SetString(kFactoryQueueItemIdKey, buildItem.blueprintId.c_str());
    row.SetInteger(kFactoryQueueItemCountKey, buildItem.count);
    outQueueTable->SetObject(static_cast<int>(++tableIndex), row);
  }
}

/**
 * Address: 0x008363E0 (FUN_008363E0, cfunc_SetCurrentFactoryForQueueDisplayL)
 *
 * What it does:
 * Binds one optional `UserUnit` argument as the factory whose build queue the UI
 * mirrors: takes a temporary weak link on it, releases the previously-bound
 * factory, erases the published queue, rebuilds it for the new unit and returns
 * the resulting `{id, count}` table (or `nil` when the rebuild produced nothing).
 */
int moho::cfunc_SetCurrentFactoryForQueueDisplayL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kSetCurrentFactoryForQueueDisplayHelpText);

  // 0x00836458: the link slot is the unit's weak-link head at +0x08. The Lua
  // object is a temporary and dies once the pointer is built.
  WeakPtr<UserUnit> factoryLink(
    GetUserUnitOptional(LuaPlus::LuaObject(LuaPlus::LuaStackObject(state, 1)), state)
  );

  LuaPlus::LuaObject queueTable;

  // 0x00836495: drop the previously-bound factory, then 0x008364E3 erases the
  // published queue before the rebuild refills it.
  sCurrentBuildFactory.UnlinkFromOwnerChain();
  FactoryQueueDisplayItem* rebasedBegin = nullptr;
  (void)RebaseFactoryQueueRangeAndTrimTail(&rebasedBegin, sCurrentBuildQueue.begin(), sCurrentBuildQueue.end());

  RebuildFactoryQueueDisplaySnapshot(sCurrentBuildQueue, factoryLink);

  if (!sCurrentBuildQueue.empty()) {
    BuildFactoryQueueLuaTable(sCurrentBuildQueue, state, &queueTable);
  } else {
    queueTable.AssignNil(state);
  }

  queueTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008C5930 (FUN_008C5930, cfunc_GetBlueprintUser)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetBlueprintUserL`.
 */
int moho::cfunc_GetBlueprintUser(lua_State* const luaContext)
{
  return cfunc_GetBlueprintUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008C5950 (FUN_008C5950, func_GetBlueprintUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua `GetBlueprint` binder.
 */
CScrLuaInitForm* moho::func_GetBlueprintUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kGetBlueprintUserName,
    &moho::cfunc_GetBlueprintUser,
    nullptr,
    "<global>",
    kGetBlueprintUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008C59B0 (FUN_008C59B0, cfunc_GetBlueprintUserL)
 *
 * What it does:
 * Resolves one `UserUnit` Lua object argument and pushes its unit blueprint
 * Lua object result.
 */
int moho::cfunc_GetBlueprintUserL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetBlueprintUserHelpText);

  const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
  UserUnit* const userUnit = SCR_FromLua_UserUnit(userUnitObject, state);
  const IUnit* const iunitBridge = GetIUnitBridge(userUnit);
  const RUnitBlueprint* const blueprint = iunitBridge ? iunitBridge->GetBlueprint() : nullptr;

  if (blueprint != nullptr) {
    LuaPlus::LuaObject luaBlueprint = blueprint->GetLuaBlueprint(state);
    luaBlueprint.PushStack(state);
  } else {
    lua_pushnil(rawState);
  }
  return 1;
}
namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct UserUnitLuaFuncDefBootstrap
  {
    UserUnitLuaFuncDefBootstrap()
    {
      (void)::moho::func_UserUnitCanAttackTarget_LuaFuncDef();
      (void)::moho::func_UserUnitGetFootPrintSize_LuaFuncDef();
      (void)::moho::func_UserUnitGetUnitId_LuaFuncDef();
      (void)::moho::func_UserUnitGetBlueprint_LuaFuncDef();
      (void)::moho::func_UserUnitIsAutoMode_LuaFuncDef();
      (void)::moho::func_UserUnitIsAutoSurfaceMode_LuaFuncDef();
      (void)::moho::func_UserUnitIsRepeatQueue_LuaFuncDef();
      (void)::moho::func_UserUnitGetEntityId_LuaFuncDef();
      (void)::moho::func_UserUnitHasUnloadCommandQueuedUp_LuaFuncDef();
      (void)::moho::func_UserUnitProcessInfo_LuaFuncDef();
      (void)::moho::func_UserUnitSetCustomName_LuaFuncDef();
      (void)::moho::func_UserUnitAddSelectionSet_LuaFuncDef();
      (void)::moho::func_UserUnitRemoveSelectionSet_LuaFuncDef();
      (void)::moho::func_UserUnitGetSelectionSets_LuaFuncDef();
      (void)::moho::func_UserUnitIsInCategory_LuaFuncDef();
      (void)::moho::func_UserUnitGetHealth_LuaFuncDef();
      (void)::moho::func_UserUnitGetMaxHealth_LuaFuncDef();
      (void)::moho::func_UserUnitGetBuildRate_LuaFuncDef();
      (void)::moho::func_UserUnitIsOverchargePaused_LuaFuncDef();
      (void)::moho::func_UserUnitIsDead_LuaFuncDef();
      (void)::moho::func_UserUnitGetFuelRatio_LuaFuncDef();
      (void)::moho::func_UserUnitGetShieldRatio_LuaFuncDef();
      (void)::moho::func_UserUnitGetWorkProgress_LuaFuncDef();
      // FAF FA-Binary-Patches additions, not in the shipped registration sequence.
      (void)::moho::func_UserUnitGetInterpolatedPosition_LuaFuncDef();
      (void)::moho::func_UserUnitGetFractionComplete_LuaFuncDef();
      (void)::moho::func_UserUnitGetStat_LuaFuncDef();
      (void)::moho::func_UserUnitIsStunned_LuaFuncDef();
      (void)::moho::func_UserUnitGetCustomName_LuaFuncDef();
      (void)::moho::func_UserUnitHasSelectionSet_LuaFuncDef();
      (void)::moho::func_UserUnitIsIdle_LuaFuncDef();
      (void)::moho::func_UserUnitGetFocus_LuaFuncDef();
      (void)::moho::func_UserUnitGetGuardedEntity_LuaFuncDef();
      (void)::moho::func_UserUnitGetCreator_LuaFuncDef();
      (void)::moho::func_UserUnitGetPosition_LuaFuncDef();
      (void)::moho::func_UserUnitGetArmy_LuaFuncDef();
      (void)::moho::func_UserUnitGetEconData_LuaFuncDef();
      (void)::moho::func_UserUnitGetCommandQueue_LuaFuncDef();
      (void)::moho::func_UserUnitGetMissileInfo_LuaFuncDef();
      (void)::moho::func_SetCurrentFactoryForQueueDisplay_LuaFuncDef();
      (void)::moho::func_GetBlueprintUser_LuaFuncDef();
    }
  };

  const UserUnitLuaFuncDefBootstrap gUserUnitLuaFuncDefBootstrap{};
}

