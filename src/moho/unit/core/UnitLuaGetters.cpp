#include "moho/unit/core/UnitLuaPrivate.h"

namespace
{
  constexpr const char* kLuaExpectedArgsRangeWarning = "%s\n  expected between %d and %d args, but got %d";
  constexpr const char* kUnitGetCargoName = "GetCargo";
  constexpr const char* kUnitGetCargoHelpText = "GetCargo(self)";
  constexpr const char* kUnitGetArmorMultName = "GetArmorMult";
  constexpr const char* kUnitGetArmorMultHelpText = "mult = Unit:GetArmorMult(damageTypeName)";
  constexpr const char* kUnitGetFocusUnitName = "GetFocusUnit";
  constexpr const char* kUnitGetFocusUnitHelpText = "GetFocusUnit(self)";
  constexpr const char* kUnitGetWeaponName = "GetWeapon";
  constexpr const char* kUnitGetWeaponHelpText =
    "GetWeapon(self,index) -- return the index'th weapon of this unit. Index must be between 1 and self:GetWeaponCount(), inclusive.";
  constexpr const char* kUnitGetWeaponInvalidIndexError =
    "Invalid weapon index %d; must be between 1 and %d (inclusive)";
  constexpr const char* kUnitGetWeaponCountName = "GetWeaponCount";
  constexpr const char* kUnitGetWeaponCountHelpText =
    "GetWeaponCount(self) -- return the number of weapons on this unit. Note that dummy weapons are not included in the count, so this may differ from the number of weapons defined in the unit's blueprint.";
  constexpr const char* kUnitGetTargetEntityName = "GetTargetEntity";
  constexpr const char* kUnitGetTargetEntityHelpText = "Return our target unit if we have one";
  constexpr const char* kUnitGetHealthName = "GetHealth";
  constexpr const char* kUnitGetHealthHelpText = "GetHealth(self)";
  constexpr const char* kUnitGetAttackerName = "GetAttacker";
  constexpr const char* kUnitGetAttackerHelpText = "GetAttacker() - get the tactical attack manager object of this unit";
  constexpr const char* kGetFireStateName = "GetFireState";
  constexpr const char* kGetFireStateArgsHelpText = "GetFireState(units)";
  constexpr const char* kGetFireStateBindHelpText = "Get the right fire state for the units passed in";
  constexpr const char* kGetIsPausedGlobalName = "GetIsPaused";
  constexpr const char* kGetIsPausedGlobalHelpText = "Is anyone ins this list builder paused?";
  constexpr const char* kGetIsAutoModeGlobalName = "GetIsAutoMode";
  constexpr const char* kGetIsAutoModeGlobalHelpText = "See if anyone in the list is auto building";
  constexpr const char* kGetIsSubmergedGlobalName = "GetIsSubmerged";
  constexpr const char* kGetIsSubmergedGlobalHelpText =
    "Determine if units are submerged (-1), not submerged(1) or unable to tell (0)";
  constexpr const char* kGetIsAutoSurfaceModeGlobalName = "GetIsAutoSurfaceMode";
  constexpr const char* kGetIsAutoSurfaceModeGlobalHelpText = "See if anyone in the list is auto surfacing";
  constexpr const char* kUnitGetCommandQueueName = "GetCommandQueue";
  constexpr const char* kUnitGetCommandQueueHelpText = "Unit:GetCommandQueue()";
  constexpr const char* kUnitGetGuardedUnitName = "GetGuardedUnit";
  constexpr const char* kUnitGetGuardedUnitHelpText = "Unit:GetGuardedUnit()";
  constexpr const char* kUnitGetGuardsName = "GetGuards";
  constexpr const char* kUnitGetGuardsHelpText = "Unit:GetGuards()";
  constexpr const char* kUnitGetTransportFerryBeaconName = "GetTransportFerryBeacon";
  constexpr const char* kUnitGetTransportFerryBeaconHelpText = "Unit:GetTransportFerryBeacon()";
  constexpr const char* kUnitHasValidTeleportDestName = "HasValidTeleportDest";
  constexpr const char* kUnitHasValidTeleportDestHelpText = "Unit:HasValidTeleportDest()";
  constexpr const char* kUnitHasMeleeSpaceAroundTargetName = "HasMeleeSpaceAroundTarget";
  constexpr const char* kUnitHasMeleeSpaceAroundTargetHelpText = "Unit:HasMeleeSpaceAroundTarget(target)";
  constexpr const char* kUnitGetCurrentMoveLocationName = "GetCurrentMoveLocation";
  constexpr const char* kUnitGetCurrentMoveLocationHelpText = "Unit:GetCurrentMoveLocation()";
  constexpr const char* kUnitGetCurrentMoveLocationInvalidUnitError =
    "UnitScript:GetCurrentMoveLocation Passed in an invalid unit";
  constexpr const char* kUnitGetNukeSiloAmmoCountName = "GetNukeSiloAmmoCount";
  constexpr const char* kUnitGetNukeSiloAmmoCountHelpText = "Unit:GetNukeSiloAmmoCount()";
  constexpr const char* kUnitGetTacticalSiloAmmoCountName = "GetTacticalSiloAmmoCount";
  constexpr const char* kUnitGetTacticalSiloAmmoCountHelpText = "Unit:GetTacticalSiloAmmoCount()";
  constexpr const char* kUnitIsIdleStateName = "IsIdleState";
  constexpr const char* kUnitIsIdleStateHelpText = "IsIdleState(unit)";
  constexpr const char* kUnitIsStunnedName = "IsStunned";
  constexpr const char* kUnitIsStunnedHelpText = "IsStunned(unit)";
  constexpr const char* kUnitIsBeingBuiltName = "IsBeingBuilt";
  constexpr const char* kUnitIsBeingBuiltHelpText = "Unit:IsBeingBuilt()";
  constexpr const char* kUnitIsPausedName = "IsPaused";
  constexpr const char* kUnitIsPausedHelpText = "Unit:IsPaused()";
  constexpr const char* kUnitGetBuildRateName = "GetBuildRate";
  constexpr const char* kUnitGetBuildRateHelpText =
    "unit:GetBuildRate() -- returns the build rate of a unit: what fraction of target unit it builds per second.";
  constexpr const char* kUnitGetConsumptionPerSecondEnergyName = "GetConsumptionPerSecondEnergy";
  constexpr const char* kUnitGetConsumptionPerSecondEnergyHelpText = "Get the consumption of energy of the unit";
  constexpr const char* kUnitGetConsumptionPerSecondMassName = "GetConsumptionPerSecondMass";
  constexpr const char* kUnitGetConsumptionPerSecondMassHelpText = "Get the consumption of mass of the unit";
  constexpr const char* kUnitGetProductionPerSecondEnergyName = "GetProductionPerSecondEnergy";
  constexpr const char* kUnitGetProductionPerSecondEnergyHelpText = "Get the production of energy of the unit";
  constexpr const char* kUnitGetProductionPerSecondMassName = "GetProductionPerSecondMass";
  constexpr const char* kUnitGetProductionPerSecondMassHelpText = "Get the production of mass of the unit";
  constexpr const char* kUnitGetResourceConsumedName = "GetResourceConsumed";
  constexpr const char* kUnitGetResourceConsumedHelpText =
    "Return the fraction of requested resources this unit consumed last tick. Normally 1, but can be fractional if economy is struggling.";
  constexpr const char* kUnitIsUnitStateName = "IsUnitState";
  constexpr const char* kUnitIsUnitStateHelpText = "IsUnitState(unit, stateName)";
  constexpr const char* kUnitGetFireStateName = "GetFireState";
  constexpr const char* kUnitGetFireStateHelpText = "Get the fire state for the unit";
  constexpr const char* kUnitIsValidTargetName = "IsValidTarget";
  constexpr const char* kUnitIsValidTargetHelpText = "bool = IsValidTarget(self)";
  constexpr const char* kUnitGetNumBuildOrdersName = "GetNumBuildOrders";
  constexpr const char* kUnitGetNumBuildOrdersHelpText =
    "Get number of factory/engineer build orders that fit in the specified category";
  constexpr const char* kUnitCalculateWorldPositionFromRelativeName = "CalculateWorldPositionFromRelative";
  constexpr const char* kUnitCalculateWorldPositionFromRelativeHelpText =
    "Calculate the desired world position from the supplied relative vector from the center of the unit";
  constexpr const char* kUnitCanBuildName = "CanBuild";
  constexpr const char* kUnitCanBuildHelpText = "CanBuild(self, blueprint";
  constexpr const char* kUnitCanBuildUnknownBlueprintError = "Unknown unit blueprint id: %s";
  constexpr const char* kUnitGetRallyPointName = "GetRallyPoint";
  constexpr const char* kUnitGetRallyPointHelpText = "Get the rally point for the factory";
  constexpr const char* kUnitGetFuelUseTimeName = "GetFuelUseTime";
  constexpr const char* kUnitGetFuelUseTimeHelpText = "Get the fuel use time";
  constexpr const char* kUnitGetFuelRatioName = "GetFuelRatio";
  constexpr const char* kUnitGetFuelRatioHelpText = "Get the fuel ratio";
  constexpr const char* kUnitGetShieldRatioName = "GetShieldRatio";
  constexpr const char* kUnitGetShieldRatioHelpText = "Get the shield ratio";
  constexpr const char* kUnitGetBlipName = "GetBlip";
  constexpr const char* kUnitGetBlipHelpText =
    "blip = GetBlip(armyIndex) - returns a blip (if any) that the given army has for the unit";
  constexpr const char* kUnitGetScriptBitHelpText = "GetScriptBit(units, bit)";
  constexpr const char* kUnitGetScriptBitName = "GetScriptBit";
  constexpr const char* kUnitGetScriptBitMethodHelpText = "Get the current toggle state of the script bit that matches the string";
  constexpr const char* kUnitGetUnitIdName = "GetUnitId";
  constexpr const char* kUnitGetUnitIdHelpText = "GetUnitId(self)";
  constexpr const char* kUnitGetCurrentLayerName = "GetCurrentLayer";
  constexpr const char* kUnitGetCurrentLayerHelpText = "GetUnitId(self)";
  constexpr const char* kUnitCanPathToName = "CanPathTo";
  constexpr const char* kUnitCanPathToHelpText = "See if the unit can path to the goal";
  constexpr const char* kUnitCanPathToRectName = "CanPathToRect";
  constexpr const char* kUnitCanPathToRectHelpText = "See if the unit can path to the goal rectangle";
  constexpr const char* kUnitIsCapturableName = "IsCapturable";
  constexpr const char* kUnitIsCapturableHelpText = "Returns if this unit can be captured or not";
  constexpr const char* kUnitIsOverchargePausedName = "IsOverchargePaused";
  constexpr const char* kUnitIsOverchargePausedHelpText = "Returns if this unit has its overcharge paused";
  constexpr const char* kUnitIsMobileName = "IsMobile";
  constexpr const char* kUnitIsMobileHelpText = "bool IsMobile() - Is this a mobile unit?";
  constexpr const char* kUnitIsMovingName = "IsMoving";
  constexpr const char* kUnitIsMovingHelpText = "bool IsMoving() - Is this unit moving?";
  constexpr const char* kUnitGetNavigatorName = "GetNavigator";
  constexpr const char* kUnitGetNavigatorHelpText = "GetNavigator() - get the navigator object of this unit";
  constexpr const char* kUnitGetVelocityName = "GetVelocity";
  constexpr const char* kUnitGetVelocityHelpText = "GetVelocity() -> x,y,z";
  constexpr const char* kUnitGetStatName = "GetStat";
  constexpr const char* kUnitGetStatHelpText = "GetStat(Name[,defaultVal])";
  constexpr const char* kUnitGetWorkProgressName = "GetWorkProgress";
  constexpr const char* kUnitGetWorkProgressHelpText = "GetWorkProgress()";
  constexpr const char* kUnitGetCargoTransportOnlyText = "Unit:GetCargo only valid for transport units";

  [[nodiscard]] Wm3::Vector3f& InvalidNavigatorTargetLane() noexcept
  {
    static bool initialized = false;
    static Wm3::Vector3f invalidTarget{};

    if (!initialized) {
      invalidTarget = Wm3::Vector3f::NaN();
      initialized = true;
    }

    return invalidTarget;
  }

  /**
   * Address: 0x00594850 (FUN_00594850, func_CastUnit)
   *
   * What it does:
   * Upcasts one reflected object lane to `Unit*` using cached `Unit` RTTI.
   */
  [[nodiscard]] Unit* UpcastUnitFromRef(const gpg::RRef& sourceRef)
  {
    const gpg::RRef unitRef = gpg::REF_UpcastPtr(sourceRef, gpg::RTypeOf<Unit>());
    return static_cast<Unit*>(unitRef.mObj);
  }

  /**
   * Address: 0x006D2490 (FUN_006D2490, func_CastUnitOpt)
   *
   * What it does:
   * Performs optional Lua `_c_object` to `Unit*` conversion: returns null for
   * missing/destroyed/non-unit payloads without raising Lua conversion errors.
   */
  [[nodiscard]] Unit* CastUnitOptionalFromLuaObject(const LuaPlus::LuaObject& unitObject)
  {
    const LuaPlus::LuaObject copiedObject(unitObject);
    CScriptObject** const scriptObjectSlot = SCR_FromLua_CScriptObject(copiedObject);
    if (!scriptObjectSlot) {
      return nullptr;
    }

    CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      return nullptr;
    }

    const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
    return UpcastUnitFromRef(sourceRef);
  }
}



/**
 * Address: 0x0067F080 (FUN_0067F080, func_GetUnitFactory)
 *
 * What it does:
 * Returns cached `Unit` metatable object from Lua object-factory storage.
 */
LuaPlus::LuaObject* moho::func_GetUnitFactory(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
{
  if (object == nullptr) {
    return nullptr;
  }

  *object = moho::CScrLuaMetatableFactory<moho::Unit>::Instance().Get(state);
  return object;
}

/**
 * Address: 0x006C3AB0 (FUN_006C3AB0, cfunc_UnitGetUnitId)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetUnitIdL`.
 */
int moho::cfunc_UnitGetUnitId(lua_State* const luaContext)
{
  return cfunc_UnitGetUnitIdL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C3AD0 (FUN_006C3AD0, func_UnitGetUnitId_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetUnitId()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetUnitId_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetUnitIdName,
    &moho::cfunc_UnitGetUnitId,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetUnitIdHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C3B30 (FUN_006C3B30, cfunc_UnitGetUnitIdL)
 *
 * What it does:
 * Returns this unit's blueprint-id token string.
 */
int moho::cfunc_UnitGetUnitIdL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetUnitIdHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  const RUnitBlueprint* const blueprint = unit->GetBlueprint();

  const char* unitId = "";
  if (blueprint != nullptr) {
    unitId = blueprint->mBlueprintId.c_str();
  }

  lua_pushstring(rawState, unitId);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C3E00 (FUN_006C3E00, cfunc_UnitGetCargoL)
 *
 * What it does:
 * Returns a Lua array containing script objects for all units currently loaded
 * by this transport unit.
 */
int moho::cfunc_UnitGetCargoL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetCargoHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  IAiTransport* const transport = unit->AiTransport;
  if (transport == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCargoTransportOnlyText);
  }

  EntitySetTemplate<Unit> loadedUnits = transport->TransportGetLoadedUnits(false);

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, 0, 0);

  int resultIndex = 1;
  for (Unit* const cargoUnit : loadedUnits) {
    LuaPlus::LuaObject cargoObject = cargoUnit->GetLuaObject();
    resultTable.Insert(resultIndex, cargoObject);
    ++resultIndex;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x006C3D80 (FUN_006C3D80, cfunc_UnitGetCargo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetCargoL`.
 */
int moho::cfunc_UnitGetCargo(lua_State* const luaContext)
{
  return cfunc_UnitGetCargoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C3DA0 (FUN_006C3DA0, func_UnitGetCargo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetCargo()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCargo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetCargoName,
    &moho::cfunc_UnitGetCargo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCargoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4180 (FUN_006C4180, cfunc_UnitGetArmorMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetArmorMultL`.
 */
int moho::cfunc_UnitGetArmorMult(lua_State* const luaContext)
{
  return cfunc_UnitGetArmorMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C41A0 (FUN_006C41A0, func_UnitGetArmorMult_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetArmorMult(damageTypeName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetArmorMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetArmorMultName,
    &moho::cfunc_UnitGetArmorMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetArmorMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4200 (FUN_006C4200, cfunc_UnitGetArmorMultL)
 *
 * What it does:
 * Returns this unit's damage-type armor multiplier, defaulting to `1.0` when
 * the armor map has no matching entry.
 */
int moho::cfunc_UnitGetArmorMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitGetArmorMultHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject damageTypeArg(state, 2);
  const char* damageTypeName = lua_tostring(rawState, 2);
  if (damageTypeName == nullptr) {
    damageTypeArg.TypeError("string");
    damageTypeName = "";
  }

  const float armorMultiplier = unit->GetArmorMult(fa::string(damageTypeName));
  lua_pushnumber(rawState, armorMultiplier);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C4670 (FUN_006C4670, cfunc_UnitGetFocusUnit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetFocusUnitL`.
 */
int moho::cfunc_UnitGetFocusUnit(lua_State* const luaContext)
{
  return cfunc_UnitGetFocusUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4690 (FUN_006C4690, func_UnitGetFocusUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetFocusUnit(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetFocusUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetFocusUnitName,
    &moho::cfunc_UnitGetFocusUnit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetFocusUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C46F0 (FUN_006C46F0, cfunc_UnitGetFocusUnitL)
 *
 * What it does:
 * Returns focused unit Lua object when the current focused entity resolves to
 * one unit; otherwise returns `nil`.
 */
int moho::cfunc_UnitGetFocusUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetFocusUnitHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (Entity* const focusEntity = unit->GetFocusEntity(); focusEntity != nullptr) {
    if (Unit* const focusUnit = focusEntity->IsUnit(); focusUnit != nullptr) {
      LuaPlus::LuaObject focusUnitObject = focusUnit->GetLuaObject();
      focusUnitObject.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C4800 (FUN_006C4800, cfunc_UnitGetWeapon)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetWeaponL`.
 */
int moho::cfunc_UnitGetWeapon(lua_State* const luaContext)
{
  return cfunc_UnitGetWeaponL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4820 (FUN_006C4820, func_UnitGetWeapon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetWeapon(self,index)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetWeapon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetWeaponName,
    &moho::cfunc_UnitGetWeapon,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetWeaponHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4880 (FUN_006C4880, cfunc_UnitGetWeaponL)
 *
 * What it does:
 * Returns one unit weapon Lua object for arg #2 index (1-based), or nil when
 * no weapon object is available at that lane.
 */
int moho::cfunc_UnitGetWeaponL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitGetWeaponHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject weaponIndexArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    weaponIndexArg.TypeError("integer");
  }

  const int weaponIndex = static_cast<int>(lua_tonumber(rawState, 2)) - 1;
  CAiAttackerImpl* attacker = unit->AiAttacker;
  const int attackerWeaponCount = attacker ? attacker->GetWeaponCount() : 0;
  if (weaponIndex >= attackerWeaponCount) {
    attacker = unit->AiAttacker;
    const int maxWeaponCount = attacker ? attacker->GetWeaponCount() : 0;
    LuaPlus::LuaState::Error(state, kUnitGetWeaponInvalidIndexError, weaponIndex + 1, maxWeaponCount);
  }

  attacker = unit->AiAttacker;
  if (attacker != nullptr) {
    UnitWeapon* const weapon = static_cast<UnitWeapon*>(attacker->GetWeapon(weaponIndex));
    if (weapon != nullptr) {
      weapon->mLuaObj.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C49F0 (FUN_006C49F0, cfunc_UnitGetWeaponCount)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetWeaponCountL`.
 */
int moho::cfunc_UnitGetWeaponCount(lua_State* const luaContext)
{
  return cfunc_UnitGetWeaponCountL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4A10 (FUN_006C4A10, func_UnitGetWeaponCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetWeaponCount(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetWeaponCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetWeaponCountName,
    &moho::cfunc_UnitGetWeaponCount,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetWeaponCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4A70 (FUN_006C4A70, cfunc_UnitGetWeaponCountL)
 *
 * What it does:
 * Returns the attacker-side runtime weapon count for this unit.
 */
int moho::cfunc_UnitGetWeaponCountL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetWeaponCountHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const CAiAttackerImpl* const attacker = unit->AiAttacker;
  const int weaponCount = attacker ? const_cast<CAiAttackerImpl*>(attacker)->GetWeaponCount() : 0;
  lua_pushnumber(rawState, static_cast<float>(weaponCount));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C4B40 (FUN_006C4B40, cfunc_UnitGetTargetEntity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetTargetEntityL`.
 */
int moho::cfunc_UnitGetTargetEntity(lua_State* const luaContext)
{
  return cfunc_UnitGetTargetEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4B60 (FUN_006C4B60, func_UnitGetTargetEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetTargetEntity(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetTargetEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetTargetEntityName,
    &moho::cfunc_UnitGetTargetEntity,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetTargetEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4BC0 (FUN_006C4BC0, cfunc_UnitGetTargetEntityL)
 *
 * What it does:
 * Returns the current desired target entity Lua object from the unit attacker
 * manager, or `nil` when no desired target is available.
 */
int moho::cfunc_UnitGetTargetEntityL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetTargetEntityHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  CAiAttackerImpl* const attacker = unit->AiAttacker;
  if (attacker != nullptr) {
    CAiTarget* const desiredTarget = attacker->GetDesiredTarget();
    if (Entity* const targetEntity = desiredTarget ? desiredTarget->GetEntity() : nullptr; targetEntity != nullptr) {
      targetEntity->mLuaObj.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C4CA0 (FUN_006C4CA0, cfunc_UnitGetHealth)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetHealthL`.
 */
int moho::cfunc_UnitGetHealth(lua_State* const luaContext)
{
  return cfunc_UnitGetHealthL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4CC0 (FUN_006C4CC0, func_UnitGetHealth_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetHealth(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetHealth_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetHealthName,
    &moho::cfunc_UnitGetHealth,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetHealthHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4D20 (FUN_006C4D20, cfunc_UnitGetHealthL)
 *
 * What it does:
 * Returns this unit's current health scalar.
 */
int moho::cfunc_UnitGetHealthL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetHealthHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = SCR_FromLua_Unit(unitObject);
  lua_pushnumber(rawState, unit->mVarDat.mHealth);
  return 1;
}

/**
 * Address: 0x006C4E10 (FUN_006C4E10, cfunc_UnitGetAttacker)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetAttackerL`.
 */
int moho::cfunc_UnitGetAttacker(lua_State* const luaContext)
{
  return cfunc_UnitGetAttackerL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4E30 (FUN_006C4E30, func_UnitGetAttacker_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetAttacker()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetAttacker_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetAttackerName,
    &moho::cfunc_UnitGetAttacker,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetAttackerHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4E90 (FUN_006C4E90, cfunc_UnitGetAttackerL)
 *
 * What it does:
 * Returns this unit's tactical attacker manager object, or nil when absent.
 */
int moho::cfunc_UnitGetAttackerL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetAttackerHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  CAiAttackerImpl* const attacker = unit->AiAttacker;
  if (attacker != nullptr) {
    attacker->PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x008BA9F0 (FUN_008BA9F0, cfunc_GetIsPaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetIsPausedL`.
 */
int moho::cfunc_GetIsPaused(lua_State* const luaContext)
{
  return cfunc_GetIsPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BAA10 (FUN_008BAA10, func_GetIsPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetIsPaused(units)`.
 */
CScrLuaInitForm* moho::func_GetIsPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kGetIsPausedGlobalName,
    &moho::cfunc_GetIsPaused,
    nullptr,
    kGlobalLuaClassName,
    kGetIsPausedGlobalHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BAA70 (FUN_008BAA70, cfunc_GetIsPausedL)
 *
 * What it does:
 * Returns true when any live unit in the input table is paused.
 */
int moho::cfunc_GetIsPausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetIsPausedGlobalHelpText);

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));
  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      // 0x008BAB2D: IUnit slot 10 (`IsDead`), then `mUnitVarDat.mIsPaused` at +0x1B0.
      if (userUnit != nullptr && !userUnit->IsDead() && userUnit->mUnitVarDat.mIsPaused) {
        lua_pushboolean(rawState, 1);
        (void)lua_gettop(rawState);
        return 1;
      }
    }
  }

  lua_pushboolean(rawState, 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008BABA0 (FUN_008BABA0, cfunc_GetIsAutoMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetIsAutoModeL`.
 */
int moho::cfunc_GetIsAutoMode(lua_State* const luaContext)
{
  return cfunc_GetIsAutoModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BABC0 (FUN_008BABC0, func_GetIsAutoMode_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetIsAutoMode(units)`.
 */
CScrLuaInitForm* moho::func_GetIsAutoMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kGetIsAutoModeGlobalName,
    &moho::cfunc_GetIsAutoMode,
    nullptr,
    kGlobalLuaClassName,
    kGetIsAutoModeGlobalHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BAC20 (FUN_008BAC20, cfunc_GetIsAutoModeL)
 *
 * What it does:
 * Returns true when all live units in the input table report auto mode.
 */
int moho::cfunc_GetIsAutoModeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetIsAutoModeGlobalHelpText);

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));
  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      // 0x008BACDD: IUnit slot 10 (`IsDead`), then primary slot 20 (`GetAutoMode`).
      if (userUnit != nullptr && !userUnit->IsDead() && !userUnit->GetAutoMode()) {
        lua_pushboolean(rawState, 0);
        (void)lua_gettop(rawState);
        return 1;
      }
    }
  }

  lua_pushboolean(rawState, 1);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008BAF60 (FUN_008BAF60, cfunc_GetIsSubmerged)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetIsSubmergedL`.
 */
int moho::cfunc_GetIsSubmerged(lua_State* const luaContext)
{
  return cfunc_GetIsSubmergedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BAF80 (FUN_008BAF80, func_GetIsSubmerged_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetIsSubmerged(units)`.
 */
CScrLuaInitForm* moho::func_GetIsSubmerged_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kGetIsSubmergedGlobalName,
    &moho::cfunc_GetIsSubmerged,
    nullptr,
    kGlobalLuaClassName,
    kGetIsSubmergedGlobalHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BAFE0 (FUN_008BAFE0, cfunc_GetIsSubmergedL)
 *
 * What it does:
 * Returns `-1` when all listed units are submerged, `1` when all are not
 * submerged, and `0` when mixed/unknown.
 */
int moho::cfunc_GetIsSubmergedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetIsSubmergedGlobalHelpText);

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));

  std::int32_t submergedState = 0;
  if (unitsObject.IsTable()) {
    // The bound is re-read every iteration (`GetCount` again at 0x008BB0C5).
    for (int unitIndex = 1; unitIndex <= unitsObject.GetCount(); ++unitIndex) {
      const LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      // 0x008BB09B: no null or death test; reads `mVariableData.mLayerMask`
      // (+0xF0) directly and maps Sub -> -1, anything else -> 1.
      const std::int32_t unitState = userUnit->mVariableData.mLayerMask != LAYER_Sub ? 1 : -1;

      if (unitIndex == 1) {
        submergedState = unitState;
      } else if (unitState != submergedState) {
        submergedState = 0;
        break;
      }
    }
  }

  lua_pushnumber(rawState, static_cast<float>(submergedState));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008BB120 (FUN_008BB120, cfunc_GetIsAutoSurfaceMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetIsAutoSurfaceModeL`.
 */
int moho::cfunc_GetIsAutoSurfaceMode(lua_State* const luaContext)
{
  return cfunc_GetIsAutoSurfaceModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB140 (FUN_008BB140, func_GetIsAutoSurfaceMode_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetIsAutoSurfaceMode(units)`.
 */
CScrLuaInitForm* moho::func_GetIsAutoSurfaceMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kGetIsAutoSurfaceModeGlobalName,
    &moho::cfunc_GetIsAutoSurfaceMode,
    nullptr,
    kGlobalLuaClassName,
    kGetIsAutoSurfaceModeGlobalHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB1A0 (FUN_008BB1A0, cfunc_GetIsAutoSurfaceModeL)
 *
 * What it does:
 * Returns true when all live units in the input table report auto-surface mode.
 */
int moho::cfunc_GetIsAutoSurfaceModeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetIsAutoSurfaceModeGlobalHelpText);

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));
  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      // 0x008BB25D: IUnit slot 10 (`IsDead`), then primary slot 21 (`IsAutoSurfaceMode`).
      if (userUnit != nullptr && !userUnit->IsDead() && !userUnit->IsAutoSurfaceMode()) {
        lua_pushboolean(rawState, 0);
        (void)lua_gettop(rawState);
        return 1;
      }
    }
  }

  lua_pushboolean(rawState, 1);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008BB560 (FUN_008BB560, cfunc_GetFireStateL)
 *
 * What it does:
 * Reads one table of user units and returns one shared fire-state value when
 * all eligible units agree, otherwise `-1`.
 */
int moho::cfunc_GetFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kGetFireStateArgsHelpText);

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));

  std::int32_t fireState = 3;
  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      if (userUnit == nullptr || userUnit->IsDead()) {
        continue;
      }

      // 0x008BB648: IUnit slot 16 (`GetAttributes`), `test byte [eax+60h], 20h`.
      if ((userUnit->GetAttributes().commandCapsMask & static_cast<std::uint32_t>(RULEUCC_RetaliateToggle)) == 0u) {
        continue;
      }

      if (fireState == 3) {
        fireState = userUnit->mUnitVarDat.mFireState;
      } else if (fireState != userUnit->mUnitVarDat.mFireState) {
        fireState = -1;
      }
    }
  }

  if (fireState == 3) {
    fireState = -1;
  }

  lua_pushnumber(rawState, static_cast<float>(fireState));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008BB4E0 (FUN_008BB4E0, cfunc_GetFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetFireStateL`.
 */
int moho::cfunc_GetFireState(lua_State* const luaContext)
{
  return cfunc_GetFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB500 (FUN_008BB500, func_GetFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `GetFireState(units)`.
 */
CScrLuaInitForm* moho::func_GetFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kGetFireStateName,
    &moho::cfunc_GetFireState,
    nullptr,
    kGlobalLuaClassName,
    kGetFireStateBindHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CD380 (FUN_006CD380, cfunc_UnitGetGuardedUnitL)
 *
 * What it does:
 * Resolves one unit and pushes its guarded target unit Lua object, or `nil`.
 */
int moho::cfunc_UnitGetGuardedUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetGuardedUnitHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (Unit* const guardedUnit = unit->GetGuardedUnit(); guardedUnit != nullptr) {
    LuaPlus::LuaObject guardedUnitObject = guardedUnit->GetLuaObject();
    guardedUnitObject.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x006CD300 (FUN_006CD300, cfunc_UnitGetGuardedUnit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetGuardedUnitL`.
 */
int moho::cfunc_UnitGetGuardedUnit(lua_State* const luaContext)
{
  return cfunc_UnitGetGuardedUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD320 (FUN_006CD320, func_UnitGetGuardedUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetGuardedUnit()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetGuardedUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetGuardedUnitName,
    &moho::cfunc_UnitGetGuardedUnit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetGuardedUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CD4E0 (FUN_006CD4E0, cfunc_UnitGetGuardsL)
 *
 * What it does:
 * Returns a Lua array containing script objects for units currently guarding
 * this unit.
 */
int moho::cfunc_UnitGetGuardsL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetGuardsHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  LuaPlus::LuaObject guardsTable{};
  guardsTable.AssignNewTable(state, 0, 0);

  int guardIndex = 1;
  // Each entry is the guard's `Entity`; the unit is its null-guarded `-8`
  // downcast (0x006CD5C6).
  for (Entity* const entry : unit->GuardedByList.mVec) {
    Unit* const guardUnit = static_cast<Unit*>(entry);
    if (guardUnit == nullptr) {
      continue;
    }

    LuaPlus::LuaObject guardObject = guardUnit->mLuaObj;
    guardsTable.Insert(guardIndex, guardObject);
    ++guardIndex;
  }

  guardsTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x006CD460 (FUN_006CD460, cfunc_UnitGetGuards)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetGuardsL`.
 */
int moho::cfunc_UnitGetGuards(lua_State* const luaContext)
{
  return cfunc_UnitGetGuardsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD480 (FUN_006CD480, func_UnitGetGuards_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetGuards()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetGuards_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetGuardsName,
    &moho::cfunc_UnitGetGuards,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetGuardsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CD6E0 (FUN_006CD6E0, cfunc_UnitGetTransportFerryBeaconL)
 *
 * What it does:
 * Returns the front command's ferry-beacon unit Lua object, or `nil` when no
 * valid beacon unit is available.
 */
int moho::cfunc_UnitGetTransportFerryBeaconL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetTransportFerryBeaconHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  Unit* const ferryBeacon = (unit != nullptr) ? unit->GetTransportFerryBeacon() : nullptr;
  if (ferryBeacon != nullptr) {
    LuaPlus::LuaObject ferryBeaconLuaObject = ferryBeacon->GetLuaObject();
    ferryBeaconLuaObject.PushStack(state);
    return 1;
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CD660 (FUN_006CD660, cfunc_UnitGetTransportFerryBeacon)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetTransportFerryBeaconL`.
 */
int moho::cfunc_UnitGetTransportFerryBeacon(lua_State* const luaContext)
{
  return cfunc_UnitGetTransportFerryBeaconL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD680 (FUN_006CD680, func_UnitGetTransportFerryBeacon_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetTransportFerryBeacon()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetTransportFerryBeacon_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetTransportFerryBeaconName,
    &moho::cfunc_UnitGetTransportFerryBeacon,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetTransportFerryBeaconHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CD860 (FUN_006CD860, cfunc_UnitHasValidTeleportDestL)
 *
 * What it does:
 * Returns whether the unit has a non-zero teleport destination on its transport AI lane.
 */
int moho::cfunc_UnitHasValidTeleportDestL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitHasValidTeleportDestHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  bool hasValidTeleportDestination = false;
  if (unit != nullptr) {
    if (IAiTransport* const aiTransport = unit->AiTransport; aiTransport != nullptr) {
      const Wm3::Vec3f teleportDestination = aiTransport->TransportGetTeleportDest();
      const Wm3::Vec3f zero{};
      hasValidTeleportDestination = teleportDestination != zero;
    }
  }

  lua_pushboolean(rawState, hasValidTeleportDestination ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CD7E0 (FUN_006CD7E0, cfunc_UnitHasValidTeleportDest)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitHasValidTeleportDestL`.
 */
int moho::cfunc_UnitHasValidTeleportDest(lua_State* const luaContext)
{
  return cfunc_UnitHasValidTeleportDestL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD800 (FUN_006CD800, func_UnitHasValidTeleportDest_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:HasValidTeleportDest()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitHasValidTeleportDest_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitHasValidTeleportDestName,
    &moho::cfunc_UnitHasValidTeleportDest,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitHasValidTeleportDestHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CDCB0 (FUN_006CDCB0, func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:HasMeleeSpaceAroundTarget(target)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitHasMeleeSpaceAroundTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitHasMeleeSpaceAroundTargetName,
    &moho::cfunc_UnitHasMeleeSpaceAroundTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitHasMeleeSpaceAroundTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CDD10 (FUN_006CDD10, cfunc_UnitHasMeleeSpaceAroundTargetL)
 *
 * IDA signature:
 * int __thiscall cfunc_UnitHasMeleeSpaceAroundTargetL(LuaPlus::LuaState *this);
 *
 * What it does:
 * Reads `(meleeUnit, target)`, computes the target footprint-origin cell, and
 * pushes whether the melee unit has adjacent melee space around the target
 * (large-target check for mobile multi-cell targets, otherwise the small-target
 * check). Returns the boolean to Lua.
 */
int moho::cfunc_UnitHasMeleeSpaceAroundTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitHasMeleeSpaceAroundTargetHelpText);

  const LuaPlus::LuaObject meleeUnitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const meleeUnit = SCR_FromLua_Unit(meleeUnitObject);

  const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const target = SCR_FromLua_Unit(targetObject);

  const SFootprint& targetFootprint = target->GetFootprint();
  const Wm3::Vec3f& targetPosition = target->GetPosition();

  SOCellPos cell{};
  cell.x = static_cast<std::int16_t>(static_cast<int>(std::lrintf(targetPosition.x - (targetFootprint.mSizeX * 0.5f))));
  cell.z = static_cast<std::int16_t>(static_cast<int>(std::lrintf(targetPosition.z - (targetFootprint.mSizeZ * 0.5f))));

  bool useLargeTargetCheck = false;
  if (target->IsMobile()) {
    const SFootprint& mobileFootprint = target->GetFootprint();
    if (std::max<int>(mobileFootprint.mSizeX, mobileFootprint.mSizeZ) > 1) {
      useLargeTargetCheck = true;
    }
  }

  const bool hasMeleeSpace = useLargeTargetCheck
    ? meleeUnit->HasMeleeSpaceAroundLargeTarget(target, &cell, 1)
    : meleeUnit->HasMeleeSpaceAroundSmallTarget(target, &cell);

  lua_pushboolean(rawState, hasMeleeSpace ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CDC90 (FUN_006CDC90, cfunc_UnitHasMeleeSpaceAroundTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitHasMeleeSpaceAroundTargetL`.
 */
int moho::cfunc_UnitHasMeleeSpaceAroundTarget(lua_State* const luaContext)
{
  return cfunc_UnitHasMeleeSpaceAroundTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CE280 (FUN_006CE280, cfunc_UnitGetCommandQueueL)
 *
 * What it does:
 * Returns Lua array copy of one unit's current command queue.
 */
int moho::cfunc_UnitGetCommandQueueL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetCommandQueueHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);
  if (unit == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidUnitError);
    return 0;
  }

  CUnitCommandQueue* const commandQueue = unit->CommandQueue;
  if (commandQueue == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidQueueError);
    return 0;
  }

  const fa::vector<WeakPtr<CUnitCommand>> commandSnapshot = commandQueue->mCommandVec;

  LuaPlus::LuaObject queueArray{};
  const int commandCount = static_cast<int>(commandSnapshot.size());
  queueArray.AssignNewTable(state, commandCount, 0u);
  for (const WeakPtr<CUnitCommand>& commandWeakPtr : commandSnapshot) {
    CUnitCommand* const command = commandWeakPtr.GetObjectPtr();
    if (command == nullptr) {
      continue;
    }

    SimGetCommandQueueInsert(queueArray, *command);
  }

  queueArray.PushStack(state);
  return 1;
}

/**
 * Address: 0x006CE200 (FUN_006CE200, cfunc_UnitGetCommandQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetCommandQueueL`.
 */
int moho::cfunc_UnitGetCommandQueue(lua_State* const luaContext)
{
  return cfunc_UnitGetCommandQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CE220 (FUN_006CE220, func_UnitGetCommandQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetCommandQueue()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCommandQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetCommandQueueName,
    &moho::cfunc_UnitGetCommandQueue,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCommandQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CEAE0 (FUN_006CEAE0, cfunc_UnitGetCurrentMoveLocationL)
 *
 * What it does:
 * Returns one current command target-position vector for supported movement
 * command types, or `false` when no supported active move command exists.
 */
int moho::cfunc_UnitGetCurrentMoveLocationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetCurrentMoveLocationHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);
  if (unit == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCurrentMoveLocationInvalidUnitError);
    return 0;
  }

  const CUnitCommandQueue* const commandQueue = unit->CommandQueue;
  const CUnitCommand* command = nullptr;
  if (commandQueue != nullptr && !commandQueue->mCommandVec.empty()) {
    command = commandQueue->mCommandVec.front().GetObjectPtr();
  }

  if (command != nullptr) {
    switch (command->mVarDat.mCmdType) {
      case EUnitCommandType::UNITCOMMAND_Move:
      case EUnitCommandType::UNITCOMMAND_FormMove:
      case EUnitCommandType::UNITCOMMAND_Attack:
      case EUnitCommandType::UNITCOMMAND_FormAttack:
      case EUnitCommandType::UNITCOMMAND_Patrol:
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
      case EUnitCommandType::UNITCOMMAND_Reclaim:
      case EUnitCommandType::UNITCOMMAND_Repair:
      case EUnitCommandType::UNITCOMMAND_Capture:
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits:
      case EUnitCommandType::UNITCOMMAND_Upgrade:
      case EUnitCommandType::UNITCOMMAND_Sacrifice:
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
      case EUnitCommandType::UNITCOMMAND_Dock: {
        const LuaPlus::LuaObject moveLocation = SCR_ToLua<Wm3::Vector3<float>>(state, command->mVarDat.mTarget1.mPos);
        moveLocation.PushStack(state);
        return 1;
      }
      default:
        break;
    }
  }

  lua_pushboolean(rawState, 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CEA60 (FUN_006CEA60, cfunc_UnitGetCurrentMoveLocation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetCurrentMoveLocationL`.
 */
int moho::cfunc_UnitGetCurrentMoveLocation(lua_State* const luaContext)
{
  return cfunc_UnitGetCurrentMoveLocationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CEA80 (FUN_006CEA80, func_UnitGetCurrentMoveLocation_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetCurrentMoveLocation()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCurrentMoveLocation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetCurrentMoveLocationName,
    &moho::cfunc_UnitGetCurrentMoveLocation,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCurrentMoveLocationHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CEFE0 (FUN_006CEFE0, cfunc_UnitGetNukeSiloAmmoCountL)
 *
 * What it does:
 * Returns the nuke silo stored ammo count for a unit, or `0` when absent.
 */
int moho::cfunc_UnitGetNukeSiloAmmoCountL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetNukeSiloAmmoCountHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  float nukeAmmoCount = 0.0f;
  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      nukeAmmoCount = static_cast<float>(siloBuild->SiloGetStorageCount(SILOTYPE_Nuke));
    }
  }

  lua_pushnumber(rawState, nukeAmmoCount);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CEF60 (FUN_006CEF60, cfunc_UnitGetNukeSiloAmmoCount)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetNukeSiloAmmoCountL`.
 */
int moho::cfunc_UnitGetNukeSiloAmmoCount(lua_State* const luaContext)
{
  return cfunc_UnitGetNukeSiloAmmoCountL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CEF80 (FUN_006CEF80, func_UnitGetNukeSiloAmmoCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetNukeSiloAmmoCount()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetNukeSiloAmmoCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetNukeSiloAmmoCountName,
    &moho::cfunc_UnitGetNukeSiloAmmoCount,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetNukeSiloAmmoCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CF3F0 (FUN_006CF3F0, cfunc_UnitGetTacticalSiloAmmoCountL)
 *
 * What it does:
 * Returns tactical silo stored ammo count for a unit, or `0` when absent.
 */
int moho::cfunc_UnitGetTacticalSiloAmmoCountL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetTacticalSiloAmmoCountHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  float tacticalAmmoCount = 0.0f;
  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      tacticalAmmoCount = static_cast<float>(siloBuild->SiloGetStorageCount(SILOTYPE_Tactical));
    }
  }

  lua_pushnumber(rawState, tacticalAmmoCount);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CF370 (FUN_006CF370, cfunc_UnitGetTacticalSiloAmmoCount)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetTacticalSiloAmmoCountL`.
 */
int moho::cfunc_UnitGetTacticalSiloAmmoCount(lua_State* const luaContext)
{
  return cfunc_UnitGetTacticalSiloAmmoCountL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CF390 (FUN_006CF390, func_UnitGetTacticalSiloAmmoCount_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetTacticalSiloAmmoCount()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetTacticalSiloAmmoCount_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetTacticalSiloAmmoCountName,
    &moho::cfunc_UnitGetTacticalSiloAmmoCount,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetTacticalSiloAmmoCountHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BBB90 (FUN_008BBB90, cfunc_GetScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetScriptBitL`.
 */
int moho::cfunc_GetScriptBit(lua_State* const luaContext)
{
  return cfunc_GetScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BBBB0 (FUN_008BBBB0, func_GetScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetScriptBit`.
 */
CScrLuaInitForm* moho::func_GetScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    "GetScriptBit",
    &moho::cfunc_GetScriptBit,
    nullptr,
    kGlobalLuaClassName,
    "Get the state for the script big"
  );
  return &binder;
}

/**
 * Address: 0x008BBC10 (FUN_008BBC10, cfunc_GetScriptBitL)
 *
 * What it does:
 * Returns true if any non-dead user unit in the input table supports `bit`
 * via toggle caps and currently has that script bit set.
 */
int moho::cfunc_GetScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitGetScriptBitHelpText);

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));

  const LuaPlus::LuaStackObject bitArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    bitArg.TypeError("integer");
  }
  const int bitIndex = static_cast<int>(lua_tonumber(rawState, 2));

  bool hasBitSet = false;
  if (unitsObject.IsTable()) {
    const int count = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= count; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      if (userUnit == nullptr || userUnit->IsDead()) {
        continue;
      }

      // 0x008BBD4A: IUnit slot 16 (`GetAttributes`); `shl edx, cl` masks the
      // count to five bits.
      const std::uint32_t toggleMask = 1u << (static_cast<std::uint32_t>(bitIndex) & 0x1Fu);
      if ((userUnit->GetAttributes().toggleCapsMask & toggleMask) == 0u) {
        continue;
      }

      // 0x008BBD63: `mUnitVarDat.mScriptbits` (+0x3A8) sign-extended (`cdq`)
      // and tested against `__allshl(1, cl)`, which reads only the low byte
      // of the count and yields 0 once it reaches 64.
      const std::uint8_t bitShift = static_cast<std::uint8_t>(bitIndex);
      const std::int64_t scriptBits =
        static_cast<std::int64_t>(static_cast<std::int32_t>(userUnit->mUnitVarDat.mScriptbits));
      const std::int64_t scriptBitMask = bitShift < 64u ? static_cast<std::int64_t>(1ull << bitShift) : 0;
      if ((scriptBits & scriptBitMask) != 0) {
        hasBitSet = true;
        break;
      }
    }
  }

  lua_pushboolean(rawState, hasBitSet ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5980 (FUN_006C5980, cfunc_UnitIsUnitStateL)
 *
 * What it does:
 * Resolves `(unit, stateName)` and returns whether that runtime unit-state bit
 * is currently set.
 */
int moho::cfunc_UnitIsUnitStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitIsUnitStateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  EUnitState unitState = UNITSTATE_Immobile;
  gpg::RRef enumRef = MakeUnitStateRef(&unitState);
  const LuaPlus::LuaStackObject stateArg(state, 2);
  const char* const stateName = lua_tostring(rawState, 2);
  if (stateName == nullptr) {
    stateArg.TypeError("string");
  }
  SCR_GetEnum(state, stateName, enumRef);

  lua_pushboolean(rawState, unit->IsUnitState(unitState) ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5900 (FUN_006C5900, cfunc_UnitIsUnitState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsUnitStateL`.
 */
int moho::cfunc_UnitIsUnitState(lua_State* const luaContext)
{
  return cfunc_UnitIsUnitStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5920 (FUN_006C5920, func_UnitIsUnitState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsUnitState(unit, stateName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsUnitState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsUnitStateName,
    &moho::cfunc_UnitIsUnitState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsUnitStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5B20 (FUN_006C5B20, cfunc_UnitIsIdleStateL)
 *
 * What it does:
 * Returns whether a unit has no live front command in its current queue.
 */
int moho::cfunc_UnitIsIdleStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitIsIdleStateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  const bool isIdle = (unit == nullptr) || unit->IsIdleState();

  lua_pushboolean(rawState, isIdle ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5AA0 (FUN_006C5AA0, cfunc_UnitIsIdleState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsIdleStateL`.
 */
int moho::cfunc_UnitIsIdleState(lua_State* const luaContext)
{
  return cfunc_UnitIsIdleStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5AC0 (FUN_006C5AC0, func_UnitIsIdleState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsIdleState(unit)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsIdleState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsIdleStateName,
    &moho::cfunc_UnitIsIdleState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsIdleStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5C90 (FUN_006C5C90, cfunc_UnitIsStunnedL)
 *
 * What it does:
 * Returns true when arg#1 does not resolve to a unit or the unit has active
 * stun ticks.
 */
int moho::cfunc_UnitIsStunnedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitIsStunnedHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = GetUnitOptional(unitObject);
  const bool isStunned = (unit == nullptr) || (unit->mUnitVarDat.mStunTicks != 0);
  lua_pushboolean(rawState, isStunned ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5C10 (FUN_006C5C10, cfunc_UnitIsStunned)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsStunnedL`.
 */
int moho::cfunc_UnitIsStunned(lua_State* const luaContext)
{
  return cfunc_UnitIsStunnedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5C30 (FUN_006C5C30, func_UnitIsStunned_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsStunned(unit)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsStunned_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsStunnedName,
    &moho::cfunc_UnitIsStunned,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsStunnedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5DE0 (FUN_006C5DE0, cfunc_UnitIsBeingBuiltL)
 *
 * What it does:
 * Returns true when arg#1 resolves to a unit currently in being-built state.
 */
int moho::cfunc_UnitIsBeingBuiltL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitIsBeingBuiltHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = GetUnitOptional(unitObject);
  lua_pushboolean(rawState, (unit != nullptr && unit->IsBeingBuilt()) ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5D60 (FUN_006C5D60, cfunc_UnitIsBeingBuilt)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsBeingBuiltL`.
 */
int moho::cfunc_UnitIsBeingBuilt(lua_State* const luaContext)
{
  return cfunc_UnitIsBeingBuiltL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5D80 (FUN_006C5D80, func_UnitIsBeingBuilt_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsBeingBuilt()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsBeingBuilt_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsBeingBuiltName,
    &moho::cfunc_UnitIsBeingBuilt,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsBeingBuiltHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5F30 (FUN_006C5F30, cfunc_UnitIsPausedL)
 *
 * What it does:
 * Returns true when arg#1 resolves to a currently paused unit.
 */
int moho::cfunc_UnitIsPausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitIsPausedHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  const Unit* const unit = GetUnitOptional(unitObject);
  lua_pushboolean(rawState, (unit != nullptr && unit->mUnitVarDat.mIsPaused) ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C5EB0 (FUN_006C5EB0, cfunc_UnitIsPaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsPausedL`.
 */
int moho::cfunc_UnitIsPaused(lua_State* const luaContext)
{
  return cfunc_UnitIsPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5ED0 (FUN_006C5ED0, func_UnitIsPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:IsPaused()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsPausedName,
    &moho::cfunc_UnitIsPaused,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9C50 (FUN_006C9C50, cfunc_UnitGetBuildRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetBuildRateL`.
 */
int moho::cfunc_UnitGetBuildRate(lua_State* const luaContext)
{
  return cfunc_UnitGetBuildRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9C70 (FUN_006C9C70, func_UnitGetBuildRate_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetBuildRate()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetBuildRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetBuildRateName,
    &moho::cfunc_UnitGetBuildRate,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetBuildRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9CD0 (FUN_006C9CD0, cfunc_UnitGetBuildRateL)
 *
 * What it does:
 * Returns `UnitAttributes::buildRate` for arg #1.
 */
int moho::cfunc_UnitGetBuildRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetBuildRateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().buildRate);
  return 1;
}

/**
 * Address: 0x006CA400 (FUN_006CA400, cfunc_UnitGetConsumptionPerSecondEnergy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetConsumptionPerSecondEnergyL`.
 */
int moho::cfunc_UnitGetConsumptionPerSecondEnergy(lua_State* const luaContext)
{
  return cfunc_UnitGetConsumptionPerSecondEnergyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA420 (FUN_006CA420, func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetConsumptionPerSecondEnergy()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetConsumptionPerSecondEnergy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetConsumptionPerSecondEnergyName,
    &moho::cfunc_UnitGetConsumptionPerSecondEnergy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetConsumptionPerSecondEnergyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA480 (FUN_006CA480, cfunc_UnitGetConsumptionPerSecondEnergyL)
 *
 * What it does:
 * Returns `UnitAttributes::consumptionPerSecondEnergy` for arg #1.
 */
int moho::cfunc_UnitGetConsumptionPerSecondEnergyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetConsumptionPerSecondEnergyHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().consumptionPerSecondEnergy);
  return 1;
}

/**
 * Address: 0x006CA550 (FUN_006CA550, cfunc_UnitGetConsumptionPerSecondMass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetConsumptionPerSecondMassL`.
 */
int moho::cfunc_UnitGetConsumptionPerSecondMass(lua_State* const luaContext)
{
  return cfunc_UnitGetConsumptionPerSecondMassL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA570 (FUN_006CA570, func_UnitGetConsumptionPerSecondMass_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetConsumptionPerSecondMass()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetConsumptionPerSecondMass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetConsumptionPerSecondMassName,
    &moho::cfunc_UnitGetConsumptionPerSecondMass,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetConsumptionPerSecondMassHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA5D0 (FUN_006CA5D0, cfunc_UnitGetConsumptionPerSecondMassL)
 *
 * What it does:
 * Returns `UnitAttributes::consumptionPerSecondMass` for arg #1.
 */
int moho::cfunc_UnitGetConsumptionPerSecondMassL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetConsumptionPerSecondMassHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().consumptionPerSecondMass);
  return 1;
}

/**
 * Address: 0x006CA6A0 (FUN_006CA6A0, cfunc_UnitGetProductionPerSecondEnergy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetProductionPerSecondEnergyL`.
 */
int moho::cfunc_UnitGetProductionPerSecondEnergy(lua_State* const luaContext)
{
  return cfunc_UnitGetProductionPerSecondEnergyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA6C0 (FUN_006CA6C0, func_UnitGetProductionPerSecondEnergy_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetProductionPerSecondEnergy()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetProductionPerSecondEnergy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetProductionPerSecondEnergyName,
    &moho::cfunc_UnitGetProductionPerSecondEnergy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetProductionPerSecondEnergyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA720 (FUN_006CA720, cfunc_UnitGetProductionPerSecondEnergyL)
 *
 * What it does:
 * Returns `UnitAttributes::productionPerSecondEnergy` for arg #1.
 */
int moho::cfunc_UnitGetProductionPerSecondEnergyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetProductionPerSecondEnergyHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().productionPerSecondEnergy);
  return 1;
}

/**
 * Address: 0x006CA7F0 (FUN_006CA7F0, cfunc_UnitGetProductionPerSecondMass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetProductionPerSecondMassL`.
 */
int moho::cfunc_UnitGetProductionPerSecondMass(lua_State* const luaContext)
{
  return cfunc_UnitGetProductionPerSecondMassL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA810 (FUN_006CA810, func_UnitGetProductionPerSecondMass_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetProductionPerSecondMass()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetProductionPerSecondMass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetProductionPerSecondMassName,
    &moho::cfunc_UnitGetProductionPerSecondMass,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetProductionPerSecondMassHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA870 (FUN_006CA870, cfunc_UnitGetProductionPerSecondMassL)
 *
 * What it does:
 * Returns `UnitAttributes::productionPerSecondMass` for arg #1.
 */
int moho::cfunc_UnitGetProductionPerSecondMassL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetProductionPerSecondMassHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->GetAttributes().productionPerSecondMass);
  return 1;
}

/**
 * Address: 0x006CA940 (FUN_006CA940, cfunc_UnitGetResourceConsumed)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetResourceConsumedL`.
 */
int moho::cfunc_UnitGetResourceConsumed(lua_State* const luaContext)
{
  return cfunc_UnitGetResourceConsumedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA960 (FUN_006CA960, func_UnitGetResourceConsumed_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetResourceConsumed()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetResourceConsumed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetResourceConsumedName,
    &moho::cfunc_UnitGetResourceConsumed,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetResourceConsumedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA9C0 (FUN_006CA9C0, cfunc_UnitGetResourceConsumedL)
 *
 * What it does:
 * Returns `Unit::ResourceConsumed` for arg #1.
 */
int moho::cfunc_UnitGetResourceConsumedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetResourceConsumedHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->ResourceConsumed);
  return 1;
}

/**
 * Address: 0x006CCCB0 (FUN_006CCCB0, cfunc_UnitGetWorkProgress)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetWorkProgressL`.
 */
int moho::cfunc_UnitGetWorkProgress(lua_State* const luaContext)
{
  return cfunc_UnitGetWorkProgressL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CCCD0 (FUN_006CCCD0, func_UnitGetWorkProgress_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetWorkProgress()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetWorkProgress_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetWorkProgressName,
    &moho::cfunc_UnitGetWorkProgress,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetWorkProgressHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CCD30 (FUN_006CCD30, cfunc_UnitGetWorkProgressL)
 *
 * What it does:
 * Resolves one unit and returns its current work-progress scalar.
 */
int moho::cfunc_UnitGetWorkProgressL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetWorkProgressHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  lua_pushnumber(rawState, unit->mUnitVarDat.mWorkProgress);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C7170 (FUN_006C7170, cfunc_UnitIsValidTargetL)
 *
 * What it does:
 * Returns the current `Unit::IsValidTarget` lane.
 */
int moho::cfunc_UnitIsValidTargetL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitIsValidTargetHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushboolean(rawState, unit->mUnitVarDat.mIsValidTarget ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C70F0 (FUN_006C70F0, cfunc_UnitIsValidTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsValidTargetL`.
 */
int moho::cfunc_UnitIsValidTarget(lua_State* const luaContext)
{
  return cfunc_UnitIsValidTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7110 (FUN_006C7110, func_UnitIsValidTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `bool = IsValidTarget(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsValidTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsValidTargetName,
    &moho::cfunc_UnitIsValidTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsValidTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C72B0 (FUN_006C72B0, cfunc_UnitGetNumBuildOrdersL)
 *
 * What it does:
 * Counts queued build orders for one builder unit that match a category.
 */
int moho::cfunc_UnitGetNumBuildOrdersL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitGetNumBuildOrdersHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  int buildOrderCount = 0;
  if (unit->AiBuilder != nullptr) {
    if (CUnitCommandQueue* const commandQueue = unit->CommandQueue; commandQueue != nullptr) {
      const fa::vector<WeakPtr<CUnitCommand>> commands(commandQueue->mCommandVec);
      for (const WeakPtr<CUnitCommand>& commandWeakRef : commands) {
        const CUnitCommand* const command = commandWeakRef.GetObjectPtr();
        if (!command) {
          continue;
        }

        if (
          command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildFactory
          && command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildMobile
        ) {
          continue;
        }

        const REntityBlueprint* const blueprint = command->mConstDat.blueprint;
        if (blueprint == nullptr) {
          continue;
        }

        if (categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
          buildOrderCount += command->mVarDat.mCount;
        }
      }
    }
  }

  lua_pushnumber(rawState, static_cast<float>(buildOrderCount));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C7230 (FUN_006C7230, cfunc_UnitGetNumBuildOrders)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetNumBuildOrdersL`.
 */
int moho::cfunc_UnitGetNumBuildOrders(lua_State* const luaContext)
{
  return cfunc_UnitGetNumBuildOrdersL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7250 (FUN_006C7250, func_UnitGetNumBuildOrders_LuaFuncDef)
 *
 * What it does:
 * Publishes the `GetNumBuildOrders(self, category)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetNumBuildOrders_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetNumBuildOrdersName,
    &moho::cfunc_UnitGetNumBuildOrders,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetNumBuildOrdersHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C74F0 (FUN_006C74F0, cfunc_UnitCalculateWorldPositionFromRelativeL)
 *
 * What it does:
 * Rotates one relative vector by unit orientation and offsets it by the
 * unit world position.
 *
 * Ground truth (`FUN_006C74F0.c`) rotates via
 * `Moho::MultQuadVec(&v13, &v15, v3)` (`v3` is the unit's transform, reread
 * as a `Wm3::Quaternionf*` since `orient` is its first member), not the
 * generic `Wm3::MultiplyQuaternionVector` -- same quaternion-convention
 * mismatch as the other `orient_`-consuming sites.
 */
int moho::cfunc_UnitCalculateWorldPositionFromRelativeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitCalculateWorldPositionFromRelativeHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject relativePosObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f relativePos = SCR_FromLuaCopy<Wm3::Vector3f>(relativePosObject);

  Wm3::Vector3f rotatedRelativePos{};
  (void)moho::MultQuadVec(&rotatedRelativePos, &relativePos, &unit->GetTransform().orient_);

  const Wm3::Vector3f unitPosition = unit->GetPosition();
  const Wm3::Vector3f worldPosition{
    unitPosition.x + rotatedRelativePos.x,
    unitPosition.y + rotatedRelativePos.y,
    unitPosition.z + rotatedRelativePos.z,
  };

  LuaPlus::LuaObject worldPositionObject = SCR_ToLua<Wm3::Vector3f>(state, worldPosition);
  worldPositionObject.PushStack(state);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C7470 (FUN_006C7470, cfunc_UnitCalculateWorldPositionFromRelative)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitCalculateWorldPositionFromRelativeL`.
 */
int moho::cfunc_UnitCalculateWorldPositionFromRelative(lua_State* const luaContext)
{
  return cfunc_UnitCalculateWorldPositionFromRelativeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7490 (FUN_006C7490, func_UnitCalculateWorldPositionFromRelative_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CalculateWorldPositionFromRelative(self, relPos)` binder.
 */
CScrLuaInitForm* moho::func_UnitCalculateWorldPositionFromRelative_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitCalculateWorldPositionFromRelativeName,
    &moho::cfunc_UnitCalculateWorldPositionFromRelative,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitCalculateWorldPositionFromRelativeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7710 (FUN_006C7710, cfunc_UnitGetScriptBitL)
 *
 * What it does:
 * Resolves one toggle-cap lexical name and returns whether the corresponding
 * script bit is currently set.
 */
int moho::cfunc_UnitGetScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitGetScriptBitMethodHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject toggleCapArg(state, 2);
  const char* const toggleCapName = lua_tostring(rawState, 2);
  if (toggleCapName == nullptr) {
    toggleCapArg.TypeError("string");
  }
  (void)enumRef.SetLexical(toggleCapName);

  const int toggleCapValue = static_cast<int>(toggleCap);
  if (toggleCapValue < 1 || toggleCapValue > 0x100) {
    return 0;
  }

  const int bitIndex = ScriptBitIndexFromToggleCapValue(toggleCapValue);
  const std::uint32_t mask = 1u << static_cast<std::uint32_t>(bitIndex);
  lua_pushboolean(rawState, (unit->mUnitVarDat.mScriptbits & mask) != 0u ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C7690 (FUN_006C7690, cfunc_UnitGetScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetScriptBitL`.
 */
int moho::cfunc_UnitGetScriptBit(lua_State* const luaContext)
{
  return cfunc_UnitGetScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C76B0 (FUN_006C76B0, func_UnitGetScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetScriptBit(toggleName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetScriptBitName,
    &moho::cfunc_UnitGetScriptBit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetScriptBitMethodHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7F20 (FUN_006C7F20, cfunc_UnitGetFireStateL)
 *
 * What it does:
 * Pushes one unit fire-state value as Lua number.
 */
int moho::cfunc_UnitGetFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetFireStateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  lua_pushnumber(rawState, static_cast<float>(unit->mUnitVarDat.mFireState));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C7EA0 (FUN_006C7EA0, cfunc_UnitGetFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetFireStateL`.
 */
int moho::cfunc_UnitGetFireState(lua_State* const luaContext)
{
  return cfunc_UnitGetFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7EC0 (FUN_006C7EC0, func_UnitGetFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GetFireState()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetFireStateName,
    &moho::cfunc_UnitGetFireState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetFireStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9700 (FUN_006C9700, cfunc_UnitIsCapturable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsCapturableL`.
 */
int moho::cfunc_UnitIsCapturable(lua_State* const luaContext)
{
  return cfunc_UnitIsCapturableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9720 (FUN_006C9720, func_UnitIsCapturable_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:IsCapturable()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsCapturable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsCapturableName,
    &moho::cfunc_UnitIsCapturable,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsCapturableHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9780 (FUN_006C9780, cfunc_UnitIsCapturableL)
 *
 * What it does:
 * Resolves one unit and returns `UnitAttributes::mCapturable`.
 */
int moho::cfunc_UnitIsCapturableL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitIsCapturableHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushboolean(rawState, unit->GetAttributes().mCapturable ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C9980 (FUN_006C9980, cfunc_UnitIsOverchargePaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitIsOverchargePausedL`.
 */
int moho::cfunc_UnitIsOverchargePaused(lua_State* const luaContext)
{
  return cfunc_UnitIsOverchargePausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C99A0 (FUN_006C99A0, func_UnitIsOverchargePaused_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:IsOverchargePaused()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsOverchargePaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsOverchargePausedName,
    &moho::cfunc_UnitIsOverchargePaused,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsOverchargePausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9A00 (FUN_006C9A00, cfunc_UnitIsOverchargePausedL)
 *
 * What it does:
 * Resolves one unit and returns `Unit::OverchargePaused`.
 */
int moho::cfunc_UnitIsOverchargePausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitIsOverchargePausedHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushboolean(rawState, unit->mUnitVarDat.mOverchargePaused ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D03E0 (FUN_006D03E0, cfunc_UnitCanBuild)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitCanBuildL`.
 */
int moho::cfunc_UnitCanBuild(lua_State* const luaContext)
{
  return cfunc_UnitCanBuildL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0400 (FUN_006D0400, func_UnitCanBuild_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:CanBuild(blueprint)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitCanBuild_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitCanBuildName,
    &moho::cfunc_UnitCanBuild,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitCanBuildHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0460 (FUN_006D0460, cfunc_UnitCanBuildL)
 *
 * What it does:
 * Resolves one unit and one blueprint id string, then returns whether the
 * unit can build that blueprint according to `Unit::CanBuild`.
 */
int moho::cfunc_UnitCanBuildL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitCanBuildHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject blueprintArg(state, 2);
  const char* blueprintText = lua_tostring(rawState, 2);
  if (!blueprintText) {
    blueprintArg.TypeError("string");
    blueprintText = "";
  }

  RResId blueprintId{};
  gpg::STR_InitFilename(&blueprintId.name, blueprintText);

  RUnitBlueprint* blueprint = nullptr;
  if (unit && unit->SimulationRef && unit->SimulationRef->mRules) {
    blueprint = unit->SimulationRef->mRules->GetUnitBlueprint(blueprintId);
  }

  if (!blueprint) {
    LuaPlus::LuaState::Error(state, kUnitCanBuildUnknownBlueprintError, blueprintText);
  }

  const bool canBuild = unit->CanBuild(blueprint);
  lua_pushboolean(rawState, canBuild ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D05D0 (FUN_006D05D0, cfunc_UnitGetRallyPoint)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetRallyPointL`.
 */
int moho::cfunc_UnitGetRallyPoint(lua_State* const luaContext)
{
  return cfunc_UnitGetRallyPointL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D05F0 (FUN_006D05F0, func_UnitGetRallyPoint_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetRallyPoint()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetRallyPoint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetRallyPointName,
    &moho::cfunc_UnitGetRallyPoint,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetRallyPointHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0650 (FUN_006D0650, cfunc_UnitGetRallyPointL)
 *
 * What it does:
 * Returns the current factory rally-point target position when a builder
 * command is available; otherwise pushes `nil`.
 */
int moho::cfunc_UnitGetRallyPointL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetRallyPointHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (IAiBuilder* const builder = unit->AiBuilder; builder != nullptr) {
    if (CUnitCommand* const command = builder->BuilderGetFactoryCommand(0); command != nullptr) {
      const Wm3::Vec3f rallyPoint = command->mTarget.GetTargetPosGun(false);
      LuaPlus::LuaObject rallyPointObject = SCR_ToLua<Wm3::Vector3<float>>(state, rallyPoint);
      rallyPointObject.PushStack(state);
      return 1;
    }
  }

  lua_pushnil(rawState);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D0770 (FUN_006D0770, cfunc_UnitGetFuelUseTime)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetFuelUseTimeL`.
 */
int moho::cfunc_UnitGetFuelUseTime(lua_State* const luaContext)
{
  return cfunc_UnitGetFuelUseTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0790 (FUN_006D0790, func_UnitGetFuelUseTime_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetFuelUseTime()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetFuelUseTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetFuelUseTimeName,
    &moho::cfunc_UnitGetFuelUseTime,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetFuelUseTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D07F0 (FUN_006D07F0, cfunc_UnitGetFuelUseTimeL)
 *
 * What it does:
 * Returns the unit motion fuel-use-time lane.
 */
int moho::cfunc_UnitGetFuelUseTimeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetFuelUseTimeHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (unit->UnitMotion == nullptr) {
    LuaPlus::LuaState::Error(state, "Unit has not motion object");
  }

  lua_pushnumber(rawState, unit->UnitMotion->mFuelUseTime);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D0A50 (FUN_006D0A50, cfunc_UnitGetFuelRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetFuelRatioL`.
 */
int moho::cfunc_UnitGetFuelRatio(lua_State* const luaContext)
{
  return cfunc_UnitGetFuelRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0A70 (FUN_006D0A70, func_UnitGetFuelRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetFuelRatio()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetFuelRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetFuelRatioName,
    &moho::cfunc_UnitGetFuelRatio,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetFuelRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0AD0 (FUN_006D0AD0, cfunc_UnitGetFuelRatioL)
 *
 * What it does:
 * Returns the unit runtime fuel-ratio lane.
 */
int moho::cfunc_UnitGetFuelRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetFuelRatioHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (unit->UnitMotion == nullptr) {
    LuaPlus::LuaState::Error(state, "Unit has not motion object");
  }

  lua_pushnumber(rawState, unit->mUnitVarDat.mFuelRatio);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D0EA0 (FUN_006D0EA0, cfunc_UnitGetShieldRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetShieldRatioL`.
 */
int moho::cfunc_UnitGetShieldRatio(lua_State* const luaContext)
{
  return cfunc_UnitGetShieldRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0EC0 (FUN_006D0EC0, func_UnitGetShieldRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetShieldRatio()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetShieldRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetShieldRatioName,
    &moho::cfunc_UnitGetShieldRatio,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetShieldRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0F20 (FUN_006D0F20, cfunc_UnitGetShieldRatioL)
 *
 * What it does:
 * Returns the unit runtime shield-ratio lane.
 */
int moho::cfunc_UnitGetShieldRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitGetShieldRatioHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushnumber(rawState, unit->mUnitVarDat.mShieldRatio);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D0FE0 (FUN_006D0FE0, cfunc_UnitGetBlip)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetBlipL`.
 */
int moho::cfunc_UnitGetBlip(lua_State* const luaContext)
{
  return cfunc_UnitGetBlipL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1000 (FUN_006D1000, func_UnitGetBlip_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetBlip(armyIndex)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetBlip_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetBlipName,
    &moho::cfunc_UnitGetBlip,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetBlipHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D1060 (FUN_006D1060, cfunc_UnitGetBlipL)
 *
 * What it does:
 * Resolves one recon blip object for `(unit, army)` and pushes it, or `nil`
 * when no blip is currently tracked.
 */
int moho::cfunc_UnitGetBlipL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitGetBlipHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);
  CAiReconDBImpl* const reconDatabase = army->GetReconDB();
  ReconBlip* const blip = reconDatabase->ReconGetBlip(unit);
  if (blip != nullptr) {
    blip->mLuaObj.PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x006CB790 (FUN_006CB790, cfunc_UnitGetCurrentLayer)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGetCurrentLayerL`.
 */
int moho::cfunc_UnitGetCurrentLayer(lua_State* const luaContext)
{
  return cfunc_UnitGetCurrentLayerL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB7B0 (FUN_006CB7B0, func_UnitGetCurrentLayer_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetCurrentLayer()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetCurrentLayer_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetCurrentLayerName,
    &moho::cfunc_UnitGetCurrentLayer,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetCurrentLayerHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB810 (FUN_006CB810, cfunc_UnitGetCurrentLayerL)
 *
 * What it does:
 * Returns this unit's current layer string token.
 */
int moho::cfunc_UnitGetCurrentLayerL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetCurrentLayerHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const ELayer layer = unit->mVarDat.mLayerMask;
  const char* const layerName =
    (static_cast<std::uint32_t>(layer) <= static_cast<std::uint32_t>(LAYER_Orbit)) ? Entity::LayerToString(layer) : "";
  lua_pushstring(rawState, layerName);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CB8E0 (FUN_006CB8E0, cfunc_UnitCanPathTo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitCanPathToL`.
 */
int moho::cfunc_UnitCanPathTo(lua_State* const luaContext)
{
  return cfunc_UnitCanPathToL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB900 (FUN_006CB900, func_UnitCanPathTo_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:CanPathTo(goal)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitCanPathTo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitCanPathToName,
    &moho::cfunc_UnitCanPathTo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitCanPathToHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB960 (FUN_006CB960, cfunc_UnitCanPathToL)
 *
 * What it does:
 * Resolves one unit and one destination argument (unit or position), then
 * returns `(canPath, targetPos)` for navigator pathing to that footprint.
 */
int moho::cfunc_UnitCanPathToL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitCanPathToHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject destinationObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const destinationUnit = CastUnitOptionalFromLuaObject(destinationObject);

  Wm3::Vector3f destinationPosition{};
  if (destinationUnit != nullptr) {
    destinationPosition = destinationUnit->GetPosition();
  } else {
    destinationPosition = SCR_FromLuaCopy<Wm3::Vector3f>(destinationObject);
  }

  SFootprint footprint = unit->GetFootprint();
  footprint.mFlags = static_cast<EFootprintFlags>(
    static_cast<std::uint8_t>(footprint.mFlags) | static_cast<std::uint8_t>(EFootprintFlags::FPFLAG_IgnoreStructures)
  );

  const SCoordsVec2 worldPosition2D{destinationPosition.x, destinationPosition.z};
  if (footprint.FitsAt(worldPosition2D, *unit->SimulationRef->mOGrid) == static_cast<EOccupancyCaps>(0)) {
    lua_pushboolean(rawState, 0);
    (void)lua_gettop(rawState);

    const Wm3::Vector3f unitPosition = unit->GetPosition();
    LuaPlus::LuaObject positionObject = SCR_ToLua<Wm3::Vector3f>(state, unitPosition);
    positionObject.PushStack(state);
    return 2;
  }

  const float footprintWidthHalf = static_cast<float>(footprint.mSizeX) * 0.5f;
  const float footprintDepthHalf = static_cast<float>(footprint.mSizeZ) * 0.5f;
  const std::int16_t footprintMinX = static_cast<std::int16_t>(std::lrint(destinationPosition.x - footprintWidthHalf));
  const std::int16_t footprintMinZ = static_cast<std::int16_t>(std::lrint(destinationPosition.z - footprintDepthHalf));

  SAiNavigatorGoal goal{};
  goal.minX = footprintMinX;
  goal.minZ = footprintMinZ;
  goal.maxX = static_cast<std::int32_t>(footprintMinX) + static_cast<std::int32_t>(footprint.mSizeX);
  goal.maxZ = static_cast<std::int32_t>(footprintMinZ) + static_cast<std::int32_t>(footprint.mSizeZ);

  Wm3::Vector3f targetPosition = InvalidNavigatorTargetLane();
  const bool canPath = unit->AiNavigator->CanPathTo(&targetPosition, goal);
  lua_pushboolean(rawState, canPath ? 1 : 0);
  (void)lua_gettop(rawState);

  LuaPlus::LuaObject targetPositionObject = SCR_ToLua<Wm3::Vector3f>(state, targetPosition);
  targetPositionObject.PushStack(state);
  return 2;
}

/**
 * Address: 0x006CBD70 (FUN_006CBD70, cfunc_UnitCanPathToRectL)
 *
 * What it does:
 * Resolves one unit plus two world-space rectangle corners, queries navigator
 * pathability to that rectangle, then returns `(canPath, targetPos)` to Lua.
 */
int moho::cfunc_UnitCanPathToRectL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kUnitCanPathToRectHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject minCornerObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f minCorner = SCR_FromLuaCopy<Wm3::Vector3f>(minCornerObject);

  const LuaPlus::LuaObject maxCornerObject(LuaPlus::LuaStackObject(state, 3));
  const Wm3::Vector3f maxCorner = SCR_FromLuaCopy<Wm3::Vector3f>(maxCornerObject);

  SAiNavigatorGoal goal{};
  // 0x006CBEA4..0x006CBF25: the binary's inlined ceil and floor.
  goal.minX = fa::FloorToIntX87(minCorner.x);
  goal.minZ = fa::FloorToIntX87(minCorner.z);
  goal.maxX = fa::CeilToIntX87(maxCorner.x);
  goal.maxZ = fa::CeilToIntX87(maxCorner.z);

  Wm3::Vector3f targetPos = InvalidNavigatorTargetLane();
  const bool canPath = unit->AiNavigator->CanPathTo(&targetPos, goal);

  lua_pushboolean(rawState, canPath ? 1 : 0);
  (void)lua_gettop(rawState);

  LuaPlus::LuaObject targetPosObject = SCR_ToLua<Wm3::Vector3f>(state, targetPos);
  targetPosObject.PushStack(state);
  return 2;
}

/**
 * Address: 0x006CBCF0 (FUN_006CBCF0, cfunc_UnitCanPathToRect)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitCanPathToRectL`.
 */
int moho::cfunc_UnitCanPathToRect(lua_State* const luaContext)
{
  return cfunc_UnitCanPathToRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CBD10 (FUN_006CBD10, func_UnitCanPathToRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:CanPathToRect(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitCanPathToRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitCanPathToRectName,
    &moho::cfunc_UnitCanPathToRect,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitCanPathToRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC040 (FUN_006CC040, cfunc_UnitIsMobile)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsMobileL`.
 */
int moho::cfunc_UnitIsMobile(lua_State* const luaContext)
{
  return cfunc_UnitIsMobileL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC060 (FUN_006CC060, func_UnitIsMobile_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:IsMobile()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsMobile_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsMobileName,
    &moho::cfunc_UnitIsMobile,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsMobileHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC0C0 (FUN_006CC0C0, cfunc_UnitIsMobileL)
 *
 * What it does:
 * Resolves one unit and returns `Unit::IsMobile()`.
 */
int moho::cfunc_UnitIsMobileL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitIsMobileHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  lua_pushboolean(rawState, unit->IsMobile() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CC180 (FUN_006CC180, cfunc_UnitIsMoving)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitIsMovingL`.
 */
int moho::cfunc_UnitIsMoving(lua_State* const luaContext)
{
  return cfunc_UnitIsMovingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC1A0 (FUN_006CC1A0, func_UnitIsMoving_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:IsMoving()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitIsMoving_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitIsMovingName,
    &moho::cfunc_UnitIsMoving,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitIsMovingHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC200 (FUN_006CC200, cfunc_UnitIsMovingL)
 *
 * What it does:
 * Resolves one unit and returns whether current and previous entity position
 * lanes differ.
 */
int moho::cfunc_UnitIsMovingL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitIsMovingHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const bool isMoving = unit->mVarDat.mCurTransform.pos_ != unit->mVarDat.mLastTransform.pos_;
  lua_pushboolean(rawState, isMoving ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006CC2D0 (FUN_006CC2D0, cfunc_UnitGetNavigator)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetNavigatorL`.
 */
int moho::cfunc_UnitGetNavigator(lua_State* const luaContext)
{
  return cfunc_UnitGetNavigatorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC2F0 (FUN_006CC2F0, func_UnitGetNavigator_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetNavigator()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetNavigator_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetNavigatorName,
    &moho::cfunc_UnitGetNavigator,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetNavigatorHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC350 (FUN_006CC350, cfunc_UnitGetNavigatorL)
 *
 * What it does:
 * Resolves one unit and pushes its navigator object or `nil`.
 */
int moho::cfunc_UnitGetNavigatorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetNavigatorHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (IAiNavigator* const navigator = unit->AiNavigator; navigator != nullptr) {
    navigator->PushStack(state);
  } else {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
  }

  return 1;
}

/**
 * Address: 0x006CC420 (FUN_006CC420, cfunc_UnitGetVelocity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetVelocityL`.
 */
int moho::cfunc_UnitGetVelocity(lua_State* const luaContext)
{
  return cfunc_UnitGetVelocityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC440 (FUN_006CC440, func_UnitGetVelocity_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetVelocity() -> x,y,z` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetVelocity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetVelocityName,
    &moho::cfunc_UnitGetVelocity,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetVelocityHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC4A0 (FUN_006CC4A0, cfunc_UnitGetVelocityL)
 *
 * What it does:
 * Resolves one unit and returns velocity components `(x, y, z)` to Lua.
 */
int moho::cfunc_UnitGetVelocityL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitGetVelocityHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  const Wm3::Vec3f velocity = unit->GetVelocity();

  lua_pushnumber(rawState, velocity.x);
  (void)lua_gettop(rawState);
  lua_pushnumber(rawState, velocity.y);
  (void)lua_gettop(rawState);
  lua_pushnumber(rawState, velocity.z);
  (void)lua_gettop(rawState);
  return 3;
}

/**
 * Address: 0x006CC5A0 (FUN_006CC5A0, cfunc_UnitGetStat)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGetStatL`.
 */
int moho::cfunc_UnitGetStat(lua_State* const luaContext)
{
  return cfunc_UnitGetStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC5C0 (FUN_006CC5C0, func_UnitGetStat_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:GetStat(name[, defaultValue])` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGetStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGetStatName,
    &moho::cfunc_UnitGetStat,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGetStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CC620 (FUN_006CC620, cfunc_UnitGetStatL)
 *
 * What it does:
 * Resolves one unit stat path and pushes the resolved stat-item Lua table (or
 * `nil`) with optional default-type dispatch.
 */
int moho::cfunc_UnitGetStatL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 2 || argumentCount > 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsRangeWarning, kUnitGetStatHelpText, 2, 3, argumentCount);
  }

  lua_settop(rawState, 3);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  StatItem* statItem = nullptr;
  if (lua_type(rawState, 3) == LUA_TNIL) {
    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = lua_tostring(rawState, 2);
    if (statName == nullptr) {
      statNameArg.TypeError("string");
    }
    statItem = unit->GetStat(statName);
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

    statItem = unit->GetStat(statName, defaultValue);
  } else if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    const float defaultValue = defaultArg.GetNumber();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = statNameArg.GetString();
    statItem = unit->GetStat(statName, defaultValue);
  } else {
    const LuaPlus::LuaStackObject defaultArg(state, 3);
    const char* const defaultString = defaultArg.GetString();
    const std::string defaultValue = defaultString ? std::string(defaultString) : std::string();

    const LuaPlus::LuaStackObject statNameArg(state, 2);
    const char* const statName = statNameArg.GetString();
    statItem = unit->GetStat(statName, defaultValue);
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
