#include "moho/unit/core/UnitLuaPrivate.h"

namespace
{
  constexpr const char* kUnitClearFocusEntityName = "ClearFocusEntity";
  constexpr const char* kUnitClearFocusEntityHelpText = "ClearFocusEntity(self)";
  constexpr const char* kUnitSetFocusEntityName = "SetFocusEntity";
  constexpr const char* kUnitSetFocusEntityHelpText = "SetFocusUnit(self, focus)";
  constexpr const char* kUnitEnableManipulatorsName = "EnableManipulators";
  constexpr const char* kUnitEnableManipulatorsHelpText =
    "Unit:EnableManipulators([string boneName | int boneIndex], bool Enable)";
  constexpr const char* kUnitSetStrategicUnderlayName = "SetStrategicUnderlay";
  constexpr const char* kUnitSetStrategicUnderlayHelpText = "SetStrategicUnderlay(icon)";
  constexpr const char* kSetFireStateName = "SetFireState";
  constexpr const char* kSetFireStateArgsHelpText = "SetFireState(units, newFireState)";
  constexpr const char* kSetFireStateBindHelpText = "Set the specific fire state for the units passed in";
  constexpr const char* kToggleFireStateGlobalName = "ToggleFireState";
  constexpr const char* kToggleFireStateGlobalArgsHelpText = "ToggleFireState(units, currentFireState)";
  constexpr const char* kToggleFireStateGlobalBindHelpText = "Set the right fire state for the units passed in";
  constexpr const char* kUnitAddUnitToStorageName = "AddUnitToStorage";
  constexpr const char* kUnitAddUnitToStorageHelpText = "Unit:AddUnitToStorage( storedUnit )";
  constexpr const char* kUnitAddUnitToStorageNoRoomWarning = "No more room available in carrier for unit to be stored";
  constexpr const char* kUnitRemoveNukeSiloAmmoName = "RemoveNukeSiloAmmo";
  constexpr const char* kUnitRemoveNukeSiloAmmoHelpText = "Unit:RemoveNukeSiloAmmo(num)";
  constexpr const char* kUnitRemoveTacticalSiloAmmoName = "RemoveTacticalSiloAmmo";
  constexpr const char* kUnitRemoveTacticalSiloAmmoHelpText = "Unit:RemoveTacticalSiloAmmo(num)";
  constexpr const char* kUnitSetPausedName = "SetPaused";
  constexpr const char* kUnitSetPausedHelpText = "Unit:SetPaused()";
  constexpr const char* kUnitSetConsumptionActiveName = "SetConsumptionActive";
  constexpr const char* kUnitSetConsumptionActiveHelpText = "Unit:SetConsumptionActive(flag)";
  constexpr const char* kUnitSetConsumptionPerSecondEnergyName = "SetConsumptionPerSecondEnergy";
  constexpr const char* kUnitSetConsumptionPerSecondEnergyHelpText =
    "unit:SetConsumptionPerSecondEnergy(value) -- Set the consumption of energy of a unit";
  constexpr const char* kUnitSetConsumptionPerSecondMassName = "SetConsumptionPerSecondMass";
  constexpr const char* kUnitSetConsumptionPerSecondMassHelpText = "Set the consumption of mass of the unit";
  constexpr const char* kUnitSetRegenRateName = "SetRegenRate";
  constexpr const char* kUnitSetRegenRateHelpText = "unit:SetRegenRate(rate) -- Set the regen rate of a unit.";
  constexpr const char* kUnitSetBuildRateName = "SetBuildRate";
  constexpr const char* kUnitSetBuildRateHelpText =
    "unit:SetBuildRate(frac) -- Set the build rate of a unit: what fraction of target unit it builds per second.";
  constexpr const char* kUnitSetProductionPerSecondEnergyName = "SetProductionPerSecondEnergy";
  constexpr const char* kUnitSetProductionPerSecondEnergyHelpText = "Set the production of energy of the unit";
  constexpr const char* kUnitSetProductionPerSecondMassName = "SetProductionPerSecondMass";
  constexpr const char* kUnitSetProductionPerSecondMassHelpText = "Set the production of mass of the unit";
  constexpr const char* kUnitSetElevationName = "SetElevation";
  constexpr const char* kUnitSetElevationHelpText = "Set the elevation of the unit";
  constexpr const char* kUnitSetSpeedMultName = "SetSpeedMult";
  constexpr const char* kUnitSetSpeedMultHelpText = "Set the speed multiplier of the unit";
  constexpr const char* kUnitSetAccMultName = "SetAccMult";
  constexpr const char* kUnitSetAccMultHelpText = "Set the acceleration multiplier of the unit";
  constexpr const char* kUnitSetTurnMultName = "SetTurnMult";
  constexpr const char* kUnitSetTurnMultHelpText = "Set the turn multiplier of the unit";
  constexpr const char* kUnitSetBreakOffTriggerMultName = "SetBreakOffTriggerMult";
  constexpr const char* kUnitSetBreakOffTriggerMultHelpText = "Set the break off trigger multiplier of the unit";
  constexpr const char* kUnitSetBreakOffDistanceMultName = "SetBreakOffDistanceMult";
  constexpr const char* kUnitSetBreakOffDistanceMultHelpText = "Set the break off distance multiplier of the unit";
  constexpr const char* kUnitSetWorkProgressName = "SetWorkProgress";
  constexpr const char* kUnitSetWorkProgressHelpText = "SetWorkProgress(float)";
  constexpr const char* kUnitToggleFireStateName = "ToggleFireState";
  constexpr const char* kUnitToggleFireStateHelpText = "Toggle the fire state for the retaliation state of the unit";
  constexpr const char* kUnitSetFireStateHelpText = "Set a specific fire state for the retaliation state of the unit";
  constexpr const char* kUnitSetAutoModeName = "SetAutoMode";
  constexpr const char* kUnitSetAutoModeHelpText = "Set auto silo build mode to on/off";
  constexpr const char* kUnitAddBuildRestrictionName = "AddBuildRestriction";
  constexpr const char* kUnitAddBuildRestrictionHelpText = "Disallow building of these categories for this unit";
  constexpr const char* kUnitRemoveBuildRestrictionName = "RemoveBuildRestriction";
  constexpr const char* kUnitRemoveBuildRestrictionHelpText = "Allow building of categories for this unit";
  constexpr const char* kUnitSetProductionActiveName = "SetProductionActive";
  constexpr const char* kUnitSetProductionActiveHelpText = "Unit:SetProductionActive(flag)";
  constexpr const char* kUnitSetBusyName = "SetBusy";
  constexpr const char* kUnitSetBusyHelpText = "SetBusy(unit, flag)";
  constexpr const char* kUnitSetBlockCommandQueueName = "SetBlockCommandQueue";
  constexpr const char* kUnitSetBlockCommandQueueHelpText = "SetBlockCommandQueue(unit, flag)";
  constexpr const char* kUnitSetImmobileName = "SetImmobile";
  constexpr const char* kUnitSetImmobileHelpText = "SetImmobile(unit, flag)";
  constexpr const char* kUnitSetUnSelectableName = "SetUnSelectable";
  constexpr const char* kUnitSetUnSelectableHelpText = "SetUnSelectable(unit, flag)";
  constexpr const char* kUnitSetDoNotTargetName = "SetDoNotTarget";
  constexpr const char* kUnitSetDoNotTargetHelpText = "SetDoNotTarget(unit, flag)";
  constexpr const char* kUnitSetIsValidTargetName = "SetIsValidTarget";
  constexpr const char* kUnitSetIsValidTargetHelpText = "SetIsValidTarget(self,bool)";
  constexpr const char* kUnitSetStunnedName = "SetStunned";
  constexpr const char* kUnitSetStunnedHelpText = "SetStunned(unit, time)";
  constexpr const char* kUnitSetUnitStateName = "SetUnitState";
  constexpr const char* kUnitSetUnitStateHelpText = "SetUnitState(name, bool)";
  constexpr const char* kUnitShowBoneName = "ShowBone";
  constexpr const char* kUnitShowBoneHelpText = "ShowBone(self,bone,affectChildren)";
  constexpr const char* kUnitHideBoneName = "HideBone";
  constexpr const char* kUnitHideBoneHelpText = "HideBone(self,bone,affectChildren)";
  constexpr const char* kUnitSetFuelUseTimeName = "SetFuelUseTime";
  constexpr const char* kUnitSetFuelUseTimeHelpText = "Set the fuel use time";
  constexpr const char* kUnitSetFuelRatioName = "SetFuelRatio";
  constexpr const char* kUnitSetFuelRatioHelpText = "Set the fuel ratio";
  constexpr const char* kUnitSetCustomNameName = "SetCustomName";
  constexpr const char* kUnitSetCustomNameHelpText = "Unit:SetCustomName(name)";
  constexpr const char* kUnitSetShieldRatioName = "SetShieldRatio";
  constexpr const char* kUnitSetShieldRatioHelpText = "Set the shield ratio";
  constexpr const char* kUnitSetScriptBitName = "SetScriptBit";
  constexpr const char* kUnitSetScriptBitHelpText = "Set the script bit that matches the string to the desired state";
  constexpr const char* kUnitToggleScriptBitName = "ToggleScriptBit";
  constexpr const char* kUnitToggleScriptBitHelpText = "Toggle the script bit that matches the string";
  constexpr const char* kUnitAddCommandCapName = "AddCommandCap";
  constexpr const char* kUnitAddCommandCapHelpText = "unit:AddCommandCap(capName) -- Add a command cap to a unit.";
  constexpr const char* kUnitRemoveCommandCapName = "RemoveCommandCap";
  constexpr const char* kUnitRemoveCommandCapHelpText =
    "unit:RemoveCommandCap(capName) -- Remove a command cap to a unit.";
  constexpr const char* kUnitAddToggleCapName = "AddToggleCap";
  constexpr const char* kUnitAddToggleCapHelpText = "unit:AddToggleCap(capName) -- Add a toggle cap to a unit.";
  constexpr const char* kUnitRemoveToggleCapName = "RemoveToggleCap";
  constexpr const char* kUnitRemoveToggleCapHelpText =
    "unit:RemoveToggleCap(capName) -- Remove a toggle cap to a unit.";
  constexpr const char* kUnitSetCreatorName = "SetCreator";
  constexpr const char* kUnitSetCreatorHelpText = "Set the creator for this unit";
  constexpr const char* kUnitSetReclaimableName = "SetReclaimable";
  constexpr const char* kUnitSetReclaimableHelpText = "Set if this unit can be reclaimed or not.";
  constexpr const char* kUnitSetCapturableName = "SetCapturable";
  constexpr const char* kUnitSetCapturableHelpText = "Set if this unit can be captured or not.";
  constexpr const char* kUnitSetOverchargePausedName = "SetOverchargePaused";
  constexpr const char* kUnitSetOverchargePausedHelpText = "Set if this unit has an overcharge pasued.";
  constexpr const char* kUnitSetStatName = "SetStat";
  constexpr const char* kUnitSetStatHelpText = "SetStat(Name, Value)";

  [[nodiscard]] CAniPoseBone* ResolveUnitPoseBone(Unit& unit, const int boneIndex) noexcept
  {
    if (unit.AniActor == nullptr || unit.AniActor->mPose.get() == nullptr || boneIndex < 0) {
      return nullptr;
    }

    CAniPose* const pose = unit.AniActor->mPose.get();
    CAniPoseBone* const bonesBegin = pose->mBones.begin();
    CAniPoseBone* const bonesEnd = pose->mBones.end();
    if (bonesBegin == nullptr || bonesEnd == nullptr || bonesBegin > bonesEnd) {
      return nullptr;
    }

    CAniPoseBone* bone = bonesBegin;
    for (int index = 0; index < boneIndex; ++index) {
      if (bone == bonesEnd) {
        return nullptr;
      }
      ++bone;
    }

    if (bone == bonesEnd) {
      return nullptr;
    }

    return bone;
  }

  [[nodiscard]] bool ParseFireStateLexical(const char* const lexical, std::int32_t& outFireState)
  {
    if (lexical == nullptr) {
      return false;
    }

    static gpg::RType* sFireStateType = nullptr;
    static bool sTypeLookupDone = false;
    if (!sTypeLookupDone) {
      sTypeLookupDone = true;
      sFireStateType = gpg::REF_FindTypeNamed("EFireState");
      if (sFireStateType == nullptr) {
        sFireStateType = gpg::REF_FindTypeNamed("Moho::EFireState");
      }
      if (sFireStateType == nullptr) {
        sFireStateType = gpg::REF_FindTypeNamed("moho::EFireState");
      }
    }

    if (sFireStateType != nullptr) {
      gpg::RRef fireStateRef{};
      fireStateRef.mObj = &outFireState;
      fireStateRef.mType = sFireStateType;
      if (fireStateRef.SetLexical(lexical)) {
        return true;
      }
    }

    char* end = nullptr;
    const long value = std::strtol(lexical, &end, 10);
    if (end != lexical && end != nullptr && *end == '\0' && value >= 0 && value <= 2) {
      outFireState = static_cast<std::int32_t>(value);
      return true;
    }

    return false;
  }

  /**
   * `Unit::ArmorMultipliers`'s red-black tree mechanics (lower-bound descent,
   * hinted/unique insert, node buy/link/rebalance, subtree teardown) are no
   * longer hand-rolled here (RULE ONE: container/template internals are
   * recovered once, generically, on the container template itself, never as
   * a per-type free-function reimplementation).
   *
   * `ArmorMultipliers` is now a real `fa::map<fa::string, float>` (see
   * the field's doc comment in `Unit.h`). Real callers use its API directly:
   * `.find()` (`Unit::ProcessArmorOnDamage`, `Unit::GetArmorMult`) and
   * `operator[]` (`Unit::InitializeArmor`, `cfunc_UnitAlterArmorL`, below).
   * The generic tree internals those calls compile down to
   * (`find`/`operator[]` in `legacy/containers/Map.h`; `lower_bound_node`/
   * `insert_hint`/`insert_unique`/`insert_at`/`buy_head`/`buy_node` in
   * `legacy/containers/RbTree.h`) carry this instantiation's own `Address:`
   * citations (0x006ADD30/0x006ADBF0/0x006AEDD0/0x006AF840/0x006AFA40/
   * 0x006AFBF0/0x006B01C0/0x006B0200) alongside every other `fa::map`
   * instantiation already documented there.
   */

  [[nodiscard]] BVIntSet& AsCategoryWordBitset(EntityCategorySet& range) noexcept
  {
    return range.mBits;
  }
}


/**
 * Address: 0x006C3C00 (FUN_006C3C00, cfunc_UnitSetCreator)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetCreatorL`.
 */
int moho::cfunc_UnitSetCreator(lua_State* const luaContext)
{
  return cfunc_UnitSetCreatorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C3C20 (FUN_006C3C20, func_UnitSetCreator_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetCreator(creator)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetCreator_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetCreatorName,
    &moho::cfunc_UnitSetCreator,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetCreatorHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C3C80 (FUN_006C3C80, cfunc_UnitSetCreatorL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit creator weak lane and marks sync dirty.
 */
int moho::cfunc_UnitSetCreatorL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetCreatorHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject creatorObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const creator = SCR_FromLua_Unit(creatorObject);

  if (unit != nullptr && creator != nullptr) {
    AssignCreatorWeakRefAndMarkSyncDirty(unit, creator);
  }

  return 0;
}

/**
 * Address: 0x006C4370 (FUN_006C4370, cfunc_UnitClearFocusEntity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitClearFocusEntityL`.
 */
int moho::cfunc_UnitClearFocusEntity(lua_State* const luaContext)
{
  return cfunc_UnitClearFocusEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4390 (FUN_006C4390, func_UnitClearFocusEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:ClearFocusEntity(self)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitClearFocusEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitClearFocusEntityName,
    &moho::cfunc_UnitClearFocusEntity,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitClearFocusEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C43F0 (FUN_006C43F0, cfunc_UnitClearFocusEntityL)
 *
 * What it does:
 * Clears the focused-entity weak lane and marks focus state as assigned for
 * script-side follow-up.
 */
int moho::cfunc_UnitClearFocusEntityL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitClearFocusEntityHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  unit->FocusEntityRef.ResetFromObject(nullptr);
  if (unit->FocusEntityRef.GetObjectPtr() != nullptr) {
    unit->RunScript(kUnitOnAssignedFocusEntityScript);
  }
  unit->NeedSyncGameData = true;
  return 0;
}

/**
 * Address: 0x006C44E0 (FUN_006C44E0, cfunc_UnitSetFocusEntity)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFocusEntityL`.
 */
int moho::cfunc_UnitSetFocusEntity(lua_State* const luaContext)
{
  return cfunc_UnitSetFocusEntityL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4500 (FUN_006C4500, func_UnitSetFocusEntity_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetFocusEntity(self, focus)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetFocusEntity_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetFocusEntityName,
    &moho::cfunc_UnitSetFocusEntity,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetFocusEntityHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4560 (FUN_006C4560, cfunc_UnitSetFocusEntityL)
 *
 * What it does:
 * Resolves optional focus entity from Lua arg #2, writes it into unit focus
 * weak lane, dispatches `OnAssignedFocusEntity`, and marks focus assigned.
 */
int moho::cfunc_UnitSetFocusEntityL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetFocusEntityHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject focusEntityObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const focusEntity = SCR_FromLua_EntityOpt(focusEntityObject);
  if (focusEntity != nullptr) {
    unit->FocusEntityRef.ResetFromObject(focusEntity);
    if (unit->FocusEntityRef.GetObjectPtr() != nullptr) {
      unit->RunScript(kUnitOnAssignedFocusEntityScript);
    }
    unit->NeedSyncGameData = true;
  }

  return 0;
}

/**
 * Address: 0x006C4FE0 (FUN_006C4FE0, cfunc_UnitEnableManipulatorsL)
 *
 * What it does:
 * Enables/disables one manipulator lane on a unit by bone index or bone name.
 */
int moho::cfunc_UnitEnableManipulatorsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kUnitEnableManipulatorsHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject enabledArg(state, 3);
  const bool enabled = enabledArg.GetBoolean();

  if (lua_type(rawState, 2) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject boneIndexArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      boneIndexArg.TypeError("integer");
    }

    const int boneIndex = static_cast<int>(lua_tonumber(rawState, 2));
    unit->AniActor->EnableBoneIndex(enabled, boneIndex);
    return 0;
  }

  const LuaPlus::LuaStackObject boneNameArg(state, 2);
  const char* boneName = lua_tostring(rawState, 2);
  if (boneName == nullptr) {
    boneNameArg.TypeError("string");
    boneName = "";
  }

  unit->AniActor->EnableBoneString(boneName, enabled);
  return 0;
}

/**
 * Address: 0x006C4F60 (FUN_006C4F60, cfunc_UnitEnableManipulators)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitEnableManipulatorsL`.
 */
int moho::cfunc_UnitEnableManipulators(lua_State* const luaContext)
{
  return cfunc_UnitEnableManipulatorsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C4F80 (FUN_006C4F80, func_UnitEnableManipulators_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:EnableManipulators(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitEnableManipulators_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitEnableManipulatorsName,
    &moho::cfunc_UnitEnableManipulators,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitEnableManipulatorsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5800 (FUN_006C5800, cfunc_UnitSetStrategicUnderlayL)
 *
 * What it does:
 * Resolves `(self, icon)` and applies one strategic underlay icon id on the
 * unit entity.
 */
int moho::cfunc_UnitSetStrategicUnderlayL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetStrategicUnderlayHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject iconArg(state, 2);
  const char* iconName = lua_tostring(rawState, 2);
  if (iconName == nullptr) {
    iconArg.TypeError("string");
    iconName = "";
  }

  RResId underlayId{};
  gpg::STR_InitFilename(&underlayId.name, iconName);
  unit->SetStrategicUnderlay(underlayId);
  return 0;
}

/**
 * Address: 0x006C5780 (FUN_006C5780, cfunc_UnitSetStrategicUnderlay)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetStrategicUnderlayL`.
 */
int moho::cfunc_UnitSetStrategicUnderlay(lua_State* const luaContext)
{
  return cfunc_UnitSetStrategicUnderlayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C57A0 (FUN_006C57A0, func_UnitSetStrategicUnderlay_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetStrategicUnderlay(icon)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetStrategicUnderlay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetStrategicUnderlayName,
    &moho::cfunc_UnitSetStrategicUnderlay,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetStrategicUnderlayHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BBA10 (FUN_008BBA10, cfunc_SetFireStateL)
 *
 * What it does:
 * Applies one fire-state string command to each live unit in the input table.
 */
int moho::cfunc_SetFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kSetFireStateArgsHelpText);

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));
  if (!unitsObject.IsTable()) {
    return 0;
  }

  const int unitCount = unitsObject.GetCount();
  for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
    LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
    UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
    if (userUnit == nullptr || userUnit->IsDead()) {
      continue;
    }

    // 0x008BBAEB: the driver is loaded without a null test.
    ISTIDriver* const activeDriver = WLD_GetDriver();
    const LuaPlus::LuaStackObject fireStateArg(state, 2);
    const char* const fireStateValue = lua_tostring(rawState, 2);
    if (fireStateValue == nullptr) {
      fireStateArg.TypeError("string");
    }

    // 0x008BBB30: entity id straight from `mParams.mEntityId` (+0x44).
    activeDriver->ProcessInfoPair(userUnit->mParams.mEntityId, kSetFireStateName, fireStateValue);
  }

  return 0;
}

/**
 * Address: 0x008BB990 (FUN_008BB990, cfunc_SetFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetFireStateL`.
 */
int moho::cfunc_SetFireState(lua_State* const luaContext)
{
  return cfunc_SetFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB9B0 (FUN_008BB9B0, func_SetFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `SetFireState(units, newFireState)`.
 */
CScrLuaInitForm* moho::func_SetFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kSetFireStateName,
    &moho::cfunc_SetFireState,
    nullptr,
    kGlobalLuaClassName,
    kSetFireStateBindHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB6E0 (FUN_008BB6E0, cfunc_ToggleFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_ToggleFireStateL`.
 */
int moho::cfunc_ToggleFireState(lua_State* const luaContext)
{
  return cfunc_ToggleFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB700 (FUN_008BB700, func_ToggleFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes global user-Lua binder for `ToggleFireState(units, currentFireState)`.
 */
CScrLuaInitForm* moho::func_ToggleFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_UserLuaInitSet(),
    kToggleFireStateGlobalName,
    &moho::cfunc_ToggleFireState,
    nullptr,
    kGlobalLuaClassName,
    kToggleFireStateGlobalBindHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB760 (FUN_008BB760, cfunc_ToggleFireStateL)
 *
 * What it does:
 * Rotates one global fire-state lane and dispatches `SetFireState` info pairs
 * for each live unit in the input table.
 */
int moho::cfunc_ToggleFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kToggleFireStateGlobalArgsHelpText);

  const LuaPlus::LuaObject unitsObject(LuaPlus::LuaStackObject(state, 1));

  LuaPlus::LuaStackObject currentFireStateArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&currentFireStateArg, "integer");
  }

  const std::int32_t currentFireState = static_cast<std::int32_t>(lua_tonumber(rawState, 2));
  EFireState nextFireState = static_cast<EFireState>((currentFireState + 1) % 3);

  if (unitsObject.IsTable()) {
    const int unitCount = unitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitsObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
      if (userUnit == nullptr || userUnit->IsDead()) {
        continue;
      }

      // 0x008BB8A4..0x008BB916: per unit, the driver is loaded without a null
      // test, the state's lexical name is rebuilt into a temporary, and the
      // entity id comes straight from `mParams.mEntityId` (+0x44).
      ISTIDriver* const activeDriver = WLD_GetDriver();
      const gpg::RRef nextFireStateRef = gpg::MakeRRef<moho::EFireState>(&nextFireState);
      activeDriver->ProcessInfoPair(
        userUnit->mParams.mEntityId, kSetFireStateName, nextFireStateRef.GetLexical().c_str()
      );
    }
  }

  return 0;
}

/**
 * Address: 0x006CD9D0 (FUN_006CD9D0, cfunc_UnitAddUnitToStorageL)
 *
 * What it does:
 * Adds one unit argument into a carrier's storage lane when capacity is available.
 */
int moho::cfunc_UnitAddUnitToStorageL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitAddUnitToStorageHelpText);

  const LuaPlus::LuaObject carrierObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const carrierUnit = SCR_FromLua_Unit(carrierObject);
  const LuaPlus::LuaObject storedUnitObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const storedUnit = SCR_FromLua_Unit(storedUnitObject);

  if (carrierUnit != nullptr && storedUnit != nullptr) {
    if (IAiTransport* const aiTransport = carrierUnit->AiTransport; aiTransport != nullptr) {
      if (aiTransport->TransportHasAvailableStorage()) {
        aiTransport->TransportAddToStorage(storedUnit);
        return 0;
      }

      gpg::Warnf(kUnitAddUnitToStorageNoRoomWarning);
    }
  }

  return 0;
}

/**
 * Address: 0x006CD950 (FUN_006CD950, cfunc_UnitAddUnitToStorage)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitAddUnitToStorageL`.
 */
int moho::cfunc_UnitAddUnitToStorage(lua_State* const luaContext)
{
  return cfunc_UnitAddUnitToStorageL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CD970 (FUN_006CD970, func_UnitAddUnitToStorage_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AddUnitToStorage(storedUnit)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitAddUnitToStorage_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitAddUnitToStorageName,
    &moho::cfunc_UnitAddUnitToStorage,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAddUnitToStorageHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CEE90 (FUN_006CEE90, cfunc_UnitRemoveNukeSiloAmmoL)
 *
 * What it does:
 * Removes a requested nuke ammo count from the unit silo lane.
 */
int moho::cfunc_UnitRemoveNukeSiloAmmoL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitRemoveNukeSiloAmmoHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      const LuaPlus::LuaStackObject amountObject(state, 2);
      const int amount = amountObject.GetInteger();
      siloBuild->SiloAdjustStorageCount(SILOTYPE_Nuke, -amount);
    }
  }

  return 0;
}

/**
 * Address: 0x006CEE10 (FUN_006CEE10, cfunc_UnitRemoveNukeSiloAmmo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveNukeSiloAmmoL`.
 */
int moho::cfunc_UnitRemoveNukeSiloAmmo(lua_State* const luaContext)
{
  return cfunc_UnitRemoveNukeSiloAmmoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CEE30 (FUN_006CEE30, func_UnitRemoveNukeSiloAmmo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveNukeSiloAmmo(num)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveNukeSiloAmmo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRemoveNukeSiloAmmoName,
    &moho::cfunc_UnitRemoveNukeSiloAmmo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveNukeSiloAmmoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CF2A0 (FUN_006CF2A0, cfunc_UnitRemoveTacticalSiloAmmoL)
 *
 * What it does:
 * Removes requested tactical missile ammo amount from unit silo storage.
 */
int moho::cfunc_UnitRemoveTacticalSiloAmmoL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitRemoveTacticalSiloAmmoHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      const LuaPlus::LuaStackObject amountObject(state, 2);
      const int amount = amountObject.GetInteger();
      siloBuild->SiloAdjustStorageCount(SILOTYPE_Tactical, -amount);
    }
  }

  return 0;
}

/**
 * Address: 0x006CF220 (FUN_006CF220, cfunc_UnitRemoveTacticalSiloAmmo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveTacticalSiloAmmoL`.
 */
int moho::cfunc_UnitRemoveTacticalSiloAmmo(lua_State* const luaContext)
{
  return cfunc_UnitRemoveTacticalSiloAmmoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CF240 (FUN_006CF240, func_UnitRemoveTacticalSiloAmmo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveTacticalSiloAmmo(num)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveTacticalSiloAmmo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRemoveTacticalSiloAmmoName,
    &moho::cfunc_UnitRemoveTacticalSiloAmmo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveTacticalSiloAmmoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6080 (FUN_006C6080, cfunc_UnitSetPausedL)
 *
 * What it does:
 * Applies paused state from arg#2 to the unit resolved from arg#1.
 */
int moho::cfunc_UnitSetPausedL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetPausedHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);

  const LuaPlus::LuaStackObject pausedArg(state, 2);
  const bool paused = pausedArg.GetBoolean();
  unit->SetPaused(paused);

  return 0;
}

/**
 * Address: 0x006C6000 (FUN_006C6000, cfunc_UnitSetPaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetPausedL`.
 */
int moho::cfunc_UnitSetPaused(lua_State* const luaContext)
{
  return cfunc_UnitSetPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6020 (FUN_006C6020, func_UnitSetPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetPaused()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetPausedName,
    &moho::cfunc_UnitSetPaused,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C61C0 (FUN_006C61C0, cfunc_UnitSetConsumptionActiveL)
 *
 * What it does:
 * Applies consumption-active flag from arg#2 to the unit resolved from arg#1.
 */
int moho::cfunc_UnitSetConsumptionActiveL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetConsumptionActiveHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);

  const LuaPlus::LuaStackObject activeArg(state, 2);
  const bool isActive = activeArg.GetBoolean();
  unit->SetConsumptionActive(isActive);

  return 1;
}

/**
 * Address: 0x006C6140 (FUN_006C6140, cfunc_UnitSetConsumptionActive)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetConsumptionActiveL`.
 */
int moho::cfunc_UnitSetConsumptionActive(lua_State* const luaContext)
{
  return cfunc_UnitSetConsumptionActiveL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6160 (FUN_006C6160, func_UnitSetConsumptionActive_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetConsumptionActive(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetConsumptionActive_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetConsumptionActiveName,
    &moho::cfunc_UnitSetConsumptionActive,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetConsumptionActiveHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9E20 (FUN_006C9E20, cfunc_UnitSetConsumptionPerSecondEnergyL)
 *
 * What it does:
 * Writes a clamped non-negative energy consumption-per-second value from arg#2
 * into the unit attributes resolved from arg#1, then refreshes active
 * consumption bookkeeping if needed.
 */
int moho::cfunc_UnitSetConsumptionPerSecondEnergyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetConsumptionPerSecondEnergyHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject consumptionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    consumptionArg.TypeError("number");
  }

  float consumptionPerSecond = static_cast<float>(lua_tonumber(rawState, 2));
  if (consumptionPerSecond < 0.0f) {
    consumptionPerSecond = 0.0f;
  }

  unit->GetAttributes().consumptionPerSecondEnergy = consumptionPerSecond;
  if (unit->ConsumptionActive) {
    unit->SetConsumptionActive(true);
  }

  return 0;
}

/**
 * Address: 0x006C9DA0 (FUN_006C9DA0, cfunc_UnitSetConsumptionPerSecondEnergy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetConsumptionPerSecondEnergyL`.
 */
int moho::cfunc_UnitSetConsumptionPerSecondEnergy(lua_State* const luaContext)
{
  return cfunc_UnitSetConsumptionPerSecondEnergyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9DC0 (FUN_006C9DC0, func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetConsumptionPerSecondEnergy(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetConsumptionPerSecondEnergy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetConsumptionPerSecondEnergyName,
    &moho::cfunc_UnitSetConsumptionPerSecondEnergy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetConsumptionPerSecondEnergyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9FC0 (FUN_006C9FC0, cfunc_UnitSetConsumptionPerSecondMassL)
 *
 * What it does:
 * Writes a clamped non-negative mass consumption-per-second value from arg#2
 * into the unit attributes resolved from arg#1, then refreshes active
 * consumption bookkeeping if needed.
 */
int moho::cfunc_UnitSetConsumptionPerSecondMassL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetConsumptionPerSecondMassHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject consumptionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    consumptionArg.TypeError("number");
  }

  float consumptionPerSecond = static_cast<float>(lua_tonumber(rawState, 2));
  if (consumptionPerSecond < 0.0f) {
    consumptionPerSecond = 0.0f;
  }

  unit->GetAttributes().consumptionPerSecondMass = consumptionPerSecond;
  if (unit->ConsumptionActive) {
    unit->SetConsumptionActive(true);
  }

  return 0;
}

/**
 * Address: 0x006C9F40 (FUN_006C9F40, cfunc_UnitSetConsumptionPerSecondMass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetConsumptionPerSecondMassL`.
 */
int moho::cfunc_UnitSetConsumptionPerSecondMass(lua_State* const luaContext)
{
  return cfunc_UnitSetConsumptionPerSecondMassL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9F60 (FUN_006C9F60, func_UnitSetConsumptionPerSecondMass_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetConsumptionPerSecondMass(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetConsumptionPerSecondMass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetConsumptionPerSecondMassName,
    &moho::cfunc_UnitSetConsumptionPerSecondMass,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetConsumptionPerSecondMassHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C91A0 (FUN_006C91A0, cfunc_UnitSetRegenRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetRegenRateL`.
 */
int moho::cfunc_UnitSetRegenRate(lua_State* const luaContext)
{
  return cfunc_UnitSetRegenRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C91C0 (FUN_006C91C0, func_UnitSetRegenRate_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetRegenRate(rate)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetRegenRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetRegenRateName,
    &moho::cfunc_UnitSetRegenRate,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetRegenRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9220 (FUN_006C9220, cfunc_UnitSetRegenRateL)
 *
 * What it does:
 * Writes a clamped non-negative regen-rate scalar from arg #2 into arg #1 unit
 * attributes.
 */
int moho::cfunc_UnitSetRegenRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetRegenRateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject rateArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    rateArg.TypeError("number");
  }

  float regenRate = static_cast<float>(lua_tonumber(rawState, 2));
  if (regenRate < 0.0f) {
    regenRate = 0.0f;
  }

  unit->GetAttributes().regenRate = regenRate;
  return 0;
}

/**
 * Address: 0x006C9AC0 (FUN_006C9AC0, cfunc_UnitSetBuildRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetBuildRateL`.
 */
int moho::cfunc_UnitSetBuildRate(lua_State* const luaContext)
{
  return cfunc_UnitSetBuildRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9AE0 (FUN_006C9AE0, func_UnitSetBuildRate_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetBuildRate(frac)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBuildRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetBuildRateName,
    &moho::cfunc_UnitSetBuildRate,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBuildRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9B40 (FUN_006C9B40, cfunc_UnitSetBuildRateL)
 *
 * What it does:
 * Writes a clamped non-negative build-rate scalar from arg #2 into arg #1 unit
 * attributes.
 */
int moho::cfunc_UnitSetBuildRateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetBuildRateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject rateArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    rateArg.TypeError("number");
  }

  float buildRate = static_cast<float>(lua_tonumber(rawState, 2));
  if (buildRate < 0.0f) {
    buildRate = 0.0f;
  }

  unit->GetAttributes().buildRate = buildRate;
  return 0;
}

/**
 * Address: 0x006CA0E0 (FUN_006CA0E0, cfunc_UnitSetProductionPerSecondEnergy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetProductionPerSecondEnergyL`.
 */
int moho::cfunc_UnitSetProductionPerSecondEnergy(lua_State* const luaContext)
{
  return cfunc_UnitSetProductionPerSecondEnergyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA100 (FUN_006CA100, func_UnitSetProductionPerSecondEnergy_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetProductionPerSecondEnergy(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetProductionPerSecondEnergy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetProductionPerSecondEnergyName,
    &moho::cfunc_UnitSetProductionPerSecondEnergy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetProductionPerSecondEnergyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA160 (FUN_006CA160, cfunc_UnitSetProductionPerSecondEnergyL)
 *
 * What it does:
 * Writes a clamped non-negative energy production-per-second scalar from arg #2
 * into arg #1 unit attributes.
 */
int moho::cfunc_UnitSetProductionPerSecondEnergyL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetProductionPerSecondEnergyHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject productionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    productionArg.TypeError("number");
  }

  float productionPerSecondEnergy = static_cast<float>(lua_tonumber(rawState, 2));
  if (productionPerSecondEnergy < 0.0f) {
    productionPerSecondEnergy = 0.0f;
  }

  unit->GetAttributes().productionPerSecondEnergy = productionPerSecondEnergy;
  return 0;
}

/**
 * Address: 0x006CA270 (FUN_006CA270, cfunc_UnitSetProductionPerSecondMass)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetProductionPerSecondMassL`.
 */
int moho::cfunc_UnitSetProductionPerSecondMass(lua_State* const luaContext)
{
  return cfunc_UnitSetProductionPerSecondMassL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CA290 (FUN_006CA290, func_UnitSetProductionPerSecondMass_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetProductionPerSecondMass(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetProductionPerSecondMass_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetProductionPerSecondMassName,
    &moho::cfunc_UnitSetProductionPerSecondMass,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetProductionPerSecondMassHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CA2F0 (FUN_006CA2F0, cfunc_UnitSetProductionPerSecondMassL)
 *
 * What it does:
 * Writes a clamped non-negative mass production-per-second scalar from arg #2
 * into arg #1 unit attributes.
 */
int moho::cfunc_UnitSetProductionPerSecondMassL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetProductionPerSecondMassHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject productionArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    productionArg.TypeError("number");
  }

  float productionPerSecondMass = static_cast<float>(lua_tonumber(rawState, 2));
  if (productionPerSecondMass < 0.0f) {
    productionPerSecondMass = 0.0f;
  }

  unit->GetAttributes().productionPerSecondMass = productionPerSecondMass;
  return 0;
}

/**
 * Address: 0x006CAA80 (FUN_006CAA80, cfunc_UnitSetElevation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetElevationL`.
 */
int moho::cfunc_UnitSetElevation(lua_State* const luaContext)
{
  return cfunc_UnitSetElevationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CAAA0 (FUN_006CAAA0, func_UnitSetElevation_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetElevation(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetElevation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetElevationName,
    &moho::cfunc_UnitSetElevation,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetElevationHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CAB00 (FUN_006CAB00, cfunc_UnitSetElevationL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit elevation offset attribute.
 */
int moho::cfunc_UnitSetElevationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetElevationHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject elevationArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    elevationArg.TypeError("number");
  }

  unit->GetAttributes().spawnElevationOffset = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CAD20 (FUN_006CAD20, cfunc_UnitSetSpeedMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetSpeedMultL`.
 */
int moho::cfunc_UnitSetSpeedMult(lua_State* const luaContext)
{
  return cfunc_UnitSetSpeedMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CAD40 (FUN_006CAD40, func_UnitSetSpeedMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetSpeedMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetSpeedMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetSpeedMultName,
    &moho::cfunc_UnitSetSpeedMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetSpeedMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CADA0 (FUN_006CADA0, cfunc_UnitSetSpeedMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit speed-multiplier attribute.
 */
int moho::cfunc_UnitSetSpeedMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetSpeedMultHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject speedArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    speedArg.TypeError("number");
  }

  unit->GetAttributes().moveSpeedMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CAE90 (FUN_006CAE90, cfunc_UnitSetAccMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetAccMultL`.
 */
int moho::cfunc_UnitSetAccMult(lua_State* const luaContext)
{
  return cfunc_UnitSetAccMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CAEB0 (FUN_006CAEB0, func_UnitSetAccMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetAccMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetAccMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetAccMultName,
    &moho::cfunc_UnitSetAccMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetAccMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CAF10 (FUN_006CAF10, cfunc_UnitSetAccMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit acceleration-multiplier attribute.
 */
int moho::cfunc_UnitSetAccMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetAccMultHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject accelerationArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    accelerationArg.TypeError("number");
  }

  unit->GetAttributes().accelerationMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CB000 (FUN_006CB000, cfunc_UnitSetTurnMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetTurnMultL`.
 */
int moho::cfunc_UnitSetTurnMult(lua_State* const luaContext)
{
  return cfunc_UnitSetTurnMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB020 (FUN_006CB020, func_UnitSetTurnMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetTurnMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetTurnMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetTurnMultName,
    &moho::cfunc_UnitSetTurnMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetTurnMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB080 (FUN_006CB080, cfunc_UnitSetTurnMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit turn-multiplier attribute.
 */
int moho::cfunc_UnitSetTurnMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetTurnMultHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject turnArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    turnArg.TypeError("number");
  }

  unit->GetAttributes().turnMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CB170 (FUN_006CB170, cfunc_UnitSetBreakOffTriggerMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetBreakOffTriggerMultL`.
 */
int moho::cfunc_UnitSetBreakOffTriggerMult(lua_State* const luaContext)
{
  return cfunc_UnitSetBreakOffTriggerMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB190 (FUN_006CB190, func_UnitSetBreakOffTriggerMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetBreakOffTriggerMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBreakOffTriggerMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetBreakOffTriggerMultName,
    &moho::cfunc_UnitSetBreakOffTriggerMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBreakOffTriggerMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB1F0 (FUN_006CB1F0, cfunc_UnitSetBreakOffTriggerMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit break-off-trigger multiplier attribute.
 */
int moho::cfunc_UnitSetBreakOffTriggerMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetBreakOffTriggerMultHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject triggerArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    triggerArg.TypeError("number");
  }

  unit->GetAttributes().breakOffTriggerMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CB2E0 (FUN_006CB2E0, cfunc_UnitSetBreakOffDistanceMult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetBreakOffDistanceMultL`.
 */
int moho::cfunc_UnitSetBreakOffDistanceMult(lua_State* const luaContext)
{
  return cfunc_UnitSetBreakOffDistanceMultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB300 (FUN_006CB300, func_UnitSetBreakOffDistanceMult_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetBreakOffDistanceMult(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBreakOffDistanceMult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetBreakOffDistanceMultName,
    &moho::cfunc_UnitSetBreakOffDistanceMult,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBreakOffDistanceMultHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB360 (FUN_006CB360, cfunc_UnitSetBreakOffDistanceMultL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit break-off-distance multiplier attribute.
 */
int moho::cfunc_UnitSetBreakOffDistanceMultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetBreakOffDistanceMultHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject distanceArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    distanceArg.TypeError("number");
  }

  unit->GetAttributes().breakOffDistanceMult = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006CC8E0 (FUN_006CC8E0, cfunc_UnitSetStat)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetStatL`.
 */
int moho::cfunc_UnitSetStat(lua_State* const luaContext)
{
  return cfunc_UnitSetStatL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CC900 (FUN_006CC900, func_UnitSetStat_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetStat(name, value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetStat_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetStatName,
    &moho::cfunc_UnitSetStat,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetStatHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D24F0 (FUN_006D24F0)
 *
 * What it does:
 * Atomically stores one primary stat-value lane and returns the previously
 * observed lane.
 */
std::int32_t StorePrimaryStatBitsAtomic(
  StatItem* const statItem,
  const std::int32_t* const newValueBits
) noexcept
{
  return platform::AtomicExchange(&statItem->mPrimaryValueBits, *newValueBits);
}

/**
 * Address: 0x006CC960 (FUN_006CC960, cfunc_UnitSetStatL)
 *
 * What it does:
 * Resolves one unit stat lane and stores arg #3 payload bits into that stat.
 */
int moho::cfunc_UnitSetStatL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kUnitSetStatHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject statNameArg(state, 2);
  const char* const statName = lua_tostring(rawState, 2);
  if (statName == nullptr) {
    statNameArg.TypeError("string");
  }

  StatItem* const statItem = unit->GetStat(statName);
  // FAF hot-patch: 0x006CCA2A jumps to 0x0129153C in .exxt, which returns
  // `true` (via 0x0128CC1D -> lua_pushboolean) when GetStat yields no item,
  // instead of falling into the store with a null stat.
  if (statItem == nullptr) {
    lua_pushboolean(rawState, 1);
    return 1;
  }

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject valueArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      valueArg.TypeError("integer");
    }

    const std::int32_t value = static_cast<std::int32_t>(lua_tonumber(rawState, 3));
    (void)StorePrimaryStatBitsAtomic(statItem, &value);
    return 0;
  }

  if (lua_type(rawState, 3) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject valueArg(state, 3);
    const float value = static_cast<float>(valueArg.ToNumber());
    std::int32_t valueBits = std::bit_cast<std::int32_t>(value);
    (void)StorePrimaryStatBitsAtomic(statItem, &valueBits);
    return 0;
  }

  const LuaPlus::LuaStackObject valueArg(state, 3);
  const char* const value = lua_tostring(rawState, 3);
  if (value == nullptr) {
    valueArg.TypeError("string");
  }

  const std::int32_t valueBits =
    static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(value != nullptr ? value : ""));
  (void)StorePrimaryStatBitsAtomic(statItem, &valueBits);
  return 0;
}

/**
 * Address: 0x006CCB40 (FUN_006CCB40, cfunc_UnitSetWorkProgress)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetWorkProgressL`.
 */
int moho::cfunc_UnitSetWorkProgress(lua_State* const luaContext)
{
  return cfunc_UnitSetWorkProgressL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CCB60 (FUN_006CCB60, func_UnitSetWorkProgress_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetWorkProgress(progress)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetWorkProgress_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetWorkProgressName,
    &moho::cfunc_UnitSetWorkProgress,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetWorkProgressHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CCBC0 (FUN_006CCBC0, cfunc_UnitSetWorkProgressL)
 *
 * What it does:
 * Writes arg #2 into arg #1 unit work-progress runtime lane.
 */
int moho::cfunc_UnitSetWorkProgressL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetWorkProgressHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject progressArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    progressArg.TypeError("number");
  }

  unit->mUnitVarDat.mWorkProgress = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006C6310 (FUN_006C6310, cfunc_UnitSetProductionActiveL)
 *
 * What it does:
 * Writes `Unit::ProductionActive` from arg #2 and dispatches
 * `OnProductionActive` / `OnProductionInActive` script callbacks.
 */
int moho::cfunc_UnitSetProductionActiveL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetProductionActiveHelpText);

  // 0x006C6381: the unit comes from the non-raising optional conversion.
  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = GetUnitOptional(unitObject);

  const LuaPlus::LuaStackObject activeArg(state, 2);
  const bool isActive = activeArg.GetBoolean();
  unit->SetProductionActive(isActive);
  return 1;
}

/**
 * Address: 0x006C6290 (FUN_006C6290, cfunc_UnitSetProductionActive)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetProductionActiveL`.
 */
int moho::cfunc_UnitSetProductionActive(lua_State* const luaContext)
{
  return cfunc_UnitSetProductionActiveL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C62B0 (FUN_006C62B0, func_UnitSetProductionActive_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetProductionActive(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetProductionActive_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetProductionActiveName,
    &moho::cfunc_UnitSetProductionActive,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetProductionActiveHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6470 (FUN_006C6470, cfunc_UnitSetBusyL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_Busy` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetBusyL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetBusyHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject busyArg(state, 2);
  const bool shouldBeBusy = busyArg.GetBoolean();

  constexpr std::uint64_t kBusyStateMask = 0x0000000000002000ull;
  if (shouldBeBusy) {
    unit->mUnitVarDat.mUnitStates |= kBusyStateMask;
  } else {
    unit->mUnitVarDat.mUnitStates &= ~kBusyStateMask;
  }

  return 0;
}

/**
 * Address: 0x006C63F0 (FUN_006C63F0, cfunc_UnitSetBusy)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetBusyL`.
 */
int moho::cfunc_UnitSetBusy(lua_State* const luaContext)
{
  return cfunc_UnitSetBusyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6410 (FUN_006C6410, func_UnitSetBusy_LuaFuncDef)
 *
 * What it does:
 * Publishes `SetBusy(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBusy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetBusyName,
    &moho::cfunc_UnitSetBusy,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBusyHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C65F0 (FUN_006C65F0, cfunc_UnitSetBlockCommandQueueL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_BlockCommandQueue` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetBlockCommandQueueL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetBlockCommandQueueHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject flagArg(state, 2);
  const bool shouldBlock = flagArg.GetBoolean();

  constexpr std::uint64_t kBlockCommandQueueMask = 0x0000040000000000ull;
  if (shouldBlock) {
    unit->mUnitVarDat.mUnitStates |= kBlockCommandQueueMask;
  } else {
    unit->mUnitVarDat.mUnitStates &= ~kBlockCommandQueueMask;
  }

  return 0;
}

/**
 * Address: 0x006C6570 (FUN_006C6570, cfunc_UnitSetBlockCommandQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetBlockCommandQueueL`.
 */
int moho::cfunc_UnitSetBlockCommandQueue(lua_State* const luaContext)
{
  return cfunc_UnitSetBlockCommandQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6590 (FUN_006C6590, func_UnitSetBlockCommandQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetBlockCommandQueue(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetBlockCommandQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetBlockCommandQueueName,
    &moho::cfunc_UnitSetBlockCommandQueue,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetBlockCommandQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6770 (FUN_006C6770, cfunc_UnitSetImmobileL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_Immobile` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetImmobileL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetImmobileHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject flagArg(state, 2);
  const bool shouldSetImmobile = flagArg.GetBoolean();

  constexpr std::uint64_t kImmobileMask = 0x0000000000000002ull;
  if (shouldSetImmobile) {
    unit->mUnitVarDat.mUnitStates |= kImmobileMask;
  } else {
    unit->mUnitVarDat.mUnitStates &= ~kImmobileMask;
  }

  return 0;
}

/**
 * Address: 0x006C66F0 (FUN_006C66F0, cfunc_UnitSetImmobile)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetImmobileL`.
 */
int moho::cfunc_UnitSetImmobile(lua_State* const luaContext)
{
  return cfunc_UnitSetImmobileL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6710 (FUN_006C6710, func_UnitSetImmobile_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetImmobile(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetImmobile_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetImmobileName,
    &moho::cfunc_UnitSetImmobile,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetImmobileHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6A50 (FUN_006C6A50, cfunc_UnitSetUnSelectableL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_UnSelectable` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetUnSelectableL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetUnSelectableHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject flagArg(state, 2);
  const bool shouldSetUnSelectable = flagArg.GetBoolean();

  constexpr std::uint64_t kUnSelectableMask = 0x0000000200000000ull;
  if (shouldSetUnSelectable) {
    unit->mUnitVarDat.mUnitStates |= kUnSelectableMask;
  } else {
    unit->mUnitVarDat.mUnitStates &= ~kUnSelectableMask;
  }

  return 0;
}

/**
 * Address: 0x006C69D0 (FUN_006C69D0, cfunc_UnitSetUnSelectable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetUnSelectableL`.
 */
int moho::cfunc_UnitSetUnSelectable(lua_State* const luaContext)
{
  return cfunc_UnitSetUnSelectableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C69F0 (FUN_006C69F0, func_UnitSetUnSelectable_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetUnSelectable(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetUnSelectable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetUnSelectableName,
    &moho::cfunc_UnitSetUnSelectable,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetUnSelectableHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6BC0 (FUN_006C6BC0, cfunc_UnitSetDoNotTargetL)
 *
 * What it does:
 * Sets or clears `UNITSTATE_DoNotTarget` bit from arg#2 on unit arg#1.
 */
int moho::cfunc_UnitSetDoNotTargetL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetDoNotTargetHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject flagArg(state, 2);
  const bool shouldSetDoNotTarget = flagArg.GetBoolean();

  constexpr std::uint64_t kDoNotTargetMask = 0x0000000400000000ull;
  if (shouldSetDoNotTarget) {
    unit->mUnitVarDat.mUnitStates |= kDoNotTargetMask;
  } else {
    unit->mUnitVarDat.mUnitStates &= ~kDoNotTargetMask;
  }

  return 0;
}

/**
 * Address: 0x006C6B40 (FUN_006C6B40, cfunc_UnitSetDoNotTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetDoNotTargetL`.
 */
int moho::cfunc_UnitSetDoNotTarget(lua_State* const luaContext)
{
  return cfunc_UnitSetDoNotTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6B60 (FUN_006C6B60, func_UnitSetDoNotTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetDoNotTarget(unit, flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetDoNotTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetDoNotTargetName,
    &moho::cfunc_UnitSetDoNotTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetDoNotTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7030 (FUN_006C7030, cfunc_UnitSetIsValidTargetL)
 *
 * What it does:
 * Writes one boolean into `Unit::IsValidTarget`.
 */
int moho::cfunc_UnitSetIsValidTargetL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetIsValidTargetHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject validTargetArg(state, 2);
  unit->mUnitVarDat.mIsValidTarget = validTargetArg.GetBoolean();
  return 0;
}

/**
 * Address: 0x006C6FB0 (FUN_006C6FB0, cfunc_UnitSetIsValidTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetIsValidTargetL`.
 */
int moho::cfunc_UnitSetIsValidTarget(lua_State* const luaContext)
{
  return cfunc_UnitSetIsValidTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6FD0 (FUN_006C6FD0, func_UnitSetIsValidTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetIsValidTarget(self,bool)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetIsValidTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetIsValidTargetName,
    &moho::cfunc_UnitSetIsValidTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetIsValidTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C68E0 (FUN_006C68E0, cfunc_UnitSetStunnedL)
 *
 * What it does:
 * Sets unit stunned ticks from arg #2 seconds, scaled by 10 simulation ticks.
 */
int moho::cfunc_UnitSetStunnedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetStunnedHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject timeArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    timeArg.TypeError("number");
  }

  // 0x006C69A0-0x006C69AE: `fmul dword [10.0f]` on the float lua_Number,
  // rounded to single precision by the sim's `_PC_24` control word, then
  // truncated by `_ftol2`.
  unit->mUnitVarDat.mStunTicks = static_cast<std::int32_t>(static_cast<float>(lua_tonumber(rawState, 2)) * 10.0f);
  return 0;
}

/**
 * Address: 0x006C6860 (FUN_006C6860, cfunc_UnitSetStunned)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetStunnedL`.
 */
int moho::cfunc_UnitSetStunned(lua_State* const luaContext)
{
  return cfunc_UnitSetStunnedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6880 (FUN_006C6880, func_UnitSetStunned_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetStunned(unit, time)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetStunned_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetStunnedName,
    &moho::cfunc_UnitSetStunned,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetStunnedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C6D30 (FUN_006C6D30, cfunc_UnitSetUnitStateL)
 *
 * What it does:
 * Resolves `(unit, stateName, enabled)` and sets/clears the corresponding
 * state bit in `Unit::UnitStateMask` when lexical enum parsing succeeds.
 */
int moho::cfunc_UnitSetUnitStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kUnitSetUnitStateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject stateArg(state, 2);
  const char* const stateName = lua_tostring(rawState, 2);
  if (stateName == nullptr) {
    stateArg.TypeError("string");
  }

  EUnitState unitState = UNITSTATE_Immobile;
  gpg::RRef enumRef = MakeUnitStateRef(&unitState);
  if (enumRef.SetLexical(stateName)) {
    const LuaPlus::LuaStackObject enabledArg(state, 3);
    const bool enabled = enabledArg.GetBoolean();
    const int bit = static_cast<int>(unitState);
    if (bit >= 0 && bit < 64) {
      const std::uint64_t mask = 1ull << static_cast<std::uint32_t>(bit);
      if (enabled) {
        unit->mUnitVarDat.mUnitStates |= mask;
      } else {
        unit->mUnitVarDat.mUnitStates &= ~mask;
      }
    }
  }

  return 0;
}

/**
 * Address: 0x006C6CB0 (FUN_006C6CB0, cfunc_UnitSetUnitState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetUnitStateL`.
 */
int moho::cfunc_UnitSetUnitState(lua_State* const luaContext)
{
  return cfunc_UnitSetUnitStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6CD0 (FUN_006C6CD0, func_UnitSetUnitState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `SetUnitState(name, bool)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetUnitState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetUnitStateName,
    &moho::cfunc_UnitSetUnitState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetUnitStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C78F0 (FUN_006C78F0, cfunc_UnitSetScriptBitL)
 *
 * What it does:
 * Resolves `(unit, toggleCapName, enabled)` and toggles the matching script
 * bit lane through `Unit::ToggleScriptBit` when desired/current states differ.
 */
int moho::cfunc_UnitSetScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kUnitSetScriptBitHelpText);

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

  const LuaPlus::LuaStackObject enabledArg(state, 3);
  const bool enabled = enabledArg.GetBoolean();

  const int toggleCapValue = static_cast<int>(toggleCap);
  if (toggleCapValue >= 1 && toggleCapValue <= 0x100) {
    const int bitIndex = ScriptBitIndexFromToggleCapValue(toggleCapValue);
    const std::uint32_t mask = 1u << static_cast<std::uint32_t>(bitIndex);
    const bool currentlySet = (unit->mUnitVarDat.mScriptbits & mask) != 0u;
    if (currentlySet != enabled) {
      unit->ToggleScriptBit(bitIndex);
    }
  }

  return 0;
}

/**
 * Address: 0x006C7870 (FUN_006C7870, cfunc_UnitSetScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetScriptBitL`.
 */
int moho::cfunc_UnitSetScriptBit(lua_State* const luaContext)
{
  return cfunc_UnitSetScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7890 (FUN_006C7890, func_UnitSetScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetScriptBit(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetScriptBitName,
    &moho::cfunc_UnitSetScriptBit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetScriptBitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7AB0 (FUN_006C7AB0, cfunc_UnitToggleScriptBitL)
 *
 * What it does:
 * Resolves one toggle-cap lexical name and toggles the matching script bit.
 */
int moho::cfunc_UnitToggleScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitToggleScriptBitHelpText);

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
  unit->ToggleScriptBit(bitIndex);
  return 0;
}

/**
 * Address: 0x006C7A30 (FUN_006C7A30, cfunc_UnitToggleScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitToggleScriptBitL`.
 */
int moho::cfunc_UnitToggleScriptBit(lua_State* const luaContext)
{
  return cfunc_UnitToggleScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7A50 (FUN_006C7A50, func_UnitToggleScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:ToggleScriptBit(toggleName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitToggleScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitToggleScriptBitName,
    &moho::cfunc_UnitToggleScriptBit,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitToggleScriptBitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7C50 (FUN_006C7C50, cfunc_UnitToggleFireStateL)
 *
 * What it does:
 * Rotates one unit fire-state lane through `[0, 1, 2]`.
 */
int moho::cfunc_UnitToggleFireStateL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitToggleFireStateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const std::int32_t nextFireState = (unit->mUnitVarDat.mFireState + 1) % 3;
  unit->SetFireState(nextFireState);
  return 0;
}

/**
 * Address: 0x006C7BD0 (FUN_006C7BD0, cfunc_UnitToggleFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitToggleFireStateL`.
 */
int moho::cfunc_UnitToggleFireState(lua_State* const luaContext)
{
  return cfunc_UnitToggleFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7BF0 (FUN_006C7BF0, func_UnitToggleFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:ToggleFireState()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitToggleFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitToggleFireStateName,
    &moho::cfunc_UnitToggleFireState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitToggleFireStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7D90 (FUN_006C7D90, cfunc_UnitSetFireStateL)
 *
 * What it does:
 * Parses arg #2 lexical fire-state and applies it to one unit when changed.
 */
int moho::cfunc_UnitSetFireStateL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetFireStateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject fireStateArg(state, 2);
  const char* const fireStateLexical = lua_tostring(rawState, 2);
  if (fireStateLexical == nullptr) {
    fireStateArg.TypeError("string");
    return 0;
  }

  std::int32_t parsedFireState = unit->mUnitVarDat.mFireState;
  if (ParseFireStateLexical(fireStateLexical, parsedFireState) && unit->mUnitVarDat.mFireState != parsedFireState) {
    unit->SetFireState(parsedFireState);
  }

  return 0;
}

/**
 * Address: 0x006C7D10 (FUN_006C7D10, cfunc_UnitSetFireState)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFireStateL`.
 */
int moho::cfunc_UnitSetFireState(lua_State* const luaContext)
{
  return cfunc_UnitSetFireStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C7D30 (FUN_006C7D30, func_UnitSetFireState_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetFireState(stateName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetFireState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kSetFireStateName,
    &moho::cfunc_UnitSetFireState,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetFireStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C7FE0 (FUN_006C7FE0, cfunc_UnitSetAutoMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetAutoModeL`.
 */
int moho::cfunc_UnitSetAutoMode(lua_State* const luaContext)
{
  return cfunc_UnitSetAutoModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8000 (FUN_006C8000, func_UnitSetAutoMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:SetAutoMode(enabled)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetAutoMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetAutoModeName,
    &moho::cfunc_UnitSetAutoMode,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetAutoModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8060 (FUN_006C8060, cfunc_UnitSetAutoModeL)
 *
 * What it does:
 * Resolves `(unit, enabled)` and dispatches to `Unit::SetAutoMode`.
 */
int moho::cfunc_UnitSetAutoModeL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetAutoModeHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject enabledArg(state, 2);
  unit->SetAutoMode(enabledArg.GetBoolean());
  return 0;
}

/**
 * Address: 0x006C8120 (FUN_006C8120, cfunc_UnitAddBuildRestriction)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitAddBuildRestrictionL`.
 */
int moho::cfunc_UnitAddBuildRestriction(lua_State* const luaContext)
{
  return cfunc_UnitAddBuildRestrictionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8140 (FUN_006C8140, func_UnitAddBuildRestriction_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AddBuildRestriction(categorySet)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitAddBuildRestriction_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitAddBuildRestrictionName,
    &moho::cfunc_UnitAddBuildRestriction,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAddBuildRestrictionHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C81A0 (FUN_006C81A0, cfunc_UnitAddBuildRestrictionL)
 *
 * What it does:
 * Merges category bits into one unit build-restriction set and marks sync dirty.
 */
int moho::cfunc_UnitAddBuildRestrictionL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitAddBuildRestrictionHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  EntityCategorySet& restrictionWords = unit->GetAttributes().restrictionCategory;
  (void)EntityCategory::Add(&restrictionWords, categorySet);
  unit->mVarDat.mRequestRefreshUI = 1;
  return 0;
}

/**
 * Address: 0x006C8290 (FUN_006C8290, cfunc_UnitRemoveBuildRestriction)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveBuildRestrictionL`.
 */
int moho::cfunc_UnitRemoveBuildRestriction(lua_State* const luaContext)
{
  return cfunc_UnitRemoveBuildRestrictionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C82B0 (FUN_006C82B0, func_UnitRemoveBuildRestriction_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveBuildRestriction(categorySet)` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveBuildRestriction_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRemoveBuildRestrictionName,
    &moho::cfunc_UnitRemoveBuildRestriction,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveBuildRestrictionHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8310 (FUN_006C8310, cfunc_UnitRemoveBuildRestrictionL)
 *
 * What it does:
 * Clears category bits from one unit build-restriction set and marks sync dirty.
 */
int moho::cfunc_UnitRemoveBuildRestrictionL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitRemoveBuildRestrictionHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
  const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

  EntityCategorySet& restrictionWords = unit->GetAttributes().restrictionCategory;
  AsCategoryWordBitset(restrictionWords).RemoveAllFrom(&categorySet->Bits());
  unit->mVarDat.mRequestRefreshUI = 1;
  return 0;
}

/**
 * Address: 0x006C85E0 (FUN_006C85E0, cfunc_UnitAddCommandCapL)
 *
 * What it does:
 * Resolves one command-cap lexical arg and ORs it into unit command-cap mask.
 */
int moho::cfunc_UnitAddCommandCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitAddCommandCapHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitCommandCaps commandCap = RULEUCC_None;
  gpg::RRef enumRef = MakeRuleUnitCommandCapsRef(&commandCap);
  const LuaPlus::LuaStackObject capArg(state, 2);
  const char* const capName = lua_tostring(rawState, 2);
  if (capName == nullptr) {
    capArg.TypeError("string");
  }

  SCR_GetEnum(state, capName, enumRef);
  unit->GetAttributes().commandCapsMask |= static_cast<std::uint32_t>(commandCap);
  unit->mVarDat.mRequestRefreshUI = 1;
  return 0;
}

/**
 * Address: 0x006C8560 (FUN_006C8560, cfunc_UnitAddCommandCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitAddCommandCapL`.
 */
int moho::cfunc_UnitAddCommandCap(lua_State* const luaContext)
{
  return cfunc_UnitAddCommandCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8580 (FUN_006C8580, func_UnitAddCommandCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AddCommandCap(capName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitAddCommandCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitAddCommandCapName,
    &moho::cfunc_UnitAddCommandCap,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAddCommandCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8780 (FUN_006C8780, cfunc_UnitRemoveCommandCapL)
 *
 * What it does:
 * Resolves one command-cap lexical arg and clears it from unit command-cap
 * mask.
 */
int moho::cfunc_UnitRemoveCommandCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitRemoveCommandCapHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitCommandCaps commandCap = RULEUCC_None;
  gpg::RRef enumRef = MakeRuleUnitCommandCapsRef(&commandCap);
  const LuaPlus::LuaStackObject capArg(state, 2);
  const char* const capName = lua_tostring(rawState, 2);
  if (capName == nullptr) {
    capArg.TypeError("string");
  }

  SCR_GetEnum(state, capName, enumRef);
  unit->GetAttributes().commandCapsMask &= ~static_cast<std::uint32_t>(commandCap);
  unit->mVarDat.mRequestRefreshUI = 1;
  return 0;
}

/**
 * Address: 0x006C8700 (FUN_006C8700, cfunc_UnitRemoveCommandCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveCommandCapL`.
 */
int moho::cfunc_UnitRemoveCommandCap(lua_State* const luaContext)
{
  return cfunc_UnitRemoveCommandCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8720 (FUN_006C8720, func_UnitRemoveCommandCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveCommandCap(capName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveCommandCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRemoveCommandCapName,
    &moho::cfunc_UnitRemoveCommandCap,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveCommandCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8C00 (FUN_006C8C00, cfunc_UnitAddToggleCapL)
 *
 * What it does:
 * Resolves one toggle-cap lexical arg and ORs it into unit toggle-cap mask.
 */
int moho::cfunc_UnitAddToggleCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitAddToggleCapHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject capArg(state, 2);
  const char* const capName = lua_tostring(rawState, 2);
  if (capName == nullptr) {
    capArg.TypeError("string");
  }

  SCR_GetEnum(state, capName, enumRef);
  unit->GetAttributes().toggleCapsMask |= static_cast<std::uint32_t>(toggleCap);
  unit->mVarDat.mRequestRefreshUI = 1;
  return 0;
}

/**
 * Address: 0x006C8B80 (FUN_006C8B80, cfunc_UnitAddToggleCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitAddToggleCapL`.
 */
int moho::cfunc_UnitAddToggleCap(lua_State* const luaContext)
{
  return cfunc_UnitAddToggleCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8BA0 (FUN_006C8BA0, func_UnitAddToggleCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AddToggleCap(capName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitAddToggleCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitAddToggleCapName,
    &moho::cfunc_UnitAddToggleCap,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAddToggleCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8DA0 (FUN_006C8DA0, cfunc_UnitRemoveToggleCapL)
 *
 * What it does:
 * Resolves one toggle-cap lexical arg and clears it from unit toggle-cap mask.
 */
int moho::cfunc_UnitRemoveToggleCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitRemoveToggleCapHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject capArg(state, 2);
  const char* const capName = lua_tostring(rawState, 2);
  if (capName == nullptr) {
    capArg.TypeError("string");
  }

  SCR_GetEnum(state, capName, enumRef);
  unit->GetAttributes().toggleCapsMask &= ~static_cast<std::uint32_t>(toggleCap);
  unit->mVarDat.mRequestRefreshUI = 1;
  return 0;
}

/**
 * Address: 0x006C8D20 (FUN_006C8D20, cfunc_UnitRemoveToggleCap)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRemoveToggleCapL`.
 */
int moho::cfunc_UnitRemoveToggleCap(lua_State* const luaContext)
{
  return cfunc_UnitRemoveToggleCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8D40 (FUN_006C8D40, func_UnitRemoveToggleCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RemoveToggleCap(capName)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRemoveToggleCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRemoveToggleCapName,
    &moho::cfunc_UnitRemoveToggleCap,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRemoveToggleCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9460 (FUN_006C9460, cfunc_UnitSetReclaimable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetReclaimableL`.
 */
int moho::cfunc_UnitSetReclaimable(lua_State* const luaContext)
{
  return cfunc_UnitSetReclaimableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9480 (FUN_006C9480, func_UnitSetReclaimable_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetReclaimable(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetReclaimable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetReclaimableName,
    &moho::cfunc_UnitSetReclaimable,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetReclaimableHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C94E0 (FUN_006C94E0, cfunc_UnitSetReclaimableL)
 *
 * What it does:
 * Resolves `(self, flag)` and updates `UnitAttributes::mReclaimable`.
 */
int moho::cfunc_UnitSetReclaimableL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetReclaimableHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject reclaimableArg(state, 2);
  unit->GetAttributes().mReclaimable = reclaimableArg.GetBoolean();
  return 0;
}

/**
 * Address: 0x006C95B0 (FUN_006C95B0, cfunc_UnitSetCapturable)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetCapturableL`.
 */
int moho::cfunc_UnitSetCapturable(lua_State* const luaContext)
{
  return cfunc_UnitSetCapturableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C95D0 (FUN_006C95D0, func_UnitSetCapturable_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetCapturable(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetCapturable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetCapturableName,
    &moho::cfunc_UnitSetCapturable,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetCapturableHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9630 (FUN_006C9630, cfunc_UnitSetCapturableL)
 *
 * What it does:
 * Resolves `(self, flag)` and updates `UnitAttributes::mCapturable`.
 */
int moho::cfunc_UnitSetCapturableL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetCapturableHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject capturableArg(state, 2);
  unit->GetAttributes().mCapturable = capturableArg.GetBoolean();
  return 0;
}

/**
 * Address: 0x006C9840 (FUN_006C9840, cfunc_UnitSetOverchargePaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitSetOverchargePausedL`.
 */
int moho::cfunc_UnitSetOverchargePaused(lua_State* const luaContext)
{
  return cfunc_UnitSetOverchargePausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9860 (FUN_006C9860, func_UnitSetOverchargePaused_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetOverchargePaused(flag)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetOverchargePaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetOverchargePausedName,
    &moho::cfunc_UnitSetOverchargePaused,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetOverchargePausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C98C0 (FUN_006C98C0, cfunc_UnitSetOverchargePausedL)
 *
 * What it does:
 * Resolves `(self, flag)` and updates `Unit::OverchargePaused`.
 */
int moho::cfunc_UnitSetOverchargePausedL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetOverchargePausedHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject pausedArg(state, 2);
  unit->mUnitVarDat.mOverchargePaused = pausedArg.GetBoolean();
  return 0;
}

/**
 * Address: 0x006D08D0 (FUN_006D08D0, cfunc_UnitSetFuelUseTime)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFuelUseTimeL`.
 */
int moho::cfunc_UnitSetFuelUseTime(lua_State* const luaContext)
{
  return cfunc_UnitSetFuelUseTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D08F0 (FUN_006D08F0, func_UnitSetFuelUseTime_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetFuelUseTime(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetFuelUseTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetFuelUseTimeName,
    &moho::cfunc_UnitSetFuelUseTime,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetFuelUseTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0950 (FUN_006D0950, cfunc_UnitSetFuelUseTimeL)
 *
 * What it does:
 * Validates `(self, fuelUseTime)` and writes the unit motion fuel-use-time
 * lane; throws a Lua error when the unit has no motion object.
 */
int moho::cfunc_UnitSetFuelUseTimeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetFuelUseTimeHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (!unit->UnitMotion) {
    LuaPlus::LuaState::Error(state, "Unit has not motion object");
  }

  const LuaPlus::LuaStackObject fuelUseTimeArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    fuelUseTimeArg.TypeError("number");
  }

  unit->UnitMotion->mFuelUseTime = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006D0BB0 (FUN_006D0BB0, cfunc_UnitSetFuelRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetFuelRatioL`.
 */
int moho::cfunc_UnitSetFuelRatio(lua_State* const luaContext)
{
  return cfunc_UnitSetFuelRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0BD0 (FUN_006D0BD0, func_UnitSetFuelRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetFuelRatio(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetFuelRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetFuelRatioName,
    &moho::cfunc_UnitSetFuelRatio,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetFuelRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0C30 (FUN_006D0C30, cfunc_UnitSetFuelRatioL)
 *
 * What it does:
 * Validates `(self, fuelRatio)` and writes the unit fuel-ratio runtime lane;
 * throws a Lua error when the unit has no motion object.
 */
int moho::cfunc_UnitSetFuelRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetFuelRatioHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (!unit->UnitMotion) {
    LuaPlus::LuaState::Error(state, "Unit has not motion object");
  }

  const LuaPlus::LuaStackObject fuelRatioArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    fuelRatioArg.TypeError("number");
  }

  unit->mUnitVarDat.mFuelRatio = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}

/**
 * Address: 0x006D1470 (FUN_006D1470, cfunc_UnitShowBone)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitShowBoneL`.
 */
int moho::cfunc_UnitShowBone(lua_State* const luaContext)
{
  return cfunc_UnitShowBoneL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1490 (FUN_006D1490, func_UnitShowBone_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:ShowBone(self,bone,affectChildren)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitShowBone_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitShowBoneName,
    &moho::cfunc_UnitShowBone,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitShowBoneHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D14F0 (FUN_006D14F0, cfunc_UnitShowBoneL)
 *
 * What it does:
 * Resolves a target bone and marks it visible; when `affectChildren` is true,
 * applies visibility recursively to descendant bones in the active pose lane.
 */
int moho::cfunc_UnitShowBoneL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 3, kUnitShowBoneHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  LuaPlus::LuaStackObject boneArg(state, 2);
  const int boneIndex = ENTSCR_ResolveBoneIndex(unit, boneArg, false);

  LuaPlus::LuaStackObject affectChildrenArg(state, 3);
  const bool affectChildren = affectChildrenArg.GetBoolean();

  if (unit != nullptr && boneIndex >= 0) {
    if (CAniPoseBone* const poseBone = ResolveUnitPoseBone(*unit, boneIndex); poseBone != nullptr) {
      if (affectChildren) {
        (void)poseBone->SetVisibleRecur(true);
      } else {
        poseBone->mVisible = 1u;
      }
    }
  }


  return 0;
}

/**
 * Address: 0x006D1610 (FUN_006D1610, cfunc_UnitHideBone)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitHideBoneL`.
 */
int moho::cfunc_UnitHideBone(lua_State* const luaContext)
{
  return cfunc_UnitHideBoneL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1630 (FUN_006D1630, func_UnitHideBone_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:HideBone(self,bone,affectChildren)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitHideBone_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitHideBoneName,
    &moho::cfunc_UnitHideBone,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitHideBoneHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D1690 (FUN_006D1690, cfunc_UnitHideBoneL)
 *
 * What it does:
 * Resolves a target bone and marks it hidden; when `affectChildren` is true,
 * applies visibility recursively to descendant bones in the active pose lane.
 */
int moho::cfunc_UnitHideBoneL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 3, kUnitHideBoneHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  LuaPlus::LuaStackObject boneArg(state, 2);
  const int boneIndex = ENTSCR_ResolveBoneIndex(unit, boneArg, false);

  LuaPlus::LuaStackObject affectChildrenArg(state, 3);
  const bool affectChildren = affectChildrenArg.GetBoolean();


  if (unit != nullptr && boneIndex >= 0) {
    if (CAniPoseBone* const poseBone = ResolveUnitPoseBone(*unit, boneIndex); poseBone != nullptr) {
      if (affectChildren) {
        (void)poseBone->SetVisibleRecur(false);
      } else {
        poseBone->mVisible = 0u;
      }
    }
  }

  return 0;
}

/**
 * Address: 0x006CDB00 (FUN_006CDB00, cfunc_UnitSetCustomName)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetCustomNameL`.
 */
int moho::cfunc_UnitSetCustomName(lua_State* const luaContext)
{
  return cfunc_UnitSetCustomNameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CDB20 (FUN_006CDB20, func_UnitSetCustomName_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetCustomName(name)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetCustomName_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetCustomNameName,
    &moho::cfunc_UnitSetCustomName,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetCustomNameHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CDB80 (FUN_006CDB80, cfunc_UnitSetCustomNameL)
 *
 * What it does:
 * Resolves `(self, name)` and dispatches `Unit::SetCustomName`.
 */
int moho::cfunc_UnitSetCustomNameL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetCustomNameHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject nameArg(state, 2);
  const char* customName = lua_tostring(rawState, 2);
  if (customName == nullptr) {
    nameArg.TypeError("string");
    customName = "";
  }

  unit->SetCustomName(std::string(customName));
  return 0;
}

/**
 * Address: 0x006D0D30 (FUN_006D0D30, cfunc_UnitSetShieldRatio)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitSetShieldRatioL`.
 */
int moho::cfunc_UnitSetShieldRatio(lua_State* const luaContext)
{
  return cfunc_UnitSetShieldRatioL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0D50 (FUN_006D0D50, func_UnitSetShieldRatio_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:SetShieldRatio(value)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitSetShieldRatio_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitSetShieldRatioName,
    &moho::cfunc_UnitSetShieldRatio,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitSetShieldRatioHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D0DB0 (FUN_006D0DB0, cfunc_UnitSetShieldRatioL)
 *
 * What it does:
 * Resolves `(self, value)` and writes `Unit::ShieldRatio`.
 */
int moho::cfunc_UnitSetShieldRatioL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitSetShieldRatioHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject ratioArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    ratioArg.TypeError("number");
  }

  unit->mUnitVarDat.mShieldRatio = static_cast<float>(lua_tonumber(rawState, 2));
  return 0;
}
