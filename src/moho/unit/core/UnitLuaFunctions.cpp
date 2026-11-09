#include "moho/unit/core/UnitLuaPrivate.h"

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kUnitAlterArmorName = "AlterArmor";
  constexpr const char* kUnitAlterArmorHelpText = "Unit:AlterArmor(damageTypeName, multiplier)";
  constexpr const char* kNotifyUpgradeName = "NotifyUpgrade";
  constexpr const char* kNotifyUpgradeGlobalClassName = "<global>";
  constexpr const char* kNotifyUpgradeHelpText = "NotifyUpgrade(from,to)";
  constexpr const char* kCreateUnit2Name = "CreateUnit2";
  constexpr const char* kCreateUnit2GlobalClassName = "<global>";
  constexpr const char* kCreateUnit2HelpText = "blueprint, army, layer, x, z, heading";
  constexpr const char* kCreateUnitName = "CreateUnit";
  constexpr const char* kCreateUnitGlobalClassName = "<global>";
  constexpr const char* kCreateUnitHelpText = "blueprint, army, tx, ty, tz, qx, qy, qz, qw, [layer]";
  constexpr const char* kCreateUnitHPRName = "CreateUnitHPR";
  constexpr const char* kCreateUnitHPRGlobalClassName = "<global>";
  constexpr const char* kCreateUnitHPRHelpText = "blueprint, army, x, y, z, pitch, yaw, roll";
  constexpr const char* kUnitKillManipulatorName = "KillManipulator";
  constexpr const char* kUnitKillManipulatorHelpText = "Kill a specific manipulator held by a script object";
  constexpr const char* kUnitKillManipulatorsName = "KillManipulators";
  constexpr const char* kUnitKillManipulatorsHelpText = "Unit:KillManipulators([boneName|boneIndex])";
  constexpr const char* kUnitScaleGetBuiltEmitterName = "ScaleGetBuiltEmitter";
  constexpr const char* kUnitScaleGetBuiltEmitterHelpText = "ScaleGetBuiltEmitter(self, emitter)";
  constexpr const char* kUnitPrintCommandQueueName = "PrintCommandQueue";
  constexpr const char* kUnitPrintCommandQueueHelpText = "Unit:PrintCommandQueue()";
  constexpr const char* kUnitPrintCommandQueueHeaderLogFormat = "*AI DEBUG: Command List for %s: \n";
  constexpr const char* kUnitPrintCommandQueueEntryLogFormat = "*AI DEBUG: %s\n";
  constexpr const char* kUnitPrintCommandQueueUnknownCommandName = "Bad Command";
  constexpr const char* kUnitMeleeWarpAdjacentToTargetName = "MeleeWarpAdjacentToTarget";
  constexpr const char* kUnitMeleeWarpAdjacentToTargetHelpText = "Unit:MeleeWarpAdjacentToTarget(target)";
  constexpr const char* kUnitForceAltFootprintName = "ForceAltFootprint";
  constexpr const char* kUnitGiveNukeSiloAmmoName = "GiveNukeSiloAmmo";
  constexpr const char* kUnitGiveNukeSiloAmmoHelpText = "Unit:GiveNukeSiloAmmo(num)";
  constexpr const char* kUnitGiveTacticalSiloAmmoName = "GiveTacticalSiloAmmo";
  constexpr const char* kUnitGiveTacticalSiloAmmoHelpText = "Unit:GiveTacticalSiloAmmo(num)";
  constexpr const char* kUnitRevertRegenRateName = "RevertRegenRate";
  constexpr const char* kUnitRevertRegenRateHelpText = "Restore regen rate of the unit back to blueprint spec.";
  constexpr const char* kUnitRevertElevationName = "RevertElevation";
  constexpr const char* kUnitRevertElevationHelpText = "Revert the elevation of the unit back to the blueperint spec";
  constexpr const char* kUnitRestoreBuildRestrictionsName = "RestoreBuildRestrictions";
  constexpr const char* kUnitRestoreBuildRestrictionsHelpText =
    "Restore buildable categories to that as defined in the blueprint";
  constexpr const char* kUnitStopSiloBuildName = "StopSiloBuild";
  constexpr const char* kUnitStopSiloBuildHelpText = "StopSiloBuild(unit)";
  constexpr const char* kUnitTransportHasSpaceForName = "TransportHasSpaceFor";
  constexpr const char* kUnitTransportHasSpaceForHelpText = "TransportHasSpaceFor(self,target)";
  constexpr const char* kUnitTransportHasAvailableStorageName = "TransportHasAvailableStorage";
  constexpr const char* kUnitTransportHasAvailableStorageHelpText = "TransportHasAvailableStorage(self)";
  constexpr const char* kUnitTransportDetachAllUnitsName = "TransportDetachAllUnits";
  constexpr const char* kUnitTransportDetachAllUnitsHelpText = "DetachAllUnits(self,destroySomeUnits)";
  constexpr const char* kUnitTransportDetachAllUnitsTransportError =
    "Unit:TransportDetachAllUnits can only be called for transports";
  constexpr const char* kUnitRestoreCommandCapsName = "RestoreCommandCaps";
  constexpr const char* kUnitRestoreCommandCapsHelpText =
    "Restore the command caps of the unit back to blueprint spec.";
  constexpr const char* kUnitRestoreToggleCapsName = "RestoreToggleCaps";
  constexpr const char* kUnitRestoreToggleCapsHelpText =
    "Restore the toggle caps of the unit back to blueprint spec.";
  constexpr const char* kUnitTestCommandCapsName = "TestCommandCaps";
  constexpr const char* kUnitTestCommandCapsHelpText =
    "Test if a unit has this specified set to true in the blueprint spec.";
  constexpr const char* kUnitTestToggleCapsName = "TestToggleCaps";
  constexpr const char* kUnitTestToggleCapsHelpText =
    "Test if a unit has this specified set to true in the blueprint spec.";
  constexpr const char* kUnitRecoilImpulseName = "RecoilImpulse";
  constexpr const char* kUnitRecoilImpulseHelpText = "RecoilImpulse(self, x, y, z)";
  constexpr const char* kUnitRevertCollisionShapeName = "RevertCollisionShape";
  constexpr const char* kUnitRevertCollisionShapeHelpText = "Revert the collision shape to the blueprint spec";

  [[nodiscard]] const char* UnitCommandTypeDebugName(const EUnitCommandType commandType) noexcept
  {
    switch (commandType) {
      case EUnitCommandType::UNITCOMMAND_None:
        return "None";
      case EUnitCommandType::UNITCOMMAND_Stop:
        return "Stop";
      case EUnitCommandType::UNITCOMMAND_Move:
        return "Move";
      case EUnitCommandType::UNITCOMMAND_Dive:
        return "Dive";
      case EUnitCommandType::UNITCOMMAND_FormMove:
        return "FormMove";
      case EUnitCommandType::UNITCOMMAND_BuildSiloTactical:
        return "BuildSiloTactical";
      case EUnitCommandType::UNITCOMMAND_BuildSiloNuke:
        return "BuildSiloNuke";
      case EUnitCommandType::UNITCOMMAND_BuildFactory:
        return "BuildFactory";
      case EUnitCommandType::UNITCOMMAND_BuildMobile:
        return "BuildMobile ";
      case EUnitCommandType::UNITCOMMAND_BuildAssist:
        return "BuildAssist";
      case EUnitCommandType::UNITCOMMAND_Attack:
        return "Attack";
      case EUnitCommandType::UNITCOMMAND_FormAttack:
        return "FormAttack";
      case EUnitCommandType::UNITCOMMAND_Nuke:
        return "Nuke";
      case EUnitCommandType::UNITCOMMAND_Tactical:
        return "Tactical";
      case EUnitCommandType::UNITCOMMAND_Teleport:
        return "Teleport";
      case EUnitCommandType::UNITCOMMAND_Guard:
        return "Guard";
      case EUnitCommandType::UNITCOMMAND_Patrol:
        return "Patrol";
      case EUnitCommandType::UNITCOMMAND_Ferry:
        return "Ferry";
      case EUnitCommandType::UNITCOMMAND_FormPatrol:
        return "FormPatrol";
      case EUnitCommandType::UNITCOMMAND_Reclaim:
        return "Reclaim";
      case EUnitCommandType::UNITCOMMAND_Repair:
        return "Repair";
      case EUnitCommandType::UNITCOMMAND_Capture:
        return "Capture";
      case EUnitCommandType::UNITCOMMAND_TransportLoadUnits:
        return "TransportLoadUnits";
      case EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits:
        return "TransportReverseLoadUnits";
      case EUnitCommandType::UNITCOMMAND_TransportUnloadUnits:
        return "TransportUnloadUnits";
      case EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits:
        return "TransportUnloadSpecificUnits";
      case EUnitCommandType::UNITCOMMAND_DetachFromTransport:
        return "DetachFromTransport";
      case EUnitCommandType::UNITCOMMAND_Upgrade:
        return "Upgrade";
      case EUnitCommandType::UNITCOMMAND_Script:
        return "Script";
      case EUnitCommandType::UNITCOMMAND_AssistCommander:
        return "AssistCommander";
      case EUnitCommandType::UNITCOMMAND_KillSelf:
        return "KillSelf";
      case EUnitCommandType::UNITCOMMAND_DestroySelf:
        return "DestroySelf";
      case EUnitCommandType::UNITCOMMAND_Sacrifice:
        return "Sacrifice";
      case EUnitCommandType::UNITCOMMAND_Pause:
        return "Pause";
      case EUnitCommandType::UNITCOMMAND_OverCharge:
        return "OverCharge";
      case EUnitCommandType::UNITCOMMAND_AggressiveMove:
        return "AggressiveMove";
      case EUnitCommandType::UNITCOMMAND_FormAggressiveMove:
        return "FormAggressiveMove";
      case EUnitCommandType::UNITCOMMAND_AssistMove:
        return "AssistMove";
      case EUnitCommandType::UNITCOMMAND_SpecialAction:
        return "SpecialAction";
      case EUnitCommandType::UNITCOMMAND_Dock:
        return "Dock";
      default:
        return kUnitPrintCommandQueueUnknownCommandName;
    }
  }

  [[nodiscard]] std::string BuildPrintCommandQueueLabel(const CUnitCommand& command)
  {
    std::string label = UnitCommandTypeDebugName(command.mVarDat.mCmdType);
    if (command.mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_BuildMobile) {
      if (const REntityBlueprint* const blueprint = command.mConstDat.blueprint; blueprint != nullptr) {
        const char* const blueprintName = blueprint->mBlueprintId.c_str();
        if (blueprintName != nullptr && blueprintName[0] != '\0') {
          label.append(blueprintName);
        }
      }
    }
    return label;
  }

  [[nodiscard]] SEfxCurve BuildSingleEmitterScaleCurve(const Wm3::Vector3f& key)
  {
    SEfxCurve curve{};
    curve.mKeys.clear();
    curve.mKeys.push_back(key);
    curve.mBoundsMin.y = key.y;
    curve.mBoundsMax.y = key.y;
    return curve;
  }
}


/**
 * Address: 0x006C3F80 (FUN_006C3F80, cfunc_UnitAlterArmor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitAlterArmorL`.
 */
int moho::cfunc_UnitAlterArmor(lua_State* const luaContext)
{
  return cfunc_UnitAlterArmorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C3FA0 (FUN_006C3FA0, func_UnitAlterArmor_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:AlterArmor(damageTypeName, multiplier)` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitAlterArmor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitAlterArmorName,
    &moho::cfunc_UnitAlterArmor,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitAlterArmorHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C4000 (FUN_006C4000, cfunc_UnitAlterArmorL)
 *
 * What it does:
 * Writes or creates one damage-type armor multiplier entry in this unit's
 * runtime armor map.
 */
int moho::cfunc_UnitAlterArmorL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 3, kUnitAlterArmorHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject damageTypeArg(state, 2);
  const char* damageTypeName = lua_tostring(rawState, 2);
  if (damageTypeName == nullptr) {
    damageTypeArg.TypeError("string");
    damageTypeName = "";
  }
  const fa::string armorTypeName(damageTypeName);

  const LuaPlus::LuaStackObject armorMultiplierArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    armorMultiplierArg.TypeError("number");
  }
  const float armorMultiplier = lua_tonumber(rawState, 3);

  unit->ArmorMultipliers[armorTypeName] = armorMultiplier;
  return 0;
}

/**
 * Address: 0x006C5170 (FUN_006C5170, cfunc_UnitKillManipulator)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitKillManipulatorL`.
 */
int moho::cfunc_UnitKillManipulator(lua_State* const luaContext)
{
  return cfunc_UnitKillManipulatorL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5190 (FUN_006C5190, func_UnitKillManipulator_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:KillManipulator(manipulator)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitKillManipulator_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitKillManipulatorName,
    &moho::cfunc_UnitKillManipulator,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitKillManipulatorHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C51F0 (FUN_006C51F0, cfunc_UnitKillManipulatorL)
 *
 * What it does:
 * Resolves `(unit, manipulator)` from Lua and destroys that exact manipulator
 * on the unit actor when present.
 */
int moho::cfunc_UnitKillManipulatorL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitKillManipulatorHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 2));
  auto* const manipulator = SCR_FromLua_IAniManipulator(manipulatorObject, state);
  unit->AniActor->KillManipulator(manipulator);
  return 1;
}

/**
 * Address: 0x006C52E0 (FUN_006C52E0, cfunc_UnitKillManipulators)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitKillManipulatorsL`.
 */
int moho::cfunc_UnitKillManipulators(lua_State* const luaContext)
{
  return cfunc_UnitKillManipulatorsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C5300 (FUN_006C5300, func_UnitKillManipulators_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:KillManipulators([boneName|boneIndex])` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitKillManipulators_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitKillManipulatorsName,
    &moho::cfunc_UnitKillManipulators,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitKillManipulatorsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C5360 (FUN_006C5360, cfunc_UnitKillManipulatorsL)
 *
 * What it does:
 * Kills each unit manipulator that matches arg #2 by bone index (`number`) or
 * bone name wildcard (`string`).
 */
int moho::cfunc_UnitKillManipulatorsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitKillManipulatorsHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (lua_type(rawState, 2) == LUA_TNUMBER) {
    const LuaPlus::LuaStackObject boneIndexArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      boneIndexArg.TypeError("integer");
    }

    const int boneIndex = static_cast<int>(lua_tonumber(rawState, 2));
    unit->AniActor->KillManipulatorByBoneIndex(boneIndex);
    return 0;
  }

  const LuaPlus::LuaStackObject boneNameArg(state, 2);
  const char* const boneName = lua_tostring(rawState, 2);
  if (boneName == nullptr) {
    boneNameArg.TypeError("string");
  }

  unit->AniActor->KillManipulatorsByBonePattern(boneName);
  return 0;
}

/**
 * Address: 0x006C5530 (FUN_006C5530, cfunc_UnitScaleGetBuiltEmitterL)
 *
 * What it does:
 * Applies unit-footprint scale curves to emitter parameters `(10, 4, 3)`.
 */
int moho::cfunc_UnitScaleGetBuiltEmitterL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitScaleGetBuiltEmitterHelpText);

  const LuaPlus::LuaObject entityObject(LuaPlus::LuaStackObject(state, 1));
  Entity* const entity = SCR_FromLua_Entity(entityObject, state);
  Unit* const unit = entity ? entity->IsUnit() : nullptr;
  if (unit == nullptr) {
    return 0;
  }

  const LuaPlus::LuaObject effectObject(LuaPlus::LuaStackObject(state, 2));
  IEffect* const effect = SCR_FromLua_IEffect(effectObject, state);

  const SFootprint& footprint = unit->GetFootprint();
  const Wm3::Vector3f scaleKey(
    static_cast<float>(footprint.mSizeX),
    static_cast<float>(footprint.mSizeZ),
    0.0f
  );

  const SEfxCurve param10Curve = BuildSingleEmitterScaleCurve(scaleKey);
  effect->SetCurveParam(10, &param10Curve);

  const SEfxCurve param4Curve = BuildSingleEmitterScaleCurve(scaleKey);
  effect->SetCurveParam(4, &param4Curve);

  const SEfxCurve param3Curve = BuildSingleEmitterScaleCurve(scaleKey);
  effect->SetCurveParam(3, &param3Curve);

  return 0;
}

/**
 * Address: 0x006C54B0 (FUN_006C54B0, cfunc_UnitScaleGetBuiltEmitter)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitScaleGetBuiltEmitterL`.
 */
int moho::cfunc_UnitScaleGetBuiltEmitter(lua_State* const luaContext)
{
  return cfunc_UnitScaleGetBuiltEmitterL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C54D0 (FUN_006C54D0, func_UnitScaleGetBuiltEmitter_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:ScaleGetBuiltEmitter(self, emitter)` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitScaleGetBuiltEmitter_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitScaleGetBuiltEmitterName,
    &moho::cfunc_UnitScaleGetBuiltEmitter,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitScaleGetBuiltEmitterHelpText
  );
  return &binder;
}

/**
 * What it does:
 * Publishes the FAF `Unit:ForceAltFootprint(flag)` Lua binder definition
 * (`.exxt` static initializer 0x01292454..0x0129247C: name, class `Unit`,
 * empty help text, function slot 0x0128DB0F, sim init set).
 */
CScrLuaInitForm* moho::func_UnitForceAltFootprint_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitForceAltFootprintName,
    &moho::cfunc_UnitForceAltFootprint,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    ""
  );
  return &binder;
}

/**
 * Address: 0x0128DB0F (FAF patch, cfunc_UnitForceAltFootprint)
 *
 * What it does:
 * FAF extension: reads `(unit, flag)` and stores `flag` into the unit's
 * secondary alt-footprint byte (`[unit+125h]`, Entity `+11Dh`), which
 * `Entity::GetFootprint` ORs with the primary one to pick `AltFootprint`.
 * Amphibious hulls such as URS0201 flip it from `OnScriptBitSet`.
 */
int moho::cfunc_UnitForceAltFootprint(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
  const int argumentCount = lua_gettop(luaContext);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitForceAltFootprintName, 2, argumentCount);
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  unit->mVarDat.mUsingAltFootprintSecondary = static_cast<std::uint8_t>(lua_toboolean(luaContext, 2));
  return 0;
}

/**
 * Address: 0x006CDF50 (FUN_006CDF50, cfunc_UnitMeleeWarpAdjacentToTargetL)
 *
 * IDA signature:
 * int __thiscall cfunc_UnitMeleeWarpAdjacentToTargetL(LuaPlus::LuaState *this);
 *
 * What it does:
 * Reads `(meleeUnit, target)`, computes the target footprint-origin cell, and
 * asks the melee unit whether it has adjacent melee space around the target
 * (large-target check for mobile multi-cell targets, otherwise the small-target
 * check). When space exists, converts the (possibly adjusted) cell back to a
 * world position using the melee unit's footprint, orients the melee unit toward
 * the target, and warps it to that adjacent transform.
 */
int moho::cfunc_UnitMeleeWarpAdjacentToTargetL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitMeleeWarpAdjacentToTargetHelpText);

  const LuaPlus::LuaObject meleeUnitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const meleeUnit = SCR_FromLua_Unit(meleeUnitObject);

  const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const target = SCR_FromLua_Unit(targetObject);

  const SFootprint& targetFootprint = target->GetFootprint();
  const Wm3::Vec3f& targetPosition = target->GetPosition();

  SOCellPos cell{};
  cell.x = static_cast<std::int16_t>(static_cast<int>(std::lrintf(targetPosition.x - (targetFootprint.mSizeX * 0.5f))));
  cell.z = static_cast<std::int16_t>(static_cast<int>(std::lrintf(targetPosition.z - (targetFootprint.mSizeZ * 0.5f))));

  bool hasMeleeSpace = false;
  if (target->IsMobile()) {
    const SFootprint& mobileFootprint = target->GetFootprint();
    const int targetSize = std::max<int>(mobileFootprint.mSizeX, mobileFootprint.mSizeZ);
    if (targetSize > 1) {
      if (!meleeUnit->HasMeleeSpaceAroundLargeTarget(target, &cell, 1)) {
        return 0;
      }
      hasMeleeSpace = true;
    }
  }
  if (!hasMeleeSpace) {
    hasMeleeSpace = meleeUnit->HasMeleeSpaceAroundSmallTarget(target, &cell);
  }

  if (hasMeleeSpace) {
    const STIMap* const mapData = meleeUnit->SimulationRef->mMapData;
    const SFootprint& meleeFootprint = meleeUnit->GetFootprint();
    // The binary forwards the melee unit's footprint occupancy-cap byte as the
    // layer selector for the cell->world conversion (preserved 1:1).
    const Wm3::Vec3f worldPosition = COORDS_ToWorldPos(
      mapData,
      cell,
      static_cast<ELayer>(static_cast<std::uint8_t>(meleeFootprint.mOccupancyCaps)),
      meleeFootprint.mSizeX,
      meleeFootprint.mSizeZ
    );

    const Wm3::Vec3f& warpTargetPosition = target->GetPosition();
    const Wm3::Vec3f toTarget{
      warpTargetPosition.x - worldPosition.x,
      warpTargetPosition.y - worldPosition.y,
      warpTargetPosition.z - worldPosition.z,
    };
    // 0x006CE175: `NormalizeVectorInto` (0x0044F7E0) -- zero only at length 0,
    // no Wm3 1e-6 tolerance.
    Wm3::Vector3f facingDirection{};
    (void)moho::NormalizeVectorInto(&facingDirection, toTarget);

    const Wm3::Quaternionf orientation = COORDS_Orient(facingDirection);
    const VTransform warpTransform(worldPosition, orientation);
    meleeUnit->Warp(warpTransform);
  }

  return 0;
}

/**
 * Address: 0x006CDED0 (FUN_006CDED0, cfunc_UnitMeleeWarpAdjacentToTarget)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitMeleeWarpAdjacentToTargetL`.
 */
int moho::cfunc_UnitMeleeWarpAdjacentToTarget(lua_State* const luaContext)
{
  return cfunc_UnitMeleeWarpAdjacentToTargetL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CDEF0 (FUN_006CDEF0, func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:MeleeWarpAdjacentToTarget(target)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitMeleeWarpAdjacentToTarget_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitMeleeWarpAdjacentToTargetName,
    &moho::cfunc_UnitMeleeWarpAdjacentToTarget,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitMeleeWarpAdjacentToTargetHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CE4A0 (FUN_006CE4A0, cfunc_UnitPrintCommandQueueL)
 *
 * What it does:
 * Logs one textual dump of the unit command queue into AI debug output.
 */
int moho::cfunc_UnitPrintCommandQueueL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitPrintCommandQueueHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  if (unit == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidUnitError);
    return 0;
  }

  const CUnitCommandQueue* const commandQueue = unit->CommandQueue;
  if (commandQueue == nullptr) {
    LuaPlus::LuaState::Error(state, kUnitGetCommandQueueInvalidQueueError);
    return 0;
  }

  const fa::vector<WeakPtr<CUnitCommand>> commandSnapshot = commandQueue->mCommandVec;

  const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
  const char* const unitName = (unitBlueprint != nullptr) ? unitBlueprint->mBlueprintId.c_str() : "";
  gpg::Logf(kUnitPrintCommandQueueHeaderLogFormat, unitName);

  for (const WeakPtr<CUnitCommand>& commandWeakPtr : commandSnapshot) {
    CUnitCommand* const command = commandWeakPtr.GetObjectPtr();
    if (command == nullptr) {
      continue;
    }

    const std::string commandLabel = BuildPrintCommandQueueLabel(*command);
    gpg::Logf(kUnitPrintCommandQueueEntryLogFormat, commandLabel.c_str());
  }

  return 1;
}

/**
 * Address: 0x006CE420 (FUN_006CE420, cfunc_UnitPrintCommandQueue)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitPrintCommandQueueL`.
 */
int moho::cfunc_UnitPrintCommandQueue(lua_State* const luaContext)
{
  return cfunc_UnitPrintCommandQueueL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CE440 (FUN_006CE440, func_UnitPrintCommandQueue_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:PrintCommandQueue()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitPrintCommandQueue_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitPrintCommandQueueName,
    &moho::cfunc_UnitPrintCommandQueue,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitPrintCommandQueueHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CED40 (FUN_006CED40, cfunc_UnitGiveNukeSiloAmmoL)
 *
 * What it does:
 * Adds nuke ammo to a unit silo, or sets current segment count when called
 * with three Lua arguments.
 */
int moho::cfunc_UnitGiveNukeSiloAmmoL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  bool setSegmentAmount = false;
  if (argumentCount != 2) {
    if (argumentCount == 3) {
      setSegmentAmount = true;
    } else {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUnitGiveNukeSiloAmmoHelpText, 2, argumentCount);
    }
  }

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      const LuaPlus::LuaStackObject amountObject(state, 2);
      const int amount = amountObject.GetInteger();
      if (setSegmentAmount) {
        // FAF hot-patch: 0x006CED74 jumps to 0x0128E955 in .exxt, which accepts
        // 2 or 3 arguments and latches "3 arguments" in a global (0x012934CC);
        // 0x006CEDF1 jumps to 0x0128E97B, which on that latch stores
        // `cvtsi2ss` of the amount into the float `mCurSegments` (+0x48)
        // instead of adjusting the nuke storage count.
        siloBuild->mCurSegments = static_cast<float>(amount);
      } else {
        siloBuild->SiloAdjustStorageCount(SILOTYPE_Nuke, amount);
      }
    }
  }

  return 0;
}

/**
 * Address: 0x006CECC0 (FUN_006CECC0, cfunc_UnitGiveNukeSiloAmmo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitGiveNukeSiloAmmoL`.
 */
int moho::cfunc_UnitGiveNukeSiloAmmo(lua_State* const luaContext)
{
  return cfunc_UnitGiveNukeSiloAmmoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CECE0 (FUN_006CECE0, func_UnitGiveNukeSiloAmmo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GiveNukeSiloAmmo(num)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGiveNukeSiloAmmo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGiveNukeSiloAmmoName,
    &moho::cfunc_UnitGiveNukeSiloAmmo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGiveNukeSiloAmmoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CF150 (FUN_006CF150, cfunc_UnitGiveTacticalSiloAmmoL)
 *
 * What it does:
 * Adds tactical missile ammo amount to the unit silo storage lane.
 */
int moho::cfunc_UnitGiveTacticalSiloAmmoL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitGiveTacticalSiloAmmoHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (unit != nullptr) {
    if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
      const LuaPlus::LuaStackObject amountObject(state, 2);
      const int amount = amountObject.GetInteger();
      siloBuild->SiloAdjustStorageCount(SILOTYPE_Tactical, amount);
    }
  }

  return 0;
}

/**
 * Address: 0x006CF0D0 (FUN_006CF0D0, cfunc_UnitGiveTacticalSiloAmmo)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitGiveTacticalSiloAmmoL`.
 */
int moho::cfunc_UnitGiveTacticalSiloAmmo(lua_State* const luaContext)
{
  return cfunc_UnitGiveTacticalSiloAmmoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CF0F0 (FUN_006CF0F0, func_UnitGiveTacticalSiloAmmo_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:GiveTacticalSiloAmmo(num)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitGiveTacticalSiloAmmo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitGiveTacticalSiloAmmoName,
    &moho::cfunc_UnitGiveTacticalSiloAmmo,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitGiveTacticalSiloAmmoHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9330 (FUN_006C9330, cfunc_UnitRevertRegenRate)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitRevertRegenRateL`.
 */
int moho::cfunc_UnitRevertRegenRate(lua_State* const luaContext)
{
  return cfunc_UnitRevertRegenRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9350 (FUN_006C9350, func_UnitRevertRegenRate_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:RevertRegenRate()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRevertRegenRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRevertRegenRateName,
    &moho::cfunc_UnitRevertRegenRate,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRevertRegenRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C93B0 (FUN_006C93B0, cfunc_UnitRevertRegenRateL)
 *
 * What it does:
 * Restores `UnitAttributes::regenRate` from blueprint defense regen data.
 */
int moho::cfunc_UnitRevertRegenRateL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitRevertRegenRateHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  UnitAttributes& attributes = unit->GetAttributes();

  attributes.regenRate = attributes.blueprint->Defense.RegenRate;
  return 0;
}

/**
 * Address: 0x006CABF0 (FUN_006CABF0, cfunc_UnitRevertElevation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitRevertElevationL`.
 */
int moho::cfunc_UnitRevertElevation(lua_State* const luaContext)
{
  return cfunc_UnitRevertElevationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CAC10 (FUN_006CAC10, func_UnitRevertElevation_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:RevertElevation()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRevertElevation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRevertElevationName,
    &moho::cfunc_UnitRevertElevation,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRevertElevationHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CAC70 (FUN_006CAC70, cfunc_UnitRevertElevationL)
 *
 * What it does:
 * Restores `UnitAttributes::spawnElevationOffset` from blueprint physics
 * elevation data.
 */
int moho::cfunc_UnitRevertElevationL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitRevertElevationHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  UnitAttributes& attributes = unit->GetAttributes();

  attributes.spawnElevationOffset = attributes.blueprint->Physics.Elevation;
  return 0;
}

/**
 * Address: 0x006C6F00 (FUN_006C6F00, cfunc_UnitStopSiloBuildL)
 *
 * What it does:
 * Stops active silo build on the unit when a silo-build AI lane exists.
 */
int moho::cfunc_UnitStopSiloBuildL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitStopSiloBuildHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  if (CAiSiloBuildImpl* const siloBuild = unit->AiSiloBuild; siloBuild != nullptr) {
    siloBuild->SiloStopBuild();
  }

  return 0;
}

/**
 * Address: 0x006C6E80 (FUN_006C6E80, cfunc_UnitStopSiloBuild)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitStopSiloBuildL`.
 */
int moho::cfunc_UnitStopSiloBuild(lua_State* const luaContext)
{
  return cfunc_UnitStopSiloBuildL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C6EA0 (FUN_006C6EA0, func_UnitStopSiloBuild_LuaFuncDef)
 *
 * What it does:
 * Publishes the `StopSiloBuild(unit)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitStopSiloBuild_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitStopSiloBuildName,
    &moho::cfunc_UnitStopSiloBuild,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitStopSiloBuildHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8400 (FUN_006C8400, cfunc_UnitRestoreBuildRestrictions)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRestoreBuildRestrictionsL`.
 */
int moho::cfunc_UnitRestoreBuildRestrictions(lua_State* const luaContext)
{
  return cfunc_UnitRestoreBuildRestrictionsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8420 (FUN_006C8420, func_UnitRestoreBuildRestrictions_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RestoreBuildRestrictions()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRestoreBuildRestrictions_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRestoreBuildRestrictionsName,
    &moho::cfunc_UnitRestoreBuildRestrictions,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRestoreBuildRestrictionsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8480 (FUN_006C8480, cfunc_UnitRestoreBuildRestrictionsL)
 *
 * What it does:
 * Clears one unit build-restriction set back to empty/default state.
 */
int moho::cfunc_UnitRestoreBuildRestrictionsL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitRestoreBuildRestrictionsHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  EntityCategorySet& restrictionWords = unit->GetAttributes().restrictionCategory;
  restrictionWords.mBits = BVIntSet{};
  unit->mVarDat.mRequestRefreshUI = 1;
  return 0;
}

/**
 * Address: 0x006C8920 (FUN_006C8920, cfunc_UnitRestoreCommandCapsL)
 *
 * What it does:
 * Restores runtime command capability mask from the owning unit blueprint.
 */
int moho::cfunc_UnitRestoreCommandCapsL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitRestoreCommandCapsHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  unit->GetAttributes().commandCapsMask = static_cast<std::uint32_t>(blueprint->General.CommandCaps);
  unit->mVarDat.mRequestRefreshUI = 1;
  return 0;
}

/**
 * Address: 0x006C88A0 (FUN_006C88A0, cfunc_UnitRestoreCommandCaps)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRestoreCommandCapsL`.
 */
int moho::cfunc_UnitRestoreCommandCaps(lua_State* const luaContext)
{
  return cfunc_UnitRestoreCommandCapsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C88C0 (FUN_006C88C0, func_UnitRestoreCommandCaps_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RestoreCommandCaps()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRestoreCommandCaps_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRestoreCommandCapsName,
    &moho::cfunc_UnitRestoreCommandCaps,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRestoreCommandCapsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8F40 (FUN_006C8F40, cfunc_UnitRestoreToggleCapsL)
 *
 * What it does:
 * Restores runtime toggle capability mask from the owning unit blueprint.
 */
int moho::cfunc_UnitRestoreToggleCapsL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitRestoreToggleCapsHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  unit->GetAttributes().toggleCapsMask = static_cast<std::uint32_t>(blueprint->General.ToggleCaps);
  unit->mVarDat.mRequestRefreshUI = 1;
  return 0;
}

/**
 * Address: 0x006C8EC0 (FUN_006C8EC0, cfunc_UnitRestoreToggleCaps)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRestoreToggleCapsL`.
 */
int moho::cfunc_UnitRestoreToggleCaps(lua_State* const luaContext)
{
  return cfunc_UnitRestoreToggleCapsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8EE0 (FUN_006C8EE0, func_UnitRestoreToggleCaps_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RestoreToggleCaps()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRestoreToggleCaps_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRestoreToggleCapsName,
    &moho::cfunc_UnitRestoreToggleCaps,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRestoreToggleCapsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C8A60 (FUN_006C8A60, cfunc_UnitTestCommandCapsL)
 *
 * What it does:
 * Resolves `(unit, commandCapName)` and returns whether the corresponding
 * blueprint capability bit is present.
 *
 * Note:
 * Binary lane tests `RUnitBlueprintGeneral::CommandCaps` at bp+0x17C
 * (`test [eax+17Ch], ecx` at 0x006C8B48).
 */
int moho::cfunc_UnitTestCommandCapsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitTestCommandCapsHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitCommandCaps commandCap = RULEUCC_None;
  gpg::RRef enumRef = MakeRuleUnitCommandCapsRef(&commandCap);
  const LuaPlus::LuaStackObject commandCapArg(state, 2);
  const char* const commandCapName = lua_tostring(rawState, 2);
  if (commandCapName == nullptr) {
    commandCapArg.TypeError("string");
  }
  SCR_GetEnum(state, commandCapName, enumRef);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  const bool hasCapability =
    (static_cast<std::uint32_t>(blueprint->General.CommandCaps) & static_cast<std::uint32_t>(commandCap)) != 0u;
  lua_pushboolean(rawState, hasCapability ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C89E0 (FUN_006C89E0, cfunc_UnitTestCommandCaps)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitTestCommandCapsL`.
 */
int moho::cfunc_UnitTestCommandCaps(lua_State* const luaContext)
{
  return cfunc_UnitTestCommandCapsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C8A00 (FUN_006C8A00, func_UnitTestCommandCaps_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:TestCommandCaps(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitTestCommandCaps_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitTestCommandCapsName,
    &moho::cfunc_UnitTestCommandCaps,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTestCommandCapsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006C9080 (FUN_006C9080, cfunc_UnitTestToggleCapsL)
 *
 * What it does:
 * Resolves `(unit, toggleCapName)` and returns whether that toggle capability
 * bit is present in the owning blueprint.
 */
int moho::cfunc_UnitTestToggleCapsL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitTestToggleCapsHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  ERuleBPUnitToggleCaps toggleCap = static_cast<ERuleBPUnitToggleCaps>(0);
  gpg::RRef enumRef = MakeRuleUnitToggleCapsRef(&toggleCap);
  const LuaPlus::LuaStackObject toggleCapArg(state, 2);
  const char* const toggleCapName = lua_tostring(rawState, 2);
  if (toggleCapName == nullptr) {
    toggleCapArg.TypeError("string");
  }
  SCR_GetEnum(state, toggleCapName, enumRef);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  const bool hasCapability =
    (static_cast<std::uint32_t>(blueprint->General.ToggleCaps) & static_cast<std::uint32_t>(toggleCap)) != 0u;
  lua_pushboolean(rawState, hasCapability ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006C9000 (FUN_006C9000, cfunc_UnitTestToggleCaps)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitTestToggleCapsL`.
 */
int moho::cfunc_UnitTestToggleCaps(lua_State* const luaContext)
{
  return cfunc_UnitTestToggleCapsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006C9020 (FUN_006C9020, func_UnitTestToggleCaps_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:TestToggleCaps(...)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitTestToggleCaps_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitTestToggleCapsName,
    &moho::cfunc_UnitTestToggleCaps,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTestToggleCapsHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB450 (FUN_006CB450, cfunc_UnitRevertCollisionShape)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitRevertCollisionShapeL`.
 */
int moho::cfunc_UnitRevertCollisionShape(lua_State* const luaContext)
{
  return cfunc_UnitRevertCollisionShapeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB470 (FUN_006CB470, func_UnitRevertCollisionShape_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:RevertCollisionShape()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRevertCollisionShape_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRevertCollisionShapeName,
    &moho::cfunc_UnitRevertCollisionShape,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRevertCollisionShapeHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB4D0 (FUN_006CB4D0, cfunc_UnitRevertCollisionShapeL)
 *
 * What it does:
 * Resolves one unit and restores entity collision shape from blueprint lanes.
 */
int moho::cfunc_UnitRevertCollisionShapeL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 1, kUnitRevertCollisionShapeHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);
  unit->Entity::RevertCollisionShape();
  return 0;
}

/**
 * Address: 0x006D1170 (FUN_006D1170, cfunc_UnitTransportHasSpaceFor)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitTransportHasSpaceForL`.
 */
int moho::cfunc_UnitTransportHasSpaceFor(lua_State* const luaContext)
{
  return cfunc_UnitTransportHasSpaceForL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1190 (FUN_006D1190, func_UnitTransportHasSpaceFor_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:TransportHasSpaceFor(target)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitTransportHasSpaceFor_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitTransportHasSpaceForName,
    &moho::cfunc_UnitTransportHasSpaceFor,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTransportHasSpaceForHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D11F0 (FUN_006D11F0, cfunc_UnitTransportHasSpaceForL)
 *
 * What it does:
 * Returns whether one transport unit can fit one target unit blueprint in
 * storage.
 */
int moho::cfunc_UnitTransportHasSpaceForL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kUnitTransportHasSpaceForHelpText);

  const LuaPlus::LuaObject transportUnitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const transportUnit = SCR_FromLua_Unit(transportUnitObject);
  const LuaPlus::LuaObject targetUnitObject(LuaPlus::LuaStackObject(state, 2));
  Unit* const targetUnit = SCR_FromLua_Unit(targetUnitObject);

  bool hasSpace = false;
  if (transportUnit != nullptr) {
    if (IAiTransport* const transport = transportUnit->AiTransport; transport != nullptr) {
      if (targetUnit != nullptr) {
        hasSpace = transport->TransportHasSpaceFor(targetUnit->GetBlueprint());
      }
    }
  }

  lua_pushboolean(rawState, hasSpace ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x006D1320 (FUN_006D1320, cfunc_UnitTransportHasAvailableStorage)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitTransportHasAvailableStorageL`.
 */
int moho::cfunc_UnitTransportHasAvailableStorage(lua_State* const luaContext)
{
  return cfunc_UnitTransportHasAvailableStorageL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D1340 (FUN_006D1340, func_UnitTransportHasAvailableStorage_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:TransportHasAvailableStorage()` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitTransportHasAvailableStorage_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitTransportHasAvailableStorageName,
    &moho::cfunc_UnitTransportHasAvailableStorage,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTransportHasAvailableStorageHelpText
  );
  return &binder;
}

/**
 * Address: 0x006D13A0 (FUN_006D13A0, cfunc_UnitTransportHasAvailableStorageL)
 *
 * What it does:
 * Returns whether a transport unit currently has free storage slots.
 */
int moho::cfunc_UnitTransportHasAvailableStorageL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 1, kUnitTransportHasAvailableStorageHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  bool hasAvailableStorage = false;
  if (unit != nullptr) {
    if (IAiTransport* const transport = unit->AiTransport; transport != nullptr) {
      hasAvailableStorage = transport->TransportHasAvailableStorage();
    }
  }

  lua_pushboolean(rawState, hasAvailableStorage ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005E8640 (FUN_005E8640, cfunc_UnitTransportDetachAllUnits)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_UnitTransportDetachAllUnitsL`.
 */
int moho::cfunc_UnitTransportDetachAllUnits(lua_State* const luaContext)
{
  return cfunc_UnitTransportDetachAllUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005E8660 (FUN_005E8660, func_UnitTransportDetachAllUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes `Unit:TransportDetachAllUnits(destroySomeUnits)` Lua binder
 * definition.
 */
CScrLuaInitForm* moho::func_UnitTransportDetachAllUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitTransportDetachAllUnitsName,
    &moho::cfunc_UnitTransportDetachAllUnits,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitTransportDetachAllUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x005E86C0 (FUN_005E86C0, cfunc_UnitTransportDetachAllUnitsL)
 *
 * What it does:
 * Validates `(self, destroySomeUnits)` and detaches all carried units from one
 * transport, throwing a Lua error when invoked on non-transport units.
 */
int moho::cfunc_UnitTransportDetachAllUnitsL(LuaPlus::LuaState* const state)
{
  moho::SCR_ExpectExactArgs(state, 2, kUnitTransportDetachAllUnitsHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject destroySomeUnitsArg(state, 2);
  const bool destroySomeUnits = destroySomeUnitsArg.GetBoolean();

  if (IAiTransport* const transport = unit->AiTransport; transport != nullptr) {
    transport->TransportDetachAllUnits(destroySomeUnits);
  } else {
    LuaPlus::LuaState::Error(state, kUnitTransportDetachAllUnitsTransportError);
  }

  return 0;
}

/**
 * Address: 0x006CB580 (FUN_006CB580, cfunc_UnitRecoilImpulse)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_UnitRecoilImpulseL`.
 */
int moho::cfunc_UnitRecoilImpulse(lua_State* const luaContext)
{
  return cfunc_UnitRecoilImpulseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CB5A0 (FUN_006CB5A0, func_UnitRecoilImpulse_LuaFuncDef)
 *
 * What it does:
 * Publishes the `Unit:RecoilImpulse(x, y, z)` Lua binder definition.
 */
CScrLuaInitForm* moho::func_UnitRecoilImpulse_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kUnitRecoilImpulseName,
    &moho::cfunc_UnitRecoilImpulse,
    &CScrLuaMetatableFactory<Unit>::Instance(),
    kUnitLuaClassName,
    kUnitRecoilImpulseHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CB600 (FUN_006CB600, cfunc_UnitRecoilImpulseL)
 *
 * What it does:
 * Applies one recoil impulse vector `(x,y,z)` to the target unit motion lane.
 */
int moho::cfunc_UnitRecoilImpulseL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 4, kUnitRecoilImpulseHelpText);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = SCR_FromLua_Unit(unitObject);

  const LuaPlus::LuaStackObject xArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    xArg.TypeError("number");
  }
  const float impulseX = static_cast<float>(lua_tonumber(rawState, 2));

  const LuaPlus::LuaStackObject yArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    yArg.TypeError("number");
  }
  const float impulseY = static_cast<float>(lua_tonumber(rawState, 3));

  const LuaPlus::LuaStackObject zArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    zArg.TypeError("number");
  }
  const float impulseZ = static_cast<float>(lua_tonumber(rawState, 4));

  const Wm3::Vector3f impulse{impulseX, impulseY, impulseZ};
  if (CUnitMotion* const motion = unit->UnitMotion; motion != nullptr) {
    motion->AddRecoilImpulse(impulse);
  }

  return 0;
}
namespace moho
{

/**
 * Address: 0x006CCE70 (FUN_006CCE70, cfunc_NotifyUpgradeL)
 *
 * IDA signature:
 * int __cdecl cfunc_NotifyUpgradeL(LuaPlus::LuaState* state);
 *
 * What it does:
 * Global Lua `NotifyUpgrade(from,to)` worker: transfers command queue, builder
 * commands, platoon membership, repeat-queue state, health ratio, and
 * guarded/guard links from the source unit to the destination unit during an
 * upgrade, and queues an allied-upgrade sync notification.
 */
int cfunc_NotifyUpgradeL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 2, kNotifyUpgradeHelpText);

  Unit* source = nullptr;
  {
    const LuaPlus::LuaObject sourceObject(LuaPlus::LuaStackObject(state, 1));
    source = GetUnitOptional(sourceObject);
  }
  Unit* dest = nullptr;
  {
    const LuaPlus::LuaObject destObject(LuaPlus::LuaStackObject(state, 2));
    dest = GetUnitOptional(destObject);
  }

  if (source == nullptr || source->IsDead() || source->CommandQueue == nullptr) {
    LuaPlus::LuaState::Error(state, "Passed in invalid source object to upgrade");
  } else if (dest == nullptr || dest->IsDead() || dest->CommandQueue == nullptr) {
    LuaPlus::LuaState::Error(state, "Passed in invalid destination object to upgrade");
  }

  // 1) Command-queue transfer: copy every source command onto the destination,
  //    skipping the upgrade command that produced `dest`. The copied weak-ptr
  //    vector unlinks + frees on scope exit (matches the binary's manual cleanup).
  if (CUnitCommandQueue* const sourceQueue = source->CommandQueue) {
    const fa::vector<WeakPtr<CUnitCommand>> commandsSnapshot = sourceQueue->mCommandVec;
    const RUnitBlueprint* const destBlueprint = dest->GetBlueprint();
    for (const WeakPtr<CUnitCommand>& weakCommand : commandsSnapshot) {
      CUnitCommand* const command = weakCommand.GetObjectPtr();
      const bool isUpgradeToDest =
        command != nullptr &&
        command->mVarDat.mCmdType == EUnitCommandType::UNITCOMMAND_Upgrade &&
        command->mConstDat.blueprint == reinterpret_cast<const REntityBlueprint*>(destBlueprint);
      if (!isUpgradeToDest) {
        dest->CommandQueue->AddCommandToQueue(command);
      }
    }
  }

  // 2) Builder factory-command transfer.
  if (source->AiBuilder != nullptr && dest->AiBuilder != nullptr) {
    dest->AiBuilder->BuilderClearFactoryCommandQueue();
    const fa::vector<WeakPtr<CUnitCommand>>& builderCommands = source->AiBuilder->BuilderGetFactoryCommandQueue();
    for (std::size_t i = 0; i < builderCommands.size(); ++i) {
      CUnitCommand* const builderCommand = source->AiBuilder->BuilderGetFactoryCommand(static_cast<int>(i));
      if (builderCommand != nullptr) {
        dest->AiBuilder->BuilderAddFactoryCommand(builderCommand, -1);
      }
    }
  }

  // 3) Platoon membership transfer.
  if (CArmyImpl* const army = source->ArmyRef) {
    ESquadClass squadClass{};
    CPlatoon* const destPlatoon = army->GetPlatoonFor(dest, &squadClass);
    if (destPlatoon != nullptr) {
      destPlatoon->RemoveUnit(dest);
    }
    CPlatoon* const sourcePlatoon = army->GetPlatoonFor(source, &squadClass);
    if (sourcePlatoon != nullptr) {
      sourcePlatoon->RemoveUnit(source);
      sourcePlatoon->AppendUnitToSquad(squadClass, dest);
    }
  }

  // 4) Repeat-queue state transfer + OnStart/OnStopRepeatQueue script dispatch.
  const bool sourceRepeat = source->mUnitVarDat.mRepeatQueue;
  if (sourceRepeat) {
    if (!dest->mUnitVarDat.mRepeatQueue) {
      dest->RunScript("OnStartRepeatQueue");
    }
  } else if (dest->mUnitVarDat.mRepeatQueue) {
    dest->RunScript("OnStopRepeatQueue");
  }
  dest->mUnitVarDat.mRepeatQueue = sourceRepeat;
  dest->mVarDat.mRequestRefreshUI = 1;

  // 5) Health ratio transfer.
  const float scaledHealth = dest->mVarDat.mMaxHealth * (source->mVarDat.mHealth / source->mVarDat.mMaxHealth);
  if (scaledHealth != dest->mVarDat.mHealth) {
    dest->SetHealth(scaledHealth);
  }

  // 6) Guarded-unit + guard-list transfer.
  dest->SetGuardedUnit(source->GuardedUnitRef.GetObjectPtr());
  dest->GuardedPos = source->GuardedPos;

  // Snapshot the guard slots first: SetGuardedUnit mutates source->GuardedByList.
  fa::vector<Unit*> guards;
  for (Entity* const entry : source->GuardedByList.mVec) {
    guards.push_back(static_cast<Unit*>(entry));
  }
  for (Unit* const guard : guards) {
    if (guard != nullptr) {
      guard->SetGuardedUnit(dest);
    }
  }

  // 7) Allied-upgrade notification: record (from,to) ids in the Sim sync lane.
  Sim* const globalUserdata = lua_getglobaluserdata_typed(rawState);
  if (dest->ArmyRef->mVarDat.mIsAlly != 0 && globalUserdata != nullptr) {
    const SUpgradeNotifyPair pair{
      static_cast<std::int32_t>(source->GetEntityId()),
      static_cast<std::int32_t>(dest->GetEntityId())
    };
    // push_back's capacity-full path is `fa::vector<SUpgradeNotifyPair>::insert`
    // (FUN_006D1A90), reached through the binary's push_back (FUN_006D1960).
    globalUserdata->mAllyUpgradeNotifications.push_back(pair);
  }

  return 0;
}

/**
 * Address: 0x006CCDF0 (FUN_006CCDF0, cfunc_NotifyUpgrade)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to `cfunc_NotifyUpgradeL`.
 */
int cfunc_NotifyUpgrade(lua_State* const luaContext)
{
  return cfunc_NotifyUpgradeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CCE10 (FUN_006CCE10, func_NotifyUpgrade_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `NotifyUpgrade(from,to)` Lua binder and links it into the
 * sim script init form set.
 */
void func_NotifyUpgrade_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kNotifyUpgradeName,
    &moho::cfunc_NotifyUpgrade,
    nullptr,
    kNotifyUpgradeGlobalClassName,
    kNotifyUpgradeHelpText
  );
  (void)binder;
}

/**
 * Address: 0x006D0080 (FUN_006D0080, cfunc_CreateUnit2L)
 *
 * IDA signature:
 * int __usercall cfunc_CreateUnit2L@<eax>(LuaPlus::LuaState* a1@<edi>);
 *
 * What it does:
 * Global Lua `CreateUnit2(blueprint, army, layer, x, z, heading)` worker. Validates
 * six arguments, resolves the unit blueprint from arg1, the owning army from the
 * 1-based index in arg2, and the movement layer from arg3. Positions the spawn at
 * (x, 0, z) with a yaw quaternion built from the heading (degrees), spawns the unit
 * through the sim, and pushes the created unit's script object back to Lua.
 */
int cfunc_CreateUnit2L(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 6, kCreateUnit2HelpText);

  Sim* const sim = lua_getglobaluserdata_typed(rawState);

  // arg1: blueprint id (string) -> resolve blueprint.
  const LuaPlus::LuaStackObject blueprintArg(state, 1);
  const char* blueprintText = lua_tostring(rawState, 1);
  if (!blueprintText) {
    blueprintArg.TypeError("string");
    blueprintText = "";
  }
  RResId blueprintId{};
  gpg::STR_InitFilename(&blueprintId.name, blueprintText);
  const RUnitBlueprint* const blueprint = sim->mRules->GetUnitBlueprint(blueprintId);
  if (!blueprint) {
    LuaPlus::LuaState::Error(state, "Unknown unit blueprint id: %s", blueprintText);
  }

  // arg2: owning army, 1-based index into the sim army list.
  const LuaPlus::LuaStackObject armyArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    armyArg.TypeError("integer");
  }
  const int armyIndex = static_cast<int>(lua_tonumber(rawState, 2));
  const int armyCount = static_cast<int>(sim->mArmiesList.size());
  if (armyIndex < 1 || armyIndex > armyCount) {
    LuaPlus::LuaState::Error(state, "Invalid army index; must be >= 1 and < %d but got %d.", armyCount, armyIndex);
  }
  CArmyImpl* const army = sim->mArmiesList[armyIndex - 1];

  // arg3: movement layer (string).
  const LuaPlus::LuaStackObject layerArg(state, 3);
  const char* layerText = lua_tostring(rawState, 3);
  if (!layerText) {
    layerArg.TypeError("string");
    layerText = "";
  }
  const ELayer layer = COORDS_StringToLayer(layerText);

  // arg5 (z) is validated/read before arg4 (x), matching the binary's read order.
  const LuaPlus::LuaStackObject zArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    zArg.TypeError("number");
  }
  const float posZ = static_cast<float>(lua_tonumber(rawState, 5));

  const LuaPlus::LuaStackObject xArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    xArg.TypeError("number");
  }
  const float posX = static_cast<float>(lua_tonumber(rawState, 4));

  // arg6: heading in degrees -> half-angle yaw quaternion about the world Y axis.
  const LuaPlus::LuaStackObject headingArg(state, 6);
  if (lua_type(rawState, 6) != LUA_TNUMBER) {
    headingArg.TypeError("number");
  }
  // 0x006D0349-0x006D0358: `fmul 0.017453292f` then `fmul 0.5f` on the float
  // lua_Number, single-precision under the sim's `_PC_24` word.
  const float halfAngle = (static_cast<float>(lua_tonumber(rawState, 6)) * 0.017453292f) * 0.5f;
  const float sinHalfAngle = fa::sin(halfAngle);
  const float cosHalfAngle = fa::cos(halfAngle);

  // 0x006D0381-0x006D03A1: the x and z lanes are `sinH * 0.0f`, not literal
  // zeros, so a negative heading leaves them -0.0f.
  const VTransform transform(
    Wm3::Vector3f(posX, 0.0f, posZ),
    Wm3::Quatf(cosHalfAngle, sinHalfAngle * 0.0f, sinHalfAngle, sinHalfAngle * 0.0f)
  );

  // The binary sets the payload fields inline (an inlined SUnitConstructionParams
  // ctor) then forces mFixElevation = 0; the ctor call below yields the identical
  // final payload (mUseLayerOverride = 1 comes from the ctor, elevation is cleared).
  SUnitConstructionParams params(static_cast<std::int32_t>(layer), transform, army, blueprint, nullptr, true);
  params.mFixElevation = 0;

  Unit* const unit = sim->CreateUnitForScript(params, true);
  unit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006D0000 (FUN_006D0000, cfunc_CreateUnit2)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to `cfunc_CreateUnit2L`.
 */
int cfunc_CreateUnit2(lua_State* const luaContext)
{
  return cfunc_CreateUnit2L(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006D0020 (FUN_006D0020, func_CreateUnit2_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `CreateUnit2(blueprint, army, layer, x, z, heading)` Lua
 * binder and links it into the sim script init form set.
 */
CScrLuaInitForm* func_CreateUnit2_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kCreateUnit2Name,
    &moho::cfunc_CreateUnit2,
    nullptr,
    kCreateUnit2GlobalClassName,
    kCreateUnit2HelpText
  );
  return &binder;
}

/**
 * Address: 0x006CF560 (FUN_006CF560, cfunc_CreateUnitL)
 *
 * IDA signature:
 * int __usercall cfunc_CreateUnitL@<eax>(LuaPlus::LuaState* a1@<edi>);
 *
 * What it does:
 * Global Lua `CreateUnit(blueprint, army, tx, ty, tz, qx, qy, qz, qw, [layer])`
 * worker. Validates 9-10 args, resolves the blueprint (arg1) and owning army
 * (arg2, 1-based). Reads the spawn position and orientation quaternion, rejects a
 * bit-zero quaternion (substituting identity + a warning), resolves the optional
 * layer string, spawns the unit through the sim, and pushes its script object.
 *
 * Numeric arguments are read right-to-left, while the constructed position
 * retains the Lua API's x, y, z order.
 */
int cfunc_CreateUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 9 || argumentCount > 10) {
    LuaPlus::LuaState::Error(
      state, "%s\n  expected between %d and %d args, but got %d", kCreateUnitHelpText, 9, 10, argumentCount);
  }

  Sim* const sim = lua_getglobaluserdata_typed(rawState);
  lua_settop(rawState, 10);

  // arg1: blueprint id (string) -> resolve blueprint.
  const LuaPlus::LuaStackObject blueprintArg(state, 1);
  const char* blueprintText = lua_tostring(rawState, 1);
  if (!blueprintText) {
    blueprintArg.TypeError("string");
    blueprintText = "";
  }
  RResId blueprintId{};
  gpg::STR_InitFilename(&blueprintId.name, blueprintText);
  const RUnitBlueprint* const blueprint = sim->mRules->GetUnitBlueprint(blueprintId);
  if (!blueprint) {
    LuaPlus::LuaState::Error(state, "Unknown unit kind: %s", blueprintText);
  }

  // arg2: owning army, 1-based index into the sim army list.
  const LuaPlus::LuaStackObject armyArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    armyArg.TypeError("integer");
  }
  const int armyIndex = static_cast<int>(lua_tonumber(rawState, 2));
  const int armyCount = static_cast<int>(sim->mArmiesList.size());
  if (armyIndex < 1 || armyIndex > armyCount) {
    LuaPlus::LuaState::Error(state, "Invalid army index; must be >= 1 and < %d but got %d.", armyCount, armyIndex);
  }

  // 0x006CF75C/0x006CF79D/0x006CF7DE read z, y, x. After the
  // outstanding Lua-call arguments are popped, 0x006CFA28..0x006CFA54
  // copy them to transform +0x10/+0x14/+0x18 as x, y, z.
  const LuaPlus::LuaStackObject vecZArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    vecZArg.TypeError("number");
  }
  const float vecZ = static_cast<float>(lua_tonumber(rawState, 5));
  const LuaPlus::LuaStackObject vecYArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    vecYArg.TypeError("number");
  }
  const float vecY = static_cast<float>(lua_tonumber(rawState, 4));
  const LuaPlus::LuaStackObject vecXArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    vecXArg.TypeError("number");
  }
  const float vecX = static_cast<float>(lua_tonumber(rawState, 3));

  // Orientation: the binary reads args 8, 7, 6 (qz, qy, qx) then 9 (qw).
  const LuaPlus::LuaStackObject quatZArg(state, 8);
  if (lua_type(rawState, 8) != LUA_TNUMBER) {
    quatZArg.TypeError("number");
  }
  const float quatZ = static_cast<float>(lua_tonumber(rawState, 8));
  const LuaPlus::LuaStackObject quatYArg(state, 7);
  if (lua_type(rawState, 7) != LUA_TNUMBER) {
    quatYArg.TypeError("number");
  }
  const float quatY = static_cast<float>(lua_tonumber(rawState, 7));
  const LuaPlus::LuaStackObject quatXArg(state, 6);
  if (lua_type(rawState, 6) != LUA_TNUMBER) {
    quatXArg.TypeError("number");
  }
  const float quatX = static_cast<float>(lua_tonumber(rawState, 6));
  const LuaPlus::LuaStackObject quatWArg(state, 9);
  if (lua_type(rawState, 9) != LUA_TNUMBER) {
    quatWArg.TypeError("number");
  }
  const float quatW = static_cast<float>(lua_tonumber(rawState, 9));

  Wm3::Quatf orient(quatW, quatX, quatY, quatZ); // (w, x, y, z)

  // A bit-zero quaternion is invalid; warn and substitute identity. Wm3::Quaternion::
  // Compare (FUN_004F0B40) is a raw 16-byte memcmp, so the rejection is bit-exact.
  static const Wm3::Quatf kZeroQuat(0.0f, 0.0f, 0.0f, 0.0f);
  if (std::memcmp(&orient, &kZeroQuat, sizeof(Wm3::Quatf)) == 0) {
    gpg::Warnf("Passed in an invalid quaternion when creating unit %s", blueprintText);
    orient = Wm3::Quatf(1.0f, 0.0f, 0.0f, 0.0f);
  }

  // Optional arg10: movement layer name (string). Absent -> layer 0.
  std::int32_t layer = 0;
  if (lua_type(rawState, 10) != 0 && lua_isstring(rawState, 10)) {
    const LuaPlus::LuaStackObject layerArg(state, 10);
    const char* layerText = lua_tostring(rawState, 10);
    if (!layerText) {
      layerArg.TypeError("string");
      layerText = "";
    }
    layer = static_cast<std::int32_t>(COORDS_StringToLayer(layerText));
  }

  CArmyImpl* const army = sim->mArmiesList[armyIndex - 1];

  const VTransform transform(Wm3::Vector3f(vecX, vecY, vecZ), orient);
  SUnitConstructionParams params(layer, transform, army, blueprint, nullptr, true);

  Unit* const unit = sim->CreateUnitForScript(params, true);
  if (!unit) {
    LuaPlus::LuaState::Error(state, "CreateUnit(%s) failed", blueprintText);
  }
  unit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006CF4E0 (FUN_006CF4E0, cfunc_CreateUnit)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to `cfunc_CreateUnitL`.
 */
int cfunc_CreateUnit(lua_State* const luaContext)
{
  return cfunc_CreateUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CF500 (FUN_006CF500, func_CreateUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `CreateUnit(...)` Lua binder and links it into the sim
 * script init form set.
 */
CScrLuaInitForm* func_CreateUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kCreateUnitName,
    &moho::cfunc_CreateUnit,
    nullptr,
    kCreateUnitGlobalClassName,
    kCreateUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x006CFB70 (FUN_006CFB70, cfunc_CreateUnitHPRL)
 *
 * IDA signature:
 * int __usercall cfunc_CreateUnitHPRL@<eax>(LuaPlus::LuaState* state@<edi>);
 *
 * What it does:
 * Global Lua `CreateUnitHPR(blueprint, army, x, y, z, pitch, yaw, roll)` worker.
 * Validates exactly 8 args, resolves the blueprint (arg1) and owning army (arg2,
 * a Lua army object). Reads the spawn position (args 3,4,5 -> x,y,z) and the
 * heading/pitch/roll Euler angles (args 6,7,8), builds a row-major rotation matrix
 * and converts it to an orientation quaternion, spawns the unit through the sim,
 * and pushes its script object.
 */
int cfunc_CreateUnitHPRL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  moho::SCR_ExpectExactArgs(state, 8, kCreateUnitHPRHelpText);

  Sim* const sim = lua_getglobaluserdata_typed(rawState);

  // arg1: blueprint id (string) -> kept as an fa::string for the lookup + errors.
  const LuaPlus::LuaStackObject blueprintArg(state, 1);
  const char* blueprintText = lua_tostring(rawState, 1);
  if (!blueprintText) {
    blueprintArg.TypeError("string");
    blueprintText = "";
  }
  const fa::string blueprintName(blueprintText, std::strlen(blueprintText));

  // arg2: owning army as a Lua object (not a 1-based index).
  const LuaPlus::LuaObject armyObject(LuaPlus::LuaStackObject(state, 2));
  CArmyImpl* const army = ARMY_FromLuaState(state, armyObject);

  // Position: args 5, 4, 3 read in that order -> x, y, z (straight, no swap).
  const LuaPlus::LuaStackObject posZArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    posZArg.TypeError("number");
  }
  const float posZ = static_cast<float>(lua_tonumber(rawState, 5));
  const LuaPlus::LuaStackObject posYArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    posYArg.TypeError("number");
  }
  const float posY = static_cast<float>(lua_tonumber(rawState, 4));
  const LuaPlus::LuaStackObject posXArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    posXArg.TypeError("number");
  }
  const float posX = static_cast<float>(lua_tonumber(rawState, 3));

  // Orientation Euler angles: arg6 -> pitch, arg7 -> heading/yaw, arg8 -> roll.
  const LuaPlus::LuaStackObject pitchArg(state, 6);
  if (lua_type(rawState, 6) != LUA_TNUMBER) {
    pitchArg.TypeError("number");
  }
  const float pitch = static_cast<float>(lua_tonumber(rawState, 6));
  const LuaPlus::LuaStackObject headingArg(state, 7);
  if (lua_type(rawState, 7) != LUA_TNUMBER) {
    headingArg.TypeError("number");
  }
  const float heading = static_cast<float>(lua_tonumber(rawState, 7));
  const LuaPlus::LuaStackObject rollArg(state, 8);
  if (lua_type(rawState, 8) != LUA_TNUMBER) {
    rollArg.TypeError("number");
  }
  const float roll = static_cast<float>(lua_tonumber(rawState, 8));

  // Blueprint lookup happens after all numeric args, matching the binary.
  RResId blueprintId{};
  gpg::STR_CopyFilename(&blueprintId.name, &blueprintName);
  const RUnitBlueprint* const blueprint = sim->mRules->GetUnitBlueprint(blueprintId);
  if (!blueprint) {
    LuaPlus::LuaState::Error(state, "Unknown unit type: %s", blueprintName.c_str());
  }

  // Euler HPR -> row-major 3x3 rotation matrix -> orientation quaternion.
  Wm3::Vector3f rotationRows[3];
  BuildRotationMatrixFromEulerHPR(rotationRows, heading, pitch, roll);
  Wm3::Quaternionf orient;
  MatrixRowsToQuatCanonical(rotationRows, &orient);

  const VTransform transform(Wm3::Vector3f(posX, posY, posZ), orient);
  SUnitConstructionParams params(0, transform, army, blueprint, nullptr, true);

  Unit* const unit = sim->CreateUnitForScript(params, true);
  if (!unit) {
    LuaPlus::LuaState::Error(state, "CreateUnitHPR(%s) failed", blueprintName.c_str());
  }

  unit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006CFAF0 (FUN_006CFAF0, cfunc_CreateUnitHPR)
 *
 * What it does:
 * Unwraps the Lua callback binding state and forwards to `cfunc_CreateUnitHPRL`.
 */
int cfunc_CreateUnitHPR(lua_State* const luaContext)
{
  return cfunc_CreateUnitHPRL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006CFB10 (FUN_006CFB10, func_CreateUnitHPR_LuaFuncDef)
 *
 * What it does:
 * Publishes the global `CreateUnitHPR(...)` Lua binder and links it into the sim
 * script init form set.
 */
CScrLuaInitForm* func_CreateUnitHPR_LuaFuncDef()
{
  static CScrLuaBinder binder(
    moho::SCR_SimLuaInitSet(),
    kCreateUnitHPRName,
    &moho::cfunc_CreateUnitHPR,
    nullptr,
    kCreateUnitHPRGlobalClassName,
    kCreateUnitHPRHelpText
  );
  return &binder;
}
}

