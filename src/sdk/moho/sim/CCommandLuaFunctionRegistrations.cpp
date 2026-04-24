#include "moho/sim/CCommandLuaFunctionRegistrations.h"

#include <bit>
#include <cstdint>
#include <cstring>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/UserEntity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/math/Vector3f.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/render/RangeRenderer.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/ui/IUIManager.h"

namespace moho
{
  class CUnitCommand;
  struct SSTICommandIssueData;
  struct SEntitySetTemplateUnit;
  class Sim;

  // Recovered child wrappers call these deeper callback lanes.
  int cfunc_UISelectionByCategoryL(LuaPlus::LuaState* state);
  int cfunc_UISelectAndZoomToL(LuaPlus::LuaState* state);
  int cfunc_UIZoomToL(LuaPlus::LuaState* state);

  [[nodiscard]] CUnitCommand* IssueCommandToSelectedUnits(
    Sim* sim,
    SEntitySetTemplateUnit& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    bool clearQueue
  );
} // namespace moho

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kInvalidUnitSetError = "Invalid unit set in %s; expected a table but got a %s";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";
  constexpr const char* kIsCommandDoneName = "IsCommandDone";
  constexpr const char* kIsCommandDoneHelpText = "IsCommandDone";
  constexpr const char* kIssueClearCommandsName = "IssueClearCommands";
  constexpr const char* kIssueClearCommandsHelpText = "IssueClearCommands";
  constexpr const char* kIssueStopName = "IssueStop";
  constexpr const char* kIssueStopHelpText = "IssueStop";
  constexpr const char* kIssuePauseName = "IssuePause";
  constexpr const char* kIssuePauseHelpText = "IssuePause";
  constexpr const char* kIssueOverChargeName = "IssueOverCharge";
  constexpr const char* kIssueOverChargeHelpText = "IssueOverCharge";
  constexpr const char* kIssueDiveName = "IssueDive";
  constexpr const char* kIssueDiveHelpText = "IssueDive";
  constexpr const char* kIssueFactoryRallyPointName = "IssueFactoryRallyPoint";
  constexpr const char* kIssueFactoryRallyPointHelpText = "IssueFactoryRallyPoint";
  constexpr const char* kIssueClearFactoryCommandsName = "IssueClearFactoryCommands";
  constexpr const char* kIssueClearFactoryCommandsHelpText = "IssueClearFactoryCommands";
  constexpr const char* kCoordinateAttacksName = "CoordinateAttacks";
  constexpr const char* kCoordinateAttacksHelpText = "CoordinateAttacks";
  constexpr const char* kDecreaseBuildCountInQueueName = "DecreaseBuildCountInQueue";
  constexpr const char* kDecreaseBuildCountInQueueHelpText = "DecreaseBuildCountInQueue(queueIndex, count)";
  constexpr const char* kGetUnitCommandDataName = "GetUnitCommandData";
  constexpr const char* kGetUnitCommandDataHelpText =
    "orders, buildableCategories, GetUnitCommandData(unitSet) -- given a set of units, gets the union of orders and "
    "unit categories (for determining builds)";
  constexpr const char* kIssueDockCommandName = "IssueDockCommand";
  constexpr const char* kIssueDockCommandHelpText = "IssueDockCommand(clear)";
  constexpr const char* kIssueCommandName = "IssueCommand";
  constexpr const char* kIssueCommandHelpText = "IssueCommand(command,[string],[clear])";
  constexpr const char* kIssueUnitCommandName = "IssueUnitCommand";
  constexpr const char* kIssueUnitCommandHelpText = "IssueUnitCommand(unitList,command,[string],[clear])";
  constexpr const char* kIssueBlueprintCommandName = "IssueBlueprintCommand";
  constexpr const char* kIssueBlueprintCommandHelpText =
    "IssueBlueprintCommand(command, blueprintid, count, clear = false)";
  constexpr const char* kGetRolloverInfoName = "GetRolloverInfo";
  constexpr const char* kGetRolloverInfoHelpText = "rolloverInfo GetRolloverInfo()";
  constexpr const char* kUISelectionByCategoryName = "UISelectionByCategory";
  constexpr const char* kUISelectionByCategoryHelpText =
    "UISelectionByCategory(expression, addToCurSel, inViewFrustum, nearestToMouse, mustBeIdle) - selects units based "
    "on a category expression";
  constexpr const char* kUISelectAndZoomToName = "UISelectAndZoomTo";
  constexpr const char* kUISelectAndZoomToHelpText = "UISelectAndZoomTo(userunit,[seconds])";
  constexpr const char* kUIZoomToName = "UIZoomTo";
  constexpr const char* kUIZoomToHelpText = "UIZoomTo(units,[seconds])";
  constexpr const char* kSetOverlayFilterName = "SetOverlayFilter";
  constexpr const char* kSetOverlayFilterHelpText = "SetOverlayFilter()";
  constexpr const char* kGetActiveBuildTemplateName = "GetActiveBuildTemplate";
  constexpr const char* kGetActiveBuildTemplateHelpText = "get active build template back to lua.";
  constexpr const char* kSetActiveBuildTemplateName = "SetActiveBuildTemplate";
  constexpr const char* kSetActiveBuildTemplateHelpText = "set this as an active build template.";
  constexpr const char* kOpenURLName = "OpenURL";
  constexpr const char* kOpenURLHelpText =
    "OpenURL(string) - open the default browser window to the specified URL";
  constexpr const char* kSetCursorName = "SetCursor";
  constexpr const char* kSetCursorHelpText = "SetCursor(cursor)";
  constexpr const char* kIssueSiloBuildTacticalHelpText = "IssueSiloBuildTactical";
  constexpr const char* kIssueSiloBuildNukeHelpText = "IssueSiloBuildNuke";
  constexpr const char* kIssueMoveOffFactoryHelpText = "IssueMoveOffFactory";
  constexpr const char* kIssueFormMoveHelpText = "IssueFormMove";
  constexpr const char* kIssueAggressiveMoveHelpText = "IssueAggressiveMove";
  constexpr const char* kIssueFormAggressiveMoveHelpText = "IssueFormAggressiveMove";
  constexpr const char* kIssueFormAttackHelpText = "IssueFormAttack";
  constexpr const char* kIssueFormPatrolHelpText = "IssueFormPatrol";
  constexpr const char* kIssueTransportLoadHelpText = "IssueTransportLoad";
  constexpr const char* kIssueGuardHelpText = "IssueGuard";
  constexpr const char* kIssueAttackHelpText = "IssueAttack";
  constexpr const char* kIssuePatrolHelpText = "IssuePatrol";
  constexpr const char* kIssueFerryHelpText = "IssueFerry";
  constexpr const char* kIssueMoveOffFactoryInvalidTargetError = "IssueMoveOffFactory: Passed in an invalid target point.";
  constexpr const char* kIssueFormMoveInvalidTargetError = "IssueFormMove: Passed in an invalid target point.";
  // Binary string lane for FUN_006F3140 uses the same text as move-off-factory.
  constexpr const char* kIssueGuardInvalidTargetError = "IssueMoveOffFactory: Passed in an invalid target point.";
  constexpr const char* kIssuePatrolInvalidTargetError = "IssuePatrol: Passed in an invalid target point.";
  constexpr const char* kIssueFerryInvalidTargetError = "IssueFerry: Passed in an invalid target point.";
  constexpr const char* kIssueAggressiveMoveInvalidTargetError = "IssueAggressiveMove: Passed in an invalid target point.";
  constexpr const char* kIssueFormAggressiveMoveInvalidTargetError =
    "IssueFormAggressiveMove: Passed in an invalid target point.";
  constexpr const char* kIssueFormAttackInvalidTargetError = "IssueFormAttack: Passed in an invalid target point.";
  constexpr const char* kIssueFormPatrolInvalidTargetError = "IssueFormPatrol: Passed in an invalid target point.";
  constexpr const char* kIssueTransportLoadAttachedError =
    "IssueTransportLoad: One or more units are already attached to something.";
  constexpr const char* kIssueTransportLoadNoUnitsError = "IssueTransportLoad: Couldn't find any units to load.";
  constexpr float kDegreesToRadians = 0.017453292f;
  constexpr const char* kIssueTransportUnloadSpecificHelpText = "IssueTransportUnloadSpecific";
  constexpr std::int32_t kGroundTargetEntitySentinel = -0x10000000;

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] gpg::RType* CachedUnitType()
  {
    static gpg::RType* cachedType = nullptr;
    if (cachedType == nullptr) {
      cachedType = gpg::LookupRType(typeid(moho::Unit));
    }
    return cachedType;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandType()
  {
    static gpg::RType* cachedType = nullptr;
    if (cachedType == nullptr) {
      cachedType = gpg::LookupRType(typeid(moho::CUnitCommand));
    }
    return cachedType;
  }

  [[nodiscard]] gpg::RRef ExtractUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int stackTop = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, stackTop);
    return out;
  }

  [[nodiscard]] moho::CScriptObject** ExtractScriptObjectSlot(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, moho::CScriptObject::GetPointerType());
    return static_cast<moho::CScriptObject**>(upcast.mObj);
  }

  [[nodiscard]] moho::Unit* GetUnitOptionalForIssue(const LuaPlus::LuaObject& unitObject, LuaPlus::LuaState* state)
  {
    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlot(unitObject);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUnitType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::Unit*>(upcast.mObj);
  }

  [[nodiscard]] moho::CUnitCommand* GetUnitCommandOptionalForIssue(
    const LuaPlus::LuaObject& commandObject,
    LuaPlus::LuaState* state
  )
  {
    moho::CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlot(commandObject);
    if (!scriptObjectSlot) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    moho::CScriptObject* const scriptObject = *scriptObjectSlot;
    if (!scriptObject) {
      return nullptr;
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedCUnitCommandType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<moho::CUnitCommand*>(upcast.mObj);
  }

  /**
   * Address: 0x006EEE40 (FUN_006EEE40, func_GetUnitList)
   *
   * What it does:
   * Reads one Lua unit-list table and collects only live `Unit*` entries into
   * the destination unit set.
   */
  void CollectLiveUnitsFromLuaTable(
    moho::UnitSet& outUnits,
    LuaPlus::LuaState* state,
    LuaPlus::LuaStackObject& listObjectArg,
    const char* helpText
  )
  {
    LuaPlus::LuaObject unitListObject(listObjectArg);
    if (!unitListObject.IsTable()) {
      const char* const unitListTypeName = unitListObject.TypeName();
      LuaPlus::LuaState::Error(state, kInvalidUnitSetError, helpText, unitListTypeName);
    }

    outUnits.Clear();
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = unitListObject[unitIndex];
      moho::Unit* const unit = GetUnitOptionalForIssue(unitObject, state);
      if (unit && !unit->IsDead()) {
        outUnits.Add(unit);
      }
    }
  }

  [[nodiscard]] moho::BVSet<moho::EntId, moho::EntIdUniverse> BuildSelectedEntitySetFromUnits(const moho::UnitSet& units)
  {
    moho::BVSet<moho::EntId, moho::EntIdUniverse> selectedUnits{};
    for (moho::Unit* const unit : units) {
      if (unit == nullptr) {
        continue;
      }

      (void)selectedUnits.mBits.Add(static_cast<unsigned int>(unit->id_));
    }
    return selectedUnits;
  }

  [[nodiscard]] moho::BVSet<moho::EntId, moho::EntIdUniverse>
    BuildSelectedEntitySetFromUserUnits(const msvc8::vector<moho::UserUnit*>& userUnits)
  {
    moho::BVSet<moho::EntId, moho::EntIdUniverse> selectedUnits{};
    for (moho::UserUnit* const unit : userUnits) {
      if (unit == nullptr) {
        continue;
      }

      const auto* const userEntity = reinterpret_cast<const moho::UserEntity*>(unit);
      (void)selectedUnits.mBits.Add(userEntity->mParams.mEntityId);
    }
    return selectedUnits;
  }

  [[nodiscard]] bool TryParseUnitCommandTypeLexical(
    const char* const lexicalCommandType,
    moho::EUnitCommandType& outCommandType
  )
  {
    if (lexicalCommandType == nullptr) {
      return false;
    }

    gpg::RRef commandTypeRef{};
    gpg::RRef_EUnitCommandType(&commandTypeRef, &outCommandType);
    return commandTypeRef.SetLexical(lexicalCommandType);
  }

  /**
   * Address: 0x006EEDB0 (FUN_006EEDB0, func_Filter_FactoryUnitsByCommandCap)
   *
   * IDA signature:
   * BOOL __usercall sub_6EEDB0@<eax>(int edi0@<edi>, Moho::EntitySetTemplate_Unit *a1, int a3);
   *
   * What it does:
   * Walks every live `Unit*` in `sourceUnits`, keeps only units whose blueprint
   * command-caps intersect `requiredCaps` AND whose `AiBuilder` reports
   * `BuilderIsFactory()`, and appends each survivor to `outFactoryUnits`.
   * Returns true when the destination set ends up non-empty.
   *
   * Used by `cfunc_IssueFactoryRallyPointL` (mask=`RULEUCC_Move`) and
   * `cfunc_IssueFactoryAssistL` (mask=`RULEUCC_Guard`) to pick only the
   * factories from the script-supplied unit list.
   */
  [[nodiscard]] bool FilterFactoryUnitsByCommandCap(
    const moho::UnitSet& sourceUnits,
    moho::SEntitySetTemplateUnit& outFactoryUnits,
    const std::uint32_t requiredCaps
  )
  {
    for (moho::Unit* const unit : sourceUnits) {
      if (unit == nullptr) {
        continue;
      }

      if ((unit->GetAttributes().commandCapsMask & requiredCaps) == 0u) {
        continue;
      }

      moho::IAiBuilder* const builder = unit->AiBuilder;
      if (builder == nullptr || !builder->BuilderIsFactory()) {
        continue;
      }

      (void)outFactoryUnits.AddUnit(unit);
    }

    return !outFactoryUnits.Empty();
  }

  /**
   * Address: 0x006EECF0 (FUN_006EECF0, func_Validate_IssueCommand)
   *
   * What it does:
   * Filters one source unit set by required command-cap mask, and applies the
   * factory mobility gate used by move/guard/patrol/ferry command lanes.
   */
  [[maybe_unused]] [[nodiscard]] bool ValidateIssueCommandUnits(
    const moho::UnitSet& sourceUnits,
    moho::UnitSet& outUnits,
    const moho::ERuleBPUnitCommandCaps requiredCaps
  )
  {
    outUnits.Clear();

    constexpr std::uint32_t kMoveGuardPatrolMask = static_cast<std::uint32_t>(moho::RULEUCC_Move)
                                                    | static_cast<std::uint32_t>(moho::RULEUCC_Guard)
                                                    | static_cast<std::uint32_t>(moho::RULEUCC_Patrol);
    constexpr std::uint32_t kFerryMask = static_cast<std::uint32_t>(moho::RULEUCC_Ferry);

    const std::uint32_t requestedMask = static_cast<std::uint32_t>(requiredCaps);
    const bool requiresFactoryMobilityGate = (requestedMask & (kMoveGuardPatrolMask | kFerryMask)) != 0u;

    for (moho::Unit* const unit : sourceUnits) {
      if (unit == nullptr) {
        continue;
      }

      if ((unit->GetAttributes().commandCapsMask & requestedMask) == 0u) {
        continue;
      }

      if (requiresFactoryMobilityGate) {
        moho::IAiBuilder* const builder = unit->AiBuilder;
        const bool isStationaryFactory = (builder != nullptr) && builder->BuilderIsFactory() && !unit->IsMobile();
        if (isStationaryFactory) {
          continue;
        }
      }

      (void)outUnits.Add(unit);
    }

    return !outUnits.Empty();
  }

  void IssueSimpleUnitCommand(
    moho::Sim* const sim,
    const moho::UnitSet& units,
    const moho::EUnitCommandType commandType
  )
  {
    if (sim == nullptr) {
      return;
    }

    const moho::BVSet<moho::EntId, moho::EntIdUniverse> selectedUnits = BuildSelectedEntitySetFromUnits(units);
    if (selectedUnits.mBits.Count() == 0) {
      return;
    }

    moho::SSTICommandIssueData commandIssueData(commandType);
    sim->IssueCommand(selectedUnits, commandIssueData, false);
  }

  [[nodiscard]] int ResolveFormationScriptIndex(
    moho::CAiFormationDBImpl* const formationDb,
    const char* const formationName,
    const moho::SEntitySetTemplateUnit& selectedUnits
  )
  {
    if (formationDb == nullptr || formationName == nullptr) {
      return -1;
    }

    const auto packedSelectionLane = static_cast<std::uint32_t>(
      reinterpret_cast<std::uintptr_t>(static_cast<const void*>(&selectedUnits))
    );
    const auto formationType = static_cast<moho::EFormationType>(packedSelectionLane);
    return formationDb->GetScriptIndex(formationName, formationType);
  }

  void PackFormCommandOrientationLanes(
    moho::SSTICommandIssueData& commandIssueData,
    const std::int32_t formationScriptIndex,
    const Wm3::Quatf& orientation
  )
  {
    const auto* const orientationLanes = reinterpret_cast<const float*>(&orientation);

    // FUN_006F2CE0 / FUN_006F5430 write the first three lanes at +0x24:
    // formation index + first two quaternion lanes.
    const std::uint32_t packedFormLanes[3] = {
      static_cast<std::uint32_t>(formationScriptIndex),
      std::bit_cast<std::uint32_t>(orientationLanes[0]),
      std::bit_cast<std::uint32_t>(orientationLanes[1]),
    };
    std::memcpy(&commandIssueData.mTarget2, packedFormLanes, sizeof(packedFormLanes));

    // The same binaries then overwrite the first three lanes at +0x3C:
    // remaining two quaternion lanes plus literal 1.0f.
    auto* const commandOriLanes = reinterpret_cast<float*>(&commandIssueData.mOri);
    commandOriLanes[0] = orientationLanes[2];
    commandOriLanes[1] = orientationLanes[3];
    commandOriLanes[2] = 1.0f;
  }

  int IssueFormCommandWithFormation(
    LuaPlus::LuaState* const state,
    const char* const helpText,
    const char* const invalidTargetError,
    const moho::EUnitCommandType commandType,
    const moho::ERuleBPUnitCommandCaps requiredCaps
  )
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, helpText, 4, argumentCount);
    }

    moho::UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, helpText);

    moho::UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, requiredCaps)) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    moho::Sim* const sim = lua_getglobaluserdata(rawState);
    if (sim == nullptr || sim->mFormationDB == nullptr) {
      return 0;
    }

    moho::SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    const LuaPlus::LuaStackObject formationNameArg(state, 3);
    const char* const formationName = lua_tostring(rawState, 3);
    if (formationName == nullptr) {
      formationNameArg.TypeError("string");
    }

    const int formationScriptIndex = ResolveFormationScriptIndex(sim->mFormationDB, formationName, selectedUnits);
    if (formationScriptIndex < 0) {
      return 0;
    }

    const LuaPlus::LuaStackObject rollArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      rollArg.TypeError("number");
    }
    const float rollRadians = static_cast<float>(lua_tonumber(rawState, 4)) * kDegreesToRadians;

    constexpr Wm3::Vector3f kYawAxis{0.0f, 1.0f, 0.0f};
    Wm3::Quatf orientation{};
    (void)moho::EulerRollToQuat(&kYawAxis, &orientation, rollRadians);

    moho::CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    moho::SCR_FromLuaCopy_CAiTarget(target, targetObject);
    if (!moho::IsValidVector3f(target.position) || target.targetType == moho::EAiTargetType::AITARGET_None) {
      LuaPlus::LuaState::Error(state, invalidTargetError);
    }

    moho::SSTICommandIssueData commandIssueData(commandType);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    PackFormCommandOrientationLanes(commandIssueData, formationScriptIndex, orientation);

    moho::CUnitCommand* const issuedCommand =
      moho::IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    if (issuedCommand == nullptr) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    issuedCommand->mArgs.PushStack(state);
    return 1;
  }

  int IssueFormCommandWithFormationNoResult(
    LuaPlus::LuaState* const state,
    const char* const helpText,
    const char* const invalidTargetError,
    const moho::EUnitCommandType commandType,
    const moho::ERuleBPUnitCommandCaps requiredCaps,
    const bool requireValidTargetVector
  )
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, helpText, 4, argumentCount);
    }

    moho::UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, helpText);

    moho::UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, requiredCaps)) {
      return 0;
    }

    moho::Sim* const sim = lua_getglobaluserdata(rawState);
    if (sim == nullptr || sim->mFormationDB == nullptr) {
      return 0;
    }

    moho::SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    const LuaPlus::LuaStackObject formationNameArg(state, 3);
    const char* const formationName = lua_tostring(rawState, 3);
    if (formationName == nullptr) {
      formationNameArg.TypeError("string");
    }

    const int formationScriptIndex = ResolveFormationScriptIndex(sim->mFormationDB, formationName, selectedUnits);
    if (formationScriptIndex < 0) {
      return 0;
    }

    const LuaPlus::LuaStackObject rollArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      rollArg.TypeError("number");
    }
    const float rollRadians = static_cast<float>(lua_tonumber(rawState, 4)) * kDegreesToRadians;

    constexpr Wm3::Vector3f kYawAxis{0.0f, 1.0f, 0.0f};
    Wm3::Quatf orientation{};
    (void)moho::EulerRollToQuat(&kYawAxis, &orientation, rollRadians);

    moho::CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    moho::SCR_FromLuaCopy_CAiTarget(target, targetObject);
    if (requireValidTargetVector
        && (!moho::IsValidVector3f(target.position) || target.targetType == moho::EAiTargetType::AITARGET_None)) {
      LuaPlus::LuaState::Error(state, invalidTargetError);
    }

    moho::SSTICommandIssueData commandIssueData(commandType);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    PackFormCommandOrientationLanes(commandIssueData, formationScriptIndex, orientation);
    (void)moho::IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  template <moho::CScrLuaInitForm* (*Target)()>
  [[nodiscard]] moho::CScrLuaInitForm* ForwardCommandLuaRegistrationThunk() noexcept
  {
    return Target();
  }
} // namespace

namespace moho
{
  int cfunc_IsCommandDone(lua_State* luaContext);
  int cfunc_IssueClearCommands(lua_State* luaContext);
  int cfunc_IssueStop(lua_State* luaContext);
  int cfunc_IssuePause(lua_State* luaContext);
  int cfunc_IssueMove(lua_State* luaContext);
  /**
   * Address: 0x006F2960 (FUN_006F2960, cfunc_IssueMoveOffFactory)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueMoveOffFactoryL`.
   */
  int cfunc_IssueMoveOffFactory(lua_State* luaContext);
  /**
   * Address: 0x006F2C70 (FUN_006F2C70, cfunc_IssueFormMove)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueFormMoveL`.
   */
  int cfunc_IssueFormMove(lua_State* luaContext);
  int cfunc_IssueGuard(lua_State* luaContext);
  int cfunc_IssueFactoryAssist(lua_State* luaContext);
  int cfunc_IssueAttack(lua_State* luaContext);
  int cfunc_IssueFormAttack(lua_State* luaContext);
  int cfunc_IssueFormAttackL(LuaPlus::LuaState* state);
  int cfunc_IssueNuke(lua_State* luaContext);
  int cfunc_IssueTactical(lua_State* luaContext);
  int cfunc_IssueTeleport(lua_State* luaContext);
  int cfunc_IssuePatrol(lua_State* luaContext);
  int cfunc_IssueFormPatrol(lua_State* luaContext);
  /**
   * Address: 0x006F50B0 (FUN_006F50B0, cfunc_IssueAggressiveMove)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueAggressiveMoveL`.
   */
  int cfunc_IssueAggressiveMove(lua_State* luaContext);
  /**
   * Address: 0x006F53C0 (FUN_006F53C0, cfunc_IssueFormAggressiveMove)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueFormAggressiveMoveL`.
   */
  int cfunc_IssueFormAggressiveMove(lua_State* luaContext);
  int cfunc_IssueFerry(lua_State* luaContext);
  int cfunc_IssueBuildMobile(lua_State* luaContext);
  int cfunc_IssueRepair(lua_State* luaContext);
  int cfunc_IssueSacrifice(lua_State* luaContext);
  int cfunc_IssueUpgrade(lua_State* luaContext);
  int cfunc_IssueScript(lua_State* luaContext);
  int cfunc_IssueReclaim(lua_State* luaContext);
  int cfunc_IssueCapture(lua_State* luaContext);
  int cfunc_IssueKillSelf(lua_State* luaContext);
  int cfunc_IssueDestroySelf(lua_State* luaContext);
  /**
   * Address: 0x006F71E0 (FUN_006F71E0, cfunc_IssueTransportLoad)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueTransportLoadL`.
   */
  int cfunc_IssueTransportLoad(lua_State* luaContext);
  int cfunc_IssueTransportUnload(lua_State* luaContext);
  int cfunc_IssueTeleportToBeacon(lua_State* luaContext);
  /**
   * Address: 0x006F7A70 (FUN_006F7A70, cfunc_IssueTransportUnloadSpecific)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_IssueTransportUnloadSpecificL`.
   */
  int cfunc_IssueTransportUnloadSpecific(lua_State* luaContext);
  int cfunc_IssueBuildFactory(lua_State* luaContext);
  int cfunc_IssueOverCharge(lua_State* luaContext);
  int cfunc_IssueDive(lua_State* luaContext);
  int cfunc_IssueFactoryRallyPoint(lua_State* luaContext);
  int cfunc_IssueUnitCommandL(LuaPlus::LuaState* state);
  int cfunc_IssueBlueprintCommandL(LuaPlus::LuaState* state);
  int cfunc_GetRolloverInfoL(LuaPlus::LuaState* state);
  int cfunc_SetOverlayFilterL(LuaPlus::LuaState* state);
  int cfunc_GetActiveBuildTemplateL(LuaPlus::LuaState* state);
  int cfunc_SetActiveBuildTemplateL(LuaPlus::LuaState* state);
  int cfunc_OpenURLL(LuaPlus::LuaState* state);
  int cfunc_SetCursorL(LuaPlus::LuaState* state);
  int cfunc_IsCommandDoneL(LuaPlus::LuaState* state);
  int cfunc_IssueClearCommandsL(LuaPlus::LuaState* state);
  int cfunc_IssueStopL(LuaPlus::LuaState* state);
  int cfunc_IssuePauseL(LuaPlus::LuaState* state);
  /**
   * Address: 0x006F29D0 (FUN_006F29D0, cfunc_IssueMoveOffFactoryL)
   *
   * What it does:
   * Parses unit list + target args, issues a move command, and marks the
   * resulting command as the special move-off-factory lane.
   */
  int cfunc_IssueMoveOffFactoryL(LuaPlus::LuaState* state);
  /**
   * Address: 0x006F2CE0 (FUN_006F2CE0, cfunc_IssueFormMoveL)
   *
   * What it does:
   * Parses `(unitList, target, formationName, orientationDegrees)`, resolves
   * formation-script/orientation payload lanes, and issues one
   * `UNITCOMMAND_FormMove`.
   */
  int cfunc_IssueFormMoveL(LuaPlus::LuaState* state);
  int cfunc_IssueTacticalL(LuaPlus::LuaState* state);
  int cfunc_IssuePatrolL(LuaPlus::LuaState* state);
  int cfunc_IssueFormPatrolL(LuaPlus::LuaState* state);
  /**
   * Address: 0x006F5120 (FUN_006F5120, cfunc_IssueAggressiveMoveL)
   *
   * What it does:
   * Parses unit list + target args and issues one aggressive-move command.
   */
  int cfunc_IssueAggressiveMoveL(LuaPlus::LuaState* state);
  /**
   * Address: 0x006F5430 (FUN_006F5430, cfunc_IssueFormAggressiveMoveL)
   *
   * What it does:
   * Parses `(unitList, target, formationName, orientationDegrees)`, resolves
   * formation-script/orientation payload lanes, and issues one
   * `UNITCOMMAND_FormAggressiveMove`.
   */
  int cfunc_IssueFormAggressiveMoveL(LuaPlus::LuaState* state);
  /**
   * Address: 0x006F7250 (FUN_006F7250, cfunc_IssueTransportLoadL)
   *
   * What it does:
   * Builds one transport-load command set from selected units + transport
   * carrier, then issues `UNITCOMMAND_TransportLoadUnits`.
   */
  int cfunc_IssueTransportLoadL(LuaPlus::LuaState* state);
  /**
   * Address: 0x006F7AE0 (FUN_006F7AE0, cfunc_IssueTransportUnloadSpecificL)
   *
   * What it does:
   * Filters transport cargo by category and issues
   * `UNITCOMMAND_TransportUnloadSpecificUnits` toward one target point.
   */
  int cfunc_IssueTransportUnloadSpecificL(LuaPlus::LuaState* state);
  int cfunc_DecreaseBuildCountInQueueL(LuaPlus::LuaState* state);
  int cfunc_GetUnitCommandDataL(LuaPlus::LuaState* state);
  int cfunc_IssueDockCommandL(LuaPlus::LuaState* state);
  int cfunc_IssueCommandL(LuaPlus::LuaState* state);

  // Shared Sim.cpp helper recovered as UNIT_IssueCommand (FUN_006F12C0).
  [[nodiscard]] CUnitCommand* IssueCommandToSelectedUnits(
    Sim* sim,
    SEntitySetTemplateUnit& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    bool clearQueue
  );

  /**
   * Address: 0x00BD9350 (FUN_00BD9350, j_func_IsCommandDone_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IsCommandDone_LuaFuncDef` to `func_IsCommandDone_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IsCommandDone_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IsCommandDone_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9360 (FUN_00BD9360, register_IssueClearCommands_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueClearCommands_LuaFuncDef` to `func_IssueClearCommands_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueClearCommands_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueClearCommands_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9370 (FUN_00BD9370, register_IssueStop_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueStop_LuaFuncDef` to `func_IssueStop_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueStop_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueStop_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9380 (FUN_00BD9380, j_func_IssuePause_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssuePause_LuaFuncDef` to `func_IssuePause_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssuePause_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssuePause_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9390 (FUN_00BD9390, register_IssueOverCharge_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueOverCharge_LuaFuncDef` to `func_IssueOverCharge_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueOverCharge_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueOverCharge_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD93A0 (FUN_00BD93A0, register_IssueDive_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueDive_LuaFuncDef` to `func_IssueDive_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueDive_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueDive_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD93B0 (FUN_00BD93B0, register_IssueFactoryRallyPoint_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFactoryRallyPoint_LuaFuncDef` to `func_IssueFactoryRallyPoint_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFactoryRallyPoint_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueFactoryRallyPoint_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD93C0 (FUN_00BD93C0, register_IssueClearFactoryCommands_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueClearFactoryCommands_LuaFuncDef` to `func_IssueClearFactoryCommands_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueClearFactoryCommands_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueClearFactoryCommands_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD93D0 (FUN_00BD93D0, j_func_IssueMove_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueMove_LuaFuncDef` to `func_IssueMove_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueMove_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueMove_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD93E0 (FUN_00BD93E0, j_func_IssueMoveOffFactory_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueMoveOffFactory_LuaFuncDef` to `func_IssueMoveOffFactory_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueMoveOffFactory_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueMoveOffFactory_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD93F0 (FUN_00BD93F0, register_IssueFormMove_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFormMove_LuaFuncDef` to `func_IssueFormMove_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFormMove_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueFormMove_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9400 (FUN_00BD9400, j_func_IssueGuard_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueGuard_LuaFuncDef` to `func_IssueGuard_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueGuard_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueGuard_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9410 (FUN_00BD9410, j_func_IssueFactoryAssist_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueFactoryAssist_LuaFuncDef` to `func_IssueFactoryAssist_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueFactoryAssist_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueFactoryAssist_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9420 (FUN_00BD9420, register_IssueAttack_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueAttack_LuaFuncDef` to `func_IssueAttack_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueAttack_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueAttack_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9430 (FUN_00BD9430, j_func_CoordinateAttacks_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_CoordinateAttacks_LuaFuncDef` to `func_CoordinateAttacks_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_CoordinateAttacks_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_CoordinateAttacks_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9440 (FUN_00BD9440, register_IssueFormAttack_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFormAttack_LuaFuncDef` to `func_IssueFormAttack_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFormAttack_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueFormAttack_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9450 (FUN_00BD9450, register_IssueSiloBuildTactical_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueSiloBuildTactical_LuaFuncDef` to `func_IssueSiloBuildTactical_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueSiloBuildTactical_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueSiloBuildTactical_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9460 (FUN_00BD9460, register_IssueSiloBuildNuke_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueSiloBuildNuke_LuaFuncDef` to `func_IssueSiloBuildNuke_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueSiloBuildNuke_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueSiloBuildNuke_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9470 (FUN_00BD9470, register_IssueNuke_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueNuke_LuaFuncDef` to `func_IssueNuke_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueNuke_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueNuke_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9480 (FUN_00BD9480, register_IssueTactical_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueTactical_LuaFuncDef` to `func_IssueTactical_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueTactical_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueTactical_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9490 (FUN_00BD9490, j_func_IssueTeleport_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueTeleport_LuaFuncDef` to `func_IssueTeleport_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueTeleport_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueTeleport_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD94A0 (FUN_00BD94A0, register_IssuePatrol_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssuePatrol_LuaFuncDef` to `func_IssuePatrol_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssuePatrol_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssuePatrol_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD94B0 (FUN_00BD94B0, register_IssueFormPatrol_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFormPatrol_LuaFuncDef` to `func_IssueFormPatrol_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFormPatrol_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueFormPatrol_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD94C0 (FUN_00BD94C0, j_func_IssueAggressiveMove_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueAggressiveMove_LuaFuncDef` to `func_IssueAggressiveMove_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueAggressiveMove_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueAggressiveMove_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD94D0 (FUN_00BD94D0, register_IssueFormAggressiveMove_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFormAggressiveMove_LuaFuncDef` to `func_IssueFormAggressiveMove_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFormAggressiveMove_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueFormAggressiveMove_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD94E0 (FUN_00BD94E0, register_IssueFerry_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueFerry_LuaFuncDef` to `func_IssueFerry_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueFerry_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueFerry_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD94F0 (FUN_00BD94F0, j_func_IssueBuildMobile_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueBuildMobile_LuaFuncDef` to `func_IssueBuildMobile_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueBuildMobile_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueBuildMobile_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9500 (FUN_00BD9500, register_IssueRepair_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueRepair_LuaFuncDef` to `func_IssueRepair_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueRepair_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueRepair_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9510 (FUN_00BD9510, register_IssueSacrifice_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueSacrifice_LuaFuncDef` to `func_IssueSacrifice_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueSacrifice_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueSacrifice_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9520 (FUN_00BD9520, register_IssueUpgrade_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueUpgrade_LuaFuncDef` to `func_IssueUpgrade_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueUpgrade_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueUpgrade_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9530 (FUN_00BD9530, register_IssueScript_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueScript_LuaFuncDef` to `func_IssueScript_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueScript_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueScript_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9540 (FUN_00BD9540, register_IssueReclaim_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueReclaim_LuaFuncDef` to `func_IssueReclaim_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueReclaim_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueReclaim_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9550 (FUN_00BD9550, j_func_IssueCapture_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueCapture_LuaFuncDef` to `func_IssueCapture_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueCapture_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueCapture_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9560 (FUN_00BD9560, register_IssueKillSelf_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueKillSelf_LuaFuncDef` to `func_IssueKillSelf_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueKillSelf_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueKillSelf_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9570 (FUN_00BD9570, register_IssueDestroySelf_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueDestroySelf_LuaFuncDef` to `func_IssueDestroySelf_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueDestroySelf_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueDestroySelf_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9580 (FUN_00BD9580, j_func_IssueTransportLoad_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueTransportLoad_LuaFuncDef` to `func_IssueTransportLoad_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueTransportLoad_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueTransportLoad_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD9590 (FUN_00BD9590, register_IssueTransportUnload_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueTransportUnload_LuaFuncDef` to `func_IssueTransportUnload_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueTransportUnload_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueTransportUnload_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD95A0 (FUN_00BD95A0, register_IssueTeleportToBeacon_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueTeleportToBeacon_LuaFuncDef` to `func_IssueTeleportToBeacon_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueTeleportToBeacon_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueTeleportToBeacon_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD95B0 (FUN_00BD95B0, j_func_IssueTransportUnloadSpecific_LuaFuncDef)
   *
   * What it does:
   * Forwards `j_func_IssueTransportUnloadSpecific_LuaFuncDef` to `func_IssueTransportUnloadSpecific_LuaFuncDef`.
   */
  CScrLuaInitForm* j_func_IssueTransportUnloadSpecific_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueTransportUnloadSpecific_LuaFuncDef>();
  }

  /**
   * Address: 0x00BD95C0 (FUN_00BD95C0, register_IssueBuildFactory_LuaFuncDef)
   *
   * What it does:
   * Forwards `register_IssueBuildFactory_LuaFuncDef` to `func_IssueBuildFactory_LuaFuncDef`.
   */
  CScrLuaInitForm* register_IssueBuildFactory_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_IssueBuildFactory_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE6240 (FUN_00BE6240, register_UISelectionByCategory_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_UISelectionByCategory_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UISelectionByCategory_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_UISelectionByCategory_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE6250 (FUN_00BE6250, register_UISelectAndZoomTo_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to
   * `func_UISelectAndZoomTo_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UISelectAndZoomTo_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_UISelectAndZoomTo_LuaFuncDef>();
  }

  /**
   * Address: 0x00BE6260 (FUN_00BE6260, register_UIZoomTo_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards registration to `func_UIZoomTo_LuaFuncDef`.
   */
  CScrLuaInitForm* register_UIZoomTo_LuaFuncDef()
  {
    return ForwardCommandLuaRegistrationThunk<&func_UIZoomTo_LuaFuncDef>();
  }

  /**
   * Address: 0x00836920 (FUN_00836920, func_DecreaseBuildCountInQueue_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `DecreaseBuildCountInQueue(queueIndex, count)`.
   */
  CScrLuaInitForm* func_DecreaseBuildCountInQueue_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kDecreaseBuildCountInQueueName,
      &moho::cfunc_DecreaseBuildCountInQueue,
      nullptr,
      "<global>",
      kDecreaseBuildCountInQueueHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008400D0 (FUN_008400D0, func_GetUnitCommandData_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `GetUnitCommandData(unitSet)`.
   */
  CScrLuaInitForm* func_GetUnitCommandData_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kGetUnitCommandDataName,
      &moho::cfunc_GetUnitCommandData,
      nullptr,
      "<global>",
      kGetUnitCommandDataHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00840A10 (FUN_00840A10, func_IssueDockCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueDockCommand(clear)`.
   */
  CScrLuaInitForm* func_IssueDockCommand_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueDockCommandName,
      &moho::cfunc_IssueDockCommand,
      nullptr,
      "<global>",
      kIssueDockCommandHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00841550 (FUN_00841550, func_IssueCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueCommand(command,[string],[clear])`.
   */
  CScrLuaInitForm* func_IssueCommand_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueCommandName,
      &moho::cfunc_IssueCommand,
      nullptr,
      "<global>",
      kIssueCommandHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00841860 (FUN_00841860, func_IssueUnitCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueUnitCommand(unitList,command,[string],[clear])`.
   */
  CScrLuaInitForm* func_IssueUnitCommand_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueUnitCommandName,
      &moho::cfunc_IssueUnitCommand,
      nullptr,
      "<global>",
      kIssueUnitCommandHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00841BB0 (FUN_00841BB0, func_IssueBlueprintCommand_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder
   * `IssueBlueprintCommand(command, blueprintid, count, clear = false)`.
   */
  CScrLuaInitForm* func_IssueBlueprintCommand_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueBlueprintCommandName,
      &moho::cfunc_IssueBlueprintCommand,
      nullptr,
      "<global>",
      kIssueBlueprintCommandHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008428C0 (FUN_008428C0, func_GetRolloverInfo_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `GetRolloverInfo()`.
   */
  CScrLuaInitForm* func_GetRolloverInfo_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kGetRolloverInfoName,
      &moho::cfunc_GetRolloverInfo,
      nullptr,
      "<global>",
      kGetRolloverInfoHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00866D50 (FUN_00866D50, func_UISelectionByCategory_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder
   * `UISelectionByCategory(expression, addToCurSel, inViewFrustum, nearestToMouse, mustBeIdle)`.
   */
  CScrLuaInitForm* func_UISelectionByCategory_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUISelectionByCategoryName,
      &moho::cfunc_UISelectionByCategory,
      nullptr,
      "<global>",
      kUISelectionByCategoryHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00866F60 (FUN_00866F60, func_UISelectAndZoomTo_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `UISelectAndZoomTo(userunit,[seconds])`.
   */
  CScrLuaInitForm* func_UISelectAndZoomTo_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUISelectAndZoomToName,
      &moho::cfunc_UISelectAndZoomTo,
      nullptr,
      "<global>",
      kUISelectAndZoomToHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x008671E0 (FUN_008671E0, func_UIZoomTo_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `UIZoomTo(units,[seconds])`.
   */
  CScrLuaInitForm* func_UIZoomTo_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kUIZoomToName,
      &moho::cfunc_UIZoomTo,
      nullptr,
      "<global>",
      kUIZoomToHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00846B80 (FUN_00846B80, func_SetOverlayFilter_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `SetOverlayFilter()`.
   */
  CScrLuaInitForm* func_SetOverlayFilter_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetOverlayFilterName,
      &moho::cfunc_SetOverlayFilter,
      nullptr,
      "<global>",
      kSetOverlayFilterHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00847290 (FUN_00847290, func_GetActiveBuildTemplate_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `GetActiveBuildTemplate()`.
   */
  CScrLuaInitForm* func_GetActiveBuildTemplate_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kGetActiveBuildTemplateName,
      &moho::cfunc_GetActiveBuildTemplate,
      nullptr,
      "<global>",
      kGetActiveBuildTemplateHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00847580 (FUN_00847580, func_SetActiveBuildTemplate_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `SetActiveBuildTemplate()`.
   */
  CScrLuaInitForm* func_SetActiveBuildTemplate_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetActiveBuildTemplateName,
      &moho::cfunc_SetActiveBuildTemplate,
      nullptr,
      "<global>",
      kSetActiveBuildTemplateHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00847FF0 (FUN_00847FF0, func_OpenURL_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `OpenURL(string)`.
   */
  CScrLuaInitForm* func_OpenURL_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kOpenURLName,
      &moho::cfunc_OpenURL,
      nullptr,
      "<global>",
      kOpenURLHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0084DCA0 (FUN_0084DCA0, func_SetCursor_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `SetCursor(cursor)`.
   */
  CScrLuaInitForm* func_SetCursor_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSetCursorName,
      &moho::cfunc_SetCursor,
      nullptr,
      "<global>",
      kSetCursorHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F17B0 (FUN_006F17B0, cfunc_IsCommandDone)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_IsCommandDoneL`.
   */
  int cfunc_IsCommandDone(lua_State* const luaContext)
  {
    return cfunc_IsCommandDoneL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F1820 (FUN_006F1820, cfunc_IsCommandDoneL)
   *
   * What it does:
   * Checks one optional command handle and returns true when the command is
   * null/expired.
   */
  int cfunc_IsCommandDoneL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsCommandDoneHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject commandObject(LuaPlus::LuaStackObject(state, 1));
    CUnitCommand* const command = GetUnitCommandOptionalForIssue(commandObject, state);
    lua_pushboolean(state->m_state, command == nullptr);
    return 1;
  }

  /**
   * Address: 0x006F18E0 (FUN_006F18E0, cfunc_IssueClearCommands)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IssueClearCommandsL`.
   */
  int cfunc_IssueClearCommands(lua_State* const luaContext)
  {
    return cfunc_IssueClearCommandsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F1950 (FUN_006F1950, cfunc_IssueClearCommandsL)
   *
   * What it does:
   * Clears command queues for one unit-table argument and stops active attacker
   * state per unit.
   */
  int cfunc_IssueClearCommandsL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueClearCommandsHelpText, 1, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueClearCommandsHelpText);

    for (Unit* const unit : units) {
      if (unit == nullptr) {
        continue;
      }

      if (unit->CommandQueue != nullptr) {
        unit->CommandQueue->ClearCommandQueue();
      }

      if (unit->AiAttacker != nullptr) {
        unit->AiAttacker->Stop();
      }
    }

    return 0;
  }

  /**
   * Address: 0x006F1A40 (FUN_006F1A40, cfunc_IssueStop)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_IssueStopL`.
   */
  int cfunc_IssueStop(lua_State* const luaContext)
  {
    return cfunc_IssueStopL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F1BE0 (FUN_006F1BE0, cfunc_IssuePause)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_IssuePauseL`.
   */
  int cfunc_IssuePause(lua_State* const luaContext)
  {
    return cfunc_IssuePauseL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F1AB0 (FUN_006F1AB0, cfunc_IssueStopL)
   *
   * What it does:
   * Resolves one unit-list argument and issues one `UNITCOMMAND_Stop` command
   * through the active sim command sink.
   */
  int cfunc_IssueStopL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueStopHelpText, 1, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueStopHelpText);

    Sim* const sim = lua_getglobaluserdata(rawState);
    IssueSimpleUnitCommand(sim, units, EUnitCommandType::UNITCOMMAND_Stop);
    return 0;
  }

  /**
   * Address: 0x006F1C50 (FUN_006F1C50, cfunc_IssuePauseL)
   *
   * What it does:
   * Resolves one unit-list argument and issues one `UNITCOMMAND_Pause`
   * command through the active sim command sink.
   */
  int cfunc_IssuePauseL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssuePauseHelpText, 1, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssuePauseHelpText);

    Sim* const sim = lua_getglobaluserdata(rawState);
    IssueSimpleUnitCommand(sim, units, EUnitCommandType::UNITCOMMAND_Pause);
    return 0;
  }

  /**
   * Address: 0x008415B0 (FUN_008415B0, cfunc_IssueCommandL)
   *
   * What it does:
   * Parses one command lexical plus optional payload/clear flag and issues the
   * command to the current world-session selection.
   */
  int cfunc_IssueCommandL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 3) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kIssueCommandHelpText, 1, 3, argumentCount);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      gpg::Warnf("Attempt to call IssueCommand before world sessions exists.");
      return 0;
    }

    const int focusArmy = session->FocusArmy;
    if (focusArmy < 0 || static_cast<std::size_t>(focusArmy) >= session->userArmies.size()
        || session->userArmies[focusArmy] == nullptr) {
      return 0;
    }

    const LuaPlus::LuaStackObject commandArg(state, 1);
    const char* const commandLexical = lua_tostring(rawState, 1);
    if (commandLexical == nullptr) {
      commandArg.TypeError("string");
      return 0;
    }

    EUnitCommandType commandType = EUnitCommandType::UNITCOMMAND_None;
    if (!TryParseUnitCommandTypeLexical(commandLexical, commandType) || commandType == EUnitCommandType::UNITCOMMAND_None) {
      return 0;
    }

    if (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical
        || commandType == EUnitCommandType::UNITCOMMAND_BuildSiloNuke) {
      if (ISTIDriver* const driver = WLD_GetDriver(); driver != nullptr) {
        msvc8::vector<UserUnit*> selectedUnits{};
        session->GetSelectionUnits(selectedUnits);

        const char* const commandKey = (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical)
          ? "SiloBuildTactical"
          : "SiloBuildNuke";
        for (UserUnit* const unit : selectedUnits) {
          if (unit == nullptr) {
            continue;
          }

          const auto* const userEntity = reinterpret_cast<const moho::UserEntity*>(unit);
          const auto entityIdAsPtr =
            reinterpret_cast<void*>(static_cast<std::uintptr_t>(userEntity->mParams.mEntityId));
          driver->ProcessInfoPair(entityIdAsPtr, commandKey, "add");
        }
      }
      return 0;
    }

    SSTICommandIssueData commandIssueData(commandType);
    if (argumentCount >= 2) {
      commandIssueData.mObject = LuaPlus::LuaStackObject(state, 2);
    }

    bool clearQueue = true;
    if (argumentCount == 3) {
      clearQueue = LuaPlus::LuaStackObject(state, 3).GetBoolean();
    }

    msvc8::vector<UserUnit*> selectedUnits{};
    session->GetSelectionUnits(selectedUnits);
    const BVSet<EntId, EntIdUniverse> selectedEntityIds = BuildSelectedEntitySetFromUserUnits(selectedUnits);
    if (selectedEntityIds.mBits.Count() == 0) {
      return 0;
    }

    if (Sim* const sim = lua_getglobaluserdata(rawState); sim != nullptr) {
      sim->IssueCommand(selectedEntityIds, commandIssueData, clearQueue);
    }
    return 0;
  }

  /**
   * Address: 0x008418C0 (FUN_008418C0, cfunc_IssueUnitCommandL)
   *
   * What it does:
   * Parses explicit user-unit list + command lexical with optional payload/clear
   * flag and issues the command to that explicit list.
   */
  int cfunc_IssueUnitCommandL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 4) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kIssueUnitCommandHelpText,
        1,
        4,
        argumentCount
      );
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      gpg::Warnf("Attempt to call IssueCommand before world sessions exists.");
      return 0;
    }

    const int focusArmy = session->FocusArmy;
    if (focusArmy < 0 || static_cast<std::size_t>(focusArmy) >= session->userArmies.size()
        || session->userArmies[focusArmy] == nullptr) {
      return 0;
    }

    if (lua_type(rawState, 1) != LUA_TTABLE) {
      LuaPlus::LuaState::Error(state, "Unit list expected as first argument");
    }

    msvc8::vector<UserUnit*> selectedUnits{};
    const LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
    if (unitListObject.IsTable()) {
      const int unitCount = unitListObject.GetCount();
      for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
        UserUnit* const unit = SCR_FromLua_UserUnit(unitListObject[unitIndex], state);
        if (unit != nullptr) {
          selectedUnits.push_back(unit);
        }
      }
    }

    const LuaPlus::LuaStackObject commandArg(state, 2);
    const char* const commandLexical = lua_tostring(rawState, 2);
    if (commandLexical == nullptr) {
      commandArg.TypeError("string");
      return 0;
    }

    EUnitCommandType commandType = EUnitCommandType::UNITCOMMAND_None;
    if (!TryParseUnitCommandTypeLexical(commandLexical, commandType) || commandType == EUnitCommandType::UNITCOMMAND_None) {
      return 0;
    }

    SSTICommandIssueData commandIssueData(commandType);
    if (argumentCount >= 3) {
      commandIssueData.mObject = LuaPlus::LuaStackObject(state, 3);
    }

    bool clearQueue = true;
    if (argumentCount == 4) {
      clearQueue = LuaPlus::LuaStackObject(state, 4).GetBoolean();
    }

    const BVSet<EntId, EntIdUniverse> selectedEntityIds = BuildSelectedEntitySetFromUserUnits(selectedUnits);
    if (selectedEntityIds.mBits.Count() == 0) {
      return 0;
    }

    if (Sim* const sim = lua_getglobaluserdata(rawState); sim != nullptr) {
      sim->IssueCommand(selectedEntityIds, commandIssueData, clearQueue);
    }
    return 0;
  }

  /**
   * Address: 0x00836900 (FUN_00836900, cfunc_DecreaseBuildCountInQueue)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_DecreaseBuildCountInQueueL`.
   */
  int cfunc_DecreaseBuildCountInQueue(lua_State* const luaContext)
  {
    return cfunc_DecreaseBuildCountInQueueL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008400B0 (FUN_008400B0, cfunc_GetUnitCommandData)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_GetUnitCommandDataL`.
   */
  int cfunc_GetUnitCommandData(lua_State* const luaContext)
  {
    return cfunc_GetUnitCommandDataL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008409F0 (FUN_008409F0, cfunc_IssueDockCommand)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_IssueDockCommandL`.
   */
  int cfunc_IssueDockCommand(lua_State* const luaContext)
  {
    return cfunc_IssueDockCommandL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00841530 (FUN_00841530, cfunc_IssueCommand)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_IssueCommandL`.
   */
  int cfunc_IssueCommand(lua_State* const luaContext)
  {
    return cfunc_IssueCommandL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00841840 (FUN_00841840, cfunc_IssueUnitCommand)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IssueUnitCommandL`.
   */
  int cfunc_IssueUnitCommand(lua_State* const luaContext)
  {
    return cfunc_IssueUnitCommandL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00841B90 (FUN_00841B90, cfunc_IssueBlueprintCommand)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_IssueBlueprintCommandL`.
   */
  int cfunc_IssueBlueprintCommand(lua_State* const luaContext)
  {
    return cfunc_IssueBlueprintCommandL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008428A0 (FUN_008428A0, cfunc_GetRolloverInfo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetRolloverInfoL`.
   */
  int cfunc_GetRolloverInfo(lua_State* const luaContext)
  {
    return cfunc_GetRolloverInfoL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00866D30 (FUN_00866D30, cfunc_UISelectionByCategory)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_UISelectionByCategoryL`.
   */
  int cfunc_UISelectionByCategory(lua_State* const luaContext)
  {
    return cfunc_UISelectionByCategoryL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00866F40 (FUN_00866F40, cfunc_UISelectAndZoomTo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UISelectAndZoomToL`.
   */
  int cfunc_UISelectAndZoomTo(lua_State* const luaContext)
  {
    return cfunc_UISelectAndZoomToL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x008671C0 (FUN_008671C0, cfunc_UIZoomTo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_UIZoomToL`.
   */
  int cfunc_UIZoomTo(lua_State* const luaContext)
  {
    return cfunc_UIZoomToL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00846BE0 (FUN_00846BE0, cfunc_SetOverlayFilterL)
   *
   * What it does:
   * Parses one overlay profile payload
   * `(name, category, buildColor, selectedColor, highlightedColor,
   * innerRadius, innerThickness, outerRadius, outerThickness)` and applies it
   * to the active viewport range-render profile map.
   */
  int cfunc_SetOverlayFilterL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 9) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetOverlayFilterHelpText, 9, argumentCount);
    }

    if (moho::WLD_GetActiveSession() == nullptr || moho::ren_Viewport == nullptr) {
      return 0;
    }

    const LuaPlus::LuaObject highlightedColorObject(LuaPlus::LuaStackObject(state, 5));
    const LuaPlus::LuaObject selectedColorObject(LuaPlus::LuaStackObject(state, 4));
    const LuaPlus::LuaObject buildColorObject(LuaPlus::LuaStackObject(state, 3));

    LuaPlus::LuaStackObject profileNameArg(state, 1);
    const char* const profileName = lua_tostring(state->m_state, 1);
    if (profileName == nullptr) {
      profileNameArg.TypeError("string");
    }

    const auto requireFloatArg = [state](const int stackIndex) -> float {
      LuaPlus::LuaStackObject argument(state, stackIndex);
      if (lua_type(state->m_state, stackIndex) != LUA_TNUMBER) {
        argument.TypeError("number");
      }
      return static_cast<float>(lua_tonumber(state->m_state, stackIndex));
    };

    const moho::RangeRingRadiusParams innerRingParams{
      requireFloatArg(6),
      requireFloatArg(7),
    };
    const moho::RangeRingRadiusParams outerRingParams{
      requireFloatArg(8),
      requireFloatArg(9),
    };

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    moho::EntityCategorySet* const categoryFilter = moho::func_GetCObj_EntityCategory(categoryObject);

    const std::uint32_t highlightedColorPacked = moho::SCR_DecodeColor(state, highlightedColorObject);
    const std::uint32_t selectedColorPacked = moho::SCR_DecodeColor(state, selectedColorObject);
    const std::uint32_t buildColorPacked = moho::SCR_DecodeColor(state, buildColorObject);

    moho::ApplyRangeProfileFilterToRenderer(
      highlightedColorPacked,
      categoryFilter,
      nullptr,
      profileName,
      buildColorPacked,
      selectedColorPacked,
      innerRingParams,
      outerRingParams
    );

    return 0;
  }

  /**
   * Address: 0x00846B60 (FUN_00846B60, cfunc_SetOverlayFilter)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_SetOverlayFilterL`.
   */
  int cfunc_SetOverlayFilter(lua_State* const luaContext)
  {
    return cfunc_SetOverlayFilterL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00847270 (FUN_00847270, cfunc_GetActiveBuildTemplate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_GetActiveBuildTemplateL`.
   */
  int cfunc_GetActiveBuildTemplate(lua_State* const luaContext)
  {
    return cfunc_GetActiveBuildTemplateL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00847560 (FUN_00847560, cfunc_SetActiveBuildTemplate)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_SetActiveBuildTemplateL`.
   */
  int cfunc_SetActiveBuildTemplate(lua_State* const luaContext)
  {
    return cfunc_SetActiveBuildTemplateL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00847FD0 (FUN_00847FD0, cfunc_OpenURL)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_OpenURLL`.
   */
  int cfunc_OpenURL(lua_State* const luaContext)
  {
    return cfunc_OpenURLL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0084DC80 (FUN_0084DC80, cfunc_SetCursor)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_SetCursorL`.
   */
  int cfunc_SetCursor(lua_State* const luaContext)
  {
    return cfunc_SetCursorL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x0084DD00 (FUN_0084DD00, cfunc_SetCursorL)
   *
   * What it does:
   * Decodes one optional cursor userdata (or nil) and updates the global UI
   * manager cursor binding.
   */
  int cfunc_SetCursorL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetCursorHelpText, 1, argumentCount);
    }

    CMauiCursor* cursor = nullptr;
    if (lua_type(state->m_state, 1) != LUA_TNIL) {
      const LuaPlus::LuaObject cursorObject(LuaPlus::LuaStackObject(state, 1));
      cursor = SCR_FromLua_CMauiCursor(cursorObject, state);
    }

    if (IUIManager* const uiManager = UI_GetManager(); uiManager != nullptr) {
      uiManager->SetCursor(cursor);
    }

    return 0;
  }

  /**
   * Address: 0x006F17D0 (FUN_006F17D0, func_IsCommandDone_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IsCommandDone`.
   */
  CScrLuaInitForm* func_IsCommandDone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIsCommandDoneName,
      &moho::cfunc_IsCommandDone,
      nullptr,
      "<global>",
      kIsCommandDoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F1900 (FUN_006F1900, func_IssueClearCommands_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueClearCommands`.
   */
  CScrLuaInitForm* func_IssueClearCommands_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueClearCommandsName,
      &moho::cfunc_IssueClearCommands,
      nullptr,
      "<global>",
      kIssueClearCommandsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F1A60 (FUN_006F1A60, func_IssueStop_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueStop`.
   */
  CScrLuaInitForm* func_IssueStop_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueStopName,
      &moho::cfunc_IssueStop,
      nullptr,
      "<global>",
      kIssueStopHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F1C00 (FUN_006F1C00, func_IssuePause_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssuePause`.
   */
  CScrLuaInitForm* func_IssuePause_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssuePauseName,
      &moho::cfunc_IssuePause,
      nullptr,
      "<global>",
      kIssuePauseHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F1DA0 (FUN_006F1DA0, func_IssueOverCharge_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueOverCharge`.
   */
  CScrLuaInitForm* func_IssueOverCharge_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueOverChargeName,
      &moho::cfunc_IssueOverCharge,
      nullptr,
      "<global>",
      kIssueOverChargeHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F2050 (FUN_006F2050, func_IssueDive_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueDive`.
   */
  CScrLuaInitForm* func_IssueDive_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueDiveName,
      &moho::cfunc_IssueDive,
      nullptr,
      "<global>",
      kIssueDiveHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F2270 (FUN_006F2270, func_IssueFactoryRallyPoint_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueFactoryRallyPoint`.
   */
  CScrLuaInitForm* func_IssueFactoryRallyPoint_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueFactoryRallyPointName,
      &moho::cfunc_IssueFactoryRallyPoint,
      nullptr,
      "<global>",
      kIssueFactoryRallyPointHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F2530 (FUN_006F2530, func_IssueClearFactoryCommands_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueClearFactoryCommands`.
   */
  CScrLuaInitForm* func_IssueClearFactoryCommands_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kIssueClearFactoryCommandsName,
      &moho::cfunc_IssueClearFactoryCommands,
      nullptr,
      "<global>",
      kIssueClearFactoryCommandsHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F2680 (FUN_006F2680, func_IssueMove_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueMove`.
   */
  CScrLuaInitForm* func_IssueMove_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueMove",
      &moho::cfunc_IssueMove,
      nullptr,
      "<global>",
      "IssueMove"
    );
    return &binder;
  }

  /**
   * Address: 0x006F2980 (FUN_006F2980, func_IssueMoveOffFactory_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueMoveOffFactory`.
   */
  CScrLuaInitForm* func_IssueMoveOffFactory_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueMoveOffFactory",
      &moho::cfunc_IssueMoveOffFactory,
      nullptr,
      "<global>",
      "IssueMoveOffFactory"
    );
    return &binder;
  }

  /**
   * Address: 0x006F2C90 (FUN_006F2C90, func_IssueFormMove_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueFormMove`.
   */
  CScrLuaInitForm* func_IssueFormMove_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueFormMove",
      &moho::cfunc_IssueFormMove,
      nullptr,
      "<global>",
      "IssueFormMove"
    );
    return &binder;
  }

  /**
   * Address: 0x006F30F0 (FUN_006F30F0, func_IssueGuard_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueGuard`.
   */
  CScrLuaInitForm* func_IssueGuard_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueGuard",
      &moho::cfunc_IssueGuard,
      nullptr,
      "<global>",
      "IssueGuard"
    );
    return &binder;
  }

  /**
   * Address: 0x006F33C0 (FUN_006F33C0, func_IssueFactoryAssist_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueFactoryAssist`.
   */
  CScrLuaInitForm* func_IssueFactoryAssist_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueFactoryAssist",
      &moho::cfunc_IssueFactoryAssist,
      nullptr,
      "<global>",
      "IssueFactoryAssist"
    );
    return &binder;
  }

  /**
   * Address: 0x006F3670 (FUN_006F3670, func_IssueAttack_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueAttack`.
   */
  CScrLuaInitForm* func_IssueAttack_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueAttack",
      &moho::cfunc_IssueAttack,
      nullptr,
      "<global>",
      "IssueAttack"
    );
    return &binder;
  }

  /**
   * Address: 0x006F3B80 (FUN_006F3B80, func_IssueFormAttack_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueFormAttack`.
   */
  CScrLuaInitForm* func_IssueFormAttack_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueFormAttack",
      &moho::cfunc_IssueFormAttack,
      nullptr,
      "<global>",
      "IssueFormAttack"
    );
    return &binder;
  }

  /**
   * Address: 0x006F3F60 (FUN_006F3F60, func_IssueSiloBuildTactical_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueSiloBuildTactical`.
   */
  CScrLuaInitForm* func_IssueSiloBuildTactical_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueSiloBuildTactical",
      &moho::cfunc_IssueSiloBuildTactical,
      nullptr,
      "<global>",
      "IssueSiloBuildTactical"
    );
    return &binder;
  }

  /**
   * Address: 0x006F40C0 (FUN_006F40C0, func_IssueSiloBuildNuke_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueSiloBuildNuke`.
   */
  CScrLuaInitForm* func_IssueSiloBuildNuke_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueSiloBuildNuke",
      &moho::cfunc_IssueSiloBuildNuke,
      nullptr,
      "<global>",
      "IssueSiloBuildNuke"
    );
    return &binder;
  }

  /**
   * Address: 0x006F4220 (FUN_006F4220, func_IssueNuke_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueNuke`.
   */
  CScrLuaInitForm* func_IssueNuke_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueNuke",
      &moho::cfunc_IssueNuke,
      nullptr,
      "<global>",
      "IssueNuke"
    );
    return &binder;
  }

  /**
   * Address: 0x006F44B0 (FUN_006F44B0, func_IssueTactical_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueTactical`.
   */
  CScrLuaInitForm* func_IssueTactical_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueTactical",
      &moho::cfunc_IssueTactical,
      nullptr,
      "<global>",
      "IssueTactical"
    );
    return &binder;
  }

  /**
   * Address: 0x006F4740 (FUN_006F4740, func_IssueTeleport_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueTeleport`.
   */
  CScrLuaInitForm* func_IssueTeleport_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueTeleport",
      &moho::cfunc_IssueTeleport,
      nullptr,
      "<global>",
      "IssueTeleport"
    );
    return &binder;
  }

  /**
   * Address: 0x006F49D0 (FUN_006F49D0, func_IssuePatrol_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssuePatrol`.
   */
  CScrLuaInitForm* func_IssuePatrol_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssuePatrol",
      &moho::cfunc_IssuePatrol,
      nullptr,
      "<global>",
      "IssuePatrol"
    );
    return &binder;
  }

  /**
   * Address: 0x006F4CA0 (FUN_006F4CA0, func_IssueFormPatrol_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueFormPatrol`.
   */
  CScrLuaInitForm* func_IssueFormPatrol_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueFormPatrol",
      &moho::cfunc_IssueFormPatrol,
      nullptr,
      "<global>",
      "IssueFormPatrol"
    );
    return &binder;
  }

  /**
   * Address: 0x006F50D0 (FUN_006F50D0, func_IssueAggressiveMove_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueAggressiveMove`.
   */
  CScrLuaInitForm* func_IssueAggressiveMove_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueAggressiveMove",
      &moho::cfunc_IssueAggressiveMove,
      nullptr,
      "<global>",
      "IssueAggressiveMove"
    );
    return &binder;
  }

  /**
   * Address: 0x006F53E0 (FUN_006F53E0, func_IssueFormAggressiveMove_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueFormAggressiveMove`.
   */
  CScrLuaInitForm* func_IssueFormAggressiveMove_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueFormAggressiveMove",
      &moho::cfunc_IssueFormAggressiveMove,
      nullptr,
      "<global>",
      "IssueFormAggressiveMove"
    );
    return &binder;
  }

  /**
   * Address: 0x006F5840 (FUN_006F5840, func_IssueFerry_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueFerry`.
   */
  CScrLuaInitForm* func_IssueFerry_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueFerry",
      &moho::cfunc_IssueFerry,
      nullptr,
      "<global>",
      "IssueFerry"
    );
    return &binder;
  }

  /**
   * Address: 0x006F5B10 (FUN_006F5B10, func_IssueBuildMobile_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueBuildMobile`.
   */
  CScrLuaInitForm* func_IssueBuildMobile_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueBuildMobile",
      &moho::cfunc_IssueBuildMobile,
      nullptr,
      "<global>",
      "IssueBuildMobile"
    );
    return &binder;
  }

  /**
   * Address: 0x006F6080 (FUN_006F6080, func_IssueRepair_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueRepair`.
   */
  CScrLuaInitForm* func_IssueRepair_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueRepair",
      &moho::cfunc_IssueRepair,
      nullptr,
      "<global>",
      "IssueRepair"
    );
    return &binder;
  }

  /**
   * Address: 0x006F6350 (FUN_006F6350, func_IssueSacrifice_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueSacrifice`.
   */
  CScrLuaInitForm* func_IssueSacrifice_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueSacrifice",
      &moho::cfunc_IssueSacrifice,
      nullptr,
      "<global>",
      "IssueSacrifice"
    );
    return &binder;
  }

  /**
   * Address: 0x006F6620 (FUN_006F6620, func_IssueUpgrade_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueUpgrade`.
   */
  CScrLuaInitForm* func_IssueUpgrade_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueUpgrade",
      &moho::cfunc_IssueUpgrade,
      nullptr,
      "<global>",
      "IssueUpgrade"
    );
    return &binder;
  }

  /**
   * Address: 0x006F67C0 (FUN_006F67C0, func_IssueScript_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueScript`.
   */
  CScrLuaInitForm* func_IssueScript_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueScript",
      &moho::cfunc_IssueScript,
      nullptr,
      "<global>",
      "IssueScript"
    );
    return &binder;
  }

  /**
   * Address: 0x006F6980 (FUN_006F6980, func_IssueReclaim_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueReclaim`.
   */
  CScrLuaInitForm* func_IssueReclaim_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueReclaim",
      &moho::cfunc_IssueReclaim,
      nullptr,
      "<global>",
      "IssueReclaim"
    );
    return &binder;
  }

  /**
   * Address: 0x006F6C40 (FUN_006F6C40, func_IssueCapture_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueCapture`.
   */
  CScrLuaInitForm* func_IssueCapture_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueCapture",
      &moho::cfunc_IssueCapture,
      nullptr,
      "<global>",
      "IssueCapture"
    );
    return &binder;
  }

  /**
   * Address: 0x006F6F00 (FUN_006F6F00, func_IssueKillSelf_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueKillSelf`.
   */
  CScrLuaInitForm* func_IssueKillSelf_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueKillSelf",
      &moho::cfunc_IssueKillSelf,
      nullptr,
      "<global>",
      "IssueKillSelf"
    );
    return &binder;
  }

  /**
   * Address: 0x006F7080 (FUN_006F7080, func_IssueDestroySelf_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueDestroySelf`.
   */
  CScrLuaInitForm* func_IssueDestroySelf_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueDestroySelf",
      &moho::cfunc_IssueDestroySelf,
      nullptr,
      "<global>",
      "IssueDestroySelf"
    );
    return &binder;
  }

  /**
   * Address: 0x006F7200 (FUN_006F7200, func_IssueTransportLoad_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueTransportLoad`.
   */
  CScrLuaInitForm* func_IssueTransportLoad_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueTransportLoad",
      &moho::cfunc_IssueTransportLoad,
      nullptr,
      "<global>",
      "IssueTransportLoad"
    );
    return &binder;
  }

  /**
   * Address: 0x006F7550 (FUN_006F7550, func_IssueTransportUnload_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueTransportUnload`.
   */
  CScrLuaInitForm* func_IssueTransportUnload_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueTransportUnload",
      &moho::cfunc_IssueTransportUnload,
      nullptr,
      "<global>",
      "IssueTransportUnload"
    );
    return &binder;
  }

  /**
   * Address: 0x006F7800 (FUN_006F7800, func_IssueTeleportToBeacon_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueTeleportToBeacon`.
   */
  CScrLuaInitForm* func_IssueTeleportToBeacon_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueTeleportToBeacon",
      &moho::cfunc_IssueTeleportToBeacon,
      nullptr,
      "<global>",
      "IssueTeleportToBeacon"
    );
    return &binder;
  }

  /**
   * Address: 0x006F7A90 (FUN_006F7A90, func_IssueTransportUnloadSpecific_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueTransportUnloadSpecific`.
   */
  CScrLuaInitForm* func_IssueTransportUnloadSpecific_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueTransportUnloadSpecific",
      &moho::cfunc_IssueTransportUnloadSpecific,
      nullptr,
      "<global>",
      "IssueTransportUnloadSpecific"
    );
    return &binder;
  }

  /**
   * Address: 0x006F7EC0 (FUN_006F7EC0, func_IssueBuildFactory_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `IssueBuildFactory`.
   */
  CScrLuaInitForm* func_IssueBuildFactory_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "IssueBuildFactory",
      &moho::cfunc_IssueBuildFactory,
      nullptr,
      "<global>",
      "IssueBuildFactory"
    );
    return &binder;
  }

  /**
   * Address: 0x006F2510 (FUN_006F2510, cfunc_IssueClearFactoryCommands)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_IssueClearFactoryCommandsL`.
   */
  int cfunc_IssueClearFactoryCommands(lua_State* const luaContext)
  {
    return cfunc_IssueClearFactoryCommandsL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F2580 (FUN_006F2580, cfunc_IssueClearFactoryCommandsL)
   *
   * What it does:
   * Parses one unit-list argument, filters dead/destroyed entries, and clears
   * each resolved unit's factory command queue.
   */
  int cfunc_IssueClearFactoryCommandsL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(
        state,
        kLuaExpectedArgsWarning,
        kIssueClearFactoryCommandsHelpText,
        1,
        argumentCount
      );
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueClearFactoryCommandsHelpText);

    for (Unit* unit : units) {
      IAiBuilder* const aiBuilder = unit ? unit->AiBuilder : nullptr;
      if (aiBuilder) {
        aiBuilder->BuilderClearFactoryCommandQueue();
      }
    }

    return 0;
  }

  /**
   * Address: 0x006F2960 (FUN_006F2960, cfunc_IssueMoveOffFactory)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueMoveOffFactoryL`.
   */
  int cfunc_IssueMoveOffFactory(lua_State* const luaContext)
  {
    return cfunc_IssueMoveOffFactoryL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F29D0 (FUN_006F29D0, cfunc_IssueMoveOffFactoryL)
   *
   * What it does:
   * Parses one unit list and one target argument, issues a move command to the
   * filtered selection, and marks the command as move-off-factory when issued.
   */
  int cfunc_IssueMoveOffFactoryL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueMoveOffFactoryHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueMoveOffFactoryHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Move)) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    SCR_FromLuaCopy_CAiTarget(target, targetObject);
    if (!IsValidVector3f(target.position) || target.targetType == EAiTargetType::AITARGET_None) {
      LuaPlus::LuaState::Error(state, kIssueMoveOffFactoryInvalidTargetError);
    }

    Sim* const sim = lua_getglobaluserdata(rawState);
    if (sim == nullptr) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Move);
    target.EncodeToSSTITarget(commandIssueData.mTarget);

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    if (issuedCommand == nullptr) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    issuedCommand->mUnknownFlag142 = true;
    issuedCommand->mArgs.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006F2C70 (FUN_006F2C70, cfunc_IssueFormMove)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueFormMoveL`.
   */
  int cfunc_IssueFormMove(lua_State* const luaContext)
  {
    return cfunc_IssueFormMoveL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F2CE0 (FUN_006F2CE0, cfunc_IssueFormMoveL)
   *
   * What it does:
   * Parses `(unitList, target, formationName, orientationDegrees)`, resolves
   * formation-script/orientation payload lanes, and issues one
   * `UNITCOMMAND_FormMove`.
   */
  int cfunc_IssueFormMoveL(LuaPlus::LuaState* const state)
  {
    return IssueFormCommandWithFormation(
      state,
      kIssueFormMoveHelpText,
      kIssueFormMoveInvalidTargetError,
      EUnitCommandType::UNITCOMMAND_FormMove,
      RULEUCC_Move
    );
  }

  /**
   * Address: 0x006F3980 (FUN_006F3980, cfunc_CoordinateAttacksL)
   *
   * What it does:
   * Resolves command objects from arg#1 table and links every command pair for
   * coordinated execution.
   */
  int cfunc_CoordinateAttacksL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCoordinateAttacksHelpText, 1, argumentCount);
    }

    const LuaPlus::LuaObject commandListObject(LuaPlus::LuaStackObject(state, 1));
    msvc8::vector<CUnitCommand*> commands{};
    if (commandListObject.IsTable()) {
      const int commandCount = commandListObject.GetCount();
      for (int commandIndex = 1; commandIndex <= commandCount; ++commandIndex) {
        const LuaPlus::LuaObject commandObject = commandListObject[commandIndex];
        if (CUnitCommand* const command = SCR_FromLua_CUnitCommand(commandObject, state); command != nullptr) {
          commands.push_back(command);
        }
      }
    }

    for (std::size_t firstIndex = 0; firstIndex + 1 < commands.size(); ++firstIndex) {
      CUnitCommand* const firstCommand = commands[firstIndex];
      for (std::size_t secondIndex = firstIndex + 1; secondIndex < commands.size(); ++secondIndex) {
        CUnitCommand* const secondCommand = commands[secondIndex];
        if (firstCommand != nullptr && secondCommand != nullptr) {
          secondCommand->CoordinateWith(firstCommand);
          firstCommand->CoordinateWith(secondCommand);
        }
      }
    }

    return 0;
  }

  /**
   * Address: 0x006F3910 (FUN_006F3910, cfunc_CoordinateAttacks)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_CoordinateAttacksL`.
   */
  int cfunc_CoordinateAttacks(lua_State* const luaContext)
  {
    return cfunc_CoordinateAttacksL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F3930 (FUN_006F3930, func_CoordinateAttacks_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder `CoordinateAttacks(commandList)`.
   */
  CScrLuaInitForm* func_CoordinateAttacks_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCoordinateAttacksName,
      &moho::cfunc_CoordinateAttacks,
      nullptr,
      "<global>",
      kCoordinateAttacksHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006F3F40 (FUN_006F3F40, cfunc_IssueSiloBuildTactical)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueSiloBuildTacticalL`.
   */
  int cfunc_IssueSiloBuildTactical(lua_State* const luaContext)
  {
    return cfunc_IssueSiloBuildTacticalL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F3FB0 (FUN_006F3FB0, cfunc_IssueSiloBuildTacticalL)
   *
   * What it does:
   * Parses one unit-list argument, filters dead/destroyed entries, and queues
   * tactical silo ammo build on each resolved unit with a silo-build lane.
   */
  int cfunc_IssueSiloBuildTacticalL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueSiloBuildTacticalHelpText, 1, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueSiloBuildTacticalHelpText);

    for (Unit* unit : units) {
      IAiSiloBuild* const aiSiloBuild = unit ? unit->AiSiloBuild : nullptr;
      if (aiSiloBuild) {
        aiSiloBuild->SiloAddBuild(SILOTYPE_Tactical);
      }
    }

    return 0;
  }

  /**
   * Address: 0x006F40A0 (FUN_006F40A0, cfunc_IssueSiloBuildNuke)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueSiloBuildNukeL`.
   */
  int cfunc_IssueSiloBuildNuke(lua_State* const luaContext)
  {
    return cfunc_IssueSiloBuildNukeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F4110 (FUN_006F4110, cfunc_IssueSiloBuildNukeL)
   *
   * What it does:
   * Parses one unit-list argument, filters dead/destroyed entries, and queues
   * nuke silo ammo build on each resolved unit with a silo-build lane.
   */
  int cfunc_IssueSiloBuildNukeL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueSiloBuildNukeHelpText, 1, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueSiloBuildNukeHelpText);

    for (Unit* unit : units) {
      IAiSiloBuild* const aiSiloBuild = unit ? unit->AiSiloBuild : nullptr;
      if (aiSiloBuild) {
        aiSiloBuild->SiloAddBuild(SILOTYPE_Nuke);
      }
    }

    return 0;
  }

  /**
   * Address: 0x006F4490 (FUN_006F4490, cfunc_IssueTactical)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueTacticalL`.
   */
  int cfunc_IssueTactical(lua_State* const luaContext)
  {
    return cfunc_IssueTacticalL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F2250 (FUN_006F2250, cfunc_IssueFactoryRallyPoint)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_IssueFactoryRallyPointL`.
   */
  int cfunc_IssueFactoryRallyPoint(lua_State* const luaContext)
  {
    return cfunc_IssueFactoryRallyPointL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F22C0 (FUN_006F22C0, cfunc_IssueFactoryRallyPointL)
   *
   * What it does:
   * Parses `(unitList, target)`, filters factory-rally-capable units, issues
   * one factory command, and returns the created Lua command object on success.
   */
  int cfunc_IssueFactoryRallyPointL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueFactoryRallyPointHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueFactoryRallyPointHelpText);

    SEntitySetTemplateUnit selectedFactories{};
    if (!FilterFactoryUnitsByCommandCap(
          sourceUnits, selectedFactories, static_cast<std::uint32_t>(RULEUCC_Move))) {
      return 0;
    }

    CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    SCR_FromLuaCopy_CAiTarget(target, targetObject);

    Sim* const sim = lua_getglobaluserdata(rawState);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Move);
    target.EncodeToSSTITarget(commandIssueData.mTarget);

    CUnitCommand* const issuedCommand =
      IssueFactoryCommandToSelectedUnits(sim, selectedFactories, commandIssueData, false);
    if (issuedCommand == nullptr) {
      return 0;
    }

    issuedCommand->mArgs.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006F30D0 (FUN_006F30D0, cfunc_IssueGuard)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueGuardL`.
   */
  int cfunc_IssueGuard(lua_State* const luaContext)
  {
    return cfunc_IssueGuardL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F3140 (FUN_006F3140, cfunc_IssueGuardL)
   *
   * What it does:
   * Parses `(unitList, target)`, validates guard-capable units, and queues
   * `UNITCOMMAND_Guard` on selected units.
   */
  int cfunc_IssueGuardL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueGuardHelpText, 2, argumentCount);
    }

    CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    SCR_FromLuaCopy_CAiTarget(target, targetObject);
    if (!IsValidVector3f(target.position) || target.targetType == EAiTargetType::AITARGET_None) {
      LuaPlus::LuaState::Error(state, kIssueGuardInvalidTargetError);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueGuardHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Guard)) {
      return 0;
    }

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Guard);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F3650 (FUN_006F3650, cfunc_IssueAttack)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueAttackL`.
   */
  int cfunc_IssueAttack(lua_State* const luaContext)
  {
    return cfunc_IssueAttackL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F36C0 (FUN_006F36C0, cfunc_IssueAttackL)
   *
   * What it does:
   * Parses `(unitList, target)`, filters attack-capable units, and returns the
   * issued command object or `nil` when command creation fails.
   */
  int cfunc_IssueAttackL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueAttackHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueAttackHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Attack)) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    SCR_FromLuaCopy_CAiTarget(target, targetObject);

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Attack);
    target.EncodeToSSTITarget(commandIssueData.mTarget);

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    if (issuedCommand == nullptr) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    issuedCommand->mArgs.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006F3B60 (FUN_006F3B60, cfunc_IssueFormAttack)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueFormAttackL`.
   */
  int cfunc_IssueFormAttack(lua_State* const luaContext)
  {
    return cfunc_IssueFormAttackL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F3BD0 (FUN_006F3BD0, cfunc_IssueFormAttackL)
   *
   * What it does:
   * Parses `(unitList, target, formationName, orientationDegrees)`, resolves
   * formation-script/orientation payload lanes, and issues one
   * `UNITCOMMAND_FormAttack`.
   */
  int cfunc_IssueFormAttackL(LuaPlus::LuaState* const state)
  {
    return IssueFormCommandWithFormationNoResult(
      state,
      kIssueFormAttackHelpText,
      kIssueFormAttackInvalidTargetError,
      EUnitCommandType::UNITCOMMAND_FormAttack,
      RULEUCC_Attack,
      false
    );
  }

  /**
   * Address: 0x006F49B0 (FUN_006F49B0, cfunc_IssuePatrol)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssuePatrolL`.
   */
  int cfunc_IssuePatrol(lua_State* const luaContext)
  {
    return cfunc_IssuePatrolL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F4A20 (FUN_006F4A20, cfunc_IssuePatrolL)
   *
   * What it does:
   * Parses `(unitList, target)`, validates patrol-capable units and target,
   * and queues `UNITCOMMAND_Patrol`.
   */
  int cfunc_IssuePatrolL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssuePatrolHelpText, 2, argumentCount);
    }

    CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    SCR_FromLuaCopy_CAiTarget(target, targetObject);
    if (!IsValidVector3f(target.position) || target.targetType == EAiTargetType::AITARGET_None) {
      LuaPlus::LuaState::Error(state, kIssuePatrolInvalidTargetError);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssuePatrolHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Patrol)) {
      return 0;
    }

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Patrol);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F4C80 (FUN_006F4C80, cfunc_IssueFormPatrol)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueFormPatrolL`.
   */
  int cfunc_IssueFormPatrol(lua_State* const luaContext)
  {
    return cfunc_IssueFormPatrolL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F4CF0 (FUN_006F4CF0, cfunc_IssueFormPatrolL)
   *
   * What it does:
   * Parses `(unitList, target, formationName, orientationDegrees)`, resolves
   * formation-script/orientation payload lanes, and issues one
   * `UNITCOMMAND_FormPatrol`.
   */
  int cfunc_IssueFormPatrolL(LuaPlus::LuaState* const state)
  {
    return IssueFormCommandWithFormationNoResult(
      state,
      kIssueFormPatrolHelpText,
      kIssueFormPatrolInvalidTargetError,
      EUnitCommandType::UNITCOMMAND_FormPatrol,
      RULEUCC_Patrol,
      true
    );
  }

  /**
   * Address: 0x006F5820 (FUN_006F5820, cfunc_IssueFerry)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueFerryL`.
   */
  int cfunc_IssueFerry(lua_State* const luaContext)
  {
    return cfunc_IssueFerryL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F5890 (FUN_006F5890, cfunc_IssueFerryL)
   *
   * What it does:
   * Parses `(unitList, target)`, validates ferry-capable units and target,
   * and queues `UNITCOMMAND_Ferry`.
   */
  int cfunc_IssueFerryL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueFerryHelpText, 2, argumentCount);
    }

    CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    SCR_FromLuaCopy_CAiTarget(target, targetObject);
    if (!IsValidVector3f(target.position) || target.targetType == EAiTargetType::AITARGET_None) {
      LuaPlus::LuaState::Error(state, kIssueFerryInvalidTargetError);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueFerryHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Ferry)) {
      return 0;
    }

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Ferry);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F50B0 (FUN_006F50B0, cfunc_IssueAggressiveMove)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueAggressiveMoveL`.
   */
  int cfunc_IssueAggressiveMove(lua_State* const luaContext)
  {
    return cfunc_IssueAggressiveMoveL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F5120 (FUN_006F5120, cfunc_IssueAggressiveMoveL)
   *
   * What it does:
   * Parses one unit list and one target argument, then issues one aggressive
   * move command to the filtered selection.
   */
  int cfunc_IssueAggressiveMoveL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueAggressiveMoveHelpText, 2, argumentCount);
    }

    CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    SCR_FromLuaCopy_CAiTarget(target, targetObject);
    if (!IsValidVector3f(target.position) || target.targetType == EAiTargetType::AITARGET_None) {
      LuaPlus::LuaState::Error(state, kIssueAggressiveMoveInvalidTargetError);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueAggressiveMoveHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Move)) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    Sim* const sim = lua_getglobaluserdata(rawState);
    if (sim == nullptr) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_AggressiveMove);
    target.EncodeToSSTITarget(commandIssueData.mTarget);

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    if (issuedCommand == nullptr) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    issuedCommand->mArgs.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006F53C0 (FUN_006F53C0, cfunc_IssueFormAggressiveMove)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_IssueFormAggressiveMoveL`.
   */
  int cfunc_IssueFormAggressiveMove(lua_State* const luaContext)
  {
    return cfunc_IssueFormAggressiveMoveL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F5430 (FUN_006F5430, cfunc_IssueFormAggressiveMoveL)
   *
   * What it does:
   * Parses `(unitList, target, formationName, orientationDegrees)`, resolves
   * formation-script/orientation payload lanes, and issues one
   * `UNITCOMMAND_FormAggressiveMove`.
   */
  int cfunc_IssueFormAggressiveMoveL(LuaPlus::LuaState* const state)
  {
    return IssueFormCommandWithFormation(
      state,
      kIssueFormAggressiveMoveHelpText,
      kIssueFormAggressiveMoveInvalidTargetError,
      EUnitCommandType::UNITCOMMAND_FormAggressiveMove,
      RULEUCC_Move
    );
  }

  /**
   * Address: 0x006F71E0 (FUN_006F71E0, cfunc_IssueTransportLoad)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueTransportLoadL`.
   */
  int cfunc_IssueTransportLoad(lua_State* const luaContext)
  {
    return cfunc_IssueTransportLoadL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F7250 (FUN_006F7250, cfunc_IssueTransportLoadL)
   *
   * What it does:
   * Builds one transport-load command set from selected units + transport
   * carrier, then issues `UNITCOMMAND_TransportLoadUnits`.
   */
  int cfunc_IssueTransportLoadL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueTransportLoadHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject unitToLoadObject(LuaPlus::LuaStackObject(state, 2));
    Unit* const unitToLoad = SCR_FromLua_Unit(unitToLoadObject);

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueTransportLoadHelpText);

    UnitSet transportUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, transportUnits, RULEUCC_Transport)) {
      return 0;
    }

    SEntitySetTemplateUnit commandUnits{};
    for (Unit* const unit : transportUnits) {
      if (unit == nullptr) {
        continue;
      }

      if (unit->IsUnitState(UNITSTATE_Attached) || unit->GetTransportedBy() != nullptr) {
        LuaPlus::LuaState::Error(state, kIssueTransportLoadAttachedError);
      }

      (void)commandUnits.AddUnit(unit);
    }

    if (commandUnits.Empty()) {
      LuaPlus::LuaState::Error(state, kIssueTransportLoadNoUnitsError);
    }

    (void)commandUnits.AddUnit(unitToLoad);

    CAiTarget target{};
    target.UpdateTarget(unitToLoad != nullptr ? static_cast<Entity*>(unitToLoad) : nullptr);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportLoadUnits);
    target.EncodeToSSTITarget(commandIssueData.mTarget);

    Sim* const sim = lua_getglobaluserdata(rawState);
    (void)IssueCommandToSelectedUnits(sim, commandUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F7A70 (FUN_006F7A70, cfunc_IssueTransportUnloadSpecific)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_IssueTransportUnloadSpecificL`.
   */
  int cfunc_IssueTransportUnloadSpecific(lua_State* const luaContext)
  {
    return cfunc_IssueTransportUnloadSpecificL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F7AE0 (FUN_006F7AE0, cfunc_IssueTransportUnloadSpecificL)
   *
   * What it does:
   * Filters transport cargo by category and issues
   * `UNITCOMMAND_TransportUnloadSpecificUnits` toward one target point.
   */
  int cfunc_IssueTransportUnloadSpecificL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueTransportUnloadSpecificHelpText, 3, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueTransportUnloadSpecificHelpText);

    UnitSet transportUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, transportUnits, RULEUCC_Transport)) {
      return 0;
    }

    const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 2));
    const EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject);

    SEntitySetTemplateUnit unitsToUnload{};
    for (Unit* const transportUnit : transportUnits) {
      if (transportUnit == nullptr) {
        continue;
      }

      IAiTransport* const transport = transportUnit->AiTransport;
      if (transport == nullptr) {
        continue;
      }

      const auto loadedUnits = transport->TransportGetLoadedUnits(false);
      for (Unit* const loadedUnit : loadedUnits) {
        if (loadedUnit == nullptr) {
          continue;
        }

        const RUnitBlueprint* const blueprint = loadedUnit->GetBlueprint();
        if (blueprint == nullptr) {
          continue;
        }

        if (!categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
          continue;
        }

        (void)unitsToUnload.AddUnit(loadedUnit);
      }
    }

    if (unitsToUnload.Empty()) {
      return 0;
    }

    CAiTarget unloadTarget{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 3));
    SCR_FromLuaCopy_CAiTarget(unloadTarget, targetObject);
    const Wm3::Vec3f targetPosition = unloadTarget.GetTargetPosGun(false);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportUnloadSpecificUnits);
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
    commandIssueData.mTarget.mEnt = kGroundTargetEntitySentinel;
    commandIssueData.mTarget.mPos = targetPosition;

    Sim* const sim = lua_getglobaluserdata(rawState);
    (void)IssueCommandToSelectedUnits(sim, unitsToUnload, commandIssueData, false);
    return 0;
  }
} // namespace moho
