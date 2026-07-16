#include "moho/sim/CCommandLuaFunctionRegistrations.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Set.h"
#include "lua/LuaTableIterator.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiTarget.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/client/Localization.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/console/CConCommand.h"
#include "moho/sim/SOCellPos.h"
#include "gpg/core/containers/String.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/UserEntity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/math/Vector3f.h"
#include "moho/resource/blueprints/RUnitBlueprintCapabilityEnums.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/render/RCamManager.h"
#include "moho/render/RangeRenderer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/ArmyUnitSet.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/sim/UserArmy.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/WeakObject.h"
#include "moho/ui/IUIManager.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/mesh/Mesh.h"
#include "moho/sim/COGrid.h"
#include "moho/math/Wm3AxisAlignedBox3FafExtras.h"
#include "moho/collision/CColPrimitiveBox3f.h"
#include "Wm3Box3.h"

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
  constexpr const char* kIssueMoveHelpText = "IssueMove";
  constexpr const char* kIssueNukeHelpText = "IssueNuke";
  constexpr const char* kIssueTacticalHelpText = "IssueTactical";
  constexpr const char* kIssueTeleportHelpText = "IssueTeleport";
  constexpr const char* kIssueTeleportToBeaconHelpText = "IssueTeleportToBeacon";
  constexpr const char* kIssueTransportUnloadHelpText = "IssueTransportUnload";
  constexpr const char* kIssueFactoryAssistHelpText = "IssueFactoryAssist";
  constexpr const char* kIssueAttackHelpText = "IssueAttack";
  constexpr const char* kIssuePatrolHelpText = "IssuePatrol";
  constexpr const char* kIssueFerryHelpText = "IssueFerry";
  constexpr const char* kIssueRepairHelpText = "IssueRepair";
  constexpr const char* kIssueReclaimHelpText = "IssueReclaim";
  constexpr const char* kIssueCaptureHelpText = "IssueCapture";
  constexpr const char* kIssueSacrificeHelpText = "IssueSacrifice";
  constexpr const char* kIssueScriptHelpText = "IssueScript";
  constexpr const char* kIssueKillSelfHelpText = "IssueKillSelf";
  constexpr const char* kIssueDestroySelfHelpText = "IssueDestroySelf";
  constexpr const char* kIssueUpgradeHelpText = "IssueUpgrade";
  constexpr const char* kIssueBuildFactoryHelpText = "IssueBuildFactory";
  // Used by the build-count argument parser shared by IssueBuildFactory (and
  // sibling Lua build callbacks). Mirrors the static string lane at the
  // 0x006EF580 "Invalid count" error site.
  constexpr const char* kLuaInvalidCountWarning = "Invalid count in %s; expected a number but got a %s";
  constexpr const char* kIssueMoveOffFactoryInvalidTargetError = "IssueMoveOffFactory: Passed in an invalid target point.";
  constexpr const char* kIssueMoveInvalidTargetError = "IssueMove: Passed in an invalid target point.";
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
  constexpr const char* kIssueBuildMobileName = "IssueBuildMobile";
  constexpr const char* kInvalidCellListError = "Invalid list of cells in %s; expected a table but got a %s";
  constexpr const char* kInvalidCellError =
    "Invalid cell in %s; expected a two element table but got a %s";

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

  /**
   * Address: 0x006EF580 (FUN_006EF580, sub_6EF580)
   *
   * What it does:
   * Coerces one Lua stack argument to a non-negative integer count, raising
   * the binary's `"Invalid count in %s; expected a number but got a %s"`
   * Lua error (followed by the LuaStackObject typed-arg error) when the
   * argument is not a number. Mirrors the inline body the IDA export
   * surfaces as `sub_6EF580` and that the build-style Lua issue callbacks
   * invoke on the count argument.
   */
  [[nodiscard]] int ResolveBuildCountArgument(
    LuaPlus::LuaState* const state,
    LuaPlus::LuaStackObject countObject,
    const char* const functionName
  )
  {
    lua_State* const rawState = countObject.m_state ? countObject.m_state->m_state : nullptr;
    if (rawState == nullptr) {
      return 0;
    }

    if (lua_type(rawState, countObject.m_stackIndex) != LUA_TNUMBER) {
      const LuaPlus::LuaObject countValue(countObject);
      LuaPlus::LuaState::Error(state, kLuaInvalidCountWarning, functionName, countValue.TypeName());
    }

    if (lua_type(rawState, countObject.m_stackIndex) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&countObject, "integer");
    }

    return static_cast<int>(lua_tonumber(rawState, countObject.m_stackIndex));
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

  /**
   * Local mirror of `CameraImpl.cpp`'s anonymous helper: build one MSVC RB-tree
   * head sentinel for `Moho::SSelectionSetUserEntity` and pre-link its
   * Left/Right/Parent lanes back to itself, matching the engine layout used by
   * the FUN_007AE1B0 (`WeakSet_UserEntity::Add`) insertion path.
   */
  [[nodiscard]] moho::SSelectionNodeUserEntity* AllocateLocalSelectionSetHead()
  {
    auto* const head =
      static_cast<moho::SSelectionNodeUserEntity*>(::operator new(sizeof(moho::SSelectionNodeUserEntity)));
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mKey = 0u;
    head->mEnt.mOwnerLinkSlot = nullptr;
    head->mEnt.mNextOwner = nullptr;
    head->mColor = 1u;
    head->mIsSentinel = 1u;
    head->pad_1A[0] = 0u;
    head->pad_1A[1] = 0u;
    return head;
  }

  void InitializeLocalSelectionSet(moho::SSelectionSetUserEntity& set)
  {
    set.mAllocProxy = nullptr;
    set.mHead = AllocateLocalSelectionSetHead();
    set.mSize = 0u;
    set.mSizeMirrorOrUnused = 0u;
  }

  /**
   * Mirrors the engine teardown chain at FUN_007AF740 (`sub_7AF740` —
   * `EraseRange` over the full tree) followed by `operator delete` on the head
   * sentinel.
   */
  void DestroyLocalSelectionSet(moho::SSelectionSetUserEntity& set) noexcept
  {
    moho::SSelectionNodeUserEntity* const head = set.mHead;
    if (head == nullptr) {
      return;
    }

    moho::SSelectionNodeUserEntity* outNode = nullptr;
    (void)set.EraseRange(&outNode, head->mLeft, head);
    ::operator delete(head);
    set.mAllocProxy = nullptr;
    set.mHead = nullptr;
    set.mSize = 0u;
    set.mSizeMirrorOrUnused = 0u;
  }

  class ScopedLocalSelectionSet final
  {
  public:
    ScopedLocalSelectionSet() { InitializeLocalSelectionSet(mSet); }
    ~ScopedLocalSelectionSet() { DestroyLocalSelectionSet(mSet); }

    ScopedLocalSelectionSet(const ScopedLocalSelectionSet&) = delete;
    ScopedLocalSelectionSet& operator=(const ScopedLocalSelectionSet&) = delete;

    [[nodiscard]] moho::SSelectionSetUserEntity& get() noexcept { return mSet; }
    [[nodiscard]] const moho::SSelectionSetUserEntity& get() const noexcept { return mSet; }

  private:
    moho::SSelectionSetUserEntity mSet{};
  };

  // ---- UISelectionByCategory support (FUN_008662B0 / FUN_00865590) ----

  // Selection weak-set nodes store `&UserEntity::mIUnitChainHead` (offset 0x08)
  // in their owner-link slot; a null slot or the tombstone sentinel `(void*)8`
  // decodes to null. Mirrors the file's existing decodeSelectionSlot lambda.
  [[nodiscard]] moho::UserEntity* DecodeSelectionEntity(const moho::SSelectionWeakRefUserEntity& weakRef) noexcept
  {
    constexpr std::uintptr_t kOwnerLinkOffset = offsetof(moho::UserEntity, mIUnitChainHead);
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
    if (raw == 0u || raw == kOwnerLinkOffset) {
      return nullptr;
    }
    return reinterpret_cast<moho::UserEntity*>(raw - kOwnerLinkOffset);
  }

  // Camera frustum-list entries use the identical owner-link encoding.
  [[nodiscard]] moho::UserEntity* DecodeFrustumEntity(const moho::CameraUserEntityWeakRef& weakRef) noexcept
  {
    constexpr std::uintptr_t kOwnerLinkOffset = offsetof(moho::UserEntity, mIUnitChainHead);
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
    if (raw == 0u || raw == kOwnerLinkOffset) {
      return nullptr;
    }
    return reinterpret_cast<moho::UserEntity*>(raw - kOwnerLinkOffset);
  }

  // File-static camera-focus cycle state for CycleCameraFocusOnSelection.
  // Decompiler globals: dword_10C4424 (3-state 0/1/2) + stru_10C4418 (a
  // persistent selection snapshot, lazily constructed).
  int gCameraFocusCycleState = 0;
  moho::SSelectionSetUserEntity* gCameraFocusCycleSelection = nullptr;

  [[nodiscard]] const Wm3::Box3f* SelectionEntityMeshBox(moho::UserEntity* const entity)
  {
    moho::MeshInstance* const meshInstance = (entity != nullptr) ? entity->mMeshInstance : nullptr;
    if (meshInstance != nullptr) {
      meshInstance->UpdateInterpolatedFields();
      return &meshInstance->box;
    }
    return &moho::Invalid<Wm3::Box3f>();
  }

  /**
   * Address: 0x00865590 (FUN_00865590, sub_865590, CycleCameraFocusOnSelection)
   *
   * What it does:
   * Three-state camera focus cycler over a selection weak-set. State 0 snapshots
   * the selection and arms the cycle; state 1 frames all selected entities with a
   * zoomed multi-target; state 2 frames the first entity's mesh box then releases
   * tracking. Advances the static cycle state each call.
   */
  void CycleCameraFocusOnSelection(moho::SSelectionSetUserEntity* const selection, moho::CameraImpl* const camera)
  {
    if (gCameraFocusCycleState == 0) {
      gCameraFocusCycleState = 1;
      if (gCameraFocusCycleSelection == nullptr) {
        gCameraFocusCycleSelection = new moho::SSelectionSetUserEntity{};
        InitializeLocalSelectionSet(*gCameraFocusCycleSelection);
      }
      if (selection != gCameraFocusCycleSelection) {
        moho::SSelectionNodeUserEntity* eraseCursor = nullptr;
        (void)gCameraFocusCycleSelection->EraseRange(
          &eraseCursor, gCameraFocusCycleSelection->mHead->mLeft, gCameraFocusCycleSelection->mHead
        );
        for (moho::SSelectionNodeUserEntity* node =
               moho::SSelectionSetUserEntity::find(selection, selection->mHead->mLeft, &node);
             node != selection->mHead;) {
          if (moho::UserEntity* const entity = DecodeSelectionEntity(node->mEnt); entity != nullptr) {
            moho::SSelectionSetUserEntity::AddResult addResult{};
            (void)moho::SSelectionSetUserEntity::Add(&addResult, gCameraFocusCycleSelection, entity);
          }
          moho::SSelectionSetUserEntity::Iterator_inc(&node);
          node = moho::SSelectionSetUserEntity::find(selection, node, &node);
        }
      }
      return;
    }

    if (gCameraFocusCycleState == 1) {
      const float targetZoom = camera->CameraGetTargetZoom();
      camera->TargetEntities(*selection, false, targetZoom, 0.0f);
      gCameraFocusCycleState = 2;
      return;
    }

    // gCameraFocusCycleState == 2: frame the first selected entity's mesh box.
    moho::SSelectionNodeUserEntity* firstNode = nullptr;
    firstNode = moho::SSelectionSetUserEntity::find(selection, selection->mHead->mLeft, &firstNode);
    const Wm3::Box3f orientedBox(*SelectionEntityMeshBox(DecodeSelectionEntity(firstNode->mEnt)));
    Wm3::AxisAlignedBox3f frameBox{};
    orientedBox.ComputeAABB(frameBox.Min, frameBox.Max);

    camera->TargetBox(frameBox, 0.0f);
    camera->TargetNothing();
    gCameraFocusCycleState = 1;
  }

  /**
   * Address: 0x008662B0 (FUN_008662B0, sub_8662B0, SelectUnitsByCategory)
   *
   * What it does:
   * Core of UISelectionByCategory. Gathers candidate units (camera frustum or the
   * spatial DB), filters by selectability / focus-army ownership / optional idle /
   * category (+ optional engineer/command exclusion), then either replaces or
   * extends the world selection. Optionally frames the result with the camera.
   */
  void SelectUnitsByCategory(
    moho::CWldSession* const session,
    moho::CameraImpl* const camera,
    const char* const categoryExpr,
    const bool addToSelection,        // a4
    const bool inViewFrustum,         // a5
    const bool nearestToMouse,        // a6
    const bool mustBeIdle,            // a7
    const bool doCameraTarget,        // a8
    const bool excludeEngineerCommand // a9
  )
  {
    // ---- Gather candidate entities ----
    gpg::fastvector<moho::UserEntity*> gathered{};
    if (inViewFrustum && camera != nullptr) {
      moho::CameraFrustumUserEntityList* const frustumList = camera->GetArmyUnitsInFrustum();
      for (moho::CameraUserEntityWeakRef* ref = frustumList->mStart; ref != frustumList->mFinish; ++ref) {
        if (moho::UserEntity* const entity = DecodeFrustumEntity(*ref); entity != nullptr) {
          gathered.push_back(entity);
        }
      }
    } else {
      auto* const spatialDb = static_cast<moho::SpatialDB_MeshInstance*>(session->GetEntitySpatialDbStorage());
      (void)spatialDb->Collect(gathered, moho::ENTITYTYPE_Unit);
    }

    // Parse the category expression once (RRuleGameRules slot 23).
    const moho::CategoryWordRangeView parsedCategory = session->mRules->ParseEntityCategory(categoryExpr);

    // Result set: start empty, optionally seed with the current selection.
    ScopedLocalSelectionSet resultGuard{};
    moho::SSelectionSetUserEntity& resultSet = resultGuard.get();
    if (addToSelection && &resultSet != &session->mSelection) {
      for (moho::SSelectionNodeUserEntity* seedNode =
             moho::SSelectionSetUserEntity::find(&session->mSelection, session->mSelection.mHead->mLeft, &seedNode);
           seedNode != session->mSelection.mHead;) {
        if (moho::UserEntity* const seedEntity = DecodeSelectionEntity(seedNode->mEnt); seedEntity != nullptr) {
          moho::SSelectionSetUserEntity::AddResult addResult{};
          (void)moho::SSelectionSetUserEntity::Add(&addResult, &resultSet, seedEntity);
        }
        moho::SSelectionSetUserEntity::Iterator_inc(&seedNode);
        seedNode = moho::SSelectionSetUserEntity::find(&session->mSelection, seedNode, &seedNode);
      }
    }

    // ---- Per-candidate filter ----
    const moho::UserArmy* const focusArmy = session->GetFocusArmy();

    moho::UserEntity* nearestEntity = nullptr;
    float nearestDistance = std::numeric_limits<float>::infinity();

    for (moho::UserEntity* const candidate : gathered) {
      moho::UserUnit* const unit = candidate->IsUserUnit();
      if (unit == nullptr) {
        continue;
      }

      // Selectable AND (owned by focus army OR cheat-select).
      if (!unit->Select()) {
        continue;
      }
      const bool ownedByFocusArmy = (focusArmy == candidate->mArmy);
      if (!ownedByFocusArmy && !(moho::UI_SelectAnything && session->IsCheatsEnabled)) {
        continue;
      }

      // Optional idle filter: not busy AND no queued commands.
      if (mustBeIdle) {
        if (unit->mSelectableOverride /* +0x1A2: UI busy/not-idle gate */) {
          continue;
        }
        if (moho::GetUserUnitManagerQueueSize(unit->mManager) != 0) {
          continue;
        }
      }

      // Category test (open-coded bitset in the binary -> EntityCategory::HasBlueprint).
      const moho::IUnit* const iunit = moho::GetIUnitBridge(unit);
      if (!moho::EntityCategory::HasBlueprint(iunit->GetBlueprint(), &parsedCategory)) {
        continue;
      }

      // Optional engineer/command exclusion (a9).
      if (excludeEngineerCommand) {
        const msvc8::string engineerCategory("ENGINEER");
        const msvc8::string commandCategory("COMMAND");
        if (candidate->IsInCategory(engineerCategory) || candidate->IsInCategory(commandCategory)) {
          continue;
        }
      }

      if (nearestToMouse) {
        // Keep only the single unit nearest the cursor world position.
        const Wm3::Vec3f& unitPos = iunit->GetPosition();
        const float dx = unitPos.x - session->CursorWorldPos.x;
        const float dy = unitPos.y - session->CursorWorldPos.y;
        const float dz = unitPos.z - session->CursorWorldPos.z;
        const float distance = std::sqrt(dx * dx + dy * dy + dz * dz);
        if (nearestDistance > distance) {
          nearestEntity = candidate;
          nearestDistance = distance;
        }
      } else if (!iunit->IsUnitState(moho::UNITSTATE_BeingUpgraded)) {
        // Add every passing unit (skip units mid-upgrade).
        moho::SSelectionSetUserEntity::AddResult addResult{};
        (void)moho::SSelectionSetUserEntity::Add(&addResult, &resultSet, candidate);
      }
    }

    if (nearestToMouse && nearestEntity != nullptr) {
      moho::SSelectionSetUserEntity::AddResult addResult{};
      (void)moho::SSelectionSetUserEntity::Add(&addResult, &resultSet, nearestEntity);
    }

    // ---- Optional camera framing of the result ----
    moho::SSelectionNodeUserEntity* probeNode = nullptr;
    probeNode = moho::SSelectionSetUserEntity::find(&resultSet, resultSet.mHead->mLeft, &probeNode);
    if (probeNode != resultSet.mHead && doCameraTarget && camera != nullptr) {
      if (mustBeIdle) {
        CycleCameraFocusOnSelection(&resultSet, camera);
      } else if (resultSet.size() == 1) {
        moho::SSelectionNodeUserEntity* firstNode = nullptr;
        firstNode = moho::SSelectionSetUserEntity::find(&resultSet, resultSet.mHead->mLeft, &firstNode);
        camera->TargetEntityBox(DecodeSelectionEntity(firstNode->mEnt), 0.0f);
      } else {
        // Combined AABB over all selected entities, then frame it.
        Wm3::AxisAlignedBox3f combined = moho::Empty<Wm3::AxisAlignedBox3f>();
        for (moho::SSelectionNodeUserEntity* node =
               moho::SSelectionSetUserEntity::find(&resultSet, resultSet.mHead->mLeft, &node);
             node != resultSet.mHead;) {
          const Wm3::Box3f orientedBox(*SelectionEntityMeshBox(DecodeSelectionEntity(node->mEnt)));
          Wm3::AxisAlignedBox3f entityBox{};
          orientedBox.ComputeAABB(entityBox.Min, entityBox.Max);

          if (entityBox.Min.x <= combined.Min.x) { combined.Min.x = entityBox.Min.x; }
          if (entityBox.Min.y <= combined.Min.y) { combined.Min.y = entityBox.Min.y; }
          if (entityBox.Min.z <= combined.Min.z) { combined.Min.z = entityBox.Min.z; }
          if (entityBox.Max.x >  combined.Max.x) { combined.Max.x = entityBox.Max.x; }
          if (entityBox.Max.y >  combined.Max.y) { combined.Max.y = entityBox.Max.y; }
          if (entityBox.Max.z >  combined.Max.z) { combined.Max.z = entityBox.Max.z; }

          moho::SSelectionSetUserEntity::Iterator_inc(&node);
          node = moho::SSelectionSetUserEntity::find(&resultSet, node, &node);
        }

        camera->TargetBox(combined, 0.0f);
        camera->TargetNothing();
      }
    }

    session->SetSelection(resultSet);
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

    // GetScriptIndex derives the formation bucket from the unit set's composition;
    // pass the set directly (type-erased) rather than punning a pointer through an
    // EFormationType lane.
    return formationDb->GetScriptIndex(formationName, &selectedUnits);
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
  int cfunc_IssueSacrificeL(LuaPlus::LuaState* state);
  int cfunc_IssueUpgrade(lua_State* luaContext);
  int cfunc_IssueScript(lua_State* luaContext);
  int cfunc_IssueScriptL(LuaPlus::LuaState* state);
  int cfunc_IssueReclaim(lua_State* luaContext);
  int cfunc_IssueReclaimL(LuaPlus::LuaState* state);
  int cfunc_IssueCapture(lua_State* luaContext);
  int cfunc_IssueCaptureL(LuaPlus::LuaState* state);
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
  int cfunc_IssueKillSelfL(LuaPlus::LuaState* state);
  int cfunc_IssueDestroySelfL(LuaPlus::LuaState* state);
  int cfunc_IssueOverChargeL(LuaPlus::LuaState* state);
  int cfunc_IssueUpgradeL(LuaPlus::LuaState* state);
  /**
   * Address: 0x006F7F10 (FUN_006F7F10, cfunc_IssueBuildFactoryL)
   *
   * What it does:
   * Parses `(unitList, factoryBlueprintId, count)`, resolves the destination
   * `RUnitBlueprint*` for the factory-build target, and issues one
   * `UNITCOMMAND_BuildFactory` per loop iteration carrying the blueprint
   * pointer through `SSTICommandIssueData::mBlueprint`.
   */
  int cfunc_IssueBuildFactoryL(LuaPlus::LuaState* state);
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
  int cfunc_IssueNukeL(LuaPlus::LuaState* state);
  int cfunc_IssueMoveL(LuaPlus::LuaState* state);
  int cfunc_IssueTeleportL(LuaPlus::LuaState* state);
  int cfunc_IssueDiveL(LuaPlus::LuaState* state);
  int cfunc_IssueFactoryAssistL(LuaPlus::LuaState* state);
  int cfunc_IssueTransportUnloadL(LuaPlus::LuaState* state);
  int cfunc_IssueTeleportToBeaconL(LuaPlus::LuaState* state);
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

    // Silo build commands (BuildSiloTactical=5 / BuildSiloNuke=6) do NOT go
    // through the command-issue pipeline. The binary iterates the live world
    // selection weak-set directly and forwards each selected entity id to the
    // sync-driver as an "add" info-pair (asm 0x84177C-0x8417F6).
    if (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical
        || commandType == EUnitCommandType::UNITCOMMAND_BuildSiloNuke) {
      // Local mirror of DecodeSelectedUserEntity / DecodeUserEntityFromSelectionSlot:
      // the weak-set stores &UserEntity::mIUnitChainHead (offset 0x08) in
      // mOwnerLinkSlot; null or the tombstone sentinel (void*)8 decode to null.
      const auto decodeSelectionSlot = [](const SSelectionWeakRefUserEntity& weakRef) -> UserEntity* {
        constexpr std::uintptr_t kSelectionOwnerLinkOffset = offsetof(UserEntity, mIUnitChainHead);
        const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(weakRef.mOwnerLinkSlot);
        if (raw == 0 || raw == kSelectionOwnerLinkOffset) {
          return nullptr;
        }
        return reinterpret_cast<UserEntity*>(raw - kSelectionOwnerLinkOffset);
      };

      const char* const commandKey = (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical)
        ? "SiloBuildTactical"
        : "SiloBuildNuke";

      SSelectionSetUserEntity& selection = session->mSelection;
      SSelectionNodeUserEntity* node = nullptr;
      node = SSelectionSetUserEntity::find(&selection, selection.mHead->mLeft, &node);
      while (node != selection.mHead) {
        if (UserEntity* const selectedEntity = decodeSelectionSlot(node->mEnt); selectedEntity != nullptr) {
          // sSimDriver global read fresh each iteration (asm reloads it in-loop).
          if (ISTIDriver* const driver = SIM_GetActiveDriver(); driver != nullptr) {
            const auto entityIdAsPtr =
              reinterpret_cast<void*>(static_cast<std::uintptr_t>(selectedEntity->mParams.mEntityId));
            driver->ProcessInfoPair(entityIdAsPtr, commandKey, "add");
          }
        }

        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
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

    // Client-side issue path: forward the current world selection weak-set to
    // the CWldSession ISSUE_Command(WeakSet) overload (asm 0x841748), NOT the
    // sim-side Sim::IssueCommand(BVSet) shortcut.
    ISSUE_Command(session->mSelection, commandIssueData, clearQueue);
    return 0;
  }

  /**
   * Address: 0x00841C10 (FUN_00841C10, cfunc_IssueBlueprintCommandL)
   *
   * What it does:
   * Parses a command lexical + a blueprint id + a repeat count (+ an optional
   * clear-queue flag) and issues that many blueprint-build commands to the
   * current world selection. Silo builds bypass the issue pipeline (per-entity
   * "add" info-pair, like cfunc_IssueCommandL); BuildFactory issues one command
   * per selected live FACTORY-category unit; every other command type issues to
   * the whole selection.
   */
  int cfunc_IssueBlueprintCommandL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 3 || argumentCount > 4) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", kIssueBlueprintCommandHelpText, 3, 4, argumentCount);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      gpg::Warnf("Attempt to call IssueBlueprintCommand before world sessions exists.");
      return 0;
    }

    // Arg 1: command lexical -> EUnitCommandType (validated by the None gate below).
    const LuaPlus::LuaStackObject commandArg(state, 1);
    const char* const commandLexical = lua_tostring(rawState, 1);
    if (commandLexical == nullptr) {
      commandArg.TypeError("string");
      return 0;
    }
    EUnitCommandType commandType = EUnitCommandType::UNITCOMMAND_None;
    TryParseUnitCommandTypeLexical(commandLexical, commandType);

    // Arg 2: blueprint id -> normalized filename -> resolved blueprint pointer.
    const LuaPlus::LuaStackObject blueprintArg(state, 2);
    const char* const blueprintLexical = lua_tostring(rawState, 2);
    if (blueprintLexical == nullptr) {
      blueprintArg.TypeError("string");
      return 0;
    }
    RResId blueprintResId{};
    gpg::STR_InitFilename(&blueprintResId.name, blueprintLexical);
    REntityBlueprint* const blueprint = session->mRules->GetEntityBlueprint(blueprintResId);

    // Arg 3: repeat count (integer).
    const LuaPlus::LuaStackObject countArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      countArg.TypeError("integer");
      return 0;
    }
    const int repeatCount = static_cast<int>(lua_tonumber(rawState, 3));

    // Arg 4 (optional): clear-queue flag; defaults to false when absent.
    bool clearQueue = false;
    if (argumentCount >= 4) {
      clearQueue = LuaPlus::LuaStackObject(state, 4).GetBoolean();
    }

    // The binary resolves the blueprint pointer, reinterprets it as a float, and
    // gates on == 0.0 (a null-pointer test); an unparsable command type is None.
    if (blueprint == nullptr || commandType == EUnitCommandType::UNITCOMMAND_None) {
      return 0;
    }

    // Silo builds bypass the command-issue pipeline (mirrors cfunc_IssueCommandL):
    // forward each selected entity id to the sync-driver as an "add" info-pair.
    if (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical
        || commandType == EUnitCommandType::UNITCOMMAND_BuildSiloNuke) {
      const char* const commandKey = (commandType == EUnitCommandType::UNITCOMMAND_BuildSiloTactical)
        ? "SiloBuildTactical"
        : "SiloBuildNuke";

      SSelectionSetUserEntity& selection = session->mSelection;
      SSelectionNodeUserEntity* node = nullptr;
      node = SSelectionSetUserEntity::find(&selection, selection.mHead->mLeft, &node);
      while (node != selection.mHead) {
        if (UserEntity* const selectedEntity = DecodeSelectionEntity(node->mEnt); selectedEntity != nullptr) {
          if (ISTIDriver* const driver = SIM_GetActiveDriver(); driver != nullptr) {
            const auto entityIdAsPtr =
              reinterpret_cast<void*>(static_cast<std::uintptr_t>(selectedEntity->mParams.mEntityId));
            driver->ProcessInfoPair(entityIdAsPtr, commandKey, "add");
          }
        }
        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
      }
      return 0;
    }

    // BuildFactory: issue `count` commands per selected live FACTORY-category
    // unit. The binary stashes the blueprint pointer bits in the command's
    // orientation quaternion w-component (a float slot), NOT in mBlueprint
    // (FUN_00841C10 branch write to mOri.w @ +0x48, distinct from the else
    // branch's mBlueprint @ +0x50).
    if (commandType == EUnitCommandType::UNITCOMMAND_BuildFactory) {
      SSTICommandIssueData factoryCommand(EUnitCommandType::UNITCOMMAND_BuildFactory);
      std::memcpy(&factoryCommand.mOri.w, &blueprint, sizeof(float));

      const msvc8::string factoryCategory("FACTORY");
      SSelectionSetUserEntity& selection = session->mSelection;
      SSelectionNodeUserEntity* node = nullptr;
      node = SSelectionSetUserEntity::find(&selection, selection.mHead->mLeft, &node);
      while (node != selection.mHead) {
        if (UserEntity* const selectedEntity = DecodeSelectionEntity(node->mEnt); selectedEntity != nullptr) {
          UserUnit* const selectedUnit = selectedEntity->IsUserUnit();
          const moho::IUnit* const factoryUnit = moho::GetIUnitBridge(selectedUnit);
          if (selectedUnit != nullptr && factoryUnit != nullptr && !factoryUnit->IsDead()
              && selectedEntity->IsInCategory(factoryCategory)) {
            ScopedLocalSelectionSet oneUnit{};
            SSelectionSetUserEntity::AddResult addResult{};
            SSelectionSetUserEntity::Add(&addResult, &oneUnit.get(), selectedEntity);
            for (int remaining = repeatCount; remaining > 0; --remaining) {
              ISSUE_Command(oneUnit.get(), factoryCommand, clearQueue);
            }
          }
        }
        SSelectionSetUserEntity::Iterator_inc(&node);
        node = SSelectionSetUserEntity::find(&selection, node, &node);
      }
      return 0;
    }

    // Every other command type: issue `count` copies to the whole selection.
    SSTICommandIssueData blueprintCommand(commandType);
    blueprintCommand.mBlueprint = static_cast<RUnitBlueprint*>(blueprint);
    for (int remaining = repeatCount; remaining > 0; --remaining) {
      ISSUE_Command(session->mSelection, blueprintCommand, clearQueue);
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

    // Binary walks the explicit unit table with a LuaTableIterator and pushes every
    // decoded value unconditionally (no null filter) into a gpg::fastvector<UserUnit*>.
    gpg::fastvector<UserUnit*> units{};
    {
      LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
      for (LuaPlus::LuaTableIterator iter(unitListObject, 1); !iter.m_isDone; iter.Next()) {
        units.push_back(SCR_FromLua_UserUnit(iter.m_valueObj, state));
      }
    }

    const LuaPlus::LuaStackObject commandArg(state, 2);
    const char* const commandLexical = lua_tostring(rawState, 2);
    if (commandLexical == nullptr) {
      commandArg.TypeError("string");
      return 0;
    }

    EUnitCommandType commandType = EUnitCommandType::UNITCOMMAND_None;
    if (!TryParseUnitCommandTypeLexical(commandLexical, commandType)
        || commandType == EUnitCommandType::UNITCOMMAND_None) {
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

    // Binary passes the SSTICommandIssueData BY VALUE to the fastvector overload of
    // Moho::ISSUE_Command (asm 0x00841B3B) — NOT via the sim BVSet path.
    ISSUE_Command(units, commandIssueData, clearQueue);
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
   * Address: 0x00840130 (FUN_00840130, cfunc_GetUnitCommandDataL)
   *
   * IDA signature:
   * int __cdecl cfunc_GetUnitCommandDataL(LuaPlus::LuaState *state);
   *
   * What it does:
   * Given a Lua table of user units, computes the intersection (across the
   * selection) of the buildable-unit category set and the union of command /
   * toggle capability masks, and returns `(commandCaps, toggleCaps, category)`.
   * For each unit the buildable set is `(blueprintEconomyCategory & armyFilter)
   * - restrictionCategory`, plus the same for every pending Upgrade command's
   * target blueprint (with the target's own blueprint-id category removed).
   */
  int cfunc_GetUnitCommandDataL(LuaPlus::LuaState* const state)
  {
    const int argc = lua_gettop(state->m_state);
    if (argc != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUnitCommandDataHelpText, 1, argc);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      gpg::Warnf("Attempt to call GetUnitCommands before world sessions exists.");
      return 0;
    }

    const LuaPlus::LuaObject unitTable(LuaPlus::LuaStackObject(state, 1));
    const int unitCount = unitTable.GetCount();

    std::uint32_t accCommandCaps = 0u;
    std::uint32_t accToggleCaps = 0u;
    bool haveAcc = false;

    EntityCategorySet accCategory{};
    accCategory.ResetToEmpty(reinterpret_cast<std::uint32_t>(session->mRules));

    for (int i = 1; i <= unitCount; ++i) {
      EntityCategorySet perUnit{};
      perUnit.ResetToEmpty(reinterpret_cast<std::uint32_t>(session->mRules));

      const LuaPlus::LuaObject unitObject = unitTable[i];
      UserUnit* const unit = GetUserUnitOptional(unitObject, state);
      if (unit != nullptr) {
        IUnit* const iunit = GetIUnitBridge(unit);
        UnitAttributes& attrs = iunit->GetAttributes();
        if (attrs.blueprint != nullptr) {
          const RUnitBlueprint* const bp = iunit->GetBlueprint();

          const auto* const economyCat = reinterpret_cast<const EntityCategorySet*>(&bp->Economy.CategoryCache);
          const UserArmy* const army = reinterpret_cast<const UserEntity*>(unit)->mArmy;
          const auto* const armyCat =
            reinterpret_cast<const EntityCategorySet*>(&army->mVarDat.mCategoryFilterSet);
          const EntityCategorySet* const restrictionCat = &attrs.restrictionCategory;

          accCommandCaps |= attrs.commandCapsMask;
          accToggleCaps |= attrs.toggleCapsMask;

          EntityCategorySet intersect{};
          (void)EntityCategory::Mul(&intersect, economyCat, armyCat);

          EntityCategorySet buildable{};
          (void)EntityCategory::Sub(&buildable, &intersect, restrictionCat);

          (void)EntityCategory::Add(&perUnit, &buildable);

          msvc8::set<const RUnitBlueprint*> upgradeTargets;
          CollectUpgradeCommandTargetBlueprints(unit, upgradeTargets);
          for (const RUnitBlueprint* const targetBp : upgradeTargets) {
            const auto* const targetEconomyCat =
              reinterpret_cast<const EntityCategorySet*>(&targetBp->Economy.CategoryCache);

            EntityCategorySet targetIntersect{};
            (void)EntityCategory::Mul(&targetIntersect, targetEconomyCat, armyCat);

            EntityCategorySet targetBuildable{};
            (void)EntityCategory::Sub(&targetBuildable, &targetIntersect, restrictionCat);

            // The binary reuses the per-unit accumulator as its scratch: it
            // OVERWRITES `perUnit` with this target's buildable set (v53 = v25),
            // then removes the target's own blueprint-id category from the rules
            // cache. Because the loop overwrites `perUnit` every iteration, the
            // accumulated per-unit set becomes the LAST upgrade target's
            // buildable set; the `Add(&perUnit, &buildable)` result above is only
            // retained when the unit has no pending Upgrade commands.
            perUnit = targetBuildable;

            const char* const bpId = targetBp->mBlueprintId.c_str();
            if (bpId != nullptr) {
              const CategoryWordRangeView* const rulesCat = session->mRules->GetEntityCategory(bpId);
              const_cast<CategoryWordRangeView*>(rulesCat)->mBits.RemoveAllFrom(&perUnit.mBits);
            }
          }
        }
      }

      if (haveAcc) {
        accCategory.mBits.IntersectWith(&perUnit.mBits);
      } else {
        accCategory = perUnit;
        haveAcc = true;
      }
    }

    LuaPlus::LuaObject commandCapsTable;
    commandCapsTable.AssignNewTable(state, 23, 0);
    int commandRow = 1;
    for (int b = 0; b < 23; ++b) {
      if (((1u << b) & accCommandCaps) != 0u) {
        moho::ERuleBPUnitCommandCaps cap = static_cast<moho::ERuleBPUnitCommandCaps>(1u << b);
        gpg::RRef capRef{};
        (void)gpg::RRef_ERuleBPUnitCommandCaps(&capRef, &cap);
        const msvc8::string lexical = capRef.GetLexical();
        commandCapsTable.SetString(commandRow, lexical.c_str());
        ++commandRow;
      }
    }
    commandCapsTable.PushStack(state);

    LuaPlus::LuaObject toggleCapsTable;
    toggleCapsTable.AssignNewTable(state, 9, 0);
    int toggleRow = 1;
    for (int b = 0; b < 9; ++b) {
      if (((1u << b) & accToggleCaps) != 0u) {
        moho::ERuleBPUnitToggleCaps cap = static_cast<moho::ERuleBPUnitToggleCaps>(1u << b);
        gpg::RRef capRef{};
        (void)gpg::RRef_ERuleBPUnitToggleCaps(&capRef, &cap);
        const msvc8::string lexical = capRef.GetLexical();
        toggleCapsTable.SetString(toggleRow, lexical.c_str());
        ++toggleRow;
      }
    }
    toggleCapsTable.PushStack(state);

    LuaPlus::LuaObject categoryObject;
    (void)func_NewEntityCategory(state, &categoryObject, &accCategory);
    categoryObject.PushStack(state);

    return 3;
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

  namespace
  {
    // Typed field view over a UI-side UserUnit for the GetRolloverInfo builders.
    // Every offset is asm-confirmed from FUN_008421F0 and matches the committed
    // UserUnitLuaRuntimeView (UserUnit.cpp). Read-only: instances are obtained by
    // reinterpret_cast over a live UserUnit, so no ctor/dtor runs on the members.
    struct RolloverUnitView
    {
      std::uint8_t pad_0000_0044[0x44];
      std::uint32_t entityId;                    // +0x44  UserEntity::mParams.mEntityId
      std::uint8_t pad_0048_0068[0x68 - 0x48];
      float health;                              // +0x68  mVariableData.mHealth
      float maxHealth;                           // +0x6C  mVariableData.mMaxHealth
      std::uint8_t pad_0070_0120[0x120 - 0x70];
      UserArmy* army;                            // +0x120
      std::uint8_t pad_0124_01A4[0x1A4 - 0x124];
      float fuelRatio;                           // +0x1A4
      float shieldRatio;                         // +0x1A8
      std::uint8_t pad_01AC_01BC[0x1BC - 0x1AC];
      float workProgress;                        // +0x1BC
      std::int32_t tacticalSiloBuildCount;       // +0x1C0
      std::int32_t nukeSiloBuildCount;           // +0x1C4
      std::int32_t tacticalSiloStorageCount;     // +0x1C8
      std::int32_t nukeSiloStorageCount;         // +0x1CC
      std::int32_t tacticalSiloMaxStorageCount;  // +0x1D0
      std::int32_t nukeSiloMaxStorageCount;      // +0x1D4
      std::uint8_t pad_01D8_01DC[0x1DC - 0x1D8];
      msvc8::string customName;                  // +0x1DC
      float producedEnergy;                      // +0x1F8  mUnitVarDat.mProduced.ENERGY
      float producedMass;                        // +0x1FC  mUnitVarDat.mProduced.MASS
      float spentEnergy;                         // +0x200  mResourcesSpent.ENERGY (consumed)
      float spentMass;                           // +0x204  mResourcesSpent.MASS
      float maintEnergy;                         // +0x208  mMaintainenceCost.ENERGY (requested)
      float maintMass;                           // +0x20C  mMaintainenceCost.MASS
      EntId focusUnitId;                         // +0x210  (mFocusUnit)
      EntId guardedUnitId;                       // +0x214  (mGuardedUnit)
      EntId targetBlipId;                        // +0x218  (mTargetBlip)
      std::uint8_t pad_021C_03E0[0x3E0 - 0x21C];
      std::uint32_t dataFlags;                   // +0x3E0  (mIntelStateFlags; 0x10=has-data, 0x08=health-valid)
    };
    static_assert(offsetof(RolloverUnitView, entityId) == 0x44, "rollover entityId @0x44");
    static_assert(offsetof(RolloverUnitView, health) == 0x68, "rollover health @0x68");
    static_assert(offsetof(RolloverUnitView, maxHealth) == 0x6C, "rollover maxHealth @0x6C");
    static_assert(offsetof(RolloverUnitView, army) == 0x120, "rollover army @0x120");
    static_assert(offsetof(RolloverUnitView, fuelRatio) == 0x1A4, "rollover fuelRatio @0x1A4");
    static_assert(offsetof(RolloverUnitView, shieldRatio) == 0x1A8, "rollover shieldRatio @0x1A8");
    static_assert(offsetof(RolloverUnitView, workProgress) == 0x1BC, "rollover workProgress @0x1BC");
    static_assert(offsetof(RolloverUnitView, tacticalSiloBuildCount) == 0x1C0, "rollover tacSiloBuild @0x1C0");
    static_assert(offsetof(RolloverUnitView, nukeSiloBuildCount) == 0x1C4, "rollover nukeSiloBuild @0x1C4");
    static_assert(offsetof(RolloverUnitView, tacticalSiloStorageCount) == 0x1C8, "rollover tacSiloStore @0x1C8");
    static_assert(offsetof(RolloverUnitView, nukeSiloStorageCount) == 0x1CC, "rollover nukeSiloStore @0x1CC");
    static_assert(offsetof(RolloverUnitView, tacticalSiloMaxStorageCount) == 0x1D0, "rollover tacSiloMax @0x1D0");
    static_assert(offsetof(RolloverUnitView, nukeSiloMaxStorageCount) == 0x1D4, "rollover nukeSiloMax @0x1D4");
    static_assert(offsetof(RolloverUnitView, customName) == 0x1DC, "rollover customName @0x1DC");
    static_assert(offsetof(RolloverUnitView, producedEnergy) == 0x1F8, "rollover producedEnergy @0x1F8");
    static_assert(offsetof(RolloverUnitView, spentEnergy) == 0x200, "rollover spentEnergy @0x200");
    static_assert(offsetof(RolloverUnitView, maintEnergy) == 0x208, "rollover maintEnergy @0x208");
    static_assert(offsetof(RolloverUnitView, focusUnitId) == 0x210, "rollover focusUnitId @0x210");
    static_assert(offsetof(RolloverUnitView, guardedUnitId) == 0x214, "rollover guardedUnitId @0x214");
    static_assert(offsetof(RolloverUnitView, targetBlipId) == 0x218, "rollover targetBlipId @0x218");
    static_assert(offsetof(RolloverUnitView, dataFlags) == 0x3E0, "rollover dataFlags @0x3E0");

    // Per-tick economy value → per-second UI rate (ds:dword_DFF31C == 10.0f).
    constexpr float kRolloverEconomyPerSecondToUiRate = 10.0f;

    [[nodiscard]] const RolloverUnitView& AsRolloverUnitView(const UserUnit* const unit) noexcept
    {
      return *reinterpret_cast<const RolloverUnitView*>(unit);
    }

    /**
     * Address: 0x008421F0 (FUN_008421F0, sub_8421F0)
     *
     * IDA signature:
     * void __usercall sub_8421F0(LuaPlus::LuaObject *out@<edi>,
     *                            Moho::UserUnit *unit@<esi>,
     *                            LuaPlus::LuaState *state);
     *
     * What it does:
     * Fills one rollover-info Lua table with full stats for a live user unit:
     * blueprint id, health/max, KILLS stat, per-second economy, silo counters,
     * fuel/shield/work ratios, the unit's own Lua object, entity id, army index
     * and encoded team color. When the +0x3E0 flag word lacks the has-unit-data
     * bit only a stubbed blueprintId / armyIndex / teamColor is written; when the
     * entity id nibble marks a being-placed entity the stat block is sentinel-filled.
     */
    void BuildUserUnitRolloverInfo(LuaPlus::LuaObject& out, UserUnit* const unit, LuaPlus::LuaState* const state)
    {
      out.AssignNewTable(state, 0, 0);

      const RolloverUnitView& view = AsRolloverUnitView(unit);
      if ((view.dataFlags & 0x10u) != 0u) {
        IUnit* const bridge = GetIUnitBridge(unit);
        out.SetString("blueprintId", bridge->GetBlueprint()->mBlueprintId.c_str());

        if ((view.dataFlags & 0x08u) != 0u) {
          out.SetNumber("health", view.health);
          out.SetNumber("maxHealth", view.maxHealth);
        }

        if ((view.entityId & 0xF0000000u) == 0x30000000u) {
          // Placeholder / being-placed entity: sentinel values.
          out.SetNumber("kills", 0.0f);
          out.SetInteger("energyConsumed", -1);
          out.SetInteger("massConsumed", -1);
          out.SetInteger("energyRequested", 0);
          out.SetInteger("massRequested", 0);
          out.SetInteger("energyProduced", -1);
          out.SetInteger("massProduced", -1);
          out.SetInteger("tacticalSiloBuildCount", 0);
          out.SetInteger("tacticalSiloStorageCount", 0);
          out.SetInteger("tacticalSiloMaxStorageCount", 0);
          out.SetInteger("nukeSiloBuildCount", 0);
          out.SetInteger("nukeSiloStorageCount", 0);
          out.SetInteger("nukeSiloMaxStorageCount", 0);
          out.SetInteger("fuelRatio", -1);
          out.SetInteger("shieldRatio", -1);
          out.SetInteger("workProgress", -1);
        } else {
          int killsDefault = 0;
          StatItem* const killsStat = bridge->GetStat("KILLS", killsDefault);
          out.SetNumber("kills", static_cast<float>(killsStat->GetInt(false)));

          out.SetInteger("energyConsumed", static_cast<int>(view.spentEnergy * kRolloverEconomyPerSecondToUiRate));
          out.SetInteger("massConsumed", static_cast<int>(view.spentMass * kRolloverEconomyPerSecondToUiRate));
          out.SetInteger("energyRequested", static_cast<int>(view.maintEnergy * kRolloverEconomyPerSecondToUiRate));
          out.SetInteger("massRequested", static_cast<int>(view.maintMass * kRolloverEconomyPerSecondToUiRate));
          out.SetInteger("energyProduced", static_cast<int>(view.producedEnergy * kRolloverEconomyPerSecondToUiRate));
          out.SetInteger("massProduced", static_cast<int>(view.producedMass * kRolloverEconomyPerSecondToUiRate));
          out.SetInteger("tacticalSiloBuildCount", view.tacticalSiloBuildCount);
          out.SetInteger("tacticalSiloStorageCount", view.tacticalSiloStorageCount);
          out.SetInteger("tacticalSiloMaxStorageCount", view.tacticalSiloMaxStorageCount);
          out.SetInteger("nukeSiloBuildCount", view.nukeSiloBuildCount);
          out.SetInteger("nukeSiloStorageCount", view.nukeSiloStorageCount);
          out.SetInteger("nukeSiloMaxStorageCount", view.nukeSiloMaxStorageCount);
          out.SetNumber("fuelRatio", view.fuelRatio);
          out.SetNumber("shieldRatio", view.shieldRatio);
          out.SetNumber("workProgress", view.workProgress);

          const LuaPlus::LuaObject unitObject = bridge->GetLuaObject();
          out.SetObject("userUnit", unitObject);

          const msvc8::string entityIdText = gpg::STR_Printf("%d", view.entityId);
          out.SetString("entityId", entityIdText.c_str());
        }

        out.SetInteger("armyIndex", static_cast<int>(view.army->mArmyIndex));
        const LuaPlus::LuaObject teamColor = SCR_EncodeColor(state, view.army->mVarDat.mPlayerColorBgra);
        out.SetObject("teamColor", teamColor);

        if (!view.customName.empty()) {
          out.SetString("customName", view.customName.c_str());
        }
      } else {
        out.SetString("blueprintId", "unknown");
        const LuaPlus::LuaObject teamColor = SCR_EncodeColor(state, view.army->mVarDat.mPlayerColorBgra);
        out.SetObject("teamColor", teamColor);
        out.SetInteger("armyIndex", static_cast<int>(view.army->mArmyIndex));
      }
    }

    /**
     * Address: 0x008427E0 (FUN_008427E0, sub_8427E0)
     *
     * IDA signature:
     * void __usercall sub_8427E0(LuaPlus::LuaState *state@<eax>,
     *                            Moho::UserUnit *unit@<edi>,
     *                            LuaPlus::LuaObject *out);
     *
     * What it does:
     * Fills one compact rollover sub-table for a focus / upgrade target unit:
     * blueprintId + health/max when the target blueprint is present and the unit
     * data flags gate (mobile → 0x08, otherwise 0x10) is satisfied; otherwise a
     * stubbed "unknown" blueprintId.
     */
    void BuildFocusUnitRolloverInfo(LuaPlus::LuaObject& out, UserUnit* const unit, LuaPlus::LuaState* const state)
    {
      out.AssignNewTable(state, 0, 0);

      IUnit* const bridge = GetIUnitBridge(unit);
      const RUnitBlueprint* const blueprint = bridge->GetBlueprint();
      const RolloverUnitView& view = AsRolloverUnitView(unit);

      bool hasBlueprintId = false;
      if (blueprint != nullptr) {
        const std::uint32_t requiredFlag = blueprint->IsMobile() ? 0x08u : 0x10u;
        hasBlueprintId = (view.dataFlags & requiredFlag) != 0u;
      }

      if (!hasBlueprintId) {
        out.SetString("blueprintId", "unknown");
        return;
      }

      out.SetString("blueprintId", blueprint->mBlueprintId.c_str());
      out.SetNumber("health", view.health);
      out.SetNumber("maxHealth", view.maxHealth);
    }

    /**
     * Address: 0x00842770 (FUN_00842770, sub_842770)
     *
     * IDA signature:
     * void __usercall sub_842770(LuaPlus::LuaObject *out@<esi>,
     *                            Moho::UserEntity *prop@<edi>,
     *                            LuaPlus::LuaState *state);
     *
     * What it does:
     * Fills one rollover sub-table for a focused prop entity: blueprintId +
     * fractionComplete, or "unknown"/0.0 when the prop has no blueprint.
     */
    void BuildFocusPropRolloverInfo(LuaPlus::LuaObject& out, UserEntity* const prop, LuaPlus::LuaState* const state)
    {
      out.AssignNewTable(state, 0, 0);

      const REntityBlueprint* const blueprint = prop->mParams.mBlueprint;
      if (blueprint != nullptr) {
        out.SetString("blueprintId", blueprint->mBlueprintId.c_str());
        out.SetNumber("fractionComplete", prop->mVariableData.mFractionComplete);
      } else {
        out.SetString("blueprintId", "unknown");
        out.SetNumber("fractionComplete", 0.0f);
      }
    }
  } // namespace

  /**
   * Address: 0x00842920 (FUN_00842920, cfunc_GetRolloverInfoL)
   *
   * IDA signature:
   * int __userpurge cfunc_GetRolloverInfoL(LuaPlus::LuaState *state@<edi>);
   *
   * What it does:
   * Builds the `GetRolloverInfo()` Lua table for the currently hovered unit:
   * fills full unit stats, then resolves the hovered unit's target-blip / focus /
   * focus-prop / guarded targets into nested tables. Pushes nil when there is no
   * in-world hovered unit. Holds a transient weak-link guard on the hovered unit
   * for the duration of the build.
   */
  int cfunc_GetRolloverInfoL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 0) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetRolloverInfoHelpText, 0, argumentCount);
    }

    CWldSession* const session = WLD_GetActiveSession();

    // Snapshot the hovered-unit weak slot and pin it with a transient guard node
    // linked into the entity's weak-owner chain (mirrors FUN_00842920 var_48 dance).
    moho::WeakObject* hoverOwner = nullptr;
    UserEntity* hoveredEntity = nullptr;
    bool inWorld = false;
    if (session != nullptr) {
      const MouseInfo& cursor = session->GetCursorInfo();
      if (cursor.mUnitHover != nullptr) {
        hoverOwner = reinterpret_cast<moho::WeakObject*>(cursor.mUnitHover);
        // The hovered UserEntity is (weak-slot value) - offsetof(UserEntity, mIUnitChainHead).
        if (reinterpret_cast<std::uintptr_t>(cursor.mUnitHover) != offsetof(UserEntity, mIUnitChainHead)) {
          hoveredEntity = reinterpret_cast<UserEntity*>(
            reinterpret_cast<char*>(cursor.mUnitHover) - offsetof(UserEntity, mIUnitChainHead));
        }
      }
      inWorld = cursor.mHitValid != 0;
    }

    moho::WeakObject::ScopedWeakLinkGuard hoverGuard(hoverOwner);

    LuaPlus::LuaObject result;

    UserUnit* hoveredUnit = nullptr;
    if (hoveredEntity != nullptr && inWorld) {
      hoveredUnit = hoveredEntity->IsUserUnit();
    }

    if (hoveredUnit == nullptr) {
      result.AssignNil(state);
    } else {
      BuildUserUnitRolloverInfo(result, hoveredUnit, state);

      const RolloverUnitView& view = AsRolloverUnitView(hoveredUnit);

      if (UserEntity* const targetEntity = session->LookupEntityId(view.targetBlipId); targetEntity != nullptr) {
        if (UserUnit* const targetUnit = targetEntity->IsUserUnit(); targetUnit != nullptr) {
          LuaPlus::LuaObject focusTable;
          BuildFocusUnitRolloverInfo(focusTable, targetUnit, state);
          result.SetObject("focus", focusTable);
        }
      } else if (UserEntity* const focusEntity = session->LookupEntityId(view.focusUnitId); focusEntity != nullptr) {
        if (UserUnit* const focusUnit = focusEntity->IsUserUnit(); focusUnit != nullptr) {
          LuaPlus::LuaObject focusTable;
          BuildUserUnitRolloverInfo(focusTable, focusUnit, state);
          // The upgrade/focus key is chosen from the HOVERED unit's state, not the focus unit's.
          IUnit* const hoveredBridge = GetIUnitBridge(hoveredUnit);
          if (hoveredBridge->IsUnitState(UNITSTATE_Upgrading)) {
            result.SetObject("focusUpgrade", focusTable);
          } else {
            result.SetObject("focus", focusTable);
          }
        } else if ((view.focusUnitId & 0xF0000000u) == 0x20000000u) {
          LuaPlus::LuaObject propTable;
          BuildFocusPropRolloverInfo(propTable, focusEntity, state);
          result.SetObject("focusProp", propTable);
        }
      } else if (UserEntity* const guardedEntity = session->LookupEntityId(view.guardedUnitId); guardedEntity != nullptr) {
        if (UserUnit* const guardedUnit = guardedEntity->IsUserUnit(); guardedUnit != nullptr) {
          LuaPlus::LuaObject guardedTable;
          BuildUserUnitRolloverInfo(guardedTable, guardedUnit, state);
          result.SetObject("guarded", guardedTable);
        }
      }
    }

    result.PushStack(state);
    return 1;
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
   * Address: 0x00866DB0 (FUN_00866DB0, cfunc_UISelectionByCategoryL)
   *
   * What it does:
   * Lua worker for UISelectionByCategory(expression, addToCurSel, inViewFrustum,
   * nearestToMouse, mustBeIdle). Validates 5 args, resolves the world camera, and
   * dispatches SelectUnitsByCategory (camera-target / engineer-exclusion are
   * always off from Lua). Emits a localized error when there is no active session.
   */
  int cfunc_UISelectionByCategoryL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 5) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kUISelectionByCategoryHelpText, 5, argumentCount);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      const msvc8::string noSessionText = Loc(USER_GetLuaState(), "<LOC _No_session>");
      CON_Printf(noSessionText.c_str());
      return 0;
    }

    const char* const categoryExpr = lua_tostring(rawState, 1);
    if (categoryExpr == nullptr) {
      LuaPlus::LuaStackObject categoryArg(state, 1);
      LuaPlus::LuaStackObject::TypeError(&categoryArg, "string");
    }

    // Decompiler bind order: arg5=mustBeIdle, arg4=nearestToMouse, arg3=inViewFrustum, arg2=addToCurSel.
    LuaPlus::LuaStackObject mustBeIdleArg(state, 5);
    const bool mustBeIdle = mustBeIdleArg.GetBoolean();
    LuaPlus::LuaStackObject nearestToMouseArg(state, 4);
    const bool nearestToMouse = nearestToMouseArg.GetBoolean();
    LuaPlus::LuaStackObject inViewFrustumArg(state, 3);
    const bool inViewFrustum = inViewFrustumArg.GetBoolean();
    LuaPlus::LuaStackObject addToSelectionArg(state, 2);
    const bool addToSelection = addToSelectionArg.GetBoolean();

    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const camera = cameraManager->GetCamera("WorldCamera");

    SelectUnitsByCategory(
      session,
      camera,
      categoryExpr,
      addToSelection,  // a4
      inViewFrustum,   // a5
      nearestToMouse,  // a6
      mustBeIdle,      // a7
      false,           // a8 doCameraTarget (no Lua arg)
      false            // a9 excludeEngineerCommand (no Lua arg)
    );
    return 0;
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
   * Address: 0x00866FC0 (FUN_00866FC0, cfunc_UISelectAndZoomToL)
   *
   * What it does:
   * Validates `UISelectAndZoomTo(userunit,[seconds])` from Lua. When the world
   * session is live and a `WorldCamera` exists, resolves the argument to a
   * `UserUnit`, replaces the active selection with the single-entity set, and
   * dispatches `CameraImpl::TargetEntityBox(unit, seconds)` to frame the
   * entity. Reports localized "No session" or the literal "No world camera
   * found." line via `CON_Printf` for the missing-prerequisite paths.
   */
  int cfunc_UISelectAndZoomToL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kUISelectAndZoomToHelpText, 1, 2, argumentCount
      );
    }

    UserUnit* unit = nullptr;
    {
      const LuaPlus::LuaObject userUnitObject(LuaPlus::LuaStackObject(state, 1));
      unit = SCR_FromLua_UserUnit(userUnitObject, state);
    }

    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr) {
      const msvc8::string noSessionText = Loc(USER_GetLuaState(), "<LOC _No_session>");
      CON_Printf("%s", noSessionText.c_str());
      return 0;
    }

    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const camera =
      (cameraManager != nullptr) ? cameraManager->GetCamera("WorldCamera") : nullptr;
    if (camera == nullptr) {
      CON_Printf("UISelectAndZoomTo: No world camera found.");
      return 0;
    }

    ScopedLocalSelectionSet selectionGuard{};
    SSelectionSetUserEntity& selection = selectionGuard.get();
    SSelectionSetUserEntity::AddResult addResult{};
    (void)SSelectionSetUserEntity::Add(
      &addResult,
      &selection,
      reinterpret_cast<UserEntity*>(unit)
    );

    session->SetSelection(selection);

    float seconds = 0.0f;
    if (lua_gettop(rawState) == 2) {
      const LuaPlus::LuaStackObject secondsArg(state, 2);
      seconds = static_cast<float>(secondsArg.GetNumber());
    }

    camera->TargetEntityBox(reinterpret_cast<UserEntity*>(unit), seconds);
    return 0;
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
   * Address: 0x00867240 (FUN_00867240, cfunc_UIZoomToL)
   *
   * IDA signature:
   * int __usercall cfunc_UIZoomToL@<eax>(LuaPlus::LuaState *state@<ebx>);
   *
   * What it does:
   * Implements `UIZoomTo(units,[seconds])`. Validates arg count (1..2). When the
   * world session is live and a `WorldCamera` exists, walks the Lua unit table,
   * resolves each element via `GetUserUnitOptional`, and accumulates the
   * world-space XZ bounds plus the Y centroid over all resolved units. When at
   * least one unit contributed, builds a world-space AABB centered on the XZ
   * min/max and the average Y, expanded by a fixed 20-unit margin on every face
   * (half-extent = 0.5 * max(spanX, spanZ)), and frames it through
   * `CameraImpl::TargetBox(box, seconds)` followed by `TargetNothing()`.
   * `seconds` defaults to 0 and is read from arg 2 when present. Reports the
   * localized "<LOC _No_session>" line when no session is active and
   * "UISelectAndZoomTo: No world camera found." when the world camera is missing.
   */
  int cfunc_UIZoomToL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected between %d and %d args, but got %d",
        kUIZoomToHelpText, 1, 2, argumentCount
      );
    }

    if (WLD_GetActiveSession() == nullptr) {
      const msvc8::string noSessionText = Loc(USER_GetLuaState(), "<LOC _No_session>");
      CON_Printf("%s", noSessionText.c_str());
      return 0;
    }

    RCamManager* const cameraManager = CAM_GetManager();
    CameraImpl* const camera = cameraManager->GetCamera("WorldCamera");
    if (camera == nullptr) {
      CON_Printf("UISelectAndZoomTo: No world camera found.");
      return 0;
    }

    const LuaPlus::LuaObject unitTable(LuaPlus::LuaStackObject(state, 1));
    if (!unitTable.IsTable() || unitTable.GetCount() <= 0) {
      return 0;
    }

    constexpr float kPositiveInfinity = std::numeric_limits<float>::infinity();
    constexpr float kNegativeInfinity = -std::numeric_limits<float>::infinity();
    constexpr float kBoxMargin = 20.0f;

    float minX = kPositiveInfinity;
    float maxX = kNegativeInfinity;
    float minZ = kPositiveInfinity;
    float maxZ = kNegativeInfinity;
    float sumY = 0.0f;
    float count = 0.0f;

    const int unitCount = unitTable.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = unitTable[unitIndex];
      UserUnit* const unit = GetUserUnitOptional(unitObject, state);
      if (unit == nullptr) {
        continue;
      }

      const Wm3::Vec3f& position = GetIUnitBridge(unit)->GetPosition();
      minZ = std::min(minZ, position.z);
      maxZ = std::max(maxZ, position.z);
      minX = std::min(minX, position.x);
      maxX = std::max(maxX, position.x);
      sumY += position.y;
      count += 1.0f;
    }

    if (count <= 0.0f) {
      return 0;
    }

    const float averageY = sumY / count;
    const float spanX = maxX - minX;
    const float spanZ = maxZ - minZ;
    const float halfExtent = std::max(spanX, spanZ) * 0.5f;

    Wm3::AxisAlignedBox3f targetBox{};
    targetBox.Min.x = minX - kBoxMargin;
    targetBox.Min.y = (averageY - halfExtent) - kBoxMargin;
    targetBox.Min.z = minZ - kBoxMargin;
    targetBox.Max.x = maxX + kBoxMargin;
    targetBox.Max.y = (averageY + halfExtent) + kBoxMargin;
    targetBox.Max.z = maxZ + kBoxMargin;

    float seconds = 0.0f;
    if (lua_gettop(rawState) == 2) {
      const LuaPlus::LuaStackObject secondsArg(state, 2);
      seconds = static_cast<float>(secondsArg.GetNumber());
    }

    camera->TargetBox(targetBox, seconds);
    camera->TargetNothing();
    return 0;
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
   * Address: 0x008472F0 (FUN_008472F0, cfunc_GetActiveBuildTemplateL)
   *
   * What it does:
   * Publishes the active world-session build-template payload as one Lua array
   * `{xSpan, zSpan, {bpId, buildOrder, x, z}...}`.
   */
  int cfunc_GetActiveBuildTemplateL(LuaPlus::LuaState* const state)
  {
    CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr) {
      return 0;
    }

    LuaPlus::LuaObject resultTable;
    resultTable.AssignNewTable(state, 0, 0);

    float templateSpanZ = 0.0f;
    float templateSpanX = 0.0f;
    SBuildTemplateBuffer activeTemplate{};
    session->GetActiveBuildTemplate(&templateSpanZ, &templateSpanX, &activeTemplate);

    if (activeTemplate.mStart != activeTemplate.mFinish) {
      resultTable.SetNumber(1, templateSpanX);
      resultTable.SetNumber(2, templateSpanZ);

      std::int32_t nextResultIndex = 3;
      for (const SBuildTemplateInfo* entry = activeTemplate.mStart; entry != activeTemplate.mFinish; ++entry) {
        LuaPlus::LuaObject entryTable;
        entryTable.AssignNewTable(state, 0, 0);
        entryTable.SetString(1, entry->mBlueprintId.c_str());
        entryTable.SetInteger(2, entry->mBuildOrder);
        entryTable.SetNumber(3, entry->mPos.x);
        entryTable.SetNumber(4, entry->mPos.z);
        resultTable.SetObject(nextResultIndex, entryTable);
        ++nextResultIndex;
      }
    }

    resultTable.PushStack(state);

    for (SBuildTemplateInfo* entry = activeTemplate.mStart; entry != activeTemplate.mFinish; ++entry) {
      entry->~SBuildTemplateInfo();
    }
    if (activeTemplate.mStart != nullptr && activeTemplate.mStart != activeTemplate.mOriginalStart) {
      ::operator delete[](activeTemplate.mStart);
      activeTemplate.mStart = activeTemplate.mOriginalStart;
      activeTemplate.mCapacity =
        reinterpret_cast<SBuildTemplateInfo*>(activeTemplate.mInlineStorage + sizeof(activeTemplate.mInlineStorage));
    }
    activeTemplate.mFinish = activeTemplate.mStart;

    return 1;
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
   * Address: 0x008475E0 (FUN_008475E0, cfunc_SetActiveBuildTemplateL)
   *
   * What it does:
   * Parses one Lua build-template table `{xSpan, zSpan, {bpId, buildOrder, x, z}...}`,
   * assembles the entries into a build-template buffer, and installs it as the
   * active world-session build template together with its X/Z spans (only when at
   * least one valid entry was parsed). Malformed template/entry tables are reported
   * via gpg::Warnf and skipped.
   */
  int cfunc_SetActiveBuildTemplateL(LuaPlus::LuaState* const state)
  {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kSetActiveBuildTemplateHelpText, 1, argumentCount);
    }

    CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr) {
      return 0;
    }

    const LuaPlus::LuaObject buildTemplate(LuaPlus::LuaStackObject(state, 1));
    if (!buildTemplate.IsTable() || buildTemplate.GetCount() < 3) {
      gpg::Warnf("Build template error! Not a table or insufficient members");
      return 0;
    }

    SBuildTemplateBuffer templates;
    templates.InitInlineStorage();

    const float templateSpanX = static_cast<float>(buildTemplate[1].GetNumber());
    const float templateSpanZ = static_cast<float>(buildTemplate[2].GetNumber());

    const int entryCount = buildTemplate.GetCount();
    for (int entryIndex = 3; entryIndex <= entryCount; ++entryIndex) {
      const LuaPlus::LuaObject entryObject = buildTemplate[entryIndex];
      if (!entryObject.IsTable() || entryObject.GetCount() < 4) {
        gpg::Warnf("Template info error! Not a table or insufficient members");
        continue;
      }

      SBuildTemplateInfo info{};
      info.mBlueprintId = entryObject[1].GetString();
      info.mBuildOrder = entryObject[2].GetInteger();
      info.mPos.x = static_cast<float>(entryObject[3].GetNumber());
      info.mPos.z = static_cast<float>(entryObject[4].GetNumber());
      info.mPos.y = 0.0f;

      templates.PushBack(info);
    }

    if (!templates.Empty()) {
      session->SetActiveBuildTemplate(templates, templateSpanX, templateSpanZ);
    }

    templates.DestroyStorage();
    return 0;
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
   * Address: 0x006F4500 (FUN_006F4500, cfunc_IssueTacticalL)
   *
   * What it does:
   * Parses `(unitList, target)`, filters tactical-capable units, resolves the
   * target payload, and queues `UNITCOMMAND_Tactical` on the selection.
   */
  int cfunc_IssueTacticalL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueTacticalHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueTacticalHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Tactical)) {
      return 0;
    }

    CAiTarget target{};
    target.SetTarget(state, kIssueTacticalHelpText, LuaPlus::LuaStackObject(state, 2));

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Tactical);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F4200 (FUN_006F4200, cfunc_IssueNuke)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueNukeL`.
   */
  int cfunc_IssueNuke(lua_State* const luaContext)
  {
    return cfunc_IssueNukeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F4270 (FUN_006F4270, cfunc_IssueNukeL)
   *
   * What it does:
   * Parses `(unitList, target)`, filters nuke-capable units, resolves the
   * target payload, and queues `UNITCOMMAND_Nuke` on the selection.
   */
  int cfunc_IssueNukeL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueNukeHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueNukeHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Nuke)) {
      return 0;
    }

    CAiTarget target{};
    target.SetTarget(state, kIssueNukeHelpText, LuaPlus::LuaStackObject(state, 2));

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Nuke);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F4720 (FUN_006F4720, cfunc_IssueTeleport)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueTeleportL`.
   */
  int cfunc_IssueTeleport(lua_State* const luaContext)
  {
    return cfunc_IssueTeleportL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F4790 (FUN_006F4790, cfunc_IssueTeleportL)
   *
   * What it does:
   * Parses `(unitList, target)`, filters teleport-capable units, resolves the
   * target payload, and queues `UNITCOMMAND_Teleport` on the selection.
   */
  int cfunc_IssueTeleportL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueTeleportHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueTeleportHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Teleport)) {
      return 0;
    }

    CAiTarget target{};
    target.SetTarget(state, kIssueTeleportHelpText, LuaPlus::LuaStackObject(state, 2));

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Teleport);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F2660 (FUN_006F2660, cfunc_IssueMove)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueMoveL`.
   */
  int cfunc_IssueMove(lua_State* const luaContext)
  {
    return cfunc_IssueMoveL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F26D0 (FUN_006F26D0, cfunc_IssueMoveL)
   *
   * What it does:
   * Parses `(unitList, target)`, filters move-capable units, validates the
   * target point, issues `UNITCOMMAND_Move`, and returns the created Lua
   * command object (or `nil` when no command is issued).
   */
  int cfunc_IssueMoveL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueMoveHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueMoveHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Move)) {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    CAiTarget target{};
    target.SetTarget(state, kIssueMoveHelpText, LuaPlus::LuaStackObject(state, 2));
    if (!IsValidVector3f(target.position) || target.targetType == EAiTargetType::AITARGET_None) {
      LuaPlus::LuaState::Error(state, kIssueMoveInvalidTargetError);
    }

    Sim* const sim = lua_getglobaluserdata(rawState);

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

    issuedCommand->mArgs.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006F2030 (FUN_006F2030, cfunc_IssueDive)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueDiveL`.
   */
  int cfunc_IssueDive(lua_State* const luaContext)
  {
    return cfunc_IssueDiveL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F20A0 (FUN_006F20A0, cfunc_IssueDiveL)
   *
   * What it does:
   * Parses one `(unitList)` argument and queues `UNITCOMMAND_Dive` on the live
   * units (no capability filter), returning the created Lua command object or
   * `nil` when no command is issued.
   */
  int cfunc_IssueDiveL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueDiveHelpText, 1, argumentCount);
    }

    // The dive command object is constructed before the unit list is parsed,
    // mirroring the binary's ordering (FUN_006F20A0).
    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Dive);

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueDiveHelpText);

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(units);

    CUnitCommand* const issuedCommand = IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    if (issuedCommand != nullptr) {
      issuedCommand->mArgs.PushStack(state);
    } else {
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
    }
    return 1;
  }

  /**
   * Address: 0x006F33A0 (FUN_006F33A0, cfunc_IssueFactoryAssist)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueFactoryAssistL`.
   */
  int cfunc_IssueFactoryAssist(lua_State* const luaContext)
  {
    return cfunc_IssueFactoryAssistL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F3410 (FUN_006F3410, cfunc_IssueFactoryAssistL)
   *
   * What it does:
   * Parses `(unitList, targetEntity)`, keeps only the factories able to guard,
   * resolves the assist target entity, and queues `UNITCOMMAND_Guard` on the
   * filtered factories.
   */
  int cfunc_IssueFactoryAssistL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueFactoryAssistHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueFactoryAssistHelpText);

    SEntitySetTemplateUnit selectedFactories{};
    if (!FilterFactoryUnitsByCommandCap(
          sourceUnits, selectedFactories, static_cast<std::uint32_t>(RULEUCC_Guard))) {
      return 0;
    }

    CAiTarget target{};
    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const assistTarget = SCR_FromLua_Entity(targetObject, state);
    target.UpdateTarget(assistTarget);

    Sim* const sim = lua_getglobaluserdata(rawState);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Guard);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, selectedFactories, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F7530 (FUN_006F7530, cfunc_IssueTransportUnload)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueTransportUnloadL`.
   */
  int cfunc_IssueTransportUnload(lua_State* const luaContext)
  {
    return cfunc_IssueTransportUnloadL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F75A0 (FUN_006F75A0, cfunc_IssueTransportUnloadL)
   *
   * What it does:
   * Parses `(unitList, target)`, filters transport-capable units, resolves the
   * target to a ground-gun position, and queues `UNITCOMMAND_TransportUnloadUnits`
   * on the selection.
   */
  int cfunc_IssueTransportUnloadL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueTransportUnloadHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueTransportUnloadHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Transport)) {
      return 0;
    }

    CAiTarget target{};
    target.SetTarget(state, kIssueTransportUnloadHelpText, LuaPlus::LuaStackObject(state, 2));
    const Wm3::Vec3f groundPosition = target.GetTargetPosGun(false);

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportUnloadUnits);
    commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
    commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
    commandIssueData.mTarget.mPos = groundPosition;
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F77E0 (FUN_006F77E0, cfunc_IssueTeleportToBeacon)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueTeleportToBeaconL`.
   */
  int cfunc_IssueTeleportToBeacon(lua_State* const luaContext)
  {
    return cfunc_IssueTeleportToBeaconL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F7850 (FUN_006F7850, cfunc_IssueTeleportToBeaconL)
   *
   * What it does:
   * Parses `(unitList, target)`, filters transport-capable units, resolves the
   * target payload, and queues `UNITCOMMAND_TransportUnloadUnits` on the
   * selection.
   */
  int cfunc_IssueTeleportToBeaconL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueTeleportToBeaconHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueTeleportToBeaconHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Transport)) {
      return 0;
    }

    CAiTarget target{};
    target.SetTarget(state, kIssueTeleportToBeaconHelpText, LuaPlus::LuaStackObject(state, 2));

    Sim* const sim = lua_getglobaluserdata(rawState);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_TransportUnloadUnits);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
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
   * Address: 0x006EF270 (FUN_006EF270, func_GetCells)
   *
   * IDA signature:
   * std::vector *__cdecl func_GetCells(std::vector *ret, LuaPlus::LuaState *state,
   *                                    LuaPlus::LuaStackObject obj);
   *
   * What it does:
   * Parses a Lua `{ {x,z}, {x,z}, ... }` cell list into a vector of `SOCellPos`
   * (x = element[1], z = element[2]). Raises the binary's Lua errors when the
   * argument is not a table, or any element is not a two-element table.
   */
  [[nodiscard]] msvc8::vector<SOCellPos> func_GetCells(LuaPlus::LuaState* const state, LuaPlus::LuaStackObject cellListArg)
  {
    msvc8::vector<SOCellPos> cells{};

    lua_State* const rawState = cellListArg.m_state->m_state;
    if (lua_type(rawState, cellListArg.m_stackIndex) != LUA_TTABLE) {
      const LuaPlus::LuaObject listObject(cellListArg);
      LuaPlus::LuaState::Error(state, kInvalidCellListError, kIssueBuildMobileName, listObject.TypeName());
    }

    const int cellCount = lua_getn(rawState, cellListArg.m_stackIndex);
    for (int cellIndex = 1; cellIndex <= cellCount; ++cellIndex) {
      lua_rawgeti(rawState, cellListArg.m_stackIndex, cellIndex);
      const LuaPlus::LuaObject cellObject(LuaPlus::LuaStackObject(cellListArg.m_state, lua_gettop(rawState)));

      if (!cellObject.IsTable() || cellObject.GetCount() != 2) {
        if (cellObject.IsTable()) {
          const msvc8::string describe = gpg::STR_Printf("%d element table", cellObject.GetCount());
          LuaPlus::LuaState::Error(state, kInvalidCellError, kIssueBuildMobileName, describe.c_str());
        } else {
          const LuaPlus::LuaObject listObject(cellListArg);
          LuaPlus::LuaState::Error(state, kInvalidCellError, kIssueBuildMobileName, listObject.TypeName());
        }
      }

      // Binary packs element[1] -> low int16 (x), element[2] -> high int16 (z).
      const std::int32_t x = cellObject[1].GetInteger();
      const std::int32_t z = cellObject[2].GetInteger();
      cells.push_back(SOCellPos{static_cast<std::int16_t>(x), static_cast<std::int16_t>(z)});
    }

    return cells;
  }

  /**
   * Address: 0x006F5B60 (FUN_006F5B60, cfunc_IssueBuildMobileL)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueBuildMobileL(LuaPlus::LuaState *state);
   *
   * What it does:
   * Lua `IssueBuildMobile(unitList, target, blueprintId, cellList)`. Resolves the
   * build target world position and the blueprint to build, parses the cell list,
   * then picks the single buildable unit from `unitList` whose position is closest
   * to the target, and issues one `UNITCOMMAND_BuildMobile` at the target ground
   * position carrying the blueprint and the cell list.
   */
  int cfunc_IssueBuildMobileL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueBuildMobileName, 4, argumentCount);
    }

    // arg1: candidate builders.
    UnitSet candidateUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(candidateUnits, state, unitListArg, kIssueBuildMobileName);

    // arg2: build target -> resolved world position. `target`'s destructor unlinks
    // its weak entity link at scope exit (the .c tail weak-list loop is that dtor).
    CAiTarget target{};
    (void)target.SetTarget(state, kIssueBuildMobileName, LuaPlus::LuaStackObject(state, 2));
    const Wm3::Vec3f targetPos = target.GetTargetPosGun(false);

    // arg3: blueprint to build.
    RUnitBlueprint* const blueprint =
      ResolveUnitBlueprintFromLuaArgument(state, LuaPlus::LuaStackObject(state, 3), kIssueBuildMobileName);

    // arg4: cell list.
    const msvc8::vector<SOCellPos> cells = func_GetCells(state, LuaPlus::LuaStackObject(state, 4));

    if (blueprint == nullptr) {
      return 0;
    }

    // NaN sentinel: a real closest unit's squared distance always beats an
    // invalid sentinel via IsValidVector3f. Matches the binary's invalid_vec.
    static const Wm3::Vector3f kInvalidVec(
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::quiet_NaN()
    );

    Unit* closestUnit = nullptr;
    Wm3::Vector3f closestDelta = kInvalidVec;
    for (Unit* const candidate : candidateUnits) {
      const Wm3::Vec3f& unitPos = candidate->GetPosition();
      const bool buildable = candidate->CanBuild(blueprint);

      const float dx = unitPos.x - targetPos.x;
      const float dy = unitPos.y - targetPos.y;
      const float dz = unitPos.z - targetPos.z;
      const float candidateDistSq = dx * dx + dy * dy + dz * dz;
      const float closestDistSq =
        closestDelta.x * closestDelta.x + closestDelta.y * closestDelta.y + closestDelta.z * closestDelta.z;

      if (buildable && IsValidVector3f(unitPos)
          && (!IsValidVector3f(closestDelta) || candidateDistSq < closestDistSq)) {
        closestDelta = Wm3::Vector3f(dx, dy, dz);
        closestUnit = candidate;
      }
    }

    if (closestUnit != nullptr) {
      SEntitySetTemplateUnit selectedUnits{};
      (void)selectedUnits.AddUnit(closestUnit);

      Sim* const sim = lua_getglobaluserdata(rawState);

      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_BuildMobile);
      commandIssueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
      commandIssueData.mTarget.mEnt = static_cast<std::uint32_t>(kGroundTargetEntitySentinel);
      commandIssueData.mTarget.mPos = targetPos;
      commandIssueData.mBlueprint = blueprint;
      for (const SOCellPos& cell : cells) {
        commandIssueData.mCells.push_back(cell);
      }

      (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    }

    return 0;
  }

  /**
   * Address: 0x006F5AF0 (FUN_006F5AF0, cfunc_IssueBuildMobile)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueBuildMobile(lua_State *a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueBuildMobileL`.
   */
  int cfunc_IssueBuildMobile(lua_State* const luaContext)
  {
    return cfunc_IssueBuildMobileL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F1D80 (FUN_006F1D80, cfunc_IssueOverCharge)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueOverCharge(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueOverChargeL`.
   */
  int cfunc_IssueOverCharge(lua_State* const luaContext)
  {
    return cfunc_IssueOverChargeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F1DF0 (FUN_006F1DF0, cfunc_IssueOverChargeL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueOverChargeL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Parses `(unitList, targetEntity)`, filters Overcharge-capable units, then
   * (when any workers remain) resolves the target entity into a `CAiTarget`,
   * encodes it into `SSTICommandIssueData::mTarget`, and queues one
   * `UNITCOMMAND_OverCharge` through the shared `IssueCommandToSelectedUnits`
   * (`UNIT_IssueCommand`) dispatch shape with `clearQueue=false`. Mirrors
   * the binary's `func_GetUnitList` + `func_Validate_IssueCommand(...,
   * RULEUCC_Overcharge)` + `SCR_FromLua_Entity` + `CAiTarget::UpdateTarget`
   * + `SSTITarget::FromAiTarget` + `UNIT_IssueCommand` sequence.
   */
  int cfunc_IssueOverChargeL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueOverChargeHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueOverChargeHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Overcharge)) {
      return 0;
    }

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const targetEntity = SCR_FromLua_Entity(targetObject, state);

    CAiTarget target{};
    target.UpdateTarget(targetEntity);

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(filteredUnits);

    Sim* const sim = lua_getglobaluserdata(rawState);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_OverCharge);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F6060 (FUN_006F6060, cfunc_IssueRepair)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueRepair(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueRepairL`.
   */
  int cfunc_IssueRepair(lua_State* const luaContext)
  {
    return cfunc_IssueRepairL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F60D0 (FUN_006F60D0, cfunc_IssueRepairL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueRepairL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Parses `(unitList, targetEntity)`, filters Repair-capable units, then
   * removes the target entity from the worker selection (so a unit does not
   * try to repair itself). If any workers remain, queues `UNITCOMMAND_Repair`
   * targeting that entity through the shared dispatch shape.
   */
  int cfunc_IssueRepairL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueRepairHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueRepairHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Repair)) {
      return 0;
    }

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const targetEntity = SCR_FromLua_Entity(targetObject, state);

    SEntitySetTemplateUnit workerSelection{};
    workerSelection.AddUnits(filteredUnits);

    // Drop the repair target itself out of the worker selection so a unit
    // does not get tasked to repair itself when the script passed the same
    // unit as both worker and target.
    (void)workerSelection.RemoveUnit(static_cast<Unit*>(targetEntity));
    if (workerSelection.Empty()) {
      return 0;
    }

    CAiTarget target{};
    target.UpdateTarget(targetEntity);

    Sim* const sim = lua_getglobaluserdata(rawState);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Repair);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, workerSelection, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F67A0 (FUN_006F67A0, cfunc_IssueScript)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueScript(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueScriptL`.
   */
  int cfunc_IssueScript(lua_State* const luaContext)
  {
    return cfunc_IssueScriptL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F6810 (FUN_006F6810, cfunc_IssueScriptL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueScriptL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Parses `(unitList, scriptObject)`, gathers live units from the Lua
   * table, and (when the selection is non-empty) issues one
   * `UNITCOMMAND_Script` carrying the second Lua argument as the
   * payload through the embedded `mObject` lane. Mirrors the binary
   * dispatch shape used by `IssueCommandToSelectedUnits`
   * (`UNIT_IssueCommand`) with `clearQueue=false`.
   */
  int cfunc_IssueScriptL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueScriptHelpText, 2, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueScriptHelpText);

    if (units.Empty()) {
      return 0;
    }

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(units);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Script);
    commandIssueData.mObject = LuaPlus::LuaStackObject(state, 2);

    Sim* const sim = lua_getglobaluserdata(rawState);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F6960 (FUN_006F6960, cfunc_IssueReclaim)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueReclaim(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueReclaimL`. The
   * binary stub is a 3-instruction tail-jump (`mov eax,[esp+4]; mov ecx,
   * [eax+0x44]; jmp cfunc_IssueReclaimL`) which the modern engine expresses
   * through `SCR_ResolveBindingState`.
   */
  int cfunc_IssueReclaim(lua_State* const luaContext)
  {
    return cfunc_IssueReclaimL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F69D0 (FUN_006F69D0, cfunc_IssueReclaimL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueReclaimL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Parses `(unitList, targetEntity)`, filters Reclaim-capable units through
   * `func_Validate_IssueCommand` with `RULEUCC_Reclaim` (0x100000), drops the
   * target entity out of the worker selection (so a unit does not get tasked
   * to reclaim itself when script passes the same unit as both worker and
   * target), resolves the target entity into a `CAiTarget`, encodes it into
   * `SSTICommandIssueData::mTarget`, and queues one `UNITCOMMAND_Reclaim`
   * (0x13) through the shared `IssueCommandToSelectedUnits`
   * (`UNIT_IssueCommand`) dispatch shape with `clearQueue=false`. Mirrors
   * the binary's `func_GetUnitList` + `func_Validate_IssueCommand(...,
   * RULEUCC_Reclaim)` + `SCR_FromLua_Entity` + `EntitySetTemplate_Unit::
   * Remove` + `CAiTarget::UpdateTarget` + `SSTITarget::FromAiTarget` +
   * `UNIT_IssueCommand` sequence.
   */
  int cfunc_IssueReclaimL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueReclaimHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueReclaimHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Reclaim)) {
      return 0;
    }

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const targetEntity = SCR_FromLua_Entity(targetObject, state);

    SEntitySetTemplateUnit workerSelection{};
    workerSelection.AddUnits(filteredUnits);

    // Drop the reclaim target itself out of the worker selection so a unit
    // does not get tasked to reclaim itself when the script passed the same
    // unit as both worker and target. Unlike Repair, the binary keeps issuing
    // even when the resulting worker set is empty (the per-unit dispatcher
    // discards impossible commands at the unit level).
    (void)workerSelection.RemoveUnit(static_cast<Unit*>(targetEntity));

    CAiTarget target{};
    target.UpdateTarget(targetEntity);

    Sim* const sim = lua_getglobaluserdata(rawState);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Reclaim);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, workerSelection, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F6C20 (FUN_006F6C20, cfunc_IssueCapture)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueCapture(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueCaptureL`. The
   * binary stub is a 3-instruction tail-jump (`mov eax,[esp+4]; mov ecx,
   * [eax+0x44]; jmp cfunc_IssueCaptureL`) which the modern engine expresses
   * through `SCR_ResolveBindingState`.
   */
  int cfunc_IssueCapture(lua_State* const luaContext)
  {
    return cfunc_IssueCaptureL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F6C90 (FUN_006F6C90, cfunc_IssueCaptureL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueCaptureL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Parses `(unitList, targetEntity)`, filters Capture-capable units through
   * `func_Validate_IssueCommand` with `RULEUCC_Capture` (0x80), drops the
   * target entity out of the worker selection (so a unit does not get tasked
   * to capture itself when the script passes the same unit as both worker
   * and target), resolves the target entity into a `CAiTarget`, encodes it
   * into `SSTICommandIssueData::mTarget`, and queues one `UNITCOMMAND_Capture`
   * (0x15) through the shared `IssueCommandToSelectedUnits`
   * (`UNIT_IssueCommand`) dispatch shape with `clearQueue=false`. Mirrors
   * the binary's `func_GetUnitList` + `func_Validate_IssueCommand(...,
   * RULEUCC_Capture)` + `SCR_FromLua_Entity` + `EntitySetTemplate_Unit::
   * Remove` + `CAiTarget::UpdateTarget` + `SSTITarget::FromAiTarget` +
   * `UNIT_IssueCommand` sequence shared with the sibling Reclaim callback
   * at FUN_006F69D0.
   */
  int cfunc_IssueCaptureL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueCaptureHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueCaptureHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Capture)) {
      return 0;
    }

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const targetEntity = SCR_FromLua_Entity(targetObject, state);

    SEntitySetTemplateUnit workerSelection{};
    workerSelection.AddUnits(filteredUnits);

    // Drop the capture target itself out of the worker selection so a unit
    // does not get tasked to capture itself when the script passed the same
    // unit as both worker and target. Like Reclaim (and unlike Repair), the
    // binary keeps issuing even when the resulting worker set is empty (the
    // per-unit dispatcher discards impossible commands at the unit level).
    (void)workerSelection.RemoveUnit(static_cast<Unit*>(targetEntity));

    CAiTarget target{};
    target.UpdateTarget(targetEntity);

    Sim* const sim = lua_getglobaluserdata(rawState);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Capture);
    target.EncodeToSSTITarget(commandIssueData.mTarget);
    (void)IssueCommandToSelectedUnits(sim, workerSelection, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F6330 (FUN_006F6330, cfunc_IssueSacrifice)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueSacrifice(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueSacrificeL`.
   */
  int cfunc_IssueSacrifice(lua_State* const luaContext)
  {
    return cfunc_IssueSacrificeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F63A0 (FUN_006F63A0, cfunc_IssueSacrificeL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueSacrificeL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Parses `(unitList, targetEntity)`, filters Sacrifice-capable units through
   * `func_Validate_IssueCommand` with `RULEUCC_Sacrifice` (0x10000), drops the
   * target entity out of the worker selection (a unit cannot sacrifice into
   * itself), and — only when at least one worker unit remains — resolves the
   * target into a `CAiTarget`, encodes it into `SSTICommandIssueData::mTarget`,
   * and queues one `UNITCOMMAND_Sacrifice` (0x20) through the shared
   * `IssueCommandToSelectedUnits` (`UNIT_IssueCommand`) dispatch shape with
   * `clearQueue=false`. Mirrors the binary's `func_GetUnitList` +
   * `func_Validate_IssueCommand(..., RULEUCC_Sacrifice)` + `SCR_FromLua_Entity`
   * + `EntitySetTemplate_Unit::Remove` + `CAiTarget::UpdateTarget` +
   * `SSTITarget::FromAiTarget` + `UNIT_IssueCommand` sequence. Unlike the
   * sibling Capture/Reclaim callbacks (which issue unconditionally), Sacrifice
   * gates the entire dispatch behind a non-empty post-removal worker set.
   */
  int cfunc_IssueSacrificeL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueSacrificeHelpText, 2, argumentCount);
    }

    UnitSet sourceUnits{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(sourceUnits, state, unitListArg, kIssueSacrificeHelpText);

    UnitSet filteredUnits{};
    if (!ValidateIssueCommandUnits(sourceUnits, filteredUnits, RULEUCC_Sacrifice)) {
      return 0;
    }

    const LuaPlus::LuaObject targetObject(LuaPlus::LuaStackObject(state, 2));
    Entity* const targetEntity = SCR_FromLua_Entity(targetObject, state);

    SEntitySetTemplateUnit workerSelection{};
    workerSelection.AddUnits(filteredUnits);

    // Drop the sacrifice target itself out of the worker selection so a unit is
    // not tasked to sacrifice into itself when the script passed the same unit
    // as both worker and target. Unlike the sibling Capture/Reclaim callbacks,
    // Sacrifice only issues when a worker unit remains after the removal.
    (void)workerSelection.RemoveUnit(static_cast<Unit*>(targetEntity));

    if (!workerSelection.Empty()) {
      CAiTarget target{};
      target.UpdateTarget(targetEntity);

      Sim* const sim = lua_getglobaluserdata(rawState);

      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Sacrifice);
      target.EncodeToSSTITarget(commandIssueData.mTarget);
      (void)IssueCommandToSelectedUnits(sim, workerSelection, commandIssueData, false);
    }
    return 0;
  }

  /**
   * Address: 0x006F6EE0 (FUN_006F6EE0, cfunc_IssueKillSelf)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueKillSelf(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueKillSelfL`.
   */
  int cfunc_IssueKillSelf(lua_State* const luaContext)
  {
    return cfunc_IssueKillSelfL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F6F50 (FUN_006F6F50, cfunc_IssueKillSelfL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueKillSelfL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Resolves one unit-list argument and issues one `UNITCOMMAND_KillSelf`
   * command through the active sim command sink, mirroring the shared
   * `IssueSimpleUnitCommand` shape used by `IssueStop`/`IssuePause`.
   */
  int cfunc_IssueKillSelfL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueKillSelfHelpText, 1, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueKillSelfHelpText);

    Sim* const sim = lua_getglobaluserdata(rawState);
    IssueSimpleUnitCommand(sim, units, EUnitCommandType::UNITCOMMAND_KillSelf);
    return 0;
  }

  /**
   * Address: 0x006F7060 (FUN_006F7060, cfunc_IssueDestroySelf)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueDestroySelf(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueDestroySelfL`.
   */
  int cfunc_IssueDestroySelf(lua_State* const luaContext)
  {
    return cfunc_IssueDestroySelfL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F70D0 (FUN_006F70D0, cfunc_IssueDestroySelfL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueDestroySelfL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Resolves one unit-list argument and issues one `UNITCOMMAND_DestroySelf`
   * command through the active sim command sink, mirroring the shared
   * `IssueSimpleUnitCommand` shape used by `IssueStop` / `IssuePause` /
   * `IssueKillSelf`.
   */
  int cfunc_IssueDestroySelfL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueDestroySelfHelpText, 1, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueDestroySelfHelpText);

    Sim* const sim = lua_getglobaluserdata(rawState);
    IssueSimpleUnitCommand(sim, units, EUnitCommandType::UNITCOMMAND_DestroySelf);
    return 0;
  }

  /**
   * Address: 0x006F6600 (FUN_006F6600, cfunc_IssueUpgrade)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueUpgrade(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueUpgradeL`.
   */
  int cfunc_IssueUpgrade(lua_State* const luaContext)
  {
    return cfunc_IssueUpgradeL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F6670 (FUN_006F6670, cfunc_IssueUpgradeL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueUpgradeL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Parses `(unitList, upgradeBlueprintId)`, resolves the destination
   * `RUnitBlueprint*` for the upgrade target, and (when both the unit
   * selection and blueprint are valid) issues one `UNITCOMMAND_Upgrade`
   * carrying the resolved blueprint pointer through the shared
   * `IssueCommandToSelectedUnits` (`UNIT_IssueCommand`) dispatch shape.
   * The blueprint pointer is stored in `SSTICommandIssueData::mBlueprint`
   * (offset +0x50) — the offset the binary writes via
   * `mov [eax+50h], esi` after `SSTICommandIssueData::SSTICommandIssueData`.
   */
  int cfunc_IssueUpgradeL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueUpgradeHelpText, 2, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueUpgradeHelpText);

    const LuaPlus::LuaStackObject blueprintArg(state, 2);
    RUnitBlueprint* const upgradeBlueprint =
      moho::ResolveUnitBlueprintFromLuaArgument(state, blueprintArg, kIssueUpgradeHelpText);

    if (units.Empty() || upgradeBlueprint == nullptr) {
      return 0;
    }

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(units);

    SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_Upgrade);
    commandIssueData.mBlueprint = upgradeBlueprint;

    Sim* const sim = lua_getglobaluserdata(rawState);
    (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    return 0;
  }

  /**
   * Address: 0x006F7EA0 (FUN_006F7EA0, cfunc_IssueBuildFactory)
   *
   * IDA signature:
   * int __cdecl cfunc_IssueBuildFactory(int a1);
   *
   * What it does:
   * Unwraps Lua callback context and forwards to `cfunc_IssueBuildFactoryL`.
   */
  int cfunc_IssueBuildFactory(lua_State* const luaContext)
  {
    return cfunc_IssueBuildFactoryL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006F7F10 (FUN_006F7F10, cfunc_IssueBuildFactoryL)
   *
   * IDA signature:
   * int __thiscall cfunc_IssueBuildFactoryL(LuaPlus::LuaState *this);
   *
   * What it does:
   * Parses `(unitList, factoryBlueprintId, count)`, resolves the destination
   * `RUnitBlueprint*` for the factory build target, and (when both the unit
   * selection and blueprint are valid) issues `count` copies of
   * `UNITCOMMAND_BuildFactory` carrying the resolved blueprint pointer
   * through the shared `IssueCommandToSelectedUnits` (`UNIT_IssueCommand`)
   * dispatch shape. Each iteration constructs a fresh `SSTICommandIssueData`
   * and writes the blueprint into `mBlueprint` (offset +0x50) — the offset
   * the binary writes via `mov [eax+50h], esi` after
   * `SSTICommandIssueData::SSTICommandIssueData`. The build-count argument
   * is coerced through `ResolveBuildCountArgument` (recovered shape of
   * `sub_6EF580`).
   */
  int cfunc_IssueBuildFactoryL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 3) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIssueBuildFactoryHelpText, 3, argumentCount);
    }

    UnitSet units{};
    LuaPlus::LuaStackObject unitListArg(state, 1);
    CollectLiveUnitsFromLuaTable(units, state, unitListArg, kIssueBuildFactoryHelpText);

    const LuaPlus::LuaStackObject blueprintArg(state, 2);
    RUnitBlueprint* const factoryBlueprint =
      moho::ResolveUnitBlueprintFromLuaArgument(state, blueprintArg, kIssueBuildFactoryHelpText);

    if (units.Empty() || factoryBlueprint == nullptr) {
      return 0;
    }

    const LuaPlus::LuaStackObject countArg(state, 3);
    const int repeatCount = ResolveBuildCountArgument(state, countArg, kIssueBuildFactoryHelpText);
    if (repeatCount <= 0) {
      return 0;
    }

    SEntitySetTemplateUnit selectedUnits{};
    selectedUnits.AddUnits(units);

    Sim* const sim = lua_getglobaluserdata(rawState);
    for (int issueIndex = 0; issueIndex < repeatCount; ++issueIndex) {
      SSTICommandIssueData commandIssueData(EUnitCommandType::UNITCOMMAND_BuildFactory);
      commandIssueData.mBlueprint = factoryBlueprint;
      (void)IssueCommandToSelectedUnits(sim, selectedUnits, commandIssueData, false);
    }

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
