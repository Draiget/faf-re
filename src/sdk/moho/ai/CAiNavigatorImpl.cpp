#include "moho/ai/CAiNavigatorImpl.h"

#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/SerializationError.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiBrain.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SFootprint.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace moho
{
  int cfunc_CAiNavigatorImplSetGoalL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplSetGoal(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplSetGoal_LuaFuncDef();
  int cfunc_CAiNavigatorImplSetDestUnitL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplSetDestUnit(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplSetDestUnit_LuaFuncDef();
  int cfunc_CAiNavigatorImplAbortMoveL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplAbortMove(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplAbortMove_LuaFuncDef();
  int cfunc_CAiNavigatorImplBroadcastResumeTaskEventL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplBroadcastResumeTaskEvent(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef();
  int cfunc_CAiNavigatorImplSetSpeedThroughGoalL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplSetSpeedThroughGoal(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef();
  int cfunc_CAiNavigatorImplGetCurrentTargetPosL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplGetCurrentTargetPos(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef();
  int cfunc_CAiNavigatorImplGetGoalPosL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplGetGoalPos(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplGetGoalPos_LuaFuncDef();
  int cfunc_CAiNavigatorImplGetStatusL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplGetStatus(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplGetStatus_LuaFuncDef();
  int cfunc_CAiNavigatorImplHasGoodPathL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplHasGoodPath(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplHasGoodPath_LuaFuncDef();
  int cfunc_CAiNavigatorImplFollowingLeaderL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplFollowingLeader(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplFollowingLeader_LuaFuncDef();
  int cfunc_CAiNavigatorImplIgnoreFormationL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplIgnoreFormation(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplIgnoreFormation_LuaFuncDef();
  int cfunc_CAiNavigatorImplIsIgnorningFormationL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplIsIgnorningFormation(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef();
  int cfunc_CAiNavigatorImplAtgoalL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplAtgoal(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplAtgoal_LuaFuncDef();
  int cfunc_CAiNavigatorImplCanPathToGoalL(LuaPlus::LuaState* state);
  int cfunc_CAiNavigatorImplCanPathToGoal(lua_State* luaContext);
  CScrLuaInitForm* func_CAiNavigatorImplCanPathToGoal_LuaFuncDef();
} // namespace moho

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kNavigatorLuaModulePath = "/lua/sim/Navigator.lua";
  constexpr const char* kNavigatorLuaClassName = "Navigator";
  constexpr const char* kNavigatorImplLuaClassName = "CAiNavigatorImpl";
  constexpr const char* kNavigatorSetGoalMethodName = "SetGoal";
  constexpr const char* kNavigatorSetGoalHelpText = "Set the navigator's destination as a particular position";
  constexpr const char* kNavigatorSetDestUnitMethodName = "SetDestUnit";
  constexpr const char* kNavigatorSetDestUnitHelpText =
    "Set the navigator's destination as another unit (chase/follow)";
  constexpr const char* kNavigatorAbortMoveMethodName = "AbortMove";
  constexpr const char* kNavigatorAbortMoveHelpText = "Abort the current move and put the navigator back to an idle state";
  constexpr const char* kNavigatorBroadcastResumeTaskEventMethodName = "BroadcastResumeTaskEvent";
  constexpr const char* kNavigatorBroadcastResumeTaskEventHelpText =
    "Broadcast event to resume any listening task that is currently suspended";
  constexpr const char* kNavigatorSetSpeedThroughGoalMethodName = "SetSpeedThroughGoal";
  constexpr const char* kNavigatorSetSpeedThroughGoalHelpText =
    " Set flag in navigator so the unit will know whether to stop at final goal  or speed through it. This would be set "
    "to True during a patrol or a series  of waypoints in a complex path.";
  constexpr const char* kNavigatorGetCurrentTargetPosMethodName = "GetCurrentTargetPos";
  constexpr const char* kNavigatorGetCurrentTargetPosHelpText =
    "This returns the current navigator target position for the unit";
  constexpr const char* kNavigatorGetGoalPosMethodName = "GetGoalPos";
  constexpr const char* kNavigatorGetGoalPosHelpText = "This returns the current goal position of our navigator";
  constexpr const char* kNavigatorGetStatusMethodName = "GetStatus";
  constexpr const char* kNavigatorHasGoodPathMethodName = "HasGoodPath";
  constexpr const char* kNavigatorFollowingLeaderMethodName = "FollowingLeader";
  constexpr const char* kNavigatorIgnoreFormationMethodName = "IgnoreFormation";
  constexpr const char* kNavigatorIsIgnorningFormationMethodName = "IsIgnorningFormation";
  constexpr const char* kNavigatorAtGoalMethodName = "AtGoal";
  constexpr const char* kNavigatorCanPathToGoalMethodName = "CanPathToGoal";
  constexpr const char* kNavigatorEmptyHelpText = "";
  CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59970 = nullptr;
  CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59960 = nullptr;

  template <std::uintptr_t SlotAddress>
  struct StartupEngineStatsSlot
  {
    static EngineStats* value;
  };

  template <>
  EngineStats* StartupEngineStatsSlot<0x10AEDB0u>::value = nullptr;

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  [[nodiscard]] gpg::RType* CachedIAiNavigatorType()
  {
    if (!IAiNavigator::sType) {
      IAiNavigator::sType = gpg::LookupRType(typeid(IAiNavigator));
    }
    return IAiNavigator::sType;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    if (!CScriptObject::sType) {
      CScriptObject::sType = gpg::LookupRType(typeid(CScriptObject));
    }
    return CScriptObject::sType;
  }

  [[nodiscard]] gpg::RType* CachedCTaskType()
  {
    if (!CTask::sType) {
      CTask::sType = gpg::LookupRType(typeid(CTask));
    }
    return CTask::sType;
  }

  [[nodiscard]] gpg::RType* CachedUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Unit));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedEAiNavigatorStatusType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(EAiNavigatorStatus));
    }
    return cached;
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadPointerWithType(
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef,
    gpg::RType* const expectedType
  )
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    const gpg::RRef source{tracked.object, tracked.type};
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    return static_cast<TObject*>(upcast.mObj);
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* const object, gpg::RType* const staticType)
  {
    gpg::RRef ref{};
    ref.mObj = nullptr;
    ref.mType = staticType;
    if (!object) {
      return ref;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!derived) {
      ref.mObj = object;
      ref.mType = dynamicType ? dynamicType : staticType;
      return ref;
    }

    ref.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    ref.mType = dynamicType;
    return ref;
  }

  template <typename TObject>
  void WritePointerWithType(
    gpg::WriteArchive* const archive,
    TObject* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, ownerRef);
  }

  /**
   * Address: 0x005A7C00 (FUN_005A7C00)
   *
   * What it does:
   * Returns `CScrLuaMetatableFactory<CAiNavigatorImpl>::sInstance.Get(state)`.
   */
  [[nodiscard]] LuaPlus::LuaObject GetNavigatorImplFactoryMetatable(LuaPlus::LuaState* const state)
  {
    return CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance().Get(state);
  }

  [[nodiscard]] CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] SAiNavigatorGoal BuildSingleCellGoalFromWorldPos(
    const Wm3::Vector3f& worldPos,
    const SFootprint& footprint
  ) noexcept
  {
    const std::int32_t minXCell = static_cast<std::int32_t>(worldPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    const std::int32_t minZCell = static_cast<std::int32_t>(worldPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));

    const std::int16_t packedMinX = static_cast<std::int16_t>(minXCell);
    const std::int16_t packedMinZ = static_cast<std::int16_t>(minZCell);

    SAiNavigatorGoal goal{};
    goal.minX = static_cast<std::int32_t>(packedMinX);
    goal.minZ = static_cast<std::int32_t>(packedMinZ);
    goal.maxX = static_cast<std::int32_t>(packedMinX) + 1;
    goal.maxZ = static_cast<std::int32_t>(packedMinZ) + 1;
    goal.aux0 = 0;
    goal.aux1 = 0;
    goal.aux2 = 0;
    goal.aux3 = 0;
    goal.aux4 = 0;
    return goal;
  }

  /**
   * Address: 0x00409A40 (FUN_00409A40, func_CreateCTaskThread)
   *
   * What it does:
   * Allocates one CTaskThread and links `dispatch` as task-top while preserving
   * prior top in `dispatch->mSubtask`.
   */
  [[nodiscard]] CTaskThread* CreateTaskThreadForDispatch(CTask* const dispatch, CTaskStage* const stage, const bool autoDelete)
  {
    if (!dispatch) {
      return nullptr;
    }

    auto* const taskThread = new CTaskThread(stage);
    dispatch->mAutoDelete = autoDelete;
    dispatch->mOwnerThread = taskThread;
    dispatch->mSubtask = taskThread->mTaskTop;
    taskThread->mTaskTop = dispatch;
    return taskThread;
  }

  void DispatchNavigatorEventList(TDatListItem<void, void>& listenerHead, const std::int32_t eventCode)
  {
    TDatList<void, void> pending{};
    if (listenerHead.mNext == &listenerHead) {
      return;
    }

    // Move current listeners to a temporary list first. This matches FUN_005A6C50
    // behavior and keeps iteration stable even when callbacks relink listeners.
    pending.mNext = listenerHead.mNext;
    pending.mPrev = listenerHead.mPrev;
    pending.mNext->mPrev = &pending;
    pending.mPrev->mNext = &pending;
    listenerHead.mNext = &listenerHead;
    listenerHead.mPrev = &listenerHead;

    while (pending.mNext != &pending) {
      auto* const listenerNode = pending.pop_front();
      if (!listenerNode) {
        break;
      }

      listenerNode->ListLinkAfter(&listenerHead);

      auto* const listener = TDatList<void, void>::owner_from_member_node<
        IAiNavigatorEventListener,
        &IAiNavigatorEventListener::mLink>(listenerNode);
      listener->OnNavigatorEvent(eventCode);
    }
  }

  template <CScrLuaInitForm* (*Target)()>
  [[nodiscard]] CScrLuaInitForm* ForwardNavigatorLuaThunk() noexcept
  {
    return Target();
  }

  /**
   * Address: 0x00BF70C0 (FUN_00BF70C0, sub_BF70C0)
   *
   * What it does:
   * Tears down one startup-owned navigator stats slot.
   */
  void cleanup_CAiNavigatorImplStartupStatsSlot()
  {
    EngineStats*& slot = StartupEngineStatsSlot<0x10AEDB0u>::value;
    if (!slot) {
      return;
    }

    delete slot;
    slot = nullptr;
  }
} // namespace

gpg::RType* CAiNavigatorImpl::sType = nullptr;
CScrLuaMetatableFactory<CAiNavigatorImpl> CScrLuaMetatableFactory<CAiNavigatorImpl>::sInstance{};

/**
 * Address: 0x005A7870 (FUN_005A7870, Moho::InstanceCounter<Moho::CAiNavigatorImpl>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for CAiNavigatorImpl
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CAiNavigatorImpl>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CAiNavigatorImpl).name());
  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x005A58E0 (FUN_005A58E0, cfunc_CAiNavigatorImplSetGoalL)
 *
 * What it does:
 * Resolves one navigator and one world-space target position, then builds a
 * one-cell goal rectangle and forwards it to `IAiNavigator::SetGoal`.
 */
int moho::cfunc_CAiNavigatorImplSetGoalL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorSetGoalHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  const LuaPlus::LuaObject targetPosObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f targetPos = SCR_FromLuaCopy<Wm3::Vector3<float>>(targetPosObject);

  const SAiNavigatorGoal goal = BuildSingleCellGoalFromWorldPos(targetPos, navigator->GetUnit()->GetFootprint());
  navigator->SetGoal(goal);
  return 0;
}

/**
 * Address: 0x005A5860 (FUN_005A5860, cfunc_CAiNavigatorImplSetGoal)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplSetGoalL`.
 */
int moho::cfunc_CAiNavigatorImplSetGoal(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplSetGoalL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A5880 (FUN_005A5880, func_CAiNavigatorImplSetGoal_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:SetGoal(position)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplSetGoal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorSetGoalMethodName,
    &moho::cfunc_CAiNavigatorImplSetGoal,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorSetGoalHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A5B10 (FUN_005A5B10, cfunc_CAiNavigatorImplSetDestUnitL)
 *
 * What it does:
 * Resolves one navigator and one destination entity object, then forwards the
 * destination lane to `IAiNavigator::SetDestUnit`.
 */
int moho::cfunc_CAiNavigatorImplSetDestUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorSetDestUnitHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  const LuaPlus::LuaObject destinationEntityObject(LuaPlus::LuaStackObject(state, 2));
  Entity* const destinationEntity = SCR_FromLua_Entity(destinationEntityObject, state);
  navigator->SetDestUnit(static_cast<Unit*>(destinationEntity));
  return 0;
}

/**
 * Address: 0x005A5A90 (FUN_005A5A90, cfunc_CAiNavigatorImplSetDestUnit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplSetDestUnitL`.
 */
int moho::cfunc_CAiNavigatorImplSetDestUnit(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplSetDestUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A5AB0 (FUN_005A5AB0, func_CAiNavigatorImplSetDestUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:SetDestUnit(entity)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplSetDestUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorSetDestUnitMethodName,
    &moho::cfunc_CAiNavigatorImplSetDestUnit,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorSetDestUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A5C70 (FUN_005A5C70, cfunc_CAiNavigatorImplAbortMoveL)
 *
 * What it does:
 * Resolves one navigator and dispatches its abort-move path.
 */
int moho::cfunc_CAiNavigatorImplAbortMoveL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorAbortMoveHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);
  navigator->AbortMove();
  return 0;
}

/**
 * Address: 0x005A5BF0 (FUN_005A5BF0, cfunc_CAiNavigatorImplAbortMove)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplAbortMoveL`.
 */
int moho::cfunc_CAiNavigatorImplAbortMove(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplAbortMoveL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A5C10 (FUN_005A5C10, func_CAiNavigatorImplAbortMove_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:AbortMove()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplAbortMove_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorAbortMoveMethodName,
    &moho::cfunc_CAiNavigatorImplAbortMove,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorAbortMoveHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A5DA0 (FUN_005A5DA0, cfunc_CAiNavigatorImplBroadcastResumeTaskEventL)
 *
 * What it does:
 * Resolves one navigator and broadcasts the resume-task event to listeners.
 */
int moho::cfunc_CAiNavigatorImplBroadcastResumeTaskEventL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(
      state,
      kLuaExpectedArgsWarning,
      kNavigatorBroadcastResumeTaskEventHelpText,
      1,
      argumentCount
    );
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);
  navigator->BroadcastResumeTaskEvent();
  return 0;
}

/**
 * Address: 0x005A5D20 (FUN_005A5D20, cfunc_CAiNavigatorImplBroadcastResumeTaskEvent)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplBroadcastResumeTaskEventL`.
 */
int moho::cfunc_CAiNavigatorImplBroadcastResumeTaskEvent(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplBroadcastResumeTaskEventL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A5D40 (FUN_005A5D40, func_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:BroadcastResumeTaskEvent()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorBroadcastResumeTaskEventMethodName,
    &moho::cfunc_CAiNavigatorImplBroadcastResumeTaskEvent,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorBroadcastResumeTaskEventHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A5ED0 (FUN_005A5ED0, cfunc_CAiNavigatorImplSetSpeedThroughGoalL)
 *
 * What it does:
 * Resolves one navigator and one boolean lane, then forwards it to
 * `IAiNavigator::SetSpeedThroughGoal`.
 */
int moho::cfunc_CAiNavigatorImplSetSpeedThroughGoalL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorSetSpeedThroughGoalHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  const bool enableSpeedThroughGoal = LuaPlus::LuaStackObject(state, 2).GetBoolean();
  navigator->SetSpeedThroughGoal(enableSpeedThroughGoal);
  return 0;
}

/**
 * Address: 0x005A5E50 (FUN_005A5E50, cfunc_CAiNavigatorImplSetSpeedThroughGoal)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplSetSpeedThroughGoalL`.
 */
int moho::cfunc_CAiNavigatorImplSetSpeedThroughGoal(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplSetSpeedThroughGoalL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A5E70 (FUN_005A5E70, func_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:SetSpeedThroughGoal(enabled)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorSetSpeedThroughGoalMethodName,
    &moho::cfunc_CAiNavigatorImplSetSpeedThroughGoal,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorSetSpeedThroughGoalHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A6010 (FUN_005A6010, cfunc_CAiNavigatorImplGetCurrentTargetPosL)
 *
 * What it does:
 * Resolves one navigator and returns current target world position to Lua.
 */
int moho::cfunc_CAiNavigatorImplGetCurrentTargetPosL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorGetCurrentTargetPosHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  const Wm3::Vector3f currentTargetPos = navigator->GetCurrentTargetPos();
  const LuaPlus::LuaObject currentTargetPosObject = SCR_ToLua<Wm3::Vector3<float>>(state, currentTargetPos);
  currentTargetPosObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x005A5F90 (FUN_005A5F90, cfunc_CAiNavigatorImplGetCurrentTargetPos)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplGetCurrentTargetPosL`.
 */
int moho::cfunc_CAiNavigatorImplGetCurrentTargetPos(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplGetCurrentTargetPosL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A5FB0 (FUN_005A5FB0, func_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:GetCurrentTargetPos()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorGetCurrentTargetPosMethodName,
    &moho::cfunc_CAiNavigatorImplGetCurrentTargetPos,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorGetCurrentTargetPosHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A6180 (FUN_005A6180, cfunc_CAiNavigatorImplGetGoalPosL)
 *
 * What it does:
 * Resolves one navigator and returns current goal world position to Lua.
 */
int moho::cfunc_CAiNavigatorImplGetGoalPosL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorGetGoalPosHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  const Wm3::Vector3f goalPos = navigator->GetGoalPos();
  const LuaPlus::LuaObject goalPosObject = SCR_ToLua<Wm3::Vector3<float>>(state, goalPos);
  goalPosObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x005A6100 (FUN_005A6100, cfunc_CAiNavigatorImplGetGoalPos)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplGetGoalPosL`.
 */
int moho::cfunc_CAiNavigatorImplGetGoalPos(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplGetGoalPosL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A6120 (FUN_005A6120, func_CAiNavigatorImplGetGoalPos_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:GetGoalPos()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplGetGoalPos_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorGetGoalPosMethodName,
    &moho::cfunc_CAiNavigatorImplGetGoalPos,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorGetGoalPosHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A62F0 (FUN_005A62F0, cfunc_CAiNavigatorImplGetStatusL)
 *
 * What it does:
 * Resolves one navigator and pushes its status enum as a Lua number.
 */
int moho::cfunc_CAiNavigatorImplGetStatusL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorEmptyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  lua_pushnumber(rawState, static_cast<float>(navigator->GetStatus()));
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005A6270 (FUN_005A6270, cfunc_CAiNavigatorImplGetStatus)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplGetStatusL`.
 */
int moho::cfunc_CAiNavigatorImplGetStatus(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplGetStatusL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A6290 (FUN_005A6290, func_CAiNavigatorImplGetStatus_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:GetStatus()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplGetStatus_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorGetStatusMethodName,
    &moho::cfunc_CAiNavigatorImplGetStatus,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorEmptyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A6440 (FUN_005A6440, cfunc_CAiNavigatorImplHasGoodPathL)
 *
 * What it does:
 * Resolves one navigator and returns whether its current path is considered
 * valid.
 */
int moho::cfunc_CAiNavigatorImplHasGoodPathL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorEmptyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  lua_pushboolean(rawState, navigator->HasGoodPath() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005A63C0 (FUN_005A63C0, cfunc_CAiNavigatorImplHasGoodPath)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplHasGoodPathL`.
 */
int moho::cfunc_CAiNavigatorImplHasGoodPath(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplHasGoodPathL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A63E0 (FUN_005A63E0, func_CAiNavigatorImplHasGoodPath_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:HasGoodPath()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplHasGoodPath_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorHasGoodPathMethodName,
    &moho::cfunc_CAiNavigatorImplHasGoodPath,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorEmptyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A6580 (FUN_005A6580, cfunc_CAiNavigatorImplFollowingLeaderL)
 *
 * What it does:
 * Resolves one navigator and returns whether it is currently following a
 * formation leader.
 */
int moho::cfunc_CAiNavigatorImplFollowingLeaderL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorEmptyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  lua_pushboolean(rawState, navigator->FollowingLeader() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005A6500 (FUN_005A6500, cfunc_CAiNavigatorImplFollowingLeader)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplFollowingLeaderL`.
 */
int moho::cfunc_CAiNavigatorImplFollowingLeader(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplFollowingLeaderL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A6520 (FUN_005A6520, func_CAiNavigatorImplFollowingLeader_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:FollowingLeader()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplFollowingLeader_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorFollowingLeaderMethodName,
    &moho::cfunc_CAiNavigatorImplFollowingLeader,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorEmptyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A66C0 (FUN_005A66C0, cfunc_CAiNavigatorImplIgnoreFormationL)
 *
 * What it does:
 * Resolves one navigator and applies one boolean ignore-formation flag.
 */
int moho::cfunc_CAiNavigatorImplIgnoreFormationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorEmptyHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  const bool ignoreFormation = LuaPlus::LuaStackObject(state, 2).GetBoolean();
  navigator->IgnoreFormation(ignoreFormation);
  return 0;
}

/**
 * Address: 0x005A6640 (FUN_005A6640, cfunc_CAiNavigatorImplIgnoreFormation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplIgnoreFormationL`.
 */
int moho::cfunc_CAiNavigatorImplIgnoreFormation(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplIgnoreFormationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A6660 (FUN_005A6660, func_CAiNavigatorImplIgnoreFormation_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:IgnoreFormation(ignore)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplIgnoreFormation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorIgnoreFormationMethodName,
    &moho::cfunc_CAiNavigatorImplIgnoreFormation,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorEmptyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A6800 (FUN_005A6800, cfunc_CAiNavigatorImplIsIgnorningFormationL)
 *
 * What it does:
 * Resolves one navigator and returns whether formation constraints are ignored.
 */
int moho::cfunc_CAiNavigatorImplIsIgnorningFormationL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorEmptyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  lua_pushboolean(rawState, navigator->IsIgnoringFormation() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005A6780 (FUN_005A6780, cfunc_CAiNavigatorImplIsIgnorningFormation)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplIsIgnorningFormationL`.
 */
int moho::cfunc_CAiNavigatorImplIsIgnorningFormation(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplIsIgnorningFormationL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A67A0 (FUN_005A67A0, func_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:IsIgnorningFormation()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorIsIgnorningFormationMethodName,
    &moho::cfunc_CAiNavigatorImplIsIgnorningFormation,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorEmptyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A6940 (FUN_005A6940, cfunc_CAiNavigatorImplAtgoalL)
 *
 * What it does:
 * Resolves one navigator and returns whether it has reached its goal area.
 */
int moho::cfunc_CAiNavigatorImplAtgoalL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorEmptyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  lua_pushboolean(rawState, navigator->AtGoal() ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005A68C0 (FUN_005A68C0, cfunc_CAiNavigatorImplAtgoal)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplAtgoalL`.
 */
int moho::cfunc_CAiNavigatorImplAtgoal(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplAtgoalL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A68E0 (FUN_005A68E0, func_CAiNavigatorImplAtgoal_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:AtGoal()` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplAtgoal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorAtGoalMethodName,
    &moho::cfunc_CAiNavigatorImplAtgoal,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorEmptyHelpText
  );
  return &binder;
}

/**
 * Address: 0x005A6A80 (FUN_005A6A80, cfunc_CAiNavigatorImplCanPathToGoalL)
 *
 * What it does:
 * Resolves one navigator plus goal-position lane, builds one-cell goal rect,
 * and returns `CanPathTo(...)` as Lua boolean.
 */
int moho::cfunc_CAiNavigatorImplCanPathToGoalL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  // Keep recovered binary shape: this lane checks for one arg but still reads
  // stack slot #2 as goal-position payload.
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kNavigatorEmptyHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject navigatorObject(LuaPlus::LuaStackObject(state, 1));
  CAiNavigatorImpl* const navigator = SCR_FromLua_CAiNavigatorImpl(navigatorObject, state);

  const LuaPlus::LuaObject goalPosObject(LuaPlus::LuaStackObject(state, 2));
  const Wm3::Vector3f goalPos = SCR_FromLuaCopy<Wm3::Vector3<float>>(goalPosObject);
  const SAiNavigatorGoal goal = BuildSingleCellGoalFromWorldPos(goalPos, navigator->GetUnit()->GetFootprint());

  lua_pushboolean(rawState, navigator->CanPathTo(goal) ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x005A6A00 (FUN_005A6A00, cfunc_CAiNavigatorImplCanPathToGoal)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CAiNavigatorImplCanPathToGoalL`.
 */
int moho::cfunc_CAiNavigatorImplCanPathToGoal(lua_State* const luaContext)
{
  return cfunc_CAiNavigatorImplCanPathToGoalL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x005A6A20 (FUN_005A6A20, func_CAiNavigatorImplCanPathToGoal_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CAiNavigatorImpl:CanPathToGoal(...)` Lua binder.
 */
CScrLuaInitForm* moho::func_CAiNavigatorImplCanPathToGoal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kNavigatorCanPathToGoalMethodName,
    &moho::cfunc_CAiNavigatorImplCanPathToGoal,
    &CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance(),
    kNavigatorImplLuaClassName,
    kNavigatorEmptyHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BCC760 (FUN_00BCC760)
 *
 * What it does:
 * Captures the current `sim` Lua-init chain head for recovery bookkeeping.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplLuaInitFormAnchor()
{
  CScrLuaInitFormSet* const simSet = moho::SCR_FindLuaInitFormSet("sim");
  if (simSet == nullptr) {
    gRecoveredSimLuaInitFormPrev_off_F59970 = nullptr;
    gRecoveredSimLuaInitFormAnchor_off_F59960 = nullptr;
    return nullptr;
  }

  CScrLuaInitForm* const previousHead = simSet->mForms;
  gRecoveredSimLuaInitFormPrev_off_F59970 = previousHead;
  gRecoveredSimLuaInitFormAnchor_off_F59960 = previousHead;
  simSet->mForms = gRecoveredSimLuaInitFormAnchor_off_F59960;
  return previousHead;
}

/**
 * Address: 0x00BCC8C0 (FUN_00BCC8C0, register_CAiNavigatorImplSetGoal_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplSetGoal_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplSetGoal_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplSetGoal_LuaFuncDef>();
}

/**
 * Address: 0x00BCC8D0 (FUN_00BCC8D0, register_CAiNavigatorImplSetDestUnit_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplSetDestUnit_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplSetDestUnit_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplSetDestUnit_LuaFuncDef>();
}

/**
 * Address: 0x00BCC8E0 (FUN_00BCC8E0, register_CAiNavigatorImplAbortMove_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplAbortMove_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplAbortMove_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplAbortMove_LuaFuncDef>();
}

/**
 * Address: 0x00BCC8F0 (FUN_00BCC8F0, register_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef>();
}

/**
 * Address: 0x00BCC900 (FUN_00BCC900, register_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef>();
}

/**
 * Address: 0x00BCC910 (FUN_00BCC910, register_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef>();
}

/**
 * Address: 0x00BCC920 (FUN_00BCC920, register_CAiNavigatorImplGetGoalPos_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplGetGoalPos_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplGetGoalPos_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplGetGoalPos_LuaFuncDef>();
}

/**
 * Address: 0x00BCC930 (FUN_00BCC930, register_CAiNavigatorImplGetStatus_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplGetStatus_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplGetStatus_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplGetStatus_LuaFuncDef>();
}

/**
 * Address: 0x00BCC940 (FUN_00BCC940, register_CAiNavigatorImplHasGoodPath_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplHasGoodPath_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplHasGoodPath_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplHasGoodPath_LuaFuncDef>();
}

/**
 * Address: 0x00BCC950 (FUN_00BCC950, register_CAiNavigatorImplFollowingLeader_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplFollowingLeader_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplFollowingLeader_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplFollowingLeader_LuaFuncDef>();
}

/**
 * Address: 0x00BCC960 (FUN_00BCC960, register_CAiNavigatorImplIgnoreFormation_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplIgnoreFormation_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplIgnoreFormation_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplIgnoreFormation_LuaFuncDef>();
}

/**
 * Address: 0x00BCC970 (FUN_00BCC970, register_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef>();
}

/**
 * Address: 0x00BCC980 (FUN_00BCC980, register_CAiNavigatorImplAtGoal_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplAtgoal_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplAtGoal_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplAtgoal_LuaFuncDef>();
}

/**
 * Address: 0x00BCC990 (FUN_00BCC990, j_func_CAiNavigatorImplCanPathToGoal_LuaFuncDef)
 *
 * What it does:
 * Forwards startup thunk to `func_CAiNavigatorImplCanPathToGoal_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplCanPathToGoal_LuaFuncDef()
{
  return ForwardNavigatorLuaThunk<&func_CAiNavigatorImplCanPathToGoal_LuaFuncDef>();
}

/**
 * Address: 0x00BCC9E0 (FUN_00BCC9E0)
 *
 * What it does:
 * Allocates and stores the startup Lua metatable-factory index for
 * `CScrLuaMetatableFactory<CAiNavigatorImpl>`.
 */
int moho::register_CScrLuaMetatableFactory_CAiNavigatorImpl_Index()
{
  const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
  CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance().SetFactoryObjectIndexForRecovery(index);
  return index;
}

/**
 * Address: 0x00BCCA60 (FUN_00BCCA60)
 *
 * What it does:
 * Installs process-exit cleanup for one startup-owned navigator stats slot.
 */
int moho::register_CAiNavigatorImplStartupCleanup()
{
  return std::atexit(&cleanup_CAiNavigatorImplStartupStatsSlot);
}

namespace
{
  struct CAiNavigatorImplStartupBootstrap
  {
    CAiNavigatorImplStartupBootstrap()
    {
      (void)moho::register_CAiNavigatorImplLuaInitFormAnchor();
      (void)moho::register_CAiNavigatorImplSetGoal_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplSetDestUnit_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplAbortMove_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplGetGoalPos_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplGetStatus_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplHasGoodPath_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplFollowingLeader_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplIgnoreFormation_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplAtGoal_LuaFuncDef();
      (void)moho::register_CAiNavigatorImplCanPathToGoal_LuaFuncDef();
      (void)moho::register_CScrLuaMetatableFactory_CAiNavigatorImpl_Index();
      (void)moho::register_CAiNavigatorImplStartupCleanup();
    }
  };

  [[maybe_unused]] CAiNavigatorImplStartupBootstrap gCAiNavigatorImplStartupBootstrap;
} // namespace

/**
 * Address: 0x1001FDE0 (MohoEngine.dll constructor shape)
 */
CScrLuaMetatableFactory<CAiNavigatorImpl>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

CScrLuaMetatableFactory<CAiNavigatorImpl>& CScrLuaMetatableFactory<CAiNavigatorImpl>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x005A7310 (FUN_005A7310, ?Create@?$CScrLuaMetatableFactory@VCAiNavigatorImpl@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
 */
LuaPlus::LuaObject CScrLuaMetatableFactory<CAiNavigatorImpl>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x005A3550 (FUN_005A3550, default ctor)
 */
CAiNavigatorImpl::CAiNavigatorImpl()
  : CTask(nullptr, false)
  , mUnit(nullptr)
  , mIgnoreFormation(0)
  , mPad61{0, 0, 0}
  , mStatus(AINAVSTATUS_Idle)
{}

/**
 * Address: 0x005A33E0 (FUN_005A33E0, unit ctor)
 */
CAiNavigatorImpl::CAiNavigatorImpl(Unit* const unit)
  : CAiNavigatorImpl()
{
  GPG_ASSERT(unit != nullptr);
  LuaPlus::LuaState* const luaState = unit->SimulationRef ? unit->SimulationRef->mLuaState : nullptr;

  LuaPlus::LuaObject arg1;
  LuaPlus::LuaObject arg2;
  LuaPlus::LuaObject arg3;
  LuaPlus::LuaObject metatable = GetMetatable(luaState);
  CreateLuaObject(metatable, arg1, arg2, arg3);

  mUnit = unit;
  mIgnoreFormation = 0u;
  mStatus = AINAVSTATUS_Idle;

  GPG_ASSERT(unit->ArmyRef != nullptr);
  CAiBrain* const brain = unit->ArmyRef->GetArmyBrain();
  GPG_ASSERT(brain != nullptr);
  CreateTaskThreadForDispatch(static_cast<CTask*>(this), brain->mAiThreadStage, false);
}

/**
 * Address: 0x005A37B0 (FUN_005A37B0, scalar deleting thunk)
 * Address: 0x005A37E0 (FUN_005A37E0, core dtor)
 */
CAiNavigatorImpl::~CAiNavigatorImpl() = default;

/**
 * Address: 0x005A8C70 (FUN_005A8C70, Moho::CAiNavigatorImpl::MemberDeserialize)
 *
 * What it does:
 * Loads reflected base lanes (`IAiNavigator`, `CScriptObject`, `CTask`)
 * followed by unit pointer, ignore-formation flag, and navigator status.
 */
void CAiNavigatorImpl::MemberDeserialize(CAiNavigatorImpl* const object, gpg::ReadArchive* const archive, const int version)
{
  if (!archive) {
    return;
  }

  if (version < 1) {
    throw gpg::SerializationError("obsolete version.");
  }

  const gpg::RRef ownerRef{};
  archive->Read(CachedIAiNavigatorType(), object, ownerRef);
  archive->Read(
    CachedCScriptObjectType(),
    object ? static_cast<void*>(static_cast<CScriptObject*>(object)) : nullptr,
    ownerRef
  );
  archive->Read(CachedCTaskType(), object ? static_cast<void*>(static_cast<CTask*>(object)) : nullptr, ownerRef);

  Unit* const loadedUnit = ReadPointerWithType<Unit>(archive, ownerRef, CachedUnitType());

  bool ignoreFormation = false;
  archive->ReadBool(&ignoreFormation);

  EAiNavigatorStatus status = AINAVSTATUS_Idle;
  archive->Read(CachedEAiNavigatorStatusType(), &status, ownerRef);

  if (!object) {
    return;
  }

  object->mUnit = loadedUnit;
  object->mIgnoreFormation = ignoreFormation ? 1u : 0u;
  object->mStatus = status;
}

/**
 * Address: 0x005A8DD0 (FUN_005A8DD0, Moho::CAiNavigatorImpl::MemberSerialize)
 *
 * What it does:
 * Saves reflected base lanes (`IAiNavigator`, `CScriptObject`, `CTask`)
 * followed by unit pointer, ignore-formation flag, and navigator status.
 */
void CAiNavigatorImpl::MemberSerialize(
  const CAiNavigatorImpl* const object,
  gpg::WriteArchive* const archive,
  const int version
)
{
  if (!archive) {
    return;
  }

  if (version < 1) {
    throw gpg::SerializationError("obsolete version.");
  }

  const gpg::RRef ownerRef{};
  archive->Write(CachedIAiNavigatorType(), object, ownerRef);
  archive->Write(
    CachedCScriptObjectType(),
    object ? static_cast<const void*>(static_cast<const CScriptObject*>(object)) : nullptr,
    ownerRef
  );
  archive->Write(
    CachedCTaskType(),
    object ? static_cast<const void*>(static_cast<const CTask*>(object)) : nullptr,
    ownerRef
  );

  WritePointerWithType(
    archive,
    object ? object->mUnit : nullptr,
    CachedUnitType(),
    gpg::TrackedPointerState::Unowned,
    ownerRef
  );

  archive->WriteBool(object && object->mIgnoreFormation != 0u);

  const EAiNavigatorStatus status = object ? object->mStatus : AINAVSTATUS_Idle;
  archive->Write(CachedEAiNavigatorStatusType(), &status, ownerRef);
}

/**
 * Address: 0x005A33A0 (FUN_005A33A0, ?GetClass@CAiNavigatorImpl@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CAiNavigatorImpl::GetClass() const
{
  gpg::RType* type = CAiNavigatorImpl::sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiNavigatorImpl));
    CAiNavigatorImpl::sType = type;
  }
  return type;
}

/**
 * Address: 0x005A33C0 (FUN_005A33C0, ?GetDerivedObjectRef@CAiNavigatorImpl@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CAiNavigatorImpl::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

/**
 * Address: 0x005A3610 (FUN_005A3610, ?GetMetatable@CAiNavigatorImpl@Moho@@QAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
 */
LuaPlus::LuaObject CAiNavigatorImpl::GetMetatable(LuaPlus::LuaState* const luaState)
{
  if (!luaState) {
    return {};
  }

  LuaPlus::LuaObject metatable;
  LuaPlus::LuaObject moduleObject = SCR_ImportLuaModule(luaState, kNavigatorLuaModulePath);
  if (!moduleObject.IsNil()) {
    LuaPlus::LuaObject navigatorTable = SCR_GetLuaTableField(luaState, moduleObject, kNavigatorLuaClassName);
    metatable = navigatorTable;
  }

  if (metatable.IsNil()) {
    metatable = GetNavigatorImplFactoryMetatable(luaState);
  }
  return metatable;
}

/**
 * Address: 0x005A3600 (FUN_005A3600)
 */
Unit* CAiNavigatorImpl::GetUnit()
{
  return mUnit;
}

/**
 * Address: 0x005A3750 (FUN_005A3750)
 */
void CAiNavigatorImpl::AbortMove()
{
  SetSpeedThroughGoal(false);
  if (NavigatorMakeIdle()) {
    DispatchNavigatorEvent(AINAVEVENT_Aborted);
  }
}

/**
 * Address: 0x005A3730 (FUN_005A3730)
 */
void CAiNavigatorImpl::BroadcastResumeTaskEvent()
{
  DispatchNavigatorEvent(AINAVEVENT_ResumeTask);
}

/**
 * Address: 0x005A37A0 (FUN_005A37A0)
 */
EAiNavigatorStatus CAiNavigatorImpl::GetStatus() const
{
  return mStatus;
}

/**
 * Address: 0x005A2D10 (FUN_005A2D10)
 */
void CAiNavigatorImpl::Func1()
{}

/**
 * Address: 0x005A2D20 (FUN_005A2D20)
 */
SNavPath* CAiNavigatorImpl::GetNavPath() const
{
  return nullptr;
}

/**
 * Address: 0x005A36F0 (FUN_005A36F0)
 */
void CAiNavigatorImpl::PushStack(LuaPlus::LuaState* const luaState)
{
  mLuaObj.PushStack(luaState);
}

/**
 * Address: 0x005A3710 (FUN_005A3710)
 */
bool CAiNavigatorImpl::NavigatorMakeIdle()
{
  if (mStatus == AINAVSTATUS_Idle) {
    return false;
  }

  mStatus = AINAVSTATUS_Idle;
  return true;
}

/**
 * Address: 0x005A6C50 (FUN_005A6C50 helper call chain)
 */
void CAiNavigatorImpl::DispatchNavigatorEvent(const std::int32_t eventCode)
{
  DispatchNavigatorEventList(mListenerNode, eventCode);
}
