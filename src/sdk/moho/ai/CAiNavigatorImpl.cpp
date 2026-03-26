#include "moho/ai/CAiNavigatorImpl.h"

#include <typeinfo>

#include "lua/LuaObject.h"
#include "moho/ai/CAiBrain.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  constexpr const char* kNavigatorLuaModulePath = "/lua/sim/Navigator.lua";
  constexpr const char* kNavigatorLuaClassName = "Navigator";

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
} // namespace

gpg::RType* CAiNavigatorImpl::sType = nullptr;
CScrLuaMetatableFactory<CAiNavigatorImpl> CScrLuaMetatableFactory<CAiNavigatorImpl>::sInstance{};

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
 * Address: 0x005A33A0 (FUN_005A33A0, ?GetClass@CAiNavigatorImpl@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CAiNavigatorImpl::GetClass() const
{
  gpg::RType* type = sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiNavigatorImpl));
    sType = type;
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
