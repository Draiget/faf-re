#include "moho/ai/CAiNavigatorImpl.h"

#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/SerializationError.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiBrain.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/Stats.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace moho
{
  CScrLuaInitForm* func_CAiNavigatorImplSetGoal_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplSetDestUnit_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplAbortMove_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplBroadcastResumeTaskEvent_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplSetSpeedThroughGoal_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplGetCurrentTargetPos_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplGetGoalPos_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplGetStatus_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplHasGoodPath_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplFollowingLeader_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplIgnoreFormation_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplIsIgnorningFormation_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplAtgoal_LuaFuncDef();
  CScrLuaInitForm* func_CAiNavigatorImplCanPathToGoal_LuaFuncDef();
} // namespace moho

namespace
{
  constexpr const char* kNavigatorLuaModulePath = "/lua/sim/Navigator.lua";
  constexpr const char* kNavigatorLuaClassName = "Navigator";
  CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59970 = nullptr;
  CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F59960 = nullptr;

  template <std::uintptr_t SlotAddress>
  struct StartupEngineStatsSlot
  {
    static EngineStats* value;
  };

  template <>
  EngineStats* StartupEngineStatsSlot<0x10AEDB0u>::value = nullptr;

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

  [[nodiscard]] CScrLuaInitFormSet* FindSimLuaInitSet() noexcept
  {
    for (CScrLuaInitFormSet* set = CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, "sim") == 0) {
        return set;
      }
    }

    return nullptr;
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
 * Address: 0x00BCC760 (FUN_00BCC760)
 *
 * What it does:
 * Saves current `sim` Lua-init form head and re-links it to recovered
 * navigator-Lua anchor lane `off_F59960`.
 */
CScrLuaInitForm* moho::register_CAiNavigatorImplLuaInitFormAnchor()
{
  CScrLuaInitFormSet* const simSet = FindSimLuaInitSet();
  if (simSet == nullptr) {
    gRecoveredSimLuaInitFormPrev_off_F59970 = nullptr;
    return nullptr;
  }

  CScrLuaInitForm* const previousHead = simSet->mForms;
  gRecoveredSimLuaInitFormPrev_off_F59970 = previousHead;
  simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gRecoveredSimLuaInitFormAnchor_off_F59960);
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
