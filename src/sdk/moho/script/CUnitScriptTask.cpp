#include "moho/script/CUnitScriptTask.h"

#include <exception>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/WeakPtr.h"
#include "moho/script/CScriptEvent.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kGetUnitName = "GetUnit";
  constexpr const char* kGetUnitHelpText = "Get the unit performing the task";
  constexpr const char* kSetAIResultName = "SetAIResult";
  constexpr const char* kSetAIResultHelpText = "Set the AI result, success or fail";
  constexpr const char* kUnitScriptTaskLuaClassName = "CUnitScriptTask";

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  /**
   * Address: 0x00623B10 (FUN_00623B10)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `CUnitScriptTask`.
   */
  [[nodiscard]] gpg::RType* CachedCUnitScriptTaskType()
  {
    if (!CUnitScriptTask::sType) {
      CUnitScriptTask::sType = gpg::LookupRType(typeid(CUnitScriptTask));
    }
    return CUnitScriptTask::sType;
  }

  /**
   * Address: 0x00624260 (FUN_00624260)
   *
   * What it does:
   * Upcasts one reflected reference lane to `moho::CUnitScriptTask*`.
   */
  [[maybe_unused]] [[nodiscard]] void* TryUpcastCUnitScriptTaskRefObject(gpg::RRef* const sourceRef)
  {
    if (!sourceRef) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(*sourceRef, CachedCUnitScriptTaskType());
    return upcast.mObj;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* cached = CCommandTask::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    return CScriptObject::StaticGetClass();
  }

  [[nodiscard]] gpg::RType* CachedLuaObjectType()
  {
    gpg::RType* cached = LuaPlus::LuaObject::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LuaPlus::LuaObject));
      LuaPlus::LuaObject::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCUnitCommandType()
  {
    gpg::RType* cached = CUnitCommand::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CUnitCommand));
      CUnitCommand::sType = cached;
    }
    return cached;
  }

  /**
   * Address: 0x00622A60 (FUN_00622A60, CUnitScriptTask class-resolve helper)
   *
   * What it does:
   * Resolves task class name from `sourceArgs["TaskName"]`, writes script
   * path, imports task module, and falls back to `ScriptTask` class lane.
   */
  [[nodiscard]] LuaPlus::LuaObject ResolveTaskClassFromSourceArgs(
    CUnitScriptTask* const task,
    const LuaPlus::LuaObject& sourceArgs
  )
  {
    LuaPlus::LuaObject taskClass{};
    LuaPlus::LuaState* const state = sourceArgs.GetActiveState();
    if (!task || !state) {
      return taskClass;
    }

    LuaPlus::LuaObject taskNameObject = sourceArgs.GetByName("TaskName");
    const char* taskName = (!taskNameObject.IsNil()) ? taskNameObject.GetString() : nullptr;
    if (taskName == nullptr || taskName[0] == '\0') {
      taskName = "ScriptTask";
    }

    task->mTaskScriptPath = gpg::STR_Printf("/lua/sim/tasks/%s.lua", taskName);

    taskClass.AssignNil(state);
    const LuaPlus::LuaObject importedTaskModule = SCR_Import(state, task->mTaskScriptPath.c_str());
    if (!importedTaskModule.IsNil()) {
      taskClass = importedTaskModule.GetByName(taskName);
    }

    if (taskClass.IsNil()) {
      gpg::Logf("Can't find task %s, using ScriptTask directly", taskName);
      const LuaPlus::LuaObject scriptTaskModule = SCR_Import(state, "/lua/sim/ScriptTask.lua");
      taskClass = scriptTaskModule.GetByName("ScriptTask");
    }

    return taskClass;
  }

  [[nodiscard]] gpg::RRef MakeCUnitScriptTaskRef(CUnitScriptTask* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedCUnitScriptTaskType();
    return ref;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] gpg::RRef MakeCUnitCommandRef(CUnitCommand* command)
  {
    gpg::RRef ref{};
    ref.mObj = nullptr;
    ref.mType = CachedCUnitCommandType();
    if (!command) {
      return ref;
    }

    gpg::RType* dynamicType = ref.mType;
    try {
      dynamicType = gpg::LookupRType(typeid(*command));
    } catch (...) {
      dynamicType = ref.mType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && ref.mType != nullptr && dynamicType->IsDerivedFrom(ref.mType, &baseOffset);
    if (!isDerived) {
      ref.mObj = command;
      ref.mType = dynamicType;
      return ref;
    }

    ref.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(command) - static_cast<std::uintptr_t>(baseOffset));
    ref.mType = dynamicType;
    return ref;
  }

  [[nodiscard]] CUnitCommand* ReadTrackedCUnitCommandPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCUnitCommandType());
    if (upcast.mObj) {
      return static_cast<CUnitCommand*>(upcast.mObj);
    }

    const char* const expected = CachedCUnitCommandType() ? CachedCUnitCommandType()->GetName() : "CUnitCommand";
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "CUnitCommand",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  [[nodiscard]] CScriptObject* ResolveWarningObject(const WeakObject::ScopedWeakLinkGuard& guard)
  {
    const WeakObject::WeakLinkSlot* const ownerLinkSlot = guard.OwnerLinkSlotAddress();
    if (!ownerLinkSlot) {
      return nullptr;
    }

    return WeakPtr<CScriptObject>::DecodeOwnerObject(
      reinterpret_cast<void*>(const_cast<WeakObject::WeakLinkSlot*>(ownerLinkSlot))
    );
  }

  struct CUnitScriptTaskListenerLaneRuntime
  {
    moho::TDatListItem<moho::Broadcaster, void>* mPrev = nullptr;   // +0x00
    moho::TDatListItem<moho::Broadcaster, void>* mNext = nullptr;   // +0x04
    std::uint8_t reserved08_0B[0x04]{};
    moho::TDatListItem<moho::Broadcaster, void>* mAnchor = nullptr; // +0x0C
    std::uint8_t reserved10_13[0x04]{};
    std::uint32_t dispatchState = 0;            // +0x14
    std::uint8_t linkState = 0;                 // +0x18
  };
  static_assert(
    offsetof(CUnitScriptTaskListenerLaneRuntime, mAnchor) == 0x0C,
    "CUnitScriptTaskListenerLaneRuntime::mAnchor offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitScriptTaskListenerLaneRuntime, dispatchState) == 0x14,
    "CUnitScriptTaskListenerLaneRuntime::dispatchState offset must be 0x14"
  );
  static_assert(
    offsetof(CUnitScriptTaskListenerLaneRuntime, linkState) == 0x18,
    "CUnitScriptTaskListenerLaneRuntime::linkState offset must be 0x18"
  );

  struct CUnitScriptTaskListenerBridgeRuntime
  {
    std::uint8_t reserved00_0B[0x0C]{};
    CUnitScriptTaskListenerLaneRuntime* listenerLane = nullptr; // +0x0C
    std::uint8_t reserved10_23[0x14]{};
    std::uint32_t pendingEventState = 0;                        // +0x24
  };
  static_assert(
    offsetof(CUnitScriptTaskListenerBridgeRuntime, listenerLane) == 0x0C,
    "CUnitScriptTaskListenerBridgeRuntime::listenerLane offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitScriptTaskListenerBridgeRuntime, pendingEventState) == 0x24,
    "CUnitScriptTaskListenerBridgeRuntime::pendingEventState offset must be 0x24"
  );

  /**
   * Address: 0x006230F0 (FUN_006230F0)
   *
   * What it does:
   * Clears one pending listener-event state lane and, when linked, unlinks and
   * reinserts the listener node before its anchor broadcaster.
   */
  [[maybe_unused]] int CUnitScriptTaskRepairListenerLinkRuntime(
    void* const listenerRuntime,
    int
  ) noexcept
  {
    auto* const listenerBase = static_cast<std::uint8_t*>(listenerRuntime);
    auto* const taskRuntime = reinterpret_cast<CUnitScriptTaskListenerBridgeRuntime*>(listenerBase - 0x64);
    taskRuntime->pendingEventState = 0;

    CUnitScriptTaskListenerLaneRuntime* const lane = taskRuntime->listenerLane;
    if (lane == nullptr) {
      return 0;
    }

    const bool alreadyUnlinked = (lane->linkState == 0);
    lane->dispatchState = 0;
    if (!alreadyUnlinked) {
      auto* const anchor = lane->mAnchor;
      auto* const laneLink = reinterpret_cast<moho::TDatListItem<moho::Broadcaster, void>*>(lane);
      lane->mPrev->mNext = lane->mNext;
      lane->mNext->mPrev = lane->mPrev;
      lane->mPrev = laneLink;
      lane->mNext = laneLink;
      lane->mPrev = anchor->mPrev;
      lane->mNext = anchor;
      anchor->mPrev = laneLink;
      lane->mPrev->mNext = laneLink;
      lane->linkState = 0;
    }

    return static_cast<int>(reinterpret_cast<std::intptr_t>(lane));
  }
} // namespace

gpg::RType* CUnitScriptTask::sType = nullptr;
CScrLuaMetatableFactory<CUnitScriptTask> CScrLuaMetatableFactory<CUnitScriptTask>::sInstance{};

/**
  * Alias of FUN_10015880 (non-canonical helper lane).
 *
 * What it does:
 * Stores one metatable-factory index used by `CScrLuaObjectFactory::Get`.
 */
moho::CScrLuaMetatableFactory<moho::CUnitScriptTask>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

moho::CScrLuaMetatableFactory<moho::CUnitScriptTask>&
moho::CScrLuaMetatableFactory<moho::CUnitScriptTask>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x006240F0 (FUN_006240F0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<CUnitScriptTask>` and returns that singleton.
 */
moho::CScrLuaMetatableFactory<moho::CUnitScriptTask>*
moho::startup_CScrLuaMetatableFactory_CUnitScriptTask_Index()
{
  auto& instance = CScrLuaMetatableFactory<CUnitScriptTask>::Instance();
  instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
  return &instance;
}

/**
 * Address: 0x00623B50 (FUN_00623B50, ?Create@?$CScrLuaMetatableFactory@VCUnitScriptTask@Moho@@@Moho@@MAE?AVLuaObject@LuaPlus@@PAVLuaState@4@@Z)
 *
 * What it does:
 * Creates the default metatable used by `CUnitScriptTask` Lua userdata.
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CUnitScriptTask>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

/**
 * Address: 0x00622810 (FUN_00622810, default ctor)
 */
CUnitScriptTask::CUnitScriptTask()
  : CCommandTask()
  , CScriptObject()
  , Listener<ECommandEvent>()
  , mSourceCommand(nullptr)
  , mSourceLuaObj()
  , mTaskClassLua()
  , mTaskScriptPath()
{}

/**
 * Address: 0x006228B0 (FUN_006228B0, dispatch ctor lane)
 */
CUnitScriptTask::CUnitScriptTask(IAiCommandDispatchImpl* const dispatchTask, const LuaPlus::LuaObject& sourceArgs)
  : CCommandTask(static_cast<CCommandTask*>(dispatchTask))
  , CScriptObject()
  , Listener<ECommandEvent>()
  , mSourceCommand(nullptr)
  , mSourceLuaObj(sourceArgs)
  , mTaskClassLua()
  , mTaskScriptPath()
{
  if (mUnit != nullptr && mUnit->CommandQueue != nullptr) {
    mSourceCommand = mUnit->CommandQueue->GetCurrentCommand();
  }

  if (mSourceCommand != nullptr) {
    mListenerLink.ListLinkBefore(static_cast<Broadcaster*>(mSourceCommand));
  }

  mTaskClassLua = ResolveTaskClassFromSourceArgs(this, mSourceLuaObj);

  LuaPlus::LuaObject nilArg1{};
  LuaPlus::LuaObject nilArg2{};
  LuaPlus::LuaObject nilArg3{};
  LuaPlus::LuaState* const state = mSourceLuaObj.GetActiveState();
  if (state != nullptr) {
    nilArg1.AssignNil(state);
    nilArg2.AssignNil(state);
    nilArg3.AssignNil(state);
  }

  CreateLuaObject(mTaskClassLua, nilArg1, nilArg2, nilArg3);
  LuaCall("OnCreate", &mSourceLuaObj);
}

/**
 * Address: 0x00622F70 (FUN_00622F70, Moho::CUnitScriptTask::operator new)
 */
CUnitScriptTask* CUnitScriptTask::Create(IAiCommandDispatchImpl* const dispatchTask, LuaPlus::LuaObject* const sourceArgs)
{
  if (sourceArgs != nullptr) {
    return new (std::nothrow) CUnitScriptTask(dispatchTask, *sourceArgs);
  }

  const LuaPlus::LuaObject emptyArgs{};
  return new (std::nothrow) CUnitScriptTask(dispatchTask, emptyArgs);
}

/**
 * Address: 0x00623140 (FUN_00623140, non-deleting body)
 */
CUnitScriptTask::~CUnitScriptTask()
{
  CallbackStr("OnDestroy");
  mListenerLink.ListUnlink();
}

/**
 * Address: 0x006227D0 (FUN_006227D0, ?GetClass@CUnitScriptTask@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CUnitScriptTask::GetClass() const
{
  return CachedCUnitScriptTaskType();
}

/**
 * Address: 0x006227F0 (FUN_006227F0, ?GetDerivedObjectRef@CUnitScriptTask@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CUnitScriptTask::GetDerivedObjectRef()
{
  return MakeCUnitScriptTaskRef(this);
}

/**
 * Address: 0x006233C0 (FUN_006233C0, cfunc_CUnitScriptTaskGetUnit)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUnitScriptTaskGetUnitL`.
 */
int moho::cfunc_CUnitScriptTaskGetUnit(lua_State* const luaContext)
{
  return cfunc_CUnitScriptTaskGetUnitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x006233E0 (FUN_006233E0, func_CUnitScriptTaskGetUnit_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUnitScriptTask:GetUnit()` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUnitScriptTaskGetUnit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kGetUnitName,
    &moho::cfunc_CUnitScriptTaskGetUnit,
    &CScrLuaMetatableFactory<CUnitScriptTask>::Instance(),
    kUnitScriptTaskLuaClassName,
    kGetUnitHelpText
  );
  return &binder;
}

/**
 * Address: 0x00623440 (FUN_00623440, cfunc_CUnitScriptTaskGetUnitL)
 *
 * What it does:
 * Resolves one `CUnitScriptTask` and pushes owner-unit Lua userdata.
 */
int moho::cfunc_CUnitScriptTaskGetUnitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUnitHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject taskObject(LuaPlus::LuaStackObject(state, 1));
  CUnitScriptTask* const task = SCR_FromLua_CUnitScriptTask(taskObject, state);
  task->mUnit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x006234F0 (FUN_006234F0, cfunc_CUnitScriptTaskSetAIResult)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to
 * `cfunc_CUnitScriptTaskSetAIResultL`.
 */
int moho::cfunc_CUnitScriptTaskSetAIResult(lua_State* const luaContext)
{
  return cfunc_CUnitScriptTaskSetAIResultL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00623510 (FUN_00623510, func_CUnitScriptTaskSetAIResult_LuaFuncDef)
 *
 * What it does:
 * Publishes the `CUnitScriptTask:SetAIResult(result)` Lua binder.
 */
moho::CScrLuaInitForm* moho::func_CUnitScriptTaskSetAIResult_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    kSetAIResultName,
    &moho::cfunc_CUnitScriptTaskSetAIResult,
    &CScrLuaMetatableFactory<CUnitScriptTask>::Instance(),
    kUnitScriptTaskLuaClassName,
    kSetAIResultHelpText
  );
  return &binder;
}

/**
 * Address: 0x00623570 (FUN_00623570, cfunc_CUnitScriptTaskSetAIResultL)
 *
 * What it does:
 * Resolves one `CUnitScriptTask` and writes one integer AI-result lane.
 */
int moho::cfunc_CUnitScriptTaskSetAIResultL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAIResultHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject taskObject(LuaPlus::LuaStackObject(state, 1));
  CUnitScriptTask* const task = SCR_FromLua_CUnitScriptTask(taskObject, state);

  LuaPlus::LuaStackObject resultArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    resultArg.TypeError("integer");
  }

  const int rawResult = static_cast<int>(lua_tonumber(rawState, 2));
  *task->mDispatchResult = static_cast<EAiResult>(rawResult);
  return 0;
}

/**
 * Address: 0x00623EF0 (FUN_00623EF0, serializer load thunk alias)
 *
 * What it does:
 * Tail-forwards one CUnitScriptTask serializer-load thunk alias into
 * `CUnitScriptTask::MemberDeserialize`.
 */
namespace moho
{
[[maybe_unused]] void DeserializeCUnitScriptTaskThunkVariantA(
  const int version,
  CUnitScriptTask* const task,
  gpg::ReadArchive* const archive
)
{
  CUnitScriptTask::MemberDeserialize(archive, task, version);
}

/**
 * Address: 0x00624190 (FUN_00624190, serializer load thunk alias)
 *
 * What it does:
 * Tail-forwards a second CUnitScriptTask serializer-load thunk alias into
 * `CUnitScriptTask::MemberDeserialize`.
 */
[[maybe_unused]] void DeserializeCUnitScriptTaskThunkVariantB(
  const int version,
  CUnitScriptTask* const task,
  gpg::ReadArchive* const archive
)
{
  CUnitScriptTask::MemberDeserialize(archive, task, version);
}

/**
 * Address: 0x00623F00 (FUN_00623F00, serializer save thunk alias)
 *
 * What it does:
 * Tail-forwards one CUnitScriptTask serializer-save thunk alias into
 * `CUnitScriptTask::MemberSerialize`.
 */
[[maybe_unused]] void SerializeCUnitScriptTaskThunkVariantA(
  const int version,
  gpg::WriteArchive* const archive,
  CUnitScriptTask* const task
)
{
  CUnitScriptTask::MemberSerialize(task, archive, version);
}

/**
 * Address: 0x006241A0 (FUN_006241A0, serializer save thunk alias)
 *
 * What it does:
 * Tail-forwards a second CUnitScriptTask serializer-save thunk alias into
 * `CUnitScriptTask::MemberSerialize`.
 */
[[maybe_unused]] void SerializeCUnitScriptTaskThunkVariantB(
  const int version,
  gpg::WriteArchive* const archive,
  CUnitScriptTask* const task
)
{
  CUnitScriptTask::MemberSerialize(task, archive, version);
}
} // namespace moho

/**
 * Address: 0x00624450 (FUN_00624450, Moho::CUnitScriptTask::MemberDeserialize)
 */
void CUnitScriptTask::MemberDeserialize(gpg::ReadArchive* const archive, CUnitScriptTask* const task, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version of CUnitScriptTask");
  }

  gpg::RRef owner{};
  archive->Read(CachedCCommandTaskType(), task, owner);

  CScriptObject* const scriptObject = task ? static_cast<CScriptObject*>(task) : nullptr;
  gpg::RRef scriptOwner{};
  archive->Read(CachedCScriptObjectType(), scriptObject, scriptOwner);

  gpg::RRef pointerOwner{};
  task->mSourceCommand = ReadTrackedCUnitCommandPointer(archive, pointerOwner);

  gpg::RRef luaOwner{};
  archive->Read(CachedLuaObjectType(), &task->mSourceLuaObj, luaOwner);
}

/**
 * Address: 0x00624550 (FUN_00624550, Moho::CUnitScriptTask::MemberSerialize)
 */
void CUnitScriptTask::MemberSerialize(CUnitScriptTask* const task, gpg::WriteArchive* const archive, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version of CUnitScriptTask");
  }

  gpg::RRef owner{};
  archive->Write(CachedCCommandTaskType(), task, owner);

  CScriptObject* const scriptObject = task ? static_cast<CScriptObject*>(task) : nullptr;
  gpg::RRef scriptOwner{};
  archive->Write(CachedCScriptObjectType(), scriptObject, scriptOwner);

  const gpg::RRef sourceCommandRef = MakeCUnitCommandRef(task->mSourceCommand);
  gpg::WriteRawPointer(archive, sourceCommandRef, gpg::TrackedPointerState::Unowned, scriptOwner);

  gpg::RRef luaOwner{};
  archive->Write(CachedLuaObjectType(), &task->mSourceLuaObj, luaOwner);
}

/**
 * Address: 0x00622FC0 (FUN_00622FC0, CUnitScriptTask primary-slot update)
 */
int CUnitScriptTask::Execute()
{
  WeakObject::ScopedWeakLinkGuard weakGuard(static_cast<WeakObject*>(static_cast<CScriptObject*>(this)));

  try {
    return CScriptObject::TaskTick();
  } catch (const std::exception& ex) {
    LogScriptWarning(ResolveWarningObject(weakGuard), mTaskScriptPath.c_str(), ex.what());
  } catch (...) {
    LogScriptWarning(ResolveWarningObject(weakGuard), mTaskScriptPath.c_str(), "unknown exception");
  }

  return -1;
}

void CUnitScriptTask::OnEvent(const ECommandEvent)
{
  (void)Execute();
}

namespace gpg
{
  /**
   * Address: 0x006240C0 (FUN_006240C0, reflection pair-pack thunk alias)
   *
   * What it does:
   * Builds one `CUnitScriptTask` reflection reference then writes the pair into
   * caller-provided `RRef` storage.
   */
  gpg::RRef* PackCUnitScriptTaskRefPair(
    moho::CUnitScriptTask* const value,
    gpg::RRef* const outPair
  )
  {
    gpg::RRef typedRef{};
    (void)gpg::RRef_CUnitScriptTask(&typedRef, value);
    *outPair = typedRef;
    return outPair;
  }

  /**
   * Address: 0x006242A0 (FUN_006242A0, gpg::RRef_CUnitScriptTask)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitScriptTask*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitScriptTask(gpg::RRef* const outRef, moho::CUnitScriptTask* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeDerivedRef(value, CachedCUnitScriptTaskType());
    return outRef;
  }
} // namespace gpg
