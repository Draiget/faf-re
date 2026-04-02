#include "CLuaTask.h"

#include <string>
#include <typeinfo>

#include "CTaskThread.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/StatItem.h"

extern "C" {
void lua_traceback(lua_State* L, const char* message);
}

using namespace moho;

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kResumeThreadHelpText =
    "ResumeThread(thread) -- resume a thread that had been suspended with SuspendCurrentThread(). Does nothing if "
    "the thread wasn't suspended.";
  constexpr const char* kResumeThreadKilledTraceback = "Attempted to resume a thread that was already killed";
  constexpr const char* kResumeThreadTypeError = "thread";
  constexpr const char* kResumeThreadForkOnlyError = "Can't resume a thread that wasn't created with ForkThread.";

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

  void AddStatCounter(moho::StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }
#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  gpg::RType* CachedCLuaTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CLuaTask));
    }
    return cached;
  }

  gpg::RType* CachedCTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTask));
    }
    return cached;
  }

  void AddCTaskBaseToTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const taskType = CachedCTaskType();
    gpg::RField baseField{};
    baseField.mName = taskType->GetName();
    baseField.mType = taskType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  const char* LuaErrorString(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return "<no lua state>";
    }

    const char* const text = lua_tostring(state->m_state, -1);
    return text ? text : "<non-string lua error>";
  }

  /**
   * Address: 0x004C9C40 (FUN_004C9C40, CLuaTaskSerializer::Deserialize callback)
   * Chain:   0x004CC2B0 (FUN_004CC2B0)
   */
  void DeserializeCLuaTask(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const task = reinterpret_cast<CLuaTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004C9C50 (FUN_004C9C50, CLuaTaskSerializer::Serialize callback)
   * Chain:   0x004CC320 (FUN_004CC320)
   */
  void SerializeCLuaTask(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const task = reinterpret_cast<CLuaTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);
    task->MemberSerialize(archive);
  }
} // namespace

/**
 * Address: 0x004D33A0 (FUN_004D33A0,
 * ?SCR_Traceback@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@PAVLuaState@LuaPlus@@VStrArg@gpg@@@Z)
 *
 * LuaPlus::LuaState *, gpg::StrArg
 *
 * What it does:
 * Pushes lua traceback text for the provided message and returns it as string.
 */
msvc8::string moho::SCR_Traceback(LuaPlus::LuaState* const state, const gpg::StrArg message)
{
  if (!state || !state->m_state) {
    return msvc8::string(message ? message : "");
  }

  lua_traceback(state->m_state, message);
  const char* const traceback = lua_tostring(state->m_state, -1);
  msvc8::string out(traceback ? traceback : "<non-string traceback>");
  lua_settop(state->m_state, -2);
  return out;
}

/**
 * Address: 0x004CB370 (FUN_004CB370, Moho::InstanceCounter<Moho::CLuaTask>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the stat slot used for CLuaTask instance-count
 * tracking (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CLuaTask>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  moho::EngineStats* const engineStats = moho::GetEngineStats();
  if (!engineStats) {
    return nullptr;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CLuaTask).name());
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x004C9570 (FUN_004C9570, ??0CLuaTask@Moho@@QAE@@Z)
 *
 * What it does:
 * Pushes this task on the provided thread stack, adopts one pending LuaState
 * pointer from `newState`, resets resume-argument state, and binds
 * `state->m_luaTask` back to this task.
 */
CLuaTask::CLuaTask(CTaskThread* const thread, LuaPlus::LuaState** const newState)
  : CTask(thread, thread != nullptr)
  , mLuaState(newState ? *newState : nullptr)
  , mResumeArgCount(0)
  , mExecuteDestroyedFlag(nullptr)
{
  AddStatCounter(InstanceCounter<CLuaTask>::GetStatItem(), 1);

  if (newState) {
    *newState = nullptr;
  }

  if (mLuaState) {
    mLuaState->m_luaTask = this;
  }
}

/**
 * Address: 0x004C9610 (FUN_004C9610, non-deleting body)
 *
 * What it does:
 * Handles running-execute guard race, releases owned LuaState when safe, then
 * tears down base task state.
 */
CLuaTask::~CLuaTask()
{
  if (mExecuteDestroyedFlag != nullptr) {
    if (mLuaState != nullptr) {
      mLuaState->m_luaTask = nullptr;
    }
    *mExecuteDestroyedFlag = true;
  } else {
    delete mLuaState;
  }

  AddStatCounter(InstanceCounter<CLuaTask>::GetStatItem(), -1);
}

/**
 * Address: 0x004C9700 (FUN_004C9700, ?Execute@CLuaTask@Moho@@UAEHXZ)
 */
int CLuaTask::Execute()
{
  LuaPlus::LuaState* const state = mLuaState;
  if (!state || !state->m_state) {
    return -1;
  }

  bool destroyedByDtor = false;
  mExecuteDestroyedFlag = &destroyedByDtor;

  try {
    const int resumeResult = lua_resume(state->m_state, mResumeArgCount);

    if (destroyedByDtor) {
      if (resumeResult != 0) {
        gpg::Warnf("Error running lua script from destroyed thread: %s", LuaErrorString(state));
      }

      delete state;
      return 1;
    }

    mExecuteDestroyedFlag = nullptr;

    if (resumeResult != 0) {
      gpg::Warnf("Error running lua script: %s", LuaErrorString(state));
      return -1;
    }

    mResumeArgCount = 0;

    if (lua_type(state->m_state, 1) == LUA_TNONE) {
      return -1;
    }

    if (lua_type(state->m_state, 1) == LUA_TNUMBER) {
      const int ticks = static_cast<int>(lua_tonumber(state->m_state, 1));
      if (ticks >= 0) {
        return ticks;
      }

      const msvc8::string traceback = SCR_Traceback(state, "Invalid args to yield(); tick count must be >=0");
      gpg::Warnf("%s", traceback.c_str());
      return -1;
    }

    const msvc8::string traceback = SCR_Traceback(state, "Invalid args to yield(); expected tick count");
    gpg::Warnf("%s", traceback.c_str());
    return -1;
  } catch (...) {
    if (destroyedByDtor) {
      delete state;
    } else {
      mExecuteDestroyedFlag = nullptr;
    }
    throw;
  }
}

/**
 * Address: 0x004C9D80 (FUN_004C9D80, cfunc_ForkThreadL)
 *
 * What it does:
 * Validates a function argument, creates one coroutine LuaState + CLuaTask
 * pair bound to the caller's task stage, copies call arguments onto the new
 * coroutine stack, pushes the new thread object to the caller, and mirrors
 * active hook settings.
 */
int moho::cfunc_ForkThreadL(LuaPlus::LuaState* const curState)
{
  if (lua_gettop(curState->m_state) == 0) {
    LuaPlus::LuaState::Error(curState, "ForkThread: missing FUNCTION argument");
  }

  const LuaPlus::LuaObject functionObject(LuaPlus::LuaStackObject(curState, 1));
  if (!functionObject.IsFunction()) {
    LuaPlus::LuaState::Error(curState, "ForkThread: first argument isn't a function");
  }

  CTaskStage* ownerStage = nullptr;
  LuaPlus::LuaState* const rootState = curState->m_rootState;
  if (rootState == curState) {
    ownerStage = reinterpret_cast<CTaskStage*>(curState->m_luaTask);
  } else {
    CLuaTask* const currentTask = curState->m_luaTask;
    if (currentTask && currentTask->mOwnerThread) {
      ownerStage = currentTask->mOwnerThread->mStage;
    } else {
      ownerStage = rootState ? reinterpret_cast<CTaskStage*>(rootState->m_luaTask) : nullptr;
    }
  }

  if (!ownerStage) {
    LuaPlus::LuaState::Error(curState, "ForkThread: Lua state has not been set up for multiple threads");
  }

  LuaPlus::LuaState* const threadState = new LuaPlus::LuaState(curState);
  LuaPlus::LuaState* pendingTransferState = threadState;
  CLuaTask* const task = new CLuaTask(new CTaskThread(ownerStage), &pendingTransferState);

  functionObject.PushStack(threadState->m_state);

  const int argumentCount = lua_gettop(curState->m_state);
  for (int stackIndex = 2; stackIndex <= argumentCount; ++stackIndex) {
    const LuaPlus::LuaObject argumentObject(LuaPlus::LuaStackObject(curState, stackIndex));
    argumentObject.PushStack(task->mLuaState->m_state);
    ++task->mResumeArgCount;
  }

  const LuaPlus::LuaObject threadObject(threadState->m_threadObj);
  threadObject.PushStack(curState);

  const int hookMask = lua_gethookmask(curState->m_state);
  if (hookMask != 0) {
    lua_Hook hookFunction = lua_gethook(curState->m_state);
    lua_sethook(threadState->m_state, hookFunction, hookMask, 0);
  }

  if (pendingTransferState != nullptr) {
    delete pendingTransferState;
  }

  return 1;
}

/**
 * Address: 0x004C9D00 (FUN_004C9D00, cfunc_ForkThread)
 *
 * What it does:
 * Unwraps binding context and forwards to `cfunc_ForkThreadL`.
 */
int moho::cfunc_ForkThread(lua_State* const luaContext)
{
  return cfunc_ForkThreadL(luaContext->stateUserData);
}

/**
 * Address: 0x004CAC10 (FUN_004CAC10, cfunc_ResumeThreadL)
 *
 * What it does:
 * Validates one coroutine thread argument, warns on stale-killed thread
 * handles, and resumes a ForkThread-created task thread by clearing pending
 * frames and unstaging the owner thread.
 */
int moho::cfunc_ResumeThreadL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kResumeThreadHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject threadArgument(state, 1);
  lua_State* const rawThreadState = lua_tothread(state->m_state, 1);
  if (!rawThreadState) {
    threadArgument.TypeError(kResumeThreadTypeError);
  }

  LuaPlus::LuaState* const threadState = rawThreadState ? rawThreadState->stateUserData : nullptr;
  if (!threadState) {
    const msvc8::string traceback = SCR_Traceback(state, kResumeThreadKilledTraceback);
    gpg::Warnf(traceback.c_str());
    return 0;
  }

  CLuaTask* const threadTask = threadState->m_luaTask;
  if (threadState->m_rootState == threadState || !threadTask) {
    LuaPlus::LuaState::Error(state, kResumeThreadForkOnlyError);
  }

  CTaskThread* const taskThread = threadTask->mOwnerThread;
  if (taskThread) {
    taskThread->mPendingFrames = 0;
    if (taskThread->mStaged) {
      taskThread->Unstage();
    }
  }

  return 0;
}

/**
 * Address: 0x004CAB90 (FUN_004CAB90, cfunc_ResumeThread)
 *
 * What it does:
 * Unwraps binding context and forwards to `cfunc_ResumeThreadL`.
 */
int moho::cfunc_ResumeThread(lua_State* const luaContext)
{
  return cfunc_ResumeThreadL(luaContext->stateUserData);
}

/**
 * Address: 0x004CC2B0 (FUN_004CC2B0, Moho::CLuaTask::MemberDeserialize)
 */
void CLuaTask::MemberDeserialize(gpg::ReadArchive* const archive)
{
  gpg::RType* taskType = CTask::sType;
  if (!taskType) {
    taskType = gpg::LookupRType(typeid(CTask));
    CTask::sType = taskType;
  }

  gpg::RRef ownerRef{};
  archive->Read(taskType, this, ownerRef);
  (void)archive->ReadPointer_LuaState(&mLuaState, &ownerRef);
  archive->ReadInt(&mResumeArgCount);

  if (mLuaState) {
    mLuaState->m_luaTask = this;
  }
}

/**
 * Address: 0x004CC320 (FUN_004CC320, Moho::CLuaTask::MemberSerialize)
 */
void CLuaTask::MemberSerialize(gpg::WriteArchive* const archive)
{
  gpg::RType* taskType = CTask::sType;
  if (!taskType) {
    taskType = gpg::LookupRType(typeid(CTask));
    CTask::sType = taskType;
  }

  gpg::RRef ownerRef{};
  archive->Write(taskType, this, ownerRef);
  gpg::RRef stateRef{};
  (void)gpg::RRef_LuaState(&stateRef, mLuaState);
  gpg::WriteRawPointer(archive, stateRef, gpg::TrackedPointerState::Owned, ownerRef);
  archive->WriteInt(mResumeArgCount);

  if (mLuaState) {
    mLuaState->m_luaTask = this;
  }
}

/**
 * Address: 0x004CAF60 (FUN_004CAF60, sub_4CAF60)
 */
void CLuaTaskConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCLuaTaskType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mSerConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

/**
 * Address: 0x004CAFE0 (FUN_004CAFE0, sub_4CAFE0)
 */
void CLuaTaskSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCLuaTaskType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = &DeserializeCLuaTask;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = &SerializeCLuaTask;
}

/**
 * Address: 0x004C9A60 (FUN_004C9A60, scalar deleting destructor thunk)
 */
CLuaTaskTypeInfo::~CLuaTaskTypeInfo() = default;

/**
 * Address: 0x004C9A50 (FUN_004C9A50, ?GetName@CLuaTaskTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CLuaTaskTypeInfo::GetName() const
{
  return "CLuaTask";
}

/**
 * Address: 0x004C9A30 (FUN_004C9A30, ?Init@CLuaTaskTypeInfo@Moho@@UAEXXZ)
 */
void CLuaTaskTypeInfo::Init()
{
  size_ = sizeof(CLuaTask);
  gpg::RType::Init();
  AddCTaskBaseToTypeInfo(this);
  Finish();
}
