#include "CLuaTask.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <string>
#include <typeinfo>

#include "CTaskThread.h"
#include "CWaitForTask.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/misc/StatItem.h"
#include "moho/script/CScriptEvent.h"

extern "C" {
int lua_traceback(lua_State* L, const char* message, int level);
}

using namespace moho;

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kWaitForHelpText = "WaitFor(event) -- suspend this thread until the event is set";
  constexpr const char* kWaitForForkOnlyError = "Can't suspend a thread that wasn't created with ForkThread.";
  constexpr const char* kForkThreadHelpText =
    "thread = ForkThread(function, ...)\nSpawns a new thread running the given function with the given args.";
  constexpr const char* kKillThreadHelpText = "KillThread(thread) -- destroy a thread started with ForkThread()";
  constexpr const char* kKillThreadForkOnlyError = "KillThread: Can't kill a thread that wasn't created with ForkThread.";
  constexpr const char* kSuspendCurrentThreadHelpText =
    "SuspendCurrentThread() -- suspend this thread indefinitely. Some external event must eventually call "
    "ResumeThread() to resume it.";
  constexpr const char* kResumeThreadHelpText =
    "ResumeThread(thread) -- resume a thread that had been suspended with SuspendCurrentThread(). Does nothing if "
    "the thread wasn't suspended.";
  constexpr const char* kCurrentThreadHelpText =
    "thread=CurrentThread() -- get a handle to the running thread for later use with ResumeThread() or KillThread()";
  constexpr const char* kResumeThreadKilledTraceback = "Attempted to resume a thread that was already killed";
  constexpr const char* kResumeThreadTypeError = "thread";
  constexpr const char* kResumeThreadForkOnlyError = "Can't resume a thread that wasn't created with ForkThread.";
  alignas(moho::CLuaTaskTypeInfo) std::byte gCLuaTaskTypeInfoStorage[sizeof(moho::CLuaTaskTypeInfo)]{};
  bool gCLuaTaskTypeInfoConstructed = false;
  alignas(moho::CLuaTaskConstruct) std::byte gCLuaTaskConstructStorage[sizeof(moho::CLuaTaskConstruct)]{};
  bool gCLuaTaskConstructInitialized = false;
  moho::CLuaTaskSerializer gCLuaTaskSerializer{};

  [[nodiscard]] moho::CLuaTaskTypeInfo& CLuaTaskTypeInfoSlot()
  {
    return *reinterpret_cast<moho::CLuaTaskTypeInfo*>(gCLuaTaskTypeInfoStorage);
  }

  [[nodiscard]] moho::CLuaTaskConstruct& CLuaTaskConstructSlot()
  {
    return *reinterpret_cast<moho::CLuaTaskConstruct*>(gCLuaTaskConstructStorage);
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mNext);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    auto* const next = static_cast<gpg::SerHelperBase*>(serializer.mNext);
    auto* const prev = static_cast<gpg::SerHelperBase*>(serializer.mPrev);
    if (next != nullptr && prev != nullptr) {
      next->mPrev = prev;
      prev->mNext = next;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mPrev = self;
    serializer.mNext = self;
    return self;
  }

  template <typename TSerializer>
  void ResetSerializerNode(TSerializer& serializer) noexcept
  {
    if (serializer.mNext == nullptr || serializer.mPrev == nullptr) {
      gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
      serializer.mPrev = self;
      serializer.mNext = self;
      return;
    }

    (void)UnlinkSerializerNode(serializer);
  }

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

  /**
   * Address: 0x004C99D0 (FUN_004C99D0, CLuaTask startup type-info pre-registration)
   *
   * What it does:
   * Materializes one startup `CLuaTaskTypeInfo` storage lane and pre-registers
   * the type descriptor for `typeid(CLuaTask)`.
   */
  [[nodiscard]] gpg::RType* PreRegisterCLuaTaskTypeInfo()
  {
    if (!gCLuaTaskTypeInfoConstructed) {
      ::new (static_cast<void*>(&CLuaTaskTypeInfoSlot())) moho::CLuaTaskTypeInfo();
      gCLuaTaskTypeInfoConstructed = true;
    }

    gpg::PreRegisterRType(typeid(CLuaTask), &CLuaTaskTypeInfoSlot());
    return &CLuaTaskTypeInfoSlot();
  }

  /**
   * Address: 0x00BF0A60 (FUN_00BF0A60, CLuaTask type-info cleanup at exit)
   *
   * What it does:
   * Releases dynamic field/base arrays from startup CLuaTask type-info storage
   * and tears down the placement-constructed type descriptor.
   */
  void CleanupCLuaTaskTypeInfoAtExit()
  {
    if (!gCLuaTaskTypeInfoConstructed) {
      return;
    }

    CLuaTaskTypeInfoSlot().fields_ = msvc8::vector<gpg::RField>{};
    CLuaTaskTypeInfoSlot().bases_ = msvc8::vector<gpg::RField>{};
    CLuaTaskTypeInfoSlot().~CLuaTaskTypeInfo();
    gCLuaTaskTypeInfoConstructed = false;
  }

  /**
   * Address: 0x004C9910 (FUN_004C9910, CLuaTask construct storage initializer)
   *
   * What it does:
   * Builds one raw `CLuaTask` object for serializer-construct paths with null
   * owner thread and null LuaState lane.
   */
  [[nodiscard]] CLuaTask* InitializeRawCLuaTaskConstructStorage(void* const storage)
  {
    if (!storage) {
      return nullptr;
    }
    return ::new (storage) CLuaTask(nullptr, nullptr);
  }

  /**
   * Address: 0x004C9BB0 (FUN_004C9BB0, CLuaTask construct callback body)
   *
   * What it does:
   * Placement-constructs one CLuaTask object in caller-provided storage for
   * reflection construct-function registration.
   */
  void ConstructCLuaTaskInPlace(void* const objectStorage)
  {
    (void)InitializeRawCLuaTaskConstructStorage(objectStorage);
  }

  /**
   * Address: 0x004CB6E0 (FUN_004CB6E0, CLuaTask construct delete callback)
   *
   * What it does:
   * Deletes one construct-path CLuaTask object through its virtual deleting
   * destructor.
   */
  void DeleteConstructedCLuaTask(void* const objectStorage)
  {
    auto* const task = static_cast<CLuaTask*>(objectStorage);
    if (!task) {
      return;
    }
    delete task;
  }

  /**
   * Address: 0x00BF0AC0 (FUN_00BF0AC0, CLuaTask construct cleanup primary)
   *
   * What it does:
   * Unlinks startup CLuaTask construct helper node from the intrusive helper
   * chain and restores self-links.
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCLuaTaskConstructVariantPrimary()
  {
    return UnlinkSerializerNode(CLuaTaskConstructSlot());
  }

  /**
   * Address: 0x004C9B40 (FUN_004C9B40, CLuaTask construct cleanup alias A)
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCLuaTaskConstructVariantAliasA()
  {
    return CleanupCLuaTaskConstructVariantPrimary();
  }

  /**
   * Address: 0x004C9B70 (FUN_004C9B70, CLuaTask construct cleanup alias B)
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCLuaTaskConstructVariantAliasB()
  {
    return CleanupCLuaTaskConstructVariantPrimary();
  }

  /**
    * Alias of FUN_004C9CA0 (non-canonical helper lane).
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCLuaTaskSerializerVariantAliasA()
  {
    return UnlinkSerializerNode(gCLuaTaskSerializer);
  }

  /**
    * Alias of FUN_004C9CD0 (non-canonical helper lane).
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupCLuaTaskSerializerVariantAliasB()
  {
    return UnlinkSerializerNode(gCLuaTaskSerializer);
  }

  void InitializeCLuaTaskConstructHelper()
  {
    if (!gCLuaTaskConstructInitialized) {
      ::new (static_cast<void*>(&CLuaTaskConstructSlot())) moho::CLuaTaskConstruct();
      gCLuaTaskConstructInitialized = true;
    }

    auto& constructHelper = CLuaTaskConstructSlot();
    ResetSerializerNode(constructHelper);
    constructHelper.mSerConstructFunc = &ConstructCLuaTaskInPlace;
    constructHelper.mDeleteFunc = &DeleteConstructedCLuaTask;
  }

  void CleanupCLuaTaskConstructAtExit()
  {
    (void)CleanupCLuaTaskConstructVariantPrimary();
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
   * Address: 0x004CB710 (FUN_004CB710, CLuaTask reflected ref store helper)
   *
   * What it does:
   * Writes one `gpg::RRef` lane for a CLuaTask pointer into caller-provided
   * output storage.
   */
  [[maybe_unused]] gpg::RRef* StoreCLuaTaskRef(gpg::RRef* const outRef, CLuaTask* const task)
  {
    return gpg::RRef_CLuaTask(outRef, task);
  }

  /**
   * Address: 0x004CB740 (FUN_004CB740, CLuaTask member-deserialize thunk)
   *
   * What it does:
   * Thin wrapper that forwards archive + object lanes into
   * `CLuaTask::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCLuaTaskThunk(gpg::ReadArchive* const archive, CLuaTask* const task)
  {
    GPG_ASSERT(task != nullptr);
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004CBD10 (FUN_004CBD10, CLuaTask member-deserialize thunk alias)
   *
   * What it does:
   * Secondary wrapper lane forwarding archive + object pointers into
   * `CLuaTask::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCLuaTaskThunkAlias(gpg::ReadArchive* const archive, CLuaTask* const task)
  {
    DeserializeCLuaTaskThunk(archive, task);
  }

  /**
   * Address: 0x004CB750 (FUN_004CB750, CLuaTask member-serialize thunk)
   *
   * What it does:
   * Thin wrapper that forwards archive + object lanes into
   * `CLuaTask::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCLuaTaskThunk(gpg::WriteArchive* const archive, CLuaTask* const task)
  {
    GPG_ASSERT(task != nullptr);
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x004CC6A0 (FUN_004CC6A0)
   *
   * What it does:
   * Saves one owned `LuaState*` tracked-pointer lane.
   */
  gpg::WriteArchive* WriteOwnedLuaStatePointer(
    gpg::WriteArchive* const archive, LuaPlus::LuaState* const state, const gpg::RRef& ownerRef
  )
  {
    gpg::RRef stateRef{};
    (void)gpg::RRef_LuaState(&stateRef, state);
    gpg::WriteRawPointer(archive, stateRef, gpg::TrackedPointerState::Owned, ownerRef);
    return archive;
  }

  /**
   * Address: 0x004C96A0 (FUN_004C96A0, ForkThread argument push helper)
   *
   * What it does:
   * Pushes one Lua argument object onto a spawned thread-state stack and
   * increments the pending resume-argument counter for that task.
   */
  void PushForkThreadArgumentAndIncrementResumeCount(CLuaTask* const task, const LuaPlus::LuaObject& argumentObject)
  {
    argumentObject.PushStack(task->mLuaState->m_state);
    ++task->mResumeArgCount;
  }

  /**
   * Address: 0x004C9C40 (FUN_004C9C40, CLuaTaskSerializer::Deserialize callback)
   * Chain:   0x004CC2B0 (FUN_004CC2B0)
   */
  void DeserializeCLuaTask(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const task = reinterpret_cast<CLuaTask*>(objectPtr);
    DeserializeCLuaTaskThunk(archive, task);
  }

  /**
   * Address: 0x004C9C50 (FUN_004C9C50, CLuaTaskSerializer::Serialize callback)
   * Chain:   0x004CC320 (FUN_004CC320)
   */
  void SerializeCLuaTask(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const task = reinterpret_cast<CLuaTask*>(objectPtr);
    SerializeCLuaTaskThunk(archive, task);
  }

  void InitializeCLuaTaskSerializer()
  {
    ResetSerializerNode(gCLuaTaskSerializer);
    gCLuaTaskSerializer.mSerLoadFunc = &DeserializeCLuaTask;
    gCLuaTaskSerializer.mSerSaveFunc = &SerializeCLuaTask;
  }

  void CleanupCLuaTaskSerializerAtExit()
  {
    (void)moho::cleanup_CLuaTaskSerializer();
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

  (void)lua_traceback(state->m_state, message, 1);
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
 * Address: 0x004CA910 (FUN_004CA910, cfunc_WaitForL)
 *
 * What it does:
 * Validates one event argument, pushes a wait-task shim above the current
 * Lua task in the owner-thread stack, then yields with one numeric return.
 */
int moho::cfunc_WaitForL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kWaitForHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject eventObject(LuaPlus::LuaStackObject(state, 1));
  (void)SCR_FromLua_CScriptEvent(eventObject, state);

  if (state->m_rootState == state || state->m_luaTask == nullptr) {
    LuaPlus::LuaState::Error(state, kWaitForForkOnlyError);
  }

  CLuaTask* const luaTask = state->m_luaTask;
  CWaitForTask* const waitTask = new (std::nothrow) CWaitForTask(eventObject);
  if (waitTask != nullptr) {
    CTaskThread* const taskThread = luaTask->mOwnerThread;
    waitTask->mAutoDelete = true;
    waitTask->mOwnerThread = taskThread;
    waitTask->mSubtask = taskThread->mTaskTop;
    taskThread->mTaskTop = waitTask;
  }

  lua_pushnumber(state->m_state, 0.0);
  (void)lua_gettop(state->m_state);
  return lua_yield(state->m_state, 1);
}

/**
 * Address: 0x004CA890 (FUN_004CA890, cfunc_WaitFor)
 *
 * What it does:
 * Unwraps Lua binding callback context and forwards to `cfunc_WaitForL`.
 */
int moho::cfunc_WaitFor(lua_State* const luaContext)
{
  return cfunc_WaitForL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004CA8B0 (FUN_004CA8B0, func_WaitFor_LuaFuncDef)
 *
 * What it does:
 * Publishes the global core-lane Lua binder definition for `WaitFor`.
 */
moho::CScrLuaInitForm* moho::func_WaitFor_LuaFuncDef()
{
  static CScrLuaBinder binder(CoreLuaInitSet(), "WaitFor", &moho::cfunc_WaitFor, nullptr, "<global>", kWaitForHelpText);
  return &binder;
}

/**
 * Address: 0x00BC6320 (FUN_00BC6320, register_WaitFor_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_WaitFor_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_WaitFor_LuaFuncDef()
{
  return func_WaitFor_LuaFuncDef();
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
    PushForkThreadArgumentAndIncrementResumeCount(task, argumentObject);
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
 * Address: 0x004C9D20 (FUN_004C9D20, func_ForkThread_LuaFuncDef)
 *
 * What it does:
 * Publishes the global core-lane Lua binder definition for `ForkThread`.
 */
moho::CScrLuaInitForm* moho::func_ForkThread_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "ForkThread",
    &moho::cfunc_ForkThread,
    nullptr,
    "<global>",
    kForkThreadHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6200 (FUN_00BC6200, register_ForkThread_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_ForkThread_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_ForkThread_LuaFuncDef()
{
  return func_ForkThread_LuaFuncDef();
}

/**
 * Address: 0x004CA060 (FUN_004CA060, cfunc_KillThreadL)
 *
 * What it does:
 * Validates one thread argument and destroys a ForkThread-created task thread.
 */
int moho::cfunc_KillThreadL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kKillThreadHelpText, 1, argumentCount);
  }

  if (lua_type(state->m_state, 1) != LUA_TNIL) {
    const LuaPlus::LuaStackObject threadArgument(state, 1);
    lua_State* const rawThreadState = lua_tothread(state->m_state, 1);
    if (!rawThreadState) {
      threadArgument.TypeError(kResumeThreadTypeError);
    }

    LuaPlus::LuaState* const threadState = LuaPlus::LuaState::CastState(rawThreadState);
    (void)lua_gethookmask(state->m_state);
    if (threadState) {
      if (threadState->m_rootState == threadState) {
        LuaPlus::LuaState::Error(state, kKillThreadForkOnlyError);
      }

      CLuaTask* const threadTask = threadState->m_luaTask;
      if (threadTask != nullptr) {
        threadTask->mOwnerThread->Destroy();
      }
    }
  }

  return 0;
}

/**
 * Address: 0x004C9FE0 (FUN_004C9FE0, cfunc_KillThread)
 *
 * What it does:
 * Unwraps Lua binding callback context and forwards to `cfunc_KillThreadL`.
 */
int moho::cfunc_KillThread(lua_State* const luaContext)
{
  return cfunc_KillThreadL(luaContext->stateUserData);
}

/**
 * Address: 0x004CA000 (FUN_004CA000, func_KillThread_LuaFuncDef)
 *
 * What it does:
 * Publishes the global core-lane Lua binder definition for `KillThread`.
 */
moho::CScrLuaInitForm* moho::func_KillThread_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "KillThread",
    &moho::cfunc_KillThread,
    nullptr,
    "<global>",
    kKillThreadHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6210 (FUN_00BC6210, register_KillThread_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_KillThread_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_KillThread_LuaFuncDef()
{
  return func_KillThread_LuaFuncDef();
}

/**
 * Address: 0x004CAAF0 (FUN_004CAAF0, cfunc_SuspendCurrentThreadL)
 *
 * What it does:
 * Validates zero args and suspends the current ForkThread-created task.
 */
int moho::cfunc_SuspendCurrentThreadL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSuspendCurrentThreadHelpText, 0, argumentCount);
  }

  if (state->m_rootState == state || state->m_luaTask == nullptr) {
    LuaPlus::LuaState::Error(state, kWaitForForkOnlyError);
  }

  CTaskThread* const taskThread = state->m_luaTask->mOwnerThread;
  if (!taskThread->mStaged) {
    taskThread->Stage();
  }

  lua_pushnumber(state->m_state, 1.0f);
  (void)lua_gettop(state->m_state);
  return lua_yield(state->m_state, 1);
}

/**
 * Address: 0x004CAA70 (FUN_004CAA70, cfunc_SuspendCurrentThread)
 *
 * What it does:
 * Unwraps binding context and forwards to `cfunc_SuspendCurrentThreadL`.
 */
int moho::cfunc_SuspendCurrentThread(lua_State* const luaContext)
{
  return cfunc_SuspendCurrentThreadL(luaContext->stateUserData);
}

/**
 * Address: 0x004CAA90 (FUN_004CAA90, func_SuspendCurrentThread_LuaFuncDef)
 *
 * What it does:
 * Publishes the global core-lane Lua binder definition for
 * `SuspendCurrentThread`.
 */
moho::CScrLuaInitForm* moho::func_SuspendCurrentThread_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "SuspendCurrentThread",
    &moho::cfunc_SuspendCurrentThread,
    nullptr,
    "<global>",
    kSuspendCurrentThreadHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6330 (FUN_00BC6330, register_SuspendCurrentThread_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to
 * `func_SuspendCurrentThread_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_SuspendCurrentThread_LuaFuncDef()
{
  return func_SuspendCurrentThread_LuaFuncDef();
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
 * Address: 0x004CABB0 (FUN_004CABB0, func_ResumeThread_LuaFuncDef)
 *
 * What it does:
 * Publishes the global core-lane Lua binder definition for `ResumeThread`.
 */
moho::CScrLuaInitForm* moho::func_ResumeThread_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "ResumeThread",
    &moho::cfunc_ResumeThread,
    nullptr,
    "<global>",
    kResumeThreadHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6340 (FUN_00BC6340, register_ResumeThread_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_ResumeThread_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_ResumeThread_LuaFuncDef()
{
  return func_ResumeThread_LuaFuncDef();
}

/**
 * Address: 0x004CADE0 (FUN_004CADE0, cfunc_CurrentThreadL)
 *
 * What it does:
 * Pushes a Lua thread-handle object for the currently running task thread.
 */
int moho::cfunc_CurrentThreadL(LuaPlus::LuaState* const state)
{
  LuaPlus::LuaObject threadObject;
  threadObject.AssignThread(state);
  threadObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x004CAD60 (FUN_004CAD60, cfunc_CurrentThread)
 *
 * What it does:
 * Unwraps binding context and forwards to `cfunc_CurrentThreadL`.
 */
int moho::cfunc_CurrentThread(lua_State* const luaContext)
{
  return cfunc_CurrentThreadL(luaContext->stateUserData);
}

/**
 * Address: 0x004CAD80 (FUN_004CAD80, func_CurrentThread_LuaFuncDef)
 *
 * What it does:
 * Publishes the global core-lane Lua binder definition for `CurrentThread`.
 */
moho::CScrLuaInitForm* moho::func_CurrentThread_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "CurrentThread",
    &moho::cfunc_CurrentThread,
    nullptr,
    "<global>",
    kCurrentThreadHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC6350 (FUN_00BC6350, register_CurrentThread_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_CurrentThread_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_CurrentThread_LuaFuncDef()
{
  return func_CurrentThread_LuaFuncDef();
}

/**
 * Address: 0x004CC2B0 (FUN_004CC2B0, Moho::CLuaTask::MemberDeserialize)
 */
void CLuaTask::MemberDeserialize(gpg::ReadArchive* const archive)
{
  gpg::RRef ownerRef{};
  moho::ReadCTaskBase(archive, this, ownerRef);
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
  gpg::RRef ownerRef{};
  moho::WriteCTaskBase(archive, this, ownerRef);
  (void)WriteOwnedLuaStatePointer(archive, mLuaState, ownerRef);
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
 * Address: 0x00BC6160 (FUN_00BC6160, CLuaTask startup type-info registration)
 *
 * What it does:
 * Pre-registers `CLuaTask` reflected type descriptor and schedules teardown
 * of startup type-info storage at process exit.
 */
void moho::register_CLuaTaskTypeInfo()
{
  static const bool kRegistered = []() {
    (void)PreRegisterCLuaTaskTypeInfo();
    (void)std::atexit(&CleanupCLuaTaskTypeInfoAtExit);
    return true;
  }();
  (void)kRegistered;
}

/**
 * Address: 0x00BC6180 (FUN_00BC6180, CLuaTask startup construct registration)
 *
 * What it does:
 * Initializes construct helper callbacks for CLuaTask reflected serializer
 * construction and schedules intrusive helper cleanup at process exit.
 */
void moho::register_CLuaTaskConstruct()
{
  static const bool kRegistered = []() {
    InitializeCLuaTaskConstructHelper();
    CLuaTaskConstructSlot().RegisterConstructFunction();
    (void)std::atexit(&CleanupCLuaTaskConstructAtExit);
    return true;
  }();
  (void)kRegistered;
}

/**
 * Address: 0x004C9CA0 (FUN_004C9CA0, serializer cleanup alias A)
 * Address: 0x004C9CD0 (FUN_004C9CD0, serializer cleanup alias B)
 *
 * What it does:
 * Unlinks static CLuaTask serializer helper node from the intrusive helper
 * list and restores self-links.
 */
gpg::SerHelperBase* moho::cleanup_CLuaTaskSerializer()
{
  return CleanupCLuaTaskSerializerVariantAliasA();
}

/**
 * Address: 0x00BC61C0 (FUN_00BC61C0, register_CLuaTaskSerializer)
 *
 * What it does:
 * Initializes startup serializer callback lanes for `CLuaTask` and schedules
 * intrusive helper cleanup at process exit.
 */
void moho::register_CLuaTaskSerializer()
{
  InitializeCLuaTaskSerializer();
  (void)std::atexit(&CleanupCLuaTaskSerializerAtExit);
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
