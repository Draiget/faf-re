#include "CTaskThread.h"

#include <exception>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "CTask.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

namespace gpg
{
  enum class TrackedPointerState : int
  {
    Unowned = 1,
    Owned = 2,
  };

  struct TrackedPointerInfo
  {
    void* object;
    gpg::RType* type;
  };

  TrackedPointerInfo ReadRawPointer(ReadArchive* archive, const gpg::RRef& ownerRef);
  void WriteRawPointer(
    WriteArchive* archive, const gpg::RRef& objectRef, TrackedPointerState state, const gpg::RRef& ownerRef
  );
  gpg::RRef REF_UpcastPtr(const gpg::RRef& source, const gpg::RType* targetType);
} // namespace gpg

namespace
{
  gpg::RType* CachedCTaskThreadType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTaskThread));
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

  gpg::RType* CachedCTaskStageType();

  template <class T>
  gpg::RRef MakeDerivedRef(T* object, gpg::RType* baseType)
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
    const bool derived = dynamicType->IsDerivedFrom(baseType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  template <class T>
  T* ReadTypedPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef, gpg::RType* expectedType)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (upcast.mObj) {
      return static_cast<T*>(upcast.mObj);
    }

    const char* const expected = expectedType ? expectedType->GetName() : "<unknown>";
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "<unknown>",
      actual ? actual : "null"
    );
    throw std::runtime_error(msg.c_str());
  }

  /**
   * Address: 0x0040B530 (FUN_0040B530, func_ReadArchive_CTaskPtr)
   *
   * What it does:
   * Loads an owned CTask pointer record used by task-stack payloads.
   */
  CTask* DeserializeOwnedTaskPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    return ReadTypedPointer<CTask>(archive, ownerRef, CachedCTaskType());
  }

  /**
   * Address: 0x0040B640 (FUN_0040B640, func_ReadArchive_CTaskWeakPtr)
   *
   * What it does:
   * Loads an unowned CTask pointer record used by task-stack payloads.
   */
  CTask* DeserializeWeakTaskPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    return ReadTypedPointer<CTask>(archive, ownerRef, CachedCTaskType());
  }

  /**
   * Address: 0x004096C0 (FUN_004096C0, func_WriteArchive_CTaskThreadTasks)
   *
   * What it does:
   * Writes task stack chain: [owns-flag,bool] + [task pointer] pairs, then
   * appends terminating null pointer record.
   */
  void SerializeTaskStack(gpg::WriteArchive* archive, CTaskThread* thread, const gpg::RRef& ownerRef)
  {
    for (CTask* task = thread->mTaskTop; task != nullptr; task = task->mSubtask) {
      archive->WriteBool(task->mAutoDelete);
      const gpg::RRef taskRef = MakeDerivedRef(task, CachedCTaskType());
      const gpg::TrackedPointerState state =
        task->mAutoDelete ? gpg::TrackedPointerState::Owned : gpg::TrackedPointerState::Unowned;
      gpg::WriteRawPointer(archive, taskRef, state, ownerRef);
    }

    archive->WriteBool(false);
    const gpg::RRef nullTaskRef = MakeDerivedRef<CTask>(nullptr, CachedCTaskType());
    gpg::WriteRawPointer(archive, nullTaskRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  /**
   * Address: 0x00409750 (FUN_00409750, func_ReadArchive_CTaskThreadTasks)
   *
   * What it does:
   * Rebuilds task stack chain by reading [owns-flag,bool] + [task pointer]
   * records until null pointer terminator.
   */
  void DeserializeTaskStack(gpg::ReadArchive* archive, CTaskThread* thread, const gpg::RRef& ownerRef)
  {
    CTask** slot = &thread->mTaskTop;
    while (true) {
      bool ownsTask = false;
      archive->ReadBool(&ownsTask);

      CTask* const task =
        ownsTask ? DeserializeOwnedTaskPointer(archive, ownerRef) : DeserializeWeakTaskPointer(archive, ownerRef);
      *slot = task;
      if (!task) {
        break;
      }

      task->mAutoDelete = ownsTask;
      task->mOwnerThread = thread;
      slot = &task->mSubtask;
    }
  }

  /**
   * Address: 0x0040D650 (FUN_0040D650, func_ReadArchive_CTaskStagePtr)
   */
  CTaskStage* DeserializeTaskStagePointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    return ReadTypedPointer<CTaskStage>(archive, ownerRef, CachedCTaskStageType());
  }

  /**
   * Address: 0x0040C300 (FUN_0040C300, func_RRefCTaskStage)
   */
  gpg::RRef SerializeTaskStagePointer(CTaskStage* stage)
  {
    return MakeDerivedRef(stage, CachedCTaskStageType());
  }

  /**
   * Address: 0x0040B800 (FUN_0040B800, func_ReadArchive_CTaskThreadPtr)
   */
  CTaskThread* DeserializeTaskThreadPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    return ReadTypedPointer<CTaskThread>(archive, ownerRef, CachedCTaskThreadType());
  }

  /**
   * Address: 0x0040BC20 (FUN_0040BC20, func_RRefCTaskThread)
   */
  gpg::RRef SerializeTaskThreadPointer(CTaskThread* thread)
  {
    return MakeDerivedRef(thread, CachedCTaskThreadType());
  }

  gpg::RType* CachedCTaskStageType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTaskStage));
    }
    return cached;
  }

  void InitializeTaskStage(CTaskStage* const stage)
  {
    if (!stage) {
      return;
    }

    stage->mThreads.mPrev = &stage->mThreads;
    stage->mThreads.mNext = &stage->mThreads;
    stage->mStagedThreads.mPrev = &stage->mStagedThreads;
    stage->mStagedThreads.mNext = &stage->mStagedThreads;
    stage->mActive = true;
  }

  gpg::RRef MakeTaskStageRef(CTaskStage* const stage)
  {
    gpg::RRef out{};
    out.mObj = stage;
    out.mType = CachedCTaskStageType();
    return out;
  }

  /**
   * Address: 0x00409950 (FUN_00409950, sub_409950)
   *
   * What it does:
   * Executes stage teardown, then unlinks both stage sentinel heads from any
   * external list linkage and resets them to singleton state.
   */
  void DestroyTaskStageInPlace(CTaskStage* const stage)
  {
    if (!stage) {
      return;
    }

    stage->Teardown();
    stage->mStagedThreads.ListUnlink();
    stage->mThreads.ListUnlink();
  }

  /**
   * Address: 0x0040B140 (FUN_0040B140, sub_40B140)
   */
  gpg::RRef NewTaskStageRef()
  {
    CTaskStage* const stage = static_cast<CTaskStage*>(::operator new(sizeof(CTaskStage), std::nothrow));
    InitializeTaskStage(stage);
    return MakeTaskStageRef(stage);
  }

  /**
   * Address: 0x0040B190 (FUN_0040B190, sub_40B190)
   */
  void DeleteTaskStage(void* const object)
  {
    auto* const stage = static_cast<CTaskStage*>(object);
    if (!stage) {
      return;
    }

    DestroyTaskStageInPlace(stage);
    ::operator delete(stage);
  }

  /**
   * Address: 0x0040B1B0 (FUN_0040B1B0, sub_40B1B0)
   */
  gpg::RRef ConstructTaskStageRef(void* const object)
  {
    auto* const stage = static_cast<CTaskStage*>(object);
    InitializeTaskStage(stage);
    return MakeTaskStageRef(stage);
  }

  /**
   * Address: 0x0040B1F0 (FUN_0040B1F0, sub_40B1F0)
   */
  void DestroyTaskStageOnly(void* const object)
  {
    DestroyTaskStageInPlace(static_cast<CTaskStage*>(object));
  }

  void PopTaskStack(CTaskThread* const thread)
  {
    while (thread->mTaskTop != nullptr) {
      CTask* const task = thread->mTaskTop;
      thread->mTaskTop = task->mSubtask;
      const bool autoDelete = task->mAutoDelete;
      task->mSubtask = nullptr;
      task->mOwnerThread = nullptr;
      if (autoDelete) {
        delete task;
      }
    }
  }

  void ClearTaskEventLinks(CTaskThread* const thread)
  {
    while (thread->mEventLinkHead != nullptr) {
      WeakPtr<CTaskThread>* const link = thread->mEventLinkHead;
      thread->mEventLinkHead = link->nextInOwner;
      link->ownerLinkSlot = nullptr;
      link->nextInOwner = nullptr;
    }
  }

  /**
   * Address: 0x004091F0 (FUN_004091F0, func_Dispatch)
   *
   * What it does:
   * Per-thread task scheduler step. Executes top task, handles completion/
   * staging return codes, exception fallback, and pending-frame throttling.
   */
  int RunThreadUserFrameStep(CTaskThread* const thread)
  {
    if (!thread) {
      return -1;
    }

    if (--thread->mPendingFrames > 0) {
      return 0;
    }

    while (true) {
      CTask* const task = thread->mTaskTop;
      if (!task) {
        return -1;
      }

      bool wasDestroyed = false;
      task->mDestroyFlag = &wasDestroyed;

      int executeResult = 0;
      try {
        executeResult = task->Execute();
      } catch (const std::exception& ex) {
        gpg::Warnf("Unhandled error -- aborting thread: %s", ex.what());
        executeResult = -3;
      } catch (...) {
        gpg::Warnf("Unhandled error -- aborting thread: %s", "<unknown>");
        executeResult = -3;
      }

      if (!wasDestroyed) {
        task->mDestroyFlag = nullptr;
      }

      switch (executeResult) {
      case -4:
        return -2;

      case -3:
        thread->Destroy();
        return -1;

      case -2:
        thread->Stage();
        return 0;

      case -1: {
        CTask** slot = &thread->mTaskTop;
        while (*slot != task) {
          slot = &(*slot)->mSubtask;
        }

        *slot = task->mSubtask;
        const bool autoDelete = task->mAutoDelete;
        task->mSubtask = nullptr;
        task->mOwnerThread = nullptr;
        if (autoDelete) {
          delete task;
        }
        continue;
      }

      case 0:
        thread->mPendingFrames = 0;
        if (thread->mStaged) {
          return 0;
        }
        continue;

      case 1:
        thread->mPendingFrames = 1;
        return 0;

      default:
        thread->mPendingFrames = executeResult - 1;
        return 0;
      }
    }
  }

  /**
   * Address: 0x004095F0 (FUN_004095F0, Moho::CTaskThreadSerializer::Deserialize)
   */
  void DeserializeCTaskThread(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const thread = reinterpret_cast<CTaskThread*>(objectPtr);
    GPG_ASSERT(thread != nullptr);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    thread->mStage = DeserializeTaskStagePointer(archive, owner);
    archive->ReadInt(&thread->mPendingFrames);
    archive->ReadBool(&thread->mStaged);
    DeserializeTaskStack(archive, thread, owner);
  }

  /**
   * Address: 0x00409610 (FUN_00409610, Moho::CTaskThreadSerializer::Serialize)
   */
  void SerializeCTaskThread(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const thread = reinterpret_cast<CTaskThread*>(objectPtr);
    GPG_ASSERT(thread != nullptr);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    const gpg::RRef stageRef = SerializeTaskStagePointer(thread->mStage);
    gpg::WriteRawPointer(archive, stageRef, gpg::TrackedPointerState::Unowned, owner);
    archive->WriteInt(thread->mPendingFrames);
    archive->WriteBool(thread->mStaged);
    SerializeTaskStack(archive, thread, owner);
  }

  /**
   * Address: 0x00409BF0 (FUN_00409BF0, Moho::CTaskStageSerializer::Deserialize)
   */
  void DeserializeCTaskStage(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const stage = reinterpret_cast<CTaskStage*>(objectPtr);
    GPG_ASSERT(stage != nullptr);

    archive->ReadBool(&stage->mActive);
    const gpg::RRef nullOwner{};

    while (true) {
      CTaskThread* const thread = DeserializeTaskThreadPointer(archive, nullOwner);
      if (!thread) {
        break;
      }
      thread->ListLinkBefore(&stage->mThreads);
    }

    while (true) {
      CTaskThread* const thread = DeserializeTaskThreadPointer(archive, nullOwner);
      if (!thread) {
        break;
      }
      thread->ListLinkBefore(&stage->mStagedThreads);
    }
  }

  /**
   * Address: 0x00409C20 (FUN_00409C20, Moho::CTaskStageSerializer::Serialize)
   */
  void SerializeCTaskStage(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const stage = reinterpret_cast<CTaskStage*>(objectPtr);
    GPG_ASSERT(stage != nullptr);

    archive->WriteBool(stage->mActive);
    const gpg::RRef nullOwner{};
    auto* const mainListEnd = reinterpret_cast<CTaskThread*>(&stage->mThreads);
    auto* const stagedListEnd = reinterpret_cast<CTaskThread*>(&stage->mStagedThreads);

    for (auto* node = static_cast<CTaskThread*>(stage->mThreads.mNext); node != mainListEnd;
         node = static_cast<CTaskThread*>(node->mNext)) {
      const gpg::RRef threadRef = SerializeTaskThreadPointer(node);
      gpg::WriteRawPointer(archive, threadRef, gpg::TrackedPointerState::Owned, nullOwner);
    }
    const gpg::RRef nullThread = SerializeTaskThreadPointer(nullptr);
    gpg::WriteRawPointer(archive, nullThread, gpg::TrackedPointerState::Owned, nullOwner);

    for (auto* node = static_cast<CTaskThread*>(stage->mStagedThreads.mNext); node != stagedListEnd;
         node = static_cast<CTaskThread*>(node->mNext)) {
      const gpg::RRef threadRef = SerializeTaskThreadPointer(node);
      gpg::WriteRawPointer(archive, threadRef, gpg::TrackedPointerState::Owned, nullOwner);
    }
    gpg::WriteRawPointer(archive, nullThread, gpg::TrackedPointerState::Owned, nullOwner);
  }
} // namespace

/**
 * Address: 0x00409050 (FUN_00409050, ??0CTaskThread@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes thread state and links it into stage main thread list.
 */
CTaskThread::CTaskThread(CTaskStage* const stage)
  : mEventLinkHead(nullptr)
  , mStage(stage)
  , mTaskTop(nullptr)
  , mPendingFrames(0)
  , mStaged(false)
{
  ListLinkBefore(&stage->mThreads);
}

/**
 * Address: 0x004090E0 (FUN_004090E0, ??1CTaskThread@Moho@@QAE@@Z)
 *
 * What it does:
 * Clears owned task stack, detaches pending event links, and unlinks thread
 * from whichever intrusive list currently owns it.
 */
CTaskThread::~CTaskThread()
{
  PopTaskStack(this);
  ClearTaskEventLinks(this);
  ListUnlink();
}

/**
 * Address: 0x00409190 (FUN_00409190, ?Destroy@CTaskThread@Moho@@QAEPAVCTaskStage@2@XZ)
 *
 * What it does:
 * Clears task stack and returns staged threads back to the main stage list.
 */
CTaskStage* CTaskThread::Destroy() noexcept
{
  PopTaskStack(this);
  mPendingFrames = 0;

  if (mStaged) {
    Unstage();
  }

  return mStage;
}

/**
 * Address: 0x004093E0 (FUN_004093E0, ?Stage@CTaskThread@Moho@@QAEXXZ)
 *
 * What it does:
 * Moves thread node from main list into staged list.
 */
void CTaskThread::Stage()
{
  if (mStaged) {
    return;
  }

  ListLinkBefore(&mStage->mStagedThreads);
  mStaged = true;
}

/**
 * Address: 0x004091C0 (FUN_004091C0, ?Unstage@CTaskThread@Moho@@QAEXXZ)
 *
 * What it does:
 * Moves thread node from staged list back to main stage list.
 */
void CTaskThread::Unstage()
{
  if (!mStaged) {
    return;
  }

  ListLinkBefore(&mStage->mThreads);
  mStaged = false;
}

/**
 * Address: 0x004099C0 (FUN_004099C0, sub_4099C0)
 *
 * What it does:
 * Marks stage inactive and destroys all thread nodes from both lists.
 */
void CTaskStage::Teardown()
{
  mActive = false;

  while (!mThreads.ListIsSingleton()) {
    auto* const thread = static_cast<CTaskThread*>(mThreads.mNext);
    delete thread;
  }

  while (!mStagedThreads.ListIsSingleton()) {
    auto* const thread = static_cast<CTaskThread*>(mStagedThreads.mNext);
    delete thread;
  }
}

/**
 * Address: 0x00409AC0 (FUN_00409AC0, sub_409AC0)
 *
 * What it does:
 * Executes frame-step for all main-list threads, applies staged/destroy
 * side effects, then splices processed list back before current main head.
 */
void CTaskStage::UserFrame()
{
  TDatList<CTaskThread, void> processed;
  auto* const stageSentinel = static_cast<TDatListItem<CTaskThread, void>*>(&mThreads);
  auto* const processedSentinel = static_cast<TDatListItem<CTaskThread, void>*>(&processed);

  auto* stageNode = mThreads.mNext;
  while (stageNode != stageSentinel) {
    auto* const thread = static_cast<CTaskThread*>(stageNode);
    thread->ListUnlink();
    thread->ListLinkBefore(&processed);

    const int stepResult = RunThreadUserFrameStep(thread);
    if (stepResult == -2) {
      thread->ListUnlink();
      thread->ListLinkBefore(&mThreads);
    } else if (stepResult == -1) {
      delete thread;
    }

    stageNode = mThreads.mNext;
  }

  auto* const localHead = processed.mNext;
  if (localHead != processedSentinel) {
    auto* const localTail = processed.mPrev;
    auto* const stageFirst = mThreads.mNext;
    auto* const stageBeforeFirst = stageFirst->mPrev;

    stageBeforeFirst->mNext = localHead;
    stageFirst->mPrev = localTail;
    localTail->mNext = stageFirst;
    localHead->mPrev = stageBeforeFirst;

    processed.mNext = processedSentinel;
    processed.mPrev = processedSentinel;
  }
}

/**
 * Address: 0x0040A630 (FUN_0040A630, sub_40A630)
 */
void CTaskThreadConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCTaskThreadType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mSerConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

/**
 * Address: 0x0040A6B0 (FUN_0040A6B0, sub_40A6B0)
 */
void CTaskThreadSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCTaskThreadType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = &DeserializeCTaskThread;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = &SerializeCTaskThread;
}

/**
 * Address: 0x00408FA0 (FUN_00408FA0, scalar deleting destructor thunk)
 */
CTaskThreadTypeInfo::~CTaskThreadTypeInfo() = default;

/**
 * Address: 0x00408F90 (FUN_00408F90, ?GetName@CTaskThreadTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CTaskThreadTypeInfo::GetName() const
{
  return "CTaskThread";
}

/**
 * Address: 0x00408F70 (FUN_00408F70, ?Init@CTaskThreadTypeInfo@Moho@@UAEXXZ)
 */
void CTaskThreadTypeInfo::Init()
{
  size_ = sizeof(CTaskThread);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x0040A7F0 (FUN_0040A7F0, sub_40A7F0)
 */
void CTaskStageSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCTaskStageType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = &DeserializeCTaskStage;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = &SerializeCTaskStage;
}

/**
 * Address: 0x00409860 (FUN_00409860, scalar deleting destructor thunk)
 */
CTaskStageTypeInfo::~CTaskStageTypeInfo() = default;

/**
 * Address: 0x00409850 (FUN_00409850, ?GetName@CTaskStageTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CTaskStageTypeInfo::GetName() const
{
  return "CTaskStage";
}

/**
 * Address: 0x00409810 (FUN_00409810, ?Init@CTaskStageTypeInfo@Moho@@UAEXXZ)
 */
void CTaskStageTypeInfo::Init()
{
  size_ = sizeof(CTaskStage);
  newRefFunc_ = &NewTaskStageRef;
  deleteFunc_ = &DeleteTaskStage;
  ctorRefFunc_ = &ConstructTaskStageRef;
  dtrFunc_ = &DestroyTaskStageOnly;
  gpg::RType::Init();
  Finish();
}
