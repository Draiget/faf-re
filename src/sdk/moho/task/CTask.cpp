#include "CTask.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <string>
#include <stdexcept>
#include <typeinfo>

#include "CTaskThread.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/misc/StatItem.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

using namespace moho;

namespace
{
  bool gCTaskTypeInfoPreregistered = false;

  /**
   * Address: 0x00408B00 (FUN_00408B00, sub_408B00)
   * Address: 0x00BEE2B0 (FUN_00BEE2B0, atexit destructor of the CTaskTypeInfo object)
   *
   * What it does:
   * Constructs the process-wide CTaskTypeInfo and pre-registers it as the
   * reflected type for CTask. The binary spells the construction as an RType
   * base ctor plus an explicit vftable store.
   */
  [[nodiscard]] gpg::RType* InitializeCTaskTypeInfoStorage()
  {
    static moho::CTaskTypeInfo sInstance;
    if (!gCTaskTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::CTask), &sInstance);
      gCTaskTypeInfoPreregistered = true;
    }

    return &sInstance;
  }

  gpg::RType* CachedCTaskType()
  {
    if (!CTask::sType) {
      CTask::sType = gpg::LookupRType(typeid(CTask));
    }
    return CTask::sType;
  }

  /**
   * Address: 0x007BB640 (FUN_007BB640)
   *
   * What it does:
   * Runs the shared `CTask` teardown lane for the `CPullTask<CGpgNetInterface>`
   * deleting-destructor vtable slot and frees storage when requested.
   */
  [[nodiscard]] CTask* DestroyPullTaskGpgNetInterfaceDeleting(
    CTask* const task,
    const unsigned char deleteFlag
  )
  {
    task->CTask::~CTask();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(task));
    }
    return task;
  }

  /**
   * Address: 0x007C9040 (FUN_007C9040)
   *
   * What it does:
   * Runs the shared `CTask` teardown lane for the `CPullTask<CDiscoveryService>`
   * deleting-destructor vtable slot and frees storage when requested.
   */
  [[nodiscard]] CTask* DestroyPullTaskDiscoveryServiceDeleting(
    CTask* const task,
    const unsigned char deleteFlag
  )
  {
    task->CTask::~CTask();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(task));
    }
    return task;
  }

  /**
   * Address: 0x007C9060 (FUN_007C9060)
   *
   * What it does:
   * Runs the shared `CTask` teardown lane for the `CPushTask<CDiscoveryService>`
   * deleting-destructor vtable slot and frees storage when requested.
   */
  [[nodiscard]] CTask* DestroyPushTaskDiscoveryServiceDeleting(
    CTask* const task,
    const unsigned char deleteFlag
  )
  {
    task->CTask::~CTask();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(task));
    }
    return task;
  }

  /**
   * Address: 0x0040BDE0 (FUN_0040BDE0, gpg::RRef_CTask)
   *
   * What it does:
   * Packs one `CTask` pointer into `RRef` lanes using reflected dynamic type
   * ownership when available.
   */
  gpg::RRef MakeCTaskRef(CTask* task)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedCTaskType();
    if (!task) {
      return out;
    }

    gpg::RType* dynamicType = CachedCTaskType();
    try {
      dynamicType = gpg::LookupRType(typeid(*task));
    } catch (...) {
      dynamicType = CachedCTaskType();
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(CachedCTaskType(), &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = task;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(task) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  /**
   * Address: 0x0040BF90 (FUN_0040BF90, gpg::RRef::Upcast_CTask)
   *
   * What it does:
   * Upcasts one reflected reference lane to `CTask` and returns the resulting
   * object pointer (or null on mismatch).
   */
  [[nodiscard]] CTask* UpcastCTaskRef(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTaskType());
    return static_cast<CTask*>(upcast.mObj);
  }

  CTask* ReadCTaskPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    CTask* const task = UpcastCTaskRef(source);
    if (task) {
      return task;
    }

    const char* const expected = CachedCTaskType()->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "CTask",
      actual ? actual : "null"
    );
    throw std::runtime_error(msg.c_str());
  }

  struct CTaskReflectionBootstrap
  {
    CTaskReflectionBootstrap()
    {
      moho::register_CTaskTypeInfo();
    }
  };

  [[maybe_unused]] CTaskReflectionBootstrap gCTaskReflectionBootstrap;

} // namespace

namespace moho
{
  /**
   * Address: 0x00BC2FC0 (FUN_00BC2FC0, register_CTaskTypeInfo)
   *
   * What it does:
   * Materializes the startup `CTaskTypeInfo` descriptor.
   */
  void register_CTaskTypeInfo()
  {
    (void)InitializeCTaskTypeInfoStorage();
  }
} // namespace moho

gpg::RType* CTask::sType = nullptr;

gpg::RType* CTask::StaticGetClass()
{
  return CachedCTaskType();
}

/**
 * Address: 0x004CC750 (FUN_004CC750)
 *
 * What it does:
 * Loads one `CTask` base lane through reflected type metadata.
 */
void moho::ReadCTaskBase(gpg::ReadArchive* const archive, void* const object, const gpg::RRef& ownerRef)
{
  gpg::RType* taskType = CTask::sType;
  if (!taskType) {
    taskType = gpg::LookupRType(typeid(CTask));
    CTask::sType = taskType;
  }

  archive->Read(taskType, object, ownerRef);
}

/**
 * Address: 0x004CC780 (FUN_004CC780)
 *
 * What it does:
 * Saves one `CTask` base lane through reflected type metadata.
 */
void moho::WriteCTaskBase(gpg::WriteArchive* const archive, const void* const object, const gpg::RRef& ownerRef)
{
  gpg::RType* taskType = CTask::sType;
  if (!taskType) {
    taskType = gpg::LookupRType(typeid(CTask));
    CTask::sType = taskType;
  }

  archive->Write(taskType, object, ownerRef);
}

/**
 * Address: 0x00408CB0 (FUN_00408CB0, ??1CTask@Moho@@UAE@XZ)
 *
 * What it does:
 * Resets task vtable, resumes owning thread, interrupts subtasks above this task,
 * unlinks this task from the thread stack, and signals pending destroy-guard.
 */
CTask::~CTask()
{
  if (mOwnerThread != nullptr) {
    mOwnerThread->mPendingFrames = 0;
    mOwnerThread->Unstage();

    TaskInterruptSubtasks();

    CTask** slot = &mOwnerThread->mTaskTop;
    while (*slot != this) {
      slot = &(*slot)->mSubtask;
    }

    *slot = mSubtask;
    mSubtask = nullptr;
    mOwnerThread = nullptr;
  }

  if (mDestroyFlag != nullptr) {
    *mDestroyFlag = true;
  }

}

/**
 * Address: 0x00408C40 (FUN_00408C40, ??0CTask@Moho@@QAE@PAVCTaskThread@1@_N@Z)
 *
 * What it does:
 * Initializes task state and pushes this task to the owning thread stack when
 * a thread is provided.
 */
CTask::CTask(CTaskThread* const thread, const bool owning)
{

  if (thread != nullptr) {
    mAutoDelete = owning;
    mOwnerThread = thread;
    mSubtask = thread->mTaskTop;
    thread->mTaskTop = this;
  }
}

/**
 * Address: 0x00408D70 (FUN_00408D70, ?TaskInterruptSubtasks@CTask@Moho@@QAEXXZ)
 *
 * What it does:
 * Pops tasks above `this` from the owning thread stack and deletes only
 * auto-delete tasks.
 */
void CTask::TaskInterruptSubtasks()
{
  CTaskThread* const thread = mOwnerThread;
  if (thread == nullptr) {
    return;
  }

  while (thread->mTaskTop != this) {
    CTask* const task = thread->mTaskTop;
    if (task != nullptr) {
      thread->mTaskTop = task->mSubtask;
      const bool autoDelete = task->mAutoDelete;
      task->mSubtask = nullptr;
      task->mOwnerThread = nullptr;
      if (autoDelete) {
        delete task;
      }
    }
  }
}

/**
 * Address: 0x00408DB0 (FUN_00408DB0, ?TaskResume@CTask@Moho@@QAEX_NH@Z)
 *
 * What it does:
 * Updates thread pending frame count, unstages thread, and optionally interrupts
 * subtask stack above this task.
 */
void CTask::TaskResume(const bool recursiveInterrupt, const int pendingFrames)
{
  CTaskThread* const thread = mOwnerThread;
  if (thread == nullptr) {
    return;
  }

  thread->mPendingFrames = pendingFrames;
  thread->Unstage();
  if (recursiveInterrupt) {
    TaskInterruptSubtasks();
  }
}

/**
 * Address: 0x00409A40 (FUN_00409A40, Moho::CTask::CreateTaskThread)
 *
 * IDA signature:
 * Moho::CTaskThread *__userpurge Moho::CTask::CreateTaskThread@<eax>(
 *         Moho::CTask *dispatch@<esi>, Moho::CTaskStage *stage@<edi>, bool own);
 *
 * What it does:
 * Allocates one `CTaskThread` on `stage` and pushes `dispatch` onto that
 * thread's task stack, keeping the previous top as `dispatch->mSubtask`.
 */
CTaskThread* CTask::CreateTaskThread(CTask* const dispatch, CTaskStage* const stage, const bool own)
{
  if (dispatch == nullptr) {
    return nullptr;
  }

  auto* const taskThread = new CTaskThread(stage);
  dispatch->mAutoDelete = own;
  dispatch->mOwnerThread = taskThread;
  dispatch->mSubtask = taskThread->mTaskTop;
  taskThread->mTaskTop = dispatch;
  return taskThread;
}

/**
 * Address: 0x00408B90 (FUN_00408B90, scalar deleting destructor thunk)
 */
CTaskTypeInfo::~CTaskTypeInfo() = default;

/**
 * Address: 0x00408B80 (FUN_00408B80, ?GetName@CTaskTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CTaskTypeInfo::GetName() const
{
  return "CTask";
}

/**
 * Address: 0x00408B60 (FUN_00408B60, ?Init@CTaskTypeInfo@Moho@@UAEXXZ)
 */
void CTaskTypeInfo::Init()
{
  size_ = sizeof(CTask);
  gpg::RType::Init();
  Finish();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CTaskTypeInfo_e70b77, moho::register_CTaskTypeInfo)

GPG_PREREGISTER_INIT(InitializeCTaskTypeInfoStorage_e70b77, InitializeCTaskTypeInfoStorage)

namespace moho
{
  /**
   * Inlined into `gpg::SerSaveLoadHelper<CTask>::Deserialize` 0x00408E00.
   */
  void CTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    CTask* subtask = mSubtask;
    subtask = ReadCTaskPointer(archive, gpg::RRef{});
    (void)subtask;
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<CTask>::Serialize` 0x00408E40.
   */
  void CTask::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef subtaskRef = MakeCTaskRef(mSubtask);
    gpg::WriteRawPointer(archive, subtaskRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CTask>`, vtable 0x00E00358.
   *
   * Address: 0x00BC2FE0 (FUN_00BC2FE0 -- constructs the global and registers its destructor.)
   * Address: 0x00BEE310 (FUN_00BEE310 -- the global's destructor.)
   * Address: 0x00408E80 (FUN_00408E80 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0040A290 (FUN_0040A290 -- `Init`.)
   * Address: 0x00408E00 (FUN_00408E00 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00408E40 (FUN_00408E40 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct CTaskSerializer : gpg::SerSaveLoadHelper<CTask>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A67A4 -- process-global `CTaskSerializer` singleton.
  moho::CTaskSerializer gCTaskSerializer;
} // namespace
