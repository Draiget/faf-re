#include "CTask.h"

#include <stdexcept>
#include <typeinfo>

#include "CTaskThread.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

using namespace moho;

namespace
{
  gpg::RType* CachedCTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTask));
    }
    return cached;
  }

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

  CTask* ReadCTaskPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCTaskType());
    if (upcast.mObj) {
      return static_cast<CTask*>(upcast.mObj);
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

  /**
   * Address: 0x00408E00 (FUN_00408E00, Moho::CTaskSerializer::Deserialize)
   *
   * What it does:
   * Reads one weak task pointer from archive payload and intentionally discards
   * it (binary callback keeps stack-link restoration in thread-level helpers).
   */
  void DeserializeCTask(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const task = reinterpret_cast<CTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    CTask* subtask = task->mSubtask;
    subtask = ReadCTaskPointer(archive, owner);
    (void)subtask;
  }

  /**
   * Address: 0x00408E40 (FUN_00408E40, Moho::CTaskSerializer::Serialize)
   *
   * What it does:
   * Saves the task-chain link (`mSubtask`) as unowned tracked pointer.
   */
  void SerializeCTask(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const task = reinterpret_cast<CTask*>(objectPtr);
    GPG_ASSERT(task != nullptr);
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    const gpg::RRef subtaskRef = MakeCTaskRef(task->mSubtask);
    gpg::WriteRawPointer(archive, subtaskRef, gpg::TrackedPointerState::Unowned, owner);
  }
} // namespace

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
 * Address: 0x0040A290 (FUN_0040A290, sub_40A290)
 */
void CTaskSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCTaskType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = &DeserializeCTask;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = &SerializeCTask;
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
