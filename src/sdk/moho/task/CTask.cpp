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

using namespace moho;

namespace
{
  alignas(moho::CTaskTypeInfo) std::byte gCTaskTypeInfoStorage[sizeof(moho::CTaskTypeInfo)]{};
  bool gCTaskTypeInfoConstructed = false;

  [[nodiscard]] moho::CTaskTypeInfo& CTaskTypeInfoSlot()
  {
    return *reinterpret_cast<moho::CTaskTypeInfo*>(gCTaskTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* InitializeCTaskTypeInfoStorage()
  {
    if (!gCTaskTypeInfoConstructed) {
      ::new (static_cast<void*>(&CTaskTypeInfoSlot())) moho::CTaskTypeInfo();
      gpg::PreRegisterRType(typeid(moho::CTask), &CTaskTypeInfoSlot());
      gCTaskTypeInfoConstructed = true;
    }

    return &CTaskTypeInfoSlot();
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

  gpg::RType* CachedCTaskType()
  {
    if (!CTask::sType) {
      CTask::sType = gpg::LookupRType(typeid(CTask));
    }
    return CTask::sType;
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

  CTaskSerializer gCTaskSerializer{};

  /**
   * Address: 0x00BC2FE0 (FUN_00BC2FE0, register_CTaskSerializer)
   *
   * What it does:
   * Initializes the global CTask serializer helper and binds task load/save
   * callbacks into reflected type metadata.
   */
  void RegisterCTaskSerializerBootstrap()
  {
    gCTaskSerializer.mNext = nullptr;
    gCTaskSerializer.mPrev = nullptr;
    gCTaskSerializer.mSerLoadFunc = &DeserializeCTask;
    gCTaskSerializer.mSerSaveFunc = &SerializeCTask;
    gCTaskSerializer.RegisterSerializeFunctions();
  }

  struct CTaskReflectionBootstrap
  {
    CTaskReflectionBootstrap()
    {
      moho::register_CTaskTypeInfo();
      RegisterCTaskSerializerBootstrap();
    }
  };

  [[maybe_unused]] CTaskReflectionBootstrap gCTaskReflectionBootstrap;

} // namespace

namespace moho
{
  /**
   * Address: 0x00BEE2B0 (FUN_00BEE2B0, sub_BEE2B0)
   *
   * What it does:
   * Executes process-exit teardown for startup `CTaskTypeInfo` storage.
   */
  void cleanup_CTaskTypeInfo()
  {
    if (!gCTaskTypeInfoConstructed) {
      return;
    }

    CTaskTypeInfoSlot().~CTaskTypeInfo();
    gCTaskTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC2FC0 (FUN_00BC2FC0, register_CTaskTypeInfo)
   *
   * What it does:
   * Materializes startup `CTaskTypeInfo` storage and registers process-exit
   * teardown.
   */
  void register_CTaskTypeInfo()
  {
    (void)InitializeCTaskTypeInfoStorage();
    (void)std::atexit(&cleanup_CTaskTypeInfo);
  }
} // namespace moho

gpg::RType* CTask::sType = nullptr;

gpg::RType* CTask::StaticGetClass()
{
  return CachedCTaskType();
}

/**
 * Address: 0x0040AB50 (FUN_0040AB50, Moho::InstanceCounter<Moho::CTask>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for task-instance
 * counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CTask>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  moho::EngineStats* const engineStats = moho::GetEngineStats();
  if (!engineStats) {
    return nullptr;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CTask).name());
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
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

  AddStatCounter(InstanceCounter<CTask>::GetStatItem(), -1);
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
  AddStatCounter(InstanceCounter<CTask>::GetStatItem(), 1);

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
