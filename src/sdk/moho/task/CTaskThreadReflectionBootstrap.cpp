#include "moho/task/CTaskThread.h"

#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  [[nodiscard]] gpg::RType* CachedCTaskThreadType()
  {
    gpg::RType* type = moho::CTaskThread::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CTaskThread));
      moho::CTaskThread::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeTaskThreadRef(moho::CTaskThread* const thread)
  {
    gpg::RRef out{};
    out.mObj = thread;
    out.mType = CachedCTaskThreadType();
    return out;
  }

  [[nodiscard]] moho::CTaskThreadConstruct* InitializeCTaskThreadConstructHelper(
    moho::CTaskThreadConstruct* const constructHelper
  )
  {
    constructHelper->mNext = nullptr;
    constructHelper->mPrev = nullptr;
    constructHelper->mSerConstructFunc =
      reinterpret_cast<gpg::RType::construct_func_t>(&moho::CTaskThreadConstruct::Construct);
    constructHelper->mDeleteFunc = &moho::CTaskThreadConstruct::Deconstruct;
    return constructHelper;
  }

  /**
   * Address: 0x00409420 (FUN_00409420, sub_409420)
   *
   * What it does:
   * Unlinks thread from current intrusive list, relinks it into owning stage
   * main-thread list, and clears staged flag.
   */
  [[maybe_unused]] moho::CTaskThread* RelinkThreadToPrimaryStageList(moho::CTaskThread* const thread)
  {
    thread->ListUnlink();
    thread->ListLinkBefore(&thread->mStage->mThreads);
    thread->mStaged = false;
    return thread;
  }

  /**
   * Address: 0x00409580 (FUN_00409580, sub_409580)
   *
   * What it does:
   * Initializes raw `CTaskThread` storage for serializer-construct path
   * without binding to a stage list.
   */
  [[nodiscard]] moho::CTaskThread* InitializeTaskThreadStorage(moho::CTaskThread* const thread)
  {
    thread->mPrev = thread;
    thread->mNext = thread;
    thread->mEventLinkHead = nullptr;
    ++moho::InstanceCounter<moho::CTaskThread>::s_count;
    thread->mStage = nullptr;
    thread->mTaskTop = nullptr;
    thread->mPendingFrames = 0;
    thread->mStaged = false;
    thread->mAlignmentPad19[0] = 0;
    thread->mAlignmentPad19[1] = 0;
    thread->mAlignmentPad19[2] = 0;
    return thread;
  }

  /**
   * Address: 0x004094F0 (FUN_004094F0, sub_4094F0)
   *
   * What it does:
   * Allocates a task-thread instance, initializes serializer construct state,
   * and stores an unowned reflected object handle in construct result.
   */
  void ConstructTaskThreadForSerializer(gpg::SerConstructResult* const result)
  {
    void* const storage = ::operator new(sizeof(moho::CTaskThread), std::nothrow);
    moho::CTaskThread* thread = nullptr;
    if (storage) {
      thread = InitializeTaskThreadStorage(static_cast<moho::CTaskThread*>(storage));
    }

    const gpg::RRef threadRef = MakeTaskThreadRef(thread);
    result->SetUnowned(threadRef, 0u);
  }

  /**
   * Address: 0x00409630 (FUN_00409630, sub_409630)
   *
   * What it does:
   * Initializes global CTaskThread serializer helper callback slots.
   */
  [[nodiscard]] moho::CTaskThreadSerializer* InitializeCTaskThreadSerializerHelper(
    moho::CTaskThreadSerializer* const serializer
  )
  {
    serializer->mNext = nullptr;
    serializer->mPrev = nullptr;
    serializer->mSerLoadFunc = &moho::CTaskThreadSerializer::Deserialize;
    serializer->mSerSaveFunc = &moho::CTaskThreadSerializer::Serialize;
    return serializer;
  }

  moho::CTaskThreadConstruct gCTaskThreadConstructHelper;
  moho::CTaskThreadSerializer gCTaskThreadSerializerHelper;

  /**
   * Address: 0x00BC3080 (FUN_00BC3080, register_CTaskThreadSerializer)
   *
   * What it does:
   * Initializes the global CTaskThread serializer helper and binds task-thread
   * load/save callbacks into reflected type metadata.
   */
  void RegisterCTaskThreadSerializerBootstrap()
  {
    InitializeCTaskThreadSerializerHelper(&gCTaskThreadSerializerHelper)->RegisterSerializeFunctions();
  }

  struct CTaskThreadSerializerRegistration
  {
    CTaskThreadSerializerRegistration()
    {
      InitializeCTaskThreadConstructHelper(&gCTaskThreadConstructHelper)->RegisterConstructFunction();
      RegisterCTaskThreadSerializerBootstrap();
    }
  };

  CTaskThreadSerializerRegistration gCTaskThreadSerializerRegistration;
} // namespace

/**
 * Address: 0x004094E0 (FUN_004094E0, Moho::CTaskThreadConstruct::Construct)
 *
 * What it does:
 * Wraps serializer construct callback and forwards to CTaskThread allocator path.
 */
void moho::CTaskThreadConstruct::Construct(
  void* /*archive*/, void* /*objectStorage*/, int /*version*/, gpg::SerConstructResult* const result
)
{
  ConstructTaskThreadForSerializer(result);
}

/**
 * Address: 0x0040B420 (FUN_0040B420, Moho::CTaskThreadConstruct::Deconstruct)
 *
 * What it does:
 * Destroys constructed CTaskThread object and frees owned storage.
 */
void moho::CTaskThreadConstruct::Deconstruct(void* const object)
{
  auto* const thread = static_cast<moho::CTaskThread*>(object);
  if (!thread) {
    return;
  }

  thread->~CTaskThread();
  ::operator delete(thread);
}
