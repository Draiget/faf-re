#include "moho/task/CTaskThread.h"

#include <cstddef>
#include <cstdlib>
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
  alignas(moho::CTaskThreadTypeInfo)
    std::byte gCTaskThreadTypeInfoStorage[sizeof(moho::CTaskThreadTypeInfo)]{};
  alignas(moho::CTaskStageTypeInfo)
    std::byte gCTaskStageTypeInfoStorage[sizeof(moho::CTaskStageTypeInfo)]{};
  bool gCTaskThreadTypeInfoConstructed = false;
  bool gCTaskStageTypeInfoConstructed = false;

  [[nodiscard]] moho::CTaskThreadTypeInfo& CTaskThreadTypeInfoSlot()
  {
    return *reinterpret_cast<moho::CTaskThreadTypeInfo*>(gCTaskThreadTypeInfoStorage);
  }

  [[nodiscard]] moho::CTaskStageTypeInfo& CTaskStageTypeInfoSlot()
  {
    return *reinterpret_cast<moho::CTaskStageTypeInfo*>(gCTaskStageTypeInfoStorage);
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper* const helper)
  {
    return reinterpret_cast<gpg::SerHelperBase*>(helper);
  }

  template <typename THelper>
  void ResetHelperIntrusiveLinks(THelper* const helper)
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper->mNext = self;
    helper->mPrev = self;
  }

  template <typename THelper>
  void UnlinkHelperIntrusiveLinks(THelper* const helper)
  {
    if (helper->mNext != nullptr && helper->mPrev != nullptr) {
      helper->mNext->mPrev = helper->mPrev;
      helper->mPrev->mNext = helper->mNext;
    }
    ResetHelperIntrusiveLinks(helper);
  }

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
    ResetHelperIntrusiveLinks(constructHelper);
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
    ResetHelperIntrusiveLinks(serializer);
    serializer->mSerLoadFunc = &moho::CTaskThreadSerializer::Deserialize;
    serializer->mSerSaveFunc = &moho::CTaskThreadSerializer::Serialize;
    return serializer;
  }

  [[nodiscard]] moho::CTaskStageSerializer* InitializeCTaskStageSerializerHelper(
    moho::CTaskStageSerializer* const serializer
  )
  {
    ResetHelperIntrusiveLinks(serializer);
    serializer->mSerLoadFunc = nullptr;
    serializer->mSerSaveFunc = nullptr;
    return serializer;
  }

  [[nodiscard]] gpg::RType* InitializeCTaskThreadTypeInfoStorage()
  {
    if (!gCTaskThreadTypeInfoConstructed) {
      ::new (static_cast<void*>(&CTaskThreadTypeInfoSlot())) moho::CTaskThreadTypeInfo();
      gpg::PreRegisterRType(typeid(moho::CTaskThread), &CTaskThreadTypeInfoSlot());
      gCTaskThreadTypeInfoConstructed = true;
    }

    return &CTaskThreadTypeInfoSlot();
  }

  [[nodiscard]] gpg::RType* InitializeCTaskStageTypeInfoStorage()
  {
    if (!gCTaskStageTypeInfoConstructed) {
      ::new (static_cast<void*>(&CTaskStageTypeInfoSlot())) moho::CTaskStageTypeInfo();
      gCTaskStageTypeInfoConstructed = true;
    }

    return &CTaskStageTypeInfoSlot();
  }

  moho::CTaskThreadConstruct gCTaskThreadConstructHelper;
  moho::CTaskThreadSerializer gCTaskThreadSerializerHelper;
  moho::CTaskStageSerializer gCTaskStageSerializerHelper;

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
      moho::register_CTaskThreadTypeInfo();
      moho::register_CTaskThreadConstruct();
      moho::register_CTaskStageTypeInfo();
      moho::register_CTaskStageSerializer();

      gCTaskThreadConstructHelper.RegisterConstructFunction();
      RegisterCTaskThreadSerializerBootstrap();
      gCTaskStageSerializerHelper.RegisterSerializeFunctions();
    }
  };

  CTaskThreadSerializerRegistration gCTaskThreadSerializerRegistration;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BEE340 (FUN_00BEE340, sub_BEE340)
   *
   * What it does:
   * Executes process-exit teardown for startup `CTaskThreadTypeInfo` storage.
   */
  void cleanup_CTaskThreadTypeInfo()
  {
    if (!gCTaskThreadTypeInfoConstructed) {
      return;
    }

    CTaskThreadTypeInfoSlot().~CTaskThreadTypeInfo();
    gCTaskThreadTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BEE3A0 (FUN_00BEE3A0, sub_BEE3A0)
   *
   * What it does:
   * Unlinks startup `CTaskThreadConstruct` helper lanes and resets them to a
   * self-linked singleton state.
   */
  void cleanup_CTaskThreadConstruct()
  {
    UnlinkHelperIntrusiveLinks(&gCTaskThreadConstructHelper);
  }

  /**
   * Address: 0x00BEE400 (FUN_00BEE400, ??1CTaskStageTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for startup `CTaskStageTypeInfo` storage.
   */
  void cleanup_CTaskStageTypeInfo()
  {
    if (!gCTaskStageTypeInfoConstructed) {
      return;
    }

    CTaskStageTypeInfoSlot().~CTaskStageTypeInfo();
    gCTaskStageTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BEE460 (FUN_00BEE460, ??1CTaskStageSerializer@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks startup `CTaskStageSerializer` helper lanes and resets them to a
   * self-linked singleton state.
   */
  void cleanup_CTaskStageSerializer()
  {
    UnlinkHelperIntrusiveLinks(&gCTaskStageSerializerHelper);
  }

  /**
   * Address: 0x00BC3020 (FUN_00BC3020, register_CTaskThreadTypeInfo)
   *
   * What it does:
   * Materializes startup `CTaskThreadTypeInfo` storage and registers
   * process-exit teardown.
   */
  void register_CTaskThreadTypeInfo()
  {
    (void)InitializeCTaskThreadTypeInfoStorage();
    (void)std::atexit(&cleanup_CTaskThreadTypeInfo);
  }

  /**
   * Address: 0x00BC3040 (FUN_00BC3040, register_CTaskThreadConstruct)
   *
   * What it does:
   * Initializes startup `CTaskThreadConstruct` helper callback lanes and
   * registers process-exit intrusive-link cleanup.
   */
  void register_CTaskThreadConstruct()
  {
    InitializeCTaskThreadConstructHelper(&gCTaskThreadConstructHelper);
    (void)std::atexit(&cleanup_CTaskThreadConstruct);
  }

  /**
   * Address: 0x00BC30C0 (FUN_00BC30C0, register_CTaskStageTypeInfo)
   *
   * What it does:
   * Materializes startup `CTaskStageTypeInfo` storage and registers
   * process-exit teardown.
   */
  void register_CTaskStageTypeInfo()
  {
    (void)InitializeCTaskStageTypeInfoStorage();
    (void)std::atexit(&cleanup_CTaskStageTypeInfo);
  }

  /**
   * Address: 0x00BC30E0 (FUN_00BC30E0, register_CTaskStageSerializer)
   *
   * What it does:
   * Initializes startup `CTaskStageSerializer` helper callback lanes and
   * registers process-exit intrusive-link cleanup.
   */
  void register_CTaskStageSerializer()
  {
    InitializeCTaskStageSerializerHelper(&gCTaskStageSerializerHelper);
    (void)std::atexit(&cleanup_CTaskStageSerializer);
  }
} // namespace moho

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
