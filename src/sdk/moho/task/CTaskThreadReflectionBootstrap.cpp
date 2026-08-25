#include "moho/task/CTaskThread.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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

  /**
   * Address: 0x00409420 (FUN_00409420, sub_409420)
   *
   * What it does:
   * Unlinks thread from current intrusive list, relinks it into owning stage
   * main-thread list, and clears staged flag.
   */
  [[maybe_unused]] moho::CTaskThread* RelinkThreadToPrimaryStageList(moho::CTaskThread* const thread)
  {
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

  // Address: 0x010A67BC -- process-global `CTaskThreadConstruct` singleton.
  moho::CTaskThreadConstruct gCTaskThreadConstructHelper;

  // Address: 0x010A672C -- process-global `CTaskThreadSerializer` singleton.
  moho::CTaskThreadSerializer gCTaskThreadSerializerHelper;

  // Address: 0x010A6834 -- process-global `CTaskStageSerializer` singleton.
  moho::CTaskStageSerializer gCTaskStageSerializerHelper;

  struct CTaskThreadSerializerRegistration
  {
    CTaskThreadSerializerRegistration()
    {
      moho::register_CTaskThreadTypeInfo();
      moho::register_CTaskStageTypeInfo();
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
   * Address: 0x00BC3040 (FUN_00BC3040, dynamic initializer for the global
   * `CTaskThreadConstruct` singleton)
   */
  CTaskThreadConstruct::CTaskThreadConstruct()
    : mSerConstructFunc(reinterpret_cast<gpg::RType::construct_func_t>(&CTaskThreadConstruct::Construct))
    , mDeleteFunc(&CTaskThreadConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00BEE3A0 (FUN_00BEE3A0, Moho::CTaskThreadConstruct::~CTaskThreadConstruct)
   */
  CTaskThreadConstruct::~CTaskThreadConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00BC3080 (FUN_00BC3080, dynamic initializer for the global
   * `CTaskThreadSerializer` singleton)
   */
  CTaskThreadSerializer::CTaskThreadSerializer()
    : mSerLoadFunc(&CTaskThreadSerializer::Deserialize)
    , mSerSaveFunc(&CTaskThreadSerializer::Serialize)
  {}

  /**
   * Address: 0x00BEE3D0 (FUN_00BEE3D0, Moho::CTaskThreadSerializer::~CTaskThreadSerializer)
   */
  CTaskThreadSerializer::~CTaskThreadSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00BC30E0 (FUN_00BC30E0, dynamic initializer for the global
   * `CTaskStageSerializer` singleton)
   */
  CTaskStageSerializer::CTaskStageSerializer()
    : mSerLoadFunc(&CTaskStageSerializer::Deserialize)
    , mSerSaveFunc(&CTaskStageSerializer::Serialize)
  {}

  /**
   * Address: 0x00BEE460 (FUN_00BEE460, Moho::CTaskStageSerializer::~CTaskStageSerializer)
   */
  CTaskStageSerializer::~CTaskStageSerializer()
  {
    ResetLinks();
  }
} // namespace moho

/**
 * Address: 0x004094E0 (FUN_004094E0, Moho::CTaskThreadConstruct::Construct)
 * Address: 0x0061AD00 (FUN_0061AD00)
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


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CTaskThreadTypeInfo_6a4218, moho::register_CTaskThreadTypeInfo)
GPG_PREREGISTER_INIT(register_CTaskStageTypeInfo_6a4218, moho::register_CTaskStageTypeInfo)

GPG_PREREGISTER_INIT(InitializeCTaskThreadTypeInfoStorage_6a4218, InitializeCTaskThreadTypeInfoStorage)
