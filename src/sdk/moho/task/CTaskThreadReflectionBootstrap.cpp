#include "moho/task/CTaskThread.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  bool gCTaskThreadTypeInfoPreregistered = false;

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
   * Address: 0x00BEE340 (FUN_00BEE340, atexit destructor of the CTaskThreadTypeInfo object)
   */
  [[nodiscard]] gpg::RType* InitializeCTaskThreadTypeInfoStorage()
  {
    static moho::CTaskThreadTypeInfo sInstance;
    if (!gCTaskThreadTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::CTaskThread), &sInstance);
      gCTaskThreadTypeInfoPreregistered = true;
    }

    return &sInstance;
  }

  /**
   * Address: 0x00BEE400 (FUN_00BEE400, atexit destructor of the CTaskStageTypeInfo object)
   */
  [[nodiscard]] gpg::RType* InitializeCTaskStageTypeInfoStorage()
  {
    static moho::CTaskStageTypeInfo sInstance;
    return &sInstance;
  }

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
   * Address: 0x00BC3020 (FUN_00BC3020, register_CTaskThreadTypeInfo)
   *
   * What it does:
   * Materializes the startup `CTaskThreadTypeInfo` object.
   */
  void register_CTaskThreadTypeInfo()
  {
    (void)InitializeCTaskThreadTypeInfoStorage();
  }

  /**
   * Address: 0x00BC30C0 (FUN_00BC30C0, register_CTaskStageTypeInfo)
   *
   * What it does:
   * Materializes the startup `CTaskStageTypeInfo` object.
   */
  void register_CTaskStageTypeInfo()
  {
    (void)InitializeCTaskStageTypeInfoStorage();
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
  CTaskThreadSerializer::~CTaskThreadSerializer() = default;

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
  CTaskStageSerializer::~CTaskStageSerializer() = default;
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CTaskThreadTypeInfo_6a4218, moho::register_CTaskThreadTypeInfo)
GPG_PREREGISTER_INIT(register_CTaskStageTypeInfo_6a4218, moho::register_CTaskStageTypeInfo)

GPG_PREREGISTER_INIT(InitializeCTaskThreadTypeInfoStorage_6a4218, InitializeCTaskThreadTypeInfoStorage)
