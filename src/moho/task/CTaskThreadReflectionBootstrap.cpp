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

} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(
  register_CTaskThreadTypeInfo_6a4218,
  moho::register_CTaskThreadTypeInfo
)
GPG_PREREGISTER_INIT(
  register_CTaskStageTypeInfo_6a4218,
  moho::register_CTaskStageTypeInfo
)

GPG_PREREGISTER_INIT(
  InitializeCTaskThreadTypeInfoStorage_6a4218,
  InitializeCTaskThreadTypeInfoStorage
)
