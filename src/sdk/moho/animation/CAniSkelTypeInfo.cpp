#include "CAniSkelTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/animation/CAniSkel.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BF4480 (FUN_00BF4480, atexit destructor of the CAniSkelTypeInfo object)
   */
  [[nodiscard]] moho::CAniSkelTypeInfo* AcquireCAniSkelTypeInfo()
  {
    static moho::CAniSkelTypeInfo sInstance;
    return &sInstance;
  }

  struct CAniSkelTypeInfoBootstrap
  {
    CAniSkelTypeInfoBootstrap()
    {
      moho::register_CAniSkelTypeInfoAtexit();
    }
  };

  CAniSkelTypeInfoBootstrap gCAniSkelTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00549FF0 (FUN_00549FF0, scalar deleting destructor thunk)
   */
  CAniSkelTypeInfo::~CAniSkelTypeInfo() = default;

  /**
   * Address: 0x00549FE0 (FUN_00549FE0)
   */
  const char* CAniSkelTypeInfo::GetName() const
  {
    return "CAniSkel";
  }

  /**
   * Address: 0x00549FC0 (FUN_00549FC0)
   *
   * What it does:
   * Initializes reflection metadata for `CAniSkel` (`sizeof = 0x2C`).
   */
  void CAniSkelTypeInfo::Init()
  {
    size_ = sizeof(CAniSkel);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00549F60 (FUN_00549F60, preregister_CAniSkelTypeInfo)
   */
  gpg::RType* preregister_CAniSkelTypeInfo()
  {
    CAniSkelTypeInfo* const typeInfo = AcquireCAniSkelTypeInfo();
    gpg::PreRegisterRType(typeid(CAniSkel), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BC9890 (FUN_00BC9890, register_CAniSkelTypeInfoAtexit)
   */
  void register_CAniSkelTypeInfoAtexit()
  {
    (void)preregister_CAniSkelTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_CAniSkelTypeInfo_9b39e1, moho::preregister_CAniSkelTypeInfo)
