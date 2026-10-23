#include "moho/animation/CAniPoseSharedPtrReflection.h"

#include "moho/animation/CAniPose.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{
  /**
   * Address: 0x0055EA20 (FUN_0055EA20, preregister_SharedPtrCAniPoseTypeStartup)
   * Address: 0x00BF5540 (FUN_00BF5540, its atexit destructor)
   */
  gpg::RType* preregister_SharedPtrCAniPoseTypeStartup()
  {
    static RSharedPointerType<moho::CAniPose> sType;
    return &sType;
  }
} // namespace gpg

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SharedPtrCAniPoseTypeStartup_4971d6, gpg::preregister_SharedPtrCAniPoseTypeStartup)
