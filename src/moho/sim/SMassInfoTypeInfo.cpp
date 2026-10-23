#include "moho/sim/SMassInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/SMassInfo.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF6460 (FUN_00BF6460, atexit destructor of the SMassInfoTypeInfo object)
   */
  [[nodiscard]] SMassInfoTypeInfo& AcquireSMassInfoTypeInfo()
  {
    static SMassInfoTypeInfo sInstance;
    return sInstance;
  }

  struct SMassInfoTypeInfoStartupBootstrap
  {
    SMassInfoTypeInfoStartupBootstrap()
    {
      moho::register_SMassInfoTypeInfoStartup();
    }
  };

  SMassInfoTypeInfoStartupBootstrap gSMassInfoTypeInfoStartupBootstrap;
} // namespace

/**
 * Address: 0x00585CD0 (FUN_00585CD0, ??0SMassInfoTypeInfo@Moho@@QAE@XZ)
 *
 * What it does:
 * Preregisters `SMassInfo` RTTI for this type-info helper.
 */
SMassInfoTypeInfo::SMassInfoTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(SMassInfo), this);
}

/**
 * Address: 0x00585D60 (FUN_00585D60, scalar deleting thunk)
 */
SMassInfoTypeInfo::~SMassInfoTypeInfo() = default;

/**
 * Address: 0x00585D50 (FUN_00585D50, ?GetName@SMassInfoTypeInfo@Moho@@UBEPBDXZ)
 */
const char* SMassInfoTypeInfo::GetName() const
{
  return "SMassInfo";
}

/**
 * Address: 0x00585D30 (FUN_00585D30, ?Init@SMassInfoTypeInfo@Moho@@UAEXXZ)
 *
 * What it does:
 * Sets size = 0x0C and finalizes.
 */
void SMassInfoTypeInfo::Init()
{
  size_ = sizeof(SMassInfo);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCB6E0 (FUN_00BCB6E0, register_SMassInfoTypeInfo)
 */
void moho::register_SMassInfoTypeInfoStartup()
{
  (void)AcquireSMassInfoTypeInfo();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SMassInfoTypeInfoStartup_53a161, moho::register_SMassInfoTypeInfoStartup)
