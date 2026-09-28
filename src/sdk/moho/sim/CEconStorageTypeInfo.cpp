#include "moho/sim/CEconStorageTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/CEconStorage.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00C022B0 (FUN_00C022B0, atexit destructor of the CEconStorageTypeInfo object)
   */
  [[nodiscard]] CEconStorageTypeInfo& Acquire()
  {
    static CEconStorageTypeInfo sInstance;
    return sInstance;
  }

  struct Bootstrap { Bootstrap() { moho::register_CEconStorageTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/**
 * Address: 0x00773320 (FUN_00773320, Moho::CEconStorageTypeInfo::CEconStorageTypeInfo)
 */
CEconStorageTypeInfo::CEconStorageTypeInfo() : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CEconStorage), this);
}

CEconStorageTypeInfo::~CEconStorageTypeInfo() = default;

const char* CEconStorageTypeInfo::GetName() const { return "CEconStorage"; }

void CEconStorageTypeInfo::Init()
{
  size_ = 0x0C;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDD150 (FUN_00BDD150, register_CEconStorageTypeInfo)
 */
void moho::register_CEconStorageTypeInfoStartup()
{
  (void)Acquire();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CEconStorageTypeInfoStartup_e016aa, moho::register_CEconStorageTypeInfoStartup)
