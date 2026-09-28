#include "moho/sim/CEconomyTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/CEconomy.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00C021F0 (FUN_00C021F0, atexit destructor of the CEconomyTypeInfo object)
   */
  [[nodiscard]] CEconomyTypeInfo& AcquireCEconomyTypeInfo()
  {
    static CEconomyTypeInfo sInstance;
    return sInstance;
  }

  struct CEconomyTypeInfoBootstrap
  {
    CEconomyTypeInfoBootstrap() { moho::register_CEconomyTypeInfoStartup(); }
  };
  CEconomyTypeInfoBootstrap gCEconomyTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x00772DE0 (FUN_00772DE0, Moho::CEconomyTypeInfo::CEconomyTypeInfo)
 */
CEconomyTypeInfo::CEconomyTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CEconomy), this);
}

/**
 * Address: 0x00772E70 (FUN_00772E70)
 */
CEconomyTypeInfo::~CEconomyTypeInfo() = default;

/**
 * Address: 0x00772E60 (FUN_00772E60)
 */
const char* CEconomyTypeInfo::GetName() const
{
  return "CEconomy";
}

/**
 * Address: 0x00772E40 (FUN_00772E40)
 */
void CEconomyTypeInfo::Init()
{
  size_ = 0x60;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDD0B0 (FUN_00BDD0B0)
 */
void moho::register_CEconomyTypeInfoStartup()
{
  (void)AcquireCEconomyTypeInfo();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CEconomyTypeInfoStartup_e9f26e, moho::register_CEconomyTypeInfoStartup)
