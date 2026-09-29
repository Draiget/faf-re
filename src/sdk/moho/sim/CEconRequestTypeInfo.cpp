#include "moho/sim/CEconRequestTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/misc/CEconomyEvent.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00C02370 (FUN_00C02370, atexit destructor of the CEconRequestTypeInfo object)
   */
  [[nodiscard]] CEconRequestTypeInfo& AcquireCEconRequestTypeInfo()
  {
    static CEconRequestTypeInfo sInstance;
    return sInstance;
  }

  struct CEconRequestTypeInfoBootstrap
  {
    CEconRequestTypeInfoBootstrap() { moho::register_CEconRequestTypeInfoStartup(); }
  };
  CEconRequestTypeInfoBootstrap gCEconRequestTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x007737B0 (FUN_007737B0, Moho::CEconRequestTypeInfo::CEconRequestTypeInfo)
 */
CEconRequestTypeInfo::CEconRequestTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CEconRequest), this);
}

/**
 * Address: 0x00773840 (FUN_00773840)
 */
CEconRequestTypeInfo::~CEconRequestTypeInfo() = default;

/**
 * Address: 0x00773830 (FUN_00773830)
 */
const char* CEconRequestTypeInfo::GetName() const
{
  return "CEconRequest";
}

/**
 * Address: 0x00773810 (FUN_00773810)
 */
void CEconRequestTypeInfo::Init()
{
  static_assert(sizeof(moho::CEconRequest) == 0x18, "moho::CEconRequest is 0x18 bytes on x86");
  size_ = sizeof(moho::CEconRequest);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BDD1F0 (FUN_00BDD1F0)
 */
void moho::register_CEconRequestTypeInfoStartup()
{
  (void)AcquireCEconRequestTypeInfo();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CEconRequestTypeInfoStartup_c49737, moho::register_CEconRequestTypeInfoStartup)
