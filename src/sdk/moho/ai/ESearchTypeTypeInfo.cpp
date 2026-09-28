#include "moho/ai/ESearchTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathFinder.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF71A0 (FUN_00BF71A0, atexit destructor of the ESearchTypeTypeInfo object)
   */
  [[nodiscard]] ESearchTypeTypeInfo* AcquireESearchTypeTypeInfo()
  {
    static ESearchTypeTypeInfo sInstance;
    return &sInstance;
  }

  // Address: 0x010AEC54 -- process-global `PrimitiveSerHelper<ESearchType,int>`
  // singleton (constructed by FUN_00BCCD10, self-registering via `__xc_a`; see
  // ESearchTypeTypeInfo.h for the real-ctor/atexit-target evidence).
  moho::ESearchTypePrimitiveSerializer gESearchTypePrimitiveSerializer;
} // namespace

/**
 * Address: 0x005A9D90 (FUN_005A9D90, Moho::ESearchTypeTypeInfo::ESearchTypeTypeInfo)
 */
ESearchTypeTypeInfo::ESearchTypeTypeInfo()
{
  gpg::PreRegisterRType(typeid(ESearchType), this);
}

/**
 * Address: 0x005A9E20 (FUN_005A9E20, scalar deleting thunk)
 */
ESearchTypeTypeInfo::~ESearchTypeTypeInfo() = default;

/**
 * Address: 0x005A9E10 (FUN_005A9E10, Moho::ESearchTypeTypeInfo::GetName)
 */
const char* ESearchTypeTypeInfo::GetName() const
{
  return "ESearchType";
}

/**
 * Address: 0x005A9DF0 (FUN_005A9DF0, Moho::ESearchTypeTypeInfo::Init)
 */
void ESearchTypeTypeInfo::Init()
{
  size_ = sizeof(ESearchType);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCCCF0 (FUN_00BCCCF0, register_ESearchTypeTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI descriptor for `ESearchType`.
 */
void moho::register_ESearchTypeTypeInfo()
{
  (void)AcquireESearchTypeTypeInfo();
}

namespace
{
  struct ESearchTypeTypeInfoBootstrap
  {
    ESearchTypeTypeInfoBootstrap()
    {
      moho::register_ESearchTypeTypeInfo();
    }
  };

  [[maybe_unused]] ESearchTypeTypeInfoBootstrap gESearchTypeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ESearchTypeTypeInfo_e65689, moho::register_ESearchTypeTypeInfo)
