#include "moho/ai/SAttachPointTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF8A30 (FUN_00BF8A30, atexit destructor of the SAttachPointTypeInfo object)
   */
  [[nodiscard]] SAttachPointTypeInfo* AcquireSAttachPointTypeInfo()
  {
    static SAttachPointTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x005E41A0 (FUN_005E41A0)
   *
   * What it does:
   * Initializes the startup-owned `SAttachPointTypeInfo` instance and
   * preregisters RTTI for `SAttachPoint`.
   */
  [[nodiscard]] gpg::RType* preregister_SAttachPointTypeInfoStartup()
  {
    SAttachPointTypeInfo* const typeInfo = AcquireSAttachPointTypeInfo();
    gpg::PreRegisterRType(typeid(SAttachPoint), typeInfo);
    return typeInfo;
  }
} // namespace

/**
 * Address: 0x005E4230 (FUN_005E4230, scalar deleting thunk)
 */
SAttachPointTypeInfo::~SAttachPointTypeInfo() = default;

/**
 * Address: 0x005E4220 (FUN_005E4220, SAttachPointTypeInfo::GetName)
 */
const char* SAttachPointTypeInfo::GetName() const
{
  return "SAttachPoint";
}

/**
 * Address: 0x005E4200 (FUN_005E4200, SAttachPointTypeInfo::Init)
 */
void SAttachPointTypeInfo::Init()
{
  size_ = sizeof(SAttachPoint);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCEDD0 (FUN_00BCEDD0, register_SAttachPointTypeInfo)
 *
 * What it does:
 * Registers `SAttachPoint` type-info.
 */
void moho::register_SAttachPointTypeInfo()
{
  (void)preregister_SAttachPointTypeInfoStartup();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SAttachPointTypeInfo_1ad790, moho::register_SAttachPointTypeInfo)

GPG_PREREGISTER_INIT(preregister_SAttachPointTypeInfoStartup_1ad790, preregister_SAttachPointTypeInfoStartup)
