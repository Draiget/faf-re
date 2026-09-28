#include "moho/ai/SContinueInfoTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathSpline.h"

#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF7450 (FUN_00BF7450, atexit destructor of the SContinueInfoTypeInfo object)
   */
  [[nodiscard]] SContinueInfoTypeInfo* AcquireSContinueInfoTypeInfo()
  {
    static SContinueInfoTypeInfo sInstance;
    return &sInstance;
  }

} // namespace

/**
 * Address: 0x005B21E0 (FUN_005B21E0, scalar deleting thunk)
 */
SContinueInfoTypeInfo::~SContinueInfoTypeInfo() = default;

/**
 * Address: 0x005B2150 (FUN_005B2150, ??0SContinueInfoTypeInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Preregisters `SContinueInfo` RTTI so lookup resolves to this type helper.
 */
SContinueInfoTypeInfo::SContinueInfoTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(SContinueInfo), this);
}

/**
 * Address: 0x005B21D0 (FUN_005B21D0)
 */
const char* SContinueInfoTypeInfo::GetName() const
{
  return "SContinueInfo";
}

/**
 * Address: 0x005B21B0 (FUN_005B21B0)
 */
void SContinueInfoTypeInfo::Init()
{
  size_ = sizeof(SContinueInfo);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCD2D0 (FUN_00BCD2D0, register_SContinueInfoTypeInfo)
 *
 * What it does:
 * Constructs startup-owned `SContinueInfoTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_SContinueInfoTypeInfo()
{
  (void)AcquireSContinueInfoTypeInfo();
}

namespace
{
  struct SContinueInfoTypeInfoBootstrap
  {
    SContinueInfoTypeInfoBootstrap()
    {
      (void)moho::register_SContinueInfoTypeInfo();
    }
  };

  [[maybe_unused]] SContinueInfoTypeInfoBootstrap gSContinueInfoTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SContinueInfoTypeInfo_3ad5d7, moho::register_SContinueInfoTypeInfo)
