#include "moho/ai/IAiFormationDBTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiFormationDB.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF67D0 (FUN_00BF67D0, atexit destructor of the IAiFormationDBTypeInfo object)
   */
  [[nodiscard]] IAiFormationDBTypeInfo* AcquireIAiFormationDBTypeInfo()
  {
    static IAiFormationDBTypeInfo sInstance;
    return &sInstance;
  }

} // namespace

/**
 * Address: 0x0059C3D0 (FUN_0059C3D0, ctor)
 *
 * What it does:
 * Preregisters `IAiFormationDB` RTTI so lookup resolves to this type helper.
 */
IAiFormationDBTypeInfo::IAiFormationDBTypeInfo()
{
  gpg::PreRegisterRType(typeid(IAiFormationDB), this);
}

/**
 * Address: 0x0059C460 (FUN_0059C460, scalar deleting thunk)
 */
IAiFormationDBTypeInfo::~IAiFormationDBTypeInfo() = default;

/**
 * Address: 0x0059C450 (FUN_0059C450, ?GetName@IAiFormationDBTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiFormationDBTypeInfo::GetName() const
{
  return "IAiFormationDB";
}

/**
 * Address: 0x0059C430 (FUN_0059C430, ?Init@IAiFormationDBTypeInfo@Moho@@UAEXXZ)
 */
void IAiFormationDBTypeInfo::Init()
{
  size_ = sizeof(IAiFormationDB);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCC190 (FUN_00BCC190)
 *
 * What it does:
 * Constructs startup-owned `IAiFormationDBTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_IAiFormationDBTypeInfo()
{
  (void)AcquireIAiFormationDBTypeInfo();
}

namespace
{
  struct IAiFormationDBTypeInfoBootstrap
  {
    IAiFormationDBTypeInfoBootstrap()
    {
      (void)moho::register_IAiFormationDBTypeInfo();
    }
  };

  [[maybe_unused]] IAiFormationDBTypeInfoBootstrap gIAiFormationDBTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_IAiFormationDBTypeInfo_86cce9, moho::register_IAiFormationDBTypeInfo)
