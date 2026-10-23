#include "moho/ai/IAiReconDBTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiReconDB.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF79F0 (FUN_00BF79F0, atexit destructor of the IAiReconDBTypeInfo object)
   */
  [[nodiscard]] IAiReconDBTypeInfo* AcquireIAiReconDBTypeInfo()
  {
    static IAiReconDBTypeInfo sInstance;
    return &sInstance;
  }

} // namespace

/**
 * Address: 0x005C2670 (FUN_005C2670, Moho::IAiReconDBTypeInfo::IAiReconDBTypeInfo)
 *
 * What it does:
 * Preregisters `IAiReconDB` RTTI into the reflection lookup table.
 */
IAiReconDBTypeInfo::IAiReconDBTypeInfo()
{
  gpg::PreRegisterRType(typeid(IAiReconDB), this);
}

/**
 * Address: 0x005C2700 (FUN_005C2700, scalar deleting thunk)
 *
 * What it does:
 * Uses compiler-emitted scalar-delete thunk behavior for `gpg::RType`
 * destruction and optional object free.
 */
IAiReconDBTypeInfo::~IAiReconDBTypeInfo() = default;

/**
 * Address: 0x005C26F0 (FUN_005C26F0)
 *
 * IDA signature:
 * const char *sub_5C26F0();
 *
 * What it does:
 * Returns `"IAiReconDB"` for reflection name lookup.
 */
const char* IAiReconDBTypeInfo::GetName() const
{
  return "IAiReconDB";
}

/**
 * Address: 0x005C26D0 (FUN_005C26D0)
 *
 * IDA signature:
 * void __thiscall Moho::IAiReconDBTypeInfo::Register(gpg::RType *this);
 *
 * What it does:
 * Sets reflected size to `sizeof(IAiReconDB)`, runs base `RType::Init()`,
 * then closes registration with `Finish()`.
 */
void IAiReconDBTypeInfo::Init()
{
  size_ = sizeof(IAiReconDB);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BCDD80 (FUN_00BCDD80, register_IAiReconDBTypeInfo)
 *
 * What it does:
 * Constructs the recovered `IAiReconDBTypeInfo` helper and installs
 * process-exit cleanup.
 */
void moho::register_IAiReconDBTypeInfo()
{
  (void)AcquireIAiReconDBTypeInfo();
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_IAiReconDBTypeInfo_254042, moho::register_IAiReconDBTypeInfo)
