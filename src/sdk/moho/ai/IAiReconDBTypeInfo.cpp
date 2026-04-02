#include "moho/ai/IAiReconDBTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiReconDB.h"

using namespace moho;

namespace
{
  alignas(IAiReconDBTypeInfo) unsigned char gIAiReconDBTypeInfoStorage[sizeof(IAiReconDBTypeInfo)];
  bool gIAiReconDBTypeInfoConstructed = false;

  [[nodiscard]] IAiReconDBTypeInfo* AcquireIAiReconDBTypeInfo()
  {
    if (!gIAiReconDBTypeInfoConstructed) {
      new (gIAiReconDBTypeInfoStorage) IAiReconDBTypeInfo();
      gIAiReconDBTypeInfoConstructed = true;
    }

    return reinterpret_cast<IAiReconDBTypeInfo*>(gIAiReconDBTypeInfoStorage);
  }

  /**
   * Address: 0x00BF79F0 (FUN_00BF79F0, cleanup_IAiReconDBTypeInfo)
   *
   * What it does:
   * Tears down recovered static `IAiReconDBTypeInfo` storage.
   */
  void cleanup_IAiReconDBTypeInfo()
  {
    if (!gIAiReconDBTypeInfoConstructed) {
      return;
    }

    AcquireIAiReconDBTypeInfo()->~IAiReconDBTypeInfo();
    gIAiReconDBTypeInfoConstructed = false;
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
  (void)std::atexit(&cleanup_IAiReconDBTypeInfo);
}
