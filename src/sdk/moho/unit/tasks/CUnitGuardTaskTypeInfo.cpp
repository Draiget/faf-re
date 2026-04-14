#include "moho/unit/tasks/CUnitGuardTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitGuardTask.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitGuardTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitGuardTask));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00614950 (FUN_00614950, Moho::CUnitGuardTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitGuardTask` and returns a typed reflection ref.
   */
  gpg::RRef CUnitGuardTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitGuardTask();
    return gpg::RRef{task, CachedCUnitGuardTaskType()};
  }

  /**
   * Address: 0x006149F0 (FUN_006149F0, Moho::CUnitGuardTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Constructs one `CUnitGuardTask` in caller-provided storage and returns a
   * typed reflection ref.
   */
  gpg::RRef CUnitGuardTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    CUnitGuardTask* task = nullptr;
    if (objectStorage != nullptr) {
      task = new (objectStorage) CUnitGuardTask();
    }

    return gpg::RRef{task, CachedCUnitGuardTaskType()};
  }
} // namespace moho
