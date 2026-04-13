#include "moho/unit/tasks/CUnitCaptureTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitCaptureTask.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitCaptureTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitCaptureTask));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00605400 (FUN_00605400, Moho::CUnitCaptureTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitCaptureTask` and returns a typed reflection ref.
   */
  gpg::RRef CUnitCaptureTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitCaptureTask();
    return gpg::RRef{task, CachedCUnitCaptureTaskType()};
  }
} // namespace moho

