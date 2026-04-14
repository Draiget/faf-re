#include "moho/unit/tasks/CUnitCarrierLaunchTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitCarrierLaunch.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitCarrierLaunchType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitCarrierLaunch));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00607D00 (FUN_00607D00, Moho::CUnitCarrierLaunchTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitCarrierLaunch` and returns a typed reflection ref.
   */
  gpg::RRef CUnitCarrierLaunchTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitCarrierLaunch();
    return gpg::RRef{task, CachedCUnitCarrierLaunchType()};
  }

  /**
   * Address: 0x00607DA0 (FUN_00607DA0, Moho::CUnitCarrierLaunchTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CUnitCarrierLaunch` in caller storage and
   * returns a typed reflection ref.
   */
  gpg::RRef CUnitCarrierLaunchTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CUnitCarrierLaunch*>(objectStorage);
    if (task) {
      new (task) CUnitCarrierLaunch();
    }

    return gpg::RRef{task, CachedCUnitCarrierLaunchType()};
  }
} // namespace moho
