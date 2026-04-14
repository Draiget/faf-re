#include "moho/unit/tasks/CFactoryBuildTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CFactoryBuildTask.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCFactoryBuildTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CFactoryBuildTask));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005FC480 (FUN_005FC480, Moho::CFactoryBuildTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CFactoryBuildTask` and returns a typed reflection ref.
   */
  gpg::RRef CFactoryBuildTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CFactoryBuildTask();
    return gpg::RRef{task, CachedCFactoryBuildTaskType()};
  }

  /**
   * Address: 0x005FC520 (FUN_005FC520, Moho::CFactoryBuildTaskTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CFactoryBuildTask` in caller storage and
   * returns a typed reflection ref.
   */
  gpg::RRef CFactoryBuildTaskTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const task = static_cast<CFactoryBuildTask*>(objectStorage);
    if (task) {
      new (task) CFactoryBuildTask();
    }

    return gpg::RRef{task, CachedCFactoryBuildTaskType()};
  }
} // namespace moho
