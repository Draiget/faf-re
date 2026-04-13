#include "moho/unit/tasks/CUnitMeleeAttackTargetTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitMeleeAttackTargetTask.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitMeleeAttackTargetTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitMeleeAttackTargetTask));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006178A0 (FUN_006178A0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitMeleeAttackTargetTask` and returns a typed reflection ref.
   */
  gpg::RRef CUnitMeleeAttackTargetTaskTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitMeleeAttackTargetTask();
    return gpg::RRef{task, CachedCUnitMeleeAttackTargetTaskType()};
  }
} // namespace moho

