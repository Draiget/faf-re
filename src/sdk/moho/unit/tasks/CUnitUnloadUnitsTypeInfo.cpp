#include "moho/unit/tasks/CUnitUnloadUnitsTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitUnloadUnits.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitUnloadUnitsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitUnloadUnits));
    }
    return cached;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00627D40 (FUN_00627D40, Moho::CUnitUnloadUnitsTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CUnitUnloadUnits` and returns a typed reflection ref.
   */
  gpg::RRef CUnitUnloadUnitsTypeInfo::NewRef()
  {
    auto* const task = new (std::nothrow) CUnitUnloadUnits();
    return gpg::RRef{task, CachedCUnitUnloadUnitsType()};
  }
} // namespace moho

