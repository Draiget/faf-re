#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitUnloadUnits;

  /**
   * Type-info owner for `CUnitUnloadUnits`.
   */
  class CUnitUnloadUnitsTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00627D40 (FUN_00627D40, Moho::CUnitUnloadUnitsTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitUnloadUnits` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();
  };

  static_assert(sizeof(CUnitUnloadUnitsTypeInfo) == 0x64, "CUnitUnloadUnitsTypeInfo size must be 0x64");
} // namespace moho

