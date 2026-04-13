#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitGuardTask;

  /**
   * Type-info owner for `CUnitGuardTask`.
   */
  class CUnitGuardTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00614950 (FUN_00614950, Moho::CUnitGuardTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitGuardTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();
  };

  static_assert(sizeof(CUnitGuardTaskTypeInfo) == 0x64, "CUnitGuardTaskTypeInfo size must be 0x64");
} // namespace moho

