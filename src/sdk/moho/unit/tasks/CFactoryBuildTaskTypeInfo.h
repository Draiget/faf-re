#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CFactoryBuildTask;

  /**
   * Type-info owner for `CFactoryBuildTask`.
   */
  class CFactoryBuildTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005FC480 (FUN_005FC480, Moho::CFactoryBuildTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CFactoryBuildTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();
  };

  static_assert(sizeof(CFactoryBuildTaskTypeInfo) == 0x64, "CFactoryBuildTaskTypeInfo size must be 0x64");
} // namespace moho

