#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCarrierLaunch;

  /**
   * Type-info owner for `CUnitCarrierLaunch`.
   */
  class CUnitCarrierLaunchTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00607D00 (FUN_00607D00, Moho::CUnitCarrierLaunchTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitCarrierLaunch` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();
  };

  static_assert(sizeof(CUnitCarrierLaunchTypeInfo) == 0x64, "CUnitCarrierLaunchTypeInfo size must be 0x64");
} // namespace moho

