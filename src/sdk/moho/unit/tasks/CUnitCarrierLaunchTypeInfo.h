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
    [[nodiscard]] const char* GetName() const override;
    void Init() override;

    /**
     * Address: 0x00607D00 (FUN_00607D00, Moho::CUnitCarrierLaunchTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitCarrierLaunch` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00607DA0 (FUN_00607DA0, Moho::CUnitCarrierLaunchTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one `CUnitCarrierLaunch` in caller storage and
     * returns a typed reflection ref.
     */
    static gpg::RRef CtrRef(void* objectStorage);
  };

  /**
   * Address: 0x00607470 (FUN_00607470, preregister_CUnitCarrierLaunchTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitCarrierLaunchTypeInfo`
   * reflection lane.
   */
  [[nodiscard]] gpg::RType* preregister_CUnitCarrierLaunchTypeInfo();

  static_assert(sizeof(CUnitCarrierLaunchTypeInfo) == 0x64, "CUnitCarrierLaunchTypeInfo size must be 0x64");
} // namespace moho
