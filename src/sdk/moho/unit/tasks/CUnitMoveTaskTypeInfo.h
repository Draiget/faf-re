#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitMoveTask;

  /**
   * Type-info owner for `CUnitMoveTask`.
   */
  class CUnitMoveTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00618EC0 (FUN_00618EC0, Moho::CUnitMoveTaskTypeInfo::Init)
     *
     * What it does:
     * Sets move-task reflected size/callback lanes, registers reflected base
     * slices, and finalizes type-info initialization.
     */
    void Init() override;

    /**
     * Address: 0x00619DD0 (FUN_00619DD0, Moho::CUnitMoveTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitMoveTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();
  };

  static_assert(sizeof(CUnitMoveTaskTypeInfo) == 0x64, "CUnitMoveTaskTypeInfo size must be 0x64");
} // namespace moho
