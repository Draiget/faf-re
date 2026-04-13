#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitMeleeAttackTargetTask;

  /**
   * Type-info owner for `CUnitMeleeAttackTargetTask`.
   */
  class CUnitMeleeAttackTargetTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006178A0 (FUN_006178A0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitMeleeAttackTargetTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();
  };

  static_assert(sizeof(CUnitMeleeAttackTargetTaskTypeInfo) == 0x64, "CUnitMeleeAttackTargetTaskTypeInfo size must be 0x64");
} // namespace moho

