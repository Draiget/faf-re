#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal stub for typeid() / TypeInfo registration.
   * Full layout recovery pending.
   */
  class CUnitAttackTargetTask
  {
    unsigned char mPadding[0x90];
  };

  static_assert(sizeof(CUnitAttackTargetTask) == 0x90, "CUnitAttackTargetTask size must be 0x90");
} // namespace moho
