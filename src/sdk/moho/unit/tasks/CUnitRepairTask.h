#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal stub for typeid() / TypeInfo registration.
   * Full layout recovery pending.
   */
  class CUnitRepairTask
  {
    unsigned char mPadding[0x9C];
  };

  static_assert(sizeof(CUnitRepairTask) == 0x9C, "CUnitRepairTask size must be 0x9C");
} // namespace moho
