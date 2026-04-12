#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal stub for typeid() / TypeInfo registration.
   * Full layout recovery pending.
   */
  class CUnitSacrificeTask
  {
    unsigned char mPadding[0x4C];
  };

  static_assert(sizeof(CUnitSacrificeTask) == 0x4C, "CUnitSacrificeTask size must be 0x4C");
} // namespace moho
