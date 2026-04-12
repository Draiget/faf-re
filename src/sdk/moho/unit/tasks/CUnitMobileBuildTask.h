#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal stub for typeid() / TypeInfo registration.
   * Full layout recovery pending.
   */
  class CUnitMobileBuildTask
  {
    unsigned char mPadding[0xE8];
  };

  static_assert(sizeof(CUnitMobileBuildTask) == 0xE8, "CUnitMobileBuildTask size must be 0xE8");
} // namespace moho
