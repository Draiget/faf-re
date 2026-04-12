#pragma once

#include <cstddef>

namespace moho
{
  /**
   * Minimal stub for typeid() / TypeInfo registration.
   * Full layout recovery pending.
   */
  class CUnitAssistMoveTask
  {
    unsigned char mPadding[0x68];
  };

  static_assert(sizeof(CUnitAssistMoveTask) == 0x68, "CUnitAssistMoveTask size must be 0x68");
} // namespace moho
